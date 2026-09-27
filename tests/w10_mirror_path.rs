//! PR10 task 01 — one mirror directory per configured remote path.
//!
//! A configured ssh source's remote `path` is mirrored under
//! `data_dir/remotes/<name>/mirror/<safe name>` and indexed from the same
//! directory. Before this task the two sides disagreed about `<safe name>`:
//! the writer derived it from the **raw** configured spelling, while the
//! index-side candidate search turned a bare `~` into `~/` first. `paths =
//! ["~"]` therefore mirrored into `root_<h("~")>` and was indexed from
//! `root_<h("~/")>` — a transfer that reported success and ingested nothing.
//!
//! Every observation is taken from the real binary (`cass index --json`, its
//! exit code, and the database it wrote) plus the crate's own
//! `build_scan_roots` for the root identity, so neither the run's exit path nor
//! the root's canonical spelling is taken on trust.
//!
//! Globals these tests touch: the ones read by `SourcesConfig::load()` and by
//! the scan-root builder (`HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`,
//! `CASS_IGNORE_SOURCES_CONFIG`) and, for the relative-data-dir case, the
//! process working directory. Subprocess tests hand their environment to the
//! child through `Command::env` and are unaffected by the parent's; the
//! in-process tests take `ENV_SERIAL` and restore every variable, and the CWD
//! window restores the previous directory on drop. Every test is `#[serial]`
//! so no two of them overlap.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use serial_test::serial;

use coding_agent_search::indexer::build_scan_roots;
use coding_agent_search::sources::sync::path_to_safe_dirname;
use coding_agent_search::storage::sqlite::FrankenStorage;

/// The in-tree codex session fixture: 1 conversation / 20 messages, so a run
/// that ingested it and a run that did not are distinguishable by count.
/// Relative to `tests/fixtures`, as [`fixture_path`] expects.
const CODEX_FIXTURE: &str = "codex_real/sessions/2025/11/25/rollout-test.jsonl";

static ENV_SERIAL: Mutex<()> = Mutex::new(());

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative)
}

/// Write the codex fixture at the connector shape `<root>/sessions/<...>`.
fn write_codex_session(under: &Path) {
    let dest = under.join("sessions/2025/11/25/rollout-test.jsonl");
    std::fs::create_dir_all(dest.parent().expect("parent")).expect("create sessions dir");
    std::fs::copy(fixture_path(CODEX_FIXTURE), &dest).expect("copy codex fixture");
}

/// One private HOME / config / data-dir triple.
struct Env {
    /// Held for its `Drop`: deleting this deletes the tree the paths point at.
    _tmp: tempfile::TempDir,
    home: PathBuf,
    config_home: PathBuf,
    data_dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let env = Env {
            home: tmp.path().join("home"),
            config_home: tmp.path().join("config"),
            data_dir: tmp.path().join("data"),
            _tmp: tmp,
        };
        std::fs::create_dir_all(&env.home).expect("create home");
        std::fs::create_dir_all(&env.data_dir).expect("create data dir");
        env
    }

    fn root(&self) -> &Path {
        self._tmp.path()
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir.join("agent_search.db")
    }

    fn write_sources_config(&self, toml: &str) {
        let path = self.config_home.join("cass/sources.toml");
        std::fs::create_dir_all(path.parent().expect("config dir")).expect("create config dir");
        std::fs::write(&path, toml).expect("write sources.toml");
    }

    /// `data_dir/remotes/<name>/mirror`, the built-in mirror root of a source
    /// that declares no `mirror_dir`.
    fn mirror_root(&self, source: &str) -> PathBuf {
        self.data_dir.join("remotes").join(source).join("mirror")
    }

    /// The binary under test with a fully private environment. `cmd.env` rather
    /// than process-global `set_var`: a subprocess gets its own copy, so these
    /// tests cannot leak into the in-process ones (and vice versa).
    ///
    /// `CASS_DATA_DIR` is deliberately left unset: the flag under test decides
    /// the data dir, and an environment fallback behind it would make a
    /// relative `--data-dir` untestable.
    fn cass(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cass"));
        cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
        cmd.env("HOME", &self.home);
        cmd.env("XDG_DATA_HOME", self.home.join(".local/share"));
        cmd.env("XDG_CONFIG_HOME", &self.config_home);
        cmd.env_remove("CASS_DATA_DIR");
        cmd.env("NO_COLOR", "1");
        // Both must be absent for the config to be *read*: one short-circuits
        // it, the other would re-enable the info-level chatter robot mode
        // pins off.
        cmd.env_remove("CASS_IGNORE_SOURCES_CONFIG");
        cmd.env_remove("RUST_LOG");
        cmd.env_remove("CLAUDE_CONFIG_DIR");
        cmd.env_remove("CODEX_HOME");
        cmd
    }

    /// `cass index --json` against `self.data_dir`.
    fn index_json(&self) -> (i32, Option<serde_json::Value>, String) {
        self.index_json_at(&self.data_dir)
    }

    /// `cass index --json` against `data_dir`, which may be a symlinked or
    /// relative spelling of the same tree. Returns the exit code, the stdout
    /// JSON object (`None` when stdout was not one), and stderr.
    fn index_json_at(&self, data_dir: &Path) -> (i32, Option<serde_json::Value>, String) {
        let data_dir = data_dir.display().to_string();
        let out = self
            .cass()
            .args(["index", "--json", "--data-dir", &data_dir])
            .output()
            .expect("spawn cass index --json");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        (
            out.status.code().unwrap_or(-1),
            serde_json::from_str::<serde_json::Value>(&stdout).ok(),
            stderr,
        )
    }

    /// Run `cass index --json` against `data_dir` and require success.
    fn index_ok_at(&self, data_dir: &Path) -> serde_json::Value {
        let (code, payload, stderr) = self.index_json_at(data_dir);
        assert_eq!(
            code, 0,
            "`cass index --json` must succeed, got {code}\n--- stdout ---\n{payload:?}\n--- stderr ---\n{stderr}"
        );
        payload.expect("a successful `index --json` prints one JSON object")
    }

    /// [`Self::index_ok_at`] against `self.data_dir`.
    fn index_ok(&self) -> serde_json::Value {
        self.index_ok_at(&self.data_dir)
    }
}

/// `(conversations, messages)` in the archive the subprocess wrote.
///
/// Read back through the crate's own storage layer rather than through the
/// run's report, so the count is independent of what the run claimed.
fn archive_counts(db_path: &Path) -> (usize, usize) {
    let storage = FrankenStorage::open(db_path).expect("open storage");
    let counts = (
        storage.total_conversation_count().expect("conversation count"),
        storage.total_message_count().expect("message count"),
    );
    storage
        .close_without_checkpoint()
        .expect("close storage without checkpoint");
    counts
}

/// Set process-global variables for one in-process check, restoring every
/// previous value on drop (including removing one that was unset before).
struct EnvWindow {
    /// Held for the whole window, so the subprocess-only tests cannot observe a
    /// half-set environment through the crate's own readers.
    _guard: std::sync::MutexGuard<'static, ()>,
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl EnvWindow {
    fn apply(pairs: &[(&'static str, Option<&Path>)]) -> Self {
        let guard = ENV_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved = pairs
            .iter()
            .map(|(key, _)| (*key, std::env::var_os(key)))
            .collect();
        for (key, value) in pairs {
            // SAFETY: `ENV_SERIAL` keeps the tests in this binary from
            // observing a half-set window; the window ends in `Drop`.
            unsafe {
                match value {
                    Some(path) => std::env::set_var(key, path),
                    None => std::env::remove_var(key),
                }
            }
        }
        Self {
            _guard: guard,
            saved,
        }
    }
}

impl Drop for EnvWindow {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            // SAFETY: as in `apply`.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// The process working directory, restored on drop: a relative `--data-dir`
/// resolves against it, and it is process-global.
struct CwdWindow {
    previous: PathBuf,
}

impl CwdWindow {
    fn enter(dir: &Path) -> Self {
        let previous = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(dir).expect("enter fixture dir");
        Self { previous }
    }
}

impl Drop for CwdWindow {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.previous).expect("restore current dir");
    }
}

/// The `ScanRoot` and its `ScanRootMeta` for `source`, looked up by
/// `data_dir`'s spelling, built through the real `build_scan_roots` entry
/// point. Returns `(ScanRoot.path, ScanRootMeta.canonical_path)`.
fn scan_root_for_at(env: &Env, data_dir: &Path, source_name: &str) -> (PathBuf, PathBuf) {
    let _env = EnvWindow::apply(&[
        ("HOME", Some(&env.home)),
        ("XDG_CONFIG_HOME", Some(&env.config_home)),
        ("XDG_DATA_HOME", Some(&env.home.join(".local/share"))),
        ("CASS_IGNORE_SOURCES_CONFIG", None),
    ]);
    let storage =
        FrankenStorage::open(&data_dir.join("agent_search.db")).expect("open storage");
    let (root_path, meta_path) = {
        let roots = build_scan_roots(&storage, data_dir);
        let root = roots
            .iter()
            .find(|root| root.origin.source_id == source_name)
            .unwrap_or_else(|| {
                panic!("source {source_name} must contribute a scan root, got {roots:?}")
            });
        let meta = coding_agent_search::indexer::build_scan_roots_with_meta(&storage, data_dir)
            .1
            .get_by_path(&root.path)
            .unwrap_or_else(|| {
                panic!(
                    "the scan root {} must carry metadata",
                    root.path.display()
                )
            })
            .canonical_path
            .clone();
        (root.path.clone(), meta)
    };
    storage
        .close_without_checkpoint()
        .expect("close storage without checkpoint");
    (root_path, meta_path)
}

fn ssh_source_toml(name: &str, path: &str) -> String {
    format!(
        "[[sources]]\nname = \"{name}\"\ntype = \"ssh\"\nhost = \"{name}\"\norigin_host = \"{name}\"\npaths = [\"{path}\"]\n"
    )
}

/// AC-1: `paths = ["~"]` mirrors into the directory the raw spelling names,
/// the index selects that same directory, and the in-tree fixture lands in the
/// database.
///
/// The failing baseline is the pair of directory names: the writer names the
/// mirror after `~` and the index looked for `~/`.
#[test]
#[serial]
fn bare_tilde_mirrors_and_indexes_the_same_directory() {
    let env = Env::new();
    env.write_sources_config(&ssh_source_toml("laptop", "~"));

    // The mirror directory exactly as the sync writer derives it today: the
    // raw configured path, run through the same safe-name function.
    let mirrored = env.mirror_root("laptop").join(path_to_safe_dirname("~"));
    write_codex_session(&mirrored);

    let payload = env.index_ok();
    assert_eq!(
        payload["scan_roots_missing"],
        serde_json::json!([]),
        "the mirror root exists, so nothing may be reported missing: {payload}"
    );
    assert_eq!(
        payload["conversations"], 1,
        "the mirrored session must be ingested exactly once: {payload}"
    );
    assert!(
        payload["messages"].as_u64().is_some_and(|n| n > 0),
        "the mirrored session must bring its messages: {payload}"
    );

    let (conversations, messages) = archive_counts(&env.db_path());
    assert_eq!(
        conversations, 1,
        "the archive must hold the one mirrored conversation"
    );
    assert!(messages > 0, "the archive must hold its messages");
}

/// AC-2 (symlinked data dir): the mirror root and its metadata carry the same
/// canonical path, and the run still ingests.
#[test]
#[serial]
fn symlinked_data_dir_scans_the_canonical_root() {
    let env = Env::new();
    let link = env.root().join("data-link");
    std::os::unix::fs::symlink(&env.data_dir, &link).expect("create data dir symlink");

    env.write_sources_config(&ssh_source_toml("laptop", "~/.codex/sessions"));
    let mirrored = env
        .mirror_root("laptop")
        .join(path_to_safe_dirname("~/.codex/sessions"));
    write_codex_session(&mirrored);

    // Both the run and the root lookup go through the *link*, so the symlink is
    // actually exercised rather than resolved away by the test.
    let payload = env.index_ok_at(&link);
    assert_eq!(
        payload["conversations"], 1,
        "the mirrored session must be ingested through the symlinked data dir: {payload}"
    );
    let (conversations, _) = archive_counts(&env.db_path());
    assert_eq!(conversations, 1, "the archive must hold the conversation");

    // The root the scan reports must be the canonical directory, not the
    // symlinked spelling: the connector and the relative-path base have to
    // name the same tree.
    let (root_path, meta_path) = scan_root_for_at(&env, &link, "laptop");
    let expected = std::fs::canonicalize(&mirrored).expect("canonicalize mirror root");
    assert_eq!(
        root_path, expected,
        "the scan root must be the canonical mirror directory"
    );
    assert_eq!(
        meta_path, expected,
        "the root metadata must carry the same canonical path"
    );
}

/// AC-2 (relative data dir): a relative `--data-dir` still yields an absolute
/// canonical scan root, and the mirrored session is ingested.
#[test]
#[serial]
fn relative_data_dir_scans_the_canonical_root() {
    let env = Env::new();
    let relative = Path::new("relative-data");
    let absolute = env.root().join(relative);
    std::fs::create_dir_all(&absolute).expect("create data dir");

    env.write_sources_config(&ssh_source_toml("laptop", "~/.codex/sessions"));
    let mirrored = absolute
        .join("remotes/laptop/mirror")
        .join(path_to_safe_dirname("~/.codex/sessions"));
    write_codex_session(&mirrored);

    // A relative `--data-dir` is resolved against the process working
    // directory, so the run happens inside the fixture root; the home and
    // config directories stay absolute.
    let (root_path, meta_path) = {
        let _cwd = CwdWindow::enter(env.root());
        let payload = env.index_ok_at(&Path::new("relative-data"));
        assert_eq!(
            payload["conversations"], 1,
            "the mirrored session must be ingested through the relative data dir: {payload}"
        );
        scan_root_for_at(&env, relative, "laptop")
    };
    let (conversations, _) = archive_counts(&absolute.join("agent_search.db"));
    assert_eq!(conversations, 1, "the archive must hold the conversation");

    let expected = std::fs::canonicalize(&mirrored).expect("canonicalize mirror root");
    assert_eq!(
        root_path, expected,
        "a relative data dir must still produce the canonical scan root"
    );
    assert_eq!(
        meta_path, expected,
        "the root metadata must carry the same canonical path"
    );
}

/// AC-3 (legacy only, bare `~`): an older index named this path
/// `root_<h("~/")>`, the `~/`-normalized spelling, and mirrors were written
/// there. With the raw spelling now decided by `~` alone, that directory has to
/// stay readable as the legacy layout.
#[test]
#[serial]
fn bare_tilde_legacy_directory_is_read_when_the_primary_is_absent() {
    let env = Env::new();
    env.write_sources_config(&ssh_source_toml("laptop", "~"));

    let primary = env.mirror_root("laptop").join(path_to_safe_dirname("~"));
    let legacy = env.mirror_root("laptop").join(path_to_safe_dirname("~/"));
    assert_ne!(
        legacy, primary,
        "the raw and the normalized spelling must name different directories, \
         or this test cannot tell them apart"
    );
    write_codex_session(&legacy);

    let payload = env.index_ok();
    assert_eq!(
        payload["conversations"], 1,
        "the legacy layout of a bare `~` must still be indexed: {payload}"
    );
}

/// AC-3 (conflict, bare `~`): the same pair, both present as different trees.
#[test]
#[serial]
fn two_mirror_directories_for_bare_tilde_is_an_error() {
    let env = Env::new();
    env.write_sources_config(&ssh_source_toml("laptop", "~"));

    write_codex_session(&env.mirror_root("laptop").join(path_to_safe_dirname("~")));
    write_codex_session(&env.mirror_root("laptop").join(path_to_safe_dirname("~/")));

    let (code, payload, stderr) = env.index_json();
    assert_ne!(
        code, 0,
        "two mirror directories for a bare `~` must fail the run\n--- stdout ---\n{payload:?}\n--- stderr ---\n{stderr}"
    );
    let payload = payload.expect("a failed `index --json` still prints one JSON object");
    let message = payload["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("mirror-root-ambiguous"),
        "the failure must name the ambiguity: exit {code}\n--- payload ---\n{payload}\n--- stderr ---\n{stderr}"
    );
    let (conversations, _) = archive_counts(&env.db_path());
    assert_eq!(
        conversations, 0,
        "an ambiguous path must not ingest either copy"
    );
}

/// AC-3 (legacy only): when the primary directory is absent but an older
/// layout is present, the older one is still read.
#[test]
#[serial]
fn legacy_candidate_is_read_when_the_primary_is_absent() {
    let env = Env::new();
    env.write_sources_config(&ssh_source_toml("laptop", "~/.codex/sessions"));

    // The pre-pin layout: the directory name derived from the path with the
    // `~/` prefix stripped, which is the suffix `remote_mirror_candidates`
    // searches siblings for.
    let legacy = env
        .mirror_root("laptop")
        .join(path_to_safe_dirname(".codex/sessions"));
    let primary = env
        .mirror_root("laptop")
        .join(path_to_safe_dirname("~/.codex/sessions"));
    assert_ne!(legacy, primary, "the two layouts must be different names");
    write_codex_session(&legacy);

    let payload = env.index_ok();
    assert_eq!(
        payload["conversations"], 1,
        "the legacy mirror directory must still be indexed: {payload}"
    );
    let (conversations, _) = archive_counts(&env.db_path());
    assert_eq!(conversations, 1, "the archive must hold the conversation");
}

/// AC-3 (conflict): when both layouts exist and name different directories,
/// the run fails and names the ambiguity instead of picking one.
#[test]
#[serial]
fn two_mirror_directories_for_one_path_is_an_error() {
    let env = Env::new();
    env.write_sources_config(&ssh_source_toml("laptop", "~/.codex/sessions"));

    let primary = env
        .mirror_root("laptop")
        .join(path_to_safe_dirname("~/.codex/sessions"));
    let legacy = env
        .mirror_root("laptop")
        .join(path_to_safe_dirname(".codex/sessions"));
    write_codex_session(&primary);
    write_codex_session(&legacy);

    let (code, payload, stderr) = env.index_json();
    assert_ne!(
        code, 0,
        "two mirror directories for one path must fail the run\n--- stdout ---\n{payload:?}\n--- stderr ---\n{stderr}"
    );
    let payload = payload.expect("a failed `index --json` still prints one JSON object");
    assert_eq!(
        payload["success"], false,
        "the failure must be reported as a failure: {payload}"
    );
    let message = payload["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("mirror-root-ambiguous"),
        "the failure must name the ambiguity: exit {code}\n--- payload ---\n{payload}\n--- stderr ---\n{stderr}"
    );
    let (conversations, _) = archive_counts(&env.db_path());
    assert_eq!(
        conversations, 0,
        "an ambiguous path must not ingest either copy"
    );
}
