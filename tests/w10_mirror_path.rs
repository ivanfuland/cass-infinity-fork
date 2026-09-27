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
//! `build_scan_roots` / `build_scan_roots_with_meta` for the root identity.
//!
//! This file mutates nothing process-global. The environment the scan-root
//! builder needs (`HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`) belongs to the
//! process that calls it, so those checks run in a **child** of this test
//! binary — [`scan_root_helper`], selected by name and handed its environment
//! and working directory through `Command` — and report back as one JSON line.
//! Nothing here calls `set_var`, `remove_var` or `set_current_dir`, so every
//! test is independent of the others and `cargo test`'s default parallelism is
//! reproducible without a serialization lock.

use std::path::{Path, PathBuf};
use std::process::Command;

use coding_agent_search::indexer::build_scan_roots;
use coding_agent_search::sources::config::SourceDefinition;
use coding_agent_search::sources::sync::{SyncEngine, mirror_path_under, path_to_safe_dirname};
use coding_agent_search::storage::sqlite::FrankenStorage;

/// The in-tree codex session fixture: 1 conversation / 3 messages, so a run
/// that ingested it and a run that did not are distinguishable by count.
/// Relative to `tests/fixtures`, as [`fixture_path`] expects.
const CODEX_FIXTURE: &str = "codex_real/sessions/2025/11/25/rollout-test.jsonl";

/// The line [`scan_root_helper`] prints; everything else on its stdout is the
/// test harness's own chatter.
const HELPER_SENTINEL: &str = "W10_SCAN_ROOT_JSON:";

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

/// The source definition the tests' `sources.toml` describes, in the shape the
/// write side is handed.
fn ssh_source(name: &str, path: &str) -> SourceDefinition {
    let mut source = SourceDefinition::ssh(name, name);
    source.paths = vec![path.to_string()];
    source.origin_host = name.to_string();
    source
}

fn ssh_source_toml(name: &str, path: &str) -> String {
    format!(
        "[[sources]]\nname = \"{name}\"\ntype = \"ssh\"\nhost = \"{name}\"\norigin_host = \"{name}\"\npaths = [\"{path}\"]\n"
    )
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

    /// The directory the **write side** mirrors one raw remote path into,
    /// obtained through the production entry points: `prepare_mirror_root`
    /// authorizes and creates the configured mirror root, and
    /// `mirror_path_under` names the per-path directory under it.
    ///
    /// The expectation this satisfies is not the function's return value —
    /// every test that calls it asserts the resulting directory by name.
    fn write_side_mirror_for(&self, source_name: &str, remote_path: &str) -> PathBuf {
        let engine = SyncEngine::new(&self.data_dir);
        let mirror_root = engine
            .prepare_mirror_root(&ssh_source(source_name, remote_path))
            .expect("the configured mirror root must be authorized");
        mirror_path_under(&mirror_root, remote_path)
    }

    /// The mirror root a source with no explicit `mirror_dir` uses.
    fn built_in_mirror_root(&self, source_name: &str) -> PathBuf {
        self.data_dir
            .join("remotes")
            .join(source_name)
            .join("mirror")
    }

    /// The binary under test with a fully private environment. `cmd.env` rather
    /// than process-global `set_var`: a subprocess gets its own copy, so these
    /// tests cannot leak into anything else in this process.
    ///
    /// `CASS_DATA_DIR` is deliberately unset: the `--data-dir` flag decides the
    /// data dir, and an environment fallback behind it would make a relative
    /// `--data-dir` untestable.
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
        self.index_json_in(&self.data_dir, None)
    }

    /// `cass index --json` against `data_dir`, which may be a symlinked or
    /// relative spelling of the same tree. `cwd` is the child's working
    /// directory, needed only when `data_dir` is relative — this process's own
    /// working directory is never moved. Returns the exit code, the stdout JSON
    /// object (`None` when stdout was not one), and stderr.
    fn index_json_in(
        &self,
        data_dir: &Path,
        cwd: Option<&Path>,
    ) -> (i32, Option<serde_json::Value>, String) {
        let data_dir = data_dir.display().to_string();
        let mut cmd = self.cass();
        cmd.args(["index", "--json", "--data-dir", &data_dir]);
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        let out = cmd.output().expect("spawn cass index --json");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        (
            out.status.code().unwrap_or(-1),
            serde_json::from_str::<serde_json::Value>(&stdout).ok(),
            stderr,
        )
    }

    /// Run `cass index --json` against `data_dir` and require success.
    fn index_ok_in(&self, data_dir: &Path, cwd: Option<&Path>) -> serde_json::Value {
        let (code, payload, stderr) = self.index_json_in(data_dir, cwd);
        assert_eq!(
            code, 0,
            "`cass index --json` must succeed, got {code}\n--- stdout ---\n{payload:?}\n--- stderr ---\n{stderr}"
        );
        payload.expect("a successful `index --json` prints one JSON object")
    }

    /// [`Self::index_ok_in`] against `self.data_dir`.
    fn index_ok(&self) -> serde_json::Value {
        self.index_ok_in(&self.data_dir, None)
    }

    /// `(ScanRoot.path, ScanRootMeta.canonical_path)` for `source_name`, as
    /// `build_scan_roots` / `build_scan_roots_with_meta` report them when the
    /// data dir is spelled `data_dir` and the source config is this fixture's.
    ///
    /// Both builders read process-global env vars, so this runs in a child of
    /// this binary; the child is handed everything it needs and the parent is
    /// untouched.
    fn scan_root_paths(&self, data_dir: &Path, cwd: &Path, source_name: &str) -> (PathBuf, PathBuf) {
        let out = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "scan_root_helper",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", self.home.join(".local/share"))
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env("W10_HELPER_DATA_DIR", data_dir)
            .env("W10_HELPER_SOURCE", source_name)
            // A relative `data_dir` resolves against the child's own working
            // directory; `set_current_dir` here would move this process.
            .current_dir(cwd)
            .output()
            .expect("spawn the scan-root helper");

        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        // The harness prints the line as `test <name> ... <output> ok`, so the
        // sentinel is somewhere inside a line rather than at its start.
        let line = stdout
            .lines()
            .find_map(|line| line.split_once(HELPER_SENTINEL).map(|(_, json)| json))
            .unwrap_or_else(|| {
                panic!(
                    "the scan-root helper printed no {HELPER_SENTINEL} line (status {:?})\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
                    out.status
                )
            });
        let payload: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("helper line is not JSON ({e}): {line}"));
        (
            PathBuf::from(payload["scan_root_path"].as_str().expect("scan_root_path")),
            PathBuf::from(payload["canonical_path"].as_str().expect("canonical_path")),
        )
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

/// The scan-root answer for the test that spawned it, printed for the parent to
/// read. Never runs as part of the suite: it is selected by name with
/// `--ignored`, so that the process whose environment it needs is a child that
/// can be given one.
#[test]
#[ignore = "subprocess entry point for the parent tests, not a test of its own"]
fn scan_root_helper() {
    let data_dir = PathBuf::from(std::env::var("W10_HELPER_DATA_DIR").expect("W10_HELPER_DATA_DIR"));
    let source_name = std::env::var("W10_HELPER_SOURCE").expect("W10_HELPER_SOURCE");

    let storage = FrankenStorage::open(&data_dir.join("agent_search.db")).expect("open storage");
    let roots = build_scan_roots(&storage, &data_dir);
    let root = roots
        .iter()
        .find(|root| root.origin.source_id == source_name)
        .unwrap_or_else(|| {
            panic!("source {source_name} must contribute a scan root, got {roots:?}")
        });
    let canonical_path = coding_agent_search::indexer::build_scan_roots_with_meta(&storage, &data_dir)
        .1
        .get_by_path(&root.path)
        .unwrap_or_else(|| panic!("the scan root {} must carry metadata", root.path.display()))
        .canonical_path
        .clone();
    let answer = serde_json::json!({
        "scan_root_path": root.path.display().to_string(),
        "canonical_path": canonical_path.display().to_string(),
    });
    storage
        .close_without_checkpoint()
        .expect("close storage without checkpoint");
    println!("{HELPER_SENTINEL}{answer}");
}

/// AC-1: `paths = ["~"]` mirrors into the directory the raw spelling names,
/// the index selects that same directory, and the in-tree fixture lands in the
/// database.
///
/// The failing baseline is the pair of directory names: the writer names the
/// mirror after `~` and the index looked for `~/`.
#[test]
fn bare_tilde_mirrors_and_indexes_the_same_directory() {
    let env = Env::new();
    env.write_sources_config(&ssh_source_toml("laptop", "~"));

    // The write side: an authorized mirror root from `prepare_mirror_root`,
    // then the per-path directory the sync writer names.
    let mirrored = env.write_side_mirror_for("laptop", "~");
    assert_eq!(
        mirrored,
        env.built_in_mirror_root("laptop")
            .join(path_to_safe_dirname("~")),
        "the write side must name the mirror directory after the raw configured path"
    );
    assert_ne!(
        mirrored.file_name().unwrap(),
        env.built_in_mirror_root("laptop")
            .join(path_to_safe_dirname("~/"))
            .file_name()
            .unwrap(),
        "the two spellings must be different directories, or this test proves nothing"
    );
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
fn symlinked_data_dir_scans_the_canonical_root() {
    let env = Env::new();
    let link = env.root().join("data-link");
    std::os::unix::fs::symlink(&env.data_dir, &link).expect("create data dir symlink");

    env.write_sources_config(&ssh_source_toml("laptop", "~/.codex/sessions"));
    let mirrored = env.write_side_mirror_for("laptop", "~/.codex/sessions");
    assert_eq!(
        mirrored,
        env.built_in_mirror_root("laptop")
            .join(path_to_safe_dirname("~/.codex/sessions")),
        "the write side must name the mirror directory after the raw configured path"
    );
    write_codex_session(&mirrored);

    // Both the run and the root lookup go through the *link*, so the symlink is
    // actually exercised rather than resolved away by the test.
    let payload = env.index_ok_in(&link, None);
    assert_eq!(
        payload["conversations"], 1,
        "the mirrored session must be ingested through the symlinked data dir: {payload}"
    );
    let (conversations, _) = archive_counts(&env.db_path());
    assert_eq!(conversations, 1, "the archive must hold the conversation");

    // The root the scan reports must be the canonical directory, not the
    // symlinked spelling: the connector and the relative-path base have to
    // name the same tree.
    let (root_path, meta_path) = env.scan_root_paths(&link, env.root(), "laptop");
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
fn relative_data_dir_scans_the_canonical_root() {
    let env = Env::new();
    let relative = Path::new("relative-data");
    let absolute = env.root().join(relative);
    std::fs::create_dir_all(&absolute).expect("create data dir");

    // The write side runs against the absolute spelling; the run below reaches
    // the same tree through the relative one.
    let engine = SyncEngine::new(&absolute);
    let mirrored = mirror_path_under(
        &engine
            .prepare_mirror_root(&ssh_source("laptop", "~/.codex/sessions"))
            .expect("the configured mirror root must be authorized"),
        "~/.codex/sessions",
    );
    assert_eq!(
        mirrored,
        absolute
            .join("remotes/laptop/mirror")
            .join(path_to_safe_dirname("~/.codex/sessions")),
        "the write side must name the mirror directory after the raw configured path"
    );
    write_codex_session(&mirrored);
    env.write_sources_config(&ssh_source_toml("laptop", "~/.codex/sessions"));

    // The binary resolves a relative `--data-dir` against its own working
    // directory; the home and config directories stay absolute.
    let payload = env.index_ok_in(relative, Some(env.root()));
    assert_eq!(
        payload["conversations"], 1,
        "the mirrored session must be ingested through the relative data dir: {payload}"
    );
    let (conversations, _) = archive_counts(&absolute.join("agent_search.db"));
    assert_eq!(conversations, 1, "the archive must hold the conversation");

    let (root_path, meta_path) = env.scan_root_paths(relative, env.root(), "laptop");
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
fn bare_tilde_legacy_directory_is_read_when_the_primary_is_absent() {
    let env = Env::new();
    env.write_sources_config(&ssh_source_toml("laptop", "~"));

    let mirror_root = env.built_in_mirror_root("laptop");
    std::fs::create_dir_all(&mirror_root).expect("create mirror root");
    let primary = mirror_root.join(path_to_safe_dirname("~"));
    let legacy = mirror_root.join(path_to_safe_dirname("~/"));
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
fn two_mirror_directories_for_bare_tilde_is_an_error() {
    let env = Env::new();
    env.write_sources_config(&ssh_source_toml("laptop", "~"));

    let mirror_root = env.built_in_mirror_root("laptop");
    std::fs::create_dir_all(&mirror_root).expect("create mirror root");
    write_codex_session(&env.write_side_mirror_for("laptop", "~"));
    write_codex_session(&mirror_root.join(path_to_safe_dirname("~/")));

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
fn legacy_candidate_is_read_when_the_primary_is_absent() {
    let env = Env::new();
    env.write_sources_config(&ssh_source_toml("laptop", "~/.codex/sessions"));

    // The pre-pin layout: the directory name derived from the path with the
    // `~/` prefix stripped, which is the suffix `remote_mirror_candidates`
    // searches siblings for.
    let mirror_root = env.built_in_mirror_root("laptop");
    std::fs::create_dir_all(&mirror_root).expect("create mirror root");
    let legacy = mirror_root.join(path_to_safe_dirname(".codex/sessions"));
    let primary = mirror_root.join(path_to_safe_dirname("~/.codex/sessions"));
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
fn two_mirror_directories_for_one_path_is_an_error() {
    let env = Env::new();
    env.write_sources_config(&ssh_source_toml("laptop", "~/.codex/sessions"));

    let mirror_root = env.built_in_mirror_root("laptop");
    std::fs::create_dir_all(&mirror_root).expect("create mirror root");
    write_codex_session(&env.write_side_mirror_for("laptop", "~/.codex/sessions"));
    write_codex_session(&mirror_root.join(path_to_safe_dirname(".codex/sessions")));

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
