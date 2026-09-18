//! PR8 C3 — per-root scan watermarks and per-file state (spec S2 / hard
//! constraints 4, 5, 6, 12).
//!
//! Every test drives the real `run_index` entry point, twice: once with the
//! streaming scan path (the default, `spawn_connector_producer`) and once with
//! the batch path (`CASS_STREAMING_INDEX=0`). The two paths must follow the
//! same per-root rules (spec R3-B1), so a rule implemented on only one of them
//! fails here.
//!
//! Globals touched, and who else touches them (INV-3):
//! - `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `CLAUDE_CONFIG_DIR`,
//!   `CODEX_HOME`, `CASS_IGNORE_SOURCES_CONFIG` and `CASS_STREAMING_INDEX` are
//!   process-global. Every test takes `ENV_SERIAL`, and `EnvWindow` restores
//!   each variable (including removing one that was previously unset) when it
//!   drops — the window covers the index run, never an assertion.
//! - Each test owns its own `TempDir`, database and fixture tree; no static,
//!   shared file or fixed path is shared between tests.
//!
//! Scope boundary, stated so the report can be read honestly: these tests
//! exercise the scan paths, the watermark/file-state rows and the ingest
//! identity they produce. The `home_scan_roots` parity check is the one case
//! that compares CASS's own root resolution against the connector's, because
//! `Connector` exposes no root list to compare against directly.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use serial_test::serial;

use coding_agent_search::indexer::scan_root_meta;
use coding_agent_search::indexer::{IndexOptions, run_index};
use coding_agent_search::sources::sync::path_to_safe_dirname;

const STREAMING_ENV: &str = "CASS_STREAMING_INDEX";

/// The connector registry name for claude_code. The registry key is `claude`
/// (the franken slug); `claude_code` is the agent slug the ingests carry.
const CLAUDE_CONNECTOR: &str = "claude";

static ENV_SERIAL: Mutex<()> = Mutex::new(());

/// Set process-global variables for one index run, restoring every previous
/// value on drop (including removing a variable that was unset before).
struct EnvWindow {
    saved: Vec<(String, Option<OsString>)>,
}

impl EnvWindow {
    fn apply(pairs: &[(&str, Option<&Path>)]) -> Self {
        let saved = pairs
            .iter()
            .map(|(key, _)| ((*key).to_string(), std::env::var_os(key)))
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
        Self { saved }
    }
}

impl Drop for EnvWindow {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            // SAFETY: as in `apply`.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(&key, value),
                    None => std::env::remove_var(&key),
                }
            }
        }
    }
}

/// Run `body` once per scan path: streaming (the default) and batch.
fn for_each_scan_path(mut body: impl FnMut(bool)) {
    for streaming in [true, false] {
        let _guard = ENV_SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
        let saved = std::env::var_os(STREAMING_ENV);
        // SAFETY: the window is covered by `ENV_SERIAL`, restored below.
        unsafe {
            if streaming {
                std::env::remove_var(STREAMING_ENV);
            } else {
                std::env::set_var(STREAMING_ENV, "0");
            }
        }
        body(streaming);
        // SAFETY: as above; the window ends here.
        unsafe {
            match saved {
                Some(value) => std::env::set_var(STREAMING_ENV, value),
                None => std::env::remove_var(STREAMING_ENV),
            }
        }
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    config_home: PathBuf,
    data_dir: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let root = dir.path().to_path_buf();
        let home = root.join(format!("home-{tag}"));
        let config_home = root.join(format!("config-{tag}"));
        let data_dir = root.join(format!("data-{tag}"));
        for path in [&home, &config_home, &data_dir] {
            std::fs::create_dir_all(path).expect("create fixture dir");
        }
        Self {
            _dir: dir,
            root,
            home,
            config_home,
            data_dir,
        }
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir.join("agent_search.db")
    }

    /// A home root (`~/.claude/projects/<project>/<file>`) holding the real
    /// claude_code fixture.
    fn claude_home_session(&self, project: &str, file: &str) -> PathBuf {
        let path = self
            .home
            .join(".claude")
            .join("projects")
            .join(project)
            .join(file);
        write_claude_fixture(&path);
        path
    }

    /// A home root (`~/.codex/sessions/<relative>`) holding a real codex
    /// rollout fixture.
    fn codex_home_session(&self, relative: &str) -> PathBuf {
        let path = self.home.join(".codex").join("sessions").join(relative);
        write_codex_fixture(&path);
        path
    }

    fn write_sources_config(&self, toml: &str) {
        let path = self.config_home.join("cass/sources.toml");
        std::fs::create_dir_all(path.parent().expect("config dir")).expect("mkdir config");
        std::fs::write(&path, toml).expect("write sources.toml");
    }

    /// Run one index. `claude_config_dir` / `codex_home` redirect that
    /// connector's own roots; `HOME` stays the fixture home unless the caller
    /// asks otherwise (see [`Self::index_as`]).
    fn index(&self, full: bool, claude_config_dir: Option<&Path>, codex_home: Option<&Path>) {
        self.index_with_home(&self.home, full, claude_config_dir, codex_home);
    }

    fn index_with_home(
        &self,
        home: &Path,
        full: bool,
        claude_config_dir: Option<&Path>,
        codex_home: Option<&Path>,
    ) {
        assert!(
            self.try_index_with_home(home, full, claude_config_dir, codex_home),
            "index run must complete"
        );
    }

    /// Run one index and report whether it completed. `run_index` returns an
    /// error when a connector's scan failed (R2-B1), which is exactly the
    /// signal a test about failing connectors needs to observe.
    fn try_index_with_home(
        &self,
        home: &Path,
        full: bool,
        claude_config_dir: Option<&Path>,
        codex_home: Option<&Path>,
    ) -> bool {
        let _env = EnvWindow::apply(&[
            ("HOME", Some(home)),
            ("XDG_CONFIG_HOME", Some(&self.config_home)),
            ("XDG_DATA_HOME", Some(&home.join(".local/share"))),
            ("CLAUDE_CONFIG_DIR", claude_config_dir),
            ("CODEX_HOME", codex_home),
            ("CASS_IGNORE_SOURCES_CONFIG", None),
        ]);
        run_index(
            IndexOptions {
                no_ingest: false,
                full,
                force_rebuild: false,
                watch: false,
                watch_once_paths: None,
                db_path: self.db_path(),
                data_dir: self.data_dir.clone(),
                semantic: false,
                embedder: "fastembed".to_string(),
                progress: None,
                watch_interval_secs: 30,
            },
            None,
        )
        .is_ok()
    }

    fn try_index(
        &self,
        full: bool,
        claude_config_dir: Option<&Path>,
        codex_home: Option<&Path>,
    ) -> bool {
        self.try_index_with_home(&self.home, full, claude_config_dir, codex_home)
    }
}

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative)
}

fn write_claude_fixture(dest: &Path) {
    std::fs::create_dir_all(dest.parent().expect("parent")).expect("mkdir");
    std::fs::copy(
        fixture_path("claude_code_real/projects/-test-project/agent-test123.jsonl"),
        dest,
    )
    .expect("copy claude fixture");
}

fn write_codex_fixture(dest: &Path) {
    std::fs::create_dir_all(dest.parent().expect("parent")).expect("mkdir");
    std::fs::copy(
        fixture_path("codex_real/sessions/2025/11/25/rollout-test.jsonl"),
        dest,
    )
    .expect("copy codex fixture");
}

/// Set a file's mtime, so a test can present history whose timestamp is older
/// than a watermark without waiting for the clock.
fn set_mtime(path: &Path, mtime: SystemTime) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for mtime");
    file.set_modified(mtime).expect("set mtime");
}

fn open_db(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).expect("open db")
}

fn conversation_count(db: &Path) -> i64 {
    open_db(db)
        .query_row("SELECT COUNT(*) FROM conversations", [], |row| row.get(0))
        .expect("count conversations")
}

fn message_count(db: &Path) -> i64 {
    open_db(db)
        .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
        .expect("count messages")
}

/// `root_id -> last_scan_ts` for the roots whose id matches `prefix`.
fn watermarks(db: &Path, prefix: &str) -> BTreeMap<String, i64> {
    let conn = open_db(db);
    let mut stmt = conn
        .prepare(
            "SELECT root_id, connector, last_scan_ts FROM scan_watermarks
             WHERE root_id LIKE ?1 ORDER BY root_id, connector",
        )
        .expect("prepare");
    let rows = stmt
        .query_map([format!("{prefix}%")], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows");
    rows.into_iter()
        .map(|(root_id, connector, ts)| (format!("{root_id}|{connector}"), ts))
        .collect()
}

/// `(root_id, connector) -> [(relative_path, size)]`.
fn file_states(db: &Path, root_prefix: &str) -> BTreeMap<String, Vec<(String, i64)>> {
    let conn = open_db(db);
    let mut stmt = conn
        .prepare(
            "SELECT root_id, connector, relative_path, size FROM scan_file_state
             WHERE root_id LIKE ?1 ORDER BY root_id, connector, relative_path",
        )
        .expect("prepare");
    let rows = stmt
        .query_map([format!("{root_prefix}%")], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows");

    let mut out: BTreeMap<String, Vec<(String, i64)>> = BTreeMap::new();
    for (root_id, connector, relative_path, size) in rows {
        out.entry(format!("{root_id}|{connector}"))
            .or_default()
            .push((relative_path, size));
    }
    out
}

/// AC-1: a fake home's `--full` does not move the real home's watermark, and
/// the real home still ingests history the fake home's scan never covered.
#[test]
#[serial]
fn fake_home_full_does_not_touch_real_home() {
    for_each_scan_path(|_streaming| {
        let fixture = Fixture::new("fake-home");
        fixture.claude_home_session("-real", "agent-b.jsonl");

        // The real home scans first and records its own watermark.
        let real_home_root_id = {
            let real_home_root = fixture.home.join(".claude/projects");
            let canonical = std::fs::canonicalize(&real_home_root).expect("canonicalize home root");
            scan_root_meta::home_root_id(CLAUDE_CONNECTOR, &canonical)
        };
        fixture.index(true, None, None);
        let before = watermarks(&fixture.db_path(), "home:claude:");
        let real_before = before.get(&format!("{real_home_root_id}|{CLAUDE_CONNECTOR}")).copied();
        assert!(
            real_before.is_some(),
            "the real home root {real_home_root_id} must have its own watermark row, got {before:?}"
        );

        // A fake home, addressed through CLAUDE_CONFIG_DIR, scans with --full.
        let fake = fixture.root.join("fake-a");
        write_claude_fixture(&fake.join("projects/-fake/agent-a.jsonl"));
        fixture.index(true, Some(&fake), None);

        let after = watermarks(&fixture.db_path(), "home:claude:");
        let real_after = after.get(&format!("{real_home_root_id}|{CLAUDE_CONNECTOR}")).copied();
        assert_eq!(
            real_before, real_after,
            "a --full scan of the fake home must not move the real home's watermark ({before:?} -> {after:?})"
        );

        // History in the real home whose mtime predates the fake home's scan,
        // and whose size equals one of the fake home's files, must still be
        // ingested by the next incremental run.
        let history = fixture.home.join(".claude/projects/-real/agent-b-history.jsonl");
        write_claude_fixture(&history);
        let fake_size = std::fs::metadata(fake.join("projects/-fake/agent-a.jsonl"))
            .expect("fake fixture metadata")
            .len();
        assert_eq!(
            std::fs::metadata(&history).expect("history metadata").len(),
            fake_size,
            "the historical file must have the same size as one of the fake home's files"
        );
        set_mtime(&history, SystemTime::now() - Duration::from_secs(3_600));

        let before_count = conversation_count(&fixture.db_path());
        fixture.index(false, None, None);
        assert!(
            conversation_count(&fixture.db_path()) > before_count,
            "the real home must ingest the historical session (before {before_count})"
        );
    });
}

/// AC-2: each configured `paths` entry is its own root, and a path added later
/// has no watermark, so its older history is ingested.
#[test]
#[serial]
fn each_config_path_has_own_root_id() {
    for_each_scan_path(|_streaming| {
        let fixture = Fixture::new("config-paths");
        let first = fixture.root.join("path-one");
        let second = fixture.root.join("path-two");
        write_claude_fixture(&first.join("projects/-p1/agent-one.jsonl"));
        write_claude_fixture(&second.join("projects/-p2/agent-two.jsonl"));

        fixture.write_sources_config(&format!(
            "[[sources]]\nname = \"laptop\"\ntype = \"local\"\norigin_host = \"laptop\"\npaths = [\"{}\"]\n",
            first.display()
        ));
        fixture.index(true, None, None);

        // The second path is registered afterwards, exactly like a path added
        // to sources.toml later, and its session carries an mtime older than
        // the first scan.
        set_mtime(
            &second.join("projects/-p2/agent-two.jsonl"),
            SystemTime::now() - Duration::from_secs(3_600),
        );
        fixture.write_sources_config(&format!(
            "[[sources]]\nname = \"laptop\"\ntype = \"local\"\norigin_host = \"laptop\"\npaths = [\"{}\", \"{}\"]\n",
            first.display(),
            second.display()
        ));

        let before_count = conversation_count(&fixture.db_path());
        fixture.index(false, None, None);
        assert!(
            conversation_count(&fixture.db_path()) > before_count,
            "the second path's older session must be ingested (before {before_count})"
        );

        let rows = watermarks(&fixture.db_path(), "cfg:laptop:");
        let root_ids: std::collections::BTreeSet<&str> = rows
            .keys()
            .filter_map(|key| key.split('|').next())
            .collect();
        assert_eq!(
            root_ids.len(),
            2,
            "two configured paths must produce two root ids, got {rows:?}"
        );
    });
}

/// AC-3: a file whose size changed while its mtime did not is read again, and
/// two roots holding identically named files do not judge each other's size.
#[test]
#[serial]
fn size_change_forces_reread() {
    for_each_scan_path(|_streaming| {
        let fixture = Fixture::new("size-change");
        let first = fixture.root.join("root-one");
        let second = fixture.root.join("root-two");
        // Same relative path under both roots, different content lengths.
        write_claude_fixture(&first.join("projects/-p/agent-same.jsonl"));
        write_claude_fixture(&second.join("projects/-p/agent-same.jsonl"));

        fixture.write_sources_config(&format!(
            "[[sources]]\nname = \"two-roots\"\ntype = \"local\"\norigin_host = \"local\"\npaths = [\"{}\", \"{}\"]\n",
            first.display(),
            second.display()
        ));
        fixture.index(true, None, None);

        let relative = "projects/-p/agent-same.jsonl";
        let first_file = first.join(relative);
        let second_size_before = std::fs::metadata(second.join(relative))
            .expect("second fixture metadata")
            .len();

        // Rewrite the first root's file with more bytes, then put its mtime
        // back where it was: only the size differs.
        let original_mtime = std::fs::metadata(&first_file)
            .expect("first fixture metadata")
            .modified()
            .expect("mtime");
        let mut content = std::fs::read_to_string(&first_file).expect("read fixture");
        content.push_str(
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"appended turn\"}}\n",
        );
        std::fs::write(&first_file, content).expect("rewrite fixture");
        // Older than the root's watermark, so only the size comparison and the
        // `since_ts = 0` bypass can bring it back into the scan.
        assert!(
            original_mtime < SystemTime::now(),
            "the fixture mtime must be in the past"
        );
        set_mtime(&first_file, SystemTime::now() - Duration::from_secs(3_600));
        let rewritten_size = std::fs::metadata(&first_file)
            .expect("rewritten fixture metadata")
            .len();

        let messages_before = message_count(&fixture.db_path());
        fixture.index(false, None, None);
        assert!(
            message_count(&fixture.db_path()) > messages_before,
            "a size-only change must force a re-read (messages before {messages_before})"
        );

        // The two roots are named by their derived ids, so the sizes can be
        // attributed to the root that actually changed.
        let first_id = scan_root_meta::config_root_id(
            "two-roots",
            &std::fs::canonicalize(&first).expect("canonicalize first root"),
        );
        let second_id = scan_root_meta::config_root_id(
            "two-roots",
            &std::fs::canonicalize(&second).expect("canonicalize second root"),
        );
        assert_ne!(first_id, second_id, "two paths are two roots");

        let states = file_states(&fixture.db_path(), "cfg:two-roots:");
        let size_of = |root_id: &str| -> Option<i64> {
            states
                .get(&format!("{root_id}|{CLAUDE_CONNECTOR}"))
                .and_then(|entries| {
                    entries
                        .iter()
                        .find(|(path, _)| path == relative)
                        .map(|(_, size)| *size)
                })
        };
        assert_eq!(
            size_of(&first_id),
            Some(rewritten_size as i64),
            "the changed root records the new size, got {states:?}"
        );
        assert_eq!(
            size_of(&second_id),
            Some(second_size_before as i64),
            "the untouched root must keep recording its own size, got {states:?}"
        );
        assert_ne!(
            size_of(&first_id),
            size_of(&second_id),
            "the two roots' identical relative paths must not share one size"
        );
    });
}

/// AC-4: a connector whose scan fails writes neither its watermark nor its file
/// state for that root.
#[test]
#[serial]
fn connector_error_keeps_watermark() {
    for_each_scan_path(|_streaming| {
        let fixture = Fixture::new("connector-error");
        let root = fixture.root.join("error-root");
        // The claude fixture plus one `turn_context` line codex cannot parse:
        // claude_code reads the file fine, codex's scan fails on it.
        let session = root.join("projects/-p/rollout-poisoned.jsonl");
        write_claude_fixture(&session);
        let mut content = std::fs::read_to_string(&session).expect("read fixture");
        content.push_str(
            "{\"timestamp\":\"2025-01-01T00:00:00Z\",\"type\":\"turn_context\",\"payload\":{}}\n",
        );
        std::fs::write(&session, content).expect("write poisoned fixture");

        fixture.write_sources_config(&format!(
            "[[sources]]\nname = \"error-root\"\ntype = \"local\"\norigin_host = \"local\"\npaths = [\"{}\"]\n",
            root.display()
        ));
        assert!(
            !fixture.try_index(true, None, None),
            "a connector whose scan failed must fail the run (that is how run_index reports it)"
        );

        let watermark_rows = watermarks(&fixture.db_path(), "cfg:error-root:");
        assert!(
            watermark_rows
                .keys()
                .any(|key| key.ends_with("|claude")),
            "the successful connector must advance its watermark, got {watermark_rows:?}"
        );
        assert!(
            !watermark_rows.keys().any(|key| key.ends_with("|codex")),
            "a failed connector's watermark must not advance, got {watermark_rows:?}"
        );
        let states = file_states(&fixture.db_path(), "cfg:error-root:");
        assert!(
            !states.keys().any(|key| key.ends_with("|codex")),
            "a failed connector must not record file state, got {states:?}"
        );
    });
}

/// AC-5: a new root is scanned in full — the missing-watermark bootstrap is
/// gone, so its (large) database size cannot make it skip history.
#[test]
#[serial]
fn new_root_never_bootstraps() {
    for_each_scan_path(|_streaming| {
        let fixture = Fixture::new("no-bootstrap");
        let root = fixture.root.join("history-root");
        write_claude_fixture(&root.join("projects/-old/agent-old.jsonl"));
        set_mtime(
            &root.join("projects/-old/agent-old.jsonl"),
            SystemTime::now() - Duration::from_secs(86_400),
        );

        fixture.write_sources_config(&format!(
            "[[sources]]\nname = \"history\"\ntype = \"local\"\norigin_host = \"local\"\npaths = [\"{}\"]\n",
            root.display()
        ));

        // Populate the database first, so the incremental run below starts
        // from a populated archive rather than an empty one.
        fixture.index(true, None, None);
        let seed = conversation_count(&fixture.db_path());
        assert!(seed > 0, "the fixture must ingest at least one session");

        // A second, brand new root: no watermark row exists for it. The
        // thresholds the old bootstrap read are irrelevant now — even a tiny
        // database must scan the whole root.
        let fresh = fixture.root.join("fresh-root");
        write_claude_fixture(&fresh.join("projects/-fresh/agent-fresh.jsonl"));
        set_mtime(
            &fresh.join("projects/-fresh/agent-fresh.jsonl"),
            SystemTime::now() - Duration::from_secs(172_800),
        );
        fixture.write_sources_config(&format!(
            "[[sources]]\nname = \"history\"\ntype = \"local\"\norigin_host = \"local\"\npaths = [\"{}\", \"{}\"]\n",
            root.display(),
            fresh.display()
        ));
        fixture.index(false, None, None);

        let rows = watermarks(&fixture.db_path(), "cfg:history:");
        let root_ids: std::collections::BTreeSet<&str> = rows
            .keys()
            .filter_map(|key| key.split('|').next())
            .collect();
        assert_eq!(
            root_ids.len(),
            2,
            "the new root must be scanned and get its own row, got {rows:?}"
        );
        assert!(
            conversation_count(&fixture.db_path()) > seed,
            "the new root's history must be ingested (seed {seed})"
        );
    });
}

/// AC-6: ssh mirror roots and `full_scan` sources keep scanning the whole root,
/// so a file whose mtime predates the watermark is still ingested.
#[test]
#[serial]
fn mirror_and_full_scan_roots_ignore_watermark() {
    for_each_scan_path(|_streaming| {
        let fixture = Fixture::new("mirror-full-scan");
        let mirror_base = fixture.root.join("mirror-base");
        // `build_scan_roots` mirrors a configured path under
        // `<mirror_dir>/<safe_dirname(path)>`; the fixture must land exactly
        // where the scan root points or the test would pass by scanning
        // nothing.
        let mirror_root = mirror_base.join(path_to_safe_dirname("~/.claude/projects"));
        let mirror_session = mirror_root.join("projects/-m/agent-m.jsonl");
        write_claude_fixture(&mirror_session);

        // An ssh source whose mirror is this directory: remote roots scan in
        // full because the synced files carry the other machine's mtime.
        fixture.write_sources_config(&format!(
            "[[sources]]\nname = \"ivanmac\"\ntype = \"ssh\"\nhost = \"ivanmac\"\norigin_host = \"ivanmac\"\npaths = [\"~/.claude/projects\"]\nmirror_dir = \"{}\"\n",
            mirror_base.display()
        ));
        fixture.index(true, None, None);
        assert!(
            conversation_count(&fixture.db_path()) > 0,
            "the mirror fixture must be ingested before the incremental claim is meaningful"
        );

        // A new file inside the mirror whose mtime is older than this run's
        // watermark must still be picked up by the next incremental run.
        let late = mirror_root.join("projects/-m/agent-late.jsonl");
        write_claude_fixture(&late);
        set_mtime(&late, SystemTime::now() - Duration::from_secs(7_200));

        let before_count = conversation_count(&fixture.db_path());
        fixture.index(false, None, None);
        assert!(
            conversation_count(&fixture.db_path()) > before_count,
            "a mirror root must be scanned in full on every run (before {before_count})"
        );

        // A `full_scan` local source behaves the same way.
        let local = fixture.root.join("full-scan-root");
        write_claude_fixture(&local.join("projects/-f/agent-f.jsonl"));
        fixture.write_sources_config(&format!(
            "[[sources]]\nname = \"ivanmac\"\ntype = \"ssh\"\nhost = \"ivanmac\"\norigin_host = \"ivanmac\"\npaths = [\"~/.claude/projects\"]\nmirror_dir = \"{}\"\n\n[[sources]]\nname = \"backup\"\ntype = \"local\"\norigin_host = \"backup\"\nfull_scan = true\npaths = [\"{}\"]\n",
            mirror_base.display(),
            local.display()
        ));
        fixture.index(true, None, None);
        let backup = local.join("projects/-f/agent-backup.jsonl");
        write_claude_fixture(&backup);
        set_mtime(&backup, SystemTime::now() - Duration::from_secs(10_800));

        let before_backup = conversation_count(&fixture.db_path());
        fixture.index(false, None, None);
        assert!(
            conversation_count(&fixture.db_path()) > before_backup,
            "a full_scan source must be scanned in full on every run (before {before_backup})"
        );
        assert!(
            watermarks(&fixture.db_path(), "cfg:backup:").is_empty(),
            "a full_scan source must not keep per-root watermarks"
        );
        assert!(
            watermarks(&fixture.db_path(), "cfg:ivanmac:").is_empty(),
            "an ssh mirror root must not keep per-root watermarks either"
        );
    });
}

/// AC-7: the legacy global `last_scan_ts` is still readable and still drives
/// the staleness signal it always drove, but schema 7 never writes it again.
#[test]
#[serial]
fn legacy_global_watermark_readonly() {
    for_each_scan_path(|_streaming| {
        let fixture = Fixture::new("legacy-global");
        fixture.claude_home_session("-real", "agent-legacy.jsonl");

        fixture.index(true, None, None);
        let db = fixture.db_path();
        assert!(
            conversation_count(&db) > 0,
            "the run must ingest the fixture session"
        );

        // Seed the legacy row the way a pre-PR8 binary left it.
        let legacy_ts = 1_700_000_000_000i64;
        {
            let conn = open_db(&db);
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('last_scan_ts', ?1)",
                [legacy_ts.to_string()],
            )
            .expect("seed legacy watermark");
        }

        fixture.index(false, None, None);
        let stored: Option<String> = open_db(&db)
            .query_row(
                "SELECT value FROM meta WHERE key = 'last_scan_ts'",
                [],
                |row| row.get(0),
            )
            .ok();
        assert_eq!(
            stored.as_deref(),
            Some(legacy_ts.to_string().as_str()),
            "schema 7 must not overwrite the legacy global watermark"
        );

        // Still readable through the same call `status --json` uses.
        let storage = coding_agent_search::storage::sqlite::FrankenStorage::open(&db)
            .expect("open storage");
        assert_eq!(
            storage.get_last_scan_ts().expect("read legacy watermark"),
            Some(legacy_ts)
        );

        // And the per-root rows are what actually moved.
        assert!(
            !watermarks(&db, "home:claude:").is_empty(),
            "the same run must advance a per-root watermark instead"
        );
    });
}

/// AC-8: file state is per connector — one connector's success must not erase
/// another connector's pending re-read of the same file.
#[test]
#[serial]
fn file_state_is_per_connector() {
    for_each_scan_path(|_streaming| {
        let fixture = Fixture::new("per-connector-state");
        let root = fixture.root.join("shared-root");
        let session = root.join("projects/-p/rollout-shared.jsonl");
        // Discovered by both connectors (claude takes any `.jsonl`, codex takes
        // `rollout-*.jsonl`) and parsed cleanly by both, so the first run
        // records state for each of them.
        let claude_fixture = fixture_path("claude_code_real/projects/-test-project/agent-test123.jsonl");
        std::fs::create_dir_all(session.parent().expect("parent")).expect("mkdir");
        std::fs::copy(&claude_fixture, &session).expect("copy claude fixture");

        fixture.write_sources_config(&format!(
            "[[sources]]\nname = \"shared\"\ntype = \"local\"\norigin_host = \"local\"\npaths = [\"{}\"]\n",
            root.display()
        ));
        assert!(
            fixture.try_index(true, None, None),
            "the first run must be clean for both connectors"
        );

        let states = file_states(&fixture.db_path(), "cfg:shared:");
        assert!(
            states.keys().any(|key| key.ends_with("|codex")),
            "the first run must record codex file state, got {states:?}"
        );
        assert!(
            states.keys().any(|key| key.ends_with("|claude")),
            "the first run must record claude_code file state, got {states:?}"
        );

        // Now make the file unreadable to codex only (`turn_context` without a
        // model) while its size changes and its mtime stays put, then run
        // again: claude_code succeeds and records the new size, codex fails
        // and must keep its own stale record.
        let mtime = std::fs::metadata(&session)
            .expect("metadata")
            .modified()
            .expect("mtime");
        let mut content = std::fs::read_to_string(&session).expect("read fixture");
        content.push_str(
            "{\"timestamp\":\"2025-01-01T00:00:00Z\",\"type\":\"turn_context\",\"payload\":{}}\n",
        );
        std::fs::write(&session, content).expect("rewrite fixture");
        set_mtime(&session, mtime);
        let poisoned_size = std::fs::metadata(&session).expect("metadata").len() as i64;

        assert!(
            !fixture.try_index(false, None, None),
            "codex's scan failure must fail the run"
        );

        let after = file_states(&fixture.db_path(), "cfg:shared:");
        let codex_rows: Vec<&(String, i64)> = after
            .iter()
            .filter(|(key, _)| key.ends_with("|codex"))
            .flat_map(|(_, entries)| entries.iter())
            .filter(|(path, _)| path == "projects/-p/rollout-shared.jsonl")
            .collect();
        let claude_rows: Vec<&(String, i64)> = after
            .iter()
            .filter(|(key, _)| key.ends_with("|claude"))
            .flat_map(|(_, entries)| entries.iter())
            .filter(|(path, _)| path == "projects/-p/rollout-shared.jsonl")
            .collect();
        assert_eq!(codex_rows.len(), 1, "codex keeps one row, got {after:?}");
        assert_eq!(
            claude_rows.len(),
            1,
            "claude_code keeps one row, got {after:?}"
        );
        assert_eq!(
            claude_rows[0].1, poisoned_size,
            "the successful connector records the new size"
        );
        assert_ne!(
            codex_rows[0].1, poisoned_size,
            "the failed connector must keep its own record, not adopt the other connector's"
        );
    });
}

/// AC-9: `home_scan_roots` covers every path the connector itself would read,
/// and the env overrides decide which root that is.
#[test]
#[serial]
fn home_scan_roots_parity() {
    for_each_scan_path(|_streaming| {
        let fixture = Fixture::new("parity");
        let alternate = fixture.root.join("alternate-claude");
        write_claude_fixture(&alternate.join("projects/-alt/agent-alt.jsonl"));

        // With `CLAUDE_CONFIG_DIR` set, both the connector's own resolution and
        // `home_scan_roots` must point at that one root — and only at it.
        {
            let _env = EnvWindow::apply(&[
                ("HOME", Some(&fixture.home)),
                ("XDG_CONFIG_HOME", Some(&fixture.config_home)),
                ("CLAUDE_CONFIG_DIR", Some(&alternate)),
                ("CODEX_HOME", None),
            ]);
            let roots = scan_root_meta::home_scan_roots("claude_code");
            assert_eq!(
                roots,
                vec![alternate.join("projects")],
                "CLAUDE_CONFIG_DIR must win and be the only root"
            );
        }

        // Without the override, the home root is the one the connector scans.
        {
            let home = fixture.home.join(".claude/projects");
            write_claude_fixture(&home.join("-home/agent-home.jsonl"));
            let _env = EnvWindow::apply(&[
                ("HOME", Some(&fixture.home)),
                ("XDG_CONFIG_HOME", Some(&fixture.config_home)),
                ("CLAUDE_CONFIG_DIR", None),
                ("CODEX_HOME", None),
            ]);
            let roots = scan_root_meta::home_scan_roots("claude_code");
            assert!(
                roots.contains(&home),
                "the home root must be among the resolved roots, got {roots:?}"
            );

            // Everything the connector discovers under this home is under one
            // of the roots C3 watermarks.
            let connector = coding_agent_search::connectors::get_connector_factories()
                .into_iter()
                .find(|(name, _)| *name == CLAUDE_CONNECTOR)
                .map(|(_, factory)| factory())
                .expect("claude_code connector");
            let ctx = coding_agent_search::connectors::ScanContext::with_roots(
                fixture.data_dir.clone(),
                roots
                    .iter()
                    .cloned()
                    .map(coding_agent_search::connectors::ScanRoot::local)
                    .collect(),
                None,
            );
            let discovered = connector
                .discover_source_files(&ctx)
                .expect("discover claude sources");
            assert!(
                !discovered.is_empty(),
                "the fixture home must yield discoverable sources"
            );
            for source in discovered {
                assert!(
                    roots.iter().any(|root| source.source_path.starts_with(root)),
                    "discovered {} is not under any home_scan_roots root {roots:?}",
                    source.source_path.display()
                );
            }

            // Codex resolves through CODEX_HOME / `$HOME/.codex` the same way.
            let codex_home = fixture.root.join("codex-home");
            std::fs::create_dir_all(codex_home.join("sessions")).expect("mkdir codex sessions");
            let _env = EnvWindow::apply(&[
                ("HOME", Some(&fixture.home)),
                ("CODEX_HOME", Some(&codex_home)),
            ]);
            assert_eq!(
                scan_root_meta::home_scan_roots("codex"),
                vec![codex_home.join("sessions")],
                "CODEX_HOME's sessions dir must be the codex root"
            );
        }
    });
}
