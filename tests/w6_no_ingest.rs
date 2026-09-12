//! PR6 T5 (任务书 #126): `cass index --semantic --no-ingest` -- the T12
//! protocol v2 exam-hall switch (spec §五「考场不拉源」).
//!
//! Two layers, both required by the control plane's #0 ruling:
//!
//! 1. **The counter** (`no_ingest_skips_the_scan_and_leaves_the_corpus_unchanged`)
//!    drives the library entry `indexer::run_index` in-process on a data dir
//!    whose live source root really does hold an un-ingested session, and
//!    asserts `IndexingStats::scan_invocations == 0` plus a byte-unchanged
//!    corpus and an unchanged `meta.last_scan_ts`. It deliberately runs with
//!    `semantic: false` so the whole test is hermetic (no Infinity service):
//!    the CLI separately rejects that combination, and the gate itself is
//!    keyed on `no_ingest` alone.
//! 2. **The CLI contract** (`no_ingest_cli_*`) spawns the real binary and
//!    asserts the four incompatible flags plus the missing `--semantic` all
//!    exit 2 without touching the corpus, and that a compliant invocation
//!    gets all the way to the hole-draining phase (proved by the failure it
//!    then reports being the Infinity probe, not a scan).

mod util;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use coding_agent_search::indexer::{self, IndexOptions, IndexingProgress};
use coding_agent_search::storage::api::Value;
use coding_agent_search::storage::sqlite::FrankenStorage;
use serial_test::serial;
use tempfile::TempDir;
use util::{EnvGuard, seed_codex_session};

/// Nothing listens here; `CASS_INFINITY_URL` pointed at it makes the semantic
/// phase fail at `probe_identity_and_fingerprint`, which is exactly the
/// "we got past the scan phase" evidence the CLI test needs. Same fixture
/// address as `src/search/query.rs`'s unreachable-Infinity test.
const UNREACHABLE_INFINITY: &str = "http://127.0.0.1:1";

struct Fixture {
    tmp: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("cass-data")).expect("data dir");
        Self { tmp }
    }

    fn home(&self) -> PathBuf {
        self.tmp.path().join("home")
    }

    fn codex_home(&self) -> PathBuf {
        self.home().join(".codex")
    }

    fn data_dir(&self) -> PathBuf {
        self.tmp.path().join("cass-data")
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir().join("agent_search.db")
    }

    /// Isolate every connector root and config lookup into the tempdir. The
    /// returned guards restore the process env on drop; callers are annotated
    /// `#[serial]` so no other test in this binary observes the mutation.
    fn isolate(&self) -> Vec<EnvGuard> {
        vec![
            EnvGuard::set("HOME", self.home().to_str().unwrap()),
            EnvGuard::set("CODEX_HOME", self.codex_home().to_str().unwrap()),
            EnvGuard::set("XDG_DATA_HOME", self.tmp.path().join("xdg-data").to_str().unwrap()),
            EnvGuard::set(
                "XDG_CONFIG_HOME",
                self.tmp.path().join("xdg-config").to_str().unwrap(),
            ),
            EnvGuard::set("CASS_IGNORE_SOURCES_CONFIG", "1"),
            EnvGuard::set("CASS_RESPONSIVENESS_DISABLE", "1"),
            EnvGuard::set("CASS_TANTIVY_REBUILD_WORKERS", "1"),
        ]
    }

    /// Write one codex session into the live source root. The connector only
    /// ingests files whose basename starts with `rollout-`.
    fn seed_session(&self, filename: &str, marker: &str) {
        seed_codex_session(&self.codex_home(), filename, marker, true);
    }
}

fn index_opts(
    fixture: &Fixture,
    progress: Arc<IndexingProgress>,
    no_ingest: bool,
) -> IndexOptions {
    IndexOptions {
        full: false,
        force_rebuild: false,
        watch: false,
        watch_once_paths: None,
        db_path: fixture.db_path(),
        data_dir: fixture.data_dir(),
        semantic: false,
        no_ingest,
        embedder: "infinity".to_string(),
        progress: Some(progress),
        watch_interval_secs: 30,
    }
}

fn corpus_counts(db_path: &Path) -> (i64, i64) {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    let conversations = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| row.get_typed(0))
        .expect("count conversations");
    let messages = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))
        .expect("count messages");
    (conversations, messages)
}

fn meta_value(db_path: &Path, key: &str) -> Option<String> {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_row_map(
            "SELECT value FROM meta WHERE key = ?1",
            &[Value::from(key)],
            |row| row.get_typed::<String>(0),
        )
        .ok()
}

fn sessions_matching(db_path: &Path, needle: &str) -> i64 {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM conversations WHERE source_path LIKE ?1",
            &[Value::from(format!("%{needle}%"))],
            |row| row.get_typed(0),
        )
        .expect("count matching conversations")
}

/// The counter assertion. A run whose live source root holds a session the
/// corpus has never seen must still leave `scan_invocations` at 0, the
/// conversation/message counts untouched, and `meta.last_scan_ts` unmoved --
/// i.e. it neither read the sources nor advanced the scan watermark past
/// them.
#[test]
#[serial]
fn no_ingest_skips_the_scan_and_leaves_the_corpus_unchanged() {
    let fixture = Fixture::new();
    let _env = fixture.isolate();
    fixture.seed_session("rollout-first.jsonl", "noingestfirstmarker");

    let baseline = Arc::new(IndexingProgress::default());
    indexer::run_index(index_opts(&fixture, Arc::clone(&baseline), false), None)
        .expect("baseline index run");

    let (conversations_before, messages_before) = corpus_counts(&fixture.db_path());
    assert!(
        conversations_before >= 1,
        "the fixture session must actually be ingested by the baseline run, else this test proves nothing"
    );
    let last_scan_ts_before = meta_value(&fixture.db_path(), "last_scan_ts");

    // A second session appears in the live source root and has never been
    // ingested. A run that scanned would pick it up.
    fixture.seed_session("rollout-second.jsonl", "noingestsecondmarker");

    let guarded = Arc::new(IndexingProgress::default());
    indexer::run_index(index_opts(&fixture, Arc::clone(&guarded), true), None)
        .expect("--no-ingest run");

    let stats = guarded.stats.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        stats.scan_invocations, 0,
        "--no-ingest must not invoke a single connector scan (got {} scan invocation(s))",
        stats.scan_invocations
    );
    assert!(stats.no_ingest, "--json must disclose that this run was --no-ingest");
    drop(stats);

    let (conversations_after, messages_after) = corpus_counts(&fixture.db_path());
    assert_eq!(
        (conversations_after, messages_after),
        (conversations_before, messages_before),
        "--no-ingest must leave the corpus identical"
    );
    assert_eq!(
        sessions_matching(&fixture.db_path(), "rollout-second"),
        0,
        "the un-ingested live session must still be absent from the corpus"
    );
    assert_eq!(
        meta_value(&fixture.db_path(), "last_scan_ts"),
        last_scan_ts_before,
        "--no-ingest must not advance the scan watermark"
    );
}

/// The CLI contract: a compliant invocation reaches the hole-draining phase
/// (proved by which failure it reports) without scanning.
#[test]
#[serial]
fn no_ingest_cli_reaches_the_semantic_phase_without_scanning() {
    let fixture = Fixture::new();
    let _env = fixture.isolate();
    fixture.seed_session("rollout-first.jsonl", "noingestclifirst");
    let home = fixture.home();
    let data_dir = fixture.data_dir();

    let mut baseline = cli(&home);
    baseline.args(["index", "--data-dir"]);
    baseline.arg(&data_dir);
    baseline.output().expect("baseline index run");
    let (conversations_before, messages_before) = corpus_counts(&fixture.db_path());
    assert!(conversations_before >= 1, "baseline run must ingest the fixture");

    fixture.seed_session("rollout-second.jsonl", "noingestclisecond");

    let mut cmd = cli(&home);
    cmd.env("CASS_INFINITY_URL", UNREACHABLE_INFINITY);
    cmd.args(["index", "--data-dir"]);
    cmd.arg(&data_dir);
    cmd.args(["--semantic", "--no-ingest", "--json"]);
    let output = cmd.output().expect("--no-ingest run");
    assert!(
        !output.status.success(),
        "--semantic against an unreachable Infinity must fail: {}",
        output.status
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("cass index --semantic") && combined.to_lowercase().contains("infinity"),
        "the failure must come from the hole-draining phase (Infinity identity probe), not the \
         scan phase -- that is the evidence the scan was skipped. Got: {combined}"
    );

    let (conversations_after, messages_after) = corpus_counts(&fixture.db_path());
    assert_eq!(
        (conversations_after, messages_after),
        (conversations_before, messages_before),
        "--no-ingest must leave the corpus identical even when the semantic phase fails"
    );
    assert_eq!(
        sessions_matching(&fixture.db_path(), "rollout-second"),
        0,
        "the live session must not be ingested by a --no-ingest run"
    );
}

fn cli(home: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("cass"));
    cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
    cmd.env("HOME", home);
    cmd.env("CODEX_HOME", home.join(".codex"));
    cmd.env("XDG_DATA_HOME", home.join(".local/share"));
    cmd.env("XDG_CONFIG_HOME", home.join(".config"));
    cmd
}

/// Each incompatible mode must be rejected with the documented usage error
/// (exit 2) before anything touches the corpus. `--semantic` is supplied so
/// the rejection can only come from the conflict, not from the
/// "requires --semantic" rule.
fn assert_rejected_for(conflict_args: &[&str], expected: &str) {
    let fixture = Fixture::new();
    let home = fixture.home();
    let data_dir = fixture.data_dir();
    let mut cmd = cli(&home);
    cmd.args(["index", "--data-dir"]);
    cmd.arg(&data_dir);
    cmd.args(["--semantic", "--no-ingest"]);
    cmd.args(conflict_args);
    cmd.assert()
        .failure()
        .code(2)
        .stderr(predicates::str::contains(expected));
}

#[test]
fn no_ingest_rejects_watch() {
    assert_rejected_for(&["--watch"], "--no-ingest cannot be combined with --watch");
}

#[test]
fn no_ingest_rejects_watch_once() {
    let fixture = Fixture::new();
    let home = fixture.home();
    let data_dir = fixture.data_dir();
    let mut cmd = cli(&home);
    cmd.args(["index", "--data-dir"]);
    cmd.arg(&data_dir);
    cmd.args(["--semantic", "--no-ingest", "--watch-once"]);
    cmd.arg(fixture.tmp.path().join("some-session.jsonl"));
    cmd.assert().failure().code(2).stderr(predicates::str::contains(
        "--no-ingest cannot be combined with --watch-once",
    ));
}

#[test]
fn no_ingest_rejects_full() {
    assert_rejected_for(&["--full"], "--no-ingest cannot be combined with --full");
}

#[test]
fn no_ingest_rejects_force_rebuild() {
    assert_rejected_for(
        &["--force-rebuild"],
        "--no-ingest cannot be combined with --force-rebuild",
    );
}

#[test]
#[serial]
fn no_ingest_requires_semantic() {
    let fixture = Fixture::new();
    let _env = fixture.isolate();
    let mut cmd = cli(&fixture.home());
    cmd.args(["index", "--data-dir"]);
    cmd.arg(fixture.data_dir());
    cmd.args(["--no-ingest"]);
    cmd.assert()
        .failure()
        .code(2)
        .stderr(predicates::str::contains("--no-ingest requires --semantic"));
}
