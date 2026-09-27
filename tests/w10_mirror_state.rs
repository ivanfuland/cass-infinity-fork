//! PR10 task 04 — an explicit ssh mirror root commits its scan state as one
//! transaction.
//!
//! Task 03 gave a configured `type = "ssh"` root the per-root watermark and
//! per-file state a local root keeps, and its own comparison rule. What it left
//! in place is the *write* side: the baseline writes each row on its own,
//! never clears the state of a path that disappeared, and turns a storage
//! failure into a `tracing::warn!` while still returning `Ok`. For a mirror
//! that is the difference between "the far machine deleted that session" and
//! "this machine silently believes it already read it" — the reappearing file
//! is never handed to the connector again.
//!
//! The transaction under test (spec hard constraint 11) is: on a clean scan of
//! an explicit ssh mirror root, drop the recorded paths the enumeration did not
//! find, write the files this run parsed, and advance the watermark — all for
//! one `(root_id, connector)`, all in one transaction, with a failure reaching
//! `cass index`'s exit code instead of a log line.
//!
//! Every observation comes from the real binary (`cass index --json`, its
//! per-run connector statistics, its exit code and the database it wrote) plus
//! the crate's own storage layer read back independently. Both scan paths run,
//! via `Command::env` rather than `set_var`, so each test owns its own
//! `TempDir`, HOME, config root, data dir and database and `cargo test`'s
//! default parallelism stays reproducible.
//!
//! `codex` is disabled in `sources.toml` on purpose and its rows are seeded by
//! hand: nothing in the run can legitimately write them, so any change to them
//! is the root-wide clear this task must not do
//! (`clear_scan_file_state_for_root` drops every connector's rows for a root).
//!
//! That scoping is not a formality. Every *enabled* connector — around twenty
//! of them, the configured root is built for all of them — scans this mirror
//! root on every run and discovers nothing in it, so each one commits a
//! transaction over an empty enumeration. A commit that forgot its `connector`
//! predicate would therefore reach into the other connectors' rows on its own,
//! with no help from the test: the isolation assertions here fail as soon as
//! the same `root_id` is cleared by a connector that found no files at all.
//!
//! Scope boundary, stated so the report can be read honestly: this file proves
//! the commit, the rollback and the connector scoping. It does not cover the
//! rsync publication guarantee (task 02), the mirror-root derivation rules
//! (task 01) or the `cass sync` entry point (tasks 05/06).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use coding_agent_search::sources::config::SourceDefinition;
use coding_agent_search::sources::sync::{SyncEngine, mirror_path_under, path_to_safe_dirname};
use coding_agent_search::storage::api::Value;
use coding_agent_search::storage::sqlite::FrankenStorage;

/// The in-tree claude_code fixture: 1 conversation / 2 messages, so a pass
/// that ingested it and a pass that did not are distinguishable by count.
const CLAUDE_FIXTURE: &str = "claude_code_real/projects/-test-project/agent-test123.jsonl";

/// The remote path the configured source mirrors, the same shape
/// `w10_mirror_select` uses so the fixture is discovered from the mirror root
/// rather than from a path this test invented.
const REMOTE_PATH: &str = "~/.claude/projects";

const SOURCE_NAME: &str = "laptop";

/// The connector kept out of the scan by `disabled_agents`. Its rows are seeded
/// by hand, which makes "verbatim unchanged" a statement about the product's
/// SQL scoping and nothing else.
const IDLE_CONNECTOR: &str = "codex";
const IDLE_RELATIVE: &str = "projects/-idle/agent-idle.jsonl";
const IDLE_SIZE: i64 = 4_242;
const IDLE_MTIME: i64 = 1_600_000_000_000;
const IDLE_WATERMARK: i64 = 1_600_000_000_001;

/// The two file-state rows [`IDLE_CONNECTOR`] is seeded with. They are not
/// interchangeable, because each one is only reachable by a different wrong
/// delete:
///
/// - [`IDLE_RELATIVE`] is a path nothing in the run has heard of, so only a
///   delete that drops the `connector` predicate *and* reads every path of the
///   root can name it (`clear_scan_file_state_for_root`'s shape);
/// - [`ALPHA_RELATIVE`] is a path the run itself recorded and then watched
///   disappear, so a delete scoped to the root instead of to the connector
///   takes the other connector's row for the very same file with it.
fn seeded_idle_rows() -> [(&'static str, i64, i64); 2] {
    [
        (IDLE_RELATIVE, IDLE_SIZE, IDLE_MTIME),
        (ALPHA_RELATIVE, IDLE_SIZE + 1, IDLE_MTIME + 1),
    ]
}

/// The fixture's own relative paths inside the mirror root. `alpha` is the file
/// the tests delete and bring back; `beta` is the file that disappears and must
/// take its row with it while its archived session stays; `late` is the file
/// that arrives after the first pass and is what the interrupted run must not
/// lose.
const ALPHA_RELATIVE: &str = "projects/-pr10/agent-alpha.jsonl";
const BETA_RELATIVE: &str = "projects/-pr10/agent-beta.jsonl";
const LATE_RELATIVE: &str = "projects/-pr10/agent-late.jsonl";

/// The name of the trigger the failure case installs. Dropped again before the
/// recovery run — nothing in the product is aware of it.
const INDUCED_FAILURE_TRIGGER: &str = "pr10_task_04_watermark_guard";

const INDUCED_FAILURE_TEXT: &str = "induced failure for PR10 task 04";

/// Run `body` once per scan path: the streaming producer (the default) and the
/// batch path (`CASS_STREAMING_INDEX=0`). Both funnel through
/// `run_local_root_scan`, so a rule implemented on only one of them fails here.
fn for_each_scan_path(mut body: impl FnMut(bool)) {
    for streaming in [true, false] {
        body(streaming);
    }
}

fn fixture_bytes() -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(CLAUDE_FIXTURE),
    )
    .expect("read the claude_code fixture")
}

/// Write the in-tree claude_code fixture at `<root>/<relative>`.
fn write_claude_session(root: &Path, relative: &str) {
    let dest = root.join(relative);
    std::fs::create_dir_all(dest.parent().expect("fixture parent")).expect("create fixture dir");
    std::fs::write(&dest, fixture_bytes()).expect("write claude fixture");
}

/// Set a file's mtime, so a file can arrive carrying an older timestamp than
/// the root's watermark without waiting for the clock.
fn set_mtime(path: &Path, mtime: SystemTime) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for mtime");
    file.set_modified(mtime).expect("set mtime");
}

/// `(size, mtime_ms)` of a file on disk, the pair `file_scan_stamp` reads.
fn fs_stamp(path: &Path) -> (i64, i64) {
    let metadata = std::fs::metadata(path).expect("fixture metadata");
    let mtime = metadata
        .modified()
        .expect("fixture mtime")
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("mtime after epoch")
        .as_millis();
    (
        i64::try_from(metadata.len()).expect("fixture size"),
        i64::try_from(mtime).expect("fixture mtime ms"),
    )
}

/// One private HOME / config / data-dir triple, and the scan path its runs use.
struct Env {
    /// Held for its `Drop`: deleting this deletes the tree the paths point at.
    _tmp: tempfile::TempDir,
    home: PathBuf,
    config_home: PathBuf,
    data_dir: PathBuf,
    streaming: bool,
}

impl Env {
    fn new(streaming: bool) -> Self {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let env = Env {
            home: tmp.path().join("home"),
            config_home: tmp.path().join("config"),
            data_dir: tmp.path().join("data"),
            streaming,
            _tmp: tmp,
        };
        std::fs::create_dir_all(&env.home).expect("create home");
        std::fs::create_dir_all(&env.data_dir).expect("create data dir");
        env
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir.join("agent_search.db")
    }

    /// `sources.toml` describing one incremental ssh mirror of
    /// [`REMOTE_PATH`], with [`IDLE_CONNECTOR`] disabled so its seeded rows can
    /// only change through a bug.
    fn write_sources_config(&self) {
        let path = self.config_home.join("cass/sources.toml");
        std::fs::create_dir_all(path.parent().expect("config dir")).expect("create config dir");
        std::fs::write(
            &path,
            format!(
                "disabled_agents = [\"{IDLE_CONNECTOR}\"]\n\n[[sources]]\nname = \"{SOURCE_NAME}\"\n\
                 type = \"ssh\"\nhost = \"{SOURCE_NAME}\"\norigin_host = \"{SOURCE_NAME}\"\n\
                 paths = [\"{REMOTE_PATH}\"]\n"
            ),
        )
        .expect("write sources.toml");
    }

    /// The mirror directory the **write side** would publish this source into,
    /// obtained through the production entry points: `prepare_mirror_root`
    /// authorizes and creates the configured mirror root, and `mirror_path_under`
    /// names the per-path directory under it (PR10 task 01's single derivation).
    fn prepare_mirror(&self) -> PathBuf {
        let mut source = SourceDefinition::ssh(SOURCE_NAME, SOURCE_NAME);
        source.paths = vec![REMOTE_PATH.to_string()];
        source.origin_host = SOURCE_NAME.to_string();
        let engine = SyncEngine::new(&self.data_dir);
        let mirror_root = engine
            .prepare_mirror_root(&source)
            .expect("the configured mirror root must be authorized");
        let mirrored = mirror_path_under(&mirror_root, REMOTE_PATH);
        assert_eq!(
            mirrored,
            self.data_dir
                .join("remotes")
                .join(SOURCE_NAME)
                .join("mirror")
                .join(path_to_safe_dirname(REMOTE_PATH)),
            "the write side must name the mirror directory after the raw configured path"
        );
        mirrored
    }

    /// The binary under test with a fully private environment. `cmd.env` rather
    /// than process-global `set_var`: a subprocess gets its own copy, so these
    /// tests cannot leak into anything else in this process.
    fn cass(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cass"));
        cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
        cmd.env("HOME", &self.home);
        cmd.env("XDG_DATA_HOME", self.home.join(".local/share"));
        cmd.env("XDG_CONFIG_HOME", &self.config_home);
        cmd.env_remove("CASS_DATA_DIR");
        cmd.env("NO_COLOR", "1");
        // Both must be absent for `sources.toml` to be read: one short-circuits
        // it, the other would re-enable info-level chatter.
        cmd.env_remove("CASS_IGNORE_SOURCES_CONFIG");
        cmd.env_remove("RUST_LOG");
        cmd.env_remove("CLAUDE_CONFIG_DIR");
        cmd.env_remove("CODEX_HOME");
        if self.streaming {
            cmd.env_remove("CASS_STREAMING_INDEX");
        } else {
            cmd.env("CASS_STREAMING_INDEX", "0");
        }
        cmd
    }

    /// `cass index --json`, returning the exit code, raw stdout and stderr. The
    /// raw stdout is kept so a failing run can be read for what it said instead
    /// of only for its code.
    fn index_raw(&self) -> (i32, String, String) {
        let mut cmd = self.cass();
        cmd.args([
            "index",
            "--json",
            "--data-dir",
            &self.data_dir.display().to_string(),
        ]);
        let out = cmd.output().expect("spawn cass index --json");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// Run `cass index --json` and require success, returning the payload.
    fn index_ok(&self) -> serde_json::Value {
        let (code, stdout, stderr) = self.index_raw();
        assert_eq!(
            code, 0,
            "`cass index --json` must succeed, got {code}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );
        serde_json::from_str::<serde_json::Value>(&stdout)
            .expect("a successful `index --json` prints one JSON object")
    }
}

/// Conversations this run handed to ingest, summed over the per-connector
/// breakdown.
///
/// The payload's top-level `conversations` is the *archive* count on the paths
/// whose totals were recorded exactly; `indexing_stats.connectors` is what this
/// run's own scan produced, which is what "how many files did the mirror hand
/// over" has to be read from.
fn parsed_this_run(payload: &serde_json::Value) -> u64 {
    payload["indexing_stats"]["connectors"]
        .as_array()
        .map(|connectors| {
            connectors
                .iter()
                .filter_map(|connector| connector["conversations"].as_u64())
                .sum()
        })
        .unwrap_or(0)
}

fn db_scalar(db_path: &Path, sql: &str) -> i64 {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_row_map(sql, &[], |row| row.get_typed(0))
        .unwrap_or_else(|e| panic!("query {sql:?}: {e}"))
}

/// Every row of a one-column projection, joined — used to compare a whole
/// table before/after without depending on row order.
fn root_rows(db_path: &Path, sql: &str, root_prefix: &str) -> Vec<String> {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_all_map(sql, &[Value::from(format!("{root_prefix}%"))], |row| {
            row.get_typed::<String>(0)
        })
        .unwrap_or_else(|e| panic!("query {sql:?}: {e}"))
}

/// The subset of a row projection belonging to one connector. The others in
/// the same root move on their own schedule, so an isolation claim has to be
/// made about that connector's rows alone.
fn rows_of(rows: &[String], connector: &str) -> Vec<String> {
    rows.iter()
        .filter(|row| row.split('|').nth(1) == Some(connector))
        .cloned()
        .collect()
}

/// The whole `(root_id, connector, last_scan_ts)` row set under one root.
const ROOT_WATERMARK_ROWS: &str = "SELECT root_id || '|' || connector || '|' || last_scan_ts \
     FROM scan_watermarks WHERE root_id LIKE ?1 ORDER BY root_id, connector";
/// The whole `(root_id, connector, relative_path, size, mtime, last_seen_ts)`
/// row set under one root — every column, so "unchanged" is byte-for-byte.
const ROOT_FILE_STATE_ROWS: &str = "SELECT root_id || '|' || connector || '|' || relative_path || '|' || size \
     || '|' || mtime || '|' || last_seen_ts \
     FROM scan_file_state WHERE root_id LIKE ?1 ORDER BY root_id, connector, relative_path";

const CONVERSATIONS: &str = "SELECT COUNT(*) FROM conversations";

fn source_root_prefix() -> String {
    format!("cfg:{SOURCE_NAME}:")
}

/// One line per observation, `w10_mirror_select`'s convention: what a pass did
/// to the two tables and to the archive is then reproducible from
/// `cargo test -- --nocapture` instead of only asserted. Restricted to the two
/// connectors the claims are about — the other ~20 connectors in this root
/// write their own rows on every run and would bury them.
fn observe(label: &str, db_path: &Path, streaming: bool, parsed: Option<u64>) -> String {
    let watermarks = root_rows(db_path, ROOT_WATERMARK_ROWS, &source_root_prefix());
    let states = root_rows(db_path, ROOT_FILE_STATE_ROWS, &source_root_prefix());
    let mut keep = rows_of(&watermarks, "claude");
    keep.extend(rows_of(&watermarks, IDLE_CONNECTOR));
    let mut state_keep = rows_of(&states, "claude");
    state_keep.extend(rows_of(&states, IDLE_CONNECTOR));
    format!(
        "[{label} streaming={streaming}] parsed_this_run={parsed:?} \
         conversations={} watermarks={keep:?} file_state={state_keep:?}",
        db_scalar(db_path, CONVERSATIONS),
    )
}

/// One `(size, mtime, last_seen_ts)` record for `(connector, relative_path)`,
/// or `None` when the root holds no such row. The record is what the next run's
/// comparison runs on, so it is the end-to-end evidence that a pass read — or
/// dropped — that file.
fn recorded_state(db_path: &Path, connector: &str, relative: &str) -> Option<(i64, i64, i64)> {
    root_rows(db_path, ROOT_FILE_STATE_ROWS, &source_root_prefix())
        .into_iter()
        .find_map(|row| {
            let fields: Vec<&str> = row.split('|').collect();
            if fields.get(1) != Some(&connector) || fields.get(2) != Some(&relative) {
                return None;
            }
            Some((
                fields.get(3)?.parse().ok()?,
                fields.get(4)?.parse().ok()?,
                fields.get(5)?.parse().ok()?,
            ))
        })
}

/// This root's watermark for `connector`.
fn recorded_watermark(db_path: &Path, connector: &str) -> Option<i64> {
    root_rows(db_path, ROOT_WATERMARK_ROWS, &source_root_prefix())
        .into_iter()
        .find_map(|row| {
            let fields: Vec<&str> = row.split('|').collect();
            if fields.get(1) != Some(&connector) {
                return None;
            }
            fields.get(2)?.parse().ok()
        })
}

/// The concrete `root_id` the run derived for the mirror root, read back from
/// the row the first pass wrote rather than recomputed by this test: the seed
/// below and the induced-failure trigger both have to name the same value the
/// product used.
fn mirror_root_id(db_path: &Path) -> String {
    root_rows(db_path, ROOT_WATERMARK_ROWS, &source_root_prefix())
        .into_iter()
        .find_map(|row| {
            let fields: Vec<&str> = row.split('|').collect();
            (fields.get(1) == Some(&"claude")).then(|| fields.first().copied().unwrap().to_string())
        })
        .expect("the first pass must leave a claude watermark row for the mirror root")
}

/// Seed [`IDLE_CONNECTOR`]'s watermark and its file-state rows at `root_id`,
/// the way a run from before that connector was disabled would have left them.
///
/// Written through the product's own storage layer rather than by SQL text, so
/// the rows are exactly the shape a real pass writes.
fn seed_idle_connector_state(db_path: &Path, root_id: &str) {
    let storage = FrankenStorage::open(db_path).expect("open the archive to seed state");
    storage
        .set_scan_watermark(root_id, IDLE_CONNECTOR, IDLE_WATERMARK)
        .expect("seed the idle connector's watermark");
    for (relative, size, mtime) in seeded_idle_rows() {
        storage
            .upsert_scan_file_state(
                root_id,
                IDLE_CONNECTOR,
                relative,
                size,
                mtime,
                IDLE_WATERMARK,
            )
            .expect("seed the idle connector's file state");
    }
    storage.close().expect("close the archive");
}

/// Install the deterministic last-write failure: the watermark insert of this
/// root's own transaction raises, after the absent-path deletes and the
/// changed-file upserts have already run inside it.
///
/// The same shape as the in-crate `n4_atomicity_guard` (`src/indexer/mod.rs`):
/// a `BEFORE INSERT ... RAISE(FAIL)`. Nothing in the product knows about it —
/// the task deliberately does not add a fault-injection switch.
fn install_watermark_failure(db_path: &Path, root_id: &str) {
    let storage = FrankenStorage::open(db_path).expect("open the archive to install the trigger");
    storage
        .raw()
        .execute_batch(&format!(
            "CREATE TRIGGER {INDUCED_FAILURE_TRIGGER} BEFORE INSERT ON scan_watermarks \
             WHEN NEW.root_id = '{root_id}' \
             BEGIN SELECT RAISE(FAIL, '{INDUCED_FAILURE_TEXT}'); END;"
        ))
        .expect("install the induced-failure trigger");
    storage.close().expect("close the archive");
}

fn drop_watermark_failure(db_path: &Path) {
    let storage = FrankenStorage::open(db_path).expect("open the archive to drop the trigger");
    storage
        .raw()
        .execute_batch(&format!("DROP TRIGGER {INDUCED_FAILURE_TRIGGER};"))
        .expect("drop the induced-failure trigger");
    storage.close().expect("close the archive");
}

// ---------------------------------------------------------------------------
// S1 — a file that left the mirror loses its state, and its return is a new file
// ---------------------------------------------------------------------------

/// Delete a mirrored session, scan, and the record of it goes with the file —
/// while its archived conversation stays. Put an identical file back (same
/// path, same size, **same** mtime) and the next scan parses it, because the
/// thing that would have called it unchanged is gone.
///
/// The last step is the point of the whole task: under the baseline the record
/// survives the deletion, the mirror comparison sees an unmodified file, and a
/// session that really did leave and come back is never read again.
#[test]
fn deleted_mirror_file_loses_its_state_and_reappears_as_new() {
    for_each_scan_path(|streaming| {
        let env = Env::new(streaming);
        env.write_sources_config();
        let mirror = env.prepare_mirror();
        write_claude_session(&mirror, ALPHA_RELATIVE);
        write_claude_session(&mirror, BETA_RELATIVE);

        let first = env.index_ok();
        let parsed_first = parsed_this_run(&first);
        assert!(
            parsed_first >= 2,
            "the first pass has no watermark, so it must read the whole mirror: {first}"
        );
        let conversations = db_scalar(&env.db_path(), CONVERSATIONS);
        assert_eq!(
            conversations, 2,
            "both mirrored sessions must be ingested exactly once: {first}"
        );

        let alpha = mirror.join(ALPHA_RELATIVE);
        let alpha_stamp = fs_stamp(&alpha);
        let alpha_modified = std::fs::metadata(&alpha)
            .expect("fixture metadata")
            .modified()
            .expect("fixture mtime");
        let alpha_bytes = std::fs::read(&alpha).expect("read the fixture copy");
        assert_eq!(
            recorded_state(&env.db_path(), "claude", ALPHA_RELATIVE)
                .map(|(size, mtime, _)| (size, mtime)),
            Some(alpha_stamp),
            "sanity: the first pass must record the file it read"
        );

        // The second connector's rows are seeded after the pass, because a
        // disabled connector has no pass of its own to write them.
        let root_id = mirror_root_id(&env.db_path());
        seed_idle_connector_state(&env.db_path(), &root_id);
        let seeded_watermarks =
            root_rows(&env.db_path(), ROOT_WATERMARK_ROWS, &source_root_prefix());
        let seeded_states = root_rows(&env.db_path(), ROOT_FILE_STATE_ROWS, &source_root_prefix());
        println!(
            "[mirror root {root_id}] {}",
            observe("pass1+seed", &env.db_path(), streaming, Some(parsed_first))
        );

        // The far machine deletes one session.
        std::fs::remove_file(&alpha).expect("delete the mirrored session");

        let second = env.index_ok();
        println!("{}", observe("pass2", &env.db_path(), streaming, Some(0)));
        assert_eq!(
            db_scalar(&env.db_path(), CONVERSATIONS),
            conversations,
            "an archived session must not be deleted with its mirror file: {second}"
        );
        assert_eq!(
            recorded_state(&env.db_path(), "claude", ALPHA_RELATIVE),
            None,
            "a path the enumeration no longer sees must lose its state: {second}"
        );
        assert!(
            recorded_state(&env.db_path(), "claude", BETA_RELATIVE).is_some(),
            "the file that is still there must keep its state, got {:?}: {second}",
            root_rows(&env.db_path(), ROOT_FILE_STATE_ROWS, &source_root_prefix())
        );
        assert_eq!(
            parsed_this_run(&second),
            0,
            "deleting a file leaves nothing to parse on a mirror: {second}"
        );
        assert_eq!(
            rows_of(
                &root_rows(&env.db_path(), ROOT_WATERMARK_ROWS, &source_root_prefix()),
                IDLE_CONNECTOR
            ),
            rows_of(&seeded_watermarks, IDLE_CONNECTOR),
            "the deleted path's cleanup must not touch another connector's watermark row"
        );
        assert_eq!(
            rows_of(
                &root_rows(&env.db_path(), ROOT_FILE_STATE_ROWS, &source_root_prefix()),
                IDLE_CONNECTOR
            ),
            rows_of(&seeded_states, IDLE_CONNECTOR),
            "the deleted path's cleanup must not touch another connector's file-state rows"
        );

        // The same file comes back, byte for byte, with its original mtime: a
        // file the mirror hands over that the state no longer knows about.
        std::fs::write(&alpha, &alpha_bytes).expect("restore the mirrored session");
        set_mtime(&alpha, alpha_modified);
        assert_eq!(
            fs_stamp(&alpha),
            alpha_stamp,
            "the restored file must match the deleted one in path, size and mtime, \
             or this case would be caught by the ordinary size/mtime comparison instead"
        );

        let third = env.index_ok();
        println!(
            "{}",
            observe(
                "pass3",
                &env.db_path(),
                streaming,
                Some(parsed_this_run(&third))
            )
        );
        assert_eq!(
            parsed_this_run(&third),
            1,
            "a file whose record was dropped must be handed to the connector again, \
             even though path, size and mtime are all identical: {third}"
        );
        assert_eq!(
            recorded_state(&env.db_path(), "claude", ALPHA_RELATIVE)
                .map(|(size, mtime, _)| (size, mtime)),
            Some(alpha_stamp),
            "the re-read must record the file again: {third}"
        );
        assert_eq!(
            db_scalar(&env.db_path(), CONVERSATIONS),
            conversations,
            "re-reading a restored file must not duplicate its conversation: {third}"
        );
    });
}

// ---------------------------------------------------------------------------
// S2 — the commit is atomic, and its failure is the run's failure
// ---------------------------------------------------------------------------

/// A scan carrying both an absent path and a changed file fails on its final
/// watermark write: the run's exit code is non-zero, and both tables still hold
/// exactly what they held before it. Remove the fault and the same scan commits
/// everything at once — the absent path's state goes, the new file is read.
///
/// Without the transaction the two tables would be left half-applied (the
/// deletes committed, the watermark not), and without the propagated error the
/// run would have reported success while doing it.
#[test]
fn failed_watermark_write_rolls_back_both_tables_and_the_rerun_commits() {
    for_each_scan_path(|streaming| {
        let env = Env::new(streaming);
        env.write_sources_config();
        let mirror = env.prepare_mirror();
        write_claude_session(&mirror, ALPHA_RELATIVE);
        write_claude_session(&mirror, BETA_RELATIVE);

        let first = env.index_ok();
        let conversations = db_scalar(&env.db_path(), CONVERSATIONS);
        assert_eq!(
            conversations, 2,
            "both mirrored sessions must be ingested before the rollback means \
             anything: {first}"
        );
        let before_alpha = recorded_state(&env.db_path(), "claude", ALPHA_RELATIVE);
        let before_beta = recorded_state(&env.db_path(), "claude", BETA_RELATIVE);
        let before_watermark = recorded_watermark(&env.db_path(), "claude")
            .expect("the first pass must leave a watermark");
        assert!(before_alpha.is_some() && before_beta.is_some());

        let root_id = mirror_root_id(&env.db_path());
        seed_idle_connector_state(&env.db_path(), &root_id);
        let seeded_watermarks =
            root_rows(&env.db_path(), ROOT_WATERMARK_ROWS, &source_root_prefix());
        let seeded_states = root_rows(&env.db_path(), ROOT_FILE_STATE_ROWS, &source_root_prefix());

        // One path disappears from the mirror, one file arrives carrying an
        // older mtime than the watermark — so the failing run really has a
        // delete and an upsert to do before it reaches the watermark.
        std::fs::remove_file(mirror.join(BETA_RELATIVE)).expect("delete a mirrored session");
        write_claude_session(&mirror, LATE_RELATIVE);
        set_mtime(
            &mirror.join(LATE_RELATIVE),
            SystemTime::now() - Duration::from_secs(7_200),
        );

        println!(
            "[mirror root {root_id}] {}",
            observe("pre-failure+seed", &env.db_path(), streaming, None)
        );

        install_watermark_failure(&env.db_path(), &root_id);
        let (code, stdout, stderr) = env.index_raw();
        println!(
            "{} (exit code {code})",
            observe("after-failed-run", &env.db_path(), streaming, None)
        );
        assert_ne!(
            code, 0,
            "a storage failure while committing the root must fail `cass index`, \
             not be logged and swallowed\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );
        assert!(
            format!("{stdout}{stderr}").contains(INDUCED_FAILURE_TEXT),
            "the failure must be the induced watermark write (proving the commit path \
             really ran), got\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );
        assert_eq!(
            root_rows(&env.db_path(), ROOT_WATERMARK_ROWS, &source_root_prefix()),
            seeded_watermarks,
            "a failed commit must leave the watermark where it was"
        );
        assert_eq!(
            root_rows(&env.db_path(), ROOT_FILE_STATE_ROWS, &source_root_prefix()),
            seeded_states,
            "a failed commit must roll the absent-path deletes and the file-state upserts \
             back too, not leave them half-applied"
        );
        assert_eq!(
            recorded_state(&env.db_path(), "claude", ALPHA_RELATIVE),
            before_alpha,
            "the unchanged file's record must survive the rollback verbatim"
        );
        assert_eq!(
            recorded_state(&env.db_path(), "claude", BETA_RELATIVE),
            before_beta,
            "the absent path's record must still be there after the rollback"
        );
        assert_eq!(
            recorded_watermark(&env.db_path(), "claude"),
            Some(before_watermark),
            "the watermark must not have moved"
        );

        // Recovery: the same scan, without the fault, commits.
        drop_watermark_failure(&env.db_path());
        let recovered = env.index_ok();
        println!(
            "{}",
            observe(
                "after-recovery",
                &env.db_path(),
                streaming,
                Some(parsed_this_run(&recovered))
            )
        );
        assert!(
            parsed_this_run(&recovered) >= 1,
            "the file the failed run could not commit must come back on the rerun: {recovered}"
        );
        assert_eq!(
            recorded_state(&env.db_path(), "claude", BETA_RELATIVE),
            None,
            "the absent path's record must go once the commit succeeds: {recovered}"
        );
        assert!(
            recorded_state(&env.db_path(), "claude", LATE_RELATIVE).is_some(),
            "the new file's record must land with the same commit: {recovered}"
        );
        let recovered_watermark = recorded_watermark(&env.db_path(), "claude")
            .expect("the recovered run must leave a claude watermark row");
        assert!(
            recovered_watermark > before_watermark,
            "the recovered run must advance the watermark it could not write before, \
             got {recovered_watermark} against {before_watermark}"
        );
        assert_eq!(
            db_scalar(&env.db_path(), CONVERSATIONS),
            conversations + 1,
            "the late session must be ingested across the failed and recovered runs, \
             exactly once: {recovered}"
        );
        assert_eq!(
            rows_of(
                &root_rows(&env.db_path(), ROOT_WATERMARK_ROWS, &source_root_prefix()),
                IDLE_CONNECTOR
            ),
            rows_of(&seeded_watermarks, IDLE_CONNECTOR),
            "the other connector's watermark row must be untouched by either run"
        );
        assert_eq!(
            rows_of(
                &root_rows(&env.db_path(), ROOT_FILE_STATE_ROWS, &source_root_prefix()),
                IDLE_CONNECTOR
            ),
            rows_of(&seeded_states, IDLE_CONNECTOR),
            "the other connector's file-state rows must be untouched by either run"
        );
    });
}
