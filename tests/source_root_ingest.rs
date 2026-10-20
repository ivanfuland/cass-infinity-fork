//! SRC05B-08 acceptance: source-aware configured scan roots and the
//! evidence-backed incremental selection.
//!
//! Every case drives the real `cass index` binary over a private synthetic
//! HOME, private synthetic configured roots (machine-local, and the mirror
//! directory the ssh writer publishes into), a private fixed safety copy and a
//! private data directory, then reads the resulting SQLite database directly.
//! The product behaviour under test is never reached through a library call:
//! the seam is the CLI, the database, the per-run JSON and the process
//! boundary.
//!
//! One fixture helper is internal, and it is the *pre-state* rather than the
//! behaviour: `util::source_legacy_seed` builds the conversation, watermark,
//! per-file state and raw-mirror capture an earlier, source-unaware run would
//! have left behind, so a migration case no longer has to run the legacy entry
//! point it is migrating away from. The run under test is still a separate
//! process.
//!
//! The fixtures are synthetic and neutral. No real session, path or secret
//! appears in this file.

mod util;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use coding_agent_search::indexer::scan_root_meta;
use coding_agent_search::sources::config::SourceDefinition;
use coding_agent_search::sources::sync::{SyncEngine, mirror_path_under, path_to_safe_dirname};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

/// The one line a source-aware commit writes from *inside* its writer closure.
///
/// It is the per-run count of inputs this run prepared and carried into the
/// commit, which is what separates "the second round read nothing" from "the
/// second round read everything and the database happened to be unchanged".
const DISPATCH_MARKER: &str = "source_input_dispatch";

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home")).expect("mkdir home");
        std::fs::create_dir_all(root.path().join("data")).expect("mkdir data");
        std::fs::write(
            root.path().join("fixed-safety.toml"),
            include_bytes!("../config/excluded_context_paths.toml"),
        )
        .expect("write fixed safety copy");
        Self { root }
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn config_home(&self) -> PathBuf {
        self.root.path().join("config")
    }

    fn db(&self) -> PathBuf {
        self.data_dir().join("agent_search.db")
    }

    fn fixed_copy(&self) -> PathBuf {
        self.root.path().join("fixed-safety.toml")
    }

    /// Point every source-discovery environment at this fixture.
    ///
    /// The host running the tests may itself export these; an inherited value
    /// would let a fixture process scan the host's real history. The fixture
    /// therefore states every one of them explicitly.
    fn isolate<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("HOME", self.home())
            .env("XDG_DATA_HOME", self.home().join(".local/share"))
            .env("XDG_CONFIG_HOME", self.config_home())
            .env("CODEX_HOME", self.home().join(".codex"))
            .env("CASS_AIDER_DATA_ROOT", self.home().join(".aider"))
            .env("PI_SESSIONS_DIR", self.home().join(".pi"))
            .env("PI_CODING_AGENT_DIR", self.home().join(".pi"))
            .env("GOOSE_PATH_ROOT", self.home().join(".goose"))
            .env("HERMES_HOME", self.home().join(".hermes"))
            .env("CASS_DATA_DIR", self.data_dir())
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("NO_COLOR", "1")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("RUST_LOG");
        cmd
    }

    /// One `sources.toml` declaring the sources the caller describes. Each
    /// entry is `(name, kind, origin_host, path, full_scan)`; `kind` is
    /// `local` or `ssh`.
    fn write_sources(&self, sources: &[(&str, &str, &str, &str, bool)]) {
        let dir = self.config_home().join("cass");
        std::fs::create_dir_all(&dir).expect("mkdir cass config");
        let mut body = String::new();
        for (name, kind, origin_host, path, full_scan) in sources {
            body.push_str("[[sources]]\n");
            body.push_str(&format!("name = \"{name}\"\n"));
            body.push_str(&format!("type = \"{kind}\"\n"));
            if *kind == "ssh" {
                body.push_str(&format!("host = \"{origin_host}\"\n"));
            }
            body.push_str(&format!("origin_host = \"{origin_host}\"\n"));
            if *full_scan {
                body.push_str("full_scan = true\n");
            }
            body.push_str(&format!("paths = [\"{path}\"]\n\n"));
        }
        std::fs::write(dir.join("sources.toml"), body).expect("write sources.toml");
    }

    /// The mirror directory the **write side** would publish an ssh source
    /// into, obtained through the production entry points.
    fn prepare_mirror(&self, source_name: &str, remote_path: &str) -> PathBuf {
        let mut source = SourceDefinition::ssh(source_name, source_name);
        source.paths = vec![remote_path.to_string()];
        source.origin_host = source_name.to_string();
        let engine = SyncEngine::new(&self.data_dir());
        let mirror_root = engine
            .prepare_mirror_root(&source)
            .expect("the configured mirror root must be authorized");
        let mirrored = mirror_path_under(&mirror_root, remote_path);
        std::fs::create_dir_all(&mirrored).expect("mkdir mirror path");
        assert_eq!(
            mirrored,
            self.data_dir()
                .join("remotes")
                .join(source_name)
                .join("mirror")
                .join(path_to_safe_dirname(remote_path)),
            "the write side names the mirror directory after the raw configured path"
        );
        mirrored
    }

    /// Write a Claude Code session under `root` at `relative`.
    fn write_session(&self, root: &Path, relative: &str, uuid: &str, answer: &str) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("session parent")).expect("mkdir session dir");
        let body: String = claude_session(uuid, "synthetic question", answer)
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&path, body).expect("write session");
        path
    }

    /// Run `cass index --json --verbose` over this fixture's own data
    /// directory: the verbose log carries the writer-closure dispatch line,
    /// which is what separates "the second round read nothing" from "the
    /// second round read everything and the database happened to be
    /// unchanged".
    fn index_verbose(&self) -> Run {
        self.index_with(&[])
    }

    /// Write a Codex rollout at the layout its connector discovers under this
    /// fixture's own `CODEX_HOME`.
    fn write_codex_session(&self, id: &str, answer: &str) -> PathBuf {
        self.write_codex_session_in(
            &self.home().join(".codex"),
            &format!("sessions/2026/01/rollout-2026-01-01T00-00-00-{id}.jsonl"),
            id,
            answer,
        )
    }

    /// Write a Codex rollout under `root`, at the `sessions/` child the Codex
    /// connector walks for `rollout-*` files.
    fn write_codex_session_in(&self, root: &Path, relative: &str, id: &str, answer: &str) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("codex parent")).expect("mkdir codex dir");
        let body: String = codex_session(id, "synthetic codex question", answer)
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&path, body).expect("write codex session");
        path
    }

    /// `cass index --json --verbose` with extra environment, so a test can arm
    /// the commit's own late fault (`CASS_SRC05B07_FAIL_AT`).
    fn index_env(&self, envs: &[(&str, &str)]) -> Run {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        for (key, value) in envs {
            cmd.env(key, value);
        }
        cmd.env("CASS_DATA_DIR", self.data_dir());
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .arg("--source-safety-config")
            .arg(self.fixed_copy())
            .args(["--json", "--verbose"]);
        Run::from(cmd.output().expect("spawn cass index"))
    }

    /// `cass index --json --verbose` with extra flags on top of the
    /// source-aware flag.
    fn index_with(&self, extra: &[&str]) -> Run {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.env("CASS_DATA_DIR", self.data_dir());
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .arg("--source-safety-config")
            .arg(self.fixed_copy())
            .args(["--json", "--verbose"])
            .args(extra);
        Run::from(cmd.output().expect("spawn cass index"))
    }

    /// A `sources.toml` declaring one private local root with a path mapping.
    fn write_mapped_source(&self, name: &str, root: &Path, to: &str) {
        let dir = self.config_home().join("cass");
        std::fs::create_dir_all(&dir).expect("mkdir cass config");
        std::fs::write(
            dir.join("sources.toml"),
            format!(
                "[[sources]]\nname = \"{name}\"\ntype = \"local\"\norigin_host = \"{name}\"\n\
                 paths = [\"{}\"]\npath_mappings = [{{ from = \"/synthetic-old\", to = \"{to}\" }}]\n",
                root.display()
            ),
        )
        .expect("write sources.toml");
    }

    /// Run `cass index --json --verbose` with one scheduling/ writer cell.
    fn index_cell(&self, streaming: bool, begin_concurrent: bool) -> Run {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.env("CASS_STREAMING_INDEX", if streaming { "1" } else { "0" })
            .env(
                "CASS_INDEXER_BEGIN_CONCURRENT",
                if begin_concurrent { "1" } else { "0" },
            )
            .env("CASS_STREAMING_CONSUMER_COMBINE", "0")
            .env("CASS_DATA_DIR", self.data_dir());
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .arg("--source-safety-config")
            .arg(self.fixed_copy())
            .args(["--json", "--verbose"]);
        Run::from(cmd.output().expect("spawn cass index"))
    }

    fn open_db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(
            self.db(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open the database read-only")
    }

}

/// One `cass index` run's observable result.
struct Run {
    code: Option<i32>,
    payload: Option<serde_json::Value>,
    stderr: String,
}

impl From<std::process::Output> for Run {
    fn from(output: std::process::Output) -> Self {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Self {
            code: output.status.code(),
            payload: serde_json::from_str::<serde_json::Value>(&stdout).ok(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }
}

impl Run {
    fn expect_failure(&self, what: &str) {
        assert_ne!(
            self.code,
            Some(0),
            "{what} must fail; stderr={}",
            self.stderr
        );
    }

    /// How many inputs this run prepared and carried into its commit.
    fn dispatches(&self) -> usize {
        self.stderr.matches(DISPATCH_MARKER).count()
    }

    fn scan_invocations(&self) -> u64 {
        self.payload.as_ref().map_or(0, |payload| {
            payload["indexing_stats"]["scan_invocations"]
                .as_u64()
                .unwrap_or(0)
        })
    }

    fn source_inputs_committed(&self) -> u64 {
        self.payload.as_ref().map_or(0, |payload| {
            payload["indexing_stats"]["source_inputs_committed"]
                .as_u64()
                .unwrap_or(0)
        })
    }
}

fn claude_session(uuid: &str, question: &str, answer: &str) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "parentUuid": null,
            "cwd": "/synthetic/project",
            "sessionId": uuid,
            "version": "2.0.37",
            "type": "user",
            "message": {"role": "user", "content": question},
            "uuid": format!("{uuid}-user"),
            "timestamp": "2026-01-01T00:00:00.000Z"
        }),
        serde_json::json!({
            "parentUuid": format!("{uuid}-user"),
            "cwd": "/synthetic/project",
            "sessionId": uuid,
            "version": "2.0.37",
            "type": "assistant",
            "message": {
                "model": "claude-opus-4",
                "role": "assistant",
                "content": [{"type": "text", "text": answer}]
            },
            "uuid": format!("{uuid}-assistant"),
            "timestamp": "2026-01-01T00:00:01.000Z"
        }),
    ]
}

/// A Codex rollout: a session header plus one user and one assistant turn.
fn codex_session(id: &str, question: &str, answer: &str) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:00.000Z",
            "type": "session_meta",
            "payload": {"id": id, "cwd": "/synthetic/project", "cli_version": "0.42.0"}
        }),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:01.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": format!("{id}-msg-1"),
                "role": "user",
                "content": [{"type": "input_text", "text": question}]
            }
        }),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:02.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": format!("{id}-msg-2"),
                "role": "assistant",
                "content": [{"type": "output_text", "text": answer}]
            }
        }),
    ]
}

/// The `identity_host` every raw-mirror manifest under `root` records, sorted:
/// the capture's own session identity, which the source path must not relabel.
fn manifest_identities(root: &Path) -> Vec<String> {
    let dir = root.join("data/raw-mirror/v1/manifests");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut identities: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .filter_map(|manifest| {
            manifest
                .get("identity_host")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .collect();
    identities.sort();
    identities
}


/// Set a file's modification time, so a test can present a file whose mtime
/// predates the run's watermark without waiting for the clock.
fn set_mtime(path: &Path, mtime: SystemTime) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for mtime");
    file.set_modified(mtime).expect("set mtime");
}

fn mtime_of(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .expect("stat")
        .modified()
        .expect("mtime")
}

/// `(size, mtime_ms)` of one path.
fn stamp(path: &Path) -> (i64, i64) {
    let metadata = std::fs::metadata(path).expect("stat");
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|m| m.duration_since(SystemTime::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    (i64::try_from(metadata.len()).unwrap_or(i64::MAX), mtime)
}

/// The rows that belong to one connector. A configured root is scanned by
/// every connector, so a comparison about one connector's failure has to name
/// that connector rather than the whole table.
fn rows_for_connector(rows: &[String], connector: &str) -> Vec<String> {
    let needle = format!("|{connector}|");
    rows.iter()
        .filter(|row| row.contains(&needle))
        .cloned()
        .collect()
}

/// Every `root_id | connector | last_scan_ts` row whose root id starts with
/// `prefix`, ordered — a whole-table comparison that does not depend on row
/// order.
fn watermark_rows(db: &rusqlite::Connection, prefix: &str) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT root_id || '|' || connector || '|' || last_scan_ts FROM scan_watermarks
             WHERE root_id LIKE ?1 || '%' ORDER BY root_id, connector",
        )
        .expect("prepare watermark rows");
    let rows: Vec<String> = stmt
        .query_map([prefix], |row| row.get::<_, String>(0))
        .expect("query watermark rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect watermark rows");
    rows
}

/// Every `root_id | connector | relative_path | size | mtime` row whose root id
/// starts with `prefix`, ordered.
fn file_state_rows(db: &rusqlite::Connection, prefix: &str) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT root_id || '|' || connector || '|' || relative_path || '|' || size || '|' || mtime
             FROM scan_file_state WHERE root_id LIKE ?1 || '%'
             ORDER BY root_id, connector, relative_path",
        )
        .expect("prepare file state rows");
    let rows: Vec<String> = stmt
        .query_map([prefix], |row| row.get::<_, String>(0))
        .expect("query file state rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect file state rows");
    rows
}

fn scalar(db: &rusqlite::Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |row| row.get(0)).expect(sql)
}

/// The source-side facts of one database: enough to tell "a replay added
/// nothing" from "a replay was never attempted".
#[derive(Debug, PartialEq, Eq)]
struct SourceFacts {
    complete_inputs: i64,
    other_inputs: i64,
    records: i64,
    receipts: i64,
    messages: i64,
}

fn source_facts(db: &rusqlite::Connection) -> SourceFacts {
    SourceFacts {
        complete_inputs: scalar(
            db,
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
        ),
        other_inputs: scalar(
            db,
            "SELECT COUNT(*) FROM source_inputs WHERE state <> 'complete'",
        ),
        records: scalar(db, "SELECT COUNT(*) FROM source_records"),
        receipts: scalar(db, "SELECT COUNT(*) FROM operation_commit_receipt"),
        messages: scalar(db, "SELECT COUNT(*) FROM messages"),
    }
}

/// Every committed receipt's own key, joined so a whole-table comparison does
/// not depend on row order.
fn receipt_keys(db: &rusqlite::Connection) -> String {
    db.query_row(
        "SELECT COALESCE(group_concat(idempotency_key, '|'), '') FROM operation_commit_receipt",
        [],
        |row| row.get(0),
    )
    .expect("read the receipt keys")
}

/// Every input's `(normalizer id, safety contract id)`, newest last.
fn input_profiles(db: &rusqlite::Connection) -> Vec<(String, String)> {
    let mut stmt = db
        .prepare("SELECT normalizer_id, safety_contract_id FROM source_inputs ORDER BY id")
        .expect("prepare input profiles");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query input profiles")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect input profiles")
}

/// Every link row's witness columns in a stable order: the installed positions,
/// digest, authority and message id of each `(record, projection)`. Byte
/// equality here is what "the installed witness was not rewritten" means.
fn link_witness_rows(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT record_id || '|' || hex(projection_key) || '|' || hex(binding_digest) || '|' ||
                    COALESCE(authority, '') || '|' || COALESCE(message_id, -1) || '|' ||
                    hex(source_positions_bin)
             FROM source_message_links ORDER BY record_id, projection_key",
        )
        .expect("prepare link witness rows");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query link witness rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect link witness rows")
}

/// Every input's state, newest last.
fn input_states(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare("SELECT state FROM source_inputs ORDER BY id")
        .expect("prepare input states");
    stmt.query_map([], |row| row.get(0))
        .expect("query input states")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect input states")
}

// ---------------------------------------------------------------------------
// R1: a configured `full_scan` root is covered by the source kernel
// ---------------------------------------------------------------------------

/// R1: both schedulings and both writer modes scan a `full_scan` configured
/// root through the source kernel, the first round lands real source facts,
/// the second round reads the same files and commits nothing new -- and the
/// root keeps no watermark row and no per-file state at any point.
#[test]
fn r1_a_full_scan_root_is_covered_and_replays_to_nothing() {
    for streaming in [true, false] {
        for begin_concurrent in [true, false] {
            let label = format!(
                "{}x{}",
                if streaming { "streaming" } else { "batch" },
                if begin_concurrent { "writer-handle" } else { "ephemeral-writer" }
            );
            let fixture = Fixture::new();
            let declared = fixture.path().join("backup-root");
            // Both connectors, one root: R1 asks for a Claude *and* a Codex
            // configured `full_scan` root. Every connector scans every
            // configured root. Ownership gives each file exactly one writer;
            // Claude's broad discovery does not create a third input.
            fixture.write_session(
                &declared,
                "projects/-f/agent-f.jsonl",
                "sess-r1-fullscan",
                "r1 answer",
            );
            fixture.write_codex_session_in(
                &declared,
                "sessions/2026/01/rollout-2026-01-01T00-00-00-sess-r1-codex.jsonl",
                "sess-r1-codex",
                "r1 codex answer",
            );
            fixture.write_sources(&[(
                "backup",
                "local",
                "backup",
                declared.to_str().unwrap(),
                true,
            )]);

            let first = fixture.index_cell(streaming, begin_concurrent);
            assert_eq!(
                first.code,
                Some(0),
                "cell {label}: a full_scan root is covered; stderr={}",
                first.stderr
            );
            assert_eq!(
                first.dispatches(),
                2,
                "cell {label}: every discovered file is prepared and dispatched \
                 (the Claude session and the Codex rollout); stderr={}",
                first.stderr
            );
            let expected_mode = if begin_concurrent {
                "mode=\"writer-handle\""
            } else {
                "mode=\"ephemeral-writer\""
            };
            assert!(
                first.stderr.contains(expected_mode),
                "cell {label}: the commit took {expected_mode}; stderr={}",
                first.stderr
            );
            assert_eq!(
                first.source_inputs_committed(),
                2,
                "cell {label}: the run's own JSON agrees two inputs committed"
            );
            assert!(
                first.scan_invocations() >= 1,
                "cell {label}: the root's scan was invoked; stderr={}",
                first.stderr
            );

            let db = fixture.open_db();
            let after_first = source_facts(&db);
            assert_eq!(
                after_first.complete_inputs, 2,
                "cell {label}: every discovered input completed"
            );
            assert_eq!(after_first.other_inputs, 0, "cell {label}: nothing staged");
            assert!(
                after_first.records >= 3,
                "cell {label}: source records land: {after_first:?}"
            );
            assert_eq!(
                after_first.receipts, 2,
                "cell {label}: one receipt per discovered input"
            );
            assert!(
                after_first.messages >= 2,
                "cell {label}: canonical messages land: {after_first:?}"
            );
            assert_eq!(
                watermark_rows(&db, "cfg:backup:"),
                Vec::<String>::new(),
                "cell {label}: a full_scan root takes no watermark row"
            );
            assert_eq!(
                file_state_rows(&db, "cfg:backup:"),
                Vec::<String>::new(),
                "cell {label}: a full_scan root takes no per-file state"
            );
            let before_keys = receipt_keys(&db);
            drop(db);

            // The second round hands over the same file again: the root keeps
            // no state to compare against, so every run is a full read, and
            // every one of them has to be a verified replay.
            let second = fixture.index_cell(streaming, begin_concurrent);
            assert_eq!(
                second.code,
                Some(0),
                "cell {label}: the replay succeeds; stderr={}",
                second.stderr
            );
            assert_eq!(
                second.dispatches(),
                2,
                "cell {label}: the full_scan root reads both again; stderr={}",
                second.stderr
            );
            assert_eq!(
                second.source_inputs_committed(),
                2,
                "cell {label}: the replays are still commits of the same inputs"
            );
            let db = fixture.open_db();
            assert_eq!(
                source_facts(&db),
                after_first,
                "cell {label}: a verified replay adds nothing"
            );
            assert_eq!(
                receipt_keys(&db),
                before_keys,
                "cell {label}: the receipts are the same ones"
            );
            assert_eq!(
                watermark_rows(&db, "cfg:backup:"),
                Vec::<String>::new(),
                "cell {label}: still no watermark row after the replay"
            );
            assert_eq!(
                file_state_rows(&db, "cfg:backup:"),
                Vec::<String>::new(),
                "cell {label}: still no per-file state after the replay"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// R2: the per-root selection, and that a skip really skips
// ---------------------------------------------------------------------------

/// R2: a configured local root that did not opt into full scans reads its
/// first round and hands over nothing on the second -- the root is not even
/// scanned, and no input is prepared, which the run's own JSON agrees with.
#[test]
fn r2_an_unchanged_local_root_is_not_scanned_or_prepared_again() {
    for streaming in [true, false] {
        let label = if streaming { "streaming" } else { "batch" };
        let fixture = Fixture::new();
        let root = fixture.path().join("laptop-root");
        fixture.write_session(
            &root,
            "projects/-l/agent-l.jsonl",
            "sess-r2-steady",
            "r2 steady answer",
        );
        fixture.write_sources(&[("laptop", "local", "laptop", root.to_str().unwrap(), false)]);

        let first = if streaming {
            fixture.index_cell(true, false)
        } else {
            fixture.index_cell(false, false)
        };
        assert_eq!(
            first.code,
            Some(0),
            "{label}: the first round succeeds; stderr={}",
            first.stderr
        );
        assert_eq!(
            first.dispatches(),
            1,
            "{label}: the first round reads the root's only file; stderr={}",
            first.stderr
        );
        assert_eq!(first.source_inputs_committed(), 1, "{label}: one commit");
        assert!(
            first.scan_invocations() >= 1,
            "{label}: the first round scanned the root"
        );
        let after_first = source_facts(&fixture.open_db());
        let states_after_first = {
            let db = fixture.open_db();
            let states = file_state_rows(&db, "cfg:laptop:");
            assert_eq!(states.len(), 1, "{label}: the root recorded its one file");
            states
        };

        let second = if streaming {
            fixture.index_cell(true, false)
        } else {
            fixture.index_cell(false, false)
        };
        assert_eq!(
            second.code,
            Some(0),
            "{label}: the second round succeeds; stderr={}",
            second.stderr
        );
        assert_eq!(
            second.dispatches(),
            0,
            "{label}: nothing is prepared on the second round; stderr={}",
            second.stderr
        );
        assert_eq!(
            second.source_inputs_committed(),
            0,
            "{label}: the run's own JSON agrees nothing committed"
        );
        // The run-wide scan counter is every connector's own invocation and
        // cannot separate this root from the others, so the root's own
        // recorded state is what has to hold still: a skipped root rewrites no
        // per-file state of its own.
        let db = fixture.open_db();
        assert_eq!(
            file_state_rows(&db, "cfg:laptop:"),
            states_after_first,
            "{label}: the skipped root rewrote no per-file state"
        );
        assert_eq!(
            source_facts(&db),
            after_first,
            "{label}: no fact moved"
        );
    }
}

/// R2: the local rule reads a size change even when the mtime did not move,
/// and keeps an older-mtime file whose size matches -- a local root holds this
/// machine's own append-only history, so the watermark is a sound cutoff.
#[test]
fn r2_a_local_root_reads_a_size_change_and_keeps_a_same_size_older_mtime() {
    let fixture = Fixture::new();
    let root = fixture.path().join("laptop-root");
    let session = fixture.write_session(
        &root,
        "projects/-l/agent-l.jsonl",
        "sess-r2-local",
        "same length answer",
    );
    fixture.write_sources(&[("laptop", "local", "laptop", root.to_str().unwrap(), false)]);

    let first = fixture.index_verbose();
    assert_eq!(first.code, Some(0), "stderr={}", first.stderr);
    assert_eq!(first.dispatches(), 1, "the first round reads the file");

    // (1) Same size, mtime moved *backwards*, content identical: the local rule
    // has nothing to act on, and the completed input is the evidence for that.
    let original_mtime = mtime_of(&session);
    set_mtime(&session, SystemTime::now() - Duration::from_secs(7_200));
    let older = fixture.index_verbose();
    assert_eq!(older.code, Some(0), "stderr={}", older.stderr);
    assert_eq!(
        older.dispatches(),
        0,
        "a local root does not re-read a same-size file whose mtime regressed; stderr={}",
        older.stderr
    );

    // (2) A size change with the mtime moved back to what the first round
    // recorded: the mtime comparison still says nothing, the size does. The
    // session grows by one more well-formed record, which is what a local
    // history does.
    let appended = serde_json::json!({
        "parentUuid": "sess-r2-local-assistant",
        "cwd": "/synthetic/project",
        "sessionId": "sess-r2-local",
        "version": "2.0.37",
        "type": "assistant",
        "message": {"model": "claude-opus-4", "role": "assistant",
                    "content": [{"type": "text", "text": "a later synthetic answer"}]},
        "uuid": "sess-r2-local-assistant-2",
        "timestamp": "2026-01-01T00:00:02.000Z"
    });
    let body = std::fs::read_to_string(&session).expect("read session");
    std::fs::write(&session, format!("{body}{appended}\n")).expect("grow the session");
    set_mtime(&session, original_mtime);
    let grown = fixture.index_verbose();
    assert_eq!(grown.code, Some(0), "stderr={}", grown.stderr);
    assert_eq!(
        grown.dispatches(),
        1,
        "a size change is read even when the mtime is unchanged; stderr={}",
        grown.stderr
    );
    assert!(
        source_facts(&fixture.open_db()).complete_inputs >= 2,
        "the grown file is a second, independently identified input"
    );

    // (3) A brand-new file carrying an old mtime has no record here, so it is
    // read whatever its timestamp says.
    let late = root.join("projects/-l/agent-late.jsonl");
    std::fs::create_dir_all(late.parent().expect("late parent")).expect("mkdir late parent");
    let late_body: String = claude_session("sess-r2-late", "synthetic question", "late answer")
        .iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&late, late_body).expect("write the late session");
    set_mtime(&late, SystemTime::now() - Duration::from_secs(7_200));
    let arrived = fixture.index_verbose();
    assert_eq!(arrived.code, Some(0), "stderr={}", arrived.stderr);
    assert_eq!(
        arrived.dispatches(),
        1,
        "a new file with an old mtime is read; stderr={}",
        arrived.stderr
    );
}

/// R2: a mirror root's own recorded state decides, not the watermark: a file
/// whose size matches but whose mtime moved is read again, and a file that
/// disappeared from the mirror loses its recorded state without disturbing the
/// file that stayed.
#[test]
fn r2_a_mirror_root_reads_a_same_size_different_mtime_and_keeps_the_rest() {
    let fixture = Fixture::new();
    const REMOTE: &str = "~/.claude/projects";
    fixture.write_sources(&[("laptop", "ssh", "laptop", REMOTE, false)]);
    let mirrored = fixture.prepare_mirror("laptop", REMOTE);
    let kept = fixture.write_session(
        &mirrored,
        "projects/-m/agent-kept.jsonl",
        "sess-r2-mirror-kept",
        "mirror kept answer",
    );
    let swapped = fixture.write_session(
        &mirrored,
        "projects/-m/agent-swapped.jsonl",
        "sess-r2-mirror-swapped",
        "mirror swapped ans",
    );

    let first = fixture.index_verbose();
    assert_eq!(first.code, Some(0), "stderr={}", first.stderr);
    assert_eq!(first.dispatches(), 2, "both mirrored files are read once");
    let db = fixture.open_db();
    let states = file_state_rows(&db, "cfg:laptop:");
    assert_eq!(states.len(), 2, "both files' state is recorded: {states:?}");
    drop(db);

    // The far machine replaces `swapped` in place with a copy of the same
    // length and an older timestamp: for a mirror root only its own recorded
    // mtime can see that.
    let original = std::fs::read(&swapped).expect("read the mirrored file");
    set_mtime(&swapped, SystemTime::now() - Duration::from_secs(7_200));
    std::fs::write(&swapped, &original).expect("rewrite the mirrored file");
    set_mtime(&swapped, SystemTime::now() - Duration::from_secs(7_200));
    assert_eq!(
        stamp(&swapped).0,
        i64::try_from(original.len()).unwrap(),
        "sanity: the replacement keeps the size"
    );

    let second = fixture.index_verbose();
    assert_eq!(second.code, Some(0), "stderr={}", second.stderr);
    assert_eq!(
        second.dispatches(),
        1,
        "only the file whose recorded mtime moved is read again; stderr={}",
        second.stderr
    );

    // The enumeration the run saw still covers both paths, so the absent one is
    // dropped from the state and the kept one stays.
    std::fs::remove_file(&swapped).expect("the file leaves the mirror");
    let third = fixture.index_verbose();
    assert_eq!(third.code, Some(0), "stderr={}", third.stderr);
    assert_eq!(
        third.dispatches(),
        0,
        "the kept file is unchanged and proven; stderr={}",
        third.stderr
    );
    let db = fixture.open_db();
    let states = file_state_rows(&db, "cfg:laptop:");
    assert_eq!(
        states.len(),
        1,
        "the absent path's state is dropped, the kept one stays: {states:?}"
    );
    assert!(
        states[0].contains("agent-kept.jsonl"),
        "the state that stayed is the kept file's: {states:?}"
    );
    let _ = kept;
}

// ---------------------------------------------------------------------------
// R3: what counts as evidence, and what must force a re-read
// ---------------------------------------------------------------------------

/// R3 (ruling fe72d5a7, 原料捕获身份): per-file state written without a source
/// receipt is not evidence that the source kernel read the file -- and the
/// source path captures a file under the *same* raw-mirror session identity the
/// older paths use, so a tree those paths already captured migrates instead of
/// colliding. The declaration's namespace stays the machine identity.
///
/// Both root kinds and both connectors take part: a machine-local configured
/// root with a Claude session, and the connector's own home roots with one
/// Claude and one Codex session.
///
/// The pre-state comes from `util::source_legacy_seed` -- public storage,
/// raw-mirror and root-id primitives -- rather than from a legacy CLI run, so
/// the case no longer depends on the entry point it is migrating away from.
/// The migration claim is unchanged: what the seed leaves behind is a
/// conversation, a settled watermark, per-file state and a capture, and *no*
/// source fact.
#[test]
fn r3_legacy_file_state_without_a_source_receipt_is_read_again() {
    let fixture = Fixture::new();
    let laptop = fixture.path().join("laptop-root");
    let configured_file = fixture.write_session(
        &laptop,
        "projects/-l/agent-l.jsonl",
        "sess-r3-cap-cfg",
        "configured answer",
    );
    fixture.write_sources(&[("laptop", "local", "laptop", laptop.to_str().unwrap(), false)]);
    let projects = fixture.home().join(".claude/projects");
    let home_file = fixture.write_session(
        &projects,
        "proj-l/session.jsonl",
        "sess-r3-cap-home",
        "home answer",
    );
    let codex_file = fixture.write_codex_session("sess-r3-cap-codex", "codex answer");
    let codex_root = fixture.home().join(".codex/sessions");

    // The pre-state: one conversation, one settled watermark, one per-file
    // state and one capture per file, and no source fact anywhere.
    util::source_legacy_seed::seed_legacy_source_fixture(
        &fixture.data_dir(),
        &[
            util::source_legacy_seed::LegacySeedFile {
                connector: "claude",
                source_id: "laptop",
                root_id: &scan_root_meta::config_root_id(
                    "laptop",
                    &scan_root_meta::canonicalize_root_path(&laptop),
                ),
                root_path: &laptop,
                source_path: &configured_file,
            },
            util::source_legacy_seed::LegacySeedFile {
                connector: "claude",
                source_id: "local",
                root_id: &scan_root_meta::home_root_id(
                    "claude",
                    &scan_root_meta::canonicalize_root_path(&projects),
                ),
                root_path: &projects,
                source_path: &home_file,
            },
            util::source_legacy_seed::LegacySeedFile {
                connector: "codex",
                source_id: "local",
                root_id: &scan_root_meta::home_root_id(
                    "codex",
                    &scan_root_meta::canonicalize_root_path(&codex_root),
                ),
                root_path: &codex_root,
                source_path: &codex_file,
            },
        ],
    )
    .expect("seed the pre-state");

    // The pre-state really is what the migration is about: the canonical facts
    // and the capture are there, and not one source fact is.
    let db = fixture.open_db();
    assert_eq!(
        scalar(&db, "SELECT COUNT(*) FROM conversations"),
        3,
        "the seed wrote a conversation per file"
    );
    assert!(
        source_facts(&db).messages > 0,
        "the seeded conversations carry messages: {:?}",
        source_facts(&db)
    );
    let facts = source_facts(&db);
    assert_eq!(facts.complete_inputs, 0, "the seed claims no source facts");
    assert_eq!(facts.other_inputs, 0, "and no unfinished input either");
    assert_eq!(facts.records, 0, "and no source record");
    assert_eq!(
        facts.receipts, 0,
        "and no source activation receipt (including source_input_activation_v1)"
    );
    assert_eq!(
        file_state_rows(&db, "cfg:laptop:").len(),
        1,
        "the seed records the configured root's file"
    );
    assert_eq!(
        file_state_rows(&db, "home:claude:").len(),
        1,
        "the seed records the Claude home file"
    );
    assert_eq!(
        file_state_rows(&db, "home:codex:").len(),
        1,
        "the seed records the Codex home file"
    );
    drop(db);
    let captured = manifest_identities(fixture.path());
    assert_eq!(
        captured.len(),
        3,
        "the seed captured each of the three sources exactly once: {captured:?}"
    );
    assert!(
        captured.iter().all(|identity| identity == "local"),
        "the captures all carry the legacy session identity: {captured:?}"
    );
    assert_eq!(
        util::source_legacy_seed::mirror_blob_files(&fixture.data_dir()).len(),
        3,
        "the raw mirror really holds the captured bytes, not only the manifests"
    );

    // The same unchanged files, now through the source kernel: the metadata
    // comparison says nothing changed, and it alone must not be enough.
    let source = fixture.index_verbose();
    assert_eq!(
        source.code,
        Some(0),
        "a tree the legacy path already scanned migrates; stderr={}",
        source.stderr
    );
    assert_eq!(
        source.dispatches(),
        3,
        "all three files are read through the source kernel; stderr={}",
        source.stderr
    );
    let db = fixture.open_db();
    assert_eq!(
        source_facts(&db).complete_inputs,
        3,
        "the source facts land for every file"
    );
    let mut namespaces: Vec<String> = {
        let mut stmt = db
            .prepare("SELECT DISTINCT identity_namespace FROM source_inputs ORDER BY 1")
            .expect("prepare namespaces");
        stmt.query_map([], |row| row.get(0))
            .expect("query namespaces")
            .collect::<Result<Vec<String>, _>>()
            .expect("collect namespaces")
    };
    namespaces.sort();
    assert!(
        namespaces.contains(&"laptop".to_string()),
        "the configured root's inputs keep the machine namespace: {namespaces:?}"
    );
    assert!(
        namespaces.contains(&"local".to_string()),
        "the home roots' inputs keep the local namespace: {namespaces:?}"
    );
    drop(db);
    assert_eq!(
        manifest_identities(fixture.path()),
        captured,
        "the source run merged into the existing captures and relabelled none"
    );
}

/// R3: the same file and the same metadata under a changed path mapping is a
/// different input. It is read again, a second identity is created, and the
/// first input stays complete with its own receipt.
#[test]
fn r3_a_changed_mapping_reads_the_file_again_and_keeps_the_old_receipt() {
    let fixture = Fixture::new();
    let root = fixture.path().join("mapped-root");
    fixture.write_session(
        &root,
        "projects/-m/agent-m.jsonl",
        "sess-r3-mapping",
        "mapped answer",
    );
    fixture.write_mapped_source("laptop", &root, "/synthetic-new-a");

    let first = fixture.index_verbose();
    assert_eq!(first.code, Some(0), "stderr={}", first.stderr);
    assert_eq!(first.dispatches(), 1, "the first round reads the file");
    let db = fixture.open_db();
    let before = input_profiles(&db);
    assert_eq!(before.len(), 1, "one input identity so far");
    let before_keys = receipt_keys(&db);
    drop(db);

    // Nothing about the file moves: only the configured mapping does.
    fixture.write_mapped_source("laptop", &root, "/synthetic-new-b");
    let second = fixture.index_verbose();
    assert_eq!(second.code, Some(0), "stderr={}", second.stderr);
    assert_eq!(
        second.dispatches(),
        1,
        "a changed mapping is a changed input, so the file is read again; stderr={}",
        second.stderr
    );

    let db = fixture.open_db();
    let after = input_profiles(&db);
    assert_eq!(after.len(), 2, "a second identity is created");
    assert_ne!(
        before[0].0, after[1].0,
        "the normalizer identity moved with the mapping"
    );
    assert_eq!(
        input_states(&db),
        vec!["complete".to_string(), "complete".to_string()],
        "the earlier input stays complete"
    );
    assert_eq!(
        after[0], before[0],
        "the earlier input's own profile is untouched"
    );
    let after_keys = receipt_keys(&db);
    assert!(
        after_keys.contains(&before_keys),
        "the earlier receipt is still there: before={before_keys} after={after_keys}"
    );
}

/// R3: a changed fixed safety copy moves the safety identity, so the file is
/// read again under the new contract rather than skipped on its metadata.
#[test]
fn r3_a_changed_fixed_copy_reads_the_file_again() {
    let fixture = Fixture::new();
    let root = fixture.path().join("laptop-root");
    fixture.write_session(
        &root,
        "projects/-l/agent-l.jsonl",
        "sess-r3-safety",
        "safety answer",
    );
    fixture.write_sources(&[("laptop", "local", "laptop", root.to_str().unwrap(), false)]);

    let first = fixture.index_verbose();
    assert_eq!(first.code, Some(0), "stderr={}", first.stderr);
    assert_eq!(first.dispatches(), 1, "the first round reads the file");
    let db = fixture.open_db();
    let before = input_profiles(&db);
    assert_eq!(before.len(), 1);
    drop(db);

    // The fixed copy itself changes: one more excluded memory filename. The
    // live configuration is not what decides this -- the caller's fixed copy
    // is.
    let copy = fixture.fixed_copy();
    let mut text = std::fs::read_to_string(&copy).expect("read the fixed copy");
    text = text.replace(
        "memory_files = [\"USER.md\"",
        "memory_files = [\"EXTRA-NOTES.md\", \"USER.md\"",
    );
    std::fs::write(&copy, text).expect("rewrite the fixed copy");

    let second = fixture.index_verbose();
    assert_eq!(second.code, Some(0), "stderr={}", second.stderr);
    assert_eq!(
        second.dispatches(),
        1,
        "a changed fixed safety copy is a changed contract, so the file is read again; stderr={}",
        second.stderr
    );
    let db = fixture.open_db();
    let after = input_profiles(&db);
    assert_eq!(after.len(), 2, "a second identity is created");
    assert_ne!(
        before[0].1, after[1].1,
        "the safety contract identity moved with the copy"
    );
    assert_eq!(after[0], before[0], "the earlier input's profile is untouched");
}

/// R3 (the coexistence case): a completed input and a later unfinished one for
/// the *same* locator. The earlier success must not hide the later failure.
///
/// The metadata never explains a read here: the third and fourth rounds put the
/// file back on exactly the size and mtime a completed read recorded, so only
/// the unfinished input decides. The third round is the same broken input
/// again -- it is attempted and fails, and nothing it could not land moves --
/// and the fourth repairs it, which is what lets the locator complete again.
#[test]
fn r3_an_unfinished_input_for_the_same_locator_forces_a_re_read() {
    let fixture = Fixture::new();
    let root = fixture.path().join("laptop-root");
    let relative = "projects/-l/agent-coexist.jsonl";
    let session = fixture.write_session(
        &root,
        relative,
        "sess-r3-coexist-a",
        "coexist answer",
    );
    fixture.write_sources(&[("laptop", "local", "laptop", root.to_str().unwrap(), false)]);
    let first_line = claude_session("sess-r3-coexist-a", "synthetic question", "coexist answer")
        .remove(0);
    let a_size = usize::try_from(stamp(&session).0).expect("a positive file size");
    let a_mtime = mtime_of(&session);

    // A completes, and its own recorded state is the baseline to protect.
    let first = fixture.index_verbose();
    assert_eq!(first.code, Some(0), "stderr={}", first.stderr);
    assert_eq!(first.dispatches(), 1, "A is read and completed");
    let db = fixture.open_db();
    assert_eq!(input_states(&db), vec!["complete".to_string()], "A completes");
    let recorded = file_state_rows(&db, "cfg:laptop:");
    let receipts = receipt_keys(&db);
    assert_eq!(recorded.len(), 1, "A's per-file state is recorded");
    drop(db);

    // B: as long as A, one unparseable line, its own session identity, and a
    // newer mtime -- the local rule's cutoff is the watermark A's run wrote.
    std::fs::write(&session, coexist_broken(&first_line, "sess-r3-coexist-b", a_size))
        .expect("write B");
    set_mtime(&session, SystemTime::now());
    let second = fixture.index_verbose();
    second.expect_failure("an input with an unparseable line is not a success");
    let db = fixture.open_db();
    assert_eq!(
        input_states(&db),
        vec!["complete".to_string(), "partial".to_string()],
        "A is complete and B is unfinished, for the same locator"
    );
    assert_eq!(
        file_state_rows(&db, "cfg:laptop:"),
        recorded,
        "the failed root kept A's per-file state"
    );
    assert_eq!(
        receipt_keys(&db),
        receipts,
        "the failed root kept A's receipt"
    );
    let witness_after_failure = link_witness_rows(&db);
    assert!(
        !witness_after_failure.is_empty(),
        "B's own published link is the witness the retry has to keep"
    );
    drop(db);

    // Back to exactly the metadata a completed read recorded. A skip would end
    // the run cleanly; the unfinished input is the only thing that can make it
    // read -- and fail -- again.
    set_mtime(&session, a_mtime);
    let third = fixture.index_verbose();
    third.expect_failure(
        "the unfinished input is attempted again and the file is still unparseable",
    );
    assert!(
        !third.stderr.contains("source conflict"),
        "the retry stages the claim with its own installed evidence instead of \
         demoting it back to pending; stderr={}",
        third.stderr
    );
    let db = fixture.open_db();
    assert_eq!(
        link_witness_rows(&db),
        witness_after_failure,
        "the installed witness is byte-for-byte unchanged by the retry"
    );
    assert_eq!(
        input_states(&db),
        vec!["complete".to_string(), "partial".to_string()],
        "B is still the unfinished input for this locator"
    );
    assert_eq!(
        file_state_rows(&db, "cfg:laptop:"),
        recorded,
        "the retry's own failure still left A's per-file state alone"
    );
    assert_eq!(
        receipt_keys(&db),
        receipts,
        "the retry's own failure still left A's receipt alone"
    );
    drop(db);

    // B repaired in place -- the same session, both records well-formed, the
    // same length and the same metadata: again only the unfinished input can
    // explain the read, and this time it completes.
    std::fs::write(
        &session,
        coexist_repaired(&first_line, "sess-r3-coexist-b", a_size),
    )
    .expect("repair B");
    set_mtime(&session, a_mtime);
    let fourth = fixture.index_verbose();
    assert_eq!(
        fourth.code,
        Some(0),
        "the repaired input completes; stderr={}",
        fourth.stderr
    );
    let db = fixture.open_db();
    assert_eq!(
        input_states(&db),
        vec![
            "complete".to_string(),
            "partial".to_string(),
            "complete".to_string()
        ],
        "the repaired input is a third, completed input for the same locator"
    );
}

/// The same file as A, one unparseable second line, its own session identity.
fn coexist_broken(first_line: &serde_json::Value, session: &str, total: usize) -> String {
    let mut line = first_line.clone();
    line["sessionId"] = serde_json::json!(session);
    line["uuid"] = serde_json::json!(format!("{session}-user"));
    let text = line.to_string();
    let rest = total
        .checked_sub(text.len() + 2)
        .expect("A is long enough for B's first line");
    format!("{text}\n{{{}\n", "x".repeat(rest - 1))
}

/// The same file as A, both records well-formed, its own session identity.
fn coexist_repaired(first_line: &serde_json::Value, session: &str, total: usize) -> String {
    let mut line = first_line.clone();
    line["sessionId"] = serde_json::json!(session);
    line["uuid"] = serde_json::json!(format!("{session}-user"));
    let text = line.to_string();
    let mut second = serde_json::json!({
        "parentUuid": format!("{session}-user"),
        "cwd": "/synthetic/project",
        "sessionId": session,
        "version": "2.0.37",
        "type": "assistant",
        "message": {"model": "claude-opus-4", "role": "assistant",
                    "content": [{"type": "text", "text": ""}]},
        "uuid": format!("{session}-assistant"),
        "timestamp": "2026-01-01T00:00:01.000Z"
    });
    let unpadded = second.to_string().len();
    let pad = total
        .checked_sub(text.len() + unpadded + 2)
        .expect("A is long enough for B's two records");
    second["message"]["content"][0]["text"] = serde_json::json!("x".repeat(pad));
    format!("{text}\n{second}\n")
}

/// R3: a legitimate late transaction failure lands no source fact, and the
/// next process reads the same input again and completes it.
#[test]
fn r3_a_late_transaction_failure_is_retried_to_completion() {
    let fixture = Fixture::new();
    let root = fixture.path().join("laptop-root");
    fixture.write_session(
        &root,
        "projects/-l/agent-l.jsonl",
        "sess-r3-late",
        "late failure answer",
    );
    fixture.write_sources(&[("laptop", "local", "laptop", root.to_str().unwrap(), false)]);

    let failed = fixture.index_env(&[("CASS_SRC05B07_FAIL_AT", "activation")]);
    failed.expect_failure("the armed late fault stops the input before it lands");
    let db = fixture.open_db();
    assert_eq!(
        source_facts(&db).complete_inputs,
        0,
        "the failed attempt left no completed input"
    );
    assert_eq!(
        file_state_rows(&db, "cfg:laptop:").len(),
        0,
        "and advanced no per-file state, so the next round reads the file"
    );
    drop(db);

    let retried = fixture.index_verbose();
    assert_eq!(
        retried.code,
        Some(0),
        "the retry completes; stderr={}",
        retried.stderr
    );
    assert_eq!(
        retried.dispatches(),
        1,
        "the same file is read again through the source kernel; stderr={}",
        retried.stderr
    );
    assert_eq!(
        source_facts(&fixture.open_db()).complete_inputs,
        1,
        "and it completes this time"
    );
}

/// SRC05B-08 (standalone ruling): a non-empty input whose records project no
/// conversation is still a complete input. Its claims are installed as
/// standalone links, it gets its own durable receipt, it creates no canonical
/// message, and a replay reproduces all of it.
///
/// The same file is exercised twice: once into a fresh database, and once into
/// one that already holds canonical messages from another session.
#[test]
fn r1_a_non_empty_input_without_a_conversation_lands_as_a_standalone() {
    for populated in [false, true] {
        let label = if populated { "populated" } else { "fresh" };
        let fixture = Fixture::new();
        let root = fixture.path().join("backup-root");
        if populated {
            // A normal session first, so the library holds messages before the
            // standalone input arrives.
            fixture.write_session(
                &root,
                "projects/-f/agent-f.jsonl",
                "sess-r1-populated",
                "populated answer",
            );
        }
        fixture.write_sources(&[("backup", "local", "backup", root.to_str().unwrap(), true)]);
        if populated {
            let seeded = fixture.index_verbose();
            assert_eq!(
                seeded.code,
                Some(0),
                "{label}: the seeding run succeeds; stderr={}",
                seeded.stderr
            );
        }
        // The fresh case has no database at all before the first run.
        let messages_before = if fixture.db().exists() {
            scalar(&fixture.open_db(), "SELECT COUNT(*) FROM messages")
        } else {
            0
        };

        // A record that maps to no message: the file is non-empty, and the
        // input has no conversation at all.
        let standalone = root.join("projects/-f/summary.jsonl");
        std::fs::create_dir_all(standalone.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &standalone,
            "{\"type\":\"summary\",\"summary\":\"synthetic standalone summary\",\"leafUuid\":\"synthetic-leaf\",\"isSidechain\":false}\n",
        )
        .expect("write the standalone file");

        let first = fixture.index_verbose();
        assert_eq!(
            first.code,
            Some(0),
            "{label}: the standalone input completes; stderr={}",
            first.stderr
        );
        // The root is a `full_scan` one: it keeps no per-file state, so every
        // round hands over its whole enumeration and the seeds are re-read as
        // replays. What has to hold is that they add nothing.
        assert_eq!(
            first.source_inputs_committed(),
            if populated { 2 } else { 1 },
            "{label}: the standalone input commits, with exactly one seed replay when populated",
        );
        let db = fixture.open_db();
        let after_first = source_facts(&db);
        assert_eq!(
            after_first.complete_inputs,
            if populated { 2 } else { 1 },
            "{label}: the standalone input reached complete"
        );
        assert_eq!(
            after_first.receipts,
            if populated { 2 } else { 1 },
            "{label}: it has its own durable receipt"
        );
        assert_eq!(
            scalar(
                &db,
                "SELECT COUNT(*) FROM source_message_links WHERE authority = 'standalone'"
            ),
            1,
            "{label}: its claim is installed as a standalone link"
        );
        assert_eq!(
            scalar(&db, "SELECT COUNT(*) FROM messages"),
            messages_before,
            "{label}: it creates no canonical message"
        );
        drop(db);

        let second = fixture.index_verbose();
        assert_eq!(
            second.code,
            Some(0),
            "{label}: the replay succeeds; stderr={}",
            second.stderr
        );
        let db = fixture.open_db();
        assert_eq!(
            source_facts(&db),
            after_first,
            "{label}: the replay adds nothing"
        );
        assert_eq!(
            scalar(&db, "SELECT COUNT(*) FROM messages"),
            messages_before,
            "{label}: and still creates no canonical message"
        );
    }
}

/// SRC05B-08 (standalone ruling): one file carrying both a conversation and a
/// record that projects no message installs a link for every record, and a
/// replay reproduces the same links and receipts.
#[test]
fn r3_a_mixed_file_installs_a_link_for_every_record() {
    let fixture = Fixture::new();
    let root = fixture.path().join("backup-root");
    fixture.write_session(
        &root,
        "projects/-f/agent-f.jsonl",
        "sess-r3-mixed",
        "mixed answer",
    );
    // The same file also carries a summary record, which projects no message.
    let session = root.join("projects/-f/agent-f.jsonl");
    let mut body = std::fs::read_to_string(&session).expect("read session");
    body.push_str(
        "{\"type\":\"summary\",\"summary\":\"synthetic mixed summary\",\"leafUuid\":\"synthetic-mixed-leaf\",\"isSidechain\":false}\n",
    );
    std::fs::write(&session, body).expect("append the summary record");
    fixture.write_sources(&[("backup", "local", "backup", root.to_str().unwrap(), true)]);

    let first = fixture.index_verbose();
    assert_eq!(
        first.code,
        Some(0),
        "a mixed file completes; stderr={}",
        first.stderr
    );
    let db = fixture.open_db();
    let after_first = source_facts(&db);
    assert_eq!(after_first.complete_inputs, 1, "one input");
    assert_eq!(
        scalar(&db, "SELECT COUNT(*) FROM source_records"),
        3,
        "all three records are staged, including the one that projects no message"
    );
    assert_eq!(
        scalar(
            &db,
            "SELECT COUNT(*) FROM source_message_links WHERE authority = 'canonical'"
        ),
        2,
        "the two message records bind canonically"
    );
    assert_eq!(
        scalar(
            &db,
            "SELECT COUNT(*) FROM source_message_links WHERE authority = 'standalone'"
        ),
        1,
        "and the summary record's claim is installed as a standalone link"
    );
    drop(db);

    let second = fixture.index_verbose();
    assert_eq!(
        second.code,
        Some(0),
        "the replay succeeds; stderr={}",
        second.stderr
    );
    let db = fixture.open_db();
    assert_eq!(source_facts(&db), after_first, "the replay adds nothing");
}

// ---------------------------------------------------------------------------
// R4: success and failure are attributed per root
// ---------------------------------------------------------------------------

/// R4: one refused root keeps its watermark and its per-file state exactly
/// where they were, while an independent healthy root advances in the same
/// run. Both schedulings.
#[test]
fn r4_a_refused_root_keeps_its_state_and_the_healthy_root_advances() {
    for streaming in [true, false] {
        let label = if streaming { "streaming" } else { "batch" };
        let fixture = Fixture::new();
        let good = fixture.path().join("good-root");
        let bad = fixture.path().join("bad-root");
        fixture.write_session(&good, "projects/-g/agent-g.jsonl", "sess-r4-good", "good answer");
        fixture.write_session(&bad, "projects/-b/agent-b.jsonl", "sess-r4-bad", "bad answer");
        fixture.write_sources(&[
            ("good", "local", "good", good.to_str().unwrap(), false),
            ("bad", "local", "bad", bad.to_str().unwrap(), false),
        ]);
        let run = |fixture: &Fixture| {
            if streaming {
                fixture.index_cell(true, false)
            } else {
                fixture.index_cell(false, false)
            }
        };

        // Round 1: both roots scan cleanly, so both have state to protect.
        let first = run(&fixture);
        assert_eq!(
            first.code,
            Some(0),
            "{label}: both roots scan cleanly; stderr={}",
            first.stderr
        );
        assert_eq!(
            first.dispatches(),
            2,
            "{label}: one file per root; stderr={}",
            first.stderr
        );
        // Every connector takes a plan for this root and scans it, so only the
        // refusing connector's own rows are the ones this case is about: the
        // others have nothing under the root and legitimately advance.
        let (before_watermarks, before_states) = {
            let db = fixture.open_db();
            (
                rows_for_connector(&watermark_rows(&db, "cfg:bad:"), "claude"),
                rows_for_connector(&file_state_rows(&db, "cfg:bad:"), "claude"),
            )
        };
        assert!(
            !before_watermarks.is_empty() && !before_states.is_empty(),
            "{label}: the refused root has rows to protect"
        );

        // Round 2: a new file in each root, and the refused root's new file
        // cannot be read by this process at all.
        fixture.write_session(&good, "projects/-g/agent-g2.jsonl", "sess-r4-good2", "good two");
        let bad_new = fixture.write_session(
            &bad,
            "projects/-b/agent-b2.jsonl",
            "sess-r4-bad2",
            "bad two",
        );
        make_unreadable(&bad_new);

        let second = run(&fixture);
        second.expect_failure(&format!("{label}: a refused input fails its root"));

        let db = fixture.open_db();
        assert_eq!(
            rows_for_connector(&watermark_rows(&db, "cfg:bad:"), "claude"),
            before_watermarks,
            "{label}: the refused root's watermark stays exactly where it was"
        );
        assert_eq!(
            rows_for_connector(&file_state_rows(&db, "cfg:bad:"), "claude"),
            before_states,
            "{label}: the refused root's per-file state stays exactly where it was"
        );
        let good_states = rows_for_connector(&file_state_rows(&db, "cfg:good:"), "claude");
        assert!(
            good_states
                .iter()
                .any(|row| row.contains("agent-g2.jsonl")),
            "{label}: the healthy root advanced past its new file: {good_states:?}"
        );
        assert!(
            !good_states.iter().any(|row| row.contains("agent-b2.jsonl")),
            "{label}: the two roots' rows stay apart: {good_states:?}"
        );
        drop(db);

        // Round 3: the obstacle is gone. The refused root commits its new file
        // and the healthy root is not read again.
        make_readable(&bad_new);
        let third = run(&fixture);
        assert_eq!(
            third.code,
            Some(0),
            "{label}: the retry succeeds; stderr={}",
            third.stderr
        );
        assert_eq!(
            third.dispatches(),
            1,
            "{label}: only the recovered root's new file is read; stderr={}",
            third.stderr
        );
    }
}

/// Only the owner may read this file: `chmod 000` is what makes an input
/// refused rather than merely slow, and it is restored by the callers.
fn make_unreadable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000))
        .expect("make the file unreadable");
}

fn make_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
        .expect("restore the file");
}

// ---------------------------------------------------------------------------
// R5: `--full` and the roots it may touch
// ---------------------------------------------------------------------------

/// R5: `--full` clears a normal root's own state and reads everything again,
/// idempotently -- and a `full_scan` root in the same run still takes neither
/// row.
#[test]
fn r5_full_re_reads_a_normal_root_and_a_full_scan_root_takes_no_state() {
    let fixture = Fixture::new();
    let normal = fixture.path().join("laptop-root");
    let declared = fixture.path().join("backup-root");
    fixture.write_session(&normal, "projects/-l/agent-l.jsonl", "sess-r5-normal", "normal one");
    fixture.write_session(&declared, "projects/-f/agent-f.jsonl", "sess-r5-full", "full one");
    fixture.write_sources(&[
        ("laptop", "local", "laptop", normal.to_str().unwrap(), false),
        ("backup", "local", "backup", declared.to_str().unwrap(), true),
    ]);

    let first = fixture.index_verbose();
    assert_eq!(first.code, Some(0), "stderr={}", first.stderr);
    assert_eq!(first.dispatches(), 2, "both roots are read once");
    let db = fixture.open_db();
    let facts = source_facts(&db);
    assert_eq!(facts.complete_inputs, 2, "one input per root");
    let normal_states = file_state_rows(&db, "cfg:laptop:");
    assert_eq!(normal_states.len(), 1, "the normal root keeps its state");
    assert_eq!(
        watermark_rows(&db, "cfg:backup:"),
        Vec::<String>::new(),
        "the full_scan root kept no watermark even here"
    );
    assert_eq!(
        file_state_rows(&db, "cfg:backup:"),
        Vec::<String>::new(),
        "the full_scan root kept no per-file state even here"
    );
    drop(db);

    // Nothing changed, so an ordinary run hands over nothing.
    let settled = fixture.index_verbose();
    assert_eq!(settled.code, Some(0), "stderr={}", settled.stderr);
    assert_eq!(settled.dispatches(), 1, "only the full_scan root is read again");

    // `--full` re-reads the normal root too, and adds nothing.
    let forced = fixture.index_with(&["--full"]);
    assert_eq!(forced.code, Some(0), "stderr={}", forced.stderr);
    assert_eq!(
        forced.dispatches(),
        2,
        "--full reads both roots again; stderr={}",
        forced.stderr
    );
    let db = fixture.open_db();
    assert_eq!(
        source_facts(&db),
        facts,
        "--full is idempotent: the same inputs, the same facts"
    );
    assert_eq!(
        watermark_rows(&db, "cfg:backup:"),
        Vec::<String>::new(),
        "a full scan of the run still leaves the full_scan root without a watermark"
    );
}
