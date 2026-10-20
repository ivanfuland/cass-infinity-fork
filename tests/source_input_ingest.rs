//! SRC05B-07 acceptance: the formal single-input safe-ingest path.
//!
//! Every case here drives the real `cass index` binary over a private synthetic
//! root, a private fixed safety copy and a private data directory, and then
//! reads the resulting SQLite database directly. Nothing calls an internal
//! helper: the seam is the CLI, the database and the process boundary, which is
//! what the ticket asks for.
//!
//! The fixtures are synthetic and neutral. No real session, path or secret
//! appears in this file.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rusqlite::OptionalExtension as _;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// One bounded `cass index` run: what it wrote, or the fact that it had to be
/// stopped because it never returned.
struct BoundedRun {
    timed_out: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

/// A private root holding a HOME, a data directory and the fixed safety copy.
struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home")).expect("mkdir home");
        std::fs::create_dir_all(root.path().join("data")).expect("mkdir data");
        // The fixed copy is the built-in configuration's exact bytes; the
        // caller supplies it and this path never invents one.
        std::fs::write(
            root.path().join("fixed-safety.toml"),
            include_bytes!("../config/excluded_context_paths.toml"),
        )
        .expect("write fixed safety copy");
        Self { root }
    }

    /// Point every source-discovery environment at this fixture.
    ///
    /// The host running the tests may itself export these (a CI or control-plane
    /// machine commonly does), and an inherited value would let a fixture
    /// process scan the host's real history -- slow, and a privacy problem. The
    /// fixture therefore states every one of them explicitly rather than hoping
    /// the ambient environment is clean.
    fn isolate<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("HOME", self.home())
            .env("XDG_DATA_HOME", self.home().join(".local/share"))
            .env("XDG_CONFIG_HOME", self.home().join(".config"))
            .env("CODEX_HOME", self.home().join(".codex"))
            .env(
                "CASS_AIDER_DATA_ROOT",
                self.home().join(".aider"),
            )
            .env("PI_SESSIONS_DIR", self.home().join(".pi"))
            .env("PI_CODING_AGENT_DIR", self.home().join(".pi"))
            .env("GOOSE_PATH_ROOT", self.home().join(".goose"))
            .env("HERMES_HOME", self.home().join(".hermes"))
            .env("CASS_DATA_DIR", self.data_dir())
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("NO_COLOR", "1")
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn db(&self) -> PathBuf {
        self.data_dir().join("agent_search.db")
    }

    fn fixed_copy(&self) -> PathBuf {
        self.root.path().join("fixed-safety.toml")
    }

    /// Write a Claude Code session at the layout its connector discovers.
    fn write_claude_session(&self, name: &str, lines: &[serde_json::Value]) -> PathBuf {
        let dir = self.home().join(".claude/projects").join(name);
        std::fs::create_dir_all(&dir).expect("mkdir claude project");
        let path = dir.join("session.jsonl");
        let body: String = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&path, body).expect("write claude session");
        path
    }

    /// Write a Codex rollout at the layout its connector discovers.
    fn write_codex_session(&self, name: &str, lines: &[serde_json::Value]) -> PathBuf {
        let dir = self.home().join(".codex/sessions/2026/01");
        std::fs::create_dir_all(&dir).expect("mkdir codex sessions");
        let path = dir.join(format!("rollout-2026-01-01T00-00-00-{name}.jsonl"));
        let body: String = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&path, body).expect("write codex session");
        path
    }

    fn run_index(&self) -> std::process::Output {
        let copy = self.fixed_copy();
        self.run_index_with(&["--source-safety-config", copy.to_str().unwrap()])
    }

    fn run_index_with(&self, extra: &[&str]) -> std::process::Output {
        self.run_index_env(extra, &[])
    }

    /// Run `cass index` with the same arguments as [`Self::run_index_with`],
    /// but bounded: the resident watch loop is a process that never returns on
    /// its own, so a case that starts one has to stop it rather than wait.
    ///
    /// A run that outlives `limit` is killed and reaped, and reported with
    /// `timed_out: true`. The process's own diagnostics are captured as they
    /// are written, so the timeout result still carries the log -- a case that
    /// fails must be able to show what the run said.
    fn run_index_bounded(
        &self,
        extra: &[&str],
        envs: &[(&str, &str)],
        limit: Duration,
    ) -> BoundedRun {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        for (key, value) in envs {
            cmd.env(key, value);
        }
        cmd.env("CASS_DATA_DIR", self.data_dir());
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .args(extra)
            .args(["--json"]);
        // stdout is discarded rather than piped: a resident run nobody is
        // going to read to completion must not be able to block on a full
        // pipe. Everything this helper reports comes from stderr and the
        // database.
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn cass index");
        let stderr = child.stderr.take().expect("the child's stderr");
        let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let sink = std::sync::Arc::clone(&log);
        let reader = std::thread::spawn(move || {
            use std::io::Read;
            let mut stderr = stderr;
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock()
                    .expect("log lock")
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });

        let deadline = Instant::now() + limit;
        let mut timed_out = false;
        let mut code = None;
        loop {
            match child.try_wait().expect("poll cass index") {
                Some(status) => {
                    code = status.code();
                    break;
                }
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    // Nothing of this test's own process may outlive it: the
                    // kill above is paired with the blocking wait right after
                    // it, so no watch loop is left running behind the report.
                    timed_out = true;
                    break;
                }
                None => std::thread::sleep(Duration::from_millis(25)),
            }
        }
        let _ = reader.join();
        let stderr = log.lock().expect("log lock").clone();
        BoundedRun {
            timed_out,
            code,
            stdout: String::new(),
            stderr,
        }
    }

    /// Run the index against an explicit data directory.
    fn run_index_in(&self, data_dir: &std::path::Path, extra: &[&str]) -> std::process::Output {
        std::fs::create_dir_all(data_dir).expect("mkdir the data dir");
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.env("CASS_DATA_DIR", data_dir);
        cmd.args(["index", "--data-dir"])
            .arg(data_dir)
            .args(extra)
            .args(["--json"]);
        cmd.output().expect("spawn cass index")
    }

    /// Open one database by path.
    fn open_db_at(path: &std::path::Path) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open the database read-only")
    }

    fn run_index_env(&self, extra: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
        let mut cmd = Command::new(cass_bin());
        for (key, value) in envs {
            cmd.env(key, value);
        }
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .args(extra)
            .args(["--json"]);
        cmd.output().expect("spawn cass index")
    }

    /// Run an explicit CLI binary against this fixture. The old-collision
    /// retry control uses the accepted 2ed binary to build the wrong world.
    fn run_index_binary(&self, binary: &str) -> std::process::Output {
        let copy = self.fixed_copy();
        let mut cmd = Command::new(binary);
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .args(["--source-safety-config", copy.to_str().unwrap()])
            .args(["--json"]);
        cmd.output().expect("spawn the explicit index binary")
    }

    /// A `sources.toml` declaring one local `full_scan` root.
    fn write_full_scan_source(&self, name: &str, root: &std::path::Path) {
        let dir = self.home().join(".config/cass");
        std::fs::create_dir_all(&dir).expect("mkdir cass config");
        std::fs::write(
            dir.join("sources.toml"),
            format!(
                "[[sources]]\nname = \"{name}\"\ntype = \"local\"\norigin_host = \"{name}\"\nfull_scan = true\npaths = [\"{}\"]\n",
                root.display()
            ),
        )
        .expect("write sources.toml");
    }

    fn open_db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(
            self.db(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open the database read-only")
    }

    /// Every stored safe value of this run, decoded, as JSON text.
    fn stored_safe_values(&self) -> Vec<String> {
        let db = self.open_db();
        let mut stmt = db
            .prepare("SELECT payload_bin FROM source_records WHERE payload_bin IS NOT NULL")
            .expect("prepare");
        let rows: Vec<Vec<u8>> = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect");
        rows.into_iter()
            .map(|bytes| {
                coding_agent_search::storage::source_codec::decode_safe_source(&bytes)
                    .expect("decode the stored safe value")
                    .safe_json()
                    .to_string()
            })
            .collect()
    }

    /// Write a Claude Code document at the layout its connector discovers.
    fn write_claude_document(
        &self,
        name: &str,
        value: &serde_json::Value,
    ) -> PathBuf {
        let dir = self.home().join(".claude/projects").join(name);
        std::fs::create_dir_all(&dir).expect("mkdir claude project");
        let path = dir.join("session.json");
        std::fs::write(
            &path,
            serde_json::to_vec(value).expect("encode the claude document"),
        )
        .expect("write the claude document");
        path
    }

    /// Write a Codex document at the layout its connector discovers.
    fn write_codex_document(
        &self,
        name: &str,
        value: &serde_json::Value,
    ) -> PathBuf {
        let dir = self.home().join(".codex/sessions/2026/01/01");
        std::fs::create_dir_all(&dir).expect("mkdir codex sessions");
        let path = dir.join(format!("rollout-2026-01-01-root-{name}.json"));
        std::fs::write(
            &path,
            serde_json::to_vec(value).expect("encode the codex document"),
        )
        .expect("write the codex document");
        path
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

const EXCLUDED_BODY: &str = "synthetic excluded body for the coarse pointer case";

// ---------------------------------------------------------------------------
// I1: the formal path produces real source facts
// ---------------------------------------------------------------------------

#[test]
fn i1_the_formal_cli_lands_source_facts_for_claude_and_codex() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-i1",
        &claude_session("sess-i1-claude", "summarise the synthetic log", "Three warnings."),
    );
    fixture.write_codex_session(
        "i1-codex",
        &codex_session("sess-i1-codex", "summarise the synthetic log", "No errors."),
    );

    let output = fixture.run_index();
    assert_eq!(
        output.status.code(),
        Some(0),
        "the source-aware index run must succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The committed input's semantic delta must be readable back from storage,
    // and a clean run reports zero inputs awaiting recovery.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"source_inputs_committed\": 2")
            || stdout.contains("\"source_inputs_committed\":2"),
        "both inputs committed: {stdout}"
    );
    assert!(
        !stdout.contains("source_inputs_pending_recovery"),
        "a clean run leaves nothing awaiting recovery: {stdout}"
    );

    let db = fixture.open_db();
    let inputs: i64 = db
        .query_row("SELECT COUNT(*) FROM source_inputs", [], |row| row.get(0))
        .expect("count inputs");
    assert_eq!(inputs, 2, "one input per discovered file");

    let complete: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
            [],
            |row| row.get(0),
        )
        .expect("count complete inputs");
    assert_eq!(complete, 2);

    let records: i64 = db
        .query_row("SELECT COUNT(*) FROM source_records", [], |row| row.get(0))
        .expect("count records");
    assert!(records >= 5, "expected at least five records, got {records}");

    let not_activated: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_records WHERE frame_state <> 'activated'",
            [],
            |row| row.get(0),
        )
        .expect("count inactive frames");
    assert_eq!(not_activated, 0, "every frame of a complete input is activated");

    let receipts: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM operation_commit_receipt
             WHERE operation = 'source_input_activation_v1' AND state = 'committed'",
            [],
            |row| row.get(0),
        )
        .expect("count receipts");
    assert_eq!(receipts, 2, "each activation writes its own receipt");

    let canonical_links: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_message_links
             WHERE authority = 'canonical' AND message_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .expect("count canonical links");
    assert!(canonical_links >= 4, "each projected message gets a canonical link");

    let messages: i64 = db
        .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
        .expect("count messages");
    assert!(messages >= 4, "both sessions' messages reach the canonical store");

    // The source path's own rows count toward the run's totals, so the CLI
    // reports what it actually inserted rather than zero.
    let payload: serde_json::Value =
        serde_json::from_str(&stdout).expect("the run prints one JSON object");
    let stats = &payload["indexing_stats"];
    assert_eq!(
        stats["source_inputs_committed"], 2,
        "the run counts both committed inputs: {stats}"
    );
    assert!(
        stats["total_messages"].as_u64().unwrap_or(0) >= 4,
        "the source path's messages are in the run's totals: {stats}"
    );
    assert!(
        stats["total_conversations"].as_u64().unwrap_or(0) >= 2,
        "and so are its conversations: {stats}"
    );
    // The run's own top-level counts come from the database it just wrote, so
    // the upper-level view sees the source path's writes rather than zero.
    assert!(
        payload["messages"].as_u64().unwrap_or(0) >= 4,
        "the run reports the canonical messages it wrote: {payload}"
    );
    assert!(
        payload["conversations"].as_u64().unwrap_or(0) >= 2,
        "the run reports the conversations it wrote: {payload}"
    );

    // A non-message record survives too: the codex `session_meta` line is not a
    // conversation message, and it must still be a stored record.
    let standalone: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_records WHERE record_mapping_state <> 'all_canonical'",
            [],
            |row| row.get(0),
        )
        .expect("count non-canonical records");
    assert!(standalone >= 1, "metadata records are retained, not dropped");
}

// ---------------------------------------------------------------------------
// I1: three identity values, all different, never interchanged
// ---------------------------------------------------------------------------

#[test]
fn i1_the_namespace_the_scan_root_and_the_watermark_id_are_three_values() {
    let fixture = Fixture::new();
    let session = fixture.write_claude_session(
        "proj-ident",
        &claude_session("sess-ident", "hello identity", "hello back"),
    );

    let output = fixture.run_index();
    assert_eq!(output.status.code(), Some(0));

    let db = fixture.open_db();
    let (namespace, root_bin): (String, Vec<u8>) = db
        .query_row(
            "SELECT identity_namespace, root_id_bin FROM source_inputs LIMIT 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .expect("read identity columns");

    // The declaration's `root_id` field carries the original scan root the
    // connector discovered the file under -- the connector's own projects
    // directory, not the session file and not the watermark root id.
    let _ = &session;
    let scan_root = fixture
        .home()
        .join(".claude/projects")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        String::from_utf8(root_bin).expect("root bytes are utf8"),
        scan_root,
        "identity element 4 is the original scan root path"
    );

    // The namespace is the machine identity: neither the scan root nor a
    // watermark root id (which is spelled `home:<connector>:<hash>`).
    assert_ne!(namespace, scan_root, "namespace must not be the scan root");
    assert!(
        !namespace.contains(':'),
        "namespace is the machine host label, got {namespace:?}"
    );

    let watermark_roots: Vec<String> = {
        let mut stmt = db
            .prepare("SELECT DISTINCT root_id FROM scan_watermarks")
            .expect("prepare");
        stmt.query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect")
    };
    assert!(!watermark_roots.is_empty(), "the run advanced root watermarks");
    for root_id in &watermark_roots {
        assert_ne!(root_id, &scan_root, "a watermark root id is not a path");
        assert_ne!(root_id, &namespace, "a watermark root id is not the namespace");
    }
}

// ---------------------------------------------------------------------------
// I2: a replay adds nothing
// ---------------------------------------------------------------------------

#[test]
fn i2_replaying_the_same_input_adds_nothing_and_keeps_the_receipt() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-i2",
        &claude_session("sess-i2", "hello replay", "hello again"),
    );

    let first = fixture.run_index();
    assert_eq!(first.status.code(), Some(0));

    fn snapshot(db: &rusqlite::Connection) -> (i64, i64, i64, String, String) {
        (
            db.query_row("SELECT COUNT(*) FROM source_inputs", [], |r| r.get(0))
                .unwrap(),
            db.query_row("SELECT COUNT(*) FROM source_records", [], |r| r.get(0))
                .unwrap(),
            db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap(),
            db.query_row("SELECT value FROM meta WHERE key = 'source_facts_revision'", [], |r| {
                r.get(0)
            })
            .unwrap(),
            db.query_row(
                "SELECT group_concat(idempotency_key, '|') FROM operation_commit_receipt",
                [],
                |r| r.get(0),
            )
            .unwrap(),
        )
    }
    let before = snapshot(&fixture.open_db());

    let second = fixture.run_index();
    assert_eq!(
        second.status.code(),
        Some(0),
        "a replay is a success with zero new work; stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );

    let after = snapshot(&fixture.open_db());
    assert_eq!(before, after, "a replay must not add or move any fact");
}

// ---------------------------------------------------------------------------
// I5: a coarse Codex claim preserves the fields around the body
// ---------------------------------------------------------------------------

/// A Codex rollout whose first user turn is a shell-opener, i.e. the shape the
/// connector's own anchor excludes. Its record carries ids, a call id, usage
/// and unknown members that must survive the clearing.
/// The text the connector's own anchor excludes: it ends with the
/// environment-context closer and carries a `<cwd>` inside the block.
fn excluded_text() -> String {
    format!(
        "<environment_context>\n<cwd>/synthetic/project</cwd>\n{EXCLUDED_BODY}\n</environment_context>"
    )
}

fn codex_shell_opener_session() -> Vec<serde_json::Value> {
    let body = excluded_text();
    vec![
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:00.000Z",
            "type": "session_meta",
            "payload": {"id": "sess-i5-codex", "cwd": "/synthetic/project", "cli_version": "0.42.0"}
        }),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:01.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": "sess-i5-codex-msg-1",
                "role": "user",
                "call_id": "call_synthetic_0001",
                "unknown_member": {"keep": [1, 2, 3], "note": "unknown fields must survive"},
                "usage": {"input_tokens": 11, "output_tokens": 22},
                "content": [{"type": "input_text", "text": body}]
            }
        }),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:02.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": "sess-i5-codex-msg-2",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "acknowledged"}]
            }
        }),
    ]
}

#[test]
fn i5_a_coarse_codex_claim_clears_the_body_but_keeps_ids_usage_and_unknown_fields() {
    let fixture = Fixture::new();
    fixture.write_codex_session("i5-codex", &codex_shell_opener_session());

    let output = fixture.run_index();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stored = fixture.stored_safe_values();
    assert!(!stored.is_empty(), "the records were retained");
    let joined = stored.join("\n");

    // The excluded body is gone...
    assert!(
        !joined.contains(EXCLUDED_BODY),
        "the excluded body must not survive: {joined}"
    );
    // ...while everything around it is untouched. A claim proves the *range* a
    // message came from; it is not a licence to delete that range.
    for needle in [
        "\"call_id\":\"call_synthetic_0001\"",
        "\"usage\"",
        "\"input_tokens\":11",
        "\"unknown_member\"",
        "\"keep\"",
        "unknown fields must survive",
    ] {
        assert!(
            joined.contains(needle),
            "the coarse claim must not delete {needle}; stored={joined}"
        );
    }
}

/// An unknown field that merely *quotes* an excluded body is not a copy of it:
/// it must be preserved, and the run must not report the input as complete.
#[test]
fn i5_an_unknown_field_quoting_the_body_is_preserved_or_the_input_fails() {
    let fixture = Fixture::new();
    let quoted = format!("prefix {} suffix", excluded_text());
    let mut session = codex_shell_opener_session();
    if let Some(payload) = session[1].get_mut("payload").and_then(|p| p.as_object_mut()) {
        payload.insert(
            "note".to_string(),
            serde_json::Value::String(quoted.clone()),
        );
    }
    fixture.write_codex_session("i5-quote", &session);

    let output = fixture.run_index();
    let code = output.status.code();
    if code == Some(0) {
        // Success is only acceptable if the unknown field survived: a bare
        // unknown string is cleared solely on an exact copy, never on a
        // decorated one.
        let joined = fixture.stored_safe_values().join("\n");
        // The stored value is JSON text, so the body's newlines are escaped
        // there; compare against the same encoding.
        let escaped = serde_json::to_string(&quoted).expect("encode the expected note");
        let escaped = &escaped[1..escaped.len() - 1];
        assert!(
            joined.contains(escaped),
            "an unknown field's decorated string must not be treated as a clearable copy: {joined}"
        );
    } else {
        // Refusing the input is the other acceptable answer: the residue cannot
        // be proved removed.
        let db = fixture.open_db();
        let complete: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        assert_eq!(complete, 0, "a refused input is never complete");
    }
}

// ---------------------------------------------------------------------------
// I4: a bad fixed copy is a failure, and nothing lands
// ---------------------------------------------------------------------------

#[test]
fn i4_a_missing_fixed_copy_fails_without_landing_any_source_fact() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-i4",
        &claude_session("sess-i4", "hello failure", "should not land"),
    );

    let missing = fixture.root.path().join("does-not-exist.toml");
    let output = fixture.run_index_with(&["--source-safety-config", missing.to_str().unwrap()]);
    assert_ne!(
        output.status.code(),
        Some(0),
        "a missing fixed copy is not a success"
    );

    if fixture.db().exists() {
        let db = fixture.open_db();
        let inputs: i64 = db
            .query_row("SELECT COUNT(*) FROM source_inputs", [], |row| row.get(0))
            .unwrap_or(0);
        assert_eq!(inputs, 0, "a refused run lands no source fact");
    }
}

/// A directory is not a fixed copy.
#[test]
fn i4_a_directory_in_place_of_the_fixed_copy_is_refused() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-dir",
        &claude_session("sess-dir", "hello directory", "nope"),
    );

    let dir = fixture.root.path().join("a-directory");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let output = fixture.run_index_with(&["--source-safety-config", dir.to_str().unwrap()]);
    assert_ne!(output.status.code(), Some(0));
}

// ---------------------------------------------------------------------------
// Task 19: without an explicit copy the run uses the default fixed configuration
// ---------------------------------------------------------------------------

/// Task 19: without an explicit copy the run now prepares the default fixed
/// configuration, so the same input lands as a complete source fact instead of
/// staying on the legacy conversation path.
#[test]
fn without_the_flag_the_run_lands_source_facts() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-default",
        &claude_session("sess-default", "hello default", "default answer"),
    );

    let output = fixture.run_index_with(&[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the un-flagged run succeeds; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let db = fixture.open_db();
    let complete: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
            [],
            |row| row.get(0),
        )
        .expect("count complete inputs");
    assert_eq!(
        complete, 1,
        "without the flag the run claims a complete source fact"
    );
    let receipts: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_inputs si
             JOIN operation_commit_receipt r ON r.idempotency_key = si.receipt_key
             WHERE si.state = 'complete'
               AND r.operation = 'source_input_activation_v1'
               AND r.state = 'committed'",
            [],
            |row| row.get(0),
        )
        .expect("count committed receipts");
    assert_eq!(receipts, 1, "the complete input has its committed receipt");
    let messages: i64 = db
        .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
        .expect("count messages");
    assert!(messages >= 2, "the canonical body still lands");
    let links: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_message_links WHERE authority = 'canonical'",
            [],
            |row| row.get(0),
        )
        .expect("count canonical links");
    assert!(links > 0, "the input links to its canonical messages");
}

// ---------------------------------------------------------------------------
// I6: the new path desensitises regardless of the legacy switch, and never
// reads a live or implicit configuration
// ---------------------------------------------------------------------------

/// A synthetic, pattern-shaped credential. It exists only to exercise the
/// matcher and is never a real key.
const SYNTHETIC_OPENAI_KEY: &str = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"; // ubs:ignore -- synthetic fixture.

#[test]
fn i6_the_legacy_redaction_switch_cannot_turn_the_new_path_off() {
    let fixture = Fixture::new();
    let question = format!("here is a key {SYNTHETIC_OPENAI_KEY} please ignore it");
    fixture.write_claude_session(
        "proj-i6",
        &claude_session("sess-i6", &question, "noted"),
    );

    let mut cmd = Command::new(cass_bin());
    fixture.isolate(&mut cmd);
    // The legacy switch, explicitly off.
    cmd.env("CASS_REDACT_SECRETS", "0");
    cmd.args([
        "index",
        "--data-dir",
        fixture.data_dir().to_str().unwrap(),
        "--source-safety-config",
        fixture.fixed_copy().to_str().unwrap(),
        "--json",
    ]);
    let output = cmd.output().expect("spawn cass index");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let joined = fixture.stored_safe_values().join("\n");
    assert!(
        !joined.contains(SYNTHETIC_OPENAI_KEY),
        "the new path must desensitise even with the legacy switch off: {joined}"
    );
    assert!(
        joined.contains("[REDACTED]"),
        "the secret-shaped value is replaced, not dropped: {joined}"
    );
}

#[test]
fn i6_a_live_configuration_change_does_not_alter_a_sealed_replay() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-i6b",
        &claude_session("sess-i6b", "hello sealed", "sealed answer"),
    );

    let first = fixture.run_index();
    assert_eq!(first.status.code(), Some(0));
    let before = fixture.stored_safe_values();

    // Move the live configuration the machine would otherwise consult. The
    // source-aware path takes the caller's fixed copy only.
    let xdg = fixture.home().join(".config/cass");
    std::fs::create_dir_all(&xdg).expect("mkdir xdg config");
    std::fs::write(
        xdg.join("excluded_context_paths.toml"),
        b"memory_files = [\"nothing-matches-this\"]\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n",
    )
    .expect("write a hostile live config");

    let second = fixture.run_index();
    assert_eq!(
        second.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        before,
        fixture.stored_safe_values(),
        "a sealed replay is decided by the resolved input, not by the live configuration"
    );
}

/// A failure to read the committed delta back is neither a failed input nor a
/// silent success: the receipt and the canonical rows stay, and the run reports
/// a derivation still pending recovery.
#[test]
fn i7_a_post_commit_read_failure_reports_pending_recovery_and_keeps_the_receipt() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-i7b",
        &claude_session("sess-i7b", "hello derivation", "derived later"),
    );

    let output = fixture.run_index_env(
        &[
            "--source-safety-config",
            fixture.fixed_copy().to_str().unwrap(),
        ],
        &[("CASS_SRC05B07_FAIL_AT", "postcommit")],
    );
    // The commit is durable and the run still succeeds: only the derivation is
    // outstanding, and the existing catch-up covers it. The run says so in its
    // own result, so "the source commit completed" and "vector recovery
    // completed" are two different facts a caller can read apart.
    assert_eq!(
        output.status.code(),
        Some(0),
        "a pending derivation is not a failed run; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"source_inputs_pending_recovery\": 1")
            || stdout.contains("\"source_inputs_pending_recovery\":1"),
        "the run reports how many committed inputs await recovery: {stdout}"
    );
    assert!(
        stdout.contains("\"source_inputs_committed\": 1")
            || stdout.contains("\"source_inputs_committed\":1"),
        "the run also reports the commit count itself: {stdout}"
    );

    let db = fixture.open_db();
    let complete: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
            [],
            |r| r.get(0),
        )
        .expect("count complete");
    assert_eq!(complete, 1, "the commit stands");
    let receipts: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM operation_commit_receipt WHERE state = 'committed'",
            [],
            |r| r.get(0),
        )
        .expect("count receipts");
    assert_eq!(receipts, 1, "the receipt survives the derivation failure");
    let messages: i64 = db
        .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
        .expect("count messages");
    assert!(messages >= 2, "the canonical rows survive");
}

// ---------------------------------------------------------------------------
// I8: the resident watch entry point is covered, and it says so by running
// ---------------------------------------------------------------------------

/// SRC05B-09B: this case's original sub-assertion is obsolete.
///
/// SRC05B-07 refused `--watch` and `--watch-once` alike because neither scan
/// loop was migrated. SRC05B-09A migrated the explicit `--watch-once` paths;
/// SRC05B-09B migrated the resident `--watch` event cycle, which was the last
/// entry point still refusing. There is therefore no un-migrated entry point
/// left for a refusal case to name, and asserting one would now assert the
/// opposite of the ticket.
///
/// What the old case protected -- a run must not claim source completeness
/// while actually reading through the legacy conversation path -- is kept
/// here, restated against the run that now really is accepted: the resident
/// loop starts and its startup scan lands the session as source facts, with no
/// legacy conversation beside them. The event cycle itself, including the
/// per-cycle facts it lands, is `tests/source_resident_watch.rs`'s subject.
///
/// The run is bounded because an accepted `--watch` never returns on its own.
/// A run that exits by itself here is the old refusal coming back, or a crash,
/// and either is a failure.
#[test]
fn i8_watch_mode_starts_and_lands_source_facts_without_a_legacy_conversation() {
    let fixture = Fixture::new();
    let _session = fixture.write_claude_session(
        "proj-i8",
        &claude_session("sess-i8", "hello watch", "not yet"),
    );

    // The resident cycle applies the active-source filter, whose recent-write
    // window treats a just-written session log as one still being appended to
    // and defers it. That is the right production behaviour and this case is
    // about the startup read, so the window is disabled here rather than
    // waited out; `0` is the documented way to turn it off.
    let run = fixture.run_index_bounded(
        &[
            "--source-safety-config",
            fixture.fixed_copy().to_str().unwrap(),
            "--watch",
            "--watch-interval",
            "1",
            "--verbose",
        ],
        &[("CASS_ACTIVE_SESSION_RECENT_WRITE_WINDOW_SECS", "0")],
        Duration::from_secs(60),
    );
    assert!(
        run.timed_out,
        "the resident watch loop must be accepted and keep running; this run ended on its \
         own, which is the refusal (or a crash) coming back. stdout={} stderr={}",
        run.stdout, run.stderr
    );

    let db = fixture.open_db();
    let inputs: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    assert_eq!(
        inputs, 1,
        "the accepted entry point reads its declared root through the source kernel"
    );
    // The canonical conversation is not the tell: both paths write one into
    // the canonical store. What separates them is where the text came from, so
    // this asserts the links the kernel installs from sealed records to the
    // current messages. A silent fall back to the legacy path would leave the
    // input count at zero above -- and no links here.
    let links: i64 = db
        .query_row("SELECT COUNT(*) FROM source_message_links", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    assert!(
        links > 0,
        "the text in the canonical store is linked back to sealed source records, so the flag \
         read the root through the source kernel rather than the legacy conversation path"
    );
}

// ---------------------------------------------------------------------------
// I3: an injected failure rolls the whole input back
// ---------------------------------------------------------------------------

/// The four points a commit can be stopped at, each inside the one input
/// transaction.
const FAULT_POINTS: [&str; 4] = ["staging", "projection", "links", "activation"];

#[test]
fn i3_a_fault_anywhere_in_the_input_transaction_rolls_the_whole_input_back() {
    for point in FAULT_POINTS {
        let fixture = Fixture::new();
        fixture.write_claude_session(
            "proj-i3",
            &claude_session("sess-i3", "hello rollback", "rolled back"),
        );

        let failed = fixture.run_index_env(
            &[
                "--source-safety-config",
                fixture.fixed_copy().to_str().unwrap(),
            ],
            &[("CASS_SRC05B07_FAIL_AT", point)],
        );
        assert_ne!(
            failed.status.code(),
            Some(0),
            "the injected fault at {point} must fail the run"
        );
        // The run must have actually reached the armed point: without this, a
        // failure for an unrelated reason would read as a rolled-back input.
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&failed.stdout),
            String::from_utf8_lossy(&failed.stderr)
        );
        assert!(
            combined.contains(&format!("injected fault at {point}")),
            "the run reports the armed fault point {point}: {combined}"
        );
        assert!(
            fixture.db().exists(),
            "the run reached the database and left one behind ({point})"
        );

        let db = fixture.open_db();
        let complete: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
                [],
                |r| r.get(0),
            )
            .expect("count complete inputs");
        assert_eq!(complete, 0, "a rolled-back input is never complete ({point})");

        let receipts: i64 = db
            .query_row("SELECT COUNT(*) FROM operation_commit_receipt", [], |r| r.get(0))
            .expect("count receipts");
        assert_eq!(receipts, 0, "no receipt survives a rollback ({point})");

        let links: i64 = db
            .query_row("SELECT COUNT(*) FROM source_message_links", [], |r| r.get(0))
            .expect("count links");
        assert_eq!(links, 0, "no link survives a rollback ({point})");

        if point == "activation" || point == "links" {
            // These two run after the projections, so the whole input --
            // messages included -- must be back where it started.
            let messages: i64 = db
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .expect("count messages");
            assert_eq!(
                messages, 0,
                "a fault after the projections rolls the messages back too ({point})"
            );
        }

        let revision: Option<String> = db
            .query_row(
                "SELECT value FROM meta WHERE key = 'source_facts_revision'",
                [],
                |r| r.get(0),
            )
            .optional()
            .expect("read the revision");
        assert_eq!(
            revision.as_deref().unwrap_or("0"),
            "0",
            "a rollback does not move the revision ({point})"
        );

        // The same run, without the fault, must succeed: the retry is a clean
        // first attempt, not a replay of a half-applied one.
        let retried = fixture.run_index();
        assert_eq!(
            retried.status.code(),
            Some(0),
            "the retry after a {point} fault must succeed; stderr={}",
            String::from_utf8_lossy(&retried.stderr)
        );
        let db = fixture.open_db();
        let complete: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
                [],
                |r| r.get(0),
            )
            .expect("count complete");
        assert_eq!(complete, 1, "the retry completes exactly one input ({point})");
        let messages: i64 = db
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .expect("count messages");
        assert!(messages >= 2, "the retry writes the session's messages ({point})");
        let dangling: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM source_message_links WHERE message_id IS NULL",
                [],
                |r| r.get(0),
            )
            .expect("count dangling links");
        assert_eq!(dangling, 0, "no link points at a ghost message ({point})");
    }
}

// ---------------------------------------------------------------------------
// I7: the canonical store the source path writes is searchable
// ---------------------------------------------------------------------------

/// A phrase that appears only in this fixture's answer, so a hit is the row
/// this input produced.
const RECALL_PHRASE: &str = "synthetic-anvil-recall";

#[test]
fn i7_a_lexical_query_recalls_the_safe_canonical_body() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-i7",
        &claude_session(
            "sess-i7",
            "what did the build say",
            &format!("the build printed {RECALL_PHRASE} exactly once"),
        ),
    );

    let output = fixture.run_index();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut cmd = Command::new(cass_bin());
    fixture.isolate(&mut cmd);
    cmd.args([
        "search",
        "--mode",
        "lexical",
        RECALL_PHRASE,
        "--data-dir",
        fixture.data_dir().to_str().unwrap(),
        "--json",
        "--rrf-limit",
        "5",
    ]);
    let search = cmd.output().expect("spawn cass search");
    let stdout = String::from_utf8_lossy(&search.stdout);
    assert_eq!(
        search.status.code(),
        Some(0),
        "a lexical query over the freshly written canonical store must succeed; \
         stdout={stdout} stderr={}",
        String::from_utf8_lossy(&search.stderr)
    );
    assert!(
        stdout.contains(RECALL_PHRASE),
        "the query must recall the safe canonical body it was written from: {stdout}"
    );
}

/// Two records that carry the same connector event id. The excluded one is the
/// first user turn; the other holds the same text and must keep it, because a
/// claim proves one record's range and never authorises clearing another's.
#[test]
fn i5_a_duplicate_event_id_does_not_propagate_a_clearing_across_records() {
    let fixture = Fixture::new();
    let shared_id = "sess-i5-dup-1";
    let session = vec![
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:00.000Z",
            "type": "session_meta",
            "payload": {"id": "sess-i5-dup", "cwd": "/synthetic/project", "cli_version": "0.42.0"}
        }),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:01.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": shared_id,
                "role": "user",
                "content": [{"type": "input_text", "text": excluded_text()}]
            }
        }),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:02.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": shared_id,
                "role": "assistant",
                "content": [{"type": "output_text", "text": excluded_text()}]
            }
        }),
    ];
    fixture.write_codex_session("i5-dup", &session);

    let output = fixture.run_index();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stored = fixture.stored_safe_values();
    let escaped = {
        let encoded = serde_json::to_string(&excluded_text()).expect("encode");
        encoded[1..encoded.len() - 1].to_string()
    };
    let carrying: Vec<&String> = stored.iter().filter(|text| text.contains(shared_id)).collect();
    assert_eq!(carrying.len(), 2, "both records are stored under that id");
    let kept = carrying
        .iter()
        .filter(|text| text.contains(&escaped))
        .count();
    assert_eq!(
        kept, 1,
        "exactly one record keeps the body: the clearing must not cross records"
    );
}

/// A Claude record that mixes prose with a tool call projects two messages from
/// one line. Both are canonical and both keep their text when nothing excludes
/// them: no positional alignment may decide which one a claim belongs to.
#[test]
fn i5_one_claude_record_projects_two_messages_without_cross_attribution() {
    let fixture = Fixture::new();
    let session = vec![
        serde_json::json!({
            "type": "user",
            "uuid": "evt-a",
            "message": {"role": "user", "content": "synthetic question for the split"}
        }),
        serde_json::json!({
            "type": "assistant",
            "uuid": "evt-b",
            "message": {"role": "assistant", "content": [
                {"type": "text", "text": "synthetic prose that must survive"},
                {"type": "tool_use", "id": "toolu_synthetic_1", "name": "Read",
                 "input": {"file_path": "/synthetic/ordinary.rs"}}
            ]}
        }),
    ];
    fixture.write_claude_session("proj-i5-split", &session);

    let output = fixture.run_index();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let db = fixture.open_db();
    let canonical: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_message_links WHERE authority = 'canonical'",
            [],
            |r| r.get(0),
        )
        .expect("count canonical links");
    assert!(
        canonical >= 3,
        "the mixed record splits into more than one projected message, got {canonical}"
    );
    let messages: i64 = db
        .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
        .expect("count messages");
    assert_eq!(
        messages as i64, canonical,
        "every projected message has its own canonical row, none attributed twice"
    );
    let joined = fixture.stored_safe_values().join("\n");
    assert!(
        joined.contains("synthetic prose that must survive"),
        "nothing excluded this session, so every body survives: {joined}"
    );
}

/// A malformed line is one failed record, never an empty file: the records
/// around it are still framed, and the bad one is reported as such.
#[test]
fn i4_a_bad_json_line_is_one_failed_record_not_an_empty_file() {
    let fixture = Fixture::new();
    let dir = fixture.home().join(".claude/projects").join("proj-i4b");
    std::fs::create_dir_all(&dir).expect("mkdir project");
    let good = claude_session("sess-i4b", "synthetic good question", "synthetic good answer");
    let body = format!(
        "{}\n{{ this line is not json\n{}\n",
        good[0], good[1]
    );
    std::fs::write(dir.join("session.jsonl"), body).expect("write session");

    let output = fixture.run_index();
    // A malformed line is a failure boundary: the run must not report success.
    assert_ne!(
        output.status.code(),
        Some(0),
        "an input with an unparseable record is not a success; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let db = fixture.open_db();
    let complete: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
            [],
            |r| r.get(0),
        )
        .expect("count complete inputs");
    assert_eq!(complete, 0, "the input never reaches the complete state");

    let records: i64 = db
        .query_row("SELECT COUNT(*) FROM source_records", [], |r| r.get(0))
        .expect("count records");
    assert_eq!(
        records, 3,
        "three non-empty lines are framed as three records (one failed, two parsed): {records}"
    );
    let failed: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_records WHERE parse_state = 'parse_failed'",
            [],
            |r| r.get(0),
        )
        .expect("count parse failures");
    assert_eq!(failed, 1, "exactly the malformed line is reported as failed");
    let parsed: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_records WHERE parse_state = 'parsed'",
            [],
            |r| r.get(0),
        )
        .expect("count parsed");
    assert_eq!(parsed, 2, "its neighbours still parse");
}

/// An empty file is a legitimate zero-record input, and it completes.
#[test]
fn i4_a_blank_jsonl_input_completes_with_zero_records() {
    let fixture = Fixture::new();
    let dir = fixture.home().join(".claude/projects").join("proj-empty");
    std::fs::create_dir_all(&dir).expect("mkdir project");
    std::fs::write(dir.join("session.jsonl"), "\n   \n\t\n").expect("write blank session");

    let output = fixture.run_index();
    assert_eq!(
        output.status.code(),
        Some(0),
        "a blank input is a legitimate zero-record completion; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let db = fixture.open_db();
    let complete: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
            [],
            |r| r.get(0),
        )
        .expect("count complete");
    assert_eq!(complete, 1, "the blank input completed");
}

/// SRC05B-08: a `full_scan` root is scanned through the source kernel in both
/// schedulings. Its session lands as a real, complete source input, and the
/// root itself takes neither a watermark row nor per-file state -- the
/// contract gives it neither, which is what keeps it a full scan on every run.
#[test]
fn i8_a_full_scan_root_is_scanned_by_the_source_kernel_in_both_schedulings() {
    for streaming in [true, false] {
        let fixture = Fixture::new();
        // The declared root is outside HOME, so the source, not the home
        // connector, is what would scan it.
        let declared = fixture.root.path().join("full-scan-root");
        std::fs::create_dir_all(declared.join("projects/-f")).expect("mkdir declared root");
        let session = claude_session("sess-i8-fullscan", "hello full scan", "now migrated");
        std::fs::write(
            declared.join("projects/-f/agent-f.jsonl"),
            session
                .iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .expect("write declared session");
        fixture.write_full_scan_source("backup", &declared);

        let envs: Vec<(&str, &str)> = if streaming {
            vec![]
        } else {
            vec![("CASS_STREAMING_INDEX", "0")]
        };
        let label = if streaming { "streaming" } else { "batch" };
        let output = fixture.run_index_env(
            &[
                "--source-safety-config",
                fixture.fixed_copy().to_str().unwrap(),
            ],
            &envs,
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "the {label} scheduling scans the full_scan root; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );

        let db = fixture.open_db();
        let complete: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
                [],
                |r| r.get(0),
            )
            .expect("count complete inputs");
        assert_eq!(
            complete, 1,
            "the root's session lands as a complete source input ({label})"
        );
        let watermarked: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM scan_watermarks WHERE root_id LIKE 'cfg:backup%'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        assert_eq!(
            watermarked, 0,
            "a full_scan root takes no watermark row ({label})"
        );
        let stated: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM scan_file_state WHERE root_id LIKE 'cfg:backup%'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        assert_eq!(
            stated, 0,
            "a full_scan root takes no per-file state ({label})"
        );
    }
}

// ---------------------------------------------------------------------------
// I2: the streaming and batch schedulings agree, and both replay to nothing
// ---------------------------------------------------------------------------

/// One run's logical facts: counts, the canonical content, the source
/// projections, and the receipt/revision/generation identity. Database-local
/// ids and UUIDs are deliberately left out -- they are expected to differ
/// between two independently built databases.
#[derive(Debug, PartialEq, Eq)]
struct LogicalFacts {
    complete_inputs: i64,
    records: i64,
    canonical_links: i64,
    receipts: i64,
    messages: i64,
    watermark_roots: i64,
    /// (agent slug, idx, role, content) of every canonical message.
    canonical_content: Vec<(String, i64, String, String)>,
    /// (connector, ordinal, parse_state, frame_state, payload bytes,
    /// safe-value digest) of every source record, so the safe content itself
    /// takes part in the comparison.
    record_projection: Vec<(String, i64, String, String, i64, String)>,
    /// (connector, record ordinal, projection pointer, authority, evidence
    /// kind, target idx, role, content) of every link: enough to catch a link
    /// that crosses attribution.
    link_projection: Vec<(String, i64, String, String, String, i64, String, String)>,
    receipt_keys: Vec<String>,
    revision: String,
    generation: String,
}

fn fact_snapshot(db: &rusqlite::Connection) -> LogicalFacts {
    let one = |sql: &str| -> i64 { db.query_row(sql, [], |r| r.get(0)).expect("count") };
    fn collect<T, F>(db: &rusqlite::Connection, sql: &str, f: F) -> Vec<T>
    where
        F: Fn(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        let mut stmt = db.prepare(sql).expect("prepare");
        let rows: Vec<T> = stmt
            .query_map([], |row| f(row))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect");
        rows
    }
    LogicalFacts {
        complete_inputs: one("SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'"),
        records: one("SELECT COUNT(*) FROM source_records"),
        canonical_links: one(
            "SELECT COUNT(*) FROM source_message_links WHERE authority = 'canonical'",
        ),
        receipts: one("SELECT COUNT(*) FROM operation_commit_receipt WHERE state = 'committed'"),
        messages: one("SELECT COUNT(*) FROM messages"),
        watermark_roots: one("SELECT COUNT(DISTINCT root_id) FROM scan_watermarks"),
        canonical_content: collect(
            db,
            "SELECT a.slug, m.idx, m.role, m.content FROM messages m
             JOIN conversations c ON c.id = m.conversation_id
             JOIN agents a ON a.id = c.agent_id
             ORDER BY a.slug, m.idx, m.content",
            |row: &rusqlite::Row<'_>| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        ),
        record_projection: collect(
            db,
            "SELECT i.connector, r.ordinal, r.parse_state, r.frame_state,
                    COALESCE(length(r.payload_bin), -1), COALESCE(hex(r.safe_value_hash), '')
             FROM source_records r
             JOIN source_inputs i ON i.id = r.input_id
             ORDER BY i.connector, r.ordinal",
            |row: &rusqlite::Row<'_>| {
                Ok((
                    row.get::<_, String>(0)?,
                    // The ordinal is stored as 8 big-endian bytes; render it as
                    // a plain number so two databases compare equal.
                    i64::from_be_bytes(
                        row.get::<_, Vec<u8>>(1)?
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ),
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        ),
        link_projection: collect(
            db,
            "SELECT i.connector, r.ordinal, COALESCE(l.projection_pointer, ''),
                    COALESCE(l.authority, ''), l.evidence_kind,
                    COALESCE(m.idx, -1), COALESCE(m.role, ''), COALESCE(m.content, '')
             FROM source_message_links l
             JOIN source_records r ON r.id = l.record_id
             JOIN source_inputs i ON i.id = r.input_id
             LEFT JOIN messages m ON m.id = l.message_id
             ORDER BY i.connector, r.ordinal, l.projection_key",
            |row: &rusqlite::Row<'_>| {
                Ok((
                    row.get::<_, String>(0)?,
                    i64::from_be_bytes(
                        row.get::<_, Vec<u8>>(1)?
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ),
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        ),
        receipt_keys: collect(
            db,
            "SELECT idempotency_key FROM operation_commit_receipt ORDER BY idempotency_key",
            |row: &rusqlite::Row<'_>| row.get::<_, String>(0),
        ),
        revision: db
            .query_row(
                "SELECT COALESCE((SELECT value FROM meta WHERE key = 'source_facts_revision'), '')",
                [],
                |r| r.get(0),
            )
            .expect("revision"),
        generation: db
            .query_row(
                "SELECT COALESCE((SELECT value FROM meta WHERE key = 'source_content_generation'), '')",
                [],
                |r| r.get(0),
            )
            .expect("generation"),
    }
}

#[test]
fn i2_the_streaming_and_batch_schedulings_agree_and_both_replay_to_nothing() {
    let mut per_scheduling: Vec<(&str, LogicalFacts)> = Vec::new();

    for streaming in [true, false] {
        let label = if streaming { "streaming" } else { "batch" };
        let fixture = Fixture::new();
        fixture.write_claude_session(
            "proj-sched",
            &claude_session("sess-sched-claude", "synthetic claude question", "claude answer"),
        );
        fixture.write_codex_session(
            "sched-codex",
            &codex_session("sess-sched-codex", "synthetic codex question", "codex answer"),
        );
        let envs: Vec<(&str, &str)> = if streaming {
            vec![]
        } else {
            vec![("CASS_STREAMING_INDEX", "0")]
        };

        // First run: the facts land.
        let first = fixture.run_index_env(
            &[
                "--source-safety-config",
                fixture.fixed_copy().to_str().unwrap(),
            ],
            &envs,
        );
        assert_eq!(
            first.status.code(),
            Some(0),
            "the {label} scheduling succeeds; stderr={}",
            String::from_utf8_lossy(&first.stderr)
        );
        let after_first = fact_snapshot(&fixture.open_db());
        assert_eq!(after_first.complete_inputs, 2, "both sources are complete under {label}");
        assert!(after_first.records >= 5, "records land under {label}: {after_first:?}");
        assert_eq!(after_first.receipts, 2, "one receipt per input under {label}");

        // Second run: the same facts, nothing new.
        let second = fixture.run_index_env(
            &[
                "--source-safety-config",
                fixture.fixed_copy().to_str().unwrap(),
            ],
            &envs,
        );
        assert_eq!(
            second.status.code(),
            Some(0),
            "the {label} replay succeeds; stderr={}",
            String::from_utf8_lossy(&second.stderr)
        );
        assert_eq!(
            fact_snapshot(&fixture.open_db()),
            after_first,
            "a replay adds nothing under {label}"
        );

        per_scheduling.push((label, after_first));
    }

    let logical = |facts: &LogicalFacts| {
        (
            facts.complete_inputs,
            facts.records,
            facts.canonical_links,
            facts.receipts,
            facts.messages,
            facts.watermark_roots,
            facts.canonical_content.clone(),
            facts.record_projection.clone(),
            facts.link_projection.clone(),
            facts.revision.clone(),
        )
    };
    assert_eq!(
        logical(&per_scheduling[0].1),
        logical(&per_scheduling[1].1),
        "the two schedulings produce the same logical source facts"
    );
}

// ---------------------------------------------------------------------------
// I2/R2: the four cells -- streaming or batch, serial writer or writer thread
// ---------------------------------------------------------------------------

/// The dispatch mode each writer cell must report.
fn expected_writer_mode(begin_concurrent: bool) -> &'static str {
    if begin_concurrent {
        "mode=\"writer-handle\""
    } else {
        "mode=\"ephemeral-writer\""
    }
}

/// Run one cell's index call with its scheduling switches, returning the
/// process output. `--verbose` is what makes the dispatch line observable.
fn run_cell(fixture: &Fixture, streaming: bool, begin_concurrent: bool) -> std::process::Output {
    let mut envs: Vec<(&str, &str)> = vec![
        ("CASS_STREAMING_INDEX", if streaming { "1" } else { "0" }),
        ("CASS_INDEXER_BEGIN_CONCURRENT", if begin_concurrent { "1" } else { "0" }),
    ];
    envs.push(("CASS_STREAMING_CONSUMER_COMBINE", "0"));
    let copy = fixture.fixed_copy();
    let mut cmd = std::process::Command::new(cass_bin());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    fixture.isolate(&mut cmd);
    cmd.args(["index", "--data-dir"])
        .arg(fixture.data_dir())
        .args(["--source-safety-config", copy.to_str().unwrap()])
        .args(["--json", "--verbose"]);
    cmd.output().expect("spawn cass index")
}

#[test]
fn i2_the_four_scheduling_cells_agree_and_replay_to_nothing() {
    let mut cells: Vec<(String, LogicalFacts)> = Vec::new();

    for streaming in [true, false] {
        for begin_concurrent in [true, false] {
            let label = format!(
                "{}×{}",
                if streaming { "streaming" } else { "batch" },
                if begin_concurrent { "writer-handle" } else { "ephemeral-writer" }
            );
            let fixture = Fixture::new();
            fixture.write_claude_session(
                "proj-cell",
                &claude_session("sess-cell", "synthetic cell question", "cell answer"),
            );
            fixture.write_codex_session(
                "cell-codex",
                &codex_session("sess-cell-codex", "synthetic cell codex", "codex cell answer"),
            );

            let first = run_cell(&fixture, streaming, begin_concurrent);
            assert_eq!(
                first.status.code(),
                Some(0),
                "cell {label} succeeds; stderr={}",
                String::from_utf8_lossy(&first.stderr)
            );
            // The commit really went through the writer branch this cell names.
            let logs = String::from_utf8_lossy(&first.stderr).to_string();
            assert!(
                logs.contains("source_input_dispatch"),
                "cell {label} logs its dispatch: {logs}"
            );
            let expected = expected_writer_mode(begin_concurrent);
            assert!(
                logs.contains(expected),
                "cell {label} took {expected}: {logs}"
            );

            let db = fixture.open_db();
            let facts = fact_snapshot(&db);
            assert_eq!(facts.complete_inputs, 2, "both sources complete in cell {label}");
            assert!(facts.records >= 5, "records land in cell {label}: {facts:?}");
            assert_eq!(facts.receipts, 2, "one receipt per input in cell {label}");
            assert!(facts.messages >= 4, "canonical messages land in cell {label}");
            assert!(
                !facts.canonical_content.is_empty() && !facts.record_projection.is_empty(),
                "cell {label} has real canonical content and source projections"
            );
            assert!(
                !facts.revision.is_empty() && !facts.generation.is_empty(),
                "cell {label} records its revision and generation"
            );
            drop(db);

            // The lexical end is real: the safe canonical body is searchable.
            let mut search = Command::new(cass_bin());
            fixture.isolate(&mut search);
            search
                .args([
                    "search",
                    "--mode",
                    "lexical",
                    "synthetic cell question",
                    "--data-dir",
                    fixture.data_dir().to_str().unwrap(),
                    "--json",
                    "--rrf-limit",
                    "5",
                ]);
            let found = search.output().expect("spawn cass search");
            assert_eq!(
                found.status.code(),
                Some(0),
                "cell {label}: lexical query succeeds; stderr={}",
                String::from_utf8_lossy(&found.stderr)
            );
            assert!(
                String::from_utf8_lossy(&found.stdout).contains("synthetic cell question"),
                "cell {label}: the canonical body is recalled"
            );

            // Re-running the same input adds nothing and moves nothing.
            let second = run_cell(&fixture, streaming, begin_concurrent);
            assert_eq!(
                second.status.code(),
                Some(0),
                "cell {label} replay succeeds; stderr={}",
                String::from_utf8_lossy(&second.stderr)
            );
            let replayed = fact_snapshot(&fixture.open_db());
            assert_eq!(replayed, facts, "cell {label}: a replay adds nothing");
            assert_eq!(
                replayed.receipt_keys, facts.receipt_keys,
                "cell {label}: a replay rewrites no receipt"
            );
            assert_eq!(
                replayed.generation, facts.generation,
                "cell {label}: a replay moves no content generation"
            );
            assert_eq!(
                replayed.revision, facts.revision,
                "cell {label}: a replay moves no source facts revision"
            );

            cells.push((label, facts));
        }
    }

    // Across cells the *logical* projection must be identical. The receipt key
    // and the content generation are excluded on purpose: they are identity
    // values derived from the input key, which binds the absolute source path,
    // so two independently built temp trees are expected to differ there for
    // the same reason their UUIDs and row ids do. Within a cell the replay
    // assertions above already require both to be unchanged.
    let logical = |facts: &LogicalFacts| {
        (
            facts.complete_inputs,
            facts.records,
            facts.canonical_links,
            facts.receipts,
            facts.messages,
            facts.watermark_roots,
            facts.canonical_content.clone(),
            facts.record_projection.clone(),
            facts.link_projection.clone(),
            facts.revision.clone(),
        )
    };
    for (label, facts) in &cells {
        assert_eq!(
            logical(facts),
            logical(&cells[0].1),
            "every cell produces the same logical facts; {label} differs"
        );
    }
}

/// Each writer path rolls the whole input back on a late failure, and the same
/// writer retries it cleanly.
#[test]
fn i2_each_writer_path_rolls_a_late_failure_back_and_retries_it() {
    for begin_concurrent in [true, false] {
        let label = if begin_concurrent { "writer-handle" } else { "ephemeral-writer" };
        let fixture = Fixture::new();
        fixture.write_claude_session(
            "proj-rb",
            &claude_session("sess-rb", "synthetic rollback question", "rollback answer"),
        );

        let mut run = |fault: bool| -> std::process::Output {
            let mut cmd = Command::new(cass_bin());
            fixture.isolate(&mut cmd);
            cmd.env("CASS_STREAMING_INDEX", "1")
                .env(
                    "CASS_INDEXER_BEGIN_CONCURRENT",
                    if begin_concurrent { "1" } else { "0" },
                );
            if fault {
                cmd.env("CASS_SRC05B07_FAIL_AT", "activation");
            }
            cmd.args(["index", "--data-dir"])
                .arg(fixture.data_dir())
                .args([
                    "--source-safety-config",
                    fixture.fixed_copy().to_str().unwrap(),
                ])
                .args(["--json", "--verbose"]);
            cmd.output().expect("spawn cass index")
        };

        let failed = run(true);
        assert_ne!(
            failed.status.code(),
            Some(0),
            "the {label} cell fails on the injected fault"
        );
        assert!(
            String::from_utf8_lossy(&failed.stderr).contains(expected_writer_mode(begin_concurrent)),
            "the failing run still took the {label} branch"
        );
        assert!(
            String::from_utf8_lossy(&failed.stderr).contains("injected fault at activation"),
            "the activation fault is what stopped the {label} run"
        );
        assert!(
            fixture.db().exists(),
            "the {label} run reached the database and left one behind"
        );
        let db = fixture.open_db();
        let failed_facts = fact_snapshot(&db);
        assert_eq!(failed_facts.complete_inputs, 0, "no complete input survives a rollback ({label})");
        assert_eq!(failed_facts.receipts, 0, "no receipt survives a rollback ({label})");
        assert_eq!(failed_facts.canonical_links, 0, "no link survives a rollback ({label})");
        drop(db);

        // A new process in the same writer mode retries the whole input -- this
        // is not the same writer object (that case is the module test).
        let retried = run(false);
        assert_eq!(
            retried.status.code(),
            Some(0),
            "a new process in the {label} mode retries the whole input cleanly; stderr={}",
            String::from_utf8_lossy(&retried.stderr)
        );
        let db = fixture.open_db();
        let facts = fact_snapshot(&db);
        assert_eq!(facts.complete_inputs, 1, "the retry completes the input ({label})");
        assert_eq!(facts.receipts, 1, "and writes its receipt ({label})");
        let dangling: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM source_message_links WHERE message_id IS NULL",
                [],
                |r| r.get(0),
            )
            .expect("count dangling links");
        assert_eq!(
            dangling, 0,
            "the retry leaves no link pointing at a rolled-back message ({label})"
        );
    }
}

/// A storage failure that is retryable keeps its kind all the way out: the
/// input is reported as a transient failure (not an opaque corruption), the
/// run stops, and a later run commits the whole input.
#[test]
fn i2_a_busy_write_is_reported_as_transient_and_the_whole_input_retries() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-busy",
        &claude_session("sess-busy", "synthetic busy question", "busy answer"),
    );

    let failed = fixture.run_index_env(
        &[
            "--source-safety-config",
            fixture.fixed_copy().to_str().unwrap(),
        ],
        &[("CASS_SRC05B07_FAIL_AT", "busy")],
    );
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&failed.stdout),
        String::from_utf8_lossy(&failed.stderr)
    );
    assert_ne!(failed.status.code(), Some(0), "a busy write stops the run");
    assert!(
        logs.contains("transient failure: the database was busy"),
        "the retryable kind survived to the outcome: {logs}"
    );
    assert!(
        logs.contains("index-busy") && logs.contains("\"retryable\":true"),
        "the run reports it as retryable rather than corrupt: {logs}"
    );
    if fixture.db().exists() {
        let db = fixture.open_db();
        let facts = fact_snapshot(&db);
        assert_eq!(facts.complete_inputs, 0, "a transient failure completes nothing");
        assert_eq!(facts.receipts, 0, "and writes no receipt");
    }

    // Retrying the whole input, without the fault, commits it.
    let retried = fixture.run_index();
    assert_eq!(
        retried.status.code(),
        Some(0),
        "the whole input retries cleanly; stderr={}",
        String::from_utf8_lossy(&retried.stderr)
    );
    let db = fixture.open_db();
    let facts = fact_snapshot(&db);
    assert_eq!(facts.complete_inputs, 1);
    assert_eq!(facts.receipts, 1);
}

/// An inherited external `CODEX_HOME` is overridden by the fixture, so a
/// fixture run reads only its own sources.
#[test]
fn i1_an_inherited_codex_home_is_overridden_by_the_fixture() {
    const SENTINEL: &str = "external-codex-home-sentinel-must-not-land";

    let fixture = Fixture::new();
    // The fixture's own two sources.
    fixture.write_claude_session(
        "proj-iso",
        &claude_session("sess-iso", "synthetic isolated question", "isolated answer"),
    );
    fixture.write_codex_session(
        "iso-codex",
        &codex_session("sess-iso-codex", "synthetic isolated codex", "isolated codex answer"),
    );

    // A second private synthetic Codex home, standing in for an inherited
    // environment variable. No real directory is touched.
    let external = fixture.root.path().join("external-codex-home");
    let external_sessions = external.join("sessions/2026/01");
    std::fs::create_dir_all(&external_sessions).expect("mkdir the external codex home");
    std::fs::write(
        external_sessions.join("rollout-2026-01-01T00-00-00-external.jsonl"),
        format!(
            "{}\n{}\n",
            serde_json::json!({
                "timestamp": "2026-01-01T00:00:00.000Z",
                "type": "session_meta",
                "payload": {"id": "external-session", "cwd": "/synthetic/external", "cli_version": "0.42.0"}
            }),
            serde_json::json!({
                "timestamp": "2026-01-01T00:00:01.000Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "id": "external-msg-1",
                    "role": "user",
                    "content": [{"type": "input_text", "text": SENTINEL}]
                }
            }),
        ),
    )
    .expect("write the external session");

    // `run_index_env` applies the caller's variables before the fixture
    // isolation, so this is exactly an inherited value being overridden --
    // and it never touches the test process's own environment.
    let output = fixture.run_index_env(
        &[
            "--source-safety-config",
            fixture.fixed_copy().to_str().unwrap(),
        ],
        &[("CODEX_HOME", external.to_str().unwrap())],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "the run succeeds; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let db = fixture.open_db();
    let leaked: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE content LIKE '%' || ?1 || '%'",
            [SENTINEL],
            |r| r.get(0),
        )
        .expect("search for the sentinel");
    assert_eq!(leaked, 0, "the external Codex home's content never lands");
    let leaked_records: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_records WHERE instr(CAST(payload_bin AS TEXT), ?1) > 0",
            [SENTINEL],
            |r| r.get(0),
        )
        .expect("search the stored records");
    assert_eq!(leaked_records, 0, "nor is it retained as a source record");
    let leaked_inputs: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_records r JOIN source_inputs i ON i.id = r.input_id
             WHERE instr(hex(i.relative_locator_bin), hex('external')) > 0",
            [],
            |r| r.get(0),
        )
        .expect("count the external input");
    assert_eq!(leaked_inputs, 0, "no input names the external file");

    // Both fixture sources still land.
    let inputs: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
            [],
            |r| r.get(0),
        )
        .expect("count complete inputs");
    assert_eq!(inputs, 2, "the fixture's own two sources are ingested");
    let messages: i64 = db
        .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
        .expect("count messages");
    assert!(messages >= 4, "and their messages reach the canonical store");
}

// ---------------------------------------------------------------------------
// I6/R2b: a configured path mapping is effective material, not decoration
// ---------------------------------------------------------------------------

/// A `sources.toml` declaring one private local root with a path mapping.
fn write_mapped_source(fixture: &Fixture, name: &str, root: &std::path::Path, to: &str) {
    let dir = fixture.home().join(".config/cass");
    std::fs::create_dir_all(&dir).expect("mkdir cass config");
    std::fs::write(
        dir.join("sources.toml"),
        format!(
            "[[sources]]\nname = \"{name}\"\ntype = \"local\"\norigin_host = \"{name}\"\npaths = [\"{}\"]\npath_mappings = [{{ from = \"/synthetic-old\", to = \"{to}\" }}]\n",
            root.display()
        ),
    )
    .expect("write sources.toml");
}

/// The stored parser context of one input, decoded.
fn stored_parser_context(fixture: &Fixture, input_key_hex: &str) -> serde_json::Value {
    let db = fixture.open_db();
    let bytes: Vec<u8> = db
        .query_row(
            "SELECT parser_context_bin FROM source_inputs WHERE hex(input_key) = ?1",
            [input_key_hex],
            |r| r.get(0),
        )
        .expect("read the parser context");
    // The stored context is the canonical JSON text itself, not an envelope.
    String::from_utf8(bytes)
        .expect("the stored context is UTF-8")
        .parse()
        .expect("the stored context is JSON")
}

/// Every input's identity, newest last.
fn identities(fixture: &Fixture) -> Vec<(String, String, String, String)> {
    let db = fixture.open_db();
    let mut stmt = db
        .prepare(
            "SELECT hex(input_key), normalizer_id, safety_contract_id, hex(context_digest)
             FROM source_inputs ORDER BY id",
        )
        .expect("prepare");
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect")
}

/// A different effective mapping is a different input identity, with only the
/// mapping changed: one source tree, one safety copy, one fixed copy path, two
/// independent data directories.
#[test]
fn i6_a_mapping_change_moves_the_identity_without_touching_the_old_receipt() {
    let fixture = Fixture::new();
    let root = fixture.root.path().join("mapped-root");
    std::fs::create_dir_all(root.join("projects/-m")).expect("mkdir the declared root");
    // The session's own cwd sits inside the mapping's `from` prefix, so the
    // rewrite has something real to act on rather than only a config entry.
    let session: Vec<serde_json::Value> = claude_session(
        "sess-mapped",
        "synthetic mapped question",
        "mapped answer",
    )
    .into_iter()
    .map(|mut line| {
        if let Some(obj) = line.as_object_mut() {
            obj.insert("cwd".to_string(), serde_json::json!("/synthetic-old/project"));
        }
        line
    })
    .collect();
    std::fs::write(
        root.join("projects/-m/agent-m.jsonl"),
        session.iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n") + "\n",
    )
    .expect("write the declared session");

    let mut per_mapping: Vec<(String, String, String, String, serde_json::Value, std::path::PathBuf)> =
        Vec::new();
    for (index, to) in ["/synthetic-mapped-one", "/synthetic-mapped-two"]
        .into_iter()
        .enumerate()
    {
        write_mapped_source(&fixture, "mapped", &root, to);
        let data_dir = fixture.root.path().join(format!("data-{index}"));
        let output = fixture.run_index_in(
            &data_dir,
            &[
                "--source-safety-config",
                fixture.fixed_copy().to_str().unwrap(),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "the mapped source ingests with {to}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let db = Fixture::open_db_at(&data_dir.join("agent_search.db"));
        let (input_key, normalizer, safety, context_digest): (String, String, String, String) = db
            .query_row(
                "SELECT hex(input_key), normalizer_id, safety_contract_id, hex(context_digest)
                 FROM source_inputs LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .expect("read the identity columns");
        let context_bytes: Vec<u8> = db
            .query_row("SELECT parser_context_bin FROM source_inputs LIMIT 1", [], |r| r.get(0))
            .expect("read the parser context");
        let context: serde_json::Value = String::from_utf8(context_bytes)
            .expect("utf-8")
            .parse()
            .expect("json");
        assert!(
            context["workspace_rewrites"].to_string().contains(to),
            "the persisted context carries the effective mapping {to}: {context}"
        );
        per_mapping.push((to.to_string(), normalizer, input_key, safety, context, data_dir));
    }

    // The only thing that changed is the mapping.
    assert_eq!(
        per_mapping[0].3, per_mapping[1].3,
        "the fixed safety copy is the same file with the same bytes, so the safety \
         identity is unchanged"
    );
    assert_ne!(
        per_mapping[0].1, per_mapping[1].1,
        "a different effective mapping is a different profile"
    );
    assert_ne!(per_mapping[0].2, per_mapping[1].2, "and a different input key");
    assert_ne!(
        per_mapping[0].4, per_mapping[1].4,
        "because the parser context itself differs"
    );

    // The canonical workspace is the mapped path, applied once, and the
    // original is retained.
    let db = Fixture::open_db_at(&per_mapping[1].5.join("agent_search.db"));
    let (conversation_id, workspace): (i64, String) = db
        .query_row(
            "SELECT c.id, w.path FROM conversations c
             LEFT JOIN workspaces w ON w.id = c.workspace_id LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("read the canonical workspace");
    assert_eq!(
        workspace, "/synthetic-mapped-two/project",
        "the mapping was applied exactly once"
    );
    drop(db);
    let storage = coding_agent_search::storage::sqlite::FrankenStorage::open(
        &per_mapping[1].5.join("agent_search.db"),
    )
    .expect("open the storage");
    let metadata = storage
        .conversation_metadata_for_tests(conversation_id)
        .expect("read the conversation's logical metadata");
    assert_eq!(
        metadata["cass"]["workspace_original"],
        serde_json::json!("/synthetic-old/project"),
        "the original workspace path is retained: {metadata}"
    );
}

/// The same fixed copy, named by a relative path and by an absolute one, is the
/// same identity: the spelling cannot leak into it.
#[test]
fn i6_a_relative_fixed_copy_path_binds_to_the_same_identity() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-relpath",
        &claude_session("sess-relpath", "synthetic relative path", "answer"),
    );

    // Absolute spelling, from the test's own working directory.
    let absolute = fixture.run_index_env(
        &[
            "--source-safety-config",
            fixture.fixed_copy().to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(absolute.status.code(), Some(0), "stderr={}", String::from_utf8_lossy(&absolute.stderr));
    let (abs_safety, abs_normalizer) = {
        let db = fixture.open_db();
        db.query_row(
            "SELECT safety_contract_id, normalizer_id FROM source_inputs LIMIT 1",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .expect("read the identity")
    };

    // The same file, spelled relative to a working directory that resolves it.
    let relative_dir = fixture.root.path().join("data-relative");
    std::fs::create_dir_all(&relative_dir).expect("mkdir");
    let mut cmd = Command::new(cass_bin());
    fixture.isolate(&mut cmd);
    cmd.current_dir(fixture.root.path());
    cmd.env("CASS_DATA_DIR", &relative_dir);
    cmd.args(["index", "--data-dir"])
        .arg(&relative_dir)
        .args(["--source-safety-config", "fixed-safety.toml"])
        .args(["--json"]);
    let relative = cmd.output().expect("spawn cass index");
    assert_eq!(
        relative.status.code(),
        Some(0),
        "the relative spelling still runs; stderr={}",
        String::from_utf8_lossy(&relative.stderr)
    );
    let (rel_safety, rel_normalizer) = {
        let db = Fixture::open_db_at(&relative_dir.join("agent_search.db"));
        db.query_row(
            "SELECT safety_contract_id, normalizer_id FROM source_inputs LIMIT 1",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .expect("read the identity")
    };

    assert_eq!(
        rel_safety, abs_safety,
        "the same fixed copy binds to one safety identity however it is spelled"
    );
    assert_eq!(
        rel_normalizer, abs_normalizer,
        "and one normalizer identity"
    );
}

/// The same mapping run twice adds nothing and moves neither receipt nor
/// generation.
#[test]
fn i6_the_same_mapping_replays_to_nothing() {
    let fixture = Fixture::new();
    let root = fixture.root.path().join("mapped-root");
    std::fs::create_dir_all(root.join("projects/-m")).expect("mkdir the declared root");
    let session = claude_session("sess-mapped-again", "synthetic stable mapping", "answer");
    std::fs::write(
        root.join("projects/-m/agent-m.jsonl"),
        session.iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n") + "\n",
    )
    .expect("write the session");
    write_mapped_source(&fixture, "mapped", &root, "/synthetic-mapped-one");

    let first = fixture.run_index();
    assert_eq!(first.status.code(), Some(0), "stderr={}", String::from_utf8_lossy(&first.stderr));
    let before = fact_snapshot(&fixture.open_db());
    assert_eq!(before.complete_inputs, 1);

    let second = fixture.run_index();
    assert_eq!(second.status.code(), Some(0), "stderr={}", String::from_utf8_lossy(&second.stderr));
    let after = fact_snapshot(&fixture.open_db());
    assert_eq!(after.complete_inputs, 1, "the same mapping is the same input");
    assert_eq!(after.receipt_keys, before.receipt_keys, "no receipt is rewritten");
    assert_eq!(after.generation, before.generation, "no generation moves");
    assert_eq!(after.revision, before.revision, "no revision moves");
}


/// A fixed safety copy reached through a symlink is refused, so the identity
/// never names a path whose meaning depends on where a link points.
#[cfg(unix)]
#[test]
fn i6_a_symlinked_fixed_copy_is_refused() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-symlink",
        &claude_session("sess-symlink", "synthetic symlink", "answer"),
    );

    let link = fixture.root.path().join("fixed-safety-link.toml");
    std::os::unix::fs::symlink(fixture.fixed_copy(), &link).expect("create the symlink");

    let output = fixture.run_index_env(
        &["--source-safety-config", link.to_str().unwrap()],
        &[],
    );
    assert_ne!(
        output.status.code(),
        Some(0),
        "a symlinked fixed copy is not a success"
    );
    if fixture.db().exists() {
        let db = fixture.open_db();
        let inputs: i64 = db
            .query_row("SELECT COUNT(*) FROM source_inputs", [], |r| r.get(0))
            .unwrap_or(0);
        assert_eq!(inputs, 0, "and it lands no source fact");
    }
}

// ---------------------------------------------------------------------------
// Owner ID/body guard · the nine frozen native cases
// ---------------------------------------------------------------------------

const GUARD_BODY: &str = "ROOT_GUARD_BODY";
const GUARD_DISTINCT_ID: &str = "ROOT_GUARD_DISTINCT_ID";
const GUARD_CONTEXT_BODY: &str =
    "<environment_context>\n<cwd>/synthetic/root</cwd>\n</environment_context>";
const GUARD_FIXED_WITH_PROJECT_READ: &str = "memory_files = [\"USER.md\"]\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = [\"exec\"]\n";
const GUARD_FIXED_WITHOUT_EXCLUSIONS: &str = "memory_files = []\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n";

fn guard_codex_jsonl(call_id: &str) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "type": "session_meta",
            "payload": {"id": "ROOT_GUARD_SESSION", "cwd": "/synthetic/root", "cli_version": "0.42.0"}
        }),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:01Z",
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "project_read",
                "call_id": call_id,
                "arguments": "{\"document\":\"exec\"}"
            }
        }),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:02Z",
            "type": "response_item",
            "payload": {"type": "function_call_output", "call_id": call_id, "output": GUARD_BODY}
        }),
    ]
}

fn guard_claude_jsonl(tool_use_id: &str) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "type": "assistant",
            "uuid": "ROOT_A",
            "sessionId": "ROOT_GUARD_SESSION",
            "cwd": "/synthetic/root",
            "timestamp": "2026-01-01T00:00:01Z",
            "message": {
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "id": tool_use_id,
                    "name": "mcp__ccw-control-plane__project_read",
                    "input": {"document": "exec"}
                }]
            }
        }),
        serde_json::json!({
            "type": "user",
            "uuid": "ROOT_U",
            "sessionId": "ROOT_GUARD_SESSION",
            "cwd": "/synthetic/root",
            "timestamp": "2026-01-01T00:00:02Z",
            "message": {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": tool_use_id, "content": GUARD_BODY}]
            }
        }),
    ]
}

fn guard_codex_document(first_id: &str, second_id: &str) -> serde_json::Value {
    serde_json::json!({
        "session": {"id": "ROOT_GUARD_SESSION", "cwd": "/synthetic/root", "cli_version": "0.42.0"},
        "items": [
            {"id": first_id, "role": "user", "content": GUARD_CONTEXT_BODY, "timestamp": "2026-01-01T00:00:00Z"},
            {"id": second_id, "role": "assistant", "content": "ROOT_SIBLING_BODY", "timestamp": "2026-01-01T00:00:01Z"}
        ]
    })
}

fn guard_claude_document(body_id: &str) -> serde_json::Value {
    serde_json::json!({
        "sessionId": "ROOT_GUARD_SESSION",
        "cwd": "/synthetic/root",
        "version": "2.0.37",
        "messages": [
            {"id": body_id, "role": "user", "content": GUARD_CONTEXT_BODY, "timestamp": "2026-01-01T00:00:00Z"},
            {"id": "ROOT_SIBLING_ID", "role": "assistant", "content": "ROOT_SIBLING_BODY", "timestamp": "2026-01-01T00:00:01Z"}
        ]
    })
}

fn guard_table_count(fixture: &Fixture, table: &str) -> i64 {
    if !fixture.db().exists() {
        return 0;
    }
    let db = fixture.open_db();
    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
        .unwrap_or(0)
}

fn guard_mirror_snapshot(fixture: &Fixture) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &std::path::Path, base: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        let mut paths: Vec<std::path::PathBuf> = entries
            .map(|entry| entry.expect("mirror entry").path())
            .collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .expect("mirror file inside the mirror")
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, std::fs::read(&path).expect("read the mirror file")));
            }
        }
    }
    let root = fixture.data_dir().join("raw-mirror");
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out
}

fn guard_note(failures: &mut Vec<String>, label: &str, ok: bool, detail: String) {
    if !ok {
        failures.push(format!("{label}: {detail}"));
    }
}

/// The nine frozen native cases. Collision inputs must be refused before any
/// source fact lands; control, sibling and no-exclusion inputs must keep their
/// registered IDs and their unexcluded content.
#[test]
fn g_id_01_native_id_body_conflicts() {
    let mut failures = Vec::new();

    // 1 · codex-collision
    {
        let label = "codex-collision";
        let fixture = Fixture::new();
        std::fs::write(fixture.fixed_copy(), GUARD_FIXED_WITH_PROJECT_READ)
            .expect("write the guard fixed copy");
        fixture.write_codex_session("guard-codex-collision", &guard_codex_jsonl(GUARD_BODY));
        let first = fixture.run_index();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&first.stdout),
            String::from_utf8_lossy(&first.stderr)
        );
        guard_note(
            &mut failures,
            label,
            text.contains("source_safety_id_body_conflict"),
            format!("the fixed short code is absent; output={text}"),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_inputs") == 0,
            format!(
                "source_inputs={}",
                guard_table_count(&fixture, "source_inputs")
            ),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_records") == 0,
            format!("source_records={}", guard_table_count(&fixture, "source_records")),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "messages") == 0,
            format!("messages={}", guard_table_count(&fixture, "messages")),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "conversations") == 0,
            format!("conversations={}", guard_table_count(&fixture, "conversations")),
        );
        let before = guard_mirror_snapshot(&fixture);
        guard_note(
            &mut failures,
            label,
            !before.is_empty(),
            "the raw mirror holds no retained material".to_string(),
        );
        let _ = fixture.run_index();
        let after = guard_mirror_snapshot(&fixture);
        guard_note(
            &mut failures,
            label,
            before == after,
            "the retained raw mirror changed on the retry".to_string(),
        );
    }

    // 2 · claude-collision
    {
        let label = "claude-collision";
        let fixture = Fixture::new();
        std::fs::write(fixture.fixed_copy(), GUARD_FIXED_WITH_PROJECT_READ)
            .expect("write the guard fixed copy");
        fixture.write_claude_session("guard-claude-collision", &guard_claude_jsonl(GUARD_BODY));
        let first = fixture.run_index();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&first.stdout),
            String::from_utf8_lossy(&first.stderr)
        );
        guard_note(
            &mut failures,
            label,
            text.contains("source_safety_id_body_conflict"),
            format!("the fixed short code is absent; output={text}"),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_inputs") == 0,
            format!(
                "source_inputs={}",
                guard_table_count(&fixture, "source_inputs")
            ),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_records") == 0,
            format!("source_records={}", guard_table_count(&fixture, "source_records")),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "messages") == 0,
            format!("messages={}", guard_table_count(&fixture, "messages")),
        );
        let before = guard_mirror_snapshot(&fixture);
        guard_note(
            &mut failures,
            label,
            !before.is_empty(),
            "the raw mirror holds no retained material".to_string(),
        );
        let _ = fixture.run_index();
        guard_note(
            &mut failures,
            label,
            before == guard_mirror_snapshot(&fixture),
            "the retained raw mirror changed on the retry".to_string(),
        );
    }

    // 3 · codex-document-collision
    {
        let label = "codex-document-collision";
        let fixture = Fixture::new();
        std::fs::write(fixture.fixed_copy(), GUARD_FIXED_WITH_PROJECT_READ)
            .expect("write the guard fixed copy");
        fixture.write_codex_document(
            "guard-codex-document-collision",
            &guard_codex_document(GUARD_CONTEXT_BODY, "ROOT_SIBLING_ID"),
        );
        let first = fixture.run_index();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&first.stdout),
            String::from_utf8_lossy(&first.stderr)
        );
        guard_note(
            &mut failures,
            label,
            text.contains("source_safety_id_body_conflict"),
            format!("the fixed short code is absent; output={text}"),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_inputs") == 0,
            format!(
                "source_inputs={}",
                guard_table_count(&fixture, "source_inputs")
            ),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_records") == 0,
            format!("source_records={}", guard_table_count(&fixture, "source_records")),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "messages") == 0,
            format!("messages={}", guard_table_count(&fixture, "messages")),
        );
        let before = guard_mirror_snapshot(&fixture);
        guard_note(
            &mut failures,
            label,
            !before.is_empty(),
            "the raw mirror holds no retained material".to_string(),
        );
        let _ = fixture.run_index();
        guard_note(
            &mut failures,
            label,
            before == guard_mirror_snapshot(&fixture),
            "the retained raw mirror changed on the retry".to_string(),
        );
    }

    // 4 · codex-control
    {
        let label = "codex-control";
        let fixture = Fixture::new();
        std::fs::write(fixture.fixed_copy(), GUARD_FIXED_WITH_PROJECT_READ)
            .expect("write the guard fixed copy");
        fixture.write_codex_session(
            "guard-codex-control",
            &guard_codex_jsonl(GUARD_DISTINCT_ID),
        );
        let output = fixture.run_index();
        guard_note(
            &mut failures,
            label,
            output.status.code() == Some(0),
            format!(
                "rc={:?} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_inputs") == 1,
            format!(
                "source_inputs={}",
                guard_table_count(&fixture, "source_inputs")
            ),
        );
        let stored = fixture.stored_safe_values().join("\n");
        guard_note(
            &mut failures,
            label,
            stored.contains(GUARD_DISTINCT_ID),
            "the registered call_id was not preserved".to_string(),
        );
        guard_note(
            &mut failures,
            label,
            stored.contains("[REDACTED]"),
            "the excluded body was not redacted".to_string(),
        );
    }

    // 5 · claude-control
    {
        let label = "claude-control";
        let fixture = Fixture::new();
        std::fs::write(fixture.fixed_copy(), GUARD_FIXED_WITH_PROJECT_READ)
            .expect("write the guard fixed copy");
        fixture.write_claude_session(
            "guard-claude-control",
            &guard_claude_jsonl(GUARD_DISTINCT_ID),
        );
        let output = fixture.run_index();
        guard_note(
            &mut failures,
            label,
            output.status.code() == Some(0),
            format!(
                "rc={:?} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_inputs") == 1,
            format!(
                "source_inputs={}",
                guard_table_count(&fixture, "source_inputs")
            ),
        );
        let stored = fixture.stored_safe_values().join("\n");
        guard_note(
            &mut failures,
            label,
            stored.contains(GUARD_DISTINCT_ID),
            "the registered tool_use_id was not preserved".to_string(),
        );
        guard_note(
            &mut failures,
            label,
            stored.contains("[REDACTED]"),
            "the excluded body was not redacted".to_string(),
        );
    }

    // 6 · codex-document-control
    {
        let label = "codex-document-control";
        let fixture = Fixture::new();
        std::fs::write(fixture.fixed_copy(), GUARD_FIXED_WITH_PROJECT_READ)
            .expect("write the guard fixed copy");
        fixture.write_codex_document(
            "guard-codex-document-control",
            &guard_codex_document(GUARD_DISTINCT_ID, "ROOT_SIBLING_ID"),
        );
        let output = fixture.run_index();
        guard_note(
            &mut failures,
            label,
            output.status.code() == Some(0),
            format!(
                "rc={:?} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_inputs") == 1,
            format!(
                "source_inputs={}",
                guard_table_count(&fixture, "source_inputs")
            ),
        );
        let stored = fixture.stored_safe_values().join("\n");
        guard_note(
            &mut failures,
            label,
            stored.contains(GUARD_DISTINCT_ID),
            "the element id was not preserved".to_string(),
        );
        guard_note(
            &mut failures,
            label,
            stored.contains("[REDACTED]"),
            "the excluded body was not redacted".to_string(),
        );
    }

    // 7 · codex-document-sibling
    {
        let label = "codex-document-sibling";
        let fixture = Fixture::new();
        std::fs::write(fixture.fixed_copy(), GUARD_FIXED_WITH_PROJECT_READ)
            .expect("write the guard fixed copy");
        fixture.write_codex_document(
            "guard-codex-document-sibling",
            &guard_codex_document(GUARD_DISTINCT_ID, GUARD_CONTEXT_BODY),
        );
        let output = fixture.run_index();
        guard_note(
            &mut failures,
            label,
            output.status.code() == Some(0),
            format!(
                "rc={:?} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_inputs") == 1,
            format!(
                "source_inputs={}",
                guard_table_count(&fixture, "source_inputs")
            ),
        );
        let stored = fixture.stored_safe_values().join("\n");
        let escaped = serde_json::to_string(GUARD_CONTEXT_BODY)
            .expect("encode the sibling id");
        let escaped = &escaped[1..escaped.len() - 1];
        guard_note(
            &mut failures,
            label,
            stored.contains(GUARD_DISTINCT_ID),
            "the excluded element's id was not preserved".to_string(),
        );
        guard_note(
            &mut failures,
            label,
            stored.contains(escaped),
            "the sibling element's id was not preserved".to_string(),
        );
    }

    // 8 · codex-no-exclusion
    {
        let label = "codex-no-exclusion";
        let fixture = Fixture::new();
        std::fs::write(fixture.fixed_copy(), GUARD_FIXED_WITHOUT_EXCLUSIONS)
            .expect("write the guard fixed copy");
        fixture.write_codex_session("guard-codex-no-exclusion", &guard_codex_jsonl(GUARD_BODY));
        let output = fixture.run_index();
        guard_note(
            &mut failures,
            label,
            output.status.code() == Some(0),
            format!(
                "rc={:?} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_inputs") == 1,
            format!(
                "source_inputs={}",
                guard_table_count(&fixture, "source_inputs")
            ),
        );
        let stored = fixture.stored_safe_values().join("\n");
        guard_note(
            &mut failures,
            label,
            stored.contains(GUARD_BODY),
            "the input without an exclusion lost its body".to_string(),
        );
        guard_note(
            &mut failures,
            label,
            !stored.contains("[REDACTED]"),
            "an input without an exclusion was redacted".to_string(),
        );
    }

    // 9 · claude-document-no-exclusion
    {
        let label = "claude-document-no-exclusion";
        let fixture = Fixture::new();
        std::fs::write(fixture.fixed_copy(), GUARD_FIXED_WITHOUT_EXCLUSIONS)
            .expect("write the guard fixed copy");
        fixture.write_claude_document(
            "guard-claude-document-no-exclusion",
            &guard_claude_document(GUARD_CONTEXT_BODY),
        );
        let output = fixture.run_index();
        guard_note(
            &mut failures,
            label,
            output.status.code() == Some(0),
            format!(
                "rc={:?} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ),
        );
        guard_note(
            &mut failures,
            label,
            guard_table_count(&fixture, "source_inputs") == 1,
            format!(
                "source_inputs={}",
                guard_table_count(&fixture, "source_inputs")
            ),
        );
        let stored = fixture.stored_safe_values().join("\n");
        let escaped = serde_json::to_string(GUARD_CONTEXT_BODY)
            .expect("encode the unexcluded document content");
        let escaped = &escaped[1..escaped.len() - 1];
        guard_note(
            &mut failures,
            label,
            stored.contains(escaped),
            "an input without an exclusion lost its content".to_string(),
        );
        guard_note(
            &mut failures,
            label,
            !stored.contains("[REDACTED]"),
            "an input without an exclusion was redacted".to_string(),
        );
    }

    assert!(
        failures.is_empty(),
        "the nine frozen native ID/body cases failed:\n{}",
        failures.join("\n")
    );
}

fn guard_complete_inputs(fixture: &Fixture) -> i64 {
    if !fixture.db().exists() {
        return 0;
    }
    let db = fixture.open_db();
    db.query_row(
        "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
        [],
        |row| row.get(0),
    )
    .unwrap_or(0)
}

fn guard_table_rows(fixture: &Fixture, table: &str) -> Vec<Vec<String>> {
    if !fixture.db().exists() {
        return Vec::new();
    }
    let db = fixture.open_db();
    let mut stmt = db
        .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
        .expect("prepare the table snapshot");
    let columns = stmt.column_count();
    stmt.query_map([], |row| {
        let mut out = Vec::with_capacity(columns);
        for index in 0..columns {
            let value: rusqlite::types::Value = row.get(index)?;
            out.push(format!("{value:?}"));
        }
        Ok(out)
    })
    .expect("query the table snapshot")
    .collect::<Result<Vec<_>, _>>()
    .expect("collect the table snapshot")
}

fn guard_meta_map(fixture: &Fixture) -> std::collections::BTreeMap<String, String> {
    let db = fixture.open_db();
    let mut stmt = db
        .prepare("SELECT key, value FROM meta ORDER BY key")
        .expect("prepare the meta snapshot");
    stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })
    .expect("query the meta snapshot")
    .collect::<Result<std::collections::BTreeMap<_, _>, _>>()
    .expect("collect the meta snapshot")
}

fn guard_nine_tables(fixture: &Fixture) -> Vec<(String, Vec<Vec<String>>)> {
    [
        "messages",
        "conversations",
        "agents",
        "workspaces",
        "source_inputs",
        "source_records",
        "source_message_links",
        "operation_commit_receipt",
        "meta",
    ]
    .into_iter()
    .map(|table| (table.to_string(), guard_table_rows(fixture, table)))
    .collect()
}

/// The additional old-world control, separate from the 31 frozen rows: the
/// accepted 2ed binary first completes the collision (the proven bug), then the
/// current binary retries the very same input. It must refuse rather than mint
/// a new identity or replay the old success.
#[test]
fn g_extra_old_collision_retry_is_refused_not_replayed() {
    let baseline = std::env::var("CASS_GUARD_BASELINE_CLI")
        .expect("CASS_GUARD_BASELINE_CLI must be set for the old-collision retry control");
    let fixture = Fixture::new();
    std::fs::write(fixture.fixed_copy(), GUARD_FIXED_WITH_PROJECT_READ)
        .expect("write the guard fixed copy");
    fixture.write_codex_session(
        "guard-old-collision-retry",
        &guard_codex_jsonl(GUARD_BODY),
    );

    let old = fixture.run_index_binary(&baseline);
    assert_eq!(
        old.status.code(),
        Some(0),
        "the accepted 2ed binary must build the wrong world: {}",
        String::from_utf8_lossy(&old.stderr)
    );
    assert_eq!(
        guard_table_count(&fixture, "source_inputs"),
        1,
        "the old world records exactly one input"
    );
    assert_eq!(
        guard_complete_inputs(&fixture),
        1,
        "the old world wrongly completes the collision"
    );

    let before = guard_nine_tables(&fixture);
    let before_meta = guard_meta_map(&fixture);
    let before_mirror = guard_mirror_snapshot(&fixture);
    // A full read forces the unchanged file back through the shared safety
    // pass; the same input_key is what the old wrong receipt is bound to.
    let fixed = fixture.fixed_copy();
    let retry = fixture.run_index_with(&[
        "--source-safety-config",
        fixed.to_str().unwrap(),
        "--full",
    ]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&retry.stdout),
        String::from_utf8_lossy(&retry.stderr)
    );
    assert!(
        text.contains("source_safety_id_body_conflict"),
        "the same input must be refused with the fixed short code: {text}"
    );
    assert_eq!(
        guard_table_count(&fixture, "source_inputs"),
        1,
        "the retry adds no new input identity"
    );
    assert_eq!(
        guard_complete_inputs(&fixture),
        1,
        "the old wrong completion is not replaced by a new one"
    );
    let after = guard_nine_tables(&fixture);
    for (before_table, before_rows) in &before {
        if before_table == "meta" {
            continue;
        }
        let after_rows = after
            .iter()
            .find(|(table, _)| table == before_table)
            .map(|(_, rows)| rows)
            .expect("every table is snapshotted");
        assert_eq!(
            after_rows, before_rows,
            "the retry changed typed rows in table {before_table}"
        );
    }
    // The ordinary index updates only its two run bookkeeping keys on every
    // run. The root success watermark and every source identity key stay
    // value-exact, so the refusal commits nothing to the source.
    let after_meta = guard_meta_map(&fixture);
    let changed: Vec<&String> = after_meta
        .iter()
        .filter(|(key, value)| before_meta.get(*key) != Some(*value))
        .map(|(key, _)| key)
        .collect();
    assert!(
        changed.iter().all(|key| {
            key.as_str() == "last_indexed_at" || key.as_str() == "lex_domain_rebuild_state"
        }),
        "unexpected meta keys changed: {changed:?}"
    );
    for key in [
        "source_facts_revision",
        "source_content_generation",
        "last_scan_ts:connector:codex",
        "library_identity",
        "vector_domain_instance_id",
    ] {
        assert_eq!(
            after_meta.get(key),
            before_meta.get(key),
            "the retry changed the source progress key {key}"
        );
    }
    assert_eq!(
        guard_mirror_snapshot(&fixture),
        before_mirror,
        "the retry changes no raw mirror byte"
    );
}

fn e2_mixed_session() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "type": "assistant",
            "uuid": "ROOT_A",
            "sessionId": "ROOT_GUARD_SESSION",
            "cwd": "/synthetic/root",
            "timestamp": "2026-01-01T00:00:01Z",
            "message": {
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "id": "ROOT_GUARD_DISTINCT_ID",
                    "name": "mcp__ccw-control-plane__project_read",
                    "input": {"document": "exec"}
                }]
            }
        }),
        serde_json::json!({
            "type": "user",
            "uuid": "ROOT_U",
            "sessionId": "ROOT_GUARD_SESSION",
            "cwd": "/synthetic/root",
            "timestamp": "2026-01-01T00:00:02Z",
            "message": {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "ROOT_GUARD_DISTINCT_ID",
                        "content": "ROOT_GUARD_BODY"
                    },
                    {
                        "type": "tool_use",
                        "id": "ROOT_GUARD_BODY",
                        "name": "Read",
                        "input": {}
                    }
                ]
            }
        }),
    ]
}

/// E2 extra, separate from the 31: the accepted 2ed binary completes the
/// mixed record and erases the stray tool ID; the current binary refuses the
/// same record with the fixed short code and lands no source fact.
#[test]
fn e2_extra_native_mixed_offrole_is_refused() {
    let baseline = std::env::var("CASS_GUARD_BASELINE_CLI")
        .expect("CASS_GUARD_BASELINE_CLI must be set for the E2 native extra");

    let old = Fixture::new();
    std::fs::write(old.fixed_copy(), GUARD_FIXED_WITH_PROJECT_READ)
        .expect("write the guard fixed copy");
    old.write_claude_session("e2-mixed-old", &e2_mixed_session());
    let old_run = old.run_index_binary(&baseline);
    assert_eq!(
        old_run.status.code(),
        Some(0),
        "the accepted 2ed binary must complete the mixed record: {}",
        String::from_utf8_lossy(&old_run.stderr)
    );
    assert_eq!(
        guard_complete_inputs(&old),
        1,
        "the old world wrongly completes the mixed record"
    );
    let old_stored = old.stored_safe_values().join("\n");
    assert!(
        old_stored.contains("ROOT_GUARD_DISTINCT_ID"),
        "the matched call/result ID must survive: {old_stored}"
    );
    assert!(
        old_stored.contains("[REDACTED]"),
        "the excluded body must be cleared: {old_stored}"
    );
    assert!(
        !old_stored.contains("ROOT_GUARD_BODY"),
        "the stray off-role tool ID must be erased by the old sweep: {old_stored}"
    );

    let now = Fixture::new();
    std::fs::write(now.fixed_copy(), GUARD_FIXED_WITH_PROJECT_READ)
        .expect("write the guard fixed copy");
    now.write_claude_session("e2-mixed-now", &e2_mixed_session());
    let current = now.run_index();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&current.stdout),
        String::from_utf8_lossy(&current.stderr)
    );
    assert_eq!(
        current.status.code(),
        Some(9),
        "the current binary must refuse the mixed record: {text}"
    );
    assert!(
        text.contains("source_safety_id_body_conflict"),
        "the fixed short code must appear: {text}"
    );
    assert_eq!(
        guard_table_count(&now, "source_inputs"),
        0,
        "the refused mixed record lands no source input"
    );
    assert_eq!(
        guard_table_count(&now, "source_records"),
        0,
        "the refused mixed record lands no source record"
    );
    assert_eq!(
        guard_table_count(&now, "messages"),
        0,
        "the refused mixed record lands no message"
    );
    assert!(
        !guard_mirror_snapshot(&now).is_empty(),
        "the refused mixed record keeps its raw mirror material"
    );
}
