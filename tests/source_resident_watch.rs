//! SRC05B-09B acceptance: the resident `--watch` event cycle under a fixed
//! safety configuration.
//!
//! Every case drives the real `cass index --watch` binary over a private
//! synthetic HOME, a private fixed safety copy and a private data directory.
//! The seam is the CLI, the process boundary, the SQLite database and the
//! lexical search surface -- nothing calls an internal helper.
//!
//! The fixtures are synthetic and neutral. No real session, path or secret
//! appears in this file.
//!
//! None of these cases sleeps for a fixed time and hopes: each one waits on a
//! bounded observation of something the run itself produced, and fails with the
//! whole captured log when the deadline passes.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::OptionalExtension as _;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

/// The line a source-aware commit writes from *inside* its writer closure: the
/// proof that a cycle really carried an input through the kernel rather than
/// merely discovering it.
const DISPATCH_MARKER: &str = "source_input_dispatch";

/// The line `watch_sources` writes once the watcher is registered and the loop
/// is about to start. Waiting for it is how these cases separate the startup
/// scan from the event cycle: everything this file asserts about the event
/// cycle happens strictly after it.
const WATCH_READY_MARKER: &str = "watch mode: minimum interval between scan cycles";

/// The explicit failure a tampered fixed copy produces, so a case can show the
/// run said so instead of quietly reading through something else.
const SAFETY_COPY_STALE_MARKER: &str = "the fixed safety copy no longer matches";

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

    fn config_home(&self) -> PathBuf {
        self.root.path().join("config")
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

    /// Point every source-discovery environment at this fixture, so an inherited
    /// value on the host cannot make a fixture process scan real history.
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
            // A resident cycle applies the active-source filter, whose
            // recent-write window treats a just-written session log as one
            // still being appended to and skips it. That protection is the
            // right production behaviour and this file exercises it nowhere:
            // what these cases need is for a file created *after* the loop is
            // ready to be read by the event cycle, so the window is disabled
            // here rather than waited out. `0` is the documented way to turn
            // it off.
            .env("CASS_ACTIVE_SESSION_RECENT_WRITE_WINDOW_SECS", "0")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("CASS_TEST_WATCH_PATHS")
            .env_remove("CASS_SRC05B07_FAIL_AT")
            .env_remove("RUST_LOG");
        cmd
    }

    /// Create the two HOME roots a resident run will watch, before it starts.
    ///
    /// A declared root is planned and watched from what exists when the run
    /// starts, so a case that wants an *event* to be the thing that lands data
    /// has to have the directories in place and empty first.
    fn create_home_roots(&self) {
        std::fs::create_dir_all(self.home().join(".claude/projects")).expect("mkdir claude root");
        std::fs::create_dir_all(self.home().join(".codex/sessions")).expect("mkdir codex root");
    }

    fn write_claude_session(&self, relative: &str, lines: &[serde_json::Value]) -> PathBuf {
        let path = self.home().join(".claude/projects").join(relative);
        std::fs::create_dir_all(path.parent().expect("session parent")).expect("mkdir session dir");
        std::fs::write(&path, jsonl(lines)).expect("write claude session");
        path
    }

    fn write_codex_session(&self, relative: &str, lines: &[serde_json::Value]) -> PathBuf {
        let path = self.home().join(".codex/sessions").join(relative);
        std::fs::create_dir_all(path.parent().expect("rollout parent")).expect("mkdir rollout dir");
        std::fs::write(&path, jsonl(lines)).expect("write codex rollout");
        path
    }

    /// One `sources.toml` declaring a local root with its own origin host.
    fn write_configured_source(&self, name: &str, origin_host: &str, root: &Path) {
        let dir = self.config_home().join("cass");
        std::fs::create_dir_all(&dir).expect("mkdir cass config");
        std::fs::write(
            dir.join("sources.toml"),
            format!(
                "[[sources]]\nname = \"{name}\"\ntype = \"local\"\n\
                 origin_host = \"{origin_host}\"\n\
                 paths = [\"{}\"]\n",
                root.display()
            ),
        )
        .expect("write sources.toml");
    }

    fn open_db(&self) -> rusqlite::Connection {
        let db = rusqlite::Connection::open_with_flags(
            self.db(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open the database read-only");
        db.busy_timeout(Duration::from_secs(30))
            .expect("busy timeout");
        db
    }

    /// A read-only handle on the live database, or `None` while it does not
    /// exist or the writer is mid-checkpoint.
    fn try_open_db(&self) -> Option<rusqlite::Connection> {
        if !self.db().exists() {
            return None;
        }
        let db = rusqlite::Connection::open_with_flags(
            self.db(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .ok()?;
        db.busy_timeout(Duration::from_secs(30)).ok()?;
        Some(db)
    }

    fn search(&self, query: &str) -> std::process::Output {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.args([
            "search",
            query,
            "--data-dir",
            self.data_dir().to_str().expect("utf-8 data dir"),
            "--json",
            "--rrf-limit",
            "5",
        ]);
        cmd.output().expect("spawn cass search")
    }

    /// Rewrite the fixed safety copy so its bytes -- and therefore its
    /// safety-contract identity -- no longer match what the run loaded.
    fn break_fixed_copy(&self) {
        let text = std::fs::read_to_string(self.fixed_copy()).expect("read the fixed copy");
        std::fs::write(
            self.fixed_copy(),
            text.replace(
                "project_read_documents = [\"exec\"",
                "project_read_documents = [\"extra_document\", \"exec\"",
            ),
        )
        .expect("rewrite the fixed copy");
    }

    fn watch_state_path(&self) -> PathBuf {
        self.data_dir().join("watch_state.json")
    }
}

fn jsonl(lines: &[serde_json::Value]) -> String {
    lines
        .iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
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

// ---------------------------------------------------------------------------
// The resident process
// ---------------------------------------------------------------------------

/// A live `cass index --watch` child, with its stderr captured as it is
/// produced so a case can wait on a line the run really wrote.
struct Resident {
    child: Child,
    log: Arc<Mutex<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Resident {
    fn start(fixture: &Fixture, extra_env: &[(&str, &str)], with_flag: bool) -> Self {
        let mut cmd = Command::new(cass_bin());
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        fixture.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"]).arg(fixture.data_dir());
        if with_flag {
            cmd.arg("--source-safety-config").arg(fixture.fixed_copy());
        }
        cmd.args(["--watch", "--watch-interval", "1", "--json", "--verbose"]);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn the resident watch process");
        let stderr = child.stderr.take().expect("the child's stderr");
        let log = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&log);
        let reader = std::thread::spawn(move || {
            let mut stderr = stderr;
            let mut buf = [0u8; 4096];
            loop {
                match stderr.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&buf[..n]).to_string();
                        sink.lock().expect("log lock").push_str(&text);
                    }
                }
            }
        });
        Self {
            child,
            log,
            reader: Some(reader),
        }
    }

    fn log(&self) -> String {
        self.log.lock().expect("log lock").clone()
    }

    /// Wait until the captured log contains `needle`, or the deadline passes.
    fn wait_for(&self, needle: &str, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            if self.log().contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Wait until the captured log counts strictly more occurrences of
    /// `needle` than `was`, and return the new count.
    fn wait_for_more(&self, needle: &str, was: usize, limit: Duration) -> Option<usize> {
        let deadline = Instant::now() + limit;
        loop {
            let seen = self.log().matches(needle).count();
            if seen > was {
                return Some(seen);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn count(&self, needle: &str) -> usize {
        self.log().matches(needle).count()
    }

    /// Poll a probe until it yields a value, failing at the deadline with this
    /// run's own log attached -- a case that fails has to be able to show what
    /// the process it started actually did.
    fn poll_until<T>(
        &self,
        what: &str,
        limit: Duration,
        mut probe: impl FnMut() -> Option<T>,
    ) -> T {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(value) = probe() {
                return value;
            }
            if Instant::now() >= deadline {
                panic!(
                    "timed out after {limit:?} waiting for {what}; the run's own log follows:\n{}",
                    self.log()
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Wait for this case's own child to be gone. Never a name- or pattern-based
    /// kill: only the process this case started.
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for Resident {
    fn drop(&mut self) {
        if self.reader.is_some() {
            self.stop();
        }
    }
}

// ---------------------------------------------------------------------------
// Database readers
// ---------------------------------------------------------------------------

fn count(db: &rusqlite::Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("{sql}: {error}"))
}

fn count_like(db: &rusqlite::Connection, needle: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM messages WHERE content LIKE '%' || ?1 || '%'",
        [needle],
        |row| row.get(0),
    )
    .expect("count messages carrying the phrase")
}

fn receipt_keys(db: &rusqlite::Connection) -> String {
    // `group_concat` is NULL, not empty, when the table holds no row, and a
    // probe that reads an unfinished run has to be able to see that rather
    // than panic on the way to its own deadline.
    db.query_row(
        "SELECT COALESCE(group_concat(idempotency_key, '|'), '') FROM operation_commit_receipt",
        [],
        |row| row.get(0),
    )
    .expect("read the receipt keys")
}

fn source_facts_revision(db: &rusqlite::Connection) -> String {
    db.query_row(
        "SELECT value FROM meta WHERE key = 'source_facts_revision'",
        [],
        |row| row.get(0),
    )
    .optional()
    .expect("read the source facts revision")
    .unwrap_or_else(|| "<absent>".to_string())
}

/// `relative_locator_bin` is a BLOB column, so every comparison against a
/// locator has to bind the locator as bytes. A string literal in the SQL would
/// compare BLOB to TEXT, which SQLite never reports as equal -- a lookup that
/// silently matches nothing, which is how a "no row for this locator"
/// assertion can pass while the row is right there.
fn input_state_for(db: &rusqlite::Connection, locator: &str) -> Option<String> {
    db.query_row(
        "SELECT state FROM source_inputs WHERE relative_locator_bin = ?1",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .optional()
    .unwrap_or_else(|error| panic!("reading the state of {locator}: {error}"))
}

/// How many source inputs this database holds for one relative locator.
fn input_rows(db: &rusqlite::Connection, locator: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM source_inputs WHERE relative_locator_bin = ?1",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("counting inputs for {locator}: {error}"))
}

/// How many of those inputs are recorded as complete.
fn complete_input_rows(db: &rusqlite::Connection, locator: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM source_inputs \
         WHERE relative_locator_bin = ?1 AND state = 'complete'",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("counting complete inputs for {locator}: {error}"))
}

/// Every input key registered for one relative locator, in order.
fn input_keys_for(db: &rusqlite::Connection, locator: &str) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT input_key FROM source_inputs \
             WHERE relative_locator_bin = ?1 ORDER BY input_key",
        )
        .expect("prepare the locator's input keys");
    let rows: Vec<Vec<u8>> = stmt
        .query_map([locator.as_bytes()], |row| row.get::<_, Vec<u8>>(0))
        .expect("query the locator's input keys")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the locator's input keys");
    rows.into_iter().map(|bytes| hex(&bytes)).collect()
}

/// Every source fact this database holds, as comparable lines.
fn source_facts_fingerprint(db: &rusqlite::Connection) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut stmt = db
        .prepare(
            "SELECT input_key, root_id_bin, relative_locator_bin, context_digest,
                    identity_namespace, origin_host, connector, state, normalizer_id,
                    safety_contract_id, sealed_sha256
             FROM source_inputs ORDER BY input_key",
        )
        .expect("prepare the input fingerprint");
    let rows = stmt
        .query_map([], |row| {
            let input_key: Vec<u8> = row.get(0)?;
            let root: Vec<u8> = row.get(1)?;
            let locator: Vec<u8> = row.get(2)?;
            let context_digest: Vec<u8> = row.get(3)?;
            let sealed: Vec<u8> = row.get(10)?;
            Ok(format!(
                "input key={} root={} locator={} context={} namespace={} origin_host={} \
                 connector={} state={} normalizer={} safety={} sealed={}",
                hex(&input_key),
                String::from_utf8_lossy(&root),
                String::from_utf8_lossy(&locator),
                hex(&context_digest),
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                hex(&sealed),
            ))
        })
        .expect("query the input fingerprint")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the input fingerprint");
    lines.extend(rows);

    for (label, sql) in [
        ("source_records", "SELECT COUNT(*) FROM source_records"),
        (
            "source_message_links",
            "SELECT COUNT(*) FROM source_message_links",
        ),
        ("messages", "SELECT COUNT(*) FROM messages"),
        ("conversations", "SELECT COUNT(*) FROM conversations"),
    ] {
        lines.push(format!("{label}={}", count(db, sql)));
    }
    lines.push(format!(
        "source_facts_revision={}",
        source_facts_revision(db)
    ));
    lines.push(format!("receipts={}", receipt_keys(db)));
    lines
}

/// One kind's persistent watch watermark, as `watch_state.json` holds it.
///
/// `ConnectorKind` serialises to a two-letter key, so the caller names the kind
/// by that key (`cd` Claude, `cx` Codex).
fn watch_watermark_for(fixture: &Fixture, kind_key: &str) -> Option<i64> {
    let raw = std::fs::read_to_string(fixture.watch_state_path()).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    value["m"][kind_key].as_i64()
}

/// The `resident_source_watch_trigger` lines a run wrote, as
/// `(connector, trigger_total, processed_conversations, sink_in_flight_high_water)`.
///
/// The run's own record of what each trigger did, and of how many triggers the
/// cycle that ran it carried -- which is how a case tells "these two kinds were
/// handled together" from "these two kinds happened to be handled one after the
/// other".
fn trigger_lines(resident: &Resident) -> Vec<TriggerLine> {
    resident
        .log()
        .lines()
        .filter(|line| line.contains("resident_source_watch_trigger"))
        .filter_map(parse_trigger_line)
        .collect()
}

fn parse_trigger_line(line: &str) -> Option<TriggerLine> {
    let field = |name: &str| -> Option<String> {
        line.split_whitespace()
            .find_map(|part| part.strip_prefix(&format!("{name}=")).map(str::to_string))
            // `tracing` renders a `&str` field quoted and a `%`-formatted one
            // bare, so the value is normalised here rather than in every
            // caller.
            .map(|value| value.trim_matches('"').to_string())
    };
    Some(TriggerLine {
        connector: field("connector")?,
        trigger_total: field("trigger_total")?.parse().ok()?,
        processed_conversations: field("processed_conversations")?.parse().ok()?,
        sink_in_flight_high_water: field("sink_in_flight_high_water")?.parse().ok()?,
        committed_inputs: field("committed_inputs")?.parse().ok()?,
    })
}

#[derive(Debug, Clone)]
struct TriggerLine {
    connector: String,
    trigger_total: usize,
    processed_conversations: usize,
    sink_in_flight_high_water: usize,
    committed_inputs: usize,
}

/// Every fingerprint line whose locator ends with `suffix`.
fn fingerprint_lines_ending(lines: &[String], suffix: &str) -> Vec<String> {
    lines
        .iter()
        .filter(|line| line.contains("locator=") && line.contains(suffix))
        .cloned()
        .collect()
}

fn namespaces_in(lines: &[String]) -> std::collections::BTreeSet<String> {
    lines
        .iter()
        .filter_map(|line| {
            line.split_whitespace()
                .find_map(|field| field.strip_prefix("namespace=").map(str::to_string))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// How many per-file progress rows exist for a file name, at any root.
///
/// Matched on the file name alone on purpose: the point of the callers is that
/// *no* root recorded this file as seen, and a lookup keyed on a root id this
/// test would have to guess could pass by matching nothing at all.
fn file_state_rows(db: &rusqlite::Connection, file_name: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM scan_file_state WHERE relative_path LIKE '%' || ?1",
        [file_name],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("reading scan_file_state: {error}"))
}

const CLAUDE_PHRASE: &str = "synthetic resident claude landing phrase";
const CODEX_PHRASE: &str = "synthetic resident codex landing phrase";
const REPAIRED_PHRASE: &str = "synthetic resident repaired landing phrase";

// ---------------------------------------------------------------------------
// R1: the event cycle lands both sources, and the startup scan did not
// ---------------------------------------------------------------------------

#[test]
fn r1_the_resident_event_cycle_lands_source_facts_for_both_sources() {
    let fixture = Fixture::new();
    fixture.create_home_roots();

    let mut resident = Resident::start(&fixture, &[], true);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );

    // The startup scan has already run at this point, against roots that hold
    // nothing. A run that landed data here would have proved nothing about the
    // event cycle.
    {
        let db = resident.poll_until(
            "the database to exist after the startup scan",
            Duration::from_secs(60),
            || fixture.try_open_db(),
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM source_inputs"),
            0,
            "the startup scan over empty roots lands no source fact"
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM conversations"),
            0,
            "and no legacy conversation either"
        );
    }

    // Only now are both sources created. Everything that lands from here on is
    // the event cycle's doing.
    fixture.write_claude_session(
        "r1/session.jsonl",
        &claude_session("sess-r1-claude", "a resident question", CLAUDE_PHRASE),
    );
    fixture.write_codex_session(
        "2026/01/rollout-r1.jsonl",
        &codex_session("sess-r1-codex", "another resident question", CODEX_PHRASE),
    );

    let landed = resident.poll_until(
        "both source inputs to complete through the event cycle",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            let complete = count(
                &db,
                "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
            );
            (complete >= 2
                && count_like(&db, CLAUDE_PHRASE) > 0
                && count_like(&db, CODEX_PHRASE) > 0)
                .then_some(complete)
        },
    );
    assert_eq!(landed, 2, "exactly the two created inputs completed");

    resident.stop();

    // Re-open the database from a fresh handle and re-read every terminal fact.
    let db = fixture.open_db();
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'"
        ),
        2,
        "both file events landed a completed source input"
    );
    assert!(
        count(&db, "SELECT COUNT(*) FROM source_records") > 0,
        "the sealed read registered source records"
    );
    assert!(
        count(&db, "SELECT COUNT(*) FROM source_message_links") > 0,
        "and installed links from those records to the current messages"
    );
    assert!(
        count_like(&db, CLAUDE_PHRASE) > 0 && count_like(&db, CODEX_PHRASE) > 0,
        "both sources' text is in the canonical store"
    );
    assert!(
        !receipt_keys(&db).is_empty(),
        "the commits wrote their activation receipts"
    );
    assert!(
        resident.count(DISPATCH_MARKER) >= 2,
        "at least one commit per source really travelled through the source kernel: {}",
        resident.log()
    );

    // The lexical tail: the end-user search surface finds the new text.
    for phrase in [CLAUDE_PHRASE, CODEX_PHRASE] {
        let output = fixture.search(phrase);
        assert!(
            output.status.success(),
            "searching for {phrase:?} must succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let payload: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("search emits JSON");
        let hits = payload["hits"].as_array().map(Vec::len).unwrap_or(0);
        assert!(
            hits > 0,
            "the lexical tail serves the text the event cycle landed: {phrase:?} -> {payload}"
        );
    }
}

// ---------------------------------------------------------------------------
// R2: a repeated event reinstalls nothing; an append is a new identity
// ---------------------------------------------------------------------------

#[test]
fn r2_a_repeated_event_reinstalls_nothing_and_an_append_is_a_new_identity() {
    let fixture = Fixture::new();
    fixture.create_home_roots();

    let mut resident = Resident::start(&fixture, &[], true);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );

    let session = fixture.write_claude_session(
        "r2/session.jsonl",
        &claude_session("sess-r2", "a repeated question", CLAUDE_PHRASE),
    );
    resident.poll_until(
        "the first input to complete",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (complete_input_rows(&db, "r2/session.jsonl") >= 1).then_some(())
        },
    );

    let dispatched_before = resident.count(DISPATCH_MARKER);
    let before = {
        let db = fixture.open_db();
        let (lines, revision, receipts) = (
            source_facts_fingerprint(&db),
            source_facts_revision(&db),
            receipt_keys(&db),
        );
        (lines, revision, receipts)
    };

    // The same bytes again: a real filesystem event, a real cycle, and a replay.
    std::fs::write(
        &session,
        jsonl(&claude_session(
            "sess-r2",
            "a repeated question",
            CLAUDE_PHRASE,
        )),
    )
    .expect("rewrite the same bytes");

    let dispatched_after = resident.poll_until(
        "the repeated event to travel through the source kernel",
        Duration::from_secs(240),
        || resident.wait_for_more(DISPATCH_MARKER, dispatched_before, Duration::from_secs(1)),
    );
    assert!(
        dispatched_after > dispatched_before,
        "the repeated event reached the kernel: {}",
        resident.log()
    );

    // Give the cycle room to finish its own bookkeeping, then compare.
    let stable = resident.poll_until(
        "the replay to leave the revision alone",
        Duration::from_secs(60),
        || {
            let db = fixture.try_open_db()?;
            (source_facts_revision(&db) == before.1).then_some(())
        },
    );
    let _ = stable;

    let db = fixture.open_db();
    assert_eq!(
        source_facts_fingerprint(&db),
        before.0,
        "a repeated event installs nothing and changes no source revision"
    );
    assert_eq!(
        source_facts_revision(&db),
        before.1,
        "the revision index did not move on a replay"
    );
    assert_eq!(
        receipt_keys(&db),
        before.2,
        "no receipt was rewritten or fabricated by the repeated event"
    );

    // An append changes the bytes: that is a new identity for the same locator.
    let dispatched_before_append = resident.count(DISPATCH_MARKER);
    let mut grown = claude_session("sess-r2", "a repeated question", CLAUDE_PHRASE);
    grown.push(serde_json::json!({
        "parentUuid": "sess-r2-assistant",
        "cwd": "/synthetic/project",
        "sessionId": "sess-r2",
        "version": "2.0.37",
        "type": "user",
        "message": {"role": "user", "content": "an appended question"},
        "uuid": "sess-r2-user-2",
        "timestamp": "2026-01-01T00:00:02.000Z"
    }));
    std::fs::write(&session, jsonl(&grown)).expect("append to the session");

    resident.poll_until(
        "the appended bytes to be read as a second input",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            let rows = input_rows(&db, "r2/session.jsonl");
            let dispatched = resident.count(DISPATCH_MARKER) > dispatched_before_append;
            (rows >= 2 && dispatched).then_some(())
        },
    );

    let db = fixture.open_db();
    let keys = input_keys_for(&db, "r2/session.jsonl");
    assert_eq!(
        keys.len(),
        2,
        "the appended content is a new identity beside the original: {keys:#?}"
    );
    assert_ne!(
        keys[0], keys[1],
        "the two identities are distinct input keys"
    );
    assert_eq!(
        complete_input_rows(&db, "r2/session.jsonl"),
        2,
        "both the original and the appended read completed"
    );

    resident.stop();
}

// ---------------------------------------------------------------------------
// R3: a bad input does not move its own root's progress, and other kinds land
// ---------------------------------------------------------------------------

#[test]
fn r3_a_bad_root_does_not_move_its_own_progress_and_other_kinds_still_land() {
    let fixture = Fixture::new();
    fixture.create_home_roots();
    // The declared root is a Claude project directory, so the root itself has
    // layout evidence and the bad file below reaches Claude parsing.
    let archive = fixture.path().join("archive-claude/.claude/projects");
    std::fs::create_dir_all(&archive).expect("mkdir the configured root");
    // The same kind as the HOME root, declared a second time under its own
    // origin host: one kind, two roots.
    fixture.write_configured_source("archive-claude", "archive-claude", &archive);

    let mut resident = Resident::start(&fixture, &[], true);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );

    // The good root of this kind first, so its own progress is written before
    // anything fails.
    fixture.write_claude_session(
        "r3/good.jsonl",
        &claude_session("sess-r3-good", "a good question", CLAUDE_PHRASE),
    );
    resident.poll_until(
        "the good input to complete",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (input_state_for(&db, "r3/good.jsonl").as_deref() == Some("complete")).then_some(())
        },
    );
    let good_lines = {
        let db = fixture.open_db();
        fingerprint_lines_ending(&source_facts_fingerprint(&db), "locator=r3/good.jsonl")
    };
    assert!(
        !good_lines.is_empty(),
        "the good root produced an identity for its file"
    );

    // The bad root: one line the framing scan cannot parse at all, so the
    // input can only be published unfinished.
    let bad = archive.join("r3-bad.jsonl");
    std::fs::write(
        &bad,
        format!(
            "{}not a json record\n",
            jsonl(&claude_session(
                "sess-r3-bad",
                "a bad question",
                "a bad answer"
            ))
        ),
    )
    .expect("write the faulty file");

    resident.poll_until(
        "the faulty input to be read and refused completion",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            let read = input_rows(&db, "r3-bad.jsonl");
            (read >= 1 && input_state_for(&db, "r3-bad.jsonl").as_deref() != Some("complete"))
                .then_some(())
        },
    );

    // An independent kind, created after the failure, must still land.
    fixture.write_codex_session(
        "2026/01/rollout-r3.jsonl",
        &codex_session("sess-r3-codex", "an independent question", CODEX_PHRASE),
    );
    resident.poll_until(
        "the independent kind to land after the other kind's failure",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (input_state_for(&db, "2026/01/rollout-r3.jsonl").as_deref() == Some("complete"))
                .then_some(())
        },
    );

    // Everything about the failure is checked while the run is still up: after
    // the repair below there are two inputs for the same locator, and "the
    // state of this locator" would no longer name one of them.
    {
        let db = fixture.open_db();
        assert_ne!(
            input_state_for(&db, "r3-bad.jsonl").as_deref(),
            Some("complete"),
            "the faulty input is never recorded as complete"
        );
        assert!(
            file_state_rows(&db, "r3-bad.jsonl") == 0,
            "the faulty file advanced no per-file progress at its own root"
        );
        assert_eq!(
            fingerprint_lines_ending(&source_facts_fingerprint(&db), "locator=r3/good.jsonl"),
            good_lines,
            "the failing root did not disturb the other root of the same kind"
        );
        assert_eq!(
            input_state_for(&db, "2026/01/rollout-r3.jsonl").as_deref(),
            Some("complete"),
            "an independent kind completes while the other kind's root is held back"
        );
        assert!(
            count_like(&db, CODEX_PHRASE) > 0,
            "and its text reached the canonical store"
        );
    }

    // The repair: the faulty path now carries a well-formed session, so the
    // next real event for it is a new identity that can complete. The held
    // back root is what makes this recovery meaningful -- its progress never
    // moved past the file, so a fresh read of it is what the cycle does.
    std::fs::write(
        &bad,
        jsonl(&claude_session(
            "sess-r3-repaired",
            "a repaired question",
            REPAIRED_PHRASE,
        )),
    )
    .expect("repair the faulty file");

    resident.poll_until(
        "the repaired file to complete on a new event",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (complete_input_rows(&db, "r3-bad.jsonl") >= 1).then_some(())
        },
    );
    // The commit's row is visible before the trigger writes the root's
    // progress, so that write is waited for here rather than raced.
    resident.poll_until(
        "the repaired file's progress to land at its root",
        Duration::from_secs(120),
        || {
            let db = fixture.try_open_db()?;
            (file_state_rows(&db, "r3-bad.jsonl") > 0).then_some(())
        },
    );

    resident.stop();

    let db = fixture.open_db();
    assert_eq!(
        complete_input_rows(&db, "r3-bad.jsonl"),
        1,
        "the repaired content completes as its own identity"
    );
    assert_eq!(
        input_keys_for(&db, "r3-bad.jsonl").len(),
        2,
        "the repair is a second identity beside the unfinished one, not a rewrite of it"
    );
    assert!(
        file_state_rows(&db, "r3-bad.jsonl") > 0,
        "and only now does the file's progress at its root advance; the run's own log follows:\n{}",
        resident.log()
    );
}

// ---------------------------------------------------------------------------
// R4: a tampered fixed copy fails the cycle and moves no progress
// ---------------------------------------------------------------------------

#[test]
fn r4_a_broken_fixed_copy_fails_the_cycle_and_moves_no_progress() {
    let fixture = Fixture::new();
    fixture.create_home_roots();

    let mut resident = Resident::start(&fixture, &[], true);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );

    fixture.write_claude_session(
        "r4/first.jsonl",
        &claude_session("sess-r4-first", "the first question", CLAUDE_PHRASE),
    );
    resident.poll_until(
        "the first input to complete",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (input_state_for(&db, "r4/first.jsonl").as_deref() == Some("complete")).then_some(())
        },
    );
    let before = {
        let db = fixture.open_db();
        source_facts_fingerprint(&db)
    };

    // A causal barrier, not a sleep and not a longer timeout: the clean
    // cycle's last act for this kind is publishing its watermark, so waiting
    // for that watermark to appear means the cycle that read the first file
    // has finished. Snapshotting before it lands is what made an earlier
    // version of this case fail against a run that had done nothing wrong --
    // the "after" read then saw the *previous* cycle's legitimate write.
    let watch_watermark_before = resident.poll_until(
        "the clean cycle to publish its watch watermark",
        Duration::from_secs(120),
        || watch_watermark_for(&fixture, "cd"),
    );

    // The copy this process started with is no longer on disk.
    fixture.break_fixed_copy();

    let secret = "synthetic resident secret that must never be logged";
    fixture.write_claude_session(
        "r4/r4-second.jsonl",
        &claude_session("sess-r4-second", "the second question", secret),
    );

    assert!(
        resident.wait_for(SAFETY_COPY_STALE_MARKER, Duration::from_secs(240)),
        "the cycle names the tampered copy instead of reading through something else: {}",
        resident.log()
    );

    resident.stop();

    let db = fixture.open_db();
    assert_eq!(
        input_rows(&db, "r4/r4-second.jsonl"),
        0,
        "a cycle under a tampered copy puts no source fact in place"
    );
    assert!(
        file_state_rows(&db, "r4-second.jsonl") == 0,
        "and it does not advance the file's progress at its root"
    );
    assert_eq!(
        count_like(&db, secret),
        0,
        "and nothing from the unread file reached the canonical store"
    );
    assert_eq!(
        fingerprint_lines_ending(&source_facts_fingerprint(&db), "locator=r4/first.jsonl"),
        fingerprint_lines_ending(&before, "locator=r4/first.jsonl"),
        "the facts the earlier clean cycle landed are exactly as they were"
    );
    // The watermark is compared by value, not by whole file: the earlier
    // clean cycle's own write is legitimate and must not be mistaken for
    // progress made by the refusal.
    assert_eq!(
        watch_watermark_for(&fixture, "cd"),
        Some(watch_watermark_before),
        "and the refused cycle advanced no watch watermark past the file it would not read"
    );
    let log = resident.log();
    assert!(
        !log.contains(secret),
        "the run's own log carries no content from the file it refused to read"
    );
}

// ---------------------------------------------------------------------------
// R5: overlapping declarations keep both identities, driven by real events
// ---------------------------------------------------------------------------

#[test]
fn r5_a_home_root_and_a_configured_declaration_write_through_both() {
    let fixture = Fixture::new();
    fixture.create_home_roots();
    // The very directory the Codex HOME root resolves to, declared again as a
    // named source with its own origin host and a non-default namespace.
    let sessions = fixture.home().join(".codex/sessions");
    fixture.write_configured_source("archive-a", "archive-a", &sessions);

    let mut resident = Resident::start(&fixture, &[], true);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );

    fixture.write_codex_session(
        "2026/01/rollout-r5.jsonl",
        &codex_session("sess-r5", "the shared question", CODEX_PHRASE),
    );

    let lines = resident.poll_until(
        "the file to be read through both declarations",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            let lines = fingerprint_lines_ending(
                &source_facts_fingerprint(&db),
                "locator=2026/01/rollout-r5.jsonl",
            );
            (!lines.is_empty() && namespaces_in(&lines).len() >= 2).then_some(lines)
        },
    );
    let namespaces = namespaces_in(&lines);
    assert!(
        namespaces.contains("local") && namespaces.contains("archive-a"),
        "an event under a path covered by two declarations is read through both, keeping the \
         event path out of it: {lines:#?}"
    );

    resident.stop();

    let db = fixture.open_db();
    let settled = fingerprint_lines_ending(
        &source_facts_fingerprint(&db),
        "locator=2026/01/rollout-r5.jsonl",
    );
    assert_eq!(
        settled.len(),
        lines.len(),
        "the settled facts hold one identity per declaration and no more: {settled:#?}"
    );
    assert!(
        settled.iter().all(|line| line.contains("state=complete")),
        "every declaration's identity completed: {settled:#?}"
    );
}

// ---------------------------------------------------------------------------
// R6: without the flag the resident loop lands source facts
// ---------------------------------------------------------------------------

/// Task 19: without an explicit copy the resident loop now prepares the
/// default fixed configuration, so the real event still has to land a complete
/// source fact -- the event wait and the body evidence are unchanged.
#[test]
fn r6_without_the_flag_the_resident_loop_lands_source_facts() {
    let fixture = Fixture::new();
    fixture.create_home_roots();

    let mut resident = Resident::start(&fixture, &[], false);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );

    fixture.write_claude_session(
        "r6/session.jsonl",
        &claude_session("sess-r6", "a default resident question", CLAUDE_PHRASE),
    );

    resident.poll_until(
        "the un-flagged resident cycle to complete the source input",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (complete_input_rows(&db, "r6/session.jsonl") >= 1).then_some(())
        },
    );

    resident.stop();

    let db = fixture.open_db();
    assert_eq!(
        complete_input_rows(&db, "r6/session.jsonl"),
        1,
        "a run without the flag writes a complete source fact"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_inputs si
             JOIN operation_commit_receipt r ON r.idempotency_key = si.receipt_key
             WHERE si.state = 'complete'
               AND r.operation = 'source_input_activation_v1'
               AND r.state = 'committed'"
        ),
        1,
        "the complete input has its committed receipt"
    );
    assert!(
        resident.count(DISPATCH_MARKER) > 0,
        "the event cycle took the source-aware commit: {}",
        resident.log()
    );
    assert!(
        count_like(&db, CLAUDE_PHRASE) > 0,
        "the canonical body still lands"
    );
}

// ---------------------------------------------------------------------------
// R7: a legal empty input completes, and invents nothing
// ---------------------------------------------------------------------------

#[test]
fn r7_an_empty_file_completes_without_inventing_a_conversation() {
    let fixture = Fixture::new();
    fixture.create_home_roots();

    let mut resident = Resident::start(&fixture, &[], true);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );

    // An empty file is a legal input that reaches EOF with zero records. It is
    // not a refusal, and it must not become a conversation nobody wrote.
    //
    // Written directly rather than through the fixture's session writer, which
    // terminates every line and so would produce a one-byte file: the input
    // under test is the zero-byte one.
    let empty = fixture.home().join(".claude/projects/r7/empty.jsonl");
    std::fs::create_dir_all(empty.parent().expect("session parent")).expect("mkdir session dir");
    std::fs::write(&empty, "").expect("write the empty session");
    assert_eq!(
        std::fs::metadata(&empty)
            .expect("stat the empty session")
            .len(),
        0,
        "the fixture wrote an empty file"
    );

    resident.poll_until(
        "the empty file's input to complete",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (input_state_for(&db, "r7/empty.jsonl").as_deref() == Some("complete")).then_some(())
        },
    );

    resident.stop();

    let db = fixture.open_db();
    assert_eq!(
        complete_input_rows(&db, "r7/empty.jsonl"),
        1,
        "the empty file registered one completed input"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM source_records"),
        0,
        "an empty file has no records"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM conversations"),
        0,
        "an empty file invents no conversation"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM operation_commit_receipt
             WHERE operation = 'source_input_activation_v1' AND state = 'committed'"
        ),
        1,
        "the zero-record activation still writes its receipt"
    );
}

// ---------------------------------------------------------------------------
// R8: one cycle, two kinds -- the failing kind's watermark stays, the other's moves
// ---------------------------------------------------------------------------

/// The per-kind watermark must answer for its own kind. The cycle-wide failure
/// flag exists so the run's *global* counters are not written as a success; it
/// has no business freezing an unrelated kind's watermark for the same cycle.
///
/// Both files are created back to back so the two events coalesce into one
/// debounce window, and the run's own `trigger_total` is what proves they
/// really were handled together -- otherwise this case would pass on a run
/// that had simply split them into two cycles, where the old behaviour also
/// happens to look right.
#[test]
fn r8_one_cycle_keeps_the_failing_kinds_watermark_and_moves_the_other() {
    let fixture = Fixture::new();
    fixture.create_home_roots();

    let mut resident = Resident::start(&fixture, &[], true);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );

    // A faulty Claude input and a perfectly good Codex one, written with no
    // gap between them.
    let bad = fixture.write_claude_session(
        "r8/bad.jsonl",
        &claude_session("sess-r8-bad", "a bad question", "a bad answer"),
    );
    let mut raw = std::fs::read_to_string(&bad).expect("read the session");
    raw.push_str("not a json record\n");
    std::fs::write(&bad, raw).expect("append the unparseable line");

    fixture.write_codex_session(
        "2026/01/rollout-r8.jsonl",
        &codex_session("sess-r8-good", "a good question", CODEX_PHRASE),
    );

    resident.poll_until(
        "the independent kind to land",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (input_state_for(&db, "2026/01/rollout-r8.jsonl").as_deref() == Some("complete"))
                .then_some(())
        },
    );

    let triggers = resident.poll_until(
        "both kinds' triggers to report for one cycle",
        Duration::from_secs(120),
        || {
            let lines = trigger_lines(&resident);
            let claude = lines.iter().any(|line| line.connector == "claude");
            let codex = lines.iter().any(|line| line.connector == "codex");
            (claude && codex).then_some(lines)
        },
    );
    let claude_trigger = triggers
        .iter()
        .find(|line| line.connector == "claude")
        .expect("the claude trigger");
    let codex_trigger = triggers
        .iter()
        .find(|line| line.connector == "codex")
        .expect("the codex trigger");
    assert_eq!(
        claude_trigger.trigger_total, 2,
        "the two kinds must be handled by ONE cycle of two triggers, or this case proves \
         nothing about per-kind isolation: {triggers:#?}"
    );
    assert_eq!(
        codex_trigger.trigger_total, 2,
        "and the same cycle carries both: {triggers:#?}"
    );

    // A second causal barrier, for the same reason `r4` needs one: the
    // independent kind's input is visible in the database before that trigger
    // has published its watermark, and the assertion below is about the
    // watermark. Triggers of one cycle run in slug order, so `claude` has
    // finished by the time `codex` has published -- whichever cycle each of
    // them ran in.
    resident.poll_until(
        "the independent kind to publish its watch watermark",
        Duration::from_secs(120),
        || watch_watermark_for(&fixture, "cx"),
    );

    resident.stop();

    let db = fixture.open_db();
    assert_ne!(
        input_state_for(&db, "r8/bad.jsonl").as_deref(),
        Some("complete"),
        "the faulty input is not complete"
    );
    assert_eq!(
        input_state_for(&db, "2026/01/rollout-r8.jsonl").as_deref(),
        Some("complete"),
        "the independent kind's input completed in that same cycle"
    );
    assert!(
        watch_watermark_for(&fixture, "cx").is_some(),
        "the independent kind's watch watermark moved, even though another kind failed in the \
         same cycle; run log:\n{}",
        resident.log()
    );
    assert_eq!(
        watch_watermark_for(&fixture, "cd"),
        None,
        "while the failing kind's own watermark stayed where it was"
    );
}

// ---------------------------------------------------------------------------
// R9: the cycle's real result reaches the call chain
// ---------------------------------------------------------------------------

/// A source-only cycle must report what it indexed. The value the cycle returns
/// is the same one the semantic catch-up gate tests and the one the stale
/// detector records, so a source cycle that always returned zero would leave
/// both of them blind -- the catch-up would never run for source-ingested
/// messages and the detector would count every such cycle as an empty one.
///
/// The stale detector's own line is the terminal observation: it is emitted
/// only for a non-zero result, at debug level, with the number.
#[test]
fn r9_a_source_cycle_reports_what_it_indexed_to_the_call_chain() {
    let fixture = Fixture::new();
    fixture.create_home_roots();

    let mut resident = Resident::start(&fixture, &[], true);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );

    let session = fixture.write_claude_session(
        "r9/session.jsonl",
        &claude_session("sess-r9", "a counted question", CLAUDE_PHRASE),
    );
    resident.poll_until("the input to complete", Duration::from_secs(240), || {
        let db = fixture.try_open_db()?;
        (input_state_for(&db, "r9/session.jsonl").as_deref() == Some("complete")).then_some(())
    });
    assert!(
        resident.wait_for(
            "stale_detector: successful ingest recorded",
            Duration::from_secs(60)
        ),
        "the cycle's real result must reach the stale detector, which records nothing but an \
         empty scan for zero; run log:\n{}",
        resident.log()
    );
    let reported = trigger_lines(&resident)
        .iter()
        .map(|line| line.processed_conversations)
        .max()
        .unwrap_or(0);
    assert!(
        reported >= 1,
        "the trigger reports the conversations it processed: {:#?}",
        trigger_lines(&resident)
    );

    // An append is a second source cycle, and it must count too: it extends an
    // existing conversation rather than creating one, which is exactly the case
    // a "rows created" count would report as zero.
    let mut grown = claude_session("sess-r9", "a counted question", CLAUDE_PHRASE);
    grown.push(serde_json::json!({
        "parentUuid": "sess-r9-assistant",
        "cwd": "/synthetic/project",
        "sessionId": "sess-r9",
        "version": "2.0.37",
        "type": "user",
        "message": {"role": "user", "content": "an appended counted question"},
        "uuid": "sess-r9-user-2",
        "timestamp": "2026-01-01T00:00:02.000Z"
    }));
    std::fs::write(&session, jsonl(&grown)).expect("append to the session");

    resident.poll_until(
        "the appended input to complete",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (complete_input_rows(&db, "r9/session.jsonl") >= 2).then_some(())
        },
    );
    resident.poll_until(
        "the appended cycle's result to reach the call chain too",
        Duration::from_secs(120),
        || {
            let reported = trigger_lines(&resident)
                .iter()
                .filter(|line| line.connector == "claude")
                .map(|line| line.processed_conversations)
                .filter(|count| *count > 0)
                .count();
            (reported >= 2).then_some(())
        },
    );

    resident.stop();
}

// ---------------------------------------------------------------------------
// R10: one root's backlog is committed input by input, not buffered whole
// ---------------------------------------------------------------------------

/// The root's sealed inputs are committed as the read hands them over, so the
/// trigger holds one input's text at a time. A design that collected the whole
/// enumeration first would show the backlog in the in-flight high-water mark,
/// which is why the trigger reports it.
#[test]
fn r10_a_root_with_several_inputs_never_holds_the_whole_backlog() {
    let fixture = Fixture::new();
    fixture.create_home_roots();

    let mut resident = Resident::start(&fixture, &[], true);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );

    // Several sessions under one declared root, all written before a single
    // debounce window closes, so one cycle reads the root's whole backlog.
    for index in 0..4 {
        fixture.write_claude_session(
            &format!("r10/session-{index}.jsonl"),
            &claude_session(
                &format!("sess-r10-{index}"),
                &format!("the question {index}"),
                &format!("the answer {index} {}", CLAUDE_PHRASE),
            ),
        );
    }

    resident.poll_until(
        "all four inputs to complete",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (0..4)
                .all(|index| {
                    input_state_for(&db, &format!("r10/session-{index}.jsonl")).as_deref()
                        == Some("complete")
                })
                .then_some(())
        },
    );

    // The trigger's own line is written after its last commit, so its absence
    // is waited out rather than raced: the database rows are visible first.
    let claude = resident.poll_until(
        "the trigger that carried all four inputs to report",
        Duration::from_secs(120),
        || {
            trigger_lines(&resident)
                .into_iter()
                .find(|line| line.connector == "claude" && line.committed_inputs >= 4)
        },
    );
    assert_eq!(
        claude.sink_in_flight_high_water, 1,
        "a root's backlog is committed one input at a time, so the trigger never held more \
         than the input being written: {claude:#?}"
    );

    resident.stop();
}
