//! Task19: the public ingestion modes consume one run-owned fixed safety
//! configuration by default.
//!
//! Every case drives the real `cass` binary over a private synthetic HOME, a
//! private data directory and a private configuration tier, and then reads the
//! resulting SQLite database directly. The seam is the CLI, the process
//! boundary and the database.
//!
//! The nine cases are the fixed roster of `task-19-test-contract.md`. The
//! legacy pre-state for the no-ingest cases comes from
//! `util/source_legacy_seed.rs` through an explicit `#[path]` module, so this
//! target holds exactly nine tests and does not pull in the shared `util`
//! module's 57 tests.
//!
//! The fixtures are synthetic and neutral. No real session, path or secret
//! appears in this file.

#[path = "util/source_legacy_seed.rs"]
mod source_legacy_seed;

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use coding_agent_search::indexer::scan_root_meta;
use coding_agent_search::storage::source_facts::decode_expected_manifest_header;
use rusqlite::OptionalExtension as _;
use sha2::{Digest as _, Sha256};

/// The line `watch_sources` writes once the watcher is registered and the loop
/// is about to start.
const WATCH_READY_MARKER: &str = "watch mode: minimum interval between scan cycles";

/// The explicit failure a tampered fixed copy produces.
const SAFETY_COPY_STALE_MARKER: &str = "the fixed safety copy no longer matches";

/// The embedding model the frozen API profile names.
const NO_INGEST_MODEL: &str = "C49-no-ingest-model";

/// The model revision the frozen API profile names.
const NO_INGEST_MODEL_REVISION: &str = "source-no-ingest-fixture-v1";

/// The closed retired-model-selection environment list. Cleared from every
/// child so a stray operator variable cannot change a fixture run.
const RETIRED_ENV: [&str; 7] = [
    "CASS_INFINITY_URL",
    "CASS_INFINITY_EMBED_MODEL",
    "CASS_INFINITY_RERANK_MODEL",
    "CASS_QWEN_RERANK_URL",
    "CASS_SEMANTIC_EMBEDDER",
    "CASS_SEMANTIC_DOWNLOAD_POLICY",
    "CASS_SEMANTIC_MAX_MODEL_SIZE_MB",
];

/// The automatic fixed configuration's identity domain.
const AUTO_IDENTITY_PREFIX: &str = "cass.source-config/1:sha256:";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home")).expect("mkdir home");
        std::fs::create_dir_all(root.path().join("data")).expect("mkdir data");
        std::fs::create_dir_all(root.path().join("config")).expect("mkdir config");
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

    /// The frozen API profile this file's no-ingest case points at.
    fn write_model_api_config(&self, endpoint: &str) -> PathBuf {
        let path = self.root.path().join("model-api.toml");
        let body = format!(
            "version = 1\n\
             default_embedding = \"local\"\n\
             \n\
             [profiles.local]\n\
             kind = \"embedding\"\n\
             protocol = \"openai-embeddings-v1\"\n\
             endpoint = \"{endpoint}\"\n\
             scope = \"loopback\"\n\
             model = \"{NO_INGEST_MODEL}\"\n\
             model_revision = \"{NO_INGEST_MODEL_REVISION}\"\n\
             normalization = \"l2\"\n\
             max_batch = 64\n"
        );
        std::fs::write(&path, body).expect("write the model API configuration");
        path
    }

    /// The live rule file the default preparation discovers.
    fn live_config(&self) -> PathBuf {
        self.config_home()
            .join("cass")
            .join("excluded_context_paths.toml")
    }

    fn corrupt_live_config(&self) {
        let path = self.live_config();
        std::fs::create_dir_all(path.parent().expect("config parent")).expect("mkdir config");
        std::fs::write(&path, "this is not toml [[[\n").expect("corrupt live config");
    }

    /// `data_dir/source-configs/v1`, where the automatic copies live.
    fn auto_config_dir(&self) -> PathBuf {
        self.data_dir().join("source-configs").join("v1")
    }

    fn auto_config_files(&self) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(self.auto_config_dir()) else {
            return Vec::new();
        };
        let mut files: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        files.sort();
        files
    }

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

    /// Point every source-discovery environment at this fixture, so an
    /// inherited value on the host cannot make a fixture process scan real
    /// history.
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
            // The resident event cycle applies the active-source filter, whose
            // recent-write window defers a just-written log. The window is
            // production behaviour; these cases need a file created after the
            // loop is ready to be read by the next event cycle.
            .env("CASS_ACTIVE_SESSION_RECENT_WRITE_WINDOW_SECS", "0")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("CASS_TEST_WATCH_PATHS")
            .env_remove("CASS_SRC05B07_FAIL_AT")
            .env_remove("CASS_API_CONFIG")
            .env_remove("RUST_LOG");
        for variable in RETIRED_ENV {
            cmd.env_remove(variable);
        }
        cmd
    }

    fn index(&self, extra: &[&str], envs: &[(&str, &str)]) -> Output {
        self.index_with(extra, envs, false)
    }

    fn index_verbose(&self, extra: &[&str], envs: &[(&str, &str)]) -> Output {
        self.index_with(extra, envs, true)
    }

    fn index_with(&self, extra: &[&str], envs: &[(&str, &str)], verbose: bool) -> Output {
        let mut cmd = Command::new(cass_bin());
        for (key, value) in envs {
            cmd.env(key, value);
        }
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"]).arg(self.data_dir());
        cmd.args(extra).arg("--json");
        if verbose {
            cmd.arg("--verbose");
        }
        cmd.output().expect("spawn cass index")
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

struct Resident {
    child: Child,
    log: Arc<Mutex<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Resident {
    fn start(fixture: &Fixture, explicit_copy: Option<&Path>) -> Self {
        let mut cmd = Command::new(cass_bin());
        fixture.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"]).arg(fixture.data_dir());
        if let Some(copy) = explicit_copy {
            cmd.arg("--source-safety-config").arg(copy);
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

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn log(&self) -> String {
        self.log.lock().expect("log lock").clone()
    }

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

    fn count(&self, needle: &str) -> usize {
        self.log().matches(needle).count()
    }

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

fn complete_inputs(db: &rusqlite::Connection) -> i64 {
    count(db, "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'")
}

/// Complete inputs whose own `receipt_key` names a committed activation
/// receipt -- the contract's per-input receipt check, not a whole-table count.
fn inputs_with_committed_receipt(db: &rusqlite::Connection) -> i64 {
    count(
        db,
        "SELECT COUNT(*) FROM source_inputs si
         JOIN operation_commit_receipt r ON r.idempotency_key = si.receipt_key
         WHERE si.state = 'complete'
           AND r.operation = 'source_input_activation_v1'
           AND r.state = 'committed'",
    )
}

fn input_rows_for(db: &rusqlite::Connection, locator: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM source_inputs WHERE relative_locator_bin = ?1",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("counting inputs for {locator}: {error}"))
}

fn complete_rows_for(db: &rusqlite::Connection, locator: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM source_inputs
         WHERE relative_locator_bin = ?1 AND state = 'complete'",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("counting complete inputs for {locator}: {error}"))
}

fn file_state_rows(db: &rusqlite::Connection, file_name: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM scan_file_state WHERE relative_path LIKE '%' || ?1",
        [file_name],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("reading scan_file_state: {error}"))
}

fn receipt_keys(db: &rusqlite::Connection) -> String {
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

/// Every `(root_id, connector, last_scan_ts)` row, ordered by its stable key.
///
/// Values, not just row counts: a rewrite of the same rows must fail this.
fn watermark_rows(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT root_id || '|' || connector || '|' || last_scan_ts
             FROM scan_watermarks ORDER BY root_id, connector",
        )
        .expect("prepare the watermark rows");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query the watermark rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the watermark rows")
}

/// Every per-file progress row, ordered by its stable key.
fn file_progress_rows(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT root_id || '|' || connector || '|' || relative_path || '|' || size || '|' || mtime
             FROM scan_file_state ORDER BY root_id, connector, relative_path",
        )
        .expect("prepare the file progress rows");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query the file progress rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the file progress rows")
}

/// Every canonical message as `id|content`, ordered by id.
fn canonical_bodies(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare("SELECT id || '|' || COALESCE(content, '') FROM messages ORDER BY id")
        .expect("prepare the canonical bodies");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query the canonical bodies")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the canonical bodies")
}

/// The safety identities carried by every stored expected-manifest header.
fn manifest_safety(db: &rusqlite::Connection) -> Vec<(String, String)> {
    let mut stmt = db
        .prepare("SELECT expected_manifest_bin FROM source_inputs ORDER BY id")
        .expect("prepare the manifest query");
    let rows: Vec<Vec<u8>> = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query the manifests")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the manifests");
    rows.into_iter()
        .map(|bytes| {
            let (_manifest, safety) =
                decode_expected_manifest_header(&bytes).expect("decode the manifest header");
            (
                safety.config_source_identity().to_string(),
                safety.fixed_config_sha256().hex(),
            )
        })
        .collect()
}

/// Every source fact this database holds, as comparable lines.
fn facts_fingerprint(db: &rusqlite::Connection) -> Vec<String> {
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

fn watch_watermark_for(fixture: &Fixture, kind_key: &str) -> Option<i64> {
    let raw = std::fs::read_to_string(fixture.data_dir().join("watch_state.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    value["m"][kind_key].as_i64()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// ---------------------------------------------------------------------------
// A loopback model service that answers every request with HTTP 500
// ---------------------------------------------------------------------------

/// A loopback service that records the legal model POSTs it sees and answers
/// every one of them with HTTP 500.
///
/// It owns one thread over a non-blocking listener. `Drop` sets the stop flag,
/// wakes a pending accept with one throwaway connection and joins the thread;
/// that wake connection carries no HTTP request and is never counted.
struct FaultModelServer {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<serde_json::Value>>>,
    answered_500: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FaultModelServer {
    fn start() -> Self {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind the fault server");
        let addr = listener.local_addr().expect("fault server address");
        listener
            .set_nonblocking(true)
            .expect("fault server nonblocking");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let answered = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let seen_thread = Arc::clone(&seen);
        let answered_thread = Arc::clone(&answered);
        let stop_thread = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let Some((method, path, body)) =
                            read_model_request(stream.try_clone().expect("clone the request"))
                        else {
                            continue;
                        };
                        if is_legal_model_post(&method, &path, &body) {
                            seen_thread.lock().expect("fault server lock").push(body);
                            // Count only an answer the transport actually
                            // completed: a failed write is not a 500 response.
                            if write_internal_error(stream).is_ok() {
                                answered_thread.fetch_add(1, Ordering::SeqCst);
                            }
                        } else {
                            let _ = write_not_found(stream);
                        }
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            seen,
            answered_500: answered,
            stop,
            handle: Some(handle),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}/embeddings", self.addr)
    }

    fn requests(&self) -> Vec<serde_json::Value> {
        self.seen.lock().expect("fault server lock").clone()
    }

    fn answered_500(&self) -> usize {
        self.answered_500.load(Ordering::SeqCst)
    }
}

impl Drop for FaultModelServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake a pending accept; the thread exits on the next flag check.
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Read one complete HTTP request line, headers and `Content-Length` body.
fn read_model_request(mut stream: TcpStream) -> Option<(String, String, serde_json::Value)> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        let Some(header_end) = find_header_end(&buffer) else {
            continue;
        };
        let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        let body_start = header_end + 4;
        while buffer.len() < body_start + content_length {
            let read = stream.read(&mut chunk).ok()?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let mut lines = headers.lines();
        let request_line = lines.next().unwrap_or_default().to_string();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();
        let body_end = body_start + content_length;
        let body = serde_json::from_slice(buffer.get(body_start..body_end).unwrap_or_default())
            .unwrap_or(serde_json::Value::Null);
        return Some((method, path, body));
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Only a POST of the configured model with a non-empty string input counts as
/// a real business request; anything else is answered but not recorded.
fn is_legal_model_post(method: &str, path: &str, body: &serde_json::Value) -> bool {
    method == "POST"
        && path == "/embeddings"
        && body.get("model").and_then(serde_json::Value::as_str) == Some(NO_INGEST_MODEL)
        && body
            .get("input")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|input| {
                !input.is_empty()
                    && input
                        .iter()
                        .all(|value| value.as_str().is_some_and(|text| !text.is_empty()))
            })
}

fn write_internal_error(mut stream: TcpStream) -> std::io::Result<()> {
    stream.write_all(
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn write_not_found(mut stream: TcpStream) -> std::io::Result<()> {
    stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

/// The contract's automatic-identity check: exactly one copy, named after its
/// own digest, and every input's manifest naming that same content address.
fn assert_auto_identity(fixture: &Fixture, label: &str) {
    let files = fixture.auto_config_files();
    assert_eq!(
        files.len(),
        1,
        "{label}: exactly one automatic fixed copy must exist: {files:?}"
    );
    let bytes = std::fs::read(&files[0]).expect("read the automatic copy");
    let digest = sha256_hex(&bytes);
    let name = files[0]
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("the automatic copy has a UTF-8 stem");
    assert_eq!(
        name, digest,
        "{label}: the automatic copy is named after its own digest"
    );

    let db = fixture.open_db();
    let identities = manifest_safety(&db);
    assert!(
        !identities.is_empty(),
        "{label}: the inputs carry expected-manifest headers"
    );
    let expected = format!("{AUTO_IDENTITY_PREFIX}{digest}");
    for (identity, _) in &identities {
        assert_eq!(
            identity, &expected,
            "{label}: the input's safety identity is the automatic content address"
        );
    }
}

// ---------------------------------------------------------------------------
// A1: the three public modes, without a flag
// ---------------------------------------------------------------------------

#[test]
fn default_index() {
    for streaming in [true, false] {
        let label = if streaming { "streaming" } else { "batch" };
        let fixture = Fixture::new();
        fixture.write_claude_session(
            "default-index/proj/session.jsonl",
            &claude_session(
                "sess-default-index",
                "the default index question",
                "the default index claude answer",
            ),
        );
        fixture.write_codex_session(
            "2026/01/rollout-default-index.jsonl",
            &codex_session(
                "sess-default-index-codex",
                "the default index codex question",
                "the default index codex answer",
            ),
        );

        let output = fixture.index(
            &[],
            &[("CASS_STREAMING_INDEX", if streaming { "1" } else { "0" })],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{label}: an un-flagged index run succeeds; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );

        let db = fixture.open_db();
        assert_eq!(complete_inputs(&db), 2, "{label}: both inputs completed");
        assert_eq!(
            inputs_with_committed_receipt(&db),
            2,
            "{label}: each complete input has its committed activation receipt"
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM source_records WHERE frame_state <> 'activated'"
            ),
            0,
            "{label}: every frame of a complete input is activated"
        );
        assert!(
            count_like(&db, "the default index claude answer") > 0,
            "{label}: the Claude body reached the canonical store"
        );
        assert!(
            count_like(&db, "the default index codex answer") > 0,
            "{label}: the Codex body reached the canonical store"
        );
        assert!(
            count(
                &db,
                "SELECT COUNT(*) FROM source_message_links WHERE authority = 'canonical'"
            ) > 0,
            "{label}: the inputs link to canonical messages"
        );
        drop(db);

        assert_auto_identity(&fixture, label);
    }
}

#[test]
fn default_watch_once() {
    let fixture = Fixture::new();
    let claude = fixture.write_claude_session(
        "default-watch-once/proj/session.jsonl",
        &claude_session(
            "sess-default-watch-once",
            "the default watch-once question",
            "the default watch-once claude answer",
        ),
    );
    let codex = fixture.write_codex_session(
        "2026/01/rollout-default-watch-once.jsonl",
        &codex_session(
            "sess-default-watch-once-codex",
            "the default watch-once codex question",
            "the default watch-once codex answer",
        ),
    );
    let claude_text = claude.to_str().expect("utf-8 claude path").to_string();
    let codex_text = codex.to_str().expect("utf-8 codex path").to_string();
    let args = [
        "--watch-once",
        claude_text.as_str(),
        "--watch-once",
        codex_text.as_str(),
    ];

    let first = fixture.index(&args, &[]);
    assert_eq!(
        first.status.code(),
        Some(0),
        "the un-flagged watch-once run succeeds; stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    let db = fixture.open_db();
    assert_eq!(complete_inputs(&db), 2, "both selected inputs completed");
    assert_eq!(
        inputs_with_committed_receipt(&db),
        2,
        "each input has its committed activation receipt"
    );
    assert!(count_like(&db, "the default watch-once claude answer") > 0);
    assert!(count_like(&db, "the default watch-once codex answer") > 0);
    let before = facts_fingerprint(&db);
    drop(db);

    // The same command again is a verified replay: the input keys, the
    // receipts and the source-facts revision do not move.
    let second = fixture.index(&args, &[]);
    assert_eq!(
        second.status.code(),
        Some(0),
        "the un-flagged replay succeeds; stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );
    let db = fixture.open_db();
    assert_eq!(
        facts_fingerprint(&db),
        before,
        "a replayed watch-once run adds nothing and moves no identity"
    );
    drop(db);

    assert_auto_identity(&fixture, "default_watch_once");
}

#[test]
fn default_resident() {
    let fixture = Fixture::new();
    fixture.create_home_roots();

    let mut resident = Resident::start(&fixture, None);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the un-flagged resident loop must reach its event cycle: {}",
        resident.log()
    );

    // The startup scan ran over empty roots, so nothing landed before the
    // event cycle could own the work.
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
    }

    fixture.write_claude_session(
        "default-resident/session.jsonl",
        &claude_session(
            "sess-default-resident",
            "the default resident question",
            "the default resident claude answer",
        ),
    );
    fixture.write_codex_session(
        "2026/01/rollout-default-resident.jsonl",
        &codex_session(
            "sess-default-resident-codex",
            "the default resident codex question",
            "the default resident codex answer",
        ),
    );

    resident.poll_until(
        "both source inputs to complete through the event cycle",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (complete_inputs(&db) >= 2).then_some(())
        },
    );
    // The cycle publishes its watermark after the commit; wait for both kinds
    // rather than racing the write.
    resident.poll_until(
        "the Claude watch watermark",
        Duration::from_secs(120),
        || watch_watermark_for(&fixture, "cd"),
    );
    resident.poll_until(
        "the Codex watch watermark",
        Duration::from_secs(120),
        || watch_watermark_for(&fixture, "cx"),
    );

    resident.stop();

    let db = fixture.open_db();
    assert_eq!(complete_inputs(&db), 2, "both event-cycle inputs completed");
    assert_eq!(
        inputs_with_committed_receipt(&db),
        2,
        "each event-cycle input has its committed receipt"
    );
    assert!(count_like(&db, "the default resident claude answer") > 0);
    assert!(count_like(&db, "the default resident codex answer") > 0);
    assert!(
        count(&db, "SELECT COUNT(*) FROM source_message_links") > 0,
        "the event-cycle inputs link to canonical messages"
    );
    drop(db);

    assert_auto_identity(&fixture, "default_resident");
}

// ---------------------------------------------------------------------------
// A2: one run keeps one fixed configuration; a damaged copy is refused
// ---------------------------------------------------------------------------

#[test]
fn fixed_run_ignores_live_change() {
    let fixture = Fixture::new();
    fixture.create_home_roots();

    let mut resident = Resident::start(&fixture, None);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident loop must reach its event cycle: {}",
        resident.log()
    );
    let pid = resident.pid();

    fixture.write_claude_session(
        "live-change/first.jsonl",
        &claude_session(
            "sess-live-change-first",
            "the first live-change question",
            "the first live-change answer",
        ),
    );
    resident.poll_until(
        "the first input to complete",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (input_rows_for(&db, "live-change/first.jsonl") == 1
                && complete_rows_for(&db, "live-change/first.jsonl") > 0)
                .then_some(())
        },
    );
    let barrier = resident.poll_until(
        "the clean cycle to publish its watch watermark",
        Duration::from_secs(120),
        || watch_watermark_for(&fixture, "cd"),
    );

    let files = fixture.auto_config_files();
    assert_eq!(
        files.len(),
        1,
        "the default run owns exactly one automatic copy: {files:?}"
    );
    let copy_bytes_before = std::fs::read(&files[0]).expect("read the automatic copy");

    // The live rule file changes under the running process.
    fixture.corrupt_live_config();
    fixture.write_claude_session(
        "live-change/second.jsonl",
        &claude_session(
            "sess-live-change-second",
            "the second live-change question",
            "the second live-change answer",
        ),
    );

    resident.poll_until(
        "the second input to complete under the same run",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (complete_rows_for(&db, "live-change/second.jsonl") > 0).then_some(())
        },
    );
    assert_eq!(
        resident.pid(),
        pid,
        "the second file must be read by the same resident process"
    );
    resident.stop();

    let db = fixture.open_db();
    assert_eq!(
        complete_inputs(&db),
        2,
        "both files completed under the run's own fixed configuration"
    );
    assert_eq!(
        inputs_with_committed_receipt(&db),
        2,
        "both inputs have their committed receipts"
    );
    let identities = manifest_safety(&db);
    assert_eq!(identities.len(), 2, "both manifests are present");
    assert_eq!(
        identities[0], identities[1],
        "both inputs carry the same safety identity and fixed-copy digest"
    );
    let state_before = (
        facts_fingerprint(&db),
        watermark_rows(&db),
        file_progress_rows(&db),
        canonical_bodies(&db),
    );
    drop(db);

    assert_eq!(
        std::fs::read(&files[0]).expect("re-read the automatic copy"),
        copy_bytes_before,
        "the run's fixed copy is byte-for-byte unchanged"
    );
    assert!(
        watch_watermark_for(&fixture, "cd") >= Some(barrier),
        "the second file advanced the same watch watermark path"
    );
    let watch_state_before =
        std::fs::read(fixture.data_dir().join("watch_state.json")).expect("read watch state");

    // A fresh run does discover the live file, and that is the control that
    // proves the corruption really is on the discovery path.
    let failed = fixture.index(&[], &[]);
    assert!(
        !failed.status.success(),
        "a new un-flagged run must refuse the corrupt live configuration: {}",
        combined(&failed)
    );
    assert!(
        combined(&failed).contains("source_config_load_failed"),
        "the failure is the source-config load failure: {}",
        combined(&failed)
    );

    let db = fixture.open_db();
    let state_after = (
        facts_fingerprint(&db),
        watermark_rows(&db),
        file_progress_rows(&db),
        canonical_bodies(&db),
    );
    assert_eq!(
        state_after, state_before,
        "the refused run adds no complete input, moves no source fact, and advances no SQL watermark or per-file progress"
    );
    drop(db);
    assert_eq!(
        std::fs::read(fixture.data_dir().join("watch_state.json")).expect("re-read watch state"),
        watch_state_before,
        "the refused run advances no watch watermark"
    );
}

#[test]
fn fixed_copy_corruption_fails() {
    let fixture = Fixture::new();
    fixture.create_home_roots();

    let mut resident = Resident::start(&fixture, None);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident loop must reach its event cycle: {}",
        resident.log()
    );

    fixture.write_claude_session(
        "corruption/first.jsonl",
        &claude_session(
            "sess-corruption-first",
            "the first corruption question",
            "the first corruption answer",
        ),
    );
    resident.poll_until(
        "the first input to complete",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (input_rows_for(&db, "corruption/first.jsonl") == 1
                && complete_rows_for(&db, "corruption/first.jsonl") > 0)
                .then_some(())
        },
    );
    let barrier = resident.poll_until(
        "the clean cycle to publish its watch watermark",
        Duration::from_secs(120),
        || watch_watermark_for(&fixture, "cd"),
    );

    let files = fixture.auto_config_files();
    assert_eq!(
        files.len(),
        1,
        "the default run owns exactly one automatic copy: {files:?}"
    );
    let copy = files[0].clone();
    let mut tampered = std::fs::read(&copy).expect("read the automatic copy");
    tampered.extend_from_slice(b"\n# task19 tampered copy\n");
    std::fs::write(&copy, &tampered).expect("tamper with the automatic copy");

    let facts_before = {
        let db = fixture.open_db();
        facts_fingerprint(&db)
    };

    fixture.write_claude_session(
        "corruption/second.jsonl",
        &claude_session(
            "sess-corruption-second",
            "the second corruption question",
            "the second corruption answer",
        ),
    );

    assert!(
        resident.wait_for(SAFETY_COPY_STALE_MARKER, Duration::from_secs(240)),
        "the cycle names the tampered fixed copy instead of reading through it: {}",
        resident.log()
    );
    resident.stop();

    let db = fixture.open_db();
    assert_eq!(
        input_rows_for(&db, "corruption/second.jsonl"),
        0,
        "a cycle under a tampered copy puts no source fact in place"
    );
    assert_eq!(
        count_like(&db, "the second corruption answer"),
        0,
        "nothing from the unread file reached the canonical store"
    );
    assert_eq!(
        file_state_rows(&db, "second.jsonl"),
        0,
        "the refused file advances no per-file progress"
    );
    assert_eq!(
        facts_fingerprint(&db),
        facts_before,
        "the earlier clean cycle's facts are exactly as they were"
    );
    drop(db);
    assert_eq!(
        watch_watermark_for(&fixture, "cd"),
        Some(barrier),
        "the refused cycle advanced no watch watermark"
    );
}

// ---------------------------------------------------------------------------
// A3: no-ingest, explicit override and the two early returns
// ---------------------------------------------------------------------------

#[test]
fn no_ingest_skips_source_config() {
    let fixture = Fixture::new();
    let session = fixture.write_claude_session(
        "no-ingest/proj/session.jsonl",
        &claude_session(
            "sess-no-ingest",
            "the seeded question",
            "the seeded canonical answer",
        ),
    );
    let projects = fixture.home().join(".claude/projects");
    source_legacy_seed::seed_legacy_source_fixture(
        &fixture.data_dir(),
        &[source_legacy_seed::LegacySeedFile {
            connector: "claude",
            source_id: "local",
            root_id: &scan_root_meta::home_root_id(
                "claude",
                &scan_root_meta::canonicalize_root_path(&projects),
            ),
            root_path: &projects,
            source_path: &session,
        }],
    )
    .expect("seed the canonical pre-state");

    let before = {
        let db = fixture.open_db();
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM conversations"),
            1,
            "the seed wrote one conversation"
        );
        assert!(
            count(&db, "SELECT COUNT(*) FROM messages") > 0,
            "the seeded conversation carries messages"
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM source_inputs"),
            0,
            "the seed claims no source fact"
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM operation_commit_receipt"),
            0,
            "the seed wrote no receipt"
        );
        let watermarks = watermark_rows(&db);
        assert!(
            !watermarks.is_empty(),
            "the seed wrote at least one real watermark row: {watermarks:?}"
        );
        (
            count(&db, "SELECT COUNT(*) FROM conversations"),
            count(&db, "SELECT COUNT(*) FROM messages"),
            watermarks,
            file_progress_rows(&db),
            canonical_bodies(&db),
            source_facts_revision(&db),
        )
    };

    fixture.corrupt_live_config();

    let server = FaultModelServer::start();
    let api_config = fixture.write_model_api_config(&server.endpoint());
    let api_config_text = api_config
        .to_str()
        .expect("utf-8 model api config")
        .to_string();

    let output = fixture.index(
        &[
            "--api-config",
            api_config_text.as_str(),
            "--semantic",
            "--no-ingest",
        ],
        &[],
    );
    let text = combined(&output);
    assert!(
        !output.status.success(),
        "--semantic against a model service answering HTTP 500 must fail: {text}"
    );
    let requests = server.requests();
    assert!(
        !requests.is_empty(),
        "the semantic phase must really reach the configured model endpoint: {text}"
    );
    for request in &requests {
        assert_eq!(
            request["model"],
            serde_json::json!(NO_INGEST_MODEL),
            "the service only records the model the profile names: {request}"
        );
        assert!(
            request["input"]
                .as_array()
                .is_some_and(|input| !input.is_empty()),
            "the recorded probe must carry a non-empty input array: {request}"
        );
    }
    assert!(
        server.answered_500() >= 1,
        "the service must have answered the probe with HTTP 500: {}",
        server.answered_500()
    );
    assert!(
        !text.contains("source_config_load_failed") && !text.contains("source safety configuration"),
        "the no-ingest path must not read or generate the source configuration: {text}"
    );

    let db = fixture.open_db();
    let after = (
        count(&db, "SELECT COUNT(*) FROM conversations"),
        count(&db, "SELECT COUNT(*) FROM messages"),
        watermark_rows(&db),
        file_progress_rows(&db),
        canonical_bodies(&db),
        source_facts_revision(&db),
    );
    assert_eq!(
        after, before,
        "the corpus bodies, watermark values and file progress are unchanged"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM source_inputs"),
        0,
        "no source fact appears in a no-ingest run"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM operation_commit_receipt"),
        0,
        "no receipt appears in a no-ingest run"
    );
    drop(db);
    assert!(
        !fixture.auto_config_dir().exists(),
        "a no-ingest run generates no automatic configuration copy"
    );
}

#[test]
fn explicit_override_keeps_identity() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "explicit/one/session.jsonl",
        &claude_session(
            "sess-explicit-claude",
            "the explicit claude question",
            "the explicit claude answer",
        ),
    );
    fixture.write_codex_session(
        "2026/01/rollout-explicit.jsonl",
        &codex_session(
            "sess-explicit-codex",
            "the explicit codex question",
            "the explicit codex answer",
        ),
    );
    fixture.corrupt_live_config();

    let copy = fixture.fixed_copy();
    let copy_text = copy.to_str().expect("utf-8 fixed copy").to_string();
    let copy_bytes_before = std::fs::read(&copy).expect("read the explicit copy");

    let output = fixture.index(&["--source-safety-config", copy_text.as_str()], &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an explicit copy still succeeds under a corrupt live file; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let db = fixture.open_db();
    assert_eq!(complete_inputs(&db), 2, "both inputs completed");
    assert_eq!(
        inputs_with_committed_receipt(&db),
        2,
        "each input has its committed receipt"
    );
    let identities = manifest_safety(&db);
    assert_eq!(identities.len(), 2);
    for (identity, _) in &identities {
        assert_eq!(
            identity, &copy_text,
            "the explicit identity is the operator's absolute path, not the automatic domain"
        );
    }
    drop(db);

    assert_eq!(
        std::fs::read(&copy).expect("re-read the explicit copy"),
        copy_bytes_before,
        "the explicit copy's bytes are unchanged"
    );
    assert!(
        !fixture.auto_config_dir().exists(),
        "an explicit run generates no automatic copy"
    );
}

#[test]
fn derived_rebuild_skips_source_config() {
    let fixture = Fixture::new();
    let session = fixture.write_claude_session(
        "derived/proj/session.jsonl",
        &claude_session(
            "sess-derived",
            "the derived question",
            "the derived canonical answer",
        ),
    );
    let projects = fixture.home().join(".claude/projects");
    source_legacy_seed::seed_legacy_source_fixture(
        &fixture.data_dir(),
        &[source_legacy_seed::LegacySeedFile {
            connector: "claude",
            source_id: "local",
            root_id: &scan_root_meta::home_root_id(
                "claude",
                &scan_root_meta::canonicalize_root_path(&projects),
            ),
            root_path: &projects,
            source_path: &session,
        }],
    )
    .expect("seed the canonical pre-state");

    // The seeded bodies are the comparison target. They are read from the
    // database, not assumed from the source text: the seed writes its own
    // canonical body string.
    let bodies_before = {
        let db = fixture.open_db();
        let bodies = canonical_bodies(&db);
        assert!(
            !bodies.is_empty(),
            "the seed wrote canonical bodies to preserve"
        );
        bodies
    };

    fixture.corrupt_live_config();

    let output = fixture.index_verbose(&["--force-rebuild"], &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the derived rebuild completes under a corrupt live file; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = combined(&output);
    assert!(
        text.contains("force rebuild from populated canonical database"),
        "the canonical-only rebuild branch really ran: {text}"
    );

    let db = fixture.open_db();
    assert_eq!(
        canonical_bodies(&db),
        bodies_before,
        "the derived rebuild preserves the exact canonical bodies it started from"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM source_inputs"),
        0,
        "a derived rebuild claims no source fact"
    );
    drop(db);
    assert!(
        !fixture.auto_config_dir().exists(),
        "a derived rebuild generates no automatic configuration copy"
    );
}

#[test]
fn absent_watch_once_skips_source_config() {
    let fixture = Fixture::new();
    let session = fixture.write_claude_session(
        "absent/proj/session.jsonl",
        &claude_session(
            "sess-absent",
            "the absent question",
            "the absent canonical answer",
        ),
    );
    let copy = fixture.fixed_copy();
    let copy_text = copy.to_str().expect("utf-8 fixed copy").to_string();

    let healthy = fixture.index(&["--source-safety-config", copy_text.as_str()], &[]);
    assert_eq!(
        healthy.status.code(),
        Some(0),
        "the healthy explicit run succeeds; stderr={}",
        String::from_utf8_lossy(&healthy.stderr)
    );
    {
        let db = fixture.open_db();
        assert_eq!(complete_inputs(&db), 1, "the healthy run completed its input");
        assert!(
            !fixture.auto_config_dir().exists(),
            "the explicit run generated no automatic copy"
        );
    }
    let state_before = {
        let db = fixture.open_db();
        let watermarks = watermark_rows(&db);
        assert!(
            !watermarks.is_empty(),
            "the healthy run left real watermark rows to protect: {watermarks:?}"
        );
        (
            count_like(&db, "the absent canonical answer"),
            facts_fingerprint(&db),
            watermarks,
            file_progress_rows(&db),
            canonical_bodies(&db),
        )
    };

    fixture.corrupt_live_config();
    let absent = fixture.path().join("does-not-exist.jsonl");
    let absent_text = absent.to_str().expect("utf-8 absent path").to_string();
    let output = fixture.index(&["--watch-once", absent_text.as_str()], &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the absent-path early return succeeds; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = combined(&output);
    assert!(
        !text.contains("source_config_load_failed") && !text.contains("source safety configuration"),
        "the absent-path early return never discovers the corrupt live file: {text}"
    );

    let db = fixture.open_db();
    assert_eq!(
        (
            count_like(&db, "the absent canonical answer"),
            facts_fingerprint(&db),
            watermark_rows(&db),
            file_progress_rows(&db),
            canonical_bodies(&db),
        ),
        state_before,
        "the absent-path run leaves the bodies, source facts, watermark values and file progress unchanged"
    );
    drop(db);
    assert!(
        !fixture.auto_config_dir().exists(),
        "the absent-path run generates no automatic configuration copy"
    );
    assert!(session.exists(), "the healthy fixture session stays on disk");
}
