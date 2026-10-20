//! Task20: the real `cass sync` entry point consumes Task19's default fixed
//! configuration, end to end.
//!
//! Every case drives the real `cass` binary through `sync --json --data-dir`
//! against an isolated HOME / XDG / connector root, a canned embedding API on
//! a random loopback port and a private data directory. The database is read
//! only after the CLI process has exited, and the contract is checked through
//! `source_inputs`, its committed activation receipts and the canonical
//! message bodies.
//!
//! The seven cases are the fixed roster of `task-20-test-contract.md`. This
//! target deliberately has no `mod util`: the shared module would add its 57
//! tests to this target and blur the intended "exactly seven" roster. The
//! fixtures below are local, synthetic and neutral; no real session, path or
//! secret appears in this file.
//!
//! `CARGO_BIN_EXE_cass` is resolved at runtime first, so the saved red/green
//! binary pair can be replayed by setting that variable to the saved path.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use coding_agent_search::storage::source_facts::decode_expected_manifest_header;
use rusqlite::OptionalExtension as _;
use sha2::{Digest as _, Sha256};

/// The dimension returned by this fixture's explicit embedding API profile.
const EMBED_DIM: usize = 1024;
/// The model explicitly named by this fixture's embedding API profile.
const EMBED_MODEL: &str = "BAAI/bge-m3";

const SCHEMA: &str = "cass.sync.v1";

/// The automatic fixed configuration's identity domain.
const AUTO_IDENTITY_PREFIX: &str = "cass.source-config/1:sha256:";

/// The real Gemini fixture; only its session id and message texts are
/// replaced where a case needs independent markers.
const GEMINI_FIXTURE: &[u8] = include_bytes!("fixtures/gemini/hash123/chats/session-test.json");

// ---------------------------------------------------------------------------
// Canned embedding API (OpenAI embeddings wire shape)
// ---------------------------------------------------------------------------

struct StubEmbeddingApi {
    base_url: String,
    wake_addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for StubEmbeddingApi {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(&self.wake_addr) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl StubEmbeddingApi {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind embedding API stub");
        listener
            .set_nonblocking(true)
            .expect("set embedding API stub nonblocking");
        let addr = listener.local_addr().expect("stub address");
        let wake_addr = addr.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => handle_http(stream),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            base_url: format!("http://{wake_addr}"),
            wake_addr,
            stop,
            handle: Some(handle),
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn read_http_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 65536 {
            return None;
        }
    };
    let header_str = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_str.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let content_length: usize = lines
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let body = buf[header_end..buf.len().min(header_end + content_length)].to_vec();
    Some((method, path, body))
}

fn ok_json(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn handle_http(mut stream: TcpStream) {
    let Some((method, path, body)) = read_http_request(&mut stream) else {
        return;
    };
    let response = if method == "GET" && path == "/models" {
        ok_json(&format!(
            r#"{{"data":[{{"id":"{EMBED_MODEL}","capabilities":["embed"]}}]}}"#
        ))
    } else if method == "POST" && path == "/embeddings" {
        let requested = serde_json::from_slice::<serde_json::Value>(&body).ok();
        let model = requested
            .as_ref()
            .and_then(|v| v.get("model"))
            .and_then(|m| m.as_str())
            .unwrap_or_default();
        if model != EMBED_MODEL {
            let msg = format!("embedding API stub: unexpected model {model:?}");
            format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                msg.len(),
                msg
            )
        } else {
            // `http_embed` requires `data[].index` to permute 0..N-1, and the
            // activation audit asks each chunk's row to be its own nearest
            // neighbour, so vectors must be distinct per input text.
            let inputs: Vec<String> = requested
                .as_ref()
                .and_then(|v| v.get("input"))
                .and_then(|i| i.as_array())
                .map(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().unwrap_or_default().to_string())
                        .collect()
                })
                .unwrap_or_else(|| vec![String::new()]);
            let data: Vec<serde_json::Value> = inputs
                .iter()
                .enumerate()
                .map(|(index, text)| {
                    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
                    for byte in text.as_bytes() {
                        hash ^= u64::from(*byte);
                        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
                    }
                    let vector: Vec<f32> = (0..EMBED_DIM)
                        .map(|i| {
                            let mixed = hash ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                            (mixed % 997) as f32 / 997.0 - 0.5
                        })
                        .collect();
                    serde_json::json!({ "embedding": vector, "index": index })
                })
                .collect();
            ok_json(&serde_json::json!({ "data": data }).to_string())
        }
    } else {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    };
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home").join(".claude/projects"))
            .expect("mkdir claude root");
        std::fs::create_dir_all(root.path().join("home").join(".codex/sessions"))
            .expect("mkdir codex root");
        std::fs::create_dir_all(root.path().join("data")).expect("mkdir data");
        std::fs::create_dir_all(root.path().join("config")).expect("mkdir config");
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

    fn sources_config(&self) -> PathBuf {
        self.config_home().join("cass").join("sources.toml")
    }

    fn write_sources_config(&self, body: &str) {
        let path = self.sources_config();
        std::fs::create_dir_all(path.parent().expect("config parent")).expect("mkdir config");
        std::fs::write(&path, body).expect("write sources.toml");
    }

    fn write_claude(&self, root: &Path, relative: &str, uuid: &str, question: &str, answer: &str) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("session parent")).expect("mkdir session dir");
        std::fs::write(&path, jsonl(&claude_session(uuid, question, answer)))
            .expect("write claude session");
        path
    }

    fn write_codex(&self, root: &Path, relative: &str, id: &str, question: &str, answer: &str) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("rollout parent")).expect("mkdir rollout dir");
        std::fs::write(&path, jsonl(&codex_session(id, question, answer)))
            .expect("write codex rollout");
        path
    }

    fn write_gemini(&self, root: &Path, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("gemini parent")).expect("mkdir gemini dir");
        std::fs::write(&path, bytes).expect("write gemini session");
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
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("CASS_RESPONSIVENESS_DISABLE", "1")
            .env("CASS_TANTIVY_REBUILD_WORKERS", "1")
            .env("CASS_SEMANTIC_FINALIZE_PROGRESS_EVERY_MS", "10")
            .env("NO_COLOR", "1")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("CASS_DATA_DIR")
            .env_remove("CASS_OUTPUT_FORMAT")
            .env_remove("TOON_DEFAULT_FORMAT")
            .env_remove("RUST_LOG");
        for variable in [
            "CASS_INFINITY_URL", "CASS_INFINITY_EMBED_MODEL", "CASS_INFINITY_RERANK_MODEL",
            "CASS_QWEN_RERANK_URL", "CASS_SEMANTIC_EMBEDDER", "CASS_SEMANTIC_DOWNLOAD_POLICY",
            "CASS_SEMANTIC_MAX_MODEL_SIZE_MB", "CASS_API_CONFIG",
        ] {
            cmd.env_remove(variable);
        }
        cmd
    }

    fn model_api_config(&self, api_base_url: &str) -> PathBuf {
        let path = self.root.path().join("model-api.toml");
        let text = format!(
            r#"version = 1
default_embedding = "local"

[profiles.local]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "{api_base_url}/embeddings"
scope = "loopback"
model = "{EMBED_MODEL}"
model_revision = "source-sync-fixture-v1"
normalization = "l2"
max_batch = 64
"#
        );
        std::fs::write(&path, text).expect("write the fixture API profile");
        path
    }

    fn sync(&self, api_base_url: &str, extra: &[&str]) -> Output {
        self.sync_with_env(api_base_url, extra, &[])
    }

    fn sync_with_env(
        &self,
        api_base_url: &str,
        extra: &[&str],
        envs: &[(&str, &str)],
    ) -> Output {
        let mut cmd = Command::new(cass_bin());
        for (key, value) in envs {
            cmd.env(key, value);
        }
        self.isolate(&mut cmd);
        cmd.arg("--api-config").arg(self.model_api_config(api_base_url));
        cmd.args(["sync", "--json", "--data-dir"]);
        cmd.arg(self.data_dir());
        cmd.args(extra);
        cmd.output().expect("spawn cass sync")
    }

    /// Read-only handle opened after the CLI process has exited.
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
}

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
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
// Report and database readers
// ---------------------------------------------------------------------------

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Parse stdout as exactly one JSON object and cross-check it against the
/// process status.
fn report_of(output: &Output) -> serde_json::Value {
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not exactly one JSON object ({e}); stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            stderr_of(output)
        )
    });
    assert_eq!(payload["schema"], serde_json::json!(SCHEMA));
    let reported = payload["exit_code"]
        .as_i64()
        .unwrap_or_else(|| panic!("report must carry an integer exit_code: {payload}"));
    assert_eq!(
        Some(reported),
        output.status.code().map(i64::from),
        "the report's exit_code must equal the process exit status: {payload}"
    );
    assert_eq!(
        payload["complete"],
        serde_json::json!(reported == 0),
        "complete must be true exactly when exit_code is 0: {payload}"
    );
    let names: Vec<&str> = payload["stages"]
        .as_array()
        .unwrap_or_else(|| panic!("the report must carry its stages: {payload}"))
        .iter()
        .map(|stage| stage["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        names,
        vec!["preflight", "mirror", "index", "report"],
        "the four stages are fixed and ordered: {payload}"
    );
    payload
}

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
/// receipt — the contract's per-input receipt check, not a whole-table count.
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

fn complete_rows_for(db: &rusqlite::Connection, locator: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM source_inputs
         WHERE relative_locator_bin = ?1 AND state = 'complete'",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("counting complete inputs for {locator}: {error}"))
}

fn committed_receipts_for(db: &rusqlite::Connection, locator: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM source_inputs si
         JOIN operation_commit_receipt r ON r.idempotency_key = si.receipt_key
         WHERE si.relative_locator_bin = ?1
           AND r.operation = 'source_input_activation_v1'
           AND r.state = 'committed'",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("counting activation receipts for {locator}: {error}"))
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// Recursive content fingerprint of a directory: relative path, size and
/// SHA256 of every file, sorted. An absent directory is empty.
fn dir_fingerprint(root: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else if path.is_file() {
                let relative = path.strip_prefix(base).unwrap_or(&path);
                let bytes = std::fs::read(&path).unwrap_or_default();
                out.push(format!(
                    "{}|{}|{}",
                    relative.display(),
                    bytes.len(),
                    sha256_hex(&bytes)
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// The automatic copies as `name|size|sha256`, sorted.
fn auto_config_fingerprint(fixture: &Fixture) -> Vec<String> {
    fixture
        .auto_config_files()
        .into_iter()
        .map(|path| {
            let bytes = std::fs::read(&path).expect("read the automatic copy");
            format!(
                "{}|{}|{}",
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default(),
                bytes.len(),
                sha256_hex(&bytes)
            )
        })
        .collect()
}

/// The contract's automatic-identity check: exactly one copy, named after its
/// own digest, and every input's manifest naming that same content address.
/// Returns the digest.
fn assert_auto_identity(fixture: &Fixture, label: &str) -> String {
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
    for (identity, fixed_sha) in &identities {
        assert_eq!(
            identity, &expected,
            "{label}: the input's safety identity is the automatic content address"
        );
        assert_eq!(
            fixed_sha, &digest,
            "{label}: the manifest's fixed-copy digest is the published copy"
        );
    }
    digest
}

// ---------------------------------------------------------------------------
// A1/A5 — HOME inputs complete through the real sync entry point
// ---------------------------------------------------------------------------

#[test]
fn sync_home_sources_complete() {
    let fixture = Fixture::new();
    let stub = StubEmbeddingApi::start();
    fixture.write_claude(
        &fixture.home().join(".claude/projects"),
        "home/proj/session.jsonl",
        "sess-sync-home-claude",
        "the sync home claude question",
        "the sync home claude answer",
    );
    fixture.write_codex(
        &fixture.home().join(".codex/sessions"),
        "2026/01/rollout-sync-home.jsonl",
        "sess-sync-home-codex",
        "the sync home codex question",
        "the sync home codex answer",
    );

    let output = fixture.sync(&stub.base_url, &[]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(0),
        "an unflagged sync must be ready: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(report["complete"], serde_json::json!(true));
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(true),
        "the local index must run: {report}"
    );
    assert_eq!(
        report["semantic_activated"],
        serde_json::json!(true),
        "a ready sync must report semantic activation: {report}"
    );
    assert!(
        report["index"]["stats"]["scan_invocations"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "the run must really scan its HOME roots: {report}"
    );
    assert_eq!(report["mirror"]["attempted"], serde_json::json!(false));
    assert_eq!(report["mirror"]["sources"], serde_json::json!([]));

    // The CLI has exited; every read below opens the archive fresh.
    let db = fixture.open_db();
    assert_eq!(complete_inputs(&db), 2, "both HOME inputs completed");
    assert_eq!(
        inputs_with_committed_receipt(&db),
        2,
        "each complete input has its own committed activation receipt"
    );
    // Per-input, by the specific BLOB locator: a total can hide one source
    // that completed twice while its sibling never did.
    for locator in ["home/proj/session.jsonl", "2026/01/rollout-sync-home.jsonl"] {
        assert_eq!(
            complete_rows_for(&db, locator),
            1,
            "{locator}: this input itself reached the complete state"
        );
        assert_eq!(
            committed_receipts_for(&db, locator),
            1,
            "{locator}: this input itself owns a committed activation receipt"
        );
    }
    assert!(
        count(&db, "SELECT COUNT(*) FROM source_message_links") > 0,
        "the inputs link to canonical messages"
    );
    assert!(
        count_like(&db, "the sync home claude answer") > 0,
        "the Claude body is readable after reopening"
    );
    assert!(
        count_like(&db, "the sync home codex answer") > 0,
        "the Codex body is readable after reopening"
    );
    let before = (
        facts_fingerprint(&db),
        count(&db, "SELECT COUNT(*) FROM operation_commit_receipt"),
        canonical_bodies(&db),
    );
    drop(db);

    assert_auto_identity(&fixture, "sync_home_sources_complete");

    // The same command again is a verified replay: no new input key and no new
    // receipt appears.
    let replay = fixture.sync(&stub.base_url, &[]);
    let report = report_of(&replay);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(0),
        "the replay must stay ready: {report} stderr={}",
        stderr_of(&replay)
    );
    let db = fixture.open_db();
    assert_eq!(
        (
            facts_fingerprint(&db),
            count(&db, "SELECT COUNT(*) FROM operation_commit_receipt"),
            canonical_bodies(&db),
        ),
        before,
        "a replayed sync adds no input key, receipt or body"
    );
}

// ---------------------------------------------------------------------------
// A1/A5 — declared local roots outside HOME complete through sync
// ---------------------------------------------------------------------------

#[test]
fn sync_declared_sources_complete() {
    let fixture = Fixture::new();
    let stub = StubEmbeddingApi::start();
    let declared_a = fixture
        .path()
        .join("declared-a")
        .join(".claude/projects");
    let declared_b = fixture
        .path()
        .join("declared-b")
        .join(".codex/sessions");
    fixture.write_claude(
        &declared_a,
        "proj/session-a.jsonl",
        "sess-sync-declared-a",
        "the declared a question",
        "the declared a answer",
    );
    fixture.write_codex(
        &declared_b,
        "2026/01/rollout-declared-b.jsonl",
        "sess-sync-declared-b",
        "the declared b question",
        "the declared b answer",
    );
    fixture.write_sources_config(&format!(
        r#"
[[sources]]
name = "declared-a"
type = "local"
origin_host = "declared-a"
paths = ["{}"]

[[sources]]
name = "declared-b"
type = "local"
origin_host = "declared-b"
paths = ["{}"]
"#,
        declared_a.display(),
        declared_b.display()
    ));

    let output = fixture.sync(&stub.base_url, &[]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(0),
        "two declared local roots make a complete round: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(
        report["mirror"]["attempted"],
        serde_json::json!(false),
        "a type=local entry is a scan root, not a mirror: {report}"
    );
    assert_eq!(report["mirror"]["sources"], serde_json::json!([]));
    assert_eq!(report["semantic_activated"], serde_json::json!(true));

    let db = fixture.open_db();
    assert_eq!(
        complete_inputs(&db),
        2,
        "the two declared roots each land one complete input"
    );
    assert_eq!(
        inputs_with_committed_receipt(&db),
        2,
        "each declared input has its committed receipt"
    );
    let sources: Vec<String> = {
        let mut stmt = db
            .prepare(
                "SELECT source_id || '|' || identity_namespace || '|' || connector
                 FROM source_inputs ORDER BY 1",
            )
            .expect("prepare the declared-source query");
        stmt.query_map([], |row| row.get::<_, String>(0))
            .expect("query the declared sources")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect the declared sources")
    };
    assert_eq!(
        sources,
        vec![
            "declared-a|declared-a|claude_code".to_string(),
            "declared-b|declared-b|codex".to_string(),
        ],
        "each input points at the declaration that owns its root"
    );
    let roots: Vec<String> = {
        let mut stmt = db
            .prepare("SELECT root_id_bin FROM source_inputs ORDER BY 1")
            .expect("prepare the root query");
        stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query the roots")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect the roots")
            .into_iter()
            .map(|bytes| String::from_utf8(bytes).expect("UTF-8 source root"))
            .collect()
    };
    assert_eq!(
        roots,
        vec![
            declared_a.to_string_lossy().into_owned(),
            declared_b.to_string_lossy().into_owned()
        ],
        "both inputs come from the declared roots, not from HOME"
    );
    assert!(
        count_like(&db, "the declared a answer") > 0
            && count_like(&db, "the declared b answer") > 0,
        "both declared bodies reached the canonical store"
    );
    // Per-input, by the specific BLOB locator relative to its declared root.
    for locator in ["proj/session-a.jsonl", "2026/01/rollout-declared-b.jsonl"] {
        assert_eq!(
            complete_rows_for(&db, locator),
            1,
            "{locator}: this declared input itself is complete"
        );
        assert_eq!(
            committed_receipts_for(&db, locator),
            1,
            "{locator}: this declared input itself owns a committed receipt"
        );
    }
    drop(db);

    assert_auto_identity(&fixture, "sync_declared_sources_complete");
}

// ---------------------------------------------------------------------------
// A2 — --no-ingest bypasses both the config and the safety preparation
// ---------------------------------------------------------------------------

#[test]
fn sync_no_ingest_preserves_source_state() {
    let fixture = Fixture::new();
    let stub = StubEmbeddingApi::start();
    fixture.write_claude(
        &fixture.home().join(".claude/projects"),
        "no-ingest/proj/session.jsonl",
        "sess-sync-no-ingest",
        "the no-ingest warmup question",
        "the no-ingest warmup answer",
    );
    fixture.write_codex(
        &fixture.home().join(".codex/sessions"),
        "2026/01/rollout-no-ingest.jsonl",
        "sess-sync-no-ingest-codex",
        "the no-ingest warmup codex question",
        "the no-ingest warmup codex answer",
    );

    let warmup = fixture.sync(&stub.base_url, &[]);
    assert_eq!(
        warmup.status.code(),
        Some(0),
        "the warmup sync must succeed: {}",
        stderr_of(&warmup)
    );
    assert_eq!(fixture.auto_config_files().len(), 1, "the warmup owns one automatic copy");

    let before = {
        let db = fixture.open_db();
        (
            canonical_bodies(&db),
            facts_fingerprint(&db),
            watermark_rows(&db),
            file_progress_rows(&db),
            dir_fingerprint(&fixture.data_dir().join("raw-mirror")),
            auto_config_fingerprint(&fixture),
            count(&db, "SELECT COUNT(*) FROM source_inputs"),
        )
    };

    // A config the run must not read, a rule file it must not discover, and a
    // session it must not scan.
    fixture.write_sources_config("this is not = valid toml [[[");
    fixture.corrupt_live_config();
    fixture.write_claude(
        &fixture.home().join(".claude/projects"),
        "no-ingest/proj/late.jsonl",
        "sess-sync-no-ingest-late",
        "the no-ingest late question",
        "the no-ingest late answer",
    );

    let output = fixture.sync(&stub.base_url, &["--no-ingest"]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(0),
        "a corrupt config must not stop --no-ingest: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(
        report["index"]["stats"]["scan_invocations"],
        serde_json::json!(0),
        "--no-ingest must not invoke a single connector scan: {report}"
    );
    assert_eq!(
        report["mirror"]["skip_reason"],
        serde_json::json!("no-ingest"),
        "the mirror stage must be reported as skipped: {report}"
    );
    assert_eq!(report["mirror"]["attempted"], serde_json::json!(false));
    assert_eq!(report["mirror"]["sources"], serde_json::json!([]));

    let db = fixture.open_db();
    let after = (
        canonical_bodies(&db),
        facts_fingerprint(&db),
        watermark_rows(&db),
        file_progress_rows(&db),
        dir_fingerprint(&fixture.data_dir().join("raw-mirror")),
        auto_config_fingerprint(&fixture),
        count(&db, "SELECT COUNT(*) FROM source_inputs"),
    );
    assert_eq!(
        after, before,
        "the bodies, source facts, receipts, watermark values, file progress, \
         raw-mirror bytes and fixed copy are unchanged"
    );
    assert_eq!(
        complete_rows_for(&db, "no-ingest/proj/late.jsonl"),
        0,
        "the late input gained no complete source fact"
    );
    assert_eq!(
        committed_receipts_for(&db, "no-ingest/proj/late.jsonl"),
        0,
        "the late input gained no activation receipt"
    );
    for locator in [
        "no-ingest/proj/session.jsonl",
        "2026/01/rollout-no-ingest.jsonl",
    ] {
        assert_eq!(
            complete_rows_for(&db, locator),
            1,
            "{locator}: the warmup input is still complete"
        );
        assert_eq!(
            committed_receipts_for(&db, locator),
            1,
            "{locator}: the warmup input still owns its committed receipt"
        );
    }
}

// ---------------------------------------------------------------------------
// A3 — a bad safety configuration is an index failure, never a precondition
// ---------------------------------------------------------------------------

#[test]
fn sync_bad_safety_is_index_failure() {
    // Subcase 1: the live rule file is corrupt. The sources config is valid,
    // so the sync preflight passes and the failure belongs to the index run.
    {
        let fixture = Fixture::new();
        let stub = StubEmbeddingApi::start();
        let local = fixture.path().join("empty-local");
        std::fs::create_dir_all(&local).expect("mkdir local root");
        fixture.write_sources_config(&format!(
            r#"
[[sources]]
name = "declared"
type = "local"
origin_host = "declared"
paths = ["{}"]
"#,
            local.display()
        ));
        fixture.write_claude(
            &fixture.home().join(".claude/projects"),
            "bad-rule/proj/session.jsonl",
            "sess-sync-bad-rule",
            "the bad rule question",
            "the bad rule answer",
        );
        fixture.corrupt_live_config();

        let output = fixture.sync(&stub.base_url, &[]);
        let report = report_of(&output);
        assert_eq!(
            report["exit_code"],
            serde_json::json!(1),
            "a corrupt live rule file is an index failure: {report} stderr={}",
            stderr_of(&output)
        );
        assert_eq!(report["complete"], serde_json::json!(false));
        assert_eq!(
            report["error"]["kind"],
            serde_json::json!("index"),
            "the failure is reported along the index category: {report}"
        );
        assert_eq!(
            report["index"]["started"],
            serde_json::json!(true),
            "the index run started and then failed: {report}"
        );
        let message = report["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            message.contains("source_config_load_failed"),
            "the failure names the rule discovery step: {message}"
        );
        let db = fixture.open_db();
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM source_inputs"),
            0,
            "a refused run lands no source fact"
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM operation_commit_receipt"),
            0,
            "a refused run writes no receipt"
        );
    }

    // Subcase 2: the content-addressed fixed copy is damaged after a clean
    // warmup. The live rules stay valid, so the failure is the publication
    // mismatch inside the index run.
    {
        let fixture = Fixture::new();
        let stub = StubEmbeddingApi::start();
        fixture.write_claude(
            &fixture.home().join(".claude/projects"),
            "bad-copy/one/session.jsonl",
            "sess-sync-bad-copy-one",
            "the bad copy first question",
            "the bad copy first answer",
        );
        fixture.write_codex(
            &fixture.home().join(".codex/sessions"),
            "2026/01/rollout-bad-copy.jsonl",
            "sess-sync-bad-copy-codex",
            "the bad copy codex question",
            "the bad copy codex answer",
        );

        let warmup = fixture.sync(&stub.base_url, &[]);
        assert_eq!(
            warmup.status.code(),
            Some(0),
            "the warmup sync must succeed: {}",
            stderr_of(&warmup)
        );
        let files = fixture.auto_config_files();
        assert_eq!(files.len(), 1, "the warmup owns one automatic copy: {files:?}");
        let copy = files[0].clone();
        let mut tampered = std::fs::read(&copy).expect("read the automatic copy");
        tampered.extend_from_slice(b"\n# task20 tampered copy\n");
        std::fs::write(&copy, &tampered).expect("tamper with the automatic copy");

        let before = {
            let db = fixture.open_db();
            (
                facts_fingerprint(&db),
                canonical_bodies(&db),
                complete_inputs(&db),
                watermark_rows(&db),
                file_progress_rows(&db),
            )
        };

        fixture.write_claude(
            &fixture.home().join(".claude/projects"),
            "bad-copy/two/session.jsonl",
            "sess-sync-bad-copy-two",
            "the bad copy second question",
            "the bad copy second answer",
        );

        let output = fixture.sync(&stub.base_url, &[]);
        let report = report_of(&output);
        assert_eq!(
            report["exit_code"],
            serde_json::json!(1),
            "a damaged fixed copy is an index failure: {report} stderr={}",
            stderr_of(&output)
        );
        assert_eq!(report["complete"], serde_json::json!(false));
        assert_eq!(report["error"]["kind"], serde_json::json!("index"));
        assert_eq!(
            report["index"]["started"],
            serde_json::json!(true),
            "the index run started and then failed: {report}"
        );
        let message = report["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            message.contains("source_config_mismatch"),
            "the failure names the fixed-copy mismatch: {message}"
        );

        let db = fixture.open_db();
        assert_eq!(
            (
                facts_fingerprint(&db),
                canonical_bodies(&db),
                complete_inputs(&db),
                watermark_rows(&db),
                file_progress_rows(&db),
            ),
            before,
            "the earlier complete facts, bodies, SQL watermark values and per-file \
             progress are exactly as they were"
        );
        assert_eq!(
            complete_rows_for(&db, "bad-copy/two/session.jsonl"),
            0,
            "the new input never reaches a complete state"
        );
        assert_eq!(
            committed_receipts_for(&db, "bad-copy/two/session.jsonl"),
            0,
            "the new input gains no activation receipt"
        );
    }
}

// ---------------------------------------------------------------------------
// A3 — a partial source is never complete
// ---------------------------------------------------------------------------

#[test]
fn sync_partial_source_is_not_complete() {
    let fixture = Fixture::new();
    let stub = StubEmbeddingApi::start();
    let good = claude_session(
        "sess-sync-partial",
        "the partial good question",
        "the partial good answer",
    );
    let body = format!("{}\n{{ this line is not json\n{}\n", good[0], good[1]);
    let dir = fixture.home().join(".claude/projects").join("partial/proj");
    std::fs::create_dir_all(&dir).expect("mkdir partial project");
    std::fs::write(dir.join("session.jsonl"), body).expect("write partial session");

    let output = fixture.sync(&stub.base_url, &[]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(1),
        "an input with an unparseable record is not a success: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(report["complete"], serde_json::json!(false));
    assert_eq!(
        report["error"]["kind"],
        serde_json::json!("index"),
        "the failure stays on the index category: {report}"
    );

    let db = fixture.open_db();
    assert_eq!(
        complete_inputs(&db),
        0,
        "the partial input never reaches the complete state"
    );
    assert_eq!(
        committed_receipts_for(&db, "partial/proj/session.jsonl"),
        0,
        "the partial input gains no activation receipt"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_records WHERE parse_state = 'parse_failed'"
        ),
        1,
        "exactly the malformed line is reported as failed"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_records WHERE parse_state = 'parsed'"
        ),
        2,
        "the two legal lines around it still parse"
    );
}

// ---------------------------------------------------------------------------
// A3/A5 — a failed mirror still ingests HOME and the successful mirror input
// ---------------------------------------------------------------------------

const FAKE_SSH: &str = r#"#!/bin/sh
last=""
for arg in "$@"; do last="$arg"; done
case "$last" in
  *CASS_HOME_MARKER*) printf 'CASS_HOME_MARKER:%s\n' "$CASS_FIXTURE_REMOTE_HOME"; exit 0 ;;
  *"rsync --version"*) printf 'rsync  version 3.2.7  protocol 31\n'; exit 0 ;;
  *) printf 'fake ssh: unsupported remote command: %s\n' "$last" >&2; exit 1 ;;
esac
"#;

const FAKE_RSYNC: &str = r#"#!/bin/sh
case "$1" in
  --version) printf 'rsync  version 3.2.7  protocol 31\n'; exit 0 ;;
  --help)
    printf 'rsync  version 3.2.7  protocol 31\n'
    printf 'Usage: rsync [OPTION]... SRC [SRC]... DEST\n'
    exit 0
    ;;
esac

previous=""
last=""
for arg in "$@"; do
  previous="$last"
  last="$arg"
done

case "$previous" in
  *cass-bad@*)
    printf 'rsync: connection unexpectedly closed (0 bytes received so far)\n' >&2
    exit 23
    ;;
esac

mkdir -p "$last/projects/-pr10"
cp "$CASS_FIXTURE_CLAUDE_SESSION" "$last/projects/-pr10/agent-remote.jsonl"
printf 'Number of regular files transferred: 1\n'
exit 0
"#;

#[test]
fn sync_mirror_failure_still_ingests_home() {
    let fixture = Fixture::new();
    let stub = StubEmbeddingApi::start();
    let fake_bin = fixture.path().join("fake-bin");
    std::fs::create_dir_all(&fake_bin).expect("mkdir fake bin");
    for (name, body) in [("ssh", FAKE_SSH), ("rsync", FAKE_RSYNC)] {
        let path = fake_bin.join(name);
        std::fs::write(&path, body).expect("write fake transport");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make the fake transport executable");
    }
    let remote_payload = fixture.write_claude(
        &fixture.path().join("remote-payload"),
        "agent-remote.jsonl",
        "sess-sync-mirror",
        "the mirrored question",
        "the mirrored answer",
    );

    fixture.write_claude(
        &fixture.home().join(".claude/projects"),
        "mirror/proj/session.jsonl",
        "sess-sync-mirror-home-claude",
        "the mirror home claude question",
        "the mirror home claude answer",
    );
    fixture.write_codex(
        &fixture.home().join(".codex/sessions"),
        "2026/01/rollout-mirror-home.jsonl",
        "sess-sync-mirror-home-codex",
        "the mirror home codex question",
        "the mirror home codex answer",
    );
    fixture.write_sources_config(
        r#"
[[sources]]
name = "cass-good"
type = "ssh"
host = "cass-good@fixture.invalid"
origin_host = "cass-good"
paths = ["~/.claude/projects"]

[[sources]]
name = "cass-bad"
type = "ssh"
host = "cass-bad@fixture.invalid"
origin_host = "cass-bad"
paths = ["~/.claude/projects"]
"#,
    );

    let existing = std::env::var_os("PATH").unwrap_or_default();
    let mut path = std::ffi::OsString::from(fake_bin.clone());
    path.push(":");
    path.push(existing);
    let path = path.to_string_lossy().into_owned();
    let payload = remote_payload.to_string_lossy().into_owned();
    let output = fixture.sync_with_env(
        &stub.base_url,
        &[],
        &[
            ("PATH", &path),
            ("CASS_FIXTURE_CLAUDE_SESSION", &payload),
            ("CASS_FIXTURE_REMOTE_HOME", "/home/cass-fixture"),
        ],
    );
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(3),
        "a failed mirror leaves a partial round: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(report["complete"], serde_json::json!(false));
    assert_eq!(
        report["partial_reasons"],
        serde_json::json!(["mirror_failed"]),
        "the partial reason names the mirror: {report}"
    );
    assert_eq!(
        report["mirror"]["attempted"],
        serde_json::json!(true),
        "the mirror stage really ran: {report}"
    );
    let sources = report["mirror"]["sources"]
        .as_array()
        .unwrap_or_else(|| panic!("mirror.sources must be an array: {report}"));
    let good = sources
        .iter()
        .find(|source| source["name"] == serde_json::json!("cass-good"))
        .expect("the good source is reported");
    let bad = sources
        .iter()
        .find(|source| source["name"] == serde_json::json!("cass-bad"))
        .expect("the bad source is reported");
    assert_eq!(good["status"], serde_json::json!("success"));
    assert_ne!(bad["status"], serde_json::json!("success"));
    assert!(bad["error"].is_string(), "the failed source names its reason");
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(true),
        "a failed mirror must not skip the local index: {report}"
    );
    assert_eq!(
        report["semantic_activated"],
        serde_json::json!(true),
        "the local half still reached semantic activation: {report}"
    );

    let db = fixture.open_db();
    assert_eq!(
        complete_inputs(&db),
        3,
        "both HOME inputs and the successfully mirrored input completed"
    );
    assert_eq!(
        inputs_with_committed_receipt(&db),
        3,
        "each of those inputs has its committed receipt"
    );
    for phrase in [
        "the mirrored answer",
        "the mirror home claude answer",
        "the mirror home codex answer",
    ] {
        assert!(
            count_like(&db, phrase) > 0,
            "{phrase}: the body must actually land"
        );
    }
    // Per-input, by the specific BLOB locator: two HOME inputs under the HOME
    // roots and one input under the successful source's mirror root.
    for locator in [
        "mirror/proj/session.jsonl",
        "2026/01/rollout-mirror-home.jsonl",
        "projects/-pr10/agent-remote.jsonl",
    ] {
        assert_eq!(
            complete_rows_for(&db, locator),
            1,
            "{locator}: this input itself is complete"
        );
        assert_eq!(
            committed_receipts_for(&db, locator),
            1,
            "{locator}: this input itself owns a committed receipt"
        );
    }
}

// ---------------------------------------------------------------------------
// A4 — a legacy connector keeps its canonical projection
// ---------------------------------------------------------------------------

#[test]
fn sync_other_connector_keeps_legacy_projection() {
    let fixture = Fixture::new();
    let stub = StubEmbeddingApi::start();
    fixture.write_claude(
        &fixture.home().join(".claude/projects"),
        "legacy/proj/session.jsonl",
        "sess-sync-legacy-claude",
        "the legacy claude question",
        "the legacy claude answer",
    );
    fixture.write_codex(
        &fixture.home().join(".codex/sessions"),
        "2026/01/rollout-legacy.jsonl",
        "sess-sync-legacy-codex",
        "the legacy codex question",
        "the legacy codex answer",
    );
    fixture.write_gemini(
        &fixture.home().join(".gemini/tmp"),
        "hash123/chats/session-test.json",
        GEMINI_FIXTURE,
    );

    let output = fixture.sync(&stub.base_url, &[]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(0),
        "a mixed round with a legacy connector is complete: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(report["complete"], serde_json::json!(true));

    let db = fixture.open_db();
    assert_eq!(
        complete_inputs(&db),
        2,
        "the two fidelity connectors each complete one input"
    );
    assert_eq!(
        inputs_with_committed_receipt(&db),
        2,
        "each fidelity input has its committed receipt"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_inputs WHERE connector = 'gemini'"
        ),
        0,
        "the legacy connector is never asked for a source input"
    );
    // Per-input for the two fidelity connectors in the mixed round.
    for locator in ["legacy/proj/session.jsonl", "2026/01/rollout-legacy.jsonl"] {
        assert_eq!(
            complete_rows_for(&db, locator),
            1,
            "{locator}: this mixed-round input itself is complete"
        );
        assert_eq!(
            committed_receipts_for(&db, locator),
            1,
            "{locator}: this mixed-round input itself owns a committed receipt"
        );
    }
    assert!(
        count_like(&db, "Gemini hello") > 0 && count_like(&db, "Hello from Gemini!") > 0,
        "both Gemini message bodies reach the canonical store: {:?}",
        canonical_bodies(&db)
    );
    let gemini_conversations = count(
        &db,
        "SELECT COUNT(*) FROM conversations c JOIN agents a ON a.id = c.agent_id
         WHERE a.slug = 'gemini'",
    );
    assert!(
        gemini_conversations > 0,
        "the Gemini conversation keeps its canonical projection"
    );
    assert!(
        count_like(&db, "the legacy claude answer") > 0,
        "the Claude body lands"
    );
    assert!(
        count_like(&db, "the legacy codex answer") > 0,
        "the Codex body lands"
    );
}
