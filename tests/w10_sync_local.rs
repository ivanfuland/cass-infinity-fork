//! PR10 task 05 — the local half of `cass sync`, end to end.
//!
//! Four behaviours, all through the real `cass` binary against an isolated
//! HOME / XDG / `--data-dir` and a canned Infinity stub:
//!
//! 1. `sync_indexes_locally_without_remote_sources` — a config with no
//!    sources still runs exactly one index, ingests a new local session,
//!    reports `mirror.sources = []`, and is idempotent on a second pass.
//! 2. `sync_no_ingest_ignores_a_broken_sources_config` — `--no-ingest` never
//!    reads `sources.toml` (so a corrupt one cannot stop it), scans nothing,
//!    and leaves the corpus and both watermark tables byte-identical.
//! 3. `sync_result_contract` — the 0 / 1 / 2 / 3 exit codes, each checked as
//!    a stdout JSON object whose `exit_code` equals the process status; plus
//!    `--full` being a clap usage error.
//! 4. `semantic_activation_decides_exit_3` — the post-index decision table
//!    itself, including the `semantic_activated = false` arm that the
//!    end-to-end fixtures cannot reach (see the note in test 3).
//!
//! The Infinity stub is a deliberate copy of the one in
//! `tests/w8_t6b_ingest.rs`: `tests/util/` is outside this task's write
//! surface, and the two stubs answering the same canned wire shape is
//! cheaper to review than a shared helper quietly changing under both.

mod util;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use coding_agent_search::storage::api::{Profile, Value};
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::testing::open_writable_for_tests;
use coding_agent_search::sync::{
    EXIT_INTERNAL, EXIT_PARTIAL, EXIT_PRECONDITION, EXIT_READY, IndexOutcome, REASON_MIRROR_FAILED,
    REASON_SEMANTIC_NOT_READY, classify_index_outcome,
};
use tempfile::TempDir;
use util::seed_codex_session;

/// `src/search/infinity.rs::DIMENSION` — the served dimension the probe
/// validates the advertised model against.
const EMBED_DIM: usize = 1024;
/// Kept in step with the fallback in `InfinityConfig::from_env`.
const EMBED_MODEL: &str = "BAAI/bge-m3";

const SCHEMA: &str = "cass.sync.v1";

// ---------------------------------------------------------------------------
// Canned Infinity stub (mirrors tests/w8_t6b_ingest.rs)
// ---------------------------------------------------------------------------

struct StubInfinity {
    base_url: String,
    wake_addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for StubInfinity {
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

impl StubInfinity {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind infinity stub");
        listener
            .set_nonblocking(true)
            .expect("set infinity stub nonblocking");
        let addr = listener.local_addr().expect("stub address");
        let wake_addr = addr.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => handle_request(stream),
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

fn handle_request(mut stream: TcpStream) {
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
            let msg = format!("infinity stub: unexpected model {model:?}");
            format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                msg.len(),
                msg
            )
        } else {
            // `http_embed` requires `data[].index` to permute 0..N-1.
            // Vectors must be distinct per input text: the activation
            // audit's ownership check asks each chunk's row to be its own
            // nearest neighbour, so collinear vectors would make every
            // chunk match every other one.
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

/// A port nobody is listening on: bind, read the address, drop the listener.
fn closed_port_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("ephemeral address");
    drop(listener);
    format!("http://{addr}")
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    tmp: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("cass-data")).expect("create data dir");
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

    fn sources_config_path(&self) -> PathBuf {
        self.tmp
            .path()
            .join("xdg-config")
            .join("cass")
            .join("sources.toml")
    }

    fn write_sources_config(&self, body: &str) {
        let path = self.sources_config_path();
        std::fs::create_dir_all(path.parent().expect("config parent")).expect("create config dir");
        std::fs::write(&path, body).expect("write sources.toml");
    }

    /// The connector only ingests files whose basename starts with `rollout-`.
    fn seed_session(&self, filename: &str, marker: &str) {
        seed_codex_session(&self.codex_home(), filename, marker, true);
    }

    /// Every env var the child needs. The isolation is explicit per child
    /// rather than via `EnvGuard`, so these tests share no process-global
    /// state and stay safe under cargo's default parallel test threads.
    fn command(&self) -> Command {
        let mut cmd = Command::new(util::cass_bin());
        cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
        cmd.env("HOME", self.home());
        cmd.env("CODEX_HOME", self.codex_home());
        cmd.env("XDG_DATA_HOME", self.home().join(".local/share"));
        cmd.env("XDG_CONFIG_HOME", self.tmp.path().join("xdg-config"));
        cmd.env("CASS_RESPONSIVENESS_DISABLE", "1");
        cmd.env("CASS_TANTIVY_REBUILD_WORKERS", "1");
        // Never inherit an operator/CI opt-out: several other suites set it,
        // and this suite's whole point is that the config IS consulted.
        cmd.env_remove("CASS_IGNORE_SOURCES_CONFIG");
        cmd.env_remove("CASS_DATA_DIR");
        cmd.env_remove("CASS_OUTPUT_FORMAT");
        cmd.env_remove("TOON_DEFAULT_FORMAT");
        cmd
    }

    /// One `cass sync --json` round against the fixture.
    fn sync_json(&self, infinity_url: &str, extra: &[&str]) -> Output {
        let mut cmd = self.command();
        cmd.env("CASS_INFINITY_URL", infinity_url);
        cmd.args(["sync", "--json", "--data-dir"]);
        cmd.arg(self.data_dir());
        cmd.args(extra);
        cmd.output().expect("spawn cass sync")
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Parse stdout as exactly one JSON object. `serde_json::from_slice` only
/// accepts a single trailing document, so a second object or any prose on
/// stdout fails here rather than being silently ignored.
fn json_of(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not exactly one JSON object ({e}); stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            stderr_of(output)
        )
    })
}

/// Parse the report and cross-check it against the process status.
fn report_of(output: &Output) -> serde_json::Value {
    let payload = json_of(output);
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
    payload
}

fn db_scalar(db_path: &Path, sql: &str) -> i64 {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_row_map(sql, &[], |row| row.get_typed(0))
        .unwrap_or_else(|e| panic!("query {sql:?}: {e}"))
}

/// Every row of a one-column projection, joined — used to compare a whole
/// watermark table before/after without depending on row order.
fn table_rows(db_path: &Path, sql: &str) -> Vec<String> {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_all_map(sql, &[], |row| row.get_typed::<String>(0))
        .unwrap_or_else(|e| panic!("query {sql:?}: {e}"))
}

const WATERMARK_ROWS: &str = "SELECT root_id || '|' || connector || '|' || last_scan_ts \
     FROM scan_watermarks ORDER BY root_id, connector";
const FILE_STATE_ROWS: &str = "SELECT root_id || '|' || connector || '|' || relative_path || '|' \
     || size || '|' || mtime FROM scan_file_state ORDER BY root_id, connector, relative_path";

// ---------------------------------------------------------------------------
// AC B1 — no remote sources still means exactly one index
// ---------------------------------------------------------------------------

#[test]
fn sync_indexes_locally_without_remote_sources() {
    let fixture = Fixture::new();
    let stub = StubInfinity::start();
    fixture.seed_session("rollout-alpha.jsonl", "w10-alpha");

    // First pass: the fixture starts from no database at all.
    let first = fixture.sync_json(&stub.base_url, &[]);
    let report = report_of(&first);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_READY),
        "a source-less sync with a live Infinity must be ready: {report} stderr={}",
        stderr_of(&first)
    );
    assert_eq!(
        report["mirror"]["sources"],
        serde_json::json!([]),
        "no configured sources means an empty mirror array: {report}"
    );
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(true),
        "the local index must run even with nothing to mirror: {report}"
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
        "the local index must actually scan the HOME roots: {report}"
    );
    assert_eq!(
        report["partial_reasons"],
        serde_json::json!([]),
        "a ready round has no partial reasons: {report}"
    );

    let db = fixture.db_path();
    let sessions_after_first = db_scalar(&db, "SELECT COUNT(*) FROM conversations");
    let messages_after_first = db_scalar(&db, "SELECT COUNT(*) FROM messages");
    assert_eq!(
        sessions_after_first, 1,
        "the seeded session must be ingested"
    );
    assert!(messages_after_first >= 2, "seeded session has two messages");

    // Second pass: nothing changed, so nothing new is ingested.
    let second = fixture.sync_json(&stub.base_url, &[]);
    let report = report_of(&second);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_READY),
        "{report}"
    );
    assert_eq!(
        db_scalar(&db, "SELECT COUNT(*) FROM conversations"),
        sessions_after_first,
        "a second pass must not add conversations"
    );
    assert_eq!(
        db_scalar(&db, "SELECT COUNT(*) FROM messages"),
        messages_after_first,
        "a second pass must not add messages"
    );
    // The index still RAN on the no-op pass -- `index.started` and a
    // published stats block are the evidence, not a scan count: a root
    // whose watermarks say "nothing changed" legitimately invokes no
    // connector at all. The point is that the local index is never skipped
    // because a mirror transferred zero files.
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(true),
        "the index must still run on a no-op pass: {report}"
    );
    assert!(
        report["index"]["stats"].is_object(),
        "a run that reached the indexer must publish its stats: {report}"
    );

    // Third pass: exactly one new session lands, and exactly one new
    // conversation appears. This is the pass where a connector scan must
    // actually be invoked -- there is a changed file to look at.
    fixture.seed_session("rollout-beta.jsonl", "w10-beta");
    let third = fixture.sync_json(&stub.base_url, &[]);
    let report = report_of(&third);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_READY),
        "{report}"
    );
    assert_eq!(
        db_scalar(&db, "SELECT COUNT(*) FROM conversations"),
        sessions_after_first + 1,
        "one new local session must add exactly one conversation"
    );
    assert!(
        db_scalar(&db, "SELECT COUNT(*) FROM messages") > messages_after_first,
        "the new session's messages must be ingested"
    );
    assert!(
        report["index"]["stats"]["scan_invocations"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "a pass with a new local session must really scan the connector roots: {report}"
    );
}

// ---------------------------------------------------------------------------
// AC B2 — --no-ingest reads no config and touches no corpus state
// ---------------------------------------------------------------------------

#[test]
fn sync_no_ingest_ignores_a_broken_sources_config() {
    let fixture = Fixture::new();
    let stub = StubInfinity::start();
    fixture.seed_session("rollout-first.jsonl", "w10-noingest-first");

    // Build a real corpus first, so "unchanged" is a meaningful claim.
    let warmup = fixture.sync_json(&stub.base_url, &[]);
    assert_eq!(
        warmup.status.code(),
        Some(EXIT_READY),
        "warmup sync must succeed: {}",
        stderr_of(&warmup)
    );

    let db = fixture.db_path();
    let sessions_before = db_scalar(&db, "SELECT COUNT(*) FROM conversations");
    let messages_before = db_scalar(&db, "SELECT COUNT(*) FROM messages");
    let watermarks_before = table_rows(&db, WATERMARK_ROWS);
    let file_state_before = table_rows(&db, FILE_STATE_ROWS);
    assert!(
        !file_state_before.is_empty(),
        "the warmup run must have recorded per-file scan state"
    );

    // A session the scan WOULD find, plus a config it must not even read.
    fixture.seed_session("rollout-second.jsonl", "w10-noingest-second");
    fixture.write_sources_config("this is not = valid toml [[[");

    let output = fixture.sync_json(&stub.base_url, &["--no-ingest"]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_READY),
        "a corrupt sources.toml must not stop --no-ingest: {report} stderr={}",
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
        "the mirror stage must be reported as skipped, not as empty: {report}"
    );
    assert_eq!(
        report["mirror"]["sources"],
        serde_json::json!([]),
        "--no-ingest pulls no sources: {report}"
    );

    assert_eq!(
        db_scalar(&db, "SELECT COUNT(*) FROM conversations"),
        sessions_before,
        "--no-ingest must not ingest the newly seeded session"
    );
    assert_eq!(
        db_scalar(&db, "SELECT COUNT(*) FROM messages"),
        messages_before,
        "--no-ingest must not change the message set"
    );
    assert_eq!(
        table_rows(&db, WATERMARK_ROWS),
        watermarks_before,
        "--no-ingest must not move any root watermark"
    );
    assert_eq!(
        table_rows(&db, FILE_STATE_ROWS),
        file_state_before,
        "--no-ingest must not touch per-file scan state"
    );
}

// ---------------------------------------------------------------------------
// AC B3 — the 0 / 1 / 2 / 3 contract
// ---------------------------------------------------------------------------

#[test]
fn sync_precondition_failures_exit_2() {
    let stub = StubInfinity::start();

    // --- a config that exists but does not load -------------------------
    {
        let fixture = Fixture::new();
        fixture.seed_session("rollout-cfg.jsonl", "w10-cfg");
        fixture.write_sources_config("this is not = valid toml [[[");

        let output = fixture.sync_json(&stub.base_url, &[]);
        let report = report_of(&output);
        assert_eq!(
            report["exit_code"],
            serde_json::json!(EXIT_PRECONDITION),
            "a corrupt sources.toml is a precondition failure: {report}"
        );
        assert_eq!(
            report["error"]["kind"],
            serde_json::json!("config"),
            "a bad config must name itself: {report}"
        );
        assert_eq!(
            report["index"]["started"],
            serde_json::json!(false),
            "the index must not start on a bad config: {report}"
        );
        assert!(
            !fixture.db_path().exists(),
            "a bad config must fail before the database is created"
        );
    }

    // --- a database older than this binary's schema ----------------------
    {
        let fixture = Fixture::new();
        fixture.seed_session("rollout-old.jsonl", "w10-old");

        let warmup = fixture.sync_json(&stub.base_url, &[]);
        assert_eq!(
            warmup.status.code(),
            Some(EXIT_READY),
            "warmup sync must succeed: {}",
            stderr_of(&warmup)
        );

        // Downgrade the version stamp only; the file stays a real archive.
        {
            let conn = open_writable_for_tests(&fixture.db_path(), Profile::Production)
                .expect("open writer for the downgrade");
            conn.execute_batch("PRAGMA user_version = 4;")
                .expect("stamp an older schema version");
            conn.close().expect("close writer");
        }

        let output = fixture.sync_json(&stub.base_url, &[]);
        let report = report_of(&output);
        assert_eq!(
            report["exit_code"],
            serde_json::json!(EXIT_PRECONDITION),
            "a schema-4 archive is rebuild-only, so it is a precondition failure: {report}"
        );
        assert_eq!(
            report["error"]["kind"],
            serde_json::json!("rebuild-error"),
            "an old schema must name the rebuild requirement: {report}"
        );
        assert_eq!(
            report["index"]["started"],
            serde_json::json!(false),
            "the index must not start against an old schema: {report}"
        );
    }

    // --- Infinity not answering -------------------------------------------
    {
        let fixture = Fixture::new();
        fixture.seed_session("rollout-inf.jsonl", "w10-inf");
        let unreachable = closed_port_url();

        let output = fixture.sync_json(&unreachable, &[]);
        let report = report_of(&output);
        assert_eq!(
            report["exit_code"],
            serde_json::json!(EXIT_PRECONDITION),
            "an unreachable Infinity is a precondition failure: {report}"
        );
        assert_eq!(
            report["error"]["kind"],
            serde_json::json!("semantic-unavailable"),
            "an unreachable Infinity must be named as such: {report}"
        );
        assert_eq!(
            report["index"]["started"],
            serde_json::json!(false),
            "the index must not start without a semantic backend: {report}"
        );
    }
}

#[test]
fn sync_partial_round_exits_3() {
    let fixture = Fixture::new();
    let stub = StubInfinity::start();
    fixture.seed_session("rollout-partial.jsonl", "w10-partial");
    // One declared source. Task 05 has no mirror stage, so this round's
    // remote half is not done -- which is a partial round (3), not a
    // failure (1) and certainly not a success (0).
    fixture.write_sources_config(
        r#"
[[sources]]
name = "bench-a"
type = "ssh"
host = "cass-fixture@127.0.0.1"
origin_host = "bench-a"
paths = ["~/.codex/sessions"]
"#,
    );

    let output = fixture.sync_json(&stub.base_url, &[]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_PARTIAL),
        "an unsynced configured source makes the round partial: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(
        report["partial_reasons"],
        serde_json::json!([REASON_MIRROR_FAILED]),
        "the partial reason must name the mirror: {report}"
    );
    assert_eq!(
        report["mirror"]["sources"][0]["name"],
        serde_json::json!("bench-a"),
        "the declared source must be reported by name: {report}"
    );
    assert_ne!(
        report["mirror"]["sources"][0]["status"],
        serde_json::json!("success"),
        "a source that was not pulled must never read as success: {report}"
    );
    assert!(
        report["mirror"]["sources"][0]["error"].is_string(),
        "the source must carry the reason it was not synced: {report}"
    );
    // Hard constraint 2: a mirror that did not run still does not skip the
    // local index.
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(true),
        "a failed mirror half must not skip the local index: {report}"
    );
    assert_eq!(
        report["semantic_activated"],
        serde_json::json!(true),
        "the local half still reached semantic activation: {report}"
    );
}

#[test]
fn sync_unidentified_index_failure_exits_1() {
    let fixture = Fixture::new();
    let stub = StubInfinity::start();
    fixture.seed_session("rollout-broken.jsonl", "w10-broken");

    // A directory where the database belongs: it exists, so the schema
    // preflight cannot classify it, and every real open fails. That is
    // exactly the "unidentified internal failure" bucket.
    std::fs::create_dir_all(fixture.db_path()).expect("create directory at the db path");

    let output = fixture.sync_json(&stub.base_url, &[]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_INTERNAL),
        "an unclassifiable index failure must land in 1: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(
        report["error"]["kind"],
        serde_json::json!("index"),
        "an internal index failure must name the index: {report}"
    );
    assert_eq!(
        report["complete"],
        serde_json::json!(false),
        "a failed round is never complete: {report}"
    );
}

#[test]
fn sync_rejects_full_as_a_usage_error() {
    let fixture = Fixture::new();
    let stub = StubInfinity::start();

    let mut cmd = fixture.command();
    cmd.env("CASS_INFINITY_URL", &stub.base_url);
    cmd.args(["sync", "--full", "--data-dir"]);
    cmd.arg(fixture.data_dir());
    let output = cmd.output().expect("spawn cass sync --full");

    assert_eq!(
        output.status.code(),
        Some(2),
        "`sync` has no --full; clap must refuse it with the usage exit code. \
         stdout={:?} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        stderr_of(&output)
    );
}

// ---------------------------------------------------------------------------
// AC B3 — the post-index decision table, including the unreachable arm
// ---------------------------------------------------------------------------

#[test]
fn semantic_activation_decides_exit_3() {
    // The end-to-end fixtures above cannot reach this arm: the drain's
    // post-loop invariant (`assert_drain_completed_or_bail`) bails the whole
    // run if any `chunk_holes` row survives, and reverse-reconciliation only
    // prunes, so `holes_after == 0` -- and therefore `activated == true` --
    // on every run that returns Ok. The classification is still this task's
    // product behaviour, so it is pinned directly here.
    let (code, reasons, error) = classify_index_outcome(IndexOutcome::Completed(false), false);
    assert_eq!(
        code, EXIT_PARTIAL,
        "an unactivated semantic domain is partial"
    );
    assert_eq!(reasons, vec![REASON_SEMANTIC_NOT_READY]);
    assert_eq!(
        error.expect("a partial round carries a reason").kind,
        "semantic-unavailable"
    );

    // Both partial causes at once are preserved (hard constraint 5/6).
    let (code, reasons, _) = classify_index_outcome(IndexOutcome::Completed(false), true);
    assert_eq!(code, EXIT_PARTIAL);
    assert_eq!(
        reasons,
        vec![REASON_MIRROR_FAILED, REASON_SEMANTIC_NOT_READY]
    );

    // Ready: only when nothing is partial.
    let (code, reasons, error) = classify_index_outcome(IndexOutcome::Completed(true), false);
    assert_eq!(code, EXIT_READY);
    assert!(reasons.is_empty());
    assert!(error.is_none());

    // Ready locally, but the remote half did not run.
    let (code, reasons, error) = classify_index_outcome(IndexOutcome::Completed(true), true);
    assert_eq!(code, EXIT_PARTIAL);
    assert_eq!(reasons, vec![REASON_MIRROR_FAILED]);
    assert_eq!(error.expect("partial carries a reason").kind, "source");

    // An index that published no semantic fact must not report success.
    let (code, _, error) =
        classify_index_outcome(IndexOutcome::CompletedWithoutSemanticFact, false);
    assert_eq!(code, EXIT_INTERNAL);
    assert_eq!(error.expect("failure carries a reason").kind, "index");

    // A real index error is an internal failure whether or not the mirror ran.
    let (code, reasons, error) =
        classify_index_outcome(IndexOutcome::Failed("boom".to_string()), false);
    assert_eq!(code, EXIT_INTERNAL);
    assert!(reasons.is_empty());
    assert_eq!(error.expect("failure carries a reason").kind, "index");
}

// ---------------------------------------------------------------------------
// The value type is exported where the report needs it
// ---------------------------------------------------------------------------

#[test]
fn sync_report_values_are_readable_from_a_plain_sqlite_handle() {
    // Guards the fixture helpers above: a raw read of the archive must see
    // the schema this suite's watermark comparisons rely on.
    let fixture = Fixture::new();
    let stub = StubInfinity::start();
    fixture.seed_session("rollout-read.jsonl", "w10-read");
    let output = fixture.sync_json(&stub.base_url, &[]);
    assert_eq!(
        output.status.code(),
        Some(EXIT_READY),
        "{}",
        stderr_of(&output)
    );

    let watermark_count = db_scalar(&fixture.db_path(), "SELECT COUNT(*) FROM scan_watermarks");
    assert!(
        watermark_count > 0,
        "a real ingest must record at least one root watermark"
    );

    let storage = FrankenStorage::open_readonly(&fixture.db_path()).expect("read-only open");
    let names: Vec<String> = storage
        .raw()
        .query_all_map("SELECT name FROM agents ORDER BY name", &[], |row| {
            row.get_typed::<String>(0)
        })
        .expect("query agents");
    assert!(
        names.iter().any(|n| n.contains("codex")),
        "the seeded Codex fixture must register a codex agent, got {names:?}"
    );
    let _ = Value::from("unused");
}
