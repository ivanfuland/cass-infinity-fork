//! API03G: `cass sync`'s semantic preflight is a **real** service check.
//!
//! Before this fix `preflight_semantic` only loaded the frozen API
//! configuration; it never contacted the endpoint. So a configured-but-
//! unreachable embedding service stopped the round *after* the mirror stage and
//! *after* `run_index` had already created the database and ingested sessions,
//! which is exactly the behaviour the pre-API `cass sync` refused to have.
//!
//! Every test here runs the real `cass` binary against a real configuration
//! file, a real loopback HTTP service and (where relevant) a real synthetic
//! SQLite archive. Nothing stubs the CLI, the transport or the store. The model
//! ids, revisions and endpoints are synthetic and public; the only traffic is to
//! a loopback stub bound on an ephemeral port, never to a real service.
//!
//! Global state: none. Each test owns a `TempDir`, its own loopback listener and
//! its own child environment, so the file is safe under cargo's default parallel
//! test threads.

mod util;

use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use coding_agent_search::storage::sqlite::FrankenStorage;

const EMBED_MODEL: &str = "example/synthetic-embed";
const EMBED_REVISION: &str = "rev-synthetic-1";
const EMBED_PATH: &str = "/v1/embeddings";
const CLOUD_MODEL: &str = "example/synthetic-embed-cloud";
const SCHEMA: &str = "cass.sync.v1";

/// The closed retired-model-selection environment list (spec §5.3). Cleared for
/// every child so a stray operator variable cannot change the round under test.
const RETIRED_ENV: [&str; 7] = [
    "CASS_INFINITY_URL",
    "CASS_INFINITY_EMBED_MODEL",
    "CASS_INFINITY_RERANK_MODEL",
    "CASS_QWEN_RERANK_URL",
    "CASS_SEMANTIC_EMBEDDER",
    "CASS_SEMANTIC_DOWNLOAD_POLICY",
    "CASS_SEMANTIC_MAX_MODEL_SIZE_MB",
];

// ---------------------------------------------------------------------------
// A loopback HTTP service that records every request it answers
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

impl RecordedRequest {
    fn body_json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    /// The `model` the request asked for, when it carried one.
    fn request_model(&self) -> String {
        self.body_json()
            .get("model")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    /// The request's `input` entries, each rendered as a string. Embedding
    /// inputs are strings, so this is the wire text the service would embed.
    fn inputs(&self) -> Vec<String> {
        self.body_json()
            .get("input")
            .and_then(serde_json::Value::as_array)
            .map(|rows| {
                rows.iter()
                    .map(|row| row.as_str().unwrap_or_default().to_string())
                    .collect()
            })
            .unwrap_or_default()
    }
}

type Responder = Arc<dyn Fn(&RecordedRequest, usize) -> (u16, String) + Send + Sync>;

struct Stub {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<RecordedRequest>>>,
    stop: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Stub {
    fn start<F>(responder: F) -> Stub
    where
        F: Fn(&RecordedRequest, usize) -> (u16, String) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind model stub");
        let addr = listener.local_addr().expect("stub local_addr");
        listener.set_nonblocking(true).expect("stub nonblocking");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let responder: Responder = Arc::new(responder);

        let seen_thread = Arc::clone(&seen);
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Some(request) = read_http_request(stream.try_clone().expect("clone"))
                        {
                            let index = {
                                let mut guard = seen_thread.lock().expect("stub lock");
                                let index = guard.len();
                                guard.push(request.clone());
                                index
                            };
                            let (status, body) = responder(&request, index);
                            let _ = write_http_response(stream, status, &body);
                        }
                    }
                    Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Stub {
            addr,
            seen,
            stop,
            handle: Mutex::new(Some(handle)),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}{EMBED_PATH}", self.addr)
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.seen.lock().expect("stub lock").clone()
    }

    fn request_count(&self) -> usize {
        self.seen.lock().expect("stub lock").len()
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.lock().expect("stub thread lock").take() {
            let _ = handle.join();
        }
    }
}

/// A listener that counts inbound connections and answers none.
///
/// It stands in for the cloud fallback so "the fallback was never contacted" is
/// provable: an unreachable address cannot show that, because a refused connect
/// looks the same whether or not anything tried it. Any attempt is recorded
/// before TLS could fail. `https://` on loopback is what the configuration
/// kernel requires of a `remote` profile.
struct ConnectionSpy {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl ConnectionSpy {
    fn start() -> Self {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind spy");
        let addr = listener.local_addr().expect("spy addr");
        listener.set_nonblocking(true).expect("spy nonblocking");
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let connections_thread = Arc::clone(&connections);
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        connections_thread.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        ConnectionSpy {
            addr,
            connections,
            stop,
            handle: Mutex::new(Some(handle)),
        }
    }

    fn endpoint(&self) -> String {
        format!("https://{}{EMBED_PATH}", self.addr)
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for ConnectionSpy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.lock().expect("spy thread lock").take() {
            let _ = handle.join();
        }
    }
}

/// A port nobody is listening on: bind, read the address, drop the listener.
fn refused_endpoint() -> String {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("ephemeral addr");
    drop(listener);
    format!("http://{addr}{EMBED_PATH}")
}

fn read_http_request(mut stream: TcpStream) -> Option<RecordedRequest> {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = find_header_end(&buffer) {
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
            let body = buffer.get(body_start..).unwrap_or_default().to_vec();
            return Some(RecordedRequest { method, path, body });
        }
    }
    None
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_http_response(mut stream: TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

// ---------------------------------------------------------------------------
// Synthetic embedding responses
// ---------------------------------------------------------------------------

/// A deterministic vector for `text`, offset by `drift`.
fn vector_for(text: &str, dim: usize, drift: u64) -> Vec<f64> {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash = hash.wrapping_add(drift.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    (0..dim)
        .map(|j| {
            let mixed = hash.wrapping_add((j as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9));
            ((mixed >> 33) % 1000) as f64 / 1000.0 + 0.5
        })
        .collect()
}

fn embed_body(inputs: &[String], dim: usize, model: &str, drift: u64) -> String {
    let data: Vec<serde_json::Value> = inputs
        .iter()
        .enumerate()
        .map(|(index, text)| {
            serde_json::json!({
                "object": "embedding",
                "index": index,
                "embedding": vector_for(text, dim, drift),
            })
        })
        .collect();
    serde_json::json!({
        "object": "list",
        "data": data,
        "model": model,
        "usage": {"prompt_tokens": inputs.len(), "total_tokens": inputs.len()},
    })
    .to_string()
}

/// A responder that answers every embedding request with `dim`-wide vectors and
/// echoes the model the request carried.
fn healthy_responder(dim: usize, drift: u64) -> impl Fn(&RecordedRequest, usize) -> (u16, String) {
    move |request: &RecordedRequest, _index: usize| {
        let model = request.request_model();
        let model = if model.is_empty() {
            EMBED_MODEL.to_string()
        } else {
            model
        };
        (200, embed_body(&request.inputs(), dim, &model, drift))
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

fn config_text(profiles: &str) -> String {
    format!("version = 1\ndefault_embedding = \"local\"\n\n{profiles}")
}

fn embedding_profile_block(
    id: &str,
    endpoint: &str,
    model: &str,
    revision: &str,
    extra: &str,
) -> String {
    format!(
        "[profiles.{id}]\n\
         kind = \"embedding\"\n\
         protocol = \"openai-embeddings-v1\"\n\
         endpoint = \"{endpoint}\"\n\
         scope = \"loopback\"\n\
         model = \"{model}\"\n\
         model_revision = \"{revision}\"\n\
         normalization = \"l2\"\n\
         max_batch = 64\n\
         {extra}\n"
    )
}

fn local_config(endpoint: &str) -> String {
    config_text(&embedding_profile_block(
        "local",
        endpoint,
        EMBED_MODEL,
        EMBED_REVISION,
        "",
    ))
}

/// A loopback primary that declares a remote cloud fallback, with **no**
/// compatibility evidence file — so the fallback may never be used.
fn fallback_config_without_proof(endpoint: &str, cloud_endpoint: &str) -> String {
    let mut local = embedding_profile_block("local", endpoint, EMBED_MODEL, EMBED_REVISION, "");
    local.push_str("fallback_profile = \"cloud\"\n");
    let cloud = format!(
        "[profiles.cloud]\n\
         kind = \"embedding\"\n\
         protocol = \"openrouter-embeddings-v1\"\n\
         endpoint = \"{cloud_endpoint}\"\n\
         scope = \"remote\"\n\
         model = \"{CLOUD_MODEL}\"\n\
         model_revision = \"rev-cloud-1\"\n\
         normalization = \"l2\"\n\
         provider_only = \"pinned-vendor\"\n"
    );
    config_text(&format!("{local}{cloud}"))
}

/// Two loopback profiles, with `default` naming the one the round should pick.
/// Written twice by the config-freeze test: first with `local` selected, then
/// with `second` selected, to prove the round kept the frozen first choice.
fn two_profile_config(local_endpoint: &str, second_endpoint: &str, default: &str) -> String {
    let local = embedding_profile_block("local", local_endpoint, EMBED_MODEL, EMBED_REVISION, "");
    let second =
        embedding_profile_block("second", second_endpoint, EMBED_MODEL, EMBED_REVISION, "");
    format!("version = 1\ndefault_embedding = \"{default}\"\n\n{local}{second}")
}

// ---------------------------------------------------------------------------
// CLI harness
// ---------------------------------------------------------------------------

struct Fixture {
    tmp: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(tmp.path().join("cass-data")).expect("create data dir");
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

    /// The connector only ingests files whose basename starts with `rollout-`.
    fn seed_session(&self, filename: &str, marker: &str) {
        util::seed_codex_session(&self.codex_home(), filename, marker, true);
    }

    fn write_config(&self, name: &str, body: &str) -> PathBuf {
        let path = self.tmp.path().join(name);
        fs::write(&path, body).expect("write api config");
        path
    }

    /// Every env var the child needs, isolated per child rather than via a
    /// process global, so these tests share no state under parallel threads.
    fn command(&self) -> Command {
        let mut cmd = Command::new(util::cass_bin());
        cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
        cmd.env("HOME", self.home());
        cmd.env("CODEX_HOME", self.codex_home());
        cmd.env("XDG_DATA_HOME", self.home().join(".local/share"));
        cmd.env("XDG_CONFIG_HOME", self.tmp.path().join("xdg-config"));
        cmd.env("CASS_RESPONSIVENESS_DISABLE", "1");
        cmd.env("CASS_TANTIVY_REBUILD_WORKERS", "1");
        // The semantic finalize progress ticker sleeps its whole interval before
        // it can stop (default 60000 ms), so a healthy round's tail can cost a
        // minute. Shorten it for this fixture only; the production default and
        // implementation are untouched, and every business/side-effect
        // assertion is unchanged.
        cmd.env("CASS_SEMANTIC_FINALIZE_PROGRESS_EVERY_MS", "10");
        for variable in RETIRED_ENV {
            cmd.env_remove(variable);
        }
        cmd.env_remove("CASS_API_CONFIG");
        cmd.env_remove("CASS_DATA_DIR");
        cmd.env_remove("CASS_IGNORE_SOURCES_CONFIG");
        cmd.env_remove("CASS_OUTPUT_FORMAT");
        cmd.env_remove("TOON_DEFAULT_FORMAT");
        cmd
    }

    /// One `cass sync --json` round, optionally with `--api-config`.
    fn sync_json(&self, config: Option<&Path>, extra: &[&str]) -> Output {
        let mut cmd = self.command();
        cmd.args(["sync", "--json", "--data-dir"]);
        cmd.arg(self.data_dir());
        if let Some(config) = config {
            cmd.arg("--api-config").arg(config);
        }
        cmd.args(extra);
        cmd.output().expect("spawn cass sync")
    }

    /// One `cass sync --json` round whose only configuration is the environment.
    fn sync_json_env(&self, envs: &[(&str, &str)]) -> Output {
        let mut cmd = self.command();
        for (name, value) in envs {
            cmd.env(name, value);
        }
        cmd.args(["sync", "--json", "--data-dir"]);
        cmd.arg(self.data_dir());
        cmd.output().expect("spawn cass sync")
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn stdout_json(output: &Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&text).unwrap_or_else(|err| {
        panic!(
            "stdout must be one JSON document: {err}\n--- stdout ---\n{text}\n--- stderr ---\n{}",
            stderr_of(output)
        )
    })
}

/// Parse the report and cross-check it against the process status.
fn report_of(output: &Output) -> serde_json::Value {
    let payload = stdout_json(output);
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

/// Persist one round's raw stdout/stderr as inspectable evidence.
fn dump_round(name: &str, output: &Output) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("api03g-sync-preflight");
    fs::create_dir_all(&dir).expect("create evidence dir");
    let combined = format!(
        "exit={:?}\n--- stdout ---\n{}\n--- stderr ---\n{}\n",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    fs::write(dir.join(format!("{name}.txt")), combined).expect("write evidence");
}

fn db_scalar(db_path: &Path, sql: &str) -> i64 {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_row_map(sql, &[], |row| row.get_typed(0))
        .unwrap_or_else(|e| panic!("query {sql:?}: {e}"))
}

/// Every row of a one-column projection, joined — compares a whole table
/// before/after without depending on row order.
fn table_rows(db_path: &Path, sql: &str) -> Vec<String> {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_all_map(sql, &[], |row| row.get_typed::<String>(0))
        .unwrap_or_else(|e| panic!("query {sql:?}: {e}"))
}

const WATERMARK_ROWS: &str = "SELECT root_id || '|' || connector || '|' || last_scan_ts \
     FROM scan_watermarks ORDER BY root_id, connector";
const GENERATION_ROWS: &str = "SELECT id || '|' || embedder_id || '|' || dim || '|' || is_active || '|' || audit_status \
     FROM embedding_generations ORDER BY id";

/// The four facts a semantic precondition failure must always carry.
fn assert_semantic_precondition(report: &serde_json::Value) {
    assert_eq!(
        report["exit_code"],
        serde_json::json!(2),
        "a semantic precondition is exit 2: {report}"
    );
    assert_eq!(
        report["error"]["kind"],
        serde_json::json!("semantic-unavailable"),
        "the refusal must name itself semantic-unavailable: {report}"
    );
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(false),
        "the index must not start without a reachable semantic backend: {report}"
    );
    assert_eq!(
        report["complete"],
        serde_json::json!(false),
        "a refused round is not complete: {report}"
    );
    assert_eq!(
        report["mirror"]["attempted"],
        serde_json::json!(false),
        "the mirror stage must not run after a semantic precondition: {report}"
    );
}

/// The semantic preflight object, which is always present in the report.
fn preflight(report: &serde_json::Value) -> serde_json::Value {
    let value = report
        .get("semantic_preflight")
        .unwrap_or_else(|| panic!("the report must always carry semantic_preflight: {report}"))
        .clone();
    // When the preflight refused, its refusal is the round's refusal. A later
    // stage's failure is a different fact and must not be compared to it.
    if !value["error"].is_null() {
        assert_eq!(
            value["error"]["kind"], report["error"]["kind"],
            "the field's refusal is this round's refusal: {value} vs {report}"
        );
    }
    value
}

/// The probe requests the preflight's own call recorded, in order.
fn preflight_probe_calls(report: &serde_json::Value) -> Vec<serde_json::Value> {
    report["semantic_preflight"]["model_api"]["probe_calls"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// AC 1a — an unreachable configured endpoint is a precondition, no new database
// ---------------------------------------------------------------------------

#[test]
fn unreachable_endpoint_is_a_precondition_and_creates_no_database() {
    let fixture = Fixture::new();
    fixture.seed_session("rollout-unreachable.jsonl", "api03g-unreachable");
    let config = fixture.write_config("models.toml", &local_config(&refused_endpoint()));

    let output = fixture.sync_json(Some(&config), &[]);
    dump_round("unreachable-no-db", &output);
    let report = report_of(&output);
    assert_semantic_precondition(&report);
    let pre = preflight(&report);
    assert_eq!(pre["outcome"], serde_json::json!("failed"), "{pre}");
    assert_eq!(pre["profile"], serde_json::json!("local"), "{pre}");
    let calls = preflight_probe_calls(&report);
    assert_eq!(
        calls.len(),
        1,
        "one probe attempt must be recorded for a refused connect: {calls:?}"
    );
    assert_eq!(calls[0]["stage"], serde_json::json!("probe"), "{calls:?}");
    assert_eq!(
        calls[0]["http_status"],
        serde_json::Value::Null,
        "a refused connect has no HTTP status: {calls:?}"
    );
    assert!(
        !fixture.db_path().exists(),
        "a semantic precondition must fail before the database is created: {}",
        fixture.db_path().display()
    );
    assert!(
        stderr_of(&output).is_empty() || !stderr_of(&output).contains("api_key"),
        "no credential material may appear on stderr"
    );
}

// ---------------------------------------------------------------------------
// AC 1b — the same failure leaves an existing archive byte-for-byte logical
// ---------------------------------------------------------------------------

#[test]
fn unreachable_endpoint_leaves_an_existing_archive_unchanged() {
    let fixture = Fixture::new();
    fixture.seed_session("rollout-archive.jsonl", "api03g-archive");

    // A healthy round first, so a real generation and real watermarks exist.
    let healthy = Stub::start(healthy_responder(16, 7));
    let healthy_config =
        fixture.write_config("models-healthy.toml", &local_config(&healthy.endpoint()));
    let first = fixture.sync_json(Some(&healthy_config), &[]);
    dump_round("archive-warmup", &first);
    let first_report = report_of(&first);
    assert_eq!(
        first_report["exit_code"],
        serde_json::json!(0),
        "the warm-up round must succeed: {first_report} stderr={}",
        stderr_of(&first)
    );

    let db_path = fixture.db_path();
    let messages_before = db_scalar(&db_path, "SELECT COUNT(*) FROM messages");
    let generations_before = table_rows(&db_path, GENERATION_ROWS);
    let watermarks_before = table_rows(&db_path, WATERMARK_ROWS);
    assert!(
        messages_before > 0,
        "the warm-up must have ingested at least one message"
    );
    assert!(
        !generations_before.is_empty(),
        "the warm-up must have produced a semantic generation"
    );

    // Now point the round at a port nothing answers.
    let dead_config = fixture.write_config("models-dead.toml", &local_config(&refused_endpoint()));
    let second = fixture.sync_json(Some(&dead_config), &[]);
    dump_round("archive-unreachable", &second);
    let second_report = report_of(&second);
    assert_semantic_precondition(&second_report);

    assert_eq!(
        db_scalar(&db_path, "SELECT COUNT(*) FROM messages"),
        messages_before,
        "a refused round must not ingest anything"
    );
    assert_eq!(
        table_rows(&db_path, GENERATION_ROWS),
        generations_before,
        "a refused round must not change the generation table"
    );
    assert_eq!(
        table_rows(&db_path, WATERMARK_ROWS),
        watermarks_before,
        "a refused round must not move the scan watermarks"
    );
}

// ---------------------------------------------------------------------------
// A gateway may report its backend model without blocking the sync.
// ---------------------------------------------------------------------------

#[test]
fn a_backend_model_name_does_not_block_sync_preflight() {
    let fixture = Fixture::new();
    fixture.seed_session("rollout-identity.jsonl", "api03g-identity");
    // A service that answers 200 but names a different model than the profile.
    let stub = Stub::start(|request: &RecordedRequest, _index: usize| {
        (
            200,
            embed_body(&request.inputs(), 16, "someone/else-entirely", 3),
        )
    });
    let config = fixture.write_config("models.toml", &local_config(&stub.endpoint()));

    let output = fixture.sync_json(Some(&config), &[]);
    dump_round("backend-model-name", &output);
    let report = report_of(&output);
    assert_eq!(report["exit_code"], serde_json::json!(0), "{report}");
    assert!(
        fixture.db_path().exists(),
        "a successful gateway response must allow indexing"
    );
    assert!(
        db_scalar(&fixture.db_path(), "SELECT COUNT(*) FROM messages") > 0,
        "sync must ingest the synthetic session"
    );
    assert!(
        stub.request_count() >= 1,
        "the round must have really contacted the configured endpoint, not just \
         inspected the configuration"
    );
}

/// A service that cannot hold one width across the probe's own requests is
/// still refused before indexing.
#[test]
fn drifting_width_across_probe_requests_is_refused_before_any_index() {
    let fixture = Fixture::new();
    fixture.seed_session("rollout-width.jsonl", "api03g-width");
    // `max_batch = 1` forces the three probe sentinels into three requests; the
    // responder widens each one, so the probe cannot settle on one dimension.
    let stub = Stub::start(|request: &RecordedRequest, index: usize| {
        let model = request.request_model();
        let model = if model.is_empty() {
            EMBED_MODEL.to_string()
        } else {
            model
        };
        (200, embed_body(&request.inputs(), 8 + index, &model, 1))
    });
    let mut block =
        embedding_profile_block("local", &stub.endpoint(), EMBED_MODEL, EMBED_REVISION, "");
    block = block.replace("max_batch = 64", "max_batch = 1");
    let config = fixture.write_config("models.toml", &config_text(&block));

    let output = fixture.sync_json(Some(&config), &[]);
    dump_round("drifting-width", &output);
    let report = report_of(&output);
    assert_semantic_precondition(&report);
    assert_eq!(
        report["semantic_preflight"]["outcome"],
        serde_json::json!("failed"),
        "{report}"
    );
    assert!(
        preflight_probe_calls(&report).len() >= 2,
        "every probe attempt that reached the service must be recorded: {report}"
    );
    assert!(!fixture.db_path().exists());
    assert!(
        stub.request_count() >= 2,
        "the probe must have spanned more than one request"
    );
}

// ---------------------------------------------------------------------------
// AC 3 — a healthy service runs the round, and the calls come from the config
// ---------------------------------------------------------------------------

#[test]
fn healthy_endpoint_runs_the_round_after_a_real_probe() {
    let fixture = Fixture::new();
    fixture.seed_session("rollout-healthy.jsonl", "api03g-healthy");
    let stub = Stub::start(healthy_responder(16, 7));
    let config = fixture.write_config("models.toml", &local_config(&stub.endpoint()));

    let output = fixture.sync_json(Some(&config), &[]);
    dump_round("healthy", &output);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(0),
        "a healthy endpoint must let the round finish: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(true),
        "the index runs only after the probe succeeds: {report}"
    );
    assert_eq!(
        report["semantic_activated"],
        serde_json::json!(true),
        "the round must activate the semantic generation: {report}"
    );
    assert!(
        fixture.db_path().exists(),
        "a successful round creates the archive"
    );

    // The preflight stage's own fact, kept even though the round then indexed:
    // one probe answered, no refusal, and no document batch is counted as one.
    let pre = preflight(&report);
    assert_eq!(pre["outcome"], serde_json::json!("ok"), "{pre}");
    assert_eq!(pre["error"], serde_json::Value::Null, "{pre}");
    assert_eq!(pre["profile"], serde_json::json!("local"), "{pre}");
    assert_eq!(
        pre["model_api"]["document_calls"],
        serde_json::json!([]),
        "the preflight object holds no document batches: {pre}"
    );
    assert_eq!(
        pre["model_api"]["audit_calls"],
        serde_json::json!([]),
        "the preflight object holds no audit calls: {pre}"
    );
    let calls = preflight_probe_calls(&report);
    assert_eq!(
        calls.len(),
        1,
        "the preflight sends exactly one probe request for three sentinels: {calls:?}"
    );
    assert_eq!(
        calls[0]["network_attempted"],
        serde_json::json!(true),
        "{calls:?}"
    );
    assert_eq!(calls[0]["http_status"], serde_json::json!(200), "{calls:?}");

    // Every request landed on the configured endpoint, and at least one carried
    // the probe's three sentinels — the call really came from the configuration.
    let requests = stub.requests();
    assert!(
        !requests.is_empty(),
        "the configured endpoint must have been contacted"
    );
    assert!(
        requests.iter().all(|r| r.method == "POST"),
        "only POSTs are sent"
    );
    assert!(
        requests.iter().any(|r| r.inputs().len() == 3),
        "one request must be the three-sentinel probe: {requests:?}"
    );
}

// ---------------------------------------------------------------------------
// AC 4 — a fallback with no compatibility proof is never contacted
// ---------------------------------------------------------------------------

#[test]
fn fallback_without_proof_is_never_contacted() {
    let fixture = Fixture::new();
    fixture.seed_session("rollout-fallback.jsonl", "api03g-fallback");
    let cloud = ConnectionSpy::start();
    let config = fixture.write_config(
        "models.toml",
        &fallback_config_without_proof(&refused_endpoint(), &cloud.endpoint()),
    );

    let output = fixture.sync_json(Some(&config), &[]);
    dump_round("fallback-no-proof", &output);
    let report = report_of(&output);
    assert_semantic_precondition(&report);
    let pre = preflight(&report);
    assert_eq!(pre["outcome"], serde_json::json!("failed"), "{pre}");
    // The one attempt went to the primary, and the fallback was never chosen.
    let calls = preflight_probe_calls(&report);
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(
        calls[0]["profile_id"],
        serde_json::json!("local"),
        "{calls:?}"
    );
    assert_eq!(
        pre["model_api"]["fallback_used"],
        serde_json::json!(false),
        "{pre}"
    );
    assert!(
        !fixture.db_path().exists(),
        "a refused fallback must not create the database"
    );
    assert_eq!(
        cloud.connections(),
        0,
        "the cloud fallback must never be contacted without compatibility evidence"
    );
}

// ---------------------------------------------------------------------------
// AC 5 — no configuration at all is the same precondition, zero requests
// ---------------------------------------------------------------------------

#[test]
fn no_configured_profile_is_a_precondition_with_no_request() {
    let fixture = Fixture::new();
    fixture.seed_session("rollout-noconfig.jsonl", "api03g-noconfig");

    let output = fixture.sync_json(None, &[]);
    dump_round("no-config", &output);
    let report = report_of(&output);
    assert_semantic_precondition(&report);
    // The load was attempted and refused, so the field is present and failed —
    // with no profile and no call, because neither was ever obtained.
    let pre = preflight(&report);
    assert_eq!(pre["outcome"], serde_json::json!("failed"), "{pre}");
    assert_eq!(pre["profile"], serde_json::Value::Null, "{pre}");
    assert_eq!(pre["model_api"], serde_json::Value::Null, "{pre}");
    assert!(!fixture.db_path().exists());

    // The same refusal through the environment-only selection path.
    let env_output = fixture.sync_json_env(&[("CASS_API_CONFIG", "")]);
    dump_round("no-config-env", &env_output);
    let env_report = report_of(&env_output);
    assert_semantic_precondition(&env_report);
    let env_pre = preflight(&env_report);
    assert_eq!(env_pre["outcome"], serde_json::json!("failed"), "{env_pre}");
    assert_eq!(env_pre["profile"], serde_json::Value::Null);
    assert_eq!(env_pre["model_api"], serde_json::Value::Null);
    assert!(!fixture.db_path().exists());
}

// ---------------------------------------------------------------------------
// AC 6 — an existing file that is not a readable archive is refused, not probed
// ---------------------------------------------------------------------------

#[test]
fn unreadable_file_at_db_path_is_refused_before_any_probe() {
    let fixture = Fixture::new();
    fixture.seed_session("rollout-garbage.jsonl", "api03g-garbage");
    // A healthy endpoint, so the only reason this round can stop early is the
    // archive file itself.
    let stub = Stub::start(healthy_responder(16, 7));
    let config = fixture.write_config("models.toml", &local_config(&stub.endpoint()));

    // A non-empty regular file that is not a SQLite archive.
    fs::write(fixture.db_path(), b"this is not a sqlite database at all\n")
        .expect("write garbage at the db path");

    let output = fixture.sync_json(Some(&config), &[]);
    dump_round("unreadable-archive", &output);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(2),
        "an unreadable archive is a precondition: {report}"
    );
    assert_eq!(
        report["error"]["kind"],
        serde_json::json!("rebuild-error"),
        "an unusable archive must name the rebuild remedy: {report}"
    );
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(false),
        "nothing may be indexed over an unreadable archive: {report}"
    );
    assert_eq!(
        report["semantic_preflight"],
        serde_json::Value::Null,
        "the archive is refused before model configuration is even loaded: {report}"
    );
    assert_eq!(
        stub.request_count(),
        0,
        "an unreadable archive must be refused before any model request"
    );
}

/// The neighbouring case the fix must NOT change: a non-regular path where the
/// database belongs is not something the preflight can classify, so the round
/// proceeds and `run_index` reports its own internal failure.
#[test]
fn directory_at_db_path_still_reaches_the_index_failure() {
    let fixture = Fixture::new();
    fixture.seed_session("rollout-dir.jsonl", "api03g-dir");
    let stub = Stub::start(healthy_responder(16, 7));
    let config = fixture.write_config("models.toml", &local_config(&stub.endpoint()));
    fs::create_dir_all(fixture.db_path()).expect("create directory at the db path");

    let output = fixture.sync_json(Some(&config), &[]);
    dump_round("directory-at-db-path", &output);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(1),
        "a non-regular db path is an internal index failure: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(
        report["error"]["kind"],
        serde_json::json!("index"),
        "an internal index failure must name the index: {report}"
    );
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(true),
        "the index stage is what fails here, so it must have started: {report}"
    );
    // The preflight stage's own fact is unaffected by the later failure: the
    // probe answered, so the field stays ok with no error.
    let pre = preflight(&report);
    assert_eq!(
        pre["outcome"],
        serde_json::json!("ok"),
        "a later index failure must not rewrite the preflight's own outcome: {pre}"
    );
    assert_eq!(pre["error"], serde_json::Value::Null, "{pre}");
}

/// A schema this binary must not open in place is still its own rebuild refusal,
/// with no probe sent.
#[test]
fn incompatible_schema_is_still_a_rebuild_refusal() {
    use coding_agent_search::storage::api::Profile;
    use coding_agent_search::storage::testing::open_writable_for_tests;

    let fixture = Fixture::new();
    fixture.seed_session("rollout-old-schema.jsonl", "api03g-oldschema");

    // Build a real archive, then stamp an older schema version on it.
    let warm = Stub::start(healthy_responder(16, 7));
    let warm_config = fixture.write_config("models-warm.toml", &local_config(&warm.endpoint()));
    let first = fixture.sync_json(Some(&warm_config), &[]);
    assert_eq!(
        report_of(&first)["exit_code"],
        serde_json::json!(0),
        "the warm-up must build a real archive: {}",
        stderr_of(&first)
    );
    {
        let conn = open_writable_for_tests(&fixture.db_path(), Profile::Production)
            .expect("open writer for the downgrade");
        conn.execute_batch("PRAGMA user_version = 4;")
            .expect("stamp an older schema version");
        conn.close().expect("close writer");
    }

    let live = Stub::start(healthy_responder(16, 7));
    let config = fixture.write_config("models.toml", &local_config(&live.endpoint()));
    let output = fixture.sync_json(Some(&config), &[]);
    dump_round("incompatible-schema", &output);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(2),
        "an old schema is rebuild-only: {report}"
    );
    assert_eq!(
        report["error"]["kind"],
        serde_json::json!("rebuild-error"),
        "{report}"
    );
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(false),
        "{report}"
    );
    assert_eq!(
        live.request_count(),
        0,
        "an incompatible archive must be refused before any model request"
    );
}

// ---------------------------------------------------------------------------
// AC 7 — the round keeps the configuration it froze, not the file on disk
// ---------------------------------------------------------------------------

/// The semantic preflight loads the model configuration once and hands the same
/// frozen snapshot to the indexer. So rewriting the TOML *during* the probe must
/// change nothing: the round keeps calling the endpoint it selected, and the
/// newly-defaulted second service gets no request at all.
#[test]
fn a_config_rewritten_during_the_probe_does_not_change_the_round() {
    let fixture = Fixture::new();
    fixture.seed_session("rollout-freeze.jsonl", "api03g-freeze");

    let second = Stub::start(healthy_responder(16, 9));
    // The first stub rewrites the configuration file the instant the probe
    // arrives. The rewrite body needs the stub's own address, so it is handed
    // in after the stub exists and before the round starts.
    let rewrite_body: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let rewrite_path: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
    let body_for_stub = Arc::clone(&rewrite_body);
    let path_for_stub = Arc::clone(&rewrite_path);
    let first = Stub::start(move |request: &RecordedRequest, index: usize| {
        if index == 0 {
            let body = body_for_stub.lock().expect("rewrite lock").clone();
            let path = path_for_stub.lock().expect("rewrite lock").clone();
            if let (Some(body), Some(path)) = (body, path) {
                fs::write(&path, body).expect("rewrite the config during the probe");
            }
        }
        let model = request.request_model();
        let model = if model.is_empty() {
            EMBED_MODEL.to_string()
        } else {
            model
        };
        (200, embed_body(&request.inputs(), 16, &model, 7))
    });

    let config = fixture.write_config(
        "models.toml",
        &two_profile_config(&first.endpoint(), &second.endpoint(), "local"),
    );
    *rewrite_body.lock().expect("rewrite lock") = Some(two_profile_config(
        &first.endpoint(),
        &second.endpoint(),
        "second",
    ));
    *rewrite_path.lock().expect("rewrite lock") = Some(config.clone());

    let output = fixture.sync_json(Some(&config), &[]);
    dump_round("config-freeze", &output);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(0),
        "the round must still finish: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(report["semantic_activated"], serde_json::json!(true), "{report}");

    // The rewrite really happened, so "the second service got nothing" means
    // something.
    let on_disk = fs::read_to_string(&config).expect("read the rewritten config");
    assert!(
        on_disk.contains("default_embedding = \"second\""),
        "the fixture must have rewritten the config mid-round: {on_disk}"
    );
    assert_eq!(
        report["semantic_preflight"]["profile"],
        serde_json::json!("local"),
        "the frozen profile is the one selected before the rewrite: {report}"
    );

    // The frozen endpoint served the whole round; the newly-defaulted one saw
    // nothing at all.
    let frozen_requests = first.requests();
    assert!(
        frozen_requests.iter().any(|r| r.inputs().len() == 3),
        "the frozen endpoint must have served the probe: {frozen_requests:?}"
    );
    assert!(
        frozen_requests.len() > 1,
        "the frozen endpoint must have served the index too: {frozen_requests:?}"
    );
    assert_eq!(
        second.request_count(),
        0,
        "the configuration must not be re-selected after the freeze"
    );
}
