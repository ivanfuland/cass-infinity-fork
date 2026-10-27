//! API02D: the real-CLI contract of the API-only primary embedding backfill.
//!
//! Every test here runs the real `cass` binary against a real configuration
//! file, a real loopback HTTP service and a real synthetic SQLite database.
//! Nothing stubs the CLI argument struct, the transport or the store: the seams
//! the ticket asks for are "real subprocess, real config file, real HTTP
//! requests inspected, real vec0/meta rows".
//!
//! The corpus, the model ids, the revisions and the endpoints are synthetic and
//! public. No private corpus, no real credential and no real endpoint is
//! involved; the only traffic is to a loopback stub bound on an ephemeral port.

use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// The shared fingerprint comparator lives in the crate-private
// `search::frankensearch_types` module, which an integration test cannot reach.
// `bakeoff::cosine_similarity` is the crate's public cosine with the same
// formula; the lib test inside `db_vector_catchup` uses the shared comparator
// itself.
use coding_agent_search::bakeoff::cosine_similarity;
use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::search::eligibility::{expected_chunks, normalized_for_chunks};
use coding_agent_search::search::model_api::{ApiConfig, ProfileKind, ValidatedProfile};
use coding_agent_search::storage::api::{StorageError, TxMode, Value};
use coding_agent_search::storage::api_generation::{
    open_api_generation, provenance_meta_key, representation_meta_key,
};
use coding_agent_search::storage::sqlite::FrankenStorage;

const EMBED_MODEL: &str = "example/synthetic-embed";
const EMBED_REVISION: &str = "rev-synthetic-1";
const DOCUMENT_PREFIX: &str = "DOC>>";
const EMBED_PATH: &str = "/v1/embeddings";
const CLOUD_MODEL: &str = "example/synthetic-embed-cloud";

/// The three probe sentinels, byte-for-byte the driver's own constant.
const SENTINELS: [&str; 3] = [
    "The quick brown fox jumps over the lazy dog.",
    "今天天气不错，我们去公园散步吧。",
    "fn main() { println!(\"hello\"); }",
];

/// The closed retired-model-selection environment list.
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

    /// The request's `input` array as strings, or empty when it has none.
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

    fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn endpoint(&self) -> String {
        format!("{}{EMBED_PATH}", self.origin())
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
///
/// Two runs with the same drift produce byte-identical vectors, so the
/// generation fingerprint matches; bumping the drift changes every vector, the
/// way a service that quietly swapped weights would.
fn vector_for(text: &str, dim: usize, drift: u64) -> Vec<f64> {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // The drift must move the bits the extraction below keeps, so any change to
    // it changes every vector (the way a service that swapped weights would).
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

/// Answer one embedding request with `dim`-wide vectors at `drift`.
///
/// The response echoes the model the request carried, which is what the
/// configuration asked for, so a profile whose model differs from another
/// profile's still sees a consistent identity.
fn respond_embed(
    request: &RecordedRequest,
    inputs: &[String],
    dim: usize,
    drift: u64,
) -> (u16, String) {
    let model = request
        .body_json()
        .get("model")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(EMBED_MODEL)
        .to_string();
    (200, embed_body(inputs, dim, &model, drift))
}

/// A responder that always answers with `dim`-wide vectors at `drift`.
fn healthy_responder(dim: usize, drift: u64) -> impl Fn(&RecordedRequest, usize) -> (u16, String) {
    move |request, _index| respond_embed(request, &request.inputs(), dim, drift)
}

// ---------------------------------------------------------------------------
// CLI harness
// ---------------------------------------------------------------------------

fn scratch() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create scratch dir");
    let data_dir = dir.path().join("data");
    fs::create_dir_all(&data_dir).expect("create data dir");
    (dir, data_dir)
}

fn build_db(data_dir: &Path, contents: &[&str]) -> FrankenStorage {
    let storage = FrankenStorage::open(&data_dir.join("agent_search.db")).expect("open storage");
    let agent_id = storage
        .ensure_agent(&Agent {
            id: None,
            slug: "claude_code".into(),
            name: "Claude Code".into(),
            version: Some("1.0".into()),
            kind: AgentKind::Cli,
        })
        .expect("ensure agent");
    let messages: Vec<Message> = contents
        .iter()
        .enumerate()
        .map(|(idx, content)| Message {
            excluded: None,
            id: None,
            idx: idx as i64,
            role: MessageRole::User,
            author: None,
            created_at: Some(1_770_600_000_000 + idx as i64),
            content: (*content).to_string(),
            extra_json: serde_json::Value::Null,
            snippets: vec![],
        })
        .collect();
    let conversation = Conversation {
        id: None,
        agent_slug: "claude_code".into(),
        workspace: None,
        external_id: Some("api02d-fixture".into()),
        title: Some("API02D fixture".into()),
        source_path: PathBuf::from("/fixtures/api02d.jsonl"),
        started_at: Some(1_770_600_000_000),
        ended_at: Some(1_770_600_001_000),
        approx_tokens: None,
        metadata_json: serde_json::Value::Null,
        messages,
        source_id: "local".into(),
        origin_host: None,
    };
    storage
        .insert_conversation_tree(agent_id, None, &conversation)
        .expect("insert fixture conversation");
    storage
}

/// The exact document texts the catch-up must send for this database, sorted.
fn expected_document_texts(storage: &FrankenStorage) -> Vec<String> {
    let rows: Vec<(i64, String, String)> = storage
        .raw()
        .query_all_map(
            "SELECT id, role, content FROM messages ORDER BY id",
            &[],
            |row| {
                Ok((
                    row.get_typed::<i64>(0)?,
                    row.get_typed::<String>(1)?,
                    row.get_typed::<String>(2)?,
                ))
            },
        )
        .expect("read messages");
    let mut texts = Vec::new();
    for (message_id, role, content) in rows {
        let normalized = normalized_for_chunks(&content);
        for chunk in expected_chunks(message_id, 0, &role, &content) {
            texts.push(normalized[chunk.byte_start..chunk.byte_end].to_string());
        }
    }
    texts.sort();
    texts
}

fn config_text(default_profile: &str, profiles: &str) -> String {
    format!("version = 1\ndefault_embedding = \"{default_profile}\"\n\n{profiles}")
}

fn embedding_profile_block(
    id: &str,
    endpoint: &str,
    model: &str,
    revision: &str,
    max_batch: u64,
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
         document_prefix = \"{DOCUMENT_PREFIX}\"\n\
         max_batch = {max_batch}\n\
         {extra}\n"
    )
}

/// An argument list with no configuration named on the command line, so the
/// environment is the only possible selection.
fn args_without_config(data_dir: &Path) -> Vec<String> {
    vec![
        "models".into(),
        "backfill".into(),
        "--json".into(),
        "--data-dir".into(),
        data_dir.display().to_string(),
    ]
}

/// Borrow an argument list built by [`backfill_args`] as `&[&str]`.
fn argv(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// One CLI invocation with a scrubbed environment.
fn cass(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let raw: Vec<(&str, std::ffi::OsString)> = envs
        .iter()
        .map(|(name, value)| (*name, std::ffi::OsString::from(*value)))
        .collect();
    cass_env_raw(args, &raw)
}

/// One CLI invocation with a scrubbed environment and raw (possibly non-UTF-8)
/// environment values.
fn cass_env_raw(args: &[&str], envs: &[(&str, std::ffi::OsString)]) -> Output {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin("cass"));
    for variable in RETIRED_ENV {
        command.env_remove(variable);
    }
    for variable in [
        "CASS_API_CONFIG",
        "CASS_DATA_DIR",
        "CASS_DB",
        "CASS_SEMANTIC_MODE",
        "CASS_SEMANTIC_BACKFILL_DISABLE",
        "CASS_SEMANTIC_BACKFILL_FORCE",
    ] {
        command.env_remove(variable);
    }
    for (name, value) in envs {
        command.env(name, value);
    }
    command.args(args).output().expect("run cass")
}

fn backfill_args(
    data_dir: &Path,
    config: &Path,
    profile: Option<&str>,
    extra: &[&str],
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "models".into(),
        "backfill".into(),
        "--json".into(),
        "--api-config".into(),
        config.display().to_string(),
        "--data-dir".into(),
        data_dir.display().to_string(),
    ];
    if let Some(profile) = profile {
        args.push("--embedding-profile".into());
        args.push(profile.to_string());
    }
    for item in extra {
        args.push((*item).to_string());
    }
    args
}

fn run_backfill(data_dir: &Path, config: &Path, profile: Option<&str>, extra: &[&str]) -> Output {
    let args = backfill_args(data_dir, config, profile, extra);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    cass(&borrowed, &[])
}

fn stdout_json(output: &Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&text).unwrap_or_else(|err| {
        panic!(
            "stdout must be one JSON document: {err}\n--- stdout ---\n{text}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// The machine error envelope the CLI writes to stderr in `--json` mode.
fn stderr_document(output: &Output) -> serde_json::Value {
    let text = stderr_text(output);
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("stderr is not a JSON error envelope ({err}); stderr: {text}"))
}

/// The JSON document the CLI writes to stderr in `--json` mode.
///
/// A plain refusal is wrapped as `{"error": {code, kind, message, ...}}`.
fn error_envelope(output: &Output) -> serde_json::Value {
    stderr_document(output)
}

/// Persist one failure's raw stderr under the target's tmp directory, so the
/// machine shape this ticket promises can be inspected after the run.
fn dump_envelope(name: &str, output: &Output) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("api02d-envelopes");
    fs::create_dir_all(&dir).expect("create envelope dir");
    fs::write(dir.join(format!("{name}.json")), &output.stderr).expect("write envelope evidence");
}

fn assert_success(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "expected success, got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    stdout_json(output)
}

/// The requests each phase made: `(probe, document, audit)`.
///
/// The slice boundaries come from the three reported counts, and the total is
/// checked against the requests the stub really saw, so a report that
/// under-counts, double-counts or folds one phase into another fails here.
fn phase_requests(
    stub: &Stub,
    payload: &serde_json::Value,
) -> (
    Vec<RecordedRequest>,
    Vec<RecordedRequest>,
    Vec<RecordedRequest>,
) {
    let model_api = &payload["model_api"];
    let probes = model_api["probe_calls"]
        .as_array()
        .expect("probe calls")
        .len();
    let documents = model_api["document_calls"]
        .as_array()
        .expect("document calls")
        .len();
    let audits = model_api["audit_calls"]
        .as_array()
        .expect("audit calls")
        .len();
    let requests = stub.requests();
    assert_eq!(
        requests.len(),
        probes + documents + audits,
        "the three reported counts must close over every request the stub saw: {model_api}"
    );
    (
        requests[..probes].to_vec(),
        requests[probes..probes + documents].to_vec(),
        requests[probes + documents..].to_vec(),
    )
}

fn generation_count(storage: &FrankenStorage) -> i64 {
    storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM embedding_generations", &[], |row| {
            row.get_typed(0)
        })
        .expect("count generations")
}

fn active_generation(storage: &FrankenStorage) -> Option<i64> {
    storage
        .raw()
        .query_opt_map(
            "SELECT id FROM embedding_generations WHERE is_active = 1",
            &[],
            |row| row.get_typed::<i64>(0),
        )
        .expect("read active generation")
}

fn meta_count(storage: &FrankenStorage) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM meta WHERE key LIKE 'api_representation:%'",
            &[],
            |row| row.get_typed(0),
        )
        .expect("count meta rows")
}

fn count_for(storage: &FrankenStorage, sql: &str, generation_id: i64) -> i64 {
    storage
        .raw()
        .query_row_map(sql, &[Value::Integer(generation_id)], |row| {
            row.get_typed(0)
        })
        .expect("count")
}

fn holes(storage: &FrankenStorage, generation_id: i64) -> i64 {
    count_for(
        storage,
        "SELECT COUNT(*) FROM chunk_holes WHERE generation_id = ?1",
        generation_id,
    )
}

fn message_chunks(storage: &FrankenStorage, generation_id: i64) -> i64 {
    count_for(
        storage,
        "SELECT COUNT(*) FROM message_chunks WHERE generation_id = ?1",
        generation_id,
    )
}

fn vec0_rows(storage: &FrankenStorage, generation_id: i64) -> i64 {
    storage
        .raw()
        .query_row_map(
            &format!("SELECT COUNT(*) FROM vec_index_gen_{generation_id}"),
            &[],
            |row| row.get_typed(0),
        )
        .expect("count vec0 rows")
}

fn parse_profile(text: &str, id: &str) -> ValidatedProfile {
    let config = ApiConfig::parse_toml(text).expect("parse config");
    let profile = config.profile(id).expect("profile present").clone();
    assert_eq!(profile.kind, ProfileKind::Embedding);
    profile
}

fn profile_reopens(
    storage: &FrankenStorage,
    generation_id: i64,
    profile: &ValidatedProfile,
) -> bool {
    storage
        .raw()
        .with_tx(TxMode::Deferred, |tx| {
            open_api_generation(tx, generation_id, profile).map_err(StorageError::from)
        })
        .is_ok()
}

/// A three-chunk fixture: 2500 separator-free characters chunk as
/// `[0,1000)`, `[900,1900)`, `[1800,2500)`.
fn filler(char_len: usize) -> String {
    let mut text = String::with_capacity(char_len + 16);
    let mut n: u64 = 0;
    while text.len() < char_len {
        text.push_str(&n.to_string());
        n += 1;
    }
    text.truncate(char_len);
    text
}

// ---------------------------------------------------------------------------
// Creation, activation and the request shape
// ---------------------------------------------------------------------------

#[test]
fn creates_embeds_and_activates_a_new_api_generation() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "expected_dimension = 8",
        ),
    );
    fs::write(&config_path, &text).expect("write config");

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    let payload = assert_success(&output);

    assert_eq!(payload["status"], "published");
    assert_eq!(payload["activated"], true);
    assert_eq!(payload["reused_existing_generation"], false);
    assert_eq!(payload["tier"], "api");

    let model_api = &payload["model_api"];
    assert_eq!(model_api["primary_profile"], "local8");
    assert_eq!(model_api["requested_model"], EMBED_MODEL);
    assert_eq!(model_api["declared_revision"], EMBED_REVISION);
    assert_eq!(model_api["allow_fallback"], true);
    assert_eq!(model_api["fallback_used"], false);
    let descriptor = model_api["descriptor_sha256"]
        .as_str()
        .expect("descriptor digest");
    assert_eq!(descriptor.len(), 64);
    let endpoint_digest = model_api["endpoint_config_sha256"]
        .as_str()
        .expect("endpoint digest");
    assert_eq!(endpoint_digest.len(), 64);
    let probe_calls = model_api["probe_calls"].as_array().expect("probe calls");
    assert_eq!(
        probe_calls.len(),
        1,
        "one probe request at max_batch 64: {model_api}"
    );
    assert_eq!(probe_calls[0]["stage"], "probe");
    assert_eq!(probe_calls[0]["profile_id"], "local8");
    assert_eq!(probe_calls[0]["http_status"], 200);
    assert_eq!(probe_calls[0]["network_attempted"], true);
    assert_eq!(probe_calls[0]["error_code"], serde_json::Value::Null);
    assert_eq!(probe_calls[0]["response_model"], EMBED_MODEL);
    let document_calls = model_api["document_calls"]
        .as_array()
        .expect("document calls");
    assert!(
        !document_calls.is_empty(),
        "the drain must send document requests"
    );
    let audit_calls = model_api["audit_calls"].as_array().expect("audit calls");
    assert!(
        !audit_calls.is_empty(),
        "a run that activates must run the audit and record its requests: {model_api}"
    );
    for call in audit_calls {
        assert_eq!(call["stage"], "audit");
    }
    for call in document_calls {
        assert_eq!(call["stage"], "document");
    }

    // The generation row names the API space, not a served model.
    let generation_id = payload["generation_id"].as_i64().expect("generation id");
    assert_eq!(active_generation(&storage), Some(generation_id));
    let embedder_id: String = storage
        .raw()
        .query_row_map(
            "SELECT embedder_id FROM embedding_generations WHERE id = ?1",
            &[Value::Integer(generation_id)],
            |row| row.get_typed(0),
        )
        .expect("embedder id");
    assert_eq!(embedder_id, format!("api:{descriptor}"));
    assert_eq!(payload["embedder_id"], embedder_id);

    // The record reopens against the same profile, and vec0 holds every chunk.
    let profile = parse_profile(&text, "local8");
    assert!(profile_reopens(&storage, generation_id, &profile));
    assert_eq!(holes(&storage, generation_id), 0);
    let chunks = message_chunks(&storage, generation_id);
    assert!(chunks >= 1);
    assert_eq!(vec0_rows(&storage, generation_id), chunks);
    assert_eq!(meta_count(&storage), 1);

    // Request shape: POSTs only, to the configured path, every input carrying
    // the document prefix and the exact chunk text.
    let (probe_requests, drain_requests, audit_requests) = phase_requests(&stub, &payload);
    assert_eq!(probe_requests.len(), 1);
    assert_eq!(drain_requests.len(), document_calls.len());
    assert_eq!(audit_requests.len(), audit_calls.len());
    for request in probe_requests
        .iter()
        .chain(&drain_requests)
        .chain(&audit_requests)
    {
        assert_eq!(
            request.method, "POST",
            "no GET may ever be sent: {request:?}"
        );
        assert_eq!(request.path, EMBED_PATH);
        assert_eq!(request.body_json()["encoding_format"], "float");
        for input in request.inputs() {
            assert!(
                input.starts_with(DOCUMENT_PREFIX),
                "every input carries the document prefix: {input}"
            );
        }
    }
    // The probe carries the three sentinels in order.
    let probe_inputs = probe_requests[0].inputs();
    let expected_sentinels: Vec<String> = SENTINELS
        .iter()
        .map(|sentinel| format!("{DOCUMENT_PREFIX}{sentinel}"))
        .collect();
    assert_eq!(
        probe_inputs, expected_sentinels,
        "the probe sends exactly the three sentinels, in order"
    );

    // Every drain document is exactly one corpus chunk, with the prefix and
    // nothing else appended.
    let expected: Vec<String> = expected_document_texts(&storage)
        .into_iter()
        .map(|chunk| format!("{DOCUMENT_PREFIX}{chunk}"))
        .collect();
    let sent_drain: Vec<String> = drain_requests
        .iter()
        .flat_map(RecordedRequest::inputs)
        .collect();
    let mut sent_drain_sorted = sent_drain.clone();
    sent_drain_sorted.sort();
    assert!(
        sent_drain_sorted.len() >= expected.len(),
        "every expected chunk must have been sent at least once"
    );
    for chunk in &expected {
        assert!(
            sent_drain.contains(chunk),
            "the drain must send the exact chunk text {chunk:?}"
        );
    }
    // The audit re-embeds the sentinels and an ownership sample, and none of
    // that may be reported as a document batch.
    let audit_texts: Vec<String> = audit_requests
        .iter()
        .flat_map(RecordedRequest::inputs)
        .collect();
    for sentinel in &expected_sentinels {
        assert!(
            audit_texts.contains(sentinel),
            "the audit re-embeds the fingerprint sentinels"
        );
    }
}

#[test]
fn a_repeat_run_probes_only_and_reuses_the_same_generation() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");

    let first = assert_success(&run_backfill(&data_dir, &config_path, None, &[]));
    let first_generation = first["generation_id"].as_i64().expect("generation id");
    let first_documents = first["model_api"]["document_calls"]
        .as_array()
        .expect("document calls")
        .len();
    assert!(first_documents >= 1);
    let after_first = stub.request_count();

    // A brand-new process, same configuration.
    let second = assert_success(&run_backfill(&data_dir, &config_path, None, &[]));
    assert_eq!(second["generation_id"].as_i64(), Some(first_generation));
    assert_eq!(second["reused_existing_generation"], true);
    assert_eq!(
        second["activated"], true,
        "the full audit still runs and still activates"
    );
    let second_model_api = &second["model_api"];
    let second_probe = second_model_api["probe_calls"]
        .as_array()
        .expect("probe calls");
    assert_eq!(second_probe.len(), 1, "a repeat run makes one fresh probe");
    assert_eq!(second_probe[0]["stage"], "probe");
    assert_eq!(
        second_model_api["document_calls"]
            .as_array()
            .expect("document calls")
            .len(),
        0,
        "a repeat run re-embeds no corpus chunk: {second}"
    );
    let second_audit = second_model_api["audit_calls"]
        .as_array()
        .expect("audit calls");
    assert!(
        !second_audit.is_empty(),
        "the activation audit still runs on a repeat run and its requests are recorded: {second_model_api}"
    );
    for call in second_audit {
        assert_eq!(call["stage"], "audit");
    }
    assert_eq!(
        stub.request_count() - after_first,
        1 + second_audit.len(),
        "the second run sends only its probe and the audit's own verification requests"
    );

    // No second generation and no duplicated record.
    assert_eq!(generation_count(&storage), 1);
    assert_eq!(meta_count(&storage), 1);
    let profile = parse_profile(&text, "local8");
    assert!(profile_reopens(&storage, first_generation, &profile));
}

#[test]
fn a_corrupted_stored_vector_is_caught_by_the_audit_on_a_repeat_run() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");
    let first = assert_success(&run_backfill(&data_dir, &config_path, Some("local8"), &[]));
    let generation_id = first["generation_id"].as_i64().expect("generation id");
    assert_eq!(active_generation(&storage), Some(generation_id));

    // Corrupt one stored vector in place. The generation stays active and its
    // record stays intact, so only the audit's own verification can catch this.
    let chunk_id: i64 = storage
        .raw()
        .query_row_map(
            "SELECT MIN(chunk_id) FROM message_chunks WHERE generation_id = ?1",
            &[Value::Integer(generation_id)],
            |row| row.get_typed(0),
        )
        .expect("chunk id");
    let garbage = vec![0u8; 8 * 4];
    storage
        .raw()
        .execute(
            "UPDATE message_chunks SET embedding = ?1 WHERE chunk_id = ?2",
            &[Value::Blob(garbage), Value::Integer(chunk_id)],
        )
        .expect("corrupt the stored vector");

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(
        !output.status.success(),
        "a run whose stored vectors are wrong must be refused by the audit, not reported as \
         already complete"
    );
    assert_eq!(output.status.code(), Some(5));
    // The refusal is the audit's, and it did not hand itself a passing status.
    let audit_status: String = storage
        .raw()
        .query_row_map(
            "SELECT audit_status FROM embedding_generations WHERE id = ?1",
            &[Value::Integer(generation_id)],
            |row| row.get_typed(0),
        )
        .expect("audit status");
    assert_eq!(
        audit_status, "passed",
        "the previously committed activation is untouched"
    );
    assert_eq!(
        generation_count(&storage),
        1,
        "no replacement generation may be built here"
    );
}

#[test]
fn document_batches_respect_max_batch_and_carry_each_chunk_once() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(&data_dir, &[filler(2500).as_str()]);
    let stub = Stub::start(healthy_responder(16, 0));
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local16",
        &embedding_profile_block(
            "local16",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            1,
            "expected_dimension = 16",
        ),
    );
    fs::write(&config_path, &text).expect("write config");

    let payload = assert_success(&run_backfill(&data_dir, &config_path, Some("local16"), &[]));
    let model_api = &payload["model_api"];
    // max_batch 1 means one request per sentinel and one per chunk.
    let probe_calls = model_api["probe_calls"].as_array().expect("probe calls");
    assert_eq!(
        probe_calls.len(),
        3,
        "one probe request per sentinel at max_batch 1"
    );
    let document_calls = model_api["document_calls"]
        .as_array()
        .expect("document calls");
    assert_eq!(document_calls.len(), 3, "three chunks, one request each");

    let (probe_requests, drain_requests, audit_requests) = phase_requests(&stub, &payload);
    assert_eq!(probe_requests.len(), 3);
    assert_eq!(drain_requests.len(), 3);
    assert!(!audit_requests.is_empty());
    for request in probe_requests
        .iter()
        .chain(&drain_requests)
        .chain(&audit_requests)
    {
        assert_eq!(request.method, "POST");
        assert!(
            request.inputs().len() <= 1,
            "max_batch 1 must never batch two inputs: {request:?}"
        );
    }
    // The drain requests carry exactly the corpus chunks, once each.
    let sent: Vec<String> = drain_requests
        .iter()
        .flat_map(RecordedRequest::inputs)
        .collect();
    let mut expected: Vec<String> = expected_document_texts(&storage)
        .into_iter()
        .map(|chunk| format!("{DOCUMENT_PREFIX}{chunk}"))
        .collect();
    expected.sort();
    let mut sent_sorted = sent.clone();
    sent_sorted.sort();
    assert_eq!(
        sent_sorted, expected,
        "the drain sends exactly the corpus chunks, once each"
    );
    assert_eq!(payload["activated"], true);
    assert_eq!(payload["holes_after"], 0);
}

// ---------------------------------------------------------------------------
// Failure: nothing half-written, nothing half-activated
// ---------------------------------------------------------------------------

#[test]
fn a_mid_run_failure_keeps_committed_pages_and_the_remaining_holes() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(&data_dir, &[filler(2500).as_str()]);
    // Fail the second drain page's request (index 2: one probe, then page 1),
    // but only for the first run, so the retry can reuse the same endpoint and
    // therefore the same generation identity.
    let failing = Arc::new(AtomicBool::new(true));
    let failing_for_stub = Arc::clone(&failing);
    let stub = Stub::start(move |request: &RecordedRequest, index: usize| {
        if index == 2 && failing_for_stub.load(Ordering::SeqCst) {
            (500, "{\"error\":\"synthetic failure\"}".to_string())
        } else {
            respond_embed(request, &request.inputs(), 8, 0)
        }
    });
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");

    let output = run_backfill(
        &data_dir,
        &config_path,
        Some("local8"),
        &["--batch-conversations", "1"],
    );
    assert!(!output.status.success(), "a failed page must fail the run");
    assert_eq!(output.status.code(), Some(5));

    let generation_id: i64 = storage
        .raw()
        .query_row_map(
            "SELECT id FROM embedding_generations ORDER BY id LIMIT 1",
            &[],
            |row| row.get_typed(0),
        )
        .expect("generation row");
    assert_eq!(
        active_generation(&storage),
        None,
        "a failed run must not activate anything"
    );
    assert_eq!(
        message_chunks(&storage, generation_id),
        1,
        "the page that succeeded before the failure stays committed"
    );
    assert_eq!(
        holes(&storage, generation_id),
        2,
        "the failing page's own holes must not disappear"
    );

    // A healthy rerun against the same endpoint finishes the same generation.
    failing.store(false, Ordering::SeqCst);
    let recovered = assert_success(&run_backfill(
        &data_dir,
        &config_path,
        Some("local8"),
        &["--batch-conversations", "1"],
    ));
    assert_eq!(recovered["activated"], true);
    assert_eq!(recovered["holes_after"], 0);
    assert_eq!(message_chunks(&storage, generation_id), 3);
    assert_eq!(
        generation_count(&storage),
        1,
        "the retry must reuse the pending generation"
    );
}

#[test]
fn a_response_with_the_wrong_length_writes_nothing() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(|request: &RecordedRequest, index: usize| {
        if index == 0 {
            respond_embed(request, &request.inputs(), 8, 0)
        } else {
            // One row short of the requested inputs.
            let mut inputs = request.inputs();
            inputs.pop();
            respond_embed(request, &inputs, 8, 0)
        }
    });
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(5));
    dump_envelope("backfill-failure", &output);
    assert_eq!(
        error_envelope(&output)["error"]["code"],
        5,
        "the exit code and /error/code agree for a plain backfill failure"
    );

    let generation_id: i64 = storage
        .raw()
        .query_row_map(
            "SELECT id FROM embedding_generations ORDER BY id LIMIT 1",
            &[],
            |row| row.get_typed(0),
        )
        .expect("generation row");
    assert_eq!(
        message_chunks(&storage, generation_id),
        0,
        "no half page may be written"
    );
    assert!(holes(&storage, generation_id) >= 1);
    assert_eq!(active_generation(&storage), None);
}

#[test]
fn a_response_with_the_wrong_width_fails_the_page() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    // The probe establishes 8; the document batch answers 4. No
    // `expected_dimension` is configured, so the engine's own cross-request
    // width check is the only defense.
    let stub = Stub::start(|request: &RecordedRequest, index: usize| {
        if index == 0 {
            respond_embed(request, &request.inputs(), 8, 0)
        } else {
            respond_embed(request, &request.inputs(), 4, 0)
        }
    });
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(
        !output.status.success(),
        "a width that drifts from the probe must fail"
    );
    assert_eq!(output.status.code(), Some(5));
    assert!(
        stderr_text(&output).contains("width"),
        "the refusal must name the width disagreement: {}",
        stderr_text(&output)
    );
    let generation_id: i64 = storage
        .raw()
        .query_row_map(
            "SELECT id FROM embedding_generations ORDER BY id LIMIT 1",
            &[],
            |row| row.get_typed(0),
        )
        .expect("generation row");
    assert_eq!(message_chunks(&storage, generation_id), 0);
    assert_eq!(active_generation(&storage), None);
}

#[test]
fn a_response_naming_another_model_is_refused_before_any_generation_exists() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(|request: &RecordedRequest, _index: usize| {
        (
            200,
            embed_body(&request.inputs(), 8, "example/other-embed", 0),
        )
    });
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(
        !output.status.success(),
        "a contradicting response identity must be refused"
    );
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(
        generation_count(&storage),
        0,
        "a probe that never validated an identity must not create a generation"
    );
}

#[test]
fn arbitrary_model_names_are_not_whitelisted() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));
    let config_path = data_dir.join("models.toml");
    // A profile id and model name that mention a real family decide nothing:
    // the id selects the profile, the document decides the kind and the model.
    let text = config_text(
        "Qwen3-Embedding-4B-local",
        &embedding_profile_block(
            "Qwen3-Embedding-4B-local",
            &stub.endpoint(),
            "Qwen/Qwen3-Embedding-4B",
            "rev-synthetic-1",
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");

    let payload = assert_success(&run_backfill(
        &data_dir,
        &config_path,
        Some("Qwen3-Embedding-4B-local"),
        &[],
    ));
    assert_eq!(
        payload["model_api"]["primary_profile"],
        "Qwen3-Embedding-4B-local"
    );
    assert_eq!(
        payload["model_api"]["requested_model"],
        "Qwen/Qwen3-Embedding-4B"
    );
    assert_eq!(payload["activated"], true);
    let generation_id = payload["generation_id"].as_i64().expect("generation id");
    assert_eq!(active_generation(&storage), Some(generation_id));
}

// ---------------------------------------------------------------------------
// An existing API generation is never impersonated
// ---------------------------------------------------------------------------

#[test]
fn a_missing_representation_record_is_refused_rather_than_replaced() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");
    let first = assert_success(&run_backfill(&data_dir, &config_path, Some("local8"), &[]));
    let generation_id = first["generation_id"].as_i64().expect("generation id");

    // Tamper: remove the representation record the identity depends on.
    let key = representation_meta_key(generation_id);
    storage
        .raw()
        .execute("DELETE FROM meta WHERE key = ?1", &[Value::Text(key)])
        .expect("delete meta");
    let before = stub.request_count();

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(
        !output.status.success(),
        "a generation whose record vanished must be refused"
    );
    assert_eq!(
        generation_count(&storage),
        1,
        "a broken record must not be papered over by a second generation"
    );
    assert_eq!(
        stub.request_count(),
        before + 1,
        "only the probe may run before the record is refused"
    );
}

#[test]
fn an_identity_match_with_a_bad_record_is_refused_despite_a_fingerprint_mismatch() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let drift = Arc::new(AtomicU64::new(0));
    let drift_for_stub = Arc::clone(&drift);
    let stub = Stub::start(move |request: &RecordedRequest, _index: usize| {
        respond_embed(
            request,
            &request.inputs(),
            8,
            drift_for_stub.load(Ordering::SeqCst),
        )
    });
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");
    let first = assert_success(&run_backfill(&data_dir, &config_path, Some("local8"), &[]));
    let generation_id = first["generation_id"].as_i64().expect("generation id");

    // Both conditions at once: the served vectors drifted (a different
    // fingerprint) AND the stored record was tampered with.
    drift.store(7, Ordering::SeqCst);
    let key = representation_meta_key(generation_id);
    storage
        .raw()
        .execute("DELETE FROM meta WHERE key = ?1", &[Value::Text(key)])
        .expect("delete meta");

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(
        !output.status.success(),
        "a fingerprint mismatch must never bypass the record guard"
    );
    assert_eq!(
        generation_count(&storage),
        1,
        "the broken candidate must be refused, not replaced by a silently built second generation"
    );
}

#[test]
fn an_identity_match_with_a_drifted_fingerprint_and_a_sound_record_is_refused() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let drift = Arc::new(AtomicU64::new(0));
    let drift_for_stub = Arc::clone(&drift);
    let stub = Stub::start(move |request: &RecordedRequest, _index: usize| {
        respond_embed(
            request,
            &request.inputs(),
            8,
            drift_for_stub.load(Ordering::SeqCst),
        )
    });
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");
    let first = assert_success(&run_backfill(&data_dir, &config_path, Some("local8"), &[]));
    let first_generation = first["generation_id"].as_i64().expect("generation id");

    // The record stays sound; only the served weights changed. A candidate
    // that carries this exact API identity but not this probe's fingerprint
    // is refused instead of being papered over by a silently built parallel
    // generation.
    drift.store(11, Ordering::SeqCst);
    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert!(
        !output.status.success(),
        "a drifted fingerprint on a sound candidate must be refused"
    );
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(output.status.code(), Some(5));
    let envelope = error_envelope(&output);
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(envelope["error"]["code"], 5);
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert!(
        envelope["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("fingerprint")),
        "the refusal must name the fingerprint rule: {envelope}"
    );
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(
        generation_count(&storage),
        1,
        "a refused drift must not build a parallel generation"
    );
    let profile = parse_profile(&text, "local8");
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert!(
        profile_reopens(&storage, first_generation, &profile),
        "the original generation must stay intact"
    );
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(
        active_generation(&storage),
        Some(first_generation),
        "the original generation must stay active"
    );
}

#[test]
fn a_relocated_endpoint_reuses_an_existing_generation() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");
    let first = assert_success(&run_backfill(&data_dir, &config_path, Some("local8"), &[]));
    let generation_id = first["generation_id"].as_i64().expect("generation id");
    let chunks_before = message_chunks(&storage, generation_id);
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert!(chunks_before >= 1);

    // The same model, revision and width, but a different endpoint. The call
    // settings moved; the declared vector space did not, and the endpoint still
    // returns the same vectors, so the generation is admitted and reused.
    let moved = Stub::start(healthy_responder(8, 0));
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_ne!(
        stub.addr, moved.addr,
        "the relocated endpoint must be a different port"
    );
    let moved_config = data_dir.join("models-moved.toml");
    let moved_text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &moved.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&moved_config, &moved_text).expect("write moved config");

    let second = assert_success(&run_backfill(&data_dir, &moved_config, Some("local8"), &[]));
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(second["status"], "published");
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(second["generation_id"].as_i64(), Some(generation_id));
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(second["reused_existing_generation"], true);
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(second["activated"], true);
    assert_eq!(
        generation_count(&storage),
        1,
        "a relocation must not silently build a replacement generation"
    );
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(
        message_chunks(&storage, generation_id),
        chunks_before,
        "a reuse must not rewrite the chunk set"
    );
    let profile = parse_profile(&text, "local8");
    assert!(profile_reopens(&storage, generation_id, &profile));
}

/// Scale `vector` to unit length.
fn normalize_vector(vector: &[f64]) -> Vec<f64> {
    let norm = vector.iter().map(|value| value * value).sum::<f64>().sqrt();
    vector.iter().map(|value| value / norm).collect()
}

/// The same served model behind a relocated backend: `original` moved
/// `0.03 * norm(original)` along a direction orthogonal to its first two
/// components. The cosine with `original` is exactly `1 / sqrt(1 + 0.03^2)` =
/// 0.9995503..., inside the `[0.999, 0.9999)` window the cross-backend rule
/// admits and below the retired `0.9999` threshold.
fn approximate_vector(original: &[f64]) -> Vec<f64> {
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert!(
        original[0] != 0.0 || original[1] != 0.0,
        "the fixture needs a non-zero first pair to build an orthogonal direction"
    );
    let mut direction = vec![0.0f64; original.len()];
    direction[0] = -original[1];
    direction[1] = original[0];
    let direction = normalize_vector(&direction);
    let norm = original
        .iter()
        .map(|value| value * value)
        .sum::<f64>()
        .sqrt();
    let moved: Vec<f64> = original
        .iter()
        .zip(&direction)
        .map(|(value, axis)| value + 0.03 * norm * axis)
        .collect();
    normalize_vector(&moved)
}

fn as_f32(vector: &[f64]) -> Vec<f32> {
    vector.iter().map(|value| *value as f32).collect()
}

/// A relocated endpoint of the same declared model: documents come back
/// byte-for-byte as before, and only the three fingerprint sentinels come back
/// approximately re-embedded.
fn relocated_approximate_responder(
    dim: usize,
) -> impl Fn(&RecordedRequest, usize) -> (u16, String) {
    move |request, _index| {
        let inputs = request.inputs();
        let sentinel_inputs: Vec<String> = SENTINELS
            .iter()
            .map(|sentinel| format!("{DOCUMENT_PREFIX}{sentinel}"))
            .collect();
        let model = request
            .body_json()
            .get("model")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(EMBED_MODEL)
            .to_string();
        let data: Vec<serde_json::Value> = inputs
            .iter()
            .enumerate()
            .map(|(index, text)| {
                let original = vector_for(text, dim, 0);
                let embedding = if sentinel_inputs.iter().any(|wire| wire == text) {
                    approximate_vector(&original)
                } else {
                    original
                };
                serde_json::json!({
                    "object": "embedding",
                    "index": index,
                    "embedding": embedding,
                })
            })
            .collect();
        let body = serde_json::json!({
            "object": "list",
            "data": data,
            "model": model,
            "usage": {"prompt_tokens": inputs.len(), "total_tokens": inputs.len()},
        });
        (200, body.to_string())
    }
}

/// One meta record's raw stored text.
fn meta_text(storage: &FrankenStorage, key: &str) -> String {
    storage
        .raw()
        .query_row_map(
            "SELECT value FROM meta WHERE key = ?1",
            &[Value::Text(key.to_string())],
            |row| row.get_typed::<String>(0),
        )
        .expect("read meta value")
}

fn fingerprint_blob(storage: &FrankenStorage, generation_id: i64) -> Vec<u8> {
    storage
        .raw()
        .query_row_map(
            "SELECT fingerprint FROM embedding_generations WHERE id = ?1",
            &[Value::Integer(generation_id)],
            |row| row.get_typed::<Vec<u8>>(0),
        )
        .expect("read generation fingerprint")
}

#[test]
fn a_relocated_endpoint_with_approximate_fingerprint_reuses_and_passes_audit() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");
    let first = assert_success(&run_backfill(&data_dir, &config_path, Some("local8"), &[]));
    let generation_id = first["generation_id"].as_i64().expect("generation id");
    let chunks_before = message_chunks(&storage, generation_id);
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert!(chunks_before >= 1);
    let fingerprint_before = fingerprint_blob(&storage, generation_id);
    let representation_before = meta_text(&storage, &representation_meta_key(generation_id));
    let provenance_before = meta_text(&storage, &provenance_meta_key(generation_id));

    // Pin the fixture's real cosine through the product's own comparison, one
    // sentinel at a time, before asking the CLI anything.
    for sentinel in SENTINELS {
        // ubs:ignore[rust.perf.string-alloc-in-loop] -- Small synthetic fixture.
        let wire = format!("{DOCUMENT_PREFIX}{sentinel}");
        let original = vector_for(&wire, 8, 0);
        let approximate = approximate_vector(&original);
        let cosine = cosine_similarity(&as_f32(&original), &as_f32(&approximate));
        // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
        assert!(
            (0.999..0.9999).contains(&cosine),
            "the relocated fixture for {sentinel:?} must sit strictly between 0.999 and 0.9999, got {cosine}"
        );
    }

    // The same model and revision at a different port: documents come back
    // unchanged, the sentinels only approximately.
    let moved = Stub::start(relocated_approximate_responder(8));
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_ne!(
        stub.addr, moved.addr,
        "the relocated endpoint must be a different port"
    );
    let moved_config = data_dir.join("models-moved-approximate.toml");
    let moved_text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &moved.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&moved_config, &moved_text).expect("write moved config");

    let second = assert_success(&run_backfill(&data_dir, &moved_config, Some("local8"), &[]));
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(second["status"], "published");
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(second["generation_id"].as_i64(), Some(generation_id));
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(second["reused_existing_generation"], true);
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(second["activated"], true);
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(generation_count(&storage), 1);
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(
        message_chunks(&storage, generation_id),
        chunks_before,
        "a reuse must not rewrite the chunk set"
    );

    // Every stored record byte is untouched: the fingerprint BLOB and both meta
    // texts are compared as the stored bytes they are, never re-serialized.
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(
        fingerprint_blob(&storage, generation_id),
        fingerprint_before,
        "reuse must not rewrite the stored fingerprint"
    );
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(
        meta_text(&storage, &representation_meta_key(generation_id)).as_bytes(),
        representation_before.as_bytes(),
        "reuse must not rewrite the representation record"
    );
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert_eq!(
        meta_text(&storage, &provenance_meta_key(generation_id)).as_bytes(),
        provenance_before.as_bytes(),
        "reuse must not rewrite the provenance record"
    );

    let model_api = &second["model_api"];
    let audit_calls = model_api["audit_calls"].as_array().expect("audit calls");
    // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
    assert!(
        !audit_calls.is_empty(),
        "a run that activates must run audit ⑪ and record its requests: {model_api}"
    );
    let (_, _, audit_requests) = phase_requests(&moved, &second);
    let audit_inputs: Vec<String> = audit_requests
        .iter()
        .flat_map(RecordedRequest::inputs)
        .collect();
    for sentinel in SENTINELS {
        // ubs:ignore[rust.panic.assert-macros] -- Required regression test assertion.
        assert!(
            // ubs:ignore[rust.perf.string-alloc-in-loop] -- Small synthetic fixture.
            audit_inputs.contains(&format!("{DOCUMENT_PREFIX}{sentinel}")),
            "the audit must re-embed the sentinel {sentinel:?} against the relocated endpoint"
        );
    }
}

#[test]
fn a_same_width_but_different_model_builds_its_own_generation() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));
    let config_path = data_dir.join("models.toml");
    let text = config_text(
        "local8",
        &embedding_profile_block(
            "local8",
            &stub.endpoint(),
            EMBED_MODEL,
            EMBED_REVISION,
            64,
            "",
        ),
    );
    fs::write(&config_path, &text).expect("write config");
    let first = assert_success(&run_backfill(&data_dir, &config_path, Some("local8"), &[]));

    let other_config = data_dir.join("models-other.toml");
    let other_text = config_text(
        "other8",
        &embedding_profile_block(
            "other8",
            &stub.endpoint(),
            "example/other-embed",
            "rev-other-1",
            64,
            "",
        ),
    );
    fs::write(&other_config, &other_text).expect("write other config");
    let second = assert_success(&run_backfill(&data_dir, &other_config, Some("other8"), &[]));

    assert_ne!(
        second["generation_id"].as_i64(),
        first["generation_id"].as_i64(),
        "a different model at the same width is a different space"
    );
    assert_ne!(
        second["model_api"]["descriptor_sha256"],
        first["model_api"]["descriptor_sha256"]
    );
    assert_eq!(generation_count(&storage), 2);
}

// ---------------------------------------------------------------------------
// The fallback boundary this ticket does not cross
// ---------------------------------------------------------------------------

fn fallback_config(endpoint: &str, cloud_endpoint: &str) -> String {
    let mut local =
        embedding_profile_block("local8", endpoint, EMBED_MODEL, EMBED_REVISION, 64, "");
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
    config_text("local8", &format!("{local}{cloud}"))
}

fn refused_endpoint() -> String {
    // Bind and immediately drop a listener to get a port nothing is listening on.
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    format!("http://{addr}{EMBED_PATH}")
}

/// A listener that counts inbound connections and answers none.
///
/// It stands in for the cloud endpoint so "the fallback was never contacted" is
/// provable: an unreachable address cannot show that, because a refused connect
/// looks the same whether or not anything tried it. Any attempt is recorded
/// before TLS could fail. The endpoint is `https://` on loopback, which is what
/// the configuration kernel requires of a `remote` profile.
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

#[test]
fn an_eligible_primary_failure_requires_compatibility_evidence_and_calls_no_cloud() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let cloud = ConnectionSpy::start();
    let config_path = data_dir.join("models.toml");
    fs::write(
        &config_path,
        fallback_config(&refused_endpoint(), &cloud.endpoint()),
    )
    .expect("write config");

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(15), "semantic-unavailable");
    dump_envelope("compatibility-required", &output);
    let envelope = error_envelope(&output);
    assert_eq!(
        envelope["error"]["code"], 15,
        "the exit code and /error/code agree: {envelope}"
    );
    assert_eq!(
        envelope["error"]["kind"], "semantic-unavailable",
        "{envelope}"
    );
    assert_eq!(envelope["error"]["retryable"], false, "{envelope}");
    assert_eq!(envelope["compatibility_required"], true, "{envelope}");
    let message = envelope["error"]["message"].as_str().unwrap_or("");
    assert!(
        message.contains("CompatibilityRequired"),
        "the refusal must name CompatibilityRequired: {message}"
    );
    assert!(
        envelope["model_api"]["document_calls"].is_array()
            || envelope["model_api"]["probe_calls"].is_array(),
        "the failure diagnostic must keep the calls already made: {envelope}"
    );
    assert_eq!(
        cloud.connections(),
        0,
        "the cloud endpoint must never be contacted"
    );
}

#[test]
fn no_model_fallback_keeps_the_original_primary_failure() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let cloud = ConnectionSpy::start();
    let config_path = data_dir.join("models.toml");
    fs::write(
        &config_path,
        fallback_config(&refused_endpoint(), &cloud.endpoint()),
    )
    .expect("write config");

    let output = run_backfill(
        &data_dir,
        &config_path,
        Some("local8"),
        &["--no-model-fallback"],
    );
    assert!(!output.status.success());
    assert_eq!(
        output.status.code(),
        Some(5),
        "the plain primary failure, not a compatibility one"
    );
    dump_envelope("no-model-fallback", &output);
    let rendered = stderr_text(&output);
    assert!(
        !rendered.contains("CompatibilityRequired"),
        "disabling the fallback must not produce a compatibility refusal: {rendered}"
    );
    assert_eq!(cloud.connections(), 0);
}

#[test]
fn a_refused_status_is_not_a_compatibility_problem() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let primary = Stub::start(|_request: &RecordedRequest, _index: usize| {
        (401, "{\"error\":\"nope\"}".to_string())
    });
    let cloud = ConnectionSpy::start();
    let config_path = data_dir.join("models.toml");
    fs::write(
        &config_path,
        fallback_config(&primary.endpoint(), &cloud.endpoint()),
    )
    .expect("write config");

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(5));
    let rendered = stderr_text(&output);
    assert!(
        !rendered.contains("CompatibilityRequired"),
        "a 401 is not a compatibility gap: {rendered}"
    );
    assert_eq!(cloud.connections(), 0);
}

// ---------------------------------------------------------------------------
// Refusals that must happen before any request
// ---------------------------------------------------------------------------

#[test]
fn retired_selections_and_broken_configs_fail_before_any_request() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));
    let good = data_dir.join("models.toml");
    fs::write(
        &good,
        config_text(
            "local8",
            &embedding_profile_block(
                "local8",
                &stub.endpoint(),
                EMBED_MODEL,
                EMBED_REVISION,
                64,
                "",
            ),
        ),
    )
    .expect("write config");

    let missing = data_dir.join("absent.toml");
    let unreadable = data_dir.join("empty.toml");
    fs::write(&unreadable, "version = 1\n").expect("write empty config");
    let no_default = data_dir.join("no-default.toml");
    fs::write(
        &no_default,
        format!(
            "version = 1\n{}",
            embedding_profile_block(
                "local8",
                &stub.endpoint(),
                EMBED_MODEL,
                EMBED_REVISION,
                64,
                ""
            )
        ),
    )
    .expect("write no-default config");
    let wrong_kind = data_dir.join("wrong-kind.toml");
    fs::write(
        &wrong_kind,
        config_text(
            "local8",
            &format!(
                "[profiles.local8]\n\
                 kind = \"rerank\"\n\
                 protocol = \"rerank-json-v1\"\n\
                 endpoint = \"{}\"\n\
                 scope = \"loopback\"\n\
                 model = \"example/rank\"\n\
                 model_revision = \"rev-rank-1\"\n",
                stub.endpoint()
            ),
        ),
    )
    .expect("write wrong-kind config");

    let cases: Vec<(&str, Vec<String>, Vec<(&str, &str)>)> = vec![
        (
            "retired --embedder",
            backfill_args(
                &data_dir,
                &good,
                Some("local8"),
                &["--embedder", "fastembed"],
            ),
            vec![],
        ),
        (
            "retired --tier",
            backfill_args(&data_dir, &good, Some("local8"), &["--tier", "quality"]),
            vec![],
        ),
        (
            "missing configuration",
            backfill_args(&data_dir, &missing, Some("local8"), &[]),
            vec![],
        ),
        (
            "unreadable configuration",
            backfill_args(&data_dir, &unreadable, Some("local8"), &[]),
            vec![],
        ),
        (
            "no default embedding profile",
            backfill_args(&data_dir, &no_default, None, &[]),
            vec![],
        ),
        (
            "rerank profile selected",
            backfill_args(&data_dir, &wrong_kind, Some("local8"), &[]),
            vec![],
        ),
        (
            "unknown profile selected",
            backfill_args(&data_dir, &good, Some("example/qwen"), &[]),
            vec![],
        ),
    ];

    for (label, args, envs) in cases {
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = cass(&borrowed, &envs);
        assert!(
            !output.status.success(),
            "{label} must be refused: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "{label} is a configuration/migration refusal"
        );
    }

    // Every one of the seven retired model-selection variables, one at a time,
    // including an empty value.
    for variable in RETIRED_ENV {
        let args = backfill_args(&data_dir, &good, Some("local8"), &[]);
        for value in ["http://127.0.0.1:9", ""] {
            let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
            let output = cass(&borrowed, &[(variable, value)]);
            assert!(
                !output.status.success(),
                "{variable}={value:?} must be refused: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert_eq!(
                output.status.code(),
                Some(2),
                "{variable}={value:?} is a migration refusal"
            );
            let envelope = error_envelope(&output);
            assert_eq!(
                envelope["error"]["kind"], "ModelApiMigration",
                "{variable}={value:?} must report the migration kind: {envelope}"
            );
            assert_eq!(
                envelope["error"]["code"], 2,
                "{variable}={value:?}: the configuration path is locatable by /error/code too"
            );
        }
    }
    assert_eq!(
        stub.request_count(),
        0,
        "no refused case may reach the endpoint"
    );
}

#[test]
fn a_profile_without_any_configuration_selection_is_refused() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));

    // An explicit profile with no configuration at all still takes the API path.
    let output = run_backfill(
        &data_dir,
        &data_dir.join("absent.toml"),
        Some("local8"),
        &[],
    );
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stub.request_count(), 0);
}

#[test]
fn the_database_resolution_and_lock_are_reused() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));
    let config_path = data_dir.join("models.toml");
    fs::write(
        &config_path,
        config_text(
            "local8",
            &embedding_profile_block(
                "local8",
                &stub.endpoint(),
                EMBED_MODEL,
                EMBED_REVISION,
                64,
                "",
            ),
        ),
    )
    .expect("write config");

    // A `--db` outside `--data-dir` is the same usage refusal as the legacy path.
    let elsewhere = data_dir.join("elsewhere");
    fs::create_dir_all(&elsewhere).expect("create elsewhere");
    let outside_db = elsewhere.join("agent_search.db");
    {
        let _ = FrankenStorage::open(&outside_db).expect("open outside db");
    }
    let mismatch = cass(
        &[
            "models",
            "backfill",
            "--json",
            "--api-config",
            &config_path.display().to_string(),
            "--data-dir",
            &data_dir.display().to_string(),
            "--db",
            &outside_db.display().to_string(),
            "--embedding-profile",
            "local8",
        ],
        &[],
    );
    assert!(!mismatch.status.success());
    assert_eq!(mismatch.status.code(), Some(2));

    // A missing database is the same `IndexMissing` refusal.
    let empty_dir = data_dir.join("no-db");
    fs::create_dir_all(&empty_dir).expect("create empty dir");
    let missing_db = run_backfill(&empty_dir, &config_path, Some("local8"), &[]);
    assert!(!missing_db.status.success());
    assert_eq!(missing_db.status.code(), Some(3));

    // The same index-run lock the legacy path takes is taken here too.
    let lock_path = data_dir.join("index-run.lock");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("open lock file");
    use fs2::FileExt as _;
    lock_file
        .try_lock_exclusive()
        .expect("hold the index-run lock");
    let locked = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(!locked.status.success());
    assert_eq!(
        locked.status.code(),
        Some(7),
        "lock-busy keeps run_index's own code"
    );
    fs2::FileExt::unlock(&lock_file).expect("release the lock");

    // The scheduler gate refuses before any request.
    let skipped = cass(
        &backfill_args(&data_dir, &config_path, Some("local8"), &["--scheduled"])
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        &[("CASS_SEMANTIC_BACKFILL_DISABLE", "1")],
    );
    assert!(skipped.status.success(), "a scheduler skip is not an error");
    let payload = stdout_json(&skipped);
    assert_eq!(
        payload["status"], "disabled",
        "the scheduler gate refused the batch"
    );
    assert_eq!(payload["primary_profile"], "local8");

    assert_eq!(
        stub.request_count(),
        0,
        "none of these refusals may reach the endpoint"
    );
}

// ---------------------------------------------------------------------------
// R1: the branch is chosen by presence, never by resolvability
// ---------------------------------------------------------------------------

/// Corrupt one API meta record from outside the running command.
///
/// A raw `rusqlite` connection is used on purpose: the point is to change the
/// private fixture database while the real `cass` process is mid-run, the way a
/// concurrent writer would, without touching any production state.
fn corrupt_representation_record(db_path: &Path) {
    let conn = rusqlite::Connection::open(db_path).expect("open raw connection");
    conn.busy_timeout(Duration::from_secs(5))
        .expect("busy timeout");
    let generation_id: i64 = conn
        .query_row(
            "SELECT id FROM embedding_generations ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("generation row");
    let removed = conn
        .execute(
            "DELETE FROM meta WHERE key = ?1",
            rusqlite::params![format!("api_representation:v1:{generation_id}")],
        )
        .expect("delete the representation record");
    assert_eq!(removed, 1, "the record to corrupt must exist");
}

#[test]
fn api_backfill_requires_configuration_for_every_selection_shape() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let stub = Stub::start(healthy_responder(8, 0));
    let good = data_dir.join("models.toml");
    fs::write(
        &good,
        config_text(
            "local8",
            &embedding_profile_block(
                "local8",
                &stub.endpoint(),
                EMBED_MODEL,
                EMBED_REVISION,
                64,
                "",
            ),
        ),
    )
    .expect("write config");
    let elsewhere = data_dir.join("elsewhere");
    fs::create_dir_all(&elsewhere).expect("create elsewhere");
    let outside_db = elsewhere.join("agent_search.db");
    {
        let _ = FrankenStorage::open(&outside_db).expect("open outside db");
    }

    // Missing API configuration is refused before any database work, even
    // when the supplied database path would also fail later validation.
    let absent = cass(
        &[
            "models",
            "backfill",
            "--json",
            "--data-dir",
            &data_dir.display().to_string(),
            "--db",
            &outside_db.display().to_string(),
        ],
        &[],
    );
    assert_eq!(
        absent.status.code(),
        Some(2),
        "missing configuration is a usage refusal"
    );
    assert_eq!(
        error_envelope(&absent)["error"]["kind"],
        "ModelApiConfiguration",
        "no selection must never reactivate the retired legacy branch"
    );

    // An empty environment value is still a selection: it must not silently fall
    // through to the legacy backend.
    let empty_env = cass(
        &argv(&args_without_config(&data_dir)),
        &[("CASS_API_CONFIG", "")],
    );
    assert_eq!(
        empty_env.status.code(),
        Some(2),
        "an empty selection is a configuration refusal"
    );
    assert_eq!(
        error_envelope(&empty_env)["error"]["kind"],
        "ModelApiConfiguration",
        "CASS_API_CONFIG='' must take the API path"
    );

    // An empty command-line path never reaches the branch logic: the CLI's own
    // argument parsing refuses a missing value for `--api-config` (exit 2,
    // `argument_parsing`) before any configuration is read and before any
    // database is touched. That is a fixed refusal, not a silent fall-through.
    let empty_cli = cass(
        &[
            "models",
            "backfill",
            "--json",
            "--api-config",
            "",
            "--data-dir",
            &data_dir.display().to_string(),
        ],
        &[],
    );
    assert_eq!(empty_cli.status.code(), Some(2));
    assert_eq!(
        error_envelope(&empty_cli)["kind"],
        "argument_parsing",
        "an empty --api-config value is refused by the parser"
    );
    assert!(
        error_envelope(&empty_cli)["error"]
            .as_str()
            .unwrap_or_default()
            .contains("--api-config"),
        "the refusal must name the flag: {}",
        stderr_text(&empty_cli)
    );
    assert_eq!(
        generation_count(&storage),
        0,
        "an empty --api-config must not reach the legacy backend and build anything"
    );

    // A non-UTF-8 environment path is a selection as well: it is read verbatim
    // and refused as a configuration problem, never routed to the legacy branch.
    use std::os::unix::ffi::OsStrExt as _;
    let non_utf8_path = std::ffi::OsStr::from_bytes(b"/tmp/api02d-\xff\xfe.toml").to_os_string();
    let non_utf8 = cass_env_raw(
        &argv(&args_without_config(&data_dir)),
        &[("CASS_API_CONFIG", non_utf8_path)],
    );
    assert_eq!(non_utf8.status.code(), Some(2));
    assert_eq!(
        error_envelope(&non_utf8)["error"]["kind"],
        "ModelApiConfiguration",
        "a non-UTF-8 selection must be refused as configuration, not ignored"
    );
    assert!(
        error_envelope(&non_utf8)["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("could not be read"),
        "a non-UTF-8 path must be a readable-path refusal: {}",
        stderr_text(&non_utf8)
    );

    // A valid explicit command-line path still wins over an empty environment.
    let explicit_wins = cass(
        &argv(&backfill_args(&data_dir, &good, Some("local8"), &[])),
        &[("CASS_API_CONFIG", "")],
    );
    let payload = assert_success(&explicit_wins);
    assert_eq!(payload["status"], "published");
    assert_eq!(payload["model_api"]["primary_profile"], "local8");

    assert_eq!(
        stub.request_count(),
        1 + payload["model_api"]["document_calls"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0)
            + payload["model_api"]["audit_calls"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(0),
        "only the one successful run may reach the endpoint"
    );
}

// ---------------------------------------------------------------------------
// R1: a width that drifts keeps its own bounded code on the request
// ---------------------------------------------------------------------------

#[test]
fn a_document_batch_with_the_wrong_width_keeps_its_failure_code() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    // No `expected_dimension`: the client validates the response shape but not
    // the width, so only this driver's own cross-batch check can refuse it.
    let stub = Stub::start(|request: &RecordedRequest, index: usize| {
        if index == 0 {
            respond_embed(request, &request.inputs(), 8, 0)
        } else {
            respond_embed(request, &request.inputs(), 16, 0)
        }
    });
    let config_path = data_dir.join("models.toml");
    fs::write(
        &config_path,
        config_text(
            "local8",
            &embedding_profile_block(
                "local8",
                &stub.endpoint(),
                EMBED_MODEL,
                EMBED_REVISION,
                64,
                "",
            ),
        ),
    )
    .expect("write config");

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(
        !output.status.success(),
        "a width that drifts must fail the run"
    );
    assert_eq!(output.status.code(), Some(5));
    let envelope = error_envelope(&output);
    let document_calls = envelope["model_api"]["document_calls"]
        .as_array()
        .expect("document calls");
    assert_eq!(document_calls.len(), 1);
    assert_eq!(
        document_calls[0]["error_code"], "DimensionDrift",
        "the drifting request must carry its own bounded code: {envelope}"
    );
    assert_eq!(
        document_calls[0]["http_status"], 200,
        "the request really succeeded at the HTTP layer: {envelope}"
    );
    assert_eq!(document_calls[0]["network_attempted"], true);
    // Nothing may be written for the refused page.
    let generation_id: i64 = storage
        .raw()
        .query_row_map(
            "SELECT id FROM embedding_generations ORDER BY id LIMIT 1",
            &[],
            |row| row.get_typed(0),
        )
        .expect("generation row");
    assert_eq!(message_chunks(&storage, generation_id), 0);
    assert_eq!(active_generation(&storage), None);
}

#[test]
fn a_probe_batch_with_the_wrong_width_keeps_its_failure_code() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    // max_batch 1 splits the three sentinels into three probe requests; the
    // second one drifts.
    let stub = Stub::start(|request: &RecordedRequest, index: usize| {
        if index == 0 {
            respond_embed(request, &request.inputs(), 8, 0)
        } else {
            respond_embed(request, &request.inputs(), 16, 0)
        }
    });
    let config_path = data_dir.join("models.toml");
    fs::write(
        &config_path,
        config_text(
            "local8",
            &embedding_profile_block(
                "local8",
                &stub.endpoint(),
                EMBED_MODEL,
                EMBED_REVISION,
                1,
                "",
            ),
        ),
    )
    .expect("write config");

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(
        !output.status.success(),
        "a drifting probe must fail the run"
    );
    assert_eq!(output.status.code(), Some(5));
    let envelope = error_envelope(&output);
    let probe_calls = envelope["model_api"]["probe_calls"]
        .as_array()
        .expect("probe calls");
    assert_eq!(
        probe_calls.len(),
        2,
        "the drift stops the probe at the second batch: {envelope}"
    );
    assert_eq!(probe_calls[0]["error_code"], serde_json::Value::Null);
    assert_eq!(
        probe_calls[1]["error_code"], "DimensionDrift",
        "the drifting probe batch must carry its own bounded code: {envelope}"
    );
    assert_eq!(probe_calls[1]["http_status"], 200);
    assert_eq!(
        generation_count(&storage),
        0,
        "a probe that never established a width must not create a generation"
    );
}

// ---------------------------------------------------------------------------
// R1: real write-transaction failure and late-identity-guard counter-examples
// ---------------------------------------------------------------------------

#[test]
fn a_write_transaction_failure_leaves_no_half_page_and_keeps_the_old_active() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(&data_dir, &[filler(2500).as_str()]);
    let stub = Stub::start(healthy_responder(8, 0));
    let config_path = data_dir.join("models.toml");
    // Two profiles over one endpoint: the first builds and activates the old
    // active generation, the second must build a candidate beside it.
    let first_profile = embedding_profile_block(
        "local8",
        &stub.endpoint(),
        EMBED_MODEL,
        EMBED_REVISION,
        64,
        "",
    );
    let second_profile = embedding_profile_block(
        "local8b",
        &stub.endpoint(),
        "example/other-embed",
        "rev-other-1",
        64,
        "",
    );
    fs::write(
        &config_path,
        config_text("local8", &format!("{first_profile}\n{second_profile}")),
    )
    .expect("write config");

    let first = assert_success(&run_backfill(&data_dir, &config_path, Some("local8"), &[]));
    let old_active = first["generation_id"].as_i64().expect("generation id");
    assert_eq!(active_generation(&storage), Some(old_active));

    // A real SQLite write failure inside the candidate's page transaction.
    let candidate_id: i64 = old_active + 1;
    storage
        .raw()
        .execute_batch(&format!(
            "CREATE TRIGGER api02d_write_failure BEFORE INSERT ON message_chunks \
             WHEN NEW.generation_id = {candidate_id} \
             BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;"
        ))
        .expect("install the write-failure trigger");

    let failed = run_backfill(
        &data_dir,
        &config_path,
        Some("local8b"),
        &["--batch-conversations", "1"],
    );
    assert!(
        !failed.status.success(),
        "the injected write failure must fail the run"
    );
    assert_eq!(failed.status.code(), Some(5));
    let staging_rows: i64 = storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM chunk_staging WHERE generation_id = ?1",
            &[Value::Integer(candidate_id)],
            |row| row.get_typed(0),
        )
        .expect("staging count");
    assert_eq!(
        message_chunks(&storage, candidate_id),
        0,
        "no half page may be committed for the failed generation"
    );
    assert_eq!(
        staging_rows, 0,
        "the failed page's staging rows must be rolled back with it"
    );
    assert!(
        holes(&storage, candidate_id) >= 1,
        "the failed page's holes must not be cleared"
    );
    assert_eq!(
        active_generation(&storage),
        Some(old_active),
        "the previously active generation must stay active"
    );

    // With the fault removed the same candidate can be finished.
    storage
        .raw()
        .execute_batch("DROP TRIGGER api02d_write_failure;")
        .expect("drop the write-failure trigger");
    let recovered = assert_success(&run_backfill(
        &data_dir,
        &config_path,
        Some("local8b"),
        &["--batch-conversations", "1"],
    ));
    assert_eq!(recovered["generation_id"].as_i64(), Some(candidate_id));
    assert_eq!(recovered["activated"], true);
    assert_eq!(holes(&storage, candidate_id), 0);
    assert_eq!(message_chunks(&storage, candidate_id), 3);
}

#[test]
fn a_page_guard_blocks_the_write_when_the_record_goes_bad_mid_run() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(&data_dir, &[filler(2500).as_str()]);
    let db_path = data_dir.join("agent_search.db");
    // One probe, then page 1; corrupt the record just before page 2's request.
    let strike_at = Arc::new(AtomicUsize::new(usize::MAX));
    let strike = Arc::clone(&strike_at);
    let db_for_stub = db_path.clone();
    let stub = Stub::start(move |request: &RecordedRequest, index: usize| {
        if index == strike.load(Ordering::SeqCst) {
            corrupt_representation_record(&db_for_stub);
        }
        respond_embed(request, &request.inputs(), 8, 0)
    });
    let config_path = data_dir.join("models.toml");
    fs::write(
        &config_path,
        config_text(
            "local8",
            &embedding_profile_block(
                "local8",
                &stub.endpoint(),
                EMBED_MODEL,
                EMBED_REVISION,
                64,
                "",
            ),
        ),
    )
    .expect("write config");
    strike_at.store(2, Ordering::SeqCst);

    let output = run_backfill(
        &data_dir,
        &config_path,
        Some("local8"),
        &["--batch-conversations", "1"],
    );
    assert!(
        !output.status.success(),
        "a page whose record went bad must not commit its vectors"
    );
    assert_eq!(output.status.code(), Some(5));
    let generation_id: i64 = storage
        .raw()
        .query_row_map(
            "SELECT id FROM embedding_generations ORDER BY id LIMIT 1",
            &[],
            |row| row.get_typed(0),
        )
        .expect("generation row");
    assert_eq!(
        message_chunks(&storage, generation_id),
        1,
        "only the page written before the record went bad may be committed"
    );
    assert_eq!(
        holes(&storage, generation_id),
        2,
        "the aborted page keeps its holes"
    );
    assert_eq!(active_generation(&storage), None);
}

#[test]
fn an_activation_guard_blocks_the_switch_when_the_record_goes_bad_late() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(
        &data_dir,
        &["a single message that is long enough to chunk once"],
    );
    let db_path = data_dir.join("agent_search.db");
    // One probe, one drain request, then the audit's own requests start. Corrupt
    // the record just before the audit's first request, so every page has
    // already been written and only the activation is left to refuse.
    let strike_at = Arc::new(AtomicUsize::new(usize::MAX));
    let strike = Arc::clone(&strike_at);
    let db_for_stub = db_path.clone();
    let stub = Stub::start(move |request: &RecordedRequest, index: usize| {
        if index == strike.load(Ordering::SeqCst) {
            corrupt_representation_record(&db_for_stub);
        }
        respond_embed(request, &request.inputs(), 8, 0)
    });
    let config_path = data_dir.join("models.toml");
    fs::write(
        &config_path,
        config_text(
            "local8",
            &embedding_profile_block(
                "local8",
                &stub.endpoint(),
                EMBED_MODEL,
                EMBED_REVISION,
                64,
                "",
            ),
        ),
    )
    .expect("write config");
    strike_at.store(2, Ordering::SeqCst);

    let output = run_backfill(&data_dir, &config_path, Some("local8"), &[]);
    assert!(!output.status.success(), "the activation must be refused");
    assert_eq!(output.status.code(), Some(5));
    let generation_id: i64 = storage
        .raw()
        .query_row_map(
            "SELECT id FROM embedding_generations ORDER BY id LIMIT 1",
            &[],
            |row| row.get_typed(0),
        )
        .expect("generation row");
    assert_eq!(
        message_chunks(&storage, generation_id),
        1,
        "the drain itself completed before the record went bad"
    );
    assert_eq!(
        active_generation(&storage),
        None,
        "the generation must not be switched active"
    );
    let audit_status: String = storage
        .raw()
        .query_row_map(
            "SELECT audit_status FROM embedding_generations WHERE id = ?1",
            &[Value::Integer(generation_id)],
            |row| row.get_typed(0),
        )
        .expect("audit status");
    assert_eq!(
        audit_status, "pending",
        "the activation transaction must not have handed itself a passing status"
    );
}

#[test]
fn api_query_reopens_generation_and_uses_query_prefix() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(&data_dir, &["a sufficiently long synthetic document for API query validation"]);
    let stub = Stub::start(healthy_responder(8, 0));
    let config = data_dir.join("models.toml");
    fs::write(&config, config_text("local8", &embedding_profile_block(
        "local8", &stub.endpoint(), EMBED_MODEL, EMBED_REVISION, 64,
        "query_prefix = \"QUERY: \"",
    ))).unwrap();
    assert_success(&run_backfill(&data_dir, &config, None, &[]));
    let before = stub.requests().len();
    let out = cass(&["search", "synthetic query", "--mode", "semantic", "--json",
        "--data-dir", data_dir.to_str().unwrap(), "--api-config", config.to_str().unwrap(),
        "--embedding-profile", "local8"], &[]);
    assert_success(&out);
    let requests = stub.requests();
    assert_eq!(requests.len(), before + 1, "query sends no probe");
    assert_eq!(requests[before].inputs(), vec!["QUERY: synthetic query".to_string()]);
    // Same width does not permit a model change against the old generation.
    let changed = fs::read_to_string(&config).unwrap().replace(EMBED_MODEL, "example/different-model");
    fs::write(&config, changed).unwrap();
    let denied = cass(&["search", "synthetic query", "--mode", "semantic", "--json",
        "--data-dir", data_dir.to_str().unwrap(), "--api-config", config.to_str().unwrap()], &[]);
    assert!(!denied.status.success());
    assert_eq!(stub.requests().len(), before + 1, "identity refusal precedes private query HTTP");
}

#[test]
fn api_query_rejects_metadata_changed_during_http() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(&data_dir, &["a sufficiently long synthetic document for API query validation"]);
    let tamper = Arc::new(AtomicBool::new(false));
    let tamper_in_http = Arc::clone(&tamper);
    let db = data_dir.join("agent_search.db");
    let stub = Stub::start(move |request, _| {
        if tamper_in_http.load(Ordering::SeqCst) { corrupt_representation_record(&db); }
        respond_embed(request, &request.inputs(), 8, 0)
    });
    let config = data_dir.join("models.toml");
    fs::write(&config, config_text("local8", &embedding_profile_block(
        "local8", &stub.endpoint(), EMBED_MODEL, EMBED_REVISION, 64, "",
    ))).unwrap();
    assert_success(&run_backfill(&data_dir, &config, None, &[]));
    let before = stub.requests().len();
    tamper.store(true, Ordering::SeqCst);
    let out = cass(&["search", "synthetic query", "--mode", "semantic", "--json",
        "--data-dir", data_dir.to_str().unwrap(), "--api-config", config.to_str().unwrap()], &[]);
    assert!(!out.status.success(), "query must not use vectors after their identity changes");
    assert_eq!(stub.requests().len(), before + 1, "the record changed inside the query request");
    assert!(String::from_utf8_lossy(&out.stderr).contains("InvalidRecord"), "{}", stderr_text(&out));
}

#[test]
fn api_query_hybrid_requires_proof_only_for_enabled_fallback() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(&data_dir, &["a sufficiently long synthetic document for API query validation"]);
    let fail = Arc::new(AtomicBool::new(false));
    let fail_http = Arc::clone(&fail);
    let stub = Stub::start(move |request, _| {
        if fail_http.load(Ordering::SeqCst) { return (503, "{}".into()); }
        respond_embed(request, &request.inputs(), 8, 0)
    });
    let cloud = ConnectionSpy::start();
    let config = data_dir.join("models.toml");
    fs::write(&config, fallback_config(&stub.endpoint(), &cloud.endpoint())).unwrap();
    assert_success(&run_backfill(&data_dir, &config, None, &[]));
    fail.store(true, Ordering::SeqCst);
    let before = stub.requests().len();
    let args = ["search", "synthetic query", "--mode", "hybrid", "--json",
        "--data-dir", data_dir.to_str().unwrap(), "--api-config", config.to_str().unwrap()];
    let out = cass(&args, &[]);
    assert!(!out.status.success(), "unverified fallback must not degrade to lexical; HTTP before={before} after={} stdout={} stderr={}", stub.requests().len(), String::from_utf8_lossy(&out.stdout), stderr_text(&out));
    assert!(stderr_text(&out).contains("CompatibilityRequired"), "{}", stderr_text(&out));
    assert_eq!(stub.requests().len(), before + 1);
    assert_eq!(cloud.connections(), 0);
    let mut disabled = args.to_vec();
    disabled.push("--no-model-fallback");
    assert_success(&cass(&disabled, &[]));
    assert_eq!(stub.requests().len(), before + 2);
    assert_eq!(cloud.connections(), 0);
}

#[test]
fn api_query_configuration_is_checked_before_database_work() {
    let (_dir, data_dir) = scratch();
    let absent = data_dir.join("must-not-be-created");
    let missing_config = data_dir.join("missing.toml");
    let output = cass(&["search", "query", "--mode", "semantic", "--json",
        "--data-dir", absent.to_str().unwrap(), "--api-config", missing_config.to_str().unwrap()], &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("ModelApiConfiguration"));
    assert!(!absent.exists(), "configuration refusal must not create a database or self-heal state");
    let _storage = build_db(&data_dir, &["a synthetic searchable document for lexical independence"]);
    let lexical = cass(&["search", "synthetic", "--mode", "lexical", "--json",
        "--data-dir", data_dir.to_str().unwrap(), "--api-config", missing_config.to_str().unwrap()], &[]);
    assert_success(&lexical);
}

#[test]
fn api_rerank_window_pages_without_http_and_rejects_changed_instruction() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(&data_dir, &[
        "synthetic document alpha with enough detail to score",
        "synthetic document beta with other detail to score",
        "synthetic document gamma with distinct detail to score",
    ]);
    let embed = Stub::start(healthy_responder(8, 0));
    let stub = Stub::start(|request, _| {
        let body = request.body_json();
        let docs = body["documents"].as_array().expect("whole rerank document window");
        let rows: Vec<_> = (0..docs.len()).map(|i| serde_json::json!({"index": i, "relevance_score": i as f64})).collect();
        (200, serde_json::json!({"model":"example/dynamic-reranker", "results":rows}).to_string())
    });
    let config = data_dir.join("models.toml");
    let mut text = format!("version=1\ndefault_embedding=\"local8\"\ndefault_rerank=\"ranker\"\n[profiles.ranker]\nkind=\"rerank\"\nprotocol=\"rerank-json-v1\"\nscope=\"loopback\"\nendpoint=\"{}\"\nmodel=\"example/dynamic-reranker\"\nmodel_revision=\"r1\"\ninstruction=\"first instruction\"\n", stub.endpoint());
    text.push_str(&embedding_profile_block("local8", &embed.endpoint(), EMBED_MODEL, EMBED_REVISION, 64, ""));
    fs::write(&config, &text).unwrap();
    assert_success(&run_backfill(&data_dir, &config, None, &[]));
    let args = ["search", "synthetic", "--mode", "lexical", "--json", "--robot-meta",
        "--rerank", "--rrf-limit", "3", "--rerank-limit", "1", "--rerank-profile", "ranker",
        "--data-dir", data_dir.to_str().unwrap(), "--api-config", config.to_str().unwrap()];
    let first = assert_success(&cass(&args, &[]));
    assert_eq!(stub.requests().len(), 1, "{first}");
    let sent = stub.requests()[0].body_json();
    assert_eq!(sent["documents"].as_array().unwrap().len(), 3);
    assert_eq!(sent["top_n"], 3);
    assert_eq!(sent["instruct"], "first instruction");
    let mut legacy = args.to_vec(); legacy.extend(["--rerank-provider", "qwen3-local"]);
    let rejected = cass(&legacy, &[]);
    assert_eq!(rejected.status.code(), Some(2));
    assert!(stderr_text(&rejected).contains("ModelApiMigration"));
    assert_eq!(stub.requests().len(), 1);

    assert_eq!(first["_meta"]["rerank"]["applied"], true, "{first}");
    assert_eq!(first["_meta"]["rerank"]["requested_model"], "example/dynamic-reranker");
    assert_eq!(first["_meta"]["rerank"]["model_api"]["realized_profile"], "ranker");
    let cursor = first["_meta"]["next_cursor"].as_str().expect("next cursor");
    let mut next = args.to_vec(); next.extend(["--cursor", cursor]);
    let second = assert_success(&cass(&next, &[]));
    assert_eq!(second["_meta"]["rerank"]["cache_reused"], true);
    assert_eq!(stub.requests().len(), 1, "continuation sends no HTTP");
    for changed in [
        text.replace("first instruction", "different instruction"),
        text.replace("example/dynamic-reranker", "example/other-reranker"),
        text.replace(&stub.endpoint(), &format!("{}/changed-path", stub.origin())),
    ] {
        fs::write(&config, changed).unwrap();
        let denied = cass(&next, &[]);
        assert!(!denied.status.success(), "old cursor cannot use changed route config");
        assert_eq!(stub.requests().len(), 1, "changed cursor is refused before HTTP");
    }
    fs::write(&config, &text).unwrap();
    drop(stub);
    let offline = assert_success(&cass(&next, &[]));
    assert_eq!(offline["_meta"]["rerank"]["cache_reused"], true);
    assert_eq!(offline["_meta"]["rerank"]["http_requests"], 0);
    assert_eq!(offline["hits"], second["hits"], "server shutdown does not change the frozen page");
}

#[test]
fn api_query_without_a_generation_preserves_hybrid_policy_without_http() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(&data_dir, &["synthetic document for hybrid without an active generation"]);
    let stub = Stub::start(healthy_responder(8, 0));
    let config = data_dir.join("models.toml");
    fs::write(&config, config_text("local8", &embedding_profile_block(
        "local8", &stub.endpoint(), EMBED_MODEL, EMBED_REVISION, 64, "",
    ))).unwrap();
    let hybrid = cass(&["search", "synthetic", "--mode", "hybrid", "--json", "--robot-meta",
        "--data-dir", data_dir.to_str().unwrap(), "--api-config", config.to_str().unwrap()], &[]);
    let result = assert_success(&hybrid);
    assert_eq!(result["_meta"]["search_mode"], "lexical");
    let semantic = cass(&["search", "synthetic", "--mode", "semantic", "--json",
        "--data-dir", data_dir.to_str().unwrap(), "--api-config", config.to_str().unwrap()], &[]);
    assert_eq!(semantic.status.code(), Some(15));
    assert_eq!(stub.requests().len(), 0);
}

#[test]
fn compatibility_capture_cli_publishes_private_pinned_files_and_never_overwrites() {
    use sha2::{Digest,Sha256};
    let digest=|bytes:&[u8]| hex::encode(Sha256::digest(bytes));
    let (_dir,data_dir)=scratch();
    let server=Stub::start(healthy_responder(8,0));
    let config=data_dir.join("models.toml");
    fs::write(&config,config_text("local8",&embedding_profile_block("local8",&server.endpoint(),EMBED_MODEL,EMBED_REVISION,2,"query_prefix = \"Q:\""))).unwrap();
    let texts=vec!["Rust 所有权是什么？".to_owned(),"Rust ownership tracks values.".to_owned(),"fn lock() {}".to_owned(),"café ☃".to_owned(),"lock".to_owned(),"x ".repeat(45)];
    let categories=["chinese","english","code","unicode","short","long"];
    let fixture=serde_json::json!({"version":1,"samples":texts.iter().enumerate().map(|(i,text)|serde_json::json!({"id":format!("s{i}"),"text":text,"coverage":categories[i]})).collect::<Vec<_>>(),
        "documents":["s1","s2"],"queries":[{"sample":"s0","expected_document":"s1"},{"sample":"s4","expected_document":"s2"}]});
    let declaration=serde_json::json!({"basis":"operator_declared","value":"synthetic test source"});
    let counter=serde_json::json!({"basis":"operator_declared","value":"synthetic scalar counter"});
    let inputs=|prefix:&str| texts.iter().map(|s|format!("{prefix}{s}")).collect::<Vec<_>>();
    let query=inputs("Q:"); let document=inputs(DOCUMENT_PREFIX);
    let records=|texts:&[String]| texts.iter().map(|s|serde_json::json!({"input_sha256":digest(s.as_bytes()),"token_ids":s.chars().map(|c|c as u32).collect::<Vec<_>>()})).collect::<Vec<_>>();
    let tokens=serde_json::json!({"version":1,"counter_id":"synthetic scalar counter","counter_source_sha256":digest(b"synthetic counter source"),
        "tokenizer_declaration_sha256":digest(&serde_json::to_vec(&declaration).unwrap()),"query":records(&query),"document":records(&document)});
    let token_bytes=serde_json::to_vec(&tokens).unwrap();
    let sources=serde_json::json!({"weights":declaration,"tokenizer":declaration,"pooling":declaration,"server_input_template":declaration,
        "token_counter":counter,"token_counter_artifact_sha256":digest(&token_bytes),"safe_input_tokens":100,
        "query_token_counts":query.iter().map(|s|s.chars().count()).collect::<Vec<_>>(),"document_token_counts":document.iter().map(|s|s.chars().count()).collect::<Vec<_>>()});
    let fixture_bytes=serde_json::to_vec(&fixture).unwrap(); let source_bytes=serde_json::to_vec(&sources).unwrap();
    let fixture_path=data_dir.join("fixture.json");let source_path=data_dir.join("sources.json");let token_path=data_dir.join("tokens.json");
    fs::write(&fixture_path,&fixture_bytes).unwrap();fs::write(&source_path,&source_bytes).unwrap();fs::write(&token_path,&token_bytes).unwrap();
    let fixture_sha=digest(&fixture_bytes);let source_sha=digest(&source_bytes);let token_sha=digest(&token_bytes);
    let output=data_dir.join("capture-result");
    let args=["models","capture-compatibility","--profile","local8","--api-config",config.to_str().unwrap(),"--json",
        "--fixture",fixture_path.to_str().unwrap(),"--fixture-sha256",&fixture_sha,
        "--sources",source_path.to_str().unwrap(),"--sources-sha256",&source_sha,
        "--token-receipt",token_path.to_str().unwrap(),"--token-receipt-sha256",&token_sha,"--output",output.to_str().unwrap()];
    let result=assert_success(&cass(&args,&[]));
    assert_eq!(result["status"],"captured");assert_eq!(result["requests"],12);assert_eq!(server.requests().len(),12);
    let manifest_bytes=fs::read(output.join("capture-manifest.json")).unwrap();
    assert_eq!(result["manifest_sha256"],digest(&manifest_bytes));
    let manifest:serde_json::Value=serde_json::from_slice(&manifest_bytes).unwrap();
    for field in ["fixture","capture","token_receipt","calls"] {
        let path=output.join(manifest[field]["name"].as_str().unwrap());
        assert_eq!(digest(&fs::read(&path).unwrap()),manifest[field]["sha256"]);
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;assert_eq!(fs::metadata(path).unwrap().permissions().mode()&0o777,0o600);}
    }
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;assert_eq!(fs::metadata(&output).unwrap().permissions().mode()&0o777,0o700);}
    let repeated=cass(&args,&[]);assert!(!repeated.status.success());
    assert_eq!(server.requests().len(),12);assert_eq!(manifest_bytes,fs::read(output.join("capture-manifest.json")).unwrap());
}

#[test]
fn absent_api_configuration_cannot_fall_through_to_a_legacy_backend() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("not-created");
    let output = cass(&argv(&args_without_config(&data)), &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("ModelApiConfiguration"));
    assert!(!data.exists(), "missing configuration must fail before database or lock creation");
}

#[test]
fn search_retires_local_selectors_before_any_database_work() {
    for selector in [vec!["--model", "hash"], vec!["--daemon"], vec!["--reranker", "minilm"], vec!["--rerank-provider", "qwen3-local"]] {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("not-created");
        let data_text = data.display().to_string();
        let mut args = vec!["search", "example", "--json", "--data-dir", data_text.as_str()];
        args.extend(selector);
        let output = cass(&args, &[]);
        assert_eq!(output.status.code(), Some(2), "{}", stderr_text(&output));
        assert!(stderr_text(&output).contains("ModelApiMigration"), "{}", stderr_text(&output));
        assert!(!data.exists());
    }
}

#[test]
fn semantic_search_requires_api_config_but_dry_run_remains_model_free() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("not-created");
    let data_text = data.display().to_string();
    for mode in ["semantic", "hybrid"] {
        let output = cass(&["search", "example", "--json", "--mode", mode, "--data-dir", &data_text], &[]);
        assert_eq!(output.status.code(), Some(2), "{}", stderr_text(&output));
        assert!(stderr_text(&output).contains("ModelApiConfiguration"));
        assert!(!data.exists());
    }
    let output = cass(&["search", "example", "--json", "--dry-run", "--data-dir", &data_text], &[]);
    assert!(output.status.success(), "{}", stderr_text(&output));
    assert!(!data.exists());
}

#[test]
fn model_configuration_is_validated_before_refresh_and_dry_run_never_refreshes() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("not-created");
    let data_text = data.display().to_string();
    let missing = root.path().join("missing.toml").display().to_string();
    let output = cass(&["search", "example", "--json", "--refresh", "--api-config", &missing,
        "--data-dir", &data_text], &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("ModelApiConfiguration"));
    assert!(!data.exists(), "configuration refusal must precede refresh ingestion");
    let output = cass(&["search", "example", "--json", "--dry-run", "--refresh", "--data-dir", &data_text], &[]);
    assert!(output.status.success(), "{}", stderr_text(&output));
    assert!(!data.exists(), "query analysis must not refresh the index");
}

#[test]
fn retired_local_model_commands_preserve_files_and_send_no_http() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let model_dir = data.join("models").join("all-MiniLM-L6-v2");
    fs::create_dir_all(&model_dir).unwrap();
    let sentinel = model_dir.join("model.onnx");
    fs::write(&sentinel, b"synthetic existing asset; do not modify").unwrap();
    let service = Stub::start(healthy_responder(8, 0));
    let endpoint = service.endpoint();
    let data_text = data.display().to_string();
    let commands = [
        vec!["install", "--mirror", endpoint.as_str(), "--yes"],
        vec!["verify", "--repair"],
        vec!["remove", "--model", "all-minilm-l6-v2", "--yes"],
        vec!["check-update"],
    ];
    for command in commands {
        let mut args = vec!["--robot-format", "json", "models"];
        args.extend(command);
        args.extend(["--data-dir", data_text.as_str()]);
        let output = cass(&args, &[]);
        assert_eq!(output.status.code(), Some(2), "{}", stderr_text(&output));
        assert!(stderr_text(&output).contains("ModelApiMigration"), "{}", stderr_text(&output));
        assert_eq!(fs::read(&sentinel).unwrap(), b"synthetic existing asset; do not modify");
        assert!(!data.join("agent_search.db").exists());
    }
    assert!(service.requests().is_empty());
}

#[test]
fn index_semantic_uses_frozen_api_configuration_without_ingestion() {
    let (_dir, data_dir) = scratch();
    let storage = build_db(&data_dir, &["A synthetic index document verifies the API vector pipeline."]);
    let config = data_dir.join("index-models.toml");
    let config_for_service = config.clone();
    let service = Stub::start(move |request: &RecordedRequest, index: usize| {
        if index == 0 { fs::write(&config_for_service, "invalid after command freeze").unwrap(); }
        respond_embed(request, &request.inputs(), 8, 0)
    });
    fs::write(&config, config_text("local8", &embedding_profile_block("local8", &service.endpoint(), EMBED_MODEL, EMBED_REVISION, 64, ""))).unwrap();
    let output = cass(&["index", "--semantic", "--no-ingest", "--json", "--data-dir", &data_dir.display().to_string(),
        "--api-config", &config.display().to_string(), "--embedding-profile", "local8"], &[]);
    assert!(output.status.success(), "{}", stderr_text(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["scan_invocations"], 0);
    let calls = &report["indexing_stats"]["model_api"];
    assert_eq!(calls["primary_profile"], "local8");
    assert!(!calls["probe_calls"].as_array().unwrap().is_empty());
    assert!(!calls["document_calls"].as_array().unwrap().is_empty());
    assert!(!calls["audit_calls"].as_array().unwrap().is_empty());
    let dim: i64 = storage.raw().query_row_map("SELECT dim FROM embedding_generations WHERE is_active=1", &[], |row| row.get_typed(0)).unwrap();
    assert_eq!(dim, 8);
    let count: i64 = storage.raw().query_row_map("SELECT COUNT(*) FROM message_chunks", &[], |row|row.get_typed(0)).unwrap();
    assert_eq!(count, 1);
    assert!(service.requests().len() >= 3, "probe, document and audit must execute against the same frozen endpoint");
}

#[test]
fn index_rejects_missing_api_configuration_and_retired_selector_before_writes() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("not-created");
    let output = cass(&["index", "--semantic", "--no-ingest", "--json", "--data-dir", &data.display().to_string()], &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("ModelApiConfiguration"));
    assert!(!data.exists());
    let output = cass(&["index", "--semantic", "--embedder", "infinity", "--json", "--data-dir", &data.display().to_string()], &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr_text(&output));
    assert!(stderr_text(&output).contains("ModelApiMigration"));
    assert!(!data.exists());
}

#[test]
fn index_failure_preserves_actual_model_request_evidence() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(&data_dir, &["A synthetic document verifies index failure evidence."]);
    let service = Stub::start(|_: &RecordedRequest, _: usize| (503, "{}".into()));
    let config = data_dir.join("index-models.toml");
    fs::write(&config, config_text("local8", &embedding_profile_block("local8", &service.endpoint(), EMBED_MODEL, EMBED_REVISION, 64, ""))).unwrap();
    let output = cass(&["index", "--semantic", "--no-ingest", "--json", "--data-dir", &data_dir.display().to_string(), "--api-config", &config.display().to_string()], &[]);
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["model_api"]["primary_profile"], "local8");
    let calls = report["model_api"]["probe_calls"].as_array().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["http_status"], 503);
    assert_eq!(service.requests().len(), 1);
}

#[test]
fn semantic_watch_once_ingests_appended_events_and_reuses_api_generation() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let codex = home.join(".codex");
    let sessions = codex.join("sessions/2026/05/28");
    fs::create_dir_all(&sessions).unwrap();
    let session = sessions.join("rollout-api-watch.jsonl");
    let initial = concat!(
        "{\"timestamp\":\"2026-05-28T09:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"api-watch\",\"cwd\":\"/synthetic\"}}\n",
        "{\"timestamp\":\"2026-05-28T09:00:01Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"A synthetic first message verifies the watch API pipeline.\"}]}}\n",
    );
    fs::write(&session, initial).unwrap();
    let data = root.path().join("data");
    fs::create_dir_all(&data).unwrap();
    let service = Stub::start(healthy_responder(8, 0));
    let config = root.path().join("models.toml");
    fs::write(&config, config_text("local8", &embedding_profile_block("local8", &service.endpoint(), EMBED_MODEL, EMBED_REVISION, 64, ""))).unwrap();
    let home_text = home.display().to_string();
    let codex_text = codex.display().to_string();
    let xdg_data = root.path().join("xdg-data").display().to_string();
    let xdg_config = root.path().join("xdg-config").display().to_string();
    let envs = [("HOME", home_text.as_str()), ("CODEX_HOME", codex_text.as_str()),
        ("XDG_DATA_HOME", xdg_data.as_str()), ("XDG_CONFIG_HOME", xdg_config.as_str()),
        ("CASS_IGNORE_SOURCES_CONFIG", "1"), ("CASS_RESPONSIVENESS_DISABLE", "1")];
    let run = || cass(&["index", "--semantic", "--watch-once", &session.display().to_string(),
        "--api-config", &config.display().to_string(), "--data-dir", &data.display().to_string(), "--json"], &envs);
    let first = run();
    assert!(first.status.success(), "{}", stderr_text(&first));
    let storage = FrankenStorage::open_readonly(&data.join("agent_search.db")).unwrap();
    let generation: i64 = storage.raw().query_row_map("SELECT id FROM embedding_generations WHERE is_active=1", &[], |row|row.get_typed(0)).unwrap();
    let chunks: i64 = storage.raw().query_row_map("SELECT COUNT(*) FROM message_chunks", &[], |row|row.get_typed(0)).unwrap();
    assert_eq!(chunks, 1);
    drop(storage);
    let added = "{\"timestamp\":\"2026-05-28T09:00:02Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"A synthetic appended answer verifies the next watch pass.\"}]}}\n";
    fs::write(&session, format!("{initial}{added}")).unwrap();
    let second = run();
    assert!(second.status.success(), "{}", stderr_text(&second));
    let storage = FrankenStorage::open_readonly(&data.join("agent_search.db")).unwrap();
    let active: i64 = storage.raw().query_row_map("SELECT id FROM embedding_generations WHERE is_active=1", &[], |row|row.get_typed(0)).unwrap();
    assert_eq!(active, generation);
    let counts: (i64,i64) = storage.raw().query_row_map("SELECT (SELECT COUNT(*) FROM messages),(SELECT COUNT(*) FROM message_chunks)", &[], |row|Ok((row.get_typed(0)?,row.get_typed(1)?))).unwrap();
    assert_eq!(counts, (2,2));
    let report: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(report["indexing_stats"]["model_api"]["primary_profile"], "local8");
    assert!(!service.requests().is_empty());
}

// ---------------------------------------------------------------------------
// The `_meta.rerank` machine schema against the real API window
// ---------------------------------------------------------------------------

/// The shipped machine schema for `_meta.rerank`.
///
/// It is read back from the binary's own discovery surface rather than from a
/// copy of the source, so this guard covers what a caller actually receives
/// from `cass introspect --json`.
fn rerank_meta_schema() -> serde_json::Value {
    let output = cass(&["introspect", "--json"], &[]);
    let document = assert_success(&output);
    let schemas = &document["response_schemas"];
    let schema = schemas["search"]["properties"]["_meta"]["properties"]["rerank"].clone();
    assert!(
        schema.is_object(),
        "introspect must publish the search rerank schema: {document}"
    );
    assert_eq!(
        schemas["search-rerank-meta"], schema,
        "both discovery paths must publish the same rerank schema"
    );
    schema
}

/// The JSON type name of a value, as a schema `type` spells it.
fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Check one emitted object against a schema object: the same keys, all of them
/// required, each value admitted by its declared type. The recursion reaches
/// every nested object and every array element, so no declared-but-unchecked
/// `{"type": "object"}` can hide a missing or mistyped field.
fn assert_object_matches_schema(schema: &serde_json::Value, value: &serde_json::Value, path: &str) {
    let emitted = value
        .as_object()
        .unwrap_or_else(|| panic!("{path} must be an object, got {value}"));
    let declared = schema["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("{path}: schema has no properties: {schema}"));
    let mut emitted_keys: Vec<&str> = emitted.keys().map(String::as_str).collect();
    let mut declared_keys: Vec<&str> = declared.keys().map(String::as_str).collect();
    emitted_keys.sort_unstable();
    declared_keys.sort_unstable();
    assert_eq!(
        emitted_keys, declared_keys,
        "{path}: the schema must name exactly the emitted fields"
    );
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap_or_else(|| panic!("{path}: schema has no required list: {schema}"))
        .iter()
        .map(|key| key.as_str().expect("required entries are strings"))
        .collect();
    for key in &declared_keys {
        assert!(
            required.contains(key),
            "{path}.{key} is always emitted, so it must be required"
        );
        let property = declared[*key]
            .as_object()
            .unwrap_or_else(|| panic!("{path}.{key}: property is not an object"));
        let field = format!("{path}.{key}");
        assert_value_matches_property(property, &emitted[*key], &field);
    }
}

/// Check one emitted value against one declared property.
fn assert_value_matches_property(
    property: &serde_json::Map<String, serde_json::Value>,
    value: &serde_json::Value,
    path: &str,
) {
    let kinds: Vec<&str> = match &property["type"] {
        serde_json::Value::String(name) => vec![name.as_str()],
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().expect("type entries are strings"))
            .collect(),
        other => panic!("{path}: property declares no type: {other}"),
    };
    let actual = json_type_name(value);
    assert!(
        kinds.contains(&actual),
        "{path}: emitted {actual} is not one of {kinds:?}"
    );
    // A `pattern` constrains strings only. A `null` (or any other branch the
    // type list admits) is already settled by the check above, so a nullable
    // patterned field must not be rejected merely for holding `null`.
    if let (Some(pattern), Some(text)) = (
        property.get("pattern").and_then(|pattern| pattern.as_str()),
        value.as_str(),
    ) {
        assert!(
            regex::Regex::new(pattern).expect("schema pattern compiles").is_match(text),
            "{path}: {text:?} does not satisfy the declared pattern {pattern:?}"
        );
    }
    // An array's element schema lives under `items`, not `properties`; recursing
    // through it is what makes the nested attempts (and their usage) checked
    // rather than waved through by a bare `{"type": "array"}`. Like `pattern`,
    // `items` applies only to the branch it describes: a `null` admitted by the
    // type list has no elements to check.
    if let Some(element) = property.get("items") {
        if let Some(rows) = value.as_array() {
            let element = element
                .as_object()
                .unwrap_or_else(|| panic!("{path}: items is not an object: {element}"));
            for (index, row) in rows.iter().enumerate() {
                assert_value_matches_property(element, row, &format!("{path}[{index}]"));
            }
        }
    }
    // The same applies to a nested object schema: it is checked only when an
    // object was actually emitted.
    if let Some(nested) = property.get("properties") {
        if value.is_object() {
            let wrapper = serde_json::json!({
                "properties": nested,
                "required": property.get("required").cloned().unwrap_or(serde_json::json!([])),
            });
            assert_object_matches_schema(&wrapper, value, path);
        }
    }
}

/// The machine schema must describe what a real API-backed window emits.
///
/// Both windows below come from a real `cass` process scoring real SQLite
/// content through a real loopback service; the schema comes from the same
/// binary's `introspect`. A schema that drops an emitted field, leaves one
/// unrequired, or still whitelists the retired `ProviderChoice` selections
/// fails here instead of at a caller.
#[test]
fn the_rerank_meta_schema_describes_the_real_api_window() {
    let (_dir, data_dir) = scratch();
    let _storage = build_db(&data_dir, &[
        "synthetic document alpha with enough detail to score",
        "synthetic document beta with other detail to score",
        "synthetic document gamma with distinct detail to score",
    ]);
    let embed = Stub::start(healthy_responder(8, 0));
    // The first scoring call reports a usage block and the second reports none,
    // so the emitted `usage` field is really exercised on both its branches.
    let stub = Stub::start(|request, call| {
        let body = request.body_json();
        let docs = body["documents"].as_array().expect("whole rerank document window");
        let rows: Vec<_> = (0..docs.len()).map(|i| serde_json::json!({"index": i, "relevance_score": i as f64})).collect();
        let mut reply = serde_json::json!({"model":"example/dynamic-reranker", "results":rows});
        if call == 0 {
            reply["usage"] = serde_json::json!({"prompt_tokens": 11, "total_tokens": 11, "cost": 0.0001});
        }
        (200, reply.to_string())
    });
    // Two operator-chosen profile ids. Neither is one of the retired
    // `ProviderChoice` names, so a schema that still enumerates those five
    // cannot accept both.
    // The second id carries a dot, which is inside the configured profile-id
    // vocabulary; the table header is quoted so TOML does not read the dot as a
    // table separator.
    let profiles = ["ranker", "ranker-north.2"];
    let config = data_dir.join("models.toml");
    let mut text = String::from("version=1\ndefault_embedding=\"local8\"\n");
    for id in profiles {
        text.push_str(&format!(
            "[profiles.\"{id}\"]\nkind=\"rerank\"\nprotocol=\"rerank-json-v1\"\nscope=\"loopback\"\n\
             endpoint=\"{}\"\nmodel=\"example/dynamic-reranker\"\nmodel_revision=\"r1\"\n",
            stub.endpoint()
        ));
    }
    text.push_str(&embedding_profile_block("local8", &embed.endpoint(), EMBED_MODEL, EMBED_REVISION, 64, ""));
    fs::write(&config, &text).unwrap();
    assert_success(&run_backfill(&data_dir, &config, None, &[]));

    let schema = rerank_meta_schema();
    assert_eq!(
        schema["properties"]["requested_provider"].get("enum"), None,
        "a profile id is operator-chosen, so the schema must not whitelist providers: {schema}"
    );
    assert_eq!(
        schema["properties"]["model_api"]["type"],
        serde_json::json!(["object", "null"]),
        "the API evidence is optional on the wire: {schema}"
    );

    let search = |query: &str, id: &str| {
        cass(&[
            "search", query, "--mode", "lexical", "--json", "--robot-meta",
            "--rerank", "--rrf-limit", "3", "--rerank-limit", "3", "--rerank-profile", id,
            "--data-dir", data_dir.to_str().unwrap(), "--api-config", config.to_str().unwrap(),
        ], &[])
    };
    let mut reported_usage = Vec::new();
    for id in profiles {
        let result = assert_success(&search("synthetic", id));
        let meta = &result["_meta"]["rerank"];
        assert_eq!(meta["applied"], true, "{result}");
        assert_eq!(meta["requested_provider"], id, "{result}");
        assert!(meta["model_api"].is_object(), "a scored window carries its API evidence: {result}");
        let attempt = &meta["model_api"]["attempts"][0];
        assert_eq!(attempt["profile"], id, "{result}");
        reported_usage.push(attempt["usage"].clone());
        assert_object_matches_schema(&schema, meta, "_meta.rerank");
    }
    assert_eq!(stub.requests().len(), 2, "one scoring call per profile");
    // `usage` is optional on the wire: the service that reported it must show an
    // object, and the one that reported nothing must show null — both admitted
    // by the same declared field.
    assert!(
        reported_usage[0].is_object(),
        "a reported usage block must survive to the window: {reported_usage:?}"
    );
    assert!(
        reported_usage[1].is_null(),
        "a service that reported no usage must not have one invented: {reported_usage:?}"
    );

    // The same command with nothing to score keeps a window whose API evidence
    // is absent, so the schema's own `null` branch is exercised on real output
    // rather than only on the type array.
    let empty = assert_success(&search("no-synthetic-document-matches-this", &profiles[0]));
    let meta = &empty["_meta"]["rerank"];
    assert!(meta.is_object(), "an unscored window still renders its rerank meta: {empty}");
    assert!(meta["model_api"].is_null(), "no call ran, so no evidence is claimed: {empty}");
    assert_object_matches_schema(&schema, meta, "_meta.rerank");
}
