//! PR3 P09: the real-CLI contract of `cass search --rerank`.
//!
//! Every assertion here drives the real `cass` binary against a real
//! file-backed schema-8 database, and the rerank backend is a loopback HTTP
//! stub reached through `CASS_INFINITY_URL`. Nothing stubs the search path or
//! the argument struct: the seam the ticket asks for is "real CLI subprocess,
//! real file library, real HTTP requests, real window cache on disk".
//!
//! The fixture builds genuine chunks: each `message_chunks` row carries the
//! `content_hash_hex` of the `canonicalize_for_embedding` + `chunk_normalized`
//! span it claims, so `context::build_documents` can prove every candidate
//! before the model is asked to score it. Nothing here copies the PR9 distance
//! test's synthetic `content_hash`.
//!
//! The stub scores with a *strictly increasing* function of the input index,
//! so a correct rerank reverses the RRF order. That makes every page's exact
//! identity predictable from the closed-state first `N`, which is what each
//! group below asserts -- not merely "the page changed".

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use coding_agent_search::search::canonicalize::{
    CANONICALIZE_PIPELINE_VERSION, canonicalize_for_embedding, content_hash_hex,
};
use coding_agent_search::search::chunking::{CHUNKING_POLICY_VERSION, chunk_normalized};
use coding_agent_search::storage::api::{TxMode, Value};
use coding_agent_search::storage::schema::{self, ChunkRow};
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::vector_domain;

const EMBED_DIM: i64 = 1024;
const RERANK_MODEL: &str = "BAAI/bge-reranker-v2-m3";
const EMBED_MODEL: &str = "BAAI/bge-m3";
const QUERY: &str = "p09 anchor token";
const DEFAULT_N: usize = 200;
const DEFAULT_K: usize = 5;

// ---------------------------------------------------------------------------
// A tiny loopback HTTP fixture that records every request it answers
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

/// The canned behaviour of the stub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StubMode {
    /// `score(i) = i`: strictly increasing, so a correct rerank reverses the
    /// input order and every page is exactly predictable.
    Ordered,
    /// Every score identical: a correct rerank keeps the input order and still
    /// reports `applied=true`.
    Tied,
    /// Drop the last score: a short array, which must be refused whole.
    MissingScore,
    /// Duplicate one index: a non-permutation, refused whole.
    DuplicateIndex,
    /// Name a model that is not an accepted alias for the selection.
    IdentityMismatch,
    /// Answer `/models` with a card for a different model.
    WrongModelList,
}

struct Stub {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<RecordedRequest>>>,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Stub {
    fn start(mode: StubMode) -> Stub {
        Stub::start_with_delay(mode, Duration::ZERO)
    }

    fn start_with_delay(mode: StubMode, delay: Duration) -> Stub {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind rerank stub");
        let addr = listener.local_addr().expect("stub local_addr");
        listener.set_nonblocking(true).expect("stub nonblocking");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let seen_thread = Arc::clone(&seen);
        let stop_thread = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Some(request) = read_http_request(stream.try_clone().expect("clone"))
                        {
                            if !delay.is_zero() {
                                thread::sleep(delay);
                            }
                            let response = response_for(mode, &request);
                            seen_thread.lock().expect("stub lock").push(request);
                            let _ = write_http_response(stream, response);
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
            thread: Mutex::new(Some(thread)),
        }
    }

    fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.seen.lock().expect("stub lock").clone()
    }

    fn request_count(&self) -> usize {
        self.seen.lock().expect("stub lock").len()
    }

    /// Stop answering but keep the recorded requests readable.
    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.lock().expect("stub thread lock").take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_http_request(mut stream: TcpStream) -> Option<RecordedRequest> {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(headers_end) = find_subslice(&buffer, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..headers_end]).to_string();
            let content_length = head
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
            let body_start = headers_end + 4;
            if buffer.len() >= body_start + content_length {
                let body = buffer[body_start..body_start + content_length].to_vec();
                let mut parts = head.lines().next().unwrap_or_default().split(' ');
                let method = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or_default().to_string();
                return Some(RecordedRequest { method, path, body });
            }
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_http_response(mut stream: TcpStream, body: Vec<u8>) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Write);
    Ok(())
}

fn response_for(mode: StubMode, request: &RecordedRequest) -> Vec<u8> {
    if request.path == "/models" {
        let id = if mode == StubMode::WrongModelList {
            "BAAI/bge-m3"
        } else {
            RERANK_MODEL
        };
        return serde_json::json!({ "data": [ { "id": id }, { "id": EMBED_MODEL } ] })
            .to_string()
            .into_bytes();
    }
    if request.path == "/embeddings" {
        let body: serde_json::Value = serde_json::from_slice(&request.body).expect("embedding body");
        assert_eq!(body["model"], EMBED_MODEL);
        let inputs = body["input"].as_array().expect("embedding inputs");
        let data: Vec<_> = (0..inputs.len())
            .map(|index| serde_json::json!({ "index": index, "embedding": fixture_embedding() }))
            .collect();
        return serde_json::json!({ "model": EMBED_MODEL, "data": data })
            .to_string()
            .into_bytes();
    }
    if request.path == "/rerank" {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).unwrap_or(serde_json::Value::Null);
        let count = body
            .get("documents")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let mut results: Vec<serde_json::Value> = (0..count)
            .map(|index| {
                let score = match mode {
                    StubMode::Tied => 1.0,
                    _ => index as f64,
                };
                serde_json::json!({ "index": index, "relevance_score": score })
            })
            .collect();
        match mode {
            StubMode::MissingScore => {
                results.pop();
            }
            StubMode::DuplicateIndex => {
                if results.len() >= 2 {
                    results[1] = results[0].clone();
                }
            }
            _ => {}
        }
        let model = if mode == StubMode::IdentityMismatch {
            "not/the-right-model"
        } else {
            RERANK_MODEL
        };
        return serde_json::json!({ "model": model, "results": results })
            .to_string()
            .into_bytes();
    }
    serde_json::json!({ "error": "not found" })
        .to_string()
        .into_bytes()
}

// ---------------------------------------------------------------------------
// The schema-8 fixture
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct FixtureOptions {
    rows: usize,
    /// Install a genuine float/vector domain for synthetic hybrid searches.
    semantic: bool,
    /// Write a scan watermark ahead of the indexed watermark, the durable
    /// half-finished-index signature `state_meta_json` reports as `partial`.
    partial: bool,
    /// Place a regular file where the rerank window directory must be, so
    /// `WindowStore::new` refuses with `cache_unavailable`.
    block_cache: bool,
    /// Drop this row index's `message_chunks`, so `build_documents` cannot
    /// prove that candidate and refuses the whole window.
    corrupt_chunk_at: Option<usize>,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        FixtureOptions {
            rows: DEFAULT_N + 1,
            semantic: false,
            partial: false,
            block_cache: false,
            corrupt_chunk_at: None,
        }
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    data_dir: PathBuf,
    db_path: PathBuf,
}

fn fixture_embedding() -> Vec<f32> {
    let mut vector = vec![0.0; EMBED_DIM as usize];
    vector[0] = 1.0;
    vector
}

fn build_fixture(options: FixtureOptions) -> Fixture {
    let dir = tempfile::tempdir().expect("fixture tempdir");
    let home = dir.path().join("home");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&home).expect("create home");
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let db_path = data_dir.join("agent_search.db");

    {
        let storage = FrankenStorage::open(&db_path).expect("open schema-8 fixture db");
        let conn = storage.raw();
        conn.execute_batch(
            "INSERT INTO agents(id,slug,name,kind,created_at,updated_at) \
             VALUES(1,'codex','codex','cli',0,0);",
        )
        .expect("insert agent");

        let generation = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                schema::create_embedding_generation(
                    tx,
                    "bge-m3",
                    EMBED_DIM,
                    CANONICALIZE_PIPELINE_VERSION,
                    CHUNKING_POLICY_VERSION,
                    b"p09-fixture",
                    1,
                )
            })
            .expect("create generation");
        if options.semantic {
            vector_domain::create_vec0_table_for_generation(conn, generation, EMBED_DIM)
                .expect("create synthetic vector domain");
        }

        for index in 0..options.rows {
            let message_id = 1000 + index as i64;
            // ASCII content stays under one chunk, so one message_chunks row.
            let content = format!(
                "p09 anchor token document {index} lorem ipsum dolor sit amet {}",
                "x".repeat(40)
            );
            let title = format!("P09 anchor {index}");
            let source_path = format!("/fixture/p09-{index}.jsonl");
            conn.with_tx_no_replay(TxMode::Immediate, |tx| {
                tx.execute(
                    "INSERT INTO conversations(id,agent_id,source_id,title,source_path) \
                     VALUES(?1,1,'local',?2,?3)",
                    &[
                        Value::from(message_id),
                        Value::from(title.clone()),
                        Value::from(source_path.clone()),
                    ],
                )?;
                tx.execute(
                    "INSERT INTO messages(id,conversation_id,idx,role,created_at,content) \
                     VALUES(?1,?1,0,'user',1,?2)",
                    &[Value::from(message_id), Value::from(content.clone())],
                )?;
                tx.execute(
                    "INSERT INTO lex_docs(doc_id,content,title,agent,workspace,source_path) \
                     VALUES(?1,?2,?3,'codex','',?4)",
                    &[
                        Value::from(message_id),
                        Value::from(content.clone()),
                        Value::from(title.clone()),
                        Value::from(source_path.clone()),
                    ],
                )?;
                if options.corrupt_chunk_at == Some(index) {
                    return Ok(());
                }
                let canonical = canonicalize_for_embedding(&content);
                for span in chunk_normalized(&canonical) {
                    let hash = content_hash_hex(&canonical[span.byte_start..span.byte_end]);
                    let embedding = if options.semantic {
                        fixture_embedding()
                    } else {
                        vec![0.0_f32; EMBED_DIM as usize]
                    };
                    let chunk_id = schema::insert_chunk_row_in_tx(
                        tx,
                        &ChunkRow {
                            generation_id: generation,
                            message_id,
                            conversation_id: message_id,
                            chunk_idx: span.chunk_idx,
                            byte_start: span.byte_start,
                            byte_end: span.byte_end,
                            content_hash: hash,
                            embedding: embedding.clone(),
                            // The schema enforces `norm > 0`.
                            norm: 1.0,
                            created_at_ms: 1,
                        },
                    )?;
                    if options.semantic {
                        let blob = schema::f32_vector_to_le_blob(&embedding);
                        vector_domain::insert_vec0_rows_in_tx(
                            tx,
                            generation,
                            &[(chunk_id, blob.as_slice())],
                        )?;
                    }
                }
                Ok(())
            })
            .expect("insert fixture row");
        }

        conn.execute_batch("INSERT INTO fts_lex(fts_lex) VALUES('rebuild');")
            .expect("rebuild fts_lex");
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('lex_domain_rebuild_state', ?1)",
            &[Value::from(format!(
                "completed:{}:{}",
                options.rows, options.rows
            ))],
        )
        .expect("set lex marker");
        // `vector_domain_instance_id` is written once by the schema itself
        // (a random 32-hex identity) and is immutable, so the fixture must not
        // touch it.
        conn.execute(
            "UPDATE embedding_generations SET is_active=1, audit_status='passed' WHERE id=?1",
            &[Value::from(generation)],
        )
        .expect("activate generation");

        if options.partial {
            // A scan advanced past the last completed projection: the durable
            // half-finished-index signature, not an age-staleness one.
            storage
                .set_last_indexed_at(1_733_000_000_000)
                .expect("set last_indexed_at");
            storage
                .set_last_scan_ts(1_733_000_002_000)
                .expect("set last_scan_ts");
        }
    }

    if options.block_cache {
        let cache = data_dir.join("cache");
        std::fs::create_dir_all(&cache).expect("create cache dir");
        // A regular file where the window directory must be: the private-cache
        // gate refuses it without any fault-injection switch.
        std::fs::write(cache.join("rerank-windows"), b"not a directory").expect("block cache dir");
    }

    Fixture {
        _dir: dir,
        home,
        data_dir,
        db_path,
    }
}

// ---------------------------------------------------------------------------
// CLI helpers
// ---------------------------------------------------------------------------

/// A local port nothing listens on (the discard port): the default origin for
/// every Command that is not served by this ticket's stub, so no test can
/// reach a real Qwen/Infinity service.
const DEAD_ORIGIN: &str = "http://127.0.0.1:9/";

struct RunEnv<'a> {
    fixture: &'a Fixture,
    stub: Option<&'a Stub>,
    /// Point `CASS_QWEN_RERANK_URL` at the same stub as `CASS_INFINITY_URL`, so
    /// a provider change keeps the endpoint identical and isolates the
    /// provider binding.
    qwen_at_stub: bool,
    /// Override `CASS_INFINITY_URL` (e.g. an origin the binding must refuse).
    infinity_override: Option<String>,
    extra_env: Vec<(&'static str, String)>,
}

impl<'a> RunEnv<'a> {
    fn new(fixture: &'a Fixture) -> Self {
        RunEnv {
            fixture,
            stub: None,
            qwen_at_stub: false,
            infinity_override: None,
            extra_env: Vec::new(),
        }
    }

    fn with_stub(fixture: &'a Fixture, stub: &'a Stub) -> Self {
        RunEnv {
            fixture,
            stub: Some(stub),
            qwen_at_stub: false,
            infinity_override: None,
            extra_env: Vec::new(),
        }
    }

    fn qwen_at_stub(mut self) -> Self {
        self.qwen_at_stub = true;
        self
    }

    fn infinity_url(mut self, url: &str) -> Self {
        self.infinity_override = Some(url.to_string());
        self
    }

    fn env(mut self, key: &'static str, value: &str) -> Self {
        self.extra_env.push((key, value.to_string()));
        self
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cass"));
        command.env_clear();
        command.env("PATH", std::env::var_os("PATH").unwrap_or_default());
        command.env("HOME", &self.fixture.home);
        command.env("TMPDIR", &self.fixture.home);
        command.env("XDG_DATA_HOME", self.fixture.home.join("xdg-data"));
        command.env("XDG_CONFIG_HOME", self.fixture.home.join("xdg-config"));
        command.env("XDG_CACHE_HOME", self.fixture.home.join("xdg-cache"));
        command.env("CASS_OUTPUT_FORMAT", "json");
        let stub_origin = self.stub.map(Stub::origin);
        let infinity = self
            .infinity_override
            .clone()
            .or_else(|| stub_origin.clone())
            .unwrap_or_else(|| DEAD_ORIGIN.to_string());
        command.env("CASS_INFINITY_URL", infinity);
        let qwen = if self.qwen_at_stub {
            stub_origin
                .clone()
                .unwrap_or_else(|| DEAD_ORIGIN.to_string())
        } else {
            DEAD_ORIGIN.to_string()
        };
        command.env("CASS_QWEN_RERANK_URL", qwen);
        for (key, value) in &self.extra_env {
            command.env(key, value);
        }
        command.current_dir(&self.fixture.home);
        command.arg("--data-dir").arg(&self.fixture.data_dir);
        command.args(args);
        command.output().expect("run cass binary")
    }
}

fn stdout_json(output: &Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(text.trim()).unwrap_or_else(|err| {
        panic!(
            "stdout is not valid JSON ({err}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed with {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Each fixture row has a unique `source_path`, so it is a stable public
/// identity across output projections and truncation.
fn ids(payload: &serde_json::Value) -> Vec<String> {
    hits(payload)
        .iter()
        .filter_map(|hit| {
            hit.get("source_path")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn hits(payload: &serde_json::Value) -> Vec<serde_json::Value> {
    payload
        .get("hits")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// `(source_path, score, rerank_score)` for every hit, in output order.
fn scored_hits(payload: &serde_json::Value) -> Vec<(String, f64, Option<f64>)> {
    hits(payload)
        .iter()
        .map(|hit| {
            (
                hit.get("source_path")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                hit.get("score")
                    .and_then(serde_json::Value::as_f64)
                    .unwrap_or_default(),
                hit.get("rerank_score").and_then(serde_json::Value::as_f64),
            )
        })
        .collect()
}

fn rerank_meta(payload: &serde_json::Value) -> Option<&serde_json::Value> {
    payload.get("_meta").and_then(|meta| meta.get("rerank"))
}

fn next_cursor(payload: &serde_json::Value) -> Option<String> {
    payload
        .get("_meta")
        .and_then(|meta| meta.get("next_cursor"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn require_cursor(payload: &serde_json::Value) -> String {
    next_cursor(payload).expect("a continuation cursor is present")
}

/// The documents the stub received in its one `/rerank` POST.
fn posted_documents(stub: &Stub) -> Vec<serde_json::Value> {
    let requests = stub.requests();
    let rerank = requests
        .iter()
        .find(|request| request.path == "/rerank")
        .expect("a /rerank request must have been recorded");
    let body: serde_json::Value =
        serde_json::from_slice(&rerank.body).expect("rerank body is JSON");
    body.get("documents")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn posted_top_n(stub: &Stub) -> Option<u64> {
    let requests = stub.requests();
    let rerank = requests
        .iter()
        .find(|request| request.path == "/rerank")
        .expect("a /rerank request must have been recorded");
    let body: serde_json::Value =
        serde_json::from_slice(&rerank.body).expect("rerank body is JSON");
    body.get("top_n").and_then(serde_json::Value::as_u64)
}

fn rerank_args(n: usize, k: usize) -> Vec<String> {
    vec![
        "search".to_string(),
        QUERY.to_string(),
        "--mode".to_string(),
        "lexical".to_string(),
        "--rerank".to_string(),
        "--rerank-provider".to_string(),
        "bge-local".to_string(),
        "--rrf-limit".to_string(),
        n.to_string(),
        "--rerank-limit".to_string(),
        k.to_string(),
        "--json".to_string(),
        "--robot-meta".to_string(),
    ]
}

fn as_args(owned: &[String]) -> Vec<&str> {
    owned.iter().map(String::as_str).collect()
}

fn closed_args(n: usize) -> Vec<String> {
    vec![
        "search".to_string(),
        QUERY.to_string(),
        "--mode".to_string(),
        "lexical".to_string(),
        "--rrf-limit".to_string(),
        n.to_string(),
        "--json".to_string(),
    ]
}

/// The closed-state first `N` identities, in RRF order.
fn closed_first_n(env: &RunEnv<'_>, n: usize) -> Vec<String> {
    let out = env.run(&as_args(&closed_args(n)));
    assert_success(&out, "closed lexical lookup");
    ids(&stdout_json(&out))
}

/// A well-formed rerank cursor naming `window_id` at `offset`.
fn synthetic_cursor(window_id: &str, offset: usize) -> String {
    use base64::Engine as _;
    let payload = serde_json::json!({ "version": 2, "window_id": window_id, "offset": offset });
    base64::prelude::BASE64_STANDARD.encode(payload.to_string())
}

// ---------------------------------------------------------------------------
// Group 1 - the first lookup: full N POSTed, K returned, exact order
// ---------------------------------------------------------------------------

#[test]
fn group1_first_lookup_posts_n_returns_k_in_the_reranked_order() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let output = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&output, "first rerank lookup");
    let payload = stdout_json(&output);

    // Exactly one BGE call: one GET /models then one POST /rerank, whose
    // `top_n` is the actual window size.
    let requests = stub.requests();
    assert_eq!(requests.len(), 2, "one readiness GET and one scoring POST");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/models");
    assert_eq!(requests[1].method, "POST");
    assert_eq!(requests[1].path, "/rerank");
    assert_eq!(
        posted_top_n(&stub),
        Some(DEFAULT_N as u64),
        "top_n must be N"
    );
    assert_eq!(
        posted_documents(&stub).len(),
        DEFAULT_N,
        "the whole N window must be POSTed"
    );

    // The window is the closed-state first N; a strictly increasing score
    // reverses it, so pages 1..2 are exact suffixes of that window.
    let closed = env.run(&as_args(&closed_args(DEFAULT_N)));
    assert_success(&closed, "closed lexical lookup");
    let closed_payload = stdout_json(&closed);
    let window_ids: Vec<String> = ids(&closed_payload).into_iter().take(DEFAULT_N).collect();
    assert_eq!(
        window_ids.len(),
        DEFAULT_N,
        "the closed run fills the window"
    );
    let mut expected_order = window_ids.clone();
    expected_order.reverse();

    let page = scored_hits(&payload);
    assert_eq!(page.len(), DEFAULT_K, "the page is K wide");
    assert_eq!(
        page.iter().map(|(id, _, _)| id.clone()).collect::<Vec<_>>(),
        expected_order[..DEFAULT_K].to_vec(),
        "the first page is the reranked window's first K, by identity"
    );

    // Every hit carries the score the stub returned for its window slot, and
    // no hit's original RRF score was overwritten.
    let closed_scores: std::collections::HashMap<String, f64> = scored_hits(&closed_payload)
        .into_iter()
        .map(|(id, score, _)| (id, score))
        .collect();
    for (position, (id, score, rerank_score)) in page.iter().enumerate() {
        // The page walks the window in reverse, so page position `p` is window
        // slot `N - 1 - p`, whose stub score is `N - 1 - p`.
        let window_slot = DEFAULT_N - 1 - position;
        assert_eq!(
            *rerank_score,
            Some(window_slot as f64),
            "hit {id} carries the stub score for window slot {window_slot}"
        );
        assert_eq!(
            Some(score),
            closed_scores.get(id),
            "hit {id} keeps its original RRF score"
        );
    }
    for hit in hits(&payload) {
        assert!(
            hit.get("content_hash").is_none(),
            "no private hash in public JSON"
        );
    }

    let meta = rerank_meta(&payload).expect("_meta.rerank is present");
    assert_eq!(meta["applied"], serde_json::json!(true));
    assert_eq!(meta["window_count"], serde_json::json!(DEFAULT_N));
    assert_eq!(meta["scored_count"], serde_json::json!(DEFAULT_N));
    assert_eq!(meta["rerank_limit"], serde_json::json!(DEFAULT_K));
    assert_eq!(meta["rrf_limit"], serde_json::json!(DEFAULT_N));
    assert_eq!(meta["returned_count"], serde_json::json!(DEFAULT_K));
    assert_eq!(meta["cache_reused"], serde_json::json!(false));
    assert_eq!(meta["requested_provider"], serde_json::json!("bge-local"));
    assert_eq!(meta["actual_provider"], serde_json::json!("bge-local"));
    assert_eq!(meta["first_http_requests"], serde_json::json!(2));
    assert_eq!(meta["http_requests"], serde_json::json!(2));
    assert_eq!(meta["first_model_requests"], serde_json::json!(1));
    assert_eq!(meta["model_requests"], serde_json::json!(1));
    assert_eq!(meta["failure_reason"], serde_json::Value::Null);
    assert!(
        next_cursor(&payload).is_some(),
        "a full window emits a cursor"
    );

    // The POSTed documents are the closed-state first N, in order, each
    // canonicalized exactly as `context::build_documents` assembles a
    // single-chunk candidate.
    let expected_documents: Vec<serde_json::Value> = hits(&closed_payload)
        .iter()
        .take(DEFAULT_N)
        .map(|hit| {
            let content = hit
                .get("content")
                .and_then(serde_json::Value::as_str)
                .expect("closed hit carries content");
            serde_json::Value::from(canonicalize_for_embedding(content))
        })
        .collect();
    assert_eq!(
        posted_documents(&stub),
        expected_documents,
        "the model input is the closed-state first N, in order"
    );

    // Tied scores keep the input order and still report `applied=true`.
    let tied_fixture = build_fixture(FixtureOptions::default());
    let tied_stub = Stub::start(StubMode::Tied);
    let tied_env = RunEnv::with_stub(&tied_fixture, &tied_stub);
    let tied = tied_env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&tied, "tied-score rerank");
    let tied_payload = stdout_json(&tied);
    assert_eq!(
        ids(&tied_payload),
        window_ids[..DEFAULT_K].to_vec(),
        "equal scores keep the original RRF order"
    );
    let tied_meta = rerank_meta(&tied_payload).expect("_meta.rerank");
    assert_eq!(tied_meta["applied"], serde_json::json!(true));
    for (_, _, rerank_score) in scored_hits(&tied_payload) {
        assert_eq!(rerank_score, Some(1.0), "the tied score is written per hit");
    }
}

// ---------------------------------------------------------------------------
// Group 2 - the continuation, and the window boundaries
// ---------------------------------------------------------------------------

#[test]
fn group2_continuation_reuses_the_window_and_pages_exactly() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let first = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&first, "first rerank lookup");
    let first_payload = stdout_json(&first);
    let cursor = require_cursor(&first_payload);
    let requests_after_first = stub.request_count();

    // The service is gone for the second page.
    stub.stop();

    let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
    args.push("--cursor".to_string());
    args.push(cursor);
    let second = env.run(&as_args(&args));
    assert_success(&second, "continuation lookup");
    let second_payload = stdout_json(&second);

    assert_eq!(
        stub.request_count(),
        requests_after_first,
        "a continuation makes no new HTTP request"
    );

    let closed = env.run(&as_args(&closed_args(DEFAULT_N)));
    let mut expected_order: Vec<String> = ids(&stdout_json(&closed));
    expected_order.truncate(DEFAULT_N);
    expected_order.reverse();

    assert_eq!(
        ids(&first_payload),
        expected_order[..DEFAULT_K].to_vec(),
        "page 1 is the reranked window's first K"
    );
    assert_eq!(
        ids(&second_payload),
        expected_order[DEFAULT_K..DEFAULT_K * 2].to_vec(),
        "page 2 is the reranked window's next K"
    );

    let meta = rerank_meta(&second_payload).expect("_meta.rerank on the continuation");
    assert_eq!(meta["cache_reused"], serde_json::json!(true));
    assert_eq!(meta["http_requests"], serde_json::json!(0));
    assert_eq!(meta["model_requests"], serde_json::json!(0));
    assert_eq!(meta["first_http_requests"], serde_json::json!(2));
    assert_eq!(meta["first_model_requests"], serde_json::json!(1));
    assert_eq!(meta["offset"], serde_json::json!(DEFAULT_K));
    assert_eq!(meta["returned_count"], serde_json::json!(DEFAULT_K));
    assert_eq!(meta["applied"], serde_json::json!(true));
    assert!(meta["first_duration_ms"].as_u64().is_some());
    assert!(
        next_cursor(&second_payload).is_some() || DEFAULT_N == DEFAULT_K * 2,
        "a window longer than two pages keeps a cursor"
    );
}

/// A continuation must not call the model, and that has to be proven against a
/// service that could record the call. The stub stays up for the whole test, so
/// its received-request count is real evidence: a continuation that re-ran the
/// model would be counted here. The failed window has a separate test so a
/// failure in this test cannot prevent its mutation check from running.
#[test]
fn online_success_window_continuation_makes_no_backend_request() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let first = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&first, "first rerank lookup");
    let first_payload = stdout_json(&first);
    let cursor = require_cursor(&first_payload);
    let first_meta = rerank_meta(&first_payload).expect("first rerank metadata");
    assert_eq!(first_meta["applied"], serde_json::json!(true));
    assert_eq!(first_meta["scored_count"], serde_json::json!(DEFAULT_N));
    assert!(first_meta["failure_reason"].is_null());

    let closed = env.run(&as_args(&closed_args(DEFAULT_N)));
    assert_success(&closed, "closed-state ordering reference");
    let mut expected_order: Vec<String> = ids(&stdout_json(&closed));
    expected_order.truncate(DEFAULT_N);
    expected_order.reverse();

    assert_eq!(ids(&first_payload), expected_order[..DEFAULT_K].to_vec());
    // All state is fixture-local. The stub stays online for the second process.
    let requests_before = stub.requests();
    assert_eq!(requests_before.len(), 2, "first lookup reached the backend");
    assert_eq!(requests_before[0].path, "/models");
    assert_eq!(requests_before[1].path, "/rerank");
    let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
    args.push("--cursor".to_string());
    args.push(cursor);
    let second = env.run(&as_args(&args));
    assert_success(&second, "continuation with the service still up");
    let requests_after = stub.requests();
    eprintln!(
        "ONLINE_SUCCESS_REQUESTS before={} after={} new={:?}",
        requests_before.len(),
        requests_after.len(),
        requests_after
            .iter()
            .skip(requests_before.len())
            .map(|request| (&request.method, &request.path))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        requests_after.len(),
        requests_before.len(),
        "the still-running service received no request from the continuation"
    );
    assert_eq!(
        requests_after, requests_before,
        "the actual request list is unchanged"
    );
    let second_payload = stdout_json(&second);
    assert_eq!(
        ids(&second_payload),
        expected_order[DEFAULT_K..DEFAULT_K * 2].to_vec(),
        "the continuation still returns the frozen second page"
    );
    for (_, _, score) in scored_hits(&second_payload) {
        assert!(score.is_some(), "the successful window keeps its scores");
    }
    let second_meta = rerank_meta(&second_payload).expect("continuation rerank metadata");
    for field in [
        "first_http_requests",
        "first_model_requests",
        "first_duration_ms",
        "applied",
        "scored_count",
        "failure_reason",
        "http_status",
    ] {
        assert_eq!(
            second_meta[field], first_meta[field],
            "frozen field {field}"
        );
    }
    assert_eq!(second_meta["cache_reused"], serde_json::json!(true));
    assert_eq!(second_meta["offset"], serde_json::json!(DEFAULT_K));
    assert_eq!(second_meta["returned_count"], serde_json::json!(DEFAULT_K));
    for field in ["http_requests", "model_requests", "duration_ms"] {
        assert_eq!(
            second_meta[field],
            serde_json::json!(0),
            "current field {field}"
        );
    }
}

#[test]
fn online_failed_window_continuation_makes_no_backend_request() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::MissingScore);
    let env = RunEnv::with_stub(&fixture, &stub);

    let first = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&first, "first lookup with a failing score response");
    let first_payload = stdout_json(&first);
    let cursor = require_cursor(&first_payload);
    let first_meta = rerank_meta(&first_payload).expect("first rerank metadata");
    assert_eq!(first_meta["applied"], serde_json::json!(false));
    assert_eq!(first_meta["scored_count"], serde_json::json!(0));
    assert!(first_meta["failure_reason"].is_string());
    for (_, _, score) in scored_hits(&first_payload) {
        assert!(score.is_none(), "the failed first page has no rerank score");
    }

    let closed = env.run(&as_args(&closed_args(DEFAULT_N)));
    assert_success(&closed, "closed-state ordering reference");
    let mut original: Vec<String> = ids(&stdout_json(&closed));
    original.truncate(DEFAULT_N);

    assert_eq!(ids(&first_payload), original[..DEFAULT_K].to_vec());
    let requests_before = stub.requests();
    assert_eq!(
        requests_before.len(),
        2,
        "the first lookup attempted scoring"
    );
    assert_eq!(requests_before[0].path, "/models");
    assert_eq!(requests_before[1].path, "/rerank");
    let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
    args.push("--cursor".to_string());
    args.push(cursor);
    let second = env.run(&as_args(&args));
    assert_success(
        &second,
        "failed-window continuation with the service still up",
    );
    let requests_after = stub.requests();
    eprintln!(
        "ONLINE_FAILED_REQUESTS before={} after={} new={:?}",
        requests_before.len(),
        requests_after.len(),
        requests_after
            .iter()
            .skip(requests_before.len())
            .map(|request| (&request.method, &request.path))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        requests_after.len(),
        requests_before.len(),
        "a failed window's continuation also makes no call, proven against a service that is up"
    );
    assert_eq!(
        requests_after, requests_before,
        "the actual request list is unchanged"
    );
    let second_payload = stdout_json(&second);
    assert_eq!(
        ids(&second_payload),
        original[DEFAULT_K..DEFAULT_K * 2].to_vec(),
        "the failed window replays in the original order"
    );
    for (_, _, score) in scored_hits(&second_payload) {
        assert!(
            score.is_none(),
            "the failed continuation has no rerank score"
        );
    }
    let second_meta = rerank_meta(&second_payload).expect("continuation rerank metadata");
    for field in [
        "first_http_requests",
        "first_model_requests",
        "first_duration_ms",
        "applied",
        "scored_count",
        "failure_reason",
        "http_status",
    ] {
        assert_eq!(
            second_meta[field], first_meta[field],
            "frozen field {field}"
        );
    }
    assert_eq!(second_meta["cache_reused"], serde_json::json!(true));
    assert_eq!(second_meta["offset"], serde_json::json!(DEFAULT_K));
    assert_eq!(second_meta["returned_count"], serde_json::json!(DEFAULT_K));
    for field in ["http_requests", "model_requests", "duration_ms"] {
        assert_eq!(
            second_meta[field],
            serde_json::json!(0),
            "current field {field}"
        );
    }
}

#[test]
fn group2_window_boundaries() {
    // (a) A window exactly one page long delivers the whole window and stops.
    // K may not exceed N, so the shortest honest page is K == N == 3.
    let fixture = build_fixture(FixtureOptions {
        rows: 4,
        ..FixtureOptions::default()
    });
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);
    let short = env.run(&as_args(&rerank_args(3, 3)));
    assert_success(&short, "one-page window rerank");
    let short_payload = stdout_json(&short);
    assert_eq!(ids(&short_payload).len(), 3, "a 3-hit window delivers 3");
    let meta = rerank_meta(&short_payload).expect("_meta.rerank");
    assert_eq!(meta["window_count"], serde_json::json!(3));
    assert_eq!(meta["returned_count"], serde_json::json!(3));
    assert!(
        next_cursor(&short_payload).is_none(),
        "the window end emits no cursor"
    );

    // (b) The last page of a two-page window stops cleanly.
    let fixture = build_fixture(FixtureOptions {
        rows: 7,
        ..FixtureOptions::default()
    });
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);
    let page1 = env.run(&as_args(&rerank_args(7, 5)));
    assert_success(&page1, "page 1 of a 7-hit window");
    let cursor = require_cursor(&stdout_json(&page1));
    let mut args = rerank_args(7, 5);
    args.push("--cursor".to_string());
    args.push(cursor);
    let page2 = env.run(&as_args(&args));
    assert_success(&page2, "page 2 of a 7-hit window");
    let page2_payload = stdout_json(&page2);
    assert_eq!(
        ids(&page2_payload).len(),
        2,
        "the trailing page holds the remainder"
    );
    assert!(
        next_cursor(&page2_payload).is_none(),
        "the last page emits no cursor"
    );

    // (c) An empty match set is a normal empty page: no request, no cursor.
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);
    let empty = env.run(&[
        "search",
        "zzz-no-such-token-zzz",
        "--mode",
        "lexical",
        "--rerank",
        "--rerank-provider",
        "bge-local",
        "--rrf-limit",
        "50",
        "--rerank-limit",
        "5",
        "--json",
        "--robot-meta",
    ]);
    assert_success(&empty, "empty rerank lookup");
    assert_eq!(stub.request_count(), 0, "an empty window makes no request");
    let empty_payload = stdout_json(&empty);
    assert!(hits(&empty_payload).is_empty(), "no hits");
    let meta = rerank_meta(&empty_payload).expect("_meta.rerank");
    assert_eq!(meta["applied"], serde_json::json!(false));
    assert_eq!(meta["scored_count"], serde_json::json!(0));
    assert_eq!(meta["first_http_requests"], serde_json::json!(0));
    assert!(
        next_cursor(&empty_payload).is_none(),
        "an empty window has no next page"
    );
}

// ---------------------------------------------------------------------------
// Group 3 - failures roll back the whole window, and are not retried
// ---------------------------------------------------------------------------

#[test]
fn group3_a_bad_response_keeps_the_original_order_and_is_not_retried() {
    for mode in [
        StubMode::MissingScore,
        StubMode::DuplicateIndex,
        StubMode::IdentityMismatch,
    ] {
        let fixture = build_fixture(FixtureOptions::default());
        let stub = Stub::start(mode);
        let env = RunEnv::with_stub(&fixture, &stub);

        let output = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
        assert_success(&output, "a bad response still returns a page");
        let payload = stdout_json(&output);

        let closed = env.run(&as_args(&closed_args(DEFAULT_N)));
        let expected: Vec<String> = ids(&stdout_json(&closed))
            .into_iter()
            .take(DEFAULT_K)
            .collect();
        assert_eq!(
            ids(&payload),
            expected,
            "a failed window keeps the original RRF order for {mode:?}"
        );
        for (_, _, rerank_score) in scored_hits(&payload) {
            assert!(
                rerank_score.is_none(),
                "no hit carries a score after a failure"
            );
        }
        let meta = rerank_meta(&payload).expect("_meta.rerank");
        assert_eq!(meta["applied"], serde_json::json!(false));
        assert_eq!(meta["scored_count"], serde_json::json!(0));
        assert!(
            meta["failure_reason"].is_string(),
            "the failure reason is a short code"
        );

        // The failed window is still frozen: its continuation replays the same
        // original order and makes no further model call.
        let cursor = require_cursor(&payload);
        let requests_before = stub.request_count();
        stub.stop();
        let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
        args.push("--cursor".to_string());
        args.push(cursor);
        let second = env.run(&as_args(&args));
        assert_success(&second, "continuation of a failed window");
        let second_payload = stdout_json(&second);
        let expected_next: Vec<String> = ids(&stdout_json(&closed))
            .into_iter()
            .skip(DEFAULT_K)
            .take(DEFAULT_K)
            .collect();
        assert_eq!(
            ids(&second_payload),
            expected_next,
            "the failed window's next page keeps the original order"
        );
        let meta = rerank_meta(&second_payload).expect("_meta.rerank");
        assert_eq!(
            meta["applied"],
            serde_json::json!(false),
            "no re-application"
        );
        assert_eq!(meta["http_requests"], serde_json::json!(0), "no retry");
        assert_eq!(meta["model_requests"], serde_json::json!(0), "no retry");
        assert_eq!(
            stub.request_count(),
            requests_before,
            "the stub saw nothing new"
        );
    }
}

#[test]
fn group3_an_unverifiable_candidate_sends_nothing_to_the_model() {
    // The unverifiable row sits *outside* the first page but inside the
    // window, so only a whole-window proof can catch it.
    let corrupt_at = DEFAULT_N - 1;
    let fixture = build_fixture(FixtureOptions {
        corrupt_chunk_at: Some(corrupt_at),
        ..FixtureOptions::default()
    });
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let output = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&output, "an unverifiable candidate still returns a page");
    assert_eq!(
        stub.request_count(),
        0,
        "a candidate that cannot be proven means the whole window sends nothing"
    );
    let payload = stdout_json(&output);
    assert_eq!(
        ids(&payload).len(),
        DEFAULT_K,
        "the original page is delivered"
    );
    for (_, _, rerank_score) in scored_hits(&payload) {
        assert!(rerank_score.is_none(), "no partial scores leak out");
    }
    let meta = rerank_meta(&payload).expect("_meta.rerank");
    assert_eq!(meta["applied"], serde_json::json!(false));
    assert_eq!(meta["first_http_requests"], serde_json::json!(0));
    assert_eq!(meta["http_requests"], serde_json::json!(0));
    assert_eq!(meta["scored_count"], serde_json::json!(0));
    assert_eq!(
        meta["failure_reason"],
        serde_json::json!("input_identity_mismatch")
    );
}

// ---------------------------------------------------------------------------
// Group 4 - a cursor is bound to its exact request and its index
// ---------------------------------------------------------------------------

#[test]
fn group4_a_cursor_is_refused_when_the_request_or_index_changes() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let first = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&first, "first rerank lookup");
    let cursor = require_cursor(&stdout_json(&first));

    let with_cursor = |extra: &[&str]| {
        let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
        args.push("--cursor".to_string());
        args.push(cursor.clone());
        args.extend(extra.iter().map(|s| (*s).to_string()));
        args
    };

    let cases: Vec<(&str, Vec<String>)> = vec![
        ("changed query", {
            let mut args = with_cursor(&[]);
            args[1] = "p09 anchor token other".to_string();
            args
        }),
        ("changed K", {
            let mut args = with_cursor(&[]);
            let k = args.iter().position(|a| a == "--rerank-limit").unwrap();
            args[k + 1] = "7".to_string();
            args
        }),
        ("changed N", {
            let mut args = with_cursor(&[]);
            let n = args.iter().position(|a| a == "--rrf-limit").unwrap();
            args[n + 1] = "199".to_string();
            args
        }),
        ("changed provider", {
            let mut args = with_cursor(&[]);
            let p = args.iter().position(|a| a == "--rerank-provider").unwrap();
            args[p + 1] = "qwen3-local".to_string();
            args
        }),
        ("changed filter", with_cursor(&["--agent", "other-agent"])),
        ("changed relative time", with_cursor(&["--days", "1"])),
        ("refresh with a cursor", with_cursor(&["--refresh"])),
        (
            "non-zero offset with a cursor",
            with_cursor(&["--offset", "3"]),
        ),
        ("malformed cursor", {
            let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
            args.push("--cursor".to_string());
            args.push("not-a-cursor".to_string());
            args
        }),
        ("a window that does not exist", {
            let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
            args.push("--cursor".to_string());
            args.push(synthetic_cursor(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                0,
            ));
            args
        }),
    ];

    for (label, args) in &cases {
        let output = env.run(&as_args(args));
        assert_eq!(
            output.status.code(),
            Some(2),
            "{label} must be a usage error; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // A real write to the index invalidates the frozen window.
    {
        let storage = FrankenStorage::open(&fixture.db_path).expect("reopen fixture db");
        storage
            .raw()
            .execute(
                "UPDATE messages SET content = content || ' touched' WHERE id = 1000",
                &[],
            )
            .expect("write to the indexed archive");
    }
    let stale = env.run(&as_args(&with_cursor(&[])));
    assert_eq!(
        stale.status.code(),
        Some(2),
        "an index write after the first page invalidates its cursor"
    );
}

// ---------------------------------------------------------------------------
// Group 5 - projection and budgets never change the model input
// ---------------------------------------------------------------------------

#[test]
fn group5_projection_and_budget_do_not_change_the_model_input() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let plain = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&plain, "plain first lookup");
    let plain_documents = posted_documents(&stub);

    let mut shaped = rerank_args(DEFAULT_N, DEFAULT_K);
    shaped.extend_from_slice(&[
        "--fields".to_string(),
        "minimal".to_string(),
        "--max-content-length".to_string(),
        "20".to_string(),
        "--max-tokens".to_string(),
        "400".to_string(),
    ]);
    let projected = env.run(&as_args(&shaped));
    assert_success(&projected, "projected first lookup");
    let requests = stub.requests();
    let last_rerank = requests
        .iter()
        .rev()
        .find(|request| request.path == "/rerank")
        .expect("a second /rerank POST");
    let projected_body: serde_json::Value =
        serde_json::from_slice(&last_rerank.body).expect("rerank body is JSON");
    assert_eq!(
        projected_body
            .get("documents")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default(),
        plain_documents,
        "field projection and content budgets never change what the model sees"
    );
    assert_eq!(
        projected_body
            .get("top_n")
            .and_then(serde_json::Value::as_u64),
        Some(DEFAULT_N as u64),
        "top_n stays the window size under every projection"
    );
}

#[test]
fn group5_a_shrunk_page_advances_by_delivered_hits_without_skipping() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let closed = env.run(&as_args(&closed_args(DEFAULT_N)));
    let mut expected_order: Vec<String> = ids(&stdout_json(&closed));
    expected_order.truncate(DEFAULT_N);
    expected_order.reverse();

    let mut budgeted = rerank_args(DEFAULT_N, DEFAULT_K);
    budgeted.extend_from_slice(&["--max-tokens".to_string(), "80".to_string()]);
    let first = env.run(&as_args(&budgeted));
    assert_success(&first, "budgeted first lookup");
    let first_payload = stdout_json(&first);
    let returned = ids(&first_payload);
    assert!(
        !returned.is_empty(),
        "a budget still delivers at least one hit"
    );
    assert!(
        returned.len() < DEFAULT_K,
        "the budget shrinks the page below K"
    );
    assert_eq!(
        returned,
        expected_order[..returned.len()].to_vec(),
        "the shrunk page is the window's prefix"
    );
    let meta = rerank_meta(&first_payload).expect("_meta.rerank");
    assert_eq!(
        meta["returned_count"].as_u64(),
        Some(returned.len() as u64),
        "returned_count reflects the post-budget count"
    );

    let cursor = require_cursor(&first_payload);
    let mut next_args = budgeted.clone();
    next_args.push("--cursor".to_string());
    next_args.push(cursor);
    let second = env.run(&as_args(&next_args));
    assert_success(&second, "continuation after a shrunk page");
    let second_payload = stdout_json(&second);
    let meta = rerank_meta(&second_payload).expect("_meta.rerank on continuation");
    assert_eq!(
        meta["offset"].as_u64(),
        Some(returned.len() as u64),
        "the next page starts exactly where this one stopped, not at K"
    );

    let mut concatenated = returned.clone();
    concatenated.extend(ids(&second_payload));
    assert_eq!(
        concatenated,
        expected_order[..concatenated.len()].to_vec(),
        "the two pages are the window's prefix of the same length, with no gap"
    );
}

// ---------------------------------------------------------------------------
// Group 6 - aggregates/explain, dry-run, and the no-cursor states
// ---------------------------------------------------------------------------

#[test]
fn group6_aggregates_and_explanation_match_the_closed_scope_and_are_reused() {
    assert_frozen_aggregate_statistics(false);
}

#[test]
fn group6_hybrid_aggregates_freeze_prefetch_statistics_without_an_exact_total() {
    assert_frozen_aggregate_statistics(true);
}

fn assert_frozen_aggregate_statistics(semantic: bool) {
    // All state belongs to this fixture or its child processes. No global
    // environment or shared counter is changed by either parallel test.
    let fixture = build_fixture(FixtureOptions {
        semantic,
        ..FixtureOptions::default()
    });
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
    if semantic {
        args[3] = "hybrid".to_string();
        args.extend_from_slice(&["--model".to_string(), "bge-m3".to_string()]);
    }
    args.extend_from_slice(&[
        "--aggregate".to_string(),
        "agent".to_string(),
        "--explain".to_string(),
    ]);
    let first = env.run(&as_args(&args));
    assert_success(&first, "rerank with aggregate/explain");
    let first_payload = stdout_json(&first);
    let first_aggregations = first_payload
        .get("aggregations")
        .cloned()
        .expect("aggregations present");
    let cursor = require_cursor(&first_payload);
    assert_eq!(first_payload["total_matches"], DEFAULT_N + 1);
    assert_eq!(
        first_payload["_meta"]["cursor_manifest"]["count_precision"],
        "lower_bound"
    );
    assert_eq!(posted_documents(&stub).len(), DEFAULT_N);
    if semantic {
        assert_eq!(first_payload["_meta"]["search_mode"], "hybrid");
        assert_eq!(first_payload["candidates"]["incomplete"], false);
        let window_id = coding_agent_search::search::rerank::window::cursor_window_id(&cursor)
            .expect("validated window cursor");
        let snapshot: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                fixture
                    .data_dir
                    .join("cache/rerank-windows")
                    .join(format!("{window_id}.json")),
            )
            .expect("read actual persisted window"),
        )
        .expect("window JSON");
        assert!(snapshot["result"]["total_count"].is_null());
        assert_eq!(snapshot["retrieval_status"]["total_matches"], DEFAULT_N + 1);
        assert_eq!(snapshot["retrieval_status"]["total_matches_exact"], false);
    }

    // The closed state computes the same aggregates over the same prefetch
    // scope; the two must agree value for value.
    let mut closed = closed_args(DEFAULT_N);
    if semantic {
        closed[3] = "hybrid".to_string();
        closed.extend_from_slice(&["--model".to_string(), "bge-m3".to_string()]);
    }
    closed.extend_from_slice(&[
        "--aggregate".to_string(),
        "agent".to_string(),
        "--explain".to_string(),
    ]);
    let closed_out = env.run(&as_args(&closed));
    assert_success(&closed_out, "closed aggregate/explain");
    let closed_payload = stdout_json(&closed_out);
    assert_eq!(
        first_aggregations,
        closed_payload
            .get("aggregations")
            .cloned()
            .unwrap_or_default(),
        "the rerank window's aggregate scope matches the closed-state scope"
    );
    assert!(
        first_payload.get("explanation").is_some(),
        "explain is computed on the first lookup"
    );

    // The continuation reuses the frozen aggregates instead of recomputing.
    let mut next = args.clone();
    next.push("--cursor".to_string());
    next.push(cursor);
    let second = env.run(&as_args(&next));
    assert_success(&second, "continuation with aggregate/explain");
    let second_payload = stdout_json(&second);
    assert_eq!(second_payload["total_matches"], first_payload["total_matches"]);
    assert_eq!(
        second_payload["_meta"]["cursor_manifest"]["count_precision"],
        first_payload["_meta"]["cursor_manifest"]["count_precision"]
    );
    assert_eq!(
        second_payload
            .get("aggregations")
            .cloned()
            .unwrap_or_default(),
        first_aggregations,
        "the continuation reuses the frozen aggregates"
    );
    assert_eq!(
        second_payload
            .get("explanation")
            .cloned()
            .unwrap_or_default(),
        first_payload
            .get("explanation")
            .cloned()
            .unwrap_or_default(),
        "the continuation reuses the frozen explanation"
    );
}

#[test]
fn group6_dry_run_writes_no_cache_and_sends_no_request() {
    // A fresh fixture with no window cache at all, so any cache write is
    // observable as a newly created directory or file.
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let cache_dir = fixture.data_dir.join("cache");
    assert!(!cache_dir.exists(), "no cache before the dry run");

    // A well-formed cursor that names a window which was never written.
    let cursor = synthetic_cursor(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        0,
    );
    let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
    args.push("--dry-run".to_string());
    args.push("--cursor".to_string());
    args.push(cursor);
    let dry = env.run(&as_args(&args));
    assert_success(&dry, "dry run with a cursor");
    let payload = stdout_json(&dry);
    assert_eq!(payload["dry_run"], serde_json::json!(true));
    assert_eq!(stub.request_count(), 0, "a dry run sends no HTTP request");
    assert!(
        !fixture
            .data_dir
            .join("cache")
            .join("rerank-windows")
            .exists(),
        "a dry run writes no window cache"
    );
}

#[test]
fn group6_partial_timeout_and_unwritable_cache_deliver_a_page_without_a_cursor() {
    // (a) A partial index: results are returned, but the window is not
    // continuable, and the decision does not depend on `--robot-meta`.
    let fixture = build_fixture(FixtureOptions {
        partial: true,
        ..FixtureOptions::default()
    });
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);
    let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
    // Drop --robot-meta: the cursor decision must not hinge on it.
    args.retain(|arg| arg.as_str() != "--robot-meta");
    let partial = env.run(&as_args(&args));
    assert_success(&partial, "partial-index rerank");
    let payload = stdout_json(&partial);
    assert!(
        !hits(&payload).is_empty(),
        "the current page is still delivered"
    );
    assert!(
        next_cursor(&payload).is_none(),
        "a partial index yields no cursor"
    );
    let meta = rerank_meta(&payload).expect("_meta.rerank present without --robot-meta");
    assert_eq!(
        meta["pagination_unavailable_reason"],
        serde_json::json!("partial_results")
    );

    // (b) The private cache cannot be used: the page is delivered, no cursor.
    let fixture = build_fixture(FixtureOptions {
        block_cache: true,
        ..FixtureOptions::default()
    });
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);
    let blocked = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&blocked, "rerank with an unwritable cache");
    let payload = stdout_json(&blocked);
    assert!(
        !hits(&payload).is_empty(),
        "the current page survives a cache failure"
    );
    assert!(
        next_cursor(&payload).is_none(),
        "an unusable cache yields no cursor"
    );
    let meta = rerank_meta(&payload).expect("_meta.rerank");
    assert_eq!(
        meta["pagination_unavailable_reason"],
        serde_json::json!("cache_unavailable")
    );

    // (c) A timeout during the model call: the page is delivered, no cursor.
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start_with_delay(StubMode::Ordered, Duration::from_millis(1_500));
    let env = RunEnv::with_stub(&fixture, &stub);
    let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
    args.push("--timeout".to_string());
    args.push("300".to_string());
    let timed = env.run(&as_args(&args));
    let payload = stdout_json(&timed);
    assert!(
        !hits(&payload).is_empty(),
        "the current page survives a timeout"
    );
    assert!(
        next_cursor(&payload).is_none(),
        "a timed-out lookup yields no cursor"
    );
    let meta = rerank_meta(&payload).expect("_meta.rerank");
    assert_eq!(
        meta["pagination_unavailable_reason"],
        serde_json::json!("search_timeout")
    );
}

// ---------------------------------------------------------------------------
// Round-1 follow-ups: an un-frozen request, the env dimension, the provider
// dimension, bad stored metadata, and a failing call's real duration
// ---------------------------------------------------------------------------

#[test]
fn a_bad_local_endpoint_still_delivers_the_page() {
    // An origin the frozen binding cannot normalize (embedded credentials) must
    // not drop the page: the current page is delivered in the original RRF
    // order, no request is made and no cursor is issued.
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub).infinity_url("http://user:pass@127.0.0.1:9/");

    let output = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&output, "un-normalizable endpoint rerank");
    assert_eq!(stub.request_count(), 0, "a refused binding sends nothing");
    let payload = stdout_json(&output);

    let closed = env.run(&as_args(&closed_args(DEFAULT_N)));
    let expected: Vec<String> = ids(&stdout_json(&closed))
        .into_iter()
        .take(DEFAULT_K)
        .collect();
    assert_eq!(
        ids(&payload),
        expected,
        "the original RRF page is delivered"
    );

    for (_, _, rerank_score) in scored_hits(&payload) {
        assert!(rerank_score.is_none(), "no scores without a frozen request");
    }
    let meta = rerank_meta(&payload).expect("_meta.rerank");
    assert_eq!(meta["applied"], serde_json::json!(false));
    assert_eq!(
        meta["pagination_unavailable_reason"],
        serde_json::json!("invalid_input")
    );
    assert!(
        next_cursor(&payload).is_none(),
        "a refused binding yields no cursor"
    );
}

#[test]
fn a_provider_change_alone_is_refused() {
    // Both local backends' origins point at the SAME stub, so the endpoint is
    // identical across the two pages and only the provider differs -- the
    // rejection is attributable to the provider binding alone.
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub).qwen_at_stub();

    let first = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&first, "first rerank lookup");
    let cursor = require_cursor(&stdout_json(&first));
    let requests_before = stub.request_count();

    let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
    let position = args.iter().position(|a| a == "--rerank-provider").unwrap();
    args[position + 1] = "qwen3-local".to_string();
    args.push("--cursor".to_string());
    args.push(cursor);
    let changed = env.run(&as_args(&args));
    assert_eq!(
        changed.status.code(),
        Some(2),
        "changing only the provider must be refused; stderr: {}",
        String::from_utf8_lossy(&changed.stderr)
    );
    assert_eq!(stub.request_count(), requests_before, "no new request");
}

#[test]
fn an_effective_embedding_env_change_is_refused() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let first = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&first, "first rerank lookup");
    let cursor = require_cursor(&stdout_json(&first));
    let requests_before = stub.request_count();

    let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
    args.push("--cursor".to_string());
    args.push(cursor);
    // The effective embedding selection is part of the frozen request, so an
    // env change between the two pages must be refused.
    let changed = RunEnv::with_stub(&fixture, &stub)
        .env("CASS_SEMANTIC_EMBEDDER", "minilm")
        .run(&as_args(&args));
    assert_eq!(
        changed.status.code(),
        Some(2),
        "an embedding selection change must be refused; stderr: {}",
        String::from_utf8_lossy(&changed.stderr)
    );
    assert_eq!(stub.request_count(), requests_before, "no new request");
}

/// Re-publish the one saved window with a required `retrieval_status` key
/// dropped, under its own content hash, so P04's hash gate passes and the
/// continuation reaches P09's restore check.
fn rewrite_snapshot_dropping_required_key(fixture: &Fixture) -> String {
    use sha2::{Digest, Sha256};

    let dir = fixture.data_dir.join("cache").join("rerank-windows");
    let mut window_file = None;
    for entry in std::fs::read_dir(&dir).expect("read window dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".json") {
            window_file = Some(entry.path());
        }
    }
    let path = window_file.expect("one saved window");
    let bytes = std::fs::read(&path).expect("read window");
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("window json");
    let status = value
        .get_mut("retrieval_status")
        .and_then(serde_json::Value::as_object_mut)
        .expect("retrieval_status object");
    status.remove("mode_defaulted");

    let new_bytes = serde_json::to_vec(&value).expect("reserialize window");
    let mut hasher = Sha256::new();
    hasher.update(&new_bytes);
    let id = format!("{:x}", hasher.finalize());
    let new_path = dir.join(format!("{id}.json"));
    std::fs::write(&new_path, &new_bytes).expect("write tampered window");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&new_path, std::fs::Permissions::from_mode(0o600))
            .expect("tighten window file");
    }
    id
}

#[test]
fn a_valid_snapshot_with_bad_metadata_is_refused() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let first = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&first, "first rerank lookup");
    let _ = require_cursor(&stdout_json(&first));

    // A tampered file whose bytes still hash to its own name is not a corrupt
    // file: it passes P04 and must be refused by P09's metadata restore.
    let id = rewrite_snapshot_dropping_required_key(&fixture);
    let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
    args.push("--cursor".to_string());
    args.push(synthetic_cursor(&id, DEFAULT_K));
    let refused = env.run(&as_args(&args));
    assert_eq!(
        refused.status.code(),
        Some(2),
        "missing required metadata must be refused, not defaulted; stderr: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

#[test]
fn a_delayed_failing_call_reports_its_real_duration() {
    // The local service waits, then returns a malformed score set: the call
    // really ran and really waited, so its duration is non-zero (0 is reserved
    // for "no call at all").
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start_with_delay(StubMode::MissingScore, Duration::from_millis(300));
    let env = RunEnv::with_stub(&fixture, &stub);

    let first = env.run(&as_args(&rerank_args(DEFAULT_N, DEFAULT_K)));
    assert_success(&first, "first rerank lookup with a delayed failure");
    let first_payload = stdout_json(&first);
    let meta = rerank_meta(&first_payload).expect("_meta.rerank");
    assert_eq!(meta["applied"], serde_json::json!(false));
    let first_duration = meta["first_duration_ms"].as_u64().unwrap_or(0);
    assert!(
        first_duration >= 250,
        "a failed call that waited 300ms must not report 0 (got {first_duration})"
    );
    let cursor = require_cursor(&first_payload);

    // The failed window is still frozen: its continuation makes no call, so its
    // own duration and request counts are 0 while the first facts are kept.
    stub.stop();
    let mut args = rerank_args(DEFAULT_N, DEFAULT_K);
    args.push("--cursor".to_string());
    args.push(cursor);
    let second = env.run(&as_args(&args));
    assert_success(&second, "continuation of a delayed failing window");
    let second_payload = stdout_json(&second);
    let meta = rerank_meta(&second_payload).expect("_meta.rerank");
    assert_eq!(meta["duration_ms"], serde_json::json!(0));
    assert_eq!(meta["http_requests"], serde_json::json!(0));
    assert_eq!(meta["model_requests"], serde_json::json!(0));
    assert_eq!(
        meta["first_duration_ms"].as_u64().unwrap_or(0),
        first_duration,
        "the first call's real duration is preserved on the continuation"
    );
}

// ---------------------------------------------------------------------------
// Group 7 - the closed path is untouched
// ---------------------------------------------------------------------------

#[test]
fn a_command_without_a_stub_uses_an_unroutable_origin() {
    // Even a Command that needs no backend gets explicit local origins that
    // nothing listens on, so a stray request can never reach a real service.
    let fixture = build_fixture(FixtureOptions::default());
    let env = RunEnv::new(&fixture);
    let closed = env.run(&as_args(&closed_args(DEFAULT_N)));
    assert_success(&closed, "closed lexical lookup without a stub");
    assert!(
        !hits(&stdout_json(&closed)).is_empty(),
        "the closed lexical path is unaffected"
    );
}

#[test]
fn group7_the_closed_path_reports_no_rerank_fields() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);

    let mut args = closed_args(DEFAULT_N);
    args.push("--robot-meta".to_string());
    let closed = env.run(&as_args(&args));
    assert_success(&closed, "closed lexical lookup");
    let payload = stdout_json(&closed);
    assert!(
        rerank_meta(&payload).is_none(),
        "a closed search emits no _meta.rerank"
    );
    assert!(
        payload.get("rerank_requested").is_none(),
        "a closed search emits no rerank_requested"
    );
    assert!(
        !hits(&payload).is_empty(),
        "the closed lexical path still returns hits"
    );
    for (_, _, rerank_score) in scored_hits(&payload) {
        assert!(
            rerank_score.is_none(),
            "a closed search writes no rerank_score"
        );
    }
    assert_eq!(
        stub.request_count(),
        0,
        "the closed path never builds a rerank backend"
    );

    // The PR9 candidate-strategy guard is unchanged: it is still refused with
    // lexical mode, which is the one entry point P09's changes could have
    // disturbed.
    let mut guarded = closed_args(DEFAULT_N);
    guarded.push("--vector-search-mode".to_string());
    guarded.push("exact".to_string());
    let refused = env.run(&as_args(&guarded));
    assert_eq!(
        refused.status.code(),
        Some(2),
        "--vector-search-mode still conflicts with lexical mode"
    );
}

// Each fixture and HTTP listener is owned by its test. Environment overrides
// are child-process-local; no shared static or parent environment is modified.
fn p10_structured_output(output: &Output, format: &str) -> serde_json::Value {
    assert_success(output, format);
    let text = std::str::from_utf8(&output.stdout).expect("output UTF-8");
    match format {
        "jsonl" => {
            let mut lines = text.lines();
            let mut header: serde_json::Value =
                serde_json::from_str(lines.next().expect("header")).unwrap();
            header["hits"] = serde_json::Value::Array(
                lines
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect(),
            );
            header
        }
        "toon" => {
            let mut value: serde_json::Value = toon::try_decode(text, None)
                .expect("decode actual TOON")
                .into();
            p10_normalize_toon_integers(&mut value);
            value
        }
        _ => serde_json::from_str(text).expect("decode actual JSON"),
    }
}

fn p10_args(n: usize, k: usize, format: &str) -> Vec<String> {
    let mut args = rerank_args(n, k);
    args.retain(|arg| arg != "--json" && arg != "--robot-meta");
    args.extend(["--robot-format".to_string(), format.to_string()]);
    args
}

// TOON uses f64 for numbers. Only normalize exactly representable integers;
// do not remove fields or change numeric values for cross-format assertions.
fn p10_normalize_toon_integers(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Number(number) => {
            if let Some(n) = number.as_f64()
                && n.fract() == 0.0
                && n.abs() <= 9_007_199_254_740_991.0
            {
                *value = serde_json::json!(n as i64);
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(p10_normalize_toon_integers),
        serde_json::Value::Object(values) => {
            values.values_mut().for_each(p10_normalize_toon_integers)
        }
        _ => {}
    }
}

#[test]
fn p10_format_switch_continuation_keeps_order_and_original_scores() {
    for mode in [StubMode::Ordered, StubMode::MissingScore] {
        let fixture = build_fixture(FixtureOptions::default());
        let stub = Stub::start(mode);
        let env = RunEnv::with_stub(&fixture, &stub);
        let closed = stdout_json(&env.run(&as_args(&closed_args(8))));
        let original = scored_hits(&closed);
        let mut expected = ids(&closed);
        expected.truncate(8);
        if mode == StubMode::Ordered {
            expected.reverse();
        }
        let first = p10_structured_output(&env.run(&as_args(&p10_args(8, 3, "json"))), "json");
        let first_meta = first["_meta"]["rerank"].clone();
        let request_count = stub.request_count();
        let mut collected = ids(&first);
        let mut cursor = next_cursor(&first);
        for format in ["jsonl", "toon"] {
            let mut args = p10_args(8, 3, format);
            args.extend([
                "--cursor".to_string(),
                cursor.take().expect("continuation cursor"),
            ]);
            let page = p10_structured_output(&env.run(&as_args(&args)), format);
            let meta = &page["_meta"]["rerank"];
            assert_eq!(meta["applied"], mode == StubMode::Ordered);
            assert_eq!(meta["failure_reason"], first_meta["failure_reason"]);
            assert_eq!(meta["cache_reused"], true);
            assert_eq!(meta["http_requests"], 0);
            assert_eq!(meta["model_requests"], 0);
            assert_eq!(meta["duration_ms"], 0);
            assert_eq!(meta["first_duration_ms"], first_meta["first_duration_ms"]);
            assert_eq!(meta["offset"], collected.len());
            for (id, score, rerank_score) in scored_hits(&page) {
                assert_eq!(score, original.iter().find(|row| row.0 == id).unwrap().1);
                assert_eq!(rerank_score.is_some(), mode == StubMode::Ordered);
            }
            assert!(
                hits(&page)
                    .iter()
                    .all(|hit| hit.get("rerank_score").is_some())
            );
            collected.extend(ids(&page));
            cursor = next_cursor(&page);
            assert_eq!(collected, expected[..collected.len()]);
        }
        assert_eq!(collected, expected);
        assert!(
            cursor.is_none(),
            "fixed window ends even if database has more matches"
        );
        assert_eq!(
            stub.request_count(),
            request_count,
            "format switch never calls backend"
        );
    }
}

#[test]
fn p10_budgeted_compact_to_jsonl_continuation_has_no_gap() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);
    let mut expected = closed_first_n(&env, 8);
    expected.reverse();
    let mut first_args = p10_args(8, 3, "compact");
    first_args.extend(["--max-tokens".to_string(), "1".to_string()]);
    let first = p10_structured_output(&env.run(&as_args(&first_args)), "compact");
    assert_eq!(ids(&first).len(), 1);
    assert_eq!(first["_meta"]["rerank"]["returned_count"], 1);
    let mut second_args = p10_args(8, 3, "jsonl");
    second_args.extend([
        "--cursor".to_string(),
        require_cursor(&first),
        "--fields".to_string(),
        "source_path,score,rerank_score".to_string(),
    ]);
    let second = p10_structured_output(&env.run(&as_args(&second_args)), "jsonl");
    assert_eq!(second["_meta"]["rerank"]["offset"], 1);
    let joined: Vec<_> = ids(&first).into_iter().chain(ids(&second)).collect();
    assert_eq!(joined, expected[..joined.len()]);
    assert!(
        hits(&second)
            .iter()
            .all(|hit| hit["rerank_score"].is_number())
    );
}

#[test]
fn p10_sessions_remains_current_page_paths_only() {
    let fixture = build_fixture(FixtureOptions::default());
    let stub = Stub::start(StubMode::Ordered);
    let env = RunEnv::with_stub(&fixture, &stub);
    let first = p10_structured_output(&env.run(&as_args(&p10_args(8, 3, "json"))), "json");
    let mut page_args = p10_args(8, 3, "sessions");
    page_args.extend(["--cursor".to_string(), require_cursor(&first)]);
    let output = env.run(&as_args(&page_args));
    assert_success(&output, "sessions continuation");
    let mut expected = closed_first_n(&env, 8);
    expected.reverse();
    let expected: std::collections::BTreeSet<_> = expected[3..6].iter().cloned().collect();
    let lines: std::collections::BTreeSet<_> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(lines, expected);
    assert_eq!(stub.request_count(), 2);
}

#[test]
fn p10_human_formats_label_backend_and_both_scores_without_raw_errors() {
    for mode in [StubMode::Tied, StubMode::MissingScore] {
        let fixture = build_fixture(FixtureOptions::default());
        let stub = Stub::start(mode);
        let env = RunEnv::with_stub(&fixture, &stub).env("CASS_OUTPUT_FORMAT", "");
        for display in ["table", "lines", "markdown"] {
            let mut args = rerank_args(8, 3);
            args.retain(|arg| arg != "--json" && arg != "--robot-meta");
            args.extend(["--display".to_string(), display.to_string()]);
            let output = env.run(&as_args(&args));
            assert_success(&output, "human rerank output");
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("Rerank: bge-local"), "{text}");
            assert!(text.to_ascii_lowercase().contains("score"), "{text}");
            assert!(text.to_ascii_lowercase().contains("rerank"), "{text}");
            if mode == StubMode::Tied {
                assert!(
                    text.contains("| applied"),
                    "equal scores still applied: {text}"
                );
            } else {
                assert!(text.contains("invalid_response"), "{text}");
                assert!(
                    text.contains("unscored"),
                    "failure must not show zero: {text}"
                );
            }
            assert!(!text.contains("relevance_score"));
            assert!(!text.contains("content_hash"));
        }
    }
}
