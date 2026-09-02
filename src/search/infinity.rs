//! Infinity HTTP embedder + reranker (M4-pre spike).
//!
//! Lets CASS build/search semantic (quality-tier) indexes and rerank by calling
//! a local [Infinity](https://github.com/michaelfeil/infinity) engine over its
//! OpenAI-compatible `/embeddings` + `/rerank` HTTP endpoints, instead of the
//! in-process ONNX runtime. This is what makes the baseline (`--no-default-features
//! --features qr,encryption,infinity`) build ORT-free yet still semantic-capable,
//! and unlocks Chinese embeddings (`bge-m3`) + Chinese rerank (`bge-reranker-v2-m3`).
//!
//! Two seams:
//! - [`InfinityEmbedder`] impl [`Embedder`] — index side (in-process, blocking HTTP).
//! - [`InfinityDaemonClient`] impl [`DaemonClient`] — search side (query embed + rerank).
//!
//! Wire format is probed, not assumed — see `/tmp/cc-infinity-contract.md`.
//! `/rerank` returns results **sorted by score**, so we scatter scores back to
//! document order by `index`.
#![cfg(feature = "infinity")]

use std::io;
use std::time::Duration;

use serde::Deserialize;

use crate::search::daemon_client::{DaemonClient, DaemonError};
use crate::search::embedder::{Embedder, EmbedderError, EmbedderResult};
use crate::search::frankensearch_types::ModelCategory;

/// bge-m3 embedding dimension.
const DIMENSION: usize = 1024;
/// Stable embedder id — written into index shard headers; index and search
/// must agree on it. Keep distinct from `embedder_type` ("infinity").
const EMBEDDER_ID: &str = "bge-m3";
/// Default batch size cap for HTTP embed calls.
pub const MAX_BATCH: usize = 64;

// ---- centralized config -----------------------------------------------------

pub struct InfinityConfig {
    pub base_url: String,
    pub embed_model: String,
    pub rerank_model: String,
    pub timeout: Duration,
    pub max_batch: usize,
}

impl InfinityConfig {
    pub fn from_env() -> Self {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    pub fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            base_url: get("CASS_INFINITY_URL")
                .unwrap_or_else(|| "http://127.0.0.1:7997".into())
                .trim_end_matches('/')
                .to_string(),
            embed_model: get("CASS_INFINITY_EMBED_MODEL").unwrap_or_else(|| "BAAI/bge-m3".into()),
            rerank_model: get("CASS_INFINITY_RERANK_MODEL")
                .unwrap_or_else(|| "BAAI/bge-reranker-v2-m3".into()),
            timeout: Duration::from_secs(60),
            max_batch: MAX_BATCH,
        }
    }
}

fn build_client(timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))
}

// ---- wire format (probed) ------------------------------------------------

#[derive(Deserialize)]
struct EmbeddingsResponse {
    data: Vec<EmbeddingItem>,
}

#[derive(Deserialize)]
struct EmbeddingItem {
    embedding: Vec<f32>,
    index: usize,
}

#[derive(Deserialize)]
struct RerankResponse {
    results: Vec<RerankItem>,
}

#[derive(Deserialize)]
struct RerankItem {
    index: usize,
    relevance_score: f32,
}

// ---- shared HTTP helpers (Result<_, String>; callers map to their error) --

/// POST `/embeddings`. Returns embeddings in **input order** (sorted by the
/// per-item `index` field, which Infinity echoes back).
fn http_embed(
    client: &reqwest::blocking::Client,
    base_url: &str,
    model: &str,
    inputs: &[&str],
    expected_dim: usize,
) -> Result<Vec<Vec<f32>>, String> {
    if inputs.is_empty() {
        return Ok(Vec::new());
    }
    let body = serde_json::json!({ "model": model, "input": inputs });
    let resp = client
        .post(format!("{base_url}/embeddings"))
        .json(&body)
        .send()
        .map_err(|e| format!("embeddings request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        return Err(format!("embeddings HTTP {status}: {text}"));
    }
    let parsed: EmbeddingsResponse = resp
        .json()
        .map_err(|e| format!("embeddings decode failed: {e}"))?;
    if parsed.data.len() != inputs.len() {
        return Err(format!(
            "embeddings count mismatch: expected {}, got {}",
            inputs.len(),
            parsed.data.len()
        ));
    }
    // Sort by index so output aligns with input order regardless of server order.
    let mut items = parsed.data;
    items.sort_by_key(|i| i.index);
    let mut out = Vec::with_capacity(items.len());
    for (pos, item) in items.into_iter().enumerate() {
        if item.embedding.len() != expected_dim {
            return Err(format!(
                "embedding dim mismatch at {pos}: expected {expected_dim}, got {}",
                item.embedding.len()
            ));
        }
        out.push(item.embedding);
    }
    Ok(out)
}

/// POST `/rerank`. Returns scores **aligned to `documents` order** (scattered
/// back from Infinity's score-sorted `results` via each item's `index`).
fn http_rerank(
    client: &reqwest::blocking::Client,
    base_url: &str,
    model: &str,
    query: &str,
    documents: &[&str],
) -> Result<Vec<f32>, String> {
    if documents.is_empty() {
        return Ok(Vec::new());
    }
    let body = serde_json::json!({ "model": model, "query": query, "documents": documents });
    let resp = client
        .post(format!("{base_url}/rerank"))
        .json(&body)
        .send()
        .map_err(|e| format!("rerank request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        return Err(format!("rerank HTTP {status}: {text}"));
    }
    let parsed: RerankResponse = resp
        .json()
        .map_err(|e| format!("rerank decode failed: {e}"))?;
    let mut scores = vec![0.0f32; documents.len()];
    for item in parsed.results {
        if item.index >= scores.len() {
            return Err(format!(
                "rerank index {} out of range (docs={})",
                item.index,
                documents.len()
            ));
        }
        scores[item.index] = item.relevance_score;
    }
    Ok(scores)
}

// ---- served-model identity probe (w3-3 Step0/Step1, d3④) --------------------

#[derive(Deserialize)]
struct ModelsResponse {
    data: Vec<ModelsResponseItem>,
}

#[derive(Deserialize)]
struct ModelsResponseItem {
    id: String,
    #[serde(default)]
    capabilities: Vec<String>,
}

/// Identity of the embedding model Infinity is *actually* serving right
/// now, established by talking to the live service — never a hardcoded
/// literal. Used to stamp a new `embedding_generations` row's
/// `embedder_id`/`dim` so the vector domain's generation identity can
/// never silently drift from the model that produced its vectors (the
/// same discipline `insert_message_embedding`'s `expected_dim` check
/// already enforces per-write, moved up to generation-creation time).
#[derive(Debug)]
pub struct InfinityServedIdentity {
    pub model_id: String,
    pub dimension: usize,
}

/// Probe Infinity's OpenAI-compatible `/models` for the currently served
/// embed-capable model id, then confirm its real output dimension with one
/// live `/embeddings` call (never assumed from the [`DIMENSION`] constant,
/// for the same "identity from the actual service, not a literal" reason).
/// Fails loudly (`Err`) rather than falling back to a hardcoded id/dim —
/// per w3-3 Step0 design ruling ①, a missing/unreachable identity is a
/// precondition failure, not something a fallback literal should paper
/// over (a wrong fallback would open a "same dimension, wrong model"
/// hole with no defense left to catch it).
pub fn probe_served_embed_identity(
    config: &InfinityConfig,
) -> Result<InfinityServedIdentity, String> {
    let client = build_client(config.timeout)?;

    let models_resp = client
        .get(format!("{}/models", config.base_url))
        .send()
        .map_err(|e| format!("infinity /models request failed: {e}"))?;
    if !models_resp.status().is_success() {
        let status = models_resp.status();
        let text = models_resp.text().unwrap_or_default();
        return Err(format!("infinity /models HTTP {status}: {text}"));
    }
    let parsed_models: ModelsResponse = models_resp
        .json()
        .map_err(|e| format!("infinity /models decode failed: {e}"))?;

    // R1-W3-B4: select by `config.embed_model` -- the exact identity the
    // real embed calls use (`InfinityEmbedder`/`SemanticIndexer` re-read
    // `CASS_INFINITY_EMBED_MODEL` from env at call time, independently of
    // this probe) -- never "the first embed-capable model /models happens
    // to list". Two served models can share the "embed" capability *and*
    // the same output dimension (the "same dimension, different model"
    // hole this whole probe exists to close per its own doc comment
    // above); picking an arbitrary one here would silently stamp a
    // generation with an identity that is not what actually produced its
    // vectors, with no defense left downstream to catch it (insert-time
    // dimension checks pass either way). Refusing loudly when the
    // configured model isn't even in the served list, rather than
    // guessing a substitute, is the same "fail closed on a precondition
    // failure" discipline this function's own doc comment already commits
    // to for a missing/unreachable identity.
    let served_model = parsed_models
        .data
        .into_iter()
        .find(|m| m.id == config.embed_model)
        .ok_or_else(|| {
            format!(
                "infinity /models does not list the configured embed model {:?} \
                 (CASS_INFINITY_EMBED_MODEL); refusing to substitute a different \
                 served model for identity purposes",
                config.embed_model
            )
        })?;
    if !served_model.capabilities.iter().any(|c| c == "embed") {
        return Err(format!(
            "infinity model {:?} (CASS_INFINITY_EMBED_MODEL) is served but does not \
             advertise the 'embed' capability (capabilities: {:?})",
            served_model.id, served_model.capabilities
        ));
    }
    let model_id = served_model.id;

    // Confirm the real output dimension with a live call -- `/models`
    // itself does not report it, and a hardcoded constant is exactly the
    // "same dimension, wrong model" hole this probe exists to close.
    let embed_resp = client
        .post(format!("{}/embeddings", config.base_url))
        .json(&serde_json::json!({
            "model": model_id,
            "input": ["cass-infinity-served-identity-probe"],
        }))
        .send()
        .map_err(|e| format!("infinity identity-probe embeddings request failed: {e}"))?;
    if !embed_resp.status().is_success() {
        let status = embed_resp.status();
        let text = embed_resp.text().unwrap_or_default();
        return Err(format!(
            "infinity identity-probe embeddings HTTP {status}: {text}"
        ));
    }
    let parsed_embed: EmbeddingsResponse = embed_resp
        .json()
        .map_err(|e| format!("infinity identity-probe embeddings decode failed: {e}"))?;
    let dimension = parsed_embed
        .data
        .first()
        .map(|item| item.embedding.len())
        .ok_or_else(|| "infinity identity-probe returned no embedding".to_string())?;
    if dimension == 0 {
        return Err("infinity identity-probe returned a zero-length embedding".to_string());
    }

    Ok(InfinityServedIdentity { model_id, dimension })
}

// ---- pure helpers -----------------------------------------------------------

/// Returns the number of chunks needed to cover `len` items with at most `max`
/// items per chunk (ceiling division). `max=0` is treated as "no split" (returns
/// 0 when len=0, else 1) — defensive guard so callers never divide by zero.
///
/// Only exercised by the unit test; production batching uses
/// `slice::chunks(max)` directly. `#[cfg(test)]` keeps the infinity-feature
/// release build warning-clean (no dead_code).
#[cfg(test)]
fn n_chunks(len: usize, max: usize) -> usize {
    if len == 0 {
        return 0;
    }
    if max == 0 {
        return 1;
    }
    len.div_ceil(max)
}

/// Retry `f` up to `max_retries` additional times when it returns a *transient*
/// error (connection / timeout / refused / broken pipe). Non-transient errors
/// are returned immediately without retrying.
fn retry_n<T>(max_retries: u32, mut f: impl FnMut() -> Result<T, String>) -> Result<T, String> {
    let mut last = String::new();
    for _ in 0..=max_retries {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let lo = e.to_ascii_lowercase();
                let transient = lo.contains("connection")
                    || lo.contains("timed out")
                    || lo.contains("timeout")
                    || lo.contains("refused")
                    || lo.contains("broken pipe");
                if !transient {
                    return Err(e);
                }
                last = e;
            }
        }
    }
    Err(format!("exhausted retries: {last}"))
}

// ---- index side: Embedder -------------------------------------------------

/// In-process [`Embedder`] backed by Infinity's `/embeddings` over blocking HTTP.
pub struct InfinityEmbedder {
    client: reqwest::blocking::Client,
    config: InfinityConfig,
    id: String,
    dimension: usize,
}

impl InfinityEmbedder {
    pub fn new() -> EmbedderResult<Self> {
        let config = InfinityConfig::from_env();
        let client = build_client(config.timeout).map_err(|msg| EmbedderError::SubsystemError {
            subsystem: "infinity-embedder",
            source: Box::new(io::Error::other(msg)),
        })?;
        Ok(Self {
            client,
            config,
            id: EMBEDDER_ID.to_string(),
            dimension: DIMENSION,
        })
    }

    fn fail(&self, msg: String) -> EmbedderError {
        EmbedderError::EmbeddingFailed {
            model: self.id.clone(),
            source: Box::new(io::Error::other(msg)),
        }
    }
}

impl Embedder for InfinityEmbedder {
    fn embed_sync(&self, text: &str) -> EmbedderResult<Vec<f32>> {
        if text.is_empty() {
            return Err(EmbedderError::InvalidConfig {
                field: "input_text".to_string(),
                value: "(empty)".to_string(),
                reason: "empty text".to_string(),
            });
        }
        let mut out = http_embed(
            &self.client,
            &self.config.base_url,
            &self.config.embed_model,
            &[text],
            self.dimension,
        )
        .map_err(|m| self.fail(m))?;
        out.pop()
            .ok_or_else(|| self.fail("infinity returned no embedding".to_string()))
    }

    fn embed_batch_sync(&self, texts: &[&str]) -> EmbedderResult<Vec<Vec<f32>>> {
        for t in texts {
            if t.is_empty() {
                return Err(EmbedderError::InvalidConfig {
                    field: "input_text".to_string(),
                    value: "(empty)".to_string(),
                    reason: "empty text in batch".to_string(),
                });
            }
        }
        let mut out = Vec::with_capacity(texts.len());
        for chunk in texts.chunks(self.config.max_batch) {
            let mut part = retry_n(2, || {
                http_embed(
                    &self.client,
                    &self.config.base_url,
                    &self.config.embed_model,
                    chunk,
                    self.dimension,
                )
            })
            .map_err(|m| self.fail(m))?;
            out.append(&mut part);
        }
        Ok(out)
    }

    fn dimension(&self) -> usize {
        self.dimension
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn model_name(&self) -> &str {
        &self.config.embed_model
    }

    fn is_semantic(&self) -> bool {
        true
    }

    fn category(&self) -> ModelCategory {
        ModelCategory::ApiEmbedder
    }

    fn tier(&self) -> crate::search::frankensearch_types::ModelTier {
        crate::search::frankensearch_types::ModelTier::Quality
    }
}

// ---- search side: DaemonClient -------------------------------------------

/// [`DaemonClient`] that fulfils query embedding + rerank against Infinity over
/// HTTP, replacing the UDS daemon. Used as the daemon in `DaemonFallback*`.
pub struct InfinityDaemonClient {
    client: reqwest::blocking::Client,
    config: InfinityConfig,
    dimension: usize,
}

impl InfinityDaemonClient {
    pub fn new() -> Result<Self, DaemonError> {
        let config = InfinityConfig::from_env();
        let client = build_client(config.timeout).map_err(DaemonError::Unavailable)?;
        Ok(Self {
            client,
            config,
            dimension: DIMENSION,
        })
    }
}

impl DaemonClient for InfinityDaemonClient {
    fn id(&self) -> &str {
        "infinity-daemon"
    }

    fn is_available(&self) -> bool {
        // Cheap liveness probe; on failure the DaemonFallback* path falls back.
        self.client
            .get(format!("{}/health", self.config.base_url))
            .timeout(Duration::from_secs(2))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    fn embed(&self, text: &str, _request_id: &str) -> Result<Vec<f32>, DaemonError> {
        let mut out = http_embed(
            &self.client,
            &self.config.base_url,
            &self.config.embed_model,
            &[text],
            self.dimension,
        )
        .map_err(DaemonError::Failed)?;
        out.pop()
            .ok_or_else(|| DaemonError::Failed("infinity returned no embedding".to_string()))
    }

    fn embed_batch(&self, texts: &[&str], _request_id: &str) -> Result<Vec<Vec<f32>>, DaemonError> {
        http_embed(
            &self.client,
            &self.config.base_url,
            &self.config.embed_model,
            texts,
            self.dimension,
        )
        .map_err(DaemonError::Failed)
    }

    fn rerank(
        &self,
        query: &str,
        documents: &[&str],
        _request_id: &str,
    ) -> Result<Vec<f32>, DaemonError> {
        http_rerank(
            &self.client,
            &self.config.base_url,
            &self.config.rerank_model,
            query,
            documents,
        )
        .map_err(DaemonError::Failed)
    }
}

// ---- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    // ---- R1-W3-B4: minimal hand-rolled mock Infinity HTTP server ----------
    //
    // No HTTP mocking crate is a dependency of this workspace (checked:
    // no wiremock/mockito/httpmock in Cargo.toml); the model_download.rs
    // test module already establishes the pattern of a raw `TcpListener`
    // mock for this codebase, so this follows the same shape rather than
    // introducing a new one. Serves exactly the two routes
    // `probe_served_embed_identity` calls: `GET /models` (fixed canned
    // body) and `POST /embeddings` (dispatches on the request's `model`
    // field so a wrong model selection surfaces as a probe `Err`, not a
    // silently-accepted wrong dimension).
    struct MockInfinityServer {
        base_url: String,
        stop: Arc<AtomicBool>,
        wake_addr: String,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl Drop for MockInfinityServer {
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

    fn start_mock_infinity_server(
        models_json: &'static str,
        expected_embed_model: &'static str,
        embed_dim: usize,
    ) -> MockInfinityServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock infinity server");
        listener
            .set_nonblocking(true)
            .expect("set mock infinity server nonblocking");
        let addr = listener.local_addr().expect("read mock server address");
        let wake_addr = addr.to_string();
        let base_url = format!("http://{wake_addr}");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        handle_mock_infinity_request(stream, models_json, expected_embed_model, embed_dim);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        MockInfinityServer {
            base_url,
            stop,
            wake_addr,
            handle: Some(handle),
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn handle_mock_infinity_request(
        mut stream: TcpStream,
        models_json: &str,
        expected_embed_model: &str,
        embed_dim: usize,
    ) {
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 4096];
        let header_end = loop {
            let n = match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(n) => n,
                Err(_) => return,
            };
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            if buf.len() > 65536 {
                return;
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
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        while buf.len() < header_end + content_length {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        let body = &buf[header_end..buf.len().min(header_end + content_length)];

        let response = if method == "GET" && path == "/models" {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                models_json.len(),
                models_json
            )
        } else if method == "POST" && path == "/embeddings" {
            let requested_model = serde_json::from_slice::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v.get("model").and_then(|m| m.as_str()).map(str::to_string))
                .unwrap_or_default();
            if requested_model == expected_embed_model {
                let embedding: Vec<f32> = (0..embed_dim).map(|i| i as f32 + 1.0).collect();
                let body_json =
                    serde_json::json!({ "data": [{ "embedding": embedding, "index": 0 }] }).to_string();
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_json.len(),
                    body_json
                )
            } else {
                let msg = format!("mock infinity: unexpected model {requested_model:?} in /embeddings request");
                format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    msg.len(),
                    msg
                )
            }
        } else {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        };
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }

    /// R1-W3-B4 regression: `/models` lists two embed-capable models; the
    /// probe must select the one named by `config.embed_model`
    /// (`CASS_INFINITY_EMBED_MODEL`), not whichever one happens to come
    /// first in Infinity's response order.
    #[test]
    fn probe_served_embed_identity_selects_the_configured_model_among_several() {
        let server = start_mock_infinity_server(
            r#"{"data":[{"id":"BAAI/bge-m3","capabilities":["embed"]},{"id":"other/embed-model","capabilities":["embed"]}]}"#,
            "other/embed-model",
            4,
        );
        let config = InfinityConfig {
            base_url: server.base_url.clone(),
            embed_model: "other/embed-model".to_string(),
            rerank_model: "unused".to_string(),
            timeout: Duration::from_secs(5),
            max_batch: MAX_BATCH,
        };
        let identity =
            probe_served_embed_identity(&config).expect("probe must select the env-configured model, not the first listed one");
        assert_eq!(identity.model_id, "other/embed-model");
        assert_eq!(identity.dimension, 4);
    }

    /// R1-W3-B4 regression: when the configured embed model is not in
    /// `/models`' served list at all, the probe must fail loudly rather
    /// than silently substituting a different served model.
    #[test]
    fn probe_served_embed_identity_errors_loudly_when_configured_model_is_not_served() {
        let server = start_mock_infinity_server(
            r#"{"data":[{"id":"BAAI/bge-m3","capabilities":["embed"]},{"id":"other/embed-model","capabilities":["embed"]}]}"#,
            "irrelevant-because-this-test-must-never-reach-/embeddings",
            4,
        );
        let config = InfinityConfig {
            base_url: server.base_url.clone(),
            embed_model: "not-served/model".to_string(),
            rerank_model: "unused".to_string(),
            timeout: Duration::from_secs(5),
            max_batch: MAX_BATCH,
        };
        let err = probe_served_embed_identity(&config)
            .expect_err("a configured model absent from /models must error, not fall back to a substitute");
        assert!(
            err.contains("not-served/model"),
            "error must name the missing configured model so an operator can act on it: {err}"
        );
    }

    #[test]
    fn config_from_env_defaults_and_overrides() {
        let def = InfinityConfig::from_env_with(|_| None);
        assert_eq!(def.base_url, "http://127.0.0.1:7997");
        assert_eq!(def.embed_model, "BAAI/bge-m3");
        assert_eq!(def.rerank_model, "BAAI/bge-reranker-v2-m3");
        assert_eq!(def.max_batch, 64);
        let ovr = InfinityConfig::from_env_with(|k| match k {
            "CASS_INFINITY_URL" => Some("http://x:9/".into()),
            _ => None,
        });
        assert_eq!(ovr.base_url, "http://x:9"); // 去尾斜杠
    }

    #[test]
    fn n_chunks_is_ceil() {
        assert_eq!(n_chunks(0, 64), 0);
        assert_eq!(n_chunks(1, 64), 1);
        assert_eq!(n_chunks(64, 64), 1);
        assert_eq!(n_chunks(65, 64), 2);
        assert_eq!(n_chunks(130, 64), 3);
        assert_eq!(n_chunks(10, 0), 1); // max=0 防御
    }

    #[test]
    fn retry_n_retries_transient_then_succeeds() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = AtomicU32::new(0);
        let r = retry_n(2, || {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                Err("connection refused".to_string())
            } else {
                Ok(7u32)
            }
        });
        assert_eq!(r.unwrap(), 7);
        assert_eq!(attempts.load(Ordering::SeqCst), 3); // 2 retries + 初次

        // 非瞬时错误不重试
        let a2 = AtomicU32::new(0);
        let e = retry_n(2, || {
            a2.fetch_add(1, Ordering::SeqCst);
            Err::<u32, _>("dim mismatch".to_string())
        });
        assert!(e.is_err());
        assert_eq!(a2.load(Ordering::SeqCst), 1);
    }
}
