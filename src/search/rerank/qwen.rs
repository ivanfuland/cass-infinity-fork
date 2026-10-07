//! Local SGLang Qwen3-Reranker-8B adapter (P05).
//!
//! [`QwenBackend`] implements the shared [`RerankBackend`] contract against one
//! local SGLang server that serves `Qwen3-Reranker-8B-local`. It owns three
//! things and nothing else:
//!
//! - **Service verification.** Two read-only GETs (`/get_model_info`,
//!   `/v1/models`) must name the expected model, must expose a rerank-bearing
//!   path field (or `is_generation: true`), must carry exactly one model card
//!   whose `id` equals the verified name, and must declare one usable context
//!   length of at least 32768.
//! - **The frozen request.** One POST `/v1/rerank` carrying exactly `query`,
//!   `documents` (every input byte, untruncated), `top_n` equal to the actual
//!   document count, `return_documents: false` and the frozen 20e `instruct`.
//!   There is no `model` field, no batching and no retry.
//! - **Complete scoring.** The native array of `index`/`score` pairs is mapped
//!   to the shared `relevance_score` shape and validated whole: one entry per
//!   input document, each index in range and unique, each score finite. The
//!   result is returned in input order; nothing is sorted, dropped or filled
//!   with a default.
//!
//! The adapter reuses the P02 transport. It builds one [`HttpTransport`] with a
//! fixed local-only configuration, sends no bearer, and adds no proxy, redirect
//! or retry behaviour of its own. Construction validates the origin and builds
//! the client; it sends no request.
//!
//! Every refusal is a short code from the shared [`RerankError`] vocabulary. No
//! error, log line or panic message carries a reported model name, a context
//! value, a response body or any other field content.

use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use super::http::{HttpConfig, HttpTransport};
use super::types::{
    CallIdentity, ProviderChoice, RerankBackend, RerankError, RerankFailureReason, RerankResponse,
    validate_index_scores,
};

/// The origin P09 binds when `CASS_QWEN_RERANK_URL` is unset.
///
/// This module never reads the environment: P09 resolves the optional override
/// once and passes the same effective origin to both the binding and
/// [`QwenBackend::new`].
pub const DEFAULT_ORIGIN: &str = "http://127.0.0.1:18002";

/// The one served-model name this adapter accepts (the verified 20e name).
const EXPECTED_MODEL: &str = "Qwen3-Reranker-8B-local";

/// The frozen 20e rerank instruction.
const INSTRUCT: &str = "Given a web search query, retrieve relevant passages that answer the query";

/// Metadata keys that may carry the served model name.
const SERVICE_NAME_KEYS: [&str; 3] = ["service_model", "served_model_name", "model_name"];

/// Metadata keys that may carry a declared context length.
const CONTEXT_KEYS: [&str; 4] = [
    "context_length",
    "max_context_length",
    "context_window",
    "max_model_len",
];

/// Metadata keys whose string value may prove the service is a reranker.
const RERANK_PATH_KEYS: [&str; 3] = ["task", "pipeline", "rerank_path"];

/// The context length every declared value must reach.
const MIN_CONTEXT_LENGTH: u64 = 32768;

/// Fixed transport budgets, matching the frozen 20e prototype.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

const INFO_PATH: &str = "/get_model_info";
const MODELS_PATH: &str = "/v1/models";
const RERANK_PATH: &str = "/v1/rerank";

/// The fixed public text the P11 readiness probe scores.
const PROBE_TEXT: &str = "rerank readiness probe";

/// The exact number of requests one successful call makes.
const REQUEST_COUNT: usize = 3;

/// The local SGLang Qwen3-Reranker-8B backend.
///
/// The struct holds the shared transport and nothing else; it is deliberately
/// neither `Debug` nor `Serialize`, because the transport owns the client.
pub struct QwenBackend {
    transport: HttpTransport,
}

impl QwenBackend {
    /// Validate `origin`, then build the fixed local-only transport.
    ///
    /// This sends no request. It proves `origin` is a bare origin that resolves
    /// to loopback and builds the client every later call reuses; a malformed
    /// or non-loopback origin is refused here, before any request exists.
    pub fn new(origin: &str) -> Result<Self, RerankError> {
        let config = HttpConfig {
            base_url: origin.to_string(),
            local_only: true,
            timeout: TOTAL_TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
            max_response_bytes: MAX_RESPONSE_BYTES,
        };
        // The local service is unauthenticated, so no bearer is ever built.
        let transport = HttpTransport::new(config, None)?;
        Ok(Self { transport })
    }

    /// Score one fixed public probe document through the normal adapter path.
    ///
    /// P11 uses this for readiness. Because the probe runs the same call as a
    /// real rerank, a successful probe returns exactly one finite score and has
    /// also proven the service identity and context contract.
    pub fn probe_ready(&self) -> Result<RerankResponse, RerankError> {
        self.rerank(PROBE_TEXT, &[PROBE_TEXT.to_string()])
    }
}

impl RerankBackend for QwenBackend {
    fn provider(&self) -> ProviderChoice {
        ProviderChoice::Qwen3Local
    }

    fn rerank(&self, query: &str, documents: &[String]) -> Result<RerankResponse, RerankError> {
        validate_inputs(query, documents)?;
        let started = Instant::now();

        // The two metadata responses are one contract, and both are read
        // before any scoring request exists.
        let info = self.transport.get_json(INFO_PATH)?;
        let models = self.transport.get_json(MODELS_PATH)?;
        let service_model = verified_service_model(&info.body, &models.body)?;

        let scored = self
            .transport
            .post_json(RERANK_PATH, &rerank_payload(query, documents))?;
        let scores = response_scores(&scored.body, documents.len())?;

        Ok(RerankResponse {
            scores,
            identity: CallIdentity {
                actual_provider: Some(ProviderChoice::Qwen3Local),
                actual_model: Some(service_model),
                // The frozen protocol carries no field that names the serving
                // provider, so this stays null rather than guessing "SGLang".
                serving_provider: None,
            },
            http_requests: REQUEST_COUNT,
            duration_ms: duration_ms(started.elapsed()),
        })
    }
}

fn invalid_input() -> RerankError {
    RerankError::new(RerankFailureReason::InvalidInput)
}

fn invalid_response() -> RerankError {
    RerankError::new(RerankFailureReason::InvalidResponse)
}

fn identity_mismatch() -> RerankError {
    RerankError::new(RerankFailureReason::ModelIdentityMismatch)
}

/// Refuse anything that cannot be scored: an empty or all-whitespace query, an
/// empty document list, or a document that is empty or all whitespace.
///
/// These refusals happen before the first request, so a rejected input never
/// reaches the service.
fn validate_inputs(query: &str, documents: &[String]) -> Result<(), RerankError> {
    if query.trim().is_empty()
        || documents.is_empty()
        || documents.iter().any(|document| document.trim().is_empty())
    {
        return Err(invalid_input());
    }
    Ok(())
}

/// The whole metadata contract, in one place.
///
/// Both bodies must be objects, exactly one model card must match the verified
/// service name, and the two responses must declare one usable context length
/// between them. The verified name is returned so the caller can report it as
/// the observed model identity.
fn verified_service_model(info: &Value, models: &Value) -> Result<String, RerankError> {
    let info = info.as_object().ok_or_else(invalid_response)?;
    let models = models.as_object().ok_or_else(invalid_response)?;

    let name = declared_service_name(info)?;

    if !reports_rerank_path(info) {
        return Err(invalid_response());
    }

    let cards = models
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(invalid_response)?;
    let mut matching = Vec::new();
    for card in cards {
        let Some(card) = card.as_object() else {
            continue; // an unrelated or malformed card cannot be the match
        };
        if card.get("id").and_then(Value::as_str) == Some(name) {
            matching.push(card);
        }
    }
    let [card] = matching.as_slice() else {
        return Err(invalid_response());
    };

    declared_context_length(card, info)?;
    Ok(name.to_string())
}

/// The one name every explicitly provided name field agrees on.
///
/// A field that is absent, or present but empty, is not a declaration. A
/// declared name that is not a string is an invalid response; a declared name
/// that is a string but differs from the expected model is an identity
/// mismatch.
fn declared_service_name(info: &Map<String, Value>) -> Result<&str, RerankError> {
    let mut declared = Vec::new();
    for key in SERVICE_NAME_KEYS {
        let Some(value) = info.get(key) else {
            continue;
        };
        let name = value.as_str().ok_or_else(invalid_response)?;
        if !name.is_empty() {
            declared.push(name);
        }
    }

    // "At least one non-empty name" and "every declared name agrees" collapse
    // into: every non-empty name is the expected model.
    if declared.is_empty() {
        return Err(invalid_response());
    }
    if declared.iter().any(|name| *name != EXPECTED_MODEL) {
        return Err(identity_mismatch());
    }
    Ok(EXPECTED_MODEL)
}

/// Whether the metadata proves this service can rerank.
///
/// `is_generation: true`, or any one string field among the rerank-path keys
/// containing "rerank" (ASCII case-insensitive), is enough.
fn reports_rerank_path(info: &Map<String, Value>) -> bool {
    if info.get("is_generation") == Some(&Value::Bool(true)) {
        return true;
    }
    RERANK_PATH_KEYS.iter().any(|key| {
        info.get(*key)
            .and_then(Value::as_str)
            .is_some_and(|text| text.to_ascii_lowercase().contains("rerank"))
    })
}

/// The single context length the two responses declare.
///
/// Every declared value is checked, so a usable value in one response cannot
/// hide a broken value in the other. Missing everywhere is a refusal, not a
/// default.
fn declared_context_length(
    card: &Map<String, Value>,
    info: &Map<String, Value>,
) -> Result<u64, RerankError> {
    let mut declared = Vec::new();
    if let Some(value) = card.get("max_model_len") {
        declared.push(context_length(value)?);
    }
    for key in CONTEXT_KEYS {
        if let Some(value) = info.get(key) {
            declared.push(context_length(value)?);
        }
    }

    let Some(first) = declared.first().copied() else {
        return Err(invalid_response());
    };
    if declared.iter().any(|other| *other != first) {
        return Err(invalid_response());
    }
    Ok(first)
}

/// One declared context length: a JSON non-negative integer at or above the
/// required floor. Floats, booleans, strings and negatives are refused.
fn context_length(value: &Value) -> Result<u64, RerankError> {
    let length = value.as_u64().ok_or_else(invalid_response)?;
    if length < MIN_CONTEXT_LENGTH {
        return Err(invalid_response());
    }
    Ok(length)
}

/// The frozen five-key scoring payload.
///
/// `documents` goes out as the input bytes; `top_n` is the actual document
/// count, never a page length. The payload deliberately carries no `model`
/// field.
fn rerank_payload(query: &str, documents: &[String]) -> Value {
    json!({
        "query": query,
        "documents": documents,
        "top_n": documents.len(),
        "return_documents": false,
        "instruct": INSTRUCT,
    })
}

/// Validate the native `index`/`score` array and return input-ordered scores.
///
/// The native `score` key is only renamed to the shared `relevance_score` key;
/// the values are then handed to the shared completeness validator, which
/// refuses a short, duplicate, out-of-range or non-finite set rather than
/// sorting, truncating or filling gaps.
fn response_scores(body: &Value, expected: usize) -> Result<Vec<f64>, RerankError> {
    let rows = body.as_array().ok_or_else(invalid_response)?;
    let mut mapped = Vec::with_capacity(rows.len());
    for row in rows {
        let row = row.as_object().ok_or_else(invalid_response)?;
        let index = row.get("index").ok_or_else(invalid_response)?;
        let score = row.get("score").ok_or_else(invalid_response)?;
        let mut entry = Map::new();
        entry.insert("index".to_string(), index.clone());
        entry.insert("relevance_score".to_string(), score.clone());
        mapped.push(Value::Object(entry));
    }
    validate_index_scores(&Value::Array(mapped), expected)
}

/// The measured duration, saturating instead of truncating on the (unreachable)
/// overflow.
fn duration_ms(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use serde_json::{Value, json};

    // ------------------------------------------------------------------
    // A tiny blocking HTTP/1.1 fixture with per-path canned responses. Every
    // instance binds an ephemeral loopback port, records the requests it
    // received and answers only the paths it was configured with; anything
    // else is a 404. It owns its own thread and sockets, and touches no
    // process-wide state.
    // ------------------------------------------------------------------

    #[derive(Clone)]
    struct Request {
        method: String,
        path: String,
        head: String,
        body: Vec<u8>,
    }

    struct Server {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<Request>>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl Server {
        fn spawn(routes: Vec<(&str, u16, Vec<u8>)>) -> Server {
            let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .expect("bind fixture port");
            let addr = listener.local_addr().expect("fixture local_addr");
            listener.set_nonblocking(true).expect("fixture nonblocking");
            let routes: Vec<(String, u16, Vec<u8>)> = routes
                .into_iter()
                .map(|(path, status, body)| (path.to_string(), status, body))
                .collect();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (seen_thread, stop_thread) = (seen.clone(), stop.clone());
            let thread = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(20);
                while !stop_thread.load(Ordering::SeqCst) && Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                            if let Some(request) = read_request(&mut stream) {
                                seen_thread.lock().unwrap().push(request.clone());
                                let response = routes
                                    .iter()
                                    .find(|(path, _, _)| path.as_str() == request.path.as_str())
                                    .map(|(_, status, body)| response_bytes(*status, body))
                                    .unwrap_or_else(|| response_bytes(404, b"{}"));
                                let _ = stream.write_all(&response);
                                let _ = stream.flush();
                            }
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Server {
                addr,
                seen,
                stop,
                thread: Some(thread),
            }
        }

        fn base(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn requests(&self) -> Vec<Request> {
            self.seen.lock().unwrap().clone()
        }

        fn paths(&self) -> Vec<String> {
            self.requests()
                .into_iter()
                .map(|request| request.path)
                .collect()
        }

        fn posts(&self) -> Vec<Request> {
            self.requests()
                .into_iter()
                .filter(|request| request.method == "POST")
                .collect()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn content_length(head: &[u8]) -> usize {
        for line in String::from_utf8_lossy(head).split("\r\n") {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-length") {
                    return value.trim().parse().unwrap_or(0);
                }
            }
        }
        0
    }

    /// Read one request: headers up to CRLFCRLF, then `Content-Length` bytes.
    fn read_request(stream: &mut TcpStream) -> Option<Request> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut head_end = None;
        let mut body_len = 0usize;
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    buf.extend_from_slice(&chunk[..read]);
                    if head_end.is_none() {
                        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
                            head_end = Some(pos + 4);
                            body_len = content_length(&buf[..pos]);
                        }
                    }
                    if let Some(end) = head_end {
                        if buf.len() >= end + body_len {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }

        let end = head_end?;
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        let request_line = head.split("\r\n").next()?;
        let mut parts = request_line.split(' ');
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();
        let body = buf[end..(end + body_len).min(buf.len())].to_vec();
        Some(Request {
            method,
            path,
            head,
            body,
        })
    }

    fn response_bytes(status: u16, body: &[u8]) -> Vec<u8> {
        let reason = if status == 200 { "OK" } else { "Status" };
        let mut out = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn as_strs(values: &[String]) -> Vec<&str> {
        values.iter().map(String::as_str).collect()
    }

    /// The verified `/get_model_info` shape: one served name and `is_generation`.
    fn info_json(name: &str) -> Value {
        json!({ "served_model_name": name, "is_generation": true })
    }

    fn card_json(id: &str, max_model_len: Value) -> Value {
        json!({ "id": id, "max_model_len": max_model_len })
    }

    fn models_json(cards: Value) -> Value {
        json!({ "data": cards })
    }

    /// The three fixture routes a complete call walks, in order.
    fn routes(info: &Value, models: &Value, scores: &Value) -> Vec<(&'static str, u16, Vec<u8>)> {
        vec![
            (INFO_PATH, 200, info.to_string().into_bytes()),
            (MODELS_PATH, 200, models.to_string().into_bytes()),
            (RERANK_PATH, 200, scores.to_string().into_bytes()),
        ]
    }

    /// A fixture that serves one expected-identity metadata pair plus `scores`.
    fn happy_server(scores: Value) -> Server {
        Server::spawn(routes(
            &info_json(EXPECTED_MODEL),
            &models_json(json!([card_json(EXPECTED_MODEL, json!(32768))])),
            &scores,
        ))
    }

    fn backend_for(server: &Server) -> QwenBackend {
        QwenBackend::new(&server.base()).expect("backend")
    }

    // ------------------------------------------------------------------
    // C1 — service metadata verification.
    // ------------------------------------------------------------------

    #[test]
    fn construction_sends_nothing_and_exposes_the_fixed_selection() {
        // Nothing listens for a request here; `new` must only validate and
        // build the client.
        let backend = QwenBackend::new(DEFAULT_ORIGIN).expect("backend");
        assert_eq!(backend.provider(), ProviderChoice::Qwen3Local);
    }

    #[test]
    fn construction_keeps_the_local_only_origin_boundary() {
        let err = QwenBackend::new("http://192.0.2.1:18002")
            .err()
            .expect("non-loopback origin must be refused");
        assert_eq!(err.reason, RerankFailureReason::NonLoopbackEndpoint);

        let err = QwenBackend::new("not a url")
            .err()
            .expect("origin must parse");
        assert_eq!(err.reason, RerankFailureReason::InvalidInput);
    }

    #[test]
    fn the_happy_path_returns_input_ordered_scores_with_the_full_identity() {
        let server = happy_server(json!([
            { "index": 0, "score": 0.125 },
            { "index": 1, "score": 0.5 },
        ]));
        let backend = backend_for(&server);
        let documents = vec!["first".to_string(), "second".to_string()];

        let got = backend.rerank("what is it", &documents).expect("rerank");
        assert_eq!(got.scores, vec![0.125, 0.5]);
        assert_eq!(
            got.identity.actual_provider,
            Some(ProviderChoice::Qwen3Local)
        );
        assert_eq!(got.identity.actual_model.as_deref(), Some(EXPECTED_MODEL));
        assert_eq!(got.identity.serving_provider, None);
        assert_eq!(got.http_requests, 3);
        assert!(got.duration_ms < 60_000, "duration_ms {}", got.duration_ms);
        assert_eq!(
            as_strs(&server.paths()),
            vec![INFO_PATH, MODELS_PATH, RERANK_PATH],
            "one metadata pair, then exactly one scoring POST"
        );
    }

    #[test]
    fn an_unrelated_card_before_the_matching_card_is_accepted() {
        let server = Server::spawn(routes(
            &info_json(EXPECTED_MODEL),
            &models_json(json!([
                card_json("some-other-model", json!(131072)),
                { "id": 42 },
                card_json(EXPECTED_MODEL, json!(32768)),
            ])),
            &json!([{ "index": 0, "score": 0.75 }]),
        ));

        let got = backend_for(&server)
            .rerank("q", &["only".to_string()])
            .expect("the matching card wins wherever it sits");
        assert_eq!(got.scores, vec![0.75]);
        assert_eq!(got.http_requests, 3);
    }

    #[test]
    fn a_missing_or_mistyped_service_name_is_an_invalid_response() {
        for info in [
            json!({ "is_generation": true }),
            json!({ "served_model_name": 42, "is_generation": true }),
            json!({ "served_model_name": "", "is_generation": true }),
            json!({ "served_model_name": ["Qwen3-Reranker-8B-local"], "is_generation": true }),
            json!({ "service_model": null, "is_generation": true }),
        ] {
            let server = Server::spawn(routes(
                &info,
                &models_json(json!([card_json(EXPECTED_MODEL, json!(32768))])),
                &json!([{ "index": 0, "score": 0.5 }]),
            ));
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "info {info}"
            );
            assert_eq!(server.posts().len(), 0, "no POST may follow {info}");
        }
    }

    #[test]
    fn every_declared_name_must_equal_the_expected_model() {
        // Two agreeing declarations are fine.
        let server = Server::spawn(routes(
            &json!({
                "service_model": EXPECTED_MODEL,
                "served_model_name": EXPECTED_MODEL,
                "is_generation": true,
            }),
            &models_json(json!([card_json(EXPECTED_MODEL, json!(32768))])),
            &json!([{ "index": 0, "score": 0.5 }]),
        ));
        backend_for(&server)
            .rerank("q", &["d".to_string()])
            .expect("agreeing names");

        // An explicitly different name is a mismatch, not a generic refusal.
        for info in [
            json!({ "served_model_name": "Qwen3-Reranker-8B", "is_generation": true }),
            json!({
                "served_model_name": EXPECTED_MODEL,
                "model_name": "some-other-model",
                "is_generation": true,
            }),
        ] {
            let server = Server::spawn(routes(
                &info,
                &models_json(json!([card_json(EXPECTED_MODEL, json!(32768))])),
                &json!([{ "index": 0, "score": 0.5 }]),
            ));
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::ModelIdentityMismatch,
                "info {info}"
            );
            assert_eq!(server.posts().len(), 0);
        }
    }

    #[test]
    fn a_refusal_never_echoes_the_reported_model_name() {
        let server = Server::spawn(routes(
            &json!({
                "served_model_name": "SYNTHETIC-MODEL-NAME-DO-NOT-LEAK",
                "is_generation": true,
            }),
            &models_json(json!([card_json(EXPECTED_MODEL, json!(32768))])),
            &json!([{ "index": 0, "score": 0.5 }]),
        ));

        let err = backend_for(&server)
            .rerank("q", &["d".to_string()])
            .unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::ModelIdentityMismatch);
        let message = err.to_string();
        assert!(
            !message.contains("SYNTHETIC-MODEL-NAME"),
            "the reported name leaked: {message}"
        );
    }

    #[test]
    fn a_service_without_a_rerank_path_hint_is_refused() {
        for info in [
            json!({ "served_model_name": EXPECTED_MODEL }),
            json!({ "served_model_name": EXPECTED_MODEL, "is_generation": false }),
            json!({ "served_model_name": EXPECTED_MODEL, "is_generation": "true" }),
            json!({ "served_model_name": EXPECTED_MODEL, "task": "chat" }),
            json!({ "served_model_name": EXPECTED_MODEL, "pipeline": 7 }),
        ] {
            let server = Server::spawn(routes(
                &info,
                &models_json(json!([card_json(EXPECTED_MODEL, json!(32768))])),
                &json!([{ "index": 0, "score": 0.5 }]),
            ));
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "info {info}"
            );
            assert_eq!(server.posts().len(), 0);
        }
    }

    #[test]
    fn any_one_rerank_bearing_string_field_is_enough() {
        for hint in [
            json!({ "task": "ReRaNk" }),
            json!({ "pipeline": "sglang-rerank" }),
            json!({ "rerank_path": "/v1/rerank" }),
        ] {
            let mut info = hint;
            info["served_model_name"] = json!(EXPECTED_MODEL);
            let server = Server::spawn(routes(
                &info,
                &models_json(json!([card_json(EXPECTED_MODEL, json!(32768))])),
                &json!([{ "index": 0, "score": 0.5 }]),
            ));
            let got = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_or_else(|err| panic!("info {info}: {err}"));
            assert_eq!(got.scores, vec![0.5]);
        }
    }

    #[test]
    fn the_matching_card_must_exist_exactly_once() {
        for data in [
            json!([]),
            json!([card_json("some-other-model", json!(32768))]),
            json!([
                card_json(EXPECTED_MODEL, json!(32768)),
                card_json(EXPECTED_MODEL, json!(32768))
            ]),
            json!([
                card_json(EXPECTED_MODEL, json!(32768)),
                card_json(EXPECTED_MODEL, json!(65536))
            ]),
        ] {
            let server = Server::spawn(routes(
                &info_json(EXPECTED_MODEL),
                &models_json(data.clone()),
                &json!([{ "index": 0, "score": 0.5 }]),
            ));
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "data {data}"
            );
            assert_eq!(server.posts().len(), 0);
        }
    }

    #[test]
    fn a_model_list_without_a_data_array_is_refused() {
        for models in [json!({}), json!({ "data": {} }), json!({ "data": "x" })] {
            let server = Server::spawn(vec![
                (
                    INFO_PATH,
                    200,
                    info_json(EXPECTED_MODEL).to_string().into_bytes(),
                ),
                (MODELS_PATH, 200, models.to_string().into_bytes()),
                (
                    RERANK_PATH,
                    200,
                    json!([{ "index": 0, "score": 0.5 }])
                        .to_string()
                        .into_bytes(),
                ),
            ]);
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "models {models}"
            );
            assert_eq!(
                server.paths().len(),
                2,
                "the call stops after the metadata pair"
            );
        }
    }

    #[test]
    fn a_declared_context_length_must_be_usable_and_every_declaration_must_agree() {
        let accepted = [
            // The verified live shape: only the card declares it.
            (
                info_json(EXPECTED_MODEL),
                card_json(EXPECTED_MODEL, json!(32768)),
            ),
            // The legacy metadata key is read when the card omits the field.
            (
                json!({
                    "served_model_name": EXPECTED_MODEL,
                    "is_generation": true,
                    "context_length": 32768,
                }),
                json!({ "id": EXPECTED_MODEL }),
            ),
            // Both declare the same usable value.
            (
                json!({
                    "served_model_name": EXPECTED_MODEL,
                    "is_generation": true,
                    "max_model_len": 32768,
                }),
                card_json(EXPECTED_MODEL, json!(32768)),
            ),
        ];
        for (info, card) in accepted {
            let server = Server::spawn(routes(
                &info,
                &models_json(json!([card])),
                &json!([{ "index": 0, "score": 0.5 }]),
            ));
            backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_or_else(|err| panic!("info {info}: {err}"));
        }

        let refused = [
            // Two declarations that disagree.
            (
                json!({
                    "served_model_name": EXPECTED_MODEL,
                    "is_generation": true,
                    "context_length": 65536,
                }),
                card_json(EXPECTED_MODEL, json!(32768)),
            ),
            // A boolean is not a context length.
            (
                info_json(EXPECTED_MODEL),
                card_json(EXPECTED_MODEL, json!(true)),
            ),
            // Below the required floor.
            (
                info_json(EXPECTED_MODEL),
                card_json(EXPECTED_MODEL, json!(32767)),
            ),
            // A numeric string is not a JSON integer.
            (
                info_json(EXPECTED_MODEL),
                card_json(EXPECTED_MODEL, json!("32768")),
            ),
            // A JSON float is not a JSON integer.
            (
                info_json(EXPECTED_MODEL),
                card_json(EXPECTED_MODEL, json!(32768.0)),
            ),
            // A usable card value does not cover a broken metadata value.
            (
                json!({
                    "served_model_name": EXPECTED_MODEL,
                    "is_generation": true,
                    "context_window": false,
                }),
                card_json(EXPECTED_MODEL, json!(32768)),
            ),
            // Nothing declares a context length at all.
            (info_json(EXPECTED_MODEL), json!({ "id": EXPECTED_MODEL })),
        ];
        for (info, card) in refused {
            let server = Server::spawn(routes(
                &info,
                &models_json(json!([card])),
                &json!([{ "index": 0, "score": 0.5 }]),
            ));
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "info {info} card {card}"
            );
            assert_eq!(server.posts().len(), 0, "info {info} card {card}");
        }
    }

    // ------------------------------------------------------------------
    // C2 — the frozen request and complete scoring.
    // ------------------------------------------------------------------

    #[test]
    fn a_blank_query_or_document_is_invalid_input_with_zero_requests() {
        let server = happy_server(json!([{ "index": 0, "score": 0.5 }]));
        let backend = backend_for(&server);
        let one = vec!["a real document".to_string()];

        for (query, documents) in [
            ("", one.clone()),
            ("   \t\n ", one.clone()),
            ("q", Vec::new()),
            ("q", vec!["ok".to_string(), " \n ".to_string()]),
        ] {
            let err = backend.rerank(query, &documents).unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidInput,
                "query {query:?} documents {documents:?}"
            );
        }
        assert_eq!(
            server.requests().len(),
            0,
            "invalid input must never reach the service"
        );
    }

    #[test]
    fn the_post_body_is_the_frozen_five_key_payload_at_full_n() {
        let documents = vec![
            "  leading and trailing spaces stay  ".to_string(),
            "第二段：中文、标点与空格 保持原样。".to_string(),
            "third".to_string(),
        ];
        let server = happy_server(json!([
            { "index": 0, "score": 0.1 },
            { "index": 1, "score": 0.2 },
            { "index": 2, "score": 0.3 },
        ]));
        let backend = backend_for(&server);

        let got = backend
            .rerank("what is the capital", &documents)
            .expect("rerank");
        assert_eq!(got.scores, vec![0.1, 0.2, 0.3]);

        let posts = server.posts();
        assert_eq!(posts.len(), 1, "exactly one scoring POST");
        assert_eq!(posts[0].path, RERANK_PATH);

        let body: Value = serde_json::from_slice(&posts[0].body).expect("POST body is JSON");
        let object = body.as_object().expect("POST body is an object");
        assert_eq!(
            object.len(),
            5,
            "the frozen payload carries exactly five keys"
        );
        assert_eq!(object["query"], json!("what is the capital"));
        assert_eq!(
            object["documents"],
            json!(documents),
            "documents go out as the input bytes, with no trimming or truncation"
        );
        assert_eq!(
            object["top_n"],
            json!(documents.len()),
            "top_n is the actual document count, never a fixed page length"
        );
        assert_eq!(object["return_documents"], json!(false));
        assert_eq!(object["instruct"], json!(INSTRUCT));
        assert!(
            !object.contains_key("model"),
            "the frozen request carries no model field"
        );
    }

    #[test]
    fn out_of_order_results_are_returned_in_input_order() {
        let server = happy_server(json!([
            { "index": 2, "score": 0.9 },
            { "index": 0, "score": 0.1 },
            { "index": 1, "score": 0.5 },
        ]));
        let documents: Vec<String> = (0..3).map(|n| format!("document {n}")).collect();

        let got = backend_for(&server)
            .rerank("q", &documents)
            .expect("rerank");
        assert_eq!(
            got.scores,
            vec![0.1, 0.5, 0.9],
            "scores are re-ordered to the input index order, including the last item"
        );
    }

    #[test]
    fn an_incomplete_or_ill_typed_score_set_fails_the_whole_call() {
        let documents = vec!["a".to_string(), "b".to_string()];
        for scores in [
            // Too few entries.
            json!([]),
            // A missing index (a gap is never filled with a default).
            json!([{ "index": 0, "score": 0.5 }]),
            // A duplicate index.
            json!([{ "index": 0, "score": 0.5 }, { "index": 0, "score": 0.6 }]),
            // An out-of-range index.
            json!([{ "index": 0, "score": 0.5 }, { "index": 2, "score": 0.6 }]),
            // A negative index.
            json!([{ "index": -1, "score": 0.5 }, { "index": 1, "score": 0.6 }]),
            // A boolean index.
            json!([{ "index": true, "score": 0.5 }, { "index": 1, "score": 0.6 }]),
            // A string index.
            json!([{ "index": "0", "score": 0.5 }, { "index": 1, "score": 0.6 }]),
            // A string score.
            json!([{ "index": 0, "score": "0.5" }, { "index": 1, "score": 0.6 }]),
            // A boolean score.
            json!([{ "index": 0, "score": 0.5 }, { "index": 1, "score": true }]),
            // A null score.
            json!([{ "index": 0, "score": null }, { "index": 1, "score": 0.6 }]),
            // A missing score key.
            json!([{ "index": 0 }, { "index": 1, "score": 0.6 }]),
            // A missing index key.
            json!([{ "score": 0.5 }, { "index": 1, "score": 0.6 }]),
            // A non-object entry.
            json!([0.5, { "index": 1, "score": 0.6 }]),
        ] {
            let server = happy_server(scores.clone());
            let err = backend_for(&server).rerank("q", &documents).unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "scores {scores}"
            );
            assert_eq!(
                server.paths().len(),
                3,
                "a refused batch is never retried or sent to another backend"
            );
        }
    }

    #[test]
    fn a_native_response_that_is_not_an_array_is_refused() {
        for scores in [json!({}), json!({ "results": [] }), json!("x"), json!(null)] {
            let server = happy_server(scores.clone());
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "scores {scores}"
            );
            assert_eq!(server.paths().len(), 3);
        }
    }

    #[test]
    fn a_non_2xx_answer_is_a_short_coded_http_error_without_the_body() {
        let models = models_json(json!([card_json(EXPECTED_MODEL, json!(32768))]));

        let server = Server::spawn(vec![
            (
                INFO_PATH,
                500,
                b"{\"error\":\"SYNTHETIC_BODY_DO_NOT_LEAK\"}".to_vec(),
            ),
            (MODELS_PATH, 200, models.to_string().into_bytes()),
            (RERANK_PATH, 200, json!([]).to_string().into_bytes()),
        ]);
        let err = backend_for(&server)
            .rerank("q", &["d".to_string()])
            .unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::HttpError);
        assert_eq!(err.http_status, Some(500));
        assert!(!err.to_string().contains("SYNTHETIC_BODY"));
        assert_eq!(
            server.paths().len(),
            1,
            "a failed metadata GET stops the call"
        );

        let server = Server::spawn(vec![
            (
                INFO_PATH,
                200,
                info_json(EXPECTED_MODEL).to_string().into_bytes(),
            ),
            (MODELS_PATH, 200, models.to_string().into_bytes()),
            (RERANK_PATH, 503, b"{}".to_vec()),
        ]);
        let err = backend_for(&server)
            .rerank("q", &["d".to_string()])
            .unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::HttpError);
        assert_eq!(err.http_status, Some(503));
        assert_eq!(server.paths().len(), 3, "one POST, no retry");
    }

    #[test]
    fn the_fixed_query_and_documents_reach_the_service_unmodified() {
        let documents = vec![
            "  a document with surrounding whitespace  ".to_string(),
            "line one\nline two".to_string(),
        ];
        let server = happy_server(json!([
            { "index": 0, "score": 0.4 },
            { "index": 1, "score": 0.6 },
        ]));
        let query = "  spaced query  ";
        backend_for(&server)
            .rerank(query, &documents)
            .expect("rerank");

        let body: Value =
            serde_json::from_slice(&server.posts()[0].body).expect("POST body is JSON");
        assert_eq!(body["query"], json!(query));
        assert_eq!(body["documents"], json!(documents));
    }

    // ------------------------------------------------------------------
    // Identity and the readiness probe.
    // ------------------------------------------------------------------

    #[test]
    fn an_unproven_serving_provider_is_left_null_rather_than_guessed() {
        // The live `/get_model_info` carries SGLang-shaped fields but nothing
        // that names the serving provider; none of them may be promoted into
        // `serving_provider`.
        let info = json!({
            "served_model_name": EXPECTED_MODEL,
            "is_generation": true,
            "model_path": "/models/Qwen3-Reranker-8B",
            "weight_version": "default",
            "load_format": "safetensors",
            "architectures": ["Qwen3ForSequenceClassification"],
        });
        let server = Server::spawn(routes(
            &info,
            &models_json(json!([card_json(EXPECTED_MODEL, json!(32768))])),
            &json!([{ "index": 0, "score": 0.5 }]),
        ));

        let got = backend_for(&server)
            .rerank("q", &["d".to_string()])
            .expect("rerank");
        assert_eq!(got.identity.serving_provider, None);
        assert_eq!(got.identity.actual_model.as_deref(), Some(EXPECTED_MODEL));
        assert_eq!(
            got.identity.actual_provider,
            Some(ProviderChoice::Qwen3Local)
        );
    }

    #[test]
    fn probe_ready_sends_one_fixed_document_and_returns_one_score() {
        let server = happy_server(json!([{ "index": 0, "score": 0.5 }]));
        let backend = backend_for(&server);

        let got = backend.probe_ready().expect("probe");
        assert_eq!(got.scores.len(), 1);
        assert!(got.scores[0].is_finite());
        assert_eq!(got.http_requests, 3);
        assert_eq!(
            as_strs(&server.paths()),
            vec![INFO_PATH, MODELS_PATH, RERANK_PATH],
            "the probe walks the same adapter path as a real call"
        );

        let body: Value =
            serde_json::from_slice(&server.posts()[0].body).expect("POST body is JSON");
        assert_eq!(body["query"], json!("rerank readiness probe"));
        assert_eq!(body["documents"], json!(["rerank readiness probe"]));
        assert_eq!(body["top_n"], json!(1));
        assert_eq!(body["return_documents"], json!(false));
        assert_eq!(body["instruct"], json!(INSTRUCT));
    }

    #[test]
    fn the_adapter_sends_no_authorization_header() {
        let server = happy_server(json!([{ "index": 0, "score": 0.5 }]));
        backend_for(&server)
            .rerank("q", &["d".to_string()])
            .expect("rerank");

        assert_eq!(server.requests().len(), 3);
        for request in server.requests() {
            let head = request.head.to_ascii_lowercase();
            assert!(
                !head.contains("authorization:"),
                "unexpected credential header in {} {}",
                request.method,
                request.path
            );
        }
    }
}
