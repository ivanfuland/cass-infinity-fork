//! Shared OpenRouter rerank adapter for the three cloud selections.
//!
//! All three OpenRouter selections (`openrouter-qwen3-8b`,
//! `openrouter-cohere-4-fast`, `openrouter-voyage-2.5-lite`) run through this
//! one adapter: only the request model differs, so there is no per-vendor
//! client and no historical serving-provider list is baked in here.
//!
//! - [`OpenRouterBackend::from_env`] is the production constructor. It refuses
//!   the two local selections, reads only `OPENROUTER_API_KEY`, and sends no
//!   HTTP request.
//! - [`DEFAULT_ORIGIN`] and the fixed `RERANK_PATH` pin the production
//!   endpoint; there is no environment or CLI override.
//! - [`OpenRouterBackend::probe_ready`] sends one fixed public pair through the
//!   same code path, for a later readiness check.
//!
//! Request and response are deliberately narrow. The request body carries only
//! `model`, `query`, `documents`, `top_n` and `provider.allow_fallbacks`; the
//! response is reduced to input-order scores plus proven identity fields. No
//! response body, query, document, credential or request payload can reach an
//! error value or a log line: the adapter emits no tracing and every failure is
//! a short code, plus an HTTP status when one was observed.

use std::time::{Duration, Instant};

use serde_json::Value;

use super::http::{HttpConfig, HttpTransport};
use super::types::{
    CallIdentity, ProviderChoice, RerankBackend, RerankError, RerankFailureReason, RerankResponse,
    validate_index_scores,
};

/// The fixed production origin of the OpenRouter rerank service.
///
/// P09 binds this value, and production construction uses the same constant, so
/// the two can never drift apart.
pub const DEFAULT_ORIGIN: &str = "https://openrouter.ai";

/// The fixed production rerank path. There is no environment or CLI override.
const RERANK_PATH: &str = "/api/v1/rerank";

/// The only credential source this adapter reads.
const API_KEY_ENV: &str = "OPENROUTER_API_KEY";

/// The fixed text [`OpenRouterBackend::probe_ready`] sends.
const PROBE_TEXT: &str = "rerank readiness probe";

/// The shared OpenRouter adapter for the three cloud selections.
///
/// It holds the bearer token inside its transport, so it deliberately
/// implements neither `Debug` nor `Serialize`.
pub struct OpenRouterBackend {
    provider: ProviderChoice,
    transport: HttpTransport,
}

impl OpenRouterBackend {
    /// Build the production adapter for `provider` from the process environment.
    ///
    /// Only `OPENROUTER_API_KEY` is read; no other provider key and no
    /// credential file is consulted. The two local selections are refused, a
    /// missing or blank key is [`RerankFailureReason::MissingCredentials`] and a
    /// non-Unicode key is [`RerankFailureReason::InvalidInput`]. Every one of
    /// those failures is decided before a transport exists, so the constructor
    /// sends no request.
    pub fn from_env(provider: ProviderChoice) -> Result<Self, RerankError> {
        match provider {
            ProviderChoice::Qwen3Local | ProviderChoice::BgeLocal => {
                return Err(RerankError::new(RerankFailureReason::UnsupportedProvider));
            }
            ProviderChoice::OpenrouterQwen38b
            | ProviderChoice::OpenrouterCohere4Fast
            | ProviderChoice::OpenrouterVoyage25Lite => {}
        }

        let raw = std::env::var(API_KEY_ENV).map_err(|err| match err {
            std::env::VarError::NotPresent => {
                RerankError::new(RerankFailureReason::MissingCredentials)
            }
            std::env::VarError::NotUnicode(_) => {
                RerankError::new(RerankFailureReason::InvalidInput)
            }
        })?;
        let token = raw.trim();
        if token.is_empty() {
            return Err(RerankError::new(RerankFailureReason::MissingCredentials));
        }

        let transport = HttpTransport::new(production_config(), Some(token.to_string()))?;
        Ok(Self {
            provider,
            transport,
        })
    }

    /// Send one fixed public pair through the normal call path.
    ///
    /// This exists so a later ticket can verify readiness without an extra
    /// request during ordinary search.
    pub fn probe_ready(&self) -> Result<RerankResponse, RerankError> {
        let documents = [PROBE_TEXT.to_string()];
        self.call(PROBE_TEXT, &documents)
    }

    /// Send one request and reduce it to input-order scores plus identity.
    fn call(&self, query: &str, documents: &[String]) -> Result<RerankResponse, RerankError> {
        if query.trim().is_empty()
            || documents.is_empty()
            || documents.iter().any(|document| document.trim().is_empty())
        {
            return Err(RerankError::new(RerankFailureReason::InvalidInput));
        }

        let started = Instant::now();
        let body = serde_json::json!({
            "model": self.provider.request_model(),
            "query": query,
            "documents": documents,
            "top_n": documents.len(),
            "provider": { "allow_fallbacks": false },
        });

        let response = self.transport.post_json(RERANK_PATH, &body)?;
        let expected = documents.len();

        let results = response.body.get("results").ok_or_else(invalid_response)?;
        let scores = validate_index_scores(results, expected)?;
        let actual_model = parse_actual_model(&response.body, self.provider)?;
        let serving_provider = parse_serving_provider(&response.body)?;

        Ok(RerankResponse {
            scores,
            identity: CallIdentity {
                actual_provider: Some(self.provider),
                actual_model,
                serving_provider,
            },
            http_requests: 1,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    }
}

impl RerankBackend for OpenRouterBackend {
    fn provider(&self) -> ProviderChoice {
        self.provider
    }

    fn rerank(&self, query: &str, documents: &[String]) -> Result<RerankResponse, RerankError> {
        self.call(query, documents)
    }
}

/// The test-only constructor: inject a transport pointed at a local fixture.
///
/// This is compiled only under `#[cfg(test)]`, so no product path can redirect
/// a real credential to another endpoint.
#[cfg(test)]
impl OpenRouterBackend {
    fn with_transport(provider: ProviderChoice, transport: HttpTransport) -> Self {
        Self {
            provider,
            transport,
        }
    }
}

/// The fixed production transport configuration.
///
/// The origin is [`DEFAULT_ORIGIN`] and the path is imposed by the adapter, so
/// there is no environment or CLI override. `local_only` stays false because the
/// service is remote; the three budgets and the bearer come from the shared P02
/// transport.
fn production_config() -> HttpConfig {
    HttpConfig {
        base_url: DEFAULT_ORIGIN.to_string(),
        local_only: false,
        timeout: Duration::from_secs(60),
        connect_timeout: Duration::from_secs(5),
        max_response_bytes: 64 * 1024 * 1024,
    }
}

fn invalid_response() -> RerankError {
    RerankError::new(RerankFailureReason::InvalidResponse)
}

/// Reduce the response's `model` field to proven identity evidence.
///
/// A missing or null field proves nothing; a non-empty string must be an
/// accepted alias for the selection; any other value is unparseable.
fn parse_actual_model(
    body: &Value,
    provider: ProviderChoice,
) -> Result<Option<String>, RerankError> {
    match body.get("model") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(model)) => {
            if model.is_empty() {
                return Err(invalid_response());
            }
            if !provider.accepts_model(model.as_str()) {
                return Err(RerankError::new(RerankFailureReason::ModelIdentityMismatch));
            }
            Ok(Some(model.to_string()))
        }
        Some(_) => Err(invalid_response()),
    }
}

/// Reduce the response's `provider` field to the value the service claimed.
///
/// The value is recorded as-is and is not checked against any historical
/// serving-provider list. A present but empty, control-bearing or non-string
/// value is unparseable, and absence proves only `None`.
fn parse_serving_provider(body: &Value) -> Result<Option<String>, RerankError> {
    match body.get("provider") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(name)) => {
            if name.is_empty() || name.chars().any(char::is_control) {
                return Err(invalid_response());
            }
            Ok(Some(name.to_string()))
        }
        Some(_) => Err(invalid_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use serde_json::json;

    use crate::search::rerank::http::{HttpConfig, HttpTransport};
    use crate::search::rerank::types::{ProviderChoice, RerankFailureReason};

    // ------------------------------------------------------------------
    // A loopback HTTP/1.1 fixture. Every instance binds its own ephemeral
    // port, records the exact request bytes it served, and reclaims its own
    // thread and socket on drop. No process-wide state is touched, so
    // instances stay independent under the default parallel runner.
    // ------------------------------------------------------------------

    /// The response the fixture sends for every connection it accepts.
    #[derive(Clone)]
    struct Reply {
        status_line: &'static str,
        body: Vec<u8>,
    }

    fn json_reply(status_line: &'static str, body: serde_json::Value) -> Reply {
        Reply {
            status_line,
            body: serde_json::to_vec(&body).expect("serialize fixture body"),
        }
    }

    fn raw_reply(status_line: &'static str, body: &str) -> Reply {
        Reply {
            status_line,
            body: body.as_bytes().to_vec(),
        }
    }

    struct Fixture {
        addr: SocketAddr,
        hits: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl Fixture {
        fn spawn(reply: Reply) -> Fixture {
            let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .expect("bind fixture port");
            let addr = listener.local_addr().expect("fixture local_addr");
            listener.set_nonblocking(true).expect("fixture nonblocking");
            let hits = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (h, r, s) = (hits.clone(), requests.clone(), stop.clone());
            let thread = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(30);
                while !s.load(Ordering::SeqCst) && Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            h.fetch_add(1, Ordering::SeqCst);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                            let request = read_request(&mut stream);
                            r.lock().unwrap().push(request);
                            let head = format!(
                                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                                reply.status_line,
                                reply.body.len()
                            );
                            let _ = stream.write_all(head.as_bytes());
                            let _ = stream.write_all(&reply.body);
                            let _ = stream.flush();
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Fixture {
                addr,
                hits,
                requests,
                stop,
                thread: Some(thread),
            }
        }

        fn base(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }

        fn captured(&self, index: usize) -> SentRequest {
            let requests = self.requests.lock().unwrap();
            parse_sent(&requests[index])
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn content_length_of_head(head: &[u8]) -> usize {
        let text = String::from_utf8_lossy(head);
        for line in text.split("\r\n") {
            if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                return rest.trim().parse().unwrap_or(0);
            }
        }
        0
    }

    /// Read one request: headers up to CRLFCRLF, then `Content-Length` bytes.
    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut header_end: Option<usize> = None;
        let mut body_len = 0usize;
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if header_end.is_none()
                        && let Some(pos) = find_subsequence(&buf, b"\r\n\r\n")
                    {
                        header_end = Some(pos + 4);
                        body_len = content_length_of_head(&buf[..pos]);
                    }
                    if let Some(end) = header_end
                        && buf.len() >= end + body_len
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        buf
    }

    /// One recorded request, reduced to the facts the contract cares about.
    struct SentRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl SentRequest {
        fn header(&self, name: &str) -> Option<&str> {
            let name = name.to_ascii_lowercase();
            self.headers
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.as_str())
        }

        fn json_body(&self) -> serde_json::Value {
            serde_json::from_slice(&self.body).expect("request body is JSON")
        }
    }

    fn parse_sent(buf: &[u8]) -> SentRequest {
        let head_end = find_subsequence(buf, b"\r\n\r\n").expect("headers terminate") + 4;
        let head = String::from_utf8_lossy(&buf[..head_end]);
        let mut lines = head.split("\r\n");
        let request_line = lines.next().expect("request line");
        let mut parts = request_line.split(' ');
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        SentRequest {
            method,
            path,
            headers,
            body: buf[head_end..].to_vec(),
        }
    }

    // ------------------------------------------------------------------
    // Synthetic credentials and the test-only transport injection.
    // ------------------------------------------------------------------

    /// A fresh synthetic token per call. It is generated at run time and is not
    /// written in any real key format, so no fixture holds a credential value.
    fn synthetic_token(label: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        format!("p07-synthetic-{label}-{:x}-{:x}", std::process::id(), nanos)
    }

    fn transport_for(base: &str, token: Option<&str>) -> HttpTransport {
        let config = HttpConfig {
            base_url: base.to_string(),
            local_only: true,
            timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(5),
            max_response_bytes: 64 * 1024 * 1024,
        };
        HttpTransport::new(config, token.map(str::to_string)).expect("test transport")
    }

    fn backend_for(provider: ProviderChoice, base: &str, token: &str) -> OpenRouterBackend {
        OpenRouterBackend::with_transport(provider, transport_for(base, Some(token)))
    }

    // ------------------------------------------------------------------
    // C1 — one adapter, one code path, three selections.
    // ------------------------------------------------------------------

    #[test]
    fn three_openrouter_providers_share_one_adapter() {
        let token = synthetic_token("shared");
        let query = "which passage answers the question?";
        let documents = vec![
            "first passage".to_string(),
            "second passage".to_string(),
            "third passage".to_string(),
        ];

        let reply = json_reply(
            "200 OK",
            json!({
                "provider": "synthetic-host",
                "results": [
                    {"index": 0, "relevance_score": 0.1},
                    {"index": 1, "relevance_score": 0.2},
                    {"index": 2, "relevance_score": 0.3}
                ]
            }),
        );
        let fixture = Fixture::spawn(reply);

        let providers = [
            ProviderChoice::OpenrouterQwen38b,
            ProviderChoice::OpenrouterCohere4Fast,
            ProviderChoice::OpenrouterVoyage25Lite,
        ];

        for (position, provider) in providers.iter().copied().enumerate() {
            let backend = backend_for(provider, &fixture.base(), &token);
            let response = backend
                .rerank(query, &documents)
                .unwrap_or_else(|err| panic!("{provider:?} call failed: {err}"));

            // Only the selected provider issued a request: the shared counter
            // moved by exactly one, so the other two selections stayed at zero.
            assert_eq!(fixture.hits(), position + 1, "{provider:?} request count");

            let sent = fixture.captured(position);
            assert_eq!(sent.method, "POST");
            assert_eq!(sent.path, RERANK_PATH);
            let expected_auth = format!("Bearer {token}");
            assert_eq!(sent.header("authorization"), Some(expected_auth.as_str()));

            let body = sent.json_body();
            let object = body.as_object().expect("request body is an object");
            let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                vec!["documents", "model", "provider", "query", "top_n"],
                "{provider:?} request payload whitelist"
            );
            assert_eq!(body["model"], json!(provider.request_model()));
            assert_eq!(body["query"], json!(query));
            assert_eq!(body["documents"], json!(documents));
            assert_eq!(body["top_n"], json!(documents.len()));
            assert_eq!(body["provider"], json!({"allow_fallbacks": false}));

            // No source path, session id, title or search-hit field rides along.
            let raw = String::from_utf8_lossy(&sent.body).to_ascii_lowercase();
            for forbidden in [
                "source_path",
                "conversation_id",
                "message_id",
                "title",
                "return_documents",
                "raw_scores",
                "searchhit",
            ] {
                assert!(
                    !raw.contains(forbidden),
                    "{provider:?} payload leaked {forbidden}"
                );
            }

            assert_eq!(response.http_requests, 1);
            assert!(response.duration_ms <= 60_000);
            assert_eq!(response.identity.actual_provider, Some(provider));
            assert_eq!(response.identity.actual_model, None);
            assert_eq!(
                response.identity.serving_provider.as_deref(),
                Some("synthetic-host")
            );
            assert_eq!(response.scores, vec![0.1, 0.2, 0.3]);
        }

        assert_eq!(fixture.hits(), 3, "exactly one request per selection");
    }

    #[test]
    fn native_alias_and_request_model_are_both_accepted() {
        let token = synthetic_token("alias");
        let documents = vec!["passage".to_string()];
        let cases = [
            (
                ProviderChoice::OpenrouterQwen38b,
                "accounts/fireworks/models/qwen3-reranker-8b",
            ),
            (ProviderChoice::OpenrouterCohere4Fast, "rerank-v4.0-fast"),
            (ProviderChoice::OpenrouterVoyage25Lite, "rerank-2.5-lite"),
        ];

        for (provider, alias) in cases {
            for reported in [provider.request_model(), alias] {
                let reply = json_reply(
                    "200 OK",
                    json!({
                        "model": reported,
                        "results": [{"index": 0, "relevance_score": 0.42}]
                    }),
                );
                let fixture = Fixture::spawn(reply);
                let backend = backend_for(provider, &fixture.base(), &token);
                let response = backend
                    .rerank("q", &documents)
                    .unwrap_or_else(|err| panic!("{provider:?}/{reported} failed: {err}"));
                assert_eq!(
                    response.identity.actual_model.as_deref(),
                    Some(reported),
                    "{provider:?} reported model"
                );
            }
        }
    }

    #[test]
    fn long_and_cjk_documents_are_sent_verbatim() {
        let token = synthetic_token("verbatim");
        let query = "Which passage explains 中文语义检索 with a 复杂 query?";
        let long_ascii = "lorem ipsum ".repeat(700);
        let documents = vec![
            "中文文档一：完整的原字符串不得被截断。".to_string(),
            long_ascii.clone(),
            format!("{}end", "尾部内容".repeat(400)),
        ];

        let reply = json_reply(
            "200 OK",
            json!({
                "results": [
                    {"index": 0, "relevance_score": 1.0},
                    {"index": 1, "relevance_score": 2.0},
                    {"index": 2, "relevance_score": 3.0}
                ]
            }),
        );
        let fixture = Fixture::spawn(reply);
        let backend = backend_for(ProviderChoice::OpenrouterQwen38b, &fixture.base(), &token);

        let response = backend
            .rerank(query, &documents)
            .unwrap_or_else(|err| panic!("call failed: {err}"));
        assert_eq!(response.scores, vec![1.0, 2.0, 3.0]);

        let sent = fixture.captured(0);
        let body = sent.json_body();
        assert_eq!(body["documents"], json!(documents));
        assert_eq!(body["query"], json!(query));
        assert_eq!(body["top_n"], json!(3));

        // The raw bytes carry the whole document, not a prefix of it.
        let raw = String::from_utf8_lossy(&sent.body);
        assert!(raw.contains(&long_ascii));
        assert!(raw.contains(&"尾部内容".repeat(400)));
    }

    #[test]
    fn results_are_restored_to_input_index_order() {
        let token = synthetic_token("order");
        let reply = json_reply(
            "200 OK",
            json!({
                "results": [
                    {"index": 2, "relevance_score": 0.9},
                    {"index": 0, "relevance_score": 0.1},
                    {"index": 1, "relevance_score": 0.5}
                ]
            }),
        );
        let fixture = Fixture::spawn(reply);
        let backend = backend_for(
            ProviderChoice::OpenrouterVoyage25Lite,
            &fixture.base(),
            &token,
        );

        let response = backend
            .rerank("q", &["a".to_string(), "b".to_string(), "c".to_string()])
            .unwrap_or_else(|err| panic!("call failed: {err}"));
        assert_eq!(response.scores, vec![0.1, 0.5, 0.9]);
    }

    // ------------------------------------------------------------------
    // C2 — identity evidence and the failure surface.
    // ------------------------------------------------------------------

    #[test]
    fn absent_and_null_identity_fields_stay_none() {
        let token = synthetic_token("identity");

        for (label, reply) in [
            (
                "absent",
                json_reply(
                    "200 OK",
                    json!({"results": [{"index": 0, "relevance_score": 0.5}]}),
                ),
            ),
            (
                "explicit null",
                json_reply(
                    "200 OK",
                    json!({
                        "model": null,
                        "provider": null,
                        "results": [{"index": 0, "relevance_score": 0.5}]
                    }),
                ),
            ),
        ] {
            let fixture = Fixture::spawn(reply);
            let backend = backend_for(
                ProviderChoice::OpenrouterCohere4Fast,
                &fixture.base(),
                &token,
            );
            let response = backend
                .rerank("q", &["d".to_string()])
                .unwrap_or_else(|err| panic!("{label} failed: {err}"));
            assert_eq!(
                response.identity.actual_provider,
                Some(ProviderChoice::OpenrouterCohere4Fast),
                "{label} actual_provider"
            );
            assert_eq!(response.identity.actual_model, None, "{label} actual_model");
            assert_eq!(
                response.identity.serving_provider, None,
                "{label} serving_provider"
            );
            assert_eq!(response.scores, vec![0.5], "{label} scores");
        }
    }

    #[test]
    fn model_mismatch_and_bad_model_types_are_refused() {
        let token = synthetic_token("model");
        let documents = vec!["d".to_string()];

        // A well-formed string that is not an accepted alias for the selection.
        let reply = json_reply(
            "200 OK",
            json!({
                "model": "cohere/rerank-4-fast",
                "results": [{"index": 0, "relevance_score": 0.5}]
            }),
        );
        let fixture = Fixture::spawn(reply);
        let backend = backend_for(ProviderChoice::OpenrouterQwen38b, &fixture.base(), &token);
        let err = backend
            .rerank("q", &documents)
            .err()
            .expect("a mismatched model must fail");
        assert_eq!(err.reason, RerankFailureReason::ModelIdentityMismatch);
        assert_eq!(err.http_status, None);

        // Empty strings and non-string types are invalid responses, not mismatches.
        for (label, model) in [
            ("empty", json!("")),
            ("number", json!(7)),
            ("array", json!(["m"])),
            ("object", json!({"m": 1})),
            ("boolean", json!(true)),
        ] {
            let reply = json_reply(
                "200 OK",
                json!({
                    "model": model,
                    "results": [{"index": 0, "relevance_score": 0.5}]
                }),
            );
            let fixture = Fixture::spawn(reply);
            let backend = backend_for(ProviderChoice::OpenrouterQwen38b, &fixture.base(), &token);
            let err = backend
                .rerank("q", &documents)
                .err()
                .expect("a bad model field must fail");
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "model {label}"
            );
        }
    }

    #[test]
    fn serving_provider_is_recorded_as_response_value() {
        let token = synthetic_token("serving");
        let documents = vec!["d".to_string()];

        // Absent, null and any non-empty string are accepted; the value is
        // recorded as-is with no historical serving-provider list in the way.
        for (label, provider_field, expected) in [
            ("absent", None, None),
            ("null", Some(json!(null)), None),
            ("fireworks", Some(json!("Fireworks")), Some("Fireworks")),
            ("cohere", Some(json!("cohere")), Some("cohere")),
            (
                "arbitrary",
                Some(json!("some-new-host")),
                Some("some-new-host"),
            ),
        ] {
            let mut body = json!({
                "results": [{"index": 0, "relevance_score": 0.5}]
            });
            if let Some(value) = provider_field {
                body["provider"] = value;
            }
            let fixture = Fixture::spawn(json_reply("200 OK", body));
            let backend = backend_for(
                ProviderChoice::OpenrouterVoyage25Lite,
                &fixture.base(),
                &token,
            );
            let response = backend
                .rerank("q", &documents)
                .unwrap_or_else(|err| panic!("{label} failed: {err}"));
            assert_eq!(
                response.identity.serving_provider.as_deref(),
                expected,
                "{label} serving_provider"
            );
        }

        // Empty, control-character-bearing and non-string values are invalid.
        for (label, value) in [
            ("empty", json!("")),
            ("control", json!("bad\u{7}name")),
            ("number", json!(3)),
            ("array", json!([])),
        ] {
            let reply = json_reply(
                "200 OK",
                json!({
                    "provider": value,
                    "results": [{"index": 0, "relevance_score": 0.5}]
                }),
            );
            let fixture = Fixture::spawn(reply);
            let backend = backend_for(
                ProviderChoice::OpenrouterVoyage25Lite,
                &fixture.base(),
                &token,
            );
            let err = backend
                .rerank("q", &documents)
                .err()
                .expect("a bad provider field must fail");
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "provider {label}"
            );
        }
    }

    #[test]
    fn malformed_results_are_refused_as_a_whole() {
        let token = synthetic_token("results");
        let documents = vec!["a".to_string(), "b".to_string()];

        let cases: Vec<(&str, Reply)> = vec![
            (
                "missing entry",
                json_reply(
                    "200 OK",
                    json!({"results": [{"index": 0, "relevance_score": 1.0}]}),
                ),
            ),
            (
                "duplicate index",
                json_reply(
                    "200 OK",
                    json!({"results": [
                        {"index": 0, "relevance_score": 1.0},
                        {"index": 0, "relevance_score": 2.0}
                    ]}),
                ),
            ),
            (
                "out of range index",
                json_reply(
                    "200 OK",
                    json!({"results": [
                        {"index": 0, "relevance_score": 1.0},
                        {"index": 5, "relevance_score": 2.0}
                    ]}),
                ),
            ),
            (
                "boolean index",
                json_reply(
                    "200 OK",
                    json!({"results": [
                        {"index": true, "relevance_score": 1.0},
                        {"index": 1, "relevance_score": 2.0}
                    ]}),
                ),
            ),
            (
                "string index",
                json_reply(
                    "200 OK",
                    json!({"results": [
                        {"index": "0", "relevance_score": 1.0},
                        {"index": 1, "relevance_score": 2.0}
                    ]}),
                ),
            ),
            (
                "fractional index",
                json_reply(
                    "200 OK",
                    json!({"results": [
                        {"index": 0.5, "relevance_score": 1.0},
                        {"index": 1, "relevance_score": 2.0}
                    ]}),
                ),
            ),
            (
                "negative index",
                json_reply(
                    "200 OK",
                    json!({"results": [
                        {"index": -1, "relevance_score": 1.0},
                        {"index": 1, "relevance_score": 2.0}
                    ]}),
                ),
            ),
            (
                "string score",
                json_reply(
                    "200 OK",
                    json!({"results": [
                        {"index": 0, "relevance_score": "1.0"},
                        {"index": 1, "relevance_score": 2.0}
                    ]}),
                ),
            ),
            (
                "missing score",
                json_reply(
                    "200 OK",
                    json!({"results": [
                        {"index": 0},
                        {"index": 1, "relevance_score": 2.0}
                    ]}),
                ),
            ),
            (
                "non-finite score",
                raw_reply(
                    "200 OK",
                    r#"{"results":[{"index":0,"relevance_score":1e999},{"index":1,"relevance_score":2.0}]}"#,
                ),
            ),
            (
                "results not an array",
                json_reply("200 OK", json!({"results": {"index": 0}})),
            ),
            (
                "results missing",
                json_reply("200 OK", json!({"object": "list"})),
            ),
        ];

        for (label, reply) in cases {
            let fixture = Fixture::spawn(reply);
            let backend = backend_for(ProviderChoice::OpenrouterQwen38b, &fixture.base(), &token);
            let err = backend
                .rerank("q", &documents)
                .err()
                .unwrap_or_else(|| panic!("{label} must fail"));
            assert_eq!(err.reason, RerankFailureReason::InvalidResponse, "{label}");
            // The failure still came from one real request.
            assert_eq!(fixture.hits(), 1, "{label} request count");
        }
    }

    #[test]
    fn blank_input_is_refused_without_a_request() {
        let token = synthetic_token("blank");
        let fixture = Fixture::spawn(json_reply(
            "200 OK",
            json!({"results": [{"index": 0, "relevance_score": 1.0}]}),
        ));
        let backend = backend_for(ProviderChoice::OpenrouterQwen38b, &fixture.base(), &token);

        let cases: Vec<(&str, &str, Vec<String>)> = vec![
            ("empty query", "", vec!["d".to_string()]),
            ("whitespace query", "  \t\n ", vec!["d".to_string()]),
            ("empty documents", "q", Vec::new()),
            (
                "blank document",
                "q",
                vec!["ok".to_string(), "   ".to_string()],
            ),
        ];

        for (label, query, documents) in cases {
            let err = backend
                .rerank(query, &documents)
                .err()
                .unwrap_or_else(|| panic!("{label} must fail"));
            assert_eq!(err.reason, RerankFailureReason::InvalidInput, "{label}");
        }

        assert_eq!(fixture.hits(), 0, "no request may be sent for blank input");
    }

    #[test]
    fn local_selections_are_refused_before_any_credential() {
        // Both local selections are rejected before the environment is read, so
        // this holds whatever OPENROUTER_API_KEY contains.
        for local in [ProviderChoice::Qwen3Local, ProviderChoice::BgeLocal] {
            let err = from_env(local)
                .err()
                .expect("a local selection must be refused");
            assert_eq!(err.reason, RerankFailureReason::UnsupportedProvider);
        }
    }

    #[test]
    fn non_2xx_status_is_short_coded_and_leaks_nothing() {
        let token = synthetic_token("non2xx");
        let secret = format!("SYNTHETIC-RESPONSE-BODY-{}", synthetic_token("body"));
        let fixture = Fixture::spawn(raw_reply("500 Internal Server Error", &secret));
        let backend = backend_for(ProviderChoice::OpenrouterQwen38b, &fixture.base(), &token);

        let err = backend
            .rerank("q", &["d".to_string()])
            .err()
            .expect("a 500 must fail");
        assert_eq!(err.reason, RerankFailureReason::HttpError);
        assert_eq!(err.http_status, Some(500));

        let rendered = format!("{err}");
        assert!(
            !rendered.contains(&secret),
            "response body leaked: {rendered}"
        );
        assert!(!rendered.contains(&token), "token leaked: {rendered}");
        assert_eq!(fixture.hits(), 1);
    }

    #[test]
    fn probe_ready_sends_the_fixed_public_pair() {
        let token = synthetic_token("probe");
        let fixture = Fixture::spawn(json_reply(
            "200 OK",
            json!({"results": [{"index": 0, "relevance_score": 0.0}]}),
        ));
        let backend = backend_for(
            ProviderChoice::OpenrouterCohere4Fast,
            &fixture.base(),
            &token,
        );

        let response = backend
            .probe_ready()
            .unwrap_or_else(|err| panic!("probe failed: {err}"));
        assert_eq!(response.scores, vec![0.0]);
        assert_eq!(fixture.hits(), 1);

        let sent = fixture.captured(0);
        assert_eq!(sent.method, "POST");
        assert_eq!(sent.path, RERANK_PATH);
        let body = sent.json_body();
        assert_eq!(body["query"], json!(PROBE_TEXT));
        assert_eq!(body["documents"], json!([PROBE_TEXT]));
        assert_eq!(body["top_n"], json!(1));
        assert_eq!(
            body["model"],
            json!(ProviderChoice::OpenrouterCohere4Fast.request_model())
        );
    }

    #[test]
    fn production_config_is_fixed_and_not_overridable() {
        let config = production_config();
        assert_eq!(config.base_url, DEFAULT_ORIGIN);
        assert_eq!(config.base_url, "https://openrouter.ai");
        assert!(!config.local_only);
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.max_response_bytes, 64 * 1024 * 1024);
        assert_eq!(RERANK_PATH, "/api/v1/rerank");
    }

    // ------------------------------------------------------------------
    // Environment boundaries: injected into a child process so the shared
    // parent test process environment is never mutated.
    // ------------------------------------------------------------------

    const ENV_CHILD_SCENARIO: &str = "P07_ENV_CHILD_SCENARIO";

    #[test]
    fn env_child_fixture() {
        let Ok(scenario) = std::env::var(ENV_CHILD_SCENARIO) else {
            return; // no-op during an ordinary parent run
        };
        let cloud = [
            ProviderChoice::OpenrouterQwen38b,
            ProviderChoice::OpenrouterCohere4Fast,
            ProviderChoice::OpenrouterVoyage25Lite,
        ];
        match scenario.as_str() {
            "missing" | "empty" | "whitespace" => {
                for provider in cloud {
                    let err = from_env(provider)
                        .err()
                        .expect("a missing or blank credential must fail");
                    assert_eq!(err.reason, RerankFailureReason::MissingCredentials);
                }
                for local in [ProviderChoice::Qwen3Local, ProviderChoice::BgeLocal] {
                    let err = from_env(local)
                        .err()
                        .expect("a local selection must be refused");
                    assert_eq!(err.reason, RerankFailureReason::UnsupportedProvider);
                }
            }
            "nonunicode" => {
                for provider in cloud {
                    let err = from_env(provider)
                        .err()
                        .expect("a non-Unicode credential must fail");
                    assert_eq!(err.reason, RerankFailureReason::InvalidInput);
                }
            }
            "valid" => {
                for provider in cloud {
                    let backend = from_env(provider)
                        .unwrap_or_else(|err| panic!("a valid key must construct: {err}"));
                    assert_eq!(backend.provider, provider);
                }
                for local in [ProviderChoice::Qwen3Local, ProviderChoice::BgeLocal] {
                    let err = from_env(local)
                        .err()
                        .expect("a local selection must be refused");
                    assert_eq!(err.reason, RerankFailureReason::UnsupportedProvider);
                }
            }
            other => panic!("unknown child scenario {other}"),
        }
    }

    fn spawn_env_child(scenario: &str) -> std::process::ExitStatus {
        let exe = std::env::current_exe().expect("current_exe");
        let mut command = Command::new(exe);
        command
            .arg("--exact")
            .arg("search::rerank::openrouter::tests::env_child_fixture")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(ENV_CHILD_SCENARIO, scenario)
            .env_remove("OPENROUTER_API_KEY");
        match scenario {
            "valid" => {
                command.env("OPENROUTER_API_KEY", synthetic_token("env-valid"));
            }
            "empty" => {
                command.env("OPENROUTER_API_KEY", "");
            }
            "whitespace" => {
                command.env("OPENROUTER_API_KEY", "  \t ");
            }
            #[cfg(unix)]
            "nonunicode" => {
                use std::ffi::OsString;
                use std::os::unix::ffi::OsStringExt;
                command.env(
                    "OPENROUTER_API_KEY",
                    OsString::from_vec(vec![0x66, 0x6f, 0x80]),
                );
            }
            _ => {}
        }
        command.status().expect("spawn child test process")
    }

    #[test]
    fn from_env_credential_and_selection_boundaries() {
        for scenario in ["missing", "empty", "whitespace", "valid"] {
            let status = spawn_env_child(scenario);
            assert!(
                status.success(),
                "child scenario {scenario} failed: {status:?}"
            );
        }
        #[cfg(unix)]
        {
            let status = spawn_env_child("nonunicode");
            assert!(
                status.success(),
                "child scenario nonunicode failed: {status:?}"
            );
        }
    }
}
