//! Local Infinity BGE reranker adapter (P06).
//!
//! [`BgeBackend`] implements the shared [`RerankBackend`] contract against one
//! local Infinity server serving `BAAI/bge-reranker-v2-m3`. It owns three
//! things and nothing else:
//!
//! - **Readiness independent of embedding.** One read-only `GET /models` must
//!   list exactly one model card whose `id` is the frozen BGE reranker model.
//!   A server that only advertises the embedding model (`BAAI/bge-m3`) is not a
//!   ready reranker. This gate never calls `/embeddings` and never inspects an
//!   embedding dimension.
//! - **The frozen request.** One `POST /rerank` carrying exactly `model`,
//!   `query`, `documents` (every input byte, untruncated), `top_n` equal to the
//!   actual document count, `return_documents: false` and `raw_scores: false`.
//!   There is no 1024-character clipping, no batching and no daemon fallback.
//! - **Complete scoring and honest identity.** The response's `results` array is
//!   validated whole through the shared P01 helper: one entry per input
//!   document, each index in range and unique, each score finite. Scores are
//!   returned in input order. `actual_model` is only what the response itself
//!   named; a missing or null `model`/`provider` stays null rather than being
//!   back-filled from the request or the `/models` list.
//!
//! The adapter reuses the P02 transport. It builds one [`HttpTransport`] with a
//! fixed local-only configuration, sends no bearer, and adds no proxy, redirect
//! or retry behaviour of its own. Construction validates the origin and builds
//! the client; it sends no request.
//!
//! Every refusal is a short code from the shared [`RerankError`] vocabulary. No
//! error, log line or panic message carries a reported model name, a provider
//! name, a response body or any other field content.
//!
//! This revision carries the contract tests only; the implementation follows so
//! the missing-implementation RED is a real compile failure, not a stand-in.

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

    /// A `/models` card carrying one id.
    fn card(id: Value) -> Value {
        json!({ "id": id })
    }

    /// A `/models` body: an object whose `data` array is the given cards.
    fn models_with(cards: Value) -> Value {
        json!({ "data": cards })
    }

    /// The ready `/models` body: exactly one card for the frozen BGE reranker.
    fn served_models() -> Value {
        models_with(json!([card(json!(RERANK_MODEL))]))
    }

    /// A scoring body naming the expected model and carrying `results`.
    fn scoring_body(results: Value) -> Value {
        json!({ "model": RERANK_MODEL, "results": results })
    }

    /// The two fixture routes a complete call walks, in order.
    fn routes(models: &Value, scores: &Value) -> Vec<(&'static str, u16, Vec<u8>)> {
        vec![
            (MODELS_PATH, 200, models.to_string().into_bytes()),
            (RERANK_PATH, 200, scores.to_string().into_bytes()),
        ]
    }

    /// A fixture that serves one ready model list plus the given scoring body.
    fn happy_server(scores: Value) -> Server {
        Server::spawn(routes(&served_models(), &scores))
    }

    fn backend_for(server: &Server) -> BgeBackend {
        BgeBackend::new(&server.base()).expect("backend")
    }

    fn post_body(server: &Server, index: usize) -> Value {
        let posts = server.posts();
        serde_json::from_slice(&posts[index].body).expect("POST body is JSON")
    }

    // ------------------------------------------------------------------
    // C1 — construction and the embedding-independent readiness gate.
    // ------------------------------------------------------------------

    #[test]
    fn construction_sends_nothing_and_exposes_the_fixed_selection() {
        // Nothing listens for a request here; `new` must only validate and
        // build the client.
        let backend = BgeBackend::new(DEFAULT_ORIGIN).expect("backend");
        assert_eq!(backend.provider(), ProviderChoice::BgeLocal);
    }

    #[test]
    fn construction_keeps_the_local_only_origin_boundary() {
        let err = BgeBackend::new("http://192.0.2.1:7997")
            .err()
            .expect("non-loopback origin must be refused");
        assert_eq!(err.reason, RerankFailureReason::NonLoopbackEndpoint);

        let err = BgeBackend::new("not a url")
            .err()
            .expect("origin must parse");
        assert_eq!(err.reason, RerankFailureReason::InvalidInput);
    }

    #[test]
    fn the_happy_path_returns_input_ordered_scores_with_the_full_identity() {
        let server = happy_server(scoring_body(json!([
            { "index": 0, "relevance_score": 0.125 },
            { "index": 1, "relevance_score": 0.5 },
        ])));
        let backend = backend_for(&server);
        let documents = vec!["first".to_string(), "second".to_string()];

        let got = backend.rerank("what is it", &documents).expect("rerank");
        assert_eq!(got.scores, vec![0.125, 0.5]);
        assert_eq!(got.identity.actual_provider, Some(ProviderChoice::BgeLocal));
        assert_eq!(got.identity.actual_model.as_deref(), Some(RERANK_MODEL));
        assert_eq!(got.identity.serving_provider, None);
        assert_eq!(got.http_requests, 2);
        assert!(got.duration_ms < 60_000, "duration_ms {}", got.duration_ms);
        assert_eq!(
            as_strs(&server.paths()),
            vec![MODELS_PATH, RERANK_PATH],
            "one readiness GET, then exactly one scoring POST"
        );
    }

    #[test]
    fn an_unrelated_card_before_the_matching_card_is_accepted() {
        let server = Server::spawn(routes(
            &models_with(json!([
                card(json!("some-other-model")),
                { "id": 42 },
                card(json!(RERANK_MODEL)),
            ])),
            &scoring_body(json!([{ "index": 0, "relevance_score": 0.75 }])),
        ));

        let got = backend_for(&server)
            .rerank("q", &["only".to_string()])
            .expect("the matching card wins wherever it sits");
        assert_eq!(got.scores, vec![0.75]);
        assert_eq!(got.http_requests, 2);
    }

    #[test]
    fn a_model_list_without_the_reranker_card_is_refused_before_any_scoring_post() {
        // The load-bearing case: a server that only serves the embedding model
        // is not a ready reranker, and no scoring POST may follow.
        for cards in [
            json!([]),
            json!([card(json!("BAAI/bge-m3"))]),
            json!([card(json!("some-other-reranker"))]),
            json!([{ "id": null }, { "id": true }]),
        ] {
            let server = Server::spawn(routes(
                &models_with(cards.clone()),
                &scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }])),
            ));
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "cards {cards}"
            );
            assert_eq!(server.posts().len(), 0, "no POST may follow cards {cards}");
        }
    }

    #[test]
    fn a_duplicated_reranker_card_is_refused_before_any_scoring_post() {
        for cards in [
            json!([card(json!(RERANK_MODEL)), card(json!(RERANK_MODEL))]),
            json!([
                card(json!(RERANK_MODEL)),
                card(json!("BAAI/bge-m3")),
                card(json!(RERANK_MODEL)),
            ]),
        ] {
            let server = Server::spawn(routes(
                &models_with(cards.clone()),
                &scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }])),
            ));
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "cards {cards}"
            );
            assert_eq!(server.posts().len(), 0);
        }
    }

    #[test]
    fn a_model_list_that_is_not_an_object_with_a_data_array_is_refused() {
        for models in [
            json!([]),
            json!("x"),
            json!(null),
            json!({}),
            json!({ "data": {} }),
            json!({ "data": "x" }),
        ] {
            let server = Server::spawn(vec![
                (MODELS_PATH, 200, models.to_string().into_bytes()),
                (
                    RERANK_PATH,
                    200,
                    scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }]))
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
                1,
                "the call stops after the readiness GET"
            );
        }
    }

    #[test]
    fn a_non_2xx_models_answer_is_a_short_coded_http_error_without_the_body() {
        let server = Server::spawn(vec![
            (
                MODELS_PATH,
                500,
                b"{\"error\":\"SYNTHETIC_BODY_DO_NOT_LEAK\"}".to_vec(),
            ),
            (
                RERANK_PATH,
                200,
                scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }]))
                    .to_string()
                    .into_bytes(),
            ),
        ]);
        let err = backend_for(&server)
            .rerank("q", &["d".to_string()])
            .unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::HttpError);
        assert_eq!(err.http_status, Some(500));
        assert!(!err.to_string().contains("SYNTHETIC_BODY"));
        assert_eq!(server.paths().len(), 1, "a failed readiness GET stops the call");
    }

    // ------------------------------------------------------------------
    // C2 — the frozen request and complete scoring.
    // ------------------------------------------------------------------

    #[test]
    fn a_blank_query_or_document_is_invalid_input_with_zero_requests() {
        let server = happy_server(scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }])));
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
    fn the_post_body_is_the_frozen_six_key_payload_at_full_n() {
        let documents = vec![
            "  leading and trailing spaces stay  ".to_string(),
            "第二段：中文、标点与空格 保持原样。".to_string(),
            "third".to_string(),
        ];
        let server = happy_server(scoring_body(json!([
            { "index": 0, "relevance_score": 0.1 },
            { "index": 1, "relevance_score": 0.2 },
            { "index": 2, "relevance_score": 0.3 },
        ])));
        let backend = backend_for(&server);

        let got = backend
            .rerank("what is the capital", &documents)
            .expect("rerank");
        assert_eq!(got.scores, vec![0.1, 0.2, 0.3]);

        let posts = server.posts();
        assert_eq!(posts.len(), 1, "exactly one scoring POST");
        assert_eq!(posts[0].path, RERANK_PATH);

        let body = post_body(&server, 0);
        let object = body.as_object().expect("POST body is an object");
        assert_eq!(object.len(), 6, "the frozen payload carries exactly six keys");
        assert_eq!(object["model"], json!(RERANK_MODEL));
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
        assert_eq!(object["raw_scores"], json!(false));
    }

    #[test]
    fn documents_far_longer_than_1024_bytes_go_out_verbatim() {
        let long = format!("HEAD{}TAIL", "长".repeat(4096));
        assert!(long.len() > 1024, "fixture must exceed the old clip window");
        let documents = vec![long.clone()];

        let server = happy_server(scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }])));
        backend_for(&server)
            .rerank("q", &documents)
            .expect("rerank");

        let body = post_body(&server, 0);
        assert_eq!(
            body["documents"],
            json!(documents),
            "input longer than 1024 bytes must not be clipped"
        );
        assert_eq!(body["top_n"], json!(1));
    }

    #[test]
    fn out_of_order_results_are_returned_in_input_order() {
        let server = happy_server(scoring_body(json!([
            { "index": 2, "relevance_score": 0.9 },
            { "index": 0, "relevance_score": 0.1 },
            { "index": 1, "relevance_score": 0.5 },
        ])));
        let documents: Vec<String> = (0..3).map(|n| format!("document {n}")).collect();

        let got = backend_for(&server).rerank("q", &documents).expect("rerank");
        assert_eq!(
            got.scores,
            vec![0.1, 0.5, 0.9],
            "scores are re-ordered to the input index order, including the last item"
        );
    }

    #[test]
    fn an_incomplete_or_ill_typed_score_set_fails_the_whole_call() {
        let documents = vec!["a".to_string(), "b".to_string()];
        for results in [
            // Too few entries.
            json!([]),
            // A missing index (a gap is never filled with a default).
            json!([{ "index": 0, "relevance_score": 0.5 }]),
            // A duplicate index.
            json!([{ "index": 0, "relevance_score": 0.5 }, { "index": 0, "relevance_score": 0.6 }]),
            // An out-of-range index.
            json!([{ "index": 0, "relevance_score": 0.5 }, { "index": 2, "relevance_score": 0.6 }]),
            // A negative index.
            json!([{ "index": -1, "relevance_score": 0.5 }, { "index": 1, "relevance_score": 0.6 }]),
            // A boolean index.
            json!([{ "index": true, "relevance_score": 0.5 }, { "index": 1, "relevance_score": 0.6 }]),
            // A string index.
            json!([{ "index": "0", "relevance_score": 0.5 }, { "index": 1, "relevance_score": 0.6 }]),
            // A string score.
            json!([{ "index": 0, "relevance_score": "0.5" }, { "index": 1, "relevance_score": 0.6 }]),
            // A boolean score.
            json!([{ "index": 0, "relevance_score": 0.5 }, { "index": 1, "relevance_score": true }]),
            // A null score.
            json!([{ "index": 0, "relevance_score": null }, { "index": 1, "relevance_score": 0.6 }]),
            // A missing score key.
            json!([{ "index": 0 }, { "index": 1, "relevance_score": 0.6 }]),
            // A missing index key.
            json!([{ "relevance_score": 0.5 }, { "index": 1, "relevance_score": 0.6 }]),
            // A non-object entry.
            json!([0.5, { "index": 1, "relevance_score": 0.6 }]),
        ] {
            let server = happy_server(scoring_body(results.clone()));
            let err = backend_for(&server).rerank("q", &documents).unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "results {results}"
            );
            assert_eq!(
                server.paths().len(),
                2,
                "a refused batch is never retried or sent to another backend"
            );
        }
    }

    #[test]
    fn a_scoring_response_that_is_not_an_object_or_lacks_results_is_refused() {
        for body in [
            json!([]),
            json!([{ "index": 0, "relevance_score": 0.5 }]),
            json!("x"),
            json!(null),
            json!({ "model": RERANK_MODEL }),
            json!({ "results": {} }),
        ] {
            let server = Server::spawn(routes(
                &served_models(),
                &body,
            ));
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "body {body}"
            );
            assert_eq!(server.paths().len(), 2);
        }
    }

    #[test]
    fn a_non_2xx_rerank_answer_is_a_short_coded_http_error_without_the_body() {
        let server = Server::spawn(vec![
            (MODELS_PATH, 200, served_models().to_string().into_bytes()),
            (RERANK_PATH, 503, b"{\"error\":\"SYNTHETIC_BODY_DO_NOT_LEAK\"}".to_vec()),
        ]);
        let err = backend_for(&server)
            .rerank("q", &["d".to_string()])
            .unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::HttpError);
        assert_eq!(err.http_status, Some(503));
        assert!(!err.to_string().contains("SYNTHETIC_BODY"));
        assert_eq!(server.paths().len(), 2, "one POST, no retry");
    }

    #[test]
    fn the_fixed_query_and_documents_reach_the_service_unmodified() {
        let documents = vec![
            "  a document with surrounding whitespace  ".to_string(),
            "line one\nline two".to_string(),
        ];
        let server = happy_server(scoring_body(json!([
            { "index": 0, "relevance_score": 0.4 },
            { "index": 1, "relevance_score": 0.6 },
        ])));
        let query = "  spaced query  ";
        backend_for(&server).rerank(query, &documents).expect("rerank");

        let body = post_body(&server, 0);
        assert_eq!(body["query"], json!(query));
        assert_eq!(body["documents"], json!(documents));
    }

    #[test]
    fn the_adapter_sends_no_authorization_header() {
        let server = happy_server(scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }])));
        backend_for(&server).rerank("q", &["d".to_string()]).expect("rerank");

        assert_eq!(server.requests().len(), 2);
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

    // ------------------------------------------------------------------
    // Identity: only what the response itself proved.
    // ------------------------------------------------------------------

    #[test]
    fn an_absent_or_null_model_and_provider_are_left_null() {
        // A response that names neither must leave the identity null; it is
        // never back-filled from the request model or the `/models` list.
        for body in [
            json!({ "results": [{ "index": 0, "relevance_score": 0.5 }] }),
            json!({
                "model": null,
                "provider": null,
                "results": [{ "index": 0, "relevance_score": 0.5 }],
            }),
        ] {
            let server = happy_server(body);
            let got = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .expect("a missing identity is not a failure");
            assert_eq!(got.identity.actual_model, None);
            assert_eq!(got.identity.serving_provider, None);
            assert_eq!(got.identity.actual_provider, Some(ProviderChoice::BgeLocal));
        }
    }

    #[test]
    fn a_response_model_that_is_a_wrong_string_is_an_identity_mismatch() {
        for model in [
            json!("BAAI/bge-m3"),
            json!("some-other-reranker"),
            json!("Qwen3-Reranker-8B-local"),
        ] {
            let mut body = scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }]));
            body["model"] = model.clone();
            let server = happy_server(body);
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::ModelIdentityMismatch,
                "model {model}"
            );
        }
    }

    #[test]
    fn a_response_model_of_the_wrong_type_or_empty_is_an_invalid_response() {
        for model in [json!(""), json!(7), json!([]), json!(true), json!({})] {
            let mut body = scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }]));
            body["model"] = model.clone();
            let server = happy_server(body);
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "model {model}"
            );
        }
    }

    #[test]
    fn a_reported_serving_provider_is_recorded_verbatim_and_never_invented() {
        // Whatever the response names is recorded as-is; nothing is fabricated
        // from a request value, the model list or a hard-coded literal.
        for provider in ["Infinity", "infinity-engine", "some-synthetic-provider"] {
            let mut body = scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }]));
            body["provider"] = json!(provider);
            let server = happy_server(body);
            let got = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .expect("rerank");
            assert_eq!(got.identity.serving_provider.as_deref(), Some(provider));
        }

        // A present but unusable provider is a refusal, not a silent drop.
        for provider in [json!(""), json!(7), json!([]), json!(true)] {
            let mut body = scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }]));
            body["provider"] = provider.clone();
            let server = happy_server(body);
            let err = backend_for(&server)
                .rerank("q", &["d".to_string()])
                .unwrap_err();
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidResponse,
                "provider {provider}"
            );
        }
    }

    #[test]
    fn a_refusal_never_echoes_the_reported_model_name() {
        let mut body = scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }]));
        body["model"] = json!("SYNTHETIC-MODEL-NAME-DO-NOT-LEAK");
        let server = happy_server(body);
        let err = backend_for(&server)
            .rerank("q", &["d".to_string()])
            .unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::ModelIdentityMismatch);
        assert!(
            !err.to_string().contains("SYNTHETIC-MODEL-NAME"),
            "the reported model name leaked: {err}"
        );
    }

    // ------------------------------------------------------------------
    // The readiness probe.
    // ------------------------------------------------------------------

    #[test]
    fn probe_ready_walks_the_same_path_and_touches_no_embeddings() {
        let server = happy_server(scoring_body(json!([{ "index": 0, "relevance_score": 0.5 }])));
        let backend = backend_for(&server);

        let got = backend.probe_ready().expect("probe");
        assert_eq!(got.scores.len(), 1);
        assert!(got.scores[0].is_finite());
        assert_eq!(got.http_requests, 2);
        assert_eq!(
            as_strs(&server.paths()),
            vec![MODELS_PATH, RERANK_PATH],
            "the probe walks the same adapter path as a real call"
        );
        assert!(
            !server.paths().iter().any(|path| path.contains("embeddings")),
            "readiness must not consult the embedding endpoint"
        );

        let body = post_body(&server, 0);
        assert_eq!(body["model"], json!(RERANK_MODEL));
        assert_eq!(body["query"], json!("rerank readiness probe"));
        assert_eq!(body["documents"], json!(["rerank readiness probe"]));
        assert_eq!(body["top_n"], json!(1));
        assert_eq!(body["return_documents"], json!(false));
        assert_eq!(body["raw_scores"], json!(false));
    }
}
