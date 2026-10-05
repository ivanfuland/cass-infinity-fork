//! Shared HTTP transport for the rerank backends.
//!
//! P02 provides the single blocking transport every rerank adapter uses. This
//! file is written test-first: the `#[cfg(test)]` module below is the fixed
//! execution contract, and the production items it exercises
//! (`HttpConfig`, `HttpTransport`, `HttpJson`) are added by the implementation
//! step of the same ticket. Until then the test build is the RED state.

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use serde_json::json;

    /// A bearer token that is obviously synthetic and must never surface.
    const FAKE_BEARER: &str = "sk-or-v1-SYNTHETIC-NOT-A-REAL-KEY-0000";
    /// A response-body marker that must never surface in an error or a log.
    const FAKE_SECRET: &str = "SYNTHETIC_SECRET_DO_NOT_LEAK";
    /// A token carrying an illegal header byte, used to prove the failure code
    /// does not echo the value back.
    const ILLEGAL_TOKEN: &str = "sk-\u{7f}-THIS-MUST-NOT-APPEAR";

    // ------------------------------------------------------------------
    // A tiny blocking HTTP/1.1 fixture. Every instance binds an ephemeral
    // port, records the bytes it received, and reclaims its own thread and
    // socket on drop. No process-wide state is touched.
    // ------------------------------------------------------------------

    #[derive(Clone)]
    enum Behavior {
        /// Answer every connection with these exact response bytes.
        Fixed(Vec<u8>),
        /// Write these bytes, then hold the connection open without ever
        /// sending the declared body, forcing a client-side read timeout.
        Stall { head: Vec<u8> },
    }

    struct Server {
        addr: SocketAddr,
        hits: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl Server {
        fn spawn(ip: IpAddr, behavior: Behavior) -> Server {
            let listener = TcpListener::bind(SocketAddr::new(ip, 0)).expect("bind fixture port");
            let addr = listener.local_addr().expect("fixture local_addr");
            listener
                .set_nonblocking(true)
                .expect("fixture nonblocking");
            let hits = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (h, r, s) = (hits.clone(), requests.clone(), stop.clone());
            let thread = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(20);
                while !s.load(Ordering::SeqCst) && Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            h.fetch_add(1, Ordering::SeqCst);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                            let request = read_request(&mut stream);
                            r.lock().unwrap().push(request);
                            match &behavior {
                                Behavior::Fixed(bytes) => {
                                    let _ = stream.write_all(bytes);
                                    let _ = stream.flush();
                                }
                                Behavior::Stall { head } => {
                                    let _ = stream.write_all(head);
                                    let _ = stream.flush();
                                    while !s.load(Ordering::SeqCst) && Instant::now() < deadline {
                                        thread::sleep(Duration::from_millis(10));
                                    }
                                }
                            }
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Server {
                addr,
                hits,
                requests,
                stop,
                thread: Some(thread),
            }
        }

        fn ipv4(behavior: Behavior) -> Server {
            Server::spawn(IpAddr::V4(Ipv4Addr::LOCALHOST), behavior)
        }

        fn ipv6(behavior: Behavior) -> Server {
            Server::spawn(IpAddr::V6(Ipv6Addr::LOCALHOST), behavior)
        }

        fn base(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }

        fn requests(&self) -> Vec<Vec<u8>> {
            self.requests.lock().unwrap().clone()
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
                    if header_end.is_none() {
                        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                            body_len = content_length_of_head(&buf[..pos]);
                        }
                    }
                    if let Some(end) = header_end {
                        if buf.len() >= end + body_len {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        buf
    }

    fn response_with(status_line: &str, body: &[u8], content_length: Option<usize>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(
            format!("HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nConnection: close\r\n")
                .as_bytes(),
        );
        if let Some(n) = content_length {
            out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(body);
        out
    }

    fn ok_json(body: &str) -> Vec<u8> {
        response_with("200 OK", body.as_bytes(), Some(body.len()))
    }

    fn config(base: &str, local_only: bool) -> HttpConfig {
        HttpConfig {
            base_url: base.to_string(),
            local_only,
            timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            max_response_bytes: 64 * 1024 * 1024,
        }
    }

    fn config_limits(
        base: &str,
        local_only: bool,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> HttpConfig {
        HttpConfig {
            base_url: base.to_string(),
            local_only,
            timeout,
            connect_timeout: Duration::from_secs(5),
            max_response_bytes,
        }
    }

    fn transport(base: &str, local_only: bool) -> HttpTransport {
        HttpTransport::new(config(base, local_only), None).expect("transport")
    }

    // ------------------------------------------------------------------
    // C1 — downstream consumption: real request/response over loopback.
    // ------------------------------------------------------------------

    #[test]
    fn get_json_reads_status_and_body() {
        let server = Server::ipv4(Behavior::Fixed(ok_json("{\"ok\":true}")));
        let t = transport(&server.base(), true);
        let got = t.get_json("/probe").expect("get_json");
        assert_eq!(got.status, 200);
        assert_eq!(got.body, json!({"ok": true}));
        assert_eq!(server.hits(), 1);
    }

    #[test]
    fn post_json_sends_the_exact_body() {
        let server = Server::ipv4(Behavior::Fixed(ok_json("{\"scored\":1}")));
        let t = transport(&server.base(), true);
        let payload = json!({"model": "m", "query": "q", "documents": ["a", "b"]});
        let got = t.post_json("/rerank", &payload).expect("post_json");
        assert_eq!(got.status, 200);
        assert_eq!(server.hits(), 1);
        let recorded = &server.requests()[0];
        let text = String::from_utf8_lossy(recorded);
        assert!(text.starts_with("POST /rerank "), "method/path: {text}");
        let head_end = find_subsequence(recorded, b"\r\n\r\n").expect("headers") + 4;
        let sent: serde_json::Value =
            serde_json::from_slice(&recorded[head_end..]).expect("request body is JSON");
        assert_eq!(sent, payload);
    }

    #[test]
    fn ipv4_loopback_is_accepted() {
        let server = Server::ipv4(Behavior::Fixed(ok_json("{\"v\":4}")));
        let t = transport(&server.base(), true);
        assert_eq!(t.get_json("/").unwrap().status, 200);
    }

    #[test]
    fn ipv6_loopback_is_accepted() {
        let server = Server::ipv6(Behavior::Fixed(ok_json("{\"v\":6}")));
        let t = transport(&server.base(), true);
        assert_eq!(t.get_json("/").unwrap().status, 200);
    }

    #[test]
    fn localhost_name_is_accepted() {
        let server = Server::ipv4(Behavior::Fixed(ok_json("{\"v\":\"localhost\"}")));
        let base = format!("http://localhost:{}", server.addr.port());
        let t = transport(&base, true);
        assert_eq!(t.get_json("/").unwrap().status, 200);
        assert_eq!(server.hits(), 1);
    }

    #[test]
    fn request_without_bearer_carries_no_authorization_header() {
        let server = Server::ipv4(Behavior::Fixed(ok_json("{\"ok\":true}")));
        let t = transport(&server.base(), true);
        t.get_json("/probe").unwrap();
        let text = String::from_utf8_lossy(&server.requests()[0]).to_ascii_lowercase();
        assert!(!text.contains("authorization:"), "unexpected header: {text}");
    }

    #[test]
    fn request_with_bearer_sends_it_and_never_leaks_on_error() {
        let server = Server::ipv4(Behavior::Fixed(ok_json("{\"ok\":true}")));
        let t = HttpTransport::new(config(&server.base(), true), Some(FAKE_BEARER.to_string()))
            .expect("transport");
        t.get_json("/probe").unwrap();
        let text = String::from_utf8_lossy(&server.requests()[0]).to_ascii_lowercase();
        assert!(
            text.contains(&format!("authorization: bearer {}", FAKE_BEARER.to_ascii_lowercase())),
            "missing bearer header: {text}"
        );

        // A non-2xx with the same transport must not surface the token.
        let err_server = Server::ipv4(Behavior::Fixed(response_with(
            "500 Internal Server Error",
            FAKE_SECRET.as_bytes(),
            Some(FAKE_SECRET.len()),
        )));
        let et = HttpTransport::new(config(&err_server.base(), true), Some(FAKE_BEARER.to_string()))
            .expect("transport");
        let err = et.get_json("/probe").unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::HttpError);
        assert_eq!(err.http_status, Some(500));
        let msg = format!("{err}");
        assert!(!msg.contains(FAKE_SECRET), "body leaked: {msg}");
        assert!(!msg.contains(FAKE_BEARER), "token leaked: {msg}");
    }

    #[test]
    fn illegal_bearer_is_short_coded_without_echoing_the_value() {
        let err = HttpTransport::new(
            config("http://127.0.0.1:9", true),
            Some(ILLEGAL_TOKEN.to_string()),
        )
        .unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InvalidInput);
        let msg = format!("{err}");
        assert!(!msg.contains("THIS-MUST-NOT-APPEAR"), "value leaked: {msg}");
    }

    // ------------------------------------------------------------------
    // C2 — safety and failure boundaries.
    // ------------------------------------------------------------------

    #[test]
    fn local_only_refuses_non_loopback_literal() {
        // 192.0.2.0/24 is TEST-NET-1: never routable to a real service.
        let err = HttpTransport::new(config("http://192.0.2.1:8080", true), None).unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::NonLoopbackEndpoint);
    }

    #[test]
    fn local_only_refuses_lookalike_loopback_domain() {
        let err =
            HttpTransport::new(config("http://127.0.0.1.evil.example:8080", true), None)
                .unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::NonLoopbackEndpoint);
        let err2 =
            HttpTransport::new(config("http://notlocalhost:8080", true), None).unwrap_err();
        assert_eq!(err2.reason, RerankFailureReason::NonLoopbackEndpoint);
    }

    #[test]
    fn base_url_with_userinfo_is_refused() {
        for base in [
            "http://user:pass@127.0.0.1:8080",
            "http://user@127.0.0.1:8080",
            // Empty-username form: the URL parser drops it, so it must be
            // caught on the raw text.
            "http://@127.0.0.1:8080",
        ] {
            let err = HttpTransport::new(config(base, false), None).unwrap_err();
            assert_eq!(err.reason, RerankFailureReason::InvalidInput, "base {base}");
        }
    }

    #[test]
    fn base_url_must_be_a_bare_origin() {
        for base in [
            "http://127.0.0.1:8080/a/path",
            "http://127.0.0.1:8080/?x=1",
            "http://127.0.0.1:8080/#frag",
            "ftp://127.0.0.1:8080",
            "not a url",
        ] {
            let err = HttpTransport::new(config(base, false), None).unwrap_err();
            assert_eq!(err.reason, RerankFailureReason::InvalidInput, "base {base}");
        }
    }

    #[test]
    fn zero_and_overflow_budgets_are_refused() {
        let base = "http://127.0.0.1:9";

        let mut c = config(base, true);
        c.timeout = Duration::ZERO;
        assert_eq!(
            HttpTransport::new(c, None).unwrap_err().reason,
            RerankFailureReason::InvalidInput
        );

        let mut c = config(base, true);
        c.connect_timeout = Duration::ZERO;
        assert_eq!(
            HttpTransport::new(c, None).unwrap_err().reason,
            RerankFailureReason::InvalidInput
        );

        let mut c = config(base, true);
        c.max_response_bytes = 0;
        assert_eq!(
            HttpTransport::new(c, None).unwrap_err().reason,
            RerankFailureReason::InvalidInput
        );

        let mut c = config(base, true);
        c.max_response_bytes = usize::MAX;
        assert_eq!(
            HttpTransport::new(c, None).unwrap_err().reason,
            RerankFailureReason::InvalidInput
        );
    }

    #[test]
    fn request_path_must_be_a_rooted_same_origin_path() {
        let server = Server::ipv4(Behavior::Fixed(ok_json("{}")));
        let t = transport(&server.base(), true);
        for path in [
            "",
            "no-slash",
            "//evil.example/x",
            "/has\\backslash",
            "/tab\there",
            "/newline\nhere",
            "/frag#ment",
        ] {
            let err = t.get_json(path).unwrap_err();
            assert_eq!(err.reason, RerankFailureReason::InvalidInput, "path {path:?}");
        }
        assert_eq!(server.hits(), 0, "no request may be sent for a bad path");
    }

    #[test]
    fn same_origin_query_is_allowed() {
        let server = Server::ipv4(Behavior::Fixed(ok_json("{}")));
        let t = transport(&server.base(), true);
        assert_eq!(t.get_json("/v1/models?verbose=1").unwrap().status, 200);
        assert_eq!(server.hits(), 1);
    }

    #[test]
    fn redirect_is_not_followed() {
        let second = Server::ipv4(Behavior::Fixed(ok_json("{\"reached\":true}")));
        let location = format!("http://{}/", second.addr);
        let body = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let first = Server::ipv4(Behavior::Fixed(body.into_bytes()));
        let t = transport(&first.base(), true);
        let err = t.get_json("/").unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::HttpError);
        assert_eq!(err.http_status, Some(302));
        assert_eq!(first.hits(), 1);
        assert_eq!(second.hits(), 0, "the redirect target must not be contacted");
    }

    #[test]
    fn oversized_body_with_content_length_is_refused() {
        let big = vec![b'a'; 200];
        let server = Server::ipv4(Behavior::Fixed(response_with("200 OK", &big, Some(big.len()))));
        let t = HttpTransport::new(config_limits(&server.base(), true, Duration::from_secs(5), 64), None)
            .expect("transport");
        let err = t.get_json("/").unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InvalidResponse);
    }

    #[test]
    fn oversized_body_without_content_length_is_refused() {
        let big = vec![b'a'; 200];
        let server = Server::ipv4(Behavior::Fixed(response_with("200 OK", &big, None)));
        let t = HttpTransport::new(config_limits(&server.base(), true, Duration::from_secs(5), 64), None)
            .expect("transport");
        let err = t.get_json("/").unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InvalidResponse);
    }

    #[test]
    fn malformed_json_is_refused() {
        let server = Server::ipv4(Behavior::Fixed(ok_json("{\"a\":")));
        let t = transport(&server.base(), true);
        assert_eq!(
            t.get_json("/").unwrap_err().reason,
            RerankFailureReason::InvalidResponse
        );
    }

    #[test]
    fn non_utf8_body_is_refused() {
        let server = Server::ipv4(Behavior::Fixed(response_with("200 OK", &[0x66, 0x6f, 0x80], Some(3))));
        let t = transport(&server.base(), true);
        assert_eq!(
            t.get_json("/").unwrap_err().reason,
            RerankFailureReason::InvalidResponse
        );
    }

    #[test]
    fn non_2xx_body_is_not_echoed() {
        let server = Server::ipv4(Behavior::Fixed(response_with(
            "500 Internal Server Error",
            FAKE_SECRET.as_bytes(),
            Some(FAKE_SECRET.len()),
        )));
        let t = transport(&server.base(), true);
        let err = t.get_json("/").unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::HttpError);
        assert_eq!(err.http_status, Some(500));
        assert!(!format!("{err}").contains(FAKE_SECRET));
        assert_eq!(server.hits(), 1, "a failed receive is attempted at most once");
    }

    #[test]
    fn stalled_read_fails_with_timeout_short_code() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nConnection: keep-alive\r\n\r\n".to_vec();
        let server = Server::ipv4(Behavior::Stall { head });
        let t = HttpTransport::new(
            config_limits(&server.base(), true, Duration::from_millis(200), 64 * 1024 * 1024),
            None,
        )
        .expect("transport");
        let start = Instant::now();
        let err = t.get_json("/").unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::Timeout);
        assert!(start.elapsed() < Duration::from_secs(15), "timeout must fire promptly");
        assert_eq!(server.hits(), 1);
    }

    // ------------------------------------------------------------------
    // Environment-proxy boundary: injected into a child process so the shared
    // parent test process environment is never mutated.
    // ------------------------------------------------------------------

    #[test]
    fn proxy_env_child_fixture() {
        let Ok(base) = std::env::var("P02_PROXY_CHILD_BASE") else {
            return; // no-op during an ordinary suite run
        };
        let t = HttpTransport::new(config(&base, true), None).expect("child transport");
        let got = t.get_json("/probe").expect("child request");
        assert_eq!(got.status, 200);
    }

    #[test]
    fn proxy_environment_is_ignored() {
        let target = Server::ipv4(Behavior::Fixed(ok_json("{\"ok\":true}")));
        let proxy = Server::ipv4(Behavior::Fixed(ok_json("{\"proxy\":true}")));
        let proxy_url = format!("http://{}", proxy.addr);
        let exe = std::env::current_exe().expect("current_exe");
        let status = std::process::Command::new(exe)
            .arg("--exact")
            .arg("search::rerank::http::tests::proxy_env_child_fixture")
            .arg("--nocapture")
            .env("P02_PROXY_CHILD_BASE", target.base())
            .env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("https_proxy", &proxy_url)
            .env("all_proxy", &proxy_url)
            .status()
            .expect("spawn child test process");
        assert!(status.success(), "child process failed: {status:?}");
        assert!(
            target.hits() >= 1,
            "the real target must have served the request"
        );
        assert_eq!(proxy.hits(), 0, "no request may reach the configured proxy");
    }
}
