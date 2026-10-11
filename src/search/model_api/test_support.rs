//! Test-only loopback fixtures for the model-service boundary.
//!
//! Every model-service test that exercises HTTP does so against a **real TCP
//! server** on an ephemeral loopback port. Nothing here returns a typed DTO in
//! place of a transport; the point of the fixtures is that the bytes really
//! travel and the request line, headers and body can be inspected afterwards.
//!
//! Two fixtures live here:
//!
//! * [`HttpFixture`] — a minimal blocking HTTP/1.1 server with a scripted reply
//!   list;
//! * `TlsFixture` (non-Windows only) — the same server behind a TLS acceptor
//!   whose chain is signed by a throwaway CA generated with the `openssl` crate
//!   that this repository already links on non-Windows targets.
//!
//! The TLS fixture exists so the "an unverifiable certificate must not fall
//! back" case is a real handshake and a real failure, not a hand-built error
//! value. The public trust store never learns about that CA: the only path that
//! trusts it is [`crate::search::rerank::http::HttpTransport::new_with_test_root`],
//! which is compiled only under `cfg(test)`.
//!
//! This file is compiled only under `cfg(test)` as a whole; the module
//! declaration in `mod.rs` carries the gate.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use url::Url;

/// How long one fixture process may live before it reclaims itself.
const FIXTURE_LIFETIME: Duration = Duration::from_secs(30);

/// What the fixture answers one connection with.
#[derive(Clone)]
pub enum Reply {
    /// A JSON body with the given status.
    Json(u16, Value),
    /// Exact response bytes, for the malformed and odd-shape cases.
    Raw(Vec<u8>),
    /// Headers that declare a body which is then never sent, so the client's
    /// read hits its own timeout.
    Stall,
}

impl Reply {
    /// `200 OK` with `body`.
    pub fn ok(body: Value) -> Self {
        Self::Json(200, body)
    }

    /// A non-success status with a synthetic error body.
    pub fn status(status: u16) -> Self {
        Self::Json(status, json!({"error": "synthetic"}))
    }

    /// Exact bytes, for a response a DTO could not express.
    pub fn raw(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Raw(bytes.into())
    }
}

/// One request the fixture actually received.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    bytes: Vec<u8>,
}

impl RecordedRequest {
    /// The request line, without its trailing CRLF.
    pub fn request_line(&self) -> String {
        let end = self
            .bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .unwrap_or(self.bytes.len());
        String::from_utf8_lossy(&self.bytes[..end]).to_string()
    }

    /// The method of the request line.
    pub fn method(&self) -> String {
        self.request_line()
            .split(' ')
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// The request target of the request line, exactly as it went on the wire.
    pub fn target(&self) -> String {
        self.request_line()
            .split(' ')
            .nth(1)
            .unwrap_or_default()
            .to_string()
    }

    /// The request body bytes.
    pub fn body_bytes(&self) -> &[u8] {
        match find(&self.bytes, b"\r\n\r\n") {
            Some(head_end) => &self.bytes[head_end + 4..],
            None => &[],
        }
    }

    /// The request body parsed as JSON.
    pub fn body(&self) -> Value {
        serde_json::from_slice(self.body_bytes()).expect("fixture request body is JSON")
    }

    /// The request body decoded as UTF-8 text.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(self.body_bytes()).to_string()
    }

    /// One header value, case-insensitively.
    pub fn header(&self, name: &str) -> Option<String> {
        let head_end = find(&self.bytes, b"\r\n\r\n").unwrap_or(self.bytes.len());
        let head = String::from_utf8_lossy(&self.bytes[..head_end]);
        let wanted = format!("{}:", name.to_ascii_lowercase());
        head.lines().find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix(&wanted)
                .map(|rest| rest.trim().to_string())
        })
    }
}

/// A loopback HTTP/1.1 fixture with a scripted reply list.
pub struct HttpFixture {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HttpFixture {
    /// Start a fixture that answers with `replies` in order.
    ///
    /// The last reply repeats once the list is exhausted, so a fixture that
    /// takes several requests needs only one entry.
    pub fn start(mut replies: Vec<Reply>) -> Self {
        if replies.is_empty() {
            replies.push(Reply::ok(json!({})));
        }
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind fixture port");
        let addr = listener.local_addr().expect("fixture local_addr");
        listener.set_nonblocking(true).expect("fixture nonblocking");

        let hits = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (hits, requests, stop) = (hits.clone(), requests.clone(), stop.clone());
            let state = Arc::new(FixtureState {
                replies,
                next: Mutex::new(0),
            });
            thread::spawn(move || run_accept_loop(listener, None, state, hits, requests, stop))
        };

        Self {
            addr,
            hits,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    /// A fixture answering `200 OK` with an empty JSON object.
    pub fn ok() -> Self {
        Self::start(vec![Reply::ok(json!({}))])
    }

    /// A fixture with no server at all: the address is bound and then released,
    /// so a connection to it is refused.
    pub fn refused_address() -> SocketAddr {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind probe port");
        let addr = listener.local_addr().expect("probe local_addr");
        drop(listener);
        addr
    }

    /// The bound address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The `http://host:port` base origin.
    pub fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// An absolute URL on this fixture, used for endpoint and target tests.
    pub fn url(&self, path_and_more: &str) -> Url {
        Url::parse(&format!("{}{}", self.base(), path_and_more)).expect("fixture url")
    }

    /// How many connections the fixture accepted.
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// Every request the fixture read.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests
            .lock()
            .expect("fixture request log")
            .iter()
            .cloned()
            .map(|bytes| RecordedRequest { bytes })
            .collect()
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The scripted reply list shared with the accept loop.
struct FixtureState {
    replies: Vec<Reply>,
    next: Mutex<usize>,
}

impl FixtureState {
    fn take(&self) -> Reply {
        let mut next = self.next.lock().expect("fixture reply index");
        let index = (*next).min(self.replies.len().saturating_sub(1));
        *next += 1;
        self.replies[index].clone()
    }
}

/// Accept connections until the fixture is dropped or its lifetime expires.
#[cfg(not(windows))]
fn run_accept_loop(
    listener: TcpListener,
    acceptor: Option<Arc<openssl::ssl::SslAcceptor>>,
    state: Arc<FixtureState>,
    hits: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
) {
    let deadline = Instant::now() + FIXTURE_LIFETIME;
    while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                hits.fetch_add(1, Ordering::SeqCst);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let reply = state.take();
                match &acceptor {
                    Some(acceptor) => {
                        if let Ok(mut tls) = acceptor.accept(stream) {
                            serve(&mut tls, &reply, &requests, &stop, deadline);
                        }
                    }
                    None => {
                        let mut plain = stream;
                        serve(&mut plain, &reply, &requests, &stop, deadline);
                    }
                }
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
}

/// Accept connections on a platform without the OpenSSL-backed TLS fixture.
#[cfg(windows)]
fn run_accept_loop(
    listener: TcpListener,
    _acceptor: Option<()>,
    state: Arc<FixtureState>,
    hits: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
) {
    let deadline = Instant::now() + FIXTURE_LIFETIME;
    while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                hits.fetch_add(1, Ordering::SeqCst);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let reply = state.take();
                serve(&mut stream, &reply, &requests, &stop, deadline);
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
}

/// Read one request, record it, and answer with `reply`.
fn serve<S: Read + Write>(
    stream: &mut S,
    reply: &Reply,
    requests: &Mutex<Vec<Vec<u8>>>,
    stop: &AtomicBool,
    deadline: Instant,
) {
    let request = read_request(stream);
    requests.lock().expect("fixture request log").push(request);
    match reply {
        Reply::Json(status, body) => {
            let body = serde_json::to_vec(body).expect("fixture json");
            let _ = stream.write_all(&response_bytes(*status, &body, Some(body.len())));
            let _ = stream.flush();
        }
        Reply::Raw(bytes) => {
            let _ = stream.write_all(bytes);
            let _ = stream.flush();
        }
        Reply::Stall => {
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000000\r\nConnection: keep-alive\r\n\r\n",
            );
            let _ = stream.flush();
            while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
    let _ = stream.flush();
}

/// Read one request: headers up to CRLFCRLF, then the declared body.
fn read_request<S: Read>(stream: &mut S) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut head_end: Option<usize> = None;
    let mut body_len = 0usize;
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                buffer.extend_from_slice(&chunk[..read]);
                if head_end.is_none() {
                    if let Some(position) = find(&buffer, b"\r\n\r\n") {
                        head_end = Some(position + 4);
                        body_len = content_length(&buffer[..position]);
                    }
                }
                if let Some(end) = head_end {
                    if buffer.len() >= end + body_len {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    buffer
}

/// One HTTP/1.1 response with an explicit `Content-Length`.
fn response_bytes(status: u16, body: &[u8], content_length: Option<usize>) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    };
    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nConnection: close\r\n"
        )
        .as_bytes(),
    );
    if let Some(length) = content_length {
        out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// The `Content-Length` of a header block, or zero.
fn content_length(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n") {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// The position of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A loopback HTTPS fixture whose chain is signed by a throwaway CA.
///
/// Non-Windows only: it is built on the `openssl` crate this repository already
/// links there for other reasons, and the spec's cleanup ticket removes no
/// dependency this fixture needs.
#[cfg(not(windows))]
pub struct TlsFixture {
    inner: HttpFixture,
    ca_pem: Vec<u8>,
}

#[cfg(not(windows))]
impl TlsFixture {
    /// Start a TLS fixture answering `replies` in order.
    pub fn start(replies: Vec<Reply>) -> Self {
        use openssl::ssl::{SslAcceptor, SslMethod};

        let (ca, ca_key) = generate_ca();
        let (leaf, leaf_key) = generate_leaf(&ca, &ca_key, "localhost");

        let mut acceptor =
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("tls acceptor");
        acceptor
            .set_private_key(&leaf_key)
            .expect("fixture private key");
        acceptor
            .set_certificate(&leaf)
            .expect("fixture certificate");
        acceptor
            .add_extra_chain_cert(ca.clone())
            .expect("fixture chain");
        // Advertise only HTTP/1.1: the rustls client offers h2 first, and the
        // fixture speaks HTTP/1.1. `set_alpn_select_callback` comes from
        // `SslContextBuilder` through `DerefMut`.
        acceptor.set_alpn_select_callback(|_, client| {
            openssl::ssl::select_next_proto(b"\x08http/1.1", client)
                .ok_or(openssl::ssl::AlpnError::NOACK)
        });
        let acceptor = Arc::new(acceptor.build());

        let ca_pem = ca.to_pem().expect("ca pem");

        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind fixture port");
        let addr = listener.local_addr().expect("fixture local_addr");
        listener.set_nonblocking(true).expect("fixture nonblocking");

        let hits = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let inner = {
            let (thread_hits, thread_requests, thread_stop) =
                (hits.clone(), requests.clone(), stop.clone());
            let state = Arc::new(FixtureState {
                replies,
                next: Mutex::new(0),
            });
            let thread = thread::spawn(move || {
                run_accept_loop(
                    listener,
                    Some(acceptor),
                    state,
                    thread_hits,
                    thread_requests,
                    thread_stop,
                )
            });
            HttpFixture {
                addr,
                hits,
                requests,
                stop,
                thread: Some(thread),
            }
        };
        Self { inner, ca_pem }
    }

    /// The throwaway CA, PEM-encoded, for the test-only trusting constructor.
    pub fn ca_pem(&self) -> &[u8] {
        &self.ca_pem
    }

    /// The underlying fixture, for the bound port and the request log.
    pub fn fixture(&self) -> &HttpFixture {
        &self.inner
    }

    /// The `https://localhost:port` base origin.
    pub fn base(&self) -> String {
        format!("https://localhost:{}", self.inner.addr().port())
    }

    /// An absolute `https://localhost:port` URL on this fixture.
    pub fn url(&self, path: &str) -> Url {
        Url::parse(&format!("{}{}", self.base(), path)).expect("tls fixture url")
    }
}

/// Generate a throwaway CA certificate and its key.
#[cfg(not(windows))]
fn generate_ca() -> (
    openssl::x509::X509,
    openssl::pkey::PKey<openssl::pkey::Private>,
) {
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509, X509NameBuilder};

    let key = PKey::from_rsa(Rsa::generate(2048).expect("ca rsa")).expect("ca key");
    let mut name = X509NameBuilder::new().expect("ca name");
    name.append_entry_by_text("CN", "cass-api01b-test-ca")
        .expect("ca cn");
    let name = name.build();

    let mut builder = X509::builder().expect("ca builder");
    builder.set_version(2).expect("ca version");
    let mut serial = BigNum::new().expect("ca serial");
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .expect("ca serial rand");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("ca serial asn1"))
        .expect("ca serial set");
    builder.set_subject_name(&name).expect("ca subject");
    builder.set_issuer_name(&name).expect("ca issuer");
    builder.set_pubkey(&key).expect("ca pubkey");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("ca not before"))
        .expect("ca not before set");
    builder
        .set_not_after(&Asn1Time::days_from_now(2).expect("ca not after"))
        .expect("ca not after set");
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .expect("ca basic constraints"),
        )
        .expect("ca basic constraints set");
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .expect("ca key usage"),
        )
        .expect("ca key usage set");
    builder
        .sign(&key, MessageDigest::sha256())
        .expect("ca sign");
    (builder.build(), key)
}

/// Generate a `localhost` server certificate signed by the throwaway CA.
#[cfg(not(windows))]
fn generate_leaf(
    ca: &openssl::x509::X509,
    ca_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    host: &str,
) -> (
    openssl::x509::X509,
    openssl::pkey::PKey<openssl::pkey::Private>,
) {
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    };
    use openssl::x509::{X509, X509NameBuilder};

    let key = PKey::from_rsa(Rsa::generate(2048).expect("leaf rsa")).expect("leaf key");
    let mut name = X509NameBuilder::new().expect("leaf name");
    name.append_entry_by_text("CN", host).expect("leaf cn");
    let name = name.build();

    let mut builder = X509::builder().expect("leaf builder");
    builder.set_version(2).expect("leaf version");
    let mut serial = BigNum::new().expect("leaf serial");
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .expect("leaf serial rand");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("leaf serial asn1"))
        .expect("leaf serial set");
    builder.set_subject_name(&name).expect("leaf subject");
    builder
        .set_issuer_name(ca.subject_name())
        .expect("leaf issuer");
    builder.set_pubkey(&key).expect("leaf pubkey");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("leaf not before"))
        .expect("leaf not before set");
    builder
        .set_not_after(&Asn1Time::days_from_now(2).expect("leaf not after"))
        .expect("leaf not after set");
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .build()
                .expect("leaf basic constraints"),
        )
        .expect("leaf basic constraints set");
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()
                .expect("leaf key usage"),
        )
        .expect("leaf key usage set");
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .server_auth()
                .build()
                .expect("leaf eku"),
        )
        .expect("leaf eku set");
    let san = SubjectAlternativeName::new()
        .dns(host)
        .build(&builder.x509v3_context(Some(ca), None))
        .expect("leaf san");
    builder.append_extension(san).expect("leaf san set");
    builder
        .sign(ca_key, MessageDigest::sha256())
        .expect("leaf sign");
    (builder.build(), key)
}
