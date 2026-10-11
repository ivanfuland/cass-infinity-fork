//! Shared HTTP transport for the rerank backends.
//!
//! P02 provides the single blocking transport every rerank adapter uses. It is
//! deliberately narrow and failure-typed:
//!
//! - [`HttpConfig`] fixes the three budgets (total wait, connect wait, response
//!   size) plus the `local_only` safety switch. All three budgets must be
//!   positive and `max_response_bytes + 1` must not overflow.
//! - [`HttpTransport::new`] validates the base URL into a bare `http`/`https`
//!   origin, refuses userinfo (including the empty-username form the URL parser
//!   would otherwise normalize away), and refuses a non-loopback target when
//!   `local_only` is set. It builds a client with environment proxies disabled,
//!   redirects disabled, retries disabled and TLS verification left on.
//! - [`HttpTransport::get_json`] and [`HttpTransport::post_json`] send exactly
//!   one request. A non-2xx status yields [`RerankFailureReason::HttpError`]
//!   with the status and without reading the body; a 2xx reads at most
//!   `max_response_bytes + 1` bytes and refuses anything larger, malformed or
//!   non-UTF-8 as [`RerankFailureReason::InvalidResponse`]. A timeout is
//!   [`RerankFailureReason::Timeout`]; every other transport problem is
//!   [`RerankFailureReason::TransportError`].
//!
//! Neither the bearer token nor any response body, query or document text can
//! reach an error value or a log line: [`RerankError`] carries only a short code
//! and an optional status, and this module emits no tracing.
//!
//! # Two entry points, one transport
//!
//! [`HttpTransport::get_json`] and [`HttpTransport::post_json`] take a rooted
//! request path and join it onto the base origin. The API-only model client
//! instead holds a *complete* endpoint URL whose path the operator wrote, so it
//! uses [`HttpTransport::get_json_target`] and
//! [`HttpTransport::post_json_target`]: those take an absolute [`Url`], require
//! it to be the same origin as the base, and send it exactly as parsed. Joining
//! a configured path instead would reinterpret a leading `//` as a new
//! authority and could send the body to a different host.
//!
//! The target entry points return [`TransportError`]: the in-memory
//! [`TransportFailure`] the model client needs to decide whether one cloud
//! attempt is allowed, together with the HTTP status the attempt actually
//! observed. The path-based entry points keep returning [`RerankError`] and map
//! every failure back onto the existing short codes, so the retired adapters
//! are unaffected.

use std::error::Error as StdError;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_json::Value;
use url::{Host, Url};

use super::types::{RerankError, RerankFailureReason};

/// Validated configuration for one [`HttpTransport`].
///
/// This carries no credential, so it may derive `Debug`.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// The backend origin: `http`/`https` scheme, host, optional port, and no
    /// userinfo, query, fragment or non-root path.
    pub base_url: String,
    /// When true, the target must resolve to a loopback address before any
    /// request body is sent. Only the `localhost` DNS name is allowed.
    pub local_only: bool,
    /// Total per-request wait budget, covering connect and response body read.
    pub timeout: Duration,
    /// Connect wait budget. Must be positive.
    pub connect_timeout: Duration,
    /// Maximum number of response bytes accepted from a 2xx body.
    pub max_response_bytes: usize,
}

/// A decoded JSON response: the HTTP status and the parsed body.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpJson {
    pub status: u16,
    pub body: Value,
}

/// The detail of one failed transport attempt, kept in memory only.
///
/// This is the classification the automatic cloud fallback reads. It is
/// deliberately finer than [`RerankFailureReason`]: the routing contract only
/// allows a second attempt for a connection refusal, an unreachable network, an
/// interrupted connection, a connect or read timeout, and six HTTP statuses.
/// Everything that cannot be attributed to one of those is
/// [`Self::UnclassifiedTransport`], which the routing contract treats as "no
/// fallback" rather than guessing.
///
/// The classification is drawn from typed error data only — a
/// [`std::io::ErrorKind`] found by walking the `source` chain, or
/// `reqwest::Error::is_timeout` — never from an error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailure {
    /// A connect or read wait exceeded its budget.
    Timeout,
    /// No connection could be established because the peer refused it.
    ConnectionRefused,
    /// An established connection broke or closed unexpectedly.
    ConnectionInterrupted,
    /// The network or the target host is not reachable.
    NetworkUnavailable,
    /// The service answered with a non-success HTTP status.
    HttpStatus(u16),
    /// The request was refused by our own validation before it was sent.
    InvalidInput,
    /// The response was unreadable, malformed, oversized or non-UTF-8.
    InvalidResponse,
    /// A transport problem this build cannot classify reliably.
    UnclassifiedTransport,
}

impl TransportFailure {
    /// The stable short code recorded on an attempt.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::ConnectionRefused => "connection_refused",
            Self::ConnectionInterrupted => "connection_interrupted",
            Self::NetworkUnavailable => "network_unavailable",
            Self::HttpStatus(_) => "http_status",
            Self::InvalidInput => "invalid_input",
            Self::InvalidResponse => "invalid_response",
            Self::UnclassifiedTransport => "unclassified_transport",
        }
    }

    /// The HTTP status this failure observed, when it observed one.
    pub const fn http_status(self) -> Option<u16> {
        match self {
            Self::HttpStatus(status) => Some(status),
            _ => None,
        }
    }

    /// Whether the request reached the service far enough to get a status.
    pub const fn network_attempted(self) -> bool {
        !matches!(self, Self::InvalidInput)
    }

    /// Map onto the short failure codes the retired adapters already use.
    pub fn to_rerank_error(self) -> RerankError {
        match self {
            Self::Timeout => RerankError::new(RerankFailureReason::Timeout),
            Self::HttpStatus(status) => {
                RerankError::with_status(RerankFailureReason::HttpError, status)
            }
            Self::InvalidInput => RerankError::new(RerankFailureReason::InvalidInput),
            Self::InvalidResponse => RerankError::new(RerankFailureReason::InvalidResponse),
            Self::ConnectionRefused
            | Self::ConnectionInterrupted
            | Self::NetworkUnavailable
            | Self::UnclassifiedTransport => RerankError::new(RerankFailureReason::TransportError),
        }
    }
}

/// A failed transport attempt: its routing classification plus the HTTP status
/// the attempt actually observed, when it observed one.
///
/// The two travel together on purpose. A read that times out after a `200`
/// answer is a timeout for routing purposes but the service did answer, and a
/// malformed body after a `200` is an invalid response — never a fallback
/// trigger — while the status stays on the record so the failure is not
/// misreported as "the service was never reached".
///
/// The classification alone decides fallback eligibility; the observed status
/// is evidence, not routing input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportError {
    failure: TransportFailure,
    http_status: Option<u16>,
}

impl TransportError {
    /// A failure with the status the attempt observed, if any.
    pub const fn new(failure: TransportFailure, http_status: Option<u16>) -> Self {
        Self {
            failure,
            http_status,
        }
    }

    /// The routing classification.
    pub const fn failure(self) -> TransportFailure {
        self.failure
    }

    /// The observed HTTP status, when a response was actually read.
    pub const fn http_status(self) -> Option<u16> {
        self.http_status
    }

    /// Map onto the short failure codes the retired adapters already use.
    ///
    /// The mapping is exactly [`TransportFailure::to_rerank_error`], so the
    /// path-based entry points keep the byte-for-byte behaviour they had before
    /// the status field existed.
    pub fn to_rerank_error(self) -> RerankError {
        self.failure.to_rerank_error()
    }
}

/// The shared blocking HTTP transport.
///
/// The struct holds the bearer token, so it deliberately implements neither
/// `Debug` nor `Serialize`.
pub struct HttpTransport {
    base: Url,
    client: reqwest::blocking::Client,
    auth: Option<HeaderValue>,
    max_response_bytes: usize,
    trace: Option<std::sync::Arc<std::sync::Mutex<crate::search::regression_trace::RequestTrace>>>,
}

impl HttpTransport {
    /// Validate `config`, prepare the credential header and build the client.
    ///
    /// A non-positive budget, an overflowing size budget, a malformed or
    /// non-origin base URL, or an illegal bearer token is
    /// [`RerankFailureReason::InvalidInput`]. A `local_only` origin that does
    /// not resolve to loopback is [`RerankFailureReason::NonLoopbackEndpoint`];
    /// it is refused here, before any request exists.
    pub fn new(config: HttpConfig, bearer: Option<String>) -> Result<Self, RerankError> {
        Self::build(config, bearer, None)
    }

    /// Build the transport, optionally trusting one extra PEM-encoded root.
    ///
    /// `extra_root` is `None` on every production path: the only caller that
    /// passes one is the test-only constructor below, which exists so a
    /// loopback TLS fixture can be connected to for real. There is no runtime
    /// switch anywhere that disables verification or adds an operator-supplied
    /// CA.
    fn build(
        config: HttpConfig,
        bearer: Option<String>,
        extra_root: Option<&[u8]>,
    ) -> Result<Self, RerankError> {
        if config.timeout.is_zero()
            || config.connect_timeout.is_zero()
            || config.max_response_bytes == 0
            || config.max_response_bytes == usize::MAX
        {
            return Err(invalid_input());
        }

        let base = validate_base_url(&config.base_url, config.local_only)?;
        let auth = match bearer {
            Some(token) => Some(build_auth_header(&token)?),
            None => None,
        };

        let mut builder = reqwest::blocking::ClientBuilder::new()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout);

        if let Some(pem) = extra_root {
            let certificate = reqwest::Certificate::from_pem(pem).map_err(|_| invalid_input())?;
            builder = builder.add_root_certificate(certificate);
        }

        if config.local_only && host_is_localhost_domain(&base) {
            // Pin the only permitted DNS name to loopback and the base port so
            // no external resolver or hosts entry can redirect it.
            let port = base.port_or_known_default().ok_or_else(invalid_input)?;
            builder = builder.resolve_to_addrs(
                "localhost",
                &[
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
                ],
            );
        }

        let client = builder.build().map_err(|_| invalid_input())?;
        Ok(Self {
            base,
            client,
            auth,
            max_response_bytes: config.max_response_bytes,
            trace: None,
        })
    }

    pub(crate) fn with_trace(
        mut self,
        trace: std::sync::Arc<std::sync::Mutex<crate::search::regression_trace::RequestTrace>>,
    ) -> Self {
        self.trace = Some(trace);
        self
    }

    /// Test-only: trust one additional PEM-encoded CA for this transport.
    ///
    /// This is the only way a test can connect to the loopback TLS fixture with
    /// a certificate the public trust store does not know. It is compiled only
    /// under `cfg(test)`, so no production build has a switch that widens trust.
    #[cfg(test)]
    pub fn new_with_test_root(
        config: HttpConfig,
        bearer: Option<String>,
        ca_pem: &[u8],
    ) -> Result<Self, RerankError> {
        Self::build(config, bearer, Some(ca_pem))
    }

    fn record_attempt(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Option<usize>, RerankError> {
        self.trace
            .as_ref()
            .map(|trace| {
                trace
                    .lock()
                    .map_err(|_| invalid_input())?
                    .begin(method, path, body)
            })
            .transpose()
    }

    /// Send one `GET` to `path` (a rooted, same-origin request path).
    pub fn get_json(&self, path: &str) -> Result<HttpJson, RerankError> {
        let target = self.resolve_target(path)?;
        self.send("GET", target, path, None)
            .map_err(TransportError::to_rerank_error)
    }

    /// Send one `POST` to `path` with `body` as a JSON payload.
    pub fn post_json(&self, path: &str, body: &Value) -> Result<HttpJson, RerankError> {
        let target = self.resolve_target(path)?;
        self.send("POST", target, path, Some(body))
            .map_err(TransportError::to_rerank_error)
    }

    /// Send one `GET` to the absolute `target` URL.
    ///
    /// `target` must be the same origin as this transport's base and carry no
    /// query or fragment. The parsed URL is sent exactly as it stands, so a
    /// configured path that keeps a leading `//`, a literal `@` or a
    /// percent-encoded byte reaches the service unchanged.
    pub fn get_json_target(&self, target: &Url) -> Result<HttpJson, TransportError> {
        self.same_origin_target(target)?;
        let trace_path = target.path().to_string();
        self.send("GET", target.clone(), &trace_path, None)
    }

    /// Send one `POST` to the absolute `target` URL with `body` as its payload.
    ///
    /// This is [`Self::get_json_target`]'s POST twin, and the entry point the
    /// API-only model client uses: it never re-joins or reinterprets the path.
    pub fn post_json_target(&self, target: &Url, body: &Value) -> Result<HttpJson, TransportError> {
        self.same_origin_target(target)?;
        let trace_path = target.path().to_string();
        self.send("POST", target.clone(), &trace_path, Some(body))
    }

    /// Refuse a target that is not this base's origin, or that carries a query
    /// or fragment no service endpoint may have.
    fn same_origin_target(&self, target: &Url) -> Result<(), TransportError> {
        if target.scheme() != self.base.scheme()
            || target.host_str() != self.base.host_str()
            || target.port_or_known_default() != self.base.port_or_known_default()
            || target.username() != self.base.username()
            || target.password() != self.base.password()
            || target.query().is_some()
            || target.fragment().is_some()
        {
            return Err(TransportError::new(TransportFailure::InvalidInput, None));
        }
        Ok(())
    }

    /// The single send path both entry points share: one request, one bounded
    /// read, and a [`TransportError`] for every way it can fail.
    fn send(
        &self,
        method: &str,
        target: Url,
        trace_path: &str,
        body: Option<&Value>,
    ) -> Result<HttpJson, TransportError> {
        let mut req = if method == "POST" {
            self.client.post(target).json(body.unwrap_or(&Value::Null))
        } else {
            self.client.get(target)
        };
        if let Some(auth) = &self.auth {
            req = req.header(AUTHORIZATION, auth.clone());
        }
        let trace_index = self
            .record_attempt(method, trace_path, body)
            .map_err(|_| TransportError::new(TransportFailure::InvalidInput, None))?;
        let resp = req
            .send()
            .map_err(|err| TransportError::new(classify_send_failure(&err), None))?;
        self.finish(resp, trace_index)
    }

    /// Validate `path` and join it onto the base origin, proving the result is
    /// still that same origin.
    ///
    /// Only the path-based entry points use this. A configured endpoint is sent
    /// through [`Self::post_json_target`] precisely because joining its path
    /// could reinterpret a leading `//` as a new authority.
    fn resolve_target(&self, path: &str) -> Result<Url, RerankError> {
        validate_request_path(path)?;
        let target = self.base.join(path).map_err(|_| invalid_input())?;
        if target.scheme() != self.base.scheme()
            || target.host_str() != self.base.host_str()
            || target.port_or_known_default() != self.base.port_or_known_default()
            || target.username() != self.base.username()
            || target.password() != self.base.password()
            || target.fragment().is_some()
        {
            return Err(invalid_input());
        }
        Ok(target)
    }

    /// Classify a sent response: status gate, then a bounded streaming read.
    fn finish(
        &self,
        resp: reqwest::blocking::Response,
        trace_index: Option<usize>,
    ) -> Result<HttpJson, TransportError> {
        let status = resp.status();
        let observed = status.as_u16();
        if let (Some(trace), Some(index)) = (&self.trace, trace_index) {
            trace
                .lock()
                .map_err(|_| TransportError::new(TransportFailure::InvalidInput, Some(observed)))?
                .response(index, observed)
                .map_err(|_| TransportError::new(TransportFailure::InvalidInput, Some(observed)))?;
        }
        if !status.is_success() {
            // The body is intentionally not read: only the status is exposed.
            return Err(TransportError::new(
                TransportFailure::HttpStatus(observed),
                Some(observed),
            ));
        }

        // Every failure below happened *after* a real answer arrived, so the
        // status stays on the record. The classification alone decides whether
        // the failure may trigger a fallback.
        let limit = self.max_response_bytes;
        let mut body = Vec::new();
        resp.take(limit as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|err| TransportError::new(classify_read_failure(err), Some(observed)))?;
        if body.len() > limit {
            return Err(TransportError::new(
                TransportFailure::InvalidResponse,
                Some(observed),
            ));
        }

        let value = serde_json::from_slice(&body)
            .map_err(|_| TransportError::new(TransportFailure::InvalidResponse, Some(observed)))?;
        Ok(HttpJson {
            status: observed,
            body: value,
        })
    }
}

fn invalid_input() -> RerankError {
    RerankError::new(RerankFailureReason::InvalidInput)
}

/// Parse and validate the base URL into a bare origin.
fn validate_base_url(raw: &str, local_only: bool) -> Result<Url, RerankError> {
    let url = Url::parse(raw).map_err(|_| invalid_input())?;

    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(invalid_input()),
    }

    // A bare origin has no legal `@` anywhere, and the URL parser normalizes
    // several userinfo shapes (`http://@host`, `http:/@host`, `http:////@host`,
    // a backslash authority, an upper-case scheme) into a bare origin with an
    // empty username. Refusing any raw `@` catches all of them without
    // rejecting a legitimate IP literal, `localhost` or port form.
    if !url.username().is_empty() || url.password().is_some() || raw.contains('@') {
        return Err(invalid_input());
    }

    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(invalid_input());
    }

    let Some(host) = url.host() else {
        return Err(invalid_input());
    };
    if let Host::Domain(name) = &host {
        if name.is_empty() {
            return Err(invalid_input());
        }
    }

    if local_only && !host_is_loopback(&host) {
        return Err(RerankError::new(RerankFailureReason::NonLoopbackEndpoint));
    }

    Ok(url)
}

/// Whether a resolved host is loopback: a loopback IP literal, or the single
/// permitted DNS name `localhost`.
///
/// `Url::host` is matched instead of `Url::host_str` so an IPv6 literal such as
/// `::1` is recognised by address; the string form keeps its surrounding
/// brackets, which would otherwise misclassify it as a domain.
fn host_is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
        Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
    }
}

/// Whether the base URL's host is the one permitted DNS name.
fn host_is_localhost_domain(url: &Url) -> bool {
    matches!(url.host(), Some(Host::Domain(name)) if name.eq_ignore_ascii_case("localhost"))
}

/// Reject anything that is not a rooted, same-origin request path.
fn validate_request_path(path: &str) -> Result<(), RerankError> {
    if path.is_empty()
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('\\')
        || path.contains('#')
        || path.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Err(invalid_input());
    }
    Ok(())
}

/// Build the sensitive `Authorization` header, echoing nothing on failure.
fn build_auth_header(token: &str) -> Result<HeaderValue, RerankError> {
    let mut value =
        HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| invalid_input())?;
    value.set_sensitive(true);
    Ok(value)
}

/// Classify a send failure. The status is unavailable here, so the failure
/// never carries a body or a URL.
///
/// The classification is typed: `is_timeout` for the wait budget, then the first
/// [`std::io::Error`] found by walking the `source` chain for the network case.
/// `reqwest::Error::is_connect` is deliberately not consulted — it is true for a
/// TLS handshake failure too, and the routing contract must not read that as a
/// retryable network fault. No error message text is ever matched.
fn classify_send_failure(err: &reqwest::Error) -> TransportFailure {
    if err.is_timeout() {
        return TransportFailure::Timeout;
    }
    if err.is_builder() {
        return TransportFailure::InvalidInput;
    }
    match first_io_kind(err) {
        Some(kind) => classify_io_kind(kind),
        None => TransportFailure::UnclassifiedTransport,
    }
}

/// Classify a body-read failure. The blocking response wraps a `reqwest::Error`
/// inside the `io::Error`, which is where a timeout classification lives.
fn classify_read_failure(err: std::io::Error) -> TransportFailure {
    if let Some(inner) = err
        .get_ref()
        .and_then(|source| source.downcast_ref::<reqwest::Error>())
    {
        if inner.is_timeout() {
            return TransportFailure::Timeout;
        }
        if let Some(kind) = first_io_kind(inner) {
            return classify_io_kind(kind);
        }
    }
    classify_io_kind(err.kind())
}

/// Walk the `source` chain of `err` and return the kind of the first
/// [`std::io::Error`] on it.
fn first_io_kind(err: &dyn StdError) -> Option<std::io::ErrorKind> {
    let mut source: Option<&(dyn StdError + 'static)> = err.source();
    while let Some(current) = source {
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            return Some(io.kind());
        }
        source = current.source();
    }
    None
}

/// Reduce an [`std::io::ErrorKind`] to the routing-relevant failure.
///
/// Anything outside the enumerated kinds is deliberately
/// [`TransportFailure::UnclassifiedTransport`]: a TLS problem, a proxy
/// rejection and anything else we cannot attribute are all "do not fall back"
/// rather than "retry somewhere else".
///
/// `UnexpectedEof` is excluded on purpose. A peer that closes a connection
/// mid-body produces it, but so does a service that answers with a truncated
/// body — a response-structure failure that must never trigger a second
/// attempt. The unambiguous interruption signals below cover the case the
/// routing contract actually allows.
fn classify_io_kind(kind: std::io::ErrorKind) -> TransportFailure {
    use std::io::ErrorKind as Kind;
    if kind == Kind::TimedOut {
        TransportFailure::Timeout
    } else if kind == Kind::ConnectionRefused {
        TransportFailure::ConnectionRefused
    } else if kind == Kind::NetworkUnreachable || kind == Kind::HostUnreachable {
        TransportFailure::NetworkUnavailable
    } else if kind == Kind::ConnectionReset
        || kind == Kind::ConnectionAborted
        || kind == Kind::BrokenPipe
        || kind == Kind::NotConnected
    {
        TransportFailure::ConnectionInterrupted
    } else {
        TransportFailure::UnclassifiedTransport
    }
}

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
            listener.set_nonblocking(true).expect("fixture nonblocking");
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
            format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nConnection: close\r\n"
            )
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

    /// A valid JSON value padded with trailing whitespace (which JSON permits)
    /// to longer than `min_bytes`. Both the whole body, and every prefix at
    /// least as long as the value, stay valid JSON. That keeps the size cap the
    /// only reason a capped implementation rejects it: one that dropped the cap
    /// would parse the body and fail the test rather than pass for the wrong
    /// reason.
    fn oversized_json(min_bytes: usize) -> Vec<u8> {
        let mut s = String::from("{\"a\":1}");
        while s.len() <= min_bytes {
            s.push(' ');
        }
        s.into_bytes()
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

    /// Construct a transport that must be refused. `Result::unwrap_err` would
    /// demand `Debug` on the (deliberately non-`Debug`) success type, so this
    /// goes through `Result::err` instead.
    fn refused(config: HttpConfig, bearer: Option<String>) -> RerankError {
        let base = config.base_url.clone();
        HttpTransport::new(config, bearer)
            .err()
            .unwrap_or_else(|| panic!("transport must be refused for base {base:?}"))
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
    fn regression_request_trace_matches_bytes_received_by_http_server() {
        use crate::search::regression_trace::RequestTrace;
        use sha2::{Digest, Sha256};
        let server = Server::ipv4(Behavior::Fixed(ok_json("{\"scored\":2}")));
        let trace = Arc::new(Mutex::new(RequestTrace::default()));
        let transport = transport(&server.base(), true).with_trace(trace.clone());
        let body = json!({"model":"synthetic", "query":"组合字符 e\u{301}", "documents":["甲\n乙", "different document"], "top_n":2});
        transport.post_json("/rerank", &body).unwrap();
        let requests = server.requests();
        let request = &requests[0];
        let split = request
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let wire: Value = serde_json::from_slice(&request[split..]).unwrap();
        let trace = trace.lock().unwrap();
        let evidence = &trace.requests[0];
        assert_eq!(
            evidence.json_body_sha256.as_ref().unwrap(),
            &hex::encode(Sha256::digest(&request[split..]))
        );
        let query = wire["query"].as_str().unwrap();
        assert_eq!(
            evidence.query.as_ref().unwrap().utf8_bytes,
            query.len() as u64
        );
        assert_eq!(
            evidence.query.as_ref().unwrap().sha256,
            hex::encode(Sha256::digest(query.as_bytes()))
        );
        for (slot, value) in wire["documents"].as_array().unwrap().iter().enumerate() {
            let text = value.as_str().unwrap();
            let actual = &evidence.documents.as_ref().unwrap()[slot];
            assert_eq!(actual.input_slot, slot);
            assert_eq!(
                actual.text.sha256,
                hex::encode(Sha256::digest(text.as_bytes()))
            );
            assert_eq!(actual.text.utf8_bytes, text.len() as u64);
        }
        assert_eq!(evidence.http_status, Some(200));
        assert_eq!(evidence.state, "http-response-observed");
        assert_eq!(trace.model_requests, None);
        let serialized = serde_json::to_string(&*trace).unwrap();
        assert!(!serialized.contains("different document"));
        assert!(!serialized.contains("组合字符"));
    }

    #[test]
    fn regression_request_trace_distinguishes_http_failure_from_delivery_unknown() {
        use crate::search::regression_trace::RequestTrace;
        let server = Server::ipv4(Behavior::Fixed(
            b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ));
        let trace = Arc::new(Mutex::new(RequestTrace::default()));
        let transport = transport(&server.base(), true).with_trace(trace.clone());
        let body = json!({"query":"synthetic", "documents":["one"]});
        assert!(transport.post_json("/rerank", &body).is_err());
        assert_eq!(trace.lock().unwrap().requests[0].http_status, Some(500));
        assert_eq!(trace.lock().unwrap().model_requests, None);
        let trace = Arc::new(Mutex::new(RequestTrace::default()));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let unused = listener.local_addr().unwrap();
        drop(listener);
        let transport = super::HttpTransport::new(config(&format!("http://{unused}"), true), None)
            .unwrap()
            .with_trace(trace.clone());
        assert!(transport.post_json("/rerank", &body).is_err());
        let trace = trace.lock().unwrap();
        assert_eq!(trace.requests.len(), 1);
        assert_eq!(trace.requests[0].state, "attempted-delivery-unknown");
        assert_eq!(trace.requests[0].http_status, None);
    }

    #[test]
    fn regression_request_trace_records_nothing_when_path_is_rejected() {
        use crate::search::regression_trace::RequestTrace;
        let server = Server::ipv4(Behavior::Fixed(ok_json("{}")));
        let trace = Arc::new(Mutex::new(RequestTrace::default()));
        let transport = transport(&server.base(), true).with_trace(trace.clone());
        assert!(
            transport
                .post_json(
                    "http://invalid.example/rerank",
                    &json!({"query":"q","documents":["d"]})
                )
                .is_err()
        );
        assert!(trace.lock().unwrap().requests.is_empty());
        assert_eq!(server.hits(), 0);
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
        assert!(
            !text.contains("authorization:"),
            "unexpected header: {text}"
        );
    }

    #[test]
    fn request_with_bearer_sends_it_and_never_leaks_on_error() {
        let server = Server::ipv4(Behavior::Fixed(ok_json("{\"ok\":true}")));
        let t = HttpTransport::new(config(&server.base(), true), Some(FAKE_BEARER.to_string()))
            .expect("transport");
        t.get_json("/probe").unwrap();
        let text = String::from_utf8_lossy(&server.requests()[0]).to_ascii_lowercase();
        assert!(
            text.contains(&format!(
                "authorization: bearer {}",
                FAKE_BEARER.to_ascii_lowercase()
            )),
            "missing bearer header: {text}"
        );

        // A non-2xx with the same transport must not surface the token.
        let err_server = Server::ipv4(Behavior::Fixed(response_with(
            "500 Internal Server Error",
            FAKE_SECRET.as_bytes(),
            Some(FAKE_SECRET.len()),
        )));
        let et = HttpTransport::new(
            config(&err_server.base(), true),
            Some(FAKE_BEARER.to_string()),
        )
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
        let err = refused(
            config("http://127.0.0.1:9", true),
            Some(ILLEGAL_TOKEN.to_string()),
        );
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
        let err = refused(config("http://192.0.2.1:8080", true), None);
        assert_eq!(err.reason, RerankFailureReason::NonLoopbackEndpoint);
    }

    #[test]
    fn local_only_refuses_lookalike_loopback_domain() {
        let err = refused(config("http://127.0.0.1.evil.example:8080", true), None);
        assert_eq!(err.reason, RerankFailureReason::NonLoopbackEndpoint);
        let err2 = refused(config("http://notlocalhost:8080", true), None);
        assert_eq!(err2.reason, RerankFailureReason::NonLoopbackEndpoint);
    }

    #[test]
    fn base_url_with_userinfo_is_refused() {
        // Every form that carries an `@` in the raw base must be refused,
        // including the shapes the URL parser would normalize to a bare origin
        // with an empty username (`http:/@host`, `http:////@host`, a backslash
        // authority, an upper-case scheme). A bare origin has no legal `@`, so
        // the raw text is the authority.
        for base in [
            "http://user:pass@127.0.0.1:8080",
            "http://user@127.0.0.1:8080",
            "http://@127.0.0.1:8080",
            "http://@localhost",
            r"http:\@localhost",
            "http:/@localhost",
            "http:////@localhost",
            r"http:\\@localhost",
            "HTTP://@localhost",
        ] {
            for local_only in [true, false] {
                let err = refused(config(base, local_only), None);
                assert_eq!(
                    err.reason,
                    RerankFailureReason::InvalidInput,
                    "base {base:?} local_only={local_only}"
                );
            }
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
            let err = refused(config(base, false), None);
            assert_eq!(err.reason, RerankFailureReason::InvalidInput, "base {base}");
        }
    }

    #[test]
    fn zero_and_overflow_budgets_are_refused() {
        let base = "http://127.0.0.1:9";

        let mut c = config(base, true);
        c.timeout = Duration::ZERO;
        assert_eq!(refused(c, None).reason, RerankFailureReason::InvalidInput);

        let mut c = config(base, true);
        c.connect_timeout = Duration::ZERO;
        assert_eq!(refused(c, None).reason, RerankFailureReason::InvalidInput);

        let mut c = config(base, true);
        c.max_response_bytes = 0;
        assert_eq!(refused(c, None).reason, RerankFailureReason::InvalidInput);

        let mut c = config(base, true);
        c.max_response_bytes = usize::MAX;
        assert_eq!(refused(c, None).reason, RerankFailureReason::InvalidInput);
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
            assert_eq!(
                err.reason,
                RerankFailureReason::InvalidInput,
                "path {path:?}"
            );
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
        assert_eq!(
            second.hits(),
            0,
            "the redirect target must not be contacted"
        );
    }

    #[test]
    fn oversized_body_with_content_length_is_refused() {
        let big = oversized_json(200);
        let server = Server::ipv4(Behavior::Fixed(response_with(
            "200 OK",
            &big,
            Some(big.len()),
        )));
        let t = HttpTransport::new(
            config_limits(&server.base(), true, Duration::from_secs(5), 64),
            None,
        )
        .expect("transport");
        let err = t.get_json("/").unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InvalidResponse);
    }

    #[test]
    fn oversized_body_without_content_length_is_refused() {
        let big = oversized_json(200);
        let server = Server::ipv4(Behavior::Fixed(response_with("200 OK", &big, None)));
        let t = HttpTransport::new(
            config_limits(&server.base(), true, Duration::from_secs(5), 64),
            None,
        )
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
        let server = Server::ipv4(Behavior::Fixed(response_with(
            "200 OK",
            &[0x66, 0x6f, 0x80],
            Some(3),
        )));
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
        assert_eq!(
            server.hits(),
            1,
            "a failed receive is attempted at most once"
        );
    }

    #[test]
    fn stalled_read_fails_with_timeout_short_code() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nConnection: keep-alive\r\n\r\n"
            .to_vec();
        let server = Server::ipv4(Behavior::Stall { head });
        let t = HttpTransport::new(
            config_limits(
                &server.base(),
                true,
                Duration::from_millis(200),
                64 * 1024 * 1024,
            ),
            None,
        )
        .expect("transport");
        let start = Instant::now();
        let err = t.get_json("/").unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::Timeout);
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "timeout must fire promptly"
        );
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

    // ------------------------------------------------------------------
    // C3 — the absolute-target entry points and the detailed classification.
    // ------------------------------------------------------------------

    use crate::search::model_api::test_support::{HttpFixture, Reply};

    #[test]
    fn the_target_entry_point_sends_the_configured_path_verbatim() {
        // A configured endpoint keeps whatever path the operator wrote. Joining
        // that path onto a base origin would read a leading `//` as a new
        // authority, so the target is sent exactly as parsed.
        let fixture = HttpFixture::ok();
        let t = transport(&fixture.base(), true);
        let target = fixture.url("//a@b%41c");
        let got = t.post_json_target(&target, &json!({"k": 1})).expect("post");
        assert_eq!(got.status, 200);
        assert_eq!(fixture.hits(), 1);
        assert_eq!(fixture.requests()[0].target(), "//a@b%41c");
    }

    #[test]
    fn the_target_entry_point_refuses_a_foreign_origin() {
        let served = HttpFixture::ok();
        let other = HttpFixture::ok();
        let t = transport(&served.base(), true);
        let target = Url::parse(&format!("http://127.0.0.1:{}/x", other.addr().port()))
            .expect("foreign url");
        let failure = t.post_json_target(&target, &json!({})).unwrap_err();
        assert_eq!(failure.failure(), TransportFailure::InvalidInput);
        assert_eq!(failure.http_status(), None);
        assert_eq!(served.hits(), 0);
        assert_eq!(other.hits(), 0);
    }

    #[test]
    fn the_target_entry_point_refuses_a_query_or_fragment() {
        let fixture = HttpFixture::ok();
        let t = transport(&fixture.base(), true);
        assert_eq!(
            t.get_json_target(&fixture.url("/x?y=1"))
                .unwrap_err()
                .failure(),
            TransportFailure::InvalidInput
        );
        assert_eq!(
            t.get_json_target(&fixture.url("/x#f"))
                .unwrap_err()
                .failure(),
            TransportFailure::InvalidInput
        );
        assert_eq!(fixture.hits(), 0);
    }

    #[test]
    fn a_refused_connection_is_classified_as_connection_refused() {
        let refused = HttpFixture::refused_address();
        let t = transport(&format!("http://{refused}"), true);
        let target = Url::parse(&format!("http://{refused}/x")).expect("url");
        let failure = t.post_json_target(&target, &json!({})).unwrap_err();
        assert_eq!(failure.failure(), TransportFailure::ConnectionRefused);
        assert_eq!(failure.http_status(), None);
    }

    #[test]
    fn a_non_success_status_is_classified_with_its_status() {
        let fixture = HttpFixture::start(vec![Reply::status(503)]);
        let t = transport(&fixture.base(), true);
        let failure = t.get_json_target(&fixture.url("/x")).unwrap_err();
        assert_eq!(failure.failure(), TransportFailure::HttpStatus(503));
        assert_eq!(failure.http_status(), Some(503));
        assert!(TransportFailure::HttpStatus(503).http_status() == Some(503));
        assert!(TransportFailure::HttpStatus(503).network_attempted());
        assert!(!TransportFailure::InvalidInput.network_attempted());
    }

    #[cfg(not(windows))]
    #[test]
    fn an_untrusted_certificate_is_unclassified_and_not_retryable() {
        use crate::search::model_api::test_support::TlsFixture;
        let tls = TlsFixture::start(vec![Reply::ok(json!({"ok": true}))]);
        let t = HttpTransport::new(
            HttpConfig {
                base_url: tls.base(),
                local_only: true,
                timeout: Duration::from_secs(10),
                connect_timeout: Duration::from_secs(10),
                max_response_bytes: 64 * 1024 * 1024,
            },
            None,
        )
        .expect("transport");
        let failure = t.get_json_target(&tls.url("/probe")).unwrap_err();
        assert_eq!(failure.failure(), TransportFailure::UnclassifiedTransport);
        assert_eq!(failure.http_status(), None);
        assert!(
            tls.fixture().hits() >= 1,
            "a real handshake must have been attempted"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_test_root_connects_to_the_loopback_tls_fixture() {
        use crate::search::model_api::test_support::TlsFixture;
        let tls = TlsFixture::start(vec![Reply::ok(json!({"ok": true}))]);
        let t = HttpTransport::new_with_test_root(
            HttpConfig {
                base_url: tls.base(),
                local_only: true,
                timeout: Duration::from_secs(10),
                connect_timeout: Duration::from_secs(10),
                max_response_bytes: 64 * 1024 * 1024,
            },
            None,
            tls.ca_pem(),
        )
        .expect("transport");
        let got = t.get_json_target(&tls.url("/probe")).expect("tls get");
        assert_eq!(got.status, 200);
        assert_eq!(got.body, json!({"ok": true}));
    }
}
