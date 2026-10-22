//! Ticket 15 cancellation, deadline and reaping tests.
//!
//! Every test drives the real `cass-mcp` binary over real HTTP against a
//! controlled companion in the test's own temp directory. The companion
//! answers `--version`, records the exact PID of each business child, writes a
//! per-request `READY` file, and then either waits for that request's release
//! file or ignores `SIGTERM` until it is killed. Nothing touches a production
//! path, a model, a real database, or another request's process.
//!
//! Two kinds of evidence are kept apart:
//!
//! * these tests use real wall-clock time, real TCP connections and real OS
//!   processes, so the deadline, the cancellation, the `wait` and the slot
//!   hand-over are observed end to end;
//! * the private unit tests inside `runner.rs` use a paused clock and the
//!   standard cancellation token for the parts that cannot be timed reliably
//!   against a real process (simultaneous priorities, remaining budget after a
//!   queue delay, the final publication decision).
//!
//! The queued order itself is never guessed from sleeps: where a test needs to
//! know that a request holds the queue, it uses the fixed `busy` refusal of a
//! second request as the observation. A cancelled request is allowed to end
//! without a tool result (C4); no test treats a missing reply as a failure or
//! waits for one before checking cleanup.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_cass-mcp");
const EXPECTED_CASS_VERSION: &str = "cass 0.6.17";
const PROTOCOL_2025: &str = "2025-11-25";
const PROTOCOL_2026: &str = "2026-07-28";
const PUBLIC_ORIGIN: &str = "http://public.example:8080";

/// Large enough that a legal envelope, its serialized tool result, and every
/// fixed error code fit. These tests are not about the byte budget.
const BUDGET: usize = 4096;

/// Observation limit used only to fail a deadlocked test; the product gets its
/// deadline from `--request-timeout-ms`, never from here.
const OBSERVE: Duration = Duration::from_secs(20);

/// How long a request that must still be waiting is observed before the test
/// continues. A bounded observation of "no answer yet"; it never decides the
/// queue order.
const SETTLE: Duration = Duration::from_millis(750);

/// How long a cancelled request may take to end without a tool result. The
/// SDK may terminate a cancelled request without a reply (C4); this window is
/// only used to prove that no success is published.
const CANCEL_SETTLE: Duration = Duration::from_secs(3);

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Controlled companion process
// ---------------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
    cass_bin: PathBuf,
    data_dir: PathBuf,
    api_config: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "cass-mcp-t15-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create sandbox directory");

        let data_dir = dir.join("data");
        fs::create_dir_all(&data_dir).expect("create data dir");

        let api_config = dir.join("api.toml");
        fs::write(&api_config, "version = 1\n").expect("write api config");

        let home = dir.join("home");
        fs::create_dir_all(&home).expect("create isolated home");

        let fixture = Self {
            cass_bin: dir.join("fake-cass"),
            dir,
            data_dir,
            api_config,
            home,
        };
        fixture.write_script();
        fixture.set_answer("search", SEARCH_ENVELOPE, "", 0);
        fixture.set_answer("expand", EXPAND_ENVELOPE, "", 0);
        fixture.set_answer("sessions", SESSIONS_ENVELOPE, "", 0);
        fixture.set_answer("timeline", TIMELINE_ENVELOPE, "", 0);
        fixture
    }

    /// One script for every business call. It derives a per-request token from
    /// the fixed argv of whichever tool called it, so the test can name the
    /// exact child behind each request: `search` uses the query, `expand` the
    /// message id, `sessions` the limit, `timeline` the group-by value.
    ///
    /// Modes:
    /// * `answer` — print the recorded answer and exit at once.
    /// * `stubborn` — record a `term` marker when `SIGTERM` arrives and keep
    ///   running until the release file appears or the process is killed.
    /// * anything else (`hold`) — wait for the release file, then answer.
    fn write_script(&self) {
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\n' '{version}'
  exit 0
fi
sub="$1"
token=""
for a in "$@"; do
  case "$a" in
    --limit=*) token="${{a#--limit=}}" ;;
    --message-id=*) token="${{a#--message-id=}}" ;;
    --group-by=*) token="${{a#--group-by=}}" ;;
    --*) ;;
    *) token="$a" ;;
  esac
done
dir='{dir}'
printf '%s\n' "$$" >> "$dir/pids"
printf '%s\n' "$$" > "$dir/pids.$token"
printf 'READY\n' > "$dir/ready.$token"
mode="hold"
if [ -f "$dir/mode.$token" ]; then mode="$(cat "$dir/mode.$token")"; fi
case "$mode" in
  answer)
    cat "$dir/answer.$sub.stdout"
    cat "$dir/answer.$sub.stderr" >&2
    exit "$(cat "$dir/answer.$sub.exit")"
    ;;
  stubborn)
    term="$dir/term.$token"
    trap 'printf "term\n" > "$term"' TERM
    while [ ! -f "$dir/release.$token" ]; do sleep 0.02; done
    cat "$dir/answer.$sub.stdout"
    exit 0
    ;;
  *)
    while [ ! -f "$dir/release.$token" ]; do sleep 0.02; done
    cat "$dir/answer.$sub.stdout"
    exit 0
    ;;
esac
"#,
            version = EXPECTED_CASS_VERSION,
            dir = self.dir.display(),
        );
        fs::write(&self.cass_bin, script).expect("write fake cass binary");
        self.set_cass_mode(0o755);
    }

    fn set_cass_mode(&self, mode: u32) {
        let mut permissions = fs::metadata(&self.cass_bin)
            .expect("stat fake cass")
            .permissions();
        permissions.set_mode(mode);
        fs::set_permissions(&self.cass_bin, permissions).expect("chmod fake cass");
    }

    fn set_mode(&self, token: &str, mode: &str) {
        fs::write(self.dir.join(format!("mode.{token}")), mode).expect("write request mode");
    }

    fn release(&self, token: &str) {
        fs::write(self.dir.join(format!("release.{token}")), b"release\n")
            .expect("write release file");
    }

    fn ready(&self, token: &str) -> bool {
        self.dir.join(format!("ready.{token}")).exists()
    }

    fn term_seen(&self, token: &str) -> bool {
        self.dir.join(format!("term.{token}")).exists()
    }

    fn set_answer(&self, subcommand: &str, stdout: &str, stderr: &str, exit: i32) {
        fs::write(self.dir.join(format!("answer.{subcommand}.stdout")), stdout)
            .expect("write answer stdout");
        fs::write(self.dir.join(format!("answer.{subcommand}.stderr")), stderr)
            .expect("write answer stderr");
        fs::write(
            self.dir.join(format!("answer.{subcommand}.exit")),
            format!("{exit}\n"),
        )
        .expect("write answer exit");
    }

    /// Every business child ever started, in start order. The `--version`
    /// probe is never recorded.
    fn pids(&self) -> Vec<i32> {
        fs::read_to_string(self.dir.join("pids"))
            .map(|text| {
                text.lines()
                    .filter_map(|line| line.trim().parse::<i32>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn pid_for(&self, token: &str) -> Option<i32> {
        fs::read_to_string(self.dir.join(format!("pids.{token}")))
            .ok()
            .and_then(|text| text.trim().parse::<i32>().ok())
    }

    fn live_pids(&self) -> Vec<i32> {
        self.pids().into_iter().filter(|pid| alive(*pid)).collect()
    }

    fn pid_gone(&self, token: &str) -> bool {
        self.pid_for(token).is_none_or(|pid| !alive(pid))
    }

    fn args(
        &self,
        bind: SocketAddr,
        concurrent: usize,
        queued: usize,
        timeout_ms: u64,
        grace_ms: u64,
    ) -> Vec<String> {
        vec![
            "--bind".to_string(),
            bind.to_string(),
            "--cass-bin".to_string(),
            self.cass_bin.display().to_string(),
            "--data-dir".to_string(),
            self.data_dir.display().to_string(),
            "--api-config".to_string(),
            self.api_config.display().to_string(),
            "--embedding-profile".to_string(),
            "embedding-profile".to_string(),
            "--rerank-profile".to_string(),
            "rerank-profile".to_string(),
            "--max-concurrent".to_string(),
            concurrent.to_string(),
            "--max-queued".to_string(),
            queued.to_string(),
            "--max-output-bytes".to_string(),
            BUDGET.to_string(),
            "--request-timeout-ms".to_string(),
            timeout_ms.to_string(),
            "--terminate-grace-ms".to_string(),
            grace_ms.to_string(),
            "--public-origin".to_string(),
            PUBLIC_ORIGIN.to_string(),
        ]
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Kill only the PIDs this fixture recorded; never by name or port.
        for pid in self.pids() {
            if alive(pid) {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn alive(pid: i32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

const SEARCH_ENVELOPE: &str =
    r#"<cass_recall version="1" tool="cass_search">{"hits":[]}</cass_recall>"#;
const EXPAND_ENVELOPE: &str = r#"<cass_recall version="1" tool="cass_expand">[]</cass_recall>"#;
const SESSIONS_ENVELOPE: &str =
    r#"<cass_recall version="1" tool="cass_sessions">{"sessions":[]}</cass_recall>"#;
const TIMELINE_ENVELOPE: &str = r#"<cass_recall version="1" tool="cass_timeline">{"range":{"start":0,"end":0},"total_sessions":0,"groups":{}}</cass_recall>"#;

// ---------------------------------------------------------------------------
// Server process
// ---------------------------------------------------------------------------

struct ServerProc {
    child: Child,
    address: SocketAddr,
}

impl Drop for ServerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_server(
    fixture: &Fixture,
    concurrent: usize,
    queued: usize,
    timeout_ms: u64,
    grace_ms: u64,
) -> ServerProc {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind");
    let mut child = Command::new(BIN)
        .args(fixture.args(bind, concurrent, queued, timeout_ms, grace_ms))
        .env("HOME", &fixture.home)
        .env("XDG_CONFIG_HOME", fixture.home.join("config"))
        .env("XDG_DATA_HOME", fixture.home.join("data"))
        .env("XDG_CACHE_HOME", fixture.home.join("cache"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cass-mcp server");

    let stderr = child.stderr.take().expect("server stderr is piped");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });

    let line = receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("server should report its listening address");
    assert!(
        line.starts_with("listening=http://") && line.ends_with("/mcp"),
        "unexpected startup line: {line}"
    );
    let address: SocketAddr = line
        .strip_prefix("listening=http://")
        .and_then(|rest| rest.strip_suffix("/mcp"))
        .unwrap_or_else(|| panic!("unexpected startup line: {line}"))
        .parse()
        .expect("listening line must carry a socket address");

    ServerProc { child, address }
}

// ---------------------------------------------------------------------------
// Raw HTTP + SSE client
// ---------------------------------------------------------------------------

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn payload(&self) -> Value {
        self.payload_opt()
            .unwrap_or_else(|| panic!("response carried no JSON payload: {}", self.body))
    }

    /// The last JSON event of the body, or `None` when the response ended
    /// without one (a cancelled request may terminate without a result).
    fn payload_opt(&self) -> Option<Value> {
        if self
            .header("content-type")
            .is_some_and(|value| value.contains("text/event-stream"))
        {
            sse_payloads(&self.body).into_iter().next_back()
        } else {
            serde_json::from_str(&self.body).ok()
        }
    }
}

fn sse_payloads(body: &str) -> Vec<Value> {
    let mut payloads = Vec::new();
    let mut data = String::new();
    let flush = |data: &mut String, payloads: &mut Vec<Value>| {
        if !data.is_empty() {
            if let Ok(value) = serde_json::from_str(data) {
                payloads.push(value);
            }
            data.clear();
        }
    };
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
        } else if line.is_empty() {
            flush(&mut data, &mut payloads);
        }
    }
    flush(&mut data, &mut payloads);
    payloads
}

/// The outcome of one HTTP exchange: a complete response, or `None` when the
/// peer kept the stream open past the observation window without finishing.
fn exchange(
    address: SocketAddr,
    host: &str,
    extra_headers: &[(String, String)],
    body: &str,
    window: Duration,
) -> Option<HttpResponse> {
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).expect("connect to cass-mcp");
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .expect("set write timeout");

    let mut request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.push_str(body);

    stream
        .write_all(request.as_bytes())
        .expect("write HTTP request");
    read_with_deadline(&mut stream, window).map(|raw| parse_http_response(&raw))
}

/// Read until the peer closes or `window` elapses. The timeout is only the
/// test's deadlock criterion.
fn read_with_deadline(stream: &mut TcpStream, window: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + window;
    let mut raw = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        stream
            .set_read_timeout(Some(remaining.min(Duration::from_millis(250))))
            .ok()?;
        match stream.read(&mut buffer) {
            Ok(0) => return Some(raw),
            Ok(n) => raw.extend_from_slice(&buffer[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Some(raw),
        }
    }
}

fn parse_http_response(raw: &[u8]) -> HttpResponse {
    let split = find_subslice(raw, b"\r\n\r\n").expect("response has a header terminator");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body_bytes = raw[split + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .expect("status line has a code")
        .parse()
        .expect("numeric status code");

    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }

    let chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    });
    let body_bytes = if chunked {
        decode_chunked(&body_bytes)
    } else {
        body_bytes
    };

    HttpResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&body_bytes).into_owned(),
    }
}

fn decode_chunked(raw: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    let mut index = 0;
    while let Some(line_end) = find_subslice(&raw[index..], b"\r\n") {
        let line = String::from_utf8_lossy(&raw[index..index + line_end]).into_owned();
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).expect("valid chunk size");
        index += line_end + 2;
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&raw[index..index + size]);
        index += size + 2;
    }
    decoded
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn post(address: SocketAddr, host: &str, headers: &[(String, String)], body: &str) -> HttpResponse {
    exchange(address, host, headers, body, OBSERVE)
        .unwrap_or_else(|| panic!("cass-mcp did not answer within {OBSERVE:?}"))
}

// ---------------------------------------------------------------------------
// Protocol helpers
// ---------------------------------------------------------------------------

fn headers_2025(session: &str) -> Vec<(String, String)> {
    vec![
        (
            "MCP-Protocol-Version".to_string(),
            PROTOCOL_2025.to_string(),
        ),
        ("Mcp-Session-Id".to_string(), session.to_string()),
    ]
}

fn meta_2026() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_2026,
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn headers_2026(method: &str, tool: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "MCP-Protocol-Version".to_string(),
            PROTOCOL_2026.to_string(),
        ),
        ("Mcp-Method".to_string(), method.to_string()),
    ];
    if let Some(tool) = tool {
        headers.push(("Mcp-Name".to_string(), tool.to_string()));
    }
    headers
}

/// Open one SDK session (`2025-11-25` lifecycle) and return its id.
fn initialize(server: &ServerProc) -> String {
    let host = format!("127.0.0.1:{}", server.address.port());
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_2025,
            "capabilities": {},
            "clientInfo": { "name": "cass-mcp-t15-test", "version": "1.0.0" }
        }
    })
    .to_string();
    let response = post(
        server.address,
        &host,
        &[(
            "MCP-Protocol-Version".to_string(),
            PROTOCOL_2025.to_string(),
        )],
        &body,
    );
    assert_eq!(response.status, 200, "initialize body: {}", response.body);
    let session = response
        .header("mcp-session-id")
        .unwrap_or_else(|| {
            panic!(
                "initialize must return Mcp-Session-Id: {:?}",
                response.headers
            )
        })
        .to_string();
    let notification =
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string();
    let response = post(
        server.address,
        &host,
        &headers_2025(&session),
        &notification,
    );
    assert_eq!(
        response.status, 202,
        "initialized notification body: {}",
        response.body
    );
    session
}

/// The stateless `2026-07-28` discovery handshake.
fn discover_2026(server: &ServerProc) {
    let host = format!("127.0.0.1:{}", server.address.port());
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": { "_meta": meta_2026() },
    })
    .to_string();
    let response = post(
        server.address,
        &host,
        &headers_2026("server/discover", None),
        &body,
    );
    assert_eq!(response.status, 200, "discover body: {}", response.body);
    let payload = response.payload();
    assert_eq!(
        payload["result"]["supportedVersions"]
            .as_array()
            .map(|versions| versions.iter().any(|v| v == PROTOCOL_2026)),
        Some(true),
        "discover must advertise 2026-07-28: {payload}"
    );
}

/// `notifications/cancelled` for one request id of one session.
fn cancel_2025(server: &ServerProc, session: &str, id: u64) {
    let host = format!("127.0.0.1:{}", server.address.port());
    let body = json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": { "requestId": id, "reason": "test cancellation" },
    })
    .to_string();
    let response = post(server.address, &host, &headers_2025(session), &body);
    assert_eq!(
        response.status, 202,
        "cancellation notification body: {}",
        response.body
    );
}

fn tool_result(mut payload: Value) -> Value {
    payload
        .get_mut("result")
        .map(Value::take)
        .unwrap_or_else(|| panic!("expected a JSON-RPC result, got {payload}"))
}

fn result_text(result: &Value) -> &str {
    let content = result["content"]
        .as_array()
        .unwrap_or_else(|| panic!("result has no content array: {result}"));
    assert_eq!(
        content.len(),
        1,
        "exactly one content block expected: {result}"
    );
    content[0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("text block has no string text: {result}"))
}

fn assert_error_code(result: &Value, code: &str) {
    assert_eq!(result["isError"], true, "expected isError=true: {result}");
    let value: Value =
        serde_json::from_str(result_text(result)).expect("error text is a JSON object");
    assert_eq!(
        value["error"]["code"], code,
        "unexpected error code: {value}"
    );
}

fn assert_success(result: &Value) {
    assert!(
        result.get("isError").is_none() || result["isError"] == false,
        "expected a success result: {result}"
    );
}

fn wait_for(mut condition: impl FnMut() -> bool, what: &str) {
    let deadline = Instant::now() + OBSERVE;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

fn wait_for_path(path: &Path) {
    wait_for(|| path.exists(), &format!("{} to appear", path.display()));
}

// ---------------------------------------------------------------------------
// In-flight calls
// ---------------------------------------------------------------------------

/// What one tool call produced. A cancelled request may end with no tool
/// result at all (C4); a request that is still held produces nothing.
#[derive(Debug)]
enum Outcome {
    Tool(Value),
    /// The HTTP response ended without a tool result.
    Ended,
    /// No response at all within the observation window.
    TimedOut,
}

struct Call {
    token: String,
    receiver: Receiver<Outcome>,
}

impl Call {
    fn settle(&self, window: Duration) -> Option<Outcome> {
        match self.receiver.recv_timeout(window) {
            Ok(outcome) => Some(outcome),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                panic!("call `{}` ended without an outcome", self.token)
            }
        }
    }

    fn recv(&self, window: Duration) -> Outcome {
        self.settle(window)
            .unwrap_or_else(|| panic!("call `{}` did not finish within {window:?}", self.token))
    }

    fn recv_tool(&self, window: Duration) -> Value {
        match self.recv(window) {
            Outcome::Tool(result) => result,
            other => panic!("call `{}` produced no tool result: {other:?}", self.token),
        }
    }

    fn assert_still_waiting(&self) {
        assert!(
            self.settle(SETTLE).is_none(),
            "call `{}` was not held in the waiting queue",
            self.token
        );
    }

    /// A cancelled request must never publish a success. An error result is
    /// legal when the SDK still allows a reply.
    fn assert_no_success(&self, window: Duration) {
        match self.recv(window) {
            Outcome::Tool(result) => {
                let is_error = result["isError"] == true;
                assert!(
                    is_error,
                    "a cancelled request published a success: {result}"
                );
                let value: Value =
                    serde_json::from_str(result_text(&result)).expect("error text is JSON");
                assert_eq!(
                    value["error"]["code"], "cancelled",
                    "a cancelled request published another failure: {value}"
                );
            }
            Outcome::Ended | Outcome::TimedOut => {}
        }
    }
}

fn request_body(id: u64, method: &str, params: Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
    .to_string()
}

/// One `tools/call` issued from its own thread, so many can be in flight at
/// once. The outcome arrives on a channel; a still-blocked call has no
/// message yet.
fn fire_params(
    server: &ServerProc,
    headers: Vec<(String, String)>,
    id: u64,
    params: Value,
    token: &str,
) -> Call {
    let address = server.address;
    let host = format!("127.0.0.1:{}", address.port());
    let token = token.to_string();
    let thread_token = token.clone();
    let body = request_body(id, "tools/call", params);
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let outcome = match exchange(address, &host, &headers, &body, OBSERVE) {
            Some(response) => {
                assert_eq!(
                    response.status, 200,
                    "tools/call `{thread_token}` body: {}",
                    response.body
                );
                match response.payload_opt() {
                    Some(payload) => Outcome::Tool(tool_result(payload)),
                    None => Outcome::Ended,
                }
            }
            None => Outcome::TimedOut,
        };
        let _ = sender.send(outcome);
    });
    Call { token, receiver }
}

/// One `2025-11-25` call on a session.
fn fire_2025(
    server: &ServerProc,
    session: &str,
    id: u64,
    name: &'static str,
    arguments: Value,
    token: &str,
) -> Call {
    fire_params(
        server,
        headers_2025(session),
        id,
        json!({ "name": name, "arguments": arguments }),
        token,
    )
}

/// One `2026-07-28` stateless call. The version meta travels inside `params`,
/// as the stateless lifecycle requires.
fn fire_2026(
    server: &ServerProc,
    id: u64,
    name: &'static str,
    arguments: Value,
    token: &str,
) -> Call {
    let params = json!({ "name": name, "arguments": arguments, "_meta": meta_2026() });
    fire_params(
        server,
        headers_2026("tools/call", Some(name)),
        id,
        params,
        token,
    )
}

/// Send one request and close the TCP connection as soon as the child behind
/// it reports `READY`, so the disconnect happens while the request is in
/// flight. Returns the moment the socket was closed.
fn fire_then_disconnect(
    server: &ServerProc,
    headers: Vec<(String, String)>,
    id: u64,
    params: Value,
    fixture_dir: &Path,
    token: &str,
) -> Receiver<Instant> {
    let address = server.address;
    let host = format!("127.0.0.1:{}", address.port());
    let ready = fixture_dir.join(format!("ready.{token}"));
    let body = request_body(id, "tools/call", params);
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))
            .expect("connect to cass-mcp");
        let mut request = format!(
            "POST /mcp HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (name, value) in &headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request.push_str(&body);
        stream
            .write_all(request.as_bytes())
            .expect("write HTTP request");
        wait_for_path(&ready);
        drop(stream);
        let _ = sender.send(Instant::now());
    });
    receiver
}

/// The index of the contender that was refused with the fixed `busy` code.
/// Exactly one of two contenders for one queue position is refused, and the
/// refusal is the observation; arrival order is never assumed.
fn wait_until_busy(calls: &[&Call]) -> usize {
    let deadline = Instant::now() + OBSERVE;
    loop {
        for (index, call) in calls.iter().enumerate() {
            if let Some(outcome) = call.settle(Duration::from_millis(25)) {
                match outcome {
                    Outcome::Tool(result) => {
                        assert_error_code(&result, "busy");
                        return index;
                    }
                    other => panic!("expected a busy refusal, got {other:?}"),
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "no contender was refused within {OBSERVE:?}"
        );
    }
}

/// Fire a fresh request until one is accepted into the queue instead of being
/// refused with `busy`. Every refusal is a complete, harmless result; the
/// accepted request has no answer yet and no child.
fn queue_until_accepted(server: &ServerProc, session: &str, rounds: u64) -> Call {
    for round in 0..rounds {
        let probe = fire_2025(
            server,
            session,
            100 + round,
            "cass_search",
            json!({ "query": "probe" }),
            "probe",
        );
        match probe.settle(SETTLE) {
            Some(Outcome::Tool(result)) => assert_error_code(&result, "busy"),
            Some(other) => panic!("a queued probe produced an unexpected outcome: {other:?}"),
            None => return probe,
        }
    }
    panic!("the queue position was never released after the cancellation");
}

// ---------------------------------------------------------------------------
// 15-AC1: a queued request that is cancelled never starts a child
// ---------------------------------------------------------------------------

#[test]
fn cancelled_queued_request_spawns_no_child_and_frees_its_queue_position() {
    let fixture = Fixture::new("queued-cancel");
    let server = start_server(&fixture, 1, 1, 30_000, 400);
    let session = initialize(&server);

    let holder = fire_2025(
        &server,
        &session,
        1,
        "cass_search",
        json!({ "query": "h1" }),
        "h1",
    );
    wait_for(|| fixture.ready("h1"), "the slot holder never started");

    // One queue position, two contenders: exactly one is refused with `busy`,
    // the other holds the queue. The refusal decides which one is the target.
    let first = fire_2025(
        &server,
        &session,
        2,
        "cass_search",
        json!({ "query": "c2" }),
        "c2",
    );
    let second = fire_2025(
        &server,
        &session,
        3,
        "cass_search",
        json!({ "query": "c3" }),
        "c3",
    );
    let contenders = [&first, &second];
    let refused = wait_until_busy(&contenders);
    let target = contenders[1 - refused];
    let target_id = if refused == 0 { 3 } else { 2 };
    assert!(
        fixture.pid_for(&target.token).is_none(),
        "a waiting request must not start a child"
    );
    target.assert_still_waiting();

    // Cancel exactly this request.
    cancel_2025(&server, &session, target_id);

    // The queue position is gone: a fresh request is accepted into the queue
    // instead of being refused with `busy`.
    let probe = queue_until_accepted(&server, &session, 12);
    assert!(
        fixture.pid_for(&target.token).is_none(),
        "a cancelled queued request must never start a child"
    );
    assert_eq!(
        fixture.pids().len(),
        1,
        "the cancellation must not start a child of its own"
    );

    // The cancelled request never publishes a success, and cleanup did not
    // wait for a reply: the probe is already queued.
    target.assert_no_success(CANCEL_SETTLE);

    // Releasing the holder advances the queue to the probe, never to the
    // cancelled request.
    fixture.release("h1");
    assert_success(&holder.recv_tool(OBSERVE));
    wait_for(
        || fixture.ready(&probe.token),
        "the queued probe must start after the holder was waited",
    );
    assert!(
        fixture.pid_for(&target.token).is_none(),
        "the cancelled request must not start after the hand-over"
    );
    assert_eq!(
        fixture.pids().len(),
        2,
        "only the holder and the probe may spawn"
    );
    fixture.release(&probe.token);
    assert_success(&probe.recv_tool(OBSERVE));
    assert!(fixture.pid_gone(&probe.token));
    assert!(fixture.live_pids().is_empty());
}

// ---------------------------------------------------------------------------
// 15-AC1 / 15-AC2: a running request that is cancelled reaps its child
// ---------------------------------------------------------------------------

#[test]
fn cancelled_running_request_terminates_its_child_and_returns_the_slot() {
    let fixture = Fixture::new("running-cancel");
    let server = start_server(&fixture, 1, 1, 30_000, 400);
    let session = initialize(&server);

    let running = fire_2025(
        &server,
        &session,
        1,
        "cass_search",
        json!({ "query": "r1" }),
        "r1",
    );
    wait_for(|| fixture.ready("r1"), "the running request never started");
    let pid = fixture
        .pid_for("r1")
        .expect("the running child recorded its pid");
    assert!(alive(pid));

    let cancelled_at = Instant::now();
    cancel_2025(&server, &session, 1);
    wait_for(
        || fixture.pid_gone("r1"),
        "the cancelled child was never reaped",
    );
    let reaped = cancelled_at.elapsed();
    println!("MEASURED running-cancel: pid={pid} reaped_after_cancel={reaped:?}");
    assert!(
        reaped < Duration::from_secs(10),
        "the cancellation must not wait for the total deadline: {reaped:?}"
    );
    assert!(
        !alive(pid),
        "the child must be waited before the slot returns"
    );

    // A repeated and a late cancellation for the same id must not disturb the
    // pool: one slot is released once, so the next request runs and the one
    // after it waits instead of also running.
    cancel_2025(&server, &session, 1);
    let next = fire_2025(
        &server,
        &session,
        2,
        "cass_search",
        json!({ "query": "r2" }),
        "r2",
    );
    wait_for(
        || fixture.ready("r2"),
        "the next request must take the released slot",
    );
    let queued = fire_2025(
        &server,
        &session,
        3,
        "cass_search",
        json!({ "query": "r3" }),
        "r3",
    );
    queued.assert_still_waiting();
    assert!(
        fixture.pid_for("r3").is_none(),
        "one cancellation may release one slot, not two"
    );

    // The cancelled request published no success.
    running.assert_no_success(CANCEL_SETTLE);

    fixture.release("r2");
    assert_success(&next.recv_tool(OBSERVE));
    wait_for(
        || fixture.ready("r3"),
        "the queued request must start after the wait",
    );
    fixture.release("r3");
    assert_success(&queued.recv_tool(OBSERVE));
    assert_eq!(fixture.pids().len(), 3);
    assert!(fixture.live_pids().is_empty());
}

#[test]
fn a_child_that_ignores_sigterm_is_killed_after_the_grace_and_waited() {
    let fixture = Fixture::new("stubborn");
    fixture.set_mode("s1", "stubborn");
    let server = start_server(&fixture, 1, 1, 30_000, 700);
    let session = initialize(&server);

    let running = fire_2025(
        &server,
        &session,
        1,
        "cass_search",
        json!({ "query": "s1" }),
        "s1",
    );
    wait_for(|| fixture.ready("s1"), "the stubborn child never started");
    let pid = fixture.pid_for("s1").expect("stubborn child pid");

    let cancelled_at = Instant::now();
    cancel_2025(&server, &session, 1);
    wait_for(
        || fixture.term_seen("s1"),
        "the stubborn child never observed SIGTERM",
    );
    assert!(
        alive(pid),
        "a child that ignores SIGTERM must still be running"
    );

    wait_for(
        || fixture.pid_gone("s1"),
        "the stubborn child was never force-killed",
    );
    let graced = cancelled_at.elapsed();
    println!("MEASURED stubborn: pid={pid} grace_from_cancel={graced:?}");
    assert!(
        graced >= Duration::from_millis(600),
        "the configured grace must be consumed before the forced kill: {graced:?}"
    );
    assert!(!alive(pid), "the forced kill must be followed by a wait");

    // The slot comes back only after the wait, and no success was published.
    let next = fire_2025(
        &server,
        &session,
        2,
        "cass_search",
        json!({ "query": "n1" }),
        "n1",
    );
    wait_for(
        || fixture.ready("n1"),
        "the slot must return after the forced wait",
    );
    running.assert_no_success(CANCEL_SETTLE);
    fixture.release("n1");
    assert_success(&next.recv_tool(OBSERVE));
    assert_eq!(fixture.pids().len(), 2);
}

// ---------------------------------------------------------------------------
// 15-AC3: the same JSON-RPC id in two sessions never cross-talks
// ---------------------------------------------------------------------------

#[test]
fn the_same_rpc_id_in_two_sessions_is_cancelled_independently_on_one_shared_pool() {
    let fixture = Fixture::new("same-id");
    let server = start_server(&fixture, 1, 1, 30_000, 400);
    let session_a = initialize(&server);
    let session_b = initialize(&server);

    let a = fire_2025(
        &server,
        &session_a,
        7,
        "cass_search",
        json!({ "query": "a1" }),
        "a1",
    );
    wait_for(|| fixture.ready("a1"), "session A's request never started");

    // Session B uses the same JSON-RPC id. One shared slot means it must wait.
    let b = fire_2025(
        &server,
        &session_b,
        7,
        "cass_search",
        json!({ "query": "b1" }),
        "b1",
    );
    b.assert_still_waiting();
    assert!(
        fixture.pid_for("b1").is_none(),
        "a per-session execution slot must not exist"
    );
    assert_eq!(
        fixture.pids().len(),
        1,
        "both sessions share the one service-wide pool"
    );

    // Cancelling A's id must reclaim only A.
    cancel_2025(&server, &session_a, 7);
    wait_for(
        || fixture.pid_gone("a1"),
        "session A's child was not reaped",
    );
    a.assert_no_success(CANCEL_SETTLE);

    // B was never cancelled and takes the slot after A's wait.
    wait_for(
        || fixture.ready("b1"),
        "session B's request must survive session A's cancellation",
    );
    fixture.release("b1");
    assert_success(&b.recv_tool(OBSERVE));
    assert_eq!(fixture.pids().len(), 2);
    assert!(fixture.live_pids().is_empty());
}

// ---------------------------------------------------------------------------
// 15-AC1 / 15-AC3: the total deadline
// ---------------------------------------------------------------------------

#[test]
fn a_running_request_reaches_its_deadline_and_still_delivers_a_timeout() {
    let fixture = Fixture::new("running-deadline");
    let server = start_server(&fixture, 1, 1, 900, 300);
    let session = initialize(&server);

    let fired = Instant::now();
    let running = fire_2025(
        &server,
        &session,
        1,
        "cass_search",
        json!({ "query": "d1" }),
        "d1",
    );
    wait_for(|| fixture.ready("d1"), "the running request never started");

    // The connection is still alive, so the deadline is a deliverable error.
    let result = running.recv_tool(OBSERVE);
    let elapsed = fired.elapsed();
    println!(
        "MEASURED running-deadline: pid_gone={} elapsed={elapsed:?}",
        fixture.pid_gone("d1")
    );
    assert_error_code(&result, "deadline_exceeded");
    assert!(
        elapsed >= Duration::from_millis(800),
        "the deadline must be the first receipt plus the configured total: {elapsed:?}"
    );
    assert!(
        fixture.pid_gone("d1"),
        "the expired child must be waited before the error is published"
    );

    // The slot is back and a neighbour still completes.
    let next = fire_2025(
        &server,
        &session,
        2,
        "cass_search",
        json!({ "query": "d2" }),
        "d2",
    );
    wait_for(
        || fixture.ready("d2"),
        "the slot must return after the deadline reap",
    );
    fixture.release("d2");
    assert_success(&next.recv_tool(OBSERVE));
    assert_eq!(fixture.pids().len(), 2);
    assert!(fixture.live_pids().is_empty());
}

#[test]
fn a_queued_request_reaches_its_deadline_during_the_holders_grace_without_a_child() {
    let fixture = Fixture::new("queued-deadline");
    fixture.set_mode("h1", "stubborn");
    let server = start_server(&fixture, 1, 1, 1_200, 600);
    let session = initialize(&server);

    let _holder = fire_2025(
        &server,
        &session,
        1,
        "cass_search",
        json!({ "query": "h1" }),
        "h1",
    );
    wait_for(|| fixture.ready("h1"), "the holder never started");
    let holder_pid = fixture.pid_for("h1").expect("holder pid");

    let queued_at = Instant::now();
    let target = fire_2025(
        &server,
        &session,
        2,
        "cass_search",
        json!({ "query": "t1" }),
        "t1",
    );
    target.assert_still_waiting();
    assert!(fixture.pid_for("t1").is_none());

    let result = target.recv_tool(OBSERVE);
    let elapsed = queued_at.elapsed();
    println!(
        "MEASURED queued-deadline: elapsed={elapsed:?} holder_alive={} target_child={:?}",
        alive(holder_pid),
        fixture.pid_for("t1"),
    );
    assert_error_code(&result, "deadline_exceeded");
    assert!(
        elapsed >= Duration::from_millis(1_100),
        "the queued deadline must count from the first receipt, never from a grant: {elapsed:?}"
    );
    assert!(
        fixture.pid_for("t1").is_none(),
        "a queued request that expired must never start a child"
    );
    assert!(
        alive(holder_pid),
        "the target must expire while the holder still occupies its reaping grace"
    );

    // The queue position is free while the holder is still reaping, and the
    // probe is accepted instead of being refused with `busy`.
    let probe = fire_2025(
        &server,
        &session,
        3,
        "cass_search",
        json!({ "query": "p1" }),
        "p1",
    );
    match probe.settle(Duration::from_millis(200)) {
        Some(Outcome::Tool(result)) => {
            panic!("the expired queue position leaked a `busy` refusal: {result}")
        }
        Some(other) => panic!("unexpected probe outcome: {other:?}"),
        None => {}
    }
    assert!(
        fixture.pid_for("p1").is_none(),
        "the holder must still occupy the only slot"
    );

    // After the holder's wait the probe takes the slot.
    wait_for(|| fixture.pid_gone("h1"), "the holder was never reaped");
    wait_for(
        || fixture.ready("p1"),
        "the queue must advance after the holder is waited",
    );
    fixture.release("p1");
    assert_success(&probe.recv_tool(OBSERVE));
    assert_eq!(fixture.pids().len(), 2);
    assert!(fixture.live_pids().is_empty());
}

// ---------------------------------------------------------------------------
// C4: both negotiated lifecycles, real disconnects
// ---------------------------------------------------------------------------

#[test]
fn a_2025_disconnect_keeps_the_request_alive_until_its_total_deadline() {
    let fixture = Fixture::new("disconnect-2025");
    let server = start_server(&fixture, 1, 1, 1_500, 300);
    let session = initialize(&server);

    let fired = Instant::now();
    let closed = fire_then_disconnect(
        &server,
        headers_2025(&session),
        1,
        json!({ "name": "cass_search", "arguments": { "query": "k1" } }),
        &fixture.dir,
        "k1",
    );
    let closed_at = closed
        .recv_timeout(OBSERVE)
        .expect("the test client must close its socket");
    let pid = fixture
        .pid_for("k1")
        .expect("the leftover child recorded its pid");

    // The session lifecycle does not treat a disconnect as a cancellation:
    // the leftover request keeps running well before its deadline.
    thread::sleep(Duration::from_millis(300));
    assert!(
        alive(pid),
        "a 2025 disconnect must not cancel the leftover request"
    );
    thread::sleep(Duration::from_millis(400));
    assert!(
        alive(pid),
        "a 2025 disconnect must not shorten the total deadline"
    );

    wait_for(
        || fixture.pid_gone("k1"),
        "the leftover request was never reaped",
    );
    let lived = fired.elapsed();
    println!("MEASURED disconnect-2025: pid={pid} lived={lived:?} (deadline 1500ms)");
    assert!(
        lived >= Duration::from_millis(1_400),
        "the leftover request died before its total deadline: {lived:?}"
    );
    assert!(
        lived < Duration::from_secs(15),
        "the leftover request outlived its total deadline: {lived:?}"
    );
    assert!(
        closed_at < Instant::now(),
        "the disconnect happened before the reclaim"
    );

    // The slot comes back and a neighbour completes.
    let next = fire_2025(
        &server,
        &session,
        2,
        "cass_search",
        json!({ "query": "k2" }),
        "k2",
    );
    wait_for(
        || fixture.ready("k2"),
        "the slot must return after the deadline reap",
    );
    fixture.release("k2");
    assert_success(&next.recv_tool(OBSERVE));
    assert_eq!(fixture.pids().len(), 2);
    assert!(fixture.live_pids().is_empty());
}

#[test]
fn a_2026_disconnect_cancels_the_request_before_its_deadline() {
    let fixture = Fixture::new("disconnect-2026");
    let server = start_server(&fixture, 1, 1, 60_000, 300);
    discover_2026(&server);

    let closed = fire_then_disconnect(
        &server,
        headers_2026("tools/call", Some("cass_search")),
        2,
        json!({
            "name": "cass_search",
            "arguments": { "query": "m1" },
            "_meta": meta_2026(),
        }),
        &fixture.dir,
        "m1",
    );
    let closed_at = closed
        .recv_timeout(OBSERVE)
        .expect("the test client must close its socket");
    let pid = fixture
        .pid_for("m1")
        .expect("the stateless child recorded its pid");

    // No session id: the disconnect cancels through the SDK token long before
    // the far total deadline.
    wait_for(
        || fixture.pid_gone("m1"),
        "the stateless request was not cancelled by the disconnect",
    );
    let killed = closed_at.elapsed();
    println!(
        "MEASURED disconnect-2026: pid={pid} cancelled_after_disconnect={killed:?} (deadline 60000ms)"
    );
    assert!(
        killed < Duration::from_secs(10),
        "the disconnect must cancel the request, not wait for the 60 s deadline: {killed:?}"
    );
    assert!(!alive(pid), "the cancelled child must be waited");

    // The slot is reusable after the wait.
    let next = fire_2026(&server, 3, "cass_search", json!({ "query": "m2" }), "m2");
    wait_for(
        || fixture.ready("m2"),
        "the slot must return after the cancelled wait",
    );
    fixture.release("m2");
    assert_success(&next.recv_tool(OBSERVE));
    assert_eq!(fixture.pids().len(), 2);
    assert!(fixture.live_pids().is_empty());
}
