//! Ticket 14 admission tests.
//!
//! Every test drives the real `cass-mcp` binary over real HTTP against a
//! controlled companion in the test's own temp directory. The companion
//! answers `--version`, records the exact PID of each business child, writes a
//! per-request `READY` file, and holds until the test writes that request's
//! release file. Nothing touches a production path, a model, a real database,
//! or another request's process.
//!
//! The pool order (FIFO, a new request never jumping the head) is proven
//! synchronously in the private `admission` unit tests. These tests prove the
//! service-level facts HTTP can observe: the number of real children never
//! exceeds P, at most Q requests may wait, the excess is refused with the fixed
//! `busy` code and no child, and every released slot admits exactly one new
//! child.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_cass-mcp");
const EXPECTED_CASS_VERSION: &str = "cass 0.6.17";
const PROTOCOL_2025: &str = "2025-11-25";
const PUBLIC_ORIGIN: &str = "http://public.example:8080";

/// Large enough that a legal envelope, its serialized tool result, and every
/// fixed error code fit. These tests are not about the byte budget.
const BUDGET: usize = 4096;

/// Observation limit used only to fail a deadlocked test; the product itself
/// gets no deadline from here (ticket 15 owns that).
const OBSERVE: Duration = Duration::from_secs(20);

/// How long a request that must still be waiting is observed before the test
/// continues. It is a bounded observation of "no answer yet", never the way the
/// queue order is decided.
const SETTLE: Duration = Duration::from_millis(750);

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
            "cass-mcp-t14-{label}-{}-{sequence}",
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
  overflow)
    trap '' TERM PIPE
    while [ ! -f "$dir/release.$token" ]; do sleep 0.02; done
    i=0
    while [ "$i" -lt 10 ]; do printf '%s' '{chunk}'; i=$((i+1)); done
    while :; do sleep 0.05; done
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
            chunk = "W".repeat(1000),
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
            "30000".to_string(),
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
const EXPAND_ENVELOPE: &str =
    r#"<cass_recall version="1" tool="cass_expand">[{"is_target":true}]</cass_recall>"#;
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

fn start_server(fixture: &Fixture, concurrent: usize, queued: usize, grace_ms: u64) -> ServerProc {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind");
    let mut child = Command::new(BIN)
        .args(fixture.args(bind, concurrent, queued, grace_ms))
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
        if self
            .header("content-type")
            .is_some_and(|value| value.contains("text/event-stream"))
        {
            sse_payloads(&self.body)
                .into_iter()
                .last()
                .unwrap_or_else(|| panic!("SSE response carried no JSON event: {}", self.body))
        } else {
            serde_json::from_str(&self.body)
                .unwrap_or_else(|error| panic!("invalid JSON body: {error}: {}", self.body))
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

fn post(
    address: SocketAddr,
    host: &str,
    extra_headers: &[(&str, &str)],
    body: &str,
) -> HttpResponse {
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).expect("connect to cass-mcp");
    stream
        .set_read_timeout(Some(OBSERVE))
        .expect("set read timeout");
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
    let raw = read_with_deadline(&mut stream);
    parse_http_response(&raw)
}

/// Read until the peer closes, bounded by [`OBSERVE`] in total. The timeout is
/// only the test's deadlock criterion.
fn read_with_deadline(stream: &mut TcpStream) -> Vec<u8> {
    let deadline = Instant::now() + OBSERVE;
    let mut raw = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "cass-mcp did not answer within {OBSERVE:?}"
        );
        stream
            .set_read_timeout(Some(remaining.min(Duration::from_millis(250))))
            .expect("set read timeout");
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buffer[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("read HTTP response: {error}"),
        }
    }
    raw
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

// ---------------------------------------------------------------------------
// Protocol helpers
// ---------------------------------------------------------------------------

fn headers_for(session: &str) -> Vec<(&str, &str)> {
    vec![
        ("MCP-Protocol-Version", PROTOCOL_2025),
        ("Mcp-Session-Id", session),
    ]
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
            "clientInfo": { "name": "cass-mcp-t14-test", "version": "1.0.0" }
        }
    })
    .to_string();
    let response = post(
        server.address,
        &host,
        &[("MCP-Protocol-Version", PROTOCOL_2025)],
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
    let response = post(server.address, &host, &headers_for(&session), &notification);
    assert_eq!(
        response.status, 202,
        "initialized notification body: {}",
        response.body
    );
    session
}

fn tool_result(mut payload: Value) -> Value {
    payload
        .get_mut("result")
        .map(Value::take)
        .unwrap_or_else(|| panic!("expected a JSON-RPC result, got {payload}"))
}

/// One `tools/call` issued from its own thread, so many can be in flight at
/// once. The result arrives on a channel; a still-blocked call has no message
/// yet.
struct Call {
    token: String,
    receiver: Receiver<Value>,
}

impl Call {
    fn settle(&self, window: Duration) -> Option<Value> {
        match self.receiver.recv_timeout(window) {
            Ok(value) => Some(value),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("call `{}` ended without a result", self.token)
            }
        }
    }

    fn recv(&self, window: Duration) -> Value {
        self.settle(window)
            .unwrap_or_else(|| panic!("call `{}` did not finish within {window:?}", self.token))
    }

    fn assert_still_waiting(&self) {
        assert!(
            self.settle(SETTLE).is_none(),
            "call `{}` was not held in the waiting queue",
            self.token
        );
    }
}

fn fire(
    server: &ServerProc,
    session: &str,
    id: u64,
    name: &'static str,
    arguments: Value,
    token: &str,
) -> Call {
    let address = server.address;
    let host = format!("127.0.0.1:{}", address.port());
    let session = session.to_string();
    let token = token.to_string();
    let (sender, receiver) = mpsc::channel();
    let thread_token = token.clone();
    thread::spawn(move || {
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        })
        .to_string();
        let response = post(address, &host, &headers_for(&session), &body);
        assert_eq!(
            response.status, 200,
            "tools/call `{thread_token}` body: {}",
            response.body
        );
        let _ = sender.send(tool_result(response.payload()));
    });
    Call { token, receiver }
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

/// Wait until exactly `expected` of these calls have answered, require every
/// answer to be the fixed `busy` refusal, and return the refused indices.
fn collect_busy(calls: &[&Call], expected: usize) -> Vec<usize> {
    let deadline = Instant::now() + OBSERVE;
    let mut refused = Vec::new();
    while refused.len() < expected {
        let mut progressed = false;
        for (index, call) in calls.iter().enumerate() {
            if refused.contains(&index) {
                continue;
            }
            if let Some(value) = call.settle(Duration::from_millis(25)) {
                assert_error_code(&value, "busy");
                refused.push(index);
                progressed = true;
            }
        }
        if !progressed {
            assert!(
                Instant::now() < deadline,
                "only {} of {expected} over-capacity calls were refused; \
                 the pool admitted more than P children",
                refused.len()
            );
        }
    }
    refused
}

// ---------------------------------------------------------------------------
// 14-AC1 / 14-AC2: one slot, one queue position
// ---------------------------------------------------------------------------

#[test]
fn one_slot_and_one_queue_position_bound_the_service() {
    let fixture = Fixture::new("p1q1");
    let server = start_server(&fixture, 1, 1, 400);
    let session_a = initialize(&server);
    let session_b = initialize(&server);

    // The admitted call holds the only slot.
    let holder = fire(
        &server,
        &session_a,
        1,
        "cass_search",
        json!({ "query": "q1" }),
        "q1",
    );
    wait_for(|| fixture.ready("q1"), "the admitted call never started");
    assert_eq!(
        fixture.pids().len(),
        1,
        "exactly one business child before any release"
    );

    // Two more calls compete for the single queue position.
    let second = fire(
        &server,
        &session_a,
        2,
        "cass_search",
        json!({ "query": "q2" }),
        "q2",
    );
    let third = fire(
        &server,
        &session_b,
        3,
        "cass_search",
        json!({ "query": "q3" }),
        "q3",
    );

    // Exactly one of the two is refused; which one depends only on arrival
    // order, which this test never uses as an ordering signal.
    let contenders = [&second, &third];
    let refused = collect_busy(&contenders, 1);
    let refused_call = contenders[refused[0]];
    let waiting_call = contenders[1 - refused[0]];

    // The refusal started no child, and the waiting call has not started one.
    assert!(
        fixture.pid_for(&refused_call.token).is_none(),
        "a busy refusal must not create a business child"
    );
    assert!(!fixture.ready(&refused_call.token));
    assert!(
        !fixture.ready(&waiting_call.token),
        "a waiting call must not start a child while the slot is held"
    );
    assert_eq!(fixture.pids().len(), 1, "no queueing or refusal may spawn");
    waiting_call.assert_still_waiting();

    // Releasing the holder admits exactly one waiting call.
    fixture.release("q1");
    assert_success(&holder.recv(OBSERVE));
    assert!(
        fixture.pid_gone("q1"),
        "the released child must be waited before the pool advances"
    );
    wait_for(
        || fixture.ready(&waiting_call.token),
        "the waiting call must start once the slot is released",
    );
    assert_eq!(
        fixture.pids().len(),
        2,
        "one release may admit exactly one waiting call"
    );
    assert!(
        !fixture.ready(&refused_call.token),
        "a refused call must never start later"
    );
    assert_eq!(fixture.live_pids().len(), 1, "live children never exceed P");

    // Releasing the second call empties the pool again.
    let waiting_token = waiting_call.token.clone();
    fixture.release(&waiting_token);
    assert_success(&waiting_call.recv(OBSERVE));
    assert!(fixture.pid_gone(&waiting_token));
    assert_eq!(
        fixture.pids().len(),
        2,
        "the fleet never exceeded P plus one"
    );
}

// ---------------------------------------------------------------------------
// 14-AC1 / 14-AC2: two slots, two queue positions, all four tools
// ---------------------------------------------------------------------------

#[test]
fn two_slots_and_two_queue_positions_are_shared_by_every_tool_and_session() {
    let fixture = Fixture::new("p2q2");
    let server = start_server(&fixture, 2, 2, 400);
    let session_a = initialize(&server);
    let session_b = initialize(&server);

    // Both admitted calls use the same JSON-RPC id in different sessions: the
    // pool must not key on a bare request id.
    let holder_search = fire(
        &server,
        &session_a,
        7,
        "cass_search",
        json!({ "query": "q1" }),
        "q1",
    );
    let holder_sessions = fire(
        &server,
        &session_b,
        7,
        "cass_sessions",
        json!({ "limit": 701 }),
        "701",
    );
    wait_for(
        || fixture.ready("q1") && fixture.ready("701"),
        "both slots must be occupied",
    );
    assert_eq!(fixture.pids().len(), 2, "P children at most");

    // Two calls wait in the queue; the next two must be refused. Together they
    // cover the remaining two tools, so one shared pool serves all four.
    let expand = fire(
        &server,
        &session_a,
        8,
        "cass_expand",
        json!({
            "message_id": 702,
            "source_id": "source-1",
            "source_path": "/tmp/source.jsonl",
            "expected_content_sha256": "0".repeat(64),
        }),
        "702",
    );
    let timeline = fire(
        &server,
        &session_b,
        9,
        "cass_timeline",
        json!({ "group_by": "none" }),
        "none",
    );
    let search = fire(
        &server,
        &session_a,
        10,
        "cass_search",
        json!({ "query": "q5" }),
        "q5",
    );
    let sessions = fire(
        &server,
        &session_b,
        11,
        "cass_sessions",
        json!({ "limit": 705 }),
        "705",
    );

    let mut contenders: Vec<Option<Call>> =
        vec![Some(expand), Some(timeline), Some(search), Some(sessions)];
    let refused = {
        let refs: Vec<&Call> = contenders
            .iter()
            .map(|call| call.as_ref().expect("contender"))
            .collect();
        collect_busy(&refs, 2)
    };
    for index in &refused {
        let call = contenders[*index].as_ref().expect("contender");
        assert!(
            fixture.pid_for(&call.token).is_none(),
            "a busy refusal must not create a business child"
        );
        assert!(!fixture.ready(&call.token));
    }
    let mut waiting: Vec<usize> = (0..contenders.len())
        .filter(|index| !refused.contains(index))
        .collect();
    for index in &waiting {
        let call = contenders[*index].as_ref().expect("contender");
        assert!(
            !fixture.ready(&call.token),
            "a waiting call must not start a child while both slots are held"
        );
        call.assert_still_waiting();
    }
    assert_eq!(
        fixture.pids().len(),
        2,
        "no queued or refused call may spawn"
    );
    assert_eq!(fixture.live_pids().len(), 2, "live children never exceed P");

    // Release one slot at a time; each must admit exactly one waiting call, and
    // every admitted call must come from the waiting set.
    let mut holders = vec![holder_search, holder_sessions];
    for round in 1..=2 {
        let holder = holders.remove(0);
        let token = holder.token.clone();
        fixture.release(&token);
        assert_success(&holder.recv(OBSERVE));
        assert!(fixture.pid_gone(&token), "a released child must be waited");
        wait_for(
            || fixture.pids().len() == 2 + round,
            "one release must admit exactly one waiting call",
        );
        assert_eq!(
            fixture.live_pids().len(),
            2,
            "the live fleet must stay at P during a handover"
        );
        let started = waiting
            .iter()
            .position(|index| fixture.ready(&contenders[*index].as_ref().expect("contender").token))
            .unwrap_or_else(|| panic!("no waiting call was admitted in round {round}"));
        let admitted = waiting.remove(started);
        holders.push(contenders[admitted].take().expect("contender"));
    }
    assert!(waiting.is_empty(), "both waiting calls were admitted");
    for index in &refused {
        assert!(
            !fixture.ready(&contenders[*index].as_ref().expect("contender").token),
            "a refused call must never start later"
        );
    }

    for holder in holders {
        let token = holder.token.clone();
        fixture.release(&token);
        assert_success(&holder.recv(OBSERVE));
        assert!(fixture.pid_gone(&token));
    }
    assert_eq!(
        fixture.pids().len(),
        4,
        "exactly P plus Q business children"
    );
    assert!(fixture.live_pids().is_empty(), "every child was reaped");
}

// ---------------------------------------------------------------------------
// 14-AC2 / 14-AC3: invalid input is decided before admission
// ---------------------------------------------------------------------------

#[test]
fn invalid_input_is_not_an_admission_decision() {
    let fixture = Fixture::new("invalid");
    let server = start_server(&fixture, 1, 1, 400);
    let session = initialize(&server);

    let holder = fire(
        &server,
        &session,
        1,
        "cass_search",
        json!({ "query": "q1" }),
        "q1",
    );
    wait_for(|| fixture.ready("q1"), "the admitted call never started");

    // Fill the queue, then prove the pool is full with one more refusal.
    let second = fire(
        &server,
        &session,
        2,
        "cass_search",
        json!({ "query": "q2" }),
        "q2",
    );
    let third = fire(
        &server,
        &session,
        3,
        "cass_search",
        json!({ "query": "q3" }),
        "q3",
    );
    let contenders = [&second, &third];
    let refused = collect_busy(&contenders, 1);
    let refused_call = contenders[refused[0]];
    let waiting_call = contenders[1 - refused[0]];
    assert!(
        fixture.pid_for(&refused_call.token).is_none(),
        "a busy refusal must not create a business child"
    );
    waiting_call.assert_still_waiting();

    // The pool is full, yet an illegal input is still a parse error.
    let host = format!("127.0.0.1:{}", server.address.port());
    for arguments in [
        json!({ "query": "ok", "unknown_field": 1 }),
        json!({}),
        json!({ "query": "   " }),
        json!({ "query": "ok", "since": "no offset" }),
    ] {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": { "name": "cass_search", "arguments": arguments },
        })
        .to_string();
        let response = post(server.address, &host, &headers_for(&session), &body);
        assert_eq!(response.status, 200, "body: {}", response.body);
        assert_error_code(&tool_result(response.payload()), "invalid_argument");
    }
    assert_eq!(
        fixture.pids().len(),
        1,
        "an invalid input must never start a business child"
    );

    fixture.release("q1");
    assert_success(&holder.recv(OBSERVE));
    let waiting_token = waiting_call.token.clone();
    fixture.release(&waiting_token);
    assert_success(&waiting_call.recv(OBSERVE));
}

// ---------------------------------------------------------------------------
// 14-AC1: a reaping child keeps its slot until its wait completes
// ---------------------------------------------------------------------------

#[test]
fn a_reaping_child_keeps_the_slot_until_it_is_waited() {
    let fixture = Fixture::new("reaping");
    fixture.set_mode("q1", "overflow");
    let server = start_server(&fixture, 1, 1, 200);
    let session_a = initialize(&server);
    let session_b = initialize(&server);

    let overflowing = fire(
        &server,
        &session_a,
        1,
        "cass_search",
        json!({ "query": "q1" }),
        "q1",
    );
    wait_for(|| fixture.ready("q1"), "the overflowing call never started");
    let overflow_pid = fixture
        .pid_for("q1")
        .expect("the overflowing child recorded its pid");

    // While the child is still running, the pool holds its slot.
    let second = fire(
        &server,
        &session_b,
        2,
        "cass_search",
        json!({ "query": "q2" }),
        "q2",
    );
    let third = fire(
        &server,
        &session_b,
        3,
        "cass_search",
        json!({ "query": "q3" }),
        "q3",
    );
    let contenders = [&second, &third];
    let refused = collect_busy(&contenders, 1);
    let refused_call = contenders[refused[0]];
    let waiting_call = contenders[1 - refused[0]];
    assert!(
        fixture.pid_for(&refused_call.token).is_none(),
        "a busy refusal must not create a business child"
    );
    assert!(
        !fixture.ready(&waiting_call.token),
        "a waiting call must not start while the child is reaping"
    );
    assert_eq!(fixture.pids().len(), 1, "reaping never adds a child");
    assert!(
        alive(overflow_pid),
        "the overflowing child must still be running"
    );

    // Start the overflow. The error is published only after SIGTERM was
    // ignored, the grace expired, the child was killed, and `wait` returned.
    let released_at = Instant::now();
    fixture.release("q1");
    assert_error_code(&overflowing.recv(OBSERVE), "result_too_large");
    let elapsed = released_at.elapsed();
    assert!(
        elapsed >= Duration::from_millis(150),
        "the ignored SIGTERM must consume the configured grace, took {elapsed:?}"
    );
    assert!(
        fixture.pid_gone("q1"),
        "the slot may only be released after the child was waited"
    );

    // Only now may the waiting call start, and exactly one may start.
    wait_for(
        || fixture.ready(&waiting_call.token),
        "the waiting call must start after the reaping child was waited",
    );
    assert_eq!(fixture.pids().len(), 2, "one release admits one call");
    let waiting_token = waiting_call.token.clone();
    fixture.release(&waiting_token);
    assert_success(&waiting_call.recv(OBSERVE));
    assert!(fixture.pid_gone(&waiting_token));
}

// ---------------------------------------------------------------------------
// 14-AC1: every failure path returns the slot
// ---------------------------------------------------------------------------

#[test]
fn spawn_failure_and_cli_failure_return_the_slot() {
    let fixture = Fixture::new("release");
    let server = start_server(&fixture, 1, 1, 400);
    let session = initialize(&server);
    let host = format!("127.0.0.1:{}", server.address.port());

    let call = |id: u64, query: &str| {
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": "cass_search", "arguments": { "query": query } },
        })
        .to_string();
        let response = post(server.address, &host, &headers_for(&session), &body);
        assert_eq!(response.status, 200, "body: {}", response.body);
        tool_result(response.payload())
    };

    // The version probe already passed; now the companion cannot be executed.
    fixture.set_cass_mode(0o000);
    assert_error_code(&call(1, "spawn-1"), "cass_exit");
    assert_error_code(&call(2, "spawn-2"), "cass_exit");
    assert!(
        fixture.pids().is_empty(),
        "a failed spawn never creates a business child"
    );

    // After the companion can run again, the slot is still usable.
    fixture.set_cass_mode(0o755);
    fixture.set_mode("ok", "answer");
    assert_success(&call(3, "ok"));
    assert_eq!(fixture.pids().len(), 1);

    // A non-zero CLI exit also returns the slot.
    fixture.set_mode("cli-fail", "answer");
    fixture.set_answer("search", "", "", 5);
    let failed = call(4, "cli-fail");
    assert_error_code(&failed, "cass_exit");
    let body: Value = serde_json::from_str(result_text(&failed)).expect("error json");
    assert_eq!(body["error"]["cli_exit_code"], 5);
    assert_eq!(fixture.pids().len(), 2);

    // The next call still runs, so the slot was released exactly once.
    fixture.set_answer("search", SEARCH_ENVELOPE, "", 0);
    fixture.set_mode("ok2", "answer");
    assert_success(&call(5, "ok2"));
    assert_eq!(fixture.pids().len(), 3);
}
