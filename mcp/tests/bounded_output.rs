//! Ticket 13 bounded-output tests.
//!
//! Every test drives the real `cass-mcp` binary over real HTTP. The companion
//! CASS binary is a controlled shell script in the test's own temp directory:
//! it answers `--version`, records each business child PID, and either prints a
//! fixed response or streams a selected number of bytes while keeping the pipe
//! open until the test releases it. Nothing touches a production path, a model,
//! or another request's process.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rmcp::model::CallToolResult;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_cass-mcp");
const EXPECTED_CASS_VERSION: &str = "cass 0.6.17";
const PROTOCOL_2025: &str = "2025-11-25";
const PUBLIC_ORIGIN: &str = "http://public.example:8080";

/// The smallest budget the product accepts: every fixed error code stays
/// representable after the optional message and CLI exit status are removed.
const MIN_BUDGET: usize = 125;

/// Observation limit used only to fail a deadlocked test; the product itself
/// gets no deadline from here (ticket 15 owns that).
const OBSERVE: Duration = Duration::from_secs(20);

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Controlled companion process
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum Producer {
    /// Print the fixture's fixed stdout/stderr/exit and terminate.
    Static,
    /// Write exactly `bytes` bytes to stdout, then stop writing and hold the
    /// pipe open until the release file appears. Stopping before the server
    /// closes the read end keeps a SIGPIPE from ending the child first.
    /// `ignore_term` makes only SIGKILL work.
    HoldStdout { bytes: usize, ignore_term: bool },
    /// The same on stderr.
    HoldStderr { bytes: usize, ignore_term: bool },
    /// Interleave two streams so each stays below the budget while the total
    /// exceeds it, then hold both pipes open.
    HoldBoth { bytes_each: usize },
    /// Flood stdout past the budget and exit non-zero immediately.
    FloodThenExit {
        chunks: usize,
        chunk: String,
        exit: i32,
    },
}

struct Fixture {
    dir: PathBuf,
    cass_bin: PathBuf,
    data_dir: PathBuf,
    api_config: PathBuf,
    home: PathBuf,
    pids: PathBuf,
    ready: PathBuf,
    release: PathBuf,
    response: PathBuf,
    response_stderr: PathBuf,
    response_exit: PathBuf,
}

impl Fixture {
    fn new(label: &str, producer: Producer) -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "cass-mcp-t13-{label}-{}-{sequence}",
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
            pids: dir.join("pids"),
            ready: dir.join("ready"),
            release: dir.join("release"),
            response: dir.join("response.stdout"),
            response_stderr: dir.join("response.stderr"),
            response_exit: dir.join("response.exit"),
            dir,
            data_dir,
            api_config,
            home,
        };
        fixture.answer("", "", 0);
        fixture.install(&producer);
        fixture
    }

    fn answer(&self, stdout: &str, stderr: &str, exit: i32) {
        fs::write(&self.response, stdout).expect("write response stdout");
        fs::write(&self.response_stderr, stderr).expect("write response stderr");
        fs::write(&self.response_exit, format!("{exit}\n")).expect("write response exit");
    }

    fn install(&self, producer: &Producer) {
        let static_body = format!(
            "cat '{stdout}'\ncat '{stderr}' >&2\nexit \"$(cat '{exit}')\"\n",
            stdout = self.response.display(),
            stderr = self.response_stderr.display(),
            exit = self.response_exit.display(),
        );
        let trap = match producer {
            Producer::HoldStdout {
                ignore_term: true, ..
            }
            | Producer::HoldStderr {
                ignore_term: true, ..
            } => "trap '' TERM\n",
            _ => "",
        };
        let body = match producer {
            Producer::Static => static_body.clone(),
            Producer::HoldStdout { bytes, .. } => format!(
                "if [ \"$1\" = \"sessions\" ]; then\n\
                 printf 'READY\\n' > '{ready}'\n\
                 {writer}\
                 while [ ! -f '{release}' ]; do sleep 0.05; done\n\
                 exit 0\n\
                 fi\n{static_body}",
                ready = self.ready.display(),
                release = self.release.display(),
                writer = exact_writer(*bytes, ""),
            ),
            Producer::HoldStderr { bytes, .. } => format!(
                "if [ \"$1\" = \"sessions\" ]; then\n\
                 printf 'READY\\n' > '{ready}'\n\
                 {writer}\
                 while [ ! -f '{release}' ]; do sleep 0.05; done\n\
                 exit 0\n\
                 fi\n{static_body}",
                ready = self.ready.display(),
                release = self.release.display(),
                writer = exact_writer(*bytes, ">&2"),
            ),
            Producer::HoldBoth { bytes_each } => format!(
                "if [ \"$1\" = \"sessions\" ]; then\n\
                 printf 'READY\\n' > '{ready}'\n\
                 i=0\n\
                 while [ \"$i\" -lt {chunks} ]; do printf '%s' '{chunk}'; printf '%s' '{chunk}' >&2; i=$((i+1)); done\n\
                 while [ ! -f '{release}' ]; do sleep 0.05; done\n\
                 exit 0\n\
                 fi\n{static_body}",
                ready = self.ready.display(),
                release = self.release.display(),
                chunks = bytes_each / 1024,
                chunk = chunk_of(b'A', 1024),
            ),
            Producer::FloodThenExit {
                chunks,
                chunk,
                exit,
            } => format!(
                "i=0\n\
                 while [ \"$i\" -lt {chunks} ]; do printf '%s' '{chunk}'; i=$((i+1)); done\n\
                 exit {exit}\n"
            ),
        };
        let script = format!(
            "#!/bin/sh\n\
             {trap}\
             if [ \"$1\" = \"--version\" ]; then printf '%s\\n' '{version}'; exit 0; fi\n\
             printf '%s\\n' \"$$\" >> '{pids}'\n\
             {body}",
            version = EXPECTED_CASS_VERSION,
            pids = self.pids.display(),
        );
        fs::write(&self.cass_bin, script).expect("write fake cass binary");
        set_mode(&self.cass_bin, 0o755);
    }

    fn args(&self, bind: SocketAddr, budget: usize, grace_ms: u64) -> Vec<String> {
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
            "2".to_string(),
            "--max-queued".to_string(),
            "2".to_string(),
            "--max-output-bytes".to_string(),
            budget.to_string(),
            "--request-timeout-ms".to_string(),
            "30000".to_string(),
            "--terminate-grace-ms".to_string(),
            grace_ms.to_string(),
            "--public-origin".to_string(),
            PUBLIC_ORIGIN.to_string(),
        ]
    }

    fn business_pids(&self) -> Vec<i32> {
        fs::read_to_string(&self.pids)
            .map(|text| {
                text.lines()
                    .filter_map(|line| line.trim().parse::<i32>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn release(&self) {
        let _ = fs::write(&self.release, b"release\n");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Unblock any producer still holding a pipe, then terminate only the
        // PIDs this fixture recorded.
        self.release();
        for pid in self.business_pids() {
            if pid_alive(pid) {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn pid_alive(pid: i32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

fn set_mode(path: &Path, mode: u32) {
    let mut permissions = fs::metadata(path).expect("stat fixture").permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).expect("chmod fixture");
}

fn chunk_of(byte: u8, size: usize) -> String {
    String::from_utf8(vec![byte; size]).expect("ascii chunk")
}

/// POSIX sh statements that write exactly `bytes` bytes to stdout (or to the
/// given redirect) and then stop writing, so closing the read end cannot
/// terminate the child with SIGPIPE before the reaping path is observed.
fn exact_writer(bytes: usize, redirect: &str) -> String {
    let chunk = chunk_of(b'W', 1024);
    let full = bytes / 1024;
    let tail = chunk_of(b'T', bytes % 1024);
    format!(
        "i=0\n\
         while [ \"$i\" -lt {full} ]; do printf '%s' '{chunk}' {redirect}; i=$((i+1)); done\n\
         printf '%s' '{tail}' {redirect}\n"
    )
}

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

fn start_server(fixture: &Fixture, budget: usize, grace_ms: u64) -> ServerProc {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind");
    let mut child = Command::new(BIN)
        .args(fixture.args(bind, budget, grace_ms))
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
/// only the test's deadlock criterion: an in-flight SSE stream sends keep-alive
/// events, so a per-read timeout alone would never fire.
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

struct Client {
    address: SocketAddr,
    host: String,
    next_id: u64,
}

impl Client {
    fn new(server: &ServerProc) -> Self {
        Self {
            address: server.address,
            host: format!("127.0.0.1:{}", server.address.port()),
            next_id: 1,
        }
    }

    fn id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn initialize(&mut self) -> String {
        let body = json!({
            "jsonrpc": "2.0",
            "id": self.id(),
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_2025,
                "capabilities": {},
                "clientInfo": { "name": "cass-mcp-t13-test", "version": "1.0.0" }
            }
        })
        .to_string();
        let response = post(
            self.address,
            &self.host,
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
        let response = post(
            self.address,
            &self.host,
            &[
                ("MCP-Protocol-Version", PROTOCOL_2025),
                ("Mcp-Session-Id", session.as_str()),
            ],
            &notification,
        );
        assert_eq!(
            response.status, 202,
            "initialized notification body: {}",
            response.body
        );
        session
    }

    fn call(&mut self, session: &str, name: &str, arguments: Value) -> Value {
        let body = json!({
            "jsonrpc": "2.0",
            "id": self.id(),
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        })
        .to_string();
        let response = post(
            self.address,
            &self.host,
            &[
                ("MCP-Protocol-Version", PROTOCOL_2025),
                ("Mcp-Session-Id", session),
            ],
            &body,
        );
        assert_eq!(response.status, 200, "tools/call body: {}", response.body);
        let mut value = response.payload();
        value
            .get_mut("result")
            .map(Value::take)
            .unwrap_or_else(|| panic!("expected a JSON-RPC result, got {value}"))
    }
}

fn session_client(server: &ServerProc) -> (Client, String) {
    let mut client = Client::new(server);
    let session = client.initialize();
    (client, session)
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
    assert_eq!(content[0]["type"], "text", "text block expected: {result}");
    content[0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("text block has no string text: {result}"))
}

fn error_body(result: &Value) -> Value {
    let value: Value = serde_json::from_str(result_text(result))
        .unwrap_or_else(|error| panic!("error text is not JSON: {error}"));
    assert!(
        value.get("error").is_some_and(Value::is_object),
        "error text must carry one error object: {value}"
    );
    value
}

fn assert_error_code(result: &Value, code: &str) {
    assert_eq!(result["isError"], true, "expected isError=true: {result}");
    let value = error_body(result);
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
    assert!(
        result.get("structuredContent").is_none(),
        "no structuredContent may duplicate the text: {result}"
    );
}

/// Bytes of the 2026 tool result this text would produce. The SDK constructor
/// carries `resultType: complete`, so this is the larger shape the budget is
/// measured against; an older protocol drops the field and can only shrink.
fn sdk_success_len(text: &str) -> usize {
    let result = CallToolResult::success(vec![rmcp::model::ContentBlock::text(text.to_string())]);
    serde_json::to_vec(&result)
        .expect("serialize SDK tool result")
        .len()
}

/// The same measurement for a received result, restored to the 2026 shape.
fn canonical_wire_len(result: &Value) -> usize {
    let mut parsed: CallToolResult =
        serde_json::from_value(result.clone()).expect("result deserializes as a tool result");
    parsed.result_type = Some(rmcp::model::ResultType::COMPLETE);
    serde_json::to_vec(&parsed)
        .expect("serialize SDK tool result")
        .len()
}

// ---------------------------------------------------------------------------
// Fixed legal payloads
// ---------------------------------------------------------------------------

const SESSIONS_EMPTY: &str =
    r#"<cass_recall version="1" tool="cass_sessions">{&quot;sessions&quot;:[]}</cass_recall>"#;
const TIMELINE_EMPTY: &str = r#"<cass_recall version="1" tool="cass_timeline">{&quot;range&quot;:{&quot;start&quot;:0,&quot;end&quot;:0},&quot;total_sessions&quot;:0,&quot;groups&quot;:{}}</cass_recall>"#;

/// A legal C04 envelope whose JSON text needs heavy escaping: quotes,
/// backslashes, multi-byte characters, and XML metacharacters.
fn decorated_envelope() -> String {
    let payload = json!({
        "sessions": [{
            "note": "quote \" backslash \\ 中文 ünïcode",
            "title": "<tag> & \"quoted\""
        }]
    })
    .to_string();
    let escaped = payload
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;");
    format!(r#"<cass_recall version="1" tool="cass_sessions">{escaped}</cass_recall>"#)
}

/// A legal C04 envelope with many multi-byte characters.
fn multibyte_envelope() -> String {
    let payload = json!({ "sessions": [{ "note": "中".repeat(400) }] }).to_string();
    let escaped = payload.replace('"', "&quot;");
    format!(r#"<cass_recall version="1" tool="cass_sessions">{escaped}</cass_recall>"#)
}

fn wait_until(deadline: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if check() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    check()
}

// ---------------------------------------------------------------------------
// 13-AC1: both streams are bounded while they are still being read
// ---------------------------------------------------------------------------

#[test]
fn streaming_stdout_over_budget_fails_before_producer_eof() {
    let budget = 4096usize;
    let fixture = Fixture::new(
        "stdout",
        Producer::HoldStdout {
            bytes: budget + 1,
            ignore_term: false,
        },
    );
    let server = start_server(&fixture, budget, 1000);
    let (mut client, session) = session_client(&server);

    let result = client.call(&session, "cass_sessions", json!({}));

    assert_error_code(&result, "result_too_large");
    assert!(
        !fixture.release.exists(),
        "the server must answer before the producer is released"
    );
    fixture.release();
    for pid in fixture.business_pids() {
        assert!(
            wait_until(Duration::from_secs(5), || !pid_alive(pid)),
            "child {pid} must be reaped before the response is published"
        );
    }
}

#[test]
fn streaming_stderr_over_budget_fails_before_producer_eof() {
    let budget = 4096usize;
    let fixture = Fixture::new(
        "stderr",
        Producer::HoldStderr {
            bytes: budget + 1,
            ignore_term: false,
        },
    );
    let server = start_server(&fixture, budget, 1000);
    let (mut client, session) = session_client(&server);

    let result = client.call(&session, "cass_sessions", json!({}));

    assert_error_code(&result, "result_too_large");
    assert!(
        !fixture.release.exists(),
        "the server must answer before the producer is released"
    );
    fixture.release();
    for pid in fixture.business_pids() {
        assert!(
            wait_until(Duration::from_secs(5), || !pid_alive(pid)),
            "child {pid} must be reaped before the response is published"
        );
    }
}

#[test]
fn combined_streams_over_budget_drains_both_pipes() {
    let budget = 10_000usize;
    // 6 * 1024 bytes on each stream: 6144 < 10000 per stream, 12288 > 10000
    // in total, and the producer never closes either pipe.
    let fixture = Fixture::new("combined", Producer::HoldBoth { bytes_each: 6144 });
    let server = start_server(&fixture, budget, 1000);
    let (mut client, session) = session_client(&server);

    let result = client.call(&session, "cass_sessions", json!({}));

    assert_error_code(&result, "result_too_large");
    assert!(
        !fixture.release.exists(),
        "the combined budget must trip while both producers still hold"
    );
    fixture.release();
    for pid in fixture.business_pids() {
        assert!(
            wait_until(Duration::from_secs(5), || !pid_alive(pid)),
            "child {pid} must be reaped before the response is published"
        );
    }
}

// ---------------------------------------------------------------------------
// 13-AC2: the final serialized tool result has its own budget
// ---------------------------------------------------------------------------

#[test]
fn serialized_result_inflation_reports_result_too_large_exact_boundary() {
    let raw = decorated_envelope();
    let wire = sdk_success_len(&raw);
    assert!(
        wire > MIN_BUDGET,
        "the decorated sample must leave room above the minimum budget"
    );
    assert!(
        raw.len() < wire,
        "the raw bytes must fit the read budget; only the serialized result may exceed"
    );

    // Exactly at the serialized boundary: success, text unchanged.
    let fixture = Fixture::new("exact", Producer::Static);
    fixture.answer(&raw, "", 0);
    let server = start_server(&fixture, wire, 1000);
    let (mut client, session) = session_client(&server);
    let result = client.call(&session, "cass_sessions", json!({}));
    assert_success(&result);
    assert_eq!(result_text(&result), raw);
    assert_eq!(canonical_wire_len(&result), wire);

    // One byte over the serialized boundary: result_too_large, no partial body.
    let fixture = Fixture::new("under", Producer::Static);
    fixture.answer(&raw, "", 0);
    let server = start_server(&fixture, wire - 1, 1000);
    let (mut client, session) = session_client(&server);
    let result = client.call(&session, "cass_sessions", json!({}));
    assert_error_code(&result, "result_too_large");
    assert!(
        canonical_wire_len(&result) < wire,
        "the replacement error must itself fit the budget"
    );
    assert!(
        !result_text(&result).contains("cass_recall"),
        "no partial recall body may be forwarded: {result}"
    );
}

#[test]
fn multibyte_output_is_counted_in_bytes() {
    let raw = multibyte_envelope();
    let budget = 800usize;
    assert!(raw.len() > budget, "byte length must exceed the budget");
    assert!(
        raw.chars().count() < budget,
        "a character count would wrongly accept this sample"
    );

    let fixture = Fixture::new("multibyte", Producer::Static);
    fixture.answer(&raw, "", 0);
    let server = start_server(&fixture, budget, 1000);
    let (mut client, session) = session_client(&server);

    let result = client.call(&session, "cass_sessions", json!({}));
    assert_error_code(&result, "result_too_large");
}

// ---------------------------------------------------------------------------
// 13-AC1/AC2 low-budget errors: code preserved, optional fields removed
// ---------------------------------------------------------------------------

#[test]
fn low_budget_errors_keep_their_code_and_drop_optional_fields() {
    // Input validation error at the minimum budget: no process starts.
    let fixture = Fixture::new("low-input", Producer::Static);
    let server = start_server(&fixture, MIN_BUDGET, 1000);
    let (mut client, session) = session_client(&server);
    let result = client.call(&session, "cass_sessions", json!({ "limit": 0 }));
    assert_error_code(&result, "invalid_argument");
    assert!(
        canonical_wire_len(&result) <= MIN_BUDGET,
        "the input error must fit the minimum budget"
    );
    assert!(
        fixture.business_pids().is_empty(),
        "invalid input must not start the companion process"
    );

    // CLI failure at the minimum budget: the mapped code survives, the
    // optional message and CLI exit status are removed to fit.
    let fixture = Fixture::new("low-cli", Producer::Static);
    fixture.answer("", r#"{"error":{"kind":"model_unavailable"}}"#, 9);
    let server = start_server(&fixture, MIN_BUDGET, 1000);
    let (mut client, session) = session_client(&server);
    let result = client.call(&session, "cass_sessions", json!({}));
    assert_error_code(&result, "model_unavailable");
    let body = error_body(&result);
    assert!(
        body["error"].get("cli_exit_code").is_none(),
        "the CLI exit status is optional and must be dropped at the minimum budget: {body}"
    );
    assert!(
        canonical_wire_len(&result) <= MIN_BUDGET,
        "the degraded error must fit the minimum budget"
    );
    assert_eq!(fixture.business_pids().len(), 1);

    // A legal success cannot fit the minimum budget: it becomes one
    // result_too_large error that itself fits.
    let fixture = Fixture::new("low-success", Producer::Static);
    fixture.answer(SESSIONS_EMPTY, "", 0);
    let server = start_server(&fixture, MIN_BUDGET, 1000);
    let (mut client, session) = session_client(&server);
    let result = client.call(&session, "cass_sessions", json!({}));
    assert_error_code(&result, "result_too_large");
    assert!(
        canonical_wire_len(&result) <= MIN_BUDGET,
        "the replacement error must fit the minimum budget"
    );
}

#[test]
fn over_budget_wins_over_a_nonzero_exit() {
    let budget = 2048usize;
    let fixture = Fixture::new(
        "priority",
        Producer::FloodThenExit {
            chunks: 4,
            chunk: chunk_of(b'C', 1024),
            exit: 9,
        },
    );
    let server = start_server(&fixture, budget, 1000);
    let (mut client, session) = session_client(&server);

    let result = client.call(&session, "cass_sessions", json!({}));

    assert_error_code(&result, "result_too_large");
    for pid in fixture.business_pids() {
        assert!(
            wait_until(Duration::from_secs(5), || !pid_alive(pid)),
            "child {pid} must be reaped before the response is published"
        );
    }
}

// ---------------------------------------------------------------------------
// 13-AC3: only the request's own child is terminated, and wait completes
// ---------------------------------------------------------------------------

#[test]
fn term_ignoring_child_is_killed_after_grace_and_neighbor_request_succeeds() {
    let budget = 4096usize;
    let grace_ms = 200u64;
    let fixture = Fixture::new(
        "ignore-term",
        Producer::HoldStdout {
            bytes: budget + 1,
            ignore_term: true,
        },
    );
    // The neighbor tool takes the static branch of the same script.
    fixture.answer(TIMELINE_EMPTY, "", 0);
    let server = start_server(&fixture, budget, grace_ms);

    // Two sessions on the same shared runner: one is the over-limit request,
    // the other is a neighbor that must complete while the first is reaped.
    let (mut holder, holder_session) = session_client(&server);
    let (mut neighbor, neighbor_session) = session_client(&server);

    let holder_call =
        thread::spawn(move || holder.call(&holder_session, "cass_sessions", json!({})));

    assert!(
        wait_until(Duration::from_secs(10), || fixture.ready.exists()),
        "the controlled producer never reported READY"
    );
    let neighbor_result = neighbor.call(&neighbor_session, "cass_timeline", json!({}));
    assert_success(&neighbor_result);
    assert_eq!(result_text(&neighbor_result), TIMELINE_EMPTY);

    let holder_result = holder_call.join().expect("holder request thread");
    assert_error_code(&holder_result, "result_too_large");
    assert!(
        !fixture.release.exists(),
        "the over-limit request must not wait for the producer to be released"
    );
    fixture.release();

    let holder_pid = fixture.business_pids()[0];
    assert!(
        !pid_alive(holder_pid),
        "the TERM-ignoring child {holder_pid} must be force-killed and waited before the response"
    );
}
