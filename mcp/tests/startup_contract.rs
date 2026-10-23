//! Startup contract tests for the `cass-mcp` companion binary.
//!
//! Every test drives the real binary in its own sandbox: unique directories,
//! unique `HOME`/`XDG_*` values, and a port-0 listener. The companion CASS
//! binary is a recording fixture that only answers `--version`.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rmcp::model::CallToolResult;

const BIN: &str = env!("CARGO_BIN_EXE_cass-mcp");
const MCP_VERSION_WORD: &str = "cass-mcp 0.6.17";
const EXPECTED_CASS_VERSION: &str = "cass 0.6.17";
const PROTOCOL_VERSION: &str = "2025-11-25";
const PUBLIC_ORIGIN: &str = "http://public.example:8080";

const OPTIONS: &[&str] = &[
    "--bind",
    "--cass-bin",
    "--data-dir",
    "--api-config",
    "--embedding-profile",
    "--rerank-profile",
    "--max-concurrent",
    "--max-queued",
    "--max-output-bytes",
    "--request-timeout-ms",
    "--terminate-grace-ms",
    "--public-origin",
];

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Sandbox and fixture
// ---------------------------------------------------------------------------

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "cass-mcp-t11-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create sandbox directory");
        Self { dir }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

struct Fixture {
    sandbox: Sandbox,
    cass_bin: PathBuf,
    log: PathBuf,
    data_dir: PathBuf,
    api_config: PathBuf,
    home: PathBuf,
}

impl Fixture {
    /// Create a sandbox whose fake CASS binary prints `version_output` and
    /// exits with `exit_code`, recording every argument vector it receives.
    fn new(label: &str, version_output: &str, exit_code: i32) -> Self {
        let sandbox = Sandbox::new(label);
        let dir = &sandbox.dir;

        let data_dir = dir.join("data");
        fs::create_dir_all(&data_dir).expect("create data dir");

        let api_config = dir.join("api.json");
        fs::write(&api_config, "{\"profiles\":{}}\n").expect("write api config");

        let log = dir.join("cass-version.log");
        let cass_bin = dir.join("fake-cass");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf '%s\\n' '{}'\nexit {}\n",
            log.display(),
            version_output,
            exit_code
        );
        fs::write(&cass_bin, script).expect("write fake cass binary");
        set_mode(&cass_bin, 0o755);

        let home = dir.join("home");
        fs::create_dir_all(&home).expect("create isolated home");

        Self {
            sandbox,
            cass_bin,
            log,
            data_dir,
            api_config,
            home,
        }
    }

    fn args(&self, bind: SocketAddr, public_origin: &str) -> Vec<String> {
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
            "embedding".to_string(),
            "--rerank-profile".to_string(),
            "rerank".to_string(),
            "--max-concurrent".to_string(),
            "4".to_string(),
            "--max-queued".to_string(),
            "8".to_string(),
            "--max-output-bytes".to_string(),
            "1048576".to_string(),
            "--request-timeout-ms".to_string(),
            "30000".to_string(),
            "--terminate-grace-ms".to_string(),
            "1000".to_string(),
            "--public-origin".to_string(),
            public_origin.to_string(),
        ]
    }

    /// Number of times the fake CASS binary was executed.
    fn invocation_count(&self) -> usize {
        fs::read_to_string(&self.log)
            .map(|text| text.lines().count())
            .unwrap_or(0)
    }

    /// Argument vectors recorded by the fake CASS binary.
    fn invocations(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn _sandbox_path(&self) -> &Path {
        &self.sandbox.dir
    }
}

fn set_mode(path: &Path, mode: u32) {
    let mut permissions = fs::metadata(path).expect("stat fixture").permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).expect("chmod fixture");
}

fn set_option(args: &mut [String], option: &str, value: &str) {
    let index = args
        .iter()
        .position(|arg| arg == option)
        .unwrap_or_else(|| panic!("missing option {option}"));
    args[index + 1] = value.to_string();
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

struct Run {
    status: ExitStatus,
    stderr: String,
}

fn run_cli(args: &[String], home: &Path) -> Run {
    let child = Command::new(BIN)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cass-mcp");

    wait_with_deadline(child, Duration::from_secs(30))
}

fn wait_with_deadline(mut child: Child, deadline: Duration) -> Run {
    let start = Instant::now();
    loop {
        match child.try_wait().expect("poll cass-mcp") {
            Some(_) => break,
            None if start.elapsed() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("cass-mcp did not exit within {deadline:?}");
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    }

    let output = child.wait_with_output().expect("collect cass-mcp output");
    Run {
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

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

fn start_server(fixture: &Fixture, public_origin: &str) -> ServerProc {
    start_server_on(fixture, "127.0.0.1:0", public_origin)
}

fn start_server_on(fixture: &Fixture, bind: &str, public_origin: &str) -> ServerProc {
    let bind: SocketAddr = bind.parse().expect("valid bind address");
    start_server_with_args(fixture, fixture.args(bind, public_origin))
}

fn start_server_with_budget(fixture: &Fixture, public_origin: &str, budget: usize) -> ServerProc {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind address");
    let mut args = fixture.args(bind, public_origin);
    set_option(&mut args, "--max-output-bytes", &budget.to_string());
    start_server_with_args(fixture, args)
}

fn start_server_with_args(fixture: &Fixture, args: Vec<String>) -> ServerProc {
    let mut child = Command::new(BIN)
        .args(args)
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
        line.starts_with("listening=http://"),
        "unexpected startup line: {line}"
    );
    assert!(line.ends_with("/mcp"), "unexpected startup line: {line}");

    let address_text = line
        .strip_prefix("listening=http://")
        .and_then(|rest| rest.strip_suffix("/mcp"))
        .unwrap_or_else(|| panic!("unexpected startup line: {line}"));
    let address: SocketAddr = address_text
        .parse()
        .unwrap_or_else(|_| panic!("listening line must carry a socket address: {line}"));

    ServerProc { child, address }
}

// ---------------------------------------------------------------------------
// Raw HTTP client (no extra dependencies)
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
}

fn post(
    server: &ServerProc,
    host: &str,
    extra_headers: &[(&str, &str)],
    body: &str,
) -> HttpResponse {
    let address: SocketAddr = (server.address.ip(), server.address.port()).into();
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).expect("connect to cass-mcp");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
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
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read HTTP response");
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> HttpResponse {
    let split = find_subslice(raw, b"\r\n\r\n").expect("response has a header terminator");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body_bytes = raw[split + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
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
    loop {
        let Some(line_end) = find_subslice(&raw[index..], b"\r\n") else {
            break;
        };
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
// Protocol requests
// ---------------------------------------------------------------------------

fn initialize_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "cass-mcp-t11-test",
                "version": "1.0.0"
            }
        }
    })
    .to_string()
}

fn tools_list_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    })
    .to_string()
}

fn json_body(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON body: {error}: {body}"))
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("ephemeral address").port();
    drop(listener);
    port
}

/// JSON-RPC payload of a JSON or SSE response. Legacy session mode answers
/// `2025-11-25` requests with SSE; stateless requests stay plain JSON.
fn response_payload(response: &HttpResponse) -> serde_json::Value {
    if response
        .header("content-type")
        .is_some_and(|value| value.contains("text/event-stream"))
    {
        sse_payloads(&response.body)
            .into_iter()
            .last()
            .unwrap_or_else(|| panic!("SSE response carried no JSON event: {}", response.body))
    } else {
        json_body(&response.body)
    }
}

fn sse_payloads(body: &str) -> Vec<serde_json::Value> {
    let mut payloads = Vec::new();
    let mut data = String::new();
    let flush = |data: &mut String, payloads: &mut Vec<serde_json::Value>| {
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

/// POST a JSON-RPC message inside an established session.
fn post_session(server: &ServerProc, host: &str, session: &str, body: &str) -> HttpResponse {
    post(
        server,
        host,
        &[
            ("MCP-Protocol-Version", PROTOCOL_VERSION),
            ("Mcp-Session-Id", session),
        ],
        body,
    )
}

/// Complete the `2025-11-25` handshake and return the session id with the
/// initialize result. `extra_headers` carries any Origin under test.
fn initialize_session(
    server: &ServerProc,
    host: &str,
    extra_headers: &[(&str, &str)],
) -> (String, serde_json::Value) {
    let mut headers = extra_headers.to_vec();
    headers.push(("MCP-Protocol-Version", PROTOCOL_VERSION));
    let response = post(server, host, &headers, &initialize_body());
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
    let value = response_payload(&response);

    let notification =
        serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string();
    let response = post_session(server, host, &session, &notification);
    assert_eq!(
        response.status, 202,
        "initialized notification body: {}",
        response.body
    );

    (session, value)
}

// ---------------------------------------------------------------------------
// 11-AC1: version and linkage
// ---------------------------------------------------------------------------

#[test]
fn binary_reports_cass_mcp_version() {
    let output = Command::new(BIN)
        .arg("--version")
        .output()
        .expect("run cass-mcp --version");

    assert!(output.status.success(), "exit status: {}", output.status);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        MCP_VERSION_WORD
    );
}

// ---------------------------------------------------------------------------
// 11-AC2: initialize and tools/list over real HTTP
// ---------------------------------------------------------------------------

#[test]
fn initialize_and_tools_list_are_served() {
    let fixture = Fixture::new("protocol", EXPECTED_CASS_VERSION, 0);
    let server = start_server(&fixture, PUBLIC_ORIGIN);
    let host = format!("127.0.0.1:{}", server.address.port());

    let (session, value) = initialize_session(&server, &host, &[]);
    assert!(
        !session.is_empty(),
        "the 2025-11-25 handshake must establish a session"
    );
    assert_eq!(value["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(value["result"]["serverInfo"]["name"], "cass-mcp");
    assert_eq!(value["result"]["serverInfo"]["version"], "0.6.17");
    assert!(
        value["result"]["capabilities"]["tools"].is_object(),
        "tools capability must be advertised: {value}"
    );

    let response = post_session(&server, &host, &session, &tools_list_body());
    assert_eq!(response.status, 200, "tools/list body: {}", response.body);
    let value = response_payload(&response);
    let tools = value["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list must return a tools array: {value}"));
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(
        names,
        vec![
            "cass_search",
            "cass_expand",
            "cass_sessions",
            "cass_timeline"
        ],
        "ticket 12 registers exactly the four read tools"
    );

    assert_eq!(fixture.invocation_count(), 1);
    assert_eq!(fixture.invocations(), vec!["--version".to_string()]);
}

/// Any loopback address is a legal `--bind` value, not only `127.0.0.1`.
/// A request without an Origin must reach `initialize` and the four-tool
/// `tools/list` over real HTTP on such an address.
#[test]
fn alternate_loopback_bind_serves_requests_without_origin() {
    let fixture = Fixture::new("loopback-bind", EXPECTED_CASS_VERSION, 0);
    let server = start_server_on(&fixture, "127.0.0.2:0", PUBLIC_ORIGIN);
    assert_eq!(server.address.ip().to_string(), "127.0.0.2");
    let host = format!("127.0.0.2:{}", server.address.port());

    let (session, value) = initialize_session(&server, &host, &[]);
    assert_eq!(value["result"]["serverInfo"]["name"], "cass-mcp");

    let response = post_session(&server, &host, &session, &tools_list_body());
    assert_eq!(
        response.status, 200,
        "tools/list without Origin on 127.0.0.2 failed; body: {}",
        response.body
    );
    let value = response_payload(&response);
    assert_eq!(
        value["result"]["tools"].as_array().map(Vec::len),
        Some(4),
        "ticket 12 advertises four tools: {value}"
    );

    assert_eq!(fixture.invocations(), vec!["--version".to_string()]);
}

/// A valid IPv6 loopback bind and its matching Origin stay usable.
#[test]
fn ipv6_loopback_bind_serves_requests_without_origin() {
    let fixture = Fixture::new("ipv6-bind", EXPECTED_CASS_VERSION, 0);
    let server = start_server_on(&fixture, "[::1]:0", PUBLIC_ORIGIN);
    assert!(server.address.is_ipv6(), "expected an IPv6 listener");
    let port = server.address.port();
    let host = format!("[::1]:{port}");

    let (session, value) = initialize_session(&server, &host, &[]);
    assert_eq!(value["result"]["serverInfo"]["name"], "cass-mcp");

    let origin = format!("http://[::1]:{port}");
    let response = post(
        &server,
        &host,
        &[
            ("Origin", origin.as_str()),
            ("MCP-Protocol-Version", PROTOCOL_VERSION),
        ],
        &initialize_body(),
    );
    assert_eq!(
        response.status, 200,
        "initialize with Origin {origin} failed; body: {}",
        response.body
    );

    let response = post_session(&server, &host, &session, &tools_list_body());
    assert_eq!(
        response.status, 200,
        "tools/list without Origin on [::1] failed; body: {}",
        response.body
    );
    let value = response_payload(&response);
    assert_eq!(
        value["result"]["tools"].as_array().map(Vec::len),
        Some(4),
        "ticket 12 advertises four tools: {value}"
    );

    assert_eq!(fixture.invocations(), vec!["--version".to_string()]);
}

/// A configured IPv6 origin must be callable with exactly that spelling.
/// Equivalent compressed spellings are not accepted as aliases.
#[test]
fn expanded_ipv6_public_origin_matches_its_exact_origin() {
    let fixture = Fixture::new("origin-expanded-ipv6", EXPECTED_CASS_VERSION, 0);
    let origin = "http://[0:0:0:0:0:0:0:1]:8080";
    let server = start_server(&fixture, origin);
    let host = format!("127.0.0.1:{}", server.address.port());

    let (session, value) = initialize_session(&server, &host, &[("Origin", origin)]);
    assert_eq!(value["result"]["serverInfo"]["name"], "cass-mcp");

    let response = post_session(&server, &host, &session, &tools_list_body());
    assert_eq!(
        response.status, 200,
        "tools/list with configured Origin {origin} failed; body: {}",
        response.body
    );
    let value = response_payload(&response);
    assert_eq!(
        value["result"]["tools"].as_array().map(Vec::len),
        Some(4),
        "ticket 12 advertises four tools: {value}"
    );

    let response = post(
        &server,
        &host,
        &[
            ("Origin", "http://[::1]:8080"),
            ("MCP-Protocol-Version", PROTOCOL_VERSION),
        ],
        &initialize_body(),
    );
    assert_eq!(
        response.status, 403,
        "a different spelling of the same address is not an alias; body: {}",
        response.body
    );
}

// ---------------------------------------------------------------------------
// 11-AC3: configuration rejection before listener and subprocess
// ---------------------------------------------------------------------------
fn expect_rejected(label: &str, fixture: &Fixture, args: &[String]) {
    let run = run_cli(args, &fixture.home);
    assert!(
        !run.status.success(),
        "[{label}] cass-mcp accepted invalid input; stderr: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("listening="),
        "[{label}] cass-mcp started listening; stderr: {}",
        run.stderr
    );
    assert_eq!(
        fixture.invocation_count(),
        0,
        "[{label}] cass-mcp probed cass-bin before rejecting the configuration"
    );
}

#[test]
fn every_option_is_required() {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind address");

    for option in OPTIONS {
        let fixture = Fixture::new("missing", EXPECTED_CASS_VERSION, 0);
        let args = fixture.args(bind, PUBLIC_ORIGIN);
        let index = args
            .iter()
            .position(|arg| arg == option)
            .unwrap_or_else(|| panic!("fixture is missing {option}"));

        let mut trimmed = args.clone();
        trimmed.drain(index..index + 2);
        expect_rejected(&format!("missing {option}"), &fixture, &trimmed);
    }
}

#[test]
fn invalid_bind_addresses_are_rejected() {
    for value in ["0.0.0.0:0", "192.0.2.1:0", "localhost:8080", "[::]:0"] {
        let fixture = Fixture::new("bind", EXPECTED_CASS_VERSION, 0);
        let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind address");
        let mut args = fixture.args(bind, PUBLIC_ORIGIN);
        set_option(&mut args, "--bind", value);
        expect_rejected(&format!("bind {value}"), &fixture, &args);
    }
}

#[test]
fn invalid_paths_and_profiles_are_rejected() {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind address");

    // Relative cass-bin.
    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    set_option(&mut args, "--cass-bin", "fake-cass");
    expect_rejected("relative cass-bin", &fixture, &args);

    // Nonexistent cass-bin.
    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    let missing = fixture._sandbox_path().join("absent-cass");
    set_option(&mut args, "--cass-bin", &missing.display().to_string());
    expect_rejected("nonexistent cass-bin", &fixture, &args);

    // Directory as cass-bin.
    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    let directory = fixture.data_dir.display().to_string();
    set_option(&mut args, "--cass-bin", &directory);
    expect_rejected("directory cass-bin", &fixture, &args);

    // Non-executable cass-bin.
    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    let plain = fixture._sandbox_path().join("plain-cass");
    fs::write(&plain, "#!/bin/sh\nexit 0\n").expect("write plain file");
    set_mode(&plain, 0o644);
    set_option(&mut args, "--cass-bin", &plain.display().to_string());
    expect_rejected("non-executable cass-bin", &fixture, &args);

    // Relative data-dir.
    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    set_option(&mut args, "--data-dir", "data");
    expect_rejected("relative data-dir", &fixture, &args);

    // Nonexistent data-dir.
    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    let missing = fixture._sandbox_path().join("absent-data");
    set_option(&mut args, "--data-dir", &missing.display().to_string());
    expect_rejected("nonexistent data-dir", &fixture, &args);

    // File as data-dir.
    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    let file = fixture.api_config.display().to_string();
    set_option(&mut args, "--data-dir", &file);
    expect_rejected("file data-dir", &fixture, &args);

    // Relative api-config.
    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    set_option(&mut args, "--api-config", "api.json");
    expect_rejected("relative api-config", &fixture, &args);

    // Nonexistent api-config.
    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    let missing = fixture._sandbox_path().join("absent-api.json");
    set_option(&mut args, "--api-config", &missing.display().to_string());
    expect_rejected("nonexistent api-config", &fixture, &args);

    // Unreadable api-config, unless the test user can bypass permissions.
    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let args = fixture.args(bind, PUBLIC_ORIGIN);
    set_mode(&fixture.api_config, 0o000);
    if fs::File::open(&fixture.api_config).is_err() {
        expect_rejected("unreadable api-config", &fixture, &args);
    } else {
        eprintln!("note: test user can read mode-000 file; unreadable api-config case skipped");
    }

    // Blank profiles.
    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    set_option(&mut args, "--embedding-profile", "   ");
    expect_rejected("blank embedding profile", &fixture, &args);

    let fixture = Fixture::new("paths", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    set_option(&mut args, "--rerank-profile", "");
    expect_rejected("blank rerank profile", &fixture, &args);
}

#[test]
fn invalid_numeric_values_are_rejected() {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind address");

    for option in [
        "--max-concurrent",
        "--max-queued",
        "--max-output-bytes",
        "--request-timeout-ms",
        "--terminate-grace-ms",
    ] {
        for value in ["0", "-1", "18446744073709551616"] {
            let fixture = Fixture::new("numbers", EXPECTED_CASS_VERSION, 0);
            let mut args = fixture.args(bind, PUBLIC_ORIGIN);
            set_option(&mut args, option, value);
            expect_rejected(&format!("{option} {value}"), &fixture, &args);
        }
    }
}

/// The lowest representable budget must start, and the service must be able
/// to deliver a standard error body at that budget. One byte below it is
/// rejected before the version probe and before any listener exists.
#[test]
fn output_budget_minimum_is_enforced_before_the_version_probe() {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind address");

    let fixture = Fixture::new("budget-below", EXPECTED_CASS_VERSION, 0);
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    set_option(&mut args, "--max-output-bytes", "124");
    expect_rejected("max-output-bytes 124", &fixture, &args);

    let fixture = Fixture::new("budget-min", EXPECTED_CASS_VERSION, 0);
    let server = start_server_with_budget(&fixture, PUBLIC_ORIGIN, 125);
    let host = format!("127.0.0.1:{}", server.address.port());
    let (session, _) = initialize_session(&server, &host, &[]);

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": "cass_sessions", "arguments": { "limit": 0 } }
    })
    .to_string();
    let response = post_session(&server, &host, &session, &body);
    assert_eq!(response.status, 200, "tools/call body: {}", response.body);
    let value = response_payload(&response);
    let result = &value["result"];
    assert_eq!(result["isError"], true, "expected a tool error: {value}");
    let text = result["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("expected one text block: {value}"));
    let error: serde_json::Value =
        serde_json::from_str(text).unwrap_or_else(|_| panic!("error text is not JSON: {text}"));
    assert_eq!(error["error"]["code"], "invalid_argument");
    assert!(
        canonical_wire_len(result) <= 125,
        "the error body must fit the minimum budget"
    );
    assert_eq!(
        fixture.invocations(),
        vec!["--version".to_string()],
        "invalid input must not start the companion process"
    );
}

/// The 2026 tool result (with `resultType: complete`) for a received result.
fn canonical_wire_len(result: &serde_json::Value) -> usize {
    let mut parsed: CallToolResult =
        serde_json::from_value(result.clone()).expect("result deserializes as a tool result");
    parsed.result_type = Some(rmcp::model::ResultType::COMPLETE);
    serde_json::to_vec(&parsed)
        .expect("serialize SDK tool result")
        .len()
}

#[test]
fn invalid_public_origins_are_rejected() {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind address");

    for origin in [
        "",
        "null",
        "ftp://example.com",
        "http://",
        "http://example.com/path",
        "http://example.com?query=1",
        "http://example.com#fragment",
        "http://user@example.com",
        "http://*.example.com",
        "http://example.com:0",
        "http://[::1",
        "http://[:::]",
        "http://[127.0.0.1]",
        "http://::1:80",
        "http://example.com:99999",
    ] {
        let fixture = Fixture::new("origin", EXPECTED_CASS_VERSION, 0);
        let args = fixture.args(bind, origin);
        expect_rejected(&format!("public origin {origin:?}"), &fixture, &args);
    }
}

#[test]
fn occupied_port_proves_version_probe_runs_before_bind() {
    let fixture = Fixture::new("occupied", EXPECTED_CASS_VERSION, 0);
    let held = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().expect("held address").port();

    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().expect("valid bind");
    let args = fixture.args(bind, PUBLIC_ORIGIN);
    let run = run_cli(&args, &fixture.home);

    assert!(!run.status.success(), "occupied bind must fail");
    assert!(!run.stderr.contains("listening="));
    assert_eq!(
        fixture.invocations(),
        vec!["--version".to_string()],
        "the version probe must run exactly once before bind"
    );
    assert!(
        run.stderr.contains("failed to bind"),
        "expected a bind error after the probe; stderr: {}",
        run.stderr
    );
    drop(held);
}

#[test]
fn invalid_configuration_wins_over_an_occupied_port() {
    let fixture = Fixture::new("order", EXPECTED_CASS_VERSION, 0);
    let held = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().expect("held address").port();

    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().expect("valid bind");
    let mut args = fixture.args(bind, PUBLIC_ORIGIN);
    set_option(&mut args, "--max-concurrent", "0");
    let run = run_cli(&args, &fixture.home);

    assert!(!run.status.success(), "invalid configuration must fail");
    assert!(
        run.stderr.contains("invalid configuration"),
        "configuration must be rejected first; stderr: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("failed to bind"),
        "the listener must never be attempted; stderr: {}",
        run.stderr
    );
    assert_eq!(fixture.invocation_count(), 0);
    drop(held);
}

// ---------------------------------------------------------------------------
// 11-AC4: Origin boundary and fixed CASS version probe
// ---------------------------------------------------------------------------

#[test]
fn version_mismatch_does_not_listen() {
    let fixture = Fixture::new("mismatch", "cass 0.6.16", 0);
    let held = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().expect("held address").port();

    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().expect("valid bind");
    let args = fixture.args(bind, PUBLIC_ORIGIN);
    let run = run_cli(&args, &fixture.home);

    assert!(!run.status.success(), "version mismatch must fail");
    assert!(!run.stderr.contains("listening="));
    assert_eq!(fixture.invocations(), vec!["--version".to_string()]);
    assert!(
        run.stderr.contains("version mismatch"),
        "expected a version mismatch error; stderr: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("cass 0.6.16"),
        "the child output must not be echoed; stderr: {}",
        run.stderr
    );
    drop(held);
}

#[test]
fn version_probe_failure_does_not_listen() {
    let fixture = Fixture::new("probe-fail", EXPECTED_CASS_VERSION, 3);
    let held = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let port = held.local_addr().expect("held address").port();

    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().expect("valid bind");
    let args = fixture.args(bind, PUBLIC_ORIGIN);
    let run = run_cli(&args, &fixture.home);

    assert!(!run.status.success(), "probe failure must fail");
    assert!(!run.stderr.contains("listening="));
    assert_eq!(fixture.invocations(), vec!["--version".to_string()]);
    assert!(
        run.stderr.contains("exited non-zero"),
        "expected a probe failure error; stderr: {}",
        run.stderr
    );
    drop(held);
}

#[test]
fn origin_allowlist_matches_loopback_and_public_entry() {
    let fixture = Fixture::new("origin-allow", EXPECTED_CASS_VERSION, 0);
    let server = start_server(&fixture, PUBLIC_ORIGIN);
    let port = server.address.port();
    let host = format!("127.0.0.1:{port}");

    let allowed = [
        None,
        Some(format!("http://127.0.0.1:{port}")),
        Some(format!("http://localhost:{port}")),
        Some(format!("http://[::1]:{port}")),
        Some(PUBLIC_ORIGIN.to_string()),
    ];

    for origin in allowed {
        let headers: Vec<(&str, &str)> = match origin.as_deref() {
            Some(value) => vec![("Origin", value)],
            None => Vec::new(),
        };
        let response = post(&server, &host, &headers, &initialize_body());
        assert_eq!(
            response.status, 200,
            "origin {origin:?} should be allowed; body: {}",
            response.body
        );
    }
}

#[test]
fn host_header_allows_loopback_and_configured_public_authority_only() {
    let fixture = Fixture::new("host-allow", EXPECTED_CASS_VERSION, 0);
    let server = start_server(&fixture, PUBLIC_ORIGIN);

    for host in ["public.example:8080", "public.example", "127.0.0.1:1"] {
        let response = post(&server, host, &[], &initialize_body());
        assert_eq!(
            response.status, 200,
            "Host {host} should be allowed; body: {}",
            response.body
        );
    }

    let response = post(&server, "evil.example", &[], &initialize_body());
    assert_eq!(
        response.status, 403,
        "Host evil.example must be rejected; body: {}",
        response.body
    );
}

#[test]
fn disallowed_origins_are_rejected() {
    let fixture = Fixture::new("origin-deny", EXPECTED_CASS_VERSION, 0);
    let server = start_server(&fixture, PUBLIC_ORIGIN);
    let port = server.address.port();
    let host = format!("127.0.0.1:{port}");
    let other_port = free_port();

    let cases: Vec<(&str, Vec<String>)> = vec![
        ("foreign origin", vec!["http://evil.example".to_string()]),
        (
            "same host different port",
            vec![format!("http://127.0.0.1:{other_port}")],
        ),
        (
            "origin with path",
            vec![format!("http://127.0.0.1:{port}/x")],
        ),
        (
            "origin with query",
            vec![format!("http://127.0.0.1:{port}?query=1")],
        ),
        (
            "origin with fragment",
            vec![format!("http://127.0.0.1:{port}#fragment")],
        ),
        (
            "origin with userinfo",
            vec![format!("http://user@127.0.0.1:{port}")],
        ),
        ("origin wildcard", vec!["http://*".to_string()]),
        ("origin null", vec!["null".to_string()]),
        (
            "bracketed IPv4 origin",
            vec![format!("http://[127.0.0.1]:{port}")],
        ),
        (
            "malformed IPv6 origin",
            vec![format!("http://[:::]:{port}")],
        ),
        ("scheme mismatch", vec![format!("https://127.0.0.1:{port}")]),
        (
            "duplicate origin headers",
            vec![
                format!("http://127.0.0.1:{port}"),
                format!("http://127.0.0.1:{port}"),
            ],
        ),
    ];

    for (label, values) in cases {
        let headers: Vec<(&str, &str)> = values
            .iter()
            .map(|value| ("Origin", value.as_str()))
            .collect();
        let response = post(&server, &host, &headers, &initialize_body());
        assert_eq!(
            response.status, 403,
            "[{label}] must be rejected; body: {}",
            response.body
        );
    }
}

#[test]
fn portless_public_origin_is_pinned_to_the_scheme_default_port() {
    let fixture = Fixture::new("origin-portless", EXPECTED_CASS_VERSION, 0);
    let server = start_server(&fixture, "http://portless.example");
    let host = format!("127.0.0.1:{}", server.address.port());

    for (label, origin, expected) in [
        ("origin without port", "http://portless.example", 200),
        (
            "origin with default port",
            "http://portless.example:80",
            200,
        ),
        (
            "origin with another port",
            "http://portless.example:81",
            403,
        ),
    ] {
        let headers = [("Origin", origin)];
        let response = post(&server, &host, &headers, &initialize_body());
        assert_eq!(
            response.status, expected,
            "[{label}] unexpected status; body: {}",
            response.body
        );
    }
}
