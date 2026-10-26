//! Ticket 12 tool-mapping tests.
//!
//! Every test drives the real `cass-mcp` binary over real HTTP. The companion
//! CASS binary is a recording shell script in the test's own temp directory:
//! it answers `--version`, records every argv vector and the child `CASS_*`
//! environment on disk, and prints whatever stdout/stderr/exit the test set.
//! No test touches a control-plane path, a production database, or a model.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_cass-mcp");
const EXPECTED_CASS_VERSION: &str = "cass 0.6.17";
const PROTOCOL_2025: &str = "2025-11-25";
const PROTOCOL_2026: &str = "2026-07-28";
const PUBLIC_ORIGIN: &str = "http://public.example:8080";

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Sandbox and recording fixture
// ---------------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
    cass_bin: PathBuf,
    log: PathBuf,
    data_dir: PathBuf,
    api_config: PathBuf,
    home: PathBuf,
    response_stdout: PathBuf,
    response_stderr: PathBuf,
    response_exit: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "cass-mcp-t12-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create sandbox directory");

        let data_dir = dir.join("data");
        fs::create_dir_all(&data_dir).expect("create data dir");

        let api_config = dir.join("api.toml");
        fs::write(&api_config, "version = 1\n").expect("write api config");

        let home = dir.join("home");
        fs::create_dir_all(&home).expect("create isolated home");

        let log = dir.join("calls.bin");
        let response_stdout = dir.join("response.stdout");
        let response_stderr = dir.join("response.stderr");
        let response_exit = dir.join("response.exit");
        let cass_bin = dir.join("fake-cass");

        let script = format!(
            "#!/bin/sh\n\
             if [ \"$1\" = \"--version\" ]; then printf '%s\\n' '{version}'; exit 0; fi\n\
             {{ printf 'CALL\\000'; for arg in \"$@\"; do printf 'ARG\\000%s\\000' \"$arg\"; done; \
             printf 'DATA\\000%s\\000' \"${{CASS_DATA_DIR-}}\"; \
             printf 'LEFTOVER\\000%s\\000' \"${{CASS_LEFTOVER-}}\"; }} >> '{log}'\n\
             cat '{stdout}'\n\
             cat '{stderr}' >&2\n\
             exit \"$(cat '{exit}')\"\n",
            version = EXPECTED_CASS_VERSION,
            log = log.display(),
            stdout = response_stdout.display(),
            stderr = response_stderr.display(),
            exit = response_exit.display(),
        );
        fs::write(&cass_bin, script).expect("write fake cass binary");
        set_mode(&cass_bin, 0o755);

        let fixture = Self {
            dir,
            cass_bin,
            log,
            data_dir,
            api_config,
            home,
            response_stdout,
            response_stderr,
            response_exit,
        };
        fixture.answer("", "", 0);
        fixture
    }

    fn answer(&self, stdout: &str, stderr: &str, exit: i32) {
        self.answer_bytes(stdout.as_bytes(), stderr.as_bytes(), exit);
    }

    fn answer_bytes(&self, stdout: &[u8], stderr: &[u8], exit: i32) {
        fs::write(&self.response_stdout, stdout).expect("write response stdout");
        fs::write(&self.response_stderr, stderr).expect("write response stderr");
        fs::write(&self.response_exit, format!("{exit}\n")).expect("write response exit");
    }

    fn args(&self, bind: SocketAddr) -> Vec<String> {
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
            "embedding profile".to_string(),
            "--rerank-profile".to_string(),
            "rerank-profile".to_string(),
            "--max-concurrent".to_string(),
            "2".to_string(),
            "--max-queued".to_string(),
            "2".to_string(),
            "--max-output-bytes".to_string(),
            "1048576".to_string(),
            "--request-timeout-ms".to_string(),
            "30000".to_string(),
            "--terminate-grace-ms".to_string(),
            "1000".to_string(),
            "--public-origin".to_string(),
            PUBLIC_ORIGIN.to_string(),
        ]
    }

    fn calls(&self) -> Vec<Call> {
        match fs::read(&self.log) {
            Ok(raw) => parse_calls(&raw),
            Err(_) => Vec::new(),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn set_mode(path: &Path, mode: u32) {
    let mut permissions = fs::metadata(path).expect("stat fixture").permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).expect("chmod fixture");
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Call {
    args: Vec<String>,
    data_dir: String,
    leftover: String,
}

fn parse_calls(raw: &[u8]) -> Vec<Call> {
    let tokens: Vec<&[u8]> = raw.split(|byte| *byte == 0).collect();
    let mut calls = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index] != b"CALL" {
            index += 1;
            continue;
        }
        index += 1;
        let mut args = Vec::new();
        let mut data_dir = String::new();
        let mut leftover = String::new();
        while index < tokens.len() && tokens[index] != b"CALL" {
            if index + 1 >= tokens.len() {
                break;
            }
            let tag = tokens[index];
            let value = String::from_utf8_lossy(tokens[index + 1]).into_owned();
            match tag {
                b"ARG" => args.push(value),
                b"DATA" => data_dir = value,
                b"LEFTOVER" => leftover = value,
                _ => {}
            }
            index += 2;
        }
        calls.push(Call {
            args,
            data_dir,
            leftover,
        });
    }
    calls
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

fn start_server(fixture: &Fixture) -> ServerProc {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("valid bind");
    let mut child = Command::new(BIN)
        .args(fixture.args(bind))
        .env("HOME", &fixture.home)
        .env("XDG_CONFIG_HOME", fixture.home.join("config"))
        .env("XDG_DATA_HOME", fixture.home.join("data"))
        .env("XDG_CACHE_HOME", fixture.home.join("cache"))
        .env("CASS_LEFTOVER", "inherited-value")
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

    /// JSON-RPC payload of a JSON or SSE response.
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
    server: &ServerProc,
    host: &str,
    extra_headers: &[(&str, &str)],
    body: &str,
) -> HttpResponse {
    let address = server.address;
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).expect("connect to cass-mcp");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
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
// Protocol helpers
// ---------------------------------------------------------------------------

struct Client<'a> {
    server: &'a ServerProc,
    host: String,
    next_id: u64,
}

impl<'a> Client<'a> {
    fn new(server: &'a ServerProc) -> Self {
        Self {
            server,
            host: format!("127.0.0.1:{}", server.address.port()),
            next_id: 1,
        }
    }

    fn id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn initialize_2025(&mut self) -> String {
        let body = json!({
            "jsonrpc": "2.0",
            "id": self.id(),
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_2025,
                "capabilities": {},
                "clientInfo": { "name": "cass-mcp-t12-test", "version": "1.0.0" }
            }
        })
        .to_string();
        let response = post(
            self.server,
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
        let value = response.payload();
        assert_eq!(value["result"]["protocolVersion"], PROTOCOL_2025);
        assert_eq!(value["result"]["serverInfo"]["name"], "cass-mcp");
        assert!(value["result"]["capabilities"]["tools"].is_object());
        session
    }

    fn notify_initialized(&self, session: &str) {
        let body = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string();
        let response = post(
            self.server,
            &self.host,
            &[
                ("MCP-Protocol-Version", PROTOCOL_2025),
                ("Mcp-Session-Id", session),
            ],
            &body,
        );
        assert_eq!(
            response.status, 202,
            "initialized notification body: {}",
            response.body
        );
    }

    fn request_2025(&mut self, session: &str, method: &str, params: Value) -> Value {
        let body = json!({
            "jsonrpc": "2.0",
            "id": self.id(),
            "method": method,
            "params": params,
        })
        .to_string();
        let response = post(
            self.server,
            &self.host,
            &[
                ("MCP-Protocol-Version", PROTOCOL_2025),
                ("Mcp-Session-Id", session),
            ],
            &body,
        );
        assert_eq!(response.status, 200, "{method} body: {}", response.body);
        response.payload()
    }

    fn call_2025(&mut self, session: &str, name: &str, arguments: Value) -> Value {
        tool_result(self.request_2025(
            session,
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        ))
    }

    fn request_2026(&mut self, method: &str, mut params: Value) -> Value {
        // The 2026-07-28 lifecycle keeps `_meta` inside `params`.
        params
            .as_object_mut()
            .expect("2026 params are an object")
            .insert(
                "_meta".to_string(),
                json!({
                    "io.modelcontextprotocol/protocolVersion": PROTOCOL_2026,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }),
            );
        let tool_name = (method == "tools/call").then(|| {
            params
                .get("name")
                .and_then(Value::as_str)
                .expect("tools/call carries a name")
                .to_string()
        });
        let body = json!({
            "jsonrpc": "2.0",
            "id": self.id(),
            "method": method,
            "params": params,
        })
        .to_string();
        // 2026-07-28 also requires the SEP-2243 routing headers.
        let mut headers: Vec<(String, String)> = vec![
            (
                "MCP-Protocol-Version".to_string(),
                PROTOCOL_2026.to_string(),
            ),
            ("Mcp-Method".to_string(), method.to_string()),
        ];
        if let Some(name) = tool_name {
            headers.push(("Mcp-Name".to_string(), name));
        }
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let response = post(self.server, &self.host, &header_refs, &body);
        assert_eq!(response.status, 200, "{method} body: {}", response.body);
        response.payload()
    }

    fn call_2026(&mut self, name: &str, arguments: Value) -> Value {
        tool_result(self.request_2026(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        ))
    }
}

/// The `result` member of a successful JSON-RPC response.
fn tool_result(mut value: Value) -> Value {
    if let Some(result) = value.get_mut("result") {
        return result.take();
    }
    panic!("expected a JSON-RPC result, got {value}");
}

fn session_client(fixture: &Fixture) -> (ServerProc, String) {
    let server = start_server(fixture);
    let session = {
        let mut client = Client::new(&server);
        let session = client.initialize_2025();
        client.notify_initialized(&session);
        session
    };
    (server, session)
}

fn tool_names(client: &mut Client<'_>, session: &str) -> Vec<String> {
    let value = client.request_2025(session, "tools/list", json!({}));
    value["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list must return an array: {value}"))
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name").to_string())
        .collect()
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

fn error_code(result: &Value) -> String {
    let value: Value = serde_json::from_str(result_text(result))
        .unwrap_or_else(|error| panic!("error text is not JSON: {error}"));
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("error text must be one object: {value}"));
    assert_eq!(
        object.len(),
        1,
        "only the top-level error object is allowed: {value}"
    );
    value["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("error has no code: {value}"))
        .to_string()
}

fn assert_is_error(result: &Value) {
    assert_eq!(result["isError"], true, "expected isError=true: {result}");
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

// ---------------------------------------------------------------------------
// Fixed legal payloads
// ---------------------------------------------------------------------------

const SEARCH_EMPTY: &str = r#"<cass_recall version="1" tool="cass_search">{&quot;query&quot;:&quot;q&quot;,&quot;hits&quot;:[]}</cass_recall>"#;
const SESSIONS_EMPTY: &str =
    r#"<cass_recall version="1" tool="cass_sessions">{&quot;sessions&quot;:[]}</cass_recall>"#;
const TIMELINE_EMPTY: &str = r#"<cass_recall version="1" tool="cass_timeline">{&quot;range&quot;:{&quot;start&quot;:0,&quot;end&quot;:0},&quot;total_sessions&quot;:0,&quot;groups&quot;:{}}</cass_recall>"#;
const EXPAND_ONE: &str = r#"<cass_recall version="1" tool="cass_expand">[{&quot;line&quot;:1,&quot;role&quot;:&quot;user&quot;,&quot;is_target&quot;:true,&quot;content&quot;:&quot;a &amp;lt; b&quot;}]</cass_recall>"#;

fn search_hit_payload() -> String {
    json!({
        "query": "q",
        "hits": [{
            "message_id": 1,
            "source_id": "local",
            "source_path": "/srv/central/session.jsonl",
            "line_number": 7,
            "content_sha256": "a".repeat(64),
            "content": "the <tag> & \"quoted\" text"
        }]
    })
    .to_string()
}

fn envelope(tool: &str, payload: &str) -> String {
    let escaped = payload
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    format!(r#"<cass_recall version="1" tool="{tool}">{escaped}</cass_recall>"#)
}

// ---------------------------------------------------------------------------
// 12-AC1 / C3: argv is exact and the query stays one literal element
// ---------------------------------------------------------------------------

#[test]
fn search_argv_is_exact_and_query_stays_one_literal_element() {
    let fixture = Fixture::new("search-argv");
    fixture.answer(&envelope("cass_search", &search_hit_payload()), "", 0);
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    let marker = fixture.dir.join("shell-marker");
    let marker2 = fixture.dir.join("shell-marker-2");
    let query = format!(
        "--help \"double quoted\" 'single quoted' 空 格 ; touch {} | $(id) > {} & * ? [abc]",
        marker.display(),
        marker2.display()
    );
    let arguments = json!({
        "query": query,
        "agent": ["claude", "claude", "--help"],
        "workspace": ["/srv/central/work a", "/srv/central/work-b"],
        "source": "local",
        "since": "2026-01-01T00:00:00+00:00",
        "until": "2026-02-01T00:00:00+00:00",
        "cursor": "next-page"
    });
    let result = client.call_2025(&session, "cass_search", arguments);
    assert_success(&result);
    assert_eq!(
        result_text(&result),
        envelope("cass_search", &search_hit_payload())
    );

    let calls = fixture.calls();
    assert_eq!(calls.len(), 1, "exactly one business subprocess expected");
    let expected = vec![
        "search".to_string(),
        "--mode=hybrid".to_string(),
        "--vector-search-mode=exact".to_string(),
        "--rerank".to_string(),
        "--rrf-limit=200".to_string(),
        "--rerank-limit=5".to_string(),
        format!("--api-config={}", fixture.api_config.display()),
        "--embedding-profile=embedding profile".to_string(),
        "--rerank-profile=rerank-profile".to_string(),
        "--no-model-fallback".to_string(),
        "--recall".to_string(),
        "--agent=claude".to_string(),
        "--agent=claude".to_string(),
        "--agent=--help".to_string(),
        "--workspace=/srv/central/work a".to_string(),
        "--workspace=/srv/central/work-b".to_string(),
        "--source=local".to_string(),
        "--since=2026-01-01T00:00:00+00:00".to_string(),
        "--until=2026-02-01T00:00:00+00:00".to_string(),
        "--cursor=next-page".to_string(),
        "--".to_string(),
        query.clone(),
    ];
    assert_eq!(calls[0].args, expected);
    assert_eq!(calls[0].data_dir, fixture.data_dir.display().to_string());
    assert_eq!(
        calls[0].leftover, "",
        "inherited CASS_* must not reach the child"
    );
    assert!(
        !marker.exists(),
        "the query must never be executed by a shell"
    );
    assert!(!marker2.exists(), "redirection must never happen");
}

#[test]
fn expand_argv_is_exact() {
    let fixture = Fixture::new("expand-argv");
    fixture.answer(EXPAND_ONE, "", 0);
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    let arguments = json!({
        "message_id": 42,
        "source_id": "local",
        "source_path": "/srv/central/work a/session.jsonl",
        "expected_content_sha256": "AbCdEf0123456789".repeat(4),
        "context": 0
    });
    let result = client.call_2025(&session, "cass_expand", arguments);
    assert_success(&result);
    assert_eq!(result_text(&result), EXPAND_ONE);

    let calls = fixture.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].args,
        vec![
            "expand",
            "/srv/central/work a/session.jsonl",
            "--source=local",
            "--message-id=42",
            "--expected-content-sha256=AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789",
            "--context=0",
            "--recall",
        ]
    );
}

#[test]
fn sessions_argv_defaults_and_explicit_order() {
    let fixture = Fixture::new("sessions-argv");
    fixture.answer(SESSIONS_EMPTY, "", 0);
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    let result = client.call_2025(&session, "cass_sessions", json!({}));
    assert_success(&result);

    let result = client.call_2025(
        &session,
        "cass_sessions",
        json!({
            "limit": 3,
            "workspace": "/srv/central/work a",
            "since": "2026-01-01T00:00:00Z"
        }),
    );
    assert_success(&result);

    let calls = fixture.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].args, vec!["sessions", "--limit=10", "--recall"]);
    assert_eq!(
        calls[1].args,
        vec![
            "sessions",
            "--limit=3",
            "--recall",
            "--workspace=/srv/central/work a",
            "--since=2026-01-01T00:00:00Z",
        ]
    );
}

#[test]
fn timeline_argv_defaults_and_explicit_order() {
    let fixture = Fixture::new("timeline-argv");
    fixture.answer(TIMELINE_EMPTY, "", 0);
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    let result = client.call_2025(&session, "cass_timeline", json!({}));
    assert_success(&result);

    let result = client.call_2025(
        &session,
        "cass_timeline",
        json!({
            "since": "2026-01-01T00:00:00Z",
            "until": "2026-02-01T00:00:00+08:00",
            "agent": ["claude", "codex", "claude"],
            "source": "local",
            "group_by": "day"
        }),
    );
    assert_success(&result);

    let calls = fixture.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].args,
        vec!["timeline", "--group-by=hour", "--recall"]
    );
    assert_eq!(
        calls[1].args,
        vec![
            "timeline",
            "--group-by=day",
            "--recall",
            "--since=2026-01-01T00:00:00Z",
            "--until=2026-02-01T00:00:00+08:00",
            "--agent=claude",
            "--agent=codex",
            "--agent=claude",
            "--source=local",
        ]
    );
}

// ---------------------------------------------------------------------------
// 12-AC2: invalid input never starts a business subprocess
// ---------------------------------------------------------------------------

#[test]
fn invalid_arguments_never_start_a_subprocess() {
    let fixture = Fixture::new("invalid");
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    let sentinel = "SENSITIVE-WORKSPACE-SENTINEL";
    let cases: Vec<(&str, Value)> = vec![
        ("cass_search", json!({})),
        ("cass_search", json!({ "query": null })),
        ("cass_search", json!({ "query": 5 })),
        ("cass_search", json!({ "query": "   " })),
        ("cass_search", json!({ "query": "ok", "offset": 1 })),
        ("cass_search", json!({ "query": "ok", "agent": "claude" })),
        (
            "cass_search",
            json!({ "query": "ok", "agent": ["claude", 1] }),
        ),
        ("cass_search", json!({ "query": "ok", "agent": ["  "] })),
        (
            "cass_search",
            json!({ "query": "ok", "workspace": [sentinel] }),
        ),
        ("cass_search", json!({ "query": "ok", "source": null })),
        (
            "cass_search",
            json!({ "query": "ok", "since": "2026-01-01T00:00:00" }),
        ),
        (
            "cass_search",
            json!({ "query": "ok", "since": "2026-01-01" }),
        ),
        (
            "cass_search",
            json!({ "query": "ok", "since": "2026-02-30T00:00:00Z" }),
        ),
        (
            "cass_search",
            json!({
                "query": "ok",
                "since": "2026-02-01T00:00:00Z",
                "until": "2026-01-01T00:00:00Z"
            }),
        ),
        ("cass_expand", json!({})),
        (
            "cass_expand",
            json!({
                "source_id": "local",
                "source_path": "/srv/x",
                "expected_content_sha256": "a".repeat(64)
            }),
        ),
        (
            "cass_expand",
            json!({
                "message_id": 1,
                "source_path": "/srv/x",
                "expected_content_sha256": "a".repeat(64)
            }),
        ),
        (
            "cass_expand",
            json!({
                "message_id": 1,
                "source_id": "local",
                "expected_content_sha256": "a".repeat(64)
            }),
        ),
        (
            "cass_expand",
            json!({
                "message_id": 1,
                "source_id": "local",
                "source_path": "/srv/x"
            }),
        ),
        (
            "cass_expand",
            json!({ "message_id": 0, "source_id": "local", "source_path": "/srv/x", "expected_content_sha256": "a".repeat(64) }),
        ),
        (
            "cass_expand",
            json!({ "message_id": -1, "source_id": "local", "source_path": "/srv/x", "expected_content_sha256": "a".repeat(64) }),
        ),
        (
            "cass_expand",
            json!({ "message_id": 1.5, "source_id": "local", "source_path": "/srv/x", "expected_content_sha256": "a".repeat(64) }),
        ),
        (
            "cass_expand",
            json!({ "message_id": 9223372036854775808u64, "source_id": "local", "source_path": "/srv/x", "expected_content_sha256": "a".repeat(64) }),
        ),
        (
            "cass_expand",
            json!({ "message_id": 1, "source_id": " ", "source_path": "/srv/x", "expected_content_sha256": "a".repeat(64) }),
        ),
        (
            "cass_expand",
            json!({ "message_id": 1, "source_id": "local", "source_path": "  ", "expected_content_sha256": "a".repeat(64) }),
        ),
        (
            "cass_expand",
            json!({ "message_id": 1, "source_id": "local", "source_path": "/srv/x", "expected_content_sha256": "a".repeat(63) }),
        ),
        (
            "cass_expand",
            json!({ "message_id": 1, "source_id": "local", "source_path": "/srv/x", "expected_content_sha256": "z".repeat(64) }),
        ),
        (
            "cass_expand",
            json!({ "message_id": 1, "source_id": "local", "source_path": "/srv/x", "expected_content_sha256": "a".repeat(64), "context": -1 }),
        ),
        (
            "cass_expand",
            json!({ "message_id": 1, "source_id": "local", "source_path": "/srv/x", "expected_content_sha256": "a".repeat(64), "line": 1 }),
        ),
        ("cass_sessions", json!({ "limit": 0 })),
        ("cass_sessions", json!({ "limit": -1 })),
        ("cass_sessions", json!({ "limit": 1.5 })),
        (
            "cass_sessions",
            serde_json::from_str::<Value>("{ \"limit\": 18446744073709551616 }")
                .expect("fixture JSON"),
        ),
        ("cass_sessions", json!({ "limit": "10" })),
        ("cass_sessions", json!({ "workspace": sentinel })),
        ("cass_sessions", json!({ "since": "yesterday" })),
        ("cass_sessions", json!({ "current": true })),
        ("cass_timeline", json!({ "group_by": "week" })),
        ("cass_timeline", json!({ "group_by": 1 })),
        ("cass_timeline", json!({ "today": true })),
        ("cass_timeline", json!({ "agent": [""] })),
        (
            "cass_timeline",
            json!({ "since": "2026-02-01T00:00:00Z", "until": "2026-01-01T00:00:00Z" }),
        ),
        ("cass_timeline", json!({ "since": "2026-01-01T00:00:00" })),
    ];

    for (tool, arguments) in cases {
        let label = format!("{tool} {arguments}");
        let result = client.call_2025(&session, tool, arguments);
        assert_is_error(&result);
        assert_eq!(
            error_code(&result),
            "invalid_argument",
            "[{label}] unexpected code"
        );
        let text = result_text(&result);
        assert!(
            !text.contains(sentinel),
            "[{label}] the error must not echo the rejected value: {text}"
        );
    }

    assert!(
        fixture.calls().is_empty(),
        "invalid input must not start a business subprocess: {:?}",
        fixture.calls()
    );
}

#[test]
fn unknown_field_error_does_not_echo_request_data() {
    let fixture = Fixture::new("unknown-field-echo");
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    // Both the query and the rejected key carry the same unique sentinel, so
    // any echo of caller data would show it verbatim.
    let sentinel = "t12_unique_query_value_not_for_error_echo";
    let cases = [
        (
            "cass_search",
            json!({
                "query": sentinel,
                "t12_unique_query_value_not_for_error_echo": sentinel
            }),
        ),
        (
            "cass_expand",
            json!({
                "message_id": 1,
                "source_id": "local",
                "source_path": "/srv/x",
                "expected_content_sha256": "a".repeat(64),
                "t12_unique_query_value_not_for_error_echo": sentinel
            }),
        ),
        (
            "cass_sessions",
            json!({ "t12_unique_query_value_not_for_error_echo": sentinel }),
        ),
        (
            "cass_timeline",
            json!({ "t12_unique_query_value_not_for_error_echo": sentinel }),
        ),
    ];

    for (tool, arguments) in cases {
        let result = client.call_2025(&session, tool, arguments);
        assert_is_error(&result);
        assert_eq!(error_code(&result), "invalid_argument", "[{tool}]");
        let text = result_text(&result);
        assert!(
            !text.contains(sentinel) && !text.contains("t12_unique"),
            "[{tool}] the error must not echo the rejected key or query: {text}"
        );
    }

    assert!(
        fixture.calls().is_empty(),
        "an unknown field must not start a business subprocess"
    );
}

// ---------------------------------------------------------------------------
// 12-AC3: one original XML text block on success
// ---------------------------------------------------------------------------

#[test]
fn success_forwards_one_original_xml_text_block() {
    let fixture = Fixture::new("forward");
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    let search = envelope("cass_search", &search_hit_payload());
    let cases = [
        ("cass_search", json!({ "query": "q" }), search.clone()),
        ("cass_sessions", json!({}), SESSIONS_EMPTY.to_string()),
        ("cass_timeline", json!({}), TIMELINE_EMPTY.to_string()),
        (
            "cass_expand",
            json!({
                "message_id": 1,
                "source_id": "local",
                "source_path": "/srv/x",
                "expected_content_sha256": "a".repeat(64)
            }),
            EXPAND_ONE.to_string(),
        ),
    ];

    for (tool, arguments, stdout) in cases {
        fixture.answer(&stdout, "", 0);
        let result = client.call_2025(&session, tool, arguments);
        assert_success(&result);
        assert_eq!(
            result_text(&result),
            stdout,
            "[{tool}] exact stdout expected"
        );
    }
}

#[test]
fn empty_results_are_success() {
    let fixture = Fixture::new("empty");
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    for (tool, arguments, stdout) in [
        ("cass_search", json!({ "query": "q" }), SEARCH_EMPTY),
        ("cass_sessions", json!({}), SESSIONS_EMPTY),
        ("cass_timeline", json!({}), TIMELINE_EMPTY),
    ] {
        fixture.answer(stdout, "", 0);
        let result = client.call_2025(&session, tool, arguments);
        assert_success(&result);
        assert_eq!(result_text(&result), stdout);
    }
}

#[test]
fn invalid_recall_output_is_rejected() {
    let fixture = Fixture::new("bad-recall");
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);
    let secret = "PAYLOAD-SENTINEL-9911";

    let bad_cases: Vec<(&str, String)> = vec![
        (
            "wrong tool",
            format!(
                r#"<cass_recall version="1" tool="cass_sessions">{}{secret}{}</cass_recall>"#,
                "&quot;sessions&quot;:[]",
                ""
            ),
        ),
        (
            "wrong version",
            r#"<cass_recall version="2" tool="cass_search">&quot;hits&quot;:[]</cass_recall>"#.to_string(),
        ),
        (
            "extra root",
            format!(
                "<cass_recall version=\"1\" tool=\"cass_search\">&quot;hits&quot;:[]</cass_recall><extra/>"
            ),
        ),
        (
            "text outside root",
            format!("{secret}<cass_recall version=\"1\" tool=\"cass_search\">&quot;hits&quot;:[]</cass_recall>"),
        ),
        (
            "application text inside",
            format!("<cass_recall version=\"1\" tool=\"cass_search\">&quot;hits&quot;:[] {secret}</cass_recall>"),
        ),
        ("plain JSON", json!({ "hits": [] }).to_string()),
        (
            "malformed XML",
            "<cass_recall version=\"1\" tool=\"cass_search\">&quot;hits&quot;:[]".to_string(),
        ),
        (
            "wrong shape",
            "<cass_recall version=\"1\" tool=\"cass_search\">{&quot;query&quot;:&quot;q&quot;}</cass_recall>".to_string(),
        ),
        (
            "doctype",
            "<!DOCTYPE x><cass_recall version=\"1\" tool=\"cass_search\">&quot;hits&quot;:[]</cass_recall>".to_string(),
        ),
        (
            "invalid JSON",
            "<cass_recall version=\"1\" tool=\"cass_search\">not json</cass_recall>".to_string(),
        ),
        (
            "second text layer",
            format!(
                "<cass_recall version=\"1\" tool=\"cass_search\">&quot;hits&quot;:[]</cass_recall>{secret}"
            ),
        ),
    ];

    for (label, stdout) in bad_cases {
        fixture.answer(&stdout, "", 0);
        let result = client.call_2025(&session, "cass_search", json!({ "query": "q" }));
        assert_is_error(&result);
        assert_eq!(error_code(&result), "invalid_recall", "[{label}]");
        assert!(
            !result_text(&result).contains(secret),
            "[{label}] no partial stdout may be forwarded"
        );
    }

    fixture.answer_bytes(b"\xff\xfe", b"", 0);
    let result = client.call_2025(&session, "cass_search", json!({ "query": "q" }));
    assert_is_error(&result);
    assert_eq!(error_code(&result), "invalid_recall", "[invalid UTF-8]");
}

// ---------------------------------------------------------------------------
// 18d-AC1 / 18d-AC2: false-success results are rejected at the accept boundary
// ---------------------------------------------------------------------------

const IDENTITY_SENTINEL: &str = "MCP18D-ID-PRIVATE-7731";
const EXPAND_SENTINEL: &str = "MCP18D-EXPAND-PRIVATE-4416";

fn search_payload_with_hit(hit: Value) -> String {
    json!({ "query": "q", "hits": [hit] }).to_string()
}

/// Every hit must carry `source_id`, `source_path`, `message_id`,
/// `line_number`, and `content_sha256` with the C02 types and ranges.
/// Missing, null, blank, wrong-type, and out-of-range values are
/// `invalid_recall`, and the original payload is never forwarded. Empty hits
/// stay legal, and a complete hit is forwarded byte for byte.
#[test]
fn mcp_result_identity_rejects_malformed_hits() {
    let fixture = Fixture::new("mcp-result-identity");
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    let legal = json!({
        "message_id": 1,
        "source_id": "local",
        "source_path": "/srv/central/session.jsonl",
        "line_number": 0,
        "content_sha256": "a".repeat(64),
        "content": format!("{IDENTITY_SENTINEL} only on success"),
        "extension_field": { "kept": true }
    });
    let drop = |key: &str| {
        let mut hit = legal.clone();
        hit.as_object_mut().expect("hit is an object").remove(key);
        hit
    };
    let set = |key: &str, value: Value| {
        let mut hit = legal.clone();
        hit.as_object_mut()
            .expect("hit is an object")
            .insert(key.to_string(), value);
        hit
    };

    let cases: Vec<(&str, Value)> = vec![
        ("missing source_id", drop("source_id")),
        ("missing source_path", drop("source_path")),
        ("missing message_id", drop("message_id")),
        ("missing line_number", drop("line_number")),
        ("missing content_sha256", drop("content_sha256")),
        ("null source_id", set("source_id", Value::Null)),
        ("null source_path", set("source_path", Value::Null)),
        ("null message_id", set("message_id", Value::Null)),
        ("null line_number", set("line_number", Value::Null)),
        ("null content_sha256", set("content_sha256", Value::Null)),
        ("blank source_id", set("source_id", json!("   "))),
        ("blank source_path", set("source_path", json!("\t"))),
        ("non-string source_id", set("source_id", json!(7))),
        (
            "non-string source_path",
            set("source_path", json!(["/srv"])),
        ),
        ("message_id zero", set("message_id", json!(0))),
        ("message_id negative", set("message_id", json!(-3))),
        ("message_id fraction", set("message_id", json!(1.5))),
        ("message_id bool", set("message_id", json!(true))),
        ("message_id string", set("message_id", json!("1"))),
        (
            "message_id above i64",
            set("message_id", json!(i64::MAX as u64 + 1)),
        ),
        ("line_number negative", set("line_number", json!(-1))),
        ("line_number fraction", set("line_number", json!(2.5))),
        ("line_number bool", set("line_number", json!(false))),
        ("line_number string", set("line_number", json!("3"))),
        (
            "content_sha256 short",
            set("content_sha256", json!("a".repeat(63))),
        ),
        (
            "content_sha256 long",
            set("content_sha256", json!("a".repeat(65))),
        ),
        (
            "content_sha256 uppercase",
            set("content_sha256", json!("A".repeat(64))),
        ),
        (
            "content_sha256 non-hex",
            set("content_sha256", json!("g".repeat(64))),
        ),
        ("content_sha256 number", set("content_sha256", json!(64))),
    ];

    for (label, hit) in cases {
        let stdout = envelope("cass_search", &search_payload_with_hit(hit));
        fixture.answer(&stdout, "", 0);
        let result = client.call_2025(&session, "cass_search", json!({ "query": "q" }));
        assert_is_error(&result);
        assert_eq!(error_code(&result), "invalid_recall", "[{label}]");
        assert!(
            !result_text(&result).contains(IDENTITY_SENTINEL),
            "[{label}] no original payload may be forwarded"
        );
    }

    let mut boundary = legal.clone();
    boundary
        .as_object_mut()
        .expect("hit is an object")
        .insert("message_id".to_string(), json!(i64::MAX));
    for (label, hit) in [("complete hit", legal), ("i64::MAX message_id", boundary)] {
        let stdout = envelope("cass_search", &search_payload_with_hit(hit));
        fixture.answer(&stdout, "", 0);
        let result = client.call_2025(&session, "cass_search", json!({ "query": "q" }));
        assert_success(&result);
        assert_eq!(result_text(&result), stdout, "[{label}] original bytes");
    }

    fixture.answer(SEARCH_EMPTY, "", 0);
    let result = client.call_2025(&session, "cass_search", json!({ "query": "q" }));
    assert_success(&result);
    assert_eq!(result_text(&result), SEARCH_EMPTY, "empty hits stay legal");
}

/// A successful expand carries an object array whose entries all state a
/// boolean `is_target`, with exactly one `true`. Empty, zero-target,
/// two-target, missing, and non-boolean markers are `invalid_recall`; one
/// target with a `false` neighbour stays legal and forwards original bytes.
#[test]
fn mcp_result_expand_requires_exactly_one_target() {
    let fixture = Fixture::new("mcp-result-expand");
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);
    let arguments = json!({
        "message_id": 1,
        "source_id": "local",
        "source_path": "/srv/central/session.jsonl",
        "expected_content_sha256": "a".repeat(64)
    });
    let target = json!({
        "line": 3,
        "role": "user",
        "is_target": true,
        "content": format!("{EXPAND_SENTINEL} only on success")
    });
    let neighbour = json!({
        "line": 4,
        "role": "assistant",
        "is_target": false,
        "content": "after"
    });

    let cases: Vec<(&str, Value)> = vec![
        ("empty array", json!([])),
        ("zero targets", json!([neighbour])),
        ("two targets", json!([target, target])),
        (
            "missing is_target",
            json!([{ "line": 3, "content": EXPAND_SENTINEL }]),
        ),
        (
            "non-bool number is_target",
            json!([{ "line": 3, "is_target": 1, "content": EXPAND_SENTINEL }]),
        ),
        (
            "non-bool string is_target",
            json!([{ "line": 3, "is_target": "true", "content": EXPAND_SENTINEL }]),
        ),
        (
            "null is_target",
            json!([{ "line": 3, "is_target": null, "content": EXPAND_SENTINEL }]),
        ),
        (
            "neighbour without is_target",
            json!([target, { "line": 4, "content": EXPAND_SENTINEL }]),
        ),
        ("object instead of array", json!({ "is_target": true })),
    ];

    for (label, payload) in cases {
        let stdout = envelope("cass_expand", &payload.to_string());
        fixture.answer(&stdout, "", 0);
        let result = client.call_2025(&session, "cass_expand", arguments.clone());
        assert_is_error(&result);
        assert_eq!(error_code(&result), "invalid_recall", "[{label}]");
        assert!(
            !result_text(&result).contains(EXPAND_SENTINEL),
            "[{label}] no original payload may be forwarded"
        );
    }

    for (label, payload) in [
        ("one target", json!([target])),
        (
            "one target with false neighbour",
            json!([neighbour, target]),
        ),
    ] {
        let stdout = envelope("cass_expand", &payload.to_string());
        fixture.answer(&stdout, "", 0);
        let result = client.call_2025(&session, "cass_expand", arguments.clone());
        assert_success(&result);
        assert_eq!(result_text(&result), stdout, "[{label}] original bytes");
    }
}

#[test]
fn cli_failures_map_from_the_error_envelope() {
    let fixture = Fixture::new("cli-errors");
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);
    let secret = "SECRET-STDERR-CONTENT";

    let cli_error = |kind: &str, code: i32| {
        json!({
            "error": {
                "code": code,
                "kind": kind,
                "message": format!("{secret} {kind}"),
                "hint": secret,
                "retryable": false
            }
        })
        .to_string()
    };

    let cases = [
        ("usage", 2, "invalid_argument"),
        ("identity_unavailable", 9, "identity_unavailable"),
        ("stale_reference", 3, "stale_reference"),
        ("model_unavailable", 9, "model_unavailable"),
        ("recall_invalid", 9, "invalid_recall"),
        ("message_not_found", 3, "cass_exit"),
        ("source_mismatch", 3, "cass_exit"),
        ("missing-index", 3, "cass_exit"),
    ];

    for (kind, exit, expected) in cases {
        fixture.answer("ignored stdout", &cli_error(kind, exit), exit);
        let result = client.call_2025(&session, "cass_sessions", json!({}));
        assert_is_error(&result);
        assert_eq!(error_code(&result), expected, "[{kind}]");
        let text = result_text(&result);
        assert!(!text.contains(secret), "[{kind}] stderr must not be echoed");
        assert!(
            !text.contains("\"hint\""),
            "[{kind}] the CLI envelope is not forwarded"
        );
        let value: Value = serde_json::from_str(text).expect("error text is JSON");
        assert_eq!(
            value["error"]["cli_exit_code"], exit,
            "[{kind}] the real numeric exit code is carried"
        );
    }

    // Complete JSON on stderr is required; anything else is cass_exit.
    for (label, stderr) in [
        ("non-JSON stderr", format!("{secret}\n")),
        ("empty stderr", String::new()),
        (
            "partial envelope",
            format!("{}\n{secret}", cli_error("usage", 2)),
        ),
        (
            "error without kind",
            json!({ "error": { "code": 2, "message": secret } }).to_string(),
        ),
        (
            "top-level not error",
            json!({ "kind": "usage", "message": secret }).to_string(),
        ),
    ] {
        fixture.answer("", &stderr, 2);
        let result = client.call_2025(&session, "cass_sessions", json!({}));
        assert_is_error(&result);
        assert_eq!(error_code(&result), "cass_exit", "[{label}]");
        assert!(!result_text(&result).contains(secret), "[{label}]");
    }

    // A signal-style status has no numeric code to carry.
    fixture.answer("", "", 137);
    let result = client.call_2025(&session, "cass_sessions", json!({}));
    assert_is_error(&result);
    assert_eq!(error_code(&result), "cass_exit");
    let value: Value = serde_json::from_str(result_text(&result)).expect("error text is JSON");
    assert_eq!(
        value["error"]["cli_exit_code"], 137,
        "the shell-reported exit status is carried as observed"
    );

    // A legal-looking stdout must not leak when the CLI failed.
    let leaked = format!(
        r#"<cass_recall version="1" tool="cass_sessions">{}{secret}</cass_recall>"#,
        "&quot;sessions&quot;:[]"
    );
    fixture.answer(&leaked, &cli_error("model_unavailable", 9), 9);
    let result = client.call_2025(&session, "cass_sessions", json!({}));
    assert_is_error(&result);
    assert_eq!(error_code(&result), "model_unavailable");
    assert!(
        !result_text(&result).contains(secret),
        "stdout must not be forwarded on a failed call"
    );
}

// ---------------------------------------------------------------------------
// 12-AC4: only the four read tools, fixed search options
// ---------------------------------------------------------------------------

#[test]
fn tools_list_exposes_exactly_the_four_read_tools() {
    let fixture = Fixture::new("tools-list");
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    let value = client.request_2025(&session, "tools/list", json!({}));
    let tools = value["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list must return an array: {value}"));
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
        ]
    );
    assert_eq!(tools.len(), 4, "no management or write tools are allowed");

    for tool in tools {
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object", "schema for {tool}");
        assert_eq!(
            schema["additionalProperties"], false,
            "unknown fields must be rejected: {tool}"
        );
    }

    assert!(
        fixture.calls().is_empty(),
        "listing tools must not start a subprocess"
    );
}

#[test]
fn search_never_adds_management_flags() {
    let fixture = Fixture::new("no-management");
    fixture.answer(SEARCH_EMPTY, "", 0);
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    let result = client.call_2025(&session, "cass_search", json!({ "query": "q" }));
    assert_success(&result);

    let calls = fixture.calls();
    assert_eq!(calls.len(), 1);
    for forbidden in [
        "--db",
        "--refresh",
        "--catch-up",
        "--json",
        "--robot-format",
        "--mode=lexical",
        "--mode=semantic",
        "index",
        "sources",
        "doctor",
    ] {
        assert!(
            !calls[0]
                .args
                .iter()
                .any(|arg| arg == forbidden || arg.starts_with(&format!("{forbidden}="))),
            "search must not add {forbidden}: {:?}",
            calls[0].args
        );
    }
    assert_eq!(
        calls[0]
            .args
            .iter()
            .filter(|arg| *arg == "--recall")
            .count(),
        1
    );
}

// ---------------------------------------------------------------------------
// C4-A1: SDK-negotiated session and stateless paths
// ---------------------------------------------------------------------------

#[test]
fn protocol_session_and_stateless_paths_both_serve_tools() {
    let fixture = Fixture::new("protocol");
    fixture.answer(SESSIONS_EMPTY, "", 0);
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    assert_eq!(
        tool_names(&mut client, &session),
        vec![
            "cass_search",
            "cass_expand",
            "cass_sessions",
            "cass_timeline"
        ]
    );
    let result = client.call_2025(&session, "cass_sessions", json!({}));
    assert_success(&result);
    assert_eq!(result_text(&result), SESSIONS_EMPTY);
    assert_eq!(fixture.calls().len(), 1);

    // 2026-07-28 is stateless: discover first, then call without a session id.
    let discover = client.request_2026("server/discover", json!({}));
    assert_eq!(
        discover["result"]["supportedVersions"]
            .as_array()
            .map(|versions| versions.iter().any(|v| v == PROTOCOL_2026)),
        Some(true),
        "discover must advertise 2026-07-28: {discover}"
    );
    let result = client.call_2026("cass_sessions", json!({}));
    assert_success(&result);
    assert_eq!(result_text(&result), SESSIONS_EMPTY);
    assert_eq!(fixture.calls().len(), 2);
}

#[test]
fn unknown_tool_is_a_protocol_error() {
    let fixture = Fixture::new("unknown-tool");
    let (server, session) = session_client(&fixture);
    let mut client = Client::new(&server);

    let value = client.request_2025(
        &session,
        "tools/call",
        json!({ "name": "cass_doctor", "arguments": {} }),
    );
    assert_eq!(
        value["error"]["code"], -32601,
        "unknown tool must be METHOD_NOT_FOUND: {value}"
    );
    assert!(
        value.get("result").is_none(),
        "no tool result may be returned"
    );
    assert!(
        fixture.calls().is_empty(),
        "an unknown tool must not start a subprocess"
    );
}

// ---------------------------------------------------------------------------
// 08-AC1: the four recall tools advertise read-only metadata over real HTTP
// ---------------------------------------------------------------------------

const ALIEN_TOOLS: [&str; 4] = [
    "cass_search",
    "cass_expand",
    "cass_sessions",
    "cass_timeline",
];

/// `tools/list` over the real HTTP transport, asserting no subprocess ran.
fn alien_tools(fixture: &Fixture) -> Vec<Value> {
    let (server, session) = session_client(fixture);
    let mut client = Client::new(&server);
    let value = client.request_2025(&session, "tools/list", json!({}));
    assert!(
        fixture.calls().is_empty(),
        "listing tools must not start a subprocess"
    );
    value["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list must return an array: {value}"))
        .clone()
}

/// Exactly the original four tools, and the named one carries the frozen
/// read-only annotations field by field.
fn assert_alien_readonly(tools: &[Value], name: &str) {
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(
        names,
        ALIEN_TOOLS.to_vec(),
        "the tool set must stay exactly the four recall tools"
    );
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == name)
        .unwrap_or_else(|| panic!("tools/list must include {name}: {tools:?}"));
    let annotations = tool
        .get("annotations")
        .unwrap_or_else(|| panic!("{name} must carry annotations: {tool}"));
    assert_eq!(annotations["readOnlyHint"], true, "{name}");
    assert_eq!(annotations["destructiveHint"], false, "{name}");
    assert_eq!(annotations["idempotentHint"], true, "{name}");
}

#[test]
fn alien_readonly_search() {
    let fixture = Fixture::new("alien-readonly-search");
    let tools = alien_tools(&fixture);
    assert_alien_readonly(&tools, "cass_search");
    assert!(
        fixture.calls().is_empty(),
        "listing tools must not start a subprocess"
    );
}

#[test]
fn alien_readonly_expand() {
    let fixture = Fixture::new("alien-readonly-expand");
    let tools = alien_tools(&fixture);
    assert_alien_readonly(&tools, "cass_expand");
    assert!(
        fixture.calls().is_empty(),
        "listing tools must not start a subprocess"
    );
}

#[test]
fn alien_readonly_sessions() {
    let fixture = Fixture::new("alien-readonly-sessions");
    let tools = alien_tools(&fixture);
    assert_alien_readonly(&tools, "cass_sessions");
    assert!(
        fixture.calls().is_empty(),
        "listing tools must not start a subprocess"
    );
}

#[test]
fn alien_readonly_timeline() {
    let fixture = Fixture::new("alien-readonly-timeline");
    let tools = alien_tools(&fixture);
    assert_alien_readonly(&tools, "cass_timeline");
    assert!(
        fixture.calls().is_empty(),
        "listing tools must not start a subprocess"
    );
}
