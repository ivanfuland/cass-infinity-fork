//! API01C: the real-CLI contract of `cass models list` and `cass models check`.
//!
//! Every assertion here drives the real `cass` binary against a real
//! configuration file and a real loopback HTTP service. Nothing stubs the CLI
//! argument struct or the transport: the seam the ticket asks for is "real
//! subprocess, real config file, real HTTP requests, request bodies and headers
//! inspected".
//!
//! The service is synthetic and public: it answers fixed JSON shapes and the
//! tests only ever send the fixed synthetic check text. No private corpus, no
//! credential value and no real endpoint is involved.

use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const EMBED_MODEL: &str = "example/synthetic-embed";
const RERANK_MODEL: &str = "example/synthetic-rank";
const EMBED_REVISION: &str = "rev-synthetic-1";
const RERANK_REVISION: &str = "rev-synthetic-2";
const BEARER: &str = "SYNTHETIC_BEARER_marker_9f3a1c7d";
const SERVICE_BODY_MARKER: &str = "SYNTHETIC_SERVICE_BODY_MARKER";
const CREDENTIAL_ENV: &str = "SYNTHETIC_MODEL_TOKEN";
const CHECK_TEXT: &str = "CASS model API check.";

// ---------------------------------------------------------------------------
// A loopback HTTP service that records every request it answers
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

impl RecordedRequest {
    fn body_json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

type Responder = Arc<dyn Fn(&RecordedRequest, usize) -> (u16, String) + Send + Sync>;

struct Stub {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<RecordedRequest>>>,
    stop: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Stub {
    fn start<F>(responder: F) -> Stub
    where
        F: Fn(&RecordedRequest, usize) -> (u16, String) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind model stub");
        let addr = listener.local_addr().expect("stub local_addr");
        listener.set_nonblocking(true).expect("stub nonblocking");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let responder: Responder = Arc::new(responder);

        let seen_thread = Arc::clone(&seen);
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Some(request) = read_http_request(stream.try_clone().expect("clone"))
                        {
                            let index = {
                                let mut guard = seen_thread.lock().expect("stub lock");
                                let index = guard.len();
                                guard.push(request.clone());
                                index
                            };
                            let (status, body) = responder(&request, index);
                            let _ = write_http_response(stream, status, &body);
                        }
                    }
                    Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Stub {
            addr,
            seen,
            stop,
            handle: Mutex::new(Some(handle)),
        }
    }

    fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.seen.lock().expect("stub lock").clone()
    }

    fn request_count(&self) -> usize {
        self.seen.lock().expect("stub lock").len()
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.lock().expect("stub thread lock").take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_http_request(mut stream: TcpStream) -> Option<RecordedRequest> {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(headers_end) = find_subslice(&buffer, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..headers_end]).to_string();
            let content_length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let body_start = headers_end + 4;
            if buffer.len() >= body_start + content_length {
                let body = buffer[body_start..body_start + content_length].to_vec();
                let mut parts = head.lines().next().unwrap_or_default().split(' ');
                let method = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or_default().to_string();
                let authorization = head.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("authorization")
                        .then(|| value.trim().to_string())
                });
                return Some(RecordedRequest {
                    method,
                    path,
                    authorization,
                    body,
                });
            }
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_http_response(mut stream: TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Error" };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Write);
    Ok(())
}

// ---------------------------------------------------------------------------
// Canned service behaviours
// ---------------------------------------------------------------------------

/// Answer an embedding request with `dimension`-wide vectors for every input.
fn embedding_answer(
    dimension: usize,
) -> impl Fn(&RecordedRequest, usize) -> (u16, String) + Send + Sync {
    move |request: &RecordedRequest, _index: usize| {
        let body = request.body_json();
        let count = body["input"].as_array().map_or(0, Vec::len);
        let data: Vec<serde_json::Value> = (0..count)
            .map(|index| {
                serde_json::json!({ "index": index, "embedding": vec![0.25_f64; dimension] })
            })
            .collect();
        (
            200,
            serde_json::json!({ "model": EMBED_MODEL, "data": data }).to_string(),
        )
    }
}

/// Answer a rerank request with one strictly increasing score per document.
fn rerank_answer() -> impl Fn(&RecordedRequest, usize) -> (u16, String) + Send + Sync {
    |request: &RecordedRequest, _index: usize| {
        let body = request.body_json();
        let count = body["documents"].as_array().map_or(0, Vec::len);
        let results: Vec<serde_json::Value> = (0..count)
            .map(|index| serde_json::json!({ "index": index, "relevance_score": index as f64 }))
            .collect();
        (
            200,
            serde_json::json!({ "model": RERANK_MODEL, "results": results }).to_string(),
        )
    }
}

// ---------------------------------------------------------------------------
// Configuration fixtures
// ---------------------------------------------------------------------------

fn embedding_profile(id: &str, origin: &str, extra: &[&str]) -> String {
    let mut block = format!(
        "[profiles.{id}]\n\
         kind = \"embedding\"\n\
         protocol = \"openai-embeddings-v1\"\n\
         endpoint = \"{origin}/v1/embeddings\"\n\
         scope = \"loopback\"\n\
         model = \"{EMBED_MODEL}\"\n\
         model_revision = \"{EMBED_REVISION}\"\n\
         normalization = \"l2\"\n"
    );
    for line in extra {
        block.push_str(line);
        block.push('\n');
    }
    block
}

fn rerank_profile(id: &str, origin: &str, extra: &[&str]) -> String {
    let mut block = format!(
        "[profiles.{id}]\n\
         kind = \"rerank\"\n\
         protocol = \"rerank-json-v1\"\n\
         endpoint = \"{origin}/v1/rerank\"\n\
         scope = \"loopback\"\n\
         model = \"{RERANK_MODEL}\"\n\
         model_revision = \"{RERANK_REVISION}\"\n"
    );
    for line in extra {
        block.push_str(line);
        block.push('\n');
    }
    block
}

fn write_config(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).expect("write api config");
    path
}

// ---------------------------------------------------------------------------
// The real-CLI harness
// ---------------------------------------------------------------------------

struct Harness {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    data_dir: PathBuf,
}

impl Harness {
    fn new() -> Harness {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let data_dir = tmp.path().join("data");
        fs::create_dir_all(&home).expect("create home");
        Harness {
            _tmp: tmp,
            home,
            data_dir,
        }
    }

    fn dir(&self) -> &Path {
        self.home.parent().expect("temp root")
    }

    fn run(&self, envs: &[(&str, &str)], args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cass"));
        command.env_clear();
        command.env("PATH", std::env::var_os("PATH").unwrap_or_default());
        command.env("HOME", &self.home);
        command.env("TMPDIR", &self.home);
        command.env("XDG_DATA_HOME", self.home.join("xdg-data"));
        command.env("XDG_CONFIG_HOME", self.home.join("xdg-config"));
        command.env("XDG_CACHE_HOME", self.home.join("xdg-cache"));
        command.env("CASS_DATA_DIR", &self.data_dir);
        for (key, value) in envs {
            command.env(key, value);
        }
        command.current_dir(&self.home);
        command.args(args);
        command.output().expect("run cass binary")
    }

    /// Every file under the temp home, so a test can prove nothing was created.
    fn files_under_home(&self) -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push(path);
                }
            }
        }
        let mut out = Vec::new();
        walk(self.dir(), &mut out);
        out
    }
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn stdout_json(output: &Output) -> serde_json::Value {
    let text = stdout_text(output);
    serde_json::from_str(text.trim()).unwrap_or_else(|err| {
        panic!(
            "stdout is not valid JSON ({err}); stderr: {}",
            stderr_text(output)
        )
    })
}

/// Parse the whole machine error envelope the CLI prints on stderr.
fn stderr_document(output: &Output) -> serde_json::Value {
    let text = stderr_text(output);
    serde_json::from_str(text.trim())
        .unwrap_or_else(|err| panic!("stderr is not a JSON error envelope ({err}); stderr: {text}"))
}

/// The `error` object of the machine error envelope.
///
/// It is either the standard `{error:{...}}` wrapper or a command's own
/// pre-formatted document carrying an `error` object.
fn stderr_error(output: &Output) -> serde_json::Value {
    let value = stderr_document(output);
    value
        .get("error")
        .cloned()
        .unwrap_or_else(|| panic!("no error object in stderr envelope: {value}"))
}

fn assert_exit(output: &Output, code: i32, context: &str) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{context}: expected exit {code}; stdout: {}; stderr: {}",
        stdout_text(output),
        stderr_text(output)
    );
}

fn err_kind(output: &Output) -> String {
    stderr_error(output)
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Read an integer field by JSON pointer, so no numeric type is inferred.
fn u64_at(value: &serde_json::Value, pointer: &str) -> Option<u64> {
    value.pointer(pointer).and_then(serde_json::Value::as_u64)
}

/// Read a boolean field by JSON pointer.
fn bool_at(value: &serde_json::Value, pointer: &str) -> Option<bool> {
    value.pointer(pointer).and_then(serde_json::Value::as_bool)
}

// ---------------------------------------------------------------------------
// M1: `models list` reads the configuration and nothing else
// ---------------------------------------------------------------------------

#[test]
fn list_reports_profiles_sorted_with_zero_http() {
    let stub = Stub::start(embedding_answer(4));
    let harness = Harness::new();
    let body = format!(
        "version = 1\ndefault_embedding = \"zzz-last\"\n\n{}{}",
        embedding_profile("zzz-last", &stub.origin(), &[]),
        embedding_profile("aaa-first", &stub.origin(), &[]),
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[],
        &[
            "models",
            "list",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 0, "models list --json");

    let payload = stdout_json(&output);
    assert_eq!(
        payload["schema"], "cass.model-api-list.v1",
        "the list envelope schema is fixed"
    );
    let profiles = payload["profiles"].as_array().expect("profiles array");
    let ids: Vec<&str> = profiles
        .iter()
        .map(|row| row["id"].as_str().expect("id"))
        .collect();
    assert_eq!(ids, vec!["aaa-first", "zzz-last"], "ascending by id");
    assert_eq!(profiles[0]["kind"], "embedding");
    assert_eq!(profiles[0]["protocol"], "openai-embeddings-v1");
    assert_eq!(profiles[0]["model"], EMBED_MODEL);
    assert_eq!(profiles[0]["model_revision"], EMBED_REVISION);
    assert_eq!(profiles[0]["scope"], "loopback");
    assert_eq!(
        bool_at(&payload, "/profiles/1/default"),
        Some(true),
        "the configured default is marked"
    );
    assert_eq!(bool_at(&payload, "/profiles/0/default"), Some(false));
    assert_eq!(
        profiles[0]["endpoint"],
        format!("{}/v1/embeddings", stub.origin())
    );

    assert_eq!(stub.request_count(), 0, "list must send no HTTP request");
    for path in harness.files_under_home() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        assert!(
            !name.ends_with(".db") && name != "model.onnx" && name != "tokenizer.json",
            "list must create no database or model weight: {}",
            path.display()
        );
    }
}

#[test]
fn list_never_reads_the_credential_value() {
    let stub = Stub::start(embedding_answer(4));
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile(
            "local-embed",
            &stub.origin(),
            &[&format!("api_key_env = \"{CREDENTIAL_ENV}\"")],
        ),
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    // The credential variable is set, but `list` must still not read it.
    let output = harness.run(
        &[(CREDENTIAL_ENV, BEARER)],
        &[
            "models",
            "list",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 0, "models list with a credential variable present");

    let payload = stdout_json(&output);
    let profiles = payload["profiles"].as_array().expect("profiles array");
    assert_eq!(
        profiles[0]["api_key_env"], CREDENTIAL_ENV,
        "the name is listed"
    );
    let combined = format!("{}{}", stdout_text(&output), stderr_text(&output));
    assert!(
        !combined.contains(BEARER),
        "the credential value must never be read or printed"
    );
    assert_eq!(stub.request_count(), 0);
}

#[test]
fn a_credential_variable_alone_is_not_a_retired_route() {
    // A credential variable that the API configuration may reference must not
    // be mistaken for a retired local/Infinity model-selection variable.
    let stub = Stub::start(embedding_answer(4));
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile(
            "local-embed",
            &stub.origin(),
            &[&format!("api_key_env = \"{CREDENTIAL_ENV}\"")],
        ),
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[(CREDENTIAL_ENV, BEARER)],
        &[
            "models",
            "list",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 0, "a credential variable is not a migration error");
}

// ---------------------------------------------------------------------------
// M2: the embedding and rerank checks against a real HTTP service
// ---------------------------------------------------------------------------

#[test]
fn embedding_check_sends_one_query_and_one_document_with_declared_prefixes() {
    let stub = Stub::start(embedding_answer(6));
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile(
            "local-embed",
            &stub.origin(),
            &[
                "query_prefix = \"query: \"",
                "document_prefix = \"passage: \""
            ],
        ),
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[],
        &[
            "models",
            "check",
            "--profile",
            "local-embed",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 0, "embedding check");

    let requests = stub.requests();
    assert_eq!(requests.len(), 2, "exactly one query and one document POST");
    assert!(
        requests.iter().all(|request| request.method == "POST"),
        "checks never GET"
    );
    assert!(
        requests
            .iter()
            .all(|request| request.path == "/v1/embeddings")
    );

    let sent: Vec<String> = requests
        .iter()
        .map(|request| {
            request.body_json()["input"][0]
                .as_str()
                .expect("one input string")
                .to_string()
        })
        .collect();
    assert_eq!(
        sent,
        vec![
            format!("query: {CHECK_TEXT}"),
            format!("passage: {CHECK_TEXT}")
        ],
        "the kernel builds each input from the profile's own prefix"
    );

    let payload = stdout_json(&output);
    assert_eq!(payload["schema"], "cass.model-api-check.v1");
    assert_eq!(payload["profile_id"], "local-embed");
    assert_eq!(payload["kind"], "embedding");
    assert_eq!(payload["requested_model"], EMBED_MODEL);
    assert_eq!(payload["declared_revision"], EMBED_REVISION);
    assert_eq!(payload["response_model"], EMBED_MODEL);
    assert_eq!(payload["revision_source"], "operator_declared");
    assert_eq!(payload["mode"], "single_profile_check");
    assert_eq!(bool_at(&payload, "/fallback_used"), Some(false));
    assert_eq!(u64_at(&payload, "/effective_dimension"), Some(6));
    assert_eq!(payload["scored_count"], serde_json::Value::Null);
    let descriptor = payload["descriptor_sha256"].as_str().expect("descriptor");
    assert_eq!(descriptor.len(), 64, "a sha256 hex digest");
    let calls = payload["calls"].as_array().expect("calls array");
    let stages: Vec<&str> = calls
        .iter()
        .map(|call| call["stage"].as_str().expect("stage"))
        .collect();
    assert_eq!(stages, vec!["query", "document"]);
    assert_eq!(bool_at(&payload, "/calls/0/network_attempted"), Some(true));
    assert_eq!(bool_at(&payload, "/calls/1/network_attempted"), Some(true));
    assert_eq!(u64_at(&payload, "/calls/0/http_status"), Some(200));
    assert_eq!(u64_at(&payload, "/calls/1/http_status"), Some(200));
}

#[test]
fn rerank_check_sends_one_post_with_the_two_synthetic_documents() {
    let stub = Stub::start(rerank_answer());
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        rerank_profile("local-rank", &stub.origin(), &[])
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[],
        &[
            "models",
            "check",
            "--profile",
            "local-rank",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 0, "rerank check");

    let requests = stub.requests();
    assert_eq!(requests.len(), 1, "exactly one rerank POST");
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/v1/rerank");
    let sent = requests[0].body_json();
    assert_eq!(sent["query"], CHECK_TEXT);
    let documents = sent["documents"].as_array().expect("documents");
    assert_eq!(documents.len(), 2, "two fixed synthetic documents");
    assert_eq!(
        sent["top_n"].as_u64(),
        Some(2),
        "top_n covers every real candidate"
    );
    assert_eq!(sent["return_documents"].as_bool(), Some(false));

    let payload = stdout_json(&output);
    assert_eq!(payload["schema"], "cass.model-api-check.v1");
    assert_eq!(payload["kind"], "rerank");
    assert_eq!(payload["mode"], "single_profile_check");
    assert_eq!(bool_at(&payload, "/fallback_used"), Some(false));
    assert_eq!(u64_at(&payload, "/scored_count"), Some(2));
    assert_eq!(payload["effective_dimension"], serde_json::Value::Null);
    assert_eq!(payload["descriptor_sha256"], serde_json::Value::Null);
    let calls = payload["calls"].as_array().expect("calls array");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["stage"], "rerank");
    assert_eq!(bool_at(&payload, "/calls/0/network_attempted"), Some(true));
}

#[test]
fn two_arbitrary_profiles_run_through_the_same_binary() {
    let stub = Stub::start(|request: &RecordedRequest, _index: usize| {
        if request.path == "/v1/rerank" {
            let body = request.body_json();
            let count = body["documents"].as_array().map_or(0, Vec::len);
            let results: Vec<serde_json::Value> = (0..count)
                .map(|index| serde_json::json!({ "index": index, "relevance_score": 0.5 }))
                .collect();
            return (
                200,
                serde_json::json!({ "model": RERANK_MODEL, "results": results }).to_string(),
            );
        }
        let body = request.body_json();
        let count = body["input"].as_array().map_or(0, Vec::len);
        let data: Vec<serde_json::Value> = (0..count)
            .map(|index| serde_json::json!({ "index": index, "embedding": vec![0.5_f64; 3] }))
            .collect();
        (
            200,
            serde_json::json!({ "model": EMBED_MODEL, "data": data }).to_string(),
        )
    });

    let harness = Harness::new();
    let body = format!(
        "version = 1\ndefault_embedding = \"alpha\"\ndefault_rerank = \"beta\"\n\n{}{}",
        embedding_profile("alpha", &stub.origin(), &[]),
        rerank_profile("beta", &stub.origin(), &[]),
    );
    let config = write_config(harness.dir(), "models.toml", &body);
    let config = config.to_str().expect("path").to_string();

    for (profile, kind) in [("alpha", "embedding"), ("beta", "rerank")] {
        let output = harness.run(
            &[],
            &[
                "models",
                "check",
                "--profile",
                profile,
                "--api-config",
                &config,
                "--json",
            ],
        );
        assert_exit(&output, 0, profile);
        let payload = stdout_json(&output);
        assert_eq!(payload["profile_id"], profile);
        assert_eq!(payload["kind"], kind);
    }
}

// ---------------------------------------------------------------------------
// M3: configuration selection, precedence and the migration gate
// ---------------------------------------------------------------------------

#[test]
fn the_cli_config_path_wins_over_the_environment() {
    let stub = Stub::start(embedding_answer(4));
    let harness = Harness::new();
    let cli_body = format!(
        "version = 1\n{}",
        embedding_profile("from-cli", &stub.origin(), &[])
    );
    let env_body = format!(
        "version = 1\n{}",
        embedding_profile("from-env", &stub.origin(), &[])
    );
    let cli_config = write_config(harness.dir(), "cli.toml", &cli_body);
    let env_config = write_config(harness.dir(), "env.toml", &env_body);

    let output = harness.run(
        &[("CASS_API_CONFIG", env_config.to_str().expect("path"))],
        &[
            "models",
            "list",
            "--api-config",
            cli_config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 0, "cli config wins");
    let payload = stdout_json(&output);
    let ids: Vec<&str> = payload["profiles"]
        .as_array()
        .expect("profiles")
        .iter()
        .map(|row| row["id"].as_str().expect("id"))
        .collect();
    assert_eq!(
        ids,
        vec!["from-cli"],
        "the environment file must be ignored"
    );

    // The same selection works with the environment alone.
    let output = harness.run(
        &[("CASS_API_CONFIG", env_config.to_str().expect("path"))],
        &["models", "list", "--json"],
    );
    assert_exit(&output, 0, "env config alone");
    let payload = stdout_json(&output);
    assert_eq!(payload["profiles"][0]["id"], "from-env");
}

#[test]
fn the_config_flag_works_before_and_after_the_subcommand() {
    let stub = Stub::start(embedding_answer(4));
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile("local-embed", &stub.origin(), &[])
    );
    let config = write_config(harness.dir(), "models.toml", &body);
    let path = config.to_str().expect("path").to_string();

    // Leading: the global flag precedes the subcommand.
    let output = harness.run(&[], &["--api-config", &path, "models", "list", "--json"]);
    assert_exit(&output, 0, "leading --api-config");
    assert_eq!(stdout_json(&output)["profiles"][0]["id"], "local-embed");

    // Trailing: the same flag follows the subcommand.
    let output = harness.run(&[], &["models", "list", "--api-config", &path, "--json"]);
    assert_exit(&output, 0, "trailing --api-config");
    assert_eq!(stdout_json(&output)["profiles"][0]["id"], "local-embed");

    // Inline `=` form, also trailing.
    let inline = format!("--api-config={path}");
    let output = harness.run(&[], &["models", "list", &inline, "--json"]);
    assert_exit(&output, 0, "inline --api-config=<PATH>");
    assert_eq!(stdout_json(&output)["profiles"][0]["id"], "local-embed");

    assert_eq!(stub.request_count(), 0, "list sends no request in any form");
}

#[test]
fn a_missing_configuration_is_refused_with_code_two_and_no_http() {
    let stub = Stub::start(embedding_answer(4));
    let harness = Harness::new();

    let output = harness.run(&[], &["models", "list", "--json"]);
    assert_exit(&output, 2, "models list without a configuration");
    assert_eq!(err_kind(&output), "ModelApiConfiguration");
    assert_eq!(stub.request_count(), 0);
}

#[test]
fn a_broken_configuration_is_refused_with_code_two_and_no_http() {
    let stub = Stub::start(embedding_answer(4));
    let harness = Harness::new();
    let config = write_config(
        harness.dir(),
        "broken.toml",
        "version = 1\nthis is not toml\n",
    );

    let output = harness.run(
        &[],
        &[
            "models",
            "list",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 2, "broken TOML");
    assert_eq!(err_kind(&output), "ModelApiConfiguration");
    assert_eq!(stub.request_count(), 0);
}

#[test]
fn an_unreadable_configuration_path_is_refused_without_echoing_it() {
    let harness = Harness::new();
    let missing = harness.dir().join("nowhere").join("absent.toml");
    let output = harness.run(
        &[],
        &[
            "models",
            "list",
            "--api-config",
            missing.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 2, "unreadable configuration");
    assert_eq!(err_kind(&output), "ModelApiConfiguration");
    let combined = format!("{}{}", stdout_text(&output), stderr_text(&output));
    assert!(
        !combined.contains("absent.toml"),
        "the path must not be echoed: {combined}"
    );
}

#[test]
fn an_unknown_profile_is_refused_with_code_two_and_no_http() {
    let stub = Stub::start(embedding_answer(4));
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile("local-embed", &stub.origin(), &[])
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[],
        &[
            "models",
            "check",
            "--profile",
            "not-configured",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 2, "unknown profile");
    assert_eq!(err_kind(&output), "ModelApiConfiguration");
    assert_eq!(
        stub.request_count(),
        0,
        "an unknown profile is refused before any request"
    );
}

#[test]
fn every_retired_variable_is_refused_before_the_configuration_is_read() {
    const RETIRED: [&str; 7] = [
        "CASS_INFINITY_URL",
        "CASS_INFINITY_EMBED_MODEL",
        "CASS_INFINITY_RERANK_MODEL",
        "CASS_QWEN_RERANK_URL",
        "CASS_SEMANTIC_EMBEDDER",
        "CASS_SEMANTIC_DOWNLOAD_POLICY",
        "CASS_SEMANTIC_MAX_MODEL_SIZE_MB",
    ];

    let stub = Stub::start(embedding_answer(4));
    let harness = Harness::new();

    for variable in RETIRED {
        for value in ["", "retired-value"] {
            // The configuration path deliberately does not exist: if the
            // migration gate did not run first, this would surface as an
            // unreadable-configuration error instead.
            let output = harness.run(
                &[(variable, value)],
                &[
                    "models",
                    "list",
                    "--api-config",
                    "/nonexistent/definitely-absent.toml",
                    "--json",
                ],
            );
            assert_exit(&output, 2, variable);
            assert_eq!(
                err_kind(&output),
                "ModelApiMigration",
                "{variable}={value:?} must be refused as a migration, not as a config error"
            );
        }
    }
    assert_eq!(stub.request_count(), 0, "the gate sends nothing");
}

// ---------------------------------------------------------------------------
// M4: a wrong response is refused, and a configured fallback never rescues it
// ---------------------------------------------------------------------------

#[test]
fn an_expected_dimension_mismatch_is_refused() {
    let stub = Stub::start(embedding_answer(4));
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile("local-embed", &stub.origin(), &["expected_dimension = 8"])
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[],
        &[
            "models",
            "check",
            "--profile",
            "local-embed",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 1, "expected dimension mismatch");
    let document = stderr_document(&output);
    assert_eq!(document["error"]["kind"], "ModelApiCheck");
    assert_eq!(document["error"]["code"], 1);
    assert!(
        document["error"]["message"]
            .as_str()
            .is_some_and(|m| !m.is_empty()),
        "the failure carries a bounded short code"
    );
    // The failure document keeps the attempt that observed the wrong width.
    let calls = document["calls"].as_array().expect("calls");
    assert_eq!(calls.len(), 1);
    assert_eq!(u64_at(&document, "/calls/0/http_status"), Some(200));
}

#[test]
fn a_missing_response_item_is_refused() {
    let stub = Stub::start(|_request: &RecordedRequest, _index: usize| {
        (
            200,
            serde_json::json!({ "model": EMBED_MODEL, "data": [] }).to_string(),
        )
    });
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile("local-embed", &stub.origin(), &[])
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[],
        &[
            "models",
            "check",
            "--profile",
            "local-embed",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 1, "a short response is refused whole");
    let document = stderr_document(&output);
    let calls = document["calls"].as_array().expect("calls");
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0]["error_code"].as_str().is_some(),
        "the rejected stage carries its bounded code"
    );
}

#[test]
fn an_http_401_is_refused_with_its_status() {
    let stub = Stub::start(|_request: &RecordedRequest, _index: usize| {
        (
            401,
            serde_json::json!({ "error": SERVICE_BODY_MARKER }).to_string(),
        )
    });
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile("local-embed", &stub.origin(), &[])
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[],
        &[
            "models",
            "check",
            "--profile",
            "local-embed",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 1, "http 401");
    let document = stderr_document(&output);
    assert_eq!(document["error"]["kind"], "ModelApiCheck");
    let calls = document["calls"].as_array().expect("calls");
    assert_eq!(calls.len(), 1, "a 401 is not fallback-eligible");
    assert_eq!(u64_at(&document, "/calls/0/http_status"), Some(401));
}

#[test]
fn a_wrong_response_model_is_refused() {
    let stub = Stub::start(|_request: &RecordedRequest, _index: usize| {
        (
            200,
            serde_json::json!({
                "model": "not/the-configured-model",
                "data": [ { "index": 0, "embedding": vec![0.25_f64; 4] } ],
            })
            .to_string(),
        )
    });
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile("local-embed", &stub.origin(), &[])
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[],
        &[
            "models",
            "check",
            "--profile",
            "local-embed",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 1, "an unaccepted response model");
}

#[test]
fn the_query_and_document_checks_must_agree_on_width() {
    let stub = Stub::start(|_request: &RecordedRequest, index: usize| {
        let dimension = if index == 0 { 4 } else { 8 };
        (
            200,
            serde_json::json!({
                "model": EMBED_MODEL,
                "data": [ { "index": 0, "embedding": vec![0.25_f64; dimension] } ],
            })
            .to_string(),
        )
    });
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile("local-embed", &stub.origin(), &[])
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[],
        &[
            "models",
            "check",
            "--profile",
            "local-embed",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 1, "the two checks must agree on width");
    let document = stderr_document(&output);
    let calls = document["calls"].as_array().expect("calls");
    assert_eq!(calls.len(), 2, "both stages really ran");
    assert_eq!(calls[0]["stage"], "query");
    assert_eq!(calls[1]["stage"], "document");
}

#[test]
fn a_configured_fallback_is_never_used_by_check() {
    let stub = Stub::start(|_request: &RecordedRequest, _index: usize| {
        (
            500,
            serde_json::json!({ "error": SERVICE_BODY_MARKER }).to_string(),
        )
    });
    let harness = Harness::new();
    // A remote https fallback that is never contacted. If the check used it,
    // the calls array would carry a second attempt.
    let body = format!(
        "version = 1\ndefault_rerank = \"local-rank\"\n\n{}{}",
        rerank_profile(
            "local-rank",
            &stub.origin(),
            &["fallback_profile = \"cloud-rank\""]
        ),
        "[profiles.cloud-rank]\n\
         kind = \"rerank\"\n\
         protocol = \"openrouter-rerank-v1\"\n\
         endpoint = \"https://127.0.0.1:9/v1/rerank\"\n\
         scope = \"remote\"\n\
         model = \"example/cloud-rank\"\n\
         model_revision = \"rev-cloud\"\n",
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[],
        &[
            "models",
            "check",
            "--profile",
            "local-rank",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 1, "a declared fallback must not rescue the check");

    let document = stderr_document(&output);
    let calls = document["calls"].as_array().expect("calls");
    assert_eq!(calls.len(), 1, "exactly the primary attempt was made");
    assert_eq!(calls[0]["stage"], "rerank");
    assert_eq!(u64_at(&document, "/calls/0/http_status"), Some(500));
    assert_eq!(bool_at(&document, "/fallback_used"), Some(false));
    assert_eq!(
        stub.request_count(),
        1,
        "the service saw the primary attempt only"
    );
}

// ---------------------------------------------------------------------------
// M5: privacy and truthful identity
// ---------------------------------------------------------------------------

#[test]
fn the_check_sends_the_bearer_and_never_echoes_it_or_the_body() {
    let stub = Stub::start(|_request: &RecordedRequest, _index: usize| {
        (
            401,
            serde_json::json!({ "detail": SERVICE_BODY_MARKER }).to_string(),
        )
    });
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile(
            "local-embed",
            &stub.origin(),
            &[&format!("api_key_env = \"{CREDENTIAL_ENV}\"")],
        )
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[(CREDENTIAL_ENV, BEARER)],
        &[
            "models",
            "check",
            "--profile",
            "local-embed",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 1, "the synthetic service refuses");

    let requests = stub.requests();
    assert!(!requests.is_empty(), "the service was really contacted");
    let expected_authorization = format!("Bearer {BEARER}");
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some(expected_authorization.as_str()),
        "the request really carries the bearer"
    );

    let combined = format!("{}{}", stdout_text(&output), stderr_text(&output));
    assert!(
        !combined.contains(BEARER),
        "the credential value must never surface: {combined}"
    );
    assert!(
        !combined.contains(SERVICE_BODY_MARKER),
        "the service response body must never surface: {combined}"
    );
}

#[test]
fn a_silent_service_keeps_the_observed_identity_null() {
    let stub = Stub::start(|_request: &RecordedRequest, _index: usize| {
        (
            200,
            serde_json::json!({
                "data": [ { "index": 0, "embedding": vec![0.25_f64; 5] } ],
            })
            .to_string(),
        )
    });
    let harness = Harness::new();
    let body = format!(
        "version = 1\n{}",
        embedding_profile("local-embed", &stub.origin(), &[])
    );
    let config = write_config(harness.dir(), "models.toml", &body);

    let output = harness.run(
        &[],
        &[
            "models",
            "check",
            "--profile",
            "local-embed",
            "--api-config",
            config.to_str().expect("path"),
            "--json",
        ],
    );
    assert_exit(&output, 0, "a response without identity is still valid");

    let payload = stdout_json(&output);
    assert_eq!(payload["response_model"], serde_json::Value::Null);
    assert_eq!(payload["response_revision"], serde_json::Value::Null);
    assert_eq!(
        payload["revision_source"], "operator_declared",
        "the declared revision must never be reported as observed"
    );
    assert_eq!(payload["declared_revision"], EMBED_REVISION);
    assert_eq!(payload["usage"], serde_json::Value::Null);
}

// ---------------------------------------------------------------------------
// M6: help and version stay available with no configuration at all
// ---------------------------------------------------------------------------

#[test]
fn help_and_version_need_no_configuration() {
    let harness = Harness::new();
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["models", "--help"],
        vec!["models", "check", "--help"],
        vec!["models", "list", "--help"],
    ] {
        let output = harness.run(&[], &args);
        assert!(
            output.status.success(),
            "{args:?} must succeed without a configuration; stderr: {}",
            stderr_text(&output)
        );
    }
}

#[test]
fn models_help_lists_both_new_subcommands() {
    let harness = Harness::new();
    let output = harness.run(&[], &["models", "--help"]);
    assert!(output.status.success(), "models --help");
    let text = format!("{}{}", stdout_text(&output), stderr_text(&output));
    assert!(
        text.contains("list"),
        "models --help must list `list`: {text}"
    );
    assert!(
        text.contains("check"),
        "models --help must list `check`: {text}"
    );
}
