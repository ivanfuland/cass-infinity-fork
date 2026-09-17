//! PR8 C8 (plan v4 Task C8, mission task_revision 2): the four T6B
//! ingest-side behaviours, end to end.
//!
//! 1. `semantic_index_implicit_ingest_is_loud` — `cass index --semantic`
//!    keeps ingesting by default (the default is *not* flipped), but now
//!    says so: `index --json.ingest_mode`, a fixed stderr warning, and an
//!    explicit `--ingest` / `--no-ingest` pair that cannot both be given.
//! 2. `open_readonly_lock_error_is_explicit` — a read-only open that cannot
//!    take the doctor mutation lock reports the fixed code
//!    `E-READONLY-LOCK-WRITE` instead of a bare io error.
//! 3. `per_session_scan_events` — one machine-readable `scan_session` line
//!    per session, carrying agent / external_id / bytes / outcome.
//! 4. `finalize_reports_progress` — a semantic run keeps posting
//!    `finalize_progress` through its drain-and-tail window, so an external
//!    `cass status --json` observer does not call a working run `stalled`.
//!
//! The semantic paths need an Infinity service. Rather than require one to
//! be installed, this file carries a canned HTTP stub (the same shape as
//! `src/search/infinity.rs`'s own unit-test mock, extended to answer one
//! vector per requested input, which `http_embed`'s index-permutation check
//! requires).

mod util;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use coding_agent_search::storage::sqlite::FrankenStorage;
use serial_test::serial;
use tempfile::TempDir;
use util::{EnvGuard, seed_codex_session};

/// `src/search/infinity.rs::DIMENSION` — the served dimension the probe
/// validates the advertised model against.
const EMBED_DIM: usize = 1024;
/// Kept in step with the fallback in `InfinityConfig::from_env`.
const EMBED_MODEL: &str = "BAAI/bge-m3";

/// The fixed stderr prefix a bare `cass index --semantic` must print.
const IMPLICIT_WARNING_PREFIX: &str =
    "warning: --semantic without --ingest/--no-ingest ingests by default";

// ---------------------------------------------------------------------------
// Canned Infinity stub
// ---------------------------------------------------------------------------

struct StubInfinity {
    base_url: String,
    wake_addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for StubInfinity {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(&self.wake_addr) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl StubInfinity {
    /// `per_request_delay` is how long each `POST /embeddings` takes to
    /// answer. The stall test uses it to hold a semantic run open long
    /// enough for a concurrent `cass status --json` observer to sample it.
    fn start(per_request_delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind infinity stub");
        listener
            .set_nonblocking(true)
            .expect("set infinity stub nonblocking");
        let addr = listener.local_addr().expect("stub address");
        let wake_addr = addr.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => handle_request(stream, per_request_delay),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            base_url: format!("http://{wake_addr}"),
            wake_addr,
            stop,
            handle: Some(handle),
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read one HTTP/1.1 request (headers + declared body) off `stream`.
fn read_http_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 65536 {
            return None;
        }
    };
    let header_str = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_str.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let content_length: usize = lines
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let body = buf[header_end..buf.len().min(header_end + content_length)].to_vec();
    Some((method, path, body))
}

fn handle_request(mut stream: TcpStream, per_request_delay: Duration) {
    let Some((method, path, body)) = read_http_request(&mut stream) else {
        return;
    };
    let response = if method == "GET" && path == "/models" {
        ok_json(&format!(
            r#"{{"data":[{{"id":"{EMBED_MODEL}","capabilities":["embed"]}}]}}"#
        ))
    } else if method == "POST" && path == "/embeddings" {
        if !per_request_delay.is_zero() {
            thread::sleep(per_request_delay);
        }
        let requested = serde_json::from_slice::<serde_json::Value>(&body).ok();
        let model = requested
            .as_ref()
            .and_then(|v| v.get("model"))
            .and_then(|m| m.as_str())
            .unwrap_or_default();
        if model != EMBED_MODEL {
            let msg = format!("infinity stub: unexpected model {model:?}");
            format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                msg.len(),
                msg
            )
        } else {
            // `http_embed` requires `data[].index` to be exactly a
            // permutation of 0..N-1, so answer one vector per requested
            // input. The vectors must be *distinct* per input text: the
            // activation audit's ownership check asks each chunk's own row
            // to be its own nearest neighbour, and a constant-offset family
            // (`i + 1 + position`) is almost collinear, so every chunk would
            // match every other chunk instead. Hashing the text keeps the
            // answer deterministic per input while separating the vectors.
            let inputs: Vec<String> = requested
                .as_ref()
                .and_then(|v| v.get("input"))
                .and_then(|i| i.as_array())
                .map(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().unwrap_or_default().to_string())
                        .collect()
                })
                .unwrap_or_else(|| vec![String::new()]);
            let data: Vec<serde_json::Value> = inputs
                .iter()
                .enumerate()
                .map(|(index, text)| {
                    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
                    for byte in text.as_bytes() {
                        hash ^= u64::from(*byte);
                        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
                    }
                    let vector: Vec<f32> = (0..EMBED_DIM)
                        .map(|i| {
                            let mixed =
                                hash ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                            (mixed % 997) as f32 / 997.0 - 0.5
                        })
                        .collect();
                    serde_json::json!({ "embedding": vector, "index": index })
                })
                .collect();
            ok_json(&serde_json::json!({ "data": data }).to_string())
        }
    } else {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    };
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn ok_json(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    tmp: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("cass-data")).expect("data dir");
        Self { tmp }
    }

    fn home(&self) -> PathBuf {
        self.tmp.path().join("home")
    }

    fn codex_home(&self) -> PathBuf {
        self.home().join(".codex")
    }

    fn data_dir(&self) -> PathBuf {
        self.tmp.path().join("cass-data")
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir().join("agent_search.db")
    }

    /// Isolate every connector root and config lookup into the tempdir.
    fn isolate(&self) -> Vec<EnvGuard> {
        vec![
            EnvGuard::set("HOME", self.home().to_str().unwrap()),
            EnvGuard::set("CODEX_HOME", self.codex_home().to_str().unwrap()),
            EnvGuard::set(
                "XDG_DATA_HOME",
                self.tmp.path().join("xdg-data").to_str().unwrap(),
            ),
            EnvGuard::set(
                "XDG_CONFIG_HOME",
                self.tmp.path().join("xdg-config").to_str().unwrap(),
            ),
            EnvGuard::set("CASS_IGNORE_SOURCES_CONFIG", "1"),
            EnvGuard::set("CASS_RESPONSIVENESS_DISABLE", "1"),
            EnvGuard::set("CASS_TANTIVY_REBUILD_WORKERS", "1"),
        ]
    }

    /// The connector only ingests files whose basename starts with `rollout-`.
    fn seed_session(&self, filename: &str, marker: &str) {
        seed_codex_session(&self.codex_home(), filename, marker, true);
    }
}

fn cli_command(fixture: &Fixture) -> Command {
    let mut cmd = Command::new(util::cass_bin());
    cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
    cmd.env("HOME", fixture.home());
    cmd.env("CODEX_HOME", fixture.codex_home());
    cmd.env("XDG_DATA_HOME", fixture.home().join(".local/share"));
    cmd.env("XDG_CONFIG_HOME", fixture.home().join(".config"));
    cmd.env("CASS_IGNORE_SOURCES_CONFIG", "1");
    cmd
}

/// Run `cass index` (plus `extra`) against the fixture, returning the child
/// output. Panics on a non-zero exit unless `expect_success` is false.
fn run_index(fixture: &Fixture, extra: &[&str], expect_success: bool) -> std::process::Output {
    let mut cmd = cli_command(fixture);
    cmd.args(["index", "--data-dir"]);
    cmd.arg(fixture.data_dir());
    cmd.args(extra);
    let output = cmd.output().expect("spawn cass index");
    if expect_success {
        assert!(
            output.status.success(),
            "`cass index {}` failed: stdout={} stderr={}",
            extra.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    output
}

fn db_scalar(db_path: &Path, sql: &str) -> i64 {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_row_map(sql, &[], |row| row.get_typed(0))
        .unwrap_or_else(|e| panic!("query {sql:?}: {e}"))
}

fn sessions_matching(db_path: &Path, needle: &str) -> i64 {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM conversations WHERE source_path LIKE ?1",
            &[coding_agent_search::storage::api::Value::from(
                format!("%{needle}%"),
            )],
            |row| row.get_typed(0),
        )
        .expect("count matching sessions")
}

fn json_of(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}); stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

// ---------------------------------------------------------------------------
// AC-1 — the implicit choice is loud, and the default is unchanged
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn semantic_index_implicit_ingest_is_loud() {
    let fixture = Fixture::new();
    let _env = fixture.isolate();
    let stub = StubInfinity::start(Duration::ZERO);
    fixture.seed_session("rollout-first.jsonl", "c8loudfirst");

    // A non-semantic run is neither implicit nor warned about.
    let plain = run_index(&fixture, &["--json"], true);
    let plain_payload = json_of(&plain);
    assert_eq!(
        plain_payload["ingest_mode"],
        serde_json::json!("explicit-ingest"),
        "a plain `cass index` ingests by construction, not by omission: {plain_payload}"
    );
    assert!(
        !stderr_of(&plain).contains(IMPLICIT_WARNING_PREFIX),
        "a non-semantic run must not warn: {}",
        stderr_of(&plain)
    );

    fixture.seed_session("rollout-second.jsonl", "c8loudsecond");

    // `--semantic` alone: still ingests, now says so.
    let mut implicit = cli_command(&fixture);
    implicit.env("CASS_INFINITY_URL", &stub.base_url);
    implicit.args(["index", "--data-dir"]);
    implicit.arg(fixture.data_dir());
    implicit.args(["--semantic", "--json"]);
    let implicit = implicit.output().expect("implicit semantic run");
    assert!(
        implicit.status.success(),
        "`cass index --semantic` against the stub must succeed: {}",
        stderr_of(&implicit)
    );
    let payload = json_of(&implicit);
    assert_eq!(
        payload["ingest_mode"],
        serde_json::json!("implicit"),
        "a bare --semantic run must disclose that it ingested by omission: {payload}"
    );
    assert_eq!(
        payload["no_ingest"],
        serde_json::json!(false),
        "the default still ingests; only the disclosure is new: {payload}"
    );
    assert!(
        payload["scan_invocations"].as_u64().unwrap_or(0) >= 1,
        "the implicit default must actually scan: {payload}"
    );
    let implicit_stderr = stderr_of(&implicit);
    assert!(
        implicit_stderr.contains(IMPLICIT_WARNING_PREFIX),
        "the implicit choice must print the fixed prefix, got stderr: {implicit_stderr:?}"
    );
    assert_eq!(
        sessions_matching(&fixture.db_path(), "rollout-second"),
        1,
        "the implicit default still ingests the live session"
    );

    // `--ingest`: explicit, and silent.
    let mut explicit = cli_command(&fixture);
    explicit.env("CASS_INFINITY_URL", &stub.base_url);
    explicit.args(["index", "--data-dir"]);
    explicit.arg(fixture.data_dir());
    explicit.args(["--semantic", "--ingest", "--json"]);
    let explicit = explicit.output().expect("explicit ingest run");
    assert!(explicit.status.success(), "{}", stderr_of(&explicit));
    let payload = json_of(&explicit);
    assert_eq!(payload["ingest_mode"], serde_json::json!("explicit-ingest"));
    assert_eq!(payload["no_ingest"], serde_json::json!(false));
    assert!(
        !stderr_of(&explicit).contains(IMPLICIT_WARNING_PREFIX),
        "an explicit choice must not warn: {}",
        stderr_of(&explicit)
    );

    // `--no-ingest`: explicit, silent, and the scan really does not run.
    fixture.seed_session("rollout-third.jsonl", "c8loudthird");
    let mut read_only = cli_command(&fixture);
    read_only.env("CASS_INFINITY_URL", &stub.base_url);
    read_only.args(["index", "--data-dir"]);
    read_only.arg(fixture.data_dir());
    read_only.args(["--semantic", "--no-ingest", "--json"]);
    let read_only = read_only.output().expect("explicit no-ingest run");
    assert!(read_only.status.success(), "{}", stderr_of(&read_only));
    let payload = json_of(&read_only);
    assert_eq!(payload["ingest_mode"], serde_json::json!("explicit-no-ingest"));
    assert_eq!(payload["scan_invocations"], serde_json::json!(0));
    assert!(
        !stderr_of(&read_only).contains(IMPLICIT_WARNING_PREFIX),
        "an explicit choice must not warn: {}",
        stderr_of(&read_only)
    );
    assert_eq!(
        sessions_matching(&fixture.db_path(), "rollout-third"),
        0,
        "--no-ingest must still leave the corpus alone"
    );

    // Both flags: opposite instructions, so a parameter error (exit 2).
    let both = run_index(&fixture, &["--semantic", "--ingest", "--no-ingest"], false);
    assert_eq!(
        both.status.code(),
        Some(2),
        "--ingest and --no-ingest are mutually exclusive: stdout={} stderr={}",
        String::from_utf8_lossy(&both.stdout),
        stderr_of(&both)
    );
    assert!(
        stderr_of(&both).contains("--ingest cannot be combined with --no-ingest"),
        "the mutual exclusion must name both flags: {}",
        stderr_of(&both)
    );
}

// ---------------------------------------------------------------------------
// AC-2 — read-only open that needs a writable lock says so, by code
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn open_readonly_lock_error_is_explicit() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let _env = fixture.isolate();
    fixture.seed_session("rollout-lock.jsonl", "c8lock");
    run_index(&fixture, &[], true);

    let db_path = fixture.db_path();
    assert!(db_path.exists(), "fixture corpus must exist");

    // Sanity: on a writable directory the same call succeeds.
    drop(FrankenStorage::open_readonly(&db_path).expect("writable dir must open read-only"));

    // `open_readonly` takes `<db_dir>/doctor/locks/doctor-repair.lock` with a
    // create+write open before it touches the database, so a read-only
    // directory is enough to fail it.
    // The failing step is "create and open the lock for writing". Removing
    // the lock tree first is what makes that step need the directory itself
    // to be writable -- with the lock already present and writable, the open
    // succeeds and the guard is taken normally, which is not the case under
    // test.
    let lock_tree = fixture.data_dir().join("doctor");
    if lock_tree.exists() {
        std::fs::remove_dir_all(&lock_tree).expect("clear doctor lock tree");
    }
    let dir = fixture.data_dir();
    let original_mode = std::fs::metadata(&dir)
        .expect("stat data dir")
        .permissions()
        .mode();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555))
        .expect("chmod data dir read-only");
    let result = FrankenStorage::open_readonly(&db_path);
    // Restore before asserting, so a failure cannot leave an undeletable tmpdir.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(original_mode))
        .expect("restore data dir mode");

    // `FrankenStorage` has no `Debug`, so `expect_err` is not available.
    let err = match result {
        Ok(_) => panic!("a read-only open must not silently succeed when its lock cannot be taken"),
        Err(err) => err,
    };
    let text = format!("{err:#}");
    assert!(
        text.contains("E-READONLY-LOCK-WRITE"),
        "the error must carry the fixed code E-READONLY-LOCK-WRITE, got: {text}"
    );
    assert!(
        text.contains("doctor-repair.lock"),
        "the error must name the lock it could not take, got: {text}"
    );
}

// ---------------------------------------------------------------------------
// AC-3 — one machine-readable line per scanned session
// ---------------------------------------------------------------------------

/// Pull `field="value"` / `field=123` out of a compact tracing line.
fn trace_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let end = rest.find(' ').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

fn scan_session_lines(trace: &Path) -> Vec<String> {
    std::fs::read_to_string(trace)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains("cass::scan_session"))
        .map(str::to_string)
        .collect()
}

#[test]
#[serial]
fn per_session_scan_events() {
    let fixture = Fixture::new();
    let mut env = fixture.isolate();
    let trace = fixture.tmp.path().join("trace.log");
    env.push(EnvGuard::set("CASS_TRACE_FILE", trace.to_str().unwrap()));

    fixture.seed_session("rollout-a.jsonl", "c8scana");
    fixture.seed_session("rollout-b.jsonl", "c8scanb");
    fixture.seed_session("rollout-c.jsonl", "c8scanc");

    run_index(&fixture, &["--full"], true);

    let lines = scan_session_lines(&trace);
    assert_eq!(
        lines.len(),
        3,
        "three seeded sessions must produce three scan_session lines, got:\n{}",
        lines.join("\n")
    );
    for line in &lines {
        assert_eq!(
            trace_field(line, "agent").as_deref(),
            Some("codex"),
            "agent field: {line}"
        );
        let external_id = trace_field(line, "external_id").expect("external_id field");
        assert!(
            external_id.contains("rollout-"),
            "external_id must name the session file: {line}"
        );
        let bytes: u64 = trace_field(line, "bytes")
            .expect("bytes field")
            .parse()
            .expect("bytes is a number");
        assert!(bytes > 0, "bytes must be the source file size: {line}");
        assert_eq!(
            trace_field(line, "outcome").as_deref(),
            Some("inserted"),
            "a first ingest inserts: {line}"
        );
    }

    // Re-ingesting the same three sessions must report them as already seen.
    std::fs::remove_file(&trace).expect("clear trace log");
    run_index(&fixture, &["--full"], true);
    let repeat = scan_session_lines(&trace);
    assert_eq!(
        repeat.len(),
        3,
        "the re-scan must also report three sessions, got:\n{}",
        repeat.join("\n")
    );
    for line in &repeat {
        let outcome = trace_field(line, "outcome").expect("outcome field");
        assert!(
            outcome == "skipped_duplicate" || outcome == "merged",
            "a re-scan reports a duplicate or a merge, never {outcome}: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// AC-4 — the drain-and-tail window is visible as progress
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn finalize_reports_progress() {
    let fixture = Fixture::new();
    let mut env = fixture.isolate();
    let fast_stub = StubInfinity::start(Duration::ZERO);
    fixture.seed_session("rollout-fin-a.jsonl", "c8finalizea");
    fixture.seed_session("rollout-fin-b.jsonl", "c8finalizeb");
    fixture.seed_session("rollout-fin-c.jsonl", "c8finalizec");
    run_index(&fixture, &["--full"], true);

    // A fresh corpus has no embedding generation, so the first ingest has
    // nothing to register holes against. One fast semantic pass establishes
    // the generation and activates it; the sessions seeded afterwards then
    // leave real drain work for the run under test.
    let mut establish = cli_command(&fixture);
    establish.env("CASS_INFINITY_URL", &fast_stub.base_url);
    establish.args(["index", "--data-dir"]);
    establish.arg(fixture.data_dir());
    establish.args(["--semantic", "--no-ingest", "--json"]);
    let establish = establish.output().expect("generation-establishing run");
    assert!(
        establish.status.success(),
        "establishing the embedding generation must succeed: {}",
        stderr_of(&establish)
    );

    fixture.seed_session("rollout-fin-d.jsonl", "c8finalized");
    fixture.seed_session("rollout-fin-e.jsonl", "c8finalizee");
    fixture.seed_session("rollout-fin-f.jsonl", "c8finalizef");
    run_index(&fixture, &["--full"], true);

    let holes = db_scalar(&fixture.db_path(), "SELECT COUNT(*) FROM chunk_holes");
    assert!(
        holes >= 1,
        "the fixture must leave hole-draining work for the semantic run, found {holes} holes"
    );

    let jsonl = fixture.tmp.path().join("semantic-progress.jsonl");
    env.push(EnvGuard::set(
        "CASS_SEMANTIC_PROGRESS_JSONL",
        jsonl.to_str().unwrap(),
    ));
    // Production cadence is 60 s and the stall threshold 120 s; the test
    // shortens both through their documented overrides so a short run still
    // crosses several periods of both.
    env.push(EnvGuard::set("CASS_SEMANTIC_FINALIZE_PROGRESS_EVERY_MS", "50"));
    env.push(EnvGuard::set("CASS_REBUILD_STALL_DETECT_SECS", "1"));
    env.push(EnvGuard::set("CASS_INDEX_RUN_LOCK_HEARTBEAT_EVERY_MS", "50"));

    let stub = StubInfinity::start(Duration::from_millis(2_000));

    let mut run = cli_command(&fixture);
    run.env("CASS_INFINITY_URL", &stub.base_url);
    run.args(["index", "--data-dir"]);
    run.arg(fixture.data_dir());
    run.args(["--semantic", "--no-ingest", "--json"]);
    run.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = run.spawn().expect("spawn semantic run");

    // Sample `cass status --json` while the run holds the index-run lock.
    let mut samples: Vec<(bool, bool)> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let mut status = cli_command(&fixture);
        status.arg("status");
        status.arg("--data-dir");
        status.arg(fixture.data_dir());
        status.arg("--json");
        if let Ok(output) = status.output()
            && let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        {
            let rebuild = &payload["rebuild"];
            samples.push((
                rebuild["active"].as_bool().unwrap_or(false),
                rebuild["stalled"].as_bool().unwrap_or(false),
            ));
        }
        let exited = matches!(
            child.try_wait(),
            Ok(Some(_))
        );
        if exited || std::time::Instant::now() > deadline {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let output = child
        .wait_with_output()
        .expect("collect semantic run output");
    assert!(
        output.status.success(),
        "the semantic run must succeed against the stub: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let observed_active: Vec<(bool, bool)> = samples
        .iter()
        .copied()
        .filter(|(active, _)| *active)
        .collect();
    assert!(
        !observed_active.is_empty(),
        "the observer never saw the index-run lock held, so it proved nothing: {samples:?}"
    );
    let stalled_while_active: Vec<bool> = observed_active
        .iter()
        .filter(|(_, stalled)| *stalled)
        .map(|(_, stalled)| *stalled)
        .collect();
    assert!(
        stalled_while_active.is_empty(),
        "a run that is posting finalize progress must never read as stalled \
         ({} of {} active samples said stalled)",
        stalled_while_active.len(),
        observed_active.len()
    );

    let events: Vec<serde_json::Value> = std::fs::read_to_string(&jsonl)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("event is JSON"))
        .filter(|event: &serde_json::Value| event["event"] == "finalize_progress")
        .collect();
    assert!(
        events.len() >= 3,
        "a working run must post at least three finalize_progress ticks, got {}",
        events.len()
    );
    for event in &events {
        assert_eq!(event["phase"], serde_json::json!("finalize"));
        assert!(event["elapsed_ms"].is_u64(), "elapsed_ms: {event}");
        assert!(event["elapsed_secs"].is_u64(), "elapsed_secs: {event}");
        let stage = event["stage"].as_str().unwrap_or_default();
        assert!(
            stage == "semantic_drain" || stage == "finalize",
            "each tick names the stage it covers: {event}"
        );
    }
    assert!(
        events
            .iter()
            .any(|event| event["stage"] == serde_json::json!("finalize")),
        "the post-drain tail must be covered by its own stage, not only the drain"
    );
}
