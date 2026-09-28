//! PR10 task 06 — the remote mirror stage of `cass sync`, end to end.
//!
//! Every observation here comes from the real `cass` binary run against an
//! isolated HOME / XDG / `--data-dir`, a canned Infinity stub, and a private
//! `PATH` containing stand-in `ssh` and `rsync` executables. No test connects
//! to a remote host, and none reads a session from a real mirror: the
//! "remote" side is decided entirely by the host token in the source's
//! `sources.toml`, so one pair of scripts covers a transfer that moves files,
//! one that moves none, one that reports success without materialising
//! anything, and one that fails.
//!
//! What is pinned:
//!
//! 1. `remote_sources_mirror_then_index_once` — a reachable source lands in
//!    the *given* data dir, an unreachable one is reported per path, and the
//!    one local index still runs and still ingests the new HOME session.
//!    Exit 3, `complete = false`, `partial_reasons = [mirror_failed]`.
//! 2. `zero_transfer_and_no_sources_still_ingest` — a source that transfers
//!    zero files and a config with no sources at all both reach the local
//!    index. A mirror result that did not transfer everything can never be
//!    reported as `success`; a partial source is not `success` either.
//! 3. `a_successful_transfer_without_its_root_is_exit_1` — the transport says
//!    success and the index side cannot find the directory it derived. The
//!    local half still runs (the HOME session is ingested) and the round is
//!    forced to exit 1 with `error.kind = index`.
//! 4. `a_held_index_lock_is_exit_2` — a contended `index-run.lock` is exit 2
//!    with `error.kind = index-busy`, and the mirror stage still ran, so no
//!    lock was taken around the transfer (hard constraint 13).
//! 5. `the_run_log_matches_stdout_byte_for_byte` — one line per round,
//!    `0700`/`0600` on Unix, and a log that cannot be written is a warning on
//!    stderr that leaves stdout and the exit code alone.
//! 6. `the_round_decision_table_keeps_both_partial_reasons` — the classification
//!    arms the CLI fixtures cannot reach, including the two partial reasons at
//!    once. The `semantic_activated = false` arm is *not* reachable through
//!    the binary (the drain's post-loop invariant bails a run that leaves a
//!    hole), so it is pinned at the function level rather than claimed as an
//!    end-to-end result.
//!
//! The shell fixtures are `#[cfg(unix)]`; a non-Unix build still compiles this
//! file and still runs the table case in (6). The rest of the file — the
//! fixture struct, the stand-in transports and the JSON helpers — is then
//! genuinely unused there rather than merely unreferenced, so the dead-code
//! and unused-import warnings are allowed away for exactly that configuration
//! and for no other.

#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

mod util;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use coding_agent_search::sync::{
    EXIT_INTERNAL, EXIT_PARTIAL, EXIT_PRECONDITION, EXIT_READY, IndexOutcome, REASON_MIRROR_FAILED,
    REASON_SEMANTIC_NOT_READY, classify_round_outcome,
};
use tempfile::TempDir;
use util::seed_codex_session;

/// `src/search/infinity.rs::DIMENSION` — the served dimension the probe
/// validates the advertised model against.
const EMBED_DIM: usize = 1024;
/// Kept in step with the fallback in `InfinityConfig::from_env`.
const EMBED_MODEL: &str = "BAAI/bge-m3";

const SCHEMA: &str = "cass.sync.v1";

/// The in-tree claude_code fixture (1 conversation / 2 messages) the
/// stand-in `rsync` publishes. It is copied into the mirror root's
/// `projects/<dir>/agent-*.jsonl` shape, which is the shape the claude_code
/// connector discovers — the same one `tests/w10_mirror_state.rs` uses.
const CLAUDE_FIXTURE: &str = "claude_code_real/projects/-test-project/agent-test123.jsonl";

/// Where the stand-in `ssh` says the "remote" home is.
const REMOTE_HOME: &str = "/home/cass-fixture";

/// The remote path the reachable fixture source mirrors.
const REMOTE_PATH: &str = "~/.claude/projects";

/// The source whose transfer moves a session.
const GOOD_SOURCE: &str = "cass-good";
/// The source whose `rsync` exits non-zero.
const BAD_SOURCE: &str = "cass-bad";
/// The source whose `rsync` succeeds and moves nothing.
const ZERO_SOURCE: &str = "cass-zero";
/// The source whose `rsync` succeeds but leaves no destination directory.
const DROP_SOURCE: &str = "cass-drop";
/// The source whose second configured path fails and whose first succeeds.
const PARTIAL_SOURCE: &str = "cass-partial";

// ---------------------------------------------------------------------------
// Canned Infinity stub (same wire shape as tests/w10_sync_local.rs)
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
    fn start() -> Self {
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
                    Ok((stream, _)) => handle_request(stream),
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

fn ok_json(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn handle_request(mut stream: TcpStream) {
    let Some((method, path, body)) = read_http_request(&mut stream) else {
        return;
    };
    let response = if method == "GET" && path == "/models" {
        ok_json(&format!(
            r#"{{"data":[{{"id":"{EMBED_MODEL}","capabilities":["embed"]}}]}}"#
        ))
    } else if method == "POST" && path == "/embeddings" {
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
            // `http_embed` requires `data[].index` to permute 0..N-1, and the
            // activation audit asks each chunk's row to be its own nearest
            // neighbour, so the vectors must be distinct per input text.
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
                            let mixed = hash ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
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

/// A port nobody is listening on: bind, read the address, drop the listener.
fn closed_port_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("ephemeral address");
    drop(listener);
    format!("http://{addr}")
}

// ---------------------------------------------------------------------------
// Stand-in `ssh` / `rsync`
// ---------------------------------------------------------------------------

/// The stand-in `ssh`, on the isolated `PATH` in front of the real one.
///
/// `SyncEngine` reaches the remote in exactly two places before a transfer:
/// it asks for `$HOME` (to expand a `~` path) and it asks whether the remote
/// `rsync` is Apple's openrsync. Both are the last argument of the command, so
/// this answers on that. Anything else is a hard failure rather than a silent
/// empty answer — a probe the fixture does not know about must not look like a
/// healthy host.
const FAKE_SSH: &str = r#"#!/bin/sh
last=""
for arg in "$@"; do last="$arg"; done
case "$last" in
  *CASS_HOME_MARKER*) printf 'CASS_HOME_MARKER:%s\n' "$CASS_FIXTURE_REMOTE_HOME"; exit 0 ;;
  *"rsync --version"*) printf 'rsync  version 3.2.7  protocol 31\n'; exit 0 ;;
  *) printf 'fake ssh: unsupported remote command: %s\n' "$last" >&2; exit 1 ;;
esac
"#;

/// The stand-in `rsync`, on the isolated `PATH` in front of the real one.
///
/// It answers the transport's two probes (`--version`, `--help`) and then
/// reads the transfer as `rsync <flags> -e <ssh> -- <host>:<path> <dest>`: the
/// last two arguments are the remote spec and the destination whatever the
/// flags before them are. The host token in the remote spec selects the
/// behaviour, so one script is every fixture this file needs.
const FAKE_RSYNC: &str = r#"#!/bin/sh
case "$1" in
  --version) printf 'rsync  version 3.2.7  protocol 31\n'; exit 0 ;;
  --help)
    printf 'rsync  version 3.2.7  protocol 31\n'
    printf 'Usage: rsync [OPTION]... SRC [SRC]... DEST\n'
    exit 0
    ;;
esac

previous=""
last=""
for arg in "$@"; do
  previous="$last"
  last="$arg"
done

case "$previous" in
  *cass-bad@*)
    printf 'rsync: connection unexpectedly closed (0 bytes received so far)\n' >&2
    exit 23
    ;;
  *cass-zero@*)
    printf 'Number of regular files transferred: 0\n'
    exit 0
    ;;
  *cass-drop@*)
    # Reports success and leaves no destination behind: the transport is
    # lying about what it materialised.
    rmdir "$last" 2>/dev/null
    printf 'Number of regular files transferred: 0\n'
    exit 0
    ;;
  *cass-partial@*sessions)
    printf 'rsync: [sender] link_stat "%s" failed: No such file or directory (2)\n' "$previous" >&2
    exit 23
    ;;
esac

mkdir -p "$last/projects/-pr10"
cp "$CASS_FIXTURE_CLAUDE_SESSION" "$last/projects/-pr10/agent-remote.jsonl"
printf 'Number of regular files transferred: 1\n'
printf 'Total transferred file size: %s bytes\n' "$(wc -c < "$CASS_FIXTURE_CLAUDE_SESSION" | tr -d ' ')"
exit 0
"#;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    tmp: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("cass-data")).expect("create data dir");
        let fixture = Self { tmp };
        fixture.install_fake_transport();
        fixture
    }

    /// Write the two stand-in executables into a private directory that goes
    /// in front of the real `PATH` for this fixture's children only. Nothing
    /// process-global is touched, so `cargo test`'s default parallelism is
    /// safe: each test owns its own directory and its own `Command`.
    fn install_fake_transport(&self) {
        let bin = self.tmp.path().join("fake-bin");
        std::fs::create_dir_all(&bin).expect("create fake bin dir");
        for (name, body) in [("ssh", FAKE_SSH), ("rsync", FAKE_RSYNC)] {
            let path = bin.join(name);
            std::fs::write(&path, body).expect("write fake transport");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                    .expect("make the fake transport executable");
            }
        }
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

    /// The data dir `cass` would use with no `--data-dir`: the round must
    /// never touch it when an explicit one is given (spec acceptance 3).
    fn default_data_dir(&self) -> PathBuf {
        self.home().join(".local/share/coding-agent-search")
    }

    fn run_log(&self) -> PathBuf {
        self.data_dir().join("logs").join("sync-runs.jsonl")
    }

    fn sources_config_path(&self) -> PathBuf {
        self.tmp
            .path()
            .join("xdg-config")
            .join("cass")
            .join("sources.toml")
    }

    fn write_sources_config(&self, body: &str) {
        let path = self.sources_config_path();
        std::fs::create_dir_all(path.parent().expect("config parent")).expect("create config dir");
        std::fs::write(&path, body).expect("write sources.toml");
    }

    /// The connector only ingests files whose basename starts with `rollout-`.
    fn seed_session(&self, filename: &str, marker: &str) {
        seed_codex_session(&self.codex_home(), filename, marker, true);
    }

    /// Every env var the child needs, including the private `PATH` and the two
    /// paths the stand-in `rsync` needs to publish the real in-tree fixture.
    fn command(&self) -> Command {
        let mut cmd = Command::new(util::cass_bin());
        let existing = std::env::var_os("PATH").unwrap_or_default();
        let mut path = std::ffi::OsString::from(self.tmp.path().join("fake-bin"));
        path.push(":");
        path.push(existing);
        cmd.env("PATH", path);
        cmd.env("CASS_FIXTURE_CLAUDE_SESSION", self.claude_fixture_path());
        cmd.env("CASS_FIXTURE_REMOTE_HOME", REMOTE_HOME);
        cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
        cmd.env("HOME", self.home());
        cmd.env("CODEX_HOME", self.codex_home());
        cmd.env("XDG_DATA_HOME", self.home().join(".local/share"));
        cmd.env("XDG_CONFIG_HOME", self.tmp.path().join("xdg-config"));
        cmd.env("CASS_RESPONSIVENESS_DISABLE", "1");
        cmd.env("CASS_TANTIVY_REBUILD_WORKERS", "1");
        cmd.env("NO_COLOR", "1");
        // Never inherit an operator/CI opt-out: several other suites set it,
        // and this suite's whole point is that the config IS consulted.
        cmd.env_remove("CASS_IGNORE_SOURCES_CONFIG");
        cmd.env_remove("CASS_DATA_DIR");
        cmd.env_remove("CASS_OUTPUT_FORMAT");
        cmd.env_remove("TOON_DEFAULT_FORMAT");
        cmd.env_remove("RUST_LOG");
        cmd
    }

    fn claude_fixture_path(&self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(CLAUDE_FIXTURE)
    }

    /// One `cass sync --json` round against the fixture.
    fn sync_json(&self, infinity_url: &str, extra: &[&str]) -> Output {
        let mut cmd = self.command();
        cmd.env("CASS_INFINITY_URL", infinity_url);
        cmd.args(["sync", "--json", "--data-dir"]);
        cmd.arg(self.data_dir());
        cmd.args(extra);
        cmd.output().expect("spawn cass sync")
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Parse stdout as exactly one JSON object. `serde_json::from_slice` only
/// accepts a single trailing document, so a second object or any prose on
/// stdout fails here rather than being silently ignored.
fn json_of(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not exactly one JSON object ({e}); stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            stderr_of(output)
        )
    })
}

/// Parse the report and cross-check it against the process status.
fn report_of(output: &Output) -> serde_json::Value {
    let payload = json_of(output);
    assert_eq!(payload["schema"], serde_json::json!(SCHEMA));
    let reported = payload["exit_code"]
        .as_i64()
        .unwrap_or_else(|| panic!("report must carry an integer exit_code: {payload}"));
    assert_eq!(
        Some(reported),
        output.status.code().map(i64::from),
        "the report's exit_code must equal the process exit status: {payload}"
    );
    assert_eq!(
        payload["complete"],
        serde_json::json!(reported == 0),
        "complete must be true exactly when exit_code is 0: {payload}"
    );
    payload
}

/// The mirror-stage entry for `name`.
fn mirror_source<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report["mirror"]["sources"]
        .as_array()
        .unwrap_or_else(|| panic!("mirror.sources must be an array: {report}"))
        .iter()
        .find(|source| source["name"] == serde_json::json!(name))
        .unwrap_or_else(|| panic!("no mirror.sources entry named {name:?}: {report}"))
}

fn db_scalar(db_path: &Path, sql: &str) -> i64 {
    use coding_agent_search::storage::sqlite::FrankenStorage;
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_row_map(sql, &[], |row| row.get_typed(0))
        .unwrap_or_else(|e| panic!("query {sql:?}: {e}"))
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

// ---------------------------------------------------------------------------
// M1 — multi-source, one entry point, one local index
// ---------------------------------------------------------------------------

const TWO_SOURCES: &str = r#"
[[sources]]
name = "cass-good"
type = "ssh"
host = "cass-good@fixture.invalid"
origin_host = "cass-good"
paths = ["~/.claude/projects"]

[[sources]]
name = "cass-bad"
type = "ssh"
host = "cass-bad@fixture.invalid"
origin_host = "cass-bad"
paths = ["~/.claude/projects"]
"#;

#[cfg(unix)]
#[test]
fn remote_sources_mirror_then_index_once() {
    let fixture = Fixture::new();
    let stub = StubInfinity::start();
    fixture.seed_session("rollout-home.jsonl", "w10-remote-home");
    fixture.write_sources_config(TWO_SOURCES);

    let output = fixture.sync_json(&stub.base_url, &[]);
    let report = report_of(&output);

    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_PARTIAL),
        "one failed mirror source makes the round partial: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(
        report["partial_reasons"],
        serde_json::json!([REASON_MIRROR_FAILED]),
        "the partial reason must name the mirror: {report}"
    );
    assert_eq!(
        report["mirror"]["attempted"],
        serde_json::json!(true),
        "two configured remote sources means the stage really ran: {report}"
    );
    assert!(
        report["mirror"]["skip_reason"].is_null(),
        "the stage ran, so nothing skipped it: {report}"
    );

    // --- the reachable source -------------------------------------------
    let good = mirror_source(&report, GOOD_SOURCE);
    assert_eq!(
        good["status"],
        serde_json::json!("success"),
        "a fully transferred source is the only thing that may read as success: {good}"
    );
    assert!(
        good["error"].is_null(),
        "a successful source carries no error: {good}"
    );
    let mirrored = PathBuf::from(
        good["paths"][0]["path"]
            .as_str()
            .unwrap_or_else(|| panic!("the source must report its mirror path: {good}")),
    );
    assert!(
        mirrored.starts_with(fixture.data_dir().join("remotes").join(GOOD_SOURCE)),
        "the transfer must land under the data dir it was given: {mirrored:?}"
    );
    assert_eq!(
        good["paths"][0]["files_transferred"],
        serde_json::json!(1),
        "the stand-in transport moved exactly one file: {good}"
    );
    assert!(
        mirrored.join("projects/-pr10/agent-remote.jsonl").is_file(),
        "the published session must exist where the report says it is: {mirrored:?}"
    );

    // --- the unreachable source ------------------------------------------
    let bad = mirror_source(&report, BAD_SOURCE);
    assert_ne!(
        bad["status"],
        serde_json::json!("success"),
        "a source whose transfer failed must never read as success: {bad}"
    );
    assert_eq!(
        bad["status"],
        serde_json::json!("failed"),
        "no path transferred, so the source failed: {bad}"
    );
    let bad_paths = bad["paths"]
        .as_array()
        .unwrap_or_else(|| panic!("a failed source still names its configured paths: {bad}"));
    assert!(
        !bad_paths.is_empty(),
        "the configured path must be reported, not an empty array: {bad}"
    );
    assert!(
        bad_paths
            .iter()
            .all(|path| path["success"] == serde_json::json!(false)),
        "every path of a failed source must say so: {bad}"
    );
    assert!(
        bad_paths
            .iter()
            .all(|path| path["error"].is_string() && path["remote_path"].is_string()),
        "each failed path must carry its remote path and its reason: {bad}"
    );

    // --- the local half ---------------------------------------------------
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(true),
        "a failed mirror half must not skip the local index: {report}"
    );
    assert_eq!(
        report["semantic_activated"],
        serde_json::json!(true),
        "the local half still reached semantic activation: {report}"
    );
    let conversations = db_scalar(&fixture.db_path(), "SELECT COUNT(*) FROM conversations");
    assert_eq!(
        conversations, 2,
        "one index run must have ingested the new HOME session AND the mirrored one"
    );
    assert!(
        db_scalar(&fixture.db_path(), "SELECT COUNT(*) FROM messages") > 0,
        "the ingested sessions must carry messages"
    );
    assert!(
        !fixture.default_data_dir().exists(),
        "the round must not fall back to the default data dir: {:?}",
        fixture.default_data_dir()
    );
}

// ---------------------------------------------------------------------------
// M2 — zero transfer, no sources, and a lying "Ok"
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn zero_transfer_and_no_sources_still_ingest() {
    let stub = StubInfinity::start();

    // --- a configured source that transfers nothing ----------------------
    {
        let fixture = Fixture::new();
        fixture.seed_session("rollout-zero.jsonl", "w10-zero");
        fixture.write_sources_config(&format!(
            r#"
[[sources]]
name = "{ZERO_SOURCE}"
type = "ssh"
host = "{ZERO_SOURCE}@fixture.invalid"
origin_host = "{ZERO_SOURCE}"
paths = ["{REMOTE_PATH}"]
"#
        ));

        let output = fixture.sync_json(&stub.base_url, &[]);
        let report = report_of(&output);
        assert_eq!(
            report["exit_code"],
            serde_json::json!(EXIT_READY),
            "a zero-file transfer is a successful transfer: {report} stderr={}",
            stderr_of(&output)
        );
        assert_eq!(
            report["mirror"]["attempted"],
            serde_json::json!(true),
            "the attempt is reported, not the file count: {report}"
        );
        let zero = mirror_source(&report, ZERO_SOURCE);
        assert_eq!(
            zero["status"],
            serde_json::json!("success"),
            "nothing to transfer is not a failure: {zero}"
        );
        assert_eq!(
            zero["paths"][0]["files_transferred"],
            serde_json::json!(0),
            "the transport moved nothing: {zero}"
        );
        assert_eq!(
            db_scalar(&fixture.db_path(), "SELECT COUNT(*) FROM conversations"),
            1,
            "zero transferred files must not skip the local ingest"
        );
    }

    // --- a config with no sources at all ---------------------------------
    {
        let fixture = Fixture::new();
        fixture.seed_session("rollout-none.jsonl", "w10-none");

        let output = fixture.sync_json(&stub.base_url, &[]);
        let report = report_of(&output);
        assert_eq!(
            report["exit_code"],
            serde_json::json!(EXIT_READY),
            "a source-less round is complete: {report} stderr={}",
            stderr_of(&output)
        );
        assert_eq!(
            report["mirror"]["sources"],
            serde_json::json!([]),
            "no configured source means an empty mirror array: {report}"
        );
        assert_eq!(
            report["mirror"]["attempted"],
            serde_json::json!(false),
            "nothing was attempted, so nothing may be claimed as attempted: {report}"
        );
        assert_eq!(
            db_scalar(&fixture.db_path(), "SELECT COUNT(*) FROM conversations"),
            1,
            "a source-less round must still ingest the local session"
        );
    }

    // --- a source with one good and one failing path ---------------------
    {
        let fixture = Fixture::new();
        fixture.seed_session("rollout-partial.jsonl", "w10-partial");
        fixture.write_sources_config(&format!(
            r#"
[[sources]]
name = "{PARTIAL_SOURCE}"
type = "ssh"
host = "{PARTIAL_SOURCE}@fixture.invalid"
origin_host = "{PARTIAL_SOURCE}"
paths = ["{REMOTE_PATH}", "~/.codex/sessions"]
"#
        ));

        let output = fixture.sync_json(&stub.base_url, &[]);
        let report = report_of(&output);
        assert_eq!(
            report["exit_code"],
            serde_json::json!(EXIT_PARTIAL),
            "a partly transferred source is not a complete round: {report} stderr={}",
            stderr_of(&output)
        );
        let partial = mirror_source(&report, PARTIAL_SOURCE);
        assert_eq!(
            partial["status"],
            serde_json::json!("partial"),
            "one good path and one bad path is `partial`: {partial}"
        );
        assert_ne!(
            partial["status"],
            serde_json::json!("success"),
            "`Ok(SyncReport)` with a failed path must never be mapped to success: {partial}"
        );
        assert!(
            partial["paths"]
                .as_array()
                .is_some_and(|paths| paths.len() == 2),
            "both configured paths must be reported: {partial}"
        );
        assert_eq!(
            report["partial_reasons"],
            serde_json::json!([REASON_MIRROR_FAILED]),
            "the partial source must surface as the mirror reason: {report}"
        );
        assert_eq!(
            db_scalar(&fixture.db_path(), "SELECT COUNT(*) FROM conversations"),
            2,
            "the local half still runs, and the one path that did transfer is still \
             indexed: {report}"
        );
    }
}

// ---------------------------------------------------------------------------
// M2 — a transfer that claims success without materialising its root
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_successful_transfer_without_its_root_is_exit_1() {
    let fixture = Fixture::new();
    let stub = StubInfinity::start();
    fixture.seed_session("rollout-drop.jsonl", "w10-drop");
    fixture.write_sources_config(&format!(
        r#"
[[sources]]
name = "{DROP_SOURCE}"
type = "ssh"
host = "{DROP_SOURCE}@fixture.invalid"
origin_host = "{DROP_SOURCE}"
paths = ["{REMOTE_PATH}"]
"#
    ));

    let output = fixture.sync_json(&stub.base_url, &[]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_INTERNAL),
        "a transfer that reported success without leaving its root is an internal \
         failure, not a complete round: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(
        report["error"]["kind"],
        serde_json::json!("index"),
        "the inconsistency must be named as the internal index-side failure: {report}"
    );
    assert_eq!(
        report["complete"],
        serde_json::json!(false),
        "an internally inconsistent round is never complete: {report}"
    );
    // The local half is innocent and its result is what the operator needs, so
    // the round must still have indexed -- not silently scanned HOME and
    // called that a success.
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(true),
        "the local index must still run: {report}"
    );
    assert_eq!(
        db_scalar(&fixture.db_path(), "SELECT COUNT(*) FROM conversations"),
        1,
        "the HOME session must still be ingested: {report}"
    );
}

// ---------------------------------------------------------------------------
// M3 — the lock is a typed precondition, and it never wraps the mirror
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_held_index_lock_is_exit_2() {
    use fs2::FileExt;

    let fixture = Fixture::new();
    let stub = StubInfinity::start();
    fixture.seed_session("rollout-lock.jsonl", "w10-lock");
    fixture.write_sources_config(&format!(
        r#"
[[sources]]
name = "{GOOD_SOURCE}"
type = "ssh"
host = "{GOOD_SOURCE}@fixture.invalid"
origin_host = "{GOOD_SOURCE}"
paths = ["{REMOTE_PATH}"]
"#
    ));

    // A real exclusive lock on the real path, taken by another process (this
    // one) before the round starts. Nothing is guessed from timing: the lock
    // is held for as long as the child could possibly want it.
    std::fs::create_dir_all(fixture.data_dir()).expect("create data dir");
    let lock_path = fixture.data_dir().join("index-run.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("open the index-run lock");
    lock.try_lock_exclusive()
        .expect("the lock must be free before the round starts");

    let output = fixture.sync_json(&stub.base_url, &[]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_PRECONDITION),
        "a contended index lock is a precondition failure: {report} stderr={}",
        stderr_of(&output)
    );
    assert_eq!(
        report["error"]["kind"],
        serde_json::json!("index-busy"),
        "the busy lock must be identified by type, not by its message text: {report}"
    );
    assert_eq!(
        report["index"]["started"],
        serde_json::json!(true),
        "the index was entered and could not take the lock: {report}"
    );
    // Hard constraint 13: `index-run.lock` covers the index and nothing else.
    // The mirror stage ran and published its file *while the lock was held*,
    // which is what proves no outer all-round lock was added around it.
    let good = mirror_source(&report, GOOD_SOURCE);
    assert_eq!(
        good["status"],
        serde_json::json!("success"),
        "the mirror stage must not be inside the index lock: {report}"
    );
    let mirrored = PathBuf::from(
        good["paths"][0]["path"]
            .as_str()
            .unwrap_or_else(|| panic!("the source must report its mirror path: {good}")),
    );
    assert!(
        mirrored.join("projects/-pr10/agent-remote.jsonl").is_file(),
        "the transfer must have happened before the lock was contended: {mirrored:?}"
    );

    // Releasing the lock must make the very same round succeed, so exit 2 is
    // the lock and not something else about this fixture.
    lock.unlock().expect("release the index-run lock");
    let after = fixture.sync_json(&stub.base_url, &[]);
    let report = report_of(&after);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_READY),
        "the same round must be complete once the lock is free: {report} stderr={}",
        stderr_of(&after)
    );
    assert_eq!(
        db_scalar(&fixture.db_path(), "SELECT COUNT(*) FROM conversations"),
        2,
        "the released round must ingest the HOME session and the mirrored one"
    );
}

#[cfg(unix)]
#[test]
fn an_unreachable_infinity_is_exit_2() {
    let fixture = Fixture::new();
    fixture.seed_session("rollout-inf.jsonl", "w10-remote-inf");
    fixture.write_sources_config(TWO_SOURCES);

    let output = fixture.sync_json(&closed_port_url(), &[]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_PRECONDITION),
        "an unreachable Infinity is a precondition failure: {report}"
    );
    assert_eq!(
        report["error"]["kind"],
        serde_json::json!("semantic-unavailable"),
        "an unreachable Infinity must be named as such: {report}"
    );
    assert_eq!(
        report["mirror"]["attempted"],
        serde_json::json!(false),
        "the preflight must stop the round before any remote is contacted: {report}"
    );
    assert_eq!(
        report["mirror"]["sources"],
        serde_json::json!([]),
        "no source may be reported as synced when nothing was pulled: {report}"
    );
    assert!(
        !fixture.db_path().exists(),
        "the round must stop before the corpus exists"
    );
}

// ---------------------------------------------------------------------------
// M3 — the run log
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn the_run_log_matches_stdout_byte_for_byte() {
    let fixture = Fixture::new();
    let stub = StubInfinity::start();
    fixture.seed_session("rollout-log.jsonl", "w10-log");
    fixture.write_sources_config(TWO_SOURCES);

    let first = fixture.sync_json(&stub.base_url, &[]);
    let report = report_of(&first);
    assert_eq!(report["exit_code"], serde_json::json!(EXIT_PARTIAL));
    let second = fixture.sync_json(&stub.base_url, &[]);
    assert_eq!(
        report_of(&second)["exit_code"],
        serde_json::json!(EXIT_PARTIAL)
    );

    assert!(fixture.run_log().is_file(), "the round log must exist");
    let raw = std::fs::read(fixture.run_log()).expect("read the round log");
    let text = String::from_utf8(raw).expect("the round log is UTF-8 JSON lines");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "one round is one line, and two rounds ran: {text:?}"
    );
    assert_eq!(
        lines[0].as_bytes(),
        first.stdout.strip_suffix(b"\n").unwrap_or(&first.stdout),
        "the logged line must be the byte-identical stdout line"
    );
    assert_eq!(
        lines[1].as_bytes(),
        second.stdout.strip_suffix(b"\n").unwrap_or(&second.stdout),
        "the second round must append its own byte-identical line"
    );

    // The line carries the four stages, each with its own window.
    let logged: serde_json::Value =
        serde_json::from_str(lines[1]).expect("the logged line is one JSON object");
    let stages = logged["stages"]
        .as_array()
        .unwrap_or_else(|| panic!("the report must carry its stages: {logged}"));
    let names: Vec<&str> = stages
        .iter()
        .map(|stage| stage["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        names,
        vec!["preflight", "mirror", "index", "report"],
        "the four stages are fixed and ordered: {logged}"
    );
    for stage in stages {
        assert!(
            stage["started_at"].is_string() && stage["finished_at"].is_string(),
            "a stage that ran must carry both timestamps: {stage}"
        );
        assert!(
            matches!(stage["status"].as_str(), Some("ok" | "failed" | "skipped")),
            "a stage status must be one of the three known values: {stage}"
        );
    }

    #[cfg(unix)]
    {
        assert_eq!(
            mode_of(&fixture.data_dir().join("logs")),
            0o700,
            "the log directory must be private"
        );
        assert_eq!(
            mode_of(&fixture.run_log()),
            0o600,
            "the log file must be private"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_log_that_cannot_be_written_only_warns() {
    let fixture = Fixture::new();
    let stub = StubInfinity::start();
    fixture.seed_session("rollout-logfail.jsonl", "w10-logfail");

    // A *file* where the log directory belongs: creating the directory cannot
    // succeed, and nothing about the round's own result may change.
    std::fs::create_dir_all(fixture.data_dir()).expect("create data dir");
    std::fs::write(fixture.data_dir().join("logs"), b"not a directory\n")
        .expect("occupy the log path with a file");

    let output = fixture.sync_json(&stub.base_url, &[]);
    let report = report_of(&output);
    assert_eq!(
        report["exit_code"],
        serde_json::json!(EXIT_READY),
        "a failed log write must not rewrite the round's result: {report}"
    );
    assert_eq!(
        output.status.code(),
        Some(EXIT_READY),
        "the process code must be the round's own: {report}"
    );
    assert!(
        stderr_of(&output).contains("could not append this round"),
        "the failure must be reported on stderr: {}",
        stderr_of(&output)
    );
    assert_eq!(
        db_scalar(&fixture.db_path(), "SELECT COUNT(*) FROM conversations"),
        1,
        "the round must still have ingested the local session"
    );
}

// ---------------------------------------------------------------------------
// The round-level decision table
// ---------------------------------------------------------------------------

#[test]
fn the_round_decision_table_keeps_both_partial_reasons() {
    // The `semantic_activated = false` arm is not reachable through the
    // binary: the drain's post-loop invariant bails the whole run if any
    // `chunk_holes` row survives, so every `Ok` run publishes `true`. The
    // classification is still this command's product behaviour, so it is
    // pinned here rather than claimed as an end-to-end result.
    let (code, reasons, error) =
        classify_round_outcome(IndexOutcome::Completed(false), true, None, None);
    assert_eq!(code, EXIT_PARTIAL, "both halves partial is still partial");
    assert_eq!(
        reasons,
        vec![REASON_MIRROR_FAILED, REASON_SEMANTIC_NOT_READY],
        "both partial reasons must survive together, neither overwritten"
    );
    assert_eq!(
        error.expect("a partial round carries a reason").kind,
        "source"
    );

    // A mirror that reported success but whose roots the index side cannot
    // find is exit 1, whatever the index itself did.
    let (code, reasons, error) = classify_round_outcome(
        IndexOutcome::Completed(true),
        false,
        Some("source `x` path `~/.claude/projects`: missing"),
        None,
    );
    assert_eq!(code, EXIT_INTERNAL);
    assert!(reasons.is_empty(), "a failing round is not a partial one");
    assert_eq!(
        error.expect("a failed round carries a reason").kind,
        "index"
    );

    // A genuine index failure is the more specific fact and is kept.
    let (code, _, error) = classify_round_outcome(
        IndexOutcome::Failed("boom".to_string()),
        false,
        Some("source `x` path `p`: missing"),
        None,
    );
    assert_eq!(code, EXIT_INTERNAL);
    let error = error.expect("a failed round carries a reason");
    assert_eq!(error.kind, "index");
    assert!(
        error.message.contains("boom"),
        "the real index failure must be reported, not replaced: {error:?}"
    );

    // A contended lock is a precondition (2), and it survives a mirror that
    // also failed.
    let (code, reasons, error) = classify_round_outcome(
        IndexOutcome::LockBusy("another cass index process already holds /x".to_string()),
        true,
        None,
        None,
    );
    assert_eq!(code, EXIT_PRECONDITION);
    assert_eq!(reasons, vec![REASON_MIRROR_FAILED]);
    assert_eq!(
        error.expect("a precondition failure carries a reason").kind,
        "index-busy"
    );

    // Ready: only when nothing is partial and nothing is inconsistent.
    let (code, reasons, error) =
        classify_round_outcome(IndexOutcome::Completed(true), false, None, None);
    assert_eq!(code, EXIT_READY);
    assert!(reasons.is_empty());
    assert!(error.is_none());
}
