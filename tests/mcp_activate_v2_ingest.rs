//! Task10: the default ingest runs the complete v2 rule epoch, and the
//! uncovered-recall counters are the run's own totals of the four fixed
//! reasons.
//!
//! Every case drives the real `cass` binary over a private synthetic HOME, a
//! private data directory and a private configuration tier, then reads the
//! resulting SQLite database and the raw mirror directly. The synthetic
//! fixtures carry no real session, path or secret.
//!
//! The expected values come from the literal fixtures in this file: the six
//! supported recall shapes are counted from the wrappers encoded here, and the
//! uncovered matrix is five literal inputs (four reasons, one of them twice).
//! No expectation is read back from the candidate's own output.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use coding_agent_search::raw_mirror::manifest_views;
use coding_agent_search::recall_output::{self, RecallTool};
use coding_agent_search::storage::api::{Conn, OpenOptions};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const SUPPORTED_QUERY: &str = "task10 supported query";
const ORDINARY_PROSE: &str = "task10 ordinary user prose stays";
const PIPELINE_OUTPUT: &str = "task10 ordinary pipeline output stays";
const TAG_DISCUSSION: &str =
    "we should never treat <cass_recall version=\"1\" tool=\"cass_search\"> as proof by itself";
const CODEX_PROSE: &str = "task10 codex prose stays";
const DYNAMIC_OUTPUT: &str = "task10 dynamic cass output stays";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

fn result_root() -> PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        if let Ok(root) = std::env::var("CASS_MCP_T10_RESULT_ROOT") {
            let path = PathBuf::from(root);
            assert!(
                !path.exists(),
                "CASS_MCP_T10_RESULT_ROOT must not exist before the first run: {}",
                path.display()
            );
            std::fs::create_dir_all(&path).expect("create the result root");
            return path;
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("cass-mcp-t10-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create fallback result root");
        path
    })
    .clone()
}

struct CaseDir {
    path: PathBuf,
}

impl CaseDir {
    fn new(test: &str, case: &str) -> Self {
        let path = result_root().join(test).join(case);
        assert!(
            !path.exists(),
            "case evidence directory already exists (refusing to overwrite): {}",
            path.display()
        );
        std::fs::create_dir_all(&path).expect("create the case evidence directory");
        Self { path }
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.path.join(name), bytes).expect("write case evidence");
    }

    fn write_json(&self, name: &str, value: &Value) {
        self.write(
            name,
            serde_json::to_vec_pretty(value)
                .expect("encode evidence")
                .as_slice(),
        );
    }
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home")).expect("mkdir home");
        std::fs::create_dir_all(root.path().join("data")).expect("mkdir data");
        std::fs::create_dir_all(root.path().join("config")).expect("mkdir config");
        Self { root }
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn config_home(&self) -> PathBuf {
        self.root.path().join("config")
    }

    fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn db(&self) -> PathBuf {
        self.data_dir().join("agent_search.db")
    }

    fn isolate<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("HOME", self.home())
            .env("XDG_DATA_HOME", self.home().join(".local/share"))
            .env("XDG_CONFIG_HOME", self.config_home())
            .env("XDG_CACHE_HOME", self.home().join(".cache"))
            .env("XDG_STATE_HOME", self.home().join(".state"))
            .env("CODEX_HOME", self.home().join(".codex"))
            .env("CASS_DATA_DIR", self.data_dir())
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("NO_COLOR", "1")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("CASS_TEST_WATCH_PATHS")
            .env_remove("CASS_SRC05B07_FAIL_AT")
            .env_remove("CASS_API_CONFIG")
            .env_remove("RUST_LOG");
        cmd
    }

    fn index(&self, extra: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(cass_bin());
        for (key, value) in envs {
            cmd.env(key, value);
        }
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"]).arg(self.data_dir());
        cmd.args(extra).arg("--json");
        cmd.output().expect("spawn cass index")
    }

    fn open_db(&self) -> Conn {
        Conn::open_read_with(
            &self.db(),
            OpenOptions {
                busy_timeout: Duration::from_secs(30),
            },
        )
        .expect("open the database read-only through the storage facade")
    }
}

fn jsonl(lines: &[Value]) -> String {
    lines
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// ---------------------------------------------------------------------------
// The literal recall shapes
// ---------------------------------------------------------------------------

fn search_value() -> Value {
    json!({"hits": [
        {"source_id": "local", "source_path": "/synthetic/t10/hit.jsonl", "line_number": 3, "content": "task10 supported hit body"},
    ]})
}

/// The unpaired candidate's envelope carries a different body, so the
/// "supported body is cleared" assertion cannot be satisfied by a preserved
/// uncovered sample that legitimately keeps its own text.
fn uncovered_search_value() -> Value {
    json!({"hits": [
        {"source_id": "local", "source_path": "/synthetic/t10/hit.jsonl", "line_number": 3, "content": "task10 uncovered hit body"},
    ]})
}

fn expand_value() -> Value {
    json!([
        {"line": 2, "role": "user", "is_target": false, "content": "task10 before"},
        {"line": 3, "role": "assistant", "is_target": true, "content": "task10 target"},
    ])
}

fn sessions_value() -> Value {
    json!({"sessions": [{"source_id": "local", "path": "/synthetic/t10/list.jsonl"}]})
}

fn timeline_value() -> Value {
    json!({"range": {"start": 1, "end": 2}, "total_sessions": 1,
           "groups": {"hour": [{"source_id": "local", "source_path": "/synthetic/t10/t.jsonl"}]}})
}

fn wrapper(tool: RecallTool, value: &Value) -> String {
    recall_output::encode(tool, value).expect("the literal value encodes as one C04 envelope")
}

fn cli_application(wrapper: &str) -> Value {
    json!({"exit_code": 0, "output": wrapper, "wall_time_seconds": 0.25, "chunk_id": "c1"})
}

fn transport_header(wall: &str) -> String {
    format!("Script completed\nWall time {wall} seconds\nOutput:")
}

fn cli_output_blocks(wrapper: &str) -> Value {
    json!([
        {"type": "input_text", "text": transport_header("0.25")},
        {"type": "input_text", "text": cli_application(wrapper).to_string()},
    ])
}

// ---------------------------------------------------------------------------
// The synthetic world: two agents, six supported shapes, five uncovered
// ---------------------------------------------------------------------------

struct World {
    claude_path: PathBuf,
    codex_path: PathBuf,
    claude_bytes: Vec<u8>,
    codex_bytes: Vec<u8>,
}

/// One Claude session with the four native MCP results, one direct Bash CLI
/// recall, and the uncovered/ordinary controls.
fn write_claude_session(fixture: &Fixture) -> (PathBuf, Vec<u8>) {
    let recall = |tool: RecallTool, value: &Value| wrapper(tool, value);
    let lines = vec![
        json!({
            "type": "user", "timestamp": "2026-01-02T00:00:00.000Z", "uuid": "t10-u0",
            "message": {"role": "user", "content": ORDINARY_PROSE}
        }),
        json!({
            "type": "assistant", "timestamp": "2026-01-02T00:00:01.000Z", "uuid": "t10-a-search",
            "message": {"role": "assistant", "content": [
                {"type": "text", "text": "Searching with the cass MCP."},
                {"type": "tool_use", "id": "toolu_t10_search", "name": "mcp__cass-mcp__cass_search", "input": {"query": SUPPORTED_QUERY}}
            ]}
        }),
        json!({
            "type": "user", "timestamp": "2026-01-02T00:00:02.000Z", "uuid": "t10-u-search",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_t10_search", "content": recall(RecallTool::Search, &search_value())}
            ]}
        }),
        json!({
            "type": "assistant", "timestamp": "2026-01-02T00:00:03.000Z", "uuid": "t10-a-expand",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_t10_expand", "name": "mcp__cass-mcp__cass_expand", "input": {"source_id": "local", "source_path": "/synthetic/t10/hit.jsonl", "message_id": 3}}
            ]}
        }),
        json!({
            "type": "user", "timestamp": "2026-01-02T00:00:04.000Z", "uuid": "t10-u-expand",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_t10_expand", "content": recall(RecallTool::Expand, &expand_value())}
            ]}
        }),
        json!({
            "type": "assistant", "timestamp": "2026-01-02T00:00:05.000Z", "uuid": "t10-a-sessions",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_t10_sessions", "name": "mcp__cass-mcp__cass_sessions", "input": {"limit": 5}}
            ]}
        }),
        json!({
            "type": "user", "timestamp": "2026-01-02T00:00:06.000Z", "uuid": "t10-u-sessions",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_t10_sessions", "content": recall(RecallTool::Sessions, &sessions_value())}
            ]}
        }),
        json!({
            "type": "assistant", "timestamp": "2026-01-02T00:00:07.000Z", "uuid": "t10-a-timeline",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_t10_timeline", "name": "mcp__cass-mcp__cass_timeline", "input": {"group_by": "hour"}}
            ]}
        }),
        json!({
            "type": "user", "timestamp": "2026-01-02T00:00:08.000Z", "uuid": "t10-u-timeline",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_t10_timeline", "content": recall(RecallTool::Timeline, &timeline_value())}
            ]}
        }),
        json!({
            "type": "assistant", "timestamp": "2026-01-02T00:00:09.000Z", "uuid": "t10-a-cli",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_t10_cli", "name": "Bash", "input": {"command": "cass search \"task10 supported query\" --recall"}}
            ]}
        }),
        json!({
            "type": "user", "timestamp": "2026-01-02T00:00:10.000Z", "uuid": "t10-u-cli",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_t10_cli", "content": recall(RecallTool::Search, &search_value())}
            ]}
        }),
        // unsupported_shell: a Cass pipeline is one recognized candidate the
        // first version keeps whole.
        json!({
            "type": "assistant", "timestamp": "2026-01-02T00:00:11.000Z", "uuid": "t10-a-pipe",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_t10_pipe", "name": "Bash", "input": {"command": "cass search \"task10\" --recall | head -5"}}
            ]}
        }),
        json!({
            "type": "user", "timestamp": "2026-01-02T00:00:12.000Z", "uuid": "t10-u-pipe",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_t10_pipe", "content": PIPELINE_OUTPUT}
            ]}
        }),
        // An ordinary shell pipeline is not a Cass candidate at all.
        json!({
            "type": "assistant", "timestamp": "2026-01-02T00:00:13.000Z", "uuid": "t10-a-grep",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_t10_grep", "name": "Bash", "input": {"command": "cat /tmp/task10.txt | grep needle"}}
            ]}
        }),
        json!({
            "type": "user", "timestamp": "2026-01-02T00:00:14.000Z", "uuid": "t10-u-grep",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_t10_grep", "content": "task10 ordinary grep output"}
            ]}
        }),
        // A user discussing the tag is prose, not a recall.
        json!({
            "type": "user", "timestamp": "2026-01-02T00:00:15.000Z", "uuid": "t10-u-tag",
            "message": {"role": "user", "content": TAG_DISCUSSION}
        }),
        json!({
            "type": "assistant", "timestamp": "2026-01-02T00:00:16.000Z", "uuid": "t10-a-end",
            "message": {"role": "assistant", "content": "task10 claude answer"}
        }),
    ];
    let body = jsonl(&lines);
    let path = fixture.home().join(".claude/projects/t10/session.jsonl");
    std::fs::create_dir_all(path.parent().expect("claude project parent"))
        .expect("mkdir claude project");
    std::fs::write(&path, body.as_bytes()).expect("write the claude session");
    (path, body.into_bytes())
}

/// One Codex rollout: a supported C07 literal, the four uncovered shapes, and
/// the two ordinary date controls.
fn write_codex_session(fixture: &Fixture) -> (PathBuf, Vec<u8>) {
    let supported = wrapper(RecallTool::Sessions, &sessions_value());
    let supported_expression = format!(
        "text(await tools.exec_command({}));",
        json!({"cmd": "cass sessions --limit 5 --recall"})
    );
    let dynamic_cass_expression = format!(
        "const r = await tools.exec_command({}); text(r);",
        json!({"cmd": "cass search \"task10\" --recall"})
    );
    let date_expression = format!(
        "text(await tools.exec_command({}));",
        json!({"cmd": "date +%F"})
    );
    let dynamic_date_expression =
        "const d = new Date(); text(await tools.exec_command({\"cmd\":\"echo \" + d.toISOString()}));"
            .to_string();
    let damaged_wrapper =
        "<cass_recall version=\"1\" tool=\"cass_search\">{\"hits\": []}".to_string();

    let lines = vec![
        json!({
            "timestamp": "2026-01-02T00:00:00.000Z",
            "type": "session_meta",
            "payload": {"id": "t10-codex", "cwd": "/synthetic/project", "cli_version": "0.42.0"}
        }),
        json!({
            "timestamp": "2026-01-02T00:00:01.000Z",
            "type": "response_item",
            "payload": {"type": "message", "id": "t10-codex-u", "role": "user",
                        "content": [{"type": "input_text", "text": CODEX_PROSE}]}
        }),
        // A supported C07 literal: one exec_command with a proven Cass read.
        json!({
            "timestamp": "2026-01-02T00:00:02.000Z",
            "type": "response_item",
            "payload": {"type": "custom_tool_call", "name": "exec",
                        "input": supported_expression, "call_id": "call_t10_ok"}
        }),
        json!({
            "timestamp": "2026-01-02T00:00:03.000Z",
            "type": "response_item",
            "payload": {"type": "custom_tool_call_output", "call_id": "call_t10_ok",
                        "output": cli_output_blocks(&supported)}
        }),
        // unsupported_shell: a recognized Cass command behind a dynamic script.
        json!({
            "timestamp": "2026-01-02T00:00:04.000Z",
            "type": "response_item",
            "payload": {"type": "custom_tool_call", "name": "exec",
                        "input": dynamic_cass_expression, "call_id": "call_t10_dynamic"}
        }),
        json!({
            "timestamp": "2026-01-02T00:00:05.000Z",
            "type": "response_item",
            "payload": {"type": "custom_tool_call_output", "call_id": "call_t10_dynamic",
                        "output": DYNAMIC_OUTPUT}
        }),
        // An ordinary literal date is not a Cass candidate.
        json!({
            "timestamp": "2026-01-02T00:00:06.000Z",
            "type": "response_item",
            "payload": {"type": "custom_tool_call", "name": "exec",
                        "input": date_expression, "call_id": "call_t10_date"}
        }),
        json!({
            "timestamp": "2026-01-02T00:00:07.000Z",
            "type": "response_item",
            "payload": {"type": "custom_tool_call_output", "call_id": "call_t10_date",
                        "output": "2026-10-22"}
        }),
        // An ordinary dynamic date is not a Cass candidate either.
        json!({
            "timestamp": "2026-01-02T00:00:08.000Z",
            "type": "response_item",
            "payload": {"type": "custom_tool_call", "name": "exec",
                        "input": dynamic_date_expression, "call_id": "call_t10_dynamic_date"}
        }),
        json!({
            "timestamp": "2026-01-02T00:00:09.000Z",
            "type": "response_item",
            "payload": {"type": "custom_tool_call_output", "call_id": "call_t10_dynamic_date",
                        "output": "2026-10-22T00:00:00.000Z"}
        }),
        // ambiguous_tool_identity: a bare same-named tool with ordinary output.
        json!({
            "timestamp": "2026-01-02T00:00:10.000Z",
            "type": "response_item",
            "payload": {"type": "function_call", "id": "fc_t10_ambiguous", "name": "cass_search",
                        "arguments": "{\"query\":\"task10\"}", "call_id": "call_t10_ambiguous"}
        }),
        json!({
            "timestamp": "2026-01-02T00:00:11.000Z",
            "type": "response_item",
            "payload": {"type": "function_call_output", "call_id": "call_t10_ambiguous",
                        "output": "{\"result\":\"task10 ordinary same-named output\"}"}
        }),
        // invalid_recall_format: the bare name with a damaged envelope.
        json!({
            "timestamp": "2026-01-02T00:00:12.000Z",
            "type": "response_item",
            "payload": {"type": "function_call", "id": "fc_t10_invalid", "name": "cass_search",
                        "arguments": "{\"query\":\"task10\"}", "call_id": "call_t10_invalid"}
        }),
        json!({
            "timestamp": "2026-01-02T00:00:13.000Z",
            "type": "response_item",
            "payload": {"type": "function_call_output", "call_id": "call_t10_invalid",
                        "output": damaged_wrapper}
        }),
        // unpaired_result: a complete envelope whose call row is missing.
        json!({
            "timestamp": "2026-01-02T00:00:14.000Z",
            "type": "response_item",
            "payload": {"type": "custom_tool_call_output", "call_id": "call_t10_unpaired",
                        "output": cli_application(&wrapper(RecallTool::Search, &uncovered_search_value())).to_string()}
        }),
        json!({
            "timestamp": "2026-01-02T00:00:15.000Z",
            "type": "response_item",
            "payload": {"type": "message", "id": "t10-codex-a", "role": "assistant",
                        "content": [{"type": "output_text", "text": "task10 codex answer"}]}
        }),
    ];
    let body = jsonl(&lines);
    let path = fixture
        .home()
        .join(".codex/sessions/2026/01/rollout-t10.jsonl");
    std::fs::create_dir_all(path.parent().expect("codex rollout parent"))
        .expect("mkdir codex rollout");
    std::fs::write(&path, body.as_bytes()).expect("write the codex rollout");
    (path, body.into_bytes())
}

fn build_world(fixture: &Fixture) -> World {
    let (claude_path, claude_bytes) = write_claude_session(fixture);
    let (codex_path, codex_bytes) = write_codex_session(fixture);
    World {
        claude_path,
        codex_path,
        claude_bytes,
        codex_bytes,
    }
}

// ---------------------------------------------------------------------------
// Task18a: native full-name MCP calls that carry no captured arguments.
// Task18e: native bare-name MCP calls that carry no captured arguments.
//
// Every value below is a literal fixture in this file. The eight strong
// missing-args calls (four per agent), the eight bare missing-args calls
// (four per agent) and the two normal-args searches are all paired with
// valid C04 envelopes, so every one of them is excluded. The two
// preservation controls below -- another server's same-suffixed tool and a
// complete envelope whose call row is missing -- exercise the unchanged
// rules and must keep their bodies, as do the ordinary same-named tool and
// the C07 `exec` without a literal.
// ---------------------------------------------------------------------------

const NATIVE_CLAUDE_PROSE: &str = "t18a native claude prose stays";
const NATIVE_CODEX_PROSE: &str = "t18a native codex prose stays";
const NATIVE_ORDINARY_OUTPUT: &str = "t18a ordinary same-named output stays";
const NATIVE_C07_MISSING_OUTPUT: &str = "t18a c07 missing literal output stays";
const NATIVE_CLAUDE_SEARCH_BODY: &str = "t18a claude native search body";
const NATIVE_CODEX_SEARCH_BODY: &str = "t18a codex native search body";
const NATIVE_CLAUDE_CONTROL_BODY: &str = "t18a claude control search body";
const NATIVE_CODEX_CONTROL_BODY: &str = "t18a codex control search body";
const NATIVE_CLAUDE_BARE_BODY: &str = "t18a claude bare missing args body stays";
const NATIVE_CODEX_BARE_BODY: &str = "t18a codex bare missing args body stays";
const NATIVE_OTHER_SERVER_BODY: &str = "t18a other-server body stays";
const NATIVE_CLAUDE_OTHER_MISSING_OUTPUT: &str =
    "t18a claude other-server missing args output stays";
const NATIVE_CODEX_OTHER_MISSING_OUTPUT: &str = "t18a codex other-server missing args output stays";
const NATIVE_UNPAIRED_BODY: &str = "t18a unpaired candidate body stays";

/// A C02-legal search hit: all five identity fields, with a 64-character
/// lowercase digest over the synthetic body. The body stays a literal written
/// here, never host data.
fn native_search_value(body: &str) -> Value {
    json!({"hits": [
        {"source_id": "local", "source_path": "/synthetic/t18a/hit.jsonl",
         "message_id": 4, "line_number": 4,
         "content_sha256": sha256_hex(body.as_bytes()),
         "content": body},
    ]})
}

/// The exact full server-namespaced tool names this fixture exercises.
fn native_full_name(tool: RecallTool) -> &'static str {
    match tool {
        RecallTool::Search => "mcp__cass-mcp__cass_search",
        RecallTool::Expand => "mcp__cass-mcp__cass_expand",
        RecallTool::Sessions => "mcp__cass-mcp__cass_sessions",
        RecallTool::Timeline => "mcp__cass-mcp__cass_timeline",
    }
}

fn native_expand_value() -> Value {
    json!([
        {"line": 1, "role": "user", "is_target": false, "content": "t18a expand before"},
        {"line": 2, "role": "assistant", "is_target": true, "content": "t18a expand target"},
    ])
}

fn native_sessions_value() -> Value {
    json!({"sessions": [{"source_id": "local", "path": "/synthetic/t18a/list.jsonl"}]})
}

fn native_timeline_value() -> Value {
    json!({"range": {"start": 1, "end": 2}, "total_sessions": 1,
           "groups": {"hour": [{"source_id": "local", "source_path": "/synthetic/t18a/t.jsonl"}]}})
}

struct NativeWorld {
    claude_path: PathBuf,
    codex_path: PathBuf,
    claude_bytes: Vec<u8>,
    codex_bytes: Vec<u8>,
    /// call id -> the exact result body that must be excluded and hashed.
    excluded_bodies: Vec<(&'static str, String)>,
}

/// One Claude session: four native full-name calls without `input`, one
/// normal-args search control, and the preservation controls.
fn write_claude_native_session(
    fixture: &Fixture,
) -> (PathBuf, Vec<u8>, Vec<(&'static str, String)>) {
    let mut excluded = Vec::new();
    let mut lines = vec![json!({
        "type": "user", "timestamp": "2026-01-03T00:00:00.000Z", "uuid": "t18a-u0",
        "message": {"role": "user", "content": NATIVE_CLAUDE_PROSE}
    })];

    let missing: [(&'static str, RecallTool, Value); 4] = [
        (
            "toolu_t18a_n_search",
            RecallTool::Search,
            native_search_value(NATIVE_CLAUDE_SEARCH_BODY),
        ),
        (
            "toolu_t18a_n_expand",
            RecallTool::Expand,
            native_expand_value(),
        ),
        (
            "toolu_t18a_n_sessions",
            RecallTool::Sessions,
            native_sessions_value(),
        ),
        (
            "toolu_t18a_n_timeline",
            RecallTool::Timeline,
            native_timeline_value(),
        ),
    ];
    for (offset, (id, tool, value)) in missing.into_iter().enumerate() {
        let call_sec = 1 + offset * 2;
        let result_sec = call_sec + 1;
        lines.push(json!({
            "type": "assistant",
            "timestamp": format!("2026-01-03T00:00:{call_sec:02}.000Z"),
            "uuid": format!("t18a-a-{id}"),
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": id, "name": native_full_name(tool)}
            ]}
        }));
        let body = wrapper(tool, &value);
        lines.push(json!({
            "type": "user",
            "timestamp": format!("2026-01-03T00:00:{result_sec:02}.000Z"),
            "uuid": format!("t18a-r-{id}"),
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": id, "content": body}
            ]}
        }));
        excluded.push((id, body));
    }

    // The normal-args control: the same full name, with its captured input.
    let control = wrapper(
        RecallTool::Search,
        &native_search_value(NATIVE_CLAUDE_CONTROL_BODY),
    );
    lines.push(json!({
        "type": "assistant", "timestamp": "2026-01-03T00:00:09.000Z", "uuid": "t18a-a-control",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_t18a_c_search", "name": "mcp__cass-mcp__cass_search",
             "input": {"query": "t18a control query"}}
        ]}
    }));
    lines.push(json!({
        "type": "user", "timestamp": "2026-01-03T00:00:10.000Z", "uuid": "t18a-r-control",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_t18a_c_search", "content": control}
        ]}
    }));
    excluded.push(("toolu_t18a_c_search", control));

    // Task18e: a bare name without captured arguments is excluded once its
    // result decodes as a complete C04 envelope for that exact tool. All four
    // tools are the positive matrix; the old preserved search literal now
    // carries the same role with a positive expectation.
    let bare_missing: [(&'static str, &'static str, RecallTool, Value); 4] = [
        (
            "toolu_t18a_bare_missing",
            "cass_search",
            RecallTool::Search,
            native_search_value(NATIVE_CLAUDE_BARE_BODY),
        ),
        (
            "toolu_t18e_bare_expand",
            "cass_expand",
            RecallTool::Expand,
            native_expand_value(),
        ),
        (
            "toolu_t18e_bare_sessions",
            "cass_sessions",
            RecallTool::Sessions,
            native_sessions_value(),
        ),
        (
            "toolu_t18e_bare_timeline",
            "cass_timeline",
            RecallTool::Timeline,
            native_timeline_value(),
        ),
    ];
    for (offset, (id, name, tool, value)) in bare_missing.into_iter().enumerate() {
        let call_sec = 11 + offset * 2;
        let result_sec = call_sec + 1;
        lines.push(json!({
            "type": "assistant",
            "timestamp": format!("2026-01-03T00:00:{call_sec:02}.000Z"),
            "uuid": format!("t18e-a-{id}"),
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": id, "name": name}
            ]}
        }));
        let body = wrapper(tool, &value);
        lines.push(json!({
            "type": "user",
            "timestamp": format!("2026-01-03T00:00:{result_sec:02}.000Z"),
            "uuid": format!("t18e-r-{id}"),
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": id, "content": body}
            ]}
        }));
        excluded.push((id, body));
    }

    // Preservation control: an ordinary same-named tool.
    lines.push(json!({
        "type": "assistant", "timestamp": "2026-01-03T00:00:19.000Z", "uuid": "t18a-a-ordinary",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_t18a_ordinary", "name": "cass_search",
             "input": {"query": "t18a ordinary query"}}
        ]}
    }));
    lines.push(json!({
        "type": "user", "timestamp": "2026-01-03T00:00:20.000Z", "uuid": "t18a-r-ordinary",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_t18a_ordinary", "content": NATIVE_ORDINARY_OUTPUT}
        ]}
    }));

    // Preservation control: another server's same-suffixed tool.
    let other = wrapper(
        RecallTool::Search,
        &native_search_value(NATIVE_OTHER_SERVER_BODY),
    );
    lines.push(json!({
        "type": "assistant", "timestamp": "2026-01-03T00:00:21.000Z", "uuid": "t18a-a-other",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_t18a_other", "name": "mcp__other-mcp__cass_search",
             "input": {"query": "t18a other server query"}}
        ]}
    }));
    lines.push(json!({
        "type": "user", "timestamp": "2026-01-03T00:00:22.000Z", "uuid": "t18a-r-other",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_t18a_other", "content": other}
        ]}
    }));

    // Preservation control: another server's tool without captured input.
    // An unknown identity must fall back to the legacy judgment before any
    // argument gate, so this row adds no v2 uncovered count.
    lines.push(json!({
        "type": "assistant", "timestamp": "2026-01-03T00:00:22.500Z", "uuid": "t18a-a-other-missing",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_t18a_other_missing", "name": "mcp__other-mcp__cass_search"}
        ]}
    }));
    lines.push(json!({
        "type": "user", "timestamp": "2026-01-03T00:00:22.750Z", "uuid": "t18a-r-other-missing",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_t18a_other_missing",
             "content": NATIVE_CLAUDE_OTHER_MISSING_OUTPUT}
        ]}
    }));

    // Preservation control: a complete envelope whose call row is missing.
    let unpaired = wrapper(
        RecallTool::Search,
        &native_search_value(NATIVE_UNPAIRED_BODY),
    );
    lines.push(json!({
        "type": "user", "timestamp": "2026-01-03T00:00:23.000Z", "uuid": "t18a-u-unpaired",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_t18a_unpaired", "content": unpaired}
        ]}
    }));
    lines.push(json!({
        "type": "assistant", "timestamp": "2026-01-03T00:00:24.000Z", "uuid": "t18a-a-end",
        "message": {"role": "assistant", "content": "t18a claude answer"}
    }));

    let body = jsonl(&lines);
    let path = fixture
        .home()
        .join(".claude/projects/t18a-native/session.jsonl");
    std::fs::create_dir_all(path.parent().expect("claude native project parent"))
        .expect("mkdir claude native project");
    std::fs::write(&path, body.as_bytes()).expect("write the claude native session");
    (path, body.into_bytes(), excluded)
}

/// One Codex rollout: the same eight missing-args targets as native
/// `function_call` rows, the normal-args control, and the preservation
/// controls including a C07 `exec` without a literal.
fn write_codex_native_session(
    fixture: &Fixture,
) -> (PathBuf, Vec<u8>, Vec<(&'static str, String)>) {
    let mut excluded = Vec::new();
    let mut lines = vec![
        json!({
            "timestamp": "2026-01-03T00:00:00.000Z",
            "type": "session_meta",
            "payload": {"id": "t18a-codex", "cwd": "/synthetic/project", "cli_version": "0.42.0"}
        }),
        json!({
            "timestamp": "2026-01-03T00:00:01.000Z",
            "type": "response_item",
            "payload": {"type": "message", "id": "t18a-codex-u", "role": "user",
                        "content": [{"type": "input_text", "text": NATIVE_CODEX_PROSE}]}
        }),
    ];

    let missing: [(&'static str, RecallTool, Value); 4] = [
        (
            "call_t18a_n_search",
            RecallTool::Search,
            native_search_value(NATIVE_CODEX_SEARCH_BODY),
        ),
        (
            "call_t18a_n_expand",
            RecallTool::Expand,
            native_expand_value(),
        ),
        (
            "call_t18a_n_sessions",
            RecallTool::Sessions,
            native_sessions_value(),
        ),
        (
            "call_t18a_n_timeline",
            RecallTool::Timeline,
            native_timeline_value(),
        ),
    ];
    for (offset, (id, tool, value)) in missing.into_iter().enumerate() {
        let call_sec = 2 + offset * 2;
        let result_sec = call_sec + 1;
        lines.push(json!({
            "timestamp": format!("2026-01-03T00:00:{call_sec:02}.000Z"),
            "type": "response_item",
            "payload": {"type": "function_call", "id": format!("fc-{id}"),
                        "name": native_full_name(tool), "call_id": id}
        }));
        let body = wrapper(tool, &value);
        lines.push(json!({
            "timestamp": format!("2026-01-03T00:00:{result_sec:02}.000Z"),
            "type": "response_item",
            "payload": {"type": "function_call_output", "call_id": id, "output": body}
        }));
        excluded.push((id, body));
    }

    let control = wrapper(
        RecallTool::Search,
        &native_search_value(NATIVE_CODEX_CONTROL_BODY),
    );
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:10.000Z",
        "type": "response_item",
        "payload": {"type": "function_call", "id": "fc-t18a-control",
                    "name": "mcp__cass-mcp__cass_search",
                    "arguments": "{\"query\":\"t18a control query\"}",
                    "call_id": "call_t18a_c_search"}
    }));
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:11.000Z",
        "type": "response_item",
        "payload": {"type": "function_call_output", "call_id": "call_t18a_c_search", "output": control}
    }));
    excluded.push(("call_t18a_c_search", control));

    // Task18e: the same four bare tools as the Claude fixture, here as native
    // `function_call` rows without `arguments`. Each complete C04 envelope is
    // excluded; the captured arguments only feed source extraction.
    let bare_missing: [(&'static str, &'static str, RecallTool, Value); 4] = [
        (
            "call_t18a_bare_missing",
            "cass_search",
            RecallTool::Search,
            native_search_value(NATIVE_CODEX_BARE_BODY),
        ),
        (
            "call_t18e_bare_expand",
            "cass_expand",
            RecallTool::Expand,
            native_expand_value(),
        ),
        (
            "call_t18e_bare_sessions",
            "cass_sessions",
            RecallTool::Sessions,
            native_sessions_value(),
        ),
        (
            "call_t18e_bare_timeline",
            "cass_timeline",
            RecallTool::Timeline,
            native_timeline_value(),
        ),
    ];
    for (offset, (id, name, tool, value)) in bare_missing.into_iter().enumerate() {
        let call_sec = 12 + offset * 2;
        let result_sec = call_sec + 1;
        lines.push(json!({
            "timestamp": format!("2026-01-03T00:00:{call_sec:02}.000Z"),
            "type": "response_item",
            "payload": {"type": "function_call", "id": format!("fc-{id}"),
                        "name": name, "call_id": id}
        }));
        let body = wrapper(tool, &value);
        lines.push(json!({
            "timestamp": format!("2026-01-03T00:00:{result_sec:02}.000Z"),
            "type": "response_item",
            "payload": {"type": "function_call_output", "call_id": id, "output": body}
        }));
        excluded.push((id, body));
    }

    // Preservation control: an ordinary same-named tool.
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:20.000Z",
        "type": "response_item",
        "payload": {"type": "function_call", "id": "fc-t18a-ordinary",
                    "name": "cass_search", "arguments": "{\"query\":\"t18a ordinary query\"}",
                    "call_id": "call_t18a_ordinary"}
    }));
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:21.000Z",
        "type": "response_item",
        "payload": {"type": "function_call_output", "call_id": "call_t18a_ordinary",
                    "output": NATIVE_ORDINARY_OUTPUT}
    }));

    // Preservation control: another server's same-suffixed tool.
    let other = wrapper(
        RecallTool::Search,
        &native_search_value(NATIVE_OTHER_SERVER_BODY),
    );
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:22.000Z",
        "type": "response_item",
        "payload": {"type": "function_call", "id": "fc-t18a-other",
                    "name": "mcp__other-mcp__cass_search",
                    "arguments": "{\"query\":\"t18a other server query\"}",
                    "call_id": "call_t18a_other"}
    }));
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:23.000Z",
        "type": "response_item",
        "payload": {"type": "function_call_output", "call_id": "call_t18a_other", "output": other}
    }));

    // Preservation control: another server's tool without captured arguments.
    // The unknown identity falls back to the legacy judgment, so this row adds
    // no v2 uncovered count.
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:23.500Z",
        "type": "response_item",
        "payload": {"type": "function_call", "id": "fc-t18a-other-missing",
                    "name": "mcp__other-mcp__cass_search",
                    "call_id": "call_t18a_other_missing"}
    }));
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:23.750Z",
        "type": "response_item",
        "payload": {"type": "function_call_output", "call_id": "call_t18a_other_missing",
                    "output": NATIVE_CODEX_OTHER_MISSING_OUTPUT}
    }));

    // Preservation control: a complete envelope whose call row is missing.
    let unpaired = wrapper(
        RecallTool::Search,
        &native_search_value(NATIVE_UNPAIRED_BODY),
    );
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:24.000Z",
        "type": "response_item",
        "payload": {"type": "function_call_output", "call_id": "call_t18a_unpaired", "output": unpaired}
    }));

    // Preservation control: a C07 `exec` with no literal at all.
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:25.000Z",
        "type": "response_item",
        "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "call_t18a_c07_missing"}
    }));
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:26.000Z",
        "type": "response_item",
        "payload": {"type": "custom_tool_call_output", "call_id": "call_t18a_c07_missing",
                    "output": NATIVE_C07_MISSING_OUTPUT}
    }));

    lines.push(json!({
        "timestamp": "2026-01-03T00:00:27.000Z",
        "type": "response_item",
        "payload": {"type": "message", "id": "t18a-codex-a", "role": "assistant",
                    "content": [{"type": "output_text", "text": "t18a codex answer"}]}
    }));

    let body = jsonl(&lines);
    let path = fixture
        .home()
        .join(".codex/sessions/2026/01/rollout-t18a-native.jsonl");
    std::fs::create_dir_all(path.parent().expect("codex native rollout parent"))
        .expect("mkdir codex native rollout");
    std::fs::write(&path, body.as_bytes()).expect("write the codex native rollout");
    (path, body.into_bytes(), excluded)
}

fn build_native_world(fixture: &Fixture) -> NativeWorld {
    let (claude_path, claude_bytes, mut excluded_bodies) = write_claude_native_session(fixture);
    let (codex_path, codex_bytes, codex_excluded) = write_codex_native_session(fixture);
    excluded_bodies.extend(codex_excluded);
    NativeWorld {
        claude_path,
        codex_path,
        claude_bytes,
        codex_bytes,
        excluded_bodies,
    }
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

fn decode_extra(text: Option<String>, binary: Option<Vec<u8>>) -> Value {
    if let Some(text) = text {
        serde_json::from_str(&text).expect("decode extra_json")
    } else if let Some(binary) = binary {
        rmp_serde::from_slice(&binary).expect("decode extra_bin")
    } else {
        Value::Null
    }
}

/// Assert every excluded row has zero recall envelope or body residue in BOTH
/// `content` and its decoded `extra_json` / `extra_bin`.
fn assert_excluded_rows_clean(db: &Conn, forbidden_needles: &[&str], label: &str) {
    let rows: Vec<(i64, String, Option<String>, Option<Vec<u8>>)> = db
        .query_all_map(
            "SELECT id, content, extra_json, extra_bin FROM messages WHERE excluded IS NOT NULL ORDER BY id",
            &[],
            |row| {
                Ok((
                    row.get_typed::<i64>(0)?,
                    row.get_typed::<String>(1)?,
                    row.get_typed::<Option<String>>(2)?,
                    row.get_typed::<Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .expect("query excluded rows with extra");
    assert!(
        !rows.is_empty(),
        "{label}: expected at least one excluded row"
    );
    for (id, content, extra_json, extra_bin) in rows {
        let extra = decode_extra(extra_json, extra_bin);
        let extra_text = extra.to_string();
        for (surface, text) in [("content", content.as_str()), ("extra", extra_text.as_str())] {
            assert!(
                !text.contains("<cass_recall "),
                "{label}: excluded message {id} retained <cass_recall envelope in {surface}: {text}"
            );
            for needle in forbidden_needles {
                assert!(
                    !text.contains(needle),
                    "{label}: excluded message {id} retained forbidden recall body {needle:?} in {surface}: {text}"
                );
            }
        }
    }
}

/// Every exclusion marker's `rule_version`, in message order.
///
/// `messages.excluded` is stored as SQLite JSONB, so the marker is read back
/// through SQLite's own `json()` decoder. The stored format is not touched.
fn marker_rule_versions(db: &Conn) -> Vec<u64> {
    let rows: Vec<String> = db
        .query_all_map(
            "SELECT json(excluded) FROM messages WHERE excluded IS NOT NULL ORDER BY id",
            &[],
            |row| row.get_typed::<String>(0),
        )
        .expect("query the markers");
    rows.into_iter()
        .map(|text| {
            let value: Value = serde_json::from_str(&text).expect("a marker is JSON");
            value["rule_version"]
                .as_u64()
                .unwrap_or_else(|| panic!("no rule_version in {value}"))
        })
        .collect()
}

fn message_contents(db: &Conn) -> Vec<String> {
    db.query_all_map("SELECT content FROM messages ORDER BY id", &[], |row| {
        row.get_typed::<String>(0)
    })
    .expect("query the bodies")
}

/// The sealed blobs' bytes, keyed by the original path they were captured from.
fn mirror_blobs(fixture: &Fixture) -> Vec<(String, Vec<u8>)> {
    let views = manifest_views(&fixture.data_dir()).expect("read the mirror manifest views");
    views
        .into_iter()
        .map(|view| {
            let path = fixture
                .data_dir()
                .join("raw-mirror")
                .join("v1")
                .join(&view.blob_relative_path);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("read the sealed blob {path:?}: {error}"));
            (view.original_path, bytes)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Assertions shared by the four transport modes
// ---------------------------------------------------------------------------

fn expected_reasons() -> Value {
    json!({
        "ambiguous_tool_identity": 1,
        "invalid_recall_format": 1,
        "unpaired_result": 1,
        "unsupported_shell": 2,
    })
}

fn assert_activation_json(report: &Value, label: &str) {
    let total = report["recall_uncovered_total"]
        .as_u64()
        .unwrap_or_else(|| panic!("{label}: no top-level recall_uncovered_total: {report}"));
    let by_reason = report["recall_uncovered_by_reason"]
        .as_object()
        .unwrap_or_else(|| panic!("{label}: no top-level recall_uncovered_by_reason: {report}"));
    assert_eq!(
        total, 5,
        "{label}: the five literal uncovered inputs are counted"
    );
    assert_eq!(
        Value::Object(by_reason.clone()),
        expected_reasons(),
        "{label}: the reasons are the four fixed ones"
    );
    assert_eq!(
        by_reason
            .values()
            .map(|value| value.as_u64().unwrap_or(0))
            .sum::<u64>(),
        total,
        "{label}: the total is the sum of the reasons"
    );

    let stats = &report["indexing_stats"];
    assert_eq!(
        stats["recall_uncovered_total"].as_u64(),
        Some(total),
        "{label}: indexing_stats carries the same total"
    );
    assert_eq!(
        stats["recall_uncovered_by_reason"], report["recall_uncovered_by_reason"],
        "{label}: indexing_stats carries the same reasons"
    );
}

fn assert_activation_db(fixture: &Fixture, world: &World, label: &str) {
    let db = fixture.open_db();

    // 10-AC1: every exclusion marker is rule version 2 under Plan A.
    let markers = marker_rule_versions(&db);
    assert_eq!(
        markers.len(),
        6,
        "{label}: six supported recall results are excluded"
    );
    for version in &markers {
        assert_eq!(
            *version, 2,
            "{label}: every exclusion marker is rule version 2"
        );
    }
    assert_excluded_rows_clean(
        &db,
        &[
            "task10 supported hit body",
            "task10 before",
            "task10 target",
            "/synthetic/t10/list.jsonl",
            "/synthetic/t10/t.jsonl",
        ],
        label,
    );

    // At least two agents really produced markers (not a pure-function claim).
    let by_agent: Vec<(String, i64)> = db
        .query_all_map(
            "SELECT a.slug, COUNT(*) FROM messages m
             JOIN conversations c ON c.id = m.conversation_id
             JOIN agents a ON a.id = c.agent_id
             WHERE m.excluded IS NOT NULL GROUP BY a.slug ORDER BY a.slug",
            &[],
            |row| Ok((row.get_typed::<String>(0)?, row.get_typed::<i64>(1)?)),
        )
        .expect("query the per-agent markers");
    assert_eq!(
        by_agent.len(),
        2,
        "{label}: both agents carry exclusions: {by_agent:?}"
    );
    for (_agent, count) in &by_agent {
        assert!(
            *count > 0,
            "{label}: non-zero exclusions per agent: {by_agent:?}"
        );
    }

    // 10-AC2: the original prose, the ordinary outputs and the tag discussion
    // survive byte-for-byte while the excluded bodies are cleared.
    let bodies = message_contents(&db);
    assert!(
        bodies.iter().any(|body| body == ORDINARY_PROSE),
        "{label}: the ordindary prose stays"
    );
    assert!(
        bodies.iter().any(|body| body == PIPELINE_OUTPUT),
        "{label}: the pipeline output stays"
    );
    assert!(
        bodies.iter().any(|body| body == TAG_DISCUSSION),
        "{label}: the tag discussion stays"
    );
    assert!(
        bodies.iter().any(|body| body == CODEX_PROSE),
        "{label}: the codex prose stays"
    );
    assert!(
        bodies.iter().any(|body| body == DYNAMIC_OUTPUT),
        "{label}: the dynamic output stays"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("task10 ordinary grep output")),
        "{label}: the ordinary grep output stays"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("task10 ordinary same-named output")),
        "{label}: the same-named tool's ordinary output stays"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body
                .contains("<cass_recall version=\"1\" tool=\"cass_search\">{\"hits\": []}")),
        "{label}: the damaged bare-name envelope stays"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("task10 uncovered hit body")),
        "{label}: the unpaired candidate's own body stays"
    );
    assert!(
        !bodies
            .iter()
            .any(|body| body.contains("task10 supported hit body")),
        "{label}: the supported recall body is not retained in a canonical message"
    );
    drop(db);

    // 10-AC2: the raw mirror holds the exact original bytes for both inputs.
    let blobs = mirror_blobs(fixture);
    assert_eq!(
        blobs.len(),
        2,
        "{label}: one sealed blob per input: {blobs:?}"
    );
    for (original_path, bytes) in &blobs {
        let expected = if original_path == &world.claude_path.to_string_lossy() {
            &world.claude_bytes
        } else if original_path == &world.codex_path.to_string_lossy() {
            &world.codex_bytes
        } else {
            panic!("{label}: unexpected mirror original path {original_path}");
        };
        assert_eq!(
            bytes, expected,
            "{label}: the raw mirror keeps the original bytes of {original_path}"
        );
    }
    // The live files were never rewritten either.
    assert_eq!(
        std::fs::read(&world.claude_path).expect("re-read the claude session"),
        world.claude_bytes,
        "{label}: the live claude source is byte-for-byte unchanged"
    );
    assert_eq!(
        std::fs::read(&world.codex_path).expect("re-read the codex rollout"),
        world.codex_bytes,
        "{label}: the live codex source is byte-for-byte unchanged"
    );
}

fn write_evidence(case: &CaseDir, argv: &[&str], envs: &[(&str, &str)], output: &Output) {
    case.write_json(
        "run.json",
        &json!({
            "argv": argv,
            "env_keys": envs.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            "rc": output.status.code(),
        }),
    );
    case.write("stdout.log", &output.stdout);
    case.write("stderr.log", &output.stderr);
}

fn run_matrix(label: &str, extra: &[&str], envs: &[(&str, &str)]) {
    let fixture = Fixture::new();
    let world = build_world(&fixture);
    let case = CaseDir::new("mcp_activate_v2_ingest", label);

    let mut argv: Vec<&str> = vec!["index", "--data-dir"];
    let data_dir = fixture.data_dir();
    let data_dir_text = data_dir.to_string_lossy().into_owned();
    argv.push(&data_dir_text);
    argv.extend_from_slice(extra);
    argv.push("--json");
    let output = fixture.index(extra, envs);
    write_evidence(&case, &argv, envs, &output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{label}: the index run succeeds; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value =
        serde_json::from_slice(&output.stdout).expect("the index output is one JSON object");
    assert_eq!(report["success"], json!(true), "{label}: success=true");
    assert_activation_json(&report, label);
    assert_activation_db(&fixture, &world, label);

    let digests = json!({
        "claude_sha256": sha256_hex(&world.claude_bytes),
        "codex_sha256": sha256_hex(&world.codex_bytes),
        "report": report,
    });
    case.write_json("expected-activation.json", &digests);
}

// ---------------------------------------------------------------------------
// 10-AC3 transport matrix
// ---------------------------------------------------------------------------

#[test]
fn mcp_activate_v2_streaming_default() {
    run_matrix("streaming-default", &[], &[]);
}

#[test]
fn mcp_activate_v2_batch() {
    run_matrix("batch", &[], &[("CASS_STREAMING_INDEX", "0")]);
}

#[test]
fn mcp_activate_v2_force_rebuild() {
    run_matrix("force-rebuild", &["--force-rebuild"], &[]);
}

#[test]
fn mcp_activate_v2_watch_once() {
    // The two explicit paths are supplied by the caller; this test builds its
    // own fixture so the paths exist before the CLI runs.
    let fixture = Fixture::new();
    let world = build_world(&fixture);
    let case = CaseDir::new("mcp_activate_v2_ingest", "watch-once");
    let data_dir_text = fixture.data_dir().to_string_lossy().into_owned();
    let claude_text = world.claude_path.to_string_lossy().into_owned();
    let codex_text = world.codex_path.to_string_lossy().into_owned();
    let extra = [
        "--watch-once",
        claude_text.as_str(),
        "--watch-once",
        codex_text.as_str(),
    ];
    let argv = [
        "index",
        "--data-dir",
        data_dir_text.as_str(),
        "--watch-once",
        claude_text.as_str(),
        "--watch-once",
        codex_text.as_str(),
        "--json",
    ];
    let output = fixture.index(&extra, &[]);
    write_evidence(&case, &argv, &[], &output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "watch-once: the index run succeeds; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("the index output is one JSON object");
    assert_eq!(report["success"], json!(true), "watch-once: success=true");
    assert_activation_json(&report, "watch-once");
    assert_activation_db(&fixture, &world, "watch-once");
}

// ---------------------------------------------------------------------------
// Task18a: native full-name calls without captured arguments
// Task18e: native bare-name calls without captured arguments
// ---------------------------------------------------------------------------

const NATIVE_MARKER_IDS: [&str; 18] = [
    "toolu_t18a_n_search",
    "toolu_t18a_n_expand",
    "toolu_t18a_n_sessions",
    "toolu_t18a_n_timeline",
    "toolu_t18a_c_search",
    "toolu_t18a_bare_missing",
    "toolu_t18e_bare_expand",
    "toolu_t18e_bare_sessions",
    "toolu_t18e_bare_timeline",
    "call_t18a_n_search",
    "call_t18a_n_expand",
    "call_t18a_n_sessions",
    "call_t18a_n_timeline",
    "call_t18a_c_search",
    "call_t18a_bare_missing",
    "call_t18e_bare_expand",
    "call_t18e_bare_sessions",
    "call_t18e_bare_timeline",
];

/// Every stored marker, decoded with SQLite's own `json()` (`messages.excluded`
/// is JSONB). The stored format is not touched.
fn marker_json(db: &Conn) -> Vec<Value> {
    let rows: Vec<String> = db
        .query_all_map(
            "SELECT json(excluded) FROM messages WHERE excluded IS NOT NULL ORDER BY id",
            &[],
            |row| row.get_typed::<String>(0),
        )
        .expect("query the marker JSON");
    rows.into_iter()
        .map(|text| serde_json::from_str(&text).expect("a marker is JSON"))
        .collect()
}

/// The literal uncovered matrix of this case: two ordinary same-named tools
/// (`ambiguous_tool_identity`) and two unpaired envelopes
/// (`unpaired_result`). Under Task18e the two bare names without captured
/// arguments are positive cases, so they are measured as markers instead.
/// Neither other-server control adds a count, with or without captured args:
/// an unknown identity goes back through the legacy judgment before any
/// argument gate. The C07 control has no Cass evidence and adds nothing.
fn assert_native_activation_json(report: &Value, label: &str) {
    assert_eq!(
        report["recall_uncovered_total"].as_u64(),
        Some(4),
        "{label}: four literal preservation controls are counted: {report}"
    );
    assert_eq!(
        report["recall_uncovered_by_reason"],
        json!({"ambiguous_tool_identity": 2, "unpaired_result": 2}),
        "{label}: the two conservative reasons only"
    );
    let stats = &report["indexing_stats"];
    assert_eq!(
        stats["recall_uncovered_total"],
        report["recall_uncovered_total"]
    );
    assert_eq!(
        stats["recall_uncovered_by_reason"],
        report["recall_uncovered_by_reason"]
    );
}

fn assert_native_activation_db(fixture: &Fixture, world: &NativeWorld, label: &str) {
    let db = fixture.open_db();

    let mut by_id = std::collections::BTreeMap::new();
    for marker in marker_json(&db) {
        let id = marker["anchor"]["tool_call_id"]
            .as_str()
            .unwrap_or_else(|| panic!("{label}: marker without a call id: {marker}"))
            .to_string();
        assert!(
            by_id.insert(id.clone(), marker).is_none(),
            "{label}: one marker per call id ({id})"
        );
    }
    assert_eq!(
        by_id.len(),
        18,
        "{label}: eighteen supported results are excluded: {:?}",
        by_id.keys().collect::<Vec<_>>()
    );
    for id in NATIVE_MARKER_IDS {
        assert!(by_id.contains_key(id), "{label}: missing marker for {id}");
    }
    for marker in by_id.values() {
        assert_eq!(
            marker["rule_version"].as_u64(),
            Some(2),
            "{label}: every marker is rule version 2: {marker}"
        );
        assert!(
            marker["parse_error"].is_null(),
            "{label}: a valid envelope carries no parse error: {marker}"
        );
    }
    for (id, body) in &world.excluded_bodies {
        let marker = by_id
            .get(*id)
            .unwrap_or_else(|| panic!("{label}: no marker for {id}"));
        assert_eq!(
            marker["bytes"].as_u64(),
            Some(body.len() as u64),
            "{label}: {id} keeps the complete original body byte count"
        );
        assert_eq!(
            marker["sha256"].as_str(),
            Some(sha256_hex(body.as_bytes()).as_str()),
            "{label}: {id} keeps the complete original body hash"
        );
    }

    // Source extraction still comes from the result payload alone. The bare
    // rows carry no captured arguments at all, so their sources prove that the
    // envelope alone is enough.
    for id in [
        "toolu_t18a_n_search",
        "call_t18a_n_search",
        "toolu_t18a_bare_missing",
        "call_t18a_bare_missing",
    ] {
        assert_eq!(
            by_id[id]["src"]["hits"][0]["source_path"],
            json!("/synthetic/t18a/hit.jsonl"),
            "{label}: the search source is read from the envelope ({id})"
        );
    }
    for id in ["toolu_t18a_n_sessions", "toolu_t18e_bare_sessions"] {
        assert_eq!(
            by_id[id]["src"]["sessions"],
            json!(["/synthetic/t18a/list.jsonl"]),
            "{label}: sessions source ({id})"
        );
    }
    for id in ["toolu_t18a_n_timeline", "toolu_t18e_bare_timeline"] {
        assert_eq!(
            by_id[id]["src"]["sessions"],
            json!(["/synthetic/t18a/t.jsonl"]),
            "{label}: timeline source ({id})"
        );
    }
    for id in [
        "toolu_t18a_n_expand",
        "call_t18a_n_expand",
        "toolu_t18e_bare_expand",
        "call_t18e_bare_expand",
    ] {
        assert_eq!(
            by_id[id]["src"]["sessions"],
            json!([]),
            "{label}: an expand without arguments fabricates no source ({id})"
        );
    }

    let by_agent: Vec<(String, i64)> = db
        .query_all_map(
            "SELECT a.slug, COUNT(*) FROM messages m
             JOIN conversations c ON c.id = m.conversation_id
             JOIN agents a ON a.id = c.agent_id
             WHERE m.excluded IS NOT NULL GROUP BY a.slug ORDER BY a.slug",
            &[],
            |row| Ok((row.get_typed::<String>(0)?, row.get_typed::<i64>(1)?)),
        )
        .expect("query the per-agent markers");
    assert_eq!(
        by_agent.len(),
        2,
        "{label}: both agents carry exclusions: {by_agent:?}"
    );
    for (agent, count) in &by_agent {
        assert_eq!(
            *count, 9,
            "{label}: nine exclusions for {agent}: {by_agent:?}"
        );
    }

    let bodies = message_contents(&db);
    for (id, body) in &world.excluded_bodies {
        assert!(
            !bodies.iter().any(|retained| retained == body),
            "{label}: the excluded body of {id} is not retained"
        );
    }
    assert_excluded_rows_clean(
        &db,
        &[
            NATIVE_CLAUDE_SEARCH_BODY,
            NATIVE_CODEX_SEARCH_BODY,
            NATIVE_CLAUDE_CONTROL_BODY,
            NATIVE_CODEX_CONTROL_BODY,
            NATIVE_CLAUDE_BARE_BODY,
            NATIVE_CODEX_BARE_BODY,
            "t18a expand before",
            "t18a expand target",
            "/synthetic/t18a/list.jsonl",
            "/synthetic/t18a/t.jsonl",
        ],
        label,
    );
    for text in [
        NATIVE_CLAUDE_PROSE,
        NATIVE_CODEX_PROSE,
        NATIVE_ORDINARY_OUTPUT,
        NATIVE_C07_MISSING_OUTPUT,
        NATIVE_CLAUDE_OTHER_MISSING_OUTPUT,
        NATIVE_CODEX_OTHER_MISSING_OUTPUT,
    ] {
        assert!(
            bodies.iter().any(|body| body == text),
            "{label}: {text} stays"
        );
    }
    for (id, text) in [
        (
            "other server",
            wrapper(
                RecallTool::Search,
                &native_search_value(NATIVE_OTHER_SERVER_BODY),
            ),
        ),
        (
            "unpaired",
            wrapper(
                RecallTool::Search,
                &native_search_value(NATIVE_UNPAIRED_BODY),
            ),
        ),
    ] {
        assert!(
            bodies.iter().any(|body| body == &text),
            "{label}: the {id} control keeps its body"
        );
    }
    drop(db);

    let blobs = mirror_blobs(fixture);
    assert_eq!(
        blobs.len(),
        2,
        "{label}: one sealed blob per input: {blobs:?}"
    );
    for (original_path, bytes) in &blobs {
        let expected = if original_path == &world.claude_path.to_string_lossy() {
            &world.claude_bytes
        } else if original_path == &world.codex_path.to_string_lossy() {
            &world.codex_bytes
        } else {
            panic!("{label}: unexpected mirror original path {original_path}");
        };
        assert_eq!(
            bytes, expected,
            "{label}: the raw mirror keeps the original bytes of {original_path}"
        );
    }
    assert_eq!(
        std::fs::read(&world.claude_path).expect("re-read the claude native session"),
        world.claude_bytes,
        "{label}: the live claude source is byte-for-byte unchanged"
    );
    assert_eq!(
        std::fs::read(&world.codex_path).expect("re-read the codex native rollout"),
        world.codex_bytes,
        "{label}: the live codex source is byte-for-byte unchanged"
    );
}

#[test]
fn mcp_activate_v2_native_missing_args() {
    let fixture = Fixture::new();
    let world = build_native_world(&fixture);
    let case = CaseDir::new("mcp_activate_v2_native", "missing-args-default");
    let data_dir_text = fixture.data_dir().to_string_lossy().into_owned();
    let argv = ["index", "--data-dir", data_dir_text.as_str(), "--json"];
    let output = fixture.index(&[], &[]);
    write_evidence(&case, &argv, &[], &output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "native missing args: the index run succeeds; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value =
        serde_json::from_slice(&output.stdout).expect("the index output is one JSON object");
    assert_eq!(
        report["success"],
        json!(true),
        "native missing args: success=true"
    );
    assert_native_activation_json(&report, "native-missing-args");
    assert_native_activation_db(&fixture, &world, "native-missing-args");

    case.write_json(
        "expected-activation.json",
        &json!({
            "claude_sha256": sha256_hex(&world.claude_bytes),
            "codex_sha256": sha256_hex(&world.codex_bytes),
            "report": report,
        }),
    );
}

// ---------------------------------------------------------------------------
// Plan A E2E reinforcements:
// 1. Claude object-form `toolUseResult.stdout` cleanup
// 2. Multi-line `.json` whole-document session cleanup
// 3. Resident `--watch` uncovered-recall diagnostics across Claude & Codex
// ---------------------------------------------------------------------------

#[test]
fn mcp_activate_v2_claude_object_tool_use_result_stdout() {
    let fixture = Fixture::new();
    let case = CaseDir::new("mcp_activate_v2_plan_a", "claude-object-tool-use-result");

    const HIT_BODY: &str = "t10 object toolUseResult stdout secret recall body";
    let recall_envelope = wrapper(RecallTool::Search, &native_search_value(HIT_BODY));
    let lines = vec![
        json!({
            "type": "user",
            "timestamp": "2026-01-04T00:00:00.000Z",
            "uuid": "obj-u0",
            "message": {"role": "user", "content": "t10 object toolUseResult user question"}
        }),
        json!({
            "type": "assistant",
            "timestamp": "2026-01-04T00:00:01.000Z",
            "uuid": "obj-a1",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_obj_stdout", "name": "Bash",
                 "input": {"command": "cass search \"object stdout query\" --recall"}}
            ]}
        }),
        json!({
            "type": "user",
            "timestamp": "2026-01-04T00:00:02.000Z",
            "uuid": "obj-u2",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_obj_stdout", "content": recall_envelope}
            ]},
            "toolUseResult": {
                "stdout": recall_envelope,
                "stderr": "",
                "interrupted": false,
                "isImage": false
            }
        }),
        json!({
            "type": "assistant",
            "timestamp": "2026-01-04T00:00:03.000Z",
            "uuid": "obj-a3",
            "message": {"role": "assistant", "content": "t10 object toolUseResult answer"}
        }),
    ];
    let body = jsonl(&lines);
    let path = fixture
        .home()
        .join(".claude/projects/t10-obj/session.jsonl");
    std::fs::create_dir_all(path.parent().expect("claude obj parent")).expect("mkdir");
    std::fs::write(&path, body.as_bytes()).expect("write session");

    let output = fixture.index(&[], &[]);
    write_evidence(&case, &["index", "--json"], &[], &output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "object toolUseResult index failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("index json");
    assert_eq!(report["success"], json!(true));
    assert_eq!(report["recall_uncovered_total"], json!(0));

    let db = fixture.open_db();
    assert_eq!(marker_rule_versions(&db), vec![2]);
    assert_excluded_rows_clean(&db, &[HIT_BODY], "claude-object-tool-use-result");

    let extra_rows: Vec<(Option<String>, Option<Vec<u8>>)> = db
        .query_all_map(
            "SELECT extra_json, extra_bin FROM messages WHERE excluded IS NOT NULL",
            &[],
            |row| {
                Ok((
                    row.get_typed::<Option<String>>(0)?,
                    row.get_typed::<Option<Vec<u8>>>(1)?,
                ))
            },
        )
        .expect("query excluded extra");
    assert_eq!(extra_rows.len(), 1);
    let extra = decode_extra(extra_rows[0].0.clone(), extra_rows[0].1.clone());
    let tool_use_result = extra
        .get("toolUseResult")
        .expect("toolUseResult object preserved with sibling metadata");
    assert_eq!(
        tool_use_result["stdout"]["redacted"],
        json!(true),
        "toolUseResult.stdout recall payload must be replaced by redacted tombstone: {tool_use_result}"
    );
    assert!(
        tool_use_result["stdout"]["sha256"].is_string()
            && tool_use_result["stdout"]["bytes"].is_u64(),
        "toolUseResult.stdout tombstone must carry sha256 and bytes: {tool_use_result}"
    );
    assert_eq!(tool_use_result["interrupted"], json!(false));
    assert_eq!(tool_use_result["isImage"], json!(false));
    drop(db);

    let blobs = mirror_blobs(&fixture);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].1, body.as_bytes());
    assert_eq!(std::fs::read(&path).expect("re-read"), body.as_bytes());
}

#[test]
fn mcp_activate_v2_multiline_json_document_session() {
    let fixture = Fixture::new();
    let case = CaseDir::new("mcp_activate_v2_plan_a", "multiline-json-document");

    const DOC_PROSE: &str = "t10 multiline json document user prose stays";
    const DOC_ANSWER: &str = "t10 multiline json document assistant answer stays";
    const DOC_HIT_BODY: &str = "t10 multiline json document recall hit body must be stripped";
    let recall_envelope = wrapper(RecallTool::Search, &native_search_value(DOC_HIT_BODY));
    let doc = json!({
        "title": "Multiline JSON Document Session",
        "messages": [
            {
                "role": "user",
                "timestamp": "2026-01-05T00:00:00.000Z",
                "content": DOC_PROSE
            },
            {
                "role": "assistant",
                "timestamp": "2026-01-05T00:00:01.000Z",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_doc_search",
                        "name": "mcp__cass-mcp__cass_search",
                        "input": {"query": "multiline json query"}
                    }
                ]
            },
            {
                "role": "tool_result",
                "timestamp": "2026-01-05T00:00:02.000Z",
                "tool_use_id": "toolu_doc_search",
                "content": recall_envelope
            },
            {
                "role": "assistant",
                "timestamp": "2026-01-05T00:00:03.000Z",
                "content": DOC_ANSWER
            }
        ]
    });
    let pretty = serde_json::to_string_pretty(&doc).expect("pretty json") + "\n";
    assert!(
        pretty.lines().count() > 10,
        "fixture must genuinely be a multi-line whole-document JSON file"
    );
    let path = fixture.home().join(".claude/projects/t10-doc/session.json");
    std::fs::create_dir_all(path.parent().expect("claude doc parent")).expect("mkdir");
    std::fs::write(&path, pretty.as_bytes()).expect("write multiline json");

    let output = fixture.index(&[], &[]);
    write_evidence(&case, &["index", "--json"], &[], &output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "multiline json index failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("index json");
    assert_eq!(report["success"], json!(true));
    assert_eq!(report["recall_uncovered_total"], json!(0));

    let db = fixture.open_db();
    assert_eq!(marker_rule_versions(&db), vec![2]);
    assert_excluded_rows_clean(&db, &[DOC_HIT_BODY], "multiline-json-document");
    let bodies = message_contents(&db);
    assert!(bodies.iter().any(|b| b == DOC_PROSE));
    assert!(bodies.iter().any(|b| b == DOC_ANSWER));
    assert!(!bodies.iter().any(|b| b.contains(DOC_HIT_BODY)));
    drop(db);

    let blobs = mirror_blobs(&fixture);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].1, pretty.as_bytes());
    assert_eq!(std::fs::read(&path).expect("re-read"), pretty.as_bytes());
}

#[cfg(target_os = "linux")]
#[test]
fn mcp_activate_v2_resident_watch_reports_uncovered() {
    use std::fs::File;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Stdio};
    use std::time::Instant;

    struct ResidentGuard {
        child: Option<Child>,
        pid: u32,
    }
    impl ResidentGuard {
        fn stop_and_assert_clean(&mut self) {
            if let Some(mut child) = self.child.take() {
                if child.try_wait().expect("try_wait").is_none() {
                    let status = Command::new("/usr/bin/kill")
                        .args(["-INT", &self.pid.to_string()])
                        .status()
                        .expect("send SIGINT");
                    assert!(status.success(), "SIGINT to resident watcher failed");
                }
                let status = child.wait().expect("wait watcher");
                assert_eq!(status.signal(), Some(2), "watcher should exit on SIGINT");
                assert!(
                    !std::path::Path::new(&format!("/proc/{}", self.pid)).exists(),
                    "watcher process must be absent after SIGINT"
                );
            }
        }
    }
    impl Drop for ResidentGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let fixture = Fixture::new();
    let case = CaseDir::new("mcp_activate_v2_plan_a", "resident-watch-uncovered");
    std::fs::create_dir_all(fixture.home().join(".claude/projects/t10")).expect("mkdir claude");
    std::fs::create_dir_all(fixture.home().join(".codex/sessions/2026/01")).expect("mkdir codex");

    let stdout_path = fixture.root.path().join("watch.stdout");
    let stderr_path = fixture.root.path().join("watch.stderr");
    let mut cmd = Command::new(cass_bin());
    fixture.isolate(&mut cmd);
    cmd.env("CASS_ACTIVE_SESSION_RECENT_WRITE_WINDOW_SECS", "0")
    .args([
        "-v",
        "index",
        "--watch",
        "--watch-interval",
        "1",
        "--data-dir",
    ])
    .arg(fixture.data_dir())
    .args(["--json", "--robot-trace-ingest"])
    .stdout(Stdio::from(File::create(&stdout_path).expect("stdout")))
    .stderr(Stdio::from(File::create(&stderr_path).expect("stderr")));

    let child = cmd.spawn().expect("spawn resident cass index --watch");
    let pid = child.id();
    let mut guard = ResidentGuard {
        child: Some(child),
        pid,
    };

    let read_log = || std::fs::read_to_string(&stderr_path).unwrap_or_default();

    // Wait for watch loop to register filesystem watchers.
    let start_deadline = Instant::now() + Duration::from_secs(60);
    while !read_log().contains("watching ") {
        assert!(
            guard.child.as_mut().unwrap().try_wait().unwrap().is_none(),
            "resident watcher exited before ready; log={}",
            read_log()
        );
        assert!(
            Instant::now() < start_deadline,
            "timed out waiting for resident watcher ready; log={}",
            read_log()
        );
        std::thread::sleep(Duration::from_millis(40));
    }

    // Write the full synthetic two-agent world (6 supported recalls + 5 uncovered across 4 reasons).
    let world = build_world(&fixture);

    // Wait until both agents' sessions have landed with all 6 rule_version=2 exclusion markers
    // AND both per-session scan_session traces are emitted.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut claude_traces: Vec<String>;
    let mut codex_traces: Vec<String>;
    loop {
        assert!(
            guard.child.as_mut().unwrap().try_wait().unwrap().is_none(),
            "resident watcher exited unexpectedly; log={}",
            read_log()
        );
        let db_ready = Conn::open_read_with(
            &fixture.db(),
            OpenOptions {
                busy_timeout: Duration::from_secs(5),
            },
        )
        .ok()
        .and_then(|db| {
            db.query_row_map(
                "SELECT COUNT(*) FROM messages WHERE excluded IS NOT NULL",
                &[],
                |row| row.get_typed::<i64>(0),
            )
            .ok()
        })
        == Some(6);
        let log = read_log();
        claude_traces = log
            .lines()
            .filter(|l| l.contains("scan_session") && l.contains("agent=claude_code"))
            .map(str::to_owned)
            .collect();
        codex_traces = log
            .lines()
            .filter(|l| l.contains("scan_session") && l.contains("agent=codex"))
            .map(str::to_owned)
            .collect();
        if db_ready && !claude_traces.is_empty() && !codex_traces.is_empty() {
            // Also wait briefly for the trailing idle progress line (phase_code=0).
            let has_idle_with_uncovered = log
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .any(|ev| {
                    ev["phase_code"] == 0
                        && ev["recall_uncovered_total"].as_u64().unwrap_or(0) > 0
                });
            if has_idle_with_uncovered {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for resident watch ingest + traces; claude={claude_traces:?} codex={codex_traces:?}\nlog={log}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let log = read_log();
    case.write("watch.stderr", log.as_bytes());
    guard.stop_and_assert_clean();

    // Verify DB + decoded extra + raw mirror integrity.
    assert_activation_db(&fixture, &world, "resident-watch-uncovered");

    // Verify per-agent scan_session trace lines report exact Plan A uncovered counts
    // totaling 5 across all 4 fixed reasons.
    let last_claude = claude_traces.last().expect("claude scan_session trace");
    let last_codex = codex_traces.last().expect("codex scan_session trace");
    assert!(
        last_claude.contains("recall_uncovered_total=1")
            && last_claude.contains(r#"recall_uncovered_by_reason={"unsupported_shell":1}"#),
        "claude resident trace mismatch: {last_claude}"
    );
    assert!(
        last_codex.contains("recall_uncovered_total=4")
            && last_codex.contains(
                r#"recall_uncovered_by_reason={"ambiguous_tool_identity":1,"invalid_recall_format":1,"unpaired_result":1,"unsupported_shell":1}"#
            ),
        "codex resident trace mismatch: {last_codex}"
    );

    // Verify live JSON progress idle events carry the uncovered reasons (across 1 or 2 cycles).
    let mut observed_reasons: BTreeMap<String, u64> = BTreeMap::new();
    let mut last_cycle_map: Option<Value> = None;
    for ev in log
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|ev| ev["phase_code"] == 0)
    {
        let total = ev["recall_uncovered_total"].as_u64().unwrap_or(0);
        if total == 0 {
            continue;
        }
        let by_reason = &ev["recall_uncovered_by_reason"];
        if last_cycle_map.as_ref() == Some(by_reason) {
            continue;
        }
        last_cycle_map = Some(by_reason.clone());
        if let Some(obj) = by_reason.as_object() {
            for (k, v) in obj {
                *observed_reasons.entry(k.clone()).or_default() += v.as_u64().unwrap_or(0);
            }
        }
    }
    assert_eq!(
        serde_json::to_value(&observed_reasons).unwrap(),
        expected_reasons(),
        "resident idle progress events must report all 5 uncovered inputs across the 4 fixed reasons; log={log}"
    );

    // Privacy check: no source prose or query text leaks into watch logs.
    for forbidden in [SUPPORTED_QUERY, ORDINARY_PROSE, CODEX_PROSE] {
        assert!(
            !log.contains(forbidden),
            "resident watch log must not leak source text {forbidden:?}"
        );
    }
}

#[test]
fn mcp_activate_v2_multiline_json_multi_tool_string_array_and_codex_doc() {
    let fixture = Fixture::new();
    let case = CaseDir::new("mcp_activate_v2_plan_a", "multiline-json-r2-regressions");

    const ALPHA_SECRET: &str = "r2_b2_multi_tool_second_call_secret_alpha";
    const BETA_SECRET: &str = "r2_b1_string_array_extra_secret_beta";
    const GAMMA_SECRET: &str = "r2_b2_codex_top_level_tool_call_secret_gamma";

    // 1. Claude multi-line .json with parallel [Read, mcp__cass-mcp__cass_search] in one assistant turn (R2-B2A).
    let multi_doc = json!({
        "title": "Claude Parallel Tool Calls Doc",
        "messages": [
            {"role": "user", "timestamp": "2026-01-05T00:00:00.000Z", "content": "multi tool user prompt stays"},
            {
                "role": "assistant",
                "timestamp": "2026-01-05T00:00:01.000Z",
                "content": [
                    {"type": "tool_use", "id": "toolu_r2_first_read", "name": "Read", "input": {"file_path": "foo.rs"}},
                    {"type": "tool_use", "id": "toolu_r2_second_cass", "name": "mcp__cass-mcp__cass_search", "input": {"query": "alpha"}}
                ]
            },
            {"role": "tool_result", "timestamp": "2026-01-05T00:00:02.000Z", "tool_use_id": "toolu_r2_first_read", "content": "fn main() {}"},
            {"role": "tool_result", "timestamp": "2026-01-05T00:00:03.000Z", "tool_use_id": "toolu_r2_second_cass", "content": wrapper(RecallTool::Search, &native_search_value(ALPHA_SECRET))},
            {"role": "assistant", "timestamp": "2026-01-05T00:00:04.000Z", "content": "multi tool assistant answer stays"}
        ]
    });
    let multi_path = fixture.home().join(".claude/projects/r2-multi/multi_tool.json");
    std::fs::create_dir_all(multi_path.parent().unwrap()).unwrap();
    std::fs::write(&multi_path, serde_json::to_string_pretty(&multi_doc).unwrap() + "\n").unwrap();

    // 2. Claude multi-line .json with string-array tool_result `content: ["<cass_recall ...>"]` (R2-B1).
    let arr_doc = json!({
        "title": "Claude String Array Result Doc",
        "messages": [
            {"role": "user", "timestamp": "2026-01-05T00:01:00.000Z", "content": "array result user prompt stays"},
            {
                "role": "assistant",
                "timestamp": "2026-01-05T00:01:01.000Z",
                "content": [
                    {"type": "tool_use", "id": "toolu_r2_arr_cass", "name": "mcp__cass-mcp__cass_search", "input": {"query": "beta"}}
                ]
            },
            {"role": "tool_result", "timestamp": "2026-01-05T00:01:02.000Z", "tool_use_id": "toolu_r2_arr_cass", "content": [wrapper(RecallTool::Search, &native_search_value(BETA_SECRET))]},
            {"role": "assistant", "timestamp": "2026-01-05T00:01:03.000Z", "content": "array result assistant answer stays"}
        ]
    });
    let arr_path = fixture.home().join(".claude/projects/r2-arr/str_array.json");
    std::fs::create_dir_all(arr_path.parent().unwrap()).unwrap();
    std::fs::write(&arr_path, serde_json::to_string_pretty(&arr_doc).unwrap() + "\n").unwrap();

    // 3. Codex multi-line rollout-*.json with top-level `items[]` `role: "tool_call"` + `tool_result` (R2-B2B).
    let codex_doc = json!({
        "id": "codex-doc-r2",
        "items": [
            {"id": "u1", "role": "user", "content": "codex doc user prompt stays"},
            {"id": "c1", "role": "tool_call", "call_id": "call_r2_codex_doc_1", "name": "mcp__cass-mcp__cass_search", "arguments": {"query": "gamma"}, "content": "[Tool: mcp__cass-mcp__cass_search]"},
            {"id": "r1", "role": "tool_result", "call_id": "call_r2_codex_doc_1", "content": wrapper(RecallTool::Search, &native_search_value(GAMMA_SECRET))},
            {"id": "a1", "role": "assistant", "content": "codex doc assistant answer stays"}
        ]
    });
    let codex_path = fixture.home().join(".codex/sessions/2026/01/rollout-doc-r2.json");
    std::fs::create_dir_all(codex_path.parent().unwrap()).unwrap();
    std::fs::write(&codex_path, serde_json::to_string_pretty(&codex_doc).unwrap() + "\n").unwrap();

    let output = fixture.index(&[], &[]);
    write_evidence(&case, &["index", "--json"], &[], &output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "r2 json regressions index failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("index json");
    assert_eq!(report["success"], json!(true));
    assert_eq!(
        report["recall_uncovered_total"],
        json!(0),
        "all 3 whole-document recall cases must be covered: {report}"
    );

    let db = fixture.open_db();
    assert_eq!(marker_rule_versions(&db), vec![2, 2, 2]);
    assert_excluded_rows_clean(
        &db,
        &[ALPHA_SECRET, BETA_SECRET, GAMMA_SECRET],
        "multiline-json-r2-regressions",
    );
    let bodies = message_contents(&db);
    for prose in [
        "multi tool user prompt stays",
        "multi tool assistant answer stays",
        "fn main() {}",
        "array result user prompt stays",
        "array result assistant answer stays",
        "codex doc user prompt stays",
        "codex doc assistant answer stays",
    ] {
        assert!(bodies.iter().any(|b| b == prose), "missing preserved prose {prose:?}");
    }
    for secret in [ALPHA_SECRET, BETA_SECRET, GAMMA_SECRET] {
        assert!(
            !bodies.iter().any(|b| b.contains(secret)),
            "secret {secret:?} leaked into messages.content"
        );
    }
}

#[test]
fn mcp_activate_v2_r2_round2_regressions() {
    let fixture = Fixture::new();
    let case = CaseDir::new("mcp_activate_v2_plan_a", "r2-round2-regressions");

    const B2_CLI_SECRET: &str = "r2_2_b2_codex_json_stringified_cli_secret";
    const B2_AGENTS_SECRET: &str = "r2_2_b2_codex_json_stringified_agents_md_secret";
    const B3_CODEX_33M_SECRET: &str = "r2_2_b3_codex_33mb_mcp_secret";
    const B3_CLAUDE_33M_SECRET: &str = "r2_2_b3_claude_33mb_mcp_secret";
    const B4A_STDERR_STDOUT_SECRET: &str = "r2_2_b4a_bash_stdout_with_long_stderr_secret";
    const B4A_TRUNC_HEAD_SECRET: &str = "r2_2_b4a_bash_truncated_stdout_head_secret";
    const B4A_TRUNC_TAIL_SECRET: &str = "r2_2_b4a_bash_truncated_stdout_tail_secret";
    const B4B_CLAUDE_PART1_SECRET: &str = "r2_2_b4b_claude_idless_multipart_part1_secret";
    const B4B_CLAUDE_PART2_SECRET: &str = "r2_2_b4b_claude_idless_multipart_part2_secret";
    const B4B_CODEX_PART1_SECRET: &str = "r2_2_b4b_codex_idless_multipart_part1_secret";
    const B4B_CODEX_PART2_SECRET: &str = "r2_2_b4b_codex_idless_multipart_part2_secret";

    // 1. B2: Codex whole-document .json with JSON-stringified `arguments` (direct CLI recall + R2 AGENTS.md).
    let codex_str_args = json!({
        "id": "codex-b2-str-args",
        "items": [
            {"id": "u0", "role": "user", "content": "find prior recall and read AGENTS.md"},
            {
                "id": "c1",
                "role": "tool_call",
                "call_id": "call_b2_cli",
                "name": "exec_command",
                "arguments": "{\"cmd\":\"cass search \\\"alpha\\\" --recall\"}",
                "content": "exec_command"
            },
            {
                "id": "r1",
                "role": "tool_result",
                "call_id": "call_b2_cli",
                "content": wrapper(RecallTool::Search, &native_search_value(B2_CLI_SECRET))
            },
            {
                "id": "c2",
                "role": "tool_call",
                "call_id": "call_b2_read",
                "name": "project_read",
                "arguments": "{\"document\":\"memory\"}",
                "content": "project_read"
            },
            {
                "id": "r2",
                "role": "tool_result",
                "call_id": "call_b2_read",
                "content": B2_AGENTS_SECRET
            }
        ]
    });
    let codex_b2_path = fixture.home().join(".codex/sessions/2026/06/01/rollout-b2-str-args.json");
    std::fs::create_dir_all(codex_b2_path.parent().unwrap()).unwrap();
    std::fs::write(&codex_b2_path, serde_json::to_string_pretty(&codex_str_args).unwrap() + "\n").unwrap();

    // 2. B3: >= 32 MiB whole-document Codex & Claude .json triggering `compact_message_extra`.
    let big_padding = "P".repeat(33 * 1024 * 1024);
    let codex_big = json!({
        "id": "codex-b3-33mb",
        "items": [
            {"id": "u0", "role": "user", "content": big_padding},
            {
                "id": "c1",
                "role": "tool_call",
                "call_id": "call_b3_codex_mcp",
                "name": "mcp__cass-mcp__cass_search",
                "input": {"query": "big-codex"},
                "content": "mcp__cass-mcp__cass_search"
            },
            {
                "id": "r1",
                "role": "tool_result",
                "call_id": "call_b3_codex_mcp",
                "content": wrapper(RecallTool::Search, &native_search_value(B3_CODEX_33M_SECRET))
            }
        ]
    });
    let codex_b3_path = fixture.home().join(".codex/sessions/2026/06/02/rollout-b3-big.json");
    std::fs::create_dir_all(codex_b3_path.parent().unwrap()).unwrap();
    std::fs::write(&codex_b3_path, serde_json::to_string(&codex_big).unwrap()).unwrap();

    let claude_big = json!({
        "title": "Claude 33 MiB Whole Doc",
        "messages": [
            {"role": "user", "timestamp": "2026-01-06T00:00:00.000Z", "content": big_padding},
            {
                "role": "assistant",
                "timestamp": "2026-01-06T00:00:01.000Z",
                "content": [
                    {"type": "tool_use", "id": "toolu_b3_read", "name": "Read", "input": {"file_path": "/synthetic/a.txt"}},
                    {"type": "tool_use", "id": "toolu_b3_mcp", "name": "mcp__cass-mcp__cass_search", "input": {"query": "big-claude"}}
                ]
            },
            {"role": "tool_result", "timestamp": "2026-01-06T00:00:02.000Z", "tool_use_id": "toolu_b3_read", "content": "normal file body stays"},
            {"role": "tool_result", "timestamp": "2026-01-06T00:00:03.000Z", "tool_use_id": "toolu_b3_mcp", "content": wrapper(RecallTool::Search, &native_search_value(B3_CLAUDE_33M_SECRET))}
        ]
    });
    let claude_b3_path = fixture.home().join(".claude/projects/r2-b3/big-claude.json");
    std::fs::create_dir_all(claude_b3_path.parent().unwrap()).unwrap();
    std::fs::write(&claude_b3_path, serde_json::to_string(&claude_big).unwrap()).unwrap();

    // 3. B4a: Claude Bash object `toolUseResult.stdout` with (i) >1024B stderr, and (ii) 35 KB truncated stdout.
    let short_stdout = wrapper(RecallTool::Search, &native_search_value(B4A_STDERR_STDOUT_SECRET));
    let long_stderr = format!("WARN_LONG_STDERR_{}", "E".repeat(2500));
    let combined_content = format!("{short_stdout}\n{long_stderr}");
    let bash_stderr_jsonl = [
        json!({
            "type": "user", "uuid": "b4a1-u0", "sessionId": "sid-b4a1", "timestamp": "2026-01-06T01:00:00.000Z",
            "message": {"role": "user", "content": [{"type": "text", "text": "run cass search with noisy stderr"}]}
        }),
        json!({
            "type": "assistant", "uuid": "b4a1-a1", "sessionId": "sid-b4a1", "timestamp": "2026-01-06T01:00:01.000Z",
            "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_b4a1", "name": "Bash", "input": {"command": "cass search \"alpha\" --recall"}}]}
        }),
        json!({
            "type": "user", "uuid": "b4a1-r2", "sessionId": "sid-b4a1", "timestamp": "2026-01-06T01:00:02.000Z",
            "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_b4a1", "content": combined_content}]},
            "toolUseResult": {"stdout": short_stdout, "stderr": long_stderr, "interrupted": false, "isImage": false}
        }),
    ]
    .iter()
    .map(Value::to_string)
    .collect::<Vec<_>>()
    .join("\n")
        + "\n";
    let b4a1_path = fixture.home().join(".claude/projects/r2-b4a/bash-long-stderr.jsonl");
    std::fs::create_dir_all(b4a1_path.parent().unwrap()).unwrap();
    std::fs::write(&b4a1_path, bash_stderr_jsonl).unwrap();

    let huge_stdout = format!(
        "<cass_recall version=\"1\" tool=\"cass_search\">{{\"hits\":[{{\"snippet\":\"{B4A_TRUNC_HEAD_SECRET}_{}_{B4A_TRUNC_TAIL_SECRET}\"}}]}}</cass_recall>",
        "Z".repeat(34_000)
    );
    let truncated_content = format!("{}... [34500 chars total, truncated]", &huge_stdout[..30_000]);
    let bash_trunc_jsonl = [
        json!({
            "type": "user", "uuid": "b4a2-u0", "sessionId": "sid-b4a2", "timestamp": "2026-01-06T01:01:00.000Z",
            "message": {"role": "user", "content": [{"type": "text", "text": "run cass search with truncated stdout"}]}
        }),
        json!({
            "type": "assistant", "uuid": "b4a2-a1", "sessionId": "sid-b4a2", "timestamp": "2026-01-06T01:01:01.000Z",
            "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_b4a2", "name": "Bash", "input": {"command": "cass search \"beta\" --recall"}}]}
        }),
        json!({
            "type": "user", "uuid": "b4a2-r2", "sessionId": "sid-b4a2", "timestamp": "2026-01-06T01:01:02.000Z",
            "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_b4a2", "content": truncated_content}]},
            "toolUseResult": {"stdout": huge_stdout, "stderr": "", "interrupted": false, "isImage": false}
        }),
    ]
    .iter()
    .map(Value::to_string)
    .collect::<Vec<_>>()
    .join("\n")
        + "\n";
    let b4a2_path = fixture.home().join(".claude/projects/r2-b4a/bash-truncated-stdout.jsonl");
    std::fs::write(&b4a2_path, bash_trunc_jsonl).unwrap();

    // 4. B4b: Whole-document .json ID-less multi-part array tool_result (Claude + Codex).
    let claude_idless_multi = json!({
        "title": "Claude ID-less Multipart Result",
        "messages": [
            {"role": "user", "timestamp": "2026-01-06T02:00:00.000Z", "content": "idless claude prompt stays"},
            {
                "role": "assistant",
                "timestamp": "2026-01-06T02:00:01.000Z",
                "content": [{"type": "tool_use", "name": "mcp__cass-mcp__cass_search", "input": {"query": "idless-claude"}}]
            },
            {
                "role": "tool_result",
                "timestamp": "2026-01-06T02:00:02.000Z",
                "content": [
                    {"type": "text", "text": wrapper(RecallTool::Search, &native_search_value(B4B_CLAUDE_PART1_SECRET))},
                    {"type": "text", "text": format!("summary tail {B4B_CLAUDE_PART2_SECRET}")}
                ]
            }
        ]
    });
    let claude_b4b_path = fixture.home().join(".claude/projects/r2-b4b/idless-multipart.json");
    std::fs::create_dir_all(claude_b4b_path.parent().unwrap()).unwrap();
    std::fs::write(&claude_b4b_path, serde_json::to_string_pretty(&claude_idless_multi).unwrap() + "\n").unwrap();

    let codex_idless_multi = json!({
        "id": "codex-b4b-idless-multi",
        "items": [
            {"id": "u0", "role": "user", "content": "idless codex prompt stays"},
            {
                "id": "c1",
                "role": "tool_call",
                "name": "mcp__cass-mcp__cass_search",
                "arguments": "{\"query\":\"idless-codex\"}",
                "content": "mcp__cass-mcp__cass_search"
            },
            {
                "id": "r1",
                "role": "tool_result",
                "content": [
                    {"type": "text", "text": wrapper(RecallTool::Search, &native_search_value(B4B_CODEX_PART1_SECRET))},
                    {"type": "text", "text": format!("summary tail {B4B_CODEX_PART2_SECRET}")}
                ]
            }
        ]
    });
    let codex_b4b_path = fixture.home().join(".codex/sessions/2026/06/03/rollout-b4b-idless-multi.json");
    std::fs::create_dir_all(codex_b4b_path.parent().unwrap()).unwrap();
    std::fs::write(&codex_b4b_path, serde_json::to_string_pretty(&codex_idless_multi).unwrap() + "\n").unwrap();

    // 5. NB1: Claude Desktop sidecars under claude-code-sessions & local-agent-mode-sessions (model-only).
    let sidecar1 = fixture.home().join("Library/Application Support/Claude/claude-code-sessions/s1.json");
    std::fs::create_dir_all(sidecar1.parent().unwrap()).unwrap();
    std::fs::write(&sidecar1, json!({"title": "Desktop Sidecar 1", "cwd": "/synthetic/ws"}).to_string()).unwrap();
    let sidecar2 = fixture.home().join("Library/Application Support/Claude/local-agent-mode-sessions/s2.json");
    std::fs::create_dir_all(sidecar2.parent().unwrap()).unwrap();
    std::fs::write(&sidecar2, json!({"model": "claude-sonnet-4-5"}).to_string()).unwrap();

    let output = fixture.index(&[], &[]);
    write_evidence(&case, &["index", "--json"], &[], &output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "r2-round2 index failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("index json");
    assert_eq!(report["success"], json!(true));
    assert_eq!(report["recall_uncovered_total"], json!(0), "report={report}");
    assert_eq!(
        report["indexing_stats"]["event_align_failed"],
        json!(0),
        "desktop sidecars and whole-doc json must align with 0 failures: {report}"
    );

    let db = fixture.open_db();
    // 8 excluded messages total: B2(2) + B3(2) + B4a(2) + B4b(2).
    assert_eq!(marker_rule_versions(&db).len(), 8, "expected all 8 excluded rows");
    let all_secrets = [
        B2_CLI_SECRET,
        B2_AGENTS_SECRET,
        B3_CODEX_33M_SECRET,
        B3_CLAUDE_33M_SECRET,
        B4A_STDERR_STDOUT_SECRET,
        B4A_TRUNC_HEAD_SECRET,
        B4A_TRUNC_TAIL_SECRET,
        B4B_CLAUDE_PART1_SECRET,
        B4B_CLAUDE_PART2_SECRET,
        B4B_CODEX_PART1_SECRET,
        B4B_CODEX_PART2_SECRET,
    ];
    assert_excluded_rows_clean(&db, &all_secrets, "r2-round2-regressions");
    let bodies = message_contents(&db);
    for secret in all_secrets {
        assert!(
            !bodies.iter().any(|b| b.contains(secret)),
            "secret {secret:?} leaked into messages.content"
        );
    }
    assert!(
        bodies.iter().any(|b| b == "normal file body stays"),
        "non-recall sibling Read tool_result in 33 MiB Claude doc must remain preserved"
    );
}

#[test]
fn mcp_activate_v2_r2_round3_regressions() {
    let fixture = Fixture::new();
    let case = CaseDir::new("mcp_activate_v2_plan_a", "r2-round3-regressions");

    const B1_RECALL_SECRET: &str = "r2_3_b1_assistant_call_id_recall_secret";
    const B1_AGENTS_SECRET: &str = "r2_3_b1_assistant_string_arguments_agents_secret";
    const B2_MSG_SIBLING_SECRET: &str = "r2_3_b2_sibling_message_key_extra_bin_secret";
    const B2_PAYLOAD_NULL_SECRET: &str = "r2_3_b2_sibling_payload_null_extra_bin_secret";

    // 1. B1: Whole-document Codex .json `assistant` turn carrying OpenAI-style
    //    `call_id` + `arguments` inside `tool_use` content blocks.
    let codex_assistant_doc = json!({
        "id": "codex-r2-3-b1",
        "items": [
            {"id": "u0", "role": "user", "content": "check previous fixes and read AGENTS.md"},
            {
                "id": "a1",
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "call_id": "call_r2_3_recall_1",
                        "name": "mcp__cass-mcp__cass_search",
                        "arguments": "{\"query\":\"r2-3\"}"
                    },
                    {
                        "type": "tool_use",
                        "id": "call_r2_3_agents_2",
                        "name": "exec_command",
                        "arguments": "{\"cmd\":\"cat /synthetic/ws/CLAUDE.local.md\"}"
                    }
                ]
            },
            {
                "id": "r1",
                "role": "tool_result",
                "call_id": "call_r2_3_recall_1",
                "content": wrapper(RecallTool::Search, &native_search_value(B1_RECALL_SECRET))
            },
            {
                "id": "r2",
                "role": "tool_result",
                "call_id": "call_r2_3_agents_2",
                "content": B1_AGENTS_SECRET
            }
        ]
    });
    let codex_b1_path = fixture.home().join(".codex/sessions/2026/06/04/rollout-r2-3-b1.json");
    std::fs::create_dir_all(codex_b1_path.parent().unwrap()).unwrap();
    std::fs::write(&codex_b1_path, serde_json::to_string_pretty(&codex_assistant_doc).unwrap() + "\n").unwrap();

    // 2. B2: Whole-document Claude .json `tool_result` carrying sibling `"message": "ok"`
    //    or `"payload": null` alongside top-level `"content": "<cass_recall ...>"`.
    let claude_sibling_keys_doc = json!({
        "title": "Claude Sibling Message And Payload Keys Doc",
        "messages": [
            {"role": "user", "timestamp": "2026-01-09T00:00:00.000Z", "content": "search recall twice"},
            {
                "role": "assistant",
                "timestamp": "2026-01-09T00:00:01.000Z",
                "content": [
                    {"type": "tool_use", "call_id": "tc_b2_msg", "name": "mcp__cass-mcp__cass_search", "input": {"query": "msg"}},
                    {"type": "tool_use", "call_id": "tc_b2_pay", "name": "mcp__cass-mcp__cass_search", "input": {"query": "pay"}}
                ]
            },
            {
                "role": "tool_result",
                "timestamp": "2026-01-09T00:00:02.000Z",
                "tool_call_id": "tc_b2_msg",
                "message": "ok",
                "content": wrapper(RecallTool::Search, &native_search_value(B2_MSG_SIBLING_SECRET))
            },
            {
                "role": "tool_result",
                "timestamp": "2026-01-09T00:00:03.000Z",
                "tool_call_id": "tc_b2_pay",
                "payload": null,
                "content": wrapper(RecallTool::Search, &native_search_value(B2_PAYLOAD_NULL_SECRET))
            }
        ]
    });
    let claude_b2_path = fixture.home().join(".claude/projects/r2-3-b2/sibling-keys.json");
    std::fs::create_dir_all(claude_b2_path.parent().unwrap()).unwrap();
    std::fs::write(&claude_b2_path, serde_json::to_string_pretty(&claude_sibling_keys_doc).unwrap() + "\n").unwrap();

    let output = fixture.index(&[], &[]);
    write_evidence(&case, &["index", "--json"], &[], &output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "r2-round3 index failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("index json");
    assert_eq!(report["success"], json!(true));
    assert_eq!(report["recall_uncovered_total"], json!(0), "report={report}");
    assert_eq!(report["indexing_stats"]["event_align_failed"], json!(0), "report={report}");

    let db = fixture.open_db();
    assert_eq!(marker_rule_versions(&db).len(), 4, "all 4 B1/B2 tool results must be excluded");
    let secrets = [
        B1_RECALL_SECRET,
        B1_AGENTS_SECRET,
        B2_MSG_SIBLING_SECRET,
        B2_PAYLOAD_NULL_SECRET,
    ];
    assert_excluded_rows_clean(&db, &secrets, "r2-round3-regressions");
    let bodies = message_contents(&db);
    for secret in secrets {
        assert!(
            !bodies.iter().any(|b| b.contains(secret)),
            "secret {secret:?} leaked into messages.content"
        );
    }
}
