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

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::Duration;

use coding_agent_search::raw_mirror::manifest_views;
use coding_agent_search::recall_output::{self, RecallTool};
use coding_agent_search::storage::api::{Conn, OpenOptions};
use coding_agent_search::storage::source_facts::decode_expected_manifest_header;
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
        let root = std::env::var("CASS_MCP_T10_RESULT_ROOT")
            .expect("CASS_MCP_T10_RESULT_ROOT must be set for every Task10 run");
        let path = PathBuf::from(root);
        assert!(
            !path.exists(),
            "CASS_MCP_T10_RESULT_ROOT must not exist before the first run: {}",
            path.display()
        );
        std::fs::create_dir_all(&path).expect("create the result root");
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
        std::fs::write(
            root.path().join("fixed-safety.toml"),
            include_bytes!("../config/excluded_context_paths.toml"),
        )
        .expect("write the fixed safety copy");
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
//
// Every value below is a literal fixture in this file. The eight missing-args
// calls (four per agent) are paired with valid C04 envelopes and omit
// `input`/`arguments` entirely. The two normal-args searches are the controls
// that prove the same shape still excludes when arguments exist. The
// preservation controls (bare name without args, ordinary same-named tool,
// another server, unpaired result, C07 without a literal) exercise the
// unchanged rules and must keep their bodies.
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

fn native_search_value(body: &str) -> Value {
    json!({"hits": [
        {"source_id": "local", "source_path": "/synthetic/t18a/hit.jsonl", "line_number": 4, "content": body},
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

    // Preservation control: a bare name without arguments keeps its result.
    let bare = wrapper(
        RecallTool::Search,
        &native_search_value(NATIVE_CLAUDE_BARE_BODY),
    );
    lines.push(json!({
        "type": "assistant", "timestamp": "2026-01-03T00:00:11.000Z", "uuid": "t18a-a-bare",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_t18a_bare_missing", "name": "cass_search"}
        ]}
    }));
    lines.push(json!({
        "type": "user", "timestamp": "2026-01-03T00:00:12.000Z", "uuid": "t18a-r-bare",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_t18a_bare_missing", "content": bare}
        ]}
    }));

    // Preservation control: an ordinary same-named tool.
    lines.push(json!({
        "type": "assistant", "timestamp": "2026-01-03T00:00:13.000Z", "uuid": "t18a-a-ordinary",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_t18a_ordinary", "name": "cass_search",
             "input": {"query": "t18a ordinary query"}}
        ]}
    }));
    lines.push(json!({
        "type": "user", "timestamp": "2026-01-03T00:00:14.000Z", "uuid": "t18a-r-ordinary",
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
        "type": "assistant", "timestamp": "2026-01-03T00:00:15.000Z", "uuid": "t18a-a-other",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_t18a_other", "name": "mcp__other-mcp__cass_search",
             "input": {"query": "t18a other server query"}}
        ]}
    }));
    lines.push(json!({
        "type": "user", "timestamp": "2026-01-03T00:00:16.000Z", "uuid": "t18a-r-other",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_t18a_other", "content": other}
        ]}
    }));

    // Preservation control: another server's tool without captured input.
    // An unknown identity must fall back to the legacy judgment before any
    // argument gate, so this row adds no v2 uncovered count.
    lines.push(json!({
        "type": "assistant", "timestamp": "2026-01-03T00:00:16.500Z", "uuid": "t18a-a-other-missing",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_t18a_other_missing", "name": "mcp__other-mcp__cass_search"}
        ]}
    }));
    lines.push(json!({
        "type": "user", "timestamp": "2026-01-03T00:00:16.750Z", "uuid": "t18a-r-other-missing",
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
        "type": "user", "timestamp": "2026-01-03T00:00:17.000Z", "uuid": "t18a-u-unpaired",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_t18a_unpaired", "content": unpaired}
        ]}
    }));
    lines.push(json!({
        "type": "assistant", "timestamp": "2026-01-03T00:00:18.000Z", "uuid": "t18a-a-end",
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

    // Preservation control: a bare name without arguments keeps its result.
    let bare = wrapper(
        RecallTool::Search,
        &native_search_value(NATIVE_CODEX_BARE_BODY),
    );
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:12.000Z",
        "type": "response_item",
        "payload": {"type": "function_call", "id": "fc-t18a-bare",
                    "name": "cass_search", "call_id": "call_t18a_bare_missing"}
    }));
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:13.000Z",
        "type": "response_item",
        "payload": {"type": "function_call_output", "call_id": "call_t18a_bare_missing", "output": bare}
    }));

    // Preservation control: an ordinary same-named tool.
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:14.000Z",
        "type": "response_item",
        "payload": {"type": "function_call", "id": "fc-t18a-ordinary",
                    "name": "cass_search", "arguments": "{\"query\":\"t18a ordinary query\"}",
                    "call_id": "call_t18a_ordinary"}
    }));
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:15.000Z",
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
        "timestamp": "2026-01-03T00:00:16.000Z",
        "type": "response_item",
        "payload": {"type": "function_call", "id": "fc-t18a-other",
                    "name": "mcp__other-mcp__cass_search",
                    "arguments": "{\"query\":\"t18a other server query\"}",
                    "call_id": "call_t18a_other"}
    }));
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:17.000Z",
        "type": "response_item",
        "payload": {"type": "function_call_output", "call_id": "call_t18a_other", "output": other}
    }));

    // Preservation control: another server's tool without captured arguments.
    // The unknown identity falls back to the legacy judgment, so this row adds
    // no v2 uncovered count.
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:17.500Z",
        "type": "response_item",
        "payload": {"type": "function_call", "id": "fc-t18a-other-missing",
                    "name": "mcp__other-mcp__cass_search",
                    "call_id": "call_t18a_other_missing"}
    }));
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:17.750Z",
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
        "timestamp": "2026-01-03T00:00:18.000Z",
        "type": "response_item",
        "payload": {"type": "function_call_output", "call_id": "call_t18a_unpaired", "output": unpaired}
    }));

    // Preservation control: a C07 `exec` with no literal at all.
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:19.000Z",
        "type": "response_item",
        "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "call_t18a_c07_missing"}
    }));
    lines.push(json!({
        "timestamp": "2026-01-03T00:00:20.000Z",
        "type": "response_item",
        "payload": {"type": "custom_tool_call_output", "call_id": "call_t18a_c07_missing",
                    "output": NATIVE_C07_MISSING_OUTPUT}
    }));

    lines.push(json!({
        "timestamp": "2026-01-03T00:00:21.000Z",
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

fn complete_input_code_versions(db: &Conn) -> Vec<String> {
    let rows: Vec<Vec<u8>> = db
        .query_all_map(
            "SELECT expected_manifest_bin FROM source_inputs ORDER BY id",
            &[],
            |row| row.get_typed::<Vec<u8>>(0),
        )
        .expect("query the manifests");
    rows.into_iter()
        .map(|bytes| {
            let (_manifest, safety) =
                decode_expected_manifest_header(&bytes).expect("decode the manifest header");
            safety.code_version().to_string()
        })
        .collect()
}

/// Every exclusion marker's `rule_version`, in message order.
///
/// `messages.excluded` is stored as SQLite JSONB, so the marker is read back
/// through SQLite's own `json()` decoder (the same read
/// `tests/mcp_restore_rule_epochs.rs` uses). The stored format is not touched.
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

    // 10-AC1: the producer wrote epoch 2, and every marker is rule version 2.
    let versions = complete_input_code_versions(&db);
    assert!(
        !versions.is_empty(),
        "{label}: the inputs carry expected-manifest headers"
    );
    for version in &versions {
        assert!(
            version.starts_with("cass-source-exclusion/2+"),
            "{label}: the producer's code version is epoch 2: {version}"
        );
    }
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
// ---------------------------------------------------------------------------

const NATIVE_MARKER_IDS: [&str; 10] = [
    "toolu_t18a_n_search",
    "toolu_t18a_n_expand",
    "toolu_t18a_n_sessions",
    "toolu_t18a_n_timeline",
    "toolu_t18a_c_search",
    "call_t18a_n_search",
    "call_t18a_n_expand",
    "call_t18a_n_sessions",
    "call_t18a_n_timeline",
    "call_t18a_c_search",
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

/// The literal uncovered matrix of this case under the original rules: two
/// ordinary same-named tools (`ambiguous_tool_identity`) and four preserved
/// candidates (`unpaired_result`: the two bare names without args and the two
/// unpaired envelopes). The eight missing-args strong results are excluded.
/// Neither other-server control adds a count, with or without captured args:
/// an unknown identity goes back through the legacy judgment before any
/// argument gate. The C07 control has no Cass evidence and adds nothing.
fn assert_native_activation_json(report: &Value, label: &str) {
    assert_eq!(
        report["recall_uncovered_total"].as_u64(),
        Some(6),
        "{label}: six literal preservation controls are counted: {report}"
    );
    assert_eq!(
        report["recall_uncovered_by_reason"],
        json!({"ambiguous_tool_identity": 2, "unpaired_result": 4}),
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

    let versions = complete_input_code_versions(&db);
    assert!(
        !versions.is_empty(),
        "{label}: the inputs carry expected-manifest headers"
    );
    for version in &versions {
        assert!(
            version.starts_with("cass-source-exclusion/2+"),
            "{label}: the producer's code version is epoch 2: {version}"
        );
    }

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
        10,
        "{label}: ten supported results are excluded: {:?}",
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

    // Source extraction still comes from the result payload alone.
    assert_eq!(
        by_id["toolu_t18a_n_search"]["src"]["hits"][0]["source_path"],
        json!("/synthetic/t18a/hit.jsonl"),
        "{label}: the claude native search source is read from the envelope"
    );
    assert_eq!(
        by_id["call_t18a_n_search"]["src"]["hits"][0]["source_path"],
        json!("/synthetic/t18a/hit.jsonl"),
        "{label}: the codex native search source is read from the envelope"
    );
    assert_eq!(
        by_id["toolu_t18a_n_sessions"]["src"]["sessions"],
        json!(["/synthetic/t18a/list.jsonl"]),
        "{label}: sessions source"
    );
    assert_eq!(
        by_id["toolu_t18a_n_timeline"]["src"]["sessions"],
        json!(["/synthetic/t18a/t.jsonl"]),
        "{label}: timeline source"
    );
    for id in ["toolu_t18a_n_expand", "call_t18a_n_expand"] {
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
            *count, 5,
            "{label}: five exclusions for {agent}: {by_agent:?}"
        );
    }

    let bodies = message_contents(&db);
    for (id, body) in &world.excluded_bodies {
        assert!(
            !bodies.iter().any(|retained| retained == body),
            "{label}: the excluded body of {id} is not retained"
        );
    }
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
            "bare claude",
            wrapper(
                RecallTool::Search,
                &native_search_value(NATIVE_CLAUDE_BARE_BODY),
            ),
        ),
        (
            "bare codex",
            wrapper(
                RecallTool::Search,
                &native_search_value(NATIVE_CODEX_BARE_BODY),
            ),
        ),
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
