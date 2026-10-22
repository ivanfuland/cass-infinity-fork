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

    fn open_db(&self) -> rusqlite::Connection {
        let db = rusqlite::Connection::open_with_flags(
            self.db(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open the database read-only");
        db.busy_timeout(Duration::from_secs(30))
            .expect("busy timeout");
        db
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
// Readers
// ---------------------------------------------------------------------------

fn complete_input_code_versions(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare("SELECT expected_manifest_bin FROM source_inputs ORDER BY id")
        .expect("prepare the manifest query");
    let rows: Vec<Vec<u8>> = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query the manifests")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the manifests");
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
fn marker_rule_versions(db: &rusqlite::Connection) -> Vec<u64> {
    let mut stmt = db
        .prepare("SELECT json(excluded) FROM messages WHERE excluded IS NOT NULL ORDER BY id")
        .expect("prepare the marker query");
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query the markers")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the markers");
    rows.into_iter()
        .map(|text| {
            let value: Value = serde_json::from_str(&text).expect("a marker is JSON");
            value["rule_version"]
                .as_u64()
                .unwrap_or_else(|| panic!("no rule_version in {value}"))
        })
        .collect()
}

fn message_contents(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare("SELECT content FROM messages ORDER BY id")
        .expect("prepare the body query");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query the bodies")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the bodies")
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
    let by_agent: Vec<(String, i64)> = {
        let mut stmt = db
            .prepare(
                "SELECT a.slug, COUNT(*) FROM messages m
                 JOIN conversations c ON c.id = m.conversation_id
                 JOIN agents a ON a.id = c.agent_id
                 WHERE m.excluded IS NOT NULL GROUP BY a.slug ORDER BY a.slug",
            )
            .expect("prepare the per-agent marker query");
        stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .expect("query the per-agent markers")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the per-agent markers")
    };
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
