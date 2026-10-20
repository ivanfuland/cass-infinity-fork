use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

use coding_agent_search::connectors::{Connector, ScanContext, ScanRoot, codex::CodexConnector};
use serial_test::serial;

fn codex_real_fixture_home() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codex_real")
}

#[test]
#[serial]
fn codex_connector_reads_modern_envelope_jsonl() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/11/21");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-1.jsonl");

    // Modern envelope format with {type, timestamp, payload}
    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"test-id","cwd":"/test/workspace","cli_version":"0.42.0"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"write a hello program"}]}}
{"timestamp":"2025-09-30T15:42:43.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"here is code"}]}}
"#;
    fs::write(&file, sample).unwrap();

    // Safe in test scope: we control process env.
    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);
    let c = &convs[0];
    assert_eq!(c.agent_slug, "codex");
    assert_eq!(c.messages.len(), 2);
    assert!(c.title.as_ref().unwrap().contains("write a hello program"));
    // Verify workspace was extracted from session_meta
    assert_eq!(c.workspace, Some(PathBuf::from("/test/workspace")));
    // Bead 7k7pl: pin timestamps parsed from the 2025-09-30 ISO-8601
    // fixture — both must be plausible ms-epoch values (>= 2020) and
    // started must be strictly before ended. A regression that
    // dropped ISO parsing (emitting 0 / default) would slip past
    // `.is_some()`.
    let started = c
        .started_at
        .expect("started_at must be parsed from ISO-8601");
    let ended = c.ended_at.expect("ended_at must be parsed from ISO-8601");
    // ms-epoch floor: 2020-01-01 (1_577_836_800_000 ms). Fixture is
    // 2025 so this is well below the real value but catches 0/MIN.
    assert!(
        started >= 1_577_836_800_000,
        "started_at must be parsed from the 2025 fixture (>= 2020); got {started}"
    );
    assert!(
        started < ended,
        "started_at must be strictly before ended_at; got started={started}, ended={ended}"
    );
}

#[test]
#[serial]
fn codex_connector_includes_agent_reasoning() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/11/22");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-reasoning.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"test-id","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"solve this problem"}]}}
{"timestamp":"2025-09-30T15:42:40.000Z","type":"event_msg","payload":{"type":"agent_reasoning","text":"Let me think about this carefully..."}}
{"timestamp":"2025-09-30T15:42:43.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"here is solution"}]}}
{"timestamp":"2025-09-30T15:42:45.000Z","type":"event_msg","payload":{"type":"token_count","input_tokens":100,"output_tokens":200}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);
    let c = &convs[0];

    // Should have 3 messages: user, reasoning, assistant
    // (token_count does not create a synthetic message)
    assert_eq!(c.messages.len(), 3);

    assert_eq!(
        c.messages
            .iter()
            .map(|m| m.role.as_str())
            .collect::<Vec<_>>(),
        ["user", "reasoning", "assistant"]
    );
    for (idx, message) in c.messages.iter().enumerate() {
        assert_eq!(message.idx, idx as i64);
    }
    // Role carries the semantic type; this fixture supplies no model author.
    let reasoning = c.messages.iter().find(|m| m.role == "reasoning").unwrap();
    assert_eq!(reasoning.author, None);
    assert_eq!(reasoning.content, "Let me think about this carefully...");

    let assistant = c.messages.iter().find(|m| {
        m.role == "assistant" && m.author.is_none() && m.content.contains("here is solution")
    });
    assert!(assistant.is_some());
    let assistant = assistant.unwrap();
    assert_eq!(
        assistant
            .extra
            .pointer("/cass/token_usage/input_tokens")
            .and_then(|v| v.as_i64()),
        Some(100)
    );
    assert_eq!(
        assistant
            .extra
            .pointer("/cass/token_usage/output_tokens")
            .and_then(|v| v.as_i64()),
        Some(200)
    );
}

#[test]
#[serial]
fn codex_connector_parses_real_tool_call_fixture() {
    let fixture_home = codex_real_fixture_home();
    let expected_path = fixture_home.join("sessions/2025/11/26/rollout-tool-call.jsonl");

    unsafe {
        std::env::set_var("CODEX_HOME", &fixture_home);
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: fixture_home.clone(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    let conv = convs
        .into_iter()
        .find(|conv| conv.source_path == expected_path)
        .expect("real Codex tool-call fixture should be discoverable");

    assert_eq!(conv.agent_slug, "codex");
    assert_eq!(conv.workspace, Some(PathBuf::from("/test/soldier/project")));
    assert_eq!(
        conv.external_id,
        Some("2025/11/26/rollout-tool-call".to_string())
    );
    assert_eq!(
        conv.title,
        Some(
            "Please trace the tool_call branch in the Codex connector and confirm invocation extraction."
                .to_string()
        )
    );
    assert_eq!(conv.messages.len(), 3);

    let tool_msg = &conv.messages[1];
    assert_eq!(tool_msg.idx, 1);
    assert_eq!(conv.messages[0].role, "user");
    assert_eq!(conv.messages[0].idx, 0);
    assert_eq!(tool_msg.role, "tool_call");
    assert_eq!(tool_msg.author, None);
    assert!(tool_msg.content.contains("bash"));
    assert!(
        tool_msg
            .content
            .contains("rg -n tool_call src/connectors/codex.rs")
    );
    assert_eq!(tool_msg.extra["tool_call_id"], "call_codex_tool_001");
    let expected_args = serde_json::json!({"cmd": "rg -n tool_call src/connectors/codex.rs", "cwd": "/test/soldier/project"});
    assert_eq!(tool_msg.extra["tool_call_args"], expected_args);
    assert_eq!(tool_msg.invocations.len(), 1);
    assert!(tool_msg.extra.get("payload").is_some());

    let invocation = &tool_msg.invocations[0];
    assert_eq!(invocation.arguments.as_ref(), Some(&expected_args));
    assert_eq!(invocation.kind, "tool");
    assert_eq!(invocation.name, "bash");
    assert_eq!(invocation.call_id.as_deref(), Some("call_codex_tool_001"));
    assert_eq!(
        invocation
            .arguments
            .as_ref()
            .and_then(|args| args.get("cmd"))
            .and_then(|value| value.as_str()),
        Some("rg -n tool_call src/connectors/codex.rs")
    );
    assert!(
        tool_msg.extra.pointer("/cass/token_usage").is_none(),
        "token usage should attach to the later assistant turn, not the tool_call message"
    );

    let assistant = &conv.messages[2];
    assert_eq!(assistant.idx, 2);
    assert_eq!(assistant.role, "assistant");
    assert!(assistant.content.contains("invocation is emitted"));
    assert_eq!(
        assistant
            .extra
            .pointer("/cass/token_usage/input_tokens")
            .and_then(|v| v.as_i64()),
        Some(120)
    );
    assert_eq!(
        assistant
            .extra
            .pointer("/cass/token_usage/output_tokens")
            .and_then(|v| v.as_i64()),
        Some(45)
    );
}

#[test]
#[serial]
fn codex_connector_indexes_modern_response_items() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2026/05/08");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-modern.jsonl");

    let sample = r#"{"timestamp":"2026-05-08T23:09:00.000Z","type":"session_meta","payload":{"id":"modern-id","cwd":"/data/projects/ntm","cli_version":"0.49.0"}}
{"timestamp":"2026-05-08T23:09:01.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"investigate cass"}]}}
{"timestamp":"2026-05-08T23:09:02.000Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"git log --grep='bd-2mb03'\"}","call_id":"call-modern-1"}}
{"timestamp":"2026-05-08T23:09:03.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call-modern-1","output":"Output:\ncommit abc123 bd-2mb03.6.5 add CASS-backed handoff context enrichment\n"}}
{"timestamp":"2026-05-08T23:09:04.000Z","type":"event_msg","payload":{"type":"agent_message","message":"The raw session contains bd-2mb03."}}
{"timestamp":"2026-05-08T23:09:04.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"The raw session contains bd-2mb03."}],"phase":"commentary"}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let conv = &convs[0];
    assert_eq!(
        conv.messages
            .iter()
            .map(|m| m.role.as_str())
            .collect::<Vec<_>>(),
        ["user", "tool_call", "tool_result", "assistant"]
    );
    for (idx, message) in conv.messages.iter().enumerate() {
        assert_eq!(message.idx, idx as i64);
    }
    let tool_call = &conv.messages[1];
    assert!(tool_call.content.contains("exec_command"));
    assert!(tool_call.content.contains("git log --grep='bd-2mb03'"));
    let expected_args = serde_json::json!({"cmd": "git log --grep='bd-2mb03'"});
    assert_eq!(tool_call.extra["tool_call_args"], expected_args);
    assert_eq!(tool_call.extra["tool_call_id"], "call-modern-1");
    assert_eq!(tool_call.invocations.len(), 1);
    let invocation = &tool_call.invocations[0];
    assert_eq!(invocation.kind, "tool");
    assert_eq!(invocation.name, "exec_command");
    assert_eq!(invocation.call_id.as_deref(), Some("call-modern-1"));
    assert_eq!(invocation.arguments.as_ref(), Some(&expected_args));
    let tool_result = &conv.messages[2];
    assert_eq!(
        tool_result.extra["tool_call_id"],
        tool_call.extra["tool_call_id"]
    );
    assert_eq!(
        tool_result.content,
        "Output:\ncommit abc123 bd-2mb03.6.5 add CASS-backed handoff context enrichment\n",
        "the normalized tool result must retain the complete output"
    );
    assert_eq!(
        conv.messages
            .iter()
            .filter(|message| message.content == "The raw session contains bd-2mb03.")
            .count(),
        1,
        "agent_message and output_text duplicates should collapse to one searchable message"
    );
}

#[test]
#[serial]
fn codex_connector_scans_explicit_rollout_file_root() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join(".codex/sessions/2026/05/08");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-explicit.jsonl");

    let sample = r#"{"timestamp":"2026-05-08T23:09:00.000Z","type":"session_meta","payload":{"id":"explicit-id","cwd":"/data/projects/ntm","cli_version":"0.49.0"}}
{"timestamp":"2026-05-08T23:09:01.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"explicit watch once bd-2mb03"}]}}
{"timestamp":"2026-05-08T23:09:02.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call-explicit","output":"bd-2mb03 direct file root output\n"}}
"#;
    fs::write(&file, sample).unwrap();

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().join(".codex"),
        scan_roots: vec![ScanRoot::local(file.clone())],
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let conv = &convs[0];
    assert_eq!(conv.source_path, file);
    assert_eq!(conv.workspace, Some(PathBuf::from("/data/projects/ntm")));
    assert!(
        conv.messages
            .iter()
            .any(|message| message.content.contains("bd-2mb03 direct file root")),
        "explicit file-root scans must index modern response items"
    );
}

#[test]
#[serial]
fn codex_connector_ignores_unmatched_token_count() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/11/23");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-filter.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"test-id","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}}
{"timestamp":"2025-09-30T15:42:37.000Z","type":"event_msg","payload":{"type":"token_count","input_tokens":10,"output_tokens":20}}
{"timestamp":"2025-09-30T15:42:38.000Z","type":"turn_context","payload":{"turn":1,"model":"gpt-5-codex"}}
{"timestamp":"2025-09-30T15:42:39.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"world"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);
    let c = &convs[0];

    // Should only have 2 messages (user, assistant).
    // token_count and turn_context do not create searchable messages.
    assert_eq!(c.messages.len(), 2);

    for msg in &c.messages {
        assert!(!msg.content.contains("token_count"));
        assert!(!msg.content.contains("turn_context"));
        assert!(!msg.content.trim().is_empty());
    }

    // token_count occurs before the first assistant turn and must not attach forward.
    let assistant = c.messages.iter().find(|m| m.role == "assistant").unwrap();
    assert!(
        assistant.extra.pointer("/cass/token_usage").is_none(),
        "unmatched token_count should be ignored"
    );
}

/// Test that since_ts uses FILE-LEVEL filtering, not message-level.
///
/// NOTE: We intentionally removed message-level timestamp filtering because
/// it caused data loss during incremental re-indexing. When a file is modified,
/// ALL messages in that file are ingested, regardless of individual timestamps.
/// The since_ts is ONLY used to decide whether to process the file at all
/// (based on file mtime vs since_ts).
#[test]
#[serial]
fn codex_connector_respects_since_ts_at_file_level_only() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/11/24");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-since.jsonl");

    // Two messages with different timestamps - both should be included
    // since since_ts filtering happens at the FILE level, not message level.
    let sample = r#"{"timestamp":"2025-09-30T15:42:34.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"old msg"}]}}
{"timestamp":1700000100000,"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"new msg"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    // since_ts does NOT filter individual messages anymore - only whole files
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: Some(1_700_000_000_000),
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);
    let c = &convs[0];

    // BOTH messages should be present - we don't filter by message timestamp
    assert_eq!(
        c.messages.len(),
        2,
        "file-level filtering means all messages in a processed file are included"
    );
    // Messages should have correct roles
    assert_eq!(c.messages[0].role, "user");
    assert!(c.messages[0].content.contains("old msg"));
    assert_eq!(c.messages[1].role, "assistant");
    assert!(c.messages[1].content.contains("new msg"));
}

/// Test legacy .json format parsing
#[test]
#[serial]
fn codex_connector_reads_legacy_json_format() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/11/25");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-legacy.json");

    // Legacy format: single JSON object with session and items
    let sample = r#"{
        "session": {
            "id": "legacy-session",
            "cwd": "/legacy/workspace"
        },
        "items": [
            {
                "role": "user",
                "timestamp": "2025-09-30T15:42:36.190Z",
                "content": "legacy user message"
            },
            {
                "role": "assistant",
                "timestamp": "2025-09-30T15:42:43.000Z",
                "content": "legacy assistant response"
            }
        ]
    }"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    assert_eq!(c.agent_slug, "codex");
    assert_eq!(c.messages.len(), 2);
    assert_eq!(c.workspace, Some(PathBuf::from("/legacy/workspace")));

    // Verify metadata indicates legacy format
    assert_eq!(
        c.metadata.get("source").and_then(|v| v.as_str()),
        Some("rollout_json")
    );

    // Check messages
    assert_eq!(c.messages[0].role, "user");
    assert!(c.messages[0].content.contains("legacy user message"));
    assert_eq!(c.messages[1].role, "assistant");
}

/// Test detection with existing sessions directory
#[test]
#[serial]
fn codex_detect_with_sessions_dir() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions");
    fs::create_dir_all(&sessions).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let result = connector.detect();
    assert!(result.detected);
    assert!(!result.evidence.is_empty());
}

/// Test detection without sessions directory
#[test]
#[serial]
fn codex_detect_without_sessions_dir() {
    let dir = TempDir::new().unwrap();
    // Don't create sessions directory

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let result = connector.detect();
    assert!(!result.detected);
}

/// Test `user_message` event type
#[test]
#[serial]
fn codex_connector_handles_user_message_event() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/11/26");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-user-event.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"test-id","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"event_msg","payload":{"type":"user_message","message":"user event message"}}
{"timestamp":"2025-09-30T15:42:43.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"assistant reply"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    assert_eq!(c.messages.len(), 2);

    // First message should be the user event
    assert_eq!(c.messages[0].role, "user");
    assert!(c.messages[0].content.contains("user event message"));
}

/// Test malformed JSONL lines are skipped gracefully
#[test]
#[serial]
fn codex_connector_skips_malformed_lines() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/11/27");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-malformed.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"test-id","cwd":"/test"}}
{ this is not valid json
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"valid message"}]}}
also not valid
{"timestamp":"2025-09-30T15:42:43.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"valid response"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    // Should have 2 valid messages, malformed lines skipped
    assert_eq!(c.messages.len(), 2);
}

/// Test multiple sessions in separate files
#[test]
#[serial]
fn codex_connector_handles_multiple_sessions() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/11/28");
    fs::create_dir_all(&sessions).unwrap();

    for i in 1..=3 {
        let file = sessions.join(format!("rollout-{i}.jsonl"));
        let sample = format!(
            r#"{{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{{"id":"session-{i}","cwd":"/test/{i}"}}}}
{{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{{"type":"message","role":"user","content":[{{"type":"input_text","text":"message {i}"}}]}}}}
"#
        );
        fs::write(&file, sample).unwrap();
    }

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 3);
}

/// Test empty content messages are filtered
///
/// set CODEX_HOME env var without proper serialization, causing parallel
/// tests to interfere with each other. Works locally but fails on CI.
/// Consider adding serial_test or refactoring to avoid env var mutation.
#[test]
#[serial]
fn codex_connector_filters_empty_content() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/11/29");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-empty.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"test-id","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"   "}]}}
{"timestamp":"2025-09-30T15:42:37.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"valid content"}]}}
{"timestamp":"2025-09-30T15:42:43.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    // Only the message with "valid content" should be included
    assert_eq!(c.messages.len(), 1);
    assert!(c.messages[0].content.contains("valid content"));
}

/// Test title extraction from first user message
///
#[test]
#[serial]
fn codex_connector_extracts_title() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/11/30");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-title.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"test-id","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:35.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"assistant first"}]}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"This is the user's question\nWith a second line"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    // Title should be first line of first user message
    assert_eq!(c.title, Some("This is the user's question".to_string()));
}

/// Test sequential index assignment
#[test]
#[serial]
fn codex_connector_assigns_sequential_indices() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/01");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-idx.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"test-id","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"first"}]}}
{"timestamp":"2025-09-30T15:42:37.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"second"}]}}
{"timestamp":"2025-09-30T15:42:38.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"third"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    assert_eq!(c.messages.len(), 3);
    assert_eq!(c.messages[0].idx, 0);
    assert_eq!(c.messages[1].idx, 1);
    assert_eq!(c.messages[2].idx, 2);
}

/// Test `external_id` comes from filename
#[test]
#[serial]
fn codex_connector_sets_external_id_from_filename() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/02");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-unique-id-123.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"test-id","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"test"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    // external_id is now the relative path from sessions dir for uniqueness across directories
    assert_eq!(
        c.external_id,
        Some("2025/12/02/rollout-unique-id-123".to_string())
    );
}

/// Test empty sessions directory returns no conversations
#[test]
#[serial]
fn codex_connector_handles_empty_sessions() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    // No files in sessions

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert!(convs.is_empty());
}

/// Test integer (milliseconds) timestamp format is rejected
#[test]
#[serial]
fn codex_connector_rejects_millis_timestamp() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/03");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-millis.jsonl");

    // Timestamps as i64 milliseconds instead of ISO-8601 strings
    let sample = r#"{"timestamp":1700000000000,"type":"session_meta","payload":{"id":"millis-test","cwd":"/millis"}}
{"timestamp":1700000001000,"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"millis timestamp test"}]}}
{"timestamp":1700000002000,"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"response with millis"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };

    // connector storage contract 起，modern Codex 的 `session_meta` 必须有 string 型
    // 顶层 `timestamp`。数字型（i64 毫秒）属类型漂移，进结构异常门 fail loud，
    // 不再静默按毫秒解析——静默接受会让未知 schema 变体混进 canonical 层。
    let err = connector
        .scan(&ctx)
        .expect_err("numeric session_meta timestamp must fail loud, not parse as millis");
    let msg = err.to_string();
    assert!(
        msg.contains("session_meta") && msg.contains("timestamp"),
        "error must name the offending field, got: {msg}"
    );
}

/// Test `tool_use` blocks in content are flattened properly
#[test]
#[serial]
fn codex_connector_flattens_tool_use_blocks() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/04");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-tools.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"tool-test","cwd":"/tools"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"read a file"}]}}
{"timestamp":"2025-09-30T15:42:43.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"Let me read that file"},{"type":"tool_use","name":"Read","input":{"file_path":"/test/file.rs"}}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    assert_eq!(c.messages.len(), 2);

    // Assistant message should contain flattened tool_use
    let assistant = &c.messages[1];
    assert!(assistant.content.contains("Let me read that file"));
    assert!(assistant.content.contains("[Tool: Read"));
    assert!(assistant.content.contains("/test/file.rs"));
}

/// Test missing cwd in `session_meta` results in None workspace
#[test]
#[serial]
fn codex_connector_rejects_missing_cwd() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/05");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-no-cwd.jsonl");

    // session_meta without cwd field
    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"no-cwd","cli_version":"0.42.0"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"test without cwd"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };

    // connector storage contract 起，modern Codex 的 `session_meta` 必须带 string 型
    // `payload.cwd`；缺字段不再按 metadata-only 放过，而是进入结构异常门 fail loud。
    // 此前的行为（照常解析、workspace 留 None）会让 schema 漂移静默通过。
    let err = connector
        .scan(&ctx)
        .expect_err("session_meta without cwd must fail loud, not parse silently");
    let msg = err.to_string();
    assert!(
        msg.contains("session_meta") && msg.contains("cwd"),
        "error must name the offending field, got: {msg}"
    );
}

/// Test files without rollout- prefix are ignored
#[test]
#[serial]
fn codex_connector_ignores_non_rollout_files() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/06");
    fs::create_dir_all(&sessions).unwrap();

    // Valid rollout file
    let rollout = sessions.join("rollout-valid.jsonl");
    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"valid","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"valid"}]}}
"#;
    fs::write(&rollout, sample).unwrap();

    // Non-rollout files that should be ignored
    let other1 = sessions.join("session-123.jsonl");
    let other2 = sessions.join("backup.json");
    let other3 = sessions.join("config.jsonl");
    fs::write(&other1, sample).unwrap();
    fs::write(&other2, sample).unwrap();
    fs::write(&other3, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    // Only the rollout- prefixed file should be processed
    assert_eq!(convs.len(), 1);
    // external_id is now the relative path from sessions dir for uniqueness across directories
    assert_eq!(
        convs[0].external_id,
        Some("2025/12/06/rollout-valid".to_string())
    );
}

/// Test legacy JSON with missing optional fields
#[test]
#[serial]
fn codex_connector_handles_legacy_json_missing_session() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/07");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-minimal.json");

    // Minimal legacy format without session object
    let sample = r#"{
        "items": [
            {
                "role": "user",
                "content": "minimal legacy message"
            }
        ]
    }"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    assert!(c.workspace.is_none());
    assert_eq!(c.messages.len(), 1);
    assert!(c.messages[0].content.contains("minimal legacy message"));
}

/// Test title fallback to first message when no user message exists
#[test]
#[serial]
fn codex_connector_title_fallback_to_first_message() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/08");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-no-user.jsonl");

    // Only assistant messages, no user message
    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"no-user","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"Assistant first line\nSecond line"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    // Title should fallback to first line of first message
    assert_eq!(c.title, Some("Assistant first line".to_string()));
}

/// Test deeply nested directory structure
#[test]
#[serial]
fn codex_connector_handles_nested_directories() {
    let dir = TempDir::new().unwrap();
    let deep_sessions = dir.path().join("sessions/2025/12/09/sub1/sub2");
    fs::create_dir_all(&deep_sessions).unwrap();
    let file = deep_sessions.join("rollout-nested.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"nested","cwd":"/nested"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"deeply nested"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);
    assert!(convs[0].source_path.to_string_lossy().contains("sub2"));
}

/// Test `turn_aborted` event is filtered out
#[test]
#[serial]
fn codex_connector_filters_turn_aborted() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/10");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-aborted.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"test-id","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"test"}]}}
{"timestamp":"2025-09-30T15:42:37.000Z","type":"event_msg","payload":{"type":"turn_aborted","reason":"user cancelled"}}
{"timestamp":"2025-09-30T15:42:38.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":"response"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    // Should only have 2 messages (user, assistant) - turn_aborted filtered
    assert_eq!(c.messages.len(), 2);
    for msg in &c.messages {
        assert!(!msg.content.contains("turn_aborted"));
    }
}

/// Test long title is truncated to 100 chars
#[test]
#[serial]
fn codex_connector_truncates_long_title() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/11");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-long-title.jsonl");

    let long_text = "A".repeat(200);
    let sample = format!(
        r#"{{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{{"id":"long","cwd":"/test"}}}}
{{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{{"type":"message","role":"user","content":[{{"type":"input_text","text":"{long_text}"}}]}}}}
"#
    );
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    // Bead 7k7pl: collapse `.is_some()` + `.unwrap().len() == 100`
    // into a single pin on the title's length (truncation contract)
    // plus a content pin — the truncated title must still be 100 x
    // 'A' (no bytes lost to multi-byte boundary confusion).
    assert_eq!(
        c.title.as_ref().map(|t| t.len()),
        Some(100),
        "title must be truncated to exactly 100 chars; got {:?}",
        c.title
    );
    assert_eq!(
        c.title.as_deref(),
        Some("A".repeat(100).as_str()),
        "title must be 100 'A's from the truncation of 200; got {:?}",
        c.title
    );
}

/// Test `source_path` matches actual file path
#[test]
#[serial]
fn codex_connector_sets_source_path() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/12");
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join("rollout-source-path.jsonl");

    let sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"path-test","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"test source path"}]}}
"#;
    fs::write(&file, sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 1);

    let c = &convs[0];
    assert_eq!(c.source_path, file);
}

/// Test metadata indicates correct source format
#[test]
#[serial]
fn codex_connector_metadata_indicates_format() {
    let dir = TempDir::new().unwrap();
    let sessions = dir.path().join("sessions/2025/12/13");
    fs::create_dir_all(&sessions).unwrap();

    // Create both JSONL and JSON files
    let jsonl_file = sessions.join("rollout-jsonl.jsonl");
    let json_file = sessions.join("rollout-json.json");

    let jsonl_sample = r#"{"timestamp":"2025-09-30T15:42:34.559Z","type":"session_meta","payload":{"id":"jsonl","cwd":"/test"}}
{"timestamp":"2025-09-30T15:42:36.190Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"jsonl format"}]}}
"#;
    fs::write(&jsonl_file, jsonl_sample).unwrap();

    let json_sample = r#"{"session":{"id":"json","cwd":"/test"},"items":[{"role":"user","content":"json format"}]}"#;
    fs::write(&json_file, json_sample).unwrap();

    unsafe {
        std::env::set_var("CODEX_HOME", dir.path());
    }

    let connector = CodexConnector::new();
    let ctx = ScanContext {
        data_dir: dir.path().to_path_buf(),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = connector.scan(&ctx).unwrap();
    assert_eq!(convs.len(), 2);

    // Find each conversation and verify metadata
    let jsonl_conv = convs.iter().find(|c| c.source_path == jsonl_file).unwrap();
    let json_conv = convs.iter().find(|c| c.source_path == json_file).unwrap();

    assert_eq!(
        jsonl_conv.metadata.get("source").and_then(|v| v.as_str()),
        Some("rollout")
    );
    assert_eq!(
        json_conv.metadata.get("source").and_then(|v| v.as_str()),
        Some("rollout_json")
    );
}

/// SRC05B-01: the CASS `codex::CodexConnector` wrapper must forward the pinned
/// franken_agent_detection sealed-source read instead of inheriting the trait's
/// `Unsupported` default.
///
/// Every fixture here is synthetic bytes turned into a sealed context through
/// the pinned public API only. No test in this module changes `CODEX_HOME`,
/// reads a real user directory or fabricates a private field; the sealed read
/// opens only the temp file the fixture wrote.
mod codex_source_aware_bridge {
    use std::fs;

    use coding_agent_search::connectors::Connector;
    use coding_agent_search::connectors::codex::CodexConnector as CassCodexConnector;
    use franken_agent_detection::{
        CodexConnector as FrankenCodexConnector, ContentDigest, Origin, SealedInputContext,
        SealedSourceRef, Sha256Digest, SourceExpectedManifest, SourceFormat, SourceInputDescriptor,
        SourceInputFinish, SourceInputRole, SourceMappedConversation, SourceMappingClaim,
        SourceMappingDiagnostic, SourceMappingSink, SourceOrigin, SourceParserContext,
        SourceParserRoot, SourceReadFailure, SourceReadFailureKind, SourceRecordLocator,
        SourceRecordOutcome, SourceRecordSink, SourceSinkControl, SourceSinkFailure,
        SourceSinkFailureCode,
    };
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    /// One `session_meta` plus one user and one assistant `response_item`, so a
    /// faithful projection produces two real messages.
    const SYNTHETIC_ROLLOUT: &str = concat!(
        r#"{"type":"session_meta","timestamp":"2026-01-01T00:00:00Z","payload":{"id":"session-bridge","cwd":"/fixture/workspace"}}"#,
        "\n",
        r#"{"type":"response_item","timestamp":"2026-01-01T00:00:01Z","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello bridge"}]}}"#,
        "\n",
        r#"{"type":"response_item","timestamp":"2026-01-01T00:00:02Z","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"bridge answer"}]}}"#,
        "\n",
    );

    /// Framing measurements and digest, computed from the bytes alone.
    fn measure_framing(bytes: &[u8], format: SourceFormat) -> (u64, u64, u64, Sha256Digest) {
        let mut framing = Sha256::new();
        framing.update(b"cass.source-framing/1");
        let mut offset = 0usize;
        let mut records = 0u64;
        let mut blank_lines = 0u64;
        let mut blank_bytes = 0u64;
        let frames: Vec<&[u8]> = match format {
            SourceFormat::Jsonl => bytes.split_inclusive(|byte| *byte == b'\n').collect(),
            SourceFormat::JsonDocument => vec![bytes],
        };
        for (line, frame) in frames.into_iter().enumerate() {
            let raw = if format == SourceFormat::Jsonl {
                frame
                    .strip_suffix(b"\r\n")
                    .or_else(|| frame.strip_suffix(b"\n"))
                    .unwrap_or(frame)
            } else {
                frame
            };
            if format == SourceFormat::Jsonl && raw.iter().all(|b| b" \t\r\n".contains(b)) {
                blank_lines += 1;
                blank_bytes += raw.len() as u64;
            } else {
                records += 1;
                let digest = format!("{:x}", Sha256::digest(raw));
                let leaf = serde_json::to_vec(&[
                    (line + 1).to_string(),
                    String::new(),
                    offset.to_string(),
                    (offset + raw.len()).to_string(),
                    digest,
                ])
                .unwrap();
                framing.update((leaf.len() as u64).to_be_bytes());
                framing.update(leaf);
            }
            offset += frame.len();
        }
        (
            records,
            blank_lines,
            blank_bytes,
            Sha256Digest::from_hex(&format!("{:x}", framing.finalize())).unwrap(),
        )
    }

    /// Build a sealed context for `bytes`. `connector` names the discovery and
    /// parser-context connector, exactly as the pinned harness does.
    fn sealed_input(
        bytes: &[u8],
        format: SourceFormat,
        connector: &str,
    ) -> (TempDir, SealedInputContext) {
        let dir = TempDir::new().unwrap();
        let sealed_locator = dir.path().join("blob");
        fs::write(&sealed_locator, bytes).unwrap();

        let (records, blank_lines, blank_bytes, framing_sha256) = measure_framing(bytes, format);
        let origin = SourceOrigin {
            origin: Origin::local(),
            source_version: None,
        };
        let discovery = SourceInputDescriptor {
            connector: connector.into(),
            scan_root: "/fixture/projects".into(),
            source_path: "/fixture/projects/session.jsonl".into(),
            relative_locator: "session.jsonl".into(),
            role: SourceInputRole::PrimarySessionLog,
            origin: origin.clone(),
            platform: None,
            size_bytes: None,
            modified_at_ms: None,
        };
        let parser_context = SourceParserContext {
            schema: "cass.source-parser-context/1".into(),
            connector: discovery.connector.clone(),
            roots: vec![SourceParserRoot {
                path: discovery.scan_root.clone(),
                origin,
                platform: None,
                workspace_rewrites: Vec::new(),
            }],
            relative_locator: discovery.relative_locator.clone(),
            role: discovery.role,
            effective_config_digest: None,
        };
        let mut sealed = SealedInputContext {
            input_key: Sha256Digest::of(b""),
            identity_namespace: "src05b-frozen".into(),
            parser_context_digest: parser_context.digest().unwrap(),
            content_digest: ContentDigest::of(bytes),
            byte_len: bytes.len() as u64,
            format,
            normalizer_id: "cass.codex/1".into(),
            safety_contract_id: "cass.source-safety/1".into(),
            sealed_locator,
            sealed_ref: SealedSourceRef {
                transport: "frozen_file_unmirrored".into(),
                blob_algorithm: None,
                blob_digest: None,
                blob_relative_path: None,
            },
            expected_manifest: SourceExpectedManifest {
                verifier_version: "cass.source-verifier/1".into(),
                format,
                records,
                blank_lines,
                blank_bytes,
                framing_sha256,
                complete: true,
            },
            discovery,
            parser_context,
        };
        rebind_identity(&mut sealed);
        (dir, sealed)
    }

    /// Recompute the two derived digests after a semantic edit, so a mutated
    /// context stays internally consistent and only the edited fact differs.
    fn rebind_identity(sealed: &mut SealedInputContext) {
        sealed.input_key = sealed.identity_for(sealed.content_digest).unwrap();
    }

    #[derive(Default)]
    struct RecordingSink {
        records: Vec<SourceRecordOutcome>,
        conversations: Vec<SourceMappedConversation>,
        claims: Vec<(SourceRecordLocator, Vec<SourceMappingClaim>)>,
        diagnostics: Vec<SourceMappingDiagnostic>,
        stop_at: Option<&'static str>,
        error: bool,
    }

    impl RecordingSink {
        fn control(&self, stage: &str) -> Result<SourceSinkControl, SourceSinkFailure> {
            if self.stop_at == Some(stage) {
                if self.error {
                    Err(SourceSinkFailure {
                        code: SourceSinkFailureCode::Rejected,
                        detail_digest: None,
                    })
                } else {
                    Ok(SourceSinkControl::Stop)
                }
            } else {
                Ok(SourceSinkControl::Continue)
            }
        }

        fn canonical(&self) -> Vec<&SourceMappingClaim> {
            self.claims
                .iter()
                .flat_map(|(_, claims)| claims)
                .filter(|claim| claim.mapping_state == "canonical")
                .collect()
        }

        fn claims_wire(&self) -> serde_json::Value {
            serde_json::Value::Array(
                self.claims
                    .iter()
                    .map(|(locator, claims)| {
                        serde_json::json!({
                            "ordinal": locator.ordinal,
                            "record_pointer": locator.record_pointer.as_str(),
                            "byte_start": locator.byte_start,
                            "byte_end": locator.byte_end,
                            "claims": serde_json::to_value(claims).unwrap(),
                        })
                    })
                    .collect(),
            )
        }

        fn records_wire(&self) -> serde_json::Value {
            serde_json::Value::Array(self.records.iter().map(record_wire).collect())
        }

        fn conversations_wire(&self) -> serde_json::Value {
            serde_json::Value::Array(
                self.conversations
                    .iter()
                    .map(|item| {
                        serde_json::json!({
                            "conversation_ordinal": item.conversation_ordinal,
                            "conversation": serde_json::to_value(&item.conversation).unwrap(),
                            "claims": serde_json::to_value(&item.claims).unwrap(),
                        })
                    })
                    .collect(),
            )
        }
    }

    impl SourceRecordSink for RecordingSink {
        fn on_record(
            &mut self,
            record: SourceRecordOutcome,
        ) -> Result<SourceSinkControl, SourceSinkFailure> {
            self.records.push(record);
            self.control("record")
        }
    }

    impl SourceMappingSink for RecordingSink {
        fn on_record_claims(
            &mut self,
            locator: SourceRecordLocator,
            claims: Vec<SourceMappingClaim>,
        ) -> Result<SourceSinkControl, SourceSinkFailure> {
            self.claims.push((locator, claims));
            self.control("claims")
        }

        fn on_conversation(
            &mut self,
            item: SourceMappedConversation,
        ) -> Result<SourceSinkControl, SourceSinkFailure> {
            self.conversations.push(item);
            self.control("conversation")
        }

        fn on_diagnostic(
            &mut self,
            item: SourceMappingDiagnostic,
        ) -> Result<SourceSinkControl, SourceSinkFailure> {
            self.diagnostics.push(item);
            self.control("diagnostic")
        }
    }

    /// Every measurable field of one original record, including the canonical
    /// text of its parsed value.
    fn record_wire(record: &SourceRecordOutcome) -> serde_json::Value {
        let value = record.value.as_ref().map(|value| {
            let mut text = Vec::new();
            value.write_canonical(&mut text).unwrap();
            String::from_utf8(text).unwrap()
        });
        serde_json::json!({
            "ordinal": record.locator.ordinal,
            "record_pointer": record.locator.record_pointer.as_str(),
            "byte_start": record.locator.byte_start,
            "byte_end": record.locator.byte_end,
            "record_byte_len": record.record_byte_len,
            "terminator_len": record.terminator_len,
            "source_record_sha256": record.source_record_sha256.to_string(),
            "value": value,
            "parse_state": serde_json::to_value(record.parse_state).unwrap(),
            "diagnostics": serde_json::to_value(&record.diagnostics).unwrap(),
        })
    }

    fn finish_wire(finish: &SourceInputFinish) -> serde_json::Value {
        serde_json::to_value(finish).unwrap()
    }

    fn failure_wire(failure: &SourceReadFailure) -> serde_json::Value {
        serde_json::json!({
            "kind": format!("{:?}", failure.kind),
            "partial_finish": serde_json::to_value(&failure.partial_finish).unwrap(),
            "next_cursor": serde_json::to_value(&failure.next_cursor).unwrap(),
            "diagnostic": serde_json::to_value(&failure.diagnostic).unwrap(),
        })
    }

    /// The wrapper, called as a trait object, reads the same fixture as the
    /// pinned native connector and reports exactly the same facts.
    #[test]
    fn codex_wrapper_forwards_sealed_read_and_matches_native_connector() {
        let (_dir, sealed) =
            sealed_input(SYNTHETIC_ROLLOUT.as_bytes(), SourceFormat::Jsonl, "codex");
        let wrapper = CassCodexConnector::new();
        let wrapper_trait: &dyn Connector = &wrapper;
        let native = FrankenCodexConnector::new();

        let mut wrapper_sink = RecordingSink::default();
        let wrapper_finish = wrapper_trait
            .scan_source_aware(&sealed, &mut wrapper_sink)
            .expect(
                "CASS CodexConnector must forward scan_source_aware to the pinned FAD connector",
            );

        let mut native_sink = RecordingSink::default();
        let native_finish = native
            .scan_source_aware(&sealed, &mut native_sink)
            .expect("the pinned FAD CodexConnector implements scan_source_aware");

        // Independent structural assertions first: the fixture really projects
        // two messages, so an "both sides empty" comparison cannot pass here.
        assert_eq!(wrapper_sink.records.len(), 3, "three source records");
        assert_eq!(wrapper_sink.conversations.len(), 1, "one conversation");
        assert_eq!(wrapper_finish.records_seen, 3);
        assert!(wrapper_finish.reached_eof);
        assert_eq!(wrapper_finish.bytes_read, SYNTHETIC_ROLLOUT.len() as u64);
        let conversation = &wrapper_sink.conversations[0].conversation;
        assert_eq!(conversation.agent_slug, "codex");
        assert_eq!(conversation.external_id.as_deref(), Some("session"));
        assert_eq!(conversation.workspace, Some("/fixture/workspace".into()));
        assert_eq!(
            conversation
                .messages
                .iter()
                .map(|m| (m.idx, m.role.as_str(), m.content.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (0, "user", "hello bridge"),
                (1, "assistant", "bridge answer"),
            ]
        );
        let canonical = wrapper_sink.canonical();
        assert_eq!(canonical.len(), 2, "one canonical claim per message");
        assert_eq!(canonical[0].final_message_idx, Some(0));
        assert_eq!(canonical[1].final_message_idx, Some(1));

        // Field-by-field equality with the pinned native implementation.
        assert_eq!(finish_wire(&wrapper_finish), finish_wire(&native_finish));
        assert_eq!(wrapper_sink.records_wire(), native_sink.records_wire());
        assert_eq!(
            wrapper_sink.conversations_wire(),
            native_sink.conversations_wire()
        );
        assert_eq!(wrapper_sink.claims_wire(), native_sink.claims_wire());
        assert_eq!(wrapper_sink.diagnostics, native_sink.diagnostics);
    }

    /// A sealed context naming another connector, and one whose parser context
    /// contradicts its discovery, must both keep the pinned `InvalidContext`
    /// failure. Neither may reach the legacy scan.
    #[test]
    fn codex_wrapper_keeps_invalid_context_failure_without_legacy_fallback() {
        let bytes = SYNTHETIC_ROLLOUT.as_bytes();

        // Positive control on the same bytes: the fixture itself is readable,
        // so the rejections below come from the context and not the input.
        let (_dir, good) = sealed_input(bytes, SourceFormat::Jsonl, "codex");
        assert!(good.validate().is_ok());
        let mut good_sink = RecordingSink::default();
        CassCodexConnector::new()
            .scan_source_aware(&good, &mut good_sink)
            .expect("positive control: connector codex reads this fixture");
        assert_eq!(good_sink.conversations.len(), 1);

        let native = FrankenCodexConnector::new();

        // Case 1: a self-consistent context that declares another connector.
        let (_dir, wrong_connector) = sealed_input(bytes, SourceFormat::Jsonl, "claude_code");
        assert!(wrong_connector.validate().is_ok());
        let mut sink = RecordingSink::default();
        let failure = CassCodexConnector::new()
            .scan_source_aware(&wrong_connector, &mut sink)
            .expect_err("a claude_code sealed context is not a codex read");
        assert_eq!(failure.kind, SourceReadFailureKind::InvalidContext);
        assert!(sink.records.is_empty(), "no record may reach the sink");
        assert!(sink.conversations.is_empty());
        let mut native_sink = RecordingSink::default();
        let native_failure = native
            .scan_source_aware(&wrong_connector, &mut native_sink)
            .expect_err("the pinned connector rejects the same context");
        assert_eq!(failure_wire(&failure), failure_wire(&native_failure));
        assert_eq!(native_sink.records.len(), sink.records.len());

        // Case 2: the parser context root contradicts the discovery scan root.
        let (_dir, bad_parser) = sealed_input(bytes, SourceFormat::Jsonl, "codex");
        let mut bad_parser = bad_parser;
        bad_parser.parser_context.roots[0].path = "/fixture/elsewhere".into();
        bad_parser.parser_context_digest = bad_parser.parser_context.digest().unwrap();
        rebind_identity(&mut bad_parser);
        assert_eq!(
            bad_parser.validate(),
            Err(SourceReadFailureKind::InvalidContext)
        );
        let mut sink = RecordingSink::default();
        let failure = CassCodexConnector::new()
            .scan_source_aware(&bad_parser, &mut sink)
            .expect_err("a context that fails validation is not read");
        assert_eq!(failure.kind, SourceReadFailureKind::InvalidContext);
        assert!(sink.records.is_empty(), "no record may reach the sink");
        let mut native_sink = RecordingSink::default();
        let native_failure = native
            .scan_source_aware(&bad_parser, &mut native_sink)
            .expect_err("the pinned connector rejects the same context");
        assert_eq!(failure_wire(&failure), failure_wire(&native_failure));
    }

    /// A sink that stops or fails mid-delivery must keep the pinned failure
    /// kind, the partial Finish and every event delivered before the stop,
    /// exactly as the native connector reports them.
    #[test]
    fn codex_wrapper_keeps_sink_stop_and_rejection_failures() {
        let bytes = SYNTHETIC_ROLLOUT.as_bytes();
        let (_dir, sealed) = sealed_input(bytes, SourceFormat::Jsonl, "codex");
        let native = FrankenCodexConnector::new();

        for stage in ["record", "conversation", "claims"] {
            for error in [false, true] {
                let mut sink = RecordingSink {
                    stop_at: Some(stage),
                    error,
                    ..RecordingSink::default()
                };
                let failure = CassCodexConnector::new()
                    .scan_source_aware(&sealed, &mut sink)
                    .expect_err("a halted or failing sink ends the read");

                let mut native_sink = RecordingSink {
                    stop_at: Some(stage),
                    error,
                    ..RecordingSink::default()
                };
                let native_failure = native
                    .scan_source_aware(&sealed, &mut native_sink)
                    .expect_err("the pinned connector stops the same way");

                let expected_kind = if error {
                    SourceReadFailureKind::Sink
                } else {
                    SourceReadFailureKind::Stopped
                };
                assert_eq!(failure.kind, expected_kind, "stage {stage}, error={error}");
                assert_eq!(failure_wire(&failure), failure_wire(&native_failure));
                assert!(!sink.records.is_empty(), "the stop happens after delivery");
                assert_eq!(sink.records.len(), native_sink.records.len());
                assert_eq!(sink.conversations.len(), native_sink.conversations.len());
                assert_eq!(sink.claims.len(), native_sink.claims.len());
                assert_eq!(sink.records_wire(), native_sink.records_wire());
                assert_eq!(sink.claims_wire(), native_sink.claims_wire());
                assert_eq!(sink.diagnostics, native_sink.diagnostics);
            }
        }
    }

    /// The whole-input projection rejection is the fourth outcome of the same
    /// delegated method: a reserved record shape rejects the projection while
    /// keeping every original record and publishing no claims.
    #[test]
    fn codex_wrapper_keeps_whole_input_projection_rejection() {
        let bytes = concat!(
            r#"{"type":"session_meta","timestamp":"2026-01-01T00:00:00Z","payload":{"id":"session-bridge","cwd":"/fixture/workspace"}}"#,
            "\n",
            r#"{"type":"response_item","raw_role":"reserved","payload":{"type":"message","role":"assistant","content":"rejected"}}"#,
            "\n",
        );
        let (_dir, sealed) = sealed_input(bytes.as_bytes(), SourceFormat::Jsonl, "codex");

        let mut sink = RecordingSink::default();
        let failure = CassCodexConnector::new()
            .scan_source_aware(&sealed, &mut sink)
            .expect_err("a reserved raw_role rejects the whole input");
        assert_eq!(failure.kind, SourceReadFailureKind::ProjectionRejected);
        assert!(failure.partial_finish.reached_eof);
        assert_eq!(failure.partial_finish.records_seen, 2);
        assert_eq!(failure.partial_finish.mapping_diagnostics, 1);
        assert_eq!(sink.records.len(), 2, "the original records still arrive");
        assert!(
            sink.claims.is_empty(),
            "a rejected input publishes no claims"
        );
        assert!(sink.conversations.is_empty());
        assert_eq!(sink.records[1].diagnostics.len(), 1);
        assert_eq!(
            sink.records[1].diagnostics[0].detail.as_deref(),
            Some("projection_reserved_raw_role")
        );
        assert!(
            sink.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "source_projection_rejected"),
            "the registered rejection reason reaches the mapping sink"
        );

        let mut native_sink = RecordingSink::default();
        let native_failure = FrankenCodexConnector::new()
            .scan_source_aware(&sealed, &mut native_sink)
            .expect_err("the pinned connector rejects the same input");
        assert_eq!(failure_wire(&failure), failure_wire(&native_failure));
        assert_eq!(sink.records_wire(), native_sink.records_wire());
        assert_eq!(sink.claims_wire(), native_sink.claims_wire());
        assert_eq!(sink.diagnostics, native_sink.diagnostics);
    }
}
