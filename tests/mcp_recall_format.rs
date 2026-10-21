use coding_agent_search::recall_output::{RecallTool, decode, encode};
use serde_json::{Value, json};

#[test]
fn all_four_shapes_round_trip_in_one_root() {
    for (tool, value) in [
        (
            RecallTool::Search,
            json!({"hits":[{"content":"a & <b> </cass_recall> 中文\n"}]}),
        ),
        (
            RecallTool::Expand,
            json!([{"line":1,"role":"user","is_target":true,"content":"<&>"}]),
        ),
        (RecallTool::Sessions, json!({"sessions":[{"title":"<&>"}]})),
        (
            RecallTool::Timeline,
            json!({"range":{"start":1,"end":2},"total_sessions":0,"groups":{}}),
        ),
    ] {
        let encoded = encode(tool, &value).unwrap();
        assert_eq!(encoded.matches("<cass_recall ").count(), 1);
        assert_eq!(encoded.matches("</cass_recall>").count(), 1);
        assert_eq!(decode(&format!(" \n{encoded}\t"), tool).unwrap(), value);
    }
}

#[test]
fn malformed_or_mixed_wrappers_never_count_as_recall() {
    let valid = encode(RecallTool::Search, &json!({"hits":[]})).unwrap();
    for bad in [
        format!("prefix{valid}"),
        format!("{valid}suffix"),
        format!("{valid}{valid}"),
        format!("<?xml version=\"1.0\"?>{valid}"),
        format!("<!DOCTYPE cass_recall [<!ENTITY x SYSTEM 'file:///private'>]>{valid}"),
        valid.replace("version=\"1\"", "version=\"2\""),
        valid.replace("version=\"1\"", "version=\"1\" extra=\"x\""),
        valid.replace("version=\"1\"", "version=\"1\" version=\"1\""),
        valid.replace("{&quot;hits&quot;:[]}", "<child/>"),
        valid.replace("{&quot;hits&quot;:[]}", "{&quot;hits&quot;:&unknown;}"),
        "<cass_recall version=\"1\" tool=\"cass_search\">{\"hits\":[]}".to_owned(),
    ] {
        assert!(decode(&bad, RecallTool::Search).is_err(), "accepted: {bad}");
    }
    assert!(decode(&valid, RecallTool::Sessions).is_err());
}

#[test]
fn wrong_result_shapes_are_rejected() {
    for tool in [
        RecallTool::Search,
        RecallTool::Expand,
        RecallTool::Sessions,
        RecallTool::Timeline,
    ] {
        assert!(encode(tool, &Value::Null).is_err());
        assert!(
            decode(
                &format!(
                    "<cass_recall version=\"1\" tool=\"{}\">null</cass_recall>",
                    tool.name()
                ),
                tool
            )
            .is_err()
        );
    }
}

#[test]
fn recall_conflicts_are_usage_errors_before_querying() {
    use assert_cmd::Command;
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["search", "query", "--recall", "--json"],
        vec!["search", "query", "--recall", "--display", "table"],
        vec!["search", "query", "--recall", "--fields", "minimal"],
        vec!["search", "query", "--recall", "--robot-format", "json"],
        vec![
            "expand",
            "missing.jsonl",
            "--line",
            "1",
            "--recall",
            "--json",
        ],
        vec![
            "expand",
            "missing.jsonl",
            "--line",
            "1",
            "--recall",
            "--robot-format",
            "json",
        ],
        vec![
            "--robot-format",
            "json",
            "expand",
            "missing.jsonl",
            "--line",
            "1",
            "--recall",
        ],
        vec!["--robot-format", "json", "search", "query", "--recall"],
        vec!["sessions", "--recall", "--json"],
        vec!["sessions", "--recall", "--robot-format", "jsonl"],
        vec!["timeline", "--recall", "--json"],
        vec!["timeline", "--recall", "--robot-format", "compact"],
    ] {
        Command::new(assert_cmd::cargo::cargo_bin!("cass"))
            .env("HOME", home.path())
            .env("CASS_DATA_DIR", home.path().join("data"))
            .args(&args)
            .assert()
            .code(2)
            .stdout(predicates::str::is_empty())
            .stderr(predicates::str::contains("--recall"));
    }
    assert!(!home.path().join("data").exists());
}

#[test]
fn real_four_commands_keep_the_existing_json_payloads() {
    use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
    use coding_agent_search::storage::sqlite::FrankenStorage;
    use std::process::Command;
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let db = data.join("agent_search.db");
    let source = home.path().join("session.jsonl");
    let storage = FrankenStorage::open(&db).unwrap();
    let agent = storage
        .ensure_agent(&Agent {
            id: None,
            slug: "codex".into(),
            name: "Codex".into(),
            version: None,
            kind: AgentKind::Cli,
        })
        .unwrap();
    let workspace = storage.ensure_workspace(home.path(), None).unwrap();
    storage
        .insert_conversation_tree(
            agent,
            Some(workspace),
            &Conversation {
                id: None,
                agent_slug: "codex".into(),
                workspace: Some(home.path().to_owned()),
                external_id: Some("recall-fixture".into()),
                title: Some("recallformatneedle".into()),
                source_path: source.clone(),
                started_at: Some(1_761_000_000_000),
                ended_at: Some(1_761_000_000_000),
                approx_tokens: None,
                metadata_json: json!({}),
                source_id: "local".into(),
                origin_host: None,
                messages: vec![Message {
                    excluded: None,
                    id: None,
                    idx: 0,
                    role: MessageRole::User,
                    author: None,
                    created_at: Some(1_761_000_000_000),
                    content: "recallformatneedle & <tag> </cass_recall> 中文".into(),
                    extra_json: json!({}),
                    snippets: vec![],
                }],
            },
        )
        .unwrap();
    drop(storage);
    let run = |args: &[&str], format: &str| {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cass"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("CASS_") {
                cmd.env_remove(key);
            }
        }
        let output = cmd
            .current_dir(home.path())
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_DATA_HOME", home.path().join("xdg"))
            .env("CASS_DATA_DIR", &data)
            .env("NO_COLOR", "1")
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .arg("--db")
            .arg(&db)
            .args(args)
            .arg(format)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    for (tool, args) in [
        (
            RecallTool::Search,
            vec![
                "search",
                "recallformatneedle",
                "--mode",
                "lexical",
                "--robot-meta",
            ],
        ),
        (
            RecallTool::Expand,
            vec![
                "expand",
                source.to_str().unwrap(),
                "--line",
                "1",
                "--source",
                "local",
            ],
        ),
        (RecallTool::Sessions, vec!["sessions"]),
        (
            RecallTool::Timeline,
            vec!["timeline", "--since", "2025-01-01", "--until", "2026-01-01"],
        ),
    ] {
        let normal: Value = serde_json::from_slice(&run(&args, "--json")).unwrap();
        let output = run(&args, "--recall");
        let text = std::str::from_utf8(&output).unwrap();
        let recalled = decode(text, tool).unwrap();
        if tool == RecallTool::Search {
            assert_eq!(recalled["hits"], normal["hits"]);
            let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
            assert_eq!(keys(&recalled), keys(&normal));
            assert_eq!(keys(&recalled["_meta"]), keys(&normal["_meta"]));
            assert_eq!(recalled["_meta"]["search_mode"], "lexical");
            assert_eq!(recalled["_meta"]["requested_search_mode"], "lexical");
            assert_eq!(recalled["_meta"]["rerank_applied"], false);
        } else {
            assert_eq!(recalled, normal, "{tool:?}");
        }
        match tool {
            RecallTool::Search => assert!(!normal["hits"].as_array().unwrap().is_empty()),
            RecallTool::Expand => assert_eq!(normal.as_array().unwrap().len(), 1),
            RecallTool::Sessions => assert_eq!(normal["sessions"].as_array().unwrap().len(), 1),
            RecallTool::Timeline => assert_eq!(normal["total_sessions"], 1),
        }
    }
}

#[test]
fn recall_is_discoverable_only_on_the_four_read_commands() {
    use std::process::Command;
    let home = tempfile::tempdir().unwrap();
    for command in ["capabilities", "introspect"] {
        let output = Command::new(assert_cmd::cargo::cargo_bin!("cass"))
            .env("HOME", home.path())
            .env("CASS_DATA_DIR", home.path().join("data"))
            .args([command, "--json"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let schema: Value = serde_json::from_slice(&output.stdout).unwrap();
        for item in schema["commands"].as_array().unwrap() {
            let name = item["name"].as_str().unwrap();
            let recall = item["arguments"]
                .as_array()
                .unwrap()
                .iter()
                .any(|arg| arg["name"] == "recall");
            assert_eq!(
                recall,
                matches!(name, "search" | "expand" | "sessions" | "timeline"),
                "{command}: {name}"
            );
        }
        let search = schema["commands"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "search")
            .unwrap();
        let format = search["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|arg| arg["name"] == "robot-format")
            .unwrap();
        assert!(
            !format["enum_values"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "recall")
        );
    }
}
