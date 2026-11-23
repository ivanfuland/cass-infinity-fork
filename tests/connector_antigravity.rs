//! cass-level integration tests for the Antigravity (agy) connector.
//!
//! These exercise the connector through cass's re-export
//! (`coding_agent_search::connectors::antigravity`) against a checked-in fixture
//! that mirrors agy's on-disk layout
//! (`<base>/brain/<uuid>/.system_generated/logs/transcript.jsonl` plus the
//! sibling `<base>/conversations/<uuid>.db`). The normalized conversations these
//! produce are exactly what cass's indexer + FTS search consume, so verifying the
//! scan here proves the index/search path covers agy. A companion check confirms
//! the legacy Gemini CLI connector is unaffected (bd-47kjh.3.3).
//!
//! NOTE: the agy connector defaults to the REAL `~/.gemini/antigravity-cli` when
//! `scan_roots` is empty, so every test passes an explicit `ScanRoot` at the
//! fixture base — never relying on default detection.

use coding_agent_search::connectors::antigravity::AntigravityConnector;
use coding_agent_search::connectors::gemini::GeminiConnector;
use coding_agent_search::connectors::{Connector, DiscoveredSourceRole, ScanContext, ScanRoot};
use std::fs;
use std::path::PathBuf;

const FIXTURE_UUID: &str = "aaaa1111-bbbb-2222-cccc-333344445555";

fn fixture_base() -> PathBuf {
    PathBuf::from("tests/fixtures/antigravity")
}

/// A scan context rooted explicitly at the fixture (never the real ~/.gemini).
fn fixture_ctx() -> ScanContext {
    let base = fixture_base();
    ScanContext {
        data_dir: base.clone(),
        scan_roots: vec![ScanRoot::local(base)],
        since_ts: None,
    }
}

fn only_conversation() -> coding_agent_search::connectors::NormalizedConversation {
    let convs = AntigravityConnector::new()
        .scan(&fixture_ctx())
        .expect("scan");
    assert_eq!(convs.len(), 1, "fixture is a single agy conversation");
    convs.into_iter().next().unwrap()
}

#[test]
fn antigravity_scans_fixture_into_one_conversation() {
    let c = only_conversation();
    assert_eq!(c.agent_slug, "antigravity");
    assert_eq!(c.external_id.as_deref(), Some(FIXTURE_UUID));
    assert!(
        c.source_path
            .to_string_lossy()
            .ends_with("transcript_full.jsonl"),
        "source_path should prefer transcript_full.jsonl when present"
    );
}

#[test]
fn antigravity_pins_model_from_settings_change() {
    let c = only_conversation();
    assert_eq!(
        c.metadata.get("model").and_then(|v| v.as_str()),
        Some("Gemini 3.1 Pro (High)"),
        "model must be extracted from the <USER_SETTINGS_CHANGE> wrapper"
    );
    assert_eq!(
        c.metadata.get("source").and_then(|v| v.as_str()),
        Some("antigravity")
    );
}

#[test]
fn antigravity_maps_all_roles() {
    let c = only_conversation();
    assert!(c.messages.iter().any(|m| m.role == "user"));
    assert!(c.messages.iter().any(|m| m.role == "assistant"));
    assert!(c.messages.iter().any(|m| m.role == "reasoning"));
    assert!(c.messages.iter().any(|m| m.role == "tool_call"));
    assert!(c.messages.iter().any(|m| m.role == "tool_result"));
    assert!(c.messages.iter().any(|m| m.role == "system"));
    // CONVERSATION_HISTORY (null content) is dropped; PLANNER_RESPONSE with
    // thinking+content splits into reasoning+assistant, and RUN_COMMAND with
    // tool_calls splits into tool_call+tool_result -> 9 canonical messages.
    assert_eq!(c.messages.len(), 9);
    for (i, m) in c.messages.iter().enumerate() {
        assert_eq!(m.idx, i64::try_from(i).unwrap());
        assert!(
            m.extra
                .get("raw_role")
                .and_then(|v| v.as_str())
                .is_some_and(|r| !r.is_empty()),
            "every message must carry non-empty raw_role"
        );
    }
}

#[test]
fn antigravity_unwraps_user_request_and_keeps_settings() {
    let c = only_conversation();
    let user = c.messages.iter().find(|m| m.role == "user").unwrap();
    assert!(user.content.contains("FLYWHEEL"));
    assert!(!user.content.contains("USER_REQUEST"));
    assert!(
        user.extra
            .get("settings_change")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.contains("Gemini 3.1 Pro (High)"))
    );
}

#[test]
fn antigravity_preserves_thinking_on_planner_response() {
    let c = only_conversation();
    let reasoning = c
        .messages
        .iter()
        .find(|m| m.role == "reasoning")
        .expect("a reasoning message emitted from PLANNER_RESPONSE.thinking");
    assert!(reasoning.content.contains("grep_search"));
    assert_eq!(
        reasoning.extra.get("raw_role").and_then(|v| v.as_str()),
        Some("assistant")
    );
}

#[test]
fn antigravity_tool_steps_carry_invocations() {
    let c = only_conversation();
    // VIEW_FILE without tool_calls -> unpaired tool_result with synthesized author.
    let view = c
        .messages
        .iter()
        .find(|m| m.extra.get("agy_type").and_then(|v| v.as_str()) == Some("VIEW_FILE"))
        .expect("VIEW_FILE message");
    assert_eq!(view.role, "tool_result");
    assert_eq!(view.author.as_deref(), Some("view_file"));
    assert_eq!(view.extra.get("unpaired").and_then(|v| v.as_bool()), Some(true));
    assert!(view.content.contains("FLYWHEEL"));

    // RUN_COMMAND -> structured grep_search tool_call + paired tool_result.
    let run_call = c
        .messages
        .iter()
        .find(|m| m.role == "tool_call" && m.invocations.iter().any(|i| i.name == "grep_search"))
        .expect("grep_search tool_call");
    assert_eq!(
        run_call.invocations[0]
            .arguments
            .as_ref()
            .and_then(|a| a.get("query"))
            .and_then(|v| v.as_str()),
        Some("FLYWHEEL")
    );
    let run_result = c
        .messages
        .iter()
        .find(|m| {
            m.role == "tool_result"
                && m.extra.get("tool_call_id").and_then(|v| v.as_str()) == Some("call_grep_01")
        })
        .expect("paired grep_search tool_result");
    assert!(run_result.content.contains("FLYWHEEL"));
}

/// The content cass's FTS would index must contain the searchable marker — this
/// is the scan-level proxy for "search a real agy conversation". The generic
/// index+search machinery covers any registered connector, so a present,
/// correctly-roled marker here means it is findable end-to-end.
#[test]
fn antigravity_indexable_content_contains_searchable_marker() {
    let c = only_conversation();
    let haystack: String = c
        .messages
        .iter()
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        haystack.contains("FLYWHEEL") && haystack.contains("42"),
        "indexable conversation text must contain the searchable FLYWHEEL/42 marker"
    );
}

#[test]
fn antigravity_discovers_transcript_and_db_sources() {
    let discovered = AntigravityConnector::new()
        .discover_source_files(&fixture_ctx())
        .expect("discover");
    assert!(discovered.iter().all(|d| d.provider_slug == "antigravity"));
    let primaries: Vec<_> = discovered
        .iter()
        .filter(|d| d.role == DiscoveredSourceRole::PrimarySessionLog)
        .collect();
    assert_eq!(
        primaries.len(),
        1,
        "directory discovery emits only the sole primary transcript"
    );
    assert!(
        primaries[0].source_path.ends_with("transcript_full.jsonl")
            && primaries[0].required_for_reconstruction
    );
    assert!(
        discovered
            .iter()
            .any(|d| d.role == DiscoveredSourceRole::SqliteDatabase
                && d.source_path.extension().is_some_and(|e| e == "db")),
        "the conversations/<uuid>.db must be discovered for archival"
    );
}

#[test]
fn antigravity_ignores_legacy_gemini_layout_under_shared_dot_gemini() {
    // Both agy and the legacy Gemini CLI live under ~/.gemini. Rooted at the
    // shared parent containing BOTH layouts, the agy connector must resolve only
    // the agy conversation.
    let tmp = tempfile::TempDir::new().unwrap();
    let dot_gemini = tmp.path().join(".gemini");

    let chats = dot_gemini.join("tmp").join("deadbeef").join("chats");
    fs::create_dir_all(&chats).unwrap();
    fs::write(chats.join("session-1.json"), "{\"messages\":[]}").unwrap();

    let logs = dot_gemini
        .join("antigravity-cli")
        .join("brain")
        .join("99990000-1111-2222-3333-444455556666")
        .join(".system_generated")
        .join("logs");
    fs::create_dir_all(&logs).unwrap();
    fs::write(
        logs.join("transcript.jsonl"),
        "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"status\":\"DONE\",\"created_at\":\"2026-06-11T20:14:42Z\",\"content\":\"<USER_REQUEST>\\nhi\\n</USER_REQUEST>\"}\n",
    )
    .unwrap();

    let base = dot_gemini.clone();
    let ctx = ScanContext {
        data_dir: base.clone(),
        scan_roots: vec![ScanRoot::local(base)],
        since_ts: None,
    };
    let convs = AntigravityConnector::new().scan(&ctx).expect("scan");
    assert_eq!(convs.len(), 1, "only the agy conversation should be found");
    assert_eq!(convs[0].agent_slug, "antigravity");
}

/// The migration must not regress the legacy Gemini CLI connector: its own
/// fixture still scans into conversations labeled "gemini".
#[test]
fn legacy_gemini_connector_still_indexes() {
    let ctx = ScanContext {
        data_dir: PathBuf::from("tests/fixtures/gemini"),
        scan_roots: Vec::new(),
        since_ts: None,
    };
    let convs = GeminiConnector::new().scan(&ctx).expect("gemini scan");
    assert!(!convs.is_empty(), "legacy gemini fixture must still index");
    assert!(convs.iter().all(|c| c.agent_slug == "gemini"));
}
