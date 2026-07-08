//! Integration test for the `search --role` CLI filter (Task 2.2b).
//!
//! `SearchFilters.roles` must be threaded through the lexical (Tantivy) query
//! path and hydrated from SQLite (Tantivy itself carries no role field), and
//! must be honored consistently regardless of engine. This builds a small
//! fixture with matching conversation_id/idx across a real SQLite DB
//! (`FrankenStorage`, for message role lookups) and a real Tantivy index
//! (`TantivyIndex`, for the actual text search) via the production
//! `persist_conversation` path — which stamps the same `conversation_id` into
//! both engines and, crucially, materializes the on-disk SQLite file so a
//! read-only `SearchClient` can hydrate roles from it. It then asserts:
//! - `--role tool` recalls a tool result containing a unique token
//! - `--role user` does not mix that tool result in
//!
//! [`role_filter_semantic_mode_role_overrides_default`] below extends this
//! to the semantic path: the lexical test above only exercises
//! `client.search()` (pure lexical), so the riskiest untested logic --
//! an explicit `--role` overriding the semantic engine's default
//! user+assistant role filter (`src/search/query.rs`
//! `search_semantic_candidates`, and `SemanticFilter::from_search_filters`
//! in `src/search/vector_index.rs`) -- had no coverage at all.

use std::collections::HashSet;

use assert_cmd::cargo::cargo_bin_cmd;
use coding_agent_search::connectors::{NormalizedConversation, NormalizedMessage};
use coding_agent_search::indexer::persist::persist_conversation;
use coding_agent_search::search::query::{FieldMask, SearchClient, SearchFilters};
use coding_agent_search::search::tantivy::{TantivyIndex, index_dir};
use coding_agent_search::search::vector_index::role_code_from_str;
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde_json::{Value, json};
use tempfile::TempDir;

mod util;
use util::EnvGuard;

#[test]
fn role_filter_tool_matches_tool_result_not_user_message() {
    let dir = TempDir::new().unwrap();
    let unique_token = "rolefiltermarkerx9k2z7abc";

    // A user message (idx 0) and a tool_result message (idx 1) both live in one
    // conversation; only the tool_result carries the unique token. Persist it
    // through the production path so SQLite (`messages.role`) and Tantivy share
    // one conversation_id and the SQLite file is flushed to disk.
    let data_dir = dir.path();
    let db_path = data_dir.join("agent_search.db");
    let index_path = index_dir(data_dir).expect("index path");
    let storage = FrankenStorage::open(&db_path).unwrap();
    let mut index = TantivyIndex::open_or_create(&index_path).unwrap();

    let source_path = data_dir.join("role-filter.jsonl");
    let normalized = NormalizedConversation {
        agent_slug: "tester".into(),
        external_id: Some("role-filter".into()),
        title: Some("role filter test".into()),
        workspace: None,
        source_path,
        started_at: Some(3000),
        ended_at: Some(3001),
        metadata: json!({}),
        messages: vec![
            NormalizedMessage {
                idx: 0,
                role: "user".into(),
                author: Some("user".into()),
                created_at: Some(3000),
                content: "Investigate the flaky integration test failure across the CI pipeline."
                    .into(),
                extra: json!({}),
                snippets: vec![],
                invocations: Vec::new(),
            },
            NormalizedMessage {
                idx: 1,
                role: "tool_result".into(),
                author: Some("tool".into()),
                created_at: Some(3001),
                content: format!(
                    "Command output: {unique_token} returned 3 matching files in the build directory."
                ),
                extra: json!({}),
                snippets: vec![],
                invocations: Vec::new(),
            },
        ],
    };
    persist_conversation(&storage, &mut index, &normalized).unwrap();
    index.commit().unwrap();

    let client = SearchClient::open(&index_path, Some(&db_path))
        .unwrap()
        .expect("client");

    // `--role tool` should recall the tool_result message.
    let mut tool_filters = SearchFilters::default();
    tool_filters.roles = Some(HashSet::from([role_code_from_str("tool").unwrap()]));
    let tool_hits = client
        .search(unique_token, tool_filters, 10, 0, FieldMask::FULL)
        .unwrap();
    assert!(
        !tool_hits.is_empty(),
        "--role tool should recall tool_result messages"
    );

    // `--role user` must not mix the tool_result message in.
    let mut user_filters = SearchFilters::default();
    user_filters.roles = Some(HashSet::from([role_code_from_str("user").unwrap()]));
    let user_hits = client
        .search(unique_token, user_filters, 10, 0, FieldMask::FULL)
        .unwrap();
    assert!(
        user_hits.is_empty(),
        "--role user should not recall tool_result messages"
    );

    println!("ROLE_CLI_OK");
}

/// Regression (codex Phase-2 P1 #1): `--role` recall in the lexical path must
/// survive the role-matching hit ranking BELOW the default small fetch window.
///
/// `--role` is applied post-hoc in `postprocess_hits_page` (Tantivy has no role
/// field), operating on an already-fetched hit window sized ~2-3x
/// `offset+limit`. The dedup/shortfall retry previously only widened its fetch
/// for `session_paths`, NOT `roles`. So when many higher-BM25 user/assistant
/// hits outrank the single `tool_result` hit, `search X --role tool --limit 1`
/// returned EMPTY even though the tool_result exists. The fix makes
/// `fallback_fetch_limit` role-aware (over-fetch capped at
/// `no_limit_result_cap()`), mirroring the session-path treatment.
///
/// This fixture forces the `tool_result` to the bottom of the ranking: six
/// short user messages repeat the query token (high term frequency) while the
/// lone `tool_result` carries the token once buried in long filler (low BM25),
/// so it ranks well below the old 3-hit fallback window. RED before the fix
/// (empty result), GREEN after.
#[test]
fn role_filter_lexical_recalls_tool_result_ranked_below_default_window() {
    let dir = TempDir::new().unwrap();
    let unique_token = "rankbelowmarkerq4w8e2rst";

    let data_dir = dir.path();
    let db_path = data_dir.join("agent_search.db");
    let index_path = index_dir(data_dir).expect("index path");
    let storage = FrankenStorage::open(&db_path).unwrap();
    let mut index = TantivyIndex::open_or_create(&index_path).unwrap();

    // Six short, high-TF user messages that will outrank the tool_result.
    let mut messages: Vec<NormalizedMessage> = (0..6)
        .map(|i| NormalizedMessage {
            idx: i,
            role: "user".into(),
            author: Some("user".into()),
            created_at: Some(4000 + i),
            content: format!(
                "{unique_token} {unique_token} {unique_token} {unique_token} short high frequency hit {i}"
            ),
            extra: json!({}),
            snippets: vec![],
            invocations: Vec::new(),
        })
        .collect();

    // One tool_result with the token buried once in long low-signal filler, so
    // BM25 ranks it last — below the default fallback window.
    let filler = "output line diagnostics build cache pipeline step artifact log trace metric \
                  status queue worker retry backoff timeout heartbeat scan watermark ingest "
        .repeat(6);
    messages.push(NormalizedMessage {
        idx: 6,
        role: "tool_result".into(),
        author: Some("tool".into()),
        created_at: Some(4100),
        content: format!("Command output. {filler} {unique_token} {filler} end of output."),
        extra: json!({}),
        snippets: vec![],
        invocations: Vec::new(),
    });

    let normalized = NormalizedConversation {
        agent_slug: "tester".into(),
        external_id: Some("role-rank".into()),
        title: Some("role rank test".into()),
        workspace: None,
        source_path: data_dir.join("role-rank.jsonl"),
        started_at: Some(4000),
        ended_at: Some(4101),
        metadata: json!({}),
        messages,
    };
    persist_conversation(&storage, &mut index, &normalized).unwrap();
    index.commit().unwrap();

    let client = SearchClient::open(&index_path, Some(&db_path))
        .unwrap()
        .expect("client");

    // Sanity: without a role filter, limit=1 returns a (high-ranking user) hit.
    let baseline = client
        .search(unique_token, SearchFilters::default(), 1, 0, FieldMask::FULL)
        .unwrap();
    assert_eq!(baseline.len(), 1, "baseline limit=1 should return one hit");

    // The crux: --role tool --limit 1 must still recall the low-ranked
    // tool_result (RED before the over-fetch fix: empty).
    let mut tool_filters = SearchFilters::default();
    tool_filters.roles = Some(HashSet::from([role_code_from_str("tool").unwrap()]));
    let tool_hits = client
        .search(unique_token, tool_filters, 1, 0, FieldMask::FULL)
        .unwrap();
    assert_eq!(
        tool_hits.len(),
        1,
        "--role tool --limit 1 must recall the tool_result even when it ranks \
         below the default fetch window"
    );

    println!("ROLE_RANK_OK");
}

/// Semantic-path regression coverage for the `--role` override (Task 2.2b
/// review finding: the shipped test only covered the lexical path).
///
/// Uses the `--embedder hash` offline harness already established by
/// `tests/e2e_semantic_search.rs` (e.g. `search_semantic_mode_returns_results`,
/// which asserts unconditional success, not "may fail if model not
/// installed" like the CLI-driven tests in `tests/semantic_integration.rs`
/// that never build a vector index at all). The hash embedder needs no
/// live Infinity/ML backend, so this runs deterministically in a normal
/// `cargo test`.
///
/// The semantic engine's role filter (`SemanticFilter::matches`, wired up
/// via `context.roles` / `SemanticFilter::from_search_filters` in
/// `src/search/query.rs` and `src/search/vector_index.rs`) is a hard
/// pre-scoring filter, not a ranking signal -- a role outside the active
/// filter set can never appear in results regardless of embedding
/// similarity. That makes "does the tool_result's unique marker show up in
/// any hit's content" a robust assertion even against the hash embedder's
/// crude similarity (unlike asserting "hits is non-empty", which the hash
/// embedder can satisfy with irrelevant matches from the *other*
/// in-scope messages).
#[test]
fn role_filter_semantic_mode_role_overrides_default() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.join(".codex");
    let data_dir = home.join("cass_data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    let unique_token = "rolesemanticmarkerz7q3k9def";

    // A user message and an assistant message (neither mentions the
    // marker) plus a standalone `function_call_output` -- normalized to
    // role `tool_result` / `ROLE_TOOL` by the Codex connector -- carrying
    // the unique marker. The semantic engine's default context.roles is
    // {user, assistant} (see `load_hash_semantic_context` et al.), so
    // without an explicit `--role` the tool_result must never surface;
    // with `--role tool` it must.
    let sessions = codex_home.join("sessions/2026/04/23");
    std::fs::create_dir_all(&sessions).unwrap();
    let filename = "rollout-role-semantic.jsonl";
    let workspace = codex_home.to_string_lossy().into_owned();
    let lines = [
        json!({
            "timestamp": "2026-04-23T00:00:00Z",
            "type": "session_meta",
            "payload": { "id": filename, "cwd": workspace, "cli_version": "0.42.0" },
        }),
        json!({
            "timestamp": "2026-04-23T00:00:01Z",
            "type": "response_item",
            "payload": {
                "type": "message", "role": "user",
                "content": [{ "type": "input_text", "text": "Investigate the flaky integration test failure across the CI pipeline." }],
            },
        }),
        json!({
            "timestamp": "2026-04-23T00:00:02Z",
            "type": "response_item",
            "payload": {
                "type": "message", "role": "assistant",
                "content": [{ "type": "text", "text": "I will check the CI logs for the pipeline failure." }],
            },
        }),
        json!({
            "timestamp": "2026-04-23T00:00:03Z",
            "type": "response_item",
            "payload": {
                "type": "function_call_output",
                "call_id": "call-role-semantic-1",
                "output": format!(
                    "Command output: {unique_token} returned 3 matching files in the build directory."
                ),
            },
        }),
    ];
    let mut body = String::new();
    for line in &lines {
        body.push_str(&serde_json::to_string(line).unwrap());
        body.push('\n');
    }
    std::fs::write(sessions.join(filename), body).unwrap();

    cargo_bin_cmd!("cass")
        .args([
            "index",
            "--full",
            "--semantic",
            "--embedder",
            "hash",
            "--data-dir",
        ])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .assert()
        .success();

    // `--role tool` must override the semantic default and recall the
    // tool_result message. `--model hash` is required here: with no
    // explicit model, `run_cli_search`'s embedder resolution (`else`
    // branch of the prefer_hash/requested_model chain in `src/lib.rs`)
    // falls through to the policy-default *quality tier* embedder
    // (minilm) rather than the hash embedder actually indexed above, and
    // that ONNX model isn't installed in this offline test environment --
    // confirmed by reproducing the same "consent required for model
    // download" failure on the *existing*, unmodified
    // `e2e_semantic_search.rs::search_semantic_mode_returns_results` test
    // under this crate's `infinity` feature build.
    let override_output = cargo_bin_cmd!("cass")
        .args([
            "search",
            unique_token,
            "--mode",
            "semantic",
            "--model",
            "hash",
            "--role",
            "tool",
            "--robot",
            "--limit",
            "10",
            "--data-dir",
        ])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .output()
        .expect("search --mode semantic --role tool");
    assert!(
        override_output.status.success(),
        "semantic search with --role tool failed: {}",
        String::from_utf8_lossy(&override_output.stderr)
    );
    let override_json: Value = serde_json::from_slice(&override_output.stdout)
        .expect("semantic --role tool output should be valid JSON");
    let override_hits = override_json
        .get("hits")
        .and_then(|v| v.as_array())
        .expect("hits must be an array");
    assert!(
        override_hits.iter().any(|hit| hit
            .get("content")
            .and_then(|c| c.as_str())
            .is_some_and(|c| c.contains(unique_token))),
        "--role tool should override the semantic default and recall the \
         tool_result message; got: {override_json}"
    );

    // Default (no --role, but still --model hash so this test isolates the
    // role override rather than embedder resolution): the same message
    // must stay excluded from the semantic candidate pool by the engine's
    // user+assistant default.
    let default_output = cargo_bin_cmd!("cass")
        .args([
            "search",
            unique_token,
            "--mode",
            "semantic",
            "--model",
            "hash",
            "--robot",
            "--limit",
            "10",
            "--data-dir",
        ])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .output()
        .expect("search --mode semantic (default roles)");
    assert!(
        default_output.status.success(),
        "semantic search (default roles) failed: {}",
        String::from_utf8_lossy(&default_output.stderr)
    );
    let default_json: Value = serde_json::from_slice(&default_output.stdout)
        .expect("semantic default output should be valid JSON");
    let default_hits = default_json
        .get("hits")
        .and_then(|v| v.as_array())
        .expect("hits must be an array");
    assert!(
        !default_hits.iter().any(|hit| hit
            .get("content")
            .and_then(|c| c.as_str())
            .is_some_and(|c| c.contains(unique_token))),
        "without --role, the semantic default (user+assistant) must NOT \
         recall the tool_result message; got: {default_json}"
    );

    println!("ROLE_SEMANTIC_OVERRIDE_OK");
}
