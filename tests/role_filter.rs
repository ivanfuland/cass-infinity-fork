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

use std::collections::HashSet;

use coding_agent_search::connectors::{NormalizedConversation, NormalizedMessage};
use coding_agent_search::indexer::persist::persist_conversation;
use coding_agent_search::search::query::{FieldMask, SearchClient, SearchFilters};
use coding_agent_search::search::tantivy::{TantivyIndex, index_dir};
use coding_agent_search::search::vector_index::role_code_from_str;
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde_json::json;
use tempfile::TempDir;

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
