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
//! The semantic path's equivalent coverage -- an explicit `--role`
//! overriding the semantic engine's default user+assistant role filter --
//! previously lived here as `role_filter_semantic_mode_role_overrides_default`
//! (a `cass index --semantic --embedder hash` + CLI roundtrip). W3-5 retired
//! both the `--embedder hash` fsvi path (4064e8fc) and the `SemanticFilter`
//! machinery that test's doc comment described
//! (`search_semantic_candidates`/`SemanticFilter::from_search_filters`,
//! 6abe79b5), leaving it permanently broken and untested for two commits.
//! Deleted rather than repaired: the same override-vs-default contract is
//! covered at the `search_db_vector_domain` level (the DB-vector-domain
//! successor) by
//! `search::query::tests::db_vector_domain_filter_fidelity_role_default_user_and_assistant`
//! and `search::query::tests::db_vector_domain_filter_fidelity_role_explicit_overrides_default`
//! in `src/search/query.rs`, which assert the identical default-fallback and
//! explicit-override semantics without depending on a retired embedder path.

use std::collections::HashSet;

use coding_agent_search::connectors::{NormalizedConversation, NormalizedMessage};
use coding_agent_search::indexer::persist::persist_conversation;
use coding_agent_search::search::query::{FieldMask, SearchClient, SearchFilters};
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
    let storage = FrankenStorage::open(&db_path).unwrap();

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
    persist_conversation(&storage, &normalized).unwrap();

    let client = SearchClient::open(data_dir, Some(&db_path))
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
    let storage = FrankenStorage::open(&db_path).unwrap();

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
    persist_conversation(&storage, &normalized).unwrap();

    let client = SearchClient::open(data_dir, Some(&db_path))
        .unwrap()
        .expect("client");

    // Sanity: without a role filter, limit=1 returns a (high-ranking user) hit.
    let baseline = client
        .search(
            unique_token,
            SearchFilters::default(),
            1,
            0,
            FieldMask::FULL,
        )
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

