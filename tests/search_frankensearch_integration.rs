//! Integration tests for cass's lexical search pipeline and doc_id parsing.
//!
//! W3-5: this file originally verified the frankensearch search migration
//! (bead s3ho2) -- both lexical (tantivy-backed) and vector (fsvi) search
//! routed through the `frankensearch` crate. That crate dependency has since
//! been retired: RRF fusion was verbatim-restored locally into
//! `src/search/frankensearch_rrf.rs` (with its own unit test coverage), and
//! fsvi vector search was replaced by DB-vector-domain search. The tests
//! that exercised `frankensearch::` types directly (fsvi VectorIndex
//! roundtrip, upstream `rrf_fuse`) were retired with the dependency; what
//! remains here is durable coverage independent of that migration: no
//! stray `tantivy::` imports/deps (dependency-hygiene sentinel), doc_id
//! parsing, and `SearchClient`'s lexical BM25 pipeline end-to-end.
//!
//! Earlier W3-5: cass's own `SemanticFilter` (a `frankensearch::core::filter::SearchFilter`
//! adapter over numeric-ID doc_id filtering) was retired alongside the fsvi
//! candidate-search path it existed for -- `search_db_vector_domain` filters
//! via SQL against the relational schema instead. The tests that verified
//! `SemanticFilter`'s trait impl directly were retired with it.

use coding_agent_search::search::query::{FieldMask, SearchClient, SearchFilters};
use coding_agent_search::indexer::persist::persist_conversation;
use coding_agent_search::storage::sqlite::SqliteStorage;
use coding_agent_search::search::vector_index::parse_semantic_doc_id;
use tempfile::TempDir;

mod util;

// =============================================================================
// ZERO TANTIVY IMPORTS AUDIT
// =============================================================================

/// Programmatic verification that no direct `use tantivy::` imports remain in src/.
/// This test reads the source files and ensures all tantivy usage goes through
/// frankensearch re-exports.
#[test]
fn no_direct_tantivy_imports_in_src() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut violations = Vec::new();

    fn scan_dir(dir: &std::path::Path, violations: &mut Vec<String>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_dir(&path, violations);
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && let Ok(content) = std::fs::read_to_string(&path)
            {
                for (line_num, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    // Skip comments
                    if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                        continue;
                    }
                    if trimmed.contains("use tantivy::") {
                        violations.push(format!(
                            "{}:{}: {}",
                            path.display(),
                            line_num + 1,
                            trimmed
                        ));
                    }
                }
            }
        }
    }

    scan_dir(&src_dir, &mut violations);

    assert!(
        violations.is_empty(),
        "Found direct tantivy imports (should use frankensearch::lexical instead):\n{}",
        violations.join("\n")
    );
}

/// Verify Cargo.toml has no direct tantivy dependency.
#[test]
fn no_direct_tantivy_in_cargo_toml() {
    let cargo_toml = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let content = std::fs::read_to_string(cargo_toml).expect("read Cargo.toml");

    // Check [dependencies] section for a direct tantivy = line
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("tantivy") && trimmed.contains('=') {
            panic!(
                "Found direct tantivy dependency in Cargo.toml: {trimmed}\n\
                 tantivy should only be used via frankensearch re-exports"
            );
        }
    }
}

// =============================================================================
// DOC_ID PARSING
// =============================================================================

/// Verify parse_semantic_doc_id is the single parser (no duplicates).
#[test]
fn parse_semantic_doc_id_roundtrip() {
    let hash_hex = "aa".repeat(32);
    let doc_id = format!("m|42|2|3|7|11|1|1700000000000|{hash_hex}");
    let parsed = parse_semantic_doc_id(&doc_id).expect("should parse valid doc_id");

    assert_eq!(parsed.message_id, 42);
    assert_eq!(parsed.chunk_idx, 2);
    assert_eq!(parsed.agent_id, 3);
    assert_eq!(parsed.workspace_id, 7);
    assert_eq!(parsed.source_id, 11);
    assert_eq!(parsed.role, 1);
    assert_eq!(parsed.created_at_ms, 1_700_000_000_000);
    assert!(parsed.content_hash.is_some(), "should parse content hash");
}

/// Verify doc_id without content hash still parses.
#[test]
fn parse_semantic_doc_id_without_hash() {
    let doc_id = "m|100|0|5|10|20|1|1700000000000";
    let parsed = parse_semantic_doc_id(doc_id).expect("should parse doc_id without hash");

    assert_eq!(parsed.message_id, 100);
    assert_eq!(parsed.chunk_idx, 0);
    assert!(parsed.content_hash.is_none(), "should have no content hash");
}

/// Invalid doc_id formats return None.
#[test]
fn parse_semantic_doc_id_rejects_invalid() {
    assert!(parse_semantic_doc_id("").is_none());
    assert!(parse_semantic_doc_id("not-a-doc-id").is_none());
    assert!(parse_semantic_doc_id("x|1|2|3|4|5|6|7").is_none()); // wrong prefix
    assert!(parse_semantic_doc_id("m|abc|2|3|4|5|6|7").is_none()); // non-numeric
    assert!(parse_semantic_doc_id("m|1|2|3").is_none()); // too few fields
}

// =============================================================================
// LEXICAL SEARCH THROUGH FRANKENSEARCH
// =============================================================================

/// Verify that lexical search through SearchClient works end-to-end.
/// This validates the full pipeline: frankensearch::lexical types → BM25 scoring.
#[test]
fn lexical_search_through_frankensearch_pipeline() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("agent_search.db");
    let storage = SqliteStorage::open(&db_path).unwrap();

    let conv = util::ConversationFixtureBuilder::new("claude_code")
        .title("frankensearch integration test")
        .source_path(dir.path().join("session.jsonl"))
        .base_ts(1_700_000_000_000)
        .messages(3)
        .with_content(0, "The authentication module handles OAuth2 flows")
        .with_content(1, "Token refresh uses exponential backoff strategy")
        .with_content(2, "Rate limiting prevents abuse of the API endpoint")
        .build_normalized();

    persist_conversation(&storage, &conv).unwrap();

    let client = SearchClient::open(dir.path(), Some(&db_path))
        .unwrap()
        .expect("client");
    let filters = SearchFilters::default();

    // Exact term search
    let hits = client
        .search("authentication", filters.clone(), 10, 0, FieldMask::FULL)
        .unwrap();
    assert!(
        !hits.is_empty(),
        "should find 'authentication' via frankensearch BM25"
    );
    assert!(hits[0].content.contains("authentication"));

    // Prefix wildcard search
    let hits = client
        .search("auth*", filters.clone(), 10, 0, FieldMask::FULL)
        .unwrap();
    assert!(!hits.is_empty(), "should match auth* prefix");

    // Multi-term search
    let hits = client
        .search("token refresh", filters, 10, 0, FieldMask::FULL)
        .unwrap();
    assert!(!hits.is_empty(), "should find multi-term query");
}

/// Verify agent filter works through the frankensearch pipeline.
#[test]
fn agent_filter_through_frankensearch_pipeline() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("agent_search.db");
    let storage = SqliteStorage::open(&db_path).unwrap();

    let conv_claude = util::ConversationFixtureBuilder::new("claude_code")
        .title("claude session")
        .source_path(dir.path().join("claude.jsonl"))
        .base_ts(1_700_000_000_000)
        .messages(1)
        .with_content(0, "debugging the database connection pool")
        .build_normalized();

    let conv_codex = util::ConversationFixtureBuilder::new("codex")
        .title("codex session")
        .source_path(dir.path().join("codex.jsonl"))
        .base_ts(1_700_000_001_000)
        .messages(1)
        .with_content(0, "debugging the cache invalidation logic")
        .build_normalized();

    persist_conversation(&storage, &conv_claude).unwrap();
    persist_conversation(&storage, &conv_codex).unwrap();

    let client = SearchClient::open(dir.path(), Some(&db_path))
        .unwrap()
        .expect("client");

    // Search with agent filter
    let mut filters = SearchFilters::default();
    filters.agents.insert("claude_code".to_string());

    let hits = client
        .search("debugging", filters, 10, 0, FieldMask::FULL)
        .unwrap();

    // Should only find claude_code results
    assert!(!hits.is_empty());
    for hit in &hits {
        assert_eq!(
            hit.agent, "claude_code",
            "agent filter should only return claude_code results"
        );
    }
}

// =============================================================================
// SEARCH RESULT CONSISTENCY
// =============================================================================

/// Verify that multiple searches with the same query produce identical results.
/// This tests determinism of the frankensearch pipeline.
#[test]
fn search_results_are_deterministic() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("agent_search.db");
    let storage = SqliteStorage::open(&db_path).unwrap();

    let conv = util::ConversationFixtureBuilder::new("claude_code")
        .title("determinism test")
        .source_path(dir.path().join("session.jsonl"))
        .base_ts(1_700_000_000_000)
        .messages(5)
        .with_content(0, "error handling in the authentication module")
        .with_content(1, "authentication token validation logic")
        .with_content(2, "error recovery from network failures")
        .with_content(3, "database query optimization techniques")
        .with_content(4, "authentication flow diagram and documentation")
        .build_normalized();

    persist_conversation(&storage, &conv).unwrap();

    let client = SearchClient::open(dir.path(), Some(&db_path))
        .unwrap()
        .expect("client");
    let filters = SearchFilters::default();

    // Run same query 3 times
    let hits1 = client
        .search("authentication", filters.clone(), 10, 0, FieldMask::FULL)
        .unwrap();
    let hits2 = client
        .search("authentication", filters.clone(), 10, 0, FieldMask::FULL)
        .unwrap();
    let hits3 = client
        .search("authentication", filters, 10, 0, FieldMask::FULL)
        .unwrap();

    // Same number of results
    assert_eq!(hits1.len(), hits2.len());
    assert_eq!(hits2.len(), hits3.len());

    // Same ordering (compare source_path + line_number as stable identifiers)
    for i in 0..hits1.len() {
        assert_eq!(
            hits1[i].source_path, hits2[i].source_path,
            "result {i} source_path should be deterministic"
        );
        assert_eq!(
            hits1[i].line_number, hits2[i].line_number,
            "result {i} line_number should be deterministic"
        );
    }
}

/// Verify SearchClient produces results with expected field population.
#[test]
fn search_results_have_expected_fields() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("agent_search.db");
    let storage = SqliteStorage::open(&db_path).unwrap();

    let conv = util::ConversationFixtureBuilder::new("claude_code")
        .title("field test session")
        .source_path(dir.path().join("session.jsonl"))
        .base_ts(1_700_000_000_000)
        .messages(1)
        .with_content(
            0,
            "testing that all search hit fields are populated correctly",
        )
        .build_normalized();

    persist_conversation(&storage, &conv).unwrap();

    let client = SearchClient::open(dir.path(), Some(&db_path))
        .unwrap()
        .expect("client");
    let filters = SearchFilters::default();

    let hits = client
        .search("testing", filters, 10, 0, FieldMask::FULL)
        .unwrap();

    assert!(!hits.is_empty());
    let hit = &hits[0];

    assert!(!hit.content.is_empty(), "content should be populated");
    assert!(
        !hit.source_path.is_empty(),
        "source_path should be populated"
    );
    assert!(!hit.agent.is_empty(), "agent should be populated");
    assert_eq!(hit.agent, "claude_code");
    assert!(hit.score > 0.0, "score should be positive");
}
