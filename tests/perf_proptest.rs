use coding_agent_search::search::canonicalize::{canonicalize_for_embedding, content_hash};
use coding_agent_search::search::query::{MatchType, SearchHit, rrf_fuse_hits};
use proptest::prelude::*;

const TOP_K: usize = 10;

fn text_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9 ]{10,200}",
        "# [A-Z][a-z]{3,10}\\n\\n[a-z ]{20,100}",
        "```rust\\nfn [a-z]{3,8}\\(\\) \\{\\}\\n```",
        "[a-z ]{20,50}\\n\\n```\\n[a-z]{3,10}\\n```\\n\\n[a-z ]{20,50}",
    ]
}

fn make_hit(id: &str, score: f32) -> SearchHit {
    SearchHit {
        title: id.to_string(),
        snippet: String::new(),
        content: id.to_string(),
        content_hash: 0,
        score,
        source_path: format!("/tmp/{id}.jsonl"),
        agent: "test".to_string(),
        workspace: String::new(),
        workspace_original: None,
        created_at: None,
        line_number: Some(1),
        match_type: MatchType::Exact,
        source_id: "local".to_string(),
        origin_kind: "local".to_string(),
        origin_host: None,
        conversation_id: None,
        message_id: None,
        winning_chunk_idx: None,
        winning_chunk_span: None,
        winning_chunk_hash: None,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn canonicalize_is_deterministic(text in text_strategy()) {
        let first = canonicalize_for_embedding(&text);
        let second = canonicalize_for_embedding(&text);
        prop_assert_eq!(first.as_str(), second.as_str());
        prop_assert_eq!(content_hash(&first), content_hash(&second));
    }

    #[test]
    fn rrf_fusion_is_deterministic(scores in prop::collection::vec(0.0f32..1000.0, 1..20)) {
        let lexical: Vec<SearchHit> = scores
            .iter()
            .enumerate()
            .map(|(i, score)| make_hit(&format!("L{i}"), *score))
            .collect();
        let semantic: Vec<SearchHit> = scores
            .iter()
            .enumerate()
            .map(|(i, score)| make_hit(&format!("S{i}"), *score * 0.5))
            .collect();

        let a = rrf_fuse_hits(&lexical, &semantic, "", TOP_K, 0);
        let b = rrf_fuse_hits(&lexical, &semantic, "", TOP_K, 0);

        let keys_a: Vec<(String, Option<usize>)> = a
            .iter()
            .map(|h| (h.source_path.clone(), h.line_number))
            .collect();
        let keys_b: Vec<(String, Option<usize>)> = b
            .iter()
            .map(|h| (h.source_path.clone(), h.line_number))
            .collect();

        prop_assert_eq!(keys_a, keys_b);
    }
}
