// R1-W3-N3 (2026-09-02 W3 PR round-1 review, task book #68):
// `find_reusable_or_create_generation` used to only look for an identity-
// matching generation whose `audit_status` was still `'pending'`. A
// steady-state corpus -- the active generation is `passed`, holes_after
// already zero, nothing new since certification -- never matched that
// query, so every single catch-up call (including a routine hourly
// production cron with zero real work to do) created a brand-new, empty
// generation and re-seeded + re-embedded the *entire* corpus from scratch.
// This whole-file `#![cfg(feature = "infinity")]` gate matches
// `tests/w3_vector_generation_cleanup.rs`'s own rationale: the module
// under test is itself `infinity`-feature-gated in `src/indexer/mod.rs`.
#![cfg(feature = "infinity")]

use coding_agent_search::indexer::db_vector_catchup::run_db_vector_catchup_backfill;
use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::storage::api::Value as V;
use coding_agent_search::storage::sqlite::FrankenStorage;

macro_rules! fparams {
    ($($val:expr),+ $(,)?) => {
        &[$(coding_agent_search::storage::api::IntoValue::into_value($val)),+] as &[V]
    };
}

const TS: i64 = 1_770_551_400_000;

fn open_storage(path: &std::path::Path) -> FrankenStorage {
    FrankenStorage::open(path).expect("open production storage")
}

fn ensure_agent(storage: &FrankenStorage) -> i64 {
    storage
        .ensure_agent(&Agent {
            id: None,
            slug: "claude_code".into(),
            name: "Claude Code".into(),
            version: Some("1.0".into()),
            kind: AgentKind::Cli,
        })
        .expect("ensure agent")
}

fn insert_one_message_conversation(storage: &FrankenStorage, external_id: &str, content: &str) {
    let agent_id = ensure_agent(storage);
    let conv = Conversation {
        id: None,
        agent_slug: "claude_code".into(),
        workspace: None,
        external_id: Some(external_id.into()),
        title: Some("w3-n3 generation reuse fixture".into()),
        source_path: std::path::PathBuf::from(format!("/fixtures/{external_id}.jsonl")),
        started_at: Some(TS),
        ended_at: Some(TS + 60_000),
        approx_tokens: None,
        metadata_json: serde_json::Value::Null,
        messages: vec![Message {
            id: None,
            idx: 0,
            role: MessageRole::User,
            author: None,
            created_at: Some(TS),
            content: content.to_string(),
            extra_json: serde_json::Value::Null,
            snippets: vec![],
        }],
        source_id: "local".into(),
        origin_host: None,
    };
    storage.insert_conversation_tree(agent_id, None, &conv).expect("insert fixture conversation");
}

fn embedding_generations_count(storage: &FrankenStorage) -> i64 {
    storage.raw().query_row_map("SELECT COUNT(*) FROM embedding_generations", &[] as &[V], |row| row.get_typed(0)).unwrap()
}

fn message_embeddings_count_for(storage: &FrankenStorage, generation_id: i64) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM message_embeddings WHERE generation_id = ?1",
            fparams![generation_id],
            |row| row.get_typed(0),
        )
        .unwrap()
}

#[test]
#[ignore = "requires a live Infinity service at 127.0.0.1:7997 (CASS_INFINITY_URL)"]
fn steady_state_rerun_reuses_the_active_generation_without_re_embedding() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("agent_search.db");
    let storage = open_storage(&db_path);

    // Genesis: one real, embeddable message activates a fresh generation.
    insert_one_message_conversation(&storage, "w3-n3-genesis", "the quick brown fox jumps over the lazy dog");
    let report1 = run_db_vector_catchup_backfill(&storage, 8).expect("genesis backfill");
    assert!(report1.activated, "genesis backfill must activate");
    assert_eq!(report1.embedded_inserted, 1);
    assert!(!report1.reused_existing_generation, "genesis must create a fresh generation, not reuse one");
    let genesis_generation_id = report1.generation_id;
    assert_eq!(embedding_generations_count(&storage), 1, "exactly one generation must exist after genesis");

    // Steady state: no new messages at all. Re-run the exact same call a
    // routine hourly cron would make.
    let report2 = run_db_vector_catchup_backfill(&storage, 8).expect("steady-state rerun");

    assert!(
        report2.reused_existing_generation,
        "a steady-state rerun must reuse the identity-matching active generation, not create a new one"
    );
    assert_eq!(
        report2.generation_id, genesis_generation_id,
        "the reused generation must be the exact same one already serving reads"
    );
    assert_eq!(
        embedding_generations_count(&storage),
        1,
        "a steady-state rerun must not leave a second (orphaned) generation behind"
    );
    assert_eq!(
        report2.embedded_inserted, 0,
        "the fix's core claim: nothing new to embed, so nothing gets re-embedded"
    );
    assert_eq!(
        report2.eligible_seeded, 0,
        "the genesis-eligibility rescan safety net still runs, but seed_embedding_holes' own \
         `WHERE NOT EXISTS (SELECT 1 FROM message_embeddings ...)` guard excludes the already-\
         embedded genesis message -- nothing new gets seeded"
    );
    assert_eq!(
        message_embeddings_count_for(&storage, genesis_generation_id),
        1,
        "the original embedding row must not be duplicated or re-written"
    );
    assert!(
        report2.activated,
        "R1-W3-N3's advisor-mandated requirement: reusing the active generation must still re-run \
         the full activation audit and re-promote through switch_active_generation, not skip \
         re-certification just because it was already active"
    );
}
