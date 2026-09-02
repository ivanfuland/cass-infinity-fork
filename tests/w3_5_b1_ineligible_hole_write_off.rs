// R1-W3-B1 (2026-09-02 W3 PR round-1 review, task book #68): a message
// whose content canonicalizes to an empty string (a short acknowledgement
// like "OK") gets an `embedding_holes` row registered unconditionally by
// the ingest-time hook (`register_embedding_hole_for_new_message_in_tx`,
// `src/storage/schema.rs` -- it has no eligibility filter of its own), but
// can never resolve that hole through the normal embed-and-CAS-write path
// (`insert_message_embedding_cas` only deletes a hole on a successful
// embedding write, and an ineligible message is never embedded). Before
// the fix, the catch-up drain loop left such a hole "unresolved for
// investigation" and `break`, so `holes_after` never reached zero and the
// generation could never return to `active+passed` -- a permanent
// self-lock, with `cass index --semantic` still reporting `Ok(())`.
//
// This whole-file `#![cfg(feature = "infinity")]` gate matches
// `tests/w3_vector_generation_cleanup.rs`'s own rationale: the module
// under test is itself `infinity`-feature-gated in `src/indexer/mod.rs`,
// so this test's entire premise does not exist outside that build.
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

/// Insert a brand-new one-message conversation through the real production
/// write path (`insert_conversation_tree`) -- not a direct schema-level
/// insert -- so the ingest-time lifecycle hooks
/// (`register_embedding_hole_for_new_message_in_tx` /
/// `demote_active_generation_readiness_in_tx`) actually fire exactly as
/// they do for a real indexing run.
fn insert_one_message_conversation(storage: &FrankenStorage, external_id: &str, content: &str) -> i64 {
    let agent_id = ensure_agent(storage);
    let conv = Conversation {
        id: None,
        agent_slug: "claude_code".into(),
        workspace: None,
        external_id: Some(external_id.into()),
        title: Some("w3-b1 hole write-off fixture".into()),
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
    let conv_id: i64 = storage
        .raw()
        .query_row_map("SELECT id FROM conversations WHERE external_id = ?1", fparams![external_id], |row| row.get_typed(0))
        .unwrap();
    storage
        .raw()
        .query_row_map("SELECT id FROM messages WHERE conversation_id = ?1 AND idx = 0", fparams![conv_id], |row| row.get_typed(0))
        .unwrap()
}

fn hole_count_for_doc(storage: &FrankenStorage, doc_id: i64) -> i64 {
    storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM embedding_holes WHERE doc_id = ?1", fparams![doc_id], |row| row.get_typed(0))
        .unwrap()
}

#[test]
#[ignore = "requires a live Infinity service at 127.0.0.1:7997 (CASS_INFINITY_URL)"]
fn ineligible_hole_is_written_off_and_generation_reactivates() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("agent_search.db");
    let storage = open_storage(&db_path);

    // Genesis: one real, embeddable message activates a fresh generation.
    insert_one_message_conversation(&storage, "w3-b1-genesis", "hello world, this message needs a real embedding");
    let report1 = run_db_vector_catchup_backfill(&storage, 8).expect("genesis backfill");
    assert!(report1.activated, "genesis backfill with one eligible message must activate");
    assert_eq!(report1.holes_after, 0);
    assert_eq!(report1.holes_written_off_ineligible, 0);

    // Ingest a short-acknowledgement message while a generation is active --
    // the exact scenario the finding describes: the ingest-time hook
    // registers a hole for it unconditionally, with no eligibility filter.
    let ok_doc_id = insert_one_message_conversation(&storage, "w3-b1-ok-message", "OK");

    // Sanity check on the bug's own precondition: if the ingest-time hook
    // ever stops registering a hole here, the rest of this test would pass
    // for the wrong reason (there would be nothing to write off).
    assert_eq!(
        hole_count_for_doc(&storage, ok_doc_id),
        1,
        "ingest-time hook must register a hole for the new ineligible message"
    );

    let report2 = run_db_vector_catchup_backfill(&storage, 8).expect("catch-up after ineligible ingest");
    assert_eq!(
        report2.holes_written_off_ineligible, 1,
        "the 'OK' message's hole must be written off as ineligible, not left permanently unresolved"
    );
    assert_eq!(
        report2.holes_after, 0,
        "holes_after must reach zero -- an ineligible hole must not permanently self-lock the generation"
    );
    assert!(
        report2.activated,
        "the generation must be able to return to active+passed once its only remaining hole was ineligible"
    );
    assert_eq!(
        hole_count_for_doc(&storage, ok_doc_id),
        0,
        "the written-off hole row must actually be deleted from the ledger, not merely uncounted"
    );
}
