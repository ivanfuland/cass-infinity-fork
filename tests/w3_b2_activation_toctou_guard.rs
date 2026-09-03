//! R1-W3-B2 (2026-09-02 W3 PR round-1 review, task book #68):
//! `schema::switch_active_generation`'s `verify` closure previously just
//! wrote `audit_status='passed'`, doing nothing to actually re-verify
//! anything -- the full six-invariant activation audit runs, necessarily,
//! *outside* the switch transaction (an expensive multi-query audit must
//! not hold a write lock open for its whole duration), which opens a
//! TOCTOU window between "the audit read holes==0 and verified
//! everything" and "the switch transaction below actually flips the
//! pointer". A message landing in that window registers no hole against
//! the not-yet-active candidate generation (ingest-time hooks only touch
//! the *currently active* generation), so the candidate would still show
//! holes==0 and would still get promoted -- silently missing that message
//! forever.
//!
//! `schema::verify_no_activation_toctou_drift_in_tx` closes that window
//! with two cheap in-transaction rechecks (holes still empty, messages'
//! high-water mark unchanged since the audit started). This file tests
//! that function directly against `switch_active_generation` -- no live
//! Infinity needed, unlike `run_db_vector_catchup_backfill`'s full flow.

use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::search::canonicalize::CANONICALIZE_PIPELINE_VERSION;
use coding_agent_search::storage::api::{TxMode, Value as V};
use coding_agent_search::storage::schema;
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::vector_domain;

macro_rules! fparams {
    ($($val:expr),+ $(,)?) => {
        &[$(coding_agent_search::storage::api::IntoValue::into_value($val)),+] as &[V]
    };
}

const TS: i64 = 1_770_551_400_000;
const DIM: i64 = 4;

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

fn insert_one_message_conversation(storage: &FrankenStorage, external_id: &str) -> (i64, i64) {
    let agent_id = ensure_agent(storage);
    let conv = Conversation {
        id: None,
        agent_slug: "claude_code".into(),
        workspace: None,
        external_id: Some(external_id.into()),
        title: Some("w3-b2 toctou fixture".into()),
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
            content: "distinct fixture content".into(),
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
    let doc_id: i64 = storage
        .raw()
        .query_row_map("SELECT id FROM messages WHERE conversation_id = ?1 AND idx = 0", fparams![conv_id], |row| row.get_typed(0))
        .unwrap();
    (conv_id, doc_id)
}

fn current_message_watermark(storage: &FrankenStorage) -> i64 {
    storage.raw().query_row_map("SELECT COALESCE(MAX(id), 0) FROM messages", &[], |row| row.get_typed(0)).unwrap()
}

fn current_message_count(storage: &FrankenStorage) -> i64 {
    storage.raw().query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0)).unwrap()
}

fn build_ready_candidate_generation(storage: &FrankenStorage, doc_id: i64, conv_id: i64) -> i64 {
    let gen_id = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::create_embedding_generation(tx, "bge-m3", DIM, CANONICALIZE_PIPELINE_VERSION, TS)
        })
        .unwrap();
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::insert_message_embedding(tx, gen_id, doc_id, conv_id, &[1.0, 0.0, 0.0, 0.0], "seed-hash", None, TS)
        })
        .unwrap();
    vector_domain::create_vec0_table_for_generation(storage.raw(), gen_id, DIM).unwrap();
    vector_domain::rebuild_vec0_table_for_generation(storage.raw(), gen_id, DIM).unwrap();
    gen_id
}

fn is_active(storage: &FrankenStorage, gen_id: i64) -> bool {
    storage
        .raw()
        .query_row_map("SELECT is_active FROM embedding_generations WHERE id = ?1", fparams![gen_id], |row| row.get_typed::<i64>(0))
        .unwrap()
        == 1
}

fn audit_status(storage: &FrankenStorage, gen_id: i64) -> String {
    storage.raw().query_row_map("SELECT audit_status FROM embedding_generations WHERE id = ?1", fparams![gen_id], |row| row.get_typed(0)).unwrap()
}

#[test]
fn switch_aborts_when_a_message_lands_after_the_watermark_was_captured() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (conv_id, doc_id) = insert_one_message_conversation(&storage, "w3-b2-genesis");
    let gen_id = build_ready_candidate_generation(&storage, doc_id, conv_id);

    // Snapshot the watermark exactly as `run_db_vector_catchup_backfill`
    // does, *before* the (here-simulated, already-passed) full audit.
    let pre_audit_watermark_message_id = current_message_watermark(&storage);
    let pre_audit_message_count = current_message_count(&storage);

    // Simulate a concurrent writer landing a brand-new message *after*
    // the watermark snapshot but *before* the switch transaction below --
    // this candidate generation is not yet active, so no ingest-time hook
    // registers a hole for it.
    insert_one_message_conversation(&storage, "w3-b2-concurrent-drift");

    let result = schema::switch_active_generation(storage.raw(), gen_id, TS + 1_000, |tx| {
        schema::verify_no_activation_toctou_drift_in_tx(tx, gen_id, pre_audit_watermark_message_id, pre_audit_message_count)?;
        tx.execute("UPDATE embedding_generations SET audit_status = 'passed' WHERE id = ?1", fparams![gen_id])?;
        Ok(())
    });

    assert!(result.is_err(), "a watermark drift between audit-time and switch-time must abort the switch");
    assert!(!is_active(&storage, gen_id), "an aborted switch must never flip is_active");
    assert_eq!(audit_status(&storage, gen_id), "pending", "an aborted switch must never write audit_status='passed'");
}

#[test]
fn switch_succeeds_when_nothing_drifted_since_the_watermark_was_captured() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (conv_id, doc_id) = insert_one_message_conversation(&storage, "w3-b2-genesis");
    let gen_id = build_ready_candidate_generation(&storage, doc_id, conv_id);

    let pre_audit_watermark_message_id = current_message_watermark(&storage);
    let pre_audit_message_count = current_message_count(&storage);
    // No concurrent write happens here -- the baseline this test proves
    // the guard does not false-positive on.

    let result = schema::switch_active_generation(storage.raw(), gen_id, TS + 1_000, |tx| {
        schema::verify_no_activation_toctou_drift_in_tx(tx, gen_id, pre_audit_watermark_message_id, pre_audit_message_count)?;
        tx.execute("UPDATE embedding_generations SET audit_status = 'passed' WHERE id = ?1", fparams![gen_id])?;
        Ok(())
    });

    assert!(result.is_ok(), "no drift must not block a legitimate switch: {result:?}");
    assert!(is_active(&storage, gen_id));
    assert_eq!(audit_status(&storage, gen_id), "passed");
}

/// R2-B2: the watermark alone cannot see a delete of a *non-max-id*
/// message -- `MAX(id)` is untouched when an earlier message is removed
/// while a later one still exists, so this concurrent-mutation shape
/// needed its own guard (a row-count recheck) on top of R1-W3-B2's
/// watermark check. Two messages exist specifically so there is a
/// non-max-id one to delete without moving the watermark.
#[test]
fn switch_aborts_when_a_non_max_id_message_is_deleted_after_the_count_was_captured() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (conv_id, doc_id) = insert_one_message_conversation(&storage, "w3-b2-genesis");
    let gen_id = build_ready_candidate_generation(&storage, doc_id, conv_id);
    let (_second_conv_id, second_doc_id) = insert_one_message_conversation(&storage, "w3-b2-second");

    let pre_audit_watermark_message_id = current_message_watermark(&storage);
    let pre_audit_message_count = current_message_count(&storage);
    assert!(
        second_doc_id > doc_id,
        "sanity: second_doc_id must be the watermark so deleting doc_id (the non-max-id message) below leaves MAX(id) unchanged"
    );
    assert_eq!(pre_audit_watermark_message_id, second_doc_id, "sanity: watermark is the second (non-deleted) message");

    // Simulate a concurrent forget/purge of the *earlier* message -- not
    // the one at the watermark -- after the count snapshot but before the
    // switch transaction below.
    storage.raw().execute("DELETE FROM messages WHERE id = ?1", fparams![doc_id]).unwrap();
    assert_eq!(
        current_message_watermark(&storage),
        pre_audit_watermark_message_id,
        "sanity: the watermark itself must be unchanged by this delete -- otherwise R1-W3-B2's existing check would already catch it"
    );

    let result = schema::switch_active_generation(storage.raw(), gen_id, TS + 1_000, |tx| {
        schema::verify_no_activation_toctou_drift_in_tx(tx, gen_id, pre_audit_watermark_message_id, pre_audit_message_count)?;
        tx.execute("UPDATE embedding_generations SET audit_status = 'passed' WHERE id = ?1", fparams![gen_id])?;
        Ok(())
    });

    assert!(
        result.is_err(),
        "a non-max-id message deletion between audit-time and switch-time must abort the switch, even though the watermark alone is unchanged"
    );
    assert!(!is_active(&storage, gen_id), "an aborted switch must never flip is_active");
    assert_eq!(audit_status(&storage, gen_id), "pending", "an aborted switch must never write audit_status='passed'");
}
