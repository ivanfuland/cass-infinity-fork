//! T6 (plan v5.1) Step 1: failing-then-green tests for the lifecycle four
//! categories (insert/update/delete/restore) wired into every write entry
//! point. Judgments (a), (d), (e), (f), (g) here -- everything reachable
//! through the public storage API (`insert_conversation_tree`,
//! `forget_conversations_by_source_glob`, `raw()` SQL, the `pub fn` v5
//! chunk-domain primitives from T4). Judgments (b) (update via the replace
//! path) and (c) (delete a single message, not a whole conversation) need
//! `pub(crate)` access to `franken_replace_conversation_messages_in_tx` /
//! `delete_messages_ordered_in_tx` directly, so they live inline in
//! `src/storage/sqlite.rs`'s own test module instead -- the same
//! file-layout deviation already established and approved for T5's
//! `tests/w4_lexical_incremental.rs` split, documented in the T6 terminal
//! report.
//!
//! Connections are opened via `FrankenStorage::open` (the real production
//! entry point), matching the fixture-fidelity discipline every prior w4
//! integration test file follows.

use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::search::eligibility::expected_chunks;
use coding_agent_search::storage::api::{TxMode, Value as V};
use coding_agent_search::storage::schema::{self, ChunkRow};
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::vector_domain;

const DIM: i64 = 8;

macro_rules! fparams {
    () => {
        &[] as &[V]
    };
    ($($val:expr),+ $(,)?) => {
        &[$(coding_agent_search::storage::api::IntoValue::into_value($val)),+] as &[V]
    };
}

fn scratch_db_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().expect("create scratch dir");
    let path = dir.path().join("agent_search.db");
    (dir, path)
}

fn open_storage(path: &std::path::Path) -> FrankenStorage {
    FrankenStorage::open(path).expect("open production storage")
}

fn ensure_test_agent(storage: &FrankenStorage) -> i64 {
    storage
        .ensure_agent(&Agent {
            id: None,
            slug: "claude_code".into(),
            name: "Claude Code".into(),
            version: None,
            kind: AgentKind::Cli,
        })
        .expect("ensure agent")
}

fn message(idx: i64, role: MessageRole, content: impl Into<String>, created_at: i64) -> Message {
    Message {
        id: None,
        idx,
        role,
        author: None,
        created_at: Some(created_at),
        content: content.into(),
        extra_json: serde_json::Value::Null,
        snippets: Vec::new(),
    }
}

fn conversation(external_id: &str, messages: Vec<Message>) -> Conversation {
    Conversation {
        id: None,
        agent_slug: "claude_code".into(),
        workspace: None,
        external_id: Some(external_id.into()),
        title: Some(format!("{external_id} fixture")),
        source_path: std::path::PathBuf::from(format!("/fixtures/{external_id}.jsonl")),
        started_at: Some(1_700_000_000_000),
        ended_at: Some(1_700_000_000_100),
        approx_tokens: None,
        metadata_json: serde_json::Value::Null,
        messages,
        source_id: "local".into(),
        origin_host: None,
    }
}

fn message_ids_for_conversation(storage: &FrankenStorage, conversation_id: i64) -> Vec<i64> {
    storage
        .raw()
        .query_all_map(
            "SELECT id FROM messages WHERE conversation_id = ?1 ORDER BY idx",
            fparams![conversation_id],
            |row| row.get_typed(0),
        )
        .expect("list message ids")
}

fn conversation_id_for_external_id(storage: &FrankenStorage, external_id: &str) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT id FROM conversations WHERE external_id = ?1",
            fparams![external_id],
            |row| row.get_typed(0),
        )
        .expect("look up conversation id")
}

fn create_generation(storage: &FrankenStorage, embedder_id: &str) -> i64 {
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::create_embedding_generation_v5(tx, embedder_id, DIM, 1, 1, b"fingerprint-bytes", 1_000)
        })
        .expect("create v5 embedding generation")
}

fn mark_generation_active(storage: &FrankenStorage, generation_id: i64) {
    storage
        .raw()
        .execute(
            "UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1",
            fparams![generation_id],
        )
        .expect("mark generation active");
}

/// Neither active nor pending -- an old, no-longer-live generation whose
/// `vec0` table must still get cleaned up on delete (T6's whole point:
/// `list_vec0_generation_ids_in_tx` enumerates by real table existence, not
/// by `is_active`/`audit_status`).
fn mark_generation_stale(storage: &FrankenStorage, generation_id: i64) {
    storage
        .raw()
        .execute(
            "UPDATE embedding_generations SET is_active = 0, audit_status = 'passed' WHERE id = ?1",
            fparams![generation_id],
        )
        .expect("mark generation stale");
}

/// Seed one embedded chunk directly into `message_chunks` for
/// `generation_id`/`message_id`, then rebuild that generation's `vec0`
/// table from it -- simulates "this message already has an embedding under
/// this generation" without needing a real embedder.
fn seed_embedded_chunk(storage: &FrankenStorage, generation_id: i64, message_id: i64, conversation_id: i64) -> i64 {
    let chunk_id = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::insert_chunk_row_in_tx(
                tx,
                &ChunkRow {
                    generation_id,
                    message_id,
                    conversation_id,
                    chunk_idx: 0,
                    byte_start: 0,
                    byte_end: 10,
                    content_hash: format!("hash-{message_id}"),
                    embedding: vec![0.1f32; DIM as usize],
                    norm: 1.0,
                    created_at_ms: 1_000,
                },
            )
        })
        .expect("insert chunk row");
    vector_domain::rebuild_vec0_table_for_generation_v5(storage.raw(), generation_id, DIM)
        .expect("rebuild vec0 table");
    chunk_id
}

fn vec0_row_count(storage: &FrankenStorage, generation_id: i64) -> i64 {
    storage
        .raw()
        .query_row_map(
            &format!("SELECT COUNT(*) FROM vec_index_gen_{generation_id}"),
            fparams![],
            |row| row.get_typed(0),
        )
        .expect("count vec0 rows")
}

fn message_chunks_count(storage: &FrankenStorage, message_id: i64) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM message_chunks WHERE message_id = ?1",
            fparams![message_id],
            |row| row.get_typed(0),
        )
        .expect("count message_chunks rows")
}

fn chunk_holes_count(storage: &FrankenStorage, message_id: i64) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM chunk_holes WHERE message_id = ?1",
            fparams![message_id],
            |row| row.get_typed(0),
        )
        .expect("count chunk_holes rows")
}

fn chunk_staging_count(storage: &FrankenStorage, message_id: i64) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM chunk_staging WHERE message_id = ?1",
            fparams![message_id],
            |row| row.get_typed(0),
        )
        .expect("count chunk_staging rows")
}

fn lex_docs_count(storage: &FrankenStorage, message_id: i64) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM lex_docs WHERE doc_id = ?1",
            fparams![message_id],
            |row| row.get_typed(0),
        )
        .expect("count lex_docs rows")
}

fn fts_match_count(storage: &FrankenStorage, term: &str) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM fts_lex WHERE fts_lex MATCH ?1",
            fparams![term],
            |row| row.get_typed(0),
        )
        .expect("fts_lex MATCH query")
}

fn fts_integrity_check(storage: &FrankenStorage) {
    storage
        .raw()
        .execute("INSERT INTO fts_lex(fts_lex, rank) VALUES('integrity-check', 1)", fparams![])
        .expect("fts_lex integrity-check must pass (no dangling/corrupt shadow rows)");
}

/// Judgment (a): a freshly inserted 3-message conversation must register
/// exactly `expected_chunks`' worth of `chunk_holes` rows for the one
/// pending generation live at insert time -- no more, no less.
#[test]
fn lifecycle_insert_registers_chunk_holes_matching_expected_chunks() {
    let (_dir, db_path) = scratch_db_path();
    let storage = open_storage(&db_path);
    let agent_id = ensure_test_agent(&storage);
    let generation_id = create_generation(&storage, "hash"); // pending by default

    let conv = conversation(
        "insert-holes-conv",
        vec![
            message(0, MessageRole::User, "alpha message body one", 1_700_000_000_010),
            message(1, MessageRole::Assistant, "beta message body two", 1_700_000_000_020),
            message(2, MessageRole::User, "gamma message body three", 1_700_000_000_030),
        ],
    );
    storage.insert_conversation_tree(agent_id, None, &conv).expect("insert conversation");
    let conversation_id = conversation_id_for_external_id(&storage, "insert-holes-conv");
    let doc_ids = message_ids_for_conversation(&storage, conversation_id);
    assert_eq!(doc_ids.len(), 3);

    let mut expected_keys: Vec<(i64, u32)> = Vec::new();
    for (idx, &doc_id) in doc_ids.iter().enumerate() {
        let role = if idx == 1 { "assistant" } else { "user" };
        let content = match idx {
            0 => "alpha message body one",
            1 => "beta message body two",
            _ => "gamma message body three",
        };
        for chunk in expected_chunks(doc_id, conversation_id, role, content) {
            expected_keys.push((chunk.message_id, chunk.chunk_idx));
        }
    }
    assert_eq!(expected_keys.len(), 3, "each short message must produce exactly one expected chunk");

    let actual_keys: Vec<(i64, u32)> = storage
        .raw()
        .query_all_map(
            "SELECT message_id, chunk_idx FROM chunk_holes WHERE generation_id = ?1 ORDER BY message_id, chunk_idx",
            fparams![generation_id],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .unwrap();
    let mut expected_sorted = expected_keys.clone();
    expected_sorted.sort_unstable();
    assert_eq!(actual_keys, expected_sorted, "chunk_holes must exactly equal expected_chunks' keys, 3 rows");
}

/// Judgment (d): deleting a whole session (conversation) must leave zero
/// orphans across chunks/holes/staging/vec0 (active + pending + a stale
/// generation, three live `vec0` tables) and lex_docs, and the deleted
/// message's unique token must no longer MATCH in fts_lex. FTS5's own
/// integrity-check command must also pass (no dangling shadow rows).
#[test]
fn lifecycle_delete_session_leaves_zero_orphans_across_all_generations() {
    let (_dir, db_path) = scratch_db_path();
    let storage = open_storage(&db_path);
    let agent_id = ensure_test_agent(&storage);

    let gen_active = create_generation(&storage, "active-embedder");
    mark_generation_active(&storage, gen_active);
    let gen_pending = create_generation(&storage, "pending-embedder");
    let gen_stale = create_generation(&storage, "stale-embedder");
    mark_generation_stale(&storage, gen_stale);

    let conv = conversation(
        "delete-session-conv",
        vec![message(0, MessageRole::User, "sessiondeletetermxyz unique body", 1_700_000_000_010)],
    );
    storage.insert_conversation_tree(agent_id, None, &conv).expect("insert conversation");
    let conversation_id = conversation_id_for_external_id(&storage, "delete-session-conv");
    let message_id = message_ids_for_conversation(&storage, conversation_id)[0];

    for gen_id in [gen_active, gen_pending, gen_stale] {
        seed_embedded_chunk(&storage, gen_id, message_id, conversation_id);
        assert_eq!(vec0_row_count(&storage, gen_id), 1, "sanity: chunk seeded into vec0 for generation {gen_id}");
    }
    assert!(message_chunks_count(&storage, message_id) >= 3, "sanity: message_chunks seeded across 3 generations");
    assert_eq!(lex_docs_count(&storage, message_id), 1, "sanity: lex_docs row exists before delete");
    assert_eq!(fts_match_count(&storage, "sessiondeletetermxyz"), 1, "sanity: fts_lex MATCH before delete");

    let deleted = storage
        .forget_conversations_by_source_glob("/fixtures/delete-session-conv.jsonl", false)
        .expect("forget conversation by source glob");
    assert_eq!(deleted.conversations_deleted, 1);

    for gen_id in [gen_active, gen_pending, gen_stale] {
        assert_eq!(vec0_row_count(&storage, gen_id), 0, "vec0 must be empty for generation {gen_id} after delete");
    }
    assert_eq!(message_chunks_count(&storage, message_id), 0, "message_chunks must be 0 after delete");
    assert_eq!(chunk_holes_count(&storage, message_id), 0, "chunk_holes must be 0 after delete");
    assert_eq!(chunk_staging_count(&storage, message_id), 0, "chunk_staging must be 0 after delete");
    assert_eq!(lex_docs_count(&storage, message_id), 0, "lex_docs must be 0 after delete");
    assert_eq!(fts_match_count(&storage, "sessiondeletetermxyz"), 0, "the deleted message's unique token must no longer MATCH");
    fts_integrity_check(&storage);
}

/// Judgment (e): a `chunk_staging` row left behind for a message must
/// vanish via cascade when that message's conversation is deleted (no
/// separate explicit staging-delete call is made by
/// `delete_messages_ordered_in_tx` -- the cascade from `DELETE FROM
/// messages` is what's under test here).
#[test]
fn lifecycle_staging_residue_cascades_away_with_message_delete() {
    let (_dir, db_path) = scratch_db_path();
    let storage = open_storage(&db_path);
    let agent_id = ensure_test_agent(&storage);
    let generation_id = create_generation(&storage, "staging-embedder");

    let conv = conversation(
        "staging-residue-conv",
        vec![message(0, MessageRole::User, "staging residue body", 1_700_000_000_010)],
    );
    storage.insert_conversation_tree(agent_id, None, &conv).expect("insert conversation");
    let conversation_id = conversation_id_for_external_id(&storage, "staging-residue-conv");
    let message_id = message_ids_for_conversation(&storage, conversation_id)[0];

    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::stage_chunk_rows_in_tx(
                tx,
                42,
                &[ChunkRow {
                    generation_id,
                    message_id,
                    conversation_id,
                    chunk_idx: 0,
                    byte_start: 0,
                    byte_end: 5,
                    content_hash: "staged-hash".into(),
                    embedding: vec![0.2f32; DIM as usize],
                    norm: 1.0,
                    created_at_ms: 1_000,
                }],
            )
        })
        .expect("stage a chunk row");
    assert_eq!(chunk_staging_count(&storage, message_id), 1, "sanity: staging row exists before delete");

    let deleted = storage
        .forget_conversations_by_source_glob("/fixtures/staging-residue-conv.jsonl", false)
        .expect("forget conversation by source glob");
    assert_eq!(deleted.conversations_deleted, 1);

    assert_eq!(chunk_staging_count(&storage, message_id), 0, "staging row must cascade away with the deleted message");
}

/// Judgment (f): behavioral proof that `vec0` rows are deleted *before*
/// their parent `messages` row -- a TEMP TRIGGER `BEFORE DELETE ON
/// message_chunks` records, for the row about to be deleted, whether its
/// parent message is still alive and whether its vec0 counterpart is
/// already gone. `parent_alive == 1 && vec0_alive == 0` for every recorded
/// row proves vec0-first ordering. Tried first as a real trigger (vec0
/// virtual tables support being SELECTed inside a trigger body in this
/// sqlite-vec build); no trace-hook fallback was needed.
#[test]
fn lifecycle_delete_order_proven_by_trigger() {
    let (_dir, db_path) = scratch_db_path();
    let storage = open_storage(&db_path);
    let agent_id = ensure_test_agent(&storage);
    let generation_id = create_generation(&storage, "order-embedder");
    mark_generation_active(&storage, generation_id);

    let conv = conversation(
        "delete-order-conv",
        vec![message(0, MessageRole::User, "order proof body", 1_700_000_000_010)],
    );
    storage.insert_conversation_tree(agent_id, None, &conv).expect("insert conversation");
    let conversation_id = conversation_id_for_external_id(&storage, "delete-order-conv");
    let message_id = message_ids_for_conversation(&storage, conversation_id)[0];
    let chunk_id = seed_embedded_chunk(&storage, generation_id, message_id, conversation_id);

    storage
        .raw()
        .execute_batch(&format!(
            "CREATE TEMP TABLE order_trace (chunk_id INTEGER PRIMARY KEY, parent_alive INTEGER, vec0_alive INTEGER); \
             CREATE TEMP TRIGGER order_trace_trigger BEFORE DELETE ON message_chunks BEGIN \
                 INSERT INTO order_trace(chunk_id, parent_alive, vec0_alive) VALUES ( \
                     OLD.chunk_id, \
                     (SELECT COUNT(*) FROM messages WHERE id = OLD.message_id), \
                     (SELECT COUNT(*) FROM vec_index_gen_{generation_id} WHERE rowid = OLD.chunk_id) \
                 ); \
             END;"
        ))
        .expect("install order-proof trigger (vec0 SELECT inside a trigger body)");

    let deleted = storage
        .forget_conversations_by_source_glob("/fixtures/delete-order-conv.jsonl", false)
        .expect("forget conversation by source glob");
    assert_eq!(deleted.conversations_deleted, 1);

    let traced: Vec<(i64, i64, i64)> = storage
        .raw()
        .query_all_map(
            "SELECT chunk_id, parent_alive, vec0_alive FROM order_trace ORDER BY chunk_id",
            fparams![],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
        )
        .unwrap();
    assert_eq!(traced.len(), 1, "the trigger must have fired exactly once, for our one seeded chunk");
    assert_eq!(traced[0].0, chunk_id);
    assert_eq!(traced[0].1, 1, "the parent messages row must still be alive when message_chunks is deleted");
    assert_eq!(traced[0].2, 0, "vec0's row for this chunk_id must already be gone (vec0-before-parent ordering)");
}

/// Judgment (g): the same alias-role message, inserted through the real
/// append entry point, must have its hole set equal `expected_chunks` --
/// proves the insert-site wiring uses `expected_chunks` (not a
/// hand-rolled equivalent) for a role that only matches via
/// `canonical_role`'s alias table (`agent` -> assistant).
#[test]
fn lifecycle_semantic_three_sites_agree() {
    let (_dir, db_path) = scratch_db_path();
    let storage = open_storage(&db_path);
    let agent_id = ensure_test_agent(&storage);
    let generation_id = create_generation(&storage, "alias-embedder");

    let conv = conversation(
        "alias-role-conv",
        vec![message(0, MessageRole::Agent, "alias role body via agent alias", 1_700_000_000_010)],
    );
    storage.insert_conversation_tree(agent_id, None, &conv).expect("insert conversation");
    let conversation_id = conversation_id_for_external_id(&storage, "alias-role-conv");
    let message_id = message_ids_for_conversation(&storage, conversation_id)[0];

    let expected = expected_chunks(message_id, conversation_id, "agent", "alias role body via agent alias");
    assert!(!expected.is_empty(), "sanity: the agent-role alias must be chunk-eligible");

    let actual_keys: Vec<(i64, u32)> = storage
        .raw()
        .query_all_map(
            "SELECT message_id, chunk_idx FROM chunk_holes WHERE generation_id = ?1 ORDER BY chunk_idx",
            fparams![generation_id],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .unwrap();
    let expected_keys: Vec<(i64, u32)> =
        expected.iter().map(|c| (c.message_id, c.chunk_idx)).collect();
    assert_eq!(actual_keys, expected_keys, "hole set for the alias-role message must equal expected_chunks exactly");
}
