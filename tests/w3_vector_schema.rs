//! W3-1 Step 1: failing tests (now green, post Step 2) for the vector-domain
//! schema (`embedding_generations`/`message_embeddings`/`embedding_holes`,
//! spec §3.1) added at schema version 4.
//!
//! Per advisor guidance (w3-d4③'s fixture-fidelity condition): connections
//! here are opened via `FrankenStorage::open` — the real production entry
//! point (`schema::ensure` + the backend's own `PRAGMA foreign_keys = ON`
//! enforcement + `apply_config`) — not a hand-rolled bare `rusqlite`
//! connection that would bypass those production PRAGMAs.

use coding_agent_search::storage::api::{StorageError, TxMode, Value as V};
use coding_agent_search::storage::schema;
use coding_agent_search::storage::sqlite::FrankenStorage;

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

/// Open through the real production entry point (`FrankenStorage::open`):
/// runs `schema::ensure` (building/migrating to the current vector-domain
/// schema) plus the backend's own PRAGMA enforcement, exactly as any real
/// consumer of this crate does.
fn open_storage(path: &std::path::Path) -> FrankenStorage {
    FrankenStorage::open(path).expect("open production storage")
}

/// Minimal real parent chain (agent/conversation/message) for `doc_id` to
/// reference — `message_embeddings.doc_id` carries a real `REFERENCES
/// messages(id) ON DELETE CASCADE` FK, so a bare row won't satisfy it.
fn insert_message_parent_chain(
    storage: &FrankenStorage,
    agent_id: i64,
    conversation_id: i64,
    message_id: i64,
) {
    let conn = storage.raw();
    conn.execute(
        "INSERT OR IGNORE INTO agents(id, slug, name, kind, created_at, updated_at) \
         VALUES (?1, ?2, ?2, 'cli', 0, 0)",
        fparams![agent_id, format!("agent-{agent_id}")],
    )
    .expect("insert parent agent");
    conn.execute(
        "INSERT OR IGNORE INTO conversations(id, agent_id, title, source_path) \
         VALUES (?1, ?2, 't', ?3)",
        fparams![conversation_id, agent_id, format!("/tmp/conv-{conversation_id}.jsonl")],
    )
    .expect("insert parent conversation");
    conn.execute(
        "INSERT INTO messages(id, conversation_id, idx, role, content) \
         VALUES (?1, ?2, ?1, 'user', 'c')",
        fparams![message_id, conversation_id],
    )
    .expect("insert parent message");
}

/// Wraps `schema::create_embedding_generation` in its own transaction (the
/// function takes `&Tx` — callers batch generation creation with other
/// writes when it matters; this fixture helper just wants one row).
fn create_generation(
    storage: &FrankenStorage,
    embedder_id: &str,
    dim: i64,
    canonicalize_version: u32,
) -> i64 {
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::create_embedding_generation(tx, embedder_id, dim, canonicalize_version, 1_000)
        })
        .expect("create embedding generation")
}

fn insert_embedding(
    storage: &FrankenStorage,
    generation_id: i64,
    doc_id: i64,
    conversation_id: i64,
    vector: &[f32],
) -> Result<(), StorageError> {
    storage.raw().with_tx_no_replay(TxMode::Immediate, |tx| {
        schema::insert_message_embedding(
            tx,
            generation_id,
            doc_id,
            conversation_id,
            vector,
            "content-hash",
            None,
            1_000,
        )
    })
}

// =============================================================================
// R0-B07: every connection opened through the production path enforces
// PRAGMA foreign_keys = ON, and it survives a batch-write transaction.
// =============================================================================

#[test]
fn pragma_foreign_keys_is_enforced_on_production_open() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    let fk: i64 = storage
        .raw()
        .query_row_map("PRAGMA foreign_keys;", &[], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(fk, 1, "production open must enforce PRAGMA foreign_keys = ON (R0-B07)");
}

// =============================================================================
// Dimension validation: two layers (DDL CHECK only enforces %4==0; the
// write-side helper enforces the exact per-generation dim).
// =============================================================================

#[test]
fn write_side_rejects_a_vector_whose_length_does_not_match_the_generation_dim() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1);

    let wrong_len = vec![1.0_f32, 2.0, 3.0]; // dim=4 expected, 3 given
    let err = insert_embedding(&storage, gen_id, 1, 1, &wrong_len)
        .expect_err("wrong-length vector must be rejected by the write-side dim check");
    assert!(matches!(err, StorageError::Constraint { .. }));

    let count: i64 = storage
        .raw()
        .query_row_map("SELECT count(*) FROM message_embeddings", &[], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(count, 0, "a dim-rejected insert must leave no row behind");
}

#[test]
fn ddl_check_rejects_a_blob_length_not_a_multiple_of_4_bytes_bypassing_the_write_side_helper() {
    // Proves the DDL CHECK backstop independently of the write-side helper:
    // a raw INSERT with a malformed BLOB (5 bytes, not a multiple of 4)
    // must still be rejected even without going through
    // `insert_message_embedding` at all.
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1);

    let malformed_blob: Vec<u8> = vec![0, 1, 2, 3, 4]; // 5 bytes, not %4==0
    let err = storage
        .raw()
        .execute(
            "INSERT INTO message_embeddings \
             (generation_id, doc_id, conversation_id, embedding, norm, content_hash, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            fparams![gen_id, 1_i64, 1_i64, malformed_blob, 1.0_f64, "h", 1_000_i64],
        )
        .expect_err("DDL CHECK(length(embedding) % 4 = 0) must reject a malformed BLOB");
    assert!(matches!(err, StorageError::Constraint { .. }));
}

// =============================================================================
// Finite validation: NaN/Inf elements are rejected.
// =============================================================================

#[test]
fn write_side_rejects_vectors_containing_nan_or_inf_elements() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1);

    for bad_value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let mut vector = vec![1.0_f32, 2.0, 3.0, 4.0];
        vector[2] = bad_value;
        let err = insert_embedding(&storage, gen_id, 1, 1, &vector)
            .expect_err(&format!("a vector containing {bad_value} must be rejected"));
        assert!(matches!(err, StorageError::Constraint { .. }));
    }

    let count: i64 = storage
        .raw()
        .query_row_map("SELECT count(*) FROM message_embeddings", &[], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(count, 0, "no non-finite vector may have been written");
}

// =============================================================================
// Zero-norm rejection (R4-N8) + norm/BLOB recompute consistency.
// =============================================================================

#[test]
fn write_side_rejects_a_zero_vector() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1);

    let zero = vec![0.0_f32, 0.0, 0.0, 0.0];
    let err = insert_embedding(&storage, gen_id, 1, 1, &zero)
        .expect_err("zero-norm vectors must be rejected (R4-N8)");
    assert!(matches!(err, StorageError::Constraint { .. }));
}

#[test]
fn stored_norm_column_matches_norm_recomputed_from_the_stored_blob() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1);

    let vector = vec![3.0_f32, 4.0, 0.0, 0.0]; // norm == 5.0 exactly
    insert_embedding(&storage, gen_id, 1, 1, &vector).expect("insert valid embedding");

    let (blob, stored_norm): (Vec<u8>, f64) = storage
        .raw()
        .query_row_map(
            "SELECT embedding, norm FROM message_embeddings WHERE generation_id = ?1 AND doc_id = ?2",
            fparams![gen_id, 1_i64],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .unwrap();

    let recovered = schema::le_blob_to_f32_vector(&blob).expect("decode stored blob");
    assert_eq!(recovered, vector, "stored BLOB must round-trip byte-exactly");
    let recomputed_norm = schema::l2_norm(&recovered);
    assert_eq!(stored_norm, recomputed_norm, "stored norm must equal the BLOB-recomputed norm");
    assert_eq!(stored_norm, 5.0, "sanity: 3-4-0-0 has an exact norm of 5.0");
}

// =============================================================================
// UNIQUE(generation_id, doc_id).
// =============================================================================

#[test]
fn unique_generation_doc_id_rejects_a_duplicate_insert() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1);

    let vector = vec![1.0_f32, 0.0, 0.0, 0.0];
    insert_embedding(&storage, gen_id, 1, 1, &vector).expect("first insert must succeed");
    let err = insert_embedding(&storage, gen_id, 1, 1, &vector)
        .expect_err("a second insert for the same (generation_id, doc_id) must be rejected");
    assert!(matches!(err, StorageError::Constraint { .. }));

    let count: i64 = storage
        .raw()
        .query_row_map("SELECT count(*) FROM message_embeddings", &[], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(count, 1, "the duplicate must not have landed a second row");
}

// =============================================================================
// ON DELETE CASCADE (real runs, not just DDL text inspection).
// =============================================================================

#[test]
fn deleting_a_message_cascades_to_its_embeddings() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1);
    insert_embedding(&storage, gen_id, 1, 1, &[1.0, 0.0, 0.0, 0.0]).unwrap();

    let before: i64 = storage
        .raw()
        .query_row_map("SELECT count(*) FROM message_embeddings", &[], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(before, 1, "sanity: the embedding row exists before the delete");

    storage.raw().execute("DELETE FROM messages WHERE id = ?1", fparams![1_i64]).unwrap();

    let after: i64 = storage
        .raw()
        .query_row_map("SELECT count(*) FROM message_embeddings", &[], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(after, 0, "deleting the parent message must cascade-delete its embedding row");
}

#[test]
fn deleting_a_conversation_cascades_through_messages_to_embeddings() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1);
    insert_embedding(&storage, gen_id, 1, 1, &[1.0, 0.0, 0.0, 0.0]).unwrap();

    storage.raw().execute("DELETE FROM conversations WHERE id = ?1", fparams![1_i64]).unwrap();

    let messages_left: i64 = storage
        .raw()
        .query_row_map("SELECT count(*) FROM messages", &[], |row| row.get_typed(0))
        .unwrap();
    let embeddings_left: i64 = storage
        .raw()
        .query_row_map("SELECT count(*) FROM message_embeddings", &[], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(messages_left, 0, "sanity: the conversation delete must cascade to messages first");
    assert_eq!(
        embeddings_left, 0,
        "deleting the conversation must transitively cascade-delete the embedding row"
    );
}

// =============================================================================
// Generation isolation (spec §3.1 R1-B01): writing a new generation must not
// affect what the active pointer reads.
// =============================================================================

#[test]
fn writing_a_new_generation_does_not_affect_the_active_pointer_or_its_reads() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);

    let gen_a = create_generation(&storage, "bge-m3", 4, 1);
    schema::switch_active_generation(storage.raw(), gen_a, 1_000, |_tx| Ok(()))
        .expect("activate generation A");
    insert_embedding(&storage, gen_a, 1, 1, &[1.0, 0.0, 0.0, 0.0]).unwrap();

    // A second (pending, not activated) generation writes a different vector
    // for the same doc_id — must not disturb the active pointer or become
    // visible to an active-scoped read.
    let gen_b = create_generation(&storage, "bge-m3-v2", 4, 2);
    insert_embedding(&storage, gen_b, 1, 1, &[0.0, 1.0, 0.0, 0.0]).unwrap();

    assert_eq!(
        schema::active_generation_id(storage.raw()).unwrap(),
        Some(gen_a),
        "creating/writing generation B must not move the active pointer off A"
    );

    let active_scoped_doc_ids: Vec<i64> = storage
        .raw()
        .query_all_map(
            "SELECT me.doc_id FROM message_embeddings me \
             JOIN embedding_generations eg ON eg.id = me.generation_id \
             WHERE eg.is_active = 1",
            &[],
            |row| row.get_typed(0),
        )
        .unwrap();
    assert_eq!(
        active_scoped_doc_ids,
        vec![1],
        "an active-scoped read must see only generation A's row, not generation B's"
    );
}

// =============================================================================
// Atomicity (spec §3.1 + w3-d9②): pointer switch and its verify/integrity
// check share one transaction — a mid-transaction failure must leave the
// pointer untouched, not partially switched.
// =============================================================================

#[test]
fn switch_active_generation_leaves_the_pointer_untouched_when_verify_fails_mid_transaction() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);

    let gen_a = create_generation(&storage, "bge-m3", 4, 1);
    schema::switch_active_generation(storage.raw(), gen_a, 1_000, |_tx| Ok(()))
        .expect("activate generation A");

    let gen_b = create_generation(&storage, "bge-m3-v2", 4, 2);
    let err = schema::switch_active_generation(storage.raw(), gen_b, 2_000, |_tx| {
        Err(StorageError::Other {
            code: None,
            detail: "injected integrity-check failure".to_string(),
        })
    })
    .expect_err("a failing verify closure must fail the whole switch");
    assert!(matches!(err, StorageError::Other { .. }));

    assert_eq!(
        schema::active_generation_id(storage.raw()).unwrap(),
        Some(gen_a),
        "a mid-transaction verify failure must leave the active pointer on the prior generation"
    );
    let gen_b_is_active: i64 = storage
        .raw()
        .query_row_map(
            "SELECT is_active FROM embedding_generations WHERE id = ?1",
            fparams![gen_b],
            |row| row.get_typed(0),
        )
        .unwrap();
    assert_eq!(gen_b_is_active, 0, "generation B's row must not have been flipped to active either");
}

#[test]
fn switch_active_generation_moves_the_pointer_when_verify_succeeds() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);

    let gen_a = create_generation(&storage, "bge-m3", 4, 1);
    schema::switch_active_generation(storage.raw(), gen_a, 1_000, |_tx| Ok(()))
        .expect("activate generation A");

    let gen_b = create_generation(&storage, "bge-m3-v2", 4, 2);
    schema::switch_active_generation(storage.raw(), gen_b, 2_000, |_tx| Ok(()))
        .expect("verify passing must allow the switch");

    assert_eq!(schema::active_generation_id(storage.raw()).unwrap(), Some(gen_b));
    let gen_a_is_active: i64 = storage
        .raw()
        .query_row_map(
            "SELECT is_active FROM embedding_generations WHERE id = ?1",
            fparams![gen_a],
            |row| row.get_typed(0),
        )
        .unwrap();
    assert_eq!(gen_a_is_active, 0, "the previously active generation must be demoted");
}

// =============================================================================
// Hole ledger (R4-B5): table shape + basic CRUD only — consumption logic is
// W3-2's job.
// =============================================================================

#[test]
fn embedding_holes_table_supports_basic_insert_select_delete() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1);

    storage
        .raw()
        .execute(
            "INSERT INTO embedding_holes (generation_id, doc_id, detected_at, reason) \
             VALUES (?1, ?2, ?3, ?4)",
            fparams![gen_id, 1_i64, 1_000_i64, "not yet embedded"],
        )
        .expect("insert a hole row");

    let count: i64 = storage
        .raw()
        .query_row_map("SELECT count(*) FROM embedding_holes", &[], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(count, 1);

    storage
        .raw()
        .execute(
            "DELETE FROM embedding_holes WHERE generation_id = ?1 AND doc_id = ?2",
            fparams![gen_id, 1_i64],
        )
        .expect("delete (resolve) the hole row");
    let after: i64 = storage
        .raw()
        .query_row_map("SELECT count(*) FROM embedding_holes", &[], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(after, 0, "resolving a hole must remove its ledger row");
}

#[test]
fn embedding_holes_primary_key_rejects_a_duplicate_hole_for_the_same_generation_and_doc() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1);

    let conn = storage.raw();
    conn.execute(
        "INSERT INTO embedding_holes (generation_id, doc_id, detected_at, reason) \
         VALUES (?1, ?2, ?3, ?4)",
        fparams![gen_id, 1_i64, 1_000_i64, "not yet embedded"],
    )
    .unwrap();
    let err = conn
        .execute(
            "INSERT INTO embedding_holes (generation_id, doc_id, detected_at, reason) \
             VALUES (?1, ?2, ?3, ?4)",
            fparams![gen_id, 1_i64, 2_000_i64, "re-detected"],
        )
        .expect_err("re-inserting the same (generation_id, doc_id) hole must be rejected");
    assert!(matches!(err, StorageError::Constraint { .. }));
}

#[test]
fn embedding_holes_doc_id_cascades_when_the_message_is_deleted() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1);

    storage
        .raw()
        .execute(
            "INSERT INTO embedding_holes (generation_id, doc_id, detected_at, reason) \
             VALUES (?1, ?2, ?3, ?4)",
            fparams![gen_id, 1_i64, 1_000_i64, "not yet embedded"],
        )
        .unwrap();
    storage.raw().execute("DELETE FROM messages WHERE id = ?1", fparams![1_i64]).unwrap();

    let count: i64 = storage
        .raw()
        .query_row_map("SELECT count(*) FROM embedding_holes", &[], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(count, 0, "a hole for a deleted message is moot and must cascade away");
}
