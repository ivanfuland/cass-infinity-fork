//! T4 (plan v5.1) Step 1: failing-then-green tests for the v5 chunk domain
//! (`message_chunks`/`chunk_holes`/`chunk_staging`, span-aware
//! staging/pruning, generation primitives, chunk-domain `vec0`
//! helpers) added at schema version 5 and finalized as the sole vector
//! domain by T11.
//!
//! Fixture-fidelity discipline: connections here are opened via
//! `FrankenStorage::open` (the real
//! production entry point: `schema::ensure` + the backend's own PRAGMA
//! enforcement), not a hand-rolled bare connection.

use coding_agent_search::search::eligibility::ExpectedChunk;
use coding_agent_search::storage::api::{StorageError, TxMode, Value as V};
use coding_agent_search::storage::schema::{self, ChunkRow};
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::vector_domain;

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

/// Minimal real parent chain (agent/conversation/message) for `message_id`
/// to reference -- `message_chunks`/`chunk_holes`/`chunk_staging` all carry
/// a real `REFERENCES messages(id) ON DELETE CASCADE` FK.
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

fn create_generation(
    storage: &FrankenStorage,
    embedder_id: &str,
    dim: i64,
    canonicalize_version: u32,
    chunking_policy_version: u32,
) -> i64 {
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::create_embedding_generation(
                tx,
                embedder_id,
                dim,
                canonicalize_version,
                chunking_policy_version,
                b"fingerprint-bytes",
                1_000,
            )
        })
        .expect("create v5 embedding generation")
}

fn sample_chunk_row(generation_id: i64, message_id: i64, chunk_idx: u32) -> ChunkRow {
    ChunkRow {
        generation_id,
        message_id,
        conversation_id: 1,
        chunk_idx,
        byte_start: (chunk_idx as usize) * 5,
        byte_end: (chunk_idx as usize) * 5 + 5,
        content_hash: format!("hash-{chunk_idx}"),
        embedding: vec![1.0, 2.0, 3.0, 4.0],
        norm: 5.477_226,
        created_at_ms: 1_000,
    }
}

// =============================================================================
// DDL shape.
// =============================================================================

#[test]
fn schema_v5_fresh_ddl_vector_segment_contains_three_tables_and_two_columns() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);

    let names: Vec<String> = storage
        .raw()
        .query_all_map("SELECT name FROM sqlite_master WHERE type = 'table'", &[], |row| {
            row.get_typed(0)
        })
        .unwrap();
    for table in ["message_chunks", "chunk_holes", "chunk_staging"] {
        assert!(names.contains(&table.to_string()), "missing v5 table {table}");
    }

    let cols: Vec<String> = storage
        .raw()
        .query_all_map(
            "SELECT name FROM pragma_table_info('embedding_generations')",
            &[],
            |row| row.get_typed(0),
        )
        .unwrap();
    for col in ["chunking_policy_version", "fingerprint"] {
        assert!(cols.contains(&col.to_string()), "missing new embedding_generations column {col}");
    }
}

#[test]
fn schema_ensure_fresh_on_empty_v0() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    let version: i64 =
        storage.raw().query_row_map("PRAGMA user_version;", &[], |row| row.get_typed(0)).unwrap();
    assert_eq!(version, schema::CURRENT_SCHEMA_VERSION);
    assert_eq!(schema::CURRENT_SCHEMA_VERSION, 5);
}

// =============================================================================
// Generation primitives.
// =============================================================================

#[test]
fn create_generation_v5_rejects_empty_fingerprint() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    let err = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::create_embedding_generation(tx, "bge-m3", 1024, 2, 1, &[], 1_000)
        })
        .expect_err("empty fingerprint must be rejected");
    assert!(matches!(err, StorageError::Constraint { .. }), "expected Constraint, got {err:?}");
}

#[test]
fn generation_fingerprint_and_policy_not_null() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    // Bare SQL, deliberately omitting chunking_policy_version and
    // fingerprint (both NOT NULL with no default) -- must hit the DDL
    // constraint itself, independent of any write-side helper.
    let err = storage
        .raw()
        .execute(
            "INSERT INTO embedding_generations (embedder_id, dim, canonicalize_version, byte_order, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            fparams!["bge-m3", 1024_i64, 2_i64, "le", 1_000_i64],
        )
        .expect_err("bare INSERT missing chunking_policy_version/fingerprint must violate NOT NULL");
    assert!(matches!(err, StorageError::Constraint { .. }), "expected Constraint, got {err:?}");
}

#[test]
fn find_pending_generation_v5_requires_policy_match() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    let gen_id = create_generation(&storage, "bge-m3", 1024, 2, 1);

    let found = schema::find_reusable_pending_generation(storage.raw(), "bge-m3", 1024, 2, 1)
        .unwrap()
        .map(|(id, _)| id);
    assert_eq!(found, Some(gen_id), "exact identity + policy match must find the row");

    let not_found = schema::find_reusable_pending_generation(storage.raw(), "bge-m3", 1024, 2, 2)
        .unwrap();
    assert!(not_found.is_none(), "a different chunking_policy_version must not match");
}

// =============================================================================
// `chunk_holes` bulk seeding.
// =============================================================================

#[test]
fn seed_chunk_holes_statements_le_1000_rows() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1, 1);

    let holes: Vec<(i64, u32)> = (0..3_500u32).map(|i| (1_i64, i)).collect();
    let outcome = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::seed_chunk_holes(tx, gen_id, &holes, 1_000, "test")
        })
        .unwrap();
    assert_eq!(outcome.rows_inserted, 3_500);
    assert_eq!(outcome.rows_conflicted, 0);
    assert_eq!(outcome.statements, 4, "3,500 rows at <=1,000/statement must take exactly 4 statements");
}

#[test]
fn seed_chunk_holes_60000_rows_beyond_variable_limit() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1, 1);

    let holes: Vec<(i64, u32)> = (0..60_000u32).map(|i| (1_i64, i)).collect();
    let outcome = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::seed_chunk_holes(tx, gen_id, &holes, 1_000, "test")
        })
        .expect(
            "60,000 holes batched at <=1,000 rows/statement must succeed even though a single \
             naive multi-row statement over them all would exceed a real variable limit",
        );
    assert_eq!(outcome.rows_inserted, 60_000);
    assert_eq!(outcome.statements, 60);
}

#[test]
fn seed_chunk_holes_reports_conflicts_not_silently() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1, 1);

    let first: Vec<(i64, u32)> = (0..10u32).map(|i| (1_i64, i)).collect();
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::seed_chunk_holes(tx, gen_id, &first, 1_000, "first")
        })
        .unwrap();

    // Re-seed the same 10, plus 5 new ones -> the first 10 must be reported
    // as conflicts, not silently absorbed into rows_inserted.
    let second: Vec<(i64, u32)> = (0..15u32).map(|i| (1_i64, i)).collect();
    let outcome = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::seed_chunk_holes(tx, gen_id, &second, 2_000, "second")
        })
        .unwrap();
    assert_eq!(outcome.rows_inserted, 5);
    assert_eq!(outcome.rows_conflicted, 10);
}

#[test]
fn register_chunk_holes_noop_without_generation() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    // Deliberately no generation created.

    let expected = vec![ExpectedChunk {
        message_id: 1,
        conversation_id: 1,
        chunk_idx: 0,
        byte_start: 0,
        byte_end: 10,
        content_hash: "h".to_string(),
    }];
    let outcome = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::register_chunk_holes_for_message_in_tx(tx, &expected, 1_000, "reason")
        })
        .unwrap();
    assert_eq!(outcome, schema::SeedOutcome::default());
}

// =============================================================================
// `message_chunks` collect/delete.
// =============================================================================

#[test]
fn collect_then_delete_chunks_returns_ids() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1, 1);

    let row = sample_chunk_row(gen_id, 1, 0);
    let chunk_id = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::insert_chunk_row_in_tx(tx, &row))
        .unwrap();

    let ids = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::collect_chunk_ids_for_messages(tx, gen_id, &[1])
        })
        .unwrap();
    assert_eq!(ids, vec![chunk_id]);

    let deleted = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::delete_chunks_by_ids_in_tx(tx, &ids))
        .unwrap();
    assert_eq!(deleted, 1);

    let count: i64 =
        storage.raw().query_row_map("SELECT COUNT(*) FROM message_chunks", &[], |row| row.get_typed(0)).unwrap();
    assert_eq!(count, 0);
}

// =============================================================================
// Staging: stage, move by key (not batch_id), reuse detection.
// =============================================================================

#[test]
fn move_staging_by_keys_across_batches() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1, 1);

    let row0 = sample_chunk_row(gen_id, 1, 0);
    let row1 = sample_chunk_row(gen_id, 1, 1);
    // Stage the two rows under two DIFFERENT batch_ids on purpose.
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::stage_chunk_rows_in_tx(tx, 111, &[row0]))
        .unwrap();
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::stage_chunk_rows_in_tx(tx, 222, &[row1]))
        .unwrap();

    let staged_count: i64 =
        storage.raw().query_row_map("SELECT COUNT(*) FROM chunk_staging", &[], |row| row.get_typed(0)).unwrap();
    assert_eq!(staged_count, 2, "sanity: both rows staged under different batch_ids");

    // Move both keys in one call, ignoring batch_id entirely.
    let new_ids = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::move_staging_to_chunks_in_tx(tx, gen_id, &[(1, 0), (1, 1)])
        })
        .unwrap();
    assert_eq!(new_ids.len(), 2, "both keys must move despite differing batch_ids");

    let staging_after: i64 =
        storage.raw().query_row_map("SELECT COUNT(*) FROM chunk_staging", &[], |row| row.get_typed(0)).unwrap();
    assert_eq!(staging_after, 0, "moved rows must be removed from staging");
    let chunks_after: i64 =
        storage.raw().query_row_map("SELECT COUNT(*) FROM message_chunks", &[], |row| row.get_typed(0)).unwrap();
    assert_eq!(chunks_after, 2);
}

#[test]
fn find_reusable_staging_requires_hash_and_span() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1, 1);

    let mut staged = sample_chunk_row(gen_id, 1, 0);
    staged.content_hash = "samehash".to_string();
    staged.byte_start = 0;
    staged.byte_end = 5;
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::stage_chunk_rows_in_tx(tx, 1, &[staged]))
        .unwrap();

    // Same hash, DIFFERENT span -> must NOT be claimed.
    let expected_diff_span = vec![ExpectedChunk {
        message_id: 1,
        conversation_id: 1,
        chunk_idx: 0,
        byte_start: 0,
        byte_end: 6,
        content_hash: "samehash".to_string(),
    }];
    let reusable = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::find_reusable_staging_in_tx(tx, gen_id, &expected_diff_span)
        })
        .unwrap();
    assert!(reusable.is_empty(), "hash match with span mismatch must not be claimed");

    // Same hash AND same span -> claimed.
    let expected_same = vec![ExpectedChunk {
        message_id: 1,
        conversation_id: 1,
        chunk_idx: 0,
        byte_start: 0,
        byte_end: 5,
        content_hash: "samehash".to_string(),
    }];
    let reusable2 = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::find_reusable_staging_in_tx(tx, gen_id, &expected_same)
        })
        .unwrap();
    assert_eq!(reusable2, vec![(1, 0)]);
}

// =============================================================================
// Pruning: span-aware.
// =============================================================================

#[test]
fn prune_chunks_drops_span_mismatch() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1, 1);

    let mut row = sample_chunk_row(gen_id, 1, 0);
    row.content_hash = "h".to_string();
    row.byte_start = 0;
    row.byte_end = 5;
    let chunk_id = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::insert_chunk_row_in_tx(tx, &row))
        .unwrap();

    // Expected chunk has the same chunk_idx/content_hash but a DIFFERENT
    // span -> the existing row must be pruned (any single field mismatch is
    // enough).
    let expected = vec![ExpectedChunk {
        message_id: 1,
        conversation_id: 1,
        chunk_idx: 0,
        byte_start: 0,
        byte_end: 6,
        content_hash: "h".to_string(),
    }];
    let pruned = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::prune_chunks_not_in_expected_in_tx(tx, gen_id, 1, &expected)
        })
        .unwrap();
    assert_eq!(pruned, vec![chunk_id]);

    let count: i64 =
        storage.raw().query_row_map("SELECT COUNT(*) FROM message_chunks", &[], |row| row.get_typed(0)).unwrap();
    assert_eq!(count, 0);
}

// =============================================================================
// `vec0` chunk-domain primitives.
// =============================================================================

#[test]
fn vec0_set_mismatch_uses_chunk_id_both_directions() {
    let (_dir, path) = scratch_db_path();
    let storage = open_storage(&path);
    insert_message_parent_chain(&storage, 1, 1, 1);
    let gen_id = create_generation(&storage, "bge-m3", 4, 1, 1);

    let row0 = sample_chunk_row(gen_id, 1, 0);
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::insert_chunk_row_in_tx(tx, &row0))
        .unwrap();

    vector_domain::rebuild_vec0_table_for_generation(storage.raw(), gen_id, 4).unwrap();
    let (missing, extra) =
        vector_domain::count_vec0_chunks_set_mismatch_for_generation(storage.raw(), gen_id).unwrap();
    assert_eq!((missing, extra), (0, 0), "freshly rebuilt vec0 must exactly match message_chunks");

    // A second chunk inserted directly into message_chunks (not into vec0)
    // -> missing_from_vec0 = 1.
    let row1 = sample_chunk_row(gen_id, 1, 1);
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::insert_chunk_row_in_tx(tx, &row1))
        .unwrap();
    let (missing, extra) =
        vector_domain::count_vec0_chunks_set_mismatch_for_generation(storage.raw(), gen_id).unwrap();
    assert_eq!((missing, extra), (1, 0));

    // An extra vec0 row with no backing message_chunks row (rowid 9_999
    // does not exist in message_chunks) -> extra_in_vec0 = 1.
    let fake_embedding = vec![0u8; 16]; // dim=4 * 4 bytes
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            vector_domain::insert_vec0_rows_in_tx(tx, gen_id, &[(9_999, fake_embedding.as_slice())])
        })
        .unwrap();
    let (missing, extra) =
        vector_domain::count_vec0_chunks_set_mismatch_for_generation(storage.raw(), gen_id).unwrap();
    assert_eq!((missing, extra), (1, 1), "both directions of the anti-join must be counted independently");
}
