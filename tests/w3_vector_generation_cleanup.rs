// W3-5 ⑤ (task book #66): `indexer::db_vector_catchup` (the module this file
// tests) is itself `#[cfg(feature = "infinity")]`-gated (src/indexer/mod.rs).
// This integration test unconditionally imported from it (a pre-existing gap
// left by W3-4/exec55, first flagged by exec56 -- see
// W3_ARTIFACTS/w3-5-exec56-handoff.md §2), which broke
// `cargo check --all-targets` under the baseline feature combo (no
// `infinity`, no `semantic`). Whole-file gate: the module, and therefore
// this test's entire premise, does not exist outside the `infinity` build.
#![cfg(feature = "infinity")]

//! W3-4 Step3 (task book #62): delayed cleanup of orphaned (non-active)
//! embedding generations, plus the R4-B5 concurrency proof the task book
//! calls for: "搜索停在读指针 × 并发清理" -- a reader that already opened a
//! `Deferred` transaction and captured its snapshot (exactly what
//! `search_db_vector_domain`, spec R4-B4, does as its very first read) must
//! be completely unaffected by a concurrent `cleanup_orphaned_generations`
//! run that deletes the very generation that reader is looking at.
//!
//! The interleaving here is built the same way
//! `api_with_tx_replays_past_a_real_busy_snapshot_conflict`
//! (`src/storage/api/conn.rs`) builds its real `BUSY_SNAPSHOT` chain: two
//! separate connections to the same file, steps happening in strict
//! sequence, no threads and no sleep-based races -- deterministic, not
//! timing-dependent.

use coding_agent_search::indexer::db_vector_catchup::cleanup_orphaned_generations;
use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::storage::api::{TxMode, Value as V};
use coding_agent_search::storage::schema;
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

const TS: i64 = 1_770_551_400_000;
const DIM: i64 = 4;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

fn open_storage(path: &std::path::Path) -> FrankenStorage {
    FrankenStorage::open(path).expect("open production storage")
}

fn ensure_agent(storage: &FrankenStorage) -> i64 {
    storage
        .ensure_agent(&Agent { id: None, slug: "claude_code".into(), name: "Claude Code".into(), version: Some("1.0".into()), kind: AgentKind::Cli })
        .expect("ensure agent")
}

fn insert_one_message_conversation(storage: &FrankenStorage, external_id: &str) -> (i64, i64) {
    let agent_id = ensure_agent(storage);
    let conv = Conversation {
        id: None,
        agent_slug: "claude_code".into(),
        workspace: None,
        external_id: Some(external_id.into()),
        title: Some("w3-4 cleanup fixture".into()),
        source_path: std::path::PathBuf::from(format!("/fixtures/{external_id}.jsonl")),
        started_at: Some(TS),
        ended_at: Some(TS + 60_000),
        approx_tokens: None,
        metadata_json: serde_json::Value::Null,
        messages: vec![Message { id: None, idx: 0, role: MessageRole::User, author: None, created_at: Some(TS), content: "self-hit anchor".into(), extra_json: serde_json::Value::Null, snippets: vec![] }],
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

fn build_active_passed_generation(storage: &FrankenStorage, doc_id: i64, conv_id: i64, created_at_ms: i64) -> i64 {
    let gen_id = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", DIM, 1, created_at_ms))
        .unwrap();
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::insert_message_embedding(tx, gen_id, doc_id, conv_id, &[1.0, 0.0, 0.0, 0.0], "seed-hash", None, created_at_ms))
        .unwrap();
    vector_domain::create_vec0_table_for_generation(storage.raw(), gen_id, DIM).unwrap();
    vector_domain::rebuild_vec0_table_for_generation(storage.raw(), gen_id, DIM).unwrap();
    storage.raw().execute("UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1", fparams![gen_id]).unwrap();
    gen_id
}

#[test]
fn cleanup_deletes_an_old_non_active_generation_and_leaves_the_active_one_alone() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("agent_search.db");
    let storage = open_storage(&db_path);
    let (conv_id, doc_id) = insert_one_message_conversation(&storage, "w3-4-cleanup-basic");

    let old_created_at = TS - 2 * DAY_MS;
    let gen_old = build_active_passed_generation(&storage, doc_id, conv_id, old_created_at);

    // Supersede gen_old with a fresh generation -- switch_active_generation
    // demotes gen_old to is_active=0 in the same transaction it activates
    // gen_new, matching production's own atomicity contract.
    let gen_new = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", DIM, 1, TS))
        .unwrap();
    schema::switch_active_generation(storage.raw(), gen_new, TS, |_tx| Ok(())).unwrap();

    let outcome = cleanup_orphaned_generations(&storage, TS).expect("cleanup must succeed");
    assert_eq!(outcome.deleted_ids, vec![gen_old], "only the old, now-inactive generation should be cleaned up");
    assert!(outcome.failures.is_empty());

    let gen_old_row_count: i64 = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM embedding_generations WHERE id = ?1", fparams![gen_old], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(gen_old_row_count, 0, "gen_old's own row must be gone");
    let gen_old_embeddings: i64 = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM message_embeddings WHERE generation_id = ?1", fparams![gen_old], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(gen_old_embeddings, 0, "gen_old's message_embeddings rows must be gone too");
    let vec0_table_exists: i64 = storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            fparams![format!("vec_index_gen_{gen_old}")],
            |row| row.get_typed(0),
        )
        .unwrap();
    assert_eq!(vec0_table_exists, 0, "gen_old's vec0 table must be dropped");

    let gen_new_is_active: i64 = storage
        .raw()
        .query_row_map("SELECT is_active FROM embedding_generations WHERE id = ?1", fparams![gen_new], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(gen_new_is_active, 1, "cleanup must never touch the currently-active generation");
}

#[test]
fn cleanup_leaves_a_recently_demoted_generation_alone_until_it_ages_past_the_threshold() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("agent_search.db");
    let storage = open_storage(&db_path);
    let (conv_id, doc_id) = insert_one_message_conversation(&storage, "w3-4-cleanup-too-young");

    // Created "now" (not backdated) -- superseded immediately, but not
    // old enough for the default 24h threshold to touch it yet.
    let gen_old = build_active_passed_generation(&storage, doc_id, conv_id, TS);
    let gen_new = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", DIM, 1, TS))
        .unwrap();
    schema::switch_active_generation(storage.raw(), gen_new, TS, |_tx| Ok(())).unwrap();

    let outcome = cleanup_orphaned_generations(&storage, TS + 1_000).expect("cleanup must succeed");
    assert!(outcome.deleted_ids.is_empty(), "a just-demoted generation must not be cleaned up before it ages past the threshold");
    assert!(outcome.failures.is_empty());

    let gen_old_row_count: i64 = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM embedding_generations WHERE id = ?1", fparams![gen_old], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(gen_old_row_count, 1, "gen_old must still be there");
}

/// R4-B5, the load-bearing test of this file: a reader that already
/// captured a `Deferred` snapshot on `gen_old` (exactly
/// `search_db_vector_domain`'s own first read) must see a fully consistent
/// view of `gen_old` -- its `message_embeddings` row count AND its `vec0`
/// self-hit -- for the rest of that transaction's lifetime, even though a
/// concurrent connection demotes `gen_old` and runs
/// `cleanup_orphaned_generations` (which deletes `gen_old` entirely,
/// `vec0` table included) and commits, all while the reader's transaction
/// is still open.
#[test]
fn a_reader_holding_an_open_snapshot_is_unaffected_by_concurrent_generation_cleanup() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("agent_search.db");
    let writer_storage = open_storage(&db_path);
    let (conv_id, doc_id) = insert_one_message_conversation(&writer_storage, "w3-4-cleanup-r4b5");

    let old_created_at = TS - 2 * DAY_MS;
    let gen_old = build_active_passed_generation(&writer_storage, doc_id, conv_id, old_created_at);

    // A second, independent connection to the same file -- the "search"
    // reader. Opens Deferred and takes its first read (the exact shape of
    // search_db_vector_domain's own first read: the active generation
    // pointer), which is what fixes this transaction's snapshot.
    let reader_storage = FrankenStorage::open(&db_path).expect("open a second connection to the same db");
    let reader_tx = reader_storage.raw().transaction_with_mode(TxMode::Deferred).expect("open reader transaction");
    let (active_gen_id, active_dim): (i64, i64) = reader_tx
        .query_row_map("SELECT id, dim FROM embedding_generations WHERE is_active = 1", &[], |row| Ok((row.get_typed(0)?, row.get_typed(1)?)))
        .unwrap();
    assert_eq!(active_gen_id, gen_old);
    assert_eq!(active_dim, DIM);

    // While the reader's transaction is still open: on the ORIGINAL writer
    // connection, supersede gen_old and clean it up. Both commit.
    let gen_new = writer_storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", DIM, 1, TS))
        .unwrap();
    schema::switch_active_generation(writer_storage.raw(), gen_new, TS, |_tx| Ok(())).unwrap();
    let outcome = cleanup_orphaned_generations(&writer_storage, TS).expect("cleanup must succeed");
    assert_eq!(outcome.deleted_ids, vec![gen_old], "gen_old must actually get cleaned up by this point");
    assert!(outcome.failures.is_empty());

    // Sanity: a FRESH read (new connection, no prior snapshot) now sees
    // gen_old truly gone -- proving the cleanup above was real, not a
    // no-op that would make the isolation check below vacuous.
    let fresh_row_count: i64 = writer_storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM embedding_generations WHERE id = ?1", fparams![gen_old], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(fresh_row_count, 0, "sanity: gen_old is really gone for a fresh reader");

    // The load-bearing assertion: the reader's ALREADY-OPEN transaction
    // must still see gen_old's message_embeddings row...
    let embedded_count: i64 = reader_tx
        .query_row_map("SELECT COUNT(*) FROM message_embeddings WHERE generation_id = ?1", fparams![active_gen_id], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(embedded_count, 1, "the reader's in-flight snapshot must still see gen_old's embedding row, unaffected by the concurrent cleanup that already deleted it for new readers");

    // ...and its vec0 self-hit must still resolve too, even though the
    // vec0 table itself was DROPed by the concurrent cleanup and no longer
    // exists for a fresh connection -- proving vec0's shadow tables
    // participate in the same MVCC snapshot as ordinary tables here.
    let table = format!("vec_index_gen_{active_gen_id}");
    let blob = schema::f32_vector_to_le_blob(&[1.0, 0.0, 0.0, 0.0]);
    let hits: Vec<(i64, f64)> = reader_tx
        .query_all_map(
            &format!("SELECT rowid, distance FROM {table} WHERE embedding MATCH ?1 AND k = ?2 ORDER BY distance"),
            fparams![blob, 1_i64],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .expect("the reader's snapshot must still be able to query gen_old's vec0 table");
    assert_eq!(hits.first().map(|(id, _)| *id), Some(doc_id), "self-hit must still resolve inside the reader's untouched snapshot");
    assert!(hits.first().is_some_and(|(_, distance)| *distance <= 1e-6));

    drop(reader_tx);
}

/// R1-W3-N4: the vec0 `DROP TABLE` used to run as its own statement
/// *after* the metadata-delete transaction had already committed -- a
/// failure in that separate, later, non-transactional drop left the
/// metadata row gone forever (this function's own candidate-scan query
/// can never find it again) while the vec0 table (and its shadow tables)
/// stayed on disk, orphaned with no code path left that would ever
/// revisit it. Folding the drop into the *same* transaction, issued
/// first, closes exactly that gap: if the drop itself fails, the whole
/// transaction (metadata deletes included) never even runs.
///
/// Proves this with a real failure at the vec0-drop step specifically
/// (not the metadata deletes -- a trigger-aborted metadata delete doesn't
/// distinguish old from new code here, since old code's separate vec0
/// drop is only ever reached *after* a successful metadata commit, so it
/// is simply never attempted either way when the metadata delete itself
/// fails; verified while designing this test, see this item's mutation
/// report). A negative `generation_id` is a real, deterministic way to
/// make `drop_vec0_table_for_generation(_in_tx)`'s own `validate_
/// generation_id_for_ddl` guard reject the DROP outright (SQLite virtual
/// tables can't be created with such a name, and the crate defensively
/// refuses to splice one into DDL text). Pre-fix (drop-after-commit),
/// that guard fires *after* the metadata is already gone; post-fix
/// (drop-first-in-tx), it fires before anything is touched.
///
/// R2-N2: this candidate's rejected delete is now caught and recorded in
/// `outcome.failures`, not propagated as an `Err` from the whole
/// function -- this test's outer assertion was updated for that (`Ok`
/// with a `failures` entry, not `Err`), but everything below it about the
/// per-candidate transaction rolling back cleanly is unchanged.
#[test]
fn cleanup_never_deletes_metadata_when_its_vec0_drop_is_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("agent_search.db");
    let storage = open_storage(&db_path);
    let (conv_id, doc_id) = insert_one_message_conversation(&storage, "w3-n4-invalid-id");

    // A malformed orphan candidate: negative generation_id. The real
    // `create_embedding_generation` path (AUTOINCREMENT) never produces
    // one -- this simulates whatever real-world condition could someday
    // hand the DDL layer a generation_id `validate_generation_id_for_ddl`
    // must refuse, while still exercising this function's real SQL path
    // end to end.
    let old_created_at = TS - 2 * DAY_MS;
    storage
        .raw()
        .execute(
            "INSERT INTO embedding_generations (id, embedder_id, dim, canonicalize_version, byte_order, created_at, is_active, audit_status) \
             VALUES (-7, 'bge-m3', ?1, 1, 'le', ?2, 0, 'passed')",
            fparams![DIM, old_created_at],
        )
        .unwrap();
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::insert_message_embedding(tx, -7, doc_id, conv_id, &[1.0, 0.0, 0.0, 0.0], "seed-hash", None, old_created_at)
        })
        .unwrap();

    // R2-N2: a second, entirely legitimate orphan candidate alongside the
    // malformed one -- proves the fix's actual point (one candidate
    // failing must not block the rest), not just "the whole call no
    // longer errors".
    let (conv_id_b, doc_id_b) = insert_one_message_conversation(&storage, "w3-n4-legit-sibling");
    let gen_legit = build_active_passed_generation(&storage, doc_id_b, conv_id_b, old_created_at);
    let gen_new = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", DIM, 1, TS))
        .unwrap();
    schema::switch_active_generation(storage.raw(), gen_new, TS, |_tx| Ok(())).unwrap();

    let outcome = cleanup_orphaned_generations(&storage, TS).expect("the whole cleanup call must still succeed -- only the malformed candidate is rejected");
    assert_eq!(outcome.deleted_ids, vec![gen_legit], "the legitimate sibling candidate must still be deleted despite the other candidate's failure");
    assert_eq!(outcome.failures.len(), 1, "the rejected candidate must be recorded in failures: {:?}", outcome.failures);
    assert_eq!(outcome.failures[0].0, -7);

    let row_count: i64 = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM embedding_generations WHERE id = -7", &[] as &[V], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(
        row_count, 1,
        "the metadata row for the rejected candidate must survive intact -- the vec0-drop \
         rejection happens first, inside the same transaction as the metadata deletes, so \
         nothing downstream of it ever runs either"
    );
    let embeddings_count: i64 = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM message_embeddings WHERE generation_id = -7", &[] as &[V], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(embeddings_count, 1, "its message_embeddings row must survive too -- nothing partially committed");
}

/// R3-6: the *initial orphan-scan query itself* failing used to `?`
/// straight out of `cleanup_orphaned_generations` -- called at the tail
/// of `run_db_vector_catchup_backfill`, after that same call's own
/// `switch_active_generation` had already committed an activation, so a
/// housekeeping-only failure here turned an otherwise fully successful
/// run into an `Err` (the exact same-shaped bug R2-N2 fixed for a
/// per-candidate delete failure, just the one remaining `?` its own fix
/// left standing). Drops `embedding_generations` out from under the scan
/// query to force a real SQL error deterministically, mirroring this
/// file's convention (see `cleanup_never_deletes_metadata_when_its_vec0_
/// drop_is_rejected`'s doc comment) of using raw-SQL corruption only to
/// simulate a condition a live write path could never itself produce.
#[test]
fn cleanup_folds_a_scan_failure_into_ok_outcome_failures_instead_of_propagating_as_err() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("agent_search.db");
    let storage = open_storage(&db_path);
    let (conv_id, doc_id) = insert_one_message_conversation(&storage, "w3-r3-6-scan-failure");

    // A genuine orphan candidate exists (superseded by a switch that has
    // already committed), so this test also proves the scan-failure path
    // is reached before any candidate work -- not merely "there was
    // nothing to clean up anyway".
    let old_created_at = TS - 2 * DAY_MS;
    let _gen_orphan = build_active_passed_generation(&storage, doc_id, conv_id, old_created_at);
    let gen_new = storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", DIM, 1, TS))
        .unwrap();
    schema::switch_active_generation(storage.raw(), gen_new, TS, |_tx| Ok(())).unwrap();

    // Renaming the column the scan's own `WHERE` clause depends on breaks
    // just that query ("no such column") without touching the table's FK
    // relationships at all (unlike dropping/renaming the table itself,
    // which `message_embeddings`/`embedding_holes` reference by FK, and
    // which `storage::api` deliberately refuses to let raw SQL bypass).
    storage.raw().execute("ALTER TABLE embedding_generations RENAME COLUMN created_at TO created_at_renamed_for_test", fparams![]).unwrap();

    let outcome = cleanup_orphaned_generations(&storage, TS)
        .expect("R3-6: a scan-level failure must be folded into Ok(outcome.failures), not propagated as Err");
    assert!(outcome.deleted_ids.is_empty(), "nothing could have been scanned, let alone deleted");
    assert_eq!(outcome.failures.len(), 1, "the scan failure itself must be recorded: {:?}", outcome.failures);
    assert_eq!(outcome.failures[0].0, 0, "a scan-level failure has no real generation_id -- 0 is never a real AUTOINCREMENT id");
    assert!(
        outcome.failures[0].1.contains("orphan-scan"),
        "failure detail must be traceable to the scan query, not a generic/opaque message: {:?}",
        outcome.failures[0]
    );
}
