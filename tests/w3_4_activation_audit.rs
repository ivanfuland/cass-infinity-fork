//! W3-4 Step1 (task book #62): full activation-audit test matrix, one test
//! per spec-numbered assertion (spec 逐款) plus one all-pass baseline.
//! Replaces `switch_active_generation`'s old minimal verify closure (which
//! only checked `embedded_count > 0`) with a real six-invariant audit:
//! ① exact dim/length match, ② finite+norm resample, ③ positive
//! self-hit content check, ④ bidirectional identity-set anti-join,
//! ⑤ canonicalize-version match, ⑥ `PRAGMA foreign_key_check`.
//!
//! Fixtures use the same production write entry points as
//! `w3_vector_lifecycle.rs` (`insert_conversation_tree`,
//! `schema::insert_message_embedding`) -- raw-SQL bypass is used only to
//! *simulate corruption* a live write path could never itself produce
//! (dim/finite/norm/FK violations), exactly the class of defect this
//! audit exists to catch post-hoc.

use coding_agent_search::indexer::db_vector_catchup::run_activation_audit_and_record;
use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::search::canonicalize::CANONICALIZE_PIPELINE_VERSION;
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

fn open_storage(path: &std::path::Path) -> FrankenStorage {
    FrankenStorage::open(path).expect("open production storage")
}

fn ensure_agent(storage: &FrankenStorage) -> i64 {
    storage
        .ensure_agent(&Agent { id: None, slug: "claude_code".into(), name: "Claude Code".into(), version: Some("1.0".into()), kind: AgentKind::Cli })
        .expect("ensure agent")
}

fn msg(idx: i64, role: MessageRole, content: &str) -> Message {
    Message { id: None, idx, role, author: None, created_at: Some(TS + idx * 1_000), content: content.into(), extra_json: serde_json::Value::Null, snippets: vec![] }
}

fn conversation(external_id: &str, messages: Vec<Message>) -> Conversation {
    Conversation {
        id: None,
        agent_slug: "claude_code".into(),
        workspace: None,
        external_id: Some(external_id.into()),
        title: Some("w3-4 activation-audit fixture".into()),
        source_path: std::path::PathBuf::from(format!("/fixtures/{external_id}.jsonl")),
        started_at: Some(TS),
        ended_at: Some(TS + 60_000),
        approx_tokens: None,
        metadata_json: serde_json::Value::Null,
        messages,
        source_id: "local".into(),
        origin_host: None,
    }
}

fn conv_id_of(storage: &FrankenStorage, external_id: &str) -> i64 {
    storage.raw().query_row_map("SELECT id FROM conversations WHERE external_id = ?1", fparams![external_id], |row| row.get_typed::<i64>(0)).unwrap()
}

fn message_id_at_idx(storage: &FrankenStorage, conv_id: i64, idx: i64) -> i64 {
    storage.raw().query_row_map("SELECT id FROM messages WHERE conversation_id = ?1 AND idx = ?2", fparams![conv_id, idx], |row| row.get_typed(0)).unwrap()
}

fn audit_status_of(storage: &FrankenStorage, generation_id: i64) -> String {
    storage.raw().query_row_map("SELECT audit_status FROM embedding_generations WHERE id = ?1", fparams![generation_id], |row| row.get_typed(0)).unwrap()
}

fn create_generation(storage: &FrankenStorage, canonicalize_version: u32) -> i64 {
    storage.raw().with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", DIM, canonicalize_version, TS)).unwrap()
}

fn embed(storage: &FrankenStorage, gen_id: i64, doc_id: i64, conv_id: i64, vector: &[f32]) {
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| schema::insert_message_embedding(tx, gen_id, doc_id, conv_id, vector, "seed-hash", None, TS))
        .unwrap();
}

fn rebuild_vec0(storage: &FrankenStorage, gen_id: i64) {
    vector_domain::create_vec0_table_for_generation(storage.raw(), gen_id, DIM).unwrap();
    vector_domain::rebuild_vec0_table_for_generation(storage.raw(), gen_id, DIM).unwrap();
}

/// One eligible conversation with two distinct-content messages, both
/// embedded (orthonormal dim=4 vectors), generation identity matches
/// production (`CANONICALIZE_PIPELINE_VERSION`), vec0 freshly rebuilt.
/// Every one of the six checks passes against this fixture unmodified --
/// callers corrupt exactly one thing per test from this baseline.
fn clean_two_message_fixture(storage: &FrankenStorage) -> (i64, i64, i64) {
    let agent_id = ensure_agent(storage);
    let conv = conversation(
        "w3-4-clean",
        vec![msg(0, MessageRole::User, "the quick brown fox jumps"), msg(1, MessageRole::Agent, "over the lazy dog")],
    );
    storage.insert_conversation_tree(agent_id, None, &conv).expect("insert fixture conversation");
    let conv_id = conv_id_of(storage, "w3-4-clean");
    let doc_a = message_id_at_idx(storage, conv_id, 0);
    let doc_b = message_id_at_idx(storage, conv_id, 1);

    let gen_id = create_generation(storage, CANONICALIZE_PIPELINE_VERSION);
    embed(storage, gen_id, doc_a, conv_id, &[1.0, 0.0, 0.0, 0.0]);
    embed(storage, gen_id, doc_b, conv_id, &[0.0, 1.0, 0.0, 0.0]);
    rebuild_vec0(storage, gen_id);
    (gen_id, doc_a, doc_b)
}

#[test]
fn full_audit_passes_and_records_passed_on_a_clean_generation() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (gen_id, _doc_a, _doc_b) = clean_two_message_fixture(&storage);

    assert_eq!(audit_status_of(&storage, gen_id), "pending", "前置：新代际起始为 pending");

    let report = run_activation_audit_and_record(&storage, gen_id, 100, None).expect("audit must run without a hard error");
    assert!(report.passed, "clean fixture must pass every check: {:?}", report.failure_reasons);
    assert_eq!(audit_status_of(&storage, gen_id), "passed", "全过必须把 audit_status 落 passed");
}

#[test]
fn audit_fails_on_dim_length_mismatch() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (gen_id, doc_a, _doc_b) = clean_two_message_fixture(&storage);

    // Simulate corruption a live write path can never itself produce: a
    // BLOB whose length satisfies the DDL's `% 4 = 0` backstop but not
    // this generation's exact dim=4 (8 floats instead of 4).
    let bad_blob = schema::f32_vector_to_le_blob(&[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
    storage.raw().execute("UPDATE message_embeddings SET embedding = ?1 WHERE generation_id = ?2 AND doc_id = ?3", fparams![bad_blob, gen_id, doc_a]).unwrap();

    let report = run_activation_audit_and_record(&storage, gen_id, 100, None).expect("audit runs, verdict is failure not an error");
    assert!(!report.passed, "dim-length mismatch must fail the audit");
    assert_eq!(report.dim_mismatch_count, 1);
    assert_eq!(audit_status_of(&storage, gen_id), "failed");
}

#[test]
fn audit_fails_on_non_finite_element_in_sample() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (gen_id, doc_a, _doc_b) = clean_two_message_fixture(&storage);

    let nan_blob = schema::f32_vector_to_le_blob(&[f32::NAN, 0.0, 0.0, 0.0]);
    storage.raw().execute("UPDATE message_embeddings SET embedding = ?1 WHERE generation_id = ?2 AND doc_id = ?3", fparams![nan_blob, gen_id, doc_a]).unwrap();

    let report = run_activation_audit_and_record(&storage, gen_id, 100, None).expect("audit runs, verdict is failure not an error");
    assert!(!report.passed, "a NaN element must fail the audit");
    assert!(report.finite_norm_violation_count >= 1);
    assert_eq!(audit_status_of(&storage, gen_id), "failed");
}

#[test]
fn audit_fails_on_norm_recompute_mismatch() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (gen_id, doc_a, _doc_b) = clean_two_message_fixture(&storage);

    // Vector stays a valid finite unit vector; only the stored `norm`
    // column is corrupted so it disagrees with a fresh recompute off the
    // BLOB -- the norm/BLOB consistency invariant this check exists for.
    storage.raw().execute("UPDATE message_embeddings SET norm = 999.0 WHERE generation_id = ?1 AND doc_id = ?2", fparams![gen_id, doc_a]).unwrap();

    let report = run_activation_audit_and_record(&storage, gen_id, 100, None).expect("audit runs, verdict is failure not an error");
    assert!(!report.passed, "a stored norm that disagrees with recompute must fail the audit");
    assert!(report.finite_norm_violation_count >= 1);
    assert_eq!(audit_status_of(&storage, gen_id), "failed");
}

#[test]
fn audit_fails_on_stale_vec0_self_hit_drift() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (gen_id, doc_a, _doc_b) = clean_two_message_fixture(&storage);

    // Authoritative table now disagrees with the already-built vec0
    // index (no rebuild issued after this write) -- the KU2 "vec0 is a
    // derived index, never a second source of truth" drift this check
    // exists to catch. Still a valid finite unit vector, orthogonal to
    // what vec0 has on file for this doc_id.
    storage
        .raw()
        .execute(
            "UPDATE message_embeddings SET embedding = ?1, norm = 1.0 WHERE generation_id = ?2 AND doc_id = ?3",
            fparams![schema::f32_vector_to_le_blob(&[0.0, 0.0, 1.0, 0.0]), gen_id, doc_a],
        )
        .unwrap();

    let report = run_activation_audit_and_record(&storage, gen_id, 100, Some(doc_a)).expect("audit runs, verdict is failure not an error");
    assert!(!report.passed, "a vec0 index stale relative to message_embeddings must fail the positive-content self-hit check");
    assert_eq!(audit_status_of(&storage, gen_id), "failed");
}

#[test]
fn audit_fails_on_eligible_message_missing_its_embedding() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let agent_id = ensure_agent(&storage);

    // Two eligible messages exist in `messages`, but only one gets
    // embedded -- the generation is missing coverage for a real,
    // embeddable message (R1-W3-N3 territory: a genuine hole, not one
    // this audit is allowed to wave through).
    let conv = conversation("w3-4-missing-embedding", vec![msg(0, MessageRole::User, "eligible message one"), msg(1, MessageRole::Agent, "eligible message two")]);
    storage.insert_conversation_tree(agent_id, None, &conv).expect("insert fixture conversation");
    let conv_id = conv_id_of(&storage, "w3-4-missing-embedding");
    let doc_a = message_id_at_idx(&storage, conv_id, 0);

    let gen_id = create_generation(&storage, CANONICALIZE_PIPELINE_VERSION);
    embed(&storage, gen_id, doc_a, conv_id, &[1.0, 0.0, 0.0, 0.0]);
    rebuild_vec0(&storage, gen_id);

    let report = run_activation_audit_and_record(&storage, gen_id, 100, Some(doc_a)).expect("audit runs, verdict is failure not an error");
    assert!(!report.passed, "an eligible message with no embedding row must fail the identity-set check");
    assert_eq!(report.eligible_not_embedded_count, 1);
    assert_eq!(audit_status_of(&storage, gen_id), "failed");
}

#[test]
fn audit_fails_on_embedded_doc_not_in_eligible_set() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let agent_id = ensure_agent(&storage);

    // One real eligible+embedded message, plus a second message whose
    // content is empty -- excluded by the packet-projection filter
    // before canonicalize even runs (same exclusion the 8MiB-truncation
    // debt in the backfill report relies on) -- yet it still has a
    // (spurious) embedding row, simulating a stale/orphaned embedding
    // for content that is no longer eligible.
    let conv = conversation("w3-4-spurious-embedding", vec![msg(0, MessageRole::User, "eligible message one"), msg(1, MessageRole::Agent, "")]);
    storage.insert_conversation_tree(agent_id, None, &conv).expect("insert fixture conversation");
    let conv_id = conv_id_of(&storage, "w3-4-spurious-embedding");
    let doc_a = message_id_at_idx(&storage, conv_id, 0);
    let doc_empty = message_id_at_idx(&storage, conv_id, 1);

    let gen_id = create_generation(&storage, CANONICALIZE_PIPELINE_VERSION);
    embed(&storage, gen_id, doc_a, conv_id, &[1.0, 0.0, 0.0, 0.0]);
    embed(&storage, gen_id, doc_empty, conv_id, &[0.0, 1.0, 0.0, 0.0]);
    rebuild_vec0(&storage, gen_id);

    let report = run_activation_audit_and_record(&storage, gen_id, 100, Some(doc_a)).expect("audit runs, verdict is failure not an error");
    assert!(!report.passed, "an embedded doc_id no longer in the eligible set must fail the identity-set check");
    assert_eq!(report.embedded_not_eligible_count, 1);
    assert_eq!(audit_status_of(&storage, gen_id), "failed");
}

#[test]
fn audit_fails_on_canonicalize_version_mismatch() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let agent_id = ensure_agent(&storage);
    let conv = conversation("w3-4-version-mismatch", vec![msg(0, MessageRole::User, "the quick brown fox jumps")]);
    storage.insert_conversation_tree(agent_id, None, &conv).expect("insert fixture conversation");
    let conv_id = conv_id_of(&storage, "w3-4-version-mismatch");
    let doc_a = message_id_at_idx(&storage, conv_id, 0);

    // Generation identity carries a canonicalize_version that no longer
    // matches the running binary's W3-0 fingerprint (an upgrade landed
    // without a fresh generation) -- must be rejected even though every
    // other invariant is clean.
    let gen_id = create_generation(&storage, CANONICALIZE_PIPELINE_VERSION + 1);
    embed(&storage, gen_id, doc_a, conv_id, &[1.0, 0.0, 0.0, 0.0]);
    rebuild_vec0(&storage, gen_id);

    let report = run_activation_audit_and_record(&storage, gen_id, 100, Some(doc_a)).expect("audit runs, verdict is failure not an error");
    assert!(!report.passed, "a canonicalize_version mismatch must fail the audit");
    assert_ne!(report.canonicalize_version_actual, i64::from(report.canonicalize_version_expected));
    assert_eq!(audit_status_of(&storage, gen_id), "failed");
}

#[test]
fn audit_fails_on_foreign_key_violation() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (gen_id, doc_a, _doc_b) = clean_two_message_fixture(&storage);

    // Orphan a message_embeddings row by deleting its parent `messages`
    // row with FK enforcement suspended on a second raw connection (the
    // crate's own `execute_batch_bypassing_foreign_keys_guard` is
    // `pub(crate)`, unreachable from this external test crate -- a bare
    // second `rusqlite` connection to the same file is this test's own
    // bypass, same spirit as the existing r2b1 stray-residue test in
    // src/indexer/mod.rs). Simulates a corruption class this
    // generation's own write path (always CASCADE) could never itself
    // produce.
    storage.close_without_checkpoint().unwrap();
    {
        let raw = rusqlite::Connection::open(dir.path().join("db.sqlite")).unwrap();
        raw.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        raw.execute("DELETE FROM messages WHERE id = ?1", rusqlite::params![doc_a]).unwrap();
        raw.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    }
    let storage = open_storage(&dir.path().join("db.sqlite"));

    let report = run_activation_audit_and_record(&storage, gen_id, 100, None).expect("audit runs, verdict is failure not an error");
    assert!(!report.passed, "an orphaned message_embeddings row must fail PRAGMA foreign_key_check");
    assert!(report.foreign_key_violation_count >= 1);
    assert_eq!(audit_status_of(&storage, gen_id), "failed");
}

#[test]
fn audit_never_touches_the_active_generation_pointer() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (gen_id, doc_a, _doc_b) = clean_two_message_fixture(&storage);

    // Mark active first (simulating switch's minimal-verify-era
    // activation, exactly staging generation_id=1's real starting state
    // per the backfill report: is_active=1, audit_status='pending').
    storage.raw().execute("UPDATE embedding_generations SET is_active = 1 WHERE id = ?1", fparams![gen_id]).unwrap();

    // Corrupt it so the audit fails.
    let bad_blob = schema::f32_vector_to_le_blob(&[1.0, 0.0]);
    storage.raw().execute("UPDATE message_embeddings SET embedding = ?1 WHERE generation_id = ?2 AND doc_id = ?3", fparams![bad_blob, gen_id, doc_a]).unwrap();

    let report = run_activation_audit_and_record(&storage, gen_id, 100, None).expect("audit runs, verdict is failure not an error");
    assert!(!report.passed);

    let is_active: i64 = storage.raw().query_row_map("SELECT is_active FROM embedding_generations WHERE id = ?1", fparams![gen_id], |row| row.get_typed(0)).unwrap();
    assert_eq!(is_active, 1, "a failed audit must never move the is_active pointer -- it only ever writes audit_status");
}

/// R1-W3-B8 (exec60 real-corpus gate run, 2026-09-02): two messages with
/// byte-identical content -- and therefore, in production, an identical
/// embedding -- produce an exact zero-distance *tie* in check ③'s
/// `vec0_knn(k=1)` self-hit query. `ORDER BY distance` has no secondary
/// key, so which of the two tied rows sorts first is unspecified; it need
/// not be the anchor row itself. Both `embed()` calls below share the
/// exact same vector *and* the exact same `content_hash` literal
/// (`"seed-hash"`, this file's placeholder for "identical content"),
/// simulating the genuine content-twin case the fix must tolerate.
fn duplicate_content_two_message_fixture(storage: &FrankenStorage) -> (i64, i64, i64, [f32; 4]) {
    let agent_id = ensure_agent(storage);
    let conv = conversation(
        "w3-8-duplicate-content",
        vec![msg(0, MessageRole::User, "same message twice"), msg(1, MessageRole::User, "same message twice")],
    );
    storage.insert_conversation_tree(agent_id, None, &conv).expect("insert fixture conversation");
    let conv_id = conv_id_of(storage, "w3-8-duplicate-content");
    let doc_a = message_id_at_idx(storage, conv_id, 0);
    let doc_b = message_id_at_idx(storage, conv_id, 1);

    let gen_id = create_generation(storage, CANONICALIZE_PIPELINE_VERSION);
    let twin_vector = [0.6, 0.8, 0.0, 0.0];
    embed(storage, gen_id, doc_a, conv_id, &twin_vector);
    embed(storage, gen_id, doc_b, conv_id, &twin_vector);
    rebuild_vec0(storage, gen_id);
    (gen_id, doc_a, doc_b, twin_vector)
}

#[test]
fn audit_check3_tolerates_a_zero_distance_content_twin_tie() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (gen_id, doc_a, doc_b, twin_vector) = duplicate_content_two_message_fixture(&storage);

    // Which of the two tied rows vec0 actually returns first for an exact
    // tie is implementation-defined (no secondary sort key) -- don't
    // hardcode an assumption about it. Anchor the audit on whichever one
    // is NOT the natural top-1, so this test always exercises the tie
    // path (anchoring on the natural winner would trivially pass even
    // without the fix and prove nothing).
    let hits = vector_domain::vec0_knn(storage.raw(), gen_id, &twin_vector, 2).expect("knn probe for test setup");
    let natural_winner = hits.first().map(|(id, _)| *id).expect("both twin rows must be present in vec0");
    let anchor = if natural_winner == doc_a { doc_b } else { doc_a };

    let report = run_activation_audit_and_record(&storage, gen_id, 100, Some(anchor)).expect("audit must run without a hard error");
    assert!(
        report.passed,
        "an exact content-identical tie must still pass check ③ (twin content, not corruption): {:?}",
        report.failure_reasons
    );
    assert_eq!(audit_status_of(&storage, gen_id), "passed");
}

/// R1-W3-B5: none of checks ①-⑥ ever count `vec0`'s rows overall -- ①/②/④
/// only read `message_embeddings`, and ③'s KNN probe only confirms one
/// specific row is present. Deleting a `vec0` row for a doc_id that check
/// ③ never happens to anchor on (both fixture docs still self-hit fine
/// individually) must still fail the audit once check ⑦ exists.
#[test]
fn audit_fails_on_vec0_row_count_deficit_against_message_embeddings() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (gen_id, _doc_a, doc_b) = clean_two_message_fixture(&storage);

    // Silently drop one row from the derived vec0 index without touching
    // the authoritative message_embeddings table -- exactly the "rebuild
    // populated fewer rows than it read" class of defect check ⑦ exists
    // to catch, and one checks ①-⑥ have no way to see (check ③'s anchor
    // is auto-picked as MIN(doc_id), i.e. doc_a, which still self-hits
    // fine after doc_b's row is gone).
    let vec0_table = format!("vec_index_gen_{gen_id}");
    storage.raw().execute(&format!("DELETE FROM {vec0_table} WHERE rowid = ?1"), fparams![doc_b]).unwrap();

    let report = run_activation_audit_and_record(&storage, gen_id, 100, None).expect("audit runs, verdict is failure not an error");
    assert!(
        !report.passed,
        "a vec0 row-count deficit against message_embeddings must fail the audit"
    );
    assert_eq!(report.vec0_row_count, 1, "vec0 must report the actual post-deletion row count");
    assert_eq!(report.message_embeddings_row_count, 2, "message_embeddings must be untouched by the vec0-only deletion");
    assert!(
        report.failure_reasons.iter().any(|r| r.contains('⑦')),
        "failure reasons must name check ⑦: {:?}",
        report.failure_reasons
    );
    assert_eq!(audit_status_of(&storage, gen_id), "failed");
}

/// R2-B4: the equal-size shape check ⑦'s original plain `COUNT(*)`
/// comparison could not see -- vec0 loses `doc_b`'s row but gains a
/// different, unrelated one, so `vec0_row_count` (2) still equals
/// `message_embeddings_row_count` (2) even though the two tables no
/// longer hold the same identity set. A pre-fix count-only check ⑦ would
/// have reported this generation `passed`; the bidirectional anti-join
/// must catch it.
#[test]
fn audit_fails_on_equal_size_vec0_identity_set_swap() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let (gen_id, _doc_a, doc_b) = clean_two_message_fixture(&storage);

    let vec0_table = format!("vec_index_gen_{gen_id}");
    // Swap doc_b's row out for an unrelated bogus rowid -- vec0's row
    // count stays 2 (equal to message_embeddings' 2), but the identity
    // sets now disagree: message_embeddings has {doc_a, doc_b}, vec0 has
    // {doc_a, 999_999}.
    storage.raw().execute(&format!("DELETE FROM {vec0_table} WHERE rowid = ?1"), fparams![doc_b]).unwrap();
    let bogus_blob = coding_agent_search::storage::schema::f32_vector_to_le_blob(&[0.0, 0.0, 1.0, 0.0]);
    storage
        .raw()
        .execute(&format!("INSERT INTO {vec0_table}(rowid, embedding) VALUES (999999, ?1)"), fparams![bogus_blob])
        .unwrap();

    let report = run_activation_audit_and_record(&storage, gen_id, 100, None).expect("audit runs, verdict is failure not an error");
    assert!(
        !report.passed,
        "an equal-size but mismatched-identity-set vec0 index must fail the audit, not pass on count alone"
    );
    assert_eq!(report.vec0_row_count, 2, "sanity: vec0's plain row count must equal message_embeddings' (the shape this test targets)");
    assert_eq!(report.message_embeddings_row_count, 2);
    assert_eq!(report.message_embeddings_rows_missing_from_vec0, 1, "doc_b must be reported missing from vec0");
    assert_eq!(report.vec0_rows_missing_from_message_embeddings, 1, "the bogus rowid must be reported extra in vec0");
    assert!(
        report.failure_reasons.iter().any(|r| r.contains('⑦')),
        "failure reasons must name check ⑦: {:?}",
        report.failure_reasons
    );
    assert_eq!(audit_status_of(&storage, gen_id), "failed");
}

/// R2-B4 real-scale cost disclosure: the bidirectional anti-join
/// ([`vector_domain::count_vec0_message_embeddings_set_mismatch_for_generation`])
/// runs two `NOT EXISTS` subqueries per activation audit, replacing what
/// was a single `COUNT(*)` comparison -- this discloses what that costs at
/// a 20k-row generation, the scale item B6 already used for its own
/// disclosure. `dim=4` (not bge-m3's real 1024): the anti-join only
/// compares `rowid`/`doc_id` identity, never decodes a vector, so the
/// embedding dimension does not affect this specific check's cost --
/// check ②'s finite/norm resample is the only audit step that does, and
/// its `finite_norm_sample_size` is fixed regardless of corpus size.
/// `#[ignore]`d for the same reason as B6's sibling probe: 20k rows of
/// direct-`tx.execute` seeding is disk/CPU work with no correctness
/// assertion beyond "printed a number", not a regression test; run
/// explicitly with `--ignored` to reproduce this disclosure's numbers.
#[test]
#[ignore = "perf disclosure probe (R2-B4); run explicitly with --ignored"]
fn audit_check7_anti_join_cost_disclosure_at_20k_rows() {
    use coding_agent_search::storage::api::TxMode as TM;

    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    const TOTAL_DOCS: i64 = 20_000;
    const DIM: i64 = 4;

    let agent_id = ensure_agent(&storage);
    let conn = storage.raw();
    conn.execute("INSERT OR IGNORE INTO sources(id, kind, created_at, updated_at) VALUES ('local', 'local', 0, 0)", fparams![])
        .unwrap();

    let seed_start = std::time::Instant::now();
    let gen_id = conn.with_tx_no_replay(TM::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", DIM, CANONICALIZE_PIPELINE_VERSION, TS)).unwrap();
    conn.with_tx_no_replay(TM::Immediate, |tx| {
        for i in 0..TOTAL_DOCS {
            let message_id = 9_000_000 + i;
            tx.execute(
                "INSERT INTO conversations(id, agent_id, source_id, title, source_path) VALUES (?1, ?2, 'local', 't', ?3)",
                fparams![message_id, agent_id, format!("/tmp/c-{message_id}.jsonl")],
            )?;
            tx.execute(
                "INSERT INTO messages(id, conversation_id, idx, role, created_at, content) VALUES (?1, ?2, 0, 'user', ?3, 'c')",
                fparams![message_id, message_id, TS + i],
            )?;
            let theta = (i as f32) * 0.001;
            schema::insert_message_embedding(tx, gen_id, message_id, message_id, &[theta.cos(), theta.sin(), 0.0, 0.0], "seed-hash", None, TS)?;
        }
        Ok(())
    })
    .unwrap();
    vector_domain::create_vec0_table_for_generation(conn, gen_id, DIM).unwrap();
    vector_domain::rebuild_vec0_table_for_generation(conn, gen_id, DIM).unwrap();
    let seed_elapsed = seed_start.elapsed();

    let anti_join_start = std::time::Instant::now();
    let (missing_from_vec0, extra_in_vec0) = vector_domain::count_vec0_message_embeddings_set_mismatch_for_generation(conn, gen_id).unwrap();
    let anti_join_elapsed = anti_join_start.elapsed();
    assert_eq!((missing_from_vec0, extra_in_vec0), (0, 0), "sanity: freshly rebuilt vec0 must match message_embeddings exactly");

    let full_audit_start = std::time::Instant::now();
    let report = run_activation_audit_and_record(&storage, gen_id, 100, None).expect("audit runs on a clean 20k-row generation");
    let full_audit_elapsed = full_audit_start.elapsed();
    assert!(report.passed, "a freshly seeded, freshly rebuilt 20k-row generation must pass every check");

    eprintln!(
        "[R2-B4 perf disclosure] rows={TOTAL_DOCS} dim={DIM} seed_ms={} anti_join_only_ms={} full_audit_ms={}",
        seed_elapsed.as_millis(),
        anti_join_elapsed.as_millis(),
        full_audit_elapsed.as_millis()
    );
}
