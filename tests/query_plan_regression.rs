//! w1b Task B9 Step 2 (plan's "缺陷 A 思想平移"): guards against the
//! specific historical defect class this migration exists to retire --
//! a hot-path point query silently degrading to a full table scan because
//! the underlying engine failed to use the primary-key index. `EXPLAIN QUERY
//! PLAN` is queried directly rather than trusting elapsed-time heuristics,
//! so a regression is caught deterministically instead of only showing up
//! as noisy p95 drift.

use coding_agent_search::storage::api::Value as ParamValue;
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::testing::open_writable_for_tests;
use coding_agent_search::storage::api::Profile;
use tempfile::TempDir;

/// Test-only parameter list builder (this integration test is a separate
/// crate and can't reach `storage::api`'s crate-private `params!` shim):
/// mirrors sqlite.rs's own `fparams!` / the same shim other integration
/// tests in this suite already define locally.
macro_rules! fparams {
    () => {
        &[] as &[ParamValue]
    };
    ($($val:expr),+ $(,)?) => {
        &[$(coding_agent_search::storage::api::IntoValue::into_value($val)),+] as &[ParamValue]
    };
}

const FIXTURE_ROW_COUNT: i64 = 100_000;

/// Seed one agent + one conversation + `FIXTURE_ROW_COUNT` messages through
/// the real production schema (`FrankenStorage::open` runs `schema::ensure`,
/// so `messages.id` is the genuine `INTEGER PRIMARY KEY` rowid alias the
/// production query planner sees).
fn seed_messages_fixture(db_path: &std::path::Path) {
    let storage = FrankenStorage::open(db_path).expect("open fixture db");
    let conn = storage.raw();
    conn.execute(
        "INSERT INTO agents(id, slug, name, kind, created_at, updated_at) \
         VALUES (1, 'codex', 'Codex', 'cli', 0, 0)",
        fparams![],
    )
    .expect("seed agent");
    conn.execute(
        "INSERT INTO conversations(id, agent_id, source_path) VALUES (1, 1, '/tmp/fixture.jsonl')",
        fparams![],
    )
    .expect("seed conversation");

    conn.with_tx_no_replay(coding_agent_search::storage::api::TxMode::Immediate, |tx| {
        for idx in 0..FIXTURE_ROW_COUNT {
            tx.execute(
                "INSERT INTO messages(id, conversation_id, idx, role, content) \
                 VALUES (?1, 1, ?2, 'user', ?3)",
                fparams![idx + 1, idx, format!("fixture message {idx}")],
            )?;
        }
        Ok(())
    })
    .expect("bulk-insert fixture messages");
}

/// Same fixture shape, but `messages_no_pk` has no primary key / index on
/// `id` at all -- an ordinary rowid-less lookup column. Used only by the
/// negative-control test below to prove the assertion in
/// `hydrate_by_ids_uses_pk_index` has teeth.
fn seed_no_pk_fixture(db_path: &std::path::Path) {
    let conn = open_writable_for_tests(db_path, Profile::Production).expect("open no-pk fixture db");
    // PK on an unrelated column -- `id` itself is deliberately left
    // unindexed, which is the whole point of this fixture.
    conn.execute_batch(
        "CREATE TABLE messages_no_pk (row_key INTEGER PRIMARY KEY, id INTEGER, content TEXT);",
    )
    .expect("create no-pk table");
    conn.with_tx_no_replay(coding_agent_search::storage::api::TxMode::Immediate, |tx| {
        for idx in 0..FIXTURE_ROW_COUNT {
            tx.execute(
                "INSERT INTO messages_no_pk(row_key, id, content) VALUES (?1, ?2, ?3)",
                fparams![idx, idx + 1, format!("fixture message {idx}")],
            )?;
        }
        Ok(())
    })
    .expect("bulk-insert no-pk fixture rows");
}

#[test]
fn hydrate_by_ids_uses_pk_index() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("query-plan-regression.db");
    seed_messages_fixture(&db_path);

    let storage = FrankenStorage::open(&db_path).expect("reopen fixture db");
    let plan: Vec<String> = storage
        .raw()
        .query_all_map(
            "EXPLAIN QUERY PLAN SELECT id, content FROM messages WHERE id IN (?1,?2,?3)",
            fparams![1_i64, 2_i64, 3_i64],
            |r| r.get_typed::<String>(3),
        )
        .unwrap();
    assert!(
        plan.iter().any(|d| d.contains("USING INTEGER PRIMARY KEY")
            || d.contains("USING ROWID SEARCH")
            || d.contains("USING INDEX")),
        "plan degraded to scan: {plan:?}"
    );
}

/// Negative control (探针自验): the same assertion against a table where
/// `id` genuinely has no index proves the assertion above would actually
/// catch a real regression, rather than being vacuously true against any
/// query plan shape.
#[test]
#[should_panic(expected = "plan degraded to scan")]
fn hydrate_by_ids_without_pk_index_degrades_to_scan() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("query-plan-regression-no-pk.db");
    seed_no_pk_fixture(&db_path);

    let conn = open_writable_for_tests(&db_path, Profile::Production).expect("reopen no-pk fixture db");
    let plan: Vec<String> = conn
        .query_all_map(
            "EXPLAIN QUERY PLAN SELECT id, content FROM messages_no_pk WHERE id IN (?1,?2,?3)",
            fparams![1_i64, 2_i64, 3_i64],
            |r| r.get_typed::<String>(3),
        )
        .unwrap();
    assert!(
        plan.iter().any(|d| d.contains("USING INTEGER PRIMARY KEY")
            || d.contains("USING ROWID SEARCH")
            || d.contains("USING INDEX")),
        "plan degraded to scan: {plan:?}"
    );
}
