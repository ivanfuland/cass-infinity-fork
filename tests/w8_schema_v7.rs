//! PR8 C1: schema v6 → v7 (`conversations.identity_host`, unique key
//! `idx_conversations_identity(identity_host, agent_id, external_id)`,
//! `scan_watermarks` / `scan_file_state`). Rebuild-only, same contract as
//! `tests/w6_schema_v6.rs`: a pre-v7 database must be rejected with
//! `SchemaRebuildRequired`, never migrated in place.
//!
//! Every test builds its own tempdir database; no env vars, statics or shared
//! files are touched, so they are safe under the default parallel runner.

use coding_agent_search::storage::api::{Profile, StorageError};
use coding_agent_search::storage::schema;
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::testing::open_writable_for_tests;

fn scratch_db_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().expect("create scratch dir");
    let path = dir.path().join("agent_search.db");
    (dir, path)
}

fn names(storage: &FrankenStorage, sql: &str) -> Vec<String> {
    storage.raw().query_all_map(sql, &[], |row| row.get_typed(0)).expect(sql)
}

#[test]
fn v7_ddl_present() {
    let (_dir, path) = scratch_db_path();
    let storage = FrankenStorage::open(&path).expect("open production storage (fresh build)");

    let version: i64 =
        storage.raw().query_row_map("PRAGMA user_version;", &[], |row| row.get_typed(0)).expect("read user_version");
    assert_eq!(version, 7, "fresh build must be schema 7");

    let cols = names(&storage, "SELECT name FROM pragma_table_info('conversations')");
    assert!(cols.contains(&"identity_host".to_string()), "conversations must have identity_host, got {cols:?}");
    assert!(cols.contains(&"origin_host".to_string()), "existing origin_host column must stay, got {cols:?}");

    let objects = names(&storage, "SELECT name FROM sqlite_master WHERE type IN ('table', 'index') ORDER BY name");
    for expected in ["idx_conversations_identity", "scan_watermarks", "scan_file_state"] {
        assert!(objects.contains(&expected.to_string()), "missing {expected}, got {objects:?}");
    }
    assert!(
        !objects.contains(&"idx_conversations_provenance".to_string()),
        "idx_conversations_provenance must be gone in schema 7"
    );

    let identity_cols = names(&storage, "SELECT name FROM pragma_index_info('idx_conversations_identity') ORDER BY seqno");
    assert_eq!(identity_cols, vec!["identity_host", "agent_id", "external_id"]);

    let watermark_cols = names(&storage, "SELECT name FROM pragma_table_info('scan_watermarks') ORDER BY cid");
    assert_eq!(watermark_cols, vec!["root_id", "connector", "last_scan_ts"]);
    let file_state_cols = names(&storage, "SELECT name FROM pragma_table_info('scan_file_state') ORDER BY cid");
    assert_eq!(file_state_cols, vec!["root_id", "connector", "relative_path", "size", "mtime", "last_seen_ts"]);
}

#[test]
fn v6_library_requires_rebuild() {
    let (_dir, path) = scratch_db_path();
    let conn = open_writable_for_tests(&path, Profile::Production).expect("schema-free writable conn");
    // Same minimal-marker convention as `tests/w6_schema_v6.rs`: `ensure`'s
    // `0 < found < CURRENT` branch rejects on the version number alone.
    conn.execute_batch("CREATE TABLE probe_marker (id INTEGER PRIMARY KEY); PRAGMA user_version = 6;")
        .expect("build minimal v6 stand-in");

    let err = schema::ensure(&conn).expect_err("ensure must reject a v6 database, not migrate it");
    assert!(
        matches!(err, StorageError::SchemaRebuildRequired { found: 6, required: 7 }),
        "expected SchemaRebuildRequired{{found: 6, required: 7}}, got {err:?}"
    );
}

#[test]
fn identity_index_is_host_scoped() {
    let (_dir, path) = scratch_db_path();
    let storage = FrankenStorage::open(&path).expect("open production storage (fresh build)");
    let conn = storage.raw();
    conn.execute(
        "INSERT INTO agents(id, slug, name, kind, created_at, updated_at) VALUES (1, 'codex', 'Codex', 'cli', 0, 0)",
        &[],
    )
    .expect("insert agent");

    conn.execute(
        "INSERT INTO conversations(agent_id, identity_host, external_id, source_path) VALUES (1, 'local', 'sess-1', 'a')",
        &[],
    )
    .expect("first host insert");
    conn.execute(
        "INSERT INTO conversations(agent_id, identity_host, external_id, source_path) VALUES (1, 'mac', 'sess-1', 'b')",
        &[],
    )
    .expect("same (agent_id, external_id) on a different identity_host must be accepted");

    let dup = conn.execute(
        "INSERT INTO conversations(agent_id, identity_host, external_id, source_path) VALUES (1, 'mac', 'sess-1', 'c')",
        &[],
    );
    let dup_err = dup.expect_err("same (identity_host, agent_id, external_id) must violate the unique index");
    assert!(format!("{dup_err:?}").contains("UNIQUE"), "expected a UNIQUE constraint error, got {dup_err:?}");

    conn.execute("INSERT INTO conversations(agent_id, external_id, source_path) VALUES (1, 'sess-2', 'd')", &[])
        .expect("insert without identity_host");
    let (identity_host, origin_host): (String, Option<String>) = conn
        .query_row_map("SELECT identity_host, origin_host FROM conversations WHERE external_id = 'sess-2'", &[], |row| {
            Ok((row.get_typed(0)?, row.get_typed(1)?))
        })
        .expect("read defaulted row");
    assert_eq!(identity_host, "local");
    assert_eq!(origin_host, None);
}
