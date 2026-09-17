//! PR6 T2a Step 1 (任务书 #113): schema v5 → v6 (`messages.excluded` JSONB
//! column + expression index). Rebuild-only, same contract as the v4 → v5
//! transition in `tests/w4_schema_v5.rs`: a pre-v6 database must be
//! rejected with `SchemaRebuildRequired`, never migrated in place.

use coding_agent_search::storage::api::{Profile, StorageError};
use coding_agent_search::storage::schema;
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::testing::open_writable_for_tests;

fn scratch_db_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().expect("create scratch dir");
    let path = dir.path().join("agent_search.db");
    (dir, path)
}

#[test]
fn schema_ensure_rejects_v5_database_with_found_5_required_6() {
    let (_dir, path) = scratch_db_path();
    let conn = open_writable_for_tests(&path, Profile::Production).expect("schema-free writable conn");
    // Same minimal-marker convention as
    // `schema_ensure_rejects_nonempty_user_version_0_1_2_3_4` in
    // `src/storage/schema.rs`: `ensure`'s `0 < found < CURRENT` branch
    // rejects on the bare version number alone, regardless of actual table
    // shape, so a probe marker plus `user_version = 5` is a faithful stand-in
    // for a real v5 database for this contract.
    conn.execute_batch("CREATE TABLE probe_marker (id INTEGER PRIMARY KEY); PRAGMA user_version = 5;")
        .expect("build minimal v5 stand-in");

    let err = schema::ensure(&conn).expect_err("ensure must reject a v5 database, not migrate it");
    assert!(
        matches!(err, StorageError::SchemaRebuildRequired { found: 5, required: 7 }),
        "expected SchemaRebuildRequired{{found: 5, required: 7}}, got {err:?}"
    );
    assert_eq!(schema::CURRENT_SCHEMA_VERSION, 7, "PR8 C1 bumped CURRENT_SCHEMA_VERSION to 7");
}

#[test]
fn fresh_v6_database_has_excluded_column_and_expression_index() {
    let (_dir, path) = scratch_db_path();
    let storage = FrankenStorage::open(&path).expect("open production storage (fresh build)");

    let version: i64 = storage
        .raw()
        .query_row_map("PRAGMA user_version;", &[], |row| row.get_typed(0))
        .expect("read user_version");
    assert_eq!(version, 7);

    let cols: Vec<String> = storage
        .raw()
        .query_all_map("SELECT name FROM pragma_table_info('messages')", &[], |row| row.get_typed(0))
        .expect("list messages columns");
    assert!(cols.contains(&"excluded".to_string()), "messages must have an `excluded` column, got {cols:?}");

    let index_names: Vec<String> = storage
        .raw()
        .query_all_map(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'messages'",
            &[],
            |row| row.get_typed(0),
        )
        .expect("list messages indexes");
    assert!(
        index_names.contains(&"idx_messages_excluded_blob".to_string()),
        "expected idx_messages_excluded_blob expression index, got {index_names:?}"
    );

    // The column must actually be usable as a JSONB target for json_extract
    // -- an empty result set (not an error) on a fresh, row-less table is
    // sufficient proof the expression index's underlying expression compiles.
    let hits: Vec<i64> = storage
        .raw()
        .query_all_map(
            "SELECT id FROM messages WHERE json_extract(excluded, '$.raw.blob') = 'nope'",
            &[],
            |row| row.get_typed(0),
        )
        .expect("json_extract(excluded, ...) must be a valid expression against the new column");
    assert!(hits.is_empty());
}
