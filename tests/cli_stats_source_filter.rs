use assert_cmd::cargo::cargo_bin_cmd;
use coding_agent_search::storage::sqlite::{ConnectionManagerConfig, FrankenConnectionManager};
use serde_json::Value;
use tempfile::TempDir;

/// Test-only parameter list builder (this integration test is a separate
/// crate and can't reach `storage::api`'s crate-private `params!` shim).
macro_rules! fparams {
    () => {
        &[] as &[coding_agent_search::storage::api::Value]
    };
    ($($val:expr),+ $(,)?) => {
        &[$(coding_agent_search::storage::api::IntoValue::into_value($val)),+]
            as &[coding_agent_search::storage::api::Value]
    };
}

#[test]
fn stats_source_filter_preserves_date_range() {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path();
    let db_path = data_dir.join("agent_search.db");

    // Minimal schema required by `cass stats` queries. Reuses cass's real
    // table names with a simplified column set, so this must stay on the
    // schema-free FrankenConnectionManager path rather than
    // `FrankenStorage::open`, which would apply cass's real migrations
    // first and collide on `CREATE TABLE conversations`.
    let mgr = FrankenConnectionManager::new(
        &db_path,
        ConnectionManagerConfig {
            reader_count: 1,
            max_writers: 1,
        },
    )
    .expect("open db");
    let mut guard = mgr.writer().expect("acquire fixture writer");
    let conn = guard.storage().raw();
    conn.execute(
        "CREATE TABLE agents (id INTEGER PRIMARY KEY, slug TEXT NOT NULL)",
        &[],
    )
    .expect("create agents");
    conn.execute(
        "CREATE TABLE workspaces (id INTEGER PRIMARY KEY, path TEXT NOT NULL)",
        &[],
    )
    .expect("create workspaces");
    conn.execute(
        "CREATE TABLE conversations (
            id INTEGER PRIMARY KEY,
            agent_id INTEGER NOT NULL,
            workspace_id INTEGER,
            source_id TEXT NOT NULL,
            started_at INTEGER
        )",
        &[],
    )
    .expect("create conversations");
    conn.execute(
        "CREATE TABLE messages (id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL)",
        &[],
    )
    .expect("create messages");

    conn.execute("INSERT INTO agents (id, slug) VALUES (1, 'codex')", &[])
        .expect("insert agent");
    conn.execute(
        "INSERT INTO workspaces (id, path) VALUES (1, '/tmp/ws')",
        &[],
    )
    .expect("insert workspace");

    let ts = 1_700_000_000_000i64;
    conn.execute(
        "INSERT INTO conversations (id, agent_id, workspace_id, source_id, started_at)
         VALUES (1, 1, 1, 'local', ?1)",
        fparams![ts],
    )
    .expect("insert conversation");
    conn.execute(
        "INSERT INTO messages (id, conversation_id) VALUES (1, 1)",
        &[],
    )
    .expect("insert message");
    guard.mark_committed();
    drop(guard);
    drop(mgr);

    let out = cargo_bin_cmd!("cass")
        .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .arg("stats")
        .arg("--json")
        .arg("--source")
        .arg("local")
        .arg("--data-dir")
        .arg(data_dir)
        .assert()
        .success()
        .get_output()
        .clone();

    let json: Value = serde_json::from_slice(&out.stdout).expect("valid json");
    assert!(
        json.get("date_range")
            .and_then(|d| d.get("oldest"))
            .is_some_and(|v| v.is_string()),
        "expected date_range.oldest to be a string, got: {json}"
    );
    assert!(
        json.get("date_range")
            .and_then(|d| d.get("newest"))
            .is_some_and(|v| v.is_string()),
        "expected date_range.newest to be a string, got: {json}"
    );
}
