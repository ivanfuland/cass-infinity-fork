//! Rusqlite Compatibility Gate Tests
//!
//! These tests verify that the crate's actual production storage backend --
//! bundled rusqlite (vanilla SQLite) -- supports the critical features cass
//! depends on: FTS5 full-text search (CREATE VIRTUAL TABLE, trigram/porter
//! tokenizers, MATCH, highlight, bm25, rebuild/optimize commands) and core
//! SQL (aggregates, joins, subqueries, NULL handling, LIKE).
//!
//! W2-6 Task己 (2026-09-01): rewritten off the `frankensqlite`/`fsqlite-types`
//! dev-dependencies these tests originally pinned directly. Those crates
//! gated frankensqlite's viability *before* it was evaluated as a storage
//! engine candidate (w1b Stage A); Stage B adopted plain rusqlite instead and
//! retired the franken backend from production entirely -- `FrankenStorage`
//! and `SqliteStorage` are the same rusqlite-backed type today (`pub type
//! SqliteStorage = FrankenStorage;`, see `storage::sqlite`). What these gates
//! actually need to keep proving is "the backend cass ships (bundled
//! rusqlite) can do X", which every FTS5/SQL gate below now asserts directly
//! against `rusqlite::Connection`. Retired outright, not faked green:
//! - Gate 2 (cross-engine file compat: write with one engine, read with the
//!   other) has no rusqlite-only equivalent -- there is no second engine left
//!   to be compatible *with*.
//! - Gate 3 (`gate3_schema_parity_transitioned_db_matches_fresh_frankensqlite_db`,
//!   already `#[ignore]`d) compared "create via `SqliteStorage` then reopen
//!   via `FrankenStorage`" against "fresh via `FrankenStorage`" -- since
//!   those are now literally the same type calling the same `open()`, the
//!   test's entire "transition between two engines" premise is vacuous (it
//!   would just be opening the same file twice with the same function).
//! - `verify_begin_concurrent` exercised `BEGIN CONCURRENT`, frankensqlite's
//!   proprietary MVCC multi-writer extension; vanilla SQLite has no such
//!   statement, so there is nothing to rewrite it against.
//! - `fsqlite_path_dependency_compile_contract` existed solely to pin the
//!   frankensqlite crate's own public API surface (import/open/params!/Row);
//!   with the dependency gone there is no surface left to pin.

#[test]
fn rusqlite_is_bundled() {
    // w1b Task B1 (plan 2026-08-25-w1-relational-sqlite-swap.md, control-plane
    // adjudicated R0-B2): Stage B promotes rusqlite from a dev-only C-SQLite
    // interop fixture to a real production storage backend (backend_sqlite.rs,
    // Task B2), directly conflicting with this test's old assertion that it
    // must stay out of `[dependencies]`. Rewritten to preserve the test's
    // actual intent -- "the linked SQLite build is reproducible" -- by
    // asserting the `bundled` feature is enabled (vendors and pins its own
    // libsqlite3 version) rather than asserting dependency-table placement.
    let manifest: toml::Table =
        toml::from_str(include_str!("../Cargo.toml")).expect("parse Cargo.toml");
    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .expect("Cargo.toml dependencies table");
    let rusqlite = dependencies
        .get("rusqlite")
        .and_then(toml::Value::as_table)
        .expect("rusqlite must be a normal production dependency (w1b Task B1)");
    let features = rusqlite
        .get("features")
        .and_then(toml::Value::as_array)
        .expect("rusqlite dependency must declare a features list");
    let has_bundled = features.iter().any(|f| f.as_str() == Some("bundled"));
    assert!(
        has_bundled,
        "rusqlite must enable the `bundled` feature so the linked SQLite \
         version is vendored/pinned, not resolved against the system libsqlite3"
    );
}

// ============================================================================
// GATE 1: FTS5 Compatibility
// ============================================================================

#[test]
fn gate1_fts5_create_virtual_table() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
        .expect("GATE 1.1 FAIL: Cannot create FTS5 virtual table");
}

#[test]
fn gate1_fts5_create_with_trigram_tokenizer() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    // Trigram tokenizer is critical for cass substring search
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content, tokenize='trigram')")
        .expect("GATE 1.1b FAIL: Cannot create FTS5 table with trigram tokenizer");
}

#[test]
fn gate1_fts5_create_with_porter_tokenizer() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content, tokenize='porter')")
        .expect("GATE 1.1c FAIL: Cannot create FTS5 table with porter tokenizer");
}

#[test]
fn gate1_fts5_insert() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
        .unwrap();

    conn.execute("INSERT INTO test_fts(content) VALUES ('hello world')", [])
        .expect("GATE 1.2 FAIL: Cannot insert into FTS5 table");
    conn.execute(
        "INSERT INTO test_fts(content) VALUES ('rust programming language')",
        [],
    )
    .expect("GATE 1.2 FAIL: Cannot insert second row");
    conn.execute(
        "INSERT INTO test_fts(content) VALUES ('hello rust developers')",
        [],
    )
    .expect("GATE 1.2 FAIL: Cannot insert third row");
}

#[test]
fn gate1_fts5_match_query() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
        .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('hello world')", [])
        .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('goodbye world')", [])
        .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('hello rust')", [])
        .unwrap();

    let mut stmt = conn
        .prepare("SELECT content FROM test_fts WHERE test_fts MATCH 'hello'")
        .expect("GATE 1.3 FAIL: FTS5 MATCH query failed");
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();

    assert_eq!(
        rows.len(),
        2,
        "GATE 1.3 FAIL: Expected 2 matches for 'hello', got {}",
        rows.len()
    );
}

#[test]
fn gate1_fts5_trigram_substring_match() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content, tokenize='trigram')")
        .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('hello world')", [])
        .unwrap();
    conn.execute(
        "INSERT INTO test_fts(content) VALUES ('say hello there')",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('nothing here')", [])
        .unwrap();

    // Trigram search for substring 'llo' should match rows containing 'hello'
    let mut stmt = conn
        .prepare("SELECT content FROM test_fts WHERE test_fts MATCH 'llo'")
        .expect("GATE 1.3b FAIL: Trigram substring search failed");
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();

    assert_eq!(
        rows.len(),
        2,
        "GATE 1.3b FAIL: Expected 2 trigram matches for 'llo', got {}",
        rows.len()
    );
}

#[test]
fn gate1_fts5_prefix_match() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
        .unwrap();
    conn.execute(
        "INSERT INTO test_fts(content) VALUES ('authentication error')",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('authorize user')", [])
        .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('something else')", [])
        .unwrap();

    // Prefix match with *
    let mut stmt = conn
        .prepare("SELECT content FROM test_fts WHERE test_fts MATCH 'auth*'")
        .expect("GATE 1.4 FAIL: FTS5 prefix matching failed");
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();

    assert_eq!(
        rows.len(),
        2,
        "GATE 1.4 FAIL: Expected 2 prefix matches for 'auth*', got {}",
        rows.len()
    );
}

#[test]
fn gate1_fts5_highlight_function() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
        .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('hello world')", [])
        .unwrap();

    let mut stmt = conn
        .prepare(
            "SELECT highlight(test_fts, 0, '<b>', '</b>') FROM test_fts WHERE test_fts MATCH 'hello'",
        )
        .expect("GATE 1.5 FAIL: FTS5 highlight() function failed");
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();

    assert_eq!(rows.len(), 1, "GATE 1.5 FAIL: Expected 1 highlighted row");
    assert!(
        rows[0].contains("<b>hello</b>"),
        "GATE 1.5 FAIL: highlight() should wrap 'hello' in <b> tags, got: {}",
        rows[0]
    );
}

#[test]
fn gate1_fts5_rebuild_command() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
        .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('test data')", [])
        .unwrap();

    conn.execute("INSERT INTO test_fts(test_fts) VALUES('rebuild')", [])
        .expect("GATE 1.6 FAIL: FTS5 rebuild command failed");
}

#[test]
fn gate1_fts5_optimize_command() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
        .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('optimize me')", [])
        .unwrap();

    conn.execute("INSERT INTO test_fts(test_fts) VALUES('optimize')", [])
        .expect("GATE 1.6b FAIL: FTS5 optimize command failed");
}

#[test]
fn gate1_fts5_multi_column() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(title, body)")
        .unwrap();
    conn.execute(
        "INSERT INTO test_fts(title, body) VALUES ('Rust Guide', 'Learn systems programming')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO test_fts(title, body) VALUES ('Python Intro', 'Learn dynamic programming')",
        [],
    )
    .unwrap();

    // Search in body column only
    let mut stmt = conn
        .prepare("SELECT title FROM test_fts WHERE test_fts MATCH 'body:systems'")
        .expect("GATE 1.7 FAIL: Multi-column FTS5 column filter failed");
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();

    assert_eq!(
        rows.len(),
        1,
        "GATE 1.7 FAIL: Expected 1 match for body:systems"
    );
}

#[test]
fn gate1_fts5_bm25_rank_function() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
        .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('rust rust rust')", []) // high relevance
        .unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('hello rust')", []) // low relevance
        .unwrap();

    // cass ranks FTS fallback queries through explicit bm25(table) calls. The
    // SQLite hidden `rank` column is useful compatibility coverage, but it is
    // not part of cass's required query surface.
    let mut stmt = conn
        .prepare(
            "SELECT content, bm25(test_fts) AS rank \
             FROM test_fts WHERE test_fts MATCH 'rust' ORDER BY rank",
        )
        .expect("GATE 1.8 FAIL: FTS5 bm25 rank function failed");
    let rows: Vec<(String, f64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();

    assert_eq!(rows.len(), 2, "GATE 1.8 FAIL: Expected 2 ranked results");
    // rank is a negative BM25 score (more negative = better match)
    assert!(
        rows[0].1 <= rows[1].1,
        "GATE 1.8 FAIL: rank should be ordered (more negative first), got {} vs {}",
        rows[0].1,
        rows[1].1
    );
}

#[test]
fn gate1_fts5_within_transaction() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
        .unwrap();

    conn.execute_batch("BEGIN").unwrap();
    conn.execute("INSERT INTO test_fts(content) VALUES ('in transaction')", [])
        .expect("GATE 1.9 FAIL: FTS5 insert within transaction failed");
    conn.execute_batch("COMMIT").unwrap();

    let mut stmt = conn
        .prepare("SELECT content FROM test_fts WHERE test_fts MATCH 'transaction'")
        .unwrap();
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "GATE 1.9 FAIL: FTS5 data not visible after commit"
    );
}

#[test]
fn gate1_fts5_transaction_rollback() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE test_fts USING fts5(content)")
        .unwrap();

    conn.execute_batch("BEGIN").unwrap();
    conn.execute(
        "INSERT INTO test_fts(content) VALUES ('will be rolled back')",
        [],
    )
    .unwrap();
    conn.execute_batch("ROLLBACK").unwrap();

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM test_fts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0, "GATE 1.9b FAIL: FTS5 data visible after rollback");
}

#[test]
fn gate1_fts5_multiple_tables_coexist() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE fts_a USING fts5(content)")
        .unwrap();
    conn.execute_batch("CREATE VIRTUAL TABLE fts_b USING fts5(content)")
        .unwrap();

    conn.execute("INSERT INTO fts_a(content) VALUES ('alpha search')", [])
        .unwrap();
    conn.execute("INSERT INTO fts_b(content) VALUES ('beta search')", [])
        .unwrap();

    let rows_a: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM fts_a WHERE fts_a MATCH 'alpha'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let rows_b: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM fts_b WHERE fts_b MATCH 'beta'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(
        rows_a, 1,
        "GATE 1.10 FAIL: Multiple FTS5 tables - first table query failed"
    );
    assert_eq!(
        rows_b, 1,
        "GATE 1.10 FAIL: Multiple FTS5 tables - second table query failed"
    );
}

#[test]
fn gate1_fts5_bulk_insert_performance() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE VIRTUAL TABLE perf_fts USING fts5(content)")
        .unwrap();

    // Insert 1000 rows
    conn.execute_batch("BEGIN").unwrap();
    for i in 0..1000 {
        conn.execute(
            "INSERT INTO perf_fts(content) VALUES (?1)",
            rusqlite::params![format!(
                "document number {i} with searchable content about rust programming"
            )],
        )
        .unwrap();
    }
    conn.execute_batch("COMMIT").unwrap();

    // Verify count
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM perf_fts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1000, "GATE 1.11 FAIL: Bulk insert count mismatch");

    // Search should work on bulk data
    let mut stmt = conn
        .prepare("SELECT content FROM perf_fts WHERE perf_fts MATCH 'rust' LIMIT 5")
        .expect("GATE 1.11 FAIL: Search on 1000-row FTS5 table failed");
    let results: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();

    assert!(
        !results.is_empty(),
        "GATE 1.11 FAIL: No results from 1000-row search"
    );
}

// ============================================================================
// Additional Verification: Features cass relies on
// ============================================================================

#[test]
fn verify_count_aggregate() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE TABLE t(x INTEGER)").unwrap();
    conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
    conn.execute("INSERT INTO t VALUES (2)", []).unwrap();
    conn.execute("INSERT INTO t VALUES (3)", []).unwrap();

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 3);
}

#[test]
fn verify_group_by_and_order_by() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE TABLE t(agent TEXT, cnt INTEGER)")
        .unwrap();
    conn.execute("INSERT INTO t VALUES ('claude', 1)", []).unwrap();
    conn.execute("INSERT INTO t VALUES ('codex', 1)", []).unwrap();
    conn.execute("INSERT INTO t VALUES ('claude', 1)", []).unwrap();

    let mut stmt = conn
        .prepare("SELECT agent, SUM(cnt) as total FROM t GROUP BY agent ORDER BY total DESC")
        .unwrap();
    let rows: Vec<(String, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, "claude");
    assert_eq!(rows[0].1, 2);
}

#[test]
fn verify_nullable_columns() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, val TEXT)")
        .unwrap();
    conn.execute(
        "INSERT INTO t VALUES (?1, ?2)",
        rusqlite::params![1_i64, Option::<String>::None],
    )
    .unwrap();

    let val: Option<String> = conn
        .query_row("SELECT val FROM t WHERE id = 1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(val, None, "NULL column should return None");

    // IS NULL comparison
    let null_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM t WHERE val IS NULL", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(null_count, 1, "IS NULL should find 1 row");
}

#[test]
fn verify_like_operator() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE TABLE t(name TEXT)").unwrap();
    conn.execute("INSERT INTO t VALUES ('authentication')", [])
        .unwrap();
    conn.execute("INSERT INTO t VALUES ('authorization')", [])
        .unwrap();
    conn.execute("INSERT INTO t VALUES ('other')", []).unwrap();

    let mut stmt = conn
        .prepare("SELECT name FROM t WHERE name LIKE 'auth%'")
        .unwrap();
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(rows.len(), 2, "LIKE 'auth%' should match 2 rows");
}

#[test]
fn verify_subquery() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    conn.execute_batch("CREATE TABLE t(id INTEGER, val INTEGER)")
        .unwrap();
    conn.execute("INSERT INTO t VALUES (1, 10)", []).unwrap();
    conn.execute("INSERT INTO t VALUES (2, 20)", []).unwrap();
    conn.execute("INSERT INTO t VALUES (3, 30)", []).unwrap();

    let mut stmt = conn
        .prepare("SELECT id FROM t WHERE val > (SELECT AVG(val) FROM t)")
        .unwrap();
    let rows: Vec<i64> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(rows.len(), 1, "Subquery should find 1 row above average");
    assert_eq!(rows[0], 3);
}

#[test]
fn verify_coalesce_and_ifnull() {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory connection");
    let fallback: String = conn
        .query_row("SELECT COALESCE(NULL, NULL, 'fallback')", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(fallback, "fallback");

    let default: String = conn
        .query_row("SELECT IFNULL(NULL, 'default')", [], |row| row.get(0))
        .unwrap();
    assert_eq!(default, "default");
}
