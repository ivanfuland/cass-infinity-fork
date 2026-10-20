//! SRC05C-01 acceptance tests for the explicit legacy schema-7/8 message
//! adapter (`storage::legacy_messages`).
//!
//! Fixtures are synthetic databases built from the real historical DDL (see
//! `tests/fixtures/source_legacy_reader/*.sql`, extracted verbatim from the
//! schema-7 and schema-8 commits). No schema-9 database is relabelled to stand
//! in for a historical one: the fixture tables and the `PRAGMA user_version`
//! marker both come from the version under test.
//!
//! These cover the L1–L5 acceptance items. L6 (build/target gates plus the
//! pre-existing named version-gate tests) and L7 (behaviour mutation) are run
//! from the command line and reported separately.

use coding_agent_search::storage::api::{Conn, Profile, Value};
use coding_agent_search::storage::legacy_messages::{
    CODE_EXTRA_DECODE_FAILED, CODE_SCHEMA_SHAPE_INVALID, CODE_SCHEMA_VERSION_MISSING,
    CODE_SCHEMA_VERSION_UNSUPPORTED, CODE_SOURCE_FACTS_UNAVAILABLE, LEGACY_SCHEMA_MAX,
    LEGACY_SCHEMA_MIN, LegacyIoKind, LegacyReadError, read_legacy_messages_ro,
};
use coding_agent_search::storage::testing::open_test_writer;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

const SCHEMA7_DDL: &str = include_str!("fixtures/source_legacy_reader/schema7_legacy.sql");
const SCHEMA8_DDL: &str = include_str!("fixtures/source_legacy_reader/schema8_legacy.sql");

/// The legacy "trim" threshold the carrier contract names: 16 MiB of UTF-8.
/// The oversized-body case must exceed this in real bytes, not in characters.
const OLD_TRIM_THRESHOLD_BYTES: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Fixture construction
// ---------------------------------------------------------------------------

fn temp_path(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(format!("{tag}.db"));
    (dir, path)
}

/// Build one static legacy fixture: historical DDL, `PRAGMA user_version`
/// marker, caller-supplied rows, then leave it in rollback-journal mode so a
/// later read-only open cannot create a WAL sidecar.
fn build_fixture(path: &Path, ddl: &str, version: i64, seed: impl FnOnce(&Conn)) {
    let mut guard = open_test_writer(path, Profile::Production).expect("open fixture writer");
    {
        let conn = guard.storage().raw();
        conn.execute_batch(ddl).expect("apply historical DDL");
        conn.execute_batch(&format!("PRAGMA user_version = {version};"))
            .expect("stamp schema version");
        seed(conn);
        conn.execute_batch("PRAGMA journal_mode = DELETE;")
            .expect("leave a static, non-WAL fixture");
    }
    guard.mark_committed();
}

/// The `meta` table statement of the historical DDL, so a fixture can omit
/// exactly that table.
const META_DDL_LINE: &str =
    "CREATE TABLE IF NOT EXISTS meta (\"key\" TEXT PRIMARY KEY, value TEXT NOT NULL);";

fn ddl_without_meta() -> String {
    SCHEMA7_DDL
        .lines()
        .filter(|line| *line != META_DDL_LINE)
        .collect::<Vec<_>>()
        .join("\n")
}

fn ddl_without_author_column() -> String {
    SCHEMA7_DDL.replace(
        "role TEXT NOT NULL, author TEXT, created_at INTEGER",
        "role TEXT NOT NULL, created_at INTEGER",
    )
}

fn seed_conversation(conn: &Conn, conversation_id: i64) {
    conn.execute_batch(
        "INSERT OR IGNORE INTO agents (id, slug, name, version, kind, created_at, updated_at) \
             VALUES (1, 'claude', 'Claude', '1.0', 'claude', 0, 0); \
         INSERT OR IGNORE INTO sources (id, kind, created_at, updated_at) \
             VALUES ('local', 'local', 0, 0);",
    )
    .expect("seed agents and sources");
    conn.execute(
        "INSERT INTO conversations (id, agent_id, source_id, source_path) VALUES (?1, 1, 'local', '/r')",
        &[Value::Integer(conversation_id)],
    )
    .expect("seed conversation");
}

#[allow(clippy::too_many_arguments)]
fn insert_message(
    conn: &Conn,
    id: i64,
    conversation_id: i64,
    idx: i64,
    role: &str,
    author: Option<&str>,
    created_at: Option<i64>,
    content: &str,
    extra_json: Option<&str>,
    extra_bin: Option<&[u8]>,
) {
    conn.execute(
        "INSERT INTO messages \
             (id, conversation_id, idx, role, author, created_at, content, extra_json, extra_bin) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        &[
            Value::Integer(id),
            Value::Integer(conversation_id),
            Value::Integer(idx),
            Value::Text(role.to_string()),
            author.map(|a| Value::Text(a.to_string())).unwrap_or(Value::Null),
            created_at.map(Value::Integer).unwrap_or(Value::Null),
            Value::Text(content.to_string()),
            extra_json.map(|s| Value::Text(s.to_string())).unwrap_or(Value::Null),
            extra_bin.map(|b| Value::Blob(b.to_vec())).unwrap_or(Value::Null),
        ],
    )
    .expect("insert legacy message");
}

fn sha256_of(path: &Path) -> [u8; 32] {
    let bytes = std::fs::read(path).expect("read archive bytes");
    Sha256::digest(bytes).into()
}

fn schema_objects(path: &Path) -> Vec<String> {
    let conn = Conn::open_read(path).expect("reopen for schema read");
    let mut names = conn
        .query_all_map(
            "SELECT type || ':' || name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY 1",
            &[],
            |row| row.get_typed::<String>(0),
        )
        .expect("read sqlite_master");
    names.sort();
    names
}

fn meta_rows(path: &Path) -> Vec<String> {
    let conn = Conn::open_read(path).expect("reopen for meta read");
    let mut rows = conn
        .query_all_map("SELECT \"key\" || '=' || value FROM meta ORDER BY 1", &[], |row| {
            row.get_typed::<String>(0)
        })
        .expect("read meta");
    rows.sort();
    rows
}

// ---------------------------------------------------------------------------
// L1 — both real historical DDLs open and read with full fidelity
// ---------------------------------------------------------------------------

#[test]
fn l1_reads_both_historical_ddls_with_full_fidelity() {
    for (label, ddl, version) in [
        ("schema7", SCHEMA7_DDL, LEGACY_SCHEMA_MIN),
        ("schema8", SCHEMA8_DDL, LEGACY_SCHEMA_MAX),
    ] {
        let (_dir, path) = temp_path(&format!("l1-{label}"));
        let msgpack = rmp_serde::to_vec(&json!({"bin": true})).expect("encode msgpack extra");
        let long_content: String = "长".repeat(60_000);
        // ASCII, so the byte length is exactly the character count: strictly
        // one byte past the 16 MiB trim threshold, +1 so the assertion cannot
        // pass on a boundary-equal body.
        let oversized: String = "A".repeat(OLD_TRIM_THRESHOLD_BYTES + 1);
        assert_eq!(oversized.len(), OLD_TRIM_THRESHOLD_BYTES + 1, "fixture body byte length");

        build_fixture(&path, ddl, version, |conn| {
            seed_conversation(conn, 10);
            seed_conversation(conn, 11);
            // Non-contiguous idx values, an unknown historical role, and NULL
            // author/created_at must all survive verbatim.
            insert_message(conn, 1, 10, 0, "user", Some("ivan"), Some(1), "first", Some("{\"b\": 2}"), None);
            insert_message(conn, 2, 10, 5, "assistant", None, None, &long_content, None, Some(&msgpack));
            insert_message(conn, 3, 10, 9, "tool_result_v2", Some("tool"), Some(3), "third", Some("null"), None);
            // Empty bin falls back to the TEXT column (existing priority rule).
            insert_message(conn, 4, 10, 12, "user", None, Some(4), "fourth", Some("{\"c\": 3}"), Some(&[]));
            // Both columns SQL NULL.
            insert_message(conn, 5, 10, 13, "assistant", None, Some(5), "fifth", None, None);
            // Conflicting dual columns: non-empty bin wins.
            insert_message(conn, 6, 10, 14, "user", None, Some(6), "sixth", Some("{\"json\": true}"), Some(&msgpack));
            // A body strictly larger than the 16 MiB trim threshold.
            insert_message(conn, 8, 10, 15, "assistant", None, Some(8), &oversized, None, None);
            // Another conversation must not leak into the first.
            insert_message(conn, 7, 11, 0, "user", None, Some(7), "other", None, None);
        });

        let reader = read_legacy_messages_ro(&path).expect("open legacy reader");
        assert_eq!(reader.schema_version(), version, "{label}: version");

        let messages = reader.fetch_messages(10).expect("fetch messages");
        assert_eq!(messages.len(), 7, "{label}: only conversation 10");
        let idx_order: Vec<i64> = messages.iter().map(|m| m.idx).collect();
        assert_eq!(idx_order, vec![0, 5, 9, 12, 13, 14, 15], "{label}: ascending idx order");

        let first = &messages[0];
        assert_eq!(first.id, 1, "{label}: id");
        assert_eq!(first.conversation_id, 10, "{label}: conversation_id");
        assert_eq!(first.role, "user", "{label}: raw role");
        assert_eq!(first.author.as_deref(), Some("ivan"), "{label}: author");
        assert_eq!(first.created_at, Some(1), "{label}: created_at");
        assert_eq!(first.content, "first", "{label}: content");
        assert_eq!(first.extra_json.as_deref(), Some("{\"b\": 2}"), "{label}: raw TEXT column");

        let second = &messages[1];
        assert_eq!(second.role, "assistant", "{label}: role");
        assert_eq!(second.author, None, "{label}: NULL author stays NULL");
        assert_eq!(second.created_at, None, "{label}: NULL created_at stays NULL");
        assert_eq!(second.content.len(), long_content.len(), "{label}: long content not truncated");
        assert_eq!(second.content, long_content, "{label}: long content byte-identical");
        assert_eq!(second.extra_bin.as_deref(), Some(msgpack.as_slice()), "{label}: raw BLOB column");
        assert_eq!(second.extra_json, None, "{label}: no TEXT column for message 2");

        assert_eq!(messages[2].role, "tool_result_v2", "{label}: unknown role preserved verbatim");

        // Six storage states: raw storage and decoded value asserted separately.
        assert_eq!(first.decode_extra().unwrap(), json!({"b": 2}), "{label}: TEXT decode");
        assert_eq!(second.decode_extra().unwrap(), json!({"bin": true}), "{label}: MsgPack decode");
        assert_eq!(messages[2].decode_extra().unwrap(), json!(null), "{label}: stored JSON null");
        assert_eq!(messages[3].decode_extra().unwrap(), json!({"c": 3}), "{label}: empty bin -> TEXT");
        assert_eq!(messages[4].decode_extra().unwrap(), json!(null), "{label}: both columns NULL");
        assert_eq!(messages[4].extra_json, None, "{label}: SQL NULL is None, not a value");
        assert_eq!(messages[4].extra_bin, None, "{label}: SQL NULL bin is None");
        assert_eq!(messages[2].extra_json.as_deref(), Some("null"), "{label}: JSON null is a value");
        assert!(messages[3].extra_bin.is_some(), "{label}: empty bin is present, not SQL NULL");
        assert_eq!(
            messages[3].extra_bin.as_deref().map(<[u8]>::len),
            Some(0),
            "{label}: empty bin kept as empty bytes"
        );
        assert_eq!(
            messages[5].decode_extra().unwrap(),
            json!({"bin": true}),
            "{label}: non-empty bin wins over TEXT"
        );
        assert_eq!(
            messages[5].extra_json.as_deref(),
            Some("{\"json\": true}"),
            "{label}: losing TEXT column still preserved"
        );

        // The oversized body must come back complete, strictly past the 16 MiB
        // trim threshold in real UTF-8 bytes. The close-and-reopen comparison
        // below re-checks the whole vector, this row included, for equality.
        let oversized_row = &messages[6];
        assert_eq!(oversized_row.idx, 15, "{label}: oversized row position");
        assert_eq!(
            oversized_row.content.len(),
            OLD_TRIM_THRESHOLD_BYTES + 1,
            "{label}: oversized body byte length"
        );
        assert!(
            oversized_row.content.len() > OLD_TRIM_THRESHOLD_BYTES,
            "{label}: oversized body exceeds the {OLD_TRIM_THRESHOLD_BYTES}-byte trim threshold"
        );
        assert_eq!(oversized_row.content, oversized, "{label}: oversized body byte-identical");
        // The measurement the acceptance asks the report to state, printed so
        // the log carries the read-back length rather than only the assertion.
        println!(
            "SRC05C-L1-OVERSIZED label={label} version={version} idx={} readback_bytes={} threshold_bytes={}",
            oversized_row.idx,
            oversized_row.content.len(),
            OLD_TRIM_THRESHOLD_BYTES
        );
        assert_eq!(oversized_row.extra_json, None, "{label}: oversized row has no TEXT column");
        assert_eq!(oversized_row.extra_bin, None, "{label}: oversized row has no BLOB column");

        assert_eq!(reader.fetch_messages(11).expect("other conversation").len(), 1, "{label}: conv 11");
        assert!(reader.fetch_messages(999).expect("absent conversation").is_empty(), "{label}: empty is empty");
        drop(reader);

        // Close-and-reopen must produce the identical view.
        let reopened = read_legacy_messages_ro(&path).expect("reopen legacy reader");
        assert_eq!(reopened.schema_version(), version, "{label}: version after reopen");
        assert_eq!(reopened.fetch_messages(10).expect("refetch"), messages, "{label}: reopen identical");
    }
}

// ---------------------------------------------------------------------------
// L2 — a bad preserved extra fails loudly, without leaking bytes or paths
// ---------------------------------------------------------------------------

#[test]
fn l2_bad_extra_fails_decoding_without_leaking_content_or_path() {
    const CONTENT_SENTINEL: &str = "SENTINEL-CONTENT-4c1f";
    const PATH_SENTINEL: &str = "SENTINEL-PATH-9ab3";
    const ROLE_SENTINEL: &str = "SENTINEL-ROLE-7d20";
    const AUTHOR_SENTINEL: &str = "SENTINEL-AUTHOR-55ea";
    const SENTINELS: [&str; 4] =
        [CONTENT_SENTINEL, PATH_SENTINEL, ROLE_SENTINEL, AUTHOR_SENTINEL];

    let (dir, _) = temp_path("l2");
    let path = dir.path().join(PATH_SENTINEL).with_extension("db");
    // 0xcc is MessagePack's `uint8` marker and is missing its payload byte, so
    // the decode must fail rather than yield a value. (`rmp_serde::from_slice`
    // tolerates *trailing* bytes, so an over-long-but-valid blob would not be
    // a bad-MsgPack case at all.)
    let bad_bin = [0xcc_u8];
    build_fixture(&path, SCHEMA7_DDL, LEGACY_SCHEMA_MIN, |conn| {
        seed_conversation(conn, 7);
        // Bad non-empty MsgPack with a perfectly valid TEXT column alongside it.
        insert_message(
            conn,
            1,
            7,
            0,
            ROLE_SENTINEL,
            Some(AUTHOR_SENTINEL),
            None,
            CONTENT_SENTINEL,
            Some("{\"ok\": 1}"),
            Some(&bad_bin),
        );
        // Bad TEXT with an empty bin, which must not rescue it.
        insert_message(conn, 2, 7, 1, ROLE_SENTINEL, Some(AUTHOR_SENTINEL), None, CONTENT_SENTINEL, Some("{not json"), Some(&[]));
    });

    let reader = read_legacy_messages_ro(&path).expect("open legacy reader");
    let messages = reader.fetch_messages(7).expect("fetch messages");

    // The read API still hands back every recorded value: no field was removed
    // to keep the logs clean.
    assert_eq!(messages[0].content, CONTENT_SENTINEL, "content is still returned");
    assert_eq!(messages[0].role, ROLE_SENTINEL, "role is still returned");
    assert_eq!(messages[0].author.as_deref(), Some(AUTHOR_SENTINEL), "author is still returned");

    // `LegacyMessage`'s hand-written Debug must render shape, not text.
    let rendered = format!("{:?}", messages[0]);
    assert!(rendered.contains("LegacyMessage"), "Debug still names the type: {rendered}");
    assert!(rendered.contains("content_len"), "Debug still reports lengths: {rendered}");
    for sentinel in SENTINELS {
        assert!(!rendered.contains(sentinel), "message Debug must not carry {sentinel}: {rendered}");
    }

    // The reader handle must not render the archive path or any message text.
    let rendered = format!("{reader:?}");
    assert!(rendered.contains("LegacyMessageReader"), "reader Debug names the type: {rendered}");
    for sentinel in SENTINELS {
        assert!(!rendered.contains(sentinel), "reader Debug must not carry {sentinel}: {rendered}");
    }

    // Decode failures, in both Debug and Display.
    let err = messages[0].decode_extra().expect_err("bad MsgPack must fail");
    assert_eq!(err, LegacyReadError::ExtraDecodeFailed { message_id: 1, column: "extra_bin" });
    assert_eq!(err.code(), CODE_EXTRA_DECODE_FAILED, "stable decode code");

    let err = messages[1].decode_extra().expect_err("bad TEXT must fail");
    assert_eq!(err, LegacyReadError::ExtraDecodeFailed { message_id: 2, column: "extra_json" });

    let rendered = format!("{:?} {}", err, err);
    assert!(rendered.contains("ExtraDecodeFailed"), "error Debug names the variant: {rendered}");
    for sentinel in SENTINELS {
        assert!(!rendered.contains(sentinel), "error Debug/Display must not carry {sentinel}: {rendered}");
    }
}

// ---------------------------------------------------------------------------
// L3 — version and shape gate
// ---------------------------------------------------------------------------

#[test]
fn l3_rejects_versions_outside_the_frozen_legacy_range() {
    for version in [4_i64, 6, 9, 10] {
        let (_dir, path) = temp_path(&format!("l3-v{version}"));
        build_fixture(&path, SCHEMA7_DDL, version, |_| {});
        let err = read_legacy_messages_ro(&path).expect_err("version must be refused");
        assert_eq!(
            err,
            LegacyReadError::VersionUnsupported { found: version },
            "version {version} must be refused by version, not by shape"
        );
        assert_eq!(err.code(), CODE_SCHEMA_VERSION_UNSUPPORTED);
    }

    // A missing marker (user_version 0) is its own refusal, not "version 0".
    let (_dir, path) = temp_path("l3-v0");
    build_fixture(&path, SCHEMA7_DDL, 0, |_| {});
    let err = read_legacy_messages_ro(&path).expect_err("missing marker must be refused");
    assert_eq!(err, LegacyReadError::VersionMissing);
    assert_eq!(err.code(), CODE_SCHEMA_VERSION_MISSING);

    // A schema-9-shaped archive must not get in by carrying source tables: the
    // version check runs first and refuses regardless of the rest of the shape.
    let (_dir, path) = temp_path("l3-source-shaped");
    build_fixture(&path, SCHEMA7_DDL, 9, |conn| {
        conn.execute_batch("CREATE TABLE source_inputs (id TEXT PRIMARY KEY);")
            .expect("plant a schema-9-shaped object");
    });
    assert_eq!(
        read_legacy_messages_ro(&path).expect_err("schema-9 shape must not open"),
        LegacyReadError::VersionUnsupported { found: 9 }
    );

    // Genuine 7 and 8 stay open.
    for version in [LEGACY_SCHEMA_MIN, LEGACY_SCHEMA_MAX] {
        let (_dir, path) = temp_path(&format!("l3-ok{version}"));
        build_fixture(&path, SCHEMA7_DDL, version, |_| {});
        assert_eq!(read_legacy_messages_ro(&path).expect("genuine legacy opens").schema_version(), version);
    }
}

/// `PRAGMA user_version` is the only version authority. The retired
/// `meta.schema_version` mirror must be neither read nor required: forge it one
/// way and omit it the other, and `user_version` decides both times.
#[test]
fn l3_trusts_only_user_version_not_the_meta_mirror() {
    // Negative: user_version says 9, the meta mirror lies that it is 7.
    let (_dir, path) = temp_path("l3-forged-meta");
    build_fixture(&path, SCHEMA7_DDL, 9, |conn| {
        conn.execute(
            "INSERT INTO meta (\"key\", value) VALUES ('schema_version', ?1)",
            &[Value::Text("7".to_string())],
        )
        .expect("forge the retired meta mirror");
    });
    assert_eq!(
        read_legacy_messages_ro(&path).expect_err("a forged meta mirror must not admit schema 9"),
        LegacyReadError::VersionUnsupported { found: 9 }
    );

    // Positive: user_version is 7 and the mirror does not exist at all.
    let (_dir, path) = temp_path("l3-no-meta-table");
    build_fixture(&path, &ddl_without_meta(), LEGACY_SCHEMA_MIN, |_| {});
    assert_eq!(
        read_legacy_messages_ro(&path).expect("a missing meta mirror must not block a schema-7 archive")
            .schema_version(),
        LEGACY_SCHEMA_MIN
    );

    // Positive: the meta table exists but carries no schema_version row.
    let (_dir, path) = temp_path("l3-empty-meta");
    build_fixture(&path, SCHEMA8_DDL, LEGACY_SCHEMA_MAX, |_| {});
    assert_eq!(
        read_legacy_messages_ro(&path).expect("an absent meta row must not block a schema-8 archive")
            .schema_version(),
        LEGACY_SCHEMA_MAX
    );
}

#[test]
fn l3_rejects_missing_message_columns() {
    let (_dir, path) = temp_path("l3-no-author");
    build_fixture(&path, &ddl_without_author_column(), LEGACY_SCHEMA_MIN, |_| {});
    let err = read_legacy_messages_ro(&path).expect_err("missing column must be refused");
    assert_eq!(err, LegacyReadError::ShapeInvalid { field: "author" });
    assert_eq!(err.code(), CODE_SCHEMA_SHAPE_INVALID);
}

#[test]
fn l3_rejects_files_that_are_not_databases_and_absent_paths() {
    let (dir, _) = temp_path("l3-notdb");
    let path = dir.path().join("not-a-database.db");
    std::fs::write(&path, b"this is not a SQLite file").expect("write non-database file");
    let err = read_legacy_messages_ro(&path).expect_err("non-database must be refused");
    assert!(
        matches!(err.code(), "legacy_db_invalid" | "legacy_db_open_failed"),
        "non-database refusal must use a stable code, got {err:?}"
    );

    let (_dir, path) = temp_path("l3-missing");
    let err = read_legacy_messages_ro(&path).expect_err("absent path must be refused");
    assert_eq!(err, LegacyReadError::OpenFailed { kind: LegacyIoKind::NotFound });
}

// ---------------------------------------------------------------------------
// L4 — source facts are never available, and reads never write
// ---------------------------------------------------------------------------

#[test]
fn l4_source_facts_unavailable_even_on_an_empty_archive() {
    let (_dir, path) = temp_path("l4-empty");
    build_fixture(&path, SCHEMA7_DDL, LEGACY_SCHEMA_MIN, |_| {});

    let reader = read_legacy_messages_ro(&path).expect("open legacy reader");
    assert!(reader.fetch_messages(1).expect("empty fetch").is_empty(), "fixture is empty");
    let err = reader.read_source_facts().expect_err("source facts must be unavailable");
    assert_eq!(err, LegacyReadError::SourceFactsUnavailable);
    assert_eq!(err.code(), CODE_SOURCE_FACTS_UNAVAILABLE);
}

#[test]
fn l4_reads_leave_the_archive_byte_identical() {
    let (_dir, path) = temp_path("l4-populated");
    build_fixture(&path, SCHEMA7_DDL, LEGACY_SCHEMA_MIN, |conn| {
        seed_conversation(conn, 1);
        insert_message(conn, 1, 1, 0, "user", None, None, "hello", None, None);
    });

    let before_bytes = sha256_of(&path);
    let before_schema = schema_objects(&path);
    let before_meta = meta_rows(&path);
    let wal_sidecar = PathBuf::from(format!("{}-wal", path.display()));
    let shm_sidecar = PathBuf::from(format!("{}-shm", path.display()));
    assert!(!wal_sidecar.exists(), "the static fixture must start with no WAL sidecar");

    let reader = read_legacy_messages_ro(&path).expect("open legacy reader");
    assert_eq!(reader.fetch_messages(1).expect("fetch").len(), 1);
    assert_eq!(reader.schema_version(), LEGACY_SCHEMA_MIN);
    assert_eq!(reader.read_source_facts().expect_err("still unavailable").code(), CODE_SOURCE_FACTS_UNAVAILABLE);
    drop(reader);

    assert_eq!(sha256_of(&path), before_bytes, "the archive's bytes must not change");
    assert!(!wal_sidecar.exists(), "no WAL sidecar may be created");
    assert!(!shm_sidecar.exists(), "no shared-memory sidecar may be created");
    assert_eq!(schema_objects(&path), before_schema, "no table may be added or removed");
    assert_eq!(meta_rows(&path), before_meta, "meta must not be written");
    assert!(
        !before_schema.iter().any(|name| name.starts_with("source_")),
        "no source table may appear: {before_schema:?}"
    );
}

// ---------------------------------------------------------------------------
// L5 — a live WAL keeps committing after the reader opens, seen in-process
// and from a separate read-only process
// ---------------------------------------------------------------------------

#[test]
fn l5_live_wal_commits_are_visible_in_process_and_from_a_child_process() {
    let (_dir, path) = temp_path("l5");

    // One writer stays open (and therefore holds the WAL open) across every read.
    let mut guard = open_test_writer(&path, Profile::Production).expect("live writer");
    {
        let conn = guard.storage().raw();
        conn.execute_batch(SCHEMA7_DDL).expect("apply historical DDL");
        conn.execute_batch("PRAGMA user_version = 7;").expect("stamp schema version");
        conn.execute_batch("PRAGMA journal_mode = WAL;").expect("fixture stays in WAL mode");
        seed_conversation(conn, 1);
        insert_message(conn, 1, 1, 0, "user", None, None, "committed into WAL", None, None);
    }

    let reader = read_legacy_messages_ro(&path).expect("open legacy reader over a live WAL");
    let messages = reader.fetch_messages(1).expect("fetch through WAL");
    assert_eq!(messages.len(), 1, "a committed WAL row must be visible");
    assert_eq!(messages[0].content, "committed into WAL");
    drop(reader);

    // A separate read-only process must see the same committed WAL row.
    let exe = std::env::current_exe().expect("test binary path");
    let output = Command::new(exe)
        .args(["l5_child_readback_helper", "--nocapture", "--test-threads=1"])
        .env("CASS_LEGACY_SUBPROCESS_DB", &path)
        .output()
        .expect("run child readback");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "child failed: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("CASS_LEGACY_SUBPROCESS_OK count=1"), "child must read the WAL row: {stdout}");

    // A later commit by the same writer must also be visible to a fresh reader.
    {
        let conn = guard.storage().raw();
        insert_message(conn, 2, 1, 1, "assistant", None, None, "second commit", None, None);
    }
    let reader = read_legacy_messages_ro(&path).expect("reopen legacy reader");
    assert_eq!(reader.fetch_messages(1).expect("refetch").len(), 2);
    drop(reader);
    guard.mark_committed();
}

/// Child-process helper for the L5 WAL test. A no-op unless the parent sets
/// `CASS_LEGACY_SUBPROCESS_DB`, so it is harmless in an ordinary test run.
#[test]
fn l5_child_readback_helper() {
    let Ok(db) = std::env::var("CASS_LEGACY_SUBPROCESS_DB") else {
        return;
    };
    let reader = read_legacy_messages_ro(Path::new(&db)).expect("child: open legacy reader");
    let messages = reader.fetch_messages(1).expect("child: fetch messages");
    println!("CASS_LEGACY_SUBPROCESS_OK count={}", messages.len());
}
