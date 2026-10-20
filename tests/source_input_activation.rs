//! SRC05A structural acceptance tests.
//!
//! These drive real SQLite. They cover the parts of the SRC05A contract that do
//! not depend on the activation pipeline being wired: the schema-9 layout, the
//! strict source-schema shape gate, the bootstrap `library_identity` and
//! `source_facts_revision` rows, and the four SQL-constraint mutant classes
//! named in contract §15.
//!
//! Every mutant test is run twice: once against a **mutated** copy of the
//! frozen DDL (the bad row must be accepted -- this is the "red"), and once
//! against the **frozen** DDL (the same row must be refused -- the "green").
//! A mutant test that only ran the red half would prove nothing about the
//! frozen schema.
//!
//! The activation primitives themselves (`stage_source_records_in_tx`,
//! `install_source_links_in_tx`, `activate_source_input_in_tx`,
//! `verify_source_receipt_in_tx`) are not exercised here yet; this file grows
//! with them.

use std::path::Path;

use coding_agent_search::storage::api::{Conn, StorageError, Tx, TxMode, Value};
use sha2::{Digest, Sha256};
use coding_agent_search::storage::schema::{
    CURRENT_SCHEMA_VERSION, SOURCE_FACTS_DDL_STATEMENTS, SOURCE_FACTS_SCHEMA_OBJECTS, ensure,
};
use coding_agent_search::storage::source_facts::{SourceSchemaError, verify_source_schema};
use coding_agent_search::storage::sqlite::FrankenStorage;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// A 32-byte SHA-shaped blob literal (64 hex characters).
const SHA: &str = "X'0011223344556677889900112233445566778899001122334455667788990011'";
/// An 8-byte big-endian integer literal holding `1` (16 hex characters).
const BE8_ONE: &str = "X'0000000000000001'";

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let unique = format!(
        "cass-src05a-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    );
    path.push(unique);
    std::fs::create_dir_all(&path).expect("create scratch dir");
    path
}

fn open_fresh_db(path: &Path) -> FrankenStorage {
    FrankenStorage::open(path).expect("build a fresh schema-9 database")
}

/// Open a schema-free in-memory connection (no `ensure`), so a mutated DDL can
/// be applied by the test itself.
fn memory_conn() -> Conn {
    Conn::open_memory().expect("open in-memory sqlite")
}

/// `PRAGMA user_version` on a facade connection.
fn user_version(conn: &Conn) -> i64 {
    conn.query_row_map("PRAGMA user_version;", &[], |row| row.get_typed(0))
        .expect("read user_version")
}

/// A meta value, or `None` when the key is absent.
fn meta_value(conn: &Conn, key: &str) -> Option<String> {
    conn.query_opt_map(
        "SELECT value FROM meta WHERE key = ?1",
        &[Value::Text(key.to_string())],
        |row| row.get_typed(0),
    )
    .expect("read meta value")
}

fn object_exists(conn: &Conn, kind: &str, name: &str) -> bool {
    conn.query_opt_map(
        "SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2",
        &[Value::Text(kind.to_string()), Value::Text(name.to_string())],
        |row| row.get_typed::<i64>(0),
    )
    .expect("query sqlite_master")
    .is_some()
}

/// Apply the frozen DDL statement-by-statement, substituting the given full
/// replacement statement for any index listed in `replacements`.
fn apply_ddl(conn: &Conn, replacements: &[(usize, String)]) {
    for (index, statement) in SOURCE_FACTS_DDL_STATEMENTS.iter().enumerate() {
        let sql = replacements
            .iter()
            .find(|(target, _)| *target == index)
            .map_or_else(|| (*statement).to_string(), |(_, replacement)| replacement.clone());
        conn.execute_batch(&format!("{sql};"))
            .unwrap_or_else(|err| panic!("apply statement {index}:\n{sql}\n{err}"));
    }
}

/// Remove one `CHECK(...)` from a `CREATE TABLE` statement by line, keeping the
/// surrounding comma list valid.
///
/// A table-constraint `CHECK` can span several lines, and dropping the last
/// constraint leaves the previous line's comma dangling, so this removes the
/// whole parenthesised block and then fixes the separator: when the removed
/// block carried the trailing comma nothing moves, and when it did not, the
/// previous constraint's comma is the one that is now dangling.
fn drop_check(statement: &str, marker: &str) -> String {
    let mut lines: Vec<String> = statement.lines().map(str::to_string).collect();
    let start = lines
        .iter()
        .position(|line| line.contains(marker))
        .unwrap_or_else(|| panic!("no CHECK line contains {marker:?}"));
    let mut end = start;
    loop {
        let block: String = lines[start..=end].join("\n");
        if block.matches('(').count() <= block.matches(')').count() || end + 1 >= lines.len() {
            break;
        }
        end += 1;
    }
    let removed_ends_with_comma = lines[end].trim_end().ends_with(',');
    lines.drain(start..=end);
    if removed_ends_with_comma {
        // The separator lived on the removed line; nothing else moves.
    } else {
        let previous = start
            .checked_sub(1)
            .unwrap_or_else(|| panic!("dropped constraint {marker:?} has no preceding line"));
        lines[previous] = lines[previous].trim_end_matches(',').to_string();
    }
    lines.join("\n")
}

/// The `messages` table the link table's `message_id` FK points at. Foreign-key
/// enforcement is on for these connections, so the parent must exist (and hold
/// the row) before a canonical link can reference it.
fn create_messages_parent(conn: &Conn) {
    conn.execute_batch("CREATE TABLE messages (id INTEGER PRIMARY KEY); INSERT INTO messages (id) VALUES (7);")
        .expect("create and seed the messages parent");
}

/// One `source_inputs` row with every NOT NULL column filled. `receipt_key`,
/// when true, adds the legacy half-filled-state column the completion CHECK
/// forbids.
fn insert_source_input(conn: &Conn, state: &str, receipt_key: bool) -> Result<usize, String> {
    let (columns, values) = if receipt_key {
        (", receipt_key", ", 'k'")
    } else {
        ("", "")
    };
    let sql = format!(
        "INSERT INTO source_inputs (
             input_key, identity_tuple_bin, source_id, identity_namespace, connector,
             root_id_bin, relative_locator_bin, discovery_bin, parser_context_bin,
             context_digest, sealed_ref_bin, sealed_sha256, byte_len, format,
             expected_manifest_bin, normalizer_id, safety_contract_id, state,
             expected_records, expected_blank_lines{columns})
         VALUES ({SHA}, X'00', 'local', 'ns', 'claude', X'00', X'00', X'00', X'00',
             {SHA}, X'00', {SHA}, {BE8_ONE}, 'jsonl', X'00', 'norm', 'safe', ?1,
             {BE8_ONE}, {BE8_ONE}{values})"
    );
    conn.execute(&sql, &[Value::Text(state.to_string())]).map_err(|err| err.to_string())
}

/// One `source_message_links` row. `projection_key` is a 32-byte blob literal,
/// so callers can keep two links on the same record distinct.
fn insert_link(
    conn: &Conn,
    projection_key: &str,
    authority: Option<&str>,
    message_id: Option<i64>,
    with_targets: bool,
) -> Result<usize, String> {
    let authority_sql = authority.map_or("NULL".to_string(), |value| format!("'{value}'"));
    let message_sql = message_id.map_or("NULL".to_string(), |value| value.to_string());
    // `standalone`/`unmapped` rows must carry an all-NULL target triple, so the
    // triple is written explicitly rather than always.
    let targets = if with_targets { "0, 0, '/messages/0'" } else { "NULL, NULL, NULL" };
    let sql = format!(
        "INSERT INTO source_message_links (
             record_id, projection_key, source_positions_bin, evidence_kind, binding_digest,
             conversation_ordinal, final_message_idx, projection_pointer, authority, message_id)
         VALUES (1, {projection_key}, X'00', 'prose', {SHA}, {targets}, {authority_sql}, \
         {message_sql})"
    );
    conn.execute(&sql, &[]).map_err(|err| err.to_string())
}

/// A distinct 32-byte projection key for the Nth link on the same record.
fn projection_key(n: u8) -> String {
    let byte = format!("{n:02x}");
    format!("X'{}'", byte.repeat(32))
}

fn insert_record(conn: &Conn, retention: &str, codec: Option<&str>) -> Result<usize, String> {
    let codec_sql = codec.map_or("NULL".to_string(), |value| format!("'{value}'"));
    let payload_sql = codec.map_or("NULL".to_string(), |_| SHA.to_string());
    let safe_hash_sql = codec.map_or("NULL".to_string(), |_| SHA.to_string());
    let sql = format!(
        "INSERT INTO source_records (
             input_id, ordinal, record_pointer, position_bin, expected_source_record_sha256,
             frame_state, parse_state, record_mapping_state, safety_state, retention_state,
             codec, payload_bin, safe_value_hash)
         VALUES (1, {BE8_ONE}, 'record-0', X'00', {SHA}, 'staged', 'parsed', 'all_canonical',
             'preserved', ?1, {codec_sql}, {payload_sql}, {safe_hash_sql})"
    );
    conn.execute(&sql, &[Value::Text(retention.to_string())]).map_err(|err| err.to_string())
}

// ---------------------------------------------------------------------------
// Schema-9 layout, bootstrap rows and the shape gate
// ---------------------------------------------------------------------------

#[test]
fn fresh_database_is_schema_nine_with_the_source_tables() {
    let dir = scratch_dir("fresh");
    let storage = open_fresh_db(&dir.join("agent_search.db"));
    let conn = storage.raw();

    assert_eq!(user_version(conn), CURRENT_SCHEMA_VERSION);
    assert_eq!(CURRENT_SCHEMA_VERSION, 9);

    for (kind, name, _) in SOURCE_FACTS_SCHEMA_OBJECTS {
        assert!(object_exists(conn, kind, name), "missing {kind} {name}");
    }

    verify_source_schema(conn).expect("the freshly built schema must pass the strict gate");
}

#[test]
fn fresh_database_bootstraps_library_identity_and_revision() {
    let dir = scratch_dir("bootstrap");
    let storage = open_fresh_db(&dir.join("agent_search.db"));
    let conn = storage.raw();

    let identity = meta_value(conn, "library_identity").expect("library_identity meta row");
    let parts: Vec<&str> = identity.split('-').collect();
    assert_eq!(parts.len(), 5, "not a canonical UUID: {identity}");
    assert_eq!(
        [parts[0].len(), parts[1].len(), parts[2].len(), parts[3].len(), parts[4].len()],
        [8, 4, 4, 4, 12],
        "not a canonical UUID: {identity}"
    );
    assert!(parts[2].starts_with('4'), "version nibble is not 4: {identity}");
    assert!(
        matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'),
        "variant nibble is not RFC 4122: {identity}"
    );
    assert_eq!(meta_value(conn, "source_facts_revision").as_deref(), Some("0"));
}

#[test]
fn library_identity_is_generated_once_and_survives_reopen() {
    let dir = scratch_dir("identity-reopen");
    let path = dir.join("agent_search.db");

    let first = {
        let storage = open_fresh_db(&path);
        meta_value(storage.raw(), "library_identity").expect("identity on first build")
    };
    let second = {
        // A second open must not rewrite the identity: initialization happens
        // once, on the empty-database path only.
        let storage = open_fresh_db(&path);
        meta_value(storage.raw(), "library_identity").expect("identity after reopen")
    };
    assert_eq!(first, second);

    let other = {
        let storage = open_fresh_db(&dir.join("other.db"));
        meta_value(storage.raw(), "library_identity").expect("identity of a distinct library")
    };
    assert_ne!(first, other, "a brand-new library must get a fresh UUID");
}

/// §15#4: a byte copy of a library keeps its identity. The reopen test beside
/// this one proves initialization happens once for one file; this proves the
/// identity travels with the bytes.
#[test]
fn a_byte_copied_library_keeps_its_identity() {
    let dir = scratch_dir("identity-copy");
    let path = dir.join("agent_search.db");
    let original = {
        let storage = open_fresh_db(&path);
        meta_value(storage.raw(), "library_identity").expect("identity on first build")
    };
    drop(open_fresh_db(&path));

    let copy_path = dir.join("copy.db");
    std::fs::copy(&path, &copy_path).expect("copy the database bytes");
    let copied = {
        let storage = open_fresh_db(&copy_path);
        meta_value(storage.raw(), "library_identity").expect("identity of the copy")
    };
    assert_eq!(original, copied, "a byte copy must keep the library's identity");

    let fresh = {
        let storage = open_fresh_db(&dir.join("fresh.db"));
        meta_value(storage.raw(), "library_identity").expect("identity of a new library")
    };
    assert_ne!(original, fresh, "a brand-new library must get a fresh identity");
}

#[test]
fn gate_refuses_a_dropped_source_table_without_repairing_it() {
    let dir = scratch_dir("dropped-table");
    let path = dir.join("agent_search.db");
    let storage = open_fresh_db(&path);
    let conn = storage.raw();

    conn.execute_batch("DROP TABLE source_message_links;").expect("drop the links table");

    let err = ensure(conn).expect_err("a missing source table must be refused");
    assert!(
        err.to_string().contains("source schema verification failed"),
        "unexpected error: {err}"
    );
    assert!(
        matches!(err, coding_agent_search::storage::api::StorageError::Corrupt { .. }),
        "the refusal must be a structured Corrupt, got {err:?}"
    );
    // The gate must not have rebuilt the table.
    assert!(!object_exists(conn, "table", "source_message_links"));
}

#[test]
fn gate_refuses_a_drifted_check_predicate() {
    let conn = memory_conn();
    // Statement 4 is `source_message_links`; strip the canonical CHECK.
    let mutated = drop_check(SOURCE_FACTS_DDL_STATEMENTS[4], "authority='canonical'");
    apply_ddl(&conn, &[(4, mutated)]);

    let err = verify_source_schema(&conn).expect_err("a mutated CHECK must be refused");
    assert!(
        matches!(&err, SourceSchemaError::DdlDrift { name } if *name == "source_message_links"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn gate_refuses_a_partial_index_without_its_predicate() {
    let conn = memory_conn();
    let statement = SOURCE_FACTS_DDL_STATEMENTS[3];
    let needle = " WHERE frame_state = 'activated'";
    assert!(statement.contains(needle), "predicate text moved");
    apply_ddl(&conn, &[(3, statement.replace(needle, ""))]);

    let err = verify_source_schema(&conn)
        .expect_err("an index missing its partial predicate must be refused");
    assert!(
        matches!(&err, SourceSchemaError::DdlDrift { name } if *name == "idx_source_records_activated"),
        "unexpected error: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Schema boundary: a pre-9 database is refused, a fresh one is schema 9
// ---------------------------------------------------------------------------

/// A database from before this schema is refused outright, and the refusal
/// writes nothing: the three source tables must not appear, so the old archive
/// is left exactly as it was for the rebuild-only path.
#[test]
fn a_pre_schema_nine_database_is_refused_without_being_written() {
    use coding_agent_search::storage::api::Profile;
    use coding_agent_search::storage::testing::open_writable_for_tests;

    for found in [7_i64, 8] {
        let dir = scratch_dir(&format!("pre-schema-{found}"));
        let path = dir.join("agent_search.db");
        let conn =
            open_writable_for_tests(&path, Profile::Production).expect("schema-free writable conn");
        conn.execute_batch(&format!(
            "CREATE TABLE probe_marker (id INTEGER PRIMARY KEY); PRAGMA user_version = {found};"
        ))
        .expect("build a minimal stand-in for the older database");

        let err = ensure(&conn).expect_err("a pre-9 database must be refused, never migrated");
        assert!(
            matches!(
                err,
                StorageError::SchemaRebuildRequired { found: f, required: r }
                    if f == found && r == CURRENT_SCHEMA_VERSION
            ),
            "unexpected refusal for user_version {found}: {err:?}"
        );

        // No repair, no bootstrap: the older archive is untouched.
        for (kind, name, _) in SOURCE_FACTS_SCHEMA_OBJECTS {
            assert!(
                !object_exists(&conn, kind, name),
                "the refusal must not create {kind} {name}"
            );
        }
        assert_eq!(user_version(&conn), found, "the refusal must not move user_version");
        assert!(object_exists(&conn, "table", "probe_marker"));
    }
}

/// The fresh-database half of the same boundary: schema 9 is the anchor, the
/// three source objects exist, and this library's identity and revision are
/// initialized exactly once.
#[test]
fn fresh_schema_nine_initialization_anchors_the_current_version() {
    assert_eq!(CURRENT_SCHEMA_VERSION, 9, "SRC05A uses rebuild-only schema 9");

    let dir = scratch_dir("schema-nine-anchor");
    let storage = open_fresh_db(&dir.join("agent_search.db"));
    let conn = storage.raw();

    assert_eq!(user_version(conn), CURRENT_SCHEMA_VERSION);
    for (kind, name, _) in SOURCE_FACTS_SCHEMA_OBJECTS {
        assert!(object_exists(conn, kind, name), "missing {kind} {name}");
    }
    verify_source_schema(conn).expect("the freshly built source schema must pass the strict gate");
    assert!(meta_value(conn, "library_identity").is_some());
    assert_eq!(meta_value(conn, "source_facts_revision").as_deref(), Some("0"));
}

// ---------------------------------------------------------------------------
// SQL constraint mutants: the bad row is accepted only without the constraint
// ---------------------------------------------------------------------------

#[test]
fn payload_retention_checks_are_load_bearing() {
    // Red: with both retention CHECKs removed, a `payload_absent` row that
    // still carries a codec/payload/hash is accepted.
    let mutated = memory_conn();
    let mut statement = drop_check(SOURCE_FACTS_DDL_STATEMENTS[1], "retention_state <> 'payload_present'");
    statement = drop_check(&statement, "retention_state <> 'payload_absent'");
    apply_ddl(&mutated, &[(1, statement)]);
    insert_source_input(&mutated, "staged", false).expect("parent input row");
    insert_record(&mutated, "payload_absent", Some("safe-json-msgpack/1"))
        .expect("RED: without the CHECK the half-filled row must be accepted");

    // Green: the frozen DDL refuses the same row.
    let frozen = memory_conn();
    apply_ddl(&frozen, &[]);
    insert_source_input(&frozen, "staged", false).expect("parent input row");
    let err = insert_record(&frozen, "payload_absent", Some("safe-json-msgpack/1"))
        .expect_err("GREEN: the frozen schema must refuse the half-filled row");
    assert!(err.contains("CHECK"), "unexpected error: {err}");

    // And the frozen DDL still accepts the honest combination.
    insert_record(&frozen, "payload_absent", None).expect("payload_absent with all three NULL");
}

#[test]
fn source_input_completion_check_is_load_bearing() {
    // Red: without the second CHECK, a `staged` row may carry a receipt key.
    let mutated = memory_conn();
    let statement = drop_check(SOURCE_FACTS_DDL_STATEMENTS[0], "state =  'complete'");
    apply_ddl(&mutated, &[(0, statement)]);
    insert_source_input(&mutated, "staged", true)
        .expect("RED: without the CHECK a staged row may carry a receipt key");

    // Green: the frozen DDL refuses it.
    let frozen = memory_conn();
    apply_ddl(&frozen, &[]);
    let err = insert_source_input(&frozen, "staged", true)
        .expect_err("GREEN: the frozen schema must refuse a half-filled staged row");
    assert!(err.contains("CHECK"), "unexpected error: {err}");
    insert_source_input(&frozen, "staged", false).expect("a bare staged row stays legal");
}

#[test]
fn canonical_link_check_is_load_bearing() {
    // Red: without the canonical CHECK, a canonical link with no message is
    // accepted.
    let mutated = memory_conn();
    let statement = drop_check(SOURCE_FACTS_DDL_STATEMENTS[4], "authority='canonical'");
    apply_ddl(&mutated, &[(4, statement)]);
    create_messages_parent(&mutated);
    insert_source_input(&mutated, "staged", false).expect("parent input row");
    insert_record(&mutated, "payload_absent", None).expect("parent record row");
    insert_link(&mutated, &projection_key(1), Some("canonical"), None, true)
        .expect("RED: without the CHECK canonical-without-message is accepted");

    // Green: the frozen DDL refuses it, and still accepts the honest shapes.
    let frozen = memory_conn();
    apply_ddl(&frozen, &[]);
    create_messages_parent(&frozen);
    insert_source_input(&frozen, "staged", false).expect("parent input row");
    insert_record(&frozen, "payload_absent", None).expect("parent record row");
    let err = insert_link(&frozen, &projection_key(1), Some("canonical"), None, true)
        .expect_err("GREEN: the frozen schema must refuse canonical without a message");
    assert!(err.contains("CHECK"), "unexpected error: {err}");
    insert_link(&frozen, &projection_key(1), Some("canonical"), Some(7), true)
        .expect("canonical with a live message");
    insert_link(&frozen, &projection_key(2), Some("standalone"), None, false)
        .expect("standalone with all-null targets");
}

// ---------------------------------------------------------------------------
// Activation against real SQLite
// ---------------------------------------------------------------------------

mod activation {
    use super::*;
    use coding_agent_search::model::types::{Conversation, Message, MessageRole};
    use franken_agent_detection::LosslessSourceValue;

    use coding_agent_search::storage::source_facts::{
        activate_source_input_in_tx, binding_digest, context_digest, decode_link_evidence,
        encode_link_evidence, expected_manifest_digest,
        install_source_links_in_tx, registered_source_input_id, semantic_request_digest,
        source_a_roots_in_tx,
        stage_source_records_in_tx, verify_source_receipt_in_tx, ClaimLinkInstall,
        ClaimMappingState, EvidenceKind, ExtraStorageKind, FramingScan, IncomingStatus, IndexStep,
        InstallationClass,
        MergeFingerprint, OriginalBinding, OriginalBindingOutcome, OriginalInstallation,
        ParseState, ProjectionDisposition, RecordMappingState, ReplayRejectReason, SafeDiagnostic,
        SafePosition, SafetyState, Sha256Digest, WinnerRejectionEvidence,
        SourceActivationOutcome, SourceActivationRequest, SourceClaim, SourceFormat,
        SourceInputDeclaration, SourceInstallError, SourceReceiptMatch, SourceSafetyConfig,
        TerminalState, VerifiedFinish, VerifiedReceipt, VerifiedSourceInput, VerifiedStagedRecord,
    };

    /// Two JSONL records with no blank line: the independent scan's denominator
    /// is 2 records, 0 blank lines, 17 bytes.
    const SEALED: &[u8] = b"{\"n\":1}\n{\"n\":2}\n";

    const CONTEXT_JSON: &[u8] = br#"{"connector":"claude","schema":"cass.source-parser-context/1"}"#;

    fn storage_err(err: SourceInstallError) -> StorageError {
        StorageError::Corrupt { detail: err.to_string() }
    }

    fn builtin_four_arrays() -> coding_agent_search::sources::config::ExcludedContextPaths {
        toml::from_str(include_str!("../config/excluded_context_paths.toml"))
            .expect("the built-in configuration parses")
    }

    fn safety_config() -> SourceSafetyConfig {
        SourceSafetyConfig {
            code_version: "test/1".to_string(),
            desensitization_enabled: true,
            config_source_identity: "config/excluded_context_paths.toml".to_string(),
            fixed_config_bytes: include_bytes!("../config/excluded_context_paths.toml").to_vec(),
            effective_four_arrays: builtin_four_arrays(),
        }
    }

    fn declaration() -> SourceInputDeclaration {
        declaration_for(SEALED)
    }

    /// The same declaration shape bound to *other* sealed bytes, so a second
    /// input gets its own real `input_key` from real content.
    fn declaration_for(sealed: &[u8]) -> SourceInputDeclaration {
        let context = LosslessSourceValue::parse(CONTEXT_JSON).expect("context json");
        // The identity tuple binds the context digest and the sealed digest;
        // both are computed here exactly as the capture would compute them.
        let context_hex = context_digest(&context).expect("context digest").hex();
        let sealed_hex = Sha256Digest::of(sealed).hex();
        SourceInputDeclaration {
            identity_tuple: vec![
                Some("cass.source-input/2".to_string()),
                Some("ns".to_string()),
                Some("local".to_string()),
                Some("claude".to_string()),
                Some("root".to_string()),
                Some("relative.jsonl".to_string()),
                Some("user".to_string()),
                None,
                None,
                None,
                None,
                Some(context_hex),
                Some(sealed_hex),
                Some("normalizer/1".to_string()),
                Some("safety-contract/1".to_string()),
            ],
            identity_namespace: "ns".to_string(),
            source_id: "local".to_string(),
            connector: "claude".to_string(),
            origin_kind: None,
            origin_host: None,
            origin_source_version: None,
            role: Some("user".to_string()),
            platform: None,
            root_id: "root".to_string(),
            relative_locator: "relative.jsonl".to_string(),
            discovery: LosslessSourceValue::parse(br#"{"a":1}"#).expect("json"),
            parser_context: context,
            sealed_ref: LosslessSourceValue::parse(br#"{"c":3}"#).expect("json"),
            format: SourceFormat::Jsonl,
            normalizer_id: "normalizer/1".to_string(),
            safety_contract_id: "safety-contract/1".to_string(),
        }
    }

    fn verified_input() -> VerifiedSourceInput {
        verified_input_for(SEALED)
    }

    fn verified_input_for(sealed: &[u8]) -> VerifiedSourceInput {
        VerifiedSourceInput::verify(declaration_for(sealed), sealed, &safety_config())
            .expect("the declaration matches the sealed bytes")
            .0
    }

    /// Stage one sealed input's frames and hand them to the reader's stage.
    fn stage_page(tx: &Tx<'_>, input: &VerifiedSourceInput, sealed: &[u8]) -> i64 {
        let mut scan = FramingScan::new(sealed, SourceFormat::Jsonl);
        let frames = scan.next_page(16).expect("scan");
        let records: Vec<VerifiedStagedRecord> = frames
            .iter()
            .map(|frame| {
                VerifiedStagedRecord::from_frame(
                    frame,
                    Some(*frame.raw_sha256()),
                    ParseState::Parsed,
                    RecordMappingState::AllCanonical,
                    SafetyState::Preserved,
                    None,
                    None,
                    None,
                )
            })
            .collect();
        let staged = stage_source_records_in_tx(tx, input, &records).expect("stage");
        tx.execute(
            "UPDATE source_records SET frame_state = 'staged' WHERE input_id = ?1",
            &[Value::Integer(staged.input_id)],
        )
        .expect("reader stage");
        staged.input_id
    }

    fn decode_receipt_detail_for_test(detail: &str) -> Result<VerifiedReceipt, StorageError> {
        coding_agent_search::storage::source_facts::decode_receipt_detail(detail.as_bytes())
            .map_err(storage_err)
    }

    /// A second, genuinely different sealed input: same shape, different bytes,
    /// so its `input_key` and record ids are its own.
    const SEALED_R2: &[u8] = b"{\"n\":1}\n{\"n\":9}\n";

    /// Stage both frames and register the parent, then hand the two rows to the
    /// reader's stage, which is what 05B owns.
    fn stage_and_mark_reader_processed(tx: &Tx<'_>, input: &VerifiedSourceInput) -> i64 {
        let mut scan = FramingScan::new(SEALED, SourceFormat::Jsonl);
        let frames = scan.next_page(16).expect("scan");
        assert_eq!(frames.len(), 2);
        let records: Vec<VerifiedStagedRecord> = frames
            .iter()
            .map(|frame| {
                VerifiedStagedRecord::from_frame(
                    frame,
                    Some(*frame.raw_sha256()),
                    ParseState::Parsed,
                    RecordMappingState::AllCanonical,
                    SafetyState::Preserved,
                    None,
                    None,
                    None,
                )
            })
            .collect();
        let staged = stage_source_records_in_tx(tx, input, &records).expect("stage");
        // 05B's reader marks a frame staged once it has processed it; a frame
        // left `frame_pending` must block activation.
        tx.execute(
            "UPDATE source_records SET frame_state = 'staged' WHERE input_id = ?1",
            &[Value::Integer(staged.input_id)],
        )
        .expect("reader stage");
        staged.input_id
    }

    fn create_conversation_and_message(tx: &Tx<'_>) -> (i64, i64) {
        // Idempotent on purpose: a later in-flight attempt reuses the same
        // parents, and re-inserting them must not be a conflict.
        tx.execute_batch(
            "INSERT OR IGNORE INTO agents (id, slug, name, kind, created_at, updated_at) \
                 VALUES (1, 'claude', 'Claude', 'agent', 0, 0);
             -- The fresh schema already seeds the bootstrap-local source row.
             INSERT OR IGNORE INTO sources (id, kind, created_at, updated_at) \
                 VALUES ('local', 'local', 0, 0);
             INSERT OR IGNORE INTO conversations (id, agent_id, source_id, source_path, identity_host) \
                 VALUES (1, 1, 'local', '/tmp/session.jsonl', 'local');
             INSERT OR IGNORE INTO messages (id, conversation_id, idx, role, content) \
                 VALUES (7, 1, 0, 'user', 'hello');",
        )
        .expect("conversation and message parents");
        (1, 7)
    }

    fn canonical_installation(
        conversation_id: i64,
        message_id: i64,
        semantic_request_digest: Sha256Digest,
    ) -> OriginalInstallation {
        OriginalInstallation {
            semantic_request_digest,
            class: InstallationClass::CanonicalBound,
            binding: Some(OriginalBinding {
                outcome: OriginalBindingOutcome::AcceptedNew,
                original_conversation_id: conversation_id,
                original_message_id: message_id,
                stored_idx: 0,
                stored_merge_fingerprint: MergeFingerprint {
                    idx: 0,
                    created_at: Some(1),
                    role: "User".to_string(),
                    author: None,
                    content_blake3_hex: "ab".repeat(32),
                },
                safe_content_sha256: Sha256Digest::of(b"hello"),
                extra_storage_kind: ExtraStorageKind::Null,
                extra_json_sha256: None,
                extra_bin_sha256: None,
                extra_semantic_digest: None,
                excluded_semantic_digest: None,
                conversation_identity_digest: Sha256Digest::of(b"identity"),
            }),
            rejection: None,
            reason: None,
        }
    }

    fn canonical_claim(input_key: &Sha256Digest) -> SourceClaim {
        SourceClaim {
            input_key: *input_key,
            record_ordinal: 1,
            record_pointer: String::new(),
            conversation_ordinal: Some(0),
            final_message_idx: Some(0),
            positions: Vec::new(),
            projection_pointer: Some("/messages/0".to_string()),
            evidence_kind: EvidenceKind::Prose,
            mapping_state: ClaimMappingState::Canonical,
        }
    }

    /// The reader's Finish for this fixture's manifest. One definition, so the
    /// request a test builds and the digest it commits to cannot drift apart.
    fn test_finish(input: &VerifiedSourceInput) -> VerifiedFinish {
        let manifest = input.manifest();
        VerifiedFinish {
            content_digest: *manifest.sealed_sha256(),
            bytes_read: manifest.byte_len(),
            records_seen: manifest.records(),
            blank_lines: manifest.blank_lines(),
            parse_failed: 0,
            mapping_diagnostics: 0,
            unprocessed_ranges: Vec::new(),
            reached_eof: true,
        }
    }

    /// §12: the semantic request digest this fixture's activation will commit
    /// to, computed from the same pieces the activation uses. It is available
    /// once the records are staged, because the A side depends on the claims and
    /// not on the installations they will carry.
    fn request_semantic_digest_for(
        tx: &Tx<'_>,
        input: &VerifiedSourceInput,
        input_id: i64,
    ) -> Sha256Digest {
        request_semantic_digest_with(
            tx,
            input,
            input_id,
            &test_finish(input),
            ProjectionDisposition::Ready,
        )
    }

    /// The same digest for a request that carries a different Finish or
    /// disposition, which is what an input with a measured parse failure, or a
    /// whole-input rejection, commits to.
    fn request_semantic_digest_with(
        tx: &Tx<'_>,
        input: &VerifiedSourceInput,
        input_id: i64,
        finish: &VerifiedFinish,
        disposition: ProjectionDisposition,
    ) -> Sha256Digest {
        let (records_root, claims_root) =
            source_a_roots_in_tx(tx, input.input_key(), input_id).expect("A roots");
        let manifest = input.manifest();
        semantic_request_digest(
            input.input_key(),
            &expected_manifest_digest(manifest, input.safety_identity()),
            manifest.sealed_sha256(),
            manifest.byte_len(),
            manifest.format().as_str(),
            "normalizer/1",
            "safety-contract/1",
            finish,
            disposition,
            &records_root,
            &claims_root,
        )
    }

    /// Install one canonical witness whose embedded request digest is the one
    /// this input's activation will recompute (§9). The claim is staged first,
    /// then the witness replaces the pending form: the digest cannot be known
    /// before the A side the claim belongs to exists.
    /// The semantic request digest the witness already installed for this input
    /// commits to, if there is one.
    fn stored_witness_request_digest(tx: &Tx<'_>, input_id: i64) -> Option<Sha256Digest> {
        let positions: Option<Vec<u8>> = tx
            .query_opt_map(
                "SELECT l.source_positions_bin
                 FROM source_message_links l
                 JOIN source_records r ON r.id = l.record_id
                 WHERE r.input_id = ?1
                 ORDER BY r.ordinal ASC, r.record_pointer ASC, l.projection_key ASC
                 LIMIT 1",
                &[Value::Integer(input_id)],
                |row| row.get_typed(0),
            )
            .expect("read the stored witness");
        positions.and_then(|bytes| {
            decode_link_evidence(&bytes)
                .expect("the stored witness decodes")
                .installation
                .map(|installation| installation.semantic_request_digest)
        })
    }

    fn install_canonical_witness(
        tx: &Tx<'_>,
        input: &VerifiedSourceInput,
        input_id: i64,
        claim: SourceClaim,
        conversation_id: i64,
        message_id: i64,
    ) {
        install_witnesses(
            tx,
            input,
            input_id,
            &[(claim, conversation_id, message_id)],
        );
    }

    /// Stage every claim, then install their canonical witnesses each carrying
    /// the semantic request digest this input's activation will recompute (§9).
    /// The digest cannot be known before the claims exist: it binds the A side,
    /// which is the claims and the records, not the installations.
    fn install_witnesses(
        tx: &Tx<'_>,
        input: &VerifiedSourceInput,
        input_id: i64,
        links: &[(SourceClaim, i64, i64)],
    ) {
        let staged = install_source_links_in_tx(
            tx,
            input_id,
            &links
                .iter()
                .map(|(claim, _, _)| ClaimLinkInstall {
                    claim: claim.clone(),
                    installation: None,
                })
                .collect::<Vec<_>>(),
        );
        if let Err(err) = &staged {
            // A claim this fixture already installed keeps its row; the witness
            // install below is the operation under test.
            assert!(
                matches!(err, SourceInstallError::Conflict { .. }),
                "staging the claims failed: {err:?}"
            );
        }
        let digest = request_semantic_digest_for(tx, input, input_id);
        install_source_links_in_tx(
            tx,
            input_id,
            &links
                .iter()
                .map(|(claim, conversation_id, message_id)| ClaimLinkInstall {
                    claim: claim.clone(),
                    installation: Some(canonical_installation(
                        *conversation_id,
                        *message_id,
                        digest,
                    )),
                })
                .collect::<Vec<_>>(),
        )
        .expect("install the canonical witnesses");
    }

    fn activation_request(
        tx: &Tx<'_>,
        input: &VerifiedSourceInput,
        input_id: i64,
    ) -> SourceActivationRequest {
        let library_identity: String = tx
            .query_row_map(
                "SELECT value FROM meta WHERE key = 'library_identity'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("library identity");
        let (records_root, claims_root) =
            source_a_roots_in_tx(tx, input.input_key(), input_id).expect("A roots");
        let manifest = input.manifest();
        SourceActivationRequest {
            input_key: *input.input_key(),
            library_identity,
            normalizer_id: "normalizer/1".to_string(),
            safety_contract_id: "safety-contract/1".to_string(),
            expected_manifest_digest: expected_manifest_digest(manifest, input.safety_identity()),
            finish: test_finish(input),
            projection_disposition: ProjectionDisposition::Ready,
            source_semantic_records_root: records_root,
            claims_root,
            requested_terminal: TerminalState::Complete,
        }
    }

    fn meta(tx: &Tx<'_>, key: &str) -> Option<String> {
        tx.query_opt_map(
            "SELECT value FROM meta WHERE key = ?1",
            &[Value::Text(key.to_string())],
            |row| row.get_typed(0),
        )
        .expect("meta read")
    }

    fn prepare(tx: &Tx<'_>) -> (VerifiedSourceInput, i64, SourceActivationRequest) {
        let input = verified_input();
        let input_id = stage_and_mark_reader_processed(tx, &input);
        let (conversation_id, message_id) = create_conversation_and_message(tx);
        install_canonical_witness(
            tx,
            &input,
            input_id,
            canonical_claim(input.input_key()),
            conversation_id,
            message_id,
        );
        let request = activation_request(tx, &input, input_id);
        (input, input_id, request)
    }

    #[test]
    fn activation_completes_the_input_and_moves_the_revision_once() {
        let dir = scratch_dir("activate");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();

        let (input, input_id, request) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let (input, input_id, request) = prepare(tx);
                assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("0"));
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                let SourceActivationOutcome::Activated {
                    receipt_key,
                    generation,
                    source_facts_revision,
                    ..
                } = outcome
                else {
                    panic!("expected an Activated outcome, got {outcome:?}");
                };
                assert!(receipt_key.starts_with("source-input-v1:"));
                assert!(generation.starts_with("source-activation-v1:"));
                assert_eq!(source_facts_revision, 1);
                // Every decided fact landed in this one transaction.
                assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("1"));
                assert_eq!(
                    meta(tx, "source_content_generation").as_deref(),
                    Some(generation.as_str())
                );
                let state: String = tx
                    .query_row_map(
                        "SELECT state FROM source_inputs WHERE id = ?1",
                        &[Value::Integer(input_id)],
                        |row| row.get_typed(0),
                    )?;
                assert_eq!(state, "complete");
                let pending: i64 = tx
                    .query_row_map(
                        "SELECT COUNT(*) FROM source_records WHERE input_id = ?1 AND frame_state <> 'activated'",
                        &[Value::Integer(input_id)],
                        |row| row.get_typed(0),
                    )?;
                assert_eq!(pending, 0, "every frame must be activated");
                let receipts: i64 = tx
                    .query_row_map(
                        "SELECT COUNT(*) FROM operation_commit_receipt WHERE idempotency_key = ?1",
                        &[Value::Text(receipt_key.clone())],
                        |row| row.get_typed(0),
                    )?;
                assert_eq!(receipts, 1);
                Ok((input, input_id, request))
            })
            .expect("activation transaction");

        // Retrying R1 must not change the winner, the A roots or the witness /
        // B roots: a fresh process sees exactly the state R1 committed.
        let state_after_r1 = persisted_state_in_a_new_process(&dir.join("agent_search.db"));

        // A fresh transaction replays the same activation: the receipt comes
        // back and nothing moves again.
        conn.with_tx(TxMode::Immediate, |tx| {
            let outcome =
                activate_source_input_in_tx(tx, &request, input.manifest()).map_err(storage_err)?;
            assert!(
                matches!(outcome, SourceActivationOutcome::Replay { .. }),
                "a committed activation must replay, got {outcome:?}"
            );
            assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("1"));
            let match_ = verify_source_receipt_in_tx(tx, &request).map_err(storage_err)?;
            assert!(
                matches!(match_, SourceReceiptMatch::VerifiedReplay { .. }),
                "the stored receipt must re-verify, got {match_:?}"
            );
            let registered = registered_source_input_id(tx, input.input_key()).map_err(storage_err)?;
            assert_eq!(registered, Some(input_id));
            // The receipt's committed roots are the ones R1 wrote, unchanged.
            let SourceReceiptMatch::VerifiedReplay { receipt, .. } = &match_ else {
                panic!("expected a verified replay");
            };
            assert_eq!(
                receipt.source_semantic_records_root,
                request.source_semantic_records_root
            );
            assert_eq!(receipt.claims_root, request.claims_root);
            Ok(())
        })
        .expect("replay transaction");

        assert_eq!(
            persisted_state_in_a_new_process(&dir.join("agent_search.db")),
            state_after_r1,
            "retrying R1 changed the stored A/witness/B state"
        );
    }

    #[test]
    fn a_frame_left_pending_blocks_activation() {
        let dir = scratch_dir("pending-frame");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();

        conn.with_tx(TxMode::Immediate, |tx| {
            let input = verified_input();
            let mut scan = FramingScan::new(SEALED, SourceFormat::Jsonl);
            let frames = scan.next_page(16).map_err(storage_err)?;
            let records: Vec<VerifiedStagedRecord> = frames
                .iter()
                .map(|frame| {
                    VerifiedStagedRecord::from_frame(
                        frame,
                        Some(*frame.raw_sha256()),
                        ParseState::Parsed,
                        RecordMappingState::AllCanonical,
                        SafetyState::Preserved,
                        None,
                        None,
                        None,
                    )
                })
                .collect();
            let staged = stage_source_records_in_tx(tx, &input, &records).map_err(storage_err)?;
            // The reader processed only the first frame.
            tx.execute(
                "UPDATE source_records SET frame_state = 'staged' WHERE input_id = ?1 AND ordinal = ?2",
                &[Value::Integer(staged.input_id), Value::Blob(vec![0, 0, 0, 0, 0, 0, 0, 1])],
            )?;
            let (conversation_id, message_id) = create_conversation_and_message(tx);
            install_canonical_witness(
                tx,
                &input,
                staged.input_id,
                canonical_claim(input.input_key()),
                conversation_id,
                message_id,
            );
            let request = activation_request(tx, &input, staged.input_id);
            let err = activate_source_input_in_tx(tx, &request, input.manifest())
                .expect_err("a frame_pending row must block activation");
            assert!(matches!(err, SourceInstallError::Activation { .. }), "{err}");
            assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("0"));
            Ok(())
        })
        .expect("pending-frame transaction");
    }

    #[test]
    fn an_incomplete_request_only_stages_and_never_moves_the_revision() {
        let dir = scratch_dir("staged-only");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();

        conn.with_tx(TxMode::Immediate, |tx| {
            let (input, _input_id, mut request) = prepare(tx);
            request.requested_terminal = TerminalState::Partial;
            let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                .map_err(storage_err)?;
            assert!(
                matches!(outcome, SourceActivationOutcome::StagedOnly { .. }),
                "a non-final failure must stay staged, got {outcome:?}"
            );
            assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("0"));
            assert_eq!(meta(tx, "source_content_generation"), None);
            Ok(())
        })
        .expect("staged-only transaction");
    }

    #[test]
    fn a_whole_input_rejection_publishes_once_and_does_not_repeat() {
        let dir = scratch_dir("publish-failure");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();

        let first_visible = conn
            .with_tx(TxMode::Immediate, |tx| {
                // The witness has to be bound to the request this input will
                // commit, including its whole-input-rejection disposition, so
                // the fixture stages the claim first and installs the witness
                // once the request it belongs to is known (§9).
                let input = verified_input();
                let input_id = stage_and_mark_reader_processed(tx, &input);
                let (conversation_id, message_id) = create_conversation_and_message(tx);
                let claim = canonical_claim(input.input_key());
                install_source_links_in_tx(
                    tx,
                    input_id,
                    &[ClaimLinkInstall {
                        claim: claim.clone(),
                        installation: None,
                    }],
                )
                .map_err(storage_err)?;
                let mut request = activation_request(tx, &input, input_id);
                request.projection_disposition = ProjectionDisposition::WholeInputRejected;
                request.requested_terminal = TerminalState::Failed;
                let digest = request_semantic_digest_with(
                    tx,
                    &input,
                    input_id,
                    &request.finish,
                    request.projection_disposition,
                );
                install_source_links_in_tx(
                    tx,
                    input_id,
                    &[ClaimLinkInstall {
                        claim,
                        installation: Some(canonical_installation(
                            conversation_id,
                            message_id,
                            digest,
                        )),
                    }],
                )
                .map_err(storage_err)?;
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                let SourceActivationOutcome::PublishedFailure {
                    source_facts_revision,
                    visible_facts_digest,
                    state,
                    ..
                } = outcome
                else {
                    panic!("expected a PublishedFailure, got {outcome:?}");
                };
                assert_eq!(state, TerminalState::Failed);
                assert_eq!(source_facts_revision, 1);
                assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("1"));
                // A failure publication writes no success receipt and does not
                // move the content generation.
                assert_eq!(meta(tx, "source_content_generation"), None);
                let receipts: i64 = tx
                    .query_row_map(
                        "SELECT COUNT(*) FROM operation_commit_receipt",
                        &[],
                        |row| row.get_typed(0),
                    )?;
                assert_eq!(receipts, 0);
                Ok((request, visible_facts_digest))
            })
            .expect("publication transaction");

        // Replaying the same publication does not move the counter again.
        let input = verified_input();
        conn.with_tx(TxMode::Immediate, |tx| {
            let (request, visible) = &first_visible;
            let outcome = activate_source_input_in_tx(tx, request, input.manifest())
                .map_err(storage_err)?;
            let SourceActivationOutcome::PublishedFailure {
                source_facts_revision,
                visible_facts_digest,
                ..
            } = outcome
            else {
                panic!("expected a repeat PublishedFailure, got {outcome:?}");
            };
            assert_eq!(source_facts_revision, 1, "a same-value replay must not re-increment");
            assert_eq!(visible_facts_digest, *visible);
            assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("1"));
            Ok(())
        })
        .expect("repeat publication transaction");
    }

    /// R1 installs; then the on-record witness is **historyized** (not
    /// deleted) and the projection is re-bound to different rows; retrying R1
    /// must return R1's own receipt unchanged and leave the later binding's
    /// state exactly as it was.
    ///
    /// What this fixture claims: the retry's receipt is field-by-field R1's,
    /// and no table changes. What it does not claim: that a published R2
    /// replacement flow is complete — that path belongs to the caller (05C)
    /// and the storage primitives expose no separate R2 receipt.
    #[test]
    fn retrying_r1_after_the_witness_is_rebound_is_a_historical_noop() {
        let dir = scratch_dir("r1-then-rebind");
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();

        // R1, keeping the receipt it returned for the later comparison.
        let (input, input_id, request, r1_receipt) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let (input, input_id, request) = prepare(tx);
                let outcome =
                    activate_source_input_in_tx(tx, &request, input.manifest()).map_err(storage_err)?;
                let SourceActivationOutcome::Activated { receipt_key, .. } = &outcome else {
                    panic!("R1 must activate, got {outcome:?}");
                };
                let detail = read_receipt_detail_for_test(tx, receipt_key)?;
                let receipt = coding_agent_search::storage::source_facts::decode_receipt_detail(
                    detail.as_bytes(),
                )
                .map_err(storage_err)?;
                Ok((input, input_id, request, receipt))
            })
            .expect("R1 activates");

        // Historyize rather than delete: the original witness row stays, only
        // its current authority changes (§6's mandated funnel), and the
        // projection is then re-bound to fresh rows.
        let rebind = conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute(
                "UPDATE source_message_links SET authority = 'historical', message_id = NULL
                 WHERE authority = 'canonical'",
                &[],
            )?;
            tx.execute_batch(
                "INSERT OR IGNORE INTO conversations (id, agent_id, source_id, source_path, identity_host) \
                     VALUES (2, 1, 'local', '/tmp/session-2.jsonl', 'local');
                 INSERT OR IGNORE INTO messages (id, conversation_id, idx, role, content) \
                     VALUES (8, 2, 0, 'user', 'hello again');",
            )?;
            let outcome = install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: canonical_claim(input.input_key()),
                    installation: Some(canonical_installation(
                        2,
                        8,
                        request_semantic_digest_for(tx, &input, input_id),
                    )),
                }],
            );
            println!("SRC05A_REBIND {outcome:?}");
            // Either the primitive re-binds the projection or it refuses; both
            // are recorded, and neither is assumed here.
            Ok(outcome.is_err())
        })
        .expect("the rebind attempt runs");

        let state_after_rebind = persisted_state_in_a_new_process(&path);

        conn.with_tx(TxMode::Immediate, |tx| {
            let outcome = activate_source_input_in_tx(tx, &request, input.manifest());
            println!("SRC05A_R1_RETRY {outcome:?}");
            let SourceActivationOutcome::Replay { receipt } = outcome.map_err(storage_err)? else {
                panic!("retrying R1 must be a historical replay");
            };
            assert_eq!(
                receipt, r1_receipt,
                "the retry must return R1's own receipt, field for field"
            );
            Ok(())
        })
        .expect("retry transaction");

        assert_eq!(
            persisted_state_in_a_new_process(&path),
            state_after_rebind,
            "retrying R1 disturbed the later binding's state"
        );
        println!("SRC05A_REBIND_REFUSED {rebind}");
    }

    /// The full R1 → R2 → retry R1 shape the controller ruled on: R2 is a
    /// second, genuinely different sealed input aimed at the same conversation
    /// position, R1's link is historyized and unbound while its witness bytes
    /// stay, and retrying R1 returns R1's own receipt without touching R2.
    #[test]
    fn r2_is_a_second_sealed_input_and_retrying_r1_stays_a_historical_noop() {
        let dir = scratch_dir("r1-then-r2-real");
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();

        // R1, keeping what R1 committed.
        let (r1_input, r1_request, r1_receipt, r1_witness, r1_digest) =
            conn.with_tx(TxMode::Immediate, |tx| {
                let input = verified_input();
                let input_id = stage_page(tx, &input, SEALED);
                let (conversation_id, message_id) = create_conversation_and_message(tx);
                install_canonical_witness(
                    tx,
                    &input,
                    input_id,
                    canonical_claim(input.input_key()),
                    conversation_id,
                    message_id,
                );
                let request = activation_request(tx, &input, input_id);
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                let SourceActivationOutcome::Activated { receipt_key, .. } = &outcome else {
                    panic!("R1 must activate, got {outcome:?}");
                };
                let detail = read_receipt_detail_for_test(tx, receipt_key)?;
                let receipt = decode_receipt_detail_for_test(&detail)?;
                let witness: Vec<u8> = tx.query_row_map(
                    "SELECT source_positions_bin FROM source_message_links",
                    &[],
                    |row| row.get_typed(0),
                )?;
                let digest: Vec<u8> = tx.query_row_map(
                    "SELECT binding_digest FROM source_message_links",
                    &[],
                    |row| row.get_typed(0),
                )?;
                Ok((input, request, receipt, witness, digest))
            })
            .expect("R1 activates");

        let r1_input_id: i64 = conn
            .query_row_map(
                "SELECT id FROM source_inputs WHERE input_key = ?1",
                &[Value::Blob(r1_input.input_key().as_bytes().to_vec())],
                |row| row.get_typed(0),
            )
            .expect("R1's parent row");

        // R2: historyize and unbind R1, replace the message at the same
        // position, then install the second sealed input as the new current one.
        let (r2_input, r2_request) = conn
            .with_tx(TxMode::Immediate, |tx| {
                tx.execute(
                    "UPDATE source_message_links SET authority = 'historical', message_id = NULL
                     WHERE authority = 'canonical'",
                    &[],
                )?;
                tx.execute("DELETE FROM messages WHERE conversation_id = 1 AND idx = 0", &[])?;
                tx.execute(
                    "INSERT INTO messages (id, conversation_id, idx, role, content)
                     VALUES (8, 1, 0, 'user', 'hello again')",
                    &[],
                )?;

                let input = verified_input_for(SEALED_R2);
                assert_ne!(
                    input.input_key(),
                    r1_input.input_key(),
                    "R2 must be a different input, derived from different bytes"
                );
                let input_id = stage_page(tx, &input, SEALED_R2);
                install_canonical_witness(
                    tx,
                    &input,
                    input_id,
                    canonical_claim(input.input_key()),
                    1,
                    8,
                );
                let request = activation_request(tx, &input, input_id);
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                println!("SRC05A_R2 {outcome:?}");
                assert!(
                    matches!(outcome, SourceActivationOutcome::Activated { .. }),
                    "R2 must become the new current installation, got {outcome:?}"
                );
                Ok((input, request))
            })
            .expect("R2 replaces the installation");

        let state_after_r2 = persisted_state_in_a_new_process(&path);

        // Retry R1.
        conn.with_tx(TxMode::Immediate, |tx| {
            let outcome = activate_source_input_in_tx(tx, &r1_request, r1_input.manifest());
            println!("SRC05A_R1_RETRY {outcome:?}");
            let SourceActivationOutcome::Replay { receipt } = outcome.map_err(storage_err)? else {
                panic!("retrying R1 after R2 must be a historical replay");
            };
            assert_eq!(
                receipt, r1_receipt,
                "the retry must return R1's own receipt, field for field"
            );
            Ok(())
        })
        .expect("retry transaction");

        // R1's historical commitments and its post-R2 state are untouched.
        conn.with_tx(TxMode::Immediate, |tx| {
            let witness: Vec<u8> = tx.query_row_map(
                "SELECT source_positions_bin FROM source_message_links
                 JOIN source_records ON source_records.id = source_message_links.record_id
                 WHERE source_records.input_id = ?1",
                &[Value::Integer(r1_input_id)],
                |row| row.get_typed(0),
            )?;
            let digest: Vec<u8> = tx.query_row_map(
                "SELECT binding_digest FROM source_message_links
                 JOIN source_records ON source_records.id = source_message_links.record_id
                 WHERE source_records.input_id = ?1",
                &[Value::Integer(r1_input_id)],
                |row| row.get_typed(0),
            )?;
            let authority: String = tx.query_row_map(
                "SELECT authority FROM source_message_links
                 JOIN source_records ON source_records.id = source_message_links.record_id
                 WHERE source_records.input_id = ?1",
                &[Value::Integer(r1_input_id)],
                |row| row.get_typed(0),
            )?;
            assert_eq!(witness, r1_witness, "R1's original witness bytes must survive");
            assert_eq!(digest, r1_digest, "R1's original binding digest must survive");
            assert_eq!(authority, "historical", "R1's link must stay historyized");
            // R2's own input is present and is the current one.
            let r2_state: String = tx.query_row_map(
                "SELECT state FROM source_inputs WHERE input_key = ?1",
                &[Value::Blob(r2_input.input_key().as_bytes().to_vec())],
                |row| row.get_typed(0),
            )?;
            assert_eq!(r2_state, "complete");
            let _ = &r2_request;
            Ok(())
        })
        .expect("post-retry inspection");

        assert_eq!(
            persisted_state_in_a_new_process(&path),
            state_after_r2,
            "retrying R1 disturbed R2's state"
        );
    }

    /// A winner-rejection installation: no binding, a real rejection, and the
    /// parent identity digest the witness needs to be re-hashable.
    fn winner_rejected_installation(
        conversation_identity_digest: Sha256Digest,
        semantic_request_digest: Sha256Digest,
    ) -> OriginalInstallation {
        OriginalInstallation {
            semantic_request_digest,
            class: InstallationClass::WinnerRejectedNoBinding,
            binding: None,
            rejection: Some(WinnerRejectionEvidence {
                claim_digest: Sha256Digest::of(b"claim"),
                conversation_identity_digest,
                incoming_idx: 0,
                incoming_merge_fingerprint: MergeFingerprint {
                    idx: 0,
                    created_at: Some(1),
                    role: "User".to_string(),
                    author: None,
                    content_blake3_hex: "ab".repeat(32),
                },
                winner_conversation_id: 1,
                winner_message_id: 7,
                winner_idx: 0,
                winner_merge_fingerprint: MergeFingerprint {
                    idx: 0,
                    created_at: Some(2),
                    role: "User".to_string(),
                    author: None,
                    content_blake3_hex: "cd".repeat(32),
                },
            }),
            reason: Some(ReplayRejectReason::WinnerRejected),
        }
    }

    /// SCOPE: the installation is built as a DTO by this test. It proves only
    /// that a `WinnerRejectedNoBinding` witness carrying its identity digest is
    /// rebuildable from the stored rows and installs as `historical` with no
    /// live message. It does NOT exercise the projection's same-idx branch, and
    /// the project's projection does not currently produce this class at all
    /// (see the pending item for `install_conversation_projection_in_tx`).
    #[test]
    fn a_hand_built_winner_rejection_witness_rebuilds_from_its_persisted_evidence() {
        let dir = scratch_dir("winner-rejection");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();

        conn.with_tx(TxMode::Immediate, |tx| {
            let input = verified_input();
            let input_id = stage_and_mark_reader_processed(tx, &input);
            let (conversation_id, message_id) = create_conversation_and_message(tx);

            let mut rejected_claim = canonical_claim(input.input_key());
            rejected_claim.final_message_idx = Some(1);
            rejected_claim.projection_pointer = Some("/messages/1".to_string());

            install_source_links_in_tx(
                tx,
                input_id,
                &[
                    ClaimLinkInstall {
                        claim: canonical_claim(input.input_key()),
                        installation: None,
                    },
                    ClaimLinkInstall {
                        claim: rejected_claim.clone(),
                        installation: None,
                    },
                ],
            )
            .map_err(storage_err)?;
            let digest = request_semantic_digest_for(tx, &input, input_id);
            install_source_links_in_tx(
                tx,
                input_id,
                &[
                    ClaimLinkInstall {
                        claim: canonical_claim(input.input_key()),
                        installation: Some(canonical_installation(
                            conversation_id,
                            message_id,
                            digest,
                        )),
                    },
                    ClaimLinkInstall {
                        claim: rejected_claim,
                        installation: Some(winner_rejected_installation(
                            Sha256Digest::of(b"parent identity"),
                            digest,
                        )),
                    },
                ],
            )
            .map_err(storage_err)?;

            // The rejection row's own authority and message binding.
            let rejected: (String, Option<i64>) = tx.query_row_map(
                "SELECT authority, message_id FROM source_message_links
                 WHERE projection_pointer = '/messages/1'",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )?;
            assert_eq!(rejected, ("historical".to_string(), None));

            // The whole B side is rebuildable from what is persisted, which is
            // only true because the rejection stores its identity digest.
            let (records_root, binding_root, counts) =
                coding_agent_search::storage::source_facts::source_b_roots_in_tx(
                    tx,
                    input.input_key(),
                    input_id,
                )
                .map_err(storage_err)?;
            assert_eq!(records_root.count, 2);
            assert_eq!(binding_root.count, 2);
            assert_eq!(counts.canonical_bound, 1);
            assert_eq!(counts.winner_rejected_no_binding, 1);
            Ok(())
        })
        .expect("winner-rejection transaction");
    }

    /// SCOPE: an ordinary `CanonicalBound` input. Once its own message is gone
    /// and its canonical link is historyized, the committed receipt still
    /// verifies — as a historical one. It does not consume any rejection
    /// witness.
    #[test]
    fn a_canonical_receipt_still_verifies_after_its_own_message_is_historyized_and_deleted() {
        let dir = scratch_dir("historyized-receipt");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();

        let (input, request, receipt) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let (input, input_id, request) = prepare(tx);
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                let SourceActivationOutcome::Activated { receipt_key, .. } = &outcome else {
                    panic!("the input must activate, got {outcome:?}");
                };
                let detail = read_receipt_detail_for_test(tx, receipt_key)?;
                let receipt = decode_receipt_detail_for_test(&detail)?;
                let _ = input_id;
                Ok((input, request, receipt))
            })
            .expect("activation");

        // Historyize first (the SQL pair refuses the delete otherwise), then
        // drop the winner's message row.
        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute(
                "UPDATE source_message_links SET authority = 'historical', message_id = NULL
                 WHERE authority = 'canonical'",
                &[],
            )?;
            tx.execute("DELETE FROM messages WHERE id = 7", &[])?;
            Ok(())
        })
        .expect("historyize then delete the winner message");

        conn.with_tx(TxMode::Immediate, |tx| {
            let matched = verify_source_receipt_in_tx(tx, &request).map_err(storage_err)?;
            let SourceReceiptMatch::VerifiedReplay { receipt: verified, currency } = matched else {
                panic!("the historyized receipt must still verify");
            };
            assert_eq!(*verified, receipt, "the receipt must be unchanged");
            assert_eq!(
                currency,
                coding_agent_search::storage::source_facts::ReceiptCurrency::Historical,
                "with no live message the receipt is historical"
            );
            Ok(())
        })
        .expect("historical verification");
        let _ = input;
    }

    #[test]
    fn a_corrupted_stored_witness_digest_is_refused() {
        let dir = scratch_dir("corrupt-witness");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();

        conn.with_tx(TxMode::Immediate, |tx| {
            let (input, _input_id, request) = prepare(tx);
            // The stored column no longer holds the digest the envelope hashes
            // to: believing the column instead of recomputing would accept it.
            tx.execute(
                "UPDATE source_message_links SET binding_digest = ?1",
                &[Value::Blob(vec![0x5a; 32])],
            )?;
            let err = activate_source_input_in_tx(tx, &request, input.manifest())
                .expect_err("a corrupted stored witness digest must be refused");
            assert!(matches!(err, SourceInstallError::Corrupt { .. }), "{err}");
            assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("0"));
            Ok(())
        })
        .expect("corrupt witness transaction");
    }

    #[test]
    fn changed_positions_under_an_unchanged_digest_break_receipt_verification() {
        use coding_agent_search::storage::source_facts::encode_link_evidence;

        let dir = scratch_dir("changed-positions");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();

        let (input, request, witness_digest) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let (input, input_id, request) = prepare(tx);
                let digest = request_semantic_digest_for(tx, &input, input_id);
                activate_source_input_in_tx(tx, &request, input.manifest()).map_err(storage_err)?;
                Ok((input, request, digest))
            })
            .expect("activation transaction");

        // Swap the evidence envelope for one describing a different target,
        // leaving the stored `binding_digest` column exactly as it was.
        let replacement = {
            let mut claim = canonical_claim(input.input_key());
            claim.final_message_idx = Some(1);
            encode_link_evidence(&claim, Some(&canonical_installation(1, 7, witness_digest)))
                .expect("encode the replacement evidence")
        };
        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute(
                "UPDATE source_message_links SET source_positions_bin = ?1",
                &[Value::Blob(replacement.clone())],
            )?;
            match verify_source_receipt_in_tx(tx, &request) {
                Ok(SourceReceiptMatch::VerifiedReplay { .. }) => {
                    panic!("changed evidence under an unchanged digest must not verify as a replay")
                }
                Ok(_) | Err(_) => {}
            }
            Ok(())
        })
        .expect("changed positions transaction");
    }

    // -----------------------------------------------------------------------
    // Failure injection, verified from a fresh process
    // -----------------------------------------------------------------------

    /// Environment variable that turns this test binary into the verifying
    /// child, pointed at the database the parent just aborted a transaction on.
    const VERIFY_DB_ENV: &str = "SRC05A_VERIFY_DB";
    /// Prefix of the child's single machine-readable output line.
    const STATE_MARKER: &str = "SRC05A_STATE ";


    /// Read one receipt's stored `detail` column.
    fn read_receipt_detail_for_test(tx: &Tx<'_>, key: &str) -> Result<String, StorageError> {
        Ok(tx
            .query_opt_map(
                "SELECT detail FROM operation_commit_receipt WHERE idempotency_key = ?1",
                &[Value::Text(key.to_string())],
                |row| row.get_typed(0),
            )?
            .expect("the receipt row exists"))
    }

    /// An unambiguous length prefix for a byte string.
    fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// One row, encoded from the facade's own `Value` so the snapshot sees the
    /// storage type and the exact bytes.
    ///
    /// SQL-level formatting is unusable here: `quote()` renders any TEXT down to
    /// its first NUL, and `CAST(real AS BLOB)` renders with `%!.15g`, so two
    /// adjacent representable doubles collapse to the same text. `Real` is
    /// therefore carried as its IEEE-754 bits, `Integer` as its fixed 8 bytes,
    /// `Text` as its full UTF-8 bytes and `Blob` as its raw bytes, each with its
    /// own tag and length; `Null` is its own tag.
    fn encode_row(row: &[Value]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(row.len() as u64).to_be_bytes());
        for value in row {
            match value {
                Value::Null => out.push(0),
                Value::Integer(number) => {
                    out.push(1);
                    out.extend_from_slice(&number.to_be_bytes());
                }
                Value::Real(number) => {
                    out.push(2);
                    out.extend_from_slice(&number.to_bits().to_be_bytes());
                }
                Value::Text(text) => {
                    out.push(3);
                    push_len_prefixed(&mut out, text.as_bytes());
                }
                Value::Blob(bytes) => {
                    out.push(4);
                    push_len_prefixed(&mut out, bytes);
                }
            }
        }
        out
    }

    /// Points at which this batch's work can be made to fail. Each one is an
    /// externally expressible boundary between the primitives; activation's own
    /// body is a single transaction, so its interior points collapse into
    /// [`InjectionPoint::DuringActivation`].
    #[derive(Debug, Clone, Copy)]
    enum InjectionPoint {
        /// After the frame rows are pre-registered.
        AfterFrameRegistration,
        /// Part-way through a staging page.
        DuringStaging,
        /// After the reader marked the frames staged, before any witness.
        BeforeWitness,
        /// After the witnesses are installed, before activation.
        AfterWitness,
        /// Inside activation, whose whole body is one transaction.
        DuringActivation,
    }

    /// Runs as its own process. Without the environment variable this is a
    /// no-op, so the ordinary suite is unaffected.
    ///
    /// It reports, for **every** table the database has, a SHA-256 over a
    /// canonical projection of every row. Counts alone cannot show that an
    /// existing row was rewritten, so the digest covers row content, ordering
    /// and the winner/derived columns as well.
    #[test]
    fn child_reports_persisted_state() {
        let Ok(path) = std::env::var(VERIFY_DB_ENV) else {
            return;
        };
        let storage =
            FrankenStorage::open(Path::new(&path)).expect("the child opens the database afresh");
        let conn = storage.raw();

        let tables: Vec<String> = conn
            .query_all_map(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
                 ORDER BY name",
                &[],
                |row| row.get_typed(0),
            )
            .expect("list tables");

        let mut digests = serde_json::Map::new();
        for table in tables {
            let columns: Vec<String> = conn
                .query_all_map(&format!("PRAGMA table_info(\"{table}\")"), &[], |row| {
                    row.get_typed(1)
                })
                .expect("column list");
            assert!(
                !columns.is_empty(),
                "the state check cannot digest table {table}: it reports no columns"
            );
            // Read every cell through the facade's `Value` and encode it in
            // Rust: the SQL layer must not format anything, because both
            // `quote()` (TEXT at its first NUL) and `CAST(real AS BLOB)`
            // (%!.15g) are lossy.
            let rows: Vec<Vec<Value>> = conn
                .query_all_map(&format!("SELECT * FROM \"{table}\""), &[], |row| {
                    let mut values = Vec::with_capacity(columns.len());
                    for index in 0..columns.len() {
                        values.push(row.get_value(index)?);
                    }
                    Ok(values)
                })
                // A table this cannot read must fail loudly here rather than be
                // silently left out of the comparison.
                .unwrap_or_else(|err| panic!("the state check cannot digest table {table}: {err}"));

            // Sorted in Rust, duplicates kept: the comparison does not depend
            // on SQL row order.
            let mut encoded: Vec<Vec<u8>> = rows.iter().map(|row| encode_row(row)).collect();
            encoded.sort();

            let mut bytes = Vec::new();
            push_len_prefixed(&mut bytes, table.as_bytes());
            bytes.extend_from_slice(&(columns.len() as u64).to_be_bytes());
            for column in &columns {
                push_len_prefixed(&mut bytes, column.as_bytes());
            }
            bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
            for row in &encoded {
                push_len_prefixed(&mut bytes, row);
            }
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let digest: [u8; 32] = hasher.finalize().into();
            digests.insert(
                table,
                serde_json::Value::String(digest.iter().map(|b| format!("{b:02x}")).collect()),
            );
        }

        let revision: Option<String> = conn
            .query_opt_map(
                "SELECT value FROM meta WHERE key = 'source_facts_revision'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("meta read");
        println!(
            "{STATE_MARKER}{}",
            serde_json::json!({ "tables": digests, "revision": revision })
        );
    }

    /// Open the given database in a **new process** and read back the state
    /// that a fresh process can see.
    fn persisted_state_in_a_new_process(path: &Path) -> serde_json::Value {
        let exe = std::env::current_exe().expect("current test executable");
        let output = std::process::Command::new(exe)
            // `--exact` needs the full path, module included.
            .args(["--exact", "activation::child_reports_persisted_state", "--nocapture"])
            .env(VERIFY_DB_ENV, path)
            .output()
            .expect("spawn the verifying child process");
        assert!(
            output.status.success(),
            "the child process failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout
            .lines()
            .find_map(|line| line.strip_prefix(STATE_MARKER))
            .expect("the child printed its state line");
        serde_json::from_str(line).expect("the child's state line is JSON")
    }

    /// Perform the work up to `point`, leaving the caller to abort.
    fn run_to(tx: &Tx<'_>, point: InjectionPoint) -> Result<(), StorageError> {
        let input = verified_input();
        let mut scan = FramingScan::new(SEALED, SourceFormat::Jsonl);
        let frames = scan.next_page(16).map_err(storage_err)?;
        let records: Vec<VerifiedStagedRecord> = frames
            .iter()
            .map(|frame| {
                VerifiedStagedRecord::from_frame(
                    frame,
                    Some(*frame.raw_sha256()),
                    ParseState::Parsed,
                    RecordMappingState::AllCanonical,
                    SafetyState::Preserved,
                    None,
                    None,
                    None,
                )
            })
            .collect();

        // Point 1: only a partial staging page has been written.
        let page = match point {
            InjectionPoint::DuringStaging => &records[..1],
            _ => &records[..],
        };
        let staged =
            stage_source_records_in_tx(tx, &input, page).map_err(storage_err)?;
        if matches!(point, InjectionPoint::AfterFrameRegistration) {
            return Ok(());
        }

        // Point 2: the reader has marked the frames staged.
        tx.execute(
            "UPDATE source_records SET frame_state = 'staged' WHERE input_id = ?1",
            &[Value::Integer(staged.input_id)],
        )?;
        if matches!(point, InjectionPoint::DuringStaging | InjectionPoint::BeforeWitness) {
            return Ok(());
        }

        // Point 3: the witnesses are installed. This test's preamble already
        // installed one, and re-installing it must be the same witness, so the
        // digest comes from the stored row rather than from the re-staged A side.
        let (conversation_id, message_id) = create_conversation_and_message(tx);
        let digest = stored_witness_request_digest(tx, staged.input_id)
            .unwrap_or_else(|| request_semantic_digest_for(tx, &input, staged.input_id));
        let claim = canonical_claim(input.input_key());
        let pending = install_source_links_in_tx(
            tx,
            staged.input_id,
            &[ClaimLinkInstall {
                claim: claim.clone(),
                installation: None,
            }],
        );
        if let Err(err) = &pending {
            assert!(
                matches!(err, SourceInstallError::Conflict { .. }),
                "staging the claim failed: {err:?}"
            );
        }
        let installed = install_source_links_in_tx(
            tx,
            staged.input_id,
            &[ClaimLinkInstall {
                claim,
                installation: Some(canonical_installation(conversation_id, message_id, digest)),
            }],
        );
        installed.map_err(storage_err)?;
        if matches!(point, InjectionPoint::AfterWitness) {
            return Ok(());
        }

        // Point 4: the whole activation body runs inside this transaction. The
        // outcome is printed so an injected failure at an internal boundary is
        // visible in the run log as having actually been hit.
        let request = activation_request(tx, &input, staged.input_id);
        let outcome = activate_source_input_in_tx(tx, &request, input.manifest());
        println!("SRC05A_ACTIVATION_OUTCOME {outcome:?}");
        outcome.map_err(storage_err)?;
        Ok(())
    }

    /// Stage both frames *with a payload* and hand them to the reader's stage.
    /// This is the "already staged page" a later failure has to leave alone.
    fn stage_a_recoverable_page(tx: &Tx<'_>, input: &VerifiedSourceInput) -> i64 {
        let mut scan = FramingScan::new(SEALED, SourceFormat::Jsonl);
        let frames = scan.next_page(16).expect("scan");
        let records: Vec<VerifiedStagedRecord> = frames
            .iter()
            .enumerate()
            .map(|(index, frame)| {
                VerifiedStagedRecord::from_frame(
                    frame,
                    Some(*frame.raw_sha256()),
                    ParseState::Parsed,
                    RecordMappingState::AllCanonical,
                    SafetyState::Preserved,
                    None,
                    Some(
                        LosslessSourceValue::parse(format!("{{\"record\":{index}}}").as_bytes())
                            .expect("payload json"),
                    ),
                    None,
                )
            })
            .collect();
        let staged = stage_source_records_in_tx(tx, input, &records).expect("stage");
        tx.execute(
            "UPDATE source_records SET frame_state = 'staged' WHERE input_id = ?1",
            &[Value::Integer(staged.input_id)],
        )
        .expect("reader stage");
        staged.input_id
    }

    #[test]
    fn the_state_snapshot_is_lossless_across_types_and_embedded_nul() {
        let dir = scratch_dir("snapshot-lossless");
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();
        conn.execute_batch("CREATE TABLE type_probe (v);").expect("probe table");

        let digest = |conn: &Conn| -> String {
            persisted_state_in_a_new_process(&path)["tables"]["type_probe"]
                .as_str()
                .expect("probe table digest")
                .to_string()
        };

        // Two texts that differ only after an embedded NUL. SQLite's `quote()`
        // renders both as `'prefix'`, so a quote-based projection would call
        // them equal and report no change.
        conn.execute(
            "INSERT INTO type_probe (v) VALUES (?1)",
            &[Value::Text("prefix\u{0}A".to_string())],
        )
        .expect("write the first NUL-suffixed text");
        let nul_a = digest(&conn);
        conn.execute(
            "UPDATE type_probe SET v = ?1",
            &[Value::Text("prefix\u{0}B".to_string())],
        )
        .expect("write the second NUL-suffixed text");
        let nul_b = digest(&conn);
        assert_ne!(
            nul_a, nul_b,
            "a change after an embedded NUL must change the snapshot"
        );

        // The same bytes stored as TEXT and as BLOB are different values.
        conn.execute(
            "UPDATE type_probe SET v = ?1",
            &[Value::Text("abc".to_string())],
        )
        .expect("write the text form");
        let as_text = digest(&conn);
        conn.execute(
            "UPDATE type_probe SET v = ?1",
            &[Value::Blob(b"abc".to_vec())],
        )
        .expect("write the blob form");
        let as_blob = digest(&conn);
        assert_ne!(
            as_text, as_blob,
            "the same bytes as TEXT and as BLOB must not collide"
        );
    }

    #[test]
    fn the_state_snapshot_distinguishes_adjacent_representable_f64() {
        let dir = scratch_dir("snapshot-f64");
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();
        conn.execute_batch("CREATE TABLE real_probe (v);").expect("probe table");

        let digest = |conn: &Conn| -> String {
            persisted_state_in_a_new_process(&path)["tables"]["real_probe"]
                .as_str()
                .expect("probe table digest")
                .to_string()
        };

        conn.execute("INSERT INTO real_probe (v) VALUES (?1)", &[Value::Real(1.0)])
            .expect("write 1.0");
        let one = digest(&conn);

        // The next representable double above 1.0. `CAST(... AS BLOB)` renders
        // both as "1.0" and `typeof` calls both "real", so only the bits tell
        // them apart.
        let neighbour = f64::from_bits(1.0_f64.to_bits() + 1);
        assert_ne!(neighbour, 1.0, "the neighbour really is a different double");
        conn.execute("UPDATE real_probe SET v = ?1", &[Value::Real(neighbour)])
            .expect("write the neighbour");
        let other = digest(&conn);

        assert_ne!(
            one, other,
            "two adjacent representable doubles must not collide in the snapshot"
        );
    }

    #[test]
    fn a_failure_at_every_expressible_point_leaves_every_table_for_a_new_process() {
        for point in [
            InjectionPoint::AfterFrameRegistration,
            InjectionPoint::DuringStaging,
            InjectionPoint::BeforeWitness,
            InjectionPoint::AfterWitness,
            InjectionPoint::DuringActivation,
        ] {
            let dir = scratch_dir(&format!("inject-{point:?}"));
            let path = dir.join("agent_search.db");
            let storage = open_fresh_db(&path);
            let conn = storage.raw();

            // A page that is already staged and payload-carrying, committed
            // before the doomed attempt: recovery means it survives intact.
            let staged_input_id = conn
                .with_tx(TxMode::Immediate, |tx| {
                    let input = verified_input();
                    let input_id = stage_a_recoverable_page(tx, &input);
                    let (conversation_id, message_id) = create_conversation_and_message(tx);
                    tx.execute(
                        "INSERT INTO snippets (message_id, file_path, start_line, end_line, language, snippet_text) \
                             VALUES (?1, '/tmp/f.rs', 1, 2, 'rust', 'fn main() {}')",
                        &[Value::Integer(message_id)],
                    )?;
                    install_canonical_witness(
                        tx,
                        &input,
                        input_id,
                        canonical_claim(input.input_key()),
                        conversation_id,
                        message_id,
                    );
                    Ok(input_id)
                })
                .expect("the pre-existing staged page commits");

            let before = persisted_state_in_a_new_process(&path);
            assert_eq!(
                before["tables"]["source_records"].as_str().map(str::len),
                Some(64),
                "the snapshot must actually cover the staged rows"
            );

            let aborted = conn.with_tx(TxMode::Immediate, |tx| {
                run_to(tx, point)?;
                Err::<(), StorageError>(StorageError::Other {
                    code: None,
                    detail: format!("injected failure at {point:?}"),
                })
            });
            assert!(aborted.is_err(), "the transaction was asked to abort at {point:?}");

            let after = persisted_state_in_a_new_process(&path);
            assert_eq!(
                before, after,
                "an aborted transaction at {point:?} left a table changed in a way a new process can see"
            );

            // And the pre-existing page is still there, still staged, still
            // carrying its payload.
            let (staged_rows, with_payload): (i64, i64) = conn
                .query_row_map(
                    "SELECT COUNT(*), SUM(payload_bin IS NOT NULL) FROM source_records WHERE input_id = ?1",
                    &[Value::Integer(staged_input_id)],
                    |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
                )
                .expect("re-read the staged page");
            assert_eq!(staged_rows, 2, "the staged page must still be there");
            assert_eq!(with_payload, 2, "its payloads must still be recoverable");
        }
    }

    #[test]
    fn the_same_final_message_idx_in_two_conversations_stays_separate() {
        let dir = scratch_dir("same-idx-two-conversations");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();

        conn.with_tx(TxMode::Immediate, |tx| {
            let input = verified_input();
            let input_id = stage_and_mark_reader_processed(tx, &input);
            let (first_conversation, first_message) = create_conversation_and_message(tx);
            // A second conversation whose first message also carries idx 0.
            tx.execute_batch(
                "INSERT INTO conversations (id, agent_id, source_id, source_path, identity_host) \
                     VALUES (2, 1, 'local', '/tmp/session-2.jsonl', 'local');
                 INSERT INTO messages (id, conversation_id, idx, role, content) \
                     VALUES (8, 2, 0, 'user', 'hello again');",
            )?;

            let mut second_claim = canonical_claim(input.input_key());
            second_claim.conversation_ordinal = Some(1);
            second_claim.projection_pointer = Some("/messages/1".to_string());
            install_witnesses(
                tx,
                &input,
                input_id,
                &[
                    (canonical_claim(input.input_key()), first_conversation, first_message),
                    (second_claim, 2, 8),
                ],
            );

            // Both rows exist, each pointing at its own conversation's message,
            // and neither was cross-wired onto the other.
            let rows: Vec<(i64, i64, i64)> = tx.query_all_map(
                "SELECT conversation_ordinal, final_message_idx, message_id
                 FROM source_message_links ORDER BY conversation_ordinal",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
            )?;
            assert_eq!(rows, vec![(0, 0, first_message), (1, 0, 8)]);
            let distinct_keys: i64 = tx.query_row_map(
                "SELECT COUNT(DISTINCT projection_key) FROM source_message_links",
                &[],
                |row| row.get_typed(0),
            )?;
            assert_eq!(distinct_keys, 2);
            Ok(())
        })
        .expect("two conversations may share one incoming idx");
    }

    #[test]
    fn a_parse_failed_record_keeps_its_claim_and_diagnostics_and_cannot_complete() {
        let dir = scratch_dir("parse-failed");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();

        conn.with_tx(TxMode::Immediate, |tx| {
            let input = verified_input();
            let mut scan = FramingScan::new(SEALED, SourceFormat::Jsonl);
            let frames = scan.next_page(16).map_err(storage_err)?;
            let records = vec![
                VerifiedStagedRecord::from_frame(
                    &frames[0],
                    Some(*frames[0].raw_sha256()),
                    ParseState::ParseFailed,
                    RecordMappingState::AllUnmapped,
                    SafetyState::Preserved,
                    None,
                    None,
                    Some(vec![SafeDiagnostic {
                        code: "bad_json".to_string(),
                        detail: None,
                        offset: Some(3),
                        position: None,
                    }]),
                ),
                VerifiedStagedRecord::from_frame(
                    &frames[1],
                    Some(*frames[1].raw_sha256()),
                    ParseState::Parsed,
                    RecordMappingState::AllCanonical,
                    SafetyState::Preserved,
                    None,
                    None,
                    None,
                ),
            ];
            let staged = stage_source_records_in_tx(tx, &input, &records).map_err(storage_err)?;
            tx.execute(
                "UPDATE source_records SET frame_state = 'staged' WHERE input_id = ?1",
                &[Value::Integer(staged.input_id)],
            )?;
            let (conversation_id, message_id) = create_conversation_and_message(tx);
            let claim = canonical_claim(input.input_key());
            install_source_links_in_tx(
                tx,
                staged.input_id,
                &[ClaimLinkInstall {
                    claim: claim.clone(),
                    installation: None,
                }],
            )
            .map_err(storage_err)?;

            let mut request = activation_request(tx, &input, staged.input_id);
            // The reader measured one parse failure against the same input, so
            // the witness has to be bound to the request that records it.
            request.finish.parse_failed = 1;
            let digest =
                request_semantic_digest_with(
                    tx,
                    &input,
                    staged.input_id,
                    &request.finish,
                    request.projection_disposition,
                );
            install_source_links_in_tx(
                tx,
                staged.input_id,
                &[ClaimLinkInstall {
                    claim,
                    installation: Some(canonical_installation(
                        conversation_id,
                        message_id,
                        digest,
                    )),
                }],
            )
            .map_err(storage_err)?;

            let outcome =
                activate_source_input_in_tx(tx, &request, input.manifest()).map_err(storage_err)?;
            assert!(
                !matches!(outcome, SourceActivationOutcome::Activated { .. }),
                "a parse failure must not produce a success receipt, got {outcome:?}"
            );
            assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("0"));
            assert_eq!(meta(tx, "source_content_generation"), None);

            let (parse_state, diagnostics): (String, Option<Vec<u8>>) = tx.query_row_map(
                "SELECT parse_state, diagnostics_bin FROM source_records
                 WHERE input_id = ?1 AND ordinal = ?2",
                &[Value::Integer(staged.input_id), Value::Blob(vec![0, 0, 0, 0, 0, 0, 0, 1])],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )?;
            assert_eq!(parse_state, "parse_failed");
            assert!(
                diagnostics.is_some(),
                "the diagnostics envelope must survive the refused activation"
            );
            let links: i64 = tx.query_row_map(
                "SELECT COUNT(*) FROM source_message_links",
                &[],
                |row| row.get_typed(0),
            )?;
            assert_eq!(links, 1, "the claim must survive the refused activation");

            // The same identity repeated is still not a success.
            let again =
                activate_source_input_in_tx(tx, &request, input.manifest()).map_err(storage_err)?;
            assert!(
                !matches!(
                    again,
                    SourceActivationOutcome::Activated { .. } | SourceActivationOutcome::Replay { .. }
                ),
                "repeating a refused activation must not become a success, got {again:?}"
            );
            Ok(())
        })
        .expect("parse-failed transaction");
    }

    #[test]
    fn a_rolled_back_activation_leaves_no_trace() {
        let dir = scratch_dir("rollback");
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();

        let request = conn
            .with_tx(TxMode::Immediate, |tx| {
                let (_input, _input_id, request) = prepare(tx);
                Ok(request)
            })
            .expect("preparation transaction");

        // Run the activation on a transaction that is dropped without commit.
        {
            let storage = open_fresh_db(&path);
            let conn = storage.raw();
            let tx = conn.transaction().expect("open a transaction");
            let input = verified_input();
            let outcome = activate_source_input_in_tx(&tx, &request, input.manifest())
                .expect("activation inside the doomed transaction");
            assert!(matches!(outcome, SourceActivationOutcome::Activated { .. }));
            drop(tx);
        }

        let storage = open_fresh_db(&path);
        let conn = storage.raw();
        let revision: Option<String> = conn
            .query_opt_map(
                "SELECT value FROM meta WHERE key = 'source_facts_revision'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("meta read");
        assert_eq!(revision.as_deref(), Some("0"), "a rollback must not move the revision");
        let receipts: i64 = conn
            .query_row_map("SELECT COUNT(*) FROM operation_commit_receipt", &[], |row| {
                row.get_typed(0)
            })
            .expect("receipt count");
        assert_eq!(receipts, 0);
    }

    // -----------------------------------------------------------------------
    // §9/§15#15: the real same-`idx` conflict branch
    // -----------------------------------------------------------------------

    /// The conversation the projection merges into: one message at `idx` with
    /// `content` and `created_at`. The started-at and path fix the merge key, so
    /// two of these with the same `created_at` address the same parent row.
    fn projection_conversation(idx: i64, content: &str, created_at: i64) -> Conversation {
        Conversation {
            id: None,
            agent_slug: "claude".to_string(),
            workspace: None,
            external_id: None,
            title: None,
            source_path: std::path::PathBuf::from("/tmp/source-conflict.jsonl"),
            started_at: Some(created_at),
            ended_at: None,
            approx_tokens: None,
            metadata_json: serde_json::json!({}),
            messages: vec![Message {
                id: None,
                idx,
                role: MessageRole::User,
                author: None,
                created_at: Some(created_at),
                content: content.to_string(),
                extra_json: serde_json::Value::Null,
                snippets: Vec::new(),
                excluded: None,
            }],
            source_id: "local".to_string(),
            origin_host: None,
        }
    }

    #[test]
    fn a_real_same_idx_conflict_produces_a_winner_rejection_installation() {
        let dir = scratch_dir("real-winner-rejection");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        let input = verified_input();
        let input_key = *input.input_key();

        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute_batch(
                "INSERT INTO agents (id, slug, name, kind, created_at, updated_at)
                     VALUES (1, 'claude', 'Claude', 'agent', 0, 0);",
            )?;

            // The winner: the first projection installs idx 0 with this content.
            let first = storage
                .install_conversation_projection_in_tx(
                    tx,
                    1,
                    None,
                    &projection_conversation(0, "the winner", 1),
                    &input_key,
                    0,
                    &[],
                )
                .map_err(storage_err)?;
            assert_eq!(first.incoming.len(), 1);
            assert_eq!(first.incoming[0].status, IncomingStatus::AcceptedNew);

            // The loser: same idx, other content. The merge keeps the winner, and
            // that is the branch §9 wants proof of.
            let claim = canonical_claim(&input_key);
            let second = storage
                .install_conversation_projection_in_tx(
                    tx,
                    1,
                    None,
                    &projection_conversation(0, "a different message", 1),
                    &input_key,
                    0,
                    std::slice::from_ref(&claim),
                )
                .map_err(storage_err)?;
            assert_eq!(second.incoming[0].status, IncomingStatus::Rejected);
            assert_eq!(
                second.incoming[0].reason,
                Some(ReplayRejectReason::WinnerRejected)
            );
            assert!(second.incoming[0].stored.is_none());

            let installation = second
                .installation_for_claim(&claim, Sha256Digest::of(b"request"))
                .expect("the projection proved the branch, so it owes a witness");
            assert_eq!(installation.class, InstallationClass::WinnerRejectedNoBinding);
            assert!(installation.binding.is_none());
            let rejection = installation.rejection.as_ref().expect("a rejection witness");
            // §9's claim digest is the frozen pending-claim digest exactly
            // (`SHA256(J(["cass.source-pending-claim/1", claim_leaf]))`, §150/§19).
            // Composed here from the claim leaf so the assertion checks the
            // formula rather than restating the helper's own answer.
            let leaf = claim.encode_leaf();
            let mut expected_bytes = Vec::new();
            expected_bytes.extend_from_slice(br#"["cass.source-pending-claim/1","#);
            expected_bytes.extend_from_slice(&leaf);
            expected_bytes.push(b']');
            let expected_digest: [u8; 32] = Sha256::digest(&expected_bytes).into();
            assert_eq!(
                rejection.claim_digest.as_bytes(),
                &expected_digest,
                "the claim digest must be the contract's pending-claim digest"
            );
            assert_eq!(rejection.claim_digest, claim.pending_claim_digest());
            // A frozen gold over the whole canonical rejection tuple, so a
            // change to either the claim digest, the identity digest or the two
            // fingerprints trips here and not only in the field assertions.
            let encoded = rejection.encode();
            let mut ends = Vec::new();
            ends.extend_from_slice(
                br#","cass.merge-existing-idx/1","existing_idx_conflict"]"#,
            );
            assert!(
                encoded.ends_with(&ends),
                "the canonical tuple must end with §9's fixed domain and reason"
            );
            assert!(
                encoded.starts_with(br#"["cass.source-winner-rejection/1","#),
                "the canonical tuple must start with §9's domain"
            );
            assert!(
                encoded
                    .windows(rejection.claim_digest.hex().len())
                    .any(|window| window == rejection.claim_digest.hex().as_bytes()),
                "the tuple must spell the claim digest in full"
            );
            // The whole canonical tuple, spelled out from §9's field list, so
            // the check covers field order, spelling and the nested fingerprint
            // arrays rather than only the values this test already asserted.
            let quote = |text: &str| format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""));
            // §4/§20.3: integers inside a canonical tuple are decimal strings.
            let decimal = |value: i64| quote(&value.to_string());
            let optional_decimal = |value: Option<i64>| {
                value.map_or_else(|| "null".to_string(), decimal)
            };
            let fingerprint = |value: &MergeFingerprint| {
                format!(
                    "[{},{},{},{},{}]",
                    decimal(value.idx),
                    optional_decimal(value.created_at),
                    quote(&value.role),
                    value.author.as_deref().map_or_else(|| "null".to_string(), quote),
                    quote(&value.content_blake3_hex)
                )
            };
            let expected_tuple = format!(
                "[\"cass.source-winner-rejection/1\",{},{},{},{},{},{},{},{},\
                 \"cass.merge-existing-idx/1\",\"existing_idx_conflict\"]",
                quote(&rejection.claim_digest.hex()),
                quote(&rejection.conversation_identity_digest.hex()),
                decimal(rejection.incoming_idx),
                fingerprint(&rejection.incoming_merge_fingerprint),
                decimal(rejection.winner_conversation_id),
                decimal(rejection.winner_message_id),
                decimal(rejection.winner_idx),
                fingerprint(&rejection.winner_merge_fingerprint),
            );
            assert_eq!(
                String::from_utf8(encoded).expect("the canonical tuple is UTF-8"),
                expected_tuple,
                "the canonical rejection tuple must match §9's field list exactly"
            );
            assert_eq!(
                rejection.conversation_identity_digest,
                second.conversation_identity_digest
            );
            assert_eq!(rejection.incoming_idx, 0);
            assert_eq!(rejection.winner_idx, 0);
            assert_eq!(rejection.winner_conversation_id, second.conversation_id);
            assert_ne!(
                rejection.incoming_merge_fingerprint, rejection.winner_merge_fingerprint,
                "the witness must record both fingerprints, and they must differ"
            );

            // The winner is the row the witness names, and it is still there.
            let (winner_id, winner_content): (i64, String) = tx.query_row_map(
                "SELECT id, content FROM messages WHERE conversation_id = ?1 AND idx = 0",
                &[Value::Integer(second.conversation_id)],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )?;
            assert_eq!(winner_content, "the winner", "the conflict must not overwrite the winner");
            assert_eq!(rejection.winner_message_id, winner_id);

            // The join is by the claim's own frozen digest, so a claim whose
            // pointer or position moved is a different claim and gets no witness.
            let mut moved_pointer = canonical_claim(&input_key);
            moved_pointer.projection_pointer = Some("/messages/9".to_string());
            assert!(
                second
                    .installation_for_claim(&moved_pointer, Sha256Digest::of(b"request"))
                    .is_none(),
                "a different projection pointer must not inherit the witness"
            );
            let mut moved_ordinal = canonical_claim(&input_key);
            moved_ordinal.record_ordinal = 0;
            assert!(
                second
                    .installation_for_claim(&moved_ordinal, Sha256Digest::of(b"request"))
                    .is_none(),
                "a different record locator must not inherit the witness"
            );
            let mut moved_idx = canonical_claim(&input_key);
            moved_idx.final_message_idx = Some(5);
            assert!(
                second
                    .installation_for_claim(&moved_idx, Sha256Digest::of(b"request"))
                    .is_none(),
                "a claim naming another position must not inherit the witness"
            );
            Ok(())
        })
        .expect("the real conflict transaction");
        let _ = input;
    }

    /// The negative half of §9: an equal fingerprint is a replay, not a
    /// rejection, and it binds canonically.
    #[test]
    fn a_same_idx_message_with_the_same_fingerprint_is_a_verified_replay() {
        let dir = scratch_dir("real-same-fingerprint");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        let input = verified_input();
        let input_key = *input.input_key();

        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute_batch(
                "INSERT INTO agents (id, slug, name, kind, created_at, updated_at)
                     VALUES (1, 'claude', 'Claude', 'agent', 0, 0);",
            )?;
            let first = storage
                .install_conversation_projection_in_tx(
                    tx,
                    1,
                    None,
                    &projection_conversation(0, "the winner", 1),
                    &input_key,
                    0,
                    &[],
                )
                .map_err(storage_err)?;
            assert_eq!(first.incoming[0].status, IncomingStatus::AcceptedNew);

            let claim = canonical_claim(&input_key);
            let second = storage
                .install_conversation_projection_in_tx(
                    tx,
                    1,
                    None,
                    &projection_conversation(0, "the winner", 1),
                    &input_key,
                    0,
                    std::slice::from_ref(&claim),
                )
                .map_err(storage_err)?;
            assert_eq!(second.incoming[0].status, IncomingStatus::VerifiedReplay);
            assert!(second.incoming[0].reason.is_none());
            assert!(second.winner_rejection_for_claim(&claim).is_none());

            let installation = second
                .installation_for_claim(&claim, Sha256Digest::of(b"request"))
                .expect("a replay binds canonically");
            assert_eq!(installation.class, InstallationClass::CanonicalBound);
            let binding = installation.binding.expect("a binding");
            assert_eq!(binding.outcome, OriginalBindingOutcome::VerifiedReplay);
            assert_eq!(
                binding.stored_idx, 0,
                "the bound row is the one this `idx` already held"
            );
            Ok(())
        })
        .expect("the replay transaction");
        let _ = input;
    }

    /// §9: the identity digest comes from the parent row this transaction
    /// merged into, not from the caller's `Conversation`. The second call names
    /// the same parent by external id but reports a different source path, so a
    /// digest taken from the caller would disagree with the row.
    #[test]
    fn the_identity_digest_tracks_the_resolved_parent_row_not_the_caller() {
        let dir = scratch_dir("identity-from-the-row");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        let input = verified_input();
        let input_key = *input.input_key();

        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute_batch(
                "INSERT INTO agents (id, slug, name, kind, created_at, updated_at)
                     VALUES (1, 'claude', 'Claude', 'agent', 0, 0);",
            )?;
            let first = storage
                .install_conversation_projection_in_tx(
                    tx,
                    1,
                    None,
                    &projection_conversation(0, "the winner", 1),
                    &input_key,
                    0,
                    &[],
                )
                .map_err(storage_err)?;
            assert_eq!(first.incoming[0].status, IncomingStatus::AcceptedNew);
            // The parent row gains an external id from elsewhere. The caller
            // still identifies it by source path and knows nothing about it, so
            // a digest taken from the caller now disagrees with the row.
            tx.execute(
                "UPDATE conversations SET external_id = 'ext-from-the-row' WHERE id = ?1",
                &[Value::Integer(first.conversation_id)],
            )?;

            let claim = canonical_claim(&input_key);
            let second = storage
                .install_conversation_projection_in_tx(
                    tx,
                    1,
                    None,
                    &projection_conversation(0, "the loser", 1),
                    &input_key,
                    0,
                    std::slice::from_ref(&claim),
                )
                .map_err(storage_err)?;
            assert_eq!(second.conversation_id, first.conversation_id);
            assert_eq!(second.incoming[0].status, IncomingStatus::Rejected);

            let (library_identity, identity_host, agent_id, external_id, source_path): (
                String,
                String,
                i64,
                Option<String>,
                String,
            ) = {
                let library_identity: String = tx.query_row_map(
                    "SELECT value FROM meta WHERE key = 'library_identity'",
                    &[],
                    |row| row.get_typed(0),
                )?;
                let row: (String, i64, Option<String>, String) = tx.query_row_map(
                    "SELECT identity_host, agent_id, external_id, source_path
                     FROM conversations WHERE id = ?1",
                    &[Value::Integer(second.conversation_id)],
                    |row| {
                        Ok((
                            row.get_typed(0)?,
                            row.get_typed(1)?,
                            row.get_typed(2)?,
                            row.get_typed(3)?,
                        ))
                    },
                )?;
                (library_identity, row.0, row.1, row.2, row.3)
            };
            assert_eq!(
                external_id.as_deref(),
                Some("ext-from-the-row"),
                "the row is the thing that carries the external id"
            );

            let from_the_row = coding_agent_search::storage::source_facts::conversation_identity_digest(
                &library_identity,
                second.conversation_id,
                &identity_host,
                agent_id,
                external_id.as_deref(),
                &source_path,
            );
            // What the caller's own `Conversation` alone would have produced.
            let from_the_caller =
                coding_agent_search::storage::source_facts::conversation_identity_digest(
                    &library_identity,
                    second.conversation_id,
                    &identity_host,
                    agent_id,
                    None,
                    &source_path,
                );
            assert_ne!(
                from_the_row, from_the_caller,
                "the fixture must distinguish the two sources, or it proves nothing"
            );
            assert_eq!(second.conversation_identity_digest, from_the_row);
            assert_eq!(
                second
                    .winner_rejection_for_claim(&claim)
                    .expect("a witness")
                    .conversation_identity_digest,
                from_the_row
            );
            Ok(())
        })
        .expect("the parent-identity transaction");
        let _ = input;
    }

    /// §6/§8: a claim the reader staged as not-yet-installed carries the
    /// pending-claim digest and a NULL authority. Its first real installation
    /// must be accepted; the witness is immutable only *after* that.
    #[test]
    fn a_staged_pending_claim_installs_on_its_first_real_installation() {
        let dir = scratch_dir("pending-installation");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        let input = verified_input();
        let input_key = *input.input_key();

        let (conversation_id, message_id) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let input_id = stage_and_mark_reader_processed(tx, &input);
                let (conversation_id, message_id) = create_conversation_and_message(tx);
                let claim = canonical_claim(&input_key);
                install_source_links_in_tx(
                    tx,
                    input_id,
                    &[ClaimLinkInstall {
                        claim: claim.clone(),
                        installation: None,
                    }],
                )
                .map_err(storage_err)?;
                // Staged, not installed: no authority, no live message, and the
                // row holds the pending-claim digest.
                let (authority, live): (Option<String>, Option<i64>) = tx.query_row_map(
                    "SELECT authority, message_id FROM source_message_links",
                    &[],
                    |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
                )?;
                assert!(authority.is_none() && live.is_none());
                let stored: Vec<u8> = tx.query_row_map(
                    "SELECT binding_digest FROM source_message_links",
                    &[],
                    |row| row.get_typed(0),
                )?;
                assert_eq!(stored, claim.pending_claim_digest().as_bytes().to_vec());
                Ok((conversation_id, message_id))
            })
            .expect("the staging transaction");

        conn.with_tx(TxMode::Immediate, |tx| {
            let input_id: i64 =
                tx.query_row_map("SELECT id FROM source_inputs", &[], |row| row.get_typed(0))?;
            let outcome = install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: canonical_claim(&input_key),
                    installation: Some(canonical_installation(conversation_id, message_id, install_only_digest())),
                }],
            )
            .map_err(storage_err)?;
            assert_eq!(outcome.inserted, 1, "the first real installation installs");
            let (authority, live): (Option<String>, Option<i64>) = tx.query_row_map(
                "SELECT authority, message_id FROM source_message_links",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )?;
            assert_eq!(authority.as_deref(), Some("canonical"));
            assert_eq!(live, Some(message_id));
            Ok(())
        })
        .expect("the first installation of a staged claim");

        // Once installed, the witness is immutable: the pending form is refused,
        // never written back over a real installation.
        conn.with_tx(TxMode::Immediate, |tx| {
            let input_id: i64 =
                tx.query_row_map("SELECT id FROM source_inputs", &[], |row| row.get_typed(0))?;
            let refused = install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: canonical_claim(&input_key),
                    installation: None,
                }],
            );
            let err = refused.expect_err("a bound witness cannot go back to pending");
            assert!(
                matches!(err, SourceInstallError::Conflict { .. }),
                "expected Conflict, got {err:?}"
            );
            Ok(())
        })
        .expect("the refused downgrade");
    }

    /// The negative half of the pending upgrade: only *this* claim's own intact
    /// pending form may be replaced, and a damaged envelope is never quietly
    /// rewritten.
    #[test]
    fn a_pending_claim_is_upgraded_only_when_its_own_pending_form_is_intact() {
        let dir = scratch_dir("pending-upgrade-negatives");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        let input = verified_input();
        let input_key = *input.input_key();

        let (conversation_id, message_id) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let input_id = stage_and_mark_reader_processed(tx, &input);
                let (conversation_id, message_id) = create_conversation_and_message(tx);
                install_source_links_in_tx(
                    tx,
                    input_id,
                    &[ClaimLinkInstall {
                        claim: canonical_claim(&input_key),
                        installation: None,
                    }],
                )
                .map_err(storage_err)?;
                Ok((conversation_id, message_id))
            })
            .expect("the staging transaction");

        // A claim that shares the projection key but is not the stored claim:
        // same record, same target, different safe positions, so a different
        // pending digest.
        conn.with_tx(TxMode::Immediate, |tx| {
            let input_id: i64 =
                tx.query_row_map("SELECT id FROM source_inputs", &[], |row| row.get_typed(0))?;
            let mut other = canonical_claim(&input_key);
            other.positions = vec![SafePosition {
                index_path: vec![IndexStep::ArrayElement(9)],
                original_pointer_sha256: Sha256Digest::of(b"elsewhere"),
                safe_pointer: Some("/messages/9".to_string()),
            }];
            assert_ne!(
                other.pending_claim_digest(),
                canonical_claim(&input_key).pending_claim_digest(),
                "the fixture must be a different claim"
            );
            let err = install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: other,
                    installation: Some(canonical_installation(conversation_id, message_id, install_only_digest())),
                }],
            )
            .expect_err("only the stored claim's own pending form may be replaced");
            assert!(
                matches!(err, SourceInstallError::Conflict { .. }),
                "expected Conflict, got {err:?}"
            );
            Ok(())
        })
        .expect("the wrong-claim refusal");

        // A damaged stored envelope is Corrupt and is left exactly as it was.
        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute(
                "UPDATE source_message_links SET source_positions_bin = X'00'",
                &[],
            )?;
            Ok(())
        })
        .expect("damage the stored envelope");

        conn.with_tx(TxMode::Immediate, |tx| {
            let input_id: i64 =
                tx.query_row_map("SELECT id FROM source_inputs", &[], |row| row.get_typed(0))?;
            let err = install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: canonical_claim(&input_key),
                    installation: Some(canonical_installation(conversation_id, message_id, install_only_digest())),
                }],
            )
            .expect_err("a damaged pending envelope must not be repaired");
            assert!(
                matches!(err, SourceInstallError::Corrupt { .. }),
                "expected Corrupt, got {err:?}"
            );
            let (positions, authority): (Vec<u8>, Option<String>) = tx.query_row_map(
                "SELECT source_positions_bin, authority FROM source_message_links",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )?;
            assert_eq!(positions, vec![0u8], "the damaged bytes must stay as they are");
            assert!(authority.is_none(), "nothing may be installed from a damaged row");
            Ok(())
        })
        .expect("the damaged-envelope refusal");
    }

    /// §9/§571: every branch reads the stored row back before trusting it. A
    /// digest column that happens to match, a damaged envelope and a drifted SQL
    /// column are all refused, and none of them may change the database.
    #[test]
    fn a_link_install_reads_back_the_stored_row_before_trusting_it() {
        let dir = scratch_dir("link-readback");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        let input = verified_input();
        let input_key = *input.input_key();

        let (conversation_id, message_id) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let input_id = stage_and_mark_reader_processed(tx, &input);
                let (conversation_id, message_id) = create_conversation_and_message(tx);
                install_source_links_in_tx(
                    tx,
                    input_id,
                    &[ClaimLinkInstall {
                        claim: canonical_claim(&input_key),
                        installation: None,
                    }],
                )
                .map_err(storage_err)?;
                Ok((conversation_id, message_id))
            })
            .expect("the staging transaction");

        let link_rows = |conn: &Conn| -> Vec<Vec<Value>> {
            conn.query_all_map(
                "SELECT source_positions_bin, authority, message_id, binding_digest,
                        conversation_ordinal, final_message_idx, projection_pointer, evidence_kind
                 FROM source_message_links ORDER BY projection_key",
                &[],
                |row| {
                    let mut values = Vec::new();
                    for index in 0..8 {
                        values.push(row.get_value(index)?);
                    }
                    Ok(values)
                },
            )
            .expect("read the link rows")
        };

        let input_id: i64 = conn
            .query_row_map("SELECT id FROM source_inputs", &[], |row| row.get_typed(0))
            .expect("the staged input id");
        let baseline = link_rows(conn);

        // 1. A claim that belongs to another input is refused before any row is
        //    touched: the record lookup must not bind across inputs.
        let other_key = *verified_input_for(SEALED_R2).input_key();
        conn.with_tx(TxMode::Immediate, |tx| {
            let stranger = install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: canonical_claim(&other_key),
                    installation: Some(canonical_installation(conversation_id, message_id, install_only_digest())),
                }],
            );
            assert!(
                matches!(stranger, Err(SourceInstallError::Staging { .. })),
                "expected Staging, got {stranger:?}"
            );
            Ok(())
        })
        .expect("the foreign-input refusal");
        assert_eq!(link_rows(conn), baseline, "a refused claim writes nothing");

        // 2. A stored envelope that no longer decodes is Corrupt even though the
        //    digest column still names the pending claim.
        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute("UPDATE source_message_links SET source_positions_bin = X'00'", &[])?;
            Ok(())
        })
        .expect("damage the pending envelope");
        conn.with_tx(TxMode::Immediate, |tx| {
            let damaged = install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: canonical_claim(&input_key),
                    installation: Some(canonical_installation(conversation_id, message_id, install_only_digest())),
                }],
            );
            assert!(
                matches!(damaged, Err(SourceInstallError::Corrupt { .. })),
                "expected Corrupt, got {damaged:?}"
            );
            Ok(())
        })
        .expect("the damaged-envelope refusal");
        let damaged_rows = link_rows(conn);
        assert_eq!(damaged_rows.len(), baseline.len());
        assert_eq!(damaged_rows[0][0], Value::Blob(vec![0u8]), "the damaged bytes stay put");
        assert_eq!(damaged_rows[0][1], Value::Null, "nothing was installed");
        assert_eq!(
            damaged_rows[0][3], baseline[0][3],
            "the digest column must not be rewritten by a refused install"
        );

    }

    /// §9/§571: a stored row whose SQL columns have drifted away from the claim
    /// its envelope carries is `Corrupt`, and the refused install leaves it
    /// exactly as it was rather than masking the drift by replacing it.
    #[test]
    fn a_stored_link_whose_columns_drift_from_its_envelope_is_corrupt() {
        let dir = scratch_dir("link-column-drift");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        let input = verified_input();
        let input_key = *input.input_key();

        let (conversation_id, message_id) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let input_id = stage_and_mark_reader_processed(tx, &input);
                let (conversation_id, message_id) = create_conversation_and_message(tx);
                install_source_links_in_tx(
                    tx,
                    input_id,
                    &[ClaimLinkInstall {
                        claim: canonical_claim(&input_key),
                        installation: None,
                    }],
                )
                .map_err(storage_err)?;
                Ok((conversation_id, message_id))
            })
            .expect("the staging transaction");

        conn.with_tx(TxMode::Immediate, |tx| {
            // The envelope still says `/messages/0`; the column now says
            // somewhere else.
            tx.execute(
                "UPDATE source_message_links SET projection_pointer = '/messages/7'",
                &[],
            )?;
            Ok(())
        })
        .expect("drift the projection pointer column");

        let input_id: i64 = conn
            .query_row_map("SELECT id FROM source_inputs", &[], |row| row.get_typed(0))
            .expect("the staged input id");
        conn.with_tx(TxMode::Immediate, |tx| {
            let drifted = install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: canonical_claim(&input_key),
                    installation: Some(canonical_installation(conversation_id, message_id, install_only_digest())),
                }],
            );
            assert!(
                matches!(drifted, Err(SourceInstallError::Corrupt { .. })),
                "expected Corrupt, got {drifted:?}"
            );
            Ok(())
        })
        .expect("the drifted-column refusal");

        let (pointer, authority, digest): (Option<String>, Option<String>, Vec<u8>) = conn
            .query_row_map(
                "SELECT projection_pointer, authority, binding_digest FROM source_message_links",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
            )
            .expect("read the row back");
        assert_eq!(pointer.as_deref(), Some("/messages/7"), "the drifted column stays drifted");
        assert!(authority.is_none(), "nothing was installed");
        assert_eq!(
            digest,
            canonical_claim(&input_key).pending_claim_digest().as_bytes().to_vec(),
            "the pending digest is untouched"
        );
    }

    /// §9: the authority and message columns are paired with the installation's
    /// class, and the digest column with the envelope. Each drift below is
    /// `Corrupt`, and the same-value install must not report the row as verified.
    #[test]
    fn a_stored_link_whose_authority_or_digest_drifted_is_corrupt() {
        let dir = scratch_dir("link-state-pairing");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        let input = verified_input();
        let input_key = *input.input_key();

        let (conversation_id, message_id) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let input_id = stage_and_mark_reader_processed(tx, &input);
                let (conversation_id, message_id) = create_conversation_and_message(tx);
                install_source_links_in_tx(
                    tx,
                    input_id,
                    &[ClaimLinkInstall {
                        claim: canonical_claim(&input_key),
                        installation: Some(canonical_installation(conversation_id, message_id, install_only_digest())),
                    }],
                )
                .map_err(storage_err)?;
                // A second message in the same conversation, so a re-pointed
                // `message_id` still satisfies the foreign key.
                tx.execute_batch(
                    "INSERT INTO messages (id, conversation_id, idx, role, content)
                         VALUES (8, 1, 1, 'user', 'another message');",
                )?;
                Ok((conversation_id, message_id))
            })
            .expect("the canonical installation");

        let install_again = |conn: &Conn, expectation: &str| {
            let input_id: i64 = conn
                .query_row_map("SELECT id FROM source_inputs", &[], |row| row.get_typed(0))
                .expect("the staged input id");
            conn.with_tx(TxMode::Immediate, |tx| {
                let outcome = install_source_links_in_tx(
                    tx,
                    input_id,
                    &[ClaimLinkInstall {
                        claim: canonical_claim(&input_key),
                        installation: Some(canonical_installation(conversation_id, message_id, install_only_digest())),
                    }],
                );
                assert!(
                    matches!(outcome, Err(SourceInstallError::Corrupt { .. })),
                    "{expectation}: expected Corrupt, got {outcome:?}"
                );
                Ok(())
            })
            .expect(expectation);
        };

        // The same value re-installed on an untouched row is a verified no-op;
        // that is the control for the three drifts below.
        let input_id: i64 = conn
            .query_row_map("SELECT id FROM source_inputs", &[], |row| row.get_typed(0))
            .expect("the staged input id");
        conn.with_tx(TxMode::Immediate, |tx| {
            let outcome = install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: canonical_claim(&input_key),
                    installation: Some(canonical_installation(conversation_id, message_id, install_only_digest())),
                }],
            )
            .map_err(storage_err)?;
            assert_eq!(outcome.verified_same, 1);
            assert_eq!(outcome.inserted, 0);
            Ok(())
        })
        .expect("the unchanged replay");

        // 1. A canonical row re-pointed at another live message.
        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute("UPDATE source_message_links SET message_id = 8", &[])?;
            Ok(())
        })
        .expect("re-point the canonical message id");
        install_again(conn, "a re-pointed canonical message id");

        // 2. A valid-but-incompatible authority for the installation's class.
        //    `unresolved` is a legal enum value and, with no message, a legal
        //    row; it is still not what a canonical installation may carry.
        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute("UPDATE source_message_links SET message_id = 7", &[])?;
            tx.execute(
                "UPDATE source_message_links SET message_id = NULL, authority = 'unresolved'",
                &[],
            )?;
            Ok(())
        })
        .expect("drift the authority column");
        install_again(conn, "an authority the class cannot have");

        // 3. A damaged digest column under an intact envelope.
        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute(
                "UPDATE source_message_links SET message_id = 7, authority = 'canonical'",
                &[],
            )?;
            tx.execute("UPDATE source_message_links SET binding_digest = zeroblob(32)", &[])?;
            Ok(())
        })
        .expect("damage the digest column");
        install_again(conn, "a damaged digest column");

        // None of the three wrote anything: the columns are still as they were
        // left, and the row was never upgraded in place.
        let (authority, live, digest): (Option<String>, Option<i64>, Vec<u8>) = conn
            .query_row_map(
                "SELECT authority, message_id, binding_digest FROM source_message_links",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
            )
            .expect("read the row back");
        assert_eq!(authority.as_deref(), Some("canonical"));
        assert_eq!(live, Some(7));
        assert_eq!(digest, vec![0u8; 32]);

        // 4. The same arm for a class that is not canonical: a standalone link
        //    whose authority drifts to another legal value is Corrupt too.
        conn.with_tx(TxMode::Immediate, |tx| {
            let standalone = SourceClaim {
                input_key,
                record_ordinal: 1,
                record_pointer: String::new(),
                conversation_ordinal: None,
                final_message_idx: None,
                positions: Vec::new(),
                projection_pointer: None,
                evidence_kind: EvidenceKind::Prose,
                mapping_state: ClaimMappingState::Standalone,
            };
            let standalone_installation = OriginalInstallation {
                semantic_request_digest: Sha256Digest::of(b"request"),
                class: InstallationClass::StandaloneNoBinding,
                binding: None,
                rejection: None,
                reason: None,
            };
            install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: standalone.clone(),
                    installation: Some(standalone_installation.clone()),
                }],
            )
            .map_err(storage_err)?;
            // `unmapped` is legal for a row with no targets, and is still not
            // what a standalone installation may carry.
            tx.execute(
                "UPDATE source_message_links SET authority = 'unmapped' \
                 WHERE authority = 'standalone'",
                &[],
            )?;
            let drifted = install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: standalone,
                    installation: Some(standalone_installation),
                }],
            );
            assert!(
                matches!(drifted, Err(SourceInstallError::Corrupt { .. })),
                "a non-canonical class with a foreign authority must be Corrupt, got {drifted:?}"
            );
            Ok(())
        })
        .expect("the standalone authority drift");
    }

    /// §12/§9: an activation retry that finds a committed receipt must
    /// re-derive it from the rows, not merely decode it. Each tamper below keeps
    /// the receipt decodable, so a decode-only replay would accept all of them.
    #[test]
    fn an_activation_retry_refuses_a_tampered_receipt() {
        let dir = scratch_dir("activation-retry");
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();

        let tamper_and_retry = |conn: &Conn, statement: &str, label: &str| {
            conn.with_tx(TxMode::Immediate, |tx| {
                tx.execute(statement, &[])?;
                Ok(())
            })
            .unwrap_or_else(|err| panic!("{label}: the tamper itself must apply: {err}"));
            conn.with_tx(TxMode::Immediate, |tx| {
                let input = verified_input();
                let request = activation_request(tx, &input, 1);
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest());
                assert!(
                    outcome.is_err(),
                    "{label}: a tampered receipt must be refused, got {outcome:?}"
                );
                Ok(())
            })
            .unwrap_or_else(|err| panic!("{label}: {err}"));
        };

        conn.with_tx(TxMode::Immediate, |tx| {
            let (input, _input_id, request) = prepare(tx);
            let outcome =
                activate_source_input_in_tx(tx, &request, input.manifest()).map_err(storage_err)?;
            assert!(matches!(outcome, SourceActivationOutcome::Activated { .. }));
            Ok(())
        })
        .expect("the first activation");

        // 1. A receipt that still decodes and still parses as JSON, with only
        //    its installation digest rewritten.
        let detail: String = conn
            .query_row_map(
                "SELECT detail FROM operation_commit_receipt LIMIT 1",
                &[],
                |row| row.get_typed(0),
            )
            .expect("the committed receipt detail");
        let mut parsed: serde_json::Value =
            serde_json::from_str(&detail).expect("the detail is JSON");
        let original = parsed["installation_digest"]
            .as_str()
            .expect("an installation digest")
            .to_string();
        parsed["installation_digest"] = serde_json::Value::String("0".repeat(64));
        let tampered = serde_json::to_string(&parsed).expect("re-serialise the detail");
        assert_ne!(tampered, detail, "the fixture must actually change the receipt");
        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute(
                "UPDATE operation_commit_receipt SET detail = ?1",
                &[Value::Text(tampered.clone())],
            )?;
            Ok(())
        })
        .expect("rewrite the receipt's installation digest");
        assert!(
            original != "0".repeat(64),
            "the fixture must write a different digest"
        );
        tamper_and_retry(conn, "SELECT 1", "a rewritten installation digest");

        // 2. A witness rewritten together with its own digest column, so the
        //    stored side is internally consistent but no longer describes the
        //    receipt the activation committed.
        conn.with_tx(TxMode::Immediate, |tx| {
            let positions: Vec<u8> = tx.query_row_map(
                "SELECT source_positions_bin FROM source_message_links LIMIT 1",
                &[],
                |row| row.get_typed(0),
            )?;
            let mut evidence = decode_link_evidence(&positions).map_err(storage_err)?;
            let installation = evidence
                .installation
                .as_mut()
                .expect("the fixture installs a witness");
            installation.binding.as_mut().expect("a canonical binding").outcome =
                coding_agent_search::storage::source_facts::OriginalBindingOutcome::VerifiedReplay;
            let reencoded = encode_link_evidence(&evidence.claim, evidence.installation.as_ref())
                .map_err(storage_err)?;
            let digest = binding_digest(
                &evidence.claim,
                evidence.installation.as_ref().expect("the rewritten installation"),
            );
            tx.execute(
                "UPDATE source_message_links SET source_positions_bin = ?1, binding_digest = ?2",
                &[
                    Value::Blob(reencoded),
                    Value::Blob(digest.as_bytes().to_vec()),
                ],
            )?;
            Ok(())
        })
        .expect("rewrite the witness and its digest");
        tamper_and_retry(conn, "SELECT 1", "a self-consistent witness rewrite");
    }

    /// §12: `verify_source_receipt_in_tx` has to bind the *request* to the
    /// stored input by itself. A caller that changes the manifest digest, the A
    /// roots or the library identity is asking about another input, and must not
    /// be told the receipt replayed.
    #[test]
    fn a_standalone_verify_rejects_a_request_that_names_another_input() {
        let dir = scratch_dir("verify-request-binding");
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();
        let input = verified_input();

        let request = conn
            .with_tx(TxMode::Immediate, |tx| {
                let (input, _input_id, request) = prepare(tx);
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                assert!(matches!(outcome, SourceActivationOutcome::Activated { .. }));
                Ok(request)
            })
            .expect("the activation");

        // The control: the untouched request verifies.
        conn.with_tx(TxMode::Immediate, |tx| {
            let matched = verify_source_receipt_in_tx(tx, &request).map_err(storage_err)?;
            assert!(
                matches!(matched, SourceReceiptMatch::VerifiedReplay { .. }),
                "the untouched request must replay, got {matched:?}"
            );
            Ok(())
        })
        .expect("the control verification");

        let before = persisted_state_in_a_new_process(&path);
        let probes: [(&str, Box<dyn Fn(&mut SourceActivationRequest)>); 6] = [
            (
                "a rewritten expected manifest digest",
                Box::new(|request: &mut SourceActivationRequest| {
                    request.expected_manifest_digest = Sha256Digest::of(b"another manifest");
                }),
            ),
            (
                "a rewritten records root",
                Box::new(|request: &mut SourceActivationRequest| {
                    request.source_semantic_records_root = coding_agent_search::storage::source_facts::Root {
                        sha256: Sha256Digest::of(b"another records root"),
                        count: request.source_semantic_records_root.count,
                    };
                }),
            ),
            (
                "a rewritten library identity",
                Box::new(|request: &mut SourceActivationRequest| {
                    request.library_identity = "00000000-0000-4000-8000-000000000000".to_string();
                }),
            ),
            (
                "a rewritten normalizer identity",
                Box::new(|request: &mut SourceActivationRequest| {
                    request.normalizer_id = "normalizer/2".to_string();
                }),
            ),
            (
                "a rewritten safety contract identity",
                Box::new(|request: &mut SourceActivationRequest| {
                    request.safety_contract_id = "safety-contract/2".to_string();
                }),
            ),
            (
                "a rewritten reader finish",
                Box::new(|request: &mut SourceActivationRequest| {
                    request.finish.bytes_read += 1;
                }),
            ),
        ];
        for (label, probe) in probes {
            let mut changed = request.clone();
            probe(&mut changed);
            conn.with_tx(TxMode::Immediate, |tx| {
                let matched = verify_source_receipt_in_tx(tx, &changed).map_err(storage_err)?;
                assert!(
                    !matches!(matched, SourceReceiptMatch::VerifiedReplay { .. }),
                    "{label}: must not verify, got {matched:?}"
                );
                Ok(())
            })
            .unwrap_or_else(|err| panic!("{label}: {err}"));
        }
        let after = persisted_state_in_a_new_process(&path);
        assert_eq!(before, after, "a refused verification must not write anything");
        let _ = input;
    }

    /// §15#18: the source-aware projection and the legacy entry share one
    /// transaction body, so the derived state they leave behind must be the
    /// same. The comparison is a per-table column list, chosen so that nothing
    /// per-library or wall-clock is compared away by accident: the excluded
    /// columns are exactly the ones §15#18 names.
    #[test]
    fn the_projection_and_the_legacy_entry_leave_the_same_derived_state() {
        let legacy_dir = scratch_dir("parity-legacy");
        let projection_dir = scratch_dir("parity-projection");
        let legacy = open_fresh_db(&legacy_dir.join("agent_search.db"));
        let projection = open_fresh_db(&projection_dir.join("agent_search.db"));

        let seed = |storage: &FrankenStorage| {
            storage
                .raw()
                .execute_batch(
                    "INSERT INTO agents (id, slug, name, kind, created_at, updated_at)
                         VALUES (1, 'claude', 'Claude', 'agent', 0, 0);",
                )
                .expect("seed the agent row");
        };
        seed(&legacy);
        seed(&projection);

        let conversation = parity_conversation();
        legacy
            .insert_conversation_tree(1, None, &conversation)
            .expect("the legacy entry installs the conversation");
        projection
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                projection
                    .install_conversation_projection_in_tx(
                        tx,
                        1,
                        None,
                        &conversation,
                        &Sha256Digest::of(b"parity-input"),
                        0,
                        &[],
                    )
                    .map_err(|err| StorageError::Corrupt { detail: err.to_string() })?;
                Ok(())
            })
            .expect("the projection installs the conversation");

        // The tables that carry derived state, with the columns that are
        // actually comparable across two libraries. `usage_*` and
        // `daily_stats` keep their wall-clock `last_updated` out of the
        // comparison and nothing else; `meta` holds each library's own
        // identity; the three source tables are written by the projection
        // alone and have no counterpart on the legacy side.
        // The third element says whether the table is expected to carry state
        // under the default deferred-analytics path. The rollup tables are
        // listed anyway, so that "empty on both sides" is an explicit, checked
        // fact rather than an unexamined omission.
        let comparisons: &[(&str, &[&str], bool)] = &[
            (
                "conversations",
                &["id", "agent_id", "source_id", "external_id", "source_path", "started_at",
                  "ended_at", "identity_host", "last_message_idx", "last_message_created_at"],
                true,
            ),
            (
                "messages",
                &["id", "conversation_id", "idx", "role", "author", "created_at", "content",
                  "extra_json"],
                true,
            ),
            (
                "snippets",
                &["id", "message_id", "file_path", "start_line", "end_line", "language",
                  "snippet_text"],
                true,
            ),
            (
                "lex_docs",
                &["doc_id", "content", "title", "agent", "workspace", "source_path"],
                true,
            ),
            (
                "conversation_tail_state",
                &["conversation_id", "ended_at", "last_message_idx", "last_message_created_at"],
                true,
            ),
            (
                "daily_stats",
                &["day_id", "agent_slug", "source_id", "session_count", "message_count",
                  "total_chars"],
                true,
            ),
            (
                "usage_hourly",
                &["hour_id", "agent_slug", "workspace_id", "source_id", "message_count",
                  "user_message_count", "assistant_message_count", "tool_call_count",
                  "content_tokens_est_total", "api_tokens_total"],
                false,
            ),
            (
                "usage_daily",
                &["day_id", "agent_slug", "workspace_id", "source_id", "message_count",
                  "user_message_count", "assistant_message_count", "tool_call_count",
                  "content_tokens_est_total", "api_tokens_total"],
                false,
            ),
            (
                "usage_models_daily",
                &["day_id", "agent_slug", "workspace_id", "source_id", "model_family",
                  "message_count", "content_tokens_est_total", "api_tokens_total"],
                false,
            ),
            (
                "token_daily_stats",
                &["day_id", "agent_slug", "source_id", "model_family", "api_call_count",
                  "user_message_count", "assistant_message_count", "grand_total_tokens"],
                false,
            ),
            (
                "token_usage",
                &["message_id", "conversation_id", "agent_id", "source_id", "day_id", "role",
                  "content_chars", "model_name", "total_tokens"],
                false,
            ),
            (
                "message_metrics",
                &["message_id", "agent_slug", "source_id", "role", "content_chars",
                  "content_tokens_est", "model_family", "has_tool_calls"],
                false,
            ),
            ("sources", &["id", "kind"], true),
        ];

        // One reader for every check below, so the replay, the rollback and the
        // append are all compared over exactly the same tables and columns.
        let read_table = |storage: &FrankenStorage, table: &str, columns: &[&str]| -> Vec<Vec<String>> {
            let statement = format!(
                "SELECT {} FROM \"{table}\" ORDER BY {}",
                columns.join(", "),
                columns.join(", ")
            );
            storage
                .raw()
                .query_all_map(&statement, &[], |row| {
                    let mut values = Vec::with_capacity(columns.len());
                    for index in 0..columns.len() {
                        values.push(format!("{:?}", row.get_value(index)?));
                    }
                    Ok(values)
                })
                .unwrap_or_else(|err| panic!("read {table}: {err}"))
        };

        let mut differences = Vec::new();
        let mut empty_on_both_sides = Vec::new();
        for (table, columns, carries_state) in comparisons {
            let left = read_table(&legacy, table, columns);
            let right = read_table(&projection, table, columns);
            // The source-aware primitive writes the analytics in full inside the
            // caller's transaction, while the legacy single entry keeps the
            // global defer behaviour it has always had. That difference is
            // intentional and belongs to the new primitive alone, so those six
            // tables are asserted as a difference rather than compared; every
            // other table must still match exactly.
            if !*carries_state {
                assert!(
                    left.is_empty(),
                    "{table} must stay empty in the legacy single entry's default mode"
                );
                assert!(
                    !right.is_empty(),
                    "{table} must be written by the source-aware path, which does not defer"
                );
                empty_on_both_sides.push(*table);
                continue;
            }
            assert!(
                !left.is_empty(),
                "{table} carries no state in the legacy database, so comparing it proves nothing"
            );
            if left != right {
                differences.push(format!(
                    "{table}: {} row(s) via the legacy entry, {} via the projection; first \
                     difference {}",
                    left.len(),
                    right.len(),
                    left.iter()
                        .zip(right.iter())
                        .find(|(a, b)| a != b)
                        .map_or_else(|| "(row counts differ)".to_string(), |(a, b)| {
                            format!("{a:?} vs {b:?}")
                        })
                ));
            }
        }
        assert!(
            differences.is_empty(),
            "the projection and the legacy entry must leave the same derived state:\n{}",
            differences.join("\n")
        );
        // Recorded, not silently skipped: these six are the tables the legacy
        // single entry leaves to the finalizer and the source-aware path writes
        // itself. Naming them keeps the difference explicit rather than
        // dropping them from the comparison.
        assert_eq!(
            empty_on_both_sides,
            vec![
                "usage_hourly",
                "usage_daily",
                "usage_models_daily",
                "token_daily_stats",
                "token_usage",
                "message_metrics"
            ],
            "the set of analytics tables the two paths differ on changed"
        );

        // What a second, identical run may change is the merge's own
        // bookkeeping, and it must be exactly what the legacy entry's second run
        // changes too. Anything else — a recounted row, a doubled derivation —
        // shows up as a column the projection moves and the legacy entry does
        // not.
        let snapshot = |storage: &FrankenStorage| -> Vec<(String, Vec<Vec<String>>)> {
            comparisons
                .iter()
                .map(|(table, columns, _)| {
                    ((*table).to_string(), read_table(storage, table, columns))
                })
                .collect()
        };
        let moved_columns = |before: &[(String, Vec<Vec<String>>)],
                             after: &[(String, Vec<Vec<String>>)]|
         -> Vec<String> {
            let mut moved = Vec::new();
            for ((table, left), (_, right)) in before.iter().zip(after.iter()) {
                assert_eq!(left.len(), right.len(), "{table}: a row was added or removed");
                let columns = comparisons
                    .iter()
                    .find(|(name, _, _)| name == table)
                    .map(|(_, columns, _)| *columns)
                    .expect("the table is in the comparison list");
                for (row_left, row_right) in left.iter().zip(right.iter()) {
                    for (index, (cell_left, cell_right)) in
                        row_left.iter().zip(row_right.iter()).enumerate()
                    {
                        if cell_left != cell_right {
                            moved.push(format!("{table}.{}", columns[index]));
                        }
                    }
                }
            }
            moved
        };

        // The projection, run twice.
        let projection_before = snapshot(&projection);
        projection
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                projection
                    .install_conversation_projection_in_tx(
                        tx,
                        1,
                        None,
                        &conversation,
                        &Sha256Digest::of(b"parity-input"),
                        0,
                        &[],
                    )
                    .map_err(|err| StorageError::Corrupt { detail: err.to_string() })?;
                Ok(())
            })
            .expect("the replayed projection");
        let projection_after = snapshot(&projection);

        // The legacy entry, run twice over its own database.
        let replay_dir = scratch_dir("parity-replay-legacy");
        let replay_path = replay_dir.join("agent_search.db");
        let replayed_legacy = open_fresh_db(&replay_path);
        replayed_legacy
            .raw()
            .execute_batch(
                "INSERT INTO agents (id, slug, name, kind, created_at, updated_at)
                     VALUES (1, 'claude', 'Claude', 'agent', 0, 0);",
            )
            .expect("seed the agent row");
        replayed_legacy
            .insert_conversation_tree(1, None, &conversation)
            .expect("the first legacy run");
        let legacy_before = snapshot(&replayed_legacy);
        replayed_legacy
            .insert_conversation_tree(1, None, &conversation)
            .expect("the replayed legacy run");
        let legacy_after = snapshot(&replayed_legacy);

        assert_eq!(
            moved_columns(&projection_before, &projection_after),
            moved_columns(&legacy_before, &legacy_after),
            "a replayed projection must move exactly the columns a replayed legacy run moves"
        );

        // A divergent same-`idx` message is rejected by the merge, so nothing it
        // carries may be counted: the tables must look exactly as they did.
        let mut divergent = conversation.clone();
        divergent.messages[1].content = "a different second message".to_string();
        projection
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                projection
                    .install_conversation_projection_in_tx(
                        tx,
                        1,
                        None,
                        &divergent,
                        &Sha256Digest::of(b"parity-input"),
                        0,
                        &[],
                    )
                    .map_err(|err| StorageError::Corrupt { detail: err.to_string() })?;
                Ok(())
            })
            .expect("the rejected projection");
        let rejection_moved = moved_columns(&projection_before, &snapshot(&projection));
        let replay_moved = moved_columns(&projection_before, &projection_after);
        assert!(
            rejection_moved
                .iter()
                .all(|column| replay_moved.contains(column)),
            "a rejected divergent message moved a column a plain replay does not: \
             {rejection_moved:?} vs {replay_moved:?}"
        );
        assert!(
            rejection_moved
                .iter()
                .all(|column| column.ends_with("ended_at")),
            "a rejected divergent message changed something other than the merge's own tail \
             bookkeeping: {rejection_moved:?}"
        );


        // The projection writes inside the caller's transaction, so an aborted
        // caller must leave nothing behind, seen from a fresh process. (The
        // legacy entry opens its own transaction by design; the projection is
        // the one §11 requires to compose.)
        let dir = scratch_dir("parity-rollback");
        let path = dir.join("agent_search.db");
        let rolled = open_fresh_db(&path);
        rolled
            .raw()
            .execute_batch(
                "INSERT INTO agents (id, slug, name, kind, created_at, updated_at)
                     VALUES (1, 'claude', 'Claude', 'agent', 0, 0);",
            )
            .expect("seed the agent row");
        let before = persisted_state_in_a_new_process(&path);
        let aborted = rolled.raw().with_tx(TxMode::Immediate, |tx| {
            rolled
                .install_conversation_projection_in_tx(
                    tx,
                    1,
                    None,
                    &conversation,
                    &Sha256Digest::of(b"parity-input"),
                    0,
                    &[],
                )
                .map_err(|err| StorageError::Corrupt { detail: err.to_string() })?;
            Err::<(), StorageError>(StorageError::Other {
                code: None,
                detail: "the caller aborts".to_string(),
            })
        });
        assert!(aborted.is_err(), "the transaction was asked to abort");
        let after = persisted_state_in_a_new_process(&path);
        assert_eq!(before, after, "an aborted projection left nothing behind");
    }

    /// A conversation with enough shape to exercise the derived state: several
    /// messages, a snippet, a tool-call extra and an excluded body.
    fn parity_conversation() -> Conversation {
        use coding_agent_search::model::types::Snippet;

        let message = |idx: i64, role: MessageRole, content: &str, snippets: Vec<Snippet>| Message {
            id: None,
            idx,
            role,
            author: None,
            created_at: Some(1_700_000_000 + idx),
            content: content.to_string(),
            extra_json: serde_json::json!({"tool_calls": [{"name": "read"}]}),
            snippets,
            excluded: None,
        };

        let mut conversation = projection_conversation(0, "the first message", 1_700_000_000);
        conversation.source_path = std::path::PathBuf::from("/tmp/parity.jsonl");
        conversation.messages = vec![
            message(
                0,
                MessageRole::User,
                "the first message",
                vec![Snippet {
                    id: None,
                    file_path: Some(std::path::PathBuf::from("/tmp/a.rs")),
                    start_line: Some(3),
                    end_line: Some(9),
                    language: Some("rust".to_string()),
                    snippet_text: Some("fn main() {}".to_string()),
                }],
            ),
            message(1, MessageRole::Assistant, "the second message", Vec::new()),
            message(2, MessageRole::Tool, "the third message", Vec::new()),
        ];
        conversation
    }

    /// §15#9: a BE8 column of the real schema-9 source table holds a u64 as
    /// eight big-endian bytes, and the value it spells is the same decimal the
    /// canonical tuples use.
    ///
    /// Nothing in the public API writes a caller-supplied u64 into a BE8 column,
    /// so the two boundary values are written into the real column directly and
    /// read back through the facade together with the column's own type and
    /// length. The product's reader is exercised separately below: it has to
    /// decode the value and notice that the row's `position_bin` still spells
    /// the original ordinal, which it cannot do if the large value were
    /// truncated or refused as malformed bytes.
    #[test]
    fn a_be8_column_round_trips_a_u64_larger_than_i64() {
        use coding_agent_search::storage::source_facts::u64_be8;

        let dir = scratch_dir("be8-large-u64");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        let input = verified_input();
        let input_id = conn
            .with_tx(TxMode::Immediate, |tx| Ok(stage_and_mark_reader_processed(tx, &input)))
            .expect("stage the fixture's records");

        // One fixed row, chosen by its own id so the update and the read-back
        // cannot land on different rows when the pointers tie.
        let target_row: i64 = conn
            .with_tx(TxMode::Immediate, |tx| {
                Ok(tx.query_row_map(
                    "SELECT MIN(id) FROM source_records WHERE input_id = ?1",
                    &[Value::Integer(input_id)],
                    |row| row.get_typed(0),
                )?)
            })
            .expect("pick the row under test");

        assert_eq!((i64::MAX as u64 + 1).to_string(), "9223372036854775808");
        assert_eq!(u64::MAX.to_string(), "18446744073709551615");

        for value in [i64::MAX as u64 + 1, u64::MAX] {
            let bytes = u64_be8(value);
            assert_eq!(bytes.len(), 8, "a BE8 value is exactly eight bytes");
            assert_eq!(
                u64::from_be_bytes(bytes),
                value,
                "the eight bytes have to decode back to the same u64"
            );

            conn.with_tx(TxMode::Immediate, |tx| {
                // One row only: the table's UNIQUE(input_id, ordinal,
                // record_pointer) would refuse two rows sharing a value.
                tx.execute(
                    "UPDATE source_records SET ordinal = ?1 WHERE id = ?2",
                    &[Value::Blob(bytes.to_vec()), Value::Integer(target_row)],
                )?;
                Ok(())
            })
            .expect("write the boundary ordinal through SQL");

            let (raw, column_type, column_length): (Vec<u8>, String, i64) = conn
                .with_tx(TxMode::Immediate, |tx| {
                    Ok(tx.query_row_map(
                        "SELECT ordinal, typeof(ordinal), length(ordinal)
                         FROM source_records WHERE id = ?1",
                        &[Value::Integer(target_row)],
                        |row| {
                            Ok((
                                row.get_typed::<Vec<u8>>(0)?,
                                row.get_typed::<String>(1)?,
                                row.get_typed::<i64>(2)?,
                            ))
                        },
                    )?)
                })
                .expect("read the column back");

            assert_eq!(column_type, "blob");
            assert_eq!(column_length, 8);
            assert_eq!(raw, bytes.to_vec(), "the stored bytes are the BE8 bytes");
            let decoded = u64::from_be_bytes(
                raw.as_slice()
                    .try_into()
                    .expect("the column really holds eight bytes"),
            );
            assert_eq!(decoded, value);
            assert_eq!(
                decoded.to_string(),
                value.to_string(),
                "the decimal spelling of the round-tripped value is exact"
            );
        }

        // Independent negative: the product's own reader has to decode the large
        // value and compare it with the ordinal the row's locator spells.
        conn.with_tx(TxMode::Immediate, |tx| {
            let err = source_a_roots_in_tx(tx, input.input_key(), input_id)
                .expect_err("a record whose ordinal does not match its locator must be refused");
            assert!(
                matches!(err, SourceInstallError::Corrupt { .. }),
                "expected Corrupt, got {err:?}"
            );
            Ok(())
        })
        .expect("the mismatched-ordinal refusal");
    }

    /// A request digest for fixtures that install a witness *without* ever
    /// activating it. The activation path requires the witness to be bound to
    /// the request it commits to, so every activating fixture builds the digest
    /// from its own A side instead of using this.
    fn install_only_digest() -> Sha256Digest {
        Sha256Digest::of(b"install-only")
    }

    /// §9: a witness that commits to some other semantic request — a
    /// placeholder, say — is not this input's witness, and activating it must be
    /// refused rather than committed.
    #[test]
    fn an_activation_refuses_a_witness_bound_to_another_request() {
        let dir = scratch_dir("witness-request-binding");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        let input = verified_input();

        conn.with_tx(TxMode::Immediate, |tx| {
            let input_id = stage_and_mark_reader_processed(tx, &input);
            let (conversation_id, message_id) = create_conversation_and_message(tx);
            // Installed with a digest that is not the one this input's
            // activation will recompute.
            install_source_links_in_tx(
                tx,
                input_id,
                &[ClaimLinkInstall {
                    claim: canonical_claim(input.input_key()),
                    installation: Some(canonical_installation(
                        conversation_id,
                        message_id,
                        install_only_digest(),
                    )),
                }],
            )
            .map_err(storage_err)?;
            assert_ne!(
                install_only_digest(),
                request_semantic_digest_for(tx, &input, input_id),
                "the fixture must install a witness bound to another request"
            );

            let request = activation_request(tx, &input, input_id);
            let err = activate_source_input_in_tx(tx, &request, input.manifest())
                .expect_err("a witness bound to another request must not activate");
            assert!(
                matches!(err, SourceInstallError::Conflict { .. }),
                "expected Conflict, got {err:?}"
            );
            let state: String = tx.query_row_map(
                "SELECT state FROM source_inputs WHERE id = ?1",
                &[Value::Integer(input_id)],
                |row| row.get_typed(0),
            )?;
            assert_eq!(state, "staged", "a refused activation must not move the input");
            let receipts: i64 =
                tx.query_row_map("SELECT COUNT(*) FROM operation_commit_receipt", &[], |row| {
                    row.get_typed(0)
                })?;
            assert_eq!(receipts, 0, "a refused activation writes no receipt");
            Ok(())
        })
        .expect("the witness-binding refusal");
    }

    /// §12: a completed input must not be re-committed under a different
    /// semantic request. The second attempt is a conflict, and the first one's
    /// header and receipt stay exactly as they were.
    #[test]
    fn an_already_complete_input_refuses_a_second_different_request() {
        let dir = scratch_dir("complete-then-different");
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();

        let (input, request) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let (input, _input_id, request) = prepare(tx);
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                assert!(matches!(outcome, SourceActivationOutcome::Activated { .. }));
                Ok((input, request))
            })
            .expect("the first activation");

        let before = persisted_state_in_a_new_process(&path);
        let mut different = request.clone();
        // A different, but still internally consistent, reader measurement: the
        // request digest moves, so this is not the commit that already landed.
        different.finish.bytes_read += 1;
        different.finish.records_seen += 0;
        conn.with_tx(TxMode::Immediate, |tx| {
            let err = activate_source_input_in_tx(tx, &different, input.manifest())
                .expect_err("a second, different request must not be committed");
            assert!(
                matches!(err, SourceInstallError::Conflict { .. }),
                "expected Conflict, got {err:?}"
            );
            Ok(())
        })
        .ok();

        // The original request still replays, and the database is untouched.
        conn.with_tx(TxMode::Immediate, |tx| {
            let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                .map_err(storage_err)?;
            assert!(
                matches!(outcome, SourceActivationOutcome::Replay { .. }),
                "the original request must still replay, got {outcome:?}"
            );
            Ok(())
        })
        .expect("the original request still replays");
        let after = persisted_state_in_a_new_process(&path);
        assert_eq!(before, after, "the refused second request changed nothing");
    }

    /// §12: the receipt key, its operation and its state are all part of what
    /// makes a replay a replay, not just "the detail parses".
    #[test]
    fn a_drifted_receipt_row_is_not_a_replay() {
        let case = |label: &str, statement: &str| {
            let dir = scratch_dir("receipt-row-drift");
            let storage = open_fresh_db(&dir.join("agent_search.db"));
            let conn = storage.raw();
            conn.with_tx(TxMode::Immediate, |tx| {
                let (input, _input_id, request) = prepare(tx);
                activate_source_input_in_tx(tx, &request, input.manifest()).map_err(storage_err)?;
                Ok(())
            })
            .expect("the case activation");
            conn.with_tx(TxMode::Immediate, |tx| {
                tx.execute(statement, &[])?;
                Ok(())
            })
            .unwrap_or_else(|err| panic!("{label}: the tamper itself must apply: {err}"));

            let input = verified_input();
            let request = conn
                .with_tx(TxMode::Immediate, |tx| {
                    let input_id: i64 = tx.query_row_map(
                        "SELECT id FROM source_inputs",
                        &[],
                        |row| row.get_typed(0),
                    )?;
                    Ok(activation_request(tx, &input, input_id))
                })
                .expect("rebuild the request");
            conn.with_tx(TxMode::Immediate, |tx| {
                let matched = verify_source_receipt_in_tx(tx, &request).map_err(storage_err)?;
                assert!(
                    !matches!(matched, SourceReceiptMatch::VerifiedReplay { .. }),
                    "{label}: must not verify, got {matched:?}"
                );
                let err = activate_source_input_in_tx(tx, &request, input.manifest())
                    .expect_err("the activation retry must refuse it too");
                assert!(
                    !matches!(err, SourceInstallError::Staging { .. }),
                    "{label}: the retry must refuse on the receipt, got {err:?}"
                );
                Ok(())
            })
            .unwrap_or_else(|err| panic!("{label}: {err}"));
        };

        case(
            "a receipt row that is no longer the activation's operation",
            "UPDATE operation_commit_receipt SET operation = 'something_else'",
        );
        case(
            "a receipt row that is no longer committed",
            "UPDATE operation_commit_receipt SET state = 'pending'",
        );
        case(
            "a parent row that names a different receipt key",
            "UPDATE source_inputs SET receipt_key = 'source-input-v1:' || lower(hex(randomblob(32)))",
        );
        case(
            "a parent row whose recorded request hash drifted",
            "UPDATE source_inputs SET activation_request_hash = zeroblob(32)",
        );
    }

    /// §9/§11: a stored link's envelope must name the input it is filed under.
    /// The join proves SQL ownership only, so the read has to check the claim's
    /// own key as well.
    #[test]
    fn a_stored_link_whose_claim_names_another_input_is_corrupt() {
        let dir = scratch_dir("link-foreign-claim");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        let input = verified_input();

        conn.with_tx(TxMode::Immediate, |tx| {
            let input_id = stage_and_mark_reader_processed(tx, &input);
            // The row needs a live message to satisfy the canonical FK.
            create_conversation_and_message(tx);
            let record_id: i64 = tx.query_row_map(
                "SELECT id FROM source_records WHERE input_id = ?1 ORDER BY ordinal LIMIT 1",
                &[Value::Integer(input_id)],
                |row| row.get_typed(0),
            )?;
            // The envelope's claim belongs to a different input, while the row
            // sits under this input's record.
            let mut foreign = canonical_claim(input.input_key());
            foreign.input_key = *verified_input_for(SEALED_R2).input_key();
            let installation = canonical_installation(1, 7, install_only_digest());
            let positions =
                encode_link_evidence(&foreign, Some(&installation)).map_err(storage_err)?;
            let digest = binding_digest(&foreign, &installation);
            tx.execute(
                "INSERT INTO source_message_links (
                     record_id, projection_key, conversation_ordinal, final_message_idx,
                     source_positions_bin, projection_pointer, message_id, authority,
                     evidence_kind, binding_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'canonical', ?8, ?9)",
                &[
                    Value::Integer(record_id),
                    Value::Blob(foreign.projection_key().as_bytes().to_vec()),
                    Value::Integer(0),
                    Value::Integer(0),
                    Value::Blob(positions),
                    Value::Text("/messages/0".to_string()),
                    Value::Integer(7),
                    Value::Text(foreign.evidence_kind.as_str().to_string()),
                    Value::Blob(digest.as_bytes().to_vec()),
                ],
            )?;

            let err = source_a_roots_in_tx(tx, input.input_key(), input_id)
                .expect_err("a link claiming another input must be Corrupt");
            assert!(
                matches!(err, SourceInstallError::Corrupt { .. }),
                "expected Corrupt, got {err:?}"
            );
            Ok(())
        })
        .expect("the foreign-claim read-back");
    }

    const PARITY_ENTRY_ENV: &str = "SRC05A_PARITY_ENTRY";
    const PARITY_STAGE_ENV: &str = "SRC05A_PARITY_STAGE";
    const PARITY_DB_ENV: &str = "SRC05A_PARITY_DB";
    const PARITY_MARKER: &str = "SRC05A_PARITY ";

    /// The derived tables §15#18 names, with the columns that are comparable
    /// across two libraries. The wall-clock `last_updated` and each library's
    /// own `meta` identity are the only things excluded — no business column is
    /// dropped to make two sides agree.
    const PARITY_TABLES: &[(&str, &[&str])] = &[
        (
            "token_usage",
            &["message_id", "conversation_id", "agent_id", "source_id", "day_id", "role",
              "content_chars", "model_name", "total_tokens", "input_tokens", "output_tokens"],
        ),
        (
            "message_metrics",
            &["message_id", "agent_slug", "source_id", "role", "content_chars",
              "content_tokens_est", "model_family", "has_tool_calls", "tool_call_count"],
        ),
        (
            "token_daily_stats",
            &["day_id", "agent_slug", "source_id", "model_family", "api_call_count",
              "user_message_count", "assistant_message_count", "grand_total_tokens"],
        ),
        (
            "usage_hourly",
            &["hour_id", "agent_slug", "workspace_id", "source_id", "message_count",
              "content_tokens_est_total", "api_tokens_total"],
        ),
        (
            "usage_daily",
            &["day_id", "agent_slug", "workspace_id", "source_id", "message_count",
              "content_tokens_est_total", "api_tokens_total"],
        ),
        (
            "usage_models_daily",
            &["day_id", "agent_slug", "workspace_id", "source_id", "model_family",
              "message_count", "content_tokens_est_total", "api_tokens_total"],
        ),
        (
            "daily_stats",
            &["day_id", "agent_slug", "source_id", "session_count", "message_count",
              "total_chars"],
        ),
        (
            "messages",
            &["conversation_id", "idx", "role", "content"],
        ),
        (
            "lex_docs",
            &["content", "title", "agent", "workspace", "source_path"],
        ),
        (
            "snippets",
            &["message_id", "file_path", "start_line", "end_line", "language", "snippet_text"],
        ),
    ];

    /// Build one parity database in this process. Run as a child, so that the
    /// analytics switches are this process's own and cannot leak into a
    /// parallel test.
    #[test]
    fn child_builds_one_parity_database() {
        let Ok(entry) = std::env::var(PARITY_ENTRY_ENV) else {
            return;
        };
        let path = std::env::var(PARITY_DB_ENV).expect("the parity database path");
        // §15#18 compares the *inline* path: the rollups are written by the
        // entry itself rather than deferred to a later finalizer.
        unsafe {
            std::env::set_var("CASS_INLINE_ANALYTICS_UPDATES", "1");
            std::env::remove_var("CASS_DEFER_ANALYTICS_UPDATES");
        }

        let storage = open_fresh_db(Path::new(&path));
        storage
            .raw()
            .execute_batch(
                "INSERT INTO agents (id, slug, name, kind, created_at, updated_at)
                     VALUES (1, 'claude', 'Claude', 'agent', 0, 0);",
            )
            .expect("seed the agent row");
        let conversation = parity_conversation();
        let stage = std::env::var(PARITY_STAGE_ENV).unwrap_or_else(|_| "fresh".to_string());

        let run_projection = |conversation: &Conversation| {
            storage
                .raw()
                .with_tx(TxMode::Immediate, |tx| {
                    storage
                        .install_conversation_projection_in_tx(
                            tx,
                            1,
                            None,
                            conversation,
                            &Sha256Digest::of(b"parity-input"),
                            0,
                            &[],
                        )
                        .map_err(|err| StorageError::Corrupt { detail: err.to_string() })?;
                    Ok(())
                })
                .expect("the projection installs the conversation");
        };
        let run_entry = |conversation: &Conversation| match entry.as_str() {
            "legacy-batch" => {
                storage
                    .insert_conversations_batched(&[(1, None, conversation)])
                    .expect("the batched legacy entry installs the conversation");
            }
            "projection" => run_projection(conversation),
            other => panic!("unknown parity entry {other}"),
        };

        match stage.as_str() {
            "fresh" => run_entry(&conversation),
            // A brand-new conversation that carries no messages at all: it still
            // owes a session row, and nothing else.
            "empty" => {
                let mut empty = conversation.clone();
                empty.messages = Vec::new();
                run_entry(&empty);
            }
            // The same conversation again: a replay must not double-count.
            "replay" => {
                run_entry(&conversation);
                run_entry(&conversation);
            }
            // The same conversation with one more message: only that message's
            // rows may be added.
            "append" => {
                run_entry(&conversation);
                let mut appended = conversation.clone();
                appended.messages.push(Message {
                    id: None,
                    idx: 3,
                    role: MessageRole::User,
                    author: None,
                    created_at: Some(1_700_000_003),
                    content: "the fourth message".to_string(),
                    extra_json: serde_json::json!({
                        "usage": {"input_tokens": 11, "output_tokens": 7},
                        "model": "claude-sonnet-4-20250514"
                    }),
                    snippets: Vec::new(),
                    excluded: None,
                });
                run_entry(&appended);
            }
            // The same messages, only the conversation's envelope changed: the
            // lexical rows carry the title, so the two entries have to agree on
            // whether re-ingest moves them.
            "envelope" => {
                run_entry(&conversation);
                let mut retitled = conversation.clone();
                retitled.title = Some("a new title".to_string());
                run_entry(&retitled);
            }
            // One committed run, then the same conversation with one message's
            // content changed: the merge rejects that `idx`, and nothing it
            // carries may be counted.
            "rejected" => {
                run_entry(&conversation);
                let mut divergent = conversation.clone();
                divergent.messages[1].content = "a different second message".to_string();
                run_entry(&divergent);
            }
            // One committed run, then an aborted outer transaction: the state
            // the child prints afterwards is the committed one, so a leak shows
            // up as a difference from the fresh stage.
            "rollback" => {
                assert_eq!(entry, "projection", "only the projection composes");
                run_entry(&conversation);
                let aborted = storage.raw().with_tx(TxMode::Immediate, |tx| {
                    storage
                        .install_conversation_projection_in_tx(
                            tx,
                            1,
                            None,
                            &conversation,
                            &Sha256Digest::of(b"parity-input"),
                            0,
                            &[],
                        )
                        .map_err(|err| StorageError::Corrupt { detail: err.to_string() })?;
                    Err::<(), StorageError>(StorageError::Other {
                        code: None,
                        detail: "the caller aborts".to_string(),
                    })
                });
                assert!(aborted.is_err(), "the transaction was asked to abort");
            }
            other => panic!("unknown parity stage {other}"),
        }

        let mut tables = serde_json::Map::new();
        for (table, columns) in PARITY_TABLES {
            let statement = format!(
                "SELECT {} FROM \"{table}\" ORDER BY {}",
                columns.join(", "),
                columns.join(", ")
            );
            let rows: Vec<Vec<String>> = storage
                .raw()
                .query_all_map(&statement, &[], |row| {
                    let mut values = Vec::with_capacity(columns.len());
                    for index in 0..columns.len() {
                        values.push(format!("{:?}", row.get_value(index)?));
                    }
                    Ok(values)
                })
                .unwrap_or_else(|err| panic!("read {table}: {err}"));
            tables.insert(
                (*table).to_string(),
                serde_json::Value::Array(
                    rows.into_iter()
                        .map(|row| {
                            serde_json::Value::Array(
                                row.into_iter().map(serde_json::Value::String).collect(),
                            )
                        })
                        .collect(),
                ),
            );
        }
        println!(
            "{PARITY_MARKER}{}",
            serde_json::json!({ "tables": tables })
        );
    }

    /// §15#18: the legacy batched entry and the source-aware projection must
    /// leave the same token, metrics and rollup state when the analytics are
    /// written inline rather than deferred.
    ///
    /// Both entries now share one collector and one flush, so this compares
    /// their actual derived rows — token_usage, message_metrics,
    /// token_daily_stats, the three usage rollups, daily_stats, the messages,
    /// the lexical rows and the snippets — under inline analytics, where none of
    /// them may be empty on both sides.
    /// Build one parity database in a child process and return its tables.
    fn parity_build(entry: &str, stage: &str) -> serde_json::Value {
        let dir = scratch_dir(&format!("parity-{entry}-{stage}"));
        let path = dir.join("agent_search.db");
        let exe = std::env::current_exe().expect("current test executable");
        let output = std::process::Command::new(exe)
            .args([
                "--exact",
                "activation::child_builds_one_parity_database",
                "--nocapture",
            ])
            .env(PARITY_ENTRY_ENV, entry)
            .env(PARITY_STAGE_ENV, stage)
            .env(PARITY_DB_ENV, &path)
            .env_remove("CASS_DEFER_ANALYTICS_UPDATES")
            .output()
            .expect("spawn the parity child");
        assert!(
            output.status.success(),
            "the {entry}/{stage} child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout
            .lines()
            .find_map(|line| line.strip_prefix(PARITY_MARKER))
            .expect("the child printed its parity line");
        serde_json::from_str(line).expect("the parity line is JSON")
    }

    /// §15#18: a brand-new conversation with no messages still owes its session
    /// row, on both entries. None of the message-level tables has anything to
    /// carry here, so they are only required to agree — not to be non-empty.
    #[test]
    fn an_empty_new_conversation_still_records_its_session_row() {
        let legacy = parity_build("legacy-batch", "empty");
        let projection = parity_build("projection", "empty");

        for table in ["token_daily_stats", "daily_stats"] {
            let rows = projection["tables"][table].as_array().expect("rows");
            assert!(
                !rows.is_empty(),
                "{table} must carry the new conversation's session row"
            );
            assert_eq!(
                legacy["tables"][table], projection["tables"][table],
                "{table} must agree between the two entries"
            );
        }
        for table in ["token_usage", "message_metrics", "messages", "lex_docs", "snippets"] {
            assert_eq!(
                legacy["tables"][table], projection["tables"][table],
                "{table} must agree; with no messages it is expected to be empty"
            );
        }
    }

    #[test]
    fn the_batch_entry_and_the_projection_agree_under_inline_analytics() {
        // Every stage the two entries can be driven through, compared table by
        // table and value by value.
        let mut differences = Vec::new();
        let mut empties = Vec::new();
        for stage in ["fresh", "replay", "append", "envelope"] {
            let legacy = parity_build("legacy-batch", stage);
            let projection = parity_build("projection", stage);
            for (table, _) in PARITY_TABLES {
                let left = legacy["tables"][table].as_array().expect("rows").len();
                let right = projection["tables"][table].as_array().expect("rows").len();
                if left == 0 && right == 0 {
                    empties.push(format!("{stage}/{table}"));
                    continue;
                }
                if legacy["tables"][table] != projection["tables"][table] {
                    differences.push(format!(
                        "{stage}/{table}: {left} row(s) via the batched entry, {right} via the \
                         projection"
                    ));
                }
            }
        }
        assert!(
            differences.is_empty(),
            "the batched entry and the projection must leave the same derived state when the \
             analytics are inline:\n{}\n(empty on both sides: {empties:?})",
            differences.join("\n")
        );
        assert!(
            empties.is_empty(),
            "with inline analytics no derived table may be empty on both sides: {empties:?}"
        );

        // A replay must add nothing, and an aborted outer transaction must leave
        // nothing behind — both checked table by table, from a new process.
        let fresh = parity_build("projection", "fresh");
        let replayed = parity_build("projection", "replay");
        let mut replay_growth = Vec::new();
        for (table, _) in PARITY_TABLES {
            // Values, not just row counts: a rollup whose counters doubled
            // without adding a row is exactly what a count check would miss.
            if fresh["tables"][table] != replayed["tables"][table] {
                replay_growth.push(format!(
                    "{table}: {} row(s) then {}",
                    fresh["tables"][table].as_array().map_or(0, Vec::len),
                    replayed["tables"][table].as_array().map_or(0, Vec::len)
                ));
            }
        }
        assert!(
            replay_growth.is_empty(),
            "a replayed projection must not change any derived value:\n{}",
            replay_growth.join("\n")
        );

        // A same-`idx` divergent message is rejected by the merge, so nothing it
        // carries may be counted.
        let rejected = parity_build("projection", "rejected");
        let mut rejection_growth = Vec::new();
        for (table, _) in PARITY_TABLES {
            if fresh["tables"][table] != rejected["tables"][table] {
                rejection_growth.push((*table).to_string());
            }
        }
        assert!(
            rejection_growth.is_empty(),
            "a rejected same-idx message must not move any derived value: {rejection_growth:?}"
        );
        let rolled_back = parity_build("projection", "rollback");
        assert_eq!(
            fresh["tables"], rolled_back["tables"],
            "an aborted outer transaction must leave no derived row behind"
        );

        // An append adds exactly the appended message's rows, on both entries.
        let appended = parity_build("projection", "append");
        for table in ["token_usage", "message_metrics"] {
            let before = fresh["tables"][table].as_array().expect("rows").len();
            let after = appended["tables"][table].as_array().expect("rows").len();
            assert_eq!(
                after,
                before + 1,
                "{table} must gain exactly the appended message's row, {before} -> {after}"
            );
        }
    }

    const RECEIPT_DB_ENV: &str = "SRC05A_RECEIPT_DB";
    const RECEIPT_MARKER: &str = "SRC05A_RECEIPT ";

    /// Child process half of the end-to-end check: rebuild the request from the
    /// database alone and verify the committed receipt, at a point where the
    /// rejection's winner row no longer exists.
    #[test]
    fn child_verifies_the_receipt_in_a_new_process() {
        let Ok(path) = std::env::var(RECEIPT_DB_ENV) else {
            return;
        };
        let storage =
            FrankenStorage::open(Path::new(&path)).expect("the child opens the database afresh");
        let conn = storage.raw();
        let input = verified_input();
        let input_id: i64 = conn
            .query_row_map("SELECT id FROM source_inputs", &[], |row| row.get_typed(0))
            .expect("exactly one staged input");

        let verified = conn
            .with_tx(TxMode::Immediate, |tx| {
                let request = activation_request(tx, &input, input_id);
                let matched = verify_source_receipt_in_tx(tx, &request).map_err(storage_err)?;
                Ok(matches!(matched, SourceReceiptMatch::VerifiedReplay { .. }))
            })
            .expect("the child verifies the receipt");
        println!("{RECEIPT_MARKER}{}", serde_json::json!({ "verified": verified }));
    }

    /// Run the receipt verification in a new process over `path`.
    fn receipt_verified_in_a_new_process(path: &Path) -> bool {
        let exe = std::env::current_exe().expect("current test executable");
        let output = std::process::Command::new(exe)
            .args([
                "--exact",
                "activation::child_verifies_the_receipt_in_a_new_process",
                "--nocapture",
            ])
            .env(RECEIPT_DB_ENV, path)
            .output()
            .expect("spawn the verifying child process");
        assert!(
            output.status.success(),
            "the child process failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout
            .lines()
            .find_map(|line| line.strip_prefix(RECEIPT_MARKER))
            .expect("the child printed its receipt line");
        let parsed: serde_json::Value = serde_json::from_str(line).expect("the line is JSON");
        parsed["verified"].as_bool().expect("a boolean verdict")
    }

    /// §9/§15#15 end to end: a real same-`idx` conflict installs as
    /// `historical`, the input activates, and the committed receipt still
    /// verifies from a **new process** after the winner row is deleted — with no
    /// repair write and without the witness being re-pointed at a new winner.
    #[test]
    fn a_winner_rejection_activates_and_verifies_after_the_winner_is_deleted() {
        let dir = scratch_dir("winner-rejection-e2e");
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();
        let input = verified_input();
        let input_key = *input.input_key();

        let (request, receipt, winner_message_id) = conn
            .with_tx(TxMode::Immediate, |tx| {
                tx.execute_batch(
                    "INSERT INTO agents (id, slug, name, kind, created_at, updated_at)
                         VALUES (1, 'claude', 'Claude', 'agent', 0, 0);",
                )?;
                storage
                    .install_conversation_projection_in_tx(
                        tx,
                        1,
                        None,
                        &projection_conversation(0, "the winner", 1),
                        &input_key,
                        0,
                        &[],
                    )
                    .map_err(storage_err)?;

                let claim = canonical_claim(&input_key);
                let second = storage
                    .install_conversation_projection_in_tx(
                        tx,
                        1,
                        None,
                        &projection_conversation(0, "the loser", 1),
                        &input_key,
                        0,
                        std::slice::from_ref(&claim),
                    )
                    .map_err(storage_err)?;
                // Stage the claim and the records first: the witness has to be
                // bound to the semantic request digest this activation will
                // recompute, and that digest needs the A side to exist (§9).
                let input_id = stage_and_mark_reader_processed(tx, &input);
                install_source_links_in_tx(
                    tx,
                    input_id,
                    &[ClaimLinkInstall {
                        claim: claim.clone(),
                        installation: None,
                    }],
                )
                .map_err(storage_err)?;
                let digest = request_semantic_digest_for(tx, &input, input_id);
                let second = storage
                    .install_conversation_projection_in_tx(
                        tx,
                        1,
                        None,
                        &projection_conversation(0, "the loser", 1),
                        &input_key,
                        0,
                        std::slice::from_ref(&claim),
                    )
                    .map_err(storage_err)?;
                let installation = second
                    .installation_for_claim(&claim, digest)
                    .expect("the projection proved the branch");
                assert_eq!(installation.class, InstallationClass::WinnerRejectedNoBinding);
                let winner_message_id = installation
                    .rejection
                    .as_ref()
                    .expect("a witness")
                    .winner_message_id;
                install_source_links_in_tx(
                    tx,
                    input_id,
                    &[ClaimLinkInstall {
                        claim,
                        installation: Some(installation),
                    }],
                )
                .map_err(storage_err)?;

                let request = activation_request(tx, &input, input_id);
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                let SourceActivationOutcome::Activated { receipt_key, .. } = &outcome else {
                    panic!("an input whose only claim is a proved rejection must activate, got {outcome:?}");
                };
                let detail = read_receipt_detail_for_test(tx, receipt_key)?;
                let receipt = decode_receipt_detail_for_test(&detail)?;

                let (authority, message_id): (String, Option<i64>) = tx.query_row_map(
                    "SELECT authority, message_id FROM source_message_links",
                    &[],
                    |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
                )?;
                assert_eq!(authority, "historical");
                assert!(message_id.is_none(), "a rejection installs no live message");
                Ok((request, receipt, winner_message_id))
            })
            .expect("the winner-rejection activation transaction");

        // §9: historical verification does not require the winner to survive.
        conn.with_tx(TxMode::Immediate, |tx| {
            tx.execute(
                "DELETE FROM messages WHERE id = ?1",
                &[Value::Integer(winner_message_id)],
            )?;
            Ok(())
        })
        .expect("delete the winner row");

        let before = persisted_state_in_a_new_process(&path);
        let storage = open_fresh_db(&path);
        let conn = storage.raw();
        conn.with_tx(TxMode::Immediate, |tx| {
            let matched = verify_source_receipt_in_tx(tx, &request).map_err(storage_err)?;
            let SourceReceiptMatch::VerifiedReplay { receipt: verified, .. } = matched else {
                panic!("the rejection's receipt must still verify once the winner is gone");
            };
            assert_eq!(*verified, receipt, "the stored receipt must be unchanged");
            Ok(())
        })
        .expect("historical verification");
        drop(conn);
        drop(storage);

        let after = persisted_state_in_a_new_process(&path);
        assert_eq!(
            before, after,
            "verifying a historical receipt must not repair or rewrite anything"
        );
        assert!(
            receipt_verified_in_a_new_process(&path),
            "a new process must reach the same verdict from the persisted witness alone"
        );
    }

    // --- SRC05B-04: legitimately empty JSONL inputs --------------------------

    /// Sealed JSONL bytes the independent framing scan reports as **zero**
    /// records: an empty file, a file of ASCII blank lines, and a file of blank
    /// lines terminated with CRLF. These are the exact bytes a real capture
    /// would seal; nothing here is trimmed by a caller.
    const EMPTY_JSONL: &[u8] = b"";
    const BLANK_JSONL_LF: &[u8] = b"  \n\t\n";
    const BLANK_JSONL_CRLF: &[u8] = b" \r\n\t\r\n";

    const EMPTY_RECEIPT_DB_ENV: &str = "CASS_SRC05B04_EMPTY_RECEIPT_DB";
    const EMPTY_RECEIPT_SEALED_ENV: &str = "CASS_SRC05B04_EMPTY_RECEIPT_SEALED_HEX";
    const EMPTY_RECEIPT_MARKER: &str = "SRC05B04_EMPTY_RECEIPT ";

    /// The independent scan's own denominator for `sealed`, computed here and
    /// never handed in to the verifier.
    fn jsonl_scan_summary(sealed: &[u8]) -> coding_agent_search::storage::source_facts::FramingSummary {
        let mut scan = FramingScan::new(sealed, SourceFormat::Jsonl);
        scan.run_to_end().expect("scan");
        scan.finish()
    }

    /// Verify and stage one zero-record JSONL input through the real framing
    /// scan. Nothing is fabricated: the scan frames no record, so the only row
    /// written is the parent's own manifest header. No record, claim or link is
    /// invented to make the input look non-empty.
    fn stage_empty_jsonl_input(tx: &Tx<'_>, sealed: &[u8]) -> (VerifiedSourceInput, i64) {
        let input = verified_input_for(sealed);
        let mut scan = FramingScan::new(sealed, SourceFormat::Jsonl);
        let frames = scan.next_page(16).expect("scan");
        assert!(frames.is_empty(), "an empty JSONL input frames no record");
        let records: Vec<VerifiedStagedRecord> = frames
            .iter()
            .map(|frame| {
                VerifiedStagedRecord::from_frame(
                    frame,
                    Some(*frame.raw_sha256()),
                    ParseState::Parsed,
                    RecordMappingState::AllCanonical,
                    SafetyState::Preserved,
                    None,
                    None,
                    None,
                )
            })
            .collect();
        let staged = stage_source_records_in_tx(tx, &input, &records).expect("stage");
        // The reader's own stage marker. A zero-record input has no frame to
        // leave `frame_pending`, so this touches nothing and is kept only so
        // this fixture drives the same path a real reader does.
        tx.execute(
            "UPDATE source_records SET frame_state = 'staged' WHERE input_id = ?1",
            &[Value::Integer(staged.input_id)],
        )
        .expect("reader stage");
        (input, staged.input_id)
    }

    fn row_count(tx: &Tx<'_>, sql: &str, input_id: i64) -> i64 {
        tx.query_row_map(sql, &[Value::Integer(input_id)], |row| row.get_typed(0))
            .expect("count")
    }

    /// Z1: verify + stage + activate a zero-record JSONL input through the real
    /// primitives, and check the completed parent, the untouched record/link
    /// tables and the full receipt field by field.
    fn assert_empty_jsonl_activates(sealed: &[u8]) {
        let tag: String = sealed.iter().map(|byte| format!("{byte:02x}")).collect();
        let dir = scratch_dir(&format!("empty-jsonl-{}-{tag}", sealed.len()));
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();

        let summary = jsonl_scan_summary(sealed);
        assert_eq!(summary.records, 0, "the fixture must be a zero-record input");
        assert!(summary.complete, "the fixture scan must reach the end");

        conn.with_tx(TxMode::Immediate, |tx| {
            let (input, input_id) = stage_empty_jsonl_input(tx, sealed);
            let manifest = input.manifest();
            // The manifest reports the bytes that were sealed, not a placeholder.
            assert_eq!(manifest.records(), 0);
            assert_eq!(manifest.byte_len(), sealed.len() as u64);
            assert_eq!(manifest.blank_lines(), summary.blank_lines);
            assert_eq!(manifest.blank_bytes(), summary.blank_bytes);
            assert_eq!(manifest.sealed_sha256(), &Sha256Digest::of(sealed));
            assert_eq!(manifest.format(), SourceFormat::Jsonl);
            assert!(manifest.complete());

            assert_eq!(
                row_count(tx, "SELECT COUNT(*) FROM source_records WHERE input_id = ?1", input_id),
                0,
                "a zero-record input stages no record"
            );
            assert_eq!(
                row_count(
                    tx,
                    "SELECT COUNT(*) FROM source_message_links l
                     JOIN source_records r ON r.id = l.record_id
                     WHERE r.input_id = ?1",
                    input_id
                ),
                0,
                "a zero-record input stages no claim or link"
            );

            let request = activation_request(tx, &input, input_id);
            let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                .map_err(storage_err)?;
            let SourceActivationOutcome::Activated {
                receipt_key,
                generation,
                source_facts_revision,
                ..
            } = outcome
            else {
                panic!("a legitimate zero-record JSONL input must activate, got {outcome:?}");
            };
            assert!(receipt_key.starts_with("source-input-v1:"));
            assert!(generation.starts_with("source-activation-v1:"));
            assert_eq!(
                source_facts_revision, 1,
                "the first complete publication moves the revision once"
            );
            assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("1"));
            assert_eq!(
                meta(tx, "source_content_generation").as_deref(),
                Some(generation.as_str())
            );
            let state: String = tx.query_row_map(
                "SELECT state FROM source_inputs WHERE id = ?1",
                &[Value::Integer(input_id)],
                |row| row.get_typed(0),
            )?;
            assert_eq!(state, "complete");
            let receipts: i64 = tx.query_row_map(
                "SELECT COUNT(*) FROM operation_commit_receipt WHERE idempotency_key = ?1",
                &[Value::Text(receipt_key.clone())],
                |row| row.get_typed(0),
            )?;
            assert_eq!(receipts, 1, "exactly one receipt row");

            // The receipt carries every field a non-empty activation's does,
            // and its roots are the empty-domain roots rather than omitted.
            let detail = read_receipt_detail_for_test(tx, &receipt_key)?;
            let receipt = decode_receipt_detail_for_test(&detail)?;
            assert_eq!(receipt.input_key, *input.input_key());
            assert_eq!(receipt.terminal_state, TerminalState::Complete);
            assert_eq!(receipt.applied_content_generation, generation);
            assert_eq!(receipt.committed_source_facts_revision, 1);
            assert_eq!(receipt.source_semantic_records_root.count, 0);
            assert_eq!(receipt.claims_root.count, 0);
            assert_eq!(receipt.immutable_records_root.count, 0);
            assert_eq!(receipt.original_binding_root.count, 0);
            assert_eq!(receipt.binding_class_counts, Default::default());
            assert_eq!(receipt.expected_manifest_digest.hex(), request.expected_manifest_digest.hex());

            // The committed receipt re-verifies against the rows it describes.
            let matched = verify_source_receipt_in_tx(tx, &request).map_err(storage_err)?;
            assert!(
                matches!(matched, SourceReceiptMatch::VerifiedReplay { .. }),
                "the empty input's own receipt must verify, got {matched:?}"
            );
            Ok(())
        })
        .expect("the empty input activates");
        drop(conn);
        drop(storage);

        // A new process reaches the same verdict from the persisted witness
        // alone — no in-memory state from this run.
        assert!(
            empty_receipt_verified_in_a_new_process(&path, sealed),
            "a new process must verify the empty input's receipt"
        );
    }

    /// Z1: a zero-byte JSONL file is a complete scan of no records, and its
    /// activation succeeds with a full receipt.
    #[test]
    fn a_zero_byte_jsonl_input_activates_with_a_full_receipt() {
        assert_empty_jsonl_activates(EMPTY_JSONL);
    }

    /// Z1: a JSONL file that holds only ASCII blank lines (LF and CRLF, spaces
    /// and tabs) is the same zero-record completion.
    #[test]
    fn a_blank_only_jsonl_input_activates_with_a_full_receipt() {
        assert_empty_jsonl_activates(BLANK_JSONL_LF);
        assert_empty_jsonl_activates(BLANK_JSONL_CRLF);
    }

    #[test]
    fn child_verifies_an_empty_input_receipt_in_a_new_process() {
        let (Ok(path), Ok(hex)) = (
            std::env::var(EMPTY_RECEIPT_DB_ENV),
            std::env::var(EMPTY_RECEIPT_SEALED_ENV),
        ) else {
            return;
        };
        let sealed: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ascii"), 16)
                    .expect("valid hex pair")
            })
            .collect();
        let storage =
            FrankenStorage::open(Path::new(&path)).expect("the child opens the database afresh");
        let conn = storage.raw();
        let input = verified_input_for(&sealed);
        let input_id: i64 = conn
            .query_row_map(
                "SELECT id FROM source_inputs WHERE input_key = ?1",
                &[Value::Blob(input.input_key().as_bytes().to_vec())],
                |row| row.get_typed(0),
            )
            .expect("the child finds the empty input's parent row");
        let verified = conn
            .with_tx(TxMode::Immediate, |tx| {
                let request = activation_request(tx, &input, input_id);
                let matched = verify_source_receipt_in_tx(tx, &request).map_err(storage_err)?;
                Ok(matches!(matched, SourceReceiptMatch::VerifiedReplay { .. }))
            })
            .expect("the child verifies the empty input's receipt");
        println!("{EMPTY_RECEIPT_MARKER}{}", serde_json::json!({ "verified": verified }));
    }

    fn empty_receipt_verified_in_a_new_process(path: &Path, sealed: &[u8]) -> bool {
        let exe = std::env::current_exe().expect("current test executable");
        let hex: String = sealed.iter().map(|byte| format!("{byte:02x}")).collect();
        let output = std::process::Command::new(exe)
            .args([
                "--exact",
                "activation::child_verifies_an_empty_input_receipt_in_a_new_process",
                "--nocapture",
            ])
            .env(EMPTY_RECEIPT_DB_ENV, path)
            .env(EMPTY_RECEIPT_SEALED_ENV, hex)
            .output()
            .expect("spawn the verifying child process");
        assert!(
            output.status.success(),
            "the child process failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout
            .lines()
            .find_map(|line| line.strip_prefix(EMPTY_RECEIPT_MARKER))
            .expect("the child printed its receipt line");
        let parsed: serde_json::Value = serde_json::from_str(line).expect("the line is JSON");
        parsed["verified"].as_bool().expect("a boolean verdict")
    }

    /// Z2: retrying the same zero-record activation returns the same receipt and
    /// moves nothing again — the revision, the generation and every table stay
    /// put — and a new process reaches the same receipt from the persisted
    /// witness.
    #[test]
    fn retrying_an_empty_jsonl_input_is_a_same_receipt_replay() {
        let dir = scratch_dir("empty-jsonl-replay");
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();

        let (input, request, receipt) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let (input, input_id) = stage_empty_jsonl_input(tx, EMPTY_JSONL);
                let request = activation_request(tx, &input, input_id);
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                let SourceActivationOutcome::Activated { receipt_key, .. } = outcome else {
                    panic!("the first activation must succeed, got {outcome:?}");
                };
                let detail = read_receipt_detail_for_test(tx, &receipt_key)?;
                let receipt = decode_receipt_detail_for_test(&detail)?;
                Ok((input, request, receipt))
            })
            .expect("the first activation");

        let before = persisted_state_in_a_new_process(&path);

        conn.with_tx(TxMode::Immediate, |tx| {
            let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                .map_err(storage_err)?;
            let SourceActivationOutcome::Replay { receipt: replayed } = outcome else {
                panic!("a same-request retry must replay, got {outcome:?}");
            };
            assert_eq!(
                replayed, receipt,
                "the replay must be the same receipt, field for field"
            );
            assert_eq!(
                meta(tx, "source_facts_revision").as_deref(),
                Some("1"),
                "a replay must not move the revision again"
            );
            Ok(())
        })
        .expect("the same-request replay");
        drop(conn);
        drop(storage);

        let after = persisted_state_in_a_new_process(&path);
        assert_eq!(before, after, "a same-request replay must not change the database again");
        assert!(
            empty_receipt_verified_in_a_new_process(&path, EMPTY_JSONL),
            "a new process must reach the same receipt"
        );
    }

    /// Z3: once a zero-record input has completed, a later input for the same
    /// source is a *new* input with its own key and receipt; the empty input's
    /// receipt still verifies and its rows are not overwritten. Any change to
    /// the sealed bytes — empty to non-empty, or blank bytes only — is a new
    /// sealed identity, and the non-empty input's message, link and receipt are
    /// written exactly once, including across a replay of its own request.
    #[test]
    fn a_later_nonempty_input_under_the_same_origin_is_a_new_input() {
        let dir = scratch_dir("empty-then-nonempty");
        let path = dir.join("agent_search.db");
        let storage = open_fresh_db(&path);
        let conn = storage.raw();

        // Changing the sealed bytes at all changes the sealed identity, so each
        // body is its own input rather than an overwrite.
        let empty = verified_input_for(EMPTY_JSONL);
        let blank = verified_input_for(BLANK_JSONL_LF);
        let nonempty = verified_input_for(SEALED);
        assert_ne!(empty.input_key(), blank.input_key(), "blank bytes are part of the sealed identity");
        assert_ne!(empty.input_key(), nonempty.input_key(), "empty and non-empty bodies differ");
        assert_ne!(blank.input_key(), nonempty.input_key());

        // The empty input activates first and keeps its own receipt.
        let empty_request = conn
            .with_tx(TxMode::Immediate, |tx| {
                let (input, input_id) = stage_empty_jsonl_input(tx, EMPTY_JSONL);
                let request = activation_request(tx, &input, input_id);
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                assert!(
                    matches!(outcome, SourceActivationOutcome::Activated { .. }),
                    "the empty input must activate first, got {outcome:?}"
                );
                Ok(request)
            })
            .expect("the empty input activates");

        // Changed blank bytes only: a different sealed identity, and its own
        // full input that completes.
        let blank_request = conn
            .with_tx(TxMode::Immediate, |tx| {
                let (input, input_id) = stage_empty_jsonl_input(tx, BLANK_JSONL_LF);
                let request = activation_request(tx, &input, input_id);
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                assert!(
                    matches!(outcome, SourceActivationOutcome::Activated { .. }),
                    "the blank-only input is its own input and completes, got {outcome:?}"
                );
                Ok(request)
            })
            .expect("the blank-only input activates");

        // A legitimate record for the same source arrives afterwards.
        let (nonempty_input_id, nonempty_request, nonempty_receipt) = conn
            .with_tx(TxMode::Immediate, |tx| {
                let input = verified_input_for(SEALED);
                let input_id = stage_and_mark_reader_processed(tx, &input);
                let (conversation_id, message_id) = create_conversation_and_message(tx);
                install_canonical_witness(
                    tx,
                    &input,
                    input_id,
                    canonical_claim(input.input_key()),
                    conversation_id,
                    message_id,
                );
                let request = activation_request(tx, &input, input_id);
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                let SourceActivationOutcome::Activated { receipt_key, .. } = outcome else {
                    panic!("the non-empty input activates as its own input, got {outcome:?}");
                };
                let detail = read_receipt_detail_for_test(tx, &receipt_key)?;
                let receipt = decode_receipt_detail_for_test(&detail)?;
                Ok((input_id, request, receipt))
            })
            .expect("the non-empty input activates");

        // The earlier inputs keep their own rows and their own receipts.
        conn.with_tx(TxMode::Immediate, |tx| {
            for (request, label) in [(&empty_request, "empty"), (&blank_request, "blank-only")] {
                let matched = verify_source_receipt_in_tx(tx, request).map_err(storage_err)?;
                assert!(
                    matches!(matched, SourceReceiptMatch::VerifiedReplay { .. }),
                    "the {label} input's receipt must still verify after later inputs, \
                     got {matched:?}"
                );
            }
            let empty_id = registered_source_input_id(tx, empty.input_key())
                .map_err(storage_err)?
                .expect("the empty input stays registered");
            let state: String = tx.query_row_map(
                "SELECT state FROM source_inputs WHERE id = ?1",
                &[Value::Integer(empty_id)],
                |row| row.get_typed(0),
            )?;
            assert_eq!(state, "complete", "the earlier input must not be overwritten");
            let inputs: i64 =
                tx.query_row_map("SELECT COUNT(*) FROM source_inputs", &[], |row| row.get_typed(0))?;
            assert_eq!(inputs, 3, "three distinct sealed bodies are three inputs");
            Ok(())
        })
        .expect("the earlier inputs are left alone");

        // The non-empty input's message, link and receipt exist exactly once —
        // the message count is read from `messages` directly, not inferred from
        // the link count — and replaying its request writes nothing new.
        let before_replay = persisted_state_in_a_new_process(&path);
        conn.with_tx(TxMode::Immediate, |tx| {
            let messages: i64 = tx.query_row_map(
                "SELECT COUNT(*) FROM messages WHERE conversation_id = 1",
                &[],
                |row| row.get_typed(0),
            )?;
            assert_eq!(messages, 1, "exactly one message row for the later input");
            let stored_link: (i64, i64) = tx.query_row_map(
                "SELECT l.message_id, COUNT(*)
                 FROM source_message_links l
                 JOIN source_records r ON r.id = l.record_id
                 WHERE r.input_id = ?1
                 GROUP BY l.message_id",
                &[Value::Integer(nonempty_input_id)],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )?;
            assert_eq!(stored_link, (7, 1), "one stored link naming the one message");
            let receipts: i64 = tx.query_row_map(
                "SELECT COUNT(*) FROM operation_commit_receipt",
                &[],
                |row| row.get_typed(0),
            )?;
            assert_eq!(receipts, 3, "one receipt per completed input");
            assert_eq!(
                meta(tx, "source_facts_revision").as_deref(),
                Some("3"),
                "each completed input moved the revision once"
            );

            let outcome =
                activate_source_input_in_tx(tx, &nonempty_request, nonempty.manifest())
                    .map_err(storage_err)?;
            let SourceActivationOutcome::Replay { receipt: replayed } = outcome else {
                panic!("replaying the non-empty request must replay, got {outcome:?}");
            };
            assert_eq!(replayed, nonempty_receipt, "the replay is the same receipt");

            let messages_after: i64 = tx.query_row_map(
                "SELECT COUNT(*) FROM messages WHERE conversation_id = 1",
                &[],
                |row| row.get_typed(0),
            )?;
            let links_after: i64 = tx.query_row_map(
                "SELECT COUNT(*) FROM source_message_links l
                 JOIN source_records r ON r.id = l.record_id
                 WHERE r.input_id = ?1",
                &[Value::Integer(nonempty_input_id)],
                |row| row.get_typed(0),
            )?;
            let receipts_after: i64 = tx.query_row_map(
                "SELECT COUNT(*) FROM operation_commit_receipt",
                &[],
                |row| row.get_typed(0),
            )?;
            assert_eq!(
                (messages_after, links_after, receipts_after),
                (1, 1, 3),
                "a replay must not add a message, a link or a receipt"
            );
            assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("3"));
            Ok(())
        })
        .expect("the non-empty replay writes nothing new");
        drop(conn);
        drop(storage);

        let after_replay = persisted_state_in_a_new_process(&path);
        assert_eq!(
            before_replay, after_replay,
            "replaying the non-empty request must not change the database"
        );
    }

    /// Z4: a zero-record manifest with a record row is refused — the change
    /// never lets a non-empty frame set complete just because the manifest says
    /// zero.
    #[test]
    fn a_zero_manifest_with_an_extra_record_row_is_refused() {
        let dir = scratch_dir("zero-manifest-extra-record");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        conn.with_tx(TxMode::Immediate, |tx| {
            let (input, input_id) = stage_empty_jsonl_input(tx, EMPTY_JSONL);
            // A real, well-formed frame from other bytes, staged against the
            // empty input's own manifest: the independent denominator says zero,
            // the rows say one.
            let mut scan = FramingScan::new(SEALED, SourceFormat::Jsonl);
            let frames = scan.next_page(1).expect("scan");
            let extra: Vec<VerifiedStagedRecord> = frames
                .iter()
                .map(|frame| {
                    VerifiedStagedRecord::from_frame(
                        frame,
                        Some(*frame.raw_sha256()),
                        ParseState::Parsed,
                        RecordMappingState::AllCanonical,
                        SafetyState::Preserved,
                        None,
                        None,
                        None,
                    )
                })
                .collect();
            stage_source_records_in_tx(tx, &input, &extra).expect("stage the extra row");
            tx.execute(
                "UPDATE source_records SET frame_state = 'staged' WHERE input_id = ?1",
                &[Value::Integer(input_id)],
            )?;
            let request = activation_request(tx, &input, input_id);
            let err = activate_source_input_in_tx(tx, &request, input.manifest())
                .expect_err("a zero manifest with a record row must be refused");
            assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");
            assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("0"));
            let receipts: i64 =
                tx.query_row_map("SELECT COUNT(*) FROM operation_commit_receipt", &[], |row| {
                    row.get_typed(0)
                })?;
            assert_eq!(receipts, 0, "a refusal writes no success receipt");
            Ok(())
        })
        .expect("the extra-record case is refused");
    }

    /// Z4: a non-zero manifest with a record missing is refused.
    #[test]
    fn a_nonzero_manifest_missing_a_record_is_refused() {
        let dir = scratch_dir("nonzero-manifest-missing-record");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        conn.with_tx(TxMode::Immediate, |tx| {
            let input = verified_input();
            assert_eq!(input.manifest().records(), 2, "the fixture manifests two records");
            let mut scan = FramingScan::new(SEALED, SourceFormat::Jsonl);
            let frames = scan.next_page(1).expect("scan");
            let partial: Vec<VerifiedStagedRecord> = frames
                .iter()
                .map(|frame| {
                    VerifiedStagedRecord::from_frame(
                        frame,
                        Some(*frame.raw_sha256()),
                        ParseState::Parsed,
                        RecordMappingState::AllCanonical,
                        SafetyState::Preserved,
                        None,
                        None,
                        None,
                    )
                })
                .collect();
            let staged = stage_source_records_in_tx(tx, &input, &partial).expect("stage one frame");
            tx.execute(
                "UPDATE source_records SET frame_state = 'staged' WHERE input_id = ?1",
                &[Value::Integer(staged.input_id)],
            )?;
            let request = activation_request(tx, &input, staged.input_id);
            let err = activate_source_input_in_tx(tx, &request, input.manifest())
                .expect_err("a manifest with a missing record must be refused");
            assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");
            Ok(())
        })
        .expect("the missing-record case is refused");
    }

    /// Z4: a Finish whose measurements disagree with the independent manifest is
    /// refused for every measured field.
    #[test]
    fn a_finish_that_disagrees_with_the_manifest_cannot_complete() {
        for which in ["content_digest", "byte_len", "blank_lines", "records_seen", "eof"] {
            let dir = scratch_dir(&format!("empty-finish-{which}"));
            let storage = open_fresh_db(&dir.join("agent_search.db"));
            let conn = storage.raw();
            conn.with_tx(TxMode::Immediate, |tx| {
                let (input, input_id) = stage_empty_jsonl_input(tx, BLANK_JSONL_LF);
                let mut request = activation_request(tx, &input, input_id);
                match which {
                    "content_digest" => {
                        request.finish.content_digest = Sha256Digest::of(b"drifted bytes");
                    }
                    "byte_len" => request.finish.bytes_read += 1,
                    "blank_lines" => request.finish.blank_lines += 1,
                    "records_seen" => request.finish.records_seen += 1,
                    "eof" => request.finish.reached_eof = false,
                    other => unreachable!("{other}"),
                }
                let err = activate_source_input_in_tx(tx, &request, input.manifest())
                    .expect_err("a Finish that disagrees with the manifest must be refused");
                assert!(matches!(err, SourceInstallError::Conflict { .. }), "{which}: {err}");
                assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("0"), "{which}");
                let receipts: i64 =
                    tx.query_row_map("SELECT COUNT(*) FROM operation_commit_receipt", &[], |row| {
                        row.get_typed(0)
                    })?;
                assert_eq!(receipts, 0, "{which} must not write a success receipt");
                Ok(())
            })
            .expect("the finish-mismatch case is refused");
        }
    }

    /// Z4: a zero-record request whose own Finish admits a failure still cannot
    /// complete — the zero-record path does not skip the failure guards.
    #[test]
    fn a_zero_record_request_that_admits_a_failure_cannot_complete() {
        for which in ["parse_failed", "unprocessed_range", "partial_terminal", "whole_input_rejected"]
        {
            let dir = scratch_dir(&format!("empty-admits-{which}"));
            let storage = open_fresh_db(&dir.join("agent_search.db"));
            let conn = storage.raw();
            conn.with_tx(TxMode::Immediate, |tx| {
                let (input, input_id) = stage_empty_jsonl_input(tx, EMPTY_JSONL);
                let mut request = activation_request(tx, &input, input_id);
                match which {
                    "parse_failed" => request.finish.parse_failed = 1,
                    "unprocessed_range" => {
                        request.finish.unprocessed_ranges = vec![
                            coding_agent_search::storage::source_facts::SourceUnprocessedRange {
                                start: 0,
                                end: 0,
                                reason: "measured gap".to_string(),
                                ordinal: None,
                                record_pointer: None,
                            },
                        ];
                    }
                    "partial_terminal" => request.requested_terminal = TerminalState::Partial,
                    "whole_input_rejected" => {
                        request.projection_disposition = ProjectionDisposition::WholeInputRejected;
                        request.requested_terminal = TerminalState::Failed;
                    }
                    other => unreachable!("{other}"),
                }
                let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                    .map_err(storage_err)?;
                assert!(
                    !matches!(outcome, SourceActivationOutcome::Activated { .. }),
                    "{which}: a zero-record request that admits a failure must not activate, \
                     got {outcome:?}"
                );
                let receipts: i64 =
                    tx.query_row_map("SELECT COUNT(*) FROM operation_commit_receipt", &[], |row| {
                        row.get_typed(0)
                    })?;
                assert_eq!(receipts, 0, "{which} must not write a success receipt");
                Ok(())
            })
            .expect("the failure-admitting case cannot complete");
        }
    }

    /// Z4/Z6's discriminating guard: a non-empty input whose claims and links
    /// have not been produced yet must stay staged, never complete. Widening the
    /// zero-record rule into a blanket "no links is fine" turns this red.
    #[test]
    fn a_nonzero_input_without_claims_or_links_cannot_complete() {
        let dir = scratch_dir("nonzero-no-links");
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        conn.with_tx(TxMode::Immediate, |tx| {
            let input = verified_input();
            let input_id = stage_and_mark_reader_processed(tx, &input);
            // No claim, no link: the input is only halfway through the pipeline.
            let request = activation_request(tx, &input, input_id);
            let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                .map_err(storage_err)?;
            assert!(
                matches!(outcome, SourceActivationOutcome::StagedOnly { .. }),
                "a non-empty input with no claims or links must not complete, got {outcome:?}"
            );
            assert_eq!(meta(tx, "source_facts_revision").as_deref(), Some("0"));
            let receipts: i64 =
                tx.query_row_map("SELECT COUNT(*) FROM operation_commit_receipt", &[], |row| {
                    row.get_typed(0)
                })?;
            assert_eq!(receipts, 0);
            Ok(())
        })
        .expect("the no-links case cannot complete");
    }

    /// A declaration for `sealed` under `format`: the wire format is part of the
    /// input, not a caller convenience.
    fn verified_input_for_format(sealed: &[u8], format: SourceFormat) -> VerifiedSourceInput {
        let mut declaration = declaration_for(sealed);
        declaration.format = format;
        VerifiedSourceInput::verify(declaration, sealed, &safety_config())
            .expect("the declaration matches the sealed bytes")
            .0
    }

    /// Z5: stage the one physical record a real scan produces for `sealed`,
    /// measured as a parse failure, and show the input still cannot complete. An
    /// empty JSON document, Unicode whitespace, invalid UTF-8 and illegal
    /// non-empty JSONL are all physical records, not zero-record inputs.
    fn assert_parse_failed_input_cannot_complete(sealed: &[u8], format: SourceFormat, tag: &str) {
        let dir = scratch_dir(&format!("parse-failed-{tag}"));
        let storage = open_fresh_db(&dir.join("agent_search.db"));
        let conn = storage.raw();
        conn.with_tx(TxMode::Immediate, |tx| {
            let input = verified_input_for_format(sealed, format);
            let mut scan = FramingScan::new(sealed, format);
            let frames = scan.next_page(8).expect("scan");
            assert_eq!(frames.len(), 1, "{tag}: the scan must frame exactly one physical record");
            assert_eq!(input.manifest().records(), 1, "{tag}");
            let records: Vec<VerifiedStagedRecord> = frames
                .iter()
                .map(|frame| {
                    VerifiedStagedRecord::from_frame(
                        frame,
                        Some(*frame.raw_sha256()),
                        ParseState::ParseFailed,
                        RecordMappingState::AllUnmapped,
                        SafetyState::Preserved,
                        None,
                        None,
                        None,
                    )
                })
                .collect();
            let staged = stage_source_records_in_tx(tx, &input, &records).expect("stage");
            tx.execute(
                "UPDATE source_records SET frame_state = 'staged' WHERE input_id = ?1",
                &[Value::Integer(staged.input_id)],
            )?;
            let mut request = activation_request(tx, &input, staged.input_id);
            assert_eq!(request.finish.records_seen, 1, "{tag}");
            request.finish.parse_failed = 1;
            let outcome = activate_source_input_in_tx(tx, &request, input.manifest())
                .map_err(storage_err)?;
            assert!(
                matches!(outcome, SourceActivationOutcome::StagedOnly { .. }),
                "{tag}: a parse-failed physical record must not complete, got {outcome:?}"
            );
            let receipts: i64 =
                tx.query_row_map("SELECT COUNT(*) FROM operation_commit_receipt", &[], |row| {
                    row.get_typed(0)
                })?;
            assert_eq!(receipts, 0, "{tag}: no success receipt");
            Ok(())
        })
        .expect("the parse-failed input cannot complete");
    }

    /// Z5: inputs that are not zero-record JSONL keep failing, so the new
    /// completion rule cannot be reached by trimming or reinterpreting bytes.
    #[test]
    fn non_zero_record_jsonl_inputs_still_cannot_complete() {
        assert_parse_failed_input_cannot_complete(b"", SourceFormat::JsonDocument, "empty-document");
        assert_parse_failed_input_cannot_complete(b"\xc2\xa0\n", SourceFormat::Jsonl, "unicode-blank");
        assert_parse_failed_input_cannot_complete(b"\xff\n", SourceFormat::Jsonl, "bad-utf8");
        assert_parse_failed_input_cannot_complete(b"{not json}\n", SourceFormat::Jsonl, "illegal-jsonl");
    }
}

// ---------------------------------------------------------------------------
// The source-aware conversation projection shares the caller's transaction
// ---------------------------------------------------------------------------

#[test]
fn source_projection_rolls_back_the_parent_source_row() {
    use coding_agent_search::model::types::{Conversation, Message, MessageRole, Snippet};
    use coding_agent_search::storage::source_facts::Sha256Digest;

    let dir = scratch_dir("projection-rollback");
    let storage = open_fresh_db(&dir.join("agent_search.db"));
    let conn = storage.raw();
    // The projection merges into the existing agent rows; only the source and
    // conversation rows are the projection's own business.
    conn.execute_batch(
        "INSERT INTO agents (id, slug, name, kind, created_at, updated_at)
             VALUES (1, 'claude', 'Claude', 'agent', 0, 0);",
    )
    .expect("seed the agent row");

    // A non-local source id, so the row under test is not the schema's
    // bootstrap-local one.
    let conversation = Conversation {
        id: None,
        agent_slug: "claude".to_string(),
        workspace: None,
        external_id: None,
        title: None,
        source_path: std::path::PathBuf::from("/tmp/projection-rollback.jsonl"),
        started_at: Some(1_700_000_000),
        ended_at: None,
        approx_tokens: None,
        metadata_json: serde_json::json!({}),
        messages: vec![Message {
            id: None,
            idx: 0,
            role: MessageRole::User,
            author: None,
            created_at: Some(1_700_000_000),
            content: "hello".to_string(),
            extra_json: serde_json::Value::Null,
            snippets: Vec::<Snippet>::new(),
            excluded: None,
        }],
        // A remote origin host, so the source is not the bootstrap-local row
        // that `ensure_source_for_conversation` deliberately skips.
        source_id: "remote-host".to_string(),
        origin_host: Some("remote-host".to_string()),
    };

    let sources_before: i64 = conn
        .query_row_map("SELECT COUNT(*) FROM sources", &[], |row| row.get_typed(0))
        .expect("baseline source count");

    let aborted = conn.with_tx(TxMode::Immediate, |tx| {
        storage
            .install_conversation_projection_in_tx(
                tx,
                1,
                None,
                &conversation,
                &Sha256Digest::of(b"input"),
                0,
                &[],
            )
            .map_err(|err| StorageError::Corrupt { detail: err.to_string() })?;
        Err::<(), StorageError>(StorageError::Other {
            code: None,
            detail: "the caller aborts after the projection".to_string(),
        })
    });
    assert!(aborted.is_err(), "the transaction was asked to abort");

    let sources_after: i64 = conn
        .query_row_map("SELECT COUNT(*) FROM sources", &[], |row| row.get_typed(0))
        .expect("count sources");
    assert_eq!(
        sources_after, sources_before,
        "an aborted projection must not leave its parent source row behind: the row has to \
         be written inside the caller's transaction, not in autocommit"
    );
    let conversations: i64 = conn
        .query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| row.get_typed(0))
        .expect("count conversations");
    assert_eq!(conversations, 0);
}

#[test]
fn deleting_a_canonical_linked_message_is_refused_until_historyized() {
    let conn = memory_conn();
    apply_ddl(&conn, &[]);
    // The links table's message FK targets `messages`; give it a minimal parent.
    // Foreign-key enforcement is on for this connection, so the parent table
    // and the referenced row must both exist.
    create_messages_parent(&conn);
    insert_source_input(&conn, "staged", false).expect("parent input row");
    insert_record(&conn, "payload_absent", None).expect("parent record row");
    insert_link(&conn, &projection_key(1), Some("canonical"), Some(7), true)
        .expect("canonical link to the live message");

    // §6: the FK's `ON DELETE SET NULL` and the canonical CHECK together make
    // this delete impossible at the SQL layer. The refusal surfaces as the
    // CHECK the SET NULL action would break, not as a plain FK error, because
    // SQLite applies the referential action and then rejects the result.
    let err = conn
        .execute("DELETE FROM messages WHERE id = 7;", &[])
        .expect_err("deleting a canonically linked message must be refused");
    let text = err.to_string();
    assert!(
        text.contains("CHECK") || text.contains("FOREIGN KEY"),
        "unexpected error: {text}"
    );

    // The contract's funnel: historyize first (same transaction), then delete.
    conn.execute_batch(
        "UPDATE source_message_links SET authority = 'historical', message_id = NULL \
         WHERE authority = 'canonical';",
    )
    .expect("historyize the link");
    conn.execute("DELETE FROM messages WHERE id = 7;", &[]).expect("delete after historyizing");
}
