//! Isolated Schema 9 legacy compatibility integration tests.
//!
//! Proves that after retiring Scheme B (`source_inputs` / `source_records` /
//! `source_message_links` writers), a real Schema 9 archive that still carries
//! those three legacy tables (with their exact frozen DDL, `ON DELETE SET NULL`
//! FK, and canonical CHECK constraint) continues to work seamlessly across:
//! 1. Opening, reading, and searching (`cass search`).
//! 2. Deleting messages via `forget_conversations_by_source_glob` and
//!    `collapse_external_id_prefix_duplicates` without triggering SQLite
//!    `CHECK constraint failed` on `source_message_links` (affected links are
//!    demoted to `authority = 'historical', message_id IS NULL`).
//! 3. `cass mirror prune --dry-run` and `--apply` protecting BOTH legacy
//!    absolute-path `messages.excluded.raw.blob` entries AND blobs referenced
//!    by unfinished (`state = 'staged'`) `source_inputs.sealed_ref_bin` rows,
//!    while pruning genuinely unreferenced old blobs without self-locking.
//! 4. Incremental `cass index` refusing to skip a file whose `(size, mtime)`
//!    matches `scan_file_state` (with future `scan_watermarks`) when a legacy
//!    `source_inputs` row for that locator has `state = 'staged'`, ingesting
//!    its conversation cleanly and making it searchable.

use std::fs::{self, File, FileTimes};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::raw_mirror::{RawMirrorCaptureInput, capture_source_file};
use coding_agent_search::storage::api::{Conn, Value as SqlValue};
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde_json::{Value, json};
use tempfile::TempDir;

/// Exact frozen Schema 9 legacy DDL statements (with `ON DELETE SET NULL` +
/// canonical CHECK constraint on `source_message_links`).
const LEGACY_SCHEMA9_SOURCE_DDL: [&str; 5] = [
    r#"CREATE TABLE source_inputs (
  id INTEGER PRIMARY KEY,
  input_key BLOB NOT NULL UNIQUE CHECK(typeof(input_key)='blob' AND length(input_key)=32),
  identity_tuple_bin BLOB NOT NULL,
  source_id TEXT NOT NULL,
  identity_namespace TEXT NOT NULL,
  connector TEXT NOT NULL,
  origin_host TEXT,
  origin_source_version TEXT,
  role_bin BLOB CHECK(role_bin IS NULL OR typeof(role_bin)='blob'),
  platform_bin BLOB CHECK(platform_bin IS NULL OR typeof(platform_bin)='blob'),
  root_id_bin BLOB NOT NULL,
  relative_locator_bin BLOB NOT NULL,
  discovery_bin BLOB NOT NULL,
  parser_context_bin BLOB NOT NULL,
  context_digest BLOB NOT NULL CHECK(typeof(context_digest)='blob' AND length(context_digest)=32),
  sealed_ref_bin BLOB NOT NULL,
  sealed_sha256 BLOB NOT NULL CHECK(typeof(sealed_sha256)='blob' AND length(sealed_sha256)=32),
  byte_len BLOB NOT NULL CHECK(typeof(byte_len)='blob' AND length(byte_len)=8),
  format TEXT NOT NULL CHECK(format IN ('jsonl','json_document')),
  expected_manifest_bin BLOB NOT NULL,
  normalizer_id TEXT NOT NULL,
  safety_contract_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('staged','partial','failed','complete')),
  expected_records BLOB NOT NULL CHECK(typeof(expected_records)='blob' AND length(expected_records)=8),
  expected_blank_lines BLOB NOT NULL CHECK(typeof(expected_blank_lines)='blob' AND length(expected_blank_lines)=8),
  observed_records BLOB CHECK(observed_records IS NULL OR (typeof(observed_records)='blob' AND length(observed_records)=8)),
  observed_blank_lines BLOB CHECK(observed_blank_lines IS NULL OR (typeof(observed_blank_lines)='blob' AND length(observed_blank_lines)=8)),
  unprocessed_ranges_bin BLOB,
  attempt_history_bin BLOB,
  activation_request_hash BLOB CHECK(activation_request_hash IS NULL OR (typeof(activation_request_hash)='blob' AND length(activation_request_hash)=32)),
  receipt_key TEXT,
  applied_content_generation TEXT,
  CHECK(state <> 'complete' OR (receipt_key IS NOT NULL AND applied_content_generation IS NOT NULL
        AND activation_request_hash IS NOT NULL AND observed_records IS NOT NULL AND observed_blank_lines IS NOT NULL)),
  CHECK(state =  'complete' OR (receipt_key IS NULL AND applied_content_generation IS NULL
        AND activation_request_hash IS NULL))
)"#,
    r#"CREATE TABLE source_records (
  id INTEGER PRIMARY KEY,
  input_id INTEGER NOT NULL REFERENCES source_inputs(id) ON DELETE CASCADE,
  ordinal BLOB NOT NULL CHECK(typeof(ordinal)='blob' AND length(ordinal)=8 AND ordinal > x'0000000000000000'),
  record_pointer TEXT NOT NULL COLLATE BINARY,
  position_bin BLOB NOT NULL,
  expected_source_record_sha256 BLOB NOT NULL CHECK(typeof(expected_source_record_sha256)='blob' AND length(expected_source_record_sha256)=32),
  observed_source_record_sha256 BLOB CHECK(observed_source_record_sha256 IS NULL OR (typeof(observed_source_record_sha256)='blob' AND length(observed_source_record_sha256)=32)),
  frame_state TEXT NOT NULL CHECK(frame_state IN ('frame_pending','staged','activated')),
  native_ids_bin BLOB,
  parse_state TEXT NOT NULL CHECK(parse_state IN ('pending','parsed','parse_failed')),
  record_mapping_state TEXT NOT NULL CHECK(record_mapping_state IN ('claims_pending','no_claims','all_canonical','all_standalone','all_unmapped','mixed')),
  safety_state TEXT NOT NULL CHECK(safety_state IN ('pending','preserved','blocked')),
  retention_state TEXT NOT NULL CHECK(retention_state IN ('payload_absent','payload_present')),
  codec TEXT CHECK(codec IS NULL OR codec = 'safe-json-msgpack/1'),
  payload_bin BLOB,
  safe_value_hash BLOB CHECK(safe_value_hash IS NULL OR (typeof(safe_value_hash)='blob' AND length(safe_value_hash)=32)),
  diagnostics_bin BLOB,
  UNIQUE(input_id, ordinal, record_pointer),
  CHECK(retention_state <> 'payload_present' OR (codec IS NOT NULL AND payload_bin IS NOT NULL AND safe_value_hash IS NOT NULL)),
  CHECK(retention_state <> 'payload_absent'  OR (codec IS NULL AND payload_bin IS NULL AND safe_value_hash IS NULL))
)"#,
    r#"CREATE INDEX idx_source_records_stream
  ON source_records(input_id, ordinal, record_pointer)"#,
    r#"CREATE INDEX idx_source_records_activated
  ON source_records(input_id, ordinal, record_pointer) WHERE frame_state = 'activated'"#,
    r#"CREATE TABLE source_message_links (
  id INTEGER PRIMARY KEY,
  record_id INTEGER NOT NULL REFERENCES source_records(id) ON DELETE CASCADE,
  projection_key BLOB NOT NULL CHECK(typeof(projection_key)='blob' AND length(projection_key)=32),
  conversation_ordinal INTEGER CHECK(conversation_ordinal IS NULL OR (typeof(conversation_ordinal)='integer' AND conversation_ordinal >= 0 AND conversation_ordinal <= 4294967295)),
  final_message_idx INTEGER CHECK(final_message_idx IS NULL OR (typeof(final_message_idx)='integer' AND final_message_idx >= 0)),
  source_positions_bin BLOB NOT NULL,
  projection_pointer TEXT COLLATE BINARY CHECK(projection_pointer IS NULL OR typeof(projection_pointer)='text'),
  message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
  authority TEXT CHECK(authority IS NULL OR authority IN ('canonical','historical','standalone','unmapped','unresolved')),
  evidence_kind TEXT NOT NULL CHECK(evidence_kind IN ('prose','tool_call','tool_result','reasoning','no_message','parse_failed')),
  binding_digest BLOB NOT NULL CHECK(typeof(binding_digest)='blob' AND length(binding_digest)=32),
  UNIQUE(record_id, projection_key),
  CHECK((conversation_ordinal IS NULL AND final_message_idx IS NULL AND projection_pointer IS NULL) OR (conversation_ordinal IS NOT NULL AND final_message_idx IS NOT NULL AND projection_pointer IS NOT NULL)),
  CHECK(authority IS NULL OR authority IN ('standalone','unmapped') OR (conversation_ordinal IS NOT NULL AND final_message_idx IS NOT NULL AND projection_pointer IS NOT NULL)),
  CHECK(authority IS NULL OR authority NOT IN ('standalone','unmapped') OR (conversation_ordinal IS NULL AND final_message_idx IS NULL AND projection_pointer IS NULL)),
  CHECK((authority IS NOT NULL AND authority='canonical' AND message_id IS NOT NULL) OR ((authority IS NULL OR authority<>'canonical') AND message_id IS NULL))
)"#,
];

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

struct LegacyFixture {
    root: TempDir,
}

impl LegacyFixture {
    fn new() -> Self {
        let root = TempDir::new().expect("tempdir");
        for dir in ["home", "data", "config", "cache", "state", "sources"] {
            fs::create_dir_all(root.path().join(dir)).expect("mkdir");
        }
        Self { root }
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir().join("agent_search.db")
    }

    fn run_cass(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(cass_bin());
        cmd.env("HOME", self.home())
            .env("XDG_DATA_HOME", self.home().join(".local/share"))
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_CACHE_HOME", self.root.path().join("cache"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("CODEX_HOME", self.home().join(".codex"))
            .env("CASS_DATA_DIR", self.data_dir())
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("NO_COLOR", "1")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("CASS_API_CONFIG")
            .env_remove("RUST_LOG");
        cmd.args(args);
        cmd.output().expect("spawn cass")
    }
}

fn attach_legacy_source_tables(storage: &FrankenStorage) {
    for ddl in LEGACY_SCHEMA9_SOURCE_DDL {
        storage
            .raw()
            .execute_batch(ddl)
            .expect("create legacy schema 9 source table");
    }
    storage
        .raw()
        .execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('source_facts_revision', '1')",
            &[],
        )
        .expect("seed legacy source_facts_revision");
}

fn insert_legacy_source_input(
    conn: &Conn,
    seed_byte: u8,
    connector: &str,
    root_id: &str,
    relative_locator: &str,
    sealed_ref_json: &[u8],
    state: &str,
) -> i64 {
    let key32 = vec![seed_byte; 32];
    let u64_one = 1u64.to_be_bytes().to_vec();
    let u64_zero = 0u64.to_be_bytes().to_vec();
    let (obs_rec, obs_blank, act_hash, receipt, applied_gen) = if state == "complete" {
        (
            SqlValue::Blob(u64_one.clone()),
            SqlValue::Blob(u64_zero.clone()),
            SqlValue::Blob(key32.clone()),
            SqlValue::Text(format!("rcpt-{seed_byte}")),
            SqlValue::Text(format!("gen-{seed_byte}")),
        )
    } else {
        (
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
        )
    };
    conn.execute(
        "INSERT INTO source_inputs (
            input_key, identity_tuple_bin, source_id, identity_namespace, connector,
            origin_host, root_id_bin, relative_locator_bin, discovery_bin, parser_context_bin,
            context_digest, sealed_ref_bin, sealed_sha256, byte_len, format,
            expected_manifest_bin, normalizer_id, safety_contract_id, state,
            expected_records, expected_blank_lines, observed_records, observed_blank_lines,
            activation_request_hash, receipt_key, applied_content_generation
         ) VALUES (
            ?1, ?2, 'local', 'local', ?3,
            'local', ?4, ?5, ?6, ?7,
            ?8, ?9, ?10, ?11, 'jsonl',
            ?12, 'norm/1', 'safety/1', ?13,
            ?14, ?15, ?16, ?17,
            ?18, ?19, ?20
         )",
        &[
            SqlValue::Blob(key32.clone()),
            SqlValue::Blob(b"{}".to_vec()),
            SqlValue::Text(connector.to_string()),
            SqlValue::Blob(root_id.as_bytes().to_vec()),
            SqlValue::Blob(relative_locator.as_bytes().to_vec()),
            SqlValue::Blob(b"{}".to_vec()),
            SqlValue::Blob(b"{}".to_vec()),
            SqlValue::Blob(key32.clone()),
            SqlValue::Blob(sealed_ref_json.to_vec()),
            SqlValue::Blob(key32),
            SqlValue::Blob(128u64.to_be_bytes().to_vec()),
            SqlValue::Blob(b"{}".to_vec()),
            SqlValue::Text(state.to_string()),
            SqlValue::Blob(u64_one),
            SqlValue::Blob(u64_zero),
            obs_rec,
            obs_blank,
            act_hash,
            receipt,
            applied_gen,
        ],
    )
    .expect("insert legacy source_inputs row");
    conn.query_row_map("SELECT last_insert_rowid()", &[], |r| r.get_typed(0))
        .expect("last_insert_rowid")
}

fn insert_legacy_canonical_link(conn: &Conn, input_id: i64, seed_byte: u8, message_id: i64) -> i64 {
    let key32 = vec![seed_byte; 32];
    conn.execute(
        "INSERT INTO source_records (
            input_id, ordinal, record_pointer, position_bin,
            expected_source_record_sha256, frame_state, parse_state,
            record_mapping_state, safety_state, retention_state
         ) VALUES (?1, ?2, ?3, ?4, ?5, 'activated', 'parsed', 'all_canonical', 'preserved', 'payload_absent')",
        &[
            SqlValue::Integer(input_id),
            SqlValue::Blob(u64::from(seed_byte.max(1)).to_be_bytes().to_vec()),
            SqlValue::Text(format!("line:{seed_byte}")),
            SqlValue::Blob(b"{}".to_vec()),
            SqlValue::Blob(key32.clone()),
        ],
    )
    .expect("insert legacy source_records row");
    let record_id: i64 = conn
        .query_row_map("SELECT last_insert_rowid()", &[], |r| r.get_typed(0))
        .expect("record_id");
    conn.execute(
        "INSERT INTO source_message_links (
            record_id, projection_key, conversation_ordinal, final_message_idx,
            source_positions_bin, projection_pointer, message_id, authority,
            evidence_kind, binding_digest
         ) VALUES (?1, ?2, 0, 0, ?3, 'messages/0', ?4, 'canonical', 'prose', ?5)",
        &[
            SqlValue::Integer(record_id),
            SqlValue::Blob(key32.clone()),
            SqlValue::Blob(b"[]".to_vec()),
            SqlValue::Integer(message_id),
            SqlValue::Blob(key32),
        ],
    )
    .expect("insert legacy canonical source_message_links row");
    conn.query_row_map("SELECT last_insert_rowid()", &[], |r| r.get_typed(0))
        .expect("link_id")
}

fn seed_conversation(
    storage: &FrankenStorage,
    agent_id: i64,
    external_id: &str,
    source_path: &Path,
    content: &str,
) -> (i64, i64) {
    let conv = Conversation {
        id: None,
        agent_slug: "claude_code".to_string(),
        workspace: None,
        external_id: Some(external_id.to_string()),
        title: Some(format!("title {external_id}")),
        source_path: source_path.to_path_buf(),
        started_at: Some(1_700_000_000_000),
        ended_at: Some(1_700_000_001_000),
        approx_tokens: Some(16),
        metadata_json: json!({}),
        messages: vec![Message {
            id: None,
            idx: 0,
            role: MessageRole::User,
            author: Some("user".to_string()),
            created_at: Some(1_700_000_000_000),
            content: content.to_string(),
            extra_json: json!({}),
            snippets: Vec::new(),
            excluded: None,
        }],
        source_id: "local".to_string(),
        origin_host: Some("local".to_string()),
    };
    let outcome = storage
        .insert_conversation_tree(agent_id, None, &conv)
        .expect("insert conversation");
    let msg_id: i64 = storage
        .raw()
        .query_row_map(
            "SELECT id FROM messages WHERE conversation_id = ?1 AND idx = 0",
            &[SqlValue::Integer(outcome.conversation_id)],
            |r| r.get_typed(0),
        )
        .expect("fetch message id");
    (outcome.conversation_id, msg_id)
}

fn backdate_mirror_manifests(mirror_root: &Path, age: Duration) {
    let target_ms = i64::try_from(
        SystemTime::now()
            .checked_sub(age)
            .expect("backdate time")
            .duration_since(UNIX_EPOCH)
            .expect("unix epoch")
            .as_millis(),
    )
    .expect("target ms");
    let target_time = SystemTime::now().checked_sub(age).expect("backdate time");
    let times = FileTimes::new().set_modified(target_time);
    for entry in walkdir::WalkDir::new(mirror_root)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path
            .components()
            .any(|c| c.as_os_str() == "manifests")
            && path.extension().and_then(|e| e.to_str()) == Some("json")
        {
            let mut val: Value =
                serde_json::from_slice(&fs::read(path).expect("read manifest")).expect("json");
            val["captured_at_ms"] = json!(target_ms);
            fs::write(path, serde_json::to_vec_pretty(&val).expect("encode"))
                .expect("rewrite manifest captured_at_ms");
        }
        if let Ok(file) = File::options().write(true).open(path) {
            let _ = file.set_times(times);
        }
    }
}

#[test]
fn schema9_legacy_deletions_demote_canonical_links_without_check_failure() {
    let fixture = LegacyFixture::new();
    let storage = FrankenStorage::open(&fixture.db_path()).expect("open schema 9 storage");
    attach_legacy_source_tables(&storage);

    let agent_id = storage
        .ensure_agent(&Agent {
            id: None,
            slug: "claude_code".to_string(),
            name: "Claude Code".to_string(),
            version: None,
            kind: AgentKind::Cli,
        })
        .expect("ensure claude_code agent");

    // 1. Conversation targeted by `forget_conversations_by_source_glob`.
    let forget_path = fixture
        .home()
        .join(".claude/projects/legacy-forget/s1.jsonl");
    let (_forget_conv_id, forget_msg_id) = seed_conversation(
        &storage,
        agent_id,
        "legacy-forget/s1",
        &forget_path,
        "legacy schema9 forgettable message alpha",
    );
    let forget_input_id = insert_legacy_source_input(
        storage.raw(),
        11,
        "claude_code",
        "/legacy/root",
        "projects/legacy-forget/s1.jsonl",
        b"{}",
        "complete",
    );
    let forget_link_id =
        insert_legacy_canonical_link(storage.raw(), forget_input_id, 11, forget_msg_id);

    // 2. Prefix-duplicate pair targeted by `collapse_external_id_prefix_duplicates`.
    let dup_path = fixture.home().join(".claude/projects/legacy-dup/s2.jsonl");
    let (dup_conv_id, dup_msg_id) = seed_conversation(
        &storage,
        agent_id,
        "projects/legacy-dup/s2",
        &dup_path,
        "legacy schema9 duplicate message beta",
    );
    let (keep_conv_id, keep_msg_id) = seed_conversation(
        &storage,
        agent_id,
        "legacy-dup/s2",
        &dup_path,
        "legacy schema9 canonical keeper message gamma",
    );
    let dup_input_id = insert_legacy_source_input(
        storage.raw(),
        22,
        "claude_code",
        "/legacy/root",
        "projects/legacy-dup/s2.jsonl",
        b"{}",
        "complete",
    );
    let dup_link_id = insert_legacy_canonical_link(storage.raw(), dup_input_id, 22, dup_msg_id);
    let keep_link_id = insert_legacy_canonical_link(storage.raw(), dup_input_id, 23, keep_msg_id);

    // Verify forget succeeds without `CHECK constraint failed` and demotes the link.
    let forget_res = storage
        .forget_conversations_by_source_glob("*legacy-forget*", false)
        .expect("forget on legacy schema 9 DB must succeed");
    assert_eq!(forget_res.conversations_deleted, 1);
    let (forget_auth, forget_mid): (Option<String>, Option<i64>) = storage
        .raw()
        .query_row_map(
            "SELECT authority, message_id FROM source_message_links WHERE id = ?1",
            &[SqlValue::Integer(forget_link_id)],
            |r| Ok((r.get_typed(0)?, r.get_typed(1)?)),
        )
        .expect("query demoted forget link");
    assert_eq!(forget_auth.as_deref(), Some("historical"));
    assert_eq!(forget_mid, None);

    // Verify prefix duplicate collapse succeeds without `CHECK constraint failed`.
    let collapse_res = storage
        .collapse_external_id_prefix_duplicates(false)
        .expect("collapse_external_id_prefix_duplicates on legacy schema 9 DB must succeed");
    assert_eq!(collapse_res.conversations_affected, 1);
    let dup_exists: i64 = storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM conversations WHERE id = ?1",
            &[SqlValue::Integer(dup_conv_id)],
            |r| r.get_typed(0),
        )
        .expect("check dup deleted");
    assert_eq!(dup_exists, 0);
    let keep_exists: i64 = storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM conversations WHERE id = ?1",
            &[SqlValue::Integer(keep_conv_id)],
            |r| r.get_typed(0),
        )
        .expect("check keeper retained");
    assert_eq!(keep_exists, 1);

    let (dup_auth, dup_mid): (Option<String>, Option<i64>) = storage
        .raw()
        .query_row_map(
            "SELECT authority, message_id FROM source_message_links WHERE id = ?1",
            &[SqlValue::Integer(dup_link_id)],
            |r| Ok((r.get_typed(0)?, r.get_typed(1)?)),
        )
        .expect("query demoted dup link");
    assert_eq!(dup_auth.as_deref(), Some("historical"));
    assert_eq!(dup_mid, None);

    // Untouched keeper link remains canonical and bound to keep_msg_id.
    let (keep_auth, keep_mid): (Option<String>, Option<i64>) = storage
        .raw()
        .query_row_map(
            "SELECT authority, message_id FROM source_message_links WHERE id = ?1",
            &[SqlValue::Integer(keep_link_id)],
            |r| Ok((r.get_typed(0)?, r.get_typed(1)?)),
        )
        .expect("query untouched keeper link");
    assert_eq!(keep_auth.as_deref(), Some("canonical"));
    assert_eq!(keep_mid, Some(keep_msg_id));

    drop(storage);

    // Open & search via real CLI against the legacy Schema 9 DB with all 3 legacy tables present.
    let search_out = fixture.run_cass(&[
        "search",
        "keeper",
        "--mode",
        "lexical",
        "--data-dir",
        fixture.data_dir().to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(
        search_out.status.code(),
        Some(0),
        "cass search must succeed on legacy Schema 9 DB; stderr={}",
        String::from_utf8_lossy(&search_out.stderr)
    );
    let search_json: Value =
        serde_json::from_slice(&search_out.stdout).expect("search output json");
    assert!(
        search_json["hits"]
            .as_array()
            .is_some_and(|hits| !hits.is_empty()),
        "search should find keeper message in legacy Schema 9 DB: {search_json}"
    );
}

#[test]
fn schema9_legacy_mirror_prune_protects_absolute_excluded_and_staged_blobs() {
    let fixture = LegacyFixture::new();
    let storage = FrankenStorage::open(&fixture.db_path()).expect("open schema 9 storage");
    attach_legacy_source_tables(&storage);

    let agent_id = storage
        .ensure_agent(&Agent {
            id: None,
            slug: "claude_code".to_string(),
            name: "Claude Code".to_string(),
            version: None,
            kind: AgentKind::Cli,
        })
        .expect("ensure agent");

    // Create 3 distinct raw-mirror blobs:
    // 1. abs_blob: referenced only via legacy absolute path in messages.excluded.raw.blob
    // 2. staged_blob: referenced only via source_inputs (state='staged') sealed_ref_bin
    // 3. orphan_blob: unreferenced, should be deleted by `mirror prune --apply`
    let src_abs = fixture.root.path().join("sources/abs-protected.jsonl");
    let src_staged = fixture.root.path().join("sources/staged-protected.jsonl");
    let src_orphan = fixture.root.path().join("sources/orphan-prunable.jsonl");
    fs::write(&src_abs, "{\"payload\":\"abs-protected-blob\"}\n").unwrap();
    fs::write(&src_staged, "{\"payload\":\"staged-protected-blob\"}\n").unwrap();
    fs::write(&src_orphan, "{\"payload\":\"orphan-prunable-blob\"}\n").unwrap();

    let cap_abs = capture_source_file(RawMirrorCaptureInput {
        data_dir: &fixture.data_dir(),
        provider: "claude_code",
        source_id: "local",
        origin_kind: "local",
        origin_host: Some("local"),
        source_path: &src_abs,
        db_links: &[],
    })
    .expect("capture abs blob");
    let cap_staged = capture_source_file(RawMirrorCaptureInput {
        data_dir: &fixture.data_dir(),
        provider: "claude_code",
        source_id: "local",
        origin_kind: "local",
        origin_host: Some("local"),
        source_path: &src_staged,
        db_links: &[],
    })
    .expect("capture staged blob");
    let cap_orphan = capture_source_file(RawMirrorCaptureInput {
        data_dir: &fixture.data_dir(),
        provider: "claude_code",
        source_id: "local",
        origin_kind: "local",
        origin_host: Some("local"),
        source_path: &src_orphan,
        db_links: &[],
    })
    .expect("capture orphan blob");

    let mirror_root = fixture.data_dir().join("raw-mirror/v1");
    let abs_blob_disk = mirror_root.join(&cap_abs.blob_relative_path);
    let staged_blob_disk = mirror_root.join(&cap_staged.blob_relative_path);
    let orphan_blob_disk = mirror_root.join(&cap_orphan.blob_relative_path);
    assert!(abs_blob_disk.is_file());
    assert!(staged_blob_disk.is_file());
    assert!(orphan_blob_disk.is_file());

    // Reference abs_blob using the legacy ABSOLUTE path format in `messages.excluded.raw.blob`.
    let (_conv_id, msg_id) = seed_conversation(
        &storage,
        agent_id,
        "legacy-abs-ref",
        &src_abs,
        "",
    );
    let legacy_excluded = json!({
        "reason": "cass_recall",
        "rule_version": 2,
        "raw": {
            "blob": abs_blob_disk.to_string_lossy()
        }
    })
    .to_string();
    storage
        .raw()
        .execute(
            "UPDATE messages SET excluded = jsonb(?1) WHERE id = ?2",
            &[SqlValue::Text(legacy_excluded), SqlValue::Integer(msg_id)],
        )
        .expect("stamp legacy absolute excluded marker");

    // Reference staged_blob via a `state = 'staged'` legacy `source_inputs` row.
    let sealed_ref_json = json!({
        "transport": "raw_blob",
        "blob_algorithm": "blake3",
        "blob_digest": cap_staged.blob_blake3,
        "blob_relative_path": cap_staged.blob_relative_path
    })
    .to_string();
    insert_legacy_source_input(
        storage.raw(),
        44,
        "claude_code",
        "/legacy/staged-root",
        "projects/p/staged.jsonl",
        sealed_ref_json.as_bytes(),
        "staged",
    );
    drop(storage);

    // Backdate mirror manifests' `captured_at_ms` & file mtimes by 10 days so
    // `--older-than 1d --safety-hold-down 0s` targets all 3.
    backdate_mirror_manifests(&mirror_root, Duration::from_secs(10 * 24 * 3600));

    let data_dir_str = fixture.data_dir().to_string_lossy().into_owned();

    // Dry-run must succeed and keep all files untouched.
    let dry_out = fixture.run_cass(&[
        "mirror",
        "prune",
        "--data-dir",
        &data_dir_str,
        "--older-than",
        "1d",
        "--safety-hold-down",
        "0s",
        "--json",
    ]);
    assert_eq!(
        dry_out.status.code(),
        Some(0),
        "mirror prune dry-run failed: stderr={}",
        String::from_utf8_lossy(&dry_out.stderr)
    );
    assert!(abs_blob_disk.is_file());
    assert!(staged_blob_disk.is_file());
    assert!(orphan_blob_disk.is_file());

    // Apply must succeed (no self-lock, no out-of-root stat error on legacy absolute path),
    // delete ONLY the unreferenced orphan blob, and keep BOTH protected blobs intact.
    let apply_out = fixture.run_cass(&[
        "mirror",
        "prune",
        "--data-dir",
        &data_dir_str,
        "--older-than",
        "1d",
        "--safety-hold-down",
        "0s",
        "--apply",
        "--json",
    ]);
    assert_eq!(
        apply_out.status.code(),
        Some(0),
        "mirror prune --apply failed: stderr={}",
        String::from_utf8_lossy(&apply_out.stderr)
    );
    assert!(
        abs_blob_disk.is_file(),
        "legacy absolute-path messages.excluded.raw.blob must be protected from prune"
    );
    assert!(
        staged_blob_disk.is_file(),
        "legacy staged source_inputs.sealed_ref_bin blob must be protected from prune"
    );
    assert!(
        !orphan_blob_disk.exists(),
        "unreferenced old orphan blob must be pruned so the protection test is non-vacuous"
    );
}

#[test]
fn schema9_legacy_staged_source_input_is_not_skipped_by_incremental_scan() {
    let fixture = LegacyFixture::new();
    let claude_root = fixture.home().join(".claude");
    let session_path = claude_root.join("projects/legacy-staged/session.jsonl");
    fs::create_dir_all(session_path.parent().unwrap()).expect("mkdir claude project");

    let session_body = format!(
        "{}\n{}\n",
        json!({
            "type": "user",
            "timestamp": "2026-01-06T00:00:00.000Z",
            "uuid": "staged-u0",
            "sessionId": "legacy-staged-session",
            "cwd": "/synthetic/legacy-staged",
            "message": {"role": "user", "content": "schema9 staged unfinished rescue needle"}
        }),
        json!({
            "type": "assistant",
            "timestamp": "2026-01-06T00:00:01.000Z",
            "uuid": "staged-a1",
            "sessionId": "legacy-staged-session",
            "cwd": "/synthetic/legacy-staged",
            "message": {"role": "assistant", "content": "schema9 staged unfinished rescue answer"}
        }),
    );
    fs::write(&session_path, session_body.as_bytes()).expect("write claude session");

    let meta = fs::metadata(&session_path).expect("stat session");
    let size = i64::try_from(meta.len()).expect("size i64");
    let mtime_ms = i64::try_from(
        meta.modified()
            .expect("mtime")
            .duration_since(UNIX_EPOCH)
            .expect("unix epoch")
            .as_millis(),
    )
    .expect("mtime i64");

    let canonical_claude_root = fs::canonicalize(&claude_root).expect("canonical claude root");
    let root_id = format!("home:claude:{}", canonical_claude_root.display());

    // Build a Schema 9 legacy DB where `scan_watermarks` & `scan_file_state` claim the
    // file is ALREADY up-to-date, NO conversation row exists yet, and `source_inputs`
    // records the file as `state = 'staged'` (simulating an interrupted Scheme B commit).
    let storage = FrankenStorage::open(&fixture.db_path()).expect("open storage");
    attach_legacy_source_tables(&storage);
    storage
        .set_scan_watermark(&root_id, "claude", mtime_ms + 60_000)
        .expect("seed future scan watermark");
    storage
        .upsert_scan_file_state(
            &root_id,
            "claude",
            "projects/legacy-staged/session.jsonl",
            size,
            mtime_ms,
            mtime_ms + 60_000,
        )
        .expect("seed matching scan_file_state");
    insert_legacy_source_input(
        storage.raw(),
        77,
        "claude_code",
        canonical_claude_root.to_str().unwrap(),
        "projects/legacy-staged/session.jsonl",
        b"{}",
        "staged",
    );
    drop(storage);

    // Run normal incremental `cass index` (NOT `--full`). Because `source_inputs` has
    // `state = 'staged'`, Plan A must NOT skip the file on matching `(size, mtime)`.
    let data_dir_str = fixture.data_dir().to_string_lossy().into_owned();
    let index_out = fixture.run_cass(&["index", "--data-dir", &data_dir_str, "--json"]);
    assert_eq!(
        index_out.status.code(),
        Some(0),
        "incremental index failed: stderr={}",
        String::from_utf8_lossy(&index_out.stderr)
    );
    let report: Value = serde_json::from_slice(&index_out.stdout).expect("index json");
    assert_eq!(report["success"], json!(true));

    let conn = Conn::open_read(&fixture.db_path()).expect("reopen db");
    let rescued: i64 = conn
        .query_row_map(
            "SELECT COUNT(*) FROM messages WHERE content LIKE '%schema9 staged unfinished rescue needle%'",
            &[],
            |r| r.get_typed(0),
        )
        .expect("query rescued message");
    assert_eq!(
        rescued, 1,
        "incremental scan must not skip a legacy state='staged' file even when (size, mtime) and watermark look current"
    );
    drop(conn);

    // Confirm search finds the rescued session.
    let search_out = fixture.run_cass(&[
        "search",
        "rescue",
        "--mode",
        "lexical",
        "--data-dir",
        &data_dir_str,
        "--json",
    ]);
    assert_eq!(
        search_out.status.code(),
        Some(0),
        "search after rescue failed: stderr={}",
        String::from_utf8_lossy(&search_out.stderr)
    );
    let search_json: Value = serde_json::from_slice(&search_out.stdout).expect("search json");
    assert!(
        search_json["hits"]
            .as_array()
            .is_some_and(|hits| !hits.is_empty()),
        "rescued legacy staged session must be searchable: {search_json}"
    );
}

/// R2-B3 + N2: historical Schema 9 raw-mirror manifests written before Plan-A
/// unification carry `provider = "claude"` while `ClaudeCodeConnector` writes
/// `agents.slug = "claude_code"`. Verify all three `cass mirror-restore` paths:
/// 1. Diverged candidate triggers `hold_diverged = 1` (never misclassified as
///    `RestoreNew` to corrupt the session).
/// 2. Strict superset triggers `Replace` (`franken_replace_conversation_messages_in_tx`),
///    demoting legacy `source_message_links` canonical rows without `CHECK` failure.
/// 3. Brand-new session restores with a non-null manifest `db_links.conversation_id`
///    (`published_without_backlink = 0`).
#[test]
fn schema9_legacy_claude_provider_mirror_restore_hold_replace_and_backlink() {
    let fixture = LegacyFixture::new();
    let claude_dir = fixture.home().join(".claude/projects/r2-b3-restore");
    fs::create_dir_all(&claude_dir).expect("mkdir claude dir");

    let diverged_path = claude_dir.join("diverged.jsonl");
    let superset_path = claude_dir.join("superset.jsonl");
    let brand_new_path = claude_dir.join("brand-new.jsonl");

    let line = |role: &str, uuid: &str, sid: &str, ts: &str, text: &str| -> String {
        json!({
            "type": role,
            "timestamp": ts,
            "uuid": uuid,
            "sessionId": sid,
            "cwd": "/synthetic/r2-b3",
            "message": {"role": role, "content": text}
        })
        .to_string()
    };

    // Seed initial 2-message sessions for diverged & superset via real `cass index`
    // so DB rows carry real `claude_code` digests & canonical agent slug.
    let diverged_db_body = format!(
        "{}\n{}\n",
        line("user", "d-u0", "sid-diverged", "2026-01-07T00:00:00.000Z", "initial question"),
        line("assistant", "d-a1", "sid-diverged", "2026-01-07T00:00:01.000Z", "DB_DIVERGED_ANSWER_KEEP_SAFE"),
    );
    let superset_db_body = format!(
        "{}\n{}\n",
        line("user", "s-u0", "sid-superset", "2026-01-07T00:01:00.000Z", "superset question"),
        line("assistant", "s-a1", "sid-superset", "2026-01-07T00:01:01.000Z", "superset answer one"),
    );
    fs::write(&diverged_path, diverged_db_body.as_bytes()).expect("write diverged db seed");
    fs::write(&superset_path, superset_db_body.as_bytes()).expect("write superset db seed");

    let data_dir_str = fixture.data_dir().to_string_lossy().into_owned();
    let seed_out = fixture.run_cass(&["index", "--data-dir", &data_dir_str, "--json"]);
    assert_eq!(
        seed_out.status.code(),
        Some(0),
        "seed index failed: stderr={}",
        String::from_utf8_lossy(&seed_out.stderr)
    );

    // Attach Schema 9 legacy source tables and canonical `source_message_links`
    // on the superset conversation's messages to verify Replace demotes them safely.
    let storage = FrankenStorage::open(&fixture.db_path()).expect("open seeded db");
    attach_legacy_source_tables(&storage);
    let superset_msg_ids: Vec<i64> = storage
        .raw()
        .query_all_map(
            "SELECT m.id FROM messages m JOIN conversations c ON c.id = m.conversation_id \
             WHERE c.source_path = ?1 ORDER BY m.idx",
            &[SqlValue::Text(superset_path.to_string_lossy().into_owned())],
            |r| r.get_typed(0),
        )
        .expect("query superset messages");
    assert_eq!(superset_msg_ids.len(), 2);
    let superset_input_id = insert_legacy_source_input(
        storage.raw(),
        91,
        "claude_code",
        "/legacy/restore-root",
        "projects/r2-b3-restore/superset.jsonl",
        b"{}",
        "complete",
    );
    let superset_link_ids: Vec<i64> = superset_msg_ids
        .iter()
        .enumerate()
        .map(|(i, &mid)| {
            insert_legacy_canonical_link(storage.raw(), superset_input_id, 210 + i as u8, mid)
        })
        .collect();
    drop(storage);

    // Build a separate mirror data_dir populated with legacy `provider = "claude"` manifests:
    // (a) diverged (conflicting idx=1 + extra idx=2)
    // (b) strict superset (same idx=0,1 + new idx=2)
    // (c) brand-new (absent from candidate DB)
    let mirror_dir = fixture.root.path().join("legacy-mirror-data");
    fs::create_dir_all(&mirror_dir).expect("mkdir mirror_dir");

    let diverged_mirror_body = format!(
        "{}\n{}\n{}\n",
        line("user", "d-u0", "sid-diverged", "2026-01-07T00:00:00.000Z", "initial question"),
        line("assistant", "d-a1", "sid-diverged", "2026-01-07T00:00:01.000Z", "MIRROR_CONFLICTING_ANSWER"),
        line("user", "d-u2", "sid-diverged", "2026-01-07T00:00:02.000Z", "MIRROR_DIVERGED_TAIL_APPENDED"),
    );
    let superset_mirror_body = format!(
        "{}\n{}\n{}\n",
        line("user", "s-u0", "sid-superset", "2026-01-07T00:01:00.000Z", "superset question"),
        line("assistant", "s-a1", "sid-superset", "2026-01-07T00:01:01.000Z", "superset answer one"),
        line("user", "s-u2", "sid-superset", "2026-01-07T00:01:02.000Z", "SUPERSET_NEW_TAIL_MESSAGE"),
    );
    let brand_new_mirror_body = format!(
        "{}\n{}\n",
        line("user", "n-u0", "sid-brand-new", "2026-01-07T00:02:00.000Z", "brand new legacy claude question"),
        line("assistant", "n-a1", "sid-brand-new", "2026-01-07T00:02:01.000Z", "brand new legacy claude answer"),
    );
    fs::write(&diverged_path, diverged_mirror_body.as_bytes()).expect("write diverged mirror src");
    fs::write(&superset_path, superset_mirror_body.as_bytes()).expect("write superset mirror src");
    fs::write(&brand_new_path, brand_new_mirror_body.as_bytes()).expect("write brand-new mirror src");

    let mut brand_new_manifest_rel = String::new();
    for (path, is_brand_new) in [
        (&diverged_path, false),
        (&superset_path, false),
        (&brand_new_path, true),
    ] {
        let cap = capture_source_file(RawMirrorCaptureInput {
            data_dir: &mirror_dir,
            provider: "claude",
            source_id: "local",
            origin_kind: "local",
            origin_host: Some("local"),
            source_path: path,
            db_links: &[],
        })
        .expect("capture legacy provider=claude manifest");
        if is_brand_new {
            brand_new_manifest_rel = cap.manifest_relative_path;
        }
    }

    let cand_db_str = fixture.db_path().to_string_lossy().into_owned();
    let mirror_dir_str = mirror_dir.to_string_lossy().into_owned();
    let scratch_dry = fixture.root.path().join("scratch-dry");
    fs::create_dir_all(&scratch_dry).expect("mkdir scratch-dry");

    // 1. Dry-run must see BOTH existing `claude_code` conversations despite legacy `provider="claude"`:
    //    diverged -> hold_diverged=1, superset -> replace=1, brand-new -> restore=1.
    let dry_out = fixture.run_cass(&[
        "mirror-restore",
        "--data-dir",
        &mirror_dir_str,
        "--candidate-db",
        &cand_db_str,
        "--scratch",
        scratch_dry.to_str().unwrap(),
        "--snapshot-root",
        "snap-r2-b3",
        "--json",
    ]);
    assert_eq!(
        dry_out.status.code(),
        Some(0),
        "mirror-restore dry-run failed: stderr={}",
        String::from_utf8_lossy(&dry_out.stderr)
    );
    let dry_json: Value = serde_json::from_slice(&dry_out.stdout).expect("dry-run json");
    assert_eq!(dry_json["identities_considered"], json!(3), "dry={dry_json}");
    assert_eq!(dry_json["candidate_versions_seen"], json!(2), "must match claude_code DB rows: {dry_json}");
    assert_eq!(dry_json["hold_diverged"], json!(1), "diverged claude row must HOLD: {dry_json}");
    assert_eq!(dry_json["replace"], json!(1), "superset claude row must plan Replace: {dry_json}");
    assert_eq!(dry_json["restore"], json!(1), "brand-new claude row must plan RestoreNew: {dry_json}");
    assert_eq!(dry_json["planned_actions"], json!(2), "only Replace + RestoreNew planned: {dry_json}");

    // 2. Apply must execute Replace (demoting legacy source_message_links without CHECK error)
    //    and RestoreNew (publishing non-null backlink), while leaving diverged conversation untouched!
    let scratch_apply = fixture.root.path().join("scratch-apply");
    fs::create_dir_all(&scratch_apply).expect("mkdir scratch-apply");
    let journal_path = fixture.root.path().join("restore-r2-b3.journal.json");
    let apply_out = fixture.run_cass(&[
        "mirror-restore",
        "--data-dir",
        &mirror_dir_str,
        "--candidate-db",
        &cand_db_str,
        "--scratch",
        scratch_apply.to_str().unwrap(),
        "--snapshot-root",
        "snap-r2-b3",
        "--generation",
        "gen-r2-b3",
        "--journal",
        journal_path.to_str().unwrap(),
        "--apply",
        "--json",
    ]);
    assert_eq!(
        apply_out.status.code(),
        Some(0),
        "mirror-restore --apply failed: stderr={}",
        String::from_utf8_lossy(&apply_out.stderr)
    );
    let apply_json: Value = serde_json::from_slice(&apply_out.stdout).expect("apply json");
    assert_eq!(apply_json["applied"], json!(true), "apply={apply_json}");
    assert_eq!(apply_json["replaced"], json!(1), "apply={apply_json}");
    assert_eq!(apply_json["restored"], json!(1), "apply={apply_json}");
    assert_eq!(apply_json["published"], json!(2), "apply={apply_json}");
    assert_eq!(
        apply_json["published_without_backlink"],
        json!(0),
        "legacy provider=claude RestoreNew must resolve its claude_code conversation_id backlink: {apply_json}"
    );

    let conn = Conn::open_read(&fixture.db_path()).expect("reopen cand db");
    // Diverged conversation remained intact (2 messages, no appended tail).
    let diverged_msgs: Vec<String> = conn
        .query_all_map(
            "SELECT m.content FROM messages m JOIN conversations c ON c.id = m.conversation_id \
             WHERE c.source_path = ?1 ORDER BY m.idx",
            &[SqlValue::Text(diverged_path.to_string_lossy().into_owned())],
            |r| r.get_typed(0),
        )
        .expect("query diverged msgs");
    assert_eq!(
        diverged_msgs,
        vec![
            "initial question".to_string(),
            "DB_DIVERGED_ANSWER_KEEP_SAFE".to_string(),
        ],
        "diverged session must not be corrupted by mirror-restore"
    );

    // Superset conversation replaced cleanly with 3 messages.
    let superset_msgs: Vec<String> = conn
        .query_all_map(
            "SELECT m.content FROM messages m JOIN conversations c ON c.id = m.conversation_id \
             WHERE c.source_path = ?1 ORDER BY m.idx",
            &[SqlValue::Text(superset_path.to_string_lossy().into_owned())],
            |r| r.get_typed(0),
        )
        .expect("query superset msgs");
    assert_eq!(
        superset_msgs,
        vec![
            "superset question".to_string(),
            "superset answer one".to_string(),
            "SUPERSET_NEW_TAIL_MESSAGE".to_string(),
        ]
    );

    // Legacy canonical `source_message_links` on replaced messages were demoted cleanly.
    for link_id in superset_link_ids {
        let (auth, mid): (Option<String>, Option<i64>) = conn
            .query_row_map(
                "SELECT authority, message_id FROM source_message_links WHERE id = ?1",
                &[SqlValue::Integer(link_id)],
                |r| Ok((r.get_typed(0)?, r.get_typed(1)?)),
            )
            .expect("query demoted replace link");
        assert_eq!(auth.as_deref(), Some("historical"));
        assert_eq!(mid, None);
    }

    // Brand-new manifest has a non-null `db_links[0].conversation_id`.
    let brand_new_manifest_disk = mirror_dir.join("raw-mirror/v1").join(&brand_new_manifest_rel);
    let manifest_json: Value = serde_json::from_slice(
        &fs::read(&brand_new_manifest_disk).expect("read brand-new manifest"),
    )
    .expect("parse brand-new manifest");
    let linked_cid = manifest_json["db_links"]
        .as_array()
        .and_then(|arr| arr.iter().find_map(|link| link["conversation_id"].as_i64()));
    assert!(
        linked_cid.is_some(),
        "brand-new legacy provider=claude manifest must carry non-null conversation_id backlink: {manifest_json}"
    );
}

#[test]
fn schema9_mixed_claude_and_claude_code_manifests_unify_identity_and_relink() {
    use coding_agent_search::raw_mirror::RawMirrorDbLink;

    let line = |role: &str, uuid: &str, sid: &str, ts: &str, text: &str| -> String {
        json!({
            "type": role,
            "uuid": uuid,
            "sessionId": sid,
            "timestamp": ts,
            "message": {"role": role, "content": [{"type": "text", "text": text}]}
        })
        .to_string()
    };

    // ------------------------------------------------------------------
    // B1-A: Candidate DB has 2-msg prefix [m0, m1]. Archive has BOTH a
    // legacy `provider = "claude"` manifest (4 msgs) and a new
    // `provider = "claude_code"` manifest (3 diverged msgs) for the same
    // session. Both MUST merge into ONE RestoreIdentity group and trigger
    // `VersionDiverged` HOLD instead of planning 2 conflicting Replaces.
    // ------------------------------------------------------------------
    let fixture_a = LegacyFixture::new();
    let proj_a = fixture_a.home().join(".claude/projects/r2-b1a");
    fs::create_dir_all(&proj_a).expect("mkdir proj_a");
    let sess_a = proj_a.join("sess_a.jsonl");
    let prefix_a = format!(
        "{}\n{}\n",
        line("user", "a-u0", "sid-b1a", "2026-01-08T00:00:00.000Z", "msg 0"),
        line("assistant", "a-a1", "sid-b1a", "2026-01-08T00:00:01.000Z", "msg 1"),
    );
    fs::write(&sess_a, prefix_a.as_bytes()).expect("write prefix_a");
    let idx_a = fixture_a.run_cass(&["index", "--json"]);
    assert_eq!(idx_a.status.code(), Some(0), "seed A failed");

    let mirror_a = fixture_a.root.path().join("mirror-b1a");
    fs::create_dir_all(&mirror_a).expect("mkdir mirror_a");
    let legacy_4 = format!(
        "{}{}\n{}\n",
        prefix_a,
        line("user", "a-u2", "sid-b1a", "2026-01-08T00:00:02.000Z", "msg 2"),
        line("assistant", "a-a3", "sid-b1a", "2026-01-08T00:00:03.000Z", "KEEP_ME_M3_FROM_LEGACY_CLAUDE"),
    );
    fs::write(&sess_a, legacy_4.as_bytes()).expect("write legacy_4");
    capture_source_file(RawMirrorCaptureInput {
        data_dir: &mirror_a,
        provider: "claude",
        source_id: "local",
        origin_kind: "local",
        origin_host: Some("local"),
        source_path: &sess_a,
        db_links: &[],
    })
    .expect("capture legacy provider=claude");

    let diverged_3 = format!(
        "{}{}\n",
        prefix_a,
        line("user", "a-u2-div", "sid-b1a", "2026-01-08T00:00:02.000Z", "DIVERGED_M2_FROM_CLAUDE_CODE"),
    );
    fs::write(&sess_a, diverged_3.as_bytes()).expect("write diverged_3");
    capture_source_file(RawMirrorCaptureInput {
        data_dir: &mirror_a,
        provider: "claude_code",
        source_id: "local",
        origin_kind: "local",
        origin_host: Some("local"),
        source_path: &sess_a,
        db_links: &[],
    })
    .expect("capture new provider=claude_code");

    let scratch_a = fixture_a.root.path().join("scratch-b1a");
    fs::create_dir_all(&scratch_a).expect("mkdir scratch_a");
    let dry_a = fixture_a.run_cass(&[
        "mirror-restore",
        "--data-dir",
        mirror_a.to_str().unwrap(),
        "--candidate-db",
        fixture_a.db_path().to_str().unwrap(),
        "--scratch",
        scratch_a.to_str().unwrap(),
        "--snapshot-root",
        "snap-b1a",
        "--json",
    ]);
    assert_eq!(
        dry_a.status.code(),
        Some(0),
        "b1a dry-run failed: {}",
        String::from_utf8_lossy(&dry_a.stderr)
    );
    let dry_a_json: Value = serde_json::from_slice(&dry_a.stdout).expect("dry_a json");
    assert_eq!(dry_a_json["manifests_seen"], json!(2), "dry_a={dry_a_json}");
    assert_eq!(
        dry_a_json["identities_considered"],
        json!(1),
        "claude and claude_code manifests for same session must unify into 1 identity: {dry_a_json}"
    );
    assert_eq!(dry_a_json["replace"], json!(0), "must not plan conflicting replaces: {dry_a_json}");
    assert_eq!(dry_a_json["holds"], json!(1), "diverged mixed-provider versions must HOLD: {dry_a_json}");
    assert_eq!(dry_a_json["planned_actions"], json!(0), "dry_a={dry_a_json}");

    // ------------------------------------------------------------------
    // B1-B: Empty candidate DB + diverged "claude" & "claude_code"
    // manifests must likewise unify into 1 identity and HOLD instead of
    // planning 2 RestoreNew actions.
    // ------------------------------------------------------------------
    let fixture_b = LegacyFixture::new();
    let idx_b = fixture_b.run_cass(&["index", "--json"]);
    assert_eq!(idx_b.status.code(), Some(0), "init empty DB failed");
    let proj_b = fixture_b.home().join(".claude/projects/r2-b1b");
    fs::create_dir_all(&proj_b).expect("mkdir proj_b");
    let sess_b = proj_b.join("sess_b.jsonl");
    let mirror_b = fixture_b.root.path().join("mirror-b1b");
    fs::create_dir_all(&mirror_b).expect("mkdir mirror_b");
    fs::write(
        &sess_b,
        format!(
            "{}\n{}\n",
            line("user", "b-u0", "sid-b1b", "2026-01-08T01:00:00.000Z", "new question"),
            line("assistant", "b-a1", "sid-b1b", "2026-01-08T01:00:01.000Z", "LEGACY_ANSWER_A1"),
        ),
    )
    .expect("write sess_b v1");
    capture_source_file(RawMirrorCaptureInput {
        data_dir: &mirror_b,
        provider: "claude",
        source_id: "local",
        origin_kind: "local",
        origin_host: Some("local"),
        source_path: &sess_b,
        db_links: &[],
    })
    .expect("capture sess_b claude");
    fs::write(
        &sess_b,
        format!(
            "{}\n{}\n",
            line("user", "b-u0", "sid-b1b", "2026-01-08T01:00:00.000Z", "new question"),
            line("assistant", "b-a1-div", "sid-b1b", "2026-01-08T01:00:01.000Z", "NEW_CONFLICT_ANSWER_B1"),
        ),
    )
    .expect("write sess_b v2");
    capture_source_file(RawMirrorCaptureInput {
        data_dir: &mirror_b,
        provider: "claude_code",
        source_id: "local",
        origin_kind: "local",
        origin_host: Some("local"),
        source_path: &sess_b,
        db_links: &[],
    })
    .expect("capture sess_b claude_code");
    let scratch_b = fixture_b.root.path().join("scratch-b1b");
    fs::create_dir_all(&scratch_b).expect("mkdir scratch_b");
    let dry_b = fixture_b.run_cass(&[
        "mirror-restore",
        "--data-dir",
        mirror_b.to_str().unwrap(),
        "--candidate-db",
        fixture_b.db_path().to_str().unwrap(),
        "--scratch",
        scratch_b.to_str().unwrap(),
        "--snapshot-root",
        "snap-b1b",
        "--json",
    ]);
    assert_eq!(dry_b.status.code(), Some(0));
    let dry_b_json: Value = serde_json::from_slice(&dry_b.stdout).expect("dry_b json");
    assert_eq!(dry_b_json["identities_considered"], json!(1), "dry_b={dry_b_json}");
    assert_eq!(dry_b_json["restore"], json!(0), "dry_b={dry_b_json}");
    assert_eq!(dry_b_json["holds"], json!(1), "dry_b={dry_b_json}");
    assert_eq!(dry_b_json["planned_actions"], json!(0), "dry_b={dry_b_json}");

    // ------------------------------------------------------------------
    // B1-C: `cass mirror-relink --apply` on a legacy `provider = "claude"`
    // manifest whose `db_links` already points at the `claude_code` DB row
    // MUST preserve `db_links` intact (0 changes, 0 findings).
    // ------------------------------------------------------------------
    let fixture_c = LegacyFixture::new();
    let proj_c = fixture_c.home().join(".claude/projects/r2-b1c");
    fs::create_dir_all(&proj_c).expect("mkdir proj_c");
    let sess_c = proj_c.join("relink.jsonl");
    let body_c = format!(
        "{}\n{}\n",
        line("user", "c-u0", "sid-b1c", "2026-01-08T02:00:00.000Z", "relink prompt"),
        line("assistant", "c-a1", "sid-b1c", "2026-01-08T02:00:01.000Z", "relink reply"),
    );
    fs::write(&sess_c, body_c.as_bytes()).expect("write sess_c");
    let idx_c = fixture_c.run_cass(&["index", "--json"]);
    assert_eq!(idx_c.status.code(), Some(0));

    // Remove auto-captured manifests so only our legacy `provider = "claude"` manifest is present.
    let data_dir_c = fixture_c.data_dir();
    let raw_mirror_dir = data_dir_c.join("raw-mirror");
    if raw_mirror_dir.exists() {
        fs::remove_dir_all(&raw_mirror_dir).expect("clear auto mirror");
    }

    let conn_c = Conn::open_read(&fixture_c.db_path()).expect("open db c");
    let (conv_id_c, started_at_c): (i64, Option<i64>) = conn_c
        .query_row_map(
            "SELECT id, started_at FROM conversations WHERE source_path = ?1",
            &[SqlValue::Text(sess_c.to_string_lossy().into_owned())],
            |r| Ok((r.get_typed(0)?, r.get_typed(1).ok())),
        )
        .expect("query conv c");
    drop(conn_c);

    let cap_c = capture_source_file(RawMirrorCaptureInput {
        data_dir: &data_dir_c,
        provider: "claude",
        source_id: "local",
        origin_kind: "local",
        origin_host: None,
        source_path: &sess_c,
        db_links: &[RawMirrorDbLink {
            conversation_id: Some(conv_id_c),
            message_count: Some(2),
            source_path: Some(sess_c.to_string_lossy().into_owned()),
            started_at_ms: started_at_c,
        }],
    })
    .expect("capture legacy claude manifest for relink");

    let relink_out = fixture_c.run_cass(&[
        "mirror-relink",
        "--data-dir",
        data_dir_c.to_str().unwrap(),
        "--apply",
        "--json",
    ]);
    assert_eq!(
        relink_out.status.code(),
        Some(0),
        "mirror-relink failed: {}",
        String::from_utf8_lossy(&relink_out.stderr)
    );
    let relink_json: Value = serde_json::from_slice(&relink_out.stdout).expect("relink json");
    assert_eq!(relink_json["changes"], json!(0), "must not wipe valid legacy claude db_links: {relink_json}");
    assert_eq!(relink_json["findings"], json!(0), "relink={relink_json}");
    let relink_manifest_disk = data_dir_c
        .join("raw-mirror/v1")
        .join(&cap_c.manifest_relative_path);
    let relink_manifest: Value =
        serde_json::from_slice(&fs::read(&relink_manifest_disk).expect("read relink manifest"))
            .expect("parse relink manifest");
    assert_eq!(
        relink_manifest["db_links"][0]["conversation_id"],
        json!(conv_id_c),
        "legacy provider=claude manifest db_links must remain intact after mirror-relink --apply: {relink_manifest}"
    );
}
