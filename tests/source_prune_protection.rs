//! SRC05C-P acceptance tests: `cass mirror prune` must protect the sealed
//! blobs that retry-pending source inputs still need (承载合同 §17.1).
//!
//! Every fixture here is synthetic and lives in the test's own temp
//! directory; the real raw mirror is never touched. The evidence is the disk
//! end after a real `--apply` (blob and manifest bytes) plus the canonical
//! archive read back through a fresh connection — never an in-memory set.

use assert_cmd::Command;
use coding_agent_search::raw_mirror::{RawMirrorCaptureInput, capture_source_file};
use coding_agent_search::storage::api::{Conn, Value};
use coding_agent_search::storage::sqlite::FrankenStorage;
use franken_agent_detection::LosslessSourceValue;
use std::path::PathBuf;
use tempfile::TempDir;

/// The raw mirror's on-disk root below the data dir.
const MIRROR_ROOT: [&str; 2] = ["raw-mirror", "v1"];

fn mirror_root(data_dir: &std::path::Path) -> PathBuf {
    MIRROR_ROOT
        .iter()
        .fold(data_dir.to_path_buf(), |acc, part| acc.join(part))
}

/// One synthetic capture: the manifest and the blob the real capture path
/// produced for it.
struct Captured {
    blob_relative_path: String,
    blob_blake3: String,
    blob_path: PathBuf,
    manifest_path: PathBuf,
    bytes: Vec<u8>,
}

struct Fixture {
    temp: TempDir,
    data_dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().expect("temp dir");
        let data_dir = temp.path().join("cass-data");
        std::fs::create_dir_all(&data_dir).expect("create the data dir");
        Self { temp, data_dir }
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir.join("agent_search.db")
    }

    /// Capture one synthetic session file through the real raw-mirror capture,
    /// so the manifest and the blob are produced by the producer rather than
    /// hand-written here.
    fn capture(&self, name: &str) -> Captured {
        let source_path = self.temp.path().join(format!("{name}.jsonl"));
        std::fs::write(
            &source_path,
            format!("{{\"type\":\"message\",\"text\":\"{name}\"}}\n"),
        )
        .expect("write the synthetic source file");
        let record = capture_source_file(RawMirrorCaptureInput {
            data_dir: &self.data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("capture the synthetic source into the raw mirror");
        let root = mirror_root(&self.data_dir);
        let blob_path = root.join(&record.blob_relative_path);
        Captured {
            bytes: std::fs::read(&blob_path).expect("read the captured blob"),
            blob_relative_path: record.blob_relative_path,
            blob_blake3: record.blob_blake3,
            blob_path,
            manifest_path: root.join(&record.manifest_relative_path),
        }
    }

    fn open_db(&self) -> FrankenStorage {
        FrankenStorage::open(&self.db_path()).expect("open the schema-9 fixture database")
    }

    /// `cass` with this fixture's data dir, no prompts and no color.
    fn cmd(&self) -> Command {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cass"));
        cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
        cmd.env("HOME", self.temp.path());
        cmd.env("XDG_DATA_HOME", self.temp.path().join(".local/share"));
        cmd.env("XDG_CONFIG_HOME", self.temp.path().join(".config"));
        cmd.env("CASS_DATA_DIR", &self.data_dir);
        cmd.env("NO_COLOR", "1");
        cmd
    }

    /// `cass mirror prune --older-than 0 --safety-hold-down 0 --json` with the
    /// given mode flag. `--older-than 0` selects every capture, so an
    /// unprotected blob cannot survive by accident: only the protection set
    /// keeps one alive.
    fn prune(&self, mode: &str) -> std::process::Output {
        self.cmd()
            .args([
                "mirror",
                "prune",
                "--older-than",
                "0",
                "--safety-hold-down",
                "0",
                mode,
                "--json",
            ])
            .output()
            .expect("run cass mirror prune")
    }

    /// The same invocation without `--json`. Robot mode pins the log filter
    /// to `error`, so a `tracing::warn!` is invisible there; the human form is
    /// the only one where "the read failed and fell back" can be observed.
    fn prune_plain(&self, mode: &str) -> std::process::Output {
        self.cmd()
            .args([
                "mirror",
                "prune",
                "--older-than",
                "0",
                "--safety-hold-down",
                "0",
                mode,
            ])
            .output()
            .expect("run cass mirror prune")
    }
}

/// The `sealed_ref_bin` bytes the capture writes: the canonical JSON of the
/// lossless tree `lossless_from_value` builds from this object
/// (`indexer/source_ingest.rs`), read back here through the same lossless
/// writer.
fn sealed_ref_bytes(blob_relative_path: &str, blob_blake3: &str) -> Vec<u8> {
    let json = format!(
        "{{\"transport\":\"raw_blob\",\"blob_algorithm\":\"blake3\",\
         \"blob_digest\":\"{blob_blake3}\",\"blob_relative_path\":\"{blob_relative_path}\"}}"
    );
    let tree = LosslessSourceValue::parse(json.as_bytes()).expect("parse the sealed reference");
    let mut bytes = Vec::new();
    tree.write_canonical(&mut bytes)
        .expect("write the canonical sealed reference");
    bytes
}

/// Insert one `source_inputs` row in `state`, with `sealed_ref_bin` as given,
/// honouring the frozen DDL's width and state-pairing CHECKs.
fn insert_source_input(storage: &FrankenStorage, state: &str, sealed_ref_bin: &[u8], key_seed: u8) {
    let complete = state == "complete";
    let tx = storage.raw().transaction().expect("begin");
    tx.execute(
        "INSERT INTO source_inputs (
             input_key, identity_tuple_bin, source_id, identity_namespace, connector,
             root_id_bin, relative_locator_bin, discovery_bin, parser_context_bin,
             context_digest, sealed_ref_bin, sealed_sha256, byte_len, format,
             expected_manifest_bin, normalizer_id, safety_contract_id, state,
             expected_records, expected_blank_lines, receipt_key, applied_content_generation,
             activation_request_hash, observed_records, observed_blank_lines)
         VALUES (?1, ?2, 'fixture-source', 'fixture-ns', 'codex', ?2, ?2, ?2, ?2,
             ?3, ?4, ?3, ?5, 'jsonl', ?2, 'fixture-normalizer', 'fixture-safety', ?6,
             ?5, ?5, ?7, ?7, ?8, ?9, ?9)",
        &[
            Value::Blob(vec![key_seed; 32]),
            Value::Blob(vec![key_seed; 4]),
            Value::Blob(vec![key_seed; 32]),
            Value::Blob(sealed_ref_bin.to_vec()),
            Value::Blob(vec![0u8; 8]),
            Value::Text(state.to_string()),
            if complete {
                Value::Text("fixture-receipt-key".to_string())
            } else {
                Value::Null
            },
            if complete { Value::Blob(vec![key_seed; 32]) } else { Value::Null },
            if complete { Value::Blob(vec![0u8; 8]) } else { Value::Null },
        ],
    )
    .expect("insert the fixture source input");
    tx.commit().expect("commit the fixture source input");
}

/// Record a legacy `messages.excluded.raw.blob` reference exactly as the
/// capture pipeline does: JSON text through `jsonb(?)`.
fn insert_excluded_raw_blob_reference(storage: &FrankenStorage, blob_relative_path: &str) {
    let tx = storage.raw().transaction().expect("begin");
    tx.execute(
        "INSERT INTO agents (id, slug, name, kind, created_at, updated_at) \
         VALUES (1, 'fixture-agent', 'Fixture Agent', 'cli', 0, 0)",
        &[],
    )
    .expect("insert the fixture agent");
    tx.execute(
        "INSERT INTO conversations (id, agent_id, source_path, started_at) \
         VALUES (1, 1, '/fixture/session.jsonl', 0)",
        &[],
    )
    .expect("insert the fixture conversation");
    tx.execute(
        "INSERT INTO messages (id, conversation_id, idx, role, content, excluded) \
         VALUES (1, 1, 0, 'user', 'fixture body', jsonb(?1))",
        &[Value::Text(format!(
            "{{\"raw\":{{\"blob\":\"{blob_relative_path}\"}}}}"
        ))],
    )
    .expect("insert the fixture message with an excluded raw blob");
    tx.commit().expect("commit the fixture message");
}

fn source_input_states(db_path: &std::path::Path) -> Vec<String> {
    let conn = Conn::open_read(db_path).expect("reopen the fixture database read-only");
    conn.query_all_map("SELECT state FROM source_inputs ORDER BY id", &[], |row| {
        row.get_typed::<String>(0)
    })
    .expect("read back the source input states")
}

/// Reopen the archive and read the stored sealed references back out of it,
/// as `(state, blob_relative_path)` in row order. This is the read the
/// acceptance asks for: the protection must be visible in the persisted rows
/// after the prune, not merely in the set the pruner computed.
fn stored_sealed_reference_paths(db_path: &std::path::Path) -> Vec<(String, String)> {
    let conn = Conn::open_read(db_path).expect("reopen the fixture database read-only");
    let rows = conn
        .query_all_map(
            "SELECT state, sealed_ref_bin FROM source_inputs ORDER BY id",
            &[],
            |row| Ok((row.get_typed::<String>(0)?, row.get_typed::<Vec<u8>>(1)?)),
        )
        .expect("read the stored sealed references");
    rows.into_iter()
        .map(|(state, bytes)| {
            let tree = LosslessSourceValue::parse(&bytes)
                .expect("the stored sealed reference is still one well-formed JSON value");
            let path = tree
                .get("blob_relative_path")
                .and_then(LosslessSourceValue::as_str)
                .expect("the stored sealed reference still names a blob path")
                .to_string();
            (state, path)
        })
        .collect()
}

fn message_count(db_path: &std::path::Path) -> i64 {
    let conn = Conn::open_read(db_path).expect("reopen the fixture database read-only");
    conn.query_row_map("SELECT COUNT(*) FROM messages", &[], |row| {
        row.get_typed::<i64>(0)
    })
    .expect("count the messages")
}

fn prune_payload(output: &std::process::Output) -> serde_json::Value {
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
            panic!(
                "stdout is not the robot JSON envelope: {err}; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    envelope
        .get("prune")
        .expect("the robot envelope carries the prune payload")
        .clone()
}

/// Acceptance ① and ②: sealed inputs in `staged`, `partial` and `failed` are
/// protected by a real `--apply` even though the archive holds no message at
/// all, while a `complete` input's blob follows the ordinary retention rules
/// and an unreferenced blob is still reclaimed.
#[test]
fn retry_pending_source_inputs_protect_their_sealed_blobs_without_any_messages() {
    let fixture = Fixture::new();
    let staged = fixture.capture("staged");
    let partial = fixture.capture("partial");
    let failed = fixture.capture("failed");
    let complete = fixture.capture("complete");
    let unreferenced = fixture.capture("unreferenced");

    {
        let storage = fixture.open_db();
        insert_source_input(
            &storage,
            "staged",
            &sealed_ref_bytes(&staged.blob_relative_path, &staged.blob_blake3),
            1,
        );
        insert_source_input(
            &storage,
            "partial",
            &sealed_ref_bytes(&partial.blob_relative_path, &partial.blob_blake3),
            2,
        );
        insert_source_input(
            &storage,
            "failed",
            &sealed_ref_bytes(&failed.blob_relative_path, &failed.blob_blake3),
            3,
        );
        insert_source_input(
            &storage,
            "complete",
            &sealed_ref_bytes(&complete.blob_relative_path, &complete.blob_blake3),
            4,
        );
    }

    let output = fixture.prune("--apply");
    assert_eq!(
        output.status.code(),
        Some(0),
        "apply must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let prune = prune_payload(&output);

    for (name, protected) in [("staged", &staged), ("partial", &partial), ("failed", &failed)] {
        assert!(
            protected.manifest_path.exists(),
            "the {name} input's manifest must survive an apply that selects every capture"
        );
        assert!(
            protected.blob_path.exists(),
            "the {name} input's sealed blob must survive an apply that selects every capture"
        );
        assert_eq!(
            std::fs::read(&protected.blob_path).expect("read the surviving blob"),
            protected.bytes,
            "the {name} input's sealed bytes must be unchanged"
        );
    }

    assert!(
        !unreferenced.blob_path.exists(),
        "an unreferenced expired blob must still be reclaimed"
    );
    assert!(
        !complete.blob_path.exists(),
        "a `complete` input must not keep its blob forever through the source table"
    );
    assert!(
        !complete.manifest_path.exists(),
        "a `complete` input's manifest must not be pinned by the source table"
    );

    assert_eq!(
        prune.get("applied_blob_count").and_then(|v| v.as_u64()),
        Some(2),
        "exactly the unreferenced and the complete blobs may be deleted: {prune}"
    );
    assert_eq!(
        prune.get("pinned_blob_count").and_then(|v| v.as_u64()),
        Some(3),
        "the three retry-pending blobs are the whole protection set: {prune}"
    );
    assert_eq!(
        prune.get("missing_referenced_blobs"),
        Some(&serde_json::json!([])),
        "no registered reference may be missing from disk: {prune}"
    );

    assert_eq!(
        source_input_states(&fixture.db_path()),
        ["staged", "partial", "failed", "complete"],
        "prune must not touch the canonical archive's source rows"
    );
    assert_eq!(
        message_count(&fixture.db_path()),
        0,
        "this fixture has no messages at all: the protection came from source_inputs"
    );
    assert_eq!(
        stored_sealed_reference_paths(&fixture.db_path()),
        vec![
            ("staged".to_string(), staged.blob_relative_path.clone()),
            ("partial".to_string(), partial.blob_relative_path.clone()),
            ("failed".to_string(), failed.blob_relative_path.clone()),
            ("complete".to_string(), complete.blob_relative_path.clone()),
        ],
        "the persisted sealed references must survive the prune unchanged"
    );
}

/// Acceptance ②'s regression guard: the legacy `messages.excluded.raw.blob`
/// protection still holds after the union grew a second source.
#[test]
fn legacy_excluded_raw_blob_reference_is_still_protected() {
    let fixture = Fixture::new();
    let referenced = fixture.capture("legacy-referenced");
    let unreferenced = fixture.capture("legacy-unreferenced");

    {
        let storage = fixture.open_db();
        insert_excluded_raw_blob_reference(&storage, &referenced.blob_relative_path);
    }

    let output = fixture.prune("--apply");
    assert_eq!(
        output.status.code(),
        Some(0),
        "apply must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let prune = prune_payload(&output);

    assert!(
        referenced.manifest_path.exists() && referenced.blob_path.exists(),
        "a blob named by messages.excluded.raw.blob must survive the apply"
    );
    assert_eq!(
        std::fs::read(&referenced.blob_path).expect("read the surviving blob"),
        referenced.bytes,
        "the legacy-referenced blob's bytes must be unchanged"
    );
    assert!(
        !unreferenced.blob_path.exists(),
        "the unreferenced blob must still be reclaimed"
    );
    assert_eq!(
        prune.get("applied_blob_count").and_then(|v| v.as_u64()),
        Some(1),
        "only the unreferenced blob may be deleted: {prune}"
    );
}

/// Acceptance ③'s first half: a dry run changes no mirror file and no archive
/// row, and it reports the same protection set the apply path would honour
/// (it must not present a protected blob's manifest as a planned deletion).
#[test]
fn dry_run_reports_the_protection_set_and_changes_nothing() {
    let fixture = Fixture::new();
    let staged = fixture.capture("dry-run-staged");
    let unreferenced = fixture.capture("dry-run-unreferenced");

    {
        let storage = fixture.open_db();
        insert_source_input(
            &storage,
            "staged",
            &sealed_ref_bytes(&staged.blob_relative_path, &staged.blob_blake3),
            5,
        );
    }

    let output = fixture.prune("--dry-run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the dry run must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let prune = prune_payload(&output);

    assert_eq!(
        prune.get("mode").and_then(|v| v.as_str()),
        Some("dry-run"),
        "the payload must report the dry-run mode: {prune}"
    );
    assert!(
        staged.manifest_path.exists() && staged.blob_path.exists(),
        "a dry run must not delete the protected manifest or blob"
    );
    assert_eq!(
        std::fs::read(&staged.blob_path).expect("read the blob"),
        staged.bytes,
        "a dry run must not rewrite the protected blob"
    );
    assert!(
        unreferenced.blob_path.exists(),
        "a dry run must not delete anything, including the unreferenced blob"
    );
    assert_eq!(
        prune.get("planned_blob_count").and_then(|v| v.as_u64()),
        Some(1),
        "the dry-run plan must exclude the protected blob: {prune}"
    );
    assert_eq!(
        prune.get("applied_blob_count").and_then(|v| v.as_u64()),
        Some(0),
        "a dry run applies nothing: {prune}"
    );
    assert_eq!(
        source_input_states(&fixture.db_path()),
        ["staged"],
        "a dry run must not change the canonical archive"
    );

    // The dry run's only write is its own audit record, and it says so.
    let audit = std::fs::read_to_string(mirror_root(&fixture.data_dir).join("pruned.jsonl"))
        .expect("the dry run writes its audit record");
    assert!(
        audit.contains("\"mode\":\"dry-run\"") && audit.contains("\"applied\":false"),
        "the audit record must be a dry-run record: {audit}"
    );
}

/// Acceptance ③'s second half: a reference the pruner cannot honour refuses
/// the apply before any file is removed. Three shapes, each of which would
/// otherwise let a protected or unrelated blob be deleted.
#[test]
fn apply_refuses_an_undecodable_sealed_reference_and_deletes_nothing() {
    let fixture = Fixture::new();
    let unreferenced = fixture.capture("undecodable-unreferenced");

    {
        let storage = fixture.open_db();
        insert_source_input(&storage, "staged", b"this is not the sealed reference", 6);
    }

    let output = fixture.prune("--apply");
    assert_ne!(
        output.status.code(),
        Some(0),
        "an undecodable sealed reference must refuse the apply"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("sealed-ref-invalid"),
        "the refusal must name the undecodable reference; stderr: {stderr}"
    );
    assert!(
        unreferenced.blob_path.exists() && unreferenced.manifest_path.exists(),
        "the refusal must come before any deletion"
    );
}

#[test]
fn apply_refuses_a_reference_without_manifest_backing_and_deletes_nothing() {
    let fixture = Fixture::new();
    let referenced = fixture.capture("dangling-reference");
    let unreferenced = fixture.capture("dangling-unreferenced");
    std::fs::remove_file(&referenced.manifest_path).expect("drop the manifest backing");

    {
        let storage = fixture.open_db();
        insert_source_input(
            &storage,
            "staged",
            &sealed_ref_bytes(&referenced.blob_relative_path, &referenced.blob_blake3),
            7,
        );
    }

    let output = fixture.prune("--apply");
    assert_ne!(
        output.status.code(),
        Some(0),
        "a reference with no manifest backing must refuse the apply"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("raw mirror prune refused"),
        "the refusal must come from the prune's own inventory check; stderr: {stderr}"
    );
    assert!(
        referenced.blob_path.exists(),
        "the registered blob must survive the refusal"
    );
    assert!(
        unreferenced.blob_path.exists(),
        "the refusal must come before the unrelated blob is deleted"
    );
}

#[test]
fn apply_refuses_a_reference_whose_blob_file_is_gone_and_deletes_nothing() {
    let fixture = Fixture::new();
    let referenced = fixture.capture("deleted-blob-reference");
    let unreferenced = fixture.capture("deleted-blob-unreferenced");
    std::fs::remove_file(&referenced.blob_path).expect("delete the sealed blob file");

    {
        let storage = fixture.open_db();
        insert_source_input(
            &storage,
            "staged",
            &sealed_ref_bytes(&referenced.blob_relative_path, &referenced.blob_blake3),
            8,
        );
    }

    let output = fixture.prune("--apply");
    assert_ne!(
        output.status.code(),
        Some(0),
        "a reference whose blob file is gone must refuse the apply"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("raw mirror prune refused"),
        "the refusal must come from the prune's own file check; stderr: {stderr}"
    );
    assert!(
        referenced.manifest_path.exists(),
        "the manifest naming the missing blob must survive the refusal"
    );
    assert!(
        unreferenced.blob_path.exists(),
        "the refusal must come before the unrelated blob is deleted"
    );
}

/// The real historical schema-7/8 DDL, extracted verbatim from the schema
/// commits — the same fixtures `tests/source_legacy_reader.rs` builds from.
/// Both include `messages.excluded`, which is the column the prune's
/// reference query reads.
const LEGACY_SCHEMA7_DDL: &str = include_str!("fixtures/source_legacy_reader/schema7_legacy.sql");
const LEGACY_SCHEMA8_DDL: &str = include_str!("fixtures/source_legacy_reader/schema8_legacy.sql");

/// The sentence `run_mirror_prune` logs when it cannot read the reference set
/// and falls back to an empty one. A legal legacy archive must never produce
/// it, and the malformed control below proves the check can see it at all.
const REFERENCE_READ_FALLBACK: &str = "failed to read the raw-mirror reference set";

/// Drop `messages.excluded` from a historical DDL, for the control that shows
/// what the fallback warning looks like.
fn legacy_ddl_without_excluded(ddl: &str) -> String {
    ddl.replace(", extra_bin BLOB, excluded BLOB, UNIQUE", ", extra_bin BLOB, UNIQUE")
}

impl Fixture {
    /// Build one legal historical archive: the real schema-7/8 DDL, its own
    /// `PRAGMA user_version` marker, a seeded conversation, and one message
    /// whose `excluded` names `excluded_blob` (the shape the schema-6 writer
    /// produced, written through the same `jsonb(?)` it used).
    fn build_legacy_archive(&self, ddl: &str, version: i64, excluded_blob: Option<&str>) {
        let mut writer = coding_agent_search::storage::testing::open_test_writer(
            &self.db_path(),
            coding_agent_search::storage::api::Profile::Production,
        )
        .expect("open the legacy fixture writer");
        {
            let conn = writer.storage().raw();
            conn.execute_batch(ddl).expect("apply the historical DDL");
            conn.execute_batch(&format!("PRAGMA user_version = {version};"))
                .expect("stamp the historical version marker");
            conn.execute_batch(
                "INSERT INTO agents (id, slug, name, version, kind, created_at, updated_at) \
                     VALUES (1, 'claude', 'Claude', '1.0', 'claude', 0, 0); \
                 INSERT INTO sources (id, kind, created_at, updated_at) \
                     VALUES ('local', 'local', 0, 0); \
                 INSERT INTO conversations (id, agent_id, source_id, source_path) \
                     VALUES (1, 1, 'local', '/legacy/session.jsonl');",
            )
            .expect("seed the legacy conversation");
            match excluded_blob {
                Some(blob_relative_path) => {
                    conn.execute(
                        "INSERT INTO messages (id, conversation_id, idx, role, content, excluded) \
                         VALUES (1, 1, 0, 'user', 'legacy body', jsonb(?1))",
                        &[Value::Text(format!(
                            "{{\"raw\":{{\"blob\":\"{blob_relative_path}\"}}}}"
                        ))],
                    )
                    .expect("insert the legacy excluded reference");
                }
                None => {
                    conn.execute(
                        "INSERT INTO messages (id, conversation_id, idx, role, content) \
                         VALUES (1, 1, 0, 'user', 'legacy body')",
                        &[],
                    )
                    .expect("insert the legacy message");
                }
            }
            conn.execute_batch("PRAGMA journal_mode = DELETE;")
                .expect("leave a static, non-WAL legacy fixture");
        }
        writer.mark_committed();
    }
}

/// Acceptance ④'s first half, corrected in rework R1. The first version of
/// this test built a five-column `messages` table, so the reference query
/// failed on a missing `excluded` column *before* the version gate ran, and a
/// dry run that only warns and continues still exited 0 — the test proved
/// nothing about a legal legacy archive.
///
/// These two drive the real historical DDL instead: `messages.excluded` is
/// present, no source table exists, and the archive carries a real legacy
/// reference. The dry run must read that reference set without the fallback
/// warning, and the apply must honour it, which is only possible if the read
/// succeeded — with the fallback's empty set the referenced blob would be
/// reclaimed along with the unreferenced one.
#[test]
fn legacy_schema7_archive_reads_its_reference_set_and_protects_it() {
    legacy_archive_reads_its_reference_set_and_protects_it(LEGACY_SCHEMA7_DDL, 7);
}

#[test]
fn legacy_schema8_archive_reads_its_reference_set_and_protects_it() {
    legacy_archive_reads_its_reference_set_and_protects_it(LEGACY_SCHEMA8_DDL, 8);
}

fn legacy_archive_reads_its_reference_set_and_protects_it(ddl: &str, version: i64) {
    let fixture = Fixture::new();
    let referenced = fixture.capture(&format!("legacy{version}-referenced"));
    let expired = fixture.capture(&format!("legacy{version}-unreferenced"));
    fixture.build_legacy_archive(ddl, version, Some(&referenced.blob_relative_path));

    // The dry run is the run that would degrade silently, so it is the run
    // that must be shown NOT to: no fallback warning, and a plan that keeps
    // the referenced manifest out of the deletion list.
    let dry = fixture.prune_plain("--dry-run");
    assert_eq!(
        dry.status.code(),
        Some(0),
        "a legal schema-{version} archive's dry run must succeed; stderr: {}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let dry_stderr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        !dry_stderr.contains(REFERENCE_READ_FALLBACK),
        "the legal schema-{version} archive's reference read must not fall back; stderr: {dry_stderr}"
    );
    let dry_stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(
        dry_stdout.contains("Raw-mirror prune (dry-run)"),
        "the dry run must print its plan: {dry_stdout}"
    );
    assert!(
        dry_stdout.contains("Planned manifests: 1") && dry_stdout.contains("Pinned blobs: 1"),
        "the dry-run plan must keep exactly the referenced blob and plan the other: {dry_stdout}"
    );

    let output = fixture.prune("--apply");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a legal schema-{version} archive's apply must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let prune = prune_payload(&output);
    assert_eq!(
        prune.get("pinned_blob_count").and_then(|v| v.as_u64()),
        Some(1),
        "the archive's own excluded reference must be in the protection set: {prune}"
    );
    assert_eq!(
        prune.get("applied_blob_count").and_then(|v| v.as_u64()),
        Some(1),
        "only the unreferenced blob may be reclaimed: {prune}"
    );
    assert!(
        referenced.manifest_path.exists() && referenced.blob_path.exists(),
        "the legacy-referenced manifest and blob must survive the apply"
    );
    assert_eq!(
        std::fs::read(&referenced.blob_path).expect("read the surviving blob"),
        referenced.bytes,
        "the legacy-referenced blob's bytes must be unchanged"
    );
    assert!(
        !expired.blob_path.exists(),
        "an unreferenced blob past retention must still be reclaimed"
    );
}

/// The control that keeps the assertion above honest: the warning the legal
/// fixtures must not produce is real and does reach stderr through this exact
/// invocation. Here the archive is missing `messages.excluded`, so the
/// reference query fails on the shape before the version gate, exactly as it
/// did in the first, false-green version of the test.
///
/// This control drives the dry run only: the fallback's masking of a read
/// error in dry-run is pre-existing behaviour that this ticket deliberately
/// does not change (the apply path refuses on that same read error).
#[test]
fn a_legacy_shaped_archive_without_excluded_does_log_the_fallback() {
    let fixture = Fixture::new();
    fixture.build_legacy_archive(&legacy_ddl_without_excluded(LEGACY_SCHEMA8_DDL), 8, None);

    let dry = fixture.prune_plain("--dry-run");
    assert_eq!(
        dry.status.code(),
        Some(0),
        "a dry run on a malformed archive still previews; stderr: {}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let stderr = String::from_utf8_lossy(&dry.stderr);
    assert!(
        stderr.contains(REFERENCE_READ_FALLBACK),
        "the malformed archive's read failure must reach stderr, or the negative \
         assertions above are vacuous; stderr: {stderr}"
    );
}
