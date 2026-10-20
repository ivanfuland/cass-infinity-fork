//! Task 31 acceptance: native JSON documents versus JSONL framing.
//!
//! Every case drives the real `cass index` binary over a private synthetic
//! HOME, a private fixed safety copy and a private data directory, and then
//! reads the resulting database through the storage facade. Where the ticket
//! asks for a migration, the pre-state is produced by the *frozen base binary*
//! named by `CASS_TASK31_BASELINE_BIN` -- proved against its published digest
//! before any use -- and never by hand-written rows pretending to be an older
//! run.
//!
//! The fixtures are synthetic and neutral. No real session, path or secret
//! appears in this file.

use std::path::{Path, PathBuf};
use std::process::Command;

use coding_agent_search::storage::api::{Conn, Value};
use sha2::{Digest as _, Sha256};

// ---------------------------------------------------------------------------
// Binaries
// ---------------------------------------------------------------------------

/// The binary under test, which cargo builds for this target.
fn cass_bin() -> String {
    env!("CARGO_BIN_EXE_cass").to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// The frozen `62d71776` binary the migration cases must seed with.
///
/// A missing or substituted binary fails the test outright: a migration case
/// that cannot run its own pre-state has proved nothing, and the ticket forbids
/// ignoring it, simulating the rows, or reporting success early.
fn baseline_bin() -> String {
    let path = dotenvy::var("CASS_TASK31_BASELINE_BIN").unwrap_or_else(|_| {
        panic!(
            "CASS_TASK31_BASELINE_BIN must name the frozen base binary; without it the \
             migration cases cannot build their pre-state"
        )
    });
    let expected = dotenvy::var("CASS_TASK31_BASELINE_SHA256")
        .unwrap_or_else(|_| panic!("CASS_TASK31_BASELINE_SHA256 must pin the frozen digest"));
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("the frozen base binary at {path} is not readable: {err}"));
    assert_eq!(
        sha256_hex(&bytes),
        expected,
        "the binary at {path} is not the frozen base build"
    );
    path
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// A private root holding a HOME, a data directory and the fixed safety copy.
struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home")).expect("mkdir home");
        std::fs::create_dir_all(root.path().join("data")).expect("mkdir data");
        // The fixed copy is the built-in configuration's exact bytes; the
        // caller supplies it and this path never invents one.
        std::fs::write(
            root.path().join("fixed-safety.toml"),
            include_bytes!("../config/excluded_context_paths.toml"),
        )
        .expect("write fixed safety copy");
        Self { root }
    }

    /// Point every source-discovery environment at this fixture.
    ///
    /// The host running the tests may itself export these, and an inherited
    /// value would let a fixture process scan the host's real history -- slow,
    /// and a privacy problem. The fixture therefore states every one of them
    /// explicitly rather than hoping the ambient environment is clean.
    fn isolate<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("HOME", self.home())
            .env("XDG_DATA_HOME", self.home().join(".local/share"))
            .env("XDG_CONFIG_HOME", self.home().join(".config"))
            .env("CODEX_HOME", self.home().join(".codex"))
            .env("CASS_AIDER_DATA_ROOT", self.home().join(".aider"))
            .env("PI_SESSIONS_DIR", self.home().join(".pi"))
            .env("PI_CODING_AGENT_DIR", self.home().join(".pi"))
            .env("GOOSE_PATH_ROOT", self.home().join(".goose"))
            .env("HERMES_HOME", self.home().join(".hermes"))
            .env("CASS_DATA_DIR", self.data_dir())
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("NO_COLOR", "1")
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn db(&self) -> PathBuf {
        self.data_dir().join("agent_search.db")
    }

    fn fixed_copy(&self) -> PathBuf {
        self.root.path().join("fixed-safety.toml")
    }

    /// Write one file at the layout the Claude connector discovers.
    fn write_claude_file(&self, project: &str, file_name: &str, body: &str) -> PathBuf {
        let dir = self.home().join(".claude/projects").join(project);
        std::fs::create_dir_all(&dir).expect("mkdir claude project");
        let path = dir.join(file_name);
        std::fs::write(&path, body).expect("write claude file");
        path
    }

    /// Write one file at the layout the Codex connector discovers.
    fn write_codex_file(&self, file_name: &str, body: &str) -> PathBuf {
        let dir = self.home().join(".codex/sessions/2026/01");
        std::fs::create_dir_all(&dir).expect("mkdir codex sessions");
        let path = dir.join(file_name);
        std::fs::write(&path, body).expect("write codex file");
        path
    }

    /// Run `cass index` with the frozen safety copy, against `bin`.
    fn run_index_with(&self, bin: &str, extra: &[&str]) -> std::process::Output {
        let copy = self.fixed_copy();
        let mut cmd = Command::new(bin);
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .args(["--source-safety-config", copy.to_str().unwrap()])
            .args(extra)
            .args(["--json"]);
        cmd.output().expect("spawn cass index")
    }

    /// Run the candidate binary.
    fn run_index(&self) -> std::process::Output {
        self.run_index_with(&cass_bin(), &[])
    }

    fn open_db(&self) -> Conn {
        Self::open_db_at(&self.db())
    }

    /// Open one database by path, read-only, as a fresh reader sees it.
    fn open_db_at(path: &Path) -> Conn {
        Conn::open_read(path).expect("open the database read-only")
    }
}

// ---------------------------------------------------------------------------
// Synthetic documents
// ---------------------------------------------------------------------------

fn claude_document(session_id: &str, question: &str, answer: &str) -> serde_json::Value {
    serde_json::json!({
        "cwd": "/synthetic/document-project",
        "sessionId": session_id,
        "version": "2.0.37",
        "title": "synthetic native document",
        "messages": [
            {
                "role": "user",
                "content": question,
                "timestamp": "2026-01-01T00:00:00.000Z"
            },
            {
                "role": "assistant",
                "content": [{"type": "text", "text": answer}],
                "timestamp": "2026-01-01T00:00:01.000Z"
            }
        ],
        "syntheticUnknownTopLevel": {"nested": ["kept", 7, true]}
    })
}

fn codex_document(session_id: &str, question: &str, answer: &str) -> serde_json::Value {
    serde_json::json!({
        "session": {
            "id": session_id,
            "cwd": "/synthetic/document-project",
            "cli_version": "0.42.0"
        },
        "items": [
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": question}],
                "timestamp": "2026-01-01T00:00:00.000Z"
            },
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": answer}],
                "timestamp": "2026-01-01T00:00:01.000Z"
            }
        ],
        "syntheticUnknownTopLevel": {"nested": ["kept", 7, true]}
    })
}

/// A turn the fixed document projection accepts although the JSONL entry core
/// would not classify it: a claude element that carries only `text` and no
/// role, and a codex item with content and no role. Both still become messages
/// with the projection's `agent` default, so the framing must carry them.
const TEXT_ONLY_TURN: &str = "synthetic text-only turn";

fn claude_with_text_only_turn(session_id: &str, question: &str, answer: &str) -> serde_json::Value {
    let mut document = claude_document(session_id, question, answer);
    document["messages"]
        .as_array_mut()
        .expect("the claude document's messages")
        .push(serde_json::json!({"text": TEXT_ONLY_TURN}));
    document
}

fn codex_with_text_only_turn(session_id: &str, question: &str, answer: &str) -> serde_json::Value {
    let mut document = codex_document(session_id, question, answer);
    document["items"]
        .as_array_mut()
        .expect("the codex document's items")
        .push(serde_json::json!({"content": TEXT_ONLY_TURN}));
    document
}

/// A genuinely multi-line document: the requirement is a real file layout, not
/// a single line that happens to parse.
fn pretty_document(document: &serde_json::Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(document).expect("pretty document"))
}

/// The Codex rollout's physical lines, one of which is blank.
fn codex_jsonl_lines(session_id: &str, question: &str, answer: &str) -> Vec<String> {
    vec![
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:00.000Z",
            "type": "session_meta",
            "payload": {"id": session_id, "cwd": "/synthetic/document-project", "cli_version": "0.42.0"}
        })
        .to_string(),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:01.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": format!("{session_id}-user"),
                "role": "user",
                "content": [{"type": "input_text", "text": question}]
            }
        })
        .to_string(),
        String::new(),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:02.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": format!("{session_id}-assistant"),
                "role": "assistant",
                "content": [{"type": "output_text", "text": answer}]
            }
        })
        .to_string(),
    ]
}

/// The byte range each non-blank physical line occupies, terminator excluded.
fn line_ranges(lines: &[String]) -> Vec<(u64, u64)> {
    let mut start = 0u64;
    let mut ranges = Vec::new();
    for line in lines {
        let end = start + line.len() as u64;
        if !line.is_empty() {
            ranges.push((start, end));
        }
        start = end + 1; // the newline that follows every physical line
    }
    ranges
}

// ---------------------------------------------------------------------------
// Reading the database
// ---------------------------------------------------------------------------

fn u64_be(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("eight big-endian bytes"))
}

/// One `source_inputs` row, every identity-bearing column included, so two
/// reads of the same row compare byte for byte.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InputRow {
    id: i64,
    key_hex: String,
    connector: String,
    format: String,
    state: String,
    byte_len: u64,
    expected_records: u64,
    expected_blank_lines: u64,
    normalizer_id: String,
    safety_contract_id: String,
    receipt_key: Option<String>,
    sealed_sha256_hex: String,
    identity_tuple_hex: String,
    discovery_hex: String,
    parser_context_hex: String,
    sealed_ref_hex: String,
    expected_manifest_hex: String,
    root_id_hex: String,
    relative_locator: String,
}

fn input_rows(db: &Conn) -> Vec<InputRow> {
    db.query_all_map(
        "SELECT id, hex(input_key), connector, format, state, byte_len, expected_records,
                expected_blank_lines, normalizer_id, safety_contract_id, receipt_key,
                hex(sealed_sha256), hex(identity_tuple_bin), hex(discovery_bin),
                hex(parser_context_bin), hex(sealed_ref_bin), hex(expected_manifest_bin),
                hex(root_id_bin), relative_locator_bin
         FROM source_inputs ORDER BY id",
        &[],
        |row| {
            Ok(InputRow {
                id: row.get_typed(0)?,
                key_hex: row.get_typed(1)?,
                connector: row.get_typed(2)?,
                format: row.get_typed(3)?,
                state: row.get_typed(4)?,
                byte_len: u64_be(&row.get_typed::<Vec<u8>>(5)?),
                expected_records: u64_be(&row.get_typed::<Vec<u8>>(6)?),
                expected_blank_lines: u64_be(&row.get_typed::<Vec<u8>>(7)?),
                normalizer_id: row.get_typed(8)?,
                safety_contract_id: row.get_typed(9)?,
                receipt_key: row.get_typed(10)?,
                sealed_sha256_hex: row.get_typed(11)?,
                identity_tuple_hex: row.get_typed(12)?,
                discovery_hex: row.get_typed(13)?,
                parser_context_hex: row.get_typed(14)?,
                sealed_ref_hex: row.get_typed(15)?,
                expected_manifest_hex: row.get_typed(16)?,
                root_id_hex: row.get_typed(17)?,
                relative_locator: String::from_utf8_lossy(&row.get_typed::<Vec<u8>>(18)?)
                    .into_owned(),
            })
        },
    )
    .expect("query the inputs")
}

/// The unique input whose relative locator ends with `suffix`.
fn input_ending_with(db: &Conn, suffix: &str) -> InputRow {
    let matches: Vec<InputRow> = input_rows(db)
        .into_iter()
        .filter(|row| row.relative_locator.ends_with(suffix))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "exactly one input is discovered under a locator ending in {suffix}: {:?}",
        input_rows(db)
            .iter()
            .map(|row| row.relative_locator.clone())
            .collect::<Vec<_>>()
    );
    matches.into_iter().next().expect("one match")
}

/// One `source_records` row of one input, including the stored payload itself:
/// "the old record is unchanged" has to mean its bytes, not only its header.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordRow {
    ordinal: u64,
    pointer: String,
    byte_start: u64,
    byte_end: u64,
    expected_sha256_hex: String,
    frame_state: String,
    parse_state: String,
    mapping_state: String,
    retention_state: String,
    payload_bin: Option<Vec<u8>>,
    safe_value_hash_hex: Option<String>,
}

fn record_rows(db: &Conn, input_id: i64) -> Vec<RecordRow> {
    db.query_all_map(
        "SELECT ordinal, record_pointer, position_bin, hex(expected_source_record_sha256),
                frame_state, parse_state, record_mapping_state, retention_state,
                payload_bin, hex(safe_value_hash)
         FROM source_records WHERE input_id = ?1 ORDER BY ordinal",
        &[Value::Integer(input_id)],
        |row| {
            let position: Vec<u8> = row.get_typed(2)?;
            let position: serde_json::Value =
                serde_json::from_slice(&position).expect("position_bin is canonical JSON");
            let parts = position.as_array().expect("position_bin is an array");
            let decimal = |index: usize| {
                parts[index]
                    .as_str()
                    .and_then(|text| text.parse::<u64>().ok())
                    .unwrap_or_else(|| {
                        panic!("position_bin element {index} is a canonical decimal")
                    })
            };
            Ok(RecordRow {
                ordinal: u64_be(&row.get_typed::<Vec<u8>>(0)?),
                pointer: row.get_typed(1)?,
                byte_start: decimal(2),
                byte_end: decimal(3),
                // `hex()` renders uppercase; every digest this file compares is
                // written lowercase.
                expected_sha256_hex: row.get_typed::<String>(3)?.to_lowercase(),
                frame_state: row.get_typed(4)?,
                parse_state: row.get_typed(5)?,
                mapping_state: row.get_typed(6)?,
                retention_state: row.get_typed(7)?,
                payload_bin: row.get_typed(8)?,
                safe_value_hash_hex: row
                    .get_typed::<Option<String>>(9)?
                    .map(|hex| hex.to_lowercase()),
            })
        },
    )
    .expect("query the records")
}

/// The canonical messages one input's records produced, in message order.
fn canonical_messages(db: &Conn, input_id: i64) -> Vec<(String, String)> {
    db.query_all_map(
        "SELECT m.role, m.content
         FROM source_message_links l
         JOIN source_records r ON r.id = l.record_id
         JOIN messages m ON m.id = l.message_id
         WHERE r.input_id = ?1 AND l.authority = 'canonical'
         ORDER BY m.idx",
        &[Value::Integer(input_id)],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
    )
    .expect("query the messages")
}

/// Every stored payload of one input, decoded into its safe JSON tree.
fn safe_values(db: &Conn, input_id: i64) -> Vec<serde_json::Value> {
    let payloads: Vec<Vec<u8>> = db
        .query_all_map(
            "SELECT payload_bin FROM source_records
             WHERE input_id = ?1 AND payload_bin IS NOT NULL ORDER BY ordinal",
            &[Value::Integer(input_id)],
            |row| row.get_typed(0),
        )
        .expect("query the payloads");
    payloads
        .iter()
        .map(|bytes| {
            let json = coding_agent_search::storage::source_codec::decode_safe_source(bytes)
                .expect("the stored safe value decodes")
                .safe_json()
                .to_string();
            serde_json::from_str(&json).expect("the stored safe value is JSON")
        })
        .collect()
}

/// The stored, decoded safe value of one record: the lossless tree the record
/// carries on disk. A document input is one record.
fn safe_value(db: &Conn, input_id: i64) -> serde_json::Value {
    let values = safe_values(db, input_id);
    assert_eq!(values.len(), 1, "a document input keeps exactly one payload");
    values.into_iter().next().expect("one payload")
}

/// Every committed activation receipt, every column and every value exactly as
/// stored. The seven schema columns include the row id, the commit time and the
/// detail, so a four-column view could not claim a row was left unchanged; the
/// values keep their stored kind (`Null`/`Text`/`Blob`) rather than being
/// coerced to strings.
fn receipt_rows(db: &Conn) -> Vec<Vec<Value>> {
    db.query_all_map(
        "SELECT id, idempotency_key, operation, state, snapshot_root, committed_at_ms, detail
         FROM operation_commit_receipt ORDER BY id",
        &[],
        |row| {
            (0..7)
                .map(|index| row.get_value(index))
                .collect::<Result<Vec<Value>, _>>()
        },
    )
    .expect("query the receipts")
}

fn message_count(db: &Conn) -> i64 {
    db.query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))
        .expect("count messages")
}

/// The bytes of the raw-mirror blob one input was sealed from.
///
/// The path comes from the input's own sealed reference, and the bytes are read
/// back from disk: this is the original file's end, not a claim about it.
fn sealed_blob_bytes(data_dir: &Path, row: &InputRow) -> Vec<u8> {
    let reference: serde_json::Value =
        serde_json::from_slice(&hex::decode(&row.sealed_ref_hex).expect("sealed_ref is hex"))
            .expect("sealed_ref is JSON");
    let relative = reference["blob_relative_path"]
        .as_str()
        .expect("the sealed reference names the blob's relative path");
    std::fs::read(data_dir.join("raw-mirror").join("v1").join(relative))
        .expect("the sealed blob is still on disk")
}

/// The format the stored expected manifest carries, decoded through the public
/// header decoder rather than by pattern-matching a blob.
fn stored_manifest_format(row: &InputRow) -> String {
    let bytes = hex::decode(&row.expected_manifest_hex).expect("the manifest column is hex");
    let (manifest, _safety) =
        coding_agent_search::storage::source_facts::decode_expected_manifest_header(&bytes)
            .expect("the stored expected manifest header decodes");
    manifest.format().as_str().to_string()
}

// ---------------------------------------------------------------------------
// F1: real native documents
// ---------------------------------------------------------------------------

#[test]
fn f1_native_documents() {
    let fixture = Fixture::new();
    let question = "synthetic document question";
    let answer = "synthetic document answer";

    // The documents as this file writes them: the expected stored tree is the
    // hand-written input itself, never the product's own output.
    let claude_expected = claude_with_text_only_turn("sess-f1-json", question, answer);
    let sidecar_expected = claude_with_text_only_turn("sess-f1-claude", question, answer);
    let codex_expected = codex_with_text_only_turn("sess-f1-codex", question, answer);
    let claude_json = pretty_document(&claude_expected);
    let claude_sidecar = pretty_document(&sidecar_expected);
    let codex_json = pretty_document(&codex_expected);

    let json_path = fixture.write_claude_file("proj-f1-json", "session.json", &claude_json);
    let sidecar_path =
        fixture.write_claude_file("proj-f1-claude", "session.claude", &claude_sidecar);
    let codex_path = fixture.write_codex_file("rollout-2026-01-01T00-00-00-f1.json", &codex_json);

    let output = fixture.run_index();
    assert_eq!(
        output.status.code(),
        Some(0),
        "the run over three native documents must succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cases: [(&str, &Path, &str, &serde_json::Value); 3] = [
        (
            "session.json",
            json_path.as_path(),
            "claude_code",
            &claude_expected,
        ),
        (
            "session.claude",
            sidecar_path.as_path(),
            "claude_code",
            &sidecar_expected,
        ),
        (
            "rollout-2026-01-01T00-00-00-f1.json",
            codex_path.as_path(),
            "codex",
            &codex_expected,
        ),
    ];

    for (label, path, connector, expected) in cases {
        let db = fixture.open_db();
        let input = input_ending_with(&db, label);
        let bytes = std::fs::read(path).expect("re-read the source bytes");

        assert_eq!(input.connector, connector, "{label}: the connector is the discoverer");
        assert_eq!(input.format, "json_document", "{label}: the declared format");
        assert_eq!(input.state, "complete", "{label}: the input completes");
        assert_eq!(
            input.byte_len,
            bytes.len() as u64,
            "{label}: the sealed length is the file's length"
        );

        let records = record_rows(&db, input.id);
        assert_eq!(records.len(), 1, "{label}: a document is exactly one record");
        let record = &records[0];
        assert_eq!(record.pointer, "", "{label}: a document frame has no pointer");
        assert_eq!(
            (record.byte_start, record.byte_end),
            (0, bytes.len() as u64),
            "{label}: the frame covers the whole file"
        );
        assert_eq!(
            record.expected_sha256_hex,
            sha256_hex(&bytes),
            "{label}: the record digest is the original bytes' digest"
        );
        assert_eq!(record.frame_state, "activated", "{label}: the frame is activated");
        assert_eq!(record.parse_state, "parsed", "{label}: the document parses");
        assert_eq!(
            record.mapping_state, "all_canonical",
            "{label}: both roles became canonical messages"
        );

        let messages = canonical_messages(&db, input.id);
        assert_eq!(
            messages,
            vec![
                ("user".to_string(), question.to_string()),
                ("assistant".to_string(), answer.to_string()),
                ("agent".to_string(), TEXT_ONLY_TURN.to_string()),
            ],
            "{label}: the document's roles and bodies, including the turn the \
             JSONL entry core would not classify"
        );

        // The whole tree survives, field for field: the stored safe value is
        // the hand-written document itself, not a projection of it.
        let tree = safe_value(&db, input.id);
        assert_eq!(
            &tree, expected,
            "{label}: the stored tree is the input document, unchanged"
        );

        drop(db);
        // Close and reopen: the facts are on disk, not in the writer's memory.
        let reopened = fixture.open_db();
        let again = input_ending_with(&reopened, label);
        assert_eq!(again, input, "{label}: the reopened input row is unchanged");
        assert_eq!(
            record_rows(&reopened, again.id),
            records,
            "{label}: the reopened record row is unchanged"
        );
        assert_eq!(
            canonical_messages(&reopened, again.id),
            messages,
            "{label}: the reopened messages are unchanged"
        );
        assert_eq!(
            safe_value(&reopened, again.id),
            tree,
            "{label}: the reopened tree is unchanged"
        );
    }
}

// ---------------------------------------------------------------------------
// F2: layout and JSONL boundaries
// ---------------------------------------------------------------------------

#[test]
fn f2_layout_and_jsonl() {
    let question = "synthetic layout question";
    let answer = "synthetic layout answer";
    let document = claude_document("sess-f2", question, answer);
    let pretty = pretty_document(&document);
    let compact = document.to_string();

    // Two independent data directories: the same tree in two layouts.
    let layout_cases = [("pretty", pretty), ("compact", compact)];
    let mut observed: Vec<(String, serde_json::Value, String, u64)> = Vec::new();
    for (label, body) in layout_cases {
        let fixture = Fixture::new();
        let path = fixture.write_claude_file("proj-f2", "session.json", &body);
        let output = fixture.run_index();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{label}: the layout must ingest; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );

        let db = fixture.open_db();
        let input = input_ending_with(&db, "session.json");
        assert_eq!(input.format, "json_document", "{label}: the declared format");
        assert_eq!(input.state, "complete", "{label}: the input completes");

        let bytes = std::fs::read(&path).expect("re-read the layout bytes");
        let records = record_rows(&db, input.id);
        assert_eq!(records.len(), 1, "{label}: one record for the document");
        assert_eq!(
            records[0].expected_sha256_hex,
            sha256_hex(&bytes),
            "{label}: each layout digests its own bytes"
        );
        assert_eq!(
            records[0].byte_end,
            bytes.len() as u64,
            "{label}: each layout's range is its own length"
        );
        assert_eq!(
            canonical_messages(&db, input.id).len(),
            2,
            "{label}: the same two messages"
        );
        // Each layout's tree is checked against the hand-written document
        // itself, not only against the other layout's output.
        let tree = safe_value(&db, input.id);
        assert_eq!(
            tree, document,
            "{label}: the stored tree is the hand-written document"
        );
        observed.push((
            label.to_string(),
            tree,
            records[0].expected_sha256_hex.clone(),
            records[0].byte_end,
        ));
    }

    let (pretty_label, pretty_tree, pretty_digest, pretty_len) = &observed[0];
    let (compact_label, compact_tree, compact_digest, compact_len) = &observed[1];
    assert_eq!(
        pretty_tree, compact_tree,
        "{pretty_label} and {compact_label}: one tree, two renderings"
    );
    assert_ne!(
        pretty_digest, compact_digest,
        "the raw digests differ because the raw bytes do"
    );
    assert_ne!(
        pretty_len, compact_len,
        "and so do the lengths"
    );

    // Codex JSONL, in three ASCII-case spellings, each through the real CLI.
    let lines = codex_jsonl_lines("sess-f2-jsonl", question, answer);
    let body = format!("{}\n", lines.join("\n"));
    let expected_ranges = line_ranges(&lines);
    let mut per_case: Vec<(String, Vec<RecordRow>)> = Vec::new();
    for file_name in ["rollout-2026-01-01T00-00-00-f2.jsonl", "rollout-2026-01-01T00-00-00-f2.JSONL", "rollout-2026-01-01T00-00-00-f2.JsonL"] {
        let fixture = Fixture::new();
        fixture.write_codex_file(file_name, &body);
        let output = fixture.run_index();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{file_name}: the rollout must ingest; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );

        let db = fixture.open_db();
        let input = input_ending_with(&db, file_name);
        assert_eq!(input.connector, "codex", "{file_name}: discovered by codex");
        assert_eq!(input.format, "jsonl", "{file_name}: line-oriented, not a document");
        assert_eq!(input.state, "complete", "{file_name}: the input completes");
        assert_eq!(
            input.expected_records,
            expected_ranges.len() as u64,
            "{file_name}: one record per non-blank line"
        );
        assert_eq!(
            input.expected_blank_lines, 1,
            "{file_name}: the blank line is counted, not framed"
        );

        let records = record_rows(&db, input.id);
        let got_ranges: Vec<(u64, u64)> =
            records.iter().map(|r| (r.byte_start, r.byte_end)).collect();
        assert_eq!(
            got_ranges, expected_ranges,
            "{file_name}: every record keeps its own byte range"
        );
        per_case.push((file_name.to_string(), records));
    }

    // The three spellings discover the same bytes, so the framing is the same
    // record for record -- only the locator that found it differs.
    let (first_label, first) = &per_case[0];
    for (label, records) in &per_case[1..] {
        assert_eq!(
            records, first,
            "{first_label} and {label} frame identically"
        );
    }
}

// ---------------------------------------------------------------------------
// F3: one format through the chain, and a real broken document
// ---------------------------------------------------------------------------

#[test]
fn f3_format_chain_and_bad_document() {
    let question = "synthetic chain question";
    let answer = "synthetic chain answer";

    // The positive case: one document, every stage claiming the same format.
    let fixture = Fixture::new();
    let body = pretty_document(&claude_document("sess-f3", question, answer));
    let path = fixture.write_claude_file("proj-f3", "session.json", &body);
    let output = fixture.run_index();
    assert_eq!(
        output.status.code(),
        Some(0),
        "the positive case must ingest; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let db = fixture.open_db();
    let input = input_ending_with(&db, "session.json");
    let bytes = std::fs::read(&path).expect("re-read the source bytes");

    // 1. The declaration (persisted as the input's own format column).
    assert_eq!(input.format, "json_document", "the declaration fixes the format");
    // 2. The independent manifest, decoded from storage.
    assert_eq!(
        stored_manifest_format(&input),
        "json_document",
        "the expected manifest carries the same format"
    );
    // 3. The pinned connector's own parse produced the document's messages.
    assert_eq!(
        canonical_messages(&db, input.id),
        vec![
            ("user".to_string(), question.to_string()),
            ("assistant".to_string(), answer.to_string()),
        ],
        "the connector parsed this as a document, not as lines"
    );
    // 4. The commit framed it as the input was handed over.
    let records = record_rows(&db, input.id);
    assert_eq!(records.len(), 1, "the commit frames one document record");
    assert_eq!(
        (records[0].byte_start, records[0].byte_end),
        (0, bytes.len() as u64),
        "and the frame covers the whole file"
    );
    assert_eq!(
        records[0].expected_sha256_hex,
        sha256_hex(&bytes),
        "with the original bytes' digest"
    );

    // The negative case: a genuinely broken multi-line document is Partial, and
    // the run does not report a complete success.
    let broken = Fixture::new();
    broken.write_claude_file(
        "proj-f3-bad",
        "session.json",
        "{\n  \"messages\": [\n    {\"role\": \"user\", \"content\": \"truncated\n",
    );
    let broken_output = broken.run_index();
    assert_ne!(
        broken_output.status.code(),
        Some(0),
        "a broken document is not a success; stderr={}",
        String::from_utf8_lossy(&broken_output.stderr)
    );

    let broken_db = broken.open_db();
    let broken_input = input_ending_with(&broken_db, "session.json");
    assert_eq!(
        broken_input.state, "partial",
        "a document that reads to EOF but does not parse is Partial"
    );
    let broken_records = record_rows(&broken_db, broken_input.id);
    assert_eq!(
        broken_records.len(),
        1,
        "the broken document is still one frame"
    );
    assert_eq!(
        broken_records[0].parse_state, "parse_failed",
        "and that frame is the parse failure"
    );
    assert!(
        canonical_messages(&broken_db, broken_input.id).is_empty(),
        "a failed parse yields no messages"
    );
}

// ---------------------------------------------------------------------------
// F4: the mapping-domain upgrade, both migration cases
// ---------------------------------------------------------------------------

#[test]
fn f4_mapping_domain_upgrade() {
    let question = "synthetic migration question";
    let answer = "synthetic migration answer";
    let baseline = baseline_bin();

    // Case one: a legal JSONL session the base binary already completed.
    let jsonl = Fixture::new();
    let jsonl_body = format!(
        "{}\n{}\n",
        claude_jsonl_user("sess-f4-jsonl", question),
        claude_jsonl_assistant("sess-f4-jsonl", answer)
    );
    jsonl.write_claude_file("proj-f4-jsonl", "session.jsonl", &jsonl_body);
    let seeded = jsonl.run_index_with(&baseline, &[]);
    assert_eq!(
        seeded.status.code(),
        Some(0),
        "the frozen base binary seeds the JSONL case; stderr={}",
        String::from_utf8_lossy(&seeded.stderr)
    );
    let before = {
        let db = jsonl.open_db();
        let rows = input_rows(&db);
        assert_eq!(rows.len(), 1, "one /1 input for the JSONL source");
        assert_eq!(rows[0].format, "jsonl", "the base binary framed it as JSONL");
        assert_eq!(rows[0].state, "complete");
        let records = record_rows(&db, rows[0].id);
        assert_eq!(records.len(), 2, "the JSONL session is two records");
        (
            rows.clone(),
            receipt_rows(&db),
            message_count(&db),
            records,
        )
    };
    // The original the /1 input was sealed from: its bytes must still be the
    // bytes that input's identity names.
    let old_blob = sealed_blob_bytes(&jsonl.data_dir(), &before.0[0]);
    assert_eq!(
        sha256_hex(&old_blob),
        before.0[0].sealed_sha256_hex.to_lowercase(),
        "the stored blob is the /1 input's sealed original"
    );

    let jsonl_run = jsonl.run_index();
    assert_eq!(
        jsonl_run.status.code(),
        Some(0),
        "the candidate re-ingests the same JSONL source; stderr={}",
        String::from_utf8_lossy(&jsonl_run.stderr)
    );
    {
        let db = jsonl.open_db();
        let after = input_rows(&db);
        assert_eq!(
            after.len(),
            2,
            "the new mapping domain is a second generation for the same file"
        );
        assert_eq!(after[0], before.0[0], "the /1 row is byte for byte unchanged");
        assert_eq!(after[1].format, "jsonl", "the JSONL file stays line-oriented");
        assert_eq!(after[1].state, "complete", "and completes under the new domain");
        assert_ne!(
            after[1].normalizer_id, after[0].normalizer_id,
            "the two generations have different normalizer identities"
        );
        assert_ne!(after[1].key_hex, after[0].key_hex, "and different input keys");

        let old_receipts = before.1.len();
        let receipts = receipt_rows(&db);
        assert_eq!(
            receipts.len(),
            old_receipts + 1,
            "each generation writes its own activation receipt"
        );
        assert_eq!(
            &receipts[..old_receipts],
            &before.1[..],
            "the /1 receipt rows are unchanged"
        );
        assert_eq!(
            message_count(&db),
            before.2,
            "the JSONL messages already in the canonical store are not duplicated"
        );
        assert_eq!(
            record_rows(&db, before.0[0].id),
            before.3,
            "the /1 records are unchanged"
        );
        assert_eq!(
            sealed_blob_bytes(&jsonl.data_dir(), &before.0[0]),
            old_blob,
            "and the /1 original is still the same bytes"
        );
    }

    let after_rows = {
        let db = jsonl.open_db();
        input_rows(&db)
    };
    let after_receipts = {
        let db = jsonl.open_db();
        receipt_rows(&db)
    };
    let after_messages = {
        let db = jsonl.open_db();
        message_count(&db)
    };
    let after_records = {
        let db = jsonl.open_db();
        record_rows(&db, after_rows[1].id)
    };

    // A repeated candidate run is a replay: no third generation, no new
    // receipt, no new message and no rewritten record.
    let repeat = jsonl.run_index();
    assert_eq!(
        repeat.status.code(),
        Some(0),
        "the repeat run must succeed; stderr={}",
        String::from_utf8_lossy(&repeat.stderr)
    );
    {
        let repeat_db = jsonl.open_db();
        assert_eq!(
            input_rows(&repeat_db),
            after_rows,
            "a repeated candidate run adds no input for the same version"
        );
        assert_eq!(
            receipt_rows(&repeat_db),
            after_receipts,
            "and adds no receipt for the same version"
        );
        assert_eq!(
            message_count(&repeat_db),
            after_messages,
            "and no message"
        );
        assert_eq!(
            record_rows(&repeat_db, after_rows[1].id),
            after_records,
            "the /2 records are stable across the replay"
        );
    }

    // Case two: a compact native Claude document the base binary completed as
    // a JSONL input, with no messages at all.
    let document = Fixture::new();
    let compact = claude_document("sess-f4-doc", question, answer).to_string();
    let path = document.write_claude_file("proj-f4-doc", "session.json", &compact);
    let seeded = document.run_index_with(&baseline, &[]);
    assert_eq!(
        seeded.status.code(),
        Some(0),
        "the base binary seeds the document case; stderr={}",
        String::from_utf8_lossy(&seeded.stderr)
    );
    let before = {
        let db = document.open_db();
        let rows = input_rows(&db);
        assert_eq!(rows.len(), 1, "the base binary records one /1 input");
        assert_eq!(rows[0].format, "jsonl", "which it framed as JSONL");
        assert_eq!(rows[0].state, "complete", "and completed");
        let records = record_rows(&db, rows[0].id);
        assert_eq!(records.len(), 1, "one JSONL record for the single line");
        assert_eq!(
            canonical_messages(&db, rows[0].id),
            Vec::<(String, String)>::new(),
            "the JSONL read of a document projects no message"
        );
        (rows.clone(), receipt_rows(&db), records)
    };
    // The document case's original, read back from its own sealed reference,
    // exactly as the JSONL case does: the file on disk is not the only thing
    // that may change.
    let old_blob = sealed_blob_bytes(&document.data_dir(), &before.0[0]);
    assert_eq!(
        sha256_hex(&old_blob),
        before.0[0].sealed_sha256_hex.to_lowercase(),
        "the stored blob is the /1 input's sealed original"
    );

    let candidate_run = document.run_index();
    assert_eq!(
        candidate_run.status.code(),
        Some(0),
        "the candidate re-ingests the document source; stderr={}",
        String::from_utf8_lossy(&candidate_run.stderr)
    );
    let bytes = std::fs::read(&path).expect("re-read the source bytes");
    let after = {
        let db = document.open_db();
        let rows = input_rows(&db);
        assert_eq!(rows.len(), 2, "the document gets its own new generation");
        assert_eq!(
            rows[0], before.0[0],
            "the /1 row is byte for byte unchanged"
        );
        let new = rows
            .iter()
            .find(|row| row.key_hex != before.0[0].key_hex)
            .expect("the new generation is a distinct input")
            .clone();
        assert_eq!(new.format, "json_document", "the new input is a document");
        assert_eq!(new.state, "complete", "and completes");
        assert_ne!(
            new.normalizer_id, before.0[0].normalizer_id,
            "under the new normalizer identity"
        );

        let records = record_rows(&db, new.id);
        assert_eq!(records.len(), 1, "the document is one record");
        assert_eq!(
            (records[0].byte_start, records[0].byte_end),
            (0, bytes.len() as u64),
            "covering the whole file"
        );
        assert_eq!(records[0].parse_state, "parsed");
        assert_eq!(
            canonical_messages(&db, new.id),
            vec![
                ("user".to_string(), question.to_string()),
                ("assistant".to_string(), answer.to_string()),
            ],
            "and the candidate projects the document's two messages"
        );
        assert_eq!(
            record_rows(&db, before.0[0].id),
            before.2,
            "the /1 records are unchanged beside the new ones"
        );
        assert_eq!(
            sealed_blob_bytes(&document.data_dir(), &before.0[0]),
            old_blob,
            "and the /1 original is still the same bytes"
        );

        let receipts = receipt_rows(&db);
        assert_eq!(receipts.len(), before.1.len() + 1, "one new receipt");
        assert_eq!(
            &receipts[..before.1.len()],
            &before.1[..],
            "the /1 receipt rows are unchanged"
        );
        (rows, receipts)
    };

    // Repeating the candidate adds nothing: no third input, no new receipt.
    let repeat = document.run_index();
    assert_eq!(
        repeat.status.code(),
        Some(0),
        "the repeat run must succeed; stderr={}",
        String::from_utf8_lossy(&repeat.stderr)
    );
    {
        let db = document.open_db();
        assert_eq!(
            input_rows(&db),
            after.0,
            "a repeated candidate run adds no input for the same version"
        );
        assert_eq!(
            receipt_rows(&db),
            after.1,
            "and adds no receipt for the same version"
        );
    }
}

// ---------------------------------------------------------------------------
// F6: an excluded body must not survive anywhere in a document's message
// ---------------------------------------------------------------------------

/// The body the exclusion rules remove, in the shape Codex's own shell-opener
/// anchor recognises: a user turn that ends with the environment-context
/// closer and carries a `<cwd>` inside the block.
const EXCLUDED_DOCUMENT_BODY: &str = "synthetic excluded context body for the document case";

/// The full text the shell-opener anchor recognises.
fn excluded_context_body() -> String {
    format!(
        "<environment_context>\n<cwd>/synthetic/project</cwd>\n{EXCLUDED_DOCUMENT_BODY}\n</environment_context>"
    )
}

fn codex_document_with_shell_opener() -> serde_json::Value {
    let body = excluded_context_body();
    serde_json::json!({
        "session": {
            "id": "sess-f6",
            "cwd": "/synthetic/document-project",
            "cli_version": "0.42.0"
        },
        "items": [
            {
                "type": "message",
                "role": "user",
                "call_id": "call_synthetic_0001",
                "unknown_member": {"keep": [1, 2, 3], "note": "unknown fields must survive"},
                "usage": {"input_tokens": 11, "output_tokens": 22},
                // All four names the JSONL entry field map addresses. A
                // document item is not a JSONL entry: the document projection
                // never reads any of them, so all four are metadata here and
                // must survive.
                "arguments": {"keep": "synthetic arguments marker"},
                "output": "synthetic non-body marker",
                "input": {"keep": "synthetic input marker"},
                "message": "synthetic message marker",
                "content": [{"type": "input_text", "text": body}]
            },
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "acknowledged"}]
            }
        ]
    })
}

/// The members that lived beside the excluded body, which a clearing claim may
/// not take with it. A claim proves the *range* a message came from; it is not
/// a licence to delete that range's siblings, and four of these are named after
/// fields the JSONL envelope's own field map clears.
const SURVIVING_MEMBERS: [&str; 7] = [
    "call_synthetic_0001",
    "unknown_member",
    "input_tokens",
    "synthetic arguments marker",
    "synthetic non-body marker",
    "synthetic input marker",
    "synthetic message marker",
];

/// The controller's safety counter-example, as a named case: a codex document
/// whose first user item is a shell opener. The excluded body must be gone from
/// the message's rendered content, from the message's own stored `extra` in
/// both stored forms, and from the record's stored payload - while the ids,
/// usage and unknown members around it survive everywhere they were kept.
#[test]
fn f6_document_exclusion_clears_every_copy() {
    let fixture = Fixture::new();
    let body = pretty_document(&codex_document_with_shell_opener());
    fixture.write_codex_file("rollout-2026-01-01T00-00-00-f6.json", &body);

    let output = fixture.run_index();
    assert_eq!(
        output.status.code(),
        Some(0),
        "the document with an excluded body must ingest; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let db = fixture.open_db();
    let input = input_ending_with(&db, "rollout-2026-01-01T00-00-00-f6.json");
    assert_eq!(input.format, "json_document");
    assert_eq!(input.state, "complete");
    assert_eq!(record_rows(&db, input.id).len(), 1);

    // 1. The canonical message the connector projected.
    let messages = canonical_messages(&db, input.id);
    assert_eq!(messages.len(), 2, "both turns are projected");
    let (user_role, user_content) = &messages[0];
    assert_eq!(user_role, "user");
    assert!(
        !user_content.contains(EXCLUDED_DOCUMENT_BODY),
        "the excluded body must not survive in the rendered content: {user_content}"
    );
    // The other turn is untouched: the clearing is scoped to the excluded row.
    assert_eq!(
        messages[1],
        ("assistant".to_string(), "acknowledged".to_string()),
        "the assistant turn is not part of the exclusion"
    );

    // 2. The message's own stored extra, in both stored forms. The body is a
    //    copy there too, so clearing only the rendered content is not enough.
    //    `hex()` renders uppercase, and the needles are lowercase hex.
    let (extra_json, extra_bin_hex): (String, String) = db
        .query_row_map(
            "SELECT COALESCE(extra_json, ''), COALESCE(lower(hex(extra_bin)), '')
             FROM messages WHERE role = 'user' ORDER BY id LIMIT 1",
            &[],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .expect("read the user message's extra");
    assert!(
        !extra_json.contains(EXCLUDED_DOCUMENT_BODY),
        "the JSON extra must not keep the body: {extra_json}"
    );
    let body_hex = hex::encode(EXCLUDED_DOCUMENT_BODY);
    assert!(
        !extra_bin_hex.contains(&body_hex),
        "the binary extra must not keep the body"
    );
    // The clearing really addressed this extra rather than finding nothing:
    // the members that lived beside the body are still there.
    for needle in SURVIVING_MEMBERS {
        assert!(
            extra_json.contains(needle) || extra_bin_hex.contains(&hex::encode(needle)),
            "{needle} must survive in the message extra"
        );
    }

    // 3. The record's own stored payload.
    let stored = safe_value(&db, input.id).to_string();
    assert!(
        !stored.contains(EXCLUDED_DOCUMENT_BODY),
        "the stored payload must not keep the body"
    );
    for needle in SURVIVING_MEMBERS {
        assert!(
            stored.contains(needle),
            "{needle} must survive in the stored payload"
        );
    }
}

/// Two turns carrying the *same* text, of which only the first is excluded: the
/// shape that separates a document, whose one record holds every element, from
/// JSONL, whose record is the entry.
fn codex_document_with_shared_body() -> serde_json::Value {
    let body = excluded_context_body();
    serde_json::json!({
        "session": {
            "id": "sess-f7",
            "cwd": "/synthetic/document-project",
            "cli_version": "0.42.0"
        },
        "items": [
            // A leading element the projection skips: it carries no content, so
            // it projects no message. Element 0 is therefore *not* message 0,
            // and a pointer read as a message index would address the wrong
            // element.
            {},
            {
                "type": "message",
                "role": "user",
                "timestamp": "2026-01-01T00:00:00.000Z",
                "content": [{"type": "input_text", "text": body}]
            },
            {
                "type": "message",
                "role": "assistant",
                "timestamp": "2026-01-01T00:00:01.000Z",
                "content": [{"type": "output_text", "text": body}]
            }
        ]
    })
}

/// The exclusion of one element must stay inside that element. A document's
/// single record holds both turns, so clearing the record - or treating every
/// other turn in it as a sibling of the excluded one - would take the second
/// turn's identical text with it. The JSONL control for this shape keeps both
/// the second turn's content and its stored record, so the document must too.
#[test]
fn f7_document_exclusion_stays_inside_its_element() {
    let fixture = Fixture::new();
    let body = excluded_context_body();
    let document = pretty_document(&codex_document_with_shared_body());
    fixture.write_codex_file("rollout-2026-01-01T00-00-00-f7.json", &document);

    let output = fixture.run_index();
    assert_eq!(
        output.status.code(),
        Some(0),
        "the document must ingest; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let db = fixture.open_db();
    let input = input_ending_with(&db, "rollout-2026-01-01T00-00-00-f7.json");
    assert_eq!(input.format, "json_document");
    assert_eq!(input.state, "complete");
    assert_eq!(record_rows(&db, input.id).len(), 1, "one record holds both turns");

    // Only the first turn is excluded, and only its own copies are gone.
    let messages = canonical_messages(&db, input.id);
    assert_eq!(messages.len(), 2, "both turns are projected");
    // The element the excluded message came from is not the message's own
    // index: the leading empty element is skipped by the projection.
    let stored_elements = safe_value(&db, input.id);
    assert_eq!(
        stored_elements
            .get("items")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(3),
        "three elements were sealed, two of which became messages"
    );
    assert_eq!(messages[0].0, "user");
    assert!(
        !messages[0].1.contains(EXCLUDED_DOCUMENT_BODY),
        "the excluded turn's own content is cleared"
    );
    assert_eq!(
        messages[1],
        ("assistant".to_string(), body.clone()),
        "the second turn's identical text is not part of the exclusion"
    );

    let excluded_flags: Vec<(String, i64)> = db
        .query_all_map(
            "SELECT role, CASE WHEN excluded IS NULL THEN 0 ELSE 1 END
             FROM messages ORDER BY idx",
            &[],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .expect("query excluded");
    assert_eq!(
        excluded_flags,
        vec![("user".to_string(), 1), ("assistant".to_string(), 0)],
        "exactly the first turn carries the exclusion marker"
    );

    // The second turn's `extra` keeps its own copy, exactly as the JSONL
    // control does.
    let (extra_json, extra_bin_hex): (String, String) = db
        .query_row_map(
            "SELECT COALESCE(extra_json, ''), COALESCE(lower(hex(extra_bin)), '')
             FROM messages WHERE role = 'assistant' ORDER BY id LIMIT 1",
            &[],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .expect("read the assistant message's extra");
    let body_hex = hex::encode(EXCLUDED_DOCUMENT_BODY);
    assert!(
        extra_json.contains(EXCLUDED_DOCUMENT_BODY) || extra_bin_hex.contains(&body_hex),
        "the second turn's extra keeps its own text"
    );

    // And the record keeps exactly one copy: the second turn's. The first
    // turn's copy is the one the exclusion removed.
    let stored = stored_elements.to_string();
    assert_eq!(
        stored.matches(EXCLUDED_DOCUMENT_BODY).count(),
        1,
        "only the excluded turn's copy is cleared out of the record"
    );
    assert!(
        stored.contains("[REDACTED]"),
        "the excluded turn's own slot is the one the clearing replaced: {stored}"
    );
}

fn claude_jsonl_user(session_id: &str, question: &str) -> String {
    serde_json::json!({
        "parentUuid": null,
        "cwd": "/synthetic/document-project",
        "sessionId": session_id,
        "version": "2.0.37",
        "type": "user",
        "message": {"role": "user", "content": question},
        "uuid": format!("{session_id}-user"),
        "timestamp": "2026-01-01T00:00:00.000Z"
    })
    .to_string()
}

fn claude_jsonl_assistant(session_id: &str, answer: &str) -> String {
    serde_json::json!({
        "parentUuid": format!("{session_id}-user"),
        "cwd": "/synthetic/document-project",
        "sessionId": session_id,
        "version": "2.0.37",
        "type": "assistant",
        "message": {
            "model": "claude-opus-4",
            "role": "assistant",
            "content": [{"type": "text", "text": answer}]
        },
        "uuid": format!("{session_id}-assistant"),
        "timestamp": "2026-01-01T00:00:01.000Z"
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// F5: the stored profile material, and replay
// ---------------------------------------------------------------------------

#[test]
fn f5_profile_and_replay() {
    let question = "synthetic profile question";
    let answer = "synthetic profile answer";
    let fixture = Fixture::new();
    // Compact, so the frozen base binary completes it as a JSONL input: a
    // multi-line document would be a parse failure under `/1` framing, and this
    // case is about the profile identity and the replay, not about that.
    let body = claude_document("sess-f5", question, answer).to_string();
    fixture.write_claude_file("proj-f5", "session.json", &body);

    // The frozen base binary leaves one /1 input behind, so the re-scan has an
    // older generation to sit beside.
    let seeded = fixture.run_index_with(&baseline_bin(), &[]);
    assert_eq!(
        seeded.status.code(),
        Some(0),
        "the base binary seeds the /1 generation; stderr={}",
        String::from_utf8_lossy(&seeded.stderr)
    );
    let (old_row, old_receipts, old_messages) = {
        let db = fixture.open_db();
        let rows = input_rows(&db);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].format, "jsonl", "the /1 read frames it line by line");
        let messages = message_count(&db);
        assert_eq!(
            messages, 0,
            "and the /1 read of a document projects no message at all"
        );
        (rows[0].clone(), receipt_rows(&db), messages)
    };

    let first = fixture.run_index();
    assert_eq!(
        first.status.code(),
        Some(0),
        "the candidate scans the source under the new domain; stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    let (rows_after_first, receipts_after_first, messages_after_first) = {
        let db = fixture.open_db();
        let rows = input_rows(&db);
        assert_eq!(rows.len(), 2, "one new generation for the same source");
        assert_eq!(rows[0], old_row, "the /1 row keeps every byte it had");
        assert_eq!(
            message_count(&db),
            2,
            "the document's two messages are new material"
        );
        assert_eq!(
            receipt_rows(&db).len(),
            old_receipts.len() + 1,
            "one new receipt"
        );
        assert_eq!(
            &receipt_rows(&db)[..old_receipts.len()],
            &old_receipts[..],
            "the /1 receipts are unchanged"
        );
        (rows, receipt_rows(&db), message_count(&db))
    };

    let new_row = rows_after_first[1].clone();
    assert_eq!(new_row.format, "json_document");
    assert_eq!(new_row.state, "complete");
    assert_ne!(
        new_row.normalizer_id, old_row.normalizer_id,
        "the stored profile material is the new mapping domain's identity"
    );

    // Repeating the candidate is a genuine replay: no new input, no new record,
    // no new receipt, no new message.
    let repeat = fixture.run_index();
    assert_eq!(
        repeat.status.code(),
        Some(0),
        "the repeat run must succeed; stderr={}",
        String::from_utf8_lossy(&repeat.stderr)
    );
    let repeat_db = fixture.open_db();
    assert_eq!(
        input_rows(&repeat_db),
        rows_after_first,
        "a repeated run adds no input"
    );
    assert_eq!(
        receipt_rows(&repeat_db),
        receipts_after_first,
        "and no receipt"
    );
    assert_eq!(
        message_count(&repeat_db),
        messages_after_first,
        "and no message"
    );
    assert_eq!(
        record_rows(&repeat_db, new_row.id).len(),
        1,
        "the document input still holds exactly its one record"
    );
    // The stored profile material is the one the scan assembles now: the repeat
    // run matched it and skipped the file, which is what the unchanged rows
    // above prove. A domain the code no longer computes would have re-ingested.
    assert_eq!(
        record_rows(&repeat_db, old_row.id).len(),
        1,
        "and the /1 generation keeps its records"
    );
}
