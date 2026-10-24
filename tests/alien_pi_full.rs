//! Ticket 02 (`cass-alien-fresh-ingest`): black-box Pi full cleanup.
//!
//! Seventeen frozen fixtures (P01..P17) are ingested through the real
//! `cass index --full` CLI twice each: the default streaming path and the
//! batch path (`CASS_STREAMING_INDEX=0`). Every case owns a fresh data dir,
//! HOME, XDG roots and TMPDIR, and the child process starts from an empty
//! environment, so no case can see another case's database or the operator's
//! real credentials, model configuration or session history.
//!
//! The judgments are the frozen ticket-02 table: what was excluded, what was
//! preserved, the per-reason uncovered counters, and the parse-error markers
//! all come from the manifest. The DB is opened read-only through the
//! in-repo storage API; the raw mirror, the CLI JSON surfaces and the
//! `cass::scan_session` diagnostics are checked against the same run.
//!
//! `CASS_ALIEN_TEST_CASS_BIN` is honored only here, in `cass_bin()`, and only
//! so the pre-fix red can run this same test source against the frozen old
//! CLI. Candidate, mutation and restore runs must leave it unset.

use coding_agent_search::storage::api::Conn;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const MANIFEST_JSON: &str = include_str!("fixtures/alien_pi_full/manifest.json");

// ============================================================================
// Manifest and fixture inputs
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Stream,
    Batch,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Self::Stream => "stream",
            Self::Batch => "batch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Expected {
    messages: u64,
    excluded: u64,
    parse_error: u64,
    uncovered: BTreeMap<String, u64>,
    ordinary_user: String,
    ordinary_final: String,
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alien_pi_full")
}

fn manifest() -> Value {
    serde_json::from_str(MANIFEST_JSON).expect("fixture manifest is JSON")
}

fn manifest_case(id: &str) -> Value {
    manifest()["cases"]
        .as_array()
        .expect("manifest cases array")
        .iter()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("manifest case {id} missing"))
        .clone()
}

fn fixture_file(id: &str) -> PathBuf {
    let case = manifest_case(id);
    let name = Path::new(case["file"].as_str().expect("manifest file"))
        .file_name()
        .expect("fixture file name")
        .to_owned();
    fixture_dir().join(name)
}

fn expected_for(id: &str) -> Expected {
    let case = manifest_case(id);
    let expected = &case["expected"];
    Expected {
        messages: expected["messages"].as_u64().expect("expected messages"),
        excluded: expected["recall_excluded"]
            .as_u64()
            .expect("expected recall_excluded"),
        parse_error: expected["parse_error_markers"]
            .as_u64()
            .expect("expected parse_error_markers"),
        uncovered: u64_map(&expected["uncovered"]),
        ordinary_user: expected["ordinary_user"]
            .as_str()
            .expect("expected ordinary_user")
            .to_string(),
        ordinary_final: expected["ordinary_final"]
            .as_str()
            .expect("expected ordinary_final")
            .to_string(),
    }
}

fn u64_map(value: &Value) -> BTreeMap<String, u64> {
    value
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        value.as_u64().unwrap_or_else(|| panic!("{key}: u64")),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The `message` records of a Pi session file, in file order. The connector
/// emits exactly these records as canonical messages; a fixture that violated
/// that would fail the message-count assertion instead of silently shifting
/// every row.
fn session_records(bytes: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value.get("type").and_then(Value::as_str) == Some("message"))
        .collect()
}

/// The 1-based physical line of each canonical message record, which is what
/// `PiFacts` stamps into `excluded.raw.event_key` (`pi:line:N`).
fn physical_lines(bytes: &[u8]) -> Vec<u64> {
    String::from_utf8_lossy(bytes)
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .filter(|(_, line)| {
            serde_json::from_str::<Value>(line)
                .map(|value| value.get("type").and_then(Value::as_str) == Some("message"))
                .unwrap_or(false)
        })
        .map(|(index, _)| index as u64 + 1)
        .collect()
}

/// The connector's flattened body for one message record: a plain string
/// as-is, otherwise its text/thinking/toolCall parts joined by a newline. This
/// mirrors the pinned FAD projection exactly, so a preserved row's stored body
/// can be compared against the raw record.
fn flatten_text_body(record: &Value) -> String {
    let content = record.pointer("/message/content");
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|block| match block.get("type").and_then(Value::as_str) {
                Some("text") => block
                    .get("text")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                Some("thinking") => block
                    .get("thinking")
                    .and_then(Value::as_str)
                    .map(|text| format!("[Thinking] {text}")),
                Some("toolCall") => {
                    let name = block
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let args = block
                        .get("arguments")
                        .and_then(Value::as_object)
                        .map(|map| {
                            map.iter()
                                .filter_map(|(key, value)| {
                                    value.as_str().map(|value| format!("{key}={value}"))
                                })
                                .take(3)
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    Some(if args.is_empty() {
                        format!("[Tool: {name}]")
                    } else {
                        format!("[Tool: {name}] {args}")
                    })
                }
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Indices of the body leaves that a cleanup may clear: the whole string, or
/// every `text` block of a text-bodied array.
fn body_block_indices(record: &Value) -> Vec<u64> {
    match record.pointer("/message/content") {
        Some(Value::String(_)) => vec![0],
        Some(Value::Array(blocks)) => blocks
            .iter()
            .enumerate()
            .filter(|(_, block)| block.get("type").and_then(Value::as_str) == Some("text"))
            .map(|(index, _)| index as u64)
            .collect(),
        _ => Vec::new(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

// ============================================================================
// Process harness
// ============================================================================

/// The candidate CLI. `CASS_ALIEN_TEST_CASS_BIN` exists only for the frozen
/// pre-fix red and is never consulted by any other path in this file.
fn cass_bin() -> PathBuf {
    match std::env::var_os("CASS_ALIEN_TEST_CASS_BIN") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(
                path.is_file(),
                "CASS_ALIEN_TEST_CASS_BIN must name an existing CLI: {}",
                path.display()
            );
            path
        }
        None => PathBuf::from(env!("CARGO_BIN_EXE_cass")),
    }
}

fn claim_artifact_dir(parent: &Path, label: &str) -> PathBuf {
    let mut attempt = 0u32;
    loop {
        let name = if attempt == 0 {
            label.to_string()
        } else {
            format!("{label}-r{}", attempt + 1)
        };
        let candidate = parent.join(name);
        match fs::create_dir(&candidate) {
            Ok(()) => return candidate,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt += 1;
                assert!(
                    attempt < 1000,
                    "cannot claim an artifact directory for {label}"
                );
            }
            Err(err) => panic!(
                "cannot create artifact directory {}: {err}",
                candidate.display()
            ),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct RowView {
    idx: i64,
    role: String,
    content: String,
    excluded: Option<Value>,
    extra: Value,
}

#[derive(Debug)]
struct MirrorFacts {
    blob_relative_path: String,
    blob_sha256: String,
    blob_blake3: String,
    source_sha256: String,
    blob_bytes: Vec<u8>,
}

#[derive(Debug)]
struct CaseRun {
    case: String,
    variant: Option<String>,
    mode: Mode,
    _temp: TempDir,
    source_bytes: Vec<u8>,
    stdout: Value,
    stderr: String,
    rows: Vec<RowView>,
    mirror: MirrorFacts,
    artifact_dir: PathBuf,
}

impl CaseRun {
    fn label(&self) -> String {
        match &self.variant {
            Some(variant) => format!("{}-{variant}-{}", self.case, self.mode.label()),
            None => format!("{}-{}", self.case, self.mode.label()),
        }
    }
}

/// Ingest one session file through the real CLI in one mode and read the
/// resulting database back. Generic assertions run later, against explicit
/// expectations, so every case can also inspect its own rows.
fn run_case(case: &str, variant: Option<&str>, mode: Mode, bytes: &[u8]) -> CaseRun {
    let temp = TempDir::new().expect("case tempdir");
    let root = temp.path().join("case");
    let home = root.join("home");
    let data_dir = root.join("data");
    let tmp = root.join("tmp");
    let cwd = root.join("cwd");
    let sessions = home.join(".pi/agent/sessions").join(case.to_lowercase());
    for dir in [&sessions, &data_dir, &tmp, &cwd] {
        fs::create_dir_all(dir).expect("create case directory");
    }

    let file_name = match variant {
        None => format!("2026-10-24T00-00-00_{case}.jsonl"),
        Some(variant) => format!("2026-10-24T00-00-00_{case}_{variant}.jsonl"),
    };
    let source_path = sessions.join(&file_name);
    fs::write(&source_path, bytes).expect("write case session");

    let label = match variant {
        None => format!("{case}-{}", mode.label()),
        Some(variant) => format!("{case}-{variant}-{}", mode.label()),
    };
    let artifact_parent = match std::env::var_os("CASS_ALIEN_TEST_ARTIFACT_ROOT") {
        Some(root) => {
            let root = PathBuf::from(root);
            fs::create_dir_all(&root).expect("create artifact root");
            root
        }
        None => {
            let fallback = root.join("artifacts");
            fs::create_dir_all(&fallback).expect("create fallback artifact root");
            fallback
        }
    };
    let artifact_dir = claim_artifact_dir(&artifact_parent, &label);
    fs::write(artifact_dir.join("session.jsonl"), bytes).expect("write session evidence");

    let mut cmd = Command::new(cass_bin());
    cmd.args(["-v", "index", "--full", "--data-dir"])
        .arg(&data_dir)
        .args(["--json", "--robot-trace-ingest"])
        .current_dir(&cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("TMPDIR", &tmp)
        // Keep the case offline and deterministic: the update checker would
        // otherwise be the only thing in this run that could touch the network.
        .env("CASS_SKIP_UPDATE", "1");
    if mode == Mode::Batch {
        cmd.env("CASS_STREAMING_INDEX", "0");
    }
    let output = cmd.output().expect("spawn cass index");

    fs::write(artifact_dir.join("stdout.json"), &output.stdout).expect("write stdout");
    fs::write(artifact_dir.join("stderr.log"), &output.stderr).expect("write stderr");
    fs::write(
        artifact_dir.join("exit_code"),
        format!("{:?}\n", output.status.code()),
    )
    .expect("write exit code");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "{}: cass index --full must succeed; exit={:?}\nstderr:\n{}",
        label,
        output.status.code(),
        stderr
    );

    let stdout: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("{label}: stdout is not one JSON document: {err}"));
    let db_path = stdout["db_path"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("agent_search.db"));
    assert!(
        db_path.is_file(),
        "{label}: CLI reported a database at {}",
        db_path.display()
    );

    let (rows, metadata) = read_rows(&db_path, &label);
    fs::write(
        artifact_dir.join("rows.json"),
        serde_json::to_vec_pretty(&rows).expect("rows are serializable"),
    )
    .expect("write rows");

    let source_sha256 = sha256_hex(bytes);
    let mirror = mirror_facts(&data_dir, &metadata, &source_path, &source_sha256, &label);

    CaseRun {
        case: case.to_string(),
        variant: variant.map(str::to_string),
        mode,
        _temp: temp,
        source_bytes: bytes.to_vec(),
        stdout,
        stderr,
        rows,
        mirror,
        artifact_dir,
    }
}

fn decode_json_or_msgpack(
    json_column: Option<String>,
    bin_column: Option<Vec<u8>>,
    what: &str,
) -> Value {
    if let Some(text) = json_column.as_deref().filter(|text| !text.is_empty()) {
        return serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("{what}: JSON column is not JSON: {err}"));
    }
    if let Some(bytes) = bin_column.filter(|bytes| !bytes.is_empty()) {
        return rmp_serde::from_slice(&bytes)
            .unwrap_or_else(|err| panic!("{what}: msgpack column is not decodable: {err}"));
    }
    Value::Null
}

fn read_rows(db_path: &Path, label: &str) -> (Vec<RowView>, Value) {
    let conn = Conn::open_read(db_path).expect("open the case database read-only");
    let conversations: i64 = conn
        .query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| {
            row.get_typed(0)
        })
        .expect("count conversations");
    assert_eq!(
        conversations, 1,
        "{label}: one isolated HOME must hold exactly one conversation"
    );
    let metadata: (Option<String>, Option<Vec<u8>>) = conn
        .query_row_map(
            "SELECT metadata_json, metadata_bin FROM conversations LIMIT 1",
            &[],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .expect("read conversation metadata");
    let metadata = decode_json_or_msgpack(metadata.0, metadata.1, label);

    let raw = conn
        .query_all_map(
            "SELECT m.idx, m.role, m.content, json(m.excluded), m.extra_json, m.extra_bin \
             FROM messages m JOIN conversations c ON c.id = m.conversation_id \
             ORDER BY m.idx",
            &[],
            |row| {
                Ok((
                    row.get_typed::<i64>(0)?,
                    row.get_typed::<String>(1)?,
                    row.get_typed::<String>(2)?,
                    row.get_typed::<Option<String>>(3)?,
                    row.get_typed::<Option<String>>(4)?,
                    row.get_typed::<Option<Vec<u8>>>(5)?,
                ))
            },
        )
        .expect("read message rows");

    let rows = raw
        .into_iter()
        .map(
            |(idx, role, content, excluded, extra_json, extra_bin)| RowView {
                idx,
                role,
                content,
                excluded: excluded.map(|text| {
                    serde_json::from_str(&text)
                        .unwrap_or_else(|err| panic!("{label}: excluded marker is not JSON: {err}"))
                }),
                extra: decode_json_or_msgpack(extra_json, extra_bin, label),
            },
        )
        .collect();
    (rows, metadata)
}

fn mirror_facts(
    data_dir: &Path,
    metadata: &Value,
    source_path: &Path,
    source_sha256: &str,
    label: &str,
) -> MirrorFacts {
    let raw_mirror = &metadata["cass"]["raw_mirror"];
    let blob_relative_path = raw_mirror["blob_relative_path"]
        .as_str()
        .unwrap_or_else(|| panic!("{label}: raw mirror blob path missing: {metadata}"))
        .to_string();
    let expected_blake3 = raw_mirror["blob_blake3"]
        .as_str()
        .unwrap_or_else(|| panic!("{label}: raw mirror blake3 missing: {metadata}"));
    let expected_size = raw_mirror["blob_size_bytes"].as_u64();

    let blob_path = data_dir
        .join("raw-mirror")
        .join("v1")
        .join(&blob_relative_path);
    let blob_bytes = fs::read(&blob_path)
        .unwrap_or_else(|err| panic!("{label}: read mirror blob {}: {err}", blob_path.display()));
    let source_bytes = fs::read(source_path).expect("read case session back");

    assert_eq!(
        sha256_hex(&blob_bytes),
        source_sha256,
        "{label}: capture sha256 must equal the source sha256"
    );
    assert_eq!(
        sha256_hex(&source_bytes),
        source_sha256,
        "{label}: the session file on disk is the captured source"
    );
    assert_eq!(
        blake3_hex(&blob_bytes),
        expected_blake3,
        "{label}: captured blob blake3 must match the recorded metadata"
    );
    if let Some(size) = expected_size {
        assert_eq!(
            blob_bytes.len() as u64,
            size,
            "{label}: captured blob size must match the recorded metadata"
        );
    }

    MirrorFacts {
        blob_relative_path,
        blob_sha256: sha256_hex(&blob_bytes),
        blob_blake3: blake3_hex(&blob_bytes),
        source_sha256: source_sha256.to_string(),
        blob_bytes,
    }
}

// ============================================================================
// Judgments
// ============================================================================

fn round_total(expected: &Expected) -> u64 {
    expected.uncovered.values().copied().sum()
}

/// AC3: the CLI stdout, `indexing_stats`, the stderr `completed` event and
/// the Pi `cass::scan_session` line all report the same per-reason map.
fn assert_round_surface(run: &CaseRun, expected: &Expected) {
    let label = run.label();
    let total = round_total(expected);
    let stdout = &run.stdout;

    assert_eq!(
        stdout["recall_uncovered_total"].as_u64(),
        Some(total),
        "{label}: stdout recall_uncovered_total"
    );
    assert_eq!(
        u64_map(&stdout["recall_uncovered_by_reason"]),
        expected.uncovered,
        "{label}: stdout recall_uncovered_by_reason"
    );
    assert_eq!(
        stdout["indexing_stats"]["recall_uncovered_total"].as_u64(),
        Some(total),
        "{label}: indexing_stats total"
    );
    assert_eq!(
        u64_map(&stdout["indexing_stats"]["recall_uncovered_by_reason"]),
        expected.uncovered,
        "{label}: indexing_stats by reason"
    );
    assert_eq!(
        stdout["messages"].as_u64(),
        Some(expected.messages),
        "{label}: stdout messages"
    );
    assert_eq!(
        stdout["conversations"].as_u64(),
        Some(1),
        "{label}: stdout conversations"
    );

    let events: Vec<Value> = run
        .stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect();
    let completed = events
        .iter()
        .find(|event| event["event"].as_str() == Some("completed"))
        .unwrap_or_else(|| panic!("{label}: stderr has no completed event"));
    assert_eq!(
        completed["recall_uncovered_total"].as_u64(),
        Some(total),
        "{label}: completed event total"
    );
    assert_eq!(
        u64_map(&completed["recall_uncovered_by_reason"]),
        expected.uncovered,
        "{label}: completed event by reason"
    );

    let pi_lines: Vec<&str> = run
        .stderr
        .lines()
        .filter(|line| line.contains("scan_session") && line.contains("agent=pi_agent"))
        .collect();
    assert_eq!(
        pi_lines.len(),
        1,
        "{label}: exactly one Pi scan_session line per successful input; stderr:\n{}",
        run.stderr
    );
    let line = pi_lines[0];
    for old_field in ["external_id=", "bytes=", "outcome="] {
        assert!(
            line.contains(old_field),
            "{label}: the Pi scan_session line keeps the old field {old_field}: {line}"
        );
    }
    assert!(
        field_after(line, "outcome=").trim_matches('"') == "inserted",
        "{label}: a fresh database inserts the conversation: {line}"
    );
    assert_eq!(
        field_after(line, "recall_uncovered_total=")
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{label}: scan_session total is a u64: {line}")),
        total,
        "{label}: scan_session per-case total equals the round JSON"
    );
    let marker = "recall_uncovered_by_reason=";
    let map: BTreeMap<String, u64> = serde_json::from_str(field_after(line, marker))
        .unwrap_or_else(|err| {
            panic!("{label}: scan_session by-reason is not JSON ({err}): {line}")
        });
    assert_eq!(
        map, expected.uncovered,
        "{label}: scan_session per-case map equals the round JSON"
    );
}

fn field_after<'a>(line: &'a str, marker: &str) -> &'a str {
    let start = line
        .find(marker)
        .unwrap_or_else(|| panic!("field {marker} missing in: {line}"))
        + marker.len();
    line[start..].split_whitespace().next().unwrap_or_default()
}

/// AC1 and AC2: every row matches the manifest and the frozen cleanup rules.
fn assert_rows(run: &CaseRun, expected: &Expected, records: &[Value], lines: &[u64]) {
    let label = run.label();
    assert_eq!(
        records.len() as u64,
        expected.messages,
        "{label}: the fixture holds exactly the manifest's message records"
    );
    assert_eq!(
        lines.len(),
        records.len(),
        "{label}: every canonical message has one physical line"
    );
    assert_eq!(
        run.rows.len() as u64,
        expected.messages,
        "{label}: the database holds the manifest's message count"
    );

    let excluded: Vec<&RowView> = run
        .rows
        .iter()
        .filter(|row| row.excluded.is_some())
        .collect();
    assert_eq!(
        excluded.len() as u64,
        expected.excluded,
        "{label}: excluded row count"
    );
    let parse_errors = excluded
        .iter()
        .filter(|row| {
            row.excluded
                .as_ref()
                .and_then(|marker| marker["parse_error"].as_str())
                .is_some()
        })
        .count() as u64;
    assert_eq!(
        parse_errors, expected.parse_error,
        "{label}: parse-error marker count"
    );

    for row in &run.rows {
        let idx = usize::try_from(row.idx).unwrap_or_else(|_| panic!("{label}: negative row idx"));
        let record = records
            .get(idx)
            .unwrap_or_else(|| panic!("{label}: row idx {idx} has no source record"));
        match &row.excluded {
            Some(marker) => assert_positive_row(run, row, record, marker, lines[idx]),
            None => assert_negative_row(run, row, record),
        }
    }

    // The ordinary first user message and the final answer stay byte-for-byte
    // identical in the stored body (AC2).
    let user = run
        .rows
        .iter()
        .find(|row| row.role == "user")
        .unwrap_or_else(|| panic!("{label}: fixture has no user row"));
    assert_eq!(
        user.content, expected.ordinary_user,
        "{label}: the ordinary user body is unchanged"
    );
    let last = run.rows.last().expect("at least one row");
    assert_eq!(
        last.content, expected.ordinary_final,
        "{label}: the ordinary final answer is unchanged"
    );

    // The captured mirror still holds every cleared body verbatim. The blob is
    // the captured source file, so the comparison decodes its own records
    // rather than searching raw bytes: JSON escaping in the file must not be
    // mistaken for a rewritten body.
    let mirror_records = session_records(&run.mirror.blob_bytes);
    assert_eq!(
        mirror_records.len(),
        records.len(),
        "{label}: the captured mirror holds the same message records"
    );
    for row in excluded {
        let idx = usize::try_from(row.idx).expect("row idx");
        let body = flatten_text_body(&records[idx]);
        assert!(!body.is_empty(), "{label}: an excluded body is never empty");
        assert_eq!(
            flatten_text_body(&mirror_records[idx]),
            body,
            "{label}: the raw mirror keeps the original body of row {idx}"
        );
    }
}

fn assert_positive_row(run: &CaseRun, row: &RowView, record: &Value, marker: &Value, line: u64) {
    let label = run.label();
    assert_eq!(
        row.content, "",
        "{label}: an excluded row's body is cleared: row {}",
        row.idx
    );
    assert_eq!(
        marker["reason"].as_str(),
        Some("cass_recall"),
        "{label}: excluded reason at row {}",
        row.idx
    );
    assert_eq!(
        marker["rule_version"].as_u64(),
        Some(2),
        "{label}: v2 rule version at row {}",
        row.idx
    );

    let body = flatten_text_body(record);
    let sha256 = marker["sha256"]
        .as_str()
        .unwrap_or_else(|| panic!("{label}: marker sha256 missing at row {}", row.idx));
    assert_eq!(sha256.len(), 64, "{label}: marker sha256 is hex64");
    assert_eq!(
        sha256,
        sha256_hex(body.as_bytes()),
        "{label}: the marker hashes the cleared body at row {}",
        row.idx
    );
    assert_eq!(
        marker["bytes"].as_u64(),
        Some(body.len() as u64),
        "{label}: the marker records the cleared body length at row {}",
        row.idx
    );
    assert_eq!(
        marker["fingerprint_blake3"].as_str(),
        Some(blake3_hex(body.as_bytes()).as_str()),
        "{label}: the marker records the body blake3 at row {}",
        row.idx
    );

    assert_eq!(
        marker["raw"]["blob"].as_str(),
        Some(run.mirror.blob_relative_path.as_str()),
        "{label}: the marker names the captured blob at row {}",
        row.idx
    );
    assert_eq!(
        marker["raw"]["idx"].as_u64(),
        Some(row.idx as u64),
        "{label}: the marker records the canonical index at row {}",
        row.idx
    );
    assert_eq!(
        marker["raw"]["event_key"].as_str(),
        Some(format!("pi:line:{line}").as_str()),
        "{label}: the marker names the physical event line at row {}",
        row.idx
    );
    assert_eq!(
        marker["raw"]["blocks"],
        json!(body_block_indices(record)),
        "{label}: the marker keeps the original body block indices at row {}",
        row.idx
    );

    let tool_call_id = record
        .pointer("/message/toolCallId")
        .and_then(Value::as_str);
    let tool_name = record.pointer("/message/toolName").and_then(Value::as_str);
    assert_eq!(
        marker["anchor"]["tool_call_id"].as_str(),
        tool_call_id,
        "{label}: the anchor keeps the real binding id at row {}",
        row.idx
    );
    assert_eq!(
        marker["anchor"]["tool_name"].as_str(),
        tool_name,
        "{label}: the anchor keeps the real binding name at row {}",
        row.idx
    );

    // A damaged strong body is still excluded, with no fabricated source and
    // one bounded parse error; a healthy body keeps its extracted source.
    match marker["parse_error"].as_str() {
        Some(parse_error) => {
            assert_eq!(
                parse_error, "invalid_recall_format",
                "{label}: the parse error is the frozen bounded reason at row {}",
                row.idx
            );
            assert!(
                marker["src"].is_null(),
                "{label}: a damaged body has no invented source at row {}",
                row.idx
            );
        }
        None => assert!(
            marker["src"].is_object(),
            "{label}: a healthy excluded body carries its extracted source at row {}: {marker}",
            row.idx
        ),
    }

    // The whole extra is decoded back: the body keeps its slot as the shared
    // placeholder, every other field and every array index stays, and no
    // original body leaf survives anywhere in the record.
    let original = &record["message"];
    let actual = &row.extra["message"];
    let placeholder = json!({
        "redacted": true,
        "sha256": sha256,
        "bytes": body.len() as u64,
    });
    match (original.get("content"), actual.get("content")) {
        (Some(Value::String(_)), Some(Value::Object(_))) => assert_eq!(
            actual["content"], placeholder,
            "{label}: a string body becomes the placeholder at row {}",
            row.idx
        ),
        (Some(Value::Array(original_blocks)), Some(Value::Array(actual_blocks))) => {
            assert_eq!(
                original_blocks.len(),
                actual_blocks.len(),
                "{label}: every content block index is retained at row {}",
                row.idx
            );
            for (index, (original_block, actual_block)) in
                original_blocks.iter().zip(actual_blocks).enumerate()
            {
                if original_block.get("type").and_then(Value::as_str) == Some("text") {
                    assert_eq!(
                        actual_block["text"], placeholder,
                        "{label}: text block {index} becomes the placeholder at row {}",
                        row.idx
                    );
                    let mut expected_block = original_block.clone();
                    expected_block["text"] = placeholder.clone();
                    assert_eq!(
                        actual_block, &expected_block,
                        "{label}: text block {index} keeps its other keys at row {}",
                        row.idx
                    );
                } else {
                    assert_eq!(
                        actual_block, original_block,
                        "{label}: non-text block {index} is untouched at row {}",
                        row.idx
                    );
                }
            }
        }
        (Some(original_content), Some(actual_content)) => assert_eq!(
            actual_content, original_content,
            "{label}: body shape at row {}",
            row.idx
        ),
        _ => panic!("{label}: row {} has no content slot", row.idx),
    }
    for (key, value) in original
        .as_object()
        .unwrap_or_else(|| panic!("{label}: record message is an object"))
    {
        if key == "content" {
            continue;
        }
        assert_eq!(
            &actual[key], value,
            "{label}: metadata field {key} is retained at row {}",
            row.idx
        );
    }
    for (key, value) in row
        .extra
        .as_object()
        .unwrap_or_else(|| panic!("{label}: extra is an object"))
    {
        if key == "message" {
            continue;
        }
        assert_eq!(
            value, &record[key],
            "{label}: record field {key} is retained at row {}",
            row.idx
        );
    }
    let decoded = serde_json::to_string(&row.extra).expect("extra serializes");
    for leaf in body_leaves(record) {
        assert!(
            !decoded.contains(&leaf),
            "{label}: the cleared body leaf does not survive in the decoded extra at row {}",
            row.idx
        );
    }
}

fn body_leaves(record: &Value) -> Vec<String> {
    match record.pointer("/message/content") {
        Some(Value::String(text)) => vec![text.clone()],
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .filter(|text| !text.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn assert_negative_row(run: &CaseRun, row: &RowView, record: &Value) {
    let label = run.label();
    assert_eq!(
        row.extra, *record,
        "{label}: a preserved row keeps its whole raw record at row {}",
        row.idx
    );
    assert_eq!(
        row.content,
        flatten_text_body(record),
        "{label}: a preserved row keeps its flattened body verbatim at row {}",
        row.idx
    );
}

/// One JSON record per executed case (34 fixed + derived cases separately).
fn emit_case_record(run: &CaseRun, expected: &Expected) {
    let excluded = run.rows.iter().filter(|row| row.excluded.is_some()).count() as u64;
    let parse_error = run
        .rows
        .iter()
        .filter(|row| {
            row.excluded
                .as_ref()
                .and_then(|marker| marker["parse_error"].as_str())
                .is_some()
        })
        .count() as u64;
    assert_eq!(
        excluded,
        expected.excluded,
        "{}: record excluded",
        run.label()
    );
    assert_eq!(
        parse_error,
        expected.parse_error,
        "{}: record parse errors",
        run.label()
    );
    let record = json!({
        "record": "cass_alien_pi_full_case",
        "case": run.case,
        "variant": run.variant,
        "mode": run.mode.label(),
        "messages": run.rows.len() as u64,
        "excluded": excluded,
        "uncovered": expected.uncovered,
        "uncovered_total": round_total(expected),
        "parse_error": parse_error,
        "source_sha256": run.mirror.source_sha256,
        "mirror_sha256": run.mirror.blob_sha256,
        "mirror_blake3": run.mirror.blob_blake3,
        "evidence": run.artifact_dir.display().to_string(),
    });
    fs::write(
        run.artifact_dir.join("case.json"),
        serde_json::to_vec_pretty(&record).expect("case record serializes"),
    )
    .expect("write case record");
    eprintln!(
        "{}",
        serde_json::to_string(&record).expect("case record serializes")
    );
}

fn run_and_judge(
    case: &str,
    variant: Option<&str>,
    mode: Mode,
    bytes: &[u8],
    expected: &Expected,
) -> CaseRun {
    let run = run_case(case, variant, mode, bytes);
    let records = session_records(bytes);
    let lines = physical_lines(bytes);
    // Rows first: a pre-fix binary must go red on the cleanup itself (an
    // uncleaned body), not merely on a missing observability field.
    assert_rows(&run, expected, &records, &lines);
    assert_round_surface(&run, expected);
    emit_case_record(&run, expected);
    run
}

/// Both real `--full` paths for one frozen fixture, each in a brand-new data
/// directory: 17 fixtures x 2 modes = the 34 fixed cases.
fn run_fixture(id: &str) -> Vec<CaseRun> {
    let expected = expected_for(id);
    let bytes = fs::read(fixture_file(id)).expect("read fixture");
    assert_eq!(
        sha256_hex(&bytes).len(),
        64,
        "{id}: the fixture bytes are readable"
    );
    vec![
        run_and_judge(id, None, Mode::Stream, &bytes, &expected),
        run_and_judge(id, None, Mode::Batch, &bytes, &expected),
    ]
}

// ============================================================================
// Fixed cases P01..P17
// ============================================================================

#[test]
fn alien_pi_full_p01() {
    let _runs = run_fixture("P01");
    run_p01_derived_variants();
}

#[test]
fn alien_pi_full_p02() {
    let _runs = run_fixture("P02");
}

#[test]
fn alien_pi_full_p03() {
    let _runs = run_fixture("P03");
}

#[test]
fn alien_pi_full_p04() {
    let _runs = run_fixture("P04");
}

#[test]
fn alien_pi_full_p05() {
    let _runs = run_fixture("P05");
}

#[test]
fn alien_pi_full_p06() {
    let _runs = run_fixture("P06");
}

#[test]
fn alien_pi_full_p07() {
    let _runs = run_fixture("P07");
}

#[test]
fn alien_pi_full_p08() {
    let _runs = run_fixture("P08");
}

#[test]
fn alien_pi_full_p09() {
    let _runs = run_fixture("P09");
}

#[test]
fn alien_pi_full_p10() {
    let _runs = run_fixture("P10");
}

#[test]
fn alien_pi_full_p11() {
    let _runs = run_fixture("P11");
}

#[test]
fn alien_pi_full_p12() {
    let _runs = run_fixture("P12");
}

#[test]
fn alien_pi_full_p13() {
    let _runs = run_fixture("P13");
}

#[test]
fn alien_pi_full_p14() {
    let _runs = run_fixture("P14");
}

#[test]
fn alien_pi_full_p15() {
    let _runs = run_fixture("P15");
}

#[test]
fn alien_pi_full_p16() {
    let _runs = run_fixture("P16");
}

#[test]
fn alien_pi_full_p17() {
    let runs = run_fixture("P17");
    for run in &runs {
        assert_p17_full_output_path(run);
    }
}

/// P17: the strong result keeps its declared `details.fullOutputPath`
/// verbatim after clearing, and the `read` of exactly that path stays fully
/// preserved. The product never reads the file and never fabricates a reply;
/// the negative read is still diagnosed as an ambiguous identity.
fn assert_p17_full_output_path(run: &CaseRun) {
    let label = run.label();
    let records = session_records(&run.source_bytes);
    let strong = run
        .rows
        .iter()
        .find(|row| {
            row.extra
                .pointer("/message/toolName")
                .and_then(Value::as_str)
                == Some("mcp__cass_mcp__cass_search")
        })
        .unwrap_or_else(|| panic!("{label}: P17 strong result row"));
    let details = &strong.extra["message"]["details"];
    assert_eq!(
        details["fullOutputPath"].as_str(),
        Some("/synthetic/alien/full-output.txt"),
        "{label}: fullOutputPath metadata is preserved verbatim"
    );
    assert_eq!(
        details["server"].as_str(),
        Some("cass-mcp"),
        "{label}: other details metadata is preserved"
    );
    assert!(
        strong.excluded.is_some(),
        "{label}: the strong result itself is the excluded row"
    );

    let read = run
        .rows
        .iter()
        .find(|row| {
            row.extra
                .pointer("/message/toolName")
                .and_then(Value::as_str)
                == Some("read")
        })
        .unwrap_or_else(|| panic!("{label}: P17 read result row"));
    assert!(
        read.excluded.is_none(),
        "{label}: a read of a declared output path is never excluded"
    );
    let read_record = records
        .get(usize::try_from(read.idx).expect("read idx"))
        .unwrap_or_else(|| panic!("{label}: the read row has a source record"));
    assert_eq!(
        read.content,
        flatten_text_body(read_record),
        "{label}: the negative read body is preserved verbatim"
    );
    assert!(
        run.source_bytes
            .windows(b"<cass_recall".len())
            .any(|window| window == b"<cass_recall"),
        "{label}: the fixture does carry the complete envelope it reads back"
    );
    assert!(
        !Path::new("/synthetic/alien/full-output.txt").exists(),
        "{label}: the declared full-output path was never materialized"
    );
}

// ============================================================================
// Derived P01 variants (counted separately from the 34 fixed cases)
// ============================================================================

fn derived_bytes(id: &str, mutate: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let bytes = fs::read(fixture_file(id)).expect("read fixture");
    let mut records: Vec<Value> = String::from_utf8_lossy(&bytes)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("fixture line is JSON"))
        .collect();
    mutate(&mut records);
    let mut text = records
        .iter()
        .map(|record| serde_json::to_string(record).expect("derived record serializes"))
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    text.into_bytes()
}

fn record_index(records: &[Value], id: &str) -> usize {
    records
        .iter()
        .position(|record| record["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("derived session has no record {id}"))
}

fn derived_expected(
    messages: u64,
    excluded: u64,
    uncovered: &[(&str, u64)],
    ordinary_final: &str,
) -> Expected {
    Expected {
        messages,
        excluded,
        parse_error: 0,
        uncovered: uncovered
            .iter()
            .map(|(reason, count)| (reason.to_string(), *count))
            .collect(),
        ordinary_user: "ordinary synthetic user".to_string(),
        ordinary_final: ordinary_final.to_string(),
    }
}

fn run_derived(variant: &str, bytes: &[u8], expected: &Expected) -> Vec<CaseRun> {
    vec![
        run_and_judge("P01", Some(variant), Mode::Stream, bytes, expected),
        run_and_judge("P01", Some(variant), Mode::Batch, bytes, expected),
    ]
}

fn result_row<'a>(run: &'a CaseRun, id: &str) -> &'a RowView {
    run.rows
        .iter()
        .find(|row| row.extra["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("{}: no row for record {id}", run.label()))
}

fn run_p01_derived_variants() {
    let original = fs::read(fixture_file("P01")).expect("read P01");
    let records = session_records(&original);
    let result_idx = records
        .iter()
        .position(|record| {
            record.pointer("/message/role").and_then(Value::as_str) == Some("toolResult")
        })
        .expect("P01 tool result");
    let body = flatten_text_body(&records[result_idx]);

    // 1. An unknown complete copy of the same body elsewhere in the same
    //    record leaves attribution unproven: keep the row and count it.
    let bytes = derived_bytes("P01", |lines| {
        let result = record_index(lines, "r-c1");
        let message = lines[result]["message"]
            .as_object_mut()
            .expect("P01 result message");
        message.insert("opaque_copy".to_string(), Value::String(body.clone()));
    });
    let runs = run_derived(
        "v01_unknown_extra_copy",
        &bytes,
        &derived_expected(4, 0, &[("unpaired_result", 1)], "ordinary synthetic answer"),
    );
    for run in &runs {
        let row = result_row(run, "r-c1");
        assert!(
            row.excluded.is_none(),
            "{}: an unproven copy elsewhere keeps the row",
            run.label()
        );
        assert_eq!(
            row.extra["message"]["opaque_copy"].as_str(),
            Some(body.as_str()),
            "{}: the unproven copy is preserved",
            run.label()
        );
        assert_eq!(
            row.content,
            body,
            "{}: the preserved body stays verbatim",
            run.label()
        );
    }

    // 2. An ordinary cross-message reference is not an unproven in-record
    //    copy: the proven result is still cleared and the reference stays.
    let bytes = derived_bytes("P01", |lines| {
        let final_idx = record_index(lines, "z");
        let final_message = lines[final_idx]["message"]
            .as_object_mut()
            .expect("P01 final message");
        let content = final_message["content"]
            .as_array_mut()
            .expect("final content");
        content.push(json!({ "type": "text", "text": body.clone() }));
    });
    let expected_final = format!("ordinary synthetic answer\n{body}");
    let runs = run_derived(
        "v02_cross_message_reference",
        &bytes,
        &derived_expected(4, 1, &[], &expected_final),
    );
    for run in &runs {
        assert!(
            result_row(run, "r-c1").excluded.is_some(),
            "{}: a cross-message reference does not block the proven result",
            run.label()
        );
        let last = run.rows.last().expect("final row");
        assert!(
            last.content.contains(body.as_str()),
            "{}: the ordinary cross-message reference is preserved",
            run.label()
        );
    }

    // 3. A bare `cass_search` bound to a complete C04 envelope is proven and
    //    cleared through the shared bare-identity core.
    let bytes = derived_bytes("P01", |lines| {
        let assistant = record_index(lines, "a");
        let block = lines[assistant]["message"]["content"]
            .as_array_mut()
            .expect("assistant content")
            .iter_mut()
            .find(|block| block["type"].as_str() == Some("toolCall"))
            .expect("assistant tool call");
        block["name"] = Value::String("cass_search".to_string());
        let result = record_index(lines, "r-c1");
        lines[result]["message"]["toolName"] = Value::String("cass_search".to_string());
    });
    let runs = run_derived(
        "v03_bare_complete_c04",
        &bytes,
        &derived_expected(4, 1, &[], "ordinary synthetic answer"),
    );
    for run in &runs {
        assert!(
            result_row(run, "r-c1").excluded.is_some(),
            "{}: a bound bare name with a complete envelope is cleared",
            run.label()
        );
    }

    // 4. An ordinary same-named tool without the envelope is not a recall at
    //    all: preserved with no warning.
    let bytes = derived_bytes("P01", |lines| {
        let assistant = record_index(lines, "a");
        let block = lines[assistant]["message"]["content"]
            .as_array_mut()
            .expect("assistant content")
            .iter_mut()
            .find(|block| block["type"].as_str() == Some("toolCall"))
            .expect("assistant tool call");
        block["name"] = Value::String("cass_search".to_string());
        let result = record_index(lines, "r-c1");
        lines[result]["message"]["toolName"] = Value::String("cass_search".to_string());
        lines[result]["message"]["content"] = json!([{
            "type": "text",
            "text": "ordinary synthetic tool output",
        }]);
    });
    let runs = run_derived(
        "v04_ordinary_same_name",
        &bytes,
        &derived_expected(4, 0, &[], "ordinary synthetic answer"),
    );
    for run in &runs {
        let row = result_row(run, "r-c1");
        assert!(
            row.excluded.is_none(),
            "{}: an ordinary same-named tool is preserved",
            run.label()
        );
        assert_eq!(
            row.content,
            "ordinary synthetic tool output",
            "{}: the ordinary same-named body is unchanged",
            run.label()
        );
    }

    // 5. A Pi bash call whose own captured command is a real CASS CLI call is
    //    diagnosed, never excluded and never executed.
    let bytes = derived_bytes("P01", |lines| {
        let assistant = record_index(lines, "a");
        let block = lines[assistant]["message"]["content"]
            .as_array_mut()
            .expect("assistant content")
            .iter_mut()
            .find(|block| block["type"].as_str() == Some("toolCall"))
            .expect("assistant tool call");
        block["name"] = Value::String("bash".to_string());
        block["arguments"] = json!({ "command": "cass search synthetic alien" });
        let result = record_index(lines, "r-c1");
        lines[result]["message"]["toolName"] = Value::String("bash".to_string());
        lines[result]["message"]["content"] = json!([{
            "type": "text",
            "text": "ordinary synthetic shell output",
        }]);
    });
    let runs = run_derived(
        "v05_bash_cass",
        &bytes,
        &derived_expected(
            4,
            0,
            &[("unsupported_shell", 1)],
            "ordinary synthetic answer",
        ),
    );
    for run in &runs {
        let row = result_row(run, "r-c1");
        assert!(
            row.excluded.is_none(),
            "{}: a shell call is never excluded",
            run.label()
        );
        assert_eq!(
            row.content,
            "ordinary synthetic shell output",
            "{}: the shell result is preserved verbatim",
            run.label()
        );
    }

    // Each derived run's TempDir is dropped with its `CaseRun`; the artifact
    // evidence above already lives under the run's own directory and nothing
    // here writes back to `tests/fixtures`.
}
