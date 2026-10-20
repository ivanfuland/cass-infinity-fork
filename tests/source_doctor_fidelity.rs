//! Task26: doctor source-rebuild and derived-rebuild fidelity.
//!
//! Four test functions hold the eight independent scenarios fixed by
//! `task-26-test-contract.md` at base a9c9d1b497c81008762c01865ebcaae63b0d3dea:
//!
//! - `doctor_empty_archive_source_rebuild` / `source_rebuild`
//! - `doctor_corrupt_archive_stays_refused` / `corrupt`, `missing`
//! - `doctor_readonly_and_derived_no_source` / `check`, `legacy`, `derived`
//! - `doctor_source_config_failure` / `bad_live`, `bad_fixed`
//!
//! Every case drives the real `cass` binary over its own `TempDir` (private
//! HOME, XDG config/data and connector roots) and reads the resulting SQLite
//! database directly. No SSH, Infinity or model endpoint is used. The legacy
//! pre-state comes from the already-verified public seed through an explicit
//! `#[path]` module, exactly as the contract requires; the seed is not modified
//! and no global defer switch or fabricated lexical state is used.
//!
//! Each case prints `TASK26_SCENARIO test=<function> case=<id> result=pass`
//! only after all of its assertions have passed.

#[path = "util/source_legacy_seed.rs"]
mod source_legacy_seed;

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use coding_agent_search::indexer::scan_root_meta;
use coding_agent_search::storage::api::Conn as FrankenConnection;
use coding_agent_search::storage::api::Value as ParamValue;
use coding_agent_search::storage::source_facts::decode_expected_manifest_header;
use coding_agent_search::storage::sqlite::FrankenStorage;
use rusqlite::OptionalExtension as _;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// The automatic fixed configuration's identity domain (source_ingest.rs).
const AUTO_IDENTITY_PREFIX: &str = "cass.source-config/1:sha256:";

/// Fixed invalid TOML used for both configuration-failure cases.
const BAD_TOML: &[u8] = b"this is not toml [[[\n";

// ---------------------------------------------------------------------------
// CLI harness
// ---------------------------------------------------------------------------

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        fs::create_dir_all(root.path().join("home")).expect("mkdir home");
        fs::create_dir_all(root.path().join("data")).expect("mkdir data");
        fs::create_dir_all(root.path().join("config")).expect("mkdir config");
        fs::write(
            root.path().join("fixed-safety.toml"),
            include_bytes!("../config/excluded_context_paths.toml"),
        )
        .expect("write explicit fixed safety copy");
        Self { root }
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn config_home(&self) -> PathBuf {
        self.root.path().join("config")
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

    fn live_config(&self) -> PathBuf {
        self.config_home()
            .join("cass")
            .join("excluded_context_paths.toml")
    }

    fn corrupt_live_config(&self) {
        let path = self.live_config();
        fs::create_dir_all(path.parent().expect("config parent")).expect("mkdir config");
        fs::write(&path, BAD_TOML).expect("corrupt live config");
    }

    fn auto_config_dir(&self) -> PathBuf {
        self.data_dir().join("source-configs").join("v1")
    }

    fn auto_config_files(&self) -> Vec<PathBuf> {
        let Ok(entries) = fs::read_dir(self.auto_config_dir()) else {
            return Vec::new();
        };
        let mut files: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        files.sort();
        files
    }

    fn create_home_roots(&self) {
        fs::create_dir_all(self.home().join(".claude/projects")).expect("mkdir claude root");
        fs::create_dir_all(self.home().join(".codex/sessions")).expect("mkdir codex root");
    }

    fn write_claude(&self, relative: &str, lines: &[Value]) -> PathBuf {
        let path = self.home().join(".claude/projects").join(relative);
        fs::create_dir_all(path.parent().expect("session parent")).expect("mkdir session dir");
        fs::write(&path, jsonl(lines)).expect("write claude session");
        path
    }

    fn write_codex(&self, relative: &str, lines: &[Value]) -> PathBuf {
        let path = self.home().join(".codex/sessions").join(relative);
        fs::create_dir_all(path.parent().expect("rollout parent")).expect("mkdir rollout dir");
        fs::write(&path, jsonl(lines)).expect("write codex rollout");
        path
    }

    /// Point every source-discovery input at this fixture. Only child-process
    /// environment is touched; the test process environment is never mutated.
    fn isolate(&self, cmd: &mut Command) {
        cmd.env("HOME", self.home())
            .env("XDG_DATA_HOME", self.home().join(".local/share"))
            .env("XDG_CONFIG_HOME", self.config_home())
            .env("CODEX_HOME", self.home().join(".codex"))
            .env("CASS_AIDER_DATA_ROOT", self.home().join(".aider"))
            .env("PI_SESSIONS_DIR", self.home().join(".pi"))
            .env("PI_CODING_AGENT_DIR", self.home().join(".pi"))
            .env("GOOSE_PATH_ROOT", self.home().join(".goose"))
            .env("HERMES_HOME", self.home().join(".hermes"))
            .env("CASS_DATA_DIR", self.data_dir())
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("NO_COLOR", "1")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("CASS_DEFER_LEXICAL_UPDATES")
            .env_remove("CASS_EXCLUDE_PATHS")
            .env_remove("CASS_OUTPUT_FORMAT")
            .env_remove("CASS_TEST_WATCH_PATHS")
            .env_remove("RUST_LOG");
    }

    fn index(&self, extra: &[&str]) -> Output {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .args(extra)
            .arg("--json");
        cmd.output().expect("spawn cass index")
    }

    /// `doctor [<extra>] --json --data-dir <dir>`.
    fn doctor(&self, extra: &[&str]) -> Output {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.arg("doctor")
            .args(extra)
            .args(["--json", "--data-dir"])
            .arg(self.data_dir());
        cmd.output().expect("spawn cass doctor")
    }

    fn search(&self, query: &str) -> Output {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.args(["search", query, "--json", "--mode", "lexical", "--data-dir"])
            .arg(self.data_dir());
        cmd.output().expect("spawn cass search")
    }

    fn open_db(&self) -> rusqlite::Connection {
        let db = rusqlite::Connection::open_with_flags(
            self.db(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open the database read-only");
        db.busy_timeout(Duration::from_secs(30))
            .expect("busy timeout");
        db
    }
}

fn jsonl(lines: &[Value]) -> String {
    lines
        .iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn claude_session(uuid: &str, question: &str, answer: &str) -> Vec<Value> {
    vec![
        serde_json::json!({
            "parentUuid": null,
            "cwd": "/synthetic/project",
            "sessionId": uuid,
            "version": "2.0.37",
            "type": "user",
            "message": {"role": "user", "content": question},
            "uuid": format!("{uuid}-user"),
            "timestamp": "2026-01-01T00:00:00.000Z"
        }),
        serde_json::json!({
            "parentUuid": format!("{uuid}-user"),
            "cwd": "/synthetic/project",
            "sessionId": uuid,
            "version": "2.0.37",
            "type": "assistant",
            "message": {
                "model": "claude-opus-4",
                "role": "assistant",
                "content": [{"type": "text", "text": answer}]
            },
            "uuid": format!("{uuid}-assistant"),
            "timestamp": "2026-01-01T00:00:01.000Z"
        }),
    ]
}

fn codex_session(id: &str, question: &str, answer: &str) -> Vec<Value> {
    vec![
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:00.000Z",
            "type": "session_meta",
            "payload": {"id": id, "cwd": "/synthetic/project", "cli_version": "0.42.0"}
        }),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:01.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": format!("{id}-msg-1"),
                "role": "user",
                "content": [{"type": "input_text", "text": question}]
            }
        }),
        serde_json::json!({
            "timestamp": "2026-01-01T00:00:02.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": format!("{id}-msg-2"),
                "role": "assistant",
                "content": [{"type": "output_text", "text": answer}]
            }
        }),
    ]
}

// ---------------------------------------------------------------------------
// Database readers
// ---------------------------------------------------------------------------

fn count(db: &rusqlite::Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("{sql}: {error}"))
}

fn count_like(db: &rusqlite::Connection, needle: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM messages WHERE content LIKE '%' || ?1 || '%'",
        [needle],
        |row| row.get(0),
    )
    .expect("count messages carrying the phrase")
}

fn complete_inputs(db: &rusqlite::Connection) -> i64 {
    count(db, "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'")
}

fn inputs_with_committed_receipt(db: &rusqlite::Connection) -> i64 {
    count(
        db,
        "SELECT COUNT(*) FROM source_inputs si
         JOIN operation_commit_receipt r ON r.idempotency_key = si.receipt_key
         WHERE si.state = 'complete'
           AND r.operation = 'source_input_activation_v1'
           AND r.state = 'committed'",
    )
}

fn complete_locators(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT relative_locator_bin FROM source_inputs
             WHERE state = 'complete' ORDER BY relative_locator_bin",
        )
        .expect("prepare locator query");
    stmt.query_map([], |row| {
        let bytes: Vec<u8> = row.get(0)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    })
    .expect("query locators")
    .collect::<Result<Vec<_>, _>>()
    .expect("collect locators")
}

fn complete_rows_for(db: &rusqlite::Connection, locator: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM source_inputs
         WHERE relative_locator_bin = ?1 AND state = 'complete'",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("counting complete inputs for {locator}: {error}"))
}

fn receipt_keys(db: &rusqlite::Connection) -> String {
    db.query_row(
        "SELECT COALESCE(group_concat(idempotency_key, '|'), '') FROM operation_commit_receipt",
        [],
        |row| row.get(0),
    )
    .expect("read the receipt keys")
}

fn source_facts_revision(db: &rusqlite::Connection) -> String {
    db.query_row(
        "SELECT value FROM meta WHERE key = 'source_facts_revision'",
        [],
        |row| row.get(0),
    )
    .optional()
    .expect("read the source facts revision")
    .unwrap_or_else(|| "<absent>".to_string())
}

fn watermark_rows(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT root_id || '|' || connector || '|' || last_scan_ts
             FROM scan_watermarks ORDER BY root_id, connector",
        )
        .expect("prepare watermark rows");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query watermark rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect watermark rows")
}

fn file_progress_rows(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT root_id || '|' || connector || '|' || relative_path || '|' || size || '|' || mtime
             FROM scan_file_state ORDER BY root_id, connector, relative_path",
        )
        .expect("prepare file progress rows");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query file progress rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect file progress rows")
}

fn manifest_safety(db: &rusqlite::Connection) -> Vec<(String, String)> {
    let mut stmt = db
        .prepare("SELECT expected_manifest_bin FROM source_inputs ORDER BY id")
        .expect("prepare manifest query");
    let rows: Vec<Vec<u8>> = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query manifests")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect manifests");
    rows.into_iter()
        .map(|bytes| {
            let (_manifest, safety) =
                decode_expected_manifest_header(&bytes).expect("decode manifest header");
            (
                safety.config_source_identity().to_string(),
                safety.fixed_config_sha256().hex(),
            )
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn doctor_payload(output: &Output, label: &str) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{label}: doctor stdout must be one JSON object: {error}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn check<'a>(payload: &'a Value, name: &str) -> &'a Value {
    payload["checks"]
        .as_array()
        .unwrap_or_else(|| panic!("doctor payload has no checks array: {payload:#}"))
        .iter()
        .find(|check| check["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("doctor payload has no {name} check: {payload:#}"))
}

fn assert_check(payload: &Value, name: &str, status: &str, fix_applied: Option<bool>) -> String {
    let item = check(payload, name);
    assert_eq!(
        item["status"].as_str(),
        Some(status),
        "{name} check status: {payload:#}"
    );
    if let Some(expected) = fix_applied {
        assert_eq!(
            item["fix_applied"].as_bool(),
            Some(expected),
            "{name} fix_applied: {payload:#}"
        );
    }
    item["message"].as_str().unwrap_or_default().to_string()
}

fn action_present(payload: &Value, needle: &str) -> bool {
    payload["auto_fix_actions"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|action| action.as_str().unwrap_or_default().contains(needle))
}

/// A file bundle snapshot: the DB and its sidecars, by existence and bytes.
fn bundle_snapshot(db: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    ["", "-wal", "-shm"]
        .into_iter()
        .map(|suffix| {
            let path = PathBuf::from(format!("{}{suffix}", db.display()));
            (format!("db{suffix}"), fs::read(&path).ok())
        })
        .collect()
}

/// A compact one-line description of a bundle snapshot for diagnostics:
/// existence, length and SHA-256 only, never the bytes themselves.
fn bundle_diag(snapshot: &[(String, Option<Vec<u8>>)]) -> String {
    snapshot
        .iter()
        .map(|(name, bytes)| match bytes {
            None => format!("{name}=absent"),
            Some(bytes) => format!(
                "{name}=len:{} sha256:{}",
                bytes.len(),
                sha256_hex(bytes)
            ),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Compare two bundle snapshots and report every component that moved.
fn assert_bundle_preserved(label: &str, before: &[(String, Option<Vec<u8>>)], after: &[(String, Option<Vec<u8>>)]) {
    let mut diffs: Vec<String> = Vec::new();
    for ((name, expected), (other_name, actual)) in before.iter().zip(after) {
        if name != other_name {
            diffs.push(format!("component order changed: {name} vs {other_name}"));
            continue;
        }
        match (expected, actual) {
            (None, None) => {}
            (Some(expected), Some(actual)) if expected == actual => {}
            (Some(expected), Some(actual)) => {
                let first_diff = expected
                    .iter()
                    .zip(actual)
                    .position(|(left, right)| left != right)
                    .unwrap_or_else(|| expected.len().min(actual.len()));
                diffs.push(format!(
                    "{name}: len {} -> {}, first differing byte {first_diff}, before_sha256={}, after_sha256={}",
                    expected.len(),
                    actual.len(),
                    sha256_hex(expected),
                    sha256_hex(actual),
                ));
            }
            _ => diffs.push(format!(
                "{name}: existence changed (before={}, after={})",
                expected.as_ref().map_or_else(
                    || "absent".to_string(),
                    |bytes| format!("len:{} sha256:{}", bytes.len(), sha256_hex(bytes))
                ),
                actual.as_ref().map_or_else(
                    || "absent".to_string(),
                    |bytes| format!("len:{} sha256:{}", bytes.len(), sha256_hex(bytes))
                )
            )),
        }
    }
    assert!(diffs.is_empty(), "{label}: bundle changed after doctor: {diffs:#?}");
}

/// Every raw-mirror blob as `relative-path|sha256`, sorted.
fn mirror_blob_fingerprints(data_dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, base, out);
            } else if let Ok(bytes) = fs::read(&path) {
                let relative = path
                    .strip_prefix(base)
                    .map(|value| value.display().to_string())
                    .unwrap_or_else(|_| path.display().to_string());
                out.push(format!("{relative}|{}", sha256_hex(&bytes)));
            }
        }
    }
    let root = data_dir.join("raw-mirror").join("v1").join("blobs");
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out.sort();
    out
}

fn scenario(test: &str, case: &str) {
    println!("TASK26_SCENARIO test={test} case={case} result=pass");
}

/// Build the contract's empty legal database through an explicit fixed safety
/// copy. This deliberately avoids the automatic copy a default index prepares.
fn init_explicit_empty(fx: &Fixture) {
    let copy = fx.fixed_copy();
    let copy_text = copy.to_str().expect("utf-8 fixed copy");
    let output = fx.index(&["--source-safety-config", copy_text]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "explicit fixed-config initialization must succeed: {}",
        combined(&output)
    );
    let db = fx.open_db();
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM messages"),
        0,
        "explicit initialization starts with no messages"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM source_inputs"),
        0,
        "explicit initialization starts with no source inputs"
    );
    assert!(
        fx.auto_config_files().is_empty(),
        "explicit initialization must not publish an automatic copy: {:?}",
        fx.auto_config_files()
    );
}

// ---------------------------------------------------------------------------
// A2 fixture: the full secondary-index corruption copied from
// tests/cli_doctor.rs::corrupt_unused_secondary_index_entry (base a9c9d1b),
// kept private to this target so the historical helper and its assertions are
// untouched.
// ---------------------------------------------------------------------------

macro_rules! fparams {
    () => {
        &[] as &[ParamValue]
    };
    ($($val:expr),+ $(,)?) => {
        &[$(coding_agent_search::storage::api::IntoValue::into_value($val)),+] as &[ParamValue]
    };
}

fn open_raw(path: &Path) -> FrankenConnection {
    FrankenStorage::open(path)
        .expect("open cass db")
        .into_raw()
}

fn corrupt_unused_secondary_index_entry(db_path: &Path) {
    let conn = open_raw(db_path);
    conn.execute(
        "CREATE TABLE doctor_integrity_probe(id INTEGER PRIMARY KEY, payload TEXT)",
        fparams![],
    )
    .expect("create integrity probe table");
    conn.execute(
        "CREATE INDEX idx_doctor_integrity_probe_payload ON doctor_integrity_probe(payload)",
        fparams![],
    )
    .expect("create integrity probe index");
    for id in 1_i64..=16 {
        let payload = format!("integrity probe payload {id:02}");
        conn.execute(
            "INSERT INTO doctor_integrity_probe(id, payload) VALUES (?1, ?2)",
            fparams![id, payload.as_str()],
        )
        .expect("insert integrity probe row");
    }
    let quick_before: String = conn
        .query_row_map("PRAGMA quick_check(1);", &[], |row| {
            row.get_typed(0)
        })
        .expect("quick_check before corruption");
    assert_eq!(quick_before, "ok");
    let index_root_page: i64 = conn
        .query_row_map(
            "SELECT rootpage FROM sqlite_master WHERE type = 'index' AND name = 'idx_doctor_integrity_probe_payload'",
            &[],
            |row| row.get_typed(0),
        )
        .expect("integrity probe index root page");
    let page_size: i64 = conn
        .query_row_map("PRAGMA page_size;", &[], |row| row.get_typed(0))
        .unwrap_or(4096);
    conn.query_all_map("PRAGMA wal_checkpoint(TRUNCATE);", &[], |row| row.get_value(0))
        .expect("checkpoint fixture db before raw page mutation");
    drop(conn);

    assert!(
        index_root_page > 1,
        "test fixture must corrupt a non-schema index page, got root_page={index_root_page}"
    );
    let offset = ((index_root_page as u64) - 1) * (page_size as u64);
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(db_path)
        .expect("open db file for index corruption");
    file.seek(SeekFrom::Start(offset))
        .expect("seek to probe index root page");
    let mut page = vec![0_u8; page_size as usize];
    file.read_exact(&mut page)
        .expect("read probe index root page");
    let needle = b"integrity probe payload 08";
    let needle_pos = page
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("probe index page should contain payload 08");
    let digit_offset = offset + (needle_pos + needle.len() - 1) as u64;
    file.seek(SeekFrom::Start(digit_offset))
        .expect("seek to probe index payload byte");
    file.write_all(b"9")
        .expect("mutate index payload without touching table row");
    file.flush().expect("flush corrupt index fixture");
    drop(file);

    let verify_conn = open_raw(db_path);
    let quick_after: String = verify_conn
        .query_row_map("PRAGMA quick_check(1);", &[], |row| {
            row.get_typed(0)
        })
        .expect("quick_check after index corruption");
    assert_eq!(
        quick_after, "ok",
        "fixture must model corruption that quick_check misses"
    );
    let integrity_after: String = verify_conn
        .query_row_map("PRAGMA integrity_check;", &[], |row| row.get_typed(0))
        .expect("integrity_check after index corruption");
    assert_ne!(
        integrity_after, "ok",
        "fixture must model corruption that full integrity_check catches"
    );
}

// ---------------------------------------------------------------------------
// A1: a legal empty archive rebuilt from source sessions.
// ---------------------------------------------------------------------------

#[test]
fn doctor_empty_archive_source_rebuild() {
    let fixture = Fixture::new();
    fixture.create_home_roots();
    init_explicit_empty(&fixture);

    fixture.write_claude(
        "p/session.jsonl",
        &claude_session(
            "sess-doctor-source",
            "the doctor source claude question",
            "the doctor source claude answer",
        ),
    );
    fixture.write_codex(
        "2026/01/rollout-fixture.jsonl",
        &codex_session(
            "sess-doctor-source-codex",
            "the doctor source codex question",
            "the doctor source codex answer",
        ),
    );

    let output = fixture.doctor(&["--fix", "--force-rebuild"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "doctor source rebuild must succeed: {}",
        combined(&output)
    );
    let payload = doctor_payload(&output, "source_rebuild");

    let database_message = assert_check(&payload, "database", "pass", None);
    assert!(
        database_message.contains("0 conversations, 0 messages"),
        "the database check must record the pre-rebuild 0/0 state: {database_message}"
    );
    assert_check(&payload, "rebuild", "pass", Some(true));
    assert!(
        action_present(&payload, "Rebuilt index from source sessions"),
        "the source-session action must be reported, not the derived path: {payload:#}"
    );

    // Reopen the closed database: per-locator completion, each input's own
    // committed activation receipt, both bodies, and canonical links.
    let db = fixture.open_db();
    assert_eq!(complete_inputs(&db), 2, "both inputs complete");
    assert_eq!(
        inputs_with_committed_receipt(&db),
        2,
        "each complete input carries its own committed activation receipt"
    );
    assert_eq!(
        complete_locators(&db),
        vec![
            "2026/01/rollout-fixture.jsonl".to_string(),
            "p/session.jsonl".to_string()
        ],
        "the two expected locators are complete"
    );
    assert_eq!(complete_rows_for(&db, "p/session.jsonl"), 1);
    assert_eq!(complete_rows_for(&db, "2026/01/rollout-fixture.jsonl"), 1);
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM messages"),
        4,
        "two sessions produce four canonical messages"
    );
    assert!(count_like(&db, "the doctor source claude answer") > 0);
    assert!(count_like(&db, "the doctor source codex answer") > 0);
    assert!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_message_links WHERE authority = 'canonical'"
        ) > 0,
        "the inputs link to canonical messages"
    );

    // The manifest identity and the actually published automatic copy agree.
    let files = fixture.auto_config_files();
    assert_eq!(
        files.len(),
        1,
        "the source rebuild prepares exactly one automatic copy: {files:?}"
    );
    let copy_bytes = fs::read(&files[0]).expect("read automatic copy");
    let digest = sha256_hex(&copy_bytes);
    let stem = files[0]
        .file_stem()
        .and_then(|value| value.to_str())
        .expect("automatic copy has a UTF-8 stem");
    assert_eq!(stem, digest, "the automatic copy is named after its bytes");
    let identities = manifest_safety(&db);
    assert_eq!(identities.len(), 2, "both input manifests are present");
    let expected_identity = format!("{AUTO_IDENTITY_PREFIX}{digest}");
    for (identity, fixed_sha) in &identities {
        assert_eq!(
            identity, &expected_identity,
            "the manifest records the automatic content address"
        );
        assert_eq!(
            fixed_sha, &digest,
            "the manifest records the actual copy's SHA-256"
        );
    }

    scenario("doctor_empty_archive_source_rebuild", "source_rebuild");
}

// ---------------------------------------------------------------------------
// A2: a damaged or missing archive stays refused without a fingerprint.
// ---------------------------------------------------------------------------

#[test]
fn doctor_corrupt_archive_stays_refused() {
    // corrupt
    {
        let fixture = Fixture::new();
        fixture.create_home_roots();
        init_explicit_empty(&fixture);
        corrupt_unused_secondary_index_entry(&fixture.db());
        // Fixture preparation, per the control-plane FullIC probe: a normal
        // native SQLite read-only verification establishes the real pre-state
        // of all three bundle files (the first native read creates the empty
        // WAL and the 32 KiB shared-memory file). Doctor's own native reader
        // then sees these files already present. This is fixture setup, not an
        // archive rewrite, and nothing is deleted afterwards.
        {
            let db = fixture.open_db();
            let quick: String = db
                .query_row("PRAGMA quick_check(1);", [], |row| row.get(0))
                .expect("native quick_check on the corrupt fixture");
            assert_eq!(quick, "ok", "quick_check must still pass");
            let full_ok = db
                .query_row("PRAGMA integrity_check;", [], |row| row.get::<_, String>(0))
                .map(|value| value == "ok")
                .unwrap_or(false);
            assert!(
                !full_ok,
                "the native full integrity_check must find the corrupt secondary index"
            );
        }
        let before = bundle_snapshot(&fixture.db());
        println!("TASK26_DIAG corrupt before {}", bundle_diag(&before));

        fixture.write_claude(
            "p/after-corruption.jsonl",
            &claude_session(
                "sess-doctor-corrupt",
                "the corrupt archive question",
                "the corrupt archive answer",
            ),
        );

        let output = fixture.doctor(&["--fix", "--force-rebuild"]);
        assert_eq!(
            output.status.code(),
            Some(5),
            "archive-risk rebuild without a fingerprint must exit 5: {}",
            combined(&output)
        );
        let payload = doctor_payload(&output, "corrupt");
        assert_check(&payload, "safe_auto_archive_rebuild", "fail", Some(false));
        assert!(
            !action_present(&payload, "Rebuilt index from source sessions"),
            "the refused archive must not report a source rebuild: {payload:#}"
        );

        let after = bundle_snapshot(&fixture.db());
        println!("TASK26_DIAG corrupt after {}", bundle_diag(&after));
        assert_bundle_preserved("corrupt", &before, &after);
        let moved: Vec<_> = fs::read_dir(fixture.data_dir())
            .expect("read data dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".corrupt."))
            .map(|entry| entry.path())
            .collect();
        assert!(
            moved.is_empty(),
            "the safe auto-run must not move the archive bundle: {moved:?}"
        );
        let db = fixture.open_db();
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM source_inputs"),
            0,
            "a refused rebuild ingests no source input"
        );
        assert!(
            fixture.auto_config_files().is_empty(),
            "a refused rebuild prepares no automatic copy"
        );

        scenario("doctor_corrupt_archive_stays_refused", "corrupt");
    }

    // missing
    {
        let fixture = Fixture::new();
        fixture.create_home_roots();
        assert!(!fixture.db().exists(), "the missing case starts with no DB");
        fixture.write_claude(
            "p/after-missing.jsonl",
            &claude_session(
                "sess-doctor-missing",
                "the missing archive question",
                "the missing archive answer",
            ),
        );

        let before = bundle_snapshot(&fixture.db());
        let output = fixture.doctor(&["--fix", "--force-rebuild"]);
        assert_eq!(
            output.status.code(),
            Some(5),
            "a missing archive must also exit 5: {}",
            combined(&output)
        );
        let payload = doctor_payload(&output, "missing");
        assert_check(&payload, "safe_auto_archive_rebuild", "fail", Some(false));
        assert_eq!(
            bundle_snapshot(&fixture.db()),
            before,
            "the missing case must not create a canonical DB or sidecars"
        );
        assert!(
            !fixture.db().exists(),
            "no canonical database may be created for the missing archive"
        );
        assert!(
            fixture.auto_config_files().is_empty(),
            "a refused missing-archive run prepares no automatic copy"
        );

        scenario("doctor_corrupt_archive_stays_refused", "missing");
    }
}

// ---------------------------------------------------------------------------
// A3: read-only surfaces write nothing; a populated archive rebuilds only the
// derived lexical domain with --force-rebuild.
// ---------------------------------------------------------------------------

#[test]
fn doctor_readonly_and_derived_no_source() {
    // check
    {
        let fixture = Fixture::new();
        fixture.create_home_roots();
        init_explicit_empty(&fixture);
        fixture.write_claude(
            "p/check-input.jsonl",
            &claude_session(
                "sess-doctor-check",
                "the check question",
                "the check answer",
            ),
        );
        fixture.corrupt_live_config();

        let before_watermarks = {
            let db = fixture.open_db();
            watermark_rows(&db)
        };
        let output = fixture.doctor(&["check"]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "doctor check must stay read-only with a corrupt live rule file: {}",
            combined(&output)
        );
        let payload = doctor_payload(&output, "check");
        assert_eq!(payload["doctor_command"]["read_only"].as_bool(), Some(true));
        assert_eq!(
            payload["doctor_command"]["mutation_allowed"].as_bool(),
            Some(false)
        );
        assert_eq!(payload["auto_fix_applied"].as_bool(), Some(false));

        let db = fixture.open_db();
        assert_eq!(count(&db, "SELECT COUNT(*) FROM messages"), 0);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM source_inputs"), 0);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM operation_commit_receipt"), 0);
        assert_eq!(
            watermark_rows(&db),
            before_watermarks,
            "read-only check moves no watermark"
        );
        assert!(
            !fixture.auto_config_dir().exists(),
            "read-only check prepares no automatic copy"
        );

        scenario("doctor_readonly_and_derived_no_source", "check");
    }

    // legacy
    {
        let fixture = Fixture::new();
        fixture.create_home_roots();
        init_explicit_empty(&fixture);
        fixture.write_claude(
            "p/legacy-input.jsonl",
            &claude_session(
                "sess-doctor-legacy",
                "the legacy question",
                "the legacy answer",
            ),
        );
        fixture.corrupt_live_config();

        let before_watermarks = {
            let db = fixture.open_db();
            watermark_rows(&db)
        };
        let output = fixture.doctor(&[]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "the legacy read-only doctor must stay read-only: {}",
            combined(&output)
        );
        let payload = doctor_payload(&output, "legacy");
        assert_eq!(payload["doctor_command"]["read_only"].as_bool(), Some(true));
        assert_eq!(
            payload["doctor_command"]["mutation_allowed"].as_bool(),
            Some(false)
        );

        let db = fixture.open_db();
        assert_eq!(count(&db, "SELECT COUNT(*) FROM messages"), 0);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM source_inputs"), 0);
        assert_eq!(
            watermark_rows(&db),
            before_watermarks,
            "legacy read-only doctor moves no watermark"
        );
        assert!(
            !fixture.auto_config_dir().exists(),
            "legacy read-only doctor prepares no automatic copy"
        );

        scenario("doctor_readonly_and_derived_no_source", "legacy");
    }

    // derived
    {
        let fixture = Fixture::new();
        fixture.create_home_roots();
        let projects = fixture.home().join(".claude/projects");
        let seed_relative = "legacy/proj/seed.jsonl";
        let seed_path = projects.join(seed_relative);
        fs::create_dir_all(seed_path.parent().expect("seed parent")).expect("mkdir seed dir");
        fs::write(
            &seed_path,
            b"{\"type\":\"message\",\"role\":\"user\",\"content\":\"ignored fixture line\"}\n",
        )
        .expect("write seed session file");
        let seed_bytes = fs::read(&seed_path).expect("read seed bytes");

        let root_id = scan_root_meta::home_root_id(
            "claude",
            &scan_root_meta::canonicalize_root_path(&projects),
        );
        source_legacy_seed::seed_legacy_source_fixture(
            &fixture.data_dir(),
            &[source_legacy_seed::LegacySeedFile {
                connector: "claude",
                source_id: "local",
                root_id: &root_id,
                root_path: &projects,
                source_path: &seed_path,
            }],
        )
        .expect("seed the legacy pre-state");

        let (before_messages, before_watermarks, before_files, before_revision, before_receipts) = {
            let db = fixture.open_db();
            assert_eq!(
                count(&db, "SELECT COUNT(*) FROM messages"),
                1,
                "the public seed writes one message"
            );
            assert_eq!(
                count(&db, "SELECT COUNT(*) FROM source_inputs"),
                0,
                "the public seed writes no source input"
            );
            assert_eq!(
                count(&db, "SELECT COUNT(*) FROM operation_commit_receipt"),
                0,
                "the public seed writes no activation receipt"
            );
            (
                count(&db, "SELECT COUNT(*) FROM messages"),
                watermark_rows(&db),
                file_progress_rows(&db),
                source_facts_revision(&db),
                receipt_keys(&db),
            )
        };
        assert!(!before_watermarks.is_empty(), "the seed writes a watermark");
        assert!(!before_files.is_empty(), "the seed writes file progress");
        let before_blobs = mirror_blob_fingerprints(&fixture.data_dir());
        assert!(!before_blobs.is_empty(), "the seed captures raw mirror bytes");

        // A new native input must not be ingested by a derived-only rebuild.
        fixture.write_claude(
            "newproj/p/new.jsonl",
            &claude_session(
                "sess-doctor-derived-new",
                "the un-ingested derived question",
                "the un-ingested derived answer",
            ),
        );
        // The live rule file is broken on purpose: the derived branch must not
        // read it.
        fixture.corrupt_live_config();

        let output = fixture.doctor(&["--fix", "--force-rebuild"]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "a populated archive must rebuild only the derived index: {}",
            combined(&output)
        );
        let payload = doctor_payload(&output, "derived");
        let rebuild_message = assert_check(&payload, "rebuild", "pass", Some(true));
        assert!(
            rebuild_message.contains("from database"),
            "the rebuild must report the database source: {rebuild_message}"
        );
        assert!(
            action_present(&payload, "Rebuilt search index from database"),
            "the derived action must be the database rebuild: {payload:#}"
        );

        let db = fixture.open_db();
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM messages"),
            before_messages,
            "a derived rebuild adds no message"
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM source_inputs"),
            0,
            "a derived rebuild writes no source input"
        );
        assert_eq!(
            receipt_keys(&db),
            before_receipts,
            "a derived rebuild writes no receipt"
        );
        assert_eq!(
            watermark_rows(&db),
            before_watermarks,
            "existing watermarks keep their exact values"
        );
        assert_eq!(
            file_progress_rows(&db),
            before_files,
            "existing file progress keeps its exact values"
        );
        assert_eq!(
            source_facts_revision(&db),
            before_revision,
            "the source facts revision is unchanged"
        );
        assert_eq!(
            count_like(&db, "the un-ingested derived answer"),
            0,
            "the new input is not ingested"
        );
        assert_eq!(
            mirror_blob_fingerprints(&fixture.data_dir()),
            before_blobs,
            "raw-mirror blobs keep their exact bytes"
        );
        assert_eq!(
            fs::read(&seed_path).expect("read seed bytes after"),
            seed_bytes,
            "the old session file keeps its exact bytes"
        );
        assert!(
            !fixture.auto_config_dir().exists(),
            "the derived branch prepares no automatic copy"
        );

        // The rebuilt lexical domain really answers the old body.
        let search = fixture.search("legacy seed body");
        assert_eq!(
            search.status.code(),
            Some(0),
            "lexical search must succeed after the derived rebuild: {}",
            combined(&search)
        );
        let search_payload: Value =
            serde_json::from_slice(&search.stdout).expect("search JSON");
        let hits = search_payload["hits"].as_array().cloned().unwrap_or_default();
        let expected_body = format!("legacy seed body for {seed_relative}");
        assert!(
            hits.iter().any(|hit| hit["content"]
                .as_str()
                .is_some_and(|content| content.contains(&expected_body))),
            "lexical search must return the seeded body {expected_body:?}: {search_payload:#}"
        );

        scenario("doctor_readonly_and_derived_no_source", "derived");
    }
}

// ---------------------------------------------------------------------------
// A4: source-preparation failures fail the rebuild without a false success.
// ---------------------------------------------------------------------------

#[test]
fn doctor_source_config_failure() {
    // bad_live: the live rule file is invalid TOML.
    {
        let fixture = Fixture::new();
        fixture.create_home_roots();
        init_explicit_empty(&fixture);
        let before_watermarks = {
            let db = fixture.open_db();
            watermark_rows(&db)
        };
        fixture.corrupt_live_config();
        fixture.write_claude(
            "p/bad-live.jsonl",
            &claude_session(
                "sess-doctor-bad-live",
                "the bad live question",
                "the bad live answer",
            ),
        );

        let output = fixture.doctor(&["--fix", "--force-rebuild"]);
        assert_eq!(
            output.status.code(),
            Some(5),
            "an invalid live rule file must fail the rebuild: {}",
            combined(&output)
        );
        let payload = doctor_payload(&output, "bad_live");
        let message = assert_check(&payload, "rebuild", "fail", Some(false));
        assert!(
            message.contains("source_config_load_failed"),
            "the rebuild failure must name the live-config load failure: {message}"
        );
        assert!(
            !action_present(&payload, "Rebuilt index from source sessions"),
            "a failed preparation must not report a source rebuild: {payload:#}"
        );

        let db = fixture.open_db();
        assert_eq!(count(&db, "SELECT COUNT(*) FROM messages"), 0);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM source_inputs"), 0);
        assert_eq!(receipt_keys(&db), "", "no activation receipt is written");
        assert_eq!(
            watermark_rows(&db),
            before_watermarks,
            "no watermark is advanced"
        );
        assert!(
            fixture.auto_config_files().is_empty(),
            "a failed live-config discovery publishes no automatic copy"
        );

        scenario("doctor_source_config_failure", "bad_live");
    }

    // bad_fixed: the automatic copy exists but its bytes are wrong.
    {
        let fixture = Fixture::new();
        fixture.create_home_roots();

        // Default initialization (no explicit copy) leaves one automatic copy.
        let init = fixture.index(&[]);
        assert_eq!(
            init.status.code(),
            Some(0),
            "default initialization must succeed: {}",
            combined(&init)
        );
        {
            let db = fixture.open_db();
            assert_eq!(count(&db, "SELECT COUNT(*) FROM messages"), 0);
            assert_eq!(count(&db, "SELECT COUNT(*) FROM source_inputs"), 0);
        }
        let files = fixture.auto_config_files();
        assert_eq!(
            files.len(),
            1,
            "default initialization publishes exactly one automatic copy: {files:?}"
        );
        let before_watermarks = {
            let db = fixture.open_db();
            watermark_rows(&db)
        };
        let before_files = {
            let db = fixture.open_db();
            file_progress_rows(&db)
        };
        let before_receipts = {
            let db = fixture.open_db();
            receipt_keys(&db)
        };

        // Keep the live rule file valid; only overwrite the published copy.
        fs::write(&files[0], BAD_TOML).expect("overwrite the automatic copy");
        fixture.write_claude(
            "p/bad-fixed.jsonl",
            &claude_session(
                "sess-doctor-bad-fixed",
                "the bad fixed question",
                "the bad fixed answer",
            ),
        );

        let output = fixture.doctor(&["--fix", "--force-rebuild"]);
        assert_eq!(
            output.status.code(),
            Some(5),
            "a tampered automatic copy must fail the rebuild: {}",
            combined(&output)
        );
        let payload = doctor_payload(&output, "bad_fixed");
        let message = assert_check(&payload, "rebuild", "fail", Some(false));
        assert!(
            message.contains("source_config_mismatch"),
            "the rebuild failure must name the copy mismatch: {message}"
        );
        assert!(
            !action_present(&payload, "Rebuilt index from source sessions"),
            "a mismatched copy must not report a source rebuild: {payload:#}"
        );

        assert_eq!(
            fs::read(&files[0]).expect("read the tampered copy after"),
            BAD_TOML,
            "the doctor must not repair the damaged copy"
        );
        assert_eq!(
            fixture.auto_config_files().len(),
            1,
            "the damaged copy is not replaced or duplicated"
        );
        let db = fixture.open_db();
        assert_eq!(count(&db, "SELECT COUNT(*) FROM messages"), 0);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM source_inputs"), 0);
        assert_eq!(receipt_keys(&db), before_receipts, "no receipt is written");
        assert_eq!(
            watermark_rows(&db),
            before_watermarks,
            "watermarks keep their exact values"
        );
        assert_eq!(
            file_progress_rows(&db),
            before_files,
            "file progress keeps its exact values"
        );

        scenario("doctor_source_config_failure", "bad_fixed");
    }
}
