//! Task22: `cass sources sync` / `cass sources reingest` fidelity and truthful
//! completion. One function per frozen contract group; every scenario prints
//! `TASK22_SCENARIO test=<fn> case=<id> result=pass` only after its assertions
//! finish. No fixture talks to a real host: the transfer is a private
//! stand-in `ssh`/`rsync` on the child's `PATH`.

#![cfg(unix)]

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use coding_agent_search::sources::config::SourceDefinition;
use coding_agent_search::sources::sync::{mirror_path_under, mirror_root_for};
use coding_agent_search::storage::source_facts::decode_expected_manifest_header;
use rusqlite::OptionalExtension as _;
use tempfile::TempDir;

const CLAUDE_PATH: &str = "~/.claude/projects";
const CODEX_PATH: &str = "~/.codex/sessions";
const REMOTE_HOME: &str = "/home/cass-fixture";
const AUTO_IDENTITY_PREFIX: &str = "cass.source-config/1:sha256:";
const CLAUDE_LOCATOR: &str = "projects/p/session.jsonl";
const CODEX_LOCATOR: &str = "sessions/2026/01/rollout-fixture.jsonl";

const DEFAULT_SOURCES: &str = r#"
[[sources]]
name = "fixture-claude"
origin_host = "fixture-claude"
type = "ssh"
host = "fixture-claude@fixture.invalid"
paths = ["~/.claude/projects"]

[[sources]]
name = "fixture-codex"
origin_host = "fixture-codex"
type = "ssh"
host = "fixture-codex@fixture.invalid"
paths = ["~/.codex/sessions"]
"#;

const FAKE_SSH: &str = r#"#!/bin/sh
last=""
for arg in "$@"; do last="$arg"; done
case "$last" in
  *CASS_HOME_MARKER*)
    if [ "${CASS_FIXTURE_MODE:-normal}" = "home_fail" ]; then
      printf 'fake ssh: fixture host unreachable\n' >&2
      exit 255
    fi
    printf 'CASS_HOME_MARKER:%s\n' "$CASS_FIXTURE_REMOTE_HOME"
    exit 0 ;;
  *"rsync --version"*)
    printf 'rsync  version 3.2.7  protocol 31\n'
    exit 0 ;;
  *)
    printf 'fake ssh: unsupported remote command: %s\n' "$last" >&2
    exit 1 ;;
esac
"#;

const FAKE_RSYNC: &str = r#"#!/bin/sh
case "$1" in
  --version) printf 'rsync  version 3.2.7  protocol 31\n'; exit 0 ;;
  --help)
    printf 'rsync  version 3.2.7  protocol 31\n'
    printf 'Usage: rsync [OPTION]... SRC [SRC]... DEST\n'
    exit 0 ;;
esac
previous=""
last=""
for arg in "$@"; do previous="$last"; last="$arg"; done
mode="${CASS_FIXTURE_MODE:-normal}"
printf 'transfer mode=%s remote=%s dest=%s\n' "$mode" "$previous" "$last" >> "${CASS_FIXTURE_LOG:-/dev/null}"
if [ "$mode" = "zero" ]; then
  printf 'Number of regular files transferred: 0\n'
  exit 0
fi
case "$previous" in
  *".codex/sessions"*)
    if [ "$mode" = "codex_fail" ]; then
      printf 'rsync: [sender] link_stat failed: No such file or directory (2)\n' >&2
      exit 23
    fi
    mkdir -p "$last/sessions/2026/01" || exit 1
    cp "$CASS_FIXTURE_CODEX_SESSION" "$last/sessions/2026/01/rollout-fixture.jsonl" || exit 1
    printf 'Number of regular files transferred: 1\n' ;;
  *)
    mkdir -p "$last/projects/p" || exit 1
    cp "$CASS_FIXTURE_CLAUDE_SESSION" "$last/projects/p/session.jsonl" || exit 1
    printf 'Number of regular files transferred: 1\n' ;;
esac
exit 0
"#;

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
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

struct Fixture {
    root: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            root: TempDir::new().expect("tempdir"),
        };
        for dir in [
            fixture.home(),
            fixture.config_home(),
            fixture.data_dir(),
            fixture.remote_dir(),
        ] {
            fs::create_dir_all(&dir).expect("create fixture dir");
        }
        fixture.install_fake_transport();
        fixture.write_claude_payload("fixture-claude question", "fixture-claude answer");
        fixture.write_codex_payload("fixture-codex question", "fixture-codex answer");
        fixture
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn home(&self) -> PathBuf {
        self.path().join("home")
    }

    fn config_home(&self) -> PathBuf {
        self.path().join("config")
    }

    fn data_dir(&self) -> PathBuf {
        self.path().join("data")
    }

    fn db(&self) -> PathBuf {
        self.data_dir().join("agent_search.db")
    }

    fn remote_dir(&self) -> PathBuf {
        self.path().join("remote")
    }

    fn fake_bin(&self) -> PathBuf {
        self.path().join("fake-bin")
    }

    fn transfer_log(&self) -> PathBuf {
        self.path().join("transfers.log")
    }

    fn claude_payload(&self) -> PathBuf {
        self.remote_dir().join("claude.jsonl")
    }

    fn codex_payload(&self) -> PathBuf {
        self.remote_dir().join("codex.jsonl")
    }

    fn write_claude_payload(&self, question: &str, answer: &str) {
        fs::write(
            self.claude_payload(),
            jsonl(&claude_session("fixture-claude-session", question, answer)),
        )
        .expect("write claude payload");
    }

    fn write_codex_payload(&self, question: &str, answer: &str) {
        fs::write(
            self.codex_payload(),
            jsonl(&codex_session("fixture-codex-session", question, answer)),
        )
        .expect("write codex payload");
    }

    fn install_fake_transport(&self) {
        let bin = self.fake_bin();
        fs::create_dir_all(&bin).expect("create fake bin");
        for (name, body) in [("ssh", FAKE_SSH), ("rsync", FAKE_RSYNC)] {
            let path = bin.join(name);
            fs::write(&path, body).expect("write fake transport");
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .expect("make fake transport executable");
        }
    }

    fn sources_config(&self) -> PathBuf {
        self.config_home().join("cass").join("sources.toml")
    }

    fn write_sources_config(&self, body: &str) {
        let path = self.sources_config();
        fs::create_dir_all(path.parent().expect("config parent")).expect("mkdir config");
        fs::write(&path, body).expect("write sources.toml");
    }

    fn live_config(&self) -> PathBuf {
        self.config_home()
            .join("cass")
            .join("excluded_context_paths.toml")
    }

    fn corrupt_live_config(&self) -> Vec<u8> {
        let path = self.live_config();
        fs::create_dir_all(path.parent().expect("config parent")).expect("mkdir config");
        let bytes = b"this is not toml [[[\n".to_vec();
        fs::write(&path, &bytes).expect("corrupt live config");
        bytes
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

    fn corrupt_auto_config(&self) -> (PathBuf, Vec<u8>) {
        let files = self.auto_config_files();
        assert_eq!(
            files.len(),
            1,
            "exactly one automatic copy must exist before it can be corrupted: {files:?}"
        );
        let bytes = b"not the published fixed configuration\n".to_vec();
        fs::write(&files[0], &bytes).expect("corrupt automatic copy");
        (files[0].clone(), bytes)
    }

    fn source_def(&self, name: &str, paths: &[&str]) -> SourceDefinition {
        let mut source = SourceDefinition::ssh(name, format!("{name}@fixture.invalid"));
        source.origin_host = name.to_string();
        source.paths = paths.iter().map(|path| path.to_string()).collect();
        source
    }

    fn mirror_path(&self, name: &str, raw_path: &str) -> PathBuf {
        let source = self.source_def(name, &[]);
        mirror_path_under(&mirror_root_for(&source, &self.data_dir()), raw_path)
    }

    fn write_mirror_file(&self, name: &str, raw_path: &str, relative: &str, body: &str) -> PathBuf {
        let path = self.mirror_path(name, raw_path).join(relative);
        fs::create_dir_all(path.parent().expect("mirror file parent")).expect("mkdir mirror dir");
        fs::write(&path, body).expect("write mirror file");
        path
    }

    fn isolate(&self, cmd: &mut Command) {
        let existing = std::env::var_os("PATH").unwrap_or_default();
        let mut path = std::ffi::OsString::from(self.fake_bin());
        path.push(":");
        path.push(existing);
        cmd.env("PATH", path)
            .env("HOME", self.home())
            .env("XDG_DATA_HOME", self.home().join(".local/share"))
            .env("XDG_CONFIG_HOME", self.config_home())
            .env("CODEX_HOME", self.home().join(".codex"))
            .env("CASS_AIDER_DATA_ROOT", self.home().join(".aider"))
            .env("PI_SESSIONS_DIR", self.home().join(".pi"))
            .env("PI_CODING_AGENT_DIR", self.home().join(".pi"))
            .env("GOOSE_PATH_ROOT", self.home().join(".goose"))
            .env("HERMES_HOME", self.home().join(".hermes"))
            .env("CASS_DATA_DIR", self.data_dir())
            .env("CASS_FIXTURE_CLAUDE_SESSION", self.claude_payload())
            .env("CASS_FIXTURE_CODEX_SESSION", self.codex_payload())
            .env("CASS_FIXTURE_REMOTE_HOME", REMOTE_HOME)
            .env("CASS_FIXTURE_LOG", self.transfer_log())
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("CASS_RESPONSIVENESS_DISABLE", "1")
            .env("CASS_TANTIVY_REBUILD_WORKERS", "1")
            .env("NO_COLOR", "1")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("CASS_OUTPUT_FORMAT")
            .env_remove("TOON_DEFAULT_FORMAT")
            .env_remove("RUST_LOG")
            .env_remove("CASS_EXCLUDE_PATHS");
    }

    fn run(&self, args: &[&str], mode: &str) -> Output {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.env("CASS_FIXTURE_MODE", mode);
        cmd.args(args);
        cmd.output().expect("spawn cass")
    }

    fn sync_json(&self, extra: &[&str], mode: &str) -> Output {
        let mut args = vec!["sources", "sync", "--json"];
        args.extend_from_slice(extra);
        self.run(&args, mode)
    }

    fn reingest_json(&self, extra: &[&str]) -> Output {
        let mut args = vec!["sources", "reingest", "--json", "--from-mirror"];
        args.extend_from_slice(extra);
        self.run(&args, "normal")
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

    fn transfer_lines(&self) -> Vec<String> {
        fs::read_to_string(self.transfer_log())
            .unwrap_or_default()
            .lines()
            .map(|line| line.to_string())
            .collect()
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn json_stream(bytes: &[u8]) -> Vec<Value> {
    let mut values = Vec::new();
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
    for value in &mut stream {
        values.push(value.expect("stdout must be a JSON value stream with no trailing non-JSON"));
    }
    values
}

fn index_success(value: &Value) -> bool {
    value.get("success") == Some(&Value::Bool(true))
        && value.get("data_dir").is_some()
        && value.get("db_path").is_some()
}

fn index_error(value: &Value) -> bool {
    value.get("success") == Some(&Value::Bool(false))
        && value.get("code").and_then(Value::as_i64) == Some(9)
        && value.get("kind").and_then(Value::as_str) == Some("index")
}

fn sync_summary(value: &Value) -> bool {
    value.get("sources").is_some()
        && value.get("total_files").is_some()
        && value.get("will_reindex").is_some()
}

fn reingest_summary(value: &Value) -> bool {
    value.get("kind").and_then(Value::as_str) == Some("sources_reingest")
}

fn expect_rc(output: &Output, expected: i32, label: &str) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{label}: expected rc {expected}, stdout={} stderr={}",
        stdout_of(output),
        stderr_of(output)
    );
}

fn expect_no_complete_summary(values: &[Value], label: &str) {
    for value in values {
        if sync_summary(value) {
            assert_ne!(
                value.get("status").and_then(Value::as_str),
                Some("complete"),
                "{label}: a failed round must not publish a complete summary: {value}"
            );
        }
        if reingest_summary(value) {
            panic!("{label}: reingest must not publish its complete summary on failure: {value}");
        }
    }
}

fn expect_summary_status(values: &[Value], status: &str, label: &str) -> Value {
    let summary = values
        .iter()
        .find(|value| sync_summary(value))
        .unwrap_or_else(|| panic!("{label}: no sync summary in {values:?}"))
        .clone();
    assert_eq!(
        summary.get("status").and_then(Value::as_str),
        Some(status),
        "{label}: summary status"
    );
    summary
}

fn scenario(test: &str, case: &str) {
    println!("TASK22_SCENARIO test={test} case={case} result=pass");
}

// ---------------------------------------------------------------------------
// Database readers (read-only, after the CLI process exits)
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

fn complete_rows_for(db: &rusqlite::Connection, locator: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM source_inputs
         WHERE relative_locator_bin = ?1 AND state = 'complete'",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("counting complete inputs for {locator}: {error}"))
}

fn committed_receipts_for(db: &rusqlite::Connection, locator: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM source_inputs si
         JOIN operation_commit_receipt r ON r.idempotency_key = si.receipt_key
         WHERE si.relative_locator_bin = ?1
           AND r.operation = 'source_input_activation_v1'
           AND r.state = 'committed'",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("counting activation receipts for {locator}: {error}"))
}

fn receipt_keys(db: &rusqlite::Connection) -> String {
    db.query_row(
        "SELECT COALESCE(group_concat(idempotency_key, '|'), '') FROM operation_commit_receipt",
        [],
        |row| row.get(0),
    )
    .expect("read the receipt keys")
}

fn watermark_rows(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT root_id || '|' || connector || '|' || last_scan_ts
             FROM scan_watermarks ORDER BY root_id, connector",
        )
        .expect("prepare the watermark rows");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query the watermark rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the watermark rows")
}

/// The `root_id|connector|last_scan_ts` rows for one root/connector pair.
/// Other healthy roots in the same run are allowed to advance.
fn watermarks_for(
    db: &rusqlite::Connection,
    root_prefix: &str,
    connector: &str,
) -> Vec<String> {
    watermark_rows(db)
        .into_iter()
        .filter(|row| {
            let mut parts = row.splitn(3, '|');
            let root = parts.next().unwrap_or_default();
            let conn = parts.next().unwrap_or_default();
            root.starts_with(root_prefix) && conn == connector
        })
        .collect()
}

fn file_progress_rows(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT root_id || '|' || connector || '|' || relative_path || '|' || size || '|' || mtime
             FROM scan_file_state ORDER BY root_id, connector, relative_path",
        )
        .expect("prepare the file progress rows");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query the file progress rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the file progress rows")
}

fn canonical_bodies(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare("SELECT id || '|' || COALESCE(content, '') FROM messages ORDER BY id")
        .expect("prepare the canonical bodies");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query the canonical bodies")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the canonical bodies")
}

fn input_keys(db: &rusqlite::Connection) -> Vec<Vec<u8>> {
    let mut stmt = db
        .prepare("SELECT input_key FROM source_inputs ORDER BY input_key")
        .expect("prepare the input keys");
    stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query the input keys")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the input keys")
}

/// Every recorded input as `state|connector|locator|root`, for diagnostics in
/// assertion messages and for proving which exact locator a fixture produced.
fn input_roster(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT state || '|' || connector || '|' || CAST(relative_locator_bin AS TEXT)
                    || '|' || CAST(root_id_bin AS TEXT)
             FROM source_inputs ORDER BY connector, relative_locator_bin",
        )
        .expect("prepare the input roster");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query the input roster")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the input roster")
}

/// One source input's own fact row, selected by its stable `input_key`.
/// `<absent>` means the key disappeared, which the caller treats as a change.
fn input_fact(db: &rusqlite::Connection, key: &[u8]) -> String {
    db.query_row(
        "SELECT hex(root_id_bin) || '|' || hex(relative_locator_bin) || '|' || hex(context_digest)
                || '|' || identity_namespace || '|' || COALESCE(CAST(origin_host AS TEXT), '')
                || '|' || connector || '|' || state || '|' || normalizer_id
                || '|' || safety_contract_id || '|' || hex(sealed_sha256)
         FROM source_inputs WHERE input_key = ?1",
        [key],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .expect("read one input's fact row")
    .unwrap_or_else(|| "<absent>".to_string())
}

/// The committed activation receipt(s) reached from one input's own
/// `receipt_key`, as `key|operation|state` lines. Empty when the input owns no
/// committed activation receipt.
fn input_receipts(db: &rusqlite::Connection, key: &[u8]) -> String {
    let mut stmt = db
        .prepare(
            "SELECT r.idempotency_key || '|' || r.operation || '|' || r.state
             FROM source_inputs si
             JOIN operation_commit_receipt r ON r.idempotency_key = si.receipt_key
             WHERE si.input_key = ?1
             ORDER BY r.idempotency_key",
        )
        .expect("prepare the per-input receipt query");
    let rows = stmt
        .query_map([key], |row| row.get::<_, String>(0))
        .expect("query the per-input receipts")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the per-input receipts");
    rows.join("\n")
}

/// The fact row and committed receipt lines for every input present at the
/// warmup. Only these keys are protected by the bad-input contract; new
/// diagnostic rows for the bad input and progress on other roots are allowed.
fn old_key_evidence(db: &rusqlite::Connection) -> Vec<(Vec<u8>, String, String)> {
    input_keys(db)
        .into_iter()
        .map(|key| {
            let fact = input_fact(db, &key);
            let receipt = input_receipts(db, &key);
            (key, fact, receipt)
        })
        .collect()
}

fn assert_old_key_evidence_unchanged(
    db: &rusqlite::Connection,
    before: &[(Vec<u8>, String, String)],
    label: &str,
) {
    for (key, fact, receipt) in before {
        assert_eq!(
            input_fact(db, key),
            *fact,
            "{label}: input key {} changed its own fact row",
            hex(key)
        );
        assert_eq!(
            input_receipts(db, key),
            *receipt,
            "{label}: input key {} changed its own committed receipt",
            hex(key)
        );
    }
}

fn manifest_safety(db: &rusqlite::Connection) -> Vec<(String, String)> {
    let mut stmt = db
        .prepare("SELECT expected_manifest_bin FROM source_inputs ORDER BY id")
        .expect("prepare the manifest query");
    let rows: Vec<Vec<u8>> = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query the manifests")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the manifests");
    rows.into_iter()
        .map(|bytes| {
            let (_manifest, safety) =
                decode_expected_manifest_header(&bytes).expect("decode the manifest header");
            (
                safety.config_source_identity().to_string(),
                safety.fixed_config_sha256().hex(),
            )
        })
        .collect()
}

fn facts_fingerprint(db: &rusqlite::Connection) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut stmt = db
        .prepare(
            "SELECT input_key, root_id_bin, relative_locator_bin, context_digest,
                    identity_namespace, origin_host, connector, state, normalizer_id,
                    safety_contract_id, sealed_sha256
             FROM source_inputs ORDER BY input_key",
        )
        .expect("prepare the input fingerprint");
    let rows = stmt
        .query_map([], |row| {
            let input_key: Vec<u8> = row.get(0)?;
            let root: Vec<u8> = row.get(1)?;
            let locator: Vec<u8> = row.get(2)?;
            let context_digest: Vec<u8> = row.get(3)?;
            let sealed: Vec<u8> = row.get(10)?;
            Ok(format!(
                "input key={} root={} locator={} context={} namespace={} origin_host={} \
                 connector={} state={} normalizer={} safety={} sealed={}",
                hex(&input_key),
                String::from_utf8_lossy(&root),
                String::from_utf8_lossy(&locator),
                hex(&context_digest),
                row.get::<_, String>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or_default(),
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                hex(&sealed),
            ))
        })
        .expect("query the input fingerprint")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the input fingerprint");
    lines.extend(rows);

    for (label, sql) in [
        ("source_records", "SELECT COUNT(*) FROM source_records"),
        (
            "source_message_links",
            "SELECT COUNT(*) FROM source_message_links",
        ),
        ("messages", "SELECT COUNT(*) FROM messages"),
        ("conversations", "SELECT COUNT(*) FROM conversations"),
    ] {
        lines.push(format!("{label}={}", count(db, sql)));
    }
    let revision: Option<String> = db
        .query_row(
            "SELECT value FROM meta WHERE key = 'source_facts_revision'",
            [],
            |row| row.get(0),
        )
        .optional()
        .expect("read the source facts revision");
    lines.push(format!(
        "source_facts_revision={}",
        revision.unwrap_or_else(|| "<absent>".to_string())
    ));
    lines.push(format!("receipts={}", receipt_keys(db)));
    lines
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn dir_fingerprint(root: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else if path.is_file() {
                let relative = path.strip_prefix(base).unwrap_or(&path);
                let bytes = fs::read(&path).unwrap_or_default();
                out.push(format!(
                    "{}|{}|{}",
                    relative.display(),
                    bytes.len(),
                    sha256_hex(&bytes)
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// A4a — failures never publish a final `complete`
// ---------------------------------------------------------------------------

#[test]
fn sources_failure_propagates() {
    // sync_bad_live — real business red on the unmodified CLI.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let first = fixture.sync_json(&[], "normal");
        expect_rc(&first, 0, "sync_bad_live healthy ingest");

        let db = fixture.open_db();
        let before_facts = facts_fingerprint(&db);
        let before_watermarks = watermark_rows(&db);
        let before_progress = file_progress_rows(&db);
        let before_bodies = canonical_bodies(&db);
        drop(db);

        fixture.write_mirror_file(
            "fixture-claude",
            CLAUDE_PATH,
            "projects/p/new-session.jsonl",
            &jsonl(&claude_session("new-session", "new question", "new answer")),
        );
        let bad_bytes = fixture.corrupt_live_config();

        let output = fixture.sync_json(&[], "normal");
        expect_rc(&output, 9, "sync_bad_live broken live rules");
        let values = json_stream(&output.stdout);
        assert!(
            values.iter().any(index_error),
            "sync_bad_live: the index error payload belongs on stdout: {values:?}"
        );
        expect_no_complete_summary(&values, "sync_bad_live");
        expect_summary_status(&values, "error", "sync_bad_live");

        let db = fixture.open_db();
        assert_eq!(
            facts_fingerprint(&db),
            before_facts,
            "sync_bad_live: old source facts must not change"
        );
        assert_eq!(
            watermark_rows(&db),
            before_watermarks,
            "sync_bad_live: watermarks must not advance on a failed index"
        );
        assert_eq!(
            file_progress_rows(&db),
            before_progress,
            "sync_bad_live: file progress must not advance on a failed index"
        );
        assert_eq!(
            canonical_bodies(&db),
            before_bodies,
            "sync_bad_live: canonical bodies must not change"
        );
        assert_eq!(
            complete_rows_for(&db, "projects/p/new-session.jsonl"),
            0,
            "sync_bad_live: the new input must not complete"
        );
        assert_eq!(
            fs::read(fixture.live_config()).expect("read the corrupted live config"),
            bad_bytes,
            "sync_bad_live: the broken live configuration is not repaired"
        );
    }
    scenario("sources_failure_propagates", "sync_bad_live");

    // sync_bad_fixed — the published copy's bytes are not the live rules any more.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let first = fixture.sync_json(&[], "normal");
        expect_rc(&first, 0, "sync_bad_fixed healthy ingest");

        let db = fixture.open_db();
        let before_facts = facts_fingerprint(&db);
        let before_watermarks = watermark_rows(&db);
        drop(db);

        fixture.write_mirror_file(
            "fixture-claude",
            CLAUDE_PATH,
            "projects/p/new-session.jsonl",
            &jsonl(&claude_session("new-session", "new question", "new answer")),
        );
        let (path, bad_bytes) = fixture.corrupt_auto_config();

        let output = fixture.sync_json(&[], "normal");
        expect_rc(&output, 9, "sync_bad_fixed");
        let values = json_stream(&output.stdout);
        assert!(
            values.iter().any(index_error),
            "sync_bad_fixed: index error payload on stdout: {values:?}"
        );
        expect_no_complete_summary(&values, "sync_bad_fixed");
        expect_summary_status(&values, "error", "sync_bad_fixed");

        let db = fixture.open_db();
        assert_eq!(
            facts_fingerprint(&db),
            before_facts,
            "sync_bad_fixed: old source facts must not change"
        );
        assert_eq!(
            watermark_rows(&db),
            before_watermarks,
            "sync_bad_fixed: watermarks must not advance"
        );
        assert_eq!(
            fs::read(&path).expect("read the corrupted fixed copy"),
            bad_bytes,
            "sync_bad_fixed: the broken fixed copy is not repaired"
        );
    }
    scenario("sources_failure_propagates", "sync_bad_fixed");

    // sync_bad_sources — the sources config itself will not load.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let first = fixture.sync_json(&[], "normal");
        expect_rc(&first, 0, "sync_bad_sources healthy ingest");
        let db = fixture.open_db();
        let before_facts = facts_fingerprint(&db);
        drop(db);

        fixture.write_sources_config("this is not toml [[[\n");
        let output = fixture.sync_json(&[], "normal");
        expect_rc(&output, 9, "sync_bad_sources");
        assert!(
            stdout_of(&output).trim().is_empty(),
            "sync_bad_sources: no summary may be published: {}",
            stdout_of(&output)
        );
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains("\"code\":9") && stderr.contains("\"kind\":\"config\""),
            "sync_bad_sources: the standard stderr envelope names the config failure: {stderr}"
        );

        let db = fixture.open_db();
        assert_eq!(
            facts_fingerprint(&db),
            before_facts,
            "sync_bad_sources: existing facts stay intact"
        );
    }
    scenario("sources_failure_propagates", "sync_bad_sources");

    // reingest_bad_live
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let mirror = fixture.sync_json(&["--no-index"], "normal");
        expect_rc(&mirror, 0, "reingest_bad_live mirror");
        let healthy = fixture.reingest_json(&[]);
        expect_rc(&healthy, 0, "reingest_bad_live healthy ingest");

        let db = fixture.open_db();
        let before_facts = facts_fingerprint(&db);
        let before_watermarks = watermark_rows(&db);
        drop(db);

        fixture.write_mirror_file(
            "fixture-claude",
            CLAUDE_PATH,
            "projects/p/new-session.jsonl",
            &jsonl(&claude_session("new-session", "new question", "new answer")),
        );
        let bad_bytes = fixture.corrupt_live_config();

        let output = fixture.reingest_json(&[]);
        expect_rc(&output, 9, "reingest_bad_live");
        let values = json_stream(&output.stdout);
        assert!(
            values.iter().any(index_error),
            "reingest_bad_live: index error payload on stdout: {values:?}"
        );
        expect_no_complete_summary(&values, "reingest_bad_live");

        let db = fixture.open_db();
        assert_eq!(
            facts_fingerprint(&db),
            before_facts,
            "reingest_bad_live: old facts stay intact"
        );
        assert_eq!(
            watermark_rows(&db),
            before_watermarks,
            "reingest_bad_live: watermarks stay put"
        );
        assert_eq!(
            fs::read(fixture.live_config()).expect("read the corrupted live config"),
            bad_bytes,
            "reingest_bad_live: the broken live configuration is not repaired"
        );
    }
    scenario("sources_failure_propagates", "reingest_bad_live");

    // reingest_bad_fixed
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let mirror = fixture.sync_json(&["--no-index"], "normal");
        expect_rc(&mirror, 0, "reingest_bad_fixed mirror");
        let healthy = fixture.reingest_json(&[]);
        expect_rc(&healthy, 0, "reingest_bad_fixed healthy ingest");

        let db = fixture.open_db();
        let before_facts = facts_fingerprint(&db);
        drop(db);

        fixture.write_mirror_file(
            "fixture-claude",
            CLAUDE_PATH,
            "projects/p/new-session.jsonl",
            &jsonl(&claude_session("new-session", "new question", "new answer")),
        );
        let (path, bad_bytes) = fixture.corrupt_auto_config();

        let output = fixture.reingest_json(&[]);
        expect_rc(&output, 9, "reingest_bad_fixed");
        let values = json_stream(&output.stdout);
        assert!(
            values.iter().any(index_error),
            "reingest_bad_fixed: index error payload on stdout: {values:?}"
        );
        expect_no_complete_summary(&values, "reingest_bad_fixed");

        let db = fixture.open_db();
        assert_eq!(
            facts_fingerprint(&db),
            before_facts,
            "reingest_bad_fixed: old facts stay intact"
        );
        assert_eq!(
            fs::read(&path).expect("read the corrupted fixed copy"),
            bad_bytes,
            "reingest_bad_fixed: the broken fixed copy is not repaired"
        );
    }
    scenario("sources_failure_propagates", "reingest_bad_fixed");

    // reingest_bad_sources
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let mirror = fixture.sync_json(&["--no-index"], "normal");
        expect_rc(&mirror, 0, "reingest_bad_sources mirror");
        let healthy = fixture.reingest_json(&[]);
        expect_rc(&healthy, 0, "reingest_bad_sources healthy ingest");
        let db = fixture.open_db();
        let before_facts = facts_fingerprint(&db);
        drop(db);

        fixture.write_sources_config("this is not toml [[[\n");
        let output = fixture.reingest_json(&[]);
        expect_rc(&output, 9, "reingest_bad_sources");
        assert!(
            stdout_of(&output).trim().is_empty(),
            "reingest_bad_sources: no summary may be published: {}",
            stdout_of(&output)
        );
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains("\"code\":9") && stderr.contains("\"kind\":\"config\""),
            "reingest_bad_sources: the standard stderr envelope names the config failure: {stderr}"
        );

        let db = fixture.open_db();
        assert_eq!(
            facts_fingerprint(&db),
            before_facts,
            "reingest_bad_sources: existing facts stay intact"
        );
    }
    scenario("sources_failure_propagates", "reingest_bad_sources");
}

// ---------------------------------------------------------------------------
// A1 — a real transfer lands both sources through the default entry
// ---------------------------------------------------------------------------

#[test]
fn sources_sync_lands_source() {
    let fixture = Fixture::new();
    fixture.write_sources_config(DEFAULT_SOURCES);

    let output = fixture.sync_json(&[], "normal");
    expect_rc(&output, 0, "sync_two_sources");
    let values = json_stream(&output.stdout);

    let index_positions: Vec<usize> = values
        .iter()
        .enumerate()
        .filter(|(_, value)| index_success(value))
        .map(|(index, _)| index)
        .collect();
    assert!(
        !index_positions.is_empty(),
        "sync_two_sources: the index success object is on stdout: {values:?}"
    );
    let summary_position = values
        .iter()
        .position(sync_summary)
        .unwrap_or_else(|| panic!("sync_two_sources: no final summary: {values:?}"));
    assert!(
        index_positions[0] < summary_position,
        "sync_two_sources: the index success object must precede the final complete summary"
    );
    let summary = expect_summary_status(&values, "complete", "sync_two_sources");
    assert_eq!(summary["will_reindex"], serde_json::json!(true));
    assert_eq!(summary["total_files"], serde_json::json!(2));

    let db = fixture.open_db();
    eprintln!("INPUT_ROSTER {:?}", input_roster(&db));
    for locator in [CLAUDE_LOCATOR, CODEX_LOCATOR] {
        assert_eq!(
            complete_rows_for(&db, locator),
            1,
            "{locator}: this exact input reached the complete state; roster={:?}",
            input_roster(&db)
        );
        assert_eq!(
            committed_receipts_for(&db, locator),
            1,
            "{locator}: this exact input owns a committed activation receipt"
        );
    }
    assert!(
        count_like(&db, "fixture-claude answer") > 0,
        "the Claude body is readable after reopening"
    );
    assert!(
        count_like(&db, "fixture-codex answer") > 0,
        "the Codex body is readable after reopening"
    );
    assert!(
        count(&db, "SELECT COUNT(*) FROM source_message_links") > 0,
        "inputs link to canonical messages"
    );
    let identities = manifest_safety(&db);
    drop(db);
    assert!(
        !identities.is_empty(),
        "the inputs carry expected-manifest headers"
    );

    let files = fixture.auto_config_files();
    assert_eq!(
        files.len(),
        1,
        "exactly one automatic fixed copy must exist: {files:?}"
    );
    let bytes = fs::read(&files[0]).expect("read the automatic copy");
    let digest = sha256_hex(&bytes);
    let name = files[0]
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("the automatic copy has a UTF-8 stem");
    assert_eq!(
        name, digest,
        "the automatic copy is named after its own digest"
    );
    let expected = format!("{AUTO_IDENTITY_PREFIX}{digest}");
    for (identity, fixed_sha) in identities {
        assert_eq!(
            identity, expected,
            "the input's safety identity is the automatic content address"
        );
        assert_eq!(
            fixed_sha, digest,
            "the manifest's fixed-copy digest is the published copy"
        );
    }

    let index = values
        .iter()
        .find(|value| index_success(value))
        .expect("index success object");
    let expected_db = fixture.db().display().to_string();
    assert_eq!(
        index["db_path"].as_str(),
        Some(expected_db.as_str()),
        "the index result names this fixture's database"
    );
    scenario("sources_sync_lands_source", "sync_two_sources");
}

// ---------------------------------------------------------------------------
// A2 — reingest default and full, both replayable without another transfer
// ---------------------------------------------------------------------------

fn reingest_case(full: bool) {
    let label = if full { "full" } else { "default" };
    let fixture = Fixture::new();
    fixture.write_sources_config(DEFAULT_SOURCES);

    let mirror = fixture.sync_json(&["--no-index"], "normal");
    expect_rc(&mirror, 0, &format!("reingest_{label} mirror"));
    assert!(
        !fixture.db().exists(),
        "reingest_{label}: the mirror-only sync creates no database"
    );
    assert!(
        fixture.auto_config_files().is_empty(),
        "reingest_{label}: the mirror-only sync prepares no automatic copy"
    );
    let transfers_after_mirror = fixture.transfer_lines().len();
    assert!(
        transfers_after_mirror > 0,
        "reingest_{label}: the fake transport really transferred"
    );

    let expected_roots: Vec<String> = ["fixture-claude", "fixture-codex"]
        .iter()
        .map(|name| {
            let raw = if *name == "fixture-claude" {
                CLAUDE_PATH
            } else {
                CODEX_PATH
            };
            let root = fixture.mirror_path(name, raw);
            fs::canonicalize(&root)
                .expect("canonical mirror root")
                .display()
                .to_string()
        })
        .collect();

    let extra: &[&str] = if full { &["--full"] } else { &[] };
    let output = fixture.reingest_json(extra);
    expect_rc(&output, 0, &format!("reingest_{label}"));
    let values = json_stream(&output.stdout);
    assert!(
        values.iter().any(index_success),
        "reingest_{label}: the index success object is on stdout: {values:?}"
    );
    let summary = values
        .iter()
        .find(|value| reingest_summary(value))
        .unwrap_or_else(|| panic!("reingest_{label}: no reingest summary: {values:?}"))
        .clone();
    assert_eq!(summary["status"], serde_json::json!("complete"));
    assert_eq!(summary["full"], serde_json::json!(full));
    assert_eq!(summary["missing_mirrors"], serde_json::json!([]));
    assert_eq!(
        summary["mirror_roots"],
        serde_json::json!(expected_roots),
        "reingest_{label}: the summary names the actual canonical mirror roots"
    );

    let db = fixture.open_db();
    eprintln!("REINGEST_ROSTER {label} {:?}", input_roster(&db));
    for locator in [CLAUDE_LOCATOR, CODEX_LOCATOR] {
        assert_eq!(
            complete_rows_for(&db, locator),
            1,
            "reingest_{label} {locator}: complete; roster={:?}",
            input_roster(&db)
        );
        assert_eq!(
            committed_receipts_for(&db, locator),
            1,
            "reingest_{label} {locator}: committed activation receipt"
        );
    }
    assert!(count_like(&db, "fixture-claude answer") > 0);
    assert!(count_like(&db, "fixture-codex answer") > 0);
    let before = (facts_fingerprint(&db), receipt_keys(&db));
    drop(db);

    let replay = fixture.reingest_json(extra);
    expect_rc(&replay, 0, &format!("reingest_{label} replay"));
    let db = fixture.open_db();
    assert_eq!(
        (facts_fingerprint(&db), receipt_keys(&db)),
        before,
        "reingest_{label}: a replay adds no input key and no receipt"
    );
    drop(db);
    assert_eq!(
        fixture.transfer_lines().len(),
        transfers_after_mirror,
        "reingest_{label}: reingest performs no transfer of its own"
    );
    scenario("sources_reingest_default_and_full", label);
}

#[test]
fn sources_reingest_default_and_full() {
    reingest_case(false);
    reingest_case(true);
}

// ---------------------------------------------------------------------------
// A3 — no-index, dry-run and zero transfer keep the original no-ingest rules
// ---------------------------------------------------------------------------

#[test]
fn sources_non_ingest_no_write() {
    // no_index: a real transfer is allowed to change the mirror; nothing else runs.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        fixture.corrupt_live_config();

        let output = fixture.sync_json(&["--no-index"], "normal");
        expect_rc(&output, 0, "no_index");
        let values = json_stream(&output.stdout);
        let summary = expect_summary_status(&values, "complete", "no_index");
        assert_eq!(summary["will_reindex"], serde_json::json!(false));
        assert!(
            !values.iter().any(index_success),
            "no_index: no index result may appear: {values:?}"
        );
        assert!(!fixture.db().exists(), "no_index: no database is created");
        assert!(
            fixture.auto_config_files().is_empty(),
            "no_index: no automatic copy is prepared"
        );
        let mirrored = fixture
            .mirror_path("fixture-claude", CLAUDE_PATH)
            .join(CLAUDE_LOCATOR);
        assert_eq!(
            fs::read(&mirrored).expect("the mirrored Claude file exists"),
            fs::read(fixture.claude_payload()).expect("read the payload"),
            "no_index: the transferred bytes are the fixture bytes"
        );
    }
    scenario("sources_non_ingest_no_write", "no_index");

    // dry_run: no transfer and no ingest.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        fixture.corrupt_live_config();

        let output = fixture.sync_json(&["--dry-run"], "normal");
        expect_rc(&output, 0, "dry_run");
        let values = json_stream(&output.stdout);
        let summary = expect_summary_status(&values, "complete", "dry_run");
        assert_eq!(summary["dry_run"], serde_json::json!(true));
        assert_eq!(summary["total_files"], serde_json::json!(0));
        assert!(!values.iter().any(index_success), "dry_run: no index result");
        assert!(!fixture.db().exists(), "dry_run: no database is created");
        assert!(
            fixture.auto_config_files().is_empty(),
            "dry_run: no automatic copy is prepared"
        );
        assert!(
            fixture.transfer_lines().is_empty(),
            "dry_run: no transfer command may run"
        );
    }
    scenario("sources_non_ingest_no_write", "dry_run");

    // zero_transfer: an existing mirror reads fine but is not indexed.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let mirror = fixture.sync_json(&["--no-index"], "normal");
        expect_rc(&mirror, 0, "zero_transfer mirror");
        let mirror_before = dir_fingerprint(&fixture.data_dir().join("remotes"));
        let transfers_before = fixture.transfer_lines().len();

        let output = fixture.sync_json(&[], "zero");
        expect_rc(&output, 0, "zero_transfer");
        let values = json_stream(&output.stdout);
        let summary = expect_summary_status(&values, "complete", "zero_transfer");
        assert_eq!(summary["total_files"], serde_json::json!(0));
        assert!(
            !values.iter().any(index_success),
            "zero_transfer: no index result may appear: {values:?}"
        );
        assert!(!fixture.db().exists(), "zero_transfer: no database is created");
        assert!(
            fixture.auto_config_files().is_empty(),
            "zero_transfer: no automatic copy is prepared"
        );
        let transfers = fixture.transfer_lines();
        assert_eq!(
            transfers.iter().filter(|line| line.contains("mode=zero")).count(),
            2,
            "zero_transfer: both selected sources ran the transport once: {transfers:?}"
        );
        assert_eq!(
            transfers.len(),
            transfers_before + 2,
            "zero_transfer: two transfer attempts were recorded"
        );
        assert_eq!(
            dir_fingerprint(&fixture.data_dir().join("remotes")),
            mirror_before,
            "zero_transfer: the existing mirror bytes are untouched"
        );
    }
    scenario("sources_non_ingest_no_write", "zero_transfer");
}

// ---------------------------------------------------------------------------
// A4a — a bad record fails the run without a complete summary
// ---------------------------------------------------------------------------

fn bad_session_body() -> String {
    let lines = claude_session("bad-session", "bad question", "bad answer");
    format!(
        "{}\n{{this line is not json}}\n{}\n",
        lines[0], lines[1]
    )
}

#[test]
fn sources_bad_input_failure_propagates() {
    // sync_bad_input
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let first = fixture.sync_json(&[], "normal");
        expect_rc(&first, 0, "sync_bad_input healthy ingest");
        let db = fixture.open_db();
        for locator in [CLAUDE_LOCATOR, CODEX_LOCATOR] {
            assert_eq!(
                complete_rows_for(&db, locator),
                1,
                "sync_bad_input warmup {locator}: complete"
            );
            assert_eq!(
                committed_receipts_for(&db, locator),
                1,
                "sync_bad_input warmup {locator}: committed activation receipt"
            );
        }
        let before_evidence = old_key_evidence(&db);
        let before_watermarks = watermarks_for(&db, "cfg:fixture-claude:", "claude");
        let before_bodies = canonical_bodies(&db);
        drop(db);

        fixture.write_mirror_file(
            "fixture-claude",
            CLAUDE_PATH,
            "projects/p/bad-session.jsonl",
            &bad_session_body(),
        );

        let output = fixture.sync_json(&[], "normal");
        expect_rc(&output, 9, "sync_bad_input");
        let values = json_stream(&output.stdout);
        assert!(
            values.iter().any(index_error),
            "sync_bad_input: index error payload on stdout: {values:?}"
        );
        expect_no_complete_summary(&values, "sync_bad_input");
        expect_summary_status(&values, "error", "sync_bad_input");

        let db = fixture.open_db();
        assert_eq!(
            complete_rows_for(&db, "projects/p/bad-session.jsonl"),
            0,
            "sync_bad_input: the bad input never completes"
        );
        assert_eq!(
            committed_receipts_for(&db, "projects/p/bad-session.jsonl"),
            0,
            "sync_bad_input: the bad input owns no activation receipt"
        );
        assert_old_key_evidence_unchanged(&db, &before_evidence, "sync_bad_input");
        for body in &before_bodies {
            assert!(
                canonical_bodies(&db).contains(body),
                "sync_bad_input: the old canonical body stays present"
            );
        }
        assert_eq!(
            watermarks_for(&db, "cfg:fixture-claude:", "claude"),
            before_watermarks,
            "sync_bad_input: the bad root's watermark must not advance"
        );
    }
    scenario("sources_bad_input_failure_propagates", "sync_bad_input");

    // reingest_bad_input
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let mirror = fixture.sync_json(&["--no-index"], "normal");
        expect_rc(&mirror, 0, "reingest_bad_input mirror");
        let healthy = fixture.reingest_json(&[]);
        expect_rc(&healthy, 0, "reingest_bad_input healthy ingest");
        let db = fixture.open_db();
        for locator in [CLAUDE_LOCATOR, CODEX_LOCATOR] {
            assert_eq!(
                complete_rows_for(&db, locator),
                1,
                "reingest_bad_input warmup {locator}: complete"
            );
            assert_eq!(
                committed_receipts_for(&db, locator),
                1,
                "reingest_bad_input warmup {locator}: committed activation receipt"
            );
        }
        let before_evidence = old_key_evidence(&db);
        let before_watermarks = watermarks_for(&db, "cfg:fixture-claude:", "claude");
        let before_bodies = canonical_bodies(&db);
        drop(db);

        fixture.write_mirror_file(
            "fixture-claude",
            CLAUDE_PATH,
            "projects/p/bad-session.jsonl",
            &bad_session_body(),
        );

        let output = fixture.reingest_json(&[]);
        expect_rc(&output, 9, "reingest_bad_input");
        let values = json_stream(&output.stdout);
        assert!(
            values.iter().any(index_error),
            "reingest_bad_input: index error payload on stdout: {values:?}"
        );
        expect_no_complete_summary(&values, "reingest_bad_input");

        let db = fixture.open_db();
        assert_eq!(
            complete_rows_for(&db, "projects/p/bad-session.jsonl"),
            0,
            "reingest_bad_input: the bad input never completes"
        );
        assert_eq!(
            committed_receipts_for(&db, "projects/p/bad-session.jsonl"),
            0,
            "reingest_bad_input: the bad input owns no activation receipt"
        );
        assert_old_key_evidence_unchanged(&db, &before_evidence, "reingest_bad_input");
        for body in &before_bodies {
            assert!(
                canonical_bodies(&db).contains(body),
                "reingest_bad_input: the old canonical body stays present"
            );
        }
        assert_eq!(
            watermarks_for(&db, "cfg:fixture-claude:", "claude"),
            before_watermarks,
            "reingest_bad_input: the bad root's watermark must not advance"
        );
    }
    scenario("sources_bad_input_failure_propagates", "reingest_bad_input");
}

// ---------------------------------------------------------------------------
// A4b — transfer failures are reported as source errors (9/source)
// ---------------------------------------------------------------------------

#[test]
fn sources_transfer_failure_reports_error() {
    // all_home_failed
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let output = fixture.sync_json(&[], "home_fail");
        expect_rc(&output, 9, "all_home_failed");
        let values = json_stream(&output.stdout);
        let summary = expect_summary_status(&values, "error", "all_home_failed");
        let sources = summary["sources"].as_array().expect("sources array");
        assert_eq!(sources.len(), 2);
        for source in sources {
            assert_ne!(
                source["status"],
                serde_json::json!("success"),
                "all_home_failed: every source reports its failure"
            );
        }
        assert!(!values.iter().any(index_success), "all_home_failed: no index");
        assert!(!fixture.db().exists(), "all_home_failed: no database");
        assert!(
            fixture.auto_config_files().is_empty(),
            "all_home_failed: no automatic copy"
        );
        assert!(
            fixture.transfer_lines().is_empty(),
            "all_home_failed: no transfer reached the fake rsync"
        );
    }
    scenario("sources_transfer_failure_reports_error", "all_home_failed");

    // partial_path_failed: one healthy path indexes, the failed path is counted.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(
            r#"
[[sources]]
name = "fixture-claude"
origin_host = "fixture-claude"
type = "ssh"
host = "fixture-claude@fixture.invalid"
paths = ["~/.claude/projects", "~/.codex/sessions"]
"#,
        );
        let output = fixture.sync_json(&[], "codex_fail");
        expect_rc(&output, 9, "partial_path_failed");
        let values = json_stream(&output.stdout);
        assert!(
            values.iter().any(index_success),
            "partial_path_failed: the healthy path still indexes: {values:?}"
        );
        let summary = expect_summary_status(&values, "error", "partial_path_failed");
        assert_eq!(
            summary["sources"][0]["status"],
            serde_json::json!("partial"),
            "partial_path_failed: the per-source report says partial"
        );
        let db = fixture.open_db();
        assert_eq!(
            complete_rows_for(&db, CLAUDE_LOCATOR),
            1,
            "partial_path_failed: the healthy Claude input completes"
        );
        assert_eq!(
            committed_receipts_for(&db, CLAUDE_LOCATOR),
            1,
            "partial_path_failed: the healthy Claude input owns a receipt"
        );
        assert!(
            count_like(&db, "fixture-claude answer") > 0,
            "partial_path_failed: the healthy body is indexed"
        );
        assert_eq!(
            complete_rows_for(&db, CODEX_LOCATOR),
            0,
            "partial_path_failed: the failed Codex path has no complete input"
        );
    }
    scenario("sources_transfer_failure_reports_error", "partial_path_failed");

    // invalid_dry_json: an invalid path entry is a source failure even in JSON.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(
            r#"
[[sources]]
name = "fixture-claude"
origin_host = "fixture-claude"
type = "ssh"
host = "fixture-claude@fixture.invalid"
paths = [""]
"#,
        );
        let output = fixture.sync_json(&["--dry-run"], "normal");
        expect_rc(&output, 9, "invalid_dry_json");
        let values = json_stream(&output.stdout);
        let summary = expect_summary_status(&values, "error", "invalid_dry_json");
        assert_eq!(
            summary["sources"][0]["status"],
            serde_json::json!("invalid_config"),
            "invalid_dry_json: the per-source report names invalid_config"
        );
        assert!(!values.iter().any(index_success));
        assert!(!fixture.db().exists(), "invalid_dry_json: no database");
        assert!(
            fixture.transfer_lines().is_empty(),
            "invalid_dry_json: no transfer"
        );
        let stderr = stderr_of(&output);
        assert!(
            stderr.contains("\"kind\":\"source\""),
            "invalid_dry_json: the standard stderr envelope names the source failure: {stderr}"
        );
    }
    scenario("sources_transfer_failure_reports_error", "invalid_dry_json");

    // invalid_dry_human: the same failure count, rendered for a person.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(
            r#"
[[sources]]
name = "fixture-claude"
origin_host = "fixture-claude"
type = "ssh"
host = "fixture-claude@fixture.invalid"
paths = [""]
"#,
        );
        let output = fixture.run(&["sources", "sync", "--dry-run"], "normal");
        expect_rc(&output, 9, "invalid_dry_human");
        assert!(
            !stdout_of(&output).trim_start().starts_with('{'),
            "invalid_dry_human: human output is not a JSON stream: {}",
            stdout_of(&output)
        );
        assert!(
            fixture.transfer_lines().is_empty(),
            "invalid_dry_human: no transfer"
        );
        assert!(!fixture.db().exists(), "invalid_dry_human: no database");
    }
    scenario("sources_transfer_failure_reports_error", "invalid_dry_human");
}

// ---------------------------------------------------------------------------
// A4c — a mixed native connector stays on its legacy projection
// ---------------------------------------------------------------------------

const GEMINI_FIXTURE: &[u8] = include_bytes!("fixtures/gemini/hash123/chats/session-test.json");

fn write_gemini(fixture: &Fixture) -> PathBuf {
    let path = fixture
        .home()
        .join(".gemini/tmp/hash123/chats/session-test.json");
    fs::create_dir_all(path.parent().expect("gemini parent")).expect("mkdir gemini dir");
    fs::write(&path, GEMINI_FIXTURE).expect("write gemini session");
    path
}

fn gemini_source_inputs(db: &rusqlite::Connection) -> i64 {
    count(
        db,
        "SELECT COUNT(*) FROM source_inputs WHERE connector LIKE '%gemini%'",
    )
}

#[test]
fn sources_mixed_legacy_connector_kept() {
    // sync_legacy
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        write_gemini(&fixture);

        let output = fixture.sync_json(&[], "normal");
        expect_rc(&output, 0, "sync_legacy");
        let values = json_stream(&output.stdout);
        expect_summary_status(&values, "complete", "sync_legacy");
        let db = fixture.open_db();
        eprintln!("LEGACY_ROSTER {:?}", input_roster(&db));
        for locator in [CLAUDE_LOCATOR, CODEX_LOCATOR] {
            assert_eq!(
                complete_rows_for(&db, locator),
                1,
                "sync_legacy {locator}; roster={:?}",
                input_roster(&db)
            );
            assert_eq!(
                committed_receipts_for(&db, locator),
                1,
                "sync_legacy {locator} receipt"
            );
        }
        assert!(
            count_like(&db, "Hello from Gemini!") > 0,
            "sync_legacy: the Gemini body lands on the legacy canonical path"
        );
        assert!(
            count_like(&db, "fixture-claude answer") > 0,
            "sync_legacy: the Claude body is present"
        );
        assert_eq!(
            gemini_source_inputs(&db),
            0,
            "sync_legacy: no Gemini source facts are fabricated"
        );
    }
    scenario("sources_mixed_legacy_connector_kept", "sync_legacy");

    // reingest_legacy: Gemini is ingested by this reingest, not by the mirror-only sync.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        write_gemini(&fixture);
        let mirror = fixture.sync_json(&["--no-index"], "normal");
        expect_rc(&mirror, 0, "reingest_legacy mirror");
        assert!(
            !fixture.db().exists(),
            "reingest_legacy: the mirror-only sync ingests nothing"
        );

        let output = fixture.reingest_json(&[]);
        expect_rc(&output, 0, "reingest_legacy");
        let values = json_stream(&output.stdout);
        let summary = values
            .iter()
            .find(|value| reingest_summary(value))
            .unwrap_or_else(|| panic!("reingest_legacy: no reingest summary: {values:?}"));
        assert_eq!(summary["status"], serde_json::json!("complete"));
        let db = fixture.open_db();
        for locator in [CLAUDE_LOCATOR, CODEX_LOCATOR] {
            assert_eq!(
                complete_rows_for(&db, locator),
                1,
                "reingest_legacy {locator}"
            );
            assert_eq!(
                committed_receipts_for(&db, locator),
                1,
                "reingest_legacy {locator} receipt"
            );
        }
        assert!(
            count_like(&db, "Hello from Gemini!") > 0,
            "reingest_legacy: this reingest really ingested the Gemini body"
        );
        assert_eq!(
            gemini_source_inputs(&db),
            0,
            "reingest_legacy: no Gemini source facts are fabricated"
        );
    }
    scenario("sources_mixed_legacy_connector_kept", "reingest_legacy");
}

// ---------------------------------------------------------------------------
// A4d — reingest mirror preflight refuses before any index or database
// ---------------------------------------------------------------------------

fn preflight_failure(fixture: &Fixture, label: &str) {
    let output = fixture.reingest_json(&[]);
    expect_rc(&output, 9, label);
    assert!(
        stdout_of(&output).trim().is_empty(),
        "{label}: no index result or summary may be published: {}",
        stdout_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("\"code\":9") && stderr.contains("\"kind\":\"source\""),
        "{label}: the standard stderr envelope names the source preflight failure: {stderr}"
    );
    assert!(
        !fixture.db().exists(),
        "{label}: preflight must not create the database"
    );
    assert!(
        fixture.auto_config_files().is_empty(),
        "{label}: preflight must not prepare the automatic copy"
    );
}

#[test]
fn sources_reingest_mirror_preflight() {
    // all_missing: a legal HOME file proves no accidental local ingest.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let home_file = fixture
            .home()
            .join(".claude/projects/home/p/session.jsonl");
        fs::create_dir_all(home_file.parent().expect("home parent")).expect("mkdir home");
        fs::write(
            &home_file,
            jsonl(&claude_session("home-session", "home q", "home a")),
        )
        .expect("write home session");
        preflight_failure(&fixture, "all_missing");
    }
    scenario("sources_reingest_mirror_preflight", "all_missing");

    // one_path_missing: one existing root cannot carry the whole source.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(
            r#"
[[sources]]
name = "fixture-claude"
origin_host = "fixture-claude"
type = "ssh"
host = "fixture-claude@fixture.invalid"
paths = ["~/.claude/projects", "~/.codex/sessions"]
"#,
        );
        fs::create_dir_all(fixture.mirror_path("fixture-claude", CLAUDE_PATH))
            .expect("create the one existing mirror root");
        preflight_failure(&fixture, "one_path_missing");
    }
    scenario("sources_reingest_mirror_preflight", "one_path_missing");

    // no_paths
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(
            r#"
[[sources]]
name = "fixture-claude"
origin_host = "fixture-claude"
type = "ssh"
host = "fixture-claude@fixture.invalid"
paths = []
"#,
        );
        preflight_failure(&fixture, "no_paths");
    }
    scenario("sources_reingest_mirror_preflight", "no_paths");

    // invalid_path: the primary candidate exists, but the entry itself is invalid.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(
            r#"
[[sources]]
name = "fixture-claude"
origin_host = "fixture-claude"
type = "ssh"
host = "fixture-claude@fixture.invalid"
paths = [""]
"#,
        );
        fs::create_dir_all(fixture.mirror_path("fixture-claude", ""))
            .expect("create the invalid entry's primary candidate");
        preflight_failure(&fixture, "invalid_path");
    }
    scenario("sources_reingest_mirror_preflight", "invalid_path");

    // ambiguous: two real layouts for one raw path.
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(
            r#"
[[sources]]
name = "fixture-claude"
origin_host = "fixture-claude"
type = "ssh"
host = "fixture-claude@fixture.invalid"
paths = ["~"]
"#,
        );
        fs::create_dir_all(fixture.mirror_path("fixture-claude", "~"))
            .expect("create the primary layout");
        fs::create_dir_all(fixture.mirror_path("fixture-claude", "~/"))
            .expect("create the legacy layout");
        preflight_failure(&fixture, "ambiguous");
    }
    scenario("sources_reingest_mirror_preflight", "ambiguous");

    // empty_existing: an existing empty mirror is not "missing".
    {
        let fixture = Fixture::new();
        fixture.write_sources_config(DEFAULT_SOURCES);
        let claude_root = fixture.mirror_path("fixture-claude", CLAUDE_PATH);
        let codex_root = fixture.mirror_path("fixture-codex", CODEX_PATH);
        fs::create_dir_all(&claude_root).expect("create claude mirror root");
        fs::create_dir_all(&codex_root).expect("create codex mirror root");

        let output = fixture.reingest_json(&[]);
        expect_rc(&output, 0, "empty_existing");
        let values = json_stream(&output.stdout);
        assert!(
            values.iter().any(index_success),
            "empty_existing: the index success object is on stdout: {values:?}"
        );
        let summary = values
            .iter()
            .find(|value| reingest_summary(value))
            .expect("reingest summary");
        assert_eq!(summary["status"], serde_json::json!("complete"));
        assert_eq!(summary["missing_mirrors"], serde_json::json!([]));
        let expected = vec![
            fs::canonicalize(&claude_root)
                .expect("canonical claude root")
                .display()
                .to_string(),
            fs::canonicalize(&codex_root)
                .expect("canonical codex root")
                .display()
                .to_string(),
        ];
        assert_eq!(summary["mirror_roots"], serde_json::json!(expected));
        let db = fixture.open_db();
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM source_inputs"),
            0,
            "empty_existing: an empty mirror yields zero source facts"
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM messages"),
            0,
            "empty_existing: an empty mirror yields zero messages"
        );
    }
    scenario("sources_reingest_mirror_preflight", "empty_existing");
}
