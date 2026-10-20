//! Task21: the three real CLI refresh entry points consume the default
//! fixed safety configuration end to end.
//!
//! Every case drives the real `cass` binary through `search --refresh`,
//! `pack --refresh` and the TUI startup refresh (`tui --once --refresh` with
//! `TUI_HEADLESS=1`), against a private synthetic HOME / XDG / connector
//! configuration tier and a private data directory. The database is read only
//! after the CLI process exits, and every expectation is checked through
//! `source_inputs`, its own committed activation receipt, the canonical
//! message bodies, the source message links, the SQL watermarks, the per-file
//! progress and the fixed configuration copies.
//!
//! The three tests are the fixed roster of `task-21-test-contract.md`. Each one
//! traverses the same three entries (`search`, `pack`, `tui_start`) in that
//! order, with a brand new fixture per entry: nine sub-scenarios in all. The
//! TUI's internal Ctrl+Shift+R event path belongs to Task27 and is not
//! exercised here.
//!
//! This target deliberately has no `mod util`: the shared module would add its
//! own tests and blur the intended "exactly three" roster. The fixtures are
//! synthetic and neutral; no real session, path or secret appears in this
//! file.
//!
//! `CARGO_BIN_EXE_cass` is resolved at runtime first, so the saved red/green
//! binary pair can be replayed by setting that variable to the saved path.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use coding_agent_search::storage::source_facts::decode_expected_manifest_header;
use rusqlite::OptionalExtension as _;
use sha2::{Digest as _, Sha256};

/// The automatic fixed configuration's identity domain.
const AUTO_IDENTITY_PREFIX: &str = "cass.source-config/1:sha256:";

/// The explicit failure a tampered automatic copy produces.
const SAFETY_COPY_STALE_MARKER: &str = "an existing fixed configuration copy has different bytes";

/// The non-fatal refresh warning `refresh_index_inline` prints.
const REFRESH_FAILURE_MARKER: &str = "Warning: --refresh indexing failed:";

/// The success line the refresh prints once the indexer thread returns `Ok`.
const REFRESH_DONE_MARKER: &str = "  done.";

/// The line printed when the refresh thread starts.
const REFRESH_START_MARKER: &str = "Refreshing index...";

/// A refresh entry can take minutes on a cold build; the bound only exists so
/// a wedged child cannot hang the gate forever.
const CHILD_TIMEOUT: Duration = Duration::from_secs(900);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Entry {
    Search,
    Pack,
    TuiStart,
}

impl Entry {
    fn id(self) -> &'static str {
        match self {
            Self::Search => "search",
            Self::Pack => "pack",
            Self::TuiStart => "tui_start",
        }
    }

    /// Whether this entry returns real hits that must be inspected.
    fn is_query_entry(self) -> bool {
        !matches!(self, Self::TuiStart)
    }
}

/// The fixed traversal order of the contract.
const ENTRY_ORDER: [Entry; 3] = [Entry::Search, Entry::Pack, Entry::TuiStart];

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home").join(".claude/projects"))
            .expect("mkdir claude root");
        std::fs::create_dir_all(root.path().join("home").join(".codex/sessions"))
            .expect("mkdir codex root");
        std::fs::create_dir_all(root.path().join("data")).expect("mkdir data");
        std::fs::create_dir_all(root.path().join("config")).expect("mkdir config");
        std::fs::write(
            root.path().join("fixed-safety.toml"),
            include_bytes!("../config/excluded_context_paths.toml"),
        )
        .expect("write the explicit fixed copy");
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

    fn explicit_copy(&self) -> PathBuf {
        self.root.path().join("fixed-safety.toml")
    }

    /// The live rule file the default preparation discovers.
    fn live_config(&self) -> PathBuf {
        self.config_home()
            .join("cass")
            .join("excluded_context_paths.toml")
    }

    fn corrupt_live_config(&self) {
        let path = self.live_config();
        std::fs::create_dir_all(path.parent().expect("config parent")).expect("mkdir config");
        std::fs::write(&path, "this is not toml [[[\n").expect("corrupt live config");
    }

    /// `data_dir/source-configs/v1`, where the automatic copies live.
    fn auto_config_dir(&self) -> PathBuf {
        self.data_dir().join("source-configs").join("v1")
    }

    fn auto_config_files(&self) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(self.auto_config_dir()) else {
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

    fn write_claude_session(&self, relative: &str, uuid: &str, question: &str, answer: &str) -> PathBuf {
        let path = self.home().join(".claude/projects").join(relative);
        std::fs::create_dir_all(path.parent().expect("session parent")).expect("mkdir session dir");
        std::fs::write(&path, jsonl(&claude_session(uuid, question, answer)))
            .expect("write claude session");
        path
    }

    fn write_codex_session(&self, relative: &str, id: &str, question: &str, answer: &str) -> PathBuf {
        let path = self.home().join(".codex/sessions").join(relative);
        std::fs::create_dir_all(path.parent().expect("rollout parent")).expect("mkdir rollout dir");
        std::fs::write(&path, jsonl(&codex_session(id, question, answer)))
            .expect("write codex rollout");
        path
    }

    /// Point every source-discovery environment at this fixture, so an
    /// inherited value on the host cannot make a fixture process scan real
    /// history. Only the child environment changes; the test process's own
    /// environment is never mutated.
    fn isolate<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("HOME", self.home())
            .env("XDG_DATA_HOME", self.home().join(".local/share"))
            .env("XDG_CONFIG_HOME", self.config_home())
            .env("CODEX_HOME", self.home().join(".codex"))
            .env("CASS_AIDER_DATA_ROOT", self.home().join(".aider"))
            .env("PI_SESSIONS_DIR", self.home().join(".pi"))
            .env("PI_CODING_AGENT_DIR", self.home().join(".pi"))
            .env("GOOSE_PATH_ROOT", self.home().join(".goose"))
            .env("HERMES_HOME", self.home().join(".hermes"))
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("NO_COLOR", "1")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("CASS_EXCLUDE_PATHS")
            .env_remove("CASS_DATA_DIR")
            .env_remove("RUST_LOG");
        cmd
    }

    /// Warm up with an explicit, complete and valid fixed copy. No automatic
    /// copy is ever prepared on this path.
    fn index_with_explicit_copy(&self) -> Output {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"]).arg(self.data_dir());
        cmd.arg("--source-safety-config").arg(self.explicit_copy());
        cmd.arg("--json");
        run_bounded(&mut cmd, "index --source-safety-config")
    }

    /// Warm up with no fidelity flag: the run discovers the live rules once and
    /// publishes its own content-addressed copy.
    fn index_default(&self) -> Output {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"]).arg(self.data_dir());
        cmd.arg("--json");
        run_bounded(&mut cmd, "index")
    }

    fn entry_command(&self, entry: Entry, marker: &str, refresh: bool) -> Command {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        match entry {
            Entry::Search => {
                cmd.args(["search", marker, "--json", "--mode", "lexical"]);
                cmd.arg("--data-dir").arg(self.data_dir());
            }
            Entry::Pack => {
                cmd.args([
                    "pack",
                    marker,
                    "--json",
                    "--mode",
                    "lexical",
                    "--freshness-policy",
                    "allow-stale",
                ]);
                cmd.arg("--data-dir").arg(self.data_dir());
            }
            Entry::TuiStart => {
                cmd.env("TUI_HEADLESS", "1");
                cmd.args(["tui", "--once"]);
                cmd.arg("--data-dir").arg(self.data_dir());
            }
        }
        if refresh {
            cmd.arg("--refresh");
        }
        cmd
    }

    fn run_entry(&self, entry: Entry, marker: &str, refresh: bool) -> Output {
        let mut cmd = self.entry_command(entry, marker, refresh);
        let label = format!("{} (refresh={refresh})", entry.id());
        run_bounded(&mut cmd, &label)
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

fn run_bounded(cmd: &mut Command, label: &str) -> Output {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|error| panic!("{label}: spawn cass: {error}"));
    let mut stdout_pipe = child.stdout.take().expect("the child's stdout");
    let mut stderr_pipe = child.stderr.take().expect("the child's stderr");
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{label}: probing the child failed: {error}");
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let stdout = String::from_utf8_lossy(&stdout_reader.join().unwrap_or_default()).into_owned();
            let stderr = String::from_utf8_lossy(&stderr_reader.join().unwrap_or_default()).into_owned();
            panic!(
                "{label}: the child did not exit within {CHILD_TIMEOUT:?}; stdout={stdout}; stderr={stderr}"
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stdout = stdout_reader.join().expect("the stdout reader");
    let stderr = stderr_reader.join().expect("the stderr reader");
    Output {
        status,
        stdout,
        stderr,
    }
}

fn jsonl(lines: &[serde_json::Value]) -> String {
    lines
        .iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn claude_session(uuid: &str, question: &str, answer: &str) -> Vec<serde_json::Value> {
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

fn codex_session(id: &str, question: &str, answer: &str) -> Vec<serde_json::Value> {
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
// SQLite readers
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

fn input_rows_for(db: &rusqlite::Connection, locator: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM source_inputs WHERE relative_locator_bin = ?1",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("counting inputs for {locator}: {error}"))
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

fn links_for(db: &rusqlite::Connection, locator: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM source_message_links l
         JOIN source_records r ON r.id = l.record_id
         JOIN source_inputs si ON si.id = r.input_id
         WHERE si.relative_locator_bin = ?1
           AND l.authority = 'canonical' AND l.message_id IS NOT NULL",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("counting canonical links for {locator}: {error}"))
}

/// The decoded safety identities and fixed-copy digests of every input row
/// for one locator.
///
/// A locator can legitimately own more than one row after its safety identity
/// changes: the earlier explicit-copy run keeps its own row, and a later run
/// under the automatic copy may add another. Each row is checked on its own
/// terms instead of assuming a single row per locator.
fn manifests_for(db: &rusqlite::Connection, locator: &str) -> Vec<(String, String)> {
    let mut stmt = db
        .prepare(
            "SELECT expected_manifest_bin FROM source_inputs
             WHERE relative_locator_bin = ?1 ORDER BY id",
        )
        .expect("prepare the manifest query");
    let rows: Vec<Vec<u8>> = stmt
        .query_map([locator.as_bytes()], |row| row.get::<_, Vec<u8>>(0))
        .unwrap_or_else(|error| panic!("query the manifest for {locator}: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("collect the manifest rows for {locator}: {error}"));
    assert!(
        !rows.is_empty(),
        "{locator}: expected at least one input row, found none"
    );
    rows.into_iter()
        .map(|bytes| {
            let (_manifest, safety) = decode_expected_manifest_header(&bytes)
                .unwrap_or_else(|error| panic!("{locator}: decode the manifest header: {error}"));
            (
                safety.config_source_identity().to_string(),
                safety.fixed_config_sha256().hex(),
            )
        })
        .collect()
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

/// Every `(root_id, connector, last_scan_ts)` row, ordered by its stable key.
/// Values, not just row counts: a rewrite of the same rows must fail this.
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

/// Every per-file progress row, ordered by its stable key.
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

/// Every canonical message as `id|content`, ordered by id.
fn canonical_bodies(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare("SELECT id || '|' || COALESCE(content, '') FROM messages ORDER BY id")
        .expect("prepare the canonical bodies");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query the canonical bodies")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the canonical bodies")
}

/// Every source fact this database holds, as comparable lines.
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
                row.get::<_, Option<String>>(5)?.unwrap_or_default(),
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
    lines.push(format!(
        "source_facts_revision={}",
        source_facts_revision(db)
    ));
    lines.push(format!("receipts={}", receipt_keys(db)));
    lines
}

/// The contract's core snapshot: facts and receipts, SQL watermarks, per-file
/// progress and canonical bodies, each by value.
#[derive(Debug, PartialEq, Eq)]
struct CoreSnapshot {
    facts: Vec<String>,
    watermarks: Vec<String>,
    file_progress: Vec<String>,
    bodies: Vec<String>,
}

fn core_snapshot(db: &rusqlite::Connection) -> CoreSnapshot {
    CoreSnapshot {
        facts: facts_fingerprint(db),
        watermarks: watermark_rows(db),
        file_progress: file_progress_rows(db),
        bodies: canonical_bodies(db),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// Recursive content fingerprint of a directory: relative path, size and
/// SHA256 of every file, sorted. An absent directory is empty.
fn dir_fingerprint(root: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else if path.is_file() {
                let relative = path.strip_prefix(base).unwrap_or(&path);
                let bytes = std::fs::read(&path).unwrap_or_default();
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

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output, label: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{label}: expected exit 0; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The contract's query-side check: a real body hit, never an echo of the
/// query string. Returns the number of inspected items.
fn assert_query_hit(entry: Entry, output: &Output, marker: &str, label: &str) {
    match entry {
        Entry::Search => {
            let json: serde_json::Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|error| panic!("{label}: search stdout is not JSON: {error}; stderr={}", stderr_of(output)));
            let hits = json
                .get("hits")
                .and_then(serde_json::Value::as_array)
                .unwrap_or_else(|| panic!("{label}: search JSON has no hits array: {json}"));
            assert!(!hits.is_empty(), "{label}: search returned no hits");
            assert!(
                hits.iter().any(|hit| {
                    hit.get("content")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|content| content.contains(marker))
                }),
                "{label}: no search hit content contains the marker {marker}: {json}"
            );
        }
        Entry::Pack => {
            let json: serde_json::Value = serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|error| panic!("{label}: pack stdout is not JSON: {error}; stderr={}", stderr_of(output)));
            let evidence = json
                .get("evidence")
                .and_then(serde_json::Value::as_array)
                .unwrap_or_else(|| panic!("{label}: pack JSON has no evidence array: {json}"));
            assert!(!evidence.is_empty(), "{label}: pack returned no evidence");
            assert!(
                evidence.iter().any(|item| {
                    item.get("excerpt")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|excerpt| excerpt.contains(marker))
                }),
                "{label}: no pack evidence excerpt contains the marker {marker}: {json}"
            );
        }
        Entry::TuiStart => {}
    }
}

fn assert_no_refresh_noise(stderr: &str, label: &str) {
    assert!(
        !stderr.contains(REFRESH_START_MARKER),
        "{label}: the no-refresh entry must not print {REFRESH_START_MARKER:?}; stderr={stderr}"
    );
    assert!(
        !stderr.contains(REFRESH_FAILURE_MARKER),
        "{label}: the no-refresh entry must not print a refresh failure; stderr={stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "{label}: the no-refresh entry must not panic; stderr={stderr}"
    );
}

fn assert_refresh_success_stderr(output: &Output, label: &str) {
    let stderr = stderr_of(output);
    assert!(
        stderr.contains(REFRESH_START_MARKER),
        "{label}: the refresh must announce itself; stderr={stderr}"
    );
    assert!(
        stderr.contains(REFRESH_DONE_MARKER),
        "{label}: the refresh must print its success line; stderr={stderr}"
    );
    assert!(
        !stderr.contains(REFRESH_FAILURE_MARKER),
        "{label}: a successful refresh must not print a failure warning; stderr={stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "{label}: the refresh must not panic; stderr={stderr}"
    );
}

fn scenario_marker(test: &str, entry: Entry) {
    // The leading newline keeps the marker on its own line even under
    // `--test-threads=1`, where libtest has already written the
    // `test <name> ... ` prefix without a line break.
    println!(
        "\nTASK21_SCENARIO test={test} entry={} result=pass",
        entry.id()
    );
}

// ---------------------------------------------------------------------------
// A1: all three entries ingest two new sources through a real refresh
// ---------------------------------------------------------------------------

fn lands_source_case(entry: Entry) {
    let test = "cli_refresh_lands_source";
    let label = format!("{test}/{}", entry.id());
    let fixture = Fixture::new();

    let old_marker = format!("task21a1{}oldmarker", entry.id());
    let new_marker = format!("task21a1{}newmarker", entry.id());
    let old_locator = "a1/warmup/old.jsonl";
    let new_claude_locator = "a1/new/claude.jsonl";
    let new_codex_locator = "2026/01/rollout-a1-new.jsonl";

    fixture.write_claude_session(
        old_locator,
        &format!("sess-a1-old-{}", entry.id()),
        &format!("the old question {old_marker}"),
        &format!("the old answer {old_marker}"),
    );
    let warm = fixture.index_with_explicit_copy();
    assert_success(&warm, &format!("{label}: warmup"));
    assert!(
        fixture.auto_config_files().is_empty(),
        "{label}: an explicit-copy warmup must not prepare an automatic copy"
    );
    {
        let db = fixture.open_db();
        assert_eq!(
            complete_rows_for(&db, old_locator),
            1,
            "{label}: the warmup input is complete"
        );
        assert_eq!(
            committed_receipts_for(&db, old_locator),
            1,
            "{label}: the warmup input has its committed activation receipt"
        );
        assert!(
            count_like(&db, &old_marker) > 0,
            "{label}: the warmup body reached the canonical store"
        );
    }

    fixture.write_claude_session(
        new_claude_locator,
        &format!("sess-a1-new-claude-{}", entry.id()),
        &format!("the new question {new_marker}"),
        &format!("the new claude answer {new_marker}"),
    );
    fixture.write_codex_session(
        new_codex_locator,
        &format!("sess-a1-new-codex-{}", entry.id()),
        &format!("the new codex question {new_marker}"),
        &format!("the new codex answer {new_marker}"),
    );

    let output = fixture.run_entry(entry, &new_marker, true);
    assert_success(&output, &label);
    assert_refresh_success_stderr(&output, &label);
    if entry.is_query_entry() {
        assert_query_hit(entry, &output, &new_marker, &label);
    }

    {
        let db = fixture.open_db();
        for locator in [new_claude_locator, new_codex_locator] {
            assert_eq!(
                input_rows_for(&db, locator),
                1,
                "{label}: {locator} has exactly one source fact"
            );
            assert_eq!(
                complete_rows_for(&db, locator),
                1,
                "{label}: {locator} is complete"
            );
            assert_eq!(
                committed_receipts_for(&db, locator),
                1,
                "{label}: {locator} is tied to its own committed activation receipt"
            );
            assert!(
                links_for(&db, locator) > 0,
                "{label}: {locator} links to canonical messages"
            );
        }
        assert!(
            count_like(&db, &new_marker) > 0,
            "{label}: the new body reached the canonical store"
        );

        let files = fixture.auto_config_files();
        assert_eq!(
            files.len(),
            1,
            "{label}: the refresh publishes exactly one automatic copy: {files:?}"
        );
        let bytes = std::fs::read(&files[0]).expect("read the automatic copy");
        let digest = sha256_hex(&bytes);
        let name = files[0]
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("the automatic copy has a UTF-8 stem");
        assert_eq!(
            name, digest,
            "{label}: the automatic copy is named after its own digest"
        );

        // Only the two new locators are checked for the automatic identity.
        // Each is ingested exactly once, by the refresh run.
        for locator in [new_claude_locator, new_codex_locator] {
            let manifests = manifests_for(&db, locator);
            assert_eq!(
                manifests.len(),
                1,
                "{label}: {locator} has exactly one input row"
            );
            let (identity, fixed_sha) = &manifests[0];
            assert_eq!(
                identity,
                &format!("{AUTO_IDENTITY_PREFIX}{digest}"),
                "{label}: {locator} carries the automatic content address"
            );
            assert_eq!(
                fixed_sha, &digest,
                "{label}: {locator}'s manifest names the published copy digest"
            );
        }

        // The warmup input keeps its explicit path identity. A later run under
        // the automatic identity may add its own row for the same locator;
        // that does not erase the earlier explicit row.
        let explicit_identity = fixture
            .explicit_copy()
            .to_str()
            .expect("utf-8 explicit copy")
            .to_string();
        let old_manifests = manifests_for(&db, old_locator);
        assert!(
            old_manifests
                .iter()
                .any(|(identity, _)| identity == &explicit_identity),
            "{label}: the warmup input keeps its explicit path identity: {old_manifests:?}"
        );
    }

    scenario_marker(test, entry);
}

#[test]
fn cli_refresh_lands_source() {
    for entry in ENTRY_ORDER {
        lands_source_case(entry);
    }
}

// ---------------------------------------------------------------------------
// A2: a damaged fixed copy fails the refresh, never the query
// ---------------------------------------------------------------------------

fn failure_not_complete_case(entry: Entry) {
    let test = "cli_refresh_failure_not_complete";
    let label = format!("{test}/{}", entry.id());
    let fixture = Fixture::new();

    let old_marker = format!("task21a2{}oldmarker", entry.id());
    let new_marker = format!("task21a2{}newmarker", entry.id());
    let old_locator = "a2/warmup/old.jsonl";
    let new_locator = "a2/new/added.jsonl";

    fixture.write_claude_session(
        old_locator,
        &format!("sess-a2-old-{}", entry.id()),
        &format!("the old question {old_marker}"),
        &format!("the old answer {old_marker}"),
    );
    let warm = fixture.index_default();
    assert_success(&warm, &format!("{label}: warmup"));
    {
        let db = fixture.open_db();
        assert_eq!(
            complete_rows_for(&db, old_locator),
            1,
            "{label}: the warmup input is complete"
        );
        assert_eq!(
            committed_receipts_for(&db, old_locator),
            1,
            "{label}: the warmup input has its committed activation receipt"
        );
        assert!(
            count_like(&db, &old_marker) > 0,
            "{label}: the warmup body reached the canonical store"
        );
    }
    let files = fixture.auto_config_files();
    assert_eq!(
        files.len(),
        1,
        "{label}: the default warmup owns exactly one automatic copy: {files:?}"
    );

    let snapshot_before = {
        let db = fixture.open_db();
        core_snapshot(&db)
    };

    // The live rules stay valid; only the published fixed copy is damaged.
    let copy = files[0].clone();
    let mut tampered = std::fs::read(&copy).expect("read the automatic copy");
    tampered.extend_from_slice(b"\n# task21 tampered copy\n");
    std::fs::write(&copy, &tampered).expect("tamper with the automatic copy");

    fixture.write_claude_session(
        new_locator,
        &format!("sess-a2-new-{}", entry.id()),
        &format!("the new question {new_marker}"),
        &format!("the new answer {new_marker}"),
    );

    let output = fixture.run_entry(entry, &old_marker, true);
    assert_success(&output, &label);
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains(REFRESH_FAILURE_MARKER),
        "{label}: the damaged fixed copy must produce the refresh failure warning; stderr={stderr}"
    );
    assert!(
        stderr.contains(SAFETY_COPY_STALE_MARKER),
        "{label}: the warning names the damaged copy; stderr={stderr}"
    );
    assert!(
        !stderr.contains(REFRESH_DONE_MARKER),
        "{label}: a failed refresh must not print the success line; stderr={stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "{label}: a failed refresh must not panic; stderr={stderr}"
    );
    if entry.is_query_entry() {
        assert_query_hit(entry, &output, &old_marker, &label);
    }

    {
        let db = fixture.open_db();
        assert_eq!(
            input_rows_for(&db, new_locator),
            0,
            "{label}: the unread input leaves no source fact"
        );
        assert_eq!(
            complete_rows_for(&db, new_locator),
            0,
            "{label}: the unread input never completes"
        );
        assert_eq!(
            committed_receipts_for(&db, new_locator),
            0,
            "{label}: the unread input has no activation receipt"
        );
        assert_eq!(
            core_snapshot(&db),
            snapshot_before,
            "{label}: the failed refresh preserves every earlier fact, receipt, \
             watermark, per-file progress row and canonical body by value"
        );
    }

    assert_eq!(
        std::fs::read(&copy).expect("re-read the automatic copy"),
        tampered,
        "{label}: the failed refresh leaves the damaged copy untouched"
    );

    scenario_marker(test, entry);
}

#[test]
fn cli_refresh_failure_not_complete() {
    for entry in ENTRY_ORDER {
        failure_not_complete_case(entry);
    }
}

// ---------------------------------------------------------------------------
// A3: no `--refresh` means no ingestion at all
// ---------------------------------------------------------------------------

fn without_refresh_no_ingest_case(entry: Entry) {
    let test = "search_without_refresh_no_ingest";
    let label = format!("{test}/{}", entry.id());
    let fixture = Fixture::new();

    let old_marker = format!("task21a3{}oldmarker", entry.id());
    let new_marker = format!("task21a3{}newmarker", entry.id());
    let old_locator = "a3/warmup/old.jsonl";
    let new_locator = "a3/new/added.jsonl";

    fixture.write_claude_session(
        old_locator,
        &format!("sess-a3-old-{}", entry.id()),
        &format!("the old question {old_marker}"),
        &format!("the old answer {old_marker}"),
    );
    let warm = fixture.index_with_explicit_copy();
    assert_success(&warm, &format!("{label}: warmup"));
    assert!(
        fixture.auto_config_files().is_empty(),
        "{label}: an explicit-copy warmup must not prepare an automatic copy"
    );
    assert!(
        !fixture.auto_config_dir().exists(),
        "{label}: an explicit-copy warmup creates no automatic-config directory"
    );
    {
        let db = fixture.open_db();
        assert_eq!(
            complete_rows_for(&db, old_locator),
            1,
            "{label}: the warmup input is complete"
        );
    }

    let snapshot_before = {
        let db = fixture.open_db();
        core_snapshot(&db)
    };
    let raw_mirror_before = dir_fingerprint(&fixture.data_dir().join("raw-mirror"));
    assert!(
        !raw_mirror_before.is_empty(),
        "{label}: the warmup captured raw-mirror bytes to compare against"
    );

    // The live rules are broken, but no flag means nothing may read them.
    fixture.corrupt_live_config();
    fixture.write_claude_session(
        new_locator,
        &format!("sess-a3-new-{}", entry.id()),
        &format!("the new question {new_marker}"),
        &format!("the new answer {new_marker}"),
    );

    let output = fixture.run_entry(entry, &old_marker, false);
    assert_success(&output, &label);
    assert_no_refresh_noise(&stderr_of(&output), &label);
    if entry.is_query_entry() {
        assert_query_hit(entry, &output, &old_marker, &label);
    }

    {
        let db = fixture.open_db();
        assert_eq!(
            input_rows_for(&db, new_locator),
            0,
            "{label}: the unread input leaves no source fact"
        );
        assert_eq!(
            complete_rows_for(&db, new_locator),
            0,
            "{label}: the unread input never completes"
        );
        assert_eq!(
            core_snapshot(&db),
            snapshot_before,
            "{label}: the no-refresh entry preserves source facts, receipts, \
             watermarks, per-file progress and canonical bodies by value"
        );
    }
    assert_eq!(
        dir_fingerprint(&fixture.data_dir().join("raw-mirror")),
        raw_mirror_before,
        "{label}: the no-refresh entry preserves every raw-mirror path and byte"
    );
    assert!(
        !fixture.auto_config_dir().exists(),
        "{label}: the no-refresh entry prepares no automatic copy"
    );

    scenario_marker(test, entry);
}

#[test]
fn search_without_refresh_no_ingest() {
    for entry in ENTRY_ORDER {
        without_refresh_no_ingest_case(entry);
    }
}
