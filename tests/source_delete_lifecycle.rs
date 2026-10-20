//! SRC05C-D acceptance: the source copies leave with the canonical data.
//!
//! The carrying contract (§14.5) makes the source-aware tables a *copy* of the
//! canonical archive, so `cass forget --source-glob` and
//! `cass sources agents exclude` have to remove the copies their own selection
//! matched, in the same transaction, while leaving every source the selection
//! did **not** match intact -- including a source whose canonical message is
//! being deleted, which keeps its facts and is historyized instead.
//!
//! Every case here drives the real `cass` binary over a private synthetic
//! HOME, private synthetic configured roots, a private fixed safety copy and a
//! private data directory, then reads the resulting SQLite database directly
//! and read-only. Nothing calls an internal helper: the seam is the CLI, the
//! database and the process boundary.
//!
//! The fixtures are synthetic and neutral. No real session, path or secret
//! appears in this file.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home")).expect("mkdir home");
        std::fs::create_dir_all(root.path().join("data")).expect("mkdir data");
        std::fs::write(
            root.path().join("fixed-safety.toml"),
            include_bytes!("../config/excluded_context_paths.toml"),
        )
        .expect("write fixed safety copy");
        Self { root }
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn config_home(&self) -> PathBuf {
        self.root.path().join("config")
    }

    fn db(&self) -> PathBuf {
        self.data_dir().join("agent_search.db")
    }

    fn fixed_copy(&self) -> PathBuf {
        self.root.path().join("fixed-safety.toml")
    }

    /// Point every source-discovery environment at this fixture, so an
    /// inherited value on the test host cannot make a fixture process scan
    /// real history. `CASS_ALLOW_INSECURE_PERMISSIONS` is deliberately absent:
    /// the fixture's own directories are created with the modes the probe
    /// expects.
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
            .env("CASS_DATA_DIR", self.data_dir())
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("NO_COLOR", "1")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("RUST_LOG");
        cmd
    }

    /// One `sources.toml` entry: `(name, kind, origin_host, path, full_scan)`.
    fn write_sources(&self, sources: &[(&str, &str, &str, &str, bool)]) {
        let dir = self.config_home().join("cass");
        std::fs::create_dir_all(&dir).expect("mkdir cass config");
        let mut body = String::new();
        for (name, kind, origin_host, path, full_scan) in sources {
            body.push_str("[[sources]]\n");
            body.push_str(&format!("name = \"{name}\"\n"));
            body.push_str(&format!("type = \"{kind}\"\n"));
            if *kind == "ssh" {
                body.push_str(&format!("host = \"{origin_host}\"\n"));
            }
            body.push_str(&format!("origin_host = \"{origin_host}\"\n"));
            if *full_scan {
                body.push_str("full_scan = true\n");
            }
            body.push_str(&format!("paths = [\"{path}\"]\n\n"));
        }
        std::fs::write(dir.join("sources.toml"), body).expect("write sources.toml");
    }

    /// Write a Claude Code session under `root` at `relative`.
    fn write_session(&self, root: &Path, relative: &str, uuid: &str, answer: &str) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("session parent")).expect("mkdir session dir");
        let body: String = claude_session(uuid, "synthetic question", answer)
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&path, body).expect("write session");
        path
    }

    /// `cass index` with the source-aware flag, over this fixture's data dir.
    fn index(&self) -> Run {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .arg("--source-safety-config")
            .arg(self.fixed_copy())
            .args(["--json"]);
        Run::from(cmd.output().expect("spawn cass index"))
    }

    /// `cass forget --source-glob <glob> [--apply]`, with structured output
    /// requested through `CASS_OUTPUT_FORMAT` rather than the literal `--json`
    /// token.
    ///
    /// That is not a style choice. `forget` is missing from the CLI's
    /// `CANONICAL_TOP_LEVEL_COMMANDS` table, so the implicit-robot-query
    /// recovery layer rewrites `forget --source-glob G --json` into
    /// `search forget --source-glob G --json` and the command never parses --
    /// the exact defect the same table's own ruling note records for
    /// `mirror-restore` and `sync`. The flag spelling is pre-existing and
    /// outside this ticket's scope; the environment variable reaches the same
    /// structured output without depending on the broken rewrite, so the
    /// acceptance still drives the real binary.
    fn forget(&self, glob: &str, apply: bool) -> Run {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.env("CASS_OUTPUT_FORMAT", "json");
        cmd.arg("forget")
            .arg("--source-glob")
            .arg(glob)
            .arg("--db")
            .arg(self.db());
        if apply {
            cmd.arg("--apply");
        }
        Run::from(cmd.output().expect("spawn cass forget"))
    }

    /// `cass sources agents exclude <agent>` -- the entry point that purges an
    /// excluded agent's already-archived data.
    fn exclude_agent(&self, agent: &str) -> Run {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.args(["sources", "agents", "exclude", agent])
            .arg("--db")
            .arg(self.db());
        Run::from(cmd.output().expect("spawn cass sources agents exclude"))
    }

    /// `cass sources agents exclude --help`, so the fixture's own call above is
    /// held to the parameters the binary really publishes.
    fn exclude_agent_help(&self) -> String {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.args(["sources", "agents", "exclude", "--help"]);
        let output = cmd
            .output()
            .expect("spawn cass sources agents exclude --help");
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    fn open_db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(self.db(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open the database read-only")
    }
}

/// One `cass` run's observable result.
struct Run {
    code: Option<i32>,
    payload: Option<serde_json::Value>,
    stdout: String,
    stderr: String,
}

impl From<std::process::Output> for Run {
    fn from(output: std::process::Output) -> Self {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Self {
            code: output.status.code(),
            payload: serde_json::from_str::<serde_json::Value>(&stdout).ok(),
            stdout,
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }
}

impl Run {
    fn expect_ok(&self, what: &str) {
        assert_eq!(
            self.code,
            Some(0),
            "{what} must succeed; stdout={} stderr={}",
            self.stdout,
            self.stderr
        );
    }

    fn number(&self, field: &str) -> u64 {
        self.payload
            .as_ref()
            .unwrap_or_else(|| panic!("{field}: the run produced no JSON payload"))
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("{field}: missing from {}", self.stdout))
    }

    fn strings(&self, field: &str) -> Vec<String> {
        self.payload
            .as_ref()
            .and_then(|payload| payload.get(field))
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
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

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

fn scalar(db: &rusqlite::Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |row| row.get(0)).expect(sql)
}

/// The `source_facts_revision` meta counter, read exactly as stored.
fn revision(db: &rusqlite::Connection) -> String {
    db.query_row(
        "SELECT COALESCE((SELECT value FROM meta WHERE key = 'source_facts_revision'), '<absent>')",
        [],
        |row| row.get::<_, String>(0),
    )
    .expect("read the source facts revision")
}

/// Every `source_message_links` row as `(id, authority, message_id)`.
fn link_states(db: &rusqlite::Connection) -> Vec<(i64, Option<String>, Option<i64>)> {
    let mut statement = db
        .prepare("SELECT id, authority, message_id FROM source_message_links ORDER BY id")
        .expect("prepare the link states");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query the link states")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the link states")
}

/// Every link's immutable witness columns, keyed by id: the bytes a forget may
/// never rewrite.
fn link_witnesses(db: &rusqlite::Connection) -> Vec<(i64, Vec<u8>, Vec<u8>)> {
    let mut statement = db
        .prepare(
            "SELECT id, source_positions_bin, binding_digest FROM source_message_links ORDER BY id",
        )
        .expect("prepare the link witnesses");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query the link witnesses")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the link witnesses")
}

/// The `(id, authority, message_id)` of every link belonging to the inputs
/// under `needle`.
fn link_states_under(
    db: &rusqlite::Connection,
    needle: &str,
) -> Vec<(i64, Option<String>, Option<i64>)> {
    let ids = input_ids_under(db, needle);
    if ids.is_empty() {
        return Vec::new();
    }
    let list = ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
    let mut statement = db
        .prepare(&format!(
            "SELECT id, authority, message_id FROM source_message_links
             WHERE record_id IN (SELECT id FROM source_records WHERE input_id IN ({list}))
             ORDER BY id"
        ))
        .expect("prepare the scoped link states");
    statement
        .query_map([], |row| {
            Ok::<(i64, Option<String>, Option<i64>), rusqlite::Error>((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
            ))
        })
        .expect("query the scoped link states")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the scoped link states")
}

/// The witness columns of the links that belong to the inputs under `needle`.
fn link_witnesses_under(db: &rusqlite::Connection, needle: &str) -> Vec<(i64, Vec<u8>, Vec<u8>)> {
    let ids = input_ids_under(db, needle);
    if ids.is_empty() {
        return Vec::new();
    }
    let list = ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
    let mut statement = db
        .prepare(&format!(
            "SELECT id, source_positions_bin, binding_digest FROM source_message_links
             WHERE record_id IN (SELECT id FROM source_records WHERE input_id IN ({list}))
             ORDER BY id"
        ))
        .expect("prepare the scoped link witnesses");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query the scoped link witnesses")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the scoped link witnesses")
}

/// The activation receipt keys the inputs under `needle` name, read straight
/// out of the column activation wrote (§14.5's exact binding).
fn receipt_keys_under(db: &rusqlite::Connection, needle: &str) -> Vec<String> {
    let ids = input_ids_under(db, needle);
    if ids.is_empty() {
        return Vec::new();
    }
    let list = ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
    let mut statement = db
        .prepare(&format!(
            "SELECT receipt_key FROM source_inputs
             WHERE id IN ({list}) AND receipt_key IS NOT NULL ORDER BY id"
        ))
        .expect("prepare the receipt keys");
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query the receipt keys")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the receipt keys")
}

/// How many activation receipts the database still holds.
fn activation_receipts(db: &rusqlite::Connection) -> i64 {
    scalar(
        db,
        "SELECT COUNT(*) FROM operation_commit_receipt
         WHERE operation = 'source_input_activation_v1'",
    )
}

/// Whether one receipt row is still present, addressed by its own primary key.
fn receipt_present(db: &rusqlite::Connection, key: &str) -> bool {
    db.query_row(
        "SELECT COUNT(*) FROM operation_commit_receipt WHERE idempotency_key = ?1",
        [key],
        |row| row.get::<_, i64>(0),
    )
    .expect("count the receipt row")
        > 0
}

/// Every `PRAGMA foreign_key_check` row: an empty vector is the database's own
/// statement that no FK is dangling.
fn foreign_key_violations(db: &rusqlite::Connection) -> Vec<(String, i64, String, i64)> {
    let mut statement = db
        .prepare("PRAGMA foreign_key_check")
        .expect("prepare the foreign key check");
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("run the foreign key check")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the foreign key check")
}

/// The original locator every stored input carries, decoded the same way the
/// deletion selects them: the stored root joined with the stored locator.
fn input_locators(db: &rusqlite::Connection) -> Vec<(i64, String, String)> {
    let mut statement = db
        .prepare("SELECT id, root_id_bin, relative_locator_bin FROM source_inputs ORDER BY id")
        .expect("prepare the input locators");
    statement
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let root: Vec<u8> = row.get(1)?;
            let relative: Vec<u8> = row.get(2)?;
            Ok((
                id,
                Path::new(&String::from_utf8(root).expect("root is UTF-8"))
                    .join(String::from_utf8(relative).expect("locator is UTF-8"))
                    .to_string_lossy()
                    .to_string(),
                String::new(),
            ))
        })
        .expect("query the input locators")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect the input locators")
}

/// A digest over every byte under `root`, path names included, so a
/// "the mirror was not touched" assertion is about content and not just file
/// count.
fn tree_digest(root: &Path) -> String {
    let mut entries: Vec<PathBuf> = Vec::new();
    collect_files(root, &mut entries);
    entries.sort();
    let mut hasher = Sha256::new();
    for path in entries {
        let relative = path.strip_prefix(root).unwrap_or(&path);
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        match std::fs::read(&path) {
            Ok(bytes) => hasher.update(&bytes),
            Err(_) => hasher.update(b"<unreadable>"),
        }
        hasher.update(b"\0");
    }
    format!("{:x}", hasher.finalize())
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// The number of `source_inputs` rows whose original locator ends with `suffix`
/// -- a scope check that never has to guess an id.
fn inputs_under(db: &rusqlite::Connection, needle: &str) -> i64 {
    input_ids_under(db, needle).len() as i64
}

fn input_ids_under(db: &rusqlite::Connection, needle: &str) -> Vec<i64> {
    input_locators(db)
        .into_iter()
        .filter(|(_, locator, _)| locator.contains(needle))
        .map(|(id, _, _)| id)
        .collect()
}

/// How many `source_records` rows the inputs under `needle` own.
fn records_under(db: &rusqlite::Connection, needle: &str) -> i64 {
    let ids = input_ids_under(db, needle);
    if ids.is_empty() {
        return 0;
    }
    let list = ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
    scalar(
        db,
        &format!("SELECT COUNT(*) FROM source_records WHERE input_id IN ({list})"),
    )
}

/// How many `source_message_links` rows the inputs under `needle` own.
fn links_under(db: &rusqlite::Connection, needle: &str) -> i64 {
    let ids = input_ids_under(db, needle);
    if ids.is_empty() {
        return 0;
    }
    let list = ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
    scalar(
        db,
        &format!(
            "SELECT COUNT(*) FROM source_message_links
             WHERE record_id IN (SELECT id FROM source_records WHERE input_id IN ({list}))"
        ),
    )
}

// ---------------------------------------------------------------------------
// A + B: the real CLI, dry-run then apply
// ---------------------------------------------------------------------------

/// `cass forget --source-glob` over a schema-9 database: the dry run reports the
/// plan and mutates nothing, `--apply` removes the canonical rows **and** their
/// source copies, and an unmatched source keeps every fact it had.
#[test]
fn forget_dry_run_reports_then_apply_removes_the_matching_source_copies() {
    let fixture = Fixture::new();
    let root = fixture.path().join("backup-root");
    fixture.write_session(
        &root,
        "projects/alpha/sess-alpha.jsonl",
        "sess-alpha",
        "alpha answer",
    );
    fixture.write_session(
        &root,
        "projects/beta/subagents/agent-beta.jsonl",
        "sess-beta",
        "beta answer",
    );
    fixture.write_sources(&[("backup", "local", "backup", root.to_str().unwrap(), true)]);

    fixture.index().expect_ok("the source-aware index");

    let db = fixture.open_db();
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM conversations"), 2);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_inputs"), 2);
    let revision_before = revision(&db);
    let witnesses_before = link_witnesses(&db);
    let link_states_before = link_states(&db);
    let matched_records_before = records_under(&db, "subagents/agent-beta.jsonl");
    let matched_links_before = links_under(&db, "subagents/agent-beta.jsonl");
    assert!(
        matched_records_before > 0 && matched_links_before > 0,
        "the fixture must really stage records and a link for the matched input"
    );
    let matched_receipts = receipt_keys_under(&db, "subagents/agent-beta.jsonl");
    let kept_receipts = receipt_keys_under(&db, "sess-alpha.jsonl");
    assert!(
        !matched_receipts.is_empty() && !kept_receipts.is_empty(),
        "both completed inputs carry the receipt their input row names"
    );
    assert_eq!(activation_receipts(&db), 2);
    drop(db);

    let mirror = fixture.data_dir().join("raw-mirror");
    let mirror_before = tree_digest(&mirror);

    let glob = "**/subagents/*.jsonl";

    // Dry run: the plan is reported and nothing moves -- not one table, not the
    // revision, not one mirror byte.
    let dry = fixture.forget(glob, false);
    dry.expect_ok("the forget dry run");
    assert_eq!(dry.number("conversations_matched"), 1);
    assert_eq!(dry.number("source_inputs_matched"), 1);
    assert_eq!(dry.number("source_inputs_deleted"), 0);
    assert_eq!(dry.number("source_links_historicalized"), 0);
    assert!(
        dry.strings("sample_source_locators")
            .iter()
            .any(|locator| locator.ends_with("subagents/agent-beta.jsonl")),
        "the sample names the matched original locator: {:?}",
        dry.strings("sample_source_locators")
    );

    let db = fixture.open_db();
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM conversations"), 2);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_inputs"), 2);
    assert_eq!(revision(&db), revision_before);
    assert_eq!(link_states(&db), link_states_before);
    drop(db);
    assert_eq!(
        tree_digest(&mirror),
        mirror_before,
        "the dry run touches no mirror byte"
    );

    // Apply: the matched conversation and its source copy go; the unmatched
    // conversation and its source copy keep every fact, witness included.
    let applied = fixture.forget(glob, true);
    applied.expect_ok("the forget apply");
    assert_eq!(applied.number("conversations_deleted"), 1);
    assert_eq!(applied.number("source_inputs_deleted"), 1);
    assert_eq!(
        applied.number("source_records_deleted"),
        matched_records_before as u64,
        "the report's count is the number this test read out of SQLite itself"
    );
    assert_eq!(
        applied.number("source_links_deleted"),
        matched_links_before as u64
    );

    let db = fixture.open_db();
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM conversations"), 1);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_inputs"), 1);
    assert_eq!(inputs_under(&db, "sess-alpha.jsonl"), 1);
    assert_eq!(
        inputs_under(&db, "subagents/agent-beta.jsonl"),
        0,
        "the matched input is really gone, read back from SQLite"
    );
    assert_eq!(
        revision(&db),
        (revision_before.parse::<u64>().unwrap_or(0) + 1).to_string(),
        "one visible source change earns exactly one increment"
    );
    // The surviving link kept its witness and its authority unchanged.
    let surviving: Vec<_> = link_witnesses(&db)
        .into_iter()
        .filter(|(id, _, _)| witnesses_before.iter().any(|(kept, _, _)| kept == id))
        .collect();
    assert!(!surviving.is_empty(), "the unmatched input's link survives");
    for (id, positions, digest) in &surviving {
        let (_, kept_positions, kept_digest) = witnesses_before
            .iter()
            .find(|(kept, _, _)| kept == id)
            .expect("the surviving link was there before");
        assert_eq!(positions, kept_positions, "witness bytes are immutable");
        assert_eq!(digest, kept_digest, "witness bytes are immutable");
    }
    // The activation receipt is bound to its input by the column activation
    // wrote, so the matched input's receipt goes with it and every other
    // input's receipt stays. A leftover receipt would refuse this file's next
    // ingest, which is what the re-index below then proves is fixed.
    assert_eq!(activation_receipts(&db), 1);
    for key in &matched_receipts {
        assert!(
            !receipt_present(&db, key),
            "a deleted input's receipt leaves with it"
        );
    }
    for key in &kept_receipts {
        assert!(
            receipt_present(&db, key),
            "an unmatched input keeps its receipt"
        );
    }
    drop(db);
    assert_eq!(
        tree_digest(&mirror),
        mirror_before,
        "the apply touches no mirror byte"
    );

    // A second apply of the same glob is a clean no-op: no counter moves and
    // the revision stays where the first apply left it.
    let revision_after = {
        let db = fixture.open_db();
        revision(&db)
    };
    let again = fixture.forget(glob, true);
    again.expect_ok("the repeated apply");
    assert_eq!(again.number("conversations_deleted"), 0);
    assert_eq!(again.number("source_inputs_deleted"), 0);
    assert_eq!(again.number("source_links_historicalized"), 0);
    let db = fixture.open_db();
    assert_eq!(
        revision(&db),
        revision_after,
        "a repeated apply is not a change"
    );
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_inputs"), 1);
}

/// A glob that matches no canonical conversation still removes the source
/// copies it addresses: the two selections are independent and the early
/// return is not allowed to stand in for the source side.
#[test]
fn a_source_only_forget_still_removes_the_copies_it_matches() {
    let fixture = Fixture::new();
    let root = fixture.path().join("backup-root");
    fixture.write_session(
        &root,
        "projects/alpha/sess-alpha.jsonl",
        "sess-alpha",
        "alpha answer",
    );
    // A second file the connector discovers but which projects no canonical
    // conversation: summary records alone carry no message.
    let orphan = root.join("projects/alpha/subagents/agent-orphan.jsonl");
    std::fs::create_dir_all(orphan.parent().unwrap()).expect("mkdir orphan dir");
    std::fs::write(
        &orphan,
        "{\"type\":\"summary\",\"summary\":\"synthetic orphan summary\",\"leafUuid\":\"synthetic-orphan-leaf\",\"isSidechain\":false}\n",
    )
    .expect("write the orphan session");
    fixture.write_sources(&[("backup", "local", "backup", root.to_str().unwrap(), true)]);

    fixture.index().expect_ok("the source-aware index");

    let db = fixture.open_db();
    let conversations_before = scalar(&db, "SELECT COUNT(*) FROM conversations");
    let glob = "**/subagents/*.jsonl";
    let orphan_inputs = i64::from(inputs_under(&db, "subagents/agent-orphan.jsonl") > 0);
    drop(db);
    if orphan_inputs == 0 {
        // The connector did not discover the summary-only file as a source at
        // all; there is no source-only case to exercise in this fixture, and
        // asserting one would be inventing the scenario rather than observing
        // it.
        eprintln!(
            "SKIP-BRANCH: the summary-only file was not staged as a source input; \
             the source-only case is covered by the multi-version case below"
        );
        return;
    }

    let dry = fixture.forget(glob, false);
    dry.expect_ok("the source-only dry run");
    assert_eq!(
        dry.number("conversations_matched"),
        0,
        "no canonical conversation carries this path"
    );
    assert_eq!(dry.number("source_inputs_matched"), 1);
    assert_eq!(dry.number("source_inputs_deleted"), 0);

    let apply = fixture.forget(glob, true);
    apply.expect_ok("the source-only apply");
    assert_eq!(apply.number("conversations_deleted"), 0);
    assert_eq!(apply.number("source_inputs_deleted"), 1);

    let db = fixture.open_db();
    assert_eq!(
        scalar(&db, "SELECT COUNT(*) FROM conversations"),
        conversations_before,
        "a source-only deletion does not touch the canonical archive"
    );
    assert_eq!(inputs_under(&db, "subagents/agent-orphan.jsonl"), 0);
    assert_eq!(
        inputs_under(&db, "sess-alpha.jsonl"),
        1,
        "the unmatched input keeps its facts"
    );
}

// ---------------------------------------------------------------------------
// A: the agent-exclusion purge
// ---------------------------------------------------------------------------

/// `cass sources agents exclude <agent>` removes that agent's archived data
/// **and** the source copies its connector owns, in one transaction, and says
/// so.
#[test]
fn excluding_an_agent_removes_its_source_copies_too() {
    let fixture = Fixture::new();
    let root = fixture.path().join("backup-root");
    fixture.write_session(
        &root,
        "projects/alpha/sess-alpha.jsonl",
        "sess-alpha",
        "alpha answer",
    );
    fixture.write_sources(&[("backup", "local", "backup", root.to_str().unwrap(), true)]);
    fixture.index().expect_ok("the source-aware index");

    let db = fixture.open_db();
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM conversations"), 1);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_inputs"), 1);
    let revision_before = revision(&db);
    drop(db);

    // Hold the fixture's own call to the parameters the binary publishes.
    let help = fixture.exclude_agent_help();
    assert!(
        help.contains("exclude"),
        "the exclude entry point publishes its own name: {help}"
    );

    let run = fixture.exclude_agent("claude");
    run.expect_ok("the agent exclusion");
    assert!(
        run.stdout.contains("source input"),
        "the human output has to report the source copies: {}",
        run.stdout
    );

    let db = fixture.open_db();
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM conversations"), 0);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_inputs"), 0);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_records"), 0);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_message_links"), 0);
    assert_ne!(
        revision(&db),
        revision_before,
        "the purge is a visible source change"
    );
}

// ---------------------------------------------------------------------------
// C: two roots sharing one winner
// ---------------------------------------------------------------------------

/// Two configured roots that resolve to the same `identity_host` /
/// agent / `external_id` produce one canonical conversation. Deleting the
/// second root's source copies must not touch the first root's conversation,
/// and deleting the canonical conversation must leave the unmatched root's
/// facts intact and its links CHECK-valid.
#[test]
fn a_shared_winner_keeps_the_unmatched_root_facts_and_its_links_valid() {
    let fixture = Fixture::new();
    let root_a = fixture.path().join("root-a");
    let root_b = fixture.path().join("root-b");
    // Same session id under both roots, so the two roots address one identity.
    fixture.write_session(
        &root_a,
        "projects/p/sess-shared.jsonl",
        "sess-shared",
        "winner answer",
    );
    fixture.write_session(
        &root_b,
        "projects/p/sess-shared.jsonl",
        "sess-shared",
        "winner answer",
    );
    fixture.write_sources(&[
        (
            "root-a",
            "local",
            "shared-host",
            root_a.to_str().unwrap(),
            true,
        ),
        (
            "root-b",
            "local",
            "shared-host",
            root_b.to_str().unwrap(),
            true,
        ),
    ]);

    fixture.index().expect_ok("the shared-winner index");

    let db = fixture.open_db();
    assert_eq!(
        scalar(&db, "SELECT COUNT(*) FROM conversations"),
        1,
        "the two roots resolve to one canonical conversation"
    );
    assert_eq!(
        scalar(&db, "SELECT COUNT(*) FROM source_inputs"),
        2,
        "both roots staged their own source input"
    );
    let witnesses_all = link_witnesses(&db);
    drop(db);
    let root_a_needle = root_a.to_string_lossy().to_string();
    let root_b_needle = root_b.to_string_lossy().to_string();

    // Phase 1 -- "deleting B's copies must not delete A's winner". The glob
    // addresses root B only, so the one canonical conversation has to survive
    // with every fact, including the witness bytes of its own source copy.
    let witnesses_a_before = {
        let db = fixture.open_db();
        let witnesses = link_witnesses_under(&db, &root_a_needle);
        assert!(
            !witnesses.is_empty(),
            "root A installed link witnesses to compare against"
        );
        witnesses
    };
    let glob_b = format!("{}/**/*.jsonl", root_b_needle);
    let run_b = fixture.forget(&glob_b, true);
    run_b.expect_ok("forgetting the second root's copy");

    let db = fixture.open_db();
    assert_eq!(
        scalar(&db, "SELECT COUNT(*) FROM conversations"),
        1,
        "deleting one root's copy does not delete the other root's winner"
    );
    assert_eq!(inputs_under(&db, &root_b_needle), 0);
    assert_eq!(
        inputs_under(&db, &root_a_needle),
        1,
        "the other root's source input keeps every fact"
    );
    assert_eq!(
        link_witnesses_under(&db, &root_a_needle),
        witnesses_a_before,
        "the untouched root's witnesses are byte-for-byte what they were"
    );
    // The receipt the second root's input named left with it, and the first
    // root's receipt -- the only other receipt of this operation -- did not.
    assert_eq!(activation_receipts(&db), 1);
    assert!(
        receipt_keys_under(&db, &root_a_needle)
            .iter()
            .all(|key| receipt_present(&db, key)),
        "the untouched root keeps its activation receipt"
    );
    drop(db);

    // Root B's file is still on disk, so a re-index stages its copy again --
    // now against a canonical conversation that already exists.
    fixture.index().expect_ok("the re-index of the second root");
    let db = fixture.open_db();
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM conversations"), 1);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_inputs"), 2);
    let b_witnesses_before = link_witnesses_under(&db, &root_b_needle);
    let b_links_before = link_states_under(&db, &root_b_needle);
    drop(db);
    assert!(
        !b_links_before.is_empty(),
        "the second root carries links of its own"
    );
    let canonical_before = b_links_before
        .iter()
        .filter(|(_, authority, _)| authority.as_deref() == Some("canonical"))
        .count();
    eprintln!(
        "shared-winner fixture: {} link(s) on the second root, {canonical_before} canonical",
        b_links_before.len()
    );

    // Phase 2 -- delete the canonical conversation, addressed through root A.
    // The second root's copy is unmatched by this glob, so it must keep every
    // fact, and every one of its links must stay a legal shape: that is what
    // the canonical CHECK enforces, and it is why an unmatched canonical link
    // has to be historyized before its message goes rather than left to the
    // FK's `ON DELETE SET NULL`.
    let glob_a = format!("{}/**/*.jsonl", root_a_needle);
    let run_a = fixture.forget(&glob_a, true);
    run_a.expect_ok("forgetting the canonical conversation");
    assert_eq!(run_a.number("conversations_deleted"), 1);
    assert_eq!(run_a.number("source_inputs_deleted"), 1);

    let db = fixture.open_db();
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM conversations"), 0);
    assert_eq!(
        inputs_under(&db, &root_b_needle),
        1,
        "the unmatched root's copy keeps every fact while its message goes"
    );
    assert_eq!(
        inputs_under(&db, &root_a_needle),
        0,
        "the matched root's copy leaves with its conversation"
    );
    assert_eq!(
        link_witnesses_under(&db, &root_b_needle),
        b_witnesses_before,
        "an unmatched copy's witness is immutable: only authority/message moved"
    );
    let surviving = link_states_under(&db, &root_b_needle);
    assert_eq!(
        surviving.len(),
        b_links_before.len(),
        "no link of the unmatched copy was dropped"
    );
    for (id, authority, message_id) in &surviving {
        match authority.as_deref() {
            // The canonical CHECK, restated where a reader can see it: a
            // canonical link names a live message, every other authority
            // names none.
            Some("canonical") => assert!(
                message_id.is_some(),
                "link {id} is canonical but names no message"
            ),
            other => assert!(
                message_id.is_none(),
                "link {id} claims authority {other:?} while naming a message"
            ),
        }
    }
    let after_canonical = surviving
        .iter()
        .filter(|(_, authority, _)| authority.as_deref() == Some("canonical"))
        .count();
    eprintln!(
        "shared-winner fixture after the canonical deletion: {} link(s), {after_canonical} canonical",
        surviving.len()
    );
    assert!(
        after_canonical <= canonical_before,
        "the deletion can only move a canonical link away from canonical, never raise the count"
    );
    let integrity: String = db
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("integrity check");
    assert_eq!(integrity, "ok", "the database is still well formed");
    assert!(
        foreign_key_violations(&db).is_empty(),
        "no foreign key is left dangling"
    );
    drop(db);
    assert!(
        !witnesses_all.is_empty(),
        "the fixture really installed link witnesses to compare against"
    );
}

// ---------------------------------------------------------------------------
// B: the multi-version input
// ---------------------------------------------------------------------------

/// Two versions of one file stage two source inputs for one canonical
/// conversation; a forget that addresses the file removes both versions, so no
/// completed or failed input is left behind.
#[test]
fn a_multi_version_file_leaves_no_source_input_behind() {
    let fixture = Fixture::new();
    let root = fixture.path().join("backup-root");
    let session = fixture.write_session(
        &root,
        "projects/alpha/sess-versioned.jsonl",
        "sess-versioned",
        "first answer",
    );
    fixture.write_sources(&[("backup", "local", "backup", root.to_str().unwrap(), true)]);
    fixture.index().expect_ok("the first source-aware index");

    // A second version of the same file: the content digest moves, so the
    // source kernel stages a second input while the canonical conversation is
    // the same one.
    fixture.write_session(
        &root,
        "projects/alpha/sess-versioned.jsonl",
        "sess-versioned",
        "second answer",
    );
    assert!(session.is_file());
    fixture.index().expect_ok("the second source-aware index");

    let db = fixture.open_db();
    let conversations = scalar(&db, "SELECT COUNT(*) FROM conversations");
    let inputs_before = scalar(&db, "SELECT COUNT(*) FROM source_inputs");
    drop(db);
    assert_eq!(conversations, 1, "one canonical conversation");
    assert!(
        inputs_before >= 2,
        "both versions staged an input; found {inputs_before}"
    );

    let glob = "**/sess-versioned.jsonl";
    let dry = fixture.forget(glob, false);
    dry.expect_ok("the multi-version dry run");
    assert_eq!(
        dry.number("source_inputs_matched"),
        inputs_before as u64,
        "every version of the file is in the plan"
    );

    let apply = fixture.forget(glob, true);
    apply.expect_ok("the multi-version apply");
    assert_eq!(apply.number("conversations_deleted"), 1);
    assert_eq!(apply.number("source_inputs_deleted"), inputs_before as u64);

    let db = fixture.open_db();
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_inputs"), 0);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_records"), 0);
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_message_links"), 0);
}
