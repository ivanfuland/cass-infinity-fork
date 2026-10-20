//! SRC05B-09A acceptance: the explicit `--watch-once <path>` run under a fixed
//! safety configuration.
//!
//! Every case here drives the real `cass index` binary over a private synthetic
//! HOME, a private fixed safety copy and a private data directory, and then
//! reads the resulting SQLite database directly. The behaviour under test is
//! never reached through a library call: the seam is the CLI, the database, the
//! per-run JSON and the process boundary, which is what the ticket asks for.
//!
//! One fixture helper is internal, and it is the *pre-state* rather than the
//! behaviour: `util::source_legacy_seed` builds the conversation, watermark,
//! per-file state and raw-mirror capture an earlier, source-unaware run would
//! have left behind, so w6 no longer has to run the legacy entry point it is
//! migrating away from. The run under test is still a separate process.
//!
//! The fixtures are synthetic and neutral. No real session, path or secret
//! appears in this file.

mod util;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use coding_agent_search::indexer::scan_root_meta;
use rusqlite::OptionalExtension as _;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

/// The one line a source-aware commit writes from *inside* its writer closure.
///
/// It is the per-run proof that an input really travelled through the commit,
/// which is what separates "the run skipped the file" from "the run read it and
/// the database happened to be unchanged".
const DISPATCH_MARKER: &str = "source_input_dispatch";

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

    fn path(&self) -> &Path {
        self.root.path()
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

    /// Point every source-discovery environment at this fixture.
    ///
    /// The host running the tests may itself export these (a CI or control-plane
    /// machine commonly does), and an inherited value would let a fixture
    /// process scan the host's real history -- slow, and a privacy problem. The
    /// fixture therefore states every one of them explicitly rather than hoping
    /// the ambient environment is clean.
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
            .env_remove("CASS_TEST_WATCH_PATHS")
            .env_remove("CASS_SRC05B07_FAIL_AT")
            .env_remove("RUST_LOG");
        cmd
    }

    /// Write a Claude Code session at `relative` under this fixture's HOME.
    fn write_claude_session(&self, relative: &str, lines: &[serde_json::Value]) -> PathBuf {
        let path = self.home().join(".claude/projects").join(relative);
        std::fs::create_dir_all(path.parent().expect("session parent")).expect("mkdir session dir");
        std::fs::write(&path, jsonl(lines)).expect("write claude session");
        path
    }

    /// Write a Codex rollout at `relative` under this fixture's HOME.
    fn write_codex_session(&self, relative: &str, lines: &[serde_json::Value]) -> PathBuf {
        let path = self.home().join(".codex/sessions").join(relative);
        std::fs::create_dir_all(path.parent().expect("rollout parent")).expect("mkdir rollout dir");
        std::fs::write(&path, jsonl(lines)).expect("write codex rollout");
        path
    }

    /// One explicit `--watch-once <path>` run of the source-aware path.
    fn watch_once(&self, paths: &[&Path]) -> Run {
        self.watch_once_with(paths, &[])
    }

    /// One explicit `--watch-once <path>` run with extra environment.
    fn watch_once_with(&self, paths: &[&Path], envs: &[(&str, &str)]) -> Run {
        let mut cmd = Command::new(cass_bin());
        for (key, value) in envs {
            cmd.env(key, value);
        }
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .arg("--source-safety-config")
            .arg(self.fixed_copy())
            .args(["--json", "--verbose"]);
        for path in paths {
            cmd.arg("--watch-once").arg(path);
        }
        Run::from(cmd.output().expect("spawn cass index"))
    }

    /// The one-shot source scan: every declared root, no explicit selection.
    /// Its identity is the one an explicit selection has to agree with.
    fn source_index_all(&self) -> Run {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.env("CASS_DATA_DIR", self.data_dir());
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .arg("--source-safety-config")
            .arg(self.fixed_copy())
            .args(["--json", "--verbose"]);
        Run::from(cmd.output().expect("spawn cass index"))
    }

    /// One `sources.toml` declaring several local roots, each with its own
    /// origin host, so two declarations of one path -- or of nested paths --
    /// are distinguishable by namespace.
    fn write_configured_sources(&self, sources: &[(&str, &str, &Path)]) {
        let dir = self.config_home().join("cass");
        std::fs::create_dir_all(&dir).expect("mkdir cass config");
        let mut body = String::new();
        for (name, origin_host, root) in sources {
            body.push_str("[[sources]]\n");
            body.push_str(&format!("name = \"{name}\"\n"));
            body.push_str("type = \"local\"\n");
            body.push_str(&format!("origin_host = \"{origin_host}\"\n"));
            body.push_str(&format!("paths = [\"{}\"]\n\n", root.display()));
        }
        std::fs::write(dir.join("sources.toml"), body).expect("write sources.toml");
    }

    /// One `sources.toml` declaring a local root with non-default origin
    /// metadata and a path mapping, so a configured root's identity is
    /// distinguishable from a home root's.
    fn write_configured_source(&self, name: &str, origin_host: &str, root: &Path) {
        let dir = self.config_home().join("cass");
        std::fs::create_dir_all(&dir).expect("mkdir cass config");
        std::fs::write(
            dir.join("sources.toml"),
            format!(
                "[[sources]]\nname = \"{name}\"\ntype = \"local\"\n\
                 origin_host = \"{origin_host}\"\n\
                 paths = [\"{}\"]\n\
                 path_mappings = [{{ from = \"/synthetic-old\", to = \"/synthetic-new\" }}]\n",
                root.display()
            ),
        )
        .expect("write sources.toml");
    }

    /// One `--watch-once <path>` run **without** the explicit-copy flag.
    /// Task 19: such a run prepares the default fixed configuration, so it
    /// travels through the source writer rather than the legacy path.
    fn watch_once_legacy(&self, paths: &[&Path]) -> Run {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .args(["--json", "--verbose"]);
        for path in paths {
            cmd.arg("--watch-once").arg(path);
        }
        Run::from(cmd.output().expect("spawn cass index"))
    }

    /// The resident loop's own entry point. SRC05B-09B migrated its event
    /// cycle, so it now starts rather than refusing; this helper is bounded
    /// because an accepted `--watch` never returns on its own, and it is kept
    /// short so a case can show the loop is running without stalling the suite.
    fn resident_watch(&self) -> Run {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .arg("--source-safety-config")
            .arg(self.fixed_copy())
            .args(["--watch", "--watch-interval", "1", "--json", "--verbose"]);
        Run::from_bounded(cmd, Duration::from_secs(60))
    }

    fn search(&self, query: &str) -> std::process::Output {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.args([
            "search",
            query,
            "--data-dir",
            self.data_dir().to_str().expect("utf-8 data dir"),
            "--json",
            "--rrf-limit",
            "5",
        ]);
        cmd.output().expect("spawn cass search")
    }

    fn open_db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(
            self.db(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open the database read-only")
    }

    /// Rewrite the fixed safety copy with one extra excluded document, so its
    /// bytes and therefore its safety-contract identity change.
    fn change_fixed_copy(&self) {
        let text = std::fs::read_to_string(self.fixed_copy()).expect("read the fixed copy");
        std::fs::write(
            self.fixed_copy(),
            text.replace(
                "project_read_documents = [\"exec\"",
                "project_read_documents = [\"extra_document\", \"exec\"",
            ),
        )
        .expect("rewrite the fixed copy");
    }

    fn watch_state_path(&self) -> PathBuf {
        self.data_dir().join("watch_state.json")
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

/// One `cass index` run's observable result.
struct Run {
    code: Option<i32>,
    payload: Option<serde_json::Value>,
    stderr: String,
}

impl From<std::process::Output> for Run {
    fn from(output: std::process::Output) -> Self {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Self {
            code: output.status.code(),
            payload: serde_json::from_str::<serde_json::Value>(&stdout).ok(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }
}

impl Run {
    /// Run a command that is expected to finish, and refuse to hang if a
    /// regression lets the resident watch loop start.
    fn from_bounded(mut cmd: Command, limit: Duration) -> Self {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = cmd.spawn().expect("spawn cass");
        match wait_bounded(child, limit) {
            Some(output) => Self::from(output),
            None => Self {
                code: None,
                payload: None,
                stderr: format!("the process was still running after {limit:?}"),
            },
        }
    }

    fn expect_success(&self, what: &str) {
        assert_eq!(self.code, Some(0), "{what} must succeed; stderr={}", self.stderr);
    }

    fn expect_failure(&self, what: &str) {
        let code = self.code.unwrap_or_else(|| {
            panic!("{what} must exit on its own, and it did not: {}", self.stderr)
        });
        assert_ne!(code, 0, "{what} must fail; stderr={}", self.stderr);
    }

    /// How many inputs this run carried into a source-aware commit.
    fn dispatches(&self) -> usize {
        self.stderr.matches(DISPATCH_MARKER).count()
    }

    /// What this run's own `--json` reports as committed, when it reported.
    fn source_inputs_committed(&self) -> Option<u64> {
        self.payload
            .as_ref()
            .and_then(|payload| payload["indexing_stats"]["source_inputs_committed"].as_u64())
    }
}

/// Wait for a child with a deadline, killing it if the deadline passes.
fn wait_bounded(mut child: Child, limit: Duration) -> Option<std::process::Output> {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait().expect("poll the child") {
            Some(_) => return child.wait_with_output().ok(),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
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
// Database readers
// ---------------------------------------------------------------------------

fn count(db: &rusqlite::Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("{sql}: {error}"))
}

/// One text column, top to bottom.
fn string_column(db: &rusqlite::Connection, sql: &str) -> Vec<String> {
    let mut stmt = db.prepare(sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap_or_else(|error| panic!("{sql}: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
    rows
}

/// One `_bin` blob column, decoded as the text it carries.
fn blob_column(db: &rusqlite::Connection, sql: &str) -> Vec<String> {
    let mut stmt = db.prepare(sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
    let rows: Vec<Vec<u8>> = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap_or_else(|error| panic!("{sql}: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
    rows.into_iter()
        .map(|bytes| String::from_utf8(bytes).expect("a utf-8 text column"))
        .collect()
}

/// The `relative_locator` of every registered source input, sorted.
fn input_locators(db: &rusqlite::Connection) -> Vec<String> {
    let mut locators = blob_column(
        db,
        "SELECT relative_locator_bin FROM source_inputs ORDER BY relative_locator_bin",
    );
    locators.sort();
    locators
}

/// One input's state, looked up by the locator the selection produced.
fn input_state_for(db: &rusqlite::Connection, locator: &str) -> Option<String> {
    db.query_row(
        "SELECT state FROM source_inputs WHERE relative_locator_bin = ?1",
        [locator.as_bytes()],
        |row| row.get(0),
    )
    .optional()
    .unwrap_or_else(|error| panic!("reading the state of {locator}: {error}"))
}

/// Every committed receipt's idempotency key, in order: the proof that no
/// activation was rewritten or fabricated.
fn receipt_keys(db: &rusqlite::Connection) -> String {
    db.query_row(
        "SELECT group_concat(idempotency_key, '|') FROM operation_commit_receipt",
        [],
        |row| row.get(0),
    )
    .expect("read the receipt keys")
}

/// The source facts that must not move on a replay.
fn source_snapshot(db: &rusqlite::Connection) -> (i64, i64, i64, String, String) {
    (
        count(db, "SELECT COUNT(*) FROM source_inputs"),
        count(db, "SELECT COUNT(*) FROM source_records"),
        count(db, "SELECT COUNT(*) FROM messages"),
        db.query_row(
            "SELECT value FROM meta WHERE key = 'source_facts_revision'",
            [],
            |row| row.get(0),
        )
        .optional()
        .expect("read the source facts revision")
        .unwrap_or_else(|| "<absent>".to_string()),
        receipt_keys(db),
    )
}

const CLAUDE_PHRASE: &str = "synthetic claude landing phrase";
const CODEX_PHRASE: &str = "synthetic codex landing phrase";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Every source fact this database holds, as comparable lines.
///
/// Identity material comes first -- the input key, the declared scan root, the
/// relative locator, the parser-context digest, the namespace and the origin
/// host -- so a change no row count would show still fails the comparison.
/// Then the rows, the revision and the receipts.
fn source_facts_fingerprint(db: &rusqlite::Connection) -> Vec<String> {
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
        db.query_row(
            "SELECT value FROM meta WHERE key = 'source_facts_revision'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .expect("read the source facts revision")
        .unwrap_or_else(|| "<absent>".to_string())
    ));
    lines.push(format!("receipts={}", receipt_keys(db)));
    lines
}

/// Every fingerprint line whose locator ends with `suffix`, in order.
///
/// One file can carry more than one input: a configured root is planned for
/// every connector, so both the connectors that can discover the file read it
/// -- exactly as the one-shot source scan reads it. What must not happen is a
/// *second identity for the same pairing*, which is what comparing these lines
/// across entry points catches.
fn fingerprint_lines_ending(lines: &[String], suffix: &str) -> Vec<String> {
    lines
        .iter()
        .filter(|line| line.contains("locator=") && line.contains(suffix))
        .cloned()
        .collect()
}

/// Every fingerprint line whose declared root is exactly `root`.
fn fingerprint_lines_rooted_at(lines: &[String], root: &Path) -> Vec<String> {
    let field = format!(
        "root={} locator=",
        std::fs::canonicalize(root)
            .unwrap_or_else(|_| root.to_path_buf())
            .display()
    );
    lines
        .iter()
        .filter(|line| line.contains(&field))
        .cloned()
        .collect()
}

/// The one fingerprint line whose locator ends with `suffix`.
fn fingerprint_line_ending(lines: &[String], suffix: &str) -> String {
    let matches = fingerprint_lines_ending(lines, suffix);
    assert_eq!(
        matches.len(),
        1,
        "exactly one input must carry the locator {suffix}: {lines:#?}"
    );
    matches[0].clone()
}

// ---------------------------------------------------------------------------
// W1: the selected paths land as real source facts, and nothing else does
// ---------------------------------------------------------------------------

#[test]
fn w1_explicit_watch_once_paths_land_as_source_facts() {
    let fixture = Fixture::new();
    let claude = fixture.write_claude_session(
        "w1/session.jsonl",
        &claude_session("sess-w1-claude", "what landed", CLAUDE_PHRASE),
    );
    // A sibling in the very directory the selected file's scan root is built
    // on: discovery sees it, the selection must not carry it into the database.
    let _sibling = fixture.write_claude_session(
        "w1/unselected.jsonl",
        &claude_session("sess-w1-unselected", "not selected", "unselected body"),
    );
    let codex = fixture.write_codex_session(
        "2026/01/rollout-2026-01-01T00-00-00-w1.jsonl",
        &codex_session("sess-w1-codex", "what landed", CODEX_PHRASE),
    );

    let run = fixture.watch_once(&[&claude, &codex]);
    run.expect_success("an explicit source watch-once run");
    assert_eq!(
        run.source_inputs_committed(),
        Some(2),
        "the run's own JSON reports both inputs committed: {}",
        run.stderr
    );

    let db = fixture.open_db();
    assert_eq!(
        input_locators(&db),
        vec![
            "2026/01/rollout-2026-01-01T00-00-00-w1.jsonl".to_string(),
            "w1/session.jsonl".to_string(),
        ],
        "exactly the two selected files have inputs, measured from their declared home \
         roots; the sibling has none"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'"
        ),
        2,
        "both selected inputs completed"
    );
    assert!(
        count(&db, "SELECT COUNT(*) FROM source_records") >= 5,
        "the selected files' records were staged"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_records WHERE frame_state <> 'activated'"
        ),
        0,
        "every frame of a complete input is activated"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM operation_commit_receipt
             WHERE operation = 'source_input_activation_v1' AND state = 'committed'"
        ),
        2,
        "each activation writes its own receipt"
    );
    assert!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_message_links
             WHERE authority = 'canonical' AND message_id IS NOT NULL"
        ) > 0,
        "the inputs' links bind real canonical messages"
    );
    assert!(
        !input_locators(&db)
            .iter()
            .any(|locator| locator.ends_with("unselected.jsonl")),
        "the unselected sibling never became an input"
    );

    // The canonical body is real, and the lexical end can recall it.
    let answers = string_column(&db, "SELECT content FROM messages ORDER BY id");
    assert!(
        answers.iter().any(|text| text.contains(CLAUDE_PHRASE)),
        "the canonical store holds the Claude body: {answers:?}"
    );
    assert!(
        answers.iter().any(|text| text.contains(CODEX_PHRASE)),
        "the canonical store holds the Codex body: {answers:?}"
    );
    let search = fixture.search("landing");
    assert_eq!(
        search.status.code(),
        Some(0),
        "a lexical query over the freshly written canonical store must succeed; stderr={}",
        String::from_utf8_lossy(&search.stderr)
    );
    let stdout = String::from_utf8_lossy(&search.stdout);
    assert!(
        stdout.contains(CLAUDE_PHRASE),
        "the lexical end recalls the Claude body: {stdout}"
    );
    assert!(
        stdout.contains(CODEX_PHRASE),
        "the lexical end recalls the Codex body: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// W2: a replay of the same bytes adds nothing and keeps the revision
// ---------------------------------------------------------------------------

#[test]
fn w2_a_replayed_input_adds_nothing_and_keeps_the_revision() {
    let fixture = Fixture::new();
    let claude = fixture.write_claude_session(
        "w2/session.jsonl",
        &claude_session("sess-w2", "a question", "a replayable answer"),
    );

    let first = fixture.watch_once(&[&claude]);
    first.expect_success("the first source watch-once run");
    assert!(
        first.dispatches() > 0,
        "the first run read the selected file through the commit: {}",
        first.stderr
    );
    let before = source_snapshot(&fixture.open_db());

    let second = fixture.watch_once(&[&claude]);
    second.expect_success("a replay is a success with zero new work");
    assert!(
        second.dispatches() > 0,
        "the second run read the file again instead of skipping it: {}",
        second.stderr
    );

    let after = source_snapshot(&fixture.open_db());
    assert_eq!(before, after, "a replay must not add or move any fact");
}

// ---------------------------------------------------------------------------
// W3: a changed input is a new identity
// ---------------------------------------------------------------------------

#[test]
fn w3_a_changed_input_gets_a_new_identity() {
    let fixture = Fixture::new();
    let mut lines = claude_session("sess-w3", "the first question", "the first answer");
    let session = fixture.write_claude_session("w3/session.jsonl", &lines);

    fixture
        .watch_once(&[&session])
        .expect_success("the first source watch-once run");
    let before = source_snapshot(&fixture.open_db());

    lines.extend(claude_session("sess-w3", "the second question", "the second answer"));
    std::fs::write(&session, jsonl(&lines)).expect("append to the session");

    fixture
        .watch_once(&[&session])
        .expect_success("the changed input is read again");

    let db = fixture.open_db();
    let after = source_snapshot(&db);
    assert_eq!(
        after.0,
        before.0 + 1,
        "the changed bytes are a new input, not a rewrite of the old one"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'"
        ),
        2,
        "both the original and the new identity are complete"
    );
    assert!(
        after.2 > before.2,
        "the appended turn landed as new canonical messages ({} -> {})",
        before.2,
        after.2
    );
}

// ---------------------------------------------------------------------------
// W4: a legal empty file is a complete input
// ---------------------------------------------------------------------------

#[test]
fn w4_an_empty_selected_file_completes_without_inventing_a_conversation() {
    let fixture = Fixture::new();
    let dir = fixture.home().join(".claude/projects/w4");
    std::fs::create_dir_all(&dir).expect("mkdir the project dir");
    let empty = dir.join("empty.jsonl");
    std::fs::write(&empty, "").expect("write the empty session");

    let run = fixture.watch_once(&[&empty]);
    run.expect_success("an empty selected file is read, not refused");

    let db = fixture.open_db();
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM source_inputs"),
        1,
        "the empty file registered one input"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'"),
        1,
        "an empty file reaches EOF and completes"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM source_records"),
        0,
        "an empty file has no records"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM conversations"),
        0,
        "an empty file invents no conversation"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM operation_commit_receipt
             WHERE operation = 'source_input_activation_v1' AND state = 'committed'"
        ),
        1,
        "the zero-record activation still writes its receipt"
    );
}

// ---------------------------------------------------------------------------
// W5: a faulty input fails the run, keeps the old facts, and a repair succeeds
// ---------------------------------------------------------------------------

#[test]
fn w5_a_faulty_input_fails_the_run_and_the_repaired_file_succeeds() {
    let fixture = Fixture::new();
    let good = fixture.write_claude_session(
        "w5/good.jsonl",
        &claude_session("sess-w5-good", "a good question", "a good answer"),
    );
    let broken_lines = codex_session("sess-w5-broken", "a broken question", "a broken answer");
    let broken = fixture.home().join(".codex/sessions/2026/01/rollout-w5-broken.jsonl");
    std::fs::create_dir_all(broken.parent().expect("rollout parent")).expect("mkdir rollout dir");
    // One line the framing scan cannot parse at all: the input can only be
    // published partial, which is a non-success the run must not report as
    // done.
    std::fs::write(&broken, format!("{}not a json record\n", jsonl(&broken_lines)))
        .expect("write the faulty rollout");

    fixture
        .watch_once(&[&good])
        .expect_success("the good input lands on its own");
    let before = {
        let db = fixture.open_db();
        (
            count(&db, "SELECT COUNT(*) FROM messages"),
            count(&db, "SELECT COUNT(*) FROM conversations"),
            receipt_keys(&db),
        )
    };
    assert!(
        !fixture.watch_state_path().exists(),
        "an explicit watch-once run writes no persistent watch state"
    );

    let failed = fixture.watch_once(&[&good, &broken]);
    failed.expect_failure("a faulty input must fail the run");
    assert!(
        failed.stderr.contains("did not land"),
        "the failure names the input that did not land: {}",
        failed.stderr
    );
    assert!(
        failed.stderr.contains("rollout-w5-broken.jsonl"),
        "the failure names the faulty file: {}",
        failed.stderr
    );

    let db = fixture.open_db();
    // The pre-existing facts survive: the good input's receipt is the very one
    // run 1 wrote, and nothing the good input landed was removed. A partial
    // input installs the records it *could* read -- the kernel's own published
    // semantics for an unfinished input -- so the canonical counts may only
    // grow here, and the unfinished input is never reported as a completed one.
    assert_eq!(
        receipt_keys(&db),
        before.2,
        "no receipt was rewritten or fabricated by the faulty run"
    );
    assert!(
        count(&db, "SELECT COUNT(*) FROM messages") >= before.0
            && count(&db, "SELECT COUNT(*) FROM conversations") >= before.1,
        "the faulty run removed no canonical fact ({} >= {}, {} >= {})",
        count(&db, "SELECT COUNT(*) FROM messages"),
        before.0,
        count(&db, "SELECT COUNT(*) FROM conversations"),
        before.1,
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_inputs WHERE connector = 'claude_code' \
             AND state = 'complete'"
        ),
        1,
        "the good input is still complete"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_inputs WHERE connector = 'codex' AND state = 'complete'"
        ),
        0,
        "the faulty input is not recorded as complete"
    );
    assert_ne!(
        input_state_for(&db, "2026/01/rollout-w5-broken.jsonl").as_deref(),
        Some("complete"),
        "the faulty input's own row is unfinished"
    );
    assert!(
        !fixture.watch_state_path().exists(),
        "a failed run writes no persistent watch state either"
    );

    // The repair: the same file, now a well-formed rollout, read by a fresh
    // process.
    let repaired = fixture.write_codex_session(
        "2026/01/rollout-w5-broken.jsonl",
        &codex_session("sess-w5-broken", "a repaired question", "a repaired answer"),
    );
    let healed = fixture.watch_once(&[&good, &broken]);
    healed.expect_success("the repaired file is read by a new process");
    assert_eq!(repaired, broken, "the repair rewrote the same selected path");

    let db = fixture.open_db();
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_inputs WHERE connector = 'codex' AND state = 'complete'"
        ),
        1,
        "the repaired input completed"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM operation_commit_receipt
             WHERE operation = 'source_input_activation_v1' AND state = 'committed'"
        ),
        2,
        "the repaired input wrote its own receipt next to the good one"
    );
}

// ---------------------------------------------------------------------------
// W6: existing legacy facts, and a changed safety identity, are never skipped
// ---------------------------------------------------------------------------

#[test]
fn w6_existing_legacy_facts_and_a_changed_safety_copy_are_never_skipped() {
    let fixture = Fixture::new();
    let session = fixture.write_claude_session(
        "w6/session.jsonl",
        &claude_session("sess-w6", "a legacy question", "a legacy answer"),
    );

    // The state the legacy skip is built on: the file has been covered before,
    // so it has a conversation, a settled watermark and an unchanged mtime.
    // None of that is a source fact, and none of it may skip the run. The
    // pre-state comes from public storage, raw-mirror and root-id primitives
    // (`util::source_legacy_seed`), not from the legacy entry point.
    let projects = fixture.home().join(".claude/projects");
    util::source_legacy_seed::seed_legacy_source_fixture(
        &fixture.data_dir(),
        &[util::source_legacy_seed::LegacySeedFile {
            connector: "claude",
            source_id: "local",
            root_id: &scan_root_meta::home_root_id(
                "claude",
                &scan_root_meta::canonicalize_root_path(&projects),
            ),
            root_path: &projects,
            source_path: &session,
        }],
    )
    .expect("seed the legacy pre-state");

    // The pre-state really is what the case is about: the canonical facts and
    // the capture are there, and not one source fact is.
    {
        let db = fixture.open_db();
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM conversations"),
            1,
            "the seed wrote a canonical conversation"
        );
        assert!(
            count(&db, "SELECT COUNT(*) FROM messages") > 0,
            "the seeded conversation carries messages"
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM scan_file_state"),
            1,
            "the file has its recorded per-file state"
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM source_inputs"),
            0,
            "no source input exists yet"
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM operation_commit_receipt
                 WHERE operation = 'source_input_activation_v1'"
            ),
            0,
            "and no source activation receipt"
        );
    }
    let seeded_manifests = util::source_legacy_seed::mirror_manifest_identities(&fixture.data_dir());
    assert_eq!(
        seeded_manifests,
        vec!["local".to_string()],
        "the seed captured the file into the raw mirror once"
    );
    assert_eq!(
        util::source_legacy_seed::mirror_blob_files(&fixture.data_dir()).len(),
        1,
        "and the mirror really holds the captured bytes"
    );

    let source = fixture.watch_once(&[&session]);
    source.expect_success("the source run must not skip a file with legacy facts");
    assert!(
        source.dispatches() > 0,
        "the source run read the file instead of skipping it: {}",
        source.stderr
    );

    let db = fixture.open_db();
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'"),
        1,
        "the input completed despite the pre-existing conversation"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM operation_commit_receipt
             WHERE operation = 'source_input_activation_v1' AND state = 'committed'"
        ),
        1,
        "and it wrote its receipt"
    );

    // A changed fixed safety copy is a changed safety identity: the same bytes
    // under a new contract are a new input, never a skip.
    fixture.change_fixed_copy();
    let changed = fixture.watch_once(&[&session]);
    changed.expect_success("the run under the new safety identity must proceed");
    assert!(
        changed.dispatches() > 0,
        "the run under the new safety identity read the file: {}",
        changed.stderr
    );

    let db = fixture.open_db();
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM source_inputs"),
        2,
        "the new safety identity registered its own input"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'"
        ),
        2,
        "both identities completed under their own contract"
    );
}

// ---------------------------------------------------------------------------
// W7: no persistent watch state, and the resident loop still refuses
// ---------------------------------------------------------------------------

#[test]
fn w7_watch_once_keeps_no_watch_state_and_the_resident_loop_now_starts() {
    let fixture = Fixture::new();
    let session = fixture.write_claude_session(
        "w7/session.jsonl",
        &claude_session("sess-w7", "a question", "an answer"),
    );

    fixture
        .watch_once(&[&session])
        .expect_success("the source watch-once run");
    assert!(
        !fixture.watch_state_path().exists(),
        "an explicit watch-once run advances no persistent watch watermark"
    );
    assert_eq!(
        count(&fixture.open_db(), "SELECT COUNT(*) FROM scan_watermarks"),
        0,
        "and it writes no (root, connector) watermark row"
    );

    // SRC05B-09B migrated the resident event cycle, so this run no longer
    // refuses. The sub-assertion that used to stand here -- "resident watch
    // under a safety configuration must fail with a refusal naming resident
    // watch" -- is obsolete because the entry point it described is now
    // covered; what it protected (no run claims source completeness while
    // reading through the legacy path) is carried by
    // `tests/source_resident_watch.rs`, which drives this same entry point and
    // asserts the facts it lands. What remains true, and is asserted here, is
    // that the loop now really starts instead of exiting: a bounded run that
    // ends on its own is the old refusal coming back.
    let watch = fixture.resident_watch();
    assert!(
        watch.code.is_none(),
        "the resident watch loop must run rather than refuse: {}",
        watch.stderr
    );
}

// ---------------------------------------------------------------------------
// W8: watch-once without the flag uses the source writer
// ---------------------------------------------------------------------------

/// Task 19: without an explicit copy the run now prepares the default fixed
/// configuration, so the same explicit watch-once run travels through the
/// source writer instead of the legacy conversation path.
#[test]
fn w8_watch_once_without_the_flag_uses_the_source_writer() {
    let fixture = Fixture::new();
    let session = fixture.write_claude_session(
        "w8/session.jsonl",
        &claude_session("sess-w8", "a default question", "a default answer"),
    );

    let run = fixture.watch_once_legacy(&[&session]);
    run.expect_success("a plain watch-once run");
    assert!(
        run.dispatches() > 0,
        "a run without the flag takes the source-aware commit: {}",
        run.stderr
    );

    let db = fixture.open_db();
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM conversations"),
        1,
        "the single session still lands once"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'"),
        1,
        "the un-flagged run claims a complete source fact"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM source_inputs si
             JOIN operation_commit_receipt r ON r.idempotency_key = si.receipt_key
             WHERE si.state = 'complete'
               AND r.operation = 'source_input_activation_v1'
               AND r.state = 'committed'"
        ),
        1,
        "the complete input has its committed receipt"
    );
    assert!(
        count(&db, "SELECT COUNT(*) FROM messages WHERE content LIKE '%a default answer%'") > 0,
        "the canonical body still lands"
    );
}

// ---------------------------------------------------------------------------
// R3: one file, one identity, whichever entry point read it
// ---------------------------------------------------------------------------

/// A file under a **home** root: the one-shot source scan and an explicit
/// `--watch-once` selection of that same file must agree on one identity.
///
/// The selection decides which file is read; it does not decide what root the
/// file belongs to. Before R3 the watch-once run rebuilt the scan root from the
/// selected file's parent directory, so the same unchanged file carried two
/// identities and the second run wrote a second input instead of replaying the
/// first.
#[test]
fn r3_a_home_root_file_keeps_one_identity_across_entry_points() {
    let fixture = Fixture::new();
    let session = fixture.write_claude_session(
        "r3h/proj/session.jsonl",
        &claude_session("sess-r3h", "the home question", CLAUDE_PHRASE),
    );
    let _sibling = fixture.write_claude_session(
        "r3h/proj/other.jsonl",
        &claude_session("sess-r3h-other", "not selected", "unselected home body"),
    );

    // 1) the one-shot source scan reads the home root.
    fixture
        .source_index_all()
        .expect_success("the one-shot source scan");
    let before = source_facts_fingerprint(&fixture.open_db());

    // Its identity is the declared home root's, measured from that root.
    let home_root = fixture.home().join(".claude/projects");
    let canonical_home = std::fs::canonicalize(&home_root).expect("canonicalise the home root");
    let selected_line = fingerprint_line_ending(&before, "locator=r3h/proj/session.jsonl");
    assert!(
        selected_line.contains(&format!("root={}", canonical_home.display())),
        "the input is rooted in the declared home root, not in the file's parent: {selected_line}"
    );

    // 2) an explicit selection of that same, unchanged file.
    let run = fixture.watch_once(&[&session]);
    run.expect_success("the watch-once run under the declared root");
    assert_eq!(
        run.dispatches(),
        1,
        "the explicit path selected one file, not its whole directory: {}",
        run.stderr
    );

    let after = source_facts_fingerprint(&fixture.open_db());
    assert_eq!(
        after, before,
        "one file has one identity: the explicit run must replay the input the one-shot \
         scan wrote, not write a second one"
    );
}

/// A file under an explicitly **configured** root, in the reverse order: the
/// explicit selection reads first, then the one-shot scan of that root.
///
/// The configured root carries non-default origin metadata and a path mapping,
/// so its identity is distinguishable from a home root's: the input key, the
/// root and relative locator, the context digest and the origin namespace must
/// be the configured root's on both sides, and the second entry point must not
/// mint a second identity for the file it already has.
#[test]
fn r3_a_configured_root_file_keeps_one_identity_in_reverse_order() {
    let fixture = Fixture::new();
    let cfg_root = fixture.path().join("cfgroot");
    std::fs::create_dir_all(&cfg_root).expect("mkdir the configured root");
    fixture.write_configured_source("r3cfg", "r3cfg-host", &cfg_root);

    let rollout_a = cfg_root.join("sessions/2026/01/rollout-r3-a.jsonl");
    std::fs::create_dir_all(rollout_a.parent().expect("rollout parent"))
        .expect("mkdir the rollout dir");
    std::fs::write(
        &rollout_a,
        jsonl(&codex_session("sess-r3-a", "the configured question", CODEX_PHRASE)),
    )
    .expect("write rollout a");
    // A sibling of the selected file, in the very directory the selection names
    // a file from: it must not be read by the explicit run.
    let rollout_b = cfg_root.join("sessions/2026/01/rollout-r3-b.jsonl");
    std::fs::write(
        &rollout_b,
        jsonl(&codex_session("sess-r3-b", "not selected", "unselected configured body")),
    )
    .expect("write rollout b");

    let a_locator = "locator=sessions/2026/01/rollout-r3-a.jsonl";
    let b_locator = "locator=sessions/2026/01/rollout-r3-b.jsonl";
    let canonical_cfg = std::fs::canonicalize(&cfg_root).expect("canonicalise the configured root");
    let declared_root = format!("root={}", canonical_cfg.display());

    // 1) the explicit selection reads first. A configured root is planned for
    //    every connector, so the connectors that can discover this file each
    //    read it -- exactly as the one-shot scan of the root reads it -- and the
    //    unselected sibling in the same directory is not read at all.
    let first = fixture.watch_once(&[&rollout_a]);
    first.expect_success("the explicit run under the configured root");
    assert!(
        first.dispatches() >= 1,
        "the explicit run read the selected file: {}",
        first.stderr
    );

    let db = fixture.open_db();
    let locators = input_locators(&db);
    assert!(
        !locators.is_empty()
            && locators.iter().all(|locator| locator.ends_with("rollout-r3-a.jsonl")),
        "only the selected file became an input, never its sibling: {locators:?}"
    );
    let after_first = source_facts_fingerprint(&db);
    let selected_lines = fingerprint_lines_ending(&after_first, a_locator);
    assert!(!selected_lines.is_empty(), "the selection landed: {after_first:#?}");
    for line in &selected_lines {
        assert!(
            line.contains(&declared_root),
            "the input is rooted in the configured root, not in the file's parent: {line}"
        );
        assert!(
            line.contains("namespace=r3cfg-host"),
            "the configured root's declared origin namespace is what the input carries: {line}"
        );
    }
    drop(db);

    // 2) the one-shot scan of the same, unchanged root.
    fixture
        .source_index_all()
        .expect_success("the one-shot source scan");

    let db = fixture.open_db();
    let after_second = source_facts_fingerprint(&db);
    assert_eq!(
        fingerprint_lines_ending(&after_second, a_locator),
        selected_lines,
        "the selected file's identity is byte-for-byte the one the explicit run wrote; \
         the second entry point must not mint a second identity for it"
    );
    let sibling_lines = fingerprint_lines_ending(&after_second, b_locator);
    assert!(
        !sibling_lines.is_empty(),
        "the root scan reads the sibling the explicit selection left alone: {after_second:#?}"
    );
    for line in &sibling_lines {
        assert!(
            line.contains(&declared_root) && line.contains("namespace=r3cfg-host"),
            "the sibling, read by the root scan, carries the same declared root identity: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// R4: every declared root the selection intersects, not one winner
// ---------------------------------------------------------------------------

/// The namespaces the given fingerprint lines carry, e.g. `local` for a home
/// root and the source's `origin_host` for a configured one.
fn namespaces_in(lines: &[String]) -> std::collections::BTreeSet<String> {
    lines
        .iter()
        .filter_map(|line| {
            line.split_whitespace()
                .find_map(|field| field.strip_prefix("namespace=").map(str::to_string))
        })
        .collect()
}

/// A `sources.toml` entry may name a directory that is also a connector's home
/// root. Both declarations are real, and a one-shot source scan reads the file
/// through both -- each carrying its own origin and namespace. The explicit
/// selection must do the same, in either order, and the second entry point must
/// replay every identity the first one wrote.
#[test]
fn r4_a_path_covered_by_two_declarations_is_read_through_both() {
    for explicit_first in [false, true] {
        let fixture = Fixture::new();
        let sessions = fixture.home().join(".codex/sessions");
        let rollout = sessions.join("2026/01/rollout-r4-two.jsonl");
        std::fs::create_dir_all(rollout.parent().expect("rollout parent"))
            .expect("mkdir the rollout dir");
        std::fs::write(
            &rollout,
            jsonl(&codex_session("sess-r4-two", "the shared question", CODEX_PHRASE)),
        )
        .expect("write the rollout");
        // The very directory the Codex HOME root resolves to, declared again as
        // a named source with its own origin host.
        fixture.write_configured_source("archive-a", "archive-a", &sessions);

        if explicit_first {
            fixture
                .watch_once(&[&rollout])
                .expect_success("the explicit run first");
        } else {
            fixture
                .source_index_all()
                .expect_success("the root scan first");
        }

        let before = source_facts_fingerprint(&fixture.open_db());
        let locator = "locator=2026/01/rollout-r4-two.jsonl";
        let lines_before = fingerprint_lines_ending(&before, locator);
        let namespaces = namespaces_in(&lines_before);
        assert!(
            namespaces.contains("local") && namespaces.contains("archive-a"),
            "the file is read through both declarations, the home root's and the configured \
             one's (explicit_first={explicit_first}): {lines_before:#?}"
        );

        if explicit_first {
            fixture
                .source_index_all()
                .expect_success("the root scan after the explicit run");
        } else {
            fixture
                .watch_once(&[&rollout])
                .expect_success("the explicit run after the root scan");
        }

        let after = source_facts_fingerprint(&fixture.open_db());
        assert_eq!(
            fingerprint_lines_ending(&after, locator),
            lines_before,
            "both entry points must agree on the same declarations for one file"
        );
        assert_eq!(
            after, before,
            "and the second entry point must replay every one of them, not add a third \
             identity (explicit_first={explicit_first})"
        );
    }
}

/// Selecting a directory that *contains* a declared root must still read that
/// root's files as the root's inputs. A selection is not a new root: the inner
/// declaration survives it, with its own namespace, and nothing is rooted in
/// the selected directory as an ad-hoc identity.
#[test]
fn r4_selecting_an_ancestor_directory_keeps_the_declared_root_inside_it() {
    let fixture = Fixture::new();
    let outer = fixture.path().join("arch");
    let inner = outer.join("inner");
    let rollout = inner.join("sessions/2026/01/rollout-r4-inner.jsonl");
    std::fs::create_dir_all(rollout.parent().expect("rollout parent"))
        .expect("mkdir the rollout dir");
    std::fs::write(
        &rollout,
        jsonl(&codex_session("sess-r4-inner", "the inner question", CODEX_PHRASE)),
    )
    .expect("write the rollout");
    // Two declared roots, one inside the other; the selection names the outer.
    fixture.write_configured_sources(&[
        ("archive-outer", "archive-outer", &outer),
        ("archive-inner", "archive-inner", &inner),
    ]);

    // The explicit selection reads the file through both declarations, on a
    // database no root scan has touched yet.
    let run = fixture.watch_once(&[&outer]);
    run.expect_success("the explicit run over the ancestor directory");
    assert!(
        run.dispatches() >= 2,
        "both declarations are read, the selection's own and the one inside it: {}",
        run.stderr
    );

    let db = fixture.open_db();
    let after_first = source_facts_fingerprint(&db);
    drop(db);

    let outer_lines = fingerprint_lines_rooted_at(&after_first, &outer);
    assert_eq!(
        namespaces_in(&outer_lines),
        std::collections::BTreeSet::from(["archive-outer".to_string()]),
        "the selection's own declaration is read under its namespace, not as an ad-hoc \
         local root: {outer_lines:#?}"
    );
    let inner_lines = fingerprint_lines_rooted_at(&after_first, &inner);
    assert_eq!(
        namespaces_in(&inner_lines),
        std::collections::BTreeSet::from(["archive-inner".to_string()]),
        "the declared root inside the selection keeps its own identity: {inner_lines:#?}"
    );

    // The one-shot scan of both roots must add nothing beyond that.
    fixture
        .source_index_all()
        .expect_success("the root scan after the explicit run");
    let after = source_facts_fingerprint(&fixture.open_db());
    assert_eq!(
        after, after_first,
        "the explicit selection and the root scan agree on every identity"
    );
    assert!(
        after.iter().all(|line| !line.contains("namespace=local locator=")
            || !line.contains(&format!(
                "root={} locator=",
                std::fs::canonicalize(&outer).expect("canonicalise").display()
            ))),
        "no ad-hoc identity is built for the selected directory: {after:#?}"
    );
}
