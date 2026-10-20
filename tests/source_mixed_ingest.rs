//! Ticket 24 acceptance: a run that mixes fidelity connectors and legacy
//! connectors dispatches each connector by its own capability.
//!
//! Every case drives the real `cass index` binary over a private synthetic
//! HOME, private synthetic configured roots (a machine-local one and the
//! mirror directory an ssh source publishes into), a private fixed safety copy
//! and a private data directory, then reads the resulting SQLite database
//! directly. One legacy pre-state is built from public library primitives in a
//! child process; the ingestion under test is still the CLI, so the seam stays
//! the CLI, the database, the per-run JSON and the process boundary.
//!
//! The mixed input is what makes the dispatch visible. A Claude Code session
//! and a Codex rollout sit under their own HOME roots; a Gemini session sits
//! under the Gemini HOME root, inside a configured local root and inside an
//! ssh mirror root. Every connector scans every configured root, so a run that
//! dispatched by connector *kind* rather than by capability would push the
//! Gemini files onto the sealed read, which the Gemini connector does not
//! implement -- and would then demand a source receipt this connector never
//! writes.
//!
//! The Gemini files are the real frozen fixture
//! `tests/fixtures/gemini/hash123/chats/session-test.json` where the placement
//! allows it, and copies of its exact shape (different session id and text, so
//! the three placements stay three conversations) where it does not. No
//! synthetic session log stands in for a connector whose parser is under test.
//!
//! The fixtures are synthetic and neutral. No real session, path or secret
//! appears in this file.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use coding_agent_search::storage::api::{Conn, Value};
use coding_agent_search::storage::sqlite::FrankenStorage;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn cass_bin() -> String {
    env!("CARGO_BIN_EXE_cass").to_string()
}

/// The one line a source-aware commit writes from inside its writer closure.
const DISPATCH_MARKER: &str = "source_input_dispatch";

/// The line `watch_sources` writes once the watcher is registered and the loop
/// is about to start, so a case can separate the startup scan from the event
/// cycle it is actually asserting about.
const WATCH_READY_MARKER: &str = "watch mode: minimum interval between scan cycles";

/// The frozen Gemini session fixture, used verbatim wherever a case may.
const GEMINI_FIXTURE: &[u8] =
    include_bytes!("fixtures/gemini/hash123/chats/session-test.json");

/// The exact strings the frozen fixture carries, so a case can prove the
/// legacy connector's own message values landed rather than only that some row
/// appeared.
const GEMINI_FIXTURE_USER: &str = "Gemini hello";
const GEMINI_FIXTURE_MODEL: &str = "Hello from Gemini!";

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

    /// Point every source-discovery environment at this fixture, so an
    /// inherited value on the host cannot make a fixture process scan real
    /// history.
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
            // A watch cycle applies the active-source filter, whose recent-write
            // window treats a just-written session log as one still being
            // appended to and skips it. That protection is right in production
            // and this file exercises it nowhere; `0` is the documented way to
            // turn it off.
            .env("CASS_ACTIVE_SESSION_RECENT_WRITE_WINDOW_SECS", "0")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("CASS_TEST_WATCH_PATHS")
            .env_remove("RUST_LOG");
        cmd
    }

    /// One `sources.toml` declaring the sources the caller describes. Each
    /// entry is `(name, kind, origin_host, path, full_scan)`; `kind` is
    /// `local` or `ssh`.
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

    /// The mirror directory the **write side** would publish an ssh source
    /// into, obtained through the production entry points.
    fn prepare_mirror(&self, source_name: &str, remote_path: &str) -> PathBuf {
        use coding_agent_search::sources::config::SourceDefinition;
        use coding_agent_search::sources::sync::{mirror_path_under, path_to_safe_dirname, SyncEngine};

        let mut source = SourceDefinition::ssh(source_name, source_name);
        source.paths = vec![remote_path.to_string()];
        source.origin_host = source_name.to_string();
        let engine = SyncEngine::new(&self.data_dir());
        let mirror_root = engine
            .prepare_mirror_root(&source)
            .expect("the configured mirror root must be authorized");
        let mirrored = mirror_path_under(&mirror_root, remote_path);
        std::fs::create_dir_all(&mirrored).expect("mkdir mirror path");
        assert_eq!(
            mirrored,
            self.data_dir()
                .join("remotes")
                .join(source_name)
                .join("mirror")
                .join(path_to_safe_dirname(remote_path)),
            "the write side names the mirror directory after the raw configured path"
        );
        mirrored
    }

    fn create_home_roots(&self) {
        std::fs::create_dir_all(self.home().join(".claude/projects")).expect("mkdir claude root");
        std::fs::create_dir_all(self.home().join(".codex/sessions")).expect("mkdir codex root");
    }

    /// Write a Claude Code session under `root` at `relative`.
    fn write_claude_session(
        &self,
        root: &Path,
        relative: &str,
        uuid: &str,
        answer: &str,
    ) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("session parent")).expect("mkdir session dir");
        std::fs::write(&path, jsonl(&claude_session(uuid, "synthetic question", answer)))
            .expect("write claude session");
        path
    }

    /// Write a Codex rollout under `root` at `relative`.
    fn write_codex_session(&self, root: &Path, relative: &str, id: &str, answer: &str) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("codex parent")).expect("mkdir codex dir");
        std::fs::write(&path, jsonl(&codex_session(id, "synthetic codex question", answer)))
            .expect("write codex rollout");
        path
    }

    /// Write a Gemini session under `root` at `relative`, at the
    /// `chats/session-*.json` layout its connector walks.
    fn write_gemini(&self, root: &Path, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("gemini parent")).expect("mkdir gemini dir");
        std::fs::write(&path, bytes).expect("write gemini session");
        path
    }

    /// `cass index --json --verbose` on top of the source-aware flag.
    fn index_with(&self, extra: &[&str]) -> Run {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.env("CASS_DATA_DIR", self.data_dir());
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .arg("--source-safety-config")
            .arg(self.fixed_copy())
            .args(["--json", "--verbose"])
            .args(extra);
        Run::from(cmd.output().expect("spawn cass index"))
    }

    /// `cass index --json --verbose` with one scheduling cell, so both real
    /// schedulings can be driven over the same synthetic input.
    fn index_cell(&self, streaming: bool) -> Run {
        let mut cmd = Command::new(cass_bin());
        self.isolate(&mut cmd);
        cmd.env("CASS_STREAMING_INDEX", if streaming { "1" } else { "0" })
            .env("CASS_STREAMING_CONSUMER_COMBINE", "0")
            .env("CASS_DATA_DIR", self.data_dir());
        cmd.args(["index", "--data-dir"])
            .arg(self.data_dir())
            .arg("--source-safety-config")
            .arg(self.fixed_copy())
            .args(["--json", "--verbose"]);
        Run::from(cmd.output().expect("spawn cass index"))
    }

    fn open_db(&self) -> Conn {
        FrankenStorage::open_readonly(&self.db()).expect("open the database read-only").into_raw()
    }

    /// A read-only handle on the live database, or `None` while it does not
    /// exist or the writer is mid-checkpoint.
    fn try_open_db(&self) -> Option<Conn> {
        if !self.db().exists() {
            return None;
        }
        FrankenStorage::open_readonly(&self.db()).ok().map(FrankenStorage::into_raw)
    }
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
    /// How many inputs this run prepared and carried into its commit.
    fn dispatches(&self) -> usize {
        self.stderr.matches(DISPATCH_MARKER).count()
    }

    /// The `(conversations, messages)` this run actually read for one
    /// connector, from the run's own per-connector breakdown, or `None` when
    /// the run reported no work for that connector at all.
    ///
    /// This is per-run, not a database total, which is what makes it the
    /// evidence for "this connector read this root in this run" and for "it
    /// did not read it again on the next".
    fn connector_read(&self, connector: &str) -> Option<(u64, u64)> {
        let connectors = self.payload.as_ref()?.get("indexing_stats")?.get("connectors")?;
        connectors.as_array()?.iter().find_map(|entry| {
            (entry.get("name")?.as_str()? == connector).then(|| {
                (
                    entry.get("conversations").and_then(|v| v.as_u64()).unwrap_or(0),
                    entry.get("messages").and_then(|v| v.as_u64()).unwrap_or(0),
                )
            })
        })
    }

    fn source_inputs_committed(&self) -> u64 {
        self.payload
            .as_ref()
            .and_then(|payload| payload.get("indexing_stats"))
            .and_then(|stats| stats.get("source_inputs_committed"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
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

/// A Gemini session in the frozen fixture's own shape, with the session id and
/// the two message texts replaced so three placements stay three
/// conversations.
fn gemini_session(session_id: &str, user: &str, model: &str) -> Vec<u8> {
    let mut value: serde_json::Value =
        serde_json::from_slice(GEMINI_FIXTURE).expect("the frozen fixture parses");
    value["sessionId"] = serde_json::Value::String(session_id.to_string());
    value["messages"][0]["content"] = serde_json::Value::String(user.to_string());
    value["messages"][1]["content"] = serde_json::Value::String(model.to_string());
    serde_json::to_vec_pretty(&value).expect("serialize the gemini session")
}

// ---------------------------------------------------------------------------
// Database readers
// ---------------------------------------------------------------------------

fn scalar(db: &Conn, sql: &str) -> i64 {
    db.query_row_map(sql, &[], |row| row.get_typed(0)).unwrap_or_else(|error| panic!("{sql}: {error}"))
}

/// Every message's role, author and text, ordered -- a whole-table comparison
/// that does not depend on row ids, which are not a cross-database identity.
fn messages_fingerprint(db: &Conn) -> Vec<String> {
    db.query_all_map(
            "SELECT COALESCE(role,'') || '|' || COALESCE(author,'') || '|' || COALESCE(content,'')
             FROM messages ORDER BY 1",
            &[], |row| row.get_typed(0),
        ).expect("query the message fingerprint")
}

/// Every conversation's agent slug and external id, ordered. Row ids are
/// deliberately absent: they are per-database counters.
fn conversations_fingerprint(db: &Conn) -> Vec<String> {
    db.query_all_map(
            "SELECT COALESCE(a.slug,'') || '|' || COALESCE(c.external_id,'') || '|' ||
                    COALESCE(c.title,'')
             FROM conversations c LEFT JOIN agents a ON a.id = c.agent_id ORDER BY 1",
            &[], |row| row.get_typed(0),
        ).expect("query the conversation fingerprint")
}

/// Every source input's connector, state and sealed identity, ordered. The
/// locator is shown in hex because it is stored as the encoded bytes the
/// kernel sealed, not as text.
fn inputs_fingerprint(db: &Conn) -> Vec<String> {
    db.query_all_map(
            "SELECT connector || '|' || state || '|' || source_id || '|' || identity_namespace || '|' || COALESCE(origin_host,'') || '|' ||
                    hex(role_bin) || '|' || hex(relative_locator_bin) || '|' || hex(sealed_sha256)
             FROM source_inputs ORDER BY 1",
            &[], |row| row.get_typed(0),
        ).expect("query the input fingerprint")
}

fn messages_containing(db: &Conn, needle: &str) -> i64 {
    scalar(
        db,
        &format!(
            "SELECT COUNT(*) FROM messages WHERE content LIKE '%{}%'",
            needle.replace('\'', "''")
        ),
    )
}

fn source_inputs_for(db: &Conn, connector: &str) -> i64 {
    db.query_row_map(
        "SELECT COUNT(*) FROM source_inputs WHERE connector = ?1",
        &[Value::Text(connector.to_string())],
        |row| row.get_typed(0),
    )
    .expect("count the connector's source inputs")
}

fn complete_source_inputs_for(db: &Conn, connector: &str) -> i64 {
    db.query_row_map(
        "SELECT COUNT(*) FROM source_inputs WHERE connector = ?1 AND state = 'complete'",
        &[Value::Text(connector.to_string())],
        |row| row.get_typed(0),
    )
    .expect("count the connector's complete source inputs")
}

/// Every `root_id | connector | last_scan_ts` row whose root id starts with
/// `prefix`, ordered.
fn watermark_rows(db: &Conn, prefix: &str) -> Vec<String> {
    db.query_all_map(
            "SELECT root_id || '|' || connector || '|' || last_scan_ts FROM scan_watermarks
             WHERE root_id LIKE ?1 || '%' ORDER BY root_id, connector",
            &[Value::Text(prefix.to_string())], |row| row.get_typed(0),
        ).expect("query watermark rows")
}

/// Every `root_id | connector | relative_path | size | mtime` row whose root id
/// starts with `prefix`, ordered.
fn file_state_rows(db: &Conn, prefix: &str) -> Vec<String> {
    db.query_all_map(
            "SELECT root_id || '|' || connector || '|' || relative_path || '|' || size || '|' || mtime
             FROM scan_file_state WHERE root_id LIKE ?1 || '%'
             ORDER BY root_id, connector, relative_path",
            &[Value::Text(prefix.to_string())], |row| row.get_typed(0),
        ).expect("query file state rows")
}

// ---------------------------------------------------------------------------
// The mixed input
// ---------------------------------------------------------------------------

/// The synthetic mixed input every scheduling case reads: two fidelity
/// connectors under their own HOME roots and one legacy connector under three
/// different root kinds.
struct MixedInputs {
    configured_root: PathBuf,
    mirror_root: PathBuf,
}

const CLAUDE_PHRASE: &str = "synthetic mixed claude landing phrase";
const CODEX_PHRASE: &str = "synthetic mixed codex landing phrase";
const GEMINI_CONFIGURED_PHRASE: &str = "synthetic mixed gemini configured phrase";
const GEMINI_MIRROR_PHRASE: &str = "synthetic mixed gemini mirror phrase";
const EXTRA_SOURCE_PHRASES: [&str; 4] = [
    "configured unique claude phrase", "configured unique codex phrase",
    "mirror unique claude phrase", "mirror unique codex phrase",
];

fn build_mixed_inputs(fixture: &Fixture) -> MixedInputs {
    // The fidelity connectors' own HOME roots.
    fixture.write_claude_session(
        &fixture.home().join(".claude/projects"),
        "synthetic/-m/mixed-home-claude.jsonl",
        "sess-mixed-home-claude",
        CLAUDE_PHRASE,
    );
    fixture.write_codex_session(
        &fixture.home().join(".codex"),
        "sessions/2026/01/rollout-2026-01-01T00-00-00-sess-mixed-home-codex.jsonl",
        "sess-mixed-home-codex",
        CODEX_PHRASE,
    );
    // The legacy connector's own HOME root, at the layout its connector walks.
    fixture.write_gemini(
        &fixture.home().join(".gemini/tmp"),
        "hash123/chats/session-test.json",
        GEMINI_FIXTURE,
    );

    // A configured local root holding only a legacy session. Every connector
    // scans every configured root, so this is where a dispatch that asked the
    // wrong connector would fail.
    let configured = fixture.path().join("mixed-configured");
    fixture.write_gemini(
        &configured,
        "hash456/chats/session-configured.json",
        &gemini_session(
            "sess-mixed-configured",
            GEMINI_CONFIGURED_PHRASE,
            "synthetic mixed gemini configured reply",
        ),
    );

    // An ssh mirror root, published through the production mirror entry points
    // and holding only a legacy session too.
    let remote = "/synthetic-mirror/gemini-tmp";
    fixture.write_sources(&[
        (
            "laptop",
            "local",
            "laptop",
            configured.to_str().expect("utf-8 configured root"),
            false,
        ),
        ("archive-a", "ssh", "archive-a", remote, false),
    ]);
    let mirrored = fixture.prepare_mirror("archive-a", remote);
    fixture.write_gemini(
        &mirrored,
        "hash789/chats/session-mirror.json",
        &gemini_session(
            "sess-mixed-mirror",
            GEMINI_MIRROR_PHRASE,
            "synthetic mixed gemini mirror reply",
        ),
    );

    for (root, id, claude_phrase, codex_phrase) in [
        (&configured, "configured", EXTRA_SOURCE_PHRASES[0], EXTRA_SOURCE_PHRASES[1]),
        (&mirrored, "mirror", EXTRA_SOURCE_PHRASES[2], EXTRA_SOURCE_PHRASES[3]),
    ] {
        fixture.write_claude_session(root, &format!("projects/p/session-{id}.jsonl"), &format!("claude-{id}"), claude_phrase);
        fixture.write_codex_session(root, &format!("sessions/rollout-{id}.jsonl"), &format!("codex-{id}"), codex_phrase);
    }
    MixedInputs {
        configured_root: configured,
        mirror_root: mirrored,
    }
}

// ---------------------------------------------------------------------------
// A1: HOME, configured and mirror inputs under one run
// ---------------------------------------------------------------------------

/// A1: one run reads Claude and Codex through the sealed kernel from their HOME
/// roots, and the legacy connector from its HOME root, a configured local root
/// and an ssh mirror root -- without any of those three legacy placements
/// being pushed onto a read its connector does not implement.
#[test]
fn a1_mixed_home_and_configured() {
    let fixture = Fixture::new();
    let mixed = build_mixed_inputs(&fixture);

    let run = fixture.index_cell(false);
    assert_eq!(
        run.code,
        Some(0),
        "a mixed run must succeed; stderr={}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("Unsupported"),
        "no connector may be asked for a sealed read it does not implement; stderr={}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("source-aware input refused"),
        "no root may be failed by the source dispatch; stderr={}",
        run.stderr
    );

    // The fidelity connectors land real source facts and their activation
    // receipts.
    let db = fixture.open_db();
    assert_eq!(
        complete_source_inputs_for(&db, "claude_code"), 3,
        "the Claude session lands as a completed sealed input"
    );
    assert_eq!(
        complete_source_inputs_for(&db, "codex"), 3,
        "the Codex rollout lands as a completed sealed input"
    );
    assert_eq!(
        scalar(&db, "SELECT COUNT(*) FROM operation_commit_receipt"), 6,
        "each sealed input carries its own activation receipt"
    );
    assert_eq!(
        run.source_inputs_committed(), 6,
        "the run's own JSON agrees the HOME roots' sealed inputs committed; stderr={}",
        run.stderr
    );

    // The legacy connector keeps its own path: no source facts, its real
    // message values present.
    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_inputs"), 6);
    assert_eq!(rows(&db, "SELECT source_id || '|' || identity_namespace || '|' || connector FROM source_inputs ORDER BY 1"), vec![
        "archive-a|archive-a|claude_code", "archive-a|archive-a|codex",
        "laptop|laptop|claude_code", "laptop|laptop|codex",
        "local|local|claude_code", "local|local|codex",
    ]);
    let input_roots: Vec<String> = db.query_all_map("SELECT root_id_bin FROM source_inputs ORDER BY root_id_bin", &[], |row| {
        let bytes: Vec<u8> = row.get_typed(0)?;
        Ok(String::from_utf8(bytes).expect("UTF-8 source root"))
    }).unwrap();
    for root in [&mixed.configured_root, &mixed.mirror_root] {
        assert_eq!(input_roots.iter().filter(|value| *value == root.to_str().unwrap()).count(), 2);
    }
    let storage = FrankenStorage::open_readonly(&fixture.db()).unwrap();
    let identities = conversation_identities(&storage);
    for (source, root) in [("laptop", &mixed.configured_root), ("archive-a", &mixed.mirror_root)] {
        let digest = blake3::hash(root.canonicalize().unwrap().to_str().unwrap().as_bytes()).to_hex();
        let expected = format!("{source}|{source}|cfg:{source}:{}", &digest[..16]);
        assert_eq!(identities.iter().filter(|value| **value == expected).count(), 3, "{identities:?}");
    }
    for (connector, root) in [
        ("claude", fixture.home().join(".claude/projects")),
        ("codex", fixture.home().join(".codex/sessions")),
    ] {
        let canonical = root.canonicalize().unwrap();
        let digest = blake3::hash(canonical.to_str().unwrap().as_bytes()).to_hex();
        let expected = format!("local|local|home:{connector}:{}", &digest[..16]);
        assert_eq!(identities.iter().filter(|value| **value == expected).count(), 1, "{identities:?}");
        assert_eq!(input_roots.iter().filter(|value| *value == canonical.to_str().unwrap()).count(), 1);
    }
    drop(storage);
    for phrase in EXTRA_SOURCE_PHRASES { assert_eq!(messages_containing(&db, phrase), 1, "{phrase}: {:?}", messages_fingerprint(&db)); }
    assert_eq!(
        source_inputs_for(&db, "gemini"),
        0,
        "the legacy connector is never asked for a source input"
    );
    for (phrase, what) in [
        (CLAUDE_PHRASE, "the Claude session's own text"),
        (CODEX_PHRASE, "the Codex rollout's own text"),
        (GEMINI_FIXTURE_USER, "the frozen Gemini fixture's user turn"),
        (GEMINI_FIXTURE_MODEL, "the frozen Gemini fixture's model turn"),
        (GEMINI_CONFIGURED_PHRASE, "the configured root's Gemini turn"),
        (GEMINI_MIRROR_PHRASE, "the mirror root's Gemini turn"),
    ] {
        assert_eq!(
            messages_containing(&db, phrase),
            1,
            "{what} must land exactly once: {phrase}"
        );
    }

    // The three legacy placements really were read in this run -- proved from
    // the run's own per-connector breakdown, not from a row count that a
    // leftover could satisfy.
    let (conversations, messages) = run
        .connector_read("gemini")
        .expect("the legacy connector reports the sessions it read this run");
    assert!(
        conversations >= 3,
        "the legacy connector read its HOME, configured and mirror sessions in one run: \
         {conversations} conversation(s), {messages} message(s)"
    );

    // All three root kinds are present in the input, not just declared.
    assert!(mixed.configured_root.exists(), "the configured root exists");
    assert!(mixed.mirror_root.exists(), "the mirror root exists");
    assert!(
        file_state_rows(&db, "cfg:laptop:").len() >= 1,
        "the configured local root keeps its per-file state under the legacy reader"
    );
}

// ---------------------------------------------------------------------------
// A2: the same mixed input under both schedulings
// ---------------------------------------------------------------------------

/// A2: the batch and streaming schedulings read the same synthetic input and
/// land the same message, conversation and source-fact sets, compared by
/// content rather than by row id.
#[test]
fn a2_mixed_batch_and_stream() {
    let mut observed: Vec<(&str, Vec<String>, Vec<String>, Vec<String>, i64)> = Vec::new();

    for (label, streaming) in [("batch", false), ("streaming", true)] {
        let fixture = Fixture::new();
        build_mixed_inputs(&fixture);
        let run = fixture.index_cell(streaming);
        assert_eq!(
            run.code,
            Some(0),
            "{label}: the mixed run must succeed; stderr={}",
            run.stderr
        );
        assert!(
            !run.stderr.contains("Unsupported"),
            "{label}: no connector may be asked for a sealed read it does not implement; \
             stderr={}",
            run.stderr
        );

        let db = fixture.open_db();
        assert_eq!(
            source_inputs_for(&db, "gemini"),
            0,
            "{label}: the legacy connector writes no source input"
        );
        assert_eq!(
            complete_source_inputs_for(&db, "claude_code"),
            3,
            "{label}: the Claude HOME session sealed"
        );
        assert_eq!(
            complete_source_inputs_for(&db, "codex"),
            3,
            "{label}: the Codex HOME rollout sealed"
        );
        assert_eq!(scalar(&db, "SELECT COUNT(*) FROM source_inputs"), 6);
        assert_eq!(run.source_inputs_committed(), 6);
        for phrase in EXTRA_SOURCE_PHRASES.into_iter().chain([
            CLAUDE_PHRASE, CODEX_PHRASE, GEMINI_FIXTURE_USER,
            GEMINI_FIXTURE_MODEL, GEMINI_CONFIGURED_PHRASE, GEMINI_MIRROR_PHRASE,
        ]) {
            assert_eq!(
                messages_containing(&db, phrase),
                1,
                "{label}: every legacy placement lands once: {phrase}"
            );
        }
        let legacy = watermark_rows(&db, "cfg:laptop:");
        assert!(
            legacy.iter().any(|row| row.contains("|gemini|")),
            "{label}: the legacy connector keeps its own watermark row: {legacy:#?}"
        );

        observed.push((
            label,
            messages_fingerprint(&db),
            conversations_fingerprint(&db),
            inputs_fingerprint(&db),
            source_inputs_for(&db, "gemini"),
        ));
    }

    let (batch_label, batch_messages, batch_convs, batch_inputs, batch_gemini) = &observed[0];
    let (stream_label, stream_messages, stream_convs, stream_inputs, stream_gemini) = &observed[1];
    assert_eq!(
        (batch_label, stream_label),
        (&"batch", &"streaming"),
        "both schedulings ran"
    );
    assert!(!batch_messages.is_empty(), "the batch run landed messages");
    assert_eq!(
        batch_messages, stream_messages,
        "the two schedulings land the same message set, compared by content"
    );
    assert_eq!(
        batch_convs, stream_convs,
        "the two schedulings land the same conversation set"
    );
    assert_eq!(
        batch_inputs, stream_inputs,
        "the two schedulings seal the same inputs"
    );
    assert_eq!(
        (batch_gemini, stream_gemini),
        (&0, &0),
        "neither scheduling asks the legacy connector for a source input"
    );
}

// ---------------------------------------------------------------------------
// A3: watch-once and resident, on real triggers
// ---------------------------------------------------------------------------

const CLAUDE_WATCH_PHRASE: &str = "synthetic mixed claude watch-once phrase";
const GEMINI_WATCH_PHRASE: &str = "synthetic mixed gemini watch-once phrase";
const CLAUDE_RESIDENT_PHRASE: &str = "synthetic mixed claude resident phrase";
const GEMINI_RESIDENT_PHRASE: &str = "synthetic mixed gemini resident phrase";

/// A live `cass index --watch` child, with its stderr captured as it is
/// produced so a case can wait on a line the run really wrote.
struct Resident {
    child: Child,
    log: Arc<Mutex<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Resident {
    fn start(fixture: &Fixture) -> Self {
        Self::start_inner(fixture, false)
    }

    /// The same resident process over a DB-registered declaration set (the
    /// `sources.toml` path is ignored, exactly as the one-shot A9 helper).
    fn start_db_backed(fixture: &Fixture) -> Self {
        Self::start_inner(fixture, true)
    }

    fn start_inner(fixture: &Fixture, db_backed: bool) -> Self {
        let mut cmd = Command::new(cass_bin());
        fixture.isolate(&mut cmd);
        if db_backed {
            cmd.env("CASS_IGNORE_SOURCES_CONFIG", "1");
        }
        cmd.args(["index", "--data-dir"])
            .arg(fixture.data_dir())
            .arg("--source-safety-config")
            .arg(fixture.fixed_copy());
        cmd.args(["--watch", "--watch-interval", "1", "--json", "--verbose"]);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn the resident watch process");
        let stderr = child.stderr.take().expect("the child's stderr");
        let log = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&log);
        let reader = std::thread::spawn(move || {
            let mut stderr = stderr;
            let mut buf = [0u8; 4096];
            loop {
                match stderr.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&buf[..n]).to_string();
                        sink.lock().expect("log lock").push_str(&text);
                    }
                }
            }
        });
        Self {
            child,
            log,
            reader: Some(reader),
        }
    }

    fn log(&self) -> String {
        self.log.lock().expect("log lock").clone()
    }

    fn wait_for(&self, needle: &str, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            if self.log().contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn count(&self, needle: &str) -> usize {
        self.log().matches(needle).count()
    }

    fn wait_for_more(&self, needle: &str, was: usize, limit: Duration) -> Option<usize> {
        let deadline = Instant::now() + limit;
        loop {
            let seen = self.count(needle);
            if seen > was {
                return Some(seen);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Poll a probe until it yields a value, failing at the deadline with this
    /// run's own log attached.
    fn poll_until<T>(
        &self,
        what: &str,
        limit: Duration,
        mut probe: impl FnMut() -> Option<T>,
    ) -> T {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(value) = probe() {
                return value;
            }
            if Instant::now() >= deadline {
                panic!(
                    "timed out after {limit:?} waiting for {what}; the run's own log follows:\n{}",
                    self.log()
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Wait for this case's own child to be gone. Never a name- or
    /// pattern-based kill: only the process this case started.
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for Resident {
    fn drop(&mut self) {
        if self.reader.is_some() {
            self.stop();
        }
    }
}

/// A3: a mixed watch-once invocation and a mixed resident event cycle both
/// reach the database, and neither pushes a legacy trigger onto the sealed
/// read.
#[test]
fn a3_mixed_watch_once_and_resident() {
    // (a) One `--watch-once` invocation selecting a fidelity path and a legacy
    //     path together: the fidelity trigger is sealed, the legacy trigger
    //     keeps the legacy body, and both land.
    {
        let fixture = Fixture::new();
        let claude = fixture.write_claude_session(
            &fixture.home().join(".claude/projects"),
            "synthetic/-w/watch-once-claude.jsonl",
            "sess-mixed-watch-claude",
            CLAUDE_WATCH_PHRASE,
        );
        let gemini = fixture.write_gemini(
            &fixture.home().join(".gemini/tmp"),
            "hash321/chats/session-watch.json",
            &gemini_session(
                "sess-mixed-watch-gemini",
                GEMINI_WATCH_PHRASE,
                "synthetic mixed gemini watch-once reply",
            ),
        );

        let run = fixture.index_with(&[
            "--watch-once",
            claude.to_str().expect("utf-8 claude path"),
            "--watch-once",
            gemini.to_str().expect("utf-8 gemini path"),
        ]);
        assert_eq!(
            run.code,
            Some(0),
            "a mixed watch-once invocation must succeed; stderr={}",
            run.stderr
        );
        assert!(
            !run.stderr.contains("Unsupported"),
            "the legacy trigger must not reach the sealed read; stderr={}",
            run.stderr
        );

        let db = fixture.open_db();
        assert_eq!(
            messages_containing(&db, CLAUDE_WATCH_PHRASE),
            1,
            "the fidelity trigger lands through the source kernel"
        );
        assert_eq!(
            messages_containing(&db, GEMINI_WATCH_PHRASE),
            1,
            "the legacy trigger lands through the legacy body"
        );
        assert_eq!(
            complete_source_inputs_for(&db, "claude_code"),
            1,
            "the fidelity trigger sealed exactly one input"
        );
        assert_eq!(
            source_inputs_for(&db, "gemini"),
            0,
            "the legacy trigger is never sealed"
        );
        assert!(
            run.dispatches() >= 1,
            "the sealed trigger really committed; stderr={}",
            run.stderr
        );
    }

    // (a2) One declaration root holding a fidelity file and a legacy file,
    //      selected as a directory. Each file is read by its own owner: the
    //      Claude file through the sealed kernel, the Gemini file through the
    //      legacy writer. The legacy file never reaches the sealed read.
    {
        let fixture = Fixture::new();
        let root = fixture.path().join("declared-mixed");
        fixture.write_sources(&[(
            "laptop",
            "local",
            "laptop",
            root.to_str().expect("utf-8 declared root"),
            false,
        )]);
        fixture.write_claude_session(
            &root,
            "projects/p/one.jsonl",
            "sess-a3-mixed-directory-claude",
            CLAUDE_WATCH_PHRASE,
        );
        fixture.write_gemini(
            &root,
            "hash/chats/session-one.json",
            &gemini_session(
                "sess-a3-mixed-directory-gemini",
                GEMINI_WATCH_PHRASE,
                "synthetic mixed directory gemini reply",
            ),
        );

        let run = fixture.index_with(&["--watch-once", root.to_str().expect("utf-8 root")]);
        assert_eq!(
            run.code,
            Some(0),
            "a mixed declaration directory must succeed; stderr={}",
            run.stderr
        );
        assert!(
            !run.stderr.contains("Unsupported"),
            "the legacy file is never pushed onto the sealed read; stderr={}",
            run.stderr
        );
        let db = fixture.open_db();
        assert_eq!(
            messages_containing(&db, CLAUDE_WATCH_PHRASE),
            1,
            "the fidelity file lands through the source kernel"
        );
        assert_eq!(
            messages_containing(&db, GEMINI_WATCH_PHRASE),
            1,
            "the legacy file lands through the legacy writer"
        );
        assert_eq!(
            complete_source_inputs_for(&db, "claude_code"),
            1,
            "exactly the fidelity file is sealed"
        );
        assert_eq!(
            source_inputs_for(&db, "gemini"),
            0,
            "the legacy file is never sealed"
        );
    }

    // (a3) An explicit selection outside every declaration keeps the bounded
    //      ad-hoc source read for a first-batch connector: the parent
    //      directory is the root, and the original `explicit-watch-once`
    //      identity still produces its source facts.
    {
        let fixture = Fixture::new();
        let outside = fixture.path().join("outside/.claude/projects/p");
        let selected = fixture.write_claude_session(
            &outside,
            "one.jsonl",
            "sess-a3-adhoc-claude",
            CLAUDE_WATCH_PHRASE,
        );
        let run = fixture.index_with(&[
            "--watch-once",
            selected.to_str().expect("utf-8 ad-hoc selection"),
        ]);
        assert_eq!(
            run.code,
            Some(0),
            "an ad-hoc selection outside every declaration must succeed; stderr={}",
            run.stderr
        );
        assert!(
            !run.stderr.contains("Unsupported"),
            "the selection never reaches a connector without a sealed read: {}",
            run.stderr
        );
        let db = fixture.open_db();
        assert_eq!(
            complete_source_inputs_for(&db, "claude_code"),
            1,
            "the bounded ad-hoc selection still lands as a sealed input"
        );
        assert_eq!(
            messages_containing(&db, CLAUDE_WATCH_PHRASE),
            1,
            "the selected file's message landed"
        );
    }

    // (b) A resident `--watch` process: a real file change under a configured
    //     root, for the legacy connector and for a fidelity connector, reaches
    //     the database.
    {
        let fixture = Fixture::new();
        fixture.create_home_roots();
        let configured = fixture.path().join("resident-configured");
        std::fs::create_dir_all(&configured).expect("mkdir the resident configured root");
        fixture.write_sources(&[(
            "laptop",
            "local",
            "laptop",
            configured.to_str().expect("utf-8 configured root"),
            false,
        )]);

        let mut resident = Resident::start(&fixture);
        assert!(
            resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
            "the resident watch loop must reach its event cycle: {}",
            resident.log()
        );

        // The real events: one legacy file under the configured root, one
        // fidelity session under its HOME root.
        fixture.write_gemini(
            &configured,
            "hash555/chats/session-late.json",
            &gemini_session(
                "sess-mixed-resident-gemini",
                GEMINI_RESIDENT_PHRASE,
                "synthetic mixed gemini resident reply",
            ),
        );
        fixture.write_claude_session(
            &fixture.home().join(".claude/projects"),
            "synthetic/-r/resident-claude.jsonl",
            "sess-mixed-resident-claude",
            CLAUDE_RESIDENT_PHRASE,
        );

        resident.poll_until(
            "both real events to reach the database",
            Duration::from_secs(240),
            || {
                let db = fixture.try_open_db()?;
                (messages_containing(&db, GEMINI_RESIDENT_PHRASE) >= 1
                    && messages_containing(&db, CLAUDE_RESIDENT_PHRASE) >= 1)
                    .then_some(())
            },
        );
        resident.stop();

        let db = fixture.open_db();
        assert_eq!(
            messages_containing(&db, GEMINI_RESIDENT_PHRASE),
            1,
            "the legacy event landed exactly once"
        );
        assert_eq!(
            messages_containing(&db, CLAUDE_RESIDENT_PHRASE),
            1,
            "the fidelity event landed exactly once"
        );
        assert_eq!(
            source_inputs_for(&db, "gemini"),
            0,
            "no resident legacy trigger becomes a source input"
        );
        assert_eq!(
            complete_source_inputs_for(&db, "claude_code"),
            1,
            "the resident fidelity event sealed exactly one input"
        );
        // The dispatch itself, from the run's own log: the source-aware
        // trigger logs a line naming its connector, and the legacy body does
        // not. A `scan_session` for Gemini is the connector's own scan.
        let log = resident.log();
        assert!(
            log.contains("resident_source_watch_trigger connector=claude"),
            "the fidelity event is read through the resident source trigger: {log}"
        );
        assert!(
            !log.contains("resident_source_watch_trigger connector=gemini"),
            "the legacy event never takes the resident source trigger: {log}"
        );
        assert!(
            log.contains("scan_session") && log.contains("agent=gemini"),
            "the legacy event was read by the connector's own scan: {log}"
        );
    }
}

// ---------------------------------------------------------------------------
// A4: a legacy connector's own read and its own watermark
// ---------------------------------------------------------------------------

const GEMINI_WATERMARK_PHRASE: &str = "synthetic mixed gemini watermark phrase";

fn rows(db: &Conn, sql: &str) -> Vec<String> {
    db.query_all_map(sql, &[], |row| row.get_typed(0)).expect("query stable rows")
}

fn expect_success(run: &Run) {
    assert_eq!(run.code, Some(0), "stderr={} payload={:?}", run.stderr, run.payload);
}

fn seed_declared(fixture: &Fixture, root: &Path, full_scan: bool) {
    fixture.write_sources(&[("laptop", "local", "laptop", root.to_str().unwrap(), full_scan)]);
    fixture.write_claude_session(root, "projects/p/good.jsonl", "good-claude", "valid claude marker");
    fixture.write_codex_session(root, "sessions/rollout-good.jsonl", "good-codex", "valid codex marker");
}

fn pair_state(db: &Conn, connector: &str) -> (Vec<String>, Vec<String>) {
    let needle = format!("|{connector}|");
    (watermark_rows(db, "cfg:laptop:").into_iter().filter(|row| row.contains(&needle)).collect(),
     file_state_rows(db, "cfg:laptop:").into_iter().filter(|row| row.contains(&needle)).collect())
}

#[test]
fn a5_ownership_rejection_keeps_valid_source_inputs() {
    for streaming in [false, true] {
        let fixture = Fixture::new();
        let root = fixture.path().join("declared");
        seed_declared(&fixture, &root, false);
        fixture.write_gemini(&root, "hash/chats/session-good.json", &gemini_session("good-gemini", "gemini first", "gemini reply"));
        expect_success(&fixture.index_cell(streaming));
        let db = fixture.open_db();
        let claude = pair_state(&db, "claude");
        let gemini = pair_state(&db, "gemini");
        assert!(!claude.0.is_empty() && !gemini.0.is_empty());
        drop(db);
        fixture.write_claude_session(&root, "notes.json", "unknown", "unknown marker");
        fixture.write_gemini(&root, "projects/p/chats/session-conflict.json", &gemini_session("conflict", "conflict marker", "conflict answer"));
        fixture.write_claude_session(&root, "projects/p/new.jsonl", "new-claude", "new valid claude");
        fixture.write_codex_session(&root, "sessions/rollout-new.jsonl", "new-codex", "new valid codex");
        let run = fixture.index_cell(streaming);
        assert_ne!(run.code, Some(0), "ownership failure must surface");
        let diagnostic = format!("{} {:?}", run.stderr, run.payload);
        assert!(diagnostic.contains("source_ownership_unresolved=1"), "{diagnostic}");
        assert!(diagnostic.contains("source_ownership_ambiguous=1"), "{diagnostic}");
        let db = fixture.open_db();
        assert_eq!(complete_source_inputs_for(&db, "claude_code"), 2);
        assert_eq!(complete_source_inputs_for(&db, "codex"), 2);
        assert_eq!(pair_state(&db, "claude"), claude);
        assert_eq!(pair_state(&db, "gemini"), gemini);
        assert!(pair_state(&db, "codex").1.iter().any(|row| row.contains("rollout-new.jsonl")));
        for phrase in ["new valid claude", "new valid codex"] { assert_eq!(messages_containing(&db, phrase), 1); }
        assert_eq!(messages_containing(&db, "unknown marker"), 0);
        assert_eq!(messages_containing(&db, "conflict marker"), 0);
        let manifests = coding_agent_search::raw_mirror::manifest_views(&fixture.data_dir()).unwrap();
        assert!(manifests.iter().all(|m| !m.original_path.ends_with("notes.json") && !m.original_path.ends_with("session-conflict.json")));
    }
}

fn write_opencode_db(path: &Path, id: &str, phrase: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = FrankenStorage::open(path).unwrap().into_raw();
    db.execute_batch("CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT, title TEXT, directory TEXT, time_created TEXT, time_updated TEXT);
        CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, data TEXT NOT NULL, time_created TEXT, time_updated TEXT);
        CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, data TEXT NOT NULL, time_created TEXT, time_updated TEXT);").unwrap();
    let text = |s: &str| Value::Text(s.to_string());
    db.execute("INSERT INTO session VALUES (?1,'project',?1,'/synthetic/work','1760000000000','1760000000000')", &[text(id)]).unwrap();
    let message = format!("msg-{id}");
    db.execute("INSERT INTO message VALUES (?1,?2,?3,'1760000000000','1760000000000')", &[
        text(&message), text(id), text(&serde_json::json!({"role":"user","time":{"created":1760000000000i64}}).to_string()),
    ]).unwrap();
    db.execute("INSERT INTO part VALUES (?1,?2,?3,?4,'1760000000000000','1760000000000')", &[
        text(&format!("part-{id}")), text(&message), text(id), text(&serde_json::json!({"type":"text","text":phrase}).to_string()),
    ]).unwrap();
}

#[test]
fn a6_opencode_ambient_sources_keep_declaration_boundaries() {
    for streaming in [false, true] {
        let fixture = Fixture::new();
        let root = fixture.path().join("declared");
        seed_declared(&fixture, &root, false);
        fixture.write_gemini(&root, "hash/chats/session-good.json", GEMINI_FIXTURE);
        let home_db = fixture.home().join(".local/share/opencode/opencode.db");
        let configured_db = root.join("opencode.db");
        write_opencode_db(&home_db, "home-session", "home opencode unique body");
        write_opencode_db(&configured_db, "configured-session", "configured opencode unique body");
        expect_success(&fixture.index_cell(streaming));
        let db = fixture.open_db();
        for phrase in ["home opencode unique body", "configured opencode unique body"] { assert_eq!(messages_containing(&db, phrase), 1); }
        assert_eq!(source_inputs_for(&db, "opencode"), 0);
        let provenance = rows(&db, "SELECT external_id || '|' || source_id || '|' || COALESCE(origin_host,'') || '|' || source_path FROM conversations WHERE external_id IN ('home-session','configured-session') ORDER BY external_id");
        assert_eq!(provenance.len(), 2, "{provenance:?}");
        assert!(provenance[0].starts_with("configured-session|laptop||"), "local declaration preserves no remote origin host: {provenance:?}");
        assert!(provenance[0].ends_with(&format!("{}/configured-session", configured_db.display())));
        assert!(provenance[1].starts_with("home-session|local|"), "{provenance:?}");
        assert!(provenance[1].ends_with(&format!("{}/home-session", home_db.display())));
        let manifests = coding_agent_search::raw_mirror::manifest_views(&fixture.data_dir()).unwrap();
        assert!(manifests.iter().any(|m| m.provider == "opencode" && m.source_id == "local" && m.original_path == home_db.to_str().unwrap()));
        assert!(manifests.iter().any(|m| m.provider == "opencode" && m.source_id == "laptop" && m.original_path == configured_db.to_str().unwrap()));
        assert!(manifests.iter().filter(|m| m.source_id == "laptop").all(|m| !m.original_path.starts_with(home_db.to_str().unwrap())));
    }
}

fn copy_opencode_fixture(root: &Path, conflict: bool) -> PathBuf {
    let inputs = [
        ("session/proj1/ses_test1.json", include_bytes!("fixtures/opencode_json/session/proj1/ses_test1.json").as_slice()),
        ("message/ses_test1/msg_test1.json", include_bytes!("fixtures/opencode_json/message/ses_test1/msg_test1.json").as_slice()),
        ("message/ses_test1/msg_test2.json", include_bytes!("fixtures/opencode_json/message/ses_test1/msg_test2.json").as_slice()),
        ("part/msg_test1/part1.json", include_bytes!("fixtures/opencode_json/part/msg_test1/part1.json").as_slice()),
        ("part/msg_test2/part1.json", include_bytes!("fixtures/opencode_json/part/msg_test2/part1.json").as_slice()),
    ];
    for (name, bytes) in inputs {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    let sidecar = root.join("part/msg_test1/rollout-conflict.json");
    if conflict { std::fs::rename(root.join("part/msg_test1/part1.json"), &sidecar).unwrap(); }
    sidecar
}

#[test]
fn a7_legacy_sidecar_conflict_refuses_whole_unit() {
    use coding_agent_search::connectors::{Connector, ScanContext, ScanRoot};
    for streaming in [false, true] {
        for full_scan in [false, true] {
            for conflict in [false, true] {
                let fixture = Fixture::new();
                let root = fixture.path().join("declared");
                let sidecar = copy_opencode_fixture(&root, conflict);
                seed_declared(&fixture, &root, full_scan);
                let connector = franken_agent_detection::OpenCodeConnector::new();
                let ctx = ScanContext::with_roots(root.clone(), vec![ScanRoot::local(root.clone())], None);
                let discovered = connector.discover_source_files(&ctx).unwrap();
                if conflict { assert!(discovered.iter().any(|source| source.source_path == sidecar)); }
                let parsed = connector.scan_with_default_locations(&ctx, &franken_agent_detection::OpenCodeDefaultLocations::default()).unwrap();
                assert_eq!(parsed.len(), 1);
                assert_eq!(parsed[0].messages.len(), 2);
                let run = fixture.index_cell(streaming);
                let db = fixture.open_db();
                if conflict {
                    assert_ne!(run.code, Some(0));
                    assert!(format!("{} {:?}", run.stderr, run.payload).contains("source_ownership_ambiguous"));
                    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM conversations WHERE external_id='ses_test1'"), 0);
                    assert!(pair_state(&db, "opencode").0.is_empty());
                    assert!(pair_state(&db, "opencode").1.is_empty());
                    assert!(coding_agent_search::raw_mirror::manifest_views(&fixture.data_dir()).unwrap().iter().all(|m| m.provider != "opencode"));
                } else {
                    expect_success(&run);
                    assert_eq!(run.connector_read("opencode"), Some((1, 2)));
                    assert_eq!(scalar(&db, "SELECT COUNT(*) FROM conversations WHERE external_id='ses_test1'"), 1);
                }
                assert_eq!(complete_source_inputs_for(&db, "claude_code"), 1);
                assert_eq!(complete_source_inputs_for(&db, "codex"), 1);
                assert_eq!(source_inputs_for(&db, "opencode"), 0);
            }
        }
    }
}

#[test]
fn a8_gemini_incremental_file_selection_stays_bounded() {
    for streaming in [false, true] {
        let fixture = Fixture::new();
        let root = fixture.path().join("declared");
        fixture.write_sources(&[("laptop", "local", "laptop", root.to_str().unwrap(), false)]);
        let first = fixture.write_gemini(&root, "hash/chats/session-one.json", &gemini_session("one", "one initial", "answer one"));
        let second = fixture.write_gemini(&root, "hash/chats/session-two.json", &gemini_session("two", "two initial", "answer two"));
        let run = fixture.index_cell(streaming);
        expect_success(&run);
        assert_eq!(run.connector_read("gemini"), Some((2, 4)));
        for (changed, untouched, id) in [(&first, &second, "one"), (&second, &first, "two")] {
            let bytes = std::fs::read(untouched).unwrap();
            let meta = std::fs::metadata(untouched).unwrap();
            let before = pair_state(&fixture.open_db(), "gemini").1;
            let manifests = coding_agent_search::raw_mirror::manifest_views(&fixture.data_dir()).unwrap();
            let untouched_count = manifests.iter().filter(|m| m.original_path == untouched.to_str().unwrap()).count();
            std::fs::write(changed, gemini_session(id, &format!("{id} substantially larger changed text"), "updated longer answer")).unwrap();
            let run = fixture.index_cell(streaming);
            expect_success(&run);
            assert_eq!(run.connector_read("gemini"), Some((1, 2)), "{}", run.stderr);
            assert_eq!(std::fs::read(untouched).unwrap(), bytes);
            assert_eq!(std::fs::metadata(untouched).unwrap().modified().unwrap(), meta.modified().unwrap());
            let after = pair_state(&fixture.open_db(), "gemini").1;
            let suffix = untouched.file_name().unwrap().to_str().unwrap();
            assert_eq!(before.iter().find(|s| s.contains(suffix)), after.iter().find(|s| s.contains(suffix)));
            assert_ne!(before, after);
            let manifests = coding_agent_search::raw_mirror::manifest_views(&fixture.data_dir()).unwrap();
            assert_eq!(manifests.iter().filter(|m| m.original_path == untouched.to_str().unwrap()).count(), untouched_count);
            assert!(manifests.iter().filter(|m| m.original_path == changed.to_str().unwrap()).count() >= 2);
        }
    }
}

// ---------------------------------------------------------------------------
// A9 legacy pre-state
//
// The legacy-first row needs the database state an older, source-unaware CLI
// left behind: the conversation and its raw capture already exist and no
// source receipt does. The current CLI writes the receipt on its first run, so
// this one fixture's pre-state is built in a child process through public
// library primitives. Every ingestion under test still goes through the CLI.
// ---------------------------------------------------------------------------

const A9_SEED_CHILD: &str = "CASS_MIXED_A9_SEED_CHILD";
const A9_SEED_DATA_DIR: &str = "CASS_MIXED_A9_SEED_DATA_DIR";
const A9_SEED_MIRROR_ROOT: &str = "CASS_MIXED_A9_SEED_MIRROR_ROOT";
const A9_SEED_OK_MARKER: &str = "SOURCE_MIXED_A9_SEED_OK";
const A9_SEED_REMOTE_ID: &str = "remote-a";
const A9_SEED_REMOTE_HOST: &str = "host-remote-a";
/// The connector's own scan id for this fixture layout. Asserted before any
/// fixture value is assigned, so a layout change fails loudly.
const A9_SEED_SCAN_EXTERNAL_ID: &str = "projects/p/fallback.jsonl";
/// Fixed gold value for this one fixture. It is a constant, not an algorithm.
const A9_SEED_FIXED_EXTERNAL_ID: &str = "p/fallback.jsonl";
const A9_SEED_QUESTION: &str = "synthetic question";
const A9_SEED_ANSWER: &str = "fallback unique answer";
/// The six real counts the parent reads back from the child's report line.
const A9_SEED_COUNTS: [(&str, i64); 6] = [
    ("conversations", 1),
    ("messages", 2),
    ("source_inputs", 0),
    ("operation_commit_receipt", 0),
    ("scan_watermarks", 0),
    ("scan_file_state", 0),
];

/// Run the A9 seed child on this fixture and check its report.
fn expect_a9_seed_child(fixture: &Fixture, mirror_root: &Path) {
    let exe = std::env::current_exe().expect("the running test executable");
    let mut cmd = Command::new(exe);
    fixture.isolate(&mut cmd);
    cmd.env_remove("CASS_EXCLUDE_PATHS")
        .env(A9_SEED_CHILD, "1")
        .env(A9_SEED_DATA_DIR, fixture.data_dir())
        .env(A9_SEED_MIRROR_ROOT, mirror_root)
        .args([
            "--exact",
            "a9_db_fallback_declarations_preserve_identity",
            "--nocapture",
            "--test-threads=1",
        ]);
    let output = cmd.output().expect("spawn the A9 seed child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the A9 seed child must exit 0: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert_eq!(
        stdout.matches(A9_SEED_OK_MARKER).count(),
        1,
        "the A9 seed child must report {A9_SEED_OK_MARKER} exactly once\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let marker_at = stdout.find(A9_SEED_OK_MARKER).unwrap_or_else(|| {
        panic!("the A9 seed child must report {A9_SEED_OK_MARKER}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    let line_end = stdout[marker_at..]
        .find('\n')
        .map(|offset| marker_at + offset)
        .unwrap_or(stdout.len());
    let report = stdout[marker_at + A9_SEED_OK_MARKER.len()..line_end].trim();
    let counts: serde_json::Value = serde_json::from_str(report).unwrap_or_else(|error| {
        panic!("the A9 seed child counts must be JSON: {error}: {report}")
    });
    for (key, expected) in A9_SEED_COUNTS {
        assert_eq!(
            counts.get(key).and_then(serde_json::Value::as_i64),
            Some(expected),
            "the A9 seed child's real {key} count\nreport: {report}"
        );
    }
}

/// The child half: build the legacy pre-state inside the parent's fixture.
fn a9_seed_child() {
    use coding_agent_search::connectors::{
        get_connector_factories, Origin, Platform, ScanContext, ScanRoot,
    };
    use coding_agent_search::indexer::persist::map_to_internal;
    use coding_agent_search::model::types::{Agent, AgentKind};
    use coding_agent_search::raw_mirror::{
        capture_source_file, manifest_views, RawMirrorCaptureInput,
    };
    use coding_agent_search::sources::provenance::SourceKind;

    match std::env::var(A9_SEED_CHILD).as_deref() {
        Ok("1") => {}
        other => panic!("{A9_SEED_CHILD} must be the string 1 in the seed child, got {other:?}"),
    }
    let data_dir = std::env::var_os(A9_SEED_DATA_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{A9_SEED_DATA_DIR} is required in the seed child"));
    let mirror_root = std::env::var_os(A9_SEED_MIRROR_ROOT)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{A9_SEED_MIRROR_ROOT} is required in the seed child"));
    let session_path = mirror_root.join(A9_SEED_SCAN_EXTERNAL_ID);
    assert!(
        session_path.is_file(),
        "the fixture session must exist at {session_path:?}"
    );
    let db_path = data_dir.join("agent_search.db");
    assert!(
        db_path.is_file(),
        "the fixture database must exist at {db_path:?}"
    );

    // The parent registered the source. Read that registration once; the seed
    // must never write it again.
    let storage = FrankenStorage::open(&db_path).expect("open the fixture database");
    let registration_before = serde_json::to_value(
        storage
            .get_source(A9_SEED_REMOTE_ID)
            .expect("read the fixture source")
            .expect("the fixture source is registered"),
    )
    .expect("serialize the fixture source");
    storage
        .close()
        .expect("close after reading the registration");

    // 1. The connector's own legacy scan over the explicit remote root.
    let origin = Origin {
        source_id: A9_SEED_REMOTE_ID.to_string(),
        kind: SourceKind::Ssh,
        host: Some(A9_SEED_REMOTE_HOST.to_string()),
    };
    let scan_root = ScanRoot::remote(mirror_root.clone(), origin, Some(Platform::Linux));
    let context = ScanContext::with_roots(mirror_root.clone(), vec![scan_root], None);
    let factory = get_connector_factories()
        .into_iter()
        .find(|(name, _)| *name == "claude")
        .map(|(_, factory)| factory)
        .expect("the claude connector factory");
    let mut conversations = factory().scan(&context).expect("scan the fixture mirror");
    assert_eq!(
        conversations.len(),
        1,
        "the fixture holds exactly one conversation"
    );
    let mut conversation = conversations.remove(0);
    assert_eq!(
        conversation.external_id.as_deref(),
        Some(A9_SEED_SCAN_EXTERNAL_ID),
        "the connector's own id for this fixture layout must be asserted before any fixture value is assigned"
    );
    let bodies: Vec<String> = conversation
        .messages
        .iter()
        .map(|message| message.content.clone())
        .collect();
    assert_eq!(
        bodies,
        vec![A9_SEED_QUESTION.to_string(), A9_SEED_ANSWER.to_string()],
        "the fixture holds the two original messages"
    );

    // 2. Fixed data for this one fixture. The scan form is asserted above;
    //    these assignments are constants, not a normalizer.
    conversation.external_id = Some(A9_SEED_FIXED_EXTERNAL_ID.to_string());
    let cass = conversation
        .metadata
        .as_object_mut()
        .expect("the connector metadata is an object for this fixture")
        .entry("cass".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let cass = cass.as_object_mut().expect("cass is an object");
    cass.insert(
        "identity".to_string(),
        serde_json::json!({"identity_host": "local", "root_id": "local"}),
    );
    cass.insert(
        "origin".to_string(),
        serde_json::json!({
            "source_id": A9_SEED_REMOTE_ID,
            "kind": "ssh",
            "host": A9_SEED_REMOTE_HOST
        }),
    );

    // 3. The raw capture the later manifests assertion looks for.
    capture_source_file(RawMirrorCaptureInput {
        data_dir: &data_dir,
        provider: &conversation.agent_slug,
        source_id: A9_SEED_REMOTE_ID,
        origin_kind: "ssh",
        origin_host: Some(A9_SEED_REMOTE_HOST),
        source_path: &session_path,
        db_links: &[],
    })
    .expect("capture the fixture session");

    // 4. Persist through the public mapping and storage entry points.
    let internal = map_to_internal(&conversation);
    let storage = FrankenStorage::open(&db_path).expect("reopen the fixture database");
    let agent = Agent {
        id: None,
        slug: conversation.agent_slug.clone(),
        name: conversation.agent_slug.clone(),
        version: None,
        kind: AgentKind::Cli,
    };
    let agent_id = storage.ensure_agent(&agent).expect("ensure the agent");
    let workspace_id = conversation
        .workspace
        .as_deref()
        .map(|workspace| storage.ensure_workspace(workspace, None).expect("ensure the workspace"));
    storage
        .insert_conversation_tree(agent_id, workspace_id, &internal)
        .expect("insert the conversation tree");
    storage.close().expect("close after the seed");

    // 5. Check the pre-state the parent's assertions describe.
    let storage =
        FrankenStorage::open_readonly(&db_path).expect("open the fixture database read-only");
    let db = storage.raw();
    let counts = serde_json::json!({
        "conversations": scalar(db, "SELECT COUNT(*) FROM conversations"),
        "messages": scalar(db, "SELECT COUNT(*) FROM messages"),
        "source_inputs": scalar(db, "SELECT COUNT(*) FROM source_inputs"),
        "operation_commit_receipt": scalar(db, "SELECT COUNT(*) FROM operation_commit_receipt"),
        "scan_watermarks": scalar(db, "SELECT COUNT(*) FROM scan_watermarks"),
        "scan_file_state": scalar(db, "SELECT COUNT(*) FROM scan_file_state"),
    });
    for (key, expected) in A9_SEED_COUNTS {
        assert_eq!(
            counts.get(key).and_then(serde_json::Value::as_i64),
            Some(expected),
            "legacy pre-state count {key}: {counts}"
        );
    }
    let registration_after = serde_json::to_value(
        storage
            .get_source(A9_SEED_REMOTE_ID)
            .expect("read the fixture source")
            .expect("the fixture source is registered"),
    )
    .expect("serialize the fixture source");
    assert_eq!(
        registration_after, registration_before,
        "the seed must not change the source registration"
    );
    let stored: Vec<String> = db
        .query_all_map(
            "SELECT COALESCE(content,'') FROM messages ORDER BY idx",
            &[],
            |row| row.get_typed(0),
        )
        .expect("read the stored messages");
    assert_eq!(
        stored,
        vec![A9_SEED_QUESTION.to_string(), A9_SEED_ANSWER.to_string()],
        "the stored messages are the two original ones"
    );
    let conversation_id: i64 = db
        .query_row_map("SELECT id FROM conversations", &[], |row| row.get_typed(0))
        .expect("the seeded conversation id");
    let metadata = storage
        .conversation_metadata_for_tests(conversation_id)
        .expect("read the seeded conversation metadata");
    assert_eq!(
        metadata
            .pointer("/cass/identity/identity_host")
            .and_then(serde_json::Value::as_str),
        Some("local"),
        "seeded identity_host: {metadata}"
    );
    assert_eq!(
        metadata
            .pointer("/cass/identity/root_id")
            .and_then(serde_json::Value::as_str),
        Some("local"),
        "seeded identity root: {metadata}"
    );
    assert_eq!(
        metadata
            .pointer("/cass/origin/source_id")
            .and_then(serde_json::Value::as_str),
        Some(A9_SEED_REMOTE_ID),
        "seeded origin source: {metadata}"
    );
    assert_eq!(
        metadata
            .pointer("/cass/origin/kind")
            .and_then(serde_json::Value::as_str),
        Some("ssh"),
        "seeded origin kind: {metadata}"
    );
    assert_eq!(
        metadata
            .pointer("/cass/origin/host")
            .and_then(serde_json::Value::as_str),
        Some(A9_SEED_REMOTE_HOST),
        "seeded origin host: {metadata}"
    );
    let columns: (String, String, Option<String>, String, String) = db
        .query_row_map(
            "SELECT external_id, source_id, origin_host, identity_host, source_path FROM conversations",
            &[],
            |row| {
                Ok((
                    row.get_typed(0)?,
                    row.get_typed(1)?,
                    row.get_typed(2)?,
                    row.get_typed(3)?,
                    row.get_typed(4)?,
                ))
            },
        )
        .expect("the seeded conversation columns");
    assert_eq!(
        columns.0, A9_SEED_FIXED_EXTERNAL_ID,
        "seeded external_id column"
    );
    assert_eq!(columns.1, A9_SEED_REMOTE_ID, "seeded source_id column");
    assert_eq!(
        columns.2.as_deref(),
        Some(A9_SEED_REMOTE_HOST),
        "seeded origin_host column"
    );
    assert_eq!(columns.3, "local", "seeded identity_host column");
    assert_eq!(
        columns.4,
        session_path.to_str().unwrap(),
        "seeded source_path column"
    );
    let capture_present = manifest_views(&data_dir)
        .expect("read the raw mirror manifests")
        .iter()
        .any(|view| {
            view.source_id == A9_SEED_REMOTE_ID
                && view.identity_host == "local"
                && view.original_path == session_path.to_str().unwrap()
        });
    assert!(
        capture_present,
        "the raw capture manifest must exist for {session_path:?}"
    );

    println!("{A9_SEED_OK_MARKER} {counts}");
}

fn index_db_fallback(fixture: &Fixture, streaming: bool, safety: bool) -> Run {
    let mut cmd = Command::new(cass_bin());
    fixture.isolate(&mut cmd);
    cmd.env("CASS_IGNORE_SOURCES_CONFIG", "1")
        .env("CASS_STREAMING_INDEX", if streaming { "1" } else { "0" })
        .env("CASS_STREAMING_CONSUMER_COMBINE", "0")
        .args(["index", "--data-dir"]).arg(fixture.data_dir())
        .args(["--json", "--verbose"]);
    if safety { cmd.arg("--source-safety-config").arg(fixture.fixed_copy()); }
    Run::from(cmd.output().unwrap())
}

fn registered_source(id: &str, local: bool, path: &str) -> coding_agent_search::sources::provenance::Source {
    use coding_agent_search::sources::provenance::{Source, SourceKind};
    let mut source = Source::remote(id, format!("host-{id}"));
    if local { source.kind = SourceKind::Local; }
    source.machine_id = Some(format!("machine-{id}"));
    source.platform = Some("linux".into());
    source.config_json = Some(serde_json::json!({"paths":[path]}));
    source.created_at = Some(1_700_000_000_000);
    source.updated_at = Some(1_700_000_000_001);
    source
}

fn conversation_identities(storage: &FrankenStorage) -> Vec<String> {
    let records: Vec<(i64, String, String)> = storage.raw().query_all_map(
        "SELECT id, source_id, identity_host FROM conversations ORDER BY source_id", &[],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
    ).unwrap();
    records.into_iter().map(|(id, source, host)| {
        let metadata = storage.conversation_metadata_for_tests(id).unwrap();
        let root = metadata
            .pointer("/cass/identity/root_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("root identity missing for conversation {id} source={source} host={host}: {metadata}"));
        format!("{source}|{host}|{root}")
    }).collect()
}

#[test]
fn a9_db_fallback_declarations_preserve_identity() {
    if std::env::var_os(A9_SEED_CHILD).is_some() {
        a9_seed_child();
        return;
    }
    for streaming in [false, true] {
        for legacy_first in [false, true] {
            let fixture = Fixture::new();
            let remote_path = "/synthetic/claude";
            let source = registered_source("remote-a", false, remote_path);
            let storage = FrankenStorage::open(&fixture.db()).unwrap();
            storage.upsert_source(&source).unwrap();
            let expected = serde_json::to_value(storage.get_source("remote-a").unwrap()).unwrap();
            storage.close().unwrap();
            let root = fixture.data_dir().join("remotes/remote-a/mirror")
                .join(coding_agent_search::sources::sync::path_to_safe_dirname(remote_path));
            fixture.write_claude_session(&root, "projects/p/fallback.jsonl", "fallback-session", "fallback unique answer");
            if legacy_first {
                expect_a9_seed_child(&fixture, &root);
                assert_eq!(scalar(&fixture.open_db(), "SELECT COUNT(*) FROM conversations"), 1);
                assert_eq!(scalar(&fixture.open_db(), "SELECT COUNT(*) FROM source_inputs"), 0);
            }
            let mut stable = None;
            for _ in 0..2 {
                expect_success(&index_db_fallback(&fixture, streaming, true));
                let storage = FrankenStorage::open_readonly(&fixture.db()).unwrap();
                assert_eq!(serde_json::to_value(storage.get_source("remote-a").unwrap()).unwrap(), expected);
                let db = storage.raw();
                assert_eq!(complete_source_inputs_for(db, "claude_code"), 1);
                assert_eq!(scalar(db, "SELECT COUNT(*) FROM conversations"), 1,
                    "streaming={streaming} legacy_first={legacy_first} identities={:?} conversations={:?}",
                    conversation_identities(&storage), rows(db, "SELECT external_id || '|' || source_id || '|' || source_path FROM conversations ORDER BY external_id"));
                assert_eq!(messages_containing(db, "fallback unique answer"), 1);
                assert_eq!(rows(db, "SELECT DISTINCT identity_namespace FROM source_inputs"), vec!["local"]);
                assert_eq!(conversation_identities(&storage), vec!["remote-a|local|local"]);
                assert!(watermark_rows(db, "").is_empty());
                assert!(file_state_rows(db, "").is_empty());
                let now = (messages_fingerprint(db), conversations_fingerprint(db), inputs_fingerprint(db));
                if let Some(old) = &stable { assert_eq!(&now, old); }
                stable = Some(now);
                let manifests = coding_agent_search::raw_mirror::manifest_views(&fixture.data_dir()).unwrap();
                assert!(manifests.iter().any(|m| m.source_id == "remote-a" && m.identity_host == "local" && m.original_path == root.join("projects/p/fallback.jsonl").to_str().unwrap()));
            }
        }
        let fixture = Fixture::new();
        let root = fixture.path().join("shared-declaration");
        fixture.write_claude_session(&root, "projects/p/shared.jsonl", "shared-session", "shared declaration answer");
        let storage = FrankenStorage::open(&fixture.db()).unwrap();
        for id in ["one", "two"] { storage.upsert_source(&registered_source(id, true, root.to_str().unwrap())).unwrap(); }
        let expected = serde_json::to_value(storage.list_sources().unwrap()).unwrap();
        storage.close().unwrap();
        let mut stable = None;
        for _ in 0..2 {
            let run = index_db_fallback(&fixture, streaming, true);
            expect_success(&run);
            for source in ["one", "two"] {
                let digest = blake3::hash(root.canonicalize().unwrap().to_str().unwrap().as_bytes()).to_hex();
                let route = format!("cfg:{source}:{}", &digest[..16]);
                assert!(run.stderr.lines().any(|line| line.contains(DISPATCH_MARKER) && line.contains(&route)), "missing {route}: {}", run.stderr);
            }
            let storage = FrankenStorage::open_readonly(&fixture.db()).unwrap();
            assert_eq!(serde_json::to_value(storage.list_sources().unwrap()).unwrap(), expected);
            let db = storage.raw();
            assert_eq!(complete_source_inputs_for(db, "claude_code"), 2);
            assert_eq!(rows(db, "SELECT source_id FROM source_inputs ORDER BY source_id"), vec!["one", "two"]);
            assert_eq!(rows(db, "SELECT DISTINCT identity_namespace FROM source_inputs"), vec!["local"]);
            assert_eq!(scalar(db, "SELECT COUNT(DISTINCT input_key) FROM source_inputs"), 2);
            let provenance = conversation_identities(&storage);
            // Same namespace/agent/external-id keeps the existing canonical
            // conversation. Each declaration retains its own source facts.
            assert_eq!(provenance.len(), 1);
            assert_eq!(scalar(db, "SELECT COUNT(*) FROM messages"), 2);
            let all_messages = rows(db, "SELECT CAST(id AS TEXT) FROM messages ORDER BY id");
            for source in ["one", "two"] {
                let linked = rows(db, &format!("SELECT CAST(l.message_id AS TEXT) FROM source_inputs i JOIN source_records r ON r.input_id=i.id JOIN source_message_links l ON l.record_id=r.id WHERE i.source_id='{source}' AND l.authority='canonical' ORDER BY l.message_id"));
                assert_eq!(linked, all_messages, "{source} must bind both messages");
                assert_eq!(scalar(db, &format!("SELECT COUNT(*) FROM source_inputs i JOIN source_records r ON r.input_id=i.id WHERE i.source_id='{source}' AND r.frame_state='activated' AND r.parse_state='parsed'")), 2);
                assert_eq!(scalar(db, &format!("SELECT COUNT(*) FROM source_inputs i JOIN operation_commit_receipt c ON c.idempotency_key=i.receipt_key WHERE i.source_id='{source}' AND c.state='committed'")), 1);
                assert!(coding_agent_search::raw_mirror::manifest_views(&fixture.data_dir()).unwrap().iter().any(|m| m.source_id == source && m.original_path == root.join("projects/p/shared.jsonl").to_str().unwrap()));
            }
            let source_identities = rows(db, "SELECT source_id || '|' || hex(input_key) || '|' || hex(root_id_bin) || '|' || hex(relative_locator_bin) || '|' || receipt_key FROM source_inputs ORDER BY source_id");
            assert_eq!(scalar(db, "SELECT COUNT(*) FROM operation_commit_receipt"), 2);
            assert!(watermark_rows(db, "").is_empty());
            assert!(file_state_rows(db, "").is_empty());
            let now = (messages_fingerprint(db), provenance, source_identities);
            if let Some(old) = &stable { assert_eq!(&now, old); }
            stable = Some(now);
        }
    }
}

/// A4: a legacy connector under a configured root reads its file on the first
/// run, records its own watermark and per-file state, and is not re-read on the
/// next run with the same unchanged file -- all while carrying no source
/// receipt at all.
#[test]
fn a4_other_connector_legacy_watermark() {
    for streaming in [false, true] {
        let fixture = Fixture::new();
        let root = fixture.path().join("legacy-only");
        fixture.write_gemini(
            &root,
            "hash909/chats/session-legacy.json",
            &gemini_session(
                "sess-mixed-legacy",
                GEMINI_WATERMARK_PHRASE,
                "synthetic mixed gemini watermark reply",
            ),
        );
        fixture.write_sources(&[("laptop", "local", "laptop", root.to_str().unwrap(), false)]);

        let first = fixture.index_cell(streaming);
        assert_eq!(
            first.code,
            Some(0),
            "the first run reads the legacy root; stderr={}",
            first.stderr
        );
        assert!(
            !first.stderr.contains("Unsupported"),
            "the legacy connector must not reach the sealed read; stderr={}",
            first.stderr
        );

        let (conversations, messages) = first
            .connector_read("gemini")
            .expect("the first run reports the legacy conversation it read");
        assert_eq!(
            (conversations, messages),
            (1, 2),
            "the first run really read the one legacy session and its two turns"
        );

        let db = fixture.open_db();
        assert_eq!(
            messages_containing(&db, GEMINI_WATERMARK_PHRASE),
            1,
            "the legacy message value landed"
        );
        assert_eq!(
            source_inputs_for(&db, "gemini"),
            0,
            "the legacy connector writes no source input, in either run"
        );
        let first_watermarks = watermark_rows(&db, "cfg:laptop:");
        assert!(
            first_watermarks.iter().any(|row| row.contains("|gemini|")),
            "the first run wrote the legacy connector's own watermark row: {first_watermarks:#?}"
        );
        let first_file_states = file_state_rows(&db, "cfg:laptop:");
        assert!(
            first_file_states
                .iter()
                .any(|row| row.contains("|gemini|") && row.contains("session-legacy.json")),
            "the first run recorded the file's own state: {first_file_states:#?}"
        );
        drop(db);

        // The second run over the same unchanged file takes the legacy skip: no
        // conversation is read again, the message is neither lost nor duplicated,
        // and the state the first run wrote is untouched.
        let second = fixture.index_cell(streaming);
        assert_eq!(
            second.code,
            Some(0),
            "the repeat run succeeds; stderr={}",
            second.stderr
        );
        assert!(
            matches!(second.connector_read("gemini"), None | Some((0, 0))),
            "an unchanged legacy file is not read again -- the run reports no gemini work; \
             stderr={}",
            second.stderr
        );
        let db = fixture.open_db();
        assert_eq!(
            messages_containing(&db, GEMINI_WATERMARK_PHRASE),
            1,
            "the repeat run neither duplicates nor loses the legacy message"
        );
        assert_eq!(
            file_state_rows(&db, "cfg:laptop:"),
            first_file_states,
            "the repeat run leaves the file's state exactly as the first run wrote it"
        );
        assert_eq!(
            source_inputs_for(&db, "gemini"),
            0,
            "the absence of a source receipt never forces a re-read"
        );
    }
}

// ---------------------------------------------------------------------------
// Task 35: watch entries consume the unique ownership and the capability
// dispatch. Every case drives the real CLI over a private synthetic HOME and
// reads the resulting database; no helper below reimplements discovery or the
// ownership decision.
// ---------------------------------------------------------------------------

const OPENHANDS_PHRASE: &str = "synthetic task35 openhands event body";
const TASK35_CODEX_PHRASE: &str = "synthetic task35 healthy codex body";
const TASK35_ONE_PHRASE: &str = "synthetic task35 gemini one body";
const TASK35_TWO_PHRASE: &str = "synthetic task35 gemini two body";

/// Write the verified OpenHands sample shape under `root`: one conversation
/// directory with two `MessageEvent` files, each carrying the
/// `llm_message.role/content` pair the real discovery and parser read.
///
/// The layout (`conversation/events/event-*.json`) and the size of the sample
/// are the verified sample shape: Claude claims both `.json` files and
/// OpenHands claims both event files, and the real resolver returns
/// `Owner(openhands)` for both paths.
fn write_openhands_events(root: &Path, id: &str) -> Vec<PathBuf> {
    let events = root.join("conversation/events");
    std::fs::create_dir_all(&events).expect("mkdir openhands events");
    let sample = [
        ("event-00000-user.json", "user", OPENHANDS_PHRASE),
        (
            "event-00001-assistant.json",
            "assistant",
            "synthetic task35 openhands reply",
        ),
    ];
    let mut written = Vec::new();
    for (index, (name, role, text)) in sample.iter().enumerate() {
        let path = events.join(name);
        std::fs::write(
            &path,
            serde_json::json!({
                "id": format!("event-{id}-{index}"),
                "timestamp": "2026-01-01T00:00:00Z",
                "kind": "MessageEvent",
                "source": role,
                "llm_message": {
                    "role": role,
                    "content": [{"type": "text", "text": text}],
                },
            })
            .to_string(),
        )
        .expect("write openhands event");
        written.push(path);
    }
    written
}

/// A10: an owner without this build's watch capability is refused in both
/// watch modes, and the healthy declaration beside it still lands. The refusal
/// is proved from the real discovery and resolver, not from a hand-made owner.
#[test]
fn a10_watch_unsupported_owner_preserves_healthy_units() {
    for mode in ["watch_once", "resident"] {
        let fixture = Fixture::new();
        fixture.create_home_roots();
        let declared = fixture.path().join("declared");
        fixture.write_sources(&[(
            "laptop",
            "local",
            "laptop",
            declared.to_str().expect("utf-8 declared root"),
            false,
        )]);
        // The configured root must exist before the resident process registers
        // its watcher, or the later event has no watch to fire on.
        std::fs::create_dir_all(&declared).expect("mkdir the declared root");

        match mode {
            "watch_once" => {
                write_openhands_events(&declared, "once");
                let codex = fixture.write_codex_session(
                    &fixture.home().join(".codex"),
                    "sessions/2026/01/rollout-task35-a10.jsonl",
                    "sess-task35-a10-codex",
                    TASK35_CODEX_PHRASE,
                );
                let run = fixture.index_with(&[
                    "--watch-once",
                    declared.to_str().expect("utf-8 declared root"),
                    "--watch-once",
                    codex.to_str().expect("utf-8 codex path"),
                ]);
                assert_ne!(
                    run.code,
                    Some(0),
                    "a watch-once run with a refused unit must fail; stderr={}",
                    run.stderr
                );
                assert!(
                    run.stderr.contains("source_ownership_unsupported_watch"),
                    "the refusal names the unsupported owner: {}",
                    run.stderr
                );
                let db = fixture.open_db();
                assert_eq!(
                    complete_source_inputs_for(&db, "codex"),
                    1,
                    "the healthy codex declaration still lands"
                );
                assert_eq!(messages_containing(&db, TASK35_CODEX_PHRASE), 1);
                assert_eq!(
                    messages_containing(&db, OPENHANDS_PHRASE),
                    0,
                    "the refused unit never reaches a writer"
                );
                assert_eq!(source_inputs_for(&db, "openhands"), 0);
            }
            _ => {
                let mut resident = Resident::start(&fixture);
                assert!(
                    resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
                    "the resident watch loop must reach its event cycle: {}",
                    resident.log()
                );
                write_openhands_events(&declared, "resident");
                fixture.write_codex_session(
                    &fixture.home().join(".codex"),
                    "sessions/2026/01/rollout-task35-a10-resident.jsonl",
                    "sess-task35-a10-resident",
                    TASK35_CODEX_PHRASE,
                );
                resident.poll_until(
                    "the healthy codex event to reach the database",
                    Duration::from_secs(240),
                    || {
                        let db = fixture.try_open_db()?;
                        (messages_containing(&db, TASK35_CODEX_PHRASE) >= 1).then_some(())
                    },
                );
                assert!(
                    resident.wait_for("source_ownership_unsupported_watch", Duration::from_secs(60)),
                    "the resident cycle reports the refused owner: {}",
                    resident.log()
                );
                assert!(
                    resident.child.try_wait().expect("probe the resident process").is_none(),
                    "the resident process keeps listening after a refused unit: {}",
                    resident.log()
                );
                resident.stop();
                let db = fixture.open_db();
                assert_eq!(messages_containing(&db, OPENHANDS_PHRASE), 0);
                assert!(
                    complete_source_inputs_for(&db, "codex") >= 1,
                    "the healthy codex event landed through the sealed kernel"
                );
            }
        }
    }
}

/// Provenance rows (`source_id|identity_host`) for conversations whose
/// external id ends with `suffix`.
fn conversation_provenance(db: &Conn, suffix: &str) -> Vec<String> {
    rows(
        db,
        &format!(
            "SELECT source_id || '|' || COALESCE(identity_host,'') FROM conversations \
             WHERE source_path LIKE '%{suffix}' ORDER BY 1"
        ),
    )
}

/// A11: an explicit Gemini selection stays bounded, and the message it writes
/// carries the declaration's own identity.
///
/// (a) The native HOME root and a configured declaration over the same
/// physical root are two declarations: an ordinary run reads the file through
/// both, each with its own source identity.
/// (b) A fresh fixture selects one file: only that body is read, and its
/// conversation is rooted in the configured declaration.
/// (c) A third fresh fixture selects the declared directory: both bodies are
/// read under the same declaration.
#[test]
fn a11_watch_gemini_selection_and_declaration_identity() {
    // (a) native HOME + configured declaration over the same physical root.
    {
        let fixture = Fixture::new();
        let home_gemini = fixture.home().join(".gemini/tmp");
        fixture.write_gemini(
            &home_gemini,
            "hash-one/chats/session-one.json",
            &gemini_session("task35-one", TASK35_ONE_PHRASE, "task35 reply one"),
        );
        fixture.write_sources(&[(
            "laptop",
            "local",
            "laptop",
            home_gemini.to_str().expect("utf-8 gemini root"),
            false,
        )]);
        let run = fixture.index_cell(false);
        expect_success(&run);
        assert!(
            !run.stderr.contains("Unsupported"),
            "the legacy connector is never pushed onto the sealed read: {}",
            run.stderr
        );
        let db = fixture.open_db();
        // Both declarations read the one file, so the body lands once per
        // declaration; the point is that each keeps its own identity.
        assert_eq!(messages_containing(&db, TASK35_ONE_PHRASE), 2);
        let provenance = conversation_provenance(&db, "session-one.json");
        assert_eq!(provenance.len(), 2, "{provenance:?}");
        assert!(
            provenance.iter().any(|row| row.starts_with("local|")),
            "the native HOME declaration keeps its own identity: {provenance:?}"
        );
        assert!(
            provenance.iter().any(|row| row.starts_with("laptop|")),
            "the configured declaration adds its own identity for the same file: {provenance:?}"
        );
        assert_eq!(
            source_inputs_for(&db, "gemini"),
            0,
            "a legacy connector writes no source input"
        );
    }

    // (b) one selected file, independent fixture.
    {
        let fixture = Fixture::new();
        let root = fixture.home().join(".gemini/tmp");
        let one = fixture.write_gemini(
            &root,
            "hash-one/chats/session-one.json",
            &gemini_session("task35-one", TASK35_ONE_PHRASE, "task35 reply one"),
        );
        fixture.write_gemini(
            &root,
            "hash-two/chats/session-two.json",
            &gemini_session("task35-two", TASK35_TWO_PHRASE, "task35 reply two"),
        );
        fixture.write_sources(&[(
            "laptop",
            "local",
            "laptop",
            root.to_str().expect("utf-8 declared root"),
            false,
        )]);

        let run = fixture.index_with(&["--watch-once", one.to_str().expect("utf-8 selection")]);
        expect_success(&run);
        assert!(
            !run.stderr.contains("Unsupported"),
            "the legacy connector is never pushed onto the sealed read: {}",
            run.stderr
        );
        let db = fixture.open_db();
        let provenance = conversation_provenance(&db, "session-one.json");
        assert_eq!(
            messages_containing(&db, TASK35_ONE_PHRASE),
            2,
            "the selected file is read through the native and the configured declaration: \
             {provenance:?} stderr={}",
            run.stderr
        );
        assert_eq!(
            messages_containing(&db, TASK35_TWO_PHRASE),
            0,
            "the single-file selection must not read the sibling"
        );
        assert_eq!(provenance.len(), 2, "{provenance:?}");
        assert!(provenance.iter().any(|row| row.starts_with("local|")), "{provenance:?}");
        assert!(provenance.iter().any(|row| row.starts_with("laptop|")), "{provenance:?}");
        assert_eq!(source_inputs_for(&db, "gemini"), 0);
        drop(db);

        let storage = FrankenStorage::open_readonly(&fixture.db()).expect("open read-only");
        let identities = conversation_identities(&storage);
        assert_eq!(identities.len(), 2, "{identities:?}");
        assert!(
            identities.iter().any(|line| line.ends_with("|local|local")),
            "the native declaration keeps its local/local identity: {identities:?}"
        );
        assert!(
            identities
                .iter()
                .any(|line| line.starts_with("laptop|") && line.contains("cfg:laptop:")),
            "the configured declaration keeps its own identity: {identities:?}"
        );
    }

    // (c) the declared directory, independent fixture.
    {
        let fixture = Fixture::new();
        let root = fixture.home().join(".gemini/tmp");
        fixture.write_gemini(
            &root,
            "hash-one/chats/session-one.json",
            &gemini_session("task35-one", TASK35_ONE_PHRASE, "task35 reply one"),
        );
        fixture.write_gemini(
            &root,
            "hash-two/chats/session-two.json",
            &gemini_session("task35-two", TASK35_TWO_PHRASE, "task35 reply two"),
        );
        fixture.write_sources(&[(
            "laptop",
            "local",
            "laptop",
            root.to_str().expect("utf-8 declared root"),
            false,
        )]);

        let run = fixture.index_with(&["--watch-once", root.to_str().expect("utf-8 root")]);
        expect_success(&run);
        let db = fixture.open_db();
        assert_eq!(messages_containing(&db, TASK35_ONE_PHRASE), 2);
        assert_eq!(messages_containing(&db, TASK35_TWO_PHRASE), 2);
        for file in ["session-one.json", "session-two.json"] {
            let provenance = conversation_provenance(&db, file);
            assert_eq!(provenance.len(), 2, "{file}: {provenance:?}");
            assert!(provenance.iter().any(|row| row.starts_with("local|")), "{file}: {provenance:?}");
            assert!(provenance.iter().any(|row| row.starts_with("laptop|")), "{file}: {provenance:?}");
        }
        assert_eq!(source_inputs_for(&db, "gemini"), 0);
        drop(db);

        let storage = FrankenStorage::open_readonly(&fixture.db()).expect("open read-only");
        let identities = conversation_identities(&storage);
        assert_eq!(identities.len(), 4, "{identities:?}");
        assert_eq!(
            identities.iter().filter(|line| line.ends_with("|local|local")).count(),
            2,
            "each file keeps the native declaration's identity: {identities:?}"
        );
        assert_eq!(
            identities
                .iter()
                .filter(|line| line.starts_with("laptop|") && line.contains("cfg:laptop:"))
                .count(),
            2,
            "each file keeps the configured declaration's identity: {identities:?}"
        );
    }
}

const TASK35_RESIDENT_PHRASE: &str = "synthetic task35 resident declaration body";

fn input_rows_for(db: &Conn, suffix: &str) -> Vec<String> {
    rows(
        db,
        &format!(
            "SELECT hex(input_key) || '|' || CAST(relative_locator_bin AS TEXT) FROM source_inputs \
             WHERE CAST(relative_locator_bin AS TEXT) LIKE '%{suffix}' ORDER BY 1"
        ),
    )
}

fn complete_inputs_for_suffix(db: &Conn, suffix: &str) -> i64 {
    rows(
        db,
        &format!(
            "SELECT CAST(id AS TEXT) FROM source_inputs WHERE state='complete' \
             AND CAST(relative_locator_bin AS TEXT) LIKE '%{suffix}'"
        ),
    )
    .len() as i64
}

/// A12: a resident event reads the declaration unit it belongs to, and a
/// sibling declaration the event never touched is not re-selected.
#[test]
fn a12_resident_event_reads_selected_declaration_unit() {
    let fixture = Fixture::new();
    let root_a = fixture.path().join("declaration-a");
    let root_b = fixture.path().join("declaration-b");
    fixture.write_sources(&[
        (
            "laptop",
            "local",
            "laptop",
            root_a.to_str().expect("utf-8 root a"),
            false,
        ),
        (
            "archive",
            "local",
            "archive",
            root_b.to_str().expect("utf-8 root b"),
            false,
        ),
    ]);
    fixture.write_claude_session(
        &root_a,
        "projects/p/one.jsonl",
        "sess-task35-a12-one",
        TASK35_RESIDENT_PHRASE,
    );
    fixture.write_claude_session(
        &root_a,
        "projects/p/two.jsonl",
        "sess-task35-a12-two",
        "synthetic task35 untouched sibling body",
    );
    fixture.write_claude_session(
        &root_b,
        "projects/p/three.jsonl",
        "sess-task35-a12-three",
        "synthetic task35 other declaration body",
    );

    let mut resident = Resident::start(&fixture);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );
    resident.poll_until(
        "the startup scan to land all three inputs",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (complete_source_inputs_for(&db, "claude_code") >= 3).then_some(())
        },
    );
    let (b_before, a_two_before, one_before) = {
        let db = fixture.open_db();
        (
            input_rows_for(&db, "three.jsonl"),
            input_rows_for(&db, "two.jsonl"),
            complete_inputs_for_suffix(&db, "one.jsonl"),
        )
    };

    // The only event: append one turn to the first file of declaration A.
    let mut lines = claude_session(
        "sess-task35-a12-one",
        "synthetic appended question",
        "synthetic appended answer after the event",
    );
    let path = root_a.join("projects/p/one.jsonl");
    let mut existing = std::fs::read_to_string(&path).expect("read the session");
    if !existing.ends_with('\n') {
        existing.push('\n');
    }
    for line in lines.drain(..) {
        existing.push_str(&line.to_string());
        existing.push('\n');
    }
    std::fs::write(&path, existing).expect("append to the session");

    resident.poll_until(
        "the event to land through the declaration",
        Duration::from_secs(240),
        || {
            let db = fixture.try_open_db()?;
            (messages_containing(&db, "synthetic appended answer after the event") >= 1).then_some(())
        },
    );
    assert!(
        resident.log().contains("resident_source_watch_trigger connector=claude"),
        "the event is read through the declaration's source trigger: {}",
        resident.log()
    );

    // Settle one more debounce window: a repeated event must not mint a second
    // identical source fact.
    std::thread::sleep(Duration::from_secs(5));
    resident.stop();

    let db = fixture.open_db();
    assert_eq!(
        input_rows_for(&db, "three.jsonl"),
        b_before,
        "the untouched sibling declaration is not re-selected"
    );
    assert_eq!(
        input_rows_for(&db, "two.jsonl"),
        a_two_before,
        "the unchanged file of the same declaration is not re-minted"
    );
    assert_eq!(
        complete_inputs_for_suffix(&db, "one.jsonl"),
        one_before + 1,
        "the changed file gains exactly one completed revision"
    );
}

const TASK35_CLAUDE_PHRASE: &str = "synthetic task35 healthy claude body";

/// A13: a legacy unit whose sidecar conflicts is refused as a whole in both
/// watch modes, while a healthy first-batch declaration beside it lands.
#[test]
fn a13_watch_legacy_sidecar_conflict_refuses_unit() {
    for mode in ["watch_once", "resident"] {
        let fixture = Fixture::new();
        fixture.create_home_roots();
        let root = fixture.path().join("declared");
        fixture.write_sources(&[(
            "laptop",
            "local",
            "laptop",
            root.to_str().expect("utf-8 declared root"),
            false,
        )]);
        // Registered before the resident watcher starts, so the later event
        // under this declaration has a watch to fire on.
        std::fs::create_dir_all(&root).expect("mkdir the declared root");
        let claude = fixture.write_claude_session(
            &fixture.home().join(".claude/projects"),
            "synthetic/-a13/healthy.jsonl",
            "sess-task35-a13-claude",
            TASK35_CLAUDE_PHRASE,
        );

        match mode {
            "watch_once" => {
                copy_opencode_fixture(&root, true);
                let run = fixture.index_with(&[
                    "--watch-once",
                    root.to_str().expect("utf-8 declared root"),
                    "--watch-once",
                    claude.to_str().expect("utf-8 claude path"),
                ]);
                assert_ne!(
                    run.code,
                    Some(0),
                    "the refused legacy unit fails the one-shot run; stderr={}",
                    run.stderr
                );
                assert!(
                    run.stderr.contains("source_ownership_ambiguous"),
                    "the conflict is named as ambiguous evidence: {}",
                    run.stderr
                );
                let db = fixture.open_db();
                assert_eq!(
                    scalar(&db, "SELECT COUNT(*) FROM conversations WHERE external_id='ses_test1'"),
                    0,
                    "the conflicted OpenCode unit is not persisted"
                );
                assert_eq!(source_inputs_for(&db, "opencode"), 0);
                assert_eq!(
                    messages_containing(&db, TASK35_CLAUDE_PHRASE),
                    1,
                    "the healthy first-batch declaration still lands"
                );
            }
            _ => {
                let mut resident = Resident::start(&fixture);
                assert!(
                    resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
                    "the resident watch loop must reach its event cycle: {}",
                    resident.log()
                );
                copy_opencode_fixture(&root, true);
                fixture.write_claude_session(
                    &fixture.home().join(".claude/projects"),
                    "synthetic/-a13/resident-healthy.jsonl",
                    "sess-task35-a13-resident",
                    TASK35_CLAUDE_PHRASE,
                );
                resident.poll_until(
                    "the healthy first-batch event to land",
                    Duration::from_secs(240),
                    || {
                        let db = fixture.try_open_db()?;
                        (messages_containing(&db, TASK35_CLAUDE_PHRASE) >= 1).then_some(())
                    },
                );
                assert!(
                    resident.wait_for("source_ownership_ambiguous", Duration::from_secs(60)),
                    "the resident cycle reports the refused unit: {}",
                    resident.log()
                );
                assert!(
                    resident.child.try_wait().expect("probe the resident process").is_none(),
                    "the resident process keeps listening after a refused unit: {}",
                    resident.log()
                );
                resident.stop();
                let db = fixture.open_db();
                assert_eq!(
                    scalar(&db, "SELECT COUNT(*) FROM conversations WHERE external_id='ses_test1'"),
                    0
                );
                assert_eq!(
                    messages_containing(&db, TASK35_CLAUDE_PHRASE),
                    1,
                    "the healthy declaration landed"
                );
            }
        }
        let _ = claude;
    }
}

fn watch_once_db_fallback(fixture: &Fixture, paths: &[&Path]) -> Run {
    let mut cmd = Command::new(cass_bin());
    fixture.isolate(&mut cmd);
    cmd.env("CASS_IGNORE_SOURCES_CONFIG", "1");
    cmd.args(["index", "--data-dir"])
        .arg(fixture.data_dir())
        .arg("--source-safety-config")
        .arg(fixture.fixed_copy())
        .args(["--json", "--verbose"]);
    for path in paths {
        cmd.arg("--watch-once").arg(path);
    }
    Run::from(cmd.output().expect("spawn cass index"))
}

fn registered_source_with_paths(
    id: &str,
    local: bool,
    paths: &[&str],
) -> coding_agent_search::sources::provenance::Source {
    let mut source = registered_source(id, local, paths.first().copied().unwrap_or(""));
    source.config_json = Some(serde_json::json!({ "paths": paths }));
    source
}

/// A14: two DB-backed declarations keep their own identity through the watch
/// entries: two sources over one root stay two, and one source over two roots
/// keeps both.
#[test]
fn a14_watch_db_fallback_declarations_stay_distinct() {
    let fixture = Fixture::new();
    let shared = fixture.path().join("shared-declaration");
    let first = fixture.write_claude_session(
        &shared,
        "projects/p/one.jsonl",
        "sess-task35-a14-one",
        "synthetic task35 shared declaration body",
    );
    {
        let storage = FrankenStorage::open(&fixture.db()).expect("open storage");
        for id in ["one", "two"] {
            storage
                .upsert_source(&registered_source_with_paths(
                    id,
                    true,
                    &[shared.to_str().expect("utf-8 shared root")],
                ))
                .expect("register the declaration");
        }
        storage.close().expect("close storage");
    }
    let run = watch_once_db_fallback(&fixture, &[&first]);
    expect_success(&run);
    let db = fixture.open_db();
    assert_eq!(
        complete_source_inputs_for(&db, "claude_code"),
        2,
        "two sources over one root keep two independent inputs: {}",
        run.stderr
    );
    assert_eq!(
        rows(&db, "SELECT source_id FROM source_inputs ORDER BY source_id"),
        vec!["one", "two"]
    );
    assert_eq!(
        rows(&db, "SELECT DISTINCT identity_namespace FROM source_inputs"),
        vec!["local"],
        "a missing-meta declaration keeps the transitional local identity"
    );
    // Two declarations over one root share one canonical conversation (same
    // namespace, agent and external id), exactly as the verified A9 case
    // states; their independence is carried by the two source inputs and
    // their own records, links and receipts.
    assert_eq!(
        scalar(&db, "SELECT COUNT(DISTINCT input_key) FROM source_inputs"),
        2,
        "each declaration keeps its own input identity"
    );
    let all_messages = rows(&db, "SELECT CAST(id AS TEXT) FROM messages ORDER BY id");
    for source in ["one", "two"] {
        let linked = rows(
            &db,
            &format!(
                "SELECT CAST(l.message_id AS TEXT) FROM source_inputs i \
                 JOIN source_records r ON r.input_id=i.id \
                 JOIN source_message_links l ON l.record_id=r.id \
                 WHERE i.source_id='{source}' AND l.authority='canonical' ORDER BY l.message_id"
            ),
        );
        assert_eq!(linked, all_messages, "{source} binds both messages");
        assert_eq!(
            scalar(
                &db,
                &format!(
                    "SELECT COUNT(*) FROM source_inputs i JOIN source_records r ON r.input_id=i.id \
                     WHERE i.source_id='{source}' AND r.frame_state='activated' AND r.parse_state='parsed'"
                )
            ),
            2
        );
        assert_eq!(
            scalar(
                &db,
                &format!(
                    "SELECT COUNT(*) FROM source_inputs i \
                     JOIN operation_commit_receipt c ON c.idempotency_key=i.receipt_key \
                     WHERE i.source_id='{source}' AND c.state='committed'"
                )
            ),
            1
        );
    }
    {
        let storage = FrankenStorage::open_readonly(&fixture.db()).expect("open read-only");
        let identities = conversation_identities(&storage);
        assert_eq!(
            identities.len(),
            1,
            "the shared canonical conversation keeps one row: {identities:?}"
        );
        assert!(
            identities[0].contains("cfg:"),
            "the canonical row is rooted in a declaration: {identities:?}"
        );
    }
    let first_fingerprint = (
        messages_fingerprint(&db),
        conversations_fingerprint(&db),
        inputs_fingerprint(&db),
    );
    drop(db);

    // Replay: the same selections mint nothing new.
    let replay = watch_once_db_fallback(&fixture, &[&first]);
    expect_success(&replay);
    let db = fixture.open_db();
    assert_eq!(
        (
            messages_fingerprint(&db),
            conversations_fingerprint(&db),
            inputs_fingerprint(&db)
        ),
        first_fingerprint,
        "a replay of the same selection adds no source fact"
    );
    drop(db);

    // One source over two roots: both roots are read and neither is folded
    // into the other by the transitional local root id. The remote paths are
    // mirrored under the data directory exactly as the A9 case lays them out;
    // the watch selects the real mirror files.
    let fixture_two = Fixture::new();
    let remote_a = "/synthetic/task35-remote-a";
    let remote_b = "/synthetic/task35-remote-b";
    let mirror_root = |remote: &str| {
        fixture_two
            .data_dir()
            .join("remotes/remote-a/mirror")
            .join(coding_agent_search::sources::sync::path_to_safe_dirname(remote))
    };
    let root_a = mirror_root(remote_a);
    let root_b = mirror_root(remote_b);
    std::fs::create_dir_all(&root_a).expect("mkdir mirror a");
    std::fs::create_dir_all(&root_b).expect("mkdir mirror b");
    let file_a = fixture_two.write_claude_session(
        &root_a,
        "projects/p/a.jsonl",
        "sess-task35-a14-a",
        "synthetic task35 two roots a",
    );
    let file_b = fixture_two.write_claude_session(
        &root_b,
        "projects/p/b.jsonl",
        "sess-task35-a14-b",
        "synthetic task35 two roots b",
    );
    {
        let storage = FrankenStorage::open(&fixture_two.db()).expect("open storage");
        storage
            .upsert_source(&registered_source_with_paths(
                "remote-a",
                false,
                &[remote_a, remote_b],
            ))
            .expect("register the source");
        storage.close().expect("close storage");
    }
    let run = watch_once_db_fallback(&fixture_two, &[&file_a, &file_b]);
    expect_success(&run);
    let db = fixture_two.open_db();
    assert_eq!(
        complete_source_inputs_for(&db, "claude_code"),
        2,
        "both roots of one source are read: {}",
        run.stderr
    );
    let roots: Vec<String> = db
        .query_all_map(
            "SELECT DISTINCT hex(root_id_bin) FROM source_inputs ORDER BY 1",
            &[],
            |row| row.get_typed(0),
        )
        .expect("query input roots");
    assert_eq!(roots.len(), 2, "the two roots keep distinct input identities: {roots:?}");
    assert_eq!(
        rows(&db, "SELECT DISTINCT source_id FROM source_inputs"),
        vec!["remote-a"]
    );
    assert_eq!(
        rows(&db, "SELECT DISTINCT identity_namespace FROM source_inputs"),
        vec!["local"],
        "a source without metadata keeps the transitional local namespace"
    );
    assert!(
        watermark_rows(&db, "").is_empty(),
        "a source without metadata writes no watermark row"
    );
    assert!(
        file_state_rows(&db, "").is_empty(),
        "a source without metadata writes no file-state row"
    );
    {
        let storage = FrankenStorage::open_readonly(&fixture_two.db()).expect("open read-only");
        let identities = conversation_identities(&storage);
        assert!(
            !identities.is_empty()
                && identities.iter().all(|line| line == "remote-a|local|local"),
            "the missing-meta source keeps the local/local identity: {identities:?}"
        );
    }

    // Resident: two sources over one root keep two declarations through a real
    // event cycle as well.
    let fixture_resident = Fixture::new();
    let resident_root = fixture_resident.path().join("resident-shared");
    std::fs::create_dir_all(&resident_root).expect("mkdir resident root");
    {
        let storage = FrankenStorage::open(&fixture_resident.db()).expect("open storage");
        for id in ["one", "two"] {
            storage
                .upsert_source(&registered_source_with_paths(
                    id,
                    true,
                    &[resident_root.to_str().expect("utf-8 resident root")],
                ))
                .expect("register the declaration");
        }
        storage.close().expect("close storage");
    }
    let mut resident = Resident::start_db_backed(&fixture_resident);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );
    fixture_resident.write_claude_session(
        &resident_root,
        "projects/p/late.jsonl",
        "sess-task35-a14-late",
        "synthetic task35 resident shared body",
    );
    resident.poll_until(
        "both declarations to read the event",
        Duration::from_secs(240),
        || {
            let db = fixture_resident.try_open_db()?;
            (complete_source_inputs_for(&db, "claude_code") >= 2).then_some(())
        },
    );
    resident.stop();
    let db = fixture_resident.open_db();
    assert_eq!(
        complete_source_inputs_for(&db, "claude_code"),
        2,
        "both declarations read the resident event"
    );
    assert_eq!(
        rows(&db, "SELECT source_id FROM source_inputs ORDER BY source_id"),
        vec!["one", "two"]
    );

    // Resident, one source over two roots: an event in each root is read, the
    // two roots keep distinct input identities, and a later event in one root
    // adds only that file's revision.
    let fixture_roots = Fixture::new();
    let remote_ra = "/synthetic/task35-resident-a";
    let remote_rb = "/synthetic/task35-resident-b";
    let resident_mirror = |remote: &str| {
        fixture_roots
            .data_dir()
            .join("remotes/remote-r/mirror")
            .join(coding_agent_search::sources::sync::path_to_safe_dirname(remote))
    };
    let resident_a = resident_mirror(remote_ra);
    let resident_b = resident_mirror(remote_rb);
    std::fs::create_dir_all(&resident_a).expect("mkdir resident root a");
    std::fs::create_dir_all(&resident_b).expect("mkdir resident root b");
    {
        let storage = FrankenStorage::open(&fixture_roots.db()).expect("open storage");
        storage
            .upsert_source(&registered_source_with_paths(
                "remote-r",
                false,
                &[remote_ra, remote_rb],
            ))
            .expect("register the source");
        storage.close().expect("close storage");
    }
    let mut resident = Resident::start_db_backed(&fixture_roots);
    assert!(
        resident.wait_for(WATCH_READY_MARKER, Duration::from_secs(180)),
        "the resident watch loop must reach its event cycle: {}",
        resident.log()
    );
    fixture_roots.write_claude_session(
        &resident_a,
        "projects/p/session-a.jsonl",
        "sess-task35-a14-ra",
        "synthetic task35 resident root a",
    );
    fixture_roots.write_claude_session(
        &resident_b,
        "projects/p/session-b.jsonl",
        "sess-task35-a14-rb",
        "synthetic task35 resident root b",
    );
    resident.poll_until(
        "both roots of one source to be read",
        Duration::from_secs(240),
        || {
            let db = fixture_roots.try_open_db()?;
            (complete_source_inputs_for(&db, "claude_code") >= 2).then_some(())
        },
    );
    let (a_rows_before, b_rows_before, receipts_before, links_before) = {
        let db = fixture_roots.open_db();
        (
            input_rows_for(&db, "session-a.jsonl"),
            input_rows_for(&db, "session-b.jsonl"),
            scalar(&db, "SELECT COUNT(*) FROM operation_commit_receipt"),
            scalar(&db, "SELECT COUNT(*) FROM source_message_links"),
        )
    };
    // Same-input replay: rewrite the exact bytes so an event fires, while the
    // input stays byte-identical. No source fact may be added, in either root.
    let path = resident_a.join("projects/p/session-a.jsonl");
    let bytes = std::fs::read(&path).expect("read the session");
    let triggers_before = resident.count("resident_source_watch_trigger connector=claude");
    std::fs::write(&path, &bytes).expect("rewrite the same bytes");
    assert!(
        resident
            .wait_for_more(
                "resident_source_watch_trigger connector=claude",
                triggers_before,
                Duration::from_secs(240),
            )
            .is_some(),
        "the same-byte rewrite must reach a watch cycle: {}",
        resident.log()
    );
    std::thread::sleep(Duration::from_secs(5));
    resident.stop();

    let db = fixture_roots.open_db();
    assert_eq!(
        input_rows_for(&db, "session-a.jsonl"),
        a_rows_before,
        "a same-input replay adds no source fact"
    );
    assert_eq!(
        scalar(&db, "SELECT COUNT(*) FROM operation_commit_receipt"),
        receipts_before,
        "a same-input replay adds no receipt"
    );
    assert_eq!(
        scalar(&db, "SELECT COUNT(*) FROM source_message_links"),
        links_before,
        "a same-input replay adds no link"
    );
    assert_eq!(
        rows(&db, "SELECT DISTINCT source_id FROM source_inputs"),
        vec!["remote-r"]
    );
    let roots: Vec<String> = db
        .query_all_map(
            "SELECT DISTINCT hex(root_id_bin) FROM source_inputs ORDER BY 1",
            &[],
            |row| row.get_typed(0),
        )
        .expect("query input roots");
    assert_eq!(
        roots.len(),
        2,
        "the two roots keep distinct input identities: {roots:?}"
    );
    assert_eq!(
        input_rows_for(&db, "session-b.jsonl"),
        b_rows_before,
        "a replay in root A does not touch root B"
    );
    assert!(watermark_rows(&db, "").is_empty());
    assert!(file_state_rows(&db, "").is_empty());
}
