//! Task27: the running TUI's real Ctrl+Shift+R refresh consumes the default
//! source-fidelity path and lands source facts.
//!
//! Every scenario is parent + child. The parent prepares a private synthetic
//! HOME/XDG/data tree, then runs this very test binary with `--exact` in a
//! child whose whole source-discovery environment points inside that tree. The
//! child is the only process that constructs `CassApp`, converts a real
//! `Event::Key` into `CassMsg::IndexRefreshRequested`, calls `Model::update`,
//! takes the returned `Cmd::Task(_, closure)`, executes that closure and feeds
//! the real terminal message back. The parent never mutates its own process
//! environment; it only sets the child's `Command` environment.
//!
//! The private `loading_context` is observed only through the public
//! `Model::view` output: a 320x50 `Full`-degradation frame rendered with the
//! crate's own `ftui_harness::buffer_to_text`. While the task is in flight the
//! runtime HUD must really say `"⣷ index"`; after the real terminal message it
//! must be gone.
//!
//! This target deliberately has no `mod util`: the shared module would add its
//! own tests and blur the intended "exactly three" roster. Fixtures are
//! synthetic and neutral; no real session, path or secret appears here.
//!
//! The test binary is linked against the normally compiled library, so the
//! `cfg(not(test))` refresh branch (the real `run_index` task) is the one the
//! child executes. The `cfg(test)` automatic-`Completed` branch is never used.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use coding_agent_search::ftui_harness;
use coding_agent_search::storage::source_facts::decode_expected_manifest_header;
use coding_agent_search::ui::app::{CassApp, CassMsg};
use coding_agent_search::ui::ftui_adapter::{Event, KeyCode, KeyEvent, Model, Modifiers};
use coding_agent_search::ui::style_system::UiThemePreset;
use rusqlite::OptionalExtension as _;
use sha2::{Digest as _, Sha256};

/// The child marker is read only by this test file.
const CHILD_MARKER: &str = "CASS_TASK27_CHILD";
/// The private fixture root the parent prepared for the child.
const CHILD_ROOT: &str = "CASS_TASK27_CHILD_ROOT";
/// Where the child writes its private proof.
const CHILD_PROOF: &str = "CASS_TASK27_CHILD_PROOF";

/// The automatic fixed configuration's identity domain.
const AUTO_IDENTITY_PREFIX: &str = "cass.source-config/1:sha256:";

/// The HUD token the contract requires while an index refresh is in flight.
const RUNNING_HUD_TOKEN: &str = "\u{28f7} index";

/// The exact spinner frame these scenarios pin (`spinner_frame = 0`).
const SPINNER_GLYPH: char = '\u{28f7}';

// ---------------------------------------------------------------------------
// Child dispatch and fixture environment
// ---------------------------------------------------------------------------

fn child_paths() -> Option<(PathBuf, PathBuf)> {
    let marker = std::env::var_os(CHILD_MARKER)?;
    if marker.is_empty() {
        return None;
    }
    let root = PathBuf::from(
        std::env::var_os(CHILD_ROOT).expect("the child fixture root is set beside the marker"),
    );
    let proof = PathBuf::from(
        std::env::var_os(CHILD_PROOF).expect("the child proof path is set beside the marker"),
    );
    Some((root, proof))
}

fn prepare_fixture(root: &Path) {
    std::fs::create_dir_all(root.join("home").join(".claude/projects")).expect("mkdir claude root");
    std::fs::create_dir_all(root.join("home").join(".codex/sessions")).expect("mkdir codex root");
    std::fs::create_dir_all(root.join("data")).expect("mkdir data");
    std::fs::create_dir_all(root.join("config").join("cass")).expect("mkdir config");
    std::fs::write(
        root.join("config")
            .join("cass")
            .join("excluded_context_paths.toml"),
        include_bytes!("../config/excluded_context_paths.toml"),
    )
    .expect("write the fixture's fixed four-array safety rules");
}

fn apply_child_environment(cmd: &mut Command, root: &Path) {
    let home = root.join("home");
    cmd.env("HOME", &home)
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("CODEX_HOME", home.join(".codex"))
        .env("CASS_DATA_DIR", root.join("data"))
        .env("CASS_AIDER_DATA_ROOT", home.join(".aider"))
        .env("PI_SESSIONS_DIR", home.join(".pi"))
        .env("PI_CODING_AGENT_DIR", home.join(".pi"))
        .env("GOOSE_PATH_ROOT", home.join(".goose"))
        .env("HERMES_HOME", home.join(".hermes"))
        .env("CASS_SKIP_UPDATE", "1")
        .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .env("NO_COLOR", "1")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CASS_EXCLUDE_PATHS")
        .env_remove("CASS_IGNORE_SOURCES_CONFIG")
        .env_remove("CASS_OUTPUT_FORMAT")
        .env_remove("CASS_DEFER_LEXICAL_UPDATES")
        .env_remove("RUST_LOG");
}

fn run_bounded(cmd: &mut Command, label: &str) -> Output {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|error| panic!("{label}: spawn the child test: {error}"));
    let mut stdout_pipe = child.stdout.take().expect("the child's stdout");
    let mut stderr_pipe = child.stderr.take().expect("the child's stderr");
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stdout_pipe, &mut buf);
        buf
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stderr_pipe, &mut buf);
        buf
    });

    // Formal collection has no time limit: wait for this same child to finish
    // while the reader threads keep draining both pipes.
    let status = child
        .wait()
        .unwrap_or_else(|error| panic!("{label}: waiting for the child failed: {error}"));
    let stdout = stdout_reader.join().expect("the stdout reader");
    let stderr = stderr_reader.join().expect("the stderr reader");
    Output {
        status,
        stdout,
        stderr,
    }
}

/// Evidence directories are unique per parent run, so the serial run and the
/// three parallel runs never overwrite each other's child records.
fn evidence_run_dir(test: &str, case: &str) -> Option<PathBuf> {
    let base = std::env::var_os("CASS_TASK_EVIDENCE")?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_nanos();
    let dir = PathBuf::from(base)
        .join("children")
        .join(format!("{test}-{case}-pid{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the per-run child evidence directory");
    Some(dir)
}

fn save_child_evidence(dir: &Path, output: &Output, proof_path: &Path) {
    std::fs::write(dir.join("child.stdout"), &output.stdout).expect("save child stdout");
    std::fs::write(dir.join("child.stderr"), &output.stderr).expect("save child stderr");
    std::fs::write(
        dir.join("child.rc"),
        format!("{:?}\n", output.status.code()),
    )
    .expect("save child rc");
    if proof_path.is_file() {
        std::fs::copy(proof_path, dir.join("proof.json")).expect("copy the child proof");
    }
}

// ---------------------------------------------------------------------------
// TUI driving: real event, real Task, public view
// ---------------------------------------------------------------------------

fn refresh_event() -> CassMsg {
    let event = Event::Key(KeyEvent {
        code: KeyCode::Char('r'),
        modifiers: Modifiers::CTRL | Modifiers::SHIFT,
        kind: ftui::KeyEventKind::Press,
    });
    let message = CassMsg::from(event);
    assert!(
        format!("{message:?}").contains("IndexRefreshRequested"),
        "the real Ctrl+Shift+R event must map to IndexRefreshRequested, got {message:?}"
    );
    message
}

fn build_app(root: &Path) -> CassApp {
    let mut app = CassApp::default();
    app.data_dir = root.join("data");
    app.db_path = app.data_dir.join("agent_search.db");
    app.theme_preset = UiThemePreset::TokyoNight;
    app.theme_dark = true;
    app.style_options.preset = UiThemePreset::TokyoNight;
    app.style_options.dark_mode = true;
    app.spinner_frame = 0;
    app.selected.clear();
    assert!(
        app.macro_recorder.is_none(),
        "no macro recorder in fixtures"
    );
    assert!(
        app.macro_playback.is_none(),
        "no macro playback in fixtures"
    );
    app
}

/// Render the public frame the contract fixes: 320x50, Full degradation,
/// TokyoNight dark, spinner frame 0 and no selection/REC/PLAY.
fn render(app: &CassApp) -> String {
    let mut pool = ftui::GraphemePool::new();
    let mut frame = ftui::Frame::new(320, 50, &mut pool);
    frame.set_degradation(ftui::render::budget::DegradationLevel::Full);
    app.view(&mut frame);
    ftui_harness::buffer_to_text(&frame.buffer)
}

fn running_hud_line(app: &CassApp) -> Option<String> {
    render(app)
        .lines()
        .find(|line| line.contains(RUNNING_HUD_TOKEN))
        .map(str::to_string)
}

fn take_task(cmd: ftui::Cmd<CassMsg>, label: &str) -> Box<dyn FnOnce() -> CassMsg + Send> {
    match cmd {
        ftui::Cmd::Task(_spec, closure) => closure,
        other => panic!("{label}: expected a real Cmd::Task, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Fixture content
// ---------------------------------------------------------------------------

fn jsonl(lines: &[serde_json::Value]) -> String {
    lines
        .iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn write_claude_session(root: &Path, locator: &str, uuid: &str, question: &str, answer: &str) {
    let path = root.join("home").join(".claude/projects").join(locator);
    std::fs::create_dir_all(path.parent().expect("session parent")).expect("mkdir session dir");
    let lines = vec![
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
    ];
    std::fs::write(&path, jsonl(&lines)).expect("write claude session");
}

fn write_codex_session(root: &Path, locator: &str, id: &str, question: &str, answer: &str) {
    let path = root.join("home").join(".codex/sessions").join(locator);
    std::fs::create_dir_all(path.parent().expect("rollout parent")).expect("mkdir rollout dir");
    let lines = vec![
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
    ];
    std::fs::write(&path, jsonl(&lines)).expect("write codex rollout");
}

// ---------------------------------------------------------------------------
// SQLite readers
// ---------------------------------------------------------------------------

fn open_db(root: &Path) -> rusqlite::Connection {
    let path = root.join("data").join("agent_search.db");
    assert!(
        path.is_file(),
        "no source database exists after the real TUI refresh; the source inputs never reached complete"
    );
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open the fixture database read-only after the run");
    db.busy_timeout(Duration::from_secs(30))
        .expect("busy timeout");
    db
}

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

fn input_keys(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare("SELECT input_key FROM source_inputs ORDER BY input_key")
        .expect("prepare input keys");
    stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query input keys")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect input keys")
        .into_iter()
        .map(|bytes| hex(&bytes))
        .collect()
}

fn receipt_keys(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT operation || '|' || idempotency_key || '|' || state
             FROM operation_commit_receipt ORDER BY operation, idempotency_key",
        )
        .expect("prepare receipt keys");
    stmt.query_map([], |row| row.get::<_, String>(0))
        .expect("query receipt keys")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect receipt keys")
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

fn input_fingerprint(db: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = db
        .prepare(
            "SELECT input_key, root_id_bin, relative_locator_bin, connector, state,
                    normalizer_id, safety_contract_id, sealed_sha256
             FROM source_inputs ORDER BY input_key",
        )
        .expect("prepare the input fingerprint");
    stmt.query_map([], |row| {
        let key: Vec<u8> = row.get(0)?;
        let root: Vec<u8> = row.get(1)?;
        let locator: Vec<u8> = row.get(2)?;
        let sealed: Vec<u8> = row.get(7)?;
        Ok(format!(
            "key={} root={} locator={} connector={} state={} normalizer={} safety={} sealed={}",
            hex(&key),
            String::from_utf8_lossy(&root),
            String::from_utf8_lossy(&locator),
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            hex(&sealed),
        ))
    })
    .expect("query the input fingerprint")
    .collect::<Result<Vec<_>, _>>()
    .expect("collect the input fingerprint")
}

/// Facts, receipts, watermarks, per-file progress, bodies and counts, all by
/// value. A rewrite of the same rows must fail this comparison.
fn core_snapshot(db: &rusqlite::Connection) -> serde_json::Value {
    serde_json::json!({
        "inputs": input_fingerprint(db),
        "receipts": receipt_keys(db),
        "watermarks": watermark_rows(db),
        "file_progress": file_progress_rows(db),
        "bodies": canonical_bodies(db),
        "source_facts_revision": source_facts_revision(db),
        "counts": {
            "source_records": count(db, "SELECT COUNT(*) FROM source_records"),
            "source_message_links": count(db, "SELECT COUNT(*) FROM source_message_links"),
            "messages": count(db, "SELECT COUNT(*) FROM messages"),
            "conversations": count(db, "SELECT COUNT(*) FROM conversations"),
        },
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn auto_config_files(root: &Path) -> Vec<PathBuf> {
    let dir = root.join("data").join("source-configs").join("v1");
    let Ok(entries) = std::fs::read_dir(&dir) else {
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

// ---------------------------------------------------------------------------
// Child bodies: the only place a real TUI refresh task runs
// ---------------------------------------------------------------------------

fn write_proof(path: &Path, proof: &serde_json::Value) {
    std::fs::write(
        path,
        serde_json::to_vec_pretty(proof).expect("serialize the proof"),
    )
    .expect("write the child proof");
}

fn child_lands(root: &Path, proof_path: &Path) {
    let claude = "p/session.jsonl";
    let codex = "2026/01/rollout-fixture.jsonl";
    let marker = "task27a1landsmarker";
    write_claude_session(
        root,
        claude,
        "sess-task27-lands-claude",
        &format!("the claude question {marker}"),
        &format!("the claude answer {marker}"),
    );
    write_codex_session(
        root,
        codex,
        "sess-task27-lands-codex",
        &format!("the codex question {marker}"),
        &format!("the codex answer {marker}"),
    );

    let mut app = build_app(root);
    assert!(!app.index_refresh_in_flight);
    assert!(app.indexing_progress.is_none());
    let before = running_hud_line(&app);
    assert!(
        before.is_none(),
        "a fresh fixture shows no running HUD: {before:?}"
    );

    let cmd = app.update(refresh_event());
    assert!(
        app.index_refresh_in_flight,
        "the request marks the refresh in flight"
    );
    assert!(
        app.indexing_progress.is_some(),
        "the request exposes its progress handle"
    );
    let hud_running = running_hud_line(&app).unwrap_or_else(|| {
        panic!(
            "the running HUD must show {RUNNING_HUD_TOKEN:?}; frame:\n{}",
            render(&app)
        )
    });

    let closure = take_task(cmd, "lands");
    let message = closure();
    assert!(
        matches!(&message, CassMsg::IndexRefreshCompleted),
        "the real task must return Completed, got {message:?}"
    );
    let followup = app.update(message);
    assert!(!app.index_refresh_in_flight, "Completed clears in-flight");
    assert!(
        app.indexing_progress.is_none(),
        "Completed drops the progress handle"
    );
    assert_eq!(app.status, "Index refresh complete");
    let hud_after = running_hud_line(&app);
    assert!(
        hud_after.is_none(),
        "the terminal message clears the HUD: {hud_after:?}"
    );
    let frame_after = render(&app);
    assert!(
        !frame_after.contains(SPINNER_GLYPH),
        "no spinner glyph may remain after Completed; frame:\n{frame_after}"
    );
    assert!(
        format!("{followup:?}").contains("SearchRequested"),
        "Completed keeps its follow-up command, got {followup:?}"
    );

    let db = open_db(root);
    for locator in [claude, codex] {
        assert_eq!(
            input_rows_for(&db, locator),
            1,
            "{locator}: one source fact"
        );
        assert_eq!(complete_rows_for(&db, locator), 1, "{locator}: complete");
        assert_eq!(
            committed_receipts_for(&db, locator),
            1,
            "{locator}: its own committed activation receipt"
        );
        assert!(links_for(&db, locator) > 0, "{locator}: canonical links");
    }
    assert!(
        count_like(&db, marker) > 0,
        "the new bodies reached the canonical store"
    );

    let files = auto_config_files(root);
    assert_eq!(files.len(), 1, "exactly one automatic copy: {files:?}");
    let bytes = std::fs::read(&files[0]).expect("read the automatic copy");
    let digest = sha256_hex(&bytes);
    let name = files[0]
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("the automatic copy has a UTF-8 stem");
    assert_eq!(name, digest, "the automatic copy is named after its digest");
    for locator in [claude, codex] {
        let manifests = manifests_for(&db, locator);
        assert_eq!(manifests.len(), 1, "{locator}: exactly one input row");
        assert_eq!(manifests[0].0, format!("{AUTO_IDENTITY_PREFIX}{digest}"));
        assert_eq!(manifests[0].1, digest);
    }

    write_proof(
        proof_path,
        &serde_json::json!({
            "result": "pass",
            "case": "lands",
            "locators": [claude, codex],
            "hud_running": hud_running,
            "hud_after": hud_after,
            "status_after": app.status,
            "in_flight_after": app.index_refresh_in_flight,
            "progress_none_after": app.indexing_progress.is_none(),
            "auto_copy_digest": digest,
            "marker_count": count_like(&db, marker),
        }),
    );
}

fn child_failure(root: &Path, proof_path: &Path) {
    let claude = "p/session.jsonl";
    let codex = "2026/01/rollout-fixture.jsonl";
    let claude_new = "p/second.jsonl";
    let codex_new = "2026/02/rollout-second.jsonl";
    let warm_marker = "task27a2warmmarker";
    write_claude_session(
        root,
        claude,
        "sess-task27-failure-warm-claude",
        &format!("the warm claude question {warm_marker}"),
        &format!("the warm claude answer {warm_marker}"),
    );
    write_codex_session(
        root,
        codex,
        "sess-task27-failure-warm-codex",
        &format!("the warm codex question {warm_marker}"),
        &format!("the warm codex answer {warm_marker}"),
    );

    // Healthy TUI warm-up: both inputs really land through the same task path.
    let mut app = build_app(root);
    let warm_cmd = app.update(refresh_event());
    let warm_hud = running_hud_line(&app).unwrap_or_else(|| {
        panic!(
            "the warm-up HUD must show {RUNNING_HUD_TOKEN:?}; frame:\n{}",
            render(&app)
        )
    });
    let warm_message = take_task(warm_cmd, "failure warm-up")();
    assert!(
        matches!(&warm_message, CassMsg::IndexRefreshCompleted),
        "the warm-up task must return Completed, got {warm_message:?}"
    );
    let _ = app.update(warm_message);
    assert_eq!(app.status, "Index refresh complete");
    assert!(running_hud_line(&app).is_none());

    let snapshot_before;
    {
        let db = open_db(root);
        for locator in [claude, codex] {
            assert_eq!(input_rows_for(&db, locator), 1);
            assert_eq!(complete_rows_for(&db, locator), 1);
            assert_eq!(committed_receipts_for(&db, locator), 1);
            assert!(links_for(&db, locator) > 0);
        }
        snapshot_before = core_snapshot(&db);
    }

    let files = auto_config_files(root);
    assert_eq!(
        files.len(),
        1,
        "the warm-up publishes exactly one automatic copy"
    );
    let copy = files[0].clone();
    let mut tampered = std::fs::read(&copy).expect("read the automatic copy");
    tampered.extend_from_slice(b"\n# task27 tampered copy\n");
    std::fs::write(&copy, &tampered).expect("tamper with the automatic copy");
    let tampered_digest = sha256_hex(&tampered);

    // The live rules stay valid; only the published copy is damaged.
    write_claude_session(
        root,
        claude_new,
        "sess-task27-failure-new-claude",
        "the new claude question task27a2newmarker",
        "the new claude answer task27a2newmarker",
    );
    write_codex_session(
        root,
        codex_new,
        "sess-task27-failure-new-codex",
        "the new codex question task27a2newmarker",
        "the new codex answer task27a2newmarker",
    );

    let cmd = app.update(refresh_event());
    assert!(app.index_refresh_in_flight);
    assert!(app.indexing_progress.is_some());
    let hud_running = running_hud_line(&app).unwrap_or_else(|| {
        panic!(
            "the failing run must still show {RUNNING_HUD_TOKEN:?}; frame:\n{}",
            render(&app)
        )
    });

    let message = take_task(cmd, "failure")();
    let error = match &message {
        CassMsg::IndexRefreshFailed(error) => error.clone(),
        other => panic!("the damaged fixed copy must return Failed, got {other:?}"),
    };
    assert!(
        error.contains("source_config_mismatch"),
        "Failed must carry source_config_mismatch, got {error:?}"
    );
    let followup = app.update(message);
    assert!(!app.index_refresh_in_flight);
    assert!(app.indexing_progress.is_none());
    assert!(
        app.status.starts_with("Index refresh failed:")
            && app.status.contains("source_config_mismatch"),
        "the UI keeps the failure status, got {:?}",
        app.status
    );
    let hud_after = running_hud_line(&app);
    assert!(hud_after.is_none(), "Failed clears the HUD: {hud_after:?}");
    let frame_after = render(&app);
    assert!(
        !frame_after.contains(SPINNER_GLYPH),
        "no spinner glyph may remain after Failed; frame:\n{frame_after}"
    );
    assert_eq!(
        format!("{followup:?}"),
        "None",
        "Failed returns no follow-up command"
    );

    let db = open_db(root);
    let snapshot_after = core_snapshot(&db);
    for locator in [claude_new, codex_new] {
        assert_eq!(input_rows_for(&db, locator), 0, "{locator}: no source fact");
        assert_eq!(
            complete_rows_for(&db, locator),
            0,
            "{locator}: never completes"
        );
        assert_eq!(
            committed_receipts_for(&db, locator),
            0,
            "{locator}: no success receipt"
        );
    }
    for locator in [claude, codex] {
        assert_eq!(
            complete_rows_for(&db, locator),
            1,
            "{locator}: the old input stays complete"
        );
        assert_eq!(
            committed_receipts_for(&db, locator),
            1,
            "{locator}: the old receipt stays"
        );
    }
    assert_eq!(
        snapshot_after, snapshot_before,
        "the failed run preserves facts, receipts, watermarks, progress and bodies by value"
    );
    assert_eq!(
        std::fs::read(&copy).expect("re-read the automatic copy"),
        tampered,
        "the failed run leaves the damaged copy untouched"
    );

    write_proof(
        proof_path,
        &serde_json::json!({
            "result": "pass",
            "case": "failure",
            "locators": [claude, codex, claude_new, codex_new],
            "warm_hud": warm_hud,
            "hud_running": hud_running,
            "hud_after": hud_after,
            "error": error,
            "status_after": app.status,
            "in_flight_after": app.index_refresh_in_flight,
            "progress_none_after": app.indexing_progress.is_none(),
            "snapshot_before": snapshot_before,
            "snapshot_after": snapshot_after,
            "copy_digest_tampered": tampered_digest,
        }),
    );
}

fn child_duplicate(root: &Path, proof_path: &Path) {
    let claude = "p/session.jsonl";
    let codex = "2026/01/rollout-fixture.jsonl";
    let marker = "task27a3duplicatemarker";
    write_claude_session(
        root,
        claude,
        "sess-task27-duplicate-claude",
        &format!("the claude question {marker}"),
        &format!("the claude answer {marker}"),
    );
    write_codex_session(
        root,
        codex,
        "sess-task27-duplicate-codex",
        &format!("the codex question {marker}"),
        &format!("the codex answer {marker}"),
    );

    let mut app = build_app(root);
    let first_cmd = app.update(refresh_event());
    assert!(
        app.index_refresh_in_flight,
        "the first request is in flight"
    );
    assert!(
        app.indexing_progress.is_some(),
        "the first request has a progress handle"
    );
    let first_hud = running_hud_line(&app).unwrap_or_else(|| {
        panic!(
            "the first run must show {RUNNING_HUD_TOKEN:?}; frame:\n{}",
            render(&app)
        )
    });
    let first_closure = take_task(first_cmd, "duplicate first");

    let second_cmd = app.update(refresh_event());
    assert!(
        matches!(&second_cmd, ftui::Cmd::None),
        "the second request must not return a Task, got {second_cmd:?}"
    );
    assert!(
        app.status.contains("already running"),
        "the status must explain the refusal, got {:?}",
        app.status
    );
    assert!(
        app.index_refresh_in_flight,
        "the first task stays in flight"
    );
    assert!(
        app.indexing_progress.is_some(),
        "the first progress handle stays"
    );
    assert!(
        running_hud_line(&app).is_some(),
        "the refused request must not clear the running HUD"
    );
    let already_running_status = app.status.clone();

    let first_message = first_closure();
    assert!(
        matches!(&first_message, CassMsg::IndexRefreshCompleted),
        "the first real task must return Completed, got {first_message:?}"
    );
    let _ = app.update(first_message);
    assert!(!app.index_refresh_in_flight);
    assert!(app.indexing_progress.is_none());
    assert!(running_hud_line(&app).is_none(), "Completed clears the HUD");
    assert_eq!(app.status, "Index refresh complete");

    let (keys_first, receipts_first);
    {
        let db = open_db(root);
        for locator in [claude, codex] {
            assert_eq!(input_rows_for(&db, locator), 1);
            assert_eq!(complete_rows_for(&db, locator), 1);
            assert_eq!(committed_receipts_for(&db, locator), 1);
            assert!(links_for(&db, locator) > 0);
        }
        keys_first = input_keys(&db);
        receipts_first = receipt_keys(&db);
        assert_eq!(keys_first.len(), 2, "two inputs after the first run");
    }

    let second_refresh_cmd = app.update(refresh_event());
    assert!(
        app.index_refresh_in_flight,
        "the later request starts a new refresh"
    );
    assert!(app.indexing_progress.is_some());
    assert!(
        running_hud_line(&app).is_some(),
        "the later request must show the running HUD"
    );
    let second_message = take_task(second_refresh_cmd, "duplicate second")();
    assert!(
        matches!(&second_message, CassMsg::IndexRefreshCompleted),
        "the later real task must return Completed, got {second_message:?}"
    );
    let _ = app.update(second_message);
    assert!(!app.index_refresh_in_flight);
    assert!(app.indexing_progress.is_none());
    let hud_after = running_hud_line(&app);
    assert!(hud_after.is_none(), "the second Completed clears the HUD");
    let frame_after = render(&app);
    assert!(
        !frame_after.contains(SPINNER_GLYPH),
        "no spinner glyph may remain after the later Completed; frame:\n{frame_after}"
    );

    let (keys_after, receipts_after);
    {
        let db = open_db(root);
        keys_after = input_keys(&db);
        receipts_after = receipt_keys(&db);
        assert_eq!(keys_after, keys_first, "the later run adds no input key");
        assert_eq!(
            receipts_after, receipts_first,
            "the later run adds no receipt"
        );
        for locator in [claude, codex] {
            assert_eq!(input_rows_for(&db, locator), 1, "{locator}: still one row");
            assert_eq!(
                complete_rows_for(&db, locator),
                1,
                "{locator}: still complete"
            );
            assert_eq!(
                committed_receipts_for(&db, locator),
                1,
                "{locator}: still one receipt"
            );
        }
    }

    write_proof(
        proof_path,
        &serde_json::json!({
            "result": "pass",
            "case": "duplicate",
            "locators": [claude, codex],
            "hud_running": first_hud,
            "hud_after": hud_after,
            "status_already_running": already_running_status,
            "status_after": app.status,
            "in_flight_after": app.index_refresh_in_flight,
            "progress_none_after": app.indexing_progress.is_none(),
            "input_keys_first": keys_first,
            "input_keys_after": keys_after,
            "receipt_keys_first": receipts_first,
            "receipt_keys_after": receipts_after,
        }),
    );
}

// ---------------------------------------------------------------------------
// Parent scenarios: distinct child environment, proof checks, one marker
// ---------------------------------------------------------------------------

fn parent_scenario(
    test: &str,
    case: &str,
    verify_parent: fn(&rusqlite::Connection, &Path, &serde_json::Value),
) {
    let fixture = tempfile::TempDir::new().expect("fixture tempdir");
    let root = fixture.path();
    prepare_fixture(root);
    let proof_path = root.join("proof.json");
    let run_dir = evidence_run_dir(test, case);

    let binary = std::env::current_exe().expect("the test binary's own path");
    let mut cmd = Command::new(binary);
    cmd.arg(test)
        .arg("--exact")
        .arg("--nocapture")
        .current_dir(root)
        .env(CHILD_MARKER, "1")
        .env(CHILD_ROOT, root)
        .env(CHILD_PROOF, &proof_path);
    apply_child_environment(&mut cmd, root);

    let output = run_bounded(&mut cmd, &format!("{test}/{case} child"));
    if let Some(dir) = run_dir.as_deref() {
        save_child_evidence(dir, &output, &proof_path);
    }
    assert_eq!(
        output.status.code(),
        Some(0),
        "{test}/{case}: the child must exit 0; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        proof_path.is_file(),
        "{test}/{case}: the child must leave its private proof"
    );
    let proof: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&proof_path).expect("read the child proof"))
            .expect("parse the child proof");
    assert_eq!(proof["result"], "pass", "{test}/{case}: child proof result");

    let db = open_db(root);
    verify_parent(&db, root, &proof);

    println!("\nTASK27_SCENARIO test={test} case={case} result=pass");
}

fn verify_lands_parent(db: &rusqlite::Connection, root: &Path, proof: &serde_json::Value) {
    let locators = proof["locators"].as_array().expect("locators");
    for locator in locators {
        let locator = locator.as_str().expect("locator text");
        assert_eq!(input_rows_for(db, locator), 1, "{locator}: one source fact");
        assert_eq!(complete_rows_for(db, locator), 1, "{locator}: complete");
        assert_eq!(committed_receipts_for(db, locator), 1, "{locator}: receipt");
        assert!(links_for(db, locator) > 0, "{locator}: links");
    }
    let files = auto_config_files(root);
    assert_eq!(files.len(), 1, "exactly one automatic copy");
    let digest = sha256_hex(&std::fs::read(&files[0]).expect("read automatic copy"));
    assert_eq!(
        proof["auto_copy_digest"], digest,
        "proof digest matches the copy"
    );
    for locator in locators {
        let locator = locator.as_str().expect("locator text");
        let manifests = manifests_for(db, locator);
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].0, format!("{AUTO_IDENTITY_PREFIX}{digest}"));
        assert_eq!(manifests[0].1, digest);
    }
    assert!(proof["marker_count"].as_i64().unwrap_or(0) > 0);
    assert_hud_proof(proof);
}

fn verify_failure_parent(db: &rusqlite::Connection, root: &Path, proof: &serde_json::Value) {
    let locators: Vec<&str> = proof["locators"]
        .as_array()
        .expect("locators")
        .iter()
        .map(|locator| locator.as_str().expect("locator text"))
        .collect();
    let (warm_claude, warm_codex, new_claude, new_codex) =
        (locators[0], locators[1], locators[2], locators[3]);
    for locator in [warm_claude, warm_codex] {
        assert_eq!(
            complete_rows_for(db, locator),
            1,
            "{locator}: warm input complete"
        );
        assert_eq!(
            committed_receipts_for(db, locator),
            1,
            "{locator}: warm receipt"
        );
    }
    for locator in [new_claude, new_codex] {
        assert_eq!(input_rows_for(db, locator), 0, "{locator}: no fact");
        assert_eq!(complete_rows_for(db, locator), 0, "{locator}: no complete");
        assert_eq!(
            committed_receipts_for(db, locator),
            0,
            "{locator}: no receipt"
        );
    }
    let error = proof["error"].as_str().expect("error text");
    assert!(
        error.contains("source_config_mismatch"),
        "proof error: {error}"
    );
    assert_eq!(
        proof["snapshot_before"], proof["snapshot_after"],
        "the child recorded identical snapshots"
    );
    assert_eq!(
        core_snapshot(db),
        proof["snapshot_after"],
        "the reopened database still equals the recorded after-snapshot"
    );
    let files = auto_config_files(root);
    assert_eq!(files.len(), 1);
    let copy = std::fs::read(&files[0]).expect("read the damaged copy");
    assert_eq!(
        sha256_hex(&copy),
        proof["copy_digest_tampered"]
            .as_str()
            .expect("tampered digest"),
        "the damaged copy is not repaired"
    );
    assert_hud_proof(proof);
}

fn verify_duplicate_parent(db: &rusqlite::Connection, _root: &Path, proof: &serde_json::Value) {
    let locators: Vec<&str> = proof["locators"]
        .as_array()
        .expect("locators")
        .iter()
        .map(|locator| locator.as_str().expect("locator text"))
        .collect();
    for locator in locators {
        assert_eq!(input_rows_for(db, locator), 1, "{locator}: one row");
        assert_eq!(complete_rows_for(db, locator), 1, "{locator}: complete");
        assert_eq!(
            committed_receipts_for(db, locator),
            1,
            "{locator}: one receipt"
        );
    }
    let keys_first = proof["input_keys_first"].as_array().expect("first keys");
    let keys_after = proof["input_keys_after"].as_array().expect("after keys");
    assert_eq!(keys_first, keys_after, "no input key is added");
    let receipts_first = proof["receipt_keys_first"]
        .as_array()
        .expect("first receipts");
    let receipts_after = proof["receipt_keys_after"]
        .as_array()
        .expect("after receipts");
    assert_eq!(receipts_first, receipts_after, "no receipt is added");
    assert_eq!(
        input_keys(db),
        json_strings(keys_after),
        "reopened input keys match"
    );
    assert_eq!(
        receipt_keys(db),
        json_strings(receipts_after),
        "reopened receipts match"
    );
    let already_running = proof["status_already_running"]
        .as_str()
        .expect("the refusal status");
    assert!(
        already_running.contains("already running"),
        "the recorded refusal status: {already_running}"
    );
    assert_hud_proof(proof);
}

fn json_strings(values: &[serde_json::Value]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_str().expect("string").to_string())
        .collect()
}

fn assert_hud_proof(proof: &serde_json::Value) {
    let running = proof["hud_running"]
        .as_str()
        .unwrap_or_else(|| panic!("proof has no running HUD line: {proof}"));
    assert!(
        running.contains(RUNNING_HUD_TOKEN),
        "the recorded running HUD must contain the token: {running}"
    );
    assert!(
        proof["hud_after"].is_null(),
        "the terminal HUD must be absent: {}",
        proof["hud_after"]
    );
    assert!(
        !proof["status_after"].as_str().unwrap_or("").is_empty(),
        "proof records the status"
    );
    assert_eq!(proof["in_flight_after"], false);
    assert_eq!(proof["progress_none_after"], true);
}

// ---------------------------------------------------------------------------
// The fixed three-test roster
// ---------------------------------------------------------------------------

#[test]
fn tui_refresh_task_lands_source() {
    if let Some((root, proof)) = child_paths() {
        return child_lands(&root, &proof);
    }
    parent_scenario(
        "tui_refresh_task_lands_source",
        "lands",
        verify_lands_parent,
    );
}

#[test]
fn tui_refresh_task_failure() {
    if let Some((root, proof)) = child_paths() {
        return child_failure(&root, &proof);
    }
    parent_scenario("tui_refresh_task_failure", "failure", verify_failure_parent);
}

#[test]
fn tui_parallel_refresh_refused() {
    if let Some((root, proof)) = child_paths() {
        return child_duplicate(&root, &proof);
    }
    parent_scenario(
        "tui_parallel_refresh_refused",
        "duplicate",
        verify_duplicate_parent,
    );
}
