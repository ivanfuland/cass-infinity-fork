//! Bead coding_agent_session_search-ghw60 (child of ibuuh.10):
//! crash-window regression for the lexical rebuild/publish contract.
//!
//! W2-6 exec39 (control-plane 2026-08-31 ruling, item2): the ORIGINAL
//! atomic-swap-publish protocol this file tested is structurally
//! extinct. `renameat2(RENAME_EXCHANGE)` staged-directory swap
//! (commits 109560e5 / a699f55b), `frankensearch::lexical` (crate
//! built without the `lexical` feature -- zero src callers of
//! `ReloadPolicy`/`IndexReader`/`cass_open_search_reader`/etc.), and
//! `open_federated_search_readers` (zero src callers, no successor)
//! are all gone. lex_docs/fts_lex now live inside the same SQLite file
//! as everything else and are rebuilt via
//! `FrankenStorage::rebuild_lex_domain_from_db`: a sequence of
//! `IMMEDIATE` transactions (200 conversations each,
//! src/storage/sqlite.rs:7059 `CONVERSATIONS_PER_TX`), never a
//! parked-then-atomically-swapped directory. There is no more
//! "half-torn intermediate filesystem state" for a directory-polling
//! reader to observe -- SQLite's own transaction atomicity replaces
//! that concern entirely.
//!
//! Two of the three original tests are judged dead outright (their
//! mechanism no longer exists) and are recorded, not kept:
//!
//!   - `concurrent_reader_never_sees_half_torn_lexical_index_during_publish_swap`
//!   - `concurrent_reader_never_sees_half_torn_federated_lexical_index_during_publish_swap`
//!     (federated reader concept additionally extinct on its own)
//!
//! Their INTENT -- what does a concurrent reader observe while a
//! rebuild is in flight? -- is not dead, and W2-6 exec39's real
//! (black-box CLI) experiment against the current DB-domain rebuild
//! found real, reproducible behavior: `has_populated_fts_lex()`
//! (src/search/query.rs:3704) retries lock contention for 2s then
//! silently reports "no index" via `.unwrap_or(false)` on any
//! remaining error, which can make a concurrent `cass search` return
//! zero hits with a misleading "index not found" warning even while
//! most of the rebuild's data is already committed. What the CORRECT
//! behavior should be here (propagate the error? report "rebuild in
//! progress, retry"? something else?) is undecided product behavior,
//! not something this test suite gets to invent an assertion for --
//! see w2-6-closeout's "重建中并发查询的行为契约未定义" debt entry.
//! Writing a new test that pins one of these undefined choices would
//! just be asserting on a coin flip, so none is added here.
//!
//! The third test, `kill_relaunch_recovers_lexical_publish_and_search_stays_stable`,
//! is REWRITTEN below (not deleted) because its intent -- "a hard
//! crash mid-rebuild is recovered on the next invocation" -- maps
//! cleanly onto a real, DEFINED, verified-by-experiment DB-domain
//! behavior: `FrankenStorage::rebuild_lex_domain_from_db` marks the
//! lex-domain meta row `building` before touching any conversation and
//! only flips it to `completed:<total>:<lex_docs_count>` atomically
//! with the LAST batch's commit (src/storage/sqlite.rs:7070-7075's own
//! comment: "A crash between here and the completed marker below
//! leaves this row at 'building', which region2's routine-run
//! detection (indexer::mod.rs) reads as incomplete and reruns from
//! zero next time"). W2-6 exec39 verified this promise empirically:
//! `cass doctor check`/`cass doctor --fix` are BOTH blind to a stuck
//! `building` marker (report `healthy`/`needs_rebuild: false` and take
//! no action -- a real, separately-tracked reporting gap, see
//! w2-6-closeout), but the plain ROUTINE `cass index` (no `--full`)
//! DOES detect it and triggers
//! `"lexical_strategy_reason": "rebuild_incomplete_lex_domain_from_canonical_db"`,
//! correctly rebuilding to completion. That is the real recovery path
//! this test now pins.

use assert_cmd::Command;
use coding_agent_search::storage::api::Value as SqliteValue;
use coding_agent_search::storage::sqlite::{FrankenStorage, LEX_DOMAIN_REBUILD_STATE_META_KEY};
use std::fs;
use std::process::{Command as StdCommand, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn cass_cmd(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cass"));
    cmd.current_dir(home);
    cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
    cmd.env("CASS_IGNORE_SOURCES_CONFIG", "1");
    cmd.env("HOME", home);
    cmd.env("XDG_DATA_HOME", home.join(".local/share"));
    cmd.env("XDG_CONFIG_HOME", home.join(".config"));
    cmd.env("CODEX_HOME", home.join(".codex"));
    cmd
}

/// Seed `count` conversations (2 messages each) directly via raw SQL --
/// bypassing the app's dual-write path entirely, so `lex_docs` starts
/// empty regardless of `count`. This is the same real production
/// staleness shape `CASS_DEFER_LEXICAL_UPDATES=1` produces (an
/// interrupted-defer incident leaves messages ingested with no
/// matching lex_docs rows); it's deliberately large enough to span
/// many `CONVERSATIONS_PER_TX=200` rebuild batches so a concurrently
/// running kill has a wide real window to land inside, not a
/// coin-flip-timed one.
fn seed_conversations_bypassing_dual_write(db_path: &std::path::Path, count: i64) {
    let storage = FrankenStorage::open(db_path).expect("open seed db");
    let conn = storage.raw();
    conn.execute(
        "INSERT OR IGNORE INTO agents(id, slug, name, version, kind, created_at, updated_at) \
         VALUES(1, 'codex', 'Codex', '0.0.0', 'cli', 0, 0)",
        &[],
    )
    .expect("seed agent");
    conn.execute("BEGIN", &[]).expect("begin seed batch");
    const INSERT_CONVERSATION_SQL: &str = "INSERT INTO conversations(
            id, agent_id, source_id, external_id, title, source_path, started_at, ended_at
         ) VALUES (?1, 1, 'local', ?2, ?3, ?4, ?5, ?6)";
    const INSERT_MESSAGE_SQL: &str = "INSERT INTO messages(
            id, conversation_id, idx, role, author, created_at, content
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
    let now = 1_733_000_000_000_i64;
    for conversation_id in 1..=count {
        let started_at = now + conversation_id;
        let external_id = format!("crash-window-{conversation_id}");
        let title = format!("Crash window {conversation_id}");
        let source_path = format!("/tmp/cass-crash-window/session-{conversation_id}.jsonl");
        conn.execute(
            INSERT_CONVERSATION_SQL,
            &[
                SqliteValue::from(conversation_id),
                SqliteValue::from(external_id.as_str()),
                SqliteValue::from(title.as_str()),
                SqliteValue::from(source_path.as_str()),
                SqliteValue::from(started_at),
                SqliteValue::from(started_at + 1),
            ],
        )
        .expect("seed conversation");
        let first_message_id = conversation_id * 2 - 1;
        conn.execute(
            INSERT_MESSAGE_SQL,
            &[
                SqliteValue::from(first_message_id),
                SqliteValue::from(conversation_id),
                SqliteValue::from(0_i64),
                SqliteValue::from("user"),
                SqliteValue::from("user"),
                SqliteValue::from(started_at),
                SqliteValue::from(format!("crash window needle {conversation_id}")),
            ],
        )
        .expect("seed user message");
        conn.execute(
            INSERT_MESSAGE_SQL,
            &[
                SqliteValue::from(first_message_id + 1),
                SqliteValue::from(conversation_id),
                SqliteValue::from(1_i64),
                SqliteValue::from("assistant"),
                SqliteValue::from("agent"),
                SqliteValue::from(started_at + 1),
                SqliteValue::from(format!("crash window response {conversation_id}")),
            ],
        )
        .expect("seed assistant message");
    }
    conn.execute("COMMIT", &[]).expect("commit seed batch");
}

// W2-6 exec39: these two pollers use `rusqlite` directly (a plain,
// read-only connection), NOT `FrankenStorage::open` -- the app's own
// open path is lock-aware and deliberately BLOCKS/refuses a concurrent
// open while `cass doctor --fix` holds its repair mutation lock
// (`doctor/locks/doctor-repair.lock`), which is exactly the state this
// test needs to poll through. A bare SQLite connection has no such
// coordination and just reads whatever is currently committed.
fn lex_domain_rebuild_marker(db_path: &std::path::Path) -> String {
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open db for marker read");
    conn.query_row(
        &format!(
            "SELECT value FROM meta WHERE key = '{}'",
            LEX_DOMAIN_REBUILD_STATE_META_KEY
        ),
        [],
        |row| row.get::<_, String>(0),
    )
    .unwrap_or_default()
}

fn lex_docs_count(db_path: &std::path::Path) -> i64 {
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open db for lex_docs count");
    conn.query_row("SELECT COUNT(*) FROM lex_docs", [], |row| {
        row.get::<_, i64>(0)
    })
    .unwrap_or(0)
}

/// Bead coding_agent_session_search-mux5k, rewritten W2-6 exec39: a
/// hard SIGKILL mid-rebuild leaves the lex-domain meta marker stuck at
/// `building` with a partially-populated `lex_docs` table. The next
/// ROUTINE `cass index` (not `--full`) must detect that stuck marker
/// and rebuild the lex domain from the canonical DB to completion --
/// this is `FrankenStorage::rebuild_lex_domain_from_db`'s own
/// documented crash-recovery contract (src/storage/sqlite.rs:7070),
/// verified against the real binary rather than assumed from the
/// comment.
#[test]
fn kill_relaunch_recovers_lexical_publish_and_search_stays_stable() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    // Phase A: bootstrap schema through the real CLI, then seed enough
    // conversations directly (bypassing the dual-write path) that
    // lex_docs starts at 0 with messages present -- the real
    // production shape `index_sync`'s staleness check exists to catch,
    // and enough of them that the batched rebuild spans dozens of
    // `CONVERSATIONS_PER_TX` transactions instead of finishing before
    // a concurrent kill can land inside it.
    cass_cmd(&home)
        .args(["index", "--json", "--data-dir"])
        .arg(&data_dir)
        .assert()
        .success();
    let db_path = data_dir.join("agent_search.db");
    const TOTAL_CONVERSATIONS: i64 = 20_000;
    seed_conversations_bypassing_dual_write(&db_path, TOTAL_CONVERSATIONS);
    assert_eq!(
        lex_docs_count(&db_path),
        0,
        "precondition: seeded conversations must bypass lex_docs population entirely"
    );

    // Phase B: trigger the real batched rebuild (`cass doctor --fix`
    // drives `FrankenStorage::rebuild_lex_domain_from_db`) and poll
    // until it is genuinely mid-flight (marker=="building" with a
    // meaningful chunk of lex_docs already committed), then SIGKILL
    // the whole process -- a hard crash, not a graceful shutdown.
    let cass_bin = assert_cmd::cargo::cargo_bin!("cass");
    let mut child = StdCommand::new(cass_bin)
        .current_dir(&home)
        .args(["doctor", "--fix", "--json", "--data-dir"])
        .arg(&data_dir)
        .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .env("CASS_IGNORE_SOURCES_CONFIG", "1")
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cass doctor --fix");

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut observed_mid_rebuild = false;
    loop {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the rebuild to reach a genuinely mid-flight state \
             (marker=building with partial lex_docs) before killing it"
        );
        let marker = lex_domain_rebuild_marker(&db_path);
        let docs = lex_docs_count(&db_path);
        if marker == "building" && docs > 0 && docs < TOTAL_CONVERSATIONS {
            observed_mid_rebuild = true;
            break;
        }
        match child.try_wait() {
            Ok(Some(_)) => break, // finished before we could catch it mid-flight
            Ok(None) => {}
            Err(err) => panic!("failed to poll doctor --fix child: {err}"),
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        observed_mid_rebuild,
        "rebuild finished before a mid-flight state could be observed and killed -- \
         increase TOTAL_CONVERSATIONS so the batched rebuild spans a wider window"
    );

    child.kill().expect("SIGKILL doctor --fix mid-rebuild");
    let exit = child.wait().expect("wait for killed doctor --fix");
    assert!(
        !exit.success(),
        "killed doctor --fix process must exit with failure status"
    );

    let marker_after_kill = lex_domain_rebuild_marker(&db_path);
    let docs_after_kill = lex_docs_count(&db_path);
    assert_eq!(
        marker_after_kill, "building",
        "a hard SIGKILL mid-rebuild must leave the marker stuck at building, not silently \
         advance to completed -- if this fails, the kill landed after the atomic last-batch \
         commit and the test caught the wrong window"
    );
    assert!(
        docs_after_kill > 0 && docs_after_kill < TOTAL_CONVERSATIONS,
        "post-kill lex_docs count ({docs_after_kill}) must be a genuine partial state, \
         not zero (rebuild never started) or complete (kill missed the window)"
    );

    // Phase C: the real recovery path. Routine `cass index` (NOT
    // `--full`) must detect the stuck `building` marker and rebuild
    // the lex domain from the canonical DB to completion.
    let recovery_output = cass_cmd(&home)
        .args(["index", "--json", "--data-dir"])
        .arg(&data_dir)
        .output()
        .expect("run routine cass index for crash recovery");
    assert!(
        recovery_output.status.success(),
        "routine cass index must succeed after crash recovery; stderr: {}",
        String::from_utf8_lossy(&recovery_output.stderr)
    );
    let recovery_json: serde_json::Value = serde_json::from_slice(&recovery_output.stdout)
        .unwrap_or_else(|err| {
            panic!(
                "routine cass index output must be valid JSON: {err}\nstdout: {}",
                String::from_utf8_lossy(&recovery_output.stdout)
            )
        });
    assert_eq!(
        recovery_json["indexing_stats"]["lexical_strategy_reason"].as_str(),
        Some("rebuild_incomplete_lex_domain_from_canonical_db"),
        "routine cass index must recognize the stuck building marker and take the \
         authoritative-DB-rebuild recovery path, not silently no-op; full payload: \
         {recovery_json:#}"
    );

    // Phase D: three-way alignment -- the marker, the lex_docs row
    // count, and the canonical conversation count must all agree.
    let marker_after_recovery = lex_domain_rebuild_marker(&db_path);
    let docs_after_recovery = lex_docs_count(&db_path);
    assert_eq!(
        marker_after_recovery,
        format!("completed:{TOTAL_CONVERSATIONS}:{docs_after_recovery}"),
        "marker must land on completed:<total_conversations>:<lex_docs_count> after recovery"
    );
    assert_eq!(
        docs_after_recovery,
        TOTAL_CONVERSATIONS * 2,
        "lex_docs must cover every message (2 per conversation) after recovery, not just \
         the conversations that happened to be present at kill time"
    );

    // Phase E: search must work and return real results, not the
    // degraded/empty state a still-broken recovery would produce.
    let search_output = cass_cmd(&home)
        .args([
            "search",
            "needle",
            "--json",
            "--mode",
            "lexical",
            "--fields",
            "minimal",
            "--limit",
            "5",
            "--data-dir",
        ])
        .arg(&data_dir)
        .output()
        .expect("search after crash recovery");
    assert!(
        search_output.status.success(),
        "search after kill-relaunch recovery must succeed; stderr: {}",
        String::from_utf8_lossy(&search_output.stderr)
    );
    let search_json: serde_json::Value = serde_json::from_slice(&search_output.stdout)
        .unwrap_or_else(|_| {
            panic!(
                "search output must be valid JSON: {}",
                String::from_utf8_lossy(&search_output.stdout)
            )
        });
    assert!(
        search_json["total_matches"].as_u64().unwrap_or(0) > 0,
        "search after recovery must return at least one result; payload: {search_json:#}"
    );
}
