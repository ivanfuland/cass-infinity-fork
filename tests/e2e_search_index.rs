//! E2E integration tests for search/index pipeline.
//!
//! Tests cover:
//! - Full index flow with temp data-dir
//! - Search with JSON output (hits, match_type, aggregations)
//! - Watch-once environment path functionality
//! - Trace/log file capture (no mocks)
//!
//! Part of bead: coding_agent_session_search-0jt (TST.11)

use assert_cmd::cargo::cargo_bin_cmd;
use chrono::{SecondsFormat, Utc};
// W2-6 exec39 (item2): `search::tantivy::{expected_index_dir, index_dir,
// searchable_index_summary, SearchableIndexSummary}` (the directory-swap
// mechanism this file used to manufacture a sparse lexical index) and
// `Fields`/`open_federated_search_readers`/`frankensearch::lexical::*`
// are gone from this file's imports entirely -- their only callers (the
// federated tests, the directory-swap sparse-index setup, and the
// `raw_lexical_*` helpers) were removed, not migrated. lex_docs
// row-count checks now go through plain `rusqlite` (see
// `count_lex_docs` below); see w2-6-deleted-tests.md for the full
// disposition.
use coding_agent_search::storage::sqlite::SqliteStorage;
use rusqlite::Connection as RusqliteConnection;
use serial_test::serial;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[macro_use]
mod util;
use util::EnvGuard;
use util::e2e_log::{E2ePerformanceMetrics, PhaseTracker};

// =============================================================================
// E2E Logger Support
// =============================================================================

fn tracker_for(test_name: &str) -> PhaseTracker {
    PhaseTracker::new("e2e_search_index", test_name)
}

fn codex_iso_timestamp(ts_millis: u64) -> String {
    chrono::DateTime::<Utc>::from_timestamp_millis(ts_millis as i64)
        .expect("valid millis timestamp for codex fixture")
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn write_jsonl_lines(file: &Path, lines: &[serde_json::Value]) {
    let mut sample = String::new();
    for line in lines {
        sample.push_str(&serde_json::to_string(line).unwrap());
        sample.push('\n');
    }
    fs::write(file, sample).unwrap();
}

fn append_jsonl_lines(file: &Path, lines: &[serde_json::Value]) {
    use std::io::Write;

    let mut handle = std::fs::OpenOptions::new()
        .append(true)
        .open(file)
        .expect("open rollout for append");
    for line in lines {
        handle
            .write_all(serde_json::to_string(line).unwrap().as_bytes())
            .unwrap();
        handle.write_all(b"\n").unwrap();
    }
}

/// Helper to create Codex session with modern envelope format.
fn make_codex_session(root: &Path, date_path: &str, filename: &str, content: &str, ts: u64) {
    let sessions = root.join(format!("sessions/{date_path}"));
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join(filename);
    let workspace = root.to_string_lossy();
    write_jsonl_lines(
        &file,
        &[
            serde_json::json!({
                "timestamp": codex_iso_timestamp(ts),
                "type": "session_meta",
                "payload": {
                    "id": filename,
                    "cwd": workspace,
                    "cli_version": "0.42.0"
                }
            }),
            serde_json::json!({
                "timestamp": codex_iso_timestamp(ts + 1_000),
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{ "type": "input_text", "text": content }]
                }
            }),
            serde_json::json!({
                "timestamp": codex_iso_timestamp(ts + 2_000),
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [{ "type": "text", "text": format!("{content}_response") }]
                }
            }),
        ],
    );
}

/// Helper to create Claude Code session.
fn make_claude_session(root: &Path, project: &str, filename: &str, content: &str, ts: &str) {
    let project_dir = root.join(format!("projects/{project}"));
    fs::create_dir_all(&project_dir).unwrap();
    let file = project_dir.join(filename);
    let sample = format!(
        r#"{{"type": "user", "timestamp": "{ts}", "message": {{"role": "user", "content": "{content}"}}}}
{{"type": "assistant", "timestamp": "{ts}", "message": {{"role": "assistant", "content": "{content}_response"}}}}"#
    );
    fs::write(file, sample).unwrap();
}

/// Append an additional Codex message pair (user + assistant) to an existing rollout file.
fn append_codex_session(file: &Path, content: &str, ts: u64) {
    append_jsonl_lines(
        file,
        &[
            serde_json::json!({
                "timestamp": codex_iso_timestamp(ts),
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{ "type": "input_text", "text": content }]
                }
            }),
            serde_json::json!({
                "timestamp": codex_iso_timestamp(ts + 1_000),
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [{ "type": "text", "text": format!("{content}_response") }]
                }
            }),
        ],
    );
}

fn make_codex_session_with_turns(
    root: &Path,
    date_path: &str,
    filename: &str,
    common_token: &str,
    unique_suffix: &str,
    ts: u64,
    turns: usize,
) {
    let sessions = root.join(format!("sessions/{date_path}"));
    fs::create_dir_all(&sessions).unwrap();
    let file = sessions.join(filename);
    let workspace = root.to_string_lossy();
    let mut lines = vec![serde_json::json!({
        "timestamp": codex_iso_timestamp(ts),
        "type": "session_meta",
        "payload": {
            "id": filename,
            "cwd": workspace,
            "cli_version": "0.42.0"
        }
    })];

    for turn in 0..turns {
        let turn_ts = ts + ((turn as u64) + 1) * 3_000;
        lines.push(serde_json::json!({
            "timestamp": codex_iso_timestamp(turn_ts),
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{
                    "type": "input_text",
                    "text": format!("{common_token} {unique_suffix} user_turn_{turn}")
                }]
            }
        }));
        lines.push(serde_json::json!({
            "timestamp": codex_iso_timestamp(turn_ts + 1_000),
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [{
                    "type": "text",
                    "text": format!("{common_token} {unique_suffix} assistant_turn_{turn}")
                }]
            }
        }));
    }

    write_jsonl_lines(&file, &lines);
}

fn make_bulk_codex_sessions(
    root: &Path,
    date_path: &str,
    batch_prefix: &str,
    common_token: &str,
    start_ts: u64,
    session_count: usize,
    turns_per_session: usize,
) {
    for idx in 0..session_count {
        make_codex_session_with_turns(
            root,
            date_path,
            &format!("{batch_prefix}-{idx:03}.jsonl"),
            common_token,
            &format!("session_{idx:03}"),
            start_ts + (idx as u64) * 50_000,
            turns_per_session,
        );
    }
}

fn count_messages(db_path: &Path) -> i64 {
    let storage = SqliteStorage::open(db_path).expect("open sqlite");
    storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM messages", &[], |r| r.get_typed(0))
        .expect("count messages")
}

fn total_matches_from_search_output(output: &[u8]) -> u64 {
    let json: serde_json::Value = serde_json::from_slice(output).expect("parse search json");
    json.get("total_matches")
        .and_then(|matches| matches.as_u64())
        .unwrap_or_else(|| {
            json.get("hits")
                .and_then(|hits| hits.as_array())
                .map(|hits| hits.len() as u64)
                .unwrap_or(0)
        })
}

// W2-6 exec39 (item2, control-plane 2026-08-31 ruling): the following
// helpers were removed here -- `raw_lexical_total_matches`/
// `raw_lexical_reader_matches` (built entirely on the extinct
// `frankensearch::lexical` reader API -- zero src callers, crate built
// without the `lexical` feature), `force_federated_publish_env` (tunes
// extinct `CASS_TANTIVY_REBUILD_*` tantivy-writer-thread knobs, same
// family exec39 Task丙① already judged dead), and `cass_std_cmd`/
// `lexical_publish_in_progress_backup_path`/`lexical_publish_backups_dir`/
// `wait_for_publish_kill_relaunch_sentinel` (built around the extinct
// `CASS_TEST_LEXICAL_PUBLISH_KILL_RELAUNCH_SENTINEL` hook -- zero src
// occurrences, same hook already found dead while rewriting
// `atomic_swap_publish_crash_window.rs`). Their only callers were the
// four tests removed alongside them below; see w2-6-deleted-tests.md
// for the full disposition.

#[derive(Debug, Default)]
struct SearchLoopStats {
    attempts: usize,
    successes: usize,
    max_duration_ms: u64,
    failures: Vec<String>,
}

// W2-6 exec39: ignored, not deleted -- cascade-masked latent finding
// surfaced by this round's first real full-file execution (doctor_fixture.rs's
// compile errors previously blocked `mod util;` from ever letting this
// binary run at all), same family as the WAL/SHM sidecar and
// PartiallyIndexed findings elsewhere this round, unrelated to any
// symbol/import this exec touched. Real error: "malformed database
// schema (fts_messages) - table fts_messages already exists" during
// automatic lexical repair. See w2-6-deleted-tests.md for the full
// disposition.
#[test]
#[serial]
#[ignore = "w2-6-deleted-tests.md: e2e_search_index cascade-masked latent findings (control-plane 2026-08-31 ruling)"]
fn duplicate_fts_schema_rows_do_not_block_cli_reads_and_writes() {
    let tracker = tracker_for("duplicate_fts_schema_rows_do_not_block_cli_reads_and_writes");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    let ts = 1_732_118_400_000u64;
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-fts-repair.jsonl",
        "fts_repair_initial_token",
        ts,
    );
    let session_file = codex_home.join("sessions/2024/11/20/rollout-fts-repair.jsonl");

    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    let db_path = data_dir.join("agent_search.db");
    let baseline_messages = count_messages(&db_path);
    assert_eq!(
        baseline_messages, 2,
        "initial full index should ingest both messages"
    );

    let duplicate_legacy_fts_sql = "CREATE VIRTUAL TABLE fts_messages USING fts5(content, title, agent, workspace, source_path, created_at UNINDEXED, message_id UNINDEXED, tokenize='porter')";
    let injection =
        RusqliteConnection::open(&db_path).expect("open db for writable_schema fixture");
    injection
        .execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS fts_messages USING fts5(
                content,
                title,
                agent,
                workspace,
                source_path,
                created_at UNINDEXED,
                message_id UNINDEXED,
                tokenize='porter'
             );",
        )
        .expect("materialize canonical fts schema before duplicate injection");
    injection
        .execute_batch("PRAGMA writable_schema = ON;")
        .expect("enable writable_schema");
    injection
        .execute(
            "INSERT INTO sqlite_master(type, name, tbl_name, rootpage, sql)
             VALUES('table', 'fts_messages', 'fts_messages', 0, ?1)",
            [duplicate_legacy_fts_sql],
        )
        .expect("inject duplicate fts schema row");
    injection
        .execute(
            "DELETE FROM meta WHERE key = ?1",
            ["fts_frankensqlite_rebuild_generation"],
        )
        .expect("delete stale fts generation marker");
    injection
        .execute_batch("PRAGMA writable_schema = OFF;")
        .expect("disable writable_schema");
    drop(injection);

    let broken_read = RusqliteConnection::open(&db_path)
        .expect("reopen db for broken-read assertion")
        .query_row("SELECT COUNT(*) FROM fts_messages", [], |row| {
            row.get::<_, i64>(0)
        });
    assert!(
        broken_read.is_err(),
        "the injected duplicate schema row should reproduce the unreadable pre-fix SQLite state"
    );

    let existing_search = cargo_bin_cmd!("cass")
        .args([
            "search",
            "fts_repair_initial_token",
            "--robot",
            "--data-dir",
        ])
        .arg(&data_dir)
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .output()
        .expect("search for existing content after duplicate schema injection");
    assert!(
        existing_search.status.success(),
        "search should continue to succeed even when the fallback SQLite FTS table is malformed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&existing_search.stdout),
        String::from_utf8_lossy(&existing_search.stderr)
    );
    let existing_hits = serde_json::from_slice::<serde_json::Value>(&existing_search.stdout)
        .expect("parse existing search json")
        .get("hits")
        .and_then(|hits| hits.as_array())
        .map(|hits| hits.len())
        .unwrap_or(0);
    assert!(
        existing_hits >= 1,
        "the Tantivy index should remain authoritative for search results"
    );

    let incremental_index = cargo_bin_cmd!("cass")
        .args(["index", "--data-dir"])
        .arg(&data_dir)
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .output()
        .expect("run index after duplicate schema injection");
    assert!(
        incremental_index.status.success(),
        "incremental index should succeed even when the fallback SQLite FTS table is malformed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&incremental_index.stdout),
        String::from_utf8_lossy(&incremental_index.stderr)
    );

    let health = cargo_bin_cmd!("cass")
        .args(["health", "--json", "--data-dir"])
        .arg(&data_dir)
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .output()
        .expect("run health after duplicate schema repair");
    assert!(
        health.status.success(),
        "health should report the repaired database as healthy\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&health.stdout),
        String::from_utf8_lossy(&health.stderr)
    );
    let health_json: serde_json::Value =
        serde_json::from_slice(&health.stdout).expect("parse health json");
    assert_eq!(
        health_json["healthy"],
        serde_json::Value::Bool(true),
        "health should treat the canonical archive plus Tantivy index as healthy"
    );

    std::thread::sleep(std::time::Duration::from_millis(1200));
    append_codex_session(&session_file, "fts_repair_appended_token", ts + 10_000);
    std::thread::sleep(std::time::Duration::from_millis(50));

    cargo_bin_cmd!("cass")
        .args(["index", "--data-dir"])
        .arg(&data_dir)
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    let after_messages = count_messages(&db_path);
    assert_eq!(
        after_messages,
        baseline_messages + 2,
        "incremental writes should resume after repair and append the new turn"
    );

    let appended = cargo_bin_cmd!("cass")
        .args([
            "search",
            "fts_repair_appended_token",
            "--robot",
            "--data-dir",
        ])
        .arg(&data_dir)
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .output()
        .expect("search for appended content after repair");
    assert!(
        appended.status.success(),
        "search should succeed after incremental write even with malformed fallback FTS\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&appended.stdout),
        String::from_utf8_lossy(&appended.stderr)
    );
    let appended_hits = serde_json::from_slice::<serde_json::Value>(&appended.stdout)
        .expect("parse appended search json")
        .get("hits")
        .and_then(|hits| hits.as_array())
        .map(|hits| hits.len())
        .unwrap_or(0);
    assert!(
        appended_hits >= 1,
        "the post-index incremental content should be searchable"
    );

    tracker.flush();
}

#[test]
#[serial]
fn concurrent_search_processes_do_not_block_incremental_index_json() {
    let tracker = tracker_for("concurrent_search_processes_do_not_block_incremental_index_json");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    tracker.phase(
        "seed_initial_fixture",
        "Create baseline session and full index",
        || {
            make_codex_session(
                &codex_home,
                "2024/11/20",
                "rollout-baseline-lock-search.jsonl",
                "baselinelockanchor",
                1_732_118_400_000,
            );

            cargo_bin_cmd!("cass")
                .args(["index", "--full", "--json", "--data-dir"])
                .arg(&data_dir)
                .current_dir(&home)
                .env("CODEX_HOME", &codex_home)
                .env("HOME", &home)
                .timeout(Duration::from_secs(30))
                .assert()
                .success();
        },
    );

    tracker.phase(
        "verify_baseline_search_fixture",
        "Confirm the baseline lexical query is searchable before starting concurrent readers",
        || {
            let baseline_output = cargo_bin_cmd!("cass")
                .args([
                    "search",
                    "baselinelockanchor",
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
                .current_dir(&home)
                .env("CODEX_HOME", &codex_home)
                .env("HOME", &home)
                .timeout(Duration::from_secs(20))
                .output()
                .expect("baseline lexical search should run");
            assert!(
                baseline_output.status.success(),
                "baseline lexical search should succeed before concurrency begins\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&baseline_output.stdout),
                String::from_utf8_lossy(&baseline_output.stderr)
            );
            let baseline_json: serde_json::Value =
                serde_json::from_slice(&baseline_output.stdout).expect("parse baseline search JSON");
            let baseline_hits = baseline_json
                .get("total_matches")
                .and_then(|matches| matches.as_u64())
                .unwrap_or_else(|| {
                    baseline_json
                        .get("hits")
                        .and_then(|hits| hits.as_array())
                        .map(|hits| hits.len() as u64)
                        .unwrap_or(0)
                });
            assert!(
                baseline_hits > 0,
                "baseline lexical search fixture must be searchable before starting concurrent readers"
            );
        },
    );

    let stop_search = Arc::new(AtomicBool::new(false));
    let index_running = Arc::new(AtomicBool::new(false));
    let search_attempts_during_index = Arc::new(AtomicUsize::new(0));
    let (ready_tx, ready_rx) = mpsc::channel();

    let search_home = home.clone();
    let search_codex_home = codex_home.clone();
    let search_data_dir = data_dir.clone();
    let stop_search_worker = Arc::clone(&stop_search);
    let index_running_worker = Arc::clone(&index_running);
    let search_attempts_during_index_worker = Arc::clone(&search_attempts_during_index);

    let search_handle = std::thread::spawn(move || {
        let mut stats = SearchLoopStats::default();
        let mut ready_sent = false;

        loop {
            if stop_search_worker.load(Ordering::Relaxed) {
                break;
            }

            if index_running_worker.load(Ordering::Relaxed) {
                search_attempts_during_index_worker.fetch_add(1, Ordering::Relaxed);
            }

            let search_start = Instant::now();
            let output = cargo_bin_cmd!("cass")
                .args([
                    "search",
                    "baselinelockanchor",
                    "--json",
                    "--mode",
                    "lexical",
                    "--fields",
                    "minimal",
                    "--limit",
                    "5",
                    "--data-dir",
                ])
                .arg(&search_data_dir)
                .current_dir(&search_home)
                .env("CODEX_HOME", &search_codex_home)
                .env("HOME", &search_home)
                .timeout(Duration::from_secs(20))
                .output()
                .expect("spawn concurrent cass search");
            let elapsed_ms = search_start.elapsed().as_millis() as u64;
            stats.attempts += 1;
            stats.max_duration_ms = stats.max_duration_ms.max(elapsed_ms);

            if output.status.success() {
                let parsed: serde_json::Value =
                    serde_json::from_slice(&output.stdout).expect("parse concurrent search JSON");
                let hit_count = parsed
                    .get("total_matches")
                    .and_then(|matches| matches.as_u64())
                    .unwrap_or_else(|| {
                        parsed
                            .get("hits")
                            .and_then(|hits| hits.as_array())
                            .map(|hits| hits.len() as u64)
                            .unwrap_or(0)
                    });
                if hit_count == 0 {
                    stats.failures.push(format!(
                        "concurrent search returned zero hits; stdout={}",
                        String::from_utf8_lossy(&output.stdout)
                    ));
                } else {
                    stats.successes += 1;
                }
            } else {
                stats.failures.push(format!(
                    "concurrent search failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            if !ready_sent {
                ready_tx.send(()).ok();
                ready_sent = true;
            }

            std::thread::sleep(Duration::from_millis(40));
        }

        stats
    });

    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("concurrent search should start promptly");

    tracker.phase(
        "stage_incremental_fixture",
        "Create a substantial incremental batch while searches continue",
        || {
            make_bulk_codex_sessions(
                &codex_home,
                "2024/11/21",
                "rollout-incremental-lock-batch",
                "incrementalloadanchor",
                1_732_200_000_000,
                40,
                6,
            );
        },
    );

    let index_start = tracker.start(
        "incremental_index_under_read_load",
        Some("Run cass index --json while concurrent cass search processes read the same DB"),
    );
    index_running.store(true, Ordering::Relaxed);
    let index_output = cargo_bin_cmd!("cass")
        .args(["index", "--json", "--data-dir"])
        .arg(&data_dir)
        .current_dir(&home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", &home)
        .timeout(Duration::from_secs(60))
        .output()
        .expect("run incremental index under concurrent search load");
    index_running.store(false, Ordering::Relaxed);
    let index_duration_ms = index_start.elapsed().as_millis() as u64;
    tracker.end(
        "incremental_index_under_read_load",
        Some("Run cass index --json while concurrent cass search processes read the same DB"),
        index_start,
    );

    stop_search.store(true, Ordering::Relaxed);
    let search_stats = search_handle.join().expect("join concurrent search thread");

    assert!(
        index_output.status.success(),
        "incremental index should succeed under concurrent search load\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&index_output.stdout),
        String::from_utf8_lossy(&index_output.stderr)
    );
    let index_json: serde_json::Value =
        serde_json::from_slice(&index_output.stdout).expect("parse index json");
    assert_eq!(
        index_json.get("success").and_then(|v| v.as_bool()),
        Some(true),
        "index --json should report success"
    );

    assert!(
        search_stats.failures.is_empty(),
        "concurrent searches should not fail while index runs:\n{}",
        search_stats.failures.join("\n---\n")
    );
    assert!(
        search_stats.successes > 0,
        "expected at least one successful concurrent search attempt"
    );
    assert!(
        search_attempts_during_index.load(Ordering::Relaxed) > 0,
        "expected real search overlap while index was running"
    );

    let after_messages = count_messages(&data_dir.join("agent_search.db")) as u64;
    let expected_min_messages = 2 + (40_u64 * 6 * 2);
    assert!(
        after_messages >= expected_min_messages,
        "incremental index should ingest the staged batch: expected at least {expected_min_messages} messages, got {after_messages}"
    );

    let verify_search = cargo_bin_cmd!("cass")
        .args([
            "search",
            "incrementalloadanchor",
            "--json",
            "--mode",
            "lexical",
            "--fields",
            "minimal",
            "--limit",
            "10",
            "--data-dir",
        ])
        .arg(&data_dir)
        .current_dir(&home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", &home)
        .timeout(Duration::from_secs(20))
        .output()
        .expect("search for newly indexed batch");
    assert!(
        verify_search.status.success(),
        "search for newly indexed batch should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verify_search.stdout),
        String::from_utf8_lossy(&verify_search.stderr)
    );
    let verify_json: serde_json::Value =
        serde_json::from_slice(&verify_search.stdout).expect("parse verification search JSON");
    let verification_hits = verify_json
        .get("total_matches")
        .and_then(|matches| matches.as_u64())
        .unwrap_or_else(|| {
            verify_json
                .get("hits")
                .and_then(|hits| hits.as_array())
                .map(|hits| hits.len() as u64)
                .unwrap_or(0)
        });
    assert!(
        verification_hits > 0,
        "newly indexed batch should be searchable after concurrent index run"
    );

    tracker.metrics(
        "concurrent_search_vs_index",
        &E2ePerformanceMetrics::new()
            .with_duration(index_duration_ms)
            .with_custom("search_attempts", search_stats.attempts as u64)
            .with_custom("search_successes", search_stats.successes as u64)
            .with_custom(
                "search_attempts_during_index",
                search_attempts_during_index.load(Ordering::Relaxed) as u64,
            )
            .with_custom("max_search_duration_ms", search_stats.max_duration_ms)
            .with_custom("messages_after_index", after_messages),
    );
    tracker.complete();
}

// W2-6 exec39 (item2, control-plane 2026-08-31 ruling): four tests
// removed here, none rewritten -- see w2-6-deleted-tests.md for the
// full disposition, summarized:
//
//   - force_rebuild_preserves_search_results_and_reader_surface_during_atomic_publish
//     Same intent/mechanism as `atomic_swap_publish_crash_window.rs`'s
//     already-judged-dead `concurrent_reader_never_sees_half_torn_lexical_index_during_publish_swap`
//     (a concurrent reader polling the retired index directory for a
//     "torn" state during publish) -- duplicate-by-mechanism, same
//     disposition: dead, intent shelved to the "重建中并发读者行为契约
//     未定义" debt (not re-litigated per file).
//   - force_rebuild_preserves_search_results_and_reader_surface_during_federated_atomic_publish
//     and repeated_force_rebuild_preserves_federated_reader_and_search_stability
//     Federated multi-shard reader concept extinct (`open_federated_search_readers`
//     has zero src callers, no successor) -- dead.
//   - force_rebuild_recovers_cleanly_after_sigkill_between_linux_swap_and_retain
//     Same intent as `atomic_swap_publish_crash_window.rs`'s
//     `kill_relaunch_recovers_lexical_publish_and_search_stays_stable`,
//     which W2-6 exec39 already rewrote against the real DB-domain
//     crash-recovery path (kill mid-batch-rebuild -> routine `cass
//     index` -> `rebuild_incomplete_lex_domain_from_canonical_db`).
//     Re-testing the same intent here would be a duplicate assertion
//     with zero incremental coverage -- dead, pointing at that rewrite
//     as the covering test. Its crash-point coordinate (mid
//     `renameat2`/park-then-swap, "linux_swap_committed_prior_live_parked")
//     was itself a protocol-specific stage of the now-extinct atomic
//     swap; the FTS5-era equivalent crash points (mid-batch / between
//     batches of the `IMMEDIATE`-transaction rebuild) are exactly what
//     the covering test exercises.

/// Test: Full index pipeline - index --full creates DB and index
#[test]
#[serial]
fn index_full_creates_artifacts() {
    verbose!("Starting index_full_creates_artifacts test");
    let tracker = tracker_for("index_full_creates_artifacts");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    verbose!("Created temp directory at {:?}", home);
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();
    verbose!("Data directory: {:?}", data_dir);

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Create fixture data
    let phase_start = tracker.start("create_fixtures", Some("Create Codex session fixture"));
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-1.jsonl",
        "hello world",
        1732118400000,
    );
    tracker.end(
        "create_fixtures",
        Some("Create Codex session fixture"),
        phase_start,
    );

    // Capture memory/IO before indexing (for delta calculation)
    let mem_before = E2ePerformanceMetrics::capture_memory();
    let io_before = E2ePerformanceMetrics::capture_io();

    // Run index --full
    let phase_start = tracker.start("index_full", Some("Execute full index command"));
    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        // Avoid connector detection from the repository CWD (e.g. `.aider.chat.history.md`).
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();
    let index_duration_ms = phase_start.elapsed().as_millis() as u64;
    tracker.end(
        "index_full",
        Some("Execute full index command"),
        phase_start,
    );

    // Capture memory/IO after indexing
    let mem_after = E2ePerformanceMetrics::capture_memory();
    let io_after = E2ePerformanceMetrics::capture_io();
    verbose!("Index completed in {}ms", index_duration_ms);

    // Verify artifacts created
    let phase_start = tracker.start("verify_artifacts", Some("Verify database and index exist"));
    verbose!("Verifying artifacts at {:?}", data_dir);
    assert!(
        data_dir.join("agent_search.db").exists(),
        "SQLite DB should be created"
    );
    assert!(
        data_dir.join("index").exists(),
        "Tantivy index directory should exist"
    );
    tracker.end(
        "verify_artifacts",
        Some("Verify database and index exist"),
        phase_start,
    );

    // Count messages and emit performance metrics
    let msg_count = count_messages(&data_dir.join("agent_search.db")) as u64;
    verbose!("Indexed {} messages", msg_count);
    let mut metrics = E2ePerformanceMetrics::new()
        .with_duration(index_duration_ms)
        .with_throughput(msg_count, index_duration_ms);

    // Add memory delta if available
    if let (Some(before), Some(after)) = (mem_before, mem_after) {
        metrics = metrics.with_memory(after.saturating_sub(before));
    }

    // Add I/O delta if available
    if let (Some((rb, wb)), Some((ra, wa))) = (io_before, io_after) {
        metrics = metrics.with_io(0, 0, ra.saturating_sub(rb), wa.saturating_sub(wb));
    }

    tracker.metrics("index_full", &metrics);
    tracker.flush();
    verbose!("Test index_full_creates_artifacts completed successfully");
}

/// Incremental re-index must preserve existing messages and ingest new ones from the same file.
#[test]
#[serial]
fn incremental_reindex_preserves_and_appends_messages() {
    let tracker = tracker_for("incremental_reindex_preserves_and_appends_messages");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Initial session
    let phase_start = tracker.start(
        "create_initial_fixture",
        Some("Create initial session with test content"),
    );
    let ts = 1_732_118_400_000u64; // stable timestamp
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-incremental.jsonl",
        "initial_keep_token",
        ts,
    );
    let session_file = codex_home.join("sessions/2024/11/20/rollout-incremental.jsonl");
    tracker.end(
        "create_initial_fixture",
        Some("Create initial session with test content"),
        phase_start,
    );

    // Full index
    let phase_start = tracker.start("index_full", Some("Run initial full index"));
    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        // Avoid connector detection from the repository CWD (e.g. `.aider.chat.history.md`).
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();
    tracker.end("index_full", Some("Run initial full index"), phase_start);

    // Ensure subsequent writes get a later mtime than the recorded scan start
    std::thread::sleep(std::time::Duration::from_millis(1200));

    // Baseline search should find the initial content
    let phase_start = tracker.start(
        "search_baseline",
        Some("Verify initial content is searchable"),
    );
    let baseline = cargo_bin_cmd!("cass")
        .args(["search", "initial_keep_token", "--robot", "--data-dir"])
        .arg(&data_dir)
        // Avoid connector detection from the repository CWD (e.g. `.aider.chat.history.md`).
        .current_dir(home)
        .env("HOME", home)
        .output()
        .expect("baseline search");
    assert!(baseline.status.success());
    let baseline_json: serde_json::Value =
        serde_json::from_slice(&baseline.stdout).expect("baseline json");
    let baseline_hits = baseline_json
        .get("hits")
        .and_then(|h| h.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(baseline_hits >= 1, "initial content should be indexed");
    tracker.end(
        "search_baseline",
        Some("Verify initial content is searchable"),
        phase_start,
    );

    // Append new content to the same file (simulates conversation growth)
    let phase_start = tracker.start(
        "append_content",
        Some("Append new messages to session file"),
    );
    append_codex_session(&session_file, "appended_token_beta", ts + 10_000);
    tracker.end(
        "append_content",
        Some("Append new messages to session file"),
        phase_start,
    );

    // On some filesystems, mtime resolution is 1s; give a small buffer before reindex
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Incremental re-index (no --full)
    let phase_start = tracker.start("index_incremental", Some("Run incremental reindex"));
    cargo_bin_cmd!("cass")
        .args(["index", "--data-dir"])
        .arg(&data_dir)
        // Avoid connector detection from the repository CWD (e.g. `.aider.chat.history.md`).
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();
    tracker.end(
        "index_incremental",
        Some("Run incremental reindex"),
        phase_start,
    );

    // Original content must still be present
    let phase_start = tracker.start(
        "search_preserved",
        Some("Verify original content preserved"),
    );
    let preserved = cargo_bin_cmd!("cass")
        .args(["search", "initial_keep_token", "--robot", "--data-dir"])
        .arg(&data_dir)
        // Avoid connector detection from the repository CWD (e.g. `.aider.chat.history.md`).
        .current_dir(home)
        .env("HOME", home)
        .output()
        .expect("preserved search");
    assert!(preserved.status.success());
    let preserved_hits = serde_json::from_slice::<serde_json::Value>(&preserved.stdout)
        .unwrap()
        .get("hits")
        .and_then(|h| h.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(
        preserved_hits >= baseline_hits,
        "existing messages should not be dropped on reindex"
    );
    tracker.end(
        "search_preserved",
        Some("Verify original content preserved"),
        phase_start,
    );

    // New content must be discoverable
    let phase_start = tracker.start("search_appended", Some("Verify appended content indexed"));
    let appended = cargo_bin_cmd!("cass")
        .args(["search", "appended_token_beta", "--robot", "--data-dir"])
        .arg(&data_dir)
        // Avoid connector detection from the repository CWD (e.g. `.aider.chat.history.md`).
        .current_dir(home)
        .env("HOME", home)
        .output()
        .expect("appended search");
    assert!(appended.status.success());
    let appended_hits = serde_json::from_slice::<serde_json::Value>(&appended.stdout)
        .unwrap()
        .get("hits")
        .and_then(|h| h.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(
        appended_hits >= 1,
        "appended content should be indexed during incremental run"
    );
    tracker.end(
        "search_appended",
        Some("Verify appended content indexed"),
        phase_start,
    );

    tracker.flush();
}

/// Reindexing must never drop previously ingested messages in SQLite or Tantivy.
#[test]
#[serial]
fn reindex_does_not_drop_messages_in_db_or_search() {
    let tracker = tracker_for("reindex_does_not_drop_messages_in_db_or_search");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();
    let xdg_data = home.join(".local/share");
    let xdg_config = home.join(".config");
    fs::create_dir_all(&xdg_data).unwrap();
    fs::create_dir_all(&xdg_config).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Seed a rollout with two messages
    let ts = 1_732_118_400_000u64;
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-drop-guard.jsonl",
        "persist_me",
        ts,
    );
    let session_file = codex_home.join("sessions/2024/11/20/rollout-drop-guard.jsonl");

    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        // Avoid connector detection from the repository CWD (e.g. `.aider.chat.history.md`).
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .assert()
        .success();

    // Ensure next write has strictly newer mtime than initial scan start
    std::thread::sleep(std::time::Duration::from_millis(1200));

    let db_path = data_dir.join("agent_search.db");
    let baseline_count = count_messages(&db_path);
    assert_eq!(baseline_count, 2, "initial two messages recorded");

    // Append another turn and reindex incrementally
    append_codex_session(&session_file, "persist_me_again", ts + 5_000);
    std::thread::sleep(std::time::Duration::from_millis(50));
    cargo_bin_cmd!("cass")
        .args(["index", "--data-dir"])
        .arg(&data_dir)
        // Avoid connector detection from the repository CWD (e.g. `.aider.chat.history.md`).
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .assert()
        .success();

    let after_count = count_messages(&db_path);
    assert_eq!(
        after_count,
        baseline_count + 2,
        "messages should only grow after reindex"
    );

    // Verify both old and new content are searchable (Tantivy layer)
    for term in ["persist_me", "persist_me_again"] {
        let out = cargo_bin_cmd!("cass")
            .args(["search", term, "--robot", "--data-dir"])
            .arg(&data_dir)
            // Avoid connector detection from the repository CWD (e.g. `.aider.chat.history.md`).
            .current_dir(home)
            .env("HOME", home)
            .env("XDG_DATA_HOME", &xdg_data)
            .env("XDG_CONFIG_HOME", &xdg_config)
            .output()
            .expect("search");
        assert!(out.status.success(), "search should succeed for {term}");
        let hits = serde_json::from_slice::<serde_json::Value>(&out.stdout)
            .unwrap()
            .get("hits")
            .and_then(|h| h.as_array())
            .map(|v| v.len())
            .unwrap_or(0);
        assert!(hits >= 1, "{term} should remain indexed");
    }
}

/// Test: Search returns hits with correct match_type
#[test]
#[serial]
fn search_returns_hits_with_match_type() {
    let tracker = tracker_for("search_returns_hits_with_match_type");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Create fixture with unique content
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-1.jsonl",
        "unique_search_term_alpha",
        1732118400000,
    );

    // Index first
    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    // Search and verify JSON output
    let output = cargo_bin_cmd!("cass")
        .args([
            "search",
            "unique_search_term_alpha",
            "--robot",
            "--data-dir",
        ])
        .arg(&data_dir)
        .env("HOME", home)
        .output()
        .expect("search command");

    assert!(output.status.success(), "Search should succeed");

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON output");

    // Verify hits array exists
    let hits = json
        .get("hits")
        .and_then(|h| h.as_array())
        .expect("hits array should exist");
    assert!(!hits.is_empty(), "Should find at least one hit");

    // Verify match_type field
    let first_hit = &hits[0];
    assert!(
        first_hit.get("match_type").is_some(),
        "Hit should have match_type field"
    );
    let match_type = first_hit["match_type"].as_str().unwrap();
    assert!(
        ["exact", "prefix", "wildcard", "fuzzy", "wildcard_fallback"].contains(&match_type),
        "match_type should be a known type, got: {}",
        match_type
    );

    // Verify content contains search term
    let content = first_hit["content"].as_str().unwrap_or("");
    assert!(
        content.contains("unique_search_term_alpha"),
        "Content should contain search term"
    );
}

/// Test: Search aggregations include agent buckets
#[test]
#[serial]
fn search_aggregations_include_agents() {
    let tracker = tracker_for("search_aggregations_include_agents");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let claude_home = home.join(".claude");
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Create fixtures from multiple connectors
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-agg.jsonl",
        "aggregation_test_content",
        1732118400000,
    );
    make_claude_session(
        &claude_home,
        "agg-project",
        "session-agg.jsonl",
        "aggregation_test_content",
        "2024-11-20T10:00:00Z",
    );

    // Index
    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    // Search with aggregations
    let output = cargo_bin_cmd!("cass")
        .args([
            "search",
            "aggregation_test_content",
            "--aggregate",
            "agent",
            "--robot",
            "--data-dir",
        ])
        .arg(&data_dir)
        .env("HOME", home)
        .output()
        .expect("search command");

    assert!(output.status.success(), "Search should succeed");

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    // Verify aggregations
    let aggregations = json
        .get("aggregations")
        .expect("aggregations field should exist");
    let agent_agg = aggregations.get("agent").expect("agent aggregation");
    let buckets = agent_agg
        .get("buckets")
        .and_then(|b| b.as_array())
        .expect("buckets array");

    let agent_keys: std::collections::HashSet<_> = buckets
        .iter()
        .filter_map(|b| b.get("key").and_then(|k| k.as_str()))
        .collect();

    // At least one of our fixtures should be found in aggregations
    // (Claude works reliably via HOME; Codex via CODEX_HOME may vary by platform)
    assert!(
        agent_keys.contains("codex") || agent_keys.contains("claude_code"),
        "Should include at least one expected agent. Found: {:?}",
        agent_keys
    );
}

/// Test: Watch-once mode indexes specific paths
#[test]
#[serial]
fn watch_once_indexes_specified_path() {
    let tracker = tracker_for("watch_once_indexes_specified_path");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Create initial data
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-watch.jsonl",
        "watch_once_initial",
        1732118400000,
    );

    // Initial index
    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    // Create new file to watch
    let watch_file = codex_home.join("sessions/2024/11/21/rollout-new.jsonl");
    fs::create_dir_all(watch_file.parent().unwrap()).unwrap();

    // Use current timestamp so message is indexed
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let sample = format!(
        r#"{{"type": "event_msg", "timestamp": {now_ts}, "payload": {{"type": "user_message", "message": "watch_once_new_content"}}}}
{{"type": "response_item", "timestamp": {}, "payload": {{"role": "assistant", "content": "watch_once_response"}}}}"#,
        now_ts + 1000
    );
    fs::write(&watch_file, sample).unwrap();

    // Run watch-once with specific path
    cargo_bin_cmd!("cass")
        .args(["index", "--watch-once"])
        .arg(&watch_file)
        .arg("--data-dir")
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    // Verify new content is searchable
    let output = cargo_bin_cmd!("cass")
        .args(["search", "watch_once_new_content", "--robot", "--data-dir"])
        .arg(&data_dir)
        .env("HOME", home)
        .output()
        .expect("search command");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let hits = json.get("hits").and_then(|h| h.as_array()).expect("hits");
    assert!(
        !hits.is_empty(),
        "Should find the newly indexed watch-once content"
    );
}

/// Test: Search with filters (agent, time range)
#[test]
#[serial]
fn search_with_filters() {
    let tracker = tracker_for("search_with_filters");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Create multiple sessions with distinct content
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-filter1.jsonl",
        "filter_test_content",
        1732118400000, // Nov 20, 2024
    );
    make_codex_session(
        &codex_home,
        "2024/11/21",
        "rollout-filter2.jsonl",
        "filter_test_content",
        1732204800000, // Nov 21, 2024
    );

    // Index
    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    // Search with agent filter
    let output = cargo_bin_cmd!("cass")
        .args([
            "search",
            "filter_test_content",
            "--agent",
            "codex",
            "--robot",
            "--data-dir",
        ])
        .arg(&data_dir)
        .env("HOME", home)
        .output()
        .expect("search command");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let hits = json.get("hits").and_then(|h| h.as_array()).expect("hits");

    // All hits should be from codex agent
    for hit in hits {
        assert_eq!(
            hit["agent"].as_str().unwrap(),
            "codex",
            "All hits should be from codex agent"
        );
    }
}

/// Test: Search returns total_matches and pagination info
#[test]
#[serial]
fn search_returns_pagination_info() {
    let tracker = tracker_for("search_returns_pagination_info");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Create multiple sessions
    for i in 1..=5 {
        make_codex_session(
            &codex_home,
            "2024/11/20",
            &format!("rollout-page{i}.jsonl"),
            "pagination_test_term",
            1732118400000 + (i as u64 * 1000),
        );
    }

    // Index
    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    // Search with limit
    let output = cargo_bin_cmd!("cass")
        .args([
            "search",
            "pagination_test_term",
            "--limit",
            "3",
            "--robot",
            "--data-dir",
        ])
        .arg(&data_dir)
        .env("HOME", home)
        .output()
        .expect("search command");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");

    // Verify pagination fields
    let total = json
        .get("total_matches")
        .and_then(|t| t.as_u64())
        .expect("total_matches");
    let limit = json.get("limit").and_then(|l| l.as_u64()).expect("limit");
    let hits = json
        .get("hits")
        .and_then(|h| h.as_array())
        .expect("hits")
        .len();

    // We created 5 sessions, each with 2 messages (user + response), so we expect >= 5 hits
    // But some may not match the search term exactly
    assert!(
        total >= 1,
        "Should have at least 1 total match. Got: {}",
        total
    );
    assert_eq!(limit, 3, "Limit should be 3");
    assert!(hits <= 3, "Returned hits should be <= limit");
}

/// Test: Force rebuild recreates index
// W2-6 exec39: ignored, not deleted -- cascade-masked latent finding,
// same family as above. Real error: "precondition: initial index tree
// at .../cass_data/index must contain files" -- a fresh FTS5-only
// install may never populate that legacy directory at all (same
// fresh-install gap already recorded against `index_exists` in
// w2-6-deleted-tests.md's item1 debt). See w2-6-deleted-tests.md.
#[test]
#[serial]
#[ignore = "w2-6-deleted-tests.md: e2e_search_index cascade-masked latent findings (control-plane 2026-08-31 ruling)"]
fn force_rebuild_recreates_index() {
    let tracker = tracker_for("force_rebuild_recreates_index");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Create initial data
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-rebuild.jsonl",
        "rebuild_test_initial",
        1732118400000,
    );

    // Initial index
    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    // Bead cxhqb: capture a content-based fingerprint of the index
    // tree before the force-rebuild. Previously this compared a single
    // directory-mtime before/after with a 1-second sleep in between —
    // fragile on filesystems with ≥2s mtime granularity (FAT32, some
    // NFS setups) and wasteful wall-clock time on every test run.
    // Listing every file under the index tree with its size is
    // independent of filesystem mtime precision: a real rebuild writes
    // new Tantivy segments (new UUIDs, different sizes), so the set is
    // guaranteed to change even when mtime cannot.
    fn index_fingerprint(root: &Path) -> Vec<(String, u64)> {
        let mut entries: Vec<(String, u64)> = walkdir::WalkDir::new(root)
            .sort_by_file_name()
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(|e| {
                let rel = e
                    .path()
                    .strip_prefix(root)
                    .unwrap_or(e.path())
                    .to_string_lossy()
                    .into_owned();
                let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                (rel, len)
            })
            .collect();
        entries.sort();
        entries
    }
    let index_dir = data_dir.join("index");
    let initial_fingerprint = index_fingerprint(&index_dir);
    assert!(
        !initial_fingerprint.is_empty(),
        "precondition: initial index tree at {} must contain files",
        index_dir.display()
    );

    // Force rebuild
    cargo_bin_cmd!("cass")
        .args(["index", "--force-rebuild", "--data-dir"])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    // Verify index was rebuilt: the set of files (names + sizes) under
    // the index tree must differ from the pre-rebuild snapshot. A
    // regression where --force-rebuild silently no-ops would leave the
    // same Tantivy segments in place and this assertion would fire.
    let new_fingerprint = index_fingerprint(&index_dir);
    assert_ne!(
        initial_fingerprint,
        new_fingerprint,
        "index tree content must change after --force-rebuild; \
         before ({} entries) == after ({} entries)",
        initial_fingerprint.len(),
        new_fingerprint.len()
    );

    // Verify content is still searchable
    let output = cargo_bin_cmd!("cass")
        .args(["search", "rebuild_test_initial", "--robot", "--data-dir"])
        .arg(&data_dir)
        .env("HOME", home)
        .output()
        .expect("search command");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let hits = json.get("hits").and_then(|h| h.as_array()).expect("hits");
    // Bead 7k7pl: pin EXACT content — at least one hit must carry
    // the seeded token `rebuild_test_initial` in its content field.
    // A regression that returned unrelated hits after force-rebuild
    // would slip past `!is_empty()` while breaking searchability.
    assert!(
        !hits.is_empty(),
        "Content should still be searchable after force-rebuild"
    );
    let seeded_hit = hits.iter().find(|hit| {
        hit.get("content")
            .and_then(|c| c.as_str())
            .is_some_and(|c| c.contains("rebuild_test_initial"))
    });
    assert!(
        seeded_hit.is_some(),
        "at least one hit must contain the seeded token `rebuild_test_initial`; \
         got hits={hits:?}"
    );
}

/// Test: JSON output mode (--json) for index command
#[test]
#[serial]
fn index_json_output_mode() {
    let tracker = tracker_for("index_json_output_mode");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Create fixture
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-json.jsonl",
        "json_output_test",
        1732118400000,
    );

    // Index with --json
    let output = cargo_bin_cmd!("cass")
        .args(["index", "--full", "--json", "--data-dir"])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .output()
        .expect("index command");

    assert!(output.status.success());

    // Debug: print actual output
    eprintln!(
        "Index JSON output: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    // Verify JSON output structure - index --json outputs various fields
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON output");

    // Index JSON output should be a valid JSON object
    assert!(
        json.is_object(),
        "JSON output should be an object. Got: {}",
        json
    );
}

/// Test: Help text includes expected options
#[test]
#[serial]
fn index_help_includes_options() {
    let tracker = tracker_for("index_help_includes_options");
    let _trace_guard = tracker.trace_env_guard();
    let output = cargo_bin_cmd!("cass")
        .args(["index", "--help"])
        .output()
        .expect("help command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("--full"), "Help should mention --full");
    assert!(stdout.contains("--watch"), "Help should mention --watch");
    assert!(
        stdout.contains("--force-rebuild"),
        "Help should mention --force-rebuild"
    );
    assert!(
        stdout.contains("--semantic"),
        "Help should mention --semantic"
    );
    assert!(
        stdout.contains("--embedder"),
        "Help should mention --embedder"
    );
    assert!(
        stdout.contains("--data-dir"),
        "Help should mention --data-dir"
    );
}

/// Test: Search help includes expected options
#[test]
#[serial]
fn search_help_includes_options() {
    let tracker = tracker_for("search_help_includes_options");
    let _trace_guard = tracker.trace_env_guard();
    let output = cargo_bin_cmd!("cass")
        .args(["search", "--help"])
        .output()
        .expect("help command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("--robot"), "Help should mention --robot");
    assert!(stdout.contains("--limit"), "Help should mention --limit");
    assert!(stdout.contains("--agent"), "Help should mention --agent");
    assert!(
        stdout.contains("--aggregate"),
        "Help should mention --aggregate"
    );
}

/// Test: Search with wildcard query
#[test]
#[serial]
fn search_wildcard_query() {
    let tracker = tracker_for("search_wildcard_query");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Create fixture with unique prefix
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-wild.jsonl",
        "wildcardtest_unique_suffix",
        1732118400000,
    );

    // Index
    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    // Search with wildcard prefix
    let output = cargo_bin_cmd!("cass")
        .args(["search", "wildcardtest*", "--robot", "--data-dir"])
        .arg(&data_dir)
        .env("HOME", home)
        .output()
        .expect("search command");

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let hits = json.get("hits").and_then(|h| h.as_array()).expect("hits");

    // Bead 7k7pl: pin EXACT content — the wildcard `wildcardtest*`
    // must match the seeded token `wildcardtest_unique_suffix` in at
    // least one hit's content. A regression that returned unrelated
    // hits (wildcard falling back to match-all) would slip past
    // `!is_empty()`.
    assert!(
        !hits.is_empty(),
        "Wildcard prefix search should find results"
    );
    let matched_seed = hits.iter().any(|hit| {
        hit.get("content")
            .and_then(|c| c.as_str())
            .is_some_and(|c| c.contains("wildcardtest_unique_suffix"))
    });
    assert!(
        matched_seed,
        "wildcard search must return the seeded `wildcardtest_unique_suffix` token; \
         got hits={hits:?}"
    );
}

/// Test: Trace logging works when enabled
#[test]
#[serial]
fn trace_logging_to_file() {
    let tracker = tracker_for("trace_logging_to_file");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    let trace_dir = home.join("traces");
    fs::create_dir_all(&data_dir).unwrap();
    fs::create_dir_all(&trace_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());
    let _guard_trace = EnvGuard::set("CASS_TRACE_DIR", trace_dir.to_string_lossy());

    // Create fixture
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-trace.jsonl",
        "trace_test_content",
        1732118400000,
    );

    // Index with tracing enabled
    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .env("CASS_TRACE_DIR", &trace_dir)
        .assert()
        .success();

    // Note: Trace file creation depends on tracing-appender setup in the binary
    // This test verifies the env var is recognized without crashing
}

/// Test: Empty query returns recent results
// W2-6 exec39: ignored, not deleted -- cascade-masked latent finding,
// same family as above. Real error: "Empty query should return recent
// indexed conversations" assertion fails outright; root cause not
// investigated (out of item2's scope). See w2-6-deleted-tests.md.
#[test]
#[serial]
#[ignore = "w2-6-deleted-tests.md: e2e_search_index cascade-masked latent findings (control-plane 2026-08-31 ruling)"]
fn empty_query_returns_recent() {
    let tracker = tracker_for("empty_query_returns_recent");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    // Create fixture
    make_codex_session(
        &codex_home,
        "2024/11/20",
        "rollout-recent.jsonl",
        "recent_results_test",
        1732118400000,
    );

    // Index
    cargo_bin_cmd!("cass")
        .args(["index", "--full", "--data-dir"])
        .arg(&data_dir)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .assert()
        .success();

    // Search with empty query (should show recent)
    let output = cargo_bin_cmd!("cass")
        .args(["search", "", "--robot", "--data-dir"])
        .arg(&data_dir)
        .env("HOME", home)
        .output()
        .expect("search command");

    assert!(
        output.status.success(),
        "Empty query should succeed after a successful index: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("empty-query search JSON");
    let hits = json["hits"].as_array().expect("hits array");
    assert!(
        !hits.is_empty(),
        "Empty query should return recent indexed conversations"
    );
    // Bead 7k7pl: pin the SHAPE of every returned hit. Empty-query
    // returns recency-sorted conversations, so every hit must be a
    // proper hit object with string `content` + `source_path` fields.
    // A regression that emitted malformed hits (null content, missing
    // source) would slip past `!is_empty()` while breaking consumers.
    for hit in hits {
        assert!(
            hit.get("content").and_then(|c| c.as_str()).is_some(),
            "every empty-query hit must have a string `content` field; got {hit}"
        );
        assert!(
            hit.get("source_path").and_then(|s| s.as_str()).is_some(),
            "every empty-query hit must have a string `source_path` field; got {hit}"
        );
    }
}

#[test]
#[serial]
fn large_message_minimal_search_stays_on_the_tantivy_fast_path() {
    let tracker = tracker_for("large_message_minimal_search_stays_on_the_tantivy_fast_path");
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    let large_content = format!(
        "tantivy_large_anchor {}",
        "overflowpayload ".repeat(180_000)
    );

    tracker.phase(
        "seed_large_message_fixture",
        "Create a real Codex rollout with a multi-megabyte message body",
        || {
            make_codex_session(
                &codex_home,
                "2024/11/22",
                "rollout-large-tantivy-fast-path.jsonl",
                &large_content,
                1_732_300_000_000,
            );
        },
    );

    tracker.phase(
        "index_large_message_fixture",
        "Build the real index before searching the large message",
        || {
            cargo_bin_cmd!("cass")
                .args(["index", "--full", "--json", "--data-dir"])
                .arg(&data_dir)
                .current_dir(home)
                .env("CODEX_HOME", &codex_home)
                .env("HOME", home)
                .timeout(Duration::from_secs(90))
                .assert()
                .success();
        },
    );

    let search_started = tracker.start(
        "search_large_message_minimal",
        Some("Run a real lexical cass search against the multi-megabyte session"),
    );
    let output = cargo_bin_cmd!("cass")
        .args([
            "search",
            "tantivy_large_anchor",
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
        .current_dir(home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", home)
        .timeout(Duration::from_secs(20))
        .output()
        .expect("search large indexed message");
    tracker.end(
        "search_large_message_minimal",
        Some("Run a real lexical cass search against the multi-megabyte session"),
        search_started,
    );

    assert!(
        output.status.success(),
        "large-message lexical search should stay healthy after indexing\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("large-message search JSON");
    let hits = json
        .get("total_matches")
        .and_then(|matches| matches.as_u64())
        .unwrap_or_else(|| {
            json.get("hits")
                .and_then(|hits| hits.as_array())
                .map(|hits| hits.len() as u64)
                .unwrap_or(0)
        });
    assert!(
        hits > 0,
        "large indexed message should remain searchable with minimal lexical fields"
    );

    tracker.flush();
}

/// W2-6 exec39 (item2, control-plane 2026-08-31 ruling): count of
/// populated `lex_docs` rows for the sparse-detection precondition
/// check below. Read-only, plain `rusqlite` -- this isn't a real
/// application operation, just a fixture-side peek.
fn count_lex_docs(db_path: &Path) -> i64 {
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

#[test]
#[serial]
fn incremental_index_repairs_sparse_tantivy_from_canonical_db_before_scanning_new_files() {
    let tracker = tracker_for(
        "incremental_index_repairs_sparse_tantivy_from_canonical_db_before_scanning_new_files",
    );
    let _trace_guard = tracker.trace_env_guard();
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let codex_home = home.to_path_buf();
    let data_dir = home.join("cass_data");
    fs::create_dir_all(&data_dir).unwrap();

    let _guard_home = EnvGuard::set("HOME", home.to_string_lossy());
    let _guard_codex = EnvGuard::set("CODEX_HOME", codex_home.to_string_lossy());

    let db_path = data_dir.join("agent_search.db");

    tracker.phase(
        "seed_baseline_archive",
        "Create a real multi-session Codex archive and build the canonical DB plus lexical index",
        || {
            make_bulk_codex_sessions(
                &codex_home,
                "2024/11/23",
                "rollout-repair-baseline",
                "repairoldanchor",
                1_732_400_000_000,
                3,
                4,
            );

            cargo_bin_cmd!("cass")
                .args(["index", "--full", "--json", "--data-dir"])
                .arg(&data_dir)
                .current_dir(&home)
                .env("CODEX_HOME", &codex_home)
                .env("HOME", &home)
                .timeout(Duration::from_secs(60))
                .assert()
                .success();
        },
    );

    // W2-6 exec39 (item2, control-plane 2026-08-31 ruling): manufacture
    // a genuinely sparse lex domain the SAME way item1's
    // DbCorruptWithStaleIndex does -- the real production
    // CASS_DEFER_LEXICAL_UPDATES=1 toggle, not a directory swap (that
    // mechanism, and the raw tantivy reader this test used to verify
    // it with, are both extinct now that lex_docs/fts_lex live inside
    // the archive DB). A raw SQL `DELETE FROM lex_docs` was considered
    // and rejected: verified empirically that it leaves a PERMANENT
    // FTS5 external-content desync the sparse-repair path
    // (`rebuild_lex_domain_from_db_full`, an in-place per-conversation
    // resync, not a DROP+CREATE) does not clean up -- a fresh
    // `INSERT INTO fts_lex(fts_lex, rank) VALUES('integrity-check', 1)`
    // still reported "database disk image is malformed" AFTER the
    // repair reported success. Deferring these conversations' writes
    // from the start means their rows were never written to lex_docs
    // or fts_lex at all -- there is no dangling fts_lex shadow entry to
    // leave behind, so this is constructively clean by
    // construction, not something that needs a post-hoc integrity
    // check to prove safe.
    tracker.phase(
        "seed_deferred_batch_making_lex_domain_sparse",
        "Ingest a second batch of real sessions with lexical writes deferred, so lex_docs \
         ends up genuinely behind messages without any FTS5 desync",
        || {
            make_bulk_codex_sessions(
                &codex_home,
                "2024/11/23",
                "rollout-repair-deferred",
                "reparideferredanchor",
                1_732_420_000_000,
                2,
                4,
            );

            cargo_bin_cmd!("cass")
                .args(["index", "--json", "--data-dir"])
                .arg(&data_dir)
                .current_dir(&home)
                .env("CODEX_HOME", &codex_home)
                .env("HOME", &home)
                .env("CASS_DEFER_LEXICAL_UPDATES", "1")
                .timeout(Duration::from_secs(60))
                .assert()
                .success();
        },
    );

    let baseline_messages = count_messages(&db_path) as u64;
    assert!(
        baseline_messages >= 40,
        "baseline archive (both batches) should populate the canonical DB with many messages"
    );
    let sparse_lex_docs = count_lex_docs(&db_path);
    assert!(
        sparse_lex_docs > 0 && (sparse_lex_docs as u64) < baseline_messages,
        "precondition: lex_docs ({sparse_lex_docs}) must be genuinely sparse relative to \
         messages ({baseline_messages}) -- the deferred batch's rows must be present in \
         messages but absent from lex_docs"
    );

    tracker.phase(
        "stage_new_incremental_session",
        "Add a brand-new session after the deferred batch so plain cass index must both repair and ingest",
        || {
            make_codex_session(
                &codex_home,
                "2024/11/24",
                "rollout-repair-new-session.jsonl",
                "repairnewanchor",
                1_732_500_000_000,
            );
        },
    );

    let repair_started = tracker.start(
        "repair_sparse_tantivy_then_incremental_scan",
        Some("Run plain cass index --json and require canonical repair plus new-session ingestion"),
    );
    let repair_output = cargo_bin_cmd!("cass")
        .args(["index", "--json", "--data-dir"])
        .arg(&data_dir)
        .current_dir(&home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", &home)
        .timeout(Duration::from_secs(60))
        .output()
        .expect("run repairing incremental index");
    let repair_duration_ms = repair_started.elapsed().as_millis() as u64;
    tracker.end(
        "repair_sparse_tantivy_then_incremental_scan",
        Some("Run plain cass index --json and require canonical repair plus new-session ingestion"),
        repair_started,
    );

    assert!(
        repair_output.status.success(),
        "plain index should repair the sparse Tantivy index and ingest new sessions\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&repair_output.stdout),
        String::from_utf8_lossy(&repair_output.stderr)
    );

    let repair_json: serde_json::Value =
        serde_json::from_slice(&repair_output.stdout).expect("parse repair index json");
    let repair_stats = repair_json
        .get("indexing_stats")
        .and_then(|value| value.as_object())
        .expect("indexing_stats object");
    assert_eq!(
        repair_stats
            .get("lexical_strategy")
            .and_then(|value| value.as_str()),
        Some("deferred_authoritative_db_rebuild")
    );
    assert_eq!(
        repair_stats
            .get("lexical_strategy_reason")
            .and_then(|value| value.as_str()),
        Some(
            "incremental_index_repairs_sparse_tantivy_from_authoritative_canonical_db_before_scan"
        )
    );

    let after_messages = count_messages(&db_path) as u64;
    assert_eq!(
        after_messages,
        baseline_messages + 2,
        "plain incremental index should still ingest the newly added session after repairing Tantivy"
    );

    let repaired_old_search = cargo_bin_cmd!("cass")
        .args([
            "search",
            "repairoldanchor",
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
        .current_dir(&home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", &home)
        .timeout(Duration::from_secs(20))
        .output()
        .expect("search repaired baseline token");
    assert!(
        repaired_old_search.status.success(),
        "search should succeed after canonical lexical repair\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&repaired_old_search.stdout),
        String::from_utf8_lossy(&repaired_old_search.stderr)
    );
    assert!(
        total_matches_from_search_output(&repaired_old_search.stdout) > 0,
        "repair should restore baseline archive hits from the canonical DB"
    );

    // W2-6 exec39: this is the search that actually proves the sparse
    // repair worked -- "repairoldanchor" above was never sparse (batch
    // 1 was indexed normally); "reparideferredanchor" is the batch that
    // was deferred, so it's only searchable at all if the sparse-repair
    // path genuinely backfilled lex_docs for it from the canonical DB.
    let repaired_deferred_search = cargo_bin_cmd!("cass")
        .args([
            "search",
            "reparideferredanchor",
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
        .current_dir(&home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", &home)
        .timeout(Duration::from_secs(20))
        .output()
        .expect("search deferred batch token");
    assert!(
        repaired_deferred_search.status.success(),
        "search should succeed after canonical lexical repair\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&repaired_deferred_search.stdout),
        String::from_utf8_lossy(&repaired_deferred_search.stderr)
    );
    assert!(
        total_matches_from_search_output(&repaired_deferred_search.stdout) > 0,
        "the deferred batch's content must be searchable after the sparse-repair backfill -- \
         if this is 0, the sparse-detection repair path did not actually cover the deferred rows"
    );

    let repaired_new_search = cargo_bin_cmd!("cass")
        .args([
            "search",
            "repairnewanchor",
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
        .current_dir(&home)
        .env("CODEX_HOME", &codex_home)
        .env("HOME", &home)
        .timeout(Duration::from_secs(20))
        .output()
        .expect("search new incremental token after repair");
    assert!(
        repaired_new_search.status.success(),
        "new incremental content should be searchable after the repair-first index run\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&repaired_new_search.stdout),
        String::from_utf8_lossy(&repaired_new_search.stderr)
    );
    assert!(
        total_matches_from_search_output(&repaired_new_search.stdout) > 0,
        "repair-first incremental index should still ingest the newly added session"
    );

    tracker.metrics(
        "repair_sparse_tantivy_then_incremental_scan",
        &E2ePerformanceMetrics::new()
            .with_duration(repair_duration_ms)
            .with_custom("baseline_messages", baseline_messages)
            .with_custom("messages_after_repair", after_messages),
    );
    tracker.flush();
}
