//! PR6 T2c (任务书 #113) mutual-exclusion judgment (R1-B1/R9): `mirror prune
//! --apply` and any writer racing to claim the same `index-run.lock` must
//! never interleave. Two shapes, per the task book: ① a real `cass`
//! subprocess against a lock already held by this process; ② an in-process
//! `raw_mirror::prune` call with a fault hook simulating a concurrent
//! writer attempting the same lock mid-prune.
//!
//! T2b (任务书 #114) owns the rest of this file's namesake test suite
//! (prepare-path CLI-level judgment); this round only adds the fingerprint
//! persistence and prune-mutex judgments item 6/8 of the mission call for.

use std::fs::OpenOptions;

use fs2::FileExt;

/// `raw_mirror::set_prune_fault_hook` is a single process-global slot.
/// `cargo test` runs every `#[test]` function in this binary on its own
/// thread by default, so the two hook-based tests below (positive +
/// mutation) must be serialized against each other or one can silently
/// clobber/observe the other's hook mid-flight -- a real, previously-hit
/// flake, not a hypothetical one.
static HOOK_TEST_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass").ok().unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

fn cass_cmd(data_dir: &std::path::Path, home: &std::path::Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(cass_bin());
    cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
    cmd.env("HOME", home);
    cmd.env("XDG_DATA_HOME", home.join(".local/share"));
    cmd.env("XDG_CONFIG_HOME", home.join(".config"));
    cmd.env("CASS_DATA_DIR", data_dir);
    cmd.env("NO_COLOR", "1");
    cmd
}

/// Mutex judgment ① (subprocess): another process (this test) holds
/// `index-run.lock`; `cass mirror prune --apply` refuses with exit 2,
/// `lock-busy`, and deletes nothing.
#[test]
fn mirror_prune_apply_subprocess_refuses_while_lock_held_by_another_process() {
    let temp = tempfile::TempDir::new().expect("tempdir");
    let data_dir = temp.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");

    // Simulate an in-flight `cass index` run: acquire the same lock file
    // `acquire_index_run_lock` would (R12: keyed by normalized data_dir).
    let lock_path = data_dir.join("index-run.lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("open lock file");
    lock_file.lock_exclusive().expect("acquire index-run.lock");

    let output = cass_cmd(&data_dir, temp.path())
        .args(["mirror", "prune", "--older-than", "0s", "--apply", "--safety-hold-down", "0s"])
        .output()
        .expect("spawn cass mirror prune subprocess");

    FileExt::unlock(&lock_file).ok();
    drop(lock_file);

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 (lock-busy); got {:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("index run is active"), "stderr should name the lock conflict: {stderr}");
    assert!(
        !data_dir.join("raw-mirror").exists(),
        "an empty mirror should stay untouched (subprocess must have refused before doing any work)"
    );
}

/// Mutex judgment ② (in-process, positive half): `raw_mirror::prune` is
/// called while this test already holds `index-run.lock` (matching what
/// `run_mirror_prune`, lib.rs, does for real before calling `prune`).
/// Mid-prune (fault hook, after the R9 protection check, before deletion),
/// a simulated concurrent writer tries to claim the SAME lock file and must
/// see it busy; once prune returns and this test releases the lock, that
/// same "writer" attempt now succeeds -- proving the lock genuinely
/// serializes the two, not just "happens to look fine" in this run.
#[test]
fn prune_holds_lock_across_hook_window_blocking_a_concurrent_writer() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let _serialize = HOOK_TEST_SERIALIZE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::TempDir::new().expect("tempdir");
    let data_dir = temp.path().join("cass-data");

    let source_path = temp.path().join("expired.jsonl");
    std::fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"about to be pruned\"}\n").expect("write source");
    let captured = coding_agent_search::raw_mirror::capture_source_file(coding_agent_search::raw_mirror::RawMirrorCaptureInput {
        data_dir: &data_dir,
        provider: "codex",
        source_id: "local",
        origin_kind: "local",
        origin_host: None,
        source_path: &source_path,
        db_links: &[],
    })
    .expect("capture source");
    let root = data_dir.join("raw-mirror").join("v1");
    let blob_path = root.join(&captured.blob_relative_path);
    assert!(blob_path.exists(), "blob B must exist before pruning");

    // Simulate `run_mirror_prune` (lib.rs) having already acquired
    // `index-run.lock` before calling `raw_mirror::prune`.
    let lock_path = data_dir.join("index-run.lock");
    let outer_lock = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&lock_path).expect("open lock file");
    outer_lock.lock_exclusive().expect("acquire outer index-run.lock");

    let writer_saw_busy = Arc::new(AtomicBool::new(false));
    let writer_saw_busy_in_hook = Arc::clone(&writer_saw_busy);
    let lock_path_in_hook = lock_path.clone();
    coding_agent_search::raw_mirror::set_prune_fault_hook(Some(Box::new(move || {
        // The "writer" attempt: a fresh handle to the SAME lock file, from
        // the same process -- `flock` semantics are per-open-file-
        // description, so this genuinely contends with `outer_lock` above.
        let writer_attempt = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&lock_path_in_hook).expect("open lock file from writer");
        let busy = writer_attempt.try_lock_exclusive().is_err();
        writer_saw_busy_in_hook.store(busy, Ordering::SeqCst);
    })));

    let report = coding_agent_search::raw_mirror::prune(
        &data_dir,
        coding_agent_search::raw_mirror::RawMirrorPruneOptions {
            referenced_blobs: std::collections::HashSet::new(),
            older_than_ms: Some(0),
            max_size_bytes: None,
            keep_tags: Vec::new(),
            safety_hold_down_ms: 0,
            apply: true,
        },
    )
    .expect("prune must succeed");

    coding_agent_search::raw_mirror::set_prune_fault_hook(None);
    FileExt::unlock(&outer_lock).ok();
    drop(outer_lock);

    assert!(writer_saw_busy.load(Ordering::SeqCst), "a concurrent writer attempting the lock mid-prune must see it busy");
    assert_eq!(report.applied_blob_count, 1, "the unreferenced expired blob (B) must have been deleted");
    assert!(!blob_path.exists(), "B must be gone after prune");

    // Retry after prune (and this test's own outer lock) have released:
    // a legitimate next writer can now proceed -- it would reference a
    // NEW blob, never B (B no longer exists to reference).
    let retry = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&lock_path).expect("open lock file for retry");
    assert!(retry.try_lock_exclusive().is_ok(), "the lock must be free again once prune and the outer holder have both released it");
    FileExt::unlock(&retry).ok();
}

/// Mutex judgment ② (mutation half): the SAME fixture and hook, but this
/// time the test does NOT hold `index-run.lock` while `prune` runs --
/// simulating the bug R1-B1 exists to prevent (a caller invoking
/// `raw_mirror::prune(..., apply: true)` directly, bypassing
/// `run_mirror_prune`'s lock acquisition). The "concurrent writer" in the
/// hook now finds the lock free and would race straight past a delete that
/// is happening in the very same window -- proving the outer lock in the
/// positive test above is what actually closes this window, not something
/// incidental to `prune`'s own internals.
#[test]
fn prune_without_an_outer_lock_leaves_the_window_open_for_a_racing_writer() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let _serialize = HOOK_TEST_SERIALIZE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::TempDir::new().expect("tempdir");
    let data_dir = temp.path().join("cass-data");

    let source_path = temp.path().join("expired.jsonl");
    std::fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"about to be pruned\"}\n").expect("write source");
    coding_agent_search::raw_mirror::capture_source_file(coding_agent_search::raw_mirror::RawMirrorCaptureInput {
        data_dir: &data_dir,
        provider: "codex",
        source_id: "local",
        origin_kind: "local",
        origin_host: None,
        source_path: &source_path,
        db_links: &[],
    })
    .expect("capture source");

    let lock_path = data_dir.join("index-run.lock");
    // MUTATION: no outer lock acquisition here (unlike the positive test).
    let writer_raced_through = Arc::new(AtomicBool::new(false));
    let writer_raced_through_in_hook = Arc::clone(&writer_raced_through);
    let lock_path_in_hook = lock_path.clone();
    coding_agent_search::raw_mirror::set_prune_fault_hook(Some(Box::new(move || {
        let writer_attempt = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&lock_path_in_hook).expect("open lock file from writer");
        let acquired = writer_attempt.try_lock_exclusive().is_ok();
        writer_raced_through_in_hook.store(acquired, Ordering::SeqCst);
        FileExt::unlock(&writer_attempt).ok();
    })));

    coding_agent_search::raw_mirror::prune(
        &data_dir,
        coding_agent_search::raw_mirror::RawMirrorPruneOptions {
            referenced_blobs: std::collections::HashSet::new(),
            older_than_ms: Some(0),
            max_size_bytes: None,
            keep_tags: Vec::new(),
            safety_hold_down_ms: 0,
            apply: true,
        },
    )
    .expect("prune must succeed");
    coding_agent_search::raw_mirror::set_prune_fault_hook(None);

    assert!(
        writer_raced_through.load(Ordering::SeqCst),
        "MUTATION: without the outer lock, a concurrent writer's lock attempt wrongly succeeds mid-prune"
    );
}

// =============================================================================
// T2b.2 (任务书 #115) A.4: transport-chain equivalence across the four
// ingestion entry points (streaming default / batch / force-rebuild /
// watch-once). The same `claude_code` session file is scanned by each into
// its own fresh `--data-dir`; if `PreparedConversation.excluded` markers
// really do survive every one of `IndexMessage::Batch` /
// `PendingBatchScan.convs` / `prepared_convs` (watch) /
// `persist_conversations_batched_*` to `map_to_internal_with_redactor`, the
// four resulting databases must agree, message-for-message, on which rows
// got excluded and what they hashed to.
//
// Disclosure: the mission text says "claude_code JSONL 含三锚点各一" but
// anchor 3 (`codex_host_shell`) is structurally codex-only (spec §2.1: the
// judgment looks at a codex session's `idx=0` message) -- there is no
// claude_code shape that can trigger it. This fixture carries the two
// anchors that DO apply to claude_code (R11: `cass_recall` via the
// `mcp__cass-mcp__*` full-name alias, `context_file_read` via `Read`) plus
// two non-excluded control messages, and the codex-specific anchor 3 case
// is covered separately in the CLI-level judgments added later in this
// file (B.10's codex fixture).
// =============================================================================

/// Writes a `claude_code` session JSONL with: a plain user question, an
/// assistant turn mixing prose + the `cass-mcp` recall tool_use on one
/// JSONL line whose `tool_result` is anchor-1 excluded, an assistant turn
/// mixing prose + a memory-file `Read` tool_use on one line whose
/// `tool_result` is anchor-2 excluded, and a closing assistant summary.
/// Returns the file path.
///
/// This is the realistic wire shape (a mixed `[text, tool_use]` content
/// array on one line) `events_from_blob`'s claude_code rule now handles
/// (T2b.2, 任务书 #115, control-plane fix 2026-09-07): earlier in this same
/// mission round it did not -- the fix and its own unit-level alignment
/// tests against the real connector live in `exclusion.rs`
/// (`events_from_blob_claude_code_thinking_text_tool_use_one_line_matches_real_reparse_positive`
/// et al.); this CLI-level test exercising the same shape end to end is
/// what proves the fix actually closes the loop for real ingestion, not
/// just for `events_from_blob` in isolation.
fn write_two_anchor_claude_session(home: &std::path::Path) -> std::path::PathBuf {
    let project_dir = home.join(".claude/projects/w6-transport-equiv");
    std::fs::create_dir_all(&project_dir).expect("mkdir claude project dir");
    let file = project_dir.join("session.jsonl");

    let recall_response = serde_json::json!({
        "query": "prior decision about worktrees",
        "limit": 5, "offset": 0, "count": 1, "total_matches": 1,
        "hits": [{
            "agent": "claude_code", "content": "we decided to use per-feature worktrees",
            "created_at": 1700000000000i64, "line_number": 7, "match_type": "exact",
            "origin_kind": "local", "score": 0.91, "snippet": "per-feature worktrees",
            "source_id": 42, "source_path": "/logs/prior-session.jsonl",
            "title": "worktree decision", "workspace": "/ws/demo"
        }],
        "cursor": null, "hits_clamped": false, "max_tokens": 8000, "request_id": "req-w6-1"
    })
    .to_string();
    let memory_file_echo = "# USER.md\n\n- test-only synthetic memory line for T2b.2 A.4 fixture\n";

    let events: Vec<serde_json::Value> = vec![
        serde_json::json!({
            "type": "user", "timestamp": "2026-09-07T10:00:00.000Z", "uuid": "w6-evt-000",
            "message": {"role": "user", "content": "search my past sessions, then check my memory notes"}
        }),
        serde_json::json!({
            "type": "assistant", "timestamp": "2026-09-07T10:00:04.000Z", "uuid": "w6-evt-001a",
            "message": {"role": "assistant", "content": [
                {"type": "text", "text": "Let me search prior sessions."},
                {"type": "tool_use", "id": "toolu_w6_recall_001", "name": "mcp__cass-mcp__cass_search", "input": {"query": "prior decision about worktrees"}}
            ]}
        }),
        serde_json::json!({
            "type": "user", "timestamp": "2026-09-07T10:00:06.000Z", "uuid": "w6-evt-002",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_w6_recall_001", "content": recall_response}
            ]}
        }),
        serde_json::json!({
            "type": "assistant", "timestamp": "2026-09-07T10:00:10.000Z", "uuid": "w6-evt-003",
            "message": {"role": "assistant", "content": [
                {"type": "text", "text": "Now let me check your memory file."},
                {"type": "tool_use", "id": "toolu_w6_read_001", "name": "Read", "input": {"file_path": home.join("cc-workspace/USER.md").display().to_string()}}
            ]}
        }),
        serde_json::json!({
            "type": "user", "timestamp": "2026-09-07T10:00:11.000Z", "uuid": "w6-evt-004",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_w6_read_001", "content": memory_file_echo}
            ]}
        }),
        serde_json::json!({
            "type": "assistant", "timestamp": "2026-09-07T10:00:15.000Z", "uuid": "w6-evt-005",
            "message": {"role": "assistant", "content": "Found the prior worktree decision and confirmed your memory file preferences."}
        }),
    ];
    let body = events.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n") + "\n";
    std::fs::write(&file, body).expect("write claude_code session fixture");
    file
}

/// `(external_id, source_path, idx, excluded_is_some, excluded_sha256)` rows
/// from `messages` joined to `conversations`, ordered for stable comparison.
#[derive(Debug, PartialEq, Eq, Clone)]
struct ExclusionRow {
    external_id: Option<String>,
    source_path: String,
    idx: i64,
    excluded_is_some: bool,
    excluded_sha256: Option<String>,
}

fn read_exclusion_rows(db_path: &std::path::Path) -> Vec<ExclusionRow> {
    let conn = rusqlite::Connection::open(db_path).expect("open candidate db");
    let mut stmt = conn
        .prepare(
            "SELECT c.external_id, c.source_path, m.idx, \
                    (m.excluded IS NOT NULL), json_extract(m.excluded, '$.sha256') \
             FROM messages m JOIN conversations c ON c.id = m.conversation_id \
             ORDER BY c.external_id, c.source_path, m.idx",
        )
        .expect("prepare exclusion-rows query");
    let rows = stmt
        .query_map([], |row| {
            Ok(ExclusionRow {
                external_id: row.get(0)?,
                source_path: row.get(1)?,
                idx: row.get(2)?,
                excluded_is_some: row.get(3)?,
                excluded_sha256: row.get(4)?,
            })
        })
        .expect("query exclusion rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect exclusion rows");
    rows
}

/// A.4: the same fixture ingested via streaming (default), batch
/// (`CASS_STREAMING_INDEX=0`), `--force-rebuild`, and `--watch-once` must
/// produce identical `(stable key, idx, excluded?, excluded.sha256)` sets,
/// and that set must be non-empty (the two anchors must actually have
/// fired in all four).
#[test]
fn transport_chain_equivalence_across_ingestion_modes() {
    let home_tmp = tempfile::TempDir::new().expect("home tempdir");
    let home = home_tmp.path();
    let session_path = write_two_anchor_claude_session(home);

    let data_root = tempfile::TempDir::new().expect("data-dir root tempdir");

    let streaming_default_dir = data_root.path().join("streaming-default");
    let batch_dir = data_root.path().join("batch-mode");
    let force_rebuild_dir = data_root.path().join("force-rebuild");
    let watch_once_dir = data_root.path().join("watch-once");

    let run = |data_dir: &std::path::Path, extra_env: Option<(&str, &str)>, extra_args: &[&str]| {
        std::fs::create_dir_all(data_dir).expect("mkdir data_dir");
        let mut cmd = cass_cmd(data_dir, home);
        cmd.args(["index"]).args(extra_args).args(["--json"]);
        if let Some((k, v)) = extra_env {
            cmd.env(k, v);
        }
        let output = cmd.output().expect("spawn cass index");
        assert!(
            output.status.success(),
            "cass index (args={extra_args:?}, env={extra_env:?}) must succeed; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        data_dir.join("agent_search.db")
    };

    let streaming_default_db = run(&streaming_default_dir, None, &["--full"]);
    let batch_db = run(&batch_dir, Some(("CASS_STREAMING_INDEX", "0")), &["--full"]);
    let force_rebuild_db = run(&force_rebuild_dir, None, &["--force-rebuild"]);
    let watch_once_db = run(
        &watch_once_dir,
        None,
        &["--watch-once", session_path.to_str().expect("utf8 session path")],
    );

    let streaming_default_rows = read_exclusion_rows(&streaming_default_db);
    let batch_rows = read_exclusion_rows(&batch_db);
    let force_rebuild_rows = read_exclusion_rows(&force_rebuild_db);
    let watch_once_rows = read_exclusion_rows(&watch_once_db);

    let excluded_count = streaming_default_rows.iter().filter(|r| r.excluded_is_some).count();
    assert!(
        excluded_count >= 2,
        "fixture must trigger both anchors (recall + context-file-read); got {excluded_count} excluded rows in {streaming_default_rows:?}"
    );
    for row in streaming_default_rows.iter().filter(|r| r.excluded_is_some) {
        assert!(
            row.excluded_sha256.as_deref().is_some_and(|s| !s.is_empty()),
            "excluded row must carry a non-empty excluded.sha256: {row:?}"
        );
    }

    assert_eq!(
        streaming_default_rows, batch_rows,
        "streaming (default) and batch (CASS_STREAMING_INDEX=0) must produce identical exclusion rows"
    );
    assert_eq!(
        streaming_default_rows, force_rebuild_rows,
        "streaming (default) and --force-rebuild must produce identical exclusion rows"
    );
    assert_eq!(
        streaming_default_rows, watch_once_rows,
        "streaming (default) and --watch-once must produce identical exclusion rows"
    );
}

// =============================================================================
// T2b.3 (B段, 任务书 #116) B.10 CLI 级判例: codex host-shell 正例（含合成秘密）+
// 捕获失败三例 + 追加判例 + status 判例。
//
// The fault-hook cases (`PrepareStage::BeforeCapture` / `BeforeDurableSync`)
// must run in-process, not as a `cass` subprocess: `set_prepare_fault_hook`
// is a single process-global slot (same reasoning as `HOOK_TEST_SERIALIZE`
// above for the prune hook), so a spawned subprocess would never see a hook
// this test process installs. `run_index` is the exact library entry point
// the CLI itself calls (`src/lib.rs`'s index-command handler spawns it in a
// thread with an `IndexOptions` built from the same flags), so calling it
// directly here with `watch_once_paths` set (bypassing `$HOME`-based
// connector auto-discovery, which would race other tests' env vars in this
// multi-threaded test binary) exercises the real prepare path.
// =============================================================================

/// codex `rollout-*.jsonl` fixture: idx=0 host-shell wrapper (anchor 3,
/// excluded), idx=1 a `cass_search` tool_call (not itself excluded) whose
/// idx=2 `tool_result` embeds a synthetic Anthropic-shaped API key (anchor
/// 1, bare codex name per R11) so the excluded row's `sha256` can be proven
/// to hash the *redacted* text, not the raw secret, idx=3 a real user
/// follow-up (not excluded). Filename must start with `rollout-`
/// (`CodexConnector::is_rollout_file` filters on this even for an explicit
/// single-file `ScanRoot::local` scan, T2b.2 finding); the path must ALSO
/// sit under a `.codex/sessions/` ancestor -- `classify_paths`
/// (`src/indexer/mod.rs`, `classify_paths_hints_codex_connector_for_
/// explicit_codex_paths`) matches an explicit `--watch-once`/in-process
/// path to a connector by that directory shape, not filename alone; a flat
/// tempdir path is silently classified as "no connector" and produces zero
/// rows with no error. Returns the file path and the raw (pre-redaction)
/// `function_call_output` string so callers can independently compute the
/// expected redacted hash.
fn write_codex_host_shell_session(dir: &std::path::Path) -> (std::path::PathBuf, String) {
    let sessions_dir = dir.join(".codex").join("sessions").join("2026").join("09");
    std::fs::create_dir_all(&sessions_dir).expect("mkdir .codex/sessions/2026/09");
    let file = sessions_dir.join("rollout-w6-hostshell.jsonl");
    let host_shell_text = "# AGENTS.md instructions for X\nbe nice\n<environment_context>\n<cwd>/home/u/project</cwd>\n</environment_context>";
    let recall_output = serde_json::json!({
        "query": "prior secret rotation note", "limit": 5, "offset": 0, "count": 1, "total_matches": 1,
        "hits": [{
            "agent": "codex", "content": "rotate the key sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij before Friday",
            "created_at": 1700000000000i64, "line_number": 3, "match_type": "exact",
            "origin_kind": "local", "score": 0.8, "snippet": "rotate the key",
            "source_id": 7, "source_path": "/logs/other-session.jsonl",
            "title": "key rotation", "workspace": "/ws/demo"
        }],
        "cursor": null, "hits_clamped": false, "max_tokens": 8000, "request_id": "req-w6-codex-1"
    })
    .to_string();

    let events: Vec<serde_json::Value> = vec![
        serde_json::json!({"type":"response_item","payload":{"type":"message","id":"msg_0","role":"user","content":[{"type":"input_text","text":host_shell_text}]}}),
        serde_json::json!({"type":"response_item","payload":{"type":"function_call","id":"fc_1","name":"cass_search","arguments":"{\"query\":\"prior secret rotation note\"}","call_id":"call_1"}}),
        serde_json::json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"call_1","output":recall_output}}),
        serde_json::json!({"type":"response_item","payload":{"type":"message","id":"msg_1","role":"user","content":[{"type":"input_text","text":"what did you find?"}]}}),
    ];
    let body = events.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n") + "\n";
    std::fs::write(&file, &body).expect("write codex session fixture");
    (file, recall_output)
}

/// `(idx, role, content, excluded_is_some, reason, sha256, raw_blob,
/// raw_event_key, raw_blocks_json)` rows, ordered by `idx`, from the first
/// (only) conversation in `db_path`.
fn read_message_rows_single_conversation(
    db_path: &std::path::Path,
) -> Vec<(i64, String, String, bool, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)> {
    let conn = rusqlite::Connection::open(db_path).expect("open candidate db");
    let mut stmt = conn
        .prepare(
            "SELECT m.idx, m.role, m.content, (m.excluded IS NOT NULL), \
                    json_extract(m.excluded,'$.reason'), json_extract(m.excluded,'$.sha256'), \
                    json_extract(m.excluded,'$.raw.blob'), json_extract(m.excluded,'$.raw.event_key'), \
                    json_extract(m.excluded,'$.raw.blocks') \
             FROM messages m ORDER BY m.idx",
        )
        .expect("prepare message-rows query");
    stmt.query_map([], |r| {
        Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
            r.get(7)?,
            r.get(8)?,
        ))
    })
    .expect("query message rows")
    .collect::<Result<Vec<_>, _>>()
    .expect("collect message rows")
}

/// Judge case B.10 #1 (codex half): the CLI subprocess ingests the codex
/// host-shell fixture; both anchors fire (idx0 anchor 3, idx2 anchor 1),
/// the tool_call row (idx1) and the trailing user follow-up (idx3) survive
/// byte-for-byte, row count is preserved (4 in, 4 out), and the anchor-1
/// row's `excluded.sha256` is the hash of the *redacted* recall output, not
/// the raw one (proving a real secret got scrubbed, not a no-op pass).
#[test]
fn normal_ingest_codex_host_shell_and_bare_name_recall_positive() {
    use sha2::{Digest, Sha256};

    let home_tmp = tempfile::TempDir::new().expect("home tempdir");
    let home = home_tmp.path();
    let data_dir = home.join("cass-data");
    std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");

    let session_dir = tempfile::TempDir::new().expect("session dir");
    let (session_path, raw_recall_output) = write_codex_host_shell_session(session_dir.path());

    let output = cass_cmd(&data_dir, home)
        .args(["index", "--watch-once", session_path.to_str().expect("utf8 session path"), "--json"])
        .output()
        .expect("spawn cass index --watch-once");
    assert!(
        output.status.success(),
        "codex ingest must succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let rows = read_message_rows_single_conversation(&data_dir.join("agent_search.db"));
    assert_eq!(rows.len(), 4, "row count must equal projected message count; rows={rows:?}");

    // idx0: host-shell wrapper, excluded via anchor 3.
    let (idx0_idx, _role0, content0, excluded0, reason0, sha0, blob0, event_key0, blocks0) = &rows[0];
    assert_eq!(*idx0_idx, 0);
    assert!(*excluded0, "idx0 must be excluded (anchor 3): {:?}", rows[0]);
    assert_eq!(reason0.as_deref(), Some("codex_host_shell"));
    assert_eq!(content0, "", "excluded content must be empty: {:?}", rows[0]);
    assert!(sha0.as_deref().is_some_and(|s| !s.is_empty()), "sha256 must be non-empty: {:?}", rows[0]);
    assert!(blob0.as_deref().is_some_and(|b| !b.is_empty()), "raw.blob must be a non-empty manifest-relative path: {:?}", rows[0]);
    assert!(event_key0.as_deref().is_some_and(|e| !e.is_empty()), "raw.event_key must be non-empty: {:?}", rows[0]);
    assert_ne!(blocks0.as_deref(), Some("[]"), "raw.blocks must be non-empty: {:?}", rows[0]);

    // idx1: the tool_call itself is never the exclusion target.
    let (idx1_idx, _role1, _content1, excluded1, ..) = &rows[1];
    assert_eq!(*idx1_idx, 1);
    assert!(!excluded1, "tool_call row must not itself be excluded: {:?}", rows[1]);

    // idx2: tool_result carrying the synthetic secret, excluded via anchor 1.
    let (idx2_idx, _role2, content2, excluded2, reason2, sha2_hex, ..) = &rows[2];
    assert_eq!(*idx2_idx, 2);
    assert!(*excluded2, "idx2 (tool_result) must be excluded (anchor 1): {:?}", rows[2]);
    assert_eq!(reason2.as_deref(), Some("cass_recall"));
    assert_eq!(content2, "", "excluded content must be empty: {:?}", rows[2]);
    let redacted = coding_agent_search::indexer::redact_secrets::redact_text(&raw_recall_output).into_owned();
    assert_ne!(redacted, raw_recall_output, "fixture sanity: the synthetic secret must actually get redacted, otherwise this assertion is vacuous");
    let expected_sha = format!("{:x}", Sha256::digest(redacted.as_bytes()));
    let raw_sha = format!("{:x}", Sha256::digest(raw_recall_output.as_bytes()));
    assert_eq!(sha2_hex.as_deref(), Some(expected_sha.as_str()), "excluded.sha256 must hash the redacted text");
    assert_ne!(sha2_hex.as_deref(), Some(raw_sha.as_str()), "excluded.sha256 must NOT equal the raw (unredacted) text's hash");

    // idx3: trailing follow-up, untouched byte-for-byte.
    let (idx3_idx, _role3, content3, excluded3, ..) = &rows[3];
    assert_eq!(*idx3_idx, 3);
    assert!(!excluded3, "idx3 must not be excluded: {:?}", rows[3]);
    assert_eq!(content3, "what did you find?", "unexcluded row content must be byte-for-byte unchanged");
}

/// In-process `run_index` call using `watch_once_paths` (bypasses `$HOME`
/// connector auto-discovery -- see the fault-hook cases' module doc above).
fn run_index_in_process(
    data_dir: &std::path::Path,
    watch_once_path: std::path::PathBuf,
) -> anyhow::Result<()> {
    let opts = coding_agent_search::indexer::IndexOptions {
        full: false,
        force_rebuild: false,
        watch: false,
        watch_once_paths: Some(vec![watch_once_path]),
        db_path: data_dir.join("agent_search.db"),
        data_dir: data_dir.to_path_buf(),
        semantic: false,
        embedder: "hash".to_string(),
        progress: None,
        watch_interval_secs: 30,
    };
    coding_agent_search::indexer::run_index(opts, None)
}

fn message_row_count(db_path: &std::path::Path) -> i64 {
    if !db_path.exists() {
        return 0;
    }
    let conn = rusqlite::Connection::open(db_path).expect("open db for row count");
    conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0)).unwrap_or(0)
}

/// Judge case B.10 #4, capture-failure ①: `PrepareStage::BeforeCapture`
/// makes the source file unreadable (mode `0o000`, not deleted -- the
/// permission-denied sibling of the delete-based case ② right below)
/// between the connector's own scan pass and `attach_raw_mirror_capture`'s
/// independent re-read of the same bytes -- the resulting permission error
/// must be a hard `CaptureFailed`, same as `NotFound`.
///
/// **Not a subprocess/exit-code test**, despite this judge case's
/// mission-text name ("只读镜像目录/退出码非零") -- two things that sound
/// simple both turned out not to hold empirically in this codebase:
/// (a) chmod'ing the *mirror* directory read-only does nothing, because
/// `raw_mirror.rs` explicitly `set_permissions(..., 0o700)`s every
/// directory it creates/ensures as part of normal capture setup (defensive
/// against a restrictive umask) -- confirmed empirically, a session
/// ingests cleanly straight through a pre-chmod'd 0o500 mirror root;
/// (b) chmod'ing the *source* file unreadable **before the CLI process
/// even starts** doesn't produce a capture failure either, because the
/// connector's own scan step can't read it at all and treats "not a
/// parseable session" as zero-conversations-found (exit 0), never
/// reaching `attach_raw_mirror_capture` in the first place -- confirmed
/// empirically (`cass index --watch-once` on a pre-`chmod 0o000`'d file:
/// `"success":true`, `"conversations":0`). The hook is what makes this a
/// genuine `CaptureFailed` rather than an invisible "no session" no-op:
/// it fires only *after* the connector's scan already produced a real
/// `NormalizedConversation` from the still-readable file, so the
/// permission change lands exactly in the window between that successful
/// scan and raw-mirror's independent re-read.
#[test]
fn capture_failed_before_capture_hook_making_source_unreadable_skips_session() {
    use std::os::unix::fs::PermissionsExt;

    let _serialize = HOOK_TEST_SERIALIZE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let home_tmp = tempfile::TempDir::new().expect("home tempdir");
    let data_dir = home_tmp.path().join("cass-data");
    std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");
    let session_dir = tempfile::TempDir::new().expect("session dir");
    let (session_path, _raw) = write_codex_host_shell_session(session_dir.path());

    let to_lock_down = session_path.clone();
    coding_agent_search::indexer::set_prepare_fault_hook(Some(Box::new(move |stage| {
        if stage == coding_agent_search::indexer::PrepareStage::BeforeCapture {
            std::fs::set_permissions(&to_lock_down, std::fs::Permissions::from_mode(0o000)).ok();
        }
    })));
    let result = run_index_in_process(&data_dir, session_path.clone());
    coding_agent_search::indexer::set_prepare_fault_hook(None);
    std::fs::set_permissions(&session_path, std::fs::Permissions::from_mode(0o600)).ok();

    assert_eq!(
        message_row_count(&data_dir.join("agent_search.db")),
        0,
        "a capture-failed session must not land any rows; run_index result={result:?}"
    );
}

/// Judge case B.10 #4, capture-failure ②: `PrepareStage::BeforeCapture`
/// deletes the source file between the first scan pass and
/// `attach_raw_mirror_capture` -- the resulting `NotFound` must be a hard
/// `CaptureFailed` (Global Constraints: `SourceKind::File` capture-time
/// absence is never treated as a logical source), so the session lands
/// zero rows.
#[test]
fn capture_failed_before_capture_hook_deleting_source_file_skips_session() {
    let _serialize = HOOK_TEST_SERIALIZE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let home_tmp = tempfile::TempDir::new().expect("home tempdir");
    let data_dir = home_tmp.path().join("cass-data");
    std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");
    let session_dir = tempfile::TempDir::new().expect("session dir");
    let (session_path, _raw) = write_codex_host_shell_session(session_dir.path());

    let to_delete = session_path.clone();
    coding_agent_search::indexer::set_prepare_fault_hook(Some(Box::new(move |stage| {
        if stage == coding_agent_search::indexer::PrepareStage::BeforeCapture {
            std::fs::remove_file(&to_delete).ok();
        }
    })));
    let result = run_index_in_process(&data_dir, session_path);
    coding_agent_search::indexer::set_prepare_fault_hook(None);

    assert_eq!(
        message_row_count(&data_dir.join("agent_search.db")),
        0,
        "a session whose source vanished before capture must not land any rows; run_index result={result:?}"
    );
}

/// Judge case B.10 #4, capture-failure ③: `PrepareStage::BeforeDurableSync`
/// chmods the raw-mirror `blobs` directory to `0o000` (no read, no
/// execute -- blocking *traversal* into it, not just writes) right before
/// `sync_capture_durable` -- its `force_sync_parent` opens the blob's
/// parent directory (a subdirectory *under* `blobs`) purely to fsync it,
/// so only blocking traversal through `blobs` itself makes that open fail;
/// `0o500` (blocks writes, keeps read+execute) does not, since nothing
/// under `sync_capture_durable` ever tries to create anything inside
/// `blobs` -- everything it touches was already written during capture,
/// earlier in the same prepare call, before this hook fires. The R2-B1
/// fsync-before-commit step must fail closed (排除行提交前镜像必须持久化),
/// so the session lands zero rows rather than committing empty content
/// with no durable original.
#[test]
fn capture_failed_before_durable_sync_hook_readonly_blob_dir_skips_session() {
    use std::os::unix::fs::PermissionsExt;

    let _serialize = HOOK_TEST_SERIALIZE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let home_tmp = tempfile::TempDir::new().expect("home tempdir");
    let data_dir = home_tmp.path().join("cass-data");
    std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");
    let session_dir = tempfile::TempDir::new().expect("session dir");
    let (session_path, _raw) = write_codex_host_shell_session(session_dir.path());

    let blobs_dir = data_dir.join("raw-mirror").join("v1").join("blobs");
    coding_agent_search::indexer::set_prepare_fault_hook(Some(Box::new(move |stage| {
        if stage == coding_agent_search::indexer::PrepareStage::BeforeDurableSync {
            std::fs::set_permissions(&blobs_dir, std::fs::Permissions::from_mode(0o000)).ok();
        }
    })));
    let result = run_index_in_process(&data_dir, session_path);
    coding_agent_search::indexer::set_prepare_fault_hook(None);

    // Restore permissions unconditionally before the tempdir is torn down.
    let blobs_dir_restore = data_dir.join("raw-mirror").join("v1").join("blobs");
    std::fs::set_permissions(&blobs_dir_restore, std::fs::Permissions::from_mode(0o700)).ok();

    assert_eq!(
        message_row_count(&data_dir.join("agent_search.db")),
        0,
        "a session whose durable-sync step failed must not land any rows; run_index result={result:?}"
    );
}

/// Judge case B.10 #5: `PrepareStage::BeforeCapture` appends a second,
/// complete synthetic event to the source file right before capture --
/// capture/reparse must pick up the appended event too (the reparse is
/// from the just-captured blob, which necessarily includes it), landing
/// N+1 rows with no error, not N (stale first-pass count) and not a
/// CaptureFailed.
#[test]
fn before_capture_hook_appending_a_complete_event_lands_n_plus_one_rows() {
    let _serialize = HOOK_TEST_SERIALIZE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let home_tmp = tempfile::TempDir::new().expect("home tempdir");
    let data_dir = home_tmp.path().join("cass-data");
    std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");
    let session_dir = tempfile::TempDir::new().expect("session dir");
    let (session_path, _raw) = write_codex_host_shell_session(session_dir.path());

    let to_append = session_path.clone();
    coding_agent_search::indexer::set_prepare_fault_hook(Some(Box::new(move |stage| {
        if stage == coding_agent_search::indexer::PrepareStage::BeforeCapture {
            use std::io::Write;
            let appended = serde_json::json!({"type":"response_item","payload":{"type":"message","id":"msg_appended","role":"user","content":[{"type":"input_text","text":"appended after first parse"}]}});
            let mut f = std::fs::OpenOptions::new().append(true).open(&to_append).expect("open source for append");
            writeln!(f, "{appended}").expect("append event");
        }
    })));
    let result = run_index_in_process(&data_dir, session_path);
    coding_agent_search::indexer::set_prepare_fault_hook(None);
    result.expect("run_index must succeed when the appended tail is a well-formed event");

    assert_eq!(
        message_row_count(&data_dir.join("agent_search.db")),
        5,
        "the fixture's 4 messages plus the appended 5th must all land, not just the pre-append 4"
    );
}

/// Judge case B.10 #7: `cass status --json`'s `last_index.*` three keys
/// reflect the most recent successful run's counters, and a subsequent
/// failed run must leave them unchanged rather than clobbering them with
/// zeros.
///
/// The second (failing) run uses the same `BeforeCapture`-hook technique as
/// `capture_failed_before_capture_hook_making_source_unreadable_skips_
/// session` above, in-process, sharing `data_dir` with the first
/// (subprocess) run's DB -- neither a subprocess-level "只读镜像目录" nor
/// an unreadable-before-launch source file actually fails this CLI (see
/// that test's doc comment for the empirical findings), so there is no
/// real subprocess invocation that reliably fails here to assert a
/// "退出码非零" half of this judge case against.
#[test]
fn status_json_last_index_counters_survive_a_failed_run() {
    use std::os::unix::fs::PermissionsExt;

    let _serialize = HOOK_TEST_SERIALIZE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let home_tmp = tempfile::TempDir::new().expect("home tempdir");
    let home = home_tmp.path();
    let data_dir = home.join("cass-data");
    std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");

    let session_dir = tempfile::TempDir::new().expect("session dir");
    let (session_path, _raw) = write_codex_host_shell_session(session_dir.path());

    let output = cass_cmd(&data_dir, home)
        .args(["index", "--watch-once", session_path.to_str().expect("utf8 session path"), "--json"])
        .output()
        .expect("spawn cass index --watch-once");
    assert!(output.status.success(), "seed ingest must succeed; stderr={}", String::from_utf8_lossy(&output.stderr));

    let status_after_success = cass_cmd(&data_dir, home)
        .args(["status", "--json"])
        .output()
        .expect("spawn cass status --json");
    assert!(status_after_success.status.success(), "cass status must succeed");
    let status_value: serde_json::Value =
        serde_json::from_slice(&status_after_success.stdout).expect("parse cass status --json output");
    let last_index_after_success = status_value.get("last_index").cloned().unwrap_or(serde_json::Value::Null);
    let hits_after_success = last_index_after_success.get("codex_host_shell_hits").and_then(serde_json::Value::as_u64);
    let total_after_success = last_index_after_success.get("codex_idx0_user_total").and_then(serde_json::Value::as_u64);
    assert_eq!(hits_after_success, Some(1), "codex_host_shell_hits must reflect this run's one anchor-3 hit: {status_value}");
    assert_eq!(total_after_success, Some(1), "codex_idx0_user_total must reflect this run's one idx0/user candidate: {status_value}");
    let event_align_failed_after_success =
        last_index_after_success.get("event_align_failed").and_then(serde_json::Value::as_u64);
    assert_eq!(event_align_failed_after_success, Some(0), "the fixture is a real mixed shape, alignment must not fail: {status_value}");

    // Now run a genuinely capture-failed session (in-process hook) against
    // the SAME data_dir -- a failed run must not clobber the counters the
    // successful subprocess run above just wrote.
    let second_session_dir = tempfile::TempDir::new().expect("second session dir");
    let (second_session_path, _raw2) = write_codex_host_shell_session(second_session_dir.path());
    let to_lock_down = second_session_path.clone();
    coding_agent_search::indexer::set_prepare_fault_hook(Some(Box::new(move |stage| {
        if stage == coding_agent_search::indexer::PrepareStage::BeforeCapture {
            std::fs::set_permissions(&to_lock_down, std::fs::Permissions::from_mode(0o000)).ok();
        }
    })));
    let second_run_result = run_index_in_process(&data_dir, second_session_path.clone());
    coding_agent_search::indexer::set_prepare_fault_hook(None);
    std::fs::set_permissions(&second_session_path, std::fs::Permissions::from_mode(0o600)).ok();
    assert!(
        second_run_result.is_ok(),
        "run_index itself returns Ok even when an individual session's capture fails (it logs and skips that session, matching the CLI's own observed behavior); a hard Err here would mean something else broke: {second_run_result:?}"
    );
    assert_eq!(
        message_row_count(&data_dir.join("agent_search.db")),
        4,
        "the failed second session must not have added any rows on top of the first run's 4"
    );

    let status_after_failure = cass_cmd(&data_dir, home)
        .args(["status", "--json"])
        .output()
        .expect("spawn cass status --json after failure");
    assert!(status_after_failure.status.success(), "cass status must succeed even after a failed index run");
    let status_value_after_failure: serde_json::Value =
        serde_json::from_slice(&status_after_failure.stdout).expect("parse cass status --json output after failure");
    let last_index_after_failure =
        status_value_after_failure.get("last_index").cloned().unwrap_or(serde_json::Value::Null);
    assert_eq!(
        last_index_after_failure.get("codex_host_shell_hits").and_then(serde_json::Value::as_u64),
        Some(1),
        "a failed run must preserve the previous successful run's codex_host_shell_hits, not zero it: {status_value_after_failure}"
    );
    assert_eq!(
        last_index_after_failure.get("codex_idx0_user_total").and_then(serde_json::Value::as_u64),
        Some(1),
        "a failed run must preserve the previous successful run's codex_idx0_user_total, not zero it: {status_value_after_failure}"
    );
}
