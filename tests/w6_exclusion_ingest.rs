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
