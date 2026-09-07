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
