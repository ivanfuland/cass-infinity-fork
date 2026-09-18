//! PR8 C9 (T6B concurrency side): the binary must name the write-lock path it
//! actually contends on.
//!
//! Background: the fork has zero hits for `CASS_WRITE_LOCK`. That variable
//! belongs to the control-plane wrapper scripts (`full-reingest.sh`,
//! `index-pull.sh`), which wrap the binary in their own `flock`. The lock the
//! *binary* takes is `<data_dir>/index-run.lock` (POSIX advisory `flock`, taken
//! in `indexer::acquire_index_run_lock`). An external observer therefore has no
//! supported way to learn that path — it had to be re-derived from source or
//! from the wrapper scripts, which is exactly the kind of drift this test pins
//! down.
//!
//! This file freezes the contract that:
//!
//! 1. `cass index --json` exposes the path at top level as
//!    `index_run_lock_path`, equal to `<data_dir>/index-run.lock`.
//! 2. `cass status --json` exposes the same key with the same value.
//! 3. The path is not merely reported but genuinely held: while a real
//!    `cass index` process is running, an exclusive advisory lock on exactly
//!    that path cannot be taken, and it can be taken again once the process is
//!    gone.
//!
//! Point 3 is measured three times — free before, contended during, free after
//! — so a probe that always fails (or always succeeds) cannot pass this test.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use fs2::FileExt;
use serde_json::Value;
use tempfile::TempDir;

/// Build a `cass` invocation pinned to a scratch home so the test never reads
/// or writes the operator's real data dir or source roots.
fn cass_cmd(home: &Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cass"));
    cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .current_dir(home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("HOME", home)
        .env("CODEX_HOME", home.join(".codex"))
        .env("CLAUDE_HOME", home.join(".claude"))
        .env("GEMINI_HOME", home.join(".gemini"))
        .env("OPENCODE_STORAGE_ROOT", home.join(".opencode"))
        .env("CASS_AIDER_DATA_ROOT", home.join(".aider-missing"))
        .env("CASS_IGNORE_SOURCES_CONFIG", "1");
    cmd
}

fn raw_cass_command(home: &Path) -> StdCommand {
    let mut cmd = StdCommand::new(assert_cmd::cargo::cargo_bin!("cass"));
    cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .current_dir(home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("HOME", home)
        .env("CODEX_HOME", home.join(".codex"))
        .env("CLAUDE_HOME", home.join(".claude"))
        .env("GEMINI_HOME", home.join(".gemini"))
        .env("OPENCODE_STORAGE_ROOT", home.join(".opencode"))
        .env("CASS_AIDER_DATA_ROOT", home.join(".aider-missing"))
        .env("CASS_IGNORE_SOURCES_CONFIG", "1");
    cmd
}

fn json_stdout(home: &Path, data_dir: &Path, args: &[&str]) -> Value {
    let output = cass_cmd(home)
        .args(args)
        .arg("--data-dir")
        .arg(data_dir)
        .output()
        .expect("run cass");
    assert!(
        output.status.success(),
        "`cass {} --data-dir {}` failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        data_dir.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "`cass {} --json` did not emit JSON on stdout: {err}\nstdout:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// Take an exclusive advisory lock on `path`, returning the held handle.
///
/// `Err` means somebody else holds it — which is the signal this test reads.
fn try_take_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    file.try_lock_exclusive()?;
    Ok(file)
}

/// A running child that is killed when dropped.
///
/// `--watch` never exits on its own, and this box is shared with other work, so
/// an assertion firing while the watcher is alive must not leave it behind.
/// `disarm` hands the child back to explicit teardown without double-killing.
struct KillOnDrop(Option<Child>);

impl KillOnDrop {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("child still owned")
    }

    fn disarm(&mut self) -> Child {
        self.0.take().expect("child still owned")
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Wait for `child` to exit, killing it if it outlives `grace`.
fn stop_child(mut child: Child, grace: Duration) {
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn lock_path_exposed_and_held() {
    let tmp = TempDir::new().expect("create temp dir");
    let home = tmp.path().to_path_buf();
    let data_dir = home.join("cass_data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let expected: PathBuf = data_dir.join("index-run.lock");

    // (1) `index --json` names the lock the run itself will take.
    let index_json = json_stdout(&home, &data_dir, &["index", "--json"]);
    let index_lock_path = index_json
        .get("index_run_lock_path")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "`index --json` must expose a top-level `index_run_lock_path`; got keys {:?}",
                index_json
                    .as_object()
                    .map(|map| map.keys().cloned().collect::<Vec<_>>())
            )
        })
        .to_string();
    assert_eq!(
        Path::new(&index_lock_path),
        expected.as_path(),
        "`index --json` must report the path the indexer actually locks"
    );

    // (2) `status --json` reports the same configuration fact.
    let status_json = json_stdout(&home, &data_dir, &["status", "--json"]);
    let status_lock_path = status_json
        .get("index_run_lock_path")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "`status --json` must expose a top-level `index_run_lock_path`; got keys {:?}",
                status_json
                    .as_object()
                    .map(|map| map.keys().cloned().collect::<Vec<_>>())
            )
        });
    assert_eq!(
        status_lock_path, index_lock_path,
        "`index --json` and `status --json` must agree on the lock path"
    );

    // (3) The reported path is the file the index run really created.
    assert!(
        expected.is_file(),
        "a completed `cass index` must have created {}",
        expected.display()
    );

    // (4a) Baseline: with no index process running, the lock is free. This
    // guards against a probe that can only ever report "held".
    try_take_exclusive(&expected)
        .expect("idle data dir must leave index-run.lock lockable")
        .unlock()
        .expect("release baseline probe lock");

    // (4b) While a real `cass index` runs, exactly that path is held. Watch
    // mode keeps the run (and therefore the lock) alive deterministically,
    // instead of racing a one-shot index against a fixed sleep.
    //
    // Clear any metadata a previous run left behind first: the "published"
    // wait below keys off the file becoming non-empty, and `acquire_index_run_lock`
    // writes its metadata immediately after taking the lock, so a non-empty
    // file is a sound "the holder is in place" signal. The `status --json` read
    // in (2) normally reaps stale metadata anyway, but do not depend on that.
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&expected)
        .expect("truncate pre-run lock metadata")
        .sync_all()
        .expect("sync truncated lock metadata");

    let mut watcher = KillOnDrop::new({
        let mut cmd = raw_cass_command(&home);
        cmd.args(["index", "--watch", "--json", "--data-dir"])
            .arg(&data_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd.spawn().expect("spawn `cass index --watch`")
    });

    // Wait for the holder to publish its metadata *before* probing. Probing
    // with our own lock any earlier would make the watcher's own
    // `try_lock_exclusive` fail, and a watcher that exits on startup cannot
    // testify to anything.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut published = false;
    while Instant::now() < deadline {
        let len = std::fs::metadata(&expected).map(|m| m.len()).unwrap_or(0);
        if len > 0 {
            published = true;
            break;
        }
        if watcher
            .child_mut()
            .try_wait()
            .expect("poll watcher")
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        published,
        "`cass index --watch` never published lock metadata at {}",
        expected.display()
    );

    let exited = watcher.child_mut().try_wait().expect("poll watcher");
    assert!(
        exited.is_none(),
        "the watcher exited on its own; the contention observed below cannot be attributed to it"
    );

    let held = match try_take_exclusive(&expected) {
        Ok(file) => {
            file.unlock().expect("release failed-probe lock");
            false
        }
        Err(_) => true,
    };
    assert!(
        held,
        "a running `cass index --watch` must hold an exclusive lock on {}",
        expected.display()
    );

    // (4c) Once the holder is gone the lock is free again — so the contention
    // in (4b) was the index process, not a stale file or an always-failing
    // probe. `--watch` runs until killed by design, so expect to wait the full
    // grace here; the interesting bound is the released-poll below.
    stop_child(watcher.disarm(), Duration::from_secs(3));
    let mut released = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Ok(file) = try_take_exclusive(&expected) {
            file.unlock().expect("release post-kill probe lock");
            released = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        released,
        "the lock must be released after the index process exits ({})",
        expected.display()
    );
}
