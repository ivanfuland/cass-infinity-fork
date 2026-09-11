//! T14-3 / #122b-1 block B: real exec of `scripts/oracle/memory_gate.sh
//! --selfcheck` against the `w6_memory_hog` example binary (and, for the
//! exit-code variant, `/bin/false`). This is CLI-level, not a unit test:
//! it shells out to the real bash script, which itself backgrounds and
//! polls a real process tree via `/proc` -- there is no mock or stub
//! anywhere in this path.
//!
//! `w6_memory_hog` is an `[[example]]`, not the `[[bin]]` target `cass`,
//! so it isn't available via `assert_cmd`'s `cargo_bin_cmd!`/
//! `CARGO_BIN_EXE_cass`-style macro the way `tests/e2e_pages.rs` locates
//! the candidate binary -- cargo only injects `CARGO_BIN_EXE_<name>` env
//! vars for `[[bin]]` targets. `hog_binary_path` below instead derives the
//! path cargo actually builds examples to: a `examples/` directory
//! sibling to this test binary's own `deps/` directory, both under the
//! same `target/<profile>/` -- the same "pre-built artifact under a known
//! relative path" convention `scripts/oracle/memory_gate.sh`'s own
//! `$EXAMPLES` env var uses for `w4_memory_fixture`/`w4_completeness_gate`
//! in normal (non-selfcheck) mode. Build it first (same mandatory env/
//! feature flags as everything else in this PR):
//!   cargo build --release --example w6_memory_hog \
//!     --no-default-features --features qr,encryption,infinity
//! before `cargo test --release --test w6_memory_gate_selfcheck ...`
//! (matching profiles matters: this test looks in ITS OWN profile's
//! `examples/` dir).

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn gate_script() -> PathBuf {
    repo_root().join("scripts/oracle/memory_gate.sh")
}

fn hog_binary_path() -> PathBuf {
    let test_exe = std::env::current_exe().expect("current_exe");
    let deps_dir = test_exe.parent().expect("deps dir has a parent");
    let profile_dir = deps_dir.parent().expect("profile dir has a parent");
    let candidate = profile_dir.join("examples").join("w6_memory_hog");
    assert!(
        candidate.is_file(),
        "w6_memory_hog example binary not found at {candidate:?} -- build it first: \
         cargo build --release --example w6_memory_hog --no-default-features \
         --features qr,encryption,infinity (with this PR's mandatory CARGO_* env vars)"
    );
    candidate
}

struct SelfcheckOutcome {
    exit_code: i32,
    stage_json: Value,
}

fn run_selfcheck(run_root: &std::path::Path, extra_args: &[&str]) -> SelfcheckOutcome {
    let mut cmd = Command::new("bash");
    cmd.arg(gate_script())
        .arg("--selfcheck")
        .arg("--")
        .args(extra_args)
        .env("RUN_ROOT", run_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd.output().expect("spawn memory_gate.sh --selfcheck");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The script's last stdout line (from `tee`) is the stage JSON; the
    // parent hog process also prints `pid=`/`child_pid=` lines before it,
    // when the tested command is the hog.
    let json_line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .unwrap_or_else(|| {
            panic!(
                "no JSON line in memory_gate.sh --selfcheck stdout: stdout={stdout:?} stderr={:?}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    let stage_json: Value = serde_json::from_str(json_line)
        .unwrap_or_else(|e| panic!("stage JSON did not parse: {e}: {json_line:?}"));
    SelfcheckOutcome { exit_code: output.status.code().unwrap_or(-1), stage_json }
}

/// Positive case (spec §四.3 / plan Task 4 Step 4 Interfaces): a process
/// tree of two live processes (hog parent + hog child), each individually
/// well under 200MiB VmHWM, whose SUMMED VmRSS crosses 280MiB -- only
/// `peak_tree` (the sum) can see that; `peak_proc` (the per-process max)
/// cannot. Both hold their allocation >=1s so the 100ms-cadence poller
/// gets >=5 real samples.
#[test]
fn selfcheck_sums_process_tree_rss_across_parent_and_child() {
    let tmp = tempfile::TempDir::new().unwrap();
    let outcome = run_selfcheck(tmp.path(), &[hog_binary_path().to_str().unwrap(), "--mib", "150", "--hold-ms", "1500"]);

    let peak_tree = outcome.stage_json["peak_tree"].as_i64().expect("peak_tree present");
    let peak_proc = outcome.stage_json["peak_proc"].as_i64().expect("peak_proc present");
    let measured = outcome.stage_json["measured"].as_bool().expect("measured present");
    let samples = outcome.stage_json["samples"].as_i64().expect("samples present");

    assert!(measured, "a >=1s two-process stage must be measured: {:?}", outcome.stage_json);
    assert!(samples >= 5, "expected >=5 samples over a >=1s hold: {:?}", outcome.stage_json);
    assert!(
        peak_tree >= 280 * 1024 * 1024,
        "peak_tree (summed tree RSS) must reach ~2x150MiB: got {peak_tree} bytes, json={:?}",
        outcome.stage_json
    );
    assert!(
        peak_proc < 200 * 1024 * 1024,
        "peak_proc (max single-process VmHWM) must stay under one hog's ~150MiB + slack: \
         got {peak_proc} bytes -- only the SUM should cross the 280MiB line, json={:?}",
        outcome.stage_json
    );
    assert_eq!(outcome.exit_code, 0, "measured && exit_code==0 && no budget must pass: {:?}", outcome.stage_json);
}

/// Variant ②: a fast-failing binary (`exit_code != 0`) must judge failed
/// regardless of what the (nonexistent, since it never got far enough to
/// allocate) memory samples say.
#[test]
fn selfcheck_judges_nonzero_exit_code_as_failed() {
    let tmp = tempfile::TempDir::new().unwrap();
    let outcome = run_selfcheck(tmp.path(), &["/bin/false"]);

    assert_eq!(outcome.stage_json["exit_code"], 1, "json={:?}", outcome.stage_json);
    assert_ne!(outcome.exit_code, 0, "a failed test process must judge failed: json={:?}", outcome.stage_json);
}

/// Variant ③: a stage shorter than the `stage_ms>=200` measured threshold
/// must report `measured=false` and judge failed, even though the process
/// itself exits cleanly (`exit_code=0`) -- an unmeasured stage is not a
/// free pass (this is the same "measurement_valid" concern the retired
/// PR4 script's R1-B6 comment called out, carried into the new judgment).
#[test]
fn selfcheck_a_too_short_stage_is_unmeasured_and_judged_failed() {
    let tmp = tempfile::TempDir::new().unwrap();
    let outcome = run_selfcheck(tmp.path(), &[hog_binary_path().to_str().unwrap(), "--mib", "1", "--hold-ms", "50"]);

    assert_eq!(outcome.stage_json["measured"], false, "a 50ms stage must be unmeasured: json={:?}", outcome.stage_json);
    assert_ne!(outcome.exit_code, 0, "an unmeasured stage must judge failed even with exit_code=0: json={:?}", outcome.stage_json);
}

/// Variant ④: `--judge` with empty stdin must fail loud (exit 2), never
/// default to a silent pass/fail. Asserts on the stderr message (not just
/// the exit code): an empty/whitespace-only input is *also* invalid JSON,
/// so `json.loads` alone would already raise and exit 2 via the "invalid
/// JSON" branch even with the dedicated empty-input check deleted --
/// confirmed empirically while proving this test's mutation-sensitivity
/// (the dedicated check's mutation left exit code 2 unchanged, only the
/// message changed to "invalid JSON: Expecting value..."). Checking the
/// specific message is what makes the dedicated empty-input branch (and
/// its clearer operator-facing error text) actually load-bearing.
#[test]
fn judge_mode_rejects_empty_input_with_exit_2() {
    let output = Command::new("bash")
        .arg(gate_script())
        .arg("--judge")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn memory_gate.sh --judge");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("empty input"), "expected the dedicated empty-input message, got: {stderr}");
}
