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

/// R6-N6-① (#128 T6-a2): the claim "a stage that fails must judge failed
/// regardless of what the memory samples say" was carried by the `/bin/false`
/// variant alone, and `/bin/false` exits before the poller ever samples it
/// (`measured=false`, `samples=0`, `stage_ms=187` on bbf8c299) -- so that
/// variant only ever exercised "unmeasured => failed". This is the missing
/// combination: a stage that *is* measured (a real ~500ms hold: samples=3,
/// stage_ms=639 on bbf8c299) and *then* fails. Only its exit code can decide
/// the verdict, and the verdict must be a real judgment (1) -- not malformed
/// input (2) and not a pass (0).
///
/// This finding has no product defect behind it (verified: the judgment is
/// already correct on bbf8c299), so its redness is a *mutation* red, per the
/// #128 任务书 ruling: deleting the `exit_code` term from `judge_from_stdin`
/// leaves the `/bin/false` variant green (it is already failed for being
/// unmeasured) and turns only this variant red.
#[test]
fn selfcheck_judges_a_measured_stage_failed_by_its_nonzero_exit_code() {
    let tmp = tempfile::TempDir::new().unwrap();
    let outcome = run_selfcheck(tmp.path(), &["bash", "-c", "sleep 0.5; exit 3"]);

    assert_eq!(outcome.stage_json["exit_code"], 3, "json={:?}", outcome.stage_json);
    assert_eq!(
        outcome.stage_json["measured"], true,
        "a ~500ms stage must be measured: json={:?}",
        outcome.stage_json
    );
    assert!(
        outcome.stage_json["samples"].as_i64().expect("samples present") >= 2,
        "json={:?}",
        outcome.stage_json
    );
    assert_eq!(
        outcome.exit_code, 1,
        "measured=true with exit_code!=0 must judge failed (1) -- neither 2 (malformed input) nor 0 (a pass): json={:?}",
        outcome.stage_json
    );
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

/// R6-B2 / R6-N6-② (#128 T6-a2): a stage's `stage_ms` ends the moment
/// `kill -0` first reports the root gone, and the liveness check runs before
/// the sample pass, so a deadline that has already passed is never paid for
/// by another full `/proc` sweep.
///
/// Adversarial input: a ~120ms command. On bbf8c299 the old loop order
/// (sample -> check -> sleep) swept the already-dead tree once more and took
/// `end_ns` after `wait`: measured `stage_ms` = 235 / 243 / 244 on an idle
/// host and 263 / 287 while a parallel cargo build was running, all from a
/// stage that had really finished in 120ms.
///
/// Timed breakdown of one pre-fix run (a timestamp-instrumented *copy* of the
/// script; the script under test was not modified):
///   sample pass 1   0.6ms -> 69ms   root alive, samples=1
///   sleep           100ms
///   sample pass 2   170ms -> 241ms  root already dead, samples stays 1
///   kill -0 fails   242ms
///   wait            1.5ms
/// `wait` was 1.5ms of those 243ms; the trailing sweep of the dead tree was
/// the rest, which is why moving `end_ns` alone is not enough and the check
/// has to come first.
///
/// Why this is asserted against a measured period and not against a fixed
/// number: the fix leaves a sub-period stage costing exactly one poll period
/// -- one `/proc` sweep plus one 100ms sleep. The pre-fix loop paid one
/// period plus a second sweep of the tree that had already died (measured
/// 55-73ms extra: that sweep still walks every `/proc/<pid>/stat` in the
/// system, it merely finds no tree members to read `status` from). So a
/// literal `stage_ms < 200` line would in fact be asserting "one /proc sweep
/// takes under 100ms *on this host*", which is a property of the machine and
/// its load, not of this change: the sweep measured ~70ms idle and ~106ms
/// with a cargo build running, and the 200ms assertion flapped exactly on
/// that difference. The loop's own period is calibrated from a long stage in
/// the same test run instead, which cancels the host term. The remaining
/// allowance is a fixed eighth of that period -- above the post-fix residual
/// over a period (≤2ms measured across runs, since the break lands
/// immediately after a cheap `kill -0`) and well below the pre-fix excess
/// (55ms+), with roughly 2x headroom on both sides. The door's own 200ms
/// `measured` line is what makes this worth pinning at all: it is the
/// threshold the reported duration must not cross for a stage that finished
/// long before it.
///
/// The `samples>=2 AND stage_ms<200` corner (two samples, a duration below
/// the threshold) is *not* reachable from a real child on this host -- two
/// samples require the root to outlive a full poll period, after which the
/// break check lands ~239ms in -- so that limb is pinned on the `--judge`
/// surface by `judge_rejects_measured_true_whose_samples_disagree_with_its_stage_ms`
/// below instead (R6-N6-②).
#[test]
fn selfcheck_a_short_stage_stays_under_the_measured_stage_ms_threshold() {
    let tmp = tempfile::TempDir::new().unwrap();

    // Calibration: a stage that outlives several poll periods reports its own
    // per-period cost as `stage_ms / samples`. Each sample is one full
    // `/proc` sweep, each sweep is followed by exactly one `POLL_INTERVAL_S`
    // sleep, and the loop breaks at the first check after the root dies -- so
    // the quotient is this run's period, with no assumption about how fast a
    // sweep is.
    let calibration = run_selfcheck(tmp.path(), &["sleep", "1.2"]);
    let cal_ms = calibration.stage_json["stage_ms"].as_i64().expect("stage_ms present");
    let cal_samples = calibration.stage_json["samples"].as_i64().expect("samples present");
    assert!(
        cal_samples >= 3,
        "the calibration stage must outlive several poll periods to price one: {:?}",
        calibration.stage_json
    );
    let period_est = cal_ms / cal_samples;

    let outcome = run_selfcheck(tmp.path(), &["sleep", "0.12"]);
    let stage_ms = outcome.stage_json["stage_ms"].as_i64().expect("stage_ms present");
    assert!(
        stage_ms <= period_est + period_est / 8,
        "a ~120ms stage must cost at most one poll period (measured period {period_est}ms on this \
         host in this run): before the fix the loop paid a second, already-dead /proc sweep on top \
         of that period. got stage_ms={stage_ms}ms, json={:?}",
        outcome.stage_json
    );
    assert!(
        outcome.stage_json["samples"].as_i64().expect("samples present") < 2,
        "a ~120ms stage cannot be sampled twice at this cadence: json={:?}",
        outcome.stage_json
    );
    assert_eq!(outcome.stage_json["measured"], false, "json={:?}", outcome.stage_json);
    assert_ne!(
        outcome.exit_code, 0,
        "an unmeasured stage must judge failed: json={:?}",
        outcome.stage_json
    );
}

/// N-回落 (#128 T6-a2, control-plane 2026-09-12 追加): the door is re-cut as
/// "record only, judge the fall" -- and a per-cell peak alone cannot show a
/// fall, so each cell now carries `last_tree` (the tree RSS of the final
/// sample pass, bytes, same unit as `peak_tree`) and `peak_sample_idx`
/// (which sample the peak came from, 1-based; 0 when nothing was sampled).
///
/// The command is chosen so the fall is *observable*: the memory hog is run
/// as a child of a longer-lived shell, so the root outlives the drop and the
/// poller keeps sampling after the tree has shrunk back to the shell itself.
/// That matters for the mutation below -- writing `last_tree = peak_tree`
/// would satisfy a bare `last_tree <= peak_tree`, so the strict
/// `last_tree < peak_tree` assertion is what makes the mutation visible. (No
/// pre-existing selfcheck command here produces a fall: `/bin/false` is
/// never sampled at all and the hog holds to the end.)
#[test]
fn selfcheck_reports_the_last_sample_and_the_peak_sample_index() {
    let tmp = tempfile::TempDir::new().unwrap();
    let command = format!(
        "{} --mib 150 --hold-ms 500 & sleep 1.2; wait",
        hog_binary_path().display()
    );
    let outcome = run_selfcheck(tmp.path(), &["bash", "-c", &command]);

    let peak = outcome.stage_json["peak_tree"].as_i64().expect("peak_tree present");
    let last = outcome.stage_json["last_tree"].as_i64().expect("last_tree must be present");
    let idx = outcome.stage_json["peak_sample_idx"]
        .as_i64()
        .expect("peak_sample_idx must be present");
    let samples = outcome.stage_json["samples"].as_i64().expect("samples present");

    assert!(
        samples >= 4,
        "a ~1.2s stage must yield several samples at this cadence: json={:?}",
        outcome.stage_json
    );
    assert!(
        idx >= 1 && idx <= samples,
        "peak_sample_idx is a 1-based ordinal into the sample count: idx={idx} samples={samples}"
    );
    assert!(last <= peak, "the last sample cannot exceed the peak: last={last} peak={peak}");
    assert!(
        last < peak,
        "this command drops its allocation while the root lives on, so the final sample must sit \
         below the peak: last={last} peak={peak}, json={:?}",
        outcome.stage_json
    );
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

/// Feed one stage-result JSON through the real `--judge` surface, with the
/// given extra flags (`--allow-null-budget`).
fn run_judge(stdin_json: &str, extra_args: &[&str]) -> std::process::Output {
    use std::io::Write as _;
    let mut child = Command::new("bash")
        .arg(gate_script())
        .arg("--judge")
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn memory_gate.sh --judge");
    child
        .stdin
        .as_mut()
        .expect("judge stdin is piped")
        .write_all(stdin_json.as_bytes())
        .expect("write the stage JSON to judge stdin");
    child.wait_with_output().expect("wait for memory_gate.sh --judge")
}

/// R7-4 (#124, control-plane adversarial review of #123, blocker class:
/// false green). Whether the budget term is *required* used to be decided by
/// the judged object's own `shape` field: any hand-written stage result
/// could declare itself `"shape":"selfcheck"` and have the budget check
/// skipped, and an explicit `"budget":null` was accepted for a normal shape
/// too. Malformed input must not be able to name the mode it wants to be
/// judged under; the caller now says so with `--allow-null-budget`, which
/// `run_stage` passes only for the two modes that have no P0 budget
/// (`--selfcheck` and `--collect-baseline`). Cases ①② are the reproductions
/// (both exited 0 before the fix), case ③ the flag, and the end-to-end case
/// at the bottom is what proves the flag really reaches the judge from
/// `run_stage` -- without it the selfcheck mode would judge every stage
/// failed.
#[test]
fn judge_requires_a_budget_unless_the_caller_allows_none() {
    const PEAKS: &str =
        r#""stage":"index","measured":true,"exit_code":0,"peak_tree":1000000000000,"peak_proc":8192,"samples":3,"stage_ms":300"#;
    let no_budget_selfcheck = format!(r#"{{"shape":"selfcheck",{PEAKS}}}"#);
    let no_budget_shape_a = format!(r#"{{"shape":"a",{PEAKS}}}"#);
    let null_budget = format!(r#"{{"shape":"a",{PEAKS},"budget":null}}"#);

    // ① a missing `budget` key: a self-declared `shape` buys no free pass.
    let out = run_judge(&no_budget_selfcheck, &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a missing budget must be malformed input even when the object calls itself `selfcheck`: stderr={stderr}"
    );
    assert!(
        stderr.contains("carries no budget"),
        "expected the missing-budget message, got: {stderr}"
    );
    assert_eq!(
        run_judge(&no_budget_shape_a, &[]).status.code(),
        Some(2),
        "a missing budget must stay malformed input for a normal shape"
    );
    // ② an explicit null is the same door, and the same shut door.
    let out = run_judge(&null_budget, &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "a null budget must be malformed input: stderr={stderr}");
    assert!(
        stderr.contains("carries no budget"),
        "expected the missing-budget message for an explicit null too, got: {stderr}"
    );

    // ③ the caller-supplied flag is what allows a budgetless verdict.
    for allowed in [&no_budget_selfcheck, &null_budget] {
        let out = run_judge(allowed, &["--allow-null-budget"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(0),
            "with --allow-null-budget a measured, zero-exit stage must pass: input={allowed} stderr={stderr}"
        );
    }

    // The budget term itself is still enforced when one is present: this is
    // what keeps ①② from being satisfiable by simply deleting the check.
    let over = format!(r#"{{"shape":"a",{PEAKS},"budget":1024}}"#);
    assert_eq!(
        run_judge(&over, &[]).status.code(),
        Some(1),
        "a budget the peaks exceed must still judge failed"
    );

    // ④ end to end: `--selfcheck` reaches the judge through `run_stage`,
    // which must therefore be passing the flag. (Before the fix this mode
    // passed on its own `shape` value, so this case alone is not the
    // reproduction -- ①② are.)
    let tmp = tempfile::TempDir::new().unwrap();
    let outcome = run_selfcheck(
        tmp.path(),
        &[hog_binary_path().to_str().unwrap(), "--mib", "8", "--hold-ms", "400"],
    );
    assert_eq!(
        outcome.stage_json["measured"], true,
        "the selfcheck stage must be measured (>=2 samples, >=200ms): {:?}",
        outcome.stage_json
    );
    assert_eq!(
        outcome.stage_json["budget"],
        Value::Null,
        "selfcheck stages carry no budget: {:?}",
        outcome.stage_json
    );
    assert_eq!(
        outcome.exit_code, 0,
        "run_stage must pass --allow-null-budget for --selfcheck: {:?}",
        outcome.stage_json
    );
}

/// R6-N6-② (#128 T6-a2): the `stage_ms>=200` limb of `measured`. A real
/// child cannot produce `samples>=2` with `stage_ms<200` on this host -- two
/// samples require the root to outlive a full poll period (~170ms: a ~70ms
/// `/proc` sweep plus the 100ms sleep), so the earliest a two-sample stage
/// can end is ~239ms -- which is why the corner is pinned here, on the one
/// surface that takes `samples`/`stage_ms` as input (R6-N6-②: 与 B2 样本合并
/// 的是真子进程那一半，这一半只能合成).
///
/// Mutation-covered: deleting the `stage_ms` half of the consistency rule in
/// `judge_from_stdin` (keeping only the sample count) turns case ① below
/// green; deleting the sample-count half turns case ② green.
#[test]
fn judge_rejects_measured_true_whose_samples_disagree_with_its_stage_ms() {
    // ① two samples, a duration below the threshold: both limbs must hold,
    // not just the sample count.
    let out = run_judge(
        r#"{"shape":"a","measured":true,"exit_code":0,"peak_tree":1000,"peak_proc":1000,"samples":2,"stage_ms":170,"budget":1000000}"#,
        &[],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "measured=true with samples=2 but stage_ms=170 must be malformed input: stderr={stderr}"
    );
    assert!(
        stderr.contains("stage_ms>=200"),
        "expected the measured-consistency message, got: {stderr}"
    );
    // ② the mirror: a duration over the threshold with a single sample. This
    // keeps ① from being satisfiable by checking only the duration.
    let out = run_judge(
        r#"{"shape":"a","measured":true,"exit_code":0,"peak_tree":1000,"peak_proc":1000,"samples":1,"stage_ms":200,"budget":1000000}"#,
        &[],
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "measured=true with stage_ms=200 but samples=1 must be malformed input: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // ③ control: both limbs satisfied, so the object is judged on its budget
    // term alone and passes -- proving ①② are not satisfied by rejecting
    // every measured object.
    let out = run_judge(
        r#"{"shape":"a","measured":true,"exit_code":0,"peak_tree":1000,"peak_proc":1000,"samples":2,"stage_ms":200,"budget":1000000}"#,
        &[],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "samples=2 / stage_ms=200 within budget must pass: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Source the gate for one function call and run
/// `check_ingest_totals <db> <manifest>`. Sourcing is what the guard added
/// at the top of the CLI dispatch makes safe: without it the sourced file
/// would fall through into `usage; exit 2` and kill this shell.
fn run_check_ingest_totals(db: &std::path::Path, manifest: &std::path::Path) -> std::process::Output {
    Command::new("bash")
        .arg("-c")
        .arg(". \"$1\"; check_ingest_totals \"$2\" \"$3\"")
        .arg("--")
        .arg(gate_script())
        .arg(db)
        .arg(manifest)
        .output()
        .expect("spawn bash -c 'source memory_gate.sh; check_ingest_totals ...'")
}

/// R7-2 (#124, control-plane adversarial review of #123, blocker class:
/// false green). The fixture hash is a sorted concatenation of every
/// `*.jsonl` with no path or length framing, so splitting one session file
/// into a scanned half plus an unscanned `z-unscanned/rest.jsonl` keeps the
/// hash identical while the connector ingests only the scanned half -- a
/// smaller workload inheriting a bigger fixture's P0 budget. The two totals
/// the manifest already freezes (message count, content bytes; verified
/// equal to `COUNT(*)` and `SUM(length(CAST(content AS BLOB)))` of a real
/// stage db for all three shapes) are now compared after stage 1.
#[test]
fn ingest_totals_must_match_the_manifest_before_stages_run() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = tmp.path().join("agent_search.db");
    let manifest = tmp.path().join("manifest.json");
    // 2 messages, 3 + 5 = 8 content bytes.
    let sqlite = Command::new("sqlite3")
        .arg(&db)
        .arg("CREATE TABLE messages(id INTEGER PRIMARY KEY, content TEXT); INSERT INTO messages(id, content) VALUES (1, 'abc'), (2, 'defgh');")
        .output()
        .expect("run sqlite3 to build the mini stage db");
    assert!(
        sqlite.status.success(),
        "sqlite3 could not build the mini db: {}",
        String::from_utf8_lossy(&sqlite.stderr)
    );

    // ① control first: an honest manifest passes. Asserted before the two
    // mismatch cases so that the check being *absent* (or unreachable the
    // way the gate's own dispatch makes it) fails here, on the semantic
    // claim, rather than on a message string.
    std::fs::write(&manifest, r#"{"messages": 2, "total_bytes": 8}"#).unwrap();
    let out = run_check_ingest_totals(&db, &manifest);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a db holding exactly what the manifest describes must pass: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ② the reviewer's shape: a manifest claiming more messages than the db
    // actually holds (the unscanned-half rewrite, reduced to its numbers).
    std::fs::write(&manifest, r#"{"messages": 10, "total_bytes": 8}"#).unwrap();
    let out = run_check_ingest_totals(&db, &manifest);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a db holding 2 of the manifest's 10 messages must fail loud, not run the stages: stderr={stderr}"
    );
    assert!(
        stderr.contains("not the ingested workload the fixture manifest describes"),
        "expected the ingest-totals mismatch message, got: {stderr}"
    );

    // ③ the byte total is a separate claim: same message count, different
    // bytes must fail too (a trimmed message body is the same attack with a
    // smaller delta).
    std::fs::write(&manifest, r#"{"messages": 2, "total_bytes": 9}"#).unwrap();
    let out = run_check_ingest_totals(&db, &manifest);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a db holding 8 of the manifest's 9 content bytes must fail loud: stderr={stderr}"
    );
    assert!(
        stderr.contains("8 content byte(s)"),
        "expected the byte total to be named in the mismatch, got: {stderr}"
    );
}

/// Source the gate and call
/// `budget_bytes_for_stage <shape> <stage> <p0.json> <fixture_sha256>`.
fn run_budget_lookup(
    p0: &std::path::Path,
    shape: &str,
    stage: &str,
    fixture_sha256: &str,
) -> std::process::Output {
    Command::new("bash")
        .arg("-c")
        .arg(". \"$1\"; budget_bytes_for_stage \"$2\" \"$3\" \"$4\" \"$5\"")
        .arg("--")
        .arg(gate_script())
        .arg(shape)
        .arg(stage)
        .arg(p0)
        .arg(fixture_sha256)
        .output()
        .expect("spawn bash -c 'source memory_gate.sh; budget_bytes_for_stage ...'")
}

/// R7-8 (#128 T6-a2). The P0 lookup did not read `samples`/`stage_ms` at all,
/// so a hand-filled cell could claim `measured:true` while the two figures
/// the measured rule is derived from contradicted it -- the asymmetry with
/// `--judge` the review named (feeding one of today's cells to `--judge`
/// exits 2 on exactly this rule).
///
/// A cell that carries the pair is now held to that rule. A cell that
/// predates it is not retro-invalidated by its absence: all nine frozen
/// `memgate-baseline.json` cells carry neither key, so requiring presence
/// would make every cell unusable and the door unable to read any budget.
/// That case is reported on stderr instead, so a later re-collection can see
/// which cells went unverified.
#[test]
fn p0_lookup_holds_a_cell_carrying_samples_to_the_judges_measured_rule() {
    let tmp = tempfile::TempDir::new().unwrap();
    let p0 = tmp.path().join("memgate-baseline.json");
    let fixture = "f".repeat(64);
    // One cell, `a`/`index`, with an optional extra key pair appended.
    let cell = |extra: &str| {
        format!(
            r#"{{"a":{{"index":{{"measured":true,"exit_code":0,"peak_tree":1000,"peak_proc":1000,"fixture_sha256":"{fixture}"{extra}}}}}}}"#
        )
    };

    // ① the reproduction: `measured:true` with a single sample. Before the fix
    // the lookup read neither key and handed out a budget from this cell.
    std::fs::write(&p0, cell(r#","samples":1,"stage_ms":100000"#)).unwrap();
    let out = run_budget_lookup(&p0, "a", "index", &fixture);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a cell whose samples contradict its own measured flag must fail loud, not supply a budget: stderr={stderr}"
    );
    assert!(
        stderr.contains("samples>=2 and stage_ms>=200"),
        "expected the measured-consistency message, got: {stderr}"
    );

    // ② the same claim from the duration side, so ① cannot be satisfied by
    // checking only the sample count.
    std::fs::write(&p0, cell(r#","samples":2,"stage_ms":170"#)).unwrap();
    let out = run_budget_lookup(&p0, "a", "index", &fixture);
    assert_eq!(
        out.status.code(),
        Some(2),
        "measured=true with stage_ms=170 must fail loud: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ③ a consistent cell still supplies its budget -- the rule must not
    // reject every hand-filled cell.
    std::fs::write(&p0, cell(r#","samples":2,"stage_ms":200"#)).unwrap();
    let out = run_budget_lookup(&p0, "a", "index", &fixture);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a consistent cell must still yield its budget: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let budget: i64 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("the lookup prints the budget in bytes");
    assert_eq!(
        budget,
        1250 + 256 * 1024 * 1024,
        "budget = 1.25 * max(peak_tree, peak_proc) + 256MiB"
    );

    // ④ the frozen format: neither key present. Readable as before, and the
    // stderr line is what makes that visible to a later re-collection.
    std::fs::write(&p0, cell("")).unwrap();
    let out = run_budget_lookup(&p0, "a", "index", &fixture);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a cell predating these keys must still yield its budget: stderr={stderr}"
    );
    assert!(
        stderr.contains("carries no samples/stage_ms"),
        "the pre-#128 format must be named on stderr, got: {stderr}"
    );

    // ⑤ half a pair is malformed: the two keys are one claim, not two.
    std::fs::write(&p0, cell(r#","samples":2"#)).unwrap();
    let out = run_budget_lookup(&p0, "a", "index", &fixture);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a cell carrying only one of the pair must fail loud: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// B12 (任务书 #131): the stage measurement record is this door's product, so
/// a `tee` that fails (here: the output path is a directory) must fail the
/// run. Pre-fix the pipeline's exit status was never checked and the
/// in-memory JSON went straight to the judge, which -- with a budget the
/// stage easily clears -- returned success: the run reported a good stage
/// while the measurement it exists to produce was never written.
///
/// Driven by sourcing the script (the same convention
/// `run_check_ingest_totals` uses) and calling `run_stage` directly, because
/// the failure has to be provoked at a path the caller names: `--selfcheck`
/// picks its own (pid-stamped) path, and normal mode would need the whole
/// fixture pipeline to get as far as a stage write.
#[test]
fn a_stage_record_that_cannot_be_written_fails_the_run() {
    let tmp = tempfile::TempDir::new().unwrap();
    let unwritable = tmp.path().join("stage.json");
    std::fs::create_dir(&unwritable).expect("pre-create the output path as a directory");

    let output = Command::new("bash")
        .arg("-c")
        // A budget the `sleep 1` stage cannot exceed, so the ONLY thing that
        // can fail this run is the write itself.
        .arg(". \"$1\"; run_stage selfcheck selfcheck 1073741824 \"\" \"\" \"\" \"$2\" sleep 1")
        .arg("--")
        .arg(gate_script())
        .arg(&unwritable)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn bash -c 'source memory_gate.sh; run_stage ...'");

    assert_ne!(
        output.status.code(),
        Some(0),
        "a stage whose measurement could not be written must not report success: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        unwritable.is_dir(),
        "the guard must not have replaced the unwritable path -- nothing was written"
    );
}

// ---------------------------------------------------------------------------
// T6-c N07 (任务书 #131 / T7 勘误): normal mode RECORDS, it does not judge a
// budget. These three tests drive the real four-stage driver against a frozen
// fixture, a stub wrapper that materializes a stage db, and a stub
// completeness gate -- so the driver's own flow (fixture identity check,
// ingest-totals check, four stages, twelve cells) runs for real, with no P0
// baseline anywhere.
// ---------------------------------------------------------------------------

const STUB_BODY: &str = "stage one body\n";

struct NormalRun {
    tmp: tempfile::TempDir,
}

impl NormalRun {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        for dir in ["run", "examples", "w6", "xdg/cass"] {
            std::fs::create_dir_all(tmp.path().join(dir)).expect("create dir");
        }
        let body_bytes = STUB_BODY.len();
        // The frozen fixture: one *.jsonl whose bytes ARE the manifest's
        // `fixture_sha256` (path-sorted concatenation of every *.jsonl).
        let session = tmp.path().join("fixture-session.jsonl");
        std::fs::write(&session, STUB_BODY).expect("write fixture session");
        let digest = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(STUB_BODY.as_bytes());
            h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        std::fs::write(
            tmp.path().join("fixture-manifest.json"),
            format!(
                "{{\"fixture_sha256\": \"{digest}\", \"messages\": 1, \"total_bytes\": {body_bytes}, \"max_message_bytes\": {body_bytes}}}\n"
            ),
        )
        .expect("write manifest");
        std::fs::write(
            tmp.path().join("examples/w4_completeness_gate"),
            "#!/bin/bash\nset -eu\n# The one thing stage 4 must do is leave the --json report behind.\nout=\"\"\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    --json) out=\"$2\"; shift 2 ;;\n    *) shift ;;\n  esac\ndone\n[ -n \"$out\" ] && printf '{\"stub\": true}\\n' > \"$out\"\nexit 0\n",
        )
        .expect("write stub gate");
        std::fs::write(
            tmp.path().join("runner.sh"),
            format!(
                "#!/bin/bash\nset -eu\nmkdir -p \"$CASS_DATA_DIR\"\npython3 - \"$CASS_DATA_DIR/agent_search.db\" <<'PY'\nimport sqlite3, sys\nconn = sqlite3.connect(sys.argv[1])\nconn.executescript(\n    \"CREATE TABLE IF NOT EXISTS conversations(id INTEGER PRIMARY KEY);\"\n    \"CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, content TEXT NOT NULL);\"\n)\nconn.execute(\"DELETE FROM conversations\")\nconn.execute(\"DELETE FROM messages\")\nconn.execute(\"INSERT INTO conversations(id) VALUES (1)\")\nconn.execute(\"INSERT INTO messages(id, content) VALUES (1, ?)\", ({:?},))\nconn.commit()\nconn.close()\nPY\nsleep 0.35\n",
                STUB_BODY
            ),
        )
        .expect("write stub wrapper");
        std::fs::write(tmp.path().join("cass-candidate"), b"not a real binary, only hashed\n").expect("write candidate");
        std::fs::write(tmp.path().join("xdg/cass/sources.toml"), "").expect("write sources.toml");
        Self { tmp }
    }

    fn prepare_shape(&self, shape: &str) {
        let fixture = self.tmp.path().join(format!("run/mem-{shape}-fixture"));
        std::fs::create_dir_all(&fixture).expect("create fixture dir");
        std::fs::copy(self.tmp.path().join("fixture-session.jsonl"), fixture.join("session.jsonl"))
            .expect("copy session");
        std::fs::copy(self.tmp.path().join("fixture-manifest.json"), fixture.join("manifest.json"))
            .expect("copy manifest");
    }

    fn run(&self, shape: &str) -> std::process::Output {
        Command::new("bash")
            .arg(gate_script())
            .arg(shape)
            .arg(self.tmp.path().join("runner.sh"))
            .env("RUN_ROOT", self.tmp.path().join("run"))
            .env("EXAMPLES", self.tmp.path().join("examples"))
            .env("W6", self.tmp.path().join("w6"))
            .env("XDG_CONFIG_HOME", self.tmp.path().join("xdg"))
            .env("CASS_CAND_BIN", self.tmp.path().join("cass-candidate"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn memory_gate.sh")
    }

    fn cells(&self) -> Value {
        let path = self.tmp.path().join("run/memgate-cells.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read the cells matrix {path:?}: {e}"));
        serde_json::from_str(&text).expect("cells matrix must be JSON")
    }
}

/// A stage result read back from disk, so the assertions are about what the
/// door actually wrote.
fn stage_json(run: &NormalRun, shape: &str, stage: &str) -> Value {
    let path = run.tmp.path().join(format!("run/mem-{shape}-stage{stage}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
    serde_json::from_str(&text).expect("stage record must be JSON")
}

const STAGE_FILES: [(&str, &str); 4] = [
    ("index", "1"),
    ("index_force_rebuild", "2"),
    ("index_semantic", "3"),
    ("completeness_gate", "4"),
];

/// N07: with no `memgate-baseline.json` at all, normal mode must still collect
/// all four stages and record them -- pre-fix it exited 2 at
/// `budget_for index` ("P0 baseline file not found") before running anything.
#[test]
fn normal_mode_records_all_four_cells_without_a_p0_baseline() {
    let run = NormalRun::new();
    run.prepare_shape("a");
    let output = run.run("a");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a missing P0 baseline must not fail the record-only door: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    for (stage, file) in STAGE_FILES {
        let cell = stage_json(&run, "a", file);
        assert_eq!(cell["stage"], stage, "stage {file} record must name its stage");
        assert!(
            cell["p0_ratio"].is_null(),
            "with no P0 cell the ratio is recorded as null, not fabricated: {cell:?}"
        );
        // The two fall keys the twelve cells are judged by must survive.
        assert!(cell["last_tree"].is_u64() && cell["peak_tree"].is_u64(), "fall keys: {cell:?}");
        assert!(cell["peak_sample_idx"].is_u64() && cell["samples"].is_u64(), "fall keys: {cell:?}");
    }

    let cells = run.cells();
    assert_eq!(
        cells.as_object().map(|m| m.len()),
        Some(4),
        "one shape's run must record its four cells: {cells:?}"
    );
    for (stage, _) in STAGE_FILES {
        assert!(cells.get(format!("a/{stage}")).is_some(), "cell a/{stage} missing: {cells:?}");
    }
}

/// N07: three shapes x four stages = the door's twelve cells, merged across
/// invocations into one matrix (`$RUN_ROOT/memgate-cells.json`), written by
/// rename so an interrupted run cannot leave a half-written file behind.
#[test]
fn normal_mode_merges_cells_across_shapes() {
    let run = NormalRun::new();
    for shape in ["a", "b"] {
        run.prepare_shape(shape);
        let output = run.run(shape);
        assert_eq!(
            output.status.code(),
            Some(0),
            "shape {shape} must record cleanly: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let cells = run.cells();
    assert_eq!(
        cells.as_object().map(|m| m.len()),
        Some(8),
        "two shapes must leave eight cells in the matrix: {cells:?}"
    );
    for shape in ["a", "b"] {
        for (stage, _) in STAGE_FILES {
            assert!(cells.get(format!("{shape}/{stage}")).is_some(), "cell {shape}/{stage} missing: {cells:?}");
        }
    }
}

/// N07: the door used to `rm -rf` whatever sat at its own output path -- an
/// earlier run's result tree included. It now refuses and writes nothing.
#[test]
fn normal_mode_refuses_to_delete_an_existing_result_tree() {
    let run = NormalRun::new();
    run.prepare_shape("a");
    let stale = run.tmp.path().join("run/mem-a");
    std::fs::create_dir_all(&stale).expect("pre-create the result tree");
    let marker = stale.join("keep-me.txt");
    std::fs::write(&marker, b"an earlier run's result\n").expect("write marker");

    let output = run.run("a");
    assert_eq!(
        output.status.code(),
        Some(2),
        "an existing result tree must be a fail-loud precondition, not something to delete: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(marker.is_file(), "the pre-existing result tree must be left exactly as it was");
    assert_eq!(
        std::fs::read(&marker).expect("read marker"),
        b"an earlier run's result\n",
        "the marker's bytes must be untouched"
    );
    assert!(
        !run.tmp.path().join("run/mem-a-stage1.json").exists(),
        "nothing may be written once the door refused"
    );
}
