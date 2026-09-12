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
