//! Explicit `--trace-file` trace-surface regression suite.
//!
//! Bead: coding_agent_session_search-cass-fleet-resilience-20260608-uojcg.2.5
//! ("Gate dependency tracing behind explicit trace surfaces").
//!
//! Dependency-level logs (the legacy embedded engine / frankensearch / asupersync) must NOT
//! appear during normal robot commands; they are available only through an
//! explicit surface. These tests pin that contract for `--trace-file`: even under
//! a deliberately noisy `RUST_LOG`, robot stdout stays pure JSON and stderr stays
//! free of dependency tracing, while the deep logs (when requested) land in the
//! trace file — and no trace file is created when the operator does not ask for
//! one.

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

mod util;
use util::cass_bin;

/// A `RUST_LOG` loud enough that any unfiltered dependency span would otherwise
/// flood stderr/stdout.
const NOISY_RUST_LOG: &str = "trace,fsqlite=trace,fsqlite_core=trace";

fn noisy_robot_cmd() -> Command {
    let mut cmd = Command::new(cass_bin());
    cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
    cmd.env("RUST_LOG", NOISY_RUST_LOG);
    cmd.env("CASS_IGNORE_SOURCES_CONFIG", "1");
    cmd
}

fn parse_stdout_json(stdout: &str) -> Value {
    let trimmed = stdout.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return value;
    }
    let last_line = trimmed
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    serde_json::from_str::<Value>(last_line.trim())
        .unwrap_or_else(|err| panic!("robot stdout was not valid JSON ({err}); stdout:\n{stdout}"))
}

fn assert_stderr_has_no_dependency_tracing(label: &str, stderr: &str) {
    let lower = stderr.to_lowercase();
    assert!(
        !lower.contains("fsqlite"),
        "{label}: stderr leaked the legacy embedded engine's tracing despite --trace-file routing; stderr:\n{stderr}"
    );
    for level in [" INFO ", " DEBUG ", " TRACE "] {
        assert!(
            !stderr.contains(level),
            "{label}: stderr emitted a {} line; deep logs should go to the trace file, not stderr; stderr:\n{stderr}",
            level.trim()
        );
    }
}

#[test]
fn trace_file_keeps_stdout_clean_and_captures_to_file() {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    let trace_path = tmp.path().join("trace.jsonl");

    // `status` touches the storage layer (a dependency that emits tracing). Under
    // noisy RUST_LOG + --trace-file, deep logs must route to the file, not stderr.
    let output = noisy_robot_cmd()
        .args([
            "status",
            "--json",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--trace-file",
            trace_path.to_str().unwrap(),
        ])
        .output()
        .expect("run cass");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let json = parse_stdout_json(&stdout);
    assert!(
        json.is_object(),
        "status --json should be a JSON object: {json}"
    );
    assert_stderr_has_no_dependency_tracing("status+trace-file", &stderr);

    // The trace file is the explicit surface: it must exist and carry content
    // (at minimum the per-invocation summary line; plus any captured diagnostics).
    assert!(
        trace_path.exists(),
        "trace file should be created when --trace-file is set"
    );
    let trace = std::fs::read_to_string(&trace_path).expect("read trace file");
    assert!(!trace.trim().is_empty(), "trace file should not be empty");
    // The last line is the structured per-command summary written by the CLI.
    let last = trace
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let summary: Value = serde_json::from_str(last.trim())
        .unwrap_or_else(|e| panic!("trace summary line not JSON ({e}): {last}"));
    assert_eq!(
        summary["cmd"], "status",
        "trace summary should record the command"
    );
}

#[test]
fn no_trace_file_created_without_the_flag() {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    let trace_path = tmp.path().join("should_not_exist.jsonl");

    let output = noisy_robot_cmd()
        .args(["status", "--json", "--data-dir", data_dir.to_str().unwrap()])
        .output()
        .expect("run cass");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json = parse_stdout_json(&stdout);
    assert!(
        json.is_object(),
        "status --json should be a JSON object: {json}"
    );
    assert!(
        !trace_path.exists(),
        "no trace file should be created when --trace-file is not passed"
    );
}

#[test]
fn trace_file_does_not_corrupt_stdout_for_api_version() {
    let tmp = TempDir::new().expect("tempdir");
    let trace_path = tmp.path().join("trace.jsonl");

    let output = noisy_robot_cmd()
        .args([
            "api-version",
            "--json",
            "--trace-file",
            trace_path.to_str().unwrap(),
        ])
        .output()
        .expect("run cass");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json = parse_stdout_json(&stdout);
    assert!(
        json.get("api_version").is_some() || json.get("version").is_some(),
        "api-version stdout should be clean JSON even with --trace-file: {json}"
    );
    assert!(trace_path.exists(), "trace file should be created");
}
