//! PR3 P08b — real-CLI contracts for the `cass search` window flags.
//!
//! `cass search` replaces the removed `--limit` with `--rrf-limit N` (candidate
//! window) and `--rerank-limit K` / `--rerank-provider P` (rerank controls).
//! These tests drive the real candidate binary and assert on exit codes and
//! output, never on a clap-only helper. Every invocation runs with an isolated
//! `HOME` / `XDG_CONFIG_HOME` / `CASS_DATA_DIR` in a temp dir, and the window
//! environment variables are scrubbed per process, so the tests are safe under
//! the default parallel test harness.
//!
//! Argument errors must be *argument* errors (exit 2, usage semantics). A
//! missing database in the empty temp data dir only ever appears as a later
//! exit code; it is never accepted as evidence for a usage boundary.

use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

/// An isolated process environment: private HOME, XDG config dir, and data dir.
struct Env {
    _tmp: TempDir,
    home: PathBuf,
    xdg: PathBuf,
    data_dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        let tmp = TempDir::new().expect("temp dir");
        let home = tmp.path().join("home");
        let xdg = tmp.path().join("xdg");
        let data_dir = tmp.path().join("data");
        for dir in [&home, &xdg, &data_dir] {
            std::fs::create_dir_all(dir).expect("create env dir");
        }
        Env {
            _tmp: tmp,
            home,
            xdg,
            data_dir,
        }
    }

    /// Write `~/.config/cass/cass.toml` (XDG-resolved) with the given body.
    fn write_config(&self, body: &str) {
        let dir = self.xdg.join("cass");
        std::fs::create_dir_all(&dir).expect("create config dir");
        std::fs::write(dir.join("cass.toml"), body).expect("write config");
    }
}

/// Build a `cass` command with the isolated environment and a clean window env.
fn cass(env: &Env) -> Command {
    let mut cmd = Command::cargo_bin("cass").expect("cass binary");
    cmd.env("HOME", &env.home)
        .env("XDG_CONFIG_HOME", &env.xdg)
        .env("CASS_DATA_DIR", &env.data_dir)
        .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .env_remove("CASS_RRF_LIMIT")
        .env_remove("CASS_RERANK_LIMIT")
        .env_remove("CASS_SEARCH_LIMIT")
        .env_remove("CASS_SEARCH_MODE")
        .env_remove("CASS_SEARCH_TIMEOUT_MS")
        .env_remove("CASS_SEARCH_TIMEOUT")
        .env_remove("CASS_OUTPUT_FORMAT");
    cmd
}

fn run(env: &Env, args: &[&str]) -> Output {
    cass(env)
        .args(["--color=never"])
        .args(args)
        .output()
        .expect("run cass")
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("cass must exit normally, not by signal")
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_usage_error(env: &Env, args: &[&str]) {
    let out = run(env, args);
    assert_eq!(
        code(&out),
        2,
        "expected usage error (exit 2) for {args:?}; got {}\n{}",
        code(&out),
        combined(&out)
    );
}

fn assert_not_usage_error(env: &Env, args: &[&str]) -> Output {
    let out = run(env, args);
    assert_ne!(
        code(&out),
        2,
        "expected {args:?} to get past argument validation; got usage error\n{}",
        combined(&out)
    );
    out
}

fn help_text(env: &Env, args: &[&str]) -> String {
    let out = run(env, args);
    assert_eq!(code(&out), 0, "help must exit 0 for {args:?}: {}", combined(&out));
    combined(&out)
}

fn capabilities(env: &Env) -> Value {
    let out = run(env, &["capabilities", "--json"]);
    assert_eq!(code(&out), 0, "capabilities --json must exit 0: {}", combined(&out));
    serde_json::from_slice(&out.stdout).expect("capabilities JSON")
}

fn command_argument_names(caps: &Value, command: &str) -> Vec<String> {
    caps["commands"]
        .as_array()
        .expect("commands array")
        .iter()
        .find(|c| c["name"] == command)
        .unwrap_or_else(|| panic!("command {command} present in capabilities"))["arguments"]
        .as_array()
        .expect("arguments array")
        .iter()
        .map(|a| a["name"].as_str().unwrap_or_default().to_string())
        .collect()
}

// --------------------------------------------------------------------------
// Real --help
// --------------------------------------------------------------------------

#[test]
fn search_help_lists_new_flags_and_provider_values() {
    let env = Env::new();
    let help = help_text(&env, &["search", "--help"]);

    assert!(help.contains("--rrf-limit"), "help missing --rrf-limit:\n{help}");
    assert!(help.contains("--rerank-limit"), "help missing --rerank-limit:\n{help}");
    assert!(help.contains("--rerank-provider"), "help missing --rerank-provider:\n{help}");
    for provider in [
        "qwen3-local",
        "bge-local",
        "openrouter-qwen3-8b",
        "openrouter-cohere-4-fast",
        "openrouter-voyage-2.5-lite",
    ] {
        assert!(help.contains(provider), "help missing provider {provider}:\n{help}");
    }

    // The legacy search count flags must not be listed as usable flags: no help
    // line starts with an indented `--limit`/`--max-results` flag entry.
    for legacy in ["--limit", "--max-results", "--top-k", "--n"] {
        let listed = help.lines().any(|line| {
            let trimmed = line.trim_start();
            let indented = line.len() != trimmed.len();
            indented
                && (trimmed.starts_with(&format!("{legacy} "))
                    || trimmed.starts_with(&format!("{legacy}="))
                    || trimmed == legacy)
        });
        assert!(!listed, "legacy flag {legacy} is still listed in search --help:\n{help}");
    }
}

#[test]
fn other_commands_still_help_their_legacy_limit() {
    let env = Env::new();
    let pack_help = help_text(&env, &["pack", "--help"]);
    assert!(pack_help.contains("--limit"), "pack must keep --limit:\n{pack_help}");

    let sessions_help = help_text(&env, &["sessions", "--help"]);
    assert!(sessions_help.contains("--limit"), "sessions must keep --limit:\n{sessions_help}");
}

// --------------------------------------------------------------------------
// Legacy result-count migration
// --------------------------------------------------------------------------

#[test]
fn legacy_search_limit_spellings_migrate_with_hint() {
    let env = Env::new();
    let cases: &[&[&str]] = &[
        &["search", "q", "--limit", "5"],
        &["search", "q", "--limit=5"],
        &["search", "q", "-limit", "5"],
        &["search", "q", "--LIMIT", "5"],
        &["search", "q", "--max-results", "5"],
        &["search", "q", "--max_results", "5"],
        &["search", "q", "--num-results", "5"],
        &["search", "q", "--results", "5"],
        &["search", "q", "--count", "5"],
        &["search", "q", "--top-k", "5"],
        &["search", "q", "--topk", "5"],
        &["search", "q", "--top_k", "5"],
        &["search", "q", "--n", "5"],
        &["search", "q", "-n", "5"],
        &["search", "q", "limit=5"],
        &["search", "q", "max_results=5"],
        &["search", "q", "limit", "5"],
        &["search", "q", "n", "5"],
    ];

    for args in cases {
        let out = run(&env, args);
        assert_eq!(code(&out), 2, "expected usage error for {args:?}:\n{}", combined(&out));
        let text = combined(&out);
        assert!(
            text.contains("rrf-limit"),
            "migration hint missing for {args:?}:\n{text}"
        );
    }
}

#[test]
fn query_after_double_dash_is_not_a_limit_error() {
    let env = Env::new();
    // `-- --limit` makes `--limit` the query literal, not a legacy flag. It must
    // get past argument validation (and then fail on the empty data dir, not 2).
    assert_not_usage_error(&env, &["search", "--json", "--", "--limit"]);
    // A value that reads like a limit flag is also not scanned.
    assert_not_usage_error(&env, &["search", "q", "--json", "--since", "--limit"]);
}

// --------------------------------------------------------------------------
// New-flag usage boundaries (all before DB open)
// --------------------------------------------------------------------------

#[test]
fn invalid_window_arguments_are_usage_errors() {
    let env = Env::new();
    let cases: &[&[&str]] = &[
        // explicit zero
        &["search", "q", "--rrf-limit", "0"],
        // K without rerank
        &["search", "q", "--rerank-limit", "3"],
        // provider without rerank
        &["search", "q", "--rerank-provider", "bge-local"],
        // K > N
        &["search", "q", "--rerank", "--rrf-limit", "10", "--rerank-limit", "11"],
        // N < 5 with K omitted (default K=5) while rerank is on
        &["search", "q", "--rerank", "--rrf-limit", "3"],
        // unknown provider value
        &["search", "q", "--rerank", "--rerank-provider", "nope"],
        // reranker + provider conflict
        &[
            "search",
            "q",
            "--rerank",
            "--reranker",
            "bge",
            "--rerank-provider",
            "bge-local",
        ],
        // N+1 overflow
        &["search", "q", "--rerank", "--rrf-limit", "18446744073709551615"],
    ];
    for args in cases {
        assert_usage_error(&env, args);
    }
}

#[test]
fn valid_window_arguments_get_past_validation() {
    let env = Env::new();
    assert_not_usage_error(&env, &["search", "q", "--json", "--rrf-limit", "30"]);
    assert_not_usage_error(
        &env,
        &[
            "search",
            "q",
            "--json",
            "--rerank",
            "--rrf-limit",
            "30",
            "--rerank-limit",
            "5",
            "--rerank-provider",
            "bge-local",
        ],
    );
}

// --------------------------------------------------------------------------
// Other commands keep their legacy limit
// --------------------------------------------------------------------------

#[test]
fn other_commands_keep_legacy_limit_accepted() {
    let env = Env::new();
    assert_not_usage_error(&env, &["pack", "q", "--limit", "0", "--json"]);
    assert_not_usage_error(&env, &["pack", "q", "--max-results", "5", "--json"]);
    assert_not_usage_error(&env, &["sessions", "--limit", "5", "--json"]);
    assert_not_usage_error(&env, &["analytics", "tools", "--limit", "5", "--json"]);
}

// --------------------------------------------------------------------------
// Env / config migration + precedence
// --------------------------------------------------------------------------

#[test]
fn legacy_env_limit_rejects_search_but_pack_accepts() {
    let env = Env::new();

    let search_out = cass(&env)
        .env("CASS_SEARCH_LIMIT", "10")
        .args(["--color=never", "search", "q", "--json"])
        .output()
        .expect("run cass");
    assert_eq!(code(&search_out), 2, "search must reject CASS_SEARCH_LIMIT: {}", combined(&search_out));
    assert!(combined(&search_out).contains("rrf-limit"), "missing hint: {}", combined(&search_out));

    let pack_out = cass(&env)
        .env("CASS_SEARCH_LIMIT", "10")
        .args(["--color=never", "pack", "q", "--json"])
        .output()
        .expect("run cass");
    assert_ne!(code(&pack_out), 2, "pack must still accept CASS_SEARCH_LIMIT: {}", combined(&pack_out));
}

#[test]
fn legacy_config_limit_rejects_search_but_pack_accepts() {
    let env = Env::new();
    env.write_config("[search]\nlimit = 7\n");

    let search_out = run(&env, &["search", "q", "--json"]);
    assert_eq!(code(&search_out), 2, "search must reject [search].limit: {}", combined(&search_out));
    assert!(combined(&search_out).contains("rrf-limit"), "missing hint: {}", combined(&search_out));

    let pack_out = run(&env, &["pack", "q", "--json"]);
    assert_ne!(code(&pack_out), 2, "pack must still accept [search].limit: {}", combined(&pack_out));
}

#[test]
fn window_precedence_cli_over_env_over_config() {
    // Observed at the K<=N boundary while reranking is on: N>=5 proceeds past
    // argument validation (and later fails on the empty data dir), N<5 with K
    // omitted is a usage error.

    // config only: N=3 -> usage error.
    let env = Env::new();
    env.write_config("[search]\nrrf_limit = 3\n");
    assert_usage_error(&env, &["search", "q", "--json", "--rerank"]);

    // env over config: N=30 -> past validation.
    let env = Env::new();
    env.write_config("[search]\nrrf_limit = 3\n");
    let out = cass(&env)
        .env("CASS_RRF_LIMIT", "30")
        .args(["--color=never", "search", "q", "--json", "--rerank"])
        .output()
        .expect("run cass");
    assert_ne!(code(&out), 2, "env must override config: {}", combined(&out));

    // CLI over env: N=30 from CLI -> past validation even though env says 3.
    let env = Env::new();
    let out = cass(&env)
        .env("CASS_RRF_LIMIT", "3")
        .args([
            "--color=never",
            "search",
            "q",
            "--json",
            "--rerank",
            "--rrf-limit",
            "30",
        ])
        .output()
        .expect("run cass");
    assert_ne!(code(&out), 2, "CLI must override env: {}", combined(&out));
}

// --------------------------------------------------------------------------
// Machine discovery
// --------------------------------------------------------------------------

#[test]
fn capabilities_search_arguments_are_the_new_flags() {
    let env = Env::new();
    let caps = capabilities(&env);

    let search = command_argument_names(&caps, "search");
    assert!(search.iter().any(|a| a == "rrf-limit"), "search args: {search:?}");
    assert!(search.iter().any(|a| a == "rerank-limit"), "search args: {search:?}");
    assert!(search.iter().any(|a| a == "rerank-provider"), "search args: {search:?}");
    assert!(
        !search.iter().any(|a| a == "limit"),
        "search must not advertise the legacy limit arg: {search:?}"
    );

    let pack = command_argument_names(&caps, "pack");
    assert!(pack.iter().any(|a| a == "limit"), "pack must still advertise limit: {pack:?}");
}

#[test]
fn robot_docs_commands_show_new_search_flags_and_pack_limit() {
    let env = Env::new();
    let out = run(&env, &["robot-docs", "commands"]);
    assert_eq!(code(&out), 0, "robot-docs commands must exit 0: {}", combined(&out));
    let text = combined(&out);

    assert!(text.contains("--rrf-limit"), "missing --rrf-limit:\n{text}");
    assert!(text.contains("--rerank-limit"), "missing --rerank-limit:\n{text}");
    assert!(text.contains("--rerank-provider"), "missing --rerank-provider:\n{text}");
    // pack and sessions keep their legacy limit.
    assert!(text.contains("[--limit N]"), "pack/sessions legacy limit missing:\n{text}");

    // No line advertises `cass search ... --limit`.
    for line in text.lines() {
        if line.contains("cass search") {
            assert!(
                !line.contains("--limit"),
                "search line still advertises --limit: {line}"
            );
        }
    }
}

#[test]
fn robot_docs_env_lists_window_variables() {
    let env = Env::new();
    let out = run(&env, &["robot-docs", "env"]);
    assert_eq!(code(&out), 0, "robot-docs env must exit 0: {}", combined(&out));
    let text = combined(&out);

    assert!(text.contains("CASS_RRF_LIMIT"), "missing CASS_RRF_LIMIT:\n{text}");
    assert!(text.contains("CASS_RERANK_LIMIT"), "missing CASS_RERANK_LIMIT:\n{text}");
    assert!(text.contains("CASS_SEARCH_LIMIT"), "missing CASS_SEARCH_LIMIT:\n{text}");
}

#[test]
fn robot_docs_examples_do_not_teach_search_limit() {
    let env = Env::new();
    let out = run(&env, &["robot-docs", "examples"]);
    assert_eq!(code(&out), 0, "robot-docs examples must exit 0: {}", combined(&out));
    let text = combined(&out);

    for line in text.lines() {
        if line.contains("cass search") {
            assert!(
                !line.contains("--limit"),
                "example still teaches `cass search ... --limit`: {line}"
            );
        }
    }
}

#[test]
fn capabilities_workflow_and_mistake_recovery_are_consistent() {
    let env = Env::new();
    let caps = capabilities(&env);

    let workflows = caps["workflows"].as_array().expect("workflows");
    let bounded = workflows
        .iter()
        .find(|w| w["name"] == "bounded-search")
        .expect("bounded-search workflow");
    let first = bounded["first_command"].as_str().unwrap_or_default();
    assert!(first.contains("--rrf-limit"), "bounded-search first_command: {first}");
    assert!(!first.contains("--limit "), "bounded-search still teaches --limit: {first}");

    let recoveries = caps["mistake_recoveries"].as_array().expect("mistake_recoveries");
    // Every search result-count alias is now an explicit rejection.
    let has_rejected_alias = recoveries.iter().any(|r| {
        r["canonical"]
            .as_str()
            .is_some_and(|c| c.contains("search") && c.contains("--rrf-limit"))
            && r["accepted"] == Value::Bool(false)
    });
    assert!(has_rejected_alias, "no rejected search count-alias recovery recorded");
}

/// Sanity: the isolated env helper really points at an empty data dir.
#[test]
fn isolated_data_dir_is_empty() {
    let env = Env::new();
    let entries = std::fs::read_dir(&env.data_dir)
        .expect("data dir readable")
        .count();
    assert_eq!(entries, 0);
    assert!(Path::new(&env.home).is_dir());
}
