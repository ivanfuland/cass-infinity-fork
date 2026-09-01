//! W2-7 判例线②: judgment 门 (`tests/fixtures/w2_judgment_cases.jsonl`,
//! see `W2_ARTIFACTS/w2-6-closeout.md` §六 for provenance and
//! `docs/projects/cass-fork/specs/2026-09-01-w2-dumping-suppression-design.md`
//! §五 判据1 for the door's definition, both under the control-plane
//! artifact root, not this repo).
//!
//! Ivan已裁定 5 条判例（indexing/indexer/connectors/duplicate/触发器，全案
//! A>B）固化为配对断言：`rank(A) < rank(B)` in the live lexical ranking --
//! **not** "A must be in top-10" (that's the separate parity gate's
//! criterion). A pair can both sit outside the top-10 and still PASS this
//! door, per advisor's 2026-09-01 clarification: pairwise preference is
//! decoupled from window position.
//!
//! Two tests:
//! - `w2_judgment_fixture_matches_frozen_shape`: fast, always runs, guards
//!   the fixture's structure against accidental edits.
//! - `w2_judgment_cases_gate`: `#[ignore]`d (needs a real candidate binary +
//!   the multi-GB w2 staging DB). Runs each case at a high `--limit` (ranks
//!   in this corpus have been observed in the hundreds, not just within
//!   top-10 -- see the exec46 Task乙 report) and reports rank(A)/rank(B)
//!   per case; does not force a PASS/FAIL judgment by fiat -- each case's
//!   outcome is asserted mechanically and a failing case's reasoning
//!   belongs in the control-plane report, not a doctored threshold here.
//!   Invoke explicitly:
//!   `CASS_W2_JUDGMENT_BINARY=... CASS_W2_JUDGMENT_DATA_DIR=... \
//!    CASS_W2_JUDGMENT_CONFIG_DIR=... \
//!    cargo test --test w2_judgment_cases -- --ignored --nocapture`

use serde::Deserialize;
use std::process::Command;

const FIXTURE_PATH: &str = "tests/fixtures/w2_judgment_cases.jsonl";
/// High enough to find both sides of a pair even when one has drifted deep
/// into the ranking (exec46 Task乙 observed ranks up to ~1300 in the
/// current, corpus-grown staging DB) -- the door is about relative order,
/// not top-10 membership, so the search limit must not silently truncate
/// the losing side out of view.
const JUDGMENT_SEARCH_LIMIT: usize = 5000;

#[derive(Debug, Deserialize, Clone)]
struct JudgmentCase {
    case: String,
    query: String,
    #[serde(default)]
    #[allow(dead_code)]
    category: String,
    #[serde(default)]
    #[allow(dead_code)]
    a_conversation_id: i64,
    a_source_path: String,
    #[serde(default)]
    #[allow(dead_code)]
    b_conversation_id: i64,
    b_source_path: String,
    ruling: String,
    #[serde(default)]
    #[allow(dead_code)]
    provenance: String,
}

fn load_fixture() -> Vec<JudgmentCase> {
    let text = std::fs::read_to_string(FIXTURE_PATH)
        .unwrap_or_else(|err| panic!("reading judgment fixture {FIXTURE_PATH}: {err}"));
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("parsing judgment fixture line {line:?}: {err}"))
        })
        .collect()
}

#[test]
fn w2_judgment_fixture_matches_frozen_shape() {
    let rows = load_fixture();
    assert_eq!(rows.len(), 5, "judgment fixture must have exactly the 5 Ivan-ruled cases");
    let expected_cases = ["indexing", "indexer", "connectors", "duplicate", "触发器"];
    let actual_cases: Vec<&str> = rows.iter().map(|r| r.case.as_str()).collect();
    assert_eq!(actual_cases, expected_cases, "judgment fixture case set/order must match the frozen 5");
    for row in &rows {
        assert_eq!(row.ruling, "A>B", "every row is an Ivan-ruled A>B preference: {row:?}");
        assert!(!row.a_source_path.is_empty() && !row.b_source_path.is_empty(), "row must have both source_paths: {row:?}");
        assert_ne!(row.a_source_path, row.b_source_path, "A and B must be distinct documents: {row:?}");
    }
}

#[derive(Debug, Deserialize)]
struct SearchHitPath {
    source_path: String,
}

#[derive(Debug, Deserialize)]
struct SearchJsonResponse {
    hits: Vec<SearchHitPath>,
    total_matches: usize,
}

fn run_lexical_search(binary: &str, data_dir: &str, config_dir: &str, query: &str) -> SearchJsonResponse {
    let output = Command::new(binary)
        .env("XDG_CONFIG_HOME", config_dir)
        .env("CASS_DATA_DIR", data_dir)
        .args([
            "search",
            query,
            "--mode",
            "lexical",
            "--limit",
            &JUDGMENT_SEARCH_LIMIT.to_string(),
            "--json",
            "--fields",
            "source_path",
        ])
        .output()
        .unwrap_or_else(|err| panic!("spawning candidate binary for query {query:?}: {err}"));
    assert!(
        output.status.success(),
        "candidate binary exited non-zero for query {query:?}: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "parsing candidate JSON for query {query:?}: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn rank_of(paths: &[String], target: &str) -> Option<usize> {
    paths.iter().position(|p| p == target).map(|i| i + 1)
}

/// W2-7 判例线②: the real judgment gate. `rank(A) < rank(B)` where both
/// ranks come from the *same* high-limit search response (`None` when a
/// side didn't appear within [`JUDGMENT_SEARCH_LIMIT`] at all -- treated as
/// "worse than any found rank", so an absent B with a present A still
/// PASSes, and an absent A always MISSes since a preference for something
/// that isn't even in the candidate set can't be asserted).
#[test]
#[ignore = "needs a real candidate binary + the multi-GB w2 staging DB; run explicitly with CASS_W2_JUDGMENT_* env set"]
fn w2_judgment_cases_gate() {
    let binary = std::env::var("CASS_W2_JUDGMENT_BINARY")
        .expect("set CASS_W2_JUDGMENT_BINARY to the candidate cass binary path");
    let data_dir = std::env::var("CASS_W2_JUDGMENT_DATA_DIR")
        .expect("set CASS_W2_JUDGMENT_DATA_DIR to the w2 staging data dir");
    let config_dir = std::env::var("CASS_W2_JUDGMENT_CONFIG_DIR")
        .expect("set CASS_W2_JUDGMENT_CONFIG_DIR to the w2 staging XDG_CONFIG_HOME");

    let fixture = load_fixture();

    struct CaseResult {
        case: String,
        query: String,
        total_matches: usize,
        rank_a: Option<usize>,
        rank_b: Option<usize>,
        pass: bool,
    }

    let mut results = Vec::with_capacity(fixture.len());
    for row in &fixture {
        let response = run_lexical_search(&binary, &data_dir, &config_dir, &row.query);
        let paths: Vec<String> = response.hits.into_iter().map(|h| h.source_path).collect();
        let rank_a = rank_of(&paths, &row.a_source_path);
        let rank_b = rank_of(&paths, &row.b_source_path);
        let pass = match (rank_a, rank_b) {
            (Some(a), Some(b)) => a < b,
            (Some(_), None) => true,
            _ => false,
        };
        results.push(CaseResult {
            case: row.case.clone(),
            query: row.query.clone(),
            total_matches: response.total_matches,
            rank_a,
            rank_b,
            pass,
        });
    }

    let mut report = String::new();
    report.push_str("=== W2-7 judgment cases gate report ===\n");
    for r in &results {
        report.push_str(&format!(
            "  [{}] query={:?} total_matches={} rank(A)={:?} rank(B)={:?} -> {}\n",
            r.case,
            r.query,
            r.total_matches,
            r.rank_a,
            r.rank_b,
            if r.pass { "PASS" } else { "MISS" }
        ));
    }
    let pass_count = results.iter().filter(|r| r.pass).count();
    report.push_str(&format!("{pass_count}/{} PASS\n", results.len()));
    println!("{report}");

    let failing: Vec<&str> = results.iter().filter(|r| !r.pass).map(|r| r.case.as_str()).collect();
    assert!(
        failing.is_empty(),
        "judgment door: {}/{} cases MISS ({}) -- see report above for rank(A)/rank(B); \
         per-case disposition is a control-plane ruling, not something this test decides:\n{report}",
        failing.len(),
        results.len(),
        failing.join(", "),
    );
}
