//! W2-5 Step 2: parity gate consuming the W2-1 predetermined query set
//! (`tests/fixtures/w2_parity_queries.jsonl`, frozen -- see
//! `W2_ARTIFACTS/w2-lexical-parity-preregistration.md` for the judged
//! thresholds and `W2_ARTIFACTS/w2-tantivy-baseline-run.jsonl` for the
//! frozen Tantivy-side denominator, both under the control-plane artifact
//! root, not this repo).
//!
//! Two tests:
//! - `w2_parity_fixture_matches_frozen_shape`: fast, always runs, guards the
//!   frozen fixture's structure (category counts, required fields) against
//!   accidental edits -- catches "someone touched the fixture" before it
//!   ever reaches the real gate.
//! - `w2_lexical_parity_gate`: `#[ignore]`d (needs a real candidate binary
//!   and the multi-GB w2 staging DB, not a `cargo test --lib`-scale
//!   fixture) -- runs `cass search --mode lexical --json` for all 40
//!   queries against the candidate binary, computes the three frozen
//!   judgment criteria against the frozen Tantivy baseline, and panics with
//!   a full report if any non-HOLD criterion fails. Invoke explicitly:
//!   `CASS_W2_PARITY_BINARY=... CASS_W2_PARITY_DATA_DIR=... \
//!    CASS_W2_PARITY_CONFIG_DIR=... CASS_W2_PARITY_BASELINE=... \
//!    cargo test --test w2_lexical_parity -- --ignored --nocapture`

use serde::Deserialize;
use std::collections::BTreeSet;
use std::process::Command;

const FIXTURE_PATH: &str = "tests/fixtures/w2_parity_queries.jsonl";

#[derive(Debug, Deserialize, Clone)]
struct FixtureQuery {
    query: String,
    category: String,
    anchor_conversation_id: i64,
    anchor_method: String,
    #[serde(default)]
    anchor_source_path: Option<String>,
}

fn load_fixture() -> Vec<FixtureQuery> {
    let text = std::fs::read_to_string(FIXTURE_PATH)
        .unwrap_or_else(|err| panic!("reading frozen fixture {FIXTURE_PATH}: {err}"));
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("parsing fixture line {line:?}: {err}"))
        })
        .collect()
}

/// Guards the frozen W2-1 fixture's shape (category counts + required
/// fields) so accidental edits are caught immediately, independent of the
/// real gate run. Per the preregistration doc's predetermined lower bounds:
/// w1_smoke_carryover>=10, en_stem_variant>=5, zh_3plus_char>=10,
/// zh_2char>=10, title_source_path_unique>=5 -- and this fixture is frozen
/// at exactly those counts (40 total), so exact-equality is the correct
/// assertion here (a *larger* count would also silently violate "frozen").
#[test]
fn w2_parity_fixture_matches_frozen_shape() {
    let rows = load_fixture();
    assert_eq!(rows.len(), 40, "frozen fixture must have exactly 40 rows");

    let mut by_category: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for row in &rows {
        *by_category.entry(row.category.as_str()).or_default() += 1;
        assert!(!row.query.trim().is_empty(), "row must have a non-empty query: {row:?}");
        assert!(row.anchor_conversation_id > 0, "row must have a positive anchor: {row:?}");
        assert!(
            row.anchor_method == "tantivy_rank1_frozen"
                || row.anchor_method == "sql_like_earliest_or_meta_match",
            "row must use one of the two frozen anchor methods: {row:?}"
        );
    }

    let expected: std::collections::BTreeMap<&str, usize> = [
        ("w1_smoke_carryover", 10),
        ("en_stem_variant", 5),
        ("zh_3plus_char", 10),
        ("zh_2char", 10),
        ("title_source_path_unique", 5),
    ]
    .into_iter()
    .collect();
    assert_eq!(by_category, expected, "frozen fixture's category distribution must match the preregistration doc exactly");
}

#[derive(Debug, Deserialize)]
struct SearchHitPath {
    source_path: String,
}

#[derive(Debug, Deserialize)]
struct SearchJsonResponse {
    hits: Vec<SearchHitPath>,
}

/// One frozen baseline row, keyed by `query` (the preregistration doc's
/// `W2_ARTIFACTS/w2-tantivy-baseline-run.jsonl`, produced once during W2-1
/// Step 3 and never rerun -- "供W2-5直接消费比对，不重跑不重算").
#[derive(Debug, Deserialize)]
struct BaselineRow {
    query: String,
    anchor_hit: bool,
    anchor_rank: usize,
    top10_source_paths: Vec<String>,
}

fn load_baseline(path: &str) -> std::collections::HashMap<String, BaselineRow> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("reading frozen tantivy baseline {path}: {err}"));
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let row: BaselineRow = serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("parsing baseline line {line:?}: {err}"));
            (row.query.clone(), row)
        })
        .collect()
}

fn run_fts5_lexical_search(binary: &str, data_dir: &str, config_dir: &str, query: &str) -> Vec<String> {
    let output = Command::new(binary)
        .env("XDG_CONFIG_HOME", config_dir)
        .env("CASS_DATA_DIR", data_dir)
        .args([
            "search",
            query,
            "--mode",
            "lexical",
            "--limit",
            "10",
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
    let response: SearchJsonResponse = serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "parsing candidate JSON for query {query:?}: {err}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    response.hits.into_iter().map(|h| h.source_path).collect()
}

/// W2-5 Step 2: the real parity gate. Judgment criteria and their
/// definitions are frozen in `W2_ARTIFACTS/w2-lexical-parity-preregistration.md`
/// and reproduced here verbatim -- do not adjust thresholds in this file;
/// any adjustment is a control-plane ruling, not an implementation detail.
#[test]
#[ignore = "needs a real candidate binary + the multi-GB w2 staging DB; run explicitly with CASS_W2_PARITY_* env set"]
fn w2_lexical_parity_gate() {
    let binary = std::env::var("CASS_W2_PARITY_BINARY")
        .expect("set CASS_W2_PARITY_BINARY to the candidate cass binary path");
    let data_dir = std::env::var("CASS_W2_PARITY_DATA_DIR")
        .expect("set CASS_W2_PARITY_DATA_DIR to the w2 staging data dir");
    let config_dir = std::env::var("CASS_W2_PARITY_CONFIG_DIR")
        .expect("set CASS_W2_PARITY_CONFIG_DIR to the w2 staging XDG_CONFIG_HOME");
    let baseline_path = std::env::var("CASS_W2_PARITY_BASELINE")
        .expect("set CASS_W2_PARITY_BASELINE to W2_ARTIFACTS/w2-tantivy-baseline-run.jsonl");

    let fixture = load_fixture();
    let baseline = load_baseline(&baseline_path);

    struct QueryResult {
        category: String,
        anchor_source_path: String,
        fts5_paths: Vec<String>,
        fts5_hit: bool,
        fts5_rank: usize,
        tantivy_hit: bool,
        tantivy_rank: usize,
        overlap: Option<f64>,
    }

    let mut results = Vec::with_capacity(fixture.len());
    for row in &fixture {
        let baseline_row = baseline
            .get(&row.query)
            .unwrap_or_else(|| panic!("query {:?} missing from frozen baseline", row.query));
        let anchor_source_path = row
            .anchor_source_path
            .clone()
            .or_else(|| baseline_row.top10_source_paths.first().cloned())
            .unwrap_or_else(|| panic!("query {:?} has no anchor_source_path in fixture or baseline", row.query));

        let fts5_paths = run_fts5_lexical_search(&binary, &data_dir, &config_dir, &row.query);
        let fts5_rank_pos = fts5_paths.iter().position(|p| p == &anchor_source_path);
        let fts5_hit = fts5_rank_pos.is_some();
        let fts5_rank = fts5_rank_pos.map(|i| i + 1).unwrap_or(11);
        let tantivy_rank = if baseline_row.anchor_hit { baseline_row.anchor_rank } else { 11 };

        let fts5_unique: BTreeSet<&str> = fts5_paths.iter().map(String::as_str).collect();
        let tantivy_unique: BTreeSet<&str> =
            baseline_row.top10_source_paths.iter().map(String::as_str).collect();
        let overlap = if tantivy_unique.is_empty() {
            None
        } else {
            let intersection = fts5_unique.intersection(&tantivy_unique).count();
            Some(intersection as f64 / tantivy_unique.len() as f64)
        };

        results.push(QueryResult {
            category: row.category.clone(),
            anchor_source_path,
            fts5_paths,
            fts5_hit,
            fts5_rank,
            tantivy_hit: baseline_row.anchor_hit,
            tantivy_rank,
            overlap,
        });
    }

    // Criterion 1: recall parity, full set and zh_2char subset.
    fn recall_parity(rows: &[&QueryResult]) -> Option<f64> {
        let tantivy_hits = rows.iter().filter(|r| r.tantivy_hit).count();
        if tantivy_hits == 0 {
            return None;
        }
        let fts5_hits = rows.iter().filter(|r| r.fts5_hit).count();
        Some(fts5_hits as f64 / tantivy_hits as f64)
    }
    let all_refs: Vec<&QueryResult> = results.iter().collect();
    let zh2_refs: Vec<&QueryResult> = results.iter().filter(|r| r.category == "zh_2char").collect();
    let recall_all = recall_parity(&all_refs);
    let recall_zh2 = recall_parity(&zh2_refs);

    // Criterion 2: top-10 overlap mean (valid queries = tantivy top-10 non-empty).
    let overlaps: Vec<f64> = results.iter().filter_map(|r| r.overlap).collect();
    let overlap_mean = if overlaps.is_empty() {
        None
    } else {
        Some(overlaps.iter().sum::<f64>() / overlaps.len() as f64)
    };

    // Criterion 3: anchor rank median, fts5 vs tantivy.
    fn median(mut values: Vec<usize>) -> Option<f64> {
        if values.is_empty() {
            return None;
        }
        values.sort_unstable();
        let mid = values.len() / 2;
        Some(if values.len() % 2 == 0 {
            (values[mid - 1] + values[mid]) as f64 / 2.0
        } else {
            values[mid] as f64
        })
    }
    // Validity per the preregistration doc: invalid (HOLD) only when EVERY
    // query's anchor is out-of-bounds on that side (all sentinel 11s), not
    // merely "some are 11".
    let fts5_ranks: Vec<usize> = results.iter().map(|r| r.fts5_rank).collect();
    let tantivy_ranks: Vec<usize> = results.iter().map(|r| r.tantivy_rank).collect();
    let rank_median_valid =
        !(fts5_ranks.iter().all(|&r| r == 11) || tantivy_ranks.iter().all(|&r| r == 11));
    let fts5_median = median(fts5_ranks);
    let tantivy_median = median(tantivy_ranks);

    let mut report = String::new();
    report.push_str("=== W2-5 lexical parity gate report ===\n");
    report.push_str(&format!(
        "criterion 1 (recall parity >= 0.95, zh_2char >= 0.90): all={recall_all:?} zh_2char={recall_zh2:?}\n"
    ));
    report.push_str(&format!("criterion 2 (top-10 overlap mean >= 0.7): {overlap_mean:?} (n={})\n", overlaps.len()));
    report.push_str(&format!(
        "criterion 3 (anchor rank median fts5 <= tantivy + 2): fts5={fts5_median:?} tantivy={tantivy_median:?} valid={rank_median_valid}\n"
    ));
    for r in &results {
        report.push_str(&format!(
            "  [{}] fts5_hit={} fts5_rank={} tantivy_hit={} tantivy_rank={} overlap={:?} anchor={}\n",
            r.category, r.fts5_hit, r.fts5_rank, r.tantivy_hit, r.tantivy_rank, r.overlap, r.anchor_source_path
        ));
        if !r.fts5_hit {
            report.push_str(&format!("    fts5 top10 (miss): {:?}\n", r.fts5_paths));
        }
    }
    println!("{report}");

    let recall_all_pass = recall_all.is_some_and(|v| v >= 0.95);
    let recall_zh2_pass = recall_zh2.is_some_and(|v| v >= 0.90);
    let overlap_pass = overlap_mean.is_some_and(|v| v >= 0.7);
    let rank_pass = rank_median_valid
        && fts5_median.zip(tantivy_median).is_some_and(|(f, t)| f <= t + 2.0);

    let recall_hold = recall_all.is_none() || recall_zh2.is_none();
    let overlap_hold = overlap_mean.is_none();
    let rank_hold = !rank_median_valid;

    if recall_hold || overlap_hold || rank_hold {
        panic!(
            "parity gate HOLD (a denominator was zero -- door invalid, not PASS/FAIL):\n{report}"
        );
    }
    assert!(recall_all_pass, "criterion 1 (full set) FAILED: {recall_all:?} < 0.95\n{report}");
    assert!(recall_zh2_pass, "criterion 1 (zh_2char) FAILED: {recall_zh2:?} < 0.90\n{report}");
    assert!(overlap_pass, "criterion 2 FAILED: {overlap_mean:?} < 0.7\n{report}");
    assert!(rank_pass, "criterion 3 FAILED: fts5 median {fts5_median:?} > tantivy median {tantivy_median:?} + 2\n{report}");
}
