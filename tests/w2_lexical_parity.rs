//! W2-5 Step 2: parity gate consuming the W2-1 predetermined query set
//! (`tests/fixtures/w2_parity_queries.jsonl`, frozen -- see
//! `W2_ARTIFACTS/w2-lexical-parity-preregistration.md` for the judged
//! thresholds, under the control-plane artifact root, not this repo).
//!
//! R1-B5 (exec48): the baseline denominator now defaults to
//! `tests/fixtures/w2-baseline-v3.jsonl`, committed in-repo (see
//! `tests/fixtures/w2-baseline-v3-provenance.md` for what it records and why
//! it is self-referential, not tantivy-comparative, from v3 onward). The
//! older `w2-tantivy-baseline-v2.jsonl` (exec28's tantivy-era denominator)
//! stays archived under the control-plane `W2_ARTIFACTS/` root, not copied
//! into this repo; `CASS_W2_PARITY_BASELINE` still overrides the default if
//! a v2 comparison run is ever needed again.
//!
//! Two tests:
//! - `w2_parity_fixture_matches_frozen_shape`: fast, always runs, guards the
//!   frozen fixture's structure (category counts, required fields) against
//!   accidental edits -- catches "someone touched the fixture" before it
//!   ever reaches the real gate.
//! - `w2_lexical_parity_gate`: a manually-run acceptance gate, `#[ignore]`d
//!   because it needs a real candidate binary and the multi-GB w2 staging DB
//!   (not a `cargo test --lib`-scale fixture) -- runs `cass search --mode
//!   lexical --json` for all 40 queries against the candidate binary,
//!   computes the three frozen judgment criteria against the frozen
//!   baseline, and panics with a full report if any non-HOLD criterion
//!   fails. Its run record and current known result (PASS 1.0/1.0/1.0 on
//!   the v3 self-referential first run) are in
//!   `W2_ARTIFACTS/w2-7-gate-certification.md`, not tracked by CI. Invoke
//!   explicitly:
//!   `CASS_W2_PARITY_BINARY=... CASS_W2_PARITY_DATA_DIR=... \
//!    CASS_W2_PARITY_CONFIG_DIR=... [CASS_W2_PARITY_BASELINE=...] \
//!    cargo test --test w2_lexical_parity -- --ignored --nocapture`

use serde::Deserialize;
use std::collections::BTreeSet;
use std::process::Command;

const FIXTURE_PATH: &str = "tests/fixtures/w2_parity_queries.jsonl";
const DEFAULT_BASELINE_PATH: &str = "tests/fixtures/w2-baseline-v3.jsonl";

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

/// Criterion 1: recall parity. R2-B2 (exec48 round 2): the numerator must be
/// *paired* -- rows where the candidate also hit the exact row the baseline
/// hit -- not the candidate's total hit count taken independently. The
/// unpaired form (`fts5_hits_total / tantivy_hits`) lets unrelated fts5 hits
/// on rows the baseline missed offset real losses on rows the baseline hit,
/// silently masking a regression as a pass (a false-green parity gate).
fn recall_parity(rows: &[&QueryResult]) -> Option<f64> {
    let tantivy_hits = rows.iter().filter(|r| r.tantivy_hit).count();
    if tantivy_hits == 0 {
        return None;
    }
    let paired_hits = rows.iter().filter(|r| r.tantivy_hit && r.fts5_hit).count();
    Some(paired_hits as f64 / tantivy_hits as f64)
}

#[cfg(test)]
mod recall_parity_formula_tests {
    use super::{QueryResult, recall_parity};

    fn row(tantivy_hit: bool, fts5_hit: bool) -> QueryResult {
        QueryResult {
            category: "synthetic".to_string(),
            anchor_source_path: "/synthetic".to_string(),
            fts5_paths: Vec::new(),
            fts5_hit,
            fts5_rank: if fts5_hit { 1 } else { 11 },
            tantivy_hit,
            tantivy_rank: if tantivy_hit { 1 } else { 11 },
            overlap: None,
        }
    }

    /// R2-B2 regression: with the old unpaired formula
    /// (`fts5_hits_total / tantivy_hits`), 6 fts5 hits on rows the baseline
    /// never hit can offset 2 real losses on rows the baseline DID hit,
    /// producing `(32 + 6) / 34 ~= 1.118` -- a false PASS (>= 0.95) even
    /// though the candidate actually lost 2 of the baseline's 34 real
    /// anchors. The paired formula must report the true, lower ratio.
    /// Mutation target: revert `r.tantivy_hit && r.fts5_hit` back to
    /// `r.fts5_hit` alone and this test goes red (ratio flips to >= 1.0).
    #[test]
    fn recall_parity_does_not_let_unrelated_fts5_hits_mask_lost_baseline_anchors() {
        let mut rows: Vec<QueryResult> = Vec::with_capacity(40);
        // 32 rows: baseline hit, candidate also hit (paired, healthy).
        for _ in 0..32 {
            rows.push(row(true, true));
        }
        // 2 rows: baseline hit, candidate missed -- the real losses.
        for _ in 0..2 {
            rows.push(row(true, false));
        }
        // 6 rows: baseline missed, candidate "found" something anyway --
        // unrelated to the 34 real baseline hits, must not offset the losses.
        for _ in 0..6 {
            rows.push(row(false, true));
        }
        assert_eq!(rows.len(), 40);
        assert_eq!(rows.iter().filter(|r| r.tantivy_hit).count(), 34);

        let refs: Vec<&QueryResult> = rows.iter().collect();
        let ratio = recall_parity(&refs).expect("34 baseline hits must yield Some(ratio)");

        assert!(
            ratio < 1.0,
            "paired recall ratio must reflect the 2 real losses (expected ~0.941), got {ratio}"
        );
        assert!(
            ratio < 0.95,
            "2 losses out of 34 baseline hits (32/34 ~= 0.941) must fail the 0.95 criterion-1 \
             threshold, got {ratio}"
        );
        let expected = 32.0 / 34.0;
        assert!(
            (ratio - expected).abs() < 1e-9,
            "expected exactly paired_hits/tantivy_hits = {expected}, got {ratio}"
        );
    }
}

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

/// One frozen baseline row, keyed by `query` (current default denominator is
/// `tests/fixtures/w2-baseline-v3.jsonl` -- see its sibling
/// `w2-baseline-v3-provenance.md` for why v3 onward is self-referential, not
/// a tantivy-comparative baseline. The older `w2-tantivy-baseline-v2.jsonl`,
/// exec28's amendment #2 recast of the original `w2-tantivy-baseline-run.jsonl`
/// produced during W2-1 Step 3, stays archived under the control-plane
/// `W2_ARTIFACTS/` root, reachable via `CASS_W2_PARITY_BASELINE`).
#[derive(Debug, Deserialize)]
struct BaselineRow {
    query: String,
    anchor_hit: bool,
    anchor_rank: usize,
    top10_source_paths: Vec<String>,
}

/// R2-N1 (exec48 round 2): raw parsed rows, duplicates and all -- unlike
/// `load_baseline` below (a `HashMap` keyed by `query`, which silently
/// collapses a duplicate query onto whichever row lost the collision), this
/// is what the non-`#[ignore]`d shape test actually needs to detect a
/// duplicate query landing in the frozen baseline file.
fn load_baseline_rows(path: &str) -> Vec<BaselineRow> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("reading frozen tantivy baseline {path}: {err}"));
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("parsing baseline line {line:?}: {err}"))
        })
        .collect()
}

fn load_baseline(path: &str) -> std::collections::HashMap<String, BaselineRow> {
    load_baseline_rows(path)
        .into_iter()
        .map(|row| (row.query.clone(), row))
        .collect()
}

/// R2-N1 (exec48 round 2): fast, always-runs guard on the frozen v3 baseline
/// file's own shape -- same "catch an accidental edit before it reaches the
/// real gate" role as `w2_parity_fixture_matches_frozen_shape` plays for the
/// query fixture, but for the baseline denominator, which previously had no
/// non-`#[ignore]`d coverage at all.
#[test]
fn w2_baseline_v3_matches_frozen_shape() {
    let rows = load_baseline_rows(DEFAULT_BASELINE_PATH);
    assert_eq!(rows.len(), 40, "frozen v3 baseline must have exactly 40 rows");

    let mut seen_queries = std::collections::HashSet::with_capacity(rows.len());
    for row in &rows {
        assert!(!row.query.trim().is_empty(), "baseline row must have a non-empty query: {row:?}");
        assert!(
            seen_queries.insert(row.query.as_str()),
            "baseline query must be unique, found a duplicate: {:?}",
            row.query
        );
        // anchor fields must actually be present/coherent, not just
        // deserialize to defaults: a hit must carry a plausible rank and at
        // least one top-10 path; a miss's own top10_source_paths (used
        // elsewhere as the criterion-2 overlap denominator) may legitimately
        // be empty, but anchor_rank must still be in-bounds.
        assert!(
            row.anchor_rank >= 1 && row.anchor_rank <= 11,
            "baseline row anchor_rank must be in [1, 11]: {row:?}"
        );
        if row.anchor_hit {
            assert!(
                !row.top10_source_paths.is_empty(),
                "baseline row with anchor_hit=true must carry a non-empty top10_source_paths: {row:?}"
            );
        }
    }
    assert_eq!(seen_queries.len(), 40, "all 40 baseline queries must be unique");
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
        .unwrap_or_else(|_| DEFAULT_BASELINE_PATH.to_string());

    let fixture = load_fixture();
    let baseline = load_baseline(&baseline_path);

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
