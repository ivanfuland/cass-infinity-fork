//! T10 (plan v5.1): `w4_parity40` -- the W2-5 lexical parity gate
//! (`tests/w2_lexical_parity.rs`'s `recall_parity`/top-10-overlap judgment
//! logic) extracted into a reusable, parameterized example: file paths for
//! the query set and baseline (instead of the hardcoded frozen fixtures)
//! and thresholds via `--min-recall`/`--min-overlap` (instead of the
//! hardcoded 0.95/0.7 constants) -- so a future run against a different
//! query set or a different acceptance bar doesn't require editing test
//! source. The two file schemas are unchanged from that test file (so the
//! real frozen fixtures, `tests/fixtures/w2_parity_queries.jsonl` and
//! `tests/fixtures/w2-baseline-v3.jsonl`, work verbatim as `--queries`/
//! `--baseline` inputs) and the recall formula is the same *paired*-hit
//! ratio that test's R2-B2 fix established (paired_hits / baseline_hits,
//! not an independent candidate-hit-count over baseline-hit-count, which
//! lets unrelated candidate hits mask real losses).
//!
//! Usage: `CASS_W2_PARITY_BINARY=... CASS_W2_PARITY_DATA_DIR=...
//! CASS_W2_PARITY_CONFIG_DIR=... cargo run --release
//! --no-default-features --features qr,encryption,infinity --example
//! w4_parity40 -- --queries <jsonl> --baseline <jsonl> --min-recall 0.95
//! --min-overlap 0.7 --json <out>`. Exit codes: 0 both criteria met; 1
//! either criterion missed (or a HOLD-worthy zero denominator, folded into
//! "not met" here since this generic tool doesn't distinguish); 2
//! precondition error (env vars unset, files missing/unparseable, or a
//! query has no matching baseline row).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(name = "w4_parity40")]
struct Cli {
    #[arg(long)]
    queries: PathBuf,
    #[arg(long)]
    baseline: PathBuf,
    #[arg(long)]
    min_recall: f64,
    #[arg(long)]
    min_overlap: f64,
    #[arg(long)]
    json: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
struct FixtureQuery {
    query: String,
    category: String,
    #[serde(default)]
    anchor_source_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct BaselineRow {
    query: String,
    anchor_hit: bool,
    anchor_rank: usize,
    top10_source_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SearchHitPath {
    source_path: String,
}

#[derive(Debug, Deserialize)]
struct SearchJsonResponse {
    hits: Vec<SearchHitPath>,
}

#[derive(Debug, Serialize, Clone)]
struct PerQuery {
    query: String,
    category: String,
    candidate_hit: bool,
    candidate_rank: usize,
    baseline_hit: bool,
    baseline_rank: usize,
    overlap: Option<f64>,
}

#[derive(Debug, Serialize, Clone)]
struct Parity40Report {
    recall_at_10: Option<f64>,
    overlap: Option<f64>,
    per_query: Vec<PerQuery>,
    passed: bool,
}

fn load_jsonl<T: for<'de> Deserialize<'de>>(path: &std::path::Path) -> anyhow::Result<Vec<T>> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| anyhow::anyhow!("parsing {}: {e}: line={l:?}", path.display())))
        .collect()
}

/// Trait object so tests can substitute a fake search backend instead of
/// spawning a real subprocess binary.
trait LexicalSearch {
    fn top10_source_paths(&self, query: &str) -> anyhow::Result<Vec<String>>;
}

struct SubprocessSearch {
    binary: String,
    data_dir: String,
    config_dir: String,
}

impl LexicalSearch for SubprocessSearch {
    fn top10_source_paths(&self, query: &str) -> anyhow::Result<Vec<String>> {
        let output = Command::new(&self.binary)
            .env("XDG_CONFIG_HOME", &self.config_dir)
            .env("CASS_DATA_DIR", &self.data_dir)
            .args(["search", query, "--mode", "lexical", "--limit", "10", "--json", "--fields", "source_path"])
            .output()
            .map_err(|e| anyhow::anyhow!("spawning candidate binary for query {query:?}: {e}"))?;
        anyhow::ensure!(
            output.status.success(),
            "candidate binary exited non-zero for query {query:?}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: SearchJsonResponse = serde_json::from_slice(&output.stdout)
            .map_err(|e| anyhow::anyhow!("parsing candidate JSON for query {query:?}: {e}"))?;
        Ok(response.hits.into_iter().map(|h| h.source_path).collect())
    }
}

fn compute_report(
    queries: &[FixtureQuery],
    baseline: &std::collections::HashMap<String, BaselineRow>,
    search: &dyn LexicalSearch,
    min_recall: f64,
    min_overlap: f64,
) -> anyhow::Result<Parity40Report> {
    let mut per_query = Vec::with_capacity(queries.len());
    for q in queries {
        let baseline_row = baseline
            .get(&q.query)
            .ok_or_else(|| anyhow::anyhow!("query {:?} missing from baseline file", q.query))?;
        let anchor_source_path = q
            .anchor_source_path
            .clone()
            .or_else(|| baseline_row.top10_source_paths.first().cloned())
            .ok_or_else(|| anyhow::anyhow!("query {:?} has no anchor_source_path in fixture or baseline", q.query))?;

        let candidate_paths = search.top10_source_paths(&q.query)?;
        let candidate_rank_pos = candidate_paths.iter().position(|p| p == &anchor_source_path);
        let candidate_hit = candidate_rank_pos.is_some();
        let candidate_rank = candidate_rank_pos.map(|i| i + 1).unwrap_or(11);
        let baseline_rank = if baseline_row.anchor_hit { baseline_row.anchor_rank } else { 11 };

        let candidate_unique: BTreeSet<&str> = candidate_paths.iter().map(String::as_str).collect();
        let baseline_unique: BTreeSet<&str> = baseline_row.top10_source_paths.iter().map(String::as_str).collect();
        let overlap = if baseline_unique.is_empty() {
            None
        } else {
            Some(candidate_unique.intersection(&baseline_unique).count() as f64 / baseline_unique.len() as f64)
        };

        per_query.push(PerQuery {
            query: q.query.clone(),
            category: q.category.clone(),
            candidate_hit,
            candidate_rank,
            baseline_hit: baseline_row.anchor_hit,
            baseline_rank,
            overlap,
        });
    }

    let baseline_hits = per_query.iter().filter(|r| r.baseline_hit).count();
    let recall_at_10 = if baseline_hits == 0 {
        None
    } else {
        let paired = per_query.iter().filter(|r| r.baseline_hit && r.candidate_hit).count();
        Some(paired as f64 / baseline_hits as f64)
    };

    let overlaps: Vec<f64> = per_query.iter().filter_map(|r| r.overlap).collect();
    let overlap_mean = if overlaps.is_empty() { None } else { Some(overlaps.iter().sum::<f64>() / overlaps.len() as f64) };

    let passed = recall_at_10.is_some_and(|v| v >= min_recall) && overlap_mean.is_some_and(|v| v >= min_overlap);

    Ok(Parity40Report { recall_at_10, overlap: overlap_mean, per_query, passed })
}

fn run(
    queries_path: &std::path::Path,
    baseline_path: &std::path::Path,
    search: &dyn LexicalSearch,
    min_recall: f64,
    min_overlap: f64,
) -> (i32, Option<Parity40Report>, String) {
    let queries: Vec<FixtureQuery> = match load_jsonl(queries_path) {
        Ok(v) => v,
        Err(e) => return (2, None, format!("precondition error: {e}")),
    };
    let baseline_rows: Vec<BaselineRow> = match load_jsonl(baseline_path) {
        Ok(v) => v,
        Err(e) => return (2, None, format!("precondition error: {e}")),
    };
    let baseline: std::collections::HashMap<String, BaselineRow> =
        baseline_rows.into_iter().map(|r| (r.query.clone(), r)).collect();

    match compute_report(&queries, &baseline, search, min_recall, min_overlap) {
        Err(e) => (2, None, format!("precondition error: {e}")),
        Ok(report) => {
            let code = if report.passed { 0 } else { 1 };
            let msg = format!(
                "parity40: recall_at_10={:?} overlap={:?} passed={} (min_recall={min_recall} min_overlap={min_overlap})",
                report.recall_at_10, report.overlap, report.passed
            );
            (code, Some(report), msg)
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let binary = std::env::var("CASS_W2_PARITY_BINARY").expect("set CASS_W2_PARITY_BINARY");
    let data_dir = std::env::var("CASS_W2_PARITY_DATA_DIR").expect("set CASS_W2_PARITY_DATA_DIR");
    let config_dir = std::env::var("CASS_W2_PARITY_CONFIG_DIR").expect("set CASS_W2_PARITY_CONFIG_DIR");
    let search = SubprocessSearch { binary, data_dir, config_dir };

    let (code, report, message) = run(&cli.queries, &cli.baseline, &search, cli.min_recall, cli.min_overlap);
    println!("{message}");
    if let Some(report) = &report {
        let json = serde_json::to_string_pretty(report).expect("Parity40Report must serialize");
        std::fs::write(&cli.json, json).expect("writing --json output must succeed");
    }
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use tempfile::TempDir;

    struct FakeSearch {
        responses: StdHashMap<String, Vec<String>>,
    }
    impl LexicalSearch for FakeSearch {
        fn top10_source_paths(&self, query: &str) -> anyhow::Result<Vec<String>> {
            Ok(self.responses.get(query).cloned().unwrap_or_default())
        }
    }

    fn write_jsonl(dir: &std::path::Path, name: &str, lines: &[String]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, lines.join("\n")).unwrap();
        path
    }

    #[test]
    fn threshold_met_passes() {
        let dir = TempDir::new().unwrap();
        let queries_path = write_jsonl(
            &dir.path(),
            "queries.jsonl",
            &[
                serde_json::json!({"query": "alpha", "category": "c1", "anchor_source_path": "/a.jsonl"}).to_string(),
                serde_json::json!({"query": "beta", "category": "c1", "anchor_source_path": "/b.jsonl"}).to_string(),
            ],
        );
        let baseline_path = write_jsonl(
            &dir.path(),
            "baseline.jsonl",
            &[
                serde_json::json!({"query": "alpha", "anchor_hit": true, "anchor_rank": 1, "top10_source_paths": ["/a.jsonl", "/x.jsonl"]}).to_string(),
                serde_json::json!({"query": "beta", "anchor_hit": true, "anchor_rank": 2, "top10_source_paths": ["/b.jsonl", "/y.jsonl"]}).to_string(),
            ],
        );
        let mut responses = StdHashMap::new();
        responses.insert("alpha".to_string(), vec!["/a.jsonl".to_string(), "/x.jsonl".to_string()]);
        responses.insert("beta".to_string(), vec!["/b.jsonl".to_string(), "/y.jsonl".to_string()]);
        let search = FakeSearch { responses };

        let (code, report, message) = run(&queries_path, &baseline_path, &search, 0.95, 0.7);
        assert_eq!(code, 0, "perfect parity must pass: {message}");
        let report = report.unwrap();
        assert_eq!(report.recall_at_10, Some(1.0));
        assert_eq!(report.overlap, Some(1.0));
    }

    #[test]
    fn recall_below_threshold_fails_exit_1() {
        let dir = TempDir::new().unwrap();
        let queries_path = write_jsonl(
            &dir.path(),
            "queries.jsonl",
            &[
                serde_json::json!({"query": "alpha", "category": "c1", "anchor_source_path": "/a.jsonl"}).to_string(),
                serde_json::json!({"query": "beta", "category": "c1", "anchor_source_path": "/b.jsonl"}).to_string(),
            ],
        );
        let baseline_path = write_jsonl(
            &dir.path(),
            "baseline.jsonl",
            &[
                serde_json::json!({"query": "alpha", "anchor_hit": true, "anchor_rank": 1, "top10_source_paths": ["/a.jsonl"]}).to_string(),
                serde_json::json!({"query": "beta", "anchor_hit": true, "anchor_rank": 1, "top10_source_paths": ["/b.jsonl"]}).to_string(),
            ],
        );
        let mut responses = StdHashMap::new();
        responses.insert("alpha".to_string(), vec!["/a.jsonl".to_string()]);
        responses.insert("beta".to_string(), vec!["/something-else.jsonl".to_string()]); // miss
        let search = FakeSearch { responses };

        let (code, report, message) = run(&queries_path, &baseline_path, &search, 0.95, 0.7);
        assert_eq!(code, 1, "1 of 2 baseline hits recovered (0.5 < 0.95) must fail: {message}");
        let report = report.unwrap();
        assert_eq!(report.recall_at_10, Some(0.5));
    }

    #[test]
    fn missing_baseline_row_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let queries_path = write_jsonl(
            &dir.path(),
            "queries.jsonl",
            &[serde_json::json!({"query": "alpha", "category": "c1", "anchor_source_path": "/a.jsonl"}).to_string()],
        );
        let baseline_path = write_jsonl(&dir.path(), "baseline.jsonl", &[]);
        let search = FakeSearch { responses: StdHashMap::new() };

        let (code, report, message) = run(&queries_path, &baseline_path, &search, 0.95, 0.7);
        assert_eq!(code, 2, "a query missing from baseline must be a precondition error: {message}");
        assert!(report.is_none());
    }

    #[test]
    fn missing_files_are_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let queries_path = dir.path().join("does-not-exist.jsonl");
        let baseline_path = dir.path().join("also-missing.jsonl");
        let search = FakeSearch { responses: StdHashMap::new() };

        let (code, report, message) = run(&queries_path, &baseline_path, &search, 0.95, 0.7);
        assert_eq!(code, 2, "missing input files must be a precondition error: {message}");
        assert!(report.is_none());
    }
}
