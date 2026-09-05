//! T10/T10.5 (plan v5.1): `w4_judgment_compare` -- per-case, per-channel
//! non-regression gate: for every fixture case, the candidate build's rank
//! of a specific target document must be at least as good as (`<=`) a
//! frozen baseline's rank of that same document, across all three search
//! channels (lexical / semantic / hybrid).
//!
//! **Correlation field: `source_path`, not `conversation_id`/`message_id`**
//! (T10.5 correction, control-plane 2026-09-05 ruling). The plan's original
//! design called for ranking by `conversation_id` ("hits carry conversation
//! id"), but `SearchHit.conversation_id` (`src/search/query.rs:1414`) is
//! `#[serde(skip_serializing)]` -- `cass search --json` never emits it,
//! regardless of `--fields`. `message_id` does serialize, but its own doc
//! comment states lexical-only hits are always `None` for it -- unusable
//! for the lexical channel, one of the three this tool must cover. Ranking
//! by `source_path` (which DOES serialize plainly) is the same correlation
//! field the precedent judgment/parity gates already use and verified
//! (`tests/w2_lexical_parity.rs`, `tests/w2_judgment_cases.rs`) -- this
//! tool follows that precedent rather than inventing a new one.
//! `W4_ARTIFACTS/judgment_baseline.json`'s own `provenance` block does not
//! record which correlation field its author used to compute each case's
//! rank; this tool assumes source_path (the only field both the real
//! fixture and `SearchHit` actually carry) and documents that assumption
//! here rather than silently guessing without a record of the choice --
//! T12 gate ⑥ must apply the same correlation field on both sides of any
//! future re-comparison.
//!
//! **Fixture**: real production data, `tests/fixtures/w2_judgment_cases.jsonl`
//! (one JSON object per line): `{case, query, category, a_conversation_id,
//! a_source_path, b_conversation_id, b_source_path, ruling, provenance}` --
//! this tool reads only `case`/`query`/`a_source_path` (the `b_*`/`ruling`
//! fields encode a *different* judgment concept, W2's pairwise A-vs-B
//! preference gate, not this tool's baseline-vs-candidate rank comparison).
//!
//! **Baseline**: `W4_ARTIFACTS/judgment_baseline.json`, a single JSON
//! object (not JSONL): `{"results": {case: {lexical, semantic, hybrid}},
//! "provenance": {...}}`, `null` meaning "not found in the baseline run"
//! (`+infinity` for the comparison). The report's own top-level keys are
//! named `case_id` in the plan's Interfaces text; this tool uses the
//! fixture's own field name `case` for both the lookup key and the output
//! key, since they're the same string.
//!
//! Usage: `CASS_W2_JUDGMENT_BINARY=... CASS_W2_JUDGMENT_DATA_DIR=...
//! CASS_W2_JUDGMENT_CONFIG_DIR=... cargo run --release
//! --no-default-features --features qr,encryption,infinity --example
//! w4_judgment_compare -- --fixture tests/fixtures/w2_judgment_cases.jsonl
//! --baseline W4_ARTIFACTS/judgment_baseline.json --json <out>`. Exit
//! codes: 0 every case/channel has `rank_candidate <= rank_baseline`; 1 at
//! least one case/channel is `ok=false`; 2 precondition error (file
//! missing/unparseable, a case from the fixture absent from baseline
//! entirely, or the candidate binary/search invocation failed
//! structurally).

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(name = "w4_judgment_compare")]
struct Cli {
    #[arg(long)]
    fixture: PathBuf,
    #[arg(long)]
    baseline: PathBuf,
    #[arg(long)]
    json: PathBuf,
}

const CHANNELS: [&str; 3] = ["lexical", "semantic", "hybrid"];

#[derive(Debug, Deserialize, Clone)]
struct JudgmentCase {
    case: String,
    query: String,
    a_source_path: String,
}

#[derive(Debug, Deserialize)]
struct SearchHitSourcePath {
    source_path: String,
}

#[derive(Debug, Deserialize)]
struct SearchJsonResponse {
    hits: Vec<SearchHitSourcePath>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq)]
struct ChannelVerdict {
    baseline: Option<usize>,
    candidate: Option<usize>,
    ok: bool,
}

fn rank_or_inf(rank: Option<usize>) -> f64 {
    rank.map(|r| r as f64).unwrap_or(f64::INFINITY)
}

fn channel_verdict(baseline: Option<usize>, candidate: Option<usize>) -> ChannelVerdict {
    let ok = rank_or_inf(candidate) <= rank_or_inf(baseline);
    ChannelVerdict { baseline, candidate, ok }
}

trait JudgmentSearch {
    fn rank_of_source_path(&self, channel: &str, query: &str, source_path: &str) -> anyhow::Result<Option<usize>>;
}

struct SubprocessJudgmentSearch {
    binary: String,
    data_dir: String,
    config_dir: String,
}

impl JudgmentSearch for SubprocessJudgmentSearch {
    fn rank_of_source_path(&self, channel: &str, query: &str, source_path: &str) -> anyhow::Result<Option<usize>> {
        let mut args: Vec<String> = vec![
            "search".into(),
            query.into(),
            "--mode".into(),
            channel.into(),
            "--limit".into(),
            "5000".into(),
            "--json".into(),
            "--fields".into(),
            "source_path".into(),
        ];
        if channel == "semantic" || channel == "hybrid" {
            args.push("--daemon".into());
            args.push("--model".into());
            args.push("bge-m3".into());
        }
        let output = Command::new(&self.binary)
            .env("XDG_CONFIG_HOME", &self.config_dir)
            .env("CASS_DATA_DIR", &self.data_dir)
            .args(&args)
            .output()
            .map_err(|e| anyhow::anyhow!("spawning candidate binary for channel={channel} query={query:?}: {e}"))?;
        anyhow::ensure!(
            output.status.success(),
            "candidate binary exited non-zero for channel={channel} query={query:?}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: SearchJsonResponse = serde_json::from_slice(&output.stdout)
            .map_err(|e| anyhow::anyhow!("parsing candidate JSON for channel={channel} query={query:?}: {e}"))?;
        Ok(response.hits.iter().position(|h| h.source_path == source_path).map(|i| i + 1))
    }
}

#[derive(Debug, Deserialize)]
struct BaselineFile {
    results: HashMap<String, HashMap<String, Option<usize>>>,
}

type Report = HashMap<String, HashMap<String, ChannelVerdict>>;

fn compute_report(cases: &[JudgmentCase], baseline: &BaselineFile, search: &dyn JudgmentSearch) -> anyhow::Result<Report> {
    let mut report = Report::new();
    for case in cases {
        let baseline_channels = baseline.results.get(&case.case).ok_or_else(|| anyhow::anyhow!("case {:?} missing from baseline", case.case))?;
        let mut channel_verdicts = HashMap::new();
        for &channel in &CHANNELS {
            let baseline_rank = baseline_channels.get(channel).copied().flatten();
            let candidate_rank = search.rank_of_source_path(channel, &case.query, &case.a_source_path)?;
            channel_verdicts.insert(channel.to_string(), channel_verdict(baseline_rank, candidate_rank));
        }
        report.insert(case.case.clone(), channel_verdicts);
    }
    Ok(report)
}

fn load_fixture(path: &std::path::Path) -> anyhow::Result<Vec<JudgmentCase>> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| anyhow::anyhow!("parsing {}: {e}: line={l:?}", path.display())))
        .collect()
}

fn load_baseline(path: &std::path::Path) -> anyhow::Result<BaselineFile> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))
}

fn run(fixture_path: &std::path::Path, baseline_path: &std::path::Path, search: &dyn JudgmentSearch) -> (i32, Option<Report>, String) {
    let cases = match load_fixture(fixture_path) {
        Ok(v) => v,
        Err(e) => return (2, None, format!("precondition error: {e}")),
    };
    let baseline = match load_baseline(baseline_path) {
        Ok(v) => v,
        Err(e) => return (2, None, format!("precondition error: {e}")),
    };
    match compute_report(&cases, &baseline, search) {
        Err(e) => (2, None, format!("precondition error: {e}")),
        Ok(report) => {
            let any_fail = report.values().any(|channels| channels.values().any(|v| !v.ok));
            let code = if any_fail { 1 } else { 0 };
            let msg = format!(
                "judgment_compare: {} case(s), {}",
                report.len(),
                if any_fail { "at least one channel regressed" } else { "all channels non-regressed" }
            );
            (code, Some(report), msg)
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let binary = std::env::var("CASS_W2_JUDGMENT_BINARY").expect("set CASS_W2_JUDGMENT_BINARY");
    let data_dir = std::env::var("CASS_W2_JUDGMENT_DATA_DIR").expect("set CASS_W2_JUDGMENT_DATA_DIR");
    let config_dir = std::env::var("CASS_W2_JUDGMENT_CONFIG_DIR").expect("set CASS_W2_JUDGMENT_CONFIG_DIR");
    let search = SubprocessJudgmentSearch { binary, data_dir, config_dir };

    let (code, report, message) = run(&cli.fixture, &cli.baseline, &search);
    println!("{message}");
    if let Some(report) = &report {
        let json = serde_json::to_string_pretty(report).expect("Report must serialize");
        std::fs::write(&cli.json, json).expect("writing --json output must succeed");
    }
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct FakeSearch {
        // (channel, query) -> rank
        ranks: HashMap<(String, String), Option<usize>>,
    }
    impl JudgmentSearch for FakeSearch {
        fn rank_of_source_path(&self, channel: &str, query: &str, _source_path: &str) -> anyhow::Result<Option<usize>> {
            Ok(self.ranks.get(&(channel.to_string(), query.to_string())).copied().flatten())
        }
    }

    fn write_file(dir: &std::path::Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    /// Real-shape fixture line, mirroring `tests/fixtures/w2_judgment_cases.jsonl`'s
    /// actual fields (only `case`/`query`/`a_source_path` are read; the rest
    /// are included so this selftest exercises real-shape deserialization,
    /// not a slimmed-down stand-in).
    fn fixture_line(case: &str, query: &str, a_source_path: &str) -> String {
        serde_json::json!({
            "case": case,
            "query": query,
            "category": "selftest",
            "a_conversation_id": 1,
            "a_source_path": a_source_path,
            "b_conversation_id": 2,
            "b_source_path": "/b.jsonl",
            "ruling": "A>B",
            "provenance": "selftest fixture, not a real judgment"
        })
        .to_string()
    }

    fn baseline_file(entries: serde_json::Value) -> String {
        serde_json::json!({"results": entries, "provenance": {"note": "selftest"}}).to_string()
    }

    #[test]
    fn all_channels_at_or_better_than_baseline_pass() {
        let dir = TempDir::new().unwrap();
        let fixture = write_file(dir.path(), "fixture.jsonl", &fixture_line("c1", "foo", "/a.jsonl"));
        let baseline = write_file(dir.path(), "baseline.json", &baseline_file(serde_json::json!({"c1": {"lexical": 3, "semantic": 5, "hybrid": 2}})));
        let mut ranks = HashMap::new();
        ranks.insert(("lexical".to_string(), "foo".to_string()), Some(2));
        ranks.insert(("semantic".to_string(), "foo".to_string()), Some(5));
        ranks.insert(("hybrid".to_string(), "foo".to_string()), Some(1));
        let search = FakeSearch { ranks };

        let (code, report, message) = run(&fixture, &baseline, &search);
        assert_eq!(code, 0, "candidate at or better than baseline on all channels must pass: {message}");
        let report = report.unwrap();
        assert!(report["c1"]["lexical"].ok);
        assert!(report["c1"]["semantic"].ok);
        assert!(report["c1"]["hybrid"].ok);
    }

    #[test]
    fn one_channel_worse_than_baseline_fails_exit_1() {
        let dir = TempDir::new().unwrap();
        let fixture = write_file(dir.path(), "fixture.jsonl", &fixture_line("c1", "foo", "/a.jsonl"));
        let baseline = write_file(dir.path(), "baseline.json", &baseline_file(serde_json::json!({"c1": {"lexical": 3, "semantic": 5, "hybrid": 2}})));
        let mut ranks = HashMap::new();
        ranks.insert(("lexical".to_string(), "foo".to_string()), Some(2));
        ranks.insert(("semantic".to_string(), "foo".to_string()), Some(9)); // worse than baseline 5
        ranks.insert(("hybrid".to_string(), "foo".to_string()), Some(1));
        let search = FakeSearch { ranks };

        let (code, report, message) = run(&fixture, &baseline, &search);
        assert_eq!(code, 1, "one regressed channel must fail the gate: {message}");
        let report = report.unwrap();
        assert!(!report["c1"]["semantic"].ok);
        assert!(report["c1"]["lexical"].ok);
    }

    #[test]
    fn baseline_null_treated_as_infinity_any_candidate_rank_passes() {
        let dir = TempDir::new().unwrap();
        let fixture = write_file(dir.path(), "fixture.jsonl", &fixture_line("c1", "foo", "/a.jsonl"));
        let baseline = write_file(dir.path(), "baseline.json", &baseline_file(serde_json::json!({"c1": {"lexical": null, "semantic": null, "hybrid": null}})));
        let mut ranks = HashMap::new();
        ranks.insert(("lexical".to_string(), "foo".to_string()), None);
        ranks.insert(("semantic".to_string(), "foo".to_string()), Some(100));
        ranks.insert(("hybrid".to_string(), "foo".to_string()), None);
        let search = FakeSearch { ranks };

        let (code, report, message) = run(&fixture, &baseline, &search);
        assert_eq!(code, 0, "baseline null (+inf) must be satisfied by any candidate rank, including candidate null: {message}");
        let report = report.unwrap();
        assert!(report["c1"]["lexical"].ok, "candidate null vs baseline null must pass");
        assert!(report["c1"]["semantic"].ok, "candidate found vs baseline null must pass");
    }

    #[test]
    fn candidate_null_vs_finite_baseline_fails() {
        let dir = TempDir::new().unwrap();
        let fixture = write_file(dir.path(), "fixture.jsonl", &fixture_line("c1", "foo", "/a.jsonl"));
        let baseline = write_file(dir.path(), "baseline.json", &baseline_file(serde_json::json!({"c1": {"lexical": 5, "semantic": 5, "hybrid": 5}})));
        let mut ranks = HashMap::new();
        ranks.insert(("lexical".to_string(), "foo".to_string()), None);
        ranks.insert(("semantic".to_string(), "foo".to_string()), Some(3));
        ranks.insert(("hybrid".to_string(), "foo".to_string()), Some(3));
        let search = FakeSearch { ranks };

        let (code, report, message) = run(&fixture, &baseline, &search);
        assert_eq!(code, 1, "candidate not-found against a finite baseline must fail: {message}");
        let report = report.unwrap();
        assert!(!report["c1"]["lexical"].ok);
    }

    #[test]
    fn missing_case_in_baseline_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let fixture = write_file(dir.path(), "fixture.jsonl", &fixture_line("c1", "foo", "/a.jsonl"));
        let baseline = write_file(dir.path(), "baseline.json", &baseline_file(serde_json::json!({})));
        let search = FakeSearch { ranks: HashMap::new() };

        let (code, report, message) = run(&fixture, &baseline, &search);
        assert_eq!(code, 2, "case absent from baseline must be a precondition error: {message}");
        assert!(report.is_none());
    }

    /// Real-shape regression guard: loads the actual `tests/fixtures/
    /// w2_judgment_cases.jsonl` (5 rows) to prove this tool's `JudgmentCase`
    /// deserializes the real file without error and extracts the expected
    /// fields -- catches a field-name drift between this tool and the
    /// fixture without needing a live candidate binary.
    #[test]
    fn real_fixture_file_deserializes() {
        let cases = load_fixture(std::path::Path::new("tests/fixtures/w2_judgment_cases.jsonl")).expect("real fixture must parse with this tool's JudgmentCase shape");
        assert_eq!(cases.len(), 5, "real fixture has exactly 5 rows");
        let case_names: Vec<&str> = cases.iter().map(|c| c.case.as_str()).collect();
        assert_eq!(case_names, ["indexing", "indexer", "connectors", "duplicate", "触发器"]);
        for c in &cases {
            assert!(!c.query.is_empty());
            assert!(!c.a_source_path.is_empty());
        }
    }
}
