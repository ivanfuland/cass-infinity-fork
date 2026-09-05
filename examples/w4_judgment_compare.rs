//! T10 (plan v5.1): `w4_judgment_compare` -- per-case, per-channel
//! non-regression gate: for every fixture case, the candidate build's rank
//! of a specific target message must be at least as good as (`<=`) a frozen
//! baseline's rank of that same message, across all three search channels
//! (lexical / semantic / hybrid).
//!
//! **Fixture schema note (deviation from the plan text's literal default
//! path)**: the plan's Interfaces line names `--fixture
//! tests/fixtures/w2_judgment_cases.jsonl` as the default input, but that
//! file's existing schema (`case, query, a_conversation_id, a_source_path,
//! b_conversation_id, b_source_path, ruling`) encodes a *pairwise* A-vs-B
//! preference at conversation/source_path granularity -- it has no
//! `message_id` field, and this tool's judgment criterion ("按 message_id
//! 取 A 的 rank", i.e. unambiguous rank lookup via the message-id field T9
//! added to search hit JSON, rather than the fragile old source_path
//! matching) needs exactly that field. Reconciling the two would mean
//! either adding `message_id` to that frozen fixture (a change to a file
//! outside T10's authorized file list) or writing a resolver that infers a
//! message_id from `a_conversation_id`/`a_source_path` against a live db
//! (underspecified: which message within that conversation is "the" A). To
//! avoid guessing a fixture-consumption contract that could silently
//! misjudge a production non-regression gate, this tool's `--fixture`
//! accepts its own, simpler schema instead: one JSON object per line,
//! `{case_id, query, message_id}`. Wiring this against the real
//! `w2_judgment_cases.jsonl` corpus is left as a follow-up needing a
//! control-plane decision on which of the above resolutions to take (noted
//! in the T10 deviation list).
//!
//! `--baseline` is a single JSON object (not JSONL): `{case_id: {channel:
//! rank_or_null}}` for `channel` in `lexical`/`semantic`/`hybrid`, `null`
//! meaning "not found in the baseline run" (`+infinity` for the comparison).
//!
//! Usage: `CASS_W2_JUDGMENT_BINARY=... CASS_W2_JUDGMENT_DATA_DIR=...
//! CASS_W2_JUDGMENT_CONFIG_DIR=... cargo run --release
//! --no-default-features --features qr,encryption,infinity --example
//! w4_judgment_compare -- --fixture <jsonl> --baseline <json> --json <out>`.
//! Exit codes: 0 every case/channel has `rank_candidate <= rank_baseline`; 1
//! at least one case/channel is `ok=false`; 2 precondition error (file
//! missing/unparseable, a case_id from the fixture absent from baseline
//! entirely, or the candidate binary/search invocation failed structurally).

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
    case_id: String,
    query: String,
    message_id: i64,
}

#[derive(Debug, Deserialize)]
struct SearchHitMessageId {
    message_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct SearchJsonResponse {
    hits: Vec<SearchHitMessageId>,
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
    fn rank_of_message(&self, channel: &str, query: &str, message_id: i64) -> anyhow::Result<Option<usize>>;
}

struct SubprocessJudgmentSearch {
    binary: String,
    data_dir: String,
    config_dir: String,
}

impl JudgmentSearch for SubprocessJudgmentSearch {
    fn rank_of_message(&self, channel: &str, query: &str, message_id: i64) -> anyhow::Result<Option<usize>> {
        let mut args: Vec<String> =
            vec!["search".into(), query.into(), "--mode".into(), channel.into(), "--limit".into(), "5000".into(), "--json".into()];
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
        Ok(response.hits.iter().position(|h| h.message_id == Some(message_id)).map(|i| i + 1))
    }
}

type BaselineMap = HashMap<String, HashMap<String, Option<usize>>>;
type Report = HashMap<String, HashMap<String, ChannelVerdict>>;

fn compute_report(cases: &[JudgmentCase], baseline: &BaselineMap, search: &dyn JudgmentSearch) -> anyhow::Result<Report> {
    let mut report = Report::new();
    for case in cases {
        let baseline_channels = baseline
            .get(&case.case_id)
            .ok_or_else(|| anyhow::anyhow!("case_id {:?} missing from baseline", case.case_id))?;
        let mut channel_verdicts = HashMap::new();
        for &channel in &CHANNELS {
            let baseline_rank = baseline_channels.get(channel).copied().flatten();
            let candidate_rank = search.rank_of_message(channel, &case.query, case.message_id)?;
            channel_verdicts.insert(channel.to_string(), channel_verdict(baseline_rank, candidate_rank));
        }
        report.insert(case.case_id.clone(), channel_verdicts);
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

fn load_baseline(path: &std::path::Path) -> anyhow::Result<BaselineMap> {
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
        fn rank_of_message(&self, channel: &str, query: &str, _message_id: i64) -> anyhow::Result<Option<usize>> {
            Ok(self.ranks.get(&(channel.to_string(), query.to_string())).copied().flatten())
        }
    }

    fn write_file(dir: &std::path::Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn all_channels_at_or_better_than_baseline_pass() {
        let dir = TempDir::new().unwrap();
        let fixture = write_file(
            dir.path(),
            "fixture.jsonl",
            &serde_json::json!({"case_id": "c1", "query": "foo", "message_id": 42}).to_string(),
        );
        let baseline = write_file(
            dir.path(),
            "baseline.json",
            &serde_json::json!({"c1": {"lexical": 3, "semantic": 5, "hybrid": 2}}).to_string(),
        );
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
        let fixture = write_file(
            dir.path(),
            "fixture.jsonl",
            &serde_json::json!({"case_id": "c1", "query": "foo", "message_id": 42}).to_string(),
        );
        let baseline = write_file(
            dir.path(),
            "baseline.json",
            &serde_json::json!({"c1": {"lexical": 3, "semantic": 5, "hybrid": 2}}).to_string(),
        );
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
        let fixture = write_file(
            dir.path(),
            "fixture.jsonl",
            &serde_json::json!({"case_id": "c1", "query": "foo", "message_id": 42}).to_string(),
        );
        let baseline = write_file(dir.path(), "baseline.json", &serde_json::json!({"c1": {"lexical": null, "semantic": null, "hybrid": null}}).to_string());
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
        let fixture = write_file(
            dir.path(),
            "fixture.jsonl",
            &serde_json::json!({"case_id": "c1", "query": "foo", "message_id": 42}).to_string(),
        );
        let baseline = write_file(dir.path(), "baseline.json", &serde_json::json!({"c1": {"lexical": 5, "semantic": 5, "hybrid": 5}}).to_string());
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
    fn missing_case_id_in_baseline_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let fixture = write_file(
            dir.path(),
            "fixture.jsonl",
            &serde_json::json!({"case_id": "c1", "query": "foo", "message_id": 42}).to_string(),
        );
        let baseline = write_file(dir.path(), "baseline.json", "{}");
        let search = FakeSearch { ranks: HashMap::new() };

        let (code, report, message) = run(&fixture, &baseline, &search);
        assert_eq!(code, 2, "case_id absent from baseline must be a precondition error: {message}");
        assert!(report.is_none());
    }
}
