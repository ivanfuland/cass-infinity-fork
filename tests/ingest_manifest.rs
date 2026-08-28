//! C1 (plan v6 Stage C, Task C1): `cass ingest manifest` candidate-inventory
//! contract. Mini 3-session fixture: 1 eligible, 1 excluded (empty session,
//! d19: exclude_reason="connector_filtered"), 1 duplicate source across two
//! scan roots that must collapse into a single manifest entry.

use assert_cmd::Command;
use blake3::Hasher;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Independent re-implementation of the plan-specified digest formula
/// (R1-S14/NG4 + R3-N5): blake3 over each message's raw UTF-8 content,
/// each one length-prefixed (u32 LE) to prevent concatenation ambiguity.
/// Computed here from scratch (not by calling production code) so the test
/// proves the contract, not just mirrors the implementation.
fn expected_digest(contents: &[&str]) -> String {
    let mut hasher = Hasher::new();
    for content in contents {
        let bytes = content.as_bytes();
        hasher.update(&(bytes.len() as u32).to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().to_hex().to_string()
}

fn write_session(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn base_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("cass"))
}

#[test]
fn manifest_reports_eligible_excluded_and_deduped_sessions() {
    let tmp = TempDir::new().unwrap();
    let root_a = tmp.path().join("root-a");
    let root_b = tmp.path().join("root-b");
    fs::create_dir_all(&root_a).unwrap();
    fs::create_dir_all(&root_b).unwrap();

    // 1. Eligible session: two plain-string messages, no filtering applies.
    write_session(
        &root_a.join("eligible.jsonl"),
        concat!(
            r#"{"type":"user","cwd":"/workspace/proj","sessionId":"sess-eligible","message":{"role":"user","content":"Hello from eligible session"},"timestamp":"2025-01-01T00:00:00.000Z"}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":"Hi there!"},"timestamp":"2025-01-01T00:00:01.000Z"}"#,
            "\n",
        ),
    );

    // 2. Empty session: every line has blank/whitespace-only content, so the
    // connector's own `messages.is_empty()` guard drops the whole file
    // (zero conversations emitted) while discover_source_files() still lists
    // it as a candidate file -> discovered-minus-scanned diff -> connector_filtered.
    write_session(
        &root_a.join("empty.jsonl"),
        concat!(
            r#"{"type":"user","message":{"role":"user","content":""}}"#,
            "\n",
            r#"{"type":"user","message":{"role":"user","content":"   "}}"#,
            "\n",
        ),
    );

    // 3. Duplicate source: byte-identical session file mirrored under two
    // different --scan-root roots (same relative filename under each root
    // -> same connector-derived external_id -> same identity_key).
    let dup_content = concat!(
        r#"{"type":"user","cwd":"/workspace/dup","sessionId":"sess-dup","message":{"role":"user","content":"Duplicate content across mirrors"},"timestamp":"2025-01-02T00:00:00.000Z"}"#,
        "\n",
    );
    write_session(&root_a.join("dup.jsonl"), dup_content);
    write_session(&root_b.join("dup.jsonl"), dup_content);

    let mirror_dir = tmp.path().join("mirror");
    fs::create_dir_all(&mirror_dir).unwrap();
    let out_path = tmp.path().join("manifest.jsonl");

    let mut cmd = base_cmd();
    cmd.args([
        "ingest",
        "manifest",
        "--scan-root",
        root_a.to_str().unwrap(),
        "--scan-root",
        root_b.to_str().unwrap(),
        "--mirror",
        mirror_dir.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    cmd.assert().success();

    let manifest_text = fs::read_to_string(&out_path)
        .unwrap_or_else(|e| panic!("manifest output file missing at {out_path:?}: {e}"));
    let mut all_lines: Vec<Value> = manifest_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad manifest line {l:?}: {e}")))
        .collect();
    assert!(!all_lines.is_empty(), "manifest is empty: {manifest_text}");

    // First line is the root-set attestation header (plan v6 Stage C Task C2:
    // "manifest 头部记录生成时的扫描根全集摘要" -- reconcile's --expected-roots
    // check needs this). Distinguished from candidate entries by the
    // scan_roots key, which no candidate line carries.
    let header = all_lines.remove(0);
    let mut header_roots: Vec<String> = header["scan_roots"]
        .as_array()
        .unwrap_or_else(|| panic!("manifest header missing scan_roots array: {header}"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    header_roots.sort();
    let mut expected_roots = vec![
        root_a.to_str().unwrap().to_string(),
        root_b.to_str().unwrap().to_string(),
    ];
    expected_roots.sort();
    assert_eq!(
        header_roots, expected_roots,
        "manifest header scan_roots must record the exact --scan-root set"
    );

    let lines = all_lines;
    assert_eq!(
        lines.len(),
        3,
        "expected 3 manifest entries (eligible + excluded + deduped dup), got {}: {manifest_text}",
        lines.len()
    );

    let find_by_source = |suffix: &str| -> &Value {
        lines
            .iter()
            .find(|entry| {
                entry["sources"]
                    .as_array()
                    .expect("sources must be an array")
                    .iter()
                    .any(|s| s.as_str().unwrap().ends_with(suffix))
            })
            .unwrap_or_else(|| panic!("no manifest entry with a source ending in {suffix}: {manifest_text}"))
    };

    let eligible_entry = find_by_source("eligible.jsonl");
    assert_eq!(eligible_entry["eligible"], true);
    assert_eq!(eligible_entry["exclude_reason"], Value::Null);
    assert_eq!(eligible_entry["message_count"], 2);
    assert_eq!(eligible_entry["sources"].as_array().unwrap().len(), 1);
    assert_eq!(
        eligible_entry["content_digest"].as_str().unwrap(),
        expected_digest(&["Hello from eligible session", "Hi there!"]),
        "eligible entry: {eligible_entry}"
    );

    let empty_entry = find_by_source("empty.jsonl");
    assert_eq!(empty_entry["eligible"], false);
    assert_eq!(empty_entry["exclude_reason"], "connector_filtered");
    assert_eq!(empty_entry["message_count"], 0);
    assert_eq!(
        empty_entry["content_digest"].as_str().unwrap(),
        expected_digest(&[]),
        "excluded entry: {empty_entry}"
    );

    let dup_entry = find_by_source("dup.jsonl");
    assert_eq!(dup_entry["eligible"], true);
    assert_eq!(dup_entry["exclude_reason"], Value::Null);
    assert_eq!(dup_entry["message_count"], 1);
    let sources: Vec<String> = dup_entry["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        sources.len(),
        2,
        "duplicate session mirrored across two scan roots must collapse into one entry with two sources: {sources:?}"
    );
    assert!(sources.iter().any(|s| s.contains("root-a")));
    assert!(sources.iter().any(|s| s.contains("root-b")));
    assert_eq!(
        dup_entry["content_digest"].as_str().unwrap(),
        expected_digest(&["Duplicate content across mirrors"]),
        "dup entry: {dup_entry}"
    );
}

/// Subagent transcripts (Claude Code's `<session>/subagents/agent-*.jsonl`)
/// are content-parseable but structurally excluded from the reingest
/// candidate accounting (plan Task C1: "资格谓词...复用连接器现有判定
/// （子代理...既有过滤 = 谓词排除项）"). This must fire independent of the
/// live indexer's `CASS_SKIP_SUBAGENTS` opt-in toggle -- the manifest's job
/// is a deterministic structural classification, not a mirror of whatever
/// env var happens to be set when it runs.
#[test]
fn manifest_excludes_subagent_transcripts() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");

    write_session(
        &root.join("session-a/session-a.jsonl"),
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"Top-level session"},"timestamp":"2025-01-03T00:00:00.000Z"}"#,
            "\n",
        ),
    );
    write_session(
        &root.join("session-a/subagents/agent-1.jsonl"),
        concat!(
            r#"{"type":"user","message":{"role":"user","content":"Subagent scratchpad"},"timestamp":"2025-01-03T00:00:01.000Z"}"#,
            "\n",
        ),
    );

    let mirror_dir = tmp.path().join("mirror");
    fs::create_dir_all(&mirror_dir).unwrap();
    let out_path = tmp.path().join("manifest.jsonl");

    let mut cmd = base_cmd();
    cmd.args([
        "ingest",
        "manifest",
        "--scan-root",
        root.to_str().unwrap(),
        "--mirror",
        mirror_dir.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    // Deliberately unset: this must not depend on the operator's live-index toggle.
    cmd.env_remove("CASS_SKIP_SUBAGENTS");
    cmd.assert().success();

    let manifest_text = fs::read_to_string(&out_path).unwrap();
    let mut all_lines: Vec<Value> = manifest_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad manifest line {l:?}: {e}")))
        .collect();
    assert!(!all_lines.is_empty(), "manifest is empty: {manifest_text}");
    let header = all_lines.remove(0);
    assert_eq!(
        header["scan_roots"].as_array().unwrap(),
        &vec![Value::String(root.to_str().unwrap().to_string())],
        "manifest header scan_roots must record the single --scan-root given: {header}"
    );
    let lines = all_lines;
    assert_eq!(
        lines.len(),
        2,
        "expected 2 manifest entries (top-level eligible + subagent excluded), got {}: {manifest_text}",
        lines.len()
    );

    let top_level = lines
        .iter()
        .find(|entry| {
            entry["sources"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s.as_str().unwrap().ends_with("session-a.jsonl") && !s.as_str().unwrap().contains("subagents"))
        })
        .unwrap_or_else(|| panic!("no top-level manifest entry: {manifest_text}"));
    assert_eq!(top_level["eligible"], true);
    assert_eq!(top_level["exclude_reason"], Value::Null);
    assert_eq!(top_level["message_count"], 1);

    let subagent_entry = lines
        .iter()
        .find(|entry| {
            entry["sources"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s.as_str().unwrap().contains("subagents"))
        })
        .unwrap_or_else(|| panic!("no subagent manifest entry: {manifest_text}"));
    assert_eq!(subagent_entry["eligible"], false);
    assert_eq!(subagent_entry["exclude_reason"], "subagent");
    assert_eq!(subagent_entry["message_count"], 0);
}
