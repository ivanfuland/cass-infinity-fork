//! C2 (plan v6 Stage C, Task C2): `cass ingest reconcile` coverage + content-
//! conservation contract. Four judgements, each independently provable:
//! forward coverage (MISSING), reverse anti-join (UNEXPECTED), root-set
//! attestation (--expected-roots), content conservation (message_count +
//! content_digest recomputed from the DB).

use assert_cmd::Command;
use blake3::Hasher;
use coding_agent_search::storage::api::Value as ParamValue;
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Every seed row below inlines its values as SQL literals (no bind params),
/// so this is always the empty parameter list -- schema.rs's own convention
/// for that case ("Empty parameter lists use a bare `&[]` at the call site").
fn fparams() -> &'static [ParamValue] {
    &[]
}

/// Independent re-implementation of the plan digest formula -- matches the
/// one in tests/ingest_manifest.rs; kept local so this test doesn't depend
/// on that file compiling first.
fn expected_digest(contents: &[&str]) -> String {
    let mut hasher = Hasher::new();
    for content in contents {
        let bytes = content.as_bytes();
        hasher.update(&(bytes.len() as u32).to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().to_hex().to_string()
}

fn write_manifest(path: &Path, scan_roots: &[&str], entries: &[Value]) {
    let mut lines = Vec::new();
    lines.push(serde_json::json!({ "scan_roots": scan_roots }).to_string());
    for entry in entries {
        lines.push(entry.to_string());
    }
    fs::write(path, lines.join("\n") + "\n").unwrap();
}

fn manifest_entry(identity_key: &str, eligible: bool, message_count: u64, digest: &str) -> Value {
    serde_json::json!({
        "identity_key": identity_key,
        "sources": [format!("/fixture/{identity_key}.jsonl")],
        "eligible": eligible,
        "exclude_reason": if eligible { Value::Null } else { Value::String("connector_filtered".into()) },
        "message_count": message_count,
        "content_digest": digest,
    })
}

fn base_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("cass"))
}

#[test]
fn reconcile_closes_when_db_matches_manifest_exactly() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("agent_search.db");

    let storage = FrankenStorage::open(&db_path).expect("open fixture db");
    let conn = storage.raw();
    conn.execute(
        "INSERT INTO agents(id, slug, name, kind, created_at, updated_at) \
         VALUES (1, 'claude_code', 'Claude Code', 'cli', 0, 0)",
        fparams(),
    )
    .expect("seed agent");
    conn.execute(
        "INSERT INTO conversations(id, agent_id, source_path, external_id) \
         VALUES (1, 1, '/fixture/session-a.jsonl', 'session-a.jsonl')",
        fparams(),
    )
    .expect("seed conversation");
    conn.execute(
        "INSERT INTO messages(id, conversation_id, idx, role, content) VALUES (1, 1, 0, 'user', 'hello')",
        fparams(),
    )
    .expect("seed message");
    drop(storage);

    let manifest_path = tmp.path().join("manifest.jsonl");
    write_manifest(
        &manifest_path,
        &["/fixture"],
        &[manifest_entry(
            "claude_code||session-a.jsonl",
            true,
            1,
            &expected_digest(&["hello"]),
        )],
    );

    let roots_path = tmp.path().join("roots.txt");
    fs::write(&roots_path, "/fixture\n").unwrap();

    let mut cmd = base_cmd();
    cmd.args([
        "ingest",
        "reconcile",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--db",
        db_path.to_str().unwrap(),
        "--expected-roots",
        roots_path.to_str().unwrap(),
    ]);
    let assertion = cmd.assert().success();
    let output = assertion.get_output();
    let report: Value = serde_json::from_slice(&output.stdout).expect("reconcile report is JSON");
    assert_eq!(report["root_set_ok"], true, "report: {report}");
    assert_eq!(report["missing"].as_array().unwrap().len(), 0, "report: {report}");
    assert_eq!(report["unexpected"].as_array().unwrap().len(), 0, "report: {report}");
    assert_eq!(report["content_mismatch"].as_array().unwrap().len(), 0, "report: {report}");
}

#[test]
fn reconcile_exits_nonzero_and_lists_every_discrepancy_class() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("agent_search.db");

    let storage = FrankenStorage::open(&db_path).expect("open fixture db");
    let conn = storage.raw();
    conn.execute(
        "INSERT INTO agents(id, slug, name, kind, created_at, updated_at) \
         VALUES (1, 'claude_code', 'Claude Code', 'cli', 0, 0)",
        fparams(),
    )
    .expect("seed agent");

    // A: correct, matches manifest exactly (control group -- must NOT appear
    // in any discrepancy list).
    conn.execute(
        "INSERT INTO conversations(id, agent_id, source_path, external_id) \
         VALUES (1, 1, '/fixture/session-a.jsonl', 'session-a.jsonl')",
        fparams(),
    )
    .expect("seed conversation A");
    conn.execute(
        "INSERT INTO messages(id, conversation_id, idx, role, content) VALUES (1, 1, 0, 'user', 'hello')",
        fparams(),
    )
    .expect("seed message A");

    // B: present in both manifest and DB, but DB content was altered after
    // ingest -- content conservation must catch this.
    conn.execute(
        "INSERT INTO conversations(id, agent_id, source_path, external_id) \
         VALUES (2, 1, '/fixture/session-b.jsonl', 'session-b.jsonl')",
        fparams(),
    )
    .expect("seed conversation B");
    conn.execute(
        "INSERT INTO messages(id, conversation_id, idx, role, content) VALUES (2, 2, 0, 'user', 'tampered content')",
        fparams(),
    )
    .expect("seed message B");

    // D: exists in the DB but was never in the manifest at all -- reverse
    // anti-join (UNEXPECTED) must catch this (guards against a manifest that
    // is itself incomplete producing a false "100% covered" forward pass).
    conn.execute(
        "INSERT INTO conversations(id, agent_id, source_path, external_id) \
         VALUES (4, 1, '/fixture/session-d.jsonl', 'session-d.jsonl')",
        fparams(),
    )
    .expect("seed conversation D");
    conn.execute(
        "INSERT INTO messages(id, conversation_id, idx, role, content) VALUES (4, 4, 0, 'user', 'unexpected session')",
        fparams(),
    )
    .expect("seed message D");
    drop(storage);

    // Manifest claims A, B, and C (C was never actually ingested into the DB
    // -- forward coverage MISSING must catch this).
    let manifest_path = tmp.path().join("manifest.jsonl");
    write_manifest(
        &manifest_path,
        &["/fixture"],
        &[
            manifest_entry("claude_code||session-a.jsonl", true, 1, &expected_digest(&["hello"])),
            manifest_entry("claude_code||session-b.jsonl", true, 1, &expected_digest(&["original content"])),
            manifest_entry("claude_code||session-c.jsonl", true, 1, &expected_digest(&["never ingested"])),
        ],
    );

    // Root-set drift: expected-roots disagrees with the manifest header.
    let roots_path = tmp.path().join("roots.txt");
    fs::write(&roots_path, "/fixture\n/nas/openclaw/my-agent-histories\n").unwrap();

    let mut cmd = base_cmd();
    cmd.args([
        "ingest",
        "reconcile",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--db",
        db_path.to_str().unwrap(),
        "--expected-roots",
        roots_path.to_str().unwrap(),
    ]);
    let output = cmd.output().expect("run reconcile");
    assert_eq!(
        output.status.code(),
        Some(1),
        "reconcile must exit 1 when any discrepancy exists; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("reconcile report is JSON");

    assert_eq!(report["root_set_ok"], false, "root drift must be flagged: {report}");

    let missing: Vec<&str> = report["missing"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(missing, vec!["claude_code||session-c.jsonl"], "report: {report}");

    let unexpected: Vec<&str> = report["unexpected"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(unexpected, vec!["claude_code||session-d.jsonl"], "report: {report}");

    let mismatches = report["content_mismatch"].as_array().unwrap();
    assert_eq!(mismatches.len(), 1, "report: {report}");
    assert_eq!(mismatches[0]["identity_key"], "claude_code||session-b.jsonl");
    assert_eq!(mismatches[0]["db_content_digest"], expected_digest(&["tampered content"]));
    assert_eq!(mismatches[0]["manifest_content_digest"], expected_digest(&["original content"]));

    // A must appear in none of the discrepancy lists.
    assert!(!missing.contains(&"claude_code||session-a.jsonl"));
    assert!(!unexpected.contains(&"claude_code||session-a.jsonl"));
    assert!(
        mismatches
            .iter()
            .all(|m| m["identity_key"] != "claude_code||session-a.jsonl")
    );
}

#[test]
fn root_set_ok_ignores_duplicate_roots_on_either_side() {
    // R1-N3: passing the same --scan-root twice at manifest-generation time
    // (a duplicated header entry) must still reconcile true against an
    // --expected-roots file that lists the same root only once, and vice
    // versa -- root-set equality is a set comparison, not a multiset one.
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("agent_search.db");
    FrankenStorage::open(&db_path).expect("open fixture db");

    let manifest_path = tmp.path().join("manifest.jsonl");
    write_manifest(&manifest_path, &["/fixture", "/fixture"], &[]);

    let roots_path = tmp.path().join("roots.txt");
    fs::write(&roots_path, "/fixture\n").unwrap();

    let mut cmd = base_cmd();
    cmd.args([
        "ingest",
        "reconcile",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--db",
        db_path.to_str().unwrap(),
        "--expected-roots",
        roots_path.to_str().unwrap(),
    ]);
    let assertion = cmd.assert().success();
    let output = assertion.get_output();
    let report: Value = serde_json::from_slice(&output.stdout).expect("reconcile report is JSON");
    assert_eq!(
        report["root_set_ok"], true,
        "duplicate root on the manifest side must not fail root-set equality: {report}"
    );
}
