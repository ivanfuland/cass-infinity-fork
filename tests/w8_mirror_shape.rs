//! PR8 C4: raw-mirror manifest session key `(identity_host, agent,
//! external_id)` and connector-shaped materialization.
//!
//! Every test captures through the real `capture_source_file_with_identity`,
//! materializes through the real `materialize_capture_to_dest`, and reparses
//! with the pinned FAD connector -- no hand-written manifest JSON.
//!
//! Global state these tests touch: the raw-mirror blob capture cache and the
//! manifest update lock, both keyed/serialized per `data_dir`; every test owns
//! its own `TempDir`, so parallel runs do not share entries. No env var is
//! set in this process; `cass` subprocesses get their own HOME/XDG env.

use std::fs;
use std::path::{Path, PathBuf};

use coding_agent_search::connectors::{
    Connector, NormalizedConversation, ScanContext, ScanRoot, claude_code::ClaudeCodeConnector,
    codex::CodexConnector, gemini::GeminiConnector,
};
use coding_agent_search::phase3_restore::{
    MirrorMaterializeOutcome, ensure_manifest_session_key_matches, materialize_capture_to_dest,
    mirror_shape_relative_path, split_connector_shape,
};
use coding_agent_search::raw_mirror::{
    RawMirrorCaptureInput, RawMirrorCaptureRecord, RawMirrorManifestView,
    RawMirrorSessionIdentity, capture_source_file, capture_source_file_with_identity,
    manifest_views, recompute_manifest_blake3,
};
use serde_json::Value;
use tempfile::TempDir;

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative)
}

/// `data_dir` is the file itself (as in FAD's own explicit-file-root tests):
/// gemini also adds `data_dir` as a root when it looks like one, so a parent
/// directory would scan the same file twice.
fn scan_explicit_file(connector: &dyn Connector, file: &Path) -> Vec<NormalizedConversation> {
    let ctx = ScanContext::with_roots(
        file.to_path_buf(),
        vec![ScanRoot::local(file.to_path_buf())],
        None,
    );
    connector.scan(&ctx).expect("connector scan")
}

fn single(convs: Vec<NormalizedConversation>, what: &str) -> NormalizedConversation {
    assert_eq!(convs.len(), 1, "{what}: expected exactly one conversation");
    convs.into_iter().next().unwrap()
}

fn capture(
    data_dir: &Path,
    provider: &str,
    source_path: &Path,
    identity_host: &str,
    external_id: Option<&str>,
) -> anyhow::Result<RawMirrorCaptureRecord> {
    capture_source_file_with_identity(
        RawMirrorCaptureInput {
            data_dir,
            provider,
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path,
            db_links: &[],
        },
        RawMirrorSessionIdentity {
            identity_host,
            external_id,
        },
    )
}

fn view_for(data_dir: &Path, record: &RawMirrorCaptureRecord) -> RawMirrorManifestView {
    manifest_views(data_dir)
        .expect("manifest views")
        .into_iter()
        .find(|view| view.manifest_id == record.manifest_id)
        .expect("manifest view for captured record")
}

fn materialized_path(outcome: MirrorMaterializeOutcome) -> PathBuf {
    match outcome {
        MirrorMaterializeOutcome::Written(path) | MirrorMaterializeOutcome::SkippedIdentical(path) => {
            path
        }
    }
}

fn copy_into(src: &Path, dest: &Path) {
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    fs::copy(src, dest).unwrap();
}

fn cass_cmd(home: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_cass"));
    cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .env("CASS_IGNORE_SOURCES_CONFIG", "1")
        .env("XDG_DATA_HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env("HOME", home)
        .env_remove("CODEX_HOME")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env("NO_COLOR", "1")
        .current_dir(home);
    cmd
}

fn run_ok(mut cmd: std::process::Command, what: &str) -> Vec<u8> {
    let out = cmd.output().expect(what);
    assert!(
        out.status.success(),
        "{what} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn sorted_json(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(sorted_json).collect()),
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = serde_json::Map::new();
            for (key, value) in entries {
                out.insert(key, sorted_json(value));
            }
            Value::Object(out)
        }
        other => other,
    }
}

/// Independent re-implementation of the manifest self-digest over whatever
/// fields the JSON actually carries (everything except `manifest_blake3`).
fn independent_manifest_digest(manifest: &Value) -> String {
    let mut value = manifest.clone();
    value.as_object_mut().unwrap().remove("manifest_blake3");
    let prefix = "doctor-raw-mirror-manifest-v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix.as_bytes());
    hasher.update(&[0]);
    hasher.update(&serde_json::to_vec(&sorted_json(value)).unwrap());
    format!("{prefix}-{}", hasher.finalize().to_hex())
}

const SESSION_KEY_FIELDS: [&str; 5] =
    ["identity_host", "agent", "external_id", "shape_root", "relative_path"];

/// AC-1 (codex): capture -> new layout -> reparse; `agent`/`external_id`
/// byte-equal to the manifest.
#[test]
fn reparse_identity_roundtrip_codex() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("data");
    let dest = temp.path().join("dest");
    let source = fixture("codex_real/sessions/2025/11/25/rollout-test.jsonl");

    let first = single(scan_explicit_file(&CodexConnector::new(), &source), "first parse");
    let first_external_id = first.external_id.clone().expect("codex external_id");
    assert_eq!(first_external_id, "2025/11/25/rollout-test");
    assert_eq!(
        split_connector_shape("codex", &source),
        Some(("sessions".to_string(), PathBuf::from("2025/11/25/rollout-test.jsonl")))
    );

    let record = capture(&data_dir, &first.agent_slug, &source, "local", Some(&first_external_id))
        .expect("capture");
    let view = view_for(&data_dir, &record);
    assert_eq!(view.identity_host, "local");
    assert_eq!(view.agent, "codex");
    assert_eq!(view.external_id.as_deref(), Some(first_external_id.as_str()));
    assert_eq!(view.shape_root.as_deref(), Some("sessions"));
    assert_eq!(view.relative_path.as_deref(), Some("2025/11/25/rollout-test.jsonl"));

    let materialized = materialized_path(
        materialize_capture_to_dest(&data_dir, &record, &dest).expect("materialize"),
    );
    assert_eq!(
        materialized,
        fs::canonicalize(&dest)
            .unwrap()
            .join("local/codex/sessions/2025/11/25/rollout-test.jsonl")
    );

    let reparsed = single(scan_explicit_file(&CodexConnector::new(), &materialized), "reparse");
    assert_eq!(reparsed.agent_slug.as_bytes(), view.agent.as_bytes());
    assert_eq!(
        reparsed.external_id.as_deref().map(str::as_bytes),
        view.external_id.as_deref().map(str::as_bytes)
    );

    // The indexer's added assertion: manifest key must equal the first parse.
    ensure_manifest_session_key_matches(&data_dir, &record, "codex", Some(&first_external_id))
        .expect("manifest key matches first parse");
    assert!(
        ensure_manifest_session_key_matches(&data_dir, &record, "codex", Some("2025/11/25/other"))
            .is_err(),
        "a different external_id must be rejected"
    );

    // End to end through `cass index`: the preparse capture (no external_id
    // yet) and the post-parse capture share one manifest; the indexer must
    // fill the session key and pass the reparse identity guard.
    let home = temp.path().join("home");
    copy_into(&source, &home.join(".codex/sessions/2025/11/25/rollout-test.jsonl"));
    let index_data = temp.path().join("index-data");
    let mut cmd = cass_cmd(&home);
    cmd.args(["index", "--full", "--json", "--data-dir", index_data.to_str().unwrap()]);
    run_ok(cmd, "cass index");
    let indexed: Vec<_> = manifest_views(&index_data)
        .expect("manifest views")
        .into_iter()
        .filter(|view| view.agent == "codex" && view.external_id.as_deref() == Some("2025/11/25/rollout-test"))
        .collect();
    assert_eq!(indexed.len(), 1, "exactly one codex manifest carries the session key");
    assert_eq!(indexed[0].identity_host, "local");
    assert_eq!(indexed[0].shape_root.as_deref(), Some("sessions"));
    assert_eq!(indexed[0].relative_path.as_deref(), Some("2025/11/25/rollout-test.jsonl"));
    let mut cmd = cass_cmd(&home);
    cmd.args(["stats", "--json", "--data-dir", index_data.to_str().unwrap()]);
    let stats: Value = serde_json::from_slice(&run_ok(cmd, "cass stats")).expect("stats json");
    assert_eq!(stats["conversations"].as_u64(), Some(1), "session must be ingested: {stats:#}");
}

/// AC-1 (claude_code).
#[test]
fn reparse_identity_roundtrip_claude() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("data");
    let dest = temp.path().join("dest");
    let source = fixture("claude_code_real/projects/-test-project/agent-test123.jsonl");

    let first = single(scan_explicit_file(&ClaudeCodeConnector::new(), &source), "first parse");
    let first_external_id = first.external_id.clone().expect("claude external_id");
    assert_eq!(first_external_id, "-test-project/agent-test123.jsonl");
    assert_eq!(
        split_connector_shape("claude_code", &source),
        Some(("projects".to_string(), PathBuf::from("-test-project/agent-test123.jsonl")))
    );

    let record = capture(&data_dir, &first.agent_slug, &source, "local", Some(&first_external_id))
        .expect("capture");
    let view = view_for(&data_dir, &record);
    assert_eq!(view.identity_host, "local");
    assert_eq!(view.agent, "claude_code");
    assert_eq!(view.external_id.as_deref(), Some(first_external_id.as_str()));
    assert_eq!(view.shape_root.as_deref(), Some("projects"));
    assert_eq!(view.relative_path.as_deref(), Some("-test-project/agent-test123.jsonl"));

    let materialized = materialized_path(
        materialize_capture_to_dest(&data_dir, &record, &dest).expect("materialize"),
    );
    assert_eq!(
        materialized,
        fs::canonicalize(&dest)
            .unwrap()
            .join("local/claude_code/projects/-test-project/agent-test123.jsonl")
    );

    let reparsed = single(
        scan_explicit_file(&ClaudeCodeConnector::new(), &materialized),
        "reparse",
    );
    assert_eq!(reparsed.agent_slug.as_bytes(), view.agent.as_bytes());
    assert_eq!(
        reparsed.external_id.as_deref().map(str::as_bytes),
        view.external_id.as_deref().map(str::as_bytes)
    );

    ensure_manifest_session_key_matches(&data_dir, &record, "claude_code", Some(&first_external_id))
        .expect("manifest key matches first parse");
    assert!(
        ensure_manifest_session_key_matches(&data_dir, &record, "codex", Some(&first_external_id))
            .is_err(),
        "a different agent must be rejected"
    );
}

/// AC-2: two hosts, same `external_id`, different materialized paths; the
/// pre-existing provenance field `origin_host` stays `None` for local.
#[test]
fn hosts_do_not_collide() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("data");
    let dest = temp.path().join("dest");
    let fixture_file = fixture("codex_real/sessions/2025/11/25/rollout-test.jsonl");
    let local_source = temp.path().join("home-local/.codex/sessions/2025/11/25/rollout-test.jsonl");
    let mac_source = temp.path().join("mirror-mac/.codex/sessions/2025/11/25/rollout-test.jsonl");
    copy_into(&fixture_file, &local_source);
    copy_into(&fixture_file, &mac_source);

    let local_first = single(scan_explicit_file(&CodexConnector::new(), &local_source), "local");
    let mac_first = single(scan_explicit_file(&CodexConnector::new(), &mac_source), "mac");
    assert_eq!(local_first.external_id, mac_first.external_id);
    let external_id = local_first.external_id.clone().unwrap();

    let local_record =
        capture(&data_dir, "codex", &local_source, "local", Some(&external_id)).expect("local");
    let mac_record =
        capture(&data_dir, "codex", &mac_source, "ivanmac", Some(&external_id)).expect("mac");
    let local_view = view_for(&data_dir, &local_record);
    let mac_view = view_for(&data_dir, &mac_record);
    assert_eq!(local_view.external_id, mac_view.external_id);
    assert_eq!(local_view.identity_host, "local");
    assert_eq!(mac_view.identity_host, "ivanmac");
    assert_eq!(local_view.origin_host, None, "existing origin_host must stay None for local");

    let local_path = materialized_path(
        materialize_capture_to_dest(&data_dir, &local_record, &dest).expect("local materialize"),
    );
    let mac_path = materialized_path(
        materialize_capture_to_dest(&data_dir, &mac_record, &dest).expect("mac materialize"),
    );
    assert_ne!(local_path, mac_path);
    let canonical_dest = fs::canonicalize(&dest).unwrap();
    assert!(local_path.starts_with(canonical_dest.join("local")));
    assert!(mac_path.starts_with(canonical_dest.join("ivanmac")));

    for (path, view) in [(&local_path, &local_view), (&mac_path, &mac_view)] {
        let reparsed = single(scan_explicit_file(&CodexConnector::new(), path), "reparse");
        assert_eq!(reparsed.agent_slug, view.agent);
        assert_eq!(reparsed.external_id, view.external_id);
    }
}

/// AC-3: same blob -> skip (Ok); different blob -> Err, bytes untouched;
/// symlinked target or ancestor -> rejected as a symlink escape.
#[test]
fn overwrite_policy() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("data");
    let fixture_file = fixture("codex_real/sessions/2025/11/25/rollout-test.jsonl");
    let original_bytes = fs::read(&fixture_file).unwrap();
    let source = temp.path().join("home/.codex/sessions/2025/11/25/rollout-test.jsonl");
    copy_into(&fixture_file, &source);
    let external_id = "2025/11/25/rollout-test";

    let first = capture(&data_dir, "codex", &source, "local", Some(external_id)).expect("capture 1");

    // Same blob twice: first write, then skip.
    let dest = temp.path().join("dest");
    let written = match materialize_capture_to_dest(&data_dir, &first, &dest).expect("first") {
        MirrorMaterializeOutcome::Written(path) => path,
        other => panic!("first materialization must write, got {other:?}"),
    };
    match materialize_capture_to_dest(&data_dir, &first, &dest).expect("same blob must be Ok") {
        MirrorMaterializeOutcome::SkippedIdentical(path) => assert_eq!(path, written),
        other => panic!("same blob must be skipped, got {other:?}"),
    }
    assert_eq!(fs::read(&written).unwrap(), original_bytes);

    // Different blob, same session key and relative shape: refuse, keep bytes.
    let mut changed = original_bytes.clone();
    changed.extend_from_slice(b"\n");
    fs::write(&source, &changed).unwrap();
    let second = capture(&data_dir, "codex", &source, "local", Some(external_id)).expect("capture 2");
    assert_ne!(first.blob_blake3, second.blob_blake3);
    let err = materialize_capture_to_dest(&data_dir, &second, &dest)
        .expect_err("different blob at an existing target must not overwrite");
    assert!(
        format!("{err:#}").contains("E-MIRROR-TARGET-CONFLICT"),
        "unexpected error: {err:#}"
    );
    assert_eq!(fs::read(&written).unwrap(), original_bytes, "existing bytes must be untouched");

    // Target is a symlink to a file outside dest.
    let victim = temp.path().join("victim.txt");
    fs::write(&victim, b"victim").unwrap();
    let dest_link = temp.path().join("dest-link");
    let link_dir = dest_link.join("local/codex/sessions/2025/11/25");
    fs::create_dir_all(&link_dir).unwrap();
    std::os::unix::fs::symlink(&victim, link_dir.join("rollout-test.jsonl")).unwrap();
    let err = materialize_capture_to_dest(&data_dir, &first, &dest_link)
        .expect_err("symlinked target must be rejected");
    assert!(
        format!("{err:#}").contains("E-SCRATCH-SYMLINK-ESCAPE"),
        "unexpected error: {err:#}"
    );
    assert_eq!(fs::read(&victim).unwrap(), b"victim");

    // An ancestor directory is a symlink to a directory outside dest.
    let outside = temp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let dest_anc = temp.path().join("dest-ancestor");
    fs::create_dir_all(dest_anc.join("local/codex")).unwrap();
    std::os::unix::fs::symlink(&outside, dest_anc.join("local/codex/sessions")).unwrap();
    let err = materialize_capture_to_dest(&data_dir, &first, &dest_anc)
        .expect_err("symlinked ancestor must be rejected");
    assert!(
        format!("{err:#}").contains("E-SCRATCH-SYMLINK-ESCAPE"),
        "unexpected error: {err:#}"
    );
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0, "nothing may land outside dest");
}

/// AC-4: a connector outside claude_code/codex keeps the baseline
/// original-path shape and its reparse identity.
#[test]
fn other_connectors_unchanged() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("data");
    let dest = temp.path().join("dest");
    let source = fixture("gemini/hash123/chats/session-test.json");

    let first = single(scan_explicit_file(&GeminiConnector::new(), &source), "first parse");
    assert_eq!(split_connector_shape(&first.agent_slug, &source), None);
    let record = capture(
        &data_dir,
        &first.agent_slug,
        &source,
        "local",
        first.external_id.as_deref(),
    )
    .expect("capture");
    let view = view_for(&data_dir, &record);
    assert_eq!(view.identity_host, "local");
    assert_eq!(view.agent, first.agent_slug);
    assert_eq!(view.external_id, first.external_id);
    assert_eq!(view.shape_root, None);
    assert_eq!(view.relative_path, None);

    let materialized = materialized_path(
        materialize_capture_to_dest(&data_dir, &record, &dest).expect("materialize"),
    );
    let baseline_relative: PathBuf = source
        .components()
        .filter(|c| matches!(c, std::path::Component::Normal(_)))
        .collect();
    assert_eq!(materialized, fs::canonicalize(&dest).unwrap().join(baseline_relative));

    let reparsed = single(scan_explicit_file(&GeminiConnector::new(), &materialized), "reparse");
    assert_eq!(reparsed.agent_slug, first.agent_slug);
    assert_eq!(reparsed.external_id, first.external_id);
}

/// AC-5: path encoding must stay inside dest.
#[test]
fn path_encoding_rejects_escape() {
    assert_eq!(
        mirror_shape_relative_path("ivan-mac.01_x", "codex", "sessions", "2025/11/25/r.jsonl")
            .expect("valid encoding"),
        PathBuf::from("ivan-mac.01_x/codex/sessions/2025/11/25/r.jsonl")
    );
    for relative in ["../escape.jsonl", "2025/../../escape.jsonl", "/etc/passwd", ""] {
        assert!(
            mirror_shape_relative_path("local", "codex", "sessions", relative).is_err(),
            "relative_path {relative:?} must be rejected"
        );
    }
    let too_long = "h".repeat(65);
    for host in ["", "ivan mac", "../evil", "a/b", "主机", too_long.as_str()] {
        assert!(
            mirror_shape_relative_path(host, "codex", "sessions", "2025/r.jsonl").is_err(),
            "identity_host {host:?} must be rejected"
        );
    }
    assert!(mirror_shape_relative_path(&"h".repeat(64), "codex", "sessions", "r.jsonl").is_ok());

    // End to end: a capture whose relative shape carries `..` is recorded
    // as-is but refused at materialization, and nothing is written.
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("data");
    let sessions = temp.path().join("home/.codex/sessions");
    fs::create_dir_all(sessions.join("a")).unwrap();
    copy_into(
        &fixture("codex_real/sessions/2025/11/25/rollout-test.jsonl"),
        &sessions.join("rollout-esc.jsonl"),
    );
    let dotted = sessions.join("a/../rollout-esc.jsonl");
    let record = capture(&data_dir, "codex", &dotted, "local", Some("rollout-esc")).expect("capture");
    let view = view_for(&data_dir, &record);
    assert_eq!(view.relative_path.as_deref(), Some("a/../rollout-esc.jsonl"));
    let dest = temp.path().join("dest");
    assert!(materialize_capture_to_dest(&data_dir, &record, &dest).is_err());
    assert!(!dest.join("local").exists(), "nothing may be materialized for an escaping shape");

    // An invalid identity_host is refused at capture time as well.
    assert!(
        capture(&data_dir, "codex", &sessions.join("rollout-esc.jsonl"), "../evil", None).is_err()
    );
}

/// AC-7: `cass doctor` recomputes the same self-digest for a manifest carrying
/// the session key (no `manifest_drift`), the five fields are inside that
/// digest, and a legacy manifest without them keeps its digest.
#[test]
fn doctor_digest_matches_new_manifest() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let data_dir = temp.path().join("cass-data");
    let mut cmd = cass_cmd(&home);
    cmd.args(["index", "--force-rebuild", "--json", "--data-dir", data_dir.to_str().unwrap()]);
    run_ok(cmd, "seed index");

    let root = data_dir.join("raw-mirror/v1");
    let new_source = fixture("codex_real/sessions/2025/11/25/rollout-test.jsonl");
    let new_record =
        capture(&data_dir, "codex", &new_source, "local", Some("2025/11/25/rollout-test"))
            .expect("capture new");
    let new_json: Value =
        serde_json::from_slice(&fs::read(root.join(&new_record.manifest_relative_path)).unwrap())
            .unwrap();
    for field in ["identity_host", "agent", "external_id", "shape_root", "relative_path"] {
        assert!(new_json.get(field).is_some(), "new manifest must carry {field}: {new_json:#}");
    }
    assert_eq!(
        new_json["manifest_blake3"].as_str(),
        Some(independent_manifest_digest(&new_json).as_str()),
        "the session key fields must be covered by the self-digest"
    );

    // Legacy manifest: strip the five fields, seal it with the digest over
    // exactly the remaining (pre-PR8) field set.
    let legacy_source = temp.path().join("legacy/session.jsonl");
    copy_into(&fixture("codex_real/sessions/2025/11/26/rollout-tool-call.jsonl"), &legacy_source);
    let legacy_record = capture_source_file(RawMirrorCaptureInput {
        data_dir: &data_dir,
        provider: "codex",
        source_id: "local",
        origin_kind: "local",
        origin_host: None,
        source_path: &legacy_source,
        db_links: &[],
    })
    .expect("capture legacy");
    let legacy_path = root.join(&legacy_record.manifest_relative_path);
    let mut legacy_json: Value = serde_json::from_slice(&fs::read(&legacy_path).unwrap()).unwrap();
    for field in SESSION_KEY_FIELDS {
        legacy_json.as_object_mut().unwrap().remove(field);
    }
    let legacy_digest = independent_manifest_digest(&legacy_json);
    legacy_json["manifest_blake3"] = Value::String(legacy_digest.clone());
    fs::write(&legacy_path, serde_json::to_vec_pretty(&legacy_json).unwrap()).unwrap();
    assert_eq!(
        recompute_manifest_blake3(&data_dir, &legacy_record.manifest_relative_path).unwrap(),
        legacy_digest,
        "a legacy manifest's digest must not change"
    );

    let mut cmd = cass_cmd(&home);
    cmd.args(["doctor", "--json", "--data-dir", data_dir.to_str().unwrap()]);
    let out = cmd.output().expect("run cass doctor");
    let payload: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|err| {
        panic!(
            "doctor json ({err}): stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let manifests = payload["raw_mirror"]["manifests"].as_array().expect("raw_mirror.manifests");
    for record in [&new_record, &legacy_record] {
        let report = manifests
            .iter()
            .find(|m| m["manifest_id"].as_str() == Some(record.manifest_id.as_str()))
            .unwrap_or_else(|| panic!("doctor report for {}: {manifests:#?}", record.manifest_id));
        assert_eq!(report["manifest_checksum_status"].as_str(), Some("matched"), "{report:#}");
        assert_ne!(report["status"].as_str(), Some("manifest_drift"), "{report:#}");
    }
    assert_eq!(
        payload["raw_mirror"]["summary"]["manifest_checksum_mismatch_count"].as_u64(),
        Some(0)
    );
}
