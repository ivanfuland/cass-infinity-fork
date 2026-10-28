//! One declared restore source input, prepared against its recorded capture.
//!
//! The declaration is not evidence. This adapter binds one caller declaration
//! to one same-capture manifest record, then hands the pair to the existing
//! sealed-preparation entry. It never reads the live source, never discovers or
//! loads a configuration, never captures and never writes to the database.
//!
//! The order below is also the error priority: a malformed declaration is
//! refused before any file is opened, and every material disagreement after
//! that answers with the same fixed code.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use franken_agent_detection as fad;

use crate::indexer::source_ingest::{
    fad_connector_name, prepare_sealed_source_input, FixedSafetyConfig, SealedSourceInputRequest,
    SourceIngestError, SourceInputJob, SourceMappingDomain, SEALED_ROLES,
};
use crate::phase3_bundle::Origin;
use crate::phase3_restore::normalize_provider_to_origin;
use crate::raw_mirror::{open_verified_capture, RawMirrorCaptureRecord};

use super::source_contexts::RestoreSourceContextDeclaration;

const CONTEXT_INVALID: &str = "source_restore_context_invalid";
const MATERIAL_MISMATCH: &str = "source_restore_material_mismatch";

fn context_invalid() -> SourceIngestError {
    SourceIngestError::Config { detail: CONTEXT_INVALID.to_string() }
}

fn material_mismatch() -> SourceIngestError {
    SourceIngestError::Config { detail: MATERIAL_MISMATCH.to_string() }
}

/// The FAD connector name a declaration must spell for one classified provider.
///
/// Only the first batch is accepted: a provider outside `claude_code` and
/// `codex` has no sealed read, so it is a material mismatch rather than a
/// declaration error.
fn connector_for(provider: &str) -> Option<(&'static str, &'static str)> {
    match normalize_provider_to_origin(provider)? {
        Origin::ClaudeCode => Some(("claude", "claude_code")),
        Origin::Codex => Some(("codex", "codex")),
        Origin::Openclaw => None,
    }
}

/// Whether a declared relative locator is the clean relative form the pinned
/// FAD discovery uses: non-empty, `/`-separated with no empty, `.` or `..`
/// segment, and every native path component `Normal`.
fn is_clean_relative(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// Prepare the input one declaration names for one already recorded capture.
///
/// The seven steps are the spec's fixed order. Every refusal is one of the two
/// short codes; no material value, path, provider or parser debug reaches the
/// returned error.
///
/// This wrapper keeps the producer default mapping identity. A restore journal
/// that declares another readable identity uses
/// [`prepare_declared_restore_source_input_for_mapping`].
pub(crate) fn prepare_declared_restore_source_input(
    data_dir: &Path,
    capture: &RawMirrorCaptureRecord,
    declaration: &RestoreSourceContextDeclaration,
    safety: Arc<FixedSafetyConfig>,
) -> Result<SourceInputJob, SourceIngestError> {
    prepare_declared_restore_source_input_for_mapping(
        data_dir,
        capture,
        declaration,
        safety,
        SourceMappingDomain::CURRENT,
        None,
    )
}

/// The same preparation under one declared mapping identity.
///
/// A restore journal names the identity its bindings were produced under; the
/// seven-field proof downstream re-derives the job under exactly that identity.
/// `claimed_normalizer_id` carries a digest-only binding claim when the caller
/// has one: the declared identity then has to be the unique readable match for
/// it, and a mismatch is the same fixed material refusal as every other step.
pub(crate) fn prepare_declared_restore_source_input_for_mapping(
    data_dir: &Path,
    capture: &RawMirrorCaptureRecord,
    declaration: &RestoreSourceContextDeclaration,
    safety: Arc<FixedSafetyConfig>,
    mapping_domain: SourceMappingDomain,
    claimed_normalizer_id: Option<&str>,
) -> Result<SourceInputJob, SourceIngestError> {
    // 1. The declaration alone. Strings keep their original spelling; only the
    // namespace's trimmed emptiness and the locator's shape are inspected.
    let declared_fad_connector = match declaration.connector.as_str() {
        "claude_code" => "claude_code",
        "codex" => "codex",
        _ => return Err(context_invalid()),
    };
    if declaration.identity_namespace.trim().is_empty() {
        return Err(context_invalid());
    }
    if declaration.origin.source_id.is_empty() {
        return Err(context_invalid());
    }
    if declaration.scan_root.is_empty() {
        return Err(context_invalid());
    }
    if !is_clean_relative(&declaration.relative_locator) {
        return Err(context_invalid());
    }
    if !SEALED_ROLES.contains(&declaration.role) {
        return Err(context_invalid());
    }

    // 2. One manifest identity check, then the one existing opener.
    if declaration.manifest_id != capture.manifest_id {
        return Err(material_mismatch());
    }
    let verified = open_verified_capture(data_dir, capture).map_err(|_| material_mismatch())?;

    // 3. The same recorded capture decides the provider. The original provider
    // text is never rewritten, trimmed or case-folded.
    let recorded = verified.recorded_metadata();
    let (cass_connector, _) =
        connector_for(&recorded.provider).ok_or_else(material_mismatch)?;
    if fad_connector_name(cass_connector) != declared_fad_connector {
        return Err(material_mismatch());
    }
    if declaration.origin.source_id != recorded.source_id
        || declaration.origin.kind.as_str() != recorded.origin_kind
        || declaration.origin.host.as_deref() != recorded.origin_host.as_deref()
    {
        return Err(material_mismatch());
    }

    // 4. The logical root joined with the declared locator must spell the
    // recorded original path. This is a lexical comparison: no live stat, no
    // symlink probe, no canonicalisation.
    let joined = PathBuf::from(&declaration.scan_root).join(&declaration.relative_locator);
    if joined != Path::new(verified.original_path()) {
        return Err(material_mismatch());
    }

    // 5. The fixed safety copy is re-read, then one single construction supplies
    // the root, the descriptor and the parser context.
    safety.recheck_bytes().map_err(|_| material_mismatch())?;

    let origin = fad::Origin {
        source_id: declaration.origin.source_id.clone(),
        kind: declaration.origin.kind,
        host: declaration.origin.host.clone(),
    };
    let scan_root = PathBuf::from(&declaration.scan_root);

    let mut root = crate::connectors::ScanRoot::remote(
        scan_root.clone(),
        origin.clone(),
        declaration.platform,
    );
    root.workspace_rewrites = declaration.workspace_rewrites.clone();

    let source_origin = fad::SourceOrigin {
        origin,
        source_version: declaration.origin.source_version.clone(),
    };
    let descriptor = fad::SourceInputDescriptor {
        connector: declared_fad_connector.to_string(),
        scan_root: scan_root.clone(),
        source_path: PathBuf::from(verified.original_path()),
        relative_locator: declaration.relative_locator.clone(),
        role: declaration.role,
        origin: source_origin.clone(),
        platform: declaration.platform,
        // The sealed blob's measured length, never a caller or live stat value.
        size_bytes: Some(verified.blob_size_bytes()),
        // The same-capture recorded mtime, never the caller's.
        modified_at_ms: recorded.source_mtime_ms,
    };
    let parser_context = fad::SourceParserContext {
        schema: "cass.source-parser-context/1".to_string(),
        connector: declared_fad_connector.to_string(),
        roots: vec![fad::SourceParserRoot {
            path: scan_root,
            origin: source_origin,
            platform: declaration.platform,
            workspace_rewrites: declaration.workspace_rewrites.clone(),
        }],
        relative_locator: declaration.relative_locator.clone(),
        role: declaration.role,
        effective_config_digest: None,
    };

    // 6. The routing identity comes from the declared namespace; the record
    // handed downstream is a local copy whose two times are the recorded ones.
    let identity = crate::indexer::IngestIdentity::for_manifest(&declaration.identity_namespace);
    let mut prepared_capture = capture.clone();
    prepared_capture.captured_at_ms = recorded.captured_at_ms;
    prepared_capture.source_mtime_ms = recorded.source_mtime_ms;
    prepared_capture.already_present = true;

    // 7. One existing shared preparation, with the connector selected from the
    // already verified provider.
    let connector: Box<dyn crate::connectors::Connector + Send> = if cass_connector == "claude" {
        Box::new(crate::connectors::claude_code::ClaudeCodeConnector::new())
    } else {
        Box::new(crate::connectors::codex::CodexConnector::new())
    };
    prepare_sealed_source_input(
        connector.as_ref(),
        &SealedSourceInputRequest {
            connector_name: cass_connector,
            data_dir,
            root: &root,
            root_id: identity.root_id.as_str(),
            identity_namespace: &declaration.identity_namespace,
            descriptor: &descriptor,
            parser_context: &parser_context,
            capture: &prepared_capture,
            verified: &verified,
            safety: &safety,
            mapping_domain,
            claimed_normalizer_id,
        },
    )
    .map_err(|_| material_mismatch())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::AssertUnwindSafe;

    use crate::indexer::source_ingest::{
        load_fixed_safety_config, prepare_source_input, SourceInputRequest, SourceProfile,
    };
    use crate::phase3_restore::source_contexts::RestoreSourceContextOrigin;
    use crate::raw_mirror::{
        capture_source_file_with_identity, recompute_manifest_blake3, RawMirrorCaptureInput,
        RawMirrorSessionIdentity, RAW_MIRROR_LOCAL_IDENTITY_HOST,
    };
    use crate::storage::source_facts::{CanonicalTuple, SourceFormat};

    const FIXED_SAFETY_UTF8: &str =
        "memory_files = []\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n";

    struct Payload {
        bytes: &'static [u8],
        sha: &'static str,
    }

    static CLAUDE_JSONL: Payload = Payload {
        bytes: br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C44 question"}}
{"type":"assistant","uuid":"C44-A","timestamp":"2026-01-01T00:00:01.000Z","message":{"role":"assistant","content":[{"type":"text","text":"C44 answer"}],"model":"C44-model"}}
"#,
        sha: "c675f87354f7cb219f991070431b98408c8ec841d8dfcc8cf69cca3af100e8fb",
    };

    static CODEX_JSONL: Payload = Payload {
        bytes: br#"{"timestamp":"2026-01-01T00:00:00.000Z","type":"session_meta","payload":{"id":"C44-CODEX","cwd":"/synthetic/c44-project","cli_version":"0.42.0"}}
{"timestamp":"2026-01-01T00:00:01.000Z","type":"response_item","payload":{"type":"message","id":"C44-U","role":"user","content":[{"type":"input_text","text":"C44 question"}]}}
{"timestamp":"2026-01-01T00:00:02.000Z","type":"response_item","payload":{"type":"message","id":"C44-A","role":"assistant","content":[{"type":"output_text","text":"C44 answer"}]}}
"#,
        sha: "d50dd595f1a3a3111fffc9bdb0eff1059826071ab4164a6fc878b284b7fad3c6",
    };

    static CLAUDE_DOCUMENT: Payload = Payload {
        bytes: br#"{
  "cwd": "/synthetic/c44-project",
  "sessionId": "C44-CLAUDE",
  "version": "2.0.37",
  "messages": [
    {
      "role": "user",
      "content": "C44 question",
      "timestamp": "2026-01-01T00:00:00.000Z"
    },
    {
      "role": "assistant",
      "content": [
        {
          "type": "text",
          "text": "C44 answer"
        }
      ],
      "timestamp": "2026-01-01T00:00:01.000Z"
    }
  ]
}
"#,
        sha: "2fdf8eb31971bfa0603cb64dd6d8f4305c0463504e5447266df72411bb0a2118",
    };

    static CODEX_DOCUMENT: Payload = Payload {
        bytes: br#"{
  "session": {
    "id": "C44-CODEX",
    "cwd": "/synthetic/c44-project",
    "cli_version": "0.42.0"
  },
  "items": [
    {
      "type": "message",
      "role": "user",
      "content": [
        {
          "type": "input_text",
          "text": "C44 question"
        }
      ],
      "timestamp": "2026-01-01T00:00:00.000Z"
    },
    {
      "type": "message",
      "role": "assistant",
      "content": [
        {
          "type": "output_text",
          "text": "C44 answer"
        }
      ],
      "timestamp": "2026-01-01T00:00:01.000Z"
    }
  ]
}
"#,
        sha: "b1f4f4c63f2a33b69c518c6fcab467b2d627e8df2843a7c2774f080177a01eec",
    };

    static EMPTY_JSONL: Payload = Payload {
        bytes: b"",
        sha: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    };

    static PARSE_FAILED_JSONL: Payload = Payload {
        bytes: br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C44 question"}}
{"type":"assistant","uuid":"C44-A","timestamp":"2026-01-01T00:00:01.000Z","message":{"role":"assistant","content":[{"type":"text","text":"C44 answer"}],"model":"C44-model"}}
{C44_BAD_JSON}
"#,
        sha: "effcc439599d87c1c49b885f4470e0bfa4e981cc0b3790cc9aecb3e859b79b25",
    };

    #[derive(Clone)]
    struct Spec {
        provider: &'static str,
        source_id: &'static str,
        origin_kind: fad::types::SourceKind,
        origin_host: Option<&'static str>,
        namespace: &'static str,
        scan_root_suffix: &'static str,
        relative_locator: &'static str,
        connector: &'static str,
        role: fad::SourceInputRole,
        source_version: Option<&'static str>,
        platform: Option<fad::types::Platform>,
        rewrites: Vec<fad::types::PathMapping>,
        captured_at_ms: i64,
        source_mtime_ms: Option<i64>,
        self_digest: bool,
        payload: &'static Payload,
        relative_root: bool,
        records: u64,
        conversations: u64,
        parse_failed: u64,
    }

    fn base_spec() -> Spec {
        Spec {
            provider: "claude",
            source_id: "C44_SOURCE",
            origin_kind: fad::types::SourceKind::Local,
            origin_host: None,
            namespace: "C44_NAMESPACE",
            scan_root_suffix: "logical/dir",
            relative_locator: "session.jsonl",
            connector: "claude_code",
            role: fad::SourceInputRole::PrimarySessionLog,
            source_version: None,
            platform: None,
            rewrites: Vec::new(),
            captured_at_ms: 43,
            source_mtime_ms: Some(-7),
            self_digest: true,
            payload: &CLAUDE_JSONL,
            relative_root: false,
            records: 2,
            conversations: 1,
            parse_failed: 0,
        }
    }

    struct Scenario {
        _temp: tempfile::TempDir,
        data_dir: PathBuf,
        safety: Arc<FixedSafetyConfig>,
        capture: RawMirrorCaptureRecord,
        declaration: RestoreSourceContextDeclaration,
        scan_root_text: String,
        live_path: PathBuf,
        original_path: String,
        fixed_path: PathBuf,
    }

    fn declaration_for(
        spec: &Spec,
        capture: &RawMirrorCaptureRecord,
        scan_root: String,
    ) -> RestoreSourceContextDeclaration {
        RestoreSourceContextDeclaration {
            manifest_id: capture.manifest_id.clone(),
            identity_namespace: spec.namespace.to_string(),
            connector: spec.connector.to_string(),
            scan_root,
            relative_locator: spec.relative_locator.to_string(),
            role: spec.role,
            origin: RestoreSourceContextOrigin {
                source_id: spec.source_id.to_string(),
                kind: spec.origin_kind,
                host: spec.origin_host.map(str::to_string),
                source_version: spec.source_version.map(str::to_string),
            },
            platform: spec.platform,
            workspace_rewrites: spec.rewrites.clone(),
        }
    }

    fn relative_from_cwd(target: &Path) -> PathBuf {
        let cwd = std::env::current_dir().expect("the test working directory");
        let base: Vec<Component> = cwd.components().collect();
        let parts: Vec<Component> = target.components().collect();
        let mut common = 0;
        while common < base.len() && common < parts.len() && base[common] == parts[common] {
            common += 1;
        }
        let mut out = PathBuf::new();
        for _ in common..base.len() {
            out.push("..");
        }
        for part in &parts[common..] {
            out.push(part.as_os_str());
        }
        out
    }

    fn build(spec: &Spec) -> Scenario {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let fixed_path = temp.path().join("fixed-safety.toml");
        std::fs::write(&fixed_path, FIXED_SAFETY_UTF8).expect("write the fixed copy");
        let safety = Arc::new(load_fixed_safety_config(&fixed_path).expect("load the fixed copy"));

        let logical_dir = temp.path().join(spec.scan_root_suffix);
        let live_path = logical_dir.join(spec.relative_locator);
        std::fs::create_dir_all(live_path.parent().expect("the live parent"))
            .expect("mkdir the live parent");
        std::fs::write(&live_path, spec.payload.bytes).expect("write the payload");

        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("mkdir data");

        let captured_source_path = if spec.relative_root {
            relative_from_cwd(&logical_dir).join(spec.relative_locator)
        } else {
            live_path.clone()
        };
        let capture = capture_source_file_with_identity(
            RawMirrorCaptureInput {
                data_dir: &data_dir,
                provider: spec.provider,
                source_id: spec.source_id,
                origin_kind: spec.origin_kind.as_str(),
                origin_host: spec.origin_host,
                source_path: &captured_source_path,
                db_links: &[],
            },
            RawMirrorSessionIdentity {
                identity_host: RAW_MIRROR_LOCAL_IDENTITY_HOST,
                external_id: None,
            },
        )
        .expect("capture the fixture");

        rewrite_manifest(
            &data_dir,
            &capture,
            spec.captured_at_ms,
            spec.source_mtime_ms,
            spec.self_digest,
        );

        let scan_root_text = if spec.relative_root {
            relative_from_cwd(&logical_dir).to_string_lossy().into_owned()
        } else {
            logical_dir.to_string_lossy().into_owned()
        };
        let declaration = declaration_for(spec, &capture, scan_root_text.clone());
        let original_path = captured_source_path.to_string_lossy().into_owned();

        Scenario {
            _temp: temp,
            data_dir,
            safety,
            capture,
            declaration,
            scan_root_text,
            live_path,
            original_path,
            fixed_path,
        }
    }

    fn rewrite_manifest(
        data_dir: &Path,
        capture: &RawMirrorCaptureRecord,
        captured_at_ms: i64,
        source_mtime_ms: Option<i64>,
        keep_self_digest: bool,
    ) {
        let path = data_dir
            .join("raw-mirror")
            .join("v1")
            .join(&capture.manifest_relative_path);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read the manifest"))
                .expect("decode the manifest");
        manifest["captured_at_ms"] = serde_json::json!(captured_at_ms);
        manifest["source_mtime_ms"] = serde_json::json!(source_mtime_ms);
        if !keep_self_digest {
            manifest
                .as_object_mut()
                .expect("manifest object")
                .remove("manifest_blake3");
        }
        std::fs::write(&path, serde_json::to_vec(&manifest).expect("encode the manifest"))
            .expect("write the manifest");
        if keep_self_digest {
            let digest = recompute_manifest_blake3(data_dir, &capture.manifest_relative_path)
                .expect("recompute the manifest self digest");
            manifest["manifest_blake3"] = serde_json::json!(digest);
            std::fs::write(&path, serde_json::to_vec(&manifest).expect("encode the manifest"))
                .expect("write the manifest");
        }
    }

    fn mirror_digest(data_dir: &Path) -> String {
        fn walk(root: &Path, base: &Path, out: &mut Vec<(String, String)>) {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
                .expect("read the mirror directory")
                .map(|entry| entry.expect("read entry").path())
                .collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    walk(&path, base, out);
                } else {
                    let bytes = std::fs::read(&path).expect("read the mirror file");
                    out.push((
                        path.strip_prefix(base)
                            .expect("inside the mirror")
                            .to_string_lossy()
                            .into_owned(),
                        crate::storage::source_facts::Sha256Digest::of(&bytes).hex(),
                    ));
                }
            }
        }
        let root = data_dir.join("raw-mirror");
        let mut out = Vec::new();
        if root.exists() {
            walk(&root, &root, &mut out);
        }
        out.sort();
        out.into_iter()
            .map(|(path, digest)| format!("{path}={digest}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn prepare(
        data_dir: &Path,
        capture: &RawMirrorCaptureRecord,
        declaration: &RestoreSourceContextDeclaration,
        safety: &Arc<FixedSafetyConfig>,
    ) -> Result<SourceInputJob, SourceIngestError> {
        prepare_declared_restore_source_input(
            data_dir,
            capture,
            declaration,
            Arc::clone(safety),
        )
    }

    struct Expected {
        cass_connector: &'static str,
        tuple: Vec<Option<String>>,
        input_key: String,
        normalizer_id: String,
        safety_contract_id: String,
        format: SourceFormat,
    }

    fn expected_format(cass_connector: &str, locator: &str) -> SourceFormat {
        let extension = Path::new(locator)
            .extension()
            .and_then(std::ffi::OsStr::to_str);
        let document = match (cass_connector, extension) {
            ("claude", Some(extension)) => {
                extension.eq_ignore_ascii_case("json") || extension.eq_ignore_ascii_case("claude")
            }
            ("codex", Some(extension)) => extension.eq_ignore_ascii_case("json"),
            _ => false,
        };
        if document {
            SourceFormat::JsonDocument
        } else {
            SourceFormat::Jsonl
        }
    }

    fn independent_expected(
        spec: &Spec,
        scan_root: &str,
        safety: &FixedSafetyConfig,
    ) -> Expected {
        independent_expected_with_domain(
            spec,
            scan_root,
            safety,
            SourceMappingDomain::CURRENT,
        )
    }

    /// The same independent oracle under one explicit mapping identity.
    fn independent_expected_with_domain(
        spec: &Spec,
        scan_root: &str,
        safety: &FixedSafetyConfig,
        mapping_domain: SourceMappingDomain,
    ) -> Expected {
        let cass_connector = match spec.connector {
            "claude_code" => "claude",
            "codex" => "codex",
            other => panic!("unexpected declared connector {other}"),
        };
        let fad_connector = fad_connector_name(cass_connector);
        let effective_material = serde_json::json!({
            "schema": "cass.source-parser-context/1",
            "connector": &fad_connector,
            "roots": [{
                "path": scan_root,
                "origin": {
                    "kind": spec.origin_kind,
                    "host": spec.origin_host,
                    "source_version": spec.source_version,
                },
                "platform": spec.platform,
                "workspace_rewrites": &spec.rewrites,
            }],
            "role": spec.role,
        });
        let profile = SourceProfile::assemble_with_mapping_domain(
            safety,
            &effective_material,
            mapping_domain,
        )
        .expect("assemble the independent profile");
        let context_wire = serde_json::json!({
            "schema": "cass.source-parser-context/1",
            "connector": &fad_connector,
            "discovery_roots": [scan_root],
            "since_ts": null,
            "relative_locator": spec.relative_locator,
            "role": spec.role,
            "origin": {
                "kind": spec.origin_kind,
                "host": spec.origin_host,
                "source_version": spec.source_version,
            },
            "platform": spec.platform,
            "workspace_rewrites": &spec.rewrites,
            "effective_config_summary": {
                "effective_digest": profile.effective_config_digest.clone(),
            },
        });
        let lossless = fad::LosslessSourceValue::parse(
            &serde_json::to_vec(&context_wire).expect("encode the manual context"),
        )
        .expect("parse the manual context");
        let context_digest = crate::storage::source_facts::context_digest(&lossless)
            .expect("digest the manual context")
            .hex();
        let tuple = vec![
            Some("cass.source-input/2".to_string()),
            Some(spec.namespace.to_string()),
            Some(spec.source_id.to_string()),
            Some(fad_connector.clone()),
            Some(scan_root.to_string()),
            Some(spec.relative_locator.to_string()),
            Some(spec.role.as_str().to_string()),
            Some(spec.origin_kind.as_str().to_string()),
            spec.origin_host.map(str::to_string),
            spec.source_version.map(str::to_string),
            spec.platform.map(|platform| platform.to_string()),
            Some(context_digest),
            Some(spec.payload.sha.to_string()),
            Some(profile.normalizer_id.clone()),
            Some(profile.safety_contract_id.clone()),
        ];
        let mut writer = CanonicalTuple::new();
        for item in &tuple {
            writer.opt_str(item.as_deref());
        }
        Expected {
            cass_connector,
            tuple,
            input_key: writer.finish_sha().hex(),
            normalizer_id: profile.normalizer_id,
            safety_contract_id: profile.safety_contract_id,
            format: expected_format(cass_connector, spec.relative_locator),
        }
    }

    fn assert_matches(
        spec: &Spec,
        expected: &Expected,
        scenario: &Scenario,
        scan_root: &str,
        job: &SourceInputJob,
    ) {
        assert_eq!(job.connector_name, expected.cass_connector);
        assert_eq!(job.root_id, format!("restore:{}", spec.namespace));
        assert_eq!(job.root.path, PathBuf::from(scan_root));
        assert_eq!(job.root.origin.source_id, spec.source_id);
        assert_eq!(job.root.origin.kind, spec.origin_kind);
        assert_eq!(job.root.origin.host, spec.origin_host.map(str::to_string));
        assert_eq!(job.root.platform, spec.platform);
        assert_eq!(job.root.workspace_rewrites, spec.rewrites);

        assert_eq!(job.capture.manifest_id, scenario.capture.manifest_id);
        assert_eq!(job.capture.captured_at_ms, spec.captured_at_ms);
        assert_eq!(job.capture.source_mtime_ms, spec.source_mtime_ms);
        assert!(job.capture.already_present);
        assert_eq!(job.original_path, scenario.original_path);

        assert_eq!(job.normalizer_id, expected.normalizer_id);
        assert_eq!(job.safety_contract_id, expected.safety_contract_id);

        assert_eq!(job.input.identity_tuple(), expected.tuple.as_slice());
        assert_eq!(job.input.input_key().hex(), expected.input_key);

        let manifest = job.input.manifest();
        assert_eq!(manifest.sealed_sha256().hex(), spec.payload.sha);
        assert_eq!(manifest.byte_len(), spec.payload.bytes.len() as u64);
        assert_eq!(manifest.format(), expected.format);
        assert_eq!(manifest.records(), spec.records);
        assert!(manifest.complete());

        assert_eq!(job.finish.records_seen, spec.records);
        assert_eq!(job.finish.parse_failed, spec.parse_failed);
        assert_eq!(job.records.len() as u64, spec.records);
        assert_eq!(job.conversations.len() as u64, spec.conversations);
    }

    fn success(scenario: &Scenario) -> SourceInputJob {
        prepare(
            &scenario.data_dir,
            &scenario.capture,
            &scenario.declaration,
            &scenario.safety,
        )
        .expect("the declared input must prepare")
    }

    fn pass(test: &str, case: &str) {
        println!("RESTORE_DECLARED_INPUT_SCENARIO test={test} case={case} result=pass");
    }

    fn assert_success(
        scenario: &Scenario,
        spec: &Spec,
        expected: &Expected,
    ) -> SourceInputJob {
        let job = success(scenario);
        assert_matches(spec, expected, scenario, &scenario.scan_root_text, &job);
        job
    }

    fn assert_refused(
        scenario: &Scenario,
        declaration: &RestoreSourceContextDeclaration,
        capture: &RawMirrorCaptureRecord,
        code: &str,
    ) {
        let before = mirror_digest(&scenario.data_dir);
        let error = prepare(&scenario.data_dir, capture, declaration, &scenario.safety)
            .expect_err("the case must be refused");
        assert_eq!(
            error.to_string(),
            format!("source safety configuration: {code}")
        );
        match error {
            SourceIngestError::Config { detail } => {
                assert_eq!(detail, code);
                assert!(!detail.contains("C44"), "no private material in {detail}");
                assert!(!detail.contains('/'), "no path fragment in {detail}");
            }
            other => panic!("unexpected error variant: {other}"),
        }
        assert_eq!(
            mirror_digest(&scenario.data_dir),
            before,
            "the sealed mirror must not change"
        );
        assert!(!scenario.data_dir.join("agent_search.db").exists());
    }

    fn assert_control(scenario: &Scenario) {
        prepare(
            &scenario.data_dir,
            &scenario.capture,
            &scenario.declaration,
            &scenario.safety,
        )
        .expect("the successful control must prepare");
    }

    fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
        if let Some(text) = payload.downcast_ref::<&str>() {
            (*text).to_string()
        } else if let Some(text) = payload.downcast_ref::<String>() {
            text.clone()
        } else {
            "non-string panic".to_string()
        }
    }

    fn conversation_text(job: &SourceInputJob) -> String {
        job.conversations
            .iter()
            .flat_map(|item| item.conversation.messages.iter())
            .map(|message| message.content.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn assert_ordinary_matches(scenario: &Scenario, spec: &Spec, job: &SourceInputJob) {
        let discovered = crate::connectors::DiscoveredSourceFile {
            provider_slug: "claude_code".to_string(),
            scan_root: PathBuf::from(&scenario.scan_root_text),
            source_path: scenario.live_path.clone(),
            role: crate::connectors::DiscoveredSourceRole::PrimarySessionLog,
            origin: fad::Origin {
                source_id: spec.source_id.to_string(),
                kind: spec.origin_kind,
                host: spec.origin_host.map(str::to_string),
            },
            platform: spec.platform,
            required_for_reconstruction: true,
            size_bytes: None,
            modified_at_ms: None,
        };
        let mut root = crate::connectors::ScanRoot::remote(
            PathBuf::from(&scenario.scan_root_text),
            discovered.origin.clone(),
            spec.platform,
        );
        root.workspace_rewrites = spec.rewrites.clone();
        let meta = crate::indexer::scan_root_meta::ScanRootMeta {
            root_id: "route:claude:task44".to_string(),
            origin_host: spec.namespace.to_string(),
            readonly: false,
            canonical_path: root.path.clone(),
            source_name: "claude".to_string(),
            watermarks_enabled: true,
            mirror_root: false,
        };
        let connector = crate::connectors::claude_code::ClaudeCodeConnector::new();
        let ordinary = prepare_source_input(
            &connector,
            &SourceInputRequest {
                connector_name: "claude",
                data_dir: &scenario.data_dir,
                root: &root,
                meta: &meta,
                discovered: &discovered,
                safety: &scenario.safety,
            },
        )
        .expect("the ordinary entry prepares the same fixture");
        assert_eq!(ordinary.input.input_key(), job.input.input_key());
        assert_eq!(ordinary.normalizer_id, job.normalizer_id);
        assert_eq!(ordinary.safety_contract_id, job.safety_contract_id);
        assert_eq!(
            ordinary.input.identity_tuple()[11],
            job.input.identity_tuple()[11]
        );
    }

    #[test]
    fn b1_declared_inputs_prepare() {
        const TEST: &str = "b1_declared_inputs_prepare";

        // claude_jsonl: the absolute-path, source_version=None material also
        // has to agree with the ordinary preparation entry.
        let spec = base_spec();
        let scenario = build(&spec);
        let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
        let job = assert_success(&scenario, &spec, &expected);
        assert_eq!(
            job.input.identity_tuple()[10],
            None,
            "the fixture declares no platform"
        );
        assert_ordinary_matches(&scenario, &spec, &job);
        pass(TEST, "claude_jsonl");

        // claude_legacy_provider: the historical provider spelling classifies
        // the same, and a Missing self-digest stays Missing.
        let mut spec = base_spec();
        spec.provider = "claude_code";
        spec.self_digest = false;
        spec.captured_at_ms = -43;
        spec.source_mtime_ms = None;
        let scenario = build(&spec);
        let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
        assert_success(&scenario, &spec, &expected);
        pass(TEST, "claude_legacy_provider");

        // codex_jsonl: an ssh origin with a host, three records.
        let mut spec = base_spec();
        spec.provider = "codex";
        spec.connector = "codex";
        spec.payload = &CODEX_JSONL;
        spec.relative_locator = "rollout-c44.jsonl";
        spec.origin_kind = fad::types::SourceKind::Ssh;
        spec.origin_host = Some("C44_HOST");
        spec.records = 3;
        let scenario = build(&spec);
        let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
        assert_success(&scenario, &spec, &expected);
        pass(TEST, "codex_jsonl");

        // claude_document: a whole JSON document, one record.
        let mut spec = base_spec();
        spec.payload = &CLAUDE_DOCUMENT;
        spec.relative_locator = "session.json";
        spec.records = 1;
        let scenario = build(&spec);
        let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
        let job = assert_success(&scenario, &spec, &expected);
        assert_eq!(job.input.manifest().format(), SourceFormat::JsonDocument);
        pass(TEST, "claude_document");

        // codex_document: the same document format under codex.
        let mut spec = base_spec();
        spec.provider = "codex";
        spec.connector = "codex";
        spec.payload = &CODEX_DOCUMENT;
        spec.relative_locator = "session.json";
        spec.records = 1;
        let scenario = build(&spec);
        let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
        let job = assert_success(&scenario, &spec, &expected);
        assert_eq!(job.input.manifest().format(), SourceFormat::JsonDocument);
        pass(TEST, "codex_document");

        // metadata_sidecar: the second allowed role, whitespace-bearing
        // identity strings kept verbatim, and an empty host distinct from None.
        let mut spec = base_spec();
        spec.role = fad::SourceInputRole::MetadataSidecar;
        spec.source_id = " C44_SIDE ";
        spec.namespace = " C44_NS ";
        spec.origin_host = Some("");
        let scenario = build(&spec);
        let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
        let job = assert_success(&scenario, &spec, &expected);
        assert_eq!(job.root_id, "restore: C44_NS ");
        assert_eq!(
            job.input.identity_tuple()[2].as_deref(),
            Some(" C44_SIDE ")
        );
        assert_ne!(
            job.input.identity_tuple()[1].as_deref(),
            Some(RAW_MIRROR_LOCAL_IDENTITY_HOST),
            "the namespace is not the raw capture's session identity host"
        );
        pass(TEST, "metadata_sidecar");

        // relative_recorded_path: the recorded original path and the declared
        // root are both relative; the declared spelling is kept.
        let mut spec = base_spec();
        spec.relative_root = true;
        let scenario = build(&spec);
        let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
        assert!(Path::new(&scenario.scan_root_text).is_relative());
        assert!(Path::new(&scenario.original_path).is_relative());
        let job = assert_success(&scenario, &spec, &expected);
        assert_eq!(job.original_path, scenario.original_path);
        pass(TEST, "relative_recorded_path");

        // empty_jsonl: zero records and zero conversations is a legal input.
        let mut spec = base_spec();
        spec.payload = &EMPTY_JSONL;
        spec.records = 0;
        spec.conversations = 0;
        let scenario = build(&spec);
        let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
        let job = assert_success(&scenario, &spec, &expected);
        assert_eq!(
            job.input.manifest().sealed_sha256().hex(),
            EMPTY_JSONL.sha
        );
        pass(TEST, "empty_jsonl");

        // parse_failed_jsonl: the bad frame is kept with its own diagnostics
        // and exactly one parse failure is reported.
        let mut spec = base_spec();
        spec.payload = &PARSE_FAILED_JSONL;
        spec.records = 3;
        spec.parse_failed = 1;
        let scenario = build(&spec);
        let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
        let job = assert_success(&scenario, &spec, &expected);
        let bad = &job.records[2];
        assert_eq!(bad.ordinal, 3);
        assert_eq!(bad.parse_state, fad::SourceParseState::ParseFailed);
        assert!(
            bad.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "object_key_not_string"),
            "the bad frame keeps its per-record diagnostic"
        );
        assert_eq!(job.finish.parse_failed, 1);
        pass(TEST, "parse_failed_jsonl");

        // declared_identity_choices: three separate calls over one capture.
        // B changes the root decomposition, C changes only the namespace.
        let spec_a = base_spec();
        let scenario = build(&spec_a);
        let expected_a =
            independent_expected(&spec_a, &scenario.scan_root_text, &scenario.safety);
        let job_a = success(&scenario);
        assert_matches(&spec_a, &expected_a, &scenario, &scenario.scan_root_text, &job_a);

        let mut spec_b = spec_a.clone();
        spec_b.scan_root_suffix = "logical";
        spec_b.relative_locator = "dir/session.jsonl";
        let mut declaration_b = scenario.declaration.clone();
        declaration_b.scan_root = scenario
            ._temp
            .path()
            .join("logical")
            .to_string_lossy()
            .into_owned();
        declaration_b.relative_locator = "dir/session.jsonl".to_string();
        let expected_b =
            independent_expected(&spec_b, &declaration_b.scan_root, &scenario.safety);
        let job_b = prepare(
            &scenario.data_dir,
            &scenario.capture,
            &declaration_b,
            &scenario.safety,
        )
        .expect("the second root decomposition must prepare");
        assert_matches(
            &spec_b,
            &expected_b,
            &scenario,
            &declaration_b.scan_root,
            &job_b,
        );

        let mut spec_c = spec_a.clone();
        spec_c.namespace = "C44_OTHER_NAMESPACE";
        let mut declaration_c = scenario.declaration.clone();
        declaration_c.identity_namespace = "C44_OTHER_NAMESPACE".to_string();
        let expected_c =
            independent_expected(&spec_c, &scenario.scan_root_text, &scenario.safety);
        let job_c = prepare(
            &scenario.data_dir,
            &scenario.capture,
            &declaration_c,
            &scenario.safety,
        )
        .expect("the third namespace choice must prepare");
        assert_matches(&spec_c, &expected_c, &scenario, &scenario.scan_root_text, &job_c);

        assert_ne!(
            job_b.input.identity_tuple()[11],
            job_a.input.identity_tuple()[11],
            "a different root decomposition changes the context digest"
        );
        assert_eq!(
            job_c.input.identity_tuple()[11],
            job_a.input.identity_tuple()[11],
            "a different namespace leaves the context digest unchanged"
        );
        assert_ne!(job_a.input.input_key(), job_b.input.input_key());
        assert_ne!(job_a.input.input_key(), job_c.input.input_key());
        assert_ne!(job_b.input.input_key(), job_c.input.input_key());
        assert_eq!(job_b.input.identity_tuple()[4].as_deref(), Some(declaration_b.scan_root.as_str()));
        assert_eq!(job_b.input.identity_tuple()[5].as_deref(), Some("dir/session.jsonl"));
        assert_eq!(job_c.input.identity_tuple()[1].as_deref(), Some("C44_OTHER_NAMESPACE"));
        // The sealed material never moves between declarations.
        assert_eq!(job_a.capture.blob_blake3, job_b.capture.blob_blake3);
        assert_eq!(job_a.capture.blob_blake3, job_c.capture.blob_blake3);
        pass(TEST, "declared_identity_choices");
    }

    #[test]
    fn b2_mismatches_refused() {
        const TEST: &str = "b2_mismatches_refused";
        let mut failures: Vec<String> = Vec::new();

        macro_rules! case {
            ($name:literal, $body:block) => {{
                match std::panic::catch_unwind(AssertUnwindSafe(|| $body)) {
                    Ok(()) => pass(TEST, $name),
                    Err(payload) => failures.push(format!("{}: {}", $name, panic_text(payload))),
                }
            }};
        }

        case!("manifest_id", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.manifest_id = "0".repeat(64);
            assert_refused(&scenario, &declaration, &scenario.capture, MATERIAL_MISMATCH);
        });

        case!("cross_connector", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.connector = "codex".to_string();
            assert_refused(&scenario, &declaration, &scenario.capture, MATERIAL_MISMATCH);
        });

        case!("source_id", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.origin.source_id = "C44_OTHER_SOURCE".to_string();
            assert_refused(&scenario, &declaration, &scenario.capture, MATERIAL_MISMATCH);
        });

        case!("origin_kind", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.origin.kind = fad::types::SourceKind::Ssh;
            assert_refused(&scenario, &declaration, &scenario.capture, MATERIAL_MISMATCH);
        });

        case!("host_none_vs_empty", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.origin.host = Some(String::new());
            assert_refused(&scenario, &declaration, &scenario.capture, MATERIAL_MISMATCH);
        });

        case!("host_value", {
            let mut spec = base_spec();
            spec.origin_host = Some("C44_HOST");
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.origin.host = Some("C44_OTHER_HOST".to_string());
            assert_refused(&scenario, &declaration, &scenario.capture, MATERIAL_MISMATCH);
        });

        case!("relative_join", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.relative_locator = "other.jsonl".to_string();
            assert_refused(&scenario, &declaration, &scenario.capture, MATERIAL_MISMATCH);
        });

        case!("unknown_provider", {
            let control = build(&base_spec());
            assert_control(&control);
            let mut spec = base_spec();
            spec.provider = "C44_FUTURE_AGENT";
            let scenario = build(&spec);
            assert_refused(
                &scenario,
                &scenario.declaration,
                &scenario.capture,
                MATERIAL_MISMATCH,
            );
        });

        case!("decl_connector_alias", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.connector = "claude".to_string();
            assert_refused(&scenario, &declaration, &scenario.capture, CONTEXT_INVALID);
        });

        case!("namespace_blank", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.identity_namespace = " \t ".to_string();
            assert_refused(&scenario, &declaration, &scenario.capture, CONTEXT_INVALID);
        });

        case!("source_id_empty", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.origin.source_id = String::new();
            assert_refused(&scenario, &declaration, &scenario.capture, CONTEXT_INVALID);
        });

        case!("scan_root_empty", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.scan_root = String::new();
            assert_refused(&scenario, &declaration, &scenario.capture, CONTEXT_INVALID);
        });

        case!("relative_empty", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.relative_locator = String::new();
            assert_refused(&scenario, &declaration, &scenario.capture, CONTEXT_INVALID);
        });

        case!("relative_parent", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.relative_locator = "../session.jsonl".to_string();
            assert_refused(&scenario, &declaration, &scenario.capture, CONTEXT_INVALID);
        });

        case!("relative_double_slash", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.relative_locator = "sub//session.jsonl".to_string();
            assert_refused(&scenario, &declaration, &scenario.capture, CONTEXT_INVALID);
        });

        case!("relative_absolute", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.relative_locator = "/session.jsonl".to_string();
            assert_refused(&scenario, &declaration, &scenario.capture, CONTEXT_INVALID);
        });

        case!("trace", {
            let spec = base_spec();
            let scenario = build(&spec);
            assert_control(&scenario);
            let mut declaration = scenario.declaration.clone();
            declaration.role = fad::SourceInputRole::Trace;
            assert_refused(&scenario, &declaration, &scenario.capture, CONTEXT_INVALID);
        });

        assert!(
            failures.is_empty(),
            "b2 case failures: {failures:#?}"
        );
    }

    #[test]
    fn b3_sealed_materials_remain_authoritative() {
        const TEST: &str = "b3_sealed_materials_remain_authoritative";

        // live_removed
        {
            let spec = base_spec();
            let scenario = build(&spec);
            let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
            let control = success(&scenario);
            assert_matches(&spec, &expected, &scenario, &scenario.scan_root_text, &control);
            std::fs::remove_file(&scenario.live_path).expect("remove the live source");
            let job = success(&scenario);
            assert_matches(&spec, &expected, &scenario, &scenario.scan_root_text, &job);
            assert_eq!(job.input.identity_tuple(), control.input.identity_tuple());
            assert!(conversation_text(&job).contains("C44 question"));
            assert!(conversation_text(&job).contains("C44 answer"));
            pass(TEST, "live_removed");
        }

        // live_rewritten
        {
            let spec = base_spec();
            let scenario = build(&spec);
            let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
            let control = success(&scenario);
            assert_matches(&spec, &expected, &scenario, &scenario.scan_root_text, &control);
            std::fs::write(
                &scenario.live_path,
                b"{\"rewritten\":\"C44 different live question and answer\"}\n",
            )
            .expect("rewrite the live source");
            let job = success(&scenario);
            assert_matches(&spec, &expected, &scenario, &scenario.scan_root_text, &job);
            assert_eq!(job.input.identity_tuple(), control.input.identity_tuple());
            assert!(conversation_text(&job).contains("C44 question"));
            assert!(!conversation_text(&job).contains("different live"));
            pass(TEST, "live_rewritten");
        }

        // caller_times_differ
        {
            let mut spec = base_spec();
            spec.source_version = Some("C44_VERSION");
            spec.platform = Some(fad::types::Platform::Linux);
            spec.rewrites = vec![
                fad::types::PathMapping {
                    from: "/synthetic/c44-project".to_string(),
                    to: "/synthetic/c44-mapped".to_string(),
                    agents: None,
                },
                fad::types::PathMapping {
                    from: "/synthetic/unused".to_string(),
                    to: "/synthetic/not-used".to_string(),
                    agents: Some(vec![
                        "codex".to_string(),
                        "claude_code".to_string(),
                        "codex".to_string(),
                    ]),
                },
            ];
            let scenario = build(&spec);
            let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
            let control = success(&scenario);
            assert_matches(&spec, &expected, &scenario, &scenario.scan_root_text, &control);

            let mut caller_capture = scenario.capture.clone();
            caller_capture.captured_at_ms = 999_999;
            caller_capture.source_mtime_ms = Some(888_888);
            caller_capture.already_present = false;
            let mut declaration = scenario.declaration.clone();
            declaration.origin.source_version = Some("C44_VERSION".to_string());
            declaration.platform = Some(fad::types::Platform::Linux);
            declaration.workspace_rewrites = spec.rewrites.clone();

            let job = prepare(
                &scenario.data_dir,
                &caller_capture,
                &declaration,
                &scenario.safety,
            )
            .expect("the caller's local record times must not refuse the input");
            assert_matches(&spec, &expected, &scenario, &scenario.scan_root_text, &job);
            assert_eq!(job.capture.captured_at_ms, 43);
            assert_eq!(job.capture.source_mtime_ms, Some(-7));
            assert!(job.capture.already_present);
            assert_eq!(caller_capture.captured_at_ms, 999_999);
            assert_eq!(caller_capture.source_mtime_ms, Some(888_888));
            assert!(!caller_capture.already_present);
            assert_eq!(job.root.platform, Some(fad::types::Platform::Linux));
            assert_eq!(job.root.workspace_rewrites, spec.rewrites);
            assert_eq!(
                job.input.identity_tuple()[9].as_deref(),
                Some("C44_VERSION")
            );
            assert_eq!(job.input.identity_tuple()[10].as_deref(), Some("linux"));
            pass(TEST, "caller_times_differ");
        }

        // fixed_changed
        {
            let spec = base_spec();
            let scenario = build(&spec);
            let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
            let control = success(&scenario);
            assert_matches(&spec, &expected, &scenario, &scenario.scan_root_text, &control);
            let mut bytes = std::fs::read(&scenario.fixed_path).expect("read the fixed copy");
            bytes.push(b'\n');
            std::fs::write(&scenario.fixed_path, bytes).expect("change the fixed copy");
            assert_refused(
                &scenario,
                &scenario.declaration,
                &scenario.capture,
                MATERIAL_MISMATCH,
            );
            pass(TEST, "fixed_changed");
        }

        // blob_same_length_tampered
        {
            let spec = base_spec();
            let scenario = build(&spec);
            let expected = independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
            let control = success(&scenario);
            assert_matches(&spec, &expected, &scenario, &scenario.scan_root_text, &control);
            let blob = scenario
                .data_dir
                .join("raw-mirror")
                .join("v1")
                .join(&scenario.capture.blob_relative_path);
            let mut bytes = std::fs::read(&blob).expect("read the sealed blob");
            let length = bytes.len();
            bytes[0] ^= 1;
            assert_eq!(bytes.len(), length);
            std::fs::write(&blob, bytes).expect("tamper the sealed blob");
            assert_refused(
                &scenario,
                &scenario.declaration,
                &scenario.capture,
                MATERIAL_MISMATCH,
            );
            pass(TEST, "blob_same_length_tampered");
        }
    }

    #[test]
    fn r16_mapping_declared_preparation() {
        let spec = base_spec();
        let scenario = build(&spec);

        let expected_two = independent_expected_with_domain(
            &spec,
            &scenario.scan_root_text,
            &scenario.safety,
            SourceMappingDomain::V2,
        );
        let expected_three = independent_expected_with_domain(
            &spec,
            &scenario.scan_root_text,
            &scenario.safety,
            SourceMappingDomain::V3,
        );
        let expected_default =
            independent_expected(&spec, &scenario.scan_root_text, &scenario.safety);
        assert_eq!(
            expected_default.normalizer_id, expected_two.normalizer_id,
            "the default oracle is the /2 identity"
        );
        assert_eq!(expected_default.input_key, expected_two.input_key);
        assert_eq!(
            expected_two.tuple[11], expected_three.tuple[11],
            "the parser-context digest does not depend on the mapping identity"
        );
        assert_eq!(expected_two.tuple[12], expected_three.tuple[12]);
        assert_eq!(
            expected_two.safety_contract_id, expected_three.safety_contract_id,
            "one fixed safety configuration carries both identities"
        );
        assert_ne!(expected_two.normalizer_id, expected_three.normalizer_id);
        assert_ne!(expected_two.input_key, expected_three.input_key);

        let before = mirror_digest(&scenario.data_dir);
        let two = prepare_declared_restore_source_input_for_mapping(
            &scenario.data_dir,
            &scenario.capture,
            &scenario.declaration,
            Arc::clone(&scenario.safety),
            SourceMappingDomain::V2,
            None,
        )
        .expect("the declared /2 input prepares");
        assert_matches(&spec, &expected_two, &scenario, &scenario.scan_root_text, &two);

        // The declaration alone decides the identity: no digest-only claim is
        // supplied here, so only the journal's plaintext label can select /3.
        let three = prepare_declared_restore_source_input_for_mapping(
            &scenario.data_dir,
            &scenario.capture,
            &scenario.declaration,
            Arc::clone(&scenario.safety),
            SourceMappingDomain::V3,
            None,
        )
        .expect("the declared /3 input prepares");
        assert_matches(&spec, &expected_three, &scenario, &scenario.scan_root_text, &three);
        assert_eq!(mirror_digest(&scenario.data_dir), before, "the mirror is unchanged");

        // With the digest-only claim present, the same declaration prepares
        // the same job; the claim corroborates the label instead of replacing
        // it.
        let claimed = prepare_declared_restore_source_input_for_mapping(
            &scenario.data_dir,
            &scenario.capture,
            &scenario.declaration,
            Arc::clone(&scenario.safety),
            SourceMappingDomain::V3,
            Some(expected_three.normalizer_id.as_str()),
        )
        .expect("the claimed /3 input prepares");
        assert_matches(&spec, &expected_three, &scenario, &scenario.scan_root_text, &claimed);
        assert_eq!(claimed.input.input_key(), three.input.input_key());

        // A declaration and a claim that name different identities are refused
        // in both directions, and a claim that names no identity is refused
        // rather than defaulted.
        let unknown = "0".repeat(64);
        for (domain, claim, case) in [
            (
                SourceMappingDomain::V2,
                Some(expected_three.normalizer_id.as_str()),
                "two_declared_three_claimed",
            ),
            (
                SourceMappingDomain::V3,
                Some(expected_two.normalizer_id.as_str()),
                "three_declared_two_claimed",
            ),
            (
                SourceMappingDomain::V3,
                Some(unknown.as_str()),
                "three_declared_unknown_claimed",
            ),
        ] {
            let error = prepare_declared_restore_source_input_for_mapping(
                &scenario.data_dir,
                &scenario.capture,
                &scenario.declaration,
                Arc::clone(&scenario.safety),
                domain,
                claim,
            )
            .expect_err(case);
            assert_eq!(
                error.to_string(),
                format!("source safety configuration: {MATERIAL_MISMATCH}"),
                "{case}"
            );
        }
        assert_eq!(
            mirror_digest(&scenario.data_dir),
            before,
            "every refusal leaves the sealed mirror unchanged"
        );
        pass("r16_mapping_declared_preparation", "declared_and_claimed");
    }
}
