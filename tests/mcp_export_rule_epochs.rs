//! Task08 acceptance tests: one export keeps every input's own rule epoch.
//!
//! Every fixture is synthetic and self-contained. Inputs are verified through
//! the existing public `VerifiedSourceInput` path, records are staged through
//! the existing public primitives, and the export runs through the real CLI
//! binary against a temporary database. The profile materials this file writes
//! are computed here from the frozen C05 identity arrays with a local canonical
//! JSON writer; no expected value is read back from the exporter under test.
//!
//! The sealed bodies are empty on purpose: these cases exercise the profile and
//! material identity of a real activation, not the record round trip. Each case
//! asserts a non-zero input count, a non-zero receipt and the exported
//! per-input identity, so an empty body is never reported as a body result.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use coding_agent_search::indexer::redact_secrets::redaction_algorithm_fingerprint;
use coding_agent_search::sources::config::ExcludedContextPaths;
use coding_agent_search::storage::api::{Tx, TxMode, Value};
use coding_agent_search::storage::source_facts::{
    ProjectionDisposition, Sha256Digest, SourceActivationRequest, SourceFormat,
    SourceInputDeclaration, SourceSafetyConfig, TerminalState, VerifiedFinish, VerifiedSourceInput,
    activate_source_input_in_tx, context_digest, decode_expected_manifest_header,
    effective_four_arrays_digest, source_a_roots_in_tx, stage_source_records_in_tx,
};
use coding_agent_search::storage::sqlite::FrankenStorage;
use franken_agent_detection::LosslessSourceValue;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

// Frozen identity material (C05). These spellings are hand-written inputs, not
// values produced by the code under test.
const FAD_PIN: &str = "61f975f3b56f8dabc4ecbe1dae4102c1ea6b16e5";
const MAPPING_DOMAIN: &str = "cass-source-mapping/2";
const NORMALIZER_DOMAIN: &str = "cass.source-normalizer/1";
const SAFETY_CONTRACT: &str = "cass.source-safety/1";
const EPOCH_V1: &str = "cass-source-exclusion/1";
const EPOCH_V2: &str = "cass-source-exclusion/2";

const NAMESPACE: &str = "MCP_EXPORT_EPOCH_NAMESPACE";
const CONNECTOR: &str = "claude_code";
const ROOT: &str = "/synthetic/mcp-export-epoch-root";
const ROLE: &str = "primary_session_log";

/// The fixed copy both epochs share: all four arrays explicitly empty.
const FIXED_TOML: &str = "injection_only_files = []\nmemory_files = []\n\
project_read_documents = []\nworkspace_scoped_files = []\n";

// ---------------------------------------------------------------------------
// Independent canonical JSON (the encoding the two profile identities hash)
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn hex_text(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_json_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br"\\"),
            '\u{08}' => out.extend_from_slice(br"\b"),
            '\u{0c}' => out.extend_from_slice(br"\f"),
            '\n' => out.extend_from_slice(br"\n"),
            '\r' => out.extend_from_slice(br"\r"),
            '\t' => out.extend_from_slice(br"\t"),
            ch if (ch as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", ch as u32).as_bytes());
            }
            ch => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_canonical(value: &Json, out: &mut Vec<u8>) {
    match value {
        Json::Object(map) => {
            let mut entries: Vec<(&String, &Json)> = map.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            out.push(b'{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_string(key, out);
                out.push(b':');
                write_canonical(item, out);
            }
            out.push(b'}');
        }
        Json::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        other => out.extend_from_slice(
            serde_json::to_string(other)
                .expect("a scalar encodes")
                .as_bytes(),
        ),
    }
}

fn canonical_digest(value: &Json) -> String {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    sha256_hex(&out)
}

fn empty_arrays() -> ExcludedContextPaths {
    ExcludedContextPaths {
        memory_files: vec![],
        injection_only_files: vec![],
        workspace_scoped_files: vec![],
        project_read_documents: vec![],
    }
}

fn fingerprint() -> String {
    redaction_algorithm_fingerprint()
}

fn code_version(epoch: &str) -> String {
    format!("{epoch}+{}", fingerprint())
}

// ---------------------------------------------------------------------------
// One case: database, fixed copies, materials and a private command env
// ---------------------------------------------------------------------------

struct Case {
    root: tempfile::TempDir,
    db: PathBuf,
    profiles: PathBuf,
    fixed: PathBuf,
    out: PathBuf,
    home: PathBuf,
    cwd: PathBuf,
    tmp: PathBuf,
}

impl Case {
    fn new(tag: &str) -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let base = root.path().to_path_buf();
        let db_dir = base.join(format!("db-{tag}"));
        fs::create_dir_all(&db_dir).expect("create db directory");
        let db = db_dir.join("agent-search.db");
        let fixed = base.join(format!("fixed-{tag}.toml"));
        fs::write(&fixed, FIXED_TOML.as_bytes()).expect("write fixed copy");
        let home = base.join("home");
        let cwd = base.join("cwd");
        let tmp = base.join("tmp");
        for directory in [&home, &cwd, &tmp] {
            fs::create_dir_all(directory).expect("create private env directory");
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("tighten private env directory");
        }
        fs::write(cwd.join(".env"), b"").expect("write empty .env");
        Self {
            out: base.join("out"),
            profiles: base.join("profile-materials.json"),
            fixed,
            db,
            home,
            cwd,
            tmp,
            root,
        }
    }

    fn fixed_digest(&self) -> String {
        sha256_hex(&fs::read(&self.fixed).expect("read fixed copy"))
    }

    fn arrays_digest(&self) -> String {
        effective_four_arrays_digest(&empty_arrays()).hex()
    }

    fn write_profiles(&self, entries: &[Json]) {
        let value = json!({
            "schema": "cass.source-profile-materials/1",
            "profiles": entries,
        });
        let mut bytes = serde_json::to_vec_pretty(&value).expect("serialise materials");
        bytes.push(b'\n');
        fs::write(&self.profiles, bytes).expect("write materials");
        fs::set_permissions(&self.profiles, fs::Permissions::from_mode(0o600))
            .expect("tighten materials");
    }

    fn run(&self, extra: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cass"));
        command.env_clear();
        command
            .env("HOME", &self.home)
            .env("XDG_CACHE_HOME", self.home.join("cache"))
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_STATE_HOME", self.home.join("state"))
            .env("TMPDIR", &self.tmp)
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env("LC_ALL", "C");
        command.current_dir(&self.cwd);
        command
            .arg("--db")
            .arg(&self.db)
            .args([
                "sources",
                "facts",
                "export",
                "--output",
                self.out.to_str().expect("utf8 output"),
                "--profile-materials",
                self.profiles.to_str().expect("utf8 profile materials"),
                "--scope",
                "all_source",
                "--json",
            ])
            .args(extra);
        command.output().expect("run the export CLI")
    }

    /// Every path and file digest under the case root, excluding the export
    /// output directory, taken before and after a run to prove the database
    /// was not written.
    fn snapshot(&self) -> Vec<(PathBuf, String)> {
        let mut out = Vec::new();
        walk(&self.root.path().to_path_buf(), &self.out, &mut out);
        out.sort();
        out
    }
}

fn walk(path: &Path, skip: &Path, out: &mut Vec<(PathBuf, String)>) {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries {
        let entry = entry.expect("directory entry");
        let child = entry.path();
        if child == skip {
            continue;
        }
        // Opening a WAL database even for reading creates the `-shm`/`-wal`
        // sidecars. They are a reader artifact, not a write by the export; the
        // main database file's digest is what the snapshot compares.
        if let Some(name) = child.file_name().and_then(|name| name.to_str()) {
            if name.starts_with("agent-search.db-") {
                continue;
            }
        }
        let metadata = fs::symlink_metadata(&child).expect("entry metadata");
        if metadata.is_dir() {
            out.push((child.clone(), "dir".to_string()));
            walk(&child, skip, out);
        } else {
            let bytes = fs::read(&child).expect("file bytes");
            out.push((child, sha256_hex(&bytes)));
        }
    }
}

// ---------------------------------------------------------------------------
// Building the real isolated inputs
// ---------------------------------------------------------------------------

struct Built {
    source_id: String,
    input_key: String,
    code_version: String,
    identity: String,
    normalizer_id: String,
    safety_contract_id: String,
    expected_records: u64,
    receipt_key: String,
    activation_request_hash: String,
}

struct Spec<'a> {
    source_id: &'a str,
    epoch: &'a str,
}

fn parser_context(locator: &str, effective_digest: &str) -> Json {
    json!({
        "schema": "cass.source-parser-context/1",
        "connector": CONNECTOR,
        "discovery_roots": [ROOT],
        "relative_locator": locator,
        "role": ROLE,
        "origin": {"kind": "local", "host": null, "source_version": null},
        "platform": null,
        "workspace_rewrites": [],
        "effective_config_summary": {"effective_digest": effective_digest},
    })
}

/// The effective-configuration material `source_export` rebuilds from the
/// context fields, encoded exactly as the profile assembler encodes it.
fn effective_material() -> Json {
    json!({
        "schema": "cass.source-parser-context/1",
        "connector": CONNECTOR,
        "roots": [{
            "path": ROOT,
            "origin": {"kind": "local", "host": null, "source_version": null},
            "platform": null,
            "workspace_rewrites": [],
        }],
        "role": ROLE,
    })
}

fn normalizer_id(effective_digest: &str) -> String {
    canonical_digest(&json!([
        NORMALIZER_DOMAIN,
        FAD_PIN,
        MAPPING_DOMAIN,
        effective_digest
    ]))
}

fn safety_contract_id(
    epoch: &str,
    identity: &str,
    fixed_sha: &str,
    arrays_sha: &str,
) -> String {
    canonical_digest(&json!([
        SAFETY_CONTRACT,
        epoch,
        fingerprint(),
        identity,
        fixed_sha,
        arrays_sha,
        true
    ]))
}

fn library_of(tx: &Tx<'_>) -> String {
    tx.query_row_map(
        "SELECT value FROM meta WHERE key = 'library_identity'",
        &[],
        |row| row.get_typed(0),
    )
    .expect("library identity")
}

fn header_of(tx: &Tx<'_>, input_id: i64) -> Vec<u8> {
    tx.query_row_map(
        "SELECT expected_manifest_bin FROM source_inputs WHERE id = ?1",
        &[Value::Integer(input_id)],
        |row| row.get_typed(0),
    )
    .expect("expected manifest header")
}

fn finish_from(
    manifest: &coding_agent_search::storage::source_facts::VerifiedExpectedManifest,
) -> VerifiedFinish {
    VerifiedFinish {
        content_digest: *manifest.sealed_sha256(),
        bytes_read: manifest.byte_len(),
        records_seen: manifest.records(),
        blank_lines: manifest.blank_lines(),
        parse_failed: 0,
        mapping_diagnostics: 0,
        unprocessed_ranges: vec![],
        reached_eof: true,
    }
}

/// Publish one empty sealed input under its own epoch and return the identity
/// the export must reproduce.
fn publish(case: &Case, spec: &Spec<'_>) -> Built {
    let epoch = spec.epoch;
    let version = code_version(epoch);
    let identity = format!(
        "MCP_EXPORT_FIXED_{}",
        if epoch == EPOCH_V1 { "V1" } else { "V2" }
    );
    let locator = format!("{}.jsonl", spec.source_id);
    let effective_digest = canonical_digest(&effective_material());
    let context_value = parser_context(&locator, &effective_digest);
    let context = LosslessSourceValue::parse(
        serde_json::to_string(&context_value)
            .expect("context text")
            .as_bytes(),
    )
    .expect("lossless context");
    let normalizer = normalizer_id(&effective_digest);
    let fixed_sha = case.fixed_digest();
    let arrays_sha = case.arrays_digest();
    let safety_id = safety_contract_id(epoch, &identity, &fixed_sha, &arrays_sha);
    let sealed: &[u8] = b"";

    let tuple = vec![
        Some("cass.source-input/2".into()),
        Some(NAMESPACE.into()),
        Some(spec.source_id.into()),
        Some(CONNECTOR.into()),
        Some(ROOT.into()),
        Some(locator.clone()),
        Some(ROLE.into()),
        Some("local".into()),
        None,
        None,
        None,
        Some(context_digest(&context).expect("context digest").hex()),
        Some(Sha256Digest::of(sealed).hex()),
        Some(normalizer.clone()),
        Some(safety_id.clone()),
    ];
    let declaration = SourceInputDeclaration {
        identity_tuple: tuple,
        identity_namespace: NAMESPACE.into(),
        source_id: spec.source_id.into(),
        connector: CONNECTOR.into(),
        origin_kind: Some("local".into()),
        origin_host: None,
        origin_source_version: None,
        role: Some(ROLE.into()),
        platform: None,
        root_id: ROOT.into(),
        relative_locator: locator,
        discovery: context.clone(),
        parser_context: context.clone(),
        sealed_ref: context,
        format: SourceFormat::Jsonl,
        normalizer_id: normalizer.clone(),
        safety_contract_id: safety_id.clone(),
    };
    let safety = SourceSafetyConfig {
        code_version: version.clone(),
        desensitization_enabled: true,
        config_source_identity: identity.clone(),
        fixed_config_bytes: FIXED_TOML.as_bytes().to_vec(),
        effective_four_arrays: empty_arrays(),
    };
    let (input, _) = VerifiedSourceInput::verify(declaration, sealed, &safety)
        .expect("the public verifier accepts the synthetic input");
    let input_key = *input.input_key();
    let expected_records = input.expected_records();

    let storage = FrankenStorage::open(&case.db).expect("open schema9");
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    let staged = stage_source_records_in_tx(&tx, &input, &[]).expect("stage");
    let (records_root, claims_root) =
        source_a_roots_in_tx(&tx, input.input_key(), staged.input_id).expect("A roots");
    let header = header_of(&tx, staged.input_id);
    let (manifest, _) = decode_expected_manifest_header(&header).expect("header");
    let finish = finish_from(&manifest);
    let (stored_normalizer, stored_safety): (String, String) = tx
        .query_row_map(
            "SELECT normalizer_id, safety_contract_id FROM source_inputs WHERE id = ?1",
            &[Value::Integer(staged.input_id)],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .expect("stored profile");
    let request = SourceActivationRequest {
        input_key: *input.input_key(),
        library_identity: library_of(&tx),
        normalizer_id: stored_normalizer,
        safety_contract_id: stored_safety,
        expected_manifest_digest: Sha256Digest::of(&header),
        finish,
        projection_disposition: ProjectionDisposition::Ready,
        source_semantic_records_root: records_root,
        claims_root,
        requested_terminal: TerminalState::Complete,
    };
    activate_source_input_in_tx(&tx, &request, &manifest).expect("activation");
    let (receipt_key, activation_request_hash): (String, Vec<u8>) = tx
        .query_row_map(
            "SELECT receipt_key, activation_request_hash FROM source_inputs WHERE id = ?1",
            &[Value::Integer(staged.input_id)],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .expect("stored receipt identity");
    tx.commit().expect("commit");
    storage.close().expect("close");

    Built {
        source_id: spec.source_id.to_string(),
        input_key: input_key.hex(),
        code_version: version,
        identity,
        normalizer_id: normalizer,
        safety_contract_id: safety_id,
        expected_records,
        receipt_key,
        activation_request_hash: hex_text(&activation_request_hash),
    }
}

fn material_entry(built: &Built, case: &Case) -> Json {
    let epoch = if built.code_version.starts_with(EPOCH_V2) {
        EPOCH_V2
    } else {
        EPOCH_V1
    };
    json!({
        "normalizer_id": built.normalizer_id,
        "safety_contract_id": built.safety_contract_id,
        "fad_pin": FAD_PIN,
        "mapping_domain": MAPPING_DOMAIN,
        "exclusion_epoch": epoch,
        "redaction_fingerprint": fingerprint(),
        "code_version": built.code_version,
        "config_source_identity": built.identity,
        "fixed_copy_path": case.fixed.to_str().expect("utf8 fixed path"),
        "fixed_config_sha256": case.fixed_digest(),
        "effective_four_arrays_sha256": case.arrays_digest(),
        "desensitization_enabled": true,
    })
}

// ---------------------------------------------------------------------------
// Reading the real export package
// ---------------------------------------------------------------------------

fn success(index: &Json) -> bool {
    index["schema"] == json!("cass.source-export/2")
}

fn read_json(path: &Path) -> Json {
    serde_json::from_slice(&fs::read(path).expect("read json")).expect("parse json")
}

fn exported_inputs(out: &Path) -> Vec<Json> {
    let index = read_json(&out.join("index.json"));
    let mut inputs = Vec::new();
    for page in index["pages"].as_array().expect("pages") {
        let path = out.join(page["path"].as_str().expect("page path"));
        let wrapper = read_json(&path);
        for input in wrapper["page"]["inputs"].as_array().expect("page inputs") {
            inputs.push(input.clone());
        }
    }
    inputs
}

fn assert_success(output: &Output, case: &Case) -> Json {
    assert!(
        output.status.success(),
        "export failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Json =
        serde_json::from_slice(&output.stdout).expect("the CLI prints one JSON summary");
    assert_eq!(summary["status"], json!("complete"));
    assert!(summary["unique_input_count"].as_str().unwrap_or("0") != "0");
    assert!(
        !case.out.join("INCOMPLETE.json").exists(),
        "a complete export leaves no marker"
    );
    let index = read_json(&case.out.join("index.json"));
    assert!(success(&index), "the published index has the frozen schema");
    index
}

fn error_kind(output: &Output) -> String {
    assert!(
        !output.status.success(),
        "the export unexpectedly succeeded: stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(output.status.code(), Some(1), "export refusals exit 1");
    let value: Json =
        serde_json::from_slice(&output.stderr).expect("the error envelope is JSON");
    value["error"]["kind"]
        .as_str()
        .expect("the envelope carries a kind")
        .to_string()
}

fn assert_no_package(case: &Case) {
    assert!(
        case.out.join("INCOMPLETE.json").is_file(),
        "a refused export keeps its incomplete marker"
    );
    assert!(
        !case.out.join("index.json").exists(),
        "a refused export publishes no index"
    );
}

/// Assert one exported input carries exactly the identity computed here.
fn assert_input_identity(input: &Json, built: &Built, case: &Case) {
    assert_eq!(input["input_key"], json!(built.input_key));
    assert_eq!(input["source_id"], json!(built.source_id));
    assert_eq!(input["normalizer_id"], json!(built.normalizer_id));
    assert_eq!(input["safety_contract_id"], json!(built.safety_contract_id));
    assert_eq!(input["state"], json!("complete"));
    assert_eq!(
        input["receipt_key"],
        json!(built.receipt_key),
        "the exported receipt is the one the activation wrote"
    );
    assert_eq!(
        input["activation_request_hash"],
        json!(built.activation_request_hash),
        "the exported activation request hash is the stored one"
    );
    assert!(
        input["receipt_key"].as_str().is_some(),
        "an activated input carries a receipt"
    );
    assert!(
        input["activation_request_hash"].as_str().is_some(),
        "an activated input records its activation request"
    );
    assert_eq!(
        input["expected_records"],
        json!(built.expected_records.to_string()),
        "the empty fixture still records its own expected record count"
    );

    let manifest = input["expected_manifest"].as_array().expect("manifest array");
    assert_eq!(manifest.len(), 15, "the frozen manifest header length");
    assert_eq!(manifest[10], json!(built.code_version), "code_version");
    assert_eq!(manifest[12], json!(built.identity), "config identity");
    assert_eq!(manifest[13], json!(case.fixed_digest()), "fixed copy digest");
    assert_eq!(
        manifest[14],
        json!(case.arrays_digest()),
        "four-array digest"
    );
}

/// Assert the profile section and the copied fixed file of one epoch.
fn assert_profile(index: &Json, built: &Built, case: &Case) {
    let profiles = index["profiles"].as_array().expect("profiles");
    let profile = profiles
        .iter()
        .find(|entry| entry["safety_contract_id"] == json!(built.safety_contract_id))
        .unwrap_or_else(|| panic!("no profile for {}", built.safety_contract_id));
    assert_eq!(profile["normalizer_id"], json!(built.normalizer_id));
    assert_eq!(profile["code_version"], json!(built.code_version));
    assert_eq!(
        profile["exclusion_epoch"],
        json!(if built.code_version.starts_with(EPOCH_V2) {
            EPOCH_V2
        } else {
            EPOCH_V1
        })
    );
    assert_eq!(profile["config_source_identity"], json!(built.identity));
    assert_eq!(profile["fixed_config_sha256"], json!(case.fixed_digest()));
    assert_eq!(profile["effective_four_arrays_sha256"], json!(case.arrays_digest()));
    assert_eq!(profile["desensitization_enabled"], json!(true));

    let relative = profile["relative_path"].as_str().expect("relative path");
    let copied = fs::read(case.out.join(relative)).expect("read the copied fixed file");
    assert_eq!(copied, FIXED_TOML.as_bytes(), "the copy is published verbatim");
    assert_eq!(
        sha256_hex(&copied),
        case.fixed_digest(),
        "the published copy has the recorded digest"
    );
    assert_eq!(
        profile["byte_len"].as_str(),
        Some(FIXED_TOML.len().to_string().as_str())
    );
}

// ---------------------------------------------------------------------------
// 08-AC1: the frozen v1 identity survives export
// ---------------------------------------------------------------------------

#[test]
fn mcp_export_v1_keeps_the_frozen_identity() {
    let case = Case::new("v1");
    let built = publish(
        &case,
        &Spec {
            source_id: "mcp-export-v1",
            epoch: EPOCH_V1,
        },
    );
    case.write_profiles(&[material_entry(&built, &case)]);

    let output = case.run(&[]);
    let index = assert_success(&output, &case);
    assert_eq!(index["unique_input_count"], json!("1"));
    assert_eq!(index["record_count"], json!("0"));

    let inputs = exported_inputs(&case.out);
    assert_eq!(inputs.len(), 1, "the page carries the activated input");
    assert_input_identity(&inputs[0], &built, &case);
    assert_profile(&index, &built, &case);
    assert_eq!(index["profiles"].as_array().expect("profiles").len(), 1);
}

// ---------------------------------------------------------------------------
// 08-AC2: v2 and a mixed library use each input's own profile
// ---------------------------------------------------------------------------

#[test]
fn mcp_export_v2_uses_the_v2_profile() {
    let case = Case::new("v2");
    let built = publish(
        &case,
        &Spec {
            source_id: "mcp-export-v2",
            epoch: EPOCH_V2,
        },
    );
    case.write_profiles(&[material_entry(&built, &case)]);

    let output = case.run(&[]);
    let index = assert_success(&output, &case);
    assert_eq!(index["unique_input_count"], json!("1"));

    let inputs = exported_inputs(&case.out);
    assert_eq!(inputs.len(), 1);
    assert_input_identity(&inputs[0], &built, &case);
    assert_profile(&index, &built, &case);
    assert_eq!(index["profiles"][0]["exclusion_epoch"], json!(EPOCH_V2));
}

#[test]
fn mcp_export_mixed_library_keeps_both_epochs() {
    let case = Case::new("mixed");
    let v1 = publish(
        &case,
        &Spec {
            source_id: "mcp-export-mixed-v1",
            epoch: EPOCH_V1,
        },
    );
    let v2 = publish(
        &case,
        &Spec {
            source_id: "mcp-export-mixed-v2",
            epoch: EPOCH_V2,
        },
    );
    case.write_profiles(&[material_entry(&v1, &case), material_entry(&v2, &case)]);

    let output = case.run(&[]);
    let index = assert_success(&output, &case);
    assert_eq!(index["unique_input_count"], json!("2"));
    assert_eq!(index["record_count"], json!("0"));

    let inputs = exported_inputs(&case.out);
    assert_eq!(inputs.len(), 2, "both inputs ride in the page");
    let by_key = |key: &str| {
        inputs
            .iter()
            .find(|input| input["input_key"] == json!(key))
            .unwrap_or_else(|| panic!("input {key} missing from the page"))
            .clone()
    };
    assert_input_identity(&by_key(&v1.input_key), &v1, &case);
    assert_input_identity(&by_key(&v2.input_key), &v2, &case);
    assert_profile(&index, &v1, &case);
    assert_profile(&index, &v2, &case);

    let profiles = index["profiles"].as_array().expect("profiles");
    assert_eq!(profiles.len(), 2, "one profile per rule epoch");
    let epochs: Vec<&str> = profiles
        .iter()
        .map(|profile| profile["exclusion_epoch"].as_str().expect("epoch"))
        .collect();
    assert!(epochs.contains(&EPOCH_V1) && epochs.contains(&EPOCH_V2));
    // The shared root and configuration give the same normalizer; the epoch
    // separates the safety identity.
    assert_eq!(v1.normalizer_id, v2.normalizer_id);
    assert_ne!(v1.safety_contract_id, v2.safety_contract_id);
}

// ---------------------------------------------------------------------------
// 08-AC3: unknown or inconsistent versions and changed material are refused
// ---------------------------------------------------------------------------

/// Build one isolated input, write its mutated (but structurally valid)
/// materials, run the real CLI and return the refusal kind. The database
/// snapshot is taken after the materials are written, so a refusal that
/// writes anything at all is caught.
fn refused_cell(
    tag: &str,
    source_id: &str,
    epoch: &str,
    mutate: impl FnOnce(&mut Json),
) -> String {
    let case = Case::new(tag);
    let built = publish(
        &case,
        &Spec {
            source_id,
            epoch,
        },
    );
    let mut entry = material_entry(&built, &case);
    mutate(&mut entry);
    case.write_profiles(&[entry]);
    let before = case.snapshot();
    let output = case.run(&[]);
    let kind = error_kind(&output);
    assert_no_package(&case);
    assert_eq!(case.snapshot(), before, "a refusal writes nothing");
    kind
}

#[test]
fn mcp_export_rejects_unknown_or_inconsistent_versions() {
    // 1. The material names a third epoch this build cannot read.
    assert_eq!(
        refused_cell("unknown-version", "mcp-export-unknown", EPOCH_V2, |entry| {
            entry["code_version"] = json!(format!("cass-source-exclusion/3+{}", fingerprint()));
        }),
        "source_export_profile_invalid"
    );

    // 2. Epoch 1 material claiming an epoch 2 code version.
    assert_eq!(
        refused_cell(
            "epoch1-code2",
            "mcp-export-epoch1-code2",
            EPOCH_V1,
            |entry| {
                entry["code_version"] = json!(code_version(EPOCH_V2));
            }
        ),
        "source_export_profile_invalid"
    );

    // 3. Epoch 2 material claiming an epoch 1 code version.
    assert_eq!(
        refused_cell(
            "epoch2-code1",
            "mcp-export-epoch2-code1",
            EPOCH_V2,
            |entry| {
                entry["code_version"] = json!(code_version(EPOCH_V1));
            }
        ),
        "source_export_profile_invalid"
    );
}

#[test]
fn mcp_export_rejects_changed_fixed_material() {
    // 1. A supported version whose logical safety identity does not match the
    //    identity the input was activated under.
    assert_eq!(
        refused_cell(
            "identity-mismatch",
            "mcp-export-identity-mismatch",
            EPOCH_V2,
            |entry| {
                entry["config_source_identity"] = json!("MCP_EXPORT_FIXED_OTHER");
            }
        ),
        "source_export_profile_mismatch"
    );

    // 2. The recorded fixed-copy digest does not match the real file.
    assert_eq!(
        refused_cell(
            "fixed-digest",
            "mcp-export-fixed-digest",
            EPOCH_V2,
            |entry| {
                entry["fixed_config_sha256"] = json!(sha256_hex(b"a different fixed copy"));
            }
        ),
        "source_export_profile_mismatch"
    );

    // 3. A profile pair no input references is still refused as missing.
    assert_eq!(
        refused_cell(
            "pair-mismatch",
            "mcp-export-pair-mismatch",
            EPOCH_V2,
            |entry| {
                entry["safety_contract_id"] = json!(sha256_hex(b"unreferenced safety identity"));
            }
        ),
        "source_export_profile_missing"
    );

    // 4. The physical copy changed after the materials were written.
    let case = Case::new("fixed-changed");
    let built = publish(
        &case,
        &Spec {
            source_id: "mcp-export-fixed-changed",
            epoch: EPOCH_V2,
        },
    );
    case.write_profiles(&[material_entry(&built, &case)]);
    let unchanged = case.snapshot();
    fs::write(
        &case.fixed,
        "injection_only_files = [\"MCP_EXPORT_CHANGED\"]\nmemory_files = []\n\
project_read_documents = []\nworkspace_scoped_files = []\n",
    )
    .expect("change the fixed copy");
    let changed = case.snapshot();
    assert_ne!(unchanged, changed, "the copy really changed");
    let output = case.run(&[]);
    assert_eq!(error_kind(&output), "source_export_profile_mismatch");
    assert_no_package(&case);
    assert_eq!(case.snapshot(), changed, "the refusal writes nothing");
}
