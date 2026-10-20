//! Task17 complete source-facts export (wire v3.1).
//!
//! This module reads one schema-9 archive through the accepted
//! [`SourceFactsReader`] and publishes a private directory whose complete
//! package is checkable by the task-17 controlled-fixture checker. It never
//! writes the input database and never discovers live configuration.
//!
//! The module is the only new producer surface for Task17. It is wired into the
//! CLI as `cass sources facts export`; the CLI argument surface, output
//! admission and error kinds are frozen by the dispatch mission.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use franken_agent_detection::LosslessSourceValue;
use serde::Deserialize;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde_json::{Value, json};

use crate::indexer::source_ingest::{
    FixedSafetyConfig, SourceProfile, load_fixed_safety_config, load_restore_fixed_safety,
};
use crate::storage::source_facts::{
    AttemptHistory, DiagnosticsEnvelope, RawSourceFactsRecord, Sha256Digest, SourceFactsFilter,
    SourceFactsInput, SourceFactsPage, SourceFactsPageLimits, SourceFactsReadError,
    SourceFactsReader, SourceFactsRecord, SourceFactsRecordLink, SourceFactsScope,
    UnprocessedRangesEnvelope, VerifiedFinish, encode_expected_manifest_header,
};

/// The one scope spelling accepted on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum FactsScopeArg {
    #[value(name = "analysis")]
    Analysis,
    #[value(name = "history_unresolved")]
    HistoryUnresolved,
    #[value(name = "all_source")]
    AllSource,
}

impl From<FactsScopeArg> for SourceFactsScope {
    fn from(value: FactsScopeArg) -> Self {
        match value {
            FactsScopeArg::Analysis => Self::Analysis,
            FactsScopeArg::HistoryUnresolved => Self::HistoryUnresolved,
            FactsScopeArg::AllSource => Self::AllSource,
        }
    }
}

/// Parse one `--input-keys` value: exactly 64 lowercase hexadecimal digits.
///
/// # Errors
/// A short human string; clap turns it into a parse refusal before any output
/// directory is touched.
pub fn parse_input_key(value: &str) -> Result<Sha256Digest, String> {
    if !is_lower_hex(value, 64) {
        return Err("input key must be 64 lowercase hex digits".to_string());
    }
    Sha256Digest::from_hex(value)
        .ok_or_else(|| "input key must be 64 lowercase hex digits".to_string())
}

/// Everything one export invocation needs.
pub struct ExportOptions {
    pub output: PathBuf,
    pub profile_materials: PathBuf,
    pub db_path: PathBuf,
    pub filter: SourceFactsFilter,
    /// The raw CLI page limits, recorded in the index exactly as given.
    pub max_records: u64,
    pub target_bytes: u64,
}

/// The fixed success summary.
#[derive(Debug, Clone)]
pub struct ExportSummary {
    pub page_count: u64,
    pub unique_input_count: u64,
    pub record_count: u64,
    pub oversized_records: u64,
    pub index_sha256: String,
}

/// The closed Task17 export error set.
///
/// Every variant carries no detail: the CLI message is the kind itself, so no
/// input path, pointer, rule text or DTO value can reach a log or a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportError {
    ProfileMissing,
    ProfileInvalid,
    ProfileMismatch,
    OutputInvalid,
    IoFailed,
    Reader(&'static str),
}

impl ExportError {
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            Self::ProfileMissing => "source_export_profile_missing",
            Self::ProfileInvalid => "source_export_profile_invalid",
            Self::ProfileMismatch => "source_export_profile_mismatch",
            Self::OutputInvalid => "source_export_output_invalid",
            Self::IoFailed => "source_export_io_failed",
            Self::Reader(kind) => kind,
        }
    }

    #[must_use]
    pub fn to_cli_error(self) -> crate::CliError {
        crate::CliError {
            code: 1,
            kind: self.kind(),
            message: self.kind().to_string(),
            hint: None,
            retryable: false,
        }
    }
}

fn reader_error(error: SourceFactsReadError) -> ExportError {
    ExportError::Reader(error.code())
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn create_new_0600(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_new_0600(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn create_dir_0700(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_dir_0700(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn set_mode_0700(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_mode_0700(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn owner_can_write_directory(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o300 == 0o300
}

#[cfg(not(unix))]
fn owner_can_write_directory(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn absolute_lexical(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::path::absolute(path)
    }
}

/// Admit the output root: every existing component must be an ordinary
/// directory (never a symlink), a missing tail is created `0700`, an existing
/// root must be empty and owner-writable, and the root is tightened to `0700`.
///
/// The input database path is rejected as an alias: the export never writes the
/// archive it reads.
fn admit_output_root(output: &Path, db_path: &Path) -> Result<(), ExportError> {
    let absolute = absolute_lexical(output).map_err(|_| ExportError::OutputInvalid)?;
    let db_absolute = absolute_lexical(db_path).map_err(|_| ExportError::OutputInvalid)?;
    if absolute == db_absolute {
        return Err(ExportError::OutputInvalid);
    }
    let mut current = PathBuf::from("/");
    for component in absolute.components().skip(1) {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ExportError::OutputInvalid);
                }
                if current == absolute {
                    let mut entries =
                        fs::read_dir(&current).map_err(|_| ExportError::OutputInvalid)?;
                    if entries.next().is_some() {
                        return Err(ExportError::OutputInvalid);
                    }
                    if !owner_can_write_directory(&metadata) {
                        return Err(ExportError::OutputInvalid);
                    }
                    set_mode_0700(&current).map_err(|_| ExportError::OutputInvalid)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_dir_0700(&current).map_err(|_| ExportError::IoFailed)?;
            }
            Err(_) => return Err(ExportError::OutputInvalid),
        }
    }
    Ok(())
}

fn new_run_id() -> String {
    let mut bytes = [0u8; 16];
    let first: u64 = rand::random();
    let second: u64 = rand::random();
    bytes[..8].copy_from_slice(&first.to_be_bytes());
    bytes[8..].copy_from_slice(&second.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn marker_bytes(run_id: &str, written_pages: u64, error_code: Option<&str>) -> Vec<u8> {
    let marker = json!({
        "schema": "cass.source-export.incomplete/2",
        "run_id": run_id,
        "written_pages": written_pages.to_string(),
        "error_code": error_code,
    });
    let mut bytes = serde_json::to_vec(&marker).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

fn create_marker(path: &Path, run_id: &str) -> io::Result<()> {
    let mut file = create_new_0600(path)?;
    file.write_all(&marker_bytes(run_id, 0, None))?;
    file.sync_all()
}

/// Best effort: a failed update keeps the original marker bytes.
fn update_marker(path: &Path, run_id: &str, written_pages: u64, error_code: Option<&str>) {
    let Ok(mut file) = OpenOptions::new().write(true).truncate(true).open(path) else {
        return;
    };
    if file
        .write_all(&marker_bytes(run_id, written_pages, error_code))
        .is_ok()
    {
        let _ = file.sync_all();
    }
}

// ---------------------------------------------------------------------------
// Strict JSON for the profile-materials FILE
// ---------------------------------------------------------------------------

/// A JSON value that refuses duplicate object members at every level.
enum StrictValue {
    Null,
    Bool(bool),
    Number,
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue::Bool(value))
            }

            fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue::Number)
            }

            fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue::Number)
            }

            fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
                Ok(StrictValue::Number)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue::String(value.to_string()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue::String(value))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue::Null)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue::Null)
            }

            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                StrictValue::deserialize(deserializer)
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = sequence.next_element()? {
                    items.push(item);
                }
                Ok(StrictValue::Array(items))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut members: Vec<(String, StrictValue)> = Vec::new();
                let mut seen = BTreeSet::new();
                while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom("duplicate object member"));
                    }
                    members.push((key, value));
                }
                Ok(StrictValue::Object(members))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

impl StrictValue {
    fn object(&self) -> Option<&[(String, Self)]> {
        match self {
            Self::Object(members) => Some(members),
            _ => None,
        }
    }

    fn array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    fn string(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    fn boolean(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// Fetch one member of a strictly parsed object. Unknown keys are the
    /// caller's responsibility; duplicates were refused during parsing.
    fn get(&self, key: &str) -> Option<&Self> {
        self.object()?
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// One validated profile-materials entry. Version semantics and the fixed copy
/// itself are checked only when an input references the pair.
#[derive(Clone)]
struct ProfileMaterial {
    normalizer_id: String,
    safety_contract_id: String,
    fad_pin: String,
    mapping_domain: String,
    exclusion_epoch: String,
    redaction_fingerprint: String,
    code_version: String,
    config_source_identity: String,
    fixed_copy_path: PathBuf,
    fixed_config_sha256: Sha256Digest,
    effective_four_arrays_sha256: Sha256Digest,
    desensitization_enabled: bool,
}

struct ProfileMaterials {
    items: Vec<ProfileMaterial>,
    by_pair: BTreeMap<(String, String), usize>,
}

const FAD_PIN: &str = "61f975f3b56f8dabc4ecbe1dae4102c1ea6b16e5";
const MAPPING_DOMAIN: &str = "cass-source-mapping/2";
const EXCLUSION_EPOCH: &str = "cass-source-exclusion/1";
const REDACTION_FINGERPRINT: &str =
    "redact-v1:fe8bda3a83e4f2f4fe85f0de5c84428140bfa658b7865706c43877488ec2bb47";
const CODE_VERSION: &str = "cass-source-exclusion/1+redact-v1:fe8bda3a83e4f2f4fe85f0de5c84428140bfa658b7865706c43877488ec2bb47";

const PROFILE_KEYS: [&str; 12] = [
    "normalizer_id",
    "safety_contract_id",
    "fad_pin",
    "mapping_domain",
    "exclusion_epoch",
    "redaction_fingerprint",
    "code_version",
    "config_source_identity",
    "fixed_copy_path",
    "fixed_config_sha256",
    "effective_four_arrays_sha256",
    "desensitization_enabled",
];

/// Read and structurally validate the profile-materials FILE.
///
/// Every item is checked for the exact key set, types and digest spellings;
/// version values and fixed copies are deferred to first reference.
fn read_profile_materials(path: &Path) -> Result<ProfileMaterials, ExportError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ExportError::ProfileMissing
        } else {
            ExportError::ProfileInvalid
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ExportError::ProfileInvalid);
    }
    let bytes = fs::read(path).map_err(|_| ExportError::ProfileInvalid)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| ExportError::ProfileInvalid)?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let root =
        StrictValue::deserialize(&mut deserializer).map_err(|_| ExportError::ProfileInvalid)?;
    deserializer
        .end()
        .map_err(|_| ExportError::ProfileInvalid)?;

    let members = root.object().ok_or(ExportError::ProfileInvalid)?;
    if members.len() != 2 {
        return Err(ExportError::ProfileInvalid);
    }
    if root.get("schema").and_then(StrictValue::string) != Some("cass.source-profile-materials/1") {
        return Err(ExportError::ProfileInvalid);
    }
    let items_value = root
        .get("profiles")
        .and_then(StrictValue::array)
        .ok_or(ExportError::ProfileInvalid)?;

    let mut items = Vec::with_capacity(items_value.len());
    let mut by_pair = BTreeMap::new();
    for item in items_value {
        let material = parse_profile_item(item)?;
        let pair = (
            material.normalizer_id.clone(),
            material.safety_contract_id.clone(),
        );
        if by_pair.contains_key(&pair) {
            return Err(ExportError::ProfileInvalid);
        }
        by_pair.insert(pair, items.len());
        items.push(material);
    }
    Ok(ProfileMaterials { items, by_pair })
}

fn parse_profile_item(value: &StrictValue) -> Result<ProfileMaterial, ExportError> {
    let members = value.object().ok_or(ExportError::ProfileInvalid)?;
    if members.len() != PROFILE_KEYS.len() {
        return Err(ExportError::ProfileInvalid);
    }
    let mut seen = BTreeSet::new();
    for (name, _) in members {
        if !PROFILE_KEYS.contains(&name.as_str()) || !seen.insert(name.as_str()) {
            return Err(ExportError::ProfileInvalid);
        }
    }
    let required = |key: &str| -> Result<&str, ExportError> {
        value
            .get(key)
            .and_then(StrictValue::string)
            .ok_or(ExportError::ProfileInvalid)
    };
    let normalizer_id = required("normalizer_id")?;
    let safety_contract_id = required("safety_contract_id")?;
    let fad_pin = required("fad_pin")?;
    let mapping_domain = required("mapping_domain")?;
    let exclusion_epoch = required("exclusion_epoch")?;
    let redaction_fingerprint = required("redaction_fingerprint")?;
    let code_version = required("code_version")?;
    let config_source_identity = required("config_source_identity")?;
    let fixed_copy_path = required("fixed_copy_path")?;
    let fixed_sha = required("fixed_config_sha256")?;
    let arrays_sha = required("effective_four_arrays_sha256")?;
    let desensitization_enabled = value
        .get("desensitization_enabled")
        .and_then(StrictValue::boolean)
        .ok_or(ExportError::ProfileInvalid)?;
    if !desensitization_enabled {
        return Err(ExportError::ProfileInvalid);
    }

    if !is_lower_hex(normalizer_id, 64)
        || !is_lower_hex(safety_contract_id, 64)
        || !is_lower_hex(fixed_sha, 64)
        || !is_lower_hex(arrays_sha, 64)
        || !is_lower_hex(fad_pin, 40)
        || config_source_identity.is_empty()
        || !Path::new(fixed_copy_path).is_absolute()
    {
        return Err(ExportError::ProfileInvalid);
    }
    Ok(ProfileMaterial {
        normalizer_id: normalizer_id.to_string(),
        safety_contract_id: safety_contract_id.to_string(),
        fad_pin: fad_pin.to_string(),
        mapping_domain: mapping_domain.to_string(),
        exclusion_epoch: exclusion_epoch.to_string(),
        redaction_fingerprint: redaction_fingerprint.to_string(),
        code_version: code_version.to_string(),
        config_source_identity: config_source_identity.to_string(),
        fixed_copy_path: PathBuf::from(fixed_copy_path),
        fixed_config_sha256: Sha256Digest::from_hex(fixed_sha)
            .ok_or(ExportError::ProfileInvalid)?,
        effective_four_arrays_sha256: Sha256Digest::from_hex(arrays_sha)
            .ok_or(ExportError::ProfileInvalid)?,
        desensitization_enabled,
    })
}

fn check_referenced_versions(material: &ProfileMaterial) -> Result<(), ExportError> {
    if material.fad_pin != FAD_PIN
        || material.mapping_domain != MAPPING_DOMAIN
        || material.exclusion_epoch != EXCLUSION_EPOCH
        || material.redaction_fingerprint != REDACTION_FINGERPRINT
        || material.code_version != CODE_VERSION
    {
        return Err(ExportError::ProfileInvalid);
    }
    Ok(())
}

/// Load, restore and verify one fixed configuration copy.
fn load_restored(material: &ProfileMaterial) -> Result<FixedSafetyConfig, ExportError> {
    match fs::symlink_metadata(&material.fixed_copy_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ExportError::ProfileMissing);
        }
        Err(_) => return Err(ExportError::ProfileInvalid),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(ExportError::ProfileInvalid);
        }
        Ok(_) => {}
    }
    let loaded = load_fixed_safety_config(&material.fixed_copy_path)
        .map_err(|_| ExportError::ProfileInvalid)?;
    if loaded.bytes_sha256() != &material.fixed_config_sha256 {
        return Err(ExportError::ProfileMismatch);
    }
    let verified = loaded
        .config()
        .verify()
        .map_err(|_| ExportError::ProfileMismatch)?;
    if verified.effective_four_arrays_sha256() != &material.effective_four_arrays_sha256 {
        return Err(ExportError::ProfileMismatch);
    }
    load_restore_fixed_safety(
        &material.fixed_copy_path,
        &material.config_source_identity,
        &material.fixed_config_sha256,
        &material.effective_four_arrays_sha256,
        &material.code_version,
    )
    .map_err(|_| ExportError::ProfileMismatch)
}

// ---------------------------------------------------------------------------
// Parser-context semantics
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ContextRewrite {
    from: String,
    to: String,
    agents: Option<Vec<String>>,
}

struct ParsedContext {
    schema: String,
    connector: String,
    roots: Vec<String>,
    role: String,
    origin_kind: String,
    origin_host: Option<String>,
    origin_source_version: Option<String>,
    platform: Option<String>,
    rewrites: Vec<ContextRewrite>,
    effective_digest: String,
}

fn context_mismatch<T>() -> Result<T, ExportError> {
    Err(ExportError::ProfileMismatch)
}

fn known_members<'a>(
    value: &'a LosslessSourceValue,
) -> Option<&'a Vec<(String, LosslessSourceValue)>> {
    match value {
        LosslessSourceValue::Object(members) => Some(members),
        _ => None,
    }
}

fn member<'a>(
    members: &'a [(String, LosslessSourceValue)],
    name: &str,
) -> Result<Option<&'a LosslessSourceValue>, ExportError> {
    let mut found = None;
    for (key, value) in members {
        if key == name {
            if found.is_some() {
                return context_mismatch();
            }
            found = Some(value);
        }
    }
    Ok(found)
}

fn required_member<'a>(
    members: &'a [(String, LosslessSourceValue)],
    name: &str,
) -> Result<&'a LosslessSourceValue, ExportError> {
    member(members, name)?.ok_or(ExportError::ProfileMismatch)
}

fn as_string(value: &LosslessSourceValue) -> Result<&str, ExportError> {
    match value {
        LosslessSourceValue::String(text) => Ok(text),
        _ => context_mismatch(),
    }
}

fn as_optional_string(value: &LosslessSourceValue) -> Result<Option<String>, ExportError> {
    match value {
        LosslessSourceValue::Null => Ok(None),
        LosslessSourceValue::String(text) => Ok(Some(text.clone())),
        _ => context_mismatch(),
    }
}

fn as_array(value: &LosslessSourceValue) -> Result<&Vec<LosslessSourceValue>, ExportError> {
    match value {
        LosslessSourceValue::Array(items) => Ok(items),
        _ => context_mismatch(),
    }
}

/// Extract only the frozen semantic members needed for the effective
/// configuration. The complete stored tree is still emitted verbatim; this
/// helper never rewrites it and never invents a default for a missing member.
fn extract_context(value: &LosslessSourceValue) -> Result<ParsedContext, ExportError> {
    let members = known_members(value).ok_or(ExportError::ProfileMismatch)?;
    let schema = as_string(required_member(members, "schema")?)?.to_string();
    if schema != "cass.source-parser-context/1" {
        return context_mismatch();
    }
    let connector = as_string(required_member(members, "connector")?)?.to_string();
    let role = as_string(required_member(members, "role")?)?.to_string();

    let roots_value = required_member(members, "discovery_roots")?;
    let roots_array = as_array(roots_value)?;
    if roots_array.is_empty() {
        return context_mismatch();
    }
    let mut roots = Vec::with_capacity(roots_array.len());
    for root in roots_array {
        roots.push(as_string(root)?.to_string());
    }

    let origin = required_member(members, "origin")?;
    let origin_members = known_members(origin).ok_or(ExportError::ProfileMismatch)?;
    let origin_kind = as_string(required_member(origin_members, "kind")?)?.to_string();
    let origin_host = as_optional_string(required_member(origin_members, "host")?)?;
    let origin_source_version =
        as_optional_string(required_member(origin_members, "source_version")?)?;

    let platform = as_optional_string(required_member(members, "platform")?)?;

    let rewrites_value = required_member(members, "workspace_rewrites")?;
    let rewrites_array = as_array(rewrites_value)?;
    let mut rewrites = Vec::with_capacity(rewrites_array.len());
    for rewrite in rewrites_array {
        let rewrite_members = known_members(rewrite).ok_or(ExportError::ProfileMismatch)?;
        let from = as_string(required_member(rewrite_members, "from")?)?.to_string();
        let to = as_string(required_member(rewrite_members, "to")?)?.to_string();
        let agents = match member(rewrite_members, "agents")? {
            None | Some(LosslessSourceValue::Null) => None,
            Some(LosslessSourceValue::Array(items)) => {
                let mut names = Vec::with_capacity(items.len());
                for item in items {
                    names.push(as_string(item)?.to_string());
                }
                Some(names)
            }
            Some(_) => return context_mismatch(),
        };
        rewrites.push(ContextRewrite { from, to, agents });
    }

    // A top-level `agents` member is an extra field: it is neither a known
    // semantic member of the effective material nor a reason to refuse the
    // context. The complete original tree is still emitted verbatim, and only
    // `workspace_rewrites[].agents` is strictly typed above.

    let summary = required_member(members, "effective_config_summary")?;
    let summary_members = known_members(summary).ok_or(ExportError::ProfileMismatch)?;
    let digest_value = required_member(summary_members, "effective_digest")?;
    let effective_digest = match digest_value {
        LosslessSourceValue::String(text) if is_lower_hex(text, 64) => text.clone(),
        _ => return context_mismatch(),
    };

    Ok(ParsedContext {
        schema,
        connector,
        roots,
        role,
        origin_kind,
        origin_host,
        origin_source_version,
        platform,
        rewrites,
        effective_digest,
    })
}

/// Build the same effective-configuration material the accepted scan path
/// builds: schema, connector, ordered roots with origin/platform/rewrites, and
/// role. Relative locators and live configuration are deliberately absent.
fn effective_material(context: &ParsedContext) -> Value {
    let rewrites: Vec<Value> = context
        .rewrites
        .iter()
        .map(|rewrite| {
            let mut object = serde_json::Map::new();
            object.insert("from".to_string(), json!(&rewrite.from));
            object.insert("to".to_string(), json!(&rewrite.to));
            if let Some(agents) = &rewrite.agents {
                object.insert("agents".to_string(), json!(agents));
            }
            Value::Object(object)
        })
        .collect();
    let roots: Vec<Value> = context
        .roots
        .iter()
        .map(|root| {
            json!({
                "path": root,
                "origin": {
                    "kind": &context.origin_kind,
                    "host": &context.origin_host,
                    "source_version": &context.origin_source_version,
                },
                "platform": &context.platform,
                "workspace_rewrites": &rewrites,
            })
        })
        .collect();
    json!({
        "schema": &context.schema,
        "connector": &context.connector,
        "roots": roots,
        "role": &context.role,
    })
}

// ---------------------------------------------------------------------------
// Wire encoding
// ---------------------------------------------------------------------------

fn tag_value(value: &Value) -> Value {
    match value {
        Value::Null => json!(["null"]),
        Value::Bool(flag) => json!(["bool", flag]),
        Value::Number(number) => json!(["num", number.to_string()]),
        Value::String(text) => json!(["str", text]),
        Value::Array(items) => {
            let mut tagged = Vec::with_capacity(items.len());
            for item in items {
                tagged.push(tag_value(item));
            }
            json!(["arr", tagged])
        }
        Value::Object(members) => {
            let mut tagged = Vec::with_capacity(members.len());
            for (key, item) in members {
                tagged.push(json!([key, tag_value(item)]));
            }
            json!(["obj", tagged])
        }
    }
}

/// Embed one canonical leaf array (already compact JSON) without changing it.
fn canonical_array(bytes: &[u8]) -> Result<Value, ExportError> {
    serde_json::from_slice(bytes).map_err(|_| ExportError::IoFailed)
}

/// The versioned canonical array rendered as the frozen tagged logical tree.
fn tagged_canonical(bytes: &[u8]) -> Result<Value, ExportError> {
    Ok(tag_value(&canonical_array(bytes)?))
}

fn tagged_lossless(value: &LosslessSourceValue) -> Result<Value, ExportError> {
    let mut bytes = Vec::new();
    value
        .write_tagged(&mut bytes)
        .map_err(|_| ExportError::IoFailed)?;
    serde_json::from_slice(&bytes).map_err(|_| ExportError::IoFailed)
}

fn tagged_object(members: Vec<(&str, Value)>) -> Value {
    let pairs: Vec<Value> = members
        .into_iter()
        .map(|(name, value)| json!([name, value]))
        .collect();
    json!(["obj", pairs])
}

fn tagged_diagnostics(envelope: &DiagnosticsEnvelope) -> Result<Value, ExportError> {
    let mut items = Vec::with_capacity(envelope.items.len());
    for item in &envelope.items {
        items.push(tagged_canonical(&item.encode())?);
    }
    Ok(tagged_object(vec![
        ("version", json!(["num", envelope.version.to_string()])),
        ("domain", json!(["str", &envelope.domain])),
        ("items", json!(["arr", items])),
    ]))
}

fn tagged_unprocessed(envelope: &UnprocessedRangesEnvelope) -> Value {
    let mut items = Vec::with_capacity(envelope.items.len());
    for item in &envelope.items {
        items.push(tagged_object(vec![
            ("start", json!(["str", item.start.to_string()])),
            ("end", json!(["str", item.end.to_string()])),
            ("reason", json!(["str", &item.reason])),
            (
                "ordinal",
                match item.ordinal {
                    Some(value) => json!(["str", value.to_string()]),
                    None => json!(["null"]),
                },
            ),
            (
                "record_pointer",
                match &item.record_pointer {
                    Some(value) => json!(["str", value]),
                    None => json!(["null"]),
                },
            ),
        ]));
    }
    tagged_object(vec![
        ("version", json!(["num", envelope.version.to_string()])),
        ("domain", json!(["str", &envelope.domain])),
        ("items", json!(["arr", items])),
    ])
}

fn tagged_finish(finish: &VerifiedFinish) -> Result<Value, ExportError> {
    tagged_canonical(&finish.encode())
}

fn tagged_attempt_history(history: &AttemptHistory) -> Result<Value, ExportError> {
    let original = match &history.original_success_finish {
        Some(finish) => tagged_finish(finish)?,
        None => json!(["null"]),
    };
    let mut attempts = Vec::with_capacity(history.attempts.len());
    for attempt in &history.attempts {
        attempts.push(tagged_object(vec![
            ("attempt", json!(["str", attempt.attempt.to_string()])),
            ("measured_finish", tagged_finish(&attempt.measured_finish)?),
            ("outcome", json!(["str", &attempt.outcome])),
        ]));
    }
    let last_failure = match &history.last_published_failure {
        Some(digest) => json!(["str", digest.hex()]),
        None => json!(["null"]),
    };
    Ok(tagged_object(vec![
        ("version", json!(["num", history.version.to_string()])),
        ("domain", json!(["str", history.domain])),
        ("original_success_finish", original),
        ("attempts", json!(["arr", attempts])),
        ("last_published_failure", last_failure),
    ]))
}

fn decimal(value: u64) -> String {
    value.to_string()
}

fn input_wire(input: &SourceFactsInput) -> Result<Value, ExportError> {
    let mut object = serde_json::Map::new();
    object.insert("input_key".to_string(), json!(input.input_key.hex()));
    object.insert("identity_tuple".to_string(), json!(&input.identity_tuple));
    object.insert(
        "identity_namespace".to_string(),
        json!(&input.identity_namespace),
    );
    object.insert("source_id".to_string(), json!(&input.source_id));
    object.insert("connector".to_string(), json!(&input.connector));
    object.insert("root_id".to_string(), json!(&input.root_id));
    object.insert(
        "relative_locator".to_string(),
        json!(&input.relative_locator),
    );
    object.insert("origin_kind".to_string(), json!(&input.origin_kind));
    object.insert("origin_host".to_string(), json!(&input.origin_host));
    object.insert(
        "origin_source_version".to_string(),
        json!(&input.origin_source_version),
    );
    object.insert("role".to_string(), json!(&input.role));
    object.insert("platform".to_string(), json!(&input.platform));
    object.insert("discovery".to_string(), tagged_lossless(&input.discovery)?);
    object.insert(
        "parser_context".to_string(),
        tagged_lossless(&input.parser_context)?,
    );
    object.insert(
        "sealed_ref".to_string(),
        tagged_lossless(&input.sealed_ref)?,
    );
    object.insert(
        "context_digest".to_string(),
        json!(input.context_digest.hex()),
    );
    object.insert(
        "sealed_sha256".to_string(),
        json!(input.sealed_sha256.hex()),
    );
    object.insert("byte_len".to_string(), json!(decimal(input.byte_len)));
    object.insert("format".to_string(), json!(input.format.as_str()));
    object.insert(
        "expected_manifest".to_string(),
        canonical_array(&encode_expected_manifest_header(
            &input.expected_manifest.manifest,
            &input.expected_manifest.safety,
        ))?,
    );
    object.insert("normalizer_id".to_string(), json!(&input.normalizer_id));
    object.insert(
        "safety_contract_id".to_string(),
        json!(&input.safety_contract_id),
    );
    object.insert("state".to_string(), json!(&input.state));
    object.insert(
        "expected_records".to_string(),
        json!(decimal(input.expected_records)),
    );
    object.insert(
        "expected_blank_lines".to_string(),
        json!(decimal(input.expected_blank_lines)),
    );
    object.insert(
        "observed_records".to_string(),
        match input.observed_records {
            Some(value) => json!(decimal(value)),
            None => Value::Null,
        },
    );
    object.insert(
        "observed_blank_lines".to_string(),
        match input.observed_blank_lines {
            Some(value) => json!(decimal(value)),
            None => Value::Null,
        },
    );
    object.insert(
        "unprocessed_ranges".to_string(),
        match &input.unprocessed_ranges {
            Some(envelope) => tagged_unprocessed(envelope),
            None => Value::Null,
        },
    );
    object.insert(
        "attempt_history".to_string(),
        match &input.attempt_history {
            Some(history) => tagged_attempt_history(history)?,
            None => Value::Null,
        },
    );
    object.insert(
        "activation_request_hash".to_string(),
        match &input.activation_request_hash {
            Some(digest) => json!(digest.hex()),
            None => Value::Null,
        },
    );
    object.insert("receipt_key".to_string(), json!(&input.receipt_key));
    object.insert(
        "applied_content_generation".to_string(),
        json!(&input.applied_content_generation),
    );
    Ok(Value::Object(object))
}

fn link_wire(link: &SourceFactsRecordLink) -> Result<Value, ExportError> {
    let mut object = serde_json::Map::new();
    object.insert(
        "claim".to_string(),
        canonical_array(&link.claim.encode_leaf())?,
    );
    object.insert(
        "original_installation".to_string(),
        match &link.original_installation {
            Some(installation) => canonical_array(&installation.encode())?,
            None => Value::Null,
        },
    );
    object.insert(
        "binding_digest".to_string(),
        json!(link.binding_digest.hex()),
    );
    object.insert("authority".to_string(), json!(&link.authority));
    object.insert(
        "message_id".to_string(),
        match link.message_id {
            Some(value) => json!(value.to_string()),
            None => Value::Null,
        },
    );
    Ok(Value::Object(object))
}

fn raw_record_wire(record: &RawSourceFactsRecord) -> Result<Value, ExportError> {
    let mut object = serde_json::Map::new();
    object.insert("input_key".to_string(), json!(record.input_key.hex()));
    object.insert("ordinal".to_string(), json!(decimal(record.ordinal)));
    object.insert("record_pointer".to_string(), json!(&record.record_pointer));
    object.insert("byte_start".to_string(), json!(decimal(record.byte_start)));
    object.insert("byte_end".to_string(), json!(decimal(record.byte_end)));
    object.insert(
        "record_byte_len".to_string(),
        json!(decimal(record.record_byte_len)),
    );
    object.insert(
        "expected_source_record_sha256".to_string(),
        json!(record.expected_source_record_sha256.hex()),
    );
    object.insert(
        "observed_source_record_sha256".to_string(),
        match &record.observed_source_record_sha256 {
            Some(digest) => json!(digest.hex()),
            None => Value::Null,
        },
    );
    object.insert("frame_state".to_string(), json!(&record.frame_state));
    object.insert("parse_state".to_string(), json!(&record.parse_state));
    object.insert(
        "record_mapping_state".to_string(),
        json!(&record.record_mapping_state),
    );
    object.insert("safety_state".to_string(), json!(&record.safety_state));
    object.insert(
        "retention_state".to_string(),
        json!(&record.retention_state),
    );
    object.insert("codec".to_string(), json!(&record.codec));
    object.insert(
        "payload_base64".to_string(),
        match &record.payload {
            Some(bytes) => json!(base64::engine::general_purpose::STANDARD.encode(bytes)),
            None => Value::Null,
        },
    );
    object.insert(
        "payload_sha256".to_string(),
        match &record.payload_sha256 {
            Some(digest) => json!(digest.hex()),
            None => Value::Null,
        },
    );
    object.insert(
        "safe_value_hash".to_string(),
        match &record.safe_value_hash {
            Some(digest) => json!(digest.hex()),
            None => Value::Null,
        },
    );
    object.insert(
        "safe_value".to_string(),
        match &record.safe_value {
            Some(value) => tagged_lossless(value)?,
            None => Value::Null,
        },
    );
    object.insert(
        "native_ids".to_string(),
        match &record.native_ids {
            Some(value) => tagged_lossless(value)?,
            None => Value::Null,
        },
    );
    object.insert(
        "diagnostics".to_string(),
        match &record.diagnostics {
            Some(envelope) => tagged_diagnostics(envelope)?,
            None => Value::Null,
        },
    );
    let mut links = Vec::with_capacity(record.links.len());
    for link in &record.links {
        links.push(link_wire(link)?);
    }
    object.insert("links".to_string(), Value::Array(links));
    Ok(Value::Object(object))
}

fn record_wire(record: &SourceFactsRecord) -> Result<Value, ExportError> {
    let mut value = raw_record_wire(&record.raw)?;
    let standard = match &record.standard {
        Some(facts) => serde_json::to_value(facts).map_err(|_| ExportError::IoFailed)?,
        None => Value::Null,
    };
    if let Value::Object(object) = &mut value {
        object.insert("standard".to_string(), standard);
    }
    Ok(value)
}

fn page_body_wire(page: &SourceFactsPage) -> Result<Value, ExportError> {
    let mut inputs = Vec::with_capacity(page.inputs.len());
    for input in &page.inputs {
        inputs.push(input_wire(input)?);
    }
    let mut records = Vec::with_capacity(page.records.len());
    for record in &page.records {
        records.push(record_wire(record)?);
    }
    Ok(json!({
        "reader_version": page.reader_version,
        "library_identity": &page.library_identity,
        "source_facts_revision": decimal(page.source_facts_revision),
        "filter_digest": page.filter_digest.hex(),
        "inputs": inputs,
        "records": records,
        "oversized_records": decimal(page.oversized_records),
        "next_cursor": &page.next_cursor,
    }))
}

fn page_wrapper_wire(
    page: &SourceFactsPage,
    page_index: u64,
    cursor_before: Option<&str>,
) -> Result<Value, ExportError> {
    Ok(json!({
        "schema": "cass.source-export.page/2",
        "page_index": decimal(page_index),
        "cursor_before": cursor_before,
        "cursor_after": &page.next_cursor,
        "page": page_body_wire(page)?,
    }))
}

// ---------------------------------------------------------------------------
// Profile validation per input
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ProfileIndexEntry {
    material: ProfileMaterial,
    relative_path: String,
    byte_len: String,
}

struct ExportState {
    copied_profiles: BTreeMap<String, Vec<u8>>,
    index_profiles: BTreeMap<(String, String), ProfileIndexEntry>,
    headers: BTreeMap<[u8; 32], Value>,
    library_identity: Option<String>,
    revision: Option<u64>,
    filter_digest: Option<Sha256Digest>,
    page_count: u64,
    record_count: u64,
    oversized_records: u64,
}

impl ExportState {
    fn new() -> Self {
        Self {
            copied_profiles: BTreeMap::new(),
            index_profiles: BTreeMap::new(),
            headers: BTreeMap::new(),
            library_identity: None,
            revision: None,
            filter_digest: None,
            page_count: 0,
            record_count: 0,
            oversized_records: 0,
        }
    }
}

fn validate_input(
    input: &SourceFactsInput,
    materials: &ProfileMaterials,
    output: &Path,
    state: &mut ExportState,
) -> Result<(), ExportError> {
    let pair = (
        input.normalizer_id.clone(),
        input.safety_contract_id.clone(),
    );
    let index = *materials
        .by_pair
        .get(&pair)
        .ok_or(ExportError::ProfileMissing)?;
    let material = &materials.items[index];
    check_referenced_versions(material)?;

    let restored = load_restored(material)?;
    let context = extract_context(&input.parser_context)?;
    let assembled = SourceProfile::assemble(&restored, &effective_material(&context))
        .map_err(|_| ExportError::ProfileMismatch)?;
    if assembled.effective_config_digest != context.effective_digest {
        return Err(ExportError::ProfileMismatch);
    }
    if assembled.normalizer_id != input.normalizer_id
        || assembled.normalizer_id != material.normalizer_id
        || assembled.safety_contract_id != input.safety_contract_id
        || assembled.safety_contract_id != material.safety_contract_id
    {
        return Err(ExportError::ProfileMismatch);
    }

    let safety = &input.expected_manifest.safety;
    if safety.code_version() != material.code_version
        || safety.code_version() != restored.config().code_version
        || !safety.desensitization_enabled()
        || safety.config_source_identity() != material.config_source_identity
        || safety.fixed_config_sha256() != &material.fixed_config_sha256
        || safety.effective_four_arrays_sha256() != &material.effective_four_arrays_sha256
    {
        return Err(ExportError::ProfileMismatch);
    }

    ensure_profile_copied(material, &restored, output, state)
}

fn ensure_profile_copied(
    material: &ProfileMaterial,
    restored: &FixedSafetyConfig,
    output: &Path,
    state: &mut ExportState,
) -> Result<(), ExportError> {
    let safety_id = material.safety_contract_id.as_str();
    let bytes = restored.config().fixed_config_bytes.clone();
    if let Some(existing) = state.copied_profiles.get(safety_id) {
        if existing != &bytes {
            return Err(ExportError::ProfileMismatch);
        }
    } else {
        restored
            .recheck_bytes()
            .map_err(|_| ExportError::ProfileMismatch)?;
        let relative_path = format!("profiles/{safety_id}.toml");
        let path = output.join(&relative_path);
        let mut file = create_new_0600(&path).map_err(|_| ExportError::IoFailed)?;
        file.write_all(&bytes).map_err(|_| ExportError::IoFailed)?;
        file.sync_all().map_err(|_| ExportError::IoFailed)?;
        let actual = fs::read(&path).map_err(|_| ExportError::IoFailed)?;
        if Sha256Digest::of(&actual) != material.fixed_config_sha256 {
            return Err(ExportError::IoFailed);
        }
        restored
            .recheck_bytes()
            .map_err(|_| ExportError::ProfileMismatch)?;
        state
            .copied_profiles
            .insert(safety_id.to_string(), bytes.clone());
    }
    state
        .index_profiles
        .entry((
            material.normalizer_id.clone(),
            material.safety_contract_id.clone(),
        ))
        .or_insert_with(|| ProfileIndexEntry {
            material: material.clone(),
            relative_path: format!("profiles/{safety_id}.toml"),
            byte_len: bytes.len().to_string(),
        });
    Ok(())
}

fn profile_index_value(entry: &ProfileIndexEntry) -> Value {
    json!({
        "normalizer_id": &entry.material.normalizer_id,
        "safety_contract_id": &entry.material.safety_contract_id,
        "fad_pin": &entry.material.fad_pin,
        "mapping_domain": &entry.material.mapping_domain,
        "exclusion_epoch": &entry.material.exclusion_epoch,
        "redaction_fingerprint": &entry.material.redaction_fingerprint,
        "code_version": &entry.material.code_version,
        "config_source_identity": &entry.material.config_source_identity,
        "fixed_config_sha256": entry.material.fixed_config_sha256.hex(),
        "effective_four_arrays_sha256": entry.material.effective_four_arrays_sha256.hex(),
        "desensitization_enabled": entry.material.desensitization_enabled,
        "relative_path": &entry.relative_path,
        "byte_len": &entry.byte_len,
        "sha256": entry.material.fixed_config_sha256.hex(),
    })
}

fn record_header(input: &SourceFactsInput, state: &mut ExportState) -> Result<(), ExportError> {
    let wire = input_wire(input)?;
    match state.headers.get(input.input_key.as_bytes()) {
        Some(existing) => {
            if existing != &wire {
                return Err(ExportError::Reader("decode_failed"));
            }
        }
        None => {
            state.headers.insert(*input.input_key.as_bytes(), wire);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pause handshake
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum PausePoint {
    PagePartial,
    IndexBeforePublish,
    IndexAfterPublish,
}

impl PausePoint {
    fn as_str(self) -> &'static str {
        match self {
            Self::PagePartial => "page_partial",
            Self::IndexBeforePublish => "index_before_publish",
            Self::IndexAfterPublish => "index_after_publish",
        }
    }
}

fn maybe_pause(point: PausePoint) -> Result<(), ExportError> {
    let Ok(requested) = dotenvy::var("CASS_SOURCE_EXPORT_PAUSE_AT") else {
        return Ok(());
    };
    if requested != point.as_str() {
        return Ok(());
    }
    let sentinel =
        dotenvy::var("CASS_SOURCE_EXPORT_PAUSE_SENTINEL").map_err(|_| ExportError::IoFailed)?;
    if sentinel.is_empty() {
        return Err(ExportError::IoFailed);
    }
    let mut file = create_new_0600(Path::new(&sentinel)).map_err(|_| ExportError::IoFailed)?;
    file.write_all(point.as_str().as_bytes())
        .map_err(|_| ExportError::IoFailed)?;
    file.write_all(b"\n").map_err(|_| ExportError::IoFailed)?;
    file.sync_all().map_err(|_| ExportError::IoFailed)?;
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Run one complete export and return the fixed success summary.
///
/// # Errors
/// The closed [`ExportError`] set. No error carries a detail string.
pub fn run_export(options: &ExportOptions) -> Result<ExportSummary, ExportError> {
    admit_output_root(&options.output, &options.db_path)?;
    let marker = options.output.join("INCOMPLETE.json");
    let run_id = new_run_id();
    create_marker(&marker, &run_id).map_err(|_| ExportError::IoFailed)?;
    let mut pages_written = 0u64;
    let result = export_after_marker(options, &marker, &run_id, &mut pages_written);
    if let Err(error) = &result {
        update_marker(&marker, &run_id, pages_written, Some(error.kind()));
    }
    result
}

fn export_after_marker(
    options: &ExportOptions,
    marker: &Path,
    run_id: &str,
    pages_written: &mut u64,
) -> Result<ExportSummary, ExportError> {
    let materials = read_profile_materials(&options.profile_materials)?;

    create_dir_0700(&options.output.join("pages")).map_err(|_| ExportError::IoFailed)?;
    create_dir_0700(&options.output.join("profiles")).map_err(|_| ExportError::IoFailed)?;

    // The reader owns the zero/overflow page-limit refusals. Opening the
    // database comes first, so a missing database is always `db_error`; an
    // unrepresentable `max_records` is the same closed `invalid_cursor` refusal
    // only after the reader has opened the archive.
    let reader = SourceFactsReader::open(&options.db_path).map_err(reader_error)?;
    if options.max_records > usize::MAX as u64 {
        return Err(ExportError::Reader("invalid_cursor"));
    }
    let limits = SourceFactsPageLimits {
        max_records: options.max_records as usize,
        target_bytes: options.target_bytes,
    };
    let mut state = ExportState::new();
    let mut cursor: Option<String> = None;
    let mut pages_meta: Vec<Value> = Vec::new();
    let output = &options.output;

    loop {
        let page = reader
            .read_source_facts(&options.filter, cursor.as_deref(), limits)
            .map_err(reader_error)?;

        match &state.library_identity {
            None => state.library_identity = Some(page.library_identity.clone()),
            Some(existing) if existing != &page.library_identity => {
                return Err(ExportError::Reader("invalid_cursor"));
            }
            Some(_) => {}
        }
        match state.revision {
            None => state.revision = Some(page.source_facts_revision),
            Some(existing) if existing != page.source_facts_revision => {
                return Err(ExportError::Reader("invalid_cursor"));
            }
            Some(_) => {}
        }
        match state.filter_digest {
            None => state.filter_digest = Some(page.filter_digest),
            Some(existing) if existing != page.filter_digest => {
                return Err(ExportError::Reader("invalid_cursor"));
            }
            Some(_) => {}
        }

        for input in &page.inputs {
            validate_input(input, &materials, output, &mut state)?;
        }
        for input in &page.inputs {
            record_header(input, &mut state)?;
        }

        let page_index = state.page_count;
        if page_index > 999_999_999_999 {
            return Err(ExportError::OutputInvalid);
        }
        let wrapper = page_wrapper_wire(&page, page_index, cursor.as_deref())?;
        let mut bytes = serde_json::to_vec(&wrapper).map_err(|_| ExportError::IoFailed)?;
        bytes.push(b'\n');
        write_page(output, page_index, &bytes)?;

        pages_written_add(pages_written);
        update_marker(marker, run_id, *pages_written, None);
        let page_path = format!("pages/{page_index:012}.json");
        pages_meta.push(json!({
            "index": decimal(page_index),
            "path": page_path,
            "byte_len": decimal(bytes.len() as u64),
            "sha256": Sha256Digest::of(&bytes).hex(),
        }));
        state.page_count += 1;
        state.record_count += page.records.len() as u64;
        state.oversized_records += page.oversized_records;

        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    let library_identity = state
        .library_identity
        .clone()
        .ok_or(ExportError::Reader("db_error"))?;
    let revision = state.revision.ok_or(ExportError::Reader("db_error"))?;
    let filter_digest = state.filter_digest.ok_or(ExportError::Reader("db_error"))?;

    let mut connectors = options.filter.connectors.clone();
    connectors.sort();
    connectors.dedup();
    let mut keys = options.filter.input_keys.clone();
    keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    keys.dedup();
    let key_text: Vec<String> = keys.iter().map(Sha256Digest::hex).collect();

    let profiles: Vec<Value> = state
        .index_profiles
        .values()
        .map(profile_index_value)
        .collect();

    let index = json!({
        "schema": "cass.source-export/2",
        "role": "candidate",
        "surface": "cass_safe_facts",
        "reader_version": 2u32,
        "library_identity": library_identity,
        "source_facts_revision": decimal(revision),
        "filter": {
            "scope": options.filter.scope.as_str(),
            "connectors": connectors,
            "input_keys": key_text,
        },
        "filter_digest": filter_digest.hex(),
        "page_limits": {
            "max_records": decimal(options.max_records),
            "target_bytes": decimal(options.target_bytes),
        },
        "pages": pages_meta,
        "profiles": profiles,
        "unique_input_count": decimal(state.headers.len() as u64),
        "record_count": decimal(state.record_count),
        "oversized_records": decimal(state.oversized_records),
    });
    let mut index_bytes = serde_json::to_vec(&index).map_err(|_| ExportError::IoFailed)?;
    index_bytes.push(b'\n');
    let index_sha = Sha256Digest::of(&index_bytes).hex();

    sync_dir(&output.join("pages")).map_err(|_| ExportError::IoFailed)?;
    sync_dir(&output.join("profiles")).map_err(|_| ExportError::IoFailed)?;

    let tmp_path = output.join("index.json.tmp");
    let mut tmp = create_new_0600(&tmp_path).map_err(|_| ExportError::IoFailed)?;
    tmp.write_all(&index_bytes)
        .map_err(|_| ExportError::IoFailed)?;
    tmp.sync_all().map_err(|_| ExportError::IoFailed)?;
    sync_dir(output).map_err(|_| ExportError::IoFailed)?;

    maybe_pause(PausePoint::IndexBeforePublish)?;
    fs::rename(&tmp_path, output.join("index.json")).map_err(|_| ExportError::IoFailed)?;
    sync_dir(output).map_err(|_| ExportError::IoFailed)?;
    maybe_pause(PausePoint::IndexAfterPublish)?;

    fs::remove_file(marker).map_err(|_| ExportError::IoFailed)?;
    sync_dir(output).map_err(|_| ExportError::IoFailed)?;

    Ok(ExportSummary {
        page_count: state.page_count,
        unique_input_count: state.headers.len() as u64,
        record_count: state.record_count,
        oversized_records: state.oversized_records,
        index_sha256: index_sha,
    })
}

fn pages_written_add(pages_written: &mut u64) {
    *pages_written += 1;
}

fn write_page(output: &Path, page_index: u64, bytes: &[u8]) -> Result<(), ExportError> {
    let page_path = output.join("pages").join(format!("{page_index:012}.json"));
    let mut file = create_new_0600(&page_path).map_err(|_| ExportError::IoFailed)?;
    let (first, rest) = bytes.split_first().ok_or(ExportError::IoFailed)?;
    file.write_all(std::slice::from_ref(first))
        .map_err(|_| ExportError::IoFailed)?;
    if page_index == 0 {
        maybe_pause(PausePoint::PagePartial)?;
    }
    file.write_all(rest).map_err(|_| ExportError::IoFailed)?;
    file.sync_all().map_err(|_| ExportError::IoFailed)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The one private grammar row
// ---------------------------------------------------------------------------

#[cfg(test)]
mod context_grammar_tests {
    use super::*;

    fn string(value: &str) -> LosslessSourceValue {
        LosslessSourceValue::String(value.to_string())
    }

    fn normal_tree() -> Vec<(String, LosslessSourceValue)> {
        vec![
            ("schema".to_string(), string("cass.source-parser-context/1")),
            ("connector".to_string(), string("codex")),
            (
                "discovery_roots".to_string(),
                LosslessSourceValue::Array(vec![string("/root")]),
            ),
            ("relative_locator".to_string(), string("session.jsonl")),
            ("role".to_string(), string("primary_session_log")),
            (
                "origin".to_string(),
                LosslessSourceValue::Object(vec![
                    ("kind".to_string(), string("local")),
                    ("host".to_string(), LosslessSourceValue::Null),
                    ("source_version".to_string(), LosslessSourceValue::Null),
                ]),
            ),
            ("platform".to_string(), LosslessSourceValue::Null),
            (
                "workspace_rewrites".to_string(),
                LosslessSourceValue::Array(Vec::new()),
            ),
            (
                "effective_config_summary".to_string(),
                LosslessSourceValue::Object(vec![(
                    "effective_digest".to_string(),
                    string("a0503a135f1e6f73fccd9f91624b450b0a2eefb53b01803c5bca9c7250e11b0d"),
                )]),
            ),
        ]
    }

    #[test]
    fn u17_01_duplicate_semantic_member() {
        // Normal control: the actual private extractor accepts a normal tree.
        let normal = LosslessSourceValue::Object(normal_tree());
        let parsed = extract_context(&normal).expect("normal context accepted");
        assert_eq!(parsed.connector, "codex");

        // Extra top-level `agents` is opaque: any type is accepted, and the
        // effective material is unchanged because the member is not semantic.
        let normal_material = effective_material(&parsed);
        let mut with_extra = normal_tree();
        with_extra.push(("agents".to_string(), string("opaque-top-level-extra")));
        let parsed_extra = extract_context(&LosslessSourceValue::Object(with_extra))
            .expect("top-level opaque agents accepted");
        assert_eq!(effective_material(&parsed_extra), normal_material);

        // Negative: a duplicate `connector` member is refused by the same
        // private extractor. The SDK parser and context digest already refuse
        // duplicate members before registration, so this component-level tree
        // is the only real construction point.
        let mut members = normal_tree();
        members.push(("connector".to_string(), string("claude_code")));
        let duplicated = LosslessSourceValue::Object(members);
        assert!(matches!(
            extract_context(&duplicated),
            Err(ExportError::ProfileMismatch)
        ));
    }
}
