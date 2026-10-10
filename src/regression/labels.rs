//! Immutable label versions. A file pin is a request, never a validation proof.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::blind::VerifiedLabelRun;
use super::input::WirePinned;
use super::types::{InputOptions, LabelKey, OutputOptions, ValidatedInputs};

#[derive(Clone, Debug)]
pub(crate) struct FilePin {
    path: PathBuf,
    expected_sha256: String,
}

impl FilePin {
    pub(crate) fn new(path: PathBuf, expected_sha256: String) -> Result<Self> {
        require(is_hex(&expected_sha256, 64), "LABEL_FILE_IDENTITY_MISMATCH")?;
        Ok(Self {
            path,
            expected_sha256,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn expected_sha256(&self) -> &str {
        &self.expected_sha256
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum HumanLabel {
    Direct,
    Partial,
    None,
    Unsure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotLabel {
    Known(HumanLabel),
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LabelCoverageState {
    Complete,
    IncompleteLabels,
}

// No constructor from records: the only production constructor runs the old
// suite/registry/window/scoreability/freeze guards.
pub(crate) struct LegacyBaseValidated {
    input: InputOptions,
    pin: FilePin,
    suite_sha256: String,
    policy_sha256: String,
    labels: HashMap<LabelKey, HumanLabel>,
    query_bindings: Vec<(String, String)>,
    inputs: ValidatedInputs,
    windows_bytes: Vec<u8>,
}

impl LegacyBaseValidated {
    pub(super) fn reload(&self) -> Result<Self> {
        let current = load_legacy_base(&self.input)?;
        require(
            current.pin.expected_sha256() == self.pin.expected_sha256()
                && current.suite_sha256 == self.suite_sha256
                && current.policy_sha256 == self.policy_sha256,
            "LABEL_PARENT_MISMATCH",
        )?;
        Ok(current)
    }
    pub(super) fn inputs(&self) -> &ValidatedInputs {
        &self.inputs
    }
    pub(super) fn windows_bytes(&self) -> &[u8] {
        &self.windows_bytes
    }
    pub(super) fn check_run(&self, run: &VerifiedLabelRun) -> Result<()> {
        require(
            run.suite_sha256() == self.suite_sha256,
            "LABEL_SUITE_MISMATCH",
        )?;
        require(
            run.policy_sha256() == self.policy_sha256,
            "LABEL_POLICY_MISMATCH",
        )?;
        require(
            run.capture()
                .questions()
                .iter()
                .map(|q| (q.qid().to_string(), q.query_sha256().to_string()))
                .eq(self.query_bindings.iter().cloned()),
            "LABEL_CAPTURE_MISMATCH",
        )
    }
}

pub(crate) fn load_capture_base(
    suite: &Path,
    expected_suite_sha256: &str,
    available_labels: &[FilePin],
    output: &OutputOptions,
) -> Result<LegacyBaseValidated> {
    // These Values only select the explicit base pin. They do not establish
    // legacy admission or impose private Run permissions on the old package.
    let suite_file =
        super::input::read_pinned_json(&suite.join("SUITE-MANIFEST.json"), expected_suite_sha256)?;
    let inventory_sha = suite_file["source_inventory_sha256"]
        .as_str()
        .context("LABEL_PARENT_MISMATCH")?;
    let inventory =
        super::input::read_pinned_json(&suite.join("SOURCE-INVENTORY.json"), inventory_sha)?;
    let registry = inventory["files"]
        .as_array()
        .context("LABEL_PARENT_MISMATCH")?;
    let candidates: Vec<_> = registry
        .iter()
        .filter(|asset| {
            asset["roles"]
                .as_array()
                .is_some_and(|roles| roles.iter().any(|r| r == "labels"))
        })
        .collect();
    require(candidates.len() == 1, "LABEL_PARENT_MISMATCH")?;
    let expected_base_sha = candidates[0]["sha256"]
        .as_str()
        .context("LABEL_PARENT_MISMATCH")?;
    let matching: Vec<_> = available_labels
        .iter()
        .filter(|pin| pin.expected_sha256() == expected_base_sha)
        .collect();
    require(matching.len() == 1, "LABEL_PARENT_MISMATCH")?;
    load_legacy_base(&InputOptions {
        suite: suite.to_path_buf(),
        suite_sha256: expected_suite_sha256.into(),
        labels: matching[0].path().to_path_buf(),
        labels_sha256: matching[0].expected_sha256().into(),
        output: output.clone(),
    })
}

fn verified_base_sha256<'a>(base: &'a LegacyBaseValidated, pin: &FilePin) -> Result<&'a str> {
    // base was just reconstructed by the complete 03 registry/freeze guard.
    // A matching hash alone must not admit an unrelated external label copy.
    require(
        pin.path() == base.pin.path() && pin.expected_sha256() == base.inputs.labels_sha256,
        "LABEL_PARENT_MISMATCH",
    )?;
    Ok(&base.inputs.labels_sha256)
}

pub(crate) struct VerifiedLabelSet {
    active: FilePin,
    active_observed_sha256: String,
    ancestor_pins: Vec<FilePin>,
    base_input: InputOptions,
    suite_sha256: String,
    policy_sha256: String,
    version: Option<String>,
    labels: HashMap<LabelKey, HumanLabel>,
    capture_maps: HashMap<String, HashMap<LabelKey, HumanLabel>>,
    ancestor_sha256s: Vec<String>,
}

impl VerifiedLabelSet {
    pub(crate) fn observed_file_sha256(&self) -> &str {
        &self.active_observed_sha256
    }
    pub(crate) fn suite_sha256(&self) -> &str {
        &self.suite_sha256
    }
    pub(crate) fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub(crate) fn lookup(&self, key: &LabelKey) -> Option<HumanLabel> {
        self.labels.get(key).copied()
    }
    pub(crate) fn verified_ancestor_sha256s(&self) -> &[String] {
        &self.ancestor_sha256s
    }

    pub(super) fn check_capture(&self, run: &VerifiedLabelRun) -> Result<()> {
        require(
            run.suite_sha256() == self.suite_sha256(),
            "LABEL_SUITE_MISMATCH",
        )?;
        require(
            run.policy_sha256() == self.policy_sha256(),
            "LABEL_POLICY_MISMATCH",
        )?;
        let map = self
            .capture_maps
            .get(run.capture_labels_sha256())
            .context("LABEL_CAPTURE_MISMATCH")?;
        for (key, capture_label) in run.capture_slots() {
            require(resolve(map, key) == capture_label, "LABEL_CAPTURE_MISMATCH")?;
        }
        Ok(())
    }

    pub(super) fn refresh(
        &self,
        base: &LegacyBaseValidated,
        left: &VerifiedLabelRun,
        right: &VerifiedLabelRun,
    ) -> Result<Self> {
        let current_base = load_legacy_base(&base.input)?;
        require(
            current_base.pin.expected_sha256() == base.pin.expected_sha256(),
            "LABEL_PARENT_MISMATCH",
        )?;
        load_label_set(
            &self.active,
            &self.ancestor_pins,
            &current_base,
            left,
            right,
        )
    }

    pub(super) fn refresh_for_export(
        &self,
        left: &VerifiedLabelRun,
        right: &VerifiedLabelRun,
    ) -> Result<Self> {
        let base = load_legacy_base(&self.base_input)?;
        load_label_set(&self.active, &self.ancestor_pins, &base, left, right)
    }

    pub(super) fn reload_base(&self) -> Result<LegacyBaseValidated> {
        load_legacy_base(&self.base_input)
    }

    pub(super) fn protected_roots(&self) -> Vec<&Path> {
        let mut roots = vec![self.base_input.suite.as_path()];
        roots.extend(
            std::iter::once(&self.active)
                .chain(&self.ancestor_pins)
                .filter_map(|pin| pin.path().parent()),
        );
        roots
    }

    pub(super) fn new_version(
        &self,
        additions: &[(LabelKey, HumanLabel)],
        version: &str,
    ) -> Result<Value> {
        require(
            valid_version(version) && self.version.as_deref() != Some(version),
            "LABEL_VERSION_INVALID",
        )?;
        let mut map = self.labels.clone();
        for (key, label) in additions {
            require(
                key.label_policy_sha256 == self.policy_sha256,
                "LABEL_POLICY_MISMATCH",
            )?;
            require(!map.contains_key(key), "LABEL_KEY_CONFLICT")?;
            map.insert(key.clone(), *label);
        }
        check_extension(&self.labels, &map)?;
        let mut records: Vec<_> = map
            .into_iter()
            .map(|(key, value)| ModernRecord {
                key: KeyWire::from(&key),
                value,
            })
            .collect();
        records.sort_by(|a, b| key_order(&a.key).cmp(&key_order(&b.key)));
        Ok(serde_json::to_value(ModernLabels {
            schema: "cass.regression-labels.v1".into(),
            version: version.into(),
            parent_labels_sha256: Some(self.observed_file_sha256().into()),
            suite_sha256: self.suite_sha256.clone(),
            label_policy_sha256: self.policy_sha256.clone(),
            records,
        })?)
    }
}

pub(crate) struct LabelCoverage {
    left: Vec<SlotLabel>,
    right: Vec<SlotLabel>,
    unknown: Vec<LabelKey>,
}

impl LabelCoverage {
    pub(crate) fn left_slot_labels(&self) -> &[SlotLabel] {
        &self.left
    }
    pub(crate) fn right_slot_labels(&self) -> &[SlotLabel] {
        &self.right
    }
    pub(crate) fn unknown_keys(&self) -> &[LabelKey] {
        &self.unknown
    }
    pub(crate) fn state(&self) -> LabelCoverageState {
        if self.unknown.is_empty() {
            LabelCoverageState::Complete
        } else {
            LabelCoverageState::IncompleteLabels
        }
    }
}

pub(crate) fn load_legacy_base(base_input: &InputOptions) -> Result<LegacyBaseValidated> {
    let inputs = super::input::validate_inputs(base_input)?;
    let mut windows_assets = inputs
        .assets
        .iter()
        .filter(|a| a.roles.iter().any(|r| r == "windows"));
    let windows_asset = windows_assets.next().context("INPUT_ROLE_MISSING")?;
    require(windows_assets.next().is_none(), "INPUT_ROLE_AMBIGUOUS")?;
    require(
        windows_asset.sha256 == inputs.windows_file_sha256,
        "INPUT_ASSET_DIGEST_MISMATCH",
    )?;
    let windows_bytes = super::input::read_registered_asset(&inputs, &windows_asset.source_path)?;
    require(
        digest(&windows_bytes) == inputs.windows_file_sha256,
        "INPUT_ASSET_DIGEST_MISMATCH",
    )?;
    let mut labels = HashMap::new();
    for record in &inputs.labels {
        let value: HumanLabel = serde_json::from_value(Value::String(record.value.clone()))
            .context("LABEL_SCHEMA_INVALID")?;
        if let Some(previous) = labels.insert(record.key.clone(), value) {
            require(previous == value, "LABEL_KEY_CONFLICT")?;
        }
    }
    // Independent caller pin, already checked against the registered legacy
    // label and freeze by validate_inputs. This never accepts a modern root.
    require(
        inputs.labels_sha256 == base_input.labels_sha256,
        "LABEL_PARENT_MISMATCH",
    )?;
    Ok(LegacyBaseValidated {
        input: base_input.clone(),
        pin: FilePin::new(base_input.labels.clone(), inputs.labels_sha256.clone())?,
        suite_sha256: inputs.suite_sha256.clone(),
        policy_sha256: inputs.label_policy_sha256.clone(),
        labels,
        query_bindings: inputs
            .windows
            .iter()
            .map(|w| (w.qid.clone(), w.query_sha256.clone()))
            .collect(),
        inputs,
        windows_bytes,
    })
}

pub(crate) fn load_label_set(
    active: &FilePin,
    ancestors: &[FilePin],
    base: &LegacyBaseValidated,
    left: &VerifiedLabelRun,
    right: &VerifiedLabelRun,
) -> Result<VerifiedLabelSet> {
    // Re-run the 03 proof. A retained wrapper is not permission to trust changed
    // parent files, suite assets, or their declared fields.
    let base_now = load_legacy_base(&base.input)?;
    base_now.check_run(left)?;
    base_now.check_run(right)?;
    require(
        base_now.pin.expected_sha256() == base.pin.expected_sha256(),
        "LABEL_PARENT_MISMATCH",
    )?;
    let mut pins = HashMap::new();
    pins.insert(active.expected_sha256().to_string(), active);
    let mut paths = HashSet::new();
    paths.insert(active.path());
    for pin in ancestors {
        require(
            paths.insert(pin.path()) && pins.insert(pin.expected_sha256().into(), pin).is_none(),
            "LABEL_PARENT_MISMATCH",
        )?;
    }
    let mut cursor = active.expected_sha256().to_string();
    let mut seen = HashSet::new();
    let mut modern = Vec::new();
    let mut ancestor_sha256s = Vec::new();
    let mut active_observed_sha256 = None;
    loop {
        require(seen.insert(cursor.clone()), "LABEL_PARENT_MISMATCH")?;
        let pin = pins.get(&cursor).context("LABEL_PARENT_MISMATCH")?;
        if cursor == base_now.inputs.labels_sha256 {
            let observed = verified_base_sha256(&base_now, pin)?;
            if cursor == active.expected_sha256() {
                active_observed_sha256 = Some(observed.to_string());
            }
            break;
        }
        let wire = read_pin(pin)?;
        if cursor == active.expected_sha256() {
            active_observed_sha256 = Some(wire.observed_file_sha256().to_string());
        }
        let labels: ModernLabels =
            serde_json::from_value(wire.value().clone()).context("LABEL_SCHEMA_INVALID")?;
        labels.validate(&base_now.suite_sha256, &base_now.policy_sha256)?;
        let parent = labels
            .parent_labels_sha256
            .clone()
            .context("LABEL_PARENT_MISMATCH")?;
        require(pins.contains_key(&parent), "LABEL_PARENT_MISMATCH")?;
        modern.push((cursor, labels));
        ancestor_sha256s.push(parent.clone());
        cursor = parent;
    }
    require(seen.len() == pins.len(), "LABEL_PARENT_MISMATCH")?;
    let mut previous = base_now.labels.clone();
    let mut previous_version: Option<String> = None;
    let mut capture_maps = HashMap::new();
    capture_maps.insert(base_now.pin.expected_sha256().into(), previous.clone());
    for (digest, version) in modern.iter().rev() {
        require(
            previous_version.as_deref() != Some(version.version.as_str()),
            "LABEL_VERSION_INVALID",
        )?;
        let map = version.label_map()?;
        check_extension(&previous, &map)?;
        capture_maps.insert(digest.clone(), map.clone());
        previous = map;
        previous_version = Some(version.version.clone());
    }
    let set = VerifiedLabelSet {
        active: active.clone(),
        active_observed_sha256: active_observed_sha256.context("LABEL_PARENT_MISMATCH")?,
        ancestor_pins: ancestors.to_vec(),
        base_input: base.input.clone(),
        suite_sha256: base_now.suite_sha256,
        policy_sha256: base_now.policy_sha256,
        version: previous_version,
        labels: previous,
        capture_maps,
        ancestor_sha256s,
    };
    set.check_capture(left)?;
    set.check_capture(right)?;
    Ok(set)
}

pub(crate) fn cover_slots(
    left: &VerifiedLabelRun,
    right: &VerifiedLabelRun,
    labels: &VerifiedLabelSet,
) -> Result<LabelCoverage> {
    labels.check_capture(left)?;
    labels.check_capture(right)?;
    let left: Vec<_> = left.capture_slots().map(|(key, _)| key).collect();
    let right: Vec<_> = right.capture_slots().map(|(key, _)| key).collect();
    Ok(cover_keys(&left, &right, &labels.labels))
}

fn cover_keys(
    left: &[&LabelKey],
    right: &[&LabelKey],
    map: &HashMap<LabelKey, HumanLabel>,
) -> LabelCoverage {
    let mut unknown = HashSet::new();
    let mut side = |keys: &[&LabelKey]| {
        keys.iter()
            .map(|key| {
                let value = resolve(map, key);
                if value == SlotLabel::Unknown {
                    unknown.insert((*key).clone());
                }
                value
            })
            .collect()
    };
    let left = side(left);
    let right = side(right);
    let mut unknown: Vec<_> = unknown.into_iter().collect();
    unknown.sort_by(|a, b| label_key_order(a).cmp(&label_key_order(b)));
    LabelCoverage {
        left,
        right,
        unknown,
    }
}

fn resolve(map: &HashMap<LabelKey, HumanLabel>, key: &LabelKey) -> SlotLabel {
    map.get(key)
        .copied()
        .map_or(SlotLabel::Unknown, SlotLabel::Known)
}

fn check_extension(
    parent: &HashMap<LabelKey, HumanLabel>,
    child: &HashMap<LabelKey, HumanLabel>,
) -> Result<()> {
    require(
        parent
            .iter()
            .all(|(key, value)| child.get(key) == Some(value)),
        "LABEL_PARENT_CONTENT_CHANGED",
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeyWire {
    pub(super) query_sha256: String,
    pub(super) label_text_sha256: String,
    pub(super) label_policy_sha256: String,
}

impl From<&LabelKey> for KeyWire {
    fn from(key: &LabelKey) -> Self {
        Self {
            query_sha256: key.query_sha256.clone(),
            label_text_sha256: key.label_text_sha256.clone(),
            label_policy_sha256: key.label_policy_sha256.clone(),
        }
    }
}

impl KeyWire {
    pub(super) fn checked(&self) -> Result<LabelKey> {
        require(
            [
                &self.query_sha256,
                &self.label_text_sha256,
                &self.label_policy_sha256,
            ]
            .iter()
            .all(|s| is_hex(s, 64)),
            "LABEL_SCHEMA_INVALID",
        )?;
        Ok(LabelKey {
            query_sha256: self.query_sha256.clone(),
            label_text_sha256: self.label_text_sha256.clone(),
            label_policy_sha256: self.label_policy_sha256.clone(),
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ModernRecord {
    key: KeyWire,
    value: HumanLabel,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ModernLabels {
    schema: String,
    version: String,
    #[serde(deserialize_with = "present_nullable")]
    parent_labels_sha256: Option<String>,
    suite_sha256: String,
    label_policy_sha256: String,
    records: Vec<ModernRecord>,
}

impl ModernLabels {
    fn validate(&self, suite: &str, policy: &str) -> Result<()> {
        require(
            self.schema == "cass.regression-labels.v1",
            "LABEL_SCHEMA_INVALID",
        )?;
        require(valid_version(&self.version), "LABEL_VERSION_INVALID")?;
        require(self.suite_sha256 == suite, "LABEL_SUITE_MISMATCH")?;
        require(self.label_policy_sha256 == policy, "LABEL_POLICY_MISMATCH")?;
        require(
            self.parent_labels_sha256
                .as_deref()
                .is_some_and(|p| is_hex(p, 64)),
            "LABEL_PARENT_MISMATCH",
        )?;
        self.label_map()?;
        Ok(())
    }

    fn label_map(&self) -> Result<HashMap<LabelKey, HumanLabel>> {
        let mut map = HashMap::new();
        for row in &self.records {
            let key = row.key.checked()?;
            require(
                key.label_policy_sha256 == self.label_policy_sha256,
                "LABEL_POLICY_MISMATCH",
            )?;
            require(map.insert(key, row.value).is_none(), "LABEL_KEY_CONFLICT")?;
        }
        Ok(map)
    }
}

pub(super) fn present_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

pub(super) fn read_pin(pin: &FilePin) -> Result<WirePinned> {
    super::input::read_private_pinned_json(
        pin.path(),
        pin.expected_sha256(),
        "LABEL_FILE_IDENTITY_MISMATCH",
    )
}

pub(super) fn read_subject(path: &Path) -> Result<WirePinned> {
    super::input::read_private_json(path)
}

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(super) fn is_hex(text: &str, size: usize) -> bool {
    text.len() == size
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn require(condition: bool, code: &'static str) -> Result<()> {
    if !condition {
        bail!(code);
    }
    Ok(())
}
fn valid_version(version: &str) -> bool {
    version.chars().any(|c| !c.is_whitespace())
}
fn key_order(key: &KeyWire) -> (&str, &str, &str) {
    (
        &key.query_sha256,
        &key.label_text_sha256,
        &key.label_policy_sha256,
    )
}
pub(super) fn label_key_order(key: &LabelKey) -> (&str, &str, &str) {
    (
        &key.query_sha256,
        &key.label_text_sha256,
        &key.label_policy_sha256,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn key(text: &[u8]) -> LabelKey {
        LabelKey {
            query_sha256: digest(b"synthetic-query"),
            label_text_sha256: digest(text),
            label_policy_sha256: digest(b"synthetic-policy"),
        }
    }

    // Owned synthetic 9x200 legacy input. No env, DB or shared files.
    #[cfg(unix)]
    fn legacy_public_modes_fixture() -> (tempfile::TempDir, InputOptions) {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let suite = root.path().join("synthetic-legacy");
        let assets = suite.join("assets");
        fs::create_dir_all(&assets).unwrap();
        for p in [&suite, &assets] {
            fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let output = root.path().join("output");
        fs::create_dir(&output).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        let mut registry = Vec::new();
        let mut add = |relative: &str, bytes: Vec<u8>, role: &str| {
            let path = suite.join(relative);
            fs::write(&path, &bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            let source = format!("/synthetic-legacy/{relative}");
            let sha = digest(&bytes);
            registry.push(json!({"source_path":source,"path":relative,"sha256":sha,"bytes":bytes.len(),"roles":[role]}));
            json!({"path":source,"sha256":sha})
        };
        let text = b"Synthetic legacy candidate.";
        let text_ref = add("assets/candidate.txt", text.to_vec(), "candidate_text");
        let policy = digest(b"synthetic-legacy-policy");
        let qids = [
            "N01", "N02", "N03", "N04", "N05", "N06", "N07", "N08", "N12",
        ];
        let mut windows = Vec::new();
        let mut spans = Vec::new();
        let mut rows = Vec::new();
        for qid in qids {
            let query = format!("Synthetic legacy query {qid}");
            let query_sha = digest(query.as_bytes());
            let mut items = Vec::new();
            let mut proofs = Vec::new();
            for rank in 1..=200 {
                items.push(json!({"rank":rank,"message_id":rank,"conversation_id":null,"text_path":text_ref["path"],"text_sha256":text_ref["sha256"],"bytes":text.len(),"source_sha256":digest(b"synthetic-source"),"original_score":1.25,"scoreable":true,"fallback_reason":null}));
                proofs.push(json!({"rank":rank,"message_id":rank}));
                rows.push(json!({"qid":qid,"rank":rank,"message_id":rank,"query_sha256":query_sha,"text_sha256":text_ref["sha256"],"label":"direct","reason":"synthetic legacy fixture","provenance":{"kind":"synthetic"}}));
            }
            windows.push(json!({"qid":qid,"query":query,"query_sha256":query_sha,"items":items}));
            spans.push(json!({"qid":qid,"items":proofs}));
        }
        let lines = |values: &[Value]| {
            values
                .iter()
                .flat_map(|v| {
                    let mut b = serde_json::to_vec(v).unwrap();
                    b.push(b'\n');
                    b
                })
                .collect::<Vec<_>>()
        };
        let windows_ref = add("assets/windows.jsonl", lines(&windows), "windows");
        let spans_ref = add("assets/spans.jsonl", lines(&spans), "span_proofs");
        let manifest = json!({"schema":"cass.pr3.default-input.v1","query_order":qids,"pool_limit":200,"files":{"windows":windows_ref,"span_proofs":spans_ref}});
        let input_ref = add(
            "assets/INPUT-MANIFEST.json",
            serde_json::to_vec(&manifest).unwrap(),
            "input_manifest",
        );
        let labels = json!({"schema":"cass.pr3.default-labels.v1","input_manifest_sha256":input_ref["sha256"],"label_policy_sha256":policy,"rows":rows});
        let label_bytes = serde_json::to_vec(&labels).unwrap();
        let labels_ref = add("assets/LABELS.json", label_bytes.clone(), "labels");
        let freeze = json!({"schema":"cass.pr3.default-labels-freeze-manifest.v1","labels_frozen":true,"labels_sha256":labels_ref["sha256"],"labels_bytes":label_bytes.len(),"labels_rows":1800,"input_manifest_sha256":input_ref["sha256"],"label_policy_sha256":policy,"not_user_confirmed":true,"not_an_independent_test_set":true});
        add(
            "assets/FREEZE.json",
            serde_json::to_vec(&freeze).unwrap(),
            "labels_freeze",
        );
        drop(add);
        let counts = json!({"direct":1800,"partial":0,"none":0,"unsure":0});
        let inventory = json!({"schema":"cass.regression.source-inventory.v1","suite_id":"synthetic-legacy","mode":"synthetic","query_order":qids,"candidate_slots":1800,"labels":counts,"runtime_prefix_map":{},"files":registry,"limits":{}});
        let inventory_bytes = serde_json::to_vec(&inventory).unwrap();
        let suite_value = json!({"schema":"cass.regression.suite-manifest.v1","suite_id":"synthetic-legacy","stage":"assets_only","mode":"synthetic","source_inventory_sha256":digest(&inventory_bytes),"query_order":qids,"candidate_slots":1800,"label_counts":counts,"runtime_prefix_map":{},"files":registry,"limits":{}});
        let suite_bytes = serde_json::to_vec(&suite_value).unwrap();
        for (name, bytes) in [
            ("SOURCE-INVENTORY.json", inventory_bytes),
            ("SUITE-MANIFEST.json", suite_bytes.clone()),
        ] {
            let path = suite.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let input = InputOptions {
            suite: suite.clone(),
            suite_sha256: digest(&suite_bytes),
            labels: suite.join("assets/LABELS.json"),
            labels_sha256: labels_ref["sha256"].as_str().unwrap().into(),
            output: OutputOptions {
                output_root: output,
                run_id: "synthetic-label-run".into(),
            },
        };
        (root, input)
    }

    #[test]
    #[cfg(unix)]
    fn legacy_0755_0644_capture_selection_and_base_pin_keep_real03_admission() {
        use std::fs;
        let (root, input) = legacy_public_modes_fixture();
        let pin = FilePin::new(input.labels.clone(), input.labels_sha256.clone()).unwrap();
        let base = load_capture_base(
            &input.suite,
            &input.suite_sha256,
            std::slice::from_ref(&pin),
            &input.output,
        )
        .unwrap();
        assert_eq!(
            base.inputs
                .windows
                .iter()
                .map(|w| w.items.len())
                .sum::<usize>(),
            1800
        );
        assert_eq!(
            verified_base_sha256(&base, &pin).unwrap(),
            digest(&fs::read(&input.labels).unwrap())
        );
        assert!(read_pin(&pin).is_err()); // Modern/private admission stays strict.
        let copy = root.path().join("external-copy.json");
        fs::copy(&input.labels, &copy).unwrap();
        assert!(
            verified_base_sha256(
                &base,
                &FilePin::new(copy, input.labels_sha256.clone()).unwrap()
            )
            .is_err()
        );
        assert!(
            load_capture_base(
                &input.suite,
                &digest(b"wrong-suite"),
                std::slice::from_ref(&pin),
                &input.output
            )
            .is_err()
        );
        fs::hard_link(&input.labels, root.path().join("label-link.json")).unwrap();
        assert!(
            load_capture_base(&input.suite, &input.suite_sha256, &[pin], &input.output).is_err()
        );
    }

    #[test]
    #[cfg(unix)]
    fn legacy_capture_does_not_admit_registered_label_symlinks() {
        use std::fs;
        use std::os::unix::fs::symlink;
        let (_root, input) = legacy_public_modes_fixture();
        let saved = input.labels.with_extension("saved");
        fs::rename(&input.labels, &saved).unwrap();
        symlink(&saved, &input.labels).unwrap();
        let pin = FilePin::new(input.labels.clone(), input.labels_sha256.clone()).unwrap();
        assert!(
            load_capture_base(&input.suite, &input.suite_sha256, &[pin], &input.output).is_err()
        );
    }

    #[test]
    fn extension_keeps_unused_unsure_and_rejects_drop_or_relabel() {
        let k = key(b"synthetic-unused");
        let parent = HashMap::from([(k.clone(), HumanLabel::Unsure)]);
        let mut child = parent.clone();
        child.insert(key(b"synthetic-new"), HumanLabel::Direct);
        assert!(check_extension(&parent, &child).is_ok());
        child.insert(k.clone(), HumanLabel::None);
        assert!(check_extension(&parent, &child).is_err());
        child.remove(&k);
        assert!(check_extension(&parent, &child).is_err());
    }

    #[test]
    fn modern_rows_reject_even_identical_duplicate_keys() {
        let k = key(b"synthetic-text");
        let mut value = serde_json::json!({"schema":"cass.regression-labels.v1","version":"v2","parent_labels_sha256":digest(b"parent"),"suite_sha256":digest(b"suite"),"label_policy_sha256":k.label_policy_sha256,"records":[{"key":k,"value":"unsure"}]});
        let row = value["records"][0].clone();
        value["records"].as_array_mut().unwrap().push(row);
        let labels: ModernLabels = serde_json::from_value(value).unwrap();
        assert!(labels.label_map().is_err());
    }

    #[test]
    fn nullable_parent_must_be_present_and_unknown_is_not_negative() {
        let value = serde_json::json!({"schema":"cass.regression-labels.v1","version":"v1","suite_sha256":digest(b"suite"),"label_policy_sha256":digest(b"policy"),"records":[]});
        assert!(serde_json::from_value::<ModernLabels>(value).is_err());
        let k = key(b"synthetic-text");
        assert_eq!(resolve(&HashMap::new(), &k), SlotLabel::Unknown);
        assert_eq!(
            resolve(&HashMap::from([(k.clone(), HumanLabel::None)]), &k),
            SlotLabel::Known(HumanLabel::None)
        );
    }

    #[test]
    fn two_sides_share_one_annotation_key_without_dropping_slots() {
        let a = key(b"synthetic-left");
        let shared = key(b"synthetic-shared");
        let b = key(b"synthetic-right");
        let coverage = cover_keys(&[&a, &shared], &[&shared, &b], &HashMap::new());
        assert_eq!(
            coverage.left_slot_labels().len() + coverage.right_slot_labels().len(),
            4
        );
        assert_eq!(coverage.unknown_keys().len(), 3);
        assert_eq!(coverage.state(), LabelCoverageState::IncompleteLabels);
        let swapped = cover_keys(&[&b, &shared], &[&shared, &a], &HashMap::new());
        assert_eq!(coverage.unknown_keys(), swapped.unknown_keys());
        let labels = HashMap::from([
            (a.clone(), HumanLabel::Partial),
            (shared.clone(), HumanLabel::Unsure),
            (b.clone(), HumanLabel::None),
        ]);
        let complete = cover_keys(&[&a, &shared], &[&shared, &b], &labels);
        assert_eq!(complete.state(), LabelCoverageState::Complete);
        assert_eq!(
            complete.left_slot_labels(),
            &[
                SlotLabel::Known(HumanLabel::Partial),
                SlotLabel::Known(HumanLabel::Unsure)
            ]
        );
        assert_eq!(
            complete.right_slot_labels(),
            &[
                SlotLabel::Known(HumanLabel::Unsure),
                SlotLabel::Known(HumanLabel::None)
            ]
        );
    }
}
