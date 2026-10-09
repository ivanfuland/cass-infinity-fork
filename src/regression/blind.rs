//! Private, source-free annotation presentation over immutable execution runs.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::labels::{
    self, FilePin, HumanLabel, KeyWire, LegacyBaseValidated, SlotLabel, VerifiedLabelSet, digest,
    is_hex, present_nullable, require,
};
use super::types::{LabelKey, RunPaths};
use crate::search::regression_binding::InputBinding;
use crate::search::regression_trace::{self, CandidateIdentity, PageEvidence, WindowEvidence};

const QIDS: [&str; 9] = [
    "N01", "N02", "N03", "N04", "N05", "N06", "N07", "N08", "N12",
];

pub(crate) struct VerifiedLabelRun {
    pin: FilePin,
    run: RunWire,
    root: PathBuf,
    subjects: Vec<SubjectFile>,
}

struct SubjectFile {
    reference: ArtifactWire,
    body: SubjectBody,
}

impl VerifiedLabelRun {
    pub(super) fn suite_sha256(&self) -> &str {
        &self.run.suite_sha256
    }
    pub(super) fn policy_sha256(&self) -> &str {
        &self.run.label_policy_sha256
    }
    pub(super) fn capture_labels_sha256(&self) -> &str {
        &self.run.labels_sha256
    }
    pub(super) fn capture_slots(&self) -> impl Iterator<Item = (&LabelKey, SlotLabel)> {
        self.run
            .questions
            .iter()
            .flat_map(|q| q.slots.iter().map(|s| (&s.key, s.label.resolved())))
    }

    fn unknown_text(&self, key: &LabelKey) -> Result<(String, String)> {
        let mut found: Option<(String, String)> = None;
        for subject in &self.subjects {
            for item in &subject.body.candidates {
                if item.label_key.checked()? == *key {
                    let text = (subject.body.query.utf8.clone(), item.text.utf8.clone());
                    require(
                        found.as_ref().is_none_or(|prior| prior == &text),
                        "LABEL_SUBJECT_INVALID",
                    )?;
                    found = Some(text);
                }
            }
        }
        found.context("LABEL_SUBJECT_INVALID")
    }
}

pub(crate) struct BlindArtifacts {
    bundle: FilePin,
    manifest: FilePin,
}
impl BlindArtifacts {
    pub(crate) fn bundle(&self) -> &FilePin {
        &self.bundle
    }
    pub(crate) fn manifest(&self) -> &FilePin {
        &self.manifest
    }
}

pub(crate) struct LabelsArtifact {
    labels: FilePin,
    receipt: FilePin,
}
impl LabelsArtifact {
    pub(crate) fn labels(&self) -> &FilePin {
        &self.labels
    }
    pub(crate) fn receipt(&self) -> &FilePin {
        &self.receipt
    }
}

pub(crate) fn load_run_subjects(pin: &FilePin) -> Result<VerifiedLabelRun> {
    let wire = labels::read_pin(pin)?;
    let mut run: RunWire = serde_json::from_value(wire.value).context("LABEL_RUN_INVALID")?;
    run.validate()?;
    // Typed-ID recovery from the original pinned pool is a separate fixed
    // consumer seam. No fabricated full CandidateIdentity is accepted here.
    require(run.mode == RunMode::FullSearch, "LABEL_RUN_INVALID")?;
    let root = pin
        .path()
        .parent()
        .context("LABEL_RUN_INVALID")?
        .to_path_buf();
    crate::search::regression_io::validate_private_run_root(&root)?;
    require(
        root == Path::new(&run.output.private_root).join(&run.output.run_relative_path),
        "LABEL_RUN_INVALID",
    )?;
    require(
        root.file_name().and_then(|s| s.to_str()) == Some(run.run_id.as_str()),
        "LABEL_RUN_INVALID",
    )?;
    require(
        pin.path().file_name().and_then(|s| s.to_str()) == Some("run.json"),
        "LABEL_RUN_INVALID",
    )?;
    validate_listing(&root, &run.output.writes_relative_paths)?;
    let mut subjects = Vec::new();
    for question in &mut run.questions {
        let relative = format!("label-subjects-{}.json", question.qid);
        listed(&run.output, &relative)?;
        let wire = labels::read_subject(&root.join(&relative))?;
        let body: SubjectBody =
            serde_json::from_value(wire.value).context("LABEL_SUBJECT_INVALID")?;
        validate_subject(
            &body,
            question,
            &run.label_policy_sha256,
            run.request.rerank,
        )?;
        validate_question_evidence(
            &root,
            &run.output,
            question,
            &body,
            &run.request,
            run.observed_before.as_ref().context("LABEL_RUN_INVALID")?,
        )?;
        subjects.push(SubjectFile {
            reference: ArtifactWire {
                relative_path: relative,
                sha256: wire.sha256,
            },
            body,
        });
    }
    let rows: Vec<_> = run
        .questions
        .iter()
        .map(|q| (&q.qid, &q.query_sha256))
        .collect();
    let mut query_manifest = b"cass.regression-query-manifest.v1\0".to_vec();
    query_manifest.extend(serde_json::to_vec(&rows)?);
    require(
        digest(&query_manifest) == run.query_manifest_sha256,
        "LABEL_RUN_INVALID",
    )?;
    let argv = read_reference(
        &root,
        &run.output,
        &ArtifactWire {
            relative_path: "argv.json".into(),
            sha256: run.argv_sha256.clone(),
        },
    )?;
    require(
        argv.is_array()
            && argv
                .as_array()
                .is_some_and(|a| a.iter().all(Value::is_string)),
        "LABEL_RUN_INVALID",
    )?;
    if let Some(sha) = &run.request.request_evidence_sha256 {
        let request = read_reference(
            &root,
            &run.output,
            &ArtifactWire {
                relative_path: "request.json".into(),
                sha256: sha.clone(),
            },
        )?;
        require(request.is_object(), "LABEL_RUN_INVALID")?;
    }
    Ok(VerifiedLabelRun {
        pin: pin.clone(),
        run,
        root,
        subjects,
    })
}

pub(crate) fn export_blind(
    left: &VerifiedLabelRun,
    right: &VerifiedLabelRun,
    parent: &VerifiedLabelSet,
    output: &RunPaths,
) -> Result<BlindArtifacts> {
    // Re-read immutable source pins even when callers retained a prior proof.
    let left = load_run_subjects(&left.pin)?;
    let right = load_run_subjects(&right.pin)?;
    let parent = parent.refresh_for_export(&left, &right)?;
    let coverage = labels::cover_slots(&left, &right, &parent)?;
    let mut protected = parent.protected_roots();
    protected.extend([left.root.as_path(), right.root.as_path()]);
    output_boundary(output, &protected)?;
    let mut used = HashSet::new();
    let bundle_id = random_id(&mut used)?;
    let mut bindings = Vec::new();
    let mut items = Vec::new();
    for key in coverage.unknown_keys() {
        let text = match (left.unknown_text(key), right.unknown_text(key)) {
            (Ok(l), Ok(r)) => {
                require(l == r, "LABEL_SUBJECT_INVALID")?;
                l
            }
            (Ok(l), Err(_)) => l,
            (Err(_), Ok(r)) => r,
            (Err(_), Err(_)) => bail!("LABEL_SUBJECT_INVALID"),
        };
        let opaque_id = random_id(&mut used)?;
        items.push(BlindItem {
            opaque_id: opaque_id.clone(),
            query_utf8: text.0,
            text_utf8: text.1,
        });
        bindings.push(BlindBinding {
            opaque_id,
            key: KeyWire::from(key),
        });
    }
    items.sort_by(|a, b| a.opaque_id.cmp(&b.opaque_id));
    bindings.sort_by(|a, b| a.opaque_id.cmp(&b.opaque_id));
    let bundle = BlindBundle {
        schema: "cass.regression-blind-bundle.v1".into(),
        bundle_id: bundle_id.clone(),
        label_policy_sha256: parent.policy_sha256().into(),
        items,
    };
    let bundle_pin = write_artifact(output, "blind-bundle.json", &serde_json::to_value(&bundle)?)?;
    let manifest = BlindManifest {
        schema: "cass.regression-blind-manifest.v1".into(),
        bundle_id,
        suite_sha256: parent.suite_sha256().into(),
        capture_suite_sha256: parent.suite_sha256().into(),
        label_policy_sha256: parent.policy_sha256().into(),
        parent_labels_file_sha256: parent.observed_file_sha256().into(),
        left_run_sha256: left.pin.expected_sha256().into(),
        right_run_sha256: right.pin.expected_sha256().into(),
        bundle: ArtifactWire {
            relative_path: "blind-bundle.json".into(),
            sha256: bundle_pin.expected_sha256().into(),
        },
        subject_refs: subject_refs(&left, &right),
        bindings,
    };
    let manifest_pin = write_artifact(
        output,
        "blind-manifest.json",
        &serde_json::to_value(manifest)?,
    )?;
    Ok(BlindArtifacts {
        bundle: bundle_pin,
        manifest: manifest_pin,
    })
}

pub(crate) fn import_blind(
    left: &VerifiedLabelRun,
    right: &VerifiedLabelRun,
    parent: &VerifiedLabelSet,
    base: &LegacyBaseValidated,
    manifest: &FilePin,
    answers: &FilePin,
    new_version: &str,
    output: &RunPaths,
) -> Result<LabelsArtifact> {
    let left = load_run_subjects(&left.pin)?;
    let right = load_run_subjects(&right.pin)?;
    let current_parent = parent.refresh(base, &left, &right)?;
    let manifest_wire = labels::read_pin(manifest)?;
    let manifest_body: BlindManifest =
        serde_json::from_value(manifest_wire.value).context("BLIND_MANIFEST_INVALID")?;
    require(
        manifest_body.schema == "cass.regression-blind-manifest.v1",
        "BLIND_MANIFEST_INVALID",
    )?;
    require(
        manifest_body.suite_sha256 == current_parent.suite_sha256()
            && manifest_body.capture_suite_sha256 == current_parent.suite_sha256(),
        "LABEL_SUITE_MISMATCH",
    )?;
    require(
        manifest_body.label_policy_sha256 == current_parent.policy_sha256(),
        "LABEL_POLICY_MISMATCH",
    )?;
    require(
        manifest_body.parent_labels_file_sha256 == current_parent.observed_file_sha256()
            && manifest_body.left_run_sha256 == left.pin.expected_sha256()
            && manifest_body.right_run_sha256 == right.pin.expected_sha256(),
        "BLIND_BINDING_MISMATCH",
    )?;
    require(
        manifest_body.subject_refs == subject_refs(&left, &right),
        "BLIND_BINDING_MISMATCH",
    )?;
    safe_relative(&manifest_body.bundle.relative_path)?;
    let bundle_pin = FilePin::new(
        manifest
            .path()
            .parent()
            .context("BLIND_MANIFEST_INVALID")?
            .join(&manifest_body.bundle.relative_path),
        manifest_body.bundle.sha256.clone(),
    )?;
    let bundle_wire = labels::read_pin(&bundle_pin)?;
    let bundle: BlindBundle =
        serde_json::from_value(bundle_wire.value).context("BLIND_BUNDLE_INVALID")?;
    let answers_wire = labels::read_pin(answers)?;
    let answers_body: BlindAnswers =
        serde_json::from_value(answers_wire.value).context("BLIND_ANSWERS_INVALID")?;
    let coverage = labels::cover_slots(&left, &right, &current_parent)?;
    let additions = validate_submission(
        &bundle,
        &manifest_body,
        &answers_body,
        coverage.unknown_keys(),
        &left,
        &right,
    )?;
    let mut protected = current_parent.protected_roots();
    protected.extend([
        left.root.as_path(),
        right.root.as_path(),
        manifest.path().parent().context("BLIND_MANIFEST_INVALID")?,
        answers.path().parent().context("BLIND_ANSWERS_INVALID")?,
    ]);
    output_boundary(output, &protected)?;
    let new_labels = current_parent.new_version(&additions, new_version)?;
    let label_pin = write_artifact(output, "labels-new.json", &new_labels)?;
    // Readback occurs before the complete receipt; partial output is not success.
    let readback = labels::read_pin(&label_pin)?;
    require(
        readback.value == new_labels
            && label_pin.expected_sha256() != current_parent.observed_file_sha256(),
        "BLIND_OUTPUT_WRITE_FAILED",
    )?;
    let receipt = ImportReceipt {
        schema: "cass.regression-label-import-receipt.v1".into(),
        status: "LABEL_COVERAGE_COMPLETE".into(),
        parent_labels_file_sha256: current_parent.observed_file_sha256().into(),
        new_labels_file_sha256: label_pin.expected_sha256().into(),
        manifest_sha256: manifest_wire.sha256,
        answers_sha256: answers_wire.sha256,
        bundle_sha256: bundle_wire.sha256,
        left_run_sha256: left.pin.expected_sha256().into(),
        right_run_sha256: right.pin.expected_sha256().into(),
        verified_ancestor_sha256s: current_parent.verified_ancestor_sha256s().to_vec(),
        version: new_version.into(),
        suite_sha256: current_parent.suite_sha256().into(),
        label_policy_sha256: current_parent.policy_sha256().into(),
    };
    // Verify the complete receipt before publishing its final filename. A
    // failed readback cannot leave the final success receipt behind. hard_link
    // creates the final name exclusively; it cannot overwrite another file.
    let pending = write_artifact(
        output,
        "import-receipt.pending.json",
        &serde_json::to_value(receipt)?,
    )?;
    let final_path = output.run_root.join("import-receipt.json");
    fs::hard_link(pending.path(), &final_path).context("BLIND_OUTPUT_WRITE_FAILED")?;
    let receipt_pin = FilePin::new(final_path, pending.expected_sha256().into())?;
    Ok(LabelsArtifact {
        labels: label_pin,
        receipt: receipt_pin,
    })
}

fn validate_submission(
    bundle: &BlindBundle,
    manifest: &BlindManifest,
    answers: &BlindAnswers,
    unknown: &[LabelKey],
    left: &VerifiedLabelRun,
    right: &VerifiedLabelRun,
) -> Result<Vec<(LabelKey, HumanLabel)>> {
    require(
        bundle.schema == "cass.regression-blind-bundle.v1" && valid_id(&bundle.bundle_id),
        "BLIND_BUNDLE_INVALID",
    )?;
    require(
        answers.schema == "cass.regression-blind-answers.v1"
            && answers.bundle_id == bundle.bundle_id
            && manifest.bundle_id == bundle.bundle_id,
        "BLIND_ANSWERS_INVALID",
    )?;
    require(
        bundle.label_policy_sha256 == manifest.label_policy_sha256,
        "LABEL_POLICY_MISMATCH",
    )?;
    let mut bindings = HashMap::new();
    let mut keys = HashSet::new();
    for binding in &manifest.bindings {
        let key = binding.key.checked()?;
        require(
            valid_id(&binding.opaque_id)
                && binding.opaque_id != bundle.bundle_id
                && bindings
                    .insert(binding.opaque_id.as_str(), key.clone())
                    .is_none()
                && keys.insert(key),
            "BLIND_MANIFEST_INVALID",
        )?;
    }
    require(
        keys == unknown.iter().cloned().collect(),
        "BLIND_BINDING_MISMATCH",
    )?;
    let mut seen_items = HashSet::new();
    let mut previous: Option<&str> = None;
    for item in &bundle.items {
        require(
            valid_id(&item.opaque_id)
                && seen_items.insert(item.opaque_id.as_str())
                && previous.is_none_or(|s| s < item.opaque_id.as_str()),
            "BLIND_BUNDLE_INVALID",
        )?;
        previous = Some(&item.opaque_id);
        let key = bindings
            .get(item.opaque_id.as_str())
            .context("BLIND_BINDING_MISMATCH")?;
        require(
            key.query_sha256 == digest(item.query_utf8.as_bytes())
                && key.label_text_sha256 == digest(item.text_utf8.as_bytes())
                && key.label_policy_sha256 == bundle.label_policy_sha256,
            "BLIND_BINDING_MISMATCH",
        )?;
        let expected = left
            .unknown_text(key)
            .or_else(|_| right.unknown_text(key))?;
        require(
            expected == (item.query_utf8.clone(), item.text_utf8.clone()),
            "BLIND_BINDING_MISMATCH",
        )?;
    }
    require(seen_items.len() == bindings.len(), "BLIND_BINDING_MISMATCH")?;
    let mut seen_answers = HashSet::new();
    let mut output = Vec::new();
    for answer in &answers.records {
        require(
            seen_answers.insert(answer.opaque_id.as_str()),
            "BLIND_ANSWERS_INVALID",
        )?;
        let key = bindings
            .get(answer.opaque_id.as_str())
            .context("BLIND_ANSWERS_INVALID")?;
        output.push((key.clone(), answer.value));
    }
    require(seen_answers == seen_items, "BLIND_ANSWERS_INVALID")?;
    Ok(output)
}

fn random_id(used: &mut HashSet<String>) -> Result<String> {
    loop {
        let mut bytes = [0u8; 16];
        rand::rngs::SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| anyhow::anyhow!("BLIND_RANDOM_UNAVAILABLE"))?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let id = hex::encode(bytes);
        if used.insert(id.clone()) {
            return Ok(id);
        }
    }
}

fn valid_id(id: &str) -> bool {
    is_hex(id, 32) && id.as_bytes()[12] == b'4' && b"89ab".contains(&id.as_bytes()[16])
}

fn safe_relative(relative: &str) -> Result<()> {
    // Uses the established 03 segment policy; Phase B opens this narrow seam.
    super::input::safe_relative(relative)
}

fn listed(output: &OutputWire, relative: &str) -> Result<()> {
    safe_relative(relative)?;
    require(
        output.writes_relative_paths.iter().any(|s| s == relative),
        "LABEL_RUN_INVALID",
    )
}

fn validate_listing(root: &Path, declared: &[String]) -> Result<()> {
    let mut expected = HashSet::new();
    for relative in declared {
        safe_relative(relative)?;
        require(expected.insert(relative.clone()), "LABEL_RUN_INVALID")?;
    }
    fn walk(root: &Path, current: &Path, files: &mut HashSet<String>) -> Result<()> {
        crate::search::regression_io::validate_private_run_root(current)?;
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            require(!kind.is_symlink(), "INPUT_PATH_SYMLINK")?;
            if kind.is_dir() {
                walk(root, &entry.path(), files)?;
            } else {
                require(kind.is_file(), "INPUT_FILE_NOT_REGULAR")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let m = entry.metadata()?;
                    require(
                        m.mode() & 0o777 == 0o600 && m.uid() == fs::metadata("/proc/self")?.uid(),
                        "LABEL_RUN_INVALID",
                    )?;
                }
                files.insert(
                    entry
                        .path()
                        .strip_prefix(root)?
                        .to_str()
                        .context("LABEL_RUN_INVALID")?
                        .into(),
                );
            }
        }
        Ok(())
    }
    let mut actual = HashSet::new();
    walk(root, root, &mut actual)?;
    require(actual == expected, "LABEL_RUN_INVALID")
}

fn read_reference(root: &Path, output: &OutputWire, reference: &ArtifactWire) -> Result<Value> {
    listed(output, &reference.relative_path)?;
    Ok(labels::read_pin(&FilePin::new(
        root.join(&reference.relative_path),
        reference.sha256.clone(),
    )?)?
    .value)
}

fn output_boundary(output: &RunPaths, inputs: &[&Path]) -> Result<()> {
    crate::search::regression_io::validate_private_run_root(&output.run_root)?;
    let destination = output.run_root.canonicalize()?;
    for input in inputs {
        let protected = input.canonicalize()?;
        require(
            !destination.starts_with(&protected) && !protected.starts_with(&destination),
            "OUTPUT_INSIDE_INPUT",
        )?;
    }
    require(
        fs::read_dir(&destination)?.next().is_none(),
        "RUN_ALREADY_EXISTS",
    )
}

fn write_artifact(output: &RunPaths, relative: &str, value: &Value) -> Result<FilePin> {
    safe_relative(relative)?;
    let reference = super::off::write_private(&output.run_root, relative, value)?;
    let pin = FilePin::new(
        output.run_root.join(relative),
        reference["sha256"]
            .as_str()
            .context("BLIND_OUTPUT_WRITE_FAILED")?
            .into(),
    )?;
    require(
        labels::read_pin(&pin)?.value == *value,
        "BLIND_OUTPUT_WRITE_FAILED",
    )?;
    Ok(pin)
}

fn subject_refs(left: &VerifiedLabelRun, right: &VerifiedLabelRun) -> Vec<SubjectRef> {
    [(Side::Left, left), (Side::Right, right)]
        .into_iter()
        .flat_map(|(side, run)| {
            run.subjects.iter().map(move |subject| SubjectRef {
                side,
                qid: subject.body.qid.clone(),
                relative_path: subject.reference.relative_path.clone(),
                sha256: subject.reference.sha256.clone(),
            })
        })
        .collect()
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlindBundle {
    schema: String,
    bundle_id: String,
    label_policy_sha256: String,
    items: Vec<BlindItem>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlindItem {
    opaque_id: String,
    query_utf8: String,
    text_utf8: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlindAnswers {
    schema: String,
    bundle_id: String,
    records: Vec<BlindAnswer>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlindAnswer {
    opaque_id: String,
    value: HumanLabel,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlindBinding {
    opaque_id: String,
    key: KeyWire,
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Side {
    Left,
    Right,
}
#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SubjectRef {
    side: Side,
    qid: String,
    relative_path: String,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlindManifest {
    schema: String,
    bundle_id: String,
    suite_sha256: String,
    capture_suite_sha256: String,
    label_policy_sha256: String,
    parent_labels_file_sha256: String,
    left_run_sha256: String,
    right_run_sha256: String,
    bundle: ArtifactWire,
    subject_refs: Vec<SubjectRef>,
    bindings: Vec<BlindBinding>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImportReceipt {
    schema: String,
    status: String,
    parent_labels_file_sha256: String,
    new_labels_file_sha256: String,
    manifest_sha256: String,
    answers_sha256: String,
    bundle_sha256: String,
    left_run_sha256: String,
    right_run_sha256: String,
    verified_ancestor_sha256s: Vec<String>,
    version: String,
    suite_sha256: String,
    label_policy_sha256: String,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactWire {
    relative_path: String,
    sha256: String,
}
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestWire {
    sha256: String,
    utf8_bytes: u64,
}
impl DigestWire {
    fn validate(&self) -> Result<()> {
        require(is_hex(&self.sha256, 64), "LABEL_RUN_INVALID")
    }
    fn matches(&self, text: &str) -> bool {
        self.sha256 == digest(text.as_bytes()) && self.utf8_bytes == text.len() as u64
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TextWire {
    utf8: String,
    sha256: String,
    utf8_bytes: u64,
}
impl TextWire {
    fn validate(&self) -> Result<()> {
        require(
            self.sha256 == digest(self.utf8.as_bytes())
                && self.utf8_bytes == self.utf8.len() as u64,
            "LABEL_SUBJECT_INVALID",
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectBody {
    schema: String,
    qid: String,
    query: TextWire,
    label_policy_sha256: String,
    candidates: Vec<SubjectItem>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectItem {
    candidate_instance_key: String,
    label_key: KeyWire,
    text: TextWire,
}

#[derive(PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RunMode {
    FullSearch,
    FixedCandidate,
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Terminal {
    Success,
    ShortWindow,
    Failed,
}
#[derive(PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Quality {
    NotEvaluated,
    Eligible,
    IncompleteLabels,
    Failed,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CapturedLabel {
    Direct,
    Partial,
    None,
    Unsure,
    Unknown,
}
impl CapturedLabel {
    fn resolved(self) -> SlotLabel {
        match self {
            Self::Direct => SlotLabel::Known(HumanLabel::Direct),
            Self::Partial => SlotLabel::Known(HumanLabel::Partial),
            Self::None => SlotLabel::Known(HumanLabel::None),
            Self::Unsure => SlotLabel::Known(HumanLabel::Unsure),
            Self::Unknown => SlotLabel::Unknown,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityWire {
    identity_host: String,
    agent_slug: String,
    external_id: String,
    message_idx: i64,
    #[serde(deserialize_with = "present_nullable")]
    chunk_idx: Option<i64>,
}
impl IdentityWire {
    fn trace(&self) -> CandidateIdentity {
        CandidateIdentity {
            identity_host: self.identity_host.clone(),
            agent_slug: self.agent_slug.clone(),
            external_id: self.external_id.clone(),
            message_idx: self.message_idx,
            chunk_idx: self.chunk_idx,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotWire {
    candidate_instance_key: String,
    #[serde(rename = "label_key", deserialize_with = "deserialize_key")]
    key: LabelKey,
    input_slot: usize,
    retrieval_rank: usize,
    final_rank: usize,
    #[serde(deserialize_with = "present_nullable")]
    identity: Option<IdentityWire>,
    #[serde(deserialize_with = "present_nullable")]
    message_id: Option<i64>,
    #[serde(deserialize_with = "present_nullable")]
    conversation_id: Option<i64>,
    candidate_text: DigestWire,
    #[serde(deserialize_with = "present_nullable")]
    sent_text: Option<DigestWire>,
    #[serde(deserialize_with = "present_nullable")]
    source_sha256: Option<String>,
    original_score: f64,
    #[serde(deserialize_with = "present_nullable")]
    rerank_score: Option<f64>,
    label: CapturedLabel,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageWire {
    window_id: String,
    trace_sha256: String,
    offset: usize,
    total_slots: usize,
    candidate_instance_keys: Vec<String>,
    cache_reused: bool,
    http_requests: u64,
    #[serde(deserialize_with = "present_nullable")]
    model_requests: Option<u64>,
    #[serde(deserialize_with = "present_nullable")]
    cursor_in_sha256: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    cursor_out_sha256: Option<String>,
    child_run_relative_path: String,
    page_evidence: ArtifactWire,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionWire {
    qid: String,
    query_sha256: String,
    requested_n: usize,
    actual_n: usize,
    pool_complete: bool,
    terminal: Terminal,
    full_requested_n_claim: bool,
    rerank_applied: bool,
    #[serde(deserialize_with = "present_nullable")]
    ordered_pool_sha256: Option<String>,
    slots: Vec<SlotWire>,
    pages: Vec<PageWire>,
    #[serde(deserialize_with = "present_nullable")]
    window_evidence: Option<ArtifactWire>,
    partial: bool,
    timed_out: bool,
    #[serde(deserialize_with = "present_nullable")]
    failure_code: Option<String>,
    lexical_statistics_status: String,
    #[serde(deserialize_with = "present_nullable")]
    lexical_statistics_sha256: Option<String>,
    cost: QuestionCostWire,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CountWire {
    scope: String,
    #[serde(deserialize_with = "present_nullable")]
    http_attempts: Option<u64>,
    #[serde(deserialize_with = "present_nullable")]
    http_response_observed: Option<u64>,
    #[serde(deserialize_with = "present_nullable")]
    delivery_unknown: Option<u64>,
    #[serde(deserialize_with = "present_nullable")]
    model_executions: Option<u64>,
    basis: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceWire {
    name: String,
    #[serde(deserialize_with = "present_nullable")]
    value: Option<f64>,
    unit: String,
    #[serde(deserialize_with = "present_nullable")]
    source: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionCostWire {
    identity_before_ms: f64,
    identity_after_ms: f64,
    retrieval_ms: f64,
    #[serde(deserialize_with = "present_nullable")]
    rerank_client_ms: Option<f64>,
    #[serde(deserialize_with = "present_nullable")]
    model_execution_ms: Option<f64>,
    paging_ms: f64,
    question_total_ms: f64,
    http: Vec<CountWire>,
    resource_measurements: Vec<ResourceWire>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunCostWire {
    all_run_ms: f64,
    identity_before_ms: f64,
    identity_after_ms: f64,
    sample_count: u64,
    #[serde(deserialize_with = "present_nullable")]
    mean_question_ms: Option<f64>,
    #[serde(deserialize_with = "present_nullable")]
    p50_question_ms: Option<f64>,
    #[serde(deserialize_with = "present_nullable")]
    p95_question_ms: Option<f64>,
    quantile_method: String,
    counts: Vec<CountWire>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceWire {
    #[serde(deserialize_with = "present_nullable")]
    source_manifest_sha256: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    source_checked: Option<u64>,
    #[serde(deserialize_with = "present_nullable")]
    source_producer_receipt_sha256: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    message_text_sha256: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    chunk_text_sha256: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    canonicalize_version: Option<u64>,
    #[serde(deserialize_with = "present_nullable")]
    chunking_policy_version: Option<u64>,
    #[serde(deserialize_with = "present_nullable")]
    statistics_policy: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendWire {
    #[serde(deserialize_with = "present_nullable")]
    provider: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    actual_model: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    model_revision: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    endpoint_origin_sha256: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    server_template_policy: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    document_assembly_policy: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    client_submission_policy: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    #[serde(deserialize_with = "present_nullable")]
    search_mode: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    vector_search_mode: Option<String>,
    rerank: bool,
    n: usize,
    #[serde(deserialize_with = "present_nullable")]
    page_k: Option<usize>,
    resolved_filters: Map<String, Value>,
    request_profile: String,
    #[serde(deserialize_with = "present_nullable")]
    request_evidence_sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputWire {
    private_root: String,
    run_relative_path: String,
    root_mode: String,
    file_mode: String,
    symlink_free: bool,
    fresh: bool,
    outside_input_and_repo: bool,
    writes_relative_paths: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimsWire {
    dataset: String,
    attribution: String,
    fts_vec_correctness: String,
    pure_engine: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AfterWire {
    basis: String,
    inventory_digests: String,
    database_sha256: String,
    source_manifest_sha256: String,
    wal_bytes: u64,
    generation_unchanged: bool,
    policies_unchanged: bool,
    shared_maintenance_lease_held: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunWire {
    schema: String,
    run_id: String,
    mode: RunMode,
    terminal: Terminal,
    quality_status: Quality,
    #[serde(deserialize_with = "present_nullable")]
    failure_code: Option<String>,
    source_commit: String,
    binary_sha256: String,
    argv_sha256: String,
    suite_sha256: String,
    query_manifest_sha256: String,
    labels_sha256: String,
    label_policy_sha256: String,
    question_count: u64,
    suite_candidate_slots: u64,
    source_identity: SourceWire,
    #[serde(deserialize_with = "present_nullable")]
    expected_binding_file_sha256: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    expected_binding: Option<InputBinding>,
    #[serde(deserialize_with = "present_nullable")]
    observed_before: Option<InputBinding>,
    #[serde(deserialize_with = "present_nullable")]
    observed_after: Option<InputBinding>,
    #[serde(deserialize_with = "present_nullable")]
    fixed_input_manifest_sha256: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    fixed_windows_file_sha256: Option<String>,
    backend_identity: BackendWire,
    request: RequestWire,
    output: OutputWire,
    questions: Vec<QuestionWire>,
    cost: RunCostWire,
    claims: ClaimsWire,
    #[serde(deserialize_with = "present_nullable")]
    after_verification: Option<AfterWire>,
}

fn deserialize_key<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<LabelKey, D::Error> {
    KeyWire::deserialize(d)?
        .checked()
        .map_err(serde::de::Error::custom)
}

impl RunWire {
    fn validate(&self) -> Result<()> {
        require(
            self.schema == "cass.regression-run.v1"
                && self.question_count == 9
                && self.suite_candidate_slots == 1800
                && self.questions.len() == 9
                && self.failure_code.is_none()
                && self.terminal != Terminal::Failed
                && self.quality_status != Quality::Failed,
            "LABEL_RUN_INVALID",
        )?;
        require(is_hex(&self.source_commit, 40), "LABEL_RUN_INVALID")?;
        for sha in [
            &self.binary_sha256,
            &self.argv_sha256,
            &self.suite_sha256,
            &self.query_manifest_sha256,
            &self.labels_sha256,
            &self.label_policy_sha256,
        ] {
            require(is_hex(sha, 64), "LABEL_RUN_INVALID")?;
        }
        for sha in [
            &self.expected_binding_file_sha256,
            &self.fixed_input_manifest_sha256,
            &self.fixed_windows_file_sha256,
            &self.backend_identity.endpoint_origin_sha256,
        ] {
            optional_sha(sha)?;
        }
        require(
            self.output.root_mode == "0700"
                && self.output.file_mode == "0600"
                && self.output.symlink_free
                && self.output.fresh
                && self.output.outside_input_and_repo,
            "LABEL_RUN_INVALID",
        )?;
        safe_relative(&self.output.run_relative_path)?;
        require(
            !self.output.run_relative_path.contains('/'),
            "LABEL_RUN_INVALID",
        )?;
        require(
            self.claims.dataset == "development-regression-9-small-sample"
                && self.claims.attribution == "observed-comparison"
                && self.claims.fts_vec_correctness == "NOT_VERIFIED"
                && !self.claims.pure_engine,
            "LABEL_RUN_INVALID",
        )?;
        require(
            self.request.n > 0 && self.request.page_k.is_none_or(|k| k > 0),
            "LABEL_RUN_INVALID",
        )?;
        optional_sha(&self.request.request_evidence_sha256)?;
        require(
            self.request
                .search_mode
                .as_deref()
                .is_none_or(|s| matches!(s, "lexical" | "semantic" | "hybrid"))
                && self
                    .request
                    .vector_search_mode
                    .as_deref()
                    .is_none_or(|s| matches!(s, "exact" | "fast")),
            "LABEL_RUN_INVALID",
        )?;
        require(
            self.cost.quantile_method == "nearest-rank" && self.cost.sample_count == 9,
            "LABEL_RUN_INVALID",
        )?;
        numbers(&[
            self.cost.all_run_ms,
            self.cost.identity_before_ms,
            self.cost.identity_after_ms,
        ])?;
        for n in [
            self.cost.mean_question_ms,
            self.cost.p50_question_ms,
            self.cost.p95_question_ms,
        ]
        .into_iter()
        .flatten()
        {
            numbers(&[n])?;
        }
        counts(&self.cost.counts)?;
        match self.mode {
            RunMode::FullSearch => {
                require(
                    self.request.request_profile == "d5-fixed-filters-v1"
                        && self.request.search_mode.is_some()
                        && self.fixed_input_manifest_sha256.is_none()
                        && self.fixed_windows_file_sha256.is_none(),
                    "LABEL_RUN_INVALID",
                )?;
                if self.request.rerank {
                    require(self.request.page_k.is_some(), "LABEL_RUN_INVALID")?;
                } else {
                    require(self.request.page_k.is_none(), "LABEL_RUN_INVALID")?;
                }
                let before = self.observed_before.as_ref().context("LABEL_RUN_INVALID")?;
                validate_binding(before)?;
                require(
                    self.expected_binding.as_ref() == Some(before)
                        && self.observed_after.as_ref() == Some(before)
                        && self.expected_binding_file_sha256.is_some(),
                    "LABEL_RUN_INVALID",
                )?;
                let source = &self.source_identity;
                require(
                    source.source_manifest_sha256.as_deref()
                        == Some(before.source_manifest_sha256.as_str())
                        && source.source_checked == Some(5049)
                        && source
                            .source_producer_receipt_sha256
                            .as_deref()
                            .is_some_and(|s| is_hex(s, 64))
                        && source.message_text_sha256.as_deref()
                            == Some(before.message_text_sha256.as_str())
                        && source.chunk_text_sha256.as_deref()
                            == Some(before.chunk_text_sha256.as_str())
                        && source.canonicalize_version == Some(3)
                        && source.chunking_policy_version == Some(1)
                        && source.statistics_policy.as_deref() == Some("regression-fresh-v1"),
                    "LABEL_RUN_INVALID",
                )?;
                let after = self
                    .after_verification
                    .as_ref()
                    .context("LABEL_RUN_INVALID")?;
                require(
                    after.basis == "equal-physical-db-and-source-generation-policy"
                        && after.inventory_digests == "reused-initial-not-independently-reexported"
                        && after.database_sha256 == before.database_sha256
                        && after.source_manifest_sha256 == before.source_manifest_sha256
                        && after.wal_bytes == 0
                        && after.generation_unchanged
                        && after.policies_unchanged
                        && after.shared_maintenance_lease_held,
                    "LABEL_RUN_INVALID",
                )?;
            }
            RunMode::FixedCandidate => {
                require(
                    self.request.request_profile == "fixed-package-v1"
                        && self.request.rerank
                        && self.request.n == 200
                        && self.request.page_k.is_none()
                        && self.request.search_mode.is_none()
                        && self.request.vector_search_mode.is_none()
                        && self.expected_binding.is_none()
                        && self.expected_binding_file_sha256.is_none()
                        && self.observed_before.is_none()
                        && self.observed_after.is_none()
                        && self.after_verification.is_none(),
                    "LABEL_RUN_INVALID",
                )?;
            }
        }
        let mut short = false;
        for (q, qid) in self.questions.iter().zip(QIDS) {
            require(
                q.qid == qid
                    && is_hex(&q.query_sha256, 64)
                    && q.requested_n == self.request.n
                    && q.actual_n == q.slots.len()
                    && q.actual_n <= q.requested_n
                    && q.pool_complete
                    && !q.partial
                    && !q.timed_out
                    && q.failure_code.is_none(),
                "LABEL_RUN_INVALID",
            )?;
            let is_short = q.actual_n < q.requested_n;
            short |= is_short;
            require(
                q.terminal
                    == if is_short {
                        Terminal::ShortWindow
                    } else {
                        Terminal::Success
                    }
                    && q.full_requested_n_claim == !is_short
                    && q.rerank_applied == (self.request.rerank && q.actual_n > 0),
                "LABEL_RUN_INVALID",
            )?;
            optional_sha(&q.ordered_pool_sha256)?;
            optional_sha(&q.lexical_statistics_sha256)?;
            require(
                matches!(q.lexical_statistics_status.as_str(), "USED" | "NOT_USED"),
                "LABEL_RUN_INVALID",
            )?;
            numbers(&[
                q.cost.identity_before_ms,
                q.cost.identity_after_ms,
                q.cost.retrieval_ms,
                q.cost.paging_ms,
                q.cost.question_total_ms,
            ])?;
            for n in [q.cost.rerank_client_ms, q.cost.model_execution_ms]
                .into_iter()
                .flatten()
            {
                numbers(&[n])?;
            }
            counts(&q.cost.http)?;
            for resource in &q.cost.resource_measurements {
                if let Some(n) = resource.value {
                    numbers(&[n])?;
                }
            }
            let mut instances = HashSet::new();
            let mut input_slots = HashSet::new();
            for (rank, slot) in q.slots.iter().enumerate() {
                require(
                    is_hex(&slot.candidate_instance_key, 64)
                        && instances.insert(&slot.candidate_instance_key)
                        && input_slots.insert(slot.input_slot)
                        && slot.input_slot < q.actual_n
                        && slot.retrieval_rank == slot.input_slot + 1
                        && slot.final_rank == rank + 1
                        && slot.key.query_sha256 == q.query_sha256
                        && slot.key.label_policy_sha256 == self.label_policy_sha256,
                    "LABEL_RUN_INVALID",
                )?;
                slot.candidate_text.validate()?;
                optional_sha(&slot.source_sha256)?;
                require(
                    slot.original_score.is_finite() && slot.rerank_score.is_none_or(f64::is_finite),
                    "LABEL_RUN_INVALID",
                )?;
                if let Some(text) = &slot.sent_text {
                    text.validate()?;
                }
                if self.mode == RunMode::FullSearch {
                    let identity = slot.identity.as_ref().context("LABEL_RUN_INVALID")?;
                    require(
                        regression_trace::candidate_instance_key(&identity.trace())?
                            == slot.candidate_instance_key
                            && slot.message_id.is_some(),
                        "LABEL_RUN_INVALID",
                    )?;
                } else {
                    require(slot.identity.is_none(), "LABEL_RUN_INVALID")?;
                }
                if !self.request.rerank {
                    require(
                        slot.sent_text.is_none()
                            && slot.rerank_score.is_none()
                            && slot.input_slot == rank,
                        "LABEL_RUN_INVALID",
                    )?;
                }
            }
        }
        require(
            self.terminal
                == if short {
                    Terminal::ShortWindow
                } else {
                    Terminal::Success
                },
            "LABEL_RUN_INVALID",
        )
    }
}

fn numbers(values: &[f64]) -> Result<()> {
    require(values.iter().all(|v| v.is_finite()), "LABEL_RUN_INVALID")
}
fn optional_sha(value: &Option<String>) -> Result<()> {
    require(
        value.as_deref().is_none_or(|s| is_hex(s, 64)),
        "LABEL_RUN_INVALID",
    )
}
fn counts(values: &[CountWire]) -> Result<()> {
    require(
        values.iter().all(|v| {
            matches!(
                v.basis.as_str(),
                "observed-client" | "observed-server-fixture" | "not-called" | "unknown"
            )
        }),
        "LABEL_RUN_INVALID",
    )
}

fn validate_binding(binding: &InputBinding) -> Result<()> {
    let g = &binding.generation;
    require(
        binding.schema == "cass.regression-input.v1"
            && binding.schema_version == 8
            && binding.wal_bytes == 0
            && binding.canonicalize_version == 3
            && binding.chunking_policy_version == 1
            && binding.statistics_policy == "regression-fresh-v1"
            && binding.statistics_encoding == "lexical-stats-v1"
            && binding.consumed_domains
                == [
                    "sqlite:lex_docs/fts_lex",
                    "sqlite:active-generation/message_chunks/vec-mirrors",
                ],
        "LABEL_RUN_INVALID",
    )?;
    for sha in [
        &binding.database_sha256,
        &binding.source_manifest_sha256,
        &binding.message_text_sha256,
        &binding.chunk_text_sha256,
        &binding.retrieval_order_sha256,
        &binding.retrieval_layout_sha256,
        &binding.lexical_statistics_sha256,
    ] {
        require(is_hex(sha, 64), "LABEL_RUN_INVALID")?;
    }
    require(
        g.generation_id >= 0
            && !g.embedder_id.is_empty()
            && g.dim >= 1
            && !g.fingerprint.is_empty()
            && g.canonicalize_version == 3
            && g.chunking_policy_version == 1
            && matches!(g.byte_order.as_str(), "le" | "be")
            && g.vector_revision >= 0
            && matches!(g.audit_status.as_str(), "passed" | "pending" | "failed")
            && is_hex(&g.vector_domain_instance_id, 32),
        "LABEL_RUN_INVALID",
    )
}

fn validate_subject(
    body: &SubjectBody,
    question: &QuestionWire,
    policy: &str,
    reranked: bool,
) -> Result<()> {
    require(
        body.schema == "cass.regression-label-subjects.v1"
            && body.qid == question.qid
            && body.query.sha256 == question.query_sha256
            && body.label_policy_sha256 == policy
            && body.candidates.len() == question.slots.len(),
        "LABEL_SUBJECT_INVALID",
    )?;
    body.query.validate()?;
    let slots: HashMap<_, _> = question
        .slots
        .iter()
        .map(|s| (s.candidate_instance_key.as_str(), s))
        .collect();
    let mut seen = HashSet::new();
    for item in &body.candidates {
        require(
            seen.insert(item.candidate_instance_key.as_str()),
            "LABEL_SUBJECT_INVALID",
        )?;
        let slot = slots
            .get(item.candidate_instance_key.as_str())
            .context("LABEL_SUBJECT_INVALID")?;
        require(
            item.label_key.checked()? == slot.key,
            "LABEL_SUBJECT_INVALID",
        )?;
        item.text.validate()?;
        let judged = if reranked {
            slot.sent_text.as_ref().context("LABEL_SUBJECT_INVALID")?
        } else {
            &slot.candidate_text
        };
        require(
            judged.matches(&item.text.utf8) && slot.key.label_text_sha256 == item.text.sha256,
            "LABEL_SUBJECT_INVALID",
        )?;
    }
    require(seen.len() == slots.len(), "LABEL_SUBJECT_INVALID")
}

fn validate_question_evidence(
    root: &Path,
    output: &OutputWire,
    question: &QuestionWire,
    body: &SubjectBody,
    request: &RequestWire,
    binding: &InputBinding,
) -> Result<()> {
    let reference = question
        .window_evidence
        .as_ref()
        .context("LABEL_RUN_INVALID")?;
    let value = read_reference(root, output, reference)?;
    // Existing WindowEvidence owns this trace protocol. Its nullable fields must
    // still be explicitly present before its serde decoder is invoked.
    for field in [
        "lexical_statistics_sha256",
        "prepared_documents",
        "failure_reason",
    ] {
        require(value.get(field).is_some(), "LABEL_RUN_INVALID")?;
    }
    let evidence: WindowEvidence = serde_json::from_value(value).context("LABEL_RUN_INVALID")?;
    require(
        evidence.schema == "cass.regression-window-trace.v2"
            && evidence.binding == *binding
            && evidence.query.sha256 == body.query.sha256
            && evidence.query.utf8_bytes == body.query.utf8_bytes
            && evidence.transport_scope == "rerank-http-v1"
            && evidence.rerank_requested == request.rerank
            && evidence.applied == question.rerank_applied
            && evidence.failure_reason.is_none()
            && evidence.final_slots.len() == question.actual_n
            && evidence.retrieval.len() == question.actual_n
            && evidence.snippets.len() == question.actual_n,
        "LABEL_RUN_INVALID",
    )?;
    for (rank, slot) in question.slots.iter().enumerate() {
        let frozen = evidence
            .final_slots
            .get(rank)
            .context("LABEL_RUN_INVALID")?;
        let identity = slot.identity.as_ref().context("LABEL_RUN_INVALID")?.trace();
        require(
            frozen.input_slot == slot.input_slot
                && frozen.retrieval_rank == slot.retrieval_rank
                && frozen.identity == identity
                && Some(frozen.message_id) == slot.message_id,
            "LABEL_RUN_INVALID",
        )?;
        let snippet = evidence
            .snippets
            .get(slot.input_slot)
            .context("LABEL_RUN_INVALID")?;
        require(
            snippet.sha256 == slot.candidate_text.sha256
                && snippet.utf8_bytes == slot.candidate_text.utf8_bytes,
            "LABEL_RUN_INVALID",
        )?;
        if request.rerank {
            let sent = evidence
                .prepared_documents
                .as_ref()
                .and_then(|d| d.get(slot.input_slot))
                .context("LABEL_RUN_INVALID")?;
            let recorded = slot.sent_text.as_ref().context("LABEL_RUN_INVALID")?;
            require(
                sent.sha256 == recorded.sha256 && sent.utf8_bytes == recorded.utf8_bytes,
                "LABEL_RUN_INVALID",
            )?;
        }
    }
    let permutation: Vec<_> = evidence.final_slots.iter().map(|s| s.input_slot).collect();
    require(
        regression_trace::final_slot_mapping(&evidence.retrieval, &permutation)?
            == evidence.final_slots,
        "LABEL_RUN_INVALID",
    )?;
    if !request.rerank || question.actual_n == 0 {
        require(question.pages.is_empty(), "LABEL_RUN_INVALID")?;
        return Ok(());
    }
    let mut pages = Vec::new();
    let mut offset = 0usize;
    let mut cursor: Option<&str> = None;
    for (index, summary) in question.pages.iter().enumerate() {
        safe_relative(&summary.child_run_relative_path)?;
        optional_sha(&summary.cursor_in_sha256)?;
        optional_sha(&summary.cursor_out_sha256)?;
        require(
            summary.cursor_in_sha256.as_deref() == cursor
                && summary.offset == offset
                && summary.total_slots == question.actual_n
                && summary.cache_reused == (index > 0),
            "LABEL_RUN_INVALID",
        )?;
        let value = read_reference(root, output, &summary.page_evidence)?;
        require(value.get("model_requests").is_some(), "LABEL_RUN_INVALID")?;
        let page: PageEvidence = serde_json::from_value(value).context("LABEL_RUN_INVALID")?;
        let end = offset
            .checked_add(page.slots.len())
            .context("LABEL_RUN_INVALID")?;
        let expected = question
            .slots
            .get(offset..end)
            .context("LABEL_RUN_INVALID")?;
        require(
            summary.window_id == page.window_id
                && summary.trace_sha256 == page.trace_sha256
                && summary.offset == page.offset
                && summary.total_slots == page.total_slots
                && summary.cache_reused == page.cache_reused
                && summary.http_requests == page.http_requests as u64
                && summary.model_requests == page.model_requests.map(|n| n as u64)
                && summary.candidate_instance_keys
                    == expected
                        .iter()
                        .map(|s| s.candidate_instance_key.clone())
                        .collect::<Vec<_>>(),
            "LABEL_RUN_INVALID",
        )?;
        offset = end;
        cursor = summary.cursor_out_sha256.as_deref();
        pages.push(page);
    }
    require(
        offset == question.actual_n && cursor.is_none(),
        "LABEL_RUN_INVALID",
    )?;
    regression_trace::validate_complete_pages(&pages, &evidence)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn human_wire_excludes_engine_rank_and_unknown_answers() {
        let id = "00000000000040008000000000000001";
        let mut value = json!({"schema":"cass.regression-blind-bundle.v1","bundle_id":id,"label_policy_sha256":digest(b"synthetic-policy"),"items":[{"opaque_id":id,"query_utf8":"synthetic-query","text_utf8":"synthetic-text"}]});
        assert!(serde_json::from_value::<BlindBundle>(value.clone()).is_ok());
        value["items"][0]["retrieval_rank"] = json!(1);
        assert!(serde_json::from_value::<BlindBundle>(value).is_err());
        let answers = json!({"schema":"cass.regression-blind-answers.v1","bundle_id":id,"records":[{"opaque_id":id,"value":"unknown"}]});
        assert!(serde_json::from_value::<BlindAnswers>(answers).is_err());
    }

    #[test]
    fn uuid_bits_and_nullable_presence_are_required() {
        assert!(valid_id("00000000000040008000000000000001"));
        assert!(!valid_id("00000000000000000000000000000001"));
        assert!(!valid_id("00000000000040007000000000000001"));
        let value = json!({"identity_host":"synthetic-host","agent_slug":"synthetic-agent","external_id":"synthetic-session","message_idx":0});
        assert!(serde_json::from_value::<IdentityWire>(value.clone()).is_err());
        let mut present = value;
        present["chunk_idx"] = Value::Null;
        assert!(serde_json::from_value::<IdentityWire>(present).is_ok());
    }

    #[test]
    fn subject_text_checks_exact_utf8_bytes_without_normalization() {
        let original = "synthetic🙂\n";
        let text = TextWire {
            utf8: original.into(),
            sha256: digest(original.as_bytes()),
            utf8_bytes: original.len() as u64,
        };
        assert!(text.validate().is_ok());
        let changed = TextWire {
            utf8: original.trim().into(),
            ..text
        };
        assert!(changed.validate().is_err());
    }
}
