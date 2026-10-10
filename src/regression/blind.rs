//! Private, source-free annotation presentation over immutable execution runs.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

use super::fixed::{ExpectedPool, PreparedPool};
use super::fixed_encoding::{NumericValue, encode_numeric};
use super::input::WirePinned;

use super::labels::{
    self, FilePin, HumanLabel, KeyWire, LegacyBaseValidated, SlotLabel, VerifiedLabelSet, digest,
    is_hex, present_nullable, require,
};
use super::types::{LabelKey, MessageId, RunPaths};
use crate::search::regression_binding::InputBinding;
use crate::search::regression_trace::{self, CandidateIdentity, PageEvidence, WindowEvidence};

const QIDS: [&str; 9] = [
    "N01", "N02", "N03", "N04", "N05", "N06", "N07", "N08", "N12",
];

pub(crate) struct VerifiedLabelRun {
    pin: FilePin,
    observed_sha256: String,
    capture: VerifiedRunCapture,
    root: PathBuf,
    subjects: Vec<SubjectFile>,
}

struct SubjectFile {
    reference: ArtifactWire,
    body: SubjectBody,
}

impl VerifiedLabelRun {
    pub(crate) fn observed_file_sha256(&self) -> &str {
        &self.observed_sha256
    }
    pub(crate) fn capture(&self) -> &VerifiedRunCapture {
        &self.capture
    }
    pub(super) fn suite_sha256(&self) -> &str {
        &self.capture.wire.suite_sha256
    }
    pub(super) fn policy_sha256(&self) -> &str {
        &self.capture.wire.label_policy_sha256
    }
    pub(super) fn capture_labels_sha256(&self) -> &str {
        &self.capture.wire.labels_sha256
    }
    pub(super) fn capture_slots(&self) -> impl Iterator<Item = (&LabelKey, SlotLabel)> {
        self.capture.questions.iter().flat_map(|q| {
            q.slots
                .iter()
                .map(|s| (&s.wire.key, s.wire.label.resolved()))
        })
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
    load_subjects(pin, None)
}

fn load_subjects(pin: &FilePin, capture: Option<&LegacyBaseValidated>) -> Result<VerifiedLabelRun> {
    let wire = labels::read_pin(pin)?;
    let observed_sha256 = wire.observed_file_sha256().to_string();
    let value = restore_run_scores(&wire)?;
    let mut run: RunWire = serde_json::from_value(value.clone()).context("LABEL_RUN_INVALID")?;
    run.validate()?;
    let pools = match run.mode {
        RunMode::FullSearch => None,
        RunMode::FixedCandidate => {
            let capture = capture.context("LABEL_RUN_INVALID")?;
            let inputs = capture.inputs();
            require(
                inputs
                    .windows
                    .iter()
                    .all(|w| w.items.iter().all(|s| s.scoreable)),
                "LABEL_RUN_INVALID",
            )?;
            require(
                run.suite_sha256 == inputs.suite_sha256
                    && run.label_policy_sha256 == inputs.label_policy_sha256
                    && run.fixed_input_manifest_sha256.as_deref()
                        == Some(inputs.input_manifest_sha256.as_str())
                    && run.fixed_windows_file_sha256.as_deref()
                        == Some(inputs.windows_file_sha256.as_str()),
                "LABEL_CAPTURE_MISMATCH",
            )?;
            let expected: Vec<_> = run
                .questions
                .iter()
                .map(|q| {
                    Ok(ExpectedPool {
                        qid: q.qid.clone(),
                        ordered_pool_sha256: q
                            .ordered_pool_sha256
                            .clone()
                            .context("LABEL_RUN_INVALID")?,
                    })
                })
                .collect::<Result<_>>()?;
            Some(super::fixed::prepare_pools(
                inputs,
                capture.windows_bytes(),
                &expected,
            )?)
        }
    };
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
    for (question_index, question) in run.questions.iter_mut().enumerate() {
        let relative = format!("label-subjects-{}.json", question.qid);
        listed(&run.output, &relative)?;
        let wire = labels::read_subject(&root.join(&relative))?;
        let body: SubjectBody =
            serde_json::from_value(wire.value().clone()).context("LABEL_SUBJECT_INVALID")?;
        validate_subject(
            &body,
            question,
            &run.label_policy_sha256,
            run.request.rerank,
        )?;
        if let Some(pools) = &pools {
            let slots = value["questions"][question_index]["slots"]
                .as_array()
                .context("LABEL_RUN_INVALID")?;
            pools[question_index].verify_recovery(slots)?;
            let copy = read_listed(
                &root,
                &run.output,
                &format!("question-{}.json", question.qid),
            )?;
            let copy = restore_fixed_question_scores(&copy)?;
            let _: QuestionWire =
                serde_json::from_value(copy.clone()).context("LABEL_RUN_INVALID")?;
            require(
                copy == value["questions"][question_index],
                "LABEL_RUN_INVALID",
            )?;
            validate_fixed_evidence(
                &root,
                &run.output,
                question,
                &body,
                &pools[question_index],
                &run.backend_identity,
            )?;
        } else {
            validate_question_evidence(
                &root,
                &run.output,
                question,
                &body,
                &run.request,
                run.observed_before.as_ref().context("LABEL_RUN_INVALID")?,
            )?;
        }
        subjects.push(SubjectFile {
            reference: ArtifactWire {
                relative_path: relative,
                sha256: wire.observed_file_sha256().to_string(),
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
    let provenance = CaptureProvenance {
        source_commit: run.source_commit.clone(),
        binary_sha256: run.binary_sha256.clone(),
        argv_sha256: run.argv_sha256.clone(),
    };
    let questions = std::mem::take(&mut run.questions)
        .into_iter()
        .map(|mut wire| {
            let slots = std::mem::take(&mut wire.slots)
                .into_iter()
                .map(|wire| {
                    Ok(VerifiedSlotCapture {
                        original_score: numeric_value(&wire.original_score)?,
                        wire,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(VerifiedQuestionCapture { wire, slots })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(VerifiedLabelRun {
        pin: pin.clone(),
        observed_sha256,
        capture: VerifiedRunCapture {
            wire: run,
            provenance,
            questions,
        },
        root,
        subjects,
    })
}

pub(crate) fn load_run_subjects_with_capture(
    run: &FilePin,
    capture: &LegacyBaseValidated,
) -> Result<VerifiedLabelRun> {
    let current_capture = capture.reload()?;
    let run = load_subjects(run, Some(&current_capture))?;
    current_capture.check_run(&run)?;
    Ok(run)
}

fn numeric_value(number: &Number) -> Result<NumericValue> {
    if let Some(value) = number.as_i64() {
        Ok(NumericValue::I64(value))
    } else if let Some(value) = number.as_u64() {
        Ok(NumericValue::U64(value))
    } else {
        let value = number.as_f64().context("LABEL_RUN_INVALID")?;
        require(value.is_finite(), "LABEL_RUN_INVALID")?;
        Ok(NumericValue::F64(value))
    }
}

fn restored_number(token: &[u8]) -> Result<Number> {
    match encode_numeric(token)
        .map_err(|_| anyhow::anyhow!("LABEL_RUN_INVALID"))?
        .value
        .map_err(|_| anyhow::anyhow!("LABEL_RUN_INVALID"))?
    {
        NumericValue::I64(value) => Ok(Number::from(value)),
        NumericValue::U64(value) => Ok(Number::from(value)),
        NumericValue::F64(value) => Number::from_f64(value).context("LABEL_RUN_INVALID"),
    }
}

#[derive(Clone, Copy)]
enum ScorePath {
    Root,
    Questions,
    Question(usize),
    Slots(usize),
    Slot(usize, usize),
    Original(usize, usize),
    Rerank(usize, usize),
    Other,
}

#[derive(Default)]
struct ScoreSpans {
    original: Option<Range<usize>>,
    // Outer Option records field presence. Inner None is explicit JSON null.
    rerank: Option<Option<Range<usize>>>,
}

struct RunScoreWalk<'a> {
    bytes: &'a [u8],
    pos: usize,
    spans: Vec<Vec<ScoreSpans>>,
}

impl RunScoreWalk<'_> {
    fn advance(&mut self) -> Result<()> {
        self.pos = self.pos.checked_add(1).context("LABEL_RUN_INVALID")?;
        require(self.pos <= self.bytes.len(), "LABEL_RUN_INVALID")
    }
    fn space(&mut self) -> Result<()> {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| b" \t\r\n".contains(b))
        {
            self.advance()?;
        }
        Ok(())
    }
    fn take(&mut self, byte: u8) -> Result<bool> {
        self.space()?;
        if self.bytes.get(self.pos) == Some(&byte) {
            self.advance()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn expect(&mut self, byte: u8) -> Result<()> {
        require(self.take(byte)?, "LABEL_RUN_INVALID")
    }
    fn string(&mut self) -> Result<Range<usize>> {
        self.space()?;
        let start = self.pos;
        self.expect(b'"')?;
        while let Some(byte) = self.bytes.get(self.pos).copied() {
            self.advance()?;
            match byte {
                b'"' => return Ok(start..self.pos),
                b'\\' => {
                    require(self.pos < self.bytes.len(), "LABEL_RUN_INVALID")?;
                    self.advance()?;
                }
                _ => {}
            }
        }
        bail!("LABEL_RUN_INVALID")
    }
    fn scalar(&mut self) -> Result<Range<usize>> {
        self.space()?;
        let start = self.pos;
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| !b" \t\r\n,]}".contains(b))
        {
            self.advance()?;
        }
        require(start < self.pos, "LABEL_RUN_INVALID")?;
        Ok(start..self.pos)
    }
    fn value(&mut self, path: ScorePath, depth: usize) -> Result<()> {
        require(depth < 128, "LABEL_RUN_INVALID")?;
        self.space()?;
        if let ScorePath::Original(q, s) | ScorePath::Rerank(q, s) = path {
            let span = self.scalar()?;
            let token = self.bytes.get(span.clone()).context("LABEL_RUN_INVALID")?;
            let target = self
                .spans
                .get_mut(q)
                .and_then(|v| v.get_mut(s))
                .context("LABEL_RUN_INVALID")?;
            match path {
                ScorePath::Original(_, _) => {
                    require(
                        target.original.is_none()
                            && token
                                .first()
                                .is_some_and(|b| b.is_ascii_digit() || *b == b'-'),
                        "LABEL_RUN_INVALID",
                    )?;
                    target.original = Some(span);
                }
                ScorePath::Rerank(_, _) => {
                    require(target.rerank.is_none(), "LABEL_RUN_INVALID")?;
                    require(
                        token == b"null"
                            || token
                                .first()
                                .is_some_and(|b| b.is_ascii_digit() || *b == b'-'),
                        "LABEL_RUN_INVALID",
                    )?;
                    target.rerank = Some(if token == b"null" { None } else { Some(span) });
                }
                _ => bail!("LABEL_RUN_INVALID"),
            }
            return Ok(());
        }
        match self.bytes.get(self.pos) {
            Some(b'{') => {
                self.advance()?;
                if !self.take(b'}')? {
                    loop {
                        let span = self.string()?;
                        let key: String = serde_json::from_slice(&self.bytes[span])
                            .context("LABEL_RUN_INVALID")?;
                        self.expect(b':')?;
                        let child = match (path, key.as_str()) {
                            (ScorePath::Root, "questions") => ScorePath::Questions,
                            (ScorePath::Question(q), "slots") => ScorePath::Slots(q),
                            (ScorePath::Slot(q, s), "original_score") => ScorePath::Original(q, s),
                            (ScorePath::Slot(q, s), "rerank_score") => ScorePath::Rerank(q, s),
                            _ => ScorePath::Other,
                        };
                        self.value(child, depth.checked_add(1).context("LABEL_RUN_INVALID")?)?;
                        if self.take(b'}')? {
                            break;
                        }
                        self.expect(b',')?;
                    }
                }
            }
            Some(b'[') => {
                self.advance()?;
                let mut index = 0usize;
                if !self.take(b']')? {
                    loop {
                        let child = match path {
                            ScorePath::Questions => ScorePath::Question(index),
                            ScorePath::Slots(q) => ScorePath::Slot(q, index),
                            _ => ScorePath::Other,
                        };
                        self.value(child, depth.checked_add(1).context("LABEL_RUN_INVALID")?)?;
                        index = index.checked_add(1).context("LABEL_RUN_INVALID")?;
                        if self.take(b']')? {
                            break;
                        }
                        self.expect(b',')?;
                    }
                }
            }
            Some(b'"') => {
                self.string()?;
            }
            Some(_) => {
                self.scalar()?;
            }
            None => bail!("LABEL_RUN_INVALID"),
        }
        Ok(())
    }
}

// The production entry accepts only the input reader's same-buffer proof.
fn restore_run_scores(wire: &WirePinned) -> Result<Value> {
    restore_score_leaves(wire.bytes(), wire.value(), false)
}

fn restore_fixed_question_scores(wire: &WirePinned) -> Result<Value> {
    restore_score_leaves(wire.bytes(), wire.value(), true)
}

fn restore_score_leaves(bytes: &[u8], strict_value: &Value, fixed_question: bool) -> Result<Value> {
    let questions: Vec<_> = if fixed_question {
        vec![strict_value]
    } else {
        strict_value["questions"]
            .as_array()
            .context("LABEL_RUN_INVALID")?
            .iter()
            .collect()
    };
    let mut count = 0usize;
    let spans = questions
        .iter()
        .map(|q| {
            require(
                q["qid"].as_str().is_some_and(|s| !s.is_empty()),
                "LABEL_RUN_INVALID",
            )?;
            let slots = q["slots"].as_array().context("LABEL_RUN_INVALID")?;
            count = count
                .checked_add(slots.len())
                .context("LABEL_RUN_INVALID")?;
            require(count <= bytes.len() / 2, "LABEL_RUN_INVALID")?;
            slots
                .iter()
                .map(|slot| {
                    require(slot["input_slot"].as_u64().is_some(), "LABEL_RUN_INVALID")?;
                    Ok(ScoreSpans::default())
                })
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;
    let mut walk = RunScoreWalk {
        bytes,
        pos: 0,
        spans,
    };
    walk.value(
        if fixed_question {
            ScorePath::Question(0)
        } else {
            ScorePath::Root
        },
        0,
    )?;
    walk.space()?;
    require(walk.pos == bytes.len(), "LABEL_RUN_INVALID")?;
    let mut value = strict_value.clone();
    for (q, slots) in walk.spans.into_iter().enumerate() {
        for (s, spans) in slots.into_iter().enumerate() {
            let original = spans.original.context("LABEL_RUN_INVALID")?;
            let rerank = spans.rerank.context("LABEL_RUN_INVALID")?;
            let question = if fixed_question {
                &mut value
            } else {
                &mut value["questions"][q]
            };
            question["slots"][s]["original_score"] = Value::Number(restored_number(
                bytes.get(original).context("LABEL_RUN_INVALID")?,
            )?);
            question["slots"][s]["rerank_score"] = match rerank {
                Some(span) => Value::Number(restored_number(
                    bytes.get(span).context("LABEL_RUN_INVALID")?,
                )?),
                None => Value::Null,
            };
        }
    }
    Ok(value)
}

pub(crate) fn export_blind(
    left: &VerifiedLabelRun,
    right: &VerifiedLabelRun,
    parent: &VerifiedLabelSet,
    output: &RunPaths,
) -> Result<BlindArtifacts> {
    // Re-read immutable source pins even when callers retained a prior proof.
    let base = parent.reload_base()?;
    let left = load_run_subjects_with_capture(&left.pin, &base)?;
    let right = load_run_subjects_with_capture(&right.pin, &base)?;
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
        left_run_sha256: left.observed_file_sha256().into(),
        right_run_sha256: right.observed_file_sha256().into(),
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
    let left = load_run_subjects_with_capture(&left.pin, base)?;
    let right = load_run_subjects_with_capture(&right.pin, base)?;
    let current_parent = parent.refresh(base, &left, &right)?;
    let manifest_wire = labels::read_pin(manifest)?;
    let manifest_body: BlindManifest =
        serde_json::from_value(manifest_wire.value().clone()).context("BLIND_MANIFEST_INVALID")?;
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
            && manifest_body.left_run_sha256 == left.observed_file_sha256()
            && manifest_body.right_run_sha256 == right.observed_file_sha256(),
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
        serde_json::from_value(bundle_wire.value().clone()).context("BLIND_BUNDLE_INVALID")?;
    let answers_wire = labels::read_pin(answers)?;
    let answers_body: BlindAnswers =
        serde_json::from_value(answers_wire.value().clone()).context("BLIND_ANSWERS_INVALID")?;
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
        readback.value() == &new_labels
            && label_pin.expected_sha256() != current_parent.observed_file_sha256(),
        "BLIND_OUTPUT_WRITE_FAILED",
    )?;
    let receipt = ImportReceipt {
        schema: "cass.regression-label-import-receipt.v1".into(),
        status: "LABEL_COVERAGE_COMPLETE".into(),
        parent_labels_file_sha256: current_parent.observed_file_sha256().into(),
        new_labels_file_sha256: readback.observed_file_sha256().into(),
        manifest_sha256: manifest_wire.observed_file_sha256().to_string(),
        answers_sha256: answers_wire.observed_file_sha256().to_string(),
        bundle_sha256: bundle_wire.observed_file_sha256().to_string(),
        left_run_sha256: left.observed_file_sha256().into(),
        right_run_sha256: right.observed_file_sha256().into(),
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
    .value()
    .clone())
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
        labels::read_pin(&pin)?.value() == value,
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
pub(crate) struct DigestWire {
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

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RunMode {
    FullSearch,
    FixedCandidate,
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Terminal {
    Success,
    ShortWindow,
    Failed,
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Quality {
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
pub(crate) struct IdentityWire {
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
    original_score: Number,
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
pub(crate) struct CountWire {
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
pub(crate) struct ResourceWire {
    name: String,
    #[serde(deserialize_with = "present_nullable")]
    value: Option<f64>,
    unit: String,
    #[serde(deserialize_with = "present_nullable")]
    source: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuestionCostWire {
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
pub(crate) struct RunCostWire {
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
pub(crate) struct SourceWire {
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
pub(crate) struct BackendWire {
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
pub(crate) struct RequestWire {
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
pub(crate) struct ClaimsWire {
    dataset: String,
    attribution: String,
    fts_vec_correctness: String,
    pure_engine: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AfterWire {
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

// Only the loaders above can construct these proof views. Their wire objects
// remain private; 08 consumes named readonly fields, never a raw JSON fallback.
pub(crate) struct VerifiedRunCapture {
    wire: RunWire,
    provenance: CaptureProvenance,
    questions: Vec<VerifiedQuestionCapture>,
}
pub(crate) struct CaptureProvenance {
    source_commit: String,
    binary_sha256: String,
    argv_sha256: String,
}
pub(crate) struct VerifiedQuestionCapture {
    wire: QuestionWire,
    slots: Vec<VerifiedSlotCapture>,
}
pub(crate) struct VerifiedSlotCapture {
    wire: SlotWire,
    original_score: NumericValue,
}
pub(crate) type RunTerminal = Terminal;
pub(crate) type RunQualityStatus = Quality;
pub(crate) type CaptureSourceIdentity = SourceWire;
pub(crate) type CaptureRequest = RequestWire;
pub(crate) type CaptureBackendIdentity = BackendWire;
pub(crate) type CaptureRunCost = RunCostWire;
pub(crate) type CaptureQuestionCost = QuestionCostWire;
pub(crate) type CaptureCounts = CountWire;
pub(crate) type CaptureResourceMeasurement = ResourceWire;
pub(crate) type CaptureClaims = ClaimsWire;
pub(crate) type CaptureAfterVerification = AfterWire;
pub(crate) type CaptureIdentity = IdentityWire;
pub(crate) type CaptureTextDigest = DigestWire;

impl VerifiedRunCapture {
    pub(crate) fn mode(&self) -> RunMode {
        self.wire.mode
    }
    pub(crate) fn terminal(&self) -> RunTerminal {
        self.wire.terminal
    }
    pub(crate) fn quality_status(&self) -> RunQualityStatus {
        self.wire.quality_status
    }
    pub(crate) fn failure_code(&self) -> Option<&str> {
        self.wire.failure_code.as_deref()
    }
    pub(crate) fn provenance(&self) -> &CaptureProvenance {
        &self.provenance
    }
    pub(crate) fn suite_sha256(&self) -> &str {
        &self.wire.suite_sha256
    }
    pub(crate) fn query_manifest_sha256(&self) -> &str {
        &self.wire.query_manifest_sha256
    }
    pub(crate) fn capture_labels_sha256(&self) -> &str {
        &self.wire.labels_sha256
    }
    pub(crate) fn label_policy_sha256(&self) -> &str {
        &self.wire.label_policy_sha256
    }
    pub(crate) fn source_identity(&self) -> &CaptureSourceIdentity {
        &self.wire.source_identity
    }
    pub(crate) fn request(&self) -> &CaptureRequest {
        &self.wire.request
    }
    pub(crate) fn backend_identity(&self) -> &CaptureBackendIdentity {
        &self.wire.backend_identity
    }
    pub(crate) fn expected_binding(&self) -> Option<&InputBinding> {
        self.wire.expected_binding.as_ref()
    }
    pub(crate) fn observed_before(&self) -> Option<&InputBinding> {
        self.wire.observed_before.as_ref()
    }
    pub(crate) fn observed_after(&self) -> Option<&InputBinding> {
        self.wire.observed_after.as_ref()
    }
    pub(crate) fn expected_binding_file_sha256(&self) -> Option<&str> {
        self.wire.expected_binding_file_sha256.as_deref()
    }
    pub(crate) fn after_verification(&self) -> Option<&CaptureAfterVerification> {
        self.wire.after_verification.as_ref()
    }
    pub(crate) fn fixed_input_manifest_sha256(&self) -> Option<&str> {
        self.wire.fixed_input_manifest_sha256.as_deref()
    }
    pub(crate) fn fixed_windows_file_sha256(&self) -> Option<&str> {
        self.wire.fixed_windows_file_sha256.as_deref()
    }
    pub(crate) fn questions(&self) -> &[VerifiedQuestionCapture] {
        &self.questions
    }
    pub(crate) fn cost(&self) -> &CaptureRunCost {
        &self.wire.cost
    }
    pub(crate) fn claims(&self) -> &CaptureClaims {
        &self.wire.claims
    }
}
impl CaptureProvenance {
    pub(crate) fn source_commit(&self) -> &str {
        &self.source_commit
    }
    pub(crate) fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }
    pub(crate) fn argv_sha256(&self) -> &str {
        &self.argv_sha256
    }
}
impl VerifiedQuestionCapture {
    pub(crate) fn qid(&self) -> &str {
        &self.wire.qid
    }
    pub(crate) fn query_sha256(&self) -> &str {
        &self.wire.query_sha256
    }
    pub(crate) fn requested_n(&self) -> usize {
        self.wire.requested_n
    }
    pub(crate) fn actual_n(&self) -> usize {
        self.wire.actual_n
    }
    pub(crate) fn pool_complete(&self) -> bool {
        self.wire.pool_complete
    }
    pub(crate) fn terminal(&self) -> RunTerminal {
        self.wire.terminal
    }
    pub(crate) fn full_requested_n_claim(&self) -> bool {
        self.wire.full_requested_n_claim
    }
    pub(crate) fn rerank_applied(&self) -> bool {
        self.wire.rerank_applied
    }
    pub(crate) fn ordered_pool_sha256(&self) -> Option<&str> {
        self.wire.ordered_pool_sha256.as_deref()
    }
    pub(crate) fn slots(&self) -> &[VerifiedSlotCapture] {
        &self.slots
    }
    pub(crate) fn pages_complete(&self) -> bool {
        true
    }
    pub(crate) fn page_count(&self) -> usize {
        self.wire.pages.len()
    }
    pub(crate) fn partial(&self) -> bool {
        self.wire.partial
    }
    pub(crate) fn timed_out(&self) -> bool {
        self.wire.timed_out
    }
    pub(crate) fn failure_code(&self) -> Option<&str> {
        self.wire.failure_code.as_deref()
    }
    pub(crate) fn lexical_statistics_status(&self) -> &str {
        &self.wire.lexical_statistics_status
    }
    pub(crate) fn lexical_statistics_sha256(&self) -> Option<&str> {
        self.wire.lexical_statistics_sha256.as_deref()
    }
    pub(crate) fn cost(&self) -> &CaptureQuestionCost {
        &self.wire.cost
    }
}
impl VerifiedSlotCapture {
    pub(crate) fn candidate_instance_key(&self) -> &str {
        &self.wire.candidate_instance_key
    }
    pub(crate) fn label_key(&self) -> &LabelKey {
        &self.wire.key
    }
    pub(crate) fn input_slot(&self) -> usize {
        self.wire.input_slot
    }
    pub(crate) fn retrieval_rank(&self) -> usize {
        self.wire.retrieval_rank
    }
    pub(crate) fn final_rank(&self) -> usize {
        self.wire.final_rank
    }
    pub(crate) fn identity(&self) -> Option<&CaptureIdentity> {
        self.wire.identity.as_ref()
    }
    pub(crate) fn message_id(&self) -> Option<i64> {
        self.wire.message_id
    }
    pub(crate) fn conversation_id(&self) -> Option<i64> {
        self.wire.conversation_id
    }
    pub(crate) fn candidate_text(&self) -> &CaptureTextDigest {
        &self.wire.candidate_text
    }
    pub(crate) fn sent_text(&self) -> Option<&CaptureTextDigest> {
        self.wire.sent_text.as_ref()
    }
    pub(crate) fn source_sha256(&self) -> Option<&str> {
        self.wire.source_sha256.as_deref()
    }
    pub(crate) fn original_score(&self) -> NumericValue {
        self.original_score
    }
    pub(crate) fn rerank_score(&self) -> Option<f64> {
        self.wire.rerank_score
    }
    pub(crate) fn capture_label(&self) -> SlotLabel {
        self.wire.label.resolved()
    }
}
impl CaptureIdentity {
    pub(crate) fn identity_host(&self) -> &str {
        &self.identity_host
    }
    pub(crate) fn agent_slug(&self) -> &str {
        &self.agent_slug
    }
    pub(crate) fn external_id(&self) -> &str {
        &self.external_id
    }
    pub(crate) fn message_idx(&self) -> i64 {
        self.message_idx
    }
    pub(crate) fn chunk_idx(&self) -> Option<i64> {
        self.chunk_idx
    }
}
impl CaptureTextDigest {
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }
    pub(crate) fn utf8_bytes(&self) -> u64 {
        self.utf8_bytes
    }
}
impl CaptureSourceIdentity {
    pub(crate) fn source_manifest_sha256(&self) -> Option<&str> {
        self.source_manifest_sha256.as_deref()
    }
    pub(crate) fn source_checked(&self) -> Option<u64> {
        self.source_checked
    }
    pub(crate) fn source_producer_receipt_sha256(&self) -> Option<&str> {
        self.source_producer_receipt_sha256.as_deref()
    }
    pub(crate) fn message_text_sha256(&self) -> Option<&str> {
        self.message_text_sha256.as_deref()
    }
    pub(crate) fn chunk_text_sha256(&self) -> Option<&str> {
        self.chunk_text_sha256.as_deref()
    }
    pub(crate) fn canonicalize_version(&self) -> Option<u64> {
        self.canonicalize_version
    }
    pub(crate) fn chunking_policy_version(&self) -> Option<u64> {
        self.chunking_policy_version
    }
    pub(crate) fn statistics_policy(&self) -> Option<&str> {
        self.statistics_policy.as_deref()
    }
}
impl CaptureRequest {
    pub(crate) fn search_mode(&self) -> Option<&str> {
        self.search_mode.as_deref()
    }
    pub(crate) fn vector_search_mode(&self) -> Option<&str> {
        self.vector_search_mode.as_deref()
    }
    pub(crate) fn rerank(&self) -> bool {
        self.rerank
    }
    pub(crate) fn n(&self) -> usize {
        self.n
    }
    pub(crate) fn page_k(&self) -> Option<usize> {
        self.page_k
    }
    pub(crate) fn request_profile(&self) -> &str {
        &self.request_profile
    }
    pub(crate) fn request_evidence_sha256(&self) -> Option<&str> {
        self.request_evidence_sha256.as_deref()
    }
    pub(crate) fn resolved_filters_sha256(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(&self.resolved_filters)?))
    }
}
impl CaptureBackendIdentity {
    pub(crate) fn provider(&self) -> Option<&str> {
        self.provider.as_deref()
    }
    pub(crate) fn actual_model(&self) -> Option<&str> {
        self.actual_model.as_deref()
    }
    pub(crate) fn model_revision(&self) -> Option<&str> {
        self.model_revision.as_deref()
    }
    pub(crate) fn endpoint_origin_sha256(&self) -> Option<&str> {
        self.endpoint_origin_sha256.as_deref()
    }
    pub(crate) fn server_template_policy(&self) -> Option<&str> {
        self.server_template_policy.as_deref()
    }
    pub(crate) fn document_assembly_policy(&self) -> Option<&str> {
        self.document_assembly_policy.as_deref()
    }
    pub(crate) fn client_submission_policy(&self) -> Option<&str> {
        self.client_submission_policy.as_deref()
    }
}
impl CaptureCounts {
    pub(crate) fn scope(&self) -> &str {
        &self.scope
    }
    pub(crate) fn http_attempts(&self) -> Option<u64> {
        self.http_attempts
    }
    pub(crate) fn http_response_observed(&self) -> Option<u64> {
        self.http_response_observed
    }
    pub(crate) fn delivery_unknown(&self) -> Option<u64> {
        self.delivery_unknown
    }
    pub(crate) fn model_executions(&self) -> Option<u64> {
        self.model_executions
    }
    pub(crate) fn basis(&self) -> &str {
        &self.basis
    }
}
impl CaptureQuestionCost {
    pub(crate) fn identity_before_ms(&self) -> f64 {
        self.identity_before_ms
    }
    pub(crate) fn identity_after_ms(&self) -> f64 {
        self.identity_after_ms
    }
    pub(crate) fn retrieval_ms(&self) -> f64 {
        self.retrieval_ms
    }
    pub(crate) fn rerank_client_ms(&self) -> Option<f64> {
        self.rerank_client_ms
    }
    pub(crate) fn model_execution_ms(&self) -> Option<f64> {
        self.model_execution_ms
    }
    pub(crate) fn paging_ms(&self) -> f64 {
        self.paging_ms
    }
    pub(crate) fn question_total_ms(&self) -> f64 {
        self.question_total_ms
    }
    pub(crate) fn http(&self) -> &[CaptureCounts] {
        &self.http
    }
    pub(crate) fn resource_measurements(&self) -> &[CaptureResourceMeasurement] {
        &self.resource_measurements
    }
}
impl CaptureRunCost {
    pub(crate) fn all_run_ms(&self) -> f64 {
        self.all_run_ms
    }
    pub(crate) fn identity_before_ms(&self) -> f64 {
        self.identity_before_ms
    }
    pub(crate) fn identity_after_ms(&self) -> f64 {
        self.identity_after_ms
    }
    pub(crate) fn sample_count(&self) -> u64 {
        self.sample_count
    }
    pub(crate) fn mean_question_ms(&self) -> Option<f64> {
        self.mean_question_ms
    }
    pub(crate) fn p50_question_ms(&self) -> Option<f64> {
        self.p50_question_ms
    }
    pub(crate) fn p95_question_ms(&self) -> Option<f64> {
        self.p95_question_ms
    }
    pub(crate) fn quantile_method(&self) -> &str {
        &self.quantile_method
    }
    pub(crate) fn counts(&self) -> &[CaptureCounts] {
        &self.counts
    }
}
impl CaptureResourceMeasurement {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn value(&self) -> Option<f64> {
        self.value
    }
    pub(crate) fn unit(&self) -> &str {
        &self.unit
    }
    pub(crate) fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }
}
impl CaptureClaims {
    pub(crate) fn dataset(&self) -> &str {
        &self.dataset
    }
    pub(crate) fn attribution(&self) -> &str {
        &self.attribution
    }
    pub(crate) fn fts_vec_correctness(&self) -> &str {
        &self.fts_vec_correctness
    }
    pub(crate) fn pure_engine(&self) -> bool {
        self.pure_engine
    }
}
impl CaptureAfterVerification {
    pub(crate) fn basis(&self) -> &str {
        &self.basis
    }
    pub(crate) fn inventory_digests(&self) -> &str {
        &self.inventory_digests
    }
    pub(crate) fn database_sha256(&self) -> &str {
        &self.database_sha256
    }
    pub(crate) fn source_manifest_sha256(&self) -> &str {
        &self.source_manifest_sha256
    }
    pub(crate) fn wal_bytes(&self) -> u64 {
        self.wal_bytes
    }
    pub(crate) fn generation_unchanged(&self) -> bool {
        self.generation_unchanged
    }
    pub(crate) fn policies_unchanged(&self) -> bool {
        self.policies_unchanged
    }
    pub(crate) fn shared_maintenance_lease_held(&self) -> bool {
        self.shared_maintenance_lease_held
    }
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
                let source = &self.source_identity;
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
                        && self.after_verification.is_none()
                        && self.request.request_evidence_sha256.is_some()
                        && self.request.resolved_filters.is_empty()
                        && source.source_manifest_sha256.is_none()
                        && source.source_checked.is_none()
                        && source.source_producer_receipt_sha256.is_none()
                        && source.message_text_sha256.is_none()
                        && source.chunk_text_sha256.is_none()
                        && source.canonicalize_version.is_none()
                        && source.chunking_policy_version.is_none()
                        && source.statistics_policy.is_none(),
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
                    slot.original_score.as_f64().is_some_and(f64::is_finite)
                        && slot.rerank_score.is_none_or(f64::is_finite),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedTraceWire {
    qid: String,
    query_sha256: String,
    ordered_pool_sha256: String,
    transport: FixedTransportWire,
    #[serde(deserialize_with = "present_nullable")]
    identity: Option<FixedCallWire>,
    terminal: Terminal,
    #[serde(deserialize_with = "present_nullable")]
    failure_code: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedCallWire {
    #[serde(deserialize_with = "present_nullable")]
    actual_provider: Option<crate::search::rerank::types::ProviderChoice>,
    #[serde(deserialize_with = "present_nullable")]
    actual_model: Option<String>,
    #[serde(rename = "serving_provider", deserialize_with = "present_nullable")]
    _serving_provider: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedTransportWire {
    requests: Vec<FixedHttpWire>,
    #[serde(deserialize_with = "present_nullable")]
    model_requests: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedHttpWire {
    method: String,
    path: String,
    state: String,
    #[serde(deserialize_with = "present_nullable")]
    query: Option<DigestWire>,
    #[serde(deserialize_with = "present_nullable")]
    documents: Option<Vec<FixedSubmittedWire>>,
    #[serde(deserialize_with = "present_nullable")]
    json_body_sha256: Option<String>,
    #[serde(deserialize_with = "present_nullable")]
    http_status: Option<u16>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedSubmittedWire {
    input_slot: usize,
    text: DigestWire,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedOrderedWire {
    qid: String,
    ordered_pool_sha256: String,
    canonical_utf8: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedRecoveryWire {
    suite_sha256: String,
    input_manifest_sha256: String,
    windows_file_sha256: String,
    qid: String,
    ordered_pool_sha256: String,
    slots: Vec<FixedRecoveredSlotWire>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedRecoveredSlotWire {
    input_slot: usize,
    retrieval_rank: usize,
    candidate_instance_key: String,
    typed_message_id: MessageId,
    scoreable: bool,
    fallback_reason: Value,
}

fn read_listed(root: &Path, output: &OutputWire, relative: &str) -> Result<WirePinned> {
    listed(output, relative)?;
    labels::read_subject(&root.join(relative))
}

fn validate_fixed_evidence(
    root: &Path,
    output: &OutputWire,
    question: &QuestionWire,
    body: &SubjectBody,
    pool: &PreparedPool,
    backend: &BackendWire,
) -> Result<()> {
    require(
        question.actual_n == 200
            && question.requested_n == 200
            && question.pages.is_empty()
            && question.window_evidence.is_none()
            && question.terminal == Terminal::Success
            && question.rerank_applied
            && question.lexical_statistics_status == "NOT_USED"
            && question.lexical_statistics_sha256.is_none(),
        "LABEL_RUN_INVALID",
    )?;
    let ordered = read_listed(
        root,
        output,
        &format!("fixed-ordered-pool-{}.json", question.qid),
    )?;
    let ordered: FixedOrderedWire =
        serde_json::from_value(ordered.value().clone()).context("LABEL_RUN_INVALID")?;
    require(
        ordered.qid == question.qid
            && Some(ordered.ordered_pool_sha256.as_str())
                == question.ordered_pool_sha256.as_deref()
            && ordered.canonical_utf8.as_bytes() == pool.ordered_bytes(),
        "LABEL_RUN_INVALID",
    )?;
    let recovery = read_listed(
        root,
        output,
        &format!("fixed-recovery-{}.json", question.qid),
    )?;
    // Diagnostic metadata is checked against the independently prepared pool;
    // it does not construct or replace that pool's original-byte proof.
    let checked: FixedRecoveryWire =
        serde_json::from_value(recovery.value().clone()).context("LABEL_RUN_INVALID")?;
    let expected = pool.recovery_evidence();
    require(recovery.value() == &expected, "LABEL_RUN_INVALID")?;
    require(
        is_hex(&checked.suite_sha256, 64)
            && is_hex(&checked.input_manifest_sha256, 64)
            && is_hex(&checked.windows_file_sha256, 64)
            && checked.qid == question.qid
            && Some(checked.ordered_pool_sha256.as_str())
                == question.ordered_pool_sha256.as_deref()
            && checked.slots.len() == 200,
        "LABEL_RUN_INVALID",
    )?;
    for (index, slot) in checked.slots.iter().enumerate() {
        require(
            slot.input_slot == index
                && slot.retrieval_rank == index + 1
                && is_hex(&slot.candidate_instance_key, 64)
                && slot.scoreable
                && !matches!(&slot.typed_message_id, MessageId::Text(id) if id.is_empty()),
            "LABEL_RUN_INVALID",
        )?;
        require(
            slot.fallback_reason == expected["slots"][index]["fallback_reason"],
            "LABEL_RUN_INVALID",
        )?;
    }
    let trace = read_listed(root, output, &format!("fixed-trace-{}.json", question.qid))?;
    let trace: FixedTraceWire =
        serde_json::from_value(trace.value().clone()).context("LABEL_RUN_INVALID")?;
    require(
        trace.qid == question.qid
            && trace.query_sha256 == question.query_sha256
            && Some(trace.ordered_pool_sha256.as_str()) == question.ordered_pool_sha256.as_deref()
            && trace.terminal == Terminal::Success
            && trace.failure_code.is_none(),
        "LABEL_RUN_INVALID",
    )?;
    if let Some(identity) = &trace.identity {
        if let Some(provider) = &backend.provider {
            require(
                identity
                    .actual_provider
                    .is_some_and(|p| p.to_string() == *provider),
                "LABEL_RUN_INVALID",
            )?;
        }
        if let Some(model) = &backend.actual_model {
            require(
                identity.actual_model.as_ref() == Some(model),
                "LABEL_RUN_INVALID",
            )?;
        }
    } else {
        require(
            backend.provider.is_none() && backend.actual_model.is_none(),
            "LABEL_RUN_INVALID",
        )?;
    }
    require(
        trace.transport.model_requests.is_none(),
        "LABEL_RUN_INVALID",
    )?;
    let posts: Vec<_> = trace
        .transport
        .requests
        .iter()
        .filter(|r| r.method == "POST")
        .collect();
    require(posts.len() == 1, "LABEL_RUN_INVALID")?;
    let post = posts[0];
    require(
        post.http_status.is_some_and(|s| (200..300).contains(&s))
            && post.state == "http-response-observed"
            && post
                .query
                .as_ref()
                .is_some_and(|q| q.matches(&body.query.utf8))
            && post
                .json_body_sha256
                .as_deref()
                .is_some_and(|s| is_hex(s, 64)),
        "LABEL_RUN_INVALID",
    )?;
    let submitted = post.documents.as_ref().context("LABEL_RUN_INVALID")?;
    require(submitted.len() == 200, "LABEL_RUN_INVALID")?;
    let mut by_input: Vec<_> = question.slots.iter().collect();
    by_input.sort_by_key(|s| s.input_slot);
    for (index, (sent, slot)) in submitted.iter().zip(by_input).enumerate() {
        require(
            sent.input_slot == index
                && slot.input_slot == index
                && sent.text.sha256 == slot.candidate_text.sha256
                && sent.text.utf8_bytes == slot.candidate_text.utf8_bytes
                && slot.sent_text.as_ref().is_some_and(|d| {
                    d.sha256 == sent.text.sha256 && d.utf8_bytes == sent.text.utf8_bytes
                })
                && slot.rerank_score.is_some(),
            "LABEL_RUN_INVALID",
        )?;
    }
    for request in &trace.transport.requests {
        require(
            !request.path.is_empty()
                && matches!(request.method.as_str(), "GET" | "POST")
                && request.state
                    == if request.http_status.is_some() {
                        "http-response-observed"
                    } else {
                        "attempted-delivery-unknown"
                    },
            "LABEL_RUN_INVALID",
        )?;
        if request.method == "GET" {
            require(
                request.query.is_none()
                    && request.documents.is_none()
                    && request.json_body_sha256.is_none(),
                "LABEL_RUN_INVALID",
            )?;
        }
    }
    let responses = trace
        .transport
        .requests
        .iter()
        .filter(|r| r.http_status.is_some())
        .count();
    require(question.cost.http.len() == 1, "LABEL_RUN_INVALID")?;
    let counts = &question.cost.http[0];
    require(
        counts.scope == "rerank-http-v1"
            && counts.basis == "observed-client"
            && counts.http_attempts == Some(trace.transport.requests.len() as u64)
            && counts.http_response_observed == Some(responses as u64)
            && counts.delivery_unknown == Some((trace.transport.requests.len() - responses) as u64)
            && counts.model_executions.is_none(),
        "LABEL_RUN_INVALID",
    )?;
    Ok(())
}

// This is the submission-only CPU slice of WindowEvidence::validate. It does
// not call the context/DB-dependent validation or construct a verified Run.
fn validate_full_submission(
    transport: &regression_trace::RequestTrace,
    query: &regression_trace::TextDigest,
    prepared: Option<&[regression_trace::TextDigest]>,
    retrieval_count: usize,
    rerank_requested: bool,
    applied: bool,
) -> Result<()> {
    require(transport.model_requests.is_none(), "LABEL_RUN_INVALID")?;
    require(
        applied == (rerank_requested && retrieval_count > 0),
        "LABEL_RUN_INVALID",
    )?;
    let posts: Vec<_> = transport
        .requests
        .iter()
        .filter(|r| r.method == "POST")
        .collect();
    require(
        posts.len() <= 1 && (!applied || posts.len() == 1),
        "LABEL_RUN_INVALID",
    )?;
    if !rerank_requested || retrieval_count == 0 {
        require(transport.requests.is_empty(), "LABEL_RUN_INVALID")?;
        return Ok(());
    }
    if let Some(post) = posts.first() {
        let submitted = post.documents.as_ref().context("LABEL_RUN_INVALID")?;
        let prepared = prepared.context("LABEL_RUN_INVALID")?;
        require(
            post.query.as_ref() == Some(query)
                && submitted.len() == retrieval_count
                && prepared.len() == submitted.len()
                && submitted
                    .iter()
                    .zip(prepared)
                    .enumerate()
                    .all(|(i, (doc, expected))| doc.input_slot == i && &doc.text == expected),
            "LABEL_RUN_INVALID",
        )?;
        require(
            post.state == "http-response-observed"
                && post.http_status.is_some_and(|s| (200..300).contains(&s))
                && post
                    .json_body_sha256
                    .as_deref()
                    .is_some_and(|s| is_hex(s, 64)),
            "LABEL_RUN_INVALID",
        )?;
    }
    for request in &transport.requests {
        require(
            request.state
                == if request.http_status.is_some() {
                    "http-response-observed"
                } else {
                    "attempted-delivery-unknown"
                },
            "LABEL_RUN_INVALID",
        )?;
    }
    Ok(())
}

fn validate_full_http_counts(
    transport: &regression_trace::RequestTrace,
    counts: &[CountWire],
) -> Result<()> {
    let mut matches = counts.iter().filter(|c| c.scope == "rerank-http-v1");
    let count = matches.next().context("LABEL_RUN_INVALID")?;
    require(matches.next().is_none(), "LABEL_RUN_INVALID")?;
    let responses = transport
        .requests
        .iter()
        .filter(|r| r.http_status.is_some())
        .count();
    let absent = transport.requests.is_empty();
    require(
        count.http_attempts == Some(transport.requests.len() as u64)
            && count.http_response_observed == Some(responses as u64)
            && count.delivery_unknown == Some((transport.requests.len() - responses) as u64)
            && count.model_executions == if absent { Some(0) } else { None }
            && count.basis
                == if absent {
                    "not-called"
                } else {
                    "observed-client"
                },
        "LABEL_RUN_INVALID",
    )
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
    // Reuse the closed transport DTO to reject omitted nullable fields and
    // extras before the existing RequestTrace decoder defaults Options.
    let _: FixedTransportWire =
        serde_json::from_value(value["transport"].clone()).context("LABEL_RUN_INVALID")?;
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
    validate_full_submission(
        &evidence.transport,
        &evidence.query,
        evidence.prepared_documents.as_deref(),
        evidence.retrieval.len(),
        evidence.rerank_requested,
        evidence.applied,
    )?;
    validate_full_http_counts(&evidence.transport, &question.cost.http)?;
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

    fn full_submission_fixture(
        count: usize,
    ) -> (
        regression_trace::RequestTrace,
        regression_trace::TextDigest,
        Vec<regression_trace::TextDigest>,
    ) {
        let query = "Synthetic full query";
        let documents: Vec<_> = (0..count)
            .map(|i| format!("Synthetic submitted document {i}"))
            .collect();
        let prepared = documents
            .iter()
            .map(|s| regression_trace::TextDigest::of(s))
            .collect();
        let mut trace = regression_trace::RequestTrace::default();
        let id = trace
            .begin(
                "POST",
                "/synthetic-rerank",
                Some(&json!({"query":query,"documents":documents})),
            )
            .unwrap();
        trace.response(id, 200).unwrap();
        (trace, regression_trace::TextDigest::of(query), prepared)
    }

    #[test]
    fn full_submission_requires_actual_post_query_documents_indices_and_response() {
        let (valid, query, prepared) = full_submission_fixture(7);
        // Seven real slots remain a legal SHORT sample; no requested-N padding.
        assert!(validate_full_submission(&valid, &query, Some(&prepared), 7, true, true).is_ok());
        for fault in [
            "no-post",
            "duplicate-post",
            "query",
            "digest",
            "input-slot",
            "short-docs",
            "non-2xx",
            "no-response",
            "unobserved-state",
            "model-count",
        ] {
            let mut trace = valid.clone();
            match fault {
                "no-post" => trace.requests.clear(),
                "duplicate-post" => trace.requests.push(trace.requests[0].clone()),
                "query" => {
                    trace.requests[0].query = Some(regression_trace::TextDigest::of(
                        "Synthetic different query",
                    ))
                }
                "digest" => {
                    trace.requests[0].documents.as_mut().unwrap()[0].text =
                        regression_trace::TextDigest::of("Synthetic changed document")
                }
                "input-slot" => trace.requests[0].documents.as_mut().unwrap()[1].input_slot = 0,
                "short-docs" => {
                    trace.requests[0].documents.as_mut().unwrap().pop();
                }
                "non-2xx" => trace.requests[0].http_status = Some(500),
                "no-response" => {
                    trace.requests[0].http_status = None;
                    trace.requests[0].state = "attempted-delivery-unknown".into();
                }
                "unobserved-state" => trace.requests[0].state = "attempted-delivery-unknown".into(),
                "model-count" => trace.model_requests = Some(0),
                _ => unreachable!(),
            }
            assert!(
                validate_full_submission(&trace, &query, Some(&prepared), 7, true, true).is_err(),
                "{fault}"
            );
        }
        assert!(validate_full_submission(&valid, &query, None, 7, true, true).is_err());
        assert!(
            validate_full_submission(&valid, &query, Some(&prepared[..6]), 7, true, true).is_err()
        );
    }

    #[test]
    fn full_off_and_empty_on_keep_zero_requests_and_unknown_transport_model_count() {
        let empty = regression_trace::RequestTrace::default();
        let query = regression_trace::TextDigest::of("Synthetic empty query");
        assert!(validate_full_submission(&empty, &query, None, 7, false, false).is_ok());
        assert!(validate_full_submission(&empty, &query, None, 0, true, false).is_ok());
        let mut requested = empty;
        requested.begin("GET", "/synthetic-models", None).unwrap();
        assert!(validate_full_submission(&requested, &query, None, 7, false, false).is_err());
        assert!(validate_full_submission(&requested, &query, None, 0, true, false).is_err());
        assert!(serde_json::from_value::<FixedTransportWire>(json!({"requests":[]})).is_err());
        assert!(
            serde_json::from_value::<FixedTransportWire>(
                json!({"requests":[],"model_requests":null})
            )
            .is_ok()
        );
    }

    #[test]
    fn full_http_costs_close_over_actual_attempt_response_and_unknown_counts() {
        let (trace, _query, _prepared) = full_submission_fixture(2);
        let good = json!({"scope":"rerank-http-v1","http_attempts":1,"http_response_observed":1,"delivery_unknown":0,"model_executions":null,"basis":"observed-client"});
        let counts = vec![serde_json::from_value::<CountWire>(good.clone()).unwrap()];
        assert!(validate_full_http_counts(&trace, &counts).is_ok());
        for field in [
            "http_attempts",
            "http_response_observed",
            "delivery_unknown",
            "model_executions",
        ] {
            let mut bad = good.clone();
            bad[field] = json!(42);
            assert!(
                validate_full_http_counts(&trace, &[serde_json::from_value(bad).unwrap()]).is_err()
            );
        }
        assert!(validate_full_http_counts(&trace, &[]).is_err());
        assert!(
            validate_full_http_counts(
                &trace,
                &[
                    serde_json::from_value(good.clone()).unwrap(),
                    serde_json::from_value(good).unwrap()
                ]
            )
            .is_err()
        );
        let zero: CountWire = serde_json::from_value(json!({"scope":"rerank-http-v1","http_attempts":0,"http_response_observed":0,"delivery_unknown":0,"model_executions":0,"basis":"not-called"})).unwrap();
        assert!(
            validate_full_http_counts(&regression_trace::RequestTrace::default(), &[zero]).is_ok()
        );
    }

    // Each test owns all files. No env/static/global counters or shared roots.
    #[cfg(unix)]
    fn synthetic_wire(bytes: &[u8]) -> Result<(tempfile::TempDir, WirePinned)> {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        let path = root.path().join("synthetic.json");
        fs::write(&path, bytes)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let wire = labels::read_subject(&path)?;
        Ok((root, wire))
    }

    #[test]
    #[cfg(unix)]
    fn run_scores_preserve_u64_negative_zero_and_exact_float_bits() {
        let bytes = br#"{"questions":[{"qid":"N01","slots":[{"input_slot":0,"original_score":18446744073709551615,"rerank_score":0.24473430858228182},{"input_slot":1,"original_score":-0.0,"rerank_score":null},{"input_slot":2,"original_score":0.24473430858228182,"rerank_score":-1.9799289335064246e+301}]}]}"#;
        let (root, wire) = synthetic_wire(bytes).unwrap();
        let value = restore_run_scores(&wire).unwrap();
        let slots = value["questions"][0]["slots"].as_array().unwrap();
        assert_eq!(slots[0]["original_score"].as_u64(), Some(u64::MAX));
        assert_eq!(
            slots[0]["rerank_score"].as_f64().unwrap().to_bits(),
            0x3fcf53742dc8f823
        );
        assert_eq!(
            slots[1]["original_score"].as_f64().unwrap().to_bits(),
            (-0.0f64).to_bits()
        );
        assert!(slots[1]["rerank_score"].is_null());
        assert_eq!(
            slots[2]["original_score"].as_f64().unwrap().to_bits(),
            0x3fcf53742dc8f823
        );
        assert_eq!(
            slots[2]["rerank_score"].as_f64().unwrap().to_bits(),
            0xfe7d909229733243
        );
        assert_eq!(wire.observed_file_sha256(), digest(bytes));
        assert_eq!(fs::read(root.path().join("synthetic.json")).unwrap(), bytes);
    }

    #[test]
    #[cfg(unix)]
    fn escaped_score_keys_field_order_and_false_nested_targets() {
        let bytes = br#"{"note":"fake \"original_score\":9","unknown":{"questions":[{"slots":[{"original_score":77,"rerank_score":88}]}]},"questions":[{"slots":[{"rerank_\u0073core":0.24473430858228182,"unused":{"original_score":99},"input_slot":0,"original_\u0073core":-0.0}],"qid":"N01"}]}"#;
        let (_root, wire) = synthetic_wire(bytes).unwrap();
        let value = restore_run_scores(&wire).unwrap();
        assert_eq!(
            value["questions"][0]["slots"][0]["original_score"]
                .as_f64()
                .unwrap()
                .to_bits(),
            (-0.0f64).to_bits()
        );
        assert_eq!(
            value["questions"][0]["slots"][0]["rerank_score"]
                .as_f64()
                .unwrap()
                .to_bits(),
            0x3fcf53742dc8f823
        );
        assert_eq!(value["unknown"], wire.value()["unknown"]);
        assert_eq!(
            value["questions"][0]["slots"][0]["unused"],
            wire.value()["questions"][0]["slots"][0]["unused"]
        );
        // The locator does not grant schema admission to the unknown fields.
        assert!(serde_json::from_value::<RunWire>(value).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn missing_nullable_scores_null_original_and_wrong_types_are_rejected() {
        for fields in [
            "\"original_score\":1.0",
            "\"rerank_score\":null",
            "\"original_score\":null,\"rerank_score\":null",
            "\"original_score\":\"1\",\"rerank_score\":null",
            "\"original_score\":1,\"rerank_score\":[]",
            "\"original_score\":1,\"rerank_score\":false",
        ] {
            let bytes = format!(
                "{{\"questions\":[{{\"qid\":\"N01\",\"slots\":[{{\"input_slot\":0,{fields}}}]}}]}}"
            );
            let (_root, wire) = synthetic_wire(bytes.as_bytes()).unwrap();
            assert!(restore_run_scores(&wire).is_err(), "{fields}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn strict_reader_rejects_duplicate_escaped_keys_and_nonfinite_before_spans() {
        for fields in [
            "\"original_score\":1,\"original_\\u0073core\":2,\"rerank_score\":null",
            "\"original_score\":NaN,\"rerank_score\":null",
            "\"original_score\":1e309,\"rerank_score\":null",
            "\"original_score\":1,\"rerank_score\":Infinity",
        ] {
            let bytes = format!(
                "{{\"questions\":[{{\"qid\":\"N01\",\"slots\":[{{\"input_slot\":0,{fields}}}]}}]}}"
            );
            assert!(synthetic_wire(bytes.as_bytes()).is_err(), "{fields}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn span_walk_obeys_strict_depth_and_does_not_apply_fixed_size_to_full() {
        for (depth, accepted) in [(126, true), (127, false)] {
            let bytes = format!(
                "{{\"questions\":[],\"unknown\":{}0{}}}",
                "[".repeat(depth),
                "]".repeat(depth)
            );
            if accepted {
                let (_root, wire) = synthetic_wire(bytes.as_bytes()).unwrap();
                assert!(restore_run_scores(&wire).is_ok());
            } else {
                assert!(synthetic_wire(bytes.as_bytes()).is_err());
            }
        }
        let slots: Vec<_> = (0..1801)
            .map(|i| {
                format!("{{\"input_slot\":{i},\"original_score\":-0.0,\"rerank_score\":null}}")
            })
            .collect();
        let bytes = format!(
            "{{\"questions\":[{{\"qid\":\"N01\",\"slots\":[{}]}}]}}",
            slots.join(",")
        );
        let (_root, wire) = synthetic_wire(bytes.as_bytes()).unwrap();
        let restored = restore_run_scores(&wire).unwrap();
        assert_eq!(
            restored["questions"][0]["slots"].as_array().unwrap().len(),
            1801
        );
        assert!(restored_number(b"18446744073709551616").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn fixed_question_copy_restores_only_score_leaves_and_preserves_file_sha() {
        let question = br#"{"qid":"N01","cost":{"question_total_ms":0.24473430858228182},"slots":[{"input_slot":0,"original_score":0.24473430858228182,"rerank_score":-0.0}]}"#;
        let mut run = b"{\"questions\":[".to_vec();
        run.extend(question);
        run.extend(b"]}");
        let (_run_root, run_wire) = synthetic_wire(&run).unwrap();
        let (_question_root, question_wire) = synthetic_wire(question).unwrap();
        let restored = restore_fixed_question_scores(&question_wire).unwrap();
        assert_eq!(
            restored,
            restore_run_scores(&run_wire).unwrap()["questions"][0]
        );
        assert_eq!(restored["cost"], question_wire.value()["cost"]);
        assert_eq!(question_wire.observed_file_sha256(), digest(question));
    }

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
