//! Read-only comparison over the label library's verified capture views.
//! This module does not read a raw execution Run or call a search/model backend.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Number, Value};

use super::blind::{self, RunMode, RunTerminal, VerifiedLabelRun, VerifiedRunCapture};
use super::fixed_encoding::NumericValue;
use super::labels::{self, FilePin, HumanLabel, LabelCoverage, SlotLabel};
use super::types::{LabelKey, OutputOptions, RunPaths};

const CONTRACT_SHA: &str = "d5436bd78207c73dfa799f34dbadb7cb005814896fe552274b9f131cac49ae41";
const QIDS: [&str; 9] = [
    "N01", "N02", "N03", "N04", "N05", "N06", "N07", "N08", "N12",
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LabelAction {
    #[default]
    Evaluate,
    ExportBlind,
    ImportBlind,
}

/// Request pins are not proofs. The engine always invokes the 07 loaders.
#[derive(Clone)]
pub(crate) struct CompareRequest {
    pub(crate) left: FilePin,
    pub(crate) right: FilePin,
    pub(crate) labels: FilePin,
    pub(crate) ancestors: Vec<FilePin>,
    pub(crate) capture_suite: PathBuf,
    pub(crate) capture_suite_sha256: String,
    pub(crate) output: OutputOptions,
    pub(crate) cutoffs: Vec<u32>,
    pub(crate) action: LabelAction,
    pub(crate) import: Option<ImportRequest>,
}

#[derive(Clone)]
pub(crate) struct ImportRequest {
    pub(crate) manifest: FilePin,
    pub(crate) answers: FilePin,
    pub(crate) version: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompareErrorCode(&'static str);
impl CompareErrorCode {
    pub(crate) fn as_str(self) -> &'static str {
        self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CompareExit {
    Zero,
    Two(CompareErrorCode),
}

#[derive(Clone, Debug, Serialize)]
struct ArtifactRef {
    relative_path: String,
    sha256: String,
}

#[derive(Serialize)]
pub(crate) struct CompareStdout {
    schema: &'static str,
    action: LabelAction,
    terminal: Terminal,
    quality_status: Quality,
    rc: u8,
    error_code: Option<&'static str>,
    report: ArtifactRef,
}

/// Constructed only after the private report has a verified physical file pin.
pub(crate) struct CompareOutcome {
    stdout: CompareStdout,
    exit: CompareExit,
}
impl CompareOutcome {
    pub(crate) fn stdout(&self) -> &CompareStdout {
        &self.stdout
    }
    pub(crate) fn exit(&self) -> CompareExit {
        self.exit
    }
    pub(crate) fn into_stdout_value(self) -> Result<Value> {
        Ok(serde_json::to_value(self.stdout)?)
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Terminal {
    Success,
    ShortWindow,
    Failed,
    IncompleteLabels,
    NonComparableMode,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Quality {
    Eligible,
    PartialCutoffs,
    Failed,
    IncompleteLabels,
    NotComparable,
    NotEvaluated,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Categories {
    direct: u64,
    partial: u64,
    none: u64,
    unsure: u64,
    unknown: u64,
}
#[derive(Clone, Debug, Serialize)]
struct Proportions {
    direct: f64,
    partial: f64,
    none: f64,
    unsure: f64,
    unknown: f64,
}
impl Categories {
    fn of(labels: &[SlotLabel]) -> Result<Self> {
        let mut result = Self::default();
        for label in labels {
            let count = match label {
                SlotLabel::Known(HumanLabel::Direct) => &mut result.direct,
                SlotLabel::Known(HumanLabel::Partial) => &mut result.partial,
                SlotLabel::Known(HumanLabel::None) => &mut result.none,
                SlotLabel::Known(HumanLabel::Unsure) => &mut result.unsure,
                SlotLabel::Unknown => &mut result.unknown,
            };
            *count = count.checked_add(1).context("COMPARE_INPUT_INVALID")?;
        }
        Ok(result)
    }
    fn add(&mut self, other: &Self) -> Result<()> {
        self.direct = self
            .direct
            .checked_add(other.direct)
            .context("COMPARE_INPUT_INVALID")?;
        self.partial = self
            .partial
            .checked_add(other.partial)
            .context("COMPARE_INPUT_INVALID")?;
        self.none = self
            .none
            .checked_add(other.none)
            .context("COMPARE_INPUT_INVALID")?;
        self.unsure = self
            .unsure
            .checked_add(other.unsure)
            .context("COMPARE_INPUT_INVALID")?;
        self.unknown = self
            .unknown
            .checked_add(other.unknown)
            .context("COMPARE_INPUT_INVALID")?;
        Ok(())
    }
    fn proportions(&self, denominator: u64) -> Result<Proportions> {
        ensure!(denominator > 0, "COMPARE_INPUT_INVALID");
        let d = denominator as f64;
        Ok(Proportions {
            direct: self.direct as f64 / d,
            partial: self.partial as f64 / d,
            none: self.none as f64 / d,
            unsure: self.unsure as f64 / d,
            unknown: self.unknown as f64 / d,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
struct Stats {
    known_samples: usize,
    total_questions: usize,
    mean: Option<f64>,
    p50: Option<f64>,
    p95: Option<f64>,
    quantile_method: &'static str,
}

fn statistics(values: &[Option<f64>]) -> Result<Stats> {
    ensure!(values.len() == 9, "COMPARE_INPUT_INVALID");
    let mut known: Vec<_> = values.iter().copied().flatten().collect();
    ensure!(known.iter().all(|x| x.is_finite()), "COMPARE_INPUT_INVALID");
    let mut result = Stats {
        known_samples: known.len(),
        total_questions: 9,
        mean: None,
        p50: None,
        p95: None,
        quantile_method: "nearest-rank",
    };
    if known.len() == 9 {
        let sum = known.iter().try_fold(0.0, |sum, x| {
            let next = sum + x;
            ensure!(next.is_finite(), "COMPARE_INPUT_INVALID");
            Ok::<_, anyhow::Error>(next)
        })?;
        known.sort_by(f64::total_cmp);
        result.mean = Some(sum / 9.0);
        result.p50 = Some(known[4]);
        result.p95 = Some(known[8]);
    }
    Ok(result)
}

fn numeric(value: NumericValue) -> Result<Number> {
    match value {
        NumericValue::I64(x) => Ok(Number::from(x)),
        NumericValue::U64(x) => Ok(Number::from(x)),
        NumericValue::F64(x) => Number::from_f64(x).context("COMPARE_INPUT_INVALID"),
    }
}

fn delta(left: Option<u64>, right: Option<u64>) -> Result<Option<i64>> {
    match (left, right) {
        (Some(l), Some(r)) => Ok(Some(
            i64::try_from(i128::from(r) - i128::from(l)).context("COMPARE_INPUT_INVALID")?,
        )),
        _ => Ok(None),
    }
}

fn recall_proxy(found: usize, union_direct: usize, fully_labelled: bool) -> Option<f64> {
    (fully_labelled && union_direct > 0).then(|| found as f64 / union_direct as f64)
}

#[derive(Clone, Debug, Serialize)]
struct Pin {
    expected_sha256: String,
    observed_sha256: Option<String>,
}
impl Pin {
    fn requested(pin: &FilePin) -> Self {
        Self {
            expected_sha256: pin.expected_sha256().into(),
            observed_sha256: None,
        }
    }
}
#[derive(Serialize)]
struct InputPins {
    left: Pin,
    right: Pin,
    active_labels: Pin,
    capture_suite: Pin,
    ancestors: Vec<Pin>,
    contract_sha256: &'static str,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Stage {
    CaptureSuite,
    RunLoad,
    LabelChain,
    BodyBinding,
    Mode,
    Source,
    FixedPool,
    LabelCoverage,
    Metrics,
    Write,
}
#[derive(Serialize)]
struct ReportError {
    code: &'static str,
    stage: Stage,
}
#[derive(Default, Serialize)]
struct AnnotationArtifacts {
    bundle: Option<ArtifactRef>,
    manifest: Option<ArtifactRef>,
    labels: Option<ArtifactRef>,
    receipt: Option<ArtifactRef>,
}
#[derive(Serialize)]
struct Diagnostics {
    unknown_union_keys: usize,
    unsupported_qids: Vec<String>,
    note_code: Option<&'static str>,
}
#[derive(Serialize)]
struct Claims {
    dataset: &'static str,
    attribution: &'static str,
    fts_vec_correctness: &'static str,
    pure_engine: bool,
    quality_improvement: &'static str,
    all_run_timing_scope: &'static str,
    process_wall_status: &'static str,
}
#[derive(Serialize)]
struct ComparisonReport {
    schema: &'static str,
    action: LabelAction,
    terminal: Terminal,
    quality_status: Quality,
    rc: u8,
    error: Option<ReportError>,
    success_summary: Option<SuccessSummary>,
    input_pins: InputPins,
    questions: Vec<QuestionReport>,
    cost: Option<CostComparison>,
    changed_inputs: Vec<ScalarChange>,
    annotation_artifacts: AnnotationArtifacts,
    diagnostics: Option<Diagnostics>,
    claims: Claims,
    aggregate_metrics: Option<AggregateMetrics>,
}
impl ComparisonReport {
    fn pending(request: &CompareRequest) -> Self {
        Self {
            schema: "cass.regression-comparison-report.v1",
            action: request.action,
            terminal: Terminal::Failed,
            quality_status: Quality::Failed,
            rc: 2,
            error: None,
            success_summary: None,
            input_pins: InputPins {
                left: Pin::requested(&request.left),
                right: Pin::requested(&request.right),
                active_labels: Pin::requested(&request.labels),
                capture_suite: Pin {
                    expected_sha256: request.capture_suite_sha256.clone(),
                    observed_sha256: None,
                },
                ancestors: request.ancestors.iter().map(Pin::requested).collect(),
                contract_sha256: CONTRACT_SHA,
            },
            questions: vec![],
            cost: None,
            changed_inputs: vec![],
            annotation_artifacts: AnnotationArtifacts::default(),
            diagnostics: None,
            claims: Claims {
                dataset: "development-regression-9-small-sample",
                attribution: "observed-comparison",
                fts_vec_correctness: "NOT_VERIFIED",
                pure_engine: false,
                quality_improvement: "NOT_ASSERTED",
                all_run_timing_scope: "recorded-runner-entry-through-report-construction",
                process_wall_status: "NOT_VERIFIED",
            },
            aggregate_metrics: None,
        }
    }
    fn fail(&mut self, failure: StepFailure) {
        self.terminal = failure.terminal;
        self.quality_status = match failure.terminal {
            Terminal::IncompleteLabels => Quality::IncompleteLabels,
            Terminal::NonComparableMode => Quality::NotComparable,
            _ => Quality::Failed,
        };
        self.rc = 2;
        self.error = Some(ReportError {
            code: failure.code.as_str(),
            stage: failure.stage,
        });
        self.success_summary = None;
        if let Some(diagnostics) = &mut self.diagnostics {
            diagnostics.note_code = Some(failure.code.as_str());
        }
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CutoffQuality {
    Eligible,
    WindowTooShort,
    IncompleteLabels,
}
#[derive(Serialize)]
struct Cutoff {
    cutoff: u32,
    size_supported: bool,
    quality_status: CutoffQuality,
    counts: Option<Categories>,
    proportions: Option<Proportions>,
    has_direct: Option<bool>,
    denominator: Option<u64>,
}
#[derive(Serialize)]
struct RecordedCount {
    scope: String,
    http_attempts: Option<u64>,
    http_response_observed: Option<u64>,
    delivery_unknown: Option<u64>,
    model_executions: Option<u64>,
    basis: String,
}
#[derive(Serialize)]
struct ResourceMeasurement {
    name: String,
    value: Option<f64>,
    unit: String,
    source: Option<String>,
}
#[derive(Serialize)]
struct QuestionCost {
    identity_before_ms: f64,
    identity_after_ms: f64,
    retrieval_ms: f64,
    rerank_client_ms: Option<f64>,
    model_execution_ms: Option<f64>,
    paging_ms: f64,
    question_total_ms: f64,
    http: Vec<RecordedCount>,
    resource_measurements: Vec<ResourceMeasurement>,
}
#[derive(Serialize)]
struct SideQuestion {
    requested_n: usize,
    actual_n: usize,
    pool_has_direct: bool,
    pool_label_counts: Categories,
    pool_distinct_direct_keys: usize,
    observed_union_recall_proxy: Option<f64>,
    cutoffs: Vec<Cutoff>,
    recorded_cost: QuestionCost,
}
#[derive(Clone, Debug, Serialize)]
struct RankPoint {
    input_slot: usize,
    retrieval_rank: usize,
    final_rank: usize,
    original_score: Number,
    rerank_score: Option<f64>,
}
#[derive(Serialize)]
struct RankChange {
    candidate_instance_key: String,
    state: &'static str,
    left: Option<RankPoint>,
    right: Option<RankPoint>,
    retrieval_rank_delta: Option<i64>,
    final_rank_delta: Option<i64>,
}
#[derive(Serialize)]
struct QuestionReport {
    qid: String,
    query_sha256: String,
    observed_union_direct_key_denominator: usize,
    left: SideQuestion,
    right: SideQuestion,
    rank_changes: Vec<RankChange>,
    question_total_delta_ms: f64,
}
#[derive(Serialize)]
struct CostComponent {
    name: &'static str,
    statistics: Stats,
}
#[derive(Serialize)]
struct SideCost {
    recorded_all_run_ms: f64,
    recorded_identity_before_ms: f64,
    recorded_identity_after_ms: f64,
    process_wall_ms: Option<f64>,
    process_receipt: Option<Pin>,
    components: Vec<CostComponent>,
    recorded_counts: Vec<RecordedCount>,
}
#[derive(Serialize)]
struct CountDelta {
    scope: String,
    http_attempts: Option<i64>,
    http_response_observed: Option<i64>,
    delivery_unknown: Option<i64>,
    model_executions: Option<i64>,
}
#[derive(Serialize)]
struct CostComparison {
    left: SideCost,
    right: SideCost,
    recorded_all_run_delta_ms: f64,
    process_wall_delta_ms: Option<f64>,
    count_deltas: Vec<CountDelta>,
}
#[derive(Serialize)]
struct QuestionCoverage {
    has_direct_count: usize,
    eligible_question_denominator: usize,
    qids_with_direct: Vec<String>,
}
#[derive(Serialize)]
struct CutoffAggregateSide {
    has_direct_question_count: usize,
    question_denominator: usize,
    label_counts: Categories,
    slot_denominator: u64,
    label_proportions: Option<Proportions>,
}
#[derive(Serialize)]
struct CutoffAggregate {
    cutoff: u32,
    supported_qids: Vec<String>,
    unsupported_qids: Vec<String>,
    supported_count: usize,
    total_questions: usize,
    left: CutoffAggregateSide,
    right: CutoffAggregateSide,
}
#[derive(Serialize)]
struct AggregateMetrics {
    pool_has_direct_left: QuestionCoverage,
    pool_has_direct_right: QuestionCoverage,
    cutoffs: Vec<CutoffAggregate>,
}
#[derive(Serialize)]
struct CutoffSupport {
    supported_qids: Vec<String>,
    unsupported_qids: Vec<String>,
    supported_count: usize,
    total_questions: usize,
    quality_status: &'static str,
}
#[derive(Serialize)]
struct SuccessSummary {
    terminal: Terminal,
    quality_status: Quality,
    rc: u8,
    supported_cutoffs: BTreeMap<String, bool>,
    cutoff_support: BTreeMap<String, CutoffSupport>,
    overall_complete_quality: bool,
    union_label_keys: usize,
    attribution: &'static str,
}
#[derive(Clone, PartialEq, Serialize)]
#[serde(untagged)]
enum Scalar {
    Text(String),
    Number(Number),
    Bool(bool),
    Null,
}
#[derive(Serialize)]
struct ScalarChange {
    field: &'static str,
    left: Scalar,
    right: Scalar,
}

struct StepFailure {
    code: CompareErrorCode,
    stage: Stage,
    terminal: Terminal,
}
type Steps<T> = std::result::Result<T, StepFailure>;
fn step<T>(result: Result<T>, stage: Stage) -> Steps<T> {
    result.map_err(|error| {
        let code = error_code(&error);
        let stage = if matches!(
            code.as_str(),
            "BLIND_OUTPUT_WRITE_FAILED" | "BLIND_RANDOM_UNAVAILABLE"
        ) {
            Stage::Write
        } else {
            stage
        };
        StepFailure {
            code,
            stage,
            terminal: Terminal::Failed,
        }
    })
}
fn denied(code: &'static str, stage: Stage, terminal: Terminal) -> StepFailure {
    StepFailure {
        code: CompareErrorCode(code),
        stage,
        terminal,
    }
}

/// Only static named causes are emitted. Raw error text never enters artifacts.
pub(crate) fn error_code(error: &anyhow::Error) -> CompareErrorCode {
    const CODES: &[&str] = &[
        "COMPARE_INPUT_INVALID",
        "INCOMPLETE_LABELS",
        "NON_COMPARABLE_MODE",
        "NON_COMPARABLE_SOURCE",
        "NON_COMPARABLE_INPUT",
        "REQUEST_PROFILE_INVALID",
        "LABEL_SCHEMA_INVALID",
        "LABEL_POLICY_MISMATCH",
        "LABEL_SUITE_MISMATCH",
        "LABEL_KEY_CONFLICT",
        "LABEL_CAPTURE_MISMATCH",
        "LABEL_PARENT_MISMATCH",
        "LABEL_PARENT_CONTENT_CHANGED",
        "LABEL_VERSION_INVALID",
        "LABEL_RUN_INVALID",
        "LABEL_SUBJECT_INVALID",
        "BLIND_BUNDLE_INVALID",
        "BLIND_MANIFEST_INVALID",
        "BLIND_ANSWERS_INVALID",
        "BLIND_BINDING_MISMATCH",
        "BLIND_RANDOM_UNAVAILABLE",
        "BLIND_OUTPUT_WRITE_FAILED",
        "TRACE_MISSING_PAGES",
        "TRACE_PAGE_SEQUENCE_MISMATCH",
        "TRACE_SUBMITTED_TEXT_MISMATCH",
        "TRACE_SCORING_RESPONSE_UNPROVEN",
        "TRACE_SCORING_REQUEST_COUNT_MISMATCH",
        "TRACE_MODEL_EXECUTION_UNPROVEN",
        "TRACE_WINDOW_SLOT_MAPPING_MISMATCH",
        "TRACE_WINDOW_BINDING_MISMATCH",
        "regression_run_root_not_private",
        "regression_run_root_not_directory",
        "regression_run_root_not_empty",
        "regression_output_inside_repository",
        "regression_path_symlink",
        "regression_platform_not_verified",
        "REGRESSION_INPUT_ENCODING_FAILED",
    ];
    for cause in error.chain() {
        let text = cause.to_string();
        if let Some(code) = CODES.iter().copied().find(|code| text == *code) {
            return CompareErrorCode(code);
        }
    }
    if let Some(code) = super::fixed::named_error_code(error) {
        return CompareErrorCode(code);
    }
    let code = super::input::error_code(error);
    if code != "REGRESSION_INPUT_FAILED" {
        return CompareErrorCode(code);
    }
    CompareErrorCode("COMPARE_INPUT_INVALID")
}

impl CompareRequest {
    fn validate(&self) -> Result<()> {
        super::input::validate_cutoffs(&self.cutoffs)?;
        ensure!(
            labels::is_hex(&self.capture_suite_sha256, 64),
            "REQUEST_PROFILE_INVALID"
        );
        match (self.action, &self.import) {
            (LabelAction::ImportBlind, Some(import)) => ensure!(
                import.version.chars().any(|c| !c.is_whitespace()),
                "LABEL_VERSION_INVALID"
            ),
            (LabelAction::ImportBlind, None) => anyhow::bail!("REQUEST_PROFILE_INVALID"),
            (_, None) => {}
            (_, Some(_)) => anyhow::bail!("REQUEST_PROFILE_INVALID"),
        }
        let mut hashes = HashSet::new();
        let mut paths = HashSet::new();
        for pin in std::iter::once(&self.labels).chain(&self.ancestors) {
            ensure!(
                hashes.insert(pin.expected_sha256()) && paths.insert(pin.path()),
                "LABEL_PARENT_MISMATCH"
            );
        }
        Ok(())
    }
    fn protected(&self) -> Vec<PathBuf> {
        let mut paths = vec![
            self.left.path().to_path_buf(),
            self.right.path().to_path_buf(),
            self.labels.path().to_path_buf(),
            self.capture_suite.clone(),
        ];
        paths.extend(self.ancestors.iter().map(|p| p.path().to_path_buf()));
        if let Some(import) = &self.import {
            paths.extend([
                import.manifest.path().to_path_buf(),
                import.answers.path().to_path_buf(),
            ]);
        }
        paths
    }
}

/// Complete three-action engine. B's argv adapter supplies this request once.
pub(crate) fn run(request: &CompareRequest) -> Result<CompareOutcome> {
    request.validate()?;
    let paths = super::input::create_run_paths(&request.output, &request.protected())?;
    let mut report = ComparisonReport::pending(request);
    if let Err(failure) = perform(request, &paths, &mut report) {
        report.fail(failure);
    }
    // The library's annotation fresh-root check must run before these writes.
    super::off::write_private(
        &paths.run_root,
        "compare-argv.json",
        &serde_json::to_value(std::env::args().collect::<Vec<_>>())?,
    )?;
    let value = serde_json::to_value(&report)?;
    let reference = super::off::write_private(&paths.run_root, "comparison-report.json", &value)?;
    let expected = reference["sha256"]
        .as_str()
        .context("BLIND_OUTPUT_WRITE_FAILED")?;
    let pin = FilePin::new(
        paths.run_root.join("comparison-report.json"),
        expected.into(),
    )?;
    let observed = labels::read_pin(&pin)?;
    let artifact = ArtifactRef {
        relative_path: "comparison-report.json".into(),
        sha256: observed.observed_file_sha256().into(),
    };
    let exit = match &report.error {
        Some(error) => CompareExit::Two(CompareErrorCode(error.code)),
        None => CompareExit::Zero,
    };
    ensure!(
        report.rc
            == if matches!(exit, CompareExit::Zero) {
                0
            } else {
                2
            },
        "COMPARE_INPUT_INVALID"
    );
    Ok(CompareOutcome {
        stdout: CompareStdout {
            schema: "cass.regression-comparison-summary.v1",
            action: report.action,
            terminal: report.terminal,
            quality_status: report.quality_status,
            rc: report.rc,
            error_code: report.error.as_ref().map(|e| e.code),
            report: artifact,
        },
        exit,
    })
}

fn artifact(paths: &RunPaths, pin: &FilePin) -> Result<ArtifactRef> {
    let relative = pin
        .path()
        .strip_prefix(&paths.run_root)?
        .to_str()
        .context("BLIND_OUTPUT_WRITE_FAILED")?;
    super::input::safe_relative(relative)?;
    let actual = labels::read_pin(pin)?;
    Ok(ArtifactRef {
        relative_path: relative.into(),
        sha256: actual.observed_file_sha256().into(),
    })
}

fn perform(request: &CompareRequest, paths: &RunPaths, report: &mut ComparisonReport) -> Steps<()> {
    let available: Vec<_> = std::iter::once(request.labels.clone())
        .chain(request.ancestors.iter().cloned())
        .collect();
    let base = step(
        labels::load_capture_base(
            &request.capture_suite,
            &request.capture_suite_sha256,
            &available,
            &request.output,
        ),
        Stage::CaptureSuite,
    )?;
    report.input_pins.capture_suite.observed_sha256 = Some(base.inputs().suite_sha256.clone());
    let left = step(
        blind::load_run_subjects_with_capture(&request.left, &base),
        Stage::RunLoad,
    )?;
    report.input_pins.left.observed_sha256 = Some(left.observed_file_sha256().into());
    let right = step(
        blind::load_run_subjects_with_capture(&request.right, &base),
        Stage::RunLoad,
    )?;
    report.input_pins.right.observed_sha256 = Some(right.observed_file_sha256().into());
    let active = step(
        labels::load_label_set(&request.labels, &request.ancestors, &base, &left, &right),
        Stage::LabelChain,
    )?;
    report.input_pins.active_labels.observed_sha256 = Some(active.observed_file_sha256().into());
    for pin in &mut report.input_pins.ancestors {
        if active
            .verified_ancestor_sha256s()
            .contains(&pin.expected_sha256)
        {
            pin.observed_sha256 = Some(pin.expected_sha256.clone());
        }
    }
    let coverage = step(
        labels::cover_slots(&left, &right, &active),
        Stage::LabelCoverage,
    )?;
    report.diagnostics = Some(Diagnostics {
        unknown_union_keys: coverage.unknown_keys().len(),
        unsupported_qids: vec![],
        note_code: None,
    });
    report.changed_inputs = step(
        changed_inputs(left.capture(), right.capture()),
        Stage::Metrics,
    )?;
    match request.action {
        LabelAction::Evaluate => evaluate(request, &left, &right, &coverage, report)?,
        LabelAction::ExportBlind => {
            let result = step(
                blind::export_blind(&left, &right, &active, paths),
                Stage::BodyBinding,
            )?;
            report.annotation_artifacts.bundle =
                Some(step(artifact(paths, result.bundle()), Stage::Write)?);
            report.annotation_artifacts.manifest =
                Some(step(artifact(paths, result.manifest()), Stage::Write)?);
            annotation_success(report, left.capture(), right.capture());
        }
        LabelAction::ImportBlind => {
            let input = request.import.as_ref().ok_or_else(|| {
                denied(
                    "REQUEST_PROFILE_INVALID",
                    Stage::BodyBinding,
                    Terminal::Failed,
                )
            })?;
            let result = step(
                blind::import_blind(
                    &left,
                    &right,
                    &active,
                    &base,
                    &input.manifest,
                    &input.answers,
                    &input.version,
                    paths,
                ),
                Stage::BodyBinding,
            )?;
            let ancestors: Vec<_> = std::iter::once(request.labels.clone())
                .chain(request.ancestors.iter().cloned())
                .collect();
            let updated = step(
                labels::load_label_set(result.labels(), &ancestors, &base, &left, &right),
                Stage::LabelChain,
            )?;
            let coverage = step(
                labels::cover_slots(&left, &right, &updated),
                Stage::LabelCoverage,
            )?;
            if !coverage.unknown_keys().is_empty() {
                return Err(denied(
                    "INCOMPLETE_LABELS",
                    Stage::LabelCoverage,
                    Terminal::IncompleteLabels,
                ));
            }
            report.annotation_artifacts.labels =
                Some(step(artifact(paths, result.labels()), Stage::Write)?);
            report.annotation_artifacts.receipt =
                Some(step(artifact(paths, result.receipt()), Stage::Write)?);
            report.diagnostics = Some(Diagnostics {
                unknown_union_keys: 0,
                unsupported_qids: vec![],
                note_code: None,
            });
            annotation_success(report, left.capture(), right.capture());
        }
    }
    Ok(())
}

fn annotation_success(
    report: &mut ComparisonReport,
    left: &VerifiedRunCapture,
    right: &VerifiedRunCapture,
) {
    report.terminal = execution_terminal(left, right);
    report.quality_status = Quality::NotEvaluated;
    report.rc = 0;
    report.error = None;
    report.success_summary = None;
}
fn execution_terminal(left: &VerifiedRunCapture, right: &VerifiedRunCapture) -> Terminal {
    if left.terminal() == RunTerminal::ShortWindow || right.terminal() == RunTerminal::ShortWindow {
        Terminal::ShortWindow
    } else {
        Terminal::Success
    }
}

fn source_equal(left: &VerifiedRunCapture, right: &VerifiedRunCapture) -> bool {
    let l = left.source_identity();
    let r = right.source_identity();
    l.source_manifest_sha256() == r.source_manifest_sha256()
        && l.message_text_sha256() == r.message_text_sha256()
        && l.chunk_text_sha256() == r.chunk_text_sha256()
        && l.canonicalize_version() == r.canonicalize_version()
        && l.chunking_policy_version() == r.chunking_policy_version()
        && l.statistics_policy() == r.statistics_policy()
}

fn evaluate(
    request: &CompareRequest,
    left: &VerifiedLabelRun,
    right: &VerifiedLabelRun,
    coverage: &LabelCoverage,
    report: &mut ComparisonReport,
) -> Steps<()> {
    let l = left.capture();
    let r = right.capture();
    if l.mode() != r.mode() {
        return Err(denied(
            "NON_COMPARABLE_MODE",
            Stage::Mode,
            Terminal::NonComparableMode,
        ));
    }
    match l.mode() {
        RunMode::FullSearch if !source_equal(l, r) => {
            return Err(denied(
                "NON_COMPARABLE_SOURCE",
                Stage::Source,
                Terminal::Failed,
            ));
        }
        RunMode::FixedCandidate => {
            if l.fixed_input_manifest_sha256() != r.fixed_input_manifest_sha256()
                || l.fixed_windows_file_sha256() != r.fixed_windows_file_sha256()
                || l.questions()
                    .iter()
                    .zip(r.questions())
                    .any(|(a, b)| a.ordered_pool_sha256() != b.ordered_pool_sha256())
            {
                return Err(denied(
                    "NON_COMPARABLE_INPUT",
                    Stage::FixedPool,
                    Terminal::Failed,
                ));
            }
        }
        _ => {}
    }
    let complete = coverage.unknown_keys().is_empty();
    let questions = step(
        question_reports(l, r, coverage, &request.cutoffs, complete),
        Stage::Metrics,
    )?;
    let aggregate = step(
        aggregate_metrics(&questions, &request.cutoffs),
        Stage::Metrics,
    )?;
    let cost = step(comparison_cost(l, r), Stage::Metrics)?;
    let all_supported = aggregate.cutoffs.iter().all(|c| c.supported_count == 9);
    let unsupported: HashSet<_> = aggregate
        .cutoffs
        .iter()
        .flat_map(|c| c.unsupported_qids.iter().cloned())
        .collect();
    report.diagnostics = Some(Diagnostics {
        unknown_union_keys: coverage.unknown_keys().len(),
        unsupported_qids: QIDS
            .iter()
            .filter(|q| unsupported.contains(**q))
            .map(|q| (*q).into())
            .collect(),
        note_code: (!complete).then_some("INCOMPLETE_LABELS"),
    });
    report.questions = questions;
    report.cost = Some(cost);
    if complete {
        report.terminal = execution_terminal(l, r);
        report.quality_status = if all_supported {
            Quality::Eligible
        } else {
            Quality::PartialCutoffs
        };
        let cutoff_support = aggregate
            .cutoffs
            .iter()
            .map(|c| {
                (
                    c.cutoff.to_string(),
                    CutoffSupport {
                        supported_qids: c.supported_qids.clone(),
                        unsupported_qids: c.unsupported_qids.clone(),
                        supported_count: c.supported_count,
                        total_questions: 9,
                        quality_status: if c.supported_count == 9 {
                            "ELIGIBLE"
                        } else {
                            "WINDOW_TOO_SHORT"
                        },
                    },
                )
            })
            .collect();
        let keys: HashSet<_> = l
            .questions()
            .iter()
            .chain(r.questions())
            .flat_map(|q| q.slots())
            .map(|s| s.label_key())
            .collect();
        report.success_summary = Some(SuccessSummary {
            terminal: report.terminal,
            quality_status: report.quality_status,
            rc: 0,
            supported_cutoffs: aggregate
                .cutoffs
                .iter()
                .map(|c| (c.cutoff.to_string(), c.supported_count == 9))
                .collect(),
            cutoff_support,
            overall_complete_quality: all_supported,
            union_label_keys: keys.len(),
            attribution: "observed-comparison",
        });
        report.rc = 0;
        report.error = None;
    }
    report.aggregate_metrics = Some(aggregate);
    if !complete {
        return Err(denied(
            "INCOMPLETE_LABELS",
            Stage::LabelCoverage,
            Terminal::IncompleteLabels,
        ));
    }
    Ok(())
}

fn finite_delta(left: f64, right: f64) -> Result<f64> {
    let result = right - left;
    ensure!(result.is_finite(), "COMPARE_INPUT_INVALID");
    Ok(result)
}

fn direct_keys<'a>(
    slots: &'a [blind::VerifiedSlotCapture],
    overlay: &[SlotLabel],
) -> Result<HashSet<&'a LabelKey>> {
    ensure!(slots.len() == overlay.len(), "COMPARE_INPUT_INVALID");
    Ok(slots
        .iter()
        .zip(overlay)
        .filter(|(_, label)| **label == SlotLabel::Known(HumanLabel::Direct))
        .map(|(slot, _)| slot.label_key())
        .collect())
}

fn question_reports(
    left: &VerifiedRunCapture,
    right: &VerifiedRunCapture,
    coverage: &LabelCoverage,
    cutoffs: &[u32],
    complete: bool,
) -> Result<Vec<QuestionReport>> {
    ensure!(
        left.questions().len() == 9 && right.questions().len() == 9,
        "COMPARE_INPUT_INVALID"
    );
    let mut lo = 0usize;
    let mut ro = 0usize;
    let mut result = Vec::with_capacity(9);
    for ((l, r), qid) in left.questions().iter().zip(right.questions()).zip(QIDS) {
        ensure!(
            l.qid() == qid && r.qid() == qid && l.query_sha256() == r.query_sha256(),
            "LABEL_CAPTURE_MISMATCH"
        );
        let le = lo
            .checked_add(l.slots().len())
            .context("COMPARE_INPUT_INVALID")?;
        let re = ro
            .checked_add(r.slots().len())
            .context("COMPARE_INPUT_INVALID")?;
        let ll = coverage
            .left_slot_labels()
            .get(lo..le)
            .context("COMPARE_INPUT_INVALID")?;
        let rl = coverage
            .right_slot_labels()
            .get(ro..re)
            .context("COMPARE_INPUT_INVALID")?;
        let lk = direct_keys(l.slots(), ll)?;
        let rk = direct_keys(r.slots(), rl)?;
        let denominator = lk.union(&rk).count();
        let proxy = |n| recall_proxy(n, denominator, complete);
        let supported_n = l.actual_n().min(r.actual_n());
        result.push(QuestionReport {
            qid: qid.into(),
            query_sha256: l.query_sha256().into(),
            observed_union_direct_key_denominator: denominator,
            left: side_question(
                l,
                ll,
                cutoffs,
                supported_n,
                complete,
                lk.len(),
                proxy(lk.len()),
            )?,
            right: side_question(
                r,
                rl,
                cutoffs,
                supported_n,
                complete,
                rk.len(),
                proxy(rk.len()),
            )?,
            rank_changes: rank_changes(&rank_observations(l)?, &rank_observations(r)?)?,
            question_total_delta_ms: finite_delta(
                l.cost().question_total_ms(),
                r.cost().question_total_ms(),
            )?,
        });
        lo = le;
        ro = re;
    }
    ensure!(
        lo == coverage.left_slot_labels().len() && ro == coverage.right_slot_labels().len(),
        "COMPARE_INPUT_INVALID"
    );
    Ok(result)
}

fn cutoffs(
    labels: &[SlotLabel],
    values: &[u32],
    supported_n: usize,
    complete: bool,
) -> Result<Vec<Cutoff>> {
    values
        .iter()
        .map(|&cutoff| {
            let n = usize::try_from(cutoff).context("COMPARE_INPUT_INVALID")?;
            let supported = supported_n >= n;
            if !supported {
                return Ok(Cutoff {
                    cutoff,
                    size_supported: false,
                    quality_status: CutoffQuality::WindowTooShort,
                    counts: None,
                    proportions: None,
                    has_direct: None,
                    denominator: None,
                });
            }
            let counts = Categories::of(labels.get(..n).context("COMPARE_INPUT_INVALID")?)?;
            Ok(Cutoff {
                cutoff,
                size_supported: true,
                quality_status: if complete {
                    CutoffQuality::Eligible
                } else {
                    CutoffQuality::IncompleteLabels
                },
                proportions: Some(counts.proportions(u64::from(cutoff))?),
                has_direct: Some(counts.direct > 0),
                denominator: Some(u64::from(cutoff)),
                counts: Some(counts),
            })
        })
        .collect()
}

#[expect(
    clippy::too_many_arguments,
    reason = "Both-side support and per-side labelled pool are separate facts"
)]
fn side_question(
    q: &blind::VerifiedQuestionCapture,
    overlay: &[SlotLabel],
    values: &[u32],
    supported_n: usize,
    complete: bool,
    distinct: usize,
    proxy: Option<f64>,
) -> Result<SideQuestion> {
    let pool = Categories::of(overlay)?;
    Ok(SideQuestion {
        requested_n: q.requested_n(),
        actual_n: q.actual_n(),
        pool_has_direct: pool.direct > 0,
        pool_label_counts: pool,
        pool_distinct_direct_keys: distinct,
        observed_union_recall_proxy: proxy,
        cutoffs: cutoffs(overlay, values, supported_n, complete)?,
        recorded_cost: recorded_question_cost(q.cost()),
    })
}

/// Ordinary metric data, not a verified input constructor or admission seam.
struct RankObservation {
    key: String,
    point: RankPoint,
}
fn rank_observations(q: &blind::VerifiedQuestionCapture) -> Result<Vec<RankObservation>> {
    q.slots()
        .iter()
        .map(|s| {
            Ok(RankObservation {
                key: s.candidate_instance_key().into(),
                point: RankPoint {
                    input_slot: s.input_slot(),
                    retrieval_rank: s.retrieval_rank(),
                    final_rank: s.final_rank(),
                    original_score: numeric(s.original_score())?,
                    rerank_score: s.rerank_score(),
                },
            })
        })
        .collect()
}
fn rank_changes(left: &[RankObservation], right: &[RankObservation]) -> Result<Vec<RankChange>> {
    let mut l = BTreeMap::new();
    let mut r = BTreeMap::new();
    for s in left {
        ensure!(
            l.insert(s.key.as_str(), &s.point).is_none(),
            "COMPARE_INPUT_INVALID"
        );
    }
    for s in right {
        ensure!(
            r.insert(s.key.as_str(), &s.point).is_none(),
            "COMPARE_INPUT_INVALID"
        );
    }
    let keys: std::collections::BTreeSet<_> = l.keys().chain(r.keys()).copied().collect();
    keys.into_iter()
        .map(|key| {
            let lp = l.get(key).copied();
            let rp = r.get(key).copied();
            let rank_delta =
                |a: usize, b: usize| delta(Some(u64::try_from(a)?), Some(u64::try_from(b)?));
            let (retrieval_rank_delta, final_rank_delta) = match (lp, rp) {
                (Some(a), Some(b)) => (
                    rank_delta(a.retrieval_rank, b.retrieval_rank)?,
                    rank_delta(a.final_rank, b.final_rank)?,
                ),
                _ => (None, None),
            };
            Ok(RankChange {
                candidate_instance_key: key.into(),
                state: match (lp, rp) {
                    (Some(_), Some(_)) => "shared",
                    (None, Some(_)) => "added",
                    _ => "removed",
                },
                left: lp.cloned(),
                right: rp.cloned(),
                retrieval_rank_delta,
                final_rank_delta,
            })
        })
        .collect()
}

fn aggregate_metrics(questions: &[QuestionReport], values: &[u32]) -> Result<AggregateMetrics> {
    let coverage = |left: bool| {
        let qids: Vec<_> = questions
            .iter()
            .filter(|q| {
                if left {
                    q.left.pool_has_direct
                } else {
                    q.right.pool_has_direct
                }
            })
            .map(|q| q.qid.clone())
            .collect();
        QuestionCoverage {
            has_direct_count: qids.len(),
            eligible_question_denominator: 9,
            qids_with_direct: qids,
        }
    };
    let mut aggregates = Vec::new();
    for (index, &cutoff) in values.iter().enumerate() {
        let supported: Vec<_> = questions
            .iter()
            .filter(|q| {
                q.left.cutoffs[index].size_supported && q.right.cutoffs[index].size_supported
            })
            .collect();
        let mut left = Categories::default();
        let mut right = Categories::default();
        let mut ld = 0;
        let mut rd = 0;
        for q in &supported {
            let l = q.left.cutoffs[index]
                .counts
                .as_ref()
                .context("COMPARE_INPUT_INVALID")?;
            let r = q.right.cutoffs[index]
                .counts
                .as_ref()
                .context("COMPARE_INPUT_INVALID")?;
            left.add(l)?;
            right.add(r)?;
            ld += usize::from(l.direct > 0);
            rd += usize::from(r.direct > 0);
        }
        let denominator = u64::from(cutoff)
            .checked_mul(u64::try_from(supported.len())?)
            .context("COMPARE_INPUT_INVALID")?;
        let side = |counts: Categories, has_direct| -> Result<_> {
            Ok(CutoffAggregateSide {
                has_direct_question_count: has_direct,
                question_denominator: supported.len(),
                label_proportions: if denominator > 0 {
                    Some(counts.proportions(denominator)?)
                } else {
                    None
                },
                label_counts: counts,
                slot_denominator: denominator,
            })
        };
        aggregates.push(CutoffAggregate {
            cutoff,
            supported_qids: supported.iter().map(|q| q.qid.clone()).collect(),
            unsupported_qids: questions
                .iter()
                .filter(|q| !q.left.cutoffs[index].size_supported)
                .map(|q| q.qid.clone())
                .collect(),
            supported_count: supported.len(),
            total_questions: 9,
            left: side(left, ld)?,
            right: side(right, rd)?,
        });
    }
    Ok(AggregateMetrics {
        pool_has_direct_left: coverage(true),
        pool_has_direct_right: coverage(false),
        cutoffs: aggregates,
    })
}

fn recorded_count(c: &blind::CaptureCounts) -> RecordedCount {
    RecordedCount {
        scope: c.scope().into(),
        http_attempts: c.http_attempts(),
        http_response_observed: c.http_response_observed(),
        delivery_unknown: c.delivery_unknown(),
        model_executions: c.model_executions(),
        basis: c.basis().into(),
    }
}
fn recorded_question_cost(c: &blind::CaptureQuestionCost) -> QuestionCost {
    QuestionCost {
        identity_before_ms: c.identity_before_ms(),
        identity_after_ms: c.identity_after_ms(),
        retrieval_ms: c.retrieval_ms(),
        rerank_client_ms: c.rerank_client_ms(),
        model_execution_ms: c.model_execution_ms(),
        paging_ms: c.paging_ms(),
        question_total_ms: c.question_total_ms(),
        http: c.http().iter().map(recorded_count).collect(),
        resource_measurements: c
            .resource_measurements()
            .iter()
            .map(|r| ResourceMeasurement {
                name: r.name().into(),
                value: r.value(),
                unit: r.unit().into(),
                source: r.source().map(str::to_owned),
            })
            .collect(),
    }
}
fn side_cost(capture: &VerifiedRunCapture) -> Result<SideCost> {
    let mut samples: [Vec<Option<f64>>; 7] = std::array::from_fn(|_| Vec::with_capacity(9));
    for q in capture.questions() {
        let c = q.cost();
        for (values, value) in samples.iter_mut().zip([
            Some(c.identity_before_ms()),
            Some(c.identity_after_ms()),
            Some(c.retrieval_ms()),
            c.rerank_client_ms(),
            c.model_execution_ms(),
            Some(c.paging_ms()),
            Some(c.question_total_ms()),
        ]) {
            values.push(value);
        }
    }
    let names = [
        "identity_before_ms",
        "identity_after_ms",
        "retrieval_ms",
        "rerank_client_ms",
        "model_execution_ms",
        "paging_ms",
        "question_total_ms",
    ];
    let components = names
        .into_iter()
        .zip(samples)
        .map(|(name, values)| {
            Ok(CostComponent {
                name,
                statistics: statistics(&values)?,
            })
        })
        .collect::<Result<_>>()?;
    let c = capture.cost();
    Ok(SideCost {
        recorded_all_run_ms: c.all_run_ms(),
        recorded_identity_before_ms: c.identity_before_ms(),
        recorded_identity_after_ms: c.identity_after_ms(),
        process_wall_ms: None,
        process_receipt: None,
        components,
        recorded_counts: c.counts().iter().map(recorded_count).collect(),
    })
}
fn comparison_cost(
    left: &VerifiedRunCapture,
    right: &VerifiedRunCapture,
) -> Result<CostComparison> {
    let l = side_cost(left)?;
    let r = side_cost(right)?;
    let lm = indexed_counts(&l.recorded_counts)?;
    let rm = indexed_counts(&r.recorded_counts)?;
    let scopes: std::collections::BTreeSet<_> = lm.keys().chain(rm.keys()).cloned().collect();
    let count_deltas = scopes
        .into_iter()
        .map(|scope| {
            let a = lm.get(&scope).copied();
            let b = rm.get(&scope).copied();
            Ok(CountDelta {
                scope,
                http_attempts: delta(
                    a.and_then(|c| c.http_attempts),
                    b.and_then(|c| c.http_attempts),
                )?,
                http_response_observed: delta(
                    a.and_then(|c| c.http_response_observed),
                    b.and_then(|c| c.http_response_observed),
                )?,
                delivery_unknown: delta(
                    a.and_then(|c| c.delivery_unknown),
                    b.and_then(|c| c.delivery_unknown),
                )?,
                model_executions: delta(
                    a.and_then(|c| c.model_executions),
                    b.and_then(|c| c.model_executions),
                )?,
            })
        })
        .collect::<Result<_>>()?;
    Ok(CostComparison {
        recorded_all_run_delta_ms: finite_delta(l.recorded_all_run_ms, r.recorded_all_run_ms)?,
        left: l,
        right: r,
        process_wall_delta_ms: None,
        count_deltas,
    })
}

fn indexed_counts(counts: &[RecordedCount]) -> Result<BTreeMap<String, &RecordedCount>> {
    let mut map = BTreeMap::new();
    for count in counts {
        ensure!(
            map.insert(count.scope.clone(), count).is_none(),
            "COMPARE_INPUT_INVALID"
        );
    }
    Ok(map)
}

fn scalar(value: impl Serialize) -> Result<Scalar> {
    match serde_json::to_value(value)? {
        Value::String(x) => Ok(Scalar::Text(x)),
        Value::Number(x) => Ok(Scalar::Number(x)),
        Value::Bool(x) => Ok(Scalar::Bool(x)),
        Value::Null => Ok(Scalar::Null),
        _ => anyhow::bail!("COMPARE_INPUT_INVALID"),
    }
}

fn changed_inputs(
    left: &VerifiedRunCapture,
    right: &VerifiedRunCapture,
) -> Result<Vec<ScalarChange>> {
    let lp = left.provenance();
    let rp = right.provenance();
    let lr = left.request();
    let rr = right.request();
    let lb = left.backend_identity();
    let rb = right.backend_identity();
    let l = left.observed_before();
    let r = right.observed_before();
    let values = [
        (
            "source_commit",
            scalar(lp.source_commit())?,
            scalar(rp.source_commit())?,
        ),
        (
            "binary_sha256",
            scalar(lp.binary_sha256())?,
            scalar(rp.binary_sha256())?,
        ),
        (
            "argv_sha256",
            scalar(lp.argv_sha256())?,
            scalar(rp.argv_sha256())?,
        ),
        (
            "capture_labels_sha256",
            scalar(left.capture_labels_sha256())?,
            scalar(right.capture_labels_sha256())?,
        ),
        (
            "database_sha256",
            scalar(l.map(|b| b.database_sha256.as_str()))?,
            scalar(r.map(|b| b.database_sha256.as_str()))?,
        ),
        (
            "generation.generation_id",
            scalar(l.map(|b| b.generation.generation_id))?,
            scalar(r.map(|b| b.generation.generation_id))?,
        ),
        (
            "generation.embedder_id",
            scalar(l.map(|b| b.generation.embedder_id.as_str()))?,
            scalar(r.map(|b| b.generation.embedder_id.as_str()))?,
        ),
        (
            "generation.dim",
            scalar(l.map(|b| b.generation.dim))?,
            scalar(r.map(|b| b.generation.dim))?,
        ),
        (
            "generation.fingerprint",
            scalar(l.map(|b| b.generation.fingerprint.as_str()))?,
            scalar(r.map(|b| b.generation.fingerprint.as_str()))?,
        ),
        (
            "generation.vector_revision",
            scalar(l.map(|b| b.generation.vector_revision))?,
            scalar(r.map(|b| b.generation.vector_revision))?,
        ),
        (
            "generation.vector_domain_instance_id",
            scalar(l.map(|b| b.generation.vector_domain_instance_id.as_str()))?,
            scalar(r.map(|b| b.generation.vector_domain_instance_id.as_str()))?,
        ),
        (
            "generation.audit_status",
            scalar(l.map(|b| b.generation.audit_status.as_str()))?,
            scalar(r.map(|b| b.generation.audit_status.as_str()))?,
        ),
        (
            "generation.byte_order",
            scalar(l.map(|b| b.generation.byte_order.as_str()))?,
            scalar(r.map(|b| b.generation.byte_order.as_str()))?,
        ),
        (
            "retrieval_order_sha256",
            scalar(l.map(|b| b.retrieval_order_sha256.as_str()))?,
            scalar(r.map(|b| b.retrieval_order_sha256.as_str()))?,
        ),
        (
            "retrieval_layout_sha256",
            scalar(l.map(|b| b.retrieval_layout_sha256.as_str()))?,
            scalar(r.map(|b| b.retrieval_layout_sha256.as_str()))?,
        ),
        // Inventory differences do not assert that semantic retrieval used stats.
        (
            "lexical_statistics_sha256",
            scalar(l.map(|b| b.lexical_statistics_sha256.as_str()))?,
            scalar(r.map(|b| b.lexical_statistics_sha256.as_str()))?,
        ),
        (
            "search_mode",
            scalar(lr.search_mode())?,
            scalar(rr.search_mode())?,
        ),
        (
            "vector_search_mode",
            scalar(lr.vector_search_mode())?,
            scalar(rr.vector_search_mode())?,
        ),
        ("rerank", scalar(lr.rerank())?, scalar(rr.rerank())?),
        ("n", scalar(lr.n())?, scalar(rr.n())?),
        ("page_k", scalar(lr.page_k())?, scalar(rr.page_k())?),
        (
            "request_profile",
            scalar(lr.request_profile())?,
            scalar(rr.request_profile())?,
        ),
        (
            "request_evidence_sha256",
            scalar(lr.request_evidence_sha256())?,
            scalar(rr.request_evidence_sha256())?,
        ),
        ("provider", scalar(lb.provider())?, scalar(rb.provider())?),
        (
            "actual_model",
            scalar(lb.actual_model())?,
            scalar(rb.actual_model())?,
        ),
        (
            "model_revision",
            scalar(lb.model_revision())?,
            scalar(rb.model_revision())?,
        ),
        (
            "endpoint_origin_sha256",
            scalar(lb.endpoint_origin_sha256())?,
            scalar(rb.endpoint_origin_sha256())?,
        ),
        (
            "server_template_policy",
            scalar(lb.server_template_policy())?,
            scalar(rb.server_template_policy())?,
        ),
        (
            "document_assembly_policy",
            scalar(lb.document_assembly_policy())?,
            scalar(rb.document_assembly_policy())?,
        ),
        (
            "client_submission_policy",
            scalar(lb.client_submission_policy())?,
            scalar(rb.client_submission_policy())?,
        ),
    ];
    Ok(values
        .into_iter()
        .filter(|(_, l, r)| l != r)
        .map(|(field, left, right)| ScalarChange { field, left, right })
        .collect())
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct NativeFixture {
        suite: PathBuf,
        suite_sha256: String,
        labels: PathBuf,
        labels_sha256: String,
        left: PathBuf,
        left_sha256: String,
        right: PathBuf,
        right_sha256: String,
        ancestors: Vec<(PathBuf, String)>,
        artifact_root: PathBuf,
        expected_rc: u8,
    }

    fn native_request() -> Result<(CompareRequest, PathBuf, u8)> {
        let path =
            dotenvy::var("CASS_S2_08_NATIVE_INPUTS").context("S208_NATIVE_INPUTS_REQUIRED")?;
        let fixture: NativeFixture = serde_json::from_slice(&std::fs::read(path)?)?;
        let root = tempfile::Builder::new()
            .prefix("s208-cycle-")
            .tempdir_in(&fixture.artifact_root)?
            .keep();
        let request = CompareRequest {
            left: FilePin::new(fixture.left, fixture.left_sha256)?,
            right: FilePin::new(fixture.right, fixture.right_sha256)?,
            labels: FilePin::new(fixture.labels, fixture.labels_sha256)?,
            ancestors: fixture
                .ancestors
                .into_iter()
                .map(|(p, h)| FilePin::new(p, h))
                .collect::<Result<_>>()?,
            capture_suite: fixture.suite,
            capture_suite_sha256: fixture.suite_sha256,
            output: OutputOptions {
                output_root: root.clone(),
                run_id: "before".into(),
            },
            cutoffs: vec![5, 10, 20],
            action: LabelAction::Evaluate,
            import: None,
        };
        Ok((request, root, fixture.expected_rc))
    }

    fn native_report(
        root: &std::path::Path,
        request: &CompareRequest,
        outcome: &CompareOutcome,
    ) -> Result<Value> {
        let directory = root.join(&request.output.run_id);
        let bytes = std::fs::read(directory.join(&outcome.stdout.report.relative_path))?;
        assert_eq!(labels::digest(&bytes), outcome.stdout.report.sha256);
        super::super::off::write_private(
            root,
            &format!("stdout-{}.json", request.output.run_id),
            &serde_json::to_value(outcome.stdout())?,
        )?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    #[test]
    #[ignore = "Uses pinned private synthetic Runs and owned persistent output"]
    fn owned_filepin_three_action_lifecycle() -> Result<()> {
        let (mut request, root, expected) = native_request()?;
        let original: Vec<_> = std::iter::once(&request.left)
            .chain(std::iter::once(&request.right))
            .chain(std::iter::once(&request.labels))
            .chain(&request.ancestors)
            .map(|p| {
                Ok((
                    p.path().to_path_buf(),
                    labels::digest(&std::fs::read(p.path())?),
                ))
            })
            .collect::<Result<_>>()?;
        let before = run(&request)?;
        assert_eq!(before.stdout.rc, expected);
        let before_report = native_report(&root, &request, &before)?;
        if expected == 2 {
            assert!(
                matches!(before.exit(),CompareExit::Two(code) if code.as_str()=="INCOMPLETE_LABELS")
            );
        }
        request.action = LabelAction::ExportBlind;
        request.output.run_id = "export".into();
        let exported = run(&request)?;
        assert!(matches!(exported.exit(), CompareExit::Zero));
        let export_report = native_report(&root, &request, &exported)?;
        assert_eq!(export_report["quality_status"], "NOT_EVALUATED");
        assert!(export_report["success_summary"].is_null());
        let bundle: Value =
            serde_json::from_slice(&std::fs::read(root.join("export/blind-bundle.json"))?)?;
        let answers = serde_json::json!({"schema":"cass.regression-blind-answers.v1","bundle_id":bundle["bundle_id"],
            "records":bundle["items"].as_array().context("bundle items")?.iter().map(|item|serde_json::json!({"opaque_id":item["opaque_id"],"value":"direct"})).collect::<Vec<_>>()});
        // Answers are an input to import. Their parent cannot be output_root.
        let answer_root = tempfile::Builder::new()
            .prefix("answer-input-")
            .tempdir_in(&root)?
            .keep();
        let answer_ref = super::super::off::write_private(&answer_root, "answers.json", &answers)?;
        request.action = LabelAction::ImportBlind;
        request.output.run_id = "import".into();
        request.import = Some(ImportRequest {
            manifest: FilePin::new(
                root.join("export/blind-manifest.json"),
                export_report["annotation_artifacts"]["manifest"]["sha256"]
                    .as_str()
                    .context("manifest hash")?
                    .into(),
            )?,
            answers: FilePin::new(
                answer_root.join("answers.json"),
                answer_ref["sha256"]
                    .as_str()
                    .context("answers hash")?
                    .into(),
            )?,
            version: "s208-native-import".into(),
        });
        let imported = run(&request)?;
        assert!(matches!(imported.exit(), CompareExit::Zero));
        let imported_report = native_report(&root, &request, &imported)?;
        assert_eq!(imported_report["quality_status"], "NOT_EVALUATED");
        assert!(imported_report["success_summary"].is_null());
        let old = request.labels.clone();
        request.labels = FilePin::new(
            root.join("import/labels-new.json"),
            imported_report["annotation_artifacts"]["labels"]["sha256"]
                .as_str()
                .context("new labels hash")?
                .into(),
        )?;
        request.ancestors.insert(0, old);
        request.action = LabelAction::Evaluate;
        request.import = None;
        request.output.run_id = "after".into();
        let after = run(&request)?;
        assert!(matches!(after.exit(), CompareExit::Zero));
        let after_report = native_report(&root, &request, &after)?;
        assert_eq!(after_report["diagnostics"]["unknown_union_keys"], 0);
        let mut bad = request.clone();
        bad.output.run_id = "bad-pin".into();
        bad.left = FilePin::new(bad.left.path().to_path_buf(), "0".repeat(64))?;
        let rejected = run(&bad)?;
        assert!(matches!(rejected.exit(), CompareExit::Two(_)));
        let rejected_report = native_report(&root, &bad, &rejected)?;
        assert_eq!(rejected_report["terminal"], "FAILED");
        let mut invalid = request.clone();
        invalid.output.run_id = "bad-flags".into();
        invalid.import = Some(ImportRequest {
            manifest: bad.left.clone(),
            answers: bad.right.clone(),
            version: "invalid".into(),
        });
        assert!(run(&invalid).is_err());
        assert!(!root.join("bad-flags").exists());
        for (p, hash) in &original {
            assert_eq!(&labels::digest(&std::fs::read(p)?), hash);
        }
        super::super::off::write_private(
            &root,
            "native-lifecycle.json",
            &serde_json::json!({"before":before_report["rc"],"after":after_report["rc"],"unknown_before":before_report["diagnostics"]["unknown_union_keys"],"unknown_after":0,"old_inputs_unchanged":true,"cass_process_exit_verified":false}),
        )?;
        println!("S208_NATIVE_LIFECYCLE_ARTIFACT={}", root.display());
        Ok(())
    }

    #[test]
    #[ignore = "Needs explicitly pinned private synthetic FilePin fixture"]
    fn owned_filepin_evaluate_report_end() -> Result<()> {
        let path =
            dotenvy::var("CASS_S2_08_NATIVE_INPUTS").context("S208_NATIVE_INPUTS_REQUIRED")?;
        let fixture: NativeFixture = serde_json::from_slice(&std::fs::read(path)?)?;
        let root = tempfile::Builder::new()
            .prefix("s208-eval-")
            .tempdir_in(&fixture.artifact_root)?
            .keep();
        let request = CompareRequest {
            left: FilePin::new(fixture.left, fixture.left_sha256)?,
            right: FilePin::new(fixture.right, fixture.right_sha256)?,
            labels: FilePin::new(fixture.labels, fixture.labels_sha256)?,
            ancestors: fixture
                .ancestors
                .into_iter()
                .map(|(p, h)| FilePin::new(p, h))
                .collect::<Result<_>>()?,
            capture_suite: fixture.suite,
            capture_suite_sha256: fixture.suite_sha256,
            output: OutputOptions {
                output_root: root.clone(),
                run_id: "evaluate".into(),
            },
            cutoffs: vec![5],
            action: LabelAction::Evaluate,
            import: None,
        };
        let outcome = run(&request)?;
        assert_eq!(outcome.stdout().rc, fixture.expected_rc);
        assert_eq!(
            matches!(outcome.exit(), CompareExit::Two(_)),
            fixture.expected_rc == 2
        );
        let report = std::fs::read(
            root.join("evaluate")
                .join(&outcome.stdout().report.relative_path),
        )?;
        assert_eq!(labels::digest(&report), outcome.stdout().report.sha256);
        let report: Value = serde_json::from_slice(&report)?;
        assert_eq!(
            report["questions"]
                .as_array()
                .context("missing questions")?
                .len(),
            9
        );
        assert_eq!(report["rc"], fixture.expected_rc);
        assert_eq!(report["claims"]["process_wall_status"], "NOT_VERIFIED");
        assert!(report["cost"]["left"]["process_wall_ms"].is_null());
        super::super::off::write_private(
            &root,
            "stdout-summary.json",
            &serde_json::to_value(outcome.stdout())?,
        )?;
        super::super::off::write_private(
            &root,
            "native-summary.json",
            &serde_json::json!({
                "artifact_root":root,"metadata":outcome.stdout(),"cass_process_exit_verified":false
            }),
        )?;
        println!("S208_NATIVE_EVALUATE_ARTIFACT={}", root.display());
        Ok(())
    }
    #[test]
    fn nearest_rank_nine_and_unknown_sample_are_distinct() {
        let values: Vec<_> = [9., 1., 8., 2., 7., 3., 6., 4., 5.]
            .into_iter()
            .map(Some)
            .collect();
        let complete = statistics(&values).unwrap();
        assert_eq!(
            (complete.mean, complete.p50, complete.p95),
            (Some(5.), Some(5.), Some(9.))
        );
        let mut partial = values;
        partial[1] = None;
        let partial = statistics(&partial).unwrap();
        assert_eq!(partial.known_samples, 8);
        assert_eq!((partial.mean, partial.p50, partial.p95), (None, None, None));
    }
    #[test]
    fn unsure_and_unknown_preserve_slot_multiplicity() {
        let c = Categories::of(&[
            SlotLabel::Known(HumanLabel::Direct),
            SlotLabel::Known(HumanLabel::Direct),
            SlotLabel::Known(HumanLabel::Unsure),
            SlotLabel::Unknown,
            SlotLabel::Known(HumanLabel::None),
        ])
        .unwrap();
        assert_eq!((c.direct, c.unsure, c.unknown, c.none), (2, 1, 1, 1));
        assert_eq!(c.proportions(5).unwrap().direct, 0.4);
        assert_eq!(delta(None, Some(0)).unwrap(), None);
        assert_eq!(delta(Some(2), Some(0)).unwrap(), Some(-2));
    }
    #[test]
    fn complete_short_cutoffs_keep_eight_of_nine_and_zero_support() {
        let known = vec![SlotLabel::Known(HumanLabel::None); 20];
        let support: Vec<_> = (0..9)
            .map(|q| cutoffs(&known, &[5, 10, 20, 21], if q == 8 { 12 } else { 20 }, true).unwrap())
            .collect();
        assert_eq!(
            (0..4)
                .map(|c| support.iter().filter(|q| q[c].size_supported).count())
                .collect::<Vec<_>>(),
            vec![9, 9, 8, 0]
        );
        assert!(support[8][2].counts.is_none());
        assert!(support[8][2].denominator.is_none());
        assert!(cutoffs(&[], &[5], 0, true).unwrap()[0].has_direct.is_none());
    }
    #[test]
    fn unknown_outside_cutoff_does_not_turn_diagnostic_into_eligible() {
        let mut labels = vec![SlotLabel::Known(HumanLabel::None); 20];
        labels[19] = SlotLabel::Unknown;
        let top = cutoffs(&labels, &[5], 20, false).unwrap();
        assert!(matches!(
            top[0].quality_status,
            CutoffQuality::IncompleteLabels
        ));
        assert_eq!(top[0].counts.as_ref().unwrap().unknown, 0);
    }
    fn observation(key: &str, input: usize, final_rank: usize) -> RankObservation {
        RankObservation {
            key: key.into(),
            point: RankPoint {
                input_slot: input,
                retrieval_rank: input + 1,
                final_rank,
                original_score: Number::from(1),
                rerank_score: None,
            },
        }
    }
    #[test]
    fn rank_matching_is_per_question_and_keeps_added_removed() {
        let one = rank_changes(
            &[observation("shared", 0, 3), observation("removed", 1, 1)],
            &[observation("shared", 0, 1), observation("added", 1, 2)],
        )
        .unwrap();
        assert_eq!(
            one.iter()
                .find(|r| r.state == "shared")
                .unwrap()
                .final_rank_delta,
            Some(-2)
        );
        assert_eq!(
            one.iter()
                .filter(|r| r.state == "added" || r.state == "removed")
                .count(),
            2
        );
        let another = rank_changes(
            &[observation("shared", 0, 1)],
            &[observation("shared", 0, 3)],
        )
        .unwrap();
        assert_eq!(another[0].final_rank_delta, Some(2));
        assert!(
            rank_changes(&[observation("same", 0, 1), observation("same", 1, 2)], &[]).is_err()
        );
    }
    #[test]
    fn precise_integer_and_negative_zero_are_not_float_coerced() {
        assert_eq!(
            numeric(NumericValue::U64(u64::MAX)).unwrap().as_u64(),
            Some(u64::MAX)
        );
        assert_eq!(
            numeric(NumericValue::F64(-0.0))
                .unwrap()
                .as_f64()
                .unwrap()
                .to_bits(),
            (-0.0f64).to_bits()
        );
        assert!(delta(Some(u64::MAX), Some(0)).is_err());
        assert!(statistics(&[Some(f64::MAX); 9]).is_err());
        assert!(statistics(&[Some(f64::NAN); 9]).is_err());
    }
    #[test]
    fn unknown_error_text_is_never_an_output_code() {
        assert_eq!(
            error_code(&anyhow::anyhow!("synthetic private body/path")).as_str(),
            "COMPARE_INPUT_INVALID"
        );
        assert_eq!(
            error_code(&anyhow::anyhow!("LABEL_PARENT_MISMATCH")).as_str(),
            "LABEL_PARENT_MISMATCH"
        );
    }
    #[test]
    fn observed_union_proxy_zero_unknown_and_duplicate_keys_are_distinct() {
        let left: HashSet<_> = ["A", "A"].into_iter().collect();
        let right: HashSet<_> = ["A", "B"].into_iter().collect();
        let denominator = left.union(&right).count();
        assert_eq!(recall_proxy(left.len(), denominator, true), Some(0.5));
        assert_eq!(recall_proxy(right.len(), denominator, true), Some(1.0));
        assert_eq!(recall_proxy(0, 0, true), None);
        assert_eq!(recall_proxy(left.len(), denominator, false), None);
    }
}
