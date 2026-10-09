//! Frozen fixed-candidate pool preparation and one-window execution.
//!
//! Phase A: this module is deliberately not declared or dispatched yet. The
//! integration caller must obtain raw windows and documents through the trusted
//! registered-asset facade, and must externally pin the pool-binding file. No
//! function here opens a path, a database, or a second scoring transport.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Result, ensure};
use serde_json::{Number, Value, json};
use sha2::{Digest, Sha256};

use super::fixed_encoding::{NumericValue, WindowScores, original_score_sideview};
use super::types::{InputSlot, InputWindow, LabelKey, LabelRecord, MessageId, ValidatedInputs};
use crate::search::regression_trace::{RequestTrace, TextDigest};
use crate::search::rerank::types::{
    CallIdentity, ProviderChoice, RerankBackend, RerankError, stable_rank_order,
};

const POOL_SIZE: usize = 200;
const QIDS: [&str; 9] = [
    "N01", "N02", "N03", "N04", "N05", "N06", "N07", "N08", "N12",
];
const INSTANCE_DOMAIN: &[u8] = b"cass.regression-fixed-candidate-instance.v1\0";

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// These declarations come from the externally pinned, strictly parsed binding,
/// never from the computed pool hash. Admission remains the input module's job.
pub(crate) struct ExpectedPool {
    pub(crate) qid: String,
    pub(crate) ordered_pool_sha256: String,
}

#[derive(Clone)]
struct PreparedSlot {
    input: InputSlot,
    conversation_id: Option<i64>,
    original_score: NumericValue,
    instance_key: String,
}

/// The original typed identifiers remain private, recoverable, and immutable.
/// Public Slot.message_id is only a projection of this pinned association.
pub(crate) struct PreparedPool {
    window: InputWindow,
    slots: Vec<PreparedSlot>,
    ordered_bytes: Vec<u8>,
    ordered_pool_sha256: String,
    suite_sha256: String,
    input_manifest_sha256: String,
    windows_file_sha256: String,
    labels_sha256: String,
    label_policy_sha256: String,
}

fn conversation(value: &Value) -> Result<Option<i64>> {
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_i64()
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("REGRESSION_FIXED_UNREPRESENTABLE_CONVERSATION"))
}

fn number(value: NumericValue) -> Result<Number> {
    match value {
        NumericValue::I64(value) => Ok(Number::from(value)),
        NumericValue::U64(value) => Ok(Number::from(value)),
        NumericValue::F64(value) => Number::from_f64(value)
            .ok_or_else(|| anyhow::anyhow!("REGRESSION_FIXED_UNREPRESENTABLE_SCORE")),
    }
}

fn original_score_matches(value: &Value, original: NumericValue) -> bool {
    match original {
        NumericValue::I64(expected) => value.is_i64() && value.as_i64() == Some(expected),
        NumericValue::U64(expected) => value.is_u64() && value.as_u64() == Some(expected),
        NumericValue::F64(expected) => {
            value.is_f64()
                && value
                    .as_f64()
                    .is_some_and(|actual| actual.to_bits() == expected.to_bits())
        }
    }
}

fn instance_key(pool_sha: &str, rank: usize, message_id: &MessageId) -> Result<String> {
    ensure!(
        is_sha(pool_sha) && (1..=POOL_SIZE).contains(&rank),
        "REGRESSION_FIXED_ID_RECOVERY_MISMATCH"
    );
    let mut bytes = INSTANCE_DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(&(pool_sha, rank, message_id))?);
    Ok(digest(&bytes))
}

fn same_slot(left: &InputSlot, right: &InputSlot) -> bool {
    left.rank == right.rank
        && left.message_id == right.message_id
        && left.conversation_id == right.conversation_id
        && left.text_sha256 == right.text_sha256
        && left.bytes == right.bytes
        && left.source_sha256 == right.source_sha256
        && left.original_score == right.original_score
        && left.text_path == right.text_path
        && left.scoreable == right.scoreable
        && left.fallback_reason == right.fallback_reason
}

fn bind_typed_bytes(windows: &[InputWindow], bytes: &[u8]) -> Result<()> {
    let mut lines = bytes.split(|b| *b == b'\n').peekable();
    let mut decoded = Vec::new();
    while let Some(line) = lines.next() {
        if line.is_empty() && lines.peek().is_none() {
            break;
        }
        let window: InputWindow = serde_json::from_slice(line)
            .map_err(|_| anyhow::anyhow!("REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH"))?;
        decoded.push(window);
    }
    ensure!(
        decoded.len() == windows.len(),
        "REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH"
    );
    for (left, right) in windows.iter().zip(decoded.iter()) {
        ensure!(
            left.qid == right.qid
                && left.query == right.query
                && left.query_sha256 == right.query_sha256
                && left.items.len() == right.items.len()
                && left
                    .items
                    .iter()
                    .zip(&right.items)
                    .all(|(a, b)| same_slot(a, b)),
            "REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH"
        );
    }
    Ok(())
}

fn prepare_pool(
    window: &InputWindow,
    sideview: &WindowScores,
    window_index: usize,
    raw: &[u8],
    expected: &ExpectedPool,
    inputs: &ValidatedInputs,
) -> Result<PreparedPool> {
    ensure!(
        window.items.len() == POOL_SIZE
            && sideview.scores.len() == POOL_SIZE
            && sideview.window_index == window_index
            && sideview.qid == window.qid,
        "REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH"
    );
    ensure!(
        expected.qid == window.qid && is_sha(&expected.ordered_pool_sha256),
        "REGRESSION_FIXED_POOL_BINDING_MISMATCH"
    );
    ensure!(
        digest(window.query.as_bytes()) == window.query_sha256,
        "REGRESSION_FIXED_QUERY_IDENTITY_MISMATCH"
    );
    let mut ordered = vec![b'['];
    let mut slots = Vec::with_capacity(POOL_SIZE);
    let mut ids = HashSet::new();
    for (index, (input, score)) in window.items.iter().zip(&sideview.scores).enumerate() {
        ensure!(
            input.rank == index + 1 && score.item_index == index && score.rank == input.rank as u64,
            "REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH"
        );
        ensure!(
            ids.insert(input.message_id.clone()),
            "REGRESSION_FIXED_ID_RECOVERY_MISMATCH"
        );
        ensure!(
            is_sha(&input.text_sha256) && is_sha(&input.source_sha256),
            "REGRESSION_FIXED_POOL_BINDING_MISMATCH"
        );
        let token = raw
            .get(score.number_span.clone())
            .ok_or_else(|| anyhow::anyhow!("REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH"))?;
        let encoding = super::fixed_encoding::encode_numeric(token)
            .map_err(|_| anyhow::anyhow!("REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH"))?;
        ensure!(
            encoding == score.encoding,
            "REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH"
        );
        let original_score = encoding
            .value
            .map_err(|_| anyhow::anyhow!("REGRESSION_FIXED_UNREPRESENTABLE_SCORE"))?;
        let conversation_id = conversation(&input.conversation_id)?;
        // Six typed non-score fields use compact UTF-8 JSON. The seventh is
        // the approved codec's unquoted canonical number, never a Value reparse.
        let mut row = serde_json::to_vec(&(
            input.rank,
            &input.message_id,
            conversation_id,
            &input.text_sha256,
            input.bytes,
            &input.source_sha256,
        ))?;
        ensure!(
            row.pop() == Some(b']'),
            "REGRESSION_FIXED_POOL_BINDING_MISMATCH"
        );
        row.push(b',');
        row.extend(&encoding.canonical);
        row.push(b']');
        if index != 0 {
            ordered.push(b',');
        }
        ordered.extend(row);
        slots.push(PreparedSlot {
            input: input.clone(),
            conversation_id,
            original_score,
            instance_key: String::new(),
        });
    }
    ordered.push(b']');
    let pool_sha = digest(&ordered);
    ensure!(
        pool_sha == expected.ordered_pool_sha256,
        "REGRESSION_FIXED_POOL_BINDING_MISMATCH"
    );
    for slot in &mut slots {
        slot.instance_key = instance_key(&pool_sha, slot.input.rank, &slot.input.message_id)?;
    }
    Ok(PreparedPool {
        window: window.clone(),
        slots,
        ordered_bytes: ordered,
        ordered_pool_sha256: pool_sha,
        suite_sha256: inputs.suite_sha256.clone(),
        input_manifest_sha256: inputs.input_manifest_sha256.clone(),
        windows_file_sha256: inputs.windows_file_sha256.clone(),
        labels_sha256: inputs.labels_sha256.clone(),
        label_policy_sha256: inputs.label_policy_sha256.clone(),
    })
}

/// Prepare all nine pools before constructing any backend. The same pinned raw
/// bytes must have passed the input module's strict reader. Comparing the typed
/// view again prevents a stale admission from being paired with new raw spans.
pub(crate) fn prepare_pools(
    inputs: &ValidatedInputs,
    raw_windows: &[u8],
    expected: &[ExpectedPool],
) -> Result<Vec<PreparedPool>> {
    ensure!(
        is_sha(&inputs.suite_sha256) && is_sha(&inputs.input_manifest_sha256),
        "REGRESSION_FIXED_INPUT_PIN_MISMATCH"
    );
    ensure!(
        digest(raw_windows) == inputs.windows_file_sha256,
        "REGRESSION_FIXED_WINDOW_PIN_MISMATCH"
    );
    ensure!(
        inputs.windows.len() == QIDS.len() && expected.len() == QIDS.len(),
        "REGRESSION_FIXED_SUITE_MISMATCH"
    );
    bind_typed_bytes(&inputs.windows, raw_windows)?;
    let sideviews = original_score_sideview(raw_windows)
        .map_err(|_| anyhow::anyhow!("REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH"))?;
    ensure!(
        sideviews.len() == QIDS.len(),
        "REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH"
    );
    inputs
        .windows
        .iter()
        .zip(&sideviews)
        .zip(expected)
        .enumerate()
        .map(|(index, ((window, sideview), pin))| {
            ensure!(window.qid == QIDS[index], "REGRESSION_FIXED_SUITE_MISMATCH");
            prepare_pool(window, sideview, index, raw_windows, pin, inputs)
        })
        .collect()
}

impl PreparedPool {
    pub(crate) fn ordered_bytes(&self) -> &[u8] {
        &self.ordered_bytes
    }

    /// Retains the pin chain and typed legacy IDs in a private evidence object.
    /// A consumer still needs the original pinned bytes to independently recover
    /// these identifiers. This object is not a replacement for those bytes.
    pub(crate) fn recovery_evidence(&self) -> Value {
        json!({"suite_sha256":self.suite_sha256,
            "input_manifest_sha256":self.input_manifest_sha256,
            "windows_file_sha256":self.windows_file_sha256,"qid":self.window.qid,
            "ordered_pool_sha256":self.ordered_pool_sha256,
            "slots":self.slots.iter().enumerate().map(|(i,s)| json!({
                "input_slot":i,"retrieval_rank":s.input.rank,
                "candidate_instance_key":s.instance_key,"typed_message_id":s.input.message_id
            })).collect::<Vec<_>>()})
    }

    /// The integration caller supplies the registered-asset guard. No arbitrary
    /// path is accepted or opened by this module. This callback must not be wired
    /// to an unchecked filesystem reader during Phase B.
    pub(crate) fn documents(
        &self,
        mut read_registered: impl FnMut(&str) -> Result<Vec<u8>>,
    ) -> Result<Vec<String>> {
        self.slots
            .iter()
            .map(|slot| {
                let bytes = read_registered(&slot.input.text_path)?;
                ensure!(
                    bytes.len() as u64 == slot.input.bytes
                        && digest(&bytes) == slot.input.text_sha256,
                    "REGRESSION_FIXED_DOCUMENT_IDENTITY_MISMATCH"
                );
                String::from_utf8(bytes)
                    .map_err(|_| anyhow::anyhow!("REGRESSION_FIXED_DOCUMENT_UTF8_MISMATCH"))
            })
            .collect()
    }

    fn original_slots(&self, labels: &[LabelRecord], policy_sha: &str) -> Result<Vec<Value>> {
        ensure!(
            policy_sha == self.label_policy_sha256 && is_sha(policy_sha),
            "REGRESSION_FIXED_LABEL_MISMATCH"
        );
        let mut indexed = HashMap::new();
        for label in labels {
            ensure!(
                matches!(
                    label.value.as_str(),
                    "direct" | "partial" | "none" | "unsure"
                ),
                "REGRESSION_FIXED_LABEL_MISMATCH"
            );
            if let Some(prior) = indexed.insert(label.key.clone(), label.value.as_str()) {
                ensure!(prior == label.value, "REGRESSION_FIXED_LABEL_MISMATCH");
            }
        }
        self.slots
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                let key = LabelKey {
                    query_sha256: self.window.query_sha256.clone(),
                    label_text_sha256: slot.input.text_sha256.clone(),
                    label_policy_sha256: policy_sha.into(),
                };
                let message_id = match slot.input.message_id {
                    MessageId::Integer(value) => Some(value),
                    MessageId::Text(_) => None,
                };
                Ok(
                    json!({"candidate_instance_key":slot.instance_key,"label_key":key,
                "input_slot":index,"retrieval_rank":slot.input.rank,"final_rank":index+1,
                "identity":null,"message_id":message_id,"conversation_id":slot.conversation_id,
                "candidate_text":{"sha256":slot.input.text_sha256,"utf8_bytes":slot.input.bytes},
                "sent_text":null,"source_sha256":slot.input.source_sha256,
                "original_score":number(slot.original_score)?,"rerank_score":null,
                "label":indexed.get(&key).copied().unwrap_or("unknown")}),
                )
            })
            .collect()
    }

    /// Check the complete final permutation against the pinned typed association.
    /// Null string projection is allowed only with this original pool available.
    pub(crate) fn verify_recovery(&self, final_slots: &[Value]) -> Result<Vec<MessageId>> {
        ensure!(
            final_slots.len() == POOL_SIZE,
            "REGRESSION_FIXED_ID_RECOVERY_MISMATCH"
        );
        let mut seen = HashSet::new();
        final_slots
            .iter()
            .enumerate()
            .map(|(final_index, output)| {
                let index = output["input_slot"]
                    .as_u64()
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or_else(|| anyhow::anyhow!("REGRESSION_FIXED_ID_RECOVERY_MISMATCH"))?;
                let slot = self
                    .slots
                    .get(index)
                    .ok_or_else(|| anyhow::anyhow!("REGRESSION_FIXED_ID_RECOVERY_MISMATCH"))?;
                let projection = match slot.input.message_id {
                    MessageId::Integer(value) => json!(value),
                    MessageId::Text(_) => Value::Null,
                };
                ensure!(
                    seen.insert(index)
                        && output["retrieval_rank"] == json!(slot.input.rank)
                        && output["final_rank"] == json!(final_index + 1)
                        && output["candidate_instance_key"] == slot.instance_key
                        && output["message_id"] == projection
                        && output["identity"].is_null()
                && output["conversation_id"] == json!(slot.conversation_id),
                "REGRESSION_FIXED_ID_RECOVERY_MISMATCH"
            );
            ensure!(original_score_matches(&output["original_score"],slot.original_score)
                && output["candidate_text"] == json!({"sha256":slot.input.text_sha256,"utf8_bytes":slot.input.bytes})
                && output["source_sha256"] == slot.input.source_sha256
                && output["label_key"] == json!({"query_sha256":self.window.query_sha256,
                    "label_text_sha256":slot.input.text_sha256,"label_policy_sha256":self.label_policy_sha256}),
                "REGRESSION_FIXED_ID_RECOVERY_MISMATCH");
                Ok(slot.input.message_id.clone())
            })
            .collect()
    }
}

pub(crate) struct WindowResult {
    pub(crate) question: Value,
    pub(crate) trace: RequestTrace,
    pub(crate) identity: Option<CallIdentity>,
    /// Only documents proven in an actual POST attempt enter label subjects.
    pub(crate) label_subjects: Vec<Value>,
    pub(crate) recovery: Value,
}

impl WindowResult {
    /// Same private label-subjects schema as the shared on/off collectors. Only
    /// an observed POST's exact submitted text is eligible for this payload.
    pub(crate) fn label_subject_cache(&self, pool: &PreparedPool) -> Result<Option<Value>> {
        ensure!(
            self.question["qid"] == pool.window.qid
                && self.question["ordered_pool_sha256"] == pool.ordered_pool_sha256,
            "REGRESSION_FIXED_SUBMISSION_MISMATCH"
        );
        if self.label_subjects.is_empty() {
            return Ok(None);
        }
        ensure!(
            self.label_subjects.len() == POOL_SIZE,
            "REGRESSION_FIXED_SUBMISSION_MISMATCH"
        );
        let query = TextDigest::of(&pool.window.query);
        Ok(Some(
            json!({"schema":"cass.regression-label-subjects.v1","qid":pool.window.qid,
            "query":{"utf8":pool.window.query,"sha256":query.sha256,"utf8_bytes":query.utf8_bytes},
            "label_policy_sha256":pool.label_policy_sha256,"candidates":self.label_subjects}),
        ))
    }
}

fn milliseconds(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn failure_code(error: &anyhow::Error) -> String {
    if let Some(error) = error.downcast_ref::<RerankError>() {
        return error.to_string();
    }
    let input_code = super::input::error_code(error);
    if input_code != "REGRESSION_INPUT_FAILED" {
        return input_code.into();
    }
    const CODES: &[&str] = &[
        "REGRESSION_FIXED_BACKEND_FAILED",
        "REGRESSION_FIXED_BACKEND_IDENTITY_MISMATCH",
        "REGRESSION_FIXED_DOCUMENT_IDENTITY_MISMATCH",
        "REGRESSION_FIXED_DOCUMENT_UTF8_MISMATCH",
        "REGRESSION_FIXED_ID_RECOVERY_MISMATCH",
        "REGRESSION_FIXED_INPUT_PIN_MISMATCH",
        "REGRESSION_FIXED_LABEL_MISMATCH",
        "REGRESSION_FIXED_NONFINITE_SCORE",
        "REGRESSION_FIXED_POOL_BINDING_MISMATCH",
        "REGRESSION_FIXED_QUERY_IDENTITY_MISMATCH",
        "REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH",
        "REGRESSION_FIXED_REPORT_FAILED",
        "REGRESSION_FIXED_SCORE_COUNT_MISMATCH",
        "REGRESSION_FIXED_SUBMISSION_MISMATCH",
        "REGRESSION_FIXED_SUITE_MISMATCH",
        "REGRESSION_FIXED_TRACE_FAILED",
        "REGRESSION_FIXED_UNREPRESENTABLE_CONVERSATION",
        "REGRESSION_FIXED_UNREPRESENTABLE_SCORE",
        "REGRESSION_FIXED_UNSCOREABLE_POOL",
        "REGRESSION_FIXED_WINDOW_PIN_MISMATCH",
    ];
    error
        .chain()
        .find_map(|cause| {
            CODES
                .iter()
                .copied()
                .find(|code| cause.to_string() == *code)
        })
        .unwrap_or("REGRESSION_FIXED_BACKEND_FAILED")
        .into()
}

fn http_counts(trace: &RequestTrace) -> Value {
    let responses = trace
        .requests
        .iter()
        .filter(|r| r.http_status.is_some())
        .count();
    json!({"scope":"rerank-client","http_attempts":trace.requests.len(),
        "http_response_observed":responses,"delivery_unknown":trace.requests.len()-responses,
        "model_executions":if trace.requests.is_empty() {Some(0)} else {None::<usize>},
        "basis":if trace.requests.is_empty() {"not-called"} else {"observed-client"}})
}

fn submitted_documents(
    pool: &PreparedPool,
    documents: &[String],
    trace: &RequestTrace,
) -> Result<bool> {
    let posts: Vec<_> = trace
        .requests
        .iter()
        .filter(|r| r.method == "POST")
        .collect();
    ensure!(posts.len() <= 1, "REGRESSION_FIXED_SUBMISSION_MISMATCH");
    let Some(post) = posts.first() else {
        return Ok(false);
    };
    ensure!(
        post.query.as_ref() == Some(&TextDigest::of(&pool.window.query))
            && post.json_body_sha256.as_ref().is_some_and(|v| is_sha(v)),
        "REGRESSION_FIXED_SUBMISSION_MISMATCH"
    );
    let sent = post
        .documents
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("REGRESSION_FIXED_SUBMISSION_MISMATCH"))?;
    ensure!(
        sent.len() == POOL_SIZE && documents.len() == POOL_SIZE,
        "REGRESSION_FIXED_SUBMISSION_MISMATCH"
    );
    for (index, (submitted, text)) in sent.iter().zip(documents).enumerate() {
        ensure!(
            submitted.input_slot == index && submitted.text == TextDigest::of(text),
            "REGRESSION_FIXED_SUBMISSION_MISMATCH"
        );
    }
    Ok(true)
}

/// Execute one already prepared window through the existing backend trait.
/// Backend construction is lazy: an unscoreable pool makes zero factory/call
/// requests. Every question owns its trace, including failures. The caller must
/// retain all nine results and persist them in a fresh private run root.
pub(crate) fn score_window(
    pool: &PreparedPool,
    labels: &[LabelRecord],
    policy_sha: &str,
    documents: &[String],
    provider: ProviderChoice,
    factory: impl FnOnce(Arc<Mutex<RequestTrace>>) -> Result<Box<dyn RerankBackend>>,
) -> Result<WindowResult> {
    let started = Instant::now();
    let mut slots = pool.original_slots(labels, policy_sha)?;
    let mut failure: Option<String> = None;
    let mut identity = None;
    let trace = Arc::new(Mutex::new(RequestTrace::default()));
    let mut scores = None;
    let mut response_http_requests = None;
    let mut rerank_ms = 0.0;
    let mut identity_before_ms = 0.0;
    if pool.slots.iter().any(|s| !s.input.scoreable) {
        failure = Some("REGRESSION_FIXED_UNSCOREABLE_POOL".into());
    } else {
        let call = (|| -> Result<_> {
            let identity_started = Instant::now();
            ensure!(
                documents.len() == POOL_SIZE,
                "REGRESSION_FIXED_DOCUMENT_IDENTITY_MISMATCH"
            );
            for (text, slot) in documents.iter().zip(&pool.slots) {
                ensure!(
                    text.len() as u64 == slot.input.bytes
                        && digest(text.as_bytes()) == slot.input.text_sha256,
                    "REGRESSION_FIXED_DOCUMENT_IDENTITY_MISMATCH"
                );
            }
            identity_before_ms = milliseconds(identity_started);
            let backend = factory(trace.clone())?;
            ensure!(
                backend.provider() == provider,
                "REGRESSION_FIXED_BACKEND_IDENTITY_MISMATCH"
            );
            let score_started = Instant::now();
            let response = backend.rerank(&pool.window.query, documents);
            rerank_ms = milliseconds(score_started);
            response.map_err(anyhow::Error::new)
        })();
        match call {
            Err(error) => failure = Some(failure_code(&error)),
            Ok(response) => {
                response_http_requests = Some(response.http_requests);
                identity = Some(response.identity.clone());
                if response.scores.len() != POOL_SIZE {
                    failure = Some("REGRESSION_FIXED_SCORE_COUNT_MISMATCH".into());
                } else if response
                    .identity
                    .actual_provider
                    .is_some_and(|p| p != provider)
                    || response
                        .identity
                        .actual_model
                        .as_deref()
                        .is_some_and(|m| !provider.accepts_model(m))
                {
                    failure = Some("REGRESSION_FIXED_BACKEND_IDENTITY_MISMATCH".into());
                } else {
                    match stable_rank_order(&response.scores) {
                        Ok(order) => scores = Some((response.scores, order)),
                        Err(_) => failure = Some("REGRESSION_FIXED_NONFINITE_SCORE".into()),
                    }
                }
            }
        }
    }
    let trace = trace
        .lock()
        .map_err(|_| anyhow::anyhow!("REGRESSION_FIXED_TRACE_FAILED"))?
        .clone();
    let submitted = match submitted_documents(pool, documents, &trace) {
        Ok(value) => value,
        Err(_) => {
            failure = Some("REGRESSION_FIXED_SUBMISSION_MISMATCH".into());
            false
        }
    };
    if failure.is_none() && !submitted {
        failure = Some("REGRESSION_FIXED_SUBMISSION_MISMATCH".into());
    }
    if failure.is_none()
        && (response_http_requests != Some(trace.requests.len())
            || !trace.requests.iter().any(|r| {
                r.method == "POST"
                    && r.http_status
                        .is_some_and(|status| (200..300).contains(&status))
            }))
    {
        failure = Some("REGRESSION_FIXED_SUBMISSION_MISMATCH".into());
    }
    let mut subjects = Vec::new();
    if submitted {
        for (index, (slot, text)) in slots.iter_mut().zip(documents).enumerate() {
            slot["sent_text"] = serde_json::to_value(TextDigest::of(text))?;
            let text_digest = TextDigest::of(text);
            subjects.push(
                json!({"candidate_instance_key":pool.slots[index].instance_key,
                "label_key":slot["label_key"],"text":{"utf8":text,
                    "sha256":text_digest.sha256,"utf8_bytes":text_digest.utf8_bytes}}),
            );
        }
    }
    if failure.is_none() {
        let (scores, order) =
            scores.ok_or_else(|| anyhow::anyhow!("REGRESSION_FIXED_SCORE_COUNT_MISMATCH"))?;
        slots = order
            .iter()
            .enumerate()
            .map(|(final_index, &input_index)| {
                let mut slot = slots[input_index].clone();
                slot["rerank_score"] = json!(scores[input_index]);
                slot["final_rank"] = json!(final_index + 1);
                slot
            })
            .collect();
    }
    pool.verify_recovery(&slots)?;
    let succeeded = failure.is_none();
    let timed_out = failure.as_deref().is_some_and(|v| v.starts_with("timeout"));
    let question = json!({"qid":pool.window.qid,"query_sha256":pool.window.query_sha256,
        "requested_n":POOL_SIZE,"actual_n":POOL_SIZE,"pool_complete":true,
        "terminal":if succeeded {"SUCCESS"} else {"FAILED"},
        "full_requested_n_claim":succeeded,"rerank_applied":succeeded,
        "ordered_pool_sha256":pool.ordered_pool_sha256,"slots":slots,
        "pages":[],"window_evidence":null,"partial":false,"timed_out":timed_out,
        "failure_code":failure,"lexical_statistics_status":"NOT_USED","lexical_statistics_sha256":null,
        "cost":{"identity_before_ms":identity_before_ms,"identity_after_ms":0.0,"retrieval_ms":0.0,
            "rerank_client_ms":rerank_ms,"model_execution_ms":null,"paging_ms":0.0,
            "question_total_ms":milliseconds(started),"http":[http_counts(&trace)],
            "resource_measurements":[]}});
    Ok(WindowResult {
        question,
        trace,
        identity,
        label_subjects: subjects,
        recovery: pool.recovery_evidence(),
    })
}

/// Run all nine admitted pools with independent request evidence. Preparation
/// has already rejected every unsupported carrier before this function starts.
/// The caller owns the guarded reader and the existing backend factory, and
/// later persists these results under the admitted fresh private run root.
/// Reading one window's documents unsuccessfully preserves that window's 200
/// original slots and does not erase earlier or later windows' actual requests.
pub(crate) fn collect_prepared(
    pools: &[PreparedPool],
    inputs: &ValidatedInputs,
    provider: ProviderChoice,
    mut read_registered: impl FnMut(&str) -> Result<Vec<u8>>,
    mut factory: impl FnMut(ProviderChoice, Arc<Mutex<RequestTrace>>) -> Result<Box<dyn RerankBackend>>,
) -> Result<Vec<WindowResult>> {
    ensure!(
        pools.len() == QIDS.len() && inputs.windows.len() == QIDS.len(),
        "REGRESSION_FIXED_SUITE_MISMATCH"
    );
    for (index, pool) in pools.iter().enumerate() {
        ensure!(
            pool.window.qid == QIDS[index]
                && inputs.windows[index].qid == QIDS[index]
                && pool.window.query_sha256 == inputs.windows[index].query_sha256
                && pool.suite_sha256 == inputs.suite_sha256
                && pool.input_manifest_sha256 == inputs.input_manifest_sha256
                && pool.windows_file_sha256 == inputs.windows_file_sha256,
            "REGRESSION_FIXED_INPUT_PIN_MISMATCH"
        );
        ensure!(
            pool.labels_sha256 == inputs.labels_sha256
                && pool.label_policy_sha256 == inputs.label_policy_sha256,
            "REGRESSION_FIXED_LABEL_MISMATCH"
        );
    }
    pools
        .iter()
        .map(|pool| {
            let started = Instant::now();
            let document_started = Instant::now();
            let documents = if pool.slots.iter().any(|s| !s.input.scoreable) {
                Ok(Vec::new())
            } else {
                pool.documents(&mut read_registered)
            };
            let document_ms = milliseconds(document_started);
            let mut result = match documents {
                Ok(documents) => score_window(
                    pool,
                    &inputs.labels,
                    &inputs.label_policy_sha256,
                    &documents,
                    provider,
                    |trace| factory(provider, trace),
                )?,
                Err(error) => {
                    let mut failed = score_window(
                        pool,
                        &inputs.labels,
                        &inputs.label_policy_sha256,
                        &[],
                        provider,
                        |_| anyhow::bail!("REGRESSION_FIXED_DOCUMENT_IDENTITY_MISMATCH"),
                    )?;
                    failed.question["failure_code"] = json!(failure_code(&error));
                    failed
                }
            };
            let checked = result.question["cost"]["identity_before_ms"]
                .as_f64()
                .ok_or_else(|| anyhow::anyhow!("REGRESSION_FIXED_REPORT_FAILED"))?;
            result.question["cost"]["identity_before_ms"] = json!(checked + document_ms);
            result.question["cost"]["question_total_ms"] = json!(milliseconds(started));
            Ok(result)
        })
        .collect()
}

/// Summary fields may only come from facts known and equal in every question.
/// A failed or unknown identity does not inherit a neighbour's claimed model.
pub(crate) fn common_identity(
    results: &[WindowResult],
) -> (Option<ProviderChoice>, Option<String>) {
    if results.len() != QIDS.len() {
        return (None, None);
    }
    let provider = results
        .first()
        .and_then(|r| r.identity.as_ref())
        .and_then(|i| i.actual_provider);
    let model = results
        .first()
        .and_then(|r| r.identity.as_ref())
        .and_then(|i| i.actual_model.clone());
    let provider = provider.filter(|p| {
        results
            .iter()
            .all(|r| r.identity.as_ref().and_then(|i| i.actual_provider) == Some(*p))
    });
    let model = model.filter(|m| {
        results
            .iter()
            .all(|r| r.identity.as_ref().and_then(|i| i.actual_model.as_ref()) == Some(m))
    });
    (provider, model)
}

/// The fixed mode never uses SHORT_WINDOW. One failed question makes the
/// aggregate FAILED, while every already collected request remains in results.
/// Complete execution is NOT_EVALUATED until a separate label comparison runs.
pub(crate) fn aggregate_outcome(
    results: &[WindowResult],
) -> Result<(&'static str, &'static str, Option<String>)> {
    ensure!(
        results.len() == QIDS.len(),
        "REGRESSION_FIXED_REPORT_FAILED"
    );
    let mut failure = None;
    for (index, result) in results.iter().enumerate() {
        ensure!(
            result.question["qid"] == QIDS[index]
                && result.question["actual_n"] == POOL_SIZE
                && result.question["slots"]
                    .as_array()
                    .is_some_and(|s| s.len() == POOL_SIZE),
            "REGRESSION_FIXED_REPORT_FAILED"
        );
        match result.question["terminal"].as_str() {
            Some("SUCCESS") => ensure!(
                result.question["failure_code"].is_null()
                    && result.question["rerank_applied"] == true,
                "REGRESSION_FIXED_REPORT_FAILED"
            ),
            Some("FAILED") => {
                let code = result.question["failure_code"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("REGRESSION_FIXED_REPORT_FAILED"))?;
                if failure.is_none() {
                    failure = Some(code.into());
                }
            }
            _ => anyhow::bail!("REGRESSION_FIXED_REPORT_FAILED"),
        }
    }
    Ok(if failure.is_some() {
        ("FAILED", "FAILED", failure)
    } else {
        ("SUCCESS", "NOT_EVALUATED", None)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::search::rerank::types::{RerankFailureReason, RerankResponse};

    const GOLDEN_POOL: &str = "3fe2c279f9465ce655cada6fb7d000a2089fb96539236cafb8de9c0301880164";
    const TOKENS: [&str; 23] = [
        "0",
        "0.0",
        "-0",
        "-0.0",
        "1",
        "1.0",
        "0.0001",
        "1e-5",
        "1e-6",
        "1e-7",
        "1e15",
        "1e16",
        "1e20",
        "1e21",
        "0.1",
        "2.2250738585072014e-308",
        "5e-324",
        "1.7976931348623157e308",
        "-1.9799289335064246e+301",
        "9007199254740993",
        "9223372036854775807",
        "-9223372036854775808",
        "18446744073709551615",
    ];

    fn typed_id(rank: usize) -> MessageId {
        match rank {
            1 => MessageId::Integer(1),
            2 => MessageId::Text("1".into()),
            3 => MessageId::Integer(i64::MIN),
            4 => MessageId::Integer(i64::MAX),
            5 => MessageId::Text("SYN_合成😀\n\"\\/".into()),
            6 => MessageId::Text("00123".into()),
            _ => MessageId::Integer(rank as i64 + 10000),
        }
    }

    // Only synthetic public strings. No fixture file or actual suite is read.
    fn fixture(
        golden: bool,
        override_score: Option<&str>,
        conversation: Value,
        unscoreable: bool,
    ) -> (ValidatedInputs, Vec<u8>, Vec<ExpectedPool>, Vec<String>) {
        let documents: Vec<_> = (1..=POOL_SIZE)
            .map(|rank| format!("Synthetic document {rank}. 无私文。\n"))
            .collect();
        let mut raw = Vec::new();
        let mut windows = Vec::new();
        let mut pins = Vec::new();
        for qid in QIDS {
            let query = format!("Synthetic query {qid}");
            let mut items = Vec::new();
            for rank in 1..=POOL_SIZE {
                let token = override_score.unwrap_or(TOKENS[(rank - 1) % TOKENS.len()]);
                let text_sha = if golden {
                    digest(format!("SYN-TEXT-{rank}").as_bytes())
                } else {
                    digest(documents[rank - 1].as_bytes())
                };
                let bytes = if golden {
                    32
                } else {
                    documents[rank - 1].len() as u64
                };
                let mut item = serde_json::to_vec(&json!({"rank":rank,"message_id":typed_id(rank),
                    "conversation_id":conversation,"text_sha256":text_sha,"bytes":bytes,
                    "source_sha256":digest(b"SYN-SOURCE"),"text_path":format!("synthetic/{rank}.txt"),
                    "scoreable":!(unscoreable && qid == "N01" && rank == 50),
                    "fallback_reason":if unscoreable && qid == "N01" && rank == 50 {json!("structural_unscoreable")} else {Value::Null}})).unwrap();
                assert_eq!(item.pop(), Some(b'}'));
                item.extend(format!(",\"original_score\":{token}}}").as_bytes());
                items.push(item);
            }
            let mut line = serde_json::to_vec(&json!({"qid":qid,"query":query,
                "query_sha256":digest(query.as_bytes())}))
            .unwrap();
            line.pop();
            line.extend(b",\"items\":[");
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    line.push(b',');
                }
                line.extend(item);
            }
            line.extend(b"]}");
            windows.push(serde_json::from_slice::<InputWindow>(&line).unwrap());
            raw.extend(&line);
            raw.push(b'\n');
            pins.push(ExpectedPool {
                qid: qid.into(),
                ordered_pool_sha256: if golden {
                    GOLDEN_POOL.into()
                } else {
                    "0".repeat(64)
                },
            });
        }
        let inputs = ValidatedInputs {
            suite_root: PathBuf::from("/synthetic-not-opened"),
            suite_sha256: digest(b"synthetic-suite"),
            source_inventory_sha256: digest(b"synthetic-inventory"),
            input_manifest_sha256: digest(b"synthetic-input"),
            windows_file_sha256: digest(&raw),
            labels_sha256: digest(b"synthetic-labels"),
            label_freeze_sha256: digest(b"synthetic-freeze"),
            label_policy_sha256: digest(b"synthetic-policy"),
            windows,
            labels: Vec::new(),
            assets: Vec::new(),
            not_user_confirmed: true,
            not_an_independent_test_set: true,
        };
        if !golden && override_score.is_none() && conversation.as_i64().is_some() {
            // For execution-only fixtures, construct the reference tuple bytes
            // directly from six fixture fields and literal codec tokens. The
            // separate GOLDEN_POOL test is the independent Python byte oracle.
            for (window, pin) in inputs.windows.iter().zip(&mut pins) {
                let mut rows = vec![b'['];
                for (index, item) in window.items.iter().enumerate() {
                    if index != 0 {
                        rows.push(b',');
                    }
                    let mut row = serde_json::to_vec(&(
                        item.rank,
                        &item.message_id,
                        &item.conversation_id,
                        &item.text_sha256,
                        item.bytes,
                        &item.source_sha256,
                    ))
                    .unwrap();
                    row.pop();
                    row.push(b',');
                    row.extend(
                        super::super::fixed_encoding::encode_numeric(
                            TOKENS[index % TOKENS.len()].as_bytes(),
                        )
                        .unwrap()
                        .canonical,
                    );
                    row.push(b']');
                    rows.extend(row);
                }
                rows.push(b']');
                pin.ordered_pool_sha256 = digest(&rows);
            }
        }
        (inputs, raw, pins, documents)
    }

    struct FakeBackend {
        trace: Arc<Mutex<RequestTrace>>,
        calls: Arc<AtomicUsize>,
        fault: &'static str,
    }

    impl RerankBackend for FakeBackend {
        fn provider(&self) -> ProviderChoice {
            ProviderChoice::BgeLocal
        }

        fn rerank(
            &self,
            query: &str,
            documents: &[String],
        ) -> std::result::Result<RerankResponse, RerankError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut trace = self.trace.lock().unwrap();
            let body =
                json!({"model":"BAAI/bge-reranker-v2-m3","query":query,"documents":documents});
            let index = trace.begin("POST", "/rerank", Some(&body))?;
            if self.fault == "disconnect" {
                return Err(RerankError::new(RerankFailureReason::TransportError));
            }
            trace.response(index, if self.fault == "http500" { 500 } else { 200 })?;
            if self.fault == "http500" {
                return Err(RerankError::with_status(
                    RerankFailureReason::HttpError,
                    500,
                ));
            }
            let scores = match self.fault {
                "short" => vec![1.0; 199],
                "extra" => vec![1.0; 201],
                "nan" => vec![f64::NAN; 200],
                "reverse" => (0..200).map(|i| i as f64).collect(),
                _ => vec![1.0; 200],
            };
            Ok(RerankResponse {
                scores,
                identity: CallIdentity {
                    actual_provider: Some(ProviderChoice::BgeLocal),
                    actual_model: Some(
                        if self.fault == "model" {
                            "wrong-model"
                        } else {
                            "BAAI/bge-reranker-v2-m3"
                        }
                        .into(),
                    ),
                    serving_provider: None,
                },
                http_requests: 1,
                duration_ms: 0,
            })
        }
    }

    fn execute(
        pool: &PreparedPool,
        documents: &[String],
        fault: &'static str,
        calls: Arc<AtomicUsize>,
    ) -> WindowResult {
        score_window(
            pool,
            &[],
            &digest(b"synthetic-policy"),
            documents,
            ProviderChoice::BgeLocal,
            |trace| {
                Ok(Box::new(FakeBackend {
                    trace,
                    calls,
                    fault,
                }))
            },
        )
        .unwrap()
    }

    #[test]
    fn python_whole_200_golden_and_typed_instance_keys() {
        let (inputs, raw, pins, _) = fixture(true, None, json!(17), false);
        let pools = prepare_pools(&inputs, &raw, &pins).unwrap();
        assert_eq!(pools.len(), 9);
        for pool in &pools {
            assert_eq!(digest(&pool.ordered_bytes), GOLDEN_POOL);
            assert_eq!(
                pool.slots[0].instance_key,
                "f058dbc82ae727ebd3560f11edf9a287c441e7322d5f12b2af2dd6e59fdaf4b7"
            );
            assert_eq!(
                pool.slots[1].instance_key,
                "ce0cef5192a83a8e8625f4dab936a7cde79be926e2e09505916c7cb8233a51e1"
            );
            assert_eq!(
                pool.slots[4].instance_key,
                "8a2dfc5aad8379351254668db53e338df47327d4baf619edfd46b590fa4ea612"
            );
            let slots = pool
                .original_slots(&[], &inputs.label_policy_sha256)
                .unwrap();
            assert_eq!(
                pool.verify_recovery(&slots).unwrap()[0],
                MessageId::Integer(1)
            );
            assert_eq!(
                pool.verify_recovery(&slots).unwrap()[1],
                MessageId::Text("1".into())
            );
            assert_eq!(slots[0]["message_id"], json!(1));
            assert!(slots[1]["message_id"].is_null());
            assert_eq!(slots[22]["original_score"].as_u64(), Some(u64::MAX));
            assert_eq!(
                slots[3]["original_score"].as_f64().unwrap().to_bits(),
                (-0.0_f64).to_bits()
            );
        }
    }

    #[test]
    fn nine_complete_windows_ties_and_permutation_preserve_all_original_identities() {
        let (inputs, raw, pins, documents) = fixture(false, None, json!(17), false);
        let pools = prepare_pools(&inputs, &raw, &pins).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut results = Vec::new();
        for pool in &pools {
            let tie = execute(pool, &documents, "tie", calls.clone());
            assert_eq!(tie.question["terminal"], "SUCCESS");
            let tie_slots = tie.question["slots"].as_array().unwrap();
            assert_eq!(
                pool.verify_recovery(tie_slots).unwrap(),
                pool.slots
                    .iter()
                    .map(|s| s.input.message_id.clone())
                    .collect::<Vec<_>>()
            );
            let reverse = execute(pool, &documents, "reverse", calls.clone());
            let reversed = pool
                .verify_recovery(reverse.question["slots"].as_array().unwrap())
                .unwrap();
            assert_eq!(
                reversed,
                pool.slots
                    .iter()
                    .rev()
                    .map(|s| s.input.message_id.clone())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                reverse.question["slots"][199]["original_score"],
                tie_slots[0]["original_score"]
            );
            assert_eq!(tie.label_subjects.len(), 200);
            assert!(tie.trace.model_requests.is_none());
            assert!(tie.question["cost"]["http"][0]["model_executions"].is_null());
            results.push(tie);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 18);
        assert_eq!(
            aggregate_outcome(&results).unwrap(),
            ("SUCCESS", "NOT_EVALUATED", None)
        );
        assert_eq!(
            common_identity(&results),
            (
                Some(ProviderChoice::BgeLocal),
                Some("BAAI/bge-reranker-v2-m3".into())
            )
        );
        results[0].identity = None;
        assert_eq!(common_identity(&results), (None, None));
        assert_eq!(
            aggregate_outcome(&results).unwrap(),
            ("SUCCESS", "NOT_EVALUATED", None)
        );
    }

    #[test]
    fn unscoreable_pool_is_atomic_unsent_and_keeps_unsure_and_other_window_calls() {
        let (mut inputs, raw, pins, documents) = fixture(false, None, json!(17), true);
        let key = LabelKey {
            query_sha256: inputs.windows[0].query_sha256.clone(),
            label_text_sha256: inputs.windows[0].items[49].text_sha256.clone(),
            label_policy_sha256: inputs.label_policy_sha256.clone(),
        };
        inputs.labels.push(LabelRecord {
            key,
            value: "unsure".into(),
        });
        let pools = prepare_pools(&inputs, &raw, &pins).unwrap();
        let result = score_window(
            &pools[0],
            &inputs.labels,
            &inputs.label_policy_sha256,
            &[],
            ProviderChoice::BgeLocal,
            |_| -> Result<Box<dyn RerankBackend>> { panic!("unscoreable factory must not run") },
        )
        .unwrap();
        assert_eq!(
            result.question["failure_code"],
            "REGRESSION_FIXED_UNSCOREABLE_POOL"
        );
        assert_eq!(result.question["terminal"], "FAILED");
        assert_eq!(result.question["slots"][49]["label"], "unsure");
        assert_eq!(result.question["slots"][0]["label"], "unknown");
        assert!(result.trace.requests.is_empty() && result.label_subjects.is_empty());
        assert_eq!(
            pools[0]
                .verify_recovery(result.question["slots"].as_array().unwrap())
                .unwrap()
                .len(),
            200
        );
        for slot in result.question["slots"].as_array().unwrap() {
            assert!(slot["rerank_score"].is_null());
        }
        let (good, good_raw, good_pins, _) = fixture(false, None, json!(17), false);
        let good_pools = prepare_pools(&good, &good_raw, &good_pins).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            execute(&good_pools[1], &documents, "tie", calls.clone()).question["terminal"],
            "SUCCESS"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn backend_failure_keeps_full_original_order_and_actual_attempts() {
        let (inputs, raw, pins, documents) = fixture(false, None, json!(17), false);
        let pools = prepare_pools(&inputs, &raw, &pins).unwrap();
        for fault in ["short", "extra", "nan", "model", "http500", "disconnect"] {
            let result = execute(&pools[0], &documents, fault, Arc::new(AtomicUsize::new(0)));
            assert_eq!(result.question["terminal"], "FAILED");
            assert_eq!(result.question["rerank_applied"], false);
            let slots = result.question["slots"].as_array().unwrap();
            assert_eq!(
                pools[0].verify_recovery(slots).unwrap(),
                pools[0]
                    .slots
                    .iter()
                    .map(|s| s.input.message_id.clone())
                    .collect::<Vec<_>>()
            );
            assert!(slots.iter().all(|s| s["rerank_score"].is_null()));
            assert_eq!(result.trace.requests.len(), 1);
            assert_eq!(result.label_subjects.len(), 200);
            assert_eq!(
                result.trace.requests[0].http_status.is_some(),
                fault != "disconnect"
            );
            assert!(result.question["cost"]["http"][0]["model_executions"].is_null());
        }
    }

    #[test]
    fn raw_pins_pool_pins_and_typed_views_cannot_be_substituted() {
        let (mut inputs, raw, mut pins, _) = fixture(true, None, json!(17), false);
        pins[0].ordered_pool_sha256 = digest(b"wrong");
        assert_eq!(
            prepare_pools(&inputs, &raw, &pins)
                .err()
                .unwrap()
                .to_string(),
            "REGRESSION_FIXED_POOL_BINDING_MISMATCH"
        );
        pins[0].ordered_pool_sha256 = GOLDEN_POOL.into();
        inputs.windows[0].items[1].message_id = MessageId::Integer(1);
        assert_eq!(
            prepare_pools(&inputs, &raw, &pins)
                .err()
                .unwrap()
                .to_string(),
            "REGRESSION_FIXED_RAW_SCORE_BINDING_MISMATCH"
        );
        inputs.windows_file_sha256 = digest(b"wrong");
        assert_eq!(
            prepare_pools(&inputs, &raw, &pins)
                .err()
                .unwrap()
                .to_string(),
            "REGRESSION_FIXED_WINDOW_PIN_MISMATCH"
        );
    }

    #[test]
    fn carrier_gaps_fail_before_any_backend_and_never_cast_or_null() {
        for token in ["18446744073709551616", "-9223372036854775809"] {
            let (inputs, raw, pins, _) = fixture(false, Some(token), json!(17), false);
            assert_eq!(
                prepare_pools(&inputs, &raw, &pins)
                    .err()
                    .unwrap()
                    .to_string(),
                "REGRESSION_FIXED_UNREPRESENTABLE_SCORE"
            );
        }
        for value in [
            json!(u64::MAX),
            json!(1.0),
            json!("17"),
            json!({"id":17}),
            json!([]),
        ] {
            let (inputs, raw, pins, _) = fixture(false, None, value, false);
            assert_eq!(
                prepare_pools(&inputs, &raw, &pins)
                    .err()
                    .unwrap()
                    .to_string(),
                "REGRESSION_FIXED_UNREPRESENTABLE_CONVERSATION"
            );
        }
    }

    #[test]
    fn recovery_rejects_duplicate_slot_changed_key_cast_and_integer_drop() {
        let (inputs, raw, pins, _) = fixture(true, None, json!(17), false);
        let pools = prepare_pools(&inputs, &raw, &pins).unwrap();
        let original = pools[0]
            .original_slots(&[], &inputs.label_policy_sha256)
            .unwrap();
        for fault in ["duplicate", "key", "cast", "drop", "rank", "original_score"] {
            let mut slots = original.clone();
            match fault {
                "duplicate" => slots[1] = slots[0].clone(),
                "key" => slots[0]["candidate_instance_key"] = json!(digest(b"wrong")),
                "cast" => slots[1]["message_id"] = json!(1),
                "drop" => slots[0]["message_id"] = Value::Null,
                "original_score" => slots[0]["original_score"] = json!(777),
                _ => slots[0]["retrieval_rank"] = json!(2),
            }
            assert_eq!(
                pools[0].verify_recovery(&slots).err().unwrap().to_string(),
                "REGRESSION_FIXED_ID_RECOVERY_MISMATCH"
            );
        }
    }

    #[test]
    fn registered_document_digest_and_submission_order_fail_closed() {
        let (inputs, raw, pins, documents) = fixture(false, None, json!(17), false);
        let pools = prepare_pools(&inputs, &raw, &pins).unwrap();
        let mut index = 0;
        assert_eq!(
            pools[0]
                .documents(|_| {
                    let value = documents[index].as_bytes().to_vec();
                    index += 1;
                    Ok(value)
                })
                .unwrap(),
            documents
        );
        assert_eq!(
            pools[0]
                .documents(|_| Ok(b"wrong bytes".to_vec()))
                .err()
                .unwrap()
                .to_string(),
            "REGRESSION_FIXED_DOCUMENT_IDENTITY_MISMATCH"
        );
        let mut swapped = documents.clone();
        swapped.swap(0, 1);
        let result = score_window(
            &pools[0],
            &[],
            &inputs.label_policy_sha256,
            &swapped,
            ProviderChoice::BgeLocal,
            |_| -> Result<Box<dyn RerankBackend>> {
                panic!("changed documents must not call backend")
            },
        )
        .unwrap();
        assert_eq!(
            result.question["failure_code"],
            "REGRESSION_FIXED_DOCUMENT_IDENTITY_MISMATCH"
        );
        assert!(result.trace.requests.is_empty());
        let mut trace = RequestTrace::default();
        trace
            .begin(
                "POST",
                "/rerank",
                Some(&json!({"query":pools[0].window.query,"documents":swapped})),
            )
            .unwrap();
        assert!(submitted_documents(&pools[0], &documents, &trace).is_err());
    }

    #[test]
    fn aggregate_unsent_and_failed_read_do_not_erase_other_questions() {
        let (mut inputs, raw, pins, documents) = fixture(false, None, json!(17), true);
        inputs.labels.push(LabelRecord {
            key: LabelKey {
                query_sha256: inputs.windows[0].query_sha256.clone(),
                label_text_sha256: inputs.windows[0].items[49].text_sha256.clone(),
                label_policy_sha256: inputs.label_policy_sha256.clone(),
            },
            value: "unsure".into(),
        });
        let pools = prepare_pools(&inputs, &raw, &pins).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut reads = 0;
        let results = collect_prepared(
            &pools,
            &inputs,
            ProviderChoice::BgeLocal,
            |reference| {
                reads += 1;
                let rank = reference
                    .strip_prefix("synthetic/")
                    .unwrap()
                    .strip_suffix(".txt")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                Ok(documents[rank - 1].as_bytes().to_vec())
            },
            |_, trace| {
                Ok(Box::new(FakeBackend {
                    trace,
                    calls: calls.clone(),
                    fault: "tie",
                }))
            },
        )
        .unwrap();
        assert_eq!(reads, 1600);
        assert_eq!(calls.load(Ordering::SeqCst), 8);
        assert_eq!(
            results[0].question["failure_code"],
            "REGRESSION_FIXED_UNSCOREABLE_POOL"
        );
        assert!(results[0].trace.requests.is_empty());
        assert!(
            results[1..]
                .iter()
                .all(|r| r.question["terminal"] == "SUCCESS")
        );
        assert_eq!(common_identity(&results), (None, None));
        let mut reads = 0;
        assert_eq!(
            aggregate_outcome(&results).unwrap(),
            (
                "FAILED",
                "FAILED",
                Some("REGRESSION_FIXED_UNSCOREABLE_POOL".into())
            )
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let results = collect_prepared(
            &pools,
            &inputs,
            ProviderChoice::BgeLocal,
            |reference| {
                reads += 1;
                if reads == 1 {
                    anyhow::bail!("INPUT_ASSET_DIGEST_MISMATCH");
                }
                let rank = reference
                    .strip_prefix("synthetic/")
                    .unwrap()
                    .strip_suffix(".txt")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                Ok(documents[rank - 1].as_bytes().to_vec())
            },
            |_, trace| {
                Ok(Box::new(FakeBackend {
                    trace,
                    calls: calls.clone(),
                    fault: "tie",
                }))
            },
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 7);
        assert_eq!(
            results[1].question["failure_code"],
            "INPUT_ASSET_DIGEST_MISMATCH"
        );
        assert_eq!(results[1].question["slots"].as_array().unwrap().len(), 200);
        assert!(results[1].trace.requests.is_empty());
        assert!(
            results[2..]
                .iter()
                .all(|r| r.question["terminal"] == "SUCCESS")
        );
    }
}
