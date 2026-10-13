//! Frozen fixed-candidate pool preparation and one-window execution.
//!
//! The input module supplies pinned descriptor bytes. Fixed execution never
//! opens a database, uses a search window, or constructs another transport.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Result, ensure};
use serde_json::{Number, Value, json};
use sha2::{Digest, Sha256};

use super::fixed_encoding::{NumericValue, WindowScores, original_score_sideview};
use super::off::{RunProvenance, private_files, query_manifest_bytes, write_private};
use super::types::{
    InputSlot, InputWindow, LabelKey, LabelRecord, MessageId, RegressionCommand, ValidatedInputs,
    ValidatedRun,
};
use crate::search::regression_trace::{RequestTrace, TextDigest};
use crate::search::rerank::types::{
    CallIdentity, ProviderChoice, RerankError, stable_rank_order,
};

#[cfg(test)]
use crate::search::rerank::types::RerankBackend;

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
    #[cfg(test)]
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
        #[cfg(test)]
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
                "candidate_instance_key":s.instance_key,"typed_message_id":s.input.message_id,
                "scoreable":s.input.scoreable,"fallback_reason":s.input.fallback_reason
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
    pub(crate) api_rerank: Option<crate::search::rerank::window::ApiWindowRerank>,
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
    named_error_code(error)
        .unwrap_or("REGRESSION_FIXED_BACKEND_FAILED")
        .into()
}

/// Only fixed-specific named causes change the shared dispatch error mapping.
/// Existing full-search/on/off errors keep their previous mapping.
pub(crate) fn named_error_code(error: &anyhow::Error) -> Option<&'static str> {
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
    error.chain().find_map(|cause| {
        CODES
            .iter()
            .copied()
            .find(|code| cause.to_string() == *code)
    })
}

fn http_counts(trace: &RequestTrace) -> Value {
    let responses = trace
        .requests
        .iter()
        .filter(|r| r.http_status.is_some())
        .count();
    json!({"scope":"rerank-http-v1","http_attempts":trace.requests.len(),
        "http_response_observed":responses,"delivery_unknown":trace.requests.len()-responses,
        "model_executions":if trace.requests.is_empty() {Some(0)} else {None::<usize>},
        "basis":if trace.requests.is_empty() {"not-called"} else {"observed-client"}})
}

#[cfg(test)]
fn submitted_documents(
    pool: &PreparedPool, documents: &[String], trace: &RequestTrace,
) -> Result<bool> {
    submitted_documents_with_limit(pool, documents, trace, 1)
}

fn submitted_documents_with_limit(
    pool: &PreparedPool,
    documents: &[String],
    trace: &RequestTrace,
    maximum: usize,
) -> Result<bool> {
    let posts: Vec<_> = trace
        .requests
        .iter()
        .filter(|r| r.method == "POST")
        .collect();
    ensure!(posts.len() <= maximum, "REGRESSION_FIXED_SUBMISSION_MISMATCH");
    if posts.is_empty() { return Ok(false); }
    for post in posts {
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
    }
    Ok(true)
}

/// Execute one already prepared window through the existing backend trait.
/// Backend construction is lazy: an unscoreable pool makes zero factory/call
/// requests. Every question owns its trace, including failures. The caller must
/// retain all nine results and persist them in a fresh private run root.
#[cfg(test)]
pub(crate) fn score_window(
    pool: &PreparedPool,
    labels: &[LabelRecord],
    policy_sha: &str,
    documents: &[String],
    provider: ProviderChoice,
    factory: impl FnOnce(Arc<Mutex<RequestTrace>>) -> Result<Box<dyn RerankBackend>>,
) -> Result<WindowResult> {
    score_window_with_call(pool, labels, policy_sha, documents, Some(provider), None,
        |trace, query, documents, _| {
            let backend = factory(trace)?;
            ensure!(backend.provider() == provider, "REGRESSION_FIXED_BACKEND_IDENTITY_MISMATCH");
            backend.rerank(query, documents).map_err(anyhow::Error::new)
        })
}

fn score_window_with_call(
    pool: &PreparedPool, labels: &[LabelRecord], policy_sha: &str, documents: &[String],
    provider: Option<ProviderChoice>, route: Option<&crate::search::rerank::window::ApiWindowRoute>,
    call_model: impl FnOnce(Arc<Mutex<RequestTrace>>, &str, &[String], &mut Option<crate::search::rerank::window::ApiWindowRerank>) -> Result<crate::search::rerank::types::RerankResponse>,
) -> Result<WindowResult> {
    ensure!(provider.is_some() != route.is_some(), "REGRESSION_FIXED_BACKEND_IDENTITY_MISMATCH");
    let started = Instant::now();
    let mut slots = pool.original_slots(labels, policy_sha)?;
    let mut failure: Option<String> = None;
    let mut identity = None;
    let mut api_rerank = None;
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
            let score_started = Instant::now();
            let response = call_model(trace.clone(), &pool.window.query, documents, &mut api_rerank);
            rerank_ms = milliseconds(score_started);
            response
        })();
        match call {
            Err(error) => failure = Some(failure_code(&error)),
            Ok(response) => {
                response_http_requests = Some(response.http_requests);
                identity = Some(response.identity.clone());
                if response.scores.len() != POOL_SIZE {
                    failure = Some("REGRESSION_FIXED_SCORE_COUNT_MISMATCH".into());
                } else if provider.is_some_and(|provider| {
                    response.identity.actual_provider.is_some_and(|p| p != provider)
                    || response.identity.actual_model.as_deref().is_some_and(|m| !provider.accepts_model(m))
                })
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
    let maximum = if route.is_some_and(|r| r.allow_fallback && r.fallback_profile.is_some()) { 2 } else { 1 };
    let proof = crate::search::regression_trace::validate_model_attempts(&trace, route, api_rerank.as_ref(), failure.is_none());
    let submitted = match proof.and_then(|_| submitted_documents_with_limit(pool, documents, &trace, maximum)) {
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
            || !trace.requests.iter().filter(|r| r.method == "POST").last().is_some_and(|r| {
                r.http_status.is_some_and(|status| (200..300).contains(&status))
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
        api_rerank,
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
#[cfg(test)]
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
            execute_prepared(pool, inputs, provider, &mut read_registered, |trace| {
                factory(provider, trace)
            })
        })
        .collect()
}

#[cfg(test)]
fn execute_prepared(
    pool: &PreparedPool,
    inputs: &ValidatedInputs,
    provider: ProviderChoice,
    read_registered: impl FnMut(&str) -> Result<Vec<u8>>,
    factory: impl FnOnce(Arc<Mutex<RequestTrace>>) -> Result<Box<dyn RerankBackend>>,
) -> Result<WindowResult> {
    execute_prepared_with_call(pool, inputs, Some(provider), None, read_registered,
        |trace, query, documents, _| {
            let backend = factory(trace)?;
            ensure!(backend.provider() == provider, "REGRESSION_FIXED_BACKEND_IDENTITY_MISMATCH");
            backend.rerank(query, documents).map_err(anyhow::Error::new)
        })
}

fn execute_prepared_with_call(
    pool: &PreparedPool, inputs: &ValidatedInputs, provider: Option<ProviderChoice>,
    route: Option<&crate::search::rerank::window::ApiWindowRoute>,
    read_registered: impl FnMut(&str) -> Result<Vec<u8>>,
    call_model: impl FnOnce(Arc<Mutex<RequestTrace>>, &str, &[String], &mut Option<crate::search::rerank::window::ApiWindowRerank>) -> Result<crate::search::rerank::types::RerankResponse>,
) -> Result<WindowResult> {
    let started = Instant::now();
    let document_started = Instant::now();
    let documents = if pool.slots.iter().any(|s| !s.input.scoreable) {
        Ok(Vec::new())
    } else {
        pool.documents(read_registered)
    };
    let document_ms = milliseconds(document_started);
    let mut result = match documents {
        Ok(documents) => score_window_with_call(
            pool,
            &inputs.labels,
            &inputs.label_policy_sha256,
            &documents,
            provider,
            route,
            call_model,
        )?,
        Err(error) => {
            let mut failed = score_window_with_call(
                pool,
                &inputs.labels,
                &inputs.label_policy_sha256,
                &[],
                provider,
                route,
                |_, _, _, _| anyhow::bail!("REGRESSION_FIXED_DOCUMENT_IDENTITY_MISMATCH"),
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

fn expected_pools(value: &Value, inputs: &ValidatedInputs) -> Result<Vec<ExpectedPool>> {
    const FIELDS: [&str; 9] = [
        "schema",
        "suite_sha256",
        "input_manifest_sha256",
        "windows_file_sha256",
        "labels_sha256",
        "label_freeze_sha256",
        "label_policy_sha256",
        "source_inventory_sha256",
        "windows",
    ];
    ensure!(
        value.as_object().is_some_and(
            |v| v.len() == FIELDS.len() && FIELDS.iter().all(|name| v.contains_key(*name))
        ) && value["schema"] == "cass.regression-fixed-pool.v1",
        "POOL_BINDING_MISMATCH"
    );
    for (name, expected) in [
        ("suite_sha256", &inputs.suite_sha256),
        ("input_manifest_sha256", &inputs.input_manifest_sha256),
        ("windows_file_sha256", &inputs.windows_file_sha256),
        ("labels_sha256", &inputs.labels_sha256),
        ("label_freeze_sha256", &inputs.label_freeze_sha256),
        ("label_policy_sha256", &inputs.label_policy_sha256),
        ("source_inventory_sha256", &inputs.source_inventory_sha256),
    ] {
        ensure!(
            is_sha(expected) && value[name] == *expected,
            "POOL_BINDING_MISMATCH"
        );
    }
    let windows = value["windows"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("POOL_BINDING_MISMATCH"))?;
    ensure!(
        windows.len() == QIDS.len() && inputs.windows.len() == QIDS.len(),
        "POOL_BINDING_MISMATCH"
    );
    windows
        .iter()
        .zip(&inputs.windows)
        .enumerate()
        .map(|(index, (declared, window))| {
            ensure!(
                declared.as_object().is_some_and(|v| v.len() == 4
                    && ["qid", "query_sha256", "count", "ordered_pool_sha256"]
                        .iter()
                        .all(|name| v.contains_key(*name)))
                    && declared["qid"] == QIDS[index]
                    && window.qid == QIDS[index]
                    && declared["query_sha256"] == window.query_sha256
                    && declared["count"] == POOL_SIZE,
                "POOL_BINDING_MISMATCH"
            );
            let sha = declared["ordered_pool_sha256"]
                .as_str()
                .filter(|v| is_sha(v))
                .ok_or_else(|| anyhow::anyhow!("POOL_BINDING_MISMATCH"))?;
            Ok(ExpectedPool {
                qid: window.qid.clone(),
                ordered_pool_sha256: sha.into(),
            })
        })
        .collect()
}

fn read_windows(inputs: &ValidatedInputs) -> Result<Vec<u8>> {
    let mut assets = inputs
        .assets
        .iter()
        .filter(|a| a.roles.iter().any(|r| r == "windows"));
    let asset = assets
        .next()
        .ok_or_else(|| anyhow::anyhow!("INPUT_ROLE_MISSING"))?;
    ensure!(assets.next().is_none(), "INPUT_ROLE_AMBIGUOUS");
    ensure!(
        asset.sha256 == inputs.windows_file_sha256,
        "REGRESSION_FIXED_WINDOW_PIN_MISMATCH"
    );
    // Use the unique admitted source name as a registry reference, not as a path.
    super::input::read_registered_asset(inputs, &asset.source_path)
}

fn preparation_failure(
    validated: &ValidatedRun,
    pool_sha: &str,
    error: &anyhow::Error,
    results: &[WindowResult],
) -> Result<()> {
    let inputs = &validated.inputs;
    let mut trace = RequestTrace::default();
    for result in results {
        trace.requests.extend(result.trace.requests.clone());
    }
    let known = inputs.windows.iter().map(|w| json!({"qid":w.qid,"query_sha256":w.query_sha256,
        "slots":w.items.iter().enumerate().map(|(index,s)| json!({"input_slot":index,
            "retrieval_rank":s.rank,"typed_message_id":s.message_id,
            "scoreable":s.scoreable,"fallback_reason":s.fallback_reason})).collect::<Vec<_>>()
    })).collect::<Vec<_>>();
    // A carrier GAP cannot produce a legal Slot.original_score. Keep the pin
    // chain and typed recovery association as diagnostics instead of inventing
    // a value or publishing an invalid complete Run.
    write_private(
        &validated.paths.run_root,
        "fixed-failure.json",
        &json!({"terminal":"FAILED","quality_status":"FAILED","failure_code":failure_code(error),
            "mode":"fixed-candidate","suite_sha256":inputs.suite_sha256,
            "input_manifest_sha256":inputs.input_manifest_sha256,
            "windows_file_sha256":inputs.windows_file_sha256,"pool_binding_file_sha256":pool_sha,
            "original_score_recovery":"original-pinned-windows-required",
            "known_original_associations":known,"completed_questions":results.len(),
            "transport":trace,"counts":[http_counts(&trace)]}),
    )?;
    Ok(())
}

/// Production entry: input admission owns all filesystem reads and run-root
/// creation. Provenance identifies this clean built executable, never git HEAD.
/// The retired local rerank provider is deliberately not selectable here: a
/// backtest names its service in a frozen model-API configuration, so the only
/// backend this selection can produce is the API one.
pub(crate) struct FixedBackend {
    config: crate::search::model_api::ValidatedApiConfig,
    profile: crate::search::model_api::ValidatedProfile,
    route: crate::search::rerank::window::ApiWindowRoute,
}

impl FixedBackend {
    fn selected(api: &crate::search::regression_input::RegressionApiOptions, legacy: Option<ProviderChoice>) -> Result<Self> {
        // Production retirement: a fixed-candidate run without a frozen model
        // API is refused, and the legacy provider selection is refused outright
        // instead of being honoured, so the old service path is unreachable.
        ensure!(api.selected(), "REGRESSION_MODEL_API_MIGRATION");
        ensure!(legacy.is_none(), "REGRESSION_MODEL_API_MIGRATION");
        ensure!(api.embedding_profile.is_none(), "REQUEST_PROFILE_INVALID");
        use crate::search::model_api::runtime;
        runtime::ensure_no_retired_model_env(|key| std::env::var_os(key))?;
        let config = runtime::load_config(api.config_path.as_deref(), |key| std::env::var_os(key))?;
        let options = crate::SemanticSearchOptions {
            api: crate::ApiSearchOptions { frozen: Some(config.clone()), rerank_profile: api.rerank_profile.clone(),
                no_model_fallback: api.no_model_fallback, ..Default::default() },
            rerank: true, ..Default::default()
        };
        let profile = crate::selected_api_rerank_profile(&options).map_err(|e| anyhow::anyhow!("{}: {}", e.kind, e.message))?
            .ok_or_else(|| anyhow::anyhow!("REQUEST_PROFILE_INVALID"))?;
        let route = crate::api_window_route(&options, Some(&profile), crate::search::query::SearchMode::Lexical)
            .map_err(|e| anyhow::anyhow!(e.message))?.ok_or_else(|| anyhow::anyhow!("REQUEST_PROFILE_INVALID"))?;
        Ok(Self { config, profile, route })
    }
    fn route(&self) -> Option<&crate::search::rerank::window::ApiWindowRoute> { Some(&self.route) }
    fn profile_id(&self) -> String { self.profile.id.clone() }
    fn origin(&self) -> String { self.profile.endpoint.url().origin().ascii_serialization() }
    fn declaration(&self) -> Result<Value> {
        Ok(crate::search::model_api::runtime::configuration_snapshot(&self.config, &self.profile)?)
    }
    fn score(&self, trace: Arc<Mutex<RequestTrace>>, query: &str, documents: &[String], evidence: &mut Option<crate::search::rerank::window::ApiWindowRerank>) -> Result<crate::search::rerank::types::RerankResponse> {
        let client = crate::search::model_api::ApiClient::new(self.config.clone(), Box::new(crate::search::model_api::EnvCredentialResolver)).with_rerank_trace(trace);
        crate::search::model_api::rerank_call::score(&client, &self.profile.id, query, documents, self.route.allow_fallback, evidence).map_err(anyhow::Error::new)
    }
}

pub(crate) fn run(command: &RegressionCommand) -> Result<Value> {
    let RegressionCommand::FixedCandidate {
        api,
        input,
        pool_binding,
        pool_binding_sha256,
        rerank_provider,
        cutoffs,
    } = command
    else {
        anyhow::bail!("REQUEST_PROFILE_INVALID");
    };
    ensure!(
        !cutoffs.is_empty()
            && cutoffs.iter().all(|n| *n > 0)
            && cutoffs.iter().collect::<HashSet<_>>().len() == cutoffs.len(),
        "REQUEST_PROFILE_INVALID"
    );
    let started = Instant::now();
    let provenance = RunProvenance::capture()?;
    let backend = FixedBackend::selected(api, *rerank_provider)?;
    let validated = super::input::prepare_fixed(input, pool_binding, pool_binding_sha256)?;
    collect(
        &validated,
        pool_binding,
        pool_binding_sha256,
        backend,
        cutoffs,
        &provenance,
        started,
        milliseconds(started),
    )
}

/// Persist each completed question before proceeding to the next one. A later
/// failure cannot overwrite an earlier trace or imply that its requests were 0.
#[expect(
    clippy::too_many_arguments,
    reason = "Explicit pinned inputs and observed provenance must stay distinct"
)]
pub(crate) fn collect(
    validated: &ValidatedRun,
    pool_path: &Path,
    pool_sha: &str,
    backend: FixedBackend,
    cutoffs: &[u32],
    provenance: &RunProvenance,
    started: Instant,
    admitted_ms: f64,
) -> Result<Value> {
    ensure!(
        validated.context.is_none()
            && validated.expected_binding.is_none()
            && validated.expected_binding_file_sha256.is_none()
            && validated.source_manifest.is_none()
            && validated.source_receipt_sha256.is_none(),
        "REGRESSION_FIXED_INPUT_PIN_MISMATCH"
    );
    let root = &validated.paths.run_root;
    let inputs = &validated.inputs;
    let endpoint = backend.origin();
    let provider = backend.profile_id();
    let argv_ref = write_private(root, "argv.json", &serde_json::to_value(&provenance.argv)?)?;
    let request = json!({"mode":"fixed-candidate","request_profile":"fixed-package-v1",
        "rerank":true,"requested_provider":provider,"model_api_route":backend.route(),"model_api_configuration":backend.declaration()?,"n":POOL_SIZE,"page_k":null,
        "search_mode":null,"vector_search_mode":null,"resolved_filters":{},"cutoffs":cutoffs,
        "configured_origin_sha256":digest(endpoint.as_bytes()),"pool_binding_file_sha256":pool_sha,
        "suite_sha256":inputs.suite_sha256,"input_manifest_sha256":inputs.input_manifest_sha256,
        "windows_file_sha256":inputs.windows_file_sha256,"labels_sha256":inputs.labels_sha256,
        "label_policy_sha256":inputs.label_policy_sha256});
    let request_ref = write_private(root, "request.json", &request)?;
    let preparation_started = Instant::now();
    let prepared = (|| -> Result<Vec<PreparedPool>> {
        let declaration = super::input::read_pinned_json(pool_path, pool_sha)?;
        let pins = expected_pools(&declaration, inputs)?;
        let bytes = read_windows(inputs)?;
        prepare_pools(inputs, &bytes, &pins)
    })();
    let preparation_ms = milliseconds(preparation_started);
    let pools = match prepared {
        Ok(pools) => pools,
        Err(error) => {
            preparation_failure(validated, pool_sha, &error, &[])?;
            return Err(error);
        }
    };
    let mut results = Vec::with_capacity(QIDS.len());
    for pool in &pools {
        let question_started = Instant::now();
        let result = execute_prepared_with_call(
            pool, inputs, None, backend.route(),
            |reference| super::input::read_registered_asset(inputs, reference),
            |trace, query, documents, evidence| backend.score(trace, query, documents, evidence),
        );
        let mut result = match result {
            Ok(result) => result,
            Err(error) => {
                preparation_failure(validated, pool_sha, &error, &results)?;
                return Err(error);
            }
        };
        let qid = &pool.window.qid;
        write_private(
            root,
            &format!("fixed-ordered-pool-{qid}.json"),
            &json!({"qid":qid,"ordered_pool_sha256":pool.ordered_pool_sha256,
                "canonical_utf8":std::str::from_utf8(pool.ordered_bytes())?}),
        )?;
        write_private(
            root,
            &format!("fixed-recovery-{qid}.json"),
            &result.recovery,
        )?;
        write_private(
            root,
            &format!("fixed-trace-{qid}.json"),
            &json!({"qid":qid,"query_sha256":pool.window.query_sha256,
                "ordered_pool_sha256":pool.ordered_pool_sha256,"transport":result.trace,
                "identity":result.identity,"model_api":result.api_rerank,"terminal":result.question["terminal"],
                "failure_code":result.question["failure_code"]}),
        )?;
        if let Some(subjects) = result.label_subject_cache(pool)? {
            write_private(root, &format!("label-subjects-{qid}.json"), &subjects)?;
        }
        result.question["cost"]["question_total_ms"] = json!(milliseconds(question_started));
        write_private(root, &format!("question-{qid}.json"), &result.question)?;
        results.push(result);
    }
    let (terminal, quality_status, failure) = aggregate_outcome(&results)?;
    let (actual_provider, actual_model) = common_identity(&results);
    let mut totals = RequestTrace::default();
    let mut times = Vec::with_capacity(results.len());
    for result in &results {
        totals.requests.extend(result.trace.requests.clone());
        times.push(
            result.question["cost"]["question_total_ms"]
                .as_f64()
                .ok_or_else(|| anyhow::anyhow!("REGRESSION_FIXED_REPORT_FAILED"))?,
        );
    }
    let mean = times.iter().sum::<f64>() / times.len() as f64;
    let mut sorted = times.clone();
    sorted.sort_by(f64::total_cmp);
    let quantile = |fraction: f64| {
        sorted[((sorted.len() as f64 * fraction).ceil() as usize).saturating_sub(1)]
    };
    let mut writes = private_files(root)?;
    writes.push("run.json".into());
    writes.sort();
    let output = json!({"schema":"cass.regression-run.v1",
        "run_id":root.file_name().and_then(|s| s.to_str()).ok_or_else(||anyhow::anyhow!("REGRESSION_REPORT_WRITE_FAILED"))?,
        "mode":"fixed-candidate","terminal":terminal,"quality_status":quality_status,"failure_code":failure,
        "source_commit":provenance.source_commit,"binary_sha256":provenance.binary_sha256,"argv_sha256":argv_ref["sha256"],
        "suite_sha256":inputs.suite_sha256,"query_manifest_sha256":digest(&query_manifest_bytes(&inputs.windows)?),
        "labels_sha256":inputs.labels_sha256,"label_policy_sha256":inputs.label_policy_sha256,
        "question_count":9,"suite_candidate_slots":1800,
        "source_identity":{"source_manifest_sha256":null,"source_checked":null,"source_producer_receipt_sha256":null,
            "message_text_sha256":null,"chunk_text_sha256":null,"canonicalize_version":null,
            "chunking_policy_version":null,"statistics_policy":null},
        "expected_binding_file_sha256":null,"expected_binding":null,"observed_before":null,"observed_after":null,
        "fixed_input_manifest_sha256":inputs.input_manifest_sha256,"fixed_windows_file_sha256":inputs.windows_file_sha256,
        "backend_identity":{"provider":actual_provider,"actual_model":actual_model,"model_revision":null,
            "endpoint_origin_sha256":null,"server_template_policy":null,
            "document_assembly_policy":"frozen-package-verbatim-v1","client_submission_policy":"verbatim-query-documents-v1"},
        "request":{"search_mode":null,"vector_search_mode":null,"rerank":true,"n":POOL_SIZE,"page_k":null,
            "resolved_filters":{},"request_profile":"fixed-package-v1","request_evidence_sha256":request_ref["sha256"]},
        "output":{"private_root":root.parent().and_then(|p|p.to_str()).ok_or_else(||anyhow::anyhow!("REGRESSION_REPORT_WRITE_FAILED"))?,
            "run_relative_path":root.file_name().and_then(|p|p.to_str()),"root_mode":"0700","file_mode":"0600",
            "symlink_free":true,"fresh":true,"outside_input_and_repo":true,"writes_relative_paths":writes},
        "questions":results.iter().map(|r| &r.question).collect::<Vec<_>>(),
        "cost":{"all_run_ms":milliseconds(started),"identity_before_ms":admitted_ms+preparation_ms,
            "identity_after_ms":0.0,"sample_count":times.len(),"mean_question_ms":mean,
            "p50_question_ms":quantile(0.5),"p95_question_ms":quantile(0.95),"quantile_method":"nearest-rank",
            "counts":[http_counts(&totals)]},
        "claims":{"dataset":"development-regression-9-small-sample","attribution":"observed-comparison",
            "fts_vec_correctness":"NOT_VERIFIED","pure_engine":false},"after_verification":null});
    write_private(root, "run.json", &output)?;
    if let Some(code) = failure {
        return Err(anyhow::anyhow!("REGRESSION_FIXED_BACKEND_FAILED").context(code));
    }
    Ok(
        json!({"schema":"cass.regression-run-summary.v1","mode":"fixed-candidate",
        "terminal":terminal,"quality_status":quality_status,"question_count":results.len()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

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

    #[test]
    fn pinned_pool_declarations_are_closed_and_match_every_metadata_and_query_identity() {
        let (inputs, _, pins, _) = fixture(true, None, json!(17), false);
        let value = json!({"schema":"cass.regression-fixed-pool.v1",
            "suite_sha256":inputs.suite_sha256,"input_manifest_sha256":inputs.input_manifest_sha256,
            "windows_file_sha256":inputs.windows_file_sha256,"labels_sha256":inputs.labels_sha256,
            "label_freeze_sha256":inputs.label_freeze_sha256,"label_policy_sha256":inputs.label_policy_sha256,
            "source_inventory_sha256":inputs.source_inventory_sha256,
            "windows":inputs.windows.iter().zip(&pins).map(|(window,pin)| json!({"qid":window.qid,
                "query_sha256":window.query_sha256,"count":200,"ordered_pool_sha256":pin.ordered_pool_sha256})).collect::<Vec<_>>()});
        assert_eq!(expected_pools(&value, &inputs).unwrap().len(), 9);
        for fault in [
            "suite",
            "labels",
            "source",
            "qid",
            "query",
            "count",
            "unknown_root",
            "unknown_window",
        ] {
            let mut changed = value.clone();
            match fault {
                "suite" => changed["suite_sha256"] = json!(digest(b"wrong")),
                "labels" => changed["labels_sha256"] = json!(digest(b"wrong")),
                "source" => changed["source_inventory_sha256"] = json!(digest(b"wrong")),
                "qid" => changed["windows"][0]["qid"] = json!("N12"),
                "query" => changed["windows"][0]["query_sha256"] = json!(digest(b"wrong")),
                "count" => changed["windows"][0]["count"] = json!(199),
                "unknown_root" => changed["new_field"] = json!(true),
                _ => changed["windows"][0]["new_field"] = json!(true),
            }
            assert_eq!(
                expected_pools(&changed, &inputs).err().unwrap().to_string(),
                "POOL_BINDING_MISMATCH"
            );
        }
    }

    struct PackageFixture {
        _root: tempfile::TempDir,
        command: RegressionCommand,
    }

    fn fixture_file(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn package_fixture(fault: &str) -> PackageFixture {
        use super::super::types::{InputOptions, OutputOptions};
        let root = tempfile::tempdir().unwrap();
        let suite = root.path().join("package");
        let output = root.path().join("output");
        std::fs::create_dir(&suite).unwrap();
        std::fs::create_dir(&output).unwrap();
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut assets = Vec::new();
        let mut add = |path: &str, bytes: Vec<u8>, role: &str| -> Value {
            fixture_file(&suite.join(path), &bytes);
            let reference = format!("/synthetic-frozen/{path}");
            assets.push(
                json!({"source_path":reference,"path":path,"sha256":digest(&bytes),
                "bytes":bytes.len(),"roles":[role]}),
            );
            json!({"path":reference,"sha256":digest(&bytes),"bytes":bytes.len()})
        };
        let mut texts = Vec::new();
        for rank in 1..=POOL_SIZE {
            let text = if fault == "empty" && rank == 42 {
                String::new()
            } else {
                format!("Synthetic document {rank}. UTF8 合成😀\n\"quoted\"\\slash")
            };
            texts.push(add(
                &format!("assets/text/{rank}.txt"),
                text.into_bytes(),
                "candidate_text",
            ));
        }
        let policy = digest(b"synthetic-fixed-label-policy");
        let mut raw = Vec::new();
        let mut spans = Vec::new();
        let mut rows = Vec::new();
        let mut declared = Vec::new();
        for qid in QIDS {
            let query = format!("Synthetic HTTP query {qid} 合成");
            let query_sha = digest(query.as_bytes());
            let mut items = Vec::new();
            let mut span_items = Vec::new();
            let mut ordered = vec![b'['];
            for rank in 1..=POOL_SIZE {
                let reference = &texts[rank - 1];
                let mid = typed_id(rank);
                let conversation = if fault == "conversation_gap" {
                    json!(u64::MAX)
                } else {
                    json!(17)
                };
                let token = if fault == "score_gap" {
                    "18446744073709551616"
                } else if rank == 1 {
                    "18446744073709551615"
                } else if rank == 3 {
                    "-0.0"
                } else {
                    "1.25"
                };
                let scoreable = !(fault == "unscoreable" && qid == "N01" && rank == 50);
                let mut item = serde_json::to_vec(&json!({"rank":rank,"message_id":mid,
                    "conversation_id":conversation,"text_path":reference["path"],"text_sha256":reference["sha256"],
                    "bytes":reference["bytes"],"source_sha256":digest(b"synthetic-source"),"scoreable":scoreable,
                    "fallback_reason":if scoreable {Value::Null} else {json!("structural_unscoreable")}})).unwrap();
                item.pop();
                item.extend(format!(",\"original_score\":{token}}}").as_bytes());
                items.push(item);
                span_items.push(json!({"rank":rank,"message_id":mid}));
                rows.push(json!({"qid":qid,"rank":rank,"message_id":mid,"query_sha256":query_sha,
                    "text_sha256":reference["sha256"],"label":if scoreable {"direct"} else {"unsure"},
                    "reason":"synthetic judgement","provenance":{"kind":if scoreable {"synthetic"} else {"structural_unscoreable"}}}));
                let mut tuple = serde_json::to_vec(&(
                    rank,
                    &mid,
                    &conversation,
                    &reference["sha256"],
                    &reference["bytes"],
                    digest(b"synthetic-source"),
                ))
                .unwrap();
                tuple.pop();
                tuple.push(b',');
                tuple.extend(token.as_bytes());
                tuple.push(b']');
                if rank != 1 {
                    ordered.push(b',');
                }
                ordered.extend(tuple);
            }
            ordered.push(b']');
            let mut window =
                serde_json::to_vec(&json!({"qid":qid,"query":query,"query_sha256":query_sha}))
                    .unwrap();
            window.pop();
            window.extend(b",\"items\":[");
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    window.push(b',');
                }
                window.extend(item);
            }
            window.extend(b"]}\n");
            raw.extend(window);
            spans.push(json!({"qid":qid,"items":span_items}));
            declared.push(json!({"qid":qid,"query_sha256":query_sha,"count":POOL_SIZE,"ordered_pool_sha256":digest(&ordered)}));
        }
        let windows = add("assets/windows.jsonl", raw, "windows");
        let span_bytes: Vec<u8> = spans
            .iter()
            .flat_map(|s| {
                let mut b = serde_json::to_vec(s).unwrap();
                b.push(b'\n');
                b
            })
            .collect();
        let spans = add("assets/spans.jsonl", span_bytes, "span_proofs");
        let manifest = add("assets/INPUT-MANIFEST.json",serde_json::to_vec(&json!({"schema":"cass.pr3.default-input.v1",
            "query_order":QIDS,"pool_limit":200,"source_query_manifest_sha256":digest(b"synthetic-history"),
            "files":{"windows":windows,"span_proofs":spans}})).unwrap(),"input_manifest");
        let labels = add(
            "assets/LABELS.json",
            serde_json::to_vec(&json!({"schema":"cass.pr3.default-labels.v1",
            "input_manifest_sha256":manifest["sha256"],"label_policy_sha256":policy,"rows":rows}))
            .unwrap(),
            "labels",
        );
        let freeze = add("assets/LABELS-FREEZE-MANIFEST.json",serde_json::to_vec(&json!({"schema":"cass.pr3.default-labels-freeze-manifest.v1",
            "labels_frozen":true,"labels_sha256":labels["sha256"],"labels_bytes":labels["bytes"],"labels_rows":1800,
            "input_manifest_sha256":manifest["sha256"],"label_policy_sha256":policy,
            "not_user_confirmed":true,"not_an_independent_test_set":true})).unwrap(),"labels_freeze");
        drop(add);
        let counts = if fault == "unscoreable" {
            json!({"direct":1799,"partial":0,"none":0,"unsure":1})
        } else {
            json!({"direct":1800,"partial":0,"none":0,"unsure":0})
        };
        let inventory = serde_json::to_vec(&json!({"schema":"cass.regression.source-inventory.v1","suite_id":"synthetic-fixed-v1",
            "mode":"synthetic","query_order":QIDS,"candidate_slots":1800,"labels":counts,"runtime_prefix_map":{},"files":assets,"limits":{}})).unwrap();
        fixture_file(&suite.join("SOURCE-INVENTORY.json"), &inventory);
        let suite_bytes = serde_json::to_vec(&json!({"schema":"cass.regression.suite-manifest.v1","suite_id":"synthetic-fixed-v1",
            "stage":"assets_only","mode":"synthetic","query_order":QIDS,"candidate_slots":1800,"label_counts":counts,
            "runtime_prefix_map":{},"files":assets,"limits":{},"source_inventory_sha256":digest(&inventory)})).unwrap();
        fixture_file(&suite.join("SUITE-MANIFEST.json"), &suite_bytes);
        let pool = root.path().join("bindings/pool.json");
        let pool_bytes = serde_json::to_vec(&json!({"schema":"cass.regression-fixed-pool.v1","suite_sha256":digest(&suite_bytes),
            "input_manifest_sha256":manifest["sha256"],"windows_file_sha256":windows["sha256"],"labels_sha256":labels["sha256"],
            "label_freeze_sha256":freeze["sha256"],"label_policy_sha256":policy,"source_inventory_sha256":digest(&inventory),"windows":declared})).unwrap();
        fixture_file(&pool, &pool_bytes);
        PackageFixture {
            command: RegressionCommand::FixedCandidate {
                api: Default::default(),
                input: InputOptions {
                    suite,
                    suite_sha256: digest(&suite_bytes),
                    labels: root.path().join("package/assets/LABELS.json"),
                    labels_sha256: labels["sha256"].as_str().unwrap().into(),
                    output: OutputOptions {
                        output_root: output,
                        run_id: "fixed-native".into(),
                    },
                },
                pool_binding: pool,
                pool_binding_sha256: digest(&pool_bytes),
                rerank_provider: Some(ProviderChoice::BgeLocal),
                cutoffs: vec![5, 10, 20],
            },
            _root: root,
        }
    }

    #[test]
    fn api_fixed_candidate_nine_windows_preserve_inputs_and_configuration() {
        use crate::search::model_api::test_support::{HttpFixture, Reply};
        let mut package = package_fixture("reverse");
        let server = HttpFixture::start(vec![Reply::ok(json!({"model":"example/fixed-rank", "results":(0..POOL_SIZE).rev().map(|i| json!({"index":i,"relevance_score":i as f64})).collect::<Vec<_>>() }))]);
        let config_path = package._root.path().join("api.toml");
        fixture_file(&config_path, format!(r#"
version=1
default_rerank="rank"
[profiles.rank]
kind="rerank"
protocol="rerank-json-v1"
scope="loopback"
endpoint="{}"
model="example/fixed-rank"
model_revision="frozen-r1"
"#, server.base()).as_bytes());
        let RegressionCommand::FixedCandidate { api, input, pool_binding, pool_binding_sha256, rerank_provider, cutoffs } = &mut package.command else { unreachable!() };
        api.config_path = Some(config_path.clone());
        api.no_model_fallback = true;
        *rerank_provider = None;
        let backend = FixedBackend::selected(api, None).unwrap();
        let validated = super::super::input::prepare_fixed(input, pool_binding, pool_binding_sha256).unwrap();
        let started = Instant::now();
        let provenance = RunProvenance::capture().unwrap();
        fixture_file(&config_path, b"invalid after freeze");
        let summary = collect(&validated, pool_binding, pool_binding_sha256, backend, cutoffs, &provenance, started, 0.0).unwrap();
        assert_eq!(summary["terminal"], "SUCCESS");
        let root = &validated.paths.run_root;
        let report: Value = serde_json::from_slice(&std::fs::read(root.join("run.json")).unwrap()).unwrap();
        assert_eq!(report["quality_status"], "NOT_EVALUATED");
        let pools = prepare_pools(&validated.inputs, &read_windows(&validated.inputs).unwrap(),
            &expected_pools(&super::super::input::read_pinned_json(pool_binding, pool_binding_sha256).unwrap(), &validated.inputs).unwrap()).unwrap();
        let requests = server.requests();
        assert_eq!(requests.len(), 9);
        for ((question, pool), request) in report["questions"].as_array().unwrap().iter().zip(&pools).zip(requests) {
            assert_eq!(question["actual_n"], POOL_SIZE);
            assert_eq!(question["cost"]["http"][0]["http_attempts"], 1);
            let slots = question["slots"].as_array().unwrap();
            assert_eq!(slots.len(), POOL_SIZE);
            pool.verify_recovery(slots).unwrap();
            let docs = pool.documents(|reference| super::super::input::read_registered_asset(&validated.inputs, reference)).unwrap();
            assert_eq!(request.method(), "POST");
            assert_eq!(request.body()["documents"], json!(docs));
            assert_eq!(request.body()["query"], pool.window.query);
            let trace: Value = serde_json::from_slice(&std::fs::read(root.join(format!("fixed-trace-{}.json", pool.window.qid))).unwrap()).unwrap();
            assert_eq!(trace["model_api"]["realized_profile"], "rank");
        }
        let request: Value = serde_json::from_slice(&std::fs::read(root.join("request.json")).unwrap()).unwrap();
        assert_eq!(request["model_api_configuration"]["primary"]["model_revision"], "frozen-r1");
        assert_eq!(request["model_api_route"]["allow_fallback"], false);
    }

    #[test]
    fn api_fixed_candidate_fallback_submits_the_same_complete_pool() {
        use crate::search::model_api::{ApiClient, ApiConfig, EnvCredentialResolver};
        use crate::search::model_api::test_support::{HttpFixture, TlsFixture, Reply};
        let package = package_fixture("reverse");
        let RegressionCommand::FixedCandidate { input, pool_binding, pool_binding_sha256, .. } = &package.command else { unreachable!() };
        let inputs = super::super::input::validate_inputs(input).unwrap();
        let pools = prepare_pools(&inputs, &read_windows(&inputs).unwrap(),
            &expected_pools(&super::super::input::read_pinned_json(pool_binding, pool_binding_sha256).unwrap(), &inputs).unwrap()).unwrap();
        let pool = &pools[0];
        let docs = pool.documents(|reference| super::super::input::read_registered_asset(&inputs, reference)).unwrap();
        let local = HttpFixture::start(vec![Reply::status(503)]);
        let cloud = TlsFixture::start(vec![Reply::ok(json!({"results":(0..POOL_SIZE).map(|i| json!({"index":i,"relevance_score":i as f64})).collect::<Vec<_>>() }))]);
        let config = ApiConfig::parse_toml(&format!(r#"
version=1
default_rerank="local"
[profiles.local]
kind="rerank"
protocol="rerank-json-v1"
scope="loopback"
endpoint="{}"
model="example/local"
model_revision="r1"
fallback_profile="cloud"
[profiles.cloud]
kind="rerank"
protocol="openrouter-rerank-v1"
scope="remote"
endpoint="{}"
model="example/cloud"
model_revision="r1"
provider_only="fixed-provider"
"#, local.base(), cloud.base())).unwrap();
        let opts = crate::SemanticSearchOptions { api: crate::ApiSearchOptions { frozen: Some(config.clone()), ..Default::default() }, ..Default::default() };
        let route = crate::api_window_route(&opts, config.profile("local"), crate::search::query::SearchMode::Lexical).unwrap().unwrap();
        let result = score_window_with_call(pool, &inputs.labels, &inputs.label_policy_sha256, &docs, None, Some(&route),
            |trace, query, documents, evidence| {
                let client = ApiClient::new_with_test_root(config, Box::new(EnvCredentialResolver), cloud.ca_pem().to_vec()).with_rerank_trace(trace);
                crate::search::model_api::rerank_call::score(&client, "local", query, documents, true, evidence).map_err(anyhow::Error::new)
            }).unwrap();
        assert_eq!(result.question["terminal"], "SUCCESS");
        assert_eq!(result.question["cost"]["http"][0]["http_attempts"], 2);
        assert_eq!(result.api_rerank.as_ref().unwrap().realized_profile.as_deref(), Some("cloud"));
        pool.verify_recovery(result.question["slots"].as_array().unwrap()).unwrap();
        assert_eq!(local.requests()[0].body()["documents"], json!(docs));
        assert_eq!(cloud.fixture().requests()[0].body()["documents"], json!(docs));
    }

    fn archive_fixture(from: &Path, to: &Path) {
        std::fs::create_dir(to).unwrap();
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o700)).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let destination = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                archive_fixture(&entry.path(), &destination);
            } else {
                fixture_file(&destination, &std::fs::read(entry.path()).unwrap());
            }
        }
    }

    #[test]
    fn owned_http_child() {
        let Ok(case) = std::env::var("CASS_S2_06_OWNED_CASE") else {
            return;
        };
        let mut package = package_fixture(&case);
        // Local inference is retired: the parent freezes the explicit model API
        // and this child runs under it, with no legacy provider selection left.
        let api_config = std::path::PathBuf::from(
            std::env::var("CASS_S2_06_API_CONFIG").expect("parent must pass the frozen api config"),
        );
        let RegressionCommand::FixedCandidate {
            api,
            rerank_provider,
            ..
        } = &mut package.command
        else {
            unreachable!();
        };
        api.config_path = Some(api_config);
        api.no_model_fallback = true;
        *rerank_provider = None;
        let outcome = run(&package.command);
        let RegressionCommand::FixedCandidate { input, .. } = &package.command else {
            unreachable!();
        };
        let root = input.output.output_root.join(&input.output.run_id);
        if let Ok(destination) = std::env::var("CASS_S2_06_CASE_ARTIFACT") {
            archive_fixture(package._root.path(), Path::new(&destination));
        }
        let gap = matches!(case.as_str(), "score_gap" | "conversation_gap");
        if gap {
            assert!(outcome.is_err());
            assert!(!root.join("run.json").exists());
            let failure: Value =
                serde_json::from_slice(&std::fs::read(root.join("fixed-failure.json")).unwrap())
                    .unwrap();
            assert_eq!(failure["quality_status"], "FAILED");
            assert_eq!(
                failure["known_original_associations"]
                    .as_array()
                    .unwrap()
                    .len(),
                9
            );
            assert_eq!(failure["counts"][0]["http_attempts"], 0);
            assert_eq!(
                failure["failure_code"],
                if case == "score_gap" {
                    "REGRESSION_FIXED_UNREPRESENTABLE_SCORE"
                } else {
                    "REGRESSION_FIXED_UNREPRESENTABLE_CONVERSATION"
                }
            );
        } else {
            assert!(
                root.join("run.json").exists(),
                "case {case}: {}",
                outcome
                    .as_ref()
                    .err()
                    .map_or("success-without-run".into(), failure_code)
            );
            let report: Value =
                serde_json::from_slice(&std::fs::read(root.join("run.json")).unwrap()).unwrap();
            let succeeds = matches!(case.as_str(), "tie" | "reverse" | "unknown_model");
            assert_eq!(outcome.is_ok(), succeeds);
            assert_eq!(
                report["terminal"],
                if succeeds { "SUCCESS" } else { "FAILED" }
            );
            assert_eq!(
                report["quality_status"],
                if succeeds { "NOT_EVALUATED" } else { "FAILED" }
            );
            assert_eq!(report["questions"].as_array().unwrap().len(), 9);
            assert!(
                report["expected_binding"].is_null()
                    && report["observed_before"].is_null()
                    && report["observed_after"].is_null()
            );
            let validated = super::super::input::validate_inputs(input).unwrap();
            let pool = super::super::input::read_pinned_json(
                match &package.command {
                    RegressionCommand::FixedCandidate { pool_binding, .. } => pool_binding,
                    _ => unreachable!(),
                },
                match &package.command {
                    RegressionCommand::FixedCandidate {
                        pool_binding_sha256,
                        ..
                    } => pool_binding_sha256,
                    _ => unreachable!(),
                },
            )
            .unwrap();
            let pools = prepare_pools(
                &validated,
                &read_windows(&validated).unwrap(),
                &expected_pools(&pool, &validated).unwrap(),
            )
            .unwrap();
            for (index, (question, pool)) in report["questions"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&pools)
                .enumerate()
            {
                let slots = question["slots"].as_array().unwrap();
                assert_eq!(pool.verify_recovery(slots).unwrap().len(), 200);
                assert_eq!(
                    slots[if case == "reverse" { 199 } else { 0 }]["original_score"].as_u64(),
                    Some(u64::MAX)
                );
                if case == "unscoreable" && index == 0 {
                    assert_eq!(
                        question["failure_code"],
                        "REGRESSION_FIXED_UNSCOREABLE_POOL"
                    );
                    assert_eq!(question["cost"]["http"][0]["http_attempts"], 0);
                    assert_eq!(slots[49]["label"], "unsure");
                    assert!(
                        !root
                            .join(format!("label-subjects-{}.json", pool.window.qid))
                            .exists()
                    );
                }
                if question["terminal"] == "FAILED" {
                    assert!(slots.iter().all(|s| s["rerank_score"].is_null()));
                }
                if question["rerank_applied"] == true {
                    let subjects: Value = serde_json::from_slice(
                        &std::fs::read(
                            root.join(format!("label-subjects-{}.json", pool.window.qid)),
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    assert_eq!(subjects["schema"], "cass.regression-label-subjects.v1");
                    assert_eq!(subjects["candidates"].as_array().unwrap().len(), 200);
                    for candidate in subjects["candidates"].as_array().unwrap() {
                        let text = candidate["text"]["utf8"].as_str().unwrap();
                        assert_eq!(candidate["text"]["sha256"], digest(text.as_bytes()));
                        let slot = slots
                            .iter()
                            .find(|s| {
                                s["candidate_instance_key"] == candidate["candidate_instance_key"]
                            })
                            .unwrap();
                        assert_eq!(
                            slot["sent_text"],
                            json!({"sha256":digest(text.as_bytes()),"utf8_bytes":text.len()})
                        );
                        assert_eq!(candidate["label_key"], slot["label_key"]);
                    }
                }
            }
            if case == "unknown_model" {
                assert!(report["backend_identity"]["actual_model"].is_null());
            }
            if case == "timeout" {
                assert_eq!(report["questions"][0]["timed_out"], true);
                assert_eq!(report["cost"]["counts"][0]["delivery_unknown"], 1);
            }
            if report["cost"]["counts"][0]["http_attempts"] != 0 {
                assert!(report["cost"]["counts"][0]["model_executions"].is_null());
            }
        }
        println!("FIXED_NATIVE_CASE={case} library_entry_complete=true actual_model_cloud=false");
    }

    fn read_http(mut stream: &TcpStream) -> (String, String, Vec<u8>) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut block = [0; 4096];
        let split = loop {
            let n = stream.read(&mut block).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&block[..n]);
            if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break index + 4;
            }
            assert!(bytes.len() < 16384);
        };
        let header = std::str::from_utf8(&bytes[..split]).unwrap();
        let first = header.lines().next().unwrap();
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap().to_string();
        let path = parts.next().unwrap().to_string();
        let len = header
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        assert!(len < 2_000_000);
        while bytes.len() - split < len {
            let n = stream.read(&mut block).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&block[..n]);
        }
        (method, path, bytes[split..split + len].to_vec())
    }

    #[test]
    fn owned_http_complete_200_failure_payloads_timeout_and_fresh_recovery() {
        // No process-global env/static state is set. The only env window is an
        // owned child, and the server listens solely on its owned loopback port.
        for case in [
            "tie",
            "reverse",
            "unscoreable",
            "short",
            "extra",
            "duplicate",
            "range",
            "type",
            "nonfinite",
            "model",
            "unknown_model",
            "http500",
            "disconnect",
            "timeout",
            "empty",
            "score_gap",
            "conversation_gap",
            "tie",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            // Local inference is retired: freeze the explicit model API the
            // child runs under, on this case's owned loopback origin, in place
            // of the legacy `CASS_INFINITY_URL` provider variable.
            let api_root = tempfile::tempdir().unwrap();
            let api_config = api_root.path().join("api.toml");
            std::fs::write(
                &api_config,
                format!(
                    "version=1\n\
                     default_rerank=\"rank\"\n\
                     [profiles.rank]\n\
                     kind=\"rerank\"\n\
                     protocol=\"rerank-json-v1\"\n\
                     scope=\"loopback\"\n\
                     endpoint=\"{origin}/rerank\"\n\
                     model=\"BAAI/bge-reranker-v2-m3\"\n\
                     model_revision=\"fixture-r1\"\n"
                ),
            )
            .unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
            let records = captured.clone();
            let post_count = Arc::new(AtomicUsize::new(0));
            let posts = post_count.clone();
            let server = std::thread::spawn(move || {
                let mut handlers = Vec::new();
                while !stopping.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let records = records.clone();
                            let posts = posts.clone();
                            handlers.push(std::thread::spawn(move || {
                                let (method,path,bytes)=read_http(&stream);
                                let body=if bytes.is_empty() {Value::Null} else {serde_json::from_slice(&bytes).unwrap()};
                                records.lock().unwrap().push(json!({"method":method,"path":path,"body":body,"body_sha256":digest(&bytes)}));
                                let (status,response)=if path=="/models" {(200,serde_json::to_vec(&json!({"data":[{"id":"BAAI/bge-reranker-v2-m3"}]})).unwrap())}
                                else {assert_eq!(method,"POST");assert_eq!(path,"/rerank");
                                    assert_eq!(body["documents"].as_array().unwrap().len(),200);
                                    let ordinal=posts.fetch_add(1,Ordering::SeqCst);
                                    if case=="disconnect" {return;}
                                    if case=="timeout" && ordinal==0 {std::thread::sleep(Duration::from_secs(65));}
                                    let mut rows:Vec<_>=(0..200).map(|i| json!({"index":i,"relevance_score":if case=="reverse" {i as f64} else {1.0}})).collect();
                                    match case {"short"=>{rows.pop();},"extra"=>rows.push(json!({"index":200,"relevance_score":1.0})),
                                        "duplicate"=>rows[199]["index"]=json!(0),"range"=>rows[199]["index"]=json!(200),
                                        "type"=>rows[0]["index"]=json!("0"),_=>{}}
                                    if case=="http500" {(500,b"{\"error\":\"SYNTHETIC_SERVER_BODY_NOT_FOR_STDOUT\"}".to_vec())}
                                    else if case=="nonfinite" {(200,b"{\"results\":[{\"index\":0,\"relevance_score\":1e999}]}".to_vec())}
                                    else {let mut response=json!({"results":rows});if case!="unknown_model" {
                                        response["model"]=json!(if case=="model" {"synthetic-wrong-model"} else {"BAAI/bge-reranker-v2-m3"});}
                                        (200,serde_json::to_vec(&response).unwrap())}
                                };
                                let header=format!("HTTP/1.1 {status} Synthetic\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len());
                                let _=stream.write_all(header.as_bytes());let _=stream.write_all(&response);
                            }));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("owned listener failed: {error}"),
                    }
                }
                for handler in handlers {
                    handler.join().unwrap();
                }
            });
            let case_root = tempfile::tempdir().unwrap();
            let archive = case_root.path().join("case");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "regression::fixed::tests::owned_http_child",
                    "--nocapture",
                ])
                .env("CASS_S2_06_API_CONFIG", &api_config)
                .env_remove("HTTP_PROXY")
                .env_remove("HTTPS_PROXY")
                .env_remove("ALL_PROXY")
                .env_remove("http_proxy")
                .env_remove("https_proxy")
                .env_remove("all_proxy")
                .env("NO_PROXY", "127.0.0.1,localhost")
                .env("CASS_S2_06_OWNED_CASE", case)
                .env("CASS_S2_06_CASE_ARTIFACT", &archive)
                .output()
                .unwrap();
            stop.store(true, Ordering::SeqCst);
            server.join().unwrap();
            assert!(
                output.status.success(),
                "case {case}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let records = captured.lock().unwrap().clone();
            assert_eq!(
                post_count.load(Ordering::SeqCst),
                if case == "unscoreable" {
                    8
                } else if matches!(case, "empty" | "score_gap" | "conversation_gap") {
                    0
                } else {
                    9
                }
            );
            let run = archive.join("output/fixed-native/run.json");
            if run.exists() {
                let report: Value = serde_json::from_slice(&std::fs::read(&run).unwrap()).unwrap();
                assert_eq!(report["cost"]["counts"][0]["http_attempts"], records.len());
                for request in records.iter().filter(|r| r["method"] == "POST") {
                    let query = request["body"]["query"].as_str().unwrap();
                    let qid = QIDS.iter().find(|qid| query.contains(**qid)).unwrap();
                    let trace: Value = serde_json::from_slice(
                        &std::fs::read(
                            archive.join(format!("output/fixed-native/fixed-trace-{qid}.json")),
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    let post = trace["transport"]["requests"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|r| r["method"] == "POST")
                        .unwrap();
                    assert_eq!(post["json_body_sha256"], request["body_sha256"]);
                    assert_eq!(post["query"]["sha256"], digest(query.as_bytes()));
                    for (index, text) in request["body"]["documents"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .enumerate()
                    {
                        let text = text.as_str().unwrap();
                        assert_eq!(post["documents"][index]["input_slot"], index);
                        assert_eq!(
                            post["documents"][index]["text"],
                            json!({"sha256":digest(text.as_bytes()),"utf8_bytes":text.len()})
                        );
                    }
                }
            }
            if let Ok(parent) = std::env::var("CASS_S2_06_ARTIFACT_ROOT") {
                let parent = Path::new(&parent);
                let suffix = std::fs::read_dir(parent).unwrap().count();
                let destination = parent.join(format!("{case}-{suffix}"));
                archive_fixture(&archive, &destination);
                fixture_file(
                    &destination.join("server-requests.json"),
                    &serde_json::to_vec(&records).unwrap(),
                );
                fixture_file(&destination.join("child-stdout.txt"), &output.stdout);
                fixture_file(&destination.join("child-stderr.txt"), &output.stderr);
            }
        }
    }
}
