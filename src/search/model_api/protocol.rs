//! The four first message protocols: request shape and response validation.
//!
//! Every function here is pure. A builder turns a validated profile plus the
//! caller's inputs into the JSON body of exactly one business `POST`; a parser
//! turns the service's JSON back into typed values, refusing anything that does
//! not cover the input set completely.
//!
//! The protocols are named after their *message shape*, never after a deployment
//! framework or a product:
//!
//! * `openai-embeddings-v1` — `input: [string]` with `encoding_format: float`.
//! * `openrouter-embeddings-v1` — the same shape plus a pinned provider block.
//! * `rerank-json-v1` — `query`, `documents`, `top_n`, `return_documents`.
//! * `openrouter-rerank-v1` — the same rerank shape plus a pinned provider block.
//!
//! # What the parsers refuse
//!
//! An embedding response must hold one entry per input with `index` covering
//! `0..N-1` exactly once. Every vector must have the same length, be finite and
//! have a non-zero norm, and its length must agree with both the configured
//! `expected_dimension` and the `request_dimensions` parameter when either is
//! set. A rerank response must cover `0..N-1` exactly once with finite scores,
//! using *one* of the two accepted shapes and never a mixture. Nothing is
//! sorted, truncated or back-filled.
//!
//! Identity fields follow one rule: a field the service did not send stays
//! `None`. A field the service did send must agree with the configuration, and a
//! present field of the wrong type is a malformed response rather than a value
//! to reinterpret.

use serde_json::{Map, Value};

use super::config::{ApiProtocol, Normalization, ProfileKind, ValidatedProfile};
use super::error::{ApiCallError, ApiCallErrorCode};
use crate::search::rerank::types::validate_index_scores;

/// Which preprocessing an embedding input receives.
///
/// The query and document prefixes come from the profile; the caller states
/// which side of the pair this input is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// A search query.
    Query,
    /// A stored document.
    Document,
}

impl InputKind {
    /// The stable short name used in traces.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Document => "document",
        }
    }
}

/// The standard token counts and cost a response may report.
///
/// Every field is `None` unless the service returned a finite, non-negative
/// number. No value is derived or estimated: an unreported cost stays `None`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Usage {
    /// `prompt_tokens`, when reported.
    pub prompt_tokens: Option<u64>,
    /// `input_tokens`, when reported.
    pub input_tokens: Option<u64>,
    /// `total_tokens`, when reported.
    pub total_tokens: Option<u64>,
    /// `completion_tokens`, when reported.
    pub completion_tokens: Option<u64>,
    /// `output_tokens`, when reported.
    pub output_tokens: Option<u64>,
    /// The service's own cost figure, when it returned one.
    pub cost: Option<f64>,
}

impl Usage {
    /// Whether the service reported nothing at all.
    pub fn is_empty(&self) -> bool {
        self == &Usage::default()
    }
}

/// What the service itself said about the call.
///
/// These are observations, never echoes of the request. A field the service did
/// not send stays `None`; it is never filled in from the configuration.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ObservedIdentity {
    /// The model name the response carried, when it carried one.
    pub response_model: Option<String>,
    /// The revision the response carried, when it carried one.
    pub response_revision: Option<String>,
    /// The serving provider the response named, when it named one.
    pub provider: Option<String>,
    /// The usage block, when the response carried any recognised field.
    pub usage: Option<Usage>,
}

/// One validated embedding response.
#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddingReply {
    /// One vector per input, in input order.
    pub vectors: Vec<Vec<f32>>,
    /// The dimension every vector actually had.
    pub dimension: usize,
    /// What the service reported about the call.
    pub identity: ObservedIdentity,
}

/// One validated rerank response.
#[derive(Debug, Clone, PartialEq)]
pub struct RerankReply {
    /// One score per document, in input order.
    pub scores: Vec<f64>,
    /// What the service reported about the call.
    pub identity: ObservedIdentity,
}

/// Apply a profile's prefix for `kind` to `text`.
///
/// The bytes are concatenated exactly: no newline, no separator and no
/// model-specific instruction is added.
pub fn embedding_input(profile: &ValidatedProfile, kind: InputKind, text: &str) -> String {
    let prefix = profile
        .embedding()
        .map(|detail| match kind {
            InputKind::Query => detail.query_prefix.as_str(),
            InputKind::Document => detail.document_prefix.as_str(),
        })
        .unwrap_or("");
    let mut prepared = String::with_capacity(prefix.len() + text.len());
    prepared.push_str(prefix);
    prepared.push_str(text);
    prepared
}

/// Build the body of one embedding `POST`.
///
/// `inputs` are the already-prefixed, complete strings the caller batched; the
/// caller owns batching, so this function never splits or joins an input.
///
/// Returns `Err` only when the profile's kind does not match the protocol, which
/// the configuration kernel already prevents — the check keeps this function
/// total on its own.
pub fn embedding_request(
    profile: &ValidatedProfile,
    inputs: &[String],
) -> Result<Value, ApiCallError> {
    let Some(detail) = profile.embedding() else {
        return Err(ApiCallError::new(ApiCallErrorCode::WrongKind));
    };

    let mut body = Map::new();
    body.insert(
        "input".to_string(),
        Value::Array(inputs.iter().cloned().map(Value::String).collect()),
    );
    body.insert(
        "encoding_format".to_string(),
        Value::String("float".to_string()),
    );
    if profile.send_model {
        body.insert("model".to_string(), Value::String(profile.model.clone()));
    }
    if let Some(dimensions) = detail.request_dimensions {
        body.insert("dimensions".to_string(), Value::from(dimensions));
    }
    if profile.protocol == ApiProtocol::OpenRouterEmbeddingsV1 {
        body.insert(
            "provider".to_string(),
            openrouter_provider_block(detail.provider_only.as_deref(), true),
        );
    }
    Ok(Value::Object(body))
}

/// Build the body of one rerank `POST`.
///
/// `top_n` is the number of documents actually sent, never a page length, and
/// `return_documents` is always `false`: the caller already holds the text.
pub fn rerank_request(
    profile: &ValidatedProfile,
    query: &str,
    documents: &[String],
) -> Result<Value, ApiCallError> {
    let Some(detail) = profile.rerank() else {
        return Err(ApiCallError::new(ApiCallErrorCode::WrongKind));
    };

    let mut body = Map::new();
    body.insert("query".to_string(), Value::String(query.to_string()));
    body.insert(
        "documents".to_string(),
        Value::Array(documents.iter().cloned().map(Value::String).collect()),
    );
    body.insert("top_n".to_string(), Value::from(documents.len()));
    body.insert("return_documents".to_string(), Value::Bool(false));
    if profile.send_model {
        body.insert("model".to_string(), Value::String(profile.model.clone()));
    }
    if let Some(instruction) = &detail.instruction {
        // `None` omits the key; `Some("")` sends the empty string. The two are
        // different values and stay different here.
        body.insert("instruct".to_string(), Value::String(instruction.clone()));
    }
    if profile.protocol == ApiProtocol::OpenRouterRerankV1 {
        body.insert(
            "provider".to_string(),
            openrouter_provider_block(detail.provider_only.as_deref(), false),
        );
    }
    Ok(Value::Object(body))
}

/// The pinned OpenRouter provider block.
///
/// `require_parameters_always` reflects the one shape difference between the two
/// OpenRouter protocols: the embeddings contract always requires parameter
/// support, the rerank contract only requires it when a provider is pinned.
fn openrouter_provider_block(pinned: Option<&str>, require_parameters_always: bool) -> Value {
    let mut block = Map::new();
    block.insert("allow_fallbacks".to_string(), Value::Bool(false));
    match pinned {
        Some(slug) => {
            block.insert(
                "only".to_string(),
                Value::Array(vec![Value::String(slug.to_string())]),
            );
            block.insert("require_parameters".to_string(), Value::Bool(true));
        }
        None => {
            if require_parameters_always {
                block.insert("require_parameters".to_string(), Value::Bool(true));
            }
        }
    }
    Value::Object(block)
}

/// Validate one embedding response against the expected input count.
pub fn parse_embedding_response(
    profile: &ValidatedProfile,
    body: &Value,
    expected: usize,
) -> Result<EmbeddingReply, ApiCallError> {
    let Some(detail) = profile.embedding() else {
        return Err(ApiCallError::new(ApiCallErrorCode::WrongKind));
    };
    let identity = observed_identity(profile, body)?;

    let rows = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(invalid_response)?;
    if rows.len() != expected {
        return Err(invalid_response());
    }

    let mut vectors: Vec<Option<Vec<f64>>> = vec![None; expected];
    let mut dimension: Option<usize> = None;
    for row in rows {
        let index = index_of(row)?;
        if index >= expected || vectors[index].is_some() {
            return Err(invalid_response());
        }
        let raw = row
            .get("embedding")
            .and_then(Value::as_array)
            .ok_or_else(invalid_response)?;
        if raw.is_empty() {
            return Err(invalid_response());
        }
        match dimension {
            None => dimension = Some(raw.len()),
            Some(seen) if seen != raw.len() => return Err(invalid_response()),
            Some(_) => {}
        }
        let mut values = Vec::with_capacity(raw.len());
        for value in raw {
            let number = value.as_f64().ok_or_else(invalid_response)?;
            if !number.is_finite() {
                return Err(invalid_response());
            }
            values.push(number);
        }
        vectors[index] = Some(values);
    }

    let dimension = dimension.ok_or_else(invalid_response)?;
    check_embedding_dimension(
        detail.expected_dimension,
        detail.request_dimensions,
        dimension,
    )?;

    let mut out = Vec::with_capacity(expected);
    for values in vectors {
        let values = values.ok_or_else(invalid_response)?;
        out.push(finalize_vector(values, detail.normalization)?);
    }
    Ok(EmbeddingReply {
        vectors: out,
        dimension,
        identity,
    })
}

/// Validate one rerank response against the expected document count.
///
/// The two accepted shapes are the object form (`results` holding
/// `index`/`relevance_score`) and the native array form (`index`/`score`). One
/// response uses exactly one of them.
pub fn parse_rerank_response(
    profile: &ValidatedProfile,
    body: &Value,
    expected: usize,
) -> Result<RerankReply, ApiCallError> {
    if profile.kind != ProfileKind::Rerank {
        return Err(ApiCallError::new(ApiCallErrorCode::WrongKind));
    }

    let (rows, identity, native) = match body {
        Value::Object(object) => {
            let identity = observed_identity(profile, body)?;
            let rows = object
                .get("results")
                .and_then(Value::as_array)
                .ok_or_else(invalid_response)?;
            (rows, identity, false)
        }
        Value::Array(rows) => {
            // A native array carries no top-level identity at all, so the
            // observation stays empty rather than borrowing the configuration.
            (rows, ObservedIdentity::default(), true)
        }
        _ => return Err(invalid_response()),
    };

    let normalized = normalize_rows(rows, native)?;
    validate_index_scores(&normalized, expected).map_err(|_| invalid_response())?;
    let mut scores = vec![0.0_f64; expected];
    for row in normalized.as_array().ok_or_else(invalid_response)? {
        let index = index_of(row)?;
        let score = row
            .get("relevance_score")
            .and_then(Value::as_f64)
            .ok_or_else(invalid_response)?;
        scores[index] = score;
    }
    Ok(RerankReply { scores, identity })
}

/// Reduce one accepted shape to the shared `index`/`relevance_score` rows.
///
/// A row carrying the *other* shape's score key is a mixture of the two shapes
/// and is refused rather than guessed at.
fn normalize_rows(rows: &[Value], native: bool) -> Result<Value, ApiCallError> {
    let mut normalized = Vec::with_capacity(rows.len());
    for row in rows {
        let object = row.as_object().ok_or_else(invalid_response)?;
        let foreign = if native { "relevance_score" } else { "score" };
        if object.contains_key(foreign) {
            return Err(invalid_response());
        }
        let score_key = if native { "score" } else { "relevance_score" };
        let mut mapped = Map::new();
        mapped.insert(
            "index".to_string(),
            object.get("index").ok_or_else(invalid_response)?.clone(),
        );
        mapped.insert(
            "relevance_score".to_string(),
            object.get(score_key).ok_or_else(invalid_response)?.clone(),
        );
        normalized.push(Value::Object(mapped));
    }
    Ok(Value::Array(normalized))
}

/// The `index` of one row, as a size.
fn index_of(row: &Value) -> Result<usize, ApiCallError> {
    let raw = row
        .as_object()
        .and_then(|object| object.get("index"))
        .and_then(Value::as_u64)
        .ok_or_else(invalid_response)?;
    usize::try_from(raw).map_err(|_| invalid_response())
}

/// Check the observed dimension against both configured constraints.
fn check_embedding_dimension(
    expected: Option<u64>,
    requested: Option<u64>,
    observed: usize,
) -> Result<(), ApiCallError> {
    let observed = observed as u64;
    if let Some(expected) = expected {
        if expected != observed {
            return Err(ApiCallError::new(ApiCallErrorCode::DimensionMismatch));
        }
    }
    if let Some(requested) = requested {
        if requested != observed {
            return Err(ApiCallError::new(ApiCallErrorCode::DimensionMismatch));
        }
    }
    Ok(())
}

/// Reject a non-finite or zero-norm vector, then apply the profile's
/// normalization.
///
/// The norm is computed in `f64` and applied there before the values are stored,
/// so the stored vector does not accumulate rounding on top of the input.
fn finalize_vector(
    values: Vec<f64>,
    normalization: Normalization,
) -> Result<Vec<f32>, ApiCallError> {
    let sum_of_squares: f64 = values.iter().map(|value| value * value).sum();
    let norm = sum_of_squares.sqrt();
    if !norm.is_finite() || norm == 0.0 {
        return Err(invalid_response());
    }
    let scale = match normalization {
        Normalization::L2 => 1.0 / norm,
        Normalization::None => 1.0,
    };
    Ok(values
        .into_iter()
        .map(|value| (value * scale) as f32)
        .collect())
}

/// Read the optional identity fields of a response.
fn observed_identity(
    profile: &ValidatedProfile,
    body: &Value,
) -> Result<ObservedIdentity, ApiCallError> {
    let Some(object) = body.as_object() else {
        return Err(invalid_response());
    };

    let response_model = match object.get("model") {
        None | Some(Value::Null) => None,
        Some(Value::String(model)) => {
            if !model_matches(profile, model) {
                return Err(ApiCallError::new(ApiCallErrorCode::IdentityMismatch));
            }
            Some(model.clone())
        }
        Some(_) => return Err(invalid_response()),
    };

    let left = optional_string(object.get("revision"))?;
    let right = optional_string(object.get("model_revision"))?;
    if let (Some(left), Some(right)) = (&left, &right) {
        if left != right {
            return Err(ApiCallError::new(ApiCallErrorCode::IdentityMismatch));
        }
    }
    let response_revision = left.or(right);
    if let Some(revision) = &response_revision {
        if revision != &profile.model_revision {
            return Err(ApiCallError::new(ApiCallErrorCode::IdentityMismatch));
        }
    }

    let provider = optional_string(object.get("provider"))?;
    if let (Some(observed), Some(pinned)) = (
        &provider,
        profile
            .embedding()
            .and_then(|detail| detail.provider_only.as_deref())
            .or_else(|| {
                profile
                    .rerank()
                    .and_then(|detail| detail.provider_only.as_deref())
            }),
    ) {
        if observed != pinned {
            return Err(ApiCallError::new(ApiCallErrorCode::IdentityMismatch));
        }
    }

    Ok(ObservedIdentity {
        response_model,
        response_revision,
        provider,
        usage: parse_usage(object),
    })
}

/// Whether a reported model name is the configured model or one of its aliases.
fn model_matches(profile: &ValidatedProfile, reported: &str) -> bool {
    reported == profile.model
        || profile
            .response_model_aliases
            .iter()
            .any(|alias| alias == reported)
}

/// A present string field, or `None` when absent or null.
fn optional_string(value: Option<&Value>) -> Result<Option<String>, ApiCallError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(invalid_response()),
    }
}

/// Extract the recognised usage fields, ignoring anything else.
fn parse_usage(object: &Map<String, Value>) -> Option<Usage> {
    let Some(usage) = object.get("usage").and_then(Value::as_object) else {
        return None;
    };
    let count = |key: &str| usage.get(key).and_then(Value::as_u64);
    let cost = usage
        .get("cost")
        .and_then(Value::as_f64)
        .filter(|cost| cost.is_finite() && *cost >= 0.0);
    let parsed = Usage {
        prompt_tokens: count("prompt_tokens"),
        input_tokens: count("input_tokens"),
        total_tokens: count("total_tokens"),
        completion_tokens: count("completion_tokens"),
        output_tokens: count("output_tokens"),
        cost,
    };
    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

/// The single malformed-response refusal.
fn invalid_response() -> ApiCallError {
    ApiCallError::new(ApiCallErrorCode::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::model_api::config::ApiConfig;
    use serde_json::json;

    fn profile(text: &str) -> ValidatedProfile {
        ApiConfig::parse_toml(text)
            .expect("configuration parses")
            .profiles()
            .next()
            .expect("one profile")
            .clone()
    }

    /// An embedding profile with the given normalization; `extra` must not
    /// repeat `normalization`.
    fn embedding_profile_with(normalization: &str, extra: &str) -> ValidatedProfile {
        profile(&format!(
            r#"
version = 1
[profiles.p]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "http://127.0.0.1:9/e"
scope = "loopback"
model = "m"
model_revision = "rev"
normalization = "{normalization}"
{extra}
"#
        ))
    }

    fn embedding_profile(extra: &str) -> ValidatedProfile {
        embedding_profile_with("none", extra)
    }

    /// An OpenRouter-protocol embedding profile, the only embedding shape that
    /// may pin a provider.
    fn openrouter_embedding_profile(extra: &str) -> ValidatedProfile {
        profile(&format!(
            r#"
version = 1
[profiles.p]
kind = "embedding"
protocol = "openrouter-embeddings-v1"
endpoint = "http://127.0.0.1:9/e"
scope = "loopback"
model = "m"
model_revision = "rev"
normalization = "none"
{extra}
"#
        ))
    }

    fn rerank_profile(extra: &str) -> ValidatedProfile {
        profile(&format!(
            r#"
version = 1
[profiles.p]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "http://127.0.0.1:9/r"
scope = "loopback"
model = "m"
model_revision = "rev"
{extra}
"#
        ))
    }

    #[test]
    fn the_prefix_is_concatenated_byte_for_byte() {
        let profile = embedding_profile("query_prefix = \"Q: \"\ndocument_prefix = \"D:\"\n");
        assert_eq!(embedding_input(&profile, InputKind::Query, "x"), "Q: x");
        assert_eq!(embedding_input(&profile, InputKind::Document, "x"), "D:x");
    }

    #[test]
    fn reported_usage_is_extracted_only_when_present() {
        let profile = embedding_profile("");
        let body = json!({
            "data": [{"index": 0, "embedding": [1.0]}],
            "usage": {
                "prompt_tokens": 12,
                "total_tokens": 12,
                "cost": 0.0001,
                "unknown_field": "ignored",
            },
        });
        let reply = parse_embedding_response(&profile, &body, 1).expect("parsed");
        let usage = reply.identity.usage.expect("usage");
        assert_eq!(usage.prompt_tokens, Some(12));
        assert_eq!(usage.total_tokens, Some(12));
        assert_eq!(usage.input_tokens, None);
        assert_eq!(usage.cost, Some(0.0001));

        let body = json!({"data": [{"index": 0, "embedding": [1.0]}]});
        let reply = parse_embedding_response(&profile, &body, 1).expect("parsed");
        assert_eq!(reply.identity.usage, None);
    }

    #[test]
    fn a_null_model_stays_none_rather_than_being_filled_in() {
        let profile = embedding_profile("");
        let body = json!({
            "model": null,
            "data": [{"index": 0, "embedding": [1.0]}],
        });
        let reply = parse_embedding_response(&profile, &body, 1).expect("parsed");
        assert_eq!(reply.identity.response_model, None);
        assert_eq!(reply.identity.response_revision, None);
    }

    #[test]
    fn a_present_provider_must_agree_with_the_pinned_one() {
        let pinned = openrouter_embedding_profile("provider_only = \"vendor-x\"\n");
        let body = json!({
            "provider": "vendor-y",
            "data": [{"index": 0, "embedding": [1.0]}],
        });
        assert_eq!(
            parse_embedding_response(&pinned, &body, 1)
                .expect_err("provider mismatch")
                .code(),
            ApiCallErrorCode::IdentityMismatch
        );

        let body = json!({
            "provider": {"nested": true},
            "data": [{"index": 0, "embedding": [1.0]}],
        });
        assert_eq!(
            parse_embedding_response(&pinned, &body, 1)
                .expect_err("non string provider")
                .code(),
            ApiCallErrorCode::InvalidResponse
        );
    }

    #[test]
    fn the_l2_convention_normalizes_and_the_none_convention_does_not() {
        let l2 = embedding_profile_with("l2", "");
        let body = json!({"data": [{"index": 0, "embedding": [3.0, 4.0]}]});
        let reply = parse_embedding_response(&l2, &body, 1).expect("parsed");
        assert_eq!(reply.dimension, 2);
        assert!((reply.vectors[0][0] - 0.6).abs() < 1e-6);
        assert!((reply.vectors[0][1] - 0.8).abs() < 1e-6);

        let none = embedding_profile("");
        let reply = parse_embedding_response(&none, &body, 1).expect("parsed");
        assert_eq!(reply.vectors[0], vec![3.0f32, 4.0]);
    }

    #[test]
    fn a_rerank_request_without_a_model_omits_the_key() {
        let profile = rerank_profile("send_model = false\n");
        let documents = vec!["a".to_string()];
        let body = rerank_request(&profile, "q", &documents).expect("body");
        let object = body.as_object().expect("object");
        assert!(!object.contains_key("model"));
        assert_eq!(object["top_n"], json!(1));
        assert_eq!(object["return_documents"], json!(false));
    }

    #[test]
    fn a_wrong_kind_is_refused_by_both_builders() {
        let embedding = embedding_profile("");
        let rerank = rerank_profile("");
        assert_eq!(
            rerank_request(&embedding, "q", &[])
                .expect_err("kind")
                .code(),
            ApiCallErrorCode::WrongKind
        );
        assert_eq!(
            embedding_request(&rerank, &[]).expect_err("kind").code(),
            ApiCallErrorCode::WrongKind
        );
    }
}
