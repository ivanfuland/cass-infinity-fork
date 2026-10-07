//! Public rerank contracts shared by every PR3 rerank backend.
//!
//! This module fixes the vocabulary the later rerank tickets consume:
//!
//! - [`ProviderChoice`]: the five fixed provider selections, with their serde
//!   wire spellings, CLI value names and request models. Unknown or empty input
//!   is refused; there is deliberately no default to fall back to.
//! - [`RerankFailureReason`] and [`RerankError`]: an enumerable short-code
//!   failure surface. Neither carries a raw response body or an arbitrary
//!   error string.
//! - [`CallIdentity`] and [`RerankResponse`]: the shared call result. Identity
//!   fields stay `None` when the service did not prove them; a request value is
//!   never copied in as if it were an observed fact.
//! - [`RerankBackend`]: the trait every adapter implements.
//! - [`validate_index_scores`] and [`stable_rank_order`]: pure score
//!   completeness and ordering helpers.
//! - [`encode_search_result`] and [`decode_search_result`]: the lossless
//!   private result codec. The public `serde` surface keeps hiding
//!   `content_hash` and `conversation_id`; the private encoding carries them
//!   explicitly, and decoding refuses any payload that is missing them.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::search::query::SearchResult;

/// One of the five fixed rerank provider selections.
///
/// The serde value and the CLI value are the same string, so a selection can
/// never mean one thing on the command line and another in persisted state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
pub enum ProviderChoice {
    /// Local SGLang serving Qwen3-Reranker-8B. The default when rerank is on.
    #[serde(rename = "qwen3-local")]
    #[value(name = "qwen3-local")]
    Qwen3Local,
    /// Local Infinity serving `BAAI/bge-reranker-v2-m3`.
    #[serde(rename = "bge-local")]
    #[value(name = "bge-local")]
    BgeLocal,
    /// OpenRouter, Qwen3-Reranker-8B.
    #[serde(rename = "openrouter-qwen3-8b")]
    #[value(name = "openrouter-qwen3-8b")]
    OpenrouterQwen38b,
    /// OpenRouter, Cohere Rerank 4 Fast.
    #[serde(rename = "openrouter-cohere-4-fast")]
    #[value(name = "openrouter-cohere-4-fast")]
    OpenrouterCohere4Fast,
    /// OpenRouter, Voyage rerank 2.5 lite.
    #[serde(rename = "openrouter-voyage-2.5-lite")]
    #[value(name = "openrouter-voyage-2.5-lite")]
    OpenrouterVoyage25Lite,
}

impl ProviderChoice {
    /// The frozen wire/CLI spelling of this selection.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Qwen3Local => "qwen3-local",
            Self::BgeLocal => "bge-local",
            Self::OpenrouterQwen38b => "openrouter-qwen3-8b",
            Self::OpenrouterCohere4Fast => "openrouter-cohere-4-fast",
            Self::OpenrouterVoyage25Lite => "openrouter-voyage-2.5-lite",
        }
    }

    /// The model identifier sent to (or expected from) the backend.
    pub fn request_model(self) -> &'static str {
        match self {
            // The local SGLang server was served under this name (20e).
            Self::Qwen3Local => "Qwen3-Reranker-8B-local",
            Self::BgeLocal => "BAAI/bge-reranker-v2-m3",
            Self::OpenrouterQwen38b => "qwen/qwen3-reranker-8b",
            Self::OpenrouterCohere4Fast => "cohere/rerank-4-fast",
            Self::OpenrouterVoyage25Lite => "voyageai/rerank-2.5-lite",
        }
    }

    /// The additional verified native identities a response may legitimately
    /// report for this selection.
    fn native_models(self) -> &'static [&'static str] {
        match self {
            Self::Qwen3Local => &["Qwen3-Reranker-8B-local"],
            Self::BgeLocal => &["BAAI/bge-reranker-v2-m3"],
            Self::OpenrouterQwen38b => &["accounts/fireworks/models/qwen3-reranker-8b"],
            Self::OpenrouterCohere4Fast => &["rerank-v4.0-fast"],
            Self::OpenrouterVoyage25Lite => &["rerank-2.5-lite"],
        }
    }

    /// Whether this selection runs against a remote provider.
    pub fn is_cloud(self) -> bool {
        matches!(
            self,
            Self::OpenrouterQwen38b | Self::OpenrouterCohere4Fast | Self::OpenrouterVoyage25Lite
        )
    }

    /// Whether a model identity observed in a response is a legal alias for
    /// this selection: either the request model or a verified native identity.
    pub fn accepts_model(self, model: &str) -> bool {
        model == self.request_model() || self.native_models().contains(&model)
    }
}

impl fmt::Display for ProviderChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProviderChoice {
    type Err = RerankError;

    /// Parse the exact wire spelling. Empty input, unknown input and any
    /// case/spelling variant are refused; the selection never falls back to a
    /// default.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "qwen3-local" => Ok(Self::Qwen3Local),
            "bge-local" => Ok(Self::BgeLocal),
            "openrouter-qwen3-8b" => Ok(Self::OpenrouterQwen38b),
            "openrouter-cohere-4-fast" => Ok(Self::OpenrouterCohere4Fast),
            "openrouter-voyage-2.5-lite" => Ok(Self::OpenrouterVoyage25Lite),
            _ => Err(RerankError::new(RerankFailureReason::UnsupportedProvider)),
        }
    }
}

/// Enumerable short-code rerank failure reasons.
///
/// A reason never carries a raw response body: the variants are the whole
/// vocabulary a caller or a log line may branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RerankFailureReason {
    /// The selected provider is empty, unknown or otherwise unsupported.
    UnsupportedProvider,
    /// The request input itself was malformed or out of contract.
    InvalidInput,
    /// A cloud backend was selected without its credential.
    MissingCredentials,
    /// A backend declared local resolved to a non-loopback endpoint.
    NonLoopbackEndpoint,
    /// The service answered with a non-success HTTP status.
    HttpError,
    /// The call exceeded its wait budget.
    Timeout,
    /// The transport failed before an HTTP status was available.
    TransportError,
    /// The response was unparseable or violated the completeness contract.
    InvalidResponse,
    /// The response named a model that is not an accepted alias.
    ModelIdentityMismatch,
    /// A candidate could not be scored (no verifiable passage).
    UnscoreableInput,
    /// A candidate's verified identity did not match the indexed chunk.
    InputIdentityMismatch,
}

impl RerankFailureReason {
    /// The short code used in every surface.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedProvider => "unsupported_provider",
            Self::InvalidInput => "invalid_input",
            Self::MissingCredentials => "missing_credentials",
            Self::NonLoopbackEndpoint => "non_loopback_endpoint",
            Self::HttpError => "http_error",
            Self::Timeout => "timeout",
            Self::TransportError => "transport_error",
            Self::InvalidResponse => "invalid_response",
            Self::ModelIdentityMismatch => "model_identity_mismatch",
            Self::UnscoreableInput => "unscoreable_input",
            Self::InputIdentityMismatch => "input_identity_mismatch",
        }
    }
}

impl fmt::Display for RerankFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rerank failure: an enumerable short code plus an optional HTTP status.
///
/// The `Display` output is only the short code and the status code. It never
/// embeds a response body, a request payload or a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RerankError {
    pub reason: RerankFailureReason,
    pub http_status: Option<u16>,
}

impl RerankError {
    /// A failure with no HTTP status evidence.
    pub fn new(reason: RerankFailureReason) -> Self {
        Self {
            reason,
            http_status: None,
        }
    }

    /// A failure that also observed an HTTP status.
    pub fn with_status(reason: RerankFailureReason, status: u16) -> Self {
        Self {
            reason,
            http_status: Some(status),
        }
    }
}

impl fmt::Display for RerankError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason.as_str())?;
        if let Some(status) = self.http_status {
            write!(f, " (http {status})")?;
        }
        Ok(())
    }
}

impl std::error::Error for RerankError {}

fn invalid_response() -> RerankError {
    RerankError::new(RerankFailureReason::InvalidResponse)
}

/// The identity evidence of one rerank call.
///
/// Every field is `None` until the corresponding fact is proven. A field is
/// never back-filled from the request: `actual_model` is what the service said,
/// not what was asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallIdentity {
    /// The adapter that actually ran, when the caller can prove it.
    pub actual_provider: Option<ProviderChoice>,
    /// The model the response itself named, when it named one.
    pub actual_model: Option<String>,
    /// The serving provider the response claimed, when it claimed one.
    pub serving_provider: Option<String>,
}

/// The shared result of one rerank call.
///
/// `scores` is one entry per input document, in input order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RerankResponse {
    pub scores: Vec<f64>,
    pub identity: CallIdentity,
    pub http_requests: usize,
    pub duration_ms: u64,
}

/// One rerank backend.
pub trait RerankBackend: Send + Sync {
    /// The fixed selection this backend implements.
    fn provider(&self) -> ProviderChoice;

    /// Score `documents` against `query`, returning one score per document in
    /// input order.
    fn rerank(&self, query: &str, documents: &[String]) -> Result<RerankResponse, RerankError>;
}

/// Validate a backend's `results` array into input-index order.
///
/// `rows` is the `results` array itself. Every entry must carry an `index` that
/// is a JSON non-negative integer, unique and inside `0..expected`, plus a
/// finite `relevance_score`. The array must hold exactly `expected` entries: a
/// missing index is a failure, never a zero-filled gap.
pub fn validate_index_scores(
    rows: &serde_json::Value,
    expected: usize,
) -> Result<Vec<f64>, RerankError> {
    let rows = rows.as_array().ok_or_else(invalid_response)?;
    if rows.len() != expected {
        return Err(invalid_response());
    }

    let mut scores = vec![0.0_f64; expected];
    let mut seen = vec![false; expected];
    for row in rows {
        let row = row.as_object().ok_or_else(invalid_response)?;

        let raw_index = row
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(invalid_response)?;
        let index = usize::try_from(raw_index).map_err(|_| invalid_response())?;
        if index >= expected || seen[index] {
            return Err(invalid_response());
        }
        seen[index] = true;

        let score = row
            .get("relevance_score")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(invalid_response)?;
        if !score.is_finite() {
            return Err(invalid_response());
        }
        scores[index] = score;
    }

    if seen.iter().any(|covered| !covered) {
        return Err(invalid_response());
    }
    Ok(scores)
}

/// Rank indices by descending score, breaking ties on the original index.
///
/// Non-finite scores are refused. The input order is the tie-break, so the
/// result is a stable full permutation of `0..scores.len()`.
pub fn stable_rank_order(scores: &[f64]) -> Result<Vec<usize>, RerankError> {
    if scores.iter().any(|score| !score.is_finite()) {
        return Err(invalid_response());
    }

    let mut order: Vec<usize> = (0..scores.len()).collect();
    order.sort_by(|&left, &right| {
        scores[right]
            .partial_cmp(&scores[left])
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.cmp(&right))
    });
    Ok(order)
}

/// Encode a [`SearchResult`] for private caching.
///
/// This rejects non-finite `score`/`rerank_score` values, then serializes with
/// the public `serde` shape and injects the hidden `content_hash` and
/// `conversation_id` into every hit object. It is the only encoding that
/// carries those two fields; the public JSON output still omits them.
pub fn encode_search_result(result: &SearchResult) -> Result<serde_json::Value, RerankError> {
    for hit in &result.hits {
        if !hit.score.is_finite() {
            return Err(invalid_response());
        }
        if hit.rerank_score.is_some_and(|score| !score.is_finite()) {
            return Err(invalid_response());
        }
    }

    let mut value = serde_json::to_value(result).map_err(|_| invalid_response())?;
    let hits = value
        .get_mut("hits")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(invalid_response)?;
    if hits.len() != result.hits.len() {
        return Err(invalid_response());
    }

    for (slot, hit) in hits.iter_mut().zip(&result.hits) {
        let object = slot.as_object_mut().ok_or_else(invalid_response)?;
        object.insert(
            "content_hash".to_string(),
            serde_json::Value::from(hit.content_hash),
        );
        object.insert(
            "conversation_id".to_string(),
            match hit.conversation_id {
                Some(id) => serde_json::Value::from(id),
                None => serde_json::Value::Null,
            },
        );
    }
    Ok(value)
}

/// Decode a payload produced by [`encode_search_result`].
///
/// Both private keys must be present in every hit object (`conversation_id`
/// may be null). Any missing key, malformed value or non-finite score is
/// refused with the `invalid_response` short code, and no input text is echoed.
pub fn decode_search_result(value: serde_json::Value) -> Result<SearchResult, RerankError> {
    let hits_json = value
        .get("hits")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(invalid_response)?;

    let mut private = Vec::with_capacity(hits_json.len());
    for slot in hits_json {
        let object = slot.as_object().ok_or_else(invalid_response)?;
        let content_hash = object
            .get("content_hash")
            .ok_or_else(invalid_response)?
            .as_u64()
            .ok_or_else(invalid_response)?;
        let conversation_id = match object.get("conversation_id").ok_or_else(invalid_response)? {
            serde_json::Value::Null => None,
            other => Some(other.as_i64().ok_or_else(invalid_response)?),
        };
        private.push((content_hash, conversation_id));
    }

    let mut result: SearchResult = serde_json::from_value(value).map_err(|_| invalid_response())?;
    if result.hits.len() != private.len() {
        return Err(invalid_response());
    }

    for (hit, (content_hash, conversation_id)) in result.hits.iter_mut().zip(private) {
        hit.content_hash = content_hash;
        hit.conversation_id = conversation_id;
    }

    for hit in &result.hits {
        if !hit.score.is_finite() {
            return Err(invalid_response());
        }
        if hit.rerank_score.is_some_and(|score| !score.is_finite()) {
            return Err(invalid_response());
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::query::{
        CacheStats, CandidateMeta, CandidateMode, MatchType, QuerySuggestion, SearchFilters,
        SearchHit, SearchResult, SuggestionKind,
    };
    use clap::ValueEnum as _;
    use serde_json::json;
    use std::collections::HashSet;

    /// Every provider selection with its frozen serde/CLI spelling and its
    /// fixed request model. This table is the single source for the C1 checks
    /// so a rename can never silently pass one surface and fail another.
    const PROVIDER_TABLE: &[(ProviderChoice, &str, &str)] = &[
        (
            ProviderChoice::Qwen3Local,
            "qwen3-local",
            "Qwen3-Reranker-8B-local",
        ),
        (
            ProviderChoice::BgeLocal,
            "bge-local",
            "BAAI/bge-reranker-v2-m3",
        ),
        (
            ProviderChoice::OpenrouterQwen38b,
            "openrouter-qwen3-8b",
            "qwen/qwen3-reranker-8b",
        ),
        (
            ProviderChoice::OpenrouterCohere4Fast,
            "openrouter-cohere-4-fast",
            "cohere/rerank-4-fast",
        ),
        (
            ProviderChoice::OpenrouterVoyage25Lite,
            "openrouter-voyage-2.5-lite",
            "voyageai/rerank-2.5-lite",
        ),
    ];

    fn hit_with(title: &str, score: f32) -> SearchHit {
        SearchHit {
            title: title.to_string(),
            snippet: format!("snippet for {title}"),
            content: format!("content for {title}"),
            content_hash: 0,
            conversation_id: None,
            score,
            source_path: format!("/tmp/{title}.jsonl"),
            agent: "claude".to_string(),
            workspace: "/workspace".to_string(),
            workspace_original: None,
            created_at: Some(1_700_000_000_000),
            line_number: Some(3),
            match_type: MatchType::Exact,
            source_id: "local".to_string(),
            origin_kind: "local".to_string(),
            origin_host: None,
            message_id: Some(7),
            winning_chunk_idx: Some(1),
            winning_chunk_span: Some((10, 20)),
            winning_chunk_hash: Some("abc123".to_string()),
            rerank_score: None,
        }
    }

    fn sample_candidates() -> CandidateMeta {
        CandidateMeta {
            mode: CandidateMode::Knn,
            k: 800,
            first_round_rows: 812,
            unique_messages: 200,
            incomplete: false,
            reason: None,
            approximate: true,
            requested_coarse_k: Some(4096),
            effective_coarse_k: Some(1024),
            coarse_cap_hit: Some(true),
            corpus_limited: Some(false),
            coarse_shard_count: Some(4),
            coarse_rows_collected: Some(1024),
            float_rescore_rows: Some(800),
            coarse_skip_reason: None,
        }
    }

    /// PR9 exact-scan metadata: round 1 was skipped outright, so no coarse
    /// screen ran at all and every coarse field is absent.
    fn exact_scan_candidates() -> CandidateMeta {
        CandidateMeta {
            mode: CandidateMode::Exact,
            k: 0,
            first_round_rows: 0,
            unique_messages: 3,
            incomplete: true,
            reason: Some("exact scan stopped at the row budget".to_string()),
            approximate: false,
            requested_coarse_k: None,
            effective_coarse_k: None,
            coarse_cap_hit: None,
            corpus_limited: None,
            coarse_shard_count: None,
            coarse_rows_collected: None,
            float_rescore_rows: None,
            coarse_skip_reason: Some("no coarse screen ran".to_string()),
        }
    }

    fn sample_result() -> SearchResult {
        let mut first = hit_with("first", 9.5);
        first.content_hash = 0xDEAD_BEEF_CAFE_1234;
        first.conversation_id = Some(4242);
        first.rerank_score = Some(0.75);

        let mut second = hit_with("second", 4.0);
        second.content_hash = 1;
        second.conversation_id = None;
        second.rerank_score = None;

        SearchResult {
            hits: vec![first, second],
            wildcard_fallback: true,
            cache_stats: CacheStats {
                cache_hits: 5,
                eviction_policy: "s3-fifo".to_string(),
                reader_generation: Some(9),
                ..Default::default()
            },
            suggestions: vec![QuerySuggestion {
                kind: SuggestionKind::RemoveFilter,
                message: "remove the agent filter".to_string(),
                suggested_query: Some("query".to_string()),
                suggested_filters: Some(SearchFilters {
                    agents: HashSet::from(["codex".to_string()]),
                    session_paths: HashSet::from(["/tmp/s.jsonl".to_string()]),
                    ..Default::default()
                }),
                shortcut: Some(2),
            }],
            total_count: Some(2),
            candidates: Some(sample_candidates()),
            semantic_degraded: false,
        }
    }

    // ------------------------------------------------------------------
    // C1 - provider choice
    // ------------------------------------------------------------------

    #[test]
    fn provider_choice_matches_serde_cli_and_display() {
        for (choice, wire, _model) in PROVIDER_TABLE {
            assert_eq!(choice.as_str(), *wire);
            assert_eq!(choice.to_string(), *wire);
            assert_eq!(
                serde_json::to_string(choice).unwrap(),
                format!("\"{wire}\"")
            );
            assert_eq!(
                serde_json::from_str::<ProviderChoice>(&format!("\"{wire}\"")).unwrap(),
                *choice
            );
            assert_eq!(wire.parse::<ProviderChoice>().unwrap(), *choice);
        }

        let cli_names: Vec<String> = ProviderChoice::value_variants()
            .iter()
            .map(|v| v.to_possible_value().unwrap().get_name().to_string())
            .collect();
        let expected: Vec<String> = PROVIDER_TABLE
            .iter()
            .map(|(_, w, _)| w.to_string())
            .collect();
        assert_eq!(cli_names, expected);
    }

    #[test]
    fn provider_choice_rejects_unknown_empty_and_case_variants() {
        assert!("".parse::<ProviderChoice>().is_err());
        assert!("   ".parse::<ProviderChoice>().is_err());
        assert!("nope".parse::<ProviderChoice>().is_err());
        // No case folding and no default: the exact wire spelling is required.
        assert!("Qwen3-Local".parse::<ProviderChoice>().is_err());
        assert!("QWEN3-LOCAL".parse::<ProviderChoice>().is_err());
        assert!("qwen3_local".parse::<ProviderChoice>().is_err());

        assert!(serde_json::from_str::<ProviderChoice>("\"\"").is_err());
        assert!(serde_json::from_str::<ProviderChoice>("\"nope\"").is_err());
        assert!(serde_json::from_str::<ProviderChoice>("null").is_err());
        assert!(serde_json::from_value::<ProviderChoice>(json!(7)).is_err());
    }

    #[test]
    fn provider_choice_request_model_and_cloud_flag() {
        for (choice, _wire, model) in PROVIDER_TABLE {
            assert_eq!(choice.request_model(), *model);
        }
        assert!(!ProviderChoice::Qwen3Local.is_cloud());
        assert!(!ProviderChoice::BgeLocal.is_cloud());
        assert!(ProviderChoice::OpenrouterQwen38b.is_cloud());
        assert!(ProviderChoice::OpenrouterCohere4Fast.is_cloud());
        assert!(ProviderChoice::OpenrouterVoyage25Lite.is_cloud());
    }

    #[test]
    fn provider_choice_accepts_request_and_native_model_aliases() {
        // The verified native identities each provider may legitimately report.
        let native = [
            (ProviderChoice::Qwen3Local, "Qwen3-Reranker-8B-local"),
            (ProviderChoice::BgeLocal, "BAAI/bge-reranker-v2-m3"),
            (
                ProviderChoice::OpenrouterQwen38b,
                "accounts/fireworks/models/qwen3-reranker-8b",
            ),
            (ProviderChoice::OpenrouterCohere4Fast, "rerank-v4.0-fast"),
            (ProviderChoice::OpenrouterVoyage25Lite, "rerank-2.5-lite"),
        ];

        for (choice, _wire, request_model) in PROVIDER_TABLE {
            assert!(choice.accepts_model(request_model));
        }
        for (choice, alias) in native {
            assert!(
                choice.accepts_model(alias),
                "{choice:?} should accept {alias}"
            );
        }

        assert!(!ProviderChoice::Qwen3Local.accepts_model("BAAI/bge-reranker-v2-m3"));
        assert!(!ProviderChoice::OpenrouterCohere4Fast.accepts_model("rerank-2.5-lite"));
        assert!(!ProviderChoice::OpenrouterQwen38b.accepts_model("qwen/qwen3-reranker-8b "));
        assert!(!ProviderChoice::Qwen3Local.accepts_model(""));
        assert!(!ProviderChoice::Qwen3Local.accepts_model("Qwen3-Reranker-8B-LOCAL"));
    }

    // ------------------------------------------------------------------
    // C1 - score validation and ordering
    // ------------------------------------------------------------------

    #[test]
    fn validate_index_scores_returns_input_index_order() {
        let rows = json!([
            {"index": 2, "relevance_score": 0.25},
            {"index": 0, "relevance_score": 0.75},
            {"index": 1, "relevance_score": 0.5}
        ]);
        assert_eq!(
            validate_index_scores(&rows, 3).unwrap(),
            vec![0.75, 0.5, 0.25]
        );
    }

    #[test]
    fn validate_index_scores_rejects_malformed_rows() {
        // Wrong row count (missing entry must not be backfilled with 0).
        assert!(validate_index_scores(&json!([{"index": 0, "relevance_score": 1.0}]), 2).is_err());
        // Duplicate index.
        assert!(
            validate_index_scores(
                &json!([
                    {"index": 0, "relevance_score": 1.0},
                    {"index": 0, "relevance_score": 2.0}
                ]),
                2
            )
            .is_err()
        );
        // Out-of-range index.
        assert!(
            validate_index_scores(
                &json!([
                    {"index": 0, "relevance_score": 1.0},
                    {"index": 5, "relevance_score": 2.0}
                ]),
                2
            )
            .is_err()
        );
        // Boolean index.
        assert!(
            validate_index_scores(
                &json!([
                    {"index": true, "relevance_score": 1.0},
                    {"index": 1, "relevance_score": 2.0}
                ]),
                2
            )
            .is_err()
        );
        // Negative index.
        assert!(validate_index_scores(&json!([{"index": -1, "relevance_score": 1.0}]), 1).is_err());
        // Fractional index.
        assert!(
            validate_index_scores(&json!([{"index": 0.5, "relevance_score": 1.0}]), 1).is_err()
        );
        // String score.
        assert!(
            validate_index_scores(&json!([{"index": 0, "relevance_score": "1.0"}]), 1).is_err()
        );
        // Missing score.
        assert!(validate_index_scores(&json!([{"index": 0}]), 1).is_err());
        // Missing index.
        assert!(validate_index_scores(&json!([{"relevance_score": 1.0}]), 1).is_err());
        // Rows is not an array.
        assert!(validate_index_scores(&json!({"results": []}), 0).is_err());
    }

    #[test]
    fn stable_rank_order_is_descending_with_original_index_tie_break() {
        let order = stable_rank_order(&[0.5, 2.0, 2.0, 1.0]).unwrap();
        assert_eq!(order, vec![1, 2, 3, 0]);
        // Empty input is a valid full permutation of nothing.
        assert_eq!(stable_rank_order(&[]).unwrap(), Vec::<usize>::new());
    }

    #[test]
    fn stable_rank_order_rejects_non_finite_scores() {
        assert!(stable_rank_order(&[1.0, f64::NAN]).is_err());
        assert!(stable_rank_order(&[f64::INFINITY]).is_err());
        assert!(stable_rank_order(&[f64::NEG_INFINITY]).is_err());
    }

    // ------------------------------------------------------------------
    // C2 - public JSON shape and the lossless private codec
    // ------------------------------------------------------------------

    #[test]
    fn public_json_hides_private_fields_and_absent_rerank_score() {
        let mut hit = hit_with("first", 3.0);
        hit.content_hash = 0x0123_4567_89AB_CDEF;
        hit.conversation_id = Some(99);
        hit.rerank_score = None;

        let value = serde_json::to_value(&hit).unwrap();
        let obj = value.as_object().unwrap();
        assert!(!obj.contains_key("content_hash"));
        assert!(!obj.contains_key("conversation_id"));
        assert!(!obj.contains_key("rerank_score"));
    }

    #[test]
    fn public_json_includes_some_rerank_score() {
        let mut hit = hit_with("first", 3.0);
        hit.rerank_score = Some(-1.5);
        let value = serde_json::to_value(&hit).unwrap();
        assert_eq!(
            value.get("rerank_score").and_then(|v| v.as_f64()),
            Some(-1.5)
        );
    }

    #[test]
    fn encode_decode_round_trips_private_fields_and_rerank_scores() {
        let original = sample_result();
        let encoded = encode_search_result(&original).unwrap();

        // The private encoding carries the hidden fields for every hit.
        let hits = encoded.get("hits").unwrap().as_array().unwrap();
        assert_eq!(
            hits[0].get("content_hash").unwrap().as_u64(),
            Some(0xDEAD_BEEF_CAFE_1234)
        );
        assert_eq!(hits[0].get("conversation_id").unwrap().as_i64(), Some(4242));
        assert_eq!(hits[0].get("rerank_score").unwrap().as_f64(), Some(0.75));
        assert_eq!(
            hits[1].get("conversation_id").unwrap(),
            &serde_json::Value::Null
        );

        let decoded = decode_search_result(encoded.clone()).unwrap();
        assert_eq!(decoded.hits[0].content_hash, 0xDEAD_BEEF_CAFE_1234);
        assert_eq!(decoded.hits[0].conversation_id, Some(4242));
        assert_eq!(decoded.hits[0].rerank_score, Some(0.75));
        assert_eq!(decoded.hits[1].content_hash, 1);
        assert_eq!(decoded.hits[1].conversation_id, None);
        assert_eq!(decoded.hits[1].rerank_score, None);

        // Re-encoding the decoded value reproduces the private encoding exactly,
        // so a dropped private field or rerank score cannot pass unnoticed.
        assert_eq!(encode_search_result(&decoded).unwrap(), encoded);

        // The public serde surface still hides the private fields.
        let public = serde_json::to_value(&decoded.hits[0]).unwrap();
        assert!(!public.as_object().unwrap().contains_key("content_hash"));
        assert!(!public.as_object().unwrap().contains_key("conversation_id"));
    }

    #[test]
    fn encode_rejects_non_finite_scores() {
        let mut result = sample_result();
        result.hits[0].score = f32::NAN;
        assert_eq!(
            encode_search_result(&result).unwrap_err().reason,
            RerankFailureReason::InvalidResponse
        );

        let mut result = sample_result();
        result.hits[0].rerank_score = Some(f64::INFINITY);
        assert_eq!(
            encode_search_result(&result).unwrap_err().reason,
            RerankFailureReason::InvalidResponse
        );
    }

    #[test]
    fn decode_rejects_missing_private_keys() {
        let original = sample_result();
        let encoded = encode_search_result(&original).unwrap();

        let mut without_hash = encoded.clone();
        without_hash["hits"][0]
            .as_object_mut()
            .unwrap()
            .remove("content_hash");
        assert_eq!(
            decode_search_result(without_hash).unwrap_err().reason,
            RerankFailureReason::InvalidResponse
        );

        let mut without_conversation = encoded.clone();
        without_conversation["hits"][1]
            .as_object_mut()
            .unwrap()
            .remove("conversation_id");
        assert_eq!(
            decode_search_result(without_conversation)
                .unwrap_err()
                .reason,
            RerankFailureReason::InvalidResponse
        );
    }

    #[test]
    fn decode_rejects_values_that_are_not_lossless() {
        let original = sample_result();
        let encoded = encode_search_result(&original).unwrap();

        // A hidden content_hash that is not a non-negative integer.
        let mut bad_hash = encoded.clone();
        bad_hash["hits"][0]["content_hash"] = json!("not-a-number");
        assert!(decode_search_result(bad_hash).is_err());

        // A conversation_id that is neither null nor an integer.
        let mut bad_conversation = encoded.clone();
        bad_conversation["hits"][0]["conversation_id"] = json!("4242");
        assert!(decode_search_result(bad_conversation).is_err());

        // A score that overflows f32 into a non-finite value.
        let mut bad_score = encoded.clone();
        bad_score["hits"][0]["score"] = json!(1e39);
        assert!(decode_search_result(bad_score).is_err());

        // A rerank score that is not a JSON number at all (JSON cannot carry
        // a non-finite f64, so a type violation is the reachable form here).
        let mut bad_rerank = encoded.clone();
        bad_rerank["hits"][0]["rerank_score"] = json!("0.75");
        assert!(decode_search_result(bad_rerank).is_err());
    }

    #[test]
    fn search_result_round_trips_pr9_metadata_and_suggestions() {
        let original = sample_result();
        let decoded = decode_search_result(encode_search_result(&original).unwrap()).unwrap();

        let candidates = decoded
            .candidates
            .expect("candidates must survive the codec");
        assert_eq!(candidates.mode, CandidateMode::Knn);
        assert!(candidates.approximate);
        assert_eq!(candidates.requested_coarse_k, Some(4096));
        assert_eq!(candidates.effective_coarse_k, Some(1024));
        assert_eq!(candidates.coarse_cap_hit, Some(true));
        assert_eq!(candidates.float_rescore_rows, Some(800));

        assert!(decoded.wildcard_fallback);
        assert_eq!(decoded.total_count, Some(2));
        assert_eq!(decoded.cache_stats.eviction_policy, "s3-fifo");
        assert_eq!(decoded.cache_stats.reader_generation, Some(9));
        assert_eq!(decoded.suggestions.len(), 1);
        assert_eq!(decoded.suggestions[0].kind, SuggestionKind::RemoveFilter);
        assert_eq!(decoded.suggestions[0].shortcut, Some(2));
        let suggestion_filters = decoded.suggestions[0]
            .suggested_filters
            .as_ref()
            .expect("suggested_filters must survive the codec");
        assert!(suggestion_filters.agents.contains("codex"));
        assert!(suggestion_filters.session_paths.contains("/tmp/s.jsonl"));
        assert_eq!(suggestion_filters.source_filter, Default::default());
    }

    #[test]
    fn search_result_round_trips_exact_scan_metadata() {
        let mut original = sample_result();
        original.candidates = Some(exact_scan_candidates());

        let encoded = encode_search_result(&original).unwrap();
        let decoded = decode_search_result(encoded.clone()).unwrap();

        let candidates = decoded
            .candidates
            .as_ref()
            .expect("exact-scan candidates must survive the codec");
        assert_eq!(candidates.mode, CandidateMode::Exact);
        assert!(
            !candidates.approximate,
            "an exact scan must read back approximate=false, never true"
        );
        assert_eq!(candidates.k, 0);
        assert_eq!(candidates.first_round_rows, 0);
        assert_eq!(candidates.unique_messages, 3);
        assert!(candidates.incomplete);
        assert_eq!(
            candidates.reason.as_deref(),
            Some("exact scan stopped at the row budget")
        );
        // Absent coarse evidence must read back as absent: not as Some(0),
        // Some(false) or a made-up value.
        assert_eq!(candidates.requested_coarse_k, None);
        assert_eq!(candidates.effective_coarse_k, None);
        assert_eq!(candidates.coarse_cap_hit, None);
        assert_eq!(candidates.corpus_limited, None);
        assert_eq!(candidates.coarse_shard_count, None);
        assert_eq!(candidates.coarse_rows_collected, None);
        assert_eq!(candidates.float_rescore_rows, None);
        assert_eq!(
            candidates.coarse_skip_reason.as_deref(),
            Some("no coarse screen ran")
        );

        assert_eq!(encode_search_result(&decoded).unwrap(), encoded);
    }

    #[test]
    fn search_result_round_trips_knn_exact_mixed_coarse_fields() {
        let mut original = sample_result();
        let mut candidates = sample_candidates();
        candidates.mode = CandidateMode::KnnExact;
        candidates.approximate = false;
        candidates.requested_coarse_k = Some(2048);
        candidates.effective_coarse_k = None; // absent must stay absent
        candidates.coarse_cap_hit = Some(false); // false is not absent
        candidates.corpus_limited = None;
        candidates.coarse_shard_count = Some(0); // zero is not absent
        candidates.coarse_rows_collected = None;
        candidates.float_rescore_rows = Some(512);
        candidates.coarse_skip_reason = Some("partial coarse screen".to_string());
        original.candidates = Some(candidates);

        let encoded = encode_search_result(&original).unwrap();
        let decoded = decode_search_result(encoded.clone()).unwrap();

        let candidates = decoded
            .candidates
            .as_ref()
            .expect("knn+exact candidates must survive the codec");
        assert_eq!(candidates.mode, CandidateMode::KnnExact);
        assert!(!candidates.approximate);
        assert_eq!(candidates.requested_coarse_k, Some(2048));
        assert_eq!(candidates.effective_coarse_k, None);
        assert_eq!(candidates.coarse_cap_hit, Some(false));
        assert_eq!(candidates.corpus_limited, None);
        assert_eq!(candidates.coarse_shard_count, Some(0));
        assert_eq!(candidates.coarse_rows_collected, None);
        assert_eq!(candidates.float_rescore_rows, Some(512));
        assert_eq!(
            candidates.coarse_skip_reason.as_deref(),
            Some("partial coarse screen")
        );

        assert_eq!(encode_search_result(&decoded).unwrap(), encoded);
    }

    #[test]
    fn search_filters_round_trips_with_skipped_defaults_and_source_filter() {
        // Missing optional fields read back as their documented defaults.
        let defaults: SearchFilters = serde_json::from_str("{}").unwrap();
        assert!(defaults.source_filter.is_all());
        assert!(defaults.session_paths.is_empty());
        assert!(defaults.agents.is_empty());
        assert_eq!(defaults.roles, None);

        // A non-default source filter and role set survive a round trip.
        let filters = SearchFilters {
            source_filter: crate::sources::provenance::SourceFilter::SourceId("laptop".into()),
            roles: Some(HashSet::from([1u8, 2u8])),
            ..Default::default()
        };
        let encoded = serde_json::to_value(&filters).unwrap();
        let decoded: SearchFilters = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.source_filter, filters.source_filter);
        assert_eq!(decoded.roles, filters.roles);
    }

    // ------------------------------------------------------------------
    // Error surface
    // ------------------------------------------------------------------

    #[test]
    fn rerank_error_display_exposes_only_short_code_and_status() {
        let plain = RerankError::new(RerankFailureReason::Timeout);
        assert_eq!(plain.to_string(), "timeout");

        let with_status = RerankError::with_status(RerankFailureReason::HttpError, 503);
        let rendered = with_status.to_string();
        assert!(rendered.contains("http_error"));
        assert!(rendered.contains("503"));

        for (reason, code) in [
            (
                RerankFailureReason::UnsupportedProvider,
                "unsupported_provider",
            ),
            (RerankFailureReason::InvalidInput, "invalid_input"),
            (
                RerankFailureReason::MissingCredentials,
                "missing_credentials",
            ),
            (
                RerankFailureReason::NonLoopbackEndpoint,
                "non_loopback_endpoint",
            ),
            (RerankFailureReason::HttpError, "http_error"),
            (RerankFailureReason::Timeout, "timeout"),
            (RerankFailureReason::TransportError, "transport_error"),
            (RerankFailureReason::InvalidResponse, "invalid_response"),
            (
                RerankFailureReason::ModelIdentityMismatch,
                "model_identity_mismatch",
            ),
            (RerankFailureReason::UnscoreableInput, "unscoreable_input"),
            (
                RerankFailureReason::InputIdentityMismatch,
                "input_identity_mismatch",
            ),
        ] {
            assert_eq!(reason.as_str(), code);
            assert_eq!(
                serde_json::to_string(&reason).unwrap(),
                format!("\"{code}\"")
            );
        }
    }
}
