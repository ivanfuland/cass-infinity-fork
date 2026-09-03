//! W3-5 verbatim restore of the `frankensearch` RRF (Reciprocal Rank Fusion)
//! hybrid-search machinery, now that the `frankensearch` Cargo dependency
//! itself is retired. `rrf_fuse`/`RrfConfig`/`ScoreSource`/`ScoredResult`
//! (plus their same-file same-fate siblings `QueryClass`/`candidate_count`/
//! `VectorHit`) are the live main hybrid-search path in
//! `crate::search::query::rrf_fuse_hits` -- not part of the two-tier/
//! progressive retirement.
//!
//! Source: `frankensearch` git rev `2cad158f4468ece7076e3fe529c8e5c20b2e020e`
//! (<https://github.com/Dicklesworthstone/frankensearch>).
//! - `crates/frankensearch-core/src/query_class.rs` -- `QueryClass` copied
//!   verbatim below (whole file).
//! - `crates/frankensearch-core/src/types.rs` -- `VectorHit`, `FusedHit`,
//!   `ScoreSource`, `ScoredResult` copied verbatim below. `ScoredResult`'s
//!   `explanation: Option<HitExplanation>` field is kept for shape parity,
//!   but `HitExplanation` itself is a deliberately simplified local stub
//!   rather than a verbatim port of upstream's 906-line
//!   `frankensearch-core/src/explanation.rs`: `rrf_fuse`'s algorithm never
//!   reads `.explanation`, and grep confirms this crate never constructs a
//!   `Some(_)` value for it (`rrf_fuse_hits` always passes `explanation:
//!   None`) -- porting the full scoring-breakdown telemetry system would
//!   just add ~900 lines of dead weight the W3-5 decommission is retiring
//!   elsewhere. `IndexableDocument`, `SearchMode`, `PhaseMetrics`,
//!   `SearchMetrics`, `EmbeddingMetrics`, `IndexMetrics`, `RankChanges`,
//!   `SearchPhase` are dropped for the same reason (zero consumers,
//!   grep-verified 2026-09-02).
//! - `crates/frankensearch-fusion/src/rrf.rs` -- `RrfConfig`,
//!   `candidate_count`, `rank_contribution`, `sanitize_rrf_k`,
//!   `sanitize_graph_weight`, `FusedHitScratch`, `rrf_fuse`,
//!   `rrf_fuse_with_graph` copied verbatim below.

use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use tracing::{Level, debug, instrument};

// ============================================================================
// frankensearch-core/src/query_class.rs (verbatim, whole file)
// ============================================================================

/// Classification of a search query by type.
///
/// Determines the retrieval budget allocation between lexical and semantic
/// search backends, and influences RRF fusion behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QueryClass {
    /// Empty or whitespace-only query. Returns empty results immediately.
    Empty,
    /// Looks like an identifier: file path, issue ID, function name, symbol.
    /// Lexical search is prioritized for exact-match capability.
    Identifier,
    /// Short keyword query (1-3 words, no question structure).
    /// Balanced between lexical and semantic retrieval.
    ShortKeyword,
    /// Natural language query (question or multi-word descriptive phrase).
    /// Semantic search is prioritized for meaning comprehension.
    NaturalLanguage,
}

impl QueryClass {
    /// Classify a query string into a `QueryClass`.
    ///
    /// Classification is based on heuristics (no ML model required):
    /// - Empty/whitespace → `Empty`
    /// - Contains path separators, `::`, dots-without-spaces, or ID patterns → `Identifier`
    /// - 1-3 words → `ShortKeyword`
    /// - 4+ words → `NaturalLanguage`
    #[must_use]
    pub fn classify(query: &str) -> Self {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Self::Empty;
        }

        if Self::looks_like_identifier(trimmed) {
            return Self::Identifier;
        }

        let word_count = trimmed.split_whitespace().count();
        if word_count <= 3 {
            Self::ShortKeyword
        } else {
            Self::NaturalLanguage
        }
    }

    /// Heuristic check for identifier-like queries.
    fn looks_like_identifier(s: &str) -> bool {
        // Path separators are identifier-like for single-token queries.
        if !s.chars().any(char::is_whitespace) && (s.contains('/') || s.contains('\\')) {
            return true;
        }

        // No whitespace and contains dots or Rust path separators
        if !s.chars().any(char::is_whitespace) && (s.contains('.') || s.contains("::")) {
            return true;
        }

        // camelCase, PascalCase, or snake_case
        if !s.chars().any(char::is_whitespace) {
            if s.contains('_') {
                return true;
            }
            let has_lower = s.chars().any(char::is_lowercase);
            let has_upper = s.chars().any(char::is_uppercase);
            let first_upper = s.chars().next().is_some_and(char::is_uppercase);
            let rest_lower = s.chars().skip(1).all(char::is_lowercase);
            if has_lower && has_upper && !(first_upper && rest_lower) {
                return true;
            }
        }

        // Issue/ticket ID pattern: prefix-digits (e.g., bd-123, JIRA-456, my-project-789)
        if !s.chars().any(char::is_whitespace) && s.contains('-') {
            let parts: Vec<&str> = s.rsplitn(2, '-').collect();
            if parts.len() == 2
                // parts[0] is the suffix (digits), parts[1] is the prefix
                && parts[0].chars().all(|c| c.is_ascii_digit())
                && parts[1].chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                && !parts[0].is_empty()
                && !parts[1].is_empty()
            {
                return true;
            }
        }

        // Starts with common code prefixes
        if s.starts_with("fn ") || s.starts_with("struct ") || s.starts_with("impl ") {
            return true;
        }

        false
    }

    /// Suggested candidate multiplier for lexical search.
    ///
    /// Applied to `TwoTierConfig::candidate_multiplier` to produce the
    /// per-source candidate budget.
    #[must_use]
    pub const fn lexical_budget_multiplier(self) -> f32 {
        match self {
            Self::Empty => 0.0,
            Self::Identifier => 2.0,      // Lean heavily lexical
            Self::ShortKeyword => 1.0,    // Balanced
            Self::NaturalLanguage => 0.5, // Lean semantic
        }
    }

    /// Suggested candidate multiplier for semantic search.
    #[must_use]
    pub const fn semantic_budget_multiplier(self) -> f32 {
        match self {
            Self::Empty => 0.0,
            Self::Identifier => 0.5,      // Lean lexical
            Self::ShortKeyword => 1.0,    // Balanced
            Self::NaturalLanguage => 2.0, // Lean heavily semantic
        }
    }
}

impl std::fmt::Display for QueryClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty"),
            Self::Identifier => write!(f, "identifier"),
            Self::ShortKeyword => write!(f, "short_keyword"),
            Self::NaturalLanguage => write!(f, "natural_language"),
        }
    }
}

// ============================================================================
// frankensearch-core/src/types.rs (verbatim subset -- see module doc comment
// for the `HitExplanation` simplification)
// ============================================================================

/// Simplified stand-in for upstream `frankensearch-core::explanation::HitExplanation`.
/// Never populated (`ScoredResult.explanation` is always `None` in this crate);
/// kept only so `ScoredResult`'s shape matches upstream. See module doc comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitExplanation {}

/// A raw hit from vector similarity search.
///
/// Produced by the vector index before fusion. Scores are raw cosine similarity
/// values (not normalized), typically in the range \[-1.0, 1.0\].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VectorHit {
    /// Positional index into the vector store (used for fast lookup).
    pub index: u32,
    /// Raw cosine similarity score.
    pub score: f32,
    /// Document identifier resolved from the index.
    pub doc_id: String,
}

/// A hit from hybrid fusion (lexical + semantic combined via RRF).
///
/// RRF scores are computed in f64 for precision during accumulation of many
/// small `1/(K+rank+1)` values, then carried as f64 throughout fusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusedHit {
    /// Document identifier.
    pub doc_id: String,
    /// RRF-fused score (f64 for precision during fusion).
    pub rrf_score: f64,
    /// Rank in the lexical (BM25) source, if present.
    pub lexical_rank: Option<usize>,
    /// Rank in the semantic (vector) source, if present.
    pub semantic_rank: Option<usize>,
    /// Internal vector index, if present.
    pub semantic_index: Option<u32>,
    /// Raw BM25 score from lexical search, if applicable.
    pub lexical_score: Option<f32>,
    /// Raw cosine similarity from semantic search, if applicable.
    pub semantic_score: Option<f32>,
    /// True if this document appeared in both lexical and semantic results.
    pub in_both_sources: bool,
}

/// Which search backend produced a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScoreSource {
    /// Lexical (BM25) search only.
    Lexical,
    /// Fast-tier semantic search only.
    SemanticFast,
    /// Quality-tier semantic search only.
    SemanticQuality,
    /// Hybrid fusion (lexical + semantic via RRF).
    Hybrid,
    /// Result was reranked by cross-encoder.
    Reranked,
}

/// The final scored search result delivered to consumers.
///
/// Intentionally does NOT carry document text. Text is expensive and most
/// consumers only need `doc_id` + scores. When text is needed (e.g., for
/// reranking or display), look it up from your document store via `doc_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredResult {
    /// Unique document identifier.
    pub doc_id: String,
    /// Primary relevance score (RRF or blended, truncated to f32).
    pub score: f32,
    /// Which search backend produced this result.
    pub source: ScoreSource,
    /// Internal vector index, if applicable.
    pub index: Option<u32>,
    /// Score from fast-tier semantic search, if applicable.
    pub fast_score: Option<f32>,
    /// Score from quality-tier semantic search, if applicable.
    pub quality_score: Option<f32>,
    /// BM25 score from lexical search, if applicable.
    pub lexical_score: Option<f32>,
    /// Cross-encoder score from reranking, if applicable.
    pub rerank_score: Option<f32>,
    /// Detailed explanation of scoring (if enabled).
    pub explanation: Option<HitExplanation>,
    /// Arbitrary document metadata (from index stored fields).
    pub metadata: Option<serde_json::Value>,
}

// ============================================================================
// frankensearch-fusion/src/rrf.rs (verbatim)
// ============================================================================

// ─── Configuration ──────────────────────────────────────────────────────────
const DEFAULT_RRF_K: f64 = 60.0;

/// RRF fusion parameters.
///
/// The `k` constant controls how steeply rank affects score:
/// - Higher K → flatter distribution (high and low ranks scored similarly)
/// - Lower K → sharper distribution (top ranks much more valuable)
///
/// K=60 is the empirically optimal value from the original paper and is
/// used in production at Elastic, Pinecone, and Vespa.
#[derive(Debug, Clone)]
pub struct RrfConfig {
    /// RRF constant K. Default: 60.0.
    pub k: f64,
}

impl Default for RrfConfig {
    fn default() -> Self {
        Self { k: DEFAULT_RRF_K }
    }
}

// ─── Candidate Budget ───────────────────────────────────────────────────────

/// Compute how many candidates to fetch from each source.
///
/// Fetches `multiplier × (limit + offset)` to ensure good coverage for
/// documents that may rank differently across sources.
///
/// # Arguments
///
/// * `limit` - Number of final results desired.
/// * `offset` - Pagination offset.
/// * `multiplier` - Candidate multiplier (typically 3).
#[must_use]
pub const fn candidate_count(limit: usize, offset: usize, multiplier: usize) -> usize {
    limit.saturating_add(offset).saturating_mul(multiplier)
}

#[inline]
fn rank_contribution(k: f64, rank: usize) -> f64 {
    let rank_u32 = u32::try_from(rank).unwrap_or(u32::MAX);
    1.0 / (k + f64::from(rank_u32) + 1.0)
}

#[inline]
fn sanitize_rrf_k(k: f64) -> f64 {
    if k.is_finite() && k >= 0.0 {
        k
    } else {
        DEFAULT_RRF_K
    }
}

#[inline]
fn sanitize_graph_weight(weight: f64) -> f64 {
    if weight.is_finite() && weight > 0.0 {
        weight
    } else {
        0.0
    }
}

#[derive(Debug)]
struct FusedHitScratch<'a> {
    doc_id: &'a str,
    rrf_score: f64,
    lexical_rank: Option<usize>,
    semantic_rank: Option<usize>,
    semantic_index: Option<u32>,
    graph_rank: Option<usize>,
    lexical_score: Option<f32>,
    semantic_score: Option<f32>,
    graph_score: Option<f32>,
    in_both_sources: bool,
}

impl FusedHitScratch<'_> {
    fn cmp_for_ranking(&self, other: &Self) -> std::cmp::Ordering {
        other
            .rrf_score
            .total_cmp(&self.rrf_score)
            .then(other.in_both_sources.cmp(&self.in_both_sources))
            .then_with(|| {
                let a = self.lexical_score.unwrap_or(f32::NEG_INFINITY);
                let b = other.lexical_score.unwrap_or(f32::NEG_INFINITY);
                b.total_cmp(&a)
            })
            .then_with(|| self.doc_id.cmp(other.doc_id))
    }

    fn into_owned(self) -> FusedHit {
        FusedHit {
            doc_id: self.doc_id.to_owned(),
            rrf_score: self.rrf_score,
            lexical_rank: self.lexical_rank,
            semantic_rank: self.semantic_rank,
            semantic_index: self.semantic_index,
            lexical_score: self.lexical_score,
            semantic_score: self.semantic_score,
            in_both_sources: self.in_both_sources,
        }
    }
}

// ─── RRF Fusion ─────────────────────────────────────────────────────────────

/// Fuse lexical and semantic search results using Reciprocal Rank Fusion.
///
/// # Algorithm
///
/// 1. Assign RRF scores: `1/(K + rank + 1)` for each source (0-based ranks).
/// 2. Sum scores for documents appearing in both sources.
/// 3. Sort by the 4-level deterministic ordering defined on [`FusedHit`]:
///    - RRF score descending
///    - `in_both_sources` (true preferred)
///    - Lexical score descending
///    - `doc_id` ascending (absolute determinism)
/// 4. Apply offset and limit for pagination.
///
/// # Arguments
///
/// * `lexical` - Lexical (BM25) search results, in descending relevance order.
/// * `semantic` - Semantic (vector) search results, in descending score order.
/// * `limit` - Maximum number of results to return.
/// * `offset` - Number of top results to skip (for pagination).
/// * `config` - RRF parameters (K constant).
#[must_use]
#[instrument(
    name = "frankensearch::rrf_fuse",
    skip(lexical, semantic),
    fields(
        lexical_count = lexical.len(),
        semantic_count = semantic.len(),
        k = config.k,
        limit,
        offset,
    )
)]
pub fn rrf_fuse(
    lexical: &[ScoredResult],
    semantic: &[VectorHit],
    limit: usize,
    offset: usize,
    config: &RrfConfig,
) -> Vec<FusedHit> {
    rrf_fuse_with_graph(lexical, semantic, &[], 0.0, limit, offset, config)
}

/// Fuse lexical, semantic, and optional graph-ranked results with weighted RRF.
#[must_use]
#[allow(clippy::too_many_lines)]
#[instrument(
    name = "frankensearch::rrf_fuse_with_graph",
    skip(lexical, semantic, graph),
    fields(
        lexical_count = lexical.len(),
        semantic_count = semantic.len(),
        graph_count = graph.len(),
        graph_weight,
        k = config.k,
        limit,
        offset,
    )
)]
pub fn rrf_fuse_with_graph(
    lexical: &[ScoredResult],
    semantic: &[VectorHit],
    graph: &[ScoredResult],
    graph_weight: f64,
    limit: usize,
    offset: usize,
    config: &RrfConfig,
) -> Vec<FusedHit> {
    let k = sanitize_rrf_k(config.k);
    let graph_weight = sanitize_graph_weight(graph_weight);
    // Adjusted for typical ~50% overlap to reduce over-allocation.
    let graph_len = if graph_weight > 0.0 { graph.len() } else { 0 };
    let capacity = (lexical.len() + semantic.len() + graph_len) * 3 / 4 + 1;
    let mut hits: AHashMap<&str, FusedHitScratch<'_>> = AHashMap::with_capacity(capacity);

    // Score lexical results.
    for (rank, result) in lexical.iter().enumerate() {
        // If we've already seen this doc in this source (lexical), skip it.
        // We iterate in rank order (0, 1, ...), so the first occurrence is the best one.
        if let Some(existing) = hits.get(result.doc_id.as_str())
            && existing.lexical_rank.is_some()
        {
            continue;
        }

        let rrf_contribution = rank_contribution(k, rank);

        hits.entry(result.doc_id.as_str())
            .and_modify(|hit| {
                hit.rrf_score += rrf_contribution;
                hit.lexical_rank = Some(rank);
                hit.lexical_score = Some(result.score);
                // Compute in_both_sources inline: if semantic was already seen.
                if hit.semantic_rank.is_some() {
                    hit.in_both_sources = true;
                }
            })
            .or_insert_with(|| FusedHitScratch {
                doc_id: result.doc_id.as_str(),
                rrf_score: rrf_contribution,
                lexical_rank: Some(rank),
                semantic_rank: None,
                semantic_index: None,
                graph_rank: None,
                lexical_score: Some(result.score),
                semantic_score: None,
                graph_score: None,
                in_both_sources: false,
            });
    }

    // Score semantic results.
    for (rank, hit) in semantic.iter().enumerate() {
        // If we've already seen this doc in this source (semantic), skip it.
        if let Some(existing) = hits.get(hit.doc_id.as_str())
            && existing.semantic_rank.is_some()
        {
            continue;
        }

        let rrf_contribution = rank_contribution(k, rank);

        hits.entry(hit.doc_id.as_str())
            .and_modify(|fh| {
                fh.rrf_score += rrf_contribution;
                fh.semantic_rank = Some(rank);
                fh.semantic_score = Some(hit.score);
                fh.semantic_index = Some(hit.index);
                // Compute in_both_sources inline: if lexical was already seen.
                if fh.lexical_rank.is_some() {
                    fh.in_both_sources = true;
                }
            })
            .or_insert_with(|| FusedHitScratch {
                doc_id: hit.doc_id.as_str(),
                rrf_score: rrf_contribution,
                lexical_rank: None,
                semantic_rank: Some(rank),
                semantic_index: Some(hit.index),
                graph_rank: None,
                lexical_score: None,
                semantic_score: Some(hit.score),
                graph_score: None,
                in_both_sources: false,
            });
    }

    if graph_weight > 0.0 {
        for (rank, result) in graph.iter().enumerate() {
            // If we've already seen this doc in this source (graph), skip it.
            if let Some(existing) = hits.get(result.doc_id.as_str())
                && existing.graph_rank.is_some()
            {
                continue;
            }

            let rrf_contribution = rank_contribution(k, rank) * graph_weight;
            hits.entry(result.doc_id.as_str())
                .and_modify(|hit| {
                    hit.rrf_score += rrf_contribution;
                    hit.graph_rank = Some(rank);
                    hit.graph_score = Some(result.score);
                })
                .or_insert_with(|| FusedHitScratch {
                    doc_id: result.doc_id.as_str(),
                    rrf_score: rrf_contribution,
                    lexical_rank: None,
                    semantic_rank: None,
                    semantic_index: None,
                    graph_rank: Some(rank),
                    lexical_score: None,
                    semantic_score: None,
                    graph_score: Some(result.score),
                    in_both_sources: false,
                });
        }
    }

    // in_both_sources was computed inline during insertion — no separate pass needed.
    let mut results: Vec<FusedHitScratch<'_>> = hits.into_values().collect();

    let overlap_count = tracing::enabled!(target: "frankensearch.rrf", Level::DEBUG)
        .then(|| results.iter().filter(|h| h.in_both_sources).count());
    let fused_count = results.len();

    // Ranking window needed for pagination. For small windows this avoids
    // sorting every fused hit while preserving deterministic output order.
    let window = limit.saturating_add(offset);
    if window == 0 {
        if let Some(overlap_count) = overlap_count {
            debug!(
                target: "frankensearch.rrf",
                fused_count,
                overlap_count,
                output_count = 0,
                "rrf fusion complete"
            );
        }
        return Vec::new();
    }
    if window < results.len() {
        let nth_index = window.saturating_sub(1);
        results.select_nth_unstable_by(nth_index, FusedHitScratch::cmp_for_ranking);
        results.truncate(window);
    }

    // Deterministic comparator gives a total order, so unstable sort is safe
    // and avoids stable-sort overhead on large candidate sets.
    results.sort_unstable_by(FusedHitScratch::cmp_for_ranking);

    // Apply offset and limit.
    let output: Vec<FusedHit> = results
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(FusedHitScratch::into_owned)
        .collect();

    if let Some(overlap_count) = overlap_count {
        debug!(
            target: "frankensearch.rrf",
            fused_count,
            overlap_count,
            output_count = output.len(),
            "rrf fusion complete"
        );
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lexical_hit(doc_id: &str, score: f32) -> ScoredResult {
        ScoredResult {
            doc_id: doc_id.into(),
            score,
            source: ScoreSource::Lexical,
            index: None,
            fast_score: None,
            quality_score: None,
            lexical_score: Some(score),
            rerank_score: None,
            explanation: None,
            metadata: None,
        }
    }

    fn semantic_hit(doc_id: &str, score: f32) -> VectorHit {
        VectorHit {
            index: 0,
            score,
            doc_id: doc_id.into(),
        }
    }

    fn graph_hit(doc_id: &str, score: f32) -> ScoredResult {
        ScoredResult {
            doc_id: doc_id.into(),
            score,
            source: ScoreSource::SemanticFast,
            index: Some(0),
            fast_score: Some(score),
            quality_score: None,
            lexical_score: None,
            rerank_score: None,
            explanation: None,
            metadata: None,
        }
    }

    // ─── Score formula tests ────────────────────────────────────────────

    #[test]
    fn rrf_score_formula_k60() {
        let config = RrfConfig::default();
        let lexical = vec![lexical_hit("doc-a", 10.0)];
        let semantic = vec![];

        let results = rrf_fuse(&lexical, &semantic, 10, 0, &config);

        assert_eq!(results.len(), 1);
        let expected = 1.0 / (60.0 + 0.0 + 1.0); // rank 0 → 1/61
        assert!(
            (results[0].rrf_score - expected).abs() < 1e-12,
            "expected {expected}, got {}",
            results[0].rrf_score
        );
    }

    #[test]
    fn rrf_score_formula_k1() {
        let config = RrfConfig { k: 1.0 };
        let semantic = vec![semantic_hit("first", 0.9), semantic_hit("second", 0.8)];

        let results = rrf_fuse(&[], &semantic, 10, 0, &config);

        assert_eq!(results.len(), 2);
        // rank 0: 1/(1+0+1) = 0.5
        // rank 1: 1/(1+1+1) = 0.333...
        assert!((results[0].rrf_score - 0.5).abs() < 1e-12);
        assert!((results[1].rrf_score - 1.0 / 3.0).abs() < 1e-12);
    }

    #[test]
    fn rrf_score_formula_k0_is_valid() {
        let config = RrfConfig { k: 0.0 };
        let lexical = vec![lexical_hit("doc-a", 10.0)];

        let results = rrf_fuse(&lexical, &[], 10, 0, &config);

        assert_eq!(results.len(), 1);
        assert!((results[0].rrf_score - 1.0).abs() < 1e-12);
    }

    #[test]
    fn invalid_k_falls_back_to_default() {
        let lexical = vec![lexical_hit("doc-a", 10.0)];
        let expected = 1.0 / (DEFAULT_RRF_K + 1.0);

        for invalid_k in [f64::NAN, f64::INFINITY, -1.0, -100.0] {
            let config = RrfConfig { k: invalid_k };
            let results = rrf_fuse(&lexical, &[], 10, 0, &config);
            assert_eq!(results.len(), 1);
            assert!(
                (results[0].rrf_score - expected).abs() < 1e-12,
                "invalid k={invalid_k} should fall back to default",
            );
        }
    }

    // ─── Multi-source fusion ────────────────────────────────────────────

    #[test]
    fn document_in_both_sources_gets_summed_score() {
        let config = RrfConfig::default();
        let lexical = vec![lexical_hit("shared", 5.0)];
        let semantic = vec![semantic_hit("shared", 0.9)];

        let results = rrf_fuse(&lexical, &semantic, 10, 0, &config);

        assert_eq!(results.len(), 1);
        let expected = 2.0 / 61.0; // Both at rank 0 → 1/61 + 1/61
        assert!(
            (results[0].rrf_score - expected).abs() < 1e-12,
            "expected {expected}, got {}",
            results[0].rrf_score
        );
        assert!(results[0].in_both_sources);
        assert_eq!(results[0].lexical_rank, Some(0));
        assert_eq!(results[0].semantic_rank, Some(0));
    }

    #[test]
    fn multi_source_doc_ranks_higher_than_single_source() {
        let config = RrfConfig::default();
        let lexical = vec![lexical_hit("shared", 5.0), lexical_hit("lex-only", 4.0)];
        let semantic = vec![semantic_hit("shared", 0.9), semantic_hit("sem-only", 0.8)];

        let results = rrf_fuse(&lexical, &semantic, 10, 0, &config);

        assert_eq!(results.len(), 3);
        // "shared" should be first (highest combined score)
        assert_eq!(results[0].doc_id, "shared");
        assert!(results[0].in_both_sources);
    }

    #[test]
    fn graph_channel_can_promote_document_with_weighted_rrf() {
        let config = RrfConfig::default();
        let semantic = vec![semantic_hit("a", 0.9), semantic_hit("b", 0.8)];
        let graph = vec![graph_hit("b", 1.0)];

        let results = rrf_fuse_with_graph(&[], &semantic, &graph, 1.0, 10, 0, &config);

        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0].doc_id, "b",
            "graph contribution should promote b above semantic rank-0 doc a"
        );
    }

    #[test]
    fn zero_graph_weight_matches_two_source_rrf() {
        let config = RrfConfig::default();
        let lexical = vec![lexical_hit("a", 10.0)];
        let semantic = vec![semantic_hit("b", 0.9)];
        let graph = vec![graph_hit("b", 1.0)];

        let base = rrf_fuse(&lexical, &semantic, 10, 0, &config);
        let weighted = rrf_fuse_with_graph(&lexical, &semantic, &graph, 0.0, 10, 0, &config);

        assert_eq!(weighted.len(), base.len());
        assert_eq!(weighted[0].doc_id, base[0].doc_id);
        assert!((weighted[0].rrf_score - base[0].rrf_score).abs() < 1e-12);
    }

    // ─── Single-source fusion ───────────────────────────────────────────

    #[test]
    fn lexical_only_produces_correct_ranking() {
        let config = RrfConfig::default();
        let lexical = vec![
            lexical_hit("a", 10.0),
            lexical_hit("b", 8.0),
            lexical_hit("c", 5.0),
        ];

        let results = rrf_fuse(&lexical, &[], 10, 0, &config);

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].doc_id, "a");
        assert_eq!(results[1].doc_id, "b");
        assert_eq!(results[2].doc_id, "c");
        // All single-source
        assert!(results.iter().all(|r| !r.in_both_sources));
    }

    #[test]
    fn semantic_only_produces_correct_ranking() {
        let config = RrfConfig::default();
        let semantic = vec![semantic_hit("x", 0.95), semantic_hit("y", 0.85)];

        let results = rrf_fuse(&[], &semantic, 10, 0, &config);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].doc_id, "x");
        assert_eq!(results[1].doc_id, "y");
    }

    // ─── Empty input ────────────────────────────────────────────────────

    #[test]
    fn both_empty_returns_empty() {
        let results = rrf_fuse(&[], &[], 10, 0, &RrfConfig::default());
        assert!(results.is_empty());
    }

    // ─── Offset and limit ───────────────────────────────────────────────

    #[test]
    fn limit_truncates_results() {
        let config = RrfConfig::default();
        let semantic = vec![
            semantic_hit("a", 0.9),
            semantic_hit("b", 0.8),
            semantic_hit("c", 0.7),
        ];

        let results = rrf_fuse(&[], &semantic, 2, 0, &config);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].doc_id, "a");
        assert_eq!(results[1].doc_id, "b");
    }

    #[test]
    fn offset_skips_top_results() {
        let config = RrfConfig::default();
        let semantic = vec![
            semantic_hit("a", 0.9),
            semantic_hit("b", 0.8),
            semantic_hit("c", 0.7),
        ];

        let results = rrf_fuse(&[], &semantic, 10, 1, &config);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].doc_id, "b");
        assert_eq!(results[1].doc_id, "c");
    }

    #[test]
    fn offset_and_limit_combined() {
        let config = RrfConfig::default();
        let semantic = vec![
            semantic_hit("a", 0.9),
            semantic_hit("b", 0.8),
            semantic_hit("c", 0.7),
            semantic_hit("d", 0.6),
        ];

        let results = rrf_fuse(&[], &semantic, 2, 1, &config);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].doc_id, "b");
        assert_eq!(results[1].doc_id, "c");
    }

    // ─── Tie-breaking ───────────────────────────────────────────────────

    #[test]
    fn tie_breaking_in_both_sources_preferred() {
        let config = RrfConfig::default();
        let lexical = vec![
            lexical_hit("only-lex", 10.0), // rank 0 → 1/61
        ];
        let semantic = vec![
            semantic_hit("only-sem", 0.9), // rank 0 → 1/61
        ];

        let results = rrf_fuse(&lexical, &semantic, 10, 0, &config);

        // Both have same RRF score (1/61). Neither is in both sources.
        // Tie-break goes to lexical_score (only-lex has Some(10.0), only-sem has None).
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].doc_id, "only-lex"); // has lexical_score
    }

    #[test]
    fn tie_breaking_doc_id_ascending() {
        let config = RrfConfig::default();
        // Same semantic scores, same rank structure, different doc_ids
        let semantic = vec![
            semantic_hit("beta", 0.9), // rank 0
        ];
        let lexical = vec![
            lexical_hit("alpha", 10.0), // rank 0
        ];

        let results = rrf_fuse(&lexical, &semantic, 10, 0, &config);

        // Same RRF, same in_both_sources (false). lexical_score tiebreak:
        // "alpha" has Some(10.0), "beta" has None → alpha first.
        assert_eq!(results[0].doc_id, "alpha");
        assert_eq!(results[1].doc_id, "beta");
    }

    // ─── Candidate budget ───────────────────────────────────────────────

    #[test]
    fn candidate_count_basic() {
        assert_eq!(candidate_count(10, 0, 3), 30);
        assert_eq!(candidate_count(10, 5, 3), 45);
        assert_eq!(candidate_count(20, 0, 4), 80);
    }

    #[test]
    fn candidate_count_overflow_safety() {
        // Should not panic on overflow
        let result = candidate_count(usize::MAX, 1, 3);
        assert_eq!(result, usize::MAX); // saturating
    }

    // ─── QueryClass ───────────────────────────────────────────────────

    #[test]
    fn classify_empty_string() {
        assert_eq!(QueryClass::classify(""), QueryClass::Empty);
    }

    #[test]
    fn classify_file_path() {
        assert_eq!(QueryClass::classify("src/main.rs"), QueryClass::Identifier);
    }

    #[test]
    fn classify_single_word() {
        assert_eq!(QueryClass::classify("search"), QueryClass::ShortKeyword);
    }

    #[test]
    fn classify_question() {
        assert_eq!(
            QueryClass::classify("how does the search pipeline work?"),
            QueryClass::NaturalLanguage
        );
    }

    #[test]
    fn display_all_variants() {
        assert_eq!(QueryClass::Empty.to_string(), "empty");
        assert_eq!(QueryClass::Identifier.to_string(), "identifier");
        assert_eq!(QueryClass::ShortKeyword.to_string(), "short_keyword");
        assert_eq!(QueryClass::NaturalLanguage.to_string(), "natural_language");
    }
}
