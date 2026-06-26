//! Infinity HTTP embedder + reranker (M4-pre spike).
//!
//! Lets CASS build/search semantic (quality-tier) indexes and rerank by calling
//! a local [Infinity](https://github.com/michaelfeil/infinity) engine over its
//! OpenAI-compatible `/embeddings` + `/rerank` HTTP endpoints, instead of the
//! in-process ONNX runtime. This is what makes the baseline (`--no-default-features
//! --features qr,encryption,infinity`) build ORT-free yet still semantic-capable,
//! and unlocks Chinese embeddings (`bge-m3`) + Chinese rerank (`bge-reranker-v2-m3`).
//!
//! Two seams:
//! - [`InfinityEmbedder`] impl [`Embedder`] — index side (in-process, blocking HTTP).
//! - [`InfinityDaemonClient`] impl [`DaemonClient`] — search side (query embed + rerank).
//!
//! Wire format is probed, not assumed — see `/tmp/cc-infinity-contract.md`.
//! `/rerank` returns results **sorted by score**, so we scatter scores back to
//! document order by `index`.
#![cfg(feature = "infinity")]

use std::io;
use std::time::Duration;

use frankensearch::ModelCategory;
use serde::Deserialize;

use crate::search::daemon_client::{DaemonClient, DaemonError};
use crate::search::embedder::{Embedder, EmbedderError, EmbedderResult};

/// bge-m3 embedding dimension.
const DIMENSION: usize = 1024;
/// Stable embedder id — written into index shard headers; index and search
/// must agree on it. Keep distinct from `embedder_type` ("infinity").
const EMBEDDER_ID: &str = "bge-m3";
/// Default batch size cap for HTTP embed calls.
pub const MAX_BATCH: usize = 64;

// ---- centralized config -----------------------------------------------------

pub struct InfinityConfig {
    pub base_url: String,
    pub embed_model: String,
    pub rerank_model: String,
    pub timeout: Duration,
    pub max_batch: usize,
}

impl InfinityConfig {
    pub fn from_env() -> Self {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    pub fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            base_url: get("CASS_INFINITY_URL")
                .unwrap_or_else(|| "http://127.0.0.1:7997".into())
                .trim_end_matches('/')
                .to_string(),
            embed_model: get("CASS_INFINITY_EMBED_MODEL")
                .unwrap_or_else(|| "BAAI/bge-m3".into()),
            rerank_model: get("CASS_INFINITY_RERANK_MODEL")
                .unwrap_or_else(|| "BAAI/bge-reranker-v2-m3".into()),
            timeout: Duration::from_secs(60),
            max_batch: MAX_BATCH,
        }
    }
}

fn build_client(timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))
}

// ---- wire format (probed) ------------------------------------------------

#[derive(Deserialize)]
struct EmbeddingsResponse {
    data: Vec<EmbeddingItem>,
}

#[derive(Deserialize)]
struct EmbeddingItem {
    embedding: Vec<f32>,
    index: usize,
}

#[derive(Deserialize)]
struct RerankResponse {
    results: Vec<RerankItem>,
}

#[derive(Deserialize)]
struct RerankItem {
    index: usize,
    relevance_score: f32,
}

// ---- shared HTTP helpers (Result<_, String>; callers map to their error) --

/// POST `/embeddings`. Returns embeddings in **input order** (sorted by the
/// per-item `index` field, which Infinity echoes back).
fn http_embed(
    client: &reqwest::blocking::Client,
    base_url: &str,
    model: &str,
    inputs: &[&str],
    expected_dim: usize,
) -> Result<Vec<Vec<f32>>, String> {
    if inputs.is_empty() {
        return Ok(Vec::new());
    }
    let body = serde_json::json!({ "model": model, "input": inputs });
    let resp = client
        .post(format!("{base_url}/embeddings"))
        .json(&body)
        .send()
        .map_err(|e| format!("embeddings request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        return Err(format!("embeddings HTTP {status}: {text}"));
    }
    let parsed: EmbeddingsResponse = resp
        .json()
        .map_err(|e| format!("embeddings decode failed: {e}"))?;
    if parsed.data.len() != inputs.len() {
        return Err(format!(
            "embeddings count mismatch: expected {}, got {}",
            inputs.len(),
            parsed.data.len()
        ));
    }
    // Sort by index so output aligns with input order regardless of server order.
    let mut items = parsed.data;
    items.sort_by_key(|i| i.index);
    let mut out = Vec::with_capacity(items.len());
    for (pos, item) in items.into_iter().enumerate() {
        if item.embedding.len() != expected_dim {
            return Err(format!(
                "embedding dim mismatch at {pos}: expected {expected_dim}, got {}",
                item.embedding.len()
            ));
        }
        out.push(item.embedding);
    }
    Ok(out)
}

/// POST `/rerank`. Returns scores **aligned to `documents` order** (scattered
/// back from Infinity's score-sorted `results` via each item's `index`).
fn http_rerank(
    client: &reqwest::blocking::Client,
    base_url: &str,
    model: &str,
    query: &str,
    documents: &[&str],
) -> Result<Vec<f32>, String> {
    if documents.is_empty() {
        return Ok(Vec::new());
    }
    let body = serde_json::json!({ "model": model, "query": query, "documents": documents });
    let resp = client
        .post(format!("{base_url}/rerank"))
        .json(&body)
        .send()
        .map_err(|e| format!("rerank request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        return Err(format!("rerank HTTP {status}: {text}"));
    }
    let parsed: RerankResponse = resp
        .json()
        .map_err(|e| format!("rerank decode failed: {e}"))?;
    let mut scores = vec![0.0f32; documents.len()];
    for item in parsed.results {
        if item.index >= scores.len() {
            return Err(format!(
                "rerank index {} out of range (docs={})",
                item.index,
                documents.len()
            ));
        }
        scores[item.index] = item.relevance_score;
    }
    Ok(scores)
}

// ---- index side: Embedder -------------------------------------------------

/// In-process [`Embedder`] backed by Infinity's `/embeddings` over blocking HTTP.
pub struct InfinityEmbedder {
    client: reqwest::blocking::Client,
    config: InfinityConfig,
    id: String,
    dimension: usize,
}

impl InfinityEmbedder {
    pub fn new() -> EmbedderResult<Self> {
        let config = InfinityConfig::from_env();
        let client = build_client(config.timeout).map_err(|msg| EmbedderError::SubsystemError {
            subsystem: "infinity-embedder",
            source: Box::new(io::Error::other(msg)),
        })?;
        Ok(Self {
            client,
            config,
            id: EMBEDDER_ID.to_string(),
            dimension: DIMENSION,
        })
    }

    fn fail(&self, msg: String) -> EmbedderError {
        EmbedderError::EmbeddingFailed {
            model: self.id.clone(),
            source: Box::new(io::Error::other(msg)),
        }
    }
}

impl Embedder for InfinityEmbedder {
    fn embed_sync(&self, text: &str) -> EmbedderResult<Vec<f32>> {
        if text.is_empty() {
            return Err(EmbedderError::InvalidConfig {
                field: "input_text".to_string(),
                value: "(empty)".to_string(),
                reason: "empty text".to_string(),
            });
        }
        let mut out = http_embed(
            &self.client,
            &self.config.base_url,
            &self.config.embed_model,
            &[text],
            self.dimension,
        )
        .map_err(|m| self.fail(m))?;
        out.pop()
            .ok_or_else(|| self.fail("infinity returned no embedding".to_string()))
    }

    fn embed_batch_sync(&self, texts: &[&str]) -> EmbedderResult<Vec<Vec<f32>>> {
        for t in texts {
            if t.is_empty() {
                return Err(EmbedderError::InvalidConfig {
                    field: "input_text".to_string(),
                    value: "(empty)".to_string(),
                    reason: "empty text in batch".to_string(),
                });
            }
        }
        http_embed(
            &self.client,
            &self.config.base_url,
            &self.config.embed_model,
            texts,
            self.dimension,
        )
        .map_err(|m| self.fail(m))
    }

    fn dimension(&self) -> usize {
        self.dimension
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn model_name(&self) -> &str {
        &self.config.embed_model
    }

    fn is_semantic(&self) -> bool {
        true
    }

    fn category(&self) -> ModelCategory {
        ModelCategory::ApiEmbedder
    }

    fn tier(&self) -> frankensearch::ModelTier {
        frankensearch::ModelTier::Quality
    }
}

// ---- search side: DaemonClient -------------------------------------------

/// [`DaemonClient`] that fulfils query embedding + rerank against Infinity over
/// HTTP, replacing the UDS daemon. Used as the daemon in `DaemonFallback*`.
pub struct InfinityDaemonClient {
    client: reqwest::blocking::Client,
    config: InfinityConfig,
    dimension: usize,
}

impl InfinityDaemonClient {
    pub fn new() -> Result<Self, DaemonError> {
        let config = InfinityConfig::from_env();
        let client = build_client(config.timeout).map_err(DaemonError::Unavailable)?;
        Ok(Self {
            client,
            config,
            dimension: DIMENSION,
        })
    }
}

impl DaemonClient for InfinityDaemonClient {
    fn id(&self) -> &str {
        "infinity-daemon"
    }

    fn is_available(&self) -> bool {
        // Cheap liveness probe; on failure the DaemonFallback* path falls back.
        self.client
            .get(format!("{}/health", self.config.base_url))
            .timeout(Duration::from_secs(2))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    fn embed(&self, text: &str, _request_id: &str) -> Result<Vec<f32>, DaemonError> {
        let mut out = http_embed(
            &self.client,
            &self.config.base_url,
            &self.config.embed_model,
            &[text],
            self.dimension,
        )
        .map_err(DaemonError::Failed)?;
        out.pop()
            .ok_or_else(|| DaemonError::Failed("infinity returned no embedding".to_string()))
    }

    fn embed_batch(&self, texts: &[&str], _request_id: &str) -> Result<Vec<Vec<f32>>, DaemonError> {
        http_embed(
            &self.client,
            &self.config.base_url,
            &self.config.embed_model,
            texts,
            self.dimension,
        )
        .map_err(DaemonError::Failed)
    }

    fn rerank(
        &self,
        query: &str,
        documents: &[&str],
        _request_id: &str,
    ) -> Result<Vec<f32>, DaemonError> {
        http_rerank(
            &self.client,
            &self.config.base_url,
            &self.config.rerank_model,
            query,
            documents,
        )
        .map_err(DaemonError::Failed)
    }
}

// ---- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_env_defaults_and_overrides() {
        let def = InfinityConfig::from_env_with(|_| None);
        assert_eq!(def.base_url, "http://127.0.0.1:7997");
        assert_eq!(def.embed_model, "BAAI/bge-m3");
        assert_eq!(def.rerank_model, "BAAI/bge-reranker-v2-m3");
        assert_eq!(def.max_batch, 64);
        let ovr = InfinityConfig::from_env_with(|k| match k {
            "CASS_INFINITY_URL" => Some("http://x:9/".into()),
            _ => None,
        });
        assert_eq!(ovr.base_url, "http://x:9"); // 去尾斜杠
    }
}
