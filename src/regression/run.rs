//! One verified aggregate search lifetime. This is shared with the later on runner.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, bail};
use serde_json::{Value, json};

use super::types::{RegressionCommand, RerankSwitch, ValidatedRun};
use crate::search::query::{
    FieldMask, SearchClient, SearchFilters, SearchMode, SearchResult, VectorSearchMode,
};
use crate::search::regression_binding::{self, InputBinding};
use crate::search::regression_io::RegressionIoContext;
use crate::search::regression_trace::{self, WindowEvidence};

pub(crate) struct RegressionSearchRun {
    pub(crate) validated: ValidatedRun,
    pub(crate) context: Arc<RegressionIoContext>,
    pub(crate) binding: InputBinding,
    pub(crate) client: SearchClient,
    pub(crate) mode: SearchMode,
    pub(crate) vector_mode: Option<VectorSearchMode>,
    pub(crate) n: usize,
    pub(crate) request: Value,
    pub(crate) rerank: Option<(usize, crate::search::rerank::types::ProviderChoice)>,
    pub(crate) endpoint: Option<String>,
}

pub(crate) struct RawSearchWindow {
    pub(crate) result: SearchResult,
    pub(crate) stamp: crate::search::rerank::window::IndexStamp,
    pub(crate) identity_before_ms: f64,
    pub(crate) identity_after_ms: f64,
    pub(crate) retrieval_ms: f64,
}

pub(crate) struct RecordedSearch {
    pub(crate) result: SearchResult,
    pub(crate) evidence: WindowEvidence,
    pub(crate) evidence_path: std::path::PathBuf,
    pub(crate) identity_before_ms: f64,
    pub(crate) identity_after_ms: f64,
    pub(crate) retrieval_ms: f64,
}

pub(crate) fn milliseconds(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

impl RegressionSearchRun {
    pub(crate) fn activate(validated: ValidatedRun, command: &RegressionCommand) -> Result<Self> {
        let RegressionCommand::FullSearch {
            search_mode,
            vector_search_mode,
            rrf_limit,
            rerank,
            page_size,
            rerank_provider,
            ..
        } = command
        else {
            bail!("REQUEST_PROFILE_INVALID");
        };
        let context = validated
            .context
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("AGGREGATE_INPUT_MISSING"))?
            .clone();
        let verified = regression_binding::activate_prepared_search(
            context.clone(),
            validated
                .expected_binding
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("AGGREGATE_INPUT_MISSING"))?,
            validated
                .expected_binding_file_sha256
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("AGGREGATE_INPUT_MISSING"))?,
            validated
                .source_manifest
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("AGGREGATE_INPUT_MISSING"))?,
        )?;
        if Some(&verified.expected_file_sha256) != validated.expected_binding_file_sha256.as_ref() {
            bail!("EXPECTED_BINDING_FILE_DIGEST_MISMATCH");
        }
        let client = verified
            .client
            .with_vector_search_mode(vector_search_mode.unwrap_or_default());
        let mut embedding_binding = None;
        if *search_mode != SearchMode::Lexical {
            #[cfg(not(feature = "infinity"))]
            bail!("REGRESSION_SEMANTIC_NOT_INTEGRATED");
            #[cfg(feature = "infinity")]
            {
                let config = crate::search::infinity::InfinityConfig::from_env();
                if config.embed_model != "BAAI/bge-m3" {
                    bail!("REGRESSION_EMBEDDING_CONFIGURATION_MISMATCH");
                }
                let setup =
                    crate::search::model_manager::load_infinity_semantic_context_for_regression(
                        &context, &config,
                    )?;
                let semantic = setup
                    .context
                    .ok_or_else(|| anyhow::anyhow!("REGRESSION_SEMANTIC_NOT_INTEGRATED"))?;
                client.set_semantic_context(semantic.embedder, semantic.roles)?;
                embedding_binding = Some(json!({
                    "requested_model": config.embed_model,
                    "origin_sha256": regression_trace::TextDigest::of(&config.base_url).sha256,
                    "dimension": config.expected_dim,
                    "timeout_ms": config.timeout.as_millis() as u64,
                    "max_batch": config.max_batch,
                }));
            }
        }
        let rerank = match rerank {
            RerankSwitch::Off => None,
            RerankSwitch::On => Some((
                page_size.ok_or_else(|| anyhow::anyhow!("REQUEST_PROFILE_INVALID"))? as usize,
                rerank_provider.ok_or_else(|| anyhow::anyhow!("REQUEST_PROFILE_INVALID"))?,
            )),
        };
        let endpoint = rerank.map(|(_, provider)| crate::rerank_endpoint_origin(provider));
        let request = crate::regression_request_evidence(
            &SearchFilters::default(),
            *search_mode,
            vector_search_mode.unwrap_or_default(),
            *rrf_limit as usize,
            None,
            &crate::SemanticSearchOptions {
                model: (*search_mode != SearchMode::Lexical).then(|| "bge-m3".into()),
                rerank: rerank.is_some(),
                reranker: None,
                use_daemon: false,
                rerank_limit: rerank.map(|(k, _)| k),
                rerank_provider: rerank.map(|(_, p)| p),
            },
            &crate::RerankRequestContext::default(),
            embedding_binding.as_ref(),
        )
        .map_err(|_| anyhow::anyhow!("REGRESSION_SEARCH_EVIDENCE_FAILED"))?;
        Ok(Self {
            validated,
            context,
            binding: verified.binding,
            client,
            mode: *search_mode,
            vector_mode: *vector_search_mode,
            n: *rrf_limit as usize,
            request,
            rerank,
            endpoint,
        })
    }

    pub(crate) fn search_window(&self, query: &str) -> Result<RawSearchWindow> {
        let identity_start = Instant::now();
        let before =
            crate::search::rerank::window::capture_index_stamp_for_regression(&self.context)?;
        let identity_before_ms = milliseconds(identity_start);
        let start = Instant::now();
        let mut mode = crate::SearchModeMeta::new(self.mode, false);
        let result = crate::execute_search_retrieval(
            &self.client,
            query,
            &SearchFilters::default(),
            self.n.saturating_add(1),
            0,
            crate::sparse_threshold_for_visible_limit(3, self.n, false),
            FieldMask::FULL,
            &mut mode,
            false,
        )
        .map_err(|error| anyhow::anyhow!("REGRESSION_SEARCH_FAILED: {}", error.message))?;
        let retrieval_ms = milliseconds(start);
        validate_retrieval(&result, mode.realized == mode.requested, false)?;
        let identity_start = Instant::now();
        let after =
            crate::search::rerank::window::capture_index_stamp_for_regression(&self.context)?;
        if before != after {
            bail!("AGGREGATE_QUERY_IDENTITY_CHANGED");
        }
        let identity_after_ms = milliseconds(identity_start);
        Ok(RawSearchWindow {
            result,
            stamp: before,
            identity_before_ms,
            identity_after_ms,
            retrieval_ms,
        })
    }

    pub(crate) fn search_off(&self, query: &str) -> Result<RecordedSearch> {
        let RawSearchWindow {
            mut result,
            stamp: before,
            identity_before_ms,
            identity_after_ms: raw_after_ms,
            retrieval_ms,
        } = self.search_window(query)?;
        result.hits.truncate(self.n);
        let evidence = regression_trace::off_evidence(
            &self.context,
            &self.binding,
            query,
            &result.hits,
            self.request.clone(),
            self.mode != SearchMode::Semantic,
        )?;
        let evidence_path = regression_trace::persist_evidence(&self.context, &evidence)?;
        let identity_start = Instant::now();
        let after =
            crate::search::rerank::window::capture_index_stamp_for_regression(&self.context)?;
        if before != after {
            bail!("AGGREGATE_QUERY_IDENTITY_CHANGED");
        }
        let identity_after_ms = raw_after_ms + milliseconds(identity_start);
        Ok(RecordedSearch {
            result,
            evidence,
            evidence_path,
            identity_before_ms,
            identity_after_ms,
            retrieval_ms,
        })
    }

    pub(crate) fn verify_end(&self) -> Result<()> {
        regression_binding::verify_aggregate_end(
            &self.context,
            &self.binding,
            self.validated
                .source_manifest
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("AGGREGATE_INPUT_MISSING"))?,
        )
    }
}

pub(crate) fn validate_retrieval(
    result: &SearchResult,
    unchanged_mode: bool,
    timed_out: bool,
) -> Result<()> {
    if timed_out {
        bail!("REGRESSION_SEARCH_TIMEOUT");
    }
    if result.candidates.as_ref().is_some_and(|c| c.incomplete) {
        bail!("REGRESSION_PARTIAL_RESULTS");
    }
    if result.semantic_degraded || !unchanged_mode {
        bail!("REGRESSION_RETRIEVAL_DEGRADED");
    }
    if result
        .hits
        .iter()
        .any(|h| !h.score.is_finite() || h.rerank_score.is_some())
    {
        bail!("REGRESSION_INVALID_OFF_SCORE");
    }
    Ok(())
}

pub(crate) fn run(command: &RegressionCommand) -> Result<Value> {
    if matches!(
        command,
        RegressionCommand::FullSearch {
            rerank: RerankSwitch::Off,
            ..
        }
    ) {
        super::off::run(command)
    } else if matches!(
        command,
        RegressionCommand::FullSearch {
            rerank: RerankSwitch::On,
            ..
        }
    ) {
        super::on::run(command)
    } else if matches!(command, RegressionCommand::FixedCandidate { .. }) {
        super::fixed::run(command)
    } else {
        super::input::run(command)
    }
}

pub(crate) fn error_code(error: &anyhow::Error) -> &'static str {
    if let Some(code) = super::fixed::named_error_code(error) {
        return code;
    }
    const CODES: &[&str] = &[
        "AGGREGATE_INPUT_MISSING",
        "AGGREGATE_GENERATION_CHANGED",
        "AGGREGATE_POLICY_CHANGED",
        "AGGREGATE_QUERY_IDENTITY_CHANGED",
        "REGRESSION_SEARCH_TIMEOUT",
        "REGRESSION_PARTIAL_RESULTS",
        "REGRESSION_INVALID_OFF_SCORE",
        "REGRESSION_PROVENANCE_UNAVAILABLE",
        "QUERY_MANIFEST_INVALID",
        "REGRESSION_REPORT_WRITE_FAILED",
    ];
    let text = format!("{error:#}");
    if let Some(code) = CODES.iter().find(|code| text.contains(**code)) {
        return code;
    }
    const WINDOW_CODES: &[&str] = &[
        "invalid_input",
        "cache_unavailable",
        "not_found",
        "invalid_cursor",
        "corrupt",
        "expired",
        "binding_mismatch",
        "index_changed",
    ];
    for cause in error.chain() {
        if let Some(code) = WINDOW_CODES.iter().find(|code| cause.to_string() == **code) {
            return code;
        }
    }
    let input = super::input::error_code(error);
    if input != "REGRESSION_INPUT_FAILED" {
        return input;
    }
    let search = crate::search::regression_input::error_code(error);
    if search != "REGRESSION_INPUT_FAILED" {
        return search;
    }
    "REGRESSION_SEARCH_FAILED"
}
