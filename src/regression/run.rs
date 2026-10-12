//! One verified aggregate search lifetime. This is shared with the later on runner.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
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
    pub(crate) rerank: Option<usize>,
    pub(crate) semantic: crate::SemanticSearchOptions,
    query_driver: Option<Arc<crate::search::model_api::query_embedding::ApiQueryEmbedder>>,
    query_attempt_start: std::cell::Cell<usize>,
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
            api,
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
        let rerank_limit = match rerank {
            RerankSwitch::Off => None,
            RerankSwitch::On => Some(page_size.ok_or_else(|| anyhow::anyhow!("REQUEST_PROFILE_INVALID"))? as usize),
        };
        let mut semantic = crate::SemanticSearchOptions {
            api: crate::ApiSearchOptions {
                config_path: api.config_path.clone(), embedding_profile: api.embedding_profile.clone(),
                rerank_profile: api.rerank_profile.clone(), no_model_fallback: api.no_model_fallback,
                ..Default::default()
            },
            model: (!api.selected() && *search_mode != SearchMode::Lexical).then(|| "bge-m3".into()),
            rerank: rerank_limit.is_some(), rerank_limit, rerank_provider: *rerank_provider,
            ..Default::default()
        };
        if api.selected() && (*search_mode != SearchMode::Lexical || semantic.rerank) {
            crate::search::model_api::runtime::ensure_no_retired_model_env(|key| std::env::var_os(key))?;
            semantic.api.frozen = Some(crate::search::model_api::runtime::load_config(api.config_path.as_deref(), |key| std::env::var_os(key))?);
        }
        let api_reranker = if semantic.rerank { crate::selected_api_rerank_profile(&semantic).map_err(|e| anyhow::anyhow!(e.message))? } else { None };
        let mut embedding_binding = None;
        let mut query_driver = None;
        if *search_mode != SearchMode::Lexical {
            if let Some(config) = &semantic.api.frozen {
                let profile = crate::select_api_embedding_profile(config, api.embedding_profile.as_deref()).map_err(|e| anyhow::anyhow!(e.message))?;
                embedding_binding = Some({ let conn = context.connection()?; crate::api_regression_embedding_binding(&conn, &profile)? });
                query_driver = Some(client.set_api_semantic_context(Arc::new(crate::search::model_api::ApiClient::new(config.clone(), Box::new(crate::search::model_api::EnvCredentialResolver))), profile, !api.no_model_fallback)?);
            } else {
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
        }        }
        let rerank = rerank_limit;
        let endpoint = api_reranker.as_ref().map(|p| p.endpoint.as_str().to_owned())
            .or_else(|| rerank_provider.map(crate::rerank_endpoint_origin));
        let request = crate::regression_request_evidence(
            &SearchFilters::default(), *search_mode, vector_search_mode.unwrap_or_default(),
            *rrf_limit as usize, None, &semantic, &crate::RerankRequestContext::default(), embedding_binding.as_ref(),
        ).map_err(|_| anyhow::anyhow!("REGRESSION_SEARCH_EVIDENCE_FAILED"))?;
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
            semantic,
            query_driver,
            query_attempt_start: std::cell::Cell::new(0),
            endpoint,
        })
    }

    pub(crate) fn embedding_cost(&self, whole_run: bool) -> Option<Value> {
        let driver = self.query_driver.as_ref()?;
        let attempts = driver.attempts();
        let start = if whole_run { 0 } else { self.query_attempt_start.get() };
        let calls = &attempts[start..];
        let attempted = calls.iter().filter(|c| c.network_attempted).count();
        let responses = calls.iter().filter(|c| c.http_status.is_some()).count();
        Some(json!({"scope":"embedding-http", "http_attempts":attempted,
            "http_response_observed":responses, "delivery_unknown":attempted.saturating_sub(responses),
            "model_executions": if attempted == 0 { Some(0) } else { None::<usize> },
            "basis": if attempted == 0 { "not-called" } else { "observed-client" }}))
    }

    pub(crate) fn persist_embedding_calls(&self) -> Result<()> {
        if let Some(driver) = &self.query_driver {
            let calls: Vec<_> = driver.attempts().iter().map(crate::search::rerank::window::ApiWindowAttempt::from).collect();
            super::off::write_private(&self.validated.paths.run_root, "api-embedding-calls.json", &json!({
                "schema":"cass.regression-api-embedding-calls.v1", "calls":calls,
                "model_executions":null,
            }))?;
        }
        Ok(())
    }

    pub(crate) fn search_window(&self, query: &str) -> Result<RawSearchWindow> {
        self.query_attempt_start.set(self.query_driver.as_ref().map(|d| d.attempts().len()).unwrap_or(0));
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

pub(crate) fn run_with_api_config(command: &RegressionCommand, path: Option<&std::path::Path>) -> Result<Value> {
    let mut command = command.clone();
    match &mut command {
        RegressionCommand::FullSearch { api, .. } | RegressionCommand::FixedCandidate { api, .. } => {
            if let Some(path) = path { api.config_path = Some(path.to_path_buf()); }
        }
        _ => {}
    }
    run(&command)
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
    } else if matches!(command, RegressionCommand::Compare { .. }) {
        run_compare(command)?.into_stdout_value()
    } else {
        super::input::run(command)
    }
}

pub(crate) fn run_compare(command: &RegressionCommand) -> Result<super::compare::CompareOutcome> {
    use super::compare::{CompareRequest, ImportRequest, LabelAction};
    use super::labels::FilePin;
    let RegressionCommand::Compare {
        left,
        left_sha256,
        right,
        right_sha256,
        labels,
        labels_sha256,
        output,
        cutoffs,
        label,
    } = command
    else {
        anyhow::bail!("REQUEST_PROFILE_INVALID");
    };
    ensure!(
        label.label_ancestor.len() == label.label_ancestor_sha256.len(),
        "LABEL_PARENT_MISMATCH"
    );
    let import = if label.label_action == LabelAction::ImportBlind {
        Some(ImportRequest {
            manifest: FilePin::new(
                label
                    .blind_manifest
                    .clone()
                    .context("REQUEST_PROFILE_INVALID")?,
                label
                    .blind_manifest_sha256
                    .clone()
                    .context("REQUEST_PROFILE_INVALID")?,
            )?,
            answers: FilePin::new(
                label
                    .blind_answers
                    .clone()
                    .context("REQUEST_PROFILE_INVALID")?,
                label
                    .blind_answers_sha256
                    .clone()
                    .context("REQUEST_PROFILE_INVALID")?,
            )?,
            version: label
                .new_label_version
                .clone()
                .context("REQUEST_PROFILE_INVALID")?,
        })
    } else {
        ensure!(
            label.blind_manifest.is_none()
                && label.blind_manifest_sha256.is_none()
                && label.blind_answers.is_none()
                && label.blind_answers_sha256.is_none()
                && label.new_label_version.is_none(),
            "REQUEST_PROFILE_INVALID"
        );
        None
    };
    let request = CompareRequest {
        left: FilePin::new(left.clone(), left_sha256.clone())?,
        right: FilePin::new(right.clone(), right_sha256.clone())?,
        labels: FilePin::new(labels.clone(), labels_sha256.clone())?,
        ancestors: label
            .label_ancestor
            .iter()
            .zip(&label.label_ancestor_sha256)
            .map(|(p, h)| FilePin::new(p.clone(), h.clone()))
            .collect::<Result<_>>()?,
        capture_suite: label
            .capture_suite
            .clone()
            .context("REQUEST_PROFILE_INVALID")?,
        capture_suite_sha256: label
            .capture_suite_sha256
            .clone()
            .context("REQUEST_PROFILE_INVALID")?,
        output: output.clone(),
        cutoffs: cutoffs.clone(),
        action: label.label_action,
        import,
    };
    super::compare::run(&request)
}

pub(crate) fn error_code(error: &anyhow::Error) -> &'static str {
    if let Some(code) = super::fixed::named_error_code(error) {
        return code;
    }
    const CODES: &[&str] = &[
        "REGRESSION_MODEL_API_MIGRATION", "ModelApiConfiguration", "ModelApiMigration",
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
