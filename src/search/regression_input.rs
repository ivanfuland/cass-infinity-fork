//! Explicit CLI for frozen-input inspection and independently pinned admission.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use clap::{Args, Subcommand};

use super::regression_binding::{inspect_input, open_verified_search};
use super::regression_io::RegressionIoContext;

#[derive(Debug, Clone, Args)]
pub struct FrozenInputArgs {
    #[arg(long, value_name = "FILE")]
    pub database: PathBuf,
    #[arg(long, value_name = "DIRECTORY")]
    pub run_root: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub source_manifest: PathBuf,
    /// Actual private question-package directory; output must be outside it.
    #[arg(long, value_name = "DIRECTORY")]
    pub question_pack_root: PathBuf,
}

#[derive(Debug, Clone, Default, Args)]
pub struct RegressionApiOptions {
    #[arg(skip)]
    pub config_path: Option<PathBuf>,
    #[arg(long)]
    pub embedding_profile: Option<String>,
    #[arg(long)]
    pub rerank_profile: Option<String>,
    #[arg(long)]
    pub no_model_fallback: bool,
}

impl RegressionApiOptions {
    pub(crate) fn selected(&self) -> bool {
        self.config_path.is_some() || self.embedding_profile.is_some() || self.rerank_profile.is_some()
            || std::env::var_os(crate::search::model_api::runtime::API_CONFIG_ENV).is_some()
    }
}

#[derive(Debug, Clone, Subcommand)]
pub enum RegressionInputCommand {
    /// Search the verified frozen lexical domain through the existing pipeline.
    Search {
        #[command(flatten)]
        api: RegressionApiOptions,
        #[command(flatten)]
        input: FrozenInputArgs,
        #[arg(long)]
        expected_binding: PathBuf,
        #[arg(long)]
        expected_sha256: String,
        query: String,
        #[arg(long, value_enum, default_value = "lexical")]
        mode: super::query::SearchMode,
        #[arg(long, value_enum)]
        vector_search_mode: Option<super::query::VectorSearchMode>,
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..))]
        rrf_limit: u32,
        #[arg(long)]
        rerank: bool,
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..))]
        rerank_limit: u32,
        #[arg(long, requires = "rerank")]
        rerank_provider: Option<super::rerank::types::ProviderChoice>,
        #[arg(long, requires_all = ["rerank", "window_root"])]
        cursor: Option<String>,
        /// Previous private run containing the frozen window; read only.
        #[arg(long, requires = "cursor")]
        window_root: Option<PathBuf>,
    },
    /// Export an observed candidate; this does not register expected identity.
    Inspect {
        #[command(flatten)]
        input: FrozenInputArgs,
    },
    /// Verify independent expected identity and readonly search admission.
    Verify {
        #[command(flatten)]
        input: FrozenInputArgs,
        #[arg(long, value_name = "FILE")]
        expected_binding: PathBuf,
        #[arg(long, value_name = "SHA256")]
        expected_sha256: String,
    },
}

pub(crate) fn run(command: &RegressionInputCommand) -> Result<Option<serde_json::Value>> {
    run_with_api_config(command, None)
}

pub(crate) fn run_with_api_config(command: &RegressionInputCommand, api_config: Option<&std::path::Path>) -> Result<Option<serde_json::Value>> {
    let input = match command {
        RegressionInputCommand::Inspect { input }
        | RegressionInputCommand::Verify { input, .. }
        | RegressionInputCommand::Search { input, .. } => input,
    };
    let context = Arc::new(RegressionIoContext::open(&input.database, &input.run_root)?);
    context.forbid_output_under(&input.question_pack_root)?;
    match command {
        RegressionInputCommand::Search {
            api,
            expected_binding,
            expected_sha256,
            query,
            mode,
            vector_search_mode,
            rrf_limit,
            rerank,
            rerank_limit,
            rerank_provider,
            cursor,
            window_root,
            ..
        } => {
            if *rerank && rerank_limit > rrf_limit {
                bail!("REGRESSION_WINDOW_LIMIT_INVALID");
            }
            if *mode == super::query::SearchMode::Lexical && vector_search_mode.is_some() {
                bail!("REGRESSION_VECTOR_MODE_REQUIRES_SEMANTIC");
            }
            // The local rerank provider is retired for the production backtest:
            // the selection is refused outright, not only when a model-API
            // configuration happens to be present as well.
            if rerank_provider.is_some() { bail!("REGRESSION_MODEL_API_MIGRATION"); }
            let verified = open_verified_search(
                context.clone(),
                expected_binding,
                expected_sha256,
                &input.source_manifest,
            )?;
            let binding = verified.binding.clone();
            crate::run_cli_search(
                query,
                &[],
                &[],
                &[],
                &(*rrf_limit as usize),
                &0,
                &true,
                Some(crate::RobotFormat::Json),
                false,
                None,
                None,
                None,
                None,
                cursor.clone(),
                None,
                &None,
                None,
                crate::WrapConfig::new(None, true),
                crate::ProgressResolved::None,
                true,
                crate::TimeFilter::new(None, false, false, false, None, None),
                None,
                false,
                false,
                None,
                false,
                None,
                None,
                Some(*mode),
                *vector_search_mode,
                crate::SemanticSearchOptions {
                    api: crate::ApiSearchOptions {
                        config_path: api_config.map(std::path::Path::to_path_buf),
                        embedding_profile: api.embedding_profile.clone(), rerank_profile: api.rerank_profile.clone(),
                        no_model_fallback: api.no_model_fallback, ..Default::default()
                    },
                    model: (!api_selected && *mode != super::query::SearchMode::Lexical).then(|| "bge-m3".into()),
                    rerank: *rerank,
                    reranker: None,
                    use_daemon: false,
                    rerank_limit: rerank.then_some(*rerank_limit as usize),
                    rerank_provider: rerank.then_some(
                        rerank_provider.unwrap_or(super::rerank::types::ProviderChoice::Qwen3Local),
                    ),
                },
                crate::RerankRequestContext::default(),
                Some(crate::RegressionSearchExecution {
                    context,
                    verified: Some(verified),
                    binding,
                    trace: Default::default(),
                    endpoint: None,
                    window_root: window_root.clone(),
                    source_manifest: input.source_manifest.clone(),
                }),
            )
            .map_err(|error| anyhow::anyhow!(error.message))?;
            Ok(None)
        }
        RegressionInputCommand::Inspect { .. } => {
            context.admit_index_run()?;
            let binding = inspect_input(&context, &input.source_manifest)?;
            Ok(Some(
                serde_json::json!({"schema":"cass.regression-input-result.v1","stage":"observed-candidate","identity":binding,"quality":"NOT_EVALUATED"}),
            ))
        }
        RegressionInputCommand::Verify {
            expected_binding,
            expected_sha256,
            ..
        } => {
            let verified = open_verified_search(
                context,
                expected_binding,
                expected_sha256,
                &input.source_manifest,
            )?;
            Ok(Some(
                serde_json::json!({"schema":"cass.regression-input-result.v1","stage":"identity-and-admission-verified","identity":verified.binding,"expected_file_sha256":verified.expected_file_sha256,"quality":"NOT_EVALUATED"}),
            ))
        }
    }
}

/// Public CLI errors contain codes, never a query or an underlying SQL value.
pub(crate) fn error_code(error: &anyhow::Error) -> &'static str {
    const CODES: &[&str] = &[
        "REGRESSION_WINDOW_LIMIT_INVALID",
        "REGRESSION_SEMANTIC_NOT_INTEGRATED",
        "REGRESSION_VECTOR_MODE_REQUIRES_SEMANTIC",
        "REGRESSION_EMBEDDER_GENERATION_MISMATCH",
        "REGRESSION_EMBEDDING_CONFIGURATION_MISMATCH",
        "REGRESSION_RETRIEVAL_DEGRADED",
        "REGRESSION_SEARCH_FAILED",
        "REGRESSION_RERANK_FAILED",
        "REGRESSION_MODEL_API_MIGRATION",
        "REGRESSION_WINDOW_UNAVAILABLE",
        "TRACE_FAILED_WINDOW",
        "REGRESSION_SEARCH_EVIDENCE_FAILED",
        "TRACE_WINDOW_MISSING",
        "TRACE_INVALID_PAGE_RANGE",
        "TRACE_MISSING_PAGES",
        "TRACE_PAGE_SEQUENCE_MISMATCH",
        "TRACE_WINDOW_BINDING_MISMATCH",
        "TRACE_WINDOW_REQUEST_MISMATCH",
        "TRACE_WINDOW_SLOT_MAPPING_MISMATCH",
        "TRACE_WINDOW_SNIPPET_MISMATCH",
        "TRACE_SCORING_REQUEST_COUNT_MISMATCH",
        "TRACE_MISSING_SUBMITTED_TEXT",
        "TRACE_SUBMITTED_TEXT_MISMATCH",
        "TRACE_SCORING_RESPONSE_UNPROVEN",
        "TRACE_MODEL_EXECUTION_UNPROVEN",
        "TRACE_INCOMPLETE_SLOT_MAPPING",
        "TRACE_INVALID_SLOT_MAPPING",
        "TRACE_MISSING_MESSAGE_ID",
        "TRACE_MISSING_STABLE_CANDIDATE",
        "TRACE_MISSING_STABLE_CHUNK",
        "TRACE_DUPLICATE_CANDIDATE_IDENTITY",
        "EMPTY_MESSAGE_CORPUS",
        "regression_output_inside_repository",
        "regression_output_inside_protected_input",
        "regression_protected_root_not_directory",
        "regression_wal_not_finalized",
        "EXPECTED_BINDING_FILE_DIGEST_MISMATCH",
        "EXPECTED_INPUT_BINDING_MISMATCH",
        "EXPECTED_SOURCE_MANIFEST_MISMATCH",
        "EXTERNAL_EXPECTED_BINDING_REQUIRED",
        "EXPECTED_BINDING_INVALID",
        "INPUT_BINDING_POLICY_MISMATCH",
        "GENERATION_BINDING_INVALID",
        "BINDING_DIGEST_INVALID",
        "BINDING_FILE_CHANGED",
        "BINDING_FILE_NOT_REGULAR",
        "BINDING_SOURCE_CHANGED",
        "EXTERNAL_SOURCE_MANIFEST_REQUIRED",
        "GENERATION_REQUIRES_RECOVERY",
        "VECTOR_DOMAIN_REQUIRES_RECOVERY",
        "LEXICAL_DOMAIN_REQUIRES_RECOVERY",
        "LEXICAL_DOMAIN_UNAVAILABLE",
        "INDEX_RUN_MAINTENANCE_ACTIVE",
        "INDEX_RUN_STATE_REQUIRES_RECOVERY",
        "INDEX_RUN_LOCK_CHANGED",
        "INDEX_RUN_LOCK_NOT_REGULAR",
        "MISSING_STABLE_CONVERSATION_KEY",
        "DUPLICATE_STABLE_CONVERSATION_KEY",
        "DUPLICATE_STABLE_MESSAGE_KEY",
        "DUPLICATE_STABLE_CHUNK_KEY",
        "IDENTITY_CARRIER_MISMATCH",
        "IDENTITY_CARRIER_DECODE_FAILED",
        "ORPHAN_MESSAGE",
        "ORPHAN_WORKSPACE",
        "ORPHAN_SOURCE",
        "ORPHAN_LEXICAL_DOCUMENT",
        "ORPHAN_ACTIVE_CHUNK",
        "LEXICAL_PROJECTION_MISMATCH",
        "LEXICAL_PROJECTION_MEMBERSHIP_MISMATCH",
        "CHUNK_MEMBERSHIP_MISMATCH",
        "CHUNK_ASSOCIATION_MISMATCH",
        "CHUNK_SPAN_MISMATCH",
        "CHUNK_HASH_MISMATCH",
        "NEGATIVE_CHUNK_ID",
        "NO_ACTIVE_GENERATION",
        "AMBIGUOUS_ACTIVE_GENERATION",
        "ACTIVE_GENERATION_CHANGED",
        "regression_database_digest_mismatch",
        "regression_input_changed",
        "regression_maintenance_lock_changed",
        "regression_maintenance_lock_busy",
        "regression_maintenance_lock_unavailable",
        "regression_run_root_not_private",
        "regression_run_root_not_empty",
        "regression_output_inside_input",
        "regression_input_name",
        "regression_path_symlink",
        "regression_path_escape",
        "regression_path_not_absolute",
    ];
    for cause in error.chain() {
        let message = cause.to_string();
        if let Some(code) = CODES.iter().find(|code| **code == message) {
            return code;
        }
    }
    "REGRESSION_INPUT_FAILED"
}

pub(crate) fn reject_global_paths(db: bool, trace: bool) -> Result<()> {
    if db || trace {
        bail!("REGRESSION_INPUT_REQUIRES_LOCAL_ARGUMENTS");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn regression_input_cli_requires_explicit_source_expected_and_output_arguments() {
        // Match the repository's existing CLI parser tests: the full command
        // tree needs 16 MiB instead of the Rust test thread's default stack.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let parsed = crate::Cli::try_parse_from([
                    "cass",
                    "regression-input",
                    "verify",
                    "--database",
                    "/input/agent_search.db",
                    "--run-root",
                    "/private/run",
                    "--source-manifest",
                    "/input/sources.json",
                    "--question-pack-root",
                    "/private/question-pack",
                    "--expected-binding",
                    "/approved/input.json",
                    "--expected-sha256",
                    &"00".repeat(32),
                ])
                .unwrap();
                assert!(matches!(
                    parsed.command,
                    Some(crate::Commands::RegressionInput { .. })
                ));
                assert!(
                    crate::Cli::try_parse_from([
                        "cass",
                        "regression-input",
                        "verify",
                        "--database",
                        "/input/agent_search.db",
                        "--run-root",
                        "/private/run",
                        "--source-manifest",
                        "/input/sources.json"
                    ])
                    .is_err()
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn regression_input_cli_sanitizes_unknown_errors() {
        assert_eq!(
            error_code(&anyhow::anyhow!("query=synthetic-private-body")),
            "REGRESSION_INPUT_FAILED"
        );
        assert_eq!(
            error_code(&anyhow::anyhow!("EXPECTED_INPUT_BINDING_MISMATCH")),
            "EXPECTED_INPUT_BINDING_MISMATCH"
        );
    }
}
