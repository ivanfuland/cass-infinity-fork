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

#[derive(Debug, Clone, Subcommand)]
pub enum RegressionInputCommand {
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

pub(crate) fn run(command: &RegressionInputCommand) -> Result<serde_json::Value> {
    let input = match command {
        RegressionInputCommand::Inspect { input }
        | RegressionInputCommand::Verify { input, .. } => input,
    };
    let context = Arc::new(RegressionIoContext::open(&input.database, &input.run_root)?);
    context.forbid_output_under(&input.question_pack_root)?;
    match command {
        RegressionInputCommand::Inspect { .. } => {
            context.admit_index_run()?;
            let binding = inspect_input(&context, &input.source_manifest)?;
            Ok(
                serde_json::json!({"schema":"cass.regression-input-result.v1","stage":"observed-candidate","identity":binding,"quality":"NOT_EVALUATED"}),
            )
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
            Ok(
                serde_json::json!({"schema":"cass.regression-input-result.v1","stage":"identity-and-admission-verified","identity":verified.binding,"expected_file_sha256":verified.expected_file_sha256,"quality":"NOT_EVALUATED"}),
            )
        }
    }
}

/// Public CLI errors contain codes, never a query or an underlying SQL value.
pub(crate) fn error_code(error: &anyhow::Error) -> &'static str {
    const CODES: &[&str] = &[
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
