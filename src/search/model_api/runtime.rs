//! The runtime edge of the model-service boundary.
//!
//! [`config`](super::config) answers "is this document valid". This module
//! answers "which file, which profile and which credential source" for one
//! command run. It reads the file the operator named, adapts the process
//! environment into a [`CredentialResolver`], selects the one profile a command
//! asked for, and owns the two report shapes that `cass models list` and
//! `cass models check` print.
//!
//! Three rules hold everywhere here:
//!
//! * No default path, host, model or credential name is guessed. A missing
//!   configuration is an error, never a silent fallback.
//! * Nothing read from the file, the environment or a service response is
//!   echoed back. A [`RuntimeError`] carries a bounded short code and, at most,
//!   a compile-time field name.
//! * A profile id selects a profile. It never selects a model.
//!
//! The module is pure at its core: the file reader and the environment lookup
//! are parameters, so every rule below is testable without touching either.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use super::client::{ApiAttempt, ApiCallFailure, ApiClient, CredentialResolver};
use super::config::{ApiConfig, ProfileKind, ValidatedApiConfig, ValidatedProfile};
use super::error::{ApiCallErrorCode, ConfigError};
use super::identity::RepresentationDescriptor;
use super::protocol::{InputKind, ObservedIdentity, Usage};

/// The environment variable that names the configuration file.
///
/// It is consulted only when the command line named no file, and it never
/// overrides the command line.
pub const API_CONFIG_ENV: &str = "CASS_API_CONFIG";

/// The schema string of the `models list` success envelope.
pub const LIST_SCHEMA: &str = "cass.model-api-list.v1";

/// The schema string of the `models check` success envelope.
pub const CHECK_SCHEMA: &str = "cass.model-api-check.v1";

/// The mode string every profile check reports.
///
/// One explicit profile is checked, so no fallback is ever part of the result.
pub const CHECK_MODE: &str = "single_profile_check";

/// The fixed public synthetic input both embedding checks send.
///
/// The kernel prefixes it per input kind. No private corpus is ever sent.
pub const CHECK_TEXT: &str = "CASS model API check.";

/// The fixed public synthetic query the rerank check sends.
pub const CHECK_QUERY: &str = "CASS model API check.";

/// The two fixed public synthetic documents the rerank check scores.
pub const CHECK_DOCUMENTS: [&str; 2] = [
    "A document about checking a model API.",
    "An unrelated document about gardening.",
];

/// The closed list of retired model-selection variables.
///
/// A model command that finds any of these set — including set to the empty
/// string — refuses before it reads a configuration or sends a request. The
/// list is closed: it is the exact set specification §5.3 retires.
pub const RETIRED_MODEL_ENV_VARS: [&str; 7] = [
    "CASS_INFINITY_URL",
    "CASS_INFINITY_EMBED_MODEL",
    "CASS_INFINITY_RERANK_MODEL",
    "CASS_QWEN_RERANK_URL",
    "CASS_SEMANTIC_EMBEDDER",
    "CASS_SEMANTIC_DOWNLOAD_POLICY",
    "CASS_SEMANTIC_MAX_MODEL_SIZE_MB",
];

/// Which of the three runtime failures a [`RuntimeError`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeErrorKind {
    /// The configuration could not be selected, read or validated.
    Configuration,
    /// A retired model-selection variable is still set.
    Migration,
    /// One profile check ran and did not succeed.
    Check,
}

impl RuntimeErrorKind {
    /// The stable `kind` string this failure reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "ModelApiConfiguration",
            Self::Migration => "ModelApiMigration",
            Self::Check => "ModelApiCheck",
        }
    }

    /// The process exit code this kind reports.
    ///
    /// Configuration and migration are usage-side refusals; a check that ran
    /// and failed is a result of its own.
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Configuration | Self::Migration => 2,
            Self::Check => 1,
        }
    }
}

impl fmt::Display for RuntimeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused runtime operation.
///
/// The payload is a bounded code plus, at most, a compile-time field name — it
/// is deliberately too small to carry a path, a file body, a credential or any
/// part of a service response, so `Display` and `Debug` are safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeError {
    kind: RuntimeErrorKind,
    message: String,
    hint: Option<String>,
    retryable: bool,
}

impl RuntimeError {
    /// A configuration error with the given bounded message and hint.
    pub fn configuration(message: impl Into<String>, hint: Option<String>) -> Self {
        Self {
            kind: RuntimeErrorKind::Configuration,
            message: message.into(),
            hint,
            retryable: false,
        }
    }

    /// No configuration file was named on the command line or in the
    /// environment.
    pub fn missing_config() -> Self {
        Self::configuration(
            "no model API configuration selected; pass --api-config <PATH> or set CASS_API_CONFIG"
                .to_string(),
            Some(
                "The file is version 1 TOML with a `profiles` table and optional \
                 `default_embedding` / `default_rerank` ids."
                    .to_string(),
            ),
        )
    }

    /// The configuration file could not be read.
    ///
    /// The path and the underlying I/O error are deliberately not included.
    pub fn unreadable_config() -> Self {
        Self::configuration(
            "the model API configuration file could not be read".to_string(),
            Some(
                "Check --api-config / CASS_API_CONFIG point at a readable UTF-8 TOML file."
                    .to_string(),
            ),
        )
    }

    /// The configuration file was read but refused.
    ///
    /// The message is the validator's own bounded code and field name; it
    /// never quotes the rejected document.
    pub fn invalid_config(error: &ConfigError) -> Self {
        Self::configuration(
            error.to_string(),
            Some("Fix the named field; run `cass robot-docs env` for the configuration entry points.".to_string()),
        )
    }

    /// The requested profile id is not defined by the configuration.
    ///
    /// The id is caller-supplied text and is never echoed: it can carry a path,
    /// a newline or a credential-shaped fragment, so the refusal reports a
    /// bounded short code and a fixed hint instead.
    pub fn unknown_profile() -> Self {
        Self::configuration(
            "unknown model API profile id".to_string(),
            Some("Run `cass models list --json` to see the configured profile ids.".to_string()),
        )
    }

    /// A retired model-selection variable is set.
    ///
    /// The named variable comes from the closed [`RETIRED_MODEL_ENV_VARS`] list,
    /// never from arbitrary environment content.
    pub fn migration(variable: &str) -> Self {
        Self {
            kind: RuntimeErrorKind::Migration,
            message: format!(
                "model selection moved to the API profile configuration; {variable} is retired"
            ),
            hint: Some(
                "Remove it and select a profile with --api-config and the profile selectors."
                    .to_string(),
            ),
            retryable: false,
        }
    }

    /// One profile check did not succeed.
    pub fn check(code: &str) -> Self {
        Self {
            kind: RuntimeErrorKind::Check,
            message: format!("model API check failed: {code}"),
            hint: Some(
                "Re-run once the endpoint answers; the calls array names the failed stage."
                    .to_string(),
            ),
            retryable: true,
        }
    }

    /// Which of the three failures this is.
    pub const fn kind(&self) -> RuntimeErrorKind {
        self.kind
    }

    /// The stable `kind` string, ready for a `CliError`.
    pub const fn kind_str(&self) -> &'static str {
        self.kind.as_str()
    }

    /// The process exit code this failure reports.
    pub const fn code(&self) -> i32 {
        self.kind.exit_code()
    }

    /// The bounded message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The operator-facing hint, when there is one.
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    /// Whether a retry could plausibly succeed.
    pub const fn retryable(&self) -> bool {
        self.retryable
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.message)
    }
}

impl std::error::Error for RuntimeError {}

/// A reproducible configuration declaration without credential values.
pub(crate) fn configuration_snapshot(config: &ValidatedApiConfig, primary: &ValidatedProfile) -> Result<serde_json::Value, ConfigError> {
    let declaration = |profile: &ValidatedProfile| -> Result<serde_json::Value, ConfigError> {
        let identity = super::EndpointConfigIdentity::from_profile(profile)?;
        Ok(serde_json::from_slice(&identity.canonical_bytes()).expect("canonical call configuration is JSON"))
    };
    let fallback = primary.fallback_profile.as_deref().and_then(|id| config.profile(id));
    Ok(serde_json::json!({"primary_profile":primary.id,"primary":declaration(primary)?,
        "fallback_profile":primary.fallback_profile,"fallback":fallback.map(declaration).transpose()?}))
}

/// The one production credential source: the process environment.
///
/// The client asks it for a profile's `api_key_env` name and receives the
/// value, or `None`. Nothing here searches a directory, reads a dotfile or
/// guesses a variable name: the read is `std::env`, not a dotfile-loading
/// helper, so this edge never widens what the process was started with. A
/// value that is unset, empty or not valid UTF-8 has no usable bearer and
/// resolves to `None`.
pub struct EnvCredentialResolver;

impl CredentialResolver for EnvCredentialResolver {
    fn resolve(&self, variable: &str) -> Option<String> {
        std::env::var(variable)
            .ok()
            .filter(|value| !value.is_empty())
    }
}

/// The first retired model-selection variable that is set, if any.
///
/// "Set" is presence, not a readable value: it includes the empty string and a
/// value that is not valid UTF-8, so the lookup returns the raw [`OsString`]
/// and the caller must not collapse `None` with "present but unreadable".
pub fn retired_model_env_in_use(lookup: impl Fn(&str) -> Option<OsString>) -> Option<&'static str> {
    RETIRED_MODEL_ENV_VARS
        .iter()
        .copied()
        .find(|name| lookup(name).is_some())
}

/// Refuse when any retired model-selection variable is set.
pub fn ensure_no_retired_model_env(
    lookup: impl Fn(&str) -> Option<OsString>,
) -> Result<(), RuntimeError> {
    match retired_model_env_in_use(lookup) {
        Some(variable) => Err(RuntimeError::migration(variable)),
        None => Ok(()),
    }
}

/// Where the selected configuration path came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPathSource {
    /// A `--api-config` command-line value.
    CliFlag,
    /// The `CASS_API_CONFIG` environment variable.
    Environment,
}

impl ConfigPathSource {
    /// The stable short name used in evidence.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CliFlag => "cli",
            Self::Environment => "environment",
        }
    }
}

/// A configuration path together with the source that named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPath {
    path: PathBuf,
    source: ConfigPathSource,
}

impl ConfigPath {
    /// The path exactly as it was given.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Where the path came from.
    pub const fn source(&self) -> ConfigPathSource {
        self.source
    }
}

/// Select the configuration path for this command.
///
/// The command line wins over the environment. No default directory is
/// searched: when neither names a file the result is `None`, and the caller
/// reports a missing configuration rather than reading an unstated path.
///
/// The path is the caller's own bytes. Only a genuinely empty environment value
/// counts as unset; nothing is trimmed or normalized, because trimming would
/// silently redirect a path such as `models.toml ` to a different file. The
/// value stays an [`OsString`] so a path that is not valid UTF-8 is still read
/// verbatim instead of being dropped and replaced by some other configuration.
pub fn resolve_config_path(
    cli_path: Option<&Path>,
    lookup: impl Fn(&str) -> Option<OsString>,
) -> Option<ConfigPath> {
    if let Some(path) = cli_path {
        return Some(ConfigPath {
            path: path.to_path_buf(),
            source: ConfigPathSource::CliFlag,
        });
    }
    let from_env = lookup(API_CONFIG_ENV)?;
    if from_env.is_empty() {
        return None;
    }
    Some(ConfigPath {
        path: PathBuf::from(from_env),
        source: ConfigPathSource::Environment,
    })
}

/// Read and validate the configuration this command selected.
pub fn load_config(
    cli_path: Option<&Path>,
    lookup: impl Fn(&str) -> Option<OsString>,
) -> Result<ValidatedApiConfig, RuntimeError> {
    load_config_with(cli_path, lookup, read_config_text)
}

/// Read a configuration file as text.
///
/// A named function rather than a closure, so the reader parameter stays
/// higher-ranked over its path lifetime.
fn read_config_text(path: &Path) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

/// [`load_config`] with an injected reader, so every refusal is testable
/// without a real file.
pub fn load_config_with(
    cli_path: Option<&Path>,
    lookup: impl Fn(&str) -> Option<OsString>,
    read: impl Fn(&Path) -> std::io::Result<String>,
) -> Result<ValidatedApiConfig, RuntimeError> {
    let Some(selected) = resolve_config_path(cli_path, lookup) else {
        return Err(RuntimeError::missing_config());
    };
    let text = read(selected.path()).map_err(|_| RuntimeError::unreadable_config())?;
    let mut config = ApiConfig::parse_toml(&text).map_err(|error| RuntimeError::invalid_config(&error))?;
    let absolute = if selected.path().is_absolute() { selected.path().to_path_buf() }
        else { std::env::current_dir().map_err(|_| RuntimeError::unreadable_config())?.join(selected.path()) };
    config.set_source_directory(absolute.parent().ok_or_else(RuntimeError::unreadable_config)?.to_path_buf());
    Ok(config)
}

/// Select one profile by its configured id.
///
/// The id is the only selector. The profile's kind comes from the document, so
/// a name that looks like a model never decides which check runs. A miss
/// reports a bounded refusal and never echoes the requested text.
pub fn profile_by_id<'a>(
    config: &'a ValidatedApiConfig,
    profile_id: &str,
) -> Result<&'a ValidatedProfile, RuntimeError> {
    config
        .profile(profile_id)
        .ok_or_else(RuntimeError::unknown_profile)
}

/// One profile as `cass models list` reports it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProfileListing {
    /// The configured profile id.
    pub id: String,
    /// `embedding` or `rerank`.
    pub kind: &'static str,
    /// The wire protocol the profile speaks.
    pub protocol: &'static str,
    /// The model identity the request carries.
    pub model: String,
    /// The revision the operator declares.
    pub model_revision: String,
    /// Whether this is the configured default for its kind.
    #[serde(rename = "default")]
    pub is_default: bool,
    /// The endpoint, exactly as configured.
    pub endpoint: String,
    /// `loopback` or `remote`.
    pub scope: &'static str,
    /// The credential variable *name*, when the profile names one. The value is
    /// never read, so it can never appear here.
    pub api_key_env: Option<String>,
}

/// Every configured profile, ascending by id.
///
/// This is a pure read of the validated document: it opens no database, loads
/// no weight and makes no request.
pub fn list_profiles(config: &ValidatedApiConfig) -> Vec<ProfileListing> {
    config
        .profiles()
        .map(|profile| ProfileListing {
            id: profile.id.clone(),
            kind: profile.kind.as_str(),
            protocol: profile.protocol.as_str(),
            model: profile.model.clone(),
            model_revision: profile.model_revision.clone(),
            is_default: config.default_profile_id(profile.kind) == Some(profile.id.as_str()),
            endpoint: profile.endpoint.as_str().to_string(),
            scope: profile.scope.as_str(),
            api_key_env: profile.api_key_env.clone(),
        })
        .collect()
}

/// One recorded stage of a profile check.
///
/// The observation fields are this stage's own response, not the command's
/// latest one: a stage that reported usage keeps it even when a later stage
/// reports none or fails. A field the service did not send stays `None`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CheckCall {
    /// `query`, `document` or `rerank`.
    pub stage: &'static str,
    /// Whether bytes were actually sent towards the service.
    pub network_attempted: bool,
    /// The HTTP status observed, when one was.
    pub http_status: Option<u16>,
    /// The measured duration, in milliseconds.
    pub duration_ms: u64,
    /// The bounded failure code, when this stage failed.
    pub error_code: Option<&'static str>,
    /// The model this stage's own response named, when it named one.
    pub response_model: Option<String>,
    /// The revision this stage's own response named, when it named one.
    pub response_revision: Option<String>,
    /// The serving provider this stage's own response named, when it named one.
    pub serving_provider: Option<String>,
    /// The usage this stage's own response reported, when it reported any.
    pub usage: Option<CheckUsage>,
}

/// The usage a service reported, mirroring [`Usage`] for serialization.
///
/// Every field is `null` unless the service returned a finite, non-negative
/// number. No value is derived or estimated.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckUsage {
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

impl CheckUsage {
    /// Mirror the observed usage, or `None` when the service reported none.
    pub fn from_observed(usage: Option<&Usage>) -> Option<Self> {
        usage.map(|usage| Self {
            prompt_tokens: usage.prompt_tokens,
            input_tokens: usage.input_tokens,
            total_tokens: usage.total_tokens,
            completion_tokens: usage.completion_tokens,
            output_tokens: usage.output_tokens,
            cost: usage.cost,
        })
    }
}

/// The report one profile check produces.
///
/// The requested identity comes from the configuration; the observed identity
/// comes from the service. A field the service did not send stays `null`, and
/// the declared revision is never written into a service-reported slot.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CheckReport {
    /// The profile that was checked.
    pub profile_id: String,
    /// `embedding` or `rerank`.
    pub kind: &'static str,
    /// The model identity the request carried.
    pub requested_model: String,
    /// The revision the configuration declares.
    pub declared_revision: String,
    /// The model the service named, when it named one.
    pub response_model: Option<String>,
    /// The revision the service named, when it named one.
    pub response_revision: Option<String>,
    /// `service_reported` when the service named a revision, else
    /// `operator_declared`.
    pub revision_source: &'static str,
    /// Always [`CHECK_MODE`].
    pub mode: &'static str,
    /// Always `false`: one explicit profile is checked.
    pub fallback_used: bool,
    /// Every stage attempt, in order.
    pub calls: Vec<CheckCall>,
    /// The measured embedding dimension, for an embedding profile.
    pub effective_dimension: Option<u64>,
    /// The representation descriptor digest, for an embedding profile.
    pub descriptor_sha256: Option<String>,
    /// The number of documents scored, for a rerank profile.
    pub scored_count: Option<u64>,
    /// The usage the last service response reported, when it reported one.
    ///
    /// This is a convenience echo of the final stage only. No cost is added
    /// across stages, and every stage's own reported usage stays readable on
    /// its entry in [`Self::calls`].
    pub usage: Option<CheckUsage>,
}

/// The bounded evidence of a check that failed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CheckFailure {
    /// The bounded failure code.
    pub code: &'static str,
    /// The HTTP status observed, when one was.
    pub http_status: Option<u16>,
}

/// One profile check: its report and, when it did not succeed, its failure.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckRun {
    /// The report. Every stage attempted so far is listed, even when an earlier
    /// stage failed.
    pub report: CheckReport,
    /// `None` when every stage succeeded.
    pub failure: Option<CheckFailure>,
}

/// Check exactly one profile against exactly its own endpoint.
///
/// An embedding profile gets two requests, one `query` and one `document`, each
/// carrying the same public synthetic text; their dimensions must agree. A
/// rerank profile gets one request over the two public synthetic documents.
/// The metadata endpoint is never fetched, no generation is registered and no
/// readiness cache is touched.
pub fn run_profile_check(client: &ApiClient, profile: &ValidatedProfile) -> CheckRun {
    match profile.kind {
        ProfileKind::Embedding => check_embedding(client, profile),
        ProfileKind::Rerank => check_rerank(client, profile),
    }
}

fn check_embedding(client: &ApiClient, profile: &ValidatedProfile) -> CheckRun {
    let mut calls: Vec<CheckCall> = Vec::new();
    let mut observed = ObservedIdentity::default();
    let mut dimensions: Vec<u64> = Vec::new();
    let mut failure: Option<CheckFailure> = None;

    for (kind, stage) in [
        (InputKind::Query, "query"),
        (InputKind::Document, "document"),
    ] {
        let inputs = [CHECK_TEXT.to_string()];
        match client.embed_once(&profile.id, &inputs, kind) {
            Ok(outcome) => {
                calls.extend(outcome.attempts.iter().map(|a| call_record(stage, a)));
                dimensions.push(outcome.dimension as u64);
                observed = outcome.identity;
            }
            Err(refused) => {
                calls.extend(refused.attempts().iter().map(|a| call_record(stage, a)));
                failure = Some(check_failure(&refused));
                break;
            }
        }
    }

    let mut effective_dimension = None;
    let mut descriptor_sha256 = None;
    if failure.is_none() {
        match dimensions.as_slice() {
            [first, second] if first == second => {
                match RepresentationDescriptor::from_profile(profile, *first) {
                    Ok(descriptor) => {
                        effective_dimension = Some(*first);
                        descriptor_sha256 = Some(descriptor.sha256());
                    }
                    Err(error) => {
                        failure = Some(CheckFailure {
                            code: error.code().as_str(),
                            http_status: None,
                        });
                    }
                }
            }
            _ => {
                failure = Some(CheckFailure {
                    code: ApiCallErrorCode::DimensionMismatch.as_str(),
                    http_status: None,
                });
            }
        }
    }

    let report = build_report(
        profile,
        "embedding",
        observed,
        calls,
        effective_dimension,
        descriptor_sha256,
        None,
    );
    CheckRun { report, failure }
}

fn check_rerank(client: &ApiClient, profile: &ValidatedProfile) -> CheckRun {
    let documents: Vec<String> = CHECK_DOCUMENTS
        .iter()
        .map(|text| (*text).to_string())
        .collect();
    let mut calls: Vec<CheckCall> = Vec::new();
    let mut observed = ObservedIdentity::default();
    let mut scored_count = None;
    let mut failure = None;

    match client.rerank_once(&profile.id, CHECK_QUERY, &documents) {
        Ok(outcome) => {
            calls.extend(outcome.attempts.iter().map(|a| call_record("rerank", a)));
            scored_count = Some(outcome.scores.len() as u64);
            observed = outcome.identity;
        }
        Err(refused) => {
            calls.extend(refused.attempts().iter().map(|a| call_record("rerank", a)));
            failure = Some(check_failure(&refused));
        }
    }

    let report = build_report(profile, "rerank", observed, calls, None, None, scored_count);
    CheckRun { report, failure }
}

fn call_record(stage: &'static str, attempt: &ApiAttempt) -> CheckCall {
    CheckCall {
        stage,
        network_attempted: attempt.network_attempted,
        http_status: attempt.http_status,
        duration_ms: attempt.duration_ms,
        error_code: attempt.error_code,
        response_model: attempt.identity.response_model.clone(),
        response_revision: attempt.identity.response_revision.clone(),
        serving_provider: attempt.identity.provider.clone(),
        usage: CheckUsage::from_observed(attempt.identity.usage.as_ref()),
    }
}

fn check_failure(refused: &ApiCallFailure) -> CheckFailure {
    CheckFailure {
        code: refused.error().code().as_str(),
        http_status: refused.error().http_status(),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_report(
    profile: &ValidatedProfile,
    kind: &'static str,
    observed: ObservedIdentity,
    calls: Vec<CheckCall>,
    effective_dimension: Option<u64>,
    descriptor_sha256: Option<String>,
    scored_count: Option<u64>,
) -> CheckReport {
    let ObservedIdentity {
        response_model,
        response_revision,
        provider: _,
        usage,
    } = observed;
    let revision_source = if response_revision.is_some() {
        "service_reported"
    } else {
        "operator_declared"
    };
    CheckReport {
        profile_id: profile.id.clone(),
        kind,
        requested_model: profile.model.clone(),
        declared_revision: profile.model_revision.clone(),
        response_model,
        response_revision,
        revision_source,
        mode: CHECK_MODE,
        fallback_used: false,
        calls,
        effective_dimension,
        descriptor_sha256,
        scored_count,
        usage: CheckUsage::from_observed(usage.as_ref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
version = 1
default_embedding = "local-embed"
default_rerank = "local-rank"

[profiles.local-embed]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "http://127.0.0.1:8080/v1/embeddings"
scope = "loopback"
model = "example/embed"
model_revision = "rev-1"
normalization = "l2"
api_key_env = "SYNTHETIC_EMBED_TOKEN"

[profiles.local-rank]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "http://127.0.0.1:8080/v1/rerank"
scope = "loopback"
model = "example/rank"
model_revision = "rev-2"
"#;

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| OsString::from(*value))
        }
    }

    #[test]
    fn cli_path_wins_over_the_environment() {
        let selected = resolve_config_path(
            Some(Path::new("/cli/models.toml")),
            env_of(&[(API_CONFIG_ENV, "/env/models.toml")]),
        )
        .expect("a cli path is always selected");
        assert_eq!(selected.path(), Path::new("/cli/models.toml"));
        assert_eq!(selected.source(), ConfigPathSource::CliFlag);
    }

    #[test]
    fn environment_path_is_used_when_the_cli_named_none() {
        let selected = resolve_config_path(None, env_of(&[(API_CONFIG_ENV, "/env/models.toml")]))
            .expect("the environment named a path");
        assert_eq!(selected.path(), Path::new("/env/models.toml"));
        assert_eq!(selected.source(), ConfigPathSource::Environment);
    }

    #[test]
    fn only_an_empty_environment_value_is_unset() {
        assert!(resolve_config_path(None, env_of(&[])).is_none());
        assert!(resolve_config_path(None, env_of(&[(API_CONFIG_ENV, "")])).is_none());
    }

    #[test]
    fn a_spaced_path_is_used_byte_for_byte() {
        // Trimming here would silently read `models.toml` instead of
        // `models.toml ` — a different file, and a different configuration.
        let selected = resolve_config_path(None, env_of(&[(API_CONFIG_ENV, "/cfg/models.toml ")]))
            .expect("a non-empty value names a path");
        assert_eq!(selected.path(), Path::new("/cfg/models.toml "));
        assert_eq!(selected.source(), ConfigPathSource::Environment);
    }

    #[test]
    fn a_missing_selection_is_a_configuration_error() {
        let error = load_config_with(None, env_of(&[]), |_| Ok(String::new()))
            .expect_err("no configuration selected");
        assert_eq!(error.kind(), RuntimeErrorKind::Configuration);
        assert_eq!(error.code(), 2);
        assert_eq!(error.kind_str(), "ModelApiConfiguration");
        assert!(!error.retryable());
    }

    #[test]
    fn an_unreadable_file_reports_no_path() {
        let error = load_config_with(
            Some(Path::new("/secret/place/models.toml")),
            env_of(&[]),
            |_| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "nope")),
        )
        .expect_err("the reader failed");
        assert_eq!(error.kind(), RuntimeErrorKind::Configuration);
        assert!(
            !error.message().contains("/secret/place"),
            "the path must not be echoed: {}",
            error.message()
        );
        assert!(!error.message().contains("nope"));
    }

    #[test]
    fn an_invalid_document_reports_only_the_bounded_code() {
        let error = load_config_with(Some(Path::new("/tmp/models.toml")), env_of(&[]), |_| {
            Ok("version = 2\n".to_string())
        })
        .expect_err("unsupported version");
        assert_eq!(error.kind(), RuntimeErrorKind::Configuration);
        assert!(
            error.message().contains("UnsupportedVersion"),
            "expected the validator code, got {}",
            error.message()
        );
    }

    #[test]
    fn compatibility_paths_follow_the_selected_toml_directory() {
        let text=r#"version=1
[profiles.embed]
kind="embedding"
protocol="openai-embeddings-v1"
endpoint="http://127.0.0.1:1/embedding"
scope="loopback"
model="example/embedding"
model_revision="r1"
normalization="l2"
fallback_compatibility_file="proofs/current.json"
"#;
        let config=load_config_with(Some(Path::new("/tmp/config-area/models.toml")),env_of(&[]), |_|Ok(text.into())).unwrap();
        let profile=config.profile("embed").unwrap();
        assert_eq!(config.compatibility_path(profile).unwrap(),Some(PathBuf::from("/tmp/config-area/proofs/current.json")));
        let memory_only=ApiConfig::parse_toml(text).unwrap();
        assert!(memory_only.compatibility_path(memory_only.profile("embed").unwrap()).is_err(),"no implicit cwd for a parser-only configuration");
        assert_eq!(super::super::EndpointConfigIdentity::from_profile(profile).unwrap().sha256(),
            super::super::EndpointConfigIdentity::from_profile(memory_only.profile("embed").unwrap()).unwrap().sha256());
    }

    #[test]
    fn a_valid_document_loads_and_selects_by_id() {
        let config = load_config_with(Some(Path::new("/tmp/models.toml")), env_of(&[]), |_| {
            Ok(SAMPLE.to_string())
        })
        .expect("valid document");
        let profile = profile_by_id(&config, "local-embed").expect("known id");
        assert_eq!(profile.kind, ProfileKind::Embedding);
        let error = profile_by_id(&config, "missing").expect_err("unknown id");
        assert_eq!(error.code(), 2);
        assert_eq!(error.kind_str(), "ModelApiConfiguration");
    }

    #[test]
    fn an_unknown_profile_id_is_never_echoed() {
        // The requested id is unvalidated caller text: it can carry a path, a
        // newline or a secret-shaped fragment, so the refusal must be bounded.
        let hostile = "SYNTHETIC_PRIVATE_PROFILE_ARGUMENT_123\n/tmp/secret";
        let error = RuntimeError::unknown_profile();
        assert!(!error.message().contains(hostile));
        assert!(!error.message().contains("SYNTHETIC_PRIVATE"));
        assert!(!error.message().contains("/tmp/secret"));
        assert!(!format!("{error:?}").contains("SYNTHETIC_PRIVATE"));
        assert!(!error.message().contains('\n'));
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("models list"))
        );
    }

    #[test]
    fn retired_variables_are_detected_including_empty_values() {
        for variable in RETIRED_MODEL_ENV_VARS {
            let error = ensure_no_retired_model_env(env_of(&[(variable, "")]))
                .expect_err("an empty value still counts as set");
            assert_eq!(error.kind(), RuntimeErrorKind::Migration);
            assert_eq!(error.code(), 2);
            assert_eq!(error.kind_str(), "ModelApiMigration");
            assert!(error.message().contains(variable));
        }
        assert!(ensure_no_retired_model_env(env_of(&[])).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_retired_value_still_counts_as_set() {
        use std::os::unix::ffi::OsStringExt;

        let raw = OsString::from_vec(vec![0x2f, 0xff, 0xfe]);
        let detected =
            retired_model_env_in_use(|key| (key == "CASS_INFINITY_URL").then(|| raw.clone()));
        assert_eq!(detected, Some("CASS_INFINITY_URL"));
    }

    #[test]
    fn listing_is_sorted_and_marks_defaults() {
        let config = ApiConfig::parse_toml(SAMPLE).expect("valid document");
        let listings = list_profiles(&config);
        let ids: Vec<&str> = listings.iter().map(|row| row.id.as_str()).collect();
        assert_eq!(ids, vec!["local-embed", "local-rank"]);
        assert!(listings[0].is_default);
        assert!(listings[1].is_default);
        assert_eq!(listings[0].kind, "embedding");
        assert_eq!(listings[1].kind, "rerank");
        assert_eq!(listings[0].scope, "loopback");
        assert_eq!(
            listings[0].api_key_env.as_deref(),
            Some("SYNTHETIC_EMBED_TOKEN")
        );
        assert_eq!(listings[1].api_key_env, None);
    }

    #[test]
    fn the_check_synthetic_inputs_are_public_constants() {
        assert_eq!(CHECK_TEXT, CHECK_QUERY);
        assert_eq!(CHECK_DOCUMENTS.len(), 2);
        assert_eq!(CHECK_MODE, "single_profile_check");
        assert_eq!(LIST_SCHEMA, "cass.model-api-list.v1");
        assert_eq!(CHECK_SCHEMA, "cass.model-api-check.v1");
    }

    #[test]
    fn a_check_failure_keeps_the_calls_it_already_made() {
        // A refusal before any request carries no attempts, and the report
        // still lists an empty calls array rather than a fabricated one.
        let run = CheckRun {
            report: CheckReport {
                profile_id: "p".to_string(),
                kind: "embedding",
                requested_model: "m".to_string(),
                declared_revision: "r".to_string(),
                response_model: None,
                response_revision: None,
                revision_source: "operator_declared",
                mode: CHECK_MODE,
                fallback_used: false,
                calls: Vec::new(),
                effective_dimension: None,
                descriptor_sha256: None,
                scored_count: None,
                usage: None,
            },
            failure: Some(CheckFailure {
                code: "Transport",
                http_status: None,
            }),
        };
        let json = serde_json::to_value(&run.report).expect("serialize the report");
        assert_eq!(json["calls"], serde_json::json!([]));
        assert_eq!(json["fallback_used"], serde_json::json!(false));
        assert_eq!(json["usage"], serde_json::Value::Null);
        assert_eq!(json["scored_count"], serde_json::Value::Null);
        assert_eq!(run.failure.as_ref().map(|f| f.code), Some("Transport"));
    }

    #[test]
    fn check_usage_mirrors_only_reported_numbers() {
        assert_eq!(CheckUsage::from_observed(None), None);
        let usage = Usage {
            total_tokens: Some(12),
            cost: Some(0.5),
            ..Usage::default()
        };
        let mirrored = CheckUsage::from_observed(Some(&usage)).expect("some usage");
        assert_eq!(mirrored.total_tokens, Some(12));
        assert_eq!(mirrored.prompt_tokens, None);
        assert_eq!(mirrored.cost, Some(0.5));
    }
}
