//! The pure model-service configuration kernel.
//!
//! This module turns the TOML text a user writes into a typed, already-verified
//! description of the embedding and rerank services CASS may call. It is the
//! configuration half of the API-only model-service contract; it owns no
//! transport, opens no socket, reads no environment variable and touches no
//! file or database. Later tickets consume [`ValidatedApiConfig`] to build
//! requests, to choose a profile and to record identity.
//!
//! # What is checked here
//!
//! * the document shape: a fixed `version`, a typed `profiles` map and the
//!   optional `default_embedding` / `default_rerank` references;
//! * every field of a profile, including which fields only exist for one
//!   [`ProfileKind`];
//! * the static URL rules: scheme, userinfo, fragment and the `loopback` /
//!   `remote` scope split, all without resolving a name;
//! * the `fallback_profile` graph: a loopback primary, a remote, same-kind
//!   target that declares no fallback of its own, and the extra restriction a
//!   cloud embedding fallback carries.
//!
//! # What is deliberately *not* checked here
//!
//! The numeric cross-endpoint compatibility evidence of spec §6.4 is never read
//! or judged. `fallback_compatibility_file` is stored as the explicit path the
//! user wrote and nothing more: a configured path, an existing path or a
//! `.json` suffix is **not** a compatibility verdict, and this module never
//! emits one. Whether a fallback may actually be used is a later ticket's job,
//! using the real fixture and probe evidence.
//!
//! # A note on URL query strings
//!
//! The spec forbids "credential query parameters" but does not enumerate them,
//! and no closed set of credential-bearing parameter names exists. Rather than
//! guess a heuristic allow-list — which would loosen the authentication
//! boundary — this validator refuses *any* query string on an endpoint, the
//! strictly safer side of the ambiguity. An endpoint that genuinely needs a
//! query string is therefore rejected today; that divergence is reported rather
//! than silently relaxed.

use std::collections::BTreeMap;

use toml::Table as TomlTable;
use toml::Value;
use url::{Host, Url};

use super::error::{ConfigError, ConfigErrorCode};

/// The only top-level schema version this build understands.
pub const SUPPORTED_VERSION: i64 = 1;

/// Default connect wait, in milliseconds (spec §4).
pub const DEFAULT_CONNECT_TIMEOUT_MS: i64 = 5_000;
/// Default total request wait, in milliseconds (spec §4).
pub const DEFAULT_TIMEOUT_MS: i64 = 60_000;
/// Default response size ceiling, in bytes (64 MiB, spec §4).
pub const DEFAULT_MAX_RESPONSE_BYTES: i64 = 64 * 1024 * 1024;
/// Default number of inputs in one embedding batch (spec §5.1).
pub const DEFAULT_MAX_BATCH: i64 = 64;

/// The root keys this schema defines.
const ROOT_KEYS: &[&str] = &["version", "profiles", "default_embedding", "default_rerank"];

/// The per-profile keys this schema defines.
const PROFILE_KEYS: &[&str] = &[
    "kind",
    "protocol",
    "endpoint",
    "scope",
    "model",
    "model_revision",
    "response_model_aliases",
    "send_model",
    "api_key_env",
    "models_endpoint",
    "connect_timeout_ms",
    "timeout_ms",
    "max_response_bytes",
    "max_batch",
    "expected_dimension",
    "request_dimensions",
    "normalization",
    "query_prefix",
    "document_prefix",
    "instruction",
    "fallback_profile",
    "fallback_compatibility_file",
    "provider_only",
];

/// Which side of the search pipeline a profile serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileKind {
    /// Produces document and query vectors.
    Embedding,
    /// Scores query/document pairs.
    Rerank,
}

impl ProfileKind {
    /// The `kind` value this variant is written as.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Embedding => "embedding",
            Self::Rerank => "rerank",
        }
    }

    /// Parse the `kind` value, with no aliases and no case folding.
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "embedding" => Some(Self::Embedding),
            "rerank" => Some(Self::Rerank),
            _ => None,
        }
    }
}

/// The wire protocol a profile speaks.
///
/// The protocol selects a message shape. It never selects a deployment
/// framework, and it never routes a profile to a hard-coded host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApiProtocol {
    /// `POST endpoint` with `input: [string]` and `encoding_format = "float"`.
    OpenAiEmbeddingsV1,
    /// [`Self::OpenAiEmbeddingsV1`] plus a pinned OpenRouter provider block.
    OpenRouterEmbeddingsV1,
    /// `POST endpoint` with `query`, `documents` and `top_n`.
    RerankJsonV1,
    /// The shared rerank shape plus a pinned OpenRouter provider block.
    OpenRouterRerankV1,
}

impl ApiProtocol {
    /// The `protocol` value this variant is written as.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiEmbeddingsV1 => "openai-embeddings-v1",
            Self::OpenRouterEmbeddingsV1 => "openrouter-embeddings-v1",
            Self::RerankJsonV1 => "rerank-json-v1",
            Self::OpenRouterRerankV1 => "openrouter-rerank-v1",
        }
    }

    /// The profile kind this protocol serves. No protocol serves both.
    pub const fn kind(self) -> ProfileKind {
        match self {
            Self::OpenAiEmbeddingsV1 | Self::OpenRouterEmbeddingsV1 => ProfileKind::Embedding,
            Self::RerankJsonV1 | Self::OpenRouterRerankV1 => ProfileKind::Rerank,
        }
    }

    /// Whether this protocol carries the pinned OpenRouter provider block.
    pub const fn is_openrouter(self) -> bool {
        matches!(
            self,
            Self::OpenRouterEmbeddingsV1 | Self::OpenRouterRerankV1
        )
    }

    /// Parse the `protocol` value, with no aliases and no case folding.
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "openai-embeddings-v1" => Some(Self::OpenAiEmbeddingsV1),
            "openrouter-embeddings-v1" => Some(Self::OpenRouterEmbeddingsV1),
            "rerank-json-v1" => Some(Self::RerankJsonV1),
            "openrouter-rerank-v1" => Some(Self::OpenRouterRerankV1),
            _ => None,
        }
    }
}

/// Where an endpoint is allowed to live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointScope {
    /// The target must be an actual loopback address before any body is sent.
    Loopback,
    /// The target must use HTTPS.
    Remote,
}

impl EndpointScope {
    /// The `scope` value this variant is written as.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Remote => "remote",
        }
    }

    /// Parse the `scope` value, with no aliases and no case folding.
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "loopback" => Some(Self::Loopback),
            "remote" => Some(Self::Remote),
            _ => None,
        }
    }
}

/// How embedding vectors are normalized before they are stored or compared.
///
/// Documents and queries of one profile must share one convention. Neither
/// value here checks a vector: refusing a non-finite or zero-norm vector belongs
/// to the response validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Normalization {
    /// The `l2` value: unit-normalized vectors.
    L2,
    /// The `none` value: the service's vectors are stored as returned.
    None,
}

impl Normalization {
    /// The `normalization` value this variant is written as.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::L2 => "l2",
            Self::None => "none",
        }
    }

    /// Parse the `normalization` value, with no aliases and no case folding.
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "l2" => Some(Self::L2),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// A statically validated endpoint URL.
///
/// The original bytes are preserved: [`Self::as_str`] returns exactly what the
/// user wrote, while [`Self::url`] exposes the parsed form used for the origin
/// and host decisions. Validation resolves no name and makes no request, so a
/// `loopback` endpoint is only *shaped* like a loopback address here; the
/// connection-time check is a separate, later guarantee.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedEndpoint {
    raw: String,
    parsed: Url,
}

impl ValidatedEndpoint {
    /// The endpoint exactly as configured, byte for byte.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The parsed URL.
    pub fn url(&self) -> &Url {
        &self.parsed
    }

    /// The scheme+host+port origin, used to require a same-origin metadata
    /// endpoint.
    fn origin(&self) -> url::Origin {
        self.parsed.origin()
    }
}

/// The embedding-only half of a profile.
///
/// These fields exist exactly when the profile's `kind` is
/// [`ProfileKind::Embedding`], so a rerank profile can never carry an embedding
/// batching or prefix setting.
#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddingProfile {
    /// Largest number of complete inputs sent in one request.
    pub max_batch: u64,
    /// The dimension the caller asserts, when it asserts one.
    pub expected_dimension: Option<u64>,
    /// An explicit `dimensions` request parameter, when configured.
    pub request_dimensions: Option<u64>,
    /// The normalization convention documents and queries share.
    pub normalization: Normalization,
    /// Bytes prepended to a query before it is sent. Empty by default.
    pub query_prefix: String,
    /// Bytes prepended to a document before it is sent. Empty by default.
    pub document_prefix: String,
    /// The path of the cross-endpoint compatibility evidence, when configured.
    ///
    /// Stored verbatim. This module never reads, parses or vouches for it.
    pub fallback_compatibility_file: Option<String>,
    /// The single pinned OpenRouter provider slug, when configured.
    pub provider_only: Option<String>,
}

/// The rerank-only half of a profile.
#[derive(Debug, Clone, PartialEq)]
pub struct RerankProfile {
    /// The instruction sent with each scoring request, when configured.
    ///
    /// `None` and `Some(String::new())` are different values here and stay
    /// different through every comparison; nothing trims or normalizes it.
    pub instruction: Option<String>,
    /// The single pinned OpenRouter provider slug, when configured.
    pub provider_only: Option<String>,
}

/// The kind-specific half of a profile.
#[derive(Debug, Clone, PartialEq)]
pub enum ProfileDetail {
    /// Settings only an embedding profile may carry.
    Embedding(EmbeddingProfile),
    /// Settings only a rerank profile may carry.
    Rerank(RerankProfile),
}

/// One fully validated profile.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedProfile {
    /// The profile id, exactly as written.
    pub id: String,
    /// Embedding or rerank.
    pub kind: ProfileKind,
    /// The message shape this profile speaks.
    pub protocol: ApiProtocol,
    /// The service endpoint, including its full path.
    pub endpoint: ValidatedEndpoint,
    /// Whether the endpoint must be loopback or remote-and-HTTPS.
    pub scope: EndpointScope,
    /// The model identity sent in the request.
    pub model: String,
    /// The deployment contract revision the operator declares.
    pub model_revision: String,
    /// Response model names accepted as equal to [`Self::model`].
    pub response_model_aliases: Vec<String>,
    /// Whether the request carries `model`.
    pub send_model: bool,
    /// The name of the environment variable holding the bearer token.
    pub api_key_env: Option<String>,
    /// The optional same-origin identity probe endpoint.
    pub models_endpoint: Option<ValidatedEndpoint>,
    /// Connect wait budget, in milliseconds.
    pub connect_timeout_ms: u64,
    /// Total request wait budget, in milliseconds.
    pub timeout_ms: u64,
    /// Response size ceiling, in bytes.
    pub max_response_bytes: u64,
    /// The `fallback_profile` this profile declares, when it declares one.
    pub fallback_profile: Option<String>,
    /// The kind-specific settings.
    pub detail: ProfileDetail,
}

impl ValidatedProfile {
    /// The embedding settings, when this is an embedding profile.
    pub fn embedding(&self) -> Option<&EmbeddingProfile> {
        match &self.detail {
            ProfileDetail::Embedding(detail) => Some(detail),
            ProfileDetail::Rerank(_) => None,
        }
    }

    /// The rerank settings, when this is a rerank profile.
    pub fn rerank(&self) -> Option<&RerankProfile> {
        match &self.detail {
            ProfileDetail::Embedding(_) => None,
            ProfileDetail::Rerank(detail) => Some(detail),
        }
    }
}

/// A parsed and fully validated model-service configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedApiConfig {
    profiles: BTreeMap<String, ValidatedProfile>,
    default_embedding: Option<String>,
    default_rerank: Option<String>,
}

impl ValidatedApiConfig {
    /// The schema version every validated document carries.
    pub const VERSION: i64 = SUPPORTED_VERSION;

    /// The schema version of this document.
    pub const fn version(&self) -> i64 {
        Self::VERSION
    }

    /// The profile with this id, when the document defines one.
    pub fn profile(&self, id: &str) -> Option<&ValidatedProfile> {
        self.profiles.get(id)
    }

    /// Every profile, in ascending id order.
    pub fn profiles(&self) -> impl Iterator<Item = &ValidatedProfile> {
        self.profiles.values()
    }

    /// The configured default profile id for `kind`, when one is set.
    pub fn default_profile_id(&self, kind: ProfileKind) -> Option<&str> {
        match kind {
            ProfileKind::Embedding => self.default_embedding.as_deref(),
            ProfileKind::Rerank => self.default_rerank.as_deref(),
        }
    }

    /// The configured default profile for `kind`, when one is set.
    pub fn default_profile(&self, kind: ProfileKind) -> Option<&ValidatedProfile> {
        self.default_profile_id(kind)
            .and_then(|id| self.profiles.get(id))
    }
}

/// The entry point for reading model-service configuration.
///
/// This is a namespace, not a stateful handle: the whole job is one pure call.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiConfig;

impl ApiConfig {
    /// Parse and validate one TOML document.
    ///
    /// The call is pure. It performs no I/O, reads no environment variable,
    /// resolves no host name and writes nothing, so a rejected document leaves
    /// no side effect behind and the same text always yields the same result.
    pub fn parse_toml(text: &str) -> Result<ValidatedApiConfig, ConfigError> {
        let root: TomlTable = text
            .parse()
            .map_err(|_| ConfigError::new(ConfigErrorCode::InvalidToml))?;

        reject_unknown(&root, ROOT_KEYS)?;

        let version = match root.get("version") {
            None => return Err(missing("version")),
            Some(Value::Integer(value)) => *value,
            Some(_) => return Err(invalid("version")),
        };
        if version != SUPPORTED_VERSION {
            return Err(ConfigError::at(
                ConfigErrorCode::UnsupportedVersion,
                "version",
            ));
        }

        let profile_tables = match root.get("profiles") {
            None => return Err(missing("profiles")),
            Some(Value::Table(table)) => table,
            Some(_) => return Err(invalid("profiles")),
        };

        let mut profiles = BTreeMap::new();
        for (id, value) in profile_tables {
            if !is_valid_profile_id(id) {
                return Err(ConfigError::at(
                    ConfigErrorCode::InvalidProfileId,
                    "profiles",
                ));
            }
            let Value::Table(table) = value else {
                return Err(invalid("profiles"));
            };
            profiles.insert(id.clone(), parse_profile(id, table)?);
        }

        validate_fallback_graph(&profiles)?;

        let default_embedding = optional_text(&root, "default_embedding")?.map(str::to_string);
        let default_rerank = optional_text(&root, "default_rerank")?.map(str::to_string);
        check_default(
            &profiles,
            default_embedding.as_deref(),
            ProfileKind::Embedding,
            "default_embedding",
        )?;
        check_default(
            &profiles,
            default_rerank.as_deref(),
            ProfileKind::Rerank,
            "default_rerank",
        )?;

        Ok(ValidatedApiConfig {
            profiles,
            default_embedding,
            default_rerank,
        })
    }
}

// ---------------------------------------------------------------------------
// Profile parsing
// ---------------------------------------------------------------------------

/// Validate one profile table into a [`ValidatedProfile`].
fn parse_profile(id: &str, table: &TomlTable) -> Result<ValidatedProfile, ConfigError> {
    reject_unknown(table, PROFILE_KEYS)?;

    let kind = match ProfileKind::parse(required_text(table, "kind")?) {
        Some(kind) => kind,
        None => return Err(invalid("kind")),
    };
    let protocol = match ApiProtocol::parse(required_text(table, "protocol")?) {
        Some(protocol) => protocol,
        None => return Err(invalid("protocol")),
    };
    if protocol.kind() != kind {
        return Err(ConfigError::at(ConfigErrorCode::KindMismatch, "protocol"));
    }

    let scope = match EndpointScope::parse(required_text(table, "scope")?) {
        Some(scope) => scope,
        None => return Err(invalid("scope")),
    };
    let endpoint = validate_endpoint(required_text(table, "endpoint")?, scope, "endpoint")?;
    let models_endpoint = match optional_text(table, "models_endpoint")? {
        None => None,
        Some(raw) => {
            let parsed = validate_endpoint(raw, scope, "models_endpoint")?;
            if parsed.origin() != endpoint.origin() {
                return Err(invalid("models_endpoint"));
            }
            Some(parsed)
        }
    };

    let model = required_text(table, "model")?.to_string();

    let revision = required_text(table, "model_revision")?;
    if revision.eq_ignore_ascii_case("main") || revision.eq_ignore_ascii_case("latest") {
        return Err(invalid("model_revision"));
    }
    let model_revision = revision.to_string();

    let response_model_aliases = match optional_text_array(table, "response_model_aliases")? {
        None => Vec::new(),
        Some(aliases) => {
            let mut seen: Vec<&str> = Vec::with_capacity(aliases.len());
            for &alias in &aliases {
                if alias.trim().is_empty()
                    || alias.contains('*')
                    || alias.contains('?')
                    || seen.contains(&alias)
                {
                    return Err(invalid("response_model_aliases"));
                }
                seen.push(alias);
            }
            aliases.into_iter().map(str::to_string).collect()
        }
    };

    let send_model = optional_bool(table, "send_model")?.unwrap_or(true);
    if protocol.is_openrouter() && !send_model {
        return Err(invalid("send_model"));
    }

    let api_key_env = match optional_text(table, "api_key_env")? {
        None => None,
        Some(name) => {
            if !is_valid_env_name(name) {
                return Err(invalid("api_key_env"));
            }
            Some(name.to_string())
        }
    };

    let connect_timeout_ms = budget(table, "connect_timeout_ms", DEFAULT_CONNECT_TIMEOUT_MS)?;
    let timeout_ms = budget(table, "timeout_ms", DEFAULT_TIMEOUT_MS)?;
    let max_response_bytes = match optional_int(table, "max_response_bytes")? {
        None => DEFAULT_MAX_RESPONSE_BYTES as u64,
        Some(value) => match response_size_limit(value) {
            Some(limit) => limit,
            None => return Err(invalid("max_response_bytes")),
        },
    };

    let fallback_profile = optional_text(table, "fallback_profile")?.map(str::to_string);
    if let Some(target) = fallback_profile.as_deref() {
        if !is_valid_profile_id(target) {
            return Err(invalid("fallback_profile"));
        }
    }

    let provider_only = match optional_text(table, "provider_only")? {
        None => None,
        Some(slug) => {
            if slug.trim().is_empty() || !protocol.is_openrouter() {
                return Err(invalid("provider_only"));
            }
            Some(slug.to_string())
        }
    };

    let detail = match kind {
        ProfileKind::Embedding => {
            // An embedding profile carries no rerank-only field.
            reject_present(table, "instruction")?;
            ProfileDetail::Embedding(EmbeddingProfile {
                max_batch: match optional_int(table, "max_batch")? {
                    None => DEFAULT_MAX_BATCH as u64,
                    Some(value) => positive(value, "max_batch")?,
                },
                expected_dimension: optional_dimension(table, "expected_dimension")?,
                request_dimensions: optional_dimension(table, "request_dimensions")?,
                normalization: match Normalization::parse(required_text(table, "normalization")?) {
                    Some(normalization) => normalization,
                    None => return Err(invalid("normalization")),
                },
                query_prefix: optional_text(table, "query_prefix")?
                    .unwrap_or("")
                    .to_string(),
                document_prefix: optional_text(table, "document_prefix")?
                    .unwrap_or("")
                    .to_string(),
                fallback_compatibility_file: optional_text(table, "fallback_compatibility_file")?
                    .map(str::to_string),
                provider_only,
            })
        }
        ProfileKind::Rerank => {
            // A rerank profile carries no embedding-only field.
            reject_present(table, "max_batch")?;
            reject_present(table, "expected_dimension")?;
            reject_present(table, "request_dimensions")?;
            reject_present(table, "normalization")?;
            reject_present(table, "query_prefix")?;
            reject_present(table, "document_prefix")?;
            reject_present(table, "fallback_compatibility_file")?;
            ProfileDetail::Rerank(RerankProfile {
                instruction: optional_text(table, "instruction")?.map(str::to_string),
                provider_only,
            })
        }
    };

    if let ProfileDetail::Embedding(embedding) = &detail {
        // When both dimensions are asserted they must agree.
        if let (Some(expected), Some(requested)) =
            (embedding.expected_dimension, embedding.request_dimensions)
        {
            if expected != requested {
                return Err(invalid("request_dimensions"));
            }
        }
        // The compatibility-evidence path only means something on the primary
        // profile of a fallback pair.
        if embedding.fallback_compatibility_file.is_some() && fallback_profile.is_none() {
            return Err(ConfigError::at(
                ConfigErrorCode::InvalidFallback,
                "fallback_compatibility_file",
            ));
        }
    }

    Ok(ValidatedProfile {
        id: id.to_string(),
        kind,
        protocol,
        endpoint,
        scope,
        model,
        model_revision,
        response_model_aliases,
        send_model,
        api_key_env,
        models_endpoint,
        connect_timeout_ms,
        timeout_ms,
        max_response_bytes,
        fallback_profile,
        detail,
    })
}

// ---------------------------------------------------------------------------
// Graph and reference validation
// ---------------------------------------------------------------------------

/// Check the whole `fallback_profile` graph at load time.
fn validate_fallback_graph(
    profiles: &BTreeMap<String, ValidatedProfile>,
) -> Result<(), ConfigError> {
    for profile in profiles.values() {
        let Some(target_id) = profile.fallback_profile.as_deref() else {
            continue;
        };
        let Some(target) = profiles.get(target_id) else {
            return Err(ConfigError::at(
                ConfigErrorCode::InvalidReference,
                "fallback_profile",
            ));
        };
        // Only a loopback primary may point anywhere, and never at itself.
        if target.id == profile.id || profile.scope != EndpointScope::Loopback {
            return Err(fallback_error());
        }
        // The target is a single remote hop that is not itself a primary.
        if target.kind != profile.kind
            || target.scope != EndpointScope::Remote
            || target.fallback_profile.is_some()
        {
            return Err(fallback_error());
        }
        match (&profile.detail, &target.detail) {
            (ProfileDetail::Embedding(_), ProfileDetail::Embedding(cloud)) => {
                // A cloud embedding fallback must speak the OpenRouter protocol
                // with a single pinned provider, or its output could come from a
                // space the primary never validated.
                if target.protocol != ApiProtocol::OpenRouterEmbeddingsV1
                    || !cloud
                        .provider_only
                        .as_deref()
                        .is_some_and(|slug| !slug.trim().is_empty())
                {
                    return Err(fallback_error());
                }
            }
            (ProfileDetail::Rerank(primary), ProfileDetail::Rerank(cloud)) => {
                // The strict `Option<String>` rule: both absent, or both present
                // and byte-identical. Absent never equals an empty string, and
                // nothing is trimmed or normalized.
                if primary.instruction.as_ref() != cloud.instruction.as_ref() {
                    return Err(ConfigError::at(
                        ConfigErrorCode::InstructionMismatch,
                        "instruction",
                    ));
                }
            }
            _ => return Err(fallback_error()),
        }
    }
    Ok(())
}

/// Check that a `default_*` reference names an existing profile of its kind.
fn check_default(
    profiles: &BTreeMap<String, ValidatedProfile>,
    id: Option<&str>,
    kind: ProfileKind,
    field: &'static str,
) -> Result<(), ConfigError> {
    let Some(id) = id else {
        return Ok(());
    };
    let Some(profile) = profiles.get(id) else {
        return Err(ConfigError::at(ConfigErrorCode::InvalidReference, field));
    };
    if profile.kind != kind {
        return Err(ConfigError::at(ConfigErrorCode::KindMismatch, field));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

/// Validate one endpoint against the static rules for its scope.
///
/// Nothing here resolves a name or opens a connection: `loopback` is checked
/// against the literal address or the single permitted DNS name, and `remote` is
/// checked for HTTPS. The connection-time loopback check belongs to the
/// transport and is not weakened by this one.
fn validate_endpoint(
    raw: &str,
    scope: EndpointScope,
    field: &'static str,
) -> Result<ValidatedEndpoint, ConfigError> {
    let invalid = || ConfigError::at(ConfigErrorCode::InvalidEndpoint, field);

    let parsed = Url::parse(raw).map_err(|_| invalid())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(invalid());
    }
    // Userinfo is refused in every shape. The URL parser normalizes several
    // spellings (`http:/@host`, `http:////@host`) into an empty username, so the
    // raw authority region is inspected as well.
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || raw_authority(raw).contains('@')
    {
        return Err(invalid());
    }
    // A fragment is never part of a service endpoint, and a query string is
    // refused rather than heuristically filtered (see the module docs).
    if parsed.fragment().is_some() || parsed.query().is_some() {
        return Err(invalid());
    }
    let Some(host) = parsed.host() else {
        return Err(invalid());
    };
    if let Host::Domain(name) = &host {
        if name.is_empty() {
            return Err(invalid());
        }
    }
    match scope {
        EndpointScope::Loopback => {
            if !host_is_loopback(&host) {
                return Err(invalid());
            }
        }
        EndpointScope::Remote => {
            if parsed.scheme() != "https" {
                return Err(invalid());
            }
        }
    }

    Ok(ValidatedEndpoint {
        raw: raw.to_string(),
        parsed,
    })
}

/// The raw authority region of a URL string: what sits between the scheme's `:`
/// and the first `/`, `?` or `#` after it.
///
/// Leading slashes are skipped so the malformed spellings the URL parser would
/// otherwise normalize away (`http:////@host`, `http:/@host`) still expose their
/// userinfo.
fn raw_authority(raw: &str) -> &str {
    let Some(colon) = raw.find(':') else {
        return "";
    };
    let rest = raw[colon + 1..].trim_start_matches('/');
    match rest.find(['/', '?', '#']) {
        Some(end) => &rest[..end],
        None => rest,
    }
}

/// Whether a host is a loopback address literal or the single permitted DNS
/// name.
///
/// `Url::host` is matched instead of `Url::host_str` so an IPv6 literal such as
/// `::1` is recognized by address; the string form keeps its surrounding
/// brackets and would otherwise look like a domain.
fn host_is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
        Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
    }
}

// ---------------------------------------------------------------------------
// Value access
// ---------------------------------------------------------------------------

/// Refuse any key outside the schema's closed set.
fn reject_unknown(table: &TomlTable, known: &[&str]) -> Result<(), ConfigError> {
    for key in table.keys() {
        if !known.contains(&key.as_str()) {
            return Err(ConfigError::new(ConfigErrorCode::UnknownField));
        }
    }
    Ok(())
}

/// Refuse a field that this `kind` does not define.
fn reject_present(table: &TomlTable, field: &'static str) -> Result<(), ConfigError> {
    if table.contains_key(field) {
        return Err(invalid(field));
    }
    Ok(())
}

/// A required string that must also carry non-whitespace content.
///
/// The emptiness test uses a trimmed view, but the value returned is the
/// original text: nothing is trimmed, folded or normalized before it is stored.
fn required_text<'a>(table: &'a TomlTable, field: &'static str) -> Result<&'a str, ConfigError> {
    match table.get(field) {
        None => Err(missing(field)),
        Some(Value::String(text)) => {
            if text.trim().is_empty() {
                Err(invalid(field))
            } else {
                Ok(text.as_str())
            }
        }
        Some(_) => Err(invalid(field)),
    }
}

/// An optional string, refused when present with a non-string type.
fn optional_text<'a>(
    table: &'a TomlTable,
    field: &'static str,
) -> Result<Option<&'a str>, ConfigError> {
    match table.get(field) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.as_str())),
        Some(_) => Err(invalid(field)),
    }
}

/// An optional boolean, refused when present with a non-boolean type.
fn optional_bool(table: &TomlTable, field: &'static str) -> Result<Option<bool>, ConfigError> {
    match table.get(field) {
        None => Ok(None),
        Some(Value::Boolean(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid(field)),
    }
}

/// An optional integer, refused when present with a non-integer type.
fn optional_int(table: &TomlTable, field: &'static str) -> Result<Option<i64>, ConfigError> {
    match table.get(field) {
        None => Ok(None),
        Some(Value::Integer(value)) => Ok(Some(*value)),
        Some(_) => Err(invalid(field)),
    }
}

/// An optional array of strings, refused when any element is not a string.
fn optional_text_array<'a>(
    table: &'a TomlTable,
    field: &'static str,
) -> Result<Option<Vec<&'a str>>, ConfigError> {
    match table.get(field) {
        None => Ok(None),
        Some(Value::Array(items)) => {
            let mut texts = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(text) => texts.push(text.as_str()),
                    _ => return Err(invalid(field)),
                }
            }
            Ok(Some(texts))
        }
        Some(_) => Err(invalid(field)),
    }
}

/// An optional positive dimension.
fn optional_dimension(table: &TomlTable, field: &'static str) -> Result<Option<u64>, ConfigError> {
    match optional_int(table, field)? {
        None => Ok(None),
        Some(value) => Ok(Some(positive(value, field)?)),
    }
}

/// A millisecond budget: the configured value, or the documented default.
fn budget(table: &TomlTable, field: &'static str, default: i64) -> Result<u64, ConfigError> {
    match optional_int(table, field)? {
        None => Ok(default as u64),
        Some(value) => positive(value, field),
    }
}

/// A strictly positive integer, refused when it is zero or negative.
fn positive(value: i64, field: &'static str) -> Result<u64, ConfigError> {
    if value < 1 {
        return Err(invalid(field));
    }
    Ok(value as u64)
}

/// The accepted response-size ceiling, in bytes.
///
/// Rejects a non-positive value and any value whose read limit `value + 1` would
/// not fit in `usize` — the transport reads one byte past the limit to detect an
/// oversized body. TOML integers are `i64`, so on a 64-bit target this second
/// arm is unreachable and exists as a portability guard.
fn response_size_limit(value: i64) -> Option<u64> {
    if value < 1 {
        return None;
    }
    let plus_one = u128::try_from(value).ok()?.checked_add(1)?;
    if plus_one > usize::MAX as u128 {
        return None;
    }
    u64::try_from(value).ok()
}

/// Whether an id is a 1–64 byte ASCII name over `[A-Za-z0-9._-]`.
fn is_valid_profile_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// Whether `name` is usable as a POSIX-style environment variable name.
///
/// Only the *name* is ever stored; a later ticket reads the value.
fn is_valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_alphabetic() || first == b'_' => {}
        _ => return false,
    }
    bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// A missing required field.
fn missing(field: &'static str) -> ConfigError {
    ConfigError::at(ConfigErrorCode::MissingField, field)
}

/// A field present with an unacceptable value.
fn invalid(field: &'static str) -> ConfigError {
    ConfigError::at(ConfigErrorCode::InvalidValue, field)
}

/// A malformed fallback declaration.
fn fallback_error() -> ConfigError {
    ConfigError::at(ConfigErrorCode::InvalidFallback, "fallback_profile")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    const LOCAL_EMBEDDING_ENDPOINT: &str = "http://127.0.0.1:8080/v1/embeddings";
    const LOCAL_RERANK_ENDPOINT: &str = "http://127.0.0.1:8081/v1/rerank";
    const CLOUD_ENDPOINT: &str = "https://cloud.example.invalid/v1/embeddings";

    fn parse(text: &str) -> ValidatedApiConfig {
        ApiConfig::parse_toml(text).expect("configuration should validate")
    }

    fn reject(text: &str) -> ConfigError {
        ApiConfig::parse_toml(text).expect_err("configuration should be refused")
    }

    /// A valid profile body with `extra` appended, indentation-free.
    fn profile_body(
        kind: &str,
        protocol: &str,
        endpoint: &str,
        scope: &str,
        extra: &str,
    ) -> String {
        format!(
            "kind = \"{kind}\"\nprotocol = \"{protocol}\"\nendpoint = \"{endpoint}\"\n\
             scope = \"{scope}\"\nmodel = \"vendor-a/arbitrary-model\"\n\
             model_revision = \"deploy-2026-03-02\"\n{extra}"
        )
    }

    fn embedding_profile(extra: &str) -> String {
        profile_body(
            "embedding",
            "openai-embeddings-v1",
            LOCAL_EMBEDDING_ENDPOINT,
            "loopback",
            &format!("normalization = \"l2\"\n{extra}"),
        )
    }

    fn rerank_profile(extra: &str) -> String {
        profile_body(
            "rerank",
            "rerank-json-v1",
            LOCAL_RERANK_ENDPOINT,
            "loopback",
            extra,
        )
    }

    /// Wrap a profile body in a one-profile document.
    fn wrapped(body: &str) -> String {
        format!("version = 1\n[profiles.p1]\n{body}")
    }

    /// A legal loopback-primary / remote-cloud embedding pair.
    fn embedding_pair(primary_extra: &str, cloud_extra: &str) -> String {
        format!(
            r#"version = 1

[profiles.primary]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "http://127.0.0.1:9100/v1/embeddings"
scope = "loopback"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
{primary_extra}

[profiles.cloud]
kind = "embedding"
protocol = "openrouter-embeddings-v1"
endpoint = "https://cloud.example.invalid/v1/embeddings"
scope = "remote"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
provider_only = "vendor-a"
{cloud_extra}
"#
        )
    }

    /// A legal loopback-primary / remote-cloud rerank pair.
    fn rerank_pair(primary_extra: &str, cloud_extra: &str) -> String {
        format!(
            r#"version = 1

[profiles.primary]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "http://127.0.0.1:9200/score"
scope = "loopback"
model = "vendor-b/arbitrary-ranker"
model_revision = "rev-b"
{primary_extra}

[profiles.cloud]
kind = "rerank"
protocol = "openrouter-rerank-v1"
endpoint = "https://cloud.example.invalid/score"
scope = "remote"
model = "vendor-b/arbitrary-ranker"
model_revision = "rev-b"
provider_only = "vendor-b"
{cloud_extra}
"#
        )
    }

    // ---- positive coverage --------------------------------------------------

    #[test]
    fn accepts_a_fully_populated_embedding_profile() {
        let config = parse(&wrapped(&embedding_profile(
            "max_batch = 32\n\
             expected_dimension = 3072\n\
             request_dimensions = 3072\n\
             query_prefix = \"query: \"\n\
             document_prefix = \"passage: \"\n\
             api_key_env = \"ARBITRARY_KEY_VAR\"\n\
             models_endpoint = \"http://127.0.0.1:8080/v1/models\"\n\
             response_model_aliases = [\"vendor-a/arbitrary-model\"]\n",
        )));

        let profile = config.profile("p1").expect("p1 exists");
        assert_eq!(profile.kind, ProfileKind::Embedding);
        assert_eq!(profile.protocol, ApiProtocol::OpenAiEmbeddingsV1);
        assert_eq!(profile.scope, EndpointScope::Loopback);
        assert_eq!(profile.model, "vendor-a/arbitrary-model");
        assert_eq!(profile.model_revision, "deploy-2026-03-02");
        assert_eq!(profile.api_key_env.as_deref(), Some("ARBITRARY_KEY_VAR"));
        assert_eq!(profile.response_model_aliases.len(), 1);
        assert!(profile.send_model);
        assert_eq!(
            profile
                .models_endpoint
                .as_ref()
                .map(ValidatedEndpoint::as_str),
            Some("http://127.0.0.1:8080/v1/models")
        );
        assert_eq!(profile.connect_timeout_ms, 5_000);
        assert_eq!(profile.timeout_ms, 60_000);
        assert_eq!(profile.max_response_bytes, 67_108_864);
        assert_eq!(config.version(), 1);

        let embedding = profile.embedding().expect("embedding detail");
        assert_eq!(embedding.max_batch, 32);
        assert_eq!(embedding.expected_dimension, Some(3072));
        assert_eq!(embedding.request_dimensions, Some(3072));
        assert_eq!(embedding.normalization, Normalization::L2);
        assert_eq!(embedding.query_prefix, "query: ");
        assert_eq!(embedding.document_prefix, "passage: ");
        assert!(embedding.fallback_compatibility_file.is_none());
    }

    #[test]
    fn accepts_rerank_json_profile_with_an_instruction() {
        let config = parse(&wrapped(&rerank_profile(
            "instruction = \"Score the passage against the question.\"\n",
        )));
        let profile = config.profile("p1").expect("p1 exists");
        assert_eq!(profile.kind, ProfileKind::Rerank);
        assert_eq!(profile.protocol, ApiProtocol::RerankJsonV1);
        assert_eq!(
            profile
                .rerank()
                .expect("rerank detail")
                .instruction
                .as_deref(),
            Some("Score the passage against the question.")
        );
        assert!(profile.embedding().is_none());
    }

    #[test]
    fn accepts_all_four_protocols_with_arbitrary_models_and_dimensions() {
        let text = r#"
version = 1
default_embedding = "emb-openai"
default_rerank = "rerank-openrouter"

[profiles.emb-openai]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "http://127.0.0.1:9001/v1/embeddings"
scope = "loopback"
model = "vendor-a/text-xyz-large"
model_revision = "rev-a1"
normalization = "none"
expected_dimension = 4096

[profiles.emb-cloud]
kind = "embedding"
protocol = "openrouter-embeddings-v1"
endpoint = "https://cloud.example.invalid/v1/embeddings"
scope = "remote"
model = "vendor-a/text-xyz-large"
model_revision = "rev-a1"
normalization = "none"
provider_only = "vendor-a"

[profiles.rerank-local]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "http://[::1]:9002/score"
scope = "loopback"
model = "vendor-b/ranker-7b"
model_revision = "rev-b7"

[profiles.rerank-openrouter]
kind = "rerank"
protocol = "openrouter-rerank-v1"
endpoint = "https://cloud.example.invalid/v1/rerank"
scope = "remote"
model = "vendor-b/ranker-7b"
model_revision = "rev-b7"
provider_only = "vendor-b"
"#;
        let config = parse(text);
        assert_eq!(config.profiles().count(), 4);
        assert_eq!(
            config
                .default_profile(ProfileKind::Embedding)
                .map(|p| p.id.as_str()),
            Some("emb-openai")
        );
        assert_eq!(
            config
                .default_profile(ProfileKind::Rerank)
                .map(|p| p.id.as_str()),
            Some("rerank-openrouter")
        );
        assert_eq!(
            config
                .profile("emb-cloud")
                .and_then(|p| p.embedding())
                .and_then(|e| e.provider_only.as_deref()),
            Some("vendor-a")
        );
    }

    #[test]
    fn accepts_a_legal_embedding_fallback_graph() {
        let text = embedding_pair(
            "expected_dimension = 1024\nfallback_profile = \"cloud\"\n\
             fallback_compatibility_file = \"/definitely/not/here/compat.json\"\n",
            "",
        );
        let config = parse(&text);
        let primary = config.profile("primary").expect("primary exists");
        assert_eq!(primary.fallback_profile.as_deref(), Some("cloud"));
        assert_eq!(
            primary
                .embedding()
                .and_then(|e| e.fallback_compatibility_file.as_deref()),
            // Stored verbatim even though no such file exists.
            Some("/definitely/not/here/compat.json")
        );
    }

    #[test]
    fn accepts_rerank_fallback_when_instructions_match_exactly() {
        let text = rerank_pair(
            "instruction = \"same bytes\"\nfallback_profile = \"cloud\"\n",
            "instruction = \"same bytes\"\n",
        );
        let config = parse(&text);
        assert_eq!(
            config
                .profile("primary")
                .and_then(|p| p.fallback_profile.as_deref()),
            Some("cloud")
        );
    }

    #[test]
    fn accepts_rerank_fallback_when_both_instructions_are_absent() {
        let text = rerank_pair("fallback_profile = \"cloud\"\n", "");
        let config = parse(&text);
        assert!(
            config
                .profile("primary")
                .and_then(ValidatedProfile::rerank)
                .expect("rerank detail")
                .instruction
                .is_none()
        );
    }

    #[test]
    fn accepts_a_rerank_cloud_primary_without_a_provider_pin() {
        // Only an *embedding* cloud fallback must pin a provider.
        let text = r#"
version = 1

[profiles.primary]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "http://127.0.0.1:9300/score"
scope = "loopback"
model = "vendor-b/arbitrary-ranker"
model_revision = "rev-b"
fallback_profile = "cloud"

[profiles.cloud]
kind = "rerank"
protocol = "openrouter-rerank-v1"
endpoint = "https://cloud.example.invalid/score"
scope = "remote"
model = "vendor-b/arbitrary-ranker"
model_revision = "rev-b"
"#;
        assert!(ApiConfig::parse_toml(text).is_ok());
    }

    #[test]
    fn applies_documented_defaults() {
        let config = parse(&wrapped(&embedding_profile("")));
        let profile = config.profile("p1").expect("p1 exists");
        assert!(profile.response_model_aliases.is_empty());
        assert!(profile.send_model);
        assert!(profile.api_key_env.is_none());
        assert!(profile.models_endpoint.is_none());
        assert!(profile.fallback_profile.is_none());
        assert_eq!(profile.connect_timeout_ms, 5_000);
        assert_eq!(profile.timeout_ms, 60_000);
        assert_eq!(profile.max_response_bytes, 67_108_864);
        let embedding = profile.embedding().expect("embedding detail");
        assert_eq!(embedding.max_batch, 64);
        assert!(embedding.expected_dimension.is_none());
        assert!(embedding.request_dimensions.is_none());
        assert_eq!(embedding.query_prefix, "");
        assert_eq!(embedding.document_prefix, "");
    }

    #[test]
    fn preserves_prefix_and_whitespace_bytes_verbatim() {
        let config = parse(&wrapped(&embedding_profile(
            "query_prefix = \"  spaced  \"\ndocument_prefix = \"line\\nbreak\"\n",
        )));
        let embedding = config
            .profile("p1")
            .and_then(ValidatedProfile::embedding)
            .expect("embedding detail");
        assert_eq!(embedding.query_prefix, "  spaced  ");
        assert_eq!(embedding.document_prefix, "line\nbreak");
    }

    #[test]
    fn preserves_model_and_revision_bytes_verbatim() {
        let text = "\
version = 1
[profiles.p1]
kind = \"embedding\"
protocol = \"openai-embeddings-v1\"
endpoint = \"http://127.0.0.1:8080/v1/embeddings\"
scope = \"loopback\"
model = \"  spaced-model  \"
model_revision = \"  rev with spaces  \"
normalization = \"none\"
";
        let config = parse(text);
        let profile = config.profile("p1").expect("p1 exists");
        assert_eq!(profile.model, "  spaced-model  ");
        assert_eq!(profile.model_revision, "  rev with spaces  ");
    }

    #[test]
    fn preserves_the_endpoint_string_verbatim() {
        let config = parse(&wrapped(&embedding_profile("")));
        assert_eq!(
            config.profile("p1").expect("p1 exists").endpoint.as_str(),
            LOCAL_EMBEDDING_ENDPOINT
        );
    }

    // ---- document shape -----------------------------------------------------

    #[test]
    fn rejects_malformed_toml() {
        assert_eq!(
            reject("this is not = = toml").code(),
            ConfigErrorCode::InvalidToml
        );
        assert_eq!(reject("version = ").code(), ConfigErrorCode::InvalidToml);
        assert_eq!(reject("").code(), ConfigErrorCode::MissingField);
    }

    #[test]
    fn rejects_duplicate_keys_and_profiles() {
        let duplicate_key = "version = 1\nversion = 1\n";
        assert_eq!(reject(duplicate_key).code(), ConfigErrorCode::InvalidToml);

        let duplicate_profile = "version = 1\n[profiles.p1]\nkind = \"embedding\"\n\
                                 [profiles.p1]\nkind = \"embedding\"\n";
        assert_eq!(
            reject(duplicate_profile).code(),
            ConfigErrorCode::InvalidToml
        );

        let duplicate_field = wrapped(&embedding_profile("").replace(
            "model = \"vendor-a/arbitrary-model\"",
            "model = \"a\"\nmodel = \"b\"",
        ));
        assert_eq!(
            reject(&duplicate_field).code(),
            ConfigErrorCode::InvalidToml
        );
    }

    #[test]
    fn rejects_a_missing_version_or_profiles_table() {
        let error = reject("[profiles.p1]\nkind = \"embedding\"\n");
        assert_eq!(error.code(), ConfigErrorCode::MissingField);
        assert_eq!(error.field(), Some("version"));

        let error = reject("version = 1\n");
        assert_eq!(error.code(), ConfigErrorCode::MissingField);
        assert_eq!(error.field(), Some("profiles"));
    }

    #[test]
    fn rejects_unsupported_versions() {
        for version in ["0", "2", "-1", "999"] {
            let text = format!(
                "version = {version}\n[profiles.p1]\n{}",
                embedding_profile("")
            );
            let error = reject(&text);
            assert_eq!(
                error.code(),
                ConfigErrorCode::UnsupportedVersion,
                "{version}"
            );
            assert_eq!(error.field(), Some("version"));
        }
    }

    #[test]
    fn rejects_a_version_that_is_not_an_integer() {
        for version in ["\"1\"", "1.0", "true", "[1]"] {
            let text = format!("version = {version}\n[profiles.p1]\n");
            assert_eq!(
                reject(&text).code(),
                ConfigErrorCode::InvalidValue,
                "{version}"
            );
        }
    }

    #[test]
    fn rejects_unknown_root_fields() {
        let text = format!(
            "version = 1\nmystery = 1\n[profiles.p1]\n{}",
            embedding_profile("")
        );
        assert_eq!(reject(&text).code(), ConfigErrorCode::UnknownField);
    }

    #[test]
    fn rejects_unknown_profile_fields() {
        let body = embedding_profile("extra_body = { override = \"everything\" }\n");
        assert_eq!(
            reject(&wrapped(&body)).code(),
            ConfigErrorCode::UnknownField
        );

        let body = embedding_profile("api_key = \"sk-plaintext-not-allowed\"\n");
        assert_eq!(
            reject(&wrapped(&body)).code(),
            ConfigErrorCode::UnknownField
        );
    }

    #[test]
    fn rejects_non_table_profiles_container_and_entries() {
        assert_eq!(
            reject("version = 1\nprofiles = 3\n").code(),
            ConfigErrorCode::InvalidValue
        );
        assert_eq!(
            reject("version = 1\nprofiles = { p1 = 3 }\n").code(),
            ConfigErrorCode::InvalidValue
        );
    }

    #[test]
    fn rejects_invalid_profile_ids() {
        for id in ["", "has space", "has/slash", "has:colon", "emoji-☃"] {
            let text = format!(
                "version = 1\n[profiles.\"{id}\"]\n{}",
                embedding_profile("")
            );
            let error = reject(&text);
            assert_eq!(error.code(), ConfigErrorCode::InvalidProfileId, "{id:?}");
            assert_eq!(error.field(), Some("profiles"));
        }

        let long = "a".repeat(65);
        let text = format!(
            "version = 1\n[profiles.\"{long}\"]\n{}",
            embedding_profile("")
        );
        assert_eq!(reject(&text).code(), ConfigErrorCode::InvalidProfileId);

        let exactly_64 = "a".repeat(64);
        let text = format!(
            "version = 1\n[profiles.\"{exactly_64}\"]\n{}",
            embedding_profile("")
        );
        assert!(ApiConfig::parse_toml(&text).is_ok());
    }

    // ---- profile fields -----------------------------------------------------

    #[test]
    fn rejects_a_missing_kind_protocol_or_normalization() {
        let without_kind = "\
version = 1
[profiles.p1]
protocol = \"openai-embeddings-v1\"
endpoint = \"http://127.0.0.1:8080/v1/embeddings\"
scope = \"loopback\"
model = \"vendor-a/m\"
model_revision = \"rev-1\"
normalization = \"l2\"
";
        let error = reject(without_kind);
        assert_eq!(error.code(), ConfigErrorCode::MissingField);
        assert_eq!(error.field(), Some("kind"));

        let without_protocol = "\
version = 1
[profiles.p1]
kind = \"embedding\"
endpoint = \"http://127.0.0.1:8080/v1/embeddings\"
scope = \"loopback\"
model = \"vendor-a/m\"
model_revision = \"rev-1\"
normalization = \"l2\"
";
        let error = reject(without_protocol);
        assert_eq!(error.code(), ConfigErrorCode::MissingField);
        assert_eq!(error.field(), Some("protocol"));

        let without_normalization = "\
version = 1
[profiles.p1]
kind = \"embedding\"
protocol = \"openai-embeddings-v1\"
endpoint = \"http://127.0.0.1:8080/v1/embeddings\"
scope = \"loopback\"
model = \"vendor-a/m\"
model_revision = \"rev-1\"
";
        let error = reject(without_normalization);
        assert_eq!(error.code(), ConfigErrorCode::MissingField);
        assert_eq!(error.field(), Some("normalization"));

        let without_scope = "\
version = 1
[profiles.p1]
kind = \"embedding\"
protocol = \"openai-embeddings-v1\"
endpoint = \"http://127.0.0.1:8080/v1/embeddings\"
model = \"vendor-a/m\"
model_revision = \"rev-1\"
normalization = \"l2\"
";
        let error = reject(without_scope);
        assert_eq!(error.code(), ConfigErrorCode::MissingField);
        assert_eq!(error.field(), Some("scope"));
    }

    #[test]
    fn rejects_empty_or_whitespace_required_text() {
        for value in ["\"\"", "\"   \""] {
            let body = embedding_profile("").replace(
                "model = \"vendor-a/arbitrary-model\"",
                &format!("model = {value}"),
            );
            assert_eq!(
                reject(&wrapped(&body)).code(),
                ConfigErrorCode::InvalidValue,
                "{value}"
            );

            let body = embedding_profile("").replace(
                "model_revision = \"deploy-2026-03-02\"",
                &format!("model_revision = {value}"),
            );
            assert_eq!(
                reject(&wrapped(&body)).code(),
                ConfigErrorCode::InvalidValue,
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_wrong_types_for_required_text() {
        for value in ["1", "1.5", "true", "[\"a\"]"] {
            let body = embedding_profile("").replace(
                "model_revision = \"deploy-2026-03-02\"",
                &format!("model_revision = {value}"),
            );
            assert_eq!(
                reject(&wrapped(&body)).code(),
                ConfigErrorCode::InvalidValue,
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_main_and_latest_as_a_revision() {
        for revision in ["main", "latest", "MAIN", "Latest"] {
            let body = embedding_profile("").replace("deploy-2026-03-02", revision);
            assert_eq!(
                reject(&wrapped(&body)).code(),
                ConfigErrorCode::InvalidValue,
                "{revision}"
            );
        }
    }

    #[test]
    fn rejects_unknown_enum_spellings() {
        let body = embedding_profile("").replace("\"embedding\"", "\"ranking\"");
        assert_eq!(
            reject(&wrapped(&body)).code(),
            ConfigErrorCode::InvalidValue
        );

        let body = embedding_profile("").replace("openai-embeddings-v1", "openai-embeddings-v2");
        assert_eq!(
            reject(&wrapped(&body)).code(),
            ConfigErrorCode::InvalidValue
        );

        let body = embedding_profile("").replace("\"l2\"", "\"cosine\"");
        assert_eq!(
            reject(&wrapped(&body)).code(),
            ConfigErrorCode::InvalidValue
        );

        let body = embedding_profile("").replace("\"loopback\"", "\"local\"");
        assert_eq!(
            reject(&wrapped(&body)).code(),
            ConfigErrorCode::InvalidValue
        );

        // Enum spellings are exact; case folding is not applied.
        let body = embedding_profile("").replace("\"embedding\"", "\"Embedding\"");
        assert_eq!(
            reject(&wrapped(&body)).code(),
            ConfigErrorCode::InvalidValue
        );
    }

    #[test]
    fn rejects_kind_and_protocol_disagreement() {
        let body = embedding_profile("").replace(
            "protocol = \"openai-embeddings-v1\"",
            "protocol = \"rerank-json-v1\"",
        );
        let error = reject(&wrapped(&body));
        assert_eq!(error.code(), ConfigErrorCode::KindMismatch);
        assert_eq!(error.field(), Some("protocol"));

        let body = rerank_profile("").replace(
            "protocol = \"rerank-json-v1\"",
            "protocol = \"openai-embeddings-v1\"",
        );
        assert_eq!(
            reject(&wrapped(&body)).code(),
            ConfigErrorCode::KindMismatch
        );
    }

    #[test]
    fn rejects_embedding_only_fields_on_a_rerank_profile() {
        for extra in [
            "max_batch = 8\n",
            "expected_dimension = 1024\n",
            "request_dimensions = 1024\n",
            "normalization = \"l2\"\n",
            "query_prefix = \"q: \"\n",
            "document_prefix = \"d: \"\n",
            "fallback_compatibility_file = \"/tmp/x.json\"\n",
        ] {
            let text = wrapped(&rerank_profile(extra));
            assert_eq!(
                reject(&text).code(),
                ConfigErrorCode::InvalidValue,
                "{extra}"
            );
        }
    }

    #[test]
    fn rejects_instruction_on_an_embedding_profile() {
        let text = wrapped(&embedding_profile("instruction = \"do not use me\"\n"));
        assert_eq!(reject(&text).code(), ConfigErrorCode::InvalidValue);
    }

    #[test]
    fn rejects_wrong_types_for_scalar_fields() {
        for extra in [
            "send_model = \"yes\"\n",
            "max_batch = \"64\"\n",
            "connect_timeout_ms = \"5\"\n",
            "timeout_ms = 1.5\n",
            "max_response_bytes = [1]\n",
            "response_model_aliases = \"one\"\n",
            "response_model_aliases = [1, 2]\n",
            "api_key_env = 7\n",
        ] {
            let text = wrapped(&embedding_profile(extra));
            assert_eq!(
                reject(&text).code(),
                ConfigErrorCode::InvalidValue,
                "{extra}"
            );
        }
    }

    #[test]
    fn rejects_zero_and_negative_budgets_and_dimensions() {
        for extra in [
            "connect_timeout_ms = 0\n",
            "connect_timeout_ms = -1\n",
            "timeout_ms = 0\n",
            "timeout_ms = -5\n",
            "max_response_bytes = 0\n",
            "max_response_bytes = -1\n",
            "max_batch = 0\n",
            "max_batch = -64\n",
            "expected_dimension = 0\n",
            "request_dimensions = 0\n",
        ] {
            let text = wrapped(&embedding_profile(extra));
            assert_eq!(
                reject(&text).code(),
                ConfigErrorCode::InvalidValue,
                "{extra}"
            );
        }
    }

    #[test]
    fn response_budget_rejects_an_overflowing_read_limit() {
        // TOML integers are `i64`, so a literal large enough to overflow a
        // 64-bit `usize` once incremented is already outside the TOML range and
        // the parse refuses it.
        let body = embedding_profile("max_response_bytes = 18446744073709551615\n");
        assert_eq!(reject(&wrapped(&body)).code(), ConfigErrorCode::InvalidToml);

        // The helper's own boundary is exercised directly, including the
        // portability arm that a 64-bit target cannot otherwise reach.
        assert_eq!(response_size_limit(0), None);
        assert_eq!(response_size_limit(-1), None);
        assert_eq!(response_size_limit(1), Some(1));
        assert_eq!(response_size_limit(67_108_864), Some(67_108_864));
        assert_eq!(response_size_limit(i64::MAX), Some(i64::MAX as u64));
        assert_eq!(
            response_size_limit(i64::MAX - 1),
            Some((i64::MAX - 1) as u64)
        );
    }

    #[test]
    fn rejects_disagreeing_dimension_declarations() {
        let text = wrapped(&embedding_profile(
            "expected_dimension = 1024\nrequest_dimensions = 768\n",
        ));
        let error = reject(&text);
        assert_eq!(error.code(), ConfigErrorCode::InvalidValue);
        assert_eq!(error.field(), Some("request_dimensions"));
    }

    #[test]
    fn accepts_equal_dimension_declarations() {
        let text = wrapped(&embedding_profile(
            "expected_dimension = 1024\nrequest_dimensions = 1024\n",
        ));
        let embedding = parse(&text)
            .profile("p1")
            .and_then(ValidatedProfile::embedding)
            .expect("embedding detail")
            .clone();
        assert_eq!(embedding.expected_dimension, Some(1024));
        assert_eq!(embedding.request_dimensions, Some(1024));
    }

    #[test]
    fn rejects_wildcard_and_duplicate_aliases() {
        for extra in [
            "response_model_aliases = [\"*\"]\n",
            "response_model_aliases = [\"vendor-?\"]\n",
            "response_model_aliases = [\"\"]\n",
            "response_model_aliases = [\"   \"]\n",
            "response_model_aliases = [\"dup\", \"dup\"]\n",
        ] {
            let text = wrapped(&embedding_profile(extra));
            assert_eq!(
                reject(&text).code(),
                ConfigErrorCode::InvalidValue,
                "{extra}"
            );
        }
    }

    #[test]
    fn accepts_exact_and_listed_aliases() {
        let text = wrapped(&embedding_profile(
            "response_model_aliases = [\"vendor-a/arbitrary-model\", \"alias-two\"]\n",
        ));
        let profile = parse(&text);
        assert_eq!(
            profile
                .profile("p1")
                .expect("p1 exists")
                .response_model_aliases,
            vec![
                "vendor-a/arbitrary-model".to_string(),
                "alias-two".to_string()
            ]
        );
    }

    #[test]
    fn rejects_invalid_api_key_env_names() {
        for name in [
            "",
            "   ",
            "1LEADING_DIGIT",
            "HAS-DASH",
            "HAS SPACE",
            "has.dot",
        ] {
            let extra = format!("api_key_env = \"{name}\"\n");
            let text = wrapped(&embedding_profile(&extra));
            let error = reject(&text);
            assert_eq!(error.code(), ConfigErrorCode::InvalidValue, "{name:?}");
            assert_eq!(error.field(), Some("api_key_env"));
        }
    }

    #[test]
    fn accepts_a_plausible_api_key_env_name() {
        let text = wrapped(&embedding_profile("api_key_env = \"_PRIVATE_KEY_2\"\n"));
        assert_eq!(
            parse(&text)
                .profile("p1")
                .and_then(|p| p.api_key_env.as_deref()),
            Some("_PRIVATE_KEY_2")
        );
    }

    #[test]
    fn rejects_openrouter_without_send_model() {
        let body = profile_body(
            "embedding",
            "openrouter-embeddings-v1",
            CLOUD_ENDPOINT,
            "remote",
            "normalization = \"l2\"\nsend_model = false\nprovider_only = \"vendor-a\"\n",
        );
        let error = reject(&wrapped(&body));
        assert_eq!(error.code(), ConfigErrorCode::InvalidValue);
        assert_eq!(error.field(), Some("send_model"));

        let body = profile_body(
            "rerank",
            "openrouter-rerank-v1",
            "https://cloud.example.invalid/score",
            "remote",
            "provider_only = \"vendor-b\"\nsend_model = false\n",
        );
        let error = reject(&wrapped(&body));
        assert_eq!(error.code(), ConfigErrorCode::InvalidValue);
        assert_eq!(error.field(), Some("send_model"));
    }

    #[test]
    fn accepts_openrouter_with_send_model_left_at_its_default() {
        let body = profile_body(
            "embedding",
            "openrouter-embeddings-v1",
            CLOUD_ENDPOINT,
            "remote",
            "normalization = \"l2\"\nprovider_only = \"vendor-a\"\n",
        );
        assert!(
            parse(&wrapped(&body))
                .profile("p1")
                .expect("p1 exists")
                .send_model
        );
    }

    #[test]
    fn rejects_provider_only_on_a_non_openrouter_protocol() {
        let text = wrapped(&embedding_profile("provider_only = \"vendor-a\"\n"));
        let error = reject(&text);
        assert_eq!(error.code(), ConfigErrorCode::InvalidValue);
        assert_eq!(error.field(), Some("provider_only"));
    }

    #[test]
    fn rejects_an_empty_provider_only() {
        let body = profile_body(
            "embedding",
            "openrouter-embeddings-v1",
            CLOUD_ENDPOINT,
            "remote",
            "normalization = \"l2\"\nprovider_only = \"   \"\n",
        );
        let error = reject(&wrapped(&body));
        assert_eq!(error.code(), ConfigErrorCode::InvalidValue);
        assert_eq!(error.field(), Some("provider_only"));
    }

    // ---- endpoint rules -----------------------------------------------------

    #[test]
    fn rejects_non_http_schemes() {
        for endpoint in [
            "ftp://127.0.0.1/v1",
            "file:///etc/passwd",
            "unix:///run/socket",
            "ws://127.0.0.1/v1",
            "127.0.0.1:8080/v1",
        ] {
            let body = embedding_profile("").replace(LOCAL_EMBEDDING_ENDPOINT, endpoint);
            let error = reject(&wrapped(&body));
            assert_eq!(error.code(), ConfigErrorCode::InvalidEndpoint, "{endpoint}");
            assert_eq!(error.field(), Some("endpoint"));
        }
    }

    #[test]
    fn rejects_userinfo_in_every_shape() {
        for endpoint in [
            "http://user:pass@127.0.0.1:8080/v1",
            "http://user@127.0.0.1:8080/v1",
            "http://@127.0.0.1:8080/v1",
        ] {
            let body = embedding_profile("").replace(LOCAL_EMBEDDING_ENDPOINT, endpoint);
            assert_eq!(
                reject(&wrapped(&body)).code(),
                ConfigErrorCode::InvalidEndpoint,
                "{endpoint}"
            );
        }
    }

    #[test]
    fn rejects_userinfo_spellings_the_url_parser_normalizes_away() {
        for endpoint in ["http:////@127.0.0.1:8080/v1", "http:/@127.0.0.1:8080/v1"] {
            let body = embedding_profile("").replace(LOCAL_EMBEDDING_ENDPOINT, endpoint);
            let error = reject(&wrapped(&body));
            assert_eq!(error.code(), ConfigErrorCode::InvalidEndpoint, "{endpoint}");
        }
    }

    #[test]
    fn accepts_an_at_sign_that_is_part_of_the_path() {
        let endpoint = "http://127.0.0.1:8080/v1/@me/embeddings";
        let body = embedding_profile("").replace(LOCAL_EMBEDDING_ENDPOINT, endpoint);
        assert!(ApiConfig::parse_toml(&wrapped(&body)).is_ok());
    }

    #[test]
    fn rejects_fragments_and_query_strings() {
        for endpoint in [
            "http://127.0.0.1:8080/v1#fragment",
            "http://127.0.0.1:8080/v1?api_key=synthetic-secret",
            "http://127.0.0.1:8080/v1?format=json",
        ] {
            let body = embedding_profile("").replace(LOCAL_EMBEDDING_ENDPOINT, endpoint);
            let error = reject(&wrapped(&body));
            assert_eq!(error.code(), ConfigErrorCode::InvalidEndpoint, "{endpoint}");
        }
    }

    #[test]
    fn rejects_a_loopback_scope_for_a_non_loopback_host() {
        for endpoint in [
            "http://192.168.1.10:8080/v1",
            "http://example.invalid/v1",
            "https://localhost.evil.invalid/v1",
            "http://10.0.0.1/v1",
        ] {
            let body = embedding_profile("").replace(LOCAL_EMBEDDING_ENDPOINT, endpoint);
            assert_eq!(
                reject(&wrapped(&body)).code(),
                ConfigErrorCode::InvalidEndpoint,
                "{endpoint}"
            );
        }
    }

    #[test]
    fn accepts_every_loopback_spelling() {
        for endpoint in [
            "http://127.0.0.1:1/v1",
            "http://127.5.5.5:1/v1",
            "http://localhost/v1",
            "https://LOCALHOST:8443/v1",
            "http://[::1]:8080/v1",
            "http://[0:0:0:0:0:0:0:1]:8080/v1",
        ] {
            let body = embedding_profile("").replace(LOCAL_EMBEDDING_ENDPOINT, endpoint);
            assert!(
                ApiConfig::parse_toml(&wrapped(&body)).is_ok(),
                "{endpoint} should validate"
            );
        }
    }

    #[test]
    fn rejects_remote_scope_over_plain_http() {
        let body = profile_body(
            "embedding",
            "openai-embeddings-v1",
            "http://api.example.invalid/v1/embeddings",
            "remote",
            "normalization = \"l2\"\n",
        );
        let error = reject(&wrapped(&body));
        assert_eq!(error.code(), ConfigErrorCode::InvalidEndpoint);
        assert_eq!(error.field(), Some("endpoint"));
    }

    #[test]
    fn accepts_remote_scope_over_https() {
        let body = embedding_profile("")
            .replace(
                LOCAL_EMBEDDING_ENDPOINT,
                "https://api.example.invalid/v1/embeddings",
            )
            .replace("\"loopback\"", "\"remote\"");
        assert!(ApiConfig::parse_toml(&wrapped(&body)).is_ok());
    }

    #[test]
    fn rejects_models_endpoint_on_a_different_origin() {
        let cases = [
            // Different port.
            "http://127.0.0.1:9090/v1/models",
            // Different host spelling.
            "http://localhost:8080/v1/models",
            // Different scheme.
            "https://127.0.0.1:8080/v1/models",
        ];
        for models in cases {
            let extra = format!("models_endpoint = \"{models}\"\n");
            let body = embedding_profile(&extra);
            let error = reject(&wrapped(&body));
            assert_eq!(error.code(), ConfigErrorCode::InvalidValue, "{models}");
            assert_eq!(error.field(), Some("models_endpoint"));
        }
    }

    #[test]
    fn rejects_models_endpoint_that_is_not_a_valid_url() {
        let body = embedding_profile("models_endpoint = \"127.0.0.1:8080/v1/models\"\n");
        let error = reject(&wrapped(&body));
        assert_eq!(error.code(), ConfigErrorCode::InvalidEndpoint);
        assert_eq!(error.field(), Some("models_endpoint"));
    }

    #[test]
    fn accepts_a_same_origin_models_endpoint_on_a_cloud_profile() {
        let body = profile_body(
            "embedding",
            "openrouter-embeddings-v1",
            CLOUD_ENDPOINT,
            "remote",
            "normalization = \"l2\"\nprovider_only = \"vendor-a\"\n\
             models_endpoint = \"https://cloud.example.invalid/v1/models\"\n",
        );
        assert!(ApiConfig::parse_toml(&wrapped(&body)).is_ok());
    }

    // ---- fallback graph -----------------------------------------------------

    #[test]
    fn rejects_a_fallback_to_an_unknown_profile() {
        let text = wrapped(&embedding_profile("fallback_profile = \"nope\"\n"));
        let error = reject(&text);
        assert_eq!(error.code(), ConfigErrorCode::InvalidReference);
        assert_eq!(error.field(), Some("fallback_profile"));
    }

    #[test]
    fn rejects_a_fallback_declared_by_a_remote_primary() {
        let text = r#"
version = 1

[profiles.primary]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "https://primary.example.invalid/v1/embeddings"
scope = "remote"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
fallback_profile = "cloud"

[profiles.cloud]
kind = "embedding"
protocol = "openrouter-embeddings-v1"
endpoint = "https://cloud.example.invalid/v1/embeddings"
scope = "remote"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
provider_only = "vendor-a"
"#;
        assert_eq!(reject(text).code(), ConfigErrorCode::InvalidFallback);
    }

    #[test]
    fn rejects_a_fallback_target_that_is_not_remote() {
        let text = embedding_pair("fallback_profile = \"cloud\"\n", "")
            .replace(CLOUD_ENDPOINT, "http://127.0.0.1:9101/v1/embeddings")
            .replace("\"remote\"", "\"loopback\"");
        assert_eq!(reject(&text).code(), ConfigErrorCode::InvalidFallback);
    }

    #[test]
    fn rejects_a_self_referencing_fallback() {
        let text = wrapped(&embedding_profile("fallback_profile = \"p1\"\n"));
        assert_eq!(reject(&text).code(), ConfigErrorCode::InvalidFallback);
    }

    #[test]
    fn rejects_a_fallback_target_that_declares_its_own_fallback() {
        let text = r#"
version = 1

[profiles.primary]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "http://127.0.0.1:9400/v1/embeddings"
scope = "loopback"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
fallback_profile = "middle"

[profiles.middle]
kind = "embedding"
protocol = "openrouter-embeddings-v1"
endpoint = "https://middle.example.invalid/v1/embeddings"
scope = "remote"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
provider_only = "vendor-a"
fallback_profile = "last"

[profiles.last]
kind = "embedding"
protocol = "openrouter-embeddings-v1"
endpoint = "https://last.example.invalid/v1/embeddings"
scope = "remote"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
provider_only = "vendor-a"
"#;
        assert_eq!(reject(text).code(), ConfigErrorCode::InvalidFallback);
    }

    #[test]
    fn rejects_a_cross_kind_fallback() {
        let text = r#"
version = 1

[profiles.local]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "http://127.0.0.1:9700/score"
scope = "loopback"
model = "vendor-b/arbitrary-ranker"
model_revision = "rev-b"
fallback_profile = "cloud"

[profiles.cloud]
kind = "embedding"
protocol = "openrouter-embeddings-v1"
endpoint = "https://cloud.example.invalid/v1/embeddings"
scope = "remote"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
provider_only = "vendor-a"
"#;
        assert_eq!(reject(text).code(), ConfigErrorCode::InvalidFallback);
    }

    #[test]
    fn rejects_an_embedding_fallback_without_a_pinned_provider() {
        let text = r#"
version = 1

[profiles.primary]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "http://127.0.0.1:9500/v1/embeddings"
scope = "loopback"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
fallback_profile = "cloud"

[profiles.cloud]
kind = "embedding"
protocol = "openrouter-embeddings-v1"
endpoint = "https://cloud.example.invalid/v1/embeddings"
scope = "remote"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
"#;
        assert_eq!(reject(text).code(), ConfigErrorCode::InvalidFallback);
    }

    #[test]
    fn rejects_an_embedding_fallback_that_is_not_openrouter() {
        // The target is a plain OpenAI embedding profile with no provider pin,
        // so it cannot serve as cloud embedding fallback.
        let text = r#"
version = 1

[profiles.primary]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "http://127.0.0.1:9600/v1/embeddings"
scope = "loopback"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
fallback_profile = "cloud"

[profiles.cloud]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "https://cloud.example.invalid/v1/embeddings"
scope = "remote"
model = "vendor-a/arbitrary-model"
model_revision = "rev-1"
normalization = "l2"
"#;
        assert_eq!(reject(text).code(), ConfigErrorCode::InvalidFallback);
    }

    #[test]
    fn rejects_a_compatibility_file_without_a_fallback() {
        let text = wrapped(&embedding_profile(
            "fallback_compatibility_file = \"/tmp/compat.json\"\n",
        ));
        let error = reject(&text);
        assert_eq!(error.code(), ConfigErrorCode::InvalidFallback);
        assert_eq!(error.field(), Some("fallback_compatibility_file"));
    }

    #[test]
    fn rejects_mismatched_rerank_instructions() {
        let text = rerank_pair(
            "instruction = \"one\"\nfallback_profile = \"cloud\"\n",
            "instruction = \"another\"\n",
        );
        let error = reject(&text);
        assert_eq!(error.code(), ConfigErrorCode::InstructionMismatch);
        assert_eq!(error.field(), Some("instruction"));
    }

    #[test]
    fn an_absent_instruction_never_equals_an_empty_one() {
        let text = rerank_pair("instruction = \"\"\nfallback_profile = \"cloud\"\n", "");
        assert_eq!(reject(&text).code(), ConfigErrorCode::InstructionMismatch);

        let text = rerank_pair("fallback_profile = \"cloud\"\n", "instruction = \"\"\n");
        assert_eq!(reject(&text).code(), ConfigErrorCode::InstructionMismatch);
    }

    #[test]
    fn rejects_a_fallback_profile_id_of_the_wrong_shape() {
        let text = wrapped(&embedding_profile("fallback_profile = \"has space\"\n"));
        let error = reject(&text);
        assert_eq!(error.code(), ConfigErrorCode::InvalidValue);
        assert_eq!(error.field(), Some("fallback_profile"));
    }

    // ---- defaults -----------------------------------------------------------

    #[test]
    fn rejects_a_default_that_does_not_resolve() {
        let text = format!(
            "version = 1\ndefault_embedding = \"ghost\"\n[profiles.p1]\n{}",
            embedding_profile("")
        );
        let error = reject(&text);
        assert_eq!(error.code(), ConfigErrorCode::InvalidReference);
        assert_eq!(error.field(), Some("default_embedding"));

        let text = format!(
            "version = 1\ndefault_rerank = \"ghost\"\n[profiles.p1]\n{}",
            embedding_profile("")
        );
        let error = reject(&text);
        assert_eq!(error.code(), ConfigErrorCode::InvalidReference);
        assert_eq!(error.field(), Some("default_rerank"));
    }

    #[test]
    fn rejects_a_default_of_the_wrong_kind() {
        let text = format!(
            "version = 1\ndefault_embedding = \"p1\"\n[profiles.p1]\n{}",
            rerank_profile("")
        );
        let error = reject(&text);
        assert_eq!(error.code(), ConfigErrorCode::KindMismatch);
        assert_eq!(error.field(), Some("default_embedding"));

        let text = format!(
            "version = 1\ndefault_rerank = \"p1\"\n[profiles.p1]\n{}",
            embedding_profile("")
        );
        let error = reject(&text);
        assert_eq!(error.code(), ConfigErrorCode::KindMismatch);
        assert_eq!(error.field(), Some("default_rerank"));
    }

    #[test]
    fn rejects_a_default_that_is_not_a_string() {
        for value in ["1", "true", "[\"p1\"]"] {
            let text = format!(
                "version = 1\ndefault_embedding = {value}\n[profiles.p1]\n{}",
                embedding_profile("")
            );
            assert_eq!(
                reject(&text).code(),
                ConfigErrorCode::InvalidValue,
                "{value}"
            );
        }
    }

    #[test]
    fn absent_defaults_query_as_none() {
        let config = parse(&wrapped(&embedding_profile("")));
        assert!(config.default_profile(ProfileKind::Embedding).is_none());
        assert!(config.default_profile(ProfileKind::Rerank).is_none());
        assert!(config.default_profile_id(ProfileKind::Embedding).is_none());
        assert!(config.profile("absent").is_none());
        assert_eq!(config.profiles().count(), 1);
    }

    #[test]
    fn an_empty_profiles_map_is_structurally_valid() {
        let config = parse("version = 1\n[profiles]\n");
        assert_eq!(config.profiles().count(), 0);
        assert!(config.default_profile(ProfileKind::Embedding).is_none());
    }

    // ---- purity and privacy -------------------------------------------------

    #[test]
    fn no_error_echoes_document_text() {
        const SECRET: &str = "sk-synthetic-secret-value-9f3a";
        const MODEL: &str = "vendor-secret-model-name";

        let body = profile_body(
            "embedding",
            "openai-embeddings-v1",
            &format!("http://user:{SECRET}@127.0.0.1:8080/v1/embeddings"),
            "loopback",
            "normalization = \"l2\"\n",
        )
        .replace("vendor-a/arbitrary-model", MODEL);
        let error = reject(&wrapped(&body));
        assert_eq!(error.code(), ConfigErrorCode::InvalidEndpoint);
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(!rendered.contains(SECRET), "{rendered}");
            assert!(!rendered.contains(MODEL), "{rendered}");
            assert!(!rendered.contains("127.0.0.1"), "{rendered}");
            assert!(!rendered.contains("http"), "{rendered}");
        }

        // A secret smuggled in a key name is refused by name only.
        let body = embedding_profile(&format!("api_key = \"{SECRET}\"\n"))
            .replace("vendor-a/arbitrary-model", MODEL);
        let error = reject(&wrapped(&body));
        assert_eq!(error.code(), ConfigErrorCode::UnknownField);
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(!rendered.contains(SECRET), "{rendered}");
            assert!(!rendered.contains(MODEL), "{rendered}");
        }

        // And a secret in a query string never reaches the message either.
        let body = embedding_profile("").replace(
            LOCAL_EMBEDDING_ENDPOINT,
            &format!("http://127.0.0.1:8080/v1?api_key={SECRET}"),
        );
        let error = reject(&wrapped(&body));
        assert_eq!(error.code(), ConfigErrorCode::InvalidEndpoint);
        assert!(!error.to_string().contains(SECRET));
        assert!(!format!("{error:?}").contains(SECRET));
    }

    #[test]
    fn parsing_reads_no_file_and_no_environment_variable() {
        const MISSING: &str = "/definitely/not/here/api01a-compat.json";
        assert!(!Path::new(MISSING).exists());

        let text = embedding_pair(
            &format!(
                "api_key_env = \"API01A_DEFINITELY_UNSET\"\nfallback_profile = \"cloud\"\n\
                 fallback_compatibility_file = \"{MISSING}\"\n"
            ),
            "",
        );
        let config = parse(&text);
        let primary = config.profile("primary").expect("primary exists");
        // Only the variable *name* is stored; its value is never resolved here.
        assert_eq!(
            primary.api_key_env.as_deref(),
            Some("API01A_DEFINITELY_UNSET")
        );
        assert!(std::env::var("API01A_DEFINITELY_UNSET").is_err());
    }

    #[test]
    fn repeated_parses_and_queries_are_pure() {
        let text = wrapped(&embedding_profile(""));
        let first = parse(&text);
        let second = parse(&text);
        assert_eq!(first, second);
        assert_eq!(first.profiles().count(), second.profiles().count());
        assert!(first.profile("p1").is_some());
        assert!(first.profile("p1").is_some());
        assert!(first.profile("p1").is_some());
    }

    #[test]
    fn wire_names_are_the_documented_spellings() {
        assert_eq!(ProfileKind::Embedding.as_str(), "embedding");
        assert_eq!(ProfileKind::Rerank.as_str(), "rerank");
        assert_eq!(
            ApiProtocol::OpenAiEmbeddingsV1.as_str(),
            "openai-embeddings-v1"
        );
        assert_eq!(
            ApiProtocol::OpenRouterEmbeddingsV1.as_str(),
            "openrouter-embeddings-v1"
        );
        assert_eq!(ApiProtocol::RerankJsonV1.as_str(), "rerank-json-v1");
        assert_eq!(
            ApiProtocol::OpenRouterRerankV1.as_str(),
            "openrouter-rerank-v1"
        );
        assert_eq!(ApiProtocol::RerankJsonV1.kind(), ProfileKind::Rerank);
        assert_eq!(
            ApiProtocol::OpenAiEmbeddingsV1.kind(),
            ProfileKind::Embedding
        );
        assert!(ApiProtocol::OpenRouterRerankV1.is_openrouter());
        assert!(!ApiProtocol::RerankJsonV1.is_openrouter());
        assert_eq!(EndpointScope::Loopback.as_str(), "loopback");
        assert_eq!(EndpointScope::Remote.as_str(), "remote");
        assert_eq!(Normalization::L2.as_str(), "l2");
        assert_eq!(Normalization::None.as_str(), "none");
    }
}
