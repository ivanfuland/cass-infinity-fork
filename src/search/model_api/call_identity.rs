//! The call-time identity of one model-service endpoint, and of one rerank route.
//!
//! Two questions need an answer that is stable across processes but separate
//! from the vector space a model produces:
//!
//! * **What call is this?** Everything about one endpoint that changes what the
//!   process sends — the protocol, the full endpoint, the scope, the model and
//!   its declared revision, the accepted response aliases, whether `model` is
//!   sent, the instruction, the pinned provider, the two timeouts, the response
//!   ceiling, the metadata endpoint and the credential *variable name*. That is
//!   [`EndpointConfigIdentity`], the single-endpoint call-configuration digest.
//! * **Which rerank route is this?** The primary profile, its call-configuration
//!   digest, the configured fallback profile and its digest, and whether this
//!   call is allowed to use that fallback. That is [`RerankRouteIdentity`].
//!
//! Both are deliberately *not* the representation identity of
//! [`crate::search::model_api::identity`]. Re-hosting a model at a new endpoint
//! changes this call digest and leaves the vector space unchanged, so it must not
//! force a re-embedding; rotating a credential value changes neither digest. The
//! call digest is what a rerank window or a generation-provenance record binds to
//! show *how* a service was called; the representation descriptor is what decides
//! *which vectors may meet*.
//!
//! # The canonical form
//!
//! The canonical bytes are a compact UTF-8 JSON object whose keys appear in ASCII
//! order at every level, with no trailing newline. Strings keep their bytes
//! exactly: nothing is trimmed, case-folded or Unicode-normalized, and
//! `serde_json` escapes them as it does everywhere else in the tree. Array order
//! is preserved. The identity is the lowercase SHA-256 of exactly those bytes,
//! and the digest of a value is never one of its own fields — a route binds the
//! two endpoint digests, but neither endpoint object carries a digest of itself.
//!
//! # What this module is not
//!
//! It is a pure encoder and a validated constructor. It reads no file, reads no
//! environment variable, opens no socket and registers no caller, so
//! `api_key_env` is stored as the *name* of a variable and its value is never
//! touched. It offers no decoder back from arbitrary bytes: a later persistence
//! ticket that needs to reopen one of these identities must ask for a strict
//! decoder of its own, and this ticket does not let a reader skip validation. It
//! makes no compatibility or health judgement — the enabled-flag says only what
//! the configured relation permits, never which backend actually served a call.

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::config::{
    ApiProtocol, EmbeddingProfile, EndpointScope, Normalization, ProfileDetail, ProfileKind,
    RerankProfile, ValidatedApiConfig, ValidatedProfile,
};
use super::error::{ConfigError, ConfigErrorCode};

/// The domain tag of a single-endpoint call-configuration digest.
pub const CALL_CONFIG_DOMAIN: &str = "cass.api-call-config/1";

/// The only version of the call-configuration object this build writes.
pub const CALL_CONFIG_VERSION: i64 = 1;

/// The domain tag of a rerank-route digest.
pub const RERANK_ROUTE_DOMAIN: &str = "cass.api-rerank-route/1";

/// The only version of the rerank-route object this build writes.
pub const RERANK_ROUTE_VERSION: i64 = 1;

/// The embedding-only half of a call configuration.
///
/// This is the effective, already-defaulted embedding setting. The compatibility
/// evidence path that lives on [`EmbeddingProfile`] is not here: it belongs to
/// the fallback relation, not to the call one endpoint describes, and copying it
/// in would fold a reference to the route back into the thing the route hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EmbeddingCall {
    document_prefix: String,
    expected_dimension: Option<u64>,
    max_batch: u64,
    normalization: Normalization,
    provider_only: Option<String>,
    query_prefix: String,
    request_dimensions: Option<u64>,
}

impl EmbeddingCall {
    fn from_detail(detail: &EmbeddingProfile) -> Self {
        Self {
            document_prefix: detail.document_prefix.clone(),
            expected_dimension: detail.expected_dimension,
            max_batch: detail.max_batch,
            normalization: detail.normalization,
            provider_only: detail.provider_only.clone(),
            query_prefix: detail.query_prefix.clone(),
            request_dimensions: detail.request_dimensions,
        }
    }

    fn wire(&self) -> EmbeddingCallWire<'_> {
        EmbeddingCallWire {
            document_prefix: &self.document_prefix,
            expected_dimension: self.expected_dimension,
            max_batch: self.max_batch,
            normalization: self.normalization.as_str(),
            provider_only: self.provider_only.as_deref(),
            query_prefix: &self.query_prefix,
            request_dimensions: self.request_dimensions,
        }
    }
}

/// The rerank-only half of a call configuration.
///
/// `instruction` keeps `None` and `Some("")` apart through every comparison and
/// through the encoding, exactly as [`RerankProfile`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RerankCall {
    instruction: Option<String>,
    provider_only: Option<String>,
}

impl RerankCall {
    fn from_detail(detail: &RerankProfile) -> Self {
        Self {
            instruction: detail.instruction.clone(),
            provider_only: detail.provider_only.clone(),
        }
    }

    fn wire(&self) -> RerankCallWire<'_> {
        RerankCallWire {
            instruction: self.instruction.as_deref(),
            provider_only: self.provider_only.as_deref(),
        }
    }
}

/// Everything about one endpoint that changes what the process sends.
///
/// Build one from a [`ValidatedProfile`] and read its digest back with
/// [`Self::sha256`]. Every field is private and there is no setter, so an
/// identity that exists has passed the consistency rules in
/// [`Self::from_profile`]. The `domain` and `version` are compile-time
/// constants, never caller input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointConfigIdentity {
    api_key_env: Option<String>,
    connect_timeout_ms: u64,
    embedding: Option<EmbeddingCall>,
    endpoint: String,
    kind: ProfileKind,
    max_response_bytes: u64,
    model: String,
    model_revision: String,
    models_endpoint: Option<String>,
    protocol: ApiProtocol,
    rerank: Option<RerankCall>,
    response_model_aliases: Vec<String>,
    scope: EndpointScope,
    send_model: bool,
    timeout_ms: u64,
}

impl EndpointConfigIdentity {
    /// Build the call configuration of one validated profile.
    ///
    /// The profile's public fields carry the effective, already-defaulted values,
    /// but a caller that holds a `ValidatedProfile` need not have obtained it from
    /// [`ApiConfig::parse_toml`](super::config::ApiConfig::parse_toml), so this
    /// re-checks the three facts a hand-edited value could break: the protocol
    /// must serve the profile's `kind`, and the kind-specific detail must be the
    /// one that kind allows. A protocol that serves embedding on a rerank profile,
    /// or a rerank detail on an embedding profile, is a [`ConfigErrorCode::KindMismatch`].
    ///
    /// The profile id is deliberately absent: two profiles with identical call
    /// settings hash the same here, and the route is what binds the id.
    pub fn from_profile(profile: &ValidatedProfile) -> Result<Self, ConfigError> {
        if profile.protocol.kind() != profile.kind {
            return Err(ConfigError::at(ConfigErrorCode::KindMismatch, "protocol"));
        }
        let (embedding, rerank) = match (&profile.detail, profile.kind) {
            (ProfileDetail::Embedding(detail), ProfileKind::Embedding) => {
                (Some(EmbeddingCall::from_detail(detail)), None)
            }
            (ProfileDetail::Rerank(detail), ProfileKind::Rerank) => {
                (None, Some(RerankCall::from_detail(detail)))
            }
            _ => return Err(ConfigError::at(ConfigErrorCode::KindMismatch, "detail")),
        };

        Ok(Self {
            api_key_env: profile.api_key_env.clone(),
            connect_timeout_ms: profile.connect_timeout_ms,
            embedding,
            endpoint: profile.endpoint.as_str().to_string(),
            kind: profile.kind,
            max_response_bytes: profile.max_response_bytes,
            model: profile.model.clone(),
            model_revision: profile.model_revision.clone(),
            models_endpoint: profile
                .models_endpoint
                .as_ref()
                .map(|url| url.as_str().to_string()),
            protocol: profile.protocol,
            rerank,
            response_model_aliases: profile.response_model_aliases.clone(),
            scope: profile.scope,
            send_model: profile.send_model,
            timeout_ms: profile.timeout_ms,
        })
    }

    /// Whether this is an embedding or a rerank call configuration.
    pub const fn kind(&self) -> ProfileKind {
        self.kind
    }

    /// The canonical bytes: one compact JSON object, ASCII-ordered, no newline.
    ///
    /// Serializing these field types into a byte buffer cannot fail, so the empty
    /// fallback is unreachable and exists only to keep an `unwrap` out of the
    /// encoding path.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.wire()).unwrap_or_default()
    }

    /// The lowercase SHA-256 of [`Self::canonical_bytes`].
    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }

    fn wire(&self) -> CallConfigWire<'_> {
        CallConfigWire {
            api_key_env: self.api_key_env.as_deref(),
            connect_timeout_ms: self.connect_timeout_ms,
            domain: CALL_CONFIG_DOMAIN,
            embedding: self.embedding.as_ref().map(EmbeddingCall::wire),
            endpoint: &self.endpoint,
            kind: self.kind.as_str(),
            max_response_bytes: self.max_response_bytes,
            model: &self.model,
            model_revision: &self.model_revision,
            models_endpoint: self.models_endpoint.as_deref(),
            protocol: self.protocol.as_str(),
            rerank: self.rerank.as_ref().map(RerankCall::wire),
            response_model_aliases: &self.response_model_aliases,
            scope: self.scope.as_str(),
            send_model: self.send_model,
            timeout_ms: self.timeout_ms,
            version: CALL_CONFIG_VERSION,
        }
    }
}

/// The pairing of a rerank primary with its configured fallback.
///
/// Build one with [`Self::from_config`]. Every field is private; the accessors
/// expose the two profile ids, the two endpoint digests and the effective policy
/// flag, and nothing else — in particular no credential, no endpoint body and no
/// per-call health or timing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RerankRouteIdentity {
    allow_fallback: bool,
    fallback_config_sha256: Option<String>,
    fallback_profile: Option<String>,
    primary_config_sha256: String,
    primary_profile: String,
}

impl RerankRouteIdentity {
    /// Bind a rerank primary and its configured fallback into one route identity.
    ///
    /// `primary_profile_id` must name a rerank profile. When that profile
    /// declares a `fallback_profile`, the target must exist, must not be the
    /// primary itself, must be a remote same-kind profile that declares no
    /// fallback of its own, and the primary must be loopback — the same relation
    /// `config` builds at load time, re-checked here because a caller that holds a
    /// `ValidatedApiConfig` could have hand-edited the profile fields. A dangling,
    /// self-referential, recursive or wrong-kind relation is refused.
    ///
    /// `allow_fallback` is this call's policy flag, not part of the configuration.
    /// When a fallback *is* configured, its id and digest are bound whether the
    /// flag is true or false: disabling the fallback is a decision about one call,
    /// and it must not erase the configured snapshot the route names. When no
    /// fallback is configured, both fallback fields are `None` even if
    /// `allow_fallback` is true — this constructor never invents a target.
    pub fn from_config(
        config: &ValidatedApiConfig,
        primary_profile_id: &str,
        allow_fallback: bool,
    ) -> Result<Self, ConfigError> {
        let primary = config
            .profile(primary_profile_id)
            .ok_or_else(|| ConfigError::at(ConfigErrorCode::InvalidReference, "primary_profile"))?;
        if primary.kind != ProfileKind::Rerank
            || primary.protocol.kind() != ProfileKind::Rerank
            || primary.rerank().is_none()
        {
            return Err(ConfigError::at(
                ConfigErrorCode::KindMismatch,
                "primary_profile",
            ));
        }
        let primary_identity = EndpointConfigIdentity::from_profile(primary)?;

        let (fallback_profile, fallback_config_sha256) = match primary.fallback_profile.as_deref() {
            None => (None, None),
            Some(target_id) => {
                if target_id == primary.id || primary.scope != EndpointScope::Loopback {
                    return Err(fallback_relation_error());
                }
                let target = config.profile(target_id).ok_or_else(|| {
                    ConfigError::at(ConfigErrorCode::InvalidReference, "fallback_profile")
                })?;
                if target.kind != ProfileKind::Rerank
                    || target.protocol.kind() != ProfileKind::Rerank
                    || target.rerank().is_none()
                    || target.id == primary.id
                    || target.scope != EndpointScope::Remote
                    || target.fallback_profile.is_some()
                {
                    return Err(fallback_relation_error());
                }
                let target_identity = EndpointConfigIdentity::from_profile(target)?;
                (Some(target_id.to_string()), Some(target_identity.sha256()))
            }
        };

        Ok(Self {
            allow_fallback,
            fallback_config_sha256,
            fallback_profile,
            primary_config_sha256: primary_identity.sha256(),
            primary_profile: primary_profile_id.to_string(),
        })
    }

    /// Whether this call is allowed to use the configured fallback.
    pub const fn allow_fallback(&self) -> bool {
        self.allow_fallback
    }

    /// The primary rerank profile id this route names.
    pub fn primary_profile(&self) -> &str {
        &self.primary_profile
    }

    /// The call-configuration digest of the primary profile.
    pub fn primary_config_sha256(&self) -> &str {
        &self.primary_config_sha256
    }

    /// The configured fallback profile id, when the primary declares one.
    pub fn fallback_profile(&self) -> Option<&str> {
        self.fallback_profile.as_deref()
    }

    /// The call-configuration digest of the configured fallback, when there is one.
    pub fn fallback_config_sha256(&self) -> Option<&str> {
        self.fallback_config_sha256.as_deref()
    }

    /// The canonical bytes: one compact JSON object, ASCII-ordered, no newline.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.wire()).unwrap_or_default()
    }

    /// The lowercase SHA-256 of [`Self::canonical_bytes`].
    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }

    fn wire(&self) -> RouteWire<'_> {
        RouteWire {
            allow_fallback: self.allow_fallback,
            domain: RERANK_ROUTE_DOMAIN,
            fallback_config_sha256: self.fallback_config_sha256.as_deref(),
            fallback_profile: self.fallback_profile.as_deref(),
            primary_config_sha256: &self.primary_config_sha256,
            primary_profile: &self.primary_profile,
            version: RERANK_ROUTE_VERSION,
        }
    }
}

/// A malformed fallback relation: not loopback, self, dangling, recursive or
/// wrong kind.
fn fallback_relation_error() -> ConfigError {
    ConfigError::at(ConfigErrorCode::InvalidFallback, "fallback_profile")
}

/// The call configuration exactly as it is written, in canonical key order.
///
/// Declaring the fields in this order is what fixes the byte layout: `serde`
/// emits struct fields in declaration order, so the output does not depend on a
/// map implementation.
#[derive(Serialize)]
struct CallConfigWire<'a> {
    api_key_env: Option<&'a str>,
    connect_timeout_ms: u64,
    domain: &'a str,
    embedding: Option<EmbeddingCallWire<'a>>,
    endpoint: &'a str,
    kind: &'a str,
    max_response_bytes: u64,
    model: &'a str,
    model_revision: &'a str,
    models_endpoint: Option<&'a str>,
    protocol: &'a str,
    rerank: Option<RerankCallWire<'a>>,
    response_model_aliases: &'a [String],
    scope: &'a str,
    send_model: bool,
    timeout_ms: u64,
    version: i64,
}

/// The embedding half exactly as it is written, in canonical key order.
#[derive(Serialize)]
struct EmbeddingCallWire<'a> {
    document_prefix: &'a str,
    expected_dimension: Option<u64>,
    max_batch: u64,
    normalization: &'a str,
    provider_only: Option<&'a str>,
    query_prefix: &'a str,
    request_dimensions: Option<u64>,
}

/// The rerank half exactly as it is written, in canonical key order.
#[derive(Serialize)]
struct RerankCallWire<'a> {
    instruction: Option<&'a str>,
    provider_only: Option<&'a str>,
}

/// The rerank route exactly as it is written, in canonical key order.
#[derive(Serialize)]
struct RouteWire<'a> {
    allow_fallback: bool,
    domain: &'a str,
    fallback_config_sha256: Option<&'a str>,
    fallback_profile: Option<&'a str>,
    primary_config_sha256: &'a str,
    primary_profile: &'a str,
    version: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::model_api::config::ApiConfig;
    use crate::search::model_api::identity::RepresentationDescriptor;

    /// The gold call configuration of an embedding profile, written out by hand.
    ///
    /// This exact byte string, and the digests below, were computed with an
    /// external tool, not by the code under test. The document carries a
    /// non-ASCII model, aliases and revision, a newline in the query prefix, an
    /// *empty* document prefix and a null `request_dimensions`, so the empty
    /// string and the null are both fixed in the literal.
    const GOLD_EMB_JSON: &str = r#"{"api_key_env":"CASS_TEST_KEY","connect_timeout_ms":1500,"domain":"cass.api-call-config/1","embedding":{"document_prefix":"","expected_dimension":1024,"max_batch":32,"normalization":"l2","provider_only":"vendor-a","query_prefix":"查询:\n","request_dimensions":null},"endpoint":"http://127.0.0.1:9100/v1/embeddings","kind":"embedding","max_response_bytes":1048576,"model":"vendor-x/模型-甲","model_revision":"rev-字","models_endpoint":"http://127.0.0.1:9100/v1/models","protocol":"openrouter-embeddings-v1","rerank":null,"response_model_aliases":["模型-甲","alias-b"],"scope":"loopback","send_model":true,"timeout_ms":45000,"version":1}"#;

    /// SHA-256 of [`GOLD_EMB_JSON`], computed externally.
    const GOLD_EMB_SHA256: &str =
        "fab714af9f9fbaf74e7b7cc036b6d0e89854fa1124e61fbe09c7ea8cd7710d1c";

    /// The gold call configuration of a remote rerank profile. It is also the
    /// configured fallback of the gold route.
    const GOLD_RRK_JSON: &str = r#"{"api_key_env":null,"connect_timeout_ms":5000,"domain":"cass.api-call-config/1","embedding":null,"endpoint":"https://api.example.invalid/v1/rerank","kind":"rerank","max_response_bytes":67108864,"model":"vendor-y/重排-乙","model_revision":"rev-2","models_endpoint":null,"protocol":"openrouter-rerank-v1","rerank":{"instruction":"给定查询:\n请评分","provider_only":"vendor-b"},"response_model_aliases":[],"scope":"remote","send_model":true,"timeout_ms":60000,"version":1}"#;

    /// SHA-256 of [`GOLD_RRK_JSON`], computed externally.
    const GOLD_RRK_SHA256: &str =
        "47666a3b34966ab024eeb631085f2143128417d5ef64a11a658974402ecc5a19";

    /// The gold call configuration of the route's loopback rerank primary.
    const GOLD_ROUTE_PRIMARY_JSON: &str = r#"{"api_key_env":null,"connect_timeout_ms":5000,"domain":"cass.api-call-config/1","embedding":null,"endpoint":"http://127.0.0.1:9200/v1/rerank","kind":"rerank","max_response_bytes":67108864,"model":"vendor-y/重排-乙","model_revision":"rev-2","models_endpoint":null,"protocol":"rerank-json-v1","rerank":{"instruction":"给定查询:\n请评分","provider_only":null},"response_model_aliases":[],"scope":"loopback","send_model":true,"timeout_ms":60000,"version":1}"#;

    /// SHA-256 of [`GOLD_ROUTE_PRIMARY_JSON`], computed externally.
    const GOLD_ROUTE_PRIMARY_SHA256: &str =
        "aa89537d09045ea625f9e65cb8059f15d00498190ebb898af2d09331a31649bc";

    /// The gold rerank route, with its fallback bound and the policy flag false.
    const GOLD_ROUTE_JSON: &str = r#"{"allow_fallback":false,"domain":"cass.api-rerank-route/1","fallback_config_sha256":"47666a3b34966ab024eeb631085f2143128417d5ef64a11a658974402ecc5a19","fallback_profile":"rrk-cloud","primary_config_sha256":"aa89537d09045ea625f9e65cb8059f15d00498190ebb898af2d09331a31649bc","primary_profile":"rrk-primary","version":1}"#;

    /// SHA-256 of [`GOLD_ROUTE_JSON`], computed externally.
    const GOLD_ROUTE_SHA256: &str =
        "6f4fb36af352a5db00e8f1cf2f3b0fb8ef9db720c5ae4da43a23fad9bb616681";

    /// The one-profile document that reproduces [`GOLD_EMB_JSON`].
    const GOLD_EMB_DOC: &str = "version = 1\n\
        [profiles.emb]\n\
        kind = \"embedding\"\n\
        protocol = \"openrouter-embeddings-v1\"\n\
        endpoint = \"http://127.0.0.1:9100/v1/embeddings\"\n\
        scope = \"loopback\"\n\
        model = \"vendor-x/模型-甲\"\n\
        model_revision = \"rev-字\"\n\
        normalization = \"l2\"\n\
        response_model_aliases = [\"模型-甲\", \"alias-b\"]\n\
        send_model = true\n\
        api_key_env = \"CASS_TEST_KEY\"\n\
        models_endpoint = \"http://127.0.0.1:9100/v1/models\"\n\
        connect_timeout_ms = 1500\n\
        timeout_ms = 45000\n\
        max_response_bytes = 1048576\n\
        max_batch = 32\n\
        expected_dimension = 1024\n\
        query_prefix = \"查询:\\n\"\n\
        document_prefix = \"\"\n\
        provider_only = \"vendor-a\"\n";

    /// The three-profile document that reproduces the route golds: a loopback
    /// rerank primary with a remote same-kind fallback, plus an embedding profile.
    const GOLD_ROUTE_DOC: &str = "version = 1\n\
        [profiles.rrk-primary]\n\
        kind = \"rerank\"\n\
        protocol = \"rerank-json-v1\"\n\
        endpoint = \"http://127.0.0.1:9200/v1/rerank\"\n\
        scope = \"loopback\"\n\
        model = \"vendor-y/重排-乙\"\n\
        model_revision = \"rev-2\"\n\
        instruction = \"给定查询:\\n请评分\"\n\
        fallback_profile = \"rrk-cloud\"\n\
        [profiles.rrk-cloud]\n\
        kind = \"rerank\"\n\
        protocol = \"openrouter-rerank-v1\"\n\
        endpoint = \"https://api.example.invalid/v1/rerank\"\n\
        scope = \"remote\"\n\
        model = \"vendor-y/重排-乙\"\n\
        model_revision = \"rev-2\"\n\
        instruction = \"给定查询:\\n请评分\"\n\
        provider_only = \"vendor-b\"\n";

    /// A parsed, validated document.
    fn config(text: &str) -> ValidatedApiConfig {
        ApiConfig::parse_toml(text).expect("fixture config must validate")
    }

    /// One profile of a parsed document.
    fn profile_of(text: &str, id: &str) -> ValidatedProfile {
        config(text).profile(id).expect("fixture profile").clone()
    }

    /// The call identity of the named profile in `text`.
    fn call_identity(text: &str, id: &str) -> EndpointConfigIdentity {
        EndpointConfigIdentity::from_profile(&profile_of(text, id)).expect("fixture call identity")
    }

    /// A single-string edit of a document, asserting the needle occurs once.
    fn edited(text: &str, needle: &str, replacement: &str) -> String {
        let out = text.replace(needle, replacement);
        assert_ne!(out, text, "needle {needle} must occur once");
        out
    }

    /// The digest of the default embedding document with `needle` replaced.
    fn emb_digest_with(needle: &str, replacement: &str) -> String {
        call_identity(&edited(GOLD_EMB_DOC, needle, replacement), "emb").sha256()
    }

    // ---- golden bytes -------------------------------------------------------

    #[test]
    fn the_gold_digests_are_of_the_gold_literals() {
        // The digests are of the literal bytes above, so the constants cannot
        // drift apart without this failing. No code under test is involved.
        assert_eq!(
            hex::encode(Sha256::digest(GOLD_EMB_JSON.as_bytes())),
            GOLD_EMB_SHA256
        );
        assert_eq!(
            hex::encode(Sha256::digest(GOLD_RRK_JSON.as_bytes())),
            GOLD_RRK_SHA256
        );
        assert_eq!(
            hex::encode(Sha256::digest(GOLD_ROUTE_PRIMARY_JSON.as_bytes())),
            GOLD_ROUTE_PRIMARY_SHA256
        );
        assert_eq!(
            hex::encode(Sha256::digest(GOLD_ROUTE_JSON.as_bytes())),
            GOLD_ROUTE_SHA256
        );
        assert!(!GOLD_EMB_JSON.ends_with('\n'));
        assert!(!GOLD_RRK_JSON.ends_with('\n'));
        assert!(!GOLD_ROUTE_PRIMARY_JSON.ends_with('\n'));
        assert!(!GOLD_ROUTE_JSON.ends_with('\n'));
    }

    #[test]
    fn the_golden_embedding_encodes_to_its_bytes() {
        let identity = call_identity(GOLD_EMB_DOC, "emb");
        assert_eq!(
            String::from_utf8(identity.canonical_bytes()).expect("utf8"),
            GOLD_EMB_JSON
        );
        assert_eq!(identity.sha256(), GOLD_EMB_SHA256);
    }

    #[test]
    fn the_golden_rerank_encodes_to_its_bytes() {
        let identity = call_identity(GOLD_ROUTE_DOC, "rrk-cloud");
        assert_eq!(
            String::from_utf8(identity.canonical_bytes()).expect("utf8"),
            GOLD_RRK_JSON
        );
        assert_eq!(identity.sha256(), GOLD_RRK_SHA256);
    }

    #[test]
    fn the_golden_route_encodes_to_its_bytes() {
        let route = RerankRouteIdentity::from_config(&config(GOLD_ROUTE_DOC), "rrk-primary", false)
            .expect("gold route builds");
        assert_eq!(
            String::from_utf8(route.canonical_bytes()).expect("utf8"),
            GOLD_ROUTE_JSON
        );
        assert_eq!(route.sha256(), GOLD_ROUTE_SHA256);
    }

    // ---- single-endpoint: every mutable field moves the digest ---------------

    #[test]
    fn the_profile_id_does_not_enter_the_endpoint_digest() {
        // Renaming the profile leaves the call settings identical, so the
        // single-endpoint digest is unchanged.
        let renamed = edited(GOLD_EMB_DOC, "profiles.emb", "profiles.emb-renamed");
        assert_eq!(
            call_identity(&renamed, "emb-renamed").sha256(),
            GOLD_EMB_SHA256
        );
    }

    #[test]
    fn changing_the_endpoint_or_its_path_moves_the_digest() {
        // A new port moves the endpoint; the metadata endpoint must follow to the
        // same origin, which the config enforces, so move both together.
        let moved_port = edited(GOLD_EMB_DOC, "127.0.0.1:9100", "127.0.0.1:9101");
        assert_ne!(call_identity(&moved_port, "emb").sha256(), GOLD_EMB_SHA256);
        // A new path keeps the origin, so the metadata endpoint stays valid.
        assert_ne!(
            emb_digest_with(
                "http://127.0.0.1:9100/v1/embeddings",
                "http://127.0.0.1:9100/v1/embed"
            ),
            GOLD_EMB_SHA256,
            "path change must move the digest"
        );
    }

    #[test]
    fn changing_the_metadata_endpoint_moves_the_digest() {
        assert_ne!(
            emb_digest_with(
                "models_endpoint = \"http://127.0.0.1:9100/v1/models\"",
                "models_endpoint = \"http://127.0.0.1:9100/v1/meta\""
            ),
            GOLD_EMB_SHA256
        );
    }

    #[test]
    fn absent_and_present_metadata_endpoint_differ() {
        let without = edited(
            GOLD_EMB_DOC,
            "models_endpoint = \"http://127.0.0.1:9100/v1/models\"\n",
            "",
        );
        let identity = call_identity(&without, "emb");
        let text = String::from_utf8(identity.canonical_bytes()).expect("utf8");
        assert!(text.contains("\"models_endpoint\":null"));
        assert_ne!(identity.sha256(), GOLD_EMB_SHA256);
    }

    #[test]
    fn changing_the_model_or_revision_moves_the_digest() {
        assert_ne!(
            emb_digest_with("vendor-x/模型-甲", "vendor-x/模型-乙"),
            GOLD_EMB_SHA256
        );
        assert_ne!(emb_digest_with("rev-字", "rev-别"), GOLD_EMB_SHA256);
    }

    #[test]
    fn changing_the_aliases_moves_the_digest_and_order_matters() {
        assert_ne!(
            emb_digest_with(
                "response_model_aliases = [\"模型-甲\", \"alias-b\"]",
                "response_model_aliases = [\"模型-甲\", \"alias-c\"]"
            ),
            GOLD_EMB_SHA256
        );
        // The same two aliases in the other order are a different array.
        assert_ne!(
            emb_digest_with(
                "response_model_aliases = [\"模型-甲\", \"alias-b\"]",
                "response_model_aliases = [\"alias-b\", \"模型-甲\"]"
            ),
            GOLD_EMB_SHA256
        );
        assert_ne!(
            emb_digest_with(
                "response_model_aliases = [\"模型-甲\", \"alias-b\"]",
                "response_model_aliases = []"
            ),
            GOLD_EMB_SHA256
        );
    }

    #[test]
    fn changing_the_timeouts_or_response_budget_moves_the_digest() {
        assert_ne!(
            emb_digest_with("connect_timeout_ms = 1500", "connect_timeout_ms = 1600"),
            GOLD_EMB_SHA256
        );
        assert_ne!(
            emb_digest_with("timeout_ms = 45000", "timeout_ms = 46000"),
            GOLD_EMB_SHA256
        );
        assert_ne!(
            emb_digest_with(
                "max_response_bytes = 1048576",
                "max_response_bytes = 1048577"
            ),
            GOLD_EMB_SHA256
        );
    }

    #[test]
    fn changing_the_credential_variable_name_moves_the_digest() {
        assert_ne!(
            emb_digest_with(
                "api_key_env = \"CASS_TEST_KEY\"",
                "api_key_env = \"CASS_OTHER_KEY\""
            ),
            GOLD_EMB_SHA256
        );
    }

    #[test]
    fn only_the_credential_variable_name_is_stored() {
        // Only the name appears in the canonical bytes; the module reads no
        // environment variable, so no value can reach the digest. The golden
        // digest holds even though no variable named `CASS_TEST_KEY` is set.
        let identity = call_identity(GOLD_EMB_DOC, "emb");
        let text = String::from_utf8(identity.canonical_bytes()).expect("utf8");
        assert!(text.contains("\"api_key_env\":\"CASS_TEST_KEY\""));
        assert_eq!(identity.sha256(), GOLD_EMB_SHA256);
        assert!(!text.contains("Bearer"));
    }

    #[test]
    fn changing_the_send_model_flag_moves_the_digest() {
        // `send_model` defaults to true and an OpenRouter protocol requires it,
        // so exercise the flag on an OpenAI-protocol profile, where false is legal.
        let base = "version = 1\n\
            [profiles.emb]\n\
            kind = \"embedding\"\n\
            protocol = \"openai-embeddings-v1\"\n\
            endpoint = \"http://127.0.0.1:9100/v1/embeddings\"\n\
            scope = \"loopback\"\n\
            model = \"vendor-x/alpha\"\n\
            model_revision = \"rev-1\"\n\
            normalization = \"l2\"\n";
        let absent = call_identity(base, "emb");
        let explicit_true = call_identity(&format!("{base}send_model = true\n"), "emb");
        let explicit_false = call_identity(&format!("{base}send_model = false\n"), "emb");
        // Absent defaults to true, so it equals an explicit true.
        assert_eq!(absent.sha256(), explicit_true.sha256());
        assert_ne!(absent.sha256(), explicit_false.sha256());
        assert!(
            String::from_utf8(explicit_false.canonical_bytes())
                .expect("utf8")
                .contains("\"send_model\":false")
        );
    }

    #[test]
    fn changing_the_pinned_provider_moves_the_digest() {
        assert_ne!(
            emb_digest_with(
                "provider_only = \"vendor-a\"",
                "provider_only = \"vendor-z\""
            ),
            GOLD_EMB_SHA256
        );
    }

    #[test]
    fn changing_the_embedding_prefixed_or_batch_fields_moves_the_digest() {
        assert_ne!(
            emb_digest_with("query_prefix = \"查询:\\n\"", "query_prefix = \"查询:\\r\""),
            GOLD_EMB_SHA256
        );
        assert_ne!(
            emb_digest_with("document_prefix = \"\"", "document_prefix = \"文档\""),
            GOLD_EMB_SHA256
        );
        assert_ne!(
            emb_digest_with("max_batch = 32", "max_batch = 33"),
            GOLD_EMB_SHA256
        );
        assert_ne!(
            emb_digest_with("expected_dimension = 1024", "expected_dimension = 768"),
            GOLD_EMB_SHA256
        );
        assert_ne!(
            emb_digest_with("normalization = \"l2\"", "normalization = \"none\""),
            GOLD_EMB_SHA256
        );
    }

    #[test]
    fn an_empty_document_prefix_is_not_null() {
        // The embedding half always carries a string prefix, and `""` must
        // encode as an empty string, never as null.
        let identity = call_identity(GOLD_EMB_DOC, "emb");
        let text = String::from_utf8(identity.canonical_bytes()).expect("utf8");
        assert!(text.contains("\"document_prefix\":\"\""));
    }

    #[test]
    fn changing_the_request_dimensions_from_null_to_a_value_moves_the_digest() {
        let with = edited(
            GOLD_EMB_DOC,
            "expected_dimension = 1024",
            "expected_dimension = 1024\nrequest_dimensions = 1024\n",
        );
        let identity = call_identity(&with, "emb");
        assert!(
            String::from_utf8(identity.canonical_bytes())
                .expect("utf8")
                .contains("\"request_dimensions\":1024")
        );
        assert_ne!(identity.sha256(), GOLD_EMB_SHA256);
    }

    #[test]
    fn changing_the_kind_legal_protocol_moves_the_digest() {
        // openrouter-embeddings-v1 and openai-embeddings-v1 serve the same kind,
        // so this is a legal change that must move the digest, but provider_only
        // is only legal on an openrouter protocol, so drop it in the same edit.
        let mut text = edited(
            GOLD_EMB_DOC,
            "protocol = \"openrouter-embeddings-v1\"",
            "protocol = \"openai-embeddings-v1\"",
        );
        text = edited(&text, "provider_only = \"vendor-a\"\n", "");
        let identity = call_identity(&text, "emb");
        assert_eq!(identity.kind(), ProfileKind::Embedding);
        assert_ne!(identity.sha256(), GOLD_EMB_SHA256);
    }

    #[test]
    fn the_domain_and_version_are_fixed_constants_in_the_bytes() {
        let identity = call_identity(GOLD_EMB_DOC, "emb");
        let text = String::from_utf8(identity.canonical_bytes()).expect("utf8");
        assert!(text.contains("\"domain\":\"cass.api-call-config/1\""));
        assert!(text.contains("\"version\":1"));
        assert_eq!(CALL_CONFIG_VERSION, 1);
    }

    #[test]
    fn the_rerank_instruction_distinguishes_absent_from_empty() {
        let base = "version = 1\n\
            [profiles.r1]\n\
            kind = \"rerank\"\n\
            protocol = \"rerank-json-v1\"\n\
            endpoint = \"http://127.0.0.1:9200/v1/rerank\"\n\
            scope = \"loopback\"\n\
            model = \"vendor-y/r\"\n\
            model_revision = \"rev-2\"\n";
        let absent = call_identity(base, "r1");
        let empty = call_identity(&format!("{base}instruction = \"\"\n"), "r1");
        let present = call_identity(&format!("{base}instruction = \"x\"\n"), "r1");
        assert!(
            String::from_utf8(absent.canonical_bytes())
                .expect("utf8")
                .contains("\"instruction\":null")
        );
        assert!(
            String::from_utf8(empty.canonical_bytes())
                .expect("utf8")
                .contains("\"instruction\":\"\"")
        );
        assert_ne!(absent.sha256(), empty.sha256());
        assert_ne!(empty.sha256(), present.sha256());
    }

    #[test]
    fn a_rerank_profile_never_carries_the_embedding_half() {
        let identity = call_identity(GOLD_ROUTE_DOC, "rrk-cloud");
        let text = String::from_utf8(identity.canonical_bytes()).expect("utf8");
        assert!(text.contains("\"embedding\":null"));
        assert!(text.contains("\"rerank\":{"));
        assert_eq!(identity.kind(), ProfileKind::Rerank);
    }

    // ---- single-endpoint: consistency of a hand-edited profile --------------

    #[test]
    fn a_protocol_that_does_not_serve_the_kind_is_refused() {
        let mut profile = profile_of(GOLD_EMB_DOC, "emb");
        profile.protocol = ApiProtocol::RerankJsonV1;
        assert_eq!(
            EndpointConfigIdentity::from_profile(&profile)
                .unwrap_err()
                .code(),
            ConfigErrorCode::KindMismatch
        );
    }

    #[test]
    fn a_detail_that_does_not_match_the_kind_is_refused() {
        // `kind` says embedding but the detail is a rerank half a caller spliced
        // in by hand; the constructor must not trust the public fields.
        let mut profile = profile_of(GOLD_EMB_DOC, "emb");
        profile.detail = ProfileDetail::Rerank(RerankProfile {
            instruction: None,
            provider_only: None,
        });
        assert_eq!(
            EndpointConfigIdentity::from_profile(&profile)
                .unwrap_err()
                .code(),
            ConfigErrorCode::KindMismatch
        );
    }

    // ---- route --------------------------------------------------------------

    #[test]
    fn the_golden_route_binds_its_fallback_even_when_disabled() {
        let route = RerankRouteIdentity::from_config(&config(GOLD_ROUTE_DOC), "rrk-primary", false)
            .expect("route builds");
        assert!(!route.allow_fallback());
        assert_eq!(route.primary_profile(), "rrk-primary");
        assert_eq!(route.primary_config_sha256(), GOLD_ROUTE_PRIMARY_SHA256);
        assert_eq!(route.fallback_profile(), Some("rrk-cloud"));
        assert_eq!(route.fallback_config_sha256(), Some(GOLD_RRK_SHA256));
    }

    #[test]
    fn flipping_the_policy_flag_moves_the_route_digest() {
        let cfg = config(GOLD_ROUTE_DOC);
        let off = RerankRouteIdentity::from_config(&cfg, "rrk-primary", false).expect("route");
        let on = RerankRouteIdentity::from_config(&cfg, "rrk-primary", true).expect("route");
        assert_ne!(off.sha256(), on.sha256());
        // Only the flag differs; the bound fallback is identical.
        assert_eq!(off.fallback_config_sha256(), on.fallback_config_sha256());
    }

    #[test]
    fn a_different_primary_digest_moves_the_route_digest() {
        let cfg = config(GOLD_ROUTE_DOC);
        let base = RerankRouteIdentity::from_config(&cfg, "rrk-primary", false).expect("route");
        let moved = edited(
            GOLD_ROUTE_DOC,
            "http://127.0.0.1:9200/v1/rerank",
            "http://127.0.0.1:9201/v1/rerank",
        );
        let other =
            RerankRouteIdentity::from_config(&config(&moved), "rrk-primary", false).expect("route");
        assert_ne!(base.sha256(), other.sha256());
    }

    #[test]
    fn a_different_fallback_digest_moves_the_route_digest() {
        let cfg = config(GOLD_ROUTE_DOC);
        let base = RerankRouteIdentity::from_config(&cfg, "rrk-primary", false).expect("route");
        let moved = edited(
            GOLD_ROUTE_DOC,
            "https://api.example.invalid/v1/rerank",
            "https://api.example.invalid/v2/rerank",
        );
        let other =
            RerankRouteIdentity::from_config(&config(&moved), "rrk-primary", false).expect("route");
        assert_ne!(base.sha256(), other.sha256());
        // Only the fallback moved; the primary digest is unchanged.
        assert_eq!(base.primary_config_sha256(), other.primary_config_sha256());
        assert_ne!(
            base.fallback_config_sha256(),
            other.fallback_config_sha256()
        );
    }

    #[test]
    fn a_renamed_fallback_moves_the_route_digest_though_its_settings_are_identical() {
        // The fallback's call settings are byte-identical, but the route names a
        // different id, so the route digest moves: the id is part of the route.
        let renamed = edited(GOLD_ROUTE_DOC, "profiles.rrk-cloud", "profiles.rrk-cloud-2");
        let renamed = edited(
            &renamed,
            "fallback_profile = \"rrk-cloud\"",
            "fallback_profile = \"rrk-cloud-2\"",
        );
        let base = RerankRouteIdentity::from_config(&config(GOLD_ROUTE_DOC), "rrk-primary", false)
            .expect("route");
        let other = RerankRouteIdentity::from_config(&config(&renamed), "rrk-primary", false)
            .expect("route");
        assert_eq!(
            base.fallback_config_sha256(),
            other.fallback_config_sha256()
        );
        assert_eq!(other.fallback_profile(), Some("rrk-cloud-2"));
        assert_ne!(base.sha256(), other.sha256());
    }

    #[test]
    fn a_renamed_profile_moves_the_route_digest_but_not_the_endpoint_digest() {
        let renamed = edited(
            GOLD_ROUTE_DOC,
            "profiles.rrk-primary",
            "profiles.rrk-renamed",
        );
        // The endpoint digest of the renamed profile is unchanged.
        assert_eq!(
            call_identity(&renamed, "rrk-renamed").sha256(),
            GOLD_ROUTE_PRIMARY_SHA256
        );
        // The route now names a different primary id, so its digest moves.
        let base = RerankRouteIdentity::from_config(&config(GOLD_ROUTE_DOC), "rrk-primary", false)
            .expect("route");
        let other = RerankRouteIdentity::from_config(&config(&renamed), "rrk-renamed", false)
            .expect("route");
        assert_eq!(base.primary_config_sha256(), other.primary_config_sha256());
        assert_ne!(base.sha256(), other.sha256());
    }

    #[test]
    fn an_unconfigured_fallback_stays_null_and_is_never_guessed() {
        let no_fallback = "version = 1\n\
            [profiles.rrk-only]\n\
            kind = \"rerank\"\n\
            protocol = \"rerank-json-v1\"\n\
            endpoint = \"http://127.0.0.1:9200/v1/rerank\"\n\
            scope = \"loopback\"\n\
            model = \"vendor-y/重排-乙\"\n\
            model_revision = \"rev-2\"\n\
            instruction = \"给定查询:\\n请评分\"\n\
            [profiles.some-remote]\n\
            kind = \"rerank\"\n\
            protocol = \"openrouter-rerank-v1\"\n\
            endpoint = \"https://api.example.invalid/v1/rerank\"\n\
            scope = \"remote\"\n\
            model = \"vendor-y/重排-乙\"\n\
            model_revision = \"rev-2\"\n\
            instruction = \"给定查询:\\n请评分\"\n\
            provider_only = \"vendor-b\"\n";
        // A remote profile exists in the document but the primary names no
        // fallback, so the route must not adopt it even with the flag true.
        let route = RerankRouteIdentity::from_config(&config(no_fallback), "rrk-only", true)
            .expect("route builds");
        assert!(route.allow_fallback());
        assert_eq!(route.fallback_profile(), None);
        assert_eq!(route.fallback_config_sha256(), None);
        let text = String::from_utf8(route.canonical_bytes()).expect("utf8");
        assert!(text.contains("\"fallback_profile\":null"));
        assert!(text.contains("\"fallback_config_sha256\":null"));
        assert!(text.contains("\"allow_fallback\":true"));
    }

    #[test]
    fn an_unknown_primary_profile_is_refused() {
        let err =
            RerankRouteIdentity::from_config(&config(GOLD_ROUTE_DOC), "nope", false).unwrap_err();
        assert_eq!(err.code(), ConfigErrorCode::InvalidReference);
    }

    #[test]
    fn an_embedding_primary_is_refused() {
        // The route constructor must not accept an embedding profile disguised
        // as a rerank primary.
        let doc = format!(
            "{GOLD_ROUTE_DOC}\
             [profiles.emb]\n\
             kind = \"embedding\"\n\
             protocol = \"openai-embeddings-v1\"\n\
             endpoint = \"http://127.0.0.1:9100/v1/embeddings\"\n\
             scope = \"loopback\"\n\
             model = \"vendor-x/alpha\"\n\
             model_revision = \"rev-1\"\n\
             normalization = \"l2\"\n"
        );
        let err = RerankRouteIdentity::from_config(&config(&doc), "emb", false).unwrap_err();
        assert_eq!(err.code(), ConfigErrorCode::KindMismatch);
    }

    #[test]
    fn the_parser_refuses_a_dangling_fallback_before_the_constructor_sees_it() {
        // The route constructor re-checks a dangling target as a second line,
        // but a `ValidatedApiConfig` cannot be hand-built from outside (its map
        // is private), so the reachable proof that a dangling target never
        // reaches the route is the parser refusing the document.
        let dangling = edited(
            GOLD_ROUTE_DOC,
            "fallback_profile = \"rrk-cloud\"",
            "fallback_profile = \"ghost\"",
        );
        let err = ApiConfig::parse_toml(&dangling).unwrap_err();
        assert_eq!(err.code(), ConfigErrorCode::InvalidReference);
    }

    #[test]
    fn the_parser_refuses_a_self_referential_fallback() {
        let selfish = edited(
            GOLD_ROUTE_DOC,
            "fallback_profile = \"rrk-cloud\"",
            "fallback_profile = \"rrk-primary\"",
        );
        let err = ApiConfig::parse_toml(&selfish).unwrap_err();
        assert_eq!(err.code(), ConfigErrorCode::InvalidFallback);
    }

    #[test]
    fn the_parser_refuses_a_recursive_fallback() {
        // Make the remote target declare a fallback of its own, which the
        // one-hop rule forbids.
        let recursive = format!(
            "{GOLD_ROUTE_DOC}\
             fallback_profile = \"rrk-primary\"\n"
        );
        let err = ApiConfig::parse_toml(&recursive).unwrap_err();
        assert_eq!(err.code(), ConfigErrorCode::InvalidFallback);
    }

    // ---- separation from the representation identity ------------------------

    #[test]
    fn a_relocated_endpoint_moves_the_call_digest_but_not_the_descriptor() {
        let moved = edited(GOLD_EMB_DOC, "127.0.0.1:9100", "127.0.0.1:9199");
        let before_call = call_identity(GOLD_EMB_DOC, "emb");
        let after_call = call_identity(&moved, "emb");
        assert_ne!(before_call.sha256(), after_call.sha256());

        let before_desc =
            RepresentationDescriptor::from_profile(&profile_of(GOLD_EMB_DOC, "emb"), 1024)
                .expect("descriptor");
        let after_desc = RepresentationDescriptor::from_profile(&profile_of(&moved, "emb"), 1024)
            .expect("descriptor");
        assert_eq!(before_desc.sha256(), after_desc.sha256());
        assert!(before_desc.is_equivalent_to(&after_desc));
    }

    #[test]
    fn a_credential_name_change_is_not_claimed_to_be_a_value_rotation() {
        // Changing the variable *name* moves the call digest; the ticket makes
        // no claim that rotating the value under one name does, and no value is
        // ever read, so the two are not equated here.
        let renamed = edited(
            GOLD_EMB_DOC,
            "api_key_env = \"CASS_TEST_KEY\"",
            "api_key_env = \"CASS_ROTATED_KEY\"",
        );
        assert_ne!(call_identity(&renamed, "emb").sha256(), GOLD_EMB_SHA256);
        assert!(
            String::from_utf8(call_identity(&renamed, "emb").canonical_bytes())
                .expect("utf8")
                .contains("\"api_key_env\":\"CASS_ROTATED_KEY\"")
        );
    }

    #[test]
    fn the_compatibility_evidence_path_does_not_enter_the_endpoint_digest() {
        // Two primary profiles that differ only in the evidence path they point
        // at, with every call field identical, hash the same: the evidence file
        // belongs to the fallback relation, and folding it in would self-reference.
        let base = "version = 1\n\
            [profiles.emb]\n\
            kind = \"embedding\"\n\
            protocol = \"openai-embeddings-v1\"\n\
            endpoint = \"http://127.0.0.1:9100/v1/embeddings\"\n\
            scope = \"loopback\"\n\
            model = \"vendor-x/alpha\"\n\
            model_revision = \"rev-1\"\n\
            normalization = \"l2\"\n";
        let with_a = call_identity(
            &format!(
                "{base}fallback_profile = \"cloud\"\nfallback_compatibility_file = \"/a.json\"\n{CLOUD}"
            ),
            "emb",
        );
        let with_b = call_identity(
            &format!(
                "{base}fallback_profile = \"cloud\"\nfallback_compatibility_file = \"/b.json\"\n{CLOUD}"
            ),
            "emb",
        );
        assert_eq!(with_a.sha256(), with_b.sha256());
    }

    /// A remote cloud embedding profile that makes the evidence-path document
    /// above validate.
    const CLOUD: &str = "[profiles.cloud]\n\
        kind = \"embedding\"\n\
        protocol = \"openrouter-embeddings-v1\"\n\
        endpoint = \"https://api.example.invalid/v1/embeddings\"\n\
        scope = \"remote\"\n\
        model = \"vendor-x/alpha\"\n\
        model_revision = \"rev-1\"\n\
        normalization = \"l2\"\n\
        provider_only = \"vendor-a\"\n";

    #[test]
    fn canonical_bytes_have_no_trailing_newline_and_are_utf8() {
        for bytes in [
            call_identity(GOLD_EMB_DOC, "emb").canonical_bytes(),
            call_identity(GOLD_ROUTE_DOC, "rrk-cloud").canonical_bytes(),
            RerankRouteIdentity::from_config(&config(GOLD_ROUTE_DOC), "rrk-primary", false)
                .expect("route")
                .canonical_bytes(),
        ] {
            assert!(!bytes.ends_with(b"\n"));
            assert!(std::str::from_utf8(&bytes).is_ok());
        }
    }
}
