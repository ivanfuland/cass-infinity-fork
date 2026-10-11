//! The single cloud-fallback admission rule.
//!
//! A rerank call may make at most **one** extra attempt, and only against the
//! one fallback profile its primary declares. This module owns the whole
//! decision, so the client never re-derives it:
//!
//! * the failure must be in the closed allowed set — a connection refusal, an
//!   unreachable network, an interrupted connection, a connect or read timeout,
//!   or one of six HTTP statuses;
//! * the caller must not have disabled fallback for this call;
//! * the primary must be a loopback profile that actually declares a fallback;
//! * the fallback must be a same-kind profile, and must not declare a fallback
//!   of its own.
//!
//! Everything else — another 4xx or 5xx, a redirect, a TLS, identity, dimension
//! or response-structure failure, a configuration error, a cancellation — never
//! triggers a cloud attempt. An unclassifiable transport problem is deliberately
//! on the "no fallback" side.

use super::config::{EndpointScope, ProfileKind, ValidatedApiConfig, ValidatedProfile};
use crate::search::rerank::http::TransportFailure;

/// The six HTTP statuses that permit one cloud attempt.
pub const FALLBACK_HTTP_STATUSES: [u16; 6] = [408, 429, 500, 502, 503, 504];

/// Whether one failed attempt permits a single retry against the fallback.
///
/// This answers only the failure half of the decision. Whether a fallback exists
/// at all, and whether this call is allowed to use it, are separate questions
/// answered by [`fallback_target`] and the caller's `--no-model-fallback`
/// option.
pub fn allows_cloud_fallback(failure: TransportFailure) -> bool {
    match failure {
        TransportFailure::Timeout
        | TransportFailure::ConnectionRefused
        | TransportFailure::ConnectionInterrupted
        | TransportFailure::NetworkUnavailable => true,
        TransportFailure::HttpStatus(status) => FALLBACK_HTTP_STATUSES.contains(&status),
        TransportFailure::InvalidInput
        | TransportFailure::InvalidResponse
        | TransportFailure::UnclassifiedTransport => false,
    }
}

/// The profile this call may fall back to, or `None` when there is no fallback.
///
/// `requested` is the caller's `allow_fallback` option; when it is false the
/// answer is `None` even for a profile that declares a fallback, so a call that
/// disabled fallback never takes the second path.
pub fn fallback_target<'a>(
    config: &'a ValidatedApiConfig,
    primary: &'a ValidatedProfile,
    requested: bool,
) -> Option<&'a ValidatedProfile> {
    if !requested {
        return None;
    }
    if primary.scope != EndpointScope::Loopback {
        return None;
    }
    let fallback_id = primary.fallback_profile.as_deref()?;
    let fallback = config.profile(fallback_id)?;
    // The configuration kernel already refuses these shapes; re-checking keeps
    // the routing decision total even if a future caller builds a profile set by
    // another path.
    if fallback.id == primary.id || fallback.kind != primary.kind {
        return None;
    }
    if fallback.fallback_profile.is_some() {
        return None;
    }
    if fallback.scope != EndpointScope::Remote {
        return None;
    }
    if primary.kind == ProfileKind::Embedding {
        // A configured path is not evidence, and the numeric admission gate of
        // spec §6.4 is a later ticket's job. Until that gate exists this kernel
        // never routes an embedding batch across endpoints, so an embedding
        // profile has no fallback target here even when one is configured.
        return None;
    }
    Some(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
version = 1
default_rerank = "local"

[profiles.local]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "http://127.0.0.1:18002/score"
scope = "loopback"
model = "local-reranker"
model_revision = "rev-local"
fallback_profile = "cloud"

[profiles.cloud]
kind = "rerank"
protocol = "openrouter-rerank-v1"
endpoint = "https://example.invalid/api/v1/rerank"
scope = "remote"
model = "cloud-reranker"
model_revision = "rev-cloud"
provider_only = "pinned-vendor"
"#;

    fn parsed() -> ValidatedApiConfig {
        crate::search::model_api::config::ApiConfig::parse_toml(CONFIG).expect("config")
    }

    #[test]
    fn only_the_closed_failure_set_allows_fallback() {
        for allowed in [
            TransportFailure::Timeout,
            TransportFailure::ConnectionRefused,
            TransportFailure::ConnectionInterrupted,
            TransportFailure::NetworkUnavailable,
        ] {
            assert!(allows_cloud_fallback(allowed), "{allowed:?}");
        }
        for status in FALLBACK_HTTP_STATUSES {
            assert!(allows_cloud_fallback(TransportFailure::HttpStatus(status)));
        }
        for refused in [
            TransportFailure::HttpStatus(400),
            TransportFailure::HttpStatus(401),
            TransportFailure::HttpStatus(403),
            TransportFailure::HttpStatus(404),
            TransportFailure::HttpStatus(501),
            TransportFailure::HttpStatus(507),
            TransportFailure::HttpStatus(302),
            TransportFailure::HttpStatus(599),
            TransportFailure::InvalidInput,
            TransportFailure::InvalidResponse,
            TransportFailure::UnclassifiedTransport,
        ] {
            assert!(!allows_cloud_fallback(refused), "{refused:?}");
        }
    }

    #[test]
    fn fallback_target_requires_the_caller_option() {
        let config = parsed();
        let primary = config.profile("local").expect("primary");
        assert!(fallback_target(&config, primary, true).is_some());
        assert!(fallback_target(&config, primary, false).is_none());
    }

    #[test]
    fn a_profile_without_fallback_has_no_target() {
        let config = parsed();
        let cloud = config.profile("cloud").expect("cloud");
        assert!(fallback_target(&config, cloud, true).is_none());
    }

    #[test]
    fn an_embedding_fallback_without_evidence_is_not_a_target() {
        let text = r#"
version = 1
[profiles.local]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "http://127.0.0.1:8000/v1/embeddings"
scope = "loopback"
model = "local-embed"
model_revision = "rev-local"
normalization = "l2"
fallback_profile = "cloud"

[profiles.cloud]
kind = "embedding"
protocol = "openrouter-embeddings-v1"
endpoint = "https://example.invalid/v1/embeddings"
scope = "remote"
model = "cloud-embed"
model_revision = "rev-cloud"
normalization = "l2"
provider_only = "pinned-vendor"
"#;
        let config = crate::search::model_api::config::ApiConfig::parse_toml(text).expect("config");
        let primary = config.profile("local").expect("primary");
        assert!(fallback_target(&config, primary, true).is_none());
    }
}
