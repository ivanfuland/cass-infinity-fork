//! The model-service API boundary: configuration, protocols and identity.
//!
//! CASS calls its embedding and rerank models over explicit HTTP/HTTPS
//! endpoints that the operator configures. This module family owns that
//! boundary. It has no local inference path, downloads no weights and hard-codes
//! no model name, endpoint or dimension.
//!
//! The tree is layered, and each layer only consumes the one below it:
//!
//! * [`config`] — the pure TOML reader. [`ApiConfig::parse_toml`] turns text into
//!   a validated [`ValidatedApiConfig`] with no I/O, no environment access and
//!   no side effects.
//! * [`error`] — the closed [`ConfigErrorCode`] set a rejection uses, plus the
//!   call-time [`ApiCallErrorCode`] set.
//! * [`protocol`] — the four message shapes: request builders and response
//!   validators, still pure.
//! * [`routing`] — the single cloud-fallback admission rule.
//! * [`client`] — [`ApiClient`], the blocking client that ties a frozen
//!   configuration, the transport and the routing rule together.
//! * [`test_support`] — loopback HTTP and TLS fixtures, `cfg(test)` only.
//!
//! The client is a kernel: it registers no production caller, reads no
//! production configuration and never deploys or starts a service.

pub mod client;
pub mod config;
pub mod error;
pub mod protocol;
pub mod routing;

#[cfg(test)]
pub mod test_support;

pub use client::{
    ApiAttempt, ApiCallFailure, ApiClient, AttemptStage, CredentialResolver, EmbedOutcome,
    EnvCredentialResolver, ProbeOutcome, RequestedIdentity, RerankOptions, RerankOutcome,
};
pub use config::{
    ApiConfig, ApiProtocol, EmbeddingProfile, EndpointScope, Normalization, ProfileDetail,
    ProfileKind, RerankProfile, ValidatedApiConfig, ValidatedEndpoint, ValidatedProfile,
};
pub use error::{ApiCallError, ApiCallErrorCode, ConfigError, ConfigErrorCode};
pub use protocol::{EmbeddingReply, InputKind, ObservedIdentity, RerankReply, Usage};
pub use routing::{allows_cloud_fallback, fallback_target};
