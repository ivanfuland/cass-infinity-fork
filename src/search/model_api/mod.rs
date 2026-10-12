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
//! * [`identity`] — the versioned representation descriptor and the record that
//!   pins one to an embedding generation, still pure: a codec, with no
//!   database, no file and no caller.
//! * [`call_identity`] — the call-configuration digest of one endpoint and the
//!   digest of one rerank route, still pure: what a rerank window or a
//!   provenance record binds to say *how* a service was called, kept apart from
//!   the representation identity that says which vectors may meet.
//! * [`routing`] — the single cloud-fallback admission rule.
//! * [`primary_embedding`] — the primary-endpoint embedding driver the DB vector
//!   catch-up loop consumes: one fresh probe (its own POSTs, counted apart from
//!   document batches), a `max_batch`-split document embed with per-request call
//!   evidence, and the typed cloud-eligibility answer.
//! * [`client`] — [`ApiClient`], the blocking client that ties a frozen
//!   configuration, the transport and the routing rule together.
//! * [`runtime`] — the edge a command uses: the configuration file, the process
//!   environment and the profile selector, plus the `models list` / `models
//!   check` report shapes.
//! * [`test_support`] — loopback HTTP and TLS fixtures, `cfg(test)` only.
//!
//! The client is a kernel: it reads no production configuration itself and
//! never deploys or starts a service. [`runtime`] is its only production
//! caller, and it only loads a configuration the operator named.

pub mod call_identity;
pub mod client;
pub mod config;
pub(crate) mod compatibility;
pub mod error;
pub mod identity;
pub mod primary_embedding;
pub mod protocol;
pub mod query_embedding;
pub mod rerank_call;
pub mod routing;
pub mod runtime;

#[cfg(test)]
pub mod test_support;

pub use call_identity::{
    CALL_CONFIG_DOMAIN, CALL_CONFIG_VERSION, EndpointConfigIdentity, RERANK_ROUTE_DOMAIN,
    RERANK_ROUTE_VERSION, RerankRouteIdentity,
};
pub use client::{
    ApiAttempt, ApiCallFailure, ApiClient, AttemptStage, CredentialResolver, EmbedOutcome,
    ProbeOutcome, RequestedIdentity, RerankOptions, RerankOutcome,
};
pub use config::{
    ApiConfig, ApiProtocol, EmbeddingProfile, EndpointScope, Normalization, ProfileDetail,
    ProfileKind, RerankProfile, ValidatedApiConfig, ValidatedEndpoint, ValidatedProfile,
};
pub use error::{ApiCallError, ApiCallErrorCode, ConfigError, ConfigErrorCode};
pub use identity::{
    IdentityError, IdentityErrorCode, REPRESENTATION_DOMAIN, REPRESENTATION_RECORD_VERSION,
    RepresentationDescriptor, RepresentationRecord,
};
pub use primary_embedding::{
    API_PROBE_SENTINELS, DIMENSION_DRIFT_CODE, EmbeddingCallEvidence, ModelApiBackfillReport,
    PrimaryEmbedFailure, PrimaryEmbeddingCall, ProbeMeasurement,
};
pub use protocol::{EmbeddingReply, InputKind, ObservedIdentity, RerankReply, Usage};
pub use routing::{allows_cloud_fallback, fallback_target};
pub use runtime::{
    CHECK_SCHEMA, EnvCredentialResolver, LIST_SCHEMA, ProfileListing, RuntimeError,
    RuntimeErrorKind,
};
