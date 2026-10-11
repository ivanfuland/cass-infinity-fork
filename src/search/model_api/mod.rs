//! The model-service API boundary: configuration, protocols and identity.
//!
//! CASS calls its embedding and rerank models over explicit HTTP/HTTPS
//! endpoints that the operator configures. This module family owns that
//! boundary. It has no local inference path, downloads no weights and hard-codes
//! no model name, endpoint or dimension.
//!
//! Today this tree contains the **configuration kernel** only:
//!
//! * [`config`] — the pure TOML reader. [`ApiConfig::parse_toml`] turns text into
//!   a validated [`ValidatedApiConfig`] with no I/O, no environment access and
//!   no side effects.
//! * [`error`] — the closed set of [`ConfigErrorCode`] values a rejection uses.
//!
//! The transport, the profile selection and the vector-generation identity are
//! later tickets; they consume the types defined here rather than re-deriving
//! them.

pub mod config;
pub mod error;

pub use config::{
    ApiConfig, ApiProtocol, EmbeddingProfile, EndpointScope, Normalization, ProfileDetail,
    ProfileKind, RerankProfile, ValidatedApiConfig, ValidatedEndpoint, ValidatedProfile,
};
pub use error::{ConfigError, ConfigErrorCode};
