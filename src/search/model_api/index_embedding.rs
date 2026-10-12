//! Frozen embedding configuration shared by indexing and watch cycles.
use std::path::Path;
use super::{ApiClient, EnvCredentialResolver, PrimaryEmbeddingCall, ProfileKind, ValidatedApiConfig};
use super::embedding_route::EmbeddingRoute;
use super::runtime::{self, RuntimeError};

/// One indexing command's model configuration and admitted route.
#[derive(Clone, Debug)]
pub struct IndexEmbeddingSetup {
    config: ValidatedApiConfig,
    route: EmbeddingRoute,
}

impl IndexEmbeddingSetup {
    /// Load explicit configuration once, without sending a model request.
    pub fn load(path: Option<&Path>, profile: Option<&str>, allow_fallback: bool) -> Result<Self, RuntimeError> {
        runtime::ensure_no_retired_model_env(|key| std::env::var_os(key))?;
        let config = runtime::load_config(path, |key| std::env::var_os(key))?;
        let id = profile.or_else(|| config.default_profile_id(ProfileKind::Embedding))
            .ok_or_else(|| RuntimeError::configuration("no embedding API profile is selected", None))?;
        let selected = runtime::profile_by_id(&config, id)?;
        if selected.kind != ProfileKind::Embedding {
            return Err(RuntimeError::configuration("selected API profile is not an embedder", None));
        }
        let route = EmbeddingRoute::load(&config, selected, allow_fallback);
        Ok(Self { config, route })
    }

    /// Selected profile ID for progress reporting.
    pub fn profile_id(&self) -> &str { &self.route.primary.id }

    /// Complete route identity for idempotency and immutable command binding.
    pub fn identity_sha256(&self) -> String { self.route.identity_sha256() }

    pub(crate) fn bind_search(&self, client: &crate::search::query::SearchClient)
        -> anyhow::Result<std::sync::Arc<super::query_embedding::ApiQueryEmbedder>> {
        client.set_api_frozen_semantic_context(std::sync::Arc::new(ApiClient::new(
            self.config.clone(), Box::new(EnvCredentialResolver))), self.route.clone())
    }

    pub(crate) fn call(&self) -> Result<PrimaryEmbeddingCall, super::ConfigError> {
        PrimaryEmbeddingCall::from_frozen_route(
            ApiClient::new(self.config.clone(), Box::new(EnvCredentialResolver)), self.route.clone())
    }
}
