//! Query-only API adapter. The database supplies the frozen representation;
//! constructing this adapter does not send a probe or infer a model identity.
use std::sync::{Arc, Mutex};

use super::{ApiAttempt, ApiClient, InputKind, ValidatedProfile};
use super::routing::failure_allows_cloud_fallback;
use crate::search::embedder::{Embedder, EmbedderError, EmbedderResult, ModelCategory};
use crate::storage::api::{StorageError, Tx};
use crate::storage::api_generation::{VerifiedPrimaryGeneration, open_api_generation};

#[derive(Debug, thiserror::Error)]
#[error("API generation is absent or not audited")]
pub struct QueryGenerationUnavailable;

/// Identity checked again in the transaction that reads candidate vectors.
#[derive(Clone)]
pub struct QueryGenerationBinding {
    profile: ValidatedProfile,
    generation_id: i64,
    embedder_id: String,
    dimension: usize,
}

impl QueryGenerationBinding {
    pub fn open(tx: &Tx, profile: ValidatedProfile) -> Result<Option<Self>, StorageError> {
        let Some(id) = tx.query_opt_map(
            "SELECT id FROM embedding_generations WHERE is_active = 1 AND audit_status = 'passed'",
            &[], |row| row.get_typed::<i64>(0),
        )? else { return Ok(None); };
        let verified = open_api_generation(tx, id, &profile).map_err(StorageError::from)?;
        Self::from_verified(profile, verified).map(Some)
    }

    fn from_verified(profile: ValidatedProfile, verified: VerifiedPrimaryGeneration) -> Result<Self, StorageError> {
        Ok(Self {
            profile,
            generation_id: verified.generation_id(),
            embedder_id: verified.embedder_id(),
            dimension: usize::try_from(verified.descriptor().effective_dimension())
                .map_err(|_| unavailable("API dimension is out of range"))?,
        })
    }

    pub fn verify_active(&self, tx: &Tx) -> Result<(), StorageError> {
        self.verify(tx, self.generation_id)
    }

    pub fn verify(&self, tx: &Tx, generation_id: i64) -> Result<(), StorageError> {
        if generation_id != self.generation_id {
            return Err(unavailable("API generation changed during query"));
        }
        let current = open_api_generation(tx, generation_id, &self.profile)
            .map_err(StorageError::from)?;
        if current.embedder_id() != self.embedder_id {
            return Err(unavailable("API representation changed during query"));
        }
        let passed = tx.query_row_map(
            "SELECT is_active = 1 AND audit_status = 'passed' FROM embedding_generations WHERE id = ?1",
            &crate::storage::api::params![generation_id], |row| row.get_typed::<i64>(0),
        )?;
        if passed != 1 { return Err(unavailable("API generation is not active and audited")); }
        Ok(())
    }
}

fn unavailable(detail: &str) -> StorageError {
    StorageError::Other { code: None, detail: detail.to_owned() }
}

/// Typed policy survives the embedding error chain; message text never decides
/// whether a query may degrade to lexical results.
#[derive(Debug, thiserror::Error)]
#[error("{code}")]
pub struct QueryApiFailure {
    pub code: &'static str,
    pub allow_lexical: bool,
}

/// Only search constructs this adapter; document embedding has its own driver.
pub struct ApiQueryEmbedder {
    client: Arc<ApiClient>,
    binding: QueryGenerationBinding,
    allow_fallback: bool,
    attempts: Mutex<Vec<ApiAttempt>>,
}

impl ApiQueryEmbedder {
    pub fn new(client: Arc<ApiClient>, binding: QueryGenerationBinding, allow_fallback: bool) -> Result<Self, StorageError> {
        let configured = client.config().profile(&binding.profile.id)
            .ok_or_else(|| unavailable("API query profile is missing"))?;
        if super::EndpointConfigIdentity::from_profile(configured)
            .map_err(|_| unavailable("Invalid API query profile"))?.sha256()
            != super::EndpointConfigIdentity::from_profile(&binding.profile)
                .map_err(|_| unavailable("Invalid bound API profile"))?.sha256() {
            return Err(unavailable("API query profile differs from verified generation"));
        }
        Ok(Self { client, binding, allow_fallback, attempts: Mutex::new(Vec::new()) })
    }

    pub fn attempts(&self) -> Vec<ApiAttempt> {
        self.attempts.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn failure(&self, code: &'static str, allow_lexical: bool) -> EmbedderError {
        EmbedderError::EmbeddingFailed {
            model: self.binding.embedder_id.clone(),
            source: Box::new(QueryApiFailure { code, allow_lexical }),
        }
    }
}

impl Embedder for ApiQueryEmbedder {
    fn embed_sync(&self, text: &str) -> EmbedderResult<Vec<f32>> {
        let profile = &self.binding.profile;
        match self.client.embed_once(&profile.id, &[text.to_owned()], InputKind::Query) {
            Ok(mut outcome) => {
                let wrong_dimension = outcome.dimension != self.binding.dimension;
                if wrong_dimension {
                    if let Some(attempt) = outcome.attempts.last_mut() {
                        attempt.error_code = Some("DimensionMismatch");
                    }
                }
                self.attempts.lock().unwrap_or_else(|p| p.into_inner()).extend(outcome.attempts);
                if wrong_dimension {
                    return Err(self.failure("DimensionMismatch", false));
                }
                outcome.vectors.pop().ok_or_else(|| self.failure("InvalidResponse", false))
            }
            Err(failure) => {
                self.attempts.lock().unwrap_or_else(|p| p.into_inner()).extend_from_slice(failure.attempts());
                let needs_proof = self.allow_fallback && profile.fallback_profile.is_some()
                    && failure_allows_cloud_fallback(&failure);
                Err(self.failure(if needs_proof { "CompatibilityRequired" } else { failure.error().code().as_str() },
                    !needs_proof && failure_allows_cloud_fallback(&failure)))
            }
        }
    }
    fn dimension(&self) -> usize { self.binding.dimension }
    fn id(&self) -> &str { &self.binding.embedder_id }
    fn is_semantic(&self) -> bool { true }
    fn category(&self) -> ModelCategory { ModelCategory::ApiEmbedder }
}
