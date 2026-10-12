//! Adapt the API call into the existing complete-window ranking result.
use super::{ApiClient, ApiCallErrorCode, RerankOptions};
use crate::search::rerank::{types::{CallIdentity, RerankResponse, RerankError, RerankFailureReason},
    window::{ApiWindowAttempt, ApiWindowRerank}};

pub fn score(client: &ApiClient, profile: &str, query: &str, documents: &[String],
    allow_fallback: bool, evidence: &mut Option<ApiWindowRerank>) -> Result<RerankResponse, RerankError> {
    match client.rerank_with_fallback(profile, query, documents, RerankOptions::with_fallback(allow_fallback)) {
        Ok(outcome) => {
            let requests = outcome.attempts.iter().filter(|a| a.network_attempted).count();
            let duration_ms = outcome.attempts.iter().map(|a| a.duration_ms).sum();
            *evidence = Some(ApiWindowRerank {
                primary_profile: profile.to_owned(), realized_profile: Some(outcome.realized_profile),
                fallback_used: outcome.fallback_used, fallback_reason: outcome.fallback_reason.map(str::to_owned),
                attempts: outcome.attempts.iter().map(ApiWindowAttempt::from).collect(),
            });
            Ok(RerankResponse { scores: outcome.scores, http_requests: requests, duration_ms,
                identity: CallIdentity { actual_provider: None, actual_model: outcome.identity.response_model,
                    serving_provider: outcome.identity.provider } })
        }
        Err(failure) => {
            *evidence = Some(ApiWindowRerank {
                primary_profile: profile.to_owned(), realized_profile: None, fallback_used: false,
                fallback_reason: (failure.attempts().len() > 1).then(|| failure.attempts()[0].error_code.map(str::to_owned)).flatten(),
                attempts: failure.attempts().iter().map(ApiWindowAttempt::from).collect(),
            });
            let reason = match failure.error().code() {
                ApiCallErrorCode::MissingCredentials => RerankFailureReason::MissingCredentials,
                ApiCallErrorCode::Transport => RerankFailureReason::TransportError,
                ApiCallErrorCode::HttpStatus => RerankFailureReason::HttpError,
                ApiCallErrorCode::IdentityMismatch => RerankFailureReason::ModelIdentityMismatch,
                ApiCallErrorCode::InvalidResponse | ApiCallErrorCode::DimensionMismatch => RerankFailureReason::InvalidResponse,
                _ => RerankFailureReason::InvalidInput,
            };
            Err(RerankError { reason, http_status: failure.error().http_status() })
        }
    }
}
