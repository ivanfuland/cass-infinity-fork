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
                ApiCallErrorCode::Transport => match super::routing::transport_failure_of(
                    failure.error().code(), failure.error().http_status(), failure.error().transport_code()) {
                    Some(crate::search::rerank::http::TransportFailure::Timeout) => RerankFailureReason::Timeout,
                    _ => RerankFailureReason::TransportError,
                },
                ApiCallErrorCode::HttpStatus => RerankFailureReason::HttpError,
                ApiCallErrorCode::IdentityMismatch => RerankFailureReason::ModelIdentityMismatch,
                ApiCallErrorCode::InvalidResponse | ApiCallErrorCode::DimensionMismatch => RerankFailureReason::InvalidResponse,
                _ => RerankFailureReason::InvalidInput,
            };
            Err(RerankError { reason, http_status: failure.error().http_status() })
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::search::model_api::{ApiConfig, CredentialResolver};
    use crate::search::model_api::test_support::{HttpFixture, TlsFixture, Reply};
    use serde_json::json;

    struct NoCredentials;
    impl CredentialResolver for NoCredentials {
        fn resolve(&self, _: &str) -> Option<String> { None }
    }

    fn client(local: &HttpFixture, cloud: &TlsFixture) -> ApiClient {
        let text = format!(r#"
version=1
[profiles.local]
kind="rerank"
protocol="rerank-json-v1"
scope="loopback"
endpoint="{}"
model="example/local-rank"
model_revision="r1"
instruction="Rank complete documents"
fallback_profile="cloud"
[profiles.cloud]
kind="rerank"
protocol="openrouter-rerank-v1"
scope="remote"
endpoint="{}"
model="example/cloud-rank"
model_revision="r2"
instruction="Rank complete documents"
provider_only="fixed-provider"
"#, local.base(), cloud.base());
        ApiClient::new_with_test_root(ApiConfig::parse_toml(&text).unwrap(), Box::new(NoCredentials), cloud.ca_pem().to_vec())
    }

    #[test]
    fn whole_window_fallback_preserves_actual_attempts_and_cloud_scores() {
        let local = HttpFixture::start(vec![Reply::status(503)]);
        let cloud = TlsFixture::start(vec![Reply::ok(json!({"results":[
            {"index":1,"relevance_score":0.9}, {"index":0,"relevance_score":0.1}
        ], "model":"example/cloud-rank", "usage":{"input_tokens":23}}))]);
        let trace = std::sync::Arc::new(std::sync::Mutex::new(crate::search::regression_trace::RequestTrace::default()));
        let api = client(&local, &cloud).with_rerank_trace(trace.clone());
        let documents = vec!["first complete document".into(), "second complete document".into()];
        let mut evidence = None;
        let result = score(&api, "local", "query", &documents, true, &mut evidence).unwrap();
        assert_eq!(result.scores, vec![0.1, 0.9]);
        assert_eq!(result.http_requests, 2);
        assert_eq!(result.identity.actual_model.as_deref(), Some("example/cloud-rank"));
        assert_eq!(result.identity.actual_provider, None);
        let evidence = evidence.unwrap();
        assert_eq!(evidence.realized_profile.as_deref(), Some("cloud"));
        assert!(evidence.fallback_used);
        assert_eq!(evidence.attempts.len(), 2);
        assert_eq!(evidence.attempts[0].http_status, Some(503));
        assert!(evidence.attempts[0].error_code.is_some());
        assert_eq!(evidence.attempts[1].http_status, Some(200));
        assert_eq!(evidence.attempts[1].error_code, None);
        assert_eq!(evidence.attempts[1].usage.as_ref().unwrap().input_tokens, Some(23));
        let first = local.requests()[0].body();
        let second = cloud.fixture().requests()[0].body();
        for field in ["query", "documents", "instruct", "top_n"] { assert_eq!(first[field], second[field], "{field}"); }
        assert_eq!(first["documents"], json!(documents));
        let captured = trace.lock().unwrap();
        assert_eq!(captured.requests.len(), 2);
        assert_eq!(captured.requests[0].http_status, Some(503));
        assert_eq!(captured.requests[1].http_status, Some(200));
        for (request, sent) in captured.requests.iter().zip([&first, &second]) {
            use sha2::{Digest, Sha256};
            assert_eq!(request.json_body_sha256.as_ref().unwrap(), &hex::encode(Sha256::digest(serde_json::to_vec(sent).unwrap())));
            assert_eq!(request.documents.as_ref().unwrap().len(), documents.len());
            for (slot, text) in request.documents.as_ref().unwrap().iter().zip(&documents) {
                assert_eq!(slot.text, crate::search::regression_trace::TextDigest::of(text));
            }
        }
        assert_eq!(captured.model_requests, None, "HTTP does not prove GPU execution count");
        assert_eq!(local.hits(), 1);
        assert_eq!(cloud.fixture().hits(), 1);
    }

    #[test]
    fn timeout_keeps_its_classification_for_regression_costs() {
        let local = HttpFixture::start(vec![Reply::Stall]);
        let text = format!(r#"
version=1
[profiles.local]
kind="rerank"
protocol="rerank-json-v1"
scope="loopback"
endpoint="{}"
model="example/rank"
model_revision="r1"
connect_timeout_ms=100
timeout_ms=200
"#, local.base());
        let api = ApiClient::new(ApiConfig::parse_toml(&text).unwrap(), Box::new(NoCredentials));
        let mut evidence = None;
        let error = score(&api, "local", "query", &["document".into()], false, &mut evidence).unwrap_err();
        assert_eq!(error.reason, RerankFailureReason::Timeout);
        assert_eq!(evidence.unwrap().attempts[0].error_code.as_deref(), Some("timeout"));
        assert_eq!(local.hits(), 1);
    }

    #[test]
    fn failed_cloud_has_no_winner_and_no_partial_score_result() {
        let local = HttpFixture::start(vec![Reply::status(503)]);
        let cloud = TlsFixture::start(vec![Reply::status(500)]);
        let api = client(&local, &cloud);
        let mut evidence = None;
        let failure = score(&api, "local", "query", &["complete document".into()], true, &mut evidence).unwrap_err();
        assert_eq!(failure.http_status, Some(500));
        let evidence = evidence.unwrap();
        assert_eq!(evidence.realized_profile, None);
        assert!(!evidence.fallback_used);
        assert_eq!(evidence.attempts.len(), 2);
        assert!(evidence.attempts.iter().all(|a| a.error_code.is_some()));
        assert_eq!(local.hits(), 1);
        assert_eq!(cloud.fixture().hits(), 1);
    }
}
