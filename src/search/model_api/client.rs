//! The blocking model API client.
//!
//! [`ApiClient`] consumes one already-validated [`ValidatedApiConfig`], freezes
//! its own copy and exposes four explicit operations:
//!
//! * [`ApiClient::embed_once`] — one embedding `POST` to one named profile.
//! * [`ApiClient::rerank_once`] — one rerank `POST` to one named profile.
//! * [`ApiClient::rerank_with_fallback`] — the same, plus at most one more
//!   attempt against the primary's declared fallback when the failure is in the
//!   allowed set.
//! * [`ApiClient::probe_models`] — one explicit `GET` of a profile's metadata
//!   endpoint, and nothing at all when the profile configures none.
//!
//! # What this kernel deliberately does not do
//!
//! It registers no production caller, reads no production configuration, starts
//! no service and runs no background thread. `embed_once` is a single-profile
//! call with no implicit fallback and no "verified" bypass; the cross-endpoint
//! embedding admission of spec §6.4 belongs to a later ticket, so this kernel
//! never routes an embedding batch to a second endpoint.
//!
//! A credential is read only for the profile that is actually selected, only
//! through the injected [`CredentialResolver`], and only at the moment of the
//! send; the client itself never touches the environment. An unused cloud
//! credential therefore never blocks a working local call. The holder of a
//! credential — [`ApiClient`], [`HttpTransport`] — implements neither `Debug`
//! nor `Serialize`, and no key value reaches an error, an attempt record or a
//! log line.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::config::{
    ApiProtocol, EndpointScope, ProfileKind, ValidatedApiConfig, ValidatedProfile,
};
use super::error::{ApiCallError, ApiCallErrorCode};
use super::protocol::{self, InputKind, ObservedIdentity, RerankReply};
use super::routing;
use crate::search::rerank::http::{HttpConfig, HttpTransport, TransportError, TransportFailure};

/// Where a per-call credential comes from.
///
/// The client stores one of these and calls it with a profile's `api_key_env`
/// name. The name, not the value, is all the configuration ever holds.
pub trait CredentialResolver: Send + Sync {
    /// The credential for `variable`, or `None` when it is unset.
    fn resolve(&self, variable: &str) -> Option<String>;
}

/// Which side of the fallback pair one attempt belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStage {
    /// The selected profile's own request.
    Primary,
    /// The one allowed request to the declared fallback.
    Fallback,
    /// The metadata probe.
    Probe,
}

impl AttemptStage {
    /// The stable short name used in evidence.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Fallback => "fallback",
            Self::Probe => "probe",
        }
    }
}

/// One recorded attempt, successful or not.
///
/// A call keeps at most two of these: one per profile it actually tried. The
/// record stores the profile, the stage, whether a network request was
/// attempted, the HTTP status when one was observed, a short error code, the
/// measured duration and whatever identity the service returned.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiAttempt {
    /// The profile this attempt used.
    pub profile_id: String,
    /// Primary, fallback or probe.
    pub stage: AttemptStage,
    /// Whether bytes were actually sent towards the service.
    pub network_attempted: bool,
    /// The HTTP status, when one was observed.
    pub http_status: Option<u16>,
    /// The short failure code, when the attempt failed.
    pub error_code: Option<&'static str>,
    /// The measured duration from just before the send to validation.
    pub duration_ms: u64,
    /// What the service reported, when it reported anything.
    pub identity: ObservedIdentity,
}

/// The identity the caller asked for, kept apart from what the service said.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestedIdentity {
    /// The profile id.
    pub profile_id: String,
    /// The protocol the profile speaks.
    pub protocol: ApiProtocol,
    /// The model the request carried.
    pub model: String,
    /// The revision the configuration declares.
    pub model_revision: String,
}

/// The result of one successful embedding call.
#[derive(Debug, Clone, PartialEq)]
pub struct EmbedOutcome {
    /// The requested identity.
    pub requested: RequestedIdentity,
    /// The profile that actually served the batch.
    pub realized_profile: String,
    /// One vector per input, in input order.
    pub vectors: Vec<Vec<f32>>,
    /// The dimension every vector actually had.
    pub dimension: usize,
    /// The attempts this call made.
    pub attempts: Vec<ApiAttempt>,
    /// What the service reported.
    pub identity: ObservedIdentity,
}

/// The result of one successful rerank call.
#[derive(Debug, Clone, PartialEq)]
pub struct RerankOutcome {
    /// The requested identity of the primary profile.
    pub requested: RequestedIdentity,
    /// The profile that actually served the window.
    pub realized_profile: String,
    /// Whether the fallback served this window.
    pub fallback_used: bool,
    /// The primary failure's short code, when the fallback was used.
    pub fallback_reason: Option<&'static str>,
    /// One score per document, in input order.
    pub scores: Vec<f64>,
    /// The attempts this call made.
    pub attempts: Vec<ApiAttempt>,
    /// What the service reported.
    pub identity: ObservedIdentity,
}

/// The result of one metadata probe.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeOutcome {
    /// The requested identity.
    pub requested: RequestedIdentity,
    /// Whether the list named the configured model or one of its aliases.
    pub model_listed: bool,
    /// The attempts this probe made.
    pub attempts: Vec<ApiAttempt>,
    /// What the service reported about the call, which for a list is nothing.
    pub identity: ObservedIdentity,
}

/// A refused call: the short error plus everything that was already attempted.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiCallFailure {
    error: ApiCallError,
    requested: Option<RequestedIdentity>,
    attempts: Vec<ApiAttempt>,
}

impl ApiCallFailure {
    /// The short failure code and its optional evidence.
    pub fn error(&self) -> &ApiCallError {
        &self.error
    }

    /// The requested identity, when a profile was selected before the failure.
    pub fn requested(&self) -> Option<&RequestedIdentity> {
        self.requested.as_ref()
    }

    /// The attempts that happened before the failure.
    pub fn attempts(&self) -> &[ApiAttempt] {
        &self.attempts
    }
}

impl std::fmt::Display for ApiCallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, f)
    }
}

impl std::error::Error for ApiCallFailure {}

/// The caller's per-call routing options.
#[derive(Debug, Clone, Copy, Default)]
pub struct RerankOptions<'a> {
    /// Whether this call may use the primary's declared fallback at all.
    pub allow_fallback: bool,
    /// The caller's cancellation flag; `None` means this call cannot be
    /// cancelled.
    pub cancel: Option<&'a AtomicBool>,
}

impl<'a> RerankOptions<'a> {
    /// Options with the given fallback setting and no cancellation flag.
    pub const fn with_fallback(allow_fallback: bool) -> Self {
        Self {
            allow_fallback,
            cancel: None,
        }
    }

    /// Whether the caller has asked to cancel.
    fn cancelled(&self) -> bool {
        self.cancel.is_some_and(|flag| flag.load(Ordering::SeqCst))
    }
}

/// The blocking model API client.
///
/// The struct holds the credential resolver, so it implements neither `Debug`
/// nor `Serialize`.
pub struct ApiClient {
    config: ValidatedApiConfig,
    credentials: Box<dyn CredentialResolver>,
    /// Test-only: one extra PEM-encoded CA every transport of this client
    /// trusts. `None` on every production path; there is no runtime switch.
    #[cfg(test)]
    test_root: Option<Vec<u8>>,
}

impl ApiClient {
    /// Freeze `config` and take `credentials` as the only credential source.
    pub fn new(config: ValidatedApiConfig, credentials: Box<dyn CredentialResolver>) -> Self {
        Self {
            config,
            credentials,
            #[cfg(test)]
            test_root: None,
        }
    }

    /// Test-only: a client whose transports additionally trust `ca_pem`.
    ///
    /// This is what lets a test reach a loopback TLS fixture over a real
    /// handshake. It exists only under `cfg(test)`, so no production build can
    /// widen the trust store.
    #[cfg(test)]
    pub fn new_with_test_root(
        config: ValidatedApiConfig,
        credentials: Box<dyn CredentialResolver>,
        ca_pem: Vec<u8>,
    ) -> Self {
        Self {
            config,
            credentials,
            test_root: Some(ca_pem),
        }
    }

    /// The frozen configuration this client works from.
    pub fn config(&self) -> &ValidatedApiConfig {
        &self.config
    }

    /// One embedding request against exactly the named profile.
    ///
    /// The batch is the caller's: an empty list and a list longer than the
    /// profile's `max_batch` are refused before anything is sent, and one call
    /// is one `POST` for the whole list.
    pub fn embed_once(
        &self,
        profile_id: &str,
        inputs: &[String],
        kind: InputKind,
    ) -> Result<EmbedOutcome, ApiCallFailure> {
        let profile = self.profile_of_kind(profile_id, ProfileKind::Embedding)?;
        let Some(detail) = profile.embedding() else {
            return Err(self.bare_failure(ApiCallErrorCode::WrongKind, Some(profile)));
        };
        if inputs.is_empty() || inputs.len() as u64 > detail.max_batch {
            return Err(self.bare_failure(ApiCallErrorCode::InvalidInput, Some(profile)));
        }
        let prepared: Vec<String> = inputs
            .iter()
            .map(|text| protocol::embedding_input(profile, kind, text))
            .collect();

        let started = Instant::now();
        let body = match protocol::embedding_request(profile, &prepared) {
            Ok(body) => body,
            Err(error) => {
                return Err(self.attempt_failure(profile, AttemptStage::Primary, error, started));
            }
        };
        let transport = match self.transport_for(profile) {
            Ok(transport) => transport,
            Err(error) => {
                return Err(self.attempt_failure(profile, AttemptStage::Primary, error, started));
            }
        };
        let json = match transport.post_json_target(profile.endpoint.url(), &body) {
            Ok(json) => json,
            Err(failure) => {
                return Err(self.transport_failure(
                    profile,
                    AttemptStage::Primary,
                    failure,
                    started,
                ));
            }
        };
        match protocol::parse_embedding_response(profile, &json.body, prepared.len()) {
            Ok(reply) => {
                let attempt = ApiAttempt {
                    profile_id: profile.id.clone(),
                    stage: AttemptStage::Primary,
                    network_attempted: true,
                    http_status: Some(json.status),
                    error_code: None,
                    duration_ms: elapsed_ms(started),
                    identity: reply.identity.clone(),
                };
                Ok(EmbedOutcome {
                    requested: requested_identity(profile),
                    realized_profile: profile.id.clone(),
                    vectors: reply.vectors,
                    dimension: reply.dimension,
                    attempts: vec![attempt],
                    identity: reply.identity,
                })
            }
            Err(error) => {
                let attempt = observed_failure_attempt(
                    profile,
                    AttemptStage::Primary,
                    Some(json.status),
                    error.code().as_str(),
                    elapsed_ms(started),
                );
                Err(self.failure(error, Some(profile), vec![attempt]))
            }
        }
    }

    /// One rerank request against exactly the named profile, with no fallback.
    pub fn rerank_once(
        &self,
        profile_id: &str,
        query: &str,
        documents: &[String],
    ) -> Result<RerankOutcome, ApiCallFailure> {
        let profile = self.profile_of_kind(profile_id, ProfileKind::Rerank)?;
        if query.is_empty() || documents.is_empty() {
            return Err(self.bare_failure(ApiCallErrorCode::InvalidInput, Some(profile)));
        }
        let outcome = self.rerank_attempt(profile, query, documents, AttemptStage::Primary, None);
        match outcome.result {
            Ok(reply) => Ok(RerankOutcome {
                requested: requested_identity(profile),
                realized_profile: profile.id.clone(),
                fallback_used: false,
                fallback_reason: None,
                scores: reply.scores,
                attempts: vec![outcome.attempt],
                identity: reply.identity,
            }),
            Err(failure) => Err(self.failure(failure.error, Some(profile), vec![outcome.attempt])),
        }
    }

    /// One rerank request, plus at most one attempt against the declared
    /// fallback.
    ///
    /// The whole fixed window is re-sent: the same query, the same documents in
    /// the same order and the same instruction. A partial primary response is
    /// discarded, never merged. The cancellation flag is checked before the
    /// primary send, after the primary returns and again before the fallback
    /// send, and a cancelled call never reaches the cloud.
    pub fn rerank_with_fallback(
        &self,
        primary_id: &str,
        query: &str,
        documents: &[String],
        options: RerankOptions<'_>,
    ) -> Result<RerankOutcome, ApiCallFailure> {
        let primary = self.profile_of_kind(primary_id, ProfileKind::Rerank)?;
        if query.is_empty() || documents.is_empty() {
            return Err(self.bare_failure(ApiCallErrorCode::InvalidInput, Some(primary)));
        }
        if options.cancelled() {
            return Err(self.bare_failure(ApiCallErrorCode::Cancelled, Some(primary)));
        }

        let fallback = routing::fallback_target(&self.config, primary, options.allow_fallback);

        let first = self.rerank_attempt(
            primary,
            query,
            documents,
            AttemptStage::Primary,
            options.cancel,
        );
        let mut attempts = vec![first.attempt];

        // Checked the moment the primary returns, before its result is used and
        // before any fallback decision. A call that has observed a cancellation
        // never reports success and never reaches the cloud, whatever the
        // primary answered.
        if options.cancelled() {
            return Err(self.failure(
                ApiCallError::new(ApiCallErrorCode::Cancelled),
                Some(primary),
                attempts,
            ));
        }

        let primary_failure = match first.result {
            Ok(reply) => {
                return Ok(RerankOutcome {
                    requested: requested_identity(primary),
                    realized_profile: primary.id.clone(),
                    fallback_used: false,
                    fallback_reason: None,
                    scores: reply.scores,
                    attempts,
                    identity: reply.identity,
                });
            }
            Err(failure) => failure,
        };

        let eligible = fallback.is_some()
            && primary_failure
                .transport
                .is_some_and(routing::allows_cloud_fallback)
            && !options.cancelled();
        let Some(fallback_profile) = fallback.filter(|_| eligible) else {
            return Err(self.failure(primary_failure.error, Some(primary), attempts));
        };

        // Checked once more immediately before the fallback request is built.
        if options.cancelled() {
            return Err(self.failure(
                ApiCallError::new(ApiCallErrorCode::Cancelled),
                Some(primary),
                attempts,
            ));
        }

        let reason = primary_failure.transport.map(TransportFailure::as_str);
        let second = self.rerank_attempt(
            fallback_profile,
            query,
            documents,
            AttemptStage::Fallback,
            options.cancel,
        );
        attempts.push(second.attempt);
        match second.result {
            Ok(reply) => Ok(RerankOutcome {
                requested: requested_identity(primary),
                realized_profile: fallback_profile.id.clone(),
                fallback_used: true,
                fallback_reason: reason,
                scores: reply.scores,
                attempts,
                identity: reply.identity,
            }),
            Err(failure) => Err(self.failure(failure.error, Some(primary), attempts)),
        }
    }

    /// One explicit `GET` of the profile's metadata endpoint.
    ///
    /// A profile without a `models_endpoint` makes no request at all and reports
    /// [`ApiCallErrorCode::UnsupportedProbe`]. The probe only checks that the
    /// list names the configured model or one of its aliases: it asks for no
    /// framework-specific capability field and never invents a revision the
    /// service did not return.
    pub fn probe_models(&self, profile_id: &str) -> Result<ProbeOutcome, ApiCallFailure> {
        let Some(profile) = self.config.profile(profile_id) else {
            return Err(self.unknown_profile());
        };
        let Some(models_endpoint) = &profile.models_endpoint else {
            return Err(self.bare_failure(ApiCallErrorCode::UnsupportedProbe, Some(profile)));
        };

        let started = Instant::now();
        let transport = match self.transport_for(profile) {
            Ok(transport) => transport,
            Err(error) => {
                return Err(self.attempt_failure(profile, AttemptStage::Probe, error, started));
            }
        };
        let json = match transport.get_json_target(models_endpoint.url()) {
            Ok(json) => json,
            Err(failure) => {
                return Err(self.transport_failure(profile, AttemptStage::Probe, failure, started));
            }
        };
        let attempt = ApiAttempt {
            profile_id: profile.id.clone(),
            stage: AttemptStage::Probe,
            network_attempted: true,
            http_status: Some(json.status),
            error_code: None,
            duration_ms: elapsed_ms(started),
            identity: ObservedIdentity::default(),
        };
        let Some(rows) = json.body.get("data").and_then(Value::as_array) else {
            let code = ApiCallErrorCode::InvalidResponse;
            return Err(self.failure(
                ApiCallError::new(code),
                Some(profile),
                vec![failed_probe_attempt(profile, json.status, code)],
            ));
        };
        let model_listed = rows.iter().any(|row| {
            row.get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| model_matches(profile, id))
        });
        if !model_listed {
            let code = ApiCallErrorCode::IdentityMismatch;
            return Err(self.failure(
                ApiCallError::new(code),
                Some(profile),
                vec![failed_probe_attempt(profile, json.status, code)],
            ));
        }
        Ok(ProbeOutcome {
            requested: requested_identity(profile),
            model_listed,
            attempts: vec![attempt],
            identity: ObservedIdentity::default(),
        })
    }

    /// Resolve `profile_id` and prove its kind.
    fn profile_of_kind(
        &self,
        profile_id: &str,
        kind: ProfileKind,
    ) -> Result<&ValidatedProfile, ApiCallFailure> {
        let Some(profile) = self.config.profile(profile_id) else {
            return Err(self.unknown_profile());
        };
        if profile.kind != kind {
            return Err(self.bare_failure(ApiCallErrorCode::WrongKind, Some(profile)));
        }
        Ok(profile)
    }

    /// One rerank attempt against `profile`, with its own record.
    ///
    /// `cancel` is checked twice around the one request: after the transport —
    /// and therefore the credential resolution — is built and before the body
    /// is sent, and again the moment a response or a failure comes back. A set
    /// flag stops the send, and a call that has observed a cancellation never
    /// reports success.
    fn rerank_attempt(
        &self,
        profile: &ValidatedProfile,
        query: &str,
        documents: &[String],
        stage: AttemptStage,
        cancel: Option<&AtomicBool>,
    ) -> AttemptOutcome {
        let started = Instant::now();
        let body = match protocol::rerank_request(profile, query, documents) {
            Ok(body) => body,
            Err(error) => return self.attempt_failure_outcome(profile, stage, error, started),
        };
        let transport = match self.transport_for(profile) {
            Ok(transport) => transport,
            Err(error) => return self.attempt_failure_outcome(profile, stage, error, started),
        };
        if is_cancelled(cancel) {
            return AttemptOutcome::failed(
                ApiCallError::new(ApiCallErrorCode::Cancelled),
                None,
                cancelled_attempt(profile, stage, false, None, elapsed_ms(started)),
            );
        }
        match transport.post_json_target(profile.endpoint.url(), &body) {
            Ok(json) => {
                let attempt = ApiAttempt {
                    profile_id: profile.id.clone(),
                    stage,
                    network_attempted: true,
                    http_status: Some(json.status),
                    error_code: None,
                    duration_ms: elapsed_ms(started),
                    identity: ObservedIdentity::default(),
                };
                if is_cancelled(cancel) {
                    // The service really answered; the cancellation still wins,
                    // and the record keeps the status so nobody can read this as
                    // "the request was never made".
                    return AttemptOutcome::failed(
                        ApiCallError::new(ApiCallErrorCode::Cancelled),
                        None,
                        cancelled_attempt(
                            profile,
                            stage,
                            true,
                            Some(json.status),
                            elapsed_ms(started),
                        ),
                    );
                }
                match protocol::parse_rerank_response(profile, &json.body, documents.len()) {
                    Ok(reply) => {
                        let attempt = ApiAttempt {
                            identity: reply.identity.clone(),
                            ..attempt
                        };
                        AttemptOutcome::succeeded(reply, attempt)
                    }
                    Err(error) => {
                        let attempt = observed_failure_attempt(
                            profile,
                            stage,
                            Some(json.status),
                            error.code().as_str(),
                            elapsed_ms(started),
                        );
                        AttemptOutcome::failed(error, None, attempt)
                    }
                }
            }
            Err(transport_error) => {
                let failure = transport_error.failure();
                let error = api_error_from_transport(failure);
                let attempt = ApiAttempt {
                    profile_id: profile.id.clone(),
                    stage,
                    network_attempted: failure.network_attempted(),
                    http_status: transport_error.http_status(),
                    error_code: Some(failure.as_str()),
                    duration_ms: elapsed_ms(started),
                    identity: ObservedIdentity::default(),
                };
                if is_cancelled(cancel) {
                    return AttemptOutcome::failed(
                        ApiCallError::new(ApiCallErrorCode::Cancelled),
                        None,
                        cancelled_attempt(
                            profile,
                            stage,
                            failure.network_attempted(),
                            transport_error.http_status(),
                            elapsed_ms(started),
                        ),
                    );
                }
                AttemptOutcome::failed(error, Some(failure), attempt)
            }
        }
    }

    /// Build the transport one profile needs, resolving its credential only now.
    fn transport_for(&self, profile: &ValidatedProfile) -> Result<HttpTransport, ApiCallError> {
        if profile.scope == EndpointScope::Remote && profile.endpoint.url().scheme() != "https" {
            return Err(ApiCallError::new(ApiCallErrorCode::InvalidInput));
        }
        let Ok(max_response_bytes) = usize::try_from(profile.max_response_bytes) else {
            return Err(ApiCallError::new(ApiCallErrorCode::InvalidInput));
        };
        let config = HttpConfig {
            base_url: profile.endpoint.url().origin().ascii_serialization(),
            local_only: profile.scope == EndpointScope::Loopback,
            timeout: Duration::from_millis(profile.timeout_ms),
            connect_timeout: Duration::from_millis(profile.connect_timeout_ms),
            max_response_bytes,
        };
        let bearer = match &profile.api_key_env {
            Some(variable) => {
                let token = self
                    .credentials
                    .resolve(variable)
                    .filter(|token| !token.is_empty())
                    .ok_or_else(|| ApiCallError::new(ApiCallErrorCode::MissingCredentials))?;
                Some(token)
            }
            None => None,
        };
        #[cfg(test)]
        if let Some(ca_pem) = &self.test_root {
            return HttpTransport::new_with_test_root(config, bearer, ca_pem)
                .map_err(|_| ApiCallError::new(ApiCallErrorCode::InvalidInput));
        }
        HttpTransport::new(config, bearer)
            .map_err(|_| ApiCallError::new(ApiCallErrorCode::InvalidInput))
    }

    /// A refusal raised before anything was sent, with its record.
    fn attempt_failure(
        &self,
        profile: &ValidatedProfile,
        stage: AttemptStage,
        error: ApiCallError,
        started: Instant,
    ) -> ApiCallFailure {
        let attempt = ApiAttempt {
            profile_id: profile.id.clone(),
            stage,
            network_attempted: false,
            http_status: error.http_status(),
            error_code: Some(error.code().as_str()),
            duration_ms: elapsed_ms(started),
            identity: ObservedIdentity::default(),
        };
        self.failure(error, Some(profile), vec![attempt])
    }

    /// A refusal raised before anything was sent, as a rerank attempt outcome.
    fn attempt_failure_outcome(
        &self,
        profile: &ValidatedProfile,
        stage: AttemptStage,
        error: ApiCallError,
        started: Instant,
    ) -> AttemptOutcome {
        let attempt = ApiAttempt {
            profile_id: profile.id.clone(),
            stage,
            network_attempted: false,
            http_status: error.http_status(),
            error_code: Some(error.code().as_str()),
            duration_ms: elapsed_ms(started),
            identity: ObservedIdentity::default(),
        };
        AttemptOutcome::failed(error, None, attempt)
    }

    /// A refusal raised by the transport layer, with its classification kept for
    /// the routing decision and the status it actually observed kept as
    /// evidence. A failure after a real answer therefore records that status
    /// instead of reporting the service as unreachable.
    fn transport_failure(
        &self,
        profile: &ValidatedProfile,
        stage: AttemptStage,
        transport_error: TransportError,
        started: Instant,
    ) -> ApiCallFailure {
        let failure = transport_error.failure();
        let error = api_error_from_transport(failure);
        let attempt = ApiAttempt {
            profile_id: profile.id.clone(),
            stage,
            network_attempted: failure.network_attempted(),
            http_status: transport_error.http_status(),
            error_code: Some(failure.as_str()),
            duration_ms: elapsed_ms(started),
            identity: ObservedIdentity::default(),
        };
        self.failure(error, Some(profile), vec![attempt])
    }

    /// A failure that happened before any profile was selected.
    fn unknown_profile(&self) -> ApiCallFailure {
        ApiCallFailure {
            error: ApiCallError::new(ApiCallErrorCode::UnknownProfile),
            requested: None,
            attempts: Vec::new(),
        }
    }

    /// A failure with no attempts recorded yet.
    fn bare_failure(
        &self,
        code: ApiCallErrorCode,
        profile: Option<&ValidatedProfile>,
    ) -> ApiCallFailure {
        self.failure(ApiCallError::new(code), profile, Vec::new())
    }

    /// A failure carrying the attempts that were already made.
    fn failure(
        &self,
        error: ApiCallError,
        profile: Option<&ValidatedProfile>,
        attempts: Vec<ApiAttempt>,
    ) -> ApiCallFailure {
        ApiCallFailure {
            error,
            requested: profile.map(requested_identity),
            attempts,
        }
    }
}

/// The outcome of one attempt plus its record.
struct AttemptOutcome {
    result: Result<RerankReply, AttemptFailure>,
    attempt: ApiAttempt,
}

/// A failed attempt, keeping the transport detail for the routing decision.
struct AttemptFailure {
    error: ApiCallError,
    transport: Option<TransportFailure>,
}

impl AttemptOutcome {
    fn succeeded(reply: RerankReply, attempt: ApiAttempt) -> Self {
        Self {
            result: Ok(reply),
            attempt,
        }
    }

    fn failed(
        error: ApiCallError,
        transport: Option<TransportFailure>,
        attempt: ApiAttempt,
    ) -> Self {
        Self {
            result: Err(AttemptFailure { error, transport }),
            attempt,
        }
    }
}

/// Whether the caller's cancellation flag is set.
fn is_cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|flag| flag.load(Ordering::SeqCst))
}

/// The record for an attempt the caller cancelled.
///
/// `network_attempted` and `http_status` are what really happened: a cancelled
/// request reports the status it did receive rather than pretending the network
/// was never touched.
fn cancelled_attempt(
    profile: &ValidatedProfile,
    stage: AttemptStage,
    network_attempted: bool,
    http_status: Option<u16>,
    duration_ms: u64,
) -> ApiAttempt {
    ApiAttempt {
        profile_id: profile.id.clone(),
        stage,
        network_attempted,
        http_status,
        error_code: Some(ApiCallErrorCode::Cancelled.as_str()),
        duration_ms,
        identity: ObservedIdentity::default(),
    }
}

/// The record for an attempt whose response was observed but rejected.
fn observed_failure_attempt(
    profile: &ValidatedProfile,
    stage: AttemptStage,
    http_status: Option<u16>,
    error_code: &'static str,
    duration_ms: u64,
) -> ApiAttempt {
    ApiAttempt {
        profile_id: profile.id.clone(),
        stage,
        network_attempted: true,
        http_status,
        error_code: Some(error_code),
        duration_ms,
        identity: ObservedIdentity::default(),
    }
}

/// The record for a probe that received a real answer and rejected it.
///
/// The HTTP status is the one the service actually returned, and the short code
/// names the rule that refused it, so a probe failure is never recorded as an
/// unexplained `None`.
fn failed_probe_attempt(
    profile: &ValidatedProfile,
    http_status: u16,
    code: ApiCallErrorCode,
) -> ApiAttempt {
    ApiAttempt {
        profile_id: profile.id.clone(),
        stage: AttemptStage::Probe,
        network_attempted: true,
        http_status: Some(http_status),
        error_code: Some(code.as_str()),
        duration_ms: 0,
        identity: ObservedIdentity::default(),
    }
}

/// The requested identity of one profile.
fn requested_identity(profile: &ValidatedProfile) -> RequestedIdentity {
    RequestedIdentity {
        profile_id: profile.id.clone(),
        protocol: profile.protocol,
        model: profile.model.clone(),
        model_revision: profile.model_revision.clone(),
    }
}

/// Whether a reported model name is the configured model or one of its aliases.
fn model_matches(profile: &ValidatedProfile, reported: &str) -> bool {
    reported == profile.model
        || profile
            .response_model_aliases
            .iter()
            .any(|alias| alias == reported)
}

/// Reduce a transport classification to the call-level short code.
fn api_error_from_transport(failure: TransportFailure) -> ApiCallError {
    match failure {
        TransportFailure::HttpStatus(status) => {
            ApiCallError::with_status(ApiCallErrorCode::HttpStatus, status)
        }
        TransportFailure::InvalidInput => ApiCallError::new(ApiCallErrorCode::InvalidInput),
        TransportFailure::InvalidResponse => {
            ApiCallError::with_transport(ApiCallErrorCode::InvalidResponse, failure.as_str())
        }
        TransportFailure::Timeout
        | TransportFailure::ConnectionRefused
        | TransportFailure::ConnectionInterrupted
        | TransportFailure::NetworkUnavailable
        | TransportFailure::UnclassifiedTransport => {
            ApiCallError::with_transport(ApiCallErrorCode::Transport, failure.as_str())
        }
    }
}

/// The measured duration, saturating instead of truncating on the (unreachable)
/// overflow.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::model_api::config::ApiConfig;
    use crate::search::model_api::test_support::{HttpFixture, Reply, TlsFixture};
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// A credential source backed by a fixed map that records every lookup.
    #[derive(Default)]
    struct FixedCredentials {
        values: HashMap<String, String>,
        lookups: Mutex<Vec<String>>,
        /// Invoked on every lookup, so a test can flip a cancellation flag at a
        /// precise point of the call.
        on_lookup: Option<Box<dyn Fn() + Send + Sync>>,
    }

    impl FixedCredentials {
        fn with(values: &[(&str, &str)]) -> Self {
            let mut map = HashMap::new();
            for (name, value) in values {
                map.insert((*name).to_string(), (*value).to_string());
            }
            Self {
                values: map,
                lookups: Mutex::new(Vec::new()),
                on_lookup: None,
            }
        }

        fn lookups(&self) -> Vec<String> {
            self.lookups.lock().expect("lookup log").clone()
        }
    }

    impl CredentialResolver for FixedCredentials {
        fn resolve(&self, variable: &str) -> Option<String> {
            self.lookups
                .lock()
                .expect("lookup log")
                .push(variable.to_string());
            if let Some(hook) = &self.on_lookup {
                hook();
            }
            self.values.get(variable).cloned()
        }
    }

    /// A shared resolver, so a test can inspect the lookups after the client
    /// has taken ownership.
    impl CredentialResolver for Arc<FixedCredentials> {
        fn resolve(&self, variable: &str) -> Option<String> {
            FixedCredentials::resolve(self, variable)
        }
    }

    fn parse(text: &str) -> ValidatedApiConfig {
        ApiConfig::parse_toml(text).expect("configuration parses")
    }

    fn client(text: &str) -> ApiClient {
        ApiClient::new(parse(text), Box::new(FixedCredentials::default()))
    }

    /// A loopback rerank primary with a remote cloud fallback.
    fn rerank_pair(primary_base: &str, fallback_base: &str) -> String {
        format!(
            r#"
version = 1
default_rerank = "local"

[profiles.local]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{primary_base}/rerank"
scope = "loopback"
model = "local-reranker"
model_revision = "rev-local"
fallback_profile = "cloud"

[profiles.cloud]
kind = "rerank"
protocol = "openrouter-rerank-v1"
endpoint = "{fallback_base}/api/v1/rerank"
scope = "remote"
model = "cloud-reranker"
model_revision = "rev-cloud"
provider_only = "pinned-vendor"
"#
        )
    }

    fn documents(n: usize) -> Vec<String> {
        (0..n).map(|index| format!("document {index}")).collect()
    }

    /// A `results`-shaped rerank answer scoring `index` as `n - index`.
    fn rerank_results(n: usize) -> Value {
        json!({
            "results": (0..n)
                .map(|index| json!({"index": index, "relevance_score": (n - index) as f64}))
                .collect::<Vec<Value>>()
        })
    }

    /// A native-array rerank answer.
    fn rerank_native(n: usize) -> Value {
        Value::Array(
            (0..n)
                .map(|index| json!({"index": index, "score": (index as f64) / 2.0}))
                .collect(),
        )
    }

    fn embedding_rows(vectors: &[Vec<f64>]) -> Value {
        json!({
            "data": vectors
                .iter()
                .enumerate()
                .map(|(index, vector)| json!({"index": index, "embedding": vector}))
                .collect::<Vec<Value>>()
        })
    }

    fn assert_close(actual: &[f32], expected: &[f32]) {
        assert_eq!(actual.len(), expected.len(), "length");
        for (left, right) in actual.iter().zip(expected) {
            assert!(
                (left - right).abs() < 1e-6,
                "expected {expected:?}, got {actual:?}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Request shape: one POST per operation, exact bytes.
    // ------------------------------------------------------------------

    #[test]
    fn openai_embedding_sends_one_post_with_the_configured_shape() {
        let fixture = HttpFixture::start(vec![Reply::ok(embedding_rows(&[
            vec![3.0, 4.0],
            vec![0.0, 5.0],
        ]))]);
        let text = format!(
            r#"
version = 1
default_embedding = "emb"

[profiles.emb]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "{base}/v1/embeddings"
scope = "loopback"
model = "some-model"
model_revision = "rev-1"
normalization = "l2"
query_prefix = "Q: "
document_prefix = "D: "
request_dimensions = 2
"#,
            base = fixture.base()
        );
        let inputs = vec!["alpha".to_string(), "beta".to_string()];
        let outcome = client(&text)
            .embed_once("emb", &inputs, InputKind::Query)
            .expect("embedding");

        assert_eq!(fixture.hits(), 1, "exactly one POST");
        let request = &fixture.requests()[0];
        assert_eq!(request.method(), "POST");
        assert_eq!(request.target(), "/v1/embeddings");
        let body = request.body();
        assert_eq!(body["input"], json!(["Q: alpha", "Q: beta"]));
        assert_eq!(body["encoding_format"], json!("float"));
        assert_eq!(body["model"], json!("some-model"));
        assert_eq!(body["dimensions"], json!(2));
        assert_eq!(body.as_object().expect("object").len(), 4);

        assert_eq!(outcome.dimension, 2);
        assert_close(&outcome.vectors[0], &[0.6, 0.8]);
        assert_close(&outcome.vectors[1], &[0.0, 1.0]);
        assert_eq!(outcome.realized_profile, "emb");
        assert_eq!(outcome.attempts.len(), 1);
        assert_eq!(outcome.attempts[0].stage, AttemptStage::Primary);
        assert!(outcome.attempts[0].network_attempted);
        assert_eq!(outcome.attempts[0].http_status, Some(200));
        assert_eq!(outcome.attempts[0].error_code, None);
        assert_eq!(outcome.requested.model, "some-model");
    }

    #[test]
    fn document_prefix_is_applied_for_document_inputs() {
        let fixture = HttpFixture::start(vec![Reply::ok(embedding_rows(&[vec![1.0, 0.0]]))]);
        let text = format!(
            r#"
version = 1
[profiles.emb]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "{base}/e"
scope = "loopback"
model = "m"
model_revision = "r"
normalization = "none"
query_prefix = "Q:"
document_prefix = "D:"
"#,
            base = fixture.base()
        );
        client(&text)
            .embed_once("emb", &["body".to_string()], InputKind::Document)
            .expect("embedding");
        assert_eq!(fixture.requests()[0].body()["input"], json!(["D:body"]));
    }

    #[test]
    fn openrouter_embedding_sends_the_pinned_provider_block() {
        let fixture = HttpFixture::start(vec![Reply::ok(embedding_rows(&[vec![1.0, 0.0]]))]);
        let text = format!(
            r#"
version = 1
[profiles.emb]
kind = "embedding"
protocol = "openrouter-embeddings-v1"
endpoint = "{base}/v1/embeddings"
scope = "loopback"
model = "m"
model_revision = "r"
normalization = "none"
provider_only = "vendor-x"
send_model = true
"#,
            base = fixture.base()
        );
        client(&text)
            .embed_once("emb", &["x".to_string()], InputKind::Query)
            .expect("embedding");
        assert_eq!(
            fixture.requests()[0].body()["provider"],
            json!({"allow_fallbacks": false, "only": ["vendor-x"], "require_parameters": true})
        );
    }

    #[test]
    fn rerank_json_sends_the_frozen_five_key_payload() {
        let fixture = HttpFixture::start(vec![Reply::ok(rerank_results(3))]);
        let text = format!(
            r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}/score"
scope = "loopback"
model = "rr-model"
model_revision = "rr-rev"
instruction = "rank it"
"#,
            base = fixture.base()
        );
        let documents = documents(3);
        let outcome = client(&text)
            .rerank_once("rr", "a query", &documents)
            .expect("rerank");

        assert_eq!(fixture.hits(), 1, "exactly one POST");
        let body = fixture.requests()[0].body();
        assert_eq!(body["query"], json!("a query"));
        assert_eq!(body["documents"], json!(documents));
        assert_eq!(body["top_n"], json!(3));
        assert_eq!(body["return_documents"], json!(false));
        assert_eq!(body["model"], json!("rr-model"));
        assert_eq!(body["instruct"], json!("rank it"));
        assert_eq!(outcome.scores, vec![3.0, 2.0, 1.0]);
    }

    #[test]
    fn instruct_is_omitted_when_unset_and_empty_when_set_to_empty() {
        let fixture = HttpFixture::start(vec![Reply::ok(rerank_results(1))]);
        let text = format!(
            r#"
version = 1
[profiles.absent]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}/score"
scope = "loopback"
model = "m"
model_revision = "r"

[profiles.blank]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}/score"
scope = "loopback"
model = "m"
model_revision = "r"
instruction = ""
"#,
            base = fixture.base()
        );
        let api = client(&text);
        let documents = documents(1);
        api.rerank_once("absent", "q", &documents).expect("rerank");
        api.rerank_once("blank", "q", &documents).expect("rerank");

        let requests = fixture.requests();
        assert!(
            !requests[0]
                .body()
                .as_object()
                .expect("object")
                .contains_key("instruct"),
            "an unset instruction must not be sent"
        );
        assert_eq!(requests[1].body()["instruct"], json!(""));
    }

    #[test]
    fn openrouter_rerank_pins_the_provider_block() {
        let fixture = HttpFixture::start(vec![Reply::ok(rerank_results(1))]);
        let text = format!(
            r#"
version = 1
[profiles.pinned]
kind = "rerank"
protocol = "openrouter-rerank-v1"
endpoint = "{base}/r"
scope = "loopback"
model = "m"
model_revision = "r"
provider_only = "vendor-y"

[profiles.unpinned]
kind = "rerank"
protocol = "openrouter-rerank-v1"
endpoint = "{base}/r"
scope = "loopback"
model = "m"
model_revision = "r"
"#,
            base = fixture.base()
        );
        let api = client(&text);
        let documents = documents(1);
        api.rerank_once("pinned", "q", &documents).expect("rerank");
        api.rerank_once("unpinned", "q", &documents)
            .expect("rerank");

        let requests = fixture.requests();
        assert_eq!(
            requests[0].body()["provider"],
            json!({"allow_fallbacks": false, "only": ["vendor-y"], "require_parameters": true})
        );
        assert_eq!(
            requests[1].body()["provider"],
            json!({"allow_fallbacks": false})
        );
    }

    #[test]
    fn a_configured_path_keeps_its_legal_at_and_double_slash() {
        let fixture = HttpFixture::start(vec![Reply::ok(rerank_results(1))]);
        let text = format!(
            r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}//a@b%41c"
scope = "loopback"
model = "m"
model_revision = "r"
"#,
            base = fixture.base()
        );
        let documents = documents(1);
        client(&text)
            .rerank_once("rr", "q", &documents)
            .expect("rerank");
        assert_eq!(fixture.hits(), 1);
        assert_eq!(
            fixture.requests()[0].target(),
            "//a@b%41c",
            "the configured path must reach the service unchanged, not re-joined"
        );
    }

    #[test]
    fn out_of_order_embedding_indices_are_restored_to_input_order() {
        let fixture = HttpFixture::start(vec![Reply::ok(json!({
            "data": [
                {"index": 1, "embedding": [0.0, 1.0]},
                {"index": 0, "embedding": [1.0, 0.0]},
            ]
        }))]);
        let text = format!(
            r#"
version = 1
[profiles.emb]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "{base}/e"
scope = "loopback"
model = "m"
model_revision = "r"
normalization = "none"
"#,
            base = fixture.base()
        );
        let outcome = client(&text)
            .embed_once(
                "emb",
                &["first".to_string(), "second".to_string()],
                InputKind::Query,
            )
            .expect("embedding");
        assert_close(&outcome.vectors[0], &[1.0, 0.0]);
        assert_close(&outcome.vectors[1], &[0.0, 1.0]);
    }

    #[test]
    fn out_of_order_rerank_indices_are_restored_to_input_order() {
        let fixture = HttpFixture::start(vec![Reply::ok(json!({
            "results": [
                {"index": 2, "relevance_score": 0.25},
                {"index": 0, "relevance_score": 0.75},
                {"index": 1, "relevance_score": 0.5},
            ]
        }))]);
        let text = format!(
            r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}/r"
scope = "loopback"
model = "m"
model_revision = "r"
"#,
            base = fixture.base()
        );
        let documents = documents(3);
        let outcome = client(&text)
            .rerank_once("rr", "q", &documents)
            .expect("rerank");
        assert_eq!(outcome.scores, vec![0.75, 0.5, 0.25]);
    }

    #[test]
    fn the_native_rerank_array_shape_is_accepted() {
        let fixture = HttpFixture::start(vec![Reply::ok(rerank_native(2))]);
        let text = format!(
            r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}/r"
scope = "loopback"
model = "m"
model_revision = "r"
"#,
            base = fixture.base()
        );
        let documents = documents(2);
        let outcome = client(&text)
            .rerank_once("rr", "q", &documents)
            .expect("rerank");
        assert_eq!(outcome.scores, vec![0.0, 0.5]);
        assert_eq!(outcome.identity.response_model, None);
    }

    // ------------------------------------------------------------------
    // Input validation happens before any request exists.
    // ------------------------------------------------------------------

    #[test]
    fn an_empty_or_oversized_batch_is_refused_before_sending() {
        let fixture = HttpFixture::ok();
        let text = format!(
            r#"
version = 1
[profiles.emb]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "{base}/e"
scope = "loopback"
model = "m"
model_revision = "r"
normalization = "none"
max_batch = 2
"#,
            base = fixture.base()
        );
        let api = client(&text);
        let empty = api
            .embed_once("emb", &[], InputKind::Query)
            .expect_err("empty batch");
        assert_eq!(empty.error().code(), ApiCallErrorCode::InvalidInput);
        assert!(empty.attempts().is_empty());

        let too_many = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let oversized = api
            .embed_once("emb", &too_many, InputKind::Query)
            .expect_err("oversized batch");
        assert_eq!(oversized.error().code(), ApiCallErrorCode::InvalidInput);
        assert_eq!(fixture.hits(), 0, "no request may be sent");
    }

    #[test]
    fn an_empty_window_is_refused_before_sending() {
        let fixture = HttpFixture::ok();
        let text = format!(
            r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}/r"
scope = "loopback"
model = "m"
model_revision = "r"
"#,
            base = fixture.base()
        );
        let api = client(&text);
        assert_eq!(
            api.rerank_once("rr", "q", &[])
                .expect_err("no documents")
                .error()
                .code(),
            ApiCallErrorCode::InvalidInput
        );
        let documents = documents(1);
        assert_eq!(
            api.rerank_once("rr", "", &documents)
                .expect_err("no query")
                .error()
                .code(),
            ApiCallErrorCode::InvalidInput
        );
        assert_eq!(fixture.hits(), 0);
    }

    #[test]
    fn an_unknown_profile_and_a_wrong_kind_are_distinguished() {
        let text = r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "http://127.0.0.1:9/r"
scope = "loopback"
model = "m"
model_revision = "r"
"#;
        let api = client(text);
        let unknown = api.embed_once("nope", &["x".to_string()], InputKind::Query);
        assert_eq!(
            unknown.expect_err("unknown").error().code(),
            ApiCallErrorCode::UnknownProfile
        );
        let wrong_kind = api.embed_once("rr", &["x".to_string()], InputKind::Query);
        assert_eq!(
            wrong_kind.expect_err("wrong kind").error().code(),
            ApiCallErrorCode::WrongKind
        );
    }

    #[test]
    fn a_missing_credential_is_refused_before_sending() {
        let fixture = HttpFixture::ok();
        let text = format!(
            r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}/r"
scope = "loopback"
model = "m"
model_revision = "r"
api_key_env = "ABSENT_KEY"
"#,
            base = fixture.base()
        );
        let documents = documents(1);
        let failure = client(&text)
            .rerank_once("rr", "q", &documents)
            .expect_err("missing credential");
        assert_eq!(failure.error().code(), ApiCallErrorCode::MissingCredentials);
        assert_eq!(fixture.hits(), 0, "no request may be sent");
        assert_eq!(failure.attempts().len(), 1);
        assert!(!failure.attempts()[0].network_attempted);
    }

    // ------------------------------------------------------------------
    // Response refusals.
    // ------------------------------------------------------------------

    fn embedding_config(base: &str, extra: &str) -> String {
        embedding_config_norm(base, "none", extra)
    }

    fn embedding_config_norm(base: &str, normalization: &str, extra: &str) -> String {
        format!(
            r#"
version = 1
[profiles.emb]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "{base}/e"
scope = "loopback"
model = "m"
model_revision = "r"
normalization = "{normalization}"
{extra}
"#
        )
    }

    #[test]
    fn a_malformed_embedding_response_is_refused() {
        let cases: Vec<(&str, Value, &str)> = vec![
            (
                "missing row",
                json!({"data": [{"index": 0, "embedding": [1.0, 0.0]}]}),
                "InvalidResponse",
            ),
            (
                "duplicate index",
                json!({"data": [{"index": 0, "embedding": [1.0, 0.0]}, {"index": 0, "embedding": [1.0, 0.0]}]}),
                "InvalidResponse",
            ),
            (
                "out of range index",
                json!({"data": [{"index": 0, "embedding": [1.0, 0.0]}, {"index": 7, "embedding": [1.0, 0.0]}]}),
                "InvalidResponse",
            ),
            (
                "ragged dimensions",
                json!({"data": [{"index": 0, "embedding": [1.0, 0.0]}, {"index": 1, "embedding": [1.0]}]}),
                "InvalidResponse",
            ),
            (
                "zero norm",
                json!({"data": [{"index": 0, "embedding": [0.0, 0.0]}, {"index": 1, "embedding": [1.0, 0.0]}]}),
                "InvalidResponse",
            ),
            (
                "non numeric component",
                json!({"data": [{"index": 0, "embedding": [1.0, "x"]}, {"index": 1, "embedding": [1.0, 0.0]}]}),
                "InvalidResponse",
            ),
            (
                "unrepresentable magnitude",
                json!({"data": [{"index": 0, "embedding": [1e308, 1e308]}, {"index": 1, "embedding": [1.0, 0.0]}]}),
                "InvalidResponse",
            ),
            (
                "missing data array",
                json!({"vectors": []}),
                "InvalidResponse",
            ),
        ];
        for (label, body, expected_code) in cases {
            let fixture = HttpFixture::start(vec![Reply::ok(body)]);
            let api = client(&embedding_config(&fixture.base(), ""));
            let inputs = vec!["a".to_string(), "b".to_string()];
            let failure = api
                .embed_once("emb", &inputs, InputKind::Query)
                .expect_err(label);
            assert_eq!(failure.error().code().as_str(), expected_code, "{label}");
        }
    }

    #[test]
    fn a_response_identity_contradiction_is_refused() {
        let good = |body: Value| {
            let fixture = HttpFixture::start(vec![Reply::ok(body)]);
            let api = client(&embedding_config(&fixture.base(), ""));
            let inputs = vec!["a".to_string()];
            (api.embed_once("emb", &inputs, InputKind::Query), fixture)
        };

        let rows = embedding_rows(&[vec![1.0, 0.0]]);
        let with = |extra: Value| {
            let mut body = rows.clone();
            for (key, value) in extra.as_object().expect("object") {
                body[key] = value.clone();
            }
            body
        };

        for (label, body) in [
            ("wrong model", with(json!({"model": "somebody-else"}))),
            (
                "wrong revision",
                with(json!({"model": "m", "revision": "rev-other"})),
            ),
            (
                "disagreeing revisions",
                with(json!({"model": "m", "revision": "r", "model_revision": "other"})),
            ),
            ("non string model", with(json!({"model": 7}))),
        ] {
            let (outcome, fixture) = good(body);
            let failure = outcome.expect_err(label);
            assert!(
                matches!(
                    failure.error().code(),
                    ApiCallErrorCode::IdentityMismatch | ApiCallErrorCode::InvalidResponse
                ),
                "{label}: {:?}",
                failure.error().code()
            );
            assert_eq!(fixture.hits(), 1);
        }

        // The configured alias is accepted.
        let aliased = format!(
            r#"
version = 1
[profiles.emb]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "http://127.0.0.1:9/e"
scope = "loopback"
model = "m"
model_revision = "r"
normalization = "none"
response_model_aliases = ["m-alias"]
"#
        );
        let fixture = HttpFixture::start(vec![Reply::ok(with(json!({"model": "m-alias"})))]);
        let text = aliased.replace("127.0.0.1:9", &fixture.addr().to_string());
        let outcome = client(&text)
            .embed_once("emb", &["a".to_string()], InputKind::Query)
            .expect("alias accepted");
        assert_eq!(outcome.identity.response_model.as_deref(), Some("m-alias"));
    }

    #[test]
    fn a_dimension_mismatch_is_refused() {
        let fixture = HttpFixture::start(vec![Reply::ok(embedding_rows(&[vec![1.0, 0.0]]))]);
        let text = embedding_config(&fixture.base(), "expected_dimension = 3\n");
        let failure = client(&text)
            .embed_once("emb", &["a".to_string()], InputKind::Query)
            .expect_err("dimension");
        assert_eq!(failure.error().code(), ApiCallErrorCode::DimensionMismatch);

        let fixture = HttpFixture::start(vec![Reply::ok(embedding_rows(&[vec![1.0, 0.0]]))]);
        let text = embedding_config(&fixture.base(), "request_dimensions = 3\n");
        let failure = client(&text)
            .embed_once("emb", &["a".to_string()], InputKind::Query)
            .expect_err("requested dimension");
        assert_eq!(failure.error().code(), ApiCallErrorCode::DimensionMismatch);
    }

    #[test]
    fn a_malformed_rerank_response_is_refused() {
        let cases: Vec<(&str, Value)> = vec![
            (
                "missing row",
                json!({"results": [{"index": 0, "relevance_score": 1.0}]}),
            ),
            (
                "duplicate index",
                json!({"results": [
                    {"index": 0, "relevance_score": 1.0},
                    {"index": 0, "relevance_score": 0.5},
                ]}),
            ),
            (
                "out of range index",
                json!({"results": [
                    {"index": 0, "relevance_score": 1.0},
                    {"index": 9, "relevance_score": 0.5},
                ]}),
            ),
            (
                "mixed shapes in a results array",
                json!({"results": [
                    {"index": 0, "relevance_score": 1.0, "score": 1.0},
                    {"index": 1, "relevance_score": 0.5},
                ]}),
            ),
            (
                "mixed shapes in a native array",
                json!([
                    {"index": 0, "score": 1.0, "relevance_score": 1.0},
                    {"index": 1, "score": 0.5},
                ]),
            ),
            ("no results field", json!({"scores": [1.0, 0.5]})),
        ];
        for (label, body) in cases {
            let fixture = HttpFixture::start(vec![Reply::ok(body)]);
            let text = format!(
                r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}/r"
scope = "loopback"
model = "m"
model_revision = "r"
"#,
                base = fixture.base()
            );
            let documents = documents(2);
            let failure = client(&text)
                .rerank_once("rr", "q", &documents)
                .expect_err(label);
            assert_eq!(
                failure.error().code(),
                ApiCallErrorCode::InvalidResponse,
                "{label}"
            );
        }
    }

    #[test]
    fn a_malformed_body_after_a_200_keeps_the_observed_status() {
        let fixture = HttpFixture::start(vec![Reply::raw(
            "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nnot-json",
        )]);
        let text = format!(
            r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}/r"
scope = "loopback"
model = "m"
model_revision = "r"
"#,
            base = fixture.base()
        );
        let documents = documents(1);
        let failure = client(&text)
            .rerank_once("rr", "q", &documents)
            .expect_err("malformed body");
        assert_eq!(failure.error().code(), ApiCallErrorCode::InvalidResponse);
        assert_eq!(failure.attempts().len(), 1);
        assert_eq!(
            failure.attempts()[0].http_status,
            Some(200),
            "the service answered, so the status is evidence"
        );
        assert_eq!(failure.attempts()[0].error_code, Some("invalid_response"));
    }

    #[test]
    fn an_unrepresentable_embedding_is_refused_over_the_wire() {
        let cases: Vec<(&str, f64, &str, bool)> = vec![
            ("a normal component passes", 1.0, "none", true),
            ("f32 overflow becomes infinity", 1e40, "none", false),
            ("f32 underflow becomes zero", 1e-50, "none", false),
            // `l2` normalizes a large finite component to a unit vector, so the
            // stored value stays representable.
            ("l2 keeps a large finite component", 1e40, "l2", true),
        ];
        for (label, component, normalization, accepted) in cases {
            let fixture = HttpFixture::start(vec![Reply::ok(embedding_rows(&[vec![component]]))]);
            let text = embedding_config_norm(&fixture.base(), normalization, "");
            let outcome = client(&text).embed_once("emb", &["a".to_string()], InputKind::Query);
            match (accepted, outcome) {
                (true, Ok(outcome)) => {
                    assert_eq!(outcome.vectors.len(), 1, "{label}");
                    assert!(
                        outcome.vectors[0].iter().all(|value| value.is_finite()),
                        "{label}: finite"
                    );
                    assert!(
                        outcome.vectors[0].iter().any(|value| *value != 0.0),
                        "{label}: non zero"
                    );
                }
                (false, Err(failure)) => {
                    assert_eq!(
                        failure.error().code(),
                        ApiCallErrorCode::InvalidResponse,
                        "{label}"
                    );
                    assert_eq!(fixture.hits(), 1, "{label}: the request was made");
                }
                (accepted, other) => panic!("{label}: expected accepted={accepted}, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_openrouter_rerank_protocol_refuses_a_native_array() {
        let native = HttpFixture::start(vec![Reply::ok(rerank_native(2))]);
        let text = format!(
            r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "openrouter-rerank-v1"
endpoint = "{base}/r"
scope = "loopback"
model = "m"
model_revision = "r"
"#,
            base = native.base()
        );
        let documents = documents(2);
        let failure = client(&text)
            .rerank_once("rr", "q", &documents)
            .expect_err("native array on the cloud protocol");
        assert_eq!(failure.error().code(), ApiCallErrorCode::InvalidResponse);

        // The same profile still accepts the standard envelope.
        let envelope = HttpFixture::start(vec![Reply::ok(rerank_results(2))]);
        let text = text.replace(&native.base(), &envelope.base());
        let outcome = client(&text)
            .rerank_once("rr", "q", &documents)
            .expect("envelope accepted");
        assert_eq!(outcome.scores, vec![2.0, 1.0]);
    }

    #[test]
    fn a_probe_failure_records_its_short_code() {
        let fixture = HttpFixture::start(vec![Reply::ok(json!({}))]);
        let text = embedding_with_models(&fixture.base(), Some(&fixture.base()));
        let failure = client(&text).probe_models("emb").expect_err("no data");
        assert_eq!(failure.error().code(), ApiCallErrorCode::InvalidResponse);
        assert_eq!(failure.attempts().len(), 1);
        assert_eq!(failure.attempts()[0].error_code, Some("InvalidResponse"));
        assert_eq!(failure.attempts()[0].http_status, Some(200));

        let fixture = HttpFixture::start(vec![Reply::ok(json!({"data": [{"id": "other"}]}))]);
        let text = embedding_with_models(&fixture.base(), Some(&fixture.base()));
        let failure = client(&text).probe_models("emb").expect_err("model absent");
        assert_eq!(failure.attempts()[0].error_code, Some("IdentityMismatch"));
        assert_eq!(failure.attempts()[0].http_status, Some(200));
    }

    #[test]
    fn a_broken_or_oversized_body_is_refused() {
        let fixture = HttpFixture::start(vec![Reply::raw(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n{\"a\":",
        )]);
        let text = format!(
            r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}/r"
scope = "loopback"
model = "m"
model_revision = "r"
"#,
            base = fixture.base()
        );
        let documents = documents(1);
        let failure = client(&text)
            .rerank_once("rr", "q", &documents)
            .expect_err("truncated json");
        assert_eq!(failure.error().code(), ApiCallErrorCode::InvalidResponse);

        let mut body = String::from("{\"results\":[]}");
        while body.len() <= 4096 {
            body.push(' ');
        }
        let fixture = HttpFixture::start(vec![Reply::raw(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ))]);
        let text = format!(
            r#"
version = 1
[profiles.rr]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{base}/r"
scope = "loopback"
model = "m"
model_revision = "r"
max_response_bytes = 64
"#,
            base = fixture.base()
        );
        let failure = client(&text)
            .rerank_once("rr", "q", &documents)
            .expect_err("oversized");
        assert_eq!(failure.error().code(), ApiCallErrorCode::InvalidResponse);
    }

    // ------------------------------------------------------------------
    // Single-hop cloud fallback.
    // ------------------------------------------------------------------

    /// The rerank pair with extra primary fields, full endpoint URLs.
    fn rerank_pair_full(
        primary_endpoint: &str,
        primary_extra: &str,
        fallback_endpoint: &str,
    ) -> String {
        format!(
            r#"
version = 1
default_rerank = "local"

[profiles.local]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "{primary_endpoint}"
scope = "loopback"
model = "local-reranker"
model_revision = "rev-local"
fallback_profile = "cloud"
{primary_extra}

[profiles.cloud]
kind = "rerank"
protocol = "openrouter-rerank-v1"
endpoint = "{fallback_endpoint}"
scope = "remote"
model = "cloud-reranker"
model_revision = "rev-cloud"
provider_only = "pinned-vendor"
"#
        )
    }

    /// A client over `text` whose transports also trust `ca_pem`.
    fn client_trusting(text: &str, ca_pem: &[u8], credentials: FixedCredentials) -> ApiClient {
        ApiClient::new_with_test_root(parse(text), Box::new(credentials), ca_pem.to_vec())
    }

    #[test]
    fn a_connection_refusal_falls_back_to_the_cloud() {
        let refused = HttpFixture::refused_address();
        let cloud = TlsFixture::start(vec![Reply::ok(rerank_results(2))]);
        let text = rerank_pair(&format!("http://{refused}"), &cloud.base());
        let api = client_trusting(&text, cloud.ca_pem(), FixedCredentials::default());

        let documents = documents(2);
        let outcome = api
            .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
            .expect("fallback");

        assert!(outcome.fallback_used);
        assert_eq!(outcome.realized_profile, "cloud");
        assert_eq!(outcome.fallback_reason, Some("connection_refused"));
        assert_eq!(outcome.scores, vec![2.0, 1.0]);
        assert_eq!(outcome.attempts.len(), 2);
        assert_eq!(outcome.attempts[0].profile_id, "local");
        assert_eq!(outcome.attempts[0].error_code, Some("connection_refused"));
        assert_eq!(outcome.attempts[1].profile_id, "cloud");
        assert_eq!(outcome.attempts[1].stage, AttemptStage::Fallback);
        assert_eq!(outcome.attempts[1].http_status, Some(200));
        assert_eq!(cloud.fixture().hits(), 1);
    }

    #[test]
    fn an_http_500_on_the_primary_falls_back() {
        let primary = HttpFixture::start(vec![Reply::status(500)]);
        let cloud = TlsFixture::start(vec![Reply::ok(rerank_results(1))]);
        let text = rerank_pair(&primary.base(), &cloud.base());
        let api = client_trusting(&text, cloud.ca_pem(), FixedCredentials::default());

        let documents = documents(1);
        let outcome = api
            .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
            .expect("fallback");
        assert!(outcome.fallback_used);
        assert_eq!(outcome.fallback_reason, Some("http_status"));
        assert_eq!(outcome.attempts[0].http_status, Some(500));
        assert_eq!(primary.hits(), 1);
        assert_eq!(cloud.fixture().hits(), 1);
    }

    #[test]
    fn a_read_timeout_on_the_primary_falls_back() {
        let primary = HttpFixture::start(vec![Reply::Stall]);
        let cloud = TlsFixture::start(vec![Reply::ok(rerank_results(1))]);
        let text = rerank_pair_full(
            &format!("{}/rerank", primary.base()),
            "connect_timeout_ms = 400\ntimeout_ms = 400",
            &format!("{}/api/v1/rerank", cloud.base()),
        );
        let api = client_trusting(&text, cloud.ca_pem(), FixedCredentials::default());

        let documents = documents(1);
        let outcome = api
            .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
            .expect("fallback");
        assert!(outcome.fallback_used);
        assert_eq!(outcome.fallback_reason, Some("timeout"));
        assert_eq!(outcome.attempts[0].error_code, Some("timeout"));
    }

    #[test]
    fn the_whole_window_is_resent_and_partial_scores_are_never_mixed() {
        let primary = HttpFixture::start(vec![Reply::status(500)]);
        let cloud = TlsFixture::start(vec![Reply::ok(rerank_results(5))]);
        let text = rerank_pair(&primary.base(), &cloud.base());
        let api = client_trusting(&text, cloud.ca_pem(), FixedCredentials::default());

        let documents = documents(5);
        let outcome = api
            .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
            .expect("fallback");
        assert!(outcome.fallback_used);

        let resent = cloud.fixture().requests();
        assert_eq!(resent.len(), 1, "exactly one cloud request");
        let body = resent[0].body();
        assert_eq!(
            body["documents"],
            json!(documents),
            "same order, full window"
        );
        assert_eq!(body["top_n"], json!(5));
        assert_eq!(outcome.scores, vec![5.0, 4.0, 3.0, 2.0, 1.0]);
    }

    #[test]
    fn a_cloud_failure_stops_after_two_attempts() {
        let primary = HttpFixture::start(vec![Reply::status(500)]);
        let cloud = TlsFixture::start(vec![Reply::status(500)]);
        let text = rerank_pair(&primary.base(), &cloud.base());
        let api = client_trusting(&text, cloud.ca_pem(), FixedCredentials::default());

        let documents = documents(2);
        let failure = api
            .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
            .expect_err("both fail");
        assert_eq!(failure.error().code(), ApiCallErrorCode::HttpStatus);
        assert_eq!(failure.error().http_status(), Some(500));
        assert_eq!(failure.attempts().len(), 2);
        assert_eq!(primary.hits(), 1, "the primary is attempted once");
        assert_eq!(cloud.fixture().hits(), 1, "the cloud is attempted once");
    }

    #[test]
    fn disabling_fallback_sends_no_cloud_request() {
        let refused = HttpFixture::refused_address();
        let cloud = TlsFixture::start(vec![Reply::ok(rerank_results(2))]);
        let text = rerank_pair(&format!("http://{refused}"), &cloud.base());
        let api = client_trusting(&text, cloud.ca_pem(), FixedCredentials::default());

        let documents = documents(2);
        let failure = api
            .rerank_with_fallback(
                "local",
                "q",
                &documents,
                RerankOptions::with_fallback(false),
            )
            .expect_err("disabled");
        assert_eq!(failure.error().code(), ApiCallErrorCode::Transport);
        assert_eq!(failure.attempts().len(), 1);
        assert_eq!(cloud.fixture().hits(), 0, "no cloud request may be sent");
    }

    #[test]
    fn a_cancellation_seen_before_the_send_stops_the_request() {
        // The credential resolver flips the flag while the transport is being
        // built, so the flag is set strictly after the call-level pre-check and
        // strictly before the request body exists. Nothing may be sent.
        let cloud = TlsFixture::start(vec![Reply::ok(rerank_results(2))]);
        let text = rerank_pair_full(
            &format!("http://127.0.0.1:9/rerank"),
            "api_key_env = \"PRIMARY_KEY\"",
            &format!("{}/api/v1/rerank", cloud.base()),
        );

        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let mut credentials = FixedCredentials::with(&[("PRIMARY_KEY", "synthetic-token")]);
        credentials.on_lookup = Some(Box::new(move || flag.store(true, Ordering::SeqCst)));
        let api = client_trusting(&text, cloud.ca_pem(), credentials);

        let documents = documents(2);
        let options = RerankOptions {
            allow_fallback: true,
            cancel: Some(&cancel),
        };
        let failure = api
            .rerank_with_fallback("local", "q", &documents, options)
            .expect_err("cancelled before the send");
        assert_eq!(failure.error().code(), ApiCallErrorCode::Cancelled);
        assert_eq!(failure.attempts().len(), 1);
        assert!(
            !failure.attempts()[0].network_attempted,
            "no request may be sent once the flag is set"
        );
        assert_eq!(failure.attempts()[0].http_status, None);
        assert_eq!(cloud.fixture().hits(), 0, "no cloud request may be sent");
    }

    #[test]
    fn a_cancellation_seen_after_a_successful_response_is_not_a_success() {
        // The service sets the flag and then answers a valid 200. The call must
        // not report success, and the record must keep the status it really
        // received rather than pretending the network was never touched.
        let cancel = Arc::new(AtomicBool::new(false));
        let primary = HttpFixture::start(vec![Reply::after_setting(
            cancel.clone(),
            Reply::ok(rerank_results(2)),
        )]);
        let cloud = TlsFixture::start(vec![Reply::ok(rerank_results(2))]);
        let text = rerank_pair(&primary.base(), &cloud.base());
        let api = client_trusting(&text, cloud.ca_pem(), FixedCredentials::default());

        let documents = documents(2);
        let options = RerankOptions {
            allow_fallback: true,
            cancel: Some(&cancel),
        };
        let failure = api
            .rerank_with_fallback("local", "q", &documents, options)
            .expect_err("cancelled after the response");
        assert_eq!(failure.error().code(), ApiCallErrorCode::Cancelled);
        assert_eq!(failure.attempts().len(), 1);
        assert!(
            failure.attempts()[0].network_attempted,
            "the request really went out"
        );
        assert_eq!(
            failure.attempts()[0].http_status,
            Some(200),
            "the service really answered"
        );
        assert_eq!(primary.hits(), 1);
        assert_eq!(cloud.fixture().hits(), 0, "no cloud request may be sent");
    }

    #[test]
    fn ineligible_failures_never_reach_the_cloud() {
        let cases: Vec<(&str, Reply)> = vec![
            ("400", Reply::status(400)),
            ("401", Reply::status(401)),
            ("403", Reply::status(403)),
            ("501", Reply::status(501)),
            ("507", Reply::status(507)),
            (
                "redirect",
                Reply::raw(
                    "HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                ),
            ),
            (
                "truncated json",
                Reply::raw(
                    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n{\"a\":",
                ),
            ),
            (
                "identity mismatch",
                Reply::Json(
                    200,
                    json!({"results": [{"index": 0, "relevance_score": 1.0}], "model": "somebody-else"}),
                ),
            ),
            (
                "incomplete scores",
                Reply::Json(
                    200,
                    json!({"results": [{"index": 0, "relevance_score": 1.0}]}),
                ),
            ),
        ];
        for (label, reply) in cases {
            let primary = HttpFixture::start(vec![reply]);
            let cloud = TlsFixture::start(vec![Reply::ok(rerank_results(2))]);
            let text = rerank_pair(&primary.base(), &cloud.base());
            let api = client_trusting(&text, cloud.ca_pem(), FixedCredentials::default());
            let documents = documents(2);
            let failure = api
                .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
                .expect_err(label);
            assert_eq!(failure.attempts().len(), 1, "{label}");
            assert_eq!(
                cloud.fixture().hits(),
                0,
                "{label}: no cloud request may be sent"
            );
        }
    }

    #[test]
    fn an_untrusted_certificate_is_not_fallback_eligible() {
        // The primary presents a chain the client's trust store does not know,
        // even though a different fixture's CA is trusted. The handshake really
        // happens and really fails.
        let untrusted = TlsFixture::start(vec![Reply::ok(rerank_results(2))]);
        let trusted = TlsFixture::start(vec![Reply::ok(rerank_results(2))]);
        let text = rerank_pair(&untrusted.base(), &trusted.base());
        let api = client_trusting(&text, trusted.ca_pem(), FixedCredentials::default());

        let documents = documents(2);
        let failure = api
            .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
            .expect_err("untrusted tls");
        assert_eq!(failure.error().code(), ApiCallErrorCode::Transport);
        assert_eq!(
            failure.error().transport_code(),
            Some("unclassified_transport")
        );
        assert_eq!(failure.attempts().len(), 1);
        assert!(
            untrusted.fixture().hits() >= 1,
            "a real handshake must have been attempted"
        );
        assert_eq!(trusted.fixture().hits(), 0, "no cloud request may be sent");
    }

    #[test]
    fn a_trusted_certificate_serves_the_window_over_real_tls() {
        let tls = TlsFixture::start(vec![Reply::ok(rerank_results(2))]);
        let unused = TlsFixture::start(vec![Reply::ok(rerank_results(2))]);
        let text = rerank_pair(&tls.base(), &unused.base());
        let api = client_trusting(&text, tls.ca_pem(), FixedCredentials::default());

        let documents = documents(2);
        let outcome = api
            .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
            .expect("tls window");
        assert!(!outcome.fallback_used);
        assert_eq!(outcome.realized_profile, "local");
        assert_eq!(outcome.scores, vec![2.0, 1.0]);
        assert_eq!(tls.fixture().hits(), 1);
    }

    #[test]
    fn the_next_call_prefers_the_primary_again() {
        let primary = HttpFixture::start(vec![Reply::status(500), Reply::ok(rerank_results(2))]);
        let cloud = TlsFixture::start(vec![Reply::ok(rerank_results(2))]);
        let text = rerank_pair(&primary.base(), &cloud.base());
        let api = client_trusting(&text, cloud.ca_pem(), FixedCredentials::default());
        let documents = documents(2);

        let first = api
            .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
            .expect("first");
        assert!(first.fallback_used);
        let cloud_hits = cloud.fixture().hits();

        let second = api
            .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
            .expect("second");
        assert!(!second.fallback_used, "no persistent health state");
        assert_eq!(second.realized_profile, "local");
        assert_eq!(cloud.fixture().hits(), cloud_hits);
    }

    #[test]
    fn a_local_success_never_touches_the_cloud_credential() {
        let primary = HttpFixture::start(vec![Reply::ok(rerank_results(2))]);
        let cloud = TlsFixture::start(vec![Reply::ok(rerank_results(2))]);
        let text = rerank_pair_full(
            &format!("{}/rerank", primary.base()),
            "",
            &format!("{}/api/v1/rerank", cloud.base()),
        )
        .replace(
            "provider_only = \"pinned-vendor\"",
            "provider_only = \"pinned-vendor\"\napi_key_env = \"CLOUD_KEY\"",
        );
        let credentials = Arc::new(FixedCredentials::with(&[("CLOUD_KEY", "synthetic-token")]));
        let api = ApiClient::new_with_test_root(
            parse(&text),
            Box::new(credentials.clone()),
            cloud.ca_pem().to_vec(),
        );

        let documents = documents(2);
        let outcome = api
            .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
            .expect("local window");
        assert!(!outcome.fallback_used);
        assert_eq!(cloud.fixture().hits(), 0);
        assert!(
            credentials.lookups().is_empty(),
            "an unused cloud credential must never be resolved"
        );
    }

    #[test]
    fn no_credential_or_response_body_reaches_the_error() {
        const TOKEN: &str = "sk-or-v1-SYNTHETIC-NOT-A-REAL-KEY-0000";
        const SECRET: &str = "SYNTHETIC_SECRET_DO_NOT_LEAK";

        let refused = HttpFixture::refused_address();
        let cloud = TlsFixture::start(vec![Reply::Json(
            401,
            json!({"error": {"message": SECRET}}),
        )]);
        let text = rerank_pair_full(
            &format!("http://{refused}/rerank"),
            "",
            &format!("{}/api/v1/rerank", cloud.base()),
        )
        .replace(
            "provider_only = \"pinned-vendor\"",
            "provider_only = \"pinned-vendor\"\napi_key_env = \"CLOUD_KEY\"",
        );
        let credentials = FixedCredentials::with(&[("CLOUD_KEY", TOKEN)]);
        let api = client_trusting(&text, cloud.ca_pem(), credentials);

        let documents = documents(2);
        let failure = api
            .rerank_with_fallback("local", "q", &documents, RerankOptions::with_fallback(true))
            .expect_err("cloud refuses");
        assert_eq!(failure.error().code(), ApiCallErrorCode::HttpStatus);
        assert_eq!(failure.error().http_status(), Some(401));

        let requests = cloud.fixture().requests();
        assert_eq!(requests.len(), 1);
        let expected = format!("bearer {}", TOKEN.to_ascii_lowercase());
        assert_eq!(
            requests[0].header("authorization"),
            Some(expected),
            "the selected cloud profile must carry its credential"
        );

        let rendered = format!("{failure}");
        let debugged = format!("{failure:?}");
        for text in [&rendered, &debugged] {
            assert!(!text.contains(SECRET), "body leaked: {text}");
            assert!(!text.contains(TOKEN), "token leaked: {text}");
        }
        assert!(!rendered.contains("example.invalid"));
    }

    // ------------------------------------------------------------------
    // Explicit metadata probe.
    // ------------------------------------------------------------------

    fn embedding_with_models(endpoint_base: &str, models: Option<&str>) -> String {
        let models = models
            .map(|base| format!("models_endpoint = \"{base}/v1/models\""))
            .unwrap_or_default();
        format!(
            r#"
version = 1
[profiles.emb]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "{endpoint_base}/v1/embeddings"
scope = "loopback"
model = "some-model"
model_revision = "rev-1"
normalization = "l2"
{models}
"#
        )
    }

    #[test]
    fn a_profile_without_a_metadata_endpoint_makes_no_request() {
        let fixture = HttpFixture::ok();
        let text = embedding_with_models(&fixture.base(), None);
        let failure = client(&text).probe_models("emb").expect_err("unsupported");
        assert_eq!(failure.error().code(), ApiCallErrorCode::UnsupportedProbe);
        assert!(failure.attempts().is_empty());
        assert_eq!(fixture.hits(), 0);
    }

    #[test]
    fn a_probe_is_one_get_and_needs_no_capability_field() {
        let fixture = HttpFixture::start(vec![Reply::ok(json!({
            "data": [{"id": "another-model"}, {"id": "some-model"}]
        }))]);
        let text = embedding_with_models(&fixture.base(), Some(&fixture.base()));
        let outcome = client(&text).probe_models("emb").expect("probe");

        assert!(outcome.model_listed);
        assert_eq!(outcome.identity, ObservedIdentity::default());
        assert_eq!(fixture.hits(), 1, "exactly one GET");
        assert_eq!(fixture.requests()[0].method(), "GET");
        assert_eq!(fixture.requests()[0].target(), "/v1/models");
        assert_eq!(outcome.attempts.len(), 1);
        assert_eq!(outcome.attempts[0].stage, AttemptStage::Probe);
    }

    #[test]
    fn a_probe_refuses_a_list_without_the_configured_model() {
        let fixture = HttpFixture::start(vec![Reply::ok(json!({
            "data": [{"id": "somebody-else"}]
        }))]);
        let text = embedding_with_models(&fixture.base(), Some(&fixture.base()));
        let failure = client(&text).probe_models("emb").expect_err("absent model");
        assert_eq!(failure.error().code(), ApiCallErrorCode::IdentityMismatch);
    }

    #[test]
    fn a_probe_refuses_a_response_without_a_data_array() {
        let fixture = HttpFixture::start(vec![Reply::ok(json!({"models": []}))]);
        let text = embedding_with_models(&fixture.base(), Some(&fixture.base()));
        let failure = client(&text).probe_models("emb").expect_err("no data");
        assert_eq!(failure.error().code(), ApiCallErrorCode::InvalidResponse);
    }
}
