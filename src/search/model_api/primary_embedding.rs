//! The primary-endpoint embedding driver for the API-only vector backfill.
//!
//! One command freezes one [`ValidatedProfile`] and one [`ApiClient`] and builds
//! this driver over them. It supplies the three things the shared catch-up loop
//! needs from an HTTP embedding primary (spec §§5.4, 6.1–6.2; API02D):
//!
//! * [`PrimaryEmbeddingCall::probe`] — one fresh probe per command. It sends the
//!   three fixed public sentinel texts as documents, measures the served width
//!   and concatenates the three returned vectors into the generation
//!   fingerprint. Nothing is cached across commands.
//! * [`PrimaryEmbeddingCall::embed_documents`] — a batched document embed that
//!   splits complete inputs on the profile's `max_batch` and records one evidence
//!   row per request. It never inserts a newline, truncates, drops or clips an
//!   input.
//! * [`PrimaryEmbeddingCall::embed_for_audit`] — the same HTTP implementation,
//!   batching and failure rules, recorded into the audit's own evidence array so
//!   the activation audit's verification requests are neither document batches
//!   nor probes.
//! * a typed, read-only answer for whether one refused call is in the frozen
//!   cloud-eligible failure set ([`PrimaryEmbedFailure::CompatibilityRequired`]).
//!
//! There is no local inference, no weight download and no Infinity dependency
//! here. The module never touches the database, so the byte-level record of what
//! was called is available to the caller even when a run fails midway.

use std::cell::{Cell, RefCell};
use std::fmt;

use super::client::{ApiCallFailure, ApiClient, EmbedOutcome};
use super::config::{ProfileKind, ValidatedProfile};
use super::error::{ConfigError, ConfigErrorCode};
use super::protocol::{InputKind, ObservedIdentity};
use super::routing;
use super::runtime::CheckUsage;
use crate::storage::schema::f32_vector_to_le_blob;

/// The three fixed public sentinel texts whose embeddings form a generation's
/// fingerprint.
///
/// These are the exact bytes the legacy Infinity path pinned in
/// `crate::search::infinity::FINGERPRINT_SENTINELS`; they are re-stated here
/// because that module is behind the `infinity` Cargo feature and this driver
/// must not depend on it. A `cfg(feature = "infinity")` unit test below pins the
/// two lists equal, so the two copies cannot drift.
///
/// Changing any sentence changes what every stored fingerprint means, so this is
/// not meant to be edited casually.
/// The bounded code one recorded request carries when its own response was
/// valid but its width disagreed with the width this command already fixed.
///
/// The request's HTTP status, service identity and usage stay recorded beside
/// it; only the code marks that this batch was refused on width.
pub const DIMENSION_DRIFT_CODE: &str = "DimensionDrift";

pub const API_PROBE_SENTINELS: [&str; 3] = [
    "The quick brown fox jumps over the lazy dog.",
    "今天天气不错，我们去公园散步吧。",
    "fn main() { println!(\"hello\"); }",
];

/// Why one primary-endpoint embedding request could not be completed.
#[derive(Debug, Clone, PartialEq)]
pub enum PrimaryEmbedFailure {
    /// The request itself was refused. It carries every attempt that happened.
    Call(ApiCallFailure),
    /// A response returned a width other than the one the probe established.
    DimensionDrift { expected: usize, observed: usize },
    /// Documents were submitted before any probe established the width.
    ProbeMissing,
    /// A checked route failed after recording all actual attempts.
    Routed { code: &'static str },
    /// The primary failed inside the frozen cloud-eligible set while a fallback
    /// was declared and not disabled. Producing vectors here would need the
    /// cross-endpoint compatibility evidence of spec §6.4. Without valid
    /// evidence the batch is refused before any backup request.
    CompatibilityRequired { code: &'static str },
}

impl PrimaryEmbedFailure {
    /// The bounded operator-facing message. It carries short codes and numbers
    /// only — never a response body, a credential or a request payload.
    pub fn message(&self) -> String {
        match self {
            Self::Call(failure) => failure.to_string(),
            Self::Routed { code } => format!("embedding route failed: {code}"),
            Self::DimensionDrift { expected, observed } => format!(
                "embedding response width {observed} differs from the probed width {expected}"
            ),
            Self::ProbeMissing => {
                "embedding documents were requested before the command probed the endpoint width"
                    .to_string()
            }
            Self::CompatibilityRequired { code } => format!(
                "CompatibilityRequired: the embedding primary failed in the eligible set ({code}) \
                 and a fallback is declared; this route has no verified cross-endpoint \
                 compatibility evidence, so the batch was not sent to the fallback and no \
                 vectors were produced"
            ),
        }
    }

    /// Whether this failure is the compatibility-required refusal.
    pub fn is_compatibility_required(&self) -> bool {
        matches!(self, Self::CompatibilityRequired { .. })
    }
}

impl fmt::Display for PrimaryEmbedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for PrimaryEmbedFailure {}

/// One recorded embedding request, successful or not.
///
/// The `stage` field separates the probe's own requests from the document
/// batches, which are counted apart everywhere. Every identity field is what the
/// service reported, so an unreported value stays `None`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct EmbeddingCallEvidence {
    /// `probe` or `document`.
    pub stage: &'static str,
    /// The profile this request used.
    pub profile_id: String,
    /// Whether bytes were actually sent towards the service.
    pub network_attempted: bool,
    /// The HTTP status observed, when one was.
    pub http_status: Option<u16>,
    /// The bounded failure code, when this request failed.
    pub error_code: Option<&'static str>,
    /// The measured duration, in milliseconds.
    pub duration_ms: u64,
    /// The model the response named, when it named one.
    pub response_model: Option<String>,
    /// The revision the response named, when it named one.
    pub response_revision: Option<String>,
    /// The serving provider the response named, when it named one.
    pub serving_provider: Option<String>,
    /// The usage the response reported, when it reported any.
    pub usage: Option<CheckUsage>,
}

/// What one fresh probe established.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeMeasurement {
    /// The width every sentinel vector actually had.
    pub dimension: usize,
    /// The three sentinel vectors, in sentinel order, as LE f32 bytes.
    pub fingerprint: Vec<u8>,
}

/// The `model_api` object reported next to the existing backfill result fields.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ModelApiBackfillReport {
    /// The profile id that produced these vectors.
    pub primary_profile: String,
    /// The model the requests carried.
    pub requested_model: String,
    /// The revision the configuration declares.
    pub declared_revision: String,
    /// The representation descriptor digest of the generation.
    pub descriptor_sha256: String,
    /// The call-configuration digest of the endpoint.
    pub endpoint_config_sha256: String,
    /// The effective fallback policy of this command.
    pub allow_fallback: bool,
    /// Always `false`: this build never produces vectors at the fallback.
    pub fallback_used: bool,
    /// The probe requests this command made, in order.
    pub probe_calls: Vec<EmbeddingCallEvidence>,
    /// The document requests the drain made, in order.
    pub document_calls: Vec<EmbeddingCallEvidence>,
    /// The requests the activation audit's own verification made, in order.
    ///
    /// The audit re-embeds the fingerprint sentinels and an ownership sample of
    /// stored chunk texts over the same endpoint and the same HTTP
    /// implementation as the drain. A repeat run of an already-complete
    /// generation sends no document batches at all, but its audit still runs and
    /// its requests are recorded here rather than being folded into either of
    /// the other two arrays.
    pub audit_calls: Vec<EmbeddingCallEvidence>,
}

/// Which evidence array a recorded request belongs to.
///
/// The three arrays are disjoint by construction: a request is recorded exactly
/// once, in the array of the phase that actually made it. The activation audit's
/// verification requests are neither probes nor document batches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceStage {
    Probe,
    Document,
    Audit,
}

impl EvidenceStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Document => "document",
            Self::Audit => "audit",
        }
    }
}

/// One frozen embedding primary, with the call evidence it has accumulated.
///
/// The type is single-threaded by construction (`Cell`/`RefCell`), matching the
/// single catch-up loop that drives it. The evidence buffers are written on both
/// success and failure, so a caller can report exactly which requests happened
/// even when the run aborted.
pub struct PrimaryEmbeddingCall {
    client: ApiClient,
    route: super::embedding_route::EmbeddingRoute,
    profile: ValidatedProfile,
    allow_fallback: bool,
    probed_dimension: Cell<usize>,
    probe_calls: RefCell<Vec<EmbeddingCallEvidence>>,
    document_calls: RefCell<Vec<EmbeddingCallEvidence>>,
    audit_calls: RefCell<Vec<EmbeddingCallEvidence>>,
    last_failure: RefCell<Option<PrimaryEmbedFailure>>,
    page_writers: RefCell<Vec<ValidatedProfile>>,
    probe_writers: RefCell<Vec<ValidatedProfile>>,
    fallback_used: Cell<bool>,
}

impl PrimaryEmbeddingCall {
    /// Freeze one embedding profile and its client.
    ///
    /// A rerank profile is refused here rather than at the first request, so a
    /// mis-selected `--embedding-profile` is a configuration error before any
    /// database or network work.
    pub fn new(
        client: ApiClient,
        profile: ValidatedProfile,
        allow_fallback: bool,
    ) -> Result<Self, ConfigError> {
        if profile.kind != ProfileKind::Embedding || profile.embedding().is_none() {
            return Err(ConfigError::at(ConfigErrorCode::KindMismatch, "kind"));
        }
        let route = super::embedding_route::EmbeddingRoute::load(client.config(), &profile, allow_fallback);
        Ok(Self {
            route,
            client,
            profile,
            allow_fallback,
            probed_dimension: Cell::new(0),
            probe_calls: RefCell::new(Vec::new()),
            document_calls: RefCell::new(Vec::new()),
            audit_calls: RefCell::new(Vec::new()),
            last_failure: RefCell::new(None),
            page_writers: RefCell::new(Vec::new()),
            probe_writers: RefCell::new(Vec::new()),
            fallback_used: Cell::new(false),
        })
    }

    pub(crate) fn route(&self) -> &super::embedding_route::EmbeddingRoute {
        &self.route
    }

    pub(crate) fn probe_writers(&self) -> Vec<ValidatedProfile> {
        self.probe_writers.borrow().clone()
    }

    pub(crate) fn page_writers(&self) -> Vec<ValidatedProfile> {
        self.page_writers.borrow().clone()
    }

    /// The frozen profile.
    pub fn profile(&self) -> &ValidatedProfile {
        &self.profile
    }

    /// Whether this command may use the profile's declared fallback at all.
    pub fn allow_fallback(&self) -> bool {
        self.allow_fallback
    }

    /// Whether any successful request in this command used its backup.
    pub fn fallback_used(&self) -> bool { self.fallback_used.get() }

    /// The width the probe established, or `0` before any probe ran.
    pub fn dimension(&self) -> usize {
        self.probed_dimension.get()
    }

    /// Every probe request this command made, in order.
    pub fn probe_calls(&self) -> Vec<EmbeddingCallEvidence> {
        self.probe_calls.borrow().clone()
    }

    /// Every document request the drain made, in order.
    pub fn document_calls(&self) -> Vec<EmbeddingCallEvidence> {
        self.document_calls.borrow().clone()
    }

    /// Every request the activation audit's own verification made, in order.
    pub fn audit_calls(&self) -> Vec<EmbeddingCallEvidence> {
        self.audit_calls.borrow().clone()
    }

    /// The refusal of the last request that failed, when one did.
    pub fn last_failure(&self) -> Option<PrimaryEmbedFailure> {
        self.last_failure.borrow().clone()
    }

    /// Build the `model_api` report over the digests the caller computed.
    pub fn model_api_report(
        &self,
        descriptor_sha256: String,
        endpoint_config_sha256: String,
    ) -> ModelApiBackfillReport {
        ModelApiBackfillReport {
            primary_profile: self.profile.id.clone(),
            requested_model: self.profile.model.clone(),
            declared_revision: self.profile.model_revision.clone(),
            descriptor_sha256,
            endpoint_config_sha256,
            allow_fallback: self.allow_fallback,
            fallback_used: self.fallback_used.get(),
            probe_calls: self.probe_calls(),
            document_calls: self.document_calls(),
            audit_calls: self.audit_calls(),
        }
    }

    /// Run one fresh probe: send the three sentinels as documents, require one
    /// width across every request, and concatenate the three vectors into the
    /// fingerprint.
    ///
    /// The probe's requests are recorded separately from document batches. A
    /// second probe on this same call re-probes the live endpoint; nothing is
    /// cached across commands.
    pub(crate) fn invalidate_probe(&self) {
        self.probed_dimension.set(0);
        self.probe_writers.borrow_mut().clear();
        self.page_writers.borrow_mut().clear();
    }

    pub fn probe(&self) -> Result<ProbeMeasurement, PrimaryEmbedFailure> {
        self.invalidate_probe();
        let mut writers = Vec::<ValidatedProfile>::new();
        let mut vectors: Vec<Vec<f32>> = Vec::with_capacity(API_PROBE_SENTINELS.len());
        let mut dimension: Option<usize> = None;
        for batch in API_PROBE_SENTINELS.chunks(self.max_batch()) {
            let inputs: Vec<String> = batch.iter().map(|text| (*text).to_string()).collect();
            let outcome = if let Some(proof) = &self.route.proof {
                self.route.embed(&self.client, &inputs, InputKind::Document, proof.primary_dimension(),
                    &proof.header().primary_descriptor_sha256)
                    .map_err(|failure| self.record_route_failure(failure, EvidenceStage::Probe))?
            } else {
                match self.client.embed_once(&self.profile.id, &inputs, InputKind::Document) {
                    Ok(outcome) => outcome,
                    Err(failure) => return Err(self.record_failure(failure, EvidenceStage::Probe)),
                }
            };
            self.record_successful_producer(&outcome, &mut writers);
            match dimension {
                None => {
                    dimension = Some(outcome.dimension);
                    self.record_success(&outcome, EvidenceStage::Probe);
                }
                Some(seen) if seen != outcome.dimension => {
                    // The request itself succeeded and its HTTP status, service
                    // identity and usage are real evidence: record them with the
                    // bounded drift code rather than as a plain success.
                    self.record_outcome(&outcome, EvidenceStage::Probe, Some(DIMENSION_DRIFT_CODE));
                    return Err(self.record_typed(PrimaryEmbedFailure::DimensionDrift {
                        expected: seen,
                        observed: outcome.dimension,
                    }));
                }
                Some(_) => {
                    self.record_success(&outcome, EvidenceStage::Probe);
                }
            }
            vectors.extend(outcome.vectors);
        }
        // `API_PROBE_SENTINELS` is non-empty and `max_batch` is at least one, so
        // `chunks` always yields at least one batch and `dimension` is set.
        let dimension = dimension.expect("a non-empty sentinel list always yields one probe batch");
        self.probed_dimension.set(dimension);
        *self.probe_writers.borrow_mut() = writers;
        let mut fingerprint = Vec::with_capacity(vectors.len() * dimension * 4);
        for vector in &vectors {
            fingerprint.extend_from_slice(&f32_vector_to_le_blob(vector));
        }
        Ok(ProbeMeasurement {
            dimension,
            fingerprint,
        })
    }

    /// Embed one logical page's document texts for the drain.
    ///
    /// The page is split into complete `max_batch`-sized requests. Every request
    /// is fully validated before any vector is merged, so a failure in a later
    /// request returns no vectors for this page at all — the caller cannot write
    /// a half page. The requests are recorded as document batches.
    pub fn embed_documents(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, PrimaryEmbedFailure> {
        self.page_writers.borrow_mut().clear();
        self.embed_into(texts, EvidenceStage::Document)
    }

    /// Embed the activation audit's own verification inputs.
    ///
    /// This is the same HTTP implementation, the same batching and the same
    /// failure rules as [`Self::embed_documents`]; only the evidence array
    /// differs, so an audit request is never counted as a document batch (nor as
    /// a probe).
    pub fn embed_for_audit(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, PrimaryEmbedFailure> {
        self.embed_into(texts, EvidenceStage::Audit)
    }

    /// The one batched embed both phases share.
    fn embed_into(
        &self,
        texts: &[&str],
        stage: EvidenceStage,
    ) -> Result<Vec<Vec<f32>>, PrimaryEmbedFailure> {
        let expected = self.probed_dimension.get();
        if expected == 0 {
            return Err(self.record_typed(PrimaryEmbedFailure::ProbeMissing));
        }
        let inputs: Vec<String> = texts.iter().map(|text| (*text).to_string()).collect();
        let mut vectors: Vec<Vec<f32>> = Vec::with_capacity(inputs.len());
        let mut writers = Vec::<ValidatedProfile>::new();
        for batch in inputs.chunks(self.max_batch()) {
            let outcome = if self.route.proof.is_some() {
                let descriptor = super::RepresentationDescriptor::from_profile(&self.profile, expected as u64)
                    .map_err(|_| self.record_typed(PrimaryEmbedFailure::Routed { code: "InvalidDescriptor" }))?;
                match self.route.embed(&self.client, batch, InputKind::Document, expected, &descriptor.sha256()) {
                    Ok(outcome) => outcome,
                    Err(failure) => return Err(self.record_route_failure(failure, stage)),
                }
            } else {
                match self.client.embed_once(&self.profile.id, batch, InputKind::Document) {
                    Ok(outcome) => outcome,
                    Err(failure) => return Err(self.record_failure(failure, stage)),
                }
            };
            if outcome.dimension != expected {
                // The response was a real, validated HTTP 200 with its own
                // service identity and usage; the only thing wrong with it is the
                // width. Record those facts with the bounded drift code so the
                // evidence never shows a failed batch as a plain success.
                self.record_outcome(&outcome, stage, Some(DIMENSION_DRIFT_CODE));
                return Err(self.record_typed(PrimaryEmbedFailure::DimensionDrift {
                    expected,
                    observed: outcome.dimension,
                }));
            }
            self.record_success(&outcome, stage);
            self.record_successful_producer(&outcome, &mut writers);
            vectors.extend(outcome.vectors);
        }
        if matches!(stage, EvidenceStage::Document) { *self.page_writers.borrow_mut() = writers; }
        Ok(vectors)
    }
    /// The largest number of complete inputs one request may carry.
    fn max_batch(&self) -> usize {
        self.route.max_batch()
    }

    fn record_successful_producer(&self, outcome: &EmbedOutcome, writers: &mut Vec<ValidatedProfile>) {
        if let Some(attempt) = outcome.attempts.last() {
            if attempt.stage == super::AttemptStage::Fallback { self.fallback_used.set(true); }
            if let Some(writer) = self.client.config().profile(&attempt.profile_id) {
                if !writers.iter().any(|profile| profile.id == writer.id) { writers.push(writer.clone()); }
            }
        }
    }

    fn evidence_buffer(&self, stage: EvidenceStage) -> &RefCell<Vec<EmbeddingCallEvidence>> {
        match stage {
            EvidenceStage::Probe => &self.probe_calls,
            EvidenceStage::Document => &self.document_calls,
            EvidenceStage::Audit => &self.audit_calls,
        }
    }

    fn record_success(&self, outcome: &EmbedOutcome, stage: EvidenceStage) {
        self.record_outcome(outcome, stage, None);
    }

    /// Record one answered request, optionally attributing a bounded code to it.
    ///
    /// `override_code` names a reason the caller found after the response itself
    /// validated (a width disagreement), which the client's own attempt record
    /// cannot know about. The attempt's own code wins when it has one.
    fn record_outcome(
        &self,
        outcome: &EmbedOutcome,
        stage: EvidenceStage,
        override_code: Option<&'static str>,
    ) {
        let mut buffer = self.evidence_buffer(stage).borrow_mut();
        for attempt in &outcome.attempts {
            buffer.push(evidence_row(
                stage,
                &attempt.profile_id,
                attempt.network_attempted,
                attempt.http_status,
                override_code.or(attempt.error_code),
                attempt.duration_ms,
                &attempt.identity,
            ));
        }
    }

    fn record_route_failure(&self, failure: super::embedding_route::RoutedEmbedFailure, stage: EvidenceStage) -> PrimaryEmbedFailure {
        let mut buffer = self.evidence_buffer(stage).borrow_mut();
        for attempt in &failure.attempts {
            buffer.push(evidence_row(stage, &attempt.profile_id, attempt.network_attempted,
                attempt.http_status, attempt.error_code, attempt.duration_ms, &attempt.identity));
        }
        drop(buffer);
        self.record_typed(if failure.compatibility_required {
            PrimaryEmbedFailure::CompatibilityRequired { code: failure.code }
        } else { PrimaryEmbedFailure::Routed { code: failure.code } })
    }

    /// Record one refused request and classify it into a typed failure.
    fn record_failure(&self, failure: ApiCallFailure, stage: EvidenceStage) -> PrimaryEmbedFailure {
        {
            let mut buffer = self.evidence_buffer(stage).borrow_mut();
            for attempt in failure.attempts() {
                buffer.push(evidence_row(
                    stage,
                    &attempt.profile_id,
                    attempt.network_attempted,
                    attempt.http_status,
                    attempt.error_code,
                    attempt.duration_ms,
                    &attempt.identity,
                ));
            }
        }
        if self.allow_fallback
            && self.profile.fallback_profile.is_some()
            && routing::failure_allows_cloud_fallback(&failure)
        {
            return self.record_typed(PrimaryEmbedFailure::CompatibilityRequired {
                code: failure.error().code().as_str(),
            });
        }
        self.record_typed(PrimaryEmbedFailure::Call(failure))
    }

    /// Remember and return a typed failure with no request behind it.
    fn record_typed(&self, failure: PrimaryEmbedFailure) -> PrimaryEmbedFailure {
        *self.last_failure.borrow_mut() = Some(failure.clone());
        failure
    }
}

#[allow(clippy::too_many_arguments)]
fn evidence_row(
    stage: EvidenceStage,
    profile_id: &str,
    network_attempted: bool,
    http_status: Option<u16>,
    error_code: Option<&'static str>,
    duration_ms: u64,
    identity: &ObservedIdentity,
) -> EmbeddingCallEvidence {
    EmbeddingCallEvidence {
        stage: stage.as_str(),
        profile_id: profile_id.to_string(),
        network_attempted,
        http_status,
        error_code,
        duration_ms,
        response_model: identity.response_model.clone(),
        response_revision: identity.response_revision.clone(),
        serving_provider: identity.provider.clone(),
        usage: CheckUsage::from_observed(identity.usage.as_ref()),
    }
}

/// The probe sentinel list must stay byte-equal to the legacy Infinity list.
///
/// The legacy constant sits behind the `infinity` Cargo feature, so this test
/// only exists in a build that has it. It is the single pin keeping the two
/// copies from drifting, because a changed sentinel silently changes what every
/// stored generation fingerprint means.
#[cfg(all(test, feature = "infinity"))]
mod sentinel_parity_tests {
    use super::*;

    #[test]
    fn api_probe_sentinels_match_the_legacy_infinity_list() {
        assert_eq!(
            API_PROBE_SENTINELS,
            crate::search::infinity::FINGERPRINT_SENTINELS
        );
    }

    #[test]
    fn sentinel_embeddings_fill_the_fingerprint_layout() {
        // The fingerprint the probe builds must be exactly `3 * dim * 4` bytes,
        // the layout `fingerprint_matches` compares.
        let vectors: Vec<Vec<f32>> = vec![vec![0.5_f32; 4]; API_PROBE_SENTINELS.len()];
        let mut fingerprint = Vec::new();
        for vector in &vectors {
            fingerprint.extend_from_slice(&f32_vector_to_le_blob(vector));
        }
        assert_eq!(fingerprint.len(), API_PROBE_SENTINELS.len() * 4 * 4);
    }
}

#[cfg(test)]
mod page_writer_tests {
    use super::*;
    use super::super::compatibility_capture::tests::inputs;
    use super::super::test_support::{HttpFixture, Reply};

    #[cfg(not(windows))]
    #[test]
    fn complete_fallback_page_records_the_backup_as_writer() {
        use super::super::compatibility_bundle::tests::fallback_fixture;
        use super::super::test_support::TlsFixture;
        let primary = HttpFixture::start(vec![Reply::Embeddings(2), Reply::status(503)]);
        let backup = TlsFixture::start(vec![Reply::Embeddings(2)]);
        let (config, proof) = fallback_fixture(&primary.base(), &backup.base());
        let profile = config.profile("primary").unwrap().clone();
        let client = ApiClient::new_with_test_root(config, Box::new(super::super::EnvCredentialResolver), backup.ca_pem().to_vec());
        let mut call = PrimaryEmbeddingCall::new(client, profile, true).unwrap();
        call.route.proof_sha256 = Some(proof.digest().into());
        call.route.proof = Some(std::sync::Arc::new(proof));
        call.probe().unwrap();
        assert_eq!(call.embed_documents(&["first", "second"]).unwrap().len(), 2);
        assert_eq!(call.page_writers().iter().map(|p| p.id.as_str()).collect::<Vec<_>>(), vec!["backup"]);
        assert!(call.model_api_report("descriptor".into(), "endpoint".into()).fallback_used);
        let calls = call.document_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].http_status, Some(503));
        assert_eq!(calls[1].profile_id, "backup");
        assert_eq!(primary.hits(), 2);
        assert_eq!(backup.fixture().hits(), 1);
    }

    #[cfg(not(windows))]
    #[test]
    fn backup_can_probe_and_embed_when_primary_is_already_down() {
        use super::super::compatibility_bundle::tests::fallback_fixture;
        use super::super::test_support::TlsFixture;
        let primary = HttpFixture::start(vec![Reply::status(503)]);
        let backup = TlsFixture::start(vec![Reply::Embeddings(2)]);
        let (config, proof) = fallback_fixture(&primary.base(), &backup.base());
        let profile = config.profile("primary").unwrap().clone();
        let client = ApiClient::new_with_test_root(config, Box::new(super::super::EnvCredentialResolver), backup.ca_pem().to_vec());
        let mut call = PrimaryEmbeddingCall::new(client, profile, true).unwrap();
        call.route.proof_sha256 = Some(proof.digest().into());
        call.route.proof = Some(std::sync::Arc::new(proof));
        let probe = call.probe().unwrap();
        assert_eq!(probe.dimension, 2);
        assert_eq!(probe.fingerprint.len(), 3 * 2 * 4);
        assert_eq!(call.probe_writers().iter().map(|p|p.id.as_str()).collect::<Vec<_>>(), vec!["backup"]);
        assert_eq!(call.probe_calls().len(), 2);
        assert_eq!(call.probe_calls()[1].profile_id, "backup");
        assert_eq!(call.embed_documents(&["first", "second"]).unwrap().len(), 2);
        assert_eq!(call.page_writers()[0].id, "backup");
        assert_eq!(primary.hits(), 2);
        assert_eq!(backup.fixture().hits(), 2);
        call.route.allow_fallback = false;
        assert!(call.probe().is_err());
        assert_eq!(call.dimension(), 0, "a failed fresh probe must invalidate its old dimension");
        assert!(call.probe_writers().is_empty());
        assert!(call.page_writers().is_empty());
        assert_eq!(call.embed_documents(&["later"]).unwrap_err(), PrimaryEmbedFailure::ProbeMissing);
        assert_eq!(backup.fixture().hits(), 2);
    }

    #[cfg(not(windows))]
    #[test]
    fn backup_only_sqlite_backfill_activates_and_reuses_the_same_generation() {
        exercise_backup_sqlite_lifecycle(false);
    }

    #[cfg(not(windows))]
    #[test]
    fn failed_backup_page_rolls_back_contributor_and_vectors_then_resumes() {
        exercise_backup_sqlite_lifecycle(true);
    }

    #[cfg(not(windows))]
    fn exercise_backup_sqlite_lifecycle(inject_failure: bool) {
        use super::super::compatibility_bundle::tests::fallback_fixture;
        use super::super::test_support::TlsFixture;
        use crate::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
        use crate::storage::api::{TxMode, StorageError};
        use crate::storage::api_generation::open_api_generation_with_compatibility;
        use crate::indexer::db_vector_catchup::{run_api_primary_catchup_backfill, probe_api_backfill};
        let primary = HttpFixture::start(if inject_failure { vec![Reply::Embeddings(2), Reply::status(503)] } else { vec![Reply::status(503)] });
        let backup = TlsFixture::start(vec![Reply::Embeddings(2)]);
        let (config, proof) = fallback_fixture(&primary.base(), &backup.base());
        let profile = config.profile("primary").unwrap().clone();
        let client = ApiClient::new_with_test_root(config, Box::new(super::super::EnvCredentialResolver), backup.ca_pem().to_vec());
        let mut call = PrimaryEmbeddingCall::new(client, profile.clone(), true).unwrap();
        call.route.proof_sha256 = Some(proof.digest().into());
        call.route.proof = Some(std::sync::Arc::new(proof));
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("db.sqlite");
        let storage = crate::storage::sqlite::FrankenStorage::open(&path).unwrap();
        let agent = storage.ensure_agent(&Agent { id:None, slug:"claude_code".into(), name:"fixture".into(), version:None, kind:AgentKind::Cli }).unwrap();
        let texts = ["A synthetic document describes how to verify an embedding service response.",
            "Another synthetic document describes atomic storage and preserving vector provenance."];
        let messages = texts.iter().enumerate().map(|(idx,text)| Message {
            excluded:None, id:None, idx:idx as i64, role:MessageRole::User, author:None,
            created_at:Some(1000 + idx as i64), content:(*text).into(), extra_json:serde_json::Value::Null, snippets:vec![],
        }).collect();
        storage.insert_conversation_tree(agent, None, &Conversation {
            id:None, agent_slug:"claude_code".into(), workspace:None, external_id:Some("backup-fixture".into()),
            title:Some("backup fixture".into()), source_path:"/fixtures/backup.jsonl".into(),
            started_at:Some(1000), ended_at:Some(1002), approx_tokens:None, metadata_json:serde_json::Value::Null,
            messages, source_id:"local".into(), origin_host:None,
        }).unwrap();
        let mut probe = probe_api_backfill(&storage, &call).unwrap_or_else(|error| panic!("{error}"));
        if inject_failure {
            use crate::storage::{api_generation, schema};
            let ids: Vec<i64> = storage.raw().query_all_map("SELECT id FROM messages ORDER BY id", &[], |row| row.get_typed(0)).unwrap();
            let id = storage.raw().with_tx(TxMode::Immediate, |tx| {
                let id = api_generation::create_api_generation(tx, &profile, 2, &probe.fingerprint, 1).map_err(StorageError::from)?;
                let holes: Vec<_> = ids.iter().map(|id| (*id, 0u32)).collect();
                schema::seed_chunk_holes(tx, id, &holes, 1, "test_seed")?;
                Ok(id)
            }).unwrap();
            let key = api_generation::provenance_meta_key(id);
            let before: String = storage.raw().query_row_map("SELECT value FROM meta WHERE key=?1", &crate::storage::api::params![key.as_str()], |row|row.get_typed(0)).unwrap();
            storage.raw().execute_batch("CREATE TRIGGER reject_backup_page BEFORE INSERT ON message_chunks BEGIN SELECT RAISE(ABORT, 'synthetic page failure'); END;").unwrap();
            let failed = run_api_primary_catchup_backfill(&storage, 1, &call, &profile, &probe, 42);
            assert!(failed.is_err());
            let diagnostic = crate::api_backfill_failure_error("synthetic page failure".into(), false,
                &profile, &call, true, root.path(), &path);
            let report: serde_json::Value = serde_json::from_str(&diagnostic.message).unwrap();
            assert_eq!(report["model_api"]["fallback_used"], true,
                "CLI failure report must retain successful backup usage before SQL failure");
            assert!(backup.fixture().hits() > 0, "backup must actually produce the refused page");
            let after: String = storage.raw().query_row_map("SELECT value FROM meta WHERE key=?1", &crate::storage::api::params![key.as_str()], |row|row.get_typed(0)).unwrap();
            assert_eq!(before, after, "failed page must roll back the new backup contributor");
            for table in ["message_chunks", "chunk_staging"] {
                let count: i64 = storage.raw().query_row_map(&format!("SELECT COUNT(*) FROM {table}"), &[], |row|row.get_typed(0)).unwrap();
                assert_eq!(count, 0, "no partial vectors in {table}");
            }
            let active: i64 = storage.raw().query_row_map("SELECT is_active FROM embedding_generations WHERE id=?1", &crate::storage::api::params![id], |row|row.get_typed(0)).unwrap();
            assert_eq!(active, 0);
            storage.raw().execute_batch("DROP TRIGGER reject_backup_page;").unwrap();
            probe = probe_api_backfill(&storage, &call).unwrap_or_else(|error| panic!("{error}"));
        }
        let first = run_api_primary_catchup_backfill(&storage, 1, &call, &profile, &probe, 42).unwrap_or_else(|error| panic!("{error}"));
        assert!(first.catchup.activated);
        assert_eq!(first.catchup.chunks_embedded, 2);
        assert_eq!(first.catchup.vec0_rows, 2);
        assert_eq!(first.catchup.holes_after, 0);
        assert!(first.model_api.fallback_used);
        assert!(!call.audit_calls().is_empty(), "activation must run the real audit requests");
        let id = first.catchup.generation_id;
        let rows: i64 = storage.raw().query_row_map("SELECT COUNT(*) FROM message_chunks WHERE generation_id=?1",
            &crate::storage::api::params![id], |row| row.get_typed(0)).unwrap();
        assert_eq!(rows, 2);
        let document_attempts = call.document_calls().len();
        drop(storage);
        let storage = crate::storage::sqlite::FrankenStorage::open(&path).unwrap();
        let probe = probe_api_backfill(&storage, &call).unwrap_or_else(|error| panic!("{error}"));
        let second = run_api_primary_catchup_backfill(&storage, 1, &call, &profile, &probe, 42).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.catchup.generation_id, id);
        assert!(second.catchup.reused_existing_generation);
        assert_eq!(second.catchup.chunks_embedded, 0);
        assert_eq!(call.document_calls().len(), document_attempts);
        let verified = storage.raw().with_tx(TxMode::Deferred, |tx| open_api_generation_with_compatibility(
            tx, id, &profile, call.route.proof.as_ref().unwrap()).map_err(StorageError::from)).unwrap();
        assert_eq!(verified.provenance().contributors().len(), if inject_failure { 2 } else { 1 });
        assert!(verified.primary_contributor().is_err());
        assert_eq!(verified.provenance().contributors().last().unwrap().endpoint_config_sha256(),
            super::super::EndpointConfigIdentity::from_profile(call.route.fallback.as_ref().unwrap()).unwrap().sha256());
        let total_attempts = call.probe_calls().len() + call.document_calls().len() + call.audit_calls().len();
        assert_eq!(primary.hits(), backup.fixture().hits() + usize::from(inject_failure));
        assert_eq!(total_attempts, primary.hits() + backup.fixture().hits());
    }

    #[cfg(not(windows))]
    #[test]
    fn historical_producer_missing_from_proof_blocks_probe_before_any_http() {
        use super::super::compatibility_bundle::tests::{fallback_fixture, migration_fixture};
        use super::super::test_support::TlsFixture;
        use crate::storage::api::{TxMode, StorageError};
        use crate::storage::api_generation::create_api_generation;
        use crate::indexer::db_vector_catchup::probe_api_backfill;
        let primary = HttpFixture::start(vec![Reply::status(503)]);
        let backup = TlsFixture::start(vec![Reply::Embeddings(2)]);
        let (config, proof) = fallback_fixture(&primary.base(), &backup.base());
        let profile = config.profile("primary").unwrap().clone();
        let client = ApiClient::new_with_test_root(config, Box::new(super::super::EnvCredentialResolver), backup.ca_pem().to_vec());
        let mut call = PrimaryEmbeddingCall::new(client, profile, true).unwrap();
        call.route.proof_sha256 = Some(proof.digest().into());
        call.route.proof = Some(std::sync::Arc::new(proof));
        let root = tempfile::tempdir().unwrap();
        let storage = crate::storage::sqlite::FrankenStorage::open(&root.path().join("db.sqlite")).unwrap();
        let (_, old) = migration_fixture(&[1,2], 1, None);
        storage.raw().with_tx(TxMode::Immediate, |tx| create_api_generation(tx, &old[0], 2, &[1;24], 1)
            .map_err(StorageError::from)).unwrap();
        let error = probe_api_backfill(&storage, &call).err().expect("uncovered historical endpoint");
        assert!(error.to_string().contains("CompatibilityRequired"));
        assert!(call.probe_calls().is_empty());
        assert_eq!(primary.hits(), 0);
        assert_eq!(backup.fixture().hits(), 0);
        // An independently measured probe must not survive a rejected build preflight.
        call.probe().unwrap();
        assert_eq!(call.dimension(), 2);
        assert!(probe_api_backfill(&storage, &call).is_err());
        assert_eq!(call.dimension(), 0);
        assert!(call.probe_writers().is_empty());
        assert!(call.page_writers().is_empty());
        assert_eq!(primary.hits(), 1);
        assert_eq!(backup.fixture().hits(), 1);
        assert_eq!(call.embed_documents(&["stale state"]).unwrap_err(), PrimaryEmbedFailure::ProbeMissing);
    }

    #[test]
    fn only_a_complete_page_publishes_its_actual_writers() {
        let server = HttpFixture::start(vec![
            Reply::Embeddings(2), Reply::Embeddings(2), // probe
            Reply::Embeddings(2), Reply::Embeddings(2), // complete page
            Reply::Embeddings(2), Reply::status(503),   // incomplete next page
        ]);
        let (client, _, _, _) = inputs(&server);
        let profile = client.config().profile("archived").unwrap().clone();
        let call = PrimaryEmbeddingCall::new(client, profile, true).unwrap();
        call.probe().unwrap();
        assert!(call.page_writers().is_empty());
        assert_eq!(call.embed_documents(&["one", "two", "three"]).unwrap().len(), 3);
        assert_eq!(call.page_writers().iter().map(|p|p.id.as_str()).collect::<Vec<_>>(), vec!["archived"]);
        assert!(call.embed_documents(&["four", "five", "six"]).is_err());
        assert!(call.page_writers().is_empty(), "failed page must not retain the preceding page's writer");
        assert_eq!(server.hits(), 6);
        assert_eq!(call.document_calls().len(), 4);
        assert_eq!(call.document_calls().last().unwrap().http_status, Some(503));
    }
}
