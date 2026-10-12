//! A frozen embedding route. Optional proof failure never opens cloud access;
//! a matching pure primary can still be used without cross-endpoint evidence.
use std::sync::Arc;
use sha2::{Digest,Sha256};
use super::{ApiClient, ApiAttempt, AttemptStage, EmbedOutcome, InputKind, ValidatedApiConfig, ValidatedProfile};
use super::compatibility_bundle::{CheckedBundle,read_regular};
use crate::storage::api::{Tx,StorageError};
use crate::storage::api_generation::{VerifiedPrimaryGeneration,open_api_generation,open_api_generation_with_compatibility};

#[derive(Clone)]
pub(crate) struct EmbeddingRoute {
    pub primary: ValidatedProfile,
    pub fallback: Option<ValidatedProfile>,
    pub allow_fallback: bool,
    pub proof: Option<Arc<CheckedBundle>>,
    pub proof_sha256: Option<String>,
}
impl std::fmt::Debug for EmbeddingRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingRoute").field("profile", &self.primary.id)
            .field("proof_sha256", &self.proof_sha256).finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub(crate) struct RoutedEmbedFailure {
    pub code: &'static str,
    pub compatibility_required: bool,
    pub lexical_eligible: bool,
    pub attempts: Vec<ApiAttempt>,
}
impl EmbeddingRoute {
    pub(crate) fn load(config:&ValidatedApiConfig, primary:&ValidatedProfile, allow_fallback:bool)->Self {
        let fallback=primary.fallback_profile.as_deref().and_then(|id|config.profile(id)).cloned();
        let mut proof_sha256=None;
        let proof=config.compatibility_path(primary).ok().flatten().and_then(|path| {
            let bytes=read_regular(&path).ok()?;
            proof_sha256=Some(hex::encode(Sha256::digest(&bytes)));
            let directory=path.parent()?;
            CheckedBundle::read(&bytes,primary,fallback.as_ref(),|pin|read_regular(&directory.join(&pin.name))).ok().map(Arc::new)
        });
        Self{primary:primary.clone(),fallback,allow_fallback,proof,proof_sha256}
    }
    pub(crate) fn open_generation(&self,tx:&Tx,id:i64)->Result<VerifiedPrimaryGeneration,StorageError> {
        match open_api_generation(tx,id,&self.primary) {
            Ok(verified)=>Ok(verified),
            Err(original)=>match &self.proof {
                Some(proof)=>open_api_generation_with_compatibility(tx,id,&self.primary,proof).map_err(StorageError::from),
                None=>Err(StorageError::from(original)),
            },
        }
    }
    pub(crate) fn identity_sha256(&self) -> String {
        let identity = |profile: &ValidatedProfile| super::EndpointConfigIdentity::from_profile(profile)
            .expect("validated embedding profile").sha256();
        let bytes = serde_json::to_vec(&serde_json::json!({
            "version": 1, "primary": identity(&self.primary),
            "fallback": self.fallback.as_ref().map(identity), "allow_fallback": self.allow_fallback,
            "proof_sha256": self.proof_sha256, "proof_admitted": self.proof.is_some(),
        })).expect("route identity serialization");
        hex::encode(Sha256::digest(bytes))
    }
    pub(crate) fn max_batch(&self)->usize {
        let primary=self.primary.embedding().map(|e|e.max_batch).unwrap_or(1);
        let maximum=if self.allow_fallback && self.proof.is_some() {
            self.fallback.as_ref().and_then(|p|p.embedding()).map(|e|primary.min(e.max_batch)).unwrap_or(primary)
        } else {primary};
        usize::try_from(maximum).unwrap_or(usize::MAX).max(1)
    }
    pub(crate) fn embed(&self,client:&ApiClient,inputs:&[String],kind:InputKind,dimension:usize,descriptor_sha:&str)
        ->Result<EmbedOutcome,RoutedEmbedFailure> {
        let failure=match client.embed_once(&self.primary.id,inputs,kind) {
            Ok(outcome)=>return checked_width(outcome,dimension),
            Err(failure)=>failure,
        };
        let eligible=super::routing::failure_allows_cloud_fallback(&failure);
        let primary_attempts=failure.attempts().to_vec();
        let Some(backup)=self.fallback.as_ref().filter(|_|self.allow_fallback && eligible) else {
            return Err(RoutedEmbedFailure{code:failure.error().code().as_str(),compatibility_required:false,lexical_eligible:eligible,attempts:primary_attempts});
        };
        let proven=self.proof.as_ref().is_some_and(|p|p.header().primary_descriptor_sha256==descriptor_sha);
        if !proven {
            return Err(RoutedEmbedFailure{code:"CompatibilityRequired",compatibility_required:true,lexical_eligible:false,attempts:primary_attempts});
        }
        match client.embed_once(&backup.id,inputs,kind) {
            Ok(mut outcome)=>{
                for attempt in &mut outcome.attempts {attempt.stage=AttemptStage::Fallback;}
                let mut combined=primary_attempts;combined.append(&mut outcome.attempts);outcome.attempts=combined;
                checked_width(outcome,dimension)
            }
            Err(failure)=>{
                let mut attempts=primary_attempts;
                attempts.extend(failure.attempts().iter().cloned().map(|mut a|{a.stage=AttemptStage::Fallback;a}));
                Err(RoutedEmbedFailure{code:failure.error().code().as_str(),compatibility_required:false,
                    lexical_eligible:super::routing::failure_allows_cloud_fallback(&failure),attempts})
            }
        }
    }
}
fn checked_width(mut outcome:EmbedOutcome,dimension:usize)->Result<EmbedOutcome,RoutedEmbedFailure> {
    if outcome.dimension!=dimension {
        if let Some(last)=outcome.attempts.last_mut() {last.error_code=Some("DimensionMismatch");}
        return Err(RoutedEmbedFailure{code:"DimensionMismatch",compatibility_required:false,lexical_eligible:false,attempts:outcome.attempts});
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::compatibility_capture::tests::inputs;
    use super::super::test_support::{HttpFixture, Reply};

    #[test]
    fn route_digest_binds_backup_policy_and_proof_without_network() {
        let server = HttpFixture::start(vec![Reply::Embeddings(2)]);
        let (client, _, _, _) = inputs(&server);
        let route = EmbeddingRoute::load(client.config(), client.config().profile("archived").unwrap(), true);
        let original = route.identity_sha256();
        let mut changed = route.clone();
        changed.allow_fallback = false;
        assert_ne!(original, changed.identity_sha256());
        let mut changed = route.clone();
        changed.fallback = Some(route.primary.clone());
        assert_ne!(original, changed.identity_sha256());
        let mut changed = route.clone();
        changed.proof_sha256 = Some("a".repeat(64));
        assert_ne!(original, changed.identity_sha256());
        let first_proof = changed.identity_sha256();
        changed.proof_sha256 = Some("b".repeat(64));
        assert_ne!(first_proof, changed.identity_sha256());
        assert_eq!(original, route.clone().identity_sha256());
        assert_eq!(server.hits(), 0);
    }

    #[test]
    fn dimension_change_is_terminal_after_actual_primary_response() {
        let server = HttpFixture::start(vec![Reply::Embeddings(3)]);
        let (client, _, _, _) = inputs(&server);
        let profile = client.config().profile("archived").unwrap();
        let route = EmbeddingRoute::load(client.config(), profile, true);
        let failure = route.embed(&client, &["query".into()], InputKind::Query, 2, "space")
            .unwrap_err();
        assert_eq!(failure.code, "DimensionMismatch");
        assert!(!failure.lexical_eligible);
        assert_eq!(failure.attempts.len(), 1);
        assert_eq!(server.hits(), 1);
    }

    #[test]
    fn unverified_backup_is_never_called_after_eligible_primary_failure() {
        let server = HttpFixture::start(vec![Reply::status(503)]);
        let (client, _, _, _) = inputs(&server);
        let profile = client.config().profile("archived").unwrap();
        let mut route = EmbeddingRoute::load(client.config(), profile, true);
        // Reuse the listener as a tripwire: any fallback would create a second POST.
        route.fallback = Some(profile.clone());
        let failure = route.embed(&client, &["query".into()], InputKind::Query, 2, "space")
            .unwrap_err();
        assert_eq!(failure.code, "CompatibilityRequired");
        assert!(failure.compatibility_required);
        assert!(!failure.lexical_eligible);
        assert_eq!(failure.attempts.len(), 1);
        assert_eq!(server.hits(), 1);
    }
}

#[cfg(all(test, not(windows)))]
mod tls_tests {
    use super::*;
    use super::super::compatibility_bundle::tests::fallback_fixture;
    use super::super::test_support::{HttpFixture, TlsFixture, Reply};

    #[test]
    fn verified_route_sends_one_complete_backup_request_over_tls() {
        let primary = HttpFixture::start(vec![Reply::status(503)]);
        let backup = TlsFixture::start(vec![Reply::Embeddings(2)]);
        let (config, proof) = fallback_fixture(&primary.base(), &backup.base());
        let descriptor = proof.header().primary_descriptor_sha256.clone();
        let mut route = EmbeddingRoute::load(&config, config.profile("primary").unwrap(), true);
        route.proof_sha256 = Some(proof.digest().into());
        route.proof = Some(Arc::new(proof));
        let client = ApiClient::new_with_test_root(config, Box::new(super::super::EnvCredentialResolver), backup.ca_pem().to_vec());
        let outcome = route.embed(&client, &["first".into(), "second".into()], InputKind::Document, 2, &descriptor).unwrap();
        assert_eq!(outcome.vectors.len(), 2);
        assert_eq!(outcome.attempts.len(), 2);
        assert_eq!(outcome.attempts[0].http_status, Some(503));
        assert_eq!(outcome.attempts[1].stage, AttemptStage::Fallback);
        assert_eq!(outcome.attempts[1].profile_id, "backup");
        assert_eq!(primary.hits(), 1);
        assert_eq!(backup.fixture().hits(), 1);
        let requests = backup.fixture().requests();
        assert_eq!(requests[0].body()["input"], serde_json::json!(["D:first", "D:second"]));
        route.allow_fallback = false;
        assert!(route.embed(&client, &["third".into()], InputKind::Query, 2, &descriptor).is_err());
        assert_eq!(primary.hits(), 2);
        assert_eq!(backup.fixture().hits(), 1, "disabled fallback must send no cloud request");
    }
}
