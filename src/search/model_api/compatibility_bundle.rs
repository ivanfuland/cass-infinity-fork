//! Recompute a complete, pinned compatibility graph. File I/O is supplied by
//! the bounded loader; nothing in this module sends requests or updates a DB.
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use super::{ApiProtocol, EndpointConfigIdentity, InputKind, RepresentationDescriptor, ValidatedProfile};
use super::compatibility::CompatibilityError as Error;
use super::compatibility_archive::{CheckedCapture, CheckedFixture, PairSummary, Sources, compare_pair};

const MAX_FILE: usize = 16 * 1024 * 1024;
const MAX_TOTAL: usize = 64 * 1024 * 1024;
const MAX_CAPTURES: usize = 16;
pub(crate) const VERIFIER_VERSION: &str = "cass.api-compatibility.v1";
fn sha(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn valid_sha(s: &str) -> bool { s.len()==64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilePin { pub name: String, pub sha256: String }
impl FilePin {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !valid_sha(&self.sha256) || self.name.is_empty() || self.name.len()>128 || self.name.starts_with('.')
            || !self.name.ends_with(".json") || !self.name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
            return Err(Error::InvalidEvidence);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Member {
    pub capture: FilePin,
    pub token_receipt: FilePin,
    pub endpoint_config_sha256: String,
    /// Canonical declaration bytes, not an unvalidated map with duplicate keys.
    pub call_configuration_json: String,
    pub sources: Sources,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairClaim {
    pub left_capture_sha256: String,
    pub right_capture_sha256: String,
    pub result: PairSummary,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bundle {
    pub version: u32,
    pub verifier: String,
    pub fixture: FilePin,
    pub members: Vec<Member>,
    pub primary_capture_sha256: String,
    pub fallback_capture_sha256: Option<String>,
    pub primary_descriptor_sha256: String,
    pub fixed_provider: Option<String>,
    pub comparisons: Vec<PairClaim>,
    pub conclusion: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CountedInput { pub input_sha256: String, pub token_ids: Vec<u32> }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenReceipt {
    pub version: u32,
    pub counter_id: String,
    pub counter_source_sha256: String,
    pub tokenizer_declaration_sha256: String,
    pub query: Vec<CountedInput>,
    pub document: Vec<CountedInput>,
}

pub(crate) fn check_counter_inputs(bytes: &[u8], source: &Sources, query_inputs: &[String], document_inputs: &[String]) -> Result<(), Error> {
    let receipt: TokenReceipt = serde_json::from_slice(bytes).map_err(|_| Error::InvalidEvidence)?;
    if receipt.version != 1 || receipt.counter_id != source.token_counter.value || !valid_sha(&receipt.counter_source_sha256)
        || receipt.tokenizer_declaration_sha256 != sha(&serde_json::to_vec(&source.tokenizer).map_err(|_| Error::InvalidEvidence)?) {
        return Err(Error::EvidenceMismatch);
    }
    for (inputs, records, counts) in [(query_inputs, &receipt.query, &source.query_token_counts),
        (document_inputs, &receipt.document, &source.document_token_counts)] {
        if records.len()!=inputs.len() || counts.len()!=inputs.len() { return Err(Error::EvidenceMismatch); }
        for ((record,input),count) in records.iter().zip(inputs).zip(counts) {
            if record.input_sha256 != sha(input.as_bytes()) || record.token_ids.len() as u64 != *count {
                return Err(Error::EvidenceMismatch);
            }
        }
    }
    Ok(())
}

fn matching_summary(a: &PairSummary, b: &PairSummary) -> bool {
    // Only report rounding gets this tolerance. The actual admission thresholds
    // have already been applied strictly to every recomputed comparison.
    let close = |x: f64,y: f64| x.is_finite() && y.is_finite() && (x-y).abs() <= 1e-12;
    a.numerical_comparisons==b.numerical_comparisons && a.retrieval_assertions==b.retrieval_assertions
        && close(a.minimum_cosine,b.minimum_cosine) && close(a.maximum_component_delta,b.maximum_component_delta)
        && close(a.maximum_relative_norm_delta,b.maximum_relative_norm_delta)
}

pub(crate) fn read_regular(path: &std::path::Path) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let metadata=std::fs::symlink_metadata(path).map_err(|_|Error::InvalidEvidence)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len()>MAX_FILE as u64 { return Err(Error::InvalidEvidence); }
    let mut options=std::fs::OpenOptions::new(); options.read(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)] {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file=options.open(path).map_err(|_|Error::InvalidEvidence)?;
    let opened=file.metadata().map_err(|_|Error::InvalidEvidence)?;
    if !opened.is_file() || opened.file_type().is_symlink() || opened.len()>MAX_FILE as u64 { return Err(Error::InvalidEvidence); }
    let mut bytes=Vec::new();
    file.take(MAX_FILE as u64+1).read_to_end(&mut bytes).map_err(|_|Error::InvalidEvidence)?;
    if bytes.len()>MAX_FILE { return Err(Error::InvalidEvidence); }
    Ok(bytes)
}

/// Private fields prevent a deserialized `passed` claim from becoming admission.
/// Production still needs the approved fixture/tool and transactional guards.
pub(crate) struct CheckedBundle {
    header: Bundle,
    digest: String,
    captures: HashMap<String, CheckedCapture>,
}
impl CheckedBundle {
    pub(crate) fn load(path: &std::path::Path, primary: &ValidatedProfile, fallback: Option<&ValidatedProfile>) -> Result<Self, Error> {
        let bytes=read_regular(path)?;
        let directory=path.parent().unwrap_or_else(|| std::path::Path::new("."));
        Self::read(&bytes,primary,fallback,|pin| read_regular(&directory.join(&pin.name)))
    }

    pub(crate) fn read(
        bytes: &[u8], primary: &ValidatedProfile, fallback: Option<&ValidatedProfile>,
        mut read: impl FnMut(&FilePin) -> Result<Vec<u8>, Error>,
    ) -> Result<Self, Error> {
        if bytes.len()>MAX_FILE { return Err(Error::InvalidEvidence); }
        let header: Bundle = serde_json::from_slice(bytes).map_err(|_| Error::InvalidEvidence)?;
        if header.version!=1 || header.verifier!=VERIFIER_VERSION || header.conclusion!="compatible"
            || header.members.len()<2 || header.members.len()>MAX_CAPTURES { return Err(Error::InvalidEvidence); }
        let mut total=bytes.len();
        let mut files: HashMap<String,Vec<u8>>=HashMap::new();
        let mut load = |pin: &FilePin| -> Result<Vec<u8>, Error> {
            pin.validate()?;
            if let Some(bytes)=files.get(&pin.name) {
                if sha(bytes)!=pin.sha256 { return Err(Error::EvidenceMismatch); }
                return Ok(bytes.clone());
            }
            let bytes=read(pin)?;
            total=total.checked_add(bytes.len()).ok_or(Error::InvalidEvidence)?;
            if bytes.len()>MAX_FILE || total>MAX_TOTAL || sha(&bytes)!=pin.sha256 { return Err(Error::EvidenceMismatch); }
            files.insert(pin.name.clone(),bytes.clone());
            Ok(bytes)
        };
        let fixture_bytes=load(&header.fixture)?;
        let fixture=CheckedFixture::read(&fixture_bytes,&header.fixture.sha256)?;
        let mut captures=HashMap::new();
        for member in &header.members {
            let bytes=load(&member.capture)?;
            let capture=CheckedCapture::read(&bytes,&member.capture.sha256,&fixture)?;
            let declaration=EndpointConfigIdentity::from_profile(&capture.profile).map_err(|_|Error::InvalidEvidence)?.canonical_bytes();
            if member.endpoint_config_sha256!=capture.endpoint_sha256 || member.call_configuration_json.as_bytes()!=declaration
                || &member.sources!=capture.sources() || member.token_receipt.sha256!=capture.sources().token_counter_artifact_sha256 {
                return Err(Error::EvidenceMismatch);
            }
            check_counter_inputs(&load(&member.token_receipt)?,capture.sources(),capture.inputs(InputKind::Query),capture.inputs(InputKind::Document))?;
            if captures.insert(member.capture.sha256.clone(),capture).is_some() { return Err(Error::InvalidEvidence); }
        }
        let main=captures.get(&header.primary_capture_sha256).ok_or(Error::EvidenceMismatch)?;
        let main_sha=EndpointConfigIdentity::from_profile(primary).map_err(|_|Error::InvalidEvidence)?.sha256();
        let descriptor=RepresentationDescriptor::from_profile(primary,main.dimension() as u64).map_err(|_|Error::InvalidEvidence)?;
        if main.endpoint_sha256!=main_sha || header.primary_descriptor_sha256!=descriptor.sha256() { return Err(Error::EvidenceMismatch); }
        match (fallback,&header.fallback_capture_sha256) {
            (None,None) if header.fixed_provider.is_none()=>{},
            (Some(profile),Some(pin))=>{
                let backup=captures.get(pin).ok_or(Error::EvidenceMismatch)?;
                let embedding=profile.embedding().ok_or(Error::InvalidEvidence)?;
                if profile.protocol!=ApiProtocol::OpenRouterEmbeddingsV1 || embedding.provider_only.is_none()
                    || profile.scope!=super::EndpointScope::Remote || primary.scope!=super::EndpointScope::Loopback
                    || primary.fallback_profile.as_deref()!=Some(profile.id.as_str())
                    || primary.id==profile.id || profile.fallback_profile.is_some()
                    || embedding.provider_only!=header.fixed_provider
                    || EndpointConfigIdentity::from_profile(profile).map_err(|_|Error::InvalidEvidence)?.sha256()!=backup.endpoint_sha256 {
                    return Err(Error::EvidenceMismatch);
                }
            }
            _=>return Err(Error::EvidenceMismatch),
        }
        let mut ids: Vec<_>=captures.keys().cloned().collect(); ids.sort();
        if header.comparisons.len()!=ids.len()*(ids.len()-1)/2 { return Err(Error::EvidenceMismatch); }
        let mut seen=HashSet::new();
        for claim in &header.comparisons {
            if claim.left_capture_sha256>=claim.right_capture_sha256
                || !seen.insert((claim.left_capture_sha256.clone(),claim.right_capture_sha256.clone())) { return Err(Error::InvalidEvidence); }
            let left=captures.get(&claim.left_capture_sha256).ok_or(Error::EvidenceMismatch)?;
            let right=captures.get(&claim.right_capture_sha256).ok_or(Error::EvidenceMismatch)?;
            let actual=compare_pair(&fixture,left,right)?;
            if !matching_summary(&claim.result,&actual) { return Err(Error::EvidenceMismatch); }
        }
        Ok(Self { header,digest:sha(bytes),captures })
    }
    pub(crate) fn digest(&self)->&str { &self.digest }
    pub(crate) fn header(&self)->&Bundle { &self.header }
    /// A historical capture pin is never replaced by a fresh sample from the
    /// same endpoint. `None` is only for the original pure-primary record.
    pub(crate) fn covers(&self, endpoint_sha:&str, historical_capture_sha:Option<&str>) -> bool {
        match historical_capture_sha {
            Some(pin)=>self.captures.get(pin).is_some_and(|c| c.endpoint_sha256==endpoint_sha),
            None=>self.captures.values().any(|c| c.endpoint_sha256==endpoint_sha),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::compatibility_archive::Capture;
    use super::super::compatibility_archive::tests::{archive, fixture};
    fn package(mut archives: Vec<Capture>, fixture_bytes: Vec<u8>, bad_counter: bool) -> (Bundle,HashMap<String,Vec<u8>>,ValidatedProfile) {
        let fixture_sha=sha(&fixture_bytes);
        let checked_fixture=CheckedFixture::read(&fixture_bytes,&fixture_sha).unwrap();
        let mut files=HashMap::from([("fixture.json".into(),fixture_bytes)]);
        let mut members=Vec::new();
        let mut checked=Vec::new();
        for (index,capture) in archives.iter_mut().enumerate() {
            let count = |calls: &[super::super::compatibility_archive::ResponseCapture]| calls.iter().flat_map(|c| &c.inputs)
                .map(|text| CountedInput{input_sha256:sha(text.as_bytes()),token_ids:text.chars().map(|c|c as u32).collect()}).collect();
            let mut receipt=TokenReceipt { version:1,counter_id:capture.sources.token_counter.value.clone(),
                counter_source_sha256:sha(b"synthetic scalar counter source"),
                tokenizer_declaration_sha256:sha(&serde_json::to_vec(&capture.sources.tokenizer).unwrap()),
                query:count(&capture.query_rounds[0]), document:count(&capture.document_rounds[0]) };
            if bad_counter && index==0 { receipt.query[0].input_sha256="0".repeat(64); }
            let receipt_bytes=serde_json::to_vec(&receipt).unwrap();
            capture.sources.token_counter_artifact_sha256=sha(&receipt_bytes);
            let bytes=serde_json::to_vec(capture).unwrap(); let digest=sha(&bytes);
            let node=CheckedCapture::read(&bytes,&digest,&checked_fixture).unwrap();
            let member=Member {
                capture:FilePin{name:format!("capture-{index}.json"),sha256:digest},
                token_receipt:FilePin{name:format!("tokens-{index}.json"),sha256:sha(&receipt_bytes)},
                endpoint_config_sha256:node.endpoint_sha256.clone(),
                call_configuration_json:String::from_utf8(EndpointConfigIdentity::from_profile(&node.profile).unwrap().canonical_bytes()).unwrap(),
                sources:capture.sources.clone(),
            };
            files.insert(member.capture.name.clone(),bytes); files.insert(member.token_receipt.name.clone(),receipt_bytes);
            members.push(member); checked.push(node);
        }
        let primary=checked[0].profile.clone();
        let mut comparisons=Vec::new();
        for i in 0..checked.len() { for j in i+1..checked.len() {
            let (l,r)=if checked[i].digest()<checked[j].digest() {(&checked[i],&checked[j])}else{(&checked[j],&checked[i])};
            // Deliberately forge a positive claim for incompatible inputs in
            // the negative test; the reader must recompute and reject it.
            let result=compare_pair(&checked_fixture,l,r).unwrap_or(PairSummary {
                minimum_cosine:1.0,maximum_component_delta:0.0,maximum_relative_norm_delta:0.0,
                numerical_comparisons:72,retrieval_assertions:32,
            });
            comparisons.push(PairClaim {left_capture_sha256:l.digest().into(),right_capture_sha256:r.digest().into(),result});
        }}
        let bundle=Bundle {version:1,verifier:VERIFIER_VERSION.into(),fixture:FilePin{name:"fixture.json".into(),sha256:fixture_sha},
            primary_capture_sha256:checked[0].digest().into(),fallback_capture_sha256:None,
            primary_descriptor_sha256:RepresentationDescriptor::from_profile(&primary,checked[0].dimension() as u64).unwrap().sha256(),
            fixed_provider:None,members,comparisons,conclusion:"compatible".into()};
        (bundle,files,primary)
    }
    fn read(bundle:&Bundle,files:&HashMap<String,Vec<u8>>,primary:&ValidatedProfile)->Result<CheckedBundle,Error> {
        CheckedBundle::read(&serde_json::to_vec(bundle).unwrap(),primary,None,|pin| files.get(&pin.name).cloned().ok_or(Error::EvidenceMismatch))
    }
    #[test]
    fn loader_reads_pinned_files_and_refuses_replaced_content() {
        let (bytes,f)=fixture();
        let (bundle,files,primary)=package(vec![archive(&f,1),archive(&f,2)],bytes,false);
        let root=tempfile::tempdir().unwrap();
        for (name,bytes) in &files { std::fs::write(root.path().join(name),bytes).unwrap(); }
        let manifest=root.path().join("proof.json");
        std::fs::write(&manifest,serde_json::to_vec(&bundle).unwrap()).unwrap();
        CheckedBundle::load(&manifest,&primary,None).unwrap();
        std::fs::write(root.path().join(&bundle.members[1].capture.name),b"{}").unwrap();
        assert!(CheckedBundle::load(&manifest,&primary,None).is_err());
        let oversized=root.path().join("oversized.json");
        std::fs::File::create(&oversized).unwrap().set_len(MAX_FILE as u64+1).unwrap();
        assert!(read_regular(&oversized).is_err());
        assert!(read_regular(root.path()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn loader_does_not_follow_a_proof_symlink() {
        let root=tempfile::tempdir().unwrap();
        let target=root.path().join("target.json"); std::fs::write(&target,b"{}").unwrap();
        let link=root.path().join("link.json"); std::os::unix::fs::symlink(&target,&link).unwrap();
        assert!(read_regular(&link).is_err());
    }

    #[test]
    fn identical_counter_receipts_can_be_shared_by_two_members() {
        let (bytes,f)=fixture();
        let (mut bundle,files,primary)=package(vec![archive(&f,1),archive(&f,2)],bytes,false);
        assert_eq!(bundle.members[0].token_receipt.sha256,bundle.members[1].token_receipt.sha256);
        bundle.members[1].token_receipt.name=bundle.members[0].token_receipt.name.clone();
        read(&bundle,&files,&primary).unwrap();
    }

    #[test]
    fn complete_graph_preserves_exact_historical_capture_identity() {
        let (bytes,f)=fixture();
        let (bundle,files,primary)=package(vec![archive(&f,1),archive(&f,2)],bytes,false);
        let checked=read(&bundle,&files,&primary).unwrap();
        let historical=&bundle.members[1];
        assert!(checked.covers(&historical.endpoint_config_sha256,Some(&historical.capture.sha256)));
        assert!(!checked.covers(&historical.endpoint_config_sha256,Some(&"0".repeat(64))));
        assert!(!checked.covers(&"0".repeat(64),None));
        assert_eq!(checked.digest(),sha(&serde_json::to_vec(&bundle).unwrap()));
        assert_eq!(checked.header().comparisons.len(),1);
    }
    #[test]
    fn backup_requires_the_explicit_remote_route_and_fixed_provider() {
        let (bytes,f)=fixture(); let a=archive(&f,1); let mut b=archive(&f,2);
        b.profile_toml=b.profile_toml.replace("openai-embeddings-v1","openrouter-embeddings-v1")
            .replace("http://127.0.0.1:2/embedding","https://example.invalid/embedding")
            .replace("scope=\"loopback\"","scope=\"remote\"");
        b.profile_toml.push_str("provider_only=\"fixed-provider\"\n");
        let config=super::super::ApiConfig::parse_toml(&b.profile_toml).unwrap();
        let mut backup=config.profiles().next().unwrap().clone();
        backup.id="backup".into();
        b.endpoint_config_sha256=EndpointConfigIdentity::from_profile(&backup).unwrap().sha256();
        let (mut bundle,files,mut primary)=package(vec![a,b],bytes,false);
        bundle.fallback_capture_sha256=Some(bundle.members[1].capture.sha256.clone());
        bundle.fixed_provider=Some("fixed-provider".into());
        let bytes=serde_json::to_vec(&bundle).unwrap();
        let load=|p:&ValidatedProfile| CheckedBundle::read(&bytes,p,Some(&backup),|pin| files.get(&pin.name).cloned().ok_or(Error::EvidenceMismatch));
        assert!(load(&primary).is_err(),"a cloud profile alone is not a declared route");
        primary.id="primary".into();
        primary.fallback_profile=Some(backup.id.clone());
        load(&primary).unwrap();
        let mut wrong=bundle.clone(); wrong.fixed_provider=Some("other-provider".into());
        assert!(CheckedBundle::read(&serde_json::to_vec(&wrong).unwrap(),&primary,Some(&backup),|pin| files.get(&pin.name).cloned().ok_or(Error::EvidenceMismatch)).is_err());
    }

    #[test]
    fn declared_pass_and_transitive_edges_do_not_admit_a_bad_direct_pair() {
        let (bytes,f)=fixture(); let a=archive(&f,1); let mut b=archive(&f,2); let mut c=archive(&f,3);
        for round in &mut b.query_rounds {round[0].vectors[0]=vec![1.0,0.0008];}
        for round in &mut c.query_rounds {round[0].vectors[0]=vec![1.0,0.0016];}
        let (bundle,files,primary)=package(vec![a,b,c],bytes,false);
        assert!(matches!(read(&bundle,&files,&primary),Err(Error::NumericalMismatch)));
        let mut incomplete=bundle.clone(); incomplete.comparisons.pop();
        assert!(read(&incomplete,&files,&primary).is_err());
    }
    #[test]
    fn counter_input_binding_and_header_cannot_be_self_asserted() {
        let (bytes,f)=fixture();
        let (bundle,files,primary)=package(vec![archive(&f,1),archive(&f,2)],bytes,true);
        assert!(matches!(read(&bundle,&files,&primary),Err(Error::EvidenceMismatch)));
        let (bytes,f)=fixture();
        let (bundle,files,primary)=package(vec![archive(&f,1),archive(&f,2)],bytes,false);
        for mutation in 0..4 {
            let mut bad=bundle.clone();
            match mutation {
                0=>bad.members[0].capture.name="../outside.json".into(),
                1=>bad.primary_descriptor_sha256="0".repeat(64),
                2=>bad.comparisons[0].result.minimum_cosine=0.5,
                _=>bad.members[0].sources.weights.value="changed statement".into(),
            }
            assert!(read(&bad,&files,&primary).is_err(),"mutation {mutation}");
        }
    }
}
