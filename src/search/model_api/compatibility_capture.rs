//! Explicit single-endpoint compatibility capture. All inputs and token receipts
//! are frozen before the first POST. No fallback, metadata GET or retry occurs.
use serde::{Serialize,Deserialize};
use sha2::{Digest, Sha256};
use super::{ApiClient, ApiCallErrorCode, EndpointConfigIdentity, InputKind, ValidatedProfile};
use super::compatibility::CompatibilityError;
use super::compatibility_archive::{Capture, CheckedCapture, CheckedFixture, ResponseCapture, Sources};
use super::compatibility_bundle::check_counter_inputs;
use crate::search::rerank::window::ApiWindowAttempt;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeAttempt { pub round: usize, pub input_kind: String, pub call: ApiWindowAttempt }
#[derive(Debug)]
pub(crate) struct CaptureFailure {
    pub code: CompatibilityError,
    pub api_error: Option<ApiCallErrorCode>,
    pub attempts: Vec<ProbeAttempt>,
}
pub(crate) struct CapturedArchive { pub bytes: Vec<u8>, pub attempts: Vec<ProbeAttempt> }
fn sha(bytes:&[u8])->String { hex::encode(Sha256::digest(bytes)) }

/// Preserve every individual call parameter, but strip routing references and
/// credential values. Reparse and compare the canonical identity before use.
fn standalone_profile(profile:&ValidatedProfile)->Result<String,CompatibilityError> {
    let identity=EndpointConfigIdentity::from_profile(profile).map_err(|_|CompatibilityError::InvalidEvidence)?;
    let wire:serde_json::Value=serde_json::from_slice(&identity.canonical_bytes()).map_err(|_|CompatibilityError::InvalidEvidence)?;
    let mut table=toml::map::Map::new();
    for (key,value) in wire.as_object().ok_or(CompatibilityError::InvalidEvidence)? {
        if ["domain","version","embedding","rerank"].contains(&key.as_str()) || value.is_null() {continue;}
        table.insert(key.clone(),toml::Value::try_from(value).map_err(|_|CompatibilityError::InvalidEvidence)?);
    }
    for (key,value) in wire["embedding"].as_object().ok_or(CompatibilityError::InvalidEvidence)? {
        if !value.is_null() { table.insert(key.clone(),toml::Value::try_from(value).map_err(|_|CompatibilityError::InvalidEvidence)?); }
    }
    let mut profiles=toml::map::Map::new(); profiles.insert("archived".into(),toml::Value::Table(table));
    let mut root=toml::map::Map::new(); root.insert("version".into(),toml::Value::Integer(1)); root.insert("profiles".into(),toml::Value::Table(profiles));
    let text=toml::to_string(&root).map_err(|_|CompatibilityError::InvalidEvidence)?;
    let parsed=super::ApiConfig::parse_toml(&text).map_err(|_|CompatibilityError::InvalidEvidence)?;
    let saved=EndpointConfigIdentity::from_profile(parsed.profile("archived").ok_or(CompatibilityError::InvalidEvidence)?)
        .map_err(|_|CompatibilityError::InvalidEvidence)?;
    if saved.sha256()!=identity.sha256() {return Err(CompatibilityError::EvidenceMismatch);}
    Ok(text)
}

pub(crate) fn capture(
    client:&ApiClient, profile_id:&str, fixture:&CheckedFixture, sources:Sources, token_receipt:&[u8],
)->Result<CapturedArchive,CaptureFailure> {
    let mut attempts=Vec::new();
    let fail=|code| CaptureFailure{code,api_error:None,attempts:Vec::new()};
    let profile=client.config().profile(profile_id).ok_or_else(||fail(CompatibilityError::InvalidEvidence))?;
    let embedding=profile.embedding().ok_or_else(||fail(CompatibilityError::InvalidEvidence))?;
    let profile_toml=standalone_profile(profile).map_err(&fail)?;
    let identity=EndpointConfigIdentity::from_profile(profile).map_err(|_|fail(CompatibilityError::InvalidEvidence))?;
    sources.validate(fixture.samples().len()).map_err(&fail)?;
    if token_receipt.len()>16*1024*1024 || sha(token_receipt)!=sources.token_counter_artifact_sha256 {
        return Err(fail(CompatibilityError::EvidenceMismatch));
    }
    let raw:Vec<_>=fixture.samples().iter().map(|s|s.text.clone()).collect();
    let inputs=|kind| raw.iter().map(|text|super::protocol::embedding_input(profile,kind,text)).collect::<Vec<_>>();
    let (query_inputs,document_inputs)=(inputs(InputKind::Query),inputs(InputKind::Document));
    check_counter_inputs(token_receipt,&sources,&query_inputs,&document_inputs).map_err(&fail)?;
    let batch=usize::try_from(embedding.max_batch).unwrap_or(usize::MAX).max(1);
    let mut query_rounds:[Vec<ResponseCapture>;2]=[Vec::new(),Vec::new()];
    let mut document_rounds:[Vec<ResponseCapture>;2]=[Vec::new(),Vec::new()];
    let mut dimension=None;
    for round in 0..2 {
        for (kind,name,expected,destination) in [
            (InputKind::Query,"query",&query_inputs,&mut query_rounds[round]),
            (InputKind::Document,"document",&document_inputs,&mut document_rounds[round]),
        ] {
            for (texts,prepared) in raw.chunks(batch).zip(expected.chunks(batch)) {
                let outcome=match client.embed_once(profile_id,texts,kind) {
                    Ok(outcome)=>outcome,
                    Err(error)=>{
                        attempts.extend(error.attempts().iter().map(|call| ProbeAttempt{round,input_kind:name.to_owned(),call:call.into()}));
                        return Err(CaptureFailure{code:CompatibilityError::CaptureFailed,api_error:Some(error.error().code()),attempts});
                    }
                };
                attempts.extend(outcome.attempts.iter().map(|call| ProbeAttempt{round,input_kind:name.to_owned(),call:call.into()}));
                if dimension.is_some_and(|seen|seen!=outcome.dimension) {
                    if let Some(last)=attempts.last_mut() {last.call.error_code=Some("DimensionMismatch".into());}
                    return Err(CaptureFailure{code:CompatibilityError::DimensionMismatch,api_error:None,attempts});
                }
                dimension=Some(outcome.dimension);
                let status=outcome.attempts.last().and_then(|a|a.http_status).ok_or_else(||CaptureFailure{
                    code:CompatibilityError::InvalidEvidence,api_error:None,attempts:attempts.clone()})?;
                destination.push(ResponseCapture { inputs:prepared.to_vec(),vectors:outcome.vectors,http_status:status,
                    response_model:outcome.identity.response_model,response_revision:outcome.identity.response_revision,
                    serving_provider:outcome.identity.provider,usage:super::runtime::CheckUsage::from_observed(outcome.identity.usage.as_ref()) });
            }
        }
    }
    let archive=Capture{version:1,profile_toml,endpoint_config_sha256:identity.sha256(),fixture_sha256:fixture.digest().into(),
        dimension:dimension.ok_or_else(||fail(CompatibilityError::InvalidEvidence))?,sources,query_rounds,document_rounds};
    let bytes=serde_json::to_vec(&archive).map_err(|_|CaptureFailure{code:CompatibilityError::InvalidEvidence,api_error:None,attempts:attempts.clone()})?;
    CheckedCapture::read(&bytes,&sha(&bytes),fixture).map_err(|code|CaptureFailure{code,api_error:None,attempts:attempts.clone()})?;
    Ok(CapturedArchive{bytes,attempts})
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use super::super::compatibility_archive::tests::{fixture,archive};
    use super::super::compatibility_bundle::{CountedInput,TokenReceipt};
    use super::super::test_support::{HttpFixture,Reply};

    pub(in crate::search::model_api) fn inputs(server:&HttpFixture)->(ApiClient,CheckedFixture,Sources,Vec<u8>) {
        let (_,fixture)=fixture(); let mut template=archive(&fixture,1);
        let text=template.profile_toml.replace("http://127.0.0.1:1/embedding",&server.base())+"max_batch=2\n";
        let config=super::super::ApiConfig::parse_toml(&text).unwrap();
        let records=|requests:&[ResponseCapture]| requests.iter().flat_map(|r|&r.inputs).map(|text|CountedInput{
            input_sha256:sha(text.as_bytes()),token_ids:text.chars().map(|c|c as u32).collect()}).collect();
        let receipt=TokenReceipt{version:1,counter_id:template.sources.token_counter.value.clone(),counter_source_sha256:sha(b"synthetic counter"),
            tokenizer_declaration_sha256:sha(&serde_json::to_vec(&template.sources.tokenizer).unwrap()),
            query:records(&template.query_rounds[0]),document:records(&template.document_rounds[0])};
        let bytes=serde_json::to_vec(&receipt).unwrap(); template.sources.token_counter_artifact_sha256=sha(&bytes);
        (ApiClient::new(config,Box::new(super::super::EnvCredentialResolver)),fixture,template.sources,bytes)
    }
    #[test]
    fn two_rounds_and_both_input_kinds_are_captured_from_actual_posts() {
        let server=HttpFixture::start(vec![Reply::Embeddings(2)]);
        let (client,fixture,sources,receipt)=inputs(&server);
        let result=capture(&client,"archived",&fixture,sources,&receipt).unwrap();
        let decoded:Capture=serde_json::from_slice(&result.bytes).unwrap();
        assert_eq!(result.attempts.len(),12);
        assert_eq!(server.hits(),12);
        let requests=server.requests(); let mut offset=0;
        for round in 0..2 {
            for (name,calls) in [("query",&decoded.query_rounds[round]),("document",&decoded.document_rounds[round])] {
                assert_eq!(calls.len(),3);
                for call in calls {
                    assert_eq!(requests[offset].method(),"POST");
                    assert_eq!(requests[offset].body()["input"],serde_json::json!(call.inputs));
                    assert_eq!(result.attempts[offset].round,round);
                    assert_eq!(result.attempts[offset].input_kind,name);
                    assert_eq!(call.response_model,None,"missing service identity must stay unknown");
                    offset+=1;
                }
            }
        }
        CheckedCapture::read(&result.bytes,&sha(&result.bytes),&fixture).unwrap();
    }
    #[test]
    fn inconsistent_count_receipt_is_refused_before_any_http() {
        let server=HttpFixture::start(vec![Reply::Embeddings(2)]);
        let (client,fixture,mut sources,receipt)=inputs(&server);
        sources.query_token_counts[0]+=1;
        let result=capture(&client,"archived",&fixture,sources,&receipt);
        let error=match result {Ok(_)=>panic!("invalid counter accepted"),Err(error)=>error};
        assert_eq!(error.code,CompatibilityError::EvidenceMismatch);
        assert!(error.attempts.is_empty()); assert_eq!(server.hits(),0);
    }
    #[test]
    fn failed_capture_retains_the_actual_calls_without_a_partial_archive() {
        let server=HttpFixture::start(vec![Reply::Embeddings(2),Reply::Embeddings(3)]);
        let (client,fixture,sources,receipt)=inputs(&server);
        let error=match capture(&client,"archived",&fixture,sources,&receipt) {Ok(_)=>panic!("drift accepted"),Err(error)=>error};
        assert_eq!(error.code,CompatibilityError::DimensionMismatch);
        assert_eq!(error.attempts.len(),2); assert_eq!(server.hits(),2);
        assert_eq!(error.attempts[1].call.http_status,Some(200));
        assert_eq!(error.attempts[1].call.error_code.as_deref(),Some("DimensionMismatch"));
    }
}
