//! Explicit compatibility artifact operations. Outputs use a fresh private
//! directory and create-new files, so a failed run never replaces older proof.
use std::path::{Path,PathBuf};
use std::io::Write;
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};
use super::compatibility::CompatibilityError as Error;
use super::compatibility_archive::{CheckedFixture,Sources};
use super::compatibility_bundle::{FilePin,read_regular};

/// Capture two query/document rounds for one pinned endpoint and input set.
#[derive(Debug,Clone,clap::Args)]
pub struct CaptureArgs {
    /// selected profile from the explicit model API configuration
    #[arg(long)] pub profile:String,
    /// frozen fixture JSON with public sample texts and independent labels
    #[arg(long)] pub fixture:PathBuf,
    /// expected SHA-256 of the exact fixture file bytes
    #[arg(long)] pub fixture_sha256:String,
    /// path to JSON declarations for model sources and input limits
    #[arg(long)] pub sources:PathBuf,
    /// expected SHA-256 of the exact source declarations file
    #[arg(long)] pub sources_sha256:String,
    /// token IDs and input hashes from the separately validated counter
    #[arg(long)] pub token_receipt:PathBuf,
    /// expected SHA-256 of the exact token receipt file
    #[arg(long)] pub token_receipt_sha256:String,
    /// a new directory; the parent must exist. Existing results are not replaced
    #[arg(long)] pub output:PathBuf,
    /// explicit machine-readable output flag; this command always emits JSON
    #[arg(long,visible_alias="robot")] pub json:bool,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureManifest {
    pub schema:String,
    pub profile_id:String,
    pub fixture:FilePin,
    pub capture:FilePin,
    pub token_receipt:FilePin,
    pub calls:FilePin,
}
fn sha(bytes:&[u8])->String {hex::encode(Sha256::digest(bytes))}
fn pinned(path:&Path,expected:&str)->Result<Vec<u8>,Error> {
    let bytes=read_regular(path)?;
    if sha(&bytes)!=expected {return Err(Error::EvidenceMismatch);}
    Ok(bytes)
}
fn fresh_directory(path:&Path)->Result<(),Error> {
    let mut builder=std::fs::DirBuilder::new();
    #[cfg(unix)] {use std::os::unix::fs::DirBuilderExt;builder.mode(0o700);}
    builder.create(path).map_err(|_|Error::InvalidEvidence)
}
fn write_new(path:&Path,bytes:&[u8])->Result<(),Error> {
    let mut options=std::fs::OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
    let mut file=options.open(path).map_err(|_|Error::InvalidEvidence)?;
    file.write_all(bytes).map_err(|_|Error::InvalidEvidence)?;
    file.sync_all().map_err(|_|Error::InvalidEvidence)
}
fn store(root:&Path,kind:&str,bytes:&[u8])->Result<FilePin,Error> {
    let digest=sha(bytes);let name=format!("{kind}-{digest}.json");
    let path=root.join(&name);
    if path.exists() {
        if read_regular(&path)?!=bytes {return Err(Error::EvidenceMismatch);}
    } else {write_new(&path,bytes)?;}
    Ok(FilePin{name,sha256:digest})
}

pub(crate) fn capture_to_directory(client:&super::ApiClient,args:&CaptureArgs)->Result<serde_json::Value,Error> {
    // Freeze all external input bytes before reserving output or making requests.
    let fixture_bytes=pinned(&args.fixture,&args.fixture_sha256)?;
    let source_bytes=pinned(&args.sources,&args.sources_sha256)?;
    let token_bytes=pinned(&args.token_receipt,&args.token_receipt_sha256)?;
    let fixture=CheckedFixture::read(&fixture_bytes,&args.fixture_sha256)?;
    let sources:Sources=serde_json::from_slice(&source_bytes).map_err(|_|Error::InvalidEvidence)?;
    if sources.token_counter_artifact_sha256!=args.token_receipt_sha256 {return Err(Error::EvidenceMismatch);}
    fresh_directory(&args.output)?;
    let fixture_pin=store(&args.output,"fixture",&fixture_bytes)?;
    let token_pin=store(&args.output,"tokens",&token_bytes)?;
    match super::compatibility_capture::capture(client,&args.profile,&fixture,sources,&token_bytes) {
        Ok(result)=>{
            let capture=store(&args.output,"capture",&result.bytes)?;
            let calls=store(&args.output,"calls",&serde_json::to_vec(&result.attempts).map_err(|_|Error::InvalidEvidence)?)?;
            let manifest=CaptureManifest {schema:"cass.compatibility-capture.v1".into(),profile_id:args.profile.clone(),
                fixture:fixture_pin,capture:capture.clone(),token_receipt:token_pin,calls};
            let bytes=serde_json::to_vec_pretty(&manifest).map_err(|_|Error::InvalidEvidence)?;
            write_new(&args.output.join("capture-manifest.json"),&bytes)?;
            Ok(serde_json::json!({"schema":"cass.compatibility-capture-summary.v1","status":"captured",
                "capture_sha256":capture.sha256,"manifest_sha256":sha(&bytes),"call_attempts":result.attempts.len(),
                "requests":result.attempts.iter().filter(|a|a.call.network_attempted).count()}))
        }
        Err(error)=>{
            let report=serde_json::json!({"schema":"cass.compatibility-capture-failure.v1","code":error.code.to_string(),
                "api_error":error.api_error.map(|code|code.as_str()),"attempts":error.attempts});
            write_new(&args.output.join("capture-failure.json"),&serde_json::to_vec_pretty(&report).map_err(|_|Error::InvalidEvidence)?)?;
            Ok(serde_json::json!({"schema":"cass.compatibility-capture-summary.v1","status":"failed",
                "code":error.code.to_string(),"call_attempts":error.attempts.len(),
                "requests":error.attempts.iter().filter(|a|a.call.network_attempted).count()}))
        }
    }
}

/// Verify all direct comparisons between pinned captures without network access.
/// Repeat manifest and digest flags in matching order, for example:
/// `--capture-manifest a.json --capture-manifest b.json
/// --capture-manifest-sha256 SHA_A --capture-manifest-sha256 SHA_B`.
#[derive(Debug,Clone,clap::Args)]
pub struct VerifyArgs {
    /// selected profile from the explicit model API configuration
    #[arg(long)] pub profile:String,
    /// capture manifests, paired by position with the repeated digest flags
    #[arg(long,required=true)] pub capture_manifest:Vec<PathBuf>,
    /// exact manifest SHA-256 values in the same order as the manifest paths
    #[arg(long,required=true)] pub capture_manifest_sha256:Vec<String>,
    /// capture digest selecting the canonical primary endpoint
    #[arg(long)] pub primary_capture_sha256:String,
    /// capture digest selecting the configured backup, when present
    #[arg(long)] pub fallback_capture_sha256:Option<String>,
    /// a new directory for proof and its immutable copied inputs
    #[arg(long)] pub output:PathBuf,
    /// explicit machine-readable output flag; this command always emits JSON
    #[arg(long,visible_alias="robot")] pub json:bool,
}
fn member_bytes(base:&Path,pin:&FilePin)->Result<Vec<u8>,Error> {
    pin.validate()?;pinned(&base.join(&pin.name),&pin.sha256)
}
fn validate_calls(manifest:&CaptureManifest,archive:&super::compatibility_archive::Capture,bytes:&[u8])->Result<(),Error> {
    let calls:Vec<super::compatibility_capture::ProbeAttempt>=serde_json::from_slice(bytes).map_err(|_|Error::InvalidEvidence)?;
    let mut index=0;
    for round in 0..2 {
        for (kind,requests) in [("query",&archive.query_rounds[round]),("document",&archive.document_rounds[round])] {
            for request in requests {
                let observed=calls.get(index).ok_or(Error::EvidenceMismatch)?;
                if observed.round!=round || observed.input_kind!=kind || observed.call.profile!=manifest.profile_id
                    || !observed.call.network_attempted || observed.call.error_code.is_some() || observed.call.http_status!=Some(request.http_status)
                    || observed.call.response_model!=request.response_model || observed.call.response_revision!=request.response_revision
                    || observed.call.serving_provider!=request.serving_provider || observed.call.usage!=request.usage {
                    return Err(Error::EvidenceMismatch);
                }
                index+=1;
            }
        }
    }
    if index!=calls.len() {return Err(Error::EvidenceMismatch);}
    Ok(())
}

pub(crate) fn verify_to_directory(config:&super::ValidatedApiConfig,args:&VerifyArgs)->Result<serde_json::Value,Error> {
    use std::collections::HashMap;
    use super::compatibility_archive::{CheckedCapture,compare_pair};
    use super::compatibility_bundle::{Bundle,Member,PairClaim,CheckedBundle,VERIFIER_VERSION};
    if args.capture_manifest.len()<2 || args.capture_manifest.len()>16 || args.capture_manifest.len()!=args.capture_manifest_sha256.len() {
        return Err(Error::InvalidEvidence);
    }
    let primary=config.profile(&args.profile).ok_or(Error::InvalidEvidence)?;
    let fallback=primary.fallback_profile.as_deref().map(|id|config.profile(id).ok_or(Error::InvalidEvidence)).transpose()?;
    let mut files:HashMap<String,Vec<u8>>=HashMap::new();
    let mut total=0usize;
    let mut keep=|kind:&str,bytes:Vec<u8>|->Result<FilePin,Error>{
        let digest=sha(&bytes);let name=format!("{kind}-{digest}.json");
        if !files.contains_key(&name) {
            total=total.checked_add(bytes.len()).ok_or(Error::InvalidEvidence)?;
            if total>64*1024*1024 {return Err(Error::InvalidEvidence);}
            files.insert(name.clone(),bytes);
        }
        Ok(FilePin{name,sha256:digest})
    };
    let mut fixture=None;let mut fixture_pin:Option<FilePin>=None;
    let mut captures=Vec::new();let mut members=Vec::new();
    for (path,digest) in args.capture_manifest.iter().zip(&args.capture_manifest_sha256) {
        let manifest_bytes=pinned(path,digest)?;
        let manifest:CaptureManifest=serde_json::from_slice(&manifest_bytes).map_err(|_|Error::InvalidEvidence)?;
        if manifest.schema!="cass.compatibility-capture.v1" {return Err(Error::InvalidEvidence);}
        let base=path.parent().unwrap_or_else(||Path::new("."));
        let fbytes=member_bytes(base,&manifest.fixture)?;
        if fixture_pin.as_ref().is_some_and(|pin|pin.sha256!=manifest.fixture.sha256) {return Err(Error::EvidenceMismatch);}
        if fixture.is_none() {
            fixture=Some(CheckedFixture::read(&fbytes,&manifest.fixture.sha256)?);
            fixture_pin=Some(keep("fixture",fbytes)?);
        }
        let checked_fixture=fixture.as_ref().ok_or(Error::InvalidEvidence)?;
        let bytes=member_bytes(base,&manifest.capture)?;
        let capture=CheckedCapture::read(&bytes,&manifest.capture.sha256,checked_fixture)?;
        let decoded:super::compatibility_archive::Capture=serde_json::from_slice(&bytes).map_err(|_|Error::InvalidEvidence)?;
        let counter=member_bytes(base,&manifest.token_receipt)?;
        let calls=member_bytes(base,&manifest.calls)?;
        validate_calls(&manifest,&decoded,&calls)?;
        let call_json=String::from_utf8(super::EndpointConfigIdentity::from_profile(&capture.profile)
            .map_err(|_|Error::InvalidEvidence)?.canonical_bytes()).map_err(|_|Error::InvalidEvidence)?;
        members.push(Member {capture:keep("capture",bytes)?,token_receipt:keep("tokens",counter)?,
            endpoint_config_sha256:capture.endpoint_sha256.clone(),call_configuration_json:call_json,sources:capture.sources().clone()});
        keep("calls",calls)?;keep("capture-manifest",manifest_bytes)?;
        captures.push(capture);
    }
    let fixture=fixture.ok_or(Error::InvalidEvidence)?;
    let selected=captures.iter().find(|c|c.digest()==args.primary_capture_sha256).ok_or(Error::EvidenceMismatch)?;
    let descriptor=super::RepresentationDescriptor::from_profile(primary,selected.dimension() as u64).map_err(|_|Error::InvalidEvidence)?;
    let mut comparisons=Vec::new();
    for i in 0..captures.len() {for j in i+1..captures.len() {
        let (left,right)=if captures[i].digest()<captures[j].digest() {(&captures[i],&captures[j])}else{(&captures[j],&captures[i])};
        comparisons.push(PairClaim {left_capture_sha256:left.digest().into(),right_capture_sha256:right.digest().into(),result:compare_pair(&fixture,left,right)?});
    }}
    let bundle=Bundle {version:1,verifier:VERIFIER_VERSION.into(),fixture:fixture_pin.ok_or(Error::InvalidEvidence)?,members,
        primary_capture_sha256:args.primary_capture_sha256.clone(),fallback_capture_sha256:args.fallback_capture_sha256.clone(),
        primary_descriptor_sha256:descriptor.sha256(),fixed_provider:fallback.and_then(|p|p.embedding()).and_then(|e|e.provider_only.clone()),
        comparisons,conclusion:"compatible".into()};
    let bytes=serde_json::to_vec_pretty(&bundle).map_err(|_|Error::InvalidEvidence)?;
    let verified=CheckedBundle::read(&bytes,primary,fallback,|pin|files.get(&pin.name).cloned().ok_or(Error::EvidenceMismatch))?;
    // Publish only after the normal reader has independently rechecked the output.
    fresh_directory(&args.output)?;
    for (name,bytes) in &files {write_new(&args.output.join(name),bytes)?;}
    write_new(&args.output.join("proof.json"),&bytes)?;
    Ok(serde_json::json!({"schema":"cass.compatibility-proof-summary.v1","status":"compatible",
        "proof_sha256":verified.digest(),"captures":bundle.members.len(),"direct_comparisons":bundle.comparisons.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::compatibility_archive::tests::{fixture,archive};
    use super::super::compatibility_capture::tests::inputs;
    use super::super::test_support::{HttpFixture,Reply};

    #[test]
    fn a_missing_credential_is_not_reported_as_a_sent_request() {
        struct Missing;
        impl super::super::CredentialResolver for Missing {fn resolve(&self,_:&str)->Option<String>{None}}
        let server=HttpFixture::start(vec![Reply::Embeddings(2)]);
        let (_,_,sources,tokens)=inputs(&server);
        let (fixture_bytes,f)=fixture();
        let template=archive(&f,1);
        let text=template.profile_toml.replace("http://127.0.0.1:1/embedding",&server.base())+"api_key_env=\"CAPTURE_TEST_KEY\"\n";
        let client=super::super::ApiClient::new(super::super::ApiConfig::parse_toml(&text).unwrap(),Box::new(Missing));
        let root=tempfile::tempdir().unwrap();
        let fp=root.path().join("fixture.json");let sp=root.path().join("sources.json");let tp=root.path().join("tokens.json");
        let source_bytes=serde_json::to_vec(&sources).unwrap();
        std::fs::write(&fp,&fixture_bytes).unwrap();std::fs::write(&sp,&source_bytes).unwrap();std::fs::write(&tp,&tokens).unwrap();
        let args=CaptureArgs {profile:"archived".into(),fixture:fp,fixture_sha256:sha(&fixture_bytes),sources:sp,sources_sha256:sha(&source_bytes),
            token_receipt:tp,token_receipt_sha256:sha(&tokens),output:root.path().join("output"),json:true};
        let result=capture_to_directory(&client,&args).unwrap();
        assert_eq!(result["status"],"failed");assert_eq!(result["call_attempts"],1);assert_eq!(result["requests"],0);
        assert_eq!(server.hits(),0);assert!(!args.output.join("capture-manifest.json").exists());
        assert!(args.output.join("capture-failure.json").is_file());
    }

    #[test]
    fn captured_endpoints_produce_replayable_proof_without_network_during_verification() {
        let (fixture_bytes,fixture)=fixture();
        let template=archive(&fixture,1);
        let vectors=&template.query_rounds[0][0].vectors;
        let replies:Vec<_>=(0..4).flat_map(|_|vectors.chunks(2).map(|chunk| Reply::ok(serde_json::json!({
            "data":chunk.iter().enumerate().map(|(index,vector)|serde_json::json!({"index":index,"embedding":vector})).collect::<Vec<_>>()
        })))).collect();
        let first=HttpFixture::start(replies.clone());let second=HttpFixture::start(replies);
        let root=tempfile::tempdir().unwrap();
        let fixture_path=root.path().join("fixture.json");std::fs::write(&fixture_path,&fixture_bytes).unwrap();
        let mut manifests=Vec::new();let mut pins=Vec::new();let mut captures=Vec::new();
        let mut selected_config=None;
        for (index,server) in [&first,&second].iter().enumerate() {
            let (client,_,sources,tokens)=inputs(server);
            if index==0 {selected_config=Some(client.config().clone());}
            let source_bytes=serde_json::to_vec(&sources).unwrap();
            let source_path=root.path().join(format!("sources-{index}.json"));let token_path=root.path().join(format!("tokens-{index}.json"));
            std::fs::write(&source_path,&source_bytes).unwrap();std::fs::write(&token_path,&tokens).unwrap();
            let output=root.path().join(format!("capture-{index}"));
            let args=CaptureArgs {profile:"archived".into(),fixture:fixture_path.clone(),fixture_sha256:sha(&fixture_bytes),
                sources:source_path,sources_sha256:sha(&source_bytes),token_receipt:token_path,token_receipt_sha256:sha(&tokens),output:output.clone(),json:true};
            let result=capture_to_directory(&client,&args).unwrap();
            assert_eq!(result["status"],"captured");assert_eq!(result["requests"],12);
            manifests.push(output.join("capture-manifest.json"));
            pins.push(result["manifest_sha256"].as_str().unwrap().to_owned());
            captures.push(result["capture_sha256"].as_str().unwrap().to_owned());
        }
        assert_eq!(first.hits(),12);assert_eq!(second.hits(),12);
        drop(first);drop(second); // All subsequent operations must be offline.
        let config=selected_config.unwrap();
        let args=VerifyArgs {profile:"archived".into(),capture_manifest:manifests,capture_manifest_sha256:pins,
            primary_capture_sha256:captures[0].clone(),fallback_capture_sha256:None,output:root.path().join("proof"),json:true};
        let result=verify_to_directory(&config,&args).unwrap();
        assert_eq!(result["status"],"compatible");assert_eq!(result["direct_comparisons"],1);
        let loaded=super::super::compatibility_bundle::CheckedBundle::load(&args.output.join("proof.json"),config.profile("archived").unwrap(),None).unwrap();
        assert_eq!(loaded.digest(),result["proof_sha256"].as_str().unwrap());
        assert!(verify_to_directory(&config,&args).is_err(),"existing proof directories remain intact");
        let original=std::fs::read(args.output.join("proof.json")).unwrap();
        assert_eq!(sha(&original),result["proof_sha256"]);
    }
}
