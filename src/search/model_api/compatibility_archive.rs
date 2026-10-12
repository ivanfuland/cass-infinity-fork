//! Pinned, complete embedding-result archives. These are validated API results,
//! not copies of raw HTTP wire bytes. This layer alone grants no runtime access.
use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use super::{ApiConfig, EndpointConfigIdentity, InputKind, Normalization, ValidatedProfile};
use super::compatibility::{CompatibilityError, RetrievalVectors, compare_vectors, verify_cross_retrieval, verify_four_observations};

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_SAMPLES: usize = 64;

fn sha(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], expected: &str) -> Result<T, CompatibilityError> {
    if bytes.len() > MAX_BYTES || sha(bytes) != expected { return Err(CompatibilityError::EvidenceMismatch); }
    serde_json::from_slice(bytes).map_err(|_| CompatibilityError::InvalidEvidence)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Coverage { Chinese, English, Code, Unicode, Short, Long }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Sample { pub id: String, pub text: String, pub coverage: Coverage }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueryLabel { pub sample: String, pub expected_document: String }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fixture {
    pub version: u32,
    pub samples: Vec<Sample>,
    pub documents: Vec<String>,
    pub queries: Vec<QueryLabel>,
}

pub(crate) struct CheckedFixture {
    data: Fixture,
    digest: String,
    documents: Vec<usize>,
    queries: Vec<usize>,
    labels: Vec<usize>,
}
impl CheckedFixture {
    pub(crate) fn read(bytes: &[u8], expected: &str) -> Result<Self, CompatibilityError> {
        let data: Fixture = decode(bytes, expected)?;
        if data.version != 1 || data.samples.len() > MAX_SAMPLES || data.samples.len() < 6
            || data.documents.len() < 2 || data.queries.len() < 2 { return Err(CompatibilityError::InvalidFixture); }
        let mut ids = HashSet::new();
        let mut coverage = HashSet::new();
        for sample in &data.samples {
            if sample.id.is_empty() || sample.id.len() > 64 || !ids.insert(sample.id.as_str()) || sample.text.is_empty() {
                return Err(CompatibilityError::InvalidFixture);
            }
            coverage.insert(sample.coverage);
        }
        if coverage.len() != 6 { return Err(CompatibilityError::InvalidFixture); }
        let locate = |id: &str| data.samples.iter().position(|s| s.id == id).ok_or(CompatibilityError::InvalidFixture);
        let documents = data.documents.iter().map(|id| locate(id)).collect::<Result<Vec<_>, _>>()?;
        let queries = data.queries.iter().map(|q| locate(&q.sample)).collect::<Result<Vec<_>, _>>()?;
        if documents.iter().collect::<HashSet<_>>().len() != documents.len()
            || queries.iter().collect::<HashSet<_>>().len() != queries.len()
            || queries.iter().any(|q| documents.contains(q)) { return Err(CompatibilityError::InvalidFixture); }
        let labels = data.queries.iter().map(|q| data.documents.iter().position(|id| id == &q.expected_document)
            .ok_or(CompatibilityError::InvalidFixture)).collect::<Result<Vec<_>, _>>()?;
        if labels.iter().collect::<HashSet<_>>().len() < 2 { return Err(CompatibilityError::InvalidFixture); }
        Ok(Self { data, digest: expected.to_owned(), documents, queries, labels })
    }
}

/// Source declarations remain declarations. Service observations live separately.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeclarationBasis { OperatorDeclared }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Declaration { pub basis: DeclarationBasis, pub value: String }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Sources {
    pub weights: Declaration, pub tokenizer: Declaration, pub pooling: Declaration,
    pub server_input_template: Declaration,
    pub token_counter: Declaration,
    pub token_counter_artifact_sha256: String,
    pub safe_input_tokens: u64,
    pub query_token_counts: Vec<u64>,
    pub document_token_counts: Vec<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponseCapture {
    pub inputs: Vec<String>,
    pub vectors: Vec<Vec<f32>>,
    pub http_status: u16,
    pub response_model: Option<String>,
    pub response_revision: Option<String>,
    pub serving_provider: Option<String>,
    pub usage: Option<super::runtime::CheckUsage>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Capture {
    pub version: u32,
    /// One standalone profile, with routing references removed; no credentials.
    pub profile_toml: String,
    pub endpoint_config_sha256: String,
    pub fixture_sha256: String,
    pub dimension: usize,
    pub sources: Sources,
    pub query_rounds: [Vec<ResponseCapture>; 2],
    pub document_rounds: [Vec<ResponseCapture>; 2],
}

pub(crate) struct CheckedCapture {
    digest: String,
    pub(crate) profile: ValidatedProfile,
    pub(crate) endpoint_sha256: String,
    fixture_sha256: String,
    dimension: usize,
    sources: Sources,
    query_inputs: Vec<String>,
    document_inputs: Vec<String>,
    query_rounds: [Vec<Vec<f32>>; 2],
    document_rounds: [Vec<Vec<f32>>; 2],
}
impl CheckedCapture {
    pub(crate) fn read(bytes: &[u8], expected: &str, fixture: &CheckedFixture) -> Result<Self, CompatibilityError> {
        let data: Capture = decode(bytes, expected)?;
        if data.version != 1 || data.fixture_sha256 != fixture.digest || data.dimension == 0 {
            return Err(CompatibilityError::InvalidEvidence);
        }
        let config = ApiConfig::parse_toml(&data.profile_toml).map_err(|_| CompatibilityError::InvalidEvidence)?;
        if config.profiles().count() != 1 { return Err(CompatibilityError::InvalidEvidence); }
        let profile = config.profiles().next().ok_or(CompatibilityError::InvalidEvidence)?.clone();
        let embedding = profile.embedding().ok_or(CompatibilityError::InvalidEvidence)?;
        if profile.fallback_profile.is_some() || embedding.fallback_compatibility_file.is_some()
            || embedding.expected_dimension.is_some_and(|d| d != data.dimension as u64)
            || embedding.request_dimensions.is_some_and(|d| d != data.dimension as u64)
            || EndpointConfigIdentity::from_profile(&profile).map_err(|_| CompatibilityError::InvalidEvidence)?.sha256() != data.endpoint_config_sha256 {
            return Err(CompatibilityError::EvidenceMismatch);
        }
        let source = &data.sources;
        if [&source.weights, &source.tokenizer, &source.pooling, &source.server_input_template, &source.token_counter]
            .iter().any(|d| d.value.trim().is_empty() || d.value.len() > 4096)
            || source.safe_input_tokens == 0 || !valid_sha(&source.token_counter_artifact_sha256) {
            return Err(CompatibilityError::InvalidEvidence);
        }
        for counts in [&source.query_token_counts, &source.document_token_counts] {
            if counts.len() != fixture.data.samples.len() || counts.iter().any(|n| *n == 0 || *n > source.safe_input_tokens) {
                return Err(CompatibilityError::InvalidEvidence);
            }
        }
        let inputs = |kind| fixture.data.samples.iter().map(|s| super::protocol::embedding_input(&profile, kind, &s.text)).collect::<Vec<_>>();
        let query_inputs = inputs(InputKind::Query);
        let document_inputs = inputs(InputKind::Document);
        let flatten = |calls: &[ResponseCapture], expected: &[String]| -> Result<Vec<Vec<f32>>, CompatibilityError> {
            if calls.is_empty() || calls.len() > expected.len() { return Err(CompatibilityError::InvalidEvidence); }
            let mut seen_inputs = Vec::new();
            let mut vectors = Vec::new();
            for call in calls {
                if !(200..300).contains(&call.http_status) || call.inputs.is_empty() || call.inputs.len() as u64 > embedding.max_batch
                    || call.inputs.len() != call.vectors.len()
                    || call.usage.as_ref().and_then(|u| u.cost).is_some_and(|c| !c.is_finite() || c < 0.0)
                    || call.response_model.as_ref().is_some_and(|m| m != &profile.model && !profile.response_model_aliases.contains(m))
                    || call.response_revision.as_ref().is_some_and(|r| r != &profile.model_revision)
                    || call.serving_provider.as_ref().zip(embedding.provider_only.as_ref()).is_some_and(|(a,b)| a != b) {
                    return Err(CompatibilityError::InvalidEvidence);
                }
                for vector in &call.vectors {
                    if vector.len() != data.dimension { return Err(CompatibilityError::DimensionMismatch); }
                    compare_vectors(vector, vector, embedding.normalization)?;
                    if embedding.normalization == Normalization::L2 {
                        let norm = vector.iter().map(|v| f64::from(*v).powi(2)).sum::<f64>().sqrt();
                        if (norm - 1.0).abs() > 0.00001 { return Err(CompatibilityError::InvalidVector); }
                    }
                }
                seen_inputs.extend(call.inputs.iter().cloned()); vectors.extend(call.vectors.iter().cloned());
            }
            if seen_inputs != expected { return Err(CompatibilityError::InputMismatch); }
            Ok(vectors)
        };
        let query_rounds = [flatten(&data.query_rounds[0], &query_inputs)?, flatten(&data.query_rounds[1], &query_inputs)?];
        let document_rounds = [flatten(&data.document_rounds[0], &document_inputs)?, flatten(&data.document_rounds[1], &document_inputs)?];
        Ok(Self { digest: expected.to_owned(), endpoint_sha256: data.endpoint_config_sha256,
            fixture_sha256: data.fixture_sha256, dimension: data.dimension, sources: data.sources,
            profile, query_inputs, document_inputs, query_rounds, document_rounds })
    }
    pub(crate) fn digest(&self) -> &str { &self.digest }
}
fn valid_sha(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }

pub(crate) fn verify_pair(fixture: &CheckedFixture, left: &CheckedCapture, right: &CheckedCapture) -> Result<(), CompatibilityError> {
    if left.fixture_sha256 != fixture.digest || right.fixture_sha256 != fixture.digest
        || left.query_inputs != right.query_inputs || left.document_inputs != right.document_inputs {
        return Err(CompatibilityError::InputMismatch);
    }
    if left.dimension != right.dimension { return Err(CompatibilityError::DimensionMismatch); }
    let shared_limit = left.sources.safe_input_tokens.min(right.sources.safe_input_tokens);
    let near_limit = |counts: &[u64]| fixture.data.samples.iter().zip(counts).any(|(s,n)| s.coverage == Coverage::Long
        && u128::from(*n) * 10 >= u128::from(shared_limit) * 9);
    for source in [&left.sources, &right.sources] {
        if !near_limit(&source.query_token_counts) || !near_limit(&source.document_token_counts) { return Err(CompatibilityError::InvalidFixture); }
    }
    let normalization = if [left,right].iter().any(|c| c.profile.embedding().is_some_and(|p| p.normalization == Normalization::None)) {
        Normalization::None
    } else { Normalization::L2 };
    for (a,b) in [(&left.query_rounds,&right.query_rounds), (&left.document_rounds,&right.document_rounds)] {
        for index in 0..fixture.data.samples.len() {
            verify_four_observations([&a[0][index], &a[1][index], &b[0][index], &b[1][index]], normalization)?;
        }
    }
    let queries = |c: &CheckedCapture| c.query_rounds.each_ref().map(|r| fixture.queries.iter().map(|i| r[*i].clone()).collect::<Vec<_>>());
    let docs = |c: &CheckedCapture| c.document_rounds.each_ref().map(|r| fixture.documents.iter().map(|i| r[*i].clone()).collect::<Vec<_>>());
    let (lq,rq,ld,rd) = (queries(left), queries(right), docs(left), docs(right));
    verify_cross_retrieval([
        RetrievalVectors { query_rounds:[&lq[0],&lq[1]], document_rounds:[&ld[0],&ld[1]] },
        RetrievalVectors { query_rounds:[&rq[0],&rq[1]], document_rounds:[&rd[0],&rd[1]] },
    ], &fixture.labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Vec<u8>, CheckedFixture) {
        let data = Fixture { version:1, samples: vec![
            Sample{id:"q1".into(),text:"Rust 所有权是什么？".into(),coverage:Coverage::Chinese},
            Sample{id:"d1".into(),text:"Rust ownership tracks values.".into(),coverage:Coverage::English},
            Sample{id:"d2".into(),text:"fn lock() {}".into(),coverage:Coverage::Code},
            Sample{id:"unicode".into(),text:"café ☃".into(),coverage:Coverage::Unicode},
            Sample{id:"q2".into(),text:"lock".into(),coverage:Coverage::Short},
            Sample{id:"long".into(),text:"x ".repeat(48),coverage:Coverage::Long},
        ], documents:vec!["d1".into(),"d2".into()], queries:vec![
            QueryLabel{sample:"q1".into(),expected_document:"d1".into()},
            QueryLabel{sample:"q2".into(),expected_document:"d2".into()},
        ]};
        let bytes = serde_json::to_vec(&data).unwrap();
        let checked = CheckedFixture::read(&bytes, &sha(&bytes)).unwrap();
        (bytes, checked)
    }
    fn archive(fixture: &CheckedFixture, port: u16) -> Capture {
        let toml = format!("version=1\n[profiles.archived]\nkind=\"embedding\"\nprotocol=\"openai-embeddings-v1\"\nendpoint=\"http://127.0.0.1:{port}/embedding\"\nscope=\"loopback\"\nmodel=\"example/embedding\"\nmodel_revision=\"r1\"\nnormalization=\"l2\"\nquery_prefix=\"Q:\"\ndocument_prefix=\"D:\"\n");
        let config = ApiConfig::parse_toml(&toml).unwrap();
        let profile = config.profile("archived").unwrap();
        let build = |kind| {
            let inputs: Vec<_> = fixture.data.samples.iter().map(|s| super::super::protocol::embedding_input(profile,kind,&s.text)).collect();
            let c = std::f32::consts::FRAC_1_SQRT_2;
            ResponseCapture{inputs, vectors:vec![vec![1.0,0.0],vec![1.0,0.0],vec![0.0,1.0],vec![c,c],vec![0.0,1.0],vec![c,c]],
                http_status:200,response_model:None,response_revision:None,serving_provider:None,usage:None}
        };
        let query = build(InputKind::Query); let doc = build(InputKind::Document);
        let declaration = || Declaration {basis:DeclarationBasis::OperatorDeclared,value:"synthetic test source".into()};
        Capture{version:1,profile_toml:toml.clone(),endpoint_config_sha256:EndpointConfigIdentity::from_profile(profile).unwrap().sha256(),
            fixture_sha256:fixture.digest.clone(),dimension:2,
            sources:Sources{weights:declaration(),tokenizer:declaration(),pooling:declaration(),server_input_template:declaration(),
                token_counter:Declaration{basis:DeclarationBasis::OperatorDeclared,value:"synthetic Unicode-scalar tokenizer".into()},
                token_counter_artifact_sha256:sha(b"synthetic Unicode-scalar tokenizer"),safe_input_tokens:100,
                query_token_counts:query.inputs.iter().map(|s|s.chars().count() as u64).collect(),
                document_token_counts:doc.inputs.iter().map(|s|s.chars().count() as u64).collect()},
            query_rounds:[vec![query.clone()],vec![query]],document_rounds:[vec![doc.clone()],vec![doc]]}
    }
    fn check(data:&Capture, fixture:&CheckedFixture) -> Result<CheckedCapture,CompatibilityError> {
        let bytes=serde_json::to_vec(data).unwrap(); CheckedCapture::read(&bytes,&sha(&bytes),fixture)
    }
    #[test]
    fn complete_archives_compare_without_inventing_service_identity() {
        let (_,fixture)=fixture();
        let a=check(&archive(&fixture,1),&fixture).unwrap();
        let b=check(&archive(&fixture,2),&fixture).unwrap();
        assert_ne!(a.endpoint_sha256,b.endpoint_sha256);
        assert_ne!(a.digest(),b.digest());
        verify_pair(&fixture,&a,&b).unwrap();
    }
    #[test]
    fn pins_shape_and_observed_identity_are_checked_before_comparison() {
        let (bytes,fixture)=fixture(); let original=archive(&fixture,1);
        assert!(CheckedFixture::read(&bytes,&"0".repeat(64)).is_err());
        for mutation in 0..7 {
            let mut changed=original.clone();
            match mutation {
                0=>changed.endpoint_config_sha256="0".repeat(64),
                1=>changed.query_rounds[1][0].inputs[0].push('x'),
                2=>{changed.document_rounds[1][0].vectors.pop();},
                3=>changed.query_rounds[0][0].response_model=Some("other".into()),
                4=>changed.query_rounds[0][0].vectors[0]=vec![2.0,0.0],
                5=>changed.sources.query_token_counts[0]=101,
                _=>changed.sources.token_counter_artifact_sha256.clear(),
            }
            assert!(check(&changed,&fixture).is_err(),"mutation {mutation}");
        }
        let mut raw=serde_json::to_string(&original).unwrap();
        raw.insert_str(1,"\"version\":1,");
        assert!(CheckedCapture::read(raw.as_bytes(),&sha(raw.as_bytes()),&fixture).is_err());
    }
    #[test]
    fn a_bad_second_round_cannot_hide_behind_good_first_rounds() {
        let (_,fixture)=fixture(); let a=archive(&fixture,1); let mut b=archive(&fixture,2);
        b.query_rounds[1][0].vectors[0]=vec![0.999999,0.0014];
        let a=check(&a,&fixture).unwrap(); let b=check(&b,&fixture).unwrap();
        assert_eq!(verify_pair(&fixture,&a,&b),Err(CompatibilityError::NumericalMismatch));
    }
    #[test]
    fn equal_vectors_do_not_override_changed_processed_inputs() {
        let (_,fixture)=fixture(); let a=archive(&fixture,1); let mut b=archive(&fixture,2);
        b.profile_toml=b.profile_toml.replace("query_prefix=\"Q:\"","query_prefix=\"Other:\"");
        let config=ApiConfig::parse_toml(&b.profile_toml).unwrap();
        b.endpoint_config_sha256=EndpointConfigIdentity::from_profile(config.profile("archived").unwrap()).unwrap().sha256();
        for round in &mut b.query_rounds { for call in round { for input in &mut call.inputs { *input=input.replacen("Q:","Other:",1); } } }
        b.sources.query_token_counts=b.query_rounds[0][0].inputs.iter().map(|s|s.chars().count() as u64).collect();
        b.sources.safe_input_tokens=110;
        let a=check(&a,&fixture).unwrap(); let b=check(&b,&fixture).unwrap();
        assert_eq!(verify_pair(&fixture,&a,&b),Err(CompatibilityError::InputMismatch));
    }
}
