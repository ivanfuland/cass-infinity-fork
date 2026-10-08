//! Request-boundary evidence. A request attempt never proves delivery or model execution.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::search::rerank::types::{RerankError, RerankFailureReason};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TextDigest {
    pub(crate) utf8_bytes: u64,
    pub(crate) sha256: String,
}

impl TextDigest {
    pub(crate) fn of(text: &str) -> Self {
        Self {
            utf8_bytes: text.len() as u64,
            sha256: hex::encode(Sha256::digest(text.as_bytes())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SubmittedDocument {
    pub(crate) input_slot: usize,
    pub(crate) text: TextDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HttpEvidence {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) state: String,
    pub(crate) query: Option<TextDigest>,
    pub(crate) documents: Option<Vec<SubmittedDocument>>,
    pub(crate) json_body_sha256: Option<String>,
    pub(crate) http_status: Option<u16>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct RequestTrace {
    pub(crate) requests: Vec<HttpEvidence>,
    /// Transport knows attempts and responses. It cannot infer GPU/model runs.
    pub(crate) model_requests: Option<usize>,
}

impl RequestTrace {
    pub(crate) fn begin(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<usize, RerankError> {
        let invalid = || RerankError::new(RerankFailureReason::InvalidInput);
        let (query, documents, json_body_sha256) = match body {
            None => (None, None, None),
            Some(body) => {
                let query = body
                    .get("query")
                    .and_then(Value::as_str)
                    .ok_or_else(invalid)?;
                let documents = body
                    .get("documents")
                    .and_then(Value::as_array)
                    .ok_or_else(invalid)?;
                let documents = documents
                    .iter()
                    .enumerate()
                    .map(|(input_slot, value)| {
                        let text = value.as_str().ok_or_else(invalid)?;
                        Ok(SubmittedDocument {
                            input_slot,
                            text: TextDigest::of(text),
                        })
                    })
                    .collect::<Result<Vec<_>, RerankError>>()?;
                let serialized = serde_json::to_vec(body).map_err(|_| invalid())?;
                (
                    Some(TextDigest::of(query)),
                    Some(documents),
                    Some(hex::encode(Sha256::digest(serialized))),
                )
            }
        };
        let index = self.requests.len();
        self.requests.push(HttpEvidence {
            method: method.into(),
            path: path.into(),
            state: "attempted-delivery-unknown".into(),
            query,
            documents,
            json_body_sha256,
            http_status: None,
        });
        Ok(index)
    }

    pub(crate) fn response(&mut self, index: usize, status: u16) -> Result<(), RerankError> {
        let item = self
            .requests
            .get_mut(index)
            .ok_or_else(|| RerankError::new(RerankFailureReason::InvalidInput))?;
        item.http_status = Some(status);
        item.state = "http-response-observed".into();
        Ok(())
    }
}
