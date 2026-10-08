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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CandidateIdentity {
    pub(crate) identity_host: String,
    pub(crate) agent_slug: String,
    pub(crate) external_id: String,
    pub(crate) message_idx: i64,
    pub(crate) chunk_idx: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RetrievalSlot {
    pub(crate) input_slot: usize,
    /// One-based rank of this exact window before model sorting.
    pub(crate) retrieval_rank: usize,
    pub(crate) identity: CandidateIdentity,
    pub(crate) message_id: i64,
}

pub(crate) fn freeze_retrieval_slots(
    context: &crate::search::regression_io::RegressionIoContext,
    hits: &[crate::search::query::SearchHit],
) -> anyhow::Result<Vec<RetrievalSlot>> {
    use crate::storage::api::params;
    use anyhow::{Context, bail};
    context.verify_input()?;
    crate::search::regression_io::validate_private_run_root(context.run_root())?;
    let messages = crate::storage::api::Conn::open_frozen_read(
        &context.run_root().join("message-inventory-spool.sqlite"),
    )?;
    let chunks = crate::storage::api::Conn::open_frozen_read(
        &context.run_root().join("chunk-inventory-spool.sqlite"),
    )?;
    let mut identities = std::collections::HashSet::new();
    let mut slots = Vec::with_capacity(hits.len());
    for (input_slot, hit) in hits.iter().enumerate() {
        let message_id = hit.message_id.context("TRACE_MISSING_MESSAGE_ID")?;
        let mut identity = messages
            .query_row_map(
                "SELECT host,agent,external,idx FROM message_rows WHERE mid=?1",
                &params![message_id],
                |row| {
                    Ok(CandidateIdentity {
                        identity_host: row.get_typed(0)?,
                        agent_slug: row.get_typed(1)?,
                        external_id: row.get_typed(2)?,
                        message_idx: row.get_typed(3)?,
                        chunk_idx: None,
                    })
                },
            )
            .context("TRACE_MISSING_STABLE_CANDIDATE")?;
        if let Some(index) = hit.winning_chunk_idx {
            let index = i64::from(index);
            let present = chunks
                .query_opt_map(
                    "SELECT 1 FROM chunk_rows WHERE message_id=?1 AND chunk_idx=?2",
                    &params![message_id, index],
                    |r| r.get_typed::<i64>(0),
                )?
                .is_some();
            if !present {
                bail!("TRACE_MISSING_STABLE_CHUNK");
            }
            identity.chunk_idx = Some(index);
        }
        let key = serde_json::to_vec(&identity)?;
        if !identities.insert(key) {
            bail!("TRACE_DUPLICATE_CANDIDATE_IDENTITY");
        }
        slots.push(RetrievalSlot {
            input_slot,
            retrieval_rank: input_slot + 1,
            identity,
            message_id,
        });
    }
    context.verify_input()?;
    Ok(slots)
}

/// Preserve a permutation of the same frozen slots. Scores are not used to
/// reconstruct the retrieval order, including when model scores tie.
pub(crate) fn final_slot_mapping(
    slots: &[RetrievalSlot],
    order: &[usize],
) -> anyhow::Result<Vec<RetrievalSlot>> {
    use anyhow::bail;
    if slots.len() != order.len() {
        bail!("TRACE_INCOMPLETE_SLOT_MAPPING");
    }
    let mut seen = vec![false; slots.len()];
    let mut output = Vec::with_capacity(slots.len());
    for &index in order {
        if index >= slots.len() || std::mem::replace(&mut seen[index], true) {
            bail!("TRACE_INVALID_SLOT_MAPPING");
        }
        output.push(slots[index].clone());
    }
    Ok(output)
}

pub(crate) fn verify_submitted_slots(
    slots: &[RetrievalSlot],
    trace: &RequestTrace,
    query: &str,
    prepared_documents: &[String],
) -> anyhow::Result<()> {
    use anyhow::bail;
    let posts: Vec<_> = trace
        .requests
        .iter()
        .filter(|r| r.method == "POST")
        .collect();
    if posts.len() != 1 {
        bail!("TRACE_SCORING_REQUEST_COUNT_MISMATCH");
    }
    let documents = posts[0]
        .documents
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TRACE_MISSING_SUBMITTED_TEXT"))?;
    if posts[0].query.as_ref() != Some(&TextDigest::of(query))
        || prepared_documents.len() != slots.len()
        || documents
            .iter()
            .zip(prepared_documents)
            .any(|(actual, prepared)| actual.text != TextDigest::of(prepared))
    {
        bail!("TRACE_SUBMITTED_TEXT_MISMATCH");
    }
    if documents.len() != slots.len()
        || documents
            .iter()
            .enumerate()
            .any(|(i, d)| d.input_slot != i || slots[i].input_slot != i)
    {
        bail!("TRACE_SUBMITTED_SLOT_MAPPING_MISMATCH");
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use serde_json::json;

    fn slot(input_slot: usize) -> RetrievalSlot {
        RetrievalSlot {
            input_slot,
            retrieval_rank: input_slot + 1,
            message_id: input_slot as i64 + 1,
            identity: CandidateIdentity {
                identity_host: "local".into(),
                agent_slug: "codex".into(),
                external_id: "synthetic".into(),
                message_idx: input_slot as i64,
                chunk_idx: None,
            },
        }
    }

    #[test]
    fn original_retrieval_ranks_survive_score_order_and_incomplete_permutations_refuse() {
        let slots = vec![slot(0), slot(1), slot(2)];
        let sorted = final_slot_mapping(&slots, &[2, 0, 1]).unwrap();
        assert_eq!(
            sorted.iter().map(|r| r.retrieval_rank).collect::<Vec<_>>(),
            vec![3, 1, 2]
        );
        assert!(final_slot_mapping(&slots, &[0, 0, 2]).is_err());
        assert!(final_slot_mapping(&slots, &[0, 1]).is_err());
        assert!(final_slot_mapping(&slots, &[0, 1, 3]).is_err());
    }

    #[test]
    fn submitted_slot_mapping_rejects_document_reorder_or_changed_query() {
        let slots = vec![slot(0), slot(1)];
        let prepared = vec!["first".to_string(), "second".to_string()];
        let mut trace = RequestTrace::default();
        trace
            .begin(
                "POST",
                "/rerank",
                Some(&json!({"query":"synthetic","documents":prepared})),
            )
            .unwrap();
        verify_submitted_slots(&slots, &trace, "synthetic", &prepared).unwrap();
        assert!(verify_submitted_slots(&slots, &trace, "changed-query", &prepared).is_err());
        assert!(
            verify_submitted_slots(
                &slots,
                &trace,
                "synthetic",
                &["second".into(), "first".into()]
            )
            .is_err()
        );
        trace.requests[0].documents.as_mut().unwrap()[1].input_slot = 0;
        assert!(verify_submitted_slots(&slots, &trace, "synthetic", &prepared).is_err());
    }

    #[test]
    fn retrieval_identity_is_read_from_validated_inventory_not_inferred_from_score() {
        use super::super::regression_binding::{
            open_verified_search,
            tests::{prepare_expected, searchable_fixture},
        };
        use std::sync::Arc;
        let (root, db, run, manifest) = searchable_fixture();
        let (expected, pin) = prepare_expected(root.path(), &db, &manifest);
        let context =
            Arc::new(super::super::regression_io::RegressionIoContext::open(&db, &run).unwrap());
        let verified = open_verified_search(context.clone(), &expected, &pin, &manifest).unwrap();
        let hits = verified
            .client
            .search(
                "retrieval",
                super::super::query::SearchFilters::default(),
                10,
                0,
                super::super::query::FieldMask::FULL,
            )
            .unwrap();
        let slots = freeze_retrieval_slots(&context, &hits).unwrap();
        assert_eq!(slots[0].identity.external_id, "synthetic-session");
        assert_eq!(slots[0].identity.message_idx, 0);
        assert_eq!(slots[0].retrieval_rank, 1);
        assert!(freeze_retrieval_slots(&context, &[hits[0].clone(), hits[0].clone()]).is_err());
        let mut no_id = hits[0].clone();
        no_id.message_id = None;
        assert!(freeze_retrieval_slots(&context, &[no_id]).is_err());
        let mut wrong_chunk = hits[0].clone();
        wrong_chunk.winning_chunk_idx = Some(999);
        assert!(freeze_retrieval_slots(&context, &[wrong_chunk]).is_err());
    }
}
