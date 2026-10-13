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

pub(crate) fn candidate_instance_key(identity: &CandidateIdentity) -> anyhow::Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(identity)?)))
}

/// Shared off evidence for the normal regression-input search and aggregate.
pub(crate) fn off_evidence(
    context: &crate::search::regression_io::RegressionIoContext,
    binding: &crate::search::regression_binding::InputBinding,
    query: &str,
    hits: &[crate::search::query::SearchHit],
    request: Value,
    lexical_statistics_used: bool,
) -> anyhow::Result<WindowEvidence> {
    let retrieval = freeze_retrieval_slots(context, hits)?;
    let evidence = WindowEvidence {
        api_rerank: None,
        schema: "cass.regression-window-trace.v2".into(),
        binding: binding.clone(), query: TextDigest::of(query), request,
        transport_scope: "rerank-http-v1".into(), lexical_statistics_used,
        lexical_statistics_sha256: lexical_statistics_used.then(|| binding.lexical_statistics_sha256.clone()),
        final_slots: retrieval.clone(), retrieval,
        snippets: hits.iter().map(|h| TextDigest::of(&h.content)).collect(),
        prepared_documents: None, transport: Default::default(),
        rerank_requested: false, applied: false, failure_reason: None,
    };
    evidence.validate(context, binding, query, hits, false)?;
    Ok(evidence)
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

/// Shared proof of which model requests could produce a complete result.
pub(crate) fn validate_model_attempts(
    trace: &RequestTrace,
    route: Option<&crate::search::rerank::window::ApiWindowRoute>,
    api_rerank: Option<&crate::search::rerank::window::ApiWindowRerank>,
    applied: bool,
) -> anyhow::Result<()> {
    use anyhow::bail;
    let posts: Vec<_> = trace.requests.iter().filter(|r| r.method == "POST").collect();
    if route.is_some() && posts.len() != trace.requests.len() { bail!("TRACE_SCORING_REQUEST_COUNT_MISMATCH"); }
    if trace.model_requests.is_some() { bail!("TRACE_MODEL_EXECUTION_UNPROVEN"); }
    for post in &posts {
        if !post.json_body_sha256.as_ref().is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
            bail!("TRACE_MISSING_SUBMITTED_TEXT");
        }
    }
        let maximum = if route.is_some_and(|r| r.allow_fallback && r.fallback_profile.is_some()) { 2 } else { 1 };
        if posts.len() > maximum || (applied && posts.is_empty()) {
            bail!("TRACE_SCORING_REQUEST_COUNT_MISMATCH");
        }
        match (route, api_rerank) {
            (Some(route), Some(api)) => {
                let attempts = &api.attempts;
                if api.primary_profile != route.rerank_profile || attempts.len() > maximum
                    || attempts.first().is_some_and(|a| a.profile != route.rerank_profile)
                    || attempts.get(1).is_some_and(|a| Some(&a.profile) != route.fallback_profile.as_ref()) {
                    bail!("TRACE_WINDOW_REQUEST_MISMATCH");
                }
                let sent: Vec<_> = attempts.iter().filter(|a| a.network_attempted).collect();
                if sent.len() != posts.len() || sent.iter().zip(&posts).any(|(a,p)| a.http_status != p.http_status) {
                    bail!("TRACE_SCORING_REQUEST_COUNT_MISMATCH");
                }
                if attempts.len() == 2 {
                    let first = &attempts[0];
                    let eligible = match first.http_status {
                        Some(status) => [408,429,500,502,503,504].contains(&status),
                        None => matches!(first.error_code.as_deref(), Some("timeout" | "connection_refused" | "connection_interrupted" | "network_unavailable")),
                    };
                    if !eligible || first.error_code.is_none() || api.fallback_reason != first.error_code {
                        bail!("TRACE_WINDOW_REQUEST_MISMATCH");
                    }
                }
                if applied {
                    let winner = attempts.last().ok_or_else(|| anyhow::anyhow!("TRACE_SCORING_RESPONSE_UNPROVEN"))?;
                    if api.realized_profile.as_ref() != Some(&winner.profile) || winner.error_code.is_some()
                        || api.fallback_used != (attempts.len() == 2) {
                        bail!("TRACE_SCORING_RESPONSE_UNPROVEN");
                    }
                } else if api.realized_profile.is_some() || api.fallback_used { bail!("TRACE_SCORING_RESPONSE_UNPROVEN"); }
            }
            (Some(_), None) if !posts.is_empty() || applied => bail!("TRACE_SCORING_RESPONSE_UNPROVEN"),
            (None, Some(_)) => bail!("TRACE_WINDOW_REQUEST_MISMATCH"),
            _ => {}
        }
    Ok(())
}

/// Stored inside the private window. The existing hit wire format stays intact.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) api_rerank: Option<crate::search::rerank::window::ApiWindowRerank>,
    pub(crate) schema: String,
    pub(crate) binding: crate::search::regression_binding::InputBinding,
    pub(crate) query: TextDigest,
    pub(crate) request: Value,
    /// Only rerank HTTP attempts are represented by `transport`.
    pub(crate) transport_scope: String,
    pub(crate) lexical_statistics_used: bool,
    pub(crate) lexical_statistics_sha256: Option<String>,
    pub(crate) retrieval: Vec<RetrievalSlot>,
    pub(crate) final_slots: Vec<RetrievalSlot>,
    pub(crate) snippets: Vec<TextDigest>,
    pub(crate) prepared_documents: Option<Vec<TextDigest>>,
    pub(crate) transport: RequestTrace,
    pub(crate) rerank_requested: bool,
    pub(crate) applied: bool,
    pub(crate) failure_reason: Option<String>,
}

impl WindowEvidence {
    pub(crate) fn validate(
        &self,
        context: &crate::search::regression_io::RegressionIoContext,
        binding: &crate::search::regression_binding::InputBinding,
        query: &str,
        hits: &[crate::search::query::SearchHit],
        applied: bool,
    ) -> anyhow::Result<()> {
        use anyhow::bail;
        if self.schema != "cass.regression-window-trace.v2"
            || self.transport_scope != "rerank-http-v1"
            || !self.request.is_object()
            || &self.binding != binding
            || self.query != TextDigest::of(query)
            || self.applied != applied
            || (applied && (!self.rerank_requested || self.failure_reason.is_some()))
        {
            bail!("TRACE_WINDOW_BINDING_MISMATCH");
        }
        match self.request.get("mode").and_then(Value::as_str) {
            Some("semantic") if !self.lexical_statistics_used => {}
            Some("lexical" | "hybrid") if self.lexical_statistics_used => {}
            _ => bail!("TRACE_WINDOW_REQUEST_MISMATCH"),
        }
        if self.lexical_statistics_sha256.as_deref()
            != self
                .lexical_statistics_used
                .then_some(self.binding.lexical_statistics_sha256.as_str())
        {
            bail!("TRACE_WINDOW_REQUEST_MISMATCH");
        }
        let actual = freeze_retrieval_slots(context, hits)?;
        let permutation: Vec<_> = self.final_slots.iter().map(|s| s.input_slot).collect();
        if final_slot_mapping(&self.retrieval, &permutation)? != self.final_slots
            || actual.len() != self.final_slots.len()
            || self.snippets.len() != self.retrieval.len()
            || self
                .retrieval
                .iter()
                .enumerate()
                .any(|(i, s)| s.input_slot != i || s.retrieval_rank != i + 1)
            || actual
                .iter()
                .zip(&self.final_slots)
                .any(|(a, s)| a.identity != s.identity || a.message_id != s.message_id)
        {
            bail!("TRACE_WINDOW_SLOT_MAPPING_MISMATCH");
        }
        if hits.iter().zip(&self.final_slots).any(|(hit, slot)| {
            self.snippets.get(slot.input_slot) != Some(&TextDigest::of(&hit.content))
        }) {
            bail!("TRACE_WINDOW_SNIPPET_MISMATCH");
        }
        let posts: Vec<_> = self
            .transport
            .requests
            .iter()
            .filter(|r| r.method == "POST")
            .collect();
        let route = self.request.get("model_api_route").filter(|v| !v.is_null())
            .map(|v| serde_json::from_value::<crate::search::rerank::window::ApiWindowRoute>(v.clone()))
            .transpose().map_err(|_| anyhow::anyhow!("TRACE_WINDOW_REQUEST_MISMATCH"))?;
        validate_model_attempts(&self.transport, route.as_ref(), self.api_rerank.as_ref(), applied)?;
        for (index, post) in posts.iter().enumerate() {
            let docs = post
                .documents
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("TRACE_MISSING_SUBMITTED_TEXT"))?;
            let prepared = self
                .prepared_documents
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("TRACE_MISSING_SUBMITTED_TEXT"))?;
            if post.query.as_ref() != Some(&self.query)
                || docs.len() != self.retrieval.len()
                || prepared.len() != docs.len()
                || docs
                    .iter()
                    .zip(prepared)
                    .enumerate()
                    .any(|(i, (doc, expected))| doc.input_slot != i || &doc.text != expected)
            {
                bail!("TRACE_SUBMITTED_TEXT_MISMATCH");
            }
            if applied && index + 1 == posts.len()
                && (post.state != "http-response-observed"
                    || !post.http_status.is_some_and(|s| (200..300).contains(&s)))
            {
                bail!("TRACE_SCORING_RESPONSE_UNPROVEN");
            }
        }
        if self.transport.model_requests.is_some() {
            bail!("TRACE_MODEL_EXECUTION_UNPROVEN");
        }
        context.verify_input()?;
        Ok(())
    }
}

pub(crate) fn persist_evidence(
    context: &crate::search::regression_io::RegressionIoContext,
    evidence: &WindowEvidence,
) -> anyhow::Result<std::path::PathBuf> {
    use std::io::Write;
    crate::search::regression_io::validate_private_run_root(context.run_root())?;
    context.verify_input()?;
    let mut file = tempfile::Builder::new()
        .prefix("regression-search-")
        .suffix(".json")
        .tempfile_in(context.run_root())?;
    serde_json::to_writer(file.as_file_mut(), evidence)?;
    file.as_file_mut().write_all(b"\n")?;
    file.as_file().sync_all()?;
    let (_, path) = file.keep()?;
    context.verify_input()?;
    Ok(path)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PageEvidence {
    pub(crate) schema: String,
    pub(crate) window_id: String,
    pub(crate) trace_sha256: String,
    pub(crate) offset: usize,
    pub(crate) total_slots: usize,
    pub(crate) slots: Vec<RetrievalSlot>,
    pub(crate) cache_reused: bool,
    pub(crate) http_requests: usize,
    pub(crate) model_requests: Option<usize>,
}

pub(crate) fn persist_page(
    context: &crate::search::regression_io::RegressionIoContext,
    evidence: &WindowEvidence,
    window_id: &str,
    offset: usize,
    limit: usize,
    cache_reused: bool,
) -> anyhow::Result<std::path::PathBuf> {
    use std::io::Write;
    if offset >= evidence.final_slots.len() || limit == 0 {
        anyhow::bail!("TRACE_INVALID_PAGE_RANGE");
    }
    let page = PageEvidence {
        schema: "cass.regression-page.v1".into(),
        window_id: window_id.into(),
        trace_sha256: hex::encode(Sha256::digest(serde_json::to_vec(evidence)?)),
        offset,
        total_slots: evidence.final_slots.len(),
        slots: evidence
            .final_slots
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect(),
        cache_reused,
        http_requests: if cache_reused {
            0
        } else {
            evidence.transport.requests.len()
        },
        model_requests: if cache_reused || evidence.transport.requests.is_empty() {
            Some(0)
        } else {
            None
        },
    };
    crate::search::regression_io::validate_private_run_root(context.run_root())?;
    context.verify_input()?;
    let mut file = tempfile::Builder::new()
        .prefix("regression-page-")
        .suffix(".json")
        .tempfile_in(context.run_root())?;
    serde_json::to_writer(file.as_file_mut(), &page)?;
    file.as_file_mut().write_all(b"\n")?;
    file.as_file().sync_all()?;
    let (_, path) = file.keep()?;
    context.verify_input()?;
    Ok(path)
}

/// A quality runner must prove a complete page sequence, not just page one.
pub(crate) fn validate_complete_pages(
    pages: &[PageEvidence],
    evidence: &WindowEvidence,
) -> anyhow::Result<()> {
    let mut offset: usize = 0;
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(evidence)?));
    let first = pages
        .first()
        .ok_or_else(|| anyhow::anyhow!("TRACE_MISSING_PAGES"))?;
    for (index, page) in pages.iter().enumerate() {
        let end = offset
            .checked_add(page.slots.len())
            .ok_or_else(|| anyhow::anyhow!("TRACE_PAGE_SEQUENCE_MISMATCH"))?;
        if page.schema != "cass.regression-page.v1"
            || page.window_id != first.window_id
            || page.trace_sha256 != digest
            || page.offset != offset
            || page.total_slots != evidence.final_slots.len()
            || page.slots.is_empty()
            || evidence.final_slots.get(offset..end) != Some(page.slots.as_slice())
            || page.cache_reused != (index > 0)
            || (index == 0
                && (page.http_requests != evidence.transport.requests.len()
                    || page.model_requests
                        != if evidence.transport.requests.is_empty() {
                            Some(0)
                        } else {
                            None
                        }))
            || (index > 0 && (page.http_requests != 0 || page.model_requests != Some(0)))
        {
            anyhow::bail!("TRACE_PAGE_SEQUENCE_MISMATCH");
        }
        offset = end;
    }
    if offset != evidence.final_slots.len() {
        anyhow::bail!("TRACE_MISSING_PAGES");
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
    fn api_fallback_trace_validates_both_real_requests_and_rejects_tampering() {
        use crate::search::model_api::{ApiConfig, ApiClient, CredentialResolver};
        use crate::search::model_api::test_support::{HttpFixture, TlsFixture, Reply};
        use crate::search::regression_binding::{open_verified_search, tests::{searchable_fixture_with_count, prepare_expected}};
        use std::sync::{Arc, Mutex};
        struct NoCredentials;
        impl CredentialResolver for NoCredentials { fn resolve(&self, _: &str) -> Option<String> { None } }
        let (root, db, run, manifest) = searchable_fixture_with_count(7);
        let (expected, pin) = prepare_expected(root.path(), &db, &manifest);
        let context = Arc::new(super::super::regression_io::RegressionIoContext::open(&db, &run).unwrap());
        let verified = open_verified_search(context.clone(), &expected, &pin, &manifest).unwrap();
        let hits = verified.client.search("retrieval", Default::default(), 7, 0, super::super::query::FieldMask::FULL).unwrap();
        let documents = super::super::rerank::context::build_documents_for_regression(&context, "retrieval", &hits).unwrap();
        let local = HttpFixture::start(vec![Reply::status(503)]);
        let cloud = TlsFixture::start(vec![Reply::ok(json!({"results":(0..hits.len()).map(|i| json!({"index":i,"relevance_score":i as f64})).collect::<Vec<_>>() }))]);
        let config = ApiConfig::parse_toml(&format!(r#"
version=1
default_rerank="local"
[profiles.local]
kind="rerank"
protocol="rerank-json-v1"
scope="loopback"
endpoint="{}"
model="example/local"
model_revision="r1"
fallback_profile="cloud"
[profiles.cloud]
kind="rerank"
protocol="openrouter-rerank-v1"
scope="remote"
endpoint="{}"
model="example/cloud"
model_revision="r1"
provider_only="fixed-provider"
"#, local.base(), cloud.base())).unwrap();
        let options = crate::SemanticSearchOptions {
            api: crate::ApiSearchOptions { frozen: Some(config.clone()), ..Default::default() },
            rerank: true, rerank_limit: Some(3), ..Default::default()
        };
        let request = crate::regression_request_evidence(&Default::default(), super::super::query::SearchMode::Lexical,
            super::super::query::VectorSearchMode::Exact, 7, None, &options, &Default::default(), None).unwrap();
        let mut proof = off_evidence(&context, &verified.binding, "retrieval", &hits, request, true).unwrap();
        let trace = Arc::new(Mutex::new(RequestTrace::default()));
        let client = ApiClient::new_with_test_root(config, Box::new(NoCredentials), cloud.ca_pem().to_vec()).with_rerank_trace(trace.clone());
        let response = super::super::model_api::rerank_call::score(&client, "local", "retrieval", &documents, true, &mut proof.api_rerank).unwrap();
        let order = super::super::rerank::types::stable_rank_order(&response.scores).unwrap();
        let sorted: Vec<_> = order.iter().map(|i| hits[*i].clone()).collect();
        proof.final_slots = final_slot_mapping(&proof.retrieval, &order).unwrap();
        proof.prepared_documents = Some(documents.iter().map(|s| TextDigest::of(s)).collect());
        proof.transport = trace.lock().unwrap().clone();
        proof.rerank_requested = true;
        proof.applied = true;
        proof.validate(&context, &verified.binding, "retrieval", &sorted, true).unwrap();
        assert_eq!(local.hits(), 1);
        assert_eq!(cloud.fixture().hits(), 1);
        for mutation in 0..5 {
            let mut bad = proof.clone();
            match mutation {
                0 => {
                    bad.transport.requests[0].http_status = Some(401);
                    bad.api_rerank.as_mut().unwrap().attempts[0].http_status = Some(401);
                }
                1 => bad.transport.requests[1].documents.as_mut().unwrap()[0].text = TextDigest::of("changed"),
                2 => bad.request["model_api_route"]["allow_fallback"] = json!(false),
                3 => bad.transport.requests[0].documents.as_mut().unwrap()[0].input_slot = 1,
                _ => bad.api_rerank.as_mut().unwrap().attempts[1].error_code = Some("InvalidResponse".into()),
            }
            assert!(bad.validate(&context, &verified.binding, "retrieval", &sorted, true).is_err(), "mutation {mutation}");
        }
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
