//! Reranker trait and types for cross-encoder reranking.
//!
//! This module re-exports the canonical [`Reranker`] trait from the
//! W3-5-restored (verbatim, ex-frankensearch) [`SyncRerank`](crate::search::frankensearch_types::SyncRerank)
//! trait. All reranking implementations must satisfy `Reranker`, which
//! provides a synchronous reranking interface suitable for cass's sync call
//! sites.
//!
//! The [`SyncRerankerAdapter`](crate::search::frankensearch_types::SyncRerankerAdapter)
//! can wrap any `Reranker` implementor into the restored async `Reranker`
//! trait when needed for the frankensearch-derived search pipeline.
//!
//! # Implementations
//!
//! - **FastEmbed Reranker**: Uses ms-marco-MiniLM-L-6-v2 cross-encoder via FastEmbed.
//!   Requires model download with user consent.

use std::fmt;

pub use crate::search::frankensearch_types::SearchError as RerankerError;
pub use crate::search::frankensearch_types::SearchResult as RerankerResult;
pub use crate::search::frankensearch_types::SyncRerank as Reranker;
pub use crate::search::frankensearch_types::{RerankDocument, RerankScore};

/// Convenience function to rerank raw text documents.
///
/// Wraps `&[&str]` documents into [`RerankDocument`] structs and extracts
/// the resulting scores back into a `Vec<f32>` in original document order.
pub fn rerank_texts(
    reranker: &dyn Reranker,
    query: &str,
    documents: &[&str],
) -> RerankerResult<Vec<f32>> {
    let rerank_docs: Vec<RerankDocument> = documents
        .iter()
        .enumerate()
        .map(|(i, text)| RerankDocument {
            doc_id: i.to_string(),
            text: text.to_string(),
        })
        .collect();

    let scores = reranker.rerank_sync(query, &rerank_docs)?;

    // Convert RerankScore vec back to Vec<f32> in original document order
    let mut result = vec![0.0f32; documents.len()];
    for rs in &scores {
        if let Ok(idx) = rs.doc_id.parse::<usize>()
            && idx < result.len()
        {
            result[idx] = rs.score;
        }
    }
    Ok(result)
}

/// Metadata about a reranker for display and logging.
#[derive(Debug, Clone)]
pub struct RerankerInfo {
    /// The reranker's unique identifier.
    pub id: String,
    /// Whether the reranker is available.
    pub is_available: bool,
}

impl RerankerInfo {
    /// Create info from a reranker instance.
    pub fn from_reranker(reranker: &dyn Reranker) -> Self {
        Self {
            id: reranker.id().to_string(),
            is_available: reranker.is_available(),
        }
    }
}

impl fmt::Display for RerankerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.is_available {
            "available"
        } else {
            "unavailable"
        };
        write!(f, "{} ({})", self.id, status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::fastembed_reranker::FastEmbedReranker;
    use std::path::PathBuf;

    fn fastembed_fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/models/xenova-ms-marco-minilm-l6-v2-int8")
    }

    // Fixed oracle for the existing SyncRerank seam. It performs no conversion
    // or sorting and does not stand in for a working semantic model.
    struct OracleReranker {
        expected_query: &'static str,
        expected_documents: &'static [(&'static str, &'static str)],
        error: Option<&'static str>,
        available: bool,
    }

    impl Reranker for OracleReranker {
        fn rerank_sync(
            &self,
            query: &str,
            documents: &[RerankDocument],
        ) -> RerankerResult<Vec<RerankScore>> {
            assert_eq!(query, self.expected_query);
            assert_eq!(documents.len(), self.expected_documents.len());
            for (actual, (id, text)) in documents.iter().zip(self.expected_documents) {
                assert_eq!(actual.doc_id, *id);
                assert_eq!(actual.text, *text);
            }
            if let Some(message) = self.error {
                return Err(RerankerError::RerankFailed {
                    model: "fixed-oracle".to_string(),
                    source: Box::new(std::io::Error::other(message)),
                });
            }
            Ok(vec![
                RerankScore {
                    doc_id: "2".into(),
                    score: 0.875,
                    original_rank: 2,
                    raw_logit: None,
                },
                RerankScore {
                    doc_id: "1".into(),
                    score: 0.5,
                    original_rank: 1,
                    raw_logit: None,
                },
                RerankScore {
                    doc_id: "0".into(),
                    score: 0.125,
                    original_rank: 0,
                    raw_logit: None,
                },
            ])
        }

        fn id(&self) -> &str {
            "fixed-oracle"
        }
        fn model_name(&self) -> &str {
            "Fixed test oracle"
        }
        fn is_available(&self) -> bool {
            self.available
        }
    }

    #[test]
    fn test_rerank_texts_converts_input_and_restores_document_order() {
        let reranker = OracleReranker {
            expected_query: "test query",
            expected_documents: &[
                ("0", "short"),
                ("1", "medium length doc"),
                ("2", "longer document text"),
            ],
            error: None,
            available: true,
        };
        let scores = rerank_texts(
            &reranker,
            "test query",
            &["short", "medium length doc", "longer document text"],
        )
        .unwrap();
        assert_eq!(scores, [0.125, 0.5, 0.875]);
    }

    #[test]
    fn test_reranker_stub_unavailable_with_or_without_fixture() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for path in [fastembed_fixture_dir(), tmp.path().to_path_buf()] {
            let error = match FastEmbedReranker::load_from_dir(&path) {
                Ok(_) => panic!("the permanent stub must not load"),
                Err(error) => error,
            };
            match error {
                RerankerError::RerankerUnavailable { model } => {
                    assert_eq!(model, "ms-marco-minilm-l6-v2");
                }
                other => panic!("expected unavailable reranker, got {other:?}"),
            }
        }
    }

    fn assert_oracle_error(result: RerankerResult<Vec<f32>>, expected: &str) {
        match result.unwrap_err() {
            RerankerError::RerankFailed { model, source } => {
                assert_eq!(model, "fixed-oracle");
                assert_eq!(source.to_string(), expected);
            }
            other => panic!("expected unchanged oracle error, got {other:?}"),
        }
    }

    #[test]
    fn test_rerank_texts_forwards_empty_query_and_backend_error() {
        let reranker = OracleReranker {
            expected_query: "",
            expected_documents: &[("0", "doc")],
            error: Some("empty query sentinel"),
            available: true,
        };
        assert_oracle_error(
            rerank_texts(&reranker, "", &["doc"]),
            "empty query sentinel",
        );
    }

    #[test]
    fn test_rerank_texts_forwards_empty_documents_and_backend_error() {
        let reranker = OracleReranker {
            expected_query: "query",
            expected_documents: &[],
            error: Some("empty documents sentinel"),
            available: true,
        };
        assert_oracle_error(
            rerank_texts(&reranker, "query", &[]),
            "empty documents sentinel",
        );
    }

    #[test]
    fn test_reranker_info_preserves_backend_availability() {
        for (available, display) in [
            (true, "fixed-oracle (available)"),
            (false, "fixed-oracle (unavailable)"),
        ] {
            let reranker = OracleReranker {
                expected_query: "unused",
                expected_documents: &[],
                error: None,
                available,
            };
            let info = RerankerInfo::from_reranker(&reranker);
            assert_eq!(info.id, "fixed-oracle");
            assert_eq!(info.is_available, available);
            assert_eq!(info.to_string(), display);
        }
    }

    #[test]
    fn test_reranker_error_display() {
        let err = RerankerError::RerankFailed {
            model: "test".to_string(),
            source: Box::new(std::io::Error::other("inference error")),
        };
        assert!(err.to_string().contains("inference error"));
    }
}
