//! Embedder trait and types for semantic search.
//!
//! This module re-exports the canonical [`Embedder`] trait from the
//! W3-5-restored (verbatim, ex-frankensearch) [`SyncEmbed`](crate::search::frankensearch_types::SyncEmbed)
//! trait. All embedding implementations must satisfy `Embedder`, which
//! provides a synchronous embedding interface suitable for cass's sync call
//! sites.
//!
//! The [`SyncEmbedderAdapter`](crate::search::frankensearch_types::SyncEmbedderAdapter)
//! can wrap any `Embedder` implementor into the restored async `Embedder`
//! trait when needed for the frankensearch-derived search pipeline.
//!
//! # Implementations
//!
//! - **Hash embedder**: FNV-1a feature hashing (always available, ~256 dimensions)
//! - **ML embedder**: FastEmbed with the MiniLM model (requires model download, 384 dimensions)

use std::fmt;

pub use crate::search::frankensearch_types::ModelCategory;
pub use crate::search::frankensearch_types::ModelTier;
pub use crate::search::frankensearch_types::SearchError as EmbedderError;
pub use crate::search::frankensearch_types::SearchResult as EmbedderResult;
pub use crate::search::frankensearch_types::SyncEmbed as Embedder;

/// Metadata about an embedder for display and logging.
#[derive(Debug, Clone)]
pub struct EmbedderInfo {
    /// The embedder's unique identifier.
    pub id: String,
    /// The output dimension.
    pub dimension: usize,
    /// Whether it's a semantic (ML) embedder.
    pub is_semantic: bool,
}

impl EmbedderInfo {
    /// Create info from an embedder instance.
    pub fn from_embedder(embedder: &dyn Embedder) -> Self {
        Self {
            id: embedder.id().to_string(),
            dimension: embedder.dimension(),
            is_semantic: embedder.is_semantic(),
        }
    }
}

impl fmt::Display for EmbedderInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_semantic {
            "semantic"
        } else {
            "lexical"
        };
        write!(f, "{} ({}, {} dims)", self.id, kind, self.dimension)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::hash_embedder::HashEmbedder;

    #[test]
    fn test_embedder_trait_basic() {
        let embedder = HashEmbedder::new(256);
        let embedding = embedder.embed_sync("hello world").unwrap();
        assert_eq!(embedding.len(), 256);
        assert_eq!(embedder.id(), "fnv1a-256");
        assert!(!embedder.is_semantic());
    }

    // These exercise the real lexical implementation, not an ML model.
    #[test]
    fn test_hash_embedder_trait_batch_preserves_order() {
        let embedder = HashEmbedder::new(256);
        let texts = ["hello", "world", "test"];
        let embeddings = embedder.embed_batch_sync(&texts).unwrap();
        assert_eq!(embeddings.len(), 3);
        for (embedding, text) in embeddings.iter().zip(texts) {
            assert_eq!(embedding.len(), 256);
            assert_eq!(*embedding, embedder.embed_sync(text).unwrap());
        }
        assert_ne!(embeddings[0], embeddings[1]);
    }

    #[test]
    fn test_hash_embedder_trait_empty_input_error() {
        let error = HashEmbedder::new(256).embed_sync("").unwrap_err();
        match error {
            EmbedderError::InvalidConfig {
                field,
                value,
                reason,
            } => {
                assert_eq!(field, "input_text");
                assert_eq!(value, "(empty)");
                assert_eq!(reason, "empty text");
            }
            other => panic!("expected empty input error, got {other:?}"),
        }
    }

    #[test]
    fn test_hash_embedder_info_is_lexical() {
        let embedder = HashEmbedder::new(256);
        let info = EmbedderInfo::from_embedder(&embedder);
        assert_eq!(info.id, "fnv1a-256");
        assert_eq!(info.dimension, 256);
        assert!(!info.is_semantic);
        assert_eq!(info.to_string(), "fnv1a-256 (lexical, 256 dims)");
    }

    #[test]
    fn test_embedder_error_display() {
        let err = EmbedderError::EmbedderUnavailable {
            model: "test".to_string(),
            reason: "model not downloaded".to_string(),
        };
        assert!(err.to_string().contains("model not downloaded"));

        let err = EmbedderError::EmbeddingFailed {
            model: "test".to_string(),
            source: Box::new(std::io::Error::other("inference error")),
        };
        assert!(err.to_string().contains("inference error"));
    }
}
