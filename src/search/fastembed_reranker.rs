//! FastEmbed-based cross-encoder reranker (ms-marco-MiniLM-L-6-v2).
//!
//! # OQ3 (W3-5): unconditional local no-op stub
//!
//! Previously this module re-exported `frankensearch::FastEmbedReranker`
//! (backed by the `frankensearch-rerank` crate, which pulls in `fastembed`)
//! when the `semantic` Cargo feature was enabled, and fell back to a local
//! stub otherwise. Now that the `frankensearch` dependency itself is
//! retired, both branches collapse onto the same stub unconditionally: it
//! has the same public surface the rest of the crate relies on
//! (`default_model_dir`, `load_from_dir`, `reranker_id_static`) but the
//! loader always returns a stable `RerankerError::RerankerUnavailable` and
//! the reranker cannot be instantiated. Lexical search remains fully
//! available. A real local cross-encoder reranker (e.g. via the `fastembed`
//! crate's own `TextRerank`, already a direct cass dependency under the
//! `semantic` feature) is a deliberately out-of-scope future decision, not
//! silently reintroduced here.

pub use stub::FastEmbedReranker;

mod stub {
    use std::path::{Path, PathBuf};

    use crate::search::frankensearch_types::{RerankDocument, RerankScore};
    use crate::search::reranker::{Reranker, RerankerError, RerankerResult};

    const MS_MARCO_RERANKER_ID: &str = "ms-marco-minilm-l6-v2";
    const MS_MARCO_DIR_NAME: &str = "ms-marco-MiniLM-L-6-v2";

    /// Baseline-build stub for the cross-encoder reranker.
    ///
    /// `FastEmbedReranker` cannot actually be instantiated in this build -
    /// [`load_from_dir`] always returns `RerankerError::RerankerUnavailable`.
    /// The struct and `Reranker` impl exist purely so existing
    /// `Arc<dyn Reranker>` plumbing (`reranker_registry`, `daemon::models`, etc.)
    /// keeps compiling.
    pub struct FastEmbedReranker {
        _private: (),
    }

    impl FastEmbedReranker {
        /// Stable reranker identifier (matches the upstream constant so
        /// metadata/JSON contracts remain stable across baseline and full
        /// builds).
        pub fn reranker_id_static() -> &'static str {
            MS_MARCO_RERANKER_ID
        }

        /// Default model directory relative to the cass data dir. Mirrors
        /// the layout used by the full build so the model_manager's
        /// "is this on disk?" probes return the same answer either way.
        pub fn default_model_dir(data_dir: &Path) -> PathBuf {
            data_dir.join("models").join(MS_MARCO_DIR_NAME)
        }

        /// Baseline-build stub: see the module-level note on cass#256.
        pub fn load_from_dir(_model_dir: &Path) -> RerankerResult<Self> {
            Err(RerankerError::RerankerUnavailable {
                model: MS_MARCO_RERANKER_ID.to_string(),
            })
        }
    }

    impl Reranker for FastEmbedReranker {
        fn rerank_sync(
            &self,
            _query: &str,
            _documents: &[RerankDocument],
        ) -> RerankerResult<Vec<RerankScore>> {
            Err(RerankerError::RerankerUnavailable {
                model: MS_MARCO_RERANKER_ID.to_string(),
            })
        }

        fn id(&self) -> &str {
            MS_MARCO_RERANKER_ID
        }

        fn model_name(&self) -> &str {
            MS_MARCO_DIR_NAME
        }

        fn is_available(&self) -> bool {
            false
        }
    }
}
