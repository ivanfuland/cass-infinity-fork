//! PR3 rerank contracts.
//!
//! This module tree holds the shared, product-facing rerank contracts plus the
//! per-backend adapters that implement them. [`types`] fixes the provider
//! enumeration, error taxonomy, response shape, score-validation helpers and
//! the lossless private result codec.
//!
//! The search CLI uses these modules to build and score a fixed window:
//!
//! - [`http`] (P02): shared HTTP transport, safety and failure boundaries.
//! - [`context`] (P03): verifiable anchor and neighbour-block document assembly.
//! - [`window`] (P04): fixed-order window snapshot and cursor persistence.
//! The per-provider adapters — the local SGLang Qwen backend, the local
//! Infinity BGE backend and the shared OpenRouter backend — were retired with
//! the model-API migration. Reranking now runs only through
//! [`crate::search::model_api`], which reuses [`types`], [`http`], [`context`]
//! and [`window`]; the retired `--rerank-provider` spellings are refused before
//! any request.
//!
//! Continuation pages load the verified window without another model request.

pub mod context;
pub mod http;
pub mod types;
pub mod window;
