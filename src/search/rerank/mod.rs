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
//! - [`qwen`] (P05): local SGLang Qwen adapter.
//! - [`bge`] (P06): local Infinity BGE adapter.
//! - [`openrouter`] (P07): shared OpenRouter adapter for its three models.
//!
//! Continuation pages load the verified window without another model request.

pub mod bge;
pub mod context;
pub mod http;
pub mod openrouter;
pub mod qwen;
pub mod types;
pub mod window;
