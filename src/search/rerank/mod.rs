//! PR3 rerank contracts.
//!
//! This module tree holds the shared, product-facing rerank contracts plus the
//! per-backend adapters that implement them. Only [`types`] carries executable
//! code today: it fixes the provider enumeration, error taxonomy, response
//! shape, score-validation helpers and the lossless private result codec that
//! the later tickets build on.
//!
//! The remaining modules are declared so their file locations and names are
//! frozen, but they are intentionally empty. Each is filled by its own ticket:
//!
//! - [`http`] (P02): shared HTTP transport, safety and failure boundaries.
//! - [`context`] (P03): verifiable anchor and neighbour-block document assembly.
//! - [`window`] (P04): fixed-order window snapshot and cursor persistence.
//! - [`qwen`] (P05): local SGLang Qwen adapter.
//! - [`bge`] (P06): local Infinity BGE adapter.
//! - [`openrouter`] (P07): shared OpenRouter adapter for its three models.
//!
//! Nothing here is wired into the search path yet, and none of the placeholder
//! modules return a successful result: an unimplemented backend is not a
//! backend that works.

pub mod bge;
pub mod context;
pub mod http;
pub mod openrouter;
pub mod qwen;
pub mod types;
pub mod window;
