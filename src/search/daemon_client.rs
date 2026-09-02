//! Daemon client integration re-exports.
//!
//! W3-5: these daemon abstractions used to live in the `frankensearch` crate
//! (now retired as a Cargo dependency); `crate::search::frankensearch_daemon`
//! is a verbatim restore of the pieces still consumed here (see that
//! module's doc comment for source provenance).

pub use crate::search::frankensearch_daemon::{
    DaemonClient, DaemonError, DaemonFallbackEmbedder, DaemonFallbackReranker, DaemonRetryConfig,
    NoopDaemonClient,
};
