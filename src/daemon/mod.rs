//! Unix socket control service and legacy wire-format readers.
//!
//! Direct embedding and rerank requests return a migration error. Model
//! inference is configured through HTTP profiles; this server loads no models.

pub mod client;
pub mod core;
pub mod protocol;
pub mod resource;

use std::path::{Path, PathBuf};

// Used by daemon client/server paths in some target combinations, but not all
// library-only builds that we verify during placeholder cleanup.
#[allow(dead_code)]
pub(crate) fn daemon_run_lock_path(socket_path: &Path) -> PathBuf {
    socket_path.with_extension("spawnlock")
}

pub(crate) fn daemon_spawn_guard_lock_path(socket_path: &Path) -> PathBuf {
    socket_path.with_extension("spawn-guard.lock")
}

// Re-export key types for convenience
pub use client::{DaemonClientConfig, UdsDaemonClient};
pub use core::{DaemonConfig, ModelDaemon};
pub use protocol::{EmbeddingJobConfig, PROTOCOL_VERSION, Request, Response, default_socket_path};
pub use resource::ResourceMonitor;
