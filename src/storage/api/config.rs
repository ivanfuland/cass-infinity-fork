//! Connection profiles and open options for storage::api.
//!
//! Stage A only defines the shapes; PRAGMA application + readback self-check
//! (spec R0-B07 / R4-B1) lands in Stage B Task B2 (`backend_sqlite.rs`).
//! The franken backend (Stage A) does not yet branch on `Profile`.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Production,
    BulkRebuild,
    ReadOnly,
    Memory,
}

/// Options for [`super::Conn::open_read_with`].
#[derive(Debug, Clone, Copy)]
pub struct OpenOptions {
    pub busy_timeout: Duration,
}
