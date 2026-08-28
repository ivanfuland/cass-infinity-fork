//! w1b Task B4 (Q3, control-plane 2026-08-26): the sanctioned way for
//! integration tests (`tests/*.rs`, `benches/*.rs` -- separate crates from
//! `coding-agent-search` itself, so `pub(crate)` items are invisible to
//! them) to obtain a schema-free writable connection now that
//! `storage::api::Conn::open_writable` is `pub(crate)` and
//! `FrankenConnectionManager`'s `max_writers` config surface (the previous
//! de facto bridge tests used to route around that visibility) is gone
//! (secondary contract #4).
//!
//! Every name here is `pub` but the module is `#[doc(hidden)]` and loud
//! about being test-only in its own names -- production code must never
//! call these. w1b Task B9 is where a closed-world grep door enforcing
//! "only `tests/`/`benches/` reference `storage::testing`" gets built; until
//! then this doc comment plus the function names are the only fence.

#![doc(hidden)]

use std::path::Path;

use crate::storage::api::{Conn, Profile, StorageError};
use crate::storage::sqlite::FrankenStorage;

/// Open a schema-free writable [`Conn`] (no migrations run, no PRAGMA
/// tuning beyond what the backend applies on open) on `path`. Bypasses
/// `Conn::open_writable`'s `pub(crate)` visibility for integration-test
/// fixture construction only.
pub fn open_writable_for_tests(path: &Path, profile: Profile) -> Result<Conn, StorageError> {
    Conn::open_writable(path, profile)
}

/// Open a schema-free [`FrankenStorage`] (no migrations run) on `path` --
/// the schema-free equivalent of `FrankenStorage::open`, for fixtures that
/// build legacy/pre-migration schemas the migration/repair system must
/// then detect and fix (the reason this bridge exists at all: routing
/// through `FrankenStorage::open` here would run cass's real migrations
/// and collide with those fixtures' own hand-built tables).
pub fn open_franken_storage_for_tests(path: &Path, profile: Profile) -> anyhow::Result<FrankenStorage> {
    let conn = Conn::open_writable(path, profile)?;
    FrankenStorage::from_writer_handle_conn(conn, path.to_path_buf())
}

/// RAII guard matching the shape of the now-retired `WriterGuard`
/// (`FrankenConnectionManager::writer()`, pre-B4): auto-rollback on drop
/// unless [`TestWriterGuard::mark_committed`] was called, so the ~50
/// fixture call sites across the integration test suite that relied on
/// that safety net keep it verbatim -- only how the guard is *constructed*
/// changed (straight to a schema-free `FrankenStorage`, no writer-token
/// semaphore in the way).
pub struct TestWriterGuard {
    storage: FrankenStorage,
    committed: bool,
}

impl TestWriterGuard {
    /// Access the underlying storage for read/write operations.
    pub fn storage(&self) -> &FrankenStorage {
        &self.storage
    }

    /// Mark this writer as successfully committed. Call after your
    /// transaction's `commit()` succeeds, to prevent the drop guard from
    /// attempting a rollback.
    pub fn mark_committed(&mut self) {
        self.committed = true;
    }
}

impl Drop for TestWriterGuard {
    fn drop(&mut self) {
        if !self.committed {
            // Best-effort rollback — connection may already be in autocommit.
            let _ = self.storage.raw().execute("ROLLBACK;", &[]);
        }
        self.storage.close_best_effort_in_place();
    }
}

/// Open a schema-free writer for integration-test fixture construction,
/// wrapped in a [`TestWriterGuard`] for drop-time auto-rollback/close --
/// the direct replacement for the pre-B4
/// `FrankenConnectionManager::new(..).writer()` pattern used throughout
/// `tests/`.
pub fn open_test_writer(path: &Path, profile: Profile) -> anyhow::Result<TestWriterGuard> {
    let storage = open_franken_storage_for_tests(path, profile)?;
    Ok(TestWriterGuard { storage, committed: false })
}
