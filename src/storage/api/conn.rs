//! Conn/Row/Tx facade (plan Task A3) — the sole consumer-facing surface of
//! storage::api. Engine type never appears here; dispatch goes through
//! [`StorageBackend`], private to this module tree.

use std::path::{Path, PathBuf};

use super::backend_franken::FrankenBackend;
use super::config::{OpenOptions, Profile};
use super::error::StorageError;
use super::value::Value;

/// Backend SPI (R0-F1, spec §3.2 trait layer's landing point). Private to `api`;
/// consumers only ever see [`Conn`]/[`Row`]/[`Tx`].
pub(crate) trait StorageBackend {
    fn execute(&self, sql: &str, params: &[Value]) -> Result<usize, StorageError>;
    fn execute_batch(&self, sql: &str) -> Result<(), StorageError>;
    fn query_map(
        &self,
        sql: &str,
        params: &[Value],
        cb: &mut dyn FnMut(&Row) -> Result<(), StorageError>,
    ) -> Result<(), StorageError>;
    /// plan delta d4: `&self`, not `&mut self` — mirrors native fsqlite
    /// `begin_transaction/commit_transaction/rollback_transaction(&self)` (the
    /// engine manages transaction state itself; Rust-level exclusivity is not how
    /// this was ever enforced). Forcing `&mut self` in Stage A would cascade into
    /// `&mut self` on every consumer-facing method that opens a transaction —
    /// a signature-propagation change, not a behavior-preserving migration.
    /// Single-writer exclusivity is Stage B's `WriterHandle` (B4), not this trait.
    fn begin(&self, mode: TxMode) -> Result<(), StorageError>;
    fn commit(&self) -> Result<(), StorageError>;
    fn rollback(&self) -> Result<(), StorageError>;
    fn last_insert_rowid(&self) -> i64;
    /// == current fsqlite `Connection::close()` (checkpoint policy left to SQLite's
    /// default close path).
    fn close(self: Box<Self>) -> Result<(), StorageError>;
    /// == current fsqlite `Connection::close_without_checkpoint()`.
    fn close_without_checkpoint(self: Box<Self>) -> Result<(), StorageError>;

    /// == current fsqlite `Connection::close_in_place(&mut self)` (Task A4a): closes
    /// without consuming the handle, for callers that only hold `&mut Conn`.
    fn close_in_place(&mut self) -> Result<(), StorageError>;
    /// == current fsqlite `Connection::close_without_checkpoint_in_place(&mut self)`.
    fn close_without_checkpoint_in_place(&mut self) -> Result<(), StorageError>;
    /// == current fsqlite `Connection::close_best_effort_in_place(&mut self)`
    /// (same no-checkpoint best-effort path as `Drop`, errors swallowed).
    fn close_best_effort_in_place(&mut self);

    /// Stage-A-only escape hatch (Task A4a): lets `run_franken_migrations` reach
    /// the native fsqlite connection to run `frankensqlite::migrate::MigrationRunner`
    /// without leaking the engine type into the `StorageBackend` trait surface.
    /// Deleted along with `backend_franken.rs` at the end of Stage B.
    fn as_franken(&self) -> Option<&super::backend_franken::FrankenBackend> {
        None
    }
}

/// Transaction begin mode. Only one variant exists in Stage A (fsqlite's
/// `begin_transaction()` takes no mode); Stage B's D2 concurrency model may
/// add Immediate/Exclusive without changing the `StorageBackend` signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxMode {
    Deferred,
}

pub struct Row<'a> {
    values: &'a [Value],
}

impl<'a> Row<'a> {
    pub(crate) fn new(values: &'a [Value]) -> Self {
        Self { values }
    }

    pub fn get_value(&self, idx: usize) -> Result<Value, StorageError> {
        self.values.get(idx).cloned().ok_or_else(|| StorageError::Other {
            code: None,
            detail: format!("column index {idx} out of range (row has {} columns)", self.values.len()),
        })
    }

    pub fn get_typed<T: super::value::FromValue>(&self, idx: usize) -> Result<T, StorageError> {
        T::from_value(self.get_value(idx)?)
    }
}

fn path_to_str(path: &Path) -> Result<&str, StorageError> {
    path.to_str().ok_or_else(|| StorageError::Other {
        code: None,
        detail: format!("non-UTF-8 path: {}", path.display()),
    })
}

fn query_row_map_impl<T>(
    backend: &dyn StorageBackend,
    sql: &str,
    params: &[Value],
    mut f: impl FnMut(&Row) -> Result<T, StorageError>,
) -> Result<T, StorageError> {
    let mut result: Option<T> = None;
    let mut count = 0usize;
    backend.query_map(sql, params, &mut |row| {
        count += 1;
        if count == 1 {
            result = Some(f(row)?);
        }
        Ok(())
    })?;
    match count {
        0 => Err(StorageError::Other {
            code: None,
            detail: super::NO_ROWS_DETAIL.to_string(),
        }),
        1 => Ok(result.expect("count == 1 implies result was set")),
        n => Err(StorageError::Other {
            code: None,
            detail: format!("query returned {n} rows, expected exactly 1"),
        }),
    }
}

fn query_opt_map_impl<T>(
    backend: &dyn StorageBackend,
    sql: &str,
    params: &[Value],
    mut f: impl FnMut(&Row) -> Result<T, StorageError>,
) -> Result<Option<T>, StorageError> {
    let mut result: Option<T> = None;
    let mut count = 0usize;
    backend.query_map(sql, params, &mut |row| {
        count += 1;
        if count == 1 {
            result = Some(f(row)?);
        }
        Ok(())
    })?;
    if count > 1 {
        return Err(StorageError::Other {
            code: None,
            detail: format!("query returned {count} rows, expected at most 1"),
        });
    }
    Ok(result)
}

fn query_all_map_impl<T>(
    backend: &dyn StorageBackend,
    sql: &str,
    params: &[Value],
    mut f: impl FnMut(&Row) -> Result<T, StorageError>,
) -> Result<Vec<T>, StorageError> {
    let mut out = Vec::new();
    backend.query_map(sql, params, &mut |row| {
        out.push(f(row)?);
        Ok(())
    })?;
    Ok(out)
}

pub struct Conn {
    inner: Box<dyn StorageBackend>,
    path: Option<PathBuf>,
}

/// Task A4a: some consumers embed `Conn` in a `#[derive(Debug)]` struct or
/// `.expect_err()` it in a test (which formats the `Ok` value on panic).
/// `dyn StorageBackend` has no principled `Debug` (the whole point of the trait
/// is hiding the engine), so this only ever prints the path.
impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn").field("path", &self.path).finish_non_exhaustive()
    }
}

impl Conn {
    pub fn open_read(path: &Path) -> Result<Conn, StorageError> {
        let backend = FrankenBackend::open_read_only(path_to_str(path)?)?;
        Ok(Conn { inner: Box::new(backend), path: Some(path.to_path_buf()) })
    }

    pub fn open_read_with(path: &Path, opts: OpenOptions) -> Result<Conn, StorageError> {
        let conn = Self::open_read(path)?;
        conn.execute_batch(&format!(
            "PRAGMA busy_timeout = {};",
            opts.busy_timeout.as_millis()
        ))?;
        Ok(conn)
    }

    /// Writable connection construction is deliberately not `pub` (R2-F3): the only
    /// public path to a writable `Conn` is `open_memory()` (test fixture) plus,
    /// once built, the `WriterHandle`/schema call sites within this crate.
    pub(crate) fn open_writable(path: &Path, _profile: Profile) -> Result<Conn, StorageError> {
        let backend = FrankenBackend::open(path_to_str(path)?)?;
        Ok(Conn { inner: Box::new(backend), path: Some(path.to_path_buf()) })
    }

    pub fn open_memory() -> Result<Conn, StorageError> {
        let backend = FrankenBackend::open_memory()?;
        Ok(Conn { inner: Box::new(backend), path: None })
    }

    pub fn execute(&self, sql: &str, params: &[Value]) -> Result<usize, StorageError> {
        self.inner.execute(sql, params)
    }

    pub fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        self.inner.execute_batch(sql)
    }

    pub fn query_row_map<T>(
        &self,
        sql: &str,
        params: &[Value],
        f: impl FnMut(&Row) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        query_row_map_impl(self.inner.as_ref(), sql, params, f)
    }

    pub fn query_opt_map<T>(
        &self,
        sql: &str,
        params: &[Value],
        f: impl FnMut(&Row) -> Result<T, StorageError>,
    ) -> Result<Option<T>, StorageError> {
        query_opt_map_impl(self.inner.as_ref(), sql, params, f)
    }

    pub fn query_all_map<T>(
        &self,
        sql: &str,
        params: &[Value],
        f: impl FnMut(&Row) -> Result<T, StorageError>,
    ) -> Result<Vec<T>, StorageError> {
        query_all_map_impl(self.inner.as_ref(), sql, params, f)
    }

    /// plan delta d4: `&self` (see [`StorageBackend::begin`] doc comment).
    pub fn transaction(&self) -> Result<Tx<'_>, StorageError> {
        self.inner.begin(TxMode::Deferred)?;
        Ok(Tx { backend: self.inner.as_ref(), finalized: false })
    }

    pub fn last_insert_rowid(&self) -> i64 {
        self.inner.last_insert_rowid()
    }

    /// Stage-A-only (Task A4a): see [`StorageBackend::as_franken`].
    pub(crate) fn as_franken(&self) -> Option<&super::backend_franken::FrankenBackend> {
        self.inner.as_franken()
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn close(self) -> Result<(), StorageError> {
        self.inner.close()
    }

    pub fn close_without_checkpoint(self) -> Result<(), StorageError> {
        self.inner.close_without_checkpoint()
    }

    /// Task A4a: see [`StorageBackend::close_in_place`].
    pub(crate) fn close_in_place(&mut self) -> Result<(), StorageError> {
        self.inner.close_in_place()
    }

    /// Task A4a: see [`StorageBackend::close_without_checkpoint_in_place`].
    pub(crate) fn close_without_checkpoint_in_place(&mut self) -> Result<(), StorageError> {
        self.inner.close_without_checkpoint_in_place()
    }

    /// Task A4a: see [`StorageBackend::close_best_effort_in_place`].
    pub(crate) fn close_best_effort_in_place(&mut self) {
        self.inner.close_best_effort_in_place()
    }

    /// == current close_storage_after_index flow: `PRAGMA wal_checkpoint(TRUNCATE)`
    /// on a still-open connection, then the plain close (indexer/mod.rs:1057).
    pub fn close_with_checkpoint(self) -> Result<(), StorageError> {
        self.inner.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        self.inner.close()
    }
}

pub struct Tx<'c> {
    backend: &'c dyn StorageBackend,
    finalized: bool,
}

impl Tx<'_> {
    pub fn execute(&self, sql: &str, params: &[Value]) -> Result<usize, StorageError> {
        self.backend.execute(sql, params)
    }

    pub fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        self.backend.execute_batch(sql)
    }

    pub fn query_row_map<T>(
        &self,
        sql: &str,
        params: &[Value],
        f: impl FnMut(&Row) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        query_row_map_impl(self.backend, sql, params, f)
    }

    pub fn query_opt_map<T>(
        &self,
        sql: &str,
        params: &[Value],
        f: impl FnMut(&Row) -> Result<T, StorageError>,
    ) -> Result<Option<T>, StorageError> {
        query_opt_map_impl(self.backend, sql, params, f)
    }

    pub fn query_all_map<T>(
        &self,
        sql: &str,
        params: &[Value],
        f: impl FnMut(&Row) -> Result<T, StorageError>,
    ) -> Result<Vec<T>, StorageError> {
        query_all_map_impl(self.backend, sql, params, f)
    }

    pub fn last_insert_rowid(&self) -> i64 {
        self.backend.last_insert_rowid()
    }

    // `commit`/`rollback` still take `self` by value (not `&self`) despite
    // `StorageBackend::commit/rollback` now being `&self` (plan d4) — consuming
    // `Tx` is what makes "used after commit" a compile error; d4 only relaxed
    // the backend-open exclusivity, not this per-`Tx` one-shot contract.
    pub fn commit(mut self) -> Result<(), StorageError> {
        self.backend.commit()?;
        self.finalized = true;
        Ok(())
    }

    /// == current fsqlite `compat::Transaction::rollback` (Task A4a): explicit
    /// rollback, distinct from the implicit best-effort rollback in `Drop`.
    pub fn rollback(mut self) -> Result<(), StorageError> {
        self.backend.rollback()?;
        self.finalized = true;
        Ok(())
    }
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if !self.finalized {
            // Best-effort rollback; errors are unobservable from Drop by design
            // (matches fsqlite's own compat::Transaction Drop behavior).
            let _ = self.backend.rollback();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::params;
    use super::*;

    #[test]
    fn api_conn_memory_smoke() {
        let mut c = Conn::open_memory().unwrap();
        c.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT);").unwrap();
        c.execute("INSERT INTO t(s) VALUES (?1)", &params!["hi"]).unwrap();
        let s: String = c
            .query_row_map("SELECT s FROM t WHERE id=?1", &params![1_i64], |r| r.get_typed(0))
            .unwrap();
        assert_eq!(s, "hi");
        assert!(c
            .query_opt_map("SELECT s FROM t WHERE id=99", &[], |r| r.get_typed::<String>(0))
            .unwrap()
            .is_none());
        let tx = c.transaction().unwrap();
        tx.execute("INSERT INTO t(s) VALUES ('tx')", &[]).unwrap();
        tx.commit().unwrap();

        let all: Vec<String> =
            c.query_all_map("SELECT s FROM t ORDER BY id", &[], |r| r.get_typed(0)).unwrap();
        assert_eq!(all, vec!["hi".to_string(), "tx".to_string()]);
    }

    #[test]
    fn api_tx_drop_without_commit_rolls_back() {
        let mut c = Conn::open_memory().unwrap();
        c.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT);").unwrap();
        {
            let tx = c.transaction().unwrap();
            tx.execute("INSERT INTO t(s) VALUES ('rolled_back')", &[]).unwrap();
            // dropped without commit
        }
        let n: i64 =
            c.query_row_map("SELECT count(*) FROM t", &[], |r| r.get_typed(0)).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn api_conn_open_read_and_path() {
        let dir = std::env::temp_dir().join(format!(
            "cc-cass-w1a-conn-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("t.db");
        {
            let conn = Conn::open_writable(&db_path, Profile::Production).unwrap();
            conn.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY);").unwrap();
            assert_eq!(conn.path(), Some(db_path.as_path()));
            conn.close().unwrap();
        }
        let reader = Conn::open_read(&db_path).unwrap();
        let n: i64 =
            reader.query_row_map("SELECT count(*) FROM t", &[], |r| r.get_typed(0)).unwrap();
        assert_eq!(n, 0);
        assert!(reader.execute("INSERT INTO t(id) VALUES (1)", &[]).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
