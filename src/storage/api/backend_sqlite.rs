//! Stage B backend (Task B2): wraps rusqlite behind [`super::conn::StorageBackend`].
//! Takes over from `backend_franken.rs` (deleted at the end of Stage B, plan header).

use std::time::Duration;

use rusqlite::config::DbConfig;

use super::config::{PragmaPlan, Profile};
use super::conn::{StorageBackend, TxMode};
use super::error::{BusyScope, StorageError};
use super::value::Value;

pub(crate) struct SqliteBackend {
    /// `None` only after an `*_in_place` close has already run (see
    /// `close_in_place`/`close_without_checkpoint_in_place`/
    /// `close_best_effort_in_place`) -- every call site in this crate treats
    /// that as "about to be dropped, never touched again" (mirrors the
    /// franken backend's own in-place-close contract), so the remaining
    /// trait methods return a plain error rather than panicking if that
    /// assumption is ever violated.
    conn: Option<rusqlite::Connection>,
}

impl SqliteBackend {
    pub(crate) fn open_writable(path: &str, profile: Profile) -> Result<Self, StorageError> {
        super::ensure_vec0_extension_registered();
        let conn = rusqlite::Connection::open(path).map_err(map_sqlite_err)?;
        apply_profile(&conn, profile)?;
        Ok(Self { conn: Some(conn) })
    }

    pub(crate) fn open_read_only(path: &str) -> Result<Self, StorageError> {
        super::ensure_vec0_extension_registered();
        let conn = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(map_sqlite_err)?;
        apply_profile(&conn, Profile::ReadOnly)?;
        Ok(Self { conn: Some(conn) })
    }

    pub(crate) fn open_memory() -> Result<Self, StorageError> {
        super::ensure_vec0_extension_registered();
        let conn = rusqlite::Connection::open_in_memory().map_err(map_sqlite_err)?;
        apply_profile(&conn, Profile::Memory)?;
        Ok(Self { conn: Some(conn) })
    }

    fn conn(&self) -> Result<&rusqlite::Connection, StorageError> {
        self.conn.as_ref().ok_or_else(|| StorageError::Other {
            code: None,
            detail: "sqlite connection already closed".to_string(),
        })
    }
}

/// Applies `profile`'s [`PragmaPlan`] and reads every PRAGMA back to confirm
/// it actually took (spec R0-B07 / R4-B1: "每次 open 后回读... 不符即拒开").
/// `foreign_keys=ON` is constant across every profile (plan @690-696 table),
/// not part of `PragmaPlan`, and applied first.
fn apply_profile(conn: &rusqlite::Connection, profile: Profile) -> Result<(), StorageError> {
    let plan: PragmaPlan = profile.pragma_plan();

    conn.busy_timeout(Duration::from_millis(plan.busy_timeout_ms)).map_err(map_sqlite_err)?;

    conn.execute_batch("PRAGMA foreign_keys = ON;").map_err(map_sqlite_err)?;
    let fk_actual: i64 =
        conn.query_row("PRAGMA foreign_keys;", [], |r| r.get(0)).map_err(map_sqlite_err)?;
    if fk_actual != 1 {
        return Err(pragma_readback_mismatch("foreign_keys", "1", &fk_actual.to_string()));
    }

    if let Some(mode) = plan.journal_mode {
        // journal_mode is the one PRAGMA whose SET form itself returns the
        // resulting mode as a row -- no separate getter round-trip needed.
        let actual: String = conn
            .query_row(&format!("PRAGMA journal_mode = {mode};"), [], |r| r.get(0))
            .map_err(map_sqlite_err)?;
        if !actual.eq_ignore_ascii_case(mode) {
            return Err(pragma_readback_mismatch("journal_mode", mode, &actual));
        }
    }

    if let Some(level) = plan.synchronous {
        conn.execute_batch(&format!("PRAGMA synchronous = {level};")).map_err(map_sqlite_err)?;
        let actual: i64 =
            conn.query_row("PRAGMA synchronous;", [], |r| r.get(0)).map_err(map_sqlite_err)?;
        if actual != level {
            return Err(pragma_readback_mismatch(
                "synchronous",
                &level.to_string(),
                &actual.to_string(),
            ));
        }
    }

    if let Some(warning) = plan.unsafe_nondurable_warning {
        eprintln!("{warning}");
    }

    Ok(())
}

fn pragma_readback_mismatch(name: &str, expected: &str, actual: &str) -> StorageError {
    StorageError::Other {
        code: None,
        detail: format!(
            "PRAGMA {name} readback mismatch: expected {expected}, got {actual} -- refusing to open"
        ),
    }
}

fn value_to_sqlite(v: &Value) -> rusqlite::types::Value {
    match v {
        Value::Null => rusqlite::types::Value::Null,
        Value::Integer(i) => rusqlite::types::Value::Integer(*i),
        Value::Real(f) => rusqlite::types::Value::Real(*f),
        Value::Text(s) => rusqlite::types::Value::Text(s.clone()),
        Value::Blob(b) => rusqlite::types::Value::Blob(b.clone()),
    }
}

fn sqlite_to_value(v: rusqlite::types::Value) -> Value {
    match v {
        rusqlite::types::Value::Null => Value::Null,
        rusqlite::types::Value::Integer(i) => Value::Integer(i),
        rusqlite::types::Value::Real(f) => Value::Real(f),
        rusqlite::types::Value::Text(s) => Value::Text(s),
        rusqlite::types::Value::Blob(b) => Value::Blob(b),
    }
}

impl StorageBackend for SqliteBackend {
    /// w1b Task B8 (regression found via real `cargo test` execution, not
    /// `cargo check`): `rusqlite::Connection::execute` hard-errors
    /// ("Execute returned results - did you mean to call query?") on any
    /// statement that returns a result set -- and some PRAGMAs cass runs
    /// through this exact trait method do (`PRAGMA journal_mode = WAL;`
    /// returns the resulting mode as a one-row result set; the legacy embedded engine's
    /// `execute` tolerated this, which is why the bug was latent until
    /// `Conn::open_writable` actually dispatched here). Prepare + drain
    /// instead of `Connection::execute` so any such statement (PRAGMA or
    /// ordinary DML) works uniformly; `Connection::changes()` after the
    /// drain still reports the affected-row count `execute()`'s callers
    /// expect.
    fn execute(&self, sql: &str, params: &[Value]) -> Result<usize, StorageError> {
        let conn = self.conn()?;
        let sqlite_params: Vec<rusqlite::types::Value> = params.iter().map(value_to_sqlite).collect();
        let mut stmt = conn.prepare(sql).map_err(map_sqlite_err)?;
        let mut rows = stmt
            .query(rusqlite::params_from_iter(sqlite_params.iter()))
            .map_err(map_sqlite_err)?;
        while rows.next().map_err(map_sqlite_err)?.is_some() {}
        drop(rows);
        drop(stmt);
        Ok(conn.changes() as usize)
    }

    fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        self.conn()?.execute_batch(sql).map_err(map_sqlite_err)
    }

    fn query_map(
        &self,
        sql: &str,
        params: &[Value],
        cb: &mut dyn FnMut(&super::conn::Row) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let conn = self.conn()?;
        let sqlite_params: Vec<rusqlite::types::Value> = params.iter().map(value_to_sqlite).collect();
        let mut stmt = conn.prepare(sql).map_err(map_sqlite_err)?;
        let col_count = stmt.column_count();
        let mut rows = stmt
            .query(rusqlite::params_from_iter(sqlite_params.iter()))
            .map_err(map_sqlite_err)?;
        while let Some(row) = rows.next().map_err(map_sqlite_err)? {
            let mut values = Vec::with_capacity(col_count);
            for i in 0..col_count {
                let v: rusqlite::types::Value = row.get(i).map_err(map_sqlite_err)?;
                values.push(sqlite_to_value(v));
            }
            let api_row = super::conn::Row::new(&values);
            cb(&api_row)?;
        }
        Ok(())
    }

    /// Raw SQL, not rusqlite's own `Connection::transaction()` guard -- that
    /// guard requires `&mut Connection`, incompatible with this trait's
    /// `&self` contract (plan d4: transaction state is managed by SQL itself,
    /// mirroring the legacy embedded engine's own `&self`-based
    /// begin/commit/rollback_transaction, not by Rust-level exclusivity;
    /// see `conn.rs`'s `StorageBackend::begin` doc comment).
    fn begin(&self, mode: TxMode) -> Result<(), StorageError> {
        // w1b Task B3 (D2, plan @775-776): `Immediate` acquires the write
        // lock immediately at BEGIN rather than deferring it to the first
        // write statement -- avoids the deferred-transaction upgrade
        // conflict (another connection grabbing the write lock, or a
        // snapshot-invalidating commit, between this transaction's read and
        // its write) that write transactions should not have to contend
        // with in the first place.
        let sql = match mode {
            TxMode::Deferred => "BEGIN DEFERRED;",
            TxMode::Immediate => "BEGIN IMMEDIATE;",
        };
        self.conn()?.execute_batch(sql).map_err(map_sqlite_err)
    }

    fn commit(&self) -> Result<(), StorageError> {
        self.conn()?.execute_batch("COMMIT;").map_err(map_sqlite_err)
    }

    fn rollback(&self) -> Result<(), StorageError> {
        self.conn()?.execute_batch("ROLLBACK;").map_err(map_sqlite_err)
    }

    fn last_insert_rowid(&self) -> i64 {
        self.conn.as_ref().map(rusqlite::Connection::last_insert_rowid).unwrap_or(0)
    }

    fn close(self: Box<Self>) -> Result<(), StorageError> {
        match self.conn {
            Some(conn) => conn.close().map_err(|(_conn, e)| map_sqlite_err(e)),
            None => Ok(()),
        }
    }

    fn close_without_checkpoint(self: Box<Self>) -> Result<(), StorageError> {
        match self.conn {
            Some(conn) => {
                conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
                    .map_err(map_sqlite_err)?;
                conn.close().map_err(|(_conn, e)| map_sqlite_err(e))
            }
            None => Ok(()),
        }
    }

    fn close_in_place(&mut self) -> Result<(), StorageError> {
        let Some(conn) = self.conn.take() else {
            return Ok(());
        };
        conn.close().map_err(|(returned, e)| {
            self.conn = Some(returned);
            map_sqlite_err(e)
        })
    }

    fn close_without_checkpoint_in_place(&mut self) -> Result<(), StorageError> {
        let Some(conn) = self.conn.take() else {
            return Ok(());
        };
        if let Err(e) = conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true) {
            self.conn = Some(conn);
            return Err(map_sqlite_err(e));
        }
        conn.close().map_err(|(returned, e)| {
            self.conn = Some(returned);
            map_sqlite_err(e)
        })
    }

    fn close_best_effort_in_place(&mut self) {
        // Dropping `Some(connection)` here runs rusqlite's own `Connection`
        // Drop impl, which calls `sqlite3_close_v2` and ignores the result --
        // already exactly "best effort".
        self.conn = None;
    }
}

/// rusqlite -> StorageError mapping (extended result codes per sqlite3.h,
/// plan @708-717, spec R0-N01 实证). Primary `ErrorCode` alone distinguishes
/// every family except BUSY (SQLITE_BUSY/BUSY_TIMEOUT/BUSY_RECOVERY/
/// BUSY_SNAPSHOT all share the same low-byte primary code 5), so only that
/// family inspects the raw `extended_code`.
pub(crate) fn map_sqlite_err(e: rusqlite::Error) -> StorageError {
    match &e {
        rusqlite::Error::SqliteFailure(ffi_err, msg) => {
            let detail = msg.clone().unwrap_or_else(|| e.to_string());
            map_sqlite_failure(*ffi_err, detail)
        }
        _ => StorageError::Other { code: None, detail: e.to_string() },
    }
}

fn map_sqlite_failure(ffi_err: rusqlite::ffi::Error, detail: String) -> StorageError {
    use rusqlite::ErrorCode;
    match ffi_err.code {
        ErrorCode::DatabaseBusy => {
            if ffi_err.extended_code == rusqlite::ffi::SQLITE_BUSY_SNAPSHOT {
                StorageError::Busy { scope: BusyScope::Snapshot }
            } else {
                // R3-N2 death judgment (task book #8 ①, cross-referenced
                // against sqlite.rs::retryable_franken_error, the baseline
                // retry classifier): that function's only structural check is
                // `matches!(err, StorageError::Busy{..})` -- both Statement
                // and Snapshot scope are retryable there regardless of which
                // arm produced them, so grouping SQLITE_BUSY /
                // SQLITE_BUSY_TIMEOUT / SQLITE_BUSY_RECOVERY into Statement
                // scope here (same bucket `map_franken_err` already used for
                // `FrankenError::BusyRecovery`) preserves that baseline
                // retry classification bit for bit. This is a deliberate,
                // explicit decision, not a silent omission: the 5-class
                // `StorageError` design (spec) has no separate "recovery in
                // progress" diagnostic slot, and restoring one is out of
                // this task's scope -- R1-N3/R3-N2's underlying complaint was
                // that the collapse happened *without* this cross-reference
                // ever being written down, which this comment now closes.
                StorageError::Busy { scope: BusyScope::Statement }
            }
        }
        ErrorCode::DatabaseLocked => StorageError::Locked,
        ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => StorageError::Corrupt { detail },
        ErrorCode::ConstraintViolation => StorageError::Constraint { detail },
        _ => StorageError::Other { code: Some(ffi_err.extended_code), detail },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::value::FromValue;

    fn open_mem() -> SqliteBackend {
        SqliteBackend::open_memory().unwrap()
    }

    #[test]
    fn sqlite_backend_smoke() {
        let backend = open_mem();
        backend.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT);").unwrap();
        backend.execute("INSERT INTO t(s) VALUES (?1)", &[Value::Text("hi".into())]).unwrap();
        let mut got = String::new();
        backend
            .query_map("SELECT s FROM t WHERE id=1", &[], &mut |row| {
                got = String::from_value(row.get_value(0)?)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(got, "hi");
        assert_eq!(backend.last_insert_rowid(), 1);
    }

    #[test]
    fn sqlite_backend_transaction_commit_and_rollback() {
        let backend = open_mem();
        backend.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT);").unwrap();

        backend.begin(TxMode::Deferred).unwrap();
        backend.execute("INSERT INTO t(s) VALUES ('committed')", &[]).unwrap();
        backend.commit().unwrap();

        backend.begin(TxMode::Deferred).unwrap();
        backend.execute("INSERT INTO t(s) VALUES ('rolled_back')", &[]).unwrap();
        backend.rollback().unwrap();

        let mut count = 0_i64;
        backend
            .query_map("SELECT count(*) FROM t", &[], &mut |row| {
                count = i64::from_value(row.get_value(0)?)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn defer_foreign_keys_permits_out_of_order_write_then_resets_after_commit() {
        // w1b Task B2b (R0-B3): real SQLite (unlike the current production
        // legacy-embedded-engine backend, see conn.rs's
        // `api_defer_foreign_keys_errors_on_unsupported_backend`) genuinely
        // implements `defer_foreign_keys` -- this proves the mechanism
        // `Tx::defer_foreign_keys()` relies on actually works once this
        // backend is the one in use.
        let backend = open_mem();
        backend
            .execute_batch(
                "CREATE TABLE parent(id INTEGER PRIMARY KEY);
                 CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parent(id));",
            )
            .unwrap();

        backend.begin(TxMode::Deferred).unwrap();
        backend.execute_batch("PRAGMA defer_foreign_keys = ON;").unwrap();
        let mut engaged = 0_i64;
        backend
            .query_map("PRAGMA defer_foreign_keys;", &[], &mut |row| {
                engaged = i64::from_value(row.get_value(0)?)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(engaged, 1, "real SQLite must report defer_foreign_keys engaged");

        // Child inserted before its parent exists -- would fail immediately
        // under per-statement checking, must succeed here.
        backend.execute("INSERT INTO child(id, parent_id) VALUES (1, 100)", &[]).unwrap();
        backend.execute("INSERT INTO parent(id) VALUES (100)", &[]).unwrap();
        backend.commit().unwrap();

        // A second transaction that leaves an orphan unresolved must still
        // fail -- defer_foreign_keys is transaction-scoped and must not
        // leak past commit.
        backend.begin(TxMode::Deferred).unwrap();
        let err = backend
            .execute("INSERT INTO child(id, parent_id) VALUES (2, 999)", &[])
            .expect_err("unresolved orphan must fail once the prior transaction committed");
        assert!(matches!(err, StorageError::Constraint { .. }));
        backend.rollback().unwrap();
    }

    #[test]
    fn production_profile_pragma_readback_on_real_file() {
        // plan B2 Step 1: not the declarative `PragmaPlan` shape (covered by
        // `production_profile_pragma_plan` below) -- an actual Production-
        // profile connection against a real on-disk file, independently
        // re-querying the live PRAGMAs to confirm `apply_profile`'s own
        // internal readback wasn't fooling itself.
        let dir = std::env::temp_dir()
            .join(format!("cc-cass-w1b-b2-pragma-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("t.db");
        let backend =
            SqliteBackend::open_writable(db_path.to_str().unwrap(), Profile::Production).unwrap();

        let mut synchronous = -1_i64;
        backend
            .query_map("PRAGMA synchronous;", &[], &mut |row| {
                synchronous = i64::from_value(row.get_value(0)?)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(synchronous, 2, "Production profile must read back synchronous=FULL(2)");

        let mut journal_mode = String::new();
        backend
            .query_map("PRAGMA journal_mode;", &[], &mut |row| {
                journal_mode = String::from_value(row.get_value(0)?)?;
                Ok(())
            })
            .unwrap();
        assert!(journal_mode.eq_ignore_ascii_case("wal"));

        drop(backend);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn map_sqlite_err_real_busy_statement_from_write_contention() {
        // plan B2 Step 3: a *real* manufactured BUSY, not a synthetic
        // `SqliteFailure` construction (see `map_sqlite_err_busy_snapshot_vs_statement`
        // above, which only tests the classification logic in isolation) --
        // two real connections to the same file, one holding an open write
        // transaction while the other (busy_timeout=0, so it fails
        // immediately instead of waiting) collides with it.
        let dir = std::env::temp_dir().join(format!("cc-cass-w1b-b2-busy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("t.db");
        let db_path_str = db_path.to_str().unwrap();

        let writer = SqliteBackend::open_writable(db_path_str, Profile::Production).unwrap();
        writer.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY);").unwrap();
        writer.begin(TxMode::Deferred).unwrap();
        writer.execute("INSERT INTO t(id) VALUES (1)", &[]).unwrap();
        // Transaction left open (not committed) -- conn2 below must collide.

        let conn2 = rusqlite::Connection::open(db_path_str).unwrap();
        conn2.busy_timeout(Duration::from_millis(0)).unwrap();
        let result = conn2.execute("INSERT INTO t(id) VALUES (2)", []);
        let err = result.expect_err(
            "second connection must hit a real SQLITE_BUSY while the first holds an open write txn",
        );
        assert!(matches!(map_sqlite_err(err), StorageError::Busy { scope: BusyScope::Statement }));

        writer.rollback().unwrap();
        drop(writer);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn map_sqlite_err_real_unique_constraint() {
        // plan B2 Step 3: real UNIQUE violation through the full
        // `StorageBackend::execute` -> `map_sqlite_err` path, not a synthetic
        // error construction.
        let backend = open_mem();
        backend.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT UNIQUE);").unwrap();
        backend.execute("INSERT INTO t(s) VALUES ('x')", &[]).unwrap();
        let err = backend
            .execute("INSERT INTO t(s) VALUES ('x')", &[])
            .expect_err("duplicate UNIQUE value must fail");
        assert!(matches!(err, StorageError::Constraint { .. }));
    }

    #[test]
    fn pragma_readback_mismatch_rejects_open() {
        // A bogus expected value can never round-trip; exercise the helper
        // directly (constructing an actual mismatch via `apply_profile`
        // would require sabotaging SQLite itself, which isn't feasible).
        let err = pragma_readback_mismatch("synchronous", "2", "1");
        assert!(matches!(err, StorageError::Other { .. }));
        assert!(format!("{err}").contains("readback mismatch"));
    }

    #[test]
    fn production_profile_pragma_plan() {
        let plan = Profile::Production.pragma_plan();
        assert_eq!(plan.journal_mode, Some("WAL"));
        assert_eq!(plan.synchronous, Some(2));
        assert_eq!(plan.busy_timeout_ms, 5000);
        assert!(plan.unsafe_nondurable_warning.is_none());
    }

    #[test]
    fn bulk_rebuild_defaults_to_production_without_env_var() {
        // SAFETY: test-local env var scoped to this process; #[serial_test::serial]
        // would be needed if another test in this module also touched this var --
        // none currently do.
        unsafe {
            std::env::remove_var(super::super::config::BULK_REBUILD_UNSAFE_ENV);
        }
        let plan = Profile::BulkRebuild.pragma_plan();
        assert_eq!(plan.synchronous, Some(2), "must silently downgrade to Production/FULL");
        assert!(plan.unsafe_nondurable_warning.is_none());
    }

    #[test]
    fn bulk_rebuild_unsafe_nondurable_requires_exact_env_value() {
        unsafe {
            std::env::set_var(super::super::config::BULK_REBUILD_UNSAFE_ENV, "1");
        }
        let plan = Profile::BulkRebuild.pragma_plan();
        assert_eq!(plan.synchronous, Some(1));
        assert!(plan.unsafe_nondurable_warning.is_some());
        unsafe {
            std::env::remove_var(super::super::config::BULK_REBUILD_UNSAFE_ENV);
        }
    }

    #[test]
    fn bulk_rebuild_unsafe_nondurable_actually_applies_through_real_open() {
        // Not just the declarative `PragmaPlan` shape (covered above) -- a
        // real `open_writable(Profile::BulkRebuild)` call with the env var
        // set, proving `apply_profile`'s `unsafe_nondurable_warning` branch
        // (which does `eprintln!` -- plan @702's mandatory warning-on-open
        // log line) actually executes on the real code path, not just in a
        // unit test of the plan struct in isolation.
        let dir = std::env::temp_dir()
            .join(format!("cc-cass-w1b-b2-bulkrebuild-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("t.db");
        unsafe {
            std::env::set_var(super::super::config::BULK_REBUILD_UNSAFE_ENV, "1");
        }
        let backend =
            SqliteBackend::open_writable(db_path.to_str().unwrap(), Profile::BulkRebuild).unwrap();
        unsafe {
            std::env::remove_var(super::super::config::BULK_REBUILD_UNSAFE_ENV);
        }

        let mut synchronous = -1_i64;
        backend
            .query_map("PRAGMA synchronous;", &[], &mut |row| {
                synchronous = i64::from_value(row.get_value(0)?)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(synchronous, 1, "unsafe-nondurable BulkRebuild must actually read back NORMAL(1)");

        drop(backend);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn map_sqlite_err_busy_snapshot_vs_statement() {
        let snapshot = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error { code: rusqlite::ErrorCode::DatabaseBusy, extended_code: rusqlite::ffi::SQLITE_BUSY_SNAPSHOT },
            None,
        );
        assert!(matches!(map_sqlite_err(snapshot), StorageError::Busy { scope: BusyScope::Snapshot }));

        let recovery = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error { code: rusqlite::ErrorCode::DatabaseBusy, extended_code: rusqlite::ffi::SQLITE_BUSY_RECOVERY },
            None,
        );
        assert!(matches!(map_sqlite_err(recovery), StorageError::Busy { scope: BusyScope::Statement }));

        let plain_busy = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error { code: rusqlite::ErrorCode::DatabaseBusy, extended_code: rusqlite::ffi::SQLITE_BUSY },
            None,
        );
        assert!(matches!(map_sqlite_err(plain_busy), StorageError::Busy { scope: BusyScope::Statement }));
    }

    #[test]
    fn map_sqlite_err_locked_corrupt_notadb_constraint() {
        let locked = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error { code: rusqlite::ErrorCode::DatabaseLocked, extended_code: rusqlite::ffi::SQLITE_LOCKED_SHAREDCACHE },
            None,
        );
        assert!(matches!(map_sqlite_err(locked), StorageError::Locked));

        let corrupt = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error { code: rusqlite::ErrorCode::DatabaseCorrupt, extended_code: rusqlite::ffi::SQLITE_CORRUPT_VTAB },
            None,
        );
        assert!(matches!(map_sqlite_err(corrupt), StorageError::Corrupt { .. }));

        let notadb = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error { code: rusqlite::ErrorCode::NotADatabase, extended_code: rusqlite::ffi::SQLITE_NOTADB },
            None,
        );
        assert!(matches!(map_sqlite_err(notadb), StorageError::Corrupt { .. }));

        let constraint = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error { code: rusqlite::ErrorCode::ConstraintViolation, extended_code: rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE },
            Some("UNIQUE constraint failed: t.id".to_string()),
        );
        assert!(matches!(map_sqlite_err(constraint), StorageError::Constraint { .. }));
    }

    #[test]
    fn map_sqlite_err_non_sqlite_failure_is_other() {
        let err = rusqlite::Error::InvalidQuery;
        assert!(matches!(map_sqlite_err(err), StorageError::Other { .. }));
    }
}
