//! Stage A backend: wraps frankensqlite behind [`super::conn::StorageBackend`].
//! Deleted at the end of Stage B once `backend_sqlite.rs` takes over (plan header).

use frankensqlite::{
    Connection as FrankenConnection, FrankenError, Row as FrankenRow, SqliteValue,
    compat::{OpenFlags as FrankenOpenFlags, open_with_flags as open_franken_with_flags},
};

use super::conn::{StorageBackend, TxMode};
use super::error::{BusyScope, StorageError};
use super::value::Value;

pub(crate) struct FrankenBackend {
    conn: FrankenConnection,
}

impl FrankenBackend {
    pub(crate) fn open(path: &str) -> Result<Self, StorageError> {
        let conn = FrankenConnection::open(path).map_err(map_franken_err)?;
        enforce_foreign_keys(&conn)?;
        Ok(Self { conn })
    }

    pub(crate) fn open_read_only(path: &str) -> Result<Self, StorageError> {
        let conn = open_franken_with_flags(path, FrankenOpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(map_franken_err)?;
        enforce_foreign_keys(&conn)?;
        Ok(Self { conn })
    }

    pub(crate) fn open_memory() -> Result<Self, StorageError> {
        let conn = FrankenConnection::open(":memory:").map_err(map_franken_err)?;
        enforce_foreign_keys(&conn)?;
        Ok(Self { conn })
    }
}

/// w1b Task B2b (R0-B3): spec R0-B07 requires every `storage::api` connection
/// to enforce FK constraints -- discovered missing here while wiring up
/// B2b's own integration test (`conn.rs::api_foreign_keys_stay_on_across_
/// batch_write_and_orphan_insert_fails`), not something this backend ever
/// had. `backend_sqlite.rs` (Task B2) applies this as part of its full
/// `Profile`-driven PRAGMA plan; this backend doesn't branch on `Profile`
/// (Stage A doc comment on `config.rs`), so it just applies the one rule
/// that's constant across every profile.
fn enforce_foreign_keys(conn: &FrankenConnection) -> Result<(), StorageError> {
    conn.execute_batch("PRAGMA foreign_keys = ON;").map_err(map_franken_err)
}

fn sqlite_to_value(v: &SqliteValue) -> Value {
    match v {
        SqliteValue::Null => Value::Null,
        SqliteValue::Integer(i) => Value::Integer(*i),
        SqliteValue::Float(f) => Value::Real(*f),
        SqliteValue::Text(_) => Value::Text(v.as_text().unwrap_or_default().to_string()),
        SqliteValue::Blob(_) => Value::Blob(v.as_blob().unwrap_or_default().to_vec()),
    }
}

fn value_to_sqlite(v: &Value) -> SqliteValue {
    match v {
        Value::Null => SqliteValue::Null,
        Value::Integer(i) => SqliteValue::Integer(*i),
        Value::Real(f) => SqliteValue::Float(*f),
        Value::Text(s) => SqliteValue::from(s.clone()),
        Value::Blob(b) => SqliteValue::from(b.clone()),
    }
}

fn row_to_values(row: &FrankenRow) -> Vec<Value> {
    row.values().iter().map(sqlite_to_value).collect()
}

impl StorageBackend for FrankenBackend {
    fn execute(&self, sql: &str, params: &[Value]) -> Result<usize, StorageError> {
        let values: Vec<SqliteValue> = params.iter().map(value_to_sqlite).collect();
        self.conn.execute_with_params(sql, &values).map_err(map_franken_err)
    }

    fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        self.conn.execute_batch(sql).map_err(map_franken_err)
    }

    fn query_map(
        &self,
        sql: &str,
        params: &[Value],
        cb: &mut dyn FnMut(&super::conn::Row) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let values: Vec<SqliteValue> = params.iter().map(value_to_sqlite).collect();
        let mut cb_err: Option<StorageError> = None;
        let result = self.conn.query_with_params_for_each(sql, &values, |franken_row| {
            let converted = row_to_values(franken_row);
            let row = super::conn::Row::new(&converted);
            match cb(&row) {
                Ok(()) => Ok(()),
                Err(e) => {
                    cb_err = Some(e);
                    // Signal the underlying iterator to stop; the concrete FrankenError
                    // variant doesn't matter because `cb_err` takes precedence below.
                    Err(FrankenError::Internal("storage::api callback error".into()))
                }
            }
        });
        if let Some(e) = cb_err {
            return Err(e);
        }
        result.map_err(map_franken_err)
    }

    fn begin(&self, _mode: TxMode) -> Result<(), StorageError> {
        self.conn.begin_transaction().map_err(map_franken_err)
    }

    fn commit(&self) -> Result<(), StorageError> {
        self.conn.commit_transaction().map_err(map_franken_err)
    }

    fn rollback(&self) -> Result<(), StorageError> {
        self.conn.rollback_transaction().map_err(map_franken_err)
    }

    fn last_insert_rowid(&self) -> i64 {
        self.conn.last_insert_rowid()
    }

    fn close(self: Box<Self>) -> Result<(), StorageError> {
        self.conn.close().map_err(map_franken_err)
    }

    fn close_without_checkpoint(self: Box<Self>) -> Result<(), StorageError> {
        self.conn.close_without_checkpoint().map_err(map_franken_err)
    }

    fn close_in_place(&mut self) -> Result<(), StorageError> {
        self.conn.close_in_place().map_err(map_franken_err)
    }

    fn close_without_checkpoint_in_place(&mut self) -> Result<(), StorageError> {
        self.conn.close_without_checkpoint_in_place().map_err(map_franken_err)
    }

    fn close_best_effort_in_place(&mut self) {
        self.conn.close_best_effort_in_place();
    }

    fn as_franken(&self) -> Option<&FrankenBackend> {
        Some(self)
    }
}

/// A single schema migration (Task A4a: mirrors `frankensqlite::migrate::Migration`'s
/// shape so `sqlite.rs` doesn't need to name that type directly).
pub(crate) struct FrankenMigration {
    pub(crate) version: i64,
    pub(crate) name: &'static str,
    pub(crate) up_sql: &'static str,
}

/// Mirrors `frankensqlite::migrate::MigrationResult`.
pub(crate) struct FrankenMigrationResult {
    pub(crate) applied: Vec<i64>,
    pub(crate) current: i64,
    pub(crate) was_fresh: bool,
}

/// Task A4a: runs `frankensqlite::migrate::MigrationRunner` against the native
/// connection behind `conn`. franken-specific migration machinery stays inside
/// this backend file; `sqlite.rs` only ever sees [`FrankenMigration`]/
/// [`FrankenMigrationResult`]. Panics if `conn` isn't backed by [`FrankenBackend`]
/// (Stage A has no other backend, so this can't happen in practice).
pub(crate) fn run_franken_migrations(
    conn: &super::conn::Conn,
    migrations: &[FrankenMigration],
) -> Result<FrankenMigrationResult, StorageError> {
    let backend = conn
        .as_franken()
        .expect("Stage A: run_franken_migrations requires the franken backend");
    let mut runner = frankensqlite::migrate::MigrationRunner::new();
    for m in migrations {
        runner = runner.add(m.version, m.name, m.up_sql);
    }
    runner
        .run(&backend.conn)
        .map(|r| FrankenMigrationResult {
            applied: r.applied,
            current: r.current,
            was_fresh: r.was_fresh,
        })
        .map_err(map_franken_err)
}

/// Stage A fsqlite error mapping (plan Task A3). Retry classification mirrors
/// `retryable_franken_error` @ sqlite.rs:766-772 bit for bit — anything that
/// function treats as retryable must land in `Busy{..}` here, or Stage A
/// silently changes retry behavior.
pub(crate) fn map_franken_err(e: FrankenError) -> StorageError {
    let detail = e.to_string();
    match e {
        FrankenError::BusySnapshot { .. }
        | FrankenError::WriteConflict { .. }
        | FrankenError::SerializationFailure { .. } => {
            StorageError::Busy { scope: BusyScope::Snapshot }
        }
        FrankenError::BusyRecovery
        | FrankenError::Busy
        | FrankenError::DatabaseLocked { .. }
        | FrankenError::LockFailed { .. } => StorageError::Busy { scope: BusyScope::Statement },
        // Task A4a: `WalCorrupt` was the only variant this arm covered under A3
        // (whose doc comment above cites only `retryable_franken_error`'s 7-variant
        // retry set as the contract to preserve bit-for-bit). Migrating
        // `schema_check_error_requires_rebuild` (sqlite.rs) surfaced a second,
        // independent contract this mapping must also satisfy: its own doc
        // comment lists `DatabaseCorrupt`/`WalCorrupt`/`NotADatabase`/`ShortRead`
        // as the exact rebuild-worthy set (cass's own judgment call — note fsqlite
        // itself classifies `ShortRead` as a plain I/O error, not corruption, but
        // cass has always treated a short read while parsing the DB header/pages
        // as a corruption signal). Adding these three doesn't touch the retry set
        // above (none of them were ever retryable).
        FrankenError::WalCorrupt { .. }
        | FrankenError::DatabaseCorrupt { .. }
        | FrankenError::NotADatabase { .. }
        | FrankenError::ShortRead { .. } => StorageError::Corrupt { detail },
        FrankenError::UniqueViolation { .. }
        | FrankenError::NotNullViolation { .. }
        | FrankenError::CheckViolation { .. }
        | FrankenError::ForeignKeyViolation
        | FrankenError::PrimaryKeyViolation => StorageError::Constraint { detail },
        // ConcurrentUnavailable deliberately falls through to Other (R3-N3): current
        // retry predicate (retryable_franken_error) does NOT retry it, and fsqlite's
        // own `is_transient()` reports false — folding it into Busy would introduce
        // unauthorized retries that don't exist today.
        _ => StorageError::Other { code: None, detail },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_franken_err_busy_snapshot_family() {
        assert!(matches!(
            map_franken_err(FrankenError::BusySnapshot { conflicting_pages: String::new() }),
            StorageError::Busy { scope: BusyScope::Snapshot }
        ));
        assert!(matches!(
            map_franken_err(FrankenError::WriteConflict { page: 1, holder: 2 }),
            StorageError::Busy { scope: BusyScope::Snapshot }
        ));
        assert!(matches!(
            map_franken_err(FrankenError::SerializationFailure { page: 1 }),
            StorageError::Busy { scope: BusyScope::Snapshot }
        ));
    }

    #[test]
    fn map_franken_err_busy_statement_family() {
        assert!(matches!(
            map_franken_err(FrankenError::BusyRecovery),
            StorageError::Busy { scope: BusyScope::Statement }
        ));
        assert!(matches!(
            map_franken_err(FrankenError::Busy),
            StorageError::Busy { scope: BusyScope::Statement }
        ));
        assert!(matches!(
            map_franken_err(FrankenError::DatabaseLocked { path: "x".into() }),
            StorageError::Busy { scope: BusyScope::Statement }
        ));
        assert!(matches!(
            map_franken_err(FrankenError::LockFailed { detail: "x".into() }),
            StorageError::Busy { scope: BusyScope::Statement }
        ));
    }

    #[test]
    fn map_franken_err_concurrent_unavailable_is_other_not_busy() {
        // R3-N3: must NOT be folded into Busy{Snapshot} — see comment on map_franken_err.
        assert!(matches!(
            map_franken_err(FrankenError::ConcurrentUnavailable),
            StorageError::Other { .. }
        ));
    }

    #[test]
    fn map_franken_err_corrupt_and_constraint() {
        assert!(matches!(
            map_franken_err(FrankenError::WalCorrupt { detail: "x".into() }),
            StorageError::Corrupt { .. }
        ));
        assert!(matches!(
            map_franken_err(FrankenError::UniqueViolation { columns: "id".into() }),
            StorageError::Constraint { .. }
        ));
        assert!(matches!(
            map_franken_err(FrankenError::ForeignKeyViolation),
            StorageError::Constraint { .. }
        ));
    }

    #[test]
    fn map_franken_err_display_text_preserved() {
        let mapped = map_franken_err(FrankenError::DatabaseFull);
        match mapped {
            StorageError::Other { detail, .. } => assert!(detail.contains("full")),
            other => panic!("expected Other, got {other:?}"),
        }
    }
}
