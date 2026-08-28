//! Conn/Row/Tx facade (plan Task A3) — the sole consumer-facing surface of
//! storage::api. Engine type never appears here; dispatch goes through
//! [`StorageBackend`], private to this module tree.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::config::{
    OpenOptions, Profile, RETRY_JITTER_MAX_PERCENT, RETRY_JITTER_MIN_PERCENT,
    STATEMENT_RETRY_BASE_MS, STATEMENT_RETRY_MAX_ATTEMPTS, STATEMENT_RETRY_TOTAL_CAP_MS,
    TX_REPLAY_BASE_MS, TX_REPLAY_MAX_ATTEMPTS,
};
use super::error::{BusyScope, StorageError};
use super::value::Value;

/// w1b Task B3 (D2): SplitMix64-derived jitter source, mirroring
/// `storage::sqlite::next_franken_retry_jitter_ms`'s approach (no `rand`
/// dependency for this -- an atomic counter plus a fixed mixing constant is
/// enough scatter to avoid lock-step retries across threads, and stays
/// dependency-free at this layer). Not shared with that function directly:
/// `storage::api` does not depend on `storage::sqlite` (the dependency runs
/// the other way), so this is a deliberate small duplication, not an
/// oversight.
static RETRY_JITTER_STATE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn next_jitter_percent() -> u64 {
    let mut value = RETRY_JITTER_STATE
        .fetch_add(0x9e37_79b9_7f4a_7c15, std::sync::atomic::Ordering::Relaxed);
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    let span = RETRY_JITTER_MAX_PERCENT - RETRY_JITTER_MIN_PERCENT + 1;
    RETRY_JITTER_MIN_PERCENT + (value % span)
}

/// w1b Task B3 (D2): `base_ms * 2^attempt`, scaled by a `±25%` jitter factor
/// (plan's "100ms*2^n ±25% 抖动" / "50ms*2^n ±25%"). `attempt` is 0-indexed
/// (the first retry uses `attempt == 0`).
fn jittered_backoff_ms(base_ms: u64, attempt: u32) -> u64 {
    let exp_ms = base_ms.saturating_mul(1u64 << attempt.min(20));
    exp_ms.saturating_mul(next_jitter_percent()) / 100
}

/// w1b Task B3 (D2, R1-N2): the shared bounded-retry loop for a single
/// statement. Only ever invoked on operations with no caller-visible
/// intermediate state -- a single `execute()` call, or a from-scratch
/// re-run of a query -- because SQLite guarantees a statement that fails
/// with `SQLITE_BUSY` made no partial change, so re-running it from
/// scratch is safe regardless of what it does. This is why `execute_batch`
/// (multiple statements, autocommit, partial-completion risk) is
/// deliberately excluded and never routed through this function.
fn retry_statement_on_busy<T>(
    mut op: impl FnMut() -> Result<T, StorageError>,
) -> Result<T, StorageError> {
    let mut attempt = 0u32;
    let mut elapsed_ms = 0u64;
    loop {
        let outcome = op();
        match &outcome {
            Ok(_) => return outcome,
            Err(StorageError::Busy { scope: BusyScope::Statement }) => {
                if attempt >= STATEMENT_RETRY_MAX_ATTEMPTS {
                    return outcome;
                }
                let backoff = jittered_backoff_ms(STATEMENT_RETRY_BASE_MS, attempt);
                if elapsed_ms.saturating_add(backoff) > STATEMENT_RETRY_TOTAL_CAP_MS {
                    return outcome;
                }
                std::thread::sleep(Duration::from_millis(backoff));
                elapsed_ms += backoff;
                attempt += 1;
                #[cfg(test)]
                test_support::note_statement_retry();
            }
            Err(_) => return outcome,
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::Cell;

    thread_local! {
        static STATEMENT_RETRY_COUNT: Cell<u32> = const { Cell::new(0) };
    }

    pub(crate) fn note_statement_retry() {
        STATEMENT_RETRY_COUNT.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn reset_statement_retry_count() {
        STATEMENT_RETRY_COUNT.with(|c| c.set(0));
    }

    pub(crate) fn statement_retry_count() -> u32 {
        STATEMENT_RETRY_COUNT.with(|c| c.get())
    }
}

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
    /// plan delta d4: `&self`, not `&mut self` — mirrors the legacy engine crate's native
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
    /// == current the legacy engine crate's `Connection::close()` (checkpoint policy left to SQLite's
    /// default close path).
    fn close(self: Box<Self>) -> Result<(), StorageError>;
    /// == current the legacy engine crate's `Connection::close_without_checkpoint()`.
    fn close_without_checkpoint(self: Box<Self>) -> Result<(), StorageError>;

    /// == current the legacy engine crate's `Connection::close_in_place(&mut self)` (Task A4a): closes
    /// without consuming the handle, for callers that only hold `&mut Conn`.
    fn close_in_place(&mut self) -> Result<(), StorageError>;
    /// == current the legacy engine crate's `Connection::close_without_checkpoint_in_place(&mut self)`.
    fn close_without_checkpoint_in_place(&mut self) -> Result<(), StorageError>;
    /// == current the legacy engine crate's `Connection::close_best_effort_in_place(&mut self)`
    /// (same no-checkpoint best-effort path as `Drop`, errors swallowed).
    fn close_best_effort_in_place(&mut self);
}

/// Transaction begin mode. w1b Task B3 (D2, plan @775-776) adds `Immediate`
/// -- write transactions use it deliberately (avoids the deferred-upgrade
/// deadlock/BUSY_SNAPSHOT surface a `Deferred` transaction hits the moment it
/// tries to upgrade from a read to a write). `pub` per the plan's stated
/// interface: callers choosing between `with_tx`/`with_tx_no_replay` pick a
/// mode explicitly. `backend_franken.rs` (Stage A, deleted at Stage B's end)
/// cannot distinguish modes -- the legacy engine crate's `begin_transaction()` takes none --
/// so it ignores this and always begins deferred-equivalent; only
/// `backend_sqlite.rs` (the eventual production backend) branches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxMode {
    Deferred,
    Immediate,
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

/// w1b Task B2b (R0-B3, R3-N7, R4-B3): the api layer provides no capability
/// to turn foreign key enforcement off -- `Conn`/`Tx` construction never
/// exposes such a knob -- but `execute`/`execute_batch` still accept
/// arbitrary SQL text, so that guarantee is not structurally airtight on the
/// string channel (R3-N7's own honest admission). This is the defense-in-
/// depth layer for that gap: reject (rather than silently execute) any SQL
/// whose full text mentions the literal `foreign_keys` keyword,
/// case-insensitively. R4-B3: scans the *entire* text, not a prefix check --
/// a prefix check is trivially bypassed by a multi-statement batch like
/// `"SELECT 1; PRAGMA foreign_keys=OFF"`. False-positive risk is accepted:
/// ordinary business SQL never contains this identifier, and even a comment
/// mentioning it should fail loud rather than risk a real bypass slipping
/// through. This is the depth layer behind two others: the runtime
/// `foreign_keys=ON` readback assertion (Task B2, `backend_sqlite.rs`) and
/// the `grep` gate over `src/`/`tests/` for literal `foreign_keys = OFF`.
fn reject_foreign_keys_keyword(sql: &str) -> Result<(), StorageError> {
    if sql.to_ascii_lowercase().contains("foreign_keys") {
        return Err(StorageError::Other {
            code: None,
            detail: "SQL text references 'foreign_keys'; storage::api does not allow \
                     toggling foreign key enforcement (use Tx::defer_foreign_keys() for \
                     legitimate out-of-order writes inside a transaction)"
                .to_string(),
        });
    }
    Ok(())
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
    /// w1b Task B4: present only on connections opened through
    /// [`Conn::open_writable`]. Its `Drop` decrements the process-wide
    /// per-path writer-connection registry (`super::writer`), which is how
    /// the B4 "at most one live writer connection per path" invariant is
    /// observed at runtime regardless of which call site opened the
    /// connection.
    _writer_open_guard: Option<super::writer::WriterOpenGuard>,
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
        let backend = super::backend_sqlite::SqliteBackend::open_read_only(path_to_str(path)?)?;
        Ok(Conn { inner: Box::new(backend), path: Some(path.to_path_buf()), _writer_open_guard: None })
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
    /// once built, the `WriterHandle`/schema call sites within this crate. w1b
    /// Task B4 (Q3): `storage::testing` re-exposes this for integration-test
    /// fixture construction only (`tests/`/`benches/` are separate crates and
    /// can't reach `pub(crate)` items directly) -- see that module's doc
    /// comment for the closed-world boundary this relies on.
    ///
    /// w1b Task B8: dispatches to `SqliteBackend` (the franken backend and
    /// its `FrankenBackend::open` dispatch here were retired together with
    /// `backend_franken.rs`).
    pub(crate) fn open_writable(path: &Path, profile: Profile) -> Result<Conn, StorageError> {
        let backend = super::backend_sqlite::SqliteBackend::open_writable(path_to_str(path)?, profile)?;
        Ok(Conn {
            inner: Box::new(backend),
            path: Some(path.to_path_buf()),
            _writer_open_guard: Some(super::writer::note_writer_opened(path)),
        })
    }

    pub fn open_memory() -> Result<Conn, StorageError> {
        let backend = super::backend_sqlite::SqliteBackend::open_memory()?;
        Ok(Conn { inner: Box::new(backend), path: None, _writer_open_guard: None })
    }

    /// w1b Task B3 (D2, R1-N2): bounded-retries on a real `Busy{Statement}`
    /// (up to [`super::config::STATEMENT_RETRY_MAX_ATTEMPTS`] times, capped
    /// at [`super::config::STATEMENT_RETRY_TOTAL_CAP_MS`] total elapsed
    /// backoff). Safe because a single statement that fails with
    /// `SQLITE_BUSY` made no partial change -- re-running it is not a
    /// double-apply risk the way re-running `execute_batch` would be.
    /// `Busy{Snapshot}` and `Locked` are NOT retried here (`Locked` per
    /// spec §3.3 -- a connection-discipline defect that retries into an
    /// infinite loop; `Busy{Snapshot}` needs a whole-transaction replay,
    /// which only makes sense inside `with_tx`, not a bare single-statement
    /// `execute()` with no transaction context to replay).
    pub fn execute(&self, sql: &str, params: &[Value]) -> Result<usize, StorageError> {
        reject_foreign_keys_keyword(sql)?;
        retry_statement_on_busy(|| self.inner.execute(sql, params))
    }

    pub fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        reject_foreign_keys_keyword(sql)?;
        self.inner.execute_batch(sql)
    }

    /// w1b Task B2b (R0-B3) exception, Ivan-adjudicated 2026-08-26:
    /// crate-internal escape hatch for the exactly three test fixtures
    /// (`storage::sqlite::tests::cleanup_orphan_fk_rows_*`) that must plant
    /// a genuine FK-orphan row -- a child referencing an already-missing
    /// parent -- to test the cass#202 self-heal (`cleanup_orphan_fk_rows`)
    /// finding and removing it. That state is structurally unreachable
    /// through any FK-respecting SQL (the constraint itself is what
    /// prevents it), so it cannot go through `execute_batch`'s
    /// `reject_foreign_keys_keyword` guard. Deliberately `pub(crate)`, not
    /// `pub`: invisible outside this crate, so it can never become a de
    /// facto public "turn FK off" capability, and its name is unambiguous
    /// about what it is for anyone who greps for it.
    pub(crate) fn execute_batch_bypassing_foreign_keys_guard(
        &self,
        sql: &str,
    ) -> Result<(), StorageError> {
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
        self.transaction_with_mode(TxMode::Deferred)
    }

    /// w1b Task B3 (D2): like [`Conn::transaction`], but lets the caller pick
    /// [`TxMode`] explicitly -- the primitive `with_tx`/`with_tx_no_replay`
    /// build on.
    pub fn transaction_with_mode(&self, mode: TxMode) -> Result<Tx<'_>, StorageError> {
        self.inner.begin(mode)?;
        Ok(Tx { backend: self.inner.as_ref(), finalized: false })
    }

    /// w1b Task B3 (D2 core, plan @775-781): whole-transaction replay on a
    /// real `Busy{Snapshot}` conflict (up to
    /// [`super::config::TX_REPLAY_MAX_ATTEMPTS`] times, `100ms*2^n ±25%`
    /// backoff between attempts). `f` must be a pure DB closure -- no
    /// caller-visible side effects outside the database -- because a replay
    /// re-invokes it from scratch against a brand-new transaction after the
    /// failed one was rolled back (via `Tx`'s `Drop`). That purity
    /// requirement is why this takes `impl Fn`, not `impl FnOnce`: the type
    /// system only allows something callable more than once. It does NOT
    /// prove the closure is actually free of non-DB side effects (Rust can't
    /// check that) -- callers whose closure does anything outside the
    /// database (I/O, logging with external effects, mutating state a retry
    /// would double-apply) must use [`Conn::with_tx_no_replay`] instead, even
    /// though its `FnOnce` signature happens to accept a technically-`Fn`
    /// closure too.
    ///
    /// Any other error (including `Locked`, which spec §3.3 found retries
    /// into an infinite loop) propagates immediately without retry.
    pub fn with_tx<T>(
        &self,
        mode: TxMode,
        f: impl Fn(&Tx) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let mut attempt = 0u32;
        loop {
            let tx = self.transaction_with_mode(mode)?;
            let outcome = match f(&tx) {
                Ok(value) => tx.commit().map(|()| value),
                Err(err) => Err(err),
            };
            match outcome {
                Ok(value) => return Ok(value),
                Err(StorageError::Busy { scope: BusyScope::Snapshot })
                    if attempt < TX_REPLAY_MAX_ATTEMPTS =>
                {
                    let backoff = jittered_backoff_ms(TX_REPLAY_BASE_MS, attempt);
                    std::thread::sleep(Duration::from_millis(backoff));
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// w1b Task B3 (D2): non-replaying counterpart to [`Conn::with_tx`] for a
    /// closure that is not (or is not known to be) a pure DB operation --
    /// runs the closure exactly once, commits on success, and propagates any
    /// error (including `Busy{Snapshot}`) without retry. The transaction
    /// still rolls back on any error path via `Tx`'s `Drop`.
    pub fn with_tx_no_replay<T>(
        &self,
        mode: TxMode,
        f: impl FnOnce(&Tx) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let tx = self.transaction_with_mode(mode)?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    pub fn last_insert_rowid(&self) -> i64 {
        self.inner.last_insert_rowid()
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
    /// w1b Task B3 (D2): same statement-level bounded retry as
    /// [`Conn::execute`] -- retrying just this one statement (not the whole
    /// transaction) is safe for the same reason: a statement that fails with
    /// `SQLITE_BUSY` made no partial change. `Busy{Snapshot}` propagates
    /// immediately here; only [`Conn::with_tx`]'s whole-transaction replay
    /// handles that (this `Tx` may already be too far along to safely retry
    /// in place -- e.g. earlier statements already executed against it).
    pub fn execute(&self, sql: &str, params: &[Value]) -> Result<usize, StorageError> {
        reject_foreign_keys_keyword(sql)?;
        retry_statement_on_busy(|| self.backend.execute(sql, params))
    }

    pub fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        reject_foreign_keys_keyword(sql)?;
        self.backend.execute_batch(sql)
    }

    /// Legitimate out-of-order multi-statement writes inside a transaction
    /// (plan Task B2b, R0-B3): SQLite's own `defer_foreign_keys` pragma
    /// delays FK checking from per-statement to commit time, scoped to this
    /// transaction only (SQLite resets it automatically at COMMIT/ROLLBACK,
    /// so it can never leak into a later transaction on the same
    /// connection). Exposed as an explicit, named method rather than being
    /// reachable through `execute`/`execute_batch` (which reject any SQL
    /// mentioning `foreign_keys`, see `reject_foreign_keys_keyword`) so it
    /// can't be invoked by accident or smuggled through arbitrary SQL text
    /// — it calls the backend directly, bypassing that guard on purpose.
    ///
    /// Reads the pragma back and errors if it didn't actually engage
    /// (discovered live, not hypothetical: the current production backend,
    /// the legacy embedded engine, silently no-ops this pragma -- `execute_batch`
    /// returns `Ok(())` but per-statement FK checking stays in effect, and
    /// `PRAGMA defer_foreign_keys;` returns zero rows, meaning it doesn't
    /// recognize the pragma at all. Without this readback, a caller relying
    /// on deferred checking for a legitimate out-of-order write would get a
    /// silent, wrong immediate-check failure instead. `backend_sqlite.rs`'s
    /// own tests confirm real SQLite honors this pragma correctly; the
    /// error path here only fires on a backend that doesn't).
    pub fn defer_foreign_keys(&self) -> Result<(), StorageError> {
        self.backend.execute_batch("PRAGMA defer_foreign_keys = ON;")?;
        let engaged =
            self.query_row_map("PRAGMA defer_foreign_keys;", &[], |r| r.get_typed::<i64>(0))
                .unwrap_or(0);
        if engaged != 1 {
            return Err(StorageError::Other {
                code: None,
                detail: "PRAGMA defer_foreign_keys did not engage on this connection -- this \
                         backend does not support deferred FK checking, so out-of-order \
                         writes inside a transaction are not available here"
                    .to_string(),
            });
        }
        Ok(())
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

    /// == current the legacy engine crate's `compat::Transaction::rollback` (Task A4a): explicit
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
            // (matches the legacy engine crate's own compat::Transaction Drop behavior).
            let _ = self.backend.rollback();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::backend_sqlite::SqliteBackend;
    use super::super::params;
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// w1b Task B3 (D2): test-only construction of a `Conn` wrapping the real
    /// `SqliteBackend` (rusqlite/real SQLite), not the Stage-A the legacy embedded engine
    /// backend `Conn::open_writable` currently resolves to. The real
    /// `BUSY`/`BUSY_SNAPSHOT` concurrency tests in this module need genuine
    /// SQLite WAL/MVCC semantics -- this is scoped to `#[cfg(test)]` only and
    /// does not touch the (separately-tracked, out-of-scope-for-B3) question
    /// of when `Conn::open_writable` itself cuts over to `SqliteBackend`.
    fn open_writable_sqlite_for_test(path: &Path) -> Conn {
        let backend = SqliteBackend::open_writable(path.to_str().unwrap(), Profile::Production)
            .expect("open real sqlite backend for test");
        Conn {
            inner: Box::new(backend),
            path: Some(path.to_path_buf()),
            _writer_open_guard: Some(crate::storage::api::writer::note_writer_opened(path)),
        }
    }

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

    #[test]
    fn api_execute_rejects_sql_mentioning_foreign_keys() {
        // R4-B3: full-text scan, not a prefix check -- a multi-statement
        // batch smuggling the keyword after a leading innocuous statement
        // must still be caught.
        let c = Conn::open_memory().unwrap();
        assert!(matches!(
            c.execute_batch("PRAGMA foreign_keys = OFF;"),
            Err(StorageError::Other { .. })
        ));
        assert!(matches!(
            c.execute_batch("SELECT 1; PRAGMA foreign_keys=OFF;"),
            Err(StorageError::Other { .. })
        ));
        assert!(matches!(
            c.execute("PRAGMA FOREIGN_KEYS = OFF", &[]),
            Err(StorageError::Other { .. })
        ), "must be case-insensitive");
    }

    #[test]
    fn api_foreign_keys_stay_on_across_batch_write_and_orphan_insert_fails() {
        // plan Task B2b Step 2's integration test: a batch write path (a
        // well-ordered multi-statement transaction -- parent before child,
        // the shape every real batch write actually uses) must not leave FK
        // enforcement off afterward, and a genuine orphan insert outside
        // that transaction must still be rejected as a real `Constraint`
        // error (see `api_defer_foreign_keys_errors_on_unsupported_backend`
        // below for the separate out-of-order/deferred-check path, which
        // the current production backend doesn't support).
        let c = Conn::open_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE parent(id INTEGER PRIMARY KEY);
             CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parent(id));",
        )
        .unwrap();

        {
            let tx = c.transaction().unwrap();
            tx.execute("INSERT INTO parent(id) VALUES (100)", &[]).unwrap();
            tx.execute("INSERT INTO child(id, parent_id) VALUES (1, 100)", &[]).unwrap();
            tx.commit().unwrap();
        }

        let fk: i64 =
            c.query_row_map("PRAGMA foreign_keys;", &[], |r| r.get_typed(0)).unwrap();
        assert_eq!(fk, 1, "foreign_keys must remain ON after a batch-write transaction");

        let err = c
            .execute("INSERT INTO child(id, parent_id) VALUES (2, 999)", &[])
            .unwrap_err();
        assert!(matches!(err, StorageError::Constraint { .. }));
    }

    // w1b Task B8: `api_defer_foreign_keys_errors_on_unsupported_backend`
    // (asserted `Conn::open_memory()` -> `defer_foreign_keys()` errors, back
    // when it resolved to the franken backend, which didn't implement the
    // pragma) retired -- `Conn::open_memory` now resolves to `SqliteBackend`,
    // which honors `defer_foreign_keys` correctly; the positive case is
    // already covered by `backend_sqlite.rs`'s
    // `defer_foreign_keys_permits_out_of_order_write_then_resets_after_commit`.

    // =========================================================================
    // w1b Task B3 (D2): retry / whole-transaction replay
    // =========================================================================

    /// Plan Step 1①: two real connections, a real `Busy{Statement}`,
    /// statement-level retry succeeds once the lock clears, retry count > 0.
    ///
    /// Drops to raw `rusqlite::Connection` rather than `Conn`/`Tx`
    /// (discovered live while wiring this test up): `StorageBackend` has no
    /// `Send` bound, and cannot gain one without breaking the still-active
    /// `FrankenBackend` impl -- the legacy engine crate's `Connection` holds `Rc<RefCell<_>>`
    /// state internally and is not `Send`. So `Box<dyn StorageBackend>` (and
    /// therefore `Conn`, and `Tx`'s `&dyn StorageBackend`) cannot cross a
    /// thread boundary today. That's a real architectural fact surfaced by
    /// this task, not a workaround-of-convenience: it means the `Conn`/`Tx`
    /// facade itself is single-thread-only until `backend_franken.rs` is
    /// retired, worth flagging for B4's `WriterHandle` design too. This test
    /// exercises the actual production `retry_statement_on_busy` function
    /// (not a reimplementation) against real rusqlite contention instead.
    #[test]
    fn api_execute_retries_past_real_statement_busy_and_succeeds() {
        let dir = std::env::temp_dir()
            .join(format!("cc-cass-w1b-b3-stmt-busy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("t.db");
        let db_path_str = db_path.to_str().unwrap().to_string();

        let holder = rusqlite::Connection::open(&db_path_str).unwrap();
        holder.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY);").unwrap();
        holder.execute_batch("BEGIN IMMEDIATE;").unwrap();
        holder.execute("INSERT INTO t(id) VALUES (1)", []).unwrap();
        // Left open (not committed) -- the contender below must collide.

        let contender = rusqlite::Connection::open(&db_path_str).unwrap();
        // busy_timeout=0 so contention surfaces as a real Busy{Statement}
        // immediately instead of blocking inside SQLite's own C busy
        // handler -- exactly like `backend_sqlite.rs`'s
        // `map_sqlite_err_real_busy_statement_from_write_contention` (this
        // task's own retry loop is meant to own that responsibility instead).
        contender.busy_timeout(Duration::from_millis(0)).unwrap();

        // Release the lock partway through the contender's retry window
        // (well inside the ~750ms-1000ms the retry schedule allows) so this
        // proves convergence, not a race against the cap. `rusqlite::
        // Connection` is `Send` (just not `Sync`), so moving `holder` here
        // is fine.
        let release_handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            holder.execute_batch("COMMIT;").unwrap();
        });

        test_support::reset_statement_retry_count();
        let result = retry_statement_on_busy(|| {
            contender
                .execute("INSERT INTO t(id) VALUES (2)", [])
                .map_err(super::super::backend_sqlite::map_sqlite_err)
        });
        release_handle.join().unwrap();

        assert!(result.is_ok(), "expected the retry loop to converge once the lock cleared, got {result:?}");
        assert!(test_support::statement_retry_count() > 0, "expected at least one observed retry");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Plan Step 1②: injected `Busy{Snapshot}` from within the closure --
    /// `with_tx` must re-invoke it and eventually return the successful
    /// result.
    #[test]
    fn api_with_tx_replays_closure_on_injected_busy_snapshot() {
        let c = Conn::open_memory().unwrap();
        c.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY);").unwrap();

        let call_count = AtomicU32::new(0);
        let result = c.with_tx(TxMode::Immediate, |tx| {
            let n = call_count.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                return Err(StorageError::Busy { scope: BusyScope::Snapshot });
            }
            tx.execute("INSERT INTO t(id) VALUES (1)", &[])?;
            Ok(())
        });

        assert!(result.is_ok(), "expected with_tx to replay past injected Busy{{Snapshot}}: {result:?}");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            3,
            "expected 2 injected failures + 1 successful invocation"
        );
        let n: i64 = c.query_row_map("SELECT count(*) FROM t", &[], |r| r.get_typed(0)).unwrap();
        assert_eq!(n, 1, "the successful attempt's write must have committed exactly once");
    }

    /// Plan Step 1③: `Locked` must never be retried, at either the
    /// statement level or `with_tx`'s transaction-replay level.
    #[test]
    fn api_locked_is_never_retried() {
        let c = Conn::open_memory().unwrap();
        c.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY);").unwrap();

        let call_count = AtomicU32::new(0);
        let result = c.with_tx(TxMode::Immediate, |_tx| {
            call_count.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(StorageError::Locked)
        });
        assert!(matches!(result, Err(StorageError::Locked)));
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "Locked must propagate on the first attempt, with_tx must not replay it"
        );

        // Statement-level: `retry_statement_on_busy` itself, isolated from
        // any real connection, must not retry a `Locked` outcome either.
        let stmt_call_count = AtomicU32::new(0);
        let stmt_result = retry_statement_on_busy(|| {
            stmt_call_count.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(StorageError::Locked)
        });
        assert!(matches!(stmt_result, Err(StorageError::Locked)));
        assert_eq!(stmt_call_count.load(Ordering::SeqCst), 1);
    }

    /// Control-plane follow-up on Step 1①: that test exercises the real
    /// `retry_statement_on_busy` production function directly, standalone --
    /// this one proves the actual wiring from `Conn::execute` through to it
    /// under real contention, single-threaded (no background thread: A never
    /// releases its lock, so this exercises the retry-exhaustion path, not
    /// eventual success -- that half is already covered by Step 1①).
    #[test]
    fn api_execute_retries_then_gives_up_past_the_bound_on_real_statement_busy() {
        let dir = std::env::temp_dir()
            .join(format!("cc-cass-w1b-b3-stmt-busy-exhaust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("t.db");

        let holder = open_writable_sqlite_for_test(&db_path);
        holder.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY);").unwrap();
        let holder_tx = holder.transaction_with_mode(TxMode::Immediate).unwrap();
        holder_tx.execute("INSERT INTO t(id) VALUES (1)", &[]).unwrap();
        // Left open for the whole test -- the contender must exhaust its
        // retry budget without ever succeeding.

        let contender = open_writable_sqlite_for_test(&db_path);
        contender.execute_batch("PRAGMA busy_timeout = 0;").unwrap();

        test_support::reset_statement_retry_count();
        let start = std::time::Instant::now();
        let result = contender.execute("INSERT INTO t(id) VALUES (2)", &[]);
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(StorageError::Busy { scope: BusyScope::Statement })),
            "expected the retry loop to exhaust and propagate the original Busy{{Statement}}, got {result:?}"
        );
        // The observed retry count here is the number of times the loop
        // actually slept-and-retried, not the raw attempt-count bound
        // (`STATEMENT_RETRY_MAX_ATTEMPTS` = 5): with the current constants
        // (50ms base, doubling, 1000ms total cap), the total-elapsed cap
        // binds before the 5th backoff would fit (50+100+200+400 = 750ms,
        // and the 5th nominal backoff of ~800ms would push cumulative
        // elapsed past 1000ms), so this converges on 4 actual retries in
        // practice, not 5 -- asserting a range rather than a single exact
        // number to tolerate the +/-25% jitter shifting which backoff trips
        // the cap.
        let retry_count = test_support::statement_retry_count();
        assert!(
            (3..=5).contains(&retry_count),
            "expected 3-5 observed retries before the total-elapsed cap or attempt bound kicked in, got {retry_count}"
        );
        assert!(
            elapsed >= Duration::from_millis(300) && elapsed <= Duration::from_millis(2000),
            "expected total elapsed time in the ballpark of the ~750ms-1000ms retry budget, got {elapsed:?}"
        );

        drop(holder_tx);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Plan Step 1④ (R4-B4, "本组最承重"): a REAL end-to-end `BUSY_SNAPSHOT`
    /// chain, not an injected one -- connection A begins DEFERRED and reads
    /// a row (establishing a read snapshot), connection B writes and
    /// commits (advancing the WAL past A's snapshot), then A attempts a
    /// write inside the SAME still-open transaction. That sequence is
    /// deliberately built without any thread/timing race for the conflict
    /// itself (only `with_tx`'s own backoff sleep involves real time) --
    /// steps happen in strict sequence across the two connections, so the
    /// real `SQLITE_BUSY_SNAPSHOT` this manufactures is deterministic, not
    /// timing-dependent.
    #[test]
    fn api_with_tx_replays_past_a_real_busy_snapshot_conflict() {
        // Half A: prove the extended-code mapping fires for real, standalone
        // (not wrapped in with_tx yet) -- this is the "real scenario exists"
        // half of Step 1④'s assertion.
        let dir_a = std::env::temp_dir()
            .join(format!("cc-cass-w1b-b3-snapshot-mapping-{}", std::process::id()));
        std::fs::create_dir_all(&dir_a).unwrap();
        let db_path_a = dir_a.join("t.db");

        let conn_a = open_writable_sqlite_for_test(&db_path_a);
        conn_a
            .execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, v INTEGER NOT NULL);")
            .unwrap();
        conn_a.execute("INSERT INTO t(id, v) VALUES (1, 0)", &[]).unwrap();

        let tx_a = conn_a.transaction_with_mode(TxMode::Deferred).unwrap();
        let _v: i64 =
            tx_a.query_row_map("SELECT v FROM t WHERE id = 1", &[], |r| r.get_typed(0)).unwrap();

        let conn_b = open_writable_sqlite_for_test(&db_path_a);
        conn_b.execute("UPDATE t SET v = v + 1 WHERE id = 1", &[]).unwrap();
        drop(conn_b);

        let write_err = tx_a.execute("UPDATE t SET v = v + 100 WHERE id = 1", &[]).unwrap_err();
        assert!(
            matches!(write_err, StorageError::Busy { scope: BusyScope::Snapshot }),
            "expected a real BUSY_SNAPSHOT from the extended-code mapping, got {write_err:?}"
        );
        drop(tx_a);
        std::fs::remove_dir_all(&dir_a).ok();

        // Half B: the same real conflict, this time driven through
        // `with_tx`, proving the whole-transaction replay actually recovers
        // from it and commits successfully.
        let dir_b = std::env::temp_dir()
            .join(format!("cc-cass-w1b-b3-snapshot-replay-{}", std::process::id()));
        std::fs::create_dir_all(&dir_b).unwrap();
        let db_path_b = dir_b.join("t.db");

        let conn = open_writable_sqlite_for_test(&db_path_b);
        conn.execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY, v INTEGER NOT NULL);")
            .unwrap();
        conn.execute("INSERT INTO t(id, v) VALUES (1, 0)", &[]).unwrap();

        let attempt_count = AtomicU32::new(0);
        let result = conn.with_tx(TxMode::Deferred, |tx| {
            let n = attempt_count.fetch_add(1, Ordering::SeqCst);
            let _v: i64 =
                tx.query_row_map("SELECT v FROM t WHERE id = 1", &[], |r| r.get_typed(0))?;
            if n == 0 {
                // Only on the first attempt: interleave a real conflicting
                // commit from another connection while this transaction is
                // still open, so the write below hits a real BUSY_SNAPSHOT
                // (not an injected one) on this attempt specifically.
                let interloper = open_writable_sqlite_for_test(&db_path_b);
                interloper.execute("UPDATE t SET v = v + 1 WHERE id = 1", &[])?;
                drop(interloper);
            }
            tx.execute("UPDATE t SET v = v + 100 WHERE id = 1", &[])?;
            Ok(())
        });

        assert!(result.is_ok(), "expected with_tx to replay past a real BUSY_SNAPSHOT: {result:?}");
        assert!(
            attempt_count.load(Ordering::SeqCst) >= 2,
            "expected the closure to be re-invoked after the real snapshot conflict, got {} attempts",
            attempt_count.load(Ordering::SeqCst)
        );

        let final_v: i64 =
            conn.query_row_map("SELECT v FROM t WHERE id = 1", &[], |r| r.get_typed(0)).unwrap();
        assert_eq!(final_v, 101, "expected exactly one successful +1 (interloper) and one +100 (replayed write), not a double-apply");

        std::fs::remove_dir_all(&dir_b).ok();
    }
}
