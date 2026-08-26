//! WriterHandle — the single-writer queue Stage B collapses all write paths
//! onto (plan Task B4, secondary contract #4).
//!
//! `franken_backend::FrankenBackend` still holds `Rc<RefCell<_>>` state
//! internally (structurally `!Send`) until it is retired in B8, which means
//! a `Conn`/`Tx` built on that backend can never cross a thread boundary.
//! `WriterHandle` works around that by never moving a `Conn` anywhere: one
//! dedicated writer thread opens the connection, keeps it for its own
//! lifetime, and consumes closures off a channel. Only the channel sender
//! (this struct) is `Send` — exactly the shape the exec8 handoff called out
//! as the only viable one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::thread::JoinHandle;

use super::config::Profile;
use super::conn::Conn;
use super::error::StorageError;

// ---------------------------------------------------------------------
// Process-wide writer-connection registry, keyed by db path.
//
// This is deliberately hooked into `Conn::open_writable` itself (see the
// `_writer_open_guard` field on `Conn`), not into `WriterHandle` -- so it
// observes every writable connection any code path opens, including ones
// that have not yet been migrated onto `WriterHandle`. That is what makes
// "peak == 1" a meaningful red/green signal instead of a tautology that
// only measures WriterHandle's own discipline.
// ---------------------------------------------------------------------

#[derive(Default)]
struct PathCounts {
    current: usize,
    peak: usize,
}

static WRITER_COUNTS: OnceLock<Mutex<HashMap<PathBuf, PathCounts>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<PathBuf, PathCounts>> {
    WRITER_COUNTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// RAII marker stored on every writable `Conn`. Increments the per-path
/// live-writer count on construction, decrements on drop -- so the count
/// reflects connections that are actually open right now, regardless of
/// which mechanism opened them.
pub(crate) struct WriterOpenGuard {
    key: PathBuf,
}

pub(crate) fn note_writer_opened(path: &Path) -> WriterOpenGuard {
    let key = path.to_path_buf();
    let mut reg = registry().lock().expect("writer registry mutex poisoned");
    let counts = reg.entry(key.clone()).or_default();
    counts.current += 1;
    if counts.current > counts.peak {
        counts.peak = counts.current;
    }
    WriterOpenGuard { key }
}

impl Drop for WriterOpenGuard {
    fn drop(&mut self) {
        let mut reg = registry().lock().expect("writer registry mutex poisoned");
        if let Some(counts) = reg.get_mut(&self.key) {
            counts.current = counts.current.saturating_sub(1);
        }
    }
}

/// Current number of writable connections open on `path` right now.
/// Under the B4 invariant this is never observed above 1 once every write
/// path routes through `WriterHandle`.
pub fn writer_connection_count(path: &Path) -> usize {
    registry()
        .lock()
        .expect("writer registry mutex poisoned")
        .get(path)
        .map(|c| c.current)
        .unwrap_or(0)
}

/// Highest `writer_connection_count` value ever observed for `path` since
/// the last [`reset_writer_connection_peak`] call (or process start).
pub fn writer_connection_peak(path: &Path) -> usize {
    registry()
        .lock()
        .expect("writer registry mutex poisoned")
        .get(path)
        .map(|c| c.peak)
        .unwrap_or(0)
}

/// Test/measurement helper: rebase the peak to the current live count, so a
/// test can isolate the peak it observes to just the window it cares about.
pub fn reset_writer_connection_peak(path: &Path) {
    let mut reg = registry().lock().expect("writer registry mutex poisoned");
    if let Some(counts) = reg.get_mut(path) {
        counts.peak = counts.current;
    }
}

// ---------------------------------------------------------------------
// WriterHandle
// ---------------------------------------------------------------------

type Job<S> = Box<dyn FnOnce(&S) + Send>;

/// The process's single writer queue for one database path. Cloning a
/// `WriterHandle` clones the channel sender only -- every clone still
/// serializes onto the same dedicated writer thread, which is the only
/// place the underlying `Conn`/`S` ever lives.
pub struct WriterHandle<S> {
    tx: mpsc::Sender<Job<S>>,
}

impl<S> Clone for WriterHandle<S> {
    fn clone(&self) -> Self {
        WriterHandle { tx: self.tx.clone() }
    }
}

impl<S: 'static> WriterHandle<S> {
    /// Spawn the dedicated writer thread: open one writable `Conn` on
    /// `db_path`, hand it to `build` (so callers can wrap it in a richer
    /// handle -- e.g. `FrankenStorage` -- without that type ever leaving the
    /// thread), then serve `submit` jobs off the channel until every
    /// `WriterHandle` clone (and this call's own copy) is dropped.
    ///
    /// Returns the handle plus a `JoinHandle` so callers that need
    /// deterministic teardown (tests, or an explicit end-of-run flush) can
    /// wait for the connection to actually close before asserting on the
    /// registry counters.
    /// `S` deliberately carries no `Send` bound here: it is constructed
    /// inside the spawned thread and never leaves it (the thread closure's
    /// own return type is `()`, not `S`) -- only the boxed `Job<S>`
    /// closures crossing the channel need to be `Send`, and they are, by
    /// construction, independent of `S`'s own Send-ness. This is exactly
    /// what lets `S = Conn` work even though `Conn` (wrapping the franken
    /// backend's `Rc<RefCell<_>>` state) is structurally `!Send` until B8.
    pub fn spawn<F>(
        db_path: PathBuf,
        profile: Profile,
        build: F,
    ) -> Result<(WriterHandle<S>, JoinHandle<()>), StorageError>
    where
        F: FnOnce(Conn) -> Result<S, StorageError> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel::<Job<S>>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), StorageError>>();

        let join = std::thread::Builder::new()
            .name("cass-writer".to_string())
            .spawn(move || {
                let storage = match Conn::open_writable(&db_path, profile).and_then(build) {
                    Ok(storage) => storage,
                    Err(err) => {
                        let _ = ready_tx.send(Err(err));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                for job in rx {
                    job(&storage);
                }
                // `storage` (and the `Conn` it owns) drops here, releasing
                // the writer-registry guard.
            })
            .map_err(|err| StorageError::Other {
                code: None,
                detail: format!("spawning cass writer thread: {err}"),
            })?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok((WriterHandle { tx }, join)),
            Ok(Err(err)) => {
                let _ = join.join();
                Err(err)
            }
            Err(_) => {
                let _ = join.join();
                Err(StorageError::Other {
                    code: None,
                    detail: "cass writer thread exited before signaling ready".to_string(),
                })
            }
        }
    }

    /// Submit a closure to run on the writer thread against the shared
    /// `S`, and block for its result. Every call across every clone of this
    /// handle is serialized by the single channel + single consumer thread
    /// -- there is no lock to contend, so a caller never observes
    /// `StorageError::Busy` from another in-process writer.
    pub fn submit<T, F>(&self, f: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(&S) -> Result<T, StorageError> + Send + 'static,
    {
        let (result_tx, result_rx) = mpsc::channel::<Result<T, StorageError>>();
        let job: Job<S> = Box::new(move |storage| {
            let _ = result_tx.send(f(storage));
        });
        self.tx.send(job).map_err(|_| StorageError::Other {
            code: None,
            detail: "cass writer thread is gone".to_string(),
        })?;
        result_rx.recv().map_err(|_| StorageError::Other {
            code: None,
            detail: "cass writer thread dropped the job without responding".to_string(),
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::api::params;

    fn spawn_test_writer(path: &Path) -> (WriterHandle<Conn>, JoinHandle<()>) {
        WriterHandle::spawn(path.to_path_buf(), Profile::Production, Ok).expect("spawn writer")
    }

    /// B4 Step 2 assertion ①: 8 threads submit through the same
    /// `WriterHandle`, together inserting exactly 1000 rows. Every insert
    /// lands (no lost writes from racing on the connection) and none of
    /// them ever see `StorageError::Busy` -- there is structurally only one
    /// thread ever touching the connection, so SQLite-level lock
    /// contention cannot occur.
    #[test]
    fn eight_threads_via_writer_handle_insert_1000_rows_with_zero_busy() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_path = dir.path().join("writer-handle-concurrency.db");
        let (handle, join) = spawn_test_writer(&db_path);

        handle
            .submit(|conn| {
                conn.execute_batch(
                    "CREATE TABLE rows_t (id INTEGER PRIMARY KEY, thread_idx INTEGER NOT NULL, seq INTEGER NOT NULL);",
                )
            })
            .expect("create table");

        const THREADS: usize = 8;
        const ROWS_PER_THREAD: usize = 125; // 8 * 125 == 1000
        let mut worker_handles = Vec::with_capacity(THREADS);
        for thread_idx in 0..THREADS {
            let handle = handle.clone();
            worker_handles.push(std::thread::spawn(move || {
                let mut busy_hits = 0usize;
                for seq in 0..ROWS_PER_THREAD {
                    let result = handle.submit(move |conn: &Conn| {
                        conn.execute(
                            "INSERT INTO rows_t (thread_idx, seq) VALUES (?1, ?2)",
                            &params![thread_idx as i64, seq as i64],
                        )
                    });
                    if matches!(result, Err(StorageError::Busy { .. })) {
                        busy_hits += 1;
                    } else {
                        result.expect("insert via WriterHandle");
                    }
                }
                busy_hits
            }));
        }

        let total_busy: usize = worker_handles
            .into_iter()
            .map(|h| h.join().expect("worker thread panicked"))
            .sum();
        assert_eq!(total_busy, 0, "single-writer queue must never surface Busy to a submitter");

        let row_count: i64 = handle
            .submit(|conn| conn.query_row_map("SELECT COUNT(*) FROM rows_t", &[], |row| row.get_typed::<i64>(0)))
            .expect("count rows");
        assert_eq!(row_count, 1000, "exactly 1000 rows must land, no more, no fewer");

        drop(handle);
        join.join().expect("writer thread teardown");
    }

    /// The registry the WriterHandle above relies on: a single spawn+submit
    /// session never observes more than 1 live writer connection on the
    /// path it owns.
    #[test]
    fn writer_handle_never_exceeds_one_live_connection_on_its_path() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_path = dir.path().join("writer-handle-peak.db");
        reset_writer_connection_peak(&db_path);
        let (handle, join) = spawn_test_writer(&db_path);

        let mut worker_handles = Vec::new();
        for _ in 0..8 {
            let handle = handle.clone();
            worker_handles.push(std::thread::spawn(move || {
                for _ in 0..20 {
                    handle
                        .submit(|conn: &Conn| conn.execute_batch("SELECT 1;"))
                        .expect("noop submit");
                }
            }));
        }
        for h in worker_handles {
            h.join().expect("worker thread panicked");
        }

        assert_eq!(writer_connection_peak(&db_path), 1);
        drop(handle);
        join.join().expect("writer thread teardown");
        assert_eq!(writer_connection_count(&db_path), 0, "connection must be closed after teardown");
    }
}
