//! Stress tests for cass's write path under realistic concurrent workloads.
//!
//! w1b Task B4 (secondary contract #4, 2026-08-26): this file used to stress
//! the legacy embedded engine's `BEGIN CONCURRENT` (MVCC) mode -- N real writer
//! connections racing on the same rows, with retry-on-conflict loops. B4
//! retires the capability to have more than 1 live writer connection on a
//! path at all (`storage::api::WriterHandle` serializes every write through
//! a single dedicated thread), so every test below is rewritten to the
//! standard-SQLite-concurrency shape: many threads submit work through one
//! `WriterHandle`, real reader threads run against independent read-only
//! connections, and correctness is proven by exact counts (serialization
//! means nothing is ever lost *or* retried away) rather than "at least N
//! survived contention". The MVCC-specific assertions this replaces are
//! recorded in the closed-world human-review checklist,
//! `w1b-b4-write-topology-inventory.md` §⑥.
//!
//! Bead: coding_agent_session_search-2tax6

use coding_agent_search::storage::api::{Conn as Connection, Profile, WriterHandle};
use coding_agent_search::storage::sqlite::FrankenStorage;

/// Test-only parameter list builder (this integration test is a separate
/// crate and can't reach `storage::api`'s crate-private `params!` shim):
/// borrows + handles the zero-arg case, mirroring sqlite.rs's own `fparams!`.
macro_rules! fparams {
    () => {
        &[] as &[coding_agent_search::storage::api::Value]
    };
    ($($val:expr),+ $(,)?) => {
        &[$(coding_agent_search::storage::api::IntoValue::into_value($val)),+]
            as &[coding_agent_search::storage::api::Value]
    };
}
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Create a cass-schema DB (via storage::api).
fn setup_db(dir: &TempDir) -> std::path::PathBuf {
    let db_path = dir.path().join("stress.db");
    let fs = FrankenStorage::open(&db_path).expect("create cass db");
    drop(fs);
    db_path
}

/// Create a DB with cass's schema plus a simple ad-hoc table for raw
/// concurrency tests. Stage A note: `storage::api::Conn::open_writable` is
/// deliberately crate-private (R2-F3 — the only public path to a writable
/// `Conn` at a real path is via `FrankenStorage`), so this integration test
/// (a separate crate) bootstraps through `FrankenStorage::open` +
/// `into_raw()` rather than opening a bare, schema-free connection the way
/// the pre-migration native-`legacy-engine` version of this helper did. The
/// extra cass tables don't collide with `items`/`counter`/`cm_stress` and
/// don't affect the concurrency behavior under test.
/// Sets WAL mode and busy_timeout — required for concurrent reads.
fn setup_simple_db(dir: &TempDir) -> std::path::PathBuf {
    let db_path = dir.path().join("simple.db");
    let conn = FrankenStorage::open(&db_path).unwrap().into_raw();
    conn.execute("PRAGMA journal_mode = WAL;", &[]).unwrap();
    conn.execute("PRAGMA synchronous = NORMAL;", &[]).unwrap();
    conn.execute("PRAGMA busy_timeout = 5000;", &[]).unwrap();
    conn.execute(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, thread_id INTEGER, seq INTEGER, val TEXT)",
        &[],
    )
    .unwrap();
    conn.execute("CREATE INDEX idx_items_thread ON items(thread_id)", &[])
        .unwrap();
    drop(conn);
    db_path
}

/// Open a genuinely read-only connection with proper WAL/busy_timeout
/// config, for the reader side of read-write mix tests. WAL mode is a
/// database-level setting (already turned on by whichever connection
/// created the file), but busy_timeout is per-connection.
fn open_read_configured(path: &std::path::Path) -> Connection {
    let conn = Connection::open_read(path).unwrap();
    let _ = conn.execute_batch("PRAGMA busy_timeout = 5000;");
    conn
}

// ============================================================================
// 1. PARALLEL CONNECTOR WRITES
// ============================================================================

#[test]
fn stress_parallel_connector_writes() {
    let dir = TempDir::new().unwrap();
    let db_path = setup_db(&dir);

    // w1b Task B4: N threads submit through one WriterHandle instead of
    // each acquiring their own `concurrent_writer()` from a
    // `FrankenConnectionManager` pool. Serialization means every insert
    // lands exactly once -- no conflicts, no retries, no "at least N".
    let (handle, join) =
        WriterHandle::<Connection>::spawn(db_path, Profile::Production, Ok).expect("spawn writer");

    handle
        .submit(|conn: &Connection| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, thread_id INTEGER, seq INTEGER, val TEXT)",
            )
        })
        .unwrap();

    let num_threads = 4;
    let writes_per_thread = 100;

    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for thread_id in 0..num_threads {
            let h = handle.clone();
            handles.push(s.spawn(move || {
                for seq in 0..writes_per_thread {
                    let val = format!("thread-{thread_id}-seq-{seq}");
                    h.submit(move |conn: &Connection| {
                        conn.execute(
                            "INSERT INTO items (thread_id, seq, val) VALUES (?1, ?2, ?3)",
                            &fparams![thread_id, seq, val.as_str()],
                        )
                    })
                    .expect("insert via WriterHandle should succeed");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    });

    let count: i64 = handle
        .submit(|conn: &Connection| conn.query_row_map("SELECT COUNT(*) FROM items", &[], |row| row.get_typed(0)))
        .unwrap();
    let expected = (num_threads * writes_per_thread) as i64;
    assert_eq!(
        count, expected,
        "single-writer serialization must land every row exactly once"
    );

    drop(handle);
    join.join().expect("writer thread teardown");
    eprintln!("Parallel write: {count} total (expected {expected})");
}

// ============================================================================
// 2. WRITE-HEAVY CONTENTION
// ============================================================================

#[test]
fn stress_write_heavy_contention() {
    let dir = TempDir::new().unwrap();
    let db_path = setup_db(&dir);

    // Models the production par_chunks pattern: each thread batches
    // multiple rows per transaction, reducing the number of submit round
    // trips through the writer. 4 threads × 20 batches × 10 rows = 800
    // total rows, all serialized through one WriterHandle.
    let (handle, join) =
        WriterHandle::<Connection>::spawn(db_path, Profile::Production, Ok).expect("spawn writer");

    handle
        .submit(|conn: &Connection| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, thread_id INTEGER, seq INTEGER, val TEXT)",
            )
        })
        .unwrap();

    let num_threads = 4;
    let batches_per_thread = 20;
    let rows_per_batch = 10;

    let start = Instant::now();

    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for thread_id in 0..num_threads {
            let h = handle.clone();
            handles.push(s.spawn(move || {
                for batch in 0..batches_per_thread {
                    h.submit(move |conn: &Connection| {
                        let tx = conn.transaction()?;
                        for row_in_batch in 0..rows_per_batch {
                            let seq = batch * rows_per_batch + row_in_batch;
                            // Unique id per thread and seq to avoid auto-increment collisions.
                            let unique_id = (thread_id * 100_000) + seq;
                            tx.execute(
                                "INSERT INTO items (id, thread_id, seq, val) VALUES (?1, ?2, ?3, 'contention')",
                                &fparams![unique_id, thread_id, seq],
                            )?;
                        }
                        tx.commit()
                    })
                    .expect("batch insert via WriterHandle should succeed");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    });

    let elapsed = start.elapsed();
    let expected = (num_threads * batches_per_thread * rows_per_batch) as i64;

    let count: i64 = handle
        .submit(|conn: &Connection| conn.query_row_map("SELECT COUNT(*) FROM items", &[], |row| row.get_typed(0)))
        .unwrap();
    let per_thread: Vec<(i64, i64)> = handle
        .submit(|conn: &Connection| {
            conn.query_all_map("SELECT thread_id, COUNT(*) FROM items GROUP BY thread_id", &[], |row| {
                Ok((row.get_typed(0)?, row.get_typed(1)?))
            })
        })
        .unwrap();
    for (tid, cnt) in &per_thread {
        assert_eq!(
            *cnt, batches_per_thread as i64 * rows_per_batch as i64,
            "thread {tid} should have inserted every one of its rows exactly once"
        );
    }

    assert_eq!(
        count, expected,
        "single-writer serialization must land every batched row exactly once"
    );

    drop(handle);
    join.join().expect("writer thread teardown");
    let throughput = count as f64 / elapsed.as_secs_f64();
    eprintln!(
        "Write contention: {count} rows in {:.2}s ({:.0} rows/sec)",
        elapsed.as_secs_f64(),
        throughput
    );
}

// ============================================================================
// 3. READ-WRITE MIX (TUI + indexer simulation)
// ============================================================================

#[test]
fn stress_read_write_mix() {
    let dir = TempDir::new().unwrap();
    let db_path = setup_simple_db(&dir);

    let (handle, join) =
        WriterHandle::<Connection>::spawn(db_path.clone(), Profile::Production, Ok).expect("spawn writer");

    let duration = Duration::from_secs(3);
    let read_count = Arc::new(AtomicUsize::new(0));
    let read_errors = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|s| {
        // 4 writer threads, all submitting through the one WriterHandle --
        // this is exactly the "TUI reads + indexer writes" scenario the
        // pre-B4 `FrankenConnectionManager` doc comment described, now
        // modeled with the architecture that actually enforces it.
        for thread_id in 0..4 {
            let h = handle.clone();
            s.spawn(move || {
                let start = Instant::now();
                let mut seq = 0;
                while start.elapsed() < duration {
                    h.submit(move |conn: &Connection| {
                        conn.execute(
                            "INSERT INTO items (thread_id, seq, val) VALUES (?1, ?2, 'rw-mix')",
                            &fparams![thread_id, seq],
                        )
                    })
                    .expect("insert via WriterHandle should succeed");
                    seq += 1;
                }
            });
        }

        // 4 reader threads, each on its own independent read-only
        // connection -- concurrent reads never contend with the single
        // writer thread under WAL.
        for _reader_id in 0..4 {
            let path = db_path.clone();
            let reads = Arc::clone(&read_count);
            let errors = Arc::clone(&read_errors);
            s.spawn(move || {
                let conn = open_read_configured(&path);
                let start = Instant::now();
                while start.elapsed() < duration {
                    match conn.query_row_map("SELECT COUNT(*) FROM items", &[], |row| row.get_typed::<i64>(0)) {
                        Ok(_count) => {
                            reads.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    std::thread::yield_now();
                }
            });
        }
    });

    let total_reads = read_count.load(Ordering::Relaxed);
    let total_read_errors = read_errors.load(Ordering::Relaxed);

    let final_count: i64 = handle
        .submit(|conn: &Connection| conn.query_row_map("SELECT COUNT(*) FROM items", &[], |row| row.get_typed(0)))
        .unwrap();
    assert!(final_count > 0, "writers should have committed rows");
    assert!(total_reads > 0, "readers should have completed queries");
    assert_eq!(
        total_read_errors, 0,
        "concurrent reads against the single writer must never error"
    );

    let integrity_rows: Vec<(i64, i64, String)> = handle
        .submit(|conn: &Connection| {
            conn.query_all_map(
                "SELECT thread_id, seq, val FROM items ORDER BY thread_id, seq",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
            )
        })
        .unwrap();
    for (tid, seq, val) in &integrity_rows {
        assert!((0..4).contains(tid), "thread_id {tid} should be 0..3");
        assert!(*seq >= 0, "seq should be non-negative");
        assert_eq!(val, "rw-mix", "val should be 'rw-mix'");
    }

    for thread_id in 0..4 {
        let thread_count: i64 = handle
            .submit(move |conn: &Connection| {
                conn.query_row_map("SELECT COUNT(*) FROM items WHERE thread_id = ?1", &fparams![thread_id], |row| {
                    row.get_typed(0)
                })
            })
            .unwrap();
        assert!(thread_count > 0, "thread {thread_id} should have written at least 1 row");
    }

    drop(handle);
    join.join().expect("writer thread teardown");
    eprintln!(
        "Read-write mix ({:.1}s): {final_count} final rows, {total_reads} reads, {total_read_errors} read errors",
        duration.as_secs_f64(),
    );
}

// ============================================================================
// 4. UNCOMMITTED-TRANSACTION ROLLBACK ON DROP
// ============================================================================

#[test]
fn stress_crash_recovery_uncommitted_data_absent() {
    let dir = TempDir::new().unwrap();
    let db_path = setup_simple_db(&dir);

    // Commit some data first.
    {
        let conn = FrankenStorage::open(&db_path).unwrap().into_raw();
        let tx = conn.transaction().unwrap();
        tx.execute("INSERT INTO items (thread_id, seq, val) VALUES (0, 0, 'committed')", &[])
            .unwrap();
        tx.commit().unwrap();
    }

    // Begin a standard transaction but DO NOT commit -- drop the guard.
    // w1b Task B4: previously issued literal `BEGIN CONCURRENT` (the legacy embedded engine's
    // MVCC syntax); rewritten to a standard transaction, since the property
    // under test -- an uncommitted transaction leaves no trace once dropped
    // -- is not MVCC-specific.
    {
        let conn = FrankenStorage::open(&db_path).unwrap().into_raw();
        let tx = conn.transaction().unwrap();
        tx.execute("INSERT INTO items (thread_id, seq, val) VALUES (1, 0, 'uncommitted')", &[])
            .unwrap();
        // `tx` (and then `conn`) drop here without `commit()` — Tx's Drop
        // does a best-effort rollback.
    }

    // Verify only committed data exists.
    let conn = FrankenStorage::open(&db_path).unwrap().into_raw();
    let count: i64 = conn.query_row_map("SELECT COUNT(*) FROM items", &[], |row| row.get_typed(0)).unwrap();
    assert_eq!(count, 1, "only committed row should exist");

    let first_val: String = conn.query_row_map("SELECT val FROM items", &[], |row| row.get_typed(0)).unwrap();
    assert_eq!(first_val, "committed", "only committed data should be present");
}

// ============================================================================
// 5. LARGE TRANSACTION
// ============================================================================

#[test]
fn stress_large_transaction() {
    let dir = TempDir::new().unwrap();
    let db_path = setup_simple_db(&dir);

    let num_rows = 10_000; // Reduced from 100K for test speed
    let start = Instant::now();

    {
        let conn = FrankenStorage::open(&db_path).unwrap().into_raw();
        let tx = conn.transaction().unwrap();

        for i in 0..num_rows {
            let val = format!("large-txn-row-{i}");
            tx.execute(
                "INSERT INTO items (thread_id, seq, val) VALUES (0, ?1, ?2)",
                &fparams![i, val.as_str()],
            )
            .unwrap();
        }

        tx.commit().unwrap();
    }

    let commit_time = start.elapsed();

    // Verify all rows present.
    let conn = FrankenStorage::open(&db_path).unwrap().into_raw();
    let count: i64 = conn.query_row_map("SELECT COUNT(*) FROM items", &[], |row| row.get_typed(0)).unwrap();
    assert_eq!(count, num_rows, "all {num_rows} rows should be present");

    eprintln!("Large transaction: {num_rows} rows committed in {:.2}s", commit_time.as_secs_f64());
    assert!(commit_time < Duration::from_secs(30), "large transaction should complete within 30 seconds");
}

// ============================================================================
// 6. SERIALIZED INCREMENTS UNDER CONTENTION (no retries needed)
// ============================================================================

#[test]
fn stress_writer_handle_serializes_conflicting_increments() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("conflict.db");

    // w1b Task B4: previously N threads each opened their own connection
    // and raced an optimistic read-modify-write loop against the same
    // counter row, retrying on conflict (the MVCC-specific behavior this
    // file was built to stress). Under `WriterHandle` there is structurally
    // only one thread ever touching the connection, so the same workload
    // can never conflict -- there is nothing to retry, and no increment can
    // ever be lost to a race.
    let (handle, join) =
        WriterHandle::<Connection>::spawn(db_path, Profile::Production, Ok).expect("spawn writer");

    handle
        .submit(|conn: &Connection| {
            conn.execute_batch(
                "CREATE TABLE counter (id INTEGER PRIMARY KEY, val INTEGER); \
                 INSERT INTO counter (id, val) VALUES (1, 0);",
            )
        })
        .unwrap();

    let num_threads = 4;
    let increments_per_thread = 50;
    let unexpected_errors = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for _thread_id in 0..num_threads {
            let h = handle.clone();
            let unexpected = Arc::clone(&unexpected_errors);
            handles.push(s.spawn(move || {
                for _ in 0..increments_per_thread {
                    let result = h.submit(|conn: &Connection| {
                        let tx = conn.transaction()?;
                        let current: i64 =
                            tx.query_row_map("SELECT val FROM counter WHERE id = 1", &[], |row| row.get_typed(0))?;
                        tx.execute("UPDATE counter SET val = ?1 WHERE id = 1", &fparams![current + 1])?;
                        tx.commit()
                    });
                    if result.is_err() {
                        unexpected.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    });

    assert_eq!(
        unexpected_errors.load(Ordering::Relaxed),
        0,
        "WriterHandle must never surface an error under pure write contention"
    );

    let final_val: i64 = handle
        .submit(|conn: &Connection| conn.query_row_map("SELECT val FROM counter WHERE id = 1", &[], |row| row.get_typed(0)))
        .unwrap();
    let expected = (num_threads * increments_per_thread) as i64;
    assert_eq!(
        final_val, expected,
        "structural serialization means every increment lands with zero retries and zero lost updates"
    );

    drop(handle);
    join.join().expect("writer thread teardown");
    eprintln!("Serialized increments: final={final_val}, expected={expected}, unexpected_errors=0");
}

// ============================================================================
// 7. MANY SUBMITTERS, ONE WRITER (replaces the old ConnectionManager stress)
// ============================================================================

/// w1b Task B4 (write-topology inventory §⑥, closed-world review item 3):
/// the old `stress_connection_manager_parallel_writers` asserted that
/// `FrankenConnectionManager` could genuinely open 4 concurrent writer
/// connections -- a capability B4 removes outright, not something to
/// "fix forward". This replacement proves the invariant that actually
/// matters post-B4: many submitter threads hammering `WriterHandle`
/// concurrently never push the live writer-connection count above 1, using
/// the same registry the B4 unit tests in `storage::api::writer` rely on.
#[test]
fn stress_writer_handle_many_submitters_never_exceed_one_connection() {
    let dir = TempDir::new().unwrap();
    let db_path = setup_db(&dir);
    coding_agent_search::storage::api::reset_writer_connection_peak(&db_path);

    let (handle, join) =
        WriterHandle::<Connection>::spawn(db_path.clone(), Profile::Production, Ok).expect("spawn writer");

    handle
        .submit(|conn: &Connection| {
            conn.execute_batch("CREATE TABLE IF NOT EXISTS cm_stress (id INTEGER PRIMARY KEY, tid INTEGER, val TEXT)")
        })
        .unwrap();

    let writes_per_thread = 50;

    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for tid in 0..4 {
            let h = handle.clone();
            handles.push(s.spawn(move || {
                for seq in 0..writes_per_thread {
                    let val = format!("cm-{tid}-{seq}");
                    h.submit(move |conn: &Connection| {
                        conn.execute("INSERT INTO cm_stress (tid, val) VALUES (?1, ?2)", &fparams![tid, val.as_str()])
                    })
                    .expect("cm write via WriterHandle should succeed");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    });

    let count: i64 = handle
        .submit(|conn: &Connection| conn.query_row_map("SELECT COUNT(*) FROM cm_stress", &[], |row| row.get_typed(0)))
        .unwrap();
    assert_eq!(count, (4 * writes_per_thread) as i64, "all writes should be persisted");
    assert_eq!(
        coding_agent_search::storage::api::writer_connection_peak(&db_path),
        1,
        "many submitters must never push the live writer-connection count above 1"
    );

    drop(handle);
    join.join().expect("writer thread teardown");
}
