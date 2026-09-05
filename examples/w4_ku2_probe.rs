//! T10 (plan v5.1): `w4_ku2_probe` -- KU2 latency probe re-pointed at the
//! chunk-domain `vec0` index (`message_chunks`/`vec_index_gen_<id>`)
//! instead of the retired v4 `message_embeddings`/`vec_index_gen_<id>`
//! scaffold this replaces (no dedicated W3 scaffold source file was found in
//! this worktree to literally "re-point" -- this is a from-scratch
//! reimplementation of the same measurement shape the module doc comment on
//! `src/storage/vector_domain.rs` describes: "KU2 basis: probe/sqlite-vec-
//! eval @969c29b9 ... scan max 1.73s@2s 阈").
//!
//! Methodology (interface's "cold x3 / hot x3" read literally as two
//! measurement phases, not two separate reported distributions -- the
//! interface asks for one printed `p50/p95/mean/max` block): sample 64
//! stored chunk vectors from the active generation by an even stride
//! (`ROW_NUMBER() OVER (ORDER BY chunk_id) - 1) % stride = 0`, so the
//! sample spans the whole table rather than clustering at one end); run
//! each of the 64 vectors through a `k=40` `vec0` KNN scan, 3 times over a
//! freshly-reopened read-only connection each rep ("cold": no warm
//! statement/page cache carried from a prior rep) and 3 times over one
//! connection kept open across all three reps ("hot": statement cache and
//! OS page cache both warm from the immediately preceding rep) -- 6 * 64 =
//! 384 individual per-query timings total, pooled into one latency
//! distribution.
//!
//! Usage: `CASS_DATA_DIR=<dir containing agent_search.db> cargo run
//! --release --no-default-features --features qr,encryption,infinity
//! --example w4_ku2_probe -- --json <out>`. Exit codes: 0 `max <= 2.0s`; 1
//! `max > 2.0s` (real latency regression); 2 precondition error (db
//! missing, no active generation, or the active generation has zero
//! chunks to sample).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use coding_agent_search::storage::schema::le_blob_to_f32_vector;
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::vector_domain::vec0_knn;
use serde::Serialize;

const SAMPLE_COUNT: i64 = 64;
const K: usize = 40;
const COLD_REPS: usize = 3;
const HOT_REPS: usize = 3;
const MAX_LATENCY_GATE: Duration = Duration::from_secs(2);

#[derive(Parser, Debug)]
#[command(name = "w4_ku2_probe")]
struct Cli {
    #[arg(long)]
    json: PathBuf,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct Ku2Report {
    samples: usize,
    k: usize,
    generation_id: i64,
    p50_ms: f64,
    p95_ms: f64,
    mean_ms: f64,
    max_ms: f64,
    passed: bool,
}

fn active_generation(storage: &FrankenStorage) -> anyhow::Result<(i64, i64)> {
    let row: (i64, i64) = storage.raw().query_row_map(
        "SELECT id, dim FROM embedding_generations WHERE is_active = 1",
        &[],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
    )?;
    Ok(row)
}

fn sample_stride_vectors(storage: &FrankenStorage, generation_id: i64, sample_count: i64) -> anyhow::Result<Vec<Vec<f32>>> {
    let total: i64 = storage.raw().query_row_map(
        "SELECT COUNT(*) FROM message_chunks WHERE generation_id = ?1",
        &[coding_agent_search::storage::api::Value::from(generation_id)],
        |row| row.get_typed(0),
    )?;
    anyhow::ensure!(total > 0, "active generation {generation_id} has zero message_chunks rows to sample");

    let stride = (total / sample_count).max(1);
    let blobs: Vec<Vec<u8>> = storage.raw().query_all_map(
        "WITH ranked AS ( \
             SELECT embedding, ROW_NUMBER() OVER (ORDER BY chunk_id) - 1 AS rn \
             FROM message_chunks WHERE generation_id = ?1 \
         ) \
         SELECT embedding FROM ranked WHERE rn % ?2 = 0 ORDER BY rn LIMIT ?3",
        &[
            coding_agent_search::storage::api::Value::from(generation_id),
            coding_agent_search::storage::api::Value::from(stride),
            coding_agent_search::storage::api::Value::from(sample_count),
        ],
        |row| row.get_typed(0),
    )?;
    anyhow::ensure!(!blobs.is_empty(), "stride sampling produced zero vectors (total={total}, stride={stride})");

    blobs.iter().map(|b| le_blob_to_f32_vector(b).map_err(anyhow::Error::from)).collect()
}

fn timed_knn_sweep(storage: &FrankenStorage, generation_id: i64, queries: &[Vec<f32>], out: &mut Vec<Duration>) -> anyhow::Result<()> {
    for q in queries {
        let t0 = Instant::now();
        vec0_knn(storage.raw(), generation_id, q, K)?;
        out.push(t0.elapsed());
    }
    Ok(())
}

fn percentile_ms(sorted_ms: &[f64], p: f64) -> f64 {
    if sorted_ms.is_empty() {
        return 0.0;
    }
    let rank = ((p * sorted_ms.len() as f64).ceil() as usize).clamp(1, sorted_ms.len());
    sorted_ms[rank - 1]
}

fn run_probe(db_path: &Path) -> anyhow::Result<Ku2Report> {
    let storage = FrankenStorage::open_readonly(db_path)?;
    let (generation_id, _dim) = active_generation(&storage)?;
    let queries = sample_stride_vectors(&storage, generation_id, SAMPLE_COUNT)?;

    let mut timings: Vec<Duration> = Vec::with_capacity((COLD_REPS + HOT_REPS) * queries.len());

    for _ in 0..COLD_REPS {
        let cold_storage = FrankenStorage::open_readonly(db_path)?;
        timed_knn_sweep(&cold_storage, generation_id, &queries, &mut timings)?;
    }

    let hot_storage = FrankenStorage::open_readonly(db_path)?;
    for _ in 0..HOT_REPS {
        timed_knn_sweep(&hot_storage, generation_id, &queries, &mut timings)?;
    }

    let mut ms: Vec<f64> = timings.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean_ms = ms.iter().sum::<f64>() / ms.len() as f64;
    let max_ms = *ms.last().unwrap();
    let passed = timings.iter().all(|d| *d <= MAX_LATENCY_GATE);

    Ok(Ku2Report {
        samples: ms.len(),
        k: K,
        generation_id,
        p50_ms: percentile_ms(&ms, 0.50),
        p95_ms: percentile_ms(&ms, 0.95),
        mean_ms,
        max_ms,
        passed,
    })
}

fn run(db_path: &Path) -> (i32, Option<Ku2Report>, String) {
    if !db_path.is_file() {
        return (2, None, format!("precondition error: db {} does not exist", db_path.display()));
    }
    match run_probe(db_path) {
        Err(e) => (2, None, format!("precondition error: {e:#}")),
        Ok(report) => {
            let code = if report.passed { 0 } else { 1 };
            let msg = format!(
                "ku2_probe: samples={} k={} p50={:.1}ms p95={:.1}ms mean={:.1}ms max={:.1}ms passed={} (gate: max <= 2000ms)",
                report.samples, report.k, report.p50_ms, report.p95_ms, report.mean_ms, report.max_ms, report.passed
            );
            (code, Some(report), msg)
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let db_path = coding_agent_search::default_db_path();
    let (code, report, message) = run(&db_path);
    println!("{message}");
    if let Some(report) = &report {
        let json = serde_json::to_string_pretty(report).expect("Ku2Report must serialize");
        std::fs::write(&cli.json, json).expect("writing --json output must succeed");
    }
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use coding_agent_search::storage::api::{TxMode, Value};
    use coding_agent_search::storage::schema;
    use coding_agent_search::storage::vector_domain;
    use tempfile::TempDir;

    fn insert_message_parent_chain(storage: &FrankenStorage, agent_id: i64, conversation_id: i64, message_id: i64) {
        let conn = storage.raw();
        conn.execute(
            "INSERT OR IGNORE INTO agents(id, slug, name, kind, created_at, updated_at) VALUES (?1, ?2, ?2, 'cli', 0, 0)",
            &[Value::from(agent_id), Value::from(format!("agent-{agent_id}"))],
        )
        .unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO conversations(id, agent_id, title, source_path) VALUES (?1, ?2, 't', ?3)",
            &[Value::from(conversation_id), Value::from(agent_id), Value::from(format!("/tmp/c-{conversation_id}.jsonl"))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages(id, conversation_id, idx, role, content) VALUES (?1, ?2, ?1, 'user', 'c')",
            &[Value::from(message_id), Value::from(conversation_id)],
        )
        .unwrap();
    }

    /// Builds a tiny synthetic v5 db with an active generation and 200
    /// chunk-domain vectors (dim=4, so KNN math is trivially checkable) --
    /// enough for stride sampling to exercise real distinct rows, small
    /// enough to run in milliseconds.
    fn build_synthetic_v5_db(path: &Path, n_chunks: i64) -> i64 {
        let storage = FrankenStorage::open(path).unwrap();
        insert_message_parent_chain(&storage, 1, 1, 1);
        let generation_id = storage
            .raw()
            .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation_v5(tx, "bge-m3", 4, 1, 1, b"fp", 1))
            .unwrap();
        storage
            .raw()
            .execute(
                "UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1",
                &[Value::from(generation_id)],
            )
            .unwrap();

        storage
            .raw()
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                for i in 0..n_chunks {
                    let v = [1.0, i as f32 * 0.001, 0.0, 0.0];
                    let blob = schema::f32_vector_to_le_blob(&v);
                    tx.execute(
                        "INSERT INTO message_chunks(chunk_id, generation_id, message_id, conversation_id, chunk_idx, \
                         byte_start, byte_end, content_hash, embedding, norm, created_at) \
                         VALUES (?1, ?2, 1, 1, ?3, 0, 1, ?4, ?5, 1.0, 1000)",
                        &[
                            Value::from(i + 1),
                            Value::from(generation_id),
                            Value::from(i),
                            Value::from(format!("hash-{i}")),
                            Value::from(blob),
                        ],
                    )?;
                }
                Ok(())
            })
            .unwrap();

        vector_domain::rebuild_vec0_table_for_generation_v5(storage.raw(), generation_id, 4).unwrap();
        generation_id
    }

    #[test]
    fn probe_runs_and_passes_on_a_tiny_synthetic_db() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("agent_search.db");
        let generation_id = build_synthetic_v5_db(&db_path, 200);

        let (code, report, message) = run(&db_path);
        assert_eq!(code, 0, "a tiny in-memory-scale KNN probe must pass the 2.0s gate: {message}");
        let report = report.unwrap();
        assert_eq!(report.generation_id, generation_id);
        assert_eq!(report.k, 40);
        assert_eq!(report.samples, 64 * 6, "3 cold + 3 hot reps * 64 sampled vectors");
        assert!(report.max_ms < 2000.0);
        assert!(report.p50_ms <= report.p95_ms);
        assert!(report.p95_ms <= report.max_ms);
    }

    #[test]
    fn missing_db_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("does-not-exist.db");
        let (code, report, message) = run(&db_path);
        assert_eq!(code, 2, "missing db must be a precondition error: {message}");
        assert!(report.is_none());
    }

    #[test]
    fn no_active_generation_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("agent_search.db");
        FrankenStorage::open(&db_path).unwrap(); // fresh v5 schema, no generation created

        let (code, report, message) = run(&db_path);
        assert_eq!(code, 2, "no active generation must be a precondition error: {message}");
        assert!(report.is_none());
    }
}
