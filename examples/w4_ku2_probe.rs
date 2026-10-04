//! T10 (plan v5.1): `w4_ku2_probe` -- KU2 latency probe re-pointed at the
//! chunk-domain `vec0` index (`message_chunks`/`vec_index_gen_<id>`)
//! instead of the retired v4 message-granularity/`vec_index_gen_<id>`
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
//! freshly-reopened read-only connection each rep ("new connection": no warm
//! statement/page cache carried from a prior rep) and 3 times over one
//! connection kept open across all three reps ("reused connection":
//! statement cache and OS page cache both warm from the immediately
//! preceding rep) -- 6 * 64 = 384 individual per-query timings total.
//!
//! PR9 task 01: the probe additionally reports what the merged block alone
//! cannot -- the identity and order of the 64 sampled query chunks, every
//! individual timing paired with the query it belongs to, and the same
//! summary block computed per phase. The merged `p50/p95/mean/max` block is
//! retained unchanged and is exactly reproducible from `timings`.
//!
//! PR9 task 10 (AC1): `--vector-search-mode exact|fast` selects which
//! **chunk-candidate** path the probe measures. This is still a candidate
//! probe, not a product query benchmark: it covers no embedding request, no
//! message fold, no relational filter, no RRF and none of the full CLI's
//! end-to-end cost. `exact` (the default) is the pre-existing float `vec0`
//! `k=40` scan and is unchanged, field for field; `fast` searches all eight
//! int8 shards at `k = 160` (40 * the product's fixed m=4 overfetch), reads
//! the authoritative float row for **every** candidate inside the same main
//! read snapshot, and re-sorts by `(distance asc, chunk_id asc)` before
//! keeping the top 40 -- the same math (`f32` decode, `f64` dot/norm
//! accumulation, `distance = 1 - dot/(norm_a*norm_b)`) the product's 09
//! fast path uses. Both modes sample and query the identical 64 stored
//! query BLOBs, so the two JSON files pair sample-for-sample. Each query's
//! timing covers everything that query actually does: query quantization,
//! worker connection + transaction, coarse scan, authoritative read and all
//! float rescoring.
//!
//! Usage: `CASS_DATA_DIR=<dir containing agent_search.db> cargo run
//! --release --no-default-features --features qr,encryption,infinity
//! --example w4_ku2_probe -- --json <out> [--vector-search-mode exact|fast]`.
//! Exit codes: 0 `max <= 2.0s`; 1 `max > 2.0s` (real latency regression); 2
//! precondition error (db missing, no active generation, the active
//! generation has zero chunks to sample, or the `fast` path found the int8
//! mirror unusable -- a shard snapshot that disagrees with the main read
//! snapshot, a missing/damaged mirror, or a candidate with no authoritative
//! float row).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use coding_agent_search::storage::api::{StorageError, TxMode, Value};
use coding_agent_search::storage::schema::le_blob_to_f32_vector;
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::vector_domain::{self, Int8Candidates, Vec0KnnHit, vec0_knn};
use serde::Serialize;
use sha2::{Digest, Sha256};

const SAMPLE_COUNT: i64 = 64;
const K: usize = 40;
const COLD_REPS: usize = 3;
const HOT_REPS: usize = 3;
const MAX_LATENCY_GATE: Duration = Duration::from_secs(2);

/// PR9 task 10 AC1: the product's fixed overfetch multiplier (spec v4.1
/// §3, `requested_coarse_k = fetch_limit * 4`). The `fast` probe searches
/// each int8 shard at `K * FAST_COARSE_MULTIPLIER`.
const FAST_COARSE_MULTIPLIER: usize = 4;
/// The per-shard coarse window the `fast` path asks each int8 shard for.
const FAST_SHARD_K: usize = K * FAST_COARSE_MULTIPLIER;
/// Authoritative float rows are read in bounded `IN (...)` batches, the
/// same batch size the product's 09 fast path uses.
const AUTHORITATIVE_BATCH_ROWS: usize = 500;

/// Label for the freshly-reopened-connection phase, and the JSON field name
/// carrying its summary.
const PHASE_NEW_CONNECTION: &str = "new_connection";
/// Label for the single-reused-connection phase, and the JSON field name
/// carrying its summary.
const PHASE_REUSED_CONNECTION: &str = "reused_connection";

/// PR9 task 10 AC1: which chunk-candidate path the probe measures. An
/// independent axis from the product's `--mode lexical|semantic|hybrid`
/// (this probe never runs lexical or hybrid at all).
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum VectorSearchMode {
    /// The pre-existing single float `vec0` `k=40` scan.
    Exact,
    /// Eight int8 shards at `k=160`, every candidate rescored against the
    /// authoritative float row, top 40 kept.
    Fast,
}

impl VectorSearchMode {
    fn label(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Fast => "fast",
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "w4_ku2_probe")]
struct Cli {
    #[arg(long)]
    json: PathBuf,
    /// PR9 task 10 AC1: `exact` keeps the original float `vec0` `k=40`
    /// scan; `fast` runs the eight-shard int8 coarse pass plus full
    /// authoritative-float rescoring. Defaults to `exact` so every earlier
    /// invocation of this probe keeps its exact original meaning.
    #[arg(long, value_enum, default_value_t = VectorSearchMode::Exact)]
    vector_search_mode: VectorSearchMode,
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
    /// PR9 task 10 AC1: which candidate path produced these samples.
    /// `exact` fields keep their original meaning; this is the only
    /// top-level field the mode change adds.
    vector_search_mode: String,
    /// The `chunk_id` of each sampled query vector, in the order the probe
    /// queries them. Length equals the number of distinct query vectors
    /// (64 when the active generation has at least `SAMPLE_COUNT * stride`
    /// rows to sample). Identical across both modes by construction: the
    /// sample is drawn from `message_chunks`, never from a mirror.
    query_chunk_ids: Vec<i64>,
    /// Summary over the `COLD_REPS` sweeps that each used a freshly-reopened
    /// read-only connection.
    new_connection: PhaseStats,
    /// Summary over the `HOT_REPS` sweeps that shared one open connection.
    reused_connection: PhaseStats,
    /// Every individual KNN timing, in execution order, carrying the query
    /// it belongs to and the chunk ids it returned.
    timings: Vec<QueryTiming>,
}

/// The original merged summary shape, computed over one phase's samples.
#[derive(Debug, Serialize, Clone, PartialEq)]
struct PhaseStats {
    samples: usize,
    p50_ms: f64,
    p95_ms: f64,
    mean_ms: f64,
    max_ms: f64,
}

/// One `k=40` KNN scan of one sampled query vector.
#[derive(Debug, Serialize, Clone, PartialEq)]
struct QueryTiming {
    /// One of `PHASE_NEW_CONNECTION` / `PHASE_REUSED_CONNECTION`.
    phase: &'static str,
    /// 0-based rep index within its phase.
    repetition: usize,
    /// 0-based index into `query_chunk_ids` -- the query this sample belongs to.
    sample_index: usize,
    /// `query_chunk_ids[sample_index]`, repeated so a single timing row is
    /// self-describing.
    chunk_id: i64,
    elapsed_ms: f64,
    /// The chunk ids the scan returned, in distance order.
    top_chunk_ids: Vec<i64>,
    /// PR9 task 10 AC1: `exact` / `fast`, repeated per sample so one timing
    /// row stays self-describing.
    vector_search_mode: &'static str,
    /// PR9 task 10 AC1: how many distinct chunk candidates the coarse pass
    /// handed to rescoring. Always `0` for `exact`, which never runs a
    /// coarse pass -- so no `exact` statistic changes meaning.
    coarse_rows_collected: usize,
    /// PR9 task 10 AC1: how many candidates were rescored against their
    /// authoritative float row. Always `0` for `exact`.
    float_rescore_rows: usize,
    /// PR9 task 10 AC1: SHA-256 of the stored authoritative f32 query BLOB
    /// (`message_chunks.embedding`) this sample used. Equal for the same
    /// `sample_index` in both modes -- that is the pairing key.
    query_f32_sha256: String,
}

/// One sampled query vector: its `chunk_id`, the decoded f32 components and
/// the SHA-256 of the exact stored BLOB those components came from.
struct SampledQuery {
    chunk_id: i64,
    vector: Vec<f32>,
    f32_sha256: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn active_generation(storage: &FrankenStorage) -> anyhow::Result<(i64, i64)> {
    let row: (i64, i64) = storage.raw().query_row_map(
        "SELECT id, dim FROM embedding_generations WHERE is_active = 1",
        &[],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
    )?;
    Ok(row)
}

fn sample_stride_vectors(storage: &FrankenStorage, generation_id: i64, sample_count: i64) -> anyhow::Result<Vec<SampledQuery>> {
    let total: i64 = storage.raw().query_row_map(
        "SELECT COUNT(*) FROM message_chunks WHERE generation_id = ?1",
        &[Value::from(generation_id)],
        |row| row.get_typed(0),
    )?;
    anyhow::ensure!(total > 0, "active generation {generation_id} has zero message_chunks rows to sample");

    let stride = (total / sample_count).max(1);
    let rows: Vec<(i64, Vec<u8>)> = storage.raw().query_all_map(
        "WITH ranked AS ( \
             SELECT chunk_id, embedding, ROW_NUMBER() OVER (ORDER BY chunk_id) - 1 AS rn \
             FROM message_chunks WHERE generation_id = ?1 \
         ) \
         SELECT chunk_id, embedding FROM ranked WHERE rn % ?2 = 0 ORDER BY rn LIMIT ?3",
        &[
            Value::from(generation_id),
            Value::from(stride),
            Value::from(sample_count),
        ],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
    )?;
    anyhow::ensure!(!rows.is_empty(), "stride sampling produced zero vectors (total={total}, stride={stride})");

    rows.into_iter()
        .map(|(chunk_id, blob)| {
            Ok(SampledQuery {
                chunk_id,
                vector: le_blob_to_f32_vector(&blob)?,
                f32_sha256: sha256_hex(&blob),
            })
        })
        .collect()
}

fn sql_placeholders(n: usize) -> String {
    vec!["?"; n].join(",")
}

/// The product's 09 float-rescoring math, replicated byte-for-byte
/// (`src/search/query.rs::cosine_distance`): decode the stored `f32`
/// components, accumulate dot and both norms in `f64`, and take
/// `1 - dot/(norm_a*norm_b)`.
fn cosine_distance_f64(a: &[f32], b: &[f32]) -> f64 {
    let dot: f64 = a.iter().zip(b).map(|(&x, &y)| f64::from(x) * f64::from(y)).sum();
    let norm_a: f64 = a.iter().map(|&x| f64::from(x) * f64::from(x)).sum::<f64>().sqrt();
    let norm_b: f64 = b.iter().map(|&x| f64::from(x) * f64::from(x)).sum::<f64>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        return 1.0;
    }
    1.0 - (dot / (norm_a * norm_b))
}

fn mirror_damaged(detail: &str) -> StorageError {
    StorageError::Other { code: None, detail: detail.to_string() }
}

/// PR9 task 10 AC1: the `fast` chunk-candidate path. One main read
/// transaction pins the database instance/generation snapshot, all eight
/// int8 shard workers are searched at `FAST_SHARD_K` against that same
/// snapshot, and every returned candidate's authoritative float row is read
/// back through the *same* transaction. Returns
/// `(top_k_by_distance_then_chunk_id, coarse_rows_collected,
/// float_rescore_rows)`.
///
/// A shard whose snapshot disagrees with the main transaction is a
/// precondition failure (rc 2), never a silent fallback to the float path:
/// the database under this probe is frozen and read-only, so a mismatch
/// means the probe's own environment is not what it claims to be.
fn fast_rescored_hits(
    path: &Path,
    storage: &FrankenStorage,
    generation_id: i64,
    query: &[f32],
) -> anyhow::Result<(Vec<Vec0KnnHit>, usize, usize)> {
    let conn = storage.raw();
    let (mut rescored, coarse_rows) = conn.with_tx_no_replay(TxMode::Deferred, |tx| {
        let snapshot = vector_domain::vector_snapshot_in_tx(tx, generation_id)?
            .ok_or_else(|| mirror_damaged("vector mirror damaged: missing database instance identity"))?;
        let quantized = vector_domain::quantize_unit_int8(conn, query)?;
        match vector_domain::parallel_int8_candidates(path, &snapshot, &quantized, FAST_SHARD_K)? {
            Int8Candidates::SnapshotMismatch => Err(mirror_damaged(
                "fast probe precondition: an int8 shard snapshot disagrees with the main read snapshot",
            )),
            Int8Candidates::Matching { rows, corpus_rows } => {
                let authoritative_rows: i64 = tx.query_row_map(
                    "SELECT COUNT(*) FROM message_chunks WHERE generation_id=?1",
                    &[Value::from(generation_id)],
                    |row| row.get_typed(0),
                )?;
                let authoritative_rows = usize::try_from(authoritative_rows)
                    .map_err(|_| mirror_damaged("vector mirror damaged: invalid authoritative row count"))?;
                if corpus_rows != authoritative_rows {
                    return Err(mirror_damaged("vector mirror damaged: int8 corpus count mismatch"));
                }
                let coarse_rows = rows.len();
                let ids: Vec<i64> = rows.iter().map(|(id, _)| *id).collect();
                let mut rescored: Vec<Vec0KnnHit> = Vec::with_capacity(ids.len());
                for batch in ids.chunks(AUTHORITATIVE_BATCH_ROWS) {
                    let sql = format!(
                        "SELECT chunk_id, generation_id, embedding FROM message_chunks WHERE chunk_id IN ({})",
                        sql_placeholders(batch.len())
                    );
                    let params: Vec<Value> = batch.iter().map(|id| Value::from(*id)).collect();
                    let found: Vec<(i64, i64, Vec<u8>)> = tx.query_all_map(&sql, &params, |row| {
                        Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?))
                    })?;
                    for (id, generation, blob) in found {
                        let vector = le_blob_to_f32_vector(&blob)?;
                        if generation != generation_id
                            || vector.len() != query.len()
                            || vector.iter().any(|x| !x.is_finite() || !(-1.0..=1.0).contains(x))
                            || vector.iter().all(|x| *x == 0.0)
                        {
                            return Err(mirror_damaged("vector mirror damaged: invalid authoritative float row"));
                        }
                        rescored.push((id, cosine_distance_f64(&vector, query)));
                    }
                }
                if rescored.len() != coarse_rows {
                    return Err(mirror_damaged("vector mirror damaged: an int8 candidate has no authoritative float row"));
                }
                Ok((rescored, coarse_rows))
            }
        }
    })?;
    rescored.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    rescored.truncate(K);
    Ok((rescored, coarse_rows, coarse_rows))
}

fn timed_knn_sweep(
    storage: &FrankenStorage,
    path: &Path,
    generation_id: i64,
    queries: &[SampledQuery],
    mode: VectorSearchMode,
    phase: &'static str,
    repetition: usize,
    out: &mut Vec<QueryTiming>,
) -> anyhow::Result<()> {
    for (sample_index, query) in queries.iter().enumerate() {
        let t0 = Instant::now();
        let (hits, coarse_rows_collected, float_rescore_rows) = match mode {
            VectorSearchMode::Exact => (vec0_knn(storage.raw(), generation_id, &query.vector, K)?, 0, 0),
            VectorSearchMode::Fast => fast_rescored_hits(path, storage, generation_id, &query.vector)?,
        };
        let elapsed = t0.elapsed();
        out.push(QueryTiming {
            phase,
            repetition,
            sample_index,
            chunk_id: query.chunk_id,
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
            top_chunk_ids: hits.into_iter().map(|(id, _)| id).collect(),
            vector_search_mode: mode.label(),
            coarse_rows_collected,
            float_rescore_rows,
            query_f32_sha256: query.f32_sha256.clone(),
        });
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

/// The original merged summary, computed over an arbitrary set of timings --
/// used once for the whole run and once per phase.
fn summarize_ms(timings: impl Iterator<Item = f64>) -> (usize, f64, f64, f64, f64) {
    let mut ms: Vec<f64> = timings.collect();
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean_ms = ms.iter().sum::<f64>() / ms.len() as f64;
    let max_ms = *ms.last().unwrap();
    (ms.len(), percentile_ms(&ms, 0.50), percentile_ms(&ms, 0.95), mean_ms, max_ms)
}

fn phase_stats(timings: &[QueryTiming], phase: &str) -> PhaseStats {
    let (samples, p50_ms, p95_ms, mean_ms, max_ms) =
        summarize_ms(timings.iter().filter(|t| t.phase == phase).map(|t| t.elapsed_ms));
    PhaseStats { samples, p50_ms, p95_ms, mean_ms, max_ms }
}

fn run_probe(db_path: &Path, mode: VectorSearchMode) -> anyhow::Result<Ku2Report> {
    let storage = FrankenStorage::open_readonly(db_path)?;
    let (generation_id, _dim) = active_generation(&storage)?;
    let queries = sample_stride_vectors(&storage, generation_id, SAMPLE_COUNT)?;

    let mut timings: Vec<QueryTiming> = Vec::with_capacity((COLD_REPS + HOT_REPS) * queries.len());

    for repetition in 0..COLD_REPS {
        let cold_storage = FrankenStorage::open_readonly(db_path)?;
        timed_knn_sweep(&cold_storage, db_path, generation_id, &queries, mode, PHASE_NEW_CONNECTION, repetition, &mut timings)?;
    }

    let hot_storage = FrankenStorage::open_readonly(db_path)?;
    for repetition in 0..HOT_REPS {
        timed_knn_sweep(&hot_storage, db_path, generation_id, &queries, mode, PHASE_REUSED_CONNECTION, repetition, &mut timings)?;
    }

    let (samples, p50_ms, p95_ms, mean_ms, max_ms) = summarize_ms(timings.iter().map(|t| t.elapsed_ms));
    let passed = timings.iter().all(|t| t.elapsed_ms <= MAX_LATENCY_GATE.as_secs_f64() * 1000.0);

    Ok(Ku2Report {
        samples,
        k: K,
        generation_id,
        p50_ms,
        p95_ms,
        mean_ms,
        max_ms,
        passed,
        vector_search_mode: mode.label().to_string(),
        query_chunk_ids: queries.iter().map(|q| q.chunk_id).collect(),
        new_connection: phase_stats(&timings, PHASE_NEW_CONNECTION),
        reused_connection: phase_stats(&timings, PHASE_REUSED_CONNECTION),
        timings,
    })
}

fn run(db_path: &Path, mode: VectorSearchMode) -> (i32, Option<Ku2Report>, String) {
    if !db_path.is_file() {
        return (2, None, format!("precondition error: db {} does not exist", db_path.display()));
    }
    match run_probe(db_path, mode) {
        Err(e) => (2, None, format!("precondition error: {e:#}")),
        Ok(report) => {
            let code = if report.passed { 0 } else { 1 };
            let msg = format!(
                "ku2_probe: mode={} samples={} k={} p50={:.1}ms p95={:.1}ms mean={:.1}ms max={:.1}ms passed={} (gate: max <= 2000ms)",
                report.vector_search_mode, report.samples, report.k, report.p50_ms, report.p95_ms, report.mean_ms, report.max_ms, report.passed
            );
            (code, Some(report), msg)
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let db_path = coding_agent_search::default_db_path();
    let (code, report, message) = run(&db_path, cli.vector_search_mode);
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

    /// Builds a tiny synthetic v5 db with an active generation and `n_chunks`
    /// chunk-domain vectors (dim=4, so KNN math is trivially checkable) --
    /// enough for stride sampling to exercise real distinct rows, small
    /// enough to run in milliseconds. `rebuild_vec0_table_for_generation`
    /// populates the float mirror and all eight int8 shards, so the `fast`
    /// path has a complete mirror to read.
    fn build_synthetic_v5_db(path: &Path, n_chunks: i64) -> i64 {
        let storage = FrankenStorage::open(path).unwrap();
        insert_message_parent_chain(&storage, 1, 1, 1);
        let generation_id = storage
            .raw()
            .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", 4, 1, 1, b"fp", 1))
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

        vector_domain::rebuild_vec0_table_for_generation(storage.raw(), generation_id, 4).unwrap();
        generation_id
    }

    #[test]
    fn default_vector_search_mode_is_exact() {
        let cli = Cli::parse_from(["w4_ku2_probe", "--json", "/tmp/ku2-out.json"]);
        assert_eq!(cli.vector_search_mode, VectorSearchMode::Exact);
        let cli = Cli::parse_from(["w4_ku2_probe", "--json", "/tmp/ku2-out.json", "--vector-search-mode", "fast"]);
        assert_eq!(cli.vector_search_mode, VectorSearchMode::Fast);
    }

    #[test]
    fn probe_runs_and_passes_on_a_tiny_synthetic_db() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("agent_search.db");
        let generation_id = build_synthetic_v5_db(&db_path, 200);

        let (code, report, message) = run(&db_path, VectorSearchMode::Exact);
        assert_eq!(code, 0, "a tiny in-memory-scale KNN probe must pass the 2.0s gate: {message}");
        let report = report.unwrap();
        assert_eq!(report.generation_id, generation_id);
        assert_eq!(report.k, 40);
        assert_eq!(report.samples, 64 * 6, "3 cold + 3 hot reps * 64 sampled vectors");
        assert!(report.max_ms < 2000.0);
        assert!(report.p50_ms <= report.p95_ms);
        assert!(report.p95_ms <= report.max_ms);
        assert_eq!(report.vector_search_mode, "exact");

        // PR9 task 01: the added observation fields must be self-consistent,
        // and the merged block must be reproducible from `timings` alone.
        assert_eq!(report.query_chunk_ids.len(), SAMPLE_COUNT as usize);
        let mut distinct = report.query_chunk_ids.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), SAMPLE_COUNT as usize, "the 64 sampled query chunk ids must be pairwise distinct");
        assert_eq!(report.timings.len(), report.samples);
        for t in &report.timings {
            assert!(report.query_chunk_ids[t.sample_index] == t.chunk_id, "each timing must name its own query");
            assert_eq!(t.top_chunk_ids.len(), K);
            // PR9 task 10 AC1: `exact` never runs a coarse pass, so the two
            // new counters stay zero and no original `exact` statistic moves.
            assert_eq!(t.vector_search_mode, "exact");
            assert_eq!(t.coarse_rows_collected, 0);
            assert_eq!(t.float_rescore_rows, 0);
            assert_eq!(t.query_f32_sha256.len(), 64);
        }
        assert_eq!(report.new_connection.samples, 64 * COLD_REPS);
        assert_eq!(report.reused_connection.samples, 64 * HOT_REPS);
        assert_eq!(report.new_connection.samples + report.reused_connection.samples, report.samples);
        assert_eq!(
            report.timings.iter().filter(|t| t.phase == PHASE_NEW_CONNECTION).count(),
            report.new_connection.samples
        );
        assert_eq!(
            report.timings.iter().filter(|t| t.phase == PHASE_REUSED_CONNECTION).count(),
            report.reused_connection.samples
        );
        let (n, p50, p95, mean, max) = summarize_ms(report.timings.iter().map(|t| t.elapsed_ms));
        assert_eq!((n, p50, p95, mean, max), (report.samples, report.p50_ms, report.p95_ms, report.mean_ms, report.max_ms));
        assert_eq!(phase_stats(&report.timings, PHASE_NEW_CONNECTION), report.new_connection);
        assert_eq!(phase_stats(&report.timings, PHASE_REUSED_CONNECTION), report.reused_connection);

        // PR9 task 01 evidence: emit the verified report so an independent
        // script can recompute the merged block from `timings` outside the
        // crate. Captured with `--nocapture`; a normal test run captures and
        // discards it. No file, no environment switch.
        println!("W4_KU2_PROBE_REPORT_JSON_BEGIN");
        println!("{}", serde_json::to_string(&report).expect("Ku2Report must serialize"));
        println!("W4_KU2_PROBE_REPORT_JSON_END");
    }

    /// PR9 task 10 AC1: the `fast` path on the same synthetic library. Both
    /// modes must draw the identical 64 query BLOBs; `fast` must collect a
    /// non-empty coarse pool, rescore exactly that pool, and return `k`
    /// hits. Every synthetic query vector's own chunk is its distance-0
    /// nearest neighbour, so the top hit must be the query's own chunk in
    /// both modes -- a cheap end-to-end cross-check that the rescored order
    /// is really by float distance.
    #[test]
    fn fast_mode_rescores_the_full_coarse_pool_on_a_tiny_synthetic_db() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("agent_search.db");
        let generation_id = build_synthetic_v5_db(&db_path, 200);

        let (exact_code, exact, _) = run(&db_path, VectorSearchMode::Exact);
        let (fast_code, fast, message) = run(&db_path, VectorSearchMode::Fast);
        assert_eq!(exact_code, 0);
        assert_eq!(fast_code, 0, "the fast path must pass on a complete mirror: {message}");
        let exact = exact.unwrap();
        let fast = fast.unwrap();

        assert_eq!(fast.vector_search_mode, "fast");
        assert_eq!(fast.generation_id, generation_id);
        assert_eq!(fast.samples, 64 * 6);
        assert_eq!(fast.query_chunk_ids, exact.query_chunk_ids, "both modes must sample the same query chunks");

        let mut fast_timings = fast.timings.clone();
        fast_timings.sort_by_key(|t| (t.phase, t.repetition, t.sample_index));
        let mut exact_timings = exact.timings.clone();
        exact_timings.sort_by_key(|t| (t.phase, t.repetition, t.sample_index));
        assert_eq!(fast_timings.len(), exact_timings.len());
        for (f, e) in fast_timings.iter().zip(exact_timings.iter()) {
            assert_eq!(f.chunk_id, e.chunk_id);
            assert_eq!(f.query_f32_sha256, e.query_f32_sha256, "the stored query f32 BLOB must be identical across modes");
            assert_eq!(f.top_chunk_ids.len(), K);
            assert_eq!(f.top_chunk_ids[0], f.chunk_id, "a synthetic query chunk is its own distance-0 nearest neighbour");
            assert_eq!(e.top_chunk_ids[0], e.chunk_id, "exact must agree on the same self-hit");
        }

        let sample = &fast.timings[0];
        assert!(sample.coarse_rows_collected > 0, "fast must collect a coarse pool");
        assert_eq!(sample.float_rescore_rows, sample.coarse_rows_collected, "every coarse candidate is rescored");
        assert!(
            fast.timings.iter().all(|t| t.coarse_rows_collected == sample.coarse_rows_collected),
            "200 synthetic chunks across 8 shards all fit under the k=160 per-shard window"
        );
    }

    #[test]
    fn fast_mode_without_an_int8_mirror_is_a_precondition_error() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("agent_search.db");
        let generation_id = build_synthetic_v5_db(&db_path, 200);
        // Drop only the int8 shards, leaving the float mirror and the
        // authoritative rows untouched -- `fast` must fail loudly instead of
        // quietly falling back to the exact path.
        let storage = FrankenStorage::open(&db_path).unwrap();
        for shard in 0..vector_domain::INT8_SHARDS {
            let table = vector_domain::int8_table_name(generation_id, shard).unwrap();
            storage.raw().execute(&format!("DROP TABLE {table}"), &[]).unwrap();
        }
        drop(storage);

        let (code, report, message) = run(&db_path, VectorSearchMode::Fast);
        assert_eq!(code, 2, "a missing int8 mirror is a fast-path precondition error: {message}");
        assert!(report.is_none());

        // The exact path is untouched by the missing mirror.
        let (exact_code, exact, _) = run(&db_path, VectorSearchMode::Exact);
        assert_eq!(exact_code, 0);
        assert_eq!(exact.unwrap().vector_search_mode, "exact");
    }

    #[test]
    fn missing_db_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("does-not-exist.db");
        let (code, report, message) = run(&db_path, VectorSearchMode::Exact);
        assert_eq!(code, 2, "missing db must be a precondition error: {message}");
        assert!(report.is_none());
    }

    #[test]
    fn no_active_generation_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("agent_search.db");
        FrankenStorage::open(&db_path).unwrap(); // fresh v5 schema, no generation created

        let (code, report, message) = run(&db_path, VectorSearchMode::Exact);
        assert_eq!(code, 2, "no active generation must be a precondition error: {message}");
        assert!(report.is_none());
    }
    #[test]
    fn fast_probe_rejects_partial_and_empty_shards() {
        for empty_shard in [false, true] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("archive.db");
            let generation = build_synthetic_v5_db(&path, 200);
            let storage = FrankenStorage::open(&path).unwrap();
            let table = vector_domain::int8_table_name(generation, 3).unwrap();
            let sql = if empty_shard {
                format!("DELETE FROM {table}")
            } else {
                format!("DELETE FROM {table} WHERE rowid=3")
            };
            storage.raw().execute(&sql, &[]).unwrap();
            drop(storage);
            let (code, report, message) = run(&path, VectorSearchMode::Fast);
            assert_eq!(code, 2, "empty_shard={empty_shard}: {message}");
            assert!(report.is_none(), "damaged input must not produce a successful timing report");
            assert!(message.contains("int8 corpus count mismatch"), "{message}");
            let (code, report, message) = run(&path, VectorSearchMode::Exact);
            assert_eq!(code, 0, "{message}");
            assert_eq!(report.unwrap().vector_search_mode, "exact");
        }
    }

}
