//! sqlite-vec (vec0) integration for the vector domain (w3 Task W3-3,
//! spec §3.4 D4 — KU2 basis: probe/sqlite-vec-eval @969c29b9, real
//! 101.6万×1024 bge-m3 corpus, B 案达标: scan max 1.73s@2s 阈, recall 9.67/10).
//!
//! `vec0` virtual tables are a **derived index** over the authoritative
//! `message_chunks` table (W3-1, chunk-granularity since T4/T11) — never a
//! second source of truth. w3-d3②: no resumable/checkpointed rebuild
//! machinery (rebuild drops, recreates and fills all mirrors in one
//! transaction, using keyset pages of at most 2048 authoritative vectors;
//! an interruption leaves the previous committed state). w3-d5: no in-process stall watchdog or size/time
//! auto-decision — progress exposure (when this module's caller wants it)
//! is a DB-internal marker or heartbeat file mtime for external sampling,
//! not anything built into this module.
//!
//! Each generation (`embedding_generations.id`) owns its original float vec0
//! mirror and eight int8 vec0 shards. The authoritative f32 BLOB remains in
//! `message_chunks`. Index dimensions are fixed per generation.
//! Table naming encodes the generation id so multiple generations' indexes
//! can coexist during the delayed-cleanup window (W3-4).

use super::api::{Conn, StorageError, Tx, TxMode, Value, params};

pub const INT8_SHARDS: usize = 8;
const REBUILD_BATCH_ROWS: usize = 2048;

pub fn int8_table_name(generation_id: i64, shard: usize) -> Result<String, StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    if shard >= INT8_SHARDS {
        return Err(reject(format!("invalid int8 shard {shard}")));
    }
    Ok(format!("vec_index_gen_{generation_id}_int8_shard_{shard}"))
}

fn bump_revision(tx: &Tx, generation_id: i64) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE embedding_generations SET vector_revision = vector_revision + 1 WHERE id = ?1",
        &params![generation_id],
    )?;
    Ok(())
}

fn validate_quantization_input(blob: &[u8], dim: usize) -> Result<(), StorageError> {
    if dim == 0 || blob.len() != dim.saturating_mul(4) {
        return Err(reject("int8 quantization dimension mismatch"));
    }
    let vector = super::schema::le_blob_to_f32_vector(blob)?;
    if vector.iter().any(|v| !v.is_finite() || !(-1.0..=1.0).contains(v)) {
        return Err(reject("int8 quantization requires finite unit-range float components"));
    }
    Ok(())
}

fn validate_quantized(blob: Vec<u8>, dim: usize) -> Result<Vec<u8>, StorageError> {
    if blob.len() != dim || blob.iter().all(|v| *v == 0) {
        return Err(reject("invalid dimension or all-zero int8 quantization"));
    }
    Ok(blob)
}

/// The locked sqlite-vec unit quantizer is the single source of byte rules.
/// Validate first: the extension itself clamps nonfinite/out-of-range values.
pub fn quantize_unit_int8(conn: &Conn, vector: &[f32]) -> Result<Vec<u8>, StorageError> {
    let blob = super::schema::f32_vector_to_le_blob(vector);
    validate_quantization_input(&blob, vector.len())?;
    let quantized = conn.query_row_map(
        "SELECT vec_quantize_int8(vec_f32(?1), 'unit')",
        &params![blob], |row| row.get_typed(0),
    )?;
    validate_quantized(quantized, vector.len())
}

/// Reject a partial layout or a table with a different element type/dimension.
/// Table existence is independent of whether its shard currently has any rows.
pub fn check_int8_layout(conn: &Conn, generation_id: i64, dim: i64) -> Result<(), StorageError> {
    let mut owned = std::collections::HashSet::new();
    for shard in 0..INT8_SHARDS {
        let table = int8_table_name(generation_id, shard)?;
        for suffix in ["", "_info", "_chunks", "_rowids", "_vector_chunks00"] {
            owned.insert(format!("{table}{suffix}"));
        }
        let sql: Option<String> = conn.query_opt_map(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            &params![table.clone()], |row| row.get_typed(0),
        )?;
        let Some(sql) = sql else {
            return Err(reject(format!("vector_domain_state=building: missing int8 mirror {table}")));
        };
        let normalized: String = sql.chars().filter(|c| !c.is_whitespace()).flat_map(char::to_lowercase).collect();
        let valid_header = normalized.starts_with(&format!("createvirtualtable{table}using"))
            || normalized.starts_with(&format!("createvirtualtableifnotexists{table}using"));
        let valid_body = normalized.split_once("using").is_some_and(|(_, body)| {
            body.trim_end_matches(';') == format!("vec0(embeddingint8[{dim}]distance_metric=cosine)")
        });
        if !valid_header || !valid_body {
            return Err(reject(format!("vector mirror damaged: invalid int8 layout in {table}")));
        }
    }
    let prefix = format!("vec_index_gen_{generation_id}_int8_shard_");
    let physical: Vec<String> = conn.query_all_map(
        "SELECT name FROM sqlite_master WHERE type='table' AND name GLOB ?1",
        &params![format!("{prefix}*")], |row| row.get_typed(0),
    )?;
    if let Some(unexpected) = physical.iter().find(|name| !owned.contains(*name)) {
        return Err(reject(format!("vector mirror damaged: unexpected int8 shard table {unexpected}")));
    }
    Ok(())
}

pub fn int8_row_matches(
    conn: &Conn, generation_id: i64, chunk_id: i64, authoritative_blob: &[u8],
) -> Result<bool, StorageError> {
    if chunk_id < 0 { return Err(reject("negative chunk ID")); }
    let vector = super::schema::le_blob_to_f32_vector(authoritative_blob)?;
    let expected = quantize_unit_int8(conn, &vector)?;
    let table = int8_table_name(generation_id, (chunk_id % INT8_SHARDS as i64) as usize)?;
    let stored: Option<Vec<u8>> = conn.query_opt_map(
        &format!("SELECT embedding FROM {table} WHERE rowid=?1"),
        &params![chunk_id], |row| row.get_typed(0),
    )?;
    Ok(stored.as_deref() == Some(expected.as_slice()))
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Int8MirrorAudit {
    pub rows: i64,
    pub missing: i64,
    pub extra: i64,
    pub wrong_shard: i64,
    pub duplicates: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorSnapshot {
    pub generation_id: i64,
    pub dim: i64,
    pub fingerprint: Vec<u8>,
    pub revision: i64,
    pub instance_id: String,
}

pub fn vector_snapshot_in_tx(tx: &Tx, generation_id: i64) -> Result<Option<VectorSnapshot>, StorageError> {
    let instance_id: String = tx.query_row_map(
        "SELECT value FROM meta WHERE key='vector_domain_instance_id'", &[], |row| row.get_typed(0),
    )?;
    if instance_id.len() != 32 || !instance_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(reject("vector mirror damaged: invalid database instance identity"));
    }
    tx.query_opt_map(
        "SELECT dim,fingerprint,vector_revision FROM embedding_generations WHERE id=?1",
        &params![generation_id],
        |row| Ok(VectorSnapshot {
            generation_id, dim: row.get_typed(0)?, fingerprint: row.get_typed(1)?,
            revision: row.get_typed(2)?, instance_id: instance_id.clone(),
        }),
    )
}

#[derive(Debug)]
pub enum Int8Candidates {
    Matching { rows: Vec<Vec0KnnHit>, corpus_rows: usize },
    SnapshotMismatch,
}

/// Each worker owns its read-only connection and transaction. No connection
/// or transaction crosses threads, and every join finishes before returning.
/// Revision mismatch discards the complete pool, never just one shard.
pub fn parallel_int8_candidates(
    path: &std::path::Path, snapshot: &VectorSnapshot, query: &[u8], k: usize,
) -> Result<Int8Candidates, StorageError> {
    let workers = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..INT8_SHARDS).map(|shard| scope.spawn(move || {
            let conn = crate::storage::sqlite::open_franken_raw_readonly_connection_with_timeout(path, std::time::Duration::from_secs(1))
                .map_err(|e| reject(e.to_string()))?;
            crate::storage::sqlite::ensure_readonly_schema_current(&conn).map_err(|e| reject(e.to_string()))?;
            conn.with_tx_no_replay(TxMode::Deferred, |tx| {
                let Some(observed) = vector_snapshot_in_tx(tx, snapshot.generation_id)? else {
                    return Ok(None);
                };
                if observed.instance_id != snapshot.instance_id {
                    return Err(reject("vector_database_changed: reopen the database before retrying"));
                }
                if observed != *snapshot { return Ok(None); }
                let table = int8_table_name(snapshot.generation_id, shard)?;
                let rows: i64 = tx.query_row_map(&format!("SELECT count(*) FROM {table}"), &[], |row| row.get_typed(0))?;
                let corpus_rows = usize::try_from(rows).map_err(|_| reject("invalid int8 shard row count"))?;
                let actual_k = k.min(corpus_rows);
                if actual_k == 0 { return Ok(Some((corpus_rows, Vec::new()))); }
                let hits: Vec<Vec0KnnHit> = tx.query_all_map(
                    &format!("SELECT rowid,distance FROM {table} WHERE embedding MATCH vec_int8(?1) AND k=?2 ORDER BY distance"),
                    &params![query.to_vec(), actual_k as i64], |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
                )?;
                if hits.len() != actual_k || hits.iter().any(|(id, distance)| *id < 0 || *id % INT8_SHARDS as i64 != shard as i64 || !distance.is_finite()) {
                    return Err(reject("vector mirror damaged: invalid int8 shard result"));
                }
                Ok(Some((corpus_rows, hits)))
            })
        })).collect();
        handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(reject("int8 search worker panicked")))).collect::<Vec<_>>()
    });
    let mut all = Vec::new();
    let mut corpus_rows = 0usize;
    let mut mismatch = false;
    for worker in workers {
        match worker? {
            Some((count, rows)) => {
                corpus_rows = corpus_rows.checked_add(count).ok_or_else(|| reject("int8 corpus count overflow"))?;
                all.extend(rows);
            }
            None => mismatch = true,
        }
    }
    if mismatch { return Ok(Int8Candidates::SnapshotMismatch); }
    all.sort_by_key(|(id, _)| *id);
    if all.windows(2).any(|w| w[0].0 == w[1].0) { return Err(reject("vector mirror damaged: duplicate int8 chunk ID")); }
    Ok(Int8Candidates::Matching { rows: all, corpus_rows })
}

/// Identity-set audit over all eight mirrors; equal counts cannot mask a swap.
pub fn audit_int8_mirror_identity(conn: &Conn, generation_id: i64, dim: i64) -> Result<Int8MirrorAudit, StorageError> {
    check_int8_layout(conn, generation_id, dim)?;
    let mut audit = Int8MirrorAudit::default();
    let mut union = Vec::with_capacity(INT8_SHARDS);
    for shard in 0..INT8_SHARDS {
        let table = int8_table_name(generation_id, shard)?;
        let count: i64 = conn.query_row_map(&format!("SELECT count(*) FROM {table}"), &[], |row| row.get_typed(0))?;
        audit.rows += count;
        audit.missing += conn.query_row_map::<i64>(
            &format!("SELECT count(*) FROM message_chunks mc WHERE generation_id=?1 AND chunk_id%8=?2 AND NOT EXISTS(SELECT 1 FROM {table} v WHERE v.rowid=mc.chunk_id)"),
            &params![generation_id, shard as i64], |row| row.get_typed(0),
        )?;
        audit.extra += conn.query_row_map::<i64>(
            &format!("SELECT count(*) FROM {table} v WHERE NOT EXISTS(SELECT 1 FROM message_chunks mc WHERE mc.generation_id=?1 AND mc.chunk_id=v.rowid)"),
            &params![generation_id], |row| row.get_typed(0),
        )?;
        audit.wrong_shard += conn.query_row_map::<i64>(
            &format!("SELECT count(*) FROM {table} WHERE rowid%8 != ?1"),
            &params![shard as i64], |row| row.get_typed(0),
        )?;
        union.push(format!("SELECT rowid AS chunk_id FROM {table}"));
    }
    audit.duplicates = conn.query_row_map(
        &format!("SELECT coalesce(sum(n-1),0) FROM (SELECT count(*) AS n FROM ({}) GROUP BY chunk_id HAVING count(*)>1)", union.join(" UNION ALL ")),
        &[], |row| row.get_typed(0),
    )?;
    Ok(audit)
}

fn create_mirrors_in_tx(tx: &Tx, generation_id: i64, dim: i64) -> Result<(), StorageError> {
    let table = vec0_table_name(generation_id);
    let count: i64 = tx.query_row_map("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1", &params![table.clone()], |row| row.get_typed(0))?;
    let mut created = count == 0;
    tx.execute_batch(&format!(
        "CREATE VIRTUAL TABLE IF NOT EXISTS {table} USING vec0(embedding float[{dim}] distance_metric=cosine);"
    ))?;
    for shard in 0..INT8_SHARDS {
        let table = int8_table_name(generation_id, shard)?;
        let count: i64 = tx.query_row_map("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1", &params![table.clone()], |row| row.get_typed(0))?;
        created |= count == 0;
        tx.execute_batch(&format!(
            "CREATE VIRTUAL TABLE IF NOT EXISTS {table} USING vec0(embedding int8[{dim}] distance_metric=cosine);"
        ))?;
    }
    if created { bump_revision(tx, generation_id)?; }
    Ok(())
}

/// `vec0` table name for a given generation. `chunk_id` (`message_chunks`'
/// own primary key) is used as the table's `rowid` on insert — unique
/// within one generation's table by construction (`message_chunks`'
/// `UNIQUE(generation_id, message_id, chunk_idx)`), so no separate
/// id-mapping table is
/// needed the way the KU2 probe's disposable harness used one (that probe
/// had no per-generation authoritative table to key off of; production
/// does).
fn vec0_table_name(generation_id: i64) -> String {
    format!("vec_index_gen_{generation_id}")
}

fn reject(detail: impl Into<String>) -> StorageError {
    StorageError::Other { code: None, detail: detail.into() }
}

/// Validate `generation_id` is a bare non-negative integer before splicing
/// it into DDL text (`CREATE VIRTUAL TABLE` cannot take a bound parameter
/// for the table name). `embedding_generations.id` is `INTEGER PRIMARY KEY
/// AUTOINCREMENT`, always non-negative in practice, but this is the
/// explicit boundary check rather than trusting that by convention.
fn validate_generation_id_for_ddl(generation_id: i64) -> Result<(), StorageError> {
    if generation_id < 0 {
        return Err(reject(format!(
            "generation_id {generation_id} is negative; refusing to splice into DDL"
        )));
    }
    Ok(())
}

/// Create (idempotently) the float vec0 and eight int8 virtual tables for
/// `generation_id` in one transaction. Cosine distance metric (KU2's validated
/// choice — the W3-0 handoff's finding that sqlite-vec's true cosine
/// scoring is more correct than fsvi's raw dot product on
/// near-but-not-exactly-unit-norm vectors).
pub fn create_vec0_table_for_generation(
    conn: &Conn,
    generation_id: i64,
    dim: i64,
) -> Result<(), StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    if dim <= 0 {
        return Err(reject(format!("dim must be positive, got {dim}")));
    }
    conn.with_tx_no_replay(TxMode::Immediate, |tx| create_mirrors_in_tx(tx, generation_id, dim))
}

/// Drop the nine derived vector tables for `generation_id`, if present.
/// `DROP TABLE` on each `vec0` virtual table also drops its shadow tables
/// (verified empirically by
/// [`vec0_shadow_tables_are_fully_enumerated_and_fully_dropped`] below —
/// w3-d8①: shadow-table behavior is taken on real `sqlite3` enumeration,
/// never assumed from documentation).
pub fn drop_vec0_table_for_generation(
    conn: &Conn,
    generation_id: i64,
) -> Result<(), StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    conn.with_tx_no_replay(TxMode::Immediate, |tx| drop_vec0_table_for_generation_in_tx(tx, generation_id))
}

/// Same DDL as [`drop_vec0_table_for_generation`], but issued against an
/// already-open [`Tx`] instead of opening (and committing) its own
/// statement -- R1-W3-N4: lets a caller fold the vec0 drop into the same
/// transaction as a relational metadata delete, so the two either commit
/// together or neither does. SQLite's DDL is transactional, so `DROP
/// TABLE` inside an open transaction participates in its rollback like
/// any other statement (`rebuild_vec0_table_for_generation` above already
/// relies on exactly this to make its own drop+recreate atomic).
pub fn drop_vec0_table_for_generation_in_tx(tx: &Tx, generation_id: i64) -> Result<(), StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    let table = vec0_table_name(generation_id);
    tx.execute_batch(&format!("DROP TABLE IF EXISTS {table};"))?;
    for shard in 0..INT8_SHARDS {
        let table = int8_table_name(generation_id, shard)?;
        tx.execute_batch(&format!("DROP TABLE IF EXISTS {table};"))?;
    }
    bump_revision(tx, generation_id)
}

/// Real `sqlite_master` enumeration of `generation_id`'s float/int8 tables
/// and their shadow tables (w3-d8① discipline: never hardcode a shadow
/// count from documentation or a prior measurement — count what is
/// actually there). Returns table names in `sqlite_master` order (main
/// table first, since `vec0` creates it before its shadows and
/// `sqlite_master`'s default rowid order is creation order).
pub fn enumerate_vec0_tables_for_generation(
    conn: &Conn,
    generation_id: i64,
) -> Result<Vec<String>, StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    let table = vec0_table_name(generation_id);
    let like_pattern = format!("{table}%");
    let names: Vec<String> = conn.query_all_map(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE ?1 ORDER BY rowid",
        &params![like_pattern],
        |row| row.get_typed(0),
    )?;
    // `_` is the namespace boundary: generation 1 must not include 10.
    Ok(names.into_iter().filter(|name| name == &table || name.starts_with(&format!("{table}_"))).collect())
}

/// Row count of `generation_id`'s main `vec0` table (never a shadow
/// table) -- the exact same table [`rebuild_vec0_table_for_generation`]
/// populates and [`vec0_knn`] scans. Activation audit check ⑦ (R1-W3-B5)
/// compares this against `COUNT(*) FROM message_chunks WHERE
/// generation_id = ?`: every other check either reads `message_chunks`
/// directly or probes `vec0` for one specific row's presence, so none of
/// them would ever notice `vec0` missing rows wholesale (a rebuild that
/// silently populated fewer rows than it read, or one that was simply
/// never re-run after `message_chunks` grew). Errors (most commonly
/// "no such table" if the `vec0` table was never created for this
/// generation) propagate as `StorageError`, not `Ok(0)` -- a missing
/// table is a different failure than a genuinely empty one and callers
/// must be able to tell them apart.
pub fn count_vec0_rows_for_generation(conn: &Conn, generation_id: i64) -> Result<i64, StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    let table = vec0_table_name(generation_id);
    conn.query_row_map(&format!("SELECT COUNT(*) FROM {table}"), &[], |row| row.get_typed(0))
}

/// One `vec0` KNN hit: `(chunk_id, distance)`, ascending distance (nearest
/// first) — the shape `SELECT rowid, distance ... ORDER BY distance`
/// naturally produces.
pub type Vec0KnnHit = (i64, f64);

/// Exact KNN scan over `generation_id`'s `vec0` table
/// (`SELECT rowid, distance FROM {table} WHERE embedding MATCH ?1 AND k =
/// ?2 ORDER BY distance` — verbatim query shape from the KU2 probe). `k`
/// caps the result count; callers scanning at the KU2-validated top-40
/// scale should pass `k=40`.
pub fn vec0_knn(
    conn: &Conn,
    generation_id: i64,
    query_vector: &[f32],
    k: usize,
) -> Result<Vec<Vec0KnnHit>, StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    let table = vec0_table_name(generation_id);
    let blob = super::schema::f32_vector_to_le_blob(query_vector);
    let k_i64 = i64::try_from(k).map_err(|_| reject(format!("k={k} does not fit in i64")))?;
    conn.query_all_map(
        &format!("SELECT rowid, distance FROM {table} WHERE embedding MATCH ?1 AND k = ?2 ORDER BY distance"),
        &params![blob, k_i64],
        |row| Ok((row.get_typed::<i64>(0)?, row.get_typed::<f64>(1)?)),
    )
}

// =============================================================================
// Chunk-domain `vec0` primitives (T4, plan v5.1; finalized T11): one
// vec0 table per generation, rowid-keyed on `message_chunks.chunk_id`.
// This is the sole vec0 domain since T11 retired the v4 message-
// granularity helpers that used to live above.
// =============================================================================

/// Bidirectional identity-set anti-join between `message_chunks` and
/// `generation_id`'s `vec0` table -- activation audit check ⑦'s original
/// `COUNT(*)` comparison ([`count_vec0_rows_for_generation`] vs.
/// `COUNT(*) FROM message_chunks`) only catches a *size* mismatch. An
/// equal-size swap (N rows missing from one side exactly offset by N
/// different extra rows on the other) sails through a plain count
/// comparison with both sides reporting the same number, passing an audit
/// over a `vec0` index that is silently indexing the wrong chunk for at
/// least one entry. `vec0`'s `rowid` is `message_chunks.chunk_id` by
/// construction ([`rebuild_vec0_table_for_generation`]'s `INSERT INTO
/// {table}(rowid, embedding)`), so a plain `NOT EXISTS` anti-join on
/// `rowid = chunk_id` is exact. Returns `(missing_from_vec0, extra_in_vec0)`.
pub fn count_vec0_chunks_set_mismatch_for_generation(
    conn: &Conn,
    generation_id: i64,
) -> Result<(i64, i64), StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    let table = vec0_table_name(generation_id);
    let missing_from_vec0: i64 = conn.query_row_map(
        &format!(
            "SELECT COUNT(*) FROM message_chunks mc \
             WHERE mc.generation_id = ?1 \
               AND NOT EXISTS (SELECT 1 FROM {table} v WHERE v.rowid = mc.chunk_id)"
        ),
        &params![generation_id],
        |row| row.get_typed(0),
    )?;
    let extra_in_vec0: i64 = conn.query_row_map(
        &format!(
            "SELECT COUNT(*) FROM {table} v \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM message_chunks mc \
                 WHERE mc.generation_id = ?1 AND mc.chunk_id = v.rowid \
             )"
        ),
        &params![generation_id],
        |row| row.get_typed(0),
    )?;
    Ok((missing_from_vec0, extra_in_vec0))
}

/// Rebuild `generation_id`'s nine derived mirrors from `message_chunks` in one
/// transaction (drop + recreate + bounded keyset population) -- sibling of
/// [`rebuild_vec0_table_for_generation`], same atomicity discipline (an
/// interruption anywhere leaves the generation's `vec0` table exactly as it
/// was before the call). Returns the number of rows populated.
pub fn rebuild_vec0_table_for_generation(
    conn: &Conn,
    generation_id: i64,
    dim: i64,
) -> Result<usize, StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    if dim <= 0 {
        return Err(reject(format!("dim must be positive, got {dim}")));
    }
    conn.with_tx_no_replay(TxMode::Immediate, |tx| {
        drop_vec0_table_for_generation_in_tx(tx, generation_id)?;
        create_mirrors_in_tx(tx, generation_id, dim)?;
        let mut last_id = i64::MIN;
        let mut populated = 0usize;
        loop {
            let rows: Vec<(i64, Vec<u8>)> = tx.query_all_map(
                "SELECT chunk_id,embedding FROM message_chunks WHERE generation_id=?1 AND chunk_id>?2 ORDER BY chunk_id LIMIT ?3",
                &params![generation_id, last_id, REBUILD_BATCH_ROWS as i64],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )?;
            if rows.is_empty() { break; }
            let borrowed: Vec<(i64, &[u8])> = rows.iter().map(|(id, blob)| (*id, blob.as_slice())).collect();
            insert_vec0_rows_in_tx(tx, generation_id, &borrowed)?;
            last_id = rows[rows.len() - 1].0;
            populated += rows.len();
        }
        Ok(populated)
    })
}

/// Insert authoritative f32 rows into the float mirror and their routed int8
/// shards in one caller-owned transaction -- the incremental counterpart to
/// [`rebuild_vec0_table_for_generation`]'s bulk rebuild, for a catch-up
/// writer landing newly-embedded chunks one small batch at a time instead of
/// re-populating the whole table. Returns the number of rows inserted.
pub fn insert_vec0_rows_in_tx(
    tx: &Tx,
    generation_id: i64,
    rows: &[(i64, &[u8])],
) -> Result<u64, StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    let table = vec0_table_name(generation_id);
    let dim: i64 = tx.query_row_map("SELECT dim FROM embedding_generations WHERE id=?1", &params![generation_id], |row| row.get_typed(0))?;
    let dim = usize::try_from(dim).map_err(|_| reject("invalid generation dimension"))?;
    let insert_sql = format!("INSERT INTO {table}(rowid, embedding) VALUES (?1, ?2)");
    let mut inserted = 0u64;
    for (chunk_id, embedding) in rows {
        if *chunk_id < 0 { return Err(reject("negative chunk ID cannot route to an int8 shard")); }
        validate_quantization_input(embedding, dim)?;
        let quantized = tx.query_row_map("SELECT vec_quantize_int8(vec_f32(?1),'unit')", &params![embedding.to_vec()], |row| row.get_typed(0))?;
        let quantized = validate_quantized(quantized, dim)?;
        tx.execute(&insert_sql, &[Value::from(*chunk_id), Value::from(embedding.to_vec())])?;
        let shard = int8_table_name(generation_id, (*chunk_id % INT8_SHARDS as i64) as usize)?;
        tx.execute(&format!("INSERT INTO {shard}(rowid,embedding) VALUES(?1,vec_int8(?2))"), &params![*chunk_id, quantized])?;
        inserted += 1;
    }
    if !rows.is_empty() { bump_revision(tx, generation_id)?; }
    Ok(inserted)
}

/// Delete each chunk from both derived mirrors in the same transaction as its
/// authoritative delete. Returns the float mirror's deleted-row count.
pub fn delete_vec0_rows_in_tx(
    tx: &Tx,
    generation_id: i64,
    chunk_ids: &[i64],
) -> Result<u64, StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    let table = vec0_table_name(generation_id);
    let delete_sql = format!("DELETE FROM {table} WHERE rowid = ?1");
    let mut deleted = 0u64;
    for chunk_id in chunk_ids {
        if *chunk_id < 0 { return Err(reject("negative chunk ID cannot route to an int8 shard")); }
        let shard = int8_table_name(generation_id, (*chunk_id % INT8_SHARDS as i64) as usize)?;
        tx.execute(&format!("DELETE FROM {shard} WHERE rowid=?1"), &params![*chunk_id])?;
        deleted += tx.execute(&delete_sql, &params![*chunk_id])? as u64;
    }
    if !chunk_ids.is_empty() { bump_revision(tx, generation_id)?; }
    Ok(deleted)
}

/// Shared strict-name-parsing half of `list_vec0_generation_ids`/
/// `list_vec0_generation_ids_in_tx` (T6, plan v5.1): whole-name regex match
/// (`^vec_index_gen_(\d+)(?:_int8_shard_[0-7])?$`), not a prefix scan with
/// loose parsing, so `vec0`'s own shadow tables for the same
/// generation (e.g. `..._info`, `..._chunks`, `..._rowids`) are never
/// mistaken for a second, differently-shaped "generation". Deduplicated and
/// returned in ascending order. One regex compiled per caller-visible
/// function, not duplicated as a second copy of the pattern string.
fn parse_vec0_generation_table_names(names: &[String]) -> Vec<i64> {
    let pattern = regex::Regex::new(r"^vec_index_gen_(\d+)(?:_int8_shard_[0-7])?$").expect("static regex must compile");
    let mut ids: Vec<i64> = names
        .iter()
        .filter_map(|name| pattern.captures(name))
        .filter_map(|caps| caps.get(1).and_then(|m| m.as_str().parse::<i64>().ok()))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

const LIST_VEC0_GENERATION_TABLE_NAMES_SQL: &str =
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'vec_index_gen_%' ORDER BY name";

/// Every `generation_id` with a live chunk-domain `vec0` table, discovered
/// by real `sqlite_master` enumeration (never hardcoded).
pub fn list_vec0_generation_ids(conn: &Conn) -> Result<Vec<i64>, StorageError> {
    let names: Vec<String> =
        conn.query_all_map(LIST_VEC0_GENERATION_TABLE_NAMES_SQL, &[], |row| row.get_typed(0))?;
    Ok(parse_vec0_generation_table_names(&names))
}

/// T6 (plan v5.1): `Tx`-scoped counterpart to [`list_vec0_generation_ids`] --
/// `delete_messages_ordered_in_tx` and other same-transaction delete paths
/// only ever hold a `&Tx<'_>`, which is a distinct type from `&Conn` (no
/// `Deref`), so the `&Conn`-only original cannot be called mid-transaction.
/// Identical query and parsing, over `tx.query_all_map` instead of
/// `conn.query_all_map`.
pub fn list_vec0_generation_ids_in_tx(tx: &Tx<'_>) -> Result<Vec<i64>, StorageError> {
    let names: Vec<String> =
        tx.query_all_map(LIST_VEC0_GENERATION_TABLE_NAMES_SQL, &[], |row| row.get_typed(0))?;
    Ok(parse_vec0_generation_table_names(&names))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::api::Profile;
    use crate::storage::schema;
    use crate::storage::testing::open_writable_for_tests;

    fn scratch_conn() -> (tempfile::TempDir, Conn) {
        let dir = tempfile::TempDir::new().expect("create scratch dir");
        let path = dir.path().join("agent_search.db");
        let conn = open_writable_for_tests(&path, Profile::Production).expect("open writer");
        schema::ensure(&conn).expect("schema::ensure should build the fresh schema");
        (dir, conn)
    }

    fn insert_message_parent_chain(conn: &Conn, agent_id: i64, conversation_id: i64, message_id: i64) {
        conn.execute(
            "INSERT OR IGNORE INTO agents(id, slug, name, kind, created_at, updated_at) VALUES (?1, ?2, ?2, 'cli', 0, 0)",
            &params![agent_id, format!("agent-{agent_id}")],
        )
        .unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO conversations(id, agent_id, title, source_path) VALUES (?1, ?2, 't', ?3)",
            &params![conversation_id, agent_id, format!("/tmp/c-{conversation_id}.jsonl")],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages(id, conversation_id, idx, role, content) VALUES (?1, ?2, ?1, 'user', 'c')",
            &params![message_id, conversation_id],
        )
        .unwrap();
    }

    fn create_generation(conn: &Conn, dim: i64) -> i64 {
        conn.with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::create_embedding_generation(tx, "bge-m3", dim, 1, 1, b"test-fingerprint", 1_000)
        })
        .unwrap()
    }

    fn insert_chunk(conn: &Conn, generation_id: i64, message_id: i64, embedding: &[f32]) -> i64 {
        conn.with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::insert_chunk_row_in_tx(
                tx,
                &schema::ChunkRow {
                    generation_id,
                    message_id,
                    conversation_id: 1,
                    chunk_idx: 0,
                    byte_start: 0,
                    byte_end: 1,
                    content_hash: format!("h{message_id}"),
                    embedding: embedding.to_vec(),
                    norm: 1.0,
                    created_at_ms: 1_000,
                },
            )
        })
        .unwrap()
    }

    #[test]
    fn create_vec0_table_is_idempotent() {
        let (_dir, conn) = scratch_conn();
        let gen_id = create_generation(&conn, 4);
        create_vec0_table_for_generation(&conn, gen_id, 4).expect("first create");
        create_vec0_table_for_generation(&conn, gen_id, 4).expect("second create is a no-op, not an error");
    }

    /// w3-d8①: never assume shadow-table shape from documentation. Real
    /// enumeration on a table this module just created.
    #[test]
    fn vec0_shadow_tables_are_fully_enumerated_and_fully_dropped() {
        let (_dir, conn) = scratch_conn();
        let gen_id = create_generation(&conn, 4);
        create_vec0_table_for_generation(&conn, gen_id, 4).unwrap();

        let names = enumerate_vec0_tables_for_generation(&conn, gen_id).unwrap();
        // Real sqlite3 enumeration, this run: main table + 4 shadow tables
        // (`_info`/`_chunks`/`_rowids`/`_vector_chunks00`) -- matches W3-0's
        // exec50 handoff finding on a separately-created vec0 table
        // (`vec_index`+4 shadows = 5, 2026-09-01), independently
        // corroborated here on a freshly created `vec_index_gen_N` table
        // (w3-d8①: real measurement, not copied from that prior report).
        let table = vec0_table_name(gen_id);
        let mut expected = vec![
            table.clone(), format!("{table}_info"), format!("{table}_chunks"),
            format!("{table}_rowids"), format!("{table}_vector_chunks00"),
        ];
        for shard in 0..INT8_SHARDS {
            let table = int8_table_name(gen_id, shard).unwrap();
            expected.extend([
                table.clone(), format!("{table}_info"), format!("{table}_chunks"),
                format!("{table}_rowids"), format!("{table}_vector_chunks00"),
            ]);
        }
        assert_eq!(
            names,
            expected,
            "vec0 shadow table set drifted from the real-measured shape -- if this is an \
             intentional sqlite-vec version change, update this assertion from a fresh \
             sqlite3 enumeration, not from memory"
        );

        drop_vec0_table_for_generation(&conn, gen_id).unwrap();
        let after = enumerate_vec0_tables_for_generation(&conn, gen_id).unwrap();
        assert!(
            after.is_empty(),
            "DROP TABLE on the main vec0 table must remove every shadow table too, left: {after:?}"
        );
    }

    #[test]
    fn drop_vec0_table_on_a_never_created_generation_is_a_harmless_no_op() {
        let (_dir, conn) = scratch_conn();
        // No create_vec0_table_for_generation call at all -- a generation
        // whose vec0 index was never built (or already dropped) must not
        // make drop an error (rebuild-not-repair discipline: dropping
        // something already absent is a valid step toward a clean rebuild).
        drop_vec0_table_for_generation(&conn, 999).expect("dropping a nonexistent vec0 table must be a no-op");
    }

    #[test]
    fn rebuild_populates_from_message_chunks_and_knn_finds_the_nearest_match() {
        let (_dir, conn) = scratch_conn();
        insert_message_parent_chain(&conn, 1, 1, 1);
        insert_message_parent_chain(&conn, 1, 1, 2);
        insert_message_parent_chain(&conn, 1, 1, 3);
        let gen_id = create_generation(&conn, 4);

        let chunk_1 = insert_chunk(&conn, gen_id, 1, &[1.0, 0.0, 0.0, 0.0]);
        insert_chunk(&conn, gen_id, 2, &[0.0, 1.0, 0.0, 0.0]);
        let chunk_3 = insert_chunk(&conn, gen_id, 3, &[0.9, 0.1, 0.0, 0.0]);

        let populated = rebuild_vec0_table_for_generation(&conn, gen_id, 4).expect("rebuild");
        assert_eq!(populated, 3, "all three rows for this generation must be populated");

        // Query near chunk_1's vector -- chunk_3 (0.9,0.1,0,0) is the
        // closer neighbor by cosine distance, chunk_1 (1,0,0,0) is exact.
        let hits = vec0_knn(&conn, gen_id, &[1.0, 0.0, 0.0, 0.0], 2).expect("knn query");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].0, chunk_1, "the exact match (chunk_1) must rank first");
        assert!(hits[0].1 < hits[1].1, "distances must be ascending (nearest first)");
        let chunk_ids: Vec<i64> = hits.iter().map(|(id, _)| *id).collect();
        assert!(chunk_ids.contains(&chunk_3), "chunk_3 (near-duplicate) must be the second hit, got {chunk_ids:?}");
    }

    #[test]
    fn rebuild_only_indexes_rows_for_the_target_generation_not_other_generations() {
        let (_dir, conn) = scratch_conn();
        insert_message_parent_chain(&conn, 1, 1, 1);
        insert_message_parent_chain(&conn, 1, 1, 2);
        let gen_a = create_generation(&conn, 4);
        let gen_b = create_generation(&conn, 4);

        let chunk_a = insert_chunk(&conn, gen_a, 1, &[1.0, 0.0, 0.0, 0.0]);
        insert_chunk(&conn, gen_b, 2, &[0.0, 1.0, 0.0, 0.0]);

        let populated_a = rebuild_vec0_table_for_generation(&conn, gen_a, 4).unwrap();
        assert_eq!(populated_a, 1, "generation A's vec0 table must only get generation A's row");

        let hits = vec0_knn(&conn, gen_a, &[0.0, 1.0, 0.0, 0.0], 10).unwrap();
        let chunk_ids: Vec<i64> = hits.iter().map(|(id, _)| *id).collect();
        assert_eq!(chunk_ids, vec![chunk_a], "generation A's index must never contain generation B's row");
    }

    #[test]
    fn rebuild_is_repeatable_and_replaces_stale_data() {
        let (_dir, conn) = scratch_conn();
        insert_message_parent_chain(&conn, 1, 1, 1);
        insert_message_parent_chain(&conn, 1, 1, 2);
        let gen_id = create_generation(&conn, 4);

        insert_chunk(&conn, gen_id, 1, &[1.0, 0.0, 0.0, 0.0]);
        let first = rebuild_vec0_table_for_generation(&conn, gen_id, 4).unwrap();
        assert_eq!(first, 1);

        insert_chunk(&conn, gen_id, 2, &[0.0, 1.0, 0.0, 0.0]);
        let second = rebuild_vec0_table_for_generation(&conn, gen_id, 4).expect("rebuild after new writes");
        assert_eq!(second, 2, "rebuild must reflect newly written rows, not stale pre-rebuild state");

        let hits = vec0_knn(&conn, gen_id, &[0.0, 1.0, 0.0, 0.0], 10).unwrap();
        assert_eq!(hits.len(), 2, "the rebuilt index must contain both rows, not just the first rebuild's snapshot");
    }
}
