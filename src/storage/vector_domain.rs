//! sqlite-vec (vec0) integration for the vector domain (w3 Task W3-3,
//! spec §3.4 D4 — KU2 basis: probe/sqlite-vec-eval @969c29b9, real
//! 101.6万×1024 bge-m3 corpus, B 案达标: scan max 1.73s@2s 阈, recall 9.67/10).
//!
//! `vec0` virtual tables are a **derived index** over the authoritative
//! `message_embeddings` table (W3-1) — never a second source of truth.
//! w3-d3②: no resumable/checkpointed rebuild machinery (rebuild is a
//! minutes-scale idempotent operation: drop the table, recreate, repopulate
//! from `message_embeddings` in one transaction — an interruption leaves
//! the previous committed state, a retry starts over cleanly, per w3-d9②'s
//! atomicity discipline). w3-d5: no in-process stall watchdog or size/time
//! auto-decision — progress exposure (when this module's caller wants it)
//! is a DB-internal marker or heartbeat file mtime for external sampling,
//! not anything built into this module.
//!
//! One `vec0` table per generation (`embedding_generations.id`), not one
//! shared table: `vec0`'s `float[N]` column width is fixed per table, and a
//! future generation may carry a different `dim` (different embedder).
//! Table naming encodes the generation id so multiple generations' indexes
//! can coexist during the delayed-cleanup window (W3-4).

use super::api::{Conn, StorageError, Tx, TxMode, Value, params};

/// `vec0` table name for a given generation. `doc_id` (not a synthetic
/// autoincrement id) is used as the table's `rowid` on insert — unique
/// within one generation's table by construction (`message_embeddings`'
/// own `UNIQUE(generation_id, doc_id)`), so no separate id-mapping table is
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

/// Create (idempotently) the `vec0` virtual table for `generation_id` with
/// the given embedding dimension. Cosine distance metric (KU2's validated
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
    let table = vec0_table_name(generation_id);
    conn.execute_batch(&format!(
        "CREATE VIRTUAL TABLE IF NOT EXISTS {table} USING vec0(embedding float[{dim}] distance_metric=cosine);"
    ))
}

/// Drop the `vec0` virtual table for `generation_id`, if it exists.
/// `DROP TABLE` on a `vec0` virtual table also drops its shadow tables
/// (verified empirically by
/// [`vec0_shadow_tables_are_fully_enumerated_and_fully_dropped`] below —
/// w3-d8①: shadow-table behavior is taken on real `sqlite3` enumeration,
/// never assumed from documentation).
pub fn drop_vec0_table_for_generation(
    conn: &Conn,
    generation_id: i64,
) -> Result<(), StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    let table = vec0_table_name(generation_id);
    conn.execute_batch(&format!("DROP TABLE IF EXISTS {table};"))
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
    tx.execute_batch(&format!("DROP TABLE IF EXISTS {table};"))
}

/// Real `sqlite_master` enumeration of `generation_id`'s `vec0` table and
/// every shadow table it owns (w3-d8① discipline: never hardcode a shadow
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
    conn.query_all_map(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE ?1 ORDER BY rowid",
        &params![like_pattern],
        |row| row.get_typed(0),
    )
}

/// Row count of `generation_id`'s main `vec0` table (never a shadow
/// table) -- the exact same table [`rebuild_vec0_table_for_generation`]
/// populates and [`vec0_knn`] scans. Activation audit check ⑦ (R1-W3-B5)
/// compares this against `COUNT(*) FROM message_embeddings WHERE
/// generation_id = ?`: every other check either reads `message_embeddings`
/// directly or probes `vec0` for one specific row's presence, so none of
/// them would ever notice `vec0` missing rows wholesale (a rebuild that
/// silently populated fewer rows than it read, or one that was simply
/// never re-run after `message_embeddings` grew). Errors (most commonly
/// "no such table" if the `vec0` table was never created for this
/// generation) propagate as `StorageError`, not `Ok(0)` -- a missing
/// table is a different failure than a genuinely empty one and callers
/// must be able to tell them apart.
pub fn count_vec0_rows_for_generation(conn: &Conn, generation_id: i64) -> Result<i64, StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    let table = vec0_table_name(generation_id);
    conn.query_row_map(&format!("SELECT COUNT(*) FROM {table}"), &[], |row| row.get_typed(0))
}

/// R2-B4: bidirectional identity-set anti-join between `message_embeddings`
/// and `generation_id`'s `vec0` table -- activation audit check ⑦'s
/// original `COUNT(*)` comparison ([`count_vec0_rows_for_generation`] vs.
/// `COUNT(*) FROM message_embeddings`) only catches a *size* mismatch. An
/// equal-size swap (N rows missing from one side exactly offset by N
/// different extra rows on the other -- e.g. a rebuild racing a concurrent
/// forget/replace that drops doc A and adds doc B between the read and the
/// populate) sails through a plain count comparison with both sides
/// reporting the same number, passing an audit over a `vec0` index that is
/// silently indexing the wrong document for at least one entry. Same
/// "same size != same set" discipline check ④
/// ([`eligible_not_embedded_count`]/[`embedded_not_eligible_count`] in
/// `db_vector_catchup.rs`) already applies one layer up, in
/// `message_embeddings` vs. eligibility; this closes the analogous gap one
/// layer down, between `message_embeddings` and its derived `vec0` index.
///
/// Returns `(missing_from_vec0, extra_in_vec0)`: the count of
/// `message_embeddings` doc_ids for `generation_id` absent from `vec0`'s
/// rowid set, and the count of `vec0` rowids absent from
/// `message_embeddings`'s doc_id set for `generation_id`. Both must be `0`
/// for the two sides to hold the identical identity set; `vec0`'s `rowid`
/// is `message_embeddings.doc_id` by construction
/// ([`rebuild_vec0_table_for_generation`]'s `INSERT INTO {table}(rowid,
/// embedding)`), so a plain `NOT EXISTS` anti-join on `rowid = doc_id` is
/// exact, not an approximation.
pub fn count_vec0_message_embeddings_set_mismatch_for_generation(
    conn: &Conn,
    generation_id: i64,
) -> Result<(i64, i64), StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    let table = vec0_table_name(generation_id);
    let missing_from_vec0: i64 = conn.query_row_map(
        &format!(
            "SELECT COUNT(*) FROM message_embeddings me \
             WHERE me.generation_id = ?1 \
               AND NOT EXISTS (SELECT 1 FROM {table} v WHERE v.rowid = me.doc_id)"
        ),
        &params![generation_id],
        |row| row.get_typed(0),
    )?;
    let extra_in_vec0: i64 = conn.query_row_map(
        &format!(
            "SELECT COUNT(*) FROM {table} v \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM message_embeddings me \
                 WHERE me.generation_id = ?1 AND me.doc_id = v.rowid \
             )"
        ),
        &params![generation_id],
        |row| row.get_typed(0),
    )?;
    Ok((missing_from_vec0, extra_in_vec0))
}

/// Rebuild `generation_id`'s `vec0` index from `message_embeddings` in one
/// transaction (drop + recreate + bulk-populate) — w3-d9②'s atomicity
/// discipline: an interruption anywhere in this function leaves the
/// generation's `vec0` table exactly as it was before the call (either
/// still the old one, if this was a true rebuild, or absent, if it never
/// existed), never a half-populated table masquerading as complete. A
/// retry after interruption starts over cleanly — no resumable/checkpoint
/// state is kept (w3-d3②).
///
/// The embedding BLOB is copied verbatim from `message_embeddings.embedding`
/// into `vec0`'s `embedding` column with no decode/re-encode round trip:
/// both are little-endian packed `f32` arrays by construction (W3-1's
/// `byte_order='le'` convention matches `vec0`'s `float[N]` column format
/// exactly), so the same bytes that passed W3-1's write-side finite/norm
/// validation are what `vec0` indexes.
///
/// Returns the number of rows populated.
pub fn rebuild_vec0_table_for_generation(
    conn: &Conn,
    generation_id: i64,
    dim: i64,
) -> Result<usize, StorageError> {
    validate_generation_id_for_ddl(generation_id)?;
    if dim <= 0 {
        return Err(reject(format!("dim must be positive, got {dim}")));
    }
    let table = vec0_table_name(generation_id);

    conn.with_tx_no_replay(TxMode::Immediate, |tx| {
        tx.execute_batch(&format!("DROP TABLE IF EXISTS {table};"))?;
        tx.execute_batch(&format!(
            "CREATE VIRTUAL TABLE {table} USING vec0(embedding float[{dim}] distance_metric=cosine);"
        ))?;

        let rows: Vec<(i64, Vec<u8>)> = tx.query_all_map(
            "SELECT doc_id, embedding FROM message_embeddings WHERE generation_id = ?1",
            &params![generation_id],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )?;

        let insert_sql = format!("INSERT INTO {table}(rowid, embedding) VALUES (?1, ?2)");
        for (doc_id, embedding) in &rows {
            tx.execute(&insert_sql, &[Value::from(*doc_id), Value::from(embedding.clone())])?;
        }

        Ok(rows.len())
    })
}

/// One `vec0` KNN hit: `(doc_id, distance)`, ascending distance (nearest
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
            schema::create_embedding_generation(tx, "bge-m3", dim, 1, 1_000)
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
        assert_eq!(
            names,
            vec![
                table.clone(),
                format!("{table}_info"),
                format!("{table}_chunks"),
                format!("{table}_rowids"),
                format!("{table}_vector_chunks00"),
            ],
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
    fn rebuild_populates_from_message_embeddings_and_knn_finds_the_nearest_match() {
        let (_dir, conn) = scratch_conn();
        insert_message_parent_chain(&conn, 1, 1, 1);
        insert_message_parent_chain(&conn, 1, 1, 2);
        insert_message_parent_chain(&conn, 1, 1, 3);
        let gen_id = create_generation(&conn, 4);

        conn.with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::insert_message_embedding(tx, gen_id, 1, 1, &[1.0, 0.0, 0.0, 0.0], "h1", None, 1_000)?;
            schema::insert_message_embedding(tx, gen_id, 2, 1, &[0.0, 1.0, 0.0, 0.0], "h2", None, 1_000)?;
            schema::insert_message_embedding(tx, gen_id, 3, 1, &[0.9, 0.1, 0.0, 0.0], "h3", None, 1_000)?;
            Ok(())
        })
        .unwrap();

        let populated = rebuild_vec0_table_for_generation(&conn, gen_id, 4).expect("rebuild");
        assert_eq!(populated, 3, "all three rows for this generation must be populated");

        // Query near doc_id=1's vector -- doc_id=3 (0.9,0.1,0,0) is the
        // closer neighbor by cosine distance, doc_id=1 (1,0,0,0) is exact.
        let hits = vec0_knn(&conn, gen_id, &[1.0, 0.0, 0.0, 0.0], 2).expect("knn query");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].0, 1, "the exact match (doc_id=1) must rank first");
        assert!(hits[0].1 < hits[1].1, "distances must be ascending (nearest first)");
        let doc_ids: Vec<i64> = hits.iter().map(|(id, _)| *id).collect();
        assert!(doc_ids.contains(&3), "doc_id=3 (near-duplicate) must be the second hit, got {doc_ids:?}");
    }

    #[test]
    fn rebuild_only_indexes_rows_for_the_target_generation_not_other_generations() {
        let (_dir, conn) = scratch_conn();
        insert_message_parent_chain(&conn, 1, 1, 1);
        insert_message_parent_chain(&conn, 1, 1, 2);
        let gen_a = create_generation(&conn, 4);
        let gen_b = create_generation(&conn, 4);

        conn.with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::insert_message_embedding(tx, gen_a, 1, 1, &[1.0, 0.0, 0.0, 0.0], "h1", None, 1_000)?;
            schema::insert_message_embedding(tx, gen_b, 2, 1, &[0.0, 1.0, 0.0, 0.0], "h2", None, 1_000)?;
            Ok(())
        })
        .unwrap();

        let populated_a = rebuild_vec0_table_for_generation(&conn, gen_a, 4).unwrap();
        assert_eq!(populated_a, 1, "generation A's vec0 table must only get generation A's row");

        let hits = vec0_knn(&conn, gen_a, &[0.0, 1.0, 0.0, 0.0], 10).unwrap();
        let doc_ids: Vec<i64> = hits.iter().map(|(id, _)| *id).collect();
        assert_eq!(doc_ids, vec![1], "generation A's index must never contain generation B's doc_id=2 row");
    }

    #[test]
    fn rebuild_is_repeatable_and_replaces_stale_data() {
        let (_dir, conn) = scratch_conn();
        insert_message_parent_chain(&conn, 1, 1, 1);
        insert_message_parent_chain(&conn, 1, 1, 2);
        let gen_id = create_generation(&conn, 4);

        conn.with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::insert_message_embedding(tx, gen_id, 1, 1, &[1.0, 0.0, 0.0, 0.0], "h1", None, 1_000)
        })
        .unwrap();
        let first = rebuild_vec0_table_for_generation(&conn, gen_id, 4).unwrap();
        assert_eq!(first, 1);

        conn.with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::insert_message_embedding(tx, gen_id, 2, 1, &[0.0, 1.0, 0.0, 0.0], "h2", None, 1_000)
        })
        .unwrap();
        let second = rebuild_vec0_table_for_generation(&conn, gen_id, 4).expect("rebuild after new writes");
        assert_eq!(second, 2, "rebuild must reflect newly written rows, not stale pre-rebuild state");

        let hits = vec0_knn(&conn, gen_id, &[0.0, 1.0, 0.0, 0.0], 10).unwrap();
        assert_eq!(hits.len(), 2, "the rebuilt index must contain both rows, not just the first rebuild's snapshot");
    }
}
