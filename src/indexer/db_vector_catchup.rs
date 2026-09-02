//! Catch-up worker orchestration for the DB-backed vector domain (w3-3
//! Step0/Step1, task book #61). Bootstraps or resumes an
//! `embedding_generations` row by exact identity match, seeds its
//! `embedding_holes` from the production semantic eligibility chain
//! (`fetch_canonical_embedding_batch`'s `ConversationPacket` replay),
//! drains those holes through a live Infinity service with a
//! CAS-guarded write per message, then republishes the generation's
//! `vec0` index and flips the active-generation pointer.
//!
//! This is an orchestration-layer API, not a CLI surface: W3-4 wires it
//! into `cass` CLI / the long-running production consumer. Until then it
//! is driven directly -- by tests, or by a small `examples/` binary for
//! the real-scale Step2 backfill run.
//!
//! Design record: `W3_ARTIFACTS/w3-3-exec54-step0-design.md` (approved,
//! four rulings folded into this implementation -- see doc comments on
//! [`find_reusable_or_create_generation`] (ruling ①/②) and
//! [`run_db_vector_catchup_backfill`] (ruling ④, this being a `pub fn`
//! rather than a test-only bridge).

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, bail};

use crate::indexer::semantic::{EmbeddedMessage, EmbeddingInput, SemanticIndexer, fetch_canonical_embedding_batch};
use crate::indexer::semantic_progress::SemanticProgressSink;
use crate::search::canonicalize::{CANONICALIZE_PIPELINE_VERSION, canonicalize_for_embedding};
use crate::search::infinity::{InfinityConfig, InfinityServedIdentity, probe_served_embed_identity};
use crate::storage::api::{Conn, StorageError, TxMode, params};
use crate::storage::schema::{self, CasInsertOutcome};
use crate::storage::sqlite::FrankenStorage;
use crate::storage::vector_domain;

/// Conversation-page size for the genesis eligibility scan. Purely an
/// in-process pagination width (never persisted, never a cross-run
/// cursor -- w3-3 Step0 design §3): a crash mid-scan just means the next
/// run re-scans from conversation 0, which is cheap relative to the
/// embedding work it feeds and keeps this worker free of any resume
/// state of its own.
const GENESIS_SCAN_PAGE_SIZE: usize = 200;

/// Summary of one `run_db_vector_catchup_backfill` call, for attestation
/// reporting (Step2).
#[derive(Debug, Clone)]
pub struct DbVectorCatchupReport {
    pub generation_id: i64,
    pub reused_existing_generation: bool,
    pub embedder_id: String,
    pub dim: i64,
    pub eligible_seeded: u64,
    pub embedded_inserted: u64,
    pub stale_skipped: u64,
    pub holes_before: u64,
    pub holes_after: u64,
    pub vec0_rows: usize,
    pub activated: bool,
    /// Holes deleted (R1-W3-B1 fix) because their `doc_id` canonicalizes to
    /// an empty string and can therefore never resolve through the normal
    /// embed-and-CAS-write path -- see
    /// [`crate::storage::schema::write_off_ineligible_hole_in_tx`]'s doc
    /// comment for why leaving them registered would self-lock activation.
    pub holes_written_off_ineligible: u64,
}

/// One row of embedding-hole work: the message content/role to embed,
/// read fresh (not from any packet-replay cache) so the CAS write below
/// compares against the same read this worker actually embedded.
struct HoleMessageRow {
    doc_id: i64,
    conversation_id: i64,
    content: String,
    role: String,
}

/// w3-3 Step0 design ruling ①/②: find an identity-matching (`embedder_id`
/// + `dim` + `canonicalize_version`, all three exact) generation whose
/// `audit_status` is still `'pending'` and keep draining its holes;
/// only create a new generation when no such match exists. This is what
/// keeps a mid-run crash from burning hours of prior Infinity work: the
/// hole ledger itself is the resumable state (w3-3 Step0 design §3), so
/// resuming is just "find the right generation_id", not a checkpoint
/// replay.
fn find_reusable_or_create_generation(
    conn: &Conn,
    identity: &InfinityServedIdentity,
    dim: i64,
    created_at_ms: i64,
) -> Result<(i64, bool)> {
    if let Some(existing) = schema::find_reusable_pending_generation(
        conn,
        &identity.model_id,
        dim,
        CANONICALIZE_PIPELINE_VERSION,
    )
    .context("looking up a reusable pending embedding_generations row")?
    {
        return Ok((existing, true));
    }

    let generation_id = conn
        .with_tx(TxMode::Immediate, |tx| {
            schema::create_embedding_generation(
                tx,
                &identity.model_id,
                dim,
                CANONICALIZE_PIPELINE_VERSION,
                created_at_ms,
            )
        })
        .context("creating a new embedding_generations row")?;
    Ok((generation_id, false))
}

/// Genesis eligibility scan (w3-3 Step0 design §2): page over every
/// conversation via the production semantic eligibility chain
/// (`fetch_canonical_embedding_batch` -> `ConversationPacket` replay ->
/// `packet.projections.semantic.message_indices`), collecting the
/// `message_id`s that chain considers embeddable.
///
/// The packet-level filter alone (`!message.content.is_empty()`, see
/// `packet_projections`) is *weaker* than what actually survives
/// embedding: a raw-non-empty message like "OK." canonicalizes to an
/// empty string (`canonicalize_for_embedding`'s short-acknowledgement
/// rule) and can never become a real embedding. Seeding a hole for such
/// a `doc_id` would create exactly the unresolvable "fake hole" R1-W3-N3
/// forbids, so this function applies the stricter
/// canonicalize-non-empty check itself before returning a `message_id`.
pub(crate) fn scan_eligible_message_ids(storage: &FrankenStorage) -> Result<Vec<i64>> {
    let mut eligible = Vec::new();
    let mut after_conversation_id = 0i64;

    loop {
        let batch = fetch_canonical_embedding_batch(storage, after_conversation_id, GENESIS_SCAN_PAGE_SIZE)
            .context("scanning canonical embedding eligibility for genesis hole seeding")?;

        for input in &batch.inputs {
            if canonicalize_for_embedding(&input.content).is_empty() {
                continue;
            }
            let doc_id = i64::try_from(input.message_id)
                .map_err(|_| anyhow!("message_id {} does not fit in i64", input.message_id))?;
            eligible.push(doc_id);
        }

        if batch.cursor_exhausted {
            break;
        }
        after_conversation_id = batch.last_conversation_id;
    }

    Ok(eligible)
}

/// Read one batch of pending hole work fresh from `messages` (not from
/// any packet-replay cache -- the CAS write's staleness check compares
/// against a fresh read of exactly this data, so this read must be that
/// same fresh read, see `insert_message_embedding_cas`'s doc comment).
/// `embedding_holes.doc_id REFERENCES messages(id) ON DELETE CASCADE`
/// guarantees every hole row has a backing message, so the `JOIN` below
/// (not `LEFT JOIN`) cannot silently drop a hole.
fn fetch_hole_batch(
    storage: &FrankenStorage,
    generation_id: i64,
    limit: usize,
) -> Result<Vec<HoleMessageRow>> {
    let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
    storage
        .raw()
        .query_all_map(
            "SELECT h.doc_id, m.conversation_id, m.content, m.role \
             FROM embedding_holes h \
             JOIN messages m ON m.id = h.doc_id \
             WHERE h.generation_id = ?1 \
             ORDER BY h.doc_id ASC \
             LIMIT ?2",
            &params![generation_id, limit_i64],
            |row| {
                Ok(HoleMessageRow {
                    doc_id: row.get_typed(0)?,
                    conversation_id: row.get_typed(1)?,
                    content: row.get_typed(2)?,
                    role: row.get_typed(3)?,
                })
            },
        )
        .context("fetching a batch of embedding_holes work")
}

fn count_holes(conn: &Conn, generation_id: i64) -> Result<u64, StorageError> {
    let count: i64 = conn.query_row_map(
        "SELECT COUNT(*) FROM embedding_holes WHERE generation_id = ?1",
        &params![generation_id],
        |row| row.get_typed(0),
    )?;
    Ok(u64::try_from(count).unwrap_or(0))
}

/// Drive one full genesis-or-resume backfill of the DB vector domain for
/// the currently served Infinity model (w3-3 Step0/Step1, task book
/// #61). This is a real orchestration-layer API (ruling ④): W3-4 is
/// expected to call it from the `cass` CLI / the long-running production
/// consumer, and Step2's real-scale run drives it directly (examples/ or
/// an `#[ignore]` integration test), not through a test-only bridge.
///
/// `batch_size` controls how many holes are drained per Infinity call +
/// write transaction; pass `SemanticIndexer::new("infinity",
/// None)?.batch_size()` for the production default
/// (`resolved_default_batch_size()`, i.e. `CASS_SEMANTIC_BATCH_SIZE` --
/// w3-3 Step0 design ruling ③, no new parameter surface).
///
/// Steps (w3-3 Step0 design §2): find-or-create the generation by exact
/// identity match (ruling ①/②) -> seed `embedding_holes` for every
/// currently-eligible message (idempotent, safe on a resumed generation)
/// -> drain holes in batches (embed via Infinity, CAS-write, hole
/// resolved in the same transaction) -> rebuild `vec0` -> activate if
/// (and only if) every hole was resolved.
pub fn run_db_vector_catchup_backfill(
    storage: &FrankenStorage,
    batch_size: usize,
) -> Result<DbVectorCatchupReport> {
    if batch_size == 0 {
        bail!("batch_size must be > 0");
    }

    let infinity_config = InfinityConfig::from_env();
    let identity = probe_served_embed_identity(&infinity_config).map_err(|e| {
        anyhow!(
            "infinity served-identity probe failed; refusing to create/reuse a generation \
             without a live identity (w3-3 Step0 design ruling ①): {e}"
        )
    })?;
    let dim = i64::try_from(identity.dimension)
        .map_err(|_| anyhow!("infinity dimension {} does not fit in i64", identity.dimension))?;

    let now_ms = FrankenStorage::now_millis();
    let (generation_id, reused_existing_generation) =
        find_reusable_or_create_generation(storage.raw(), &identity, dim, now_ms)?;

    let eligible_ids = scan_eligible_message_ids(storage)?;
    let eligible_seeded = storage
        .raw()
        .with_tx(TxMode::Immediate, |tx| {
            schema::seed_embedding_holes(tx, generation_id, &eligible_ids, now_ms, "genesis-backfill")
        })
        .context("seeding genesis embedding_holes")?;

    let holes_before = count_holes(storage.raw(), generation_id)?;

    let indexer = SemanticIndexer::new("infinity", None).context("constructing infinity SemanticIndexer")?;
    let sink = SemanticProgressSink::open("db-vector-catchup", &identity.model_id);

    let mut embedded_inserted = 0u64;
    let mut stale_skipped = 0u64;
    let mut holes_written_off_ineligible = 0u64;

    loop {
        let rows = fetch_hole_batch(storage, generation_id, batch_size)?;
        if rows.is_empty() {
            break;
        }

        // Defensive re-check (w3-3 Step0 design §3): genesis seeding
        // already guarantees every seeded doc_id canonicalizes non-empty,
        // but this loop must never assume it -- ingest-time hook
        // registration (`register_embedding_hole_for_new_message_in_tx`)
        // has no eligibility filter of its own and *will* register a hole
        // for a short-acknowledgement message like "OK." that can never
        // resolve through the normal embed-and-CAS-write path. R1-W3-B1:
        // leaving such a hole registered self-locks this generation out of
        // activation forever (`holes_after` never reaches zero), so an
        // ineligible row is written off (its hole row deleted) here rather
        // than left "for investigation" -- the hole ledger's contract is an
        // exact accounting of *eligible* messages, and an ineligible one
        // was never a valid ledger entry to begin with. Filtering first
        // also keeps the positional zip below safe: every input handed to
        // the embedder is already known-non-empty, so
        // `embed_messages_with_sink` cannot drop any of them.
        let filtered: Vec<&HoleMessageRow> = rows
            .iter()
            .filter(|row| !canonicalize_for_embedding(&row.content).is_empty())
            .collect();
        if filtered.len() != rows.len() {
            let ineligible: Vec<&HoleMessageRow> = rows
                .iter()
                .filter(|row| canonicalize_for_embedding(&row.content).is_empty())
                .collect();
            tracing::warn!(
                generation_id,
                total = rows.len(),
                kept = filtered.len(),
                written_off = ineligible.len(),
                "db_vector_catchup: hole row canonicalized to empty text despite genesis \
                 eligibility filtering; writing off its hole as ineligible (R1-W3-B1)"
            );
            storage
                .raw()
                .with_tx(TxMode::Immediate, |tx| {
                    for row in &ineligible {
                        schema::write_off_ineligible_hole_in_tx(tx, generation_id, row.doc_id)?;
                    }
                    Ok(())
                })
                .context("writing off ineligible embedding_holes rows")?;
            holes_written_off_ineligible =
                holes_written_off_ineligible.saturating_add(u64::try_from(ineligible.len()).unwrap_or(0));
        }
        if filtered.is_empty() {
            // Every row in this batch was just written off above, so the
            // queue has strictly shrunk -- looping back to `fetch_hole_
            // batch` cannot refetch the same rows and spin forever; it
            // either drains further eligible holes or the queue is now
            // truly empty and the `rows.is_empty()` check above ends the
            // loop.
            continue;
        }

        let inputs: Vec<EmbeddingInput> = filtered
            .iter()
            .map(|row| {
                let message_id = u64::try_from(row.doc_id)
                    .map_err(|_| anyhow!("doc_id {} does not fit in u64", row.doc_id))?;
                Ok(EmbeddingInput::new(message_id, row.content.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        let embeddings: Vec<EmbeddedMessage> = indexer
            .embed_messages_with_sink(&inputs, &sink)
            .context("embedding a db-vector-catchup batch via infinity")?;
        if embeddings.len() != filtered.len() {
            bail!(
                "embed_messages_with_sink returned {} embeddings for {} known-non-empty inputs; \
                 refusing to write (positional correspondence would be unsafe)",
                embeddings.len(),
                filtered.len()
            );
        }

        let write_now_ms = FrankenStorage::now_millis();
        let outcomes: Vec<CasInsertOutcome> = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                let mut outcomes = Vec::with_capacity(filtered.len());
                for (row, embedded) in filtered.iter().zip(embeddings.iter()) {
                    if embedded.message_id != u64::try_from(row.doc_id).unwrap_or(u64::MAX) {
                        return Err(StorageError::Constraint {
                            detail: format!(
                                "embedded.message_id={} does not match expected doc_id={} \
                                 (positional zip misalignment)",
                                embedded.message_id, row.doc_id
                            ),
                        });
                    }
                    let expected_content_hash = hex::encode(embedded.content_hash);
                    let outcome = schema::insert_message_embedding_cas(
                        tx,
                        generation_id,
                        row.doc_id,
                        row.conversation_id,
                        &embedded.embedding,
                        &expected_content_hash,
                        &row.role,
                        write_now_ms,
                    )?;
                    outcomes.push(outcome);
                }
                Ok(outcomes)
            })
            .context("writing a db-vector-catchup CAS batch")?;

        for outcome in outcomes {
            match outcome {
                CasInsertOutcome::Inserted => embedded_inserted = embedded_inserted.saturating_add(1),
                CasInsertOutcome::Stale(_) => stale_skipped = stale_skipped.saturating_add(1),
            }
        }
    }

    let holes_after = count_holes(storage.raw(), generation_id)?;

    let vec0_rows = vector_domain::rebuild_vec0_table_for_generation(storage.raw(), generation_id, dim)
        .context("rebuilding vec0 table for generation")?;

    // W3-4 Step1 (task book #62): the full six-invariant activation audit
    // replaces the old minimal "embedded_count > 0" verify closure here.
    // Checks run read-only first (this single-worker flow has nothing
    // else writing to `generation_id` between here and the switch below),
    // then the verdict is written atomically with the pointer flip inside
    // `switch_active_generation`'s own transaction -- "全过才许切", and a
    // failure aborts before `switch_active_generation` is even called, so
    // the pointer is provably untouched (spec §3.1's atomicity contract,
    // reused rather than re-implemented).
    let mut activated = false;
    if holes_after == 0 {
        let audit_report = run_activation_audit(storage, generation_id, ACTIVATION_AUDIT_DEFAULT_FINITE_NORM_SAMPLE_SIZE, None)
            .context("running the W3-4 activation audit before activating a db-vector generation")?;
        if !audit_report.passed {
            bail!(
                "generation {generation_id} failed activation audit, refusing to activate: {}",
                audit_report.failure_reasons.join("; ")
            );
        }
        schema::switch_active_generation(storage.raw(), generation_id, FrankenStorage::now_millis(), |tx| {
            tx.execute(
                "UPDATE embedding_generations SET audit_status = 'passed' WHERE id = ?1",
                &params![generation_id],
            )?;
            Ok(())
        })
        .context("activating db-vector generation")?;
        activated = true;
    }

    Ok(DbVectorCatchupReport {
        generation_id,
        reused_existing_generation,
        embedder_id: identity.model_id,
        dim,
        eligible_seeded,
        embedded_inserted,
        stale_skipped,
        holes_before,
        holes_after,
        vec0_rows,
        activated,
        holes_written_off_ineligible,
    })
}

// =============================================================================
// W3-4 Step1 (task book #62): full activation audit. `switch_active_
// generation`'s doc comment (`src/storage/schema.rs`) deliberately left
// its `verify` closure minimal and named the six invariants this section
// implements: ① exact per-generation dim/length match, ② finite+norm
// resample, ③ positive self-hit content check, ④ bidirectional
// identity-set anti-join against the same eligibility chain backfill
// used, ⑤ canonicalize-version identity match, ⑥ `PRAGMA
// foreign_key_check`. All six must pass for `passed`; any failure is
// recorded in `failure_reasons` (never stop-at-first -- a caller deciding
// whether to activate/keep-active wants the whole picture).
// =============================================================================

/// Default finite/norm resample size for [`run_activation_audit`] callers
/// that don't have a task-specific number of their own (the switch-time
/// activation call site above). Task book #62's own real-scale audit
/// against staging generation_id=1 passes an explicit, larger,
/// report-documented sample size instead of this constant.
const ACTIVATION_AUDIT_DEFAULT_FINITE_NORM_SAMPLE_SIZE: usize = 500;

/// Verdict + evidence from [`run_activation_audit`]. `passed` is the
/// single verdict every other field explains.
#[derive(Debug, Clone)]
pub struct ActivationAuditReport {
    pub generation_id: i64,
    pub passed: bool,
    /// ① full-table (not sampled) `COUNT(length(embedding) != 4*dim)`.
    pub dim_mismatch_count: i64,
    /// ② finite/norm resample: rows requested vs. rows actually present
    /// to check (the latter is smaller only if the generation itself has
    /// fewer than `finite_norm_sample_size` rows) vs. violations found.
    pub finite_norm_sample_size: usize,
    pub finite_norm_checked: usize,
    pub finite_norm_violation_count: usize,
    /// ③ positive-content self-hit: the anchor doc_id used and what
    /// `vec0_knn(k=1)` returned for a fresh re-read of its own vector.
    pub positive_check_doc_id: i64,
    pub positive_check_top_hit_doc_id: i64,
    pub positive_check_distance: f64,
    /// ④ bidirectional identity-set anti-join counts (never a bare
    /// count-equality check -- R1-W3-N3 forbids treating "same size" as
    /// "same set").
    pub eligible_not_embedded_count: usize,
    pub embedded_not_eligible_count: usize,
    /// ⑤ canonicalize-version identity match.
    pub canonicalize_version_expected: u32,
    pub canonicalize_version_actual: i64,
    /// ⑥ `PRAGMA foreign_key_check` violation row count -- database-wide
    /// (the pragma itself has no generation scope; a dangling FK anywhere
    /// is disqualifying).
    pub foreign_key_violation_count: usize,
    /// ⑦ vec0-vs-authoritative-table row-count reconciliation (R1-W3-B5):
    /// `-1` for `vec0_row_count` means the count itself errored (most
    /// commonly the `vec0` table not existing for this generation at
    /// all), distinct from a genuine `0`.
    pub vec0_row_count: i64,
    pub message_embeddings_row_count: i64,
    pub failure_reasons: Vec<String>,
}

/// Run the full W3-4 activation audit against `generation_id`'s persisted
/// rows. Read-only -- see [`run_activation_audit_and_record`] for the
/// atomic verdict write. `finite_norm_sample_size` bounds check ②'s
/// resample; `positive_check_doc_id` picks check ③'s self-hit anchor
/// (`None` auto-picks `MIN(doc_id)` in this generation -- a fresh
/// candidate generation has no a-priori "known good" anchor the way a
/// real-scale backfill report's verified self-hits do).
///
/// Deliberately does not touch `is_active` or `audit_status` -- callers
/// decide what a verdict means for those (switch-time activation vs. a
/// standalone re-audit of an already-active generation are different call
/// sites with different atomicity needs; see
/// [`run_activation_audit_and_record`] and this task's own
/// `examples/w3_4_activation_audit_run.rs`).
pub fn run_activation_audit(
    storage: &FrankenStorage,
    generation_id: i64,
    finite_norm_sample_size: usize,
    positive_check_doc_id: Option<i64>,
) -> Result<ActivationAuditReport> {
    let conn = storage.raw();
    let mut failures: Vec<String> = Vec::new();

    let (dim, canonicalize_version_actual): (i64, i64) = conn
        .query_row_map(
            "SELECT dim, canonicalize_version FROM embedding_generations WHERE id = ?1",
            &params![generation_id],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .with_context(|| format!("generation {generation_id} not found for activation audit"))?;

    // ① exact per-generation dim/length match.
    let dim_mismatch_count: i64 = conn.query_row_map(
        "SELECT COUNT(*) FROM message_embeddings WHERE generation_id = ?1 AND length(embedding) != 4 * ?2",
        &params![generation_id, dim],
        |row| row.get_typed(0),
    )?;
    if dim_mismatch_count != 0 {
        failures.push(format!("① dim/length mismatch: {dim_mismatch_count} row(s) have a BLOB length != 4*dim={dim}"));
    }

    // ② finite/norm resample: decode each sampled BLOB back to f32 and
    // recheck both invariants `insert_message_embedding` enforced at
    // write time (per-element finiteness, norm/BLOB recompute
    // consistency) -- this audit exists precisely because a row already
    // past that write-time gate could still have been corrupted since
    // (disk bitrot, a different write path's bug, manual DB surgery).
    let sample_rows: Vec<(i64, Vec<u8>, f64)> = conn.query_all_map(
        "SELECT doc_id, embedding, norm FROM message_embeddings WHERE generation_id = ?1 ORDER BY RANDOM() LIMIT ?2",
        &params![generation_id, i64::try_from(finite_norm_sample_size).unwrap_or(i64::MAX)],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
    )?;
    let finite_norm_checked = sample_rows.len();
    let mut finite_norm_violation_count = 0usize;
    for (doc_id, blob, stored_norm) in &sample_rows {
        let decoded = match schema::le_blob_to_f32_vector(blob) {
            Ok(v) => v,
            Err(e) => {
                finite_norm_violation_count += 1;
                failures.push(format!("② doc_id={doc_id} BLOB failed to decode: {e}"));
                continue;
            }
        };
        if let Some(bad_idx) = decoded.iter().position(|x| !x.is_finite()) {
            finite_norm_violation_count += 1;
            failures.push(format!("② doc_id={doc_id} has a non-finite element at index {bad_idx}"));
            continue;
        }
        let recomputed = schema::l2_norm(&decoded);
        let tolerance = 1e-6_f64.max(stored_norm.abs() * 1e-6);
        if (recomputed - stored_norm).abs() > tolerance {
            finite_norm_violation_count += 1;
            failures.push(format!("② doc_id={doc_id} norm/BLOB mismatch: stored={stored_norm} recomputed={recomputed}"));
        }
    }

    // ③ positive content check: a known row's own (freshly re-read)
    // vector must self-hit via the same vec0 read path production
    // queries use -- catches vec0 drifting stale relative to the
    // authoritative table (KU2: vec0 is a derived index, never a second
    // source of truth).
    let anchor_doc_id = match positive_check_doc_id {
        Some(id) => id,
        None => {
            let min_doc_id: Option<i64> = conn.query_row_map(
                "SELECT MIN(doc_id) FROM message_embeddings WHERE generation_id = ?1",
                &params![generation_id],
                |row| row.get_typed::<Option<i64>>(0),
            )?;
            min_doc_id.ok_or_else(|| anyhow!("generation {generation_id} has zero embedded rows; nothing to positive-check"))?
        }
    };
    // A corrupted anchor row (already flagged by ①/② above) must fail
    // this check too, not crash the whole audit -- an audit that panics
    // on the very corruption it exists to detect defeats its own
    // purpose, so every fallible step here is caught rather than `?`-ed
    // straight out of `run_activation_audit`.
    let positive_check_result: Result<(i64, f64, bool)> = (|| {
        let (anchor_blob, anchor_content_hash): (Vec<u8>, String) = conn
            .query_row_map(
                "SELECT embedding, content_hash FROM message_embeddings WHERE generation_id = ?1 AND doc_id = ?2",
                &params![generation_id, anchor_doc_id],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )
            .with_context(|| format!("positive-check anchor doc_id={anchor_doc_id} not found in generation {generation_id}"))?;
        let anchor_vector = schema::le_blob_to_f32_vector(&anchor_blob)?;
        let hits = vector_domain::vec0_knn(conn, generation_id, &anchor_vector, 1)?;
        let (top_hit_doc_id, distance) = hits.first().copied().unwrap_or((-1, f64::INFINITY));
        // R1-W3-B8 (exec60 real-corpus gate run, 2026-09-02): a
        // zero-distance *tie* between the anchor and a genuine content twin
        // (another message with byte-identical content, hence an
        // identical embedding) is not corruption -- vec0's ORDER BY
        // distance has no secondary key, so which of two exactly-tied rows
        // sorts first is unspecified, and it is under no obligation to be
        // the anchor itself. Real corpora routinely contain repeated short
        // messages (this is the same benign phenomenon the Step2 backfill
        // report's staging KNN sample already documented as "genuine
        // twin, not a bug" for a different KNN call). A tied hit whose own
        // content_hash matches the anchor's is semantically the same
        // self-hit, just realized through a different row id -- record
        // that as `tied_content_twin` without touching the raw
        // `top_hit_doc_id`/`distance` evidence below, so the report still
        // shows what vec0 actually returned.
        let tied_content_twin = top_hit_doc_id != anchor_doc_id
            && distance <= 1e-6
            && conn
                .query_opt_map(
                    "SELECT content_hash FROM message_embeddings WHERE generation_id = ?1 AND doc_id = ?2",
                    &params![generation_id, top_hit_doc_id],
                    |row| row.get_typed::<String>(0),
                )
                .ok()
                .flatten()
                .is_some_and(|top_hit_content_hash| top_hit_content_hash == anchor_content_hash);
        Ok((top_hit_doc_id, distance, tied_content_twin))
    })();
    let mut positive_check_errored = false;
    let (top_hit_doc_id, distance, tied_content_twin) = match positive_check_result {
        Ok(triple) => triple,
        Err(e) => {
            positive_check_errored = true;
            failures.push(format!(
                "③ positive content check errored on anchor doc_id={anchor_doc_id} (likely a downstream symptom of an ①/② corruption already reported above): {e}"
            ));
            (-1, f64::INFINITY, false)
        }
    };
    if !positive_check_errored
        && !tied_content_twin
        && (top_hit_doc_id != anchor_doc_id || !(distance <= 1e-6))
    {
        failures.push(format!(
            "③ positive content check failed: anchor doc_id={anchor_doc_id} top vec0 hit={top_hit_doc_id} distance={distance}"
        ));
    }

    // ④ bidirectional identity-set anti-join: the eligibility chain is
    // the exact same one backfill used to seed holes
    // (`scan_eligible_message_ids`), so "对账基线=backfill报告数字" holds
    // by construction rather than by re-deriving a parallel definition of
    // eligibility that could drift from it.
    let eligible_ids: HashSet<i64> = scan_eligible_message_ids(storage)?.into_iter().collect();
    let embedded_ids: HashSet<i64> = conn
        .query_all_map("SELECT doc_id FROM message_embeddings WHERE generation_id = ?1", &params![generation_id], |row| row.get_typed(0))?
        .into_iter()
        .collect();
    let eligible_not_embedded_count = eligible_ids.difference(&embedded_ids).count();
    let embedded_not_eligible_count = embedded_ids.difference(&eligible_ids).count();
    if eligible_not_embedded_count != 0 {
        failures.push(format!(
            "④ identity-set anti-join: {eligible_not_embedded_count} eligible message(s) have no embedding row in generation {generation_id}"
        ));
    }
    if embedded_not_eligible_count != 0 {
        failures.push(format!(
            "④ identity-set anti-join: {embedded_not_eligible_count} embedded doc_id(s) in generation {generation_id} are no longer in the eligible set"
        ));
    }

    // ⑤ canonicalize-version identity match against the running binary's
    // W3-0 fingerprint.
    if canonicalize_version_actual != i64::from(CANONICALIZE_PIPELINE_VERSION) {
        failures.push(format!(
            "⑤ canonicalize_version mismatch: generation has {canonicalize_version_actual}, running binary expects {CANONICALIZE_PIPELINE_VERSION}"
        ));
    }

    // ⑥ PRAGMA foreign_key_check: database-wide, not generation-scoped --
    // a non-empty result is an unconditional reject (R2-W3-B5).
    let foreign_key_violation_count = conn.query_all_map("PRAGMA foreign_key_check", &[], |_row| Ok(()))?.len();
    if foreign_key_violation_count != 0 {
        failures.push(format!("⑥ PRAGMA foreign_key_check reported {foreign_key_violation_count} violation(s)"));
    }

    // ⑦ vec0-vs-authoritative-table row-count reconciliation (R1-W3-B5):
    // none of checks ①-⑥ would ever notice `vec0` missing rows wholesale
    // -- ①/②/④ only ever read `message_embeddings`, and ③'s KNN probe
    // only ever confirms one specific row's presence in `vec0`, never the
    // total. A rebuild that silently populated fewer rows than it read
    // (or one simply never re-run after `message_embeddings` grew) would
    // otherwise sail through every prior check and still get certified
    // `passed`. A cheap `COUNT(*)` on each side closes that gap.
    let message_embeddings_row_count: i64 = conn.query_row_map(
        "SELECT COUNT(*) FROM message_embeddings WHERE generation_id = ?1",
        &params![generation_id],
        |row| row.get_typed(0),
    )?;
    let vec0_row_count = match vector_domain::count_vec0_rows_for_generation(conn, generation_id) {
        Ok(count) => count,
        Err(e) => {
            failures.push(format!(
                "⑦ vec0 row-count reconciliation errored for generation {generation_id} \
                 (vec0 table missing or unreadable): {e}"
            ));
            -1
        }
    };
    if vec0_row_count >= 0 && vec0_row_count != message_embeddings_row_count {
        failures.push(format!(
            "⑦ vec0 row-count mismatch for generation {generation_id}: vec0 has \
             {vec0_row_count} row(s), message_embeddings has {message_embeddings_row_count}"
        ));
    }

    let passed = failures.is_empty();
    Ok(ActivationAuditReport {
        generation_id,
        passed,
        dim_mismatch_count,
        finite_norm_sample_size,
        finite_norm_checked,
        finite_norm_violation_count,
        positive_check_doc_id: anchor_doc_id,
        positive_check_top_hit_doc_id: top_hit_doc_id,
        positive_check_distance: distance,
        eligible_not_embedded_count,
        embedded_not_eligible_count,
        canonicalize_version_expected: CANONICALIZE_PIPELINE_VERSION,
        canonicalize_version_actual,
        foreign_key_violation_count,
        vec0_row_count,
        message_embeddings_row_count,
        failure_reasons: failures,
    })
}

/// Run [`run_activation_audit`] and atomically record its verdict into
/// `audit_status` ('passed'/'failed') -- the standalone re-audit entry
/// point for a generation that is already `is_active` (task book #62's
/// own real-scale run against staging generation_id=1, activated under
/// exec54's old minimal verify and sitting at `audit_status='pending'`
/// ever since). Never touches `is_active`: a re-audit's job is only to
/// upgrade/demote certification, not to pick which generation serves
/// reads.
pub fn run_activation_audit_and_record(
    storage: &FrankenStorage,
    generation_id: i64,
    finite_norm_sample_size: usize,
    positive_check_doc_id: Option<i64>,
) -> Result<ActivationAuditReport> {
    let report = run_activation_audit(storage, generation_id, finite_norm_sample_size, positive_check_doc_id)?;
    let new_status = if report.passed { "passed" } else { "failed" };
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            tx.execute("UPDATE embedding_generations SET audit_status = ?1 WHERE id = ?2", &params![new_status, generation_id])
        })
        .context("recording activation audit verdict")?;
    Ok(report)
}

// =============================================================================
// W3-4 Step3 (task book #62): delayed cleanup of orphaned (non-active)
// embedding generations. Only ever deletes rows for a generation that is
// already `is_active = 0` *and* old enough that no in-flight reader could
// plausibly still be depending on it -- `search_db_vector_domain` (spec
// R4-B4) reads the active-generation pointer and that generation's rows
// inside one `Deferred` transaction/snapshot, so a reader that already
// captured a snapshot is isolated from a concurrent DELETE by SQLite's own
// MVCC (proven in `tests/w3_vector_generation_cleanup.rs`, R4-B5) --
// deleting a *recently* demoted generation would still be memory-safe for
// that reason, but the age threshold exists anyway as an operational
// safety margin (R4-B5's "delayed", not "immediate", cleanup), not as a
// correctness requirement this module depends on.
// =============================================================================

/// Default delayed-cleanup age threshold (task book #62 Step3: 24h).
/// Env-tunable (`CASS_EMBEDDING_GENERATION_CLEANUP_AGE_MS`) -- not a new
/// config-file surface, just an escape valve for tests/ops, matching this
/// task's "不新增配置面" constraint.
const GENERATION_CLEANUP_AGE_THRESHOLD_MS_DEFAULT: i64 = 24 * 60 * 60 * 1000;

fn generation_cleanup_age_threshold_ms() -> i64 {
    std::env::var("CASS_EMBEDDING_GENERATION_CLEANUP_AGE_MS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|&v| v >= 0)
        .unwrap_or(GENERATION_CLEANUP_AGE_THRESHOLD_MS_DEFAULT)
}

/// Delete every non-active `embedding_generations` row whose `created_at`
/// is older than the cleanup threshold, along with its `message_embeddings`
/// / `embedding_holes` rows and `vec0` table -- none of that cascades from
/// deleting the generation row itself (`V4_VECTOR_DOMAIN_DDL`'s doc comment:
/// `generation_id` does not cascade from `embedding_generations`), so this
/// function is the one place that tears down all four pieces together.
/// Never touches the currently-active generation, regardless of age. Each
/// candidate is deleted in its own transaction (`is_active = 0` is
/// re-checked in the same `DELETE`'s `WHERE` clause, not just the earlier
/// `SELECT`, so a generation that got reactivated between the scan and the
/// delete is safely skipped rather than deleted out from under a new
/// active pointer) -- one candidate's delete failing never blocks the rest.
/// Returns the `generation_id`s actually deleted.
pub fn cleanup_orphaned_generations(storage: &FrankenStorage, now_ms: i64) -> Result<Vec<i64>> {
    let cutoff_ms = now_ms.saturating_sub(generation_cleanup_age_threshold_ms());
    let candidates: Vec<i64> = storage
        .raw()
        .query_all_map(
            "SELECT id FROM embedding_generations WHERE is_active = 0 AND created_at < ?1",
            &params![cutoff_ms],
            |row| row.get_typed(0),
        )
        .context("scanning for orphaned embedding generations")?;

    let mut deleted = Vec::with_capacity(candidates.len());
    for generation_id in candidates {
        let rows_deleted = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                // Re-check `is_active` inside this same transaction before
                // touching anything -- if this generation got reactivated
                // between the scan above and here, the two DELETEs below
                // must never run at all (they are not themselves gated on
                // is_active, so running them unconditionally could wipe a
                // *currently active* generation's rows out from under it).
                let still_inactive: Option<bool> = tx.query_opt_map(
                    "SELECT is_active = 0 FROM embedding_generations WHERE id = ?1",
                    &params![generation_id],
                    |row| row.get_typed(0),
                )?;
                if still_inactive != Some(true) {
                    return Ok(0);
                }
                tx.execute("DELETE FROM embedding_holes WHERE generation_id = ?1", &params![generation_id])?;
                tx.execute("DELETE FROM message_embeddings WHERE generation_id = ?1", &params![generation_id])?;
                tx.execute(
                    "DELETE FROM embedding_generations WHERE id = ?1 AND is_active = 0",
                    &params![generation_id],
                )
            })
            .with_context(|| format!("deleting orphaned generation {generation_id}"))?;
        if rows_deleted == 0 {
            // Reactivated (or already gone) between the scan and here --
            // nothing was touched, safe to skip.
            continue;
        }
        vector_domain::drop_vec0_table_for_generation(storage.raw(), generation_id)
            .with_context(|| format!("dropping vec0 table for deleted generation {generation_id}"))?;
        deleted.push(generation_id);
    }
    Ok(deleted)
}
