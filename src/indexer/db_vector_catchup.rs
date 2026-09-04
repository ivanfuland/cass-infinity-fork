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
use crate::search::chunking::canonical_role;
use crate::search::eligibility::{ExpectedChunk, expected_chunks, for_each_expected_chunk};
use crate::search::frankensearch_types::cosine_similarity;
use crate::search::infinity::{InfinityConfig, InfinityServedIdentity, fingerprint_matches, probe_served_embed_identity};
use crate::storage::api::{Conn, StorageError, Tx, TxMode, params};
use crate::storage::schema::{self, CasInsertOutcome, ChunkRow};
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
    /// Embedded `message_embeddings` rows deleted (task book #80, exec72
    /// fix) because their `doc_id` was found embedded but no longer in the
    /// eligibility chain -- see the reverse-reconciliation step in
    /// [`run_db_vector_catchup_backfill`], right before `holes_after` is
    /// computed, for why leaving them in place would self-lock activation
    /// audit ④ forever.
    pub embeddings_pruned_ineligible: u64,
    /// Orphaned (non-active, past the cleanup age threshold) generations
    /// deleted at the tail of this call (R1-W3-N3). Empty on the common
    /// case (nothing old enough to prune yet).
    pub cleanup_deleted_generation_ids: Vec<i64>,
    /// R3-6: cleanup failures from this same tail call --
    /// [`GenerationCleanupOutcome::failures`] verbatim (a candidate whose
    /// delete errored, or a sentinel `generation_id=0` entry if the
    /// orphan-scan query itself failed) -- previously discarded entirely
    /// (only `deleted_ids` was projected into this report), silently
    /// hiding a real cleanup failure from every attestation consumer
    /// (JSON/human CLI output alike). Empty on the common case.
    pub cleanup_failures: Vec<(i64, String)>,
    /// T8 (plan v5.1): chunks newly embedded and moved from `chunk_staging`
    /// into `message_chunks` this run. `0` for a [`run_db_vector_catchup_
    /// backfill`] (v4) call -- the chunk domain is a [`run_db_vector_
    /// catchup_backfill_v5`]-only concept.
    pub chunks_embedded: u64,
    /// T8: `message_chunks` rows deleted by the reverse-reconciliation step
    /// (`prune_chunks_not_in_expected_in_tx`) because the message's current
    /// `ExpectedChunk` set no longer contains them (content/role changed
    /// since they were embedded). The normal-path invariant is `0` -- a
    /// non-zero value means this run itself did reconciliation work, not
    /// that anything is wrong.
    pub chunks_pruned: u64,
    /// T8: `chunk_holes` rows written off with disposition
    /// `WriteOffIndexBeyondExpected` (the hole's `chunk_idx` is no longer
    /// covered by the message's current expected-chunk count) -- distinct
    /// from `holes_written_off_ineligible` above, which is the v4
    /// (message-level) write-off counter.
    pub holes_written_off_beyond_expected: u64,
    /// T8: `chunk_staging` rows this run recognized as already matching the
    /// current expected chunk (same `content_hash`/span) and reused instead
    /// of re-embedding -- `find_reusable_staging_in_tx`'s hit count, the
    /// crash-resume fast path.
    pub staging_reused: u64,
    /// T8: stale `chunk_staging` rows purged (`purge_stale_staging_in_tx`)
    /// because their content/span no longer matches what this run's fresh
    /// expected-chunk computation says the hole should look like -- a prior
    /// run's staged embedding invalidated by a content edit since.
    pub staging_purged: u64,
    /// T8: distinct messages `load_message_once` actually read from
    /// `messages` this run -- must equal the number of distinct
    /// `message_id`s among the drained hole keys, never more (the "load
    /// each message once per run" invariant `catchup_loads_each_message_
    /// once_per_run` proves).
    pub messages_loaded: u64,
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

/// What to do with one drained `embedding_holes` row (task book #81, R2
/// review). A pure function -- no I/O -- so the two write-off reasons are
/// directly unit-testable without a database or a live Infinity service.
///
/// Root cause this closes: before this fix, the drain loop's own
/// defensive filter only checked `canonicalize_for_embedding(&row.content)
/// .is_empty()`, never whether `row.doc_id` was actually in the
/// eligibility snapshot the same call already computed. A hole gets
/// registered unconditionally for every newly-ingested message
/// (`register_embedding_hole_for_new_message_in_tx` has no eligibility
/// filter of its own), including one whose conversation has already
/// crossed the shared 8 MiB per-conversation content cap (`#290`) -- such
/// a row's *raw* content is non-empty (canonicalize check passes) even
/// though it is not, and never was, in `eligible_ids` for this call. The
/// old loop embedded it anyway (a real Infinity call, GPU cycles spent),
/// only for the reverse-reconciliation prune step further down to delete
/// it again immediately -- and worse, since that embed happens *during*
/// this call (`created_at >= now_ms`), the R1-N2 snapshot scope on that
/// prune step correctly refuses to touch it, so it survives to fail
/// activation audit ④ instead (the diag3 exit-9 failure this fix
/// resolves). Catching it here, at the same triage point the
/// canonicalize-empty case already used, avoids the wasted embed *and*
/// the possibility of it ever reaching `message_embeddings` in the first
/// place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HoleDisposition {
    Embed,
    WriteOffCanonicalizeEmpty,
    WriteOffOutOfEligibilityScope,
}

fn classify_hole_row(row: &HoleMessageRow, eligible_id_set: &HashSet<i64>) -> HoleDisposition {
    if canonicalize_for_embedding(&row.content).is_empty() {
        HoleDisposition::WriteOffCanonicalizeEmpty
    } else if !eligible_id_set.contains(&row.doc_id) {
        HoleDisposition::WriteOffOutOfEligibilityScope
    } else {
        HoleDisposition::Embed
    }
}

/// w3-3 Step0 design ruling ①/②, extended by R1-W3-N3: find an
/// identity-matching (`embedder_id` + `dim` + `canonicalize_version`, all
/// three exact) generation to keep draining holes on, in priority order,
/// only creating a new generation when neither match exists:
///
/// 1. The identity-matching *active* generation, regardless of its
///    current `audit_status` (R1-W3-N3). This is the steady-state case a
///    production cron actually hits every run: the active generation is
///    `passed` with zero outstanding holes, so before this fix nothing
///    ever matched here (only `audit_status='pending'` did) and the
///    worker created a brand-new empty-holes generation and re-embedded
///    the *entire* corpus from scratch on every single call -- the exact
///    thing that makes an hourly cron model impossible. New messages
///    landing on this active generation between runs already registered
///    a hole against it directly (ingest-time hooks only ever touch the
///    *currently active* generation), so reusing it is a hole-driven
///    incremental catch-up with no new drain logic needed -- and if
///    `holes_after` reaches zero, the caller re-runs the full activation
///    audit and re-promotes through the same `switch_active_generation`
///    call as any other candidate (idempotent to re-certify an
///    already-active generation).
/// 2. The identity-matching *pending* (not-yet-promoted, or demoted-back-
///    to-pending by new writes) generation -- the original w3-3 Step0
///    behavior, still needed for the "candidate not yet certified" case.
/// 3. Neither found: create a new, empty generation.
///
/// This is what keeps a mid-run crash from burning hours of prior
/// Infinity work: the hole ledger itself is the resumable state (w3-3
/// Step0 design §3), so resuming is just "find the right generation_id",
/// not a checkpoint replay.
fn find_reusable_or_create_generation(
    conn: &Conn,
    identity: &InfinityServedIdentity,
    dim: i64,
    created_at_ms: i64,
) -> Result<(i64, bool)> {
    if let Some(existing) = schema::find_active_generation_matching_identity(
        conn,
        &identity.model_id,
        dim,
        CANONICALIZE_PIPELINE_VERSION,
    )
    .context("looking up an identity-matching active embedding_generations row")?
    {
        return Ok((existing, true));
    }

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
    // Task book #81 (R2 review, root cause of the exit-9 diag3 gate②
    // failure): the *drain loop* below and the reverse-reconciliation
    // prune step near the end of this function both need "is this doc_id
    // in the eligibility snapshot" -- built once, right after the scan
    // that produced `eligible_ids`, and reused by both, so neither can
    // drift from a second, later re-derivation of the same set.
    let eligible_id_set: HashSet<i64> = eligible_ids.iter().copied().collect();
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

        // Defensive re-check (w3-3 Step0 design §3, extended by task book
        // #81 R2 review): genesis seeding already guarantees every seeded
        // doc_id both canonicalizes non-empty and is in `eligible_ids`,
        // but this loop must never assume either stays true -- ingest-time
        // hook registration (`register_embedding_hole_for_new_message_in_
        // tx`) has no eligibility filter of its own and *will* register a
        // hole for (a) a short-acknowledgement message like "OK." that can
        // never resolve through the normal embed-and-CAS-write path
        // (R1-W3-B1), or (b) a message whose conversation has already
        // crossed the shared 8 MiB per-conversation content cap by the
        // time this call's own eligibility snapshot was taken (task book
        // #81 R2: `classify_hole_row`'s own doc comment has the full
        // mechanism). Either kind self-locks this generation out of
        // activation forever if left registered (`holes_after` never
        // reaches zero) or, worse for (b), gets embedded anyway only to
        // fail activation audit ④ once its now-stale row is caught later
        // -- so both are written off (their hole rows deleted) here rather
        // than left "for investigation": the hole ledger's contract is an
        // exact accounting of *eligible* messages, and neither kind was
        // ever a valid ledger entry to begin with. Filtering first also
        // keeps the positional zip below safe: every input handed to the
        // embedder is already known-eligible, so `embed_messages_with_
        // sink` cannot drop any of them.
        let filtered: Vec<&HoleMessageRow> =
            rows.iter().filter(|row| classify_hole_row(row, &eligible_id_set) == HoleDisposition::Embed).collect();
        if filtered.len() != rows.len() {
            let canonicalize_empty: Vec<&HoleMessageRow> = rows
                .iter()
                .filter(|row| classify_hole_row(row, &eligible_id_set) == HoleDisposition::WriteOffCanonicalizeEmpty)
                .collect();
            let out_of_eligibility_scope: Vec<&HoleMessageRow> = rows
                .iter()
                .filter(|row| classify_hole_row(row, &eligible_id_set) == HoleDisposition::WriteOffOutOfEligibilityScope)
                .collect();
            tracing::warn!(
                generation_id,
                total = rows.len(),
                kept = filtered.len(),
                written_off_canonicalize_empty = canonicalize_empty.len(),
                written_off_out_of_eligibility_scope = out_of_eligibility_scope.len(),
                "db_vector_catchup: writing off ineligible embedding_holes rows before spending an \
                 Infinity call on them (R1-W3-B1 / task book #81 R2)"
            );
            let written_off = storage
                .raw()
                .with_tx(TxMode::Immediate, |tx| {
                    let mut written_off = 0u64;
                    for row in canonicalize_empty.iter().chain(out_of_eligibility_scope.iter()) {
                        written_off =
                            written_off.saturating_add(schema::write_off_ineligible_hole_in_tx(tx, generation_id, row.doc_id)?);
                    }
                    Ok(written_off)
                })
                .context("writing off ineligible embedding_holes rows")?;
            // R2-N4: report what the DELETEs actually affected, not the
            // size of the two candidate lists -- same discipline as
            // R1-N3's fix to the reverse-reconciliation prune step below.
            holes_written_off_ineligible = holes_written_off_ineligible.saturating_add(written_off);
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

    // Task book #80 (exec72, R1 review fixes): reverse reconciliation, the
    // half of the eligibility<->embedded accounting the loop above never
    // did. Every path above only ever grows `message_embeddings` toward
    // the eligible set (`eligible_ids` -> `seed_embedding_holes` -> drain);
    // nothing shrinks it back when a message that used to be eligible no
    // longer is (e.g. its conversation is deleted or its content is edited
    // out from under it between generations). Left unpruned, such a row
    // makes activation audit ④'s `embedded_not_eligible_count` check
    // permanently non-zero and this generation can never activate again.
    // `eligible_ids` (collected above, before the drain loop) is the same
    // eligibility snapshot the drain loop and `holes_after` below are
    // already consistent with, so diffing against it here -- rather than
    // re-scanning -- can't introduce a second, later eligibility snapshot
    // that disagrees with what this same call already seeded holes
    // against.
    //
    // R1-N2: `eligible_ids` was scanned once, before the drain loop, but a
    // concurrent writer can land a brand-new message during the loop --
    // its ingest-time hook registers a hole against this same active
    // generation (`register_embedding_hole_for_new_message_in_tx` touches
    // only the currently-active generation), the drain loop above can pick
    // that hole up and embed it within this same call, yet that doc_id
    // never appears in the *already-captured* `eligible_ids` snapshot.
    // Diffing embedded-vs-`eligible_ids` naively would misclassify that
    // brand-new, genuinely-eligible row as an orphan and prune what this
    // same call just wrote. `now_ms` (captured above, before the
    // eligibility scan) is the snapshot boundary: scoping the candidate
    // scan to `created_at < now_ms` excludes every row written by this
    // call's own drain loop (all timestamped with a `write_now_ms` taken
    // after `now_ms`), leaving only rows that were already sitting in
    // `message_embeddings` before this call started -- the only rows
    // `eligible_ids` could possibly have a stale opinion about.
    // (`eligible_id_set` itself was built once, right after `eligible_ids`
    // was scanned, and reused by the drain loop's `classify_hole_row`
    // calls above -- see that construction's own doc comment.)
    let embedded_rows: Vec<(i64, i64)> = storage.raw().query_all_map(
        "SELECT me.doc_id, m.conversation_id \
         FROM message_embeddings me JOIN messages m ON m.id = me.doc_id \
         WHERE me.generation_id = ?1 AND me.created_at < ?2",
        &params![generation_id, now_ms],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
    )?;
    let ineligible_embedded: Vec<(i64, i64)> =
        embedded_rows.into_iter().filter(|(doc_id, _)| !eligible_id_set.contains(doc_id)).collect();
    // R1-N3: report the rows the DELETEs below actually affected, not the
    // size of the candidate list computed above -- a candidate whose hole
    // (or embedding row) another concurrent writer already resolved/
    // deleted between this SELECT and the prune transaction would
    // otherwise be double-counted here despite the DELETE affecting zero
    // rows for it.
    let mut embeddings_pruned_ineligible: u64 = 0;
    if !ineligible_embedded.is_empty() {
        let mut per_conversation_counts: std::collections::BTreeMap<i64, u64> = std::collections::BTreeMap::new();
        for (_, conversation_id) in &ineligible_embedded {
            *per_conversation_counts.entry(*conversation_id).or_insert(0) += 1;
        }
        for (conversation_id, count) in &per_conversation_counts {
            tracing::warn!(
                generation_id,
                conversation_id,
                count,
                "db_vector_catchup: pruning embedded doc_id(s) whose message fell out of the \
                 eligibility chain since they were embedded (task book #80)"
            );
        }
        let doc_ids: Vec<i64> = ineligible_embedded.iter().map(|(doc_id, _)| *doc_id).collect();
        embeddings_pruned_ineligible = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                let mut pruned = 0u64;
                for doc_id in &doc_ids {
                    pruned = pruned.saturating_add(schema::prune_ineligible_message_embedding_in_tx(tx, generation_id, *doc_id)?);
                }
                // R1-B1: this generation may already be `is_active=1,
                // audit_status='passed'` (the steady-state reuse case,
                // ruling ①) -- a row deleted here without also demoting
                // that certification would leave a *currently-serving*
                // generation reporting `passed` between this commit and
                // whatever later call re-audits it, i.e. exactly the
                // false-green window this demotion exists to prevent for
                // every other mutation category. Folding it into this same
                // transaction, gated on `pruned > 0`, makes the demotion
                // atomic with the delete it is compensating for -- no
                // window where the deleted row is committed but the stale
                // 'passed' status still reads back.
                //
                // R2-N3: scoped to this specific `generation_id`, not the
                // unscoped `demote_active_generation_readiness_in_tx` --
                // `generation_id` here is whatever `find_reusable_or_
                // create_generation` returned at the top of this call,
                // which by ruling ② can be a *not-yet-active* pending
                // candidate while some *other* generation is the one
                // currently serving reads. The unscoped demote would wrongly
                // touch that other, currently-active generation instead of
                // (correctly) doing nothing here.
                if pruned > 0 {
                    schema::demote_generation_readiness_if_active_in_tx(tx, generation_id)?;
                }
                Ok(pruned)
            })
            .context("pruning embedded-but-ineligible message_embeddings rows")?;
    }

    let holes_after = count_holes(storage.raw(), generation_id)?;

    let vec0_rows = vector_domain::rebuild_vec0_table_for_generation(storage.raw(), generation_id, dim)
        .context("rebuilding vec0 table for generation")?;

    // W3-4 Step1 (task book #62): the full six-invariant activation audit
    // replaces the old minimal "embedded_count > 0" verify closure here.
    // Checks run read-only first (a fresh watertight snapshot is what the
    // audit itself validates), then the verdict is written atomically with
    // the pointer flip inside `switch_active_generation`'s own transaction
    // -- "全过才许切", and a failure aborts before `switch_active_
    // generation` is even called, so the pointer is provably untouched
    // (spec §3.1's atomicity contract, reused rather than re-implemented).
    //
    // R1-W3-B2: the full audit runs *outside* a transaction (an expensive
    // multi-query audit must not hold a write lock open for its whole
    // duration) -- exec55's single-writer assumption for this flow does
    // not hold in general (a concurrent index/watch/restore connection can
    // land a new message while this audit is running), so a TOCTOU window
    // exists between "audit read holes==0 and verified everything" and
    // "the switch transaction below actually flips the pointer". A message
    // landing in that window registers no hole against this candidate
    // generation (ingest-time hooks only touch the *currently active*
    // generation, and this one isn't active yet), so the candidate would
    // still show holes==0 and would still get promoted -- silently missing
    // that message forever. `pre_audit_watermark_message_id` plus the
    // cheap in-tx recheck below close that window without paying for a
    // second full audit. R2-B2: `pre_audit_message_count` closes the
    // complementary gap the watermark alone leaves -- a concurrent delete
    // of a non-max-id message doesn't move MAX(id), so only a row-count
    // recheck catches it (see `verify_no_activation_toctou_drift_in_tx`'s
    // doc comment for why a full mutation-epoch mechanism was rejected in
    // favor of this).
    let pre_audit_watermark_message_id: i64 = storage
        .raw()
        .query_row_map("SELECT COALESCE(MAX(id), 0) FROM messages", &[], |row| row.get_typed(0))
        .context("reading pre-audit messages high-water mark")?;
    let pre_audit_message_count: i64 = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))
        .context("reading pre-audit messages row count")?;
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
            // R1-W3-B2: cheap in-transaction re-verification of the two
            // invariants a concurrent writer could have invalidated since
            // the full audit above read them -- see
            // `verify_no_activation_toctou_drift_in_tx`'s doc comment.
            // Either violation aborts the whole transaction (the pointer
            // flip and the `audit_status='passed'` write below never
            // happen); the caller's *next* call re-scans and re-audits
            // from scratch, so no partial/stale promotion is ever
            // committed.
            schema::verify_no_activation_toctou_drift_in_tx(
                tx,
                generation_id,
                pre_audit_watermark_message_id,
                pre_audit_message_count,
            )?;
            tx.execute(
                "UPDATE embedding_generations SET audit_status = 'passed' WHERE id = ?1",
                &params![generation_id],
            )?;
            Ok(())
        })
        .context("activating db-vector generation")?;
        activated = true;
    }

    // R1-W3-N3: without this, N3's own fix (reusing the identity-matching
    // active generation instead of always creating a new one on a
    // steady-state cron run) is the only thing that would ever stop
    // orphaned generations from accumulating -- but a real model/dim
    // upgrade, or any run that *did* still need to create a new
    // generation, still leaves its predecessor(s) behind with no
    // production caller ever pruning them (task book #62 Step3's
    // `cleanup_orphaned_generations` existed, but nothing in this worker
    // -- the actual production entry point -- ever called it). Runs
    // unconditionally at the tail, regardless of this call's own
    // activation outcome: pruning old orphans is this run's own
    // housekeeping, not contingent on what this run did.
    // R3-6: `cleanup_orphaned_generations` itself never returns `Err`
    // (both a per-candidate delete failure and a scan-level failure are
    // folded into `.failures` -- see its own doc comment), so there is no
    // `?`/`.context(...)` left here to lose this run's already-committed
    // activation to a housekeeping failure.
    let cleanup_outcome = cleanup_orphaned_generations(storage, FrankenStorage::now_millis());
    let (cleanup_deleted_generation_ids, cleanup_failures) = match cleanup_outcome {
        Ok(outcome) => (outcome.deleted_ids, outcome.failures),
        Err(e) => (Vec::new(), vec![(0, format!("cleanup_orphaned_generations errored: {e}"))]),
    };

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
        embeddings_pruned_ineligible,
        cleanup_deleted_generation_ids,
        cleanup_failures,
        // T8 chunk-domain fields: not this (v4) function's concept.
        chunks_embedded: 0,
        chunks_pruned: 0,
        holes_written_off_beyond_expected: 0,
        staging_reused: 0,
        staging_purged: 0,
        messages_loaded: 0,
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
    /// ⑦ vec0-vs-authoritative-table reconciliation (R1-W3-B5, upgraded to
    /// a bidirectional anti-join by R2-B4). `-1` for `vec0_row_count` means
    /// the count itself errored (most commonly the `vec0` table not
    /// existing for this generation at all), distinct from a genuine `0`;
    /// `message_embeddings_rows_missing_from_vec0`/
    /// `vec0_rows_missing_from_message_embeddings` stay `0` in that same
    /// errored case (the anti-join is skipped, not run against a missing
    /// table). The plain row counts are kept as a cheap diagnostic pair,
    /// not the pass/fail signal -- the anti-join counts are (see
    /// [`crate::storage::vector_domain::count_vec0_message_embeddings_set_mismatch_for_generation`]'s
    /// doc comment for why a size-only comparison can miss an equal-size
    /// identity-set swap).
    pub vec0_row_count: i64,
    pub message_embeddings_row_count: i64,
    pub message_embeddings_rows_missing_from_vec0: i64,
    pub vec0_rows_missing_from_message_embeddings: i64,
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

    // ⑦ vec0-vs-authoritative-table reconciliation (R1-W3-B5, upgraded to
    // a bidirectional anti-join by R2-B4): none of checks ①-⑥ would ever
    // notice `vec0` disagreeing with `message_embeddings` on *which* rows
    // it holds -- ①/②/④ only ever read `message_embeddings`, and ③'s KNN
    // probe only ever confirms one specific row's presence in `vec0`,
    // never the full set. A plain `COUNT(*)` comparison closes the
    // wholesale-loss gap (a rebuild that silently populated fewer rows
    // than it read) but not an equal-size identity-set swap (N rows
    // missing from one side exactly offset by N different extra rows on
    // the other -- both counts still match). The anti-join closes that:
    // both `message_embeddings_rows_missing_from_vec0` and
    // `vec0_rows_missing_from_message_embeddings` must be `0` to pass;
    // the plain counts are retained purely as a cheap diagnostic pair.
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
    let (message_embeddings_rows_missing_from_vec0, vec0_rows_missing_from_message_embeddings) =
        if vec0_row_count >= 0 {
            vector_domain::count_vec0_message_embeddings_set_mismatch_for_generation(conn, generation_id)?
        } else {
            (0, 0)
        };
    if message_embeddings_rows_missing_from_vec0 != 0 || vec0_rows_missing_from_message_embeddings != 0 {
        failures.push(format!(
            "⑦ vec0/message_embeddings identity-set mismatch for generation {generation_id}: \
             {message_embeddings_rows_missing_from_vec0} message_embeddings row(s) missing from vec0, \
             {vec0_rows_missing_from_message_embeddings} vec0 row(s) missing from message_embeddings \
             (vec0 has {vec0_row_count} row(s), message_embeddings has {message_embeddings_row_count})"
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
        message_embeddings_rows_missing_from_vec0,
        vec0_rows_missing_from_message_embeddings,
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
    // R3-1: this standalone re-audit entry point runs the same
    // out-of-transaction, multi-query audit `switch_active_generation`'s
    // activation path does (see the `pre_audit_watermark_message_id`
    // block above) and is exposed to the identical TOCTOU window -- a
    // message landing, or a non-max-id message getting deleted, between
    // the audit's reads and this function's `audit_status` write would
    // otherwise get silently certified `passed` over a now-stale
    // snapshot. Reuses `verify_no_activation_toctou_drift_in_tx` (R2-B2's
    // guard) rather than reinventing it.
    let pre_audit_watermark_message_id: i64 = storage
        .raw()
        .query_row_map("SELECT COALESCE(MAX(id), 0) FROM messages", &[], |row| row.get_typed(0))
        .context("reading pre-audit messages high-water mark")?;
    let pre_audit_message_count: i64 = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))
        .context("reading pre-audit messages row count")?;
    let report = run_activation_audit(storage, generation_id, finite_norm_sample_size, positive_check_doc_id)?;
    let new_status = if report.passed { "passed" } else { "failed" };
    storage
        .raw()
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            if new_status == "passed" {
                schema::verify_no_activation_toctou_drift_in_tx(
                    tx,
                    generation_id,
                    pre_audit_watermark_message_id,
                    pre_audit_message_count,
                )?;
            }
            let changed = tx.execute(
                "UPDATE embedding_generations SET audit_status = ?1 WHERE id = ?2",
                &params![new_status, generation_id],
            )?;
            if changed != 1 {
                return Err(StorageError::Constraint {
                    detail: format!(
                        "run_activation_audit_and_record: expected to update exactly 1 row for \
                         generation {generation_id}, changed {changed} (R3-1)"
                    ),
                });
            }
            Ok(())
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

/// Outcome of [`cleanup_orphaned_generations`] (R2-N2/R3-6): `deleted_ids`
/// for candidates actually torn down, `failures` for either a candidate
/// whose delete transaction itself errored (its real `generation_id` and a
/// rendered error detail) or the initial orphan-scan query itself failing
/// (sentinel `generation_id=0`, never a real `AUTOINCREMENT` id). Either
/// way, whatever `failures` covers is simply left in place -- exactly what
/// would already be true of it before this function ever ran -- so it is
/// retried the next time this cleanup runs, same as it always was for a
/// `still_inactive != Some(true)` skip.
#[derive(Debug, Default, Clone)]
pub struct GenerationCleanupOutcome {
    pub deleted_ids: Vec<i64>,
    pub failures: Vec<(i64, String)>,
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
/// active pointer).
///
/// R2-N2: one candidate's delete transaction erroring used to `?`
/// immediately out of the whole function -- called at the tail of
/// [`run_db_vector_catchup_backfill`], that turned this run's own already-
/// committed activation into an `Err`, and any candidate after the first
/// failure never even got a delete attempt (the doc comment above claimed
/// "one candidate's delete failing never blocks the rest", which this
/// early-return directly violated). Each candidate's error is now caught
/// and recorded into `failures` instead, and the loop continues to the
/// next candidate.
///
/// R3-6: the initial orphan-scan query itself used to still `?` straight
/// out (same bug, same call site, just the one remaining `?` R2-N2's own
/// fix left standing) -- it too is now caught and folded into `failures`
/// (sentinel `generation_id=0`, never a real `AUTOINCREMENT` id) rather
/// than propagated. This function never returns `Err`; the caller reads
/// `failures` to learn whether anything went wrong.
pub fn cleanup_orphaned_generations(storage: &FrankenStorage, now_ms: i64) -> Result<GenerationCleanupOutcome> {
    let cutoff_ms = now_ms.saturating_sub(generation_cleanup_age_threshold_ms());
    let candidates: Vec<i64> = match storage.raw().query_all_map(
        "SELECT id FROM embedding_generations WHERE is_active = 0 AND created_at < ?1",
        &params![cutoff_ms],
        |row| row.get_typed(0),
    ) {
        Ok(ids) => ids,
        Err(e) => {
            // R3-6: the initial orphan-scan query erroring used to `?`
            // straight out of this function -- called at the tail of
            // `run_db_vector_catchup_backfill`, after that call's own
            // activation had already committed, that turned an otherwise-
            // successful run into an `Err`, the exact same-shaped bug
            // R2-N2 already fixed for a per-candidate delete failure.
            // `0` is never a real `id` (`embedding_generations.id` is
            // `AUTOINCREMENT`, starting at 1) -- an unambiguous sentinel
            // for "this failure isn't about any one candidate".
            tracing::warn!(
                error = %e,
                "cleanup_orphaned_generations: the orphan-scan query itself failed; skipping this \
                 cleanup pass, leaving every candidate in place for the next one (R3-6)"
            );
            return Ok(GenerationCleanupOutcome {
                deleted_ids: Vec::new(),
                failures: vec![(0, format!("orphan-scan query failed: {e}"))],
            });
        }
    };

    let mut outcome = GenerationCleanupOutcome { deleted_ids: Vec::with_capacity(candidates.len()), failures: Vec::new() };
    for generation_id in candidates {
        let delete_result = storage.raw().with_tx(TxMode::Immediate, |tx| {
            // Re-check `is_active` inside this same transaction before
            // touching anything -- if this generation got reactivated
            // between the scan above and here, none of the drops/
            // deletes below must run at all (they are not themselves
            // gated on is_active, so running them unconditionally
            // could wipe a *currently active* generation's rows out
            // from under it).
            let still_inactive: Option<bool> = tx.query_opt_map(
                "SELECT is_active = 0 FROM embedding_generations WHERE id = ?1",
                &params![generation_id],
                |row| row.get_typed(0),
            )?;
            if still_inactive != Some(true) {
                return Ok(0);
            }
            // R1-W3-N4: the vec0 DROP used to run as its own statement
            // *after* this transaction had already committed the
            // metadata deletes below. SQLite DDL is transactional
            // (`rebuild_vec0_table_for_generation` already relies on
            // this for its own drop+recreate), so folding the drop
            // into this same transaction -- issued first -- means a
            // failure here rolls back the metadata deletes too: no
            // window where the metadata row is gone but the vec0
            // table (and its shadow tables) are still on disk with no
            // `embedding_generations` row left to ever find them
            // again via this function's own candidate-scan query.
            vector_domain::drop_vec0_table_for_generation_in_tx(tx, generation_id)?;
            tx.execute("DELETE FROM embedding_holes WHERE generation_id = ?1", &params![generation_id])?;
            tx.execute("DELETE FROM message_embeddings WHERE generation_id = ?1", &params![generation_id])?;
            tx.execute(
                "DELETE FROM embedding_generations WHERE id = ?1 AND is_active = 0",
                &params![generation_id],
            )
        });
        match delete_result {
            Ok(0) => {
                // Reactivated (or already gone) between the scan and here --
                // nothing was touched, safe to skip.
            }
            Ok(_) => outcome.deleted_ids.push(generation_id),
            Err(e) => {
                tracing::warn!(
                    generation_id,
                    error = %e,
                    "cleanup_orphaned_generations: failed to delete an orphaned generation; \
                     leaving it in place for the next cleanup pass (R2-N2)"
                );
                outcome.failures.push((generation_id, e.to_string()));
            }
        }
    }
    Ok(outcome)
}

// =============================================================================
// T8 (plan v5.1, task book #92): chunk-level catch-up drain, key-paged
// staging, generation reuse by policy+fingerprint identity, and the
// audits-8-through-11 (plus a chunk-keyed ④ and a chunk-scoped ⑦)
// activation audit. Coexists with the v4 (embedding_holes-driven) code
// above -- neither replaces the other; v4 stays as-is until T11 retires it.
// =============================================================================

/// One drained `chunk_holes` key: which message and which expected
/// `chunk_idx` within it. Deliberately carries no content -- the whole
/// point of key-paged draining is to decide what to *do* with a key
/// (embed / write off) without having read anything yet; content is read
/// exactly once per distinct `message_id` via [`load_message_once`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct HoleKey {
    message_id: i64,
    chunk_idx: u32,
}

/// The concrete slice of a message's normalized text one `Embed`-
/// dispositioned hole must be embedded from, plus the content hash it must
/// be written with -- everything [`classify_chunk_hole`] can determine
/// about a hole from the message's already-computed `ExpectedChunk`s alone
/// (no I/O of its own).
#[derive(Clone, Debug, PartialEq, Eq)]
struct ChunkSpanRef {
    chunk_idx: u32,
    byte_start: usize,
    byte_end: usize,
    content_hash: String,
}

/// What to do with one drained `chunk_holes` key, given the owning
/// message's current `ExpectedChunk` set (T8; named `ChunkHoleDisposition`
/// here, not `HoleDisposition`, to avoid colliding with the v4 enum of
/// that name above -- both are kept per the "old names coexist" contract).
///
/// [`classify_chunk_hole`] itself only ever produces the first three
/// variants (it has no visibility into the message's `role`, only its
/// already-computed `expected` chunk list). `WriteOffOutOfEligibilityScope`
/// is produced one level up, by the drain loop, for a hole whose message's
/// `role_raw` is outside the embedding whitelist ([`canonical_role`]
/// returns `None`) -- the v5 sibling of v4's "structurally never eligible"
/// reason, kept distinct from `WriteOffCanonicalizeEmpty` (role is fine,
/// but the *content* canonicalizes to nothing) the same way v4 keeps its
/// two write-off reasons distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ChunkHoleDisposition {
    Embed(ChunkSpanRef),
    WriteOffCanonicalizeEmpty,
    WriteOffOutOfEligibilityScope,
    WriteOffIndexBeyondExpected,
}

/// Pure triage: does `key.chunk_idx` land inside `expected` (the owning
/// message's current, freshly-computed `ExpectedChunk` list)? `expected`
/// empty means the message's content canonicalizes to nothing (the role
/// itself was already filtered by the caller before `expected` was ever
/// computed -- see [`ChunkHoleDisposition`]'s doc comment); a non-empty
/// `expected` whose highest `chunk_idx` is below `key.chunk_idx` means the
/// message used to chunk into more pieces than it does now (content
/// shrank) -- `expected_chunks`' `chunk_idx` values are always the exact
/// contiguous range `0..expected.len()` (T2/T3), so "not found but
/// `expected` non-empty" and "index >= `expected.len()`" are the same
/// condition, checked the cheap way.
fn classify_chunk_hole(key: &HoleKey, expected: &[ExpectedChunk]) -> ChunkHoleDisposition {
    if expected.is_empty() {
        return ChunkHoleDisposition::WriteOffCanonicalizeEmpty;
    }
    match expected.iter().find(|c| c.chunk_idx == key.chunk_idx) {
        Some(c) => ChunkHoleDisposition::Embed(ChunkSpanRef {
            chunk_idx: c.chunk_idx,
            byte_start: c.byte_start,
            byte_end: c.byte_end,
            content_hash: c.content_hash.clone(),
        }),
        None => ChunkHoleDisposition::WriteOffIndexBeyondExpected,
    }
}

/// One page of `chunk_holes` keys for `generation_id`, ordered
/// `(message_id, chunk_idx)` ascending, content-free (no `JOIN` against
/// `messages` -- see [`load_message_once`] for the one-read-per-message
/// content fetch this pairs with). `after` is the last key of the
/// previous page (`None` for the first page); the `OR` shape below is the
/// standard keyset-pagination predicate for a two-column ascending order,
/// and works unmodified for the first page too since every real
/// `message_id` is `>= 1` (`AUTOINCREMENT`), always `> 0`.
fn fetch_hole_keys(
    storage: &FrankenStorage,
    generation_id: i64,
    after: Option<(i64, u32)>,
    limit: usize,
) -> Result<Vec<HoleKey>> {
    let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
    let (after_message_id, after_chunk_idx) = after.unwrap_or((0, 0));
    storage
        .raw()
        .query_all_map(
            "SELECT message_id, chunk_idx FROM chunk_holes \
             WHERE generation_id = ?1 AND (message_id > ?2 OR (message_id = ?2 AND chunk_idx > ?3)) \
             ORDER BY message_id, chunk_idx LIMIT ?4",
            &params![generation_id, after_message_id, after_chunk_idx, limit_i64],
            |row| Ok(HoleKey { message_id: row.get_typed(0)?, chunk_idx: row.get_typed(1)? }),
        )
        .context("fetching a page of chunk_holes keys")
}

/// Read one message's `(conversation_id, role, content)` fresh. The sole
/// per-message read the T8 drain loop performs -- callers must cache the
/// result across every `HoleKey` sharing the same `message_id` within a
/// run (the "跨页保留 current 消息" contract; [`run_db_vector_catchup_
/// backfill_v5`]'s loop is what actually enforces "exactly once", this
/// function has no memory of its own). `chunk_holes.message_id REFERENCES
/// messages(id) ON DELETE CASCADE` guarantees a hole's message can never
/// be missing under normal operation -- an error here is a genuine
/// invariant violation, not a race to paper over.
fn load_message_once(storage: &FrankenStorage, message_id: i64) -> Result<(i64, String, String)> {
    storage
        .raw()
        .query_row_map(
            "SELECT conversation_id, role, content FROM messages WHERE id = ?1",
            &params![message_id],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
        )
        .with_context(|| format!("loading message {message_id} for T8 chunk catch-up (chunk_holes FK should make this impossible)"))
}

/// T8 sibling of [`find_reusable_or_create_generation`]: identity now
/// includes `chunking_policy_version` (structural exclusion of legacy
/// rows, see [`schema::find_active_generation_matching_identity_v5`]'s doc
/// comment) *and* the generation fingerprint (plan v5.1 参数冻结 "代际身份"
/// row) -- a same-`(embedder_id, dim, canonicalize_version,
/// chunking_policy_version)` row whose *fingerprint* has drifted (the
/// served model's weights changed under an unchanged id/dim, T7's whole
/// reason for existing) is NOT a reuse match; the search falls through to
/// the next priority tier exactly as if the row didn't exist at all.
/// Same three-tier priority as v4: identity+fingerprint-matching active ->
/// identity+fingerprint-matching pending -> create new.
fn find_reusable_or_create_generation_v5(
    conn: &Conn,
    identity: &InfinityServedIdentity,
    canonicalize_version: u32,
    chunking_policy_version: u32,
    fingerprint: &[u8],
    now_ms: i64,
) -> Result<(i64, bool)> {
    let dim = i64::try_from(identity.dimension)
        .map_err(|_| anyhow!("infinity dimension {} does not fit in i64", identity.dimension))?;

    if let Some((existing, stored_fingerprint)) = schema::find_active_generation_matching_identity_v5(
        conn,
        &identity.model_id,
        dim,
        canonicalize_version,
        chunking_policy_version,
    )
    .context("looking up an identity-matching active v5 embedding_generations row")?
        && fingerprint_matches(&stored_fingerprint, fingerprint, identity.dimension)
    {
        return Ok((existing, true));
    }

    if let Some((existing, stored_fingerprint)) = schema::find_reusable_pending_generation_v5(
        conn,
        &identity.model_id,
        dim,
        canonicalize_version,
        chunking_policy_version,
    )
    .context("looking up a reusable pending v5 embedding_generations row")?
        && fingerprint_matches(&stored_fingerprint, fingerprint, identity.dimension)
    {
        return Ok((existing, true));
    }

    let generation_id = conn
        .with_tx(TxMode::Immediate, |tx| {
            schema::create_embedding_generation_v5(
                tx,
                &identity.model_id,
                dim,
                canonicalize_version,
                chunking_policy_version,
                fingerprint,
                now_ms,
            )
        })
        .context("creating a new v5 embedding_generations row")?;
    Ok((generation_id, false))
}

// =============================================================================
// T8: full v5 activation audit (checks ①②③⑤⑥ carried over from v4, scoped to
// the chunk domain; ④⑦⑧⑨⑩⑪ new/rebuilt for it).
// =============================================================================

/// Deterministic, dependency-free seeded ranking key for ownership-check
/// sampling (check ⑩): no new crate (`rand` is a workspace dependency
/// elsewhere, but its exact 0.10 seeding API was not worth the risk of
/// getting wrong sight-unseen when a few lines of splitmix64-style mixing
/// do the same job -- deterministic given `(seed, chunk_id)`, roughly
/// uniform, zero new dependency surface). Sampling = sort all chunk_ids by
/// this key ascending, take the first N; reproducible for a given seed,
/// which is exactly what makes `ownership_seed` meaningful to log.
fn ownership_sample_key(seed: u64, chunk_id: i64) -> u64 {
    let mut z = seed ^ (chunk_id as u64).wrapping_mul(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// Re-derive a fresh generation fingerprint through the injected
/// `embedder` closure (not [`crate::search::infinity::compute_generation_
/// fingerprint`], which insists on its own live `InfinityConfig`/HTTP
/// client -- audit check ⑪ must be exercisable with a deterministic mock
/// embedder in tests, same as check ⑩). Same wire format:
/// [`crate::search::infinity::FINGERPRINT_SENTINELS`] embedded in order,
/// concatenated as LE f32 bytes.
fn compute_fresh_fingerprint_via(
    embedder: &dyn Fn(&[&str]) -> std::result::Result<Vec<Vec<f32>>, String>,
    dim: usize,
) -> Result<Vec<u8>> {
    let inputs: Vec<&str> = crate::search::infinity::FINGERPRINT_SENTINELS.to_vec();
    let vectors = embedder(&inputs).map_err(|e| anyhow!("re-embedding fingerprint sentinels failed: {e}"))?;
    if vectors.len() != inputs.len() {
        bail!("fingerprint embedder returned {} vectors for {} sentinels", vectors.len(), inputs.len());
    }
    let mut out = Vec::with_capacity(vectors.len() * dim * 4);
    for v in &vectors {
        if v.len() != dim {
            bail!("fingerprint sentinel vector has dim {} != expected {dim}", v.len());
        }
        out.extend_from_slice(&schema::f32_vector_to_le_blob(v));
    }
    Ok(out)
}

/// Verdict + evidence from [`run_activation_audit_v5`]. `passed` is the
/// single verdict every other field explains. Field groups mirror
/// [`ActivationAuditReport`] (v4) where the same check carries over
/// (①②③⑤⑥, scoped to `message_chunks`/chunk identity instead of
/// `message_embeddings`), plus T8's new/rebuilt checks ④⑦⑧⑨⑩⑪.
#[derive(Debug, Clone)]
pub struct ActivationAuditReportV5 {
    pub generation_id: i64,
    pub passed: bool,
    /// ① full-table `COUNT(length(embedding) != 4*dim)` over `message_chunks`.
    pub dim_mismatch_count: i64,
    /// ② finite/norm resample over `message_chunks`.
    pub finite_norm_sample_size: usize,
    pub finite_norm_checked: usize,
    pub finite_norm_violation_count: usize,
    /// ③ positive content self-hit, chunk-domain: the message anchor used,
    /// which of its chunk rows (`chunk_id`) that resolved to, and vec0's
    /// top-1 self-hit for that chunk's own (freshly re-read) vector.
    pub positive_check_message_id: i64,
    pub positive_check_chunk_id: i64,
    pub positive_check_top_hit_chunk_id: i64,
    pub positive_check_distance: f64,
    /// ④ bidirectional anti-join, element = `(message_id, chunk_idx)`.
    pub eligible_not_embedded_count: usize,
    pub embedded_not_eligible_count: usize,
    /// ⑤ canonicalize-version identity match.
    pub canonicalize_version_expected: u32,
    pub canonicalize_version_actual: i64,
    /// ⑥ `PRAGMA foreign_key_check` violation row count (database-wide).
    pub foreign_key_violation_count: usize,
    /// ⑦ vec0-vs-`message_chunks` bidirectional anti-join
    /// (`count_vec0_chunks_set_mismatch_for_generation`), `== (0,0)` to pass.
    pub chunk_count: i64,
    pub vec0_row_count: i64,
    pub chunks_missing_from_vec0: i64,
    pub vec0_chunks_missing_from_message_chunks: i64,
    /// ⑧ full-table (not sampled) recomputed-`content_hash` mismatch count.
    pub hash_mismatch: u64,
    /// ⑨ completeness: span mismatch (same key, different byte range),
    /// missing (expected but not stored), extra (stored but not
    /// expected), conversation_id mismatch, and outstanding `chunk_holes`
    /// rows for this generation (must be `0` to pass).
    pub span_mismatch: u64,
    pub completeness_missing: u64,
    pub completeness_extra: u64,
    pub conversation_id_mismatch: u64,
    pub chunk_holes_remaining: i64,
    /// ⑩ ownership: `min(ownership_sample, chunk_count)` chunks re-embedded
    /// and cross-checked (fresh-vs-stored cosine >= 0.999, vec0 self-hit at
    /// distance ~0). `ownership_skipped=true` (embedder was `None`) always
    /// implies `passed=false` -- only a `--no-ownership` diagnostic tool
    /// may pass `None`, and even then the resulting report is never a
    /// "clean" activation verdict.
    pub ownership_checked: u64,
    pub ownership_failed: u64,
    pub ownership_seed: u64,
    pub ownership_skipped: bool,
    /// ⑪ generation fingerprint re-verification.
    pub fingerprint_ok: bool,
    pub failure_reasons: Vec<String>,
}

/// Default finite/norm resample size for [`run_activation_audit_v5`],
/// mirroring v4's [`ACTIVATION_AUDIT_DEFAULT_FINITE_NORM_SAMPLE_SIZE`].
const ACTIVATION_AUDIT_V5_DEFAULT_FINITE_NORM_SAMPLE_SIZE: usize = 500;

/// Plan v5.1 参数冻结 "代际身份": ownership check ⑩'s per-generation-lifetime
/// resample size, fixed for every real activation/re-audit call
/// (`index --semantic` / `models backfill`) -- not a knob a caller
/// chooses per-call, so it lives here, not as a parameter default.
const OWNERSHIP_SAMPLE_SIZE_DEFAULT: usize = 200;

/// Run the full T8 chunk-domain activation audit against `generation_id`.
/// Read-only. `embedder`: `Some` for a real activation/re-audit call
/// (checks ⑩/⑪ actually re-embed and compare); `None` only for a
/// diagnostic tool that explicitly opted out of that cost -- the report
/// still comes back (`ownership_skipped=true`), but `passed` is
/// unconditionally `false` (plan v5.1: an audit that couldn't verify
/// ownership/fingerprint is not a "clean" verdict, regardless of what
/// checks ①-⑨ found).
#[allow(clippy::too_many_arguments)]
pub fn run_activation_audit_v5(
    storage: &FrankenStorage,
    generation_id: i64,
    finite_norm_sample_size: usize,
    positive_check_message_id: Option<i64>,
    embedder: Option<&dyn Fn(&[&str]) -> std::result::Result<Vec<Vec<f32>>, String>>,
    ownership_sample: usize,
    ownership_seed: u64,
) -> Result<ActivationAuditReportV5> {
    let conn = storage.raw();
    let mut failures: Vec<String> = Vec::new();

    let (dim, canonicalize_version_actual, stored_fingerprint): (i64, i64, Vec<u8>) = conn
        .query_row_map(
            "SELECT dim, canonicalize_version, fingerprint FROM embedding_generations WHERE id = ?1",
            &params![generation_id],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
        )
        .with_context(|| format!("generation {generation_id} not found for T8 activation audit"))?;
    let dim_usize = usize::try_from(dim).unwrap_or(0);

    // ① dim/length match.
    let dim_mismatch_count: i64 = conn.query_row_map(
        "SELECT COUNT(*) FROM message_chunks WHERE generation_id = ?1 AND length(embedding) != 4 * ?2",
        &params![generation_id, dim],
        |row| row.get_typed(0),
    )?;
    if dim_mismatch_count != 0 {
        failures.push(format!("① dim/length mismatch: {dim_mismatch_count} chunk row(s) have a BLOB length != 4*dim={dim}"));
    }

    // ② finite/norm resample.
    let sample_rows: Vec<(i64, i64, u32, Vec<u8>, f64)> = conn.query_all_map(
        "SELECT chunk_id, message_id, chunk_idx, embedding, norm FROM message_chunks WHERE generation_id = ?1 ORDER BY RANDOM() LIMIT ?2",
        &params![generation_id, i64::try_from(finite_norm_sample_size).unwrap_or(i64::MAX)],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?, row.get_typed(4)?)),
    )?;
    let finite_norm_checked = sample_rows.len();
    let mut finite_norm_violation_count = 0usize;
    for (chunk_id, message_id, chunk_idx, blob, stored_norm) in &sample_rows {
        let decoded = match schema::le_blob_to_f32_vector(blob) {
            Ok(v) => v,
            Err(e) => {
                finite_norm_violation_count += 1;
                failures.push(format!("② chunk_id={chunk_id} (message_id={message_id}, chunk_idx={chunk_idx}) BLOB failed to decode: {e}"));
                continue;
            }
        };
        if let Some(bad_idx) = decoded.iter().position(|x| !x.is_finite()) {
            finite_norm_violation_count += 1;
            failures.push(format!("② chunk_id={chunk_id} has a non-finite element at index {bad_idx}"));
            continue;
        }
        let recomputed = schema::l2_norm(&decoded);
        let tolerance = 1e-6_f64.max(stored_norm.abs() * 1e-6);
        if (recomputed - stored_norm).abs() > tolerance {
            finite_norm_violation_count += 1;
            failures.push(format!("② chunk_id={chunk_id} norm/BLOB mismatch: stored={stored_norm} recomputed={recomputed}"));
        }
    }

    // ③ positive content self-hit, resolved to a chunk row.
    let anchor: Result<(i64, i64, Vec<u8>)> = (|| {
        Ok(match positive_check_message_id {
            Some(mid) => conn.query_row_map(
                "SELECT message_id, chunk_id, embedding FROM message_chunks \
                 WHERE generation_id = ?1 AND message_id = ?2 ORDER BY chunk_idx LIMIT 1",
                &params![generation_id, mid],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
            )
            .with_context(|| format!("positive-check message_id={mid} has no chunk row in generation {generation_id}"))?,
            None => conn
                .query_row_map(
                    "SELECT message_id, chunk_id, embedding FROM message_chunks WHERE generation_id = ?1 ORDER BY chunk_id LIMIT 1",
                    &params![generation_id],
                    |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
                )
                .with_context(|| format!("generation {generation_id} has zero chunk rows; nothing to positive-check"))?,
        })
    })();
    let mut positive_check_errored = false;
    let (anchor_message_id, anchor_chunk_id, top_hit_chunk_id, distance) = match anchor {
        Ok((message_id, chunk_id, blob)) => match schema::le_blob_to_f32_vector(&blob)
            .map_err(anyhow::Error::from)
            .and_then(|v| vector_domain::vec0_knn(conn, generation_id, &v, 1).map_err(anyhow::Error::from))
        {
            Ok(hits) => {
                let (top_hit, distance) = hits.first().copied().unwrap_or((-1, f64::INFINITY));
                (message_id, chunk_id, top_hit, distance)
            }
            Err(e) => {
                positive_check_errored = true;
                failures.push(format!("③ positive content check errored on message_id={message_id} chunk_id={chunk_id}: {e}"));
                (message_id, chunk_id, -1, f64::INFINITY)
            }
        },
        Err(e) => {
            positive_check_errored = true;
            failures.push(format!("③ positive content check anchor lookup failed: {e}"));
            (positive_check_message_id.unwrap_or(-1), -1, -1, f64::INFINITY)
        }
    };
    if !positive_check_errored && (top_hit_chunk_id != anchor_chunk_id || !(distance <= 1e-6)) {
        failures.push(format!(
            "③ positive content check failed: anchor chunk_id={anchor_chunk_id} (message_id={anchor_message_id}) top vec0 hit={top_hit_chunk_id} distance={distance}"
        ));
    }

    // ④ bidirectional anti-join, element = (message_id, chunk_idx).
    let mut eligible_keys: HashSet<(i64, u32)> = HashSet::new();
    for_each_expected_chunk(storage, 200, |c| {
        eligible_keys.insert((c.message_id, c.chunk_idx));
        Ok(())
    })?;
    let embedded_keys: HashSet<(i64, u32)> = conn
        .query_all_map(
            "SELECT message_id, chunk_idx FROM message_chunks WHERE generation_id = ?1",
            &params![generation_id],
            |row| Ok((row.get_typed::<i64>(0)?, row.get_typed::<u32>(1)?)),
        )?
        .into_iter()
        .collect();
    let eligible_not_embedded_count = eligible_keys.difference(&embedded_keys).count();
    let embedded_not_eligible_count = embedded_keys.difference(&eligible_keys).count();
    if eligible_not_embedded_count != 0 {
        failures.push(format!(
            "④ identity-set anti-join: {eligible_not_embedded_count} eligible chunk(s) have no message_chunks row in generation {generation_id}"
        ));
    }
    if embedded_not_eligible_count != 0 {
        failures.push(format!(
            "④ identity-set anti-join: {embedded_not_eligible_count} message_chunks row(s) in generation {generation_id} are no longer eligible"
        ));
    }

    // ⑤ canonicalize-version identity match.
    if canonicalize_version_actual != i64::from(CANONICALIZE_PIPELINE_VERSION) {
        failures.push(format!(
            "⑤ canonicalize_version mismatch: generation has {canonicalize_version_actual}, running binary expects {CANONICALIZE_PIPELINE_VERSION}"
        ));
    }

    // ⑥ PRAGMA foreign_key_check.
    let foreign_key_violation_count = conn.query_all_map("PRAGMA foreign_key_check", &[], |_row| Ok(()))?.len();
    if foreign_key_violation_count != 0 {
        failures.push(format!("⑥ PRAGMA foreign_key_check reported {foreign_key_violation_count} violation(s)"));
    }

    // ⑦ vec0-vs-message_chunks bidirectional anti-join.
    let chunk_count: i64 = conn.query_row_map(
        "SELECT COUNT(*) FROM message_chunks WHERE generation_id = ?1",
        &params![generation_id],
        |row| row.get_typed(0),
    )?;
    let vec0_row_count = match vector_domain::count_vec0_rows_for_generation(conn, generation_id) {
        Ok(count) => count,
        Err(e) => {
            failures.push(format!("⑦ vec0 row-count reconciliation errored for generation {generation_id} (vec0 table missing or unreadable): {e}"));
            -1
        }
    };
    let (chunks_missing_from_vec0, vec0_chunks_missing_from_message_chunks) = if vec0_row_count >= 0 {
        let (a, b) = vector_domain::count_vec0_chunks_set_mismatch_for_generation(conn, generation_id)?;
        (a, b)
    } else {
        (0, 0)
    };
    if chunks_missing_from_vec0 != 0 || vec0_chunks_missing_from_message_chunks != 0 {
        failures.push(format!(
            "⑦ vec0/message_chunks identity-set mismatch for generation {generation_id}: \
             {chunks_missing_from_vec0} message_chunks row(s) missing from vec0, \
             {vec0_chunks_missing_from_message_chunks} vec0 row(s) missing from message_chunks \
             (vec0 has {vec0_row_count} row(s), message_chunks has {chunk_count})"
        ));
    }

    // ⑧⑨: one pass over expected-vs-stored, keyed by (message_id, chunk_idx)
    // -- recomputed content_hash (⑧, full-table), span/conversation_id/
    // completeness (⑨).
    let mut expected_by_key: std::collections::HashMap<(i64, u32), (i64, usize, usize, String)> = std::collections::HashMap::new();
    for_each_expected_chunk(storage, 200, |c| {
        expected_by_key.insert((c.message_id, c.chunk_idx), (c.conversation_id, c.byte_start, c.byte_end, c.content_hash));
        Ok(())
    })?;
    let stored_rows: Vec<(i64, i64, u32, i64, i64, String)> = conn.query_all_map(
        "SELECT message_id, conversation_id, chunk_idx, byte_start, byte_end, content_hash FROM message_chunks WHERE generation_id = ?1",
        &params![generation_id],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?, row.get_typed(4)?, row.get_typed(5)?)),
    )?;
    let mut stored_by_key: std::collections::HashMap<(i64, u32), (i64, i64, i64, String)> = std::collections::HashMap::new();
    for (message_id, conversation_id, chunk_idx, byte_start, byte_end, content_hash) in stored_rows {
        stored_by_key.insert((message_id, chunk_idx), (conversation_id, byte_start, byte_end, content_hash));
    }
    let mut hash_mismatch = 0u64;
    let mut span_mismatch = 0u64;
    let mut conversation_id_mismatch = 0u64;
    let mut completeness_missing = 0u64;
    let mut completeness_extra = 0u64;
    for (key, (exp_conv, exp_start, exp_end, exp_hash)) in &expected_by_key {
        match stored_by_key.get(key) {
            Some((st_conv, st_start, st_end, st_hash)) => {
                if st_hash != exp_hash {
                    hash_mismatch += 1;
                }
                if *st_start as usize != *exp_start || *st_end as usize != *exp_end {
                    span_mismatch += 1;
                }
                if st_conv != exp_conv {
                    conversation_id_mismatch += 1;
                }
            }
            None => completeness_missing += 1,
        }
    }
    for key in stored_by_key.keys() {
        if !expected_by_key.contains_key(key) {
            completeness_extra += 1;
        }
    }
    let chunk_holes_remaining: i64 = conn.query_row_map(
        "SELECT COUNT(*) FROM chunk_holes WHERE generation_id = ?1",
        &params![generation_id],
        |row| row.get_typed(0),
    )?;
    if hash_mismatch != 0 {
        failures.push(format!("⑧ {hash_mismatch} chunk(s) have a stored content_hash that does not match the recomputed one"));
    }
    if span_mismatch != 0 {
        failures.push(format!("⑨ {span_mismatch} chunk(s) have a stored byte span that does not match the recomputed one"));
    }
    if completeness_missing != 0 || completeness_extra != 0 {
        failures.push(format!(
            "⑨ completeness mismatch: {completeness_missing} expected chunk(s) missing from storage, {completeness_extra} stored chunk(s) not in the expected set"
        ));
    }
    if conversation_id_mismatch != 0 {
        failures.push(format!("⑨ {conversation_id_mismatch} chunk(s) have a stored conversation_id that does not match the owning message's"));
    }
    if chunk_holes_remaining != 0 {
        failures.push(format!("⑨ {chunk_holes_remaining} chunk_holes row(s) remain outstanding for generation {generation_id}"));
    }

    // ⑩⑪: ownership resample + fingerprint re-verification, both gated on
    // `embedder` being `Some` (plan v5.1: `None` => passed=false).
    let mut ownership_checked = 0u64;
    let mut ownership_failed = 0u64;
    let mut ownership_skipped = false;
    let mut fingerprint_ok = false;
    match embedder {
        None => {
            ownership_skipped = true;
            failures.push("⑩ ownership check skipped: embedder=None (only a --no-ownership diagnostic may pass None; the resulting report is never a clean activation verdict)".to_string());
            failures.push("⑪ fingerprint re-verification skipped: embedder=None".to_string());
        }
        Some(embed_fn) => {
            let n = usize::try_from(chunk_count).unwrap_or(0).min(ownership_sample);
            let mut chunk_ids: Vec<i64> = conn.query_all_map(
                "SELECT chunk_id FROM message_chunks WHERE generation_id = ?1",
                &params![generation_id],
                |row| row.get_typed(0),
            )?;
            chunk_ids.sort_by_key(|&id| ownership_sample_key(ownership_seed, id));
            chunk_ids.truncate(n);
            for chunk_id in &chunk_ids {
                ownership_checked += 1;
                let row: Option<(i64, i64, i64, Vec<u8>)> = conn.query_opt_map(
                    "SELECT message_id, byte_start, byte_end, embedding FROM message_chunks WHERE generation_id = ?1 AND chunk_id = ?2",
                    &params![generation_id, *chunk_id],
                    |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?)),
                )?;
                let Some((message_id, byte_start, byte_end, stored_blob)) = row else {
                    ownership_failed += 1;
                    failures.push(format!("⑩ chunk_id={chunk_id} disappeared mid-audit (concurrent write)"));
                    continue;
                };
                let ownership_result: Result<()> = (|| {
                    let (_conv_id, role, content) = load_message_once(storage, message_id)?;
                    let normalized = crate::search::eligibility::normalized_for_chunks(&content);
                    let (bs, be) = (usize::try_from(byte_start)?, usize::try_from(byte_end)?);
                    if be > normalized.len() || bs > be {
                        bail!("chunk span [{bs},{be}) out of bounds for message {message_id}'s normalized text (len {})", normalized.len());
                    }
                    let text = &normalized[bs..be];
                    let stored_vec = schema::le_blob_to_f32_vector(&stored_blob)?;
                    let fresh = embed_fn(&[text]).map_err(|e| anyhow!("re-embed failed: {e}"))?;
                    let fresh_vec = fresh.first().ok_or_else(|| anyhow!("re-embed returned no vector"))?;
                    let cos = cosine_similarity(&stored_vec, fresh_vec);
                    if cos < 0.999 {
                        bail!("fresh-vs-stored cosine {cos} < 0.999 (role={role})");
                    }
                    let hits = vector_domain::vec0_knn(conn, generation_id, &stored_vec, 1)?;
                    let (top_hit, distance) = hits.first().copied().unwrap_or((-1, f64::INFINITY));
                    if top_hit != *chunk_id || !(distance <= 1e-6) {
                        bail!("vec0 row for chunk_id={chunk_id} does not match message_chunks' own BLOB (vec0 top hit={top_hit}, distance={distance})");
                    }
                    Ok(())
                })();
                if let Err(e) = ownership_result {
                    ownership_failed += 1;
                    failures.push(format!("⑩ ownership check failed for chunk_id={chunk_id}: {e}"));
                }
            }
            if ownership_failed != 0 {
                failures.push(format!("⑩ {ownership_failed}/{ownership_checked} sampled chunk(s) failed ownership verification"));
            }

            match compute_fresh_fingerprint_via(embed_fn, dim_usize) {
                Ok(fresh_fingerprint) => {
                    fingerprint_ok = fingerprint_matches(&stored_fingerprint, &fresh_fingerprint, dim_usize);
                    if !fingerprint_ok {
                        failures.push("⑪ fingerprint re-verification failed: fresh sentinel embeddings no longer match the stored generation fingerprint".to_string());
                    }
                }
                Err(e) => {
                    failures.push(format!("⑪ fingerprint re-verification errored: {e}"));
                }
            }
        }
    }

    let passed = failures.is_empty() && !ownership_skipped;
    Ok(ActivationAuditReportV5 {
        generation_id,
        passed,
        dim_mismatch_count,
        finite_norm_sample_size,
        finite_norm_checked,
        finite_norm_violation_count,
        positive_check_message_id: anchor_message_id,
        positive_check_chunk_id: anchor_chunk_id,
        positive_check_top_hit_chunk_id: top_hit_chunk_id,
        positive_check_distance: distance,
        eligible_not_embedded_count,
        embedded_not_eligible_count,
        canonicalize_version_expected: CANONICALIZE_PIPELINE_VERSION,
        canonicalize_version_actual,
        foreign_key_violation_count,
        chunk_count,
        vec0_row_count,
        chunks_missing_from_vec0,
        vec0_chunks_missing_from_message_chunks,
        hash_mismatch,
        span_mismatch,
        completeness_missing,
        completeness_extra,
        conversation_id_mismatch,
        chunk_holes_remaining,
        ownership_checked,
        ownership_failed,
        ownership_seed,
        ownership_skipped,
        fingerprint_ok,
        failure_reasons: failures,
    })
}

/// The fixed activation-time policy plan v5.1 mandates for every real
/// caller ("激活路径（index --semantic / models backfill）必须传
/// Some(embedder)、样本 200、seed 落日志"): run [`run_activation_audit_v5`]
/// with a real embedder (never `None`), `OWNERSHIP_SAMPLE_SIZE_DEFAULT`
/// (200), and log `ownership_seed` so a later investigation can find
/// exactly which chunks a given run's ownership check sampled. Standalone
/// (not folded into [`run_db_vector_catchup_backfill_v5`]) so both the
/// backfill's own activation step and a future standalone re-audit entry
/// point share one policy definition.
pub fn activate_generation_v5(
    storage: &FrankenStorage,
    generation_id: i64,
    embedder: &dyn Fn(&[&str]) -> std::result::Result<Vec<Vec<f32>>, String>,
    ownership_seed: u64,
) -> Result<ActivationAuditReportV5> {
    tracing::info!(
        generation_id,
        ownership_seed,
        ownership_sample = OWNERSHIP_SAMPLE_SIZE_DEFAULT,
        "db_vector_catchup (T8): running v5 activation audit"
    );
    run_activation_audit_v5(
        storage,
        generation_id,
        ACTIVATION_AUDIT_V5_DEFAULT_FINITE_NORM_SAMPLE_SIZE,
        None,
        Some(embedder),
        OWNERSHIP_SAMPLE_SIZE_DEFAULT,
        ownership_seed,
    )
}

/// The exact `switch_active_generation` verify closure the v5 activation
/// path uses (T8.5, task book #92b) -- pulled out to a named function, not
/// left as an inline closure, so the same TOCTOU-window tests that exercise
/// this function also exercise the production wiring: a mutation that
/// deletes the `verify_no_activation_toctou_drift_v5_in_tx` call *here*
/// (rather than inside that function's own body) is caught by those tests
/// too, closing the exact "verify function exists but the real switch
/// closure never calls it" gap T8's own hand-off left open for the
/// pre-T8.5 state of this call site.
fn v5_switch_guard_in_tx(tx: &Tx, generation_id: i64, pre_audit_chunk_count: i64) -> Result<(), StorageError> {
    schema::verify_no_activation_toctou_drift_v5_in_tx(tx, generation_id, pre_audit_chunk_count)?;
    tx.execute("UPDATE embedding_generations SET audit_status = 'passed' WHERE id = ?1", &params![generation_id])?;
    Ok(())
}

/// Drive one full v5 chunk-domain catch-up run (T8, plan v5.1, task book
/// #92): find-or-create the generation by policy+fingerprint identity
/// ([`find_reusable_or_create_generation_v5`]) -> claim/purge stale
/// `chunk_staging` -> drain `chunk_holes` in key-paged batches (embed via
/// `embedder`, small per-batch staging transaction, one message load per
/// distinct `message_id` -- [`load_message_once`]/[`classify_chunk_hole`])
/// -> move staged rows into `message_chunks` + `vec0` at each batch's end
/// -> reverse-reconcile every touched message's stored chunks against its
/// current expected set -> activate via [`activate_generation_v5`] iff no
/// holes remain.
///
/// `identity`/`fingerprint` are caller-supplied (not probed internally)
/// so this function -- and everything it calls -- is fully exercisable
/// against a deterministic mock `embedder` in tests, with zero live
/// Infinity dependency; the real CLI call sites probe them once via
/// [`crate::search::infinity::probe_identity_and_fingerprint`] and pass
/// the results straight through.
#[allow(clippy::too_many_arguments)]
pub fn run_db_vector_catchup_backfill_v5(
    storage: &FrankenStorage,
    batch_size: usize,
    identity: &InfinityServedIdentity,
    canonicalize_version: u32,
    chunking_policy_version: u32,
    fingerprint: &[u8],
    embedder: &dyn Fn(&[&str]) -> std::result::Result<Vec<Vec<f32>>, String>,
    ownership_seed: u64,
) -> Result<DbVectorCatchupReport> {
    if batch_size == 0 {
        bail!("batch_size must be > 0");
    }
    let dim = i64::try_from(identity.dimension)
        .map_err(|_| anyhow!("infinity dimension {} does not fit in i64", identity.dimension))?;
    let now_ms = FrankenStorage::now_millis();

    let (generation_id, reused_existing_generation) = find_reusable_or_create_generation_v5(
        storage.raw(),
        identity,
        canonicalize_version,
        chunking_policy_version,
        fingerprint,
        now_ms,
    )?;
    // Idempotent (`CREATE VIRTUAL TABLE IF NOT EXISTS`): a no-op for a
    // reused generation, and the one place a brand-new generation's vec0
    // table actually gets created (T8 populates it incrementally via
    // `insert_vec0_rows_in_tx`, never a bulk rebuild, so nothing else in
    // this function would ever create it otherwise).
    vector_domain::create_vec0_table_for_generation(storage.raw(), generation_id, dim)
        .context("ensuring the v5 chunk-domain vec0 table exists for this generation")?;

    // Claim/purge stale staging up front (crash-resume): every currently
    // expected chunk whose staging row already matches (same span+hash) is
    // "reusable" and kept; anything else left over from a prior crashed
    // run is purged, so a re-embed is never skipped for content that has
    // since changed.
    let mut all_expected: Vec<ExpectedChunk> = Vec::new();
    for_each_expected_chunk(storage, 200, |c| {
        all_expected.push(c);
        Ok(())
    })?;
    let (reusable_staged_keys, staging_purged) = storage
        .raw()
        .with_tx(TxMode::Immediate, |tx| {
            let reusable = schema::find_reusable_staging_in_tx(tx, generation_id, &all_expected)?;
            let purged = schema::purge_stale_staging_in_tx(tx, generation_id, &reusable)?;
            Ok((reusable, purged))
        })
        .context("claiming/purging chunk_staging at the start of the T8 catch-up run")?;
    let staging_reused = reusable_staged_keys.len() as u64;
    let reusable_staged_keys: HashSet<(i64, u32)> = reusable_staged_keys.into_iter().collect();

    let mut chunks_embedded = 0u64;
    let mut holes_written_off_beyond_expected = 0u64;
    let mut messages_loaded = 0u64;
    let mut touched_message_ids: HashSet<i64> = HashSet::new();

    let mut after: Option<(i64, u32)> = None;
    let mut current: Option<(i64, Vec<ExpectedChunk>)> = None; // (message_id, expected)
    loop {
        let keys = fetch_hole_keys(storage, generation_id, after, batch_size)?;
        if keys.is_empty() {
            break;
        }
        after = keys.last().map(|k| (k.message_id, k.chunk_idx));

        let mut batch_rows: Vec<ChunkRow> = Vec::new();
        let mut batch_keys: Vec<(i64, u32)> = Vec::new();
        let mut resolved_off: Vec<(i64, u32)> = Vec::new();
        let mut off_beyond_expected: Vec<(i64, u32)> = Vec::new();
        // Collected here, embedded in one batched call below (control
        // plane 2026-09-04: T12 shards ~2M chunks, one-Infinity-call-per-
        // chunk is not viable at that scale -- a page's worth of pending
        // embeds, up to `batch_size`, goes out as a single request, same
        // batching discipline v4's `embed_messages_with_sink` already
        // uses for `message_embeddings`).
        let mut pending_embed: Vec<(i64, u32, i64, ChunkSpanRef, String)> = Vec::new();

        for key in &keys {
            touched_message_ids.insert(key.message_id);
            if current.as_ref().map(|(mid, _)| *mid) != Some(key.message_id) {
                let (conversation_id, role, content) = load_message_once(storage, key.message_id)?;
                messages_loaded += 1;
                let expected = if canonical_role(&role).is_none() {
                    Vec::new()
                } else {
                    expected_chunks(key.message_id, conversation_id, &role, &content)
                };
                current = Some((key.message_id, expected));
            }
            let (_, expected) = current.as_ref().expect("just set above");

            if canonical_role_is_excluded(storage, key.message_id, &current)? {
                resolved_off.push((key.message_id, key.chunk_idx));
                continue;
            }

            match classify_chunk_hole(key, expected) {
                ChunkHoleDisposition::Embed(span) => {
                    let map_key = (key.message_id, key.chunk_idx);
                    if reusable_staged_keys.contains(&map_key) {
                        // Crash-resume fast path: a prior (possibly
                        // crashed) run already staged this exact chunk
                        // (same span+hash, confirmed by `find_reusable_
                        // staging_in_tx` up front) -- move it straight
                        // into `message_chunks`/`vec0` without spending a
                        // second (real, possibly expensive) Infinity call
                        // re-embedding content that was already embedded.
                        batch_keys.push(map_key);
                    } else {
                        let (conversation_id, _role, content) = load_message_once(storage, key.message_id)?;
                        let normalized = crate::search::eligibility::normalized_for_chunks(&content);
                        if span.byte_end > normalized.len() || span.byte_start > span.byte_end {
                            bail!(
                                "chunk span [{},{}) out of bounds for message {}'s normalized text (len {})",
                                span.byte_start, span.byte_end, key.message_id, normalized.len()
                            );
                        }
                        let text = normalized[span.byte_start..span.byte_end].to_string();
                        pending_embed.push((key.message_id, key.chunk_idx, conversation_id, span, text));
                    }
                }
                ChunkHoleDisposition::WriteOffCanonicalizeEmpty | ChunkHoleDisposition::WriteOffOutOfEligibilityScope => {
                    resolved_off.push((key.message_id, key.chunk_idx));
                }
                ChunkHoleDisposition::WriteOffIndexBeyondExpected => {
                    off_beyond_expected.push((key.message_id, key.chunk_idx));
                }
            }
        }

        if !pending_embed.is_empty() {
            let texts: Vec<&str> = pending_embed.iter().map(|(_, _, _, _, t)| t.as_str()).collect();
            let vectors = embedder(&texts).map_err(|e| anyhow!("batched embedding of {} chunk(s) failed: {e}", texts.len()))?;
            if vectors.len() != pending_embed.len() {
                bail!("embedder returned {} vector(s) for {} input(s) (batched embed)", vectors.len(), pending_embed.len());
            }
            for ((message_id, chunk_idx, conversation_id, span, _text), vector) in pending_embed.into_iter().zip(vectors) {
                if vector.len() != identity.dimension {
                    bail!("embedder returned dim {} != expected {} for message {message_id} chunk_idx {chunk_idx}", vector.len(), identity.dimension);
                }
                let norm = schema::l2_norm(&vector) as f32;
                batch_rows.push(ChunkRow {
                    generation_id,
                    message_id,
                    conversation_id,
                    chunk_idx: span.chunk_idx,
                    byte_start: span.byte_start,
                    byte_end: span.byte_end,
                    content_hash: span.content_hash,
                    embedding: vector,
                    norm,
                    created_at_ms: FrankenStorage::now_millis(),
                });
                batch_keys.push((message_id, chunk_idx));
            }
        }

        let batch_id = now_ms.wrapping_add(i64::try_from(chunks_embedded).unwrap_or(0));
        storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                if !batch_rows.is_empty() {
                    schema::stage_chunk_rows_in_tx(tx, batch_id, &batch_rows)?;
                }
                if !batch_keys.is_empty() {
                    // Moves *every* key in this batch -- both rows just
                    // staged above and rows that were already reusably
                    // staged from a prior run (skipped the embed, see the
                    // `reusable_staged_keys` branch above) -- in one pass,
                    // since `move_staging_to_chunks_in_tx` reads straight
                    // from `chunk_staging` by key regardless of which
                    // batch actually wrote that row.
                    let new_chunk_ids = schema::move_staging_to_chunks_in_tx(tx, generation_id, &batch_keys)?;
                    // Re-read the moved rows' own embedding BLOBs (not
                    // `batch_rows`, which is missing the reused-staging
                    // entries and would misalign with `new_chunk_ids`) to
                    // populate vec0.
                    let blobs: Vec<(i64, Vec<u8>)> = conn_blobs_for_chunk_ids(tx, &new_chunk_ids)?;
                    let vec0_rows: Vec<(i64, &[u8])> = blobs.iter().map(|(id, blob)| (*id, blob.as_slice())).collect();
                    vector_domain::insert_vec0_rows_in_tx(tx, generation_id, &vec0_rows)?;
                }
                for (message_id, chunk_idx) in resolved_off.iter().chain(off_beyond_expected.iter()) {
                    schema::write_off_chunk_hole_in_tx(tx, generation_id, *message_id, *chunk_idx)?;
                }
                Ok(())
            })
            .context("writing a T8 chunk catch-up batch (stage -> move -> vec0 insert -> hole resolve)")?;

        chunks_embedded = chunks_embedded.saturating_add(batch_rows.len() as u64);
        holes_written_off_beyond_expected = holes_written_off_beyond_expected.saturating_add(off_beyond_expected.len() as u64);
    }

    // Reverse reconciliation: every message this run touched (had at least
    // one hole key for) gets its full stored-chunk set pruned against its
    // current expected set -- catches a message whose chunk count shrank
    // (some of its old chunk rows are no longer expected at all, not just
    // "index beyond expected" for a hole that never existed for them).
    let mut chunks_pruned = 0u64;
    for message_id in &touched_message_ids {
        let expected: Vec<ExpectedChunk> = all_expected.iter().filter(|c| c.message_id == *message_id).cloned().collect();
        let pruned = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                let pruned_chunk_ids = schema::prune_chunks_not_in_expected_in_tx(tx, generation_id, *message_id, &expected)?;
                if !pruned_chunk_ids.is_empty() {
                    vector_domain::delete_vec0_rows_in_tx(tx, generation_id, &pruned_chunk_ids)?;
                }
                Ok(pruned_chunk_ids.len() as u64)
            })
            .context("reverse-reconciling a touched message's stored chunks")?;
        chunks_pruned = chunks_pruned.saturating_add(pruned);
    }

    let holes_after: i64 = storage.raw().query_row_map(
        "SELECT COUNT(*) FROM chunk_holes WHERE generation_id = ?1",
        &params![generation_id],
        |row| row.get_typed(0),
    )?;
    let mut activated = false;
    if holes_after == 0 {
        let audit_report = activate_generation_v5(storage, generation_id, embedder, ownership_seed)
            .context("running the T8 v5 activation audit before activating a chunk-domain generation")?;
        if !audit_report.passed {
            bail!(
                "generation {generation_id} failed T8 activation audit, refusing to activate: {}",
                audit_report.failure_reasons.join("; ")
            );
        }
        schema::switch_active_generation(storage.raw(), generation_id, FrankenStorage::now_millis(), |tx| {
            v5_switch_guard_in_tx(tx, generation_id, audit_report.chunk_count)
        })
        .context("activating v5 chunk-domain generation")?;
        activated = true;
    }

    let vec0_rows = usize::try_from(vector_domain::count_vec0_rows_for_generation(storage.raw(), generation_id).unwrap_or(0)).unwrap_or(0);

    Ok(DbVectorCatchupReport {
        generation_id,
        reused_existing_generation,
        embedder_id: identity.model_id.clone(),
        dim,
        eligible_seeded: 0,
        embedded_inserted: 0,
        stale_skipped: 0,
        holes_before: 0,
        holes_after: u64::try_from(holes_after).unwrap_or(0),
        vec0_rows,
        activated,
        holes_written_off_ineligible: 0,
        embeddings_pruned_ineligible: 0,
        cleanup_deleted_generation_ids: Vec::new(),
        cleanup_failures: Vec::new(),
        chunks_embedded,
        chunks_pruned,
        holes_written_off_beyond_expected,
        staging_reused,
        staging_purged,
        messages_loaded,
    })
}

/// Re-read `message_chunks.embedding` for exactly the `chunk_id`s
/// `move_staging_to_chunks_in_tx` just produced -- used instead of zipping
/// against `batch_rows` because that Vec is missing an entry for every key
/// that took the reused-staging fast path (never built a `ChunkRow` at
/// all), which would misalign a positional zip against `new_chunk_ids`.
fn conn_blobs_for_chunk_ids(tx: &crate::storage::api::Tx, chunk_ids: &[i64]) -> Result<Vec<(i64, Vec<u8>)>, StorageError> {
    let mut out = Vec::with_capacity(chunk_ids.len());
    for chunk_id in chunk_ids {
        let blob: Vec<u8> = tx.query_row_map(
            "SELECT embedding FROM message_chunks WHERE chunk_id = ?1",
            &params![*chunk_id],
            |row| row.get_typed(0),
        )?;
        out.push((*chunk_id, blob));
    }
    Ok(out)
}

/// `canonical_role`-exclusion re-check, factored out only to keep the
/// drain loop's per-key body readable -- always reads the *already-cached*
/// `current` message's role from `messages` again rather than caching the
/// role itself alongside `expected`, since the empty-`expected` case alone
/// cannot distinguish "role excluded" from "content canonicalizes empty"
/// (see [`ChunkHoleDisposition`]'s doc comment). One extra indexed lookup
/// per distinct message (not per hole key -- `current` still only changes
/// once per message), not per key.
fn canonical_role_is_excluded(storage: &FrankenStorage, message_id: i64, current: &Option<(i64, Vec<ExpectedChunk>)>) -> Result<bool> {
    let Some((mid, expected)) = current else { return Ok(false) };
    if *mid != message_id || !expected.is_empty() {
        return Ok(false);
    }
    let role: String = storage
        .raw()
        .query_row_map("SELECT role FROM messages WHERE id = ?1", &params![message_id], |row| row.get_typed(0))
        .with_context(|| format!("re-reading role for message {message_id}"))?;
    Ok(canonical_role(&role).is_none())
}

// =============================================================================
// Task book #80 (exec72): reverse-reconciliation prune. These tests exercise
// `schema::prune_ineligible_message_embedding_in_tx` and its effect on
// `run_activation_audit`'s check ④ directly -- not through
// `run_db_vector_catchup_backfill`, which unconditionally probes a live
// Infinity service before it does anything else (`w3_b2_activation_toctou_
// guard.rs`'s own doc comment states the same rationale for testing
// `switch_active_generation` directly instead of the full backfill
// wrapper). `run_activation_audit` itself never touches Infinity -- it only
// reads already-persisted rows -- so it, and the new prune primitive, are
// both exercisable here without live infra.
// =============================================================================
#[cfg(test)]
mod ineligible_embedding_prune_tests {
    use super::*;
    use crate::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};

    const TS: i64 = 1_770_551_400_000;
    const DIM: i64 = 4;

    fn open_storage(path: &std::path::Path) -> FrankenStorage {
        FrankenStorage::open(path).expect("open production storage")
    }

    fn ensure_agent(storage: &FrankenStorage) -> i64 {
        storage
            .ensure_agent(&Agent {
                id: None,
                slug: "claude_code".into(),
                name: "Claude Code".into(),
                version: Some("1.0".into()),
                kind: AgentKind::Cli,
            })
            .expect("ensure agent")
    }

    /// Insert a brand-new one-message conversation through the real
    /// production write path, matching `w3_5_b1_ineligible_hole_write_off
    /// .rs`/`w3_b2_activation_toctou_guard.rs`'s own fixture helper.
    fn insert_one_message_conversation(storage: &FrankenStorage, external_id: &str, content: &str) -> (i64, i64) {
        let agent_id = ensure_agent(storage);
        let conv = Conversation {
            id: None,
            agent_slug: "claude_code".into(),
            workspace: None,
            external_id: Some(external_id.into()),
            title: Some("exec72 prune fixture".into()),
            source_path: std::path::PathBuf::from(format!("/fixtures/{external_id}.jsonl")),
            started_at: Some(TS),
            ended_at: Some(TS + 60_000),
            approx_tokens: None,
            metadata_json: serde_json::Value::Null,
            messages: vec![Message {
                id: None,
                idx: 0,
                role: MessageRole::User,
                author: None,
                created_at: Some(TS),
                content: content.to_string(),
                extra_json: serde_json::Value::Null,
                snippets: vec![],
            }],
            source_id: "local".into(),
            origin_host: None,
        };
        storage.insert_conversation_tree(agent_id, None, &conv).expect("insert fixture conversation");
        let conv_id: i64 = storage
            .raw()
            .query_row_map("SELECT id FROM conversations WHERE external_id = ?1", &params![external_id], |row| {
                row.get_typed(0)
            })
            .unwrap();
        let doc_id: i64 = storage
            .raw()
            .query_row_map(
                "SELECT id FROM messages WHERE conversation_id = ?1 AND idx = 0",
                &params![conv_id],
                |row| row.get_typed(0),
            )
            .unwrap();
        (conv_id, doc_id)
    }

    fn embedding_row_count(storage: &FrankenStorage, generation_id: i64, doc_id: i64) -> i64 {
        storage
            .raw()
            .query_row_map(
                "SELECT COUNT(*) FROM message_embeddings WHERE generation_id = ?1 AND doc_id = ?2",
                &params![generation_id, doc_id],
                |row| row.get_typed(0),
            )
            .unwrap()
    }

    fn audit_status(storage: &FrankenStorage, generation_id: i64) -> String {
        storage
            .raw()
            .query_row_map("SELECT audit_status FROM embedding_generations WHERE id = ?1", &params![generation_id], |row| {
                row.get_typed(0)
            })
            .unwrap()
    }

    /// Positive case: an embedded message falls out of the eligibility
    /// chain (simulated here the way the task's own drill (`examples/w3_5_
    /// audit_orphans.rs`) proved the real 40-row incident worked -- content
    /// that used to be non-empty ends up empty by the time the eligibility
    /// scan reads it; #290's byte-cap truncation does this at read time
    /// without ever touching the `messages` row, this test does it by
    /// writing the row directly, an accepted equivalent per the task book
    /// since the prune logic only cares about the eligible/embedded set
    /// diff, not *why* a doc_id fell out). Before the prune, audit ④ must
    /// be the one thing that catches it (red). After the prune, the
    /// generation must fully pass.
    #[test]
    fn embedded_ineligible_row_is_pruned_and_audit_four_recovers() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));

        let (conv_a, doc_a) = insert_one_message_conversation(&storage, "exec72-stays-eligible", "real content, stays eligible");
        let (conv_b, doc_b) = insert_one_message_conversation(&storage, "exec72-falls-ineligible", "real content, will fall out");

        let generation_id = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::create_embedding_generation(tx, "bge-m3", DIM, CANONICALIZE_PIPELINE_VERSION, TS)
            })
            .unwrap();
        storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::insert_message_embedding(tx, generation_id, doc_a, conv_a, &[1.0, 0.0, 0.0, 0.0], "seed-hash-a", None, TS)?;
                schema::insert_message_embedding(tx, generation_id, doc_b, conv_b, &[0.0, 1.0, 0.0, 0.0], "seed-hash-b", None, TS)
            })
            .unwrap();
        vector_domain::create_vec0_table_for_generation(storage.raw(), generation_id, DIM).unwrap();
        vector_domain::rebuild_vec0_table_for_generation(storage.raw(), generation_id, DIM).unwrap();

        // R1-B1 setup: certify this generation active+passed, the
        // steady-state case (ruling ①) the demotion below must actually
        // protect -- a fresh never-activated generation would make the
        // demotion below a no-op that proves nothing.
        storage
            .raw()
            .execute(
                "UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1",
                &params![generation_id],
            )
            .unwrap();

        // Sanity: both messages start eligible and embedded -- audit ④
        // must be clean before the simulated fall-out below, or the rest
        // of this test would pass for the wrong reason.
        let baseline = run_activation_audit(&storage, generation_id, 10, Some(doc_a)).expect("baseline audit");
        assert_eq!(baseline.embedded_not_eligible_count, 0, "sanity: both rows must start eligible: {baseline:?}");

        // Simulate doc_b falling out of the eligibility chain.
        storage.raw().execute("UPDATE messages SET content = '' WHERE id = ?1", &params![doc_b]).unwrap();

        // Variant (mutation) proof: with no prune, audit ④ is the gate
        // that catches the now-orphaned embedding and refuses to pass.
        let before_prune = run_activation_audit(&storage, generation_id, 10, Some(doc_a)).expect("pre-prune audit");
        assert!(!before_prune.passed, "an embedded-but-ineligible row must fail activation audit");
        assert_eq!(
            before_prune.embedded_not_eligible_count, 1,
            "audit ④ must count exactly the one row that fell out: {before_prune:?}"
        );
        assert_eq!(embedding_row_count(&storage, generation_id, doc_b), 1, "sanity: the orphaned row is still present pre-prune");
        assert_eq!(audit_status(&storage, generation_id), "passed", "sanity: still certified passed pre-prune");

        // Positive proof: prune the row exactly as `run_db_vector_catchup_
        // backfill`'s reverse-reconciliation step does -- delete inside a
        // transaction that also demotes this (still-active, still-
        // certified) generation's `audit_status` back to 'pending' (R1-B1:
        // atomic with the delete, so there is no window where the deleted
        // row is committed but a stale 'passed' status still reads back),
        // then rebuild vec0 from what remains.
        let pruned = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                let pruned = schema::prune_ineligible_message_embedding_in_tx(tx, generation_id, doc_b)?;
                if pruned > 0 {
                    schema::demote_generation_readiness_if_active_in_tx(tx, generation_id)?;
                }
                Ok(pruned)
            })
            .unwrap();
        assert_eq!(pruned, 1, "R1-N3: the primitive must report the one row it actually deleted");
        assert_eq!(embedding_row_count(&storage, generation_id, doc_b), 0, "the pruned row must actually be deleted, not merely uncounted");
        // R1-B1: read this *before* rebuild/audit below -- the demotion
        // must already be visible immediately after the prune transaction
        // committed, not merely as a side effect of the audit that follows.
        assert_eq!(audit_status(&storage, generation_id), "pending", "R1-B1: pruning a row from an active+passed generation must demote it atomically, closing the false-green window");

        vector_domain::rebuild_vec0_table_for_generation(storage.raw(), generation_id, DIM).unwrap();
        let after_prune = run_activation_audit(&storage, generation_id, 10, Some(doc_a)).expect("post-prune audit");
        assert!(after_prune.passed, "activation audit must fully pass once the orphaned row is pruned: {after_prune:?}");
        assert_eq!(after_prune.embedded_not_eligible_count, 0);
        assert_eq!(after_prune.eligible_not_embedded_count, 0, "doc_b's message itself is still there, just empty -- correctly no longer eligible either");

        // A second prune attempt on the same (already-gone) row must be a
        // true no-op: 0 rows affected, and it must not demote an
        // already-'pending' generation into some other observable state.
        let repeat_pruned = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| schema::prune_ineligible_message_embedding_in_tx(tx, generation_id, doc_b))
            .unwrap();
        assert_eq!(repeat_pruned, 0, "R1-N3: pruning an already-gone row must report 0 affected rows, not 1");
    }

    /// R1-N2 (optional per task book, included since it is cheap and
    /// proves the exact SQL shape `run_db_vector_catchup_backfill` uses):
    /// a row embedded *after* the eligibility snapshot boundary must never
    /// be a prune candidate, even if it would otherwise look
    /// embedded-but-not-in-some-older-eligible-set -- this is what stops a
    /// concurrently-landed, genuinely-eligible message (embedded within
    /// this same catch-up call's own drain loop, timestamped after
    /// `now_ms`) from being misclassified as an orphan and deleted by the
    /// very call that just wrote it.
    #[test]
    fn candidate_scan_excludes_rows_created_at_or_after_the_snapshot() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));

        let (conv_old, doc_old) = insert_one_message_conversation(&storage, "exec72-n2-old-row", "embedded before the snapshot");
        let (conv_new, doc_new) = insert_one_message_conversation(&storage, "exec72-n2-new-row", "embedded during this call's own drain loop");

        let generation_id = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::create_embedding_generation(tx, "bge-m3", DIM, CANONICALIZE_PIPELINE_VERSION, TS)
            })
            .unwrap();
        let snapshot_ms = TS + 1_000;
        storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                // Written well before the snapshot boundary -- eligible to
                // be pruned if it ever falls out of the eligible set.
                schema::insert_message_embedding(tx, generation_id, doc_old, conv_old, &[1.0, 0.0, 0.0, 0.0], "seed-hash-old", None, TS)?;
                // Written at-or-after the snapshot boundary -- simulates a
                // row this same call's own drain loop just wrote; must
                // never be pruned regardless of eligibility-set staleness.
                schema::insert_message_embedding(
                    tx,
                    generation_id,
                    doc_new,
                    conv_new,
                    &[0.0, 1.0, 0.0, 0.0],
                    "seed-hash-new",
                    None,
                    snapshot_ms,
                )
            })
            .unwrap();

        // The exact query shape `run_db_vector_catchup_backfill` uses,
        // scoped to `created_at < snapshot_ms`. Neither row is in an
        // eligible-id set here (there is none in this focused test), so
        // both would qualify as candidates on eligibility grounds alone --
        // the `created_at` scope is the only thing standing between
        // `doc_new` and a wrongful delete.
        let candidates: Vec<i64> = storage
            .raw()
            .query_all_map(
                "SELECT me.doc_id FROM message_embeddings me JOIN messages m ON m.id = me.doc_id \
                 WHERE me.generation_id = ?1 AND me.created_at < ?2",
                &params![generation_id, snapshot_ms],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(candidates, vec![doc_old], "only the pre-snapshot row may ever become a prune candidate");
    }

    /// Task book #81 R2 review: `classify_hole_row` is the pure triage
    /// point that closes the diag3 exit-9 root cause (a hole whose doc_id
    /// fell outside the eligibility snapshot, but whose raw content is
    /// non-empty, used to sail past the old canonicalize-only filter and
    /// get embedded). All three dispositions in one table-driven test
    /// since there is no I/O to isolate them across.
    #[test]
    fn classify_hole_row_covers_all_three_dispositions() {
        let eligible_id_set: HashSet<i64> = [1i64, 2].into_iter().collect();
        let row = |doc_id: i64, content: &str| HoleMessageRow {
            doc_id,
            conversation_id: 1,
            content: content.to_string(),
            role: "user".to_string(),
        };

        assert_eq!(
            classify_hole_row(&row(1, "OK"), &eligible_id_set),
            HoleDisposition::WriteOffCanonicalizeEmpty,
            "a short acknowledgement must never reach the embedder, regardless of eligibility"
        );
        assert_eq!(
            classify_hole_row(&row(3, "real content, plenty of it"), &eligible_id_set),
            HoleDisposition::WriteOffOutOfEligibilityScope,
            "real (non-canonicalize-empty) content whose doc_id fell outside this call's eligibility \
             snapshot must be written off, not embedded -- the diag3 exit-9 root cause"
        );
        assert_eq!(
            classify_hole_row(&row(1, "real content, plenty of it"), &eligible_id_set),
            HoleDisposition::Embed,
            "real content whose doc_id is in the eligibility snapshot must be embedded"
        );
    }

    // `scan_eligible_message_ids_excludes_a_tail_message_past_the_byte_cap`
    // (task book #81 R2) retired under plan v5.1 T5: the 8 MiB
    // per-conversation lexical truncation cap it exercised (#290) is gone,
    // and `scan_eligible_message_ids` inherited that cap only as a
    // transitive side effect of reusing the (now capless) single-conversation
    // fetch helper for semantic/embedding checkpoint scanning. A tail
    // message that used to fall outside the cap is now semantically
    // eligible like any other message -- a real, intended behavior change
    // from dropping the cap, not a regression in this function.

    /// Task book #81 R2-N3: `demote_generation_readiness_if_active_in_tx`
    /// must only ever touch the exact `generation_id` it was called with,
    /// even when that row is not (or is no longer) the active one --
    /// unlike the unscoped `demote_active_generation_readiness_in_tx`,
    /// which would demote whatever generation *is* currently active
    /// instead, silently invalidating a certification the caller's own
    /// mutation never touched.
    #[test]
    fn demote_generation_readiness_if_active_never_touches_a_different_active_generation() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));

        let gen_active = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::create_embedding_generation(tx, "bge-m3", DIM, CANONICALIZE_PIPELINE_VERSION, TS)
            })
            .unwrap();
        let gen_other = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::create_embedding_generation(tx, "bge-m3", DIM, CANONICALIZE_PIPELINE_VERSION, TS + 1)
            })
            .unwrap();
        storage
            .raw()
            .execute(
                "UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1",
                &params![gen_active],
            )
            .unwrap();
        storage
            .raw()
            .execute("UPDATE embedding_generations SET is_active = 0, audit_status = 'passed' WHERE id = ?1", &params![gen_other])
            .unwrap();

        // Calling it for `gen_other` -- not active -- must be a true no-op
        // for both rows: `gen_other` itself stays 'passed' (it is not the
        // row this call is entitled to demote, since it is not active),
        // and `gen_active` (a wholly different generation this call was
        // never told about) must not be touched either.
        storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| schema::demote_generation_readiness_if_active_in_tx(tx, gen_other))
            .unwrap();
        assert_eq!(audit_status(&storage, gen_other), "passed", "a non-active generation must never be demoted by this call");
        assert_eq!(
            audit_status(&storage, gen_active),
            "passed",
            "a different generation (even the currently active one) must never be touched by a call scoped to gen_other"
        );

        // Calling it for `gen_active` -- the one actually active -- must
        // demote exactly that row.
        storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| schema::demote_generation_readiness_if_active_in_tx(tx, gen_active))
            .unwrap();
        assert_eq!(audit_status(&storage, gen_active), "pending", "the active generation this call was scoped to must be demoted");
        assert_eq!(audit_status(&storage, gen_other), "passed", "gen_other must still be untouched");
    }
}

// =============================================================================
// T8 (plan v5.1, task book #92) tests: chunk-level catch-up drain, staging
// crash-resume, generation reuse by policy+fingerprint, audits ④⑦⑧⑨⑩⑪.
// All non-`#[ignore]` tests use a deterministic mock embedder (no live
// Infinity); `fingerprint_live_infinity_roundtrip`-style live proof is
// `fingerprint_live_chunk_backfill_activates` at the bottom, `--ignored`.
// =============================================================================
#[cfg(test)]
mod chunk_catchup_v5_tests {
    use super::*;
    use crate::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
    use crate::search::chunking::CHUNKING_POLICY_VERSION;
    use crate::search::infinity::FINGERPRINT_SENTINELS;

    const TS: i64 = 1_770_600_000_000;
    const DIM: usize = 4;

    fn open_storage(path: &std::path::Path) -> FrankenStorage {
        FrankenStorage::open(path).expect("open production storage")
    }

    fn ensure_agent(storage: &FrankenStorage) -> i64 {
        storage
            .ensure_agent(&Agent { id: None, slug: "claude_code".into(), name: "Claude Code".into(), version: Some("1.0".into()), kind: AgentKind::Cli })
            .expect("ensure agent")
    }

    /// Deterministic, dependency-free "embedding": reproducible per exact
    /// input text (critical for the ownership check's fresh-vs-stored
    /// cosine to read exactly 1.0 for unmodified content), distinct with
    /// overwhelming probability across different texts. Not cryptographic,
    /// not `rand`-backed -- see [`ownership_sample_key`]'s doc comment for
    /// the same "no new dependency, a few lines of hashing is enough"
    /// reasoning applied here to embedding instead of sampling.
    /// A long, pure-ASCII, non-repeating filler of exactly `char_len` bytes
    /// (Champernowne-style increasing digit stream: "0123456789101112...",
    /// truncated) -- unlike `"a".repeat(n)`, no two same-length windows of
    /// this string are ever byte-identical, so slicing it into multiple
    /// chunks never accidentally produces genuine content twins (which
    /// would make [`deterministic_vector`] -- keyed purely on text --
    /// produce the same vector for two different `chunk_id`s, confusing
    /// audit ③'s self-hit check the same way v4's own `tied_content_twin`
    /// doc comment describes for repeated short messages). No markdown
    /// symbols or whitespace, so `canonicalize_for_embedding` passes it
    /// through byte-for-byte -- the chunk math in these tests assumes that.
    fn long_unique_filler(char_len: usize) -> String {
        let mut s = String::with_capacity(char_len + 16);
        let mut n: u64 = 0;
        while s.len() < char_len {
            s.push_str(&n.to_string());
            n += 1;
        }
        s.truncate(char_len);
        s
    }

    fn deterministic_vector(text: &str, dim: usize) -> Vec<f32> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        (0..dim)
            .map(|i| {
                let mut hasher = DefaultHasher::new();
                text.hash(&mut hasher);
                i.hash(&mut hasher);
                1.0 + (hasher.finish() % 1000) as f32 / 1000.0
            })
            .collect()
    }

    fn mock_embed(texts: &[&str]) -> std::result::Result<Vec<Vec<f32>>, String> {
        Ok(texts.iter().map(|t| deterministic_vector(t, DIM)).collect())
    }

    fn mock_fingerprint() -> Vec<u8> {
        let mut out = Vec::new();
        for s in FINGERPRINT_SENTINELS {
            out.extend_from_slice(&schema::f32_vector_to_le_blob(&deterministic_vector(s, DIM)));
        }
        out
    }

    fn mock_identity() -> InfinityServedIdentity {
        InfinityServedIdentity { model_id: "mock-embedder-t8".to_string(), dimension: DIM }
    }

    fn insert_conversation(storage: &FrankenStorage, external_id: &str, contents: &[&str]) -> Vec<i64> {
        let agent_id = ensure_agent(storage);
        let messages: Vec<Message> = contents
            .iter()
            .enumerate()
            .map(|(idx, content)| Message {
                id: None,
                idx: idx as i64,
                role: MessageRole::User,
                author: None,
                created_at: Some(TS + idx as i64),
                content: content.to_string(),
                extra_json: serde_json::Value::Null,
                snippets: vec![],
            })
            .collect();
        let conv = Conversation {
            id: None,
            agent_slug: "claude_code".into(),
            workspace: None,
            external_id: Some(external_id.into()),
            title: Some("T8 v5 fixture".into()),
            source_path: std::path::PathBuf::from(format!("/fixtures/{external_id}.jsonl")),
            started_at: Some(TS),
            ended_at: Some(TS + contents.len() as i64),
            approx_tokens: None,
            metadata_json: serde_json::Value::Null,
            messages,
            source_id: "local".into(),
            origin_host: None,
        };
        storage.insert_conversation_tree(agent_id, None, &conv).expect("insert fixture conversation");
        storage
            .raw()
            .query_all_map(
                "SELECT m.id FROM messages m JOIN conversations c ON c.id = m.conversation_id WHERE c.external_id = ?1 ORDER BY m.idx",
                &params![external_id],
                |row| row.get_typed(0),
            )
            .unwrap()
    }

    fn chunk_holes_count(storage: &FrankenStorage, generation_id: i64) -> i64 {
        storage.raw().query_row_map("SELECT COUNT(*) FROM chunk_holes WHERE generation_id = ?1", &params![generation_id], |row| row.get_typed(0)).unwrap()
    }

    fn message_chunks_count(storage: &FrankenStorage, generation_id: i64) -> i64 {
        storage.raw().query_row_map("SELECT COUNT(*) FROM message_chunks WHERE generation_id = ?1", &params![generation_id], |row| row.get_typed(0)).unwrap()
    }

    fn chunk_staging_count(storage: &FrankenStorage, generation_id: i64) -> i64 {
        storage.raw().query_row_map("SELECT COUNT(*) FROM chunk_staging WHERE generation_id = ?1", &params![generation_id], |row| row.get_typed(0)).unwrap()
    }

    /// Genesis call (empty DB -> creates+activates a fresh generation with
    fn backfill(storage: &FrankenStorage) -> Result<DbVectorCatchupReport> {
        run_db_vector_catchup_backfill_v5(storage, 100, &mock_identity(), CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &mock_fingerprint(), &mock_embed, 42)
    }

    /// Create the (pending, unactivated) generation + its empty vec0 table
    /// directly -- *not* via [`backfill`] -- so a fixture's messages can be
    /// inserted afterward with something for `register_chunk_holes_for_
    /// message_in_tx` to register against (it matches `is_active=1 OR
    /// audit_status='pending'`, and a freshly created row is already
    /// `audit_status='pending'` by DDL default, no activation needed).
    /// Deliberately does not run the full activate-audit path on a
    /// zero-chunk generation -- ③'s positive-check has no anchor to pick
    /// with nothing embedded yet, the same reason v4's own audit `?`-
    /// propagates rather than reporting `passed=false` for an empty
    /// generation; a real corpus is never actually empty in production.
    fn genesis(storage: &FrankenStorage) -> i64 {
        let identity = mock_identity();
        let generation_id = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::create_embedding_generation_v5(tx, &identity.model_id, DIM as i64, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &mock_fingerprint(), TS)
            })
            .unwrap();
        vector_domain::create_vec0_table_for_generation(storage.raw(), generation_id, DIM as i64).unwrap();
        generation_id
    }

    #[test]
    fn catchup_drains_multi_chunk_message_via_staging() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let generation_id = genesis(&storage);

        // "a"*2500, no separators -> 3 hard-cut chunks: [0,1000) [900,1900) [1800,2500).
        insert_conversation(&storage, "t8-multi-chunk", &[long_unique_filler(2500).as_str()]);
        assert_eq!(chunk_holes_count(&storage, generation_id), 3, "sanity: ingest-time hook must have registered 3 chunk_holes");

        let report = backfill(&storage).unwrap();
        assert_eq!(report.chunks_embedded, 3, "all 3 chunks must be embedded via staging: {report:?}");
        assert_eq!(message_chunks_count(&storage, generation_id), 3);
        assert_eq!(chunk_holes_count(&storage, generation_id), 0, "every hole must be resolved");
        assert_eq!(chunk_staging_count(&storage, generation_id), 0, "staging must be empty once moved");
        assert!(report.activated, "zero remaining holes must activate: {report:?}");
    }

    #[test]
    fn catchup_loads_each_message_once_per_run() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let generation_id = genesis(&storage);

        // 269,600 'a's -> exactly 300 chunks (299 hard-cut + 1 final), by
        // construction: chunk k (0-indexed) starts at 900*k; chunk 299
        // starts at 269,100 with 500 chars remaining (<=1000 -> final).
        insert_conversation(&storage, "t8-once-big", &[long_unique_filler(269_600).as_str()]);
        for i in 0..5 {
            insert_conversation(&storage, &format!("t8-once-small-{i}"), &[format!("a single-chunk message number {i} with plenty of distinct real content to embed").as_str()]);
        }
        assert_eq!(chunk_holes_count(&storage, generation_id), 305, "sanity: 300 + 5*1 holes registered");

        let report = backfill(&storage).unwrap();
        assert_eq!(report.chunks_embedded, 305);
        // Direct evidence of the "load each message once" invariant: the
        // per-message read counter incremented exactly once per distinct
        // message_id, across however many pages (batch_size=100 -> the
        // 300-chunk message spans 3 pages) that message's holes spanned.
        assert_eq!(report.messages_loaded, 6, "6 distinct messages must each be loaded exactly once, regardless of how many pages/chunks they span: {report:?}");
        assert_eq!(chunk_holes_count(&storage, generation_id), 0);
    }

    #[test]
    fn catchup_resumes_from_staging_after_crash() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let generation_id = genesis(&storage);

        // "a"*1500 -> 2 chunks: [0,1000) hard-cut, [900,1500) final.
        insert_conversation(&storage, "t8-resume", &["a".repeat(1500).as_str()]);
        let message_id: i64 = storage.raw().query_row_map("SELECT id FROM messages LIMIT 1", &[], |row| row.get_typed(0)).unwrap();
        let expected = crate::search::eligibility::expected_chunks(message_id, 0, "user", &"a".repeat(1500));
        assert_eq!(expected.len(), 2);

        // Simulate "chunk_idx=0 already embedded by a run that crashed
        // before it could move staging into message_chunks": stage it
        // directly with the real span/hash/vector a live run would have
        // produced.
        let chunk0 = &expected[0];
        let normalized = crate::search::eligibility::normalized_for_chunks(&"a".repeat(1500));
        let text0 = &normalized[chunk0.byte_start..chunk0.byte_end];
        let vector0 = deterministic_vector(text0, DIM);
        let norm0 = schema::l2_norm(&vector0) as f32;
        storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::stage_chunk_rows_in_tx(
                    tx,
                    999_000, // fabricated batch_id, distinct from any real run's
                    &[ChunkRow {
                        generation_id,
                        message_id,
                        conversation_id: 0, // overwritten below to the real value before asserting
                        chunk_idx: chunk0.chunk_idx,
                        byte_start: chunk0.byte_start,
                        byte_end: chunk0.byte_end,
                        content_hash: chunk0.content_hash.clone(),
                        embedding: vector0.clone(),
                        norm: norm0,
                        created_at_ms: TS,
                    }],
                )
            })
            .unwrap();
        // conversation_id above was a placeholder (0) -- correct it so the
        // reuse match (which does not check conversation_id) still lands
        // on a row `move_staging_to_chunks_in_tx` can insert without a FK
        // violation against the real conversations row.
        let conv_id: i64 = storage.raw().query_row_map("SELECT conversation_id FROM messages WHERE id = ?1", &params![message_id], |row| row.get_typed(0)).unwrap();
        storage
            .raw()
            .execute(
                "UPDATE chunk_staging SET conversation_id = ?1 WHERE generation_id = ?2 AND message_id = ?3 AND chunk_idx = ?4",
                &params![conv_id, generation_id, message_id, chunk0.chunk_idx],
            )
            .unwrap();

        let report = backfill(&storage).unwrap();
        assert_eq!(report.staging_reused, 1, "the pre-staged chunk_idx=0 must be recognized as reusable: {report:?}");
        assert_eq!(message_chunks_count(&storage, generation_id), 2, "both chunks must land in message_chunks, the reused one and the freshly-embedded one");
        assert_eq!(chunk_holes_count(&storage, generation_id), 0);
        assert_eq!(chunk_staging_count(&storage, generation_id), 0);
    }

    #[test]
    fn catchup_purges_stale_staging_on_hash_or_span_change() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let generation_id = genesis(&storage);

        insert_conversation(&storage, "t8-stale-staging", &["a single-chunk message with plenty of real content to embed"]);
        let message_id: i64 = storage.raw().query_row_map("SELECT id FROM messages LIMIT 1", &[], |row| row.get_typed(0)).unwrap();
        let conv_id: i64 = storage.raw().query_row_map("SELECT conversation_id FROM messages WHERE id = ?1", &params![message_id], |row| row.get_typed(0)).unwrap();

        // A staged row for chunk_idx=0 whose content_hash does NOT match
        // what `expected_chunks` currently says (simulates content that
        // changed since a prior crashed run staged this chunk).
        storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::stage_chunk_rows_in_tx(
                    tx,
                    999_001,
                    &[ChunkRow {
                        generation_id,
                        message_id,
                        conversation_id: conv_id,
                        chunk_idx: 0,
                        byte_start: 0,
                        byte_end: 10,
                        content_hash: "stale-hash-does-not-match-current-content".to_string(),
                        embedding: vec![9.0; DIM],
                        norm: 9.0,
                        created_at_ms: TS,
                    }],
                )
            })
            .unwrap();
        assert_eq!(chunk_staging_count(&storage, generation_id), 1, "sanity: the stale row is staged before the run");

        let report = backfill(&storage).unwrap();
        assert_eq!(report.staging_purged, 1, "the stale (hash-mismatched) staged row must be purged, not reused: {report:?}");
        assert_eq!(report.staging_reused, 0);
        assert_eq!(message_chunks_count(&storage, generation_id), 1, "the chunk must still get correctly (freshly) embedded despite the stale staging leftover");
        assert_eq!(chunk_holes_count(&storage, generation_id), 0);
    }

    #[test]
    fn catchup_active_generation_requires_policy_and_fingerprint() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let identity = mock_identity();
        let wrong_fingerprint = vec![0u8; mock_fingerprint().len()];

        let stale_generation_id = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::create_embedding_generation_v5(tx, &identity.model_id, DIM as i64, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &wrong_fingerprint, TS)
            })
            .unwrap();
        storage.raw().execute("UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1", &params![stale_generation_id]).unwrap();

        let (generation_id, reused) =
            find_reusable_or_create_generation_v5(storage.raw(), &identity, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &mock_fingerprint(), TS + 1).unwrap();
        assert_ne!(generation_id, stale_generation_id, "an active row with a drifted fingerprint must never be reused, even with matching embedder_id/dim/versions");
        assert!(!reused, "a fingerprint mismatch must fall through to creating a new generation: reused={reused}");
    }

    #[test]
    fn catchup_pending_generation_requires_policy_and_fingerprint() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let identity = mock_identity();
        let wrong_fingerprint = vec![0u8; mock_fingerprint().len()];

        let stale_generation_id = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::create_embedding_generation_v5(tx, &identity.model_id, DIM as i64, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &wrong_fingerprint, TS)
            })
            .unwrap();
        // Left is_active=0, audit_status='pending' (the DDL default) --
        // the pending-reuse tier.

        let (generation_id, reused) =
            find_reusable_or_create_generation_v5(storage.raw(), &identity, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &mock_fingerprint(), TS + 1).unwrap();
        assert_ne!(generation_id, stale_generation_id, "a pending row with a drifted fingerprint must never be reused");
        assert!(!reused);
    }

    /// Builds a small, fully-consistent generation (2 single-chunk
    /// messages, cleanly activated) for the audit tests below to corrupt
    /// in a targeted way and re-audit.
    fn clean_two_message_generation(storage: &FrankenStorage) -> (i64, i64, i64) {
        let generation_id = genesis(storage);
        insert_conversation(storage, "t8-audit-a", &["message A has plenty of real content to embed and chunk"]);
        insert_conversation(storage, "t8-audit-b", &["message B has plenty of real content to embed and chunk"]);
        let report = backfill(storage).unwrap();
        assert!(report.activated, "fixture setup must cleanly activate: {report:?}");
        assert_eq!(message_chunks_count(storage, generation_id), 2);
        let ids: Vec<i64> = storage.raw().query_all_map("SELECT chunk_id FROM message_chunks WHERE generation_id = ?1 ORDER BY chunk_id", &params![generation_id], |row| row.get_typed(0)).unwrap();
        (generation_id, ids[0], ids[1])
    }

    #[test]
    fn audit_4_bidirectional_anti_join_by_chunk() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, chunk_id_a, _chunk_id_b) = clean_two_message_generation(&storage);

        let baseline = run_activation_audit_v5(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
        assert_eq!(baseline.eligible_not_embedded_count, 0);
        assert_eq!(baseline.embedded_not_eligible_count, 0);

        // Delete one message_chunks row directly (bypassing the catch-up
        // worker) -- its message is still eligible, so this now leaves an
        // "eligible but not embedded" gap check ④ must catch.
        storage.raw().execute("DELETE FROM message_chunks WHERE chunk_id = ?1", &params![chunk_id_a]).unwrap();

        let after = run_activation_audit_v5(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
        assert!(!after.passed);
        assert_eq!(after.eligible_not_embedded_count, 1, "④ must count exactly the one row removed: {after:?}");
    }

    #[test]
    fn audit_7_detects_vec0_set_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, chunk_id_a, _chunk_id_b) = clean_two_message_generation(&storage);

        storage.raw().with_tx(TxMode::Immediate, |tx| vector_domain::delete_vec0_rows_in_tx(tx, generation_id, &[chunk_id_a])).unwrap();

        let after = run_activation_audit_v5(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
        assert!(!after.passed);
        assert_eq!(after.chunks_missing_from_vec0, 1, "⑦ must count the one message_chunks row now missing from vec0: {after:?}");
        assert_eq!(after.vec0_chunks_missing_from_message_chunks, 0);
    }

    #[test]
    fn audit_8_detects_stale_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, chunk_id_a, _chunk_id_b) = clean_two_message_generation(&storage);

        storage.raw().execute("UPDATE message_chunks SET content_hash = 'deliberately-wrong-hash' WHERE chunk_id = ?1", &params![chunk_id_a]).unwrap();

        let after = run_activation_audit_v5(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
        assert!(!after.passed);
        assert_eq!(after.hash_mismatch, 1, "⑧ must catch the one stored hash that no longer matches the recomputed one: {after:?}");
        assert_eq!(after.span_mismatch, 0, "only the hash was corrupted, not the span");
    }

    #[test]
    fn audit_9_detects_span_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, chunk_id_a, _chunk_id_b) = clean_two_message_generation(&storage);

        storage.raw().execute("UPDATE message_chunks SET byte_start = byte_start + 1 WHERE chunk_id = ?1", &params![chunk_id_a]).unwrap();

        let after = run_activation_audit_v5(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
        assert_eq!(after.span_mismatch, 1, "⑨ must catch the one chunk whose stored span no longer matches the recomputed one: {after:?}");
        assert!(!after.passed);
    }

    #[test]
    fn audit_9_detects_missing_extra_and_conversation_id() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, chunk_id_a, chunk_id_b) = clean_two_message_generation(&storage);

        // Missing: delete A's row entirely (also exercises ④, but ⑨'s
        // completeness_missing must independently count it too).
        let (message_id_a, conv_id_a, chunk_idx_a, byte_start_a, byte_end_a, hash_a, embedding_a, norm_a): (i64, i64, u32, i64, i64, String, Vec<u8>, f64) = storage
            .raw()
            .query_row_map(
                "SELECT message_id, conversation_id, chunk_idx, byte_start, byte_end, content_hash, embedding, norm FROM message_chunks WHERE chunk_id = ?1",
                &params![chunk_id_a],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?, row.get_typed(4)?, row.get_typed(5)?, row.get_typed(6)?, row.get_typed(7)?)),
            )
            .unwrap();
        storage.raw().execute("DELETE FROM message_chunks WHERE chunk_id = ?1", &params![chunk_id_a]).unwrap();

        // conversation_id mismatch: corrupt B's stored conversation_id.
        storage.raw().execute("UPDATE message_chunks SET conversation_id = conversation_id + 999999 WHERE chunk_id = ?1", &params![chunk_id_b]).unwrap();

        // Extra: insert a bogus row for message A at an index the current
        // expected-chunk set does not have (message A only has chunk_idx=0).
        storage
            .raw()
            .execute(
                "INSERT INTO message_chunks (generation_id, message_id, conversation_id, chunk_idx, byte_start, byte_end, content_hash, embedding, norm, created_at) \
                 VALUES (?1, ?2, ?3, 7, 0, 5, 'bogus-extra-hash', ?4, 1.0, ?5)",
                &params![generation_id, message_id_a, conv_id_a, schema::f32_vector_to_le_blob(&deterministic_vector("bogus", DIM)), TS],
            )
            .unwrap();
        let _ = (chunk_idx_a, byte_start_a, byte_end_a, hash_a, embedding_a, norm_a); // captured for readability, not reused

        let after = run_activation_audit_v5(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
        assert!(!after.passed);
        assert_eq!(after.completeness_missing, 1, "⑨ missing: {after:?}");
        assert_eq!(after.completeness_extra, 1, "⑨ extra: {after:?}");
        assert_eq!(after.conversation_id_mismatch, 1, "⑨ conversation_id: {after:?}");
    }

    #[test]
    fn audit_10_detects_swapped_vectors() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, chunk_id_a, chunk_id_b) = clean_two_message_generation(&storage);

        let embed_a: Vec<u8> = storage.raw().query_row_map("SELECT embedding FROM message_chunks WHERE chunk_id = ?1", &params![chunk_id_a], |row| row.get_typed(0)).unwrap();
        let embed_b: Vec<u8> = storage.raw().query_row_map("SELECT embedding FROM message_chunks WHERE chunk_id = ?1", &params![chunk_id_b], |row| row.get_typed(0)).unwrap();
        storage.raw().execute("UPDATE message_chunks SET embedding = ?1 WHERE chunk_id = ?2", &params![embed_b.clone(), chunk_id_a]).unwrap();
        storage.raw().execute("UPDATE message_chunks SET embedding = ?1 WHERE chunk_id = ?2", &params![embed_a.clone(), chunk_id_b]).unwrap();

        let after = run_activation_audit_v5(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
        assert!(!after.passed);
        assert_eq!(after.ownership_checked, 2);
        assert_eq!(after.ownership_failed, 2, "⑩ both swapped chunks must fail ownership (fresh re-embed no longer matches stored, and/or vec0 no longer matches the swapped BLOB): {after:?}");
        assert!(!after.ownership_skipped);
    }

    #[test]
    fn audit_10_none_embedder_fails_activation() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, _a, _b) = clean_two_message_generation(&storage);

        let after = run_activation_audit_v5(&storage, generation_id, 10, None, None, 10, 1).unwrap();
        assert!(after.ownership_skipped);
        assert!(!after.passed, "embedder=None must always fail the verdict, even if ①-⑨ are otherwise clean: {after:?}");
    }

    #[test]
    fn activation_path_passes_some_embedder_sample_200_and_logs_seed() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, _a, _b) = clean_two_message_generation(&storage);

        let seed = 987_654_321_u64;
        let report = activate_generation_v5(&storage, generation_id, &mock_embed, seed).unwrap();
        assert!(report.passed, "a clean generation must pass the fixed activation policy: {report:?}");
        assert!(!report.ownership_skipped, "activate_generation_v5 must always pass Some(embedder), never None");
        assert_eq!(report.ownership_seed, seed, "the seed passed in must be exactly what the report (and the tracing::info! log line) carries");
        assert_eq!(report.ownership_checked, 2, "min(200, chunk_count=2) = 2");
        assert!(report.fingerprint_ok);
    }

    fn is_active(storage: &FrankenStorage, generation_id: i64) -> bool {
        storage
            .raw()
            .query_row_map("SELECT is_active FROM embedding_generations WHERE id = ?1", &params![generation_id], |row| row.get_typed::<i64>(0))
            .unwrap()
            == 1
    }

    fn audit_status(storage: &FrankenStorage, generation_id: i64) -> String {
        storage.raw().query_row_map("SELECT audit_status FROM embedding_generations WHERE id = ?1", &params![generation_id], |row| row.get_typed(0)).unwrap()
    }

    /// T8.5 (task book #92b, R2-B2 chunk-domain class): the v5 activation
    /// branch's `switch_active_generation` verify closure previously
    /// called nothing beyond writing `audit_status='passed'` -- the full
    /// audit (`activate_generation_v5`) necessarily runs *outside* the
    /// switch transaction, opening a TOCTOU window between "the audit read
    /// chunk_holes==0 and verified completeness" and "the switch
    /// transaction actually flips `is_active`". A message landing in that
    /// window via the real production insert path registers a fresh
    /// `chunk_holes` row against this generation (`register_chunk_holes_
    /// for_message_in_tx` matches `is_active=1 OR audit_status='pending'`,
    /// and this fixture's generation is already active) -- the candidate
    /// would otherwise get silently re-promoted still missing that chunk.
    #[test]
    fn activation_v5_aborts_when_chunk_hole_appears_after_audit() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, _chunk_id_a, _chunk_id_b) = clean_two_message_generation(&storage);
        assert!(is_active(&storage, generation_id));
        assert_eq!(audit_status(&storage, generation_id), "passed");

        // Re-run the exact audit the real activation path runs (`db_vector_
        // catchup.rs`'s activation branch calls this same function
        // immediately before its `switch_active_generation` call),
        // capturing the `chunk_count` watermark it observed.
        let audit_report = activate_generation_v5(&storage, generation_id, &mock_embed, 42).unwrap();
        assert!(audit_report.passed, "sanity: a clean generation must pass before we inject drift: {audit_report:?}");

        // Simulate a concurrent writer landing a new message in the
        // audit-to-switch window via the real production insert path. The
        // same write entry point also runs the pre-existing (v4-era)
        // `demote_active_generation_readiness_in_tx`, which independently
        // flips this still-active generation's `audit_status` back to
        // 'pending' -- exactly the staleness signal an unconditional
        // `UPDATE ... SET audit_status = 'passed'` in the switch closure
        // (the pre-T8.5 behavior) would have silently clobbered, on top of
        // missing the chunk itself.
        insert_conversation(&storage, "t8-5-concurrent-drift", &["a brand new message landing in the toctou window"]);
        assert!(chunk_holes_count(&storage, generation_id) > 0, "sanity: the concurrent insert must have registered at least one chunk_holes row");
        assert_eq!(audit_status(&storage, generation_id), "pending", "sanity: the concurrent insert's demotion must have already fired");

        let result = schema::switch_active_generation(storage.raw(), generation_id, TS + 999_999, |tx| {
            v5_switch_guard_in_tx(tx, generation_id, audit_report.chunk_count)
        });

        assert!(result.is_err(), "a chunk_holes row appearing between audit-time and switch-time must abort the switch");
        assert!(is_active(&storage, generation_id), "an aborted re-switch must leave the pre-existing is_active flag untouched");
        assert_eq!(
            audit_status(&storage, generation_id),
            "pending",
            "an aborted re-switch must never write audit_status='passed', leaving the concurrent insert's demotion intact"
        );
    }

    /// T8.5 (task book #92b, R2-B2 chunk-domain class): a `message_chunks`
    /// shrink between audit-time and switch-time leaves `chunk_holes`
    /// untouched (deleting a stored chunk row does not itself create a
    /// hole) -- the reason this needs its own row-count recheck alongside
    /// the `chunk_holes`-emptiness one.
    #[test]
    fn activation_v5_aborts_when_chunk_count_drifts_after_audit() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, chunk_id_a, _chunk_id_b) = clean_two_message_generation(&storage);
        assert!(is_active(&storage, generation_id));
        assert_eq!(audit_status(&storage, generation_id), "passed");

        let audit_report = activate_generation_v5(&storage, generation_id, &mock_embed, 42).unwrap();
        assert!(audit_report.passed, "sanity: a clean generation must pass before we inject drift: {audit_report:?}");
        assert_eq!(audit_report.chunk_count, 2, "sanity: the fixture has exactly 2 chunks");

        // Simulate a concurrent shrink -- a chunk row disappearing between
        // audit-time and switch-time.
        storage.raw().execute("DELETE FROM message_chunks WHERE chunk_id = ?1", &params![chunk_id_a]).unwrap();
        assert_eq!(chunk_holes_count(&storage, generation_id), 0, "sanity: the direct delete must not have registered a hole");
        assert_eq!(message_chunks_count(&storage, generation_id), 1);

        let result = schema::switch_active_generation(storage.raw(), generation_id, TS + 999_999, |tx| {
            v5_switch_guard_in_tx(tx, generation_id, audit_report.chunk_count)
        });

        assert!(
            result.is_err(),
            "a message_chunks count drift between audit-time and switch-time must abort the switch, even with chunk_holes still empty"
        );
        assert!(is_active(&storage, generation_id));
        assert_eq!(audit_status(&storage, generation_id), "passed");
    }

    #[test]
    fn audit_11_detects_fingerprint_drift() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let identity = mock_identity();
        let wrong_fingerprint = vec![0u8; mock_fingerprint().len()];
        let generation_id = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::create_embedding_generation_v5(tx, &identity.model_id, DIM as i64, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &wrong_fingerprint, TS)
            })
            .unwrap();
        vector_domain::create_vec0_table_for_generation(storage.raw(), generation_id, DIM as i64).unwrap();

        let after = run_activation_audit_v5(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
        assert!(!after.fingerprint_ok, "a stored fingerprint that does not match the embedder's real sentinel output must fail ⑪: {after:?}");
        assert!(!after.passed);
    }

    #[test]
    fn audit_normal_path_prune_and_writeoff_zero() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let generation_id = genesis(&storage);
        insert_conversation(&storage, "t8-normal-path", &["a normal message with plenty of real content to embed and chunk cleanly"]);

        let report = backfill(&storage).unwrap();
        assert_eq!(report.chunks_pruned, 0, "the normal path must never prune anything: {report:?}");
        assert_eq!(report.holes_written_off_beyond_expected, 0);
        assert!(report.activated);
        let _ = generation_id;
    }

    /// plan v5.1 Global Constraints "三处同函数 + 独立 oracle": the drain
    /// loop's per-message `expected_chunks` call, audit ④'s `for_each_
    /// expected_chunk` eligible set, and audit ⑧⑨'s `for_each_expected_
    /// chunk`-derived expected-by-key map must never diverge from each
    /// other or from what actually ends up persisted -- there is exactly
    /// one shared primitive (`crate::search::eligibility`) all three read
    /// through, not three independent re-derivations that could drift.
    #[test]
    fn semantic_three_sites_agree() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let generation_id = genesis(&storage);
        insert_conversation(&storage, "t8-agree-a", &[long_unique_filler(2500).as_str(), "a short but real second message here"]);
        insert_conversation(&storage, "t8-agree-b", &["another real message with enough content to chunk"]);
        backfill(&storage).unwrap();

        let mut independently_computed: HashSet<(i64, u32, i64, i64, String)> = HashSet::new();
        for_each_expected_chunk(&storage, 200, |c| {
            independently_computed.insert((c.message_id, c.chunk_idx, c.byte_start as i64, c.byte_end as i64, c.content_hash));
            Ok(())
        })
        .unwrap();

        let stored: HashSet<(i64, u32, i64, i64, String)> = storage
            .raw()
            .query_all_map(
                "SELECT message_id, chunk_idx, byte_start, byte_end, content_hash FROM message_chunks WHERE generation_id = ?1",
                &params![generation_id],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?, row.get_typed(4)?)),
            )
            .unwrap()
            .into_iter()
            .collect();

        assert_eq!(stored, independently_computed, "the drain-time (per-message expected_chunks), audit-time (for_each_expected_chunk), and persisted sets must be identical -- no divergent re-derivation");
    }

    /// Live proof (real Infinity at 127.0.0.1:7997): a real chunk-domain
    /// backfill run must actually activate, using the real production
    /// embedder wrapper (`InfinityEmbedder::embed_batch_sync`) instead of
    /// the deterministic mock every other test in this module uses.
    /// `#[ignore]`d -- run explicitly with `--ignored`.
    #[test]
    #[ignore]
    fn fingerprint_live_chunk_backfill_activates() {
        use crate::search::embedder::Embedder as _;
        use crate::search::infinity::{InfinityConfig, InfinityEmbedder, probe_identity_and_fingerprint};
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));

        let config = InfinityConfig::from_env();
        let (identity, fingerprint) = probe_identity_and_fingerprint(&config).expect("live infinity identity+fingerprint probe");
        let embedder = InfinityEmbedder::new().expect("live infinity embedder");
        let embed_fn = |texts: &[&str]| embedder.embed_batch_sync(texts).map_err(|e| e.to_string());

        // Create the (pending) generation + its vec0 table directly --
        // not via a genesis backfill call on zero messages -- for the same
        // reason `genesis()` above does (③'s positive-check has no anchor
        // to pick with nothing embedded yet; a real corpus is never
        // actually empty in production).
        let generation_id = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::create_embedding_generation_v5(tx, &identity.model_id, i64::try_from(identity.dimension).unwrap(), CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &fingerprint, TS)
            })
            .unwrap();
        vector_domain::create_vec0_table_for_generation(storage.raw(), generation_id, i64::try_from(identity.dimension).unwrap()).unwrap();

        insert_conversation(&storage, "t8-live", &["a real message about how vec0 chunk-domain catch-up should behave against a live Infinity service"]);
        let report = run_db_vector_catchup_backfill_v5(&storage, 32, &identity, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &fingerprint, &embed_fn, 7).unwrap();
        assert_eq!(report.generation_id, generation_id);
        assert!(report.activated, "a real live drain of one small message must activate cleanly: {report:?}");
        assert!(report.chunks_embedded >= 1);
    }

    /// mission #92 Step 4/5 (T-R's own v5 positive fixture source, per
    /// control plane 2026-09-04): a synthetic 200-conversation corpus,
    /// drained through the *real* candidate release binary (via the run
    /// root wrapper, `$CASS_WRAP index --semantic`) against a real
    /// Infinity, must activate cleanly with a zero-failure audit and
    /// `ownership_checked == 200`. `#[ignore]`d, run with `--ignored`.
    ///
    /// No run-root path is hardcoded here (PUBLIC repo constraint,
    /// control plane 2026-09-04): the data dir comes from
    /// `CASS_W4_SYNTH_DIR` (falls back to an ephemeral tempdir if unset,
    /// so the test still runs standalone) and the wrapper binary from
    /// `CASS_WRAP` -- both set by whoever invokes this test, not baked
    /// into the source.
    ///
    /// The 200 conversations are seeded via the production write path
    /// directly (`insert_conversation_tree`) -- "走生产写入路径建库" -- not
    /// via any CLI ingest command (there is no source file to scan); only
    /// the *semantic* step goes through the real CLI subprocess. The
    /// generation is pre-created (same reason `genesis()`/the single-
    /// message live test above do it) via the exact same `probe_identity_
    /// and_fingerprint` call the CLI subprocess will independently make
    /// against the same live Infinity -- both resolve to the same
    /// identity+fingerprint bytes, so the subprocess's own generation
    /// lookup reuses this pre-created row (tier ① of `find_reusable_or_
    /// create_generation_v5`) instead of creating a second one.
    #[test]
    #[ignore]
    fn live_synth_200_v5_backfill_via_real_binary() {
        use crate::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
        use crate::search::infinity::{InfinityConfig, InfinityEmbedder, probe_identity_and_fingerprint};

        let synth_dir_env = std::env::var("CASS_W4_SYNTH_DIR").ok();
        let _tempdir_keepalive;
        let synth_dir: std::path::PathBuf = match &synth_dir_env {
            Some(dir) => {
                std::fs::create_dir_all(dir).expect("create CASS_W4_SYNTH_DIR");
                _tempdir_keepalive = None;
                std::path::PathBuf::from(dir)
            }
            None => {
                let t = tempfile::TempDir::new().unwrap();
                let p = t.path().to_path_buf();
                _tempdir_keepalive = Some(t);
                p
            }
        };
        let db_path = synth_dir.join("agent_search.db");

        let config = InfinityConfig::from_env();
        let (identity, fingerprint) = probe_identity_and_fingerprint(&config).expect("live infinity identity+fingerprint probe");

        let storage = FrankenStorage::open(&db_path).expect("open synth db");
        let generation_id = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::create_embedding_generation_v5(
                    tx,
                    &identity.model_id,
                    i64::try_from(identity.dimension).unwrap(),
                    CANONICALIZE_PIPELINE_VERSION,
                    CHUNKING_POLICY_VERSION,
                    &fingerprint,
                    TS,
                )
            })
            .unwrap();
        vector_domain::create_vec0_table_for_generation(storage.raw(), generation_id, i64::try_from(identity.dimension).unwrap()).unwrap();

        let agent_id = storage
            .ensure_agent(&Agent { id: None, slug: "claude_code".into(), name: "Claude Code".into(), version: Some("1.0".into()), kind: AgentKind::Cli })
            .unwrap();
        for i in 0..200 {
            let conv = Conversation {
                id: None,
                agent_slug: "claude_code".into(),
                workspace: None,
                external_id: Some(format!("t8-synth200-{i}")),
                title: Some("T8 synth-200-v5 fixture".into()),
                source_path: std::path::PathBuf::from(format!("/fixtures/synth200-{i}.jsonl")),
                started_at: Some(TS),
                ended_at: Some(TS + 1),
                approx_tokens: None,
                metadata_json: serde_json::Value::Null,
                messages: vec![Message {
                    id: None,
                    idx: 0,
                    role: MessageRole::User,
                    author: None,
                    created_at: Some(TS),
                    content: format!("synthetic T-R fixture message number {i} with distinct real content for chunk-domain backfill"),
                    extra_json: serde_json::Value::Null,
                    snippets: vec![],
                }],
                source_id: "local".into(),
                origin_host: None,
            };
            storage.insert_conversation_tree(agent_id, None, &conv).expect("insert synth conversation");
        }
        drop(storage);

        let wrapper = std::env::var("CASS_WRAP").expect("CASS_WRAP env var must point at the run-root wrapper script (no path hardcoded in source)");
        // control plane 2026-09-04 (root-cause correction): cass's built-in
        // agent source discovery walks HOME (`~/.codex`, `~/.claude`, ...)
        // directly, unaffected by XDG_CONFIG_HOME -- an inherited real HOME
        // makes `index` (even scoped to an isolated CASS_DATA_DIR) discover
        // and ingest the *real* local corpus. `CASS_W4_TEST_HOME` (an
        // empty, run-root-scoped directory the caller creates) must be
        // passed explicitly; no path is hardcoded in source.
        let test_home = std::env::var("CASS_W4_TEST_HOME").expect("CASS_W4_TEST_HOME env var must point at an empty run-root-scoped HOME (no path hardcoded in source)");
        // `$RUN_ROOT/cass-candidate` is T12's own setup-cass-fork.sh output
        // position (sha-asserted there) -- this test must not pre-occupy
        // it, so it points the wrapper at this run's own release build via
        // the wrapper's CASS_CAND_BIN override instead.
        let cand_bin = std::env::var("CASS_CAND_BIN").unwrap_or_else(|_| "/tmp/cc-cass-pr4-target/release/cass".to_string());

        // Dry run first (no --semantic): proves HOME isolation actually
        // worked -- the streaming-ingest summary must report exactly the
        // 200 synthetic conversations/messages just seeded, not a real
        // local corpus, before any Infinity call is ever made.
        let dry_run = std::process::Command::new(&wrapper)
            .arg("index")
            .env("CASS_DATA_DIR", &synth_dir)
            .env("HOME", &test_home)
            .env("CASS_CAND_BIN", &cand_bin)
            .output()
            .expect("spawn $CASS_WRAP index (dry run, no --semantic)");
        assert!(
            dry_run.status.success(),
            "dry-run `index` must exit 0: stdout={} stderr={}",
            String::from_utf8_lossy(&dry_run.stdout),
            String::from_utf8_lossy(&dry_run.stderr)
        );
        // HOME isolation proof: the 200 conversations were seeded directly
        // via the production write path (not by `index` scanning source
        // files), so a correctly-isolated `index` run finds *zero* new
        // conversations to discover from disk -- `total_conversations=0`
        // is the *positive* signal here, not a fluke; a real-corpus leak
        // (this test's original failure mode) would instead show
        // `discovered=true` for at least one connector and a large
        // nonzero total_conversations/total_messages count.
        let dry_run_stderr = String::from_utf8_lossy(&dry_run.stderr);
        assert!(
            dry_run_stderr.contains("total_conversations=0 total_messages=0"),
            "HOME isolation must be proven BEFORE any Infinity call: expected zero newly-discovered conversations (the 200 fixture rows were seeded directly, not via source-file ingest), got: {dry_run_stderr}"
        );
        assert!(
            !dry_run_stderr.contains("discovered=true"),
            "no connector may discover a real local corpus once HOME is isolated: {dry_run_stderr}"
        );
        let seeded_message_count: i64 = FrankenStorage::open_readonly(&db_path)
            .expect("reopen synth db read-only to confirm the 200 fixture rows survived the dry run")
            .raw()
            .query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))
            .unwrap();
        assert_eq!(seeded_message_count, 200, "the 200 directly-seeded messages must still be present after the dry run");

        let output = std::process::Command::new(&wrapper)
            .arg("index")
            .arg("--semantic")
            .env("CASS_DATA_DIR", &synth_dir)
            .env("HOME", &test_home)
            .env("CASS_CAND_BIN", &cand_bin)
            .output()
            .expect("spawn $CASS_WRAP index --semantic");
        assert!(
            output.status.success(),
            "real candidate binary `index --semantic` must exit 0: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let storage = FrankenStorage::open_readonly(&db_path).expect("reopen synth db read-only");
        let (active_generation_id, audit_status): (i64, String) = storage
            .raw()
            .query_row_map("SELECT id, audit_status FROM embedding_generations WHERE is_active = 1", &[], |row| Ok((row.get_typed(0)?, row.get_typed(1)?)))
            .expect("an active generation must exist after a successful CLI run");
        assert_eq!(active_generation_id, generation_id, "the CLI subprocess must have reused the pre-created generation (identity+fingerprint match), not created a second one");
        assert_eq!(audit_status, "passed");

        let embedder = InfinityEmbedder::new().expect("live infinity embedder for the re-verification audit");
        use crate::search::embedder::Embedder as _;
        let embed_fn = |texts: &[&str]| embedder.embed_batch_sync(texts).map_err(|e| e.to_string());
        let report = run_activation_audit_v5(&storage, generation_id, 500, None, Some(&embed_fn), 200, 12345).expect("re-audit the CLI-produced generation");
        assert!(report.passed, "the CLI-produced generation must re-audit clean: {report:?}");
        assert_eq!(report.hash_mismatch, 0, "⑧: {report:?}");
        assert_eq!(report.span_mismatch, 0, "⑨ span: {report:?}");
        assert_eq!(report.completeness_missing, 0, "⑨ completeness missing: {report:?}");
        assert_eq!(report.completeness_extra, 0, "⑨ completeness extra: {report:?}");
        assert_eq!(report.ownership_failed, 0, "⑩: {report:?}");
        assert!(report.fingerprint_ok, "⑪: {report:?}");
        assert_eq!(report.ownership_checked, 200, "min(200, chunk_count) must be 200 for a 200-message, one-chunk-each corpus: {report:?}");

        if synth_dir_env.is_some() {
            eprintln!("live_synth_200_v5_backfill_via_real_binary: synth-200-v5 library left at {} (not cleaned up)", synth_dir.display());
        }
    }
}
