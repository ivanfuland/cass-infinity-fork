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
            storage
                .raw()
                .with_tx(TxMode::Immediate, |tx| {
                    for row in canonicalize_empty.iter().chain(out_of_eligibility_scope.iter()) {
                        schema::write_off_ineligible_hole_in_tx(tx, generation_id, row.doc_id)?;
                    }
                    Ok(())
                })
                .context("writing off ineligible embedding_holes rows")?;
            holes_written_off_ineligible = holes_written_off_ineligible
                .saturating_add(u64::try_from(canonicalize_empty.len()).unwrap_or(0))
                .saturating_add(u64::try_from(out_of_eligibility_scope.len()).unwrap_or(0));
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
    // longer is (most commonly: a conversation's cumulative content
    // crosses the shared 8 MiB per-conversation cap -- `FrankenStorage::
    // fetch_messages_for_lexical_rebuild`'s `truncate_lexical_rebuild_
    // conversation_content`, #290 -- which `scan_eligible_message_ids`
    // reuses and which silently clears an already-embedded tail message's
    // content out of the eligibility scan). Left unpruned, such a row
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
                // false-green window `demote_active_generation_readiness_
                // in_tx` exists to prevent for every other mutation
                // category. Folding it into this same transaction, gated
                // on `pruned > 0`, makes the demotion atomic with the
                // delete it is compensating for -- no window where the
                // deleted row is committed but the stale 'passed' status
                // still reads back.
                if pruned > 0 {
                    schema::demote_active_generation_readiness_in_tx(tx)?;
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
                    schema::demote_active_generation_readiness_in_tx(tx)?;
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

    /// Task book #81 R2 review: proves `scan_eligible_message_ids` itself
    /// -- not just `classify_hole_row`'s consumption of its output -- puts
    /// the 8 MiB per-conversation truncation cap (#290) into the
    /// eligibility snapshot. A conversation with one message just over the
    /// cap followed by a second (tail) message: the cap boundary lands
    /// inside the first message (truncated, but still non-empty) and
    /// clears the second entirely, so only the first message's doc_id can
    /// ever be eligible.
    #[test]
    fn scan_eligible_message_ids_excludes_a_tail_message_past_the_byte_cap() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let agent_id = ensure_agent(&storage);

        // One byte over `LEXICAL_MAX_CONVERSATION_CONTENT_BYTES_DEFAULT`
        // (8 * 1024 * 1024) on its own -- guarantees truncation kicks in
        // within this single conversation regardless of the second
        // message's size.
        let big_content = "x".repeat(8 * 1024 * 1024 + 1);
        let conv = Conversation {
            id: None,
            agent_slug: "claude_code".into(),
            workspace: None,
            external_id: Some("exec72-r2-byte-cap-tail".into()),
            title: Some("exec72 R2 byte-cap fixture".into()),
            source_path: std::path::PathBuf::from("/fixtures/exec72-r2-byte-cap-tail.jsonl"),
            started_at: Some(TS),
            ended_at: Some(TS + 60_000),
            approx_tokens: None,
            metadata_json: serde_json::Value::Null,
            messages: vec![
                Message {
                    id: None,
                    idx: 0,
                    role: MessageRole::User,
                    author: None,
                    created_at: Some(TS),
                    content: big_content,
                    extra_json: serde_json::Value::Null,
                    snippets: vec![],
                },
                Message {
                    id: None,
                    idx: 1,
                    role: MessageRole::Assistant,
                    author: None,
                    created_at: Some(TS + 1_000),
                    content: "this tail message must fall outside the eligibility snapshot".to_string(),
                    extra_json: serde_json::Value::Null,
                    snippets: vec![],
                },
            ],
            source_id: "local".into(),
            origin_host: None,
        };
        storage.insert_conversation_tree(agent_id, None, &conv).expect("insert fixture conversation");
        let conv_id: i64 = storage
            .raw()
            .query_row_map(
                "SELECT id FROM conversations WHERE external_id = ?1",
                &params!["exec72-r2-byte-cap-tail"],
                |row| row.get_typed(0),
            )
            .unwrap();
        let doc_head: i64 = storage
            .raw()
            .query_row_map("SELECT id FROM messages WHERE conversation_id = ?1 AND idx = 0", &params![conv_id], |row| {
                row.get_typed(0)
            })
            .unwrap();
        let doc_tail: i64 = storage
            .raw()
            .query_row_map("SELECT id FROM messages WHERE conversation_id = ?1 AND idx = 1", &params![conv_id], |row| {
                row.get_typed(0)
            })
            .unwrap();

        let eligible = scan_eligible_message_ids(&storage).expect("scan eligibility");
        assert!(eligible.contains(&doc_head), "the truncated-but-nonempty head message must stay eligible");
        assert!(!eligible.contains(&doc_tail), "the fully-cleared tail message must not be eligible");
    }
}
