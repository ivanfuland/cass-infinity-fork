//! Catch-up worker orchestration for the DB-backed chunk-domain vector
//! schema (originally w3-3 Step0/Step1 task book #61, finalized as the
//! sole vector domain by T8/T11 plan v5.1). Bootstraps or resumes an
//! `embedding_generations` row by exact identity+fingerprint match, seeds
//! its `chunk_holes` from the production chunk-eligibility chain, drains
//! those holes through a live Infinity service with a key-paged staging
//! write, then republishes the generation's `vec0` index and flips the
//! active-generation pointer.
//!
//! This is an orchestration-layer API wired into `cass index --semantic` /
//! `cass models backfill` (`src/indexer/mod.rs`/`src/lib.rs`), not a CLI
//! surface of its own.
//!
//! Design record: `W3_ARTIFACTS/w3-3-exec54-step0-design.md` for the
//! original generation-reuse rulings (①/②, still followed by
//! [`find_reusable_or_create_generation`]); T8/T10.5 extended the design
//! to chunk-granularity holes and generation fingerprinting.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow, bail};

use crate::search::canonicalize::CANONICALIZE_PIPELINE_VERSION;
use crate::search::chunking::canonical_role;
use crate::search::eligibility::{ExpectedChunk, expected_chunks, for_each_expected_chunk};
use crate::search::frankensearch_types::cosine_similarity;
use crate::search::infinity::{InfinityServedIdentity, fingerprint_matches};
use crate::storage::api::{Conn, StorageError, Tx, TxMode, params};
use crate::storage::schema::{self, ChunkRow};
use crate::storage::sqlite::FrankenStorage;
use crate::storage::vector_domain;

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
    /// Legacy field from the retired message-granularity engine (T11):
    /// always `0` now that the chunk-domain engine below is the only vector
    /// catch-up path. Kept for `cass models backfill` JSON/human output
    /// stability.
    pub holes_written_off_ineligible: u64,
    /// Legacy field from the retired message-granularity engine (T11):
    /// always `0` now that the chunk-domain engine below is the only vector
    /// catch-up path. Kept for `cass models backfill` JSON/human output
    /// stability.
    pub embeddings_pruned_ineligible: u64,
    /// Orphaned (non-active, past the cleanup age threshold) generations
    /// deleted at the tail of this call (R1-W3-N3, extended T11 to the
    /// chunk domain). Empty on the common case (nothing old enough to
    /// prune yet).
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
    /// into `message_chunks` this run.
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
    /// covered by the message's current expected-chunk count).
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
    /// T10.5: `chunk_holes` rows seeded for a brand-new generation's ENTIRE
    /// expected-chunk set, in the same transaction the generation row
    /// itself was created in ([`find_reusable_or_create_generation`]'s doc
    /// comment). `0` for a reused generation (T6's ingest-time hook already
    /// covers it).
    pub holes_seeded: u64,
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
/// is older than the cleanup threshold, along with its chunk-domain rows
/// (`message_chunks`/`chunk_holes`/`chunk_staging`) and `vec0` table --
/// none of that cascades from deleting the generation row itself
/// (`generation_id` does not cascade from `embedding_generations`), so this
/// function is the one place that tears down all five pieces together
/// (extended T11 from the retired v4 message-granularity tables to the
/// chunk domain). Never touches the currently-active generation, regardless
/// of age. Each
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
            tx.execute("DELETE FROM chunk_holes WHERE generation_id = ?1", &params![generation_id])?;
            tx.execute("DELETE FROM chunk_staging WHERE generation_id = ?1", &params![generation_id])?;
            tx.execute("DELETE FROM message_chunks WHERE generation_id = ?1", &params![generation_id])?;
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
// activation audit. This is the sole vector catch-up engine since T11
// retired the v4 message-granularity engine that used to coexist here.
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

/// Task book #98 Step 3: post-drain hard invariant, called exactly once,
/// immediately after the drain loop in [`run_db_vector_catchup_backfill`]
/// exits and strictly before reverse reconciliation/activation runs. The
/// drain loop must never be followed by either of those while
/// `chunk_holes` rows remain for this generation -- T12's real stall
/// proved a silent, non-erroring drain-loop exit with holes still
/// outstanding is possible (475 holes left forever, zero error, zero
/// event, root cause undetermined); this turns any future recurrence
/// (however it happens) into an immediate, loud failure instead of
/// quietly falling through as if the drain had genuinely finished.
/// Returns the (necessarily zero) remaining count on success so the
/// caller's `drain_done` event can report it verbatim.
fn assert_drain_completed_or_bail(storage: &FrankenStorage, generation_id: i64) -> Result<i64> {
    let holes_remaining: i64 =
        storage.raw().query_row_map("SELECT COUNT(*) FROM chunk_holes WHERE generation_id = ?1", &params![generation_id], |row| row.get_typed(0))?;
    if holes_remaining != 0 {
        let first_remaining: Option<(i64, u32)> = storage.raw().query_opt_map(
            "SELECT message_id, chunk_idx FROM chunk_holes WHERE generation_id = ?1 ORDER BY message_id, chunk_idx LIMIT 1",
            &params![generation_id],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )?;
        let (mid, idx) = first_remaining.unwrap_or((-1, 0));
        bail!("drain loop exited with {holes_remaining} holes remaining (first key {mid},{idx})");
    }
    Ok(holes_remaining)
}

/// Read one message's `(conversation_id, role, content)` fresh. The sole
/// per-message read the T8 drain loop performs -- callers must cache the
/// result across every `HoleKey` sharing the same `message_id` within a
/// run (the "跨页保留 current 消息" contract; [`run_db_vector_catchup_
/// backfill`]'s loop is what actually enforces "exactly once", this
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
/// rows, see [`schema::find_active_generation_matching_identity`]'s doc
/// comment) *and* the generation fingerprint (plan v5.1 参数冻结 "代际身份"
/// row) -- a same-`(embedder_id, dim, canonicalize_version,
/// chunking_policy_version)` row whose *fingerprint* has drifted (the
/// served model's weights changed under an unchanged id/dim, T7's whole
/// reason for existing) is NOT a reuse match; the search falls through to
/// the next priority tier exactly as if the row didn't exist at all.
/// Same three-tier priority as v4: identity+fingerprint-matching active ->
/// identity+fingerprint-matching pending -> create new.
/// T10.5 (exec80, 2026-09-05): a brand-new generation's `chunk_holes` are
/// now seeded from `all_expected` in the SAME transaction as the
/// `INSERT INTO embedding_generations` -- fixes a real gap the plan's T8
/// design left open: T6's ingest-time hole registration only ever fires
/// against an *already-existing* active-or-pending generation
/// (`register_chunk_holes_for_message_in_tx`'s own doc comment), so a
/// brand-new database that ingests all its content BEFORE the first
/// `index --semantic`/`models backfill` call creates generation 1 gets
/// zero holes registered anywhere, ever -- the T8 drain loop below then
/// finds nothing to do and the activation audit fails outright
/// ("generation N has zero chunk rows") on a corpus that in fact has
/// plenty of eligible content. `exec77`'s `synth-200-v5` avoided this by
/// building its generation before inserting messages (T6's hook then
/// covers it); a real green-field deployment can't rely on that ordering.
/// Same-transaction atomicity means a crash/error mid-seed leaves NO
/// generation row at all (verified by `catchup_seed_crash_leaves_no_
/// generation_row` below), not a generation with a partially-seeded hole
/// set that would silently under-report `chunk_holes`.
///
/// Two accepted, documented gaps (control-plane 2026-09-05 ruling, not
/// fixed here):
/// ① `all_expected` is fully materialized in memory by the caller before
///    this function runs (T8's existing pattern -- this change only moves
///    an already-existing full-materialization earlier, it does not
///    introduce a new one). At real corpus scale (~2M chunks x ~100B ~=
///    200MB) this is a real, measurable term against T12's memory door
///    (`VmHWM <= startup_rss + 2*max_message_bytes + 256MiB`); if that
///    door goes red because of this term specifically, the fix is to seed
///    holes via a streamed/paged `for_each_expected_chunk` callback
///    instead of collecting the whole `Vec` first -- not attempted here.
/// ② `all_expected` is computed by the caller *before* this function's own
///    transaction opens (necessarily -- the seed data must exist before
///    the seeding statement can run). A message ingested in the window
///    between that scan and this transaction committing is invisible to
///    BOTH the T6 ingest hook (no generation exists yet to register
///    against) and this seed (already past its own scan) -- a real but
///    narrow race that can leak exactly one missed hole per such message.
///    Accepted as out of scope: this path only runs once per fresh
///    database (first-ever generation creation), and T12's rehearsal is
///    offline (no concurrent ingest). Closing it for good would mean
///    sharing a write lock between "pull new content" and "create first
///    generation", not attempted here.
fn find_reusable_or_create_generation(
    conn: &Conn,
    identity: &InfinityServedIdentity,
    canonicalize_version: u32,
    chunking_policy_version: u32,
    fingerprint: &[u8],
    now_ms: i64,
    all_expected: &[ExpectedChunk],
) -> Result<(i64, bool, u64)> {
    let dim = i64::try_from(identity.dimension)
        .map_err(|_| anyhow!("infinity dimension {} does not fit in i64", identity.dimension))?;

    if let Some((existing, stored_fingerprint)) = schema::find_active_generation_matching_identity(
        conn,
        &identity.model_id,
        dim,
        canonicalize_version,
        chunking_policy_version,
    )
    .context("looking up an identity-matching active v5 embedding_generations row")?
        && fingerprint_matches(&stored_fingerprint, fingerprint, identity.dimension)
    {
        return Ok((existing, true, 0));
    }

    if let Some((existing, stored_fingerprint)) = schema::find_reusable_pending_generation(
        conn,
        &identity.model_id,
        dim,
        canonicalize_version,
        chunking_policy_version,
    )
    .context("looking up a reusable pending v5 embedding_generations row")?
        && fingerprint_matches(&stored_fingerprint, fingerprint, identity.dimension)
    {
        return Ok((existing, true, 0));
    }

    let (generation_id, holes_seeded) = conn
        .with_tx(TxMode::Immediate, |tx| {
            let generation_id = schema::create_embedding_generation(
                tx,
                &identity.model_id,
                dim,
                canonicalize_version,
                chunking_policy_version,
                fingerprint,
                now_ms,
            )?;
            let holes: Vec<(i64, u32)> = all_expected.iter().map(|c| (c.message_id, c.chunk_idx)).collect();
            let outcome = schema::seed_chunk_holes(tx, generation_id, &holes, now_ms, "generation_seed")?;
            Ok((generation_id, outcome.rows_inserted))
        })
        .context("creating a new v5 embedding_generations row and seeding its chunk_holes")?;
    Ok((generation_id, false, holes_seeded))
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

/// Fresh (not cached) `content_hash` lookup for `chunk_id`, used only by
/// the R1-B8 exact-content-twin tolerance in checks ③/⑩ (task book #98):
/// `vec0`'s own rows carry no hash, so telling "this KNN tie is a genuine
/// content twin" from "this is a real drift" requires a point read against
/// `message_chunks` for whichever chunk_id vec0's tie-break actually
/// returned. `Ok(None)` if the row is gone (concurrent write / already
/// pruned) -- callers must not tolerate a tie against a chunk_id that no
/// longer resolves to anything.
fn chunk_content_hash(conn: &Conn, chunk_id: i64) -> Result<Option<String>, StorageError> {
    conn.query_opt_map("SELECT content_hash FROM message_chunks WHERE chunk_id = ?1", &params![chunk_id], |row| row.get_typed(0))
}

/// Task book #98 Step 3: single emission point for every drain
/// observability event (`catchup_page` / `catchup_page_slow` /
/// `drain_done`) -- restricted to this catch-up drain path only, never
/// `search`/`status`/`doctor` (control plane 2026-09-05 ruling). Prints
/// unconditionally (not gated on --json/robot-mode: this module has no
/// access to that CLI flag without threading a new parameter through
/// call sites in other files, out of this task book's single-file scope,
/// and the CLI's own stderr tracing layer is pinned to `error` in
/// robot/json mode regardless -- a `tracing::debug!` here would be
/// silently dropped exactly when it matters most).
///
/// The `#[cfg(test)]` build additionally mirrors every emitted line into
/// a thread-local buffer so tests can assert on the exact events a real
/// `run_db_vector_catchup_backfill` call actually emitted (real behavior,
/// not a reimplementation) instead of scraping process-wide stderr.
#[cfg(not(test))]
fn emit_drain_event(event: &serde_json::Value) {
    eprintln!("{event}");
}

#[cfg(test)]
thread_local! {
    static DRAIN_EVENTS_FOR_TEST: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn emit_drain_event(event: &serde_json::Value) {
    let line = event.to_string();
    eprintln!("{line}");
    DRAIN_EVENTS_FOR_TEST.with(|events| events.borrow_mut().push(line));
}

#[cfg(test)]
fn drain_events_for_test() -> Vec<String> {
    DRAIN_EVENTS_FOR_TEST.with(|events| events.borrow().clone())
}

#[cfg(test)]
fn clear_drain_events_for_test() {
    DRAIN_EVENTS_FOR_TEST.with(|events| events.borrow_mut().clear());
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

/// Verdict + evidence from [`run_activation_audit`]. `passed` is the
/// single verdict every other field explains. Checks ①②③⑤⑥ carry over
/// the original W3-4 activation-audit design, scoped to `message_chunks`/
/// chunk identity; ④⑦⑧⑨⑩⑪ are T8's new/rebuilt checks for the chunk
/// domain.
#[derive(Debug, Clone)]
pub struct ActivationAuditReport {
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
    /// R1-B8 (task book #98): `true` iff ③'s top-1 hit was not the anchor
    /// chunk's own row but was tolerated as an exact-content twin
    /// (`distance <= 1e-6` AND the two chunks' stored `content_hash` are
    /// equal) rather than flagged as a self-hit failure.
    pub positive_check_tied_twin: bool,
    /// The sibling chunk_id ③'s self-hit tied with, set iff
    /// `positive_check_tied_twin` is `true`.
    pub positive_check_twin_chunk_id: Option<i64>,
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
    /// Same R1-B8 tolerance as ③'s `positive_check_tied_twin`, applied
    /// per-sample: count of sampled chunks whose vec0 top-1 hit was an
    /// exact-content twin (not itself) rather than a real ownership drift.
    pub ownership_tied_twins: u64,
    pub ownership_seed: u64,
    pub ownership_skipped: bool,
    /// ⑪ generation fingerprint re-verification.
    pub fingerprint_ok: bool,
    pub failure_reasons: Vec<String>,
}

/// Default finite/norm resample size for [`run_activation_audit`],
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
pub fn run_activation_audit(
    storage: &FrankenStorage,
    generation_id: i64,
    finite_norm_sample_size: usize,
    positive_check_message_id: Option<i64>,
    embedder: Option<&dyn Fn(&[&str]) -> std::result::Result<Vec<Vec<f32>>, String>>,
    ownership_sample: usize,
    ownership_seed: u64,
) -> Result<ActivationAuditReport> {
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
    let anchor: Result<(i64, i64, Vec<u8>, String)> = (|| {
        Ok(match positive_check_message_id {
            Some(mid) => conn.query_row_map(
                "SELECT message_id, chunk_id, embedding, content_hash FROM message_chunks \
                 WHERE generation_id = ?1 AND message_id = ?2 ORDER BY chunk_idx LIMIT 1",
                &params![generation_id, mid],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?)),
            )
            .with_context(|| format!("positive-check message_id={mid} has no chunk row in generation {generation_id}"))?,
            None => conn
                .query_row_map(
                    "SELECT message_id, chunk_id, embedding, content_hash FROM message_chunks WHERE generation_id = ?1 ORDER BY chunk_id LIMIT 1",
                    &params![generation_id],
                    |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?)),
                )
                .with_context(|| format!("generation {generation_id} has zero chunk rows; nothing to positive-check"))?,
        })
    })();
    let mut positive_check_errored = false;
    let mut positive_check_tied_twin = false;
    let mut positive_check_twin_chunk_id: Option<i64> = None;
    let (anchor_message_id, anchor_chunk_id, top_hit_chunk_id, distance) = match anchor {
        Ok((message_id, chunk_id, blob, anchor_hash)) => match schema::le_blob_to_f32_vector(&blob)
            .map_err(anyhow::Error::from)
            .and_then(|v| vector_domain::vec0_knn(conn, generation_id, &v, 1).map_err(anyhow::Error::from))
        {
            Ok(hits) => {
                let (top_hit, distance) = hits.first().copied().unwrap_or((-1, f64::INFINITY));
                if top_hit != chunk_id && distance <= 1e-6 {
                    // R1-B8 (task book #98): vec0's own KNN tie-break among
                    // byte-identical vectors is not guaranteed to prefer a
                    // chunk's own row -- before flagging this as a self-hit
                    // failure, check whether the tie is a genuine
                    // exact-content twin (same `content_hash`, read fresh
                    // from `message_chunks` -- vec0 itself carries no hash).
                    if let Ok(Some(top_hash)) = chunk_content_hash(conn, top_hit) {
                        if top_hash == anchor_hash {
                            positive_check_tied_twin = true;
                            positive_check_twin_chunk_id = Some(top_hit);
                        }
                    }
                }
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
    if !positive_check_errored && !positive_check_tied_twin && (top_hit_chunk_id != anchor_chunk_id || !(distance <= 1e-6)) {
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
    let mut ownership_tied_twins = 0u64;
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
                let row: Option<(i64, i64, i64, Vec<u8>, String)> = conn.query_opt_map(
                    "SELECT message_id, byte_start, byte_end, embedding, content_hash FROM message_chunks WHERE generation_id = ?1 AND chunk_id = ?2",
                    &params![generation_id, *chunk_id],
                    |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?, row.get_typed(4)?)),
                )?;
                let Some((message_id, byte_start, byte_end, stored_blob, stored_hash)) = row else {
                    ownership_failed += 1;
                    failures.push(format!("⑩ chunk_id={chunk_id} disappeared mid-audit (concurrent write)"));
                    continue;
                };
                // `Ok(true)` = tolerated as an exact-content twin (R1-B8,
                // task book #98); `Ok(false)` = ordinary clean pass.
                let ownership_result: Result<bool> = (|| {
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
                    if top_hit != *chunk_id {
                        if distance <= 1e-6 && chunk_content_hash(conn, top_hit)?.as_deref() == Some(stored_hash.as_str()) {
                            return Ok(true);
                        }
                        bail!("vec0 row for chunk_id={chunk_id} does not match message_chunks' own BLOB (vec0 top hit={top_hit}, distance={distance})");
                    } else if !(distance <= 1e-6) {
                        bail!("vec0 row for chunk_id={chunk_id} does not match message_chunks' own BLOB (vec0 top hit={top_hit}, distance={distance})");
                    }
                    Ok(false)
                })();
                match ownership_result {
                    Ok(true) => ownership_tied_twins += 1,
                    Ok(false) => {}
                    Err(e) => {
                        ownership_failed += 1;
                        failures.push(format!("⑩ ownership check failed for chunk_id={chunk_id}: {e}"));
                    }
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
    Ok(ActivationAuditReport {
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
        positive_check_tied_twin,
        positive_check_twin_chunk_id,
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
        ownership_tied_twins,
        ownership_seed,
        ownership_skipped,
        fingerprint_ok,
        failure_reasons: failures,
    })
}

/// The fixed activation-time policy plan v5.1 mandates for every real
/// caller ("激活路径（index --semantic / models backfill）必须传
/// Some(embedder)、样本 200、seed 落日志"): run [`run_activation_audit`]
/// with a real embedder (never `None`), `OWNERSHIP_SAMPLE_SIZE_DEFAULT`
/// (200), and log `ownership_seed` so a later investigation can find
/// exactly which chunks a given run's ownership check sampled. Standalone
/// (not folded into [`run_db_vector_catchup_backfill`]) so both the
/// backfill's own activation step and a future standalone re-audit entry
/// point share one policy definition.
pub fn activate_generation(
    storage: &FrankenStorage,
    generation_id: i64,
    embedder: &dyn Fn(&[&str]) -> std::result::Result<Vec<Vec<f32>>, String>,
    ownership_seed: u64,
) -> Result<ActivationAuditReport> {
    tracing::info!(
        generation_id,
        ownership_seed,
        ownership_sample = OWNERSHIP_SAMPLE_SIZE_DEFAULT,
        "db_vector_catchup (T8): running v5 activation audit"
    );
    run_activation_audit(
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
/// deletes the `verify_no_activation_toctou_drift_in_tx` call *here*
/// (rather than inside that function's own body) is caught by those tests
/// too, closing the exact "verify function exists but the real switch
/// closure never calls it" gap T8's own hand-off left open for the
/// pre-T8.5 state of this call site.
fn switch_guard_in_tx(tx: &Tx, generation_id: i64, pre_audit_chunk_count: i64) -> Result<(), StorageError> {
    schema::verify_no_activation_toctou_drift_in_tx(tx, generation_id, pre_audit_chunk_count)?;
    tx.execute("UPDATE embedding_generations SET audit_status = 'passed' WHERE id = ?1", &params![generation_id])?;
    Ok(())
}

/// Drive one full v5 chunk-domain catch-up run (T8, plan v5.1, task book
/// #92): find-or-create the generation by policy+fingerprint identity
/// ([`find_reusable_or_create_generation`]) -> claim/purge stale
/// `chunk_staging` -> drain `chunk_holes` in key-paged batches (embed via
/// `embedder`, small per-batch staging transaction, one message load per
/// distinct `message_id` -- [`load_message_once`]/[`classify_chunk_hole`])
/// -> move staged rows into `message_chunks` + `vec0` at each batch's end
/// -> reverse-reconcile every touched message's stored chunks against its
/// current expected set -> activate via [`activate_generation`] iff no
/// holes remain.
///
/// `identity`/`fingerprint` are caller-supplied (not probed internally)
/// so this function -- and everything it calls -- is fully exercisable
/// against a deterministic mock `embedder` in tests, with zero live
/// Infinity dependency; the real CLI call sites probe them once via
/// [`crate::search::infinity::probe_identity_and_fingerprint`] and pass
/// the results straight through.
///
/// Task book #98 Step 2: `#[cfg(test)]`-only wall-clock hook for the
/// reverse-reconciliation pass below -- compiled out entirely (zero
/// runtime cost, no stderr, no production report field) outside `cargo
/// test`, same idiom as this module's own `#[cfg(test)] mod
/// chunk_catchup_v5_tests`. Exists so a timed guard test can assert on
/// that pass's own cost in isolation, without the assertion being
/// swamped by unrelated per-batch drain-loop transaction overhead (a
/// pre-existing, unrelated cost this task book did not touch).
#[cfg(test)]
static RECONCILIATION_LAST_DURATION_NANOS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
fn reconciliation_last_duration_for_test() -> std::time::Duration {
    std::time::Duration::from_nanos(RECONCILIATION_LAST_DURATION_NANOS.load(std::sync::atomic::Ordering::Relaxed))
}

#[allow(clippy::too_many_arguments)]
pub fn run_db_vector_catchup_backfill(
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

    // T10.5: moved up from immediately after generation resolution (was
    // "claim/purge stale staging up front" below) so a brand-new
    // generation can be seeded with holes for the *entire* corpus in the
    // same transaction it's created in -- see `find_reusable_or_create_
    // generation`'s doc comment for why (and for the two accepted,
    // documented gaps this reordering carries). Still computed exactly
    // once and reused for both purposes (staging reuse/purge below, and
    // the reverse-reconciliation pass at the end of this function).
    let mut all_expected: Vec<ExpectedChunk> = Vec::new();
    for_each_expected_chunk(storage, 200, |c| {
        all_expected.push(c);
        Ok(())
    })?;
    // Task book #98 Step 2: index `all_expected` by `message_id` exactly
    // once here, up front, so the reverse-reconciliation pass below (which
    // used to do a full `all_expected.iter().filter(...)` linear scan per
    // touched message -- O(touched_message_ids.len() * all_expected.len()),
    // multiple minutes/hours at T12's real scale of ~1.35M touched
    // messages against ~2M expected chunks) is O(touched) instead: one
    // O(1)-amortized `HashMap` lookup per touched message. Behavior is
    // unchanged -- same expected set per message_id, same prune/keep
    // decisions -- only the algorithmic cost of assembling it moves from
    // per-lookup-linear-scan to a single up-front `O(all_expected.len())`
    // index build (also reused by nothing else; `find_reusable_or_create_
    // generation`'s own use of `all_expected` below stays a plain slice).
    let mut expected_by_message: HashMap<i64, Vec<ExpectedChunk>> = HashMap::new();
    for c in &all_expected {
        expected_by_message.entry(c.message_id).or_default().push(c.clone());
    }

    let (generation_id, reused_existing_generation, holes_seeded) = find_reusable_or_create_generation(
        storage.raw(),
        identity,
        canonicalize_version,
        chunking_policy_version,
        fingerprint,
        now_ms,
        &all_expected,
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
    let mut page_number: u64 = 0;
    loop {
        let page_started = std::time::Instant::now();
        let keys = fetch_hole_keys(storage, generation_id, after, batch_size)?;
        if keys.is_empty() {
            break;
        }
        page_number += 1;
        after = keys.last().map(|k| (k.message_id, k.chunk_idx));
        let page_first_key = keys.first().map(|k| (k.message_id, k.chunk_idx)).expect("keys checked non-empty above");
        let page_last_key = after.expect("just set from a non-empty keys Vec above");
        let page_keys_count = keys.len();

        let mut batch_rows: Vec<ChunkRow> = Vec::new();
        let mut batch_keys: Vec<(i64, u32)> = Vec::new();
        let mut resolved_off: Vec<(i64, u32)> = Vec::new();
        let mut off_beyond_expected: Vec<(i64, u32)> = Vec::new();
        // Collected here, embedded in one batched call below (control
        // plane 2026-09-04: T12 shards ~2M chunks, one-Infinity-call-per-
        // chunk is not viable at that scale -- a page's worth of pending
        // embeds, up to `batch_size`, goes out as a single request via
        // `embed_messages_with_sink`).
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

        // Task book #98 Step 3 (control plane 2026-09-05 ruling: emit
        // unconditionally, not gated on --json/robot-mode -- this
        // function has no access to that CLI flag without threading a new
        // parameter through call sites in other files, out of this task
        // book's single-file scope; the CLI's own stderr tracing layer is
        // pinned to `error` in robot/json mode regardless, so a
        // `tracing::debug!` here would be silently dropped exactly when
        // it matters most). T12's real-scale stall left zero trace of
        // drain progress -- `semantic.err`'s only progress counter was the
        // unrelated lexical-indexing phase, frozen at "indexing 14/14"
        // for the entire ≥143-minute stall. This line, and `catchup_page_
        // slow`/`drain_done` below, are the only signal a future stuck
        // run has to distinguish "still draining, page N" from "the drain
        // loop itself hung" -- restricted to this drain path only, never
        // emitted from `search`/`status`/`doctor`.
        let page_embedded = batch_rows.len();
        let page_written_off = resolved_off.len() + off_beyond_expected.len();
        chunks_embedded = chunks_embedded.saturating_add(batch_rows.len() as u64);
        holes_written_off_beyond_expected = holes_written_off_beyond_expected.saturating_add(off_beyond_expected.len() as u64);

        let page_elapsed = page_started.elapsed();
        emit_drain_event(&serde_json::json!({
            "event": "catchup_page",
            "page": page_number,
            "first_key": [page_first_key.0, page_first_key.1],
            "last_key": [page_last_key.0, page_last_key.1],
            "keys": page_keys_count,
            "embed": page_embedded,
            "written_off": page_written_off,
            "ms": page_elapsed.as_millis(),
        }));
        if page_elapsed > std::time::Duration::from_secs(60) {
            emit_drain_event(&serde_json::json!({
                "event": "catchup_page_slow",
                "page": page_number,
                "first_key": [page_first_key.0, page_first_key.1],
                "last_key": [page_last_key.0, page_last_key.1],
                "ms": page_elapsed.as_millis(),
            }));
        }
    }

    let holes_remaining_after_drain = assert_drain_completed_or_bail(storage, generation_id)?;
    emit_drain_event(&serde_json::json!({"event": "drain_done", "holes": holes_remaining_after_drain}));

    // Reverse reconciliation: every message this run touched (had at least
    // one hole key for) gets its full stored-chunk set pruned against its
    // current expected set -- catches a message whose chunk count shrank
    // (some of its old chunk rows are no longer expected at all, not just
    // "index beyond expected" for a hole that never existed for them).
    let mut chunks_pruned = 0u64;
    let no_expected_chunks: Vec<ExpectedChunk> = Vec::new();
    #[cfg(test)]
    let __reconciliation_started = std::time::Instant::now();
    for message_id in &touched_message_ids {
        let expected = expected_by_message.get(message_id).unwrap_or(&no_expected_chunks);
        let pruned = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                let pruned_chunk_ids = schema::prune_chunks_not_in_expected_in_tx(tx, generation_id, *message_id, expected)?;
                if !pruned_chunk_ids.is_empty() {
                    vector_domain::delete_vec0_rows_in_tx(tx, generation_id, &pruned_chunk_ids)?;
                }
                Ok(pruned_chunk_ids.len() as u64)
            })
            .context("reverse-reconciling a touched message's stored chunks")?;
        chunks_pruned = chunks_pruned.saturating_add(pruned);
    }
    #[cfg(test)]
    RECONCILIATION_LAST_DURATION_NANOS.store(u64::try_from(__reconciliation_started.elapsed().as_nanos()).unwrap_or(u64::MAX), std::sync::atomic::Ordering::Relaxed);

    let holes_after: i64 = storage.raw().query_row_map(
        "SELECT COUNT(*) FROM chunk_holes WHERE generation_id = ?1",
        &params![generation_id],
        |row| row.get_typed(0),
    )?;
    let mut activated = false;
    if holes_after == 0 {
        let audit_report = activate_generation(storage, generation_id, embedder, ownership_seed)
            .context("running the T8 v5 activation audit before activating a chunk-domain generation")?;
        // Task book #98 Step 1/4: the R1-B8 exact-content-twin tolerance
        // this task book added to checks ③/⑩ has no other observable
        // surface (`ActivationAuditReport` itself is discarded once this
        // function reads `.passed`/`.chunk_count` -- it was never part of
        // `DbVectorCatchupReport`, and the CLI's own stderr tracing layer
        // is pinned to `error` in robot/json mode regardless of level).
        // Routed through the same unconditional `emit_drain_event` channel
        // Step 3 built, real data straight off the just-computed report
        // (not a reimplementation), emitted for both a passing and a
        // failing audit so a refused activation's diagnostics are visible
        // too.
        emit_drain_event(&serde_json::json!({
            "event": "activation_audit",
            "generation_id": generation_id,
            "passed": audit_report.passed,
            "positive_check_tied_twin": audit_report.positive_check_tied_twin,
            "positive_check_twin_chunk_id": audit_report.positive_check_twin_chunk_id,
            "ownership_checked": audit_report.ownership_checked,
            "ownership_failed": audit_report.ownership_failed,
            "ownership_tied_twins": audit_report.ownership_tied_twins,
        }));
        if !audit_report.passed {
            bail!(
                "generation {generation_id} failed T8 activation audit, refusing to activate: {}",
                audit_report.failure_reasons.join("; ")
            );
        }
        schema::switch_active_generation(storage.raw(), generation_id, FrankenStorage::now_millis(), |tx| {
            switch_guard_in_tx(tx, generation_id, audit_report.chunk_count)
        })
        .context("activating v5 chunk-domain generation")?;
        activated = true;
    }

    let vec0_rows = usize::try_from(vector_domain::count_vec0_rows_for_generation(storage.raw(), generation_id).unwrap_or(0)).unwrap_or(0);

    // T11 (task book #95): wire the delayed orphan-generation cleanup into
    // this backfill's own tail -- the only production entry point that
    // drives `run_db_vector_catchup_backfill` is exactly the place this
    // housekeeping belongs, mirroring the retired v4 engine's own tail
    // call (task book #62 Step3's `cleanup_orphaned_generations` otherwise
    // has no production caller). Runs unconditionally, regardless of this
    // call's own activation outcome. `cleanup_orphaned_generations` itself
    // never returns `Err` (both a per-candidate delete failure and a
    // scan-level failure are folded into `.failures`), so there is no
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
        cleanup_deleted_generation_ids,
        cleanup_failures,
        chunks_embedded,
        chunks_pruned,
        holes_written_off_beyond_expected,
        staging_reused,
        staging_purged,
        messages_loaded,
        holes_seeded,
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
        run_db_vector_catchup_backfill(storage, 100, &mock_identity(), CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &mock_fingerprint(), &mock_embed, 42)
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
                schema::create_embedding_generation(tx, &identity.model_id, DIM as i64, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &mock_fingerprint(), TS)
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
                schema::create_embedding_generation(tx, &identity.model_id, DIM as i64, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &wrong_fingerprint, TS)
            })
            .unwrap();
        storage.raw().execute("UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1", &params![stale_generation_id]).unwrap();

        let (generation_id, reused, _holes_seeded) =
            find_reusable_or_create_generation(storage.raw(), &identity, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &mock_fingerprint(), TS + 1, &[]).unwrap();
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
                schema::create_embedding_generation(tx, &identity.model_id, DIM as i64, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &wrong_fingerprint, TS)
            })
            .unwrap();
        // Left is_active=0, audit_status='pending' (the DDL default) --
        // the pending-reuse tier.

        let (generation_id, reused, _holes_seeded) =
            find_reusable_or_create_generation(storage.raw(), &identity, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &mock_fingerprint(), TS + 1, &[]).unwrap();
        assert_ne!(generation_id, stale_generation_id, "a pending row with a drifted fingerprint must never be reused");
        assert!(!reused);
    }

    /// T10.5 regression: a brand-new database (NO generation exists at
    /// all, `genesis()` deliberately not called) that ingests content
    /// before its first `index --semantic`/`models backfill` call used to
    /// end up with zero `chunk_holes` ever registered (T6's ingest hook
    /// only fires against an *already-existing* generation) -- the T8
    /// drain loop then found nothing to do and activation failed outright
    /// on a corpus that in fact had eligible content. Two conversations, 3
    /// messages including one long enough (2400 chars @ 1000/100 chunking)
    /// to produce 3 chunks, for `holes_seeded` to be a real multi-message,
    /// multi-chunk sum rather than a degenerate 1.
    #[test]
    fn catchup_seeds_holes_for_a_brand_new_generation_on_a_fresh_database() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));

        insert_conversation(&storage, "t10_5-fresh-a", &["short message one has plenty of real content to embed and chunk"]);
        let long_content = "x".repeat(1200) + &"y".repeat(1200);
        insert_conversation(&storage, "t10_5-fresh-b", &["short message two also has plenty of real content to embed and chunk", &long_content]);

        assert_eq!(
            storage.raw().query_row_map("SELECT COUNT(*) FROM embedding_generations", &[], |row| row.get_typed::<i64>(0)).unwrap(),
            0,
            "sanity: no generation must exist before this run -- that's the exact scenario under test"
        );

        let mut expected_total = 0usize;
        for_each_expected_chunk(&storage, 200, |_c| {
            expected_total += 1;
            Ok(())
        })
        .unwrap();
        assert!(expected_total >= 4, "fixture must produce at least 4 expected chunks (2 single + 1 that splits into >=2): got {expected_total}");

        let report = backfill(&storage).unwrap();
        assert_eq!(report.holes_seeded, expected_total as u64, "holes_seeded must equal the brand-new generation's ENTIRE expected-chunk set: {report:?}");
        assert!(!report.reused_existing_generation);
        assert!(report.activated, "a fresh generation with all its holes seeded and then drained must cleanly activate: {report:?}");
        assert_eq!(message_chunks_count(&storage, report.generation_id), expected_total as i64);
        assert_eq!(chunk_holes_count(&storage, report.generation_id), 0, "every seeded hole must have been drained by the same run");
    }

    /// T10.5: same-transaction atomicity for the new generation-creation +
    /// hole-seeding pair -- an error partway through seeding (here, a
    /// `chunk_holes.message_id` foreign-key violation against a message
    /// that doesn't exist, injected directly into `find_reusable_or_
    /// create_generation`'s `all_expected` argument rather than through
    /// `for_each_expected_chunk`, which only ever returns real rows) must
    /// roll back the WHOLE transaction, including the `INSERT INTO
    /// embedding_generations` -- never leave a generation row with a
    /// partially-seeded (and therefore silently under-reported)
    /// `chunk_holes` set.
    #[test]
    fn catchup_seed_crash_leaves_no_generation_row() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let identity = mock_identity();

        let real_ids = insert_conversation(&storage, "t10_5-crash", &["a real message with plenty of content to embed and chunk cleanly"]);
        let mut all_expected = expected_chunks(real_ids[0], 0, "user", "a real message with plenty of content to embed and chunk cleanly");
        assert_eq!(all_expected.len(), 1, "sanity: fixture message must produce exactly one real expected chunk");
        // A second "expected chunk" for a message_id that does not exist --
        // `chunk_holes.message_id REFERENCES messages(id)` rejects it,
        // failing the seed statement mid-batch.
        let mut bogus = all_expected[0].clone();
        bogus.message_id = 999_999;
        bogus.chunk_idx = 0;
        all_expected.push(bogus);

        let before: i64 = storage.raw().query_row_map("SELECT COUNT(*) FROM embedding_generations", &[], |row| row.get_typed(0)).unwrap();
        assert_eq!(before, 0);

        let result = find_reusable_or_create_generation(
            storage.raw(),
            &identity,
            CANONICALIZE_PIPELINE_VERSION,
            CHUNKING_POLICY_VERSION,
            &mock_fingerprint(),
            TS + 1,
            &all_expected,
        );
        assert!(result.is_err(), "a seed-time FK violation must surface as Err, not silently succeed partially");

        let after: i64 = storage.raw().query_row_map("SELECT COUNT(*) FROM embedding_generations", &[], |row| row.get_typed(0)).unwrap();
        assert_eq!(after, 0, "same-transaction atomicity: a crash mid-seed must leave NO generation row at all, not a half-seeded one");
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

    /// Two messages with byte-identical content -- a genuine "content
    /// twin" (task book #98, R1-B8's W3 judgement carried to v5): real
    /// production ingestion (`insert_conversation`) + drain (`backfill`)
    /// naturally gives both chunks the same `content_hash` and the same
    /// embedding (`deterministic_vector` is purely content-keyed), and
    /// vec0's own KNN tie-break for either chunk's own vector is not
    /// guaranteed to land on itself -- reproduced deterministically here
    /// exactly as in production (T12 real-scale run): `backfill`'s own
    /// automatic post-drain activation is expected to fail pre-fix, so its
    /// `Result` is deliberately discarded; the per-batch chunk writes it
    /// already committed before attempting activation are not affected by
    /// that failure and are asserted below.
    fn twin_two_message_generation(storage: &FrankenStorage) -> (i64, i64, i64, i64, i64) {
        let generation_id = genesis(storage);
        const TWIN_TEXT: &str = "identical twin content shared by two distinct messages for the audit tolerance test";
        let ids_a = insert_conversation(storage, "t11-5-twin-a", &[TWIN_TEXT]);
        let ids_b = insert_conversation(storage, "t11-5-twin-b", &[TWIN_TEXT]);
        let _ = backfill(storage);
        assert_eq!(message_chunks_count(storage, generation_id), 2, "both twin chunks must be embedded and moved out of staging regardless of whether the automatic post-drain activation itself passed");
        let chunk_id_a: i64 = storage
            .raw()
            .query_row_map("SELECT chunk_id FROM message_chunks WHERE generation_id = ?1 AND message_id = ?2", &params![generation_id, ids_a[0]], |row| row.get_typed(0))
            .unwrap();
        let chunk_id_b: i64 = storage
            .raw()
            .query_row_map("SELECT chunk_id FROM message_chunks WHERE generation_id = ?1 AND message_id = ?2", &params![generation_id, ids_b[0]], |row| row.get_typed(0))
            .unwrap();
        (generation_id, ids_a[0], chunk_id_a, ids_b[0], chunk_id_b)
    }

    /// R1-B8 (task book #98, Step 1): a genuine content twin -- two chunks
    /// under two different messages, byte-identical content, hence
    /// byte-identical `content_hash` and embedding -- must not fail ③'s
    /// self-hit check or ⑩'s per-chunk ownership check merely because
    /// vec0's own KNN tie-break happened to return the sibling chunk_id
    /// instead of the queried chunk's own rowid; the real T12 stall
    /// evidence hit exactly this shape (anchor chunk_id=1, top hit=2,
    /// distance=0, `content_hash` equal).
    #[test]
    fn audit_3_and_10_tolerate_exact_content_twins() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, message_id_a, chunk_id_a, message_id_b, chunk_id_b) = twin_two_message_generation(&storage);
        assert_ne!(chunk_id_a, chunk_id_b);

        // Anchor on the twin whose own KNN query resolves to its sibling
        // (chunk_id_a, per the deterministic tie-break this fixture
        // reproduces) -- the case that must now be tolerated.
        let report = run_activation_audit(&storage, generation_id, 10, Some(message_id_a), Some(&mock_embed), 10, 1).unwrap();
        assert!(report.passed, "an exact-content twin tie must not fail the audit: {report:?}");
        assert!(report.positive_check_tied_twin, "③ must record that the self-hit was tolerated as a tied twin, not a plain pass: {report:?}");
        assert_eq!(report.positive_check_twin_chunk_id, Some(chunk_id_b), "the recorded twin must be the sibling chunk vec0 actually returned: {report:?}");
        assert_eq!(report.positive_check_top_hit_chunk_id, chunk_id_b);
        assert_eq!(report.positive_check_distance, 0.0);
        assert_eq!(report.ownership_checked, 2);
        assert_eq!(report.ownership_failed, 0, "⑩ must not count the tied-twin sample as a failure: {report:?}");
        assert_eq!(report.ownership_tied_twins, 1, "exactly the one sampled chunk whose own KNN query ties onto its twin must be counted: {report:?}");
        assert!(report.failure_reasons.is_empty(), "a clean twin tie must leave zero failure reasons: {report:?}");

        // Anchor on the other twin, whose own query resolves to itself
        // (no tie to tolerate) -- must stay an ordinary, non-twin pass.
        let report_b = run_activation_audit(&storage, generation_id, 10, Some(message_id_b), Some(&mock_embed), 10, 1).unwrap();
        assert!(report_b.passed, "{report_b:?}");
        assert!(!report_b.positive_check_tied_twin, "the anchor whose own query already resolves to itself must not be misreported as a tied twin: {report_b:?}");
        assert_eq!(report_b.positive_check_twin_chunk_id, None);
    }

    /// R1-B8's tolerance must not swallow a genuine anomaly: two chunks
    /// whose *embeddings* happen to collide at distance 0 (forced here by
    /// directly overwriting one chunk's stored embedding+vec0 row with the
    /// other's) but whose real, independently-recomputable `content_hash`
    /// still differ (their underlying message content is NOT the same)
    /// must stay a hard ③/⑩ failure -- an embedding-space collision
    /// between genuinely different content is exactly the kind of drift
    /// the audit exists to catch, and is not the benign "verbatim-repeated
    /// short message" case ③'s twin tolerance is scoped to.
    #[test]
    fn audit_3_and_10_still_flag_real_drift_despite_zero_distance() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, chunk_id_a, chunk_id_b) = clean_two_message_generation(&storage);
        let message_id_a: i64 = storage.raw().query_row_map("SELECT message_id FROM message_chunks WHERE chunk_id = ?1", &params![chunk_id_a], |row| row.get_typed(0)).unwrap();
        let (embedding_a, norm_a): (Vec<u8>, f64) =
            storage.raw().query_row_map("SELECT embedding, norm FROM message_chunks WHERE chunk_id = ?1", &params![chunk_id_a], |row| Ok((row.get_typed(0)?, row.get_typed(1)?))).unwrap();
        // Force chunk_id_b's stored embedding (message_chunks AND its own
        // vec0 row) to be byte-identical to chunk_id_a's, WITHOUT touching
        // either chunk's `content_hash` -- the two chunks' real content
        // (and therefore their genuinely different, self-consistent
        // hashes) is left alone, isolating an embedding-space collision
        // from a real content twin.
        storage.raw().execute("UPDATE message_chunks SET embedding = ?1, norm = ?2 WHERE chunk_id = ?3", &params![embedding_a.clone(), norm_a, chunk_id_b]).unwrap();
        storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                vector_domain::delete_vec0_rows_in_tx(tx, generation_id, &[chunk_id_b])?;
                vector_domain::insert_vec0_rows_in_tx(tx, generation_id, &[(chunk_id_b, embedding_a.as_slice())])?;
                Ok(())
            })
            .unwrap();

        let report = run_activation_audit(&storage, generation_id, 10, Some(message_id_a), Some(&mock_embed), 10, 1).unwrap();
        assert!(!report.passed, "an embedding collision between chunks with genuinely different content_hash must still fail: {report:?}");
        assert!(!report.positive_check_tied_twin, "different content_hash must never be tolerated as a tied twin: {report:?}");
        assert_eq!(report.positive_check_twin_chunk_id, None);
        assert_eq!(report.positive_check_top_hit_chunk_id, chunk_id_b);
        assert_eq!(report.positive_check_distance, 0.0);
        assert!(
            report.failure_reasons.iter().any(|r| r.contains("③ positive content check failed") && r.contains(&format!("top vec0 hit={chunk_id_b} distance=0"))),
            "③ must still report the mismatch verbatim when the tie is not a genuine content twin: {report:?}"
        );
        assert_eq!(report.ownership_tied_twins, 0, "no sampled chunk in this fixture is a genuine content twin: {report:?}");
    }

    #[test]
    fn audit_4_bidirectional_anti_join_by_chunk() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, chunk_id_a, _chunk_id_b) = clean_two_message_generation(&storage);

        let baseline = run_activation_audit(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
        assert_eq!(baseline.eligible_not_embedded_count, 0);
        assert_eq!(baseline.embedded_not_eligible_count, 0);

        // Delete one message_chunks row directly (bypassing the catch-up
        // worker) -- its message is still eligible, so this now leaves an
        // "eligible but not embedded" gap check ④ must catch.
        storage.raw().execute("DELETE FROM message_chunks WHERE chunk_id = ?1", &params![chunk_id_a]).unwrap();

        let after = run_activation_audit(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
        assert!(!after.passed);
        assert_eq!(after.eligible_not_embedded_count, 1, "④ must count exactly the one row removed: {after:?}");
    }

    #[test]
    fn audit_7_detects_vec0_set_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, chunk_id_a, _chunk_id_b) = clean_two_message_generation(&storage);

        storage.raw().with_tx(TxMode::Immediate, |tx| vector_domain::delete_vec0_rows_in_tx(tx, generation_id, &[chunk_id_a])).unwrap();

        let after = run_activation_audit(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
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

        let after = run_activation_audit(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
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

        let after = run_activation_audit(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
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

        let after = run_activation_audit(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
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

        let after = run_activation_audit(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
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

        let after = run_activation_audit(&storage, generation_id, 10, None, None, 10, 1).unwrap();
        assert!(after.ownership_skipped);
        assert!(!after.passed, "embedder=None must always fail the verdict, even if ①-⑨ are otherwise clean: {after:?}");
    }

    #[test]
    fn activation_path_passes_some_embedder_sample_200_and_logs_seed() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, _a, _b) = clean_two_message_generation(&storage);

        let seed = 987_654_321_u64;
        let report = activate_generation(&storage, generation_id, &mock_embed, seed).unwrap();
        assert!(report.passed, "a clean generation must pass the fixed activation policy: {report:?}");
        assert!(!report.ownership_skipped, "activate_generation must always pass Some(embedder), never None");
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
    /// audit (`activate_generation`) necessarily runs *outside* the
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
        let audit_report = activate_generation(&storage, generation_id, &mock_embed, 42).unwrap();
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
            switch_guard_in_tx(tx, generation_id, audit_report.chunk_count)
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

        let audit_report = activate_generation(&storage, generation_id, &mock_embed, 42).unwrap();
        assert!(audit_report.passed, "sanity: a clean generation must pass before we inject drift: {audit_report:?}");
        assert_eq!(audit_report.chunk_count, 2, "sanity: the fixture has exactly 2 chunks");

        // Simulate a concurrent shrink -- a chunk row disappearing between
        // audit-time and switch-time.
        storage.raw().execute("DELETE FROM message_chunks WHERE chunk_id = ?1", &params![chunk_id_a]).unwrap();
        assert_eq!(chunk_holes_count(&storage, generation_id), 0, "sanity: the direct delete must not have registered a hole");
        assert_eq!(message_chunks_count(&storage, generation_id), 1);

        let result = schema::switch_active_generation(storage.raw(), generation_id, TS + 999_999, |tx| {
            switch_guard_in_tx(tx, generation_id, audit_report.chunk_count)
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
                schema::create_embedding_generation(tx, &identity.model_id, DIM as i64, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &wrong_fingerprint, TS)
            })
            .unwrap();
        vector_domain::create_vec0_table_for_generation(storage.raw(), generation_id, DIM as i64).unwrap();

        let after = run_activation_audit(&storage, generation_id, 10, None, Some(&mock_embed), 10, 1).unwrap();
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

    /// Task book #98 Step 2 timed guard: reverse reconciliation used to be
    /// `all_expected.iter().filter(|c| c.message_id == *message_id)` per
    /// touched message -- O(touched * all_expected.len()). This fixture is
    /// the worst case for that shape: `N` messages, 3 hard-cut chunks each
    /// (`3*N` expected chunks total), and because it's a brand-new
    /// database every single one of those messages' holes gets drained in
    /// the same run, so `touched_message_ids` ends up covering all `N`.
    ///
    /// **Deviation from the task book's literal "10,000" fixture size**
    /// (plan v5.1 Global Constraints: test fixture construction is
    /// "推荐默认", changeable with a documented reason): measured directly
    /// (mutation test, reverting to the old linear-scan code, discarded
    /// after measuring) -- at 10,000 messages (30,000 expected chunks) the
    /// old O(touched*expected) code finishes reconciliation in ~1.46s in
    /// this debug build, i.e. it does NOT trip a `< 2s` guard at that size
    /// here (a release build or a machine with a faster allocator could
    /// go either way, but this repo's own disk/build law mandates debug
    /// builds for iteration -- `CARGO_PROFILE_DEV_DEBUG=0`, no release
    /// profile in play -- so the guard must discriminate under the exact
    /// profile it will actually run under). Doubling to 20,000 messages
    /// (60,000 expected chunks) gives real separation: old code measured
    /// ~5.31s (fails), fixed code measured ~0.78s (comfortably passes) --
    /// consistent with O(N^2) vs O(N) scaling from the 10k measurements
    /// (old: 1.46s -> ~5.3s at 4x the work, roughly the predicted ~4x;
    /// fixed: ~0.39s -> ~0.78s, roughly the predicted 2x).
    ///
    /// Only [`reconciliation_last_duration_for_test`]'s own window is
    /// asserted on, not the whole `backfill()` call -- the drain loop's
    /// ~200 per-batch SQLite transactions and the final activation audit's
    /// own full-corpus scans are real, pre-existing costs this task book's
    /// Step 2 was never scoped to touch (confirmed unaffected: this same
    /// fixture's full `backfill()` wall time is dominated by those, while
    /// the reconciliation window alone is the ~0.78s above), and bundling
    /// them in would make this guard fail on a cost it has no way to fix.
    /// `#[ignore]`d (heavy fixture setup) -- run explicitly with
    /// `--ignored` to get real numbers; the assertion itself still runs
    /// and is real, not a stub, whenever it does run.
    #[test]
    #[ignore]
    fn catchup_reverse_reconciliation_is_linear_in_touched_messages_20k() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let generation_id = genesis(&storage);

        const N: usize = 20_000;
        for i in 0..N {
            // Each message is 2500 unique bytes -> 3 hard-cut chunks
            // ([0,1000) [900,1900) [1800,2500)), same math as the other
            // multi-chunk fixtures in this module; the `{i:010}` prefix
            // guarantees every message's content (and therefore
            // content_hash) is distinct across all N messages, so this
            // fixture never exercises Step 1's twin tolerance -- purely a
            // reverse-reconciliation cost measurement.
            let content = format!("{i:010}{}", long_unique_filler(2490));
            insert_conversation(&storage, &format!("t11-5-perf-{i}"), &[content.as_str()]);
        }
        assert_eq!(chunk_holes_count(&storage, generation_id), (N * 3) as i64, "sanity: every message's 3 chunks must have registered a hole");

        let report = backfill(&storage).unwrap();
        let reconciliation_elapsed = reconciliation_last_duration_for_test();

        assert_eq!(report.chunks_embedded, (N * 3) as u64);
        assert!(report.activated, "{report:?}");
        assert_eq!(chunk_holes_count(&storage, generation_id), 0);
        eprintln!(
            "catchup_reverse_reconciliation_is_linear_in_touched_messages_20k: reverse reconciliation ({N} touched messages x {} expected chunks) took {reconciliation_elapsed:?}",
            N * 3
        );
        assert!(
            reconciliation_elapsed < std::time::Duration::from_secs(2),
            "O(touched) reverse reconciliation must comfortably clear 20,000 touched messages x 60,000 expected chunks in well under 2s; took {reconciliation_elapsed:?}"
        );
    }

    /// Task book #98 Step 3: every `catchup_page` event the drain loop
    /// emits must be valid JSON, and the number of pages emitted must
    /// equal `ceil(holes / batch_size)` -- 250 single-chunk holes,
    /// `backfill()`'s fixed `batch_size=100` -> pages of 100, 100, 50
    /// (page 3 partial). Reads the real events `run_db_vector_catchup_
    /// backfill` actually emitted via [`drain_events_for_test`] (the
    /// `#[cfg(test)]` mirror of [`emit_drain_event`]'s real call sites),
    /// not a reimplementation.
    #[test]
    fn catchup_page_events_are_parseable_and_page_count_matches_ceil_holes_over_batch() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let generation_id = genesis(&storage);

        const N: usize = 250;
        for i in 0..N {
            insert_conversation(&storage, &format!("t11-5-page-{i}"), &[format!("distinct single-chunk message number {i} with plenty of real content to embed and chunk").as_str()]);
        }
        assert_eq!(chunk_holes_count(&storage, generation_id), N as i64, "sanity: 250 single-chunk messages -> 250 holes");

        clear_drain_events_for_test();
        let report = backfill(&storage).unwrap();
        let events = drain_events_for_test();

        assert!(report.activated, "{report:?}");
        assert_eq!(chunk_holes_count(&storage, generation_id), 0);
        assert!(!events.is_empty(), "the drain loop must have emitted at least the catchup_page events for a 250-hole run");

        let parsed: Vec<serde_json::Value> = events.iter().map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("every emitted drain event line must be valid JSON, got {line:?}: {e}"))).collect();
        let page_events: Vec<&serde_json::Value> = parsed.iter().filter(|v| v["event"] == "catchup_page").collect();
        let expected_pages = N.div_ceil(100);
        assert_eq!(expected_pages, 3, "sanity on the fixture's own arithmetic: ceil(250/100)");
        assert_eq!(page_events.len(), expected_pages, "page count must equal ceil(holes/batch_size): {parsed:?}");

        let mut total_keys = 0u64;
        for (i, ev) in page_events.iter().enumerate() {
            assert_eq!(ev["page"].as_u64().unwrap(), (i + 1) as u64, "page numbers must be 1-indexed and sequential: {parsed:?}");
            assert!(ev["first_key"].is_array() && ev["first_key"].as_array().unwrap().len() == 2, "{parsed:?}");
            assert!(ev["last_key"].is_array() && ev["last_key"].as_array().unwrap().len() == 2, "{parsed:?}");
            total_keys += ev["keys"].as_u64().unwrap();
        }
        assert_eq!(total_keys, N as u64, "keys across all pages must sum to the total hole count: {parsed:?}");
        assert_eq!(page_events[2]["keys"].as_u64().unwrap(), 50, "the last page must be the partial remainder (250 - 2*100): {parsed:?}");

        let drain_done: Vec<&serde_json::Value> = parsed.iter().filter(|v| v["event"] == "drain_done").collect();
        assert_eq!(drain_done.len(), 1, "exactly one drain_done event must be emitted per run: {parsed:?}");
        assert_eq!(drain_done[0]["holes"].as_i64().unwrap(), 0);
    }

    /// Task book #98 Step 3: a rerun against an already fully-drained,
    /// already-active generation (the realistic "T12 rerun after the fix"
    /// shape -- nothing left to embed) must still emit exactly one
    /// `drain_done` event with `holes=0`, even though zero `catchup_page`
    /// events fire (zero pages). This is the ONLY signal available to
    /// distinguish "the drain loop ran and correctly found nothing to do"
    /// from "the drain loop silently never ran at all".
    #[test]
    fn drain_done_event_fires_with_zero_pages_on_an_already_drained_rerun() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let generation_id = genesis(&storage);
        insert_conversation(&storage, "t11-5-drain-done", &["a real message with plenty of content to embed and chunk"]);
        let first = backfill(&storage).unwrap();
        assert!(first.activated, "{first:?}");
        assert_eq!(chunk_holes_count(&storage, generation_id), 0);

        clear_drain_events_for_test();
        let second = backfill(&storage).unwrap();
        let events = drain_events_for_test();
        let parsed: Vec<serde_json::Value> = events.iter().map(|line| serde_json::from_str(line).unwrap()).collect();

        assert_eq!(parsed.iter().filter(|v| v["event"] == "catchup_page").count(), 0, "an already-drained rerun must produce zero pages: {parsed:?}");
        let drain_done: Vec<&serde_json::Value> = parsed.iter().filter(|v| v["event"] == "drain_done").collect();
        assert_eq!(drain_done.len(), 1, "drain_done must still fire on a zero-page rerun: {parsed:?}");
        assert_eq!(drain_done[0]["holes"].as_i64().unwrap(), 0);
        assert!(second.activated, "a rerun of an already-clean generation must still (idempotently) activate: {second:?}");
    }

    /// Task book #98 Step 3 mutation-testable unit: [`assert_drain_completed_or_bail`]
    /// is called exactly once per `run_db_vector_catchup_backfill` run, right after
    /// the drain loop exits and strictly before reconciliation/activation --
    /// tested directly here (not through a full backfill run) because
    /// reproducing T12's actual root cause for "the drain loop exits while a
    /// real hole remains" is explicitly out of this task book's scope (mission
    /// text: "本棒不猜根因"). A hand-planted ("手工留一条洞") extra `chunk_holes`
    /// row for an otherwise fully-activated generation exercises the exact
    /// invariant this function guards, independent of how such a row could
    /// arise in production.
    #[test]
    fn assert_drain_completed_or_bail_detects_a_manually_left_hole() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let (generation_id, _a, _b) = clean_two_message_generation(&storage);
        assert!(assert_drain_completed_or_bail(&storage, generation_id).is_ok(), "a genuinely fully-drained generation must not bail");

        let message_id: i64 = storage.raw().query_row_map("SELECT id FROM messages ORDER BY id LIMIT 1", &[], |row| row.get_typed(0)).unwrap();
        storage
            .raw()
            .execute(
                "INSERT INTO chunk_holes (generation_id, message_id, chunk_idx, detected_at, reason) VALUES (?1, ?2, 99, ?3, 'manually-left-for-test')",
                &params![generation_id, message_id, TS],
            )
            .unwrap();

        let result = assert_drain_completed_or_bail(&storage, generation_id);
        assert!(result.is_err(), "a manually left-over chunk_holes row must be caught, not silently ignored");
        let message = format!("{:#}", result.unwrap_err());
        assert!(message.contains("drain loop exited with 1 holes remaining"), "error text: {message}");
        assert!(message.contains(&format!("first key {message_id},99")), "error text must name the first remaining key: {message}");
    }

    /// Task book #98 Step 4 requirement ④: [`fetch_hole_keys`]'s keyset
    /// pagination query must resolve via `chunk_holes`' own composite
    /// `PRIMARY KEY(generation_id, message_id, chunk_idx)` (SQLite creates
    /// an implicit autoindex for a multi-column PK on a rowid table --
    /// verified empirically to read `SEARCH chunk_holes USING COVERING
    /// INDEX sqlite_autoindex_chunk_holes_1 (...)`, not the literal
    /// substring "USING INDEX" the task book's own prose guessed), never a
    /// full table `SCAN` -- correctness of `catchup_loads_each_message_
    /// once_per_run` at real (millions-of-rows) scale depends on this
    /// being an indexed seek, not a scan re-read on every page.
    #[test]
    fn fetch_hole_keys_query_plan_uses_the_composite_primary_key_index() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = open_storage(&dir.path().join("db.sqlite"));
        let plan_details: Vec<String> = storage
            .raw()
            .query_all_map(
                "EXPLAIN QUERY PLAN SELECT message_id, chunk_idx FROM chunk_holes \
                 WHERE generation_id = ?1 AND (message_id > ?2 OR (message_id = ?2 AND chunk_idx > ?3)) \
                 ORDER BY message_id, chunk_idx LIMIT ?4",
                &params![1i64, 0i64, 0i64, 100i64],
                |row| row.get_typed(3),
            )
            .unwrap();
        assert!(plan_details.iter().any(|d| d.contains("chunk_holes")), "sanity: plan must reference chunk_holes at all: {plan_details:?}");
        assert!(
            plan_details.iter().any(|d| d.contains("USING") && d.contains("INDEX")),
            "fetch_hole_keys' keyset pagination must resolve via an index (the composite PRIMARY KEY autoindex), not a full scan: {plan_details:?}"
        );
        assert!(!plan_details.iter().any(|d| d.contains("SCAN chunk_holes")), "must not fall back to a chunk_holes table SCAN: {plan_details:?}");
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
                schema::create_embedding_generation(tx, &identity.model_id, i64::try_from(identity.dimension).unwrap(), CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &fingerprint, TS)
            })
            .unwrap();
        vector_domain::create_vec0_table_for_generation(storage.raw(), generation_id, i64::try_from(identity.dimension).unwrap()).unwrap();

        insert_conversation(&storage, "t8-live", &["a real message about how vec0 chunk-domain catch-up should behave against a live Infinity service"]);
        let report = run_db_vector_catchup_backfill(&storage, 32, &identity, CANONICALIZE_PIPELINE_VERSION, CHUNKING_POLICY_VERSION, &fingerprint, &embed_fn, 7).unwrap();
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
    /// create_generation`) instead of creating a second one.
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
                schema::create_embedding_generation(
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
        let report = run_activation_audit(&storage, generation_id, 500, None, Some(&embed_fn), 200, 12345).expect("re-audit the CLI-produced generation");
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
