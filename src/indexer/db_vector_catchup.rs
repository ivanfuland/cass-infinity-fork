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
fn scan_eligible_message_ids(storage: &FrankenStorage) -> Result<Vec<i64>> {
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

    loop {
        let rows = fetch_hole_batch(storage, generation_id, batch_size)?;
        if rows.is_empty() {
            break;
        }

        // Defensive re-check (w3-3 Step0 design §3): genesis seeding
        // already guarantees every seeded doc_id canonicalizes non-empty,
        // but this loop must never assume it -- a silent drop inside
        // `embed_messages_with_sink`'s own prepare step would misalign
        // the positional zip below and attribute the wrong embedding to
        // the wrong doc_id. Filtering here first makes that impossible:
        // every input handed to the embedder is already known-non-empty,
        // so `embed_messages_with_sink` cannot drop any of them.
        let filtered: Vec<&HoleMessageRow> = rows
            .iter()
            .filter(|row| !canonicalize_for_embedding(&row.content).is_empty())
            .collect();
        if filtered.len() != rows.len() {
            tracing::warn!(
                generation_id,
                total = rows.len(),
                kept = filtered.len(),
                "db_vector_catchup: hole row canonicalized to empty text despite genesis \
                 eligibility filtering; leaving its hole unresolved for investigation"
            );
        }
        if filtered.is_empty() {
            // Every row in this batch was the defensive case above; avoid
            // spinning on the same non-empty-but-unembeddable rows forever
            // by stopping here rather than looping on an unchanged queue.
            break;
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

    let mut activated = false;
    if holes_after == 0 {
        schema::switch_active_generation(storage.raw(), generation_id, FrankenStorage::now_millis(), |tx| {
            let embedded_count: i64 = tx.query_row_map(
                "SELECT COUNT(*) FROM message_embeddings WHERE generation_id = ?1",
                &params![generation_id],
                |row| row.get_typed(0),
            )?;
            if embedded_count <= 0 {
                return Err(StorageError::Constraint {
                    detail: format!(
                        "generation {generation_id} has zero embedded rows; refusing to activate"
                    ),
                });
            }
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
    })
}
