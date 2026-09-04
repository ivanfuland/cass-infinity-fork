//! Drill asset (task book #80, exec72) — not a product feature, not wired
//! into the `cass` command surface.
//!
//! Locates the exact `doc_id`s that activation audit ④ (`db_vector_catchup
//! ::run_activation_audit`) flags as "embedded but no longer eligible" for
//! the currently-active generation, and prints per-row diagnostics so the
//! mechanism can be read off the evidence instead of guessed at.
//!
//! Read-only by default: only ever issues `SELECT`s and the public
//! read-path methods (`fetch_messages_for_conversation`, renamed from
//! `fetch_messages_for_lexical_rebuild` under plan v5.1 T5, which also
//! removed the 8 MiB per-conversation cap this drill originally diagnosed
//! -- the "post-truncation"/"byte_cap_*" framing below is now historical:
//! every conversation's content reaches this scan whole) that the real
//! eligibility scan (`db_vector_catchup::scan_eligible_message_ids`, itself
//! `pub(crate)` and therefore unreachable from an `examples/` binary) is
//! built from. Opens via `FrankenStorage::open_readonly` so there is no
//! writer lock, no migration write, no activation side effect possible
//! from this binary regardless of which database path it is pointed at.
//!
//! `APPLY=1` switches to a writer connection and additionally *applies*
//! the task book #80/#81 fix's reverse-reconciliation step against
//! whatever database `CASS_DATA_DIR` points at -- the same prune-then-
//! demote-then-rebuild sequence `run_db_vector_catchup_backfill`'s own
//! reverse-reconciliation step runs (not a byte-for-byte reproduction of
//! the whole function: this drill only ever prunes, it never drains holes
//! or embeds anything, since it has no Infinity indexer of its own) --
//! then always runs the real `run_activation_audit` (no Infinity call
//! inside it) regardless of whether there was anything to prune (R2-B2),
//! so a clean database still gets a real pass/fail verdict instead of a
//! silent "nothing to do". The process exit code reflects that verdict
//! (R2-N5): 0 only if the audit actually passed. Only ever point this at
//! the read-only diagnostic copy, never at a production data dir.
//!
//! R1-N4: no `examples/` target in this crate declares `required-features`
//! in `Cargo.toml` (none exist there at all, including the sibling
//! `w3_3`/`w3_4` drills this one is modeled on), so this file follows that
//! same convention rather than introducing the first one -- the
//! requirement is documented here instead. `run_activation_audit`'s own
//! dependency chain needs the `infinity` feature compiled in.
//!
//! Usage: `cargo run --release --no-default-features --features
//! qr,encryption,infinity --example w3_5_audit_orphans`, with
//! `CASS_DATA_DIR=<dir containing agent_search.db>
//! [XDG_CONFIG_HOME=<empty dir>] [APPLY=1]` set on the resulting binary.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow};
use coding_agent_search::default_db_path;
use coding_agent_search::indexer::db_vector_catchup::run_activation_audit;
use coding_agent_search::search::canonicalize::canonicalize_for_embedding;
use coding_agent_search::storage::api::{TxMode, Value};
use coding_agent_search::storage::schema;
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::vector_domain;

/// One conversation's eligibility state, computed the exact same way
/// `db_vector_catchup::scan_eligible_message_ids` computes it --
/// `fetch_messages_for_conversation` (idx order; capless since T5 retired
/// the 8 MiB per-conversation content cap, `#290`) then the same two
/// filters (`!content.is_empty()`, `!canonicalize_for_embedding(content).
/// is_empty()`).
struct ConversationEligibility {
    total_messages: usize,
    eligible_idx: HashSet<i64>,
    /// idx -> content length as fetched (kept as a field name for
    /// historical continuity with pre-T5 runs of this drill; no longer
    /// truncation-shortened -- see the module doc comment).
    truncated_len_by_idx: HashMap<i64, usize>,
}

fn main() -> Result<()> {
    let apply = std::env::var("APPLY").map(|v| v == "1").unwrap_or(false);
    let db_path = default_db_path();
    let storage = if apply {
        eprintln!("APPLY=1: opening (writer) {} -- will prune + rebuild vec0 on this database", db_path.display());
        FrankenStorage::open_writer(&db_path).with_context(|| format!("opening {} as writer for APPLY", db_path.display()))?
    } else {
        eprintln!("opening (read-only) {}", db_path.display());
        FrankenStorage::open_readonly(&db_path).with_context(|| format!("opening {} read-only", db_path.display()))?
    };

    let generation_id: i64 = storage
        .raw()
        .query_row_map("SELECT id FROM embedding_generations WHERE is_active = 1", &[], |row| {
            row.get_typed(0)
        })
        .map_err(|e| anyhow!("no active generation: {e}"))?;
    eprintln!("active generation_id={generation_id}");

    let embedded_ids: Vec<i64> = storage.raw().query_all_map(
        "SELECT doc_id FROM message_embeddings WHERE generation_id = ?1",
        &[Value::from(generation_id)],
        |row| row.get_typed(0),
    )?;
    let embedded_set: HashSet<i64> = embedded_ids.iter().copied().collect();
    eprintln!("embedded_set size={}", embedded_set.len());

    let conversation_ids: Vec<i64> =
        storage
            .raw()
            .query_all_map("SELECT id FROM conversations ORDER BY id", &[], |row| row.get_typed(0))?;
    eprintln!("scanning {} conversations for eligibility (post-truncation replay)...", conversation_ids.len());

    let mut eligible_set: HashSet<i64> = HashSet::new();
    let mut eligibility_by_conv: HashMap<i64, ConversationEligibility> = HashMap::with_capacity(conversation_ids.len());

    for &cid in &conversation_ids {
        let messages = storage
            .fetch_messages_for_conversation(cid)
            .with_context(|| format!("fetching messages for conversation {cid}"))?;
        let mut eligible_idx = HashSet::new();
        let mut truncated_len_by_idx = HashMap::with_capacity(messages.len());
        for m in &messages {
            truncated_len_by_idx.insert(m.idx, m.content.len());
            if m.content.is_empty() {
                continue;
            }
            if canonicalize_for_embedding(&m.content).is_empty() {
                continue;
            }
            if let Some(id) = m.id {
                eligible_set.insert(id);
                eligible_idx.insert(m.idx);
            }
        }
        eligibility_by_conv.insert(
            cid,
            ConversationEligibility { total_messages: messages.len(), eligible_idx, truncated_len_by_idx },
        );
    }
    eprintln!("eligible_set size={}", eligible_set.len());

    let mut eligible_not_embedded: Vec<i64> = eligible_set.difference(&embedded_set).copied().collect();
    eligible_not_embedded.sort_unstable();
    let mut embedded_not_eligible: Vec<i64> = embedded_set.difference(&eligible_set).copied().collect();
    embedded_not_eligible.sort_unstable();

    println!(
        "eligible_not_embedded_count={} embedded_not_eligible_count={}",
        eligible_not_embedded.len(),
        embedded_not_eligible.len()
    );
    if !eligible_not_embedded.is_empty() {
        println!(
            "eligible_not_embedded (first 20): {:?}",
            &eligible_not_embedded[..eligible_not_embedded.len().min(20)]
        );
    }
    println!("---- embedded_not_eligible full table ----");

    let mut per_conv_reason_counts: HashMap<(i64, &'static str), usize> = HashMap::new();

    for &doc_id in &embedded_not_eligible {
        let row: Option<(i64, i64, String, String)> = storage.raw().query_opt_map(
            "SELECT conversation_id, idx, role, content FROM messages WHERE id = ?1",
            &[Value::from(doc_id)],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?)),
        )?;
        let Some((conversation_id, idx, role, raw_content)) = row else {
            println!("doc_id={doc_id} -- messages row GONE (should have cascade-deleted its embedding too; separate bug if seen)");
            continue;
        };

        let (source_path, agent_slug): (String, String) = storage
            .raw()
            .query_row_map(
                "SELECT c.source_path, a.slug FROM conversations c JOIN agents a ON a.id = c.agent_id WHERE c.id = ?1",
                &[Value::from(conversation_id)],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )
            .unwrap_or(("<unknown>".to_string(), "<unknown>".to_string()));
        let tail: String = {
            let chars: Vec<char> = source_path.chars().collect();
            let start = chars.len().saturating_sub(60);
            chars[start..].iter().collect()
        };

        let elig = eligibility_by_conv.get(&conversation_id);
        let conv_total_msgs = elig.map(|e| e.total_messages).unwrap_or(0);
        let in_semantic_projection = elig.map(|e| e.eligible_idx.contains(&idx)).unwrap_or(false);
        let truncated_len = elig.and_then(|e| e.truncated_len_by_idx.get(&idx).copied());

        let raw_canon_empty = canonicalize_for_embedding(&raw_content).is_empty();
        let truncated_to_empty = truncated_len == Some(0) && !raw_content.is_empty();
        let reason: &'static str = if truncated_to_empty {
            "byte_cap_truncated_to_empty"
        } else if raw_canon_empty {
            "raw_content_canonicalizes_empty"
        } else if truncated_len.is_some_and(|len| len < raw_content.len()) {
            "byte_cap_partial_truncation_still_nonempty_canonicalize_check_below"
        } else {
            "unexplained"
        };
        *per_conv_reason_counts.entry((conversation_id, reason)).or_insert(0) += 1;

        println!(
            "doc_id={doc_id} conv={conversation_id} agent={agent_slug} source_tail=...{tail} idx={idx} role={role} \
             raw_content_len={} truncated_content_len={:?} raw_canon_empty={raw_canon_empty} \
             conv_total_msgs={conv_total_msgs} in_semantic_projection={in_semantic_projection} reason={reason}",
            raw_content.len(),
            truncated_len,
        );
    }

    println!("---- clustered by (conversation_id, reason) ----");
    let mut clustered: Vec<((i64, &'static str), usize)> = per_conv_reason_counts.into_iter().collect();
    clustered.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    for ((conversation_id, reason), count) in clustered {
        println!("conv={conversation_id} reason={reason} count={count}");
    }

    if apply {
        println!("---- APPLY: reproducing the fix's reverse-reconciliation step ----");
        if embedded_not_eligible.is_empty() {
            println!("APPLY: nothing to prune (embedded_not_eligible is already empty).");
        } else {
            eprintln!(
                "APPLY: pruning {} ineligible embedded doc_id(s) on {}",
                embedded_not_eligible.len(),
                db_path.display()
            );
            storage
                .raw()
                .with_tx(TxMode::Immediate, |tx| {
                    let mut pruned = 0u64;
                    for doc_id in &embedded_not_eligible {
                        pruned = pruned.saturating_add(schema::prune_ineligible_message_embedding_in_tx(tx, generation_id, *doc_id)?);
                    }
                    // R1-B1/R2-N3: same atomic-demote discipline as the
                    // production prune step, scoped to this generation_id.
                    if pruned > 0 {
                        schema::demote_generation_readiness_if_active_in_tx(tx, generation_id)?;
                    }
                    Ok(pruned)
                })
                .context("APPLY: pruning ineligible message_embeddings rows")?;

            let dim: i64 = storage.raw().query_row_map(
                "SELECT dim FROM embedding_generations WHERE id = ?1",
                &[Value::from(generation_id)],
                |row| row.get_typed(0),
            )?;
            eprintln!("APPLY: rebuilding vec0 for generation_id={generation_id} dim={dim}...");
            let vec0_rows = vector_domain::rebuild_vec0_table_for_generation(storage.raw(), generation_id, dim)
                .context("APPLY: rebuilding vec0 table for generation")?;
            println!("APPLY: vec0_rows after rebuild = {vec0_rows}");
        }

        // R2-B2: always run the real audit, whether or not there was
        // anything to prune -- a clean database (already fully
        // reconciled, or with nothing ever ineligible) deserves a real
        // pass/fail verdict too, not a silently-skipped "nothing to do"
        // that never actually confirmed the generation is activatable.
        eprintln!("APPLY: running the real activation audit (no Infinity call)...");
        let audit =
            run_activation_audit(&storage, generation_id, 5_000, None).context("APPLY: running activation audit")?;
        println!(
            "APPLY: activation audit passed={} embedded_not_eligible_count={} eligible_not_embedded_count={} \
             dim_mismatch_count={} finite_norm_violation_count={} foreign_key_violation_count={} \
             message_embeddings_rows_missing_from_vec0={} vec0_rows_missing_from_message_embeddings={} failure_reasons={:?}",
            audit.passed,
            audit.embedded_not_eligible_count,
            audit.eligible_not_embedded_count,
            audit.dim_mismatch_count,
            audit.finite_norm_violation_count,
            audit.foreign_key_violation_count,
            audit.message_embeddings_rows_missing_from_vec0,
            audit.vec0_rows_missing_from_message_embeddings,
            audit.failure_reasons,
        );
        // R2-N5: the exit code is the audit verdict, not merely "the
        // prune-and-rebuild sequence didn't error" -- a caller scripting
        // this drill must be able to trust `$?` alone.
        if !audit.passed {
            anyhow::bail!("APPLY: activation audit failed -- fix is not sufficient");
        }
    }

    Ok(())
}
