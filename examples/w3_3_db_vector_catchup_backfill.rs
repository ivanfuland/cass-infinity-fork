//! Drill asset (w3-3 Step2, task book #61) — not a product feature, not
//! wired into the `cass` command surface or `Commands` enum.
//!
//! Drives `coding_agent_search::indexer::db_vector_catchup::
//! run_db_vector_catchup_backfill` against a real database for the
//! Step2 real-scale backfill run (per w3-3 Step0 design ruling ④: the
//! worker is a `pub fn` orchestration-layer API, not a CLI surface yet
//! -- W3-4 wires that in -- so Step2's real-scale run drives it directly
//! from a small `examples/` binary rather than through `cass`).
//!
//! Usage: `cass_db_path=<path> cargo run --release --example
//! w3_3_db_vector_catchup_backfill` (env var, not an argv flag, so the
//! nohup launch command stays a single simple invocation). Set
//! `CASS_SEMANTIC_PROGRESS_JSONL=<path>` before launching to get the
//! existing JSONL progress sink's marker/heartbeat stream (w3-3 Step0
//! design d5: no in-process watchdog, judge progress by that file's
//! last line + mtime, never by process state).
//!
//! Prints the final `DbVectorCatchupReport` as JSON to stdout on
//! success. Non-zero exit + the error's full context chain (via `{:#}`)
//! on failure.

fn main() -> anyhow::Result<()> {
    let db_path = std::env::var("cass_db_path")
        .map_err(|_| anyhow::anyhow!("set cass_db_path=<path to agent_search.db>"))?;
    let db_path = std::path::PathBuf::from(db_path);

    eprintln!(
        "[w3_3_db_vector_catchup_backfill] opening {} (started {})",
        db_path.display(),
        chrono_now_string()
    );

    let storage = coding_agent_search::storage::sqlite::FrankenStorage::open_writer(&db_path)
        .map_err(|e| anyhow::anyhow!("opening {}: {e}", db_path.display()))?;

    let batch_size = coding_agent_search::indexer::semantic::SemanticIndexer::new("infinity", None)?
        .batch_size();
    eprintln!("[w3_3_db_vector_catchup_backfill] batch_size={batch_size} (resolved_default_batch_size / CASS_SEMANTIC_BATCH_SIZE)");

    let report = coding_agent_search::indexer::db_vector_catchup::run_db_vector_catchup_backfill(
        &storage,
        batch_size,
    )?;

    eprintln!(
        "[w3_3_db_vector_catchup_backfill] done ({})",
        chrono_now_string()
    );
    println!("{}", serde_json::to_string_pretty(&ReportJson::from(&report))?);
    Ok(())
}

fn chrono_now_string() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("unix_ms={now}")
}

#[derive(serde::Serialize)]
struct ReportJson {
    generation_id: i64,
    reused_existing_generation: bool,
    embedder_id: String,
    dim: i64,
    eligible_seeded: u64,
    embedded_inserted: u64,
    stale_skipped: u64,
    holes_before: u64,
    holes_after: u64,
    vec0_rows: usize,
    activated: bool,
}

impl From<&coding_agent_search::indexer::db_vector_catchup::DbVectorCatchupReport> for ReportJson {
    fn from(r: &coding_agent_search::indexer::db_vector_catchup::DbVectorCatchupReport) -> Self {
        Self {
            generation_id: r.generation_id,
            reused_existing_generation: r.reused_existing_generation,
            embedder_id: r.embedder_id.clone(),
            dim: r.dim,
            eligible_seeded: r.eligible_seeded,
            embedded_inserted: r.embedded_inserted,
            stale_skipped: r.stale_skipped,
            holes_before: r.holes_before,
            holes_after: r.holes_after,
            vec0_rows: r.vec0_rows,
            activated: r.activated,
        }
    }
}
