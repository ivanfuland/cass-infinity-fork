//! Drill asset (W3-4 Step1, task book #62) — not a product feature, not
//! wired into the `cass` command surface.
//!
//! Runs the real full activation audit
//! (`coding_agent_search::indexer::db_vector_catchup::
//! run_activation_audit_and_record`) against the currently-active
//! generation of a real database (staging generation_id=1's real starting
//! state per the backfill report: `is_active=1`, `audit_status='pending'`).
//! Prints the full report as JSON and exits non-zero if the audit failed,
//! so a caller can gate on it without parsing prose.
//!
//! Usage: `cass_db_path=<path> [FINITE_NORM_SAMPLE_SIZE=5000]
//! [POSITIVE_CHECK_DOC_ID=1000003] cargo run --release --example
//! w3_4_activation_audit_run`

use coding_agent_search::indexer::db_vector_catchup::run_activation_audit_and_record;
use coding_agent_search::storage::sqlite::FrankenStorage;

fn main() -> anyhow::Result<()> {
    let db_path = std::env::var("cass_db_path").map_err(|_| anyhow::anyhow!("set cass_db_path=<path to agent_search.db>"))?;
    let storage = FrankenStorage::open_writer(std::path::Path::new(&db_path)).map_err(|e| anyhow::anyhow!("opening {db_path}: {e}"))?;

    let generation_id: i64 = storage
        .raw()
        .query_row_map("SELECT id FROM embedding_generations WHERE is_active = 1", &[], |row| row.get_typed(0))
        .map_err(|e| anyhow::anyhow!("no active generation: {e}"))?;

    let finite_norm_sample_size: usize =
        std::env::var("FINITE_NORM_SAMPLE_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(5_000);
    let positive_check_doc_id: Option<i64> =
        std::env::var("POSITIVE_CHECK_DOC_ID").ok().and_then(|v| v.parse().ok());

    let started = std::time::Instant::now();
    let report = run_activation_audit_and_record(&storage, generation_id, finite_norm_sample_size, positive_check_doc_id)?;
    let elapsed_ms = started.elapsed().as_millis();

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "generation_id": report.generation_id,
            "passed": report.passed,
            "elapsed_ms": elapsed_ms,
            "dim_mismatch_count": report.dim_mismatch_count,
            "finite_norm_sample_size": report.finite_norm_sample_size,
            "finite_norm_checked": report.finite_norm_checked,
            "finite_norm_violation_count": report.finite_norm_violation_count,
            "positive_check_doc_id": report.positive_check_doc_id,
            "positive_check_top_hit_doc_id": report.positive_check_top_hit_doc_id,
            "positive_check_distance": report.positive_check_distance,
            "eligible_not_embedded_count": report.eligible_not_embedded_count,
            "embedded_not_eligible_count": report.embedded_not_eligible_count,
            "canonicalize_version_expected": report.canonicalize_version_expected,
            "canonicalize_version_actual": report.canonicalize_version_actual,
            "foreign_key_violation_count": report.foreign_key_violation_count,
            "failure_reasons": report.failure_reasons,
        }))?
    );

    if !report.passed {
        anyhow::bail!("activation audit failed for generation {generation_id}");
    }
    Ok(())
}
