//! Drill asset (w3-3 Step2, task book #61) — not a product feature.
//!
//! Post-backfill attestation helper: samples N doc_ids from the active
//! generation's `message_embeddings`, self-queries each one's own stored
//! vector through `vector_domain::vec0_knn`, and reports whether the
//! nearest hit is the doc itself at near-1.0 cosine similarity (`1 -
//! distance`). A real read-path light-up at the full query.rs level
//! (`SearchClient::search_db_vector_domain`) was already proven in the
//! w3-3 Step1 `#[ignore]` test on a small fixture; this binary exercises
//! the same underlying `vec0` index at real scale.
//!
//! Usage: `cass_db_path=<path> cargo run --release --example
//! w3_3_db_vector_catchup_verify`

use coding_agent_search::storage::api::{IntoValue, Value};
use coding_agent_search::storage::schema::le_blob_to_f32_vector;
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::vector_domain::vec0_knn;

macro_rules! params {
    ($($val:expr),+ $(,)?) => {
        &[$(IntoValue::into_value($val)),+] as &[Value]
    };
}

fn main() -> anyhow::Result<()> {
    let db_path = std::env::var("cass_db_path")
        .map_err(|_| anyhow::anyhow!("set cass_db_path=<path to agent_search.db>"))?;
    let storage = FrankenStorage::open_writer(std::path::Path::new(&db_path))
        .map_err(|e| anyhow::anyhow!("opening {db_path}: {e}"))?;
    let conn = storage.raw();

    let generation_id: i64 = conn
        .query_row_map(
            "SELECT id FROM embedding_generations WHERE is_active = 1",
            &[],
            |row| row.get_typed(0),
        )
        .map_err(|e| anyhow::anyhow!("no active generation: {e}"))?;

    let sample_count = std::env::var("SAMPLE_COUNT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(5);

    let samples: Vec<(i64, Vec<u8>)> = conn.query_all_map(
        "SELECT doc_id, embedding FROM message_embeddings \
         WHERE generation_id = ?1 \
         ORDER BY (doc_id * 2654435761) % 1000003 \
         LIMIT ?2",
        params![generation_id, sample_count as i64],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
    )?;

    let mut results = Vec::new();
    for (doc_id, blob) in &samples {
        let vector = le_blob_to_f32_vector(blob)?;
        let hits = vec0_knn(conn, generation_id, &vector, 5)?;
        let top = hits.first().copied();
        let self_hit = hits.first().is_some_and(|(hit_doc_id, _)| hit_doc_id == doc_id);
        let content: String = conn
            .query_row_map(
                "SELECT substr(content, 1, 60) FROM messages WHERE id = ?1",
                params![*doc_id],
                |row| row.get_typed(0),
            )
            .unwrap_or_default();
        results.push(serde_json::json!({
            "doc_id": doc_id,
            "content_preview": content,
            "top_hit_doc_id": top.map(|(id, _)| id),
            "top_hit_distance": top.map(|(_, d)| d),
            "self_hit": self_hit,
            "hit_count": hits.len(),
        }));
    }

    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "generation_id": generation_id,
        "sample_count": samples.len(),
        "samples": results,
    }))?);
    Ok(())
}
