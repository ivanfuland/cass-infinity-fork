//! T11.9 (mission #102, control-plane 2026-09-05): the chunk-domain
//! provenance fields T9 added to `SearchHit` (`message_id`,
//! `winning_chunk_idx`, `winning_chunk_span`, `winning_chunk_hash`) are
//! populated correctly at the query layer (`src/search/query.rs`'s
//! `hydrate_semantic_hits_with_ids`) but several hand-written CLI output
//! fast paths in `src/lib.rs` serialize `SearchHit` themselves instead of
//! going through its own `#[derive(Serialize)]` -- this file proves each
//! of those paths (bare `--json`, `--json --robot-meta`, `--fields
//! <names>`, `--jsonl`, and the `--fields summary` projection) actually
//! emits the four fields for a semantic hit, and that a lexical-only hit
//! (which never goes through the chunk domain at all) emits none of them.
//!
//! Fixture mirrors `tests/w4_search_chunks.rs`'s v5 single-chunk setup
//! (same real bge-m3 dimension, same live-Infinity dependency, hence
//! `#[ignore]`d the same way) plus a second, chunk-domain-free message
//! findable only lexically -- proving the two hit kinds' provenance
//! shape differs as expected, not merely that the semantic one has it.

use coding_agent_search::model::types::{Agent, AgentKind};
use coding_agent_search::storage::api::{IntoValue, TxMode, Value};
use coding_agent_search::storage::schema::{self, ChunkRow};
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::vector_domain;
use serde_json::Value as Json;
use std::path::Path;
use std::process::Command;

macro_rules! fparams {
    ($($val:expr),+ $(,)?) => {
        &[$(Value::from(IntoValue::into_value($val))),+] as &[Value]
    };
}

/// bge-m3's real production embedding dimension -- must match what a live
/// Infinity server actually returns for a query embed (see
/// `tests/w4_search_chunks.rs`'s identical constant/comment).
const DIM: i64 = 1024;

const SEMANTIC_QUERY: &str = "hello provenance world alpha";
const LEXICAL_ONLY_QUERY: &str = "xylophone lexical marker beta";
const CONTENT_HASH: &str = "w4-cli-hit-provenance-h1";

fn cass_cmd(data_dir: &Path, test_home: &Path) -> Command {
    let mut cmd = Command::new(std::env::var("CARGO_BIN_EXE_cass").unwrap_or_else(|_| env!("CARGO_BIN_EXE_cass").to_string()));
    cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .env("HOME", test_home)
        .env("XDG_DATA_HOME", test_home)
        .env("XDG_CONFIG_HOME", test_home.join(".config"))
        .env("CASS_IGNORE_SOURCES_CONFIG", "1")
        .args(["--data-dir", data_dir.to_str().expect("utf8 data dir")]);
    cmd
}

/// Message 1: one v5 chunk-domain generation, one chunk, certified active
/// (`is_active=1 AND audit_status='passed'`) -- the only embedded content
/// in the whole corpus, so a semantic query for its own text trivially
/// returns it as the sole KNN candidate regardless of the (synthetic,
/// meaningless) placeholder vector's actual geometry -- same trick
/// `tests/w4_search_chunks.rs` relies on.
///
/// Message 2: plain FTS-only content, no `message_chunks` row, no
/// embedding -- reachable exclusively via lexical search, so its hit can
/// never carry chunk-domain provenance no matter what this file's fix
/// does.
fn build_fixture(data_dir: &Path) {
    std::fs::create_dir_all(data_dir).expect("create data dir");
    let db_path = data_dir.join("agent_search.db");
    let storage = FrankenStorage::open(&db_path).expect("open storage");
    let agent_id = storage
        .ensure_agent(&Agent { id: None, slug: "codex".to_string(), name: "codex".to_string(), version: None, kind: AgentKind::Cli })
        .expect("ensure agent");
    let conn = storage.raw();
    conn.execute("INSERT OR IGNORE INTO sources(id, kind, created_at, updated_at) VALUES ('local', 'local', 0, 0)", &[]).expect("insert source");

    conn.execute(
        "INSERT INTO conversations(id, agent_id, source_id, title, source_path) VALUES (1, ?1, 'local', 't', '/tmp/w4-cli-hit-provenance-1.jsonl')",
        fparams![agent_id],
    )
    .expect("insert conversation 1");
    conn.execute(
        &format!("INSERT INTO messages(id, conversation_id, idx, role, created_at, content) VALUES (1, 1, 0, 'user', 100, '{SEMANTIC_QUERY}')"),
        &[],
    )
    .expect("insert message 1");

    conn.execute(
        "INSERT INTO conversations(id, agent_id, source_id, title, source_path) VALUES (2, ?1, 'local', 't', '/tmp/w4-cli-hit-provenance-2.jsonl')",
        fparams![agent_id],
    )
    .expect("insert conversation 2");
    conn.execute(
        &format!("INSERT INTO messages(id, conversation_id, idx, role, created_at, content) VALUES (2, 2, 0, 'user', 100, '{LEXICAL_ONLY_QUERY}')"),
        &[],
    )
    .expect("insert message 2 (lexical-only, never chunked/embedded)");

    let vector: Vec<f32> = {
        let mut v = vec![0.0_f32; DIM as usize];
        v[0] = 1.0;
        v
    };
    let fingerprint = vec![0u8; 3 * (DIM as usize) * 4];
    let generation_id = conn
        .with_tx(TxMode::Immediate, |tx| {
            let generation_id = schema::create_embedding_generation(tx, "bge-m3", DIM, 1, 1, &fingerprint, 1_000)?;
            let norm = schema::l2_norm(&vector) as f32;
            schema::insert_chunk_row_in_tx(
                tx,
                &ChunkRow {
                    generation_id,
                    message_id: 1,
                    conversation_id: 1,
                    chunk_idx: 0,
                    byte_start: 0,
                    byte_end: SEMANTIC_QUERY.len(),
                    content_hash: CONTENT_HASH.to_string(),
                    embedding: vector.clone(),
                    norm,
                    created_at_ms: 1_000,
                },
            )?;
            Ok(generation_id)
        })
        .expect("seed v5 generation + chunk for message 1");
    vector_domain::create_vec0_table_for_generation(conn, generation_id, DIM).expect("create vec0 table");
    let blob = schema::f32_vector_to_le_blob(&vector);
    conn.with_tx(TxMode::Immediate, |tx| vector_domain::insert_vec0_rows_in_tx(tx, generation_id, &[(1, blob.as_slice())])).expect("insert vec0 row");
    schema::switch_active_generation(conn, generation_id, 2_000, |_tx| Ok(())).expect("activate generation");
    conn.execute("UPDATE embedding_generations SET audit_status = 'passed' WHERE id = ?1", fparams![generation_id]).expect("certify generation");
}

fn run_search(data_dir: &Path, test_home: &Path, extra_args: &[&str], query: &str) -> Json {
    let output = cass_cmd(data_dir, test_home).args(["search", query]).args(extra_args).args(["--limit", "5", "--model", "bge-m3"]).output().expect("run cass search");
    assert!(
        output.status.success(),
        "cass search {extra_args:?} exited non-zero: status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("valid json output for {extra_args:?}: {e}\nstdout:\n{}", String::from_utf8_lossy(&output.stdout)))
}

fn first_hit<'a>(payload: &'a Json, query_desc: &str) -> &'a Json {
    payload.get("hits").and_then(Json::as_array).and_then(|hits| hits.first()).unwrap_or_else(|| panic!("expected at least one hit for {query_desc}, got: {payload:#?}"))
}

fn assert_semantic_provenance(hit: &Json) {
    assert_eq!(hit.get("message_id").and_then(Json::as_i64), Some(1), "message_id: {hit:#?}");
    assert_eq!(hit.get("winning_chunk_idx").and_then(Json::as_u64), Some(0), "winning_chunk_idx: {hit:#?}");
    let span: Vec<u64> = hit.get("winning_chunk_span").and_then(Json::as_array).unwrap_or_else(|| panic!("winning_chunk_span missing: {hit:#?}")).iter().map(|v| v.as_u64().expect("span element is a number")).collect();
    assert_eq!(span, vec![0, SEMANTIC_QUERY.len() as u64], "winning_chunk_span: {hit:#?}");
    assert_eq!(hit.get("winning_chunk_hash").and_then(Json::as_str), Some(CONTENT_HASH), "winning_chunk_hash: {hit:#?}");
}

/// T11.11 (mission #105, rootcause report §0): a lexical hit *does* carry
/// `message_id` now (`search_fts_lex_domain` fills it from
/// `candidate.doc_id`, which is exactly `lex_docs.doc_id` / `messages.id`)
/// -- but never the three `winning_chunk_*` fields, since a lexical-only
/// message (no `message_chunks` row at all, per this fixture's message 2)
/// has no chunk-domain provenance to report.
fn assert_lexical_hit_carries_message_id_only(hit: &Json, expected_message_id: i64) {
    assert_eq!(
        hit.get("message_id").and_then(Json::as_i64),
        Some(expected_message_id),
        "message_id: {hit:#?}"
    );
    for key in ["winning_chunk_idx", "winning_chunk_span", "winning_chunk_hash"] {
        assert!(hit.get(key).is_none(), "expected no {key:?} key on a lexical-only hit: {hit:#?}");
    }
}

#[test]
#[ignore = "requires a live Infinity service at 127.0.0.1:7997 (CASS_INFINITY_URL)"]
fn bare_json_semantic_hit_has_provenance_lexical_hit_has_message_id_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    build_fixture(&data_dir);

    let semantic_payload = run_search(&data_dir, dir.path(), &["--json", "--mode", "semantic", "--daemon"], SEMANTIC_QUERY);
    assert_semantic_provenance(first_hit(&semantic_payload, "bare --json semantic query"));

    // Default mode is "hybrid-preferred", which (with the v5 chunk domain
    // Ready and only ever one embedded item in this fixture) accepts the
    // trivial single-candidate semantic match for ANY query text rather
    // than falling through to lexical -- explicit `--mode lexical` is the
    // only way to reliably reach message 2's lexical-only hit.
    let lexical_payload = run_search(&data_dir, dir.path(), &["--json", "--mode", "lexical"], LEXICAL_ONLY_QUERY);
    assert_lexical_hit_carries_message_id_only(first_hit(&lexical_payload, "bare --json lexical-only query"), 2);
}

#[test]
#[ignore = "requires a live Infinity service at 127.0.0.1:7997 (CASS_INFINITY_URL)"]
fn json_robot_meta_semantic_hit_has_provenance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    build_fixture(&data_dir);

    let payload = run_search(&data_dir, dir.path(), &["--json", "--robot-meta", "--mode", "semantic", "--daemon"], SEMANTIC_QUERY);
    assert_semantic_provenance(first_hit(&payload, "--json --robot-meta semantic query"));
}

#[test]
#[ignore = "requires a live Infinity service at 127.0.0.1:7997 (CASS_INFINITY_URL)"]
fn fields_projection_includes_provenance_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    build_fixture(&data_dir);

    let payload = run_search(&data_dir, dir.path(), &["--json", "--mode", "semantic", "--daemon", "--fields", "message_id,winning_chunk_idx,winning_chunk_span,winning_chunk_hash,source_path"], SEMANTIC_QUERY);
    let hit = first_hit(&payload, "--fields <provenance names> semantic query");
    assert_semantic_provenance(hit);
    assert!(hit.get("source_path").and_then(Json::as_str).is_some(), "source_path should still project alongside the new fields: {hit:#?}");
    // The projection is exact -- no field outside the requested list leaks in.
    assert_eq!(hit.as_object().map(|m| m.len()), Some(5), "unexpected extra fields in --fields projection: {hit:#?}");
}

#[test]
#[ignore = "requires a live Infinity service at 127.0.0.1:7997 (CASS_INFINITY_URL)"]
fn jsonl_semantic_hit_has_provenance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    build_fixture(&data_dir);

    let output =
        cass_cmd(&data_dir, dir.path()).args(["search", SEMANTIC_QUERY, "--robot-format", "jsonl", "--mode", "semantic", "--daemon", "--limit", "5", "--model", "bge-m3"]).output().expect("run cass search --robot-format jsonl");
    assert!(output.status.success(), "cass search --robot-format jsonl exited non-zero: {:?}\nstderr:\n{}", output.status, String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).expect("utf8 jsonl stdout");
    let hit_line = stdout.lines().find_map(|line| {
        let value: Json = serde_json::from_str(line).ok()?;
        (value.get("_meta").is_none() && value.get("message_id").is_some()).then_some(value)
    });
    let hit = hit_line.unwrap_or_else(|| panic!("no jsonl hit line carried message_id; full stdout:\n{stdout}"));
    assert_semantic_provenance(&hit);
}

#[test]
#[ignore = "requires a live Infinity service at 127.0.0.1:7997 (CASS_INFINITY_URL)"]
fn summary_projection_includes_message_id_and_winning_chunk_idx() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    build_fixture(&data_dir);

    let payload = run_search(&data_dir, dir.path(), &["--json", "--mode", "semantic", "--daemon", "--fields", "summary"], SEMANTIC_QUERY);
    let hit = first_hit(&payload, "--fields summary semantic query");
    assert_eq!(hit.get("message_id").and_then(Json::as_i64), Some(1), "summary projection message_id: {hit:#?}");
    assert_eq!(hit.get("winning_chunk_idx").and_then(Json::as_u64), Some(0), "summary projection winning_chunk_idx: {hit:#?}");
    // Summary is a deliberately thin projection -- span/hash do not belong here (mission's own ②).
    assert!(hit.get("winning_chunk_span").is_none(), "summary projection should not include winning_chunk_span: {hit:#?}");
    assert!(hit.get("winning_chunk_hash").is_none(), "summary projection should not include winning_chunk_hash: {hit:#?}");
}
