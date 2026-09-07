//! T9 part 2 (mission #93b Step 1/3, control-plane 2026-09-04 addendum):
//! freezes the `_meta.candidates{...}` / top-level `_meta.semantic_degraded`
//! envelope shape `cass search --json/--jsonl --robot-meta` emits, against a
//! small, fixed, self-contained fixture -- one message with one v5
//! chunk-domain generation (dim=1024, matching bge-m3's real production
//! dimension so the CLI's auto-detected `InfinityEmbedder` round-trips
//! against a live Infinity server without a dimension mismatch). The
//! embedding vector stored for the chunk is a synthetic placeholder (its
//! semantic value is irrelevant here -- only the JSON envelope's *shape* is
//! under test); the real production write path (`cass index --semantic`)
//! is exercised elsewhere.
//!
//! Requires a live Infinity server reachable at `CASS_INFINITY_URL`
//! (default `http://127.0.0.1:7997`) serving `bge-m3` -- matching this
//! repo's other live-Infinity-dependent tests
//! (`db_vector_catchup_end_to_end_via_live_infinity`,
//! `fingerprint_live_infinity_roundtrip`), this test is `#[ignore]`d so a
//! plain `cargo test` run never depends on external network state; run it
//! explicitly with `--ignored` when Infinity is up.

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
/// Infinity server actually returns for a query embed, or `InfinityEmbedder`
/// (T7 protocol validation) rejects the round trip as
/// `embed_protocol_violation: dimension mismatch`.
const DIM: i64 = 1024;

fn cass_cmd(data_dir: &Path, test_home: &Path) -> Command {
    let mut cmd = Command::new(
        std::env::var("CARGO_BIN_EXE_cass").unwrap_or_else(|_| env!("CARGO_BIN_EXE_cass").to_string()),
    );
    cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .env("HOME", test_home)
        .env("XDG_DATA_HOME", test_home)
        .env("XDG_CONFIG_HOME", test_home.join(".config"))
        .env("CASS_IGNORE_SOURCES_CONFIG", "1")
        .args(["--data-dir", data_dir.to_str().expect("utf8 data dir")]);
    cmd
}

/// One message, one chunk, one active v5 generation certified
/// `audit_status='passed'` (the CLI's `load_semantic_context` ->
/// `probe_db_vector_domain_availability` gate requires both `is_active=1`
/// *and* `audit_status='passed'` before it reports `Ready` -- unlike this
/// PR's inline `search_db_vector_domain` unit tests, which call the
/// candidate-search function directly and never pass through that probe).
fn build_fixture(data_dir: &Path) {
    std::fs::create_dir_all(data_dir).expect("create data dir");
    let db_path = data_dir.join("agent_search.db");
    let storage = FrankenStorage::open(&db_path).expect("open storage");
    let agent_id = storage
        .ensure_agent(&Agent {
            id: None,
            slug: "codex".to_string(),
            name: "codex".to_string(),
            version: None,
            kind: AgentKind::Cli,
        })
        .expect("ensure agent");
    let conn = storage.raw();
    conn.execute(
        "INSERT OR IGNORE INTO sources(id, kind, created_at, updated_at) VALUES ('local', 'local', 0, 0)",
        &[],
    )
    .expect("insert source");
    conn.execute(
        "INSERT INTO conversations(id, agent_id, source_id, title, source_path) \
         VALUES (1, ?1, 'local', 't', '/tmp/w4-envelope-golden.jsonl')",
        fparams![agent_id],
    )
    .expect("insert conversation");
    conn.execute(
        "INSERT INTO messages(id, conversation_id, idx, role, created_at, content) \
         VALUES (1, 1, 0, 'user', 100, 'hello envelope world')",
        &[],
    )
    .expect("insert message");

    let vector: Vec<f32> = {
        let mut v = vec![0.0_f32; DIM as usize];
        v[0] = 1.0;
        v
    };
    let fingerprint = vec![0u8; 3 * (DIM as usize) * 4];
    let generation_id = conn
        .with_tx(TxMode::Immediate, |tx| {
            let generation_id =
                schema::create_embedding_generation(tx, "bge-m3", DIM, 1, 1, &fingerprint, 1_000)?;
            let norm = schema::l2_norm(&vector) as f32;
            schema::insert_chunk_row_in_tx(
                tx,
                &ChunkRow {
                    generation_id,
                    message_id: 1,
                    conversation_id: 1,
                    chunk_idx: 0,
                    byte_start: 0,
                    byte_end: 1,
                    content_hash: "h1".to_string(),
                    embedding: vector.clone(),
                    norm,
                    created_at_ms: 1_000,
                },
            )?;
            Ok(generation_id)
        })
        .expect("seed v5 generation + chunk");
    vector_domain::create_vec0_table_for_generation(conn, generation_id, DIM).expect("create vec0 table");
    let blob = schema::f32_vector_to_le_blob(&vector);
    conn.with_tx(TxMode::Immediate, |tx| {
        vector_domain::insert_vec0_rows_in_tx(tx, generation_id, &[(1, blob.as_slice())])
    })
    .expect("insert vec0 row");
    schema::switch_active_generation(conn, generation_id, 2_000, |_tx| Ok(())).expect("activate generation");
    conn.execute(
        "UPDATE embedding_generations SET audit_status = 'passed' WHERE id = ?1",
        fparams![generation_id],
    )
    .expect("certify generation");
}

fn extract_envelope(payload: &Json) -> Json {
    let meta = payload.get("_meta").cloned().unwrap_or(Json::Null);
    serde_json::json!({
        "candidates": meta.get("candidates").cloned().unwrap_or(Json::Null),
        "semantic_degraded": meta.get("semantic_degraded").cloned().unwrap_or(Json::Null),
    })
}

/// Same query, same fixture, run twice -- `--json` then `--jsonl` -- and
/// assert both formats' `_meta.candidates`/`_meta.semantic_degraded`
/// envelope slice matches the frozen golden
/// (`tests/fixtures/w4_search_envelope.golden.json`) *and* each other (the
/// two formats must agree on this envelope, not just each match the golden
/// independently).
#[test]
#[ignore = "requires a live Infinity service at 127.0.0.1:7997 (CASS_INFINITY_URL)"]
fn robot_json_and_jsonl_match_envelope_golden() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    build_fixture(&data_dir);

    let json_output = cass_cmd(&data_dir, dir.path())
        .args([
            "search",
            "hello envelope world",
            "--json",
            "--robot-meta",
            "--limit",
            "5",
            "--model",
            "bge-m3",
        ])
        .output()
        .expect("run cass search --json --robot-meta");
    assert!(
        json_output.status.success(),
        "cass search --json exited non-zero: status={:?}\nstdout:\n{}\nstderr:\n{}",
        json_output.status,
        String::from_utf8_lossy(&json_output.stdout),
        String::from_utf8_lossy(&json_output.stderr),
    );
    let json_payload: Json = serde_json::from_slice(&json_output.stdout).expect("valid search --json output");
    let json_envelope = extract_envelope(&json_payload);

    let jsonl_output = cass_cmd(&data_dir, dir.path())
        .args([
            "search",
            "hello envelope world",
            "--robot-format",
            "jsonl",
            "--robot-meta",
            "--limit",
            "5",
            "--model",
            "bge-m3",
        ])
        .output()
        .expect("run cass search --jsonl --robot-meta");
    assert!(
        jsonl_output.status.success(),
        "cass search --jsonl exited non-zero: status={:?}\nstdout:\n{}\nstderr:\n{}",
        jsonl_output.status,
        String::from_utf8_lossy(&jsonl_output.stdout),
        String::from_utf8_lossy(&jsonl_output.stderr),
    );
    let jsonl_stdout = String::from_utf8(jsonl_output.stdout).expect("utf8 jsonl stdout");
    let meta_line = jsonl_stdout
        .lines()
        .find_map(|line| {
            let value: Json = serde_json::from_str(line).ok()?;
            value.get("_meta").is_some().then_some(value)
        })
        .expect("jsonl output must have a _meta header line");
    let jsonl_envelope = extract_envelope(&meta_line);

    assert_eq!(
        json_envelope, jsonl_envelope,
        "--json and --jsonl must agree on the candidates/semantic_degraded envelope"
    );

    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/w4_search_envelope.golden.json");
    let golden: Json = serde_json::from_str(
        &std::fs::read_to_string(&golden_path)
            .unwrap_or_else(|err| panic!("read {}: {err}", golden_path.display())),
    )
    .unwrap_or_else(|err| panic!("parse {}: {err}", golden_path.display()));
    assert_eq!(
        json_envelope, golden,
        "_meta.candidates/_meta.semantic_degraded envelope drifted from tests/fixtures/w4_search_envelope.golden.json"
    );
}
