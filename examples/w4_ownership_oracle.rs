//! T10 (plan v5.1): `w4_ownership_oracle` -- proves each stored chunk in
//! `message_chunks` (active generation) genuinely "belongs" to the text it
//! claims to: its stored span really is what independent re-chunking of its
//! message's content produces, its stored embedding really is a faithful
//! embedding of that span's text, and its `vec0` mirror really is a
//! byte-identical copy of that same embedding.
//!
//! Division of labor (interface's own framing): this Rust binary only
//! fetches stored chunks (including their storage span) and re-embeds via
//! Infinity -- it never re-derives what a span *should* be. Span judgment
//! is entirely `ownership_oracle.py`'s job (this file's sibling, itself
//! built on `normalize_v2.py`'s independent chunking re-implementation),
//! fed one JSON line per sampled chunk over stdin and read back one JSON
//! verdict line per chunk over stdout (protocol documented in that script's
//! own module docstring).
//!
//! Three independent judgments per chunk:
//!   - span: stored `(byte_start, byte_end)` vs `ownership_oracle.py`'s
//!     independently recomputed span for that `chunk_idx` (a `ok: false`
//!     verdict -- e.g. the message's role isn't even in the whitelist --
//!     also counts as a span failure, since no valid stored span could
//!     possibly correspond to a chunk that shouldn't exist at all).
//!   - cosine: re-embed (via Infinity, using the *stored* span's text,
//!     sliced from `eligibility::normalized_for_chunks`) and compare
//!     against the stored `message_chunks.embedding` via cosine similarity
//!     -- must be `>= 0.999`.
//!   - vec0: `message_chunks.embedding` vs the `vec0` mirror's raw BLOB for
//!     the same `chunk_id` (`rowid`) -- must be byte-identical.
//!
//! Usage: `cargo run --release --no-default-features --features
//! qr,encryption,infinity --example w4_ownership_oracle -- --db <path>
//! (--full | --sample <N> --seed <S>) --infinity <url> --json <out>`. Exit
//! codes: 0 `span_failed == 0 && cosine_failed == 0 && vec0_mismatch == 0`;
//! 1 any of those is nonzero; 2 precondition error (db missing, no active
//! generation, zero chunks, Infinity unreachable, or the
//! `ownership_oracle.py` subprocess failed to start/speak its protocol).

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use clap::Parser;
use coding_agent_search::search::eligibility::normalized_for_chunks;
use coding_agent_search::storage::api::Value;
use coding_agent_search::storage::schema::le_blob_to_f32_vector;
use coding_agent_search::storage::sqlite::FrankenStorage;
use rand::SeedableRng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;
use serde::Serialize;

const OWNERSHIP_ORACLE_PY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/oracle/ownership_oracle.py");

#[derive(Parser, Debug)]
#[command(name = "w4_ownership_oracle")]
struct Cli {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    full: bool,
    #[arg(long)]
    sample: Option<usize>,
    #[arg(long)]
    seed: Option<u64>,
    #[arg(long)]
    infinity: String,
    #[arg(long)]
    json: PathBuf,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct OwnershipReport {
    checked: usize,
    span_failed: usize,
    cosine_failed: usize,
    vec0_mismatch: usize,
    min_cosine: Option<f32>,
    seed: Option<u64>,
}
impl OwnershipReport {
    fn passed(&self) -> bool {
        self.span_failed == 0 && self.cosine_failed == 0 && self.vec0_mismatch == 0
    }
}

/// `search::frankensearch_types::cosine_similarity` is `pub(crate)`
/// (`frankensearch_types` itself is a `pub(crate)` module) -- not worth a
/// `src/` visibility change for one diagnostic-tool caller, given this is a
/// two-line formula to replicate directly.
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 { 0.0 } else { dot / (norm_a * norm_b) }
}

struct StoredChunk {
    chunk_id: i64,
    message_id: i64,
    chunk_idx: i64,
    byte_start: i64,
    byte_end: i64,
    embedding: Vec<u8>,
}

fn active_generation(storage: &FrankenStorage) -> anyhow::Result<(i64, i64, String)> {
    let row: (i64, i64, String) = storage.raw().query_row_map(
        "SELECT id, dim, embedder_id FROM embedding_generations WHERE is_active = 1",
        &[],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
    )?;
    Ok(row)
}

fn fetch_stored_chunks(storage: &FrankenStorage, generation_id: i64) -> anyhow::Result<Vec<StoredChunk>> {
    let rows: Vec<StoredChunk> = storage.raw().query_all_map(
        "SELECT chunk_id, message_id, chunk_idx, byte_start, byte_end, embedding FROM message_chunks WHERE generation_id = ?1 ORDER BY chunk_id",
        &[Value::from(generation_id)],
        |row| {
            Ok(StoredChunk {
                chunk_id: row.get_typed(0)?,
                message_id: row.get_typed(1)?,
                chunk_idx: row.get_typed(2)?,
                byte_start: row.get_typed(3)?,
                byte_end: row.get_typed(4)?,
                embedding: row.get_typed(5)?,
            })
        },
    )?;
    Ok(rows)
}

/// Self-contained `POST /embeddings` call (deliberately not reusing
/// `search::infinity::http_embed`, which is a private `fn` in that module
/// -- adding `pub` there for a single diagnostic-tool caller was judged not
/// worth the `src/` surface-area increase; this is the same simple
/// OpenAI-compatible wire protocol that module's own doc comment
/// documents, ~20 lines to replicate directly).
fn http_embed_one(client: &reqwest::blocking::Client, base_url: &str, model: &str, text: &str) -> anyhow::Result<Vec<f32>> {
    #[derive(serde::Deserialize)]
    struct Item {
        embedding: Vec<f32>,
        index: usize,
    }
    #[derive(serde::Deserialize)]
    struct Resp {
        data: Vec<Item>,
    }
    let body = serde_json::json!({ "model": model, "input": [text] });
    let resp = client.post(format!("{base_url}/embeddings")).json(&body).send()?;
    anyhow::ensure!(resp.status().is_success(), "embeddings HTTP {}: {}", resp.status(), resp.text().unwrap_or_default());
    let parsed: Resp = resp.json()?;
    let item = parsed.data.into_iter().find(|i| i.index == 0).ok_or_else(|| anyhow::anyhow!("no index-0 item in embeddings response"))?;
    Ok(item.embedding)
}

#[derive(serde::Deserialize)]
struct OracleVerdict {
    correlation_id: Option<i64>,
    ok: bool,
    byte_start: Option<i64>,
    byte_end: Option<i64>,
}

fn run_ownership_oracle_py(requests: &[(i64, String, String, i64)]) -> anyhow::Result<std::collections::HashMap<i64, OracleVerdict>> {
    let mut child = Command::new("python3")
        .arg(OWNERSHIP_ORACLE_PY)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawning ownership_oracle.py: {e}"))?;

    {
        let stdin = child.stdin.as_mut().ok_or_else(|| anyhow::anyhow!("no stdin handle"))?;
        for (correlation_id, role, content, chunk_idx) in requests {
            let line = serde_json::json!({"correlation_id": correlation_id, "role": role, "content": content, "chunk_idx": chunk_idx});
            writeln!(stdin, "{line}")?;
        }
    }
    let output = child.wait_with_output()?;
    anyhow::ensure!(output.status.success(), "ownership_oracle.py exited non-zero (protocol error)");

    let reader = BufReader::new(output.stdout.as_slice());
    let mut out = std::collections::HashMap::with_capacity(requests.len());
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let verdict: OracleVerdict = serde_json::from_str(&line).map_err(|e| anyhow::anyhow!("parsing oracle verdict line {line:?}: {e}"))?;
        if let Some(id) = verdict.correlation_id {
            out.insert(id, verdict);
        }
    }
    Ok(out)
}

fn compute_report(
    storage: &FrankenStorage,
    generation_id: i64,
    dim: i64,
    embedder_id: &str,
    infinity_url: &str,
    chunks: &[StoredChunk],
    seed: Option<u64>,
) -> anyhow::Result<OwnershipReport> {
    let client = reqwest::blocking::Client::new();

    let mut requests = Vec::with_capacity(chunks.len());
    for c in chunks {
        let (role, content): (String, String) =
            storage.raw().query_row_map("SELECT role, content FROM messages WHERE id = ?1", &[Value::from(c.message_id)], |row| Ok((row.get_typed(0)?, row.get_typed(1)?)))?;
        requests.push((c.chunk_id, role, content, c.chunk_idx));
    }
    let verdicts = run_ownership_oracle_py(&requests)?;

    let mut span_failed = 0usize;
    let mut cosine_failed = 0usize;
    let mut vec0_mismatch = 0usize;
    let mut min_cosine: Option<f32> = None;

    let content_by_message: std::collections::HashMap<i64, String> = {
        let mut map = std::collections::HashMap::new();
        for (chunk_id, _role, content, _idx) in &requests {
            let stored = chunks.iter().find(|c| c.chunk_id == *chunk_id).unwrap();
            map.insert(stored.message_id, content.clone());
        }
        map
    };

    for c in chunks {
        let verdict = verdicts.get(&c.chunk_id);
        let span_ok = match verdict {
            Some(v) if v.ok => v.byte_start == Some(c.byte_start) && v.byte_end == Some(c.byte_end),
            _ => false,
        };
        if !span_ok {
            span_failed += 1;
        }

        // vec0 byte-identity check.
        let vec0_blob: Option<Vec<u8>> = storage
            .raw()
            .query_opt_map(&format!("SELECT embedding FROM vec_index_gen_{generation_id} WHERE rowid = ?1"), &[Value::from(c.chunk_id)], |row| row.get_typed(0))?;
        match vec0_blob {
            Some(blob) if blob == c.embedding => {}
            _ => vec0_mismatch += 1,
        }

        // Cosine re-embedding check: slice the STORED span out of the
        // message's normalized text (guarded against an out-of-bounds span
        // from a tampering injection -- an unsliceable span cannot be
        // re-embedded, so it's skipped here, but it was already counted
        // above via `span_failed` since no oracle verdict could match it).
        if let Some(content) = content_by_message.get(&c.message_id) {
            let normalized = normalized_for_chunks(content);
            let start = c.byte_start as usize;
            let end = c.byte_end as usize;
            if end <= normalized.len() && start <= end && normalized.is_char_boundary(start) && normalized.is_char_boundary(end) {
                let text = &normalized[start..end];
                match http_embed_one(&client, infinity_url, embedder_id, text) {
                    Ok(fresh) if fresh.len() == dim as usize => {
                        let stored_vec = le_blob_to_f32_vector(&c.embedding)?;
                        let cos = cosine_similarity(&stored_vec, &fresh);
                        min_cosine = Some(min_cosine.map_or(cos, |m: f32| m.min(cos)));
                        if cos < 0.999 {
                            cosine_failed += 1;
                        }
                    }
                    _ => cosine_failed += 1,
                }
            }
        }
    }

    Ok(OwnershipReport { checked: chunks.len(), span_failed, cosine_failed, vec0_mismatch, min_cosine, seed })
}

fn select_sample(mut chunks: Vec<StoredChunk>, sample: Option<usize>, seed: Option<u64>) -> Vec<StoredChunk> {
    match (sample, seed) {
        (Some(n), Some(s)) if n < chunks.len() => {
            let mut rng = ChaCha8Rng::seed_from_u64(s);
            chunks.shuffle(&mut rng);
            chunks.truncate(n);
            chunks.sort_by_key(|c| c.chunk_id);
            chunks
        }
        _ => chunks,
    }
}

fn run(db_path: &std::path::Path, full: bool, sample: Option<usize>, seed: Option<u64>, infinity_url: &str) -> (i32, Option<OwnershipReport>, String) {
    if !full && (sample.is_none() || seed.is_none()) {
        return (2, None, "precondition error: pass either --full or both --sample and --seed".to_string());
    }
    if !db_path.is_file() {
        return (2, None, format!("precondition error: db {} does not exist", db_path.display()));
    }
    let storage = match FrankenStorage::open_readonly(db_path) {
        Ok(s) => s,
        Err(e) => return (2, None, format!("precondition error opening db: {e:#}")),
    };
    let (generation_id, dim, embedder_id) = match active_generation(&storage) {
        Ok(v) => v,
        Err(e) => return (2, None, format!("precondition error: no active generation: {e:#}")),
    };
    let chunks = match fetch_stored_chunks(&storage, generation_id) {
        Ok(v) => v,
        Err(e) => return (2, None, format!("precondition error fetching message_chunks: {e:#}")),
    };
    if chunks.is_empty() {
        return (2, None, "precondition error: active generation has zero message_chunks rows".to_string());
    }
    let chunks = if full { chunks } else { select_sample(chunks, sample, seed) };

    match compute_report(&storage, generation_id, dim, &embedder_id, infinity_url, &chunks, seed) {
        Err(e) => (2, None, format!("precondition error: {e:#}")),
        Ok(report) => {
            let code = if report.passed() { 0 } else { 1 };
            let msg = format!(
                "ownership_oracle: checked={} span_failed={} cosine_failed={} vec0_mismatch={} min_cosine={:?} passed={}",
                report.checked,
                report.span_failed,
                report.cosine_failed,
                report.vec0_mismatch,
                report.min_cosine,
                report.passed()
            );
            (code, Some(report), msg)
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let (code, report, message) = run(&cli.db, cli.full, cli.sample, cli.seed, &cli.infinity);
    println!("{message}");
    if let Some(report) = &report {
        let json = serde_json::to_string_pretty(report).expect("OwnershipReport must serialize");
        std::fs::write(&cli.json, json).expect("writing --json output must succeed");
    }
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use coding_agent_search::storage::api::TxMode;
    use coding_agent_search::storage::schema;
    use coding_agent_search::storage::vector_domain;
    use tempfile::TempDir;

    fn insert_message_parent_chain(storage: &FrankenStorage, agent_id: i64, conversation_id: i64, message_id: i64, role: &str, content: &str) {
        let conn = storage.raw();
        conn.execute(
            "INSERT OR IGNORE INTO agents(id, slug, name, kind, created_at, updated_at) VALUES (?1, ?2, ?2, 'cli', 0, 0)",
            &[Value::from(agent_id), Value::from(format!("agent-{agent_id}"))],
        )
        .unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO conversations(id, agent_id, title, source_path) VALUES (?1, ?2, 't', ?3)",
            &[Value::from(conversation_id), Value::from(agent_id), Value::from(format!("/tmp/c-{conversation_id}.jsonl"))],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages(id, conversation_id, idx, role, content) VALUES (?1, ?2, ?1, ?3, ?4)",
            &[Value::from(message_id), Value::from(conversation_id), Value::from(role), Value::from(content)],
        )
        .unwrap();
    }

    /// One conversation, 3 messages each producing exactly 1 chunk (short
    /// content), a real active generation, correctly-derived message_chunks
    /// rows (span from `expected_chunks`, embedding = a fixed unit-ish
    /// vector distinct per message so a swap is detectable), and a
    /// byte-identical `vec0` mirror.
    fn seed_baseline(path: &std::path::Path) -> (i64, Vec<i64>) {
        let storage = FrankenStorage::open(path).unwrap();
        let contents = [
            (1i64, "user", "The quick brown fox jumps over the lazy dog in a normal sentence with enough length."),
            (2i64, "user", "A second distinct message about something else entirely, also long enough to chunk cleanly."),
            (3i64, "user", "A third distinct message, again long enough, discussing yet another unrelated topic here."),
        ];
        for (id, role, content) in &contents {
            insert_message_parent_chain(&storage, 1, 1, *id, role, content);
        }
        // A 4th message with NO message_chunks row of its own -- exists
        // purely so `batch_misalignment_swap_message_id_is_detected` can
        // reassign a real chunk's `message_id` to it without colliding with
        // `message_chunks`' `UNIQUE(generation_id, message_id, chunk_idx)`
        // constraint (every one of messages 1-3 already owns a chunk_idx=0
        // row, so reassigning between them would hit that constraint
        // instead of exercising the misalignment scenario at all).
        insert_message_parent_chain(&storage, 1, 1, 4, "user", "A fourth message that never gets its own chunk, used only as a misalignment target.");

        let generation_id = storage
            .raw()
            .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation_v5(tx, "bge-m3", 4, 1, 1, b"fp", 1_700_000_000_000))
            .unwrap();
        storage
            .raw()
            .execute("UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1", &[Value::from(generation_id)])
            .unwrap();

        let mut chunk_ids = Vec::new();
        storage
            .raw()
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                for (i, (message_id, role, content)) in contents.iter().enumerate() {
                    let chunks = coding_agent_search::search::eligibility::expected_chunks(*message_id, 1, role, content);
                    assert_eq!(chunks.len(), 1, "fixture messages must each produce exactly one chunk");
                    let chunk = &chunks[0];
                    // A distinct-per-message vector so a rowid/embedding swap
                    // between messages is detectable by cosine/vec0 checks.
                    let mut v = [0.0f32; 4];
                    v[i] = 1.0;
                    let embedding = schema::f32_vector_to_le_blob(&v);
                    tx.execute(
                        "INSERT INTO message_chunks(chunk_id, generation_id, message_id, conversation_id, chunk_idx, byte_start, byte_end, content_hash, embedding, norm, created_at) \
                         VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, 1.0, 1700000000000)",
                        &[
                            Value::from((i as i64) + 1),
                            Value::from(generation_id),
                            Value::from(*message_id),
                            Value::from(chunk.chunk_idx as i64),
                            Value::from(chunk.byte_start as i64),
                            Value::from(chunk.byte_end as i64),
                            Value::from(chunk.content_hash.clone()),
                            Value::from(embedding),
                        ],
                    )?;
                    chunk_ids.push((i as i64) + 1);
                }
                Ok(())
            })
            .unwrap();
        vector_domain::rebuild_vec0_table_for_generation_v5(storage.raw(), generation_id, 4).unwrap();

        (generation_id, chunk_ids)
    }

    fn fresh_baseline() -> (TempDir, std::path::PathBuf, i64, Vec<i64>) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent_search.db");
        let (generation_id, chunk_ids) = seed_baseline(&path);
        (dir, path, generation_id, chunk_ids)
    }

    /// A tiny local mock Infinity `/embeddings` server that always returns
    /// the SAME vector the caller's message index maps to under this
    /// fixture's convention (`[1,0,0,0]` for message 1's text, `[0,1,0,0]`
    /// for message 2's, `[0,0,1,0]` for message 3's) -- matched by simple
    /// substring sniffing of the request body against each message's known
    /// content, since this fixture's whole point is deterministic,
    /// injection-sensitive cosine checks, not exercising a real model.
    fn start_mock_infinity() -> (std::net::SocketAddr, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            while !stop2.load(std::sync::atomic::Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 65536];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let vec = if req.contains("quick brown fox") {
                            [1.0, 0.0, 0.0, 0.0]
                        } else if req.contains("second distinct message") {
                            [0.0, 1.0, 0.0, 0.0]
                        } else {
                            [0.0, 0.0, 1.0, 0.0]
                        };
                        let body = serde_json::json!({"data": [{"embedding": vec, "index": 0}]}).to_string();
                        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        (addr, stop)
    }

    #[test]
    fn baseline_passes_with_zero_findings() {
        let (_dir, path, _gen, _ids) = fresh_baseline();
        let (addr, stop) = start_mock_infinity();
        let (code, report, message) = run(&path, true, None, None, &format!("http://{addr}"));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(code, 0, "{message}");
        let report = report.unwrap();
        assert_eq!(report.checked, 3);
        assert_eq!(report.span_failed, 0);
        assert_eq!(report.cosine_failed, 0);
        assert_eq!(report.vec0_mismatch, 0);
        assert!(report.min_cosine.unwrap() > 0.999);
    }

    #[test]
    fn batch_misalignment_swap_message_id_is_detected() {
        let (_dir, path, gen_id, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        // Chunk 1's message_id now points at message 4's content (which has
        // no chunk of its own -- see seed_baseline's comment), but its
        // stored span/embedding still describe message 1's text.
        storage.raw().execute("UPDATE message_chunks SET message_id = 4 WHERE chunk_id = ?1 AND generation_id = ?2", &[Value::from(ids[0]), Value::from(gen_id)]).unwrap();
        drop(storage);
        let (addr, stop) = start_mock_infinity();
        let (code, report, message) = run(&path, true, None, None, &format!("http://{addr}"));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(code, 1, "{message}");
        assert!(report.unwrap().span_failed >= 1, "batch misalignment must trip span_failed (independent re-chunk of the wrong message can't match the stored span)");
    }

    #[test]
    fn rowid_swap_embeddings_is_detected() {
        let (_dir, path, gen_id, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                let e1: Vec<u8> = tx.query_row_map("SELECT embedding FROM message_chunks WHERE chunk_id = ?1", &[Value::from(ids[0])], |row| row.get_typed(0))?;
                let e2: Vec<u8> = tx.query_row_map("SELECT embedding FROM message_chunks WHERE chunk_id = ?1", &[Value::from(ids[1])], |row| row.get_typed(0))?;
                tx.execute("UPDATE message_chunks SET embedding = ?1 WHERE chunk_id = ?2", &[Value::from(e2), Value::from(ids[0])])?;
                tx.execute("UPDATE message_chunks SET embedding = ?1 WHERE chunk_id = ?2", &[Value::from(e1), Value::from(ids[1])])?;
                Ok(())
            })
            .unwrap();
        drop(storage);
        let _ = gen_id;
        let (addr, stop) = start_mock_infinity();
        let (code, report, message) = run(&path, true, None, None, &format!("http://{addr}"));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(code, 1, "{message}");
        assert!(report.unwrap().cosine_failed >= 2, "swapped embeddings must trip cosine_failed on both sides");
    }

    #[test]
    fn vec0_one_sided_corruption_is_detected() {
        let (_dir, path, gen_id, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        let bogus = schema::f32_vector_to_le_blob(&[9.0, 9.0, 9.0, 9.0]);
        storage.raw().execute(&format!("UPDATE vec_index_gen_{gen_id} SET embedding = ?1 WHERE rowid = ?2"), &[Value::from(bogus), Value::from(ids[0])]).unwrap();
        drop(storage);
        let (addr, stop) = start_mock_infinity();
        let (code, report, message) = run(&path, true, None, None, &format!("http://{addr}"));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(code, 1, "{message}");
        assert_eq!(report.unwrap().vec0_mismatch, 1);
    }

    #[test]
    fn span_tampering_is_detected() {
        let (_dir, path, gen_id, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        storage.raw().execute("UPDATE message_chunks SET byte_start = byte_start + 3 WHERE chunk_id = ?1 AND generation_id = ?2", &[Value::from(ids[0]), Value::from(gen_id)]).unwrap();
        drop(storage);
        let (addr, stop) = start_mock_infinity();
        let (code, report, message) = run(&path, true, None, None, &format!("http://{addr}"));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(code, 1, "{message}");
        assert!(report.unwrap().span_failed >= 1);
    }

    #[test]
    fn missing_full_or_sample_seed_is_precondition_error_exit_2() {
        let (_dir, path, _gen, _ids) = fresh_baseline();
        let (code, report, message) = run(&path, false, None, None, "http://127.0.0.1:1");
        assert_eq!(code, 2, "{message}");
        assert!(report.is_none());
    }

    #[test]
    fn missing_db_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.db");
        let (code, report, message) = run(&path, true, None, None, "http://127.0.0.1:1");
        assert_eq!(code, 2, "{message}");
        assert!(report.is_none());
    }
}
