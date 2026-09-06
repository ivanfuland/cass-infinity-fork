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
//! T11.8: this file was rewritten end-to-end to fix four harness defects a
//! real 105-minute `--full` deadlock against a ~2M-chunk generation exposed
//! (`W4_ARTIFACTS/t12-step5-ownership-deadlock.md`; `src/` untouched, none
//! of these are candidate-binary bugs):
//!   1. **Pipe deadlock** -- the old code wrote every request line into
//!      `ownership_oracle.py`'s stdin, then called `wait_with_output()` to
//!      read stdout back, all in one shot. Once the verdict output grew
//!      past the OS pipe's buffer, python (which prints+flushes every
//!      line as it goes) blocked writing to a full stdout pipe with
//!      nothing reading it yet, and this process blocked writing to
//!      python's stdin with python not yet back at the top of its read
//!      loop -- a classic two-way pipe deadlock. Fixed by spawning the
//!      subprocess exactly once for the whole run and giving it a
//!      dedicated reader thread that drains stdout continuously from the
//!      moment it's spawned, decoupled from whenever the main thread gets
//!      around to writing the next request.
//!   2. **O(N^2) content lookup** -- `content_by_message` used to rebuild
//!      itself with a linear `chunks.iter().find(...)` per chunk. Fixed by
//!      a small rolling one-message cache (this file's version of T8's
//!      "load each message at most once" contract), not a
//!      materialized-then-searched map.
//!   3. **Full materialization** -- the old code pulled every
//!      `message_chunks` row (with its 4 KiB embedding) up front, and
//!      copied its entire message's content into a `requests` entry once
//!      per chunk (a message with 1,000 chunks meant 1,000 copies of the
//!      same content) -- ~37 GB RSS against a real ~2M-chunk generation.
//!      Fixed by keyset-paginating `message_chunks` (`--full`) or
//!      filtering a page-at-a-time scan by a pre-selected sample id set
//!      (`--sample`), so peak memory is one page's rows plus one cached
//!      message, never the whole corpus.
//!   4. **Serial per-chunk embedding** -- the old code issued one
//!      `/embeddings` POST per chunk. Fixed by batching up to
//!      [`EMBED_BATCH`] texts per request, response items aligned strictly
//!      by their own `index` field (never by response-array position).
//!
//! Usage: `cargo run --release --no-default-features --features
//! qr,encryption,infinity --example w4_ownership_oracle -- --db <path>
//! (--full | --sample <N> --seed <S>) --infinity <url> --json <out>`. Exit
//! codes: 0 `span_failed == 0 && cosine_failed == 0 && vec0_mismatch == 0`;
//! 1 any of those is nonzero; 2 precondition error (db missing, no active
//! generation, zero chunks, Infinity unreachable, or the
//! `ownership_oracle.py` subprocess failed to start/speak its protocol, or
//! stalled/exited before finishing this run's verdicts).

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
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

/// Keyset-pagination page size for `--full`'s `message_chunks` scan (and,
/// for `--sample`, the scan page it filters down to the pre-selected id
/// set) -- also the row cap for each page's single `vec0` `IN (...)`
/// lookup. Chosen so a page's peak memory (one page of rows + one page's
/// worth of verdicts + one page's `vec0` blobs) stays a firmly bounded
/// fraction of the corpus regardless of its total size.
const PAGE_ROWS: usize = 1024;
/// Batch cap for a single Infinity `/embeddings` POST.
const EMBED_BATCH: usize = 128;
/// How long the main thread waits on the reader thread's channel for one
/// more verdict before declaring `ownership_oracle.py` stalled. Generous
/// enough that legitimate per-line latency never trips it, but finite --
/// the main thread must never wait on this channel forever (see this
/// file's module doc comment for the deadlock the old design could hit).
const VERDICT_RECV_TIMEOUT: Duration = Duration::from_secs(120);

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
    /// Debug-only (T11.8 investigation): dump up to [`DUMP_FAILURES_CAP`]
    /// span/cosine/vec0 failure records (chunk_id, message_id, chunk_idx,
    /// stored span, independent oracle span/error, cosine) as a JSON
    /// array to this path.
    #[arg(long)]
    dump_failures: Option<PathBuf>,
    /// Debug-only (T11.8 investigation), `--full` only: stop after this
    /// many pages and report with `partial: true` -- for timing a small,
    /// representative slice of a real `--full` run without waiting for
    /// the whole corpus, so its per-page cost can be extrapolated over
    /// the corpus's real total page count instead of guessed from
    /// `--sample` (whose full-table-scan-then-filter design pays the same
    /// per-page cost for far less per-page useful work; see this file's
    /// `--sample`/`select_sample_ids` doc comments).
    #[arg(long)]
    max_pages: Option<usize>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct OwnershipReport {
    checked: usize,
    span_failed: usize,
    cosine_failed: usize,
    vec0_mismatch: usize,
    min_cosine: Option<f32>,
    seed: Option<u64>,
    batches: usize,
    /// Distinct `message_id`s touching at least one `span_failed` chunk --
    /// the only sound way to compare this file's per-CHUNK `--sample`
    /// rate against `chunk_oracle.py`'s per-MESSAGE stratified-sample
    /// rate (T11.8 investigation, 2026-09-05): a span divergence at one
    /// chunk of a long message shifts every later chunk's span too, so
    /// per-chunk sampling counts one divergent message many times over
    /// while chunk_oracle counts it once.
    span_failed_messages: usize,
    /// Same idea as `span_failed_messages`, for `cosine_failed`.
    cosine_failed_messages: usize,
    /// Set when `--max-pages` cut the run short (debug-only timing
    /// probe) -- `false` for every real `--full`/`--sample` run.
    partial: bool,
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

fn generation_has_any_chunks(storage: &FrankenStorage, generation_id: i64) -> anyhow::Result<bool> {
    let row: Option<i64> =
        storage.raw().query_opt_map("SELECT 1 FROM message_chunks WHERE generation_id = ?1 LIMIT 1", &[Value::from(generation_id)], |row| row.get_typed(0))?;
    Ok(row.is_some())
}

fn fetch_chunk_page(storage: &FrankenStorage, generation_id: i64, after_chunk_id: i64, limit: usize) -> anyhow::Result<Vec<StoredChunk>> {
    let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
    let rows = storage.raw().query_all_map(
        "SELECT chunk_id, message_id, chunk_idx, byte_start, byte_end, embedding FROM message_chunks \
         WHERE generation_id = ?1 AND chunk_id > ?2 ORDER BY chunk_id LIMIT ?3",
        &[Value::from(generation_id), Value::from(after_chunk_id), Value::from(limit_i64)],
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

fn all_chunk_ids(storage: &FrankenStorage, generation_id: i64) -> anyhow::Result<Vec<i64>> {
    let ids =
        storage.raw().query_all_map("SELECT chunk_id FROM message_chunks WHERE generation_id = ?1 ORDER BY chunk_id", &[Value::from(generation_id)], |row| row.get_typed(0))?;
    Ok(ids)
}

/// Byte-for-byte the same seeded shuffle-then-truncate selection the
/// pre-rewrite `select_sample` used, just operating on the ordered
/// `chunk_id` list alone (membership is all that's needed now -- row
/// fetch happens by scanning pages and filtering against this set, not by
/// holding every row in memory at once). See
/// `sample_id_selection_matches_legacy_algorithm` for the regression test
/// proving a given seed still selects the same id set as before.
fn select_sample_ids(mut ids: Vec<i64>, sample: usize, seed: u64) -> HashSet<i64> {
    if sample >= ids.len() {
        return ids.into_iter().collect();
    }
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    ids.shuffle(&mut rng);
    ids.truncate(sample);
    ids.into_iter().collect()
}

fn in_clause_placeholders(n: usize) -> String {
    vec!["?"; n].join(",")
}

/// Batch `vec0` lookup for exactly one page's `chunk_id`s (never more than
/// [`PAGE_ROWS`] at a time, so this is always a single bounded `IN (...)`
/// statement, not something that needs its own internal batching loop).
fn fetch_vec0_batch(storage: &FrankenStorage, generation_id: i64, chunk_ids: &[i64]) -> anyhow::Result<HashMap<i64, Vec<u8>>> {
    if chunk_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = in_clause_placeholders(chunk_ids.len());
    let sql = format!("SELECT rowid, embedding FROM vec_index_gen_{generation_id} WHERE rowid IN ({placeholders})");
    let params: Vec<Value> = chunk_ids.iter().map(|id| Value::from(*id)).collect();
    let rows: Vec<(i64, Vec<u8>)> = storage.raw().query_all_map(&sql, &params, |row| Ok((row.get_typed(0)?, row.get_typed(1)?)))?;
    Ok(rows.into_iter().collect())
}

#[derive(serde::Deserialize, Clone)]
struct OracleVerdict {
    correlation_id: Option<i64>,
    ok: bool,
    byte_start: Option<i64>,
    byte_end: Option<i64>,
    /// Only present on an `ok: false` verdict (`non_whitelist_role` /
    /// `canonicalize_empty` / `chunk_idx_out_of_range` -- see
    /// `ownership_oracle.py`'s module docstring). Absent on `ok: true`,
    /// hence `#[serde(default)]`.
    #[serde(default)]
    error: Option<String>,
}

/// Row cap for `--dump-failures`'s JSON array, applied per failure
/// category (T11.8 investigation aid, not part of the ownership
/// protocol) -- span/cosine/vec0 each get their own 200 slots so one
/// category filling up first (in practice, span failures vastly
/// outnumber cosine/vec0 ones) never crowds the others out.
const DUMP_FAILURES_CAP: usize = 200;

/// `--dump-failures`' accumulated state: the records themselves, keyed by
/// `chunk_id` (a chunk failing more than one check gets one row with all
/// the relevant flags set), plus one dumped-count per category so each
/// category's [`DUMP_FAILURES_CAP`] is enforced independently.
#[derive(Default)]
struct DumpTracker {
    records: HashMap<i64, FailureRecord>,
    span_dumped: usize,
    cosine_dumped: usize,
    vec0_dumped: usize,
}

/// One `--dump-failures` row: a chunk that tripped span, cosine, and/or
/// `vec0` -- carries both this file's stored view and `ownership_oracle
/// .py`'s independently recomputed verdict for the same chunk, side by
/// side, so a divergence is diagnosable without re-running anything.
#[derive(Serialize)]
struct FailureRecord {
    chunk_id: i64,
    message_id: i64,
    chunk_idx: i64,
    stored_byte_start: i64,
    stored_byte_end: i64,
    oracle_ok: Option<bool>,
    oracle_byte_start: Option<i64>,
    oracle_byte_end: Option<i64>,
    oracle_error: Option<String>,
    cosine: Option<f32>,
    span_failed: bool,
    cosine_failed: bool,
    vec0_mismatch: bool,
}

/// The persistent `ownership_oracle.py` subprocess for one `run()` call:
/// spawned exactly once, with a dedicated thread continuously draining its
/// stdout into `rx` from the moment it's spawned -- this decoupling (not
/// batch size) is what makes the pipe deadlock this file's module doc
/// comment describes structurally impossible, regardless of how much
/// verdict output accumulates.
struct OracleClient {
    child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<OracleVerdict>,
    reader_handle: std::thread::JoinHandle<()>,
}

fn spawn_oracle_client() -> anyhow::Result<OracleClient> {
    let mut child = Command::new("python3")
        .arg(OWNERSHIP_ORACLE_PY)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawning ownership_oracle.py: {e}"))?;
    let stdin = child.stdin.take().ok_or_else(|| anyhow::anyhow!("no stdin handle"))?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow::anyhow!("no stdout handle"))?;

    let (tx, rx) = mpsc::channel::<OracleVerdict>();
    let reader_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for raw in reader.lines() {
            let Ok(raw) = raw else { break };
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            // A malformed/protocol-error line from ownership_oracle.py's
            // own error path has no `correlation_id` and fails to parse
            // into `OracleVerdict` -- dropped here rather than counted;
            // the main loop's per-page verdict count simply comes up
            // short and times out/bails, which is the correct signal for
            // a protocol violation (not a normal per-record verdict).
            if let Ok(v) = serde_json::from_str::<OracleVerdict>(trimmed)
                && tx.send(v).is_err()
            {
                break; // receiver gone (run already erroring out) -- stop draining.
            }
        }
        // `tx` drops here on scope exit, disconnecting the channel -- the
        // main thread's next `recv_timeout` sees `Disconnected` instead of
        // ever waiting on a channel nothing will ever send on again.
    });
    Ok(OracleClient { child, stdin, rx, reader_handle })
}

/// Self-contained batched `POST /embeddings` call (deliberately not
/// reusing `search::infinity::http_embed`, which is a private `fn` in
/// that module -- adding `pub` there for a single diagnostic-tool caller
/// was judged not worth the `src/` surface-area increase; this is the
/// same simple OpenAI-compatible wire protocol that module's own doc
/// comment documents). Returns embeddings keyed by each response item's
/// own `index` field -- callers must never assume response-array
/// position matches request order (Infinity is free to reorder; this
/// file's `start_mock_infinity` test helper deliberately does, to prove
/// real alignment logic can't get away with assuming otherwise).
fn http_embed_batch(client: &reqwest::blocking::Client, base_url: &str, model: &str, texts: &[&str]) -> anyhow::Result<HashMap<usize, Vec<f32>>> {
    #[derive(serde::Deserialize)]
    struct Item {
        embedding: Vec<f32>,
        index: usize,
    }
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        data: Vec<Item>,
    }
    if texts.is_empty() {
        return Ok(HashMap::new());
    }
    let body = serde_json::json!({ "model": model, "input": texts });
    let resp = client.post(format!("{base_url}/embeddings")).json(&body).send()?;
    anyhow::ensure!(resp.status().is_success(), "embeddings HTTP {}: {}", resp.status(), resp.text().unwrap_or_default());
    let parsed: Resp = resp.json().unwrap_or(Resp { data: Vec::new() });
    let mut out = HashMap::with_capacity(parsed.data.len());
    for item in parsed.data {
        if item.index < texts.len() {
            out.insert(item.index, item.embedding);
        }
    }
    Ok(out)
}

fn emit_ownership_event(event: &serde_json::Value) {
    eprintln!("{event}");
}

/// One chunk queued for re-embedding -- carries enough of its own
/// identity (beyond just the sliced text) that a pure cosine failure
/// (span and `vec0` both fine) can still produce a full `--dump-failures`
/// row without a second DB round-trip.
struct PendingEmbed {
    chunk_id: i64,
    message_id: i64,
    chunk_idx: i64,
    stored_byte_start: i64,
    stored_byte_end: i64,
    stored_embedding: Vec<u8>,
    text: String,
}

/// Embed+compare whatever's accumulated in `pending` (up to [`EMBED_BATCH`]
/// items), then clear it. A whole-batch HTTP failure marks every pending
/// chunk `cosine_failed` (logged once) rather than aborting the run --
/// same per-item-failure semantics the old single-embed-call code had,
/// just batched. `cosine_failed_message_ids` always accumulates (report
/// field, not debug-only); `dump` (only `Some` under `--dump-failures`)
/// additionally records up to `DumpTracker::cosine_dumped` rows purely
/// for a cosine failure, and attaches the actual cosine value to any row
/// a span/vec0 failure already created for this chunk.
fn flush_embed_pending(
    client: &reqwest::blocking::Client,
    infinity_url: &str,
    embedder_id: &str,
    dim: i64,
    pending: &mut Vec<PendingEmbed>,
    verdicts: &HashMap<i64, OracleVerdict>,
    cosine_failed: &mut usize,
    cosine_failed_message_ids: &mut HashSet<i64>,
    min_cosine: &mut Option<f32>,
    mut dump: Option<&mut DumpTracker>,
) -> anyhow::Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let texts: Vec<&str> = pending.iter().map(|p| p.text.as_str()).collect();
    let by_index = match http_embed_batch(client, infinity_url, embedder_id, &texts) {
        Ok(m) => m,
        Err(e) => {
            emit_ownership_event(&serde_json::json!({"event": "ownership_embed_batch_failed", "error": e.to_string(), "batch_len": pending.len()}));
            HashMap::new()
        }
    };
    for (i, item) in pending.iter().enumerate() {
        let fresh = by_index.get(&i).filter(|v| v.len() == dim as usize && v.iter().all(|x| x.is_finite()));
        let cos = match fresh {
            Some(fresh) => {
                let stored_vec = le_blob_to_f32_vector(&item.stored_embedding)?;
                Some(cosine_similarity(&stored_vec, fresh))
            }
            None => None,
        };
        let item_failed = match cos {
            Some(c) => {
                *min_cosine = Some(min_cosine.map_or(c, |m: f32| m.min(c)));
                c < 0.999
            }
            None => true,
        };
        if item_failed {
            *cosine_failed += 1;
            cosine_failed_message_ids.insert(item.message_id);
        }

        if let Some(dump) = dump.as_deref_mut() {
            if let Some(existing) = dump.records.get_mut(&item.chunk_id) {
                existing.cosine = cos;
                if item_failed && !existing.cosine_failed {
                    existing.cosine_failed = true;
                    dump.cosine_dumped += 1;
                }
            } else if item_failed && dump.cosine_dumped < DUMP_FAILURES_CAP {
                let v = verdicts.get(&item.chunk_id);
                dump.records.insert(
                    item.chunk_id,
                    FailureRecord {
                        chunk_id: item.chunk_id,
                        message_id: item.message_id,
                        chunk_idx: item.chunk_idx,
                        stored_byte_start: item.stored_byte_start,
                        stored_byte_end: item.stored_byte_end,
                        oracle_ok: v.map(|vv| vv.ok),
                        oracle_byte_start: v.and_then(|vv| vv.byte_start),
                        oracle_byte_end: v.and_then(|vv| vv.byte_end),
                        oracle_error: v.and_then(|vv| vv.error.clone()),
                        cosine: cos,
                        span_failed: false,
                        cosine_failed: true,
                        vec0_mismatch: false,
                    },
                );
                dump.cosine_dumped += 1;
            }
        }
    }
    pending.clear();
    Ok(())
}

fn compute_report(
    storage: &FrankenStorage,
    generation_id: i64,
    dim: i64,
    embedder_id: &str,
    infinity_url: &str,
    sample_ids: Option<&HashSet<i64>>,
    seed: Option<u64>,
    dump_failures_path: Option<&Path>,
    max_pages: Option<usize>,
) -> anyhow::Result<OwnershipReport> {
    let client = reqwest::blocking::Client::new();
    let mut oracle = spawn_oracle_client()?;

    let mut checked = 0usize;
    let mut span_failed = 0usize;
    let mut cosine_failed = 0usize;
    let mut vec0_mismatch = 0usize;
    let mut min_cosine: Option<f32> = None;
    let mut batches = 0usize;
    let mut partial = false;
    let mut span_failed_message_ids: HashSet<i64> = HashSet::new();
    let mut cosine_failed_message_ids: HashSet<i64> = HashSet::new();
    let mut dump: Option<DumpTracker> = dump_failures_path.map(|_| DumpTracker::default());

    let mut after_chunk_id = 0i64;
    let run_started = Instant::now();

    loop {
        let mut page = fetch_chunk_page(storage, generation_id, after_chunk_id, PAGE_ROWS)?;
        if page.is_empty() {
            break;
        }
        after_chunk_id = page.last().expect("just checked non-empty").chunk_id;
        if let Some(ids) = sample_ids {
            page.retain(|c| ids.contains(&c.chunk_id));
        }
        if page.is_empty() {
            continue;
        }
        batches += 1;

        // Pass A: write this page's requests, one per chunk, caching the
        // current message's (role, content) across consecutive chunks
        // that share a `message_id` (this file's version of T8's "load
        // each message at most once" contract) -- reads each distinct
        // message at most once per page here.
        let mut write_cache: Option<(i64, String, String)> = None; // (message_id, role, content)
        for c in &page {
            if write_cache.as_ref().map(|(mid, ..)| *mid) != Some(c.message_id) {
                let (role, content): (String, String) =
                    storage.raw().query_row_map("SELECT role, content FROM messages WHERE id = ?1", &[Value::from(c.message_id)], |row| Ok((row.get_typed(0)?, row.get_typed(1)?)))?;
                write_cache = Some((c.message_id, role, content));
            }
            let (_, role, content) = write_cache.as_ref().expect("just set above");
            let line = serde_json::json!({"correlation_id": c.chunk_id, "role": role, "content": content, "chunk_idx": c.chunk_idx});
            writeln!(oracle.stdin, "{line}").context("writing a request line to ownership_oracle.py's stdin")?;
        }
        oracle.stdin.flush().context("flushing ownership_oracle.py's stdin")?;

        // Collect exactly this page's verdicts off the always-draining
        // reader thread. Timeout and channel-disconnect both fail loud
        // (precondition error) instead of ever blocking the main thread
        // forever -- see this file's module doc comment for the deadlock
        // the old "write everything, then read everything" design could
        // hit instead.
        let mut verdicts: HashMap<i64, OracleVerdict> = HashMap::with_capacity(page.len());
        while verdicts.len() < page.len() {
            match oracle.rx.recv_timeout(VERDICT_RECV_TIMEOUT) {
                Ok(v) => {
                    if let Some(id) = v.correlation_id {
                        verdicts.insert(id, v);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let _ = oracle.child.kill();
                    anyhow::bail!(
                        "ownership_oracle.py stalled: got {}/{} verdicts for the page ending at chunk_id {after_chunk_id} (no output line in {VERDICT_RECV_TIMEOUT:?})",
                        verdicts.len(),
                        page.len()
                    );
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let exit = oracle.child.try_wait().ok().flatten();
                    let _ = oracle.child.kill();
                    anyhow::bail!(
                        "ownership_oracle.py ended early: got {}/{} verdicts for the page ending at chunk_id {after_chunk_id} (subprocess exit status: {exit:?})",
                        verdicts.len(),
                        page.len()
                    );
                }
            }
        }

        // vec0 batch fetch for exactly this page's chunk_ids.
        let chunk_ids: Vec<i64> = page.iter().map(|c| c.chunk_id).collect();
        let vec0_by_id = fetch_vec0_batch(storage, generation_id, &chunk_ids)?;

        // Pass B: span + vec0 verdicts, and batched re-embedding
        // (`pending_embed` flushed every `EMBED_BATCH` chunks, and once
        // more at page end). A second, separate rolling message cache --
        // re-reads a message's content at most once more per page than
        // pass A did, but never clones a shared message's content per
        // chunk, which is exactly the full-materialization blow-up this
        // rewrite fixes.
        let mut check_cache: Option<(i64, String)> = None; // (message_id, normalized)
        let mut pending_embed: Vec<PendingEmbed> = Vec::with_capacity(EMBED_BATCH);
        for c in &page {
            checked += 1;
            let verdict = verdicts.get(&c.chunk_id);
            let span_ok = matches!(verdict, Some(v) if v.ok && v.byte_start == Some(c.byte_start) && v.byte_end == Some(c.byte_end));
            if !span_ok {
                span_failed += 1;
            }

            if !span_ok {
                span_failed_message_ids.insert(c.message_id);
            }

            let vec0_ok = matches!(vec0_by_id.get(&c.chunk_id), Some(blob) if *blob == c.embedding);
            if !vec0_ok {
                vec0_mismatch += 1;
            }

            if let Some(dump) = dump.as_mut() {
                let want_span = !span_ok && dump.span_dumped < DUMP_FAILURES_CAP;
                let want_vec0 = !vec0_ok && dump.vec0_dumped < DUMP_FAILURES_CAP;
                if want_span || want_vec0 {
                    let entry = dump.records.entry(c.chunk_id).or_insert_with(|| FailureRecord {
                        chunk_id: c.chunk_id,
                        message_id: c.message_id,
                        chunk_idx: c.chunk_idx,
                        stored_byte_start: c.byte_start,
                        stored_byte_end: c.byte_end,
                        oracle_ok: verdict.map(|v| v.ok),
                        oracle_byte_start: verdict.and_then(|v| v.byte_start),
                        oracle_byte_end: verdict.and_then(|v| v.byte_end),
                        oracle_error: verdict.and_then(|v| v.error.clone()),
                        cosine: None,
                        span_failed: false,
                        cosine_failed: false,
                        vec0_mismatch: false,
                    });
                    if want_span {
                        entry.span_failed = true;
                        dump.span_dumped += 1;
                    }
                    if want_vec0 {
                        entry.vec0_mismatch = true;
                        dump.vec0_dumped += 1;
                    }
                }
            }

            if check_cache.as_ref().map(|(mid, _)| *mid) != Some(c.message_id) {
                let content: String = storage.raw().query_row_map("SELECT content FROM messages WHERE id = ?1", &[Value::from(c.message_id)], |row| row.get_typed(0))?;
                check_cache = Some((c.message_id, normalized_for_chunks(&content)));
            }
            let (_, normalized) = check_cache.as_ref().expect("just set above");

            // An unsliceable span (out-of-bounds after a tampering
            // injection) cannot be re-embedded, so it's skipped here --
            // it was already counted above via `span_failed` since no
            // oracle verdict could match it either.
            let start = c.byte_start as usize;
            let end = c.byte_end as usize;
            if end <= normalized.len() && start <= end && normalized.is_char_boundary(start) && normalized.is_char_boundary(end) {
                pending_embed.push(PendingEmbed {
                    chunk_id: c.chunk_id,
                    message_id: c.message_id,
                    chunk_idx: c.chunk_idx,
                    stored_byte_start: c.byte_start,
                    stored_byte_end: c.byte_end,
                    stored_embedding: c.embedding.clone(),
                    text: normalized[start..end].to_string(),
                });
                if pending_embed.len() >= EMBED_BATCH {
                    flush_embed_pending(&client, infinity_url, embedder_id, dim, &mut pending_embed, &verdicts, &mut cosine_failed, &mut cosine_failed_message_ids, &mut min_cosine, dump.as_mut())?;
                }
            }
        }
        flush_embed_pending(&client, infinity_url, embedder_id, dim, &mut pending_embed, &verdicts, &mut cosine_failed, &mut cosine_failed_message_ids, &mut min_cosine, dump.as_mut())?;

        if batches % 100 == 0 {
            emit_ownership_event(&serde_json::json!({"event": "ownership_progress", "checked": checked, "batches": batches, "elapsed_ms": run_started.elapsed().as_millis() as u64}));
        }

        if let Some(max) = max_pages
            && batches >= max
        {
            partial = true;
            break;
        }
    }

    // Close stdin so ownership_oracle.py's `for raw_line in sys.stdin`
    // loop sees EOF and exits; only then is its overall exit code
    // meaningful (mirrors the old code's one-shot `wait_with_output`
    // check, just moved to the end of a now-streaming run).
    drop(oracle.stdin);
    let status = oracle.child.wait().context("waiting for ownership_oracle.py to exit")?;
    let _ = oracle.reader_handle.join();
    anyhow::ensure!(status.success(), "ownership_oracle.py exited non-zero (protocol error): {status:?}");

    emit_ownership_event(&serde_json::json!({"event": "ownership_done", "checked": checked, "batches": batches, "elapsed_ms": run_started.elapsed().as_millis() as u64}));

    if let (Some(path), Some(dump)) = (dump_failures_path, dump.as_ref()) {
        let mut records: Vec<&FailureRecord> = dump.records.values().collect();
        records.sort_by_key(|r| r.chunk_id);
        let json = serde_json::to_string_pretty(&records).expect("Vec<FailureRecord> must serialize");
        std::fs::write(path, json).with_context(|| format!("writing --dump-failures output to {}", path.display()))?;
    }

    Ok(OwnershipReport {
        checked,
        span_failed,
        cosine_failed,
        vec0_mismatch,
        min_cosine,
        seed,
        batches,
        partial,
        span_failed_messages: span_failed_message_ids.len(),
        cosine_failed_messages: cosine_failed_message_ids.len(),
    })
}

fn run(
    db_path: &Path,
    full: bool,
    sample: Option<usize>,
    seed: Option<u64>,
    infinity_url: &str,
    dump_failures_path: Option<&Path>,
    max_pages: Option<usize>,
) -> (i32, Option<OwnershipReport>, String) {
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
    match generation_has_any_chunks(&storage, generation_id) {
        Ok(true) => {}
        Ok(false) => return (2, None, "precondition error: active generation has zero message_chunks rows".to_string()),
        Err(e) => return (2, None, format!("precondition error checking message_chunks: {e:#}")),
    }

    let sample_ids: Option<HashSet<i64>> = if full {
        None
    } else {
        let n = sample.expect("checked above");
        let s = seed.expect("checked above");
        match all_chunk_ids(&storage, generation_id) {
            Ok(ids) => Some(select_sample_ids(ids, n, s)),
            Err(e) => return (2, None, format!("precondition error listing chunk_ids for sampling: {e:#}")),
        }
    };

    match compute_report(&storage, generation_id, dim, &embedder_id, infinity_url, sample_ids.as_ref(), seed, dump_failures_path, max_pages) {
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
    let (code, report, message) = run(&cli.db, cli.full, cli.sample, cli.seed, &cli.infinity, cli.dump_failures.as_deref(), cli.max_pages);
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
            .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", 4, 1, 1, b"fp", 1_700_000_000_000))
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
        vector_domain::rebuild_vec0_table_for_generation(storage.raw(), generation_id, 4).unwrap();

        (generation_id, chunk_ids)
    }

    fn fresh_baseline() -> (TempDir, std::path::PathBuf, i64, Vec<i64>) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent_search.db");
        let (generation_id, chunk_ids) = seed_baseline(&path);
        (dir, path, generation_id, chunk_ids)
    }

    /// Content with zero markdown/whitespace punctuation (so
    /// `canonicalize_for_embedding` passes it through byte-for-byte and
    /// the chunk count this function's caller computes from
    /// `expected_chunks` matches what actually gets stored) -- same
    /// construction `db_vector_catchup`'s own tests use for oversized
    /// fixtures.
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

    /// One conversation, one ~5 MB message -- chunks into several thousand
    /// `message_chunks` rows, which `full_run_does_not_deadlock_on_large_
    /// oracle_output` needs so `ownership_oracle.py`'s combined stdout for
    /// a single `--full` run exceeds a pipe's OS buffer (a handful of
    /// short messages, as `seed_baseline` builds, never would). Every row
    /// gets the same placeholder embedding, matched by `start_mock_
    /// infinity`'s fallback branch -- this fixture is for proving
    /// liveness (the run finishes, and does so correctly), not for
    /// exercising span/cosine/vec0 tampering, which the five tests built
    /// on `fresh_baseline` above already cover.
    fn seed_large_single_message(path: &std::path::Path) -> (i64, usize) {
        let storage = FrankenStorage::open(path).unwrap();
        let message_id = 1i64;
        let content = long_unique_filler(5_000_000);
        insert_message_parent_chain(&storage, 1, 1, message_id, "user", &content);

        let generation_id = storage
            .raw()
            .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", 4, 1, 1, b"fp", 1_700_000_000_000))
            .unwrap();
        storage
            .raw()
            .execute("UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1", &[Value::from(generation_id)])
            .unwrap();

        let expected = coding_agent_search::search::eligibility::expected_chunks(message_id, 1, "user", &content);
        assert!(expected.len() >= 5_000, "fixture must produce >= 5,000 chunks to exceed a pipe's OS buffer with ownership_oracle.py's verdict output; got {}", expected.len());
        let embedding = schema::f32_vector_to_le_blob(&[0.0, 0.0, 1.0, 0.0]);
        storage
            .raw()
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                for chunk in &expected {
                    tx.execute(
                        "INSERT INTO message_chunks(chunk_id, generation_id, message_id, conversation_id, chunk_idx, byte_start, byte_end, content_hash, embedding, norm, created_at) \
                         VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, 1.0, 1700000000000)",
                        &[
                            Value::from((chunk.chunk_idx as i64) + 1),
                            Value::from(generation_id),
                            Value::from(message_id),
                            Value::from(chunk.chunk_idx as i64),
                            Value::from(chunk.byte_start as i64),
                            Value::from(chunk.byte_end as i64),
                            Value::from(chunk.content_hash.clone()),
                            Value::from(embedding.clone()),
                        ],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        vector_domain::rebuild_vec0_table_for_generation(storage.raw(), generation_id, 4).unwrap();

        (generation_id, expected.len())
    }

    /// A tiny local mock Infinity `/embeddings` server. Parses the
    /// request's own `input` array (rather than sniffing the whole
    /// request body for a single known substring, which breaks once
    /// batched embedding puts several texts in one POST) and replies with
    /// each text's known fixture vector tagged by its own `index` -- and,
    /// to prove the real client aligns strictly by that `index` field
    /// rather than by response-array position, always emits the items in
    /// REVERSED order. Falls back to a fixed vector for any text matching
    /// neither known message (used by the large-single-message fixture,
    /// where correctness of the match isn't the point).
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
                        // A single `read()` isn't guaranteed to return a
                        // whole request in one call -- a full 128-text
                        // embed batch can be well over 100 KB, arriving
                        // across several TCP reads. Loop until the
                        // headers' own `Content-Length` says the body is
                        // fully in hand (a mock-only concern: `full_run_
                        // does_not_deadlock_on_large_oracle_output`'s
                        // first run against this without this loop
                        // silently truncated every full-size batch,
                        // reporting spurious `cosine_failed` for none of
                        // this file's own reasons).
                        let mut buf: Vec<u8> = Vec::with_capacity(8192);
                        let mut tmp = [0u8; 8192];
                        let body_end = loop {
                            let n = stream.read(&mut tmp).unwrap_or(0);
                            if n == 0 {
                                break buf.len();
                            }
                            buf.extend_from_slice(&tmp[..n]);
                            let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) else { continue };
                            let headers = String::from_utf8_lossy(&buf[..header_end]);
                            let content_length: usize = headers
                                .lines()
                                .find_map(|l| {
                                    let lower = l.to_ascii_lowercase();
                                    lower.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            if buf.len() >= header_end + content_length {
                                break header_end + content_length;
                            }
                        };
                        let req = String::from_utf8_lossy(&buf[..body_end]);
                        let body_start = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
                        let parsed: serde_json::Value = serde_json::from_str(&req[body_start..]).unwrap_or(serde_json::json!({}));
                        let inputs = parsed.get("input").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                        let mut items: Vec<serde_json::Value> = inputs
                            .iter()
                            .enumerate()
                            .map(|(i, v)| {
                                let text = v.as_str().unwrap_or("");
                                let vec = if text.contains("quick brown fox") {
                                    [1.0, 0.0, 0.0, 0.0]
                                } else if text.contains("second distinct message") {
                                    [0.0, 1.0, 0.0, 0.0]
                                } else {
                                    [0.0, 0.0, 1.0, 0.0]
                                };
                                serde_json::json!({"embedding": vec, "index": i})
                            })
                            .collect();
                        items.reverse();
                        let body = serde_json::json!({"data": items}).to_string();
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
        let (code, report, message) = run(&path, true, None, None, &format!("http://{addr}"), None, None);
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
        let (code, report, message) = run(&path, true, None, None, &format!("http://{addr}"), None, None);
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
        let (code, report, message) = run(&path, true, None, None, &format!("http://{addr}"), None, None);
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
        let (code, report, message) = run(&path, true, None, None, &format!("http://{addr}"), None, None);
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
        let (code, report, message) = run(&path, true, None, None, &format!("http://{addr}"), None, None);
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(code, 1, "{message}");
        assert!(report.unwrap().span_failed >= 1);
    }

    #[test]
    fn missing_full_or_sample_seed_is_precondition_error_exit_2() {
        let (_dir, path, _gen, _ids) = fresh_baseline();
        let (code, report, message) = run(&path, false, None, None, "http://127.0.0.1:1", None, None);
        assert_eq!(code, 2, "{message}");
        assert!(report.is_none());
    }

    #[test]
    fn missing_db_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.db");
        let (code, report, message) = run(&path, true, None, None, "http://127.0.0.1:1", None, None);
        assert_eq!(code, 2, "{message}");
        assert!(report.is_none());
    }

    /// T11.8 regression: a `--full` run over a generation whose combined
    /// `ownership_oracle.py` verdict output exceeds a pipe's OS buffer
    /// must still complete (not deadlock). Runs `run()` on a background
    /// thread and gives it a generous 180s upper bound via
    /// `recv_timeout` -- the pre-rewrite code hung here indefinitely
    /// (verified once by hand: it never returned inside 180s and had to
    /// be killed), since ownership_oracle.py's ~5,000 output lines
    /// (~400 KB) far exceed a typical pipe buffer while the old code was
    /// still blocked writing the rest of its ~5,000 input lines.
    #[test]
    fn full_run_does_not_deadlock_on_large_oracle_output() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent_search.db");
        let (_gen_id, chunk_count) = seed_large_single_message(&path);
        let (addr, stop) = start_mock_infinity();

        let path_for_thread = path.clone();
        let infinity_url = format!("http://{addr}");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = run(&path_for_thread, true, None, None, &infinity_url, None, None);
            let _ = tx.send(result);
        });

        let result = rx.recv_timeout(std::time::Duration::from_secs(180));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let (code, report, message) = result.unwrap_or_else(|_| panic!("deadlock: run(--full) over a {chunk_count}-chunk single message did not return within 180s"));
        assert_eq!(code, 0, "{message}");
        let report = report.unwrap();
        assert_eq!(report.checked, chunk_count);
        assert_eq!(report.span_failed, 0);
        assert_eq!(report.cosine_failed, 0);
        assert_eq!(report.vec0_mismatch, 0);
        assert!(report.batches >= 2, "a {chunk_count}-chunk generation must span more than one {PAGE_ROWS}-row page");
    }

    /// T11.8: proves `select_sample_ids` (the rewritten, ids-only
    /// selection) picks exactly the same `chunk_id` set the pre-rewrite
    /// `select_sample` (which shuffled/truncated full `StoredChunk` rows
    /// fetched in ascending `chunk_id` order) would have, for the same
    /// seed. The legacy algorithm is reproduced verbatim here (operating
    /// on the id list alone, since only the resulting id SET -- not row
    /// contents -- determines equivalence: shuffling an ascending id list
    /// with a given seed visits the same positions as shuffling an
    /// equal-length, equally-ordered `Vec<StoredChunk>` with that seed).
    #[test]
    fn sample_id_selection_matches_legacy_algorithm() {
        fn legacy_select_sample_ids(mut ids: Vec<i64>, sample: usize, seed: u64) -> Vec<i64> {
            if sample >= ids.len() {
                return ids;
            }
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            ids.shuffle(&mut rng);
            ids.truncate(sample);
            ids.sort();
            ids
        }

        let ids: Vec<i64> = (1..=10_000).collect();
        for seed in [1u64, 20260905, 42, 999_999_999] {
            let legacy: HashSet<i64> = legacy_select_sample_ids(ids.clone(), 137, seed).into_iter().collect();
            let rewritten = select_sample_ids(ids.clone(), 137, seed);
            assert_eq!(legacy, rewritten, "seed {seed} must select the same chunk_id set before and after the T10 streaming rewrite");
        }
        // sample >= len keeps everything under both algorithms.
        let all: HashSet<i64> = ids.iter().copied().collect();
        assert_eq!(select_sample_ids(ids.clone(), ids.len(), 7), all);
        let ids_len = ids.len();
        assert_eq!(select_sample_ids(ids, ids_len + 1, 7), all);
    }
}
