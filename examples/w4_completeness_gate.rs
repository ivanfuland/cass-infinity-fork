//! T10 (plan v5.1): `w4_completeness_gate` -- the index-completeness door.
//! Bidirectional set comparison of "what the semantic/lexical domains
//! currently hold" against "what [`eligibility`]'s single-source-of-truth
//! functions say SHOULD be there", computed straight from `messages` (never
//! by grepping or re-deriving chunking/eligibility rules a second time).
//!
//! Semantic: `message_chunks` rows for the active generation vs
//! [`eligibility::for_each_expected_chunk`]'s output, keyed by `(message_id,
//! chunk_idx)`; for keys present on both sides, `content_hash`/span
//! (`byte_start`,`byte_end`)/`conversation_id` are compared field-by-field.
//! Plus: `chunk_holes` row count for the generation (must be zero) and
//! [`vector_domain::count_vec0_chunks_set_mismatch_for_generation`] (must be
//! `(0, 0)`).
//!
//! PR9 task 10 AC2: the semantic side also compares the active generation's
//! authoritative chunk ids against the eight int8 shards, as a set of
//! `(physical shard, chunk_id)` pairs -- `int8_missing` counts authoritative
//! chunks whose `chunk_id % 8` shard does not hold their row, and
//! `int8_extra` counts rows physically sitting in a shard that either are
//! not routed there (`rowid % 8` differs from that shard) or have no
//! authoritative row at all. Because the pair carries the *physical* shard
//! index, a chunk moved into another shard and the same chunk duplicated
//! across two shards both surface -- neither can be hidden behind an equal
//! total row count. This is computed from raw SQL in this file; the
//! product's own `audit_int8_mirror_identity` is not consulted for it.
//! Only the layout's existence/type/dimension is taken from the product
//! (`check_int8_layout`), the same structural precondition the product's
//! own fast path runs.
//!
//! Lexical: `lex_docs.doc_id` vs [`eligibility::lexical_eligible`]'s
//! derived id set; for ids present on both sides, the five projected
//! columns (`content`/`title`/`agent`/`workspace`/`source_path`, computed
//! via the exact same `messages JOIN conversations JOIN agents LEFT JOIN
//! workspaces` shape `sqlite.rs`'s `sync_lexical_docs_for_messages_in_tx`
//! uses) are byte-compared against the stored `lex_docs` row. Plus: FTS5's
//! own `INSERT INTO fts_lex(fts_lex, rank) VALUES('integrity-check', 1)`
//! shadow-table integrity check (requires a writer connection, hence this
//! tool opens `--db` writable, not read-only, even though it makes no other
//! writes).
//!
//! `excluded` breaks down *why* a message contributes zero expected chunks
//! or is lexically ineligible (diagnostic only, computed via
//! `chunking::canonical_role`/`eligibility::normalized_for_chunks`/
//! `canonicalize::is_hard_message_noise` -- the same underlying functions
//! `expected_chunks`/`lexical_eligible` already call, not a re-derivation):
//! `non_whitelist` (role outside the `CanonicalRole` whitelist -- excludes a
//! message from BOTH domains), `canonicalize_empty` (whitelisted role, but
//! `canonicalize`'s stage-4 low-signal filter empties the normalized text --
//! excludes from semantic only, since `lexical_eligible` doesn't use
//! normalized text), `hard_noise` (whitelisted role, but
//! `is_hard_message_noise` flags it as a tool/short acknowledgement --
//! excludes from lexical only).
//!
//! Usage: `cargo run --release --no-default-features --features
//! qr,encryption,infinity --example w4_completeness_gate -- --db <path>
//! --json <out>`. No stdout progress protocol -- `--json` is written once,
//! at the end. Exit codes: 0 both domains complete; 1 either domain has a
//! nonzero finding (a missing/damaged int8 shard layout is a precondition
//! error, not a finding -- the layout is structure, not data); 2
//! precondition error (db missing, no active generation to scope the
//! semantic comparison to, or an incomplete/invalid int8 shard layout).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use clap::Parser;
use coding_agent_search::search::canonicalize::is_hard_message_noise;
use coding_agent_search::search::chunking::canonical_role;
use coding_agent_search::search::eligibility::{for_each_expected_chunk, lexical_eligible, normalized_for_chunks};
use coding_agent_search::storage::api::Value;
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::vector_domain::{INT8_SHARDS, check_int8_layout, count_vec0_chunks_set_mismatch_for_generation, int8_table_name};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "w4_completeness_gate")]
struct Cli {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    json: PathBuf,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Default)]
struct SemanticReport {
    missing: i64,
    extra: i64,
    hash_mismatch: i64,
    span_mismatch: i64,
    conv_mismatch: i64,
    holes: i64,
    vec0_mismatch: (i64, i64),
    /// PR9 task 10 AC2: authoritative chunks whose routed int8 shard
    /// (`chunk_id % 8`) does not hold their row, summed over the eight
    /// shards.
    int8_missing: i64,
    /// PR9 task 10 AC2: rows physically present in a shard that either are
    /// not routed there (`rowid % 8 != shard`) or have no authoritative row
    /// in the active generation, summed over the eight shards.
    int8_extra: i64,
}
impl SemanticReport {
    fn passed(&self) -> bool {
        self.missing == 0
            && self.extra == 0
            && self.hash_mismatch == 0
            && self.span_mismatch == 0
            && self.conv_mismatch == 0
            && self.holes == 0
            && self.vec0_mismatch == (0, 0)
            && self.int8_missing == 0
            && self.int8_extra == 0
    }
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq)]
struct LexicalReport {
    missing: i64,
    extra: i64,
    column_mismatch: i64,
    fts_integrity_ok: bool,
}
impl LexicalReport {
    fn passed(&self) -> bool {
        self.missing == 0 && self.extra == 0 && self.column_mismatch == 0 && self.fts_integrity_ok
    }
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Default)]
struct ExcludedReport {
    non_whitelist: i64,
    canonicalize_empty: i64,
    hard_noise: i64,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Default)]
struct ChunksPerMessageReport {
    max: i64,
    p99: f64,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct CompletenessReport {
    semantic: SemanticReport,
    lexical: LexicalReport,
    excluded: ExcludedReport,
    chunks_per_message: ChunksPerMessageReport,
}
impl CompletenessReport {
    fn passed(&self) -> bool {
        self.semantic.passed() && self.lexical.passed()
    }
}

fn active_generation(storage: &FrankenStorage) -> anyhow::Result<(i64, i64)> {
    let row = storage
        .raw()
        .query_row_map("SELECT id, dim FROM embedding_generations WHERE is_active = 1", &[], |row| {
            Ok((row.get_typed::<i64>(0)?, row.get_typed::<i64>(1)?))
        })?;
    Ok(row)
}

/// PR9 task 10 AC2: the eight-shard int8 set comparison, computed directly
/// from SQL here -- the product's `audit_int8_mirror_identity` is not the
/// judge. The comparison pairs each row with the shard it *physically*
/// sits in, so:
///
/// * `missing` -- an authoritative chunk whose `chunk_id % 8` shard does
///   not hold its row.
/// * `extra` -- a row in shard `s` whose id is either not routed to `s`
///   (`rowid % 8 != s`) or has no authoritative row at all.
///
/// A chunk moved to another shard therefore scores `missing = 1` *and*
/// `extra = 1`, and duplicating a chunk into a second shard scores
/// `extra = 1` while `missing` stays `0`; neither case can be hidden by an
/// unchanged aggregate row count across the eight shards.
fn count_int8_set_mismatch(storage: &FrankenStorage, generation_id: i64) -> anyhow::Result<(i64, i64)> {
    let mut missing = 0i64;
    let mut extra = 0i64;
    for shard in 0..INT8_SHARDS {
        let table = int8_table_name(generation_id, shard)?;
        let shard_missing: i64 = storage.raw().query_row_map(
            &format!(
                "SELECT COUNT(*) FROM message_chunks mc WHERE mc.generation_id = ?1 AND mc.chunk_id % {INT8_SHARDS} = ?2 \
                 AND NOT EXISTS(SELECT 1 FROM {table} v WHERE v.rowid = mc.chunk_id)"
            ),
            &[Value::from(generation_id), Value::from(shard as i64)],
            |row| row.get_typed(0),
        )?;
        let shard_extra: i64 = storage.raw().query_row_map(
            &format!(
                "SELECT COUNT(*) FROM {table} v WHERE v.rowid % {INT8_SHARDS} != ?1 \
                 OR NOT EXISTS(SELECT 1 FROM message_chunks mc WHERE mc.generation_id = ?2 AND mc.chunk_id = v.rowid)"
            ),
            &[Value::from(shard as i64), Value::from(generation_id)],
            |row| row.get_typed(0),
        )?;
        missing += shard_missing;
        extra += shard_extra;
    }
    Ok((missing, extra))
}

#[derive(Clone, PartialEq)]
struct ActualChunk {
    conversation_id: i64,
    byte_start: i64,
    byte_end: i64,
    content_hash: String,
}

fn compute_semantic_report(storage: &FrankenStorage, generation_id: i64, dim: i64) -> anyhow::Result<SemanticReport> {
    let mut expected: HashMap<(i64, u32), coding_agent_search::search::eligibility::ExpectedChunk> = HashMap::new();
    for_each_expected_chunk(storage, 5_000, |chunk| {
        expected.insert((chunk.message_id, chunk.chunk_idx), chunk);
        Ok(())
    })?;

    let actual_rows: Vec<(i64, u32, i64, i64, i64, String)> = storage.raw().query_all_map(
        &format!("SELECT message_id, chunk_idx, conversation_id, byte_start, byte_end, content_hash FROM message_chunks WHERE generation_id = ?1"),
        &[Value::from(generation_id)],
        |row| {
            Ok((
                row.get_typed(0)?,
                row.get_typed::<i64>(1)? as u32,
                row.get_typed(2)?,
                row.get_typed(3)?,
                row.get_typed(4)?,
                row.get_typed(5)?,
            ))
        },
    )?;
    let mut actual: HashMap<(i64, u32), ActualChunk> = HashMap::with_capacity(actual_rows.len());
    for (message_id, chunk_idx, conversation_id, byte_start, byte_end, content_hash) in actual_rows {
        actual.insert((message_id, chunk_idx), ActualChunk { conversation_id, byte_start, byte_end, content_hash });
    }

    let expected_keys: HashSet<&(i64, u32)> = expected.keys().collect();
    let actual_keys: HashSet<&(i64, u32)> = actual.keys().collect();

    let missing = expected_keys.difference(&actual_keys).count() as i64;
    let extra = actual_keys.difference(&expected_keys).count() as i64;

    let mut hash_mismatch = 0i64;
    let mut span_mismatch = 0i64;
    let mut conv_mismatch = 0i64;
    for key in expected_keys.intersection(&actual_keys) {
        let e = &expected[key];
        let a = &actual[key];
        if e.content_hash != a.content_hash {
            hash_mismatch += 1;
        }
        if e.byte_start as i64 != a.byte_start || e.byte_end as i64 != a.byte_end {
            span_mismatch += 1;
        }
        if e.conversation_id != a.conversation_id {
            conv_mismatch += 1;
        }
    }

    let holes: i64 = storage.raw().query_row_map(
        "SELECT COUNT(*) FROM chunk_holes WHERE generation_id = ?1",
        &[Value::from(generation_id)],
        |row| row.get_typed(0),
    )?;

    let vec0_mismatch = count_vec0_chunks_set_mismatch_for_generation(storage.raw(), generation_id)?;

    // PR9 task 10 AC2: the eight int8 shards must exist with the right
    // element type and dimension before their row sets mean anything --
    // a partial or mistyped layout is a structural precondition failure,
    // exactly as the product's own fast path treats it, not a data finding.
    check_int8_layout(storage.raw(), generation_id, dim)?;
    let (int8_missing, int8_extra) = count_int8_set_mismatch(storage, generation_id)?;

    Ok(SemanticReport { missing, extra, hash_mismatch, span_mismatch, conv_mismatch, holes, vec0_mismatch, int8_missing, int8_extra })
}

struct LexicalProjection {
    content: String,
    title: String,
    agent: String,
    workspace: String,
    source_path: String,
}

fn expected_lexical_projection(storage: &FrankenStorage, message_id: i64) -> anyhow::Result<LexicalProjection> {
    let (content, title, agent, workspace, source_path): (String, String, String, String, String) = storage.raw().query_row_map(
        "SELECT m.content, COALESCE(c.title, ''), COALESCE(a.slug, ''), COALESCE(w.path, ''), c.source_path \
         FROM messages m JOIN conversations c ON c.id = m.conversation_id JOIN agents a ON a.id = c.agent_id \
         LEFT JOIN workspaces w ON w.id = c.workspace_id WHERE m.id = ?1",
        &[Value::from(message_id)],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?, row.get_typed(4)?)),
    )?;
    Ok(LexicalProjection { content, title, agent, workspace, source_path })
}

fn compute_lexical_report(storage: &FrankenStorage, message_rows: &[(i64, String, String)]) -> anyhow::Result<LexicalReport> {
    let mut eligible_ids: HashSet<i64> = HashSet::new();
    for (id, role, content) in message_rows {
        if lexical_eligible(role, content) {
            eligible_ids.insert(*id);
        }
    }

    let lex_doc_ids: Vec<i64> = storage.raw().query_all_map("SELECT doc_id FROM lex_docs", &[], |row| row.get_typed(0))?;
    let lex_doc_set: HashSet<i64> = lex_doc_ids.into_iter().collect();

    let missing = eligible_ids.difference(&lex_doc_set).count() as i64;
    let extra = lex_doc_set.difference(&eligible_ids).count() as i64;

    let mut column_mismatch = 0i64;
    for doc_id in eligible_ids.intersection(&lex_doc_set) {
        let expected = expected_lexical_projection(storage, *doc_id)?;
        let actual: (String, String, String, String, String) = storage.raw().query_row_map(
            "SELECT content, title, agent, workspace, source_path FROM lex_docs WHERE doc_id = ?1",
            &[Value::from(*doc_id)],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?, row.get_typed(4)?)),
        )?;
        if expected.content != actual.0 || expected.title != actual.1 || expected.agent != actual.2 || expected.workspace != actual.3 || expected.source_path != actual.4 {
            column_mismatch += 1;
        }
    }

    let fts_integrity_ok = storage.raw().execute("INSERT INTO fts_lex(fts_lex, rank) VALUES('integrity-check', 1)", &[]).is_ok();

    Ok(LexicalReport { missing, extra, column_mismatch, fts_integrity_ok })
}

fn percentile(sorted: &[i64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1] as f64
}

fn compute_chunks_per_message(storage: &FrankenStorage, generation_id: i64) -> anyhow::Result<ChunksPerMessageReport> {
    let mut counts: Vec<i64> = storage.raw().query_all_map(
        "SELECT COUNT(*) FROM message_chunks WHERE generation_id = ?1 GROUP BY message_id",
        &[Value::from(generation_id)],
        |row| row.get_typed(0),
    )?;
    counts.sort_unstable();
    let max = counts.last().copied().unwrap_or(0);
    let p99 = percentile(&counts, 0.99);
    Ok(ChunksPerMessageReport { max, p99 })
}

fn fetch_all_messages(storage: &FrankenStorage) -> anyhow::Result<Vec<(i64, String, String)>> {
    let mut out = Vec::new();
    let mut cursor_id = 0i64;
    loop {
        let rows: Vec<(i64, String, String)> = storage.raw().query_all_map(
            "SELECT id, role, content FROM messages WHERE id > ?1 ORDER BY id LIMIT 5000",
            &[Value::from(cursor_id)],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
        )?;
        if rows.is_empty() {
            break;
        }
        let page_len = rows.len();
        for row in &rows {
            cursor_id = row.0;
        }
        out.extend(rows);
        if page_len < 5_000 {
            break;
        }
    }
    Ok(out)
}

fn compute_excluded_report(message_rows: &[(i64, String, String)]) -> ExcludedReport {
    let mut report = ExcludedReport::default();
    for (_id, role, content) in message_rows {
        match canonical_role(role) {
            None => report.non_whitelist += 1,
            Some(canon) => {
                if normalized_for_chunks(content).is_empty() {
                    report.canonicalize_empty += 1;
                }
                if is_hard_message_noise(Some(canon.as_str()), content) {
                    report.hard_noise += 1;
                }
            }
        }
    }
    report
}

fn compute_report(storage: &FrankenStorage) -> anyhow::Result<CompletenessReport> {
    let (generation_id, dim) = active_generation(storage)?;
    let semantic = compute_semantic_report(storage, generation_id, dim)?;
    let message_rows = fetch_all_messages(storage)?;
    let lexical = compute_lexical_report(storage, &message_rows)?;
    let excluded = compute_excluded_report(&message_rows);
    let chunks_per_message = compute_chunks_per_message(storage, generation_id)?;
    Ok(CompletenessReport { semantic, lexical, excluded, chunks_per_message })
}

fn run(db_path: &std::path::Path) -> (i32, Option<CompletenessReport>, String) {
    if !db_path.is_file() {
        return (2, None, format!("precondition error: db {} does not exist", db_path.display()));
    }
    let storage = match FrankenStorage::open_writer(db_path) {
        Ok(s) => s,
        Err(e) => return (2, None, format!("precondition error opening db writer: {e:#}")),
    };
    match compute_report(&storage) {
        Err(e) => (2, None, format!("precondition error: {e:#}")),
        Ok(report) => {
            let code = if report.passed() { 0 } else { 1 };
            let msg = format!(
                "completeness_gate: semantic={:?} lexical={:?} excluded={:?} chunks_per_message={:?} passed={}",
                report.semantic,
                report.lexical,
                report.excluded,
                report.chunks_per_message,
                report.passed()
            );
            (code, Some(report), msg)
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let (code, report, message) = run(&cli.db);
    println!("{message}");
    if let Some(report) = &report {
        let json = serde_json::to_string_pretty(report).expect("CompletenessReport must serialize");
        std::fs::write(&cli.json, json).expect("writing --json output must succeed");
    }
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
    use coding_agent_search::sources::provenance::LOCAL_SOURCE_ID;
    use coding_agent_search::storage::api::TxMode;
    use coding_agent_search::storage::schema;
    use coding_agent_search::storage::vector_domain;
    use tempfile::TempDir;

    /// Six messages, hand-picked to exercise every exclusion category
    /// independently (see the module doc comment's `excluded` field
    /// explanation):
    ///   0 "user"      normal prose            -> chunked + lex-eligible
    ///   1 "assistant" normal prose             -> chunked + lex-eligible
    ///   2 "reasoning" normal prose             -> non_whitelist (both domains excluded)
    ///   3 "user"      "ok"                     -> canonicalize_empty AND hard_noise (both lists include "ok")
    ///   4 "user"      "acknowledged"           -> hard_noise only (chunked, but lex-excluded)
    ///   5 "user"      "yes"                    -> canonicalize_empty only (lex-eligible, but zero chunks)
    fn seed_baseline_db(path: &std::path::Path) -> (i64 /* generation_id */, Vec<i64> /* message ids in insertion order */) {
        let storage = FrankenStorage::open(path).unwrap();
        let agent = Agent { id: None, slug: "codex".into(), name: "Codex".into(), version: Some("0.1".into()), kind: AgentKind::Cli };
        let agent_id = storage.ensure_agent(&agent).unwrap();

        let contents = [
            ("user", "This is a perfectly normal user message with enough substantive text to be both lexically eligible and semantically chunkable without any noise filtering issues at all."),
            ("assistant", "This is a perfectly normal assistant reply with enough substantive text to be both lexically eligible and semantically chunkable without any noise filtering issues at all."),
            ("reasoning", "This is reasoning trace text that should be excluded from both semantic and lexical domains entirely because reasoning is not in the canonical role whitelist at all."),
            ("user", "ok"),
            ("user", "acknowledged"),
            ("user", "yes"),
        ];
        let messages: Vec<Message> = contents
            .iter()
            .enumerate()
            .map(|(i, (role, content))| Message {
                id: None,
                idx: i as i64,
                role: match *role {
                    "user" => MessageRole::User,
                    "assistant" => MessageRole::Assistant,
                    other => MessageRole::Other(other.to_string()),
                },
                author: Some((*role).to_string()),
                created_at: Some(1_700_000_000_000 + i as i64),
                content: content.to_string(),
                extra_json: serde_json::json!({}),
                snippets: Vec::new(),
                excluded: None,
            })
            .collect();
        let conversation = Conversation {
            id: None,
            agent_slug: "codex".into(),
            workspace: Some(PathBuf::from("/tmp/workspace")),
            external_id: Some("completeness-gate-fixture".into()),
            title: Some("Completeness gate fixture".into()),
            source_path: PathBuf::from("/tmp/completeness-gate-fixture.jsonl"),
            started_at: Some(1_700_000_000_000),
            ended_at: Some(1_700_000_000_010),
            approx_tokens: Some(64),
            metadata_json: serde_json::Value::Null,
            messages,
            source_id: LOCAL_SOURCE_ID.into(),
            origin_host: None,
        };
        storage.insert_conversations_batched(&[(agent_id, None, &conversation)]).unwrap();

        let message_ids: Vec<i64> =
            storage.raw().query_all_map("SELECT id FROM messages ORDER BY idx", &[], |row| row.get_typed(0)).unwrap();
        let conversation_id: i64 = storage.raw().query_row_map("SELECT id FROM conversations LIMIT 1", &[], |row| row.get_typed(0)).unwrap();

        let generation_id = storage
            .raw()
            .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "bge-m3", 4, 1, 1, b"fp", 1_700_000_000_000))
            .unwrap();
        storage
            .raw()
            .execute("UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1", &[Value::from(generation_id)])
            .unwrap();

        // Semantic domain: insert exactly the chunks eligibility::expected_chunks
        // says should exist (messages 0, 1, 4 -- each short enough for exactly one chunk).
        storage
            .raw()
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                for (i, (role, content)) in contents.iter().enumerate() {
                    let message_id = message_ids[i];
                    for chunk in coding_agent_search::search::eligibility::expected_chunks(message_id, conversation_id, role, content) {
                        let embedding = schema::f32_vector_to_le_blob(&[1.0, 0.0, 0.0, 0.0]);
                        tx.execute(
                            "INSERT INTO message_chunks(generation_id, message_id, conversation_id, chunk_idx, byte_start, byte_end, \
                             content_hash, embedding, norm, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1.0, ?9)",
                            &[
                                Value::from(generation_id),
                                Value::from(message_id),
                                Value::from(chunk.conversation_id),
                                Value::from(chunk.chunk_idx as i64),
                                Value::from(chunk.byte_start as i64),
                                Value::from(chunk.byte_end as i64),
                                Value::from(chunk.content_hash.clone()),
                                Value::from(embedding),
                                Value::from(1_700_000_000_000i64),
                            ],
                        )?;
                    }
                }
                Ok(())
            })
            .unwrap();
        vector_domain::rebuild_vec0_table_for_generation(storage.raw(), generation_id, 4).unwrap();

        // Lexical domain: `insert_conversations_batched` (the production
        // write path used above) already synced `lex_docs`/`fts_lex` for
        // every eligible message as part of the insert itself -- confirmed
        // empirically (a redundant manual insert here originally collided
        // with a UNIQUE constraint on `lex_docs.doc_id`). Nothing further to
        // do; `compute_lexical_report`'s own projection query is what
        // proves the auto-synced rows are byte-correct, not this fixture.

        (generation_id, message_ids)
    }

    fn fresh_baseline() -> (TempDir, std::path::PathBuf, i64, Vec<i64>) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent_search.db");
        let (generation_id, message_ids) = seed_baseline_db(&path);
        (dir, path, generation_id, message_ids)
    }

    #[test]
    fn baseline_passes_with_all_zero_findings() {
        let (_dir, path, _gen, _ids) = fresh_baseline();
        let (code, report, message) = run(&path);
        assert_eq!(code, 0, "clean baseline must pass: {message}");
        let report = report.unwrap();
        assert_eq!(report.semantic, SemanticReport::default());
        assert_eq!(report.lexical, LexicalReport { missing: 0, extra: 0, column_mismatch: 0, fts_integrity_ok: true });
        assert_eq!(report.excluded, ExcludedReport { non_whitelist: 1, canonicalize_empty: 2, hard_noise: 2 });
        assert_eq!(report.chunks_per_message.max, 1, "every chunked message has exactly one chunk");
    }

    // ---- semantic: 8 injections, one per predicate ----

    #[test]
    fn semantic_missing_chunk_is_detected() {
        let (_dir, path, gen_id, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        storage
            .raw()
            .execute("DELETE FROM message_chunks WHERE generation_id = ?1 AND message_id = ?2", &[Value::from(gen_id), Value::from(ids[0])])
            .unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        assert_eq!(report.unwrap().semantic.missing, 1);
    }

    #[test]
    fn semantic_extra_chunk_is_detected() {
        let (_dir, path, gen_id, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        let embedding = schema::f32_vector_to_le_blob(&[1.0, 0.0, 0.0, 0.0]);
        storage
            .raw()
            .execute(
                "INSERT INTO message_chunks(generation_id, message_id, conversation_id, chunk_idx, byte_start, byte_end, content_hash, embedding, norm, created_at) \
                 VALUES (?1, ?2, 1, 99, 0, 5, 'bogus-hash', ?3, 1.0, 1700000000000)",
                &[Value::from(gen_id), Value::from(ids[0]), Value::from(embedding)],
            )
            .unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        assert_eq!(report.unwrap().semantic.extra, 1);
    }

    #[test]
    fn semantic_hash_mismatch_is_detected() {
        let (_dir, path, gen_id, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        storage
            .raw()
            .execute(
                "UPDATE message_chunks SET content_hash = 'corrupted-hash' WHERE generation_id = ?1 AND message_id = ?2",
                &[Value::from(gen_id), Value::from(ids[0])],
            )
            .unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        assert_eq!(report.unwrap().semantic.hash_mismatch, 1);
    }

    #[test]
    fn semantic_span_mismatch_is_detected() {
        let (_dir, path, gen_id, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        storage
            .raw()
            .execute(
                "UPDATE message_chunks SET byte_start = byte_start + 1 WHERE generation_id = ?1 AND message_id = ?2",
                &[Value::from(gen_id), Value::from(ids[0])],
            )
            .unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        assert_eq!(report.unwrap().semantic.span_mismatch, 1);
    }

    #[test]
    fn semantic_conversation_id_mismatch_is_detected() {
        let (_dir, path, gen_id, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        storage
            .raw()
            .execute(
                "UPDATE message_chunks SET conversation_id = conversation_id + 999 WHERE generation_id = ?1 AND message_id = ?2",
                &[Value::from(gen_id), Value::from(ids[0])],
            )
            .unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        assert_eq!(report.unwrap().semantic.conv_mismatch, 1);
    }

    #[test]
    fn semantic_chunk_hole_is_detected() {
        let (_dir, path, gen_id, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        storage
            .raw()
            .execute(
                "INSERT INTO chunk_holes(generation_id, message_id, chunk_idx, detected_at, reason) VALUES (?1, ?2, 0, 1700000000000, 'test-hole')",
                &[Value::from(gen_id), Value::from(ids[0])],
            )
            .unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        assert_eq!(report.unwrap().semantic.holes, 1);
    }

    #[test]
    fn semantic_vec0_extra_row_is_detected() {
        let (_dir, path, gen_id, _ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        storage.raw().execute(&format!("INSERT INTO vec_index_gen_{gen_id}(rowid, embedding) VALUES (999999, ?1)"), &[Value::from(schema::f32_vector_to_le_blob(&[0.0, 0.0, 0.0, 1.0]))]).unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        assert_eq!(report.unwrap().semantic.vec0_mismatch, (0, 1));
    }

    #[test]
    fn semantic_vec0_missing_row_is_detected() {
        let (_dir, path, gen_id, _ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        storage.raw().execute(&format!("DELETE FROM vec_index_gen_{gen_id} WHERE rowid = (SELECT chunk_id FROM message_chunks WHERE generation_id = {gen_id} LIMIT 1)"), &[]).unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        assert_eq!(report.unwrap().semantic.vec0_mismatch, (1, 0));
    }

    // ---- PR9 task 10 AC2: the eight-shard int8 mirror ----

    /// The fixture's chunk ids and their routed shards, read back from the
    /// database rather than assumed.
    fn chunk_shard_pairs(storage: &FrankenStorage, gen_id: i64) -> Vec<(i64, usize)> {
        let ids: Vec<i64> = storage
            .raw()
            .query_all_map("SELECT chunk_id FROM message_chunks WHERE generation_id = ?1 ORDER BY chunk_id", &[Value::from(gen_id)], |row| row.get_typed(0))
            .unwrap();
        ids.into_iter().map(|id| (id, (id % INT8_SHARDS as i64) as usize)).collect()
    }

    /// A valid int8 encoding of a fixed unit vector, of the fixture's
    /// dimension -- used for inserting rows the fixture never wrote.
    fn quantized_unit_blob(storage: &FrankenStorage) -> Vec<u8> {
        let blob = schema::f32_vector_to_le_blob(&[0.0, 0.0, 0.0, 1.0]);
        storage
            .raw()
            .query_row_map("SELECT vec_quantize_int8(vec_f32(?1), 'unit')", &[Value::from(blob)], |row| row.get_typed(0))
            .unwrap()
    }

    #[test]
    fn semantic_int8_missing_row_is_detected() {
        let (_dir, path, gen_id, _ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        let (chunk_id, shard) = chunk_shard_pairs(&storage, gen_id)[0];
        let table = int8_table_name(gen_id, shard).unwrap();
        storage.raw().execute(&format!("DELETE FROM {table} WHERE rowid = ?1"), &[Value::from(chunk_id)]).unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        let report = report.unwrap();
        assert_eq!(report.semantic.int8_missing, 1);
        assert_eq!(report.semantic.int8_extra, 0, "a plain deletion adds no row anywhere");
        assert_eq!(report.semantic.vec0_mismatch, (0, 0), "the float mirror still holds every row");
    }

    #[test]
    fn semantic_int8_extra_row_is_detected() {
        let (_dir, path, gen_id, _ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        let shard = 3usize;
        let table = int8_table_name(gen_id, shard).unwrap();
        let orphan_id = (shard as i64) + (INT8_SHARDS as i64) * 1_000;
        storage
            .raw()
            .execute(
                &format!("INSERT INTO {table}(rowid, embedding) VALUES (?1, vec_int8(?2))"),
                &[Value::from(orphan_id), Value::from(quantized_unit_blob(&storage))],
            )
            .unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        let report = report.unwrap();
        assert_eq!(report.semantic.int8_extra, 1);
        assert_eq!(report.semantic.int8_missing, 0, "an orphan in the right shard is extra only");
    }

    /// A chunk whose int8 row was physically moved into a different shard:
    /// the routed shard is short one row and the other shard has one it
    /// should not -- both sides must show, so a compensating total cannot
    /// hide it.
    #[test]
    fn semantic_int8_row_moved_to_the_wrong_shard_is_detected() {
        let (_dir, path, gen_id, _ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        let (chunk_id, shard) = chunk_shard_pairs(&storage, gen_id)[0];
        let other = (shard + 1) % INT8_SHARDS;
        let correct = int8_table_name(gen_id, shard).unwrap();
        let wrong = int8_table_name(gen_id, other).unwrap();
        let blob = quantized_unit_blob(&storage);
        storage.raw().execute(&format!("DELETE FROM {correct} WHERE rowid = ?1"), &[Value::from(chunk_id)]).unwrap();
        storage
            .raw()
            .execute(&format!("INSERT INTO {wrong}(rowid, embedding) VALUES (?1, vec_int8(?2))"), &[Value::from(chunk_id), Value::from(blob)])
            .unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        let report = report.unwrap();
        assert_eq!(report.semantic.int8_missing, 1, "the routed shard lost the row");
        assert_eq!(report.semantic.int8_extra, 1, "the other shard gained a row that is not routed there");
    }

    /// The same chunk present in two shards: nothing is missing, but the
    /// duplicate is extra in the shard it does not belong to.
    #[test]
    fn semantic_int8_duplicate_across_shards_is_detected() {
        let (_dir, path, gen_id, _ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        let (chunk_id, shard) = chunk_shard_pairs(&storage, gen_id)[0];
        let other = (shard + 1) % INT8_SHARDS;
        let wrong = int8_table_name(gen_id, other).unwrap();
        let blob = quantized_unit_blob(&storage);
        storage
            .raw()
            .execute(&format!("INSERT INTO {wrong}(rowid, embedding) VALUES (?1, vec_int8(?2))"), &[Value::from(chunk_id), Value::from(blob)])
            .unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        let report = report.unwrap();
        assert_eq!(report.semantic.int8_missing, 0, "the routed shard still holds its row");
        assert_eq!(report.semantic.int8_extra, 1);
    }

    #[test]
    fn semantic_int8_missing_shard_layout_is_a_precondition_error() {
        let (_dir, path, gen_id, _ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        storage.raw().execute(&format!("DROP TABLE {}", int8_table_name(gen_id, 5).unwrap()), &[]).unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 2, "a partial int8 layout is structure, not a data finding: {message}");
        assert!(report.is_none());
    }

    // ---- lexical: missing / extra / column_mismatch (all 5 columns) / fts_integrity ----

    #[test]
    fn lexical_missing_doc_is_detected() {
        let (_dir, path, _gen, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        storage.raw().execute("DELETE FROM lex_docs WHERE doc_id = ?1", &[Value::from(ids[0])]).unwrap();
        storage.raw().execute("DELETE FROM fts_lex WHERE rowid = ?1", &[Value::from(ids[0])]).unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        assert_eq!(report.unwrap().lexical.missing, 1);
    }

    #[test]
    fn lexical_extra_doc_for_an_ineligible_message_is_detected() {
        let (_dir, path, _gen, ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        // ids[2] is the "reasoning" message -- non-whitelist, never eligible.
        storage
            .raw()
            .execute(
                "INSERT INTO lex_docs(doc_id, content, title, agent, workspace, source_path) VALUES (?1, 'x', 't', 'a', 'w', 's')",
                &[Value::from(ids[2])],
            )
            .unwrap();
        storage
            .raw()
            .execute("INSERT INTO fts_lex(rowid, content, title, agent, workspace, source_path) VALUES (?1, 'x', 't', 'a', 'w', 's')", &[Value::from(ids[2])])
            .unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        assert_eq!(report.unwrap().lexical.extra, 1);
    }

    #[test]
    fn lexical_column_mismatch_each_of_five_columns_is_detected() {
        for column in ["content", "title", "agent", "workspace", "source_path"] {
            let (_dir, path, _gen, ids) = fresh_baseline();
            let storage = FrankenStorage::open_writer(&path).unwrap();
            storage
                .raw()
                .execute(&format!("UPDATE lex_docs SET {column} = 'CORRUPTED-VALUE' WHERE doc_id = ?1"), &[Value::from(ids[0])])
                .unwrap();
            drop(storage);
            let (code, report, message) = run(&path);
            assert_eq!(code, 1, "column {column}: {message}");
            assert_eq!(report.unwrap().lexical.column_mismatch, 1, "column {column} must trip column_mismatch");
        }
    }

    #[test]
    fn lexical_fts_integrity_check_runs_and_reports_ok_on_a_clean_index() {
        let (_dir, path, _gen, _ids) = fresh_baseline();
        let (code, report, message) = run(&path);
        assert_eq!(code, 0, "{message}");
        assert!(report.unwrap().lexical.fts_integrity_ok, "a freshly built fts5 shadow index must pass its own integrity-check");
    }

    #[test]
    fn lexical_fts_inverted_index_corruption_is_detected() {
        let (_dir, path, _gen, _ids) = fresh_baseline();
        let storage = FrankenStorage::open_writer(&path).unwrap();
        // Break only the inverted index's own segment storage (`fts_lex_data`,
        // FTS5's b-tree shadow table), leaving `lex_docs`/`fts_lex`'s external-
        // content row set untouched -- this is "只破坏 FTS 倒排" (corrupt the
        // inverted index specifically, not the content table), matching the
        // interface's own framing distinct from the missing/extra/
        // column_mismatch cases above.
        storage.raw().execute("DELETE FROM fts_lex_data WHERE rowid = (SELECT MAX(rowid) FROM fts_lex_data)", &[]).unwrap();
        drop(storage);
        let (code, report, message) = run(&path);
        assert_eq!(code, 1, "{message}");
        assert!(!report.unwrap().lexical.fts_integrity_ok, "a corrupted fts5 shadow index must fail its own integrity-check");
    }

    #[test]
    fn missing_db_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.db");
        let (code, report, message) = run(&path);
        assert_eq!(code, 2, "{message}");
        assert!(report.is_none());
    }

    #[test]
    fn no_active_generation_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent_search.db");
        FrankenStorage::open(&path).unwrap();
        let (code, report, message) = run(&path);
        assert_eq!(code, 2, "{message}");
        assert!(report.is_none());
    }
}
