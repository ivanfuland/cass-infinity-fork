//! Verifiable anchor and neighbour-block document assembly (P03).
//!
//! [`build_documents`] turns a rerank candidate window into the exact text a
//! rerank backend will score. It is deliberately narrow: it does not search,
//! does not call a model and does not own a cursor. It reads one candidate
//! window out of the archive, proves every byte it is about to score against
//! that archive's own records, and refuses the whole batch the moment any one
//! candidate fails to prove out.
//!
//! The anchor comes from one of two places, and the ticket fixes which:
//!
//! - **Semantic winner.** The hit already carries the winning chunk identity
//!   (`winning_chunk_idx` / `winning_chunk_span` / `winning_chunk_hash`). All
//!   three fields must be present and must equal the archive's `message_chunks`
//!   row. A hit with a *broken* winning identity is an error -- it is never
//!   re-anchored by falling back to the lexical locator.
//! - **Lexical anchor.** The hit carries no winning chunk, so the anchor is
//!   located by re-running the frozen locator algorithm over the message's
//!   canonical body. That algorithm is the verified prototype ported in P03:
//!   the same KU3 short-query / short-subterm routing, the same FTS5
//!   transpilation and the same `LIKE` fallbacks the production query path
//!   already uses (this module calls those existing functions rather than
//!   copying them).
//!
//! Once the anchor chunk indices are known, each anchor expands to its left and
//! right *existing* neighbour blocks, the selected byte intervals are unioned
//! (overlap and adjacency merge), and the disjoint intervals are joined with a
//! blank line. Only canonical-text byte ranges are sliced; nothing is truncated
//! and no overlap is emitted twice.
//!
//! Failure vocabulary is short and enumerable ([`RerankError`]):
//! [`RerankFailureReason::UnscoreableInput`] for "no verifiable body to
//! score", and [`RerankFailureReason::InputIdentityMismatch`] for every
//! missing record, version drift, bad chunk identity or SQL/open failure. No
//! error carries SQL text, row content or a path.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use crate::search::canonicalize::{
    CANONICALIZE_PIPELINE_VERSION, canonicalize_for_embedding, content_hash_hex,
};
use crate::search::chunking::{CHUNKING_POLICY_VERSION, chunk_normalized};
use crate::search::query::{
    SearchClient, SearchHit, is_lexical_ku3_short_query, query_has_short_subterm_after_normalization,
    transpile_to_fts5,
};
use crate::search::rerank::types::{RerankError, RerankFailureReason};
use crate::storage::api::{Conn, TxMode, Value};

/// The separator placed between two disjoint anchor intervals.
const JOIN_SEPARATOR: &str = "\n\n";

/// Candidate cap for the in-memory locator. The locator table holds exactly one
/// row, so this only needs to exceed one; it matches the verified prototype's
/// value so the two stay directly comparable.
const LOCATOR_CANDIDATE_CAP: usize = 100;

/// Read-only open budget for the archive. Opening a read-only archive is a
/// metadata operation, so this is generous rather than tuned.
const READ_ONLY_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

fn unscoreable() -> RerankError {
    RerankError::new(RerankFailureReason::UnscoreableInput)
}

fn identity_mismatch() -> RerankError {
    RerankError::new(RerankFailureReason::InputIdentityMismatch)
}

/// The archive's active embedding generation, plus the two version stamps the
/// chunk identity contract is pinned to.
#[derive(Debug, Clone, Copy)]
struct GenerationFact {
    id: i64,
    canonicalize_version: i64,
    chunking_policy_version: i64,
}

/// One `messages` row's body and conversation identity.
#[derive(Debug, Clone)]
struct MessageFact {
    content: String,
    conversation_id: i64,
}

/// The `lex_docs` projection of one message: the same body plus the metadata
/// columns the lexical locator searches.
#[derive(Debug, Clone)]
struct LexFact {
    content: String,
    title: String,
    agent: String,
    workspace: String,
    source_path: String,
}

/// One archived chunk row, in the columns the identity contract checks.
#[derive(Debug, Clone)]
struct ChunkFact {
    chunk_idx: u32,
    byte_start: usize,
    byte_end: usize,
    content_hash: String,
}

/// Everything read for one hit inside the read transaction. Any `None`/empty
/// slot is a missing record and becomes an identity failure during assembly.
#[derive(Debug, Clone)]
struct HitFacts {
    message: Option<MessageFact>,
    lex: Option<LexFact>,
    chunks: Vec<ChunkFact>,
}

/// Assemble the rerank input texts for one candidate window.
///
/// The returned `Vec` is index-aligned with `hits`: `out[i]` is the document
/// for `hits[i]`, and the input order is never re-sorted.
///
/// An empty `hits` returns an empty `Vec` *without* touching `db_path`, so a
/// caller can hand in a window it already knows is empty without paying for a
/// database open (or failing on a path that does not exist).
///
/// Any other outcome is all-or-nothing: one candidate that cannot be proven
/// returns `Err` and no partial document list is produced.
pub fn build_documents(
    db_path: &Path,
    query: &str,
    hits: &[SearchHit],
) -> Result<Vec<String>, RerankError> {
    if hits.is_empty() {
        return Ok(Vec::new());
    }

    // TESTS-ONLY RED STATE: the production assembly is deliberately not
    // implemented in this step. The module tests must fail here (behaviour
    // failure), proving they bind to a real implementation. Removed by the
    // implementing commit that follows.
    unimplemented!("P03 tests-only RED: production document assembly not implemented yet");

    #[allow(unreachable_code)]
    let conn = crate::storage::sqlite::open_franken_raw_readonly_connection_with_timeout(
        db_path,
        READ_ONLY_OPEN_TIMEOUT,
    )
    .map_err(|_| identity_mismatch())?;
    crate::storage::sqlite::ensure_readonly_schema_current(&conn).map_err(|_| identity_mismatch())?;

    let (generation, facts) = conn
        .with_tx_no_replay(TxMode::Deferred, |tx| {
            let generation = tx.query_opt_map(
                "SELECT id, canonicalize_version, chunking_policy_version \
                 FROM embedding_generations WHERE is_active = 1 LIMIT 1",
                &[],
                |row| {
                    Ok(GenerationFact {
                        id: row.get_typed(0)?,
                        canonicalize_version: row.get_typed(1)?,
                        chunking_policy_version: row.get_typed(2)?,
                    })
                },
            )?;

            let generation_id = generation.map(|g| g.id);

            let mut out = Vec::with_capacity(hits.len());
            for hit in hits {
                out.push(read_hit_facts(tx, hit.message_id, generation_id)?);
            }
            Ok((generation, out))
        })
        .map_err(|_| identity_mismatch())?;

    let generation = generation.ok_or_else(identity_mismatch)?;
    if generation.canonicalize_version != i64::from(CANONICALIZE_PIPELINE_VERSION)
        || generation.chunking_policy_version != i64::from(CHUNKING_POLICY_VERSION)
    {
        return Err(identity_mismatch());
    }

    let mut documents = Vec::with_capacity(hits.len());
    for (hit, facts) in hits.iter().zip(facts.iter()) {
        documents.push(assemble_document(query, hit, facts)?);
    }
    Ok(documents)
}

/// Read everything one hit needs from the archive, inside the read transaction.
///
/// A missing or non-positive `message_id` yields an empty `HitFacts` rather
/// than an error here: the decision to reject belongs to assembly, where it
/// stays next to the other identity rules.
fn read_hit_facts(
    tx: &crate::storage::api::Tx<'_>,
    message_id: Option<i64>,
    generation_id: Option<i64>,
) -> Result<HitFacts, crate::storage::api::StorageError> {
    let Some(mid) = message_id.filter(|id| *id > 0) else {
        return Ok(HitFacts { message: None, lex: None, chunks: Vec::new() });
    };

    let message = tx.query_opt_map(
        "SELECT content, conversation_id FROM messages WHERE id = ?1",
        &[Value::Integer(mid)],
        |row| {
            Ok(MessageFact {
                content: row.get_typed(0)?,
                conversation_id: row.get_typed(1)?,
            })
        },
    )?;

    let lex = tx.query_opt_map(
        "SELECT content, title, agent, workspace, source_path FROM lex_docs WHERE doc_id = ?1",
        &[Value::Integer(mid)],
        |row| {
            Ok(LexFact {
                content: row.get_typed(0)?,
                title: row.get_typed(1)?,
                agent: row.get_typed(2)?,
                workspace: row.get_typed(3)?,
                source_path: row.get_typed(4)?,
            })
        },
    )?;

    let chunks = match generation_id {
        Some(gid) => tx.query_all_map(
            "SELECT chunk_idx, byte_start, byte_end, content_hash FROM message_chunks \
             WHERE message_id = ?1 AND generation_id = ?2 ORDER BY chunk_idx",
            &[Value::Integer(mid), Value::Integer(gid)],
            |row| {
                Ok(ChunkFact {
                    chunk_idx: row.get_typed(0)?,
                    byte_start: row.get_typed(1)?,
                    byte_end: row.get_typed(2)?,
                    content_hash: row.get_typed(3)?,
                })
            },
        )?,
        None => Vec::new(),
    };

    Ok(HitFacts { message, lex, chunks })
}

/// Prove one candidate and assemble its document.
fn assemble_document(
    query: &str,
    hit: &SearchHit,
    facts: &HitFacts,
) -> Result<String, RerankError> {
    let message = facts.message.as_ref().ok_or_else(identity_mismatch)?;
    let lex = facts.lex.as_ref().ok_or_else(identity_mismatch)?;

    // The body the lexical locator searches and the body the chunk domain was
    // built from must be the same message, byte for byte.
    if message.content != lex.content {
        return Err(identity_mismatch());
    }
    // `conversation_id` is part of the private codec but is absent from older
    // public `SearchHit` JSON; only a value that was actually carried is a
    // real comparison, so a defaulted `None` proves nothing either way.
    if let Some(carried) = hit.conversation_id {
        if carried != message.conversation_id {
            return Err(identity_mismatch());
        }
    }

    let canonical = canonicalize_for_embedding(&message.content);
    if canonical.is_empty() {
        return Err(unscoreable());
    }

    let expected = chunk_normalized(&canonical);
    if expected.len() != facts.chunks.len() {
        return Err(identity_mismatch());
    }

    let mut by_idx: HashMap<u32, &ChunkFact> = HashMap::with_capacity(facts.chunks.len());
    for (span, recorded) in expected.iter().zip(facts.chunks.iter()) {
        if recorded.chunk_idx != span.chunk_idx
            || recorded.byte_start != span.byte_start
            || recorded.byte_end != span.byte_end
        {
            return Err(identity_mismatch());
        }
        if !canonical.is_char_boundary(span.byte_start) || !canonical.is_char_boundary(span.byte_end)
        {
            return Err(identity_mismatch());
        }
        let recomputed = content_hash_hex(&canonical[span.byte_start..span.byte_end]);
        if recomputed != recorded.content_hash {
            return Err(identity_mismatch());
        }
        by_idx.insert(span.chunk_idx, recorded);
    }

    let anchors = select_anchors(query, hit, lex, &canonical, &facts.chunks, &by_idx)?;
    if anchors.is_empty() {
        return Err(unscoreable());
    }

    let selected = expand_anchors(&anchors, &by_idx);
    if selected.is_empty() {
        return Err(unscoreable());
    }

    let unions = union_intervals(&selected, &by_idx);
    let mut text = String::new();
    for (i, (start, end)) in unions.iter().enumerate() {
        if !canonical.is_char_boundary(*start) || !canonical.is_char_boundary(*end) {
            return Err(identity_mismatch());
        }
        if i > 0 {
            text.push_str(JOIN_SEPARATOR);
        }
        text.push_str(&canonical[*start..*end]);
    }
    if text.is_empty() {
        return Err(unscoreable());
    }
    Ok(text)
}

/// Resolve the anchor chunk indices for one hit.
///
/// A hit that carries *any* of the three winning-chunk fields must carry all
/// three, and they must match the archived chunk row exactly. A partial or
/// contradictory winning identity is an error -- it is never downgraded to a
/// lexical re-anchor, which would silently mask a corrupt identity.
fn select_anchors(
    query: &str,
    hit: &SearchHit,
    lex: &LexFact,
    canonical: &str,
    chunks: &[ChunkFact],
    by_idx: &HashMap<u32, &ChunkFact>,
) -> Result<Vec<u32>, RerankError> {
    let carries_winning = hit.winning_chunk_idx.is_some()
        || hit.winning_chunk_span.is_some()
        || hit.winning_chunk_hash.is_some();

    if carries_winning {
        let idx = hit.winning_chunk_idx.ok_or_else(identity_mismatch)?;
        let span = hit.winning_chunk_span.ok_or_else(identity_mismatch)?;
        let hash = hit.winning_chunk_hash.as_deref().ok_or_else(identity_mismatch)?;
        let recorded = by_idx.get(&idx).ok_or_else(identity_mismatch)?;
        if recorded.byte_start != span.0 || recorded.byte_end != span.1 {
            return Err(identity_mismatch());
        }
        if recorded.content_hash != hash {
            return Err(identity_mismatch());
        }
        return Ok(vec![idx]);
    }

    let location = locate_lexical_anchor(
        canonical,
        &lex.title,
        &lex.agent,
        &lex.workspace,
        &lex.source_path,
        query,
    )?;
    // An unsupported route and a matched-but-title-only location both leave no
    // body anchor: neither is a candidate this module may score.
    if location.route == LocatorRoute::Unsupported || location.body_spans.is_empty() {
        return Err(unscoreable());
    }

    let mut anchors: Vec<u32> = Vec::new();
    for (span_start, span_end) in &location.body_spans {
        for chunk in chunks {
            if chunk.byte_start < *span_end && chunk.byte_end > *span_start {
                anchors.push(chunk.chunk_idx);
            }
        }
    }
    anchors.sort_unstable();
    anchors.dedup();
    Ok(anchors)
}

/// Expand each anchor to its left and right *existing* neighbour chunk.
fn expand_anchors(anchors: &[u32], by_idx: &HashMap<u32, &ChunkFact>) -> Vec<u32> {
    let mut selected: Vec<u32> = Vec::new();
    for anchor in anchors {
        for delta in [-1_i64, 0, 1] {
            let candidate = i64::from(*anchor) + delta;
            if candidate < 0 {
                continue;
            }
            let candidate = candidate as u32;
            if by_idx.contains_key(&candidate) {
                selected.push(candidate);
            }
        }
    }
    selected.sort_unstable();
    selected.dedup();
    selected
}

/// Union the selected chunks' byte intervals, merging overlap and adjacency.
fn union_intervals(selected: &[u32], by_idx: &HashMap<u32, &ChunkFact>) -> Vec<(usize, usize)> {
    let mut intervals: Vec<(usize, usize)> = selected
        .iter()
        .filter_map(|idx| by_idx.get(idx))
        .map(|chunk| (chunk.byte_start, chunk.byte_end))
        .collect();
    intervals.sort_unstable();

    let mut unions: Vec<(usize, usize)> = Vec::new();
    for (start, end) in intervals {
        match unions.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => unions.push((start, end)),
        }
    }
    unions
}

/// How the lexical locator anchored one message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocatorRoute {
    /// The body matched a transpiled FTS5 `MATCH` query (spans from `highlight`).
    Match,
    /// The short/failed query degraded to a whole-string `LIKE`.
    LikeLiteral,
    /// The short query degraded to a multi-term `LIKE`; spans are per term.
    LikeTerms,
    /// The query cannot be represented by either locator route.
    Unsupported,
}

/// One locator result: the route taken and the anchored body spans.
#[derive(Debug, Clone)]
struct LexicalLocation {
    route: LocatorRoute,
    body_spans: Vec<(usize, usize)>,
}

/// The locator plan for a query: the route plus the SQL and bound parameters
/// the production candidate-query builders produced for it.
enum LocatorPlan {
    Match { fts_query: String, sql: String, params: Vec<Value> },
    LikeLiteral { term: String, sql: String, params: Vec<Value> },
    LikeTerms { terms: Vec<String>, sql: String, params: Vec<Value> },
    Unsupported,
}

/// Choose the locator route the way the production lexical path does.
///
/// This mirrors the verified prototype's `plan` exactly, but delegates every
/// actual decision (short-query detection, term extraction, FTS5
/// transpilation, SQL construction) to the existing production functions.
fn plan_locator(query: &str) -> LocatorPlan {
    let short = is_lexical_ku3_short_query(query)
        || query_has_short_subterm_after_normalization(query);

    if short {
        let terms = SearchClient::ku3_like_fallback_terms(query);
        if terms.mixed_operators
            || terms.positive.is_empty()
            || (terms.negative.is_empty() && terms.positive.len() < 2)
        {
            let raw_term = query.trim().replace('*', "");
            let (sql, params) =
                SearchClient::lex_docs_like_candidates_query(&raw_term, LOCATOR_CANDIDATE_CAP);
            LocatorPlan::LikeLiteral { term: raw_term, sql, params }
        } else {
            let (sql, params) = SearchClient::lex_docs_like_candidates_query_multi_term(
                &terms,
                LOCATOR_CANDIDATE_CAP,
            );
            LocatorPlan::LikeTerms { terms: terms.positive, sql, params }
        }
    } else {
        match transpile_to_fts5(query) {
            Some(fts_query) if !fts_query.trim().is_empty() => {
                let (sql, params) =
                    SearchClient::fts_lex_match_candidates_query(&fts_query, LOCATOR_CANDIDATE_CAP);
                LocatorPlan::Match { fts_query, sql, params }
            }
            _ => LocatorPlan::Unsupported,
        }
    }
}

/// Locate the lexical anchor spans inside `body`.
///
/// The locator runs against a single-row in-memory `lex_docs` / `fts_lex` pair
/// carrying the *canonical* body plus the archive's original metadata columns,
/// using the same `porter trigram` FTS5 tokenizer the real `fts_lex` uses. The
/// body is searched, never a snippet or a `content` prefix: a `title`-only or
/// `source_path`-only match produces an empty `body_spans` and is caught later
/// as unscoreable.
fn locate_lexical_anchor(
    body: &str,
    title: &str,
    agent: &str,
    workspace: &str,
    source_path: &str,
    query: &str,
) -> Result<LexicalLocation, RerankError> {
    let plan = plan_locator(query);
    let conn = Conn::open_memory().map_err(|_| identity_mismatch())?;
    conn.execute_batch(
        "CREATE TABLE lex_docs (doc_id INTEGER PRIMARY KEY, content TEXT, title TEXT, \
         agent TEXT, workspace TEXT, source_path TEXT); \
         CREATE VIRTUAL TABLE fts_lex USING fts5(content, title, agent, workspace, \
         source_path, tokenize = 'porter trigram');",
    )
    .map_err(|_| identity_mismatch())?;

    let row = [
        Value::Text(body.to_string()),
        Value::Text(title.to_string()),
        Value::Text(agent.to_string()),
        Value::Text(workspace.to_string()),
        Value::Text(source_path.to_string()),
    ];
    conn.execute("INSERT INTO lex_docs VALUES (1, ?1, ?2, ?3, ?4, ?5)", &row)
        .map_err(|_| identity_mismatch())?;
    conn.execute(
        "INSERT INTO fts_lex (rowid, content, title, agent, workspace, source_path) \
         VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        &row,
    )
    .map_err(|_| identity_mismatch())?;

    let (route, sql, params) = match &plan {
        LocatorPlan::Match { sql, params, .. } => (LocatorRoute::Match, sql, params),
        LocatorPlan::LikeLiteral { sql, params, .. } => (LocatorRoute::LikeLiteral, sql, params),
        LocatorPlan::LikeTerms { sql, params, .. } => (LocatorRoute::LikeTerms, sql, params),
        LocatorPlan::Unsupported => {
            return Ok(LexicalLocation { route: LocatorRoute::Unsupported, body_spans: Vec::new() });
        }
    };

    let matched = !conn
        .query_all_map(sql, params, |_row| Ok(()))
        .map_err(|_| identity_mismatch())?
        .is_empty();

    let mut body_spans: Vec<(usize, usize)> = Vec::new();
    if matched {
        match &plan {
            LocatorPlan::Match { fts_query, .. } => {
                let (open, close) = choose_markers(body);
                let marked: String = conn
                    .query_row_map(
                        "SELECT highlight(fts_lex, 0, ?1, ?2) FROM fts_lex WHERE fts_lex MATCH ?3",
                        &[
                            Value::Text(open.clone()),
                            Value::Text(close.clone()),
                            Value::Text(fts_query.clone()),
                        ],
                        |row| row.get_typed(0),
                    )
                    .map_err(|_| identity_mismatch())?;
                if marked.replace(&open, "").replace(&close, "") != body {
                    return Err(identity_mismatch());
                }
                body_spans = parse_marked_spans(&marked, &open, &close)?;
            }
            LocatorPlan::LikeLiteral { term, .. } => {
                body_spans = ascii_match_spans(body, std::slice::from_ref(term));
            }
            LocatorPlan::LikeTerms { terms, .. } => {
                body_spans = ascii_match_spans(body, terms);
            }
            LocatorPlan::Unsupported => {}
        }
    }

    Ok(LexicalLocation { route, body_spans })
}

/// Pick a marker pair that does not occur in `body`.
///
/// The first attempt keeps the prototype's `[CC_B]`/`[CC_E]`; if the body
/// already contains either literal, a numbered variant is used until both are
/// absent. This guarantees the highlighted string, once de-marked, is the body
/// again byte for byte -- content carrying the old markers is neither dropped
/// nor confused with a new span.
fn choose_markers(body: &str) -> (String, String) {
    let mut n: u64 = 0;
    loop {
        let (open, close) = if n == 0 {
            ("[CC_B]".to_string(), "[CC_E]".to_string())
        } else {
            (format!("[CC_B{n}]"), format!("[CC_E{n}]"))
        };
        if !body.contains(&open) && !body.contains(&close) {
            return (open, close);
        }
        n += 1;
    }
}

/// Parse `open`/`close`-delimited spans out of a highlighted string.
fn parse_marked_spans(
    marked: &str,
    open: &str,
    close: &str,
) -> Result<Vec<(usize, usize)>, RerankError> {
    let mut spans = Vec::new();
    let mut rest = marked;
    let mut offset = 0usize;
    while let Some(start) = rest.find(open) {
        offset += start;
        rest = &rest[start + open.len()..];
        let len = rest.find(close).ok_or_else(identity_mismatch)?;
        spans.push((offset, offset + len));
        offset += len;
        rest = &rest[len + close.len()..];
    }
    Ok(spans)
}

/// Substring spans for the `LIKE` routes, over an ASCII-lowercased copy.
///
/// `LIKE` is ASCII-case-insensitive, so lowercasing both sides (which never
/// changes byte length for the ASCII range and leaves non-ASCII untouched)
/// reproduces the same match set with byte offsets valid against `body`.
fn ascii_match_spans(body: &str, terms: &[String]) -> Vec<(usize, usize)> {
    let lower = body.to_ascii_lowercase();
    let mut spans = Vec::new();
    for term in terms {
        let needle = term.to_ascii_lowercase();
        if needle.is_empty() {
            continue;
        }
        for (start, matched) in lower.match_indices(&needle) {
            spans.push((start, start + matched.len()));
        }
    }
    spans.sort_unstable();
    spans.dedup();
    spans
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::api::Profile;
    use std::fs;
    use std::path::PathBuf;

    // ---- synthetic locator fixtures (the frozen 27 boundary cases) ----------
    //
    // Ported from the verified locator-boundary probe's `fixtures.json` /
    // `synthetic-final.json`. These are synthetic boundary cases, not real
    // questions; only the route/body_spans/intersect expectations are frozen
    // here, the canonical body and chunks are recomputed from `content`.

    struct SynCase {
        id: &'static str,
        query: &'static str,
        content: &'static str,
        title: &'static str,
        source_path: &'static str,
        route: LocatorRoute,
        spans: Vec<(usize, usize)>,
        intersect: Vec<Vec<usize>>,
    }

    fn synthetic_cases() -> Vec<SynCase> {
        // The frozen fixture's exact body: 980 x's, 事务, 1100 y's, 事务 tail.
        // Leaked to `&'static str` so it can live in the table beside the other
        // literals; the value is deterministic and constructed once per call.
        let boundary_repeat_body: &'static str =
            Box::leak(format!("{}事务{}事务 tail", "x".repeat(980), "y".repeat(1100)).into_boxed_str());

        vec![
            SynCase { id: "zh_two", query: "事务", content: "检查事务隔离，事务回滚。", title: "", source_path: "", route: LocatorRoute::LikeLiteral, spans: vec![(6, 12), (21, 27)], intersect: vec![vec![0], vec![0]] },
            SynCase { id: "zh_three", query: "事务回", content: "检查事务回滚与隔离。", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![(6, 15)], intersect: vec![vec![0]] },
            SynCase { id: "ascii_two", query: "io", content: "The IO path writes io data.", title: "", source_path: "", route: LocatorRoute::LikeLiteral, spans: vec![(4, 6), (19, 21)], intersect: vec![vec![0], vec![0]] },
            SynCase { id: "cpp", query: "c++", content: "Use C++ for renderer code.", title: "", source_path: "", route: LocatorRoute::LikeLiteral, spans: vec![(4, 7)], intersect: vec![vec![0]] },
            SynCase { id: "underscore", query: "my_variable", content: "my_variable stores state.", title: "", source_path: "", route: LocatorRoute::LikeTerms, spans: vec![(0, 2), (3, 11)], intersect: vec![vec![0], vec![0]] },
            SynCase { id: "multi_zh", query: "事务 rollback", content: "rollback protects this 事务 boundary.", title: "", source_path: "", route: LocatorRoute::LikeTerms, spans: vec![(0, 8), (23, 29)], intersect: vec![vec![0], vec![0]] },
            SynCase { id: "or_short", query: "alpha OR io", content: "the IO path is here", title: "", source_path: "", route: LocatorRoute::LikeTerms, spans: vec![(4, 6)], intersect: vec![vec![0]] },
            SynCase { id: "not_short", query: "alpha NOT io", content: "alpha function version IO", title: "", source_path: "", route: LocatorRoute::LikeTerms, spans: vec![(0, 5)], intersect: vec![vec![0]] },
            SynCase { id: "mixed_short", query: "alpha OR io NOT beta", content: "alpha appears here", title: "", source_path: "", route: LocatorRoute::LikeLiteral, spans: vec![], intersect: vec![] },
            SynCase { id: "and", query: "alpha beta", content: "alpha far apart from beta", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![(0, 5), (21, 25)], intersect: vec![vec![0], vec![0]] },
            SynCase { id: "or", query: "alpha OR beta", content: "beta only", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![(0, 4)], intersect: vec![vec![0]] },
            SynCase { id: "not", query: "alpha NOT beta", content: "alpha only", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![(0, 5)], intersect: vec![vec![0]] },
            SynCase { id: "excluded", query: "alpha NOT beta", content: "alpha and beta", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![], intersect: vec![] },
            SynCase { id: "phrase", query: "\"alpha beta\"", content: "alpha beta works", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![(0, 10)], intersect: vec![vec![0]] },
            SynCase { id: "phrase_gap", query: "\"alpha beta\"", content: "alpha extra beta", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![], intersect: vec![] },
            SynCase { id: "prefix", query: "render*", content: "renderer stages", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![(0, 6)], intersect: vec![vec![0]] },
            SynCase { id: "hyphen", query: "foo-bar", content: "foo-bar identifier", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![(0, 7)], intersect: vec![vec![0]] },
            SynCase { id: "title_only", query: "renderer", content: "No relevant words here", title: "renderer design", source_path: "", route: LocatorRoute::Match, spans: vec![], intersect: vec![] },
            SynCase { id: "path_only", query: "renderer", content: "No relevant words here", title: "", source_path: "/synthetic/renderer/file", route: LocatorRoute::Match, spans: vec![], intersect: vec![] },
            SynCase { id: "cross_field_and", query: "alpha beta", content: "alpha lives here", title: "beta title", source_path: "", route: LocatorRoute::Match, spans: vec![(0, 5)], intersect: vec![vec![0]] },
            SynCase { id: "nfd_body", query: "café", content: "Cafe\u{301} renderer notes.", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![(0, 5)], intersect: vec![vec![0]] },
            SynCase { id: "markdown_join", query: "foobar", content: "foo**bar** valid explanation", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![(0, 6)], intersect: vec![vec![0]] },
            SynCase { id: "markdown_query_deleted", query: "strong", content: "**strong** statement", title: "", source_path: "", route: LocatorRoute::Match, spans: vec![(0, 6)], intersect: vec![vec![0]] },
            SynCase { id: "low_signal", query: "ok", content: "ok", title: "", source_path: "", route: LocatorRoute::LikeLiteral, spans: vec![], intersect: vec![] },
            SynCase { id: "boundary_repeat", query: "事务", content: boundary_repeat_body, title: "", source_path: "", route: LocatorRoute::LikeLiteral, spans: vec![(980, 986), (2086, 2092)], intersect: vec![vec![0, 1], vec![2]] },
            SynCase { id: "literal_percent", query: "中%", content: "必须保留中%符号", title: "", source_path: "", route: LocatorRoute::LikeLiteral, spans: vec![(12, 16)], intersect: vec![vec![0]] },
            SynCase { id: "unsupported_wildcard", query: "ren*der", content: "renderer logic", title: "", source_path: "", route: LocatorRoute::Unsupported, spans: vec![], intersect: vec![] },
        ]
    }

    #[test]
    fn synthetic_boundary_cases_match_frozen_locator() {
        // Leak the rendered boundary body so `&'static str` can hold it for the
        // duration of the test; the value is deterministic, so this is stable.
        let cases = synthetic_cases();
        assert_eq!(cases.len(), 27, "the frozen boundary set has exactly 27 cases");

        for case in &cases {
            let body = canonicalize_for_embedding(case.content);
            let chunks = chunk_normalized(&body);
            let location = locate_lexical_anchor(
                &body,
                case.title,
                "",
                "",
                case.source_path,
                case.query,
            )
            .unwrap_or_else(|e| panic!("{}: locator failed: {e}", case.id));

            assert_eq!(location.route, case.route, "{}: route", case.id);
            assert_eq!(location.body_spans, case.spans, "{}: body_spans", case.id);

            let intersect: Vec<Vec<usize>> = location
                .body_spans
                .iter()
                .map(|(a, b)| {
                    chunks
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| c.byte_start < *b && c.byte_end > *a)
                        .map(|(i, _)| i)
                        .collect()
                })
                .collect();
            assert_eq!(intersect, case.intersect, "{}: intersect_chunks", case.id);
        }
    }

    // ---- synthetic database fixtures for build_documents ------------------

    struct Fixture {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("temp dir");
            let path = dir.path().join("agent_search.db");
            let conn = Conn::open_writable(&path, Profile::Production).expect("create db");
            conn.execute_batch(
                "CREATE TABLE messages (id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL, \
                 content TEXT NOT NULL); \
                 CREATE TABLE lex_docs (doc_id INTEGER PRIMARY KEY, content TEXT NOT NULL, \
                 title TEXT NOT NULL, agent TEXT NOT NULL, workspace TEXT NOT NULL, \
                 source_path TEXT NOT NULL); \
                 CREATE TABLE message_chunks (chunk_id INTEGER PRIMARY KEY, generation_id INTEGER \
                 NOT NULL, message_id INTEGER NOT NULL, chunk_idx INTEGER NOT NULL, byte_start \
                 INTEGER NOT NULL, byte_end INTEGER NOT NULL, content_hash TEXT NOT NULL); \
                 CREATE TABLE embedding_generations (id INTEGER PRIMARY KEY, is_active INTEGER \
                 NOT NULL, canonicalize_version INTEGER NOT NULL, chunking_policy_version INTEGER \
                 NOT NULL); \
                 PRAGMA user_version = 8;",
            )
            .expect("schema");
            conn.close().expect("close");
            Self { _dir: dir, path }
        }

        fn conn(&self) -> Conn {
            Conn::open_writable(&self.path, Profile::Production).expect("reopen")
        }

        fn insert_generation(&self, id: i64, active: bool, canon: i64, chunk: i64) {
            self.conn()
                .execute(
                    "INSERT INTO embedding_generations (id, is_active, canonicalize_version, \
                     chunking_policy_version) VALUES (?1, ?2, ?3, ?4)",
                    &[
                        Value::Integer(id),
                        Value::Integer(i64::from(active)),
                        Value::Integer(canon),
                        Value::Integer(chunk),
                    ],
                )
                .expect("generation");
        }

        fn insert_message(&self, id: i64, conversation_id: i64, content: &str) {
            self.conn()
                .execute(
                    "INSERT INTO messages (id, conversation_id, content) VALUES (?1, ?2, ?3)",
                    &[
                        Value::Integer(id),
                        Value::Integer(conversation_id),
                        Value::Text(content.to_string()),
                    ],
                )
                .expect("message");
        }

        fn insert_lex(&self, doc_id: i64, content: &str, title: &str) {
            self.conn()
                .execute(
                    "INSERT INTO lex_docs (doc_id, content, title, agent, workspace, source_path) \
                     VALUES (?1, ?2, ?3, '', '', '')",
                    &[
                        Value::Integer(doc_id),
                        Value::Text(content.to_string()),
                        Value::Text(title.to_string()),
                    ],
                )
                .expect("lex");
        }

        /// Insert the archive-correct chunk rows for `content` (canonical body
        /// computed the same way the pipeline does).
        fn insert_chunks(&self, generation_id: i64, message_id: i64, content: &str) -> Vec<ChunkFact> {
            let canonical = canonicalize_for_embedding(content);
            let spans = chunk_normalized(&canonical);
            let conn = self.conn();
            let mut facts = Vec::new();
            for span in &spans {
                let hash = content_hash_hex(&canonical[span.byte_start..span.byte_end]);
                conn.execute(
                    "INSERT INTO message_chunks (generation_id, message_id, chunk_idx, byte_start, \
                     byte_end, content_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    &[
                        Value::Integer(generation_id),
                        Value::Integer(message_id),
                        Value::Integer(i64::from(span.chunk_idx)),
                        Value::Integer(span.byte_start as i64),
                        Value::Integer(span.byte_end as i64),
                        Value::Text(hash.clone()),
                    ],
                )
                .expect("chunk");
                facts.push(ChunkFact {
                    chunk_idx: span.chunk_idx,
                    byte_start: span.byte_start,
                    byte_end: span.byte_end,
                    content_hash: hash,
                });
            }
            facts
        }

        fn insert_chunk_raw(
            &self,
            generation_id: i64,
            message_id: i64,
            chunk_idx: u32,
            byte_start: usize,
            byte_end: usize,
            hash: &str,
        ) {
            self.conn()
                .execute(
                    "INSERT INTO message_chunks (generation_id, message_id, chunk_idx, byte_start, \
                     byte_end, content_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    &[
                        Value::Integer(generation_id),
                        Value::Integer(message_id),
                        Value::Integer(i64::from(chunk_idx)),
                        Value::Integer(byte_start as i64),
                        Value::Integer(byte_end as i64),
                        Value::Text(hash.to_string()),
                    ],
                )
                .expect("raw chunk");
        }
    }

    fn hit(message_id: i64) -> SearchHit {
        let mut h = empty_hit();
        h.message_id = Some(message_id);
        h
    }

    fn empty_hit() -> SearchHit {
        SearchHit {
            title: String::new(),
            snippet: String::new(),
            content: String::new(),
            content_hash: 0,
            conversation_id: None,
            score: 0.0,
            source_path: String::new(),
            agent: String::new(),
            workspace: String::new(),
            workspace_original: None,
            created_at: None,
            line_number: None,
            match_type: Default::default(),
            source_id: String::new(),
            origin_kind: String::new(),
            origin_host: None,
            message_id: None,
            winning_chunk_idx: None,
            winning_chunk_span: None,
            winning_chunk_hash: None,
            rerank_score: None,
        }
    }

    fn standard_fixture() -> (Fixture, Vec<ChunkFact>) {
        // One generation + one message long enough to force several chunks, so
        // neighbour selection is exercised for real.
        let fixture = Fixture::new();
        fixture.insert_generation(1, true, i64::from(CANONICALIZE_PIPELINE_VERSION), i64::from(CHUNKING_POLICY_VERSION));
        let content = build_long_body();
        fixture.insert_message(7, 42, &content);
        fixture.insert_lex(7, &content, "");
        let chunks = fixture.insert_chunks(1, 7, &content);
        (fixture, chunks)
    }

    fn build_long_body() -> String {
        // > 2 chunks: paragraph break near char 600 keeps non-final chunk
        // lengths inside [500, 1000].
        let mut s = String::new();
        for i in 0..8 {
            s.push_str(&"alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu ".repeat(8));
            s.push('\n');
            if i == 3 {
                s.push('\n');
            }
        }
        s.push_str("tail marker");
        s
    }

    fn canonical_of(content: &str) -> String {
        canonicalize_for_embedding(content)
    }

    #[test]
    fn semantic_winner_expands_to_existing_neighbours() {
        let (fixture, chunks) = standard_fixture();
        assert!(chunks.len() >= 3, "test body must have at least 3 chunks");

        let middle = chunks[1].chunk_idx;
        let mut h = hit(7);
        h.winning_chunk_idx = Some(middle);
        h.winning_chunk_span = Some((chunks[1].byte_start, chunks[1].byte_end));
        h.winning_chunk_hash = Some(chunks[1].content_hash.clone());

        let docs = build_documents(&fixture.path, "unused", &[h]).expect("build");
        assert_eq!(docs.len(), 1);

        let content = read_message(&fixture, 7);
        let canonical = canonical_of(&content);
        // Consecutive chunks overlap by 100 chars, so the three selected
        // intervals merge into one continuous span -- no blank-line join here.
        assert_eq!(docs[0], canonical[chunks[0].byte_start..chunks[2].byte_end]);
    }

    #[test]
    fn edge_anchor_uses_only_existing_neighbours() {
        let (fixture, chunks) = standard_fixture();
        let canonical = canonical_of(&read_message(&fixture, 7));

        // First chunk -> itself + next chunk (no left neighbour).
        let mut h = hit(7);
        h.winning_chunk_idx = Some(chunks[0].chunk_idx);
        h.winning_chunk_span = Some((chunks[0].byte_start, chunks[0].byte_end));
        h.winning_chunk_hash = Some(chunks[0].content_hash.clone());
        let docs = build_documents(&fixture.path, "unused", &[h]).expect("build");
        assert_eq!(docs[0], canonical[chunks[0].byte_start..chunks[1].byte_end]);

        // Last chunk -> itself + previous chunk.
        let last = chunks.len() - 1;
        let mut h = hit(7);
        h.winning_chunk_idx = Some(chunks[last].chunk_idx);
        h.winning_chunk_span = Some((chunks[last].byte_start, chunks[last].byte_end));
        h.winning_chunk_hash = Some(chunks[last].content_hash.clone());
        let docs = build_documents(&fixture.path, "unused", &[h]).expect("build");
        assert_eq!(docs[0], canonical[chunks[last - 1].byte_start..chunks[last].byte_end]);
    }

    #[test]
    fn lexical_anchor_joins_disjoint_intervals_with_blank_line() {
        // Two far-apart occurrences of a short CJK term -> two anchor groups
        // that do not touch, joined by a blank line.
        let fixture = Fixture::new();
        fixture.insert_generation(1, true, i64::from(CANONICALIZE_PIPELINE_VERSION), i64::from(CHUNKING_POLICY_VERSION));
        // Long enough (~10k chars, ~12 chunks) that the two anchors' neighbour
        // groups stay separate instead of merging into one interval.
        let content =
            format!("{}事务{}事务{}", "a".repeat(5000), "b".repeat(5000), "c".repeat(200));
        fixture.insert_message(9, 5, &content);
        fixture.insert_lex(9, &content, "");
        let _ = fixture.insert_chunks(1, 9, &content);

        let h = hit(9);
        let docs = build_documents(&fixture.path, "事务", std::slice::from_ref(&h)).expect("build");
        assert_eq!(
            docs[0].matches(JOIN_SEPARATOR).count(),
            1,
            "two disjoint anchor groups must be joined by exactly one blank line"
        );
        // The first interval is covered back to the body start and the second
        // forward to the body end (both anchors are interior, so the neighbour
        // expansion reaches both edges).
        assert!(docs[0].starts_with("aaa"));
        assert!(docs[0].ends_with("ccc"));
    }

    #[test]
    fn empty_hits_does_not_open_the_database() {
        let missing = Path::new("/nonexistent/cc-p03/never.db");
        let docs = build_documents(missing, "anything", &[]).expect("empty window");
        assert!(docs.is_empty());
    }

    #[test]
    fn missing_message_is_identity_mismatch() {
        let fixture = Fixture::new();
        fixture.insert_generation(1, true, i64::from(CANONICALIZE_PIPELINE_VERSION), i64::from(CHUNKING_POLICY_VERSION));
        let err = build_documents(&fixture.path, "q", &[hit(12345)]).unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InputIdentityMismatch);
    }

    #[test]
    fn missing_lex_row_is_identity_mismatch() {
        let fixture = Fixture::new();
        fixture.insert_generation(1, true, i64::from(CANONICALIZE_PIPELINE_VERSION), i64::from(CHUNKING_POLICY_VERSION));
        let content = build_long_body();
        fixture.insert_message(7, 1, &content);
        fixture.insert_chunks(1, 7, &content);
        let err = build_documents(&fixture.path, "q", &[hit(7)]).unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InputIdentityMismatch);
    }

    #[test]
    fn bad_winning_hash_is_not_downgraded_to_lexical() {
        let (fixture, chunks) = standard_fixture();
        let mut h = hit(7);
        h.winning_chunk_idx = Some(chunks[1].chunk_idx);
        h.winning_chunk_span = Some((chunks[1].byte_start, chunks[1].byte_end));
        h.winning_chunk_hash = Some("00".repeat(32)); // wrong hash, right length
        let err = build_documents(&fixture.path, "alpha", &[h]).unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InputIdentityMismatch);
    }

    #[test]
    fn partial_winning_identity_is_identity_mismatch() {
        let (fixture, chunks) = standard_fixture();
        let mut h = hit(7);
        h.winning_chunk_idx = Some(chunks[1].chunk_idx);
        // span and hash deliberately absent
        let err = build_documents(&fixture.path, "alpha", &[h]).unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InputIdentityMismatch);
    }

    #[test]
    fn corrupt_chunk_byte_span_is_identity_mismatch() {
        let fixture = Fixture::new();
        fixture.insert_generation(1, true, i64::from(CANONICALIZE_PIPELINE_VERSION), i64::from(CHUNKING_POLICY_VERSION));
        let content = "short body";
        fixture.insert_message(3, 1, content);
        fixture.insert_lex(3, content, "");
        fixture.insert_chunk_raw(1, 3, 0, 0, 4, &content_hash_hex("shor"));
        let err = build_documents(&fixture.path, "q", &[hit(3)]).unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InputIdentityMismatch);
    }

    #[test]
    fn generation_version_drift_is_identity_mismatch() {
        let fixture = Fixture::new();
        fixture.insert_generation(1, true, 99, i64::from(CHUNKING_POLICY_VERSION));
        let content = "some body";
        fixture.insert_message(3, 1, content);
        fixture.insert_lex(3, content, "");
        fixture.insert_chunks(1, 3, content);
        let err = build_documents(&fixture.path, "q", &[hit(3)]).unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InputIdentityMismatch);
    }

    #[test]
    fn title_only_anchor_is_unscoreable() {
        let fixture = Fixture::new();
        fixture.insert_generation(1, true, i64::from(CANONICALIZE_PIPELINE_VERSION), i64::from(CHUNKING_POLICY_VERSION));
        let content = "no matching words in the body at all";
        fixture.insert_message(3, 1, content);
        fixture.insert_lex(3, content, "renderer");
        fixture.insert_chunks(1, 3, content);
        let err = build_documents(&fixture.path, "renderer", &[hit(3)]).unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::UnscoreableInput);
    }

    #[test]
    fn empty_body_is_unscoreable() {
        let fixture = Fixture::new();
        fixture.insert_generation(1, true, i64::from(CANONICALIZE_PIPELINE_VERSION), i64::from(CHUNKING_POLICY_VERSION));
        // "ok" canonicalizes to the empty string (low-signal filter).
        fixture.insert_message(3, 1, "ok");
        fixture.insert_lex(3, "ok", "");
        let err = build_documents(&fixture.path, "ok", &[hit(3)]).unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::UnscoreableInput);
    }

    #[test]
    fn second_candidate_failure_fails_the_whole_batch() {
        let (fixture, chunks) = standard_fixture();
        let mut good = hit(7);
        good.winning_chunk_idx = Some(chunks[0].chunk_idx);
        good.winning_chunk_span = Some((chunks[0].byte_start, chunks[0].byte_end));
        good.winning_chunk_hash = Some(chunks[0].content_hash.clone());

        // Second candidate's message does not exist.
        let bad = hit(999_999);
        let err = build_documents(&fixture.path, "alpha", &[good, bad]).unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InputIdentityMismatch);
    }

    #[test]
    fn conversation_id_when_carried_must_match() {
        let (fixture, chunks) = standard_fixture();
        let mut h = hit(7);
        h.conversation_id = Some(4242); // archive says 42
        h.winning_chunk_idx = Some(chunks[0].chunk_idx);
        h.winning_chunk_span = Some((chunks[0].byte_start, chunks[0].byte_end));
        h.winning_chunk_hash = Some(chunks[0].content_hash.clone());
        let err = build_documents(&fixture.path, "alpha", &[h]).unwrap_err();
        assert_eq!(err.reason, RerankFailureReason::InputIdentityMismatch);

        // The matching id is accepted.
        let mut ok = hit(7);
        ok.conversation_id = Some(42);
        ok.winning_chunk_idx = Some(chunks[0].chunk_idx);
        ok.winning_chunk_span = Some((chunks[0].byte_start, chunks[0].byte_end));
        ok.winning_chunk_hash = Some(chunks[0].content_hash.clone());
        assert!(build_documents(&fixture.path, "alpha", &[ok]).is_ok());
    }

    #[test]
    fn documents_follow_input_order_and_are_exact_utf8() {
        let fixture = Fixture::new();
        fixture.insert_generation(1, true, i64::from(CANONICALIZE_PIPELINE_VERSION), i64::from(CHUNKING_POLICY_VERSION));

        let bodies = ["中文第一条消息内容", "第二条 different body here"];
        let mut hits = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            let id = (i as i64) + 1;
            fixture.insert_message(id, id, body);
            fixture.insert_lex(id, body, "");
            let chunks = fixture.insert_chunks(1, id, body);
            assert_eq!(chunks.len(), 1, "each synthetic body is a single chunk");
            let mut h = hit(id);
            h.winning_chunk_idx = Some(chunks[0].chunk_idx);
            h.winning_chunk_span = Some((chunks[0].byte_start, chunks[0].byte_end));
            h.winning_chunk_hash = Some(chunks[0].content_hash.clone());
            hits.push(h);
        }
        // Hand them in reverse id order; output order must follow the input.
        hits.reverse();

        let docs = build_documents(&fixture.path, "unused", &hits).expect("build");
        assert_eq!(docs.len(), hits.len());
        for (hit, doc) in hits.iter().zip(docs.iter()) {
            let expected = canonical_of(&read_message(&fixture, hit.message_id.unwrap()));
            assert_eq!(*doc, expected, "document must be the exact canonical UTF-8 body");
        }
        // Order is really reversed relative to id, so the first document is the
        // second body.
        assert_eq!(docs[0], canonical_of(bodies[1]));
    }

    #[test]
    fn marker_collision_in_body_is_handled() {
        // The body itself carries the prototype's old markers; the locator must
        // pick different ones and still return the body byte-for-byte.
        let body = "[CC_B] alpha [CC_E] plain";
        let location = locate_lexical_anchor(body, "", "", "", "", "alpha").expect("locate");
        assert_eq!(location.route, LocatorRoute::Match);
        assert_eq!(location.body_spans, vec![(7, 12)]);
    }

    #[test]
    fn utf8_multibyte_anchor_bytes_are_exact() {
        let body = canonical_of("前缀中文事务后缀");
        let location = locate_lexical_anchor(&body, "", "", "", "", "事务").expect("locate");
        assert_eq!(location.body_spans, vec![(12, 18)]);
        // Slice must land on char boundaries.
        let (a, b) = location.body_spans[0];
        assert!(body.is_char_boundary(a) && body.is_char_boundary(b));
        assert_eq!(&body[a..b], "事务");
    }

    fn read_message(fixture: &Fixture, message_id: i64) -> String {
        let conn = Conn::open_read(&fixture.path).expect("open read");
        conn.query_row_map(
            "SELECT content FROM messages WHERE id = ?1",
            &[Value::Integer(message_id)],
            |row| row.get_typed(0),
        )
        .expect("read message")
    }

    // ---- real frozen-corpus equivalence (private, opt-in) ------------------
    //
    // This test only runs when explicitly invoked with `--ignored` and the
    // corpus roots are supplied through the environment. It never hardcodes a
    // private path, a question or a body: the raw hit lists, the queries and
    // the expected texts all come from the supplied roots.

    #[test]
    #[ignore = "real frozen corpus; needs CASS_PR3_P03_DB_PATH / CASS_PR3_P03_RAW_DIR / CASS_PR3_P03_TEXTS_DIR"]
    fn frozen_corpus_equivalence() {
        let db_path = std::env::var("CASS_PR3_P03_DB_PATH").expect("CASS_PR3_P03_DB_PATH");
        let raw_dir = PathBuf::from(std::env::var("CASS_PR3_P03_RAW_DIR").expect("CASS_PR3_P03_RAW_DIR"));
        let texts_dir =
            PathBuf::from(std::env::var("CASS_PR3_P03_TEXTS_DIR").expect("CASS_PR3_P03_TEXTS_DIR"));

        let manifest = std::env::var("CASS_PR3_P03_MANIFEST").ok().map(|p| {
            let text = fs::read_to_string(&p).expect("read manifest");
            let value: serde_json::Value = serde_json::from_str(&text).expect("parse manifest");
            value["query_order"]
                .as_array()
                .expect("query_order array")
                .iter()
                .map(|v| v.as_str().expect("qid string").to_string())
                .collect::<Vec<_>>()
        });
        let order = manifest.unwrap_or_else(|| {
            let mut ids: Vec<String> = fs::read_dir(&raw_dir)
                .expect("raw dir")
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    name.strip_suffix(".json").map(|s| s.to_string())
                })
                .collect();
            ids.sort();
            ids
        });

        let mut checked = 0usize;
        for qid in &order {
            let raw_text = fs::read_to_string(raw_dir.join(format!("{qid}.json"))).expect("raw hit file");
            let raw: serde_json::Value = serde_json::from_str(&raw_text).expect("raw json");
            let query = raw["query"].as_str().expect("raw query").to_string();
            let hits: Vec<SearchHit> =
                serde_json::from_value(raw["hits"].clone()).expect("raw hits -> SearchHit");

            let docs = build_documents(Path::new(&db_path), &query, &hits)
                .unwrap_or_else(|e| panic!("{qid}: build_documents failed: {e}"));
            assert_eq!(docs.len(), hits.len(), "{qid}: document count");

            for (rank, (hit, doc)) in hits.iter().zip(docs.iter()).enumerate() {
                let mid = hit.message_id.expect("message id");
                let expected_path = texts_dir.join(format!("{qid}-{:03}-{mid}.txt", rank + 1));
                let expected = fs::read(&expected_path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", expected_path.display()));
                assert_eq!(
                    doc.as_bytes(),
                    expected.as_slice(),
                    "{qid} rank {} (message {mid}) bytes differ",
                    rank + 1
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 1800, "the frozen corpus has 9 x 200 = 1800 candidate slots");
    }
}
