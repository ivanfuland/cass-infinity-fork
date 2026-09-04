//! Chunk eligibility and expected-chunk computation (T3, plan v5.1).
//!
//! Single source of truth for "what chunks SHOULD exist for a message" and
//! "is this message eligible for lexical indexing". Built on T1's
//! [`crate::search::canonicalize`] and T2's [`crate::search::chunking`] --
//! not wired into any call site here (T5/T6/T8 do that).

use crate::search::canonicalize::{canonicalize_for_embedding, is_hard_message_noise};
use crate::search::chunking::{canonical_role, chunk_hash, chunk_normalized};

/// One expected chunk for a message: which generation-independent slice of
/// the message's normalized text it covers, and that slice's content hash.
///
/// Set/collection equality compares the whole struct -- including
/// `chunk_idx`/`byte_start`/`byte_end` -- so two chunks with the same
/// `content_hash` but different spans are NOT equal (span participates in
/// equality; see `expected_chunk_equality_includes_span`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExpectedChunk {
    pub message_id: i64,
    pub conversation_id: i64,
    pub chunk_idx: u32,
    pub byte_start: usize,
    pub byte_end: usize,
    pub content_hash: String,
}

/// The chunks a message *should* have, computed straight from `role_raw` +
/// `content` (no DB access). Empty when the role is out of the embedding
/// whitelist ([`canonical_role`] returns `None`) or when the normalized text
/// is empty (canonicalize's own stage-4 low-signal filter, or genuinely
/// empty/whitespace-only content). Offsets in the returned `ExpectedChunk`s
/// point into [`normalized_for_chunks`]'s output, not the raw `content`.
pub fn expected_chunks(
    message_id: i64,
    conversation_id: i64,
    role_raw: &str,
    content: &str,
) -> Vec<ExpectedChunk> {
    if canonical_role(role_raw).is_none() {
        return Vec::new();
    }

    let normalized = normalized_for_chunks(content);
    if normalized.is_empty() {
        return Vec::new();
    }

    chunk_normalized(&normalized)
        .into_iter()
        .map(|span| ExpectedChunk {
            message_id,
            conversation_id,
            chunk_idx: span.chunk_idx,
            byte_start: span.byte_start,
            byte_end: span.byte_end,
            content_hash: chunk_hash(&normalized, &span),
        })
        .collect()
}

/// The exact text [`expected_chunks`] slices its spans from -- T8/T9 must
/// use this (not re-derive normalization themselves) so span offsets stay
/// valid against whatever they slice.
pub fn normalized_for_chunks(content: &str) -> String {
    canonicalize_for_embedding(content)
}

/// Whether a message is eligible for the lexical (FTS) index: its role is
/// in the embedding whitelist AND it isn't tool-acknowledgement/short-ack
/// noise (`is_hard_message_noise`, `src/search/canonicalize.rs:687`, takes
/// the *canonical* role string per the T3 call-site contract this function
/// implements: `Some(role.as_str())`, not the raw provider role string).
pub fn lexical_eligible(role_raw: &str, content: &str) -> bool {
    match canonical_role(role_raw) {
        Some(role) => !is_hard_message_noise(Some(role.as_str()), content),
        None => false,
    }
}

/// Test-only direct evidence of how many DB pages [`for_each_expected_chunk`]
/// actually fetched (one fetch per non-empty page), read/reset by
/// `for_each_expected_chunk_streams_and_propagates_error` to assert the
/// function stops fetching once a callback returns `Err` mid-page, rather
/// than only inferring an upper bound from the callback invocation count.
#[cfg(test)]
static TEST_PAGE_FETCH_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Stream every message in `storage` (ascending `id`, `page_size` per DB
/// round trip) through [`expected_chunks`], invoking `f` once per chunk.
/// Read-only. `f` returning `Err` stops iteration immediately (no further
/// pages are fetched) and that `Err` is returned. Returns the total number
/// of chunks `f` was successfully called with.
pub fn for_each_expected_chunk<F>(
    storage: &crate::storage::sqlite::FrankenStorage,
    page_size: usize,
    mut f: F,
) -> anyhow::Result<u64>
where
    F: FnMut(ExpectedChunk) -> anyhow::Result<()>,
{
    let conn = storage.raw();
    let mut cursor_id: i64 = 0;
    let mut total_chunks: u64 = 0;

    loop {
        let rows: Vec<(i64, i64, String, String)> = conn.query_all_map(
            "SELECT id, conversation_id, role, content FROM messages WHERE id > ?1 ORDER BY id LIMIT ?2",
            &crate::storage::api::params![cursor_id, page_size],
            |row| {
                Ok((
                    row.get_typed::<i64>(0)?,
                    row.get_typed::<i64>(1)?,
                    row.get_typed::<String>(2)?,
                    row.get_typed::<String>(3)?,
                ))
            },
        )?;

        if rows.is_empty() {
            break;
        }

        #[cfg(test)]
        TEST_PAGE_FETCH_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let page_len = rows.len();
        for (message_id, conversation_id, role, content) in rows {
            cursor_id = message_id;
            for chunk in expected_chunks(message_id, conversation_id, &role, &content) {
                f(chunk)?;
                total_chunks += 1;
            }
        }

        if page_len < page_size {
            break;
        }
    }

    Ok(total_chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
    use crate::sources::provenance::LOCAL_SOURCE_ID;
    use crate::storage::sqlite::FrankenStorage;
    use std::collections::HashSet;
    use tempfile::TempDir;

    #[test]
    fn expected_chunks_reasoning_is_empty() {
        let chunks = expected_chunks(1, 1, "reasoning", "This is a long enough reasoning trace that would otherwise chunk.");
        assert!(chunks.is_empty(), "role out of the whitelist must produce no chunks");
    }

    #[test]
    fn expected_chunks_alias_roles() {
        let content = "This is an ordinary message with enough content to not be filtered as noise.";
        for role_raw in ["tool", "toolResult", "agent"] {
            let chunks = expected_chunks(1, 1, role_raw, content);
            assert!(
                !chunks.is_empty(),
                "alias role {role_raw:?} must produce chunks"
            );
        }
    }

    #[test]
    fn expected_chunks_canonicalize_empty_is_empty() {
        let chunks = expected_chunks(1, 1, "user", "OK");
        assert!(
            chunks.is_empty(),
            "canonicalize's own stage-4 low-signal filter must empty out \"OK\", so no chunks"
        );
    }

    #[test]
    fn expected_chunks_multi_chunk_hashes_distinct() {
        let content = "a".repeat(1200) + &"b".repeat(1200);
        let chunks = expected_chunks(1, 1, "user", &content);
        assert!(chunks.len() > 1, "long content must produce multiple chunks");
        let hashes: HashSet<&str> = chunks.iter().map(|c| c.content_hash.as_str()).collect();
        assert_eq!(
            hashes.len(),
            chunks.len(),
            "every chunk's content_hash must be distinct"
        );
    }

    /// Raw content is built so canonicalize_for_embedding's output is
    /// *exactly* known: a markdown header + extra blank lines that
    /// normalize to `"Title\n\n"` (7 chars), followed by plain-ASCII runs
    /// with a `\n\n`, then a `\n`, then a `' '` placed so each lands inside
    /// its chunk's separator search window -- forcing the three non-final
    /// cuts to hit paragraph/line/space respectively, in that order. The
    /// tail run (`"x"*700`) must be long enough that `remaining` after the
    /// second cut (`total_chars - 900`) still exceeds `CHUNK_CHARS` (1000)
    /// -- otherwise `chunk_normalized` short-circuits straight to a final
    /// chunk instead of doing a third windowed search.
    /// Derivation (char offsets into the *normalized* text):
    ///   [0,5)="Title" [5,7)="\n\n" [7,597)="x"*590 [597,599)="\n\n"
    ///   [599,999)="x"*400 [999,1000)="\n" [1000,1500)="x"*500
    ///   [1500,1501)=" " [1501,2201)="x"*700
    /// -> cut0=599 (paragraph, window [500,1000]), cut1=1000 (line, window
    /// [999,1499]), cut2=1501 (space, window [1400,1900]), final chunk
    /// [1401,2201) (remaining 800 <= 1000).
    #[test]
    fn expected_chunks_end_to_end_hits_paragraph_line_space_boundaries() {
        let raw = format!(
            "#  Title  \n\n\n\n{}\n\n{}\n{} {}",
            "x".repeat(590),
            "x".repeat(400),
            "x".repeat(500),
            "x".repeat(700),
        );

        let normalized = normalized_for_chunks(&raw);
        assert_eq!(
            normalized,
            format!(
                "Title\n\n{}\n\n{}\n{} {}",
                "x".repeat(590),
                "x".repeat(400),
                "x".repeat(500),
                "x".repeat(700)
            ),
            "normalization of the crafted raw content must match the hand-derived expectation"
        );

        let chunks = expected_chunks(1, 1, "user", &raw);
        assert!(chunks.len() >= 4, "expected 3 non-final cuts + 1 final chunk");

        let bytes = normalized.as_bytes();
        assert!(
            bytes[..chunks[0].byte_end].ends_with(b"\n\n"),
            "chunk 0 must end on a paragraph break"
        );
        assert!(
            bytes[..chunks[1].byte_end].ends_with(b"\n") && !bytes[..chunks[1].byte_end].ends_with(b"\n\n"),
            "chunk 1 must end on a single newline (not a paragraph break)"
        );
        assert!(
            bytes[..chunks[2].byte_end].ends_with(b" ") && !bytes[..chunks[2].byte_end].ends_with(b"\n"),
            "chunk 2 must end on a space (not a newline)"
        );

        // de-overlapped reconstruction must equal the normalized text.
        let mut reconstructed = String::new();
        for (i, c) in chunks.iter().enumerate() {
            let piece = &normalized[c.byte_start..c.byte_end];
            if i == 0 {
                reconstructed.push_str(piece);
            } else {
                let skip = 100.min(piece.chars().count());
                let skip_bytes: usize = piece.chars().take(skip).map(char::len_utf8).sum();
                reconstructed.push_str(&piece[skip_bytes..]);
            }
        }
        assert_eq!(reconstructed, normalized);
    }

    #[test]
    fn expected_chunk_equality_includes_span() {
        let a = ExpectedChunk {
            message_id: 1,
            conversation_id: 1,
            chunk_idx: 0,
            byte_start: 0,
            byte_end: 10,
            content_hash: "same-hash".to_string(),
        };
        let b = ExpectedChunk {
            message_id: 1,
            conversation_id: 1,
            chunk_idx: 1,
            byte_start: 10,
            byte_end: 20,
            content_hash: "same-hash".to_string(),
        };
        assert_ne!(
            a, b,
            "same content_hash but different span must NOT compare equal"
        );
    }

    #[test]
    fn lexical_eligible_excludes_reasoning_and_noise() {
        assert!(!lexical_eligible("reasoning", "anything at all"));
        assert!(!lexical_eligible("user", "OK"));
        assert!(!lexical_eligible("tool_result", "no matches found"));
        assert!(lexical_eligible(
            "user",
            "This is genuinely useful content worth indexing."
        ));
    }

    fn seed_storage_with_messages(count: usize) -> (TempDir, FrankenStorage) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("eligibility-fixture.db");
        let storage = FrankenStorage::open(&db_path).unwrap();

        let agent = Agent {
            id: None,
            slug: "codex".into(),
            name: "Codex".into(),
            version: Some("0.2.3".into()),
            kind: AgentKind::Cli,
        };
        let agent_id = storage.ensure_agent(&agent).unwrap();

        // Production write path (insert_conversations_batched), not hand-rolled
        // INSERT -- mirrors the existing seed_lexical_rebuild_fixture pattern
        // (src/indexer/mod.rs:22530) and lexical_rebuild_packet_* tests'
        // Agent/Conversation/Message construction.
        let per_conv = 100usize;
        let n_conv = count.div_ceil(per_conv);
        let mut conversations: Vec<Conversation> = Vec::with_capacity(n_conv);
        let mut idx = 0usize;
        for c in 0..n_conv {
            let mut messages = Vec::new();
            for _ in 0..per_conv {
                if idx >= count {
                    break;
                }
                messages.push(Message {
                    id: None,
                    idx: messages.len() as i64,
                    role: MessageRole::User,
                    author: Some("user".into()),
                    created_at: Some(1_700_000_000_000_i64 + idx as i64),
                    content: format!(
                        "message body number {idx} with enough text to survive normalization and not match any low-signal phrase."
                    ),
                    extra_json: serde_json::json!({}),
                    snippets: Vec::new(),
                });
                idx += 1;
            }
            conversations.push(Conversation {
                id: None,
                agent_slug: "codex".into(),
                workspace: Some(std::path::PathBuf::from("/tmp/workspace")),
                external_id: Some(format!("eligibility-fixture-{c}")),
                title: Some("Eligibility fixture".into()),
                source_path: std::path::PathBuf::from(format!("/tmp/eligibility-fixture-{c}.jsonl")),
                started_at: Some(1_700_000_000_000_i64),
                ended_at: Some(1_700_000_000_000_i64 + per_conv as i64),
                approx_tokens: Some(64),
                metadata_json: serde_json::Value::Null,
                messages,
                source_id: LOCAL_SOURCE_ID.into(),
                origin_host: None,
            });
        }

        let batch: Vec<(i64, Option<i64>, &Conversation)> =
            conversations.iter().map(|c| (agent_id, None, c)).collect();
        storage.insert_conversations_batched(&batch).unwrap();

        (dir, storage)
    }

    #[test]
    fn for_each_expected_chunk_streams_and_propagates_error() {
        let (_dir, storage) = seed_storage_with_messages(10_000);

        // Happy path: full streaming pass, page_size=100 -> 100 pages.
        TEST_PAGE_FETCH_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        let mut seen = 0u64;
        let total = for_each_expected_chunk(&storage, 100, |_chunk| {
            seen += 1;
            Ok(())
        })
        .expect("full pass must not error");
        assert_eq!(total, 10_000, "one chunk per synthetic message, 10,000 total");
        assert_eq!(seen, 10_000);
        assert_eq!(
            TEST_PAGE_FETCH_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            100,
            "10,000 messages / page_size 100 = 100 pages"
        );

        // Error path: callback fails on the first message of page 5
        // (message_id 401, 1-indexed ids from a fresh DB) -- must stop
        // immediately, not fetch page 6 or beyond.
        TEST_PAGE_FETCH_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        let mut callback_calls = 0u64;
        let result = for_each_expected_chunk(&storage, 100, |chunk| {
            callback_calls += 1;
            if chunk.message_id > 400 {
                anyhow::bail!("synthetic error at page 5");
            }
            Ok(())
        });
        assert!(result.is_err(), "callback Err must propagate");
        let pages_fetched = TEST_PAGE_FETCH_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            pages_fetched, 5,
            "must stop after fetching exactly the page containing the erroring message, not continue to page 6"
        );
        // Upper-bound corroboration via callback-count inference (mission's
        // fallback: page_size * pages_fetched bounds the invocation count).
        assert!(
            callback_calls <= 100 * pages_fetched as u64,
            "callback invocation count must not exceed page_size * pages_fetched"
        );
    }
}
