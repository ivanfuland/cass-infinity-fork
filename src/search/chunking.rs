//! Character-recursive chunking and canonical role aliasing (T2, plan v5.1).
//!
//! Splits normalized text (already run through
//! [`crate::search::canonicalize::canonicalize_for_embedding`]) into
//! overlapping chunks for the semantic index, on Unicode scalar (`char`)
//! boundaries. Every `ChunkSpan`'s byte offsets are guaranteed to land on
//! `char` boundaries, so `chunk_text` can always slice `text` directly.

use crate::search::canonicalize::content_hash_hex;

/// Chunking policy fingerprint. Bump whenever a change alters chunk
/// boundaries or count for the same input (mirrors
/// `CANONICALIZE_PIPELINE_VERSION`'s role for canonicalization).
pub const CHUNKING_POLICY_VERSION: u32 = 1;

/// Target chunk length, in Unicode scalars (`char`s), for a non-final chunk
/// that hits a hard cut (no separator found in the search window).
pub const CHUNK_CHARS: usize = 1000;

/// Overlap between consecutive chunks, in `char`s.
pub const CHUNK_OVERLAP_CHARS: usize = 100;

/// Lower bound of the separator search window, in `char`s from the current
/// chunk's start. A non-final chunk is never shorter than this.
pub const CHUNK_MIN_SPLIT_CHARS: usize = 500;

/// The whitelisted message roles the search/embedding pipeline recognizes.
/// Any raw role string that doesn't map to one of these (see
/// [`canonical_role`]) is out of scope for chunking/embedding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CanonicalRole {
    User,
    Assistant,
    ToolCall,
    ToolResult,
}

impl CanonicalRole {
    pub fn as_str(self) -> &'static str {
        match self {
            CanonicalRole::User => "user",
            CanonicalRole::Assistant => "assistant",
            CanonicalRole::ToolCall => "tool_call",
            CanonicalRole::ToolResult => "tool_result",
        }
    }
}

/// Map a raw, provider-specific role string to a [`CanonicalRole`], or
/// `None` when the role is out of the whitelist (`reasoning`, `gemini`,
/// `info`, `error`, etc. -- these carry no embedding-eligible role).
pub fn canonical_role(raw: &str) -> Option<CanonicalRole> {
    match raw {
        "user" => Some(CanonicalRole::User),
        "assistant" | "agent" => Some(CanonicalRole::Assistant),
        "tool_call" => Some(CanonicalRole::ToolCall),
        "tool_result" | "tool" | "toolResult" => Some(CanonicalRole::ToolResult),
        _ => None,
    }
}

/// One chunk's position within its source text, in byte offsets (always on
/// `char` boundaries).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkSpan {
    pub chunk_idx: u32,
    pub byte_start: usize,
    pub byte_end: usize,
}

/// Split `text` into overlapping chunks.
///
/// Non-final chunks are `[500, 1000]` chars long: the cut point is the last
/// paragraph break (`\n\n`), else the last single newline, else the last
/// space, found within the char window `[start+500, start+1000]`; if none
/// of those exist in the window, the chunk is hard-cut at `start+1000`.
/// Each next chunk starts `CHUNK_OVERLAP_CHARS` before the previous chunk's
/// end. The final chunk (whenever the remaining text is `<= CHUNK_CHARS`
/// long) runs to the end of the text and is not itself overlapped by a
/// further chunk. Empty input produces an empty `Vec`.
pub fn chunk_normalized(text: &str) -> Vec<ChunkSpan> {
    if text.is_empty() {
        return Vec::new();
    }

    // char_idx -> (byte_offset, char), built once so every subsequent
    // window search is a slice into this, not a re-scan of `text` from the
    // start (which would make chunking a long message O(n^2)).
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let total_chars = chars.len();
    let byte_len = text.len();

    let byte_at = |char_idx: usize| -> usize {
        if char_idx >= total_chars {
            byte_len
        } else {
            chars[char_idx].0
        }
    };

    let mut spans = Vec::new();
    let mut start_char = 0usize;
    let mut chunk_idx: u32 = 0;

    loop {
        let remaining = total_chars - start_char;
        if remaining <= CHUNK_CHARS {
            spans.push(ChunkSpan {
                chunk_idx,
                byte_start: byte_at(start_char),
                byte_end: byte_len,
            });
            break;
        }

        let window_start = start_char + CHUNK_MIN_SPLIT_CHARS;
        let window_end = start_char + CHUNK_CHARS;

        // `e` is a candidate cut position: the char index right after the
        // separator character at `chars[e - 1]`. Scanning left-to-right and
        // overwriting on each match naturally keeps the *last* occurrence
        // of each separator kind within the window.
        let mut last_parabreak: Option<usize> = None;
        let mut last_newline: Option<usize> = None;
        let mut last_space: Option<usize> = None;

        let scan_upper = window_end.min(total_chars);
        for e in window_start.max(1)..=scan_upper {
            match chars[e - 1].1 {
                '\n' => {
                    last_newline = Some(e);
                    if e >= 2 && chars[e - 2].1 == '\n' {
                        last_parabreak = Some(e);
                    }
                }
                ' ' => {
                    last_space = Some(e);
                }
                _ => {}
            }
        }

        let end_char = last_parabreak
            .or(last_newline)
            .or(last_space)
            .unwrap_or(window_end);

        spans.push(ChunkSpan {
            chunk_idx,
            byte_start: byte_at(start_char),
            byte_end: byte_at(end_char),
        });

        chunk_idx += 1;
        start_char = end_char - CHUNK_OVERLAP_CHARS;
    }

    spans
}

/// Slice `text` for `span`. `span`'s offsets must have come from
/// [`chunk_normalized`] run on this exact `text` (byte offsets are only
/// guaranteed valid `char` boundaries for the text they were computed on).
pub fn chunk_text<'a>(text: &'a str, span: &ChunkSpan) -> &'a str {
    &text[span.byte_start..span.byte_end]
}

/// SHA-256 hex digest of the chunk's text (reuses
/// [`content_hash_hex`], the same hasher canonicalization uses).
pub fn chunk_hash(text: &str, span: &ChunkSpan) -> String {
    content_hash_hex(chunk_text(text, span))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_covers_and_overlaps(text: &str) {
        let spans = chunk_normalized(text);
        let total_chars = text.chars().count();

        if text.is_empty() {
            assert!(spans.is_empty(), "empty input must produce an empty Vec");
            return;
        }

        assert!(!spans.is_empty(), "non-empty input must produce >=1 chunk");

        // chunk_idx monotonic from 0
        for (i, span) in spans.iter().enumerate() {
            assert_eq!(span.chunk_idx as usize, i, "chunk_idx must be monotonic from 0");
        }

        // all offsets on char boundaries
        for span in &spans {
            assert!(
                text.is_char_boundary(span.byte_start),
                "byte_start {} not a char boundary",
                span.byte_start
            );
            assert!(
                text.is_char_boundary(span.byte_end),
                "byte_end {} not a char boundary",
                span.byte_end
            );
        }

        // non-final chunk length in [500, 1000] chars; adjacent-chunk
        // 100-char overlap equality (skip the final chunk for both, per
        // spec: "末块除外").
        for i in 0..spans.len() {
            let is_final = i == spans.len() - 1;
            let chunk_str = chunk_text(text, &spans[i]);
            let chunk_char_len = chunk_str.chars().count();
            if !is_final {
                assert!(
                    (CHUNK_MIN_SPLIT_CHARS..=CHUNK_CHARS).contains(&chunk_char_len),
                    "non-final chunk {i} length {chunk_char_len} not in [{CHUNK_MIN_SPLIT_CHARS}, {CHUNK_CHARS}]"
                );
                let next = &spans[i + 1];
                // Frozen policy value (NOT `CHUNK_OVERLAP_CHARS`): this check
                // must independently pin "overlap == 100 chars" so a
                // mutation to the constant itself (e.g. 100 -> 99) reddens
                // this property test rather than silently staying green
                // because it's self-referentially checking against whatever
                // the constant currently says.
                const FROZEN_OVERLAP_CHARS: usize = 100;
                let this_tail: String = chunk_str
                    .chars()
                    .rev()
                    .take(FROZEN_OVERLAP_CHARS)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                let next_str = chunk_text(text, next);
                let next_head: String = next_str.chars().take(FROZEN_OVERLAP_CHARS).collect();
                assert_eq!(
                    this_tail, next_head,
                    "chunk {i}'s last {FROZEN_OVERLAP_CHARS} chars must equal chunk {}'s first {FROZEN_OVERLAP_CHARS} chars",
                    i + 1
                );
            }
        }

        // reconstruct by dropping the overlapping head of every chunk after
        // the first, and concatenating -- must equal the original text
        // byte-for-byte.
        let mut reconstructed = String::new();
        for (i, span) in spans.iter().enumerate() {
            let piece = chunk_text(text, span);
            if i == 0 {
                reconstructed.push_str(piece);
            } else {
                let skip_chars = CHUNK_OVERLAP_CHARS.min(piece.chars().count());
                let tail: String = piece.chars().skip(skip_chars).collect();
                reconstructed.push_str(&tail);
            }
        }
        assert_eq!(
            reconstructed.as_bytes(),
            text.as_bytes(),
            "de-overlapped reconstruction must equal original text byte-for-byte"
        );

        // every char covered by >=1 chunk: total_chars participate, which
        // the byte-exact reconstruction above already proves; belt-and-
        // suspenders direct check on char count too.
        assert_eq!(reconstructed.chars().count(), total_chars);
    }

    #[test]
    fn chunking_properties_cover_and_overlap() {
        let lengths = [
            0usize, 1, 999, 1000, 1001, 1099, 1100, 1101, 1500, 5000,
        ];
        for &n in &lengths {
            let text: String = "a".repeat(n);
            assert_covers_and_overlaps(&text);
        }
        // n x 900 +/- 1 for a handful of n, to exercise the "next_start
        // lands exactly on a fresh window" family of boundaries.
        for n in 1..=5usize {
            let base = n * 900;
            for delta in [-1i64, 0, 1] {
                let len = (base as i64 + delta).max(0) as usize;
                let text: String = "b".repeat(len);
                assert_covers_and_overlaps(&text);
            }
        }
        // multi-byte / emoji / NFC / NFD / no-newline-no-space continuous text
        let multibyte = "你好世界".repeat(400); // 4 chars * 400 = 1600 chars, 3 bytes/char
        assert_covers_and_overlaps(&multibyte);
        let emoji = "\u{1F600}\u{1F601}\u{1F602}".repeat(400); // 1200 chars, 4 bytes/char
        assert_covers_and_overlaps(&emoji);
        let nfc = "\u{00E9}".repeat(1300); // precomposed é
        assert_covers_and_overlaps(&nfc);
        let nfd = "e\u{0301}".repeat(1300); // decomposed e + combining acute (2 chars each)
        assert_covers_and_overlaps(&nfd);
        let no_seps: String = "x".repeat(3000); // continuous, no newline/space at all
        assert_covers_and_overlaps(&no_seps);
    }

    #[test]
    fn chunking_prefers_paragraph_then_line_then_space() {
        // Case 1: a paragraph break, a single newline, and a space are all
        // present in the search window -- paragraph break wins.
        let mut s = String::new();
        s.push_str(&"a".repeat(600)); // 0..600
        s.push_str("\n\n"); // 600..602 paragraph break (within [500,1000])
        s.push_str(&"b".repeat(50)); // 602..652
        s.push('\n'); // 652..653 single newline (also within window)
        s.push_str(&"c".repeat(50)); // 653..703
        s.push(' '); // 703..704 space (also within window)
        s.push_str(&"d".repeat(400)); // pad past 1000 so this isn't the final chunk
        let text = s;
        let spans = chunk_normalized(&text);
        assert!(spans.len() >= 2, "need at least 2 chunks to inspect the first cut");
        assert_eq!(
            spans[0].byte_end, 602,
            "paragraph break must win over a later single newline and space in the same window"
        );

        // Case 2: no paragraph break, but a single newline and a space are
        // present -- single newline wins over space.
        let mut s2 = String::new();
        s2.push_str(&"a".repeat(600));
        s2.push('\n'); // 600..601
        s2.push_str(&"b".repeat(100));
        s2.push(' '); // 701..702
        s2.push_str(&"c".repeat(400));
        let text2 = s2;
        let spans2 = chunk_normalized(&text2);
        assert!(spans2.len() >= 2);
        assert_eq!(
            spans2[0].byte_end, 601,
            "single newline must win over a later space in the same window"
        );

        // Case 3: only a space in the window -- space wins over hard cut.
        let mut s3 = String::new();
        s3.push_str(&"a".repeat(700));
        s3.push(' '); // 700..701
        s3.push_str(&"b".repeat(500));
        let text3 = s3;
        let spans3 = chunk_normalized(&text3);
        assert!(spans3.len() >= 2);
        assert_eq!(spans3[0].byte_end, 701, "space must be used when it's the only separator in the window");
    }

    #[test]
    fn chunking_early_separator_does_not_stall() {
        // A paragraph break at char 50 is well before the search window
        // [500, 1000] for the first chunk, so it must be ignored; the next
        // 2000 chars have no separator at all, so the first chunk must
        // hard-cut at 1000 and the second chunk must start at 900.
        let mut s = String::new();
        s.push_str(&"a".repeat(48));
        s.push_str("\n\n"); // ends at char 50
        s.push_str(&"b".repeat(2000));
        let text = s;

        let spans = chunk_normalized(&text);
        assert!(spans.len() >= 2);
        assert_eq!(
            spans[0].byte_end, 1000,
            "early separator outside the window must not be used; must hard-cut at 1000"
        );
        assert_eq!(
            spans[1].byte_start, 900,
            "second chunk must start at end(1000) - overlap(100) = 900"
        );
    }

    #[test]
    fn role_alias_table() {
        assert_eq!(canonical_role("user"), Some(CanonicalRole::User));
        assert_eq!(canonical_role("assistant"), Some(CanonicalRole::Assistant));
        assert_eq!(canonical_role("agent"), Some(CanonicalRole::Assistant));
        assert_eq!(canonical_role("tool_call"), Some(CanonicalRole::ToolCall));
        assert_eq!(canonical_role("tool_result"), Some(CanonicalRole::ToolResult));
        assert_eq!(canonical_role("tool"), Some(CanonicalRole::ToolResult));
        assert_eq!(canonical_role("toolResult"), Some(CanonicalRole::ToolResult));
        assert_eq!(canonical_role("reasoning"), None);
        assert_eq!(canonical_role("gemini"), None);
        assert_eq!(canonical_role("info"), None);
        assert_eq!(canonical_role("error"), None);
    }

    #[test]
    fn chunk_hash_matches_content_hash_hex() {
        let text = "hello world";
        let spans = chunk_normalized(text);
        assert_eq!(spans.len(), 1);
        let expected = content_hash_hex(chunk_text(text, &spans[0]));
        assert_eq!(chunk_hash(text, &spans[0]), expected);
    }

    /// 60 deterministic samples spanning CN/EN prose, fenced code, emoji,
    /// well-formed and malformed markdown, and `canonicalize_low_signal`
    /// hard-noise phrases -- the fixed cross-implementation consistency
    /// suite `tests/fixtures/chunking_samples.json` compares against
    /// (`scripts/oracle/normalize_v2.py`, T2, plan v5.1 Step 5).
    fn build_chunking_samples() -> Vec<String> {
        let mut v = Vec::new();

        // 15: CN / EN / mixed prose, deliberately long enough (via repeat)
        // to force multiple chunks for several of them.
        for i in 0..15usize {
            let s = match i % 3 {
                0 => "你好世界，这是一个测试消息，用来验证分块与规范化的行为是否正确。"
                    .repeat(1 + i * 3),
                1 => "Hello world, this is a test message about the search index and chunking pipeline. "
                    .repeat(1 + i * 3),
                _ => "混合 mixed 内容 content 测试 test 消息 message，包含中英文交替出现的情况。 "
                    .repeat(1 + i * 3),
            };
            v.push(s);
        }

        // 10: fenced code blocks (short / long-enough-to-exceed-30-lines /
        // medium), embedded with surrounding prose to exercise the
        // fence-line-dropped-but-content-verbatim rule.
        for i in 0..10usize {
            let n_lines = match i % 3 {
                0 => 5,
                1 => 35,
                _ => 12,
            };
            let mut code = String::from("Here is some code:\n```rust\n");
            for l in 1..=n_lines {
                code.push_str(&format!("let x{l} = {l}; // line {l} of the snippet\n"));
            }
            code.push_str("```\nEnd of snippet.");
            v.push(code);
        }

        // 10: emoji-heavy (multi-byte, non-ASCII forces the slow path).
        let emojis = ["😀", "😁", "😂", "🚀", "🔥", "✨", "🎉", "🐛", "✅", "❌"];
        for (i, e) in emojis.iter().enumerate() {
            v.push(e.repeat(50 + i * 30));
        }

        // 15: well-formed and malformed markdown.
        let markdown_samples = [
            "# Title\n\nSome **bold** and _italic_ text with a [link](http://example.com/path).",
            "## Subheading\n\n> A blockquote line\n> continues here.",
            "- item one\n- item two\n+ item three\n1. numbered item",
            "Unclosed **bold marker and *italic without close",
            "Malformed [link text without closing paren(http://x.com",
            "### Header with `inline code` and __bold underscore__.",
            "Mixed: not a header because no space after hash #NoSpace vs # Real Header",
            "Nested markers: **bold *italic inside bold* still bold**.",
            "> Quote\n# Header inside quote context\n- list under quote",
            "Plain paragraph with an unclosed_underscore_ marker and *dangling star",
            "[text](url) followed by more [second](url2) links in one line.",
            "**a** *b* __c__ _d_ combined emphasis in one short line.",
            "```\nfenced with no language tag\nline two\n```\nafter fence text.",
            "1. first\n2. second\n3. third\nwith trailing prose after the list.",
            "not a header (no space, e.g. #123), but # 456 is a header.",
        ];
        for s in markdown_samples {
            v.push(s.to_string());
        }

        // 10: `canonicalize_low_signal` hard-noise phrases (case variations),
        // each expected to normalize to the empty string (stage 4).
        let noise = [
            "OK", "Ok.", "DONE", "Thanks.", "YES", "no", "Sure", "Understood.",
            "Thank You.", "Got it.",
        ];
        for s in noise {
            v.push(s.to_string());
        }

        v
    }

    #[test]
    fn chunking_samples_frozen() {
        let samples = build_chunking_samples();
        assert_eq!(samples.len(), 60, "must have exactly 60 frozen samples");

        let mut records = Vec::new();
        for input in &samples {
            let normalized = crate::search::canonicalize::canonicalize_for_embedding(input);
            let spans = chunk_normalized(&normalized);
            let span_pairs: Vec<serde_json::Value> = spans
                .iter()
                .map(|s| serde_json::json!([s.byte_start, s.byte_end]))
                .collect();
            records.push(serde_json::json!({
                "input": input,
                "normalized": normalized,
                "spans": span_pairs,
            }));
        }
        let computed = serde_json::Value::Array(records);

        let path = "tests/fixtures/chunking_samples.json";
        match std::fs::read_to_string(path) {
            Ok(existing) => {
                let existing_value: serde_json::Value = serde_json::from_str(&existing)
                    .expect("parsing existing tests/fixtures/chunking_samples.json");
                assert_eq!(
                    existing_value, computed,
                    "tests/fixtures/chunking_samples.json has drifted from current \
                     canonicalize_for_embedding + chunk_normalized output -- if this is an \
                     intentional v2/policy change, regenerate the file (delete it and rerun \
                     this test) and note it in the commit message"
                );
            }
            Err(_) => {
                std::fs::create_dir_all("tests/fixtures").expect("creating tests/fixtures dir");
                let pretty = serde_json::to_string_pretty(&computed)
                    .expect("serializing chunking_samples.json");
                std::fs::write(path, pretty)
                    .expect("writing tests/fixtures/chunking_samples.json");
            }
        }
    }
}
