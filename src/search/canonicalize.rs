//! Text canonicalization for consistent embedding input.
//!
//! Delegates to [`DefaultCanonicalizer`] for the full preprocessing pipeline
//! (NFC normalization, markdown stripping that keeps link text and URLs,
//! whitespace normalization that keeps newlines, and low-signal filtering).
//! `CANONICALIZE_PIPELINE_VERSION = 2` (T1, plan v5.1): the ingest path is
//! lossless -- no length truncation and no code-block collapsing. The query
//! path (`canonicalize_query`) is unchanged and still truncates.
//!
//! This module adds content hashing on top of the shared canonicalization logic.
//!
//! # Example
//!
//! ```ignore
//! use crate::search::canonicalize::{canonicalize_for_embedding, content_hash};
//!
//! let raw = "**Hello** world!\n\n```rust\nfn main() {}\n```";
//! let canonical = canonicalize_for_embedding(raw);
//! let hash = content_hash(&canonical);
//! ```

use ring::digest::{self, SHA256};
use unicode_normalization::UnicodeNormalization;

// ============================================================================
// W3-5 verbatim restore of `frankensearch-core/src/canonicalize.rs`
// (git rev `2cad158f4468ece7076e3fe529c8e5c20b2e020e`,
// <https://github.com/Dicklesworthstone/frankensearch>), now that the
// `frankensearch` Cargo dependency itself is retired. **Canonicalize
// equivalence is load-bearing**: `content_hash` reuse across embedding
// generations assumes byte-identical canonicalization output for the same
// input, so `Canonicalizer`/`DefaultCanonicalizer` below are copied
// byte-for-byte from upstream -- zero behavior change,
// `CANONICALIZE_PIPELINE_VERSION` is NOT bumped for this move. The existing
// `content_hash`/`canonicalize_for_embedding` tests further down this file
// pass unchanged against this restored implementation, and
// `canonicalize_restore_pins_fixed_sample_hashes` below pins fixed-sample
// content hashes as a regression nail against future silent drift.
// ============================================================================

/// Low-signal content to filter out (exact matches, case-insensitive).
///
/// When the entire canonicalized text matches one of these patterns,
/// the result is an empty string (the message carries no semantic value).
const FS_LOW_SIGNAL_CONTENT: &[&str] = &[
    "ok",
    "done",
    "done.",
    "got it",
    "got it.",
    "understood",
    "understood.",
    "sure",
    "sure.",
    "yes",
    "no",
    "thanks",
    "thanks.",
    "thank you",
    "thank you.",
];

/// Trait for text preprocessing before embedding.
///
/// Custom implementations can add domain-specific preprocessing
/// (e.g., abbreviation expansion, jargon normalization).
pub trait Canonicalizer: Send + Sync {
    /// Preprocess document text for embedding.
    fn canonicalize(&self, text: &str) -> String;

    /// Preprocess a search query.
    ///
    /// Typically simpler than document canonicalization since queries
    /// are short and don't contain markdown or code blocks.
    fn canonicalize_query(&self, query: &str) -> String;
}

/// Default canonicalization pipeline (v2, lossless).
///
/// Applies NFC normalization, markdown stripping (keeping link text and
/// URLs), whitespace normalization (collapsing intra-line whitespace runs,
/// keeping newlines, folding 3+ consecutive newlines to 2), and low-signal
/// filtering. No length truncation, no code-block collapsing -- fenced code
/// block content is kept verbatim, line by line.
pub struct DefaultCanonicalizer;

impl Default for DefaultCanonicalizer {
    fn default() -> Self {
        Self
    }
}

impl Canonicalizer for DefaultCanonicalizer {
    fn canonicalize(&self, text: &str) -> String {
        // v2 (lossless): 1. NFC  2. strip markdown, keep code block content
        // and link URLs  3. normalize whitespace, keep newlines  4. filter
        // low-signal content. No truncation.
        let normalized: String = text.nfc().collect();
        let stripped = self.strip_markdown_and_code(&normalized);
        let ws_normalized = fs_normalize_whitespace(&stripped);
        fs_filter_low_signal(&ws_normalized)
    }

    fn canonicalize_query(&self, query: &str) -> String {
        // Queries are short — just NFC normalize and trim. Truncation here
        // is UNCHANGED by v2 (out of scope for the lossless-ingest change).
        let normalized: String = query.nfc().collect();
        let trimmed = normalized.trim();
        fs_truncate_to_chars(trimmed, QUERY_MAX_CHARS)
    }
}

impl DefaultCanonicalizer {
    /// Strip markdown formatting from regular text; keep fenced code block
    /// content verbatim. v2: fence marker lines are dropped, there is no
    /// head/tail collapsing, and every line (including blank ones, which
    /// matter for stage 3's 3+-newline fold) is preserved.
    fn strip_markdown_and_code(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut in_code_block = false;

        for line in text.lines() {
            if line.starts_with("```") {
                // Fence line: delete it, just toggle code-block state.
                in_code_block = !in_code_block;
                continue;
            }
            if in_code_block {
                // v2: keep code block content verbatim, line by line.
                result.push_str(line);
                result.push('\n');
            } else {
                let stripped = fs_strip_markdown_line(line);
                result.push_str(&stripped);
                result.push('\n');
            }
        }

        result
    }
}

/// Strip markdown formatting from a single line.
fn fs_strip_markdown_line(line: &str) -> String {
    let mut result = line.to_string();

    // Remove bold/italic markers
    result = result.replace("**", "");
    result = result.replace("__", "");
    result = result.replace('*', "");
    result = fs_strip_italic_underscores(&result);

    // Remove inline code backticks
    result = result.replace('`', "");

    // Convert links [text](url) to just text
    result = fs_strip_markdown_links(&result);

    // Remove headers (# prefix)
    result = result.trim_start_matches('#').trim_start().to_string();

    // Remove blockquote prefix
    result = result.trim_start_matches('>').trim_start().to_string();

    // Remove list markers
    result = fs_strip_list_marker(&result);

    result
}

/// Strip italic underscore markers (`_word_`) while preserving underscores inside
/// identifiers (`snake_case`). An underscore is treated as an italic marker only
/// when it lies on a word boundary: no adjacent alphanumeric or underscore on
/// the side facing away from the emphasized span.
fn fs_strip_italic_underscores(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut keep = vec![true; n];
    let is_word = |c: char| c.is_alphanumeric() || c == '_';

    for i in 0..n {
        if chars[i] != '_' {
            continue;
        }
        let prev_is_word = i > 0 && is_word(chars[i - 1]) && chars[i - 1] != '_';
        let next_is_word = i + 1 < n && is_word(chars[i + 1]) && chars[i + 1] != '_';
        // Opening marker: preceded by non-word (or BOL), followed by word
        // Closing marker: preceded by word, followed by non-word (or EOL)
        if (!prev_is_word && next_is_word) || (prev_is_word && !next_is_word) {
            keep[i] = false;
        }
    }

    chars
        .into_iter()
        .zip(keep)
        .filter_map(|(c, k)| if k { Some(c) } else { None })
        .collect()
}

/// Strip markdown links: `[text](url)` → `text url` (v2: keeps the URL).
fn fs_strip_markdown_links(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '[' {
            // Potential link start
            let mut link_text = String::new();
            let mut found_close = false;
            let mut bracket_depth = 1;

            for inner in chars.by_ref() {
                if inner == '[' {
                    bracket_depth += 1;
                } else if inner == ']' {
                    bracket_depth -= 1;
                    if bracket_depth == 0 {
                        found_close = true;
                        break;
                    }
                }
                link_text.push(inner);
            }

            if found_close && chars.peek() == Some(&'(') {
                // Potential URL start
                chars.next(); // consume '('
                let mut url_part = String::from("(");
                let mut depth = 1;
                let mut valid_link = false;

                for inner in chars.by_ref() {
                    url_part.push(inner);
                    match inner {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                valid_link = true;
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                if valid_link {
                    // v2: keep both link text and URL: [text](url) -> "text url"
                    result.push_str(&link_text);
                    result.push(' ');
                    // url_part is "(...)" including the outer parens; strip them.
                    result.push_str(&url_part[1..url_part.len() - 1]);
                } else {
                    // Unbalanced parens or EOF: restore everything
                    result.push('[');
                    result.push_str(&link_text);
                    result.push(']');
                    result.push_str(&url_part);
                }
            } else {
                // Not a proper link (no '(' after ']'), keep original
                result.push('[');
                result.push_str(&link_text);
                if found_close {
                    result.push(']');
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Strip markdown list markers from the start of a line.
///
/// Strips unordered (`- `, `+ `) and ordered (`1. `, `10. `) markers.
/// Does NOT strip arbitrary numbers (`3.14159` stays intact).
fn fs_strip_list_marker(line: &str) -> String {
    let trimmed = line.trim_start();

    // Check for unordered list markers: "- " or "+ "
    if let Some(rest) = trimmed.strip_prefix("- ") {
        return rest.to_string();
    }
    if let Some(rest) = trimmed.strip_prefix("+ ") {
        return rest.to_string();
    }

    // Check for ordered list markers: digits followed by ". "
    let mut chars = trimmed.chars().peekable();
    let mut digit_count = 0;

    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            digit_count += 1;
            chars.next();
        } else {
            break;
        }
    }

    // Must have at least one digit, followed by ". " (dot then space)
    if digit_count > 0 && chars.next() == Some('.') && chars.peek() == Some(&' ') {
        chars.next(); // consume the space
        return chars.collect();
    }

    // Not a list marker, return original
    line.to_string()
}

/// Normalize whitespace (v2, keeps newlines): collapse intra-line
/// whitespace runs to a single space, trim each line's head/tail, then fold
/// runs of 3+ consecutive newlines down to exactly 2 (at most one blank
/// line between paragraphs). v1 folded ALL whitespace -- including `\n` --
/// to a single space; v2 keeps `\n` as the paragraph/line-break signal.
fn fs_normalize_whitespace(text: &str) -> String {
    let mut normalized_lines: Vec<String> = Vec::with_capacity(text.len() / 16 + 1);
    for line in text.split('\n') {
        let mut out = String::with_capacity(line.len());
        let mut prev_space = true; // trim leading horizontal whitespace
        for c in line.chars() {
            if c.is_whitespace() {
                if !prev_space {
                    out.push(' ');
                    prev_space = true;
                }
            } else {
                out.push(c);
                prev_space = false;
            }
        }
        normalized_lines.push(out.trim_end().to_string());
    }
    let joined = normalized_lines.join("\n");

    // Fold runs of 3+ consecutive newlines down to exactly 2.
    let mut result = String::with_capacity(joined.len());
    let mut newline_run = 0usize;
    for c in joined.chars() {
        if c == '\n' {
            newline_run += 1;
            if newline_run <= 2 {
                result.push(c);
            }
        } else {
            newline_run = 0;
            result.push(c);
        }
    }

    result
        .trim_matches(|c: char| c == '\n' || c.is_whitespace())
        .to_string()
}

/// Filter out low-signal content.
///
/// If the entire text (after trimming and lowercasing) matches a known
/// low-signal pattern, returns empty string.
fn fs_filter_low_signal(text: &str) -> String {
    let trimmed = text.trim();
    let lower = trimmed.to_lowercase();

    for pattern in FS_LOW_SIGNAL_CONTENT {
        if lower == *pattern {
            return String::new();
        }
    }

    text.to_string()
}

/// Truncate string to at most N characters, respecting char boundaries.
fn fs_truncate_to_chars(text: &str, max_chars: usize) -> String {
    for (count, (idx, _)) in text.char_indices().enumerate() {
        if count == max_chars {
            return text[..idx].to_owned();
        }
    }
    text.to_owned()
}

/// Canonicalization pipeline version fingerprint.
///
/// Bump this whenever a commit changes the *output* of
/// [`canonicalize_for_embedding`] for any input — markdown stripping rules,
/// code block collapsing thresholds, whitespace normalization, the
/// low-signal filter table, truncation length, fast/slow path equivalence,
/// or NFC handling. A version mismatch is the explicit, checked signal that
/// `content_hash` reuse across embedding generations is unsafe (the same
/// raw text now canonicalizes to different bytes), replacing what would
/// otherwise be a silent hash-based staleness bug. Do NOT bump for changes
/// that provably do not alter output (internal caching, comments, doc-only
/// edits, test-only code).
///
/// Consumers must not assume "absent fingerprint" means "matches v1" —
/// see `R1-W3-N1` in the wave-3 plan: a manifest written before this
/// constant existed carries no fingerprint at all, and the correct
/// disposition for that case is a source-diff attestation
/// (`git diff <legacy-source-commit>..HEAD -- src/search/canonicalize.rs`),
/// not a silent pass. Runtime readiness checks therefore treat a missing
/// or mismatched fingerprint as failing generation activation by default;
/// callers that have performed the attestation stamp the accepted version
/// explicitly rather than relying on an inferred match.
pub const CANONICALIZE_PIPELINE_VERSION: u32 = 2;

/// Maximum characters to keep for a canonicalized *query* (unchanged by
/// v2 -- the ingest path no longer truncates, but the query path still
/// does; see `Canonicalizer::canonicalize_query`).
pub const QUERY_MAX_CHARS: usize = 2000;

thread_local! {
    /// Per-thread cached canonicalizer. DefaultCanonicalizer is a stateless
    /// POD (three `usize` fields), so the cost of `Default::default()` per
    /// call was pure overhead; caching it also gives a clean injection point
    /// for future input-length short-circuiting.
    static CANONICALIZER: DefaultCanonicalizer = DefaultCanonicalizer::default();
}

/// Low-signal content tokens. Must stay in sync with frankensearch's
/// `LOW_SIGNAL_CONTENT` constant; the slow path falls through to the shared
/// canonicalizer so any drift is caught by `canonicalize_for_embedding_fast_path_matches_slow_path`.
const LOW_SIGNAL_CONTENT: &[&str] = &[
    "ok",
    "done",
    "done.",
    "got it",
    "got it.",
    "understood",
    "understood.",
    "sure",
    "sure.",
    "yes",
    "no",
    "thanks",
    "thanks.",
    "thank you",
    "thank you.",
];

/// Return `Some(canonical)` when `text` can be processed by the cheap
/// whitespace-only fast path, `None` otherwise. The fast path matches the
/// output of the full `DefaultCanonicalizer` pipeline exactly when the input
/// is pure ASCII and contains no markdown discriminators.
///
/// For the dominant tool-output message shape (short plain-ASCII strings
/// without inline markdown markers, headers, links, blockquotes, or list
/// markers), this skips NFC normalization and markdown line-by-line
/// stripping — the expensive parts of the slow path — and just does
/// whitespace normalization (via the same [`fs_normalize_whitespace`] the
/// slow path uses, so the two provably agree) + low-signal filter. v2: no
/// truncation.
fn canonicalize_fast_path(text: &str) -> Option<String> {
    // Pure-ASCII check implies NFC is a no-op; any non-ASCII byte must
    // flow through the full pipeline because NFC may re-encode composed
    // characters.
    if !text.is_ascii() {
        return None;
    }
    // Any markdown discriminator byte forces the slow path. `]` is excluded
    // because on its own it's harmless; `[` is the real link start token, so
    // looking for `[` alone suffices.
    if text
        .bytes()
        .any(|b| matches!(b, b'`' | b'*' | b'_' | b'#' | b'['))
    {
        return None;
    }
    if has_markdown_line_prefix(text) {
        return None;
    }

    // v2: reuse the shared whitespace normalizer directly (keeps newlines,
    // collapses intra-line runs, folds 3+ newlines to 2) so the fast path is
    // provably byte-identical to the slow path's stage 3 output for any
    // input that reaches here (no markdown discriminator bytes and no
    // markdown line prefixes, so the slow path's stage 2 would have been a
    // no-op transform anyway).
    let collapsed = fs_normalize_whitespace(text);

    // Low-signal filter: case-insensitive ASCII match against the shared
    // pattern list. `str::eq_ignore_ascii_case` walks both operands byte-by-
    // byte and does the case-fold inline, so we avoid the `to_ascii_lowercase`
    // allocation that the previous version paid on every ack-length input.
    if !collapsed.is_empty() {
        for pattern in LOW_SIGNAL_CONTENT {
            if collapsed.eq_ignore_ascii_case(pattern) {
                return Some(String::new());
            }
        }
    }

    Some(collapsed)
}

fn has_markdown_line_prefix(text: &str) -> bool {
    text.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with('>')
            || trimmed.starts_with("- ")
            || trimmed.starts_with("+ ")
            || has_ordered_list_marker(trimmed)
    })
}

fn has_ordered_list_marker(line: &str) -> bool {
    let mut bytes = line.bytes().peekable();
    let mut saw_digit = false;

    while bytes.next_if(u8::is_ascii_digit).is_some() {
        saw_digit = true;
    }

    saw_digit && bytes.next() == Some(b'.') && bytes.next() == Some(b' ')
}

/// Canonicalize text for embedding.
///
/// Applies the full preprocessing pipeline to produce clean, consistent text
/// suitable for embedding. The output is deterministic: the same visual input
/// always produces the same output.
///
/// Hot-path: when the input is pure ASCII and contains no markdown
/// discriminator bytes, a cheap whitespace-only fast path is used and the
/// full `DefaultCanonicalizer` pipeline is skipped. The fast path is a
/// superset-preserving refinement — for any input where it fires, its output
/// is byte-identical to the slow path.
pub fn canonicalize_for_embedding(text: &str) -> String {
    if let Some(fast) = canonicalize_fast_path(text) {
        return fast;
    }
    CANONICALIZER.with(|c| c.canonicalize(text))
}

/// Compute SHA256 content hash of text.
///
/// The hash is computed on the UTF-8 bytes of the input. For consistent
/// hashing, always canonicalize text first.
pub fn content_hash(text: &str) -> [u8; 32] {
    let digest = digest::digest(&SHA256, text.as_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    hash
}

/// Compute SHA256 content hash as hex string.
///
/// Convenience wrapper around [`content_hash`] that returns a hex-encoded string.
pub fn content_hash_hex(text: &str) -> String {
    let hash = content_hash(text);
    hex::encode(hash)
}

fn is_short_acknowledgement(lower: &str) -> bool {
    matches!(
        lower,
        "ok" | "ok."
            | "okay"
            | "okay."
            | "done"
            | "done."
            | "done!"
            | "got it"
            | "got it."
            | "got it!"
            | "ack"
            | "ack."
            | "acknowledged"
            | "acknowledged."
            | "confirmed"
            | "confirmed."
            | "completed"
            | "completed."
            | "complete"
            | "complete."
    )
}

/// Return true when text is a low-value acknowledgement/tool confirmation.
///
/// These messages add little search value and tend to dominate result sets with
/// repeated "done/acknowledged/wrote file" noise.
pub fn is_tool_acknowledgement(role: Option<&str>, text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }

    if trimmed.len() > 200 {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    if is_short_acknowledgement(&lower) {
        return true;
    }

    // Tool-class classification must recognize the canonical 6-role
    // `"tool_result"` output role (and the legacy `"toolResult"` spelling), not
    // just the literal `"tool"`. The real-time lexical ingest path
    // (`search::tantivy::cass_document_for_message` /
    // `cass_document_for_packet_message`) passes the RAW `msg.role.as_str()`
    // here, which is `"tool_result"` after the unified codec. If this only
    // matched `"tool"`, real-time ingest would KEEP a `tool_result` ack that
    // the force-rebuild sink drops (it routes tool-class roles through
    // `is_lexical_rebuild_tool_class_role` and remaps to `"tool"`), diverging
    // observed vs. `expected_live_lexical_doc_count` and re-triggering the
    // cass#244/#258 sparse-repair false-positive loop. Share the SINGLE
    // source-of-truth classifier so all three sites (real-time ingest,
    // force-rebuild sink, expected-count) agree on which roles are tool output.
    let toolish = role.is_some_and(crate::storage::sqlite::is_lexical_rebuild_tool_class_role);
    let short_tool_ack = lower == "no matches found"
        || lower == "no changes made"
        || lower == "no changes"
        || lower == "already up to date"
        || lower == "up to date"
        || lower == "file written";
    if short_tool_ack && (toolish || lower.contains("file") || lower.contains("match")) {
        return true;
    }

    let prefixed_tool_ack = lower.starts_with("successfully wrote to ")
        || lower.starts_with("successfully updated ")
        || lower.starts_with("successfully created ")
        || lower.starts_with("successfully deleted ")
        || lower.starts_with("successfully saved ")
        || lower.starts_with("successfully applied ")
        || lower.starts_with("applied patch")
        || lower.starts_with("patch applied");
    prefixed_tool_ack && (toolish || lower.contains('/') || lower.contains("file"))
}

/// Return true when content looks like an injected prompt/instructions block.
///
/// We keep these messages in storage, but suppress them from normal search
/// results unless the query is clearly asking for prompt/instruction content.
pub fn is_system_prompt_text(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("# agents.md instructions for ")
        || lower.starts_with("agents.md instructions for ")
        || lower.starts_with("system prompt:")
        || lower.starts_with("developer prompt:")
        || lower.starts_with("developer message:")
        || lower.starts_with("system message:")
        || lower.contains("follow the agents.md instructions")
        || ((lower.starts_with("you are a ") || lower.starts_with("you are an "))
            && (lower.contains("assistant") || lower.contains("coding agent"))
            && (lower.contains("instructions")
                || lower.contains("follow")
                || lower.contains("must")
                || lower.contains("rules")))
}

/// Return true when a query explicitly asks for prompt/instructions content.
pub fn query_requests_system_prompt(query: &str) -> bool {
    let lower = query.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }

    lower.contains("system prompt")
        || lower.contains("developer prompt")
        || lower.contains("system message")
        || lower.contains("developer message")
        || lower.contains("system instructions")
        || lower.contains("developer instructions")
        || lower.contains("agents.md")
        || lower.contains("agents md")
        || lower.contains("claude.md")
        || lower.contains("claude md")
        || lower.contains("prompt text")
        || ((lower.starts_with("you are ") || lower.contains(" you are "))
            && (lower.contains("assistant") || lower.contains("coding agent")))
        || lower.contains("\"you are")
}

/// Noise we can safely skip during indexing.
pub fn is_hard_message_noise(role: Option<&str>, text: &str) -> bool {
    text.trim().is_empty() || is_tool_acknowledgement(role, text)
}

/// Noise we should suppress from search results.
pub fn is_search_noise_text(text: &str, query: &str) -> bool {
    let trimmed = text.trim();
    trimmed.is_empty()
        || is_tool_acknowledgement(None, trimmed)
        || (is_system_prompt_text(trimmed) && !query_requests_system_prompt(query))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_fast_path_matches_slow_path_for_pure_ascii_inputs() {
        // Every input in this table must either (a) hit the fast path and
        // match the slow path byte-for-byte, or (b) correctly fall through
        // to the slow path because it contains a markdown discriminator or
        // non-ASCII bytes. If the fast path ever diverges, this test catches
        // it before it reaches production.
        let cases = &[
            // Pure-ASCII, no markdown — fast path eligible
            "hello world",
            "  hello   world  ",
            "hello\n\n\nworld\n",
            "line one\nline two\nline three",
            "Thanks!",
            "plain text with punctuation: comma, period. question?",
            "simple-hyphen and plus+signs",
            "parens (like this) are fine",
            // Low-signal acks — fast path must return ""
            "OK",
            "ok",
            "  Done.  ",
            "got it",
            "Thanks",
            "thank you.",
            // Markdown discriminators — fall through to slow path
            "**bold** text",
            "has `inline code`",
            "# A Header",
            "list [link](url)",
            "_italic_ too",
            "> quoted text",
            ">> nested quoted text",
            "1. First item\n2. Second item",
            "  - dash item\n  + plus item",
            // Non-ASCII — fall through (NFC must run)
            "café au lait",
            "caf\u{0065}\u{0301}",
            "emoji 👋 mix",
            // Empty / whitespace-only
            "",
            "   ",
            "\n\n\n",
        ];

        for input in cases {
            let slow = CANONICALIZER.with(|c| c.canonicalize(input));
            let combined = canonicalize_for_embedding(input);
            assert_eq!(
                combined, slow,
                "canonicalize_for_embedding({input:?}) diverged from slow path"
            );
        }
    }

    #[test]
    fn test_unicode_nfc_normalization() {
        let composed = "caf\u{00E9}";
        let decomposed = "cafe\u{0301}";
        assert_ne!(composed, decomposed);
        let canon_composed = canonicalize_for_embedding(composed);
        let canon_decomposed = canonicalize_for_embedding(decomposed);
        assert_eq!(canon_composed, canon_decomposed);
    }

    #[test]
    fn test_unicode_nfc_hash_stability() {
        let composed = "caf\u{00E9}";
        let decomposed = "cafe\u{0301}";
        let hash1 = content_hash(&canonicalize_for_embedding(composed));
        let hash2 = content_hash(&canonicalize_for_embedding(decomposed));
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_canonicalize_deterministic() {
        let text = "**Hello** _world_!\n\nThis is a [link](http://example.com).";
        let result1 = canonicalize_for_embedding(text);
        let result2 = canonicalize_for_embedding(text);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_strip_markdown_bold_italic() {
        let text = "**bold** and *italic* and __also bold__";
        let canonical = canonicalize_for_embedding(text);
        assert!(!canonical.contains("**"));
        assert!(!canonical.contains("__"));
        assert!(canonical.contains("bold"));
        assert!(canonical.contains("italic"));
    }

    #[test]
    fn test_strip_markdown_links() {
        // v2: link text AND URL are both kept (v1 dropped the URL).
        let text = "Check out [this link](http://example.com) for more info.";
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains("this link"));
        assert!(canonical.contains("http://example.com"));
    }

    #[test]
    fn test_strip_markdown_headers() {
        let text = "# Header 1\n## Header 2\n### Header 3";
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains("Header 1"));
        assert!(canonical.contains("Header 2"));
        assert!(canonical.contains("Header 3"));
    }

    #[test]
    fn test_code_block_short() {
        // v2: fence lines are dropped, code content kept verbatim; no
        // "[code: lang]" label (that was tied to the removed collapse
        // formatter).
        let text = "```rust\nfn main() {\n    println!(\"Hello\");\n}\n```";
        let canonical = canonicalize_for_embedding(text);
        assert!(!canonical.contains("```"));
        assert!(canonical.contains("fn main()"));
    }

    #[test]
    fn test_code_block_no_collapse_long() {
        // v2: no head/tail collapsing regardless of block length -- every
        // line, including the middle, is kept and "lines omitted" never
        // appears.
        let mut lines = Vec::new();
        for i in 0..50 {
            lines.push(format!("line {i}"));
        }
        let code = format!("```python\n{}\n```", lines.join("\n"));
        let canonical = canonicalize_for_embedding(&code);

        assert!(canonical.contains("line 0"));
        assert!(canonical.contains("line 19"));
        assert!(canonical.contains("line 25"));
        assert!(canonical.contains("line 40"));
        assert!(canonical.contains("line 49"));
        assert!(!canonical.contains("lines omitted"));
    }

    #[test]
    fn test_whitespace_normalization() {
        let text = "hello    world\n\n\nwith   multiple   spaces";
        let canonical = canonicalize_for_embedding(text);
        assert!(!canonical.contains("  "));
        assert!(canonical.contains("hello"));
        assert!(canonical.contains("world"));
    }

    #[test]
    fn test_low_signal_filtered() {
        assert_eq!(canonicalize_for_embedding("OK"), "");
        assert_eq!(canonicalize_for_embedding("Done."), "");
        assert_eq!(canonicalize_for_embedding("Got it."), "");
        assert_eq!(canonicalize_for_embedding("Thanks!"), "Thanks!");
    }

    #[test]
    fn test_no_truncation() {
        // v2: the ingest path no longer truncates (v1 capped at 2000 chars).
        let long_text: String = "a".repeat(5000);
        let canonical = canonicalize_for_embedding(&long_text);
        assert_eq!(canonical.chars().count(), 5000);
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(canonicalize_for_embedding(""), "");
    }

    #[test]
    fn test_content_hash_deterministic() {
        let text = "Hello, world!";
        let hash1 = content_hash(text);
        let hash2 = content_hash(text);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_content_hash_different_for_different_input() {
        let hash1 = content_hash("Hello");
        let hash2 = content_hash("World");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_content_hash_hex() {
        let hex = content_hash_hex("test");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_is_tool_acknowledgement_detects_short_replies() {
        assert!(is_tool_acknowledgement(None, "OK"));
        assert!(is_tool_acknowledgement(None, "Acknowledged."));
        assert!(is_tool_acknowledgement(None, "Done!"));
        assert!(!is_tool_acknowledgement(None, "Thanks!"));
    }

    #[test]
    fn test_is_tool_acknowledgement_detects_tool_write_confirmations() {
        assert!(is_tool_acknowledgement(
            Some("tool"),
            "Successfully wrote to /tmp/output.rs"
        ));
        assert!(is_tool_acknowledgement(Some("tool"), "No matches found"));
        assert!(!is_tool_acknowledgement(
            Some("tool"),
            "Compilation failed with an auth refresh error"
        ));
    }

    #[test]
    fn test_is_tool_acknowledgement_recognizes_tool_result_role() {
        // Regression (codex Phase-2 P1 #2): the real-time lexical ingest path
        // passes the raw `"tool_result"` role (unified 6-role codec) here. Both
        // the canonical `"tool_result"` and legacy `"toolResult"` spellings must
        // be treated as tool-class, identically to
        // `storage::sqlite::is_lexical_rebuild_tool_class_role`, so real-time
        // ingest DROPS the same tool acks the force-rebuild sink drops.
        assert!(is_tool_acknowledgement(
            Some("tool_result"),
            "already up to date"
        ));
        assert!(is_tool_acknowledgement(Some("toolResult"), "up to date"));
        assert!(is_tool_acknowledgement(
            Some("tool_result"),
            "Successfully wrote to /tmp/output.rs"
        ));
        // `"tool_call"` is the assistant-side invocation, NOT tool output — it
        // must NOT be treated as tool-class (parity with the shared helper).
        assert!(!is_tool_acknowledgement(
            Some("tool_call"),
            "already up to date"
        ));
        // Non-tool roles are unchanged: a bare "already up to date" from a
        // non-tool role (and lacking file/match keywords) is not an ack.
        assert!(!is_tool_acknowledgement(
            Some("assistant"),
            "already up to date"
        ));
    }

    #[test]
    fn test_is_hard_message_noise_drops_tool_result_ack() {
        // Parity with the force-rebuild path: a `tool_result` ack is hard noise
        // that real-time ingest (`is_hard_message_noise`) must skip.
        assert!(is_hard_message_noise(
            Some("tool_result"),
            "already up to date"
        ));
    }

    #[test]
    fn test_is_system_prompt_text_detects_instruction_blocks() {
        assert!(is_system_prompt_text(
            "# AGENTS.md instructions for /repo\n\nFollow these rules carefully."
        ));
        assert!(is_system_prompt_text(
            "You are a coding assistant. You must follow the instructions exactly."
        ));
        assert!(!is_system_prompt_text(
            "You are looking at the auth module."
        ));
    }

    #[test]
    fn test_query_requests_system_prompt_matches_prompt_terms() {
        assert!(query_requests_system_prompt("AGENTS.md instructions"));
        assert!(query_requests_system_prompt("show me the system prompt"));
        assert!(query_requests_system_prompt("you are a coding assistant"));
        assert!(!query_requests_system_prompt("build instructions"));
        assert!(!query_requests_system_prompt("authentication failure"));
    }

    #[test]
    fn test_list_markers_stripped() {
        let text = "1. First item\n2. Second item\n10. Tenth item";
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains("First item"));
        assert!(canonical.contains("Second item"));
        assert!(canonical.contains("Tenth item"));
    }

    #[test]
    fn test_numbers_not_list_markers_preserved() {
        let text = "3.14159 is pi";
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains("3.14159"));
    }

    #[test]
    fn test_blockquote() {
        let text = "> This is a quote\n> spanning multiple lines";
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains("This is a quote"));
    }

    #[test]
    fn test_inline_code() {
        let text = "Use `fn main()` to start.";
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains("fn main()"));
        assert!(!canonical.contains('`'));
    }

    #[test]
    fn test_emoji_preserved() {
        let text = "Hello 👋 World 🌍";
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains('👋'));
        assert!(canonical.contains('🌍'));
    }

    #[test]
    fn test_mixed_content() {
        let text = r#"# Welcome

**Bold** and *italic* text.

```rust
fn hello() {
    println!("Hello!");
}
```

See [docs](http://docs.rs) for more.
"#;
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains("Welcome"));
        assert!(!canonical.contains("**"));
        assert!(canonical.contains("Bold"));
        assert!(canonical.contains("fn hello()"));
        assert!(canonical.contains("docs"));
        // v2: URL is kept (v1 dropped it).
        assert!(canonical.contains("http://docs.rs"));
    }

    #[test]
    fn test_unbalanced_link_preserves_content() {
        let text = "Check [link](url( unbalanced. Next sentence.";
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains("Next sentence"));
        assert!(canonical.contains("unbalanced"));
    }

    /// W3-5 regression nail: pins `content_hash_hex` for a fixed sample set
    /// spanning the fast path (pure ASCII, no markdown), the slow path
    /// (markdown/code-block/NFC-triggering input), and the low-signal filter,
    /// against the exact hex digests produced by this file's restored
    /// `DefaultCanonicalizer`/`Canonicalizer` (byte-for-byte copy of
    /// frankensearch-core's `canonicalize.rs`, git rev
    /// `2cad158f4468ece7076e3fe529c8e5c20b2e020e`). If a future edit to this
    /// file (or its `unicode-normalization`/markdown-stripping helpers)
    /// silently changes canonicalization output, this test fails loudly
    /// instead of letting stale `content_hash` reuse across embedding
    /// generations go undetected -- see `CANONICALIZE_PIPELINE_VERSION`'s
    /// doc comment above for why that matters.
    #[test]
    fn canonicalize_restore_pins_fixed_sample_hashes() {
        let cases: &[(&str, &str)] = &[
            (
                "plain ascii fast-path input",
                "b0918a54d7ef0bdada25231588aa3b681fe81c4fcb0e71731617acd1f97ba68f",
            ),
            (
                "**bold** _italic_ [link](http://example.com) and `code`\n\n```rust\nfn main() {}\n```",
                // v2 resample (T1, plan v5.1): markdown+code-block+link
                // input is exactly what v2 changes (keeps URL, keeps code
                // content, keeps newlines) -- old v1 hash was
                // f7e12d641f8d760a791219163ec59961d2cc0782651ef71d031a9f4434d6f2e3.
                "aef208e2cecd470d0a93ee28ad2a39c6d92ef41f8025d47723b28d3eef783655",
            ),
            (
                "caf\u{0065}\u{0301} au lait",
                "7c413039fbb2248e2b18b98e7a8d4d85bdcac7cd79b9477a0923f97e3a1f2b50",
            ),
            (
                "OK",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        ];
        for (input, expected_hex) in cases {
            let canonical = canonicalize_for_embedding(input);
            let hex = content_hash_hex(&canonical);
            assert_eq!(
                &hex, expected_hex,
                "content_hash_hex drifted for input {input:?} -- canonicalize equivalence broken"
            );
        }
    }

    // =========================================================================
    // T1 (plan v5.1): lossless normalization v2 -- keep newlines, no length
    // truncation, no code-block collapsing, keep link URLs. Written red
    // against the v1 pipeline first (TDD); 6 of the 7 below were red, 1
    // (query truncation) was already green because the query path is
    // explicitly unchanged by v2.
    // =========================================================================

    #[test]
    fn canonicalize_v2_keeps_code_block_middle() {
        let mut lines = Vec::new();
        for i in 0..40 {
            lines.push(format!("line {i}"));
        }
        let code = format!("```python\n{}\n```", lines.join("\n"));
        let canonical = canonicalize_for_embedding(&code);
        assert!(
            canonical.contains("line 25"),
            "v2 must keep the middle of a long code block: {canonical}"
        );
        assert!(
            !canonical.contains("lines omitted"),
            "v2 must not collapse code blocks: {canonical}"
        );
    }

    #[test]
    fn canonicalize_v2_no_length_truncation() {
        let long_text = format!("# heading\n{}", "b".repeat(2500));
        let canonical = canonicalize_for_embedding(&long_text);
        assert!(
            canonical.chars().count() > 2000,
            "v2 must not truncate to 2000 chars: got {} chars",
            canonical.chars().count()
        );
    }

    #[test]
    fn canonicalize_v2_keeps_link_url() {
        let text = "[Example](https://example.com/x?y=1)";
        let canonical = canonicalize_for_embedding(text);
        assert!(
            canonical.contains("Example"),
            "link text lost: {canonical}"
        );
        assert!(
            canonical.contains("https://example.com/x?y=1"),
            "v2 must keep the URL: {canonical}"
        );
    }

    #[test]
    fn canonicalize_v2_preserves_newlines_and_collapses_runs() {
        let text = "line one\nline two\n\n\n\n\nline three";
        let canonical = canonicalize_for_embedding(text);
        assert_eq!(canonical, "line one\nline two\n\nline three");
    }

    #[test]
    fn canonicalize_v2_markdown_strip_precedes_whitespace() {
        // A header line that strips to nothing must be treated as a blank
        // line (created by stage 2) BEFORE stage 3's 3+-newline fold runs --
        // proving strip-then-normalize ordering, not the reverse. If
        // whitespace normalization ran first, this 4-newline run would not
        // exist yet (only two independent 2-newline gaps would), so the
        // fold would never trigger and the output would keep 4 newlines.
        let text = "para one\n\n# \n\npara two";
        let canonical = canonicalize_for_embedding(text);
        assert_eq!(canonical, "para one\n\npara two");
    }

    #[test]
    fn canonicalize_v2_fast_and_slow_paths_agree_on_long_ascii() {
        let long_ascii: String = "word ".repeat(700); // > 2000 chars, pure ASCII, no markdown bytes
        assert!(long_ascii.len() > 2000);
        let fast = canonicalize_fast_path(&long_ascii).expect("must be fast-path eligible");
        let slow = CANONICALIZER.with(|c| c.canonicalize(&long_ascii));
        assert_eq!(fast, slow, "fast/slow path diverged on long ASCII input");
        assert!(
            fast.chars().count() > 2000,
            "neither path should truncate: got {} chars",
            fast.chars().count()
        );
    }

    #[test]
    fn canonicalize_query_truncation_unchanged() {
        let long_query = "q".repeat(5000);
        let canonical = CANONICALIZER.with(|c| c.canonicalize_query(&long_query));
        assert_eq!(
            canonical.chars().count(),
            2000,
            "query truncation must stay unchanged at 2000 chars"
        );
    }

    /// T1 (plan v5.1, Step 6b): `scripts/oracle/hard_noise_phrases.json` must
    /// stay in sync with the actual `is_short_acknowledgement` /
    /// `is_tool_acknowledgement` source logic it transcribes. This can't
    /// enumerate the Rust `matches!` arms directly, so it verifies the
    /// contract from both directions: every phrase/prefix the JSON claims is
    /// noise really is (per the actual functions), the counts match the
    /// frozen totals (catches JSON drift/typos), and a control phrase that
    /// is NOT noise really isn't (catches a degenerate always-true stub).
    #[test]
    fn hard_noise_phrases_json_matches_source() {
        let raw = std::fs::read_to_string("scripts/oracle/hard_noise_phrases.json")
            .expect("reading scripts/oracle/hard_noise_phrases.json");
        let doc: serde_json::Value =
            serde_json::from_str(&raw).expect("parsing hard_noise_phrases.json");

        let short_acks = doc["short_acknowledgements"]["phrases"]
            .as_array()
            .expect("short_acknowledgements.phrases must be an array");
        assert_eq!(
            short_acks.len(),
            20,
            "short_acknowledgements count drifted from source"
        );
        for phrase in short_acks {
            let phrase = phrase.as_str().expect("phrase must be a string");
            assert!(
                is_tool_acknowledgement(None, phrase),
                "short_acknowledgements phrase {phrase:?} is not recognized by is_tool_acknowledgement"
            );
        }

        let short_tool_acks = doc["short_tool_acks"]["phrases"]
            .as_array()
            .expect("short_tool_acks.phrases must be an array");
        assert_eq!(
            short_tool_acks.len(),
            6,
            "short_tool_acks count drifted from source"
        );
        for phrase in short_tool_acks {
            let phrase = phrase.as_str().expect("phrase must be a string");
            // toolish=true (role=Some("tool")) isolates the phrase-membership
            // check from the toolish/contains-file/contains-match condition.
            assert!(
                is_tool_acknowledgement(Some("tool"), phrase),
                "short_tool_acks phrase {phrase:?} is not recognized by is_tool_acknowledgement"
            );
        }

        let prefixes = doc["prefixed_tool_acks"]["prefixes"]
            .as_array()
            .expect("prefixed_tool_acks.prefixes must be an array");
        assert_eq!(
            prefixes.len(),
            8,
            "prefixed_tool_acks count drifted from source"
        );
        for prefix in prefixes {
            let prefix = prefix.as_str().expect("prefix must be a string");
            let text = format!("{prefix}/tmp/example.rs");
            assert!(
                is_tool_acknowledgement(Some("tool"), &text),
                "prefixed_tool_acks prefix {prefix:?} is not recognized by is_tool_acknowledgement"
            );
        }

        // Control: an ordinary sentence must NOT be classified as noise.
        assert!(!is_tool_acknowledgement(
            Some("assistant"),
            "The authentication module needs a retry policy."
        ));
    }

    /// Sync guard for `hard_noise_phrases.json`'s `canonicalize_low_signal`
    /// key (T1 vRulesGap-01, folded into T2, plan v5.1): freezes
    /// `FS_LOW_SIGNAL_CONTENT` (and, by the doc comment on `LOW_SIGNAL_CONTENT`
    /// pinning the two in sync, the fast-path table too) as public JSON so the
    /// T2 python oracle can implement `canonicalize()`'s stage-4 whole-text
    /// empty-output filter without reading this source file.
    #[test]
    fn low_signal_phrases_json_matches_source() {
        let raw = std::fs::read_to_string("scripts/oracle/hard_noise_phrases.json")
            .expect("reading scripts/oracle/hard_noise_phrases.json");
        let doc: serde_json::Value =
            serde_json::from_str(&raw).expect("parsing hard_noise_phrases.json");

        let phrases = doc["canonicalize_low_signal"]["phrases"]
            .as_array()
            .expect("canonicalize_low_signal.phrases must be an array");
        assert_eq!(
            phrases.len(),
            FS_LOW_SIGNAL_CONTENT.len(),
            "canonicalize_low_signal count drifted from FS_LOW_SIGNAL_CONTENT"
        );
        assert_eq!(
            phrases.len(),
            LOW_SIGNAL_CONTENT.len(),
            "canonicalize_low_signal count drifted from LOW_SIGNAL_CONTENT"
        );
        for (i, phrase) in phrases.iter().enumerate() {
            let phrase = phrase.as_str().expect("phrase must be a string");
            assert_eq!(
                phrase, FS_LOW_SIGNAL_CONTENT[i],
                "canonicalize_low_signal[{i}] order/value drifted from FS_LOW_SIGNAL_CONTENT"
            );
            assert_eq!(
                phrase, LOW_SIGNAL_CONTENT[i],
                "canonicalize_low_signal[{i}] order/value drifted from LOW_SIGNAL_CONTENT"
            );
            // Exact-case match empties out via the slow-path filter.
            assert_eq!(
                fs_filter_low_signal(phrase),
                "",
                "phrase {phrase:?} must be filtered to empty by fs_filter_low_signal"
            );
            // Case-insensitivity: an uppercased variant must also empty out.
            assert_eq!(
                fs_filter_low_signal(&phrase.to_uppercase()),
                "",
                "uppercased {phrase:?} must also be filtered to empty (case-insensitive match)"
            );
        }

        // Control: an ordinary sentence must NOT be filtered.
        assert_eq!(
            fs_filter_low_signal("The authentication module needs a retry policy."),
            "The authentication module needs a retry policy."
        );
    }
}
