//! Text canonicalization for consistent embedding input.
//!
//! Delegates to [`frankensearch::DefaultCanonicalizer`] for the full preprocessing
//! pipeline (NFC normalization, markdown stripping, code block collapsing,
//! whitespace normalization, low-signal filtering, and truncation).
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

/// Default canonicalization pipeline.
///
/// Applies NFC normalization, markdown stripping, code block collapsing,
/// whitespace normalization, low-signal filtering, and length truncation.
pub struct DefaultCanonicalizer {
    /// Maximum characters for canonicalized text. Default: 2000.
    pub max_length: usize,
    /// Maximum lines to keep from the start of a fenced code block. Default: 20.
    pub code_head_lines: usize,
    /// Maximum lines to keep from the end of a fenced code block. Default: 10.
    pub code_tail_lines: usize,
}

impl Default for DefaultCanonicalizer {
    fn default() -> Self {
        Self {
            max_length: 2000,
            code_head_lines: 20,
            code_tail_lines: 10,
        }
    }
}

impl Canonicalizer for DefaultCanonicalizer {
    fn canonicalize(&self, text: &str) -> String {
        // 1. NFC Unicode normalization (critical for hash stability)
        let normalized: String = text.nfc().collect();
        // 2. Strip markdown and collapse code blocks
        let stripped = self.strip_markdown_and_code(&normalized);
        // 3. Normalize whitespace
        let ws_normalized = fs_normalize_whitespace(&stripped);
        // 4. Filter low-signal content
        let filtered = fs_filter_low_signal(&ws_normalized);
        // 5. Truncate to max length
        fs_truncate_to_chars(&filtered, self.max_length)
    }

    fn canonicalize_query(&self, query: &str) -> String {
        // Queries are short — just NFC normalize and trim
        let normalized: String = query.nfc().collect();
        let trimmed = normalized.trim();
        fs_truncate_to_chars(trimmed, self.max_length)
    }
}

impl DefaultCanonicalizer {
    /// Strip markdown formatting and collapse code blocks.
    fn strip_markdown_and_code(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut in_code_block = false;
        let mut code_block_lang = String::new();
        let mut code_lines: Vec<&str> = Vec::new();

        for line in text.lines() {
            if line.starts_with("```") {
                if in_code_block {
                    // End of code block — collapse it
                    result.push_str(&fs_collapse_code_block(
                        &code_block_lang,
                        &code_lines,
                        self.code_head_lines,
                        self.code_tail_lines,
                    ));
                    result.push('\n');
                    code_lines.clear();
                    code_block_lang.clear();
                    in_code_block = false;
                } else {
                    // Start of code block
                    in_code_block = true;
                    code_block_lang = line.trim_start_matches('`').trim().to_string();
                }
            } else if in_code_block {
                code_lines.push(line);
            } else {
                // Strip markdown from regular text
                let stripped = fs_strip_markdown_line(line);
                if !stripped.is_empty() {
                    result.push_str(&stripped);
                    result.push('\n');
                }
            }
        }

        // Handle unclosed code block
        if in_code_block && !code_lines.is_empty() {
            result.push_str(&fs_collapse_code_block(
                &code_block_lang,
                &code_lines,
                self.code_head_lines,
                self.code_tail_lines,
            ));
            result.push('\n');
        }

        result
    }
}

/// Collapse a code block to first N + last M lines.
fn fs_collapse_code_block(lang: &str, lines: &[&str], head: usize, tail: usize) -> String {
    let lang_label = if lang.is_empty() {
        "code".to_string()
    } else {
        format!("code: {lang}")
    };

    if lines.len() <= head + tail {
        // Short enough to keep in full
        format!("[{lang_label}]\n{}", lines.join("\n"))
    } else {
        // Collapse middle
        let head_part: Vec<_> = lines.iter().take(head).copied().collect();
        let tail_part: Vec<_> = lines.iter().skip(lines.len() - tail).copied().collect();
        let omitted = lines.len() - head - tail;
        format!(
            "[{lang_label}]\n{}\n[... {omitted} lines omitted ...]\n{}",
            head_part.join("\n"),
            tail_part.join("\n")
        )
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

/// Strip markdown links: `[text](url)` → `text`.
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
                    // Valid link: [text](url) -> text
                    result.push_str(&link_text);
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

/// Normalize whitespace: collapse runs to single space, trim.
fn fs_normalize_whitespace(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut prev_whitespace = true; // Start as true to trim leading

    for c in text.chars() {
        if c.is_whitespace() {
            if !prev_whitespace {
                result.push(' ');
                prev_whitespace = true;
            }
        } else {
            result.push(c);
            prev_whitespace = false;
        }
    }

    // Trim trailing whitespace
    result.trim_end().to_string()
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
pub const CANONICALIZE_PIPELINE_VERSION: u32 = 1;

/// Maximum characters to keep after canonicalization.
pub const MAX_EMBED_CHARS: usize = 2000;

/// Maximum lines to keep from the beginning of a code block.
pub const CODE_HEAD_LINES: usize = 20;

/// Maximum lines to keep from the end of a code block.
pub const CODE_TAIL_LINES: usize = 10;

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
/// markers), this skips NFC normalization, markdown line-by-line stripping,
/// and code-block collapse — the expensive parts of the slow path — and just
/// does whitespace collapse + low-signal filter + truncation.
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

    // Whitespace-collapsed string: split_whitespace + join(' ') produces the
    // same output as the slow path's char-by-char collapse + trim.
    // Pre-size the buffer from the input length — collapsed output is always
    // <= input length for ASCII.
    let mut collapsed = String::with_capacity(text.len());
    let mut first = true;
    for token in text.split_whitespace() {
        if !first {
            collapsed.push(' ');
        }
        collapsed.push_str(token);
        first = false;
    }

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

    // Truncate to MAX_EMBED_CHARS. Pure-ASCII inputs let us slice by byte
    // index == char index.
    if collapsed.len() > MAX_EMBED_CHARS {
        collapsed.truncate(MAX_EMBED_CHARS);
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
    fn canonicalize_fast_path_truncates_to_max_embed_chars() {
        let long_ascii: String = "a ".repeat(MAX_EMBED_CHARS);
        let out = canonicalize_for_embedding(&long_ascii);
        assert!(out.chars().count() <= MAX_EMBED_CHARS);
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
        let text = "Check out [this link](http://example.com) for more info.";
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains("this link"));
        assert!(!canonical.contains("http://example.com"));
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
        let text = "```rust\nfn main() {\n    println!(\"Hello\");\n}\n```";
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains("[code: rust]"));
        assert!(canonical.contains("fn main()"));
    }

    #[test]
    fn test_code_block_collapse_long() {
        let mut lines = Vec::new();
        for i in 0..50 {
            lines.push(format!("line {i}"));
        }
        let code = format!("```python\n{}\n```", lines.join("\n"));
        let canonical = canonicalize_for_embedding(&code);

        assert!(canonical.contains("line 0"));
        assert!(canonical.contains("line 19"));
        assert!(canonical.contains("line 40"));
        assert!(canonical.contains("line 49"));
        assert!(canonical.contains("lines omitted"));
        assert!(!canonical.contains("line 25"));
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
    fn test_truncation() {
        let long_text: String = "a".repeat(5000);
        let canonical = canonicalize_for_embedding(&long_text);
        assert_eq!(canonical.chars().count(), 2000);
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
        assert!(canonical.contains("[code: rust]"));
        assert!(canonical.contains("docs"));
        assert!(!canonical.contains("http://docs.rs"));
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
                "f7e12d641f8d760a791219163ec59961d2cc0782651ef71d031a9f4434d6f2e3",
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
}
