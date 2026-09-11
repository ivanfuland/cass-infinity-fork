//! Text canonicalization for consistent embedding input.
//!
//! Delegates to [`DefaultCanonicalizer`] for the full preprocessing pipeline
//! (NFC normalization, markdown stripping that keeps link text and URLs,
//! whitespace normalization that keeps newlines, and low-signal filtering).
//! `CANONICALIZE_PIPELINE_VERSION = 3` (T1, plan v5.1; v3: PR6 T3, 任务书
//! #121a): the ingest path is lossless -- no length truncation and no
//! code-block collapsing.
//!
//! **Two distinct "query" things, not one** (R1-N5 fix, T2 code-ledger
//! finding): the actual production query path
//! (`src/search/query.rs:4162`) calls [`canonicalize_for_embedding`] --
//! the same, non-truncating, v3 function documented above and in
//! `scripts/oracle/normalize_v3_rules.md` -- so production queries are
//! NOT truncated. `Canonicalizer::canonicalize_query` (below) is a
//! separate function that still truncates to [`QUERY_MAX_CHARS`]; it has
//! exactly one caller left in `src/`, a test in this file
//! (`canonicalize_query_truncation_unchanged`). It is kept, unmodified,
//! for that test's sake, not because production queries go through it.
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
    "wait timed out",
    "bash completed with no output",
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
            if fs_is_fence_marker(line) {
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

/// Fenced code block fence-marker recognition (R1, v3): a line is a fence
/// marker when it has at most 3 leading spaces followed immediately by
/// `` ``` `` -- CommonMark's own fence-indentation tolerance. Pre-v3 this
/// required the marker at column 0 exactly (`line.starts_with("```")`), so
/// an indented fence fell through to ordinary per-line stripping instead of
/// toggling the code-block state.
fn fs_is_fence_marker(line: &str) -> bool {
    let trimmed = line.trim_start_matches(' ');
    let leading_spaces = line.len() - trimmed.len();
    leading_spaces <= 3 && trimmed.starts_with("```")
}

/// ATX header recognition and stripping (R2, v3): a line is a header when it
/// matches at most 3 leading spaces, then 1-6 `#` characters, then either a
/// space or end-of-line. On a match, the `#` run and (if present) one
/// following space are removed; everything else -- including the leading
/// spaces -- is kept verbatim. A line that does not match this shape is
/// returned completely unchanged.
///
/// Pre-v3 this was `result.trim_start_matches('#').trim_start()`: it
/// required the `#` at byte 0 (so any leading whitespace defeated
/// recognition entirely, while the unconditional trailing `.trim_start()`
/// still silently ate that whitespace anyway), had no 1-6 count cap, and
/// never checked for a following space/end-of-line -- wrong in both
/// directions (under-strips an indented real header, over-strips a `#` that
/// isn't a heading marker at all, e.g. a shebang or issue reference).
fn fs_strip_atx_header(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] == b' ' && i < 3 {
        i += 1;
    }
    let hash_start = i;
    let mut hash_count = 0;
    while i < bytes.len() && bytes[i] == b'#' && hash_count < 6 {
        i += 1;
        hash_count += 1;
    }
    if hash_count == 0 {
        return line.to_string();
    }
    // A 7th (or later) consecutive '#' disqualifies the whole run -- it's
    // not a 1-6-count heading marker at all.
    if i < bytes.len() && bytes[i] == b'#' {
        return line.to_string();
    }
    // Must be followed by a space or end-of-line.
    if i < bytes.len() && bytes[i] != b' ' {
        return line.to_string();
    }
    let rest_start = if i < bytes.len() { i + 1 } else { i };
    format!("{}{}", &line[..hash_start], &line[rest_start..])
}

/// Paired backtick-run stripping (R3, v3): a run of N consecutive backticks
/// pairs with the *next* run of exactly N consecutive backticks encountered
/// scanning forward (any non-backtick content, and any differently-sized
/// backtick run, may sit between them); both runs are deleted and the
/// content between them is kept verbatim. A run with no same-length partner
/// later in the line is left untouched, backticks included. This is only
/// equal-length run pairing -- deliberately not full CommonMark
/// inline-code-span semantics (no leading/trailing single-space stripping,
/// no backslash escaping).
///
/// Pre-v3 this was `result.replace('`', "")`: every backtick removed
/// unconditionally, paired or not.
fn fs_strip_paired_backticks(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let n = chars.len();

    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < n {
        if chars[i] == '`' {
            let start = i;
            let mut len = 0;
            while i < n && chars[i] == '`' {
                i += 1;
                len += 1;
            }
            runs.push((start, len));
        } else {
            i += 1;
        }
    }

    let mut delete = vec![false; runs.len()];
    let mut idx = 0;
    while idx < runs.len() {
        if delete[idx] {
            idx += 1;
            continue;
        }
        let len_a = runs[idx].1;
        let partner = ((idx + 1)..runs.len()).find(|&j| !delete[j] && runs[j].1 == len_a);
        if let Some(j) = partner {
            delete[idx] = true;
            delete[j] = true;
        }
        idx += 1;
    }

    let mut result = String::with_capacity(line.len());
    let mut pos = 0;
    for (k, &(start, len)) in runs.iter().enumerate() {
        if delete[k] {
            result.extend(chars[pos..start].iter().copied());
            pos = start + len;
        }
    }
    result.extend(chars[pos..n].iter().copied());
    result
}

/// Strip markdown formatting from a single line.
fn fs_strip_markdown_line(line: &str) -> String {
    let mut result = line.to_string();

    // Remove bold/italic markers, then run the shared single-marker
    // neighbor rule (R4) over whatever `*`/`_` remain.
    result = result.replace("**", "");
    result = result.replace("__", "");
    result = fs_strip_italic_underscores(&result);

    // Remove paired backtick runs (R3).
    result = fs_strip_paired_backticks(&result);

    // Convert links [text](url) to just text
    result = fs_strip_markdown_links(&result);

    // Remove headers (R2).
    result = fs_strip_atx_header(&result);

    // Remove blockquote prefix
    result = result.trim_start_matches('>').trim_start().to_string();

    // Remove list markers
    result = fs_strip_list_marker(&result);

    result
}

/// Strip single `*`/`_` emphasis markers (`_word_`, `*word*`) while
/// preserving them inside identifiers/tokens (`snake_case`, `a*b`). A marker
/// is treated as an opening/closing emphasis marker -- and deleted -- only
/// when it lies on a word boundary: *exactly one* immediate neighbor is
/// Unicode-alphanumeric (a missing neighbor at line start/end counts as
/// "not alphanumeric"); when both neighbors are alphanumeric, or neither
/// is, the marker is kept.
///
/// R4 (v3): `*` now goes through this same rule (call site no longer does a
/// separate unconditional `result.replace('*', "")` first). Pre-v3 this
/// function only handled `_`, and had an extra special case treating an
/// immediately-adjacent `_` as "not a word neighbor" (via `is_word(c) = c
/// .is_alphanumeric() || c == '_'` combined with `&& c != '_'` at each call
/// site). That combination is algebraically identical to plain
/// `c.is_alphanumeric()` for every possible `c` -- the `c == '_'` disjunct
/// of `is_word` is always cancelled by the `&& c != '_'` guard -- so the
/// special case was already a no-op; dropped here (see
/// `canonicalize_v3_underscore_adjacent_underscore_special_case_is_unreachable`
/// for the pinned before/after examples that would have distinguished it,
/// had it ever mattered).
fn fs_strip_italic_underscores(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut keep = vec![true; n];
    let is_marker = |c: char| c == '_' || c == '*';

    for i in 0..n {
        if !is_marker(chars[i]) {
            continue;
        }
        let prev_is_word = i > 0 && chars[i - 1].is_alphanumeric();
        let next_is_word = i + 1 < n && chars[i + 1].is_alphanumeric();
        // Opening marker: preceded by non-word (or BOL), followed by word
        // Closing marker: preceded by word, followed by non-word (or EOL)
        if prev_is_word != next_is_word {
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
pub const CANONICALIZE_PIPELINE_VERSION: u32 = 3;

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
    "wait timed out",
    "bash completed with no output",
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
        || lower == "file written"
        || lower == "wait timed out"
        || lower == "bash completed with no output";
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

    /// PR6 T1 (任务书 #111): two new hard-noise receipts must be recognized
    /// on both sides -- the lexical/word-level side (`is_hard_message_noise`,
    /// whose real source is `is_short_acknowledgement` at :558) and the
    /// block/embedding side (`canonicalize_for_embedding`, which must hit the
    /// pure-ASCII fast path since both phrases contain no markdown
    /// discriminator bytes or non-ASCII bytes).
    #[test]
    fn hard_noise_two_receipts_are_noise_on_both_sides() {
        assert!(
            is_hard_message_noise(Some("tool_result"), "Wait timed out"),
            "lexical side: \"Wait timed out\" must be hard message noise"
        );
        assert!(
            is_hard_message_noise(Some("tool_result"), "Bash completed with no output"),
            "lexical side: \"Bash completed with no output\" must be hard message noise"
        );

        assert_eq!(
            canonicalize_for_embedding("Wait timed out"),
            "",
            "block side: \"Wait timed out\" must canonicalize to empty"
        );
        assert_eq!(
            canonicalize_for_embedding("Bash completed with no output"),
            "",
            "block side: \"Bash completed with no output\" must canonicalize to empty"
        );

        // Both phrases must be fast-path eligible (pure ASCII, no markdown
        // discriminator bytes) so this test actually exercises the fast path,
        // not a fallthrough to the slow pipeline.
        assert!(
            canonicalize_fast_path("Wait timed out").is_some(),
            "\"Wait timed out\" must be fast-path eligible"
        );
        assert!(
            canonicalize_fast_path("Bash completed with no output").is_some(),
            "\"Bash completed with no output\" must be fast-path eligible"
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
            8,
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

    // =========================================================================
    // T3 v3 (任务书 #121a, `scripts/oracle/normalize_v3_rules.md` R1-R4): fence
    // indentation tolerance, ATX header recognition, paired backtick runs,
    // and a unified `*`/`_` neighbor rule. Written red against v2 first
    // (TDD); each positive case here also serves as its own regression
    // guard against reverting to the corresponding v2 behavior.
    // =========================================================================

    #[test]
    fn canonicalize_v3_fence_tolerates_up_to_three_space_indent() {
        let text = " ```\nindented fence body\n ```\nafter";
        let canonical = canonicalize_for_embedding(text);
        assert_eq!(
            canonical, "indented fence body\nafter",
            "a fence indented by <=3 spaces must be recognized (R1) and its \
             body kept verbatim, matching the already-correct column-0 case"
        );
    }

    #[test]
    fn canonicalize_v3_fence_four_space_indent_not_recognized() {
        // 4 spaces exceeds R1's <=3 tolerance -- this codebase does not
        // implement CommonMark indented-code-block recognition, so a >3
        // space line still falls through to ordinary per-line stripping
        // (same as v2's column-0 rule did for any indent at all). Not a
        // v2/v3 diff -- a boundary check that R1's tolerance is exactly
        // <=3, not unlimited.
        let text = "    ```\nbody\n    ```\nafter";
        let canonical = canonicalize_for_embedding(text);
        assert!(canonical.contains("body"));
        assert!(canonical.contains("after"));
        assert!(
            canonical.contains("```"),
            "R1's <=3-space tolerance excludes a 4-space indent, so these \
             lines are not recognized as fences; R3's paired-backtick rule \
             then finds no partner for either lone length-3 backtick run \
             (each line only has one run of its own) and leaves it \
             untouched -- unlike v2's unconditional backtick deletion, \
             which would have erased it either way. Got: {canonical:?}"
        );
    }

    #[test]
    fn canonicalize_v3_header_tolerates_leading_indent_and_caps_hash_run() {
        assert_eq!(
            canonicalize_for_embedding(" ## docs/m7-arch"),
            "docs/m7-arch",
            "R2: <=3 leading spaces + 1-6 '#' + space must be recognized as \
             a header (stage 2 keeps the leading space as 'everything \
             else', but stage 3's per-line leading-whitespace trim removes \
             it from the final canonicalize_for_embedding output either way)"
        );
        assert_eq!(
            canonicalize_for_embedding("#!/usr/bin/env bash"),
            "#!/usr/bin/env bash",
            "R2: '#' not followed by a space/EOL is not a header marker at \
             all and must be left completely untouched"
        );
        assert_eq!(
            canonicalize_for_embedding("#76"),
            "#76",
            "R2: '#' immediately followed by a digit (not a space/EOL) must \
             be left untouched"
        );
        assert_eq!(
            canonicalize_for_embedding("####### not a heading"),
            "####### not a heading",
            "R2: 7 consecutive '#'s exceed the 1-6 count cap, so the whole \
             line is left untouched, not partially stripped"
        );
        assert_eq!(
            canonicalize_for_embedding("## Real Heading"),
            "Real Heading",
            "R2: a genuine column-0, in-range, space-terminated header must \
             still strip correctly (regression check, not a v3 change)"
        );
    }

    #[test]
    fn canonicalize_v3_backtick_pairs_by_equal_run_length_only() {
        assert_eq!(
            canonicalize_for_embedding("`code`"),
            "code",
            "R3: two length-1 runs pair with each other and both delete"
        );
        assert_eq!(
            canonicalize_for_embedding("text with `one backtick"),
            "text with `one backtick",
            "R3: an unpaired backtick (no later run of the same length) is \
             left in place, not deleted"
        );
        assert_eq!(
            canonicalize_for_embedding("``a`b``"),
            "a`b",
            "R3: the two length-2 runs pair with EACH OTHER, skipping over \
             the length-1 run in between (which has no partner of its own \
             and survives as literal content)"
        );
    }

    #[test]
    fn canonicalize_v3_asterisk_and_underscore_share_neighbor_rule() {
        assert_eq!(
            canonicalize_for_embedding("*bold*"),
            "bold",
            "boundary case: exactly one side alphanumeric on each marker -- \
             strips, same output v2's unconditional removal happened to \
             already produce here"
        );
        assert_eq!(
            canonicalize_for_embedding("a*b"),
            "a*b",
            "R4: both neighbors alphanumeric -- '*' must now be preserved, \
             matching '_'s existing rule (v2 deleted every '*' \
             unconditionally regardless of neighbors)"
        );
        assert_eq!(
            canonicalize_for_embedding("5*3"),
            "5*3",
            "R4: digit neighbors on both sides -- preserved"
        );
        assert_eq!(
            canonicalize_for_embedding("snake_case"),
            "snake_case",
            "regression check: '_' already had this rule pre-v3, must still \
             hold once merged with '*' into one function"
        );
    }

    /// Pre-v3, `fs_strip_italic_underscores` special-cased an
    /// immediately-adjacent `_` as "not a word neighbor" (distinct from
    /// plain non-alphanumeric). That special case is algebraically a no-op
    /// for every possible neighbor character: the old test
    /// `is_word(c) && c != '_'` (where `is_word(c) = c.is_alphanumeric() ||
    /// c == '_'`) reduces to exactly `c.is_alphanumeric()`, because the `c
    /// == '_'` disjunct of `is_word` is always cancelled by the `&& c !=
    /// '_'` guard, and `c.is_alphanumeric()` and `c == '_'` are mutually
    /// exclusive. `**`/`__` are still stripped in an earlier, separate step
    /// before this function ever runs, so two bare adjacent `_`s can't even
    /// arise from an `__` remnant. These two inputs are exactly the shapes
    /// that would have distinguished the old special case from a plain
    /// alphanumeric check, if it had ever been reachable -- both confirm
    /// the plain check alone reproduces the intended output.
    #[test]
    fn canonicalize_v3_underscore_adjacent_underscore_special_case_is_unreachable() {
        assert_eq!(
            canonicalize_for_embedding("___x___"),
            "x",
            "'__' pairs strip first, leaving '_x_'; each remaining single \
             '_' has exactly one alphanumeric neighbor ('x') and one \
             non-word neighbor (line start/end) -- both delete"
        );
        assert_eq!(
            canonicalize_for_embedding("a__b"),
            "ab",
            "'__' strips first, leaving no single '_' at all to run the \
             neighbor rule on"
        );
    }
}
