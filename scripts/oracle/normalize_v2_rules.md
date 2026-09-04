# Normalization v2 — public rules (`CANONICALIZE_PIPELINE_VERSION = 2`)

Authoritative rule text for the ingest-side canonicalization pipeline
(`src/search/canonicalize.rs`, `DefaultCanonicalizer::canonicalize`). The
**query** path (`canonicalize_query`) is unchanged by v2 and is not
described here (it stays: NFC → trim → truncate to `QUERY_MAX_CHARS`).

Each rule below applies in this exact order (order 2 → 3 matters — see
`canonicalize_v2_markdown_strip_precedes_whitespace` in
`src/search/canonicalize.rs`, which pins this ordering as a regression
guard). Every example was produced by running the actual pipeline
(`canonicalize_for_embedding`), not hand-computed.

## ① NFC Unicode normalization

Text is normalized to Unicode Normalization Form C (composed form) before
anything else. This is load-bearing for hash stability: two byte-different
encodings of the same visual text must canonicalize to the same output.

- Input: `"cafe\u{0301}"` (`e` + combining acute accent, decomposed)
- Output: `"café"` (single composed `é`)

## ② Strip markdown syntax, keep link text **and** URL

Removes markdown syntax markers — bold/italic (`**`, `__`, `*`, `_`),
inline-code backticks (`` ` ``), headers (`#`), blockquotes (`>`), list
markers (`- `, `+ `, `1. `) — from regular (non-code-block) text. A markdown
link `[text](url)` becomes `"text url"` — **v2 change**: v1 dropped the URL
and kept only the link text.

- Input: `"**bold** and [text](http://x.com)"`
- Output: `"bold and text http://x.com"`

## ③ Whitespace normalization, keeping newlines

Per line: collapse runs of intra-line whitespace to a single space, trim
the line's leading/trailing whitespace. Across lines: keep `\n` as the
paragraph/line-break signal (**v2 change**: v1 folded *all* whitespace,
including `\n`, into a single space). Runs of 3 or more consecutive
newlines fold down to exactly 2 (i.e. at most one blank line survives
between paragraphs). Overall leading/trailing whitespace is trimmed.

- Input: `"a    b\n\n\n\nc"` (4 spaces; 4 newlines)
- Output: `"a b\n\nc"` (single space; 4-newline run folded to 2)

This stage runs **after** stage ②: a markdown line that strips down to
nothing (e.g. a bare `# ` header marker) becomes a blank line *before* the
newline-fold rule sees it, so it participates in the fold. Running stage ③
first would normalize newlines against the raw (un-stripped) text and miss
blank lines created by stripping.

## ④ Hard-noise filtering

Two independent judgments, both unchanged from v1:

- **Whole-text low-signal filter** (inside `canonicalize()`, stage 4): if
  the canonicalized text case-insensitively equals one of 15 short
  acknowledgement phrases (`FS_LOW_SIGNAL_CONTENT` /
  `LOW_SIGNAL_CONTENT`), the canonicalized output is the empty string.
  - Input: `"OK"` → Output: `""`
- **Whole-message tool-acknowledgement filter** (`is_hard_message_noise`,
  called by the indexer before a message even reaches `canonicalize()`):
  a broader phrase table (`is_short_acknowledgement` +
  `is_tool_acknowledgement`), frozen verbatim in
  `scripts/oracle/hard_noise_phrases.json`. See that file for the exact
  phrase/prefix lists and `hard_noise_phrases_json_matches_source` (Rust
  test) for the sync guard.

## ⑤ No truncation, no code-block collapsing, no base64/binary stripping

**v2 change**: v1 truncated the canonicalized ingest text to 2000 chars
(`MAX_EMBED_CHARS`) and collapsed fenced code blocks longer than 30 lines
(`CODE_HEAD_LINES=20` + `CODE_TAIL_LINES=10`) down to a head/tail excerpt
with a `[... N lines omitted ...]` marker and a `[code: lang]` label. v2
does neither: the ingest pipeline has no length cap, and fenced code block
content is kept verbatim, line by line (only the ` ``` ` fence marker lines
themselves are dropped). Nothing that looks like base64 or binary data is
stripped or altered by any stage.

- Input: a fenced block of 35 lines, `L1`..`L35`
- Output: all 35 lines, newline-joined, verbatim — no omission marker, no
  `[code: ...]` label:
  `"L1\nL2\n...\nL34\nL35"`
