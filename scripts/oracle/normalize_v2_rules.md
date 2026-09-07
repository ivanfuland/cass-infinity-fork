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
backticks (`` ` ``), headers (`#`), blockquotes (`>`), list markers (`- `,
`+ `, `1. `) — from regular (non-code-block) text. A markdown link
`[text](url)` becomes `"text url"` — **v2 change**: v1 dropped the URL and
kept only the link text.

- Input: `"**bold** and [text](http://x.com)"`
- Output: `"bold and text http://x.com"`

**Backticks are stripped unconditionally, not as paired inline-code
spans** (T11.7 clarification, 2026-09-05 -- amends the earlier
"inline-code backticks" framing, which implied pairing): every backtick
character on a non-code-block line is removed regardless of whether it
has a matching partner. A line with an odd or unpaired backtick run (e.g.
a fence marker line the code-block detector below didn't recognize as a
fence, so it fell through to this stage) still has every `` ` `` in it
removed.

- Input: `` "text with `one backtick" ``
- Output: `"text with one backtick"` (not left un-stripped for lack of a pair)

**Code-block fence recognition requires the fence marker at column 0**
(T11.7 clarification): a line only toggles the code-block state when it
starts with `` ``` `` with **zero** leading whitespace. A `` ``` `` fence
indented under a list item or otherwise preceded by any whitespace is
*not* recognized as a fence — it falls through to the regular
(non-code-block) per-line stripping above instead (so its backticks are
removed per the unconditional rule, not kept verbatim as code content).
**Known divergence from CommonMark** (which tolerates up to 3 spaces of
fence indentation): this is the ingest pipeline's actual current
behavior, not a considered design choice.

### Further known divergences (T11.7, 2026-09-05) — not yet aligned in the python oracle

T11.7 ran the full `gates/chunk-oracle.json` diff population (216 messages,
not just its 50-sample `diff_details`) through both `canonicalize_for_embedding`
(Rust) and `normalize()` (this oracle) and diffed the two normalized texts.
The fence/backtick alignment above accounts for 116/216 (53.7%); the
remaining 100/216 (46.3%) break down into six further, independent
mechanisms below. These are recorded here as **factual descriptions of the
ingest pipeline's current behavior**, not endorsements — each is a
candidate for alignment to CommonMark-like semantics, planned alongside the
PR6 re-ingest (`canonicalize` v3), not before. Full per-message evidence:
`W4_ARTIFACTS/t11.7-diag/diff50-classification.md` (60/8/19/10/2/1 = 100,
zero unclassified).

- **Underscore retention rule** (60/216): Rust's `fs_strip_italic_underscores`
  keeps a standalone `_` when *both* neighbors are non-alphanumeric (it only
  drops `_` acting as an opening/closing italic marker, i.e. one alphanumeric
  neighbor and one non-alphanumeric neighbor); this oracle's
  `_strip_emphasis_chars` keeps `_`/`*` only when *both* neighbors are
  alphanumeric, dropping it in every other case. Example ids: 4887, 11453,
  23699, 81631, 98772 (full list in the classification doc).
- **List-marker masked by bold, stripping-order mismatch** (8/216): Rust
  strips `**`/backticks/links character-by-character *before* checking for a
  line-leading list marker; this oracle checks the line-leading list-marker
  regex *before* stripping inline markdown. On input like `**1. Heading**`,
  Rust unmasks the `1. ` (by removing `**` first) and then strips it; this
  oracle's regex sees `**1.` (not `\d+\.` at the line start) and never
  recognizes it as a list item, so `1. ` survives. Example ids: 88905, 90183,
  94389, 160060.
- **Header-strip doesn't tolerate leading whitespace/characters** (19/216):
  Rust's `result.trim_start_matches('#').trim_start()` only strips `#`
  characters that are literally at byte offset 0 of the line; a line like
  `" ## docs/m7-..."` (one leading space, common where shell command output
  such as `git status --short --branch`'s `## <branch>` porcelain line is
  pasted into prose rather than a fence) or one with a non-# character
  before the `#` run keeps its `#`/`##` intact. This oracle's `_HEADER_RE`
  (`^(\s*)(#{1,6})(\s+)(.*)$`) tolerates leading whitespace and strips
  correctly. Same underlying theme as the fence-indentation divergence
  above, but on headers, not fences. Example ids: 71397, 84619, 86996,
  90152, 135404.
- **Asterisk stripped unconditionally, unlike underscore** (10/216): Rust's
  `*` handling is a blind `result.replace('*', "")` — every `*` is removed
  regardless of neighboring characters (no alphanumeric-neighbor exception
  like underscore gets from `fs_strip_italic_underscores`). This oracle
  applies the *same* alphanumeric-neighbor rule to both `_` and `*`, so a
  `*` flanked by alphanumerics (including CJK, which Python's `str.isalnum()`
  treats as alphanumeric) on both sides — shell arithmetic `5*1048576`,
  `printf` `%0*d`, regex quantifiers `\s*`, Chinese emphasis `*能力*` — is
  kept by this oracle and dropped by Rust. Example ids: 270431, 289414,
  361904, 381746, 387529.
- **Nested/double-bracket link parsing differs** (2/216): Rust's link
  stripper is a character-level state machine that tracks bracket depth
  (so it "sees through" a nested `[` inside a link's text span); this
  oracle's link regex (`` \[([^\]\n]*)\]\(([^)\n]*)\) ``) is a single,
  non-recursive pattern that closes on the *first* `]` it meets. On
  adjacent-bracket constructs (an Obsidian-style `[[wikilink]]`, or
  `foo[](bar)`), the two sides disagree on which `[`/`]` pair up, leaving a
  different residual bracket count. Example ids: 177547, 361832.
- **Whitespace-collapse character class differs (Unicode vs. ASCII)**
  (1/216): Rust's whitespace-collapse step uses `char::is_whitespace()`
  (full Unicode, including U+00A0 no-break space); this oracle's
  `_INTRALINE_WS_RE` (`[ \t\r\f\v]+`) is ASCII-only and does not match
  U+00A0, so a no-break space passes through unchanged here while Rust
  folds it to a regular space. Example id: 1399007.

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

Two independent judgments, both unchanged from v1. **Both are in scope for
the T2 python oracle**: `normalize()` implements the first (it's a step of
`canonicalize_for_embedding` itself); `is_hard_noise(role, text)`
implements the second (a separate, earlier gate the indexer applies before
a message reaches `canonicalize()` at all).

- **Whole-text low-signal filter** (inside `canonicalize()`, stage 4 --
  part of `normalize()`'s own pipeline, applied *after* stages ①②③): if
  the entire already-normalized text, trimmed and lowercased, exactly
  equals one of 15 short acknowledgement phrases (`FS_LOW_SIGNAL_CONTENT`
  in the slow path, byte-identical `LOW_SIGNAL_CONTENT` in the fast path),
  the canonicalized output is the empty string. Full frozen list + the
  Rust sync guard: `scripts/oracle/hard_noise_phrases.json` key
  `canonicalize_low_signal` / test `low_signal_phrases_json_matches_source`
  (this list was originally *not* frozen by T1 -- filled in as a T1
  rules-doc gap fix folded into T2, plan v5.1).
  - Input: `"OK"` → Output: `""`
- **Whole-message tool-acknowledgement filter** (`is_hard_message_noise`,
  called by the indexer before a message even reaches `canonicalize()`,
  exposed to the T2 oracle as `is_hard_noise(role, text)`): a broader,
  role-aware phrase table (`is_short_acknowledgement` +
  `is_tool_acknowledgement`), frozen verbatim in
  `scripts/oracle/hard_noise_phrases.json` (keys `short_acknowledgements` /
  `short_tool_acks` / `prefixed_tool_acks`). See that file for the exact
  phrase/prefix lists and match rules (trim/case/length/role conditions),
  and `hard_noise_phrases_json_matches_source` (Rust test) for the sync
  guard.

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
