# Normalization v3 — public rules (`CANONICALIZE_PIPELINE_VERSION = 3`)

Authoritative rule text for the ingest-side canonicalization pipeline
(`src/search/canonicalize.rs`, `DefaultCanonicalizer::canonicalize`).
Supersedes `normalize_v2_rules.md` (v2). This document is the shared
specification for **both** engines -- Rust and the python oracle
(`scripts/oracle/normalize_v2.py`) -- but as of this pass only Rust has been
brought in line with it (任务书 #121a). The judge currently mirrors *v2's
old* fence/backtick behavior (column-0-only fence, unconditional backtick
deletion) -- a prior Plan-B pass deliberately aligned it to that v2
behavior, which is exactly the side R1/R3 replace in this document. The
judge's alignment to R1–R7 here, R1/R3 included, is entirely 任务书 #121b's
job; none of it is done yet. Until #121b lands, the two engines disagree on
stage ②; that divergence is exactly what
`scripts/oracle/normalize_v2.py --compare` and
`examples/w6_normalize_dump.rs` measure.

The **query** path (`canonicalize_query`) is not changed by v2 or v3 -- it
stays: NFC → trim → truncate to `QUERY_MAX_CHARS`. Note that as of this
writing `canonicalize_query` itself has no production caller left; the
production query path calls `canonicalize_for_embedding` (the same,
non-truncating function documented below) -- see `canonicalize.rs`'s own
header comment for the exact call-site references.

Every example below marked "verified" was produced by actually running
`canonicalize_for_embedding` against the stated input -- the "v2 output"
lines against the pre-D commit of this same task (still v2), the "v3
output" lines against the post-D commit (v3), neither hand-computed. A
handful of R2/R4 examples say "v3 target: unchanged" instead of "v3
output": those inputs' v2 and v3 output are identical, so the v2 line
above them already is the verified v3 value too.

## ① NFC Unicode normalization

Text is normalized to Unicode Normalization Form C (composed form) before
anything else. This is load-bearing for hash stability: two byte-different
encodings of the same visual text must canonicalize to the same output.
Unchanged from v2.

- Input: `"cafe\u{0301}"` (`e` + combining acute accent, decomposed)
- Output: `"café"` (single composed `é`)

## ② Strip markdown syntax, keep link text **and** URL

Per-line processing order (unified across Rust and the judge as of this
document -- Rust already implements this order; the judge currently does
the header/blockquote/list-marker checks *before* inline-marker stripping,
the opposite order -- see R5):

1. Literal removal of every `**` and `__` run (bold/strong markers),
   unconditionally, anywhere in the line.
2. Remaining single `*` or `_` characters: neighbor rule (R4).
3. Paired backtick runs (R3).
4. Markdown links `[text](url)` → `text url` (R6; unchanged from v2).
5. ATX headers (R2).
6. Blockquote prefix `>` (unchanged from v2: strip leading `>` characters,
   then leading whitespace). **Known**: `>` recognition does not tolerate
   leading whitespace (unlike R1/R2's ≤3-space tolerance) -- both engines
   agree on this (Rust's `trim_start_matches('>')` only fires when `>` is
   the line's literal first character). **v4 candidate**: whether to align
   this to R1/R2's ≤3-space tolerance is left to the R1 review; this pass
   does not touch Rust.
7. List markers `- `, `+ `, `N. ` (unchanged from v2).

A markdown link `[text](url)` becomes `"text url"` (v2 change, carried
forward unchanged into v3): v1 dropped the URL and kept only the link text.

### R1 — Fenced code block recognition (v3 change)

A line toggles the code-block state when it matches up to 3 leading spaces
followed immediately by `` ``` `` -- CommonMark's own fence-indentation
tolerance. v2 required the fence marker at column 0 exactly
(`line.starts_with("```")`), so an indented fence line fell through to
ordinary per-line stripping instead of toggling the code-block state. The
fence line itself is dropped either way; code-block content is kept
verbatim, line by line, once the state is on.

- Input: `" \`\`\`\nindented fence body\n \`\`\`\nafter"` (fence markers
  indented by 1 space)
  - v2 output (verified): `"indented fence body\n\nafter"` -- neither
    indented fence line is recognized as a fence, so each one strips its
    (unconditionally-removed) backticks down to an empty line instead of
    toggling code-block state; the body line happens to be unaffected
    either way since it contains no markdown markers.
  - v3 output (verified): `"indented fence body\nafter"` -- the fence lines
    are recognized and dropped, matching the already-correct column-0 case
    (verified: `"\`\`\`\nverbatim body\n\`\`\`\nafter"` →
    `"verbatim body\nafter"`).

### R2 — ATX header recognition (v3 change, two independent directions)

A line is an ATX header when it matches: ≤3 leading spaces, then 1–6 `#`
characters, then either a space or end-of-line. On a match, the `#` run and
one following space (if present) are removed; everything else on the line,
including the ≤3 leading spaces, is kept. A line that does **not** match
this shape is left completely untouched, `#` characters included.

v2's rule (`result.trim_start_matches('#').trim_start()`) requires the `#`
to be the line's very first byte, strips *every* leading `#` with no 1–6
count cap, and never checks for a following space or end-of-line. This is
wrong in two independent directions:

- **Under-strips** (leading whitespace defeats recognition entirely): a
  `#`/`##` run preceded by 1–3 spaces is not at byte 0, so v2's
  `trim_start_matches('#')` never fires on it -- but the same line's
  trailing unconditional `.trim_start()` still eats the leading space
  regardless, so the line is *partially* mangled without ever being
  recognized as a header.
  - Input: `" ## docs/m7-arch"`
  - v2 output (verified): `"## docs/m7-arch"` (leading space silently
    dropped, `##` left untouched -- neither "recognized as a header" nor
    "left completely alone")
  - v3 output (verified): `"docs/m7-arch"` -- recognized and stripped.
    (Stage ② itself keeps the leading space as "everything else"; it is
    stage ③'s per-line leading-whitespace trim, unrelated to this rule,
    that removes it from the final `canonicalize_for_embedding` output
    either way.)
- **Over-strips** (no count cap, no space requirement): any leading run of
  `#` characters is removed even when it isn't followed by whitespace (so
  it isn't really a heading marker) or when it exceeds 6 `#`s (CommonMark
  caps ATX headers at 6, so a longer run isn't a heading at all).
  - Input: `"#!/usr/bin/env bash"` (shebang line)
    - v2 output (verified): `"!/usr/bin/env bash"` (the shebang's `#` is
      gone)
    - v3 target: unchanged, `"#!/usr/bin/env bash"`.
  - Input: `"#76"` (an issue/PR reference, not a header)
    - v2 output (verified): `"76"`
    - v3 target: unchanged, `"#76"`.
  - Input: `"####### not a heading"` (7 `#`s -- one past CommonMark's cap
    of 6)
    - v2 output (verified): `"not a heading"`
    - v3 target: unchanged, the whole line verbatim
      (`"####### not a heading"`) -- 7 consecutive `#`s don't match the
      1–6 window at all, so nothing is stripped.
- **Already correct** (regression check, not a behavior change): a genuine
  column-0 header with a valid count and a following space already strips
  correctly in v2 and must keep doing so in v3.
  - Input: `"## Real Heading"`
  - Output (verified, both v2 and v3): `"Real Heading"`.

### R3 — Paired backtick runs (v3 change)

Within a line, a run of N consecutive backticks pairs with the *next* run
of exactly N consecutive backticks encountered scanning forward (any
non-backtick content, and any differently-sized backtick run, may sit
between them); both runs are deleted and the content between them is kept
verbatim. A run with no same-length partner later in the line is left
untouched, backticks included. **This is only equal-length run pairing** --
it is deliberately not full CommonMark inline-code-span semantics (no
leading/trailing single-space stripping inside the span, no backslash
escaping rules); if a future need turns up requiring that fuller semantics,
it does not belong in this rule.

v2 removes every backtick character unconditionally, paired or not.

- Input: `` "`code`" `` (two length-1 runs, they do pair)
  - v2 output (verified): `"code"`
  - v3 target: unchanged, `"code"` (the runs pair, so the observable result
    happens to already match for this simple case).
- Input: `` "text with `one backtick" `` (one backtick, no closing run of
  the same length anywhere later in the line)
  - v2 output (verified): `"text with one backtick"` (backtick removed even
    though it has no partner)
  - v3 output (verified): `` "text with `one backtick" `` -- the backtick
    is preserved, since it has no matching same-length partner.
- Input: `` "``a`b``" `` (a length-2 run, then a length-1 run, then a
  length-2 run)
  - v2 output (verified): `"ab"` (all four backtick characters removed
    unconditionally)
  - v3 output (verified): `` "a`b" `` -- the two length-2 runs pair with
    *each other* (the length-1 run in between doesn't match N=2, so it is
    skipped when looking for a partner), deleting the two length-2 runs and
    keeping `` a`b `` -- including the middle single backtick -- as literal
    content between them.

### R4 — Single `*`/`_` neighbor rule (v3 change: `*` joins `_`'s existing rule)

After step 1 (`**`/`__` literal removal), for each remaining single `*` or
`_` character: if *exactly one* immediate neighbor (the character before or
after it; a missing neighbor at line start/end counts as "not
alphanumeric") is Unicode-alphanumeric, the character is an opening/closing
emphasis marker and is deleted; otherwise -- both neighbors alphanumeric,
or neither is -- it is left in place. `_` already has this rule in v2
(`fs_strip_italic_underscores`); v3 makes `*` go through the same rule
instead of its previous unconditional `result.replace('*', "")`.

- Input: `"*bold*"` (both `*` sit at a word boundary: one side alphanumeric,
  the other side start/end-of-line)
  - Output (verified, both v2 and v3): `"bold"` -- already correct for the
    boundary case; v2's blind unconditional removal happens to agree with
    the neighbor rule here.
- Input: `"a*b"` (both neighbors of `*` are alphanumeric)
  - v2 output (verified): `"ab"` (wrong -- v2 deletes every `*` regardless
    of neighbors)
  - v3 output (verified): `"a*b"` (preserved -- matches `_`'s existing,
    already-correct behavior on the analogous case, verified unchanged:
    `"snake_case"` → `"snake_case"`).
- Input: `"5*3"` (shell-arithmetic-shaped: both neighbors of `*` are
  digits)
  - v2 output (verified): `"53"`
  - v3 output (verified): `"5*3"` (preserved; the same shape as
    real-world cases like shell arithmetic, regex quantifiers, or
    CJK-flanked emphasis, where both neighbors of `*` are alphanumeric).

### R5 — Stage-② processing order (documentation only; no Rust change this pass)

The order listed at the top of §② (`**`/`__` → single `*`/`_` → paired
backticks → links → headers → blockquote → list markers) is Rust's
*existing* order and is not changed by v3 -- it is written down here
because the judge currently does the opposite (header/blockquote/
list-marker prefix checks *before* inline-marker stripping), which masks a
list marker wrapped in bold. On input like `"**1. Heading**"`: Rust
unmasks `"1. "` by stripping the `**` first (step 1), then recognizes the
now-exposed list marker (step 7) and strips it, producing `"Heading"`; the
judge's line-start regex instead sees `"**1."` at the start of the raw
line -- which doesn't match its ordered-list pattern -- so it never
recognizes a list item, and `"1. "` survives in the output alongside the
now-stripped `**`. Reordering the judge to match this order is 任务书
#121b's job; this entry exists purely so both engines implement one
written specification rather than each engine's incidental order.

### R6 — Nested-bracket link parsing (documentation only; no Rust change this pass)

`fs_strip_markdown_links` is a character-level state machine, not a regex:
after an opening `[`, it tracks a bracket-depth counter that increments on
every inner `[` and decrements on every `]`, treating only the `]` that
brings the counter back to zero as the link text's real closing bracket --
everything up to and including any earlier, still-nested `[`/`]` pair is
kept as literal link-text content. Only then does it check for an
immediately-following `(...)` (itself parsed with matching, paren-depth-
aware balancing) to complete the link; if no such following URL is found,
the entire construct -- brackets included -- is restored verbatim.

- Input: `"[[inner]text](http://x.com)"`
  - Output (verified, unchanged by v3): `"[inner]text http://x.com"` -- the
    inner `[`/`]` pair is absorbed into the link text rather than
    terminating the link early.

Recorded here so the judge's future alignment (#121b) implements the same
depth-aware algorithm, rather than a single-pass, non-recursive regex that
cannot see through a nested bracket pair the way this state machine does.

### R7 — Intra-line whitespace collapse scope (documentation only; no Rust change this pass)

The whitespace-collapse stage (③, below) treats a character as collapsible
intra-line whitespace using Rust's `char::is_whitespace()` -- the full
Unicode `White_Space` property, which includes U+00A0 (NO-BREAK SPACE)
among others.

- Input: `"a\u{00A0}b"` (`a`, NBSP, `b`)
  - Output (verified, unchanged by v3): `"a b"` -- the NBSP is folded to a
    regular space like any other whitespace.

Known edge case for the judge's future alignment (#121b): Python's
`str.isspace()` returns `True` for U+001C–U+001F (the four "information
separator" control characters), which are **not** in Unicode's
`White_Space` property and therefore are **not** whitespace under Rust's
rule. If the judge is switched to `str.isspace()` to chase Unicode-
whitespace parity, these four codepoints would diverge in the *opposite*
direction from today's ASCII-only gap. Not designed around pre-emptively --
no codepoints in this range have been observed in the 216-example or
5,000-sample corpora as of this writing; flag it if a later sampling run
surfaces one, rather than guessing at a fix now.

### R8 — Pipeline version

`CANONICALIZE_PIPELINE_VERSION: u32 = 3` (`src/search/canonicalize.rs`).
All consumers reference the constant itself (or `+ 1`), not a literal, so
no other source changes are expected; `cargo check --all-targets` is the
verification that nothing broke.

## ③ Whitespace normalization, keeping newlines

Per line: collapse runs of intra-line whitespace to a single space (scope:
R7 above), trim the line's leading/trailing whitespace. Across lines: keep
`\n` as the paragraph/line-break signal. Runs of 3 or more consecutive
newlines fold down to exactly 2 (i.e. at most one blank line survives
between paragraphs). Overall leading/trailing whitespace is trimmed.
Unchanged from v2.

- Input: `"a    b\n\n\n\nc"` (4 spaces; 4 newlines)
- Output: `"a b\n\nc"` (single space; 4-newline run folded to 2)

This stage runs **after** stage ②: a markdown line that strips down to
nothing (e.g. a bare `# ` header marker) becomes a blank line *before* the
newline-fold rule sees it, so it participates in the fold.

## ④ Hard-noise filtering

Two independent judgments, both unchanged from v2. **Both are in scope for
the python oracle**: `normalize()` implements the first (a step of
`canonicalize_for_embedding` itself); `is_hard_noise(role, text)`
implements the second (a separate, earlier gate the indexer applies before
a message reaches `canonicalize()` at all).

- **Whole-text low-signal filter** (inside `canonicalize()`, stage 4 --
  applied *after* stages ①②③): if the entire already-normalized text,
  trimmed and lowercased, exactly equals one of the frozen short
  acknowledgement phrases (`FS_LOW_SIGNAL_CONTENT` in the slow path,
  byte-identical `LOW_SIGNAL_CONTENT` in the fast path), the canonicalized
  output is the empty string. Full frozen list + the Rust sync guard:
  `scripts/oracle/hard_noise_phrases.json` key `canonicalize_low_signal` /
  test `low_signal_phrases_json_matches_source`.
  - Input: `"OK"` → Output: `""`
- **Whole-message tool-acknowledgement filter** (`is_hard_message_noise`,
  called by the indexer before a message even reaches `canonicalize()`,
  exposed to the oracle as `is_hard_noise(role, text)`): a broader,
  role-aware phrase table, frozen verbatim in
  `scripts/oracle/hard_noise_phrases.json`. See that file for the exact
  phrase/prefix lists and match rules, and
  `hard_noise_phrases_json_matches_source` (Rust test) for the sync guard.

## ⑤ No truncation, no code-block collapsing, no base64/binary stripping

Unchanged from v2: the ingest pipeline has no length cap, and fenced code
block content is kept verbatim, line by line (only the fence marker lines
themselves are dropped, per R1's recognition rule above). Nothing that
looks like base64 or binary data is stripped or altered by any stage.

- Input: a fenced block of 35 lines, `L1`..`L35`
- Output: all 35 lines, newline-joined, verbatim -- no omission marker, no
  `[code: ...]` label: `"L1\nL2\n...\nL34\nL35"`

## v2 → v3 变更清单

Only entries where Rust's *output* actually changes belong here. R5/R6/R7
above are documentation-only clarifications of existing, unchanged Rust
behavior (written down so the judge's future alignment in #121b implements
the same specification) and are deliberately not listed as diffs.

| 类别 | v2 行为 | v3 行为 | 例子 |
|---|---|---|---|
| R1 围栏缩进 | 围栏标记只认列 0 (`line.starts_with("\`\`\`")`) | 允许 ≤3 个前导空格 | `" \`\`\`\nbody\n \`\`\`"` -- v2 不识别为围栏（内容被当普通行处理）；v3 识别并按围栏处理，内容原样保留 |
| R2 标题 | 只认列 0、无 1–6 个数上限、不要求标记后有空格或行尾 | ≤3 前导空格 + 1–6 个 `#` + (空格或行尾) 才算标题 | `"#76"` v2 剥成 `"76"`（不该剥）；`" ## x"` v2 没剥（该剥没剥，只是巧合地把前导空格吃掉）；v3 两个方向都按精确规则判定 |
| R3 反引号 | 无条件逐字符删除所有反引号 | 只删除等长配对的两串反引号，未配对的原样保留 | `` "text with `x" `` v2 删成 `"text with x"`（不该删，无配对）；v3 保留反引号 |
| R4 星号邻居规则 | `*` 无条件删除（`result.replace('*', "")`）；`_` 已有邻居规则，与 `*` 规则不对称 | `*` 与 `_` 走同一套「恰好一侧字母数字才删」规则 | `"a*b"` v2 删成 `"ab"`（不该删，两侧都是字母数字）；v3 保留 `"a*b"` |
