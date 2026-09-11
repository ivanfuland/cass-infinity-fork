#!/usr/bin/env python3
"""Independent Python oracle for T2 (plan v5.1): normalization v2, canonical
role aliasing, hard-noise classification, and character-recursive chunking.

Zero third-party dependencies (stdlib only: unicodedata, re, sqlite3, json,
argparse, sys, random, time).

This is an INDEPENDENT re-implementation of the rules frozen in:
  - scripts/oracle/normalize_v2_rules.md   (normalization v2, five stages)
  - scripts/oracle/hard_noise_phrases.json (short_acknowledgements /
    short_tool_acks / prefixed_tool_acks / canonicalize_low_signal)
  - docs/projects/cass-fork/plans/2026-09-03-pr4-index-correctness.md
    (Global Constraints + parameter-freeze table, "分块" row)

It is NOT derived by shelling out to the Rust binary/tests or by tuning
against Rust's printed output -- disagreements found by `--selftest`'s
60-sample comparison (driven by the caller) are triaged against the written
spec, not silently patched to match Rust.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
import time
import unicodedata
from typing import Optional

# ---------------------------------------------------------------------------
# Parameter freeze (plan v5.1, chunking_policy_version = 1)
# ---------------------------------------------------------------------------

CHUNKING_POLICY_VERSION = 1
CHUNK_CHARS = 1000
CHUNK_OVERLAP_CHARS = 100
CHUNK_MIN_SPLIT_CHARS = 500

# ---------------------------------------------------------------------------
# canonical_role: raw provider role -> canonical role string, or None.
# ---------------------------------------------------------------------------

_ROLE_ALIASES = {
    "user": "user",
    "assistant": "assistant",
    "agent": "assistant",
    "tool_call": "tool_call",
    "tool_result": "tool_result",
    "tool": "tool_result",
    "toolResult": "tool_result",
}


def canonical_role(raw: str) -> Optional[str]:
    return _ROLE_ALIASES.get(raw)


_TOOL_CLASS_ROLES = {"tool_call", "tool_result"}

# ---------------------------------------------------------------------------
# is_hard_noise: whole-message tool-acknowledgement filter
# (scripts/oracle/hard_noise_phrases.json: short_acknowledgements [20] +
# short_tool_acks [8] + prefixed_tool_acks [8] = 36 phrases/prefixes).
# PR6 T1 (任务书 #111): SHORT_TOOL_ACKS and CANONICALIZE_LOW_SIGNAL below each
# gained two hard-noise receipts ("wait timed out", "bash completed with no
# output"), mirroring the Rust `is_tool_acknowledgement` short_tool_ack gate
# and FS_LOW_SIGNAL_CONTENT/LOW_SIGNAL_CONTENT additions -- manual sync since
# these two lists are NOT loaded from hard_noise_phrases.json.
# `role` here is the CANONICAL role string (canonical_role's return value,
# or None), matching the Rust call site `is_hard_message_noise(Some(role.as_str()), ...)`.
# ---------------------------------------------------------------------------

SHORT_ACKNOWLEDGEMENTS = [
    "ok", "ok.", "okay", "okay.", "done", "done.", "done!",
    "got it", "got it.", "got it!",
    "ack", "ack.", "acknowledged", "acknowledged.",
    "confirmed", "confirmed.",
    "completed", "completed.", "complete", "complete.",
]

SHORT_TOOL_ACKS = [
    "no matches found", "no changes made", "no changes",
    "already up to date", "up to date", "file written",
    "wait timed out", "bash completed with no output",
]

PREFIXED_TOOL_ACKS = [
    "successfully wrote to ", "successfully updated ", "successfully created ",
    "successfully deleted ", "successfully saved ", "successfully applied ",
    "applied patch", "patch applied",
]

# canonicalize()'s own stage-4 whole-text low-signal filter (SEPARATE list;
# applied inside normalize(), not by is_hard_noise()).
CANONICALIZE_LOW_SIGNAL = [
    "ok", "done", "done.", "got it", "got it.",
    "understood", "understood.", "sure", "sure.",
    "yes", "no", "thanks", "thanks.", "thank you", "thank you.",
    "wait timed out", "bash completed with no output",
]


def is_short_acknowledgement(text: str) -> bool:
    t = text.strip()
    if len(t) > 200:
        return False
    return t.lower() in SHORT_ACKNOWLEDGEMENTS


def is_tool_acknowledgement(role: Optional[str], text: str) -> bool:
    if is_short_acknowledgement(text):
        return True
    t = text.strip()
    lower = t.lower()
    toolish = role in _TOOL_CLASS_ROLES
    if lower in SHORT_TOOL_ACKS and (toolish or "file" in lower or "match" in lower):
        return True
    for prefix in PREFIXED_TOOL_ACKS:
        if lower.startswith(prefix) and (toolish or "/" in lower or "file" in lower):
            return True
    return False


def is_hard_noise(role: Optional[str], text: str) -> bool:
    # Mirrors `is_hard_message_noise` (src/search/canonicalize.rs:687-689):
    # `text.trim().is_empty() || is_tool_acknowledgement(role, text)`. The
    # empty/whitespace-only branch was missing from this port (T11.7
    # finding, 2026-09-05): lexical_oracle.py counted 6939 zero-length
    # tool_result messages as lexically eligible when the candidate
    # correctly excludes them via this branch.
    return text.strip() == "" or is_tool_acknowledgement(role, text)


# ---------------------------------------------------------------------------
# normalize: canonicalize_for_embedding, stages (1)(2)(3)(5) + stage 4.
# ---------------------------------------------------------------------------

#
# 任务书 #121b (R1, v3): fence-marker recognition tolerates up to 3 leading
# spaces, mirroring Rust's `fs_is_fence_marker` (CommonMark's own
# fence-indentation tolerance). Pre-v3 this required column 0 exactly.
_FENCE_RE = re.compile(r"^ {0,3}```")  # <=3 leading spaces, mirrors `fs_is_fence_marker`
_HEADER_RE = re.compile(r"^( {0,3})(#{1,6})( |$)(.*)$")
_BLOCKQUOTE_RE = re.compile(r"^(\s*)>+\s?(.*)$")
_LIST_RE = re.compile(r"^(\s*)(?:[-+]|\d+\.)\s+(.*)$")
_LINK_RE = re.compile(r"\[([^\]\n]*)\]\(([^)\n]*)\)")
_MULTI_NEWLINE_RE = re.compile(r"\n{3,}")


def _strip_emphasis_chars(line: str) -> str:
    # `*` / `_` are stripped per-character (NOT as paired `**text**` /
    # `_text_` spans) UNLESS both immediate neighbors are alphanumeric, in
    # which case the character is kept literally (protects identifier-style
    # tokens like `snake_case` or `a*b` from being mangled). Decided on
    # both neighbors of the *original* line so a run like `**` strips fully
    # regardless of the two chars' mutual (non-alnum) adjacency.
    n = len(line)
    out = []
    for i, ch in enumerate(line):
        if ch in ("*", "_"):
            left = line[i - 1] if i > 0 else ""
            right = line[i + 1] if i + 1 < n else ""
            if left.isalnum() and right.isalnum():
                out.append(ch)
            # else: dropped
        else:
            out.append(ch)
    return "".join(out)


def _strip_paired_backticks(line: str) -> str:
    # R3 (v3): a run of N consecutive backticks pairs with the *next* run of
    # exactly N consecutive backticks encountered scanning forward (any
    # non-backtick content, and any differently-sized run, may sit between
    # them); both runs are deleted, content between kept verbatim. A run
    # with no same-length partner later in the line is left untouched.
    # Mirrors Rust's `fs_strip_paired_backticks`: collect runs first, then
    # walk with `idx += 1` only (never `idx = j + 1`), relying on
    # `delete[idx]` to short-circuit runs already claimed as a partner.
    n = len(line)
    runs: list[tuple[int, int]] = []
    i = 0
    while i < n:
        if line[i] == "`":
            start = i
            length = 0
            while i < n and line[i] == "`":
                i += 1
                length += 1
            runs.append((start, length))
        else:
            i += 1

    delete = [False] * len(runs)
    idx = 0
    while idx < len(runs):
        if delete[idx]:
            idx += 1
            continue
        len_a = runs[idx][1]
        partner = next(
            (j for j in range(idx + 1, len(runs)) if not delete[j] and runs[j][1] == len_a),
            None,
        )
        if partner is not None:
            delete[idx] = True
            delete[partner] = True
        idx += 1

    out = []
    pos = 0
    for k, (start, length) in enumerate(runs):
        if delete[k]:
            out.append(line[pos:start])
            pos = start + length
    out.append(line[pos:])
    return "".join(out)


def _strip_inline_markdown(line: str) -> str:
    # Order: links first (so bracket/paren text isn't mistaken for emphasis
    # markers), then emphasis chars, then paired backticks.
    line = _LINK_RE.sub(lambda m: f"{m.group(1)} {m.group(2)}", line)
    line = _strip_emphasis_chars(line)
    line = _strip_paired_backticks(line)
    return line


def _strip_markdown_and_code(text: str) -> str:
    out_lines = []
    in_fence = False
    for line in text.split("\n"):
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue  # fence marker line itself is dropped entirely (no blank-line residue)
        if in_fence:
            out_lines.append(line)  # verbatim, no stripping
            continue
        m = _HEADER_RE.match(line)
        if m:
            line = m.group(1) + m.group(4)
        m = _BLOCKQUOTE_RE.match(line)
        if m:
            line = m.group(1) + m.group(2)
        m = _LIST_RE.match(line)
        if m:
            line = m.group(1) + m.group(2)
        line = _strip_inline_markdown(line)
        out_lines.append(line)
    return "\n".join(out_lines)


def _collapse_intraline_whitespace(line: str) -> str:
    # R7 (v3): a character is collapsible intra-line whitespace when
    # ch.isspace() is true (Python's Unicode White_Space test, e.g. NBSP
    # U+00A0) -- mirrors Rust's char::is_whitespace() scope. Pre-v3 this was
    # an ASCII-only class ([ \t\r\f\v]). Leading whitespace is dropped
    # entirely (never emitted as a space); trailing whitespace is trimmed
    # by the final .rstrip() -- both use the same Unicode-aware test as the
    # collapse itself, per Ivan's ruling that trim shares R7's scope rather
    # than being a separate rule.
    out = []
    prev_space = True
    for ch in line:
        if ch.isspace():
            if not prev_space:
                out.append(" ")
                prev_space = True
        else:
            out.append(ch)
            prev_space = False
    return "".join(out).rstrip()


def _normalize_whitespace(text: str) -> str:
    lines = text.split("\n")
    lines = [_collapse_intraline_whitespace(ln) for ln in lines]
    joined = "\n".join(lines)
    joined = _MULTI_NEWLINE_RE.sub("\n\n", joined)
    return joined.strip()


def _filter_low_signal(text: str) -> str:
    trimmed = text.strip()
    if trimmed.lower() in CANONICALIZE_LOW_SIGNAL:
        return ""
    return text


def normalize(text: str) -> str:
    nfc = unicodedata.normalize("NFC", text)
    stripped = _strip_markdown_and_code(nfc)
    ws = _normalize_whitespace(stripped)
    return _filter_low_signal(ws)


# ---------------------------------------------------------------------------
# chunk_normalized: char-based recursive chunker (plan v5.1 参数冻结「分块」行).
# ---------------------------------------------------------------------------

def chunk_normalized(text: str) -> list[tuple[int, int]]:
    if text == "":
        return []

    total_chars = len(text)
    byte_offsets = [0] * (total_chars + 1)
    acc = 0
    for i, ch in enumerate(text):
        byte_offsets[i] = acc
        acc += len(ch.encode("utf-8"))
    byte_offsets[total_chars] = acc

    spans: list[tuple[int, int]] = []
    start_char = 0
    while True:
        remaining = total_chars - start_char
        if remaining <= CHUNK_CHARS:
            spans.append((byte_offsets[start_char], byte_offsets[total_chars]))
            break

        window_start = start_char + CHUNK_MIN_SPLIT_CHARS
        window_end = start_char + CHUNK_CHARS
        scan_upper = min(window_end, total_chars)

        last_parabreak = None
        last_newline = None
        last_space = None
        e = max(window_start, 1)
        while e <= scan_upper:
            c = text[e - 1]
            if c == "\n":
                last_newline = e
                if e >= 2 and text[e - 2] == "\n":
                    last_parabreak = e
            elif c == " ":
                last_space = e
            e += 1

        if last_parabreak is not None:
            end_char = last_parabreak
        elif last_newline is not None:
            end_char = last_newline
        elif last_space is not None:
            end_char = last_space
        else:
            end_char = window_end

        spans.append((byte_offsets[start_char], byte_offsets[end_char]))
        start_char = end_char - CHUNK_OVERLAP_CHARS

    return spans


def chunk_text(text: str, span: tuple[int, int]) -> str:
    b = text.encode("utf-8")
    return b[span[0]:span[1]].decode("utf-8")


# ---------------------------------------------------------------------------
# --selftest
# ---------------------------------------------------------------------------

def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _assert_covers_and_overlaps(text: str) -> None:
    spans = chunk_normalized(text)
    total_chars = len(text)

    if text == "":
        _assert(spans == [], "empty input must produce an empty list")
        return

    _assert(len(spans) >= 1, "non-empty input must produce >=1 chunk")

    for i in range(len(spans) - 1):
        is_final = False
        chunk_str = chunk_text(text, spans[i])
        chunk_len = len(chunk_str)
        _assert(
            CHUNK_MIN_SPLIT_CHARS <= chunk_len <= CHUNK_CHARS,
            f"non-final chunk {i} length {chunk_len} not in [{CHUNK_MIN_SPLIT_CHARS}, {CHUNK_CHARS}]",
        )
        next_str = chunk_text(text, spans[i + 1])
        this_tail = chunk_str[-100:] if len(chunk_str) >= 100 else chunk_str
        next_head = next_str[:100]
        _assert(
            this_tail == next_head,
            f"chunk {i}'s last 100 chars must equal chunk {i + 1}'s first 100 chars",
        )

    # byte-exact de-overlapped reconstruction
    reconstructed = []
    for i, span in enumerate(spans):
        piece = chunk_text(text, span)
        if i == 0:
            reconstructed.append(piece)
        else:
            skip = min(CHUNK_OVERLAP_CHARS, len(piece))
            reconstructed.append(piece[skip:])
    joined = "".join(reconstructed)
    _assert(joined == text, "de-overlapped reconstruction must equal original text")
    _assert(len(joined) == total_chars, "reconstructed char count must equal original")


def _selftest_properties() -> None:
    lengths = [0, 1, 999, 1000, 1001, 1099, 1100, 1101, 1500, 5000]
    for n in lengths:
        _assert_covers_and_overlaps("a" * n)
    for n in range(1, 6):
        base = n * 900
        for delta in (-1, 0, 1):
            ln = max(base + delta, 0)
            _assert_covers_and_overlaps("b" * ln)
    _assert_covers_and_overlaps("你好世界" * 400)
    _assert_covers_and_overlaps("\U0001F600\U0001F601\U0001F602" * 400)
    _assert_covers_and_overlaps("é" * 1300)
    _assert_covers_and_overlaps("é" * 1300)
    _assert_covers_and_overlaps("x" * 3000)


def _selftest_prefers_paragraph_then_line_then_space() -> None:
    s = "a" * 600 + "\n\n" + "b" * 50 + "\n" + "c" * 50 + " " + "d" * 400
    spans = chunk_normalized(s)
    _assert(len(spans) >= 2, "case1 needs >=2 chunks")
    _assert(spans[0][1] == 602, f"case1 paragraph break must win, got {spans[0][1]}")

    s2 = "a" * 600 + "\n" + "b" * 100 + " " + "c" * 400
    spans2 = chunk_normalized(s2)
    _assert(len(spans2) >= 2, "case2 needs >=2 chunks")
    _assert(spans2[0][1] == 601, f"case2 newline must win over space, got {spans2[0][1]}")

    s3 = "a" * 700 + " " + "b" * 500
    spans3 = chunk_normalized(s3)
    _assert(len(spans3) >= 2, "case3 needs >=2 chunks")
    _assert(spans3[0][1] == 701, f"case3 space must be used, got {spans3[0][1]}")


def _selftest_early_separator_does_not_stall() -> None:
    s = "a" * 48 + "\n\n" + "b" * 2000
    spans = chunk_normalized(s)
    _assert(len(spans) >= 2, "needs >=2 chunks")
    _assert(spans[0][1] == 1000, f"must hard-cut at 1000, got {spans[0][1]}")
    _assert(spans[1][0] == 900, f"second chunk must start at 900, got {spans[1][0]}")


def _selftest_role_alias_table() -> None:
    _assert(canonical_role("user") == "user", "user")
    _assert(canonical_role("assistant") == "assistant", "assistant")
    _assert(canonical_role("agent") == "assistant", "agent")
    _assert(canonical_role("tool_call") == "tool_call", "tool_call")
    _assert(canonical_role("tool_result") == "tool_result", "tool_result")
    _assert(canonical_role("tool") == "tool_result", "tool")
    _assert(canonical_role("toolResult") == "tool_result", "toolResult")
    for none_role in ("reasoning", "gemini", "info", "error"):
        _assert(canonical_role(none_role) is None, f"{none_role} must map to None")


def _selftest_normalize_examples() -> None:
    # Rule 1: NFC
    _assert(normalize("café") == "café", "NFC composition")
    # Rule 2: markdown link keeps text and URL
    _assert(
        normalize("**bold** and [text](http://x.com)") == "bold and text http://x.com",
        "markdown strip + link text+url",
    )
    # Rule 3: whitespace normalize, keep newlines, fold 3+ newlines to 2
    _assert(normalize("a    b\n\n\n\nc") == "a b\n\nc", "whitespace normalize")
    # Rule 4: hard-noise (canonicalize's own stage-4) empties out
    _assert(normalize("OK") == "", "stage-4 low-signal filter")
    # Rule 5: no truncation, fenced code kept verbatim (fence lines dropped)
    lines = [f"L{i}" for i in range(1, 36)]
    fenced = "```\n" + "\n".join(lines) + "\n```"
    _assert(normalize(fenced) == "\n".join(lines), "fenced code verbatim, no collapse")
    # R1 (v3): fence marker tolerates up to 3 leading spaces (indented fence
    # lines toggle code-block state and are dropped, same as column 0).
    _assert(
        normalize(" ```\nindented fence body\n ```\nafter") == "indented fence body\nafter",
        "R1: indented fence (<=3 spaces) recognized as fence marker",
    )
    # R7 (v3): Unicode White_Space (e.g. NBSP U+00A0) is collapsible
    # intra-line whitespace, not just the ASCII set.
    _assert(normalize("a b") == "a b", "R7: NBSP folds to a regular space")
    # R2 (v3): ATX header = <=3 leading spaces, 1-6 `#`, then space-or-EOL.
    _assert(
        normalize(" ## docs/m7-arch") == "docs/m7-arch",
        "R2: under-strip fixed -- indented header now recognized and stripped",
    )
    _assert(
        normalize("#!/usr/bin/env bash") == "#!/usr/bin/env bash",
        "R2: over-strip fixed -- shebang '#' has no following space, left alone",
    )
    _assert(
        normalize("#76") == "#76",
        "R2: over-strip fixed -- issue reference has no following space, left alone",
    )
    _assert(
        normalize("####### not a heading") == "####### not a heading",
        "R2: over-strip fixed -- 7 consecutive #s exceed the 1-6 window, left alone",
    )
    _assert(
        normalize("## Real Heading") == "Real Heading",
        "R2: already-correct column-0 header regression check",
    )
    # R2 known deviation from CommonMark (which allows tab as leading
    # whitespace): a tab before the `#` run does NOT count as leading
    # whitespace, matching Rust's `fs_strip_atx_header` (which only trims
    # literal ' ' bytes) -- so this line is left untouched, not recognized
    # as a header. This is the one example that actually discriminates the
    # old `\s*`/`\s+` regex (which treated tab as whitespace and WOULD have
    # stripped the header here) from the new ' {0,3}'/'( |$)' regex.
    _assert(
        normalize("\t## tab-indented") == "## tab-indented",
        "R2: leading tab does not count as header indentation (known deviation)",
    )
    # R2: 4 leading spaces exceed the <=3 cap -- another genuine
    # discriminator between old `\s*` (unbounded, would strip) and new
    # ` {0,3}` (capped, must not recognize).
    _assert(
        normalize("    ## four-space") == "## four-space",
        "R2: 4 leading spaces exceed the <=3 indentation cap, header not recognized",
    )
    # R3 (v3): paired backtick runs -- only equal-length runs pair.
    _assert(normalize("`code`") == "code", "R3: simple paired backticks (regression pin)")
    _assert(
        normalize("text with `one backtick") == "text with `one backtick",
        "R3: unpaired backtick has no partner, left untouched",
    )
    _assert(
        normalize("``a`b``") == "a`b",
        "R3: two length-2 runs pair with each other, middle length-1 run kept literal",
    )


def _selftest_is_hard_noise_empty_and_normal() -> None:
    # T11.7 regression: empty/whitespace-only content is hard noise
    # regardless of role (mirrors canonicalize.rs:687-689's
    # `text.trim().is_empty()` branch), independent of the phrase table.
    _assert(is_hard_noise("tool_result", "") is True, "empty tool_result must be hard noise")
    _assert(is_hard_noise("tool_result", "   \n\t ") is True, "whitespace-only tool_result must be hard noise")
    _assert(is_hard_noise("user", "") is True, "empty content is hard noise for any role")
    # Phrase-table branch still fires for short-ack noise (regardless of emptiness check).
    _assert(is_hard_noise("assistant", "OK") is True, "short-ack phrase must be hard noise")
    _assert(is_hard_noise("tool_result", "no matches found") is True, "tool-ack phrase must be hard noise")
    # A normal, substantive message must NOT be classified as hard noise.
    _assert(
        is_hard_noise("user", "This is a normal message with real content, not an ack.") is False,
        "normal non-empty message must not be hard noise",
    )


def run_selftest() -> int:
    checks = [
        ("properties_cover_and_overlap", _selftest_properties),
        ("prefers_paragraph_then_line_then_space", _selftest_prefers_paragraph_then_line_then_space),
        ("early_separator_does_not_stall", _selftest_early_separator_does_not_stall),
        ("role_alias_table", _selftest_role_alias_table),
        ("normalize_v2_rule_examples", _selftest_normalize_examples),
        ("is_hard_noise_empty_and_normal", _selftest_is_hard_noise_empty_and_normal),
    ]
    failed = False
    for name, fn in checks:
        try:
            fn()
            print(f"ok  {name}")
        except AssertionError as e:
            failed = True
            print(f"FAIL {name}: {e}")
    return 1 if failed else 0


# ---------------------------------------------------------------------------
# --count-db
# ---------------------------------------------------------------------------

def run_count_db(db_path: str, json_out: str) -> int:
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, role, content FROM messages")

        chunks_by_role: dict[str, int] = {}
        chunks_total_v2 = 0
        messages_over_100_chunks: list[dict] = []
        messages_scanned = 0
        t0 = time.time()

        for message_id, role_raw, content in cur:
            messages_scanned += 1
            role = canonical_role(role_raw if role_raw is not None else "")
            if role is None:
                continue
            text = content if content is not None else ""
            normalized = normalize(text)
            if normalized == "":
                continue
            spans = chunk_normalized(normalized)
            n = len(spans)
            if n == 0:
                continue
            chunks_by_role[role] = chunks_by_role.get(role, 0) + n
            chunks_total_v2 += n
            if n > 100:
                messages_over_100_chunks.append({"message_id": message_id, "chunk_count": n})

        elapsed = time.time() - t0
        result = {
            "chunks_by_role": chunks_by_role,
            "chunks_total_v2": chunks_total_v2,
            "messages_over_100_chunks": messages_over_100_chunks,
            "messages_scanned": messages_scanned,
            "elapsed_seconds": round(elapsed, 3),
        }
        with open(json_out, "w") as f:
            json.dump(result, f, indent=2, sort_keys=True)
        print(
            f"messages_scanned={messages_scanned} chunks_total_v2={chunks_total_v2} "
            f"messages_over_100_chunks={len(messages_over_100_chunks)} elapsed={elapsed:.1f}s"
        )
        return 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# --check-fixtures: compare against the Rust-frozen 60-sample suite
# (tests/fixtures/chunking_samples.json, generated by `chunking_samples_frozen`).
# ---------------------------------------------------------------------------

def run_check_fixtures(path: str) -> int:
    with open(path) as f:
        records = json.load(f)

    diffs = []
    for i, rec in enumerate(records):
        input_text = rec["input"]
        expected_normalized = rec["normalized"]
        expected_spans = [tuple(s) for s in rec["spans"]]

        got_normalized = normalize(input_text)
        got_spans = chunk_normalized(got_normalized)

        if got_normalized != expected_normalized:
            diffs.append({
                "index": i,
                "field": "normalized",
                "input": input_text,
                "expected": expected_normalized,
                "got": got_normalized,
            })
        if got_spans != expected_spans:
            diffs.append({
                "index": i,
                "field": "spans",
                "input": input_text,
                "expected": expected_spans,
                "got": got_spans,
            })

    if diffs:
        print(f"FAIL: {len(diffs)} diff(s) across {len(records)} samples")
        for d in diffs:
            print(f"  [{d['index']}] {d['field']}: expected={d['expected']!r} got={d['got']!r} input={d['input']!r}")
        return 1

    print(f"ok  {len(records)} samples, 0 diffs")
    return 0


# ---------------------------------------------------------------------------
# --compare: T3 (任务书 #121a) A2 -- compare a `w6_normalize_dump` jsonl
# (message_id, content_sha256, rust_normalized) against this oracle's
# `normalize()` on the same rows re-read from `--db`. `normalize()` and its
# helpers are not touched by this addition -- this only wires an existing,
# unmodified function into a new read-only comparison entry point.
# ---------------------------------------------------------------------------

def run_compare(jsonl_path: str, db_path: str, buckets_path: Optional[str]) -> int:
    with open(jsonl_path) as f:
        records = [json.loads(line) for line in f if line.strip()]

    uri = f"file:{db_path}?immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as e:
        print(f"precondition error: cannot open --db {db_path}: {e}", file=sys.stderr)
        return 2

    diffs = 0
    sha_mismatch = 0
    total = 0
    precondition_error = False
    diff_ids: list[str] = []

    try:
        cur = conn.cursor()
        for rec in records:
            message_id = rec["message_id"]
            expected_sha = rec["content_sha256"]
            rust_normalized = rec["rust_normalized"]
            total += 1
            try:
                row = cur.execute(
                    "SELECT content FROM messages WHERE id = ?", (message_id,)
                ).fetchone()
            except sqlite3.Error as e:
                print(f"precondition error: query failed for message_id {message_id}: {e}", file=sys.stderr)
                precondition_error = True
                continue
            if row is None:
                print(f"precondition error: message_id {message_id} not found in --db", file=sys.stderr)
                precondition_error = True
                continue
            content = row[0] if row[0] is not None else ""
            actual_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if actual_sha != expected_sha:
                sha_mismatch += 1
                continue
            got_normalized = normalize(content)
            if got_normalized != rust_normalized:
                diffs += 1
                diff_ids.append(str(message_id))
    finally:
        conn.close()

    print(f"diffs={diffs} sha_mismatch={sha_mismatch} total={total}")

    if buckets_path:
        with open(buckets_path) as f:
            bucket_doc = json.load(f)
        buckets = bucket_doc["buckets"] if "buckets" in bucket_doc else bucket_doc
        diff_id_set = set(diff_ids)
        all_ids = {str(rec["message_id"]) for rec in records}
        # "unclassified" is recomputed here rather than trusted from the
        # buckets file: the file's own "unclassified" entry is a stale,
        # separately-authored list (may be empty even when ids outside the
        # named buckets exist), so trusting it breaks the invariant
        # `total diffs == sum(named buckets) + unclassified`. Recomputing
        # as "ids in this jsonl not covered by any named bucket" keeps that
        # invariant true regardless of what the buckets file says.
        covered_ids: set[str] = set()
        for name, ids in buckets.items():
            if name == "unclassified":
                continue
            id_set = {str(i) for i in ids}
            covered_ids |= id_set
            n_diff = len(id_set & diff_id_set)
            print(f"bucket={name} diffs={n_diff}/{len(id_set)}")
        unclassified_ids = all_ids - covered_ids
        n_diff = len(unclassified_ids & diff_id_set)
        print(f"bucket=unclassified diffs={n_diff}/{len(unclassified_ids)}")

    if precondition_error or sha_mismatch > 0:
        return 2
    if diffs > 0:
        return 1
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--check-fixtures", metavar="PATH")
    p.add_argument("--count-db", metavar="DB")
    p.add_argument("--json", metavar="OUT")
    p.add_argument("--compare", metavar="JSONL")
    p.add_argument("--db", metavar="DB")
    p.add_argument("--buckets", metavar="JSON")
    args = p.parse_args()

    if args.selftest:
        return run_selftest()
    if args.check_fixtures:
        return run_check_fixtures(args.check_fixtures)
    if args.count_db:
        if not args.json:
            print("--count-db requires --json <out>", file=sys.stderr)
            return 2
        return run_count_db(args.count_db, args.json)
    if args.compare:
        if not args.db:
            print("--compare requires --db <db>", file=sys.stderr)
            return 2
        return run_compare(args.compare, args.db, args.buckets)

    p.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
