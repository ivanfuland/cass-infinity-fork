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
# short_tool_acks [6] + prefixed_tool_acks [8] = 34 phrases/prefixes).
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
    return is_tool_acknowledgement(role, text)


# ---------------------------------------------------------------------------
# normalize: canonicalize_for_embedding, stages (1)(2)(3)(5) + stage 4.
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"^\s*```")
_HEADER_RE = re.compile(r"^(\s*)(#{1,6})(\s+)(.*)$")
_BLOCKQUOTE_RE = re.compile(r"^(\s*)>+\s?(.*)$")
_LIST_RE = re.compile(r"^(\s*)(?:[-+]|\d+\.)\s+(.*)$")
_LINK_RE = re.compile(r"\[([^\]\n]*)\]\(([^)\n]*)\)")
_INLINE_CODE_RE = re.compile(r"`([^`\n]+?)`")
_INTRALINE_WS_RE = re.compile(r"[ \t\r\f\v]+")
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


def _strip_inline_markdown(line: str) -> str:
    # Order: links first (so bracket/paren text isn't mistaken for emphasis
    # markers), then emphasis chars, then inline code.
    line = _LINK_RE.sub(lambda m: f"{m.group(1)} {m.group(2)}", line)
    line = _strip_emphasis_chars(line)
    line = _INLINE_CODE_RE.sub(lambda m: m.group(1), line)
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


def _normalize_whitespace(text: str) -> str:
    lines = text.split("\n")
    lines = [_INTRALINE_WS_RE.sub(" ", ln).strip(" \t\r\f\v") for ln in lines]
    joined = "\n".join(lines)
    joined = _MULTI_NEWLINE_RE.sub("\n\n", joined)
    return joined.strip("\n \t\r\f\v")


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


def run_selftest() -> int:
    checks = [
        ("properties_cover_and_overlap", _selftest_properties),
        ("prefers_paragraph_then_line_then_space", _selftest_prefers_paragraph_then_line_then_space),
        ("early_separator_does_not_stall", _selftest_early_separator_does_not_stall),
        ("role_alias_table", _selftest_role_alias_table),
        ("normalize_v2_rule_examples", _selftest_normalize_examples),
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


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--check-fixtures", metavar="PATH")
    p.add_argument("--count-db", metavar="DB")
    p.add_argument("--json", metavar="OUT")
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

    p.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
