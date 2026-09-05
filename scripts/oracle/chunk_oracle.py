#!/usr/bin/env python3
"""T10 (plan v5.1): `chunk_oracle.py` -- independent (Python, not calling
into the Rust binary) re-verification of the semantic domain's chunk
correctness, stratified-sampled from a real database rather than exhaustive
(exhaustive coverage is `w4_completeness_gate`'s job; this oracle trades
completeness for depth -- it recomputes each sampled message's *entire*
expected chunk set, including exact spans and hashes, and diffs it against
what's actually stored).

Stratified sample (seeded, deterministic -- `--seed`), union of:
  - up to 200 messages per `CanonicalRole` (user/assistant/tool_call/tool_result)
  - up to 100 messages per raw-content-length quintile (5 buckets over ALL
    messages' `len(content)`, not just whitelisted ones)
  - up to 200 messages containing a markdown code fence (` ``` `)
  - up to 200 messages with at least one non-ASCII character
  - up to 200 messages from the single largest conversation (by message count)
  - ALL messages whose raw `role` does not canonicalize at all (a rare-role
    census, not a sample -- there typically aren't many, and undersampling
    them would miss role-aliasing regressions entirely)

For each sampled message, independently computes the *entire* expected
chunk set (empty if role is non-whitelist or normalized text is empty,
else one `(chunk_idx, byte_start, byte_end, content_hash)` tuple per
`normalize_v2.chunk_normalized` span) and compares it against
`message_chunks` for the database's active generation.

Usage: `python3 chunk_oracle.py --db <path> --seed 20260903 --report
<json>`, or `python3 chunk_oracle.py --selftest` (no db needed -- exercises
`normalize_v2`'s own selftest plus this script's independent hash/sampling
logic against fixed inputs). Exit codes: 0 zero diffs; 1 nonzero diffs
(`--db` mode) or a selftest assertion failed; 2 precondition error (db
missing, no active generation).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize_v2 import canonical_role, chunk_normalized, chunk_text, normalize  # noqa: E402

CATEGORY_CAPS = {
    "role": 200,
    "length_quintile": 100,
    "code_fence": 200,
    "non_ascii": 200,
    "largest_conversation": 200,
}


def content_hash_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def expected_chunks_for_message(role_raw: str, content: str) -> list[tuple[int, int, int, str]]:
    """Returns `[(chunk_idx, byte_start, byte_end, content_hash), ...]`,
    empty when the role is out of whitelist or normalized text is empty --
    mirrors `eligibility::expected_chunks`, independently re-derived."""
    if canonical_role(role_raw) is None:
        return []
    normalized = normalize(content)
    if normalized == "":
        return []
    out = []
    for idx, span in enumerate(chunk_normalized(normalized)):
        text = chunk_text(normalized, span)
        out.append((idx, span[0], span[1], content_hash_hex(text)))
    return out


def stratified_sample(rows: list[tuple], seed: int) -> tuple[set[int], dict[str, int]]:
    """`rows`: `(id, conversation_id, role, content)` tuples. Returns
    `(sampled_ids, counts_by_category)`."""
    rng = random.Random(seed)
    sampled: set[int] = set()
    counts: dict[str, int] = {}

    def take(pool: list[tuple], cap: int, label: str) -> None:
        chosen = pool if len(pool) <= cap else rng.sample(pool, cap)
        counts[label] = len(chosen)
        for row in chosen:
            sampled.add(row[0])

    by_role: dict[str, list[tuple]] = {}
    rare_role_rows: list[tuple] = []
    for row in rows:
        _id, _conv, role_raw, _content = row
        role = canonical_role(role_raw)
        if role is None:
            rare_role_rows.append(row)
        else:
            by_role.setdefault(role, []).append(row)
    for role, pool in by_role.items():
        take(pool, CATEGORY_CAPS["role"], f"role:{role}")
    counts["rare_role_all"] = len(rare_role_rows)
    for row in rare_role_rows:
        sampled.add(row[0])

    lengths = sorted(len(row[3] or "") for row in rows)
    if lengths:
        n = len(lengths)
        boundaries = [lengths[min(int(n * q / 5), n - 1)] for q in range(1, 5)]

        def quintile_of(length: int) -> int:
            for i, b in enumerate(boundaries):
                if length <= b:
                    return i
            return 4

        buckets: dict[int, list[tuple]] = {i: [] for i in range(5)}
        for row in rows:
            buckets[quintile_of(len(row[3] or ""))].append(row)
        for q, pool in buckets.items():
            take(pool, CATEGORY_CAPS["length_quintile"], f"length_quintile:{q}")

    code_fence_pool = [row for row in rows if "```" in (row[3] or "")]
    take(code_fence_pool, CATEGORY_CAPS["code_fence"], "code_fence")

    non_ascii_pool = [row for row in rows if any(ord(ch) > 127 for ch in (row[3] or ""))]
    take(non_ascii_pool, CATEGORY_CAPS["non_ascii"], "non_ascii")

    by_conversation: dict[int, list[tuple]] = {}
    for row in rows:
        by_conversation.setdefault(row[1], []).append(row)
    if by_conversation:
        largest_conv = max(by_conversation, key=lambda c: len(by_conversation[c]))
        take(by_conversation[largest_conv], CATEGORY_CAPS["largest_conversation"], "largest_conversation")

    return sampled, counts


def run(db_path: str, seed: int, report_path: str) -> int:
    if not os.path.isfile(db_path):
        print(f"precondition error: db not found: {db_path}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        gen_row = conn.execute("SELECT id FROM embedding_generations WHERE is_active = 1").fetchone()
        if gen_row is None:
            print("precondition error: no active embedding_generation", file=sys.stderr)
            return 2
        generation_id = gen_row[0]

        rows = conn.execute("SELECT id, conversation_id, role, content FROM messages").fetchall()
        sampled_ids, counts_by_category = stratified_sample(rows, seed)
        rows_by_id = {row[0]: row for row in rows}

        diffs = []
        for message_id in sorted(sampled_ids):
            _id, _conv, role_raw, content = rows_by_id[message_id]
            expected = expected_chunks_for_message(role_raw, content or "")

            actual_rows = conn.execute(
                "SELECT chunk_idx, byte_start, byte_end, content_hash FROM message_chunks "
                "WHERE generation_id = ? AND message_id = ? ORDER BY chunk_idx",
                (generation_id, message_id),
            ).fetchall()
            actual = [tuple(r) for r in actual_rows]

            if actual != expected:
                diffs.append({"message_id": message_id, "expected": expected, "actual": actual})
    finally:
        conn.close()

    report = {
        "checked": len(sampled_ids),
        "sampled_by_category": counts_by_category,
        "diffs": len(diffs),
        "diff_details": diffs[:50],
        "seed": seed,
    }
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    print(f"chunk_oracle: checked={report['checked']} diffs={report['diffs']} seed={seed}")
    return 1 if diffs else 0


def run_selftest() -> int:
    failed = False

    def check(cond: bool, msg: str) -> None:
        nonlocal failed
        if not cond:
            failed = True
            print(f"FAIL {msg}")
        else:
            print(f"ok   {msg}")

    # normalize_v2's own selftest is the foundation this oracle builds on.
    import normalize_v2

    if normalize_v2.run_selftest() != 0:
        failed = True

    # This script's own hash function must match Rust's content_hash_hex
    # convention (SHA-256 hex over UTF-8 bytes) -- pinned against a known
    # vector rather than re-deriving it from normalize_v2.
    check(content_hash_hex("test") == hashlib.sha256(b"test").hexdigest(), "content_hash_hex matches raw hashlib.sha256 hex digest")

    # expected_chunks_for_message: whitelist + empty-normalization + real chunking.
    check(expected_chunks_for_message("reasoning", "anything at all, long enough to chunk if it were whitelisted") == [], "non-whitelist role produces zero expected chunks")
    check(expected_chunks_for_message("user", "OK") == [], "canonicalize-empty content produces zero expected chunks")
    long_text = "a" * 1200 + "b" * 1200
    chunks = expected_chunks_for_message("user", long_text)
    check(len(chunks) > 1, "long content produces multiple expected chunks")
    check(len({c[3] for c in chunks}) == len(chunks), "every expected chunk's hash is distinct")

    # Stratified sampling: deterministic under a fixed seed, and every
    # sampled id is a real row id (no fabricated ids).
    rows = [(i, 1, "user", f"message body number {i} with enough content to not be filtered as noise at all.") for i in range(1, 501)]
    sample_a, _ = stratified_sample(rows, seed=42)
    sample_b, _ = stratified_sample(rows, seed=42)
    check(sample_a == sample_b, "stratified_sample is deterministic under a fixed seed")
    check(sample_a.issubset({row[0] for row in rows}), "every sampled id is a real row id")

    return 1 if failed else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--db")
    p.add_argument("--seed", type=int)
    p.add_argument("--report")
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args()

    if args.selftest:
        return run_selftest()
    if not args.db or args.seed is None or not args.report:
        print("--db, --seed, and --report are all required (unless --selftest)", file=sys.stderr)
        return 2
    return run(args.db, args.seed, args.report)


if __name__ == "__main__":
    sys.exit(main())
