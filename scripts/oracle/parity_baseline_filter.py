#!/usr/bin/env python3
"""T10 (plan v5.1): `parity_baseline_filter.py` -- re-cast a frozen W2
lexical-parity baseline (`tests/fixtures/w2-baseline-v3.jsonl`-shaped: one
JSON object per line, `{query, anchor_hit, anchor_rank, top10_source_paths}`)
under the v5 embedding-whitelist (`CanonicalRole`: user/assistant/tool_call/
tool_result -- reasoning and any other raw role stay excluded), producing a
`parity_baseline_v4.jsonl` with the same schema so it drops straight into
`w4_parity40 --baseline` / `tests/w2_lexical_parity.rs`'s loader.

Per baseline row: a hit's "matching message" is resolved against
`--db <frozen_snapshot.db>` by finding, among the conversation(s) at that
hit's `source_path`, the first message whose `content` contains the row's
`query` text (case-insensitive substring -- the same crude lexical-match
proxy the original W2 fts5/tantivy comparison used, since neither engine's
exact match internals are available to this offline filter). If that
message's role is not in the new whitelist, the hit is dropped from
`top10_source_paths` (order otherwise preserved); if no matching message can
be found at all, the hit is conservatively KEPT (logged to stderr) rather
than silently dropped on an inconclusive lookup.

The anchor's own source_path is derived from `anchor_rank` (1-indexed
position into the *original* `top10_source_paths`, `<=10` when
`anchor_hit`), then `anchor_hit`/`anchor_rank` are recomputed against the
*filtered* list (11 = sentinel "not present in the reconstructed top-10",
matching the existing schema's own miss-sentinel convention).

Zero third-party dependencies (stdlib + `normalize_v2.py`, this script's own
sibling, for `canonical_role`).

Usage: `python3 parity_baseline_filter.py --baseline <w2-baseline-v3.jsonl>
--db <frozen_snapshot.db> --out <parity_baseline_v4.jsonl>`. Exit codes: 0
always on a completed run (this is a data-transform tool, not a pass/fail
gate); 2 precondition error (missing/unparseable input files).
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize_v2 import canonical_role  # noqa: E402


def load_baseline(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def resolve_role_for_hit(conn: sqlite3.Connection, source_path: str, query: str) -> str | None:
    """Returns the canonical role of the first message whose content
    case-insensitively contains `query`, among conversations at
    `source_path` -- or the sentinel `"__no_match__"` if no such message
    exists (distinct from a real `None` canonical-role result, so the
    caller can tell "found but off-whitelist" from "couldn't resolve at
    all")."""
    cur = conn.execute(
        "SELECT m.role FROM messages m JOIN conversations c ON c.id = m.conversation_id "
        "WHERE c.source_path = ? AND m.content LIKE '%' || ? || '%' COLLATE NOCASE "
        "ORDER BY m.idx LIMIT 1",
        (source_path, query),
    )
    row = cur.fetchone()
    if row is None:
        return "__no_match__"
    return canonical_role(row[0])


def filter_row(conn: sqlite3.Connection, row: dict) -> tuple[dict, int]:
    query = row["query"]
    original_top10: list[str] = row["top10_source_paths"]
    anchor_hit: bool = row["anchor_hit"]
    anchor_rank: int = row["anchor_rank"]

    anchor_source_path = None
    if anchor_hit and 1 <= anchor_rank <= len(original_top10):
        anchor_source_path = original_top10[anchor_rank - 1]

    new_top10: list[str] = []
    dropped = 0
    for source_path in original_top10:
        role = resolve_role_for_hit(conn, source_path, query)
        if role == "__no_match__":
            print(f"WARN: query={query!r} source_path={source_path!r}: no matching message found, keeping hit", file=sys.stderr)
            new_top10.append(source_path)
        elif role is None:
            dropped += 1
        else:
            new_top10.append(source_path)

    if anchor_source_path is not None and anchor_source_path in new_top10:
        new_anchor_hit = True
        new_anchor_rank = new_top10.index(anchor_source_path) + 1
    else:
        new_anchor_hit = False
        new_anchor_rank = 11

    return (
        {
            "query": query,
            "anchor_hit": new_anchor_hit,
            "anchor_rank": new_anchor_rank,
            "top10_source_paths": new_top10,
        },
        dropped,
    )


def run(baseline_path: str, db_path: str, out_path: str) -> int:
    if not os.path.isfile(baseline_path):
        print(f"precondition error: baseline file not found: {baseline_path}", file=sys.stderr)
        return 2
    if not os.path.isfile(db_path):
        print(f"precondition error: db not found: {db_path}", file=sys.stderr)
        return 2

    try:
        rows = load_baseline(baseline_path)
    except (OSError, json.JSONDecodeError) as e:
        print(f"precondition error: {e}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        total_dropped = 0
        out_rows = []
        for row in rows:
            new_row, dropped = filter_row(conn, row)
            total_dropped += dropped
            out_rows.append(new_row)
    finally:
        conn.close()

    with open(out_path, "w", encoding="utf-8") as f:
        for row in out_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"parity_baseline_filter: {len(rows)} rows, {total_dropped} hit(s) dropped (non-whitelist role) -> {out_path}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", required=True)
    p.add_argument("--db", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    return run(args.baseline, args.db, args.out)


if __name__ == "__main__":
    sys.exit(main())
