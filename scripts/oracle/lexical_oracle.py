#!/usr/bin/env python3
"""T10 (plan v5.1): `lexical_oracle.py` -- independent (Python, not calling
into the Rust binary) re-verification of the lexical domain's completeness,
built on `normalize_v2.py`'s own `canonical_role`/`is_hard_noise`
re-implementations (the same functions `chunk_oracle.py` uses for the
semantic side).

A message is lexically eligible iff its role canonicalizes AND it is not
tool/short-acknowledgement noise -- the Python mirror of
`eligibility::lexical_eligible`, but independently re-derived rather than
imported from the Rust crate. For every message, the expected five-column
projection (`content` = raw content, `title`/`agent`/`workspace` = the
owning conversation/agent/workspace's own fields (empty string if absent),
`source_path` = the conversation's `source_path`) is compared against
`lex_docs`' stored row.

Usage: `python3 lexical_oracle.py --db <path> --report <json>`. Reports
`{checked, missing, extra, column_mismatch}` -- `missing` = eligible
messages absent from `lex_docs`; `extra` = `lex_docs` rows whose message is
NOT eligible; `column_mismatch` = doc_ids present on both sides where at
least one of the five columns differs. Exit codes: 0 all three zero; 1 any
nonzero; 2 precondition error (db missing/unreadable).
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize_v2 import canonical_role, is_hard_noise  # noqa: E402


def lexical_eligible(role_raw: str, content: str) -> bool:
    role = canonical_role(role_raw)
    if role is None:
        return False
    return not is_hard_noise(role, content)


def run(db_path: str, report_path: str) -> int:
    if not os.path.isfile(db_path):
        print(f"precondition error: db not found: {db_path}", file=sys.stderr)
        return 2

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error as e:
        print(f"precondition error: {e}", file=sys.stderr)
        return 2

    try:
        message_rows = conn.execute(
            "SELECT m.id, m.role, m.content, COALESCE(c.title, ''), COALESCE(a.slug, ''), "
            "COALESCE(w.path, ''), c.source_path "
            "FROM messages m JOIN conversations c ON c.id = m.conversation_id "
            "JOIN agents a ON a.id = c.agent_id LEFT JOIN workspaces w ON w.id = c.workspace_id"
        ).fetchall()

        eligible_projection: dict[int, tuple[str, str, str, str, str]] = {}
        for doc_id, role, content, title, agent, workspace, source_path in message_rows:
            if lexical_eligible(role, content or ""):
                eligible_projection[doc_id] = (content, title, agent, workspace, source_path)

        lex_doc_rows = conn.execute("SELECT doc_id, content, title, agent, workspace, source_path FROM lex_docs").fetchall()
        lex_docs: dict[int, tuple[str, str, str, str, str]] = {row[0]: tuple(row[1:]) for row in lex_doc_rows}
    finally:
        conn.close()

    eligible_ids = set(eligible_projection.keys())
    lex_doc_ids = set(lex_docs.keys())

    missing = len(eligible_ids - lex_doc_ids)
    extra = len(lex_doc_ids - eligible_ids)
    column_mismatch = sum(1 for doc_id in eligible_ids & lex_doc_ids if eligible_projection[doc_id] != lex_docs[doc_id])

    report = {
        "checked": len(message_rows),
        "missing": missing,
        "extra": extra,
        "column_mismatch": column_mismatch,
    }
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    print(f"lexical_oracle: checked={report['checked']} missing={missing} extra={extra} column_mismatch={column_mismatch}")
    return 1 if (missing or extra or column_mismatch) else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--db", required=True)
    p.add_argument("--report", required=True)
    args = p.parse_args()
    return run(args.db, args.report)


if __name__ == "__main__":
    sys.exit(main())
