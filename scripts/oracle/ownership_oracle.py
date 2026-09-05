#!/usr/bin/env python3
"""T10 (plan v5.1): `ownership_oracle.py` -- the independent re-chunking
half of `w4_ownership_oracle`. The Rust side owns fetching stored chunks
(with their storage span) and re-embedding via Infinity; this script owns
computing what the span SHOULD independently be, using `normalize_v2.py`
(this script's sibling, itself an independent re-implementation of the
chunking rules, not a call into the Rust binary) rather than trusting the
Rust binary's own chunking code to grade itself.

Protocol: reads one JSON object per line from stdin --
`{"correlation_id": <chunk_id>, "role": <raw role string>, "content": <raw
message content>, "chunk_idx": <int>}` -- and writes exactly one JSON object
per line to stdout, in the same order:
  - `{"correlation_id": ..., "ok": true, "byte_start": ..., "byte_end": ...}`
    when `chunk_idx` resolves to a real, independently-recomputed span.
  - `{"correlation_id": ..., "ok": false, "error": "<reason>"}` otherwise,
    `<reason>` one of `non_whitelist_role` (role outside `CanonicalRole`),
    `canonicalize_empty` (normalized text is empty), or
    `chunk_idx_out_of_range` (fewer independent chunks than `chunk_idx`+1 --
    itself evidence of an ownership mismatch, since the caller only ever
    asks about a `chunk_idx` it found stored in `message_chunks`).

Zero third-party dependencies (stdlib + `normalize_v2.py`).

Usage: `python3 ownership_oracle.py` (stdin/stdout only, no CLI flags).
Exits 0 after processing all input lines; 1 on a malformed input line
(protocol error, distinct from a per-record `ok: false` verdict, which is
expected/normal output, not a script failure).
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize_v2 import canonical_role, chunk_normalized, normalize  # noqa: E402


def process_line(line: str) -> dict:
    record = json.loads(line)
    correlation_id = record["correlation_id"]
    role = record["role"]
    content = record["content"]
    chunk_idx = record["chunk_idx"]

    if canonical_role(role) is None:
        return {"correlation_id": correlation_id, "ok": False, "error": "non_whitelist_role"}

    normalized = normalize(content)
    if normalized == "":
        return {"correlation_id": correlation_id, "ok": False, "error": "canonicalize_empty"}

    spans = chunk_normalized(normalized)
    if chunk_idx < 0 or chunk_idx >= len(spans):
        return {"correlation_id": correlation_id, "ok": False, "error": "chunk_idx_out_of_range"}

    byte_start, byte_end = spans[chunk_idx]
    return {"correlation_id": correlation_id, "ok": True, "byte_start": byte_start, "byte_end": byte_end}


def main() -> int:
    had_protocol_error = False
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            result = process_line(line)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            had_protocol_error = True
            print(json.dumps({"ok": False, "error": f"protocol_error: {e}"}), flush=True)
            continue
        print(json.dumps(result), flush=True)
    return 1 if had_protocol_error else 0


if __name__ == "__main__":
    sys.exit(main())
