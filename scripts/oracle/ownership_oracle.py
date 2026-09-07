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

T11.8.1: a request line may instead be `{"correlation_id": ...,
"chunk_idx": ..., "same_as_prev": true}`, omitting `role`/`content`
entirely -- means "this chunk's message is the same one the immediately
preceding line already carried in full". Reuses this script's own
one-slot (role, content) -> (normalized, spans) cache (below) rather than
re-deriving `role`/`content` from anywhere; a `same_as_prev` line with no
prior cached (role, content) -- e.g. the very first request line, or a
caller bug -- is a protocol error (`{"correlation_id": ..., "ok": false,
"error": "protocol_error: ..."}`, correlation_id preserved for tracing,
still counted toward this process's exit code same as any other protocol
error). Exists because a message with N chunks otherwise re-sent its
entire content N times over the pipe -- a real ~0.85 MB message with
~1,000 chunks was ~850 MB for that message alone.

Zero third-party dependencies (stdlib + `normalize_v2.py`).

Usage: `python3 ownership_oracle.py` (stdin/stdout only) or `python3
ownership_oracle.py --selftest` (no stdin needed -- exercises the
`same_as_prev` cache-hit/cache-miss paths directly). Exits 0 after
processing all input lines; 1 on a malformed input line or a
`same_as_prev` protocol violation (distinct from a per-record `ok: false`
verdict, which is expected/normal output, not a script failure).
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize_v2 import canonical_role, chunk_normalized, normalize  # noqa: E402

# T11.8: a message with N chunks sends N request lines sharing the same
# (role, content) -- without this cache, `normalize`+`chunk_normalized` ran
# once per chunk (N times) instead of once per message. Single-slot: only
# the immediately preceding (role, content) is remembered, matching the
# Rust side's own one-message-at-a-time cache and this script's protocol
# (a strict per-line stream, never reordered or replayed).
_cache_key: tuple[str, str] | None = None
_cache_normalized: str = ""
_cache_spans: list[tuple[int, int]] = []


def process_line(line: str) -> dict:
    global _cache_key, _cache_normalized, _cache_spans
    record = json.loads(line)
    correlation_id = record["correlation_id"]
    chunk_idx = record["chunk_idx"]

    if record.get("same_as_prev"):
        if _cache_key is None:
            return {"correlation_id": correlation_id, "ok": False, "error": "protocol_error: same_as_prev with no prior (role, content) cached"}
        role, content = _cache_key
    else:
        role = record["role"]
        content = record["content"]

    if canonical_role(role) is None:
        return {"correlation_id": correlation_id, "ok": False, "error": "non_whitelist_role"}

    cache_key = (role, content)
    if cache_key == _cache_key:
        normalized = _cache_normalized
        spans = _cache_spans
    else:
        normalized = normalize(content)
        spans = chunk_normalized(normalized) if normalized != "" else []
        _cache_key, _cache_normalized, _cache_spans = cache_key, normalized, spans

    if normalized == "":
        return {"correlation_id": correlation_id, "ok": False, "error": "canonicalize_empty"}

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
        if isinstance(result.get("error"), str) and result["error"].startswith("protocol_error"):
            had_protocol_error = True
        print(json.dumps(result), flush=True)
    return 1 if had_protocol_error else 0


def run_selftest() -> int:
    """T11.8.1: exercises `same_as_prev`'s cache-hit and cache-miss paths
    directly (no stdin needed) -- `python3 ownership_oracle.py --selftest`."""
    global _cache_key, _cache_normalized, _cache_spans
    _cache_key, _cache_normalized, _cache_spans = None, "", []

    # Cache miss: `same_as_prev` with nothing cached yet is a protocol
    # error, correlation_id preserved.
    miss = process_line(json.dumps({"correlation_id": 1, "chunk_idx": 0, "same_as_prev": True}))
    assert miss["correlation_id"] == 1, miss
    assert miss["ok"] is False, miss
    assert miss["error"].startswith("protocol_error"), miss

    # A full line seeds the (role, content) cache.
    content = "A same_as_prev selftest message, long enough to chunk cleanly for this test case here today."
    seeded = process_line(json.dumps({"correlation_id": 2, "role": "user", "content": content, "chunk_idx": 0}))
    assert seeded["ok"] is True, seeded

    # Cache hit: `same_as_prev` reuses the cached (role, content) and
    # reproduces the identical span for the same chunk_idx.
    hit = process_line(json.dumps({"correlation_id": 3, "chunk_idx": 0, "same_as_prev": True}))
    assert hit["ok"] is True, hit
    assert (hit["byte_start"], hit["byte_end"]) == (seeded["byte_start"], seeded["byte_end"]), (hit, seeded)

    print("ownership_oracle.py --selftest: OK")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(run_selftest())
    sys.exit(main())
