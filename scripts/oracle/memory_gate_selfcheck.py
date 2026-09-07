#!/usr/bin/env python3
"""T10 (plan v5.1): `memory_gate_selfcheck.py` -- a tiny stand-in process
for `memory_gate.sh`'s `--selfcheck` mode, used to prove the memory door's
judgment math actually catches a real over-budget process (rather than
trivially passing everything because nothing ever gets measured correctly).

`--alloc-and-hold <SIZE>` (e.g. `1536MiB`, `512KiB`, `2GiB`): allocates a
single `bytearray` of that size immediately on startup (forcing real RSS,
not a lazy/virtual mapping -- `bytearray(n)` zero-fills eagerly in CPython),
holds it until the process is signaled to exit, and prints no progress
output at all (the gate's poll loop must not be able to "cheat" by reading
stdout for hints -- it only ever sees `/proc/<pid>/status`). Exits on
SIGTERM/SIGINT (the gate's caller is expected to send one once its own
per-stage timeout or explicit stop condition is reached) or after
`--hold-seconds` (default 30) if no signal arrives first.

Zero third-party dependencies (stdlib only).

Usage: `python3 memory_gate_selfcheck.py --alloc-and-hold 1536MiB
[--hold-seconds 30]`. Always exits 0 (this is the *process under test*, not
a judge -- the pass/fail verdict is `memory_gate.sh`'s job, computed from
this process's observed RSS/HWM).
"""

from __future__ import annotations

import argparse
import re
import signal
import sys
import time

_UNIT_MULTIPLIERS = {
    "b": 1,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
}

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]+)\s*$")


def parse_size(text: str) -> int:
    m = _SIZE_RE.match(text)
    if not m:
        raise ValueError(f"cannot parse size {text!r} (expected e.g. '1536MiB', '512KiB', '2GiB')")
    value, unit = m.group(1), m.group(2).lower()
    if unit not in _UNIT_MULTIPLIERS:
        raise ValueError(f"unknown size unit {unit!r} in {text!r}")
    return int(float(value) * _UNIT_MULTIPLIERS[unit])


_stop = False


def _handle_stop(signum, frame) -> None:  # noqa: ANN001
    global _stop
    _stop = True


def run(size_bytes: int, hold_seconds: float) -> int:
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    # bytearray(n) eagerly zero-fills -- real, resident memory, not a
    # lazily-faulted virtual mapping mmap.mmap could leave un-touched.
    held = bytearray(size_bytes)
    held[0] = 1  # touch it, defeating any hypothetical copy-on-write trick
    held[-1] = 1

    deadline = time.monotonic() + hold_seconds
    while not _stop and time.monotonic() < deadline:
        time.sleep(0.05)

    del held
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--alloc-and-hold", required=True, metavar="SIZE")
    p.add_argument("--hold-seconds", type=float, default=30.0)
    args = p.parse_args()

    size_bytes = parse_size(args.alloc_and_hold)
    return run(size_bytes, args.hold_seconds)


if __name__ == "__main__":
    sys.exit(main())
