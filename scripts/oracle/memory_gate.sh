#!/bin/bash
# T10 (plan v5.1): memory_gate.sh -- the memory door's four-stage runner.
#
# Normal mode: memory_gate.sh <shape:a|b|c> <cass_wrapper>
#   Requires env: RUN_ROOT, GATES, EXAMPLES (matching this PR's run-root
#   env.sh conventions). Builds the shape's raw fixture once (via
#   $EXAMPLES/w4_memory_fixture) into $RUN_ROOT/mem-<shape>-fixture, then
#   runs 4 stages against an isolated data dir $RUN_ROOT/mem-<shape>, each a
#   fresh background invocation:
#     1. index                        (ingest the fixture)
#     2. index --force-rebuild
#     3. index --semantic
#     4. $EXAMPLES/w4_completeness_gate --db <data_dir>/agent_search.db
#        --json <stage 4 report>
#   Prints one JSON object per stage to stdout (one line each) and to
#   $RUN_ROOT/mem-<shape>-stage<N>.json, per the interface's report shape:
#   {shape, stage, pid, startup_rss, min_rss, peak_hwm, max_message_bytes,
#   pass_absolute, pass_relative}. Exit code = 1 if any stage fails either
#   judgment criterion (parameter-freeze "内存门" row: absolute PRIMARY,
#   relative secondary -- both must hold), 0 otherwise.
#
# --selfcheck mode (added for the interface's "门自验两例" -- not part of
# the plan's literal 4-arg signature, since the two self-checks need to run
# a stand-in process instead of `<cass_wrapper> index ...`):
#   memory_gate.sh --selfcheck <max_message_bytes> <startup_rss> -- <binary>
#   [binary-args...]
#   Runs exactly ONE stage against `<binary> [binary-args...]` (no
#   ingestion, no completeness gate -- the binary itself IS the process
#   under test), using the given max_message_bytes/startup_rss directly
#   instead of measuring/reading them from a real fixture+db, and prints the
#   same per-stage JSON shape (with `shape` and `stage` fixed to
#   "selfcheck"). Same exit-code convention.
#
# Methodology note (interface text, verbatim): "fork 后立即 50 ms 轮询
# /proc/<pid>/status: min_rss = min(VmRSS), peak = VmHWM (末次读数, 与
# /usr/bin/time -v 交叉核)". This script implements the poll-loop half of
# that; the `/usr/bin/time -v` cross-check is NOT implemented here (left as
# a documented gap, not silently skipped) -- `peak_hwm` is the last
# successfully read `VmHWM` value before the process exits (a kernel-
# monotonic counter, so "last reading before exit" is the true peak *unless*
# the process allocates, frees, and exits within a single 50ms poll gap,
# which the interface's own sampling cadence accepts as a known blind spot
# of external polling, not something this script can close).
set -u

usage() {
  echo "usage: memory_gate.sh <shape:a|b|c> <cass_wrapper>" >&2
  echo "       memory_gate.sh --selfcheck <max_message_bytes> <startup_rss> -- <binary> [args...]" >&2
  exit 2
}

poll_and_wait() {
  # $1 = pid to poll; on return, sets globals MIN_RSS_KB and PEAK_HWM_KB
  # (both in KiB, as /proc/<pid>/status reports VmRSS/VmHWM).
  local pid="$1"
  MIN_RSS_KB=""
  PEAK_HWM_KB=""
  while kill -0 "$pid" 2>/dev/null; do
    if [ -r "/proc/$pid/status" ]; then
      local rss hwm
      rss=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null)
      hwm=$(awk '/^VmHWM:/{print $2}' "/proc/$pid/status" 2>/dev/null)
      if [ -n "$rss" ]; then
        if [ -z "$MIN_RSS_KB" ] || [ "$rss" -lt "$MIN_RSS_KB" ]; then
          MIN_RSS_KB="$rss"
        fi
      fi
      if [ -n "$hwm" ]; then
        PEAK_HWM_KB="$hwm"
      fi
    fi
    sleep 0.05
  done
  wait "$pid"
  return $?
}

# Judgment (parameter-freeze "内存门" row): both must hold.
#   absolute: VmHWM <= startup_rss + 2*max_message_bytes + 256MiB
#   relative: VmHWM - min_VmRSS <= 2*max_message_bytes + 256MiB
# All arithmetic in bytes; /proc reports KiB, so callers pass *_kb and this
# converts. Sets PASS_ABSOLUTE / PASS_RELATIVE globals ("true"/"false").
judge() {
  local peak_hwm_kb="$1" min_rss_kb="$2" startup_rss_bytes="$3" max_message_bytes="$4"
  python3 - "$peak_hwm_kb" "$min_rss_kb" "$startup_rss_bytes" "$max_message_bytes" <<'PYEOF'
import sys
peak_hwm_kb, min_rss_kb, startup_rss, max_message_bytes = (int(x) for x in sys.argv[1:5])
peak_hwm = peak_hwm_kb * 1024
min_rss = min_rss_kb * 1024
budget = 2 * max_message_bytes + 256 * 1024 * 1024
pass_absolute = peak_hwm <= startup_rss + budget
pass_relative = (peak_hwm - min_rss) <= budget
print(f"{'true' if pass_absolute else 'false'} {'true' if pass_relative else 'false'}")
PYEOF
}

run_stage() {
  # $1=shape $2=stage_name $3=startup_rss_bytes $4=max_message_bytes $5=out_json -- rest: command to run
  local shape="$1" stage="$2" startup_rss="$3" max_message_bytes="$4" out_json="$5"
  shift 5

  "$@" &
  local pid=$!
  poll_and_wait "$pid"
  local rc=$?

  local peak_hwm_kb="${PEAK_HWM_KB:-0}"
  local min_rss_kb="${MIN_RSS_KB:-0}"
  local verdict
  verdict=$(judge "$peak_hwm_kb" "$min_rss_kb" "$startup_rss" "$max_message_bytes")
  local pass_absolute pass_relative
  pass_absolute=$(echo "$verdict" | awk '{print $1}')
  pass_relative=$(echo "$verdict" | awk '{print $2}')

  local peak_hwm_bytes=$((peak_hwm_kb * 1024))
  local min_rss_bytes=$((min_rss_kb * 1024))

  local json
  json=$(printf '{"shape":"%s","stage":"%s","pid":%d,"startup_rss":%d,"min_rss":%d,"peak_hwm":%d,"max_message_bytes":%d,"pass_absolute":%s,"pass_relative":%s,"exit_code":%d}' \
    "$shape" "$stage" "$pid" "$startup_rss" "$min_rss_bytes" "$peak_hwm_bytes" "$max_message_bytes" "$pass_absolute" "$pass_relative" "$rc")
  echo "$json" | tee "$out_json"

  if [ "$pass_absolute" = "true" ] && [ "$pass_relative" = "true" ]; then
    return 0
  else
    return 1
  fi
}

max_message_bytes_of_db() {
  sqlite3 "$1" "SELECT COALESCE(MAX(LENGTH(CAST(content AS BLOB))), 0) FROM messages;"
}

startup_rss_from_gates() {
  python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['startup_rss'])" "$GATES/startup-rss.json"
}

if [ "${1:-}" = "--selfcheck" ]; then
  max_message_bytes="${2:?missing max_message_bytes}"
  startup_rss="${3:?missing startup_rss}"
  shift 3
  if [ "${1:-}" != "--" ]; then
    usage
  fi
  shift
  [ $# -ge 1 ] || usage
  out_json="${RUN_ROOT:-/tmp}/memory-selfcheck-$$.json"
  run_stage "selfcheck" "selfcheck" "$startup_rss" "$max_message_bytes" "$out_json" "$@"
  exit $?
fi

[ $# -eq 2 ] || usage
shape="$1"
cass_wrapper="$2"
: "${RUN_ROOT:?RUN_ROOT must be set}"
: "${GATES:?GATES must be set}"
: "${EXAMPLES:?EXAMPLES must be set}"

fixture_dir="$RUN_ROOT/mem-${shape}-fixture"
data_dir="$RUN_ROOT/mem-${shape}"
rm -rf "$data_dir"
mkdir -p "$data_dir"

if [ ! -d "$fixture_dir" ]; then
  "$EXAMPLES/w4_memory_fixture" --shape "$shape" --out "$fixture_dir" || exit 2
fi

startup_rss=$(startup_rss_from_gates) || exit 2

overall_rc=0

export CASS_DATA_DIR="$data_dir"
export HOME="$fixture_dir"

run_stage "$shape" "index" "$startup_rss" 0 "$RUN_ROOT/mem-${shape}-stage1.json" \
  "$cass_wrapper" index || overall_rc=1
max_message_bytes=$(max_message_bytes_of_db "$data_dir/agent_search.db")

run_stage "$shape" "index_force_rebuild" "$startup_rss" "$max_message_bytes" "$RUN_ROOT/mem-${shape}-stage2.json" \
  "$cass_wrapper" index --force-rebuild || overall_rc=1

run_stage "$shape" "index_semantic" "$startup_rss" "$max_message_bytes" "$RUN_ROOT/mem-${shape}-stage3.json" \
  "$cass_wrapper" index --semantic || overall_rc=1

run_stage "$shape" "completeness_gate" "$startup_rss" "$max_message_bytes" "$RUN_ROOT/mem-${shape}-stage4.json" \
  "$EXAMPLES/w4_completeness_gate" --db "$data_dir/agent_search.db" --json "$RUN_ROOT/mem-${shape}-completeness.json" || overall_rc=1

exit "$overall_rc"
