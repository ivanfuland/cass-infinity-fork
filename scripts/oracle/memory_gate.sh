#!/bin/bash
# #122b-1 (spec v4.5 §四.3 / plan Task 4 Step 4 / parameter-freeze "内存门"
# row): memory_gate.sh -- the memory door's process-tree gate, replacing the
# PR4 T10 single-process/absolute-relative-budget form (T12 复盘已判该预算
# 模型连基线都过不了, retired).
#
# Measurement object = the cass PROCESS TREE, not one pid. The wrapper
# under test must `exec` itself into the measured binary (cass-cand.sh does
# this already), so the pid this script backgrounds via `"$@" &` IS the
# tree's root. Every 100ms (fixed -- this script does not implement the
# spec's "阶段短于2个周期用50ms" adaptive-interval exception: that requires
# knowing a stage's duration before it finishes, which a live single-pass
# poll cannot; whether a stage is `measured` depends only on `samples>=2 ∧
# stage_ms>=200`, both of which a 100ms-fixed cadence still resolves
# correctly for any stage lasting >=1 poll period -- 2026-09-11 control-
# plane approved this reading over the spec's literal adaptive wording),
# one sample = one pass over /proc/[0-9]*/stat (pure bash builtins, no
# forked `ps`/`pgrep`/`awk` per sample -- see collect_process_maps below)
# to rebuild the whole system's pid->ppid map, then a BFS closure from the
# root pid gives this poll's tree membership. For each tree member still
# alive, one read of /proc/<pid>/status (again pure bash, no fork) gives
# VmRSS (summed into this sample's tree_rss) and VmHWM (folded into that
# pid's running-max, kept in PEAK_PROC_KB even after the pid exits and
# drops out of /proc, since VmHWM is monotonic and its last reading before
# exit is real "peak-and-not-yet-reused-since" data).
#
# Normal mode: memory_gate.sh [--collect-baseline] [--stage4-db <path>]
#   <shape:a|b|c> <cass_wrapper>
#   Requires env RUN_ROOT, EXAMPLES, XDG_CONFIG_HOME, W6 (W6 holds
#   memgate-baseline.json, read for the budget unless --collect-baseline).
#   Builds the shape's fixture once (via $EXAMPLES/w4_memory_fixture, which
#   also freezes <fixture_dir>/manifest.json) into
#   $RUN_ROOT/mem-<shape>-fixture, then runs 4 stages against an isolated
#   data dir $RUN_ROOT/mem-<shape>:
#     1. index                        (ingest the fixture)
#     2. index --force-rebuild
#     3. index --semantic
#     4. $EXAMPLES/w4_completeness_gate --db <stage4 db> --json <report>
#   Stage 4 always measures against its OWN db (--stage4-db, or
#   <data_dir>-stage4/agent_search.db by default) -- per parameter-freeze,
#   stage 4's baseline binary (82cd5f0a) differs from stages 1-3's
#   (4423e48b) and never shares a measurement unit with them; stage_merge
#   (from the fixture manifest) may only combine stages within 1-3.
#   Prints one JSON object per stage to stdout (one line each) and to
#   $RUN_ROOT/mem-<shape>-stage<N>.json:
#   {shape, stage, pid, peak_tree, peak_proc, samples, stage_ms, measured,
#   merged_from, budget, exit_code, binary_sha256, fixture_sha256} (bytes
#   throughout, budget/merged_from may be null/[]). Stage 1's JSON also
#   carries `ingested_sessions` (session count read from the stage db's
#   `conversations` table -- the other option the mission text allows,
#   `cass index --json`'s own field, isn't used because this script never
#   parses the wrapped binary's stdout for anything else today and adding
#   that parsing path is exactly the kind of scope growth #122b-1's
#   boundary order forbids for a single-field readout).
#   Exit code = 1 if any stage fails judgment (measured && exit_code==0 &&
#   max(peak_tree,peak_proc)<=budget when budget is non-null; budget is
#   null only in --collect-baseline/--selfcheck, where judgment drops the
#   budget term), 0 otherwise. --collect-baseline additionally asserts
#   `pgrep -x cargo`/`pgrep -x cass` are both empty before sampling, and
#   never reads/judges against $W6/memgate-baseline.json -- P0 itself is
#   collected in --collect-baseline mode, so it cannot also be an input.
#   Outside --collect-baseline, a missing/incomplete
#   $W6/memgate-baseline.json entry for a [shape,stage] is a fail-loud exit
#   2 (never a silent 0 budget -- #122b-1 boundary order).
#
# --selfcheck mode (the interface's own self-test surface, T14-3 /
# tests/w6_memory_gate_selfcheck.rs's entry point):
#   memory_gate.sh --selfcheck -- <binary> [binary-args...]
#   Runs exactly ONE stage against `<binary> [binary-args...]` (no
#   fixture, no ingestion, no completeness gate -- the binary itself IS the
#   process under test), shape/stage fixed to "selfcheck", budget/
#   merged_from/binary_sha256/fixture_sha256 all null (there is no P0, no
#   fixture, and hashing an arbitrary selfcheck binary buys nothing).
#   Verdict = measured && exit_code==0 (no budget term). Same JSON/exit
#   convention as normal mode, written to
#   $RUN_ROOT/memory-selfcheck-$$.json (or /tmp if RUN_ROOT unset).
#
# --judge mode (standalone judgment, for testing "空输入 fail-loud" without
# a real stage run): memory_gate.sh --judge < stage.json
#   Reads one stage-result JSON object from stdin, applies the same
#   judgment `judge_from_stdin` uses internally, exits 0 (pass) / 1 (fail)
#   / 2 (empty input, invalid JSON, a field missing, or a field whose type
#   or value is not a valid measurement -- #123 R6-B1: these are treated
#   as an adversary's input, so `"false"` is not a bool, a negative peak is
#   not a count, and `measured=true` needs the samples/stage_ms the
#   emitter's own rule requires). Fail-loud, never defaults. This is also
#   how run_stage's own judgment
#   step is implemented (it pipes the JSON it just built through the same
#   function), so there is exactly one judgment code path.
set -u

usage() {
  echo "usage: memory_gate.sh [--collect-baseline] [--stage4-db <path>] <shape:a|b|c> <cass_wrapper>" >&2
  echo "       memory_gate.sh --selfcheck -- <binary> [args...]" >&2
  echo "       memory_gate.sh --judge   # reads one stage JSON object from stdin" >&2
  exit 2
}

POLL_INTERVAL_S=0.1

# ---------------------------------------------------------------------
# Process-tree sampling (no forked ps/pgrep/awk in the poll loop).
# ---------------------------------------------------------------------

declare -A PPID_OF
declare -A CHILDREN
declare -A PEAK_PROC_KB

# One pass over /proc/[0-9]*/stat -> PPID_OF[pid]=ppid, CHILDREN[ppid]="pid1
# pid2 ...". /proc/<pid>/stat's format is "<pid> (<comm>) <state> <ppid>
# ..."; comm may itself contain spaces or parens, so this splits on the
# LAST ") " rather than trusting field position, matching the kernel's own
# documented escaping convention for this file.
collect_process_maps() {
  PPID_OF=()
  CHILDREN=()
  local f pid line after ppid
  for f in /proc/[0-9]*/stat; do
    [ -r "$f" ] || continue
    read -r line < "$f" 2>/dev/null || continue
    pid="${f#/proc/}"
    pid="${pid%/stat}"
    after="${line##*) }"   # "<state> <ppid> <pgrp> ..."
    set -- $after
    ppid="${2:-0}"
    PPID_OF["$pid"]="$ppid"
    CHILDREN["$ppid"]+=" $pid"
  done
}

# BFS closure of $1's descendants (including $1 itself), one pid per line.
tree_pids_of() {
  local root="$1"
  local -a queue=("$root")
  local -A seen=(["$root"]=1)
  local i=0 qpid c
  while [ "$i" -lt "${#queue[@]}" ]; do
    qpid="${queue[$i]}"
    i=$((i + 1))
    echo "$qpid"
    for c in ${CHILDREN[$qpid]:-}; do
      if [ -z "${seen[$c]:-}" ]; then
        seen["$c"]=1
        queue+=("$c")
      fi
    done
  done
}

# Pure-bash read of /proc/<pid>/status's VmRSS/VmHWM lines (kB), no fork.
# Sets STATUS_VMRSS_KB / STATUS_VMHWM_KB (empty string if unreadable/absent).
read_status_kb() {
  STATUS_VMRSS_KB=""
  STATUS_VMHWM_KB=""
  local line val
  while IFS= read -r line; do
    case "$line" in
      VmRSS:*)
        val="${line#VmRSS:}"; val="${val%kB}"; val="${val// /}"
        STATUS_VMRSS_KB="$val"
        ;;
      VmHWM:*)
        val="${line#VmHWM:}"; val="${val%kB}"; val="${val// /}"
        STATUS_VMHWM_KB="$val"
        ;;
    esac
  done < "/proc/$1/status" 2>/dev/null
}

# One sample against $1=root pid: rebuilds the process maps, sums VmRSS
# across the current tree into SAMPLE_TREE_RSS_KB, folds VmHWM into the
# (persistent, across-samples) PEAK_PROC_KB per-pid running max.
# SAMPLE_PID_COUNT = how many tree members were actually readable this
# sample (0 means the sample caught nothing, e.g. the process had already
# exited -- callers must not count that as a sample).
sample_tree() {
  local root="$1"
  collect_process_maps
  local pid sum=0 count=0
  for pid in $(tree_pids_of "$root"); do
    [ -r "/proc/$pid/status" ] || continue
    read_status_kb "$pid"
    if [ -n "$STATUS_VMRSS_KB" ]; then
      sum=$((sum + STATUS_VMRSS_KB))
      count=$((count + 1))
    fi
    if [ -n "$STATUS_VMHWM_KB" ]; then
      local prev="${PEAK_PROC_KB[$pid]:-0}"
      if [ "$STATUS_VMHWM_KB" -gt "$prev" ]; then
        PEAK_PROC_KB["$pid"]="$STATUS_VMHWM_KB"
      fi
    fi
  done
  SAMPLE_TREE_RSS_KB="$sum"
  SAMPLE_PID_COUNT="$count"
}

# ---------------------------------------------------------------------
# Judgment (single code path for both run_stage's internal use and the
# standalone `--judge` CLI surface).
# ---------------------------------------------------------------------

# Reads one stage-result JSON object from stdin; exits 0 (pass) / 1 (fail)
# / 2 (empty input, invalid JSON, or missing a required field).
judge_from_stdin() {
  # NOTE: this must be `python3 -c '<code>'`, NOT `python3 - <<'PYEOF'`.
  # `python3 -` reads its own PROGRAM from stdin, so a heredoc there
  # supplies the code and leaves nothing in stdin for `sys.stdin.read()`
  # to see -- every caller would get a false "empty input". `-c` takes the
  # code as an argv string instead, leaving the piped JSON on stdin where
  # `sys.stdin.read()` can actually read it (caught via the --selfcheck
  # smoke test below, which is why this note exists).
  python3 -c '
import json
import sys

raw = sys.stdin.read()
if not raw.strip():
    print("judge: empty input", file=sys.stderr)
    sys.exit(2)
try:
    obj = json.loads(raw)
except json.JSONDecodeError as e:
    print(f"judge: invalid JSON: {e}", file=sys.stderr)
    sys.exit(2)

required = ["measured", "exit_code", "peak_tree", "peak_proc"]
missing = [k for k in required if k not in obj]
if missing:
    print(f"judge: missing required field(s): {missing}", file=sys.stderr)
    sys.exit(2)

def is_int(v):
    # bool is an int subclass in Python; a JSON `true` is not a count.
    return isinstance(v, int) and not isinstance(v, bool)

# R6-B1 (control-plane adversarial review of T4, blocker class: false
# green). The hand-fillable surfaces here (a hand-written P0 entry, or any
# JSON piped into `--judge`) must be validated as adversarial input, not
# trusted: `bool(measured)` alone accepted the string `"false"` as true,
# zero samples and zero stage_ms passed as a valid measurement, negative
# peaks compared as numbers, and an absent `budget` key silently dropped
# the budget term (the four reproductions in the review all exited 0).
# Types are checked before values, and an internally inconsistent object
# (`measured=true` with fewer than the two samples / 200ms that run_stage
# itself requires) is malformed input, not a pass.
measured = obj["measured"]
exit_code = obj["exit_code"]
peak_tree = obj["peak_tree"]
peak_proc = obj["peak_proc"]

if not isinstance(measured, bool):
    print(f"judge: field measured must be a JSON bool, got {measured!r}", file=sys.stderr)
    sys.exit(2)
for name, value in (("exit_code", exit_code), ("peak_tree", peak_tree), ("peak_proc", peak_proc)):
    if not is_int(value) or value < 0:
        print(f"judge: field {name} must be a non-negative integer, got {value!r}", file=sys.stderr)
        sys.exit(2)
for name in ("samples", "stage_ms"):
    value = obj.get(name)
    if value is not None and (not is_int(value) or value < 0):
        print(f"judge: field {name} must be a non-negative integer, got {value!r}", file=sys.stderr)
        sys.exit(2)
if measured and not (is_int(obj.get("samples")) and obj["samples"] >= 2
                     and is_int(obj.get("stage_ms")) and obj["stage_ms"] >= 200):
    print(
        "judge: measured=true requires samples>=2 and stage_ms>=200 (the same rule run_stage uses to set measured)",
        file=sys.stderr,
    )
    sys.exit(2)

# `budget` is null only in --collect-baseline/--selfcheck, both of which
# still *emit* the key; a normal stage result whose key is absent is a
# hand-trimmed object, not a collected one -- fail loud rather than
# silently dropping the budget term. (An explicit null for a normal shape
# stays accepted: --collect-baseline also pipes its stages through this
# same judgment, and that run legitimately carries null.)
if "budget" not in obj and obj.get("shape") != "selfcheck":
    print("judge: missing required field budget for a non-selfcheck stage (fail-loud, not a free pass)", file=sys.stderr)
    sys.exit(2)
budget = obj.get("budget")
if budget is not None and (not is_int(budget) or budget < 0):
    print(f"judge: field budget must be null or a non-negative integer, got {budget!r}", file=sys.stderr)
    sys.exit(2)

ok = measured and exit_code == 0
if budget is not None:
    ok = ok and max(peak_tree, peak_proc) <= budget
sys.exit(0 if ok else 1)
'
}

# ---------------------------------------------------------------------
# JSON assembly (one place, via python3 json.dumps -- never hand-printf'd,
# since budget/merged_from/binary_sha256/fixture_sha256 can all be null).
# ---------------------------------------------------------------------

emit_stage_json() {
  # $1=shape $2=stage $3=pid $4=peak_tree_bytes $5=peak_proc_bytes
  # $6=samples $7=stage_ms $8=measured(true/false) $9=merged_from_csv
  # $10=budget_bytes("" -> null) $11=exit_code $12=binary_sha256("" -> null)
  # $13=fixture_sha256("" -> null)
  python3 - "$@" <<'PYEOF'
import json
import sys

(shape, stage, pid, peak_tree, peak_proc, samples, stage_ms, measured,
 merged_from_csv, budget, exit_code, binary_sha256, fixture_sha256) = sys.argv[1:14]

obj = {
    "shape": shape,
    "stage": stage,
    "pid": int(pid),
    "peak_tree": int(peak_tree),
    "peak_proc": int(peak_proc),
    "samples": int(samples),
    "stage_ms": int(stage_ms),
    "measured": measured == "true",
    "merged_from": [s for s in merged_from_csv.split(",") if s] if merged_from_csv else [],
    "budget": None if budget == "" else int(budget),
    "exit_code": int(exit_code),
    "binary_sha256": binary_sha256 or None,
    "fixture_sha256": fixture_sha256 or None,
}
print(json.dumps(obj))
PYEOF
}

# ---------------------------------------------------------------------
# One stage: background the command, poll its process tree until it
# exits, judge, emit+tee the JSON, return the judgment's exit code.
# ---------------------------------------------------------------------

run_stage() {
  # $1=shape $2=stage $3=budget_bytes("" -> null) $4=merged_from_csv
  # $5=binary_sha256 $6=fixture_sha256 $7=out_json -- rest: the command to
  # run
  local shape="$1" stage="$2" budget="$3" merged_from_csv="$4"
  local binary_sha256="$5" fixture_sha256="$6" out_json="$7"
  shift 7

  "$@" &
  local root_pid=$!

  PEAK_PROC_KB=()
  local peak_tree_kb=0 samples=0
  local start_ns end_ns
  start_ns=$(date +%s%N)

  while :; do
    sample_tree "$root_pid"
    if [ "${SAMPLE_PID_COUNT:-0}" -gt 0 ]; then
      samples=$((samples + 1))
      if [ "$SAMPLE_TREE_RSS_KB" -gt "$peak_tree_kb" ]; then
        peak_tree_kb="$SAMPLE_TREE_RSS_KB"
      fi
    fi
    kill -0 "$root_pid" 2>/dev/null || break
    sleep "$POLL_INTERVAL_S"
  done

  wait "$root_pid"
  local rc=$?
  end_ns=$(date +%s%N)
  local stage_ms=$(( (end_ns - start_ns) / 1000000 ))

  local peak_proc_kb=0 pid
  for pid in "${!PEAK_PROC_KB[@]}"; do
    if [ "${PEAK_PROC_KB[$pid]}" -gt "$peak_proc_kb" ]; then
      peak_proc_kb="${PEAK_PROC_KB[$pid]}"
    fi
  done

  local measured="false"
  if [ "$samples" -ge 2 ] && [ "$stage_ms" -ge 200 ]; then
    measured="true"
  fi

  local peak_tree_bytes=$((peak_tree_kb * 1024))
  local peak_proc_bytes=$((peak_proc_kb * 1024))

  local json
  json=$(emit_stage_json "$shape" "$stage" "$root_pid" "$peak_tree_bytes" "$peak_proc_bytes" \
    "$samples" "$stage_ms" "$measured" "$merged_from_csv" "$budget" "$rc" \
    "$binary_sha256" "$fixture_sha256")
  echo "$json" | tee "$out_json"

  echo "$json" | judge_from_stdin
}

# ---------------------------------------------------------------------
# --selfcheck: one stage, no fixture, no budget.
# ---------------------------------------------------------------------

run_selfcheck() {
  local out_json="${RUN_ROOT:-/tmp}/memory-selfcheck-$$.json"
  run_stage "selfcheck" "selfcheck" "" "" "" "" "$out_json" "$@"
}

# ---------------------------------------------------------------------
# Normal-mode helpers.
# ---------------------------------------------------------------------

manifest_field() {
  # $1=manifest.json path $2=field name
  python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"
}

# Fail-loud (exit 2, never a silent 0) lookup of budget bytes for
# [shape,stage] from $W6/memgate-baseline.json. Schema assumed (this file
# does not exist yet -- it's #122b-3's Step 6 deliverable):
#   {"<shape>": {"<stage>": {"binary_sha": "...", "peak_tree": <bytes>,
#     "peak_proc": <bytes>, "exit_code": 0, "measured": true,
#     "max_over_min": <float>}}}
# If #122b-3 lands a different shape, this function is the one place to
# update.
budget_bytes_for_stage() {
  local shape="$1" stage="$2" baseline_json="$3"
  if [ ! -f "$baseline_json" ]; then
    echo "memory_gate: P0 baseline file not found: $baseline_json (fail-loud, not defaulting to 0 budget)" >&2
    return 2
  fi
  python3 - "$baseline_json" "$shape" "$stage" <<'PYEOF'
import json
import sys

path, shape, stage = sys.argv[1:4]
try:
    with open(path) as f:
        data = json.load(f)
except Exception as e:
    print(f"memory_gate: cannot parse P0 baseline {path}: {e}", file=sys.stderr)
    sys.exit(2)
entry = (data.get(shape) or {}).get(stage)
if not entry:
    print(f"memory_gate: P0 baseline missing entry for shape={shape} stage={stage}", file=sys.stderr)
    sys.exit(2)
def is_int(v):
    # bool is an int subclass in Python; a JSON `true` is not a count.
    return isinstance(v, int) and not isinstance(v, bool)

# R6-B1: the P0 file is hand-filled (memgate-baseline.json is written by a
# human copying a collected run's numbers), so its entries get the same
# adversarial-reading validation `--judge` applies to a stage result:
# `entry.get("measured")` was a truth test, so a hand-typed string
# "false" passed as a valid run; `int(...)` coerced a string peak.
if entry.get("measured") is not True:
    print(f"memory_gate: P0 baseline entry for {shape}/{stage} is not a valid run (measured must be the JSON boolean true)", file=sys.stderr)
    sys.exit(2)
if not is_int(entry.get("exit_code")) or entry.get("exit_code") != 0:
    print(f"memory_gate: P0 baseline entry for {shape}/{stage} is not a valid run (exit_code must be the integer 0)", file=sys.stderr)
    sys.exit(2)
peak_tree = entry.get("peak_tree")
peak_proc = entry.get("peak_proc")
if not is_int(peak_tree) or peak_tree < 0 or not is_int(peak_proc) or peak_proc < 0:
    print(f"memory_gate: P0 baseline entry for {shape}/{stage} has a non-integer or negative peak (peak_tree={peak_tree!r}, peak_proc={peak_proc!r})", file=sys.stderr)
    sys.exit(2)
p0 = max(peak_tree, peak_proc)
budget = int(1.25 * p0 + 256 * 1024 * 1024)
print(budget)
PYEOF
}

assert_sources_toml_only_lists_fixture_root() {
  # $1=XDG_CONFIG_HOME $2=fixture_dir
  # T4-F7 (#122b-3): normal mode both exports HOME=$fixture_dir (Claude
  # Code connector auto-discovery) AND used to require an explicit
  # [[sources]] entry here -- both discovery paths scanned the same tree,
  # double-ingesting the fixture (#122b-2 exec112: conversations=2,
  # messages=20,000 against a 10,000-message manifest). This now asserts
  # the opposite: sources.toml must declare ZERO [[sources]] tables, so
  # normal mode relies solely on HOME=$fixture_dir auto-discovery.
  local xdg="$1" fixture_dir="$2"
  local toml="$xdg/cass/sources.toml"
  [ -f "$toml" ] || { echo "memory_gate: $toml not found before running the gate" >&2; return 2; }
  if grep -qE '^[[:space:]]*\[\[sources\]\]' "$toml"; then
    echo "memory_gate: $toml declares [[sources]] entries -- normal mode relies solely on HOME=$fixture_dir auto-discovery (T4-F7), remove them" >&2
    return 2
  fi
}

ingested_sessions_of() {
  sqlite3 "$1" "SELECT COUNT(*) FROM conversations;" 2>/dev/null || echo 0
}

binary_sha256_of() {
  sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

# ---------------------------------------------------------------------
# CLI dispatch.
# ---------------------------------------------------------------------

if [ "${1:-}" = "--selfcheck" ]; then
  shift
  [ "${1:-}" = "--" ] || usage
  shift
  [ $# -ge 1 ] || usage
  run_selfcheck "$@"
  exit $?
fi

if [ "${1:-}" = "--judge" ]; then
  judge_from_stdin
  exit $?
fi

COLLECT_BASELINE=0
STAGE4_DB=""
while [ $# -gt 0 ]; do
  case "$1" in
    --collect-baseline) COLLECT_BASELINE=1; shift ;;
    --stage4-db) STAGE4_DB="${2:?missing --stage4-db path}"; shift 2 ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done

[ $# -eq 2 ] || usage
shape="$1"
cass_wrapper="$2"
: "${RUN_ROOT:?RUN_ROOT must be set}"
: "${EXAMPLES:?EXAMPLES must be set}"
if [ "$COLLECT_BASELINE" -eq 0 ]; then
  : "${W6:?W6 must be set (holds memgate-baseline.json)}"
fi

if [ "$COLLECT_BASELINE" -eq 1 ]; then
  if pgrep -x cargo >/dev/null 2>&1; then
    echo "memory_gate: --collect-baseline requires no running cargo process" >&2
    exit 2
  fi
  if pgrep -x cass >/dev/null 2>&1; then
    echo "memory_gate: --collect-baseline requires no running cass process" >&2
    exit 2
  fi
fi

fixture_dir="$RUN_ROOT/mem-${shape}-fixture"
data_dir="$RUN_ROOT/mem-${shape}"
rm -rf "$data_dir"
mkdir -p "$data_dir"

if [ ! -d "$fixture_dir" ]; then
  "$EXAMPLES/w4_memory_fixture" --shape "$shape" --out "$fixture_dir" || exit 2
fi
manifest="$fixture_dir/manifest.json"
[ -f "$manifest" ] || { echo "memory_gate: $manifest missing (fixture must be frozen by w4_memory_fixture)" >&2; exit 2; }
fixture_sha256=$(manifest_field "$manifest" fixture_sha256) || exit 2

# #122b-3c: hash the binary the wrapper execs into, not the wrapper shim
# (a per-run-root constant, so baseline and candidate rounds shared it).
binary_path="${CASS_CAND_BIN:-$RUN_ROOT/cass-candidate}"
binary_sha256=$(binary_sha256_of "$binary_path")
[ -n "$binary_sha256" ] || { echo "memory_gate: cannot hash the binary under test: $binary_path" >&2; exit 2; }

baseline_json="${W6:-}/memgate-baseline.json"

budget_for() {
  local stage="$1"
  if [ "$COLLECT_BASELINE" -eq 1 ]; then
    echo ""
    return 0
  fi
  budget_bytes_for_stage "$shape" "$stage" "$baseline_json"
}

overall_rc=0

export CASS_DATA_DIR="$data_dir"
export HOME="$fixture_dir"

assert_sources_toml_only_lists_fixture_root "${XDG_CONFIG_HOME:-}" "$fixture_dir" || exit 2

budget1=$(budget_for index) || exit 2
run_stage "$shape" "index" "$budget1" "" "$binary_sha256" "$fixture_sha256" \
  "$RUN_ROOT/mem-${shape}-stage1.json" \
  "$cass_wrapper" index || overall_rc=1

# Stage 1 has now actually ingested the fixture -- patch ingested_sessions
# (the mission's "阶段 1 JSON" requirement) into the JSON just written,
# rather than trying to know it before the stage runs.
ingested=$(ingested_sessions_of "$data_dir/agent_search.db")
python3 - "$RUN_ROOT/mem-${shape}-stage1.json" "$ingested" <<'PYEOF'
import json
import sys

path, ingested = sys.argv[1], int(sys.argv[2])
with open(path) as f:
    obj = json.load(f)
obj["ingested_sessions"] = ingested
with open(path, "w") as f:
    json.dump(obj, f)
    f.write("\n")
print(json.dumps(obj))
PYEOF

# T4-F7 (#122b-3): the fixture generator (examples/w4_memory_fixture.rs R2)
# writes exactly one session file per shape -- HOME-based auto-discovery
# must therefore see exactly one session regardless of shape. This is a
# structural fact of the fixture layout, not a manifest/config value.
expected_sessions=1
if [ "$ingested" != "$expected_sessions" ]; then
  echo "memory_gate: stage 1 ingested_sessions=$ingested, expected=$expected_sessions (T4-F7)" >&2
  overall_rc=1
fi

budget2=$(budget_for index_force_rebuild) || exit 2
run_stage "$shape" "index_force_rebuild" "$budget2" "" "$binary_sha256" "$fixture_sha256" \
  "$RUN_ROOT/mem-${shape}-stage2.json" \
  "$cass_wrapper" index --force-rebuild || overall_rc=1

budget3=$(budget_for index_semantic) || exit 2
run_stage "$shape" "index_semantic" "$budget3" "" "$binary_sha256" "$fixture_sha256" \
  "$RUN_ROOT/mem-${shape}-stage3.json" \
  "$cass_wrapper" index --semantic || overall_rc=1

stage4_db="${STAGE4_DB:-$data_dir-stage4/agent_search.db}"
budget4=$(budget_for completeness_gate) || exit 2
run_stage "$shape" "completeness_gate" "$budget4" "" "$binary_sha256" "$fixture_sha256" \
  "$RUN_ROOT/mem-${shape}-stage4.json" \
  "$EXAMPLES/w4_completeness_gate" --db "$stage4_db" --json "$RUN_ROOT/mem-${shape}-completeness.json" || overall_rc=1

exit "$overall_rc"
