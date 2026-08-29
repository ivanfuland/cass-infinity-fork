#!/usr/bin/env bash
# Task C7 (plan 2026-08-25-w1-relational-sqlite-swap.md @1259-1271): drives
# sustained concurrent read+write load against an isolated drill copy of the
# staging DB and classifies the result into the four judgment criteria
# (panic / unmapped error / search timeout>30s / lock-contention buckets).
#
# Concurrently for DURATION_SECS:
#   1. one `cass index --watch` process (incremental, real write path)
#   2. N_SEARCHERS parallel `cass search --mode lexical` loops
#   3. a wal_checkpoint(PASSIVE) observation every CHECKPOINT_INTERVAL_SECS
#
# R4-N3: never point this at a live/authenticated DB. It refuses to run
# unless CASS_DRILL_DATA_DIR's path contains "drill" (or --force is passed).
set -uo pipefail

BIN="${CASS_DRILL_BIN:?set CASS_DRILL_BIN to the candidate cass binary}"
DATA_DIR="${CASS_DRILL_DATA_DIR:?set CASS_DRILL_DATA_DIR to an isolated drill-copy data dir}"
OUT_DIR="${CASS_DRILL_OUT_DIR:-/tmp/cc-cass-w1-concurrency-drill}"
DURATION_SECS="${CASS_DRILL_DURATION_SECS:-1800}"
N_SEARCHERS="${CASS_DRILL_N_SEARCHERS:-8}"
CHECKPOINT_INTERVAL_SECS="${CASS_DRILL_CHECKPOINT_INTERVAL_SECS:-300}"
SEARCH_TIMEOUT_MS="${CASS_DRILL_SEARCH_TIMEOUT_MS:-30000}"
HARD_TIMEOUT_SECS="${CASS_DRILL_HARD_TIMEOUT_SECS:-35}"

if [[ "$DATA_DIR" != *drill* && "${1:-}" != "--force" ]]; then
  echo "refusing: CASS_DRILL_DATA_DIR ('$DATA_DIR') does not look like a drill copy" >&2
  echo "(pass --force to override; R4-N3: this drill must never touch a live/authenticated DB)" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
: > "$OUT_DIR/searcher-results.tsv"
echo -e "searcher_id\titer\tts\tquery\texit_code\telapsed_ms" >> "$OUT_DIR/searcher-results.tsv"
: > "$OUT_DIR/searcher-stderr-all.log"
: > "$OUT_DIR/checkpoint-observations.tsv"
echo -e "ts\twal_bytes\tbusy_ms_since_start\tckpt_pragma_raw" >> "$OUT_DIR/checkpoint-observations.tsv"

QUERIES=(python docker error test config search index database timeout retry
         lock checkpoint session claude codex agent workspace conversation sql)

start_ts=$(date +%s)
end_ts=$(( start_ts + DURATION_SECS ))
echo "drill start: $(date -Is), duration=${DURATION_SECS}s, searchers=${N_SEARCHERS}, data_dir=${DATA_DIR}" \
  | tee "$OUT_DIR/drill-meta.log"

# --- 1. writer: real incremental index, watch mode, for the whole window ---
"$BIN" index --watch --data-dir "$DATA_DIR" --watch-interval 15 --json \
  >"$OUT_DIR/writer.stdout.ndjson" 2>"$OUT_DIR/writer.stderr.log" &
WRITER_PID=$!
echo "writer pid: $WRITER_PID" >> "$OUT_DIR/drill-meta.log"

sleep 2  # let the writer attach/lock before search load starts

# --- 2. N_SEARCHERS concurrent search loops ---
searcher() {
  local id="$1"
  local n=0
  while [ "$(date +%s)" -lt "$end_ts" ]; do
    local q="${QUERIES[$((RANDOM % ${#QUERIES[@]}))]}"
    local err_file="$OUT_DIR/.searcher${id}-${n}.stderr"
    local t0 t1 rc elapsed_ms
    t0=$(date +%s.%N)
    timeout "$HARD_TIMEOUT_SECS" "$BIN" search "$q" --mode lexical --limit 5 \
      --timeout "$SEARCH_TIMEOUT_MS" --data-dir "$DATA_DIR" --json \
      >/dev/null 2>"$err_file"
    rc=$?
    t1=$(date +%s.%N)
    elapsed_ms=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.0f", (b-a)*1000}')
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$n" "$(date -Is)" "$q" "$rc" "$elapsed_ms" \
      >> "$OUT_DIR/searcher-results.tsv"
    if [ -s "$err_file" ]; then
      { echo "=== searcher $id iter $n rc=$rc ==="; cat "$err_file"; } >> "$OUT_DIR/searcher-stderr-all.log"
    fi
    rm -f "$err_file"
    n=$((n + 1))
  done
}

for i in $(seq 1 "$N_SEARCHERS"); do
  searcher "$i" &
done
SEARCHER_PIDS=$(jobs -p | grep -v "^${WRITER_PID}\$")

# --- 3. periodic wal_checkpoint(PASSIVE) observation ---
(
  while [ "$(date +%s)" -lt "$end_ts" ]; do
    sleep "$CHECKPOINT_INTERVAL_SECS"
    [ "$(date +%s)" -ge "$end_ts" ] && break
    ts=$(date -Is)
    wal_bytes=$(stat -c%s "${DATA_DIR}/agent_search.db-wal" 2>/dev/null || echo 0)
    since_start_ms=$(( ($(date +%s) - start_ts) * 1000 ))
    ckpt_raw=$(sqlite3 "${DATA_DIR}/agent_search.db" \
      "PRAGMA busy_timeout=5000; PRAGMA wal_checkpoint(PASSIVE);" 2>&1 | tr '\n' ' ')
    printf '%s\t%s\t%s\t%s\n' "$ts" "$wal_bytes" "$since_start_ms" "$ckpt_raw" \
      >> "$OUT_DIR/checkpoint-observations.tsv"
  done
) &
CKPT_PID=$!

# Wait only for the searcher loops (they self-terminate at end_ts).
wait $SEARCHER_PIDS 2>/dev/null
wait "$CKPT_PID" 2>/dev/null

# Writer runs forever in --watch mode; stop it now that the window is over.
kill "$WRITER_PID" 2>/dev/null
wait "$WRITER_PID" 2>/dev/null

echo "drill end: $(date -Is)" >> "$OUT_DIR/drill-meta.log"

# --- classify into the four judgment criteria ---
# Contention three-category split, per cass's own documented `capabilities`
# exit-code table (0=success; 5/7/8=documented, self-describing, retryable
# degraded/busy/partial responses -- not bugs; anything else non-zero and
# not a hard hang is "unmapped" -- an exit code the CLI's own contract
# doesn't account for).
panic_count=$(grep -h "panicked at" "$OUT_DIR/writer.stderr.log" "$OUT_DIR/searcher-stderr-all.log" 2>/dev/null | wc -l)
hard_hang_count=$(awk -F'\t' 'NR>1 && $5==124' "$OUT_DIR/searcher-results.tsv" | wc -l)
soft_timeout_count=$(awk -F'\t' 'NR>1 && $5!=124 && $6>30000' "$OUT_DIR/searcher-results.tsv" | wc -l)
timeout_count=$((hard_hang_count + soft_timeout_count))
documented_contention_count=$(awk -F'\t' 'NR>1 && ($5==5 || $5==7 || $5==8)' "$OUT_DIR/searcher-results.tsv" | wc -l)
unmapped_count=$(awk -F'\t' 'NR>1 && $5!=0 && $5!=5 && $5!=7 && $5!=8 && $5!=124' "$OUT_DIR/searcher-results.tsv" | wc -l)
total_searches=$(( $(wc -l < "$OUT_DIR/searcher-results.tsv") - 1 ))
ok_count=$(awk -F'\t' 'NR>1 && $5==0' "$OUT_DIR/searcher-results.tsv" | wc -l)

{
  echo "panic_count=${panic_count}"
  echo "unmapped_error_count=${unmapped_count}"
  echo "timeout_count_gt_30s=${timeout_count} (hard_hang_exit124=${hard_hang_count}, soft_over_30000ms=${soft_timeout_count})"
  echo "total_searches=${total_searches}"
  echo "ok_count=${ok_count}"
  echo "documented_contention_count(exit5|7|8)=${documented_contention_count}"
  if [ "$total_searches" -gt 0 ]; then
    awk -v b="$documented_contention_count" -v t="$total_searches" 'BEGIN{printf "busy_timeout_ratio=%.4f\n", b/t}'
  else
    echo "busy_timeout_ratio=n/a"
  fi
} | tee "$OUT_DIR/classification-summary.txt"
