#!/usr/bin/env bash
# cass ingest entry template (one sync round per call).
#
# The installer renders the six placeholder values below by plain text
# replacement. The rendered script runs one fixed command:
#   <CASS_BIN> sync --json --no-mirror --data-dir <DATA_DIR> --api-config <API_CONFIG>
# It ignores all caller arguments and SSH_ORIGINAL_COMMAND.
#
# Each placeholder value is placed inside single quotes. A value must not
# contain a single quote, a newline or two consecutive at signs. The renderer
# must refuse such values (a later task implements the renderer).
#
# stdout: exactly one JSON line, schema cass.ingest-entry.v1. Diagnostics and
# the stderr of cass go to stderr.
# Exit code: 0 for ok, skipped and warning; 1 for failed and unknown_exit.
set -u

CASS_BIN='@@CASS_BIN@@'
DATA_DIR='@@DATA_DIR@@'
API_CONFIG='@@API_CONFIG@@'
ENV_FILE='@@ENV_FILE@@'
CONFIG_HOME='@@CONFIG_HOME@@'
INSTANCE='@@INSTANCE@@'
readonly CASS_BIN DATA_DIR API_CONFIG ENV_FILE CONFIG_HOME INSTANCE

unset SSH_ORIGINAL_COMMAND

utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Prints the result line and exits with the entry exit code.
# Arguments: sync exit code ("" when cass did not start), sync stdout file
# ("" when there is none), started_at, finished_at.
report() {
  python3 -I -c '
import json, sys
instance, rc_text, out_path, started, finished = sys.argv[1:6]
rc = int(rc_text) if rc_text != "" else None
obj = None
if out_path:
    try:
        with open(out_path, "rb") as handle:
            obj = json.loads(handle.read().decode("utf-8").strip())
    except (OSError, ValueError):
        obj = None
error_kind = run_id = None
if isinstance(obj, dict):
    error = obj.get("error")
    if isinstance(error, dict) and isinstance(error.get("kind"), str):
        error_kind = error["kind"]
    if isinstance(obj.get("run_id"), str):
        run_id = obj["run_id"]
if rc is None or not isinstance(obj, dict):
    classification = "failed"
elif rc == 0:
    classification = "ok"
elif rc == 2:
    classification = "skipped" if error_kind == "index-busy" else "warning"
elif rc == 3:
    classification = "warning"
elif rc == 1:
    classification = "failed"
else:
    classification = "unknown_exit"
line = json.dumps({
    "schema": "cass.ingest-entry.v1",
    "instance": instance,
    "classification": classification,
    "sync_exit_code": rc,
    "error_kind": error_kind,
    "sync_run_id": run_id,
    "started_at": started,
    "finished_at": finished,
}, separators=(",", ":"))
sys.stdout.write(line + "\n")
sys.exit(0 if classification in ("ok", "skipped", "warning") else 1)
' "$INSTANCE" "$1" "$2" "$3" "$4"
  local status=$?
  if [ "$status" -gt 1 ]; then
    echo "cass-ingest-entry: python3 could not build the result line (status $status)" >&2
    status=1
  fi
  exit "$status"
}

started_at=$(utc_now)

# A placeholder that was not rendered still has the @@...@@ form.
for value in "$CASS_BIN" "$DATA_DIR" "$API_CONFIG" "$ENV_FILE" "$CONFIG_HOME" "$INSTANCE"; do
  case $value in
    @@*@@)
      echo "cass-ingest-entry: template placeholder not rendered: $value" >&2
      report "" "" "$started_at" "$(utc_now)" ;;
  esac
done

# A missing env file is a deployment error: do not start cass.
if [ ! -e "$ENV_FILE" ]; then
  echo "cass-ingest-entry: env file does not exist: $ENV_FILE" >&2
  report "" "" "$started_at" "$(utc_now)"
elif [ ! -f "$ENV_FILE" ]; then
  echo "cass-ingest-entry: env file is not a regular file: $ENV_FILE" >&2
  report "" "" "$started_at" "$(utc_now)"
elif [ ! -r "$ENV_FILE" ]; then
  echo "cass-ingest-entry: env file is not readable: $ENV_FILE" >&2
  report "" "" "$started_at" "$(utc_now)"
fi

# Load KEY=VALUE lines without evaluating them. Values are never printed.
# Keys that control this entry or its child process are reserved: the env
# file cannot change them.
line_no=0
while IFS= read -r line || [ -n "$line" ]; do
  line_no=$((line_no + 1))
  if [[ $line =~ ^[[:space:]]*$ || $line =~ ^[[:space:]]*# ]]; then
    continue
  fi
  if [[ $line =~ ^[A-Z_][A-Z0-9_]*= ]]; then
    key=${line%%=*}
    case $key in
      CASS_BIN|DATA_DIR|API_CONFIG|ENV_FILE|CONFIG_HOME|INSTANCE|PATH|TMPDIR|HOME|XDG_CONFIG_HOME)
        echo "cass-ingest-entry: reserved key ignored: $key" >&2 ;;
      *) export "$key=${line#*=}" ;;
    esac
  else
    echo "cass-ingest-entry: ignored invalid line $line_no in env file" >&2
  fi
done < "$ENV_FILE"
unset line line_no key

export XDG_CONFIG_HOME="$CONFIG_HOME"

if [ -d "$CASS_BIN" ] || [ ! -x "$CASS_BIN" ]; then
  echo "cass-ingest-entry: cass binary is not executable: $CASS_BIN" >&2
  report "" "" "$started_at" "$(utc_now)"
fi

out_file=$(mktemp "${TMPDIR:-/tmp}/cass-ingest-entry.XXXXXX") || {
  echo "cass-ingest-entry: cannot create a temporary file" >&2
  report "" "" "$started_at" "$(utc_now)"
}
trap 'rm -f -- "$out_file"' EXIT

"$CASS_BIN" sync --json --no-mirror --data-dir "$DATA_DIR" --api-config "$API_CONFIG" > "$out_file"
sync_rc=$?
report "$sync_rc" "$out_file" "$started_at" "$(utc_now)"
