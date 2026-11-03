#!/usr/bin/env bash
# Switch the user service cass-mcp.service to a rendered unit, with automatic rollback.
#
#   cass-mcp-switch.sh <rendered unit file> <expected data-dir> <bind address>
#
# Steps: validate; refuse when the user manager loads cass-mcp.service from outside
# the unit directory; move the current base unit and its whole drop-in directory
# into <unit dir>/cass-mcp.backup-<UTC timestamp>/; install the new unit (0644);
# daemon-reload and restart; self-check for at most 30 seconds in total (the
# manager loads exactly the new unit with no drop-ins, the running process's argv
# equals the new ExecStart, MCP initialize = 200, tools/list contains
# cass_search); then enable the unit. On any failure after the first change the
# new unit is removed, the backup is moved back, the service is reloaded and
# restarted (a fresh install is stopped instead, unless it was already active),
# and the script exits 1.
# Exit codes: 0 success (stdout: backup directory), 1 self-check failed and rolled
# back, 2 invalid arguments (nothing changed), 3 rollback itself failed.
#
# Test hooks (defaults are the real paths): CASS_MCP_SWITCH_PROC_ROOT,
# CASS_MCP_SWITCH_CURL, CASS_MCP_SWITCH_WAIT_SECONDS.
set -uo pipefail

UNIT_NAME=cass-mcp.service
PROC_ROOT=${CASS_MCP_SWITCH_PROC_ROOT:-/proc}
CURL=${CASS_MCP_SWITCH_CURL:-curl}
WAIT_SECONDS=${CASS_MCP_SWITCH_WAIT_SECONDS:-30}

die() { printf 'cass-mcp-switch: %s\n' "$*" >&2; exit 2; }
say() { printf 'cass-mcp-switch: %s\n' "$*" >&2; }

[ $# -eq 3 ] || die "usage: cass-mcp-switch.sh <rendered unit file> <expected data-dir> <bind address>"
SRC=$1 DATA_DIR=$2 BIND=$3
[ -f "$SRC" ] && [ -r "$SRC" ] || die "unit file is not a readable regular file: $SRC"
[ -n "$DATA_DIR" ] || die "expected data-dir is empty"
case "$WAIT_SECONDS" in ''|*[!0-9]*) die "invalid CASS_MCP_SWITCH_WAIT_SECONDS: $WAIT_SECONDS" ;; esac
case "$BIND" in
  127.*:[0-9]*|'[::1]':[0-9]*|localhost:[0-9]*) ;;
  *) die "bind address must be loopback host:port: $BIND" ;;
esac
if grep -q '@@' "$SRC"; then die "unit file still contains unrendered placeholders: $SRC"; fi

# The effective ExecStart is the last non-empty one; read its arguments.
EXEC=$(sed -n 's/^ExecStart=//p' "$SRC" | grep -v '^[[:space:]]*$' | tail -n 1)
[ -n "$EXEC" ] || die "unit file has no ExecStart: $SRC"
arg_value() { # $1=flag, remaining=argv; prints the value of --flag v or --flag=v
  local flag=$1 prev=''; shift
  for a in "$@"; do
    if [ "$prev" = "$flag" ]; then printf '%s' "$a"; return 0; fi
    case "$a" in "$flag="*) printf '%s' "${a#*=}"; return 0 ;; esac
    prev=$a
  done
  return 1
}
read -r -a EXEC_ARGV <<< "$EXEC"
UNIT_DATA_DIR=$(arg_value --data-dir "${EXEC_ARGV[@]}") || die "unit ExecStart has no --data-dir"
[ "$UNIT_DATA_DIR" = "$DATA_DIR" ] || die "unit --data-dir '$UNIT_DATA_DIR' differs from expected '$DATA_DIR'"
UNIT_BIND=$(arg_value --bind "${EXEC_ARGV[@]}") || die "unit ExecStart has no --bind"
[ "$UNIT_BIND" = "$BIND" ] || die "unit --bind '$UNIT_BIND' differs from bind argument '$BIND'"

UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
TARGET="$UNIT_DIR/$UNIT_NAME"
DROPIN="$UNIT_DIR/$UNIT_NAME.d"
SRC_REAL=$(realpath -- "$SRC") || die "cannot resolve unit file: $SRC"
[ "$SRC_REAL" != "$(realpath -m -- "$TARGET")" ] || die "unit file must not be the installed unit itself: $SRC"
case "$SRC_REAL" in "$(realpath -m -- "$DROPIN")"/*) die "unit file must not live in the drop-in directory: $SRC" ;; esac

# Preflight: the manager must load cass-mcp.service from this unit directory (or
# not at all); otherwise the new unit would be shadowed or would shadow another.
FRAG_LINE=$(systemctl --user show -p FragmentPath "$UNIT_NAME") \
  || die "cannot query the systemd user manager for $UNIT_NAME"
LOADED=$(printf '%s\n' "$FRAG_LINE" | sed -n 's/^FragmentPath=//p')
if [ -n "$LOADED" ]; then
  case "$(realpath -m -- "$LOADED")" in
    "$(realpath -m -- "$UNIT_DIR")"/*) ;;
    *) die "systemd loads $UNIT_NAME from FragmentPath=$LOADED, outside $UNIT_DIR; refusing" ;;
  esac
fi
WAS_ACTIVE=$(systemctl --user is-active "$UNIT_NAME" 2>/dev/null || true)
WANTS_DIR="$UNIT_DIR/default.target.wants"
WANTS_LINK="$WANTS_DIR/$UNIT_NAME"

mkdir -p -- "$UNIT_DIR" || die "cannot create unit directory: $UNIT_DIR"
BACKUP="$UNIT_DIR/cass-mcp.backup-$(date -u +%Y%m%dT%H%M%S%NZ)"
mkdir -- "$BACKUP" || die "cannot create backup directory: $BACKUP"

# From here on the unit directory is changed; any failure rolls back.
MOVED=()
INSTALLED=0
ENABLE_TRIED=0 HAD_WANTS_DIR=0 HAD_WANTS_LINK=0
rollback() { # $1=reason; restores the original layout, reloads and restarts
  trap - INT TERM HUP
  say "self-check failed: $1"
  say "rolling back from $BACKUP"
  local ok=1 name
  if [ ${#MOVED[@]} -eq 0 ] && [ "$WAS_ACTIVE" != active ]; then
    # Nothing existed before and nothing ran: stop what this script started.
    systemctl --user stop "$UNIT_NAME" || ok=0
  fi
  if [ "$ENABLE_TRIED" = 1 ]; then
    # Undo only the wants link and directory that enable created.
    if [ "$HAD_WANTS_LINK" = 0 ]; then rm -f -- "$WANTS_LINK" || ok=0; fi
    if [ "$HAD_WANTS_DIR" = 0 ] && [ -d "$WANTS_DIR" ]; then rmdir -- "$WANTS_DIR" 2>/dev/null || true; fi
  fi
  if [ "$INSTALLED" = 1 ] || [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
    # A unit at TARGET can only be ours here: the original was moved away first.
    rm -f -- "$TARGET" || ok=0
  fi
  for name in "${MOVED[@]}"; do
    mv -T -- "$BACKUP/$name" "$UNIT_DIR/$name" || { ok=0; say "cannot restore $name"; }
  done
  if [ "$ok" = 1 ]; then rmdir -- "$BACKUP" || ok=0; fi
  systemctl --user daemon-reload || ok=0
  if [ ${#MOVED[@]} -gt 0 ]; then systemctl --user restart "$UNIT_NAME" || ok=0; fi
  if [ "$ok" = 1 ]; then say "rollback complete; original units restored"; exit 1; fi
  say "ROLLBACK INCOMPLETE; inspect $UNIT_DIR and $BACKUP manually"
  exit 3
}
trap 'rollback "interrupted"' INT TERM HUP

for name in "$UNIT_NAME" "$UNIT_NAME.d"; do
  if [ -e "$UNIT_DIR/$name" ] || [ -L "$UNIT_DIR/$name" ]; then
    mv -T -- "$UNIT_DIR/$name" "$BACKUP/$name" || rollback "cannot move $name into backup"
    MOVED+=("$name")
  fi
done

install -m 0644 -T -- "$SRC" "$TARGET" || rollback "cannot install $TARGET"
INSTALLED=1
systemctl --user daemon-reload || rollback "systemctl --user daemon-reload failed"
systemctl --user restart "$UNIT_NAME" || rollback "systemctl --user restart $UNIT_NAME failed"

# ---- self-check ------------------------------------------------------------
WORK=$(mktemp -d "${TMPDIR:-/tmp}/cass-mcp-switch.XXXXXX") || rollback "cannot create work directory"
cleanup_work() { rm -rf -- "$WORK"; }
trap cleanup_work EXIT
trap 'rollback "interrupted"' INT TERM HUP
URL="http://$BIND/mcp"
DEADLINE=$((SECONDS + WAIT_SECONDS))
REASON='no attempt made'
SESSION=''
HTTP_CODE=''

mcp_post() { # $1=name $2=json body; sets HTTP_CODE, writes $WORK/$1.{body,headers}
  local remaining=$((DEADLINE - SECONDS)) hdr=()
  if [ "$remaining" -le 0 ]; then HTTP_CODE="deadline-exceeded"; return 0; fi
  [ -z "$SESSION" ] || hdr=(-H "Mcp-Session-Id: $SESSION")
  # Loopback only: a proxy from the environment must never carry the probe.
  HTTP_CODE=$("$CURL" -sS --noproxy '*' --max-time "$remaining" -o "$WORK/$1.body" -D "$WORK/$1.headers" \
    -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' "${hdr[@]}" --data "$2" "$URL" 2>"$WORK/$1.err") \
    || HTTP_CODE="curl-error($(head -c 200 "$WORK/$1.err" | tr '\n' ' '))"
}

check_once() {
  local pid data
  HTTP_CODE=''
  # The manager must load exactly the new unit, with no drop-in left over.
  local props frag drop
  props=$(systemctl --user show -p FragmentPath -p DropInPaths "$UNIT_NAME") || { REASON='cannot read FragmentPath/DropInPaths'; return 1; }
  frag=$(printf '%s\n' "$props" | sed -n 's/^FragmentPath=//p')
  drop=$(printf '%s\n' "$props" | sed -n 's/^DropInPaths=//p')
  [ -n "$frag" ] && [ "$(realpath -m -- "$frag")" = "$(realpath -m -- "$TARGET")" ] \
    || { REASON="systemd loads FragmentPath='$frag', expected '$TARGET'"; return 1; }
  [ -z "$drop" ] || { REASON="systemd still applies DropInPaths='$drop'"; return 1; }
  pid=$(systemctl --user show -p MainPID --value "$UNIT_NAME" 2>/dev/null) || { REASON='cannot read MainPID'; return 1; }
  case "$pid" in ''|0|*[!0-9]*) REASON="service has no main process (MainPID='$pid')"; return 1 ;; esac
  [ -r "$PROC_ROOT/$pid/cmdline" ] || { REASON="cannot read $PROC_ROOT/$pid/cmdline"; return 1; }
  local argv=()
  mapfile -d '' -t argv < "$PROC_ROOT/$pid/cmdline"
  data=$(arg_value --data-dir "${argv[@]}") || { REASON="running process $pid has no --data-dir"; return 1; }
  [ "$data" = "$DATA_DIR" ] || { REASON="running process $pid has --data-dir '$data', expected '$DATA_DIR'"; return 1; }
  # The whole argv must equal the new ExecStart, so an old process cannot pass.
  [ ${#argv[@]} -eq ${#EXEC_ARGV[@]} ] || {
    REASON="running process $pid argv has ${#argv[@]} items, the new ExecStart has ${#EXEC_ARGV[@]}"; return 1; }
  local i
  for i in "${!EXEC_ARGV[@]}"; do
    [ "${argv[$i]}" = "${EXEC_ARGV[$i]}" ] || { REASON="running process $pid argv[$i] is '${argv[$i]}', expected '${EXEC_ARGV[$i]}'"; return 1; }
  done

  SESSION=''
  mcp_post initialize '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cass-mcp-switch","version":"1"}}}'
  [ "$HTTP_CODE" = 200 ] || { REASON="MCP initialize at $URL returned $HTTP_CODE, expected 200"; return 1; }
  SESSION=$(tr -d '\r' < "$WORK/initialize.headers" | sed -n 's/^[Mm][Cc][Pp]-[Ss][Ee][Ss][Ss][Ii][Oo][Nn]-[Ii][Dd]:[[:space:]]*//p' | tail -n 1)
  mcp_post initialized '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  case "$HTTP_CODE" in 2??) ;; *) REASON="MCP notifications/initialized returned $HTTP_CODE"; return 1 ;; esac
  mcp_post tools '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
  [ "$HTTP_CODE" = 200 ] || { REASON="MCP tools/list returned $HTTP_CODE, expected 200"; return 1; }
  grep -Eq '"name"[[:space:]]*:[[:space:]]*"cass_search"' "$WORK/tools.body" \
    || { REASON='MCP tools/list does not contain cass_search'; return 1; }
  [ "$SECONDS" -le "$DEADLINE" ] || { REASON='self-check finished after the deadline'; return 1; }
  return 0
}

LAST_REASON=''
until check_once; do
  # An attempt cut short by the deadline keeps the previous, more specific reason.
  case "$HTTP_CODE" in deadline-exceeded) ;; *) LAST_REASON=$REASON ;; esac
  if [ "$SECONDS" -ge "$DEADLINE" ]; then
    cleanup_work
    rollback "${LAST_REASON:-$REASON} (gave up after ${WAIT_SECONDS}s)"
  fi
  sleep 1
done

[ ! -d "$WANTS_DIR" ] || HAD_WANTS_DIR=1
[ ! -e "$WANTS_LINK" ] && [ ! -L "$WANTS_LINK" ] || HAD_WANTS_LINK=1
ENABLE_TRIED=1
systemctl --user enable "$UNIT_NAME" || rollback "systemctl --user enable $UNIT_NAME failed"

trap - INT TERM HUP
printf '%s\n' "$BACKUP"
exit 0
