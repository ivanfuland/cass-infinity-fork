#!/usr/bin/env bash
# Control-flow tests for scripts/release-templates/cass-mcp-switch.sh and the
# cass-mcp.service.in template: bash scripts/tests/test-cass-mcp-switch.sh
#
# MOCK BOUNDARY: systemctl is a PATH shim that logs every call and emulates the
# user manager's answers (MainPID, FragmentPath, DropInPaths, is-active) from the
# fake HOME; curl is injected through CASS_MCP_SWITCH_CURL; /proc is a fake tree
# injected through CASS_MCP_SWITCH_PROC_ROOT. Every case owns a temporary HOME,
# so the real ~/.config/systemd, the real user manager and the running
# cass-mcp.service are never touched. A plain `curl` on PATH is a trap.
# The default sandbox is removed when every case passes; TEST_SANDBOX is kept.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
TEMPLATES="$HERE/../release-templates"
SWITCH=${SWITCH_SCRIPT:-$TEMPLATES/cass-mcp-switch.sh}
TEMPLATE=${UNIT_TEMPLATE:-$TEMPLATES/cass-mcp.service.in}
SANDBOX=${TEST_SANDBOX:-$(mktemp -d "${TMPDIR:-/tmp}/cc-cass-mcp-switch-test.XXXXXX")}
mkdir -p "$SANDBOX"
PASS=0; FAIL=0
SECRET='sk-test-0123456789-not-a-real-key'
DATA_DIR=/srv/cass/new-library
BIND=127.0.0.1:8777
printf 'sandbox=%s switch=%s template=%s\n' "$SANDBOX" "$SWITCH" "$TEMPLATE"

# Render the template the way the installer will: plain placeholder substitution.
render() { # $1=output $2=env file
  [ -f "$TEMPLATE" ] || { echo "missing template: $TEMPLATE" >&2; return 1; }
  sed -e "s#@@CASS_MCP_BIN@@#/opt/cass/v2/cass-mcp#g" \
      -e "s#@@CASS_BIN@@#/opt/cass/v2/cass#g" \
      -e "s#@@DATA_DIR@@#$DATA_DIR#g" \
      -e "s#@@API_CONFIG@@#/opt/cass/config/api.toml#g" \
      -e "s#@@ENV_FILE@@#$2#g" \
      -e "s#@@BIND@@#$BIND#g" \
      -e "s#@@PUBLIC_ORIGIN@@#https://cass.example.ts.net#g" \
      -e "s#@@EMBED_PROFILE@@#local-embed#g" \
      -e "s#@@RERANK_PROFILE@@#local-rank#g" "$TEMPLATE" > "$1"
}

# Byte-level fingerprint of a tree: names, types, link targets, modes and hashes.
tree_print() { (cd "$1" && find . -printf '%P %y %m %l\n' | sort && find . -type f -exec sha256sum {} + | sort -k2); }

setup_case() { # creates fakes for one case in $dir
  mkdir -p "$dir/home" "$dir/bin" "$dir/proc/4242"
  cat > "$dir/bin/systemctl" <<'SH'
#!/usr/bin/env bash
# Emulates the user manager. Its search path is the fake HOME's own
# ~/.config/systemd/user then ~/.local/share/systemd/user: like the real manager
# it ignores the caller's XDG_CONFIG_HOME. Behaviour switches are marker files.
dir=${0%/bin/*}
printf '%s\n' "$*" >> "$dir/systemctl.log"
[ "$1" = --user ] || exit 97
shift
bump() { local n; n=$(cat "$dir/$1-count" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$dir/$1-count"; echo "$n"; }
fragment() {
  if [ -e "$dir/frag-hidden-preflight" ] && [ ! -e "$dir/reloaded" ]; then return 0; fi
  local d
  for d in "$dir/home/.config/systemd/user" "$dir/home/.local/share/systemd/user"; do
    if [ -e "$d/cass-mcp.service" ]; then printf '%s' "$d/cass-mcp.service"; return 0; fi
  done
}
dropins() {
  local f frag out=(); frag=$(fragment)
  if [ -n "$frag" ]; then for f in "$frag.d"/*.conf; do [ ! -e "$f" ] || out+=("$f"); done; fi
  [ ! -e "$dir/extra-dropin" ] || out+=(/etc/systemd/user/cass-mcp.service.d/extra.conf)
  printf '%s' "${out[*]}"
}
case "$1" in
  show)
    shift; value=0; props=()
    while [ $# -gt 1 ]; do
      case "$1" in -p) props+=("$2"); shift ;; --value) value=1 ;; *) exit 98 ;; esac; shift
    done
    [ "$1" = cass-mcp.service ] || exit 98
    for p in "${props[@]}"; do
      case "$p" in
        MainPID)
          n=$(bump mainpid); [ "$n" -ne 1 ] || touch "$dir/first-mainpid"
          # The first answer is 0, as while systemd is still starting the new process.
          if [ "$n" -le 1 ] || [ -e "$dir/never-starts" ]; then v=0; else v=4242; fi ;;
        FragmentPath) v=$(fragment) ;;
        DropInPaths) v=$(dropins) ;;
        *) exit 98 ;;
      esac
      if [ "$value" = 1 ]; then printf '%s\n' "$v"; else printf '%s=%s\n' "$p" "$v"; fi
    done ;;
  is-active) a=$(cat "$dir/active" 2>/dev/null || echo inactive); echo "$a"; [ "$a" = active ] ;;
  daemon-reload) touch "$dir/reloaded" ;;
  restart)
    [ "$2" = cass-mcp.service ] || exit 98
    n=$(bump restart); if [ -e "$dir/restart-fails" ] && [ "$n" -eq 1 ]; then exit 1; fi ;;
  enable)
    [ "$2" = cass-mcp.service ] || exit 98
    if [ -e "$dir/enable-fails" ]; then
      # A partial enable: the wants link is written, then the call fails.
      mkdir -p "$dir/home/.config/systemd/user/default.target.wants"
      ln -s "$(fragment)" "$dir/home/.config/systemd/user/default.target.wants/cass-mcp.service"
      exit 1
    fi ;;
  stop) [ "$2" = cass-mcp.service ] || exit 98 ;;
  *) exit 99 ;;
esac
SH
  cat > "$dir/bin/curl" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${0%/bin/*}/unexpected-curl"
exit 89
SH
  cat > "$dir/fake-curl" <<'SH'
#!/usr/bin/env bash
dir=${0%/*}
out=/dev/null; hdr=/dev/null; fmt=''; data=''; url=''; session=''; accept=''; ctype=''; noproxy=''; maxtime=''
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift ;;
    -D) hdr=$2; shift ;;
    -w) fmt=$2; shift ;;
    -d|--data|--data-raw|--data-binary) data=$2; shift ;;
    --noproxy) noproxy=$2; shift ;;
    --max-time|-m) maxtime=$2; shift ;;
    -X|--connect-timeout) shift ;;
    -H) case "$2" in
          [Mm]cp-[Ss]ession-[Ii]d:*) session=${2#*: } ;;
          [Aa]ccept:*) accept=${2#*: } ;;
          [Cc]ontent-[Tt]ype:*) ctype=${2#*: } ;;
        esac; shift ;;
    -*) ;;
    *) url=$1 ;;
  esac
  shift
done
printf 'url=%s session=%s noproxy=%s maxtime=%s data=%s\n' "$url" "$session" "$noproxy" "$maxtime" "$data" >> "$dir/curl.log"
code=200; body=''; extra=''
if [ -n "${http_proxy:-}${HTTP_PROXY:-}${ALL_PROXY:-}${all_proxy:-}" ] && [ "$noproxy" != '*' ]; then
  code=407
elif [ "$url" != "http://127.0.0.1:8777/mcp" ] || [ "$ctype" != application/json ] \
   || [ "$accept" != 'application/json, text/event-stream' ]; then
  code=406
else
  case "$data" in
    *'"method":"initialize"'*)
      if [ -e "$dir/initialize-fails" ]; then code=500; body='{"error":"boom"}'
      elif [ -e "$dir/slow-initialize" ]; then sleep "${maxtime:-60}"; printf '000'; exit 28
      else
        extra='Mcp-Session-Id: sess-abc'
        body='{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"cass-mcp","version":"0.6.17"}}}'
      fi ;;
    *'"method":"notifications/initialized"'*)
      if [ "$session" = sess-abc ]; then code=202; else code=400; fi ;;
    *'"method":"tools/list"'*)
      if [ "$session" = sess-abc ] && [ -e "$dir/tools-missing" ]; then
        body='{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"cass_expand"}]}}'
      elif [ "$session" = sess-abc ]; then
        body=$'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"cass_search"},{"name":"cass_expand"},{"name":"cass_sessions"},{"name":"cass_timeline"}]}}\n'
      else code=400; body='{"error":"missing session"}'; fi ;;
    *) code=400 ;;
  esac
fi
{ printf 'HTTP/1.1 %s X\r\n' "$code"; [ -z "$extra" ] || printf '%s\r\n' "$extra"; printf '\r\n'; } > "$hdr"
printf '%s' "$body" > "$out"
[ -z "$fmt" ] || printf '%s' "${fmt//'%{http_code}'/$code}"
exit 0
SH
  chmod +x "$dir/bin/systemctl" "$dir/bin/curl" "$dir/fake-curl"
  printf 'LITELLM_CASS_KEY=%s\n' "$SECRET" > "$dir/mcp.env"; chmod 600 "$dir/mcp.env"
  render "$dir/new.service" "$dir/mcp.env"
  proc_cmdline "$DATA_DIR"
  HOME_UNITS="$dir/home/.config/systemd/user"
  UNIT_DIR=$HOME_UNITS
}
# Fake running process: the new unit's ExecStart argv, with --data-dir set to $1;
# $2 optionally rewrites the ExecStart line first (sed expression).
proc_cmdline() {
  local exec_line argv=() i
  exec_line=$(sed -n 's/^ExecStart=//p' "$dir/new.service")
  [ -z "${2:-}" ] || exec_line=$(printf '%s' "$exec_line" | sed "$2")
  read -r -a argv <<< "$exec_line"
  for i in "${!argv[@]}"; do [ "${argv[$i]}" != --data-dir ] || argv[i+1]=$1; done
  printf '%s\0' "${argv[@]}" > "$dir/proc/4242/cmdline"
}

seed_units() { # the live layout: 1 base unit + 6 drop-ins, the last one resets ExecStart
  local UNIT_DIR=${1:-$UNIT_DIR}
  echo active > "$dir/active"
  mkdir -p "$UNIT_DIR/cass-mcp.service.d"
  printf '[Unit]\nDescription=old cass mcp\n[Service]\nExecStart=/usr/bin/env -i LITELLM_CASS_KEY=old /old/cass-mcp --data-dir /old/lib\n' > "$UNIT_DIR/cass-mcp.service"
  local i
  for i in 1 2 3 4 5; do printf '[Service]\nEnvironment=DROPIN_%s=%s\n' "$i" "$i" > "$UNIT_DIR/cass-mcp.service.d/0$i-part.conf"; done
  printf '[Service]\nExecStart=\nExecStart=/usr/bin/env -i /old/cass-mcp --data-dir /old/lib2\n' > "$UNIT_DIR/cass-mcp.service.d/99-override.conf"
  chmod 0600 "$UNIT_DIR/cass-mcp.service.d/03-part.conf"
  printf 'unrelated\n' > "$UNIT_DIR/other.service"
}

EXTRA_ENV=()
switch_cmd() { # sets SW to the exact command line; EXTRA_ENV adds variables
  SW=(env -i HOME="$dir/home" PATH="$dir/bin:/usr/bin:/bin"
    CASS_MCP_SWITCH_PROC_ROOT="$dir/proc" CASS_MCP_SWITCH_CURL="$dir/fake-curl"
    CASS_MCP_SWITCH_WAIT_SECONDS="${WAIT:-30}" "${EXTRA_ENV[@]}" bash "$SWITCH")
}
run_switch() { # $1=unit file $2=data dir $3=bind
  switch_cmd
  "${SW[@]}" "$@" > "$dir/out" 2> "$dir/err"
}
mutating_calls() { grep -Ev '^--user (show|is-active) ' "$dir/systemctl.log" || true; }
expect_calls() { # $@ = expected mutating calls, one per argument
  local want; want=$(printf '%s\n' "$@")
  [ "$(mutating_calls)" = "${want%$'\n'}" ] || { echo "calls:"; mutating_calls; echo "want:"; printf '%s\n' "$@"; return 1; } >&2
}
RELOAD='--user daemon-reload'; RESTART='--user restart cass-mcp.service'
ENABLE='--user enable cass-mcp.service'; STOP='--user stop cass-mcp.service'
# `! cmd` never trips errexit, so negative checks go through this helper.
absent() { if grep "$@"; then echo "unexpected match: $*" >&2; return 1; fi; }
no_traps() { [ ! -e "$dir/unexpected-curl" ]; [ ! -e "$dir/systemctl.log" ] || absent -v '^--user ' "$dir/systemctl.log"; }

assert_restored() { # $1=before fingerprint
  local after; after=$(tree_print "$UNIT_DIR")
  [ "$1" = "$after" ] || { diff <(printf '%s\n' "$1") <(printf '%s\n' "$after") >&2; return 1; }
  expect_calls "$RELOAD" "$RESTART" "${@:2}" "$RELOAD" "$RESTART"
}
expect_rollback() { # $1=stderr pattern; asserts exit 1, empty stdout, restored tree
  [ "$rc" -eq 1 ] || { echo "rc=$rc" >&2; return 1; }
  [ ! -s "$dir/out" ]
  grep -qi -- "$1" "$dir/err"
}

one_case() (
  set -e
  local kind=$1 dir="$SANDBOX/$1" before
  setup_case
  case "$kind" in
    ac1-switch-existing)
      seed_units
      # Reference copy of exactly what must move: the base unit and the whole drop-in dir.
      mkdir "$dir/ref"
      cp -a "$UNIT_DIR/cass-mcp.service" "$UNIT_DIR/cass-mcp.service.d" "$dir/ref/"
      run_switch "$dir/new.service" "$DATA_DIR" "$BIND"
      [ "$(wc -l < "$dir/out")" -eq 1 ]
      local backup; backup=$(cat "$dir/out")
      case "$backup" in "$UNIT_DIR"/cass-mcp.backup-*) ;; *) echo "bad backup path $backup" >&2; exit 1 ;; esac
      [ -d "$backup" ]
      # Backup holds exactly the base unit and the whole drop-in directory, byte for byte.
      diff <(tree_print "$dir/ref" | grep -v '^ d ') <(tree_print "$backup" | grep -v '^ d ')
      [ "$(find "$backup/cass-mcp.service.d" -type f | wc -l)" -eq 6 ]
      [ "$(sed -n '1,$p' "$backup/cass-mcp.service.d/99-override.conf")" = $'[Service]\nExecStart=\nExecStart=/usr/bin/env -i /old/cass-mcp --data-dir /old/lib2' ]
      [ "$(stat -c %a "$backup/cass-mcp.service.d/03-part.conf")" = 600 ]
      # Unit directory: only the new unit (plus the backup and the unrelated unit).
      [ ! -e "$UNIT_DIR/cass-mcp.service.d" ]
      cmp "$dir/new.service" "$UNIT_DIR/cass-mcp.service"
      [ "$(stat -c %a "$UNIT_DIR/cass-mcp.service")" = 644 ]
      [ "$(find "$UNIT_DIR" -mindepth 1 -maxdepth 1 -printf '%f\n' | grep -v '^cass-mcp\.backup-' | sort | tr '\n' ' ')" = 'cass-mcp.service other.service ' ]
      expect_calls "$RELOAD" "$RESTART" "$ENABLE"
      grep -q 'session=sess-abc .*data=.*"method":"tools/list"' "$dir/curl.log"
      ;;
    ac2-datadir-mismatch|ac2-initialize-fails)
      seed_units
      before=$(tree_print "$UNIT_DIR")
      if [ "$kind" = ac2-datadir-mismatch ]; then proc_cmdline /old/lib2; else touch "$dir/initialize-fails"; fi
      local rc=0; WAIT=3 run_switch "$dir/new.service" "$DATA_DIR" "$BIND" || rc=$?
      [ "$rc" -eq 1 ]
      [ ! -s "$dir/out" ]
      if [ "$kind" = ac2-datadir-mismatch ]; then grep -q 'data-dir' "$dir/err"; else grep -qi 'initialize' "$dir/err"; fi
      assert_restored "$before"
      ;;
    ac3-render)
      local unit="$dir/new.service" execstart
      # The template carries exactly the nine frozen placeholders.
      [ "$(grep -o '@@[A-Z_]*@@' "$TEMPLATE" | sort -u | tr '\n' ' ')" = \
        '@@API_CONFIG@@ @@BIND@@ @@CASS_BIN@@ @@CASS_MCP_BIN@@ @@DATA_DIR@@ @@EMBED_PROFILE@@ @@ENV_FILE@@ @@PUBLIC_ORIGIN@@ @@RERANK_PROFILE@@ ' ]
      absent -q '@@' "$unit"
      absent -qF -- "$SECRET" "$unit"
      absent -q 'LITELLM_CASS_KEY' "$unit"
      absent -Eq 'env[[:space:]]+-i' "$unit"
      grep -qx "EnvironmentFile=$dir/mcp.env" "$unit"
      [ "$(grep -c '^ExecStart=' "$unit")" -eq 1 ]
      execstart=$(sed -n 's/^ExecStart=//p' "$unit")
      [ "$execstart" = "/opt/cass/v2/cass-mcp --bind 127.0.0.1:8777 --cass-bin /opt/cass/v2/cass --data-dir $DATA_DIR --api-config /opt/cass/config/api.toml --embedding-profile local-embed --rerank-profile local-rank --max-concurrent 2 --max-queued 1 --max-output-bytes 131072 --request-timeout-ms 600000 --terminate-grace-ms 100 --public-origin https://cass.example.ts.net" ]
      [[ "$execstart" == *' --bind 127.0.0.1'* ]]
      grep -qx 'Environment=HOME=%h/.local/state/cass-mcp' "$unit"
      grep -qx 'Environment=XDG_CONFIG_HOME=%h/.local/state/cass-mcp/config' "$unit"
      grep -qx 'Environment=XDG_DATA_HOME=%h/.local/state/cass-mcp/data' "$unit"
      grep -qx 'Environment=XDG_STATE_HOME=%h/.local/state/cass-mcp/state' "$unit"
      grep -qx 'Environment=XDG_CACHE_HOME=%h/.cache/cass-mcp' "$unit"
      grep -qx 'Environment=TMPDIR=%t/cass-mcp' "$unit"
      grep -qx 'Environment=PATH=/usr/bin:/bin' "$unit"
      grep -qx 'Environment=LANG=C.UTF-8' "$unit"
      grep -qx 'Environment=LC_ALL=C.UTF-8' "$unit"
      grep -qx 'RuntimeDirectory=cass-mcp' "$unit"
      grep -qx 'StateDirectory=cass-mcp' "$unit"
      grep -qx 'CacheDirectory=cass-mcp' "$unit"
      grep -qx 'Restart=on-failure' "$unit"
      grep -qx 'WantedBy=default.target' "$unit"
      ;;
    ac4-fresh-install)
      run_switch "$dir/new.service" "$DATA_DIR" "$BIND"
      cmp "$dir/new.service" "$UNIT_DIR/cass-mcp.service"
      [ "$(stat -c %a "$UNIT_DIR/cass-mcp.service")" = 644 ]
      local backup; backup=$(cat "$dir/out")
      if [ -n "$backup" ] && [ -e "$backup" ]; then [ -z "$(ls -A "$backup")" ]; fi
      [ "$(find "$UNIT_DIR" -mindepth 1 -maxdepth 1 -printf '%f\n' | grep -v '^cass-mcp\.backup-' | sort | tr '\n' ' ')" = 'cass-mcp.service ' ]
      expect_calls "$RELOAD" "$RESTART" "$ENABLE"
      ;;
    reject-datadir-arg|reject-placeholder|reject-public-bind|reject-bind-mismatch)
      seed_units
      before=$(tree_print "$UNIT_DIR")
      local args=("$dir/new.service" "$DATA_DIR" "$BIND")
      case "$kind" in
        reject-datadir-arg) args[1]=/srv/cass/other ;;
        reject-placeholder) sed -i 's#--data-dir [^ ]*#--data-dir @@DATA_DIR@@#' "$dir/new.service"; args[1]=@@DATA_DIR@@ ;;
        reject-public-bind) sed -i 's#--bind [^ ]*#--bind 0.0.0.0:8777#' "$dir/new.service"; args[2]=0.0.0.0:8777 ;;
        reject-bind-mismatch) args[2]=127.0.0.1:9999 ;;
      esac
      local rc=0; run_switch "${args[@]}" || rc=$?
      [ "$rc" -ne 0 ]; [ "$rc" -ne 1 ]
      [ -s "$dir/err" ]
      [ ! -e "$dir/systemctl.log" ]
      [ "$before" = "$(tree_print "$UNIT_DIR")" ]
      ;;
    r1-xdg-elsewhere|r1-selfcheck-fragment)
      # Caller points XDG_CONFIG_HOME elsewhere; the manager still loads the old unit
      # from ~/.config, and the old process happens to use the expected data-dir.
      seed_units "$HOME_UNITS"
      UNIT_DIR="$dir/elsewhere/systemd/user"
      before=$(tree_print "$HOME_UNITS")
      proc_cmdline "$DATA_DIR" 's#^/opt/cass/v2/cass-mcp#/old/cass-mcp#'
      EXTRA_ENV=(XDG_CONFIG_HOME="$dir/elsewhere")
      if [ "$kind" = r1-xdg-elsewhere ]; then
        local rc=0; WAIT=3 run_switch "$dir/new.service" "$DATA_DIR" "$BIND" || rc=$?
        [ "$rc" -eq 2 ] || { echo "rc=$rc" >&2; exit 1; }
        grep -q 'FragmentPath' "$dir/err"
        expect_calls
        [ ! -e "$UNIT_DIR" ]
      else
        # Defence in depth: preflight cannot see the old unit, the self-check must.
        touch "$dir/frag-hidden-preflight"
        local rc=0; WAIT=3 run_switch "$dir/new.service" "$DATA_DIR" "$BIND" || rc=$?
        expect_rollback 'FragmentPath'
        [ ! -e "$UNIT_DIR/cass-mcp.service" ]
      fi
      [ "$before" = "$(tree_print "$HOME_UNITS")" ]
      ;;
    r1-argv-mismatch|r1-dropin-left|r4-tools-missing|r4-restart-fails|r3-enable-fails)
      seed_units
      before=$(tree_print "$UNIT_DIR")
      local pattern extra=()
      case "$kind" in
        r1-argv-mismatch) proc_cmdline "$DATA_DIR" 's#--max-concurrent 2#--max-concurrent 4#'; pattern=argv ;;
        r1-dropin-left) touch "$dir/extra-dropin"; pattern=DropInPaths ;;
        r4-tools-missing) touch "$dir/tools-missing"; pattern=cass_search ;;
        r4-restart-fails) touch "$dir/restart-fails"; pattern=restart ;;
        r3-enable-fails) touch "$dir/enable-fails"; pattern=enable; extra=("$ENABLE") ;;
      esac
      local rc=0; WAIT=3 run_switch "$dir/new.service" "$DATA_DIR" "$BIND" || rc=$?
      expect_rollback "$pattern"
      assert_restored "$before" "${extra[@]}"
      ;;
    r2-unit-elsewhere)
      local other="$dir/home/.local/share/systemd/user"
      seed_units "$other"
      before=$(tree_print "$dir/home")
      local rc=0; run_switch "$dir/new.service" "$DATA_DIR" "$BIND" || rc=$?
      [ "$rc" -eq 2 ] || { echo "rc=$rc" >&2; exit 1; }
      grep -q "$other" "$dir/err"
      expect_calls
      [ "$before" = "$(tree_print "$dir/home")" ]
      ;;
    r4-fresh-fails|r2-fresh-fails-was-active)
      touch "$dir/initialize-fails"
      [ "$kind" != r2-fresh-fails-was-active ] || echo active > "$dir/active"
      local rc=0; WAIT=3 run_switch "$dir/new.service" "$DATA_DIR" "$BIND" || rc=$?
      expect_rollback initialize
      if [ "$kind" = r4-fresh-fails ]; then expect_calls "$RELOAD" "$RESTART" "$STOP" "$RELOAD"
      else expect_calls "$RELOAD" "$RESTART" "$RELOAD"; fi
      [ -z "$(find "$UNIT_DIR" -mindepth 1)" ]
      ;;
    r4-term-during-check)
      seed_units
      before=$(tree_print "$UNIT_DIR")
      touch "$dir/never-starts"
      WAIT=20 switch_cmd
      ( exec "${SW[@]}" "$dir/new.service" "$DATA_DIR" "$BIND" > "$dir/out" 2> "$dir/err" ) &
      local pid=$! i
      for i in $(seq 100); do [ ! -e "$dir/first-mainpid" ] || break; sleep 0.1; done
      [ -e "$dir/first-mainpid" ]
      kill -TERM "$pid"
      local rc=0; wait "$pid" || rc=$?
      expect_rollback interrupted
      assert_restored "$before"
      ;;
    r5-proxy-env)
      EXTRA_ENV=(http_proxy=http://proxy.invalid:3128 ALL_PROXY=socks5://proxy.invalid:1080)
      run_switch "$dir/new.service" "$DATA_DIR" "$BIND"
      [ "$(grep -c . "$dir/curl.log")" -ge 3 ]
      absent -v 'noproxy=\* ' "$dir/curl.log"
      ;;
    r6-deadline)
      seed_units
      before=$(tree_print "$UNIT_DIR")
      touch "$dir/slow-initialize"
      local start=$SECONDS rc=0; WAIT=3 run_switch "$dir/new.service" "$DATA_DIR" "$BIND" || rc=$?
      [ $((SECONDS - start)) -le 5 ] || { echo "took $((SECONDS - start))s" >&2; exit 1; }
      expect_rollback initialize
      assert_restored "$before"
      # Every curl call is bounded by the time left, never more than WAIT itself.
      local t
      while read -r t; do
        if [ "$t" -lt 1 ] || [ "$t" -gt 3 ]; then echo "max-time $t" >&2; exit 1; fi
      done < <(sed -n 's/.* maxtime=\([^ ]*\) .*/\1/p' "$dir/curl.log")
      ;;
    *) exit 2 ;;
  esac
  no_traps
)

for kind in ac1-switch-existing ac2-datadir-mismatch ac2-initialize-fails ac3-render \
  ac4-fresh-install reject-datadir-arg reject-placeholder reject-public-bind reject-bind-mismatch \
  r1-xdg-elsewhere r1-selfcheck-fragment r1-argv-mismatch r1-dropin-left r2-unit-elsewhere \
  r2-fresh-fails-was-active r3-enable-fails r4-tools-missing r4-fresh-fails r4-restart-fails \
  r4-term-during-check r5-proxy-env r6-deadline; do
  set +e
  one_case "$kind" > "$SANDBOX/$kind.log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then PASS=$((PASS+1)); printf 'PASS %s\n' "$kind"
  else FAIL=$((FAIL+1)); printf 'FAIL %s: %s\n' "$kind" "$SANDBOX/$kind.log"; fi
done
printf 'TEST_SUMMARY total=%s pass=%s fail=%s\n' "$((PASS+FAIL))" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
[ -n "${TEST_SANDBOX:-}" ] || rm -rf -- "$SANDBOX"
