#!/usr/bin/env bash
# Usage: bash scripts/tests/test-cass-ingest-entry.sh
# Renders scripts/release-templates/cass-ingest-entry.sh with sed and runs it
# against a stand-in `cass`. Each case owns its directory, HOME and PATH.
# No real cass, cargo, network or credentials are used.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
TEMPLATE="$ROOT/scripts/release-templates/cass-ingest-entry.sh"
# A sandbox this script creates is removed when every case passes and kept
# on failure. A sandbox given in TEST_SANDBOX is never removed.
if [ -n "${TEST_SANDBOX:-}" ]; then
  SANDBOX=$TEST_SANDBOX; OWN_SANDBOX=0
else
  SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/cc-cass-ingest-entry-test.XXXXXX"); OWN_SANDBOX=1
fi
mkdir -p "$SANDBOX"
RESERVED_KEYS='CASS_BIN DATA_DIR API_CONFIG ENV_FILE CONFIG_HOME INSTANCE PATH TMPDIR HOME XDG_CONFIG_HOME'
REAL_PY=$(command -v python3)
SECRET='s3cr3t value $(touch PWNED) `id` ;|&'
PASS=0; FAIL=0; SKIP=0
printf 'sandbox=%s template=%s\n' "$SANDBOX" "$TEMPLATE"

# Validates one entry run. Arguments: stdout file, entry exit code, then the
# expected entry exit code, classification, sync_exit_code, error_kind and
# sync_run_id (JSON literals).
check_output() {
  "$REAL_PY" -I - "$@" <<'PY'
import json, re, sys
out, rc, want_rc, cls, code, kind, run_id = sys.argv[1:8]
data = open(out, "rb").read().decode("utf-8")
problems = []
if not data.endswith("\n") or data.count("\n") != 1:
    problems.append("stdout is not exactly one line: %r" % data)
try:
    obj = json.loads(data)
except ValueError as exc:
    sys.exit("stdout is not JSON: %s: %r" % (exc, data))
keys = ["schema", "instance", "classification", "sync_exit_code", "error_kind",
        "sync_run_id", "started_at", "finished_at"]
if not isinstance(obj, dict) or list(obj) != keys:
    sys.exit("unexpected fields: %r" % (obj,))
ts = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
expect = {
    "schema": "cass.ingest-entry.v1",
    "instance": "inst-test",
    "classification": cls,
    "sync_exit_code": json.loads(code),
    "error_kind": json.loads(kind),
    "sync_run_id": json.loads(run_id),
}
for key, value in expect.items():
    if obj[key] != value or type(obj[key]) is not type(value):
        problems.append("%s=%r, want %r" % (key, obj[key], value))
for key in ("started_at", "finished_at"):
    if not isinstance(obj[key], str) or not ts.match(obj[key]):
        problems.append("%s has bad format: %r" % (key, obj[key]))
if not problems and obj["started_at"] > obj["finished_at"]:
    problems.append("started_at is after finished_at")
if int(rc) != int(want_rc):
    problems.append("entry exit code %s, want %s" % (rc, want_rc))
if problems:
    sys.exit("; ".join(problems))
PY
}

one_case() (
  set -e
  local kind=$1 dir="$SANDBOX/$1"
  mkdir -p "$dir/home" "$dir/config" "$dir/data" "$dir/shim" "$dir/bin"
  printf '[api]\n' > "$dir/api.toml"
  printf '%s' "$SECRET" > "$dir/secret"
  {
    printf '# comment line\n\n'
    printf 'CASS_TEST_SECRET=%s\n' "$SECRET"
    printf 'CASS_TEST_PLAIN=plain\n'
    printf 'lower_case=ignored\n'
    printf 'not a valid line\n'
    printf '  # indented comment\n'
  } > "$dir/env"

  # Stand-in cass: logs argv and environment, scans every process argv for
  # the secret, writes a stderr marker, then replays the scripted result.
  cat > "$dir/bin/cass" <<SH
#!/bin/bash
d='$dir'
printf '%s\n' "\$@" > "\$d/argv"
{
  printf 'HOME=%s\n' "\${HOME-<unset>}"
  printf 'XDG_CONFIG_HOME=%s\n' "\${XDG_CONFIG_HOME-<unset>}"
  printf 'CASS_TEST_PLAIN=%s\n' "\${CASS_TEST_PLAIN-<unset>}"
  printf 'lower_case=%s\n' "\${lower_case-<unset>}"
  printf 'SSH_ORIGINAL_COMMAND=%s\n' "\${SSH_ORIGINAL_COMMAND-<unset>}"
  printf 'PATH=%s\n' "\${PATH-<unset>}"
  printf 'TMPDIR=%s\n' "\${TMPDIR-<unset>}"
  printf 'CASS_TEST_LAST=%s\n' "\${CASS_TEST_LAST-<unset>}"
} > "\$d/env.seen"
if [ "\${CASS_TEST_SECRET-}" = "\$(cat "\$d/secret")" ]; then echo yes > "\$d/secret.seen"; fi
'$REAL_PY' -I -c '
import os, sys
secret = open(sys.argv[1], "rb").read()
hits = []
for pid in os.listdir("/proc"):
    if pid.isdigit():
        try:
            if secret in open("/proc/%s/cmdline" % pid, "rb").read():
                hits.append(pid)
        except OSError:
            pass
open(sys.argv[2], "w").write(" ".join(hits))
' "\$d/secret" "\$d/proc-hits"
echo fake-cass-stderr-marker >&2
cat "\$d/reply.out" 2>/dev/null
exit "\$(cat "\$d/reply.rc")"
SH
  chmod +x "$dir/bin/cass"

  # PATH shims log argv of every external tool the entry may call.
  cat > "$dir/shim/python3" <<SH
#!/bin/bash
printf '%s\n' "\$*" >> '$dir/tool-argv'
exec '$REAL_PY' "\$@"
SH
  local tool
  for tool in date mktemp rm cat env sed grep awk tr head xargs; do
    cat > "$dir/shim/$tool" <<SH
#!/bin/bash
printf '%s\n' "\$*" >> '$dir/tool-argv'
exec '$(command -v "$tool")' "\$@"
SH
  done
  printf '#!/bin/bash\necho "$0" >> %q\nexit 89\n' "$dir/forbidden-calls" > "$dir/shim/jq"
  chmod +x "$dir/shim/"*

  # Decoys: any use of them leaves an evil-ran marker.
  mkdir -p "$dir/evilpath" "$dir/evilhome"
  local decoy
  for decoy in "$dir/bin/evil" "$dir/evilpath/python3" "$dir/evilpath/date" \
    "$dir/evilpath/mktemp" "$dir/evilpath/rm" "$dir/evilpath/cat"; do
    printf '#!/bin/bash\necho "$0" >> %q\necho %s\nexit 0\n' "$dir/evil-ran" \
      "'{\"schema\":\"cass.sync.v1\",\"run_id\":\"evil\",\"exit_code\":0}'" > "$decoy"
    chmod +x "$decoy"
  done

  local bin="$dir/bin/cass" reply_rc=0 reply_out unrendered='' want_last='<unset>'
  local want_rc want_cls want_code want_kind='null' want_id='null' reserved=''
  local ok_reply='{"schema":"cass.sync.v1","run_id":"run-ok","exit_code":0}'
  case "$kind" in
    ok) reply_out='{"schema":"cass.sync.v1","run_id":"run-ok","exit_code":0}'
      want_rc=0; want_cls=ok; want_code=0; want_id='"run-ok"' ;;
    index-busy) reply_rc=2
      reply_out='{"schema":"cass.sync.v1","run_id":"run-busy","exit_code":2,"error":{"kind":"index-busy","message":"lock held"}}'
      want_rc=0; want_cls=skipped; want_code=2; want_kind='"index-busy"'; want_id='"run-busy"' ;;
    precondition) reply_rc=2
      reply_out='{"schema":"cass.sync.v1","run_id":"run-pre","exit_code":2,"error":{"kind":"semantic-unavailable","message":"probe failed"}}'
      want_rc=0; want_cls=warning; want_code=2; want_kind='"semantic-unavailable"'; want_id='"run-pre"' ;;
    partial) reply_rc=3
      reply_out='{"schema":"cass.sync.v1","run_id":"run-part","exit_code":3}'
      want_rc=0; want_cls=warning; want_code=3; want_id='"run-part"' ;;
    internal) reply_rc=1
      reply_out='{"schema":"cass.sync.v1","run_id":"run-int","exit_code":1,"error":{"kind":"index","message":"boom"}}'
      want_rc=1; want_cls=failed; want_code=1; want_kind='"index"'; want_id='"run-int"' ;;
    not-json) reply_rc=2; reply_out='error: unexpected argument --bogus'
      want_rc=1; want_cls=failed; want_code=2 ;;
    not-object) reply_rc=0; reply_out='["schema","cass.sync.v1"]'
      want_rc=1; want_cls=failed; want_code=0 ;;
    unknown-exit) reply_rc=7
      reply_out='{"schema":"cass.sync.v1","run_id":"run-odd","exit_code":7}'
      want_rc=1; want_cls=unknown_exit; want_code=7; want_id='"run-odd"' ;;
    not-executable) chmod -x "$dir/bin/cass"; reply_out=''
      want_rc=1; want_cls=failed; want_code=null ;;
    missing-binary) bin="$dir/bin/absent"; reply_out=''
      want_rc=1; want_cls=failed; want_code=null ;;
    env-missing) rm -f -- "$dir/env"; reply_out=''
      want_rc=1; want_cls=failed; want_code=null ;;
    env-directory) rm -f -- "$dir/env"; mkdir "$dir/env"; reply_out=''
      want_rc=1; want_cls=failed; want_code=null ;;
    env-unreadable)
      if [ "$(id -u)" -eq 0 ]; then echo 'root ignores file modes' >&2; exit 77; fi
      chmod 000 "$dir/env"; reply_out=''
      want_rc=1; want_cls=failed; want_code=null ;;
    reserved-keys)
      {
        printf 'CASS_BIN=%s\n' "$dir/bin/evil"
        printf 'DATA_DIR=/evil/data\nAPI_CONFIG=/evil/api.toml\nENV_FILE=/evil/env\n'
        printf 'CONFIG_HOME=/evil/config\nINSTANCE=spoofed\n'
        printf 'PATH=%s\n' "$dir/evilpath"
        printf 'TMPDIR=%s\n' "$dir/evil-tmp-missing"
        printf 'HOME=%s\n' "$dir/evilhome"
        printf 'XDG_CONFIG_HOME=/evil/xdg\n'
      } >> "$dir/env"
      reserved=$RESERVED_KEYS; reply_out=$ok_reply
      want_rc=0; want_cls=ok; want_code=0; want_id='"run-ok"' ;;
    home-empty) printf 'HOME=\n' >> "$dir/env"
      reserved=HOME; reply_out=$ok_reply
      want_rc=0; want_cls=ok; want_code=0; want_id='"run-ok"' ;;
    unrendered) unrendered=DATA_DIR; reply_out=$ok_reply
      want_rc=1; want_cls=failed; want_code=null ;;
    last-line-no-newline) printf 'CASS_TEST_LAST=last' >> "$dir/env"
      want_last=last; reply_out=$ok_reply
      want_rc=0; want_cls=ok; want_code=0; want_id='"run-ok"' ;;
    *) exit 2 ;;
  esac
  printf '%s\n' "$reply_out" > "$dir/reply.out"
  printf '%s\n' "$reply_rc" > "$dir/reply.rc"

  local name value render=()
  for name in CASS_BIN DATA_DIR API_CONFIG ENV_FILE CONFIG_HOME INSTANCE; do
    case $name in
      CASS_BIN) value=$bin ;; DATA_DIR) value=$dir/data ;; API_CONFIG) value=$dir/api.toml ;;
      ENV_FILE) value=$dir/env ;; CONFIG_HOME) value=$dir/config ;; INSTANCE) value=inst-test ;;
    esac
    [ "$name" = "$unrendered" ] || render+=(-e "s|@@$name@@|$value|g")
  done
  sed "${render[@]}" "$TEMPLATE" > "$dir/entry.sh"
  if [ -n "$unrendered" ]; then
    grep -q "@@$unrendered@@" "$dir/entry.sh"
  else
    ! grep -q '@@[A-Z_]*@@' "$dir/entry.sh" || exit 1
  fi

  # Caller arguments, SSH_ORIGINAL_COMMAND and a wrong XDG_CONFIG_HOME must
  # all be ignored.
  local rc=0
  # The entry runs inside the case directory, so stray relative writes stay
  # in the sandbox instead of the repository.
  /usr/bin/env -i -C "$dir" HOME="$dir/home" PATH="$dir/shim:/usr/bin:/bin" XDG_CONFIG_HOME=/wrong/config \
    SSH_ORIGINAL_COMMAND='cass index --full; touch /tmp/x' \
    bash "$dir/entry.sh" --data-dir /evil sync index --full \
    > "$dir/stdout" 2> "$dir/stderr" || rc=$?
  check_output "$dir/stdout" "$rc" "$want_rc" "$want_cls" "$want_code" "$want_kind" "$want_id"

  # The secret never reaches stdout, stderr or any external tool argv.
  # `! cmd` never trips errexit, so each negation exits explicitly.
  ! grep -qF -- "$SECRET" "$dir/stdout" "$dir/stderr" || exit 1
  [ -s "$dir/tool-argv" ]
  ! grep -qF -- "$SECRET" "$dir/tool-argv" || exit 1
  [ ! -e "$dir/forbidden-calls" ]
  [ ! -e "$dir/PWNED" ]
  [ ! -e "$dir/home/PWNED" ]
  [ ! -e PWNED ]
  [ ! -e "$dir/evil-ran" ]
  for name in $reserved; do
    grep -qxF "cass-ingest-entry: reserved key ignored: $name" "$dir/stderr"
  done
  ! grep -qE 'spoofed|/evil|evilhome|evilpath|evil-tmp' "$dir/stderr" || exit 1

  if [ "$want_code" = null ]; then
    [ ! -e "$dir/argv" ]
    [ "$(wc -l < "$dir/stderr")" -ge 1 ]
    case $kind in
      env-*) [ "$(wc -l < "$dir/stderr")" -eq 1 ]
        grep -qF 'env file' "$dir/stderr" ;;
    esac
    return 0
  fi
  printf 'sync\n--json\n--no-mirror\n--data-dir\n%s\n--api-config\n%s\n' \
    "$dir/data" "$dir/api.toml" | diff - "$dir/argv"
  printf 'HOME=%s\nXDG_CONFIG_HOME=%s\nCASS_TEST_PLAIN=plain\nlower_case=<unset>\nSSH_ORIGINAL_COMMAND=<unset>\nPATH=%s\nTMPDIR=<unset>\nCASS_TEST_LAST=%s\n' \
    "$dir/home" "$dir/config" "$dir/shim:/usr/bin:/bin" "$want_last" | diff - "$dir/env.seen"
  [ "$(cat "$dir/secret.seen")" = yes ]
  [ ! -s "$dir/proc-hits" ]
  grep -qx fake-cass-stderr-marker "$dir/stderr"
  ! grep -q fake-cass-stderr-marker "$dir/stdout" || exit 1
)

for kind in ok index-busy precondition partial internal not-json not-object \
  unknown-exit not-executable missing-binary env-missing env-directory \
  reserved-keys home-empty unrendered env-unreadable last-line-no-newline; do
  # Capture each subshell status outside a conditional so its errexit stays active.
  set +e
  ( set -x; one_case "$kind" ) > "$SANDBOX/$kind.log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    PASS=$((PASS+1)); printf 'PASS %s\n' "$kind"
  elif [ "$rc" -eq 77 ]; then
    SKIP=$((SKIP+1)); printf 'SKIP %s: %s\n' "$kind" "$SANDBOX/$kind.log"
  else
    FAIL=$((FAIL+1)); printf 'FAIL %s: %s\n' "$kind" "$SANDBOX/$kind.log"
  fi
done
printf 'TEST_SUMMARY total=%s pass=%s fail=%s skip=%s\n' "$((PASS+FAIL+SKIP))" "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -ne 0 ]; then
  printf 'sandbox kept: %s\n' "$SANDBOX"
  exit 1
fi
if [ "$OWN_SANDBOX" -eq 1 ]; then
  rm -rf -- "$SANDBOX"
fi
