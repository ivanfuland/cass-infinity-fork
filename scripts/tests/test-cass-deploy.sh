#!/usr/bin/env bash
# Full deployment mode of install.sh (--deploy): version and current pointer,
# data directory states, and the installer-owned configuration directory.
# Usage: bash scripts/tests/test-cass-deploy.sh /absolute/extracted-v1-bundle
# A format 2 test bundle is built from the given real binaries and the installer
# under test (DEPLOY_INSTALL_SCRIPT overrides it). Each case owns a temporary
# HOME, prefix, data and configuration directory. The real cass binary only ever
# runs against those temporary directories. The sandbox is removed when all
# cases pass.
set -euo pipefail
SRC=${1:?usage: test-cass-deploy.sh /absolute/extracted-bundle}
SRC=$(cd -- "$SRC" && pwd -P)
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
INSTALLER=${DEPLOY_INSTALL_SCRIPT:-$REPO/scripts/install-cass-fork-release.sh}
SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/cc-cass-deploy-test.XXXXXX")
BUNDLE="$SANDBOX/bundle"
COMMIT=$(sed -n 's/^source_commit=//p' "$SRC/release.env")
ID="cass-fork-$COMMIT-linux-x86_64"
KEY_VALUE='sk-SYNTHETIC-t02-0123456789abcdef=='
KEY_ENV=CASS_TEST_API_KEY
# The connector set of the baseline binary (src/indexer connectors, e5f0fa43).
ALL_CONNECTORS='aider amp antigravity chatgpt claude_code clawdbot cline codex copilot copilot_cli crush cursor factory gemini hermes kimi openclaw opencode openhands pi_agent qwen vibe'
DISABLED='aider amp antigravity chatgpt clawdbot cline copilot copilot_cli crush cursor factory gemini hermes kimi openclaw opencode openhands qwen vibe'
PASS=0; FAIL=0
printf 'sandbox=%s source_bundle=%s installer=%s\n' "$SANDBOX" "$SRC" "$INSTALLER"

mkdir -p "$BUNDLE/templates"
cp -p -- "$SRC/cass" "$SRC/cass-mcp" "$BUNDLE/"
cp -- "$INSTALLER" "$BUNDLE/install.sh"; chmod 755 "$BUNDLE/install.sh"
sed 's#^format=.*#format=cass-fork-release/2#' "$SRC/release.env" > "$BUNDLE/release.env"
# The deployment templates of this source tree, as setup-cass-fork.sh packs them.
cp -p -- "$REPO"/scripts/release-templates/* "$BUNDLE/templates/"
(cd "$BUNDLE" && { printf '%s\n' cass cass-mcp install.sh release.env; find templates -type f; } \
  | LC_ALL=C sort | xargs -d '\n' sha256sum -- > SHA256SUMS)
# R2: a correctly signed format 2 bundle whose entry template has an unknown placeholder.
BAD_BUNDLE="$SANDBOX/bundle-unknown-placeholder"
cp -a -- "$BUNDLE" "$BAD_BUNDLE"
printf '# @@UNKNOWN@@\n' >> "$BAD_BUNDLE/templates/cass-ingest-entry.sh"
(cd "$BAD_BUNDLE" && { printf '%s\n' cass cass-mcp install.sh release.env; find templates -type f; } \
  | LC_ALL=C sort | xargs -d '\n' sha256sum -- > SHA256SUMS)

tree_hash() {
  [ -e "$1" ] || [ -L "$1" ] || { echo absent; return; }
  [ -d "$1" ] || { stat -c '%F %a' -- "$1"; sha256sum -- "$1"; return; }
  (cd "$1" && find . -printf '%y %m %P %l\n' | LC_ALL=C sort && find . -type f -exec sha256sum {} + | LC_ALL=C sort)
}
home_cfg_hash() { tree_hash "$dir/home/.config/cass"; }
# Sets dir-scoped variables of the calling case (dynamic scope).
prepare_case() {
  mkdir -p "$dir/home/.config/cass" "$dir/prefix" "$dir/tools"
  path="$dir/tools:/usr/bin:/bin"
  cat > "$dir/tools/forbidden-tool" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$0" >> "${0%/*}/unexpected-tool-calls"
exit 89
SH
  chmod +x "$dir/tools/forbidden-tool"
  local tool
  for tool in git cargo rustup rustc python python3 curl wget jq systemctl tailscale; do
    ln -s forbidden-tool "$dir/tools/$tool"
  done
  # Production rollback configuration under the test HOME: never read or written.
  printf 'disabled_agents = ["codex", "claude_code", "pi_agent"]\n' > "$dir/home/.config/cass/sources.toml"
  printf '# production rollback copy\nversion = 1\n' > "$dir/home/.config/cass/model-api.toml"
  printf 'PROD_KEY=production-value-not-touched\n' > "$dir/home/.config/cass/model-api.env"
  # Agent roots that the real binary detects, for the onboarding check.
  local h="$dir/home"
  mkdir -p "$h/.claude/projects/p" "$h/.codex/sessions" "$h/.pi/agent/sessions" "$h/.gemini/tmp" \
    "$h/.aider" "$h/.cursor" "$h/.local/share/opencode" "$h/.openclaw" "$h/.qwen" "$h/.factory"
  printf '{}\n' > "$h/.claude/projects/p/s.jsonl"
  printf '%s\n' "$KEY_VALUE" > "$dir/key"
  prefix="$dir/prefix"; data="$dir/data"; cfg="$dir/cfg"; inst=alpha
  embed=http://127.0.0.1:18080/v1/embeddings; rerank=https://rerank.invalid.example/v1/rerank
  keyfile="$dir/key"; legacy=""
  # T10: --mcp none and no first round unless a case asks for them.
  mcp=none; first_round=skip; xenv=(); bundle=$BUNDLE
}
run_deploy() {
  local -a args=(--prefix "$prefix" --deploy --instance "$inst" --data-dir "$data" --config-dir "$cfg"
    --embed-endpoint "$embed" --embed-model synthetic-embed --embed-revision rev-e1
    --rerank-endpoint "$rerank" --rerank-model synthetic-rerank --rerank-revision rev-r1
    --key-env "$KEY_ENV" --key-file "$keyfile")
  [ -z "$legacy" ] || args+=(--legacy-source "$legacy")
  [ -z "$mcp" ] || args+=(--mcp "$mcp")
  [ "$first_round" = run ] || args+=(--skip-first-round)
  local rc=0
  env -i HOME="$dir/home" PATH="$path" "${xenv[@]}" bash "$bundle/install.sh" "${args[@]}" "$@" > "$dir/install.log" 2>&1 || rc=$?
  cat "$dir/install.log" >> "$dir/all-output.log"
  return "$rc"
}
# expect_rc <code> [extra args]: run once and require that exit status.
expect_rc() {
  local want=$1 rc=0; shift
  run_deploy "$@" || rc=$?
  [ "$rc" -eq "$want" ] || { printf 'expected rc=%s got rc=%s\n' "$want" "$rc"; cat "$dir/install.log"; return 1; }
}
no_secret() { if grep -rqF -- "$KEY_VALUE" "$dir/all-output.log" 2>/dev/null; then echo 'secret value in output'; return 1; fi; }
# The complete expected configuration for the default arguments.
expected_sources() {
  printf '# Generated by install.sh --deploy for instance %s. Rewritten on every deploy.\n' "$inst"
  printf 'disabled_agents = [\n'
  local name; for name in $DISABLED; do printf '  "%s",\n' "$name"; done
  printf ']\n'
  if [ -n "$legacy" ]; then
    printf '\n[[sources]]\nname = "%s"\ntype = "local"\norigin_host = "local"\nreadonly = true\npaths = ["%s/.claude/projects"]\n' \
      "${legacy##*/}" "$legacy"
  fi
}
expected_model_api() {
  cat <<EOF
# Generated by install.sh --deploy for instance $inst. Rewritten on every deploy.
version = 1
default_embedding = "embed"
default_rerank = "rerank"

[profiles.embed]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "$embed"
scope = "${1:-loopback}"
model = "synthetic-embed"
model_revision = "rev-e1"
api_key_env = "$KEY_ENV"
normalization = "l2"
timeout_ms = 125000

[profiles.rerank]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "$rerank"
scope = "${2:-remote}"
model = "synthetic-rerank"
model_revision = "rev-r1"
api_key_env = "$KEY_ENV"
timeout_ms = 125000
EOF
}
check_deployed() {
  [ -L "$prefix/current" ]; [ "$(readlink "$prefix/current")" = "$ID" ]
  (cd "$prefix/$ID" && sha256sum --check --quiet SHA256SUMS)
  [ "$(cat "$data/.cass-install-instance")" = "$inst" ]
  [ "$(stat -c %a "$data")" = 700 ]
  local unit_line=(); [ "$mcp" != install ] || unit_line=('f 644 cass-mcp.service')
  [ "$(cd "$cfg" && find . -mindepth 1 -printf '%y %m %P\n' | LC_ALL=C sort)" = "$(printf '%s\n' \
    'd 700 cass' 'f 600 .cass-install-instance' "${unit_line[@]}" 'f 600 cass/sources.toml' 'f 700 cass-ingest-entry' \
    'f 600 model-api.env' 'f 600 model-api.toml' | LC_ALL=C sort)" ]
  diff <(expected_entry) "$cfg/cass-ingest-entry"
  [ "$mcp" != install ] || diff <(expected_unit) "$cfg/cass-mcp.service"
  [ "$(stat -c %a "$cfg")" = 700 ]
  [ "$(cat "$cfg/.cass-install-instance")" = "$inst" ]
  diff <(expected_sources) "$cfg/cass/sources.toml"
  diff <(expected_model_api "$@") "$cfg/model-api.toml"
  # Exactly one line KEY=VALUE, LF terminated, no CR.
  printf '%s=%s\n' "$KEY_ENV" "$KEY_VALUE" | cmp -- - "$cfg/model-api.env"
  grep -q '^DEPLOY_OK ' "$dir/install.log"
}
# The real binary, only against this case's temporary directories.
real_cass() { env -i HOME="$dir/home" XDG_CONFIG_HOME="$cfg" PATH=/usr/bin:/bin "$prefix/current/cass" "$@"; }

# ---------------------------------------------------------------------------
# T10: rendered entry and unit, MCP switch, first round, tailnet, self-check.
# ---------------------------------------------------------------------------
TEMPLATES="$REPO/scripts/release-templates"
BIND=127.0.0.1:18777; ORIGIN=https://alien.example.ts.net
# The expected rendering: plain replacement with the canonical absolute paths.
expected_entry() {
  local c d; c=$(realpath -m -- "$cfg"); d=$(realpath -m -- "$data")
  sed -e "s|@@CASS_BIN@@|$(realpath -m -- "$prefix")/current/cass|" -e "s|@@DATA_DIR@@|$d|" \
    -e "s|@@API_CONFIG@@|$c/model-api.toml|" -e "s|@@ENV_FILE@@|$c/model-api.env|" \
    -e "s|@@CONFIG_HOME@@|$c|" -e "s|@@INSTANCE@@|$inst|" "$TEMPLATES/cass-ingest-entry.sh"
}
expected_unit() {
  local c d p; c=$(realpath -m -- "$cfg"); d=$(realpath -m -- "$data"); p=$(realpath -m -- "$prefix")/current
  sed -e "s|@@CASS_MCP_BIN@@|$p/cass-mcp|g" -e "s|@@CASS_BIN@@|$p/cass|g" -e "s|@@DATA_DIR@@|$d|g" \
    -e "s|@@API_CONFIG@@|$c/model-api.toml|g" -e "s|@@ENV_FILE@@|$c/model-api.env|g" -e "s|@@BIND@@|$BIND|g" \
    -e "s|@@PUBLIC_ORIGIN@@|$ORIGIN|g" -e "s|@@EMBED_PROFILE@@|embed|g" -e "s|@@RERANK_PROFILE@@|rerank|g" \
    "$TEMPLATES/cass-mcp.service.in"
}
# First round injection. The installer runs the rendered entry through env. This
# env shim copies the entry, changes only its CASS_BIN line to the fake cass and
# runs the copy; every other env call passes through. The mode file selects the
# fake sync result; "nonjson" replaces the entry output with plain text.
install_first_round_fakes() {
  first_round=run
  printf '%s\n' "${1:-ok}" > "$dir/first-round-mode"
  cat > "$dir/tools/env" <<'SH'
#!/usr/bin/env bash
last=${!#}
case "$last" in
  */cass-ingest-entry)
    d=${0%/tools/*}
    printf '%s\n' "$*" >> "$d/entry-calls"
    case "$(cat "$d/first-round-mode")" in
      nonjson) echo 'this is not json'; exit 0 ;;
      nonjson-long) head -c 3000 /dev/zero | tr '\0' y; exit 0 ;;
    esac
    sed "s|^CASS_BIN='.*'\$|CASS_BIN='$d/fake-cass'|" "$last" > "$d/entry-under-test"
    chmod 700 "$d/entry-under-test"
    set -- "${@:1:$#-1}" "$d/entry-under-test"
    exec /usr/bin/env "$@" ;;
esac
exec /usr/bin/env "$@"
SH
  cat > "$dir/fake-cass" <<'SH'
#!/usr/bin/env bash
d=${0%/*}
echo first-round >> "$d/sequence"
printf '%s\0' "$@" > "$d/fake-cass-argv"
printf '%s' "${CASS_TEST_API_KEY-UNSET}" > "$d/fake-cass-key"
printf '%s\n' "XDG_CONFIG_HOME=${XDG_CONFIG_HOME-unset}" "SSH_ORIGINAL_COMMAND=${SSH_ORIGINAL_COMMAND-unset}" > "$d/fake-cass-env"
echo 'fake cass stderr line' >&2
case "$(cat "$d/first-round-mode")" in
  ok) echo '{"run_id":"run-ok"}'; exit 0 ;;
  warning) echo '{"run_id":"run-warn"}'; exit 3 ;;
  skipped) echo '{"error":{"kind":"index-busy"}}'; exit 2 ;;
  failed) echo '{"error":{"kind":"boom"}}'; exit 1 ;;
  unknown) echo '{}'; exit 7 ;;
esac
exit 9
SH
  chmod +x "$dir/tools/env" "$dir/fake-cass"
}
# MCP fakes: a systemctl that emulates the user manager from the test HOME and
# refuses any call without --user, an MCP endpoint (curl hook), a fake /proc and a
# tailscale that logs. They replace the forbidden-tool links for this case only.
install_mcp_fakes() {
  mcp=install
  rm -f "$dir/tools/systemctl" "$dir/tools/tailscale"
  cat > "$dir/tools/systemctl" <<'SH'
#!/usr/bin/env bash
d=${0%/tools/*}
printf '%s XDG=%s\n' "$*" "${XDG_CONFIG_HOME-unset}" >> "$d/systemctl.log"
[ "$1" = --user ] || { printf 'systemctl %s\n' "$*" >> "$d/tools/unexpected-tool-calls"; exit 97; }
shift
units="$d/home/.config/systemd/user"
case "$1" in
  show)
    shift; value=0; props=()
    while [ $# -gt 1 ]; do
      case "$1" in -p) props+=("$2"); shift ;; --value) value=1 ;; *) exit 98 ;; esac; shift
    done
    [ "$1" = cass-mcp.service ] || exit 98
    for p in "${props[@]}"; do
      case "$p" in
        MainPID) if [ -e "$d/started" ]; then v=4242; else v=0; fi ;;
        FragmentPath) v=; [ ! -e "$units/cass-mcp.service" ] || v="$units/cass-mcp.service" ;;
        DropInPaths) v= ;;
        *) exit 98 ;;
      esac
      if [ "$value" = 1 ]; then printf '%s\n' "$v"; else printf '%s=%s\n' "$p" "$v"; fi
    done ;;
  is-active) if [ -e "$d/started" ]; then echo active; else echo inactive; exit 3; fi ;;
  daemon-reload) ;;
  restart)
    [ "$2" = cass-mcp.service ] || exit 98
    exec_line=$(sed -n 's/^ExecStart=//p' "$units/cass-mcp.service")
    read -r -a argv <<< "$exec_line"
    mkdir -p "$d/proc/4242"; printf '%s\0' "${argv[@]}" > "$d/proc/4242/cmdline"
    touch "$d/started"; echo systemctl-restart >> "$d/sequence" ;;
  enable|stop) [ "$2" = cass-mcp.service ] || exit 98; [ "$1" != stop ] || rm -f "$d/started" ;;
  *) exit 99 ;;
esac
SH
  cat > "$dir/tools/tailscale" <<'SH'
#!/usr/bin/env bash
d=${0%/tools/*}
printf '%s\n' "$*" >> "$d/tailscale.log"; echo tailscale >> "$d/sequence"
[ ! -e "$d/tailscale-fails" ] || { echo 'tailscale: serve refused' >&2; exit 1; }
SH
  cat > "$dir/fake-curl" <<'SH'
#!/usr/bin/env bash
d=${0%/*}
out=/dev/null; hdr=/dev/null; fmt=''; data=''; url=''; session=''
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift ;; -D) hdr=$2; shift ;; -w) fmt=$2; shift ;; --data) data=$2; shift ;;
    --noproxy|--max-time|-X) shift ;;
    -H) case "$2" in [Mm]cp-[Ss]ession-[Ii]d:*) session=${2#*: } ;; esac; shift ;;
    -*) ;; *) url=$1 ;;
  esac
  shift
done
printf 'url=%s data=%s\n' "$url" "$data" >> "$d/curl.log"
code=200; body=''; extra=''
if [ "$url" != "http://127.0.0.1:18777/mcp" ]; then code=404
else
  case "$data" in
    *'"method":"initialize"'*)
      if [ -e "$d/initialize-fails" ]; then code=500
      else extra='Mcp-Session-Id: sess-t10'; body='{"jsonrpc":"2.0","id":1,"result":{}}'; fi ;;
    *'"method":"notifications/initialized"'*) code=202 ;;
    *'"method":"tools/list"'*)
      if [ "$session" = sess-t10 ]; then body='{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"cass_search"}]}}'
      else code=400; fi ;;
    *) code=400 ;;
  esac
fi
{ printf 'HTTP/1.1 %s X\r\n' "$code"; [ -z "$extra" ] || printf '%s\r\n' "$extra"; printf '\r\n'; } > "$hdr"
printf '%s' "$body" > "$out"
printf '%s' "${fmt//'%{http_code}'/$code}"
SH
  chmod +x "$dir/tools/systemctl" "$dir/tools/tailscale" "$dir/fake-curl"
  # XDG_CONFIG_HOME is set for the installer; the switch script must not see it.
  xenv=(XDG_CONFIG_HOME="$dir/xdg-trap" CASS_MCP_SWITCH_PROC_ROOT="$dir/proc"
    CASS_MCP_SWITCH_CURL="$dir/fake-curl" CASS_MCP_SWITCH_WAIT_SECONDS=3)
}
mcp_args=(--mcp-bind "$BIND" --public-origin "$ORIGIN")
units_hash() { tree_hash "$dir/home/.config/systemd/user"; }
mutating_calls() { grep -Ev '^--user (show|is-active) ' "$dir/systemctl.log" | sed 's/ XDG=.*//' || true; }
# `! cmd` never trips errexit, so negative checks go through this helper.
absent() { if grep -q "$@"; then echo "unexpected match: $*"; return 1; fi; }
nothing_written() { [ ! -e "$prefix/current" ] && [ ! -e "$prefix/$ID" ] && [ ! -e "$cfg" ] && [ ! -e "$data" ]; }

one_case() (
  set -e
  local kind=$1 dir="$SANDBOX/$1" prefix data cfg inst embed rerank keyfile legacy path before mcp first_round xenv bundle
  prepare_case
  before=$(home_cfg_hash)
  case "$kind" in
    fresh-absent)
      expect_rc 0; check_deployed ;;
    fresh-empty)
      mkdir -m 755 "$data"; expect_rc 0; check_deployed ;;
    same-instance-rerun)
      expect_rc 0; check_deployed
      printf 'library bytes\n' > "$data/sentinel.db"
      local cfg1 cur1 data1
      cfg1=$(tree_hash "$cfg"); cur1=$(readlink "$prefix/current"); data1=$(tree_hash "$data")
      expect_rc 0; check_deployed
      [ "$(tree_hash "$cfg")" = "$cfg1" ]
      [ "$(readlink "$prefix/current")" = "$cur1" ]
      [ "$(tree_hash "$data")" = "$data1" ]
      grep -q '^VERSION_OK already installed' "$dir/install.log"
      if grep -q '^INSTALL_OK ' "$dir/install.log"; then return 1; fi ;;
    foreign-nonempty|foreign-other-instance|foreign-file)
      case "$kind" in
        foreign-nonempty) mkdir -p "$data"; printf 'someone else\n' > "$data/index.db" ;;
        foreign-other-instance) mkdir -p "$data"; printf 'beta\n' > "$data/.cass-install-instance"; printf 'x\n' > "$data/db" ;;
        foreign-file) printf 'plain file\n' > "$data" ;;
      esac
      local d1; d1=$(tree_hash "$data")
      expect_rc 3
      grep -q '^FAIL\[install\]: ' "$dir/install.log"
      [ "$(tree_hash "$data")" = "$d1" ]
      [ ! -e "$prefix/current" ]; [ ! -e "$prefix/$ID" ]; [ ! -e "$cfg" ] ;;
    fail-key-missing)
      mkdir "$prefix/old-version"; ln -s old-version "$prefix/current"
      keyfile="$dir/no-such-key"; expect_rc 2
      grep -q '^FAIL\[install\]: ' "$dir/install.log"
      [ "$(readlink "$prefix/current")" = old-version ]
      [ ! -e "$prefix/$ID" ]; [ ! -e "$cfg" ]; [ ! -e "$data" ] ;;
    fail-remote-http)
      expect_rc 0; check_deployed
      local cfg1; cfg1=$(tree_hash "$cfg")
      rerank=http://rerank.invalid.example/v1/rerank; expect_rc 2
      grep -q 'https' "$dir/install.log"
      [ "$(readlink "$prefix/current")" = "$ID" ]
      [ "$(tree_hash "$cfg")" = "$cfg1" ] ;;
    fail-remote-http-fresh)
      embed=http://127.0.0.2:18080/v1/embeddings; expect_rc 2
      [ ! -e "$prefix/current" ]; [ ! -e "$prefix/$ID" ]; [ ! -e "$cfg" ] ;;
    fail-version-mismatch)
      expect_rc 0; check_deployed
      local cfg1; cfg1=$(tree_hash "$cfg")
      printf 'changed\n' >> "$prefix/$ID/templates/README.md"
      expect_rc 1
      grep -q 'version directory differs' "$dir/install.log"
      [ "$(readlink "$prefix/current")" = "$ID" ]
      [ "$(tree_hash "$cfg")" = "$cfg1" ] ;;
    fail-version-mismatch-fresh)
      mkdir "$prefix/old-version"; ln -s old-version "$prefix/current"
      mkdir -p "$prefix/$ID"; printf 'other\n' > "$prefix/$ID/cass"
      expect_rc 1
      grep -q 'version directory differs' "$dir/install.log"
      [ "$(readlink "$prefix/current")" = old-version ]
      [ "$(cat "$prefix/$ID/cass")" = other ]
      [ -z "$(find "$cfg" -type f 2>/dev/null)" ] ;;
    fail-config-move)
      # The final move of one configuration file fails: no partial or staged file remains.
      cat > "$dir/tools/mv" <<'SH'
#!/usr/bin/env bash
case "${!#}" in */cfg/model-api.env) exit 1 ;; esac
exec /usr/bin/mv "$@"
SH
      chmod +x "$dir/tools/mv"
      mkdir "$prefix/old-version"; ln -s old-version "$prefix/current"
      if run_deploy; then return 1; fi
      grep -q '^FAIL\[install\]: ' "$dir/install.log"
      if grep -q '^DEPLOY_OK ' "$dir/install.log"; then return 1; fi
      [ "$(readlink "$prefix/current")" = old-version ]
      [ -z "$(find "$cfg" -name '.cass-install-stage.*')" ]
      [ ! -e "$cfg/model-api.env" ]
      # The run reached the final moves: the earlier files are complete.
      [ -f "$cfg/model-api.toml" ]; [ -f "$cfg/cass/sources.toml" ]
      local f
      for f in $(cd "$cfg" && find . -type f -printf '%P\n'); do
        case "$f" in cass/sources.toml) diff <(expected_sources) "$cfg/$f" ;;
          model-api.toml) diff <(expected_model_api) "$cfg/$f" ;;
          .cass-install-instance) [ "$(cat "$cfg/$f")" = "$inst" ] ;; *) return 1 ;; esac
      done ;;
    home-config-rejected)
      local variant
      for variant in "$dir/home/.config" "$dir/home/.config/" "$dir/home/x/../.config" "$dir/home/.config/cass" "$dir/link-to-config"; do
        ln -sfn "$dir/home/.config" "$dir/link-to-config"
        cfg=$variant; expect_rc 2
        grep -q '^FAIL\[install\]: ' "$dir/install.log"
      done
      [ ! -e "$prefix/current" ]; [ ! -e "$prefix/$ID" ]; [ ! -e "$data" ] ;;
    onboarding-real)
      legacy="$dir/claude-legacy"; mkdir -p "$legacy/.claude/projects"
      expect_rc 0; check_deployed
      [ "$(real_cass capabilities --json | sed -n '/"connectors": \[/,/\]/p' | sed -n 's/^ *"\([a-z0-9_]*\)",\{0,1\}$/\1/p' | LC_ALL=C sort | xargs)" = "$ALL_CONNECTORS" ]
      mkdir "$dir/obdata"
      real_cass onboarding --json --data-dir "$dir/obdata" > "$dir/onboarding.json"
      python3 -I - "$dir/onboarding.json" "$DISABLED" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
active = sorted(p["name"] for p in report["providers"] if p["readiness"] != "excluded")
assert active == ["claude", "codex", "pi_agent"], active
disabled = set(sys.argv[2].split())
excluded = report["excluded_providers"]
assert excluded and set(excluded) <= disabled, excluded
assert all(p["readiness"] == "excluded" for p in report["providers"] if p["name"] in disabled)
PY
      real_cass models list --api-config "$cfg/model-api.toml" --json > "$dir/models.json"
      python3 -I - "$dir/models.json" "$KEY_ENV" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
got = sorted((p["id"], p["kind"], p["scope"], p["api_key_env"], p["default"]) for p in d["profiles"])
assert got == [("embed", "embedding", "loopback", sys.argv[2], True), ("rerank", "rerank", "remote", sys.argv[2], True)], got
PY
      real_cass sources list --json > "$dir/sources.json"
      python3 -I - "$dir/sources.json" "$legacy" "$DISABLED" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert [(s["name"], s["type"], s["paths"]) for s in d["sources"]] == [("claude-legacy", "local", [sys.argv[2] + "/.claude/projects"])], d["sources"]
assert d["disabled_agents"] == sys.argv[3].split(), d["disabled_agents"]
PY
      # Optional evidence copy (no env file: it holds the synthetic key).
      if [ -n "${DEPLOY_TEST_EVIDENCE:-}" ]; then
        mkdir -p "$DEPLOY_TEST_EVIDENCE"
        cp -- "$dir/onboarding.json" "$dir/models.json" "$dir/sources.json" "$dir/install.log" \
          "$cfg/cass/sources.toml" "$cfg/model-api.toml" "$DEPLOY_TEST_EVIDENCE/"
      fi
      ;;
    loopback-scopes)
      embed='http://[::1]:18080/v1/embeddings'; rerank=http://LOCALHOST:18081/v1/rerank
      expect_rc 0; check_deployed loopback loopback ;;
    env-format)
      expect_rc 0; check_deployed
      [ "$(wc -l < "$cfg/model-api.env")" -eq 1 ]
      if grep -q $'\r' "$cfg/model-api.env"; then return 1; fi
      [ "$(stat -c %a "$cfg/model-api.env")" = 600 ]
      # One trailing newline is removed from the key file; a key without one is identical.
      printf '%s' "$KEY_VALUE" > "$dir/key"; expect_rc 0; check_deployed ;;
    bad-key-values)
      # Each entry is a printf format for the whole key file. Every value starts
      # with a marker that must never appear in any output.
      local fmt
      for fmt in 'sk-LEAK"q\n' "sk-LEAK'q\n" 'sk-LEAK q\n' 'sk-LEAK\tq\n' 'sk-LEAK\rq\n' 'sk-LEAK\nq\n' \
        'sk-LEAK\n\n' 'sk-LEAK\\q\n' 'sk-LEAK\001q\n' 'sk-LEAK\000q\n' 'sk-LEAK\177q\n' '' '\n' '\n\n'; do
        # shellcheck disable=SC2059 # The format is the test data.
        printf "$fmt" > "$dir/key"
        expect_rc 2
        grep -q '^FAIL\[install\]: ' "$dir/install.log"
      done
      if grep -qF 'sk-LEAK' "$dir/all-output.log"; then return 1; fi
      [ ! -e "$prefix/current" ]; [ ! -e "$cfg" ] ;;
    bad-arguments)
      inst=Bad_Name; expect_rc 2; inst=alpha
      data=relative/data; expect_rc 2; data="$dir/data"
      cfg=relative/cfg; expect_rc 2; cfg="$dir/cfg"
      expect_rc 2 --unknown-flag
      expect_rc 2 --instance beta
      embed=ftp://127.0.0.1/x; expect_rc 2; embed=http://127.0.0.1:18080/v1/embeddings
      embed='http://user@127.0.0.1/x'; expect_rc 2; embed=http://127.0.0.1:18080/v1/embeddings
      local ke
      for ke in lower_case 9START HOME PATH XDG_CONFIG_HOME 'A-B'; do
        KEY_ENV=$ke expect_rc 2
      done
      legacy='/tmp/with"quote'; expect_rc 2; legacy=relative; expect_rc 2; legacy=""
      [ ! -e "$prefix/current" ]; [ ! -e "$prefix/$ID" ]; [ ! -e "$cfg" ]; [ ! -e "$data" ] ;;
    publish-only-unchanged)
      # Without --deploy, deployment flags remain unknown arguments (exit 1) and
      # a plain installation behaves as before.
      local rc=0
      env -i HOME="$dir/home" PATH="$path" bash "$BUNDLE/install.sh" --prefix "$prefix" --instance alpha > "$dir/install.log" 2>&1 || rc=$?
      [ "$rc" -eq 1 ]; grep -q 'unknown argument: --instance' "$dir/install.log"
      env -i HOME="$dir/home" PATH="$path" bash "$BUNDLE/install.sh" --prefix "$prefix" > "$dir/install.log" 2>&1
      grep -q '^INSTALL_OK ' "$dir/install.log"
      [ ! -e "$prefix/current" ]
      rc=0
      env -i HOME="$dir/home" PATH="$path" bash "$BUNDLE/install.sh" --prefix "$prefix" > "$dir/install.log" 2>&1 || rc=$?
      [ "$rc" -eq 1 ]; grep -q 'version already exists' "$dir/install.log" ;;
    data-parent-readonly)
      # R1: creating the data directory fails; current keeps its old target.
      mkdir "$prefix/old-version"; ln -s old-version "$prefix/current"
      mkdir -m 555 "$dir/ro"; data="$dir/ro/data"
      local rc=0; run_deploy || rc=$?
      chmod 755 "$dir/ro"
      [ "$rc" -eq 1 ] || { cat "$dir/install.log"; return 1; }
      [ "$(readlink "$prefix/current")" = old-version ]
      [ ! -e "$data" ]
      [ -z "$(find "$cfg" -name '.cass-install-stage.*' 2>/dev/null)" ] ;;
    connectors-forged-dash|connectors-forged-upper)
      # R2: a capabilities list with a name outside [a-z0-9_] is refused.
      local edit='s/^    "codex",$/    "codex",\n    "new-agent",/'
      [ "$kind" = connectors-forged-dash ] || edit='s/^    "gemini",$/    "Gemini",/'
      cat > "$dir/tools/env" <<SH
#!/usr/bin/env bash
case " \$* " in
  *" capabilities --json "*) /usr/bin/env "\$@" | /usr/bin/sed '$edit'; exit "\${PIPESTATUS[0]}" ;;
esac
exec /usr/bin/env "\$@"
SH
      chmod +x "$dir/tools/env"
      mkdir "$prefix/old-version"; ln -s old-version "$prefix/current"
      expect_rc 1
      grep -q 'entries but only .* valid names' "$dir/install.log"
      [ "$(readlink "$prefix/current")" = old-version ]
      [ ! -e "$prefix/$ID" ]; [ ! -e "$cfg" ]; [ ! -e "$data" ] ;;
    term-at-stage|term-at-marker)
      # R4: TERM while temporaries exist; the EXIT cleanup still runs.
      if [ "$kind" = term-at-stage ]; then
        cat > "$dir/tools/env" <<'SH'
#!/usr/bin/env bash
case " $* " in *" models list "*) kill -TERM "$PPID" ;; esac
exec /usr/bin/env "$@"
SH
        chmod +x "$dir/tools/env"
      else
        cat > "$dir/tools/mv" <<'SH'
#!/usr/bin/env bash
case "${!#}" in */data/.cass-install-instance) kill -TERM "$PPID"; exit 1 ;; esac
exec /usr/bin/mv "$@"
SH
        chmod +x "$dir/tools/mv"
      fi
      mkdir "$prefix/old-version"; ln -s old-version "$prefix/current"
      expect_rc 143
      [ "$(readlink "$prefix/current")" = old-version ]
      [ -d "$cfg" ]; [ -z "$(find "$cfg" -name '.cass-install-stage.*')" ]
      [ -z "$(find "$data" -name '.cass-install-instance.*' 2>/dev/null)" ]
      [ "$kind" = term-at-stage ] || [ -d "$data" ] ;;
    endpoint-bad-port)
      # R5: accepted by the installer's own checks, refused by the binary.
      mkdir "$prefix/old-version"; ln -s old-version "$prefix/current"
      embed=http://127.0.0.1:99999/v1; expect_rc 1
      grep -q 'model-api.toml rejected' "$dir/install.log"
      [ "$(readlink "$prefix/current")" = old-version ]
      [ -z "$(find "$cfg" -type f 2>/dev/null)" ]
      [ ! -e "$data" ] ;;
    overlapping-dirs)
      # R3: data-dir, config-dir and prefix must be three separate trees.
      local pair
      for pair in "$dir/same $dir/same $prefix" "$dir/same $dir/same/ $prefix" "$dir/d $dir/d/cfg $prefix" \
        "$dir/c/data $dir/c $prefix" "$prefix/data $dir/cfg $prefix" "$dir/data $dir/cfg $dir/data/prefix" \
        "$dir/data $dir/cfg $dir/cfg/x/../prefix" "$dir/x/../data $dir/data $prefix"; do
        read -r data cfg prefix <<< "$pair"
        expect_rc 2
        grep -q '^FAIL\[install\]: ' "$dir/install.log"
      done
      prefix="$dir/prefix"
      [ "$(find "$dir" -mindepth 1 -maxdepth 1 -type d -printf '%P\n' | LC_ALL=C sort | xargs)" = 'home prefix tools' ]
      [ -z "$(find "$prefix" -mindepth 1)" ] ;;
    config-foreign-instance)
      # R6: another instance's configuration directory is refused unchanged.
      inst=beta; expect_rc 0
      local c1; c1=$(tree_hash "$cfg")
      inst=alpha; data="$dir/data2"; expect_rc 3
      [ "$(tree_hash "$cfg")" = "$c1" ]
      [ ! -e "$data" ] ;;
    config-foreign-nonempty)
      mkdir -m 755 "$cfg"; printf 'other tool\n' > "$cfg/settings.ini"
      local c1; c1=$(tree_hash "$cfg")
      expect_rc 3
      [ "$(tree_hash "$cfg")" = "$c1" ]; [ "$(stat -c %a "$cfg")" = 755 ]
      [ ! -e "$prefix/current" ]; [ ! -e "$prefix/$ID" ]; [ ! -e "$data" ] ;;
    config-cass-symlink)
      # R7: <config-dir>/cass must not be a symbolic link.
      mkdir -p "$cfg" "$dir/elsewhere"; ln -s "$dir/elsewhere" "$cfg/cass"
      expect_rc 2
      [ -z "$(find "$dir/elsewhere" -mindepth 1)" ]
      [ ! -e "$prefix/current" ]; [ ! -e "$data" ] ;;
    t10-mcp-none)
      # AC1: --mcp none never touches the user unit directory, systemctl or tailscale.
      local u="$dir/home/.config/systemd/user"
      mkdir -p "$u/cass-mcp.service.d"
      printf '[Service]\nExecStart=/old/cass-mcp --data-dir /old\n' > "$u/cass-mcp.service"
      printf '[Service]\nEnvironment=A=1\n' > "$u/cass-mcp.service.d/a.conf"
      local u1; u1=$(units_hash)
      install_first_round_fakes ok
      expect_rc 0; check_deployed
      grep -q '^MCP_NOT_MANAGED$' "$dir/install.log"
      grep -q '^SCHEDULE_READY ' "$dir/install.log"
      grep -q '^DEPLOY_COMPLETE instance=alpha mcp=none first_round=ok tailnet=off$' "$dir/install.log"
      [ "$(units_hash)" = "$u1" ]
      [ ! -e "$dir/systemctl.log" ]; [ ! -e "$dir/tailscale.log" ]; [ ! -e "$dir/xdg-trap" ]
      if [ -n "${DEPLOY_TEST_EVIDENCE:-}" ]; then
        mkdir -p "$DEPLOY_TEST_EVIDENCE"; cp -- "$dir/install.log" "$DEPLOY_TEST_EVIDENCE/mcp-none.log"
      fi ;;
    t10-mcp-install)
      # AC2 and AC5: install, then rerun the same command.
      install_mcp_fakes; install_first_round_fakes ok
      expect_rc 0 "${mcp_args[@]}" --tailnet-serve; check_deployed
      local u="$dir/home/.config/systemd/user"
      diff <(expected_unit) "$u/cass-mcp.service"
      [ "$(stat -c %a "$u/cass-mcp.service")" = 644 ]
      grep -q "^ExecStart=$(realpath -m "$prefix")/current/cass-mcp --bind $BIND --cass-bin $(realpath -m "$prefix")/current/cass --data-dir $(realpath -m "$data") --api-config $(realpath -m "$cfg")/model-api.toml --embedding-profile embed --rerank-profile rerank " "$u/cass-mcp.service"
      grep -qx "EnvironmentFile=$(realpath -m "$cfg")/model-api.env" "$u/cass-mcp.service"
      [ "$(mutating_calls)" = "$(printf '%s\n' '--user daemon-reload' '--user restart cass-mcp.service' '--user enable cass-mcp.service')" ]
      # The switch script ran without XDG_CONFIG_HOME: every systemctl call says unset.
      [ "$(grep -c ' XDG=unset$' "$dir/systemctl.log")" -eq "$(wc -l < "$dir/systemctl.log")" ]
      [ ! -e "$dir/xdg-trap" ]
      grep -q "^MCP_OK unit=$(realpath -m "$cfg")/cass-mcp.service backup=$u/cass-mcp.backup-" "$dir/install.log"
      [ "$(cat "$dir/tailscale.log")" = "serve --bg --https=18777 http://$BIND" ]
      # Order: MCP, then the first round, then tailnet.
      [ "$(cat "$dir/sequence")" = "$(printf '%s\n' systemctl-restart first-round tailscale)" ]
      grep -q '^SELF_CHECK_OK$' "$dir/install.log"
      grep -q '^DEPLOY_COMPLETE instance=alpha mcp=install first_round=ok tailnet=on$' "$dir/install.log"
      # R1: SCHEDULE_READY is the line right before DEPLOY_COMPLETE, after every step.
      [ "$(tail -n 2 "$dir/install.log" | head -n 1)" = "SCHEDULE_READY instance=alpha entry=$(realpath -m "$cfg")/cass-ingest-entry" ]
      cp -- "$dir/install.log" "$dir/install-first.log"
      local e1 n1; e1=$(sha256sum < "$cfg/cass-ingest-entry"); n1=$(sha256sum < "$cfg/cass-mcp.service")
      expect_rc 0 "${mcp_args[@]}" --tailnet-serve; check_deployed
      [ "$(sha256sum < "$cfg/cass-ingest-entry")" = "$e1" ]; [ "$(sha256sum < "$cfg/cass-mcp.service")" = "$n1" ]
      [ "$(sha256sum < "$u/cass-mcp.service")" = "$n1" ]
      [ "$(sort -u "$dir/tailscale.log")" = "serve --bg --https=18777 http://$BIND" ]; [ "$(wc -l < "$dir/tailscale.log")" -eq 2 ]
      if [ -n "${DEPLOY_TEST_EVIDENCE:-}" ]; then
        mkdir -p "$DEPLOY_TEST_EVIDENCE"
        cp -- "$dir/install-first.log" "$DEPLOY_TEST_EVIDENCE/mcp-install-first.log"
        cp -- "$dir/install.log" "$DEPLOY_TEST_EVIDENCE/mcp-install-rerun.log"
        cp -- "$cfg/cass-mcp.service" "$cfg/cass-ingest-entry" "$dir/systemctl.log" "$dir/tailscale.log" "$DEPLOY_TEST_EVIDENCE/"
      fi ;;
    t10-mcp-install-no-tailnet)
      # AC5: without --tailnet-serve tailscale is never called; --skip-first-round runs no entry.
      install_mcp_fakes; install_first_round_fakes ok; first_round=skip
      expect_rc 0 "${mcp_args[@]}"; check_deployed
      [ ! -e "$dir/tailscale.log" ]; [ ! -e "$dir/entry-calls" ]
      grep -q '^FIRST_ROUND_SKIPPED$' "$dir/install.log"
      absent '^SCHEDULE_READY' "$dir/install.log"
      grep -q '^DEPLOY_COMPLETE instance=alpha mcp=install first_round=skipped tailnet=off$' "$dir/install.log" ;;
    t10-first-round)
      # AC3 and AC7.
      install_first_round_fakes ok
      expect_rc 0; check_deployed
      local entry; entry="$(realpath -m "$cfg")/cass-ingest-entry"
      grep -qx "SCHEDULE_READY instance=alpha entry=$entry" "$dir/install.log"
      grep -q '^FIRST_ROUND {"schema":"cass.ingest-entry.v1","instance":"alpha","classification":"ok",' "$dir/install.log"
      grep -q '^fake cass stderr line$' "$dir/install.log"
      [ "$(wc -l < "$dir/entry-calls")" -eq 1 ]
      # The injected copy differs from the rendered entry only in its CASS_BIN line.
      [ "$(diff "$cfg/cass-ingest-entry" "$dir/entry-under-test" | grep -c '^[<>]')" -eq 2 ]
      # AC7: the key seen by cass equals the env file value byte for byte.
      printf '%s' "$KEY_VALUE" | cmp -- - "$dir/fake-cass-key"
      sed -n "s/^$KEY_ENV=//p" "$cfg/model-api.env" | head -c -1 | cmp -- - "$dir/fake-cass-key"
      [ "$(tr '\0' ' ' < "$dir/fake-cass-argv")" = "sync --json --no-mirror --data-dir $(realpath -m "$data") --api-config $(realpath -m "$cfg")/model-api.toml " ]
      grep -qx "XDG_CONFIG_HOME=$(realpath -m "$cfg")" "$dir/fake-cass-env"
      local mode want
      local ek
      for mode in warning:5:null skipped:5:index-busy failed:4: unknown:4: nonjson:4:; do
        IFS=: read -r mode want ek <<< "$mode"
        printf '%s\n' "$mode" > "$dir/first-round-mode"
        expect_rc "$want"
        absent '^SCHEDULE_READY' "$dir/install.log"
        absent '^DEPLOY_COMPLETE' "$dir/install.log"
        if [ "$want" = 5 ]; then
          # R3: the error kind and the hint to check endpoints or use --skip-first-round.
          grep -qx "FIRST_ROUND_INCOMPLETE classification=$mode error_kind=$ek" "$dir/install.log"
          grep -q '^FAIL\[install\]: first round incomplete.*model endpoints.*--skip-first-round' "$dir/install.log"
        else grep -q '^FAIL\[install\]: first round' "$dir/install.log"; fi
      done
      # R5: output that is not a result line is echoed (first 2000 bytes) before exit 4.
      grep -q '^FAIL\[install\]: entry stdout (first 2000 bytes):$' "$dir/install.log"
      grep -qx 'this is not json' "$dir/install.log"
      printf 'nonjson-long\n' > "$dir/first-round-mode"
      expect_rc 4
      [ "$(grep -o 'yyyy*' "$dir/install.log" | awk '{ print length }' | sort -n | tail -n 1)" -eq 2000 ]
      local calls; calls=$(wc -l < "$dir/entry-calls")
      first_round=skip; expect_rc 0
      [ "$(wc -l < "$dir/entry-calls")" -eq "$calls" ]
      absent '^SCHEDULE_READY' "$dir/install.log" ;;
    t10-ssh-entry)
      # AC4: the restricted line; authorized_keys is never read or written.
      mkdir -p "$dir/home/.ssh"; printf 'ssh-ed25519 AAAAexisting other\n' > "$dir/home/.ssh/authorized_keys"
      local ak1; ak1=$(tree_hash "$dir/home/.ssh")
      local pub="$dir/id.pub" bad
      for bad in 'ssh-dss AAAAB3NzaC1kc3M= x' 'ssh-ed25519' '-----BEGIN OPENSSH PRIVATE KEY-----' \
        'ssh-ed25519 AAAA"C3Nz' 'command="x" ssh-ed25519 AAAAC3Nz' 'ssh-ed25519 AAAA!bad' ''; do
        printf '%s\n' "$bad" > "$pub"
        expect_rc 2 --ssh-authorized-key "$pub" --ssh-from 100.64.0.0/10
      done
      printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOsynthetic+key/0123456789abcdef jarvis@host\nsecond line\n' > "$pub"
      expect_rc 2 --ssh-authorized-key "$pub"
      expect_rc 2 --ssh-from 100.64.0.0/10
      expect_rc 2 --ssh-authorized-key relative.pub --ssh-from 100.64.0.0/10
      expect_rc 2 --ssh-authorized-key "$pub" --ssh-from '1.2.3.4" x'
      nothing_written
      install_first_round_fakes ok
      expect_rc 0 --ssh-authorized-key "$pub" --ssh-from 100.64.0.0/10; check_deployed
      grep -qxF "AUTHORIZED_KEY restrict,from=\"100.64.0.0/10\",command=\"$(realpath -m "$cfg")/cass-ingest-entry\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOsynthetic+key/0123456789abcdef" "$dir/install.log"
      [ "$(grep -c '^AUTHORIZED_KEY ' "$dir/install.log")" -eq 1 ]
      if [ -n "${DEPLOY_TEST_EVIDENCE:-}" ]; then
        mkdir -p "$DEPLOY_TEST_EVIDENCE"; cp -- "$dir/install.log" "$DEPLOY_TEST_EVIDENCE/ssh-entry.log"
      fi
      [ "$(tree_hash "$dir/home/.ssh")" = "$ak1" ]
      printf 'ecdsa-sha2-nistp256 AAAAE2VjZHNh\n' > "$pub"
      expect_rc 0 --ssh-authorized-key "$pub" --ssh-from 192.168.1.20
      grep -qxF "AUTHORIZED_KEY restrict,from=\"192.168.1.20\",command=\"$(realpath -m "$cfg")/cass-ingest-entry\" ecdsa-sha2-nistp256 AAAAE2VjZHNh" "$dir/install.log"
      [ "$(tree_hash "$dir/home/.ssh")" = "$ak1" ] ;;
    t10-render-unsafe)
      # AC6: a placeholder value with a quote, a newline or @@ stops before any write.
      local v
      for v in "$dir/da'ta" "$dir/d@@ta" "$dir/da"$'\n'"ta"; do
        data=$v; expect_rc 2; grep -q '^FAIL\[install\]: ' "$dir/install.log"; nothing_written
      done
      data="$dir/da'ta"; expect_rc 2; grep -q 'placeholder value' "$dir/install.log"
      data="$dir/d@@ta"; expect_rc 2; grep -q 'placeholder value' "$dir/install.log"
      data="$dir/data"
      for v in "al'pha" 'al@@pha' $'al\npha'; do
        inst=$v; expect_rc 2; nothing_written
      done
      inst=alpha
      cfg="$dir/c@@fg"; expect_rc 2; nothing_written; cfg="$dir/cfg"
      prefix="$dir/pre'fix"; expect_rc 2; [ ! -e "$prefix" ]; prefix="$dir/prefix"
      install_mcp_fakes
      expect_rc 2 --mcp-bind "$BIND" --public-origin "https://a'b.example"; nothing_written
      expect_rc 2 --mcp-bind "$BIND" --public-origin 'https://a@@b.example'; nothing_written
      # A systemd unit value must not contain whitespace or % specifiers either.
      data="$dir/da ta"; expect_rc 2 "${mcp_args[@]}"; nothing_written
      data="$dir/da%hta"; expect_rc 2 "${mcp_args[@]}"; nothing_written; data="$dir/data"
      [ ! -e "$dir/systemctl.log" ]
      [ -z "$(find "$dir" -mindepth 1 -maxdepth 1 \( -name 'd*ta*' -o -name 'c*fg' \))" ]
      # Positive control: the same arguments with safe values succeed.
      mcp=none; xenv=(); expect_rc 0 ;;
    t10-bad-arguments)
      expect_rc 2 --mcp none --mcp none
      mcp=""; expect_rc 2
      mcp=bogus; expect_rc 2
      mcp=install; expect_rc 2 --public-origin "$ORIGIN"
      expect_rc 2 --mcp-bind "$BIND"
      expect_rc 2 --mcp-bind 0.0.0.0:18777 --public-origin "$ORIGIN"
      expect_rc 2 --mcp-bind 127.0.0.1:99999 --public-origin "$ORIGIN"
      expect_rc 2 --mcp-bind "$BIND" --public-origin http://alien.example.ts.net
      expect_rc 2 --mcp-bind "$BIND" --public-origin https://alien.example.ts.net/path
      mcp=none
      expect_rc 2 --tailnet-serve
      expect_rc 2 --mcp-bind "$BIND"
      expect_rc 2 --public-origin "$ORIGIN"
      expect_rc 2 --skip-first-round
      nothing_written
      # Positive control: valid T10 arguments are accepted.
      expect_rc 0
      # Without --deploy the new flags stay unknown (exit 1).
      local rc=0
      env -i HOME="$dir/home" PATH="$path" bash "$BUNDLE/install.sh" --prefix "$prefix" --mcp none > "$dir/install.log" 2>&1 || rc=$?
      [ "$rc" -eq 1 ] ;;
    t10-mcp-switch-fails)
      # The switch script rolls back and exits 1: the installer exits 6 with its stderr.
      install_mcp_fakes; install_first_round_fakes ok; touch "$dir/initialize-fails"
      xenv[3]=CASS_MCP_SWITCH_WAIT_SECONDS=1
      expect_rc 6 "${mcp_args[@]}"
      grep -q '^cass-mcp-switch: self-check failed: ' "$dir/install.log"
      grep -q '^FAIL\[install\]: ' "$dir/install.log"
      [ ! -e "$dir/entry-calls" ]
      absent '^SCHEDULE_READY' "$dir/install.log"
      [ ! -e "$dir/home/.config/systemd/user/cass-mcp.service" ] ;;
    t10-tailnet-fails)
      install_mcp_fakes; install_first_round_fakes ok; touch "$dir/tailscale-fails"
      expect_rc 7 "${mcp_args[@]}" --tailnet-serve
      # R1: the first round was ok, but a later step failed: no SCHEDULE_READY.
      grep -q '^FIRST_ROUND {"schema":"cass.ingest-entry.v1","instance":"alpha","classification":"ok",' "$dir/install.log"
      absent '^SCHEDULE_READY' "$dir/install.log"
      absent '^DEPLOY_COMPLETE' "$dir/install.log" ;;
    t10-self-check-fails)
      # Each variant breaks one self-check input; the first round is ok every time.
      install_first_round_fakes ok
      local variant
      for variant in ldd-onnx ldd-exit strings-hit; do
        rm -f "$dir/tools/ldd" "$dir/tools/strings"
        case "$variant" in
          ldd-onnx) # ldd reports an ONNX Runtime library for cass.
            cat > "$dir/tools/ldd" <<'SH'
#!/usr/bin/env bash
/usr/bin/ldd "$@" || exit
case "${!#}" in */current/cass) printf '\tlibonnxruntime.so.1 => /opt/x/libonnxruntime.so.1 (0x0)\n' ;; esac
SH
            ;;
          ldd-exit) # ldd itself fails for cass-mcp, without any onnx line.
            cat > "$dir/tools/ldd" <<'SH'
#!/usr/bin/env bash
case "${!#}" in */current/cass-mcp) echo 'ldd: simulated failure' >&2; exit 1 ;; esac
exec /usr/bin/ldd "$@"
SH
            ;;
          strings-hit) # strings of cass contains an onnxruntime symbol.
            cat > "$dir/tools/strings" <<'SH'
#!/usr/bin/env bash
/usr/bin/strings "$@" || exit
case "${!#}" in */current/cass) echo 'OrtGetApiBase onnxruntime_c_api' ;; esac
SH
            ;;
        esac
        chmod +x "$dir/tools/"{ldd,strings} 2>/dev/null || true
        expect_rc 8
        grep -q '^FAIL\[install\]: self-check' "$dir/install.log"
        grep -q '^FIRST_ROUND {"schema":"cass.ingest-entry.v1","instance":"alpha","classification":"ok",' "$dir/install.log"
        absent '^SCHEDULE_READY' "$dir/install.log"
        absent '^DEPLOY_COMPLETE' "$dir/install.log"
      done
      case "$(grep '^FAIL\[install\]: self-check' "$dir/all-output.log" | tr '\n' '|')" in
        *'links an ONNX Runtime library'*'ldd failed for'*'onnxruntime/ort_sys strings'*) ;;
        *) echo 'self-check variants did not fail for their own reasons'; return 1 ;;
      esac ;;
    t10-range-checks)
      # R4: address, prefix and port ranges; each refusal writes nothing.
      printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 x\n' > "$dir/id.pub"
      local from
      for from in 256.1.1.1 1.2.3.999 1.2.3.4/33 10.0.0.0/99 fe80:1 2001:db8::/129 '::/200' 1.2.3.4/-1; do
        expect_rc 2 --ssh-authorized-key "$dir/id.pub" --ssh-from "$from"
        grep -q 'ssh-from' "$dir/install.log"
        nothing_written
      done
      mcp=install
      local origin
      for origin in https://alien.example.ts.net:65536 https://alien.example.ts.net:99999 https://alien.example.ts.net:0; do
        expect_rc 2 --mcp-bind "$BIND" --public-origin "$origin"
        grep -q 'public-origin' "$dir/install.log"
        nothing_written
      done
      mcp=none
      # Boundary values that are valid.
      for from in 0.0.0.0/0 255.255.255.255/32 ::1 2001:db8::/128 fe80::1/0; do
        expect_rc 0 --ssh-authorized-key "$dir/id.pub" --ssh-from "$from"
        grep -qF "AUTHORIZED_KEY restrict,from=\"$from\",command=" "$dir/install.log"
      done ;;
    t10-entry-template-unknown)
      # R2: an unknown placeholder left after rendering exits 1; current keeps its target.
      bundle=$BAD_BUNDLE
      mkdir "$prefix/old-version"; ln -s old-version "$prefix/current"
      expect_rc 1
      grep -q '^FAIL\[install\]: rendered template still contains @@UNKNOWN@@' "$dir/install.log"
      [ "$(readlink "$prefix/current")" = old-version ]
      [ ! -e "$cfg/cass-ingest-entry" ]
      [ -z "$(find "$cfg" -name '.cass-install-stage.*')" ]
      absent '^DEPLOY_OK' "$dir/install.log" ;;
    t10-ssh-command-path)
      # R2: the command= path must not need quoting; the same path is fine without ssh.
      printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 x\n' > "$dir/id.pub"
      cfg="$dir/c fg"
      expect_rc 2 --ssh-authorized-key "$dir/id.pub" --ssh-from 100.64.0.0/10
      grep -q 'authorized_keys command' "$dir/install.log"
      nothing_written
      expect_rc 0
      [ -f "$cfg/cass-ingest-entry" ] ;;
    *) exit 2 ;;
  esac
  [ "$(home_cfg_hash)" = "$before" ]
  no_secret
  [ ! -e "$dir/tools/unexpected-tool-calls" ]
)

CASES='fresh-absent fresh-empty same-instance-rerun foreign-nonempty foreign-other-instance foreign-file
  fail-key-missing fail-remote-http fail-remote-http-fresh fail-version-mismatch fail-version-mismatch-fresh
  fail-config-move home-config-rejected onboarding-real loopback-scopes env-format bad-key-values
  bad-arguments publish-only-unchanged
  data-parent-readonly connectors-forged-dash connectors-forged-upper term-at-stage term-at-marker
  endpoint-bad-port overlapping-dirs config-foreign-instance config-foreign-nonempty config-cass-symlink
  t10-mcp-none t10-mcp-install t10-mcp-install-no-tailnet t10-first-round t10-ssh-entry t10-render-unsafe
  t10-bad-arguments t10-mcp-switch-fails t10-tailnet-fails t10-self-check-fails
  t10-entry-template-unknown t10-ssh-command-path t10-range-checks'
for kind in $CASES; do
  set +e
  one_case "$kind" > "$SANDBOX/$kind.log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then PASS=$((PASS+1)); printf 'PASS %s\n' "$kind"
  else FAIL=$((FAIL+1)); printf 'FAIL %s: %s\n' "$kind" "$SANDBOX/$kind.log"; fi
done
printf 'TEST_SUMMARY total=%s pass=%s fail=%s\n' "$((PASS+FAIL))" "$PASS" "$FAIL"
if [ "$FAIL" -eq 0 ]; then rm -rf -- "$SANDBOX"; exit 0; fi
printf 'sandbox kept: %s\n' "$SANDBOX"
exit 1
