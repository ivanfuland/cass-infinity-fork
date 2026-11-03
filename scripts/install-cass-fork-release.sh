#!/usr/bin/env bash
# Shipped as install.sh in a native Linux release (format 2). No build tools or network.
# Format 2 adds templates/: regular files and directories, all listed in SHA256SUMS.
set -euo pipefail
export LC_ALL=C

die() { printf 'FAIL[install]: %s\n' "$*" >&2; exit 1; }
usage() { printf 'Usage: bash install.sh --prefix /absolute/version-root\n'; }
# Full deployment (--deploy) exit codes: 0 success, 1 general failure,
# 2 invalid argument, 3 data directory belongs to something else.
die_arg() { printf 'FAIL[install]: %s\n' "$*" >&2; exit 2; }
deploy_usage() {
  printf '%s\n' 'Usage: bash install.sh --prefix /abs/version-root --deploy --instance NAME' \
    '         --data-dir /abs --config-dir /abs' \
    '         --embed-endpoint URL --embed-model NAME --embed-revision REV' \
    '         --rerank-endpoint URL --rerank-model NAME --rerank-revision REV' \
    '         --key-env NAME --key-file /abs [--legacy-source /abs]'
}
DEPLOY=0
for arg in "$@"; do [ "$arg" != --deploy ] || DEPLOY=1; done
PREFIX=""
declare -A OPT=()
if [ "$DEPLOY" -eq 0 ]; then
  # Publish-only mode: unchanged interface and exit codes.
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h) usage; exit 0 ;;
      --prefix)
        [ "$#" -ge 2 ] && [ -z "$PREFIX" ] || die '--prefix requires one value'
        PREFIX="$2"; shift 2 ;;
      *) usage >&2; die "unknown argument: $1" ;;
    esac
  done
else
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h) deploy_usage; exit 0 ;;
      --deploy) shift ;;
      --prefix|--instance|--data-dir|--config-dir|--embed-endpoint|--embed-model|--embed-revision|\
      --rerank-endpoint|--rerank-model|--rerank-revision|--key-env|--key-file|--legacy-source)
        [ "$#" -ge 2 ] || die_arg "$1 requires one value"
        [ -z "${OPT[${1#--}]+present}" ] || die_arg "$1 given more than once"
        OPT[${1#--}]=$2; shift 2 ;;
      *) deploy_usage >&2; die_arg "unknown argument: $1" ;;
    esac
  done
  for name in prefix instance data-dir config-dir embed-endpoint embed-model embed-revision \
    rerank-endpoint rerank-model rerank-revision key-env key-file; do
    [ -n "${OPT[$name]+present}" ] || die_arg "--$name is required with --deploy"
  done
  PREFIX=${OPT[prefix]}
fi

# ---------------------------------------------------------------------------
# Full deployment: argument and key validation. Nothing is written here.
# ---------------------------------------------------------------------------
# A value that is written into a TOML basic string: no quote, backslash or
# control character, so it needs no escaping.
toml_safe() {
  local re='[[:cntrl:]"\\]'
  [ -n "$2" ] && ! [[ $2 =~ $re ]] || die_arg "$1 must be non-empty without quotes, backslashes or control characters"
}
abs_path() {
  toml_safe "$1" "$2"
  case "$2" in /*) ;; *) die_arg "$1 must be an absolute path" ;; esac
}
# endpoint_scope <flag> <url>: prints loopback or remote. Remote requires https.
endpoint_scope() {
  local flag=$1 url=$2 scheme rest auth host
  toml_safe "$flag" "$url"
  case "$url" in
    http://*) scheme=http; rest=${url#http://} ;;
    https://*) scheme=https; rest=${url#https://} ;;
    *) die_arg "$flag must be an http or https URL" ;;
  esac
  auth=${rest%%[/?#]*}
  [ -n "$auth" ] || die_arg "$flag has no host"
  case "$auth" in *@*) die_arg "$flag must not contain user information" ;; esac
  case "$auth" in '['*) host=${auth%%]*}] ;; *) host=${auth%%:*} ;; esac
  host=${host,,}
  case "$host" in
    127.0.0.1|'[::1]'|localhost) printf loopback ;;
    *) [ "$scheme" = https ] || die_arg "$flag: a remote endpoint must use https"
       printf remote ;;
  esac
}
# Reads --key-file into KEY_VALUE. The value itself is never printed.
read_key() {
  local file=$1 bad='[[:space:][:cntrl:]"'"'"'\\]'
  [ -f "$file" ] && [ -r "$file" ] || die_arg '--key-file is not a readable regular file'
  tr -d '\000' < "$file" | cmp -s -- - "$file" || die_arg 'key file contains a NUL byte'
  KEY_VALUE=$(cat -- "$file" && printf x) || die_arg 'cannot read --key-file'
  KEY_VALUE=${KEY_VALUE%x}; KEY_VALUE=${KEY_VALUE%$'\n'}
  [ -n "$KEY_VALUE" ] || die_arg 'key file is empty'
  ! [[ $KEY_VALUE =~ $bad ]] || die_arg 'key value contains a quote, whitespace, backslash or control character'
}
if [ "$DEPLOY" -eq 1 ]; then
  abs_path --prefix "$PREFIX"
  INSTANCE=${OPT[instance]}
  [[ $INSTANCE =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || die_arg '--instance must match [a-z0-9][a-z0-9-]{0,31}'
  DATA_DIR=${OPT[data-dir]}; abs_path --data-dir "$DATA_DIR"
  CONFIG_DIR=${OPT[config-dir]}; abs_path --config-dir "$CONFIG_DIR"
  KEY_FILE=${OPT[key-file]}; abs_path --key-file "$KEY_FILE"
  KEY_ENV=${OPT[key-env]}
  [[ $KEY_ENV =~ ^[A-Z_][A-Z0-9_]*$ ]] || die_arg '--key-env must be an upper-case variable name'
  # The ingest entry reserves these names and would ignore them in the env file.
  case "$KEY_ENV" in
    CASS_BIN|DATA_DIR|API_CONFIG|ENV_FILE|CONFIG_HOME|INSTANCE|PATH|TMPDIR|HOME|XDG_CONFIG_HOME)
      die_arg "--key-env is a reserved name: $KEY_ENV" ;;
  esac
  for name in embed-model embed-revision rerank-model rerank-revision; do toml_safe "--$name" "${OPT[$name]}"; done
  EMBED_SCOPE=$(endpoint_scope --embed-endpoint "${OPT[embed-endpoint]}")
  RERANK_SCOPE=$(endpoint_scope --rerank-endpoint "${OPT[rerank-endpoint]}")
  LEGACY=${OPT[legacy-source]:-}
  if [ -n "${OPT[legacy-source]+present}" ]; then
    abs_path --legacy-source "$LEGACY"
    LEGACY=${LEGACY%/}; LEGACY_NAME=${LEGACY##*/}
    [[ $LEGACY_NAME =~ ^[A-Za-z0-9._-]{1,64}$ ]] && [ "$LEGACY_NAME" != . ] && [ "$LEGACY_NAME" != .. ] \
      && [ "${LEGACY_NAME,,}" != local ] || die_arg '--legacy-source basename must match [A-Za-z0-9._-]{1,64} and not be "local"'
  fi
  # The production configuration under ~/.config/cass is never read or written.
  case "${HOME:-}" in /*) ;; *) die_arg 'HOME must be an absolute path' ;; esac
  home_config=$(realpath -m -- "$HOME/.config") || die_arg 'cannot resolve $HOME/.config'
  home_cass=$(realpath -m -- "$HOME/.config/cass") || die_arg 'cannot resolve $HOME/.config/cass'
  own=$(realpath -m -- "$CONFIG_DIR") || die_arg 'cannot resolve --config-dir'
  own_cass=$(realpath -m -- "$CONFIG_DIR/cass") || die_arg 'cannot resolve --config-dir'
  case "$own/" in "$home_cass"/*) die_arg '--config-dir must not be inside $HOME/.config/cass' ;; esac
  [ "$own" != "$home_config" ] && [ "$own_cass" != "$home_cass" ] \
    || die_arg '--config-dir must not make <config-dir>/cass resolve to $HOME/.config/cass'
  [ ! -L "$CONFIG_DIR/cass" ] || die_arg '<config-dir>/cass must not be a symbolic link'
  # The version root, the data directory and the configuration directory are
  # three separate trees: none equals or contains another.
  real_prefix=$(realpath -m -- "$PREFIX") || die_arg 'cannot resolve --prefix'
  real_data=$(realpath -m -- "$DATA_DIR") || die_arg 'cannot resolve --data-dir'
  overlaps() { case "${1%/}/" in "${2%/}/"*) return 0 ;; esac; case "${2%/}/" in "${1%/}/"*) return 0 ;; esac; return 1; }
  ! overlaps "$real_data" "$own" || die_arg '--data-dir and --config-dir must not be equal or nested'
  ! overlaps "$real_data" "$real_prefix" || die_arg '--data-dir and --prefix must not be equal or nested'
  ! overlaps "$own" "$real_prefix" || die_arg '--config-dir and --prefix must not be equal or nested'
  read_key "$KEY_FILE"

  # Ownership of the data and configuration directories. Absent or empty: this
  # run claims it. This instance's marker: continue. Anything else is refused
  # with exit 3 before any file is written or any mode is changed.
  MARKER=.cass-install-instance
  dir_state() {
    local dir=$1 first
    if [ ! -e "$dir" ] && [ ! -L "$dir" ]; then printf absent; return; fi
    [ -d "$dir" ] || { printf foreign; return; }
    first=$(find "$dir" -mindepth 1 -maxdepth 1 -print -quit) || die "cannot read directory: $dir"
    if [ -z "$first" ]; then printf empty
    elif [ -f "$dir/$MARKER" ] && [ ! -L "$dir/$MARKER" ] \
      && printf '%s\n' "$INSTANCE" | cmp -s -- - "$dir/$MARKER"; then printf own
    else printf foreign; fi
  }
  DATA_STATE=$(dir_state "$DATA_DIR") || exit 1
  CONFIG_STATE=$(dir_state "$CONFIG_DIR") || exit 1
  if [ "$DATA_STATE" = foreign ]; then
    printf 'FAIL[install]: %s\n' "data directory is not empty and is not instance $INSTANCE; nothing changed: $DATA_DIR" >&2
    exit 3
  fi
  if [ "$CONFIG_STATE" = foreign ]; then
    printf 'FAIL[install]: %s\n' "configuration directory is not empty and is not instance $INSTANCE; nothing changed: $CONFIG_DIR" >&2
    exit 3
  fi
fi
case "$PREFIX" in /*) ;; *) die '--prefix must be an absolute directory' ;; esac
BUNDLE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
FIXED=(cass cass-mcp install.sh release.env)
for name in "${FIXED[@]}" SHA256SUMS; do
  [ -f "$BUNDLE/$name" ] && [ ! -L "$BUNDLE/$name" ] || die "not a regular bundle file: $name"
done
[ -d "$BUNDLE/templates" ] && [ ! -L "$BUNDLE/templates" ] || die 'missing templates directory'

# list_tree <root> <array-name>: regular files below root, relative and NUL-safe.
# Only the five members and templates/ may exist; templates/ holds only regular
# files and directories. Every other type, including symlinks, is rejected.
list_tree() {
  local root=$1 entry type rel
  local -n out=$2
  local -a entries
  out=()
  mapfile -d '' -t entries < <(find "$root" -mindepth 1 -printf '%y %P\0')
  wait "$!" || die "cannot list bundle files: $root"
  for entry in "${entries[@]}"; do
    type=${entry%% *}; rel=${entry#* }
    case "$type" in
      f) out+=("$rel") ;;
      d) case "$rel" in templates|templates/*) ;; *) die "unexpected bundle directory: $rel" ;; esac ;;
      *) die "not a regular bundle file: $rel" ;;
    esac
  done
}
# A listed path is one fixed member or templates/<segments>, never absolute,
# empty, "." or ".." segments, backslashes or the checksum list itself.
safe_path() {
  local rel=$1 seg
  local -a segs
  case "$rel" in cass|cass-mcp|install.sh|release.env) return 0 ;; templates/?*) ;; *) return 1 ;; esac
  case "$rel" in *'\'*|*//*|*/) return 1 ;; esac
  IFS=/ read -r -a segs <<< "$rel"
  for seg in "${segs[@]}"; do
    case "$seg" in ''|.|..) return 1 ;; esac
  done
}

digest() { local value; value=$(sha256sum -- "$1") || die "cannot hash $1"; printf '%s' "${value%% *}"; }
declare -A HASHES=()
while IFS= read -r line || [ -n "$line" ]; do
  [[ "$line" =~ ^([0-9a-f]{64})\ \ (.+)$ ]] || die 'invalid SHA256SUMS line'
  hash=${BASH_REMATCH[1]}; name=${BASH_REMATCH[2]}
  safe_path "$name" || die "unsafe checksum path: $name"
  [ -z "${HASHES[$name]+present}" ] || die "duplicate checksum: $name"
  HASHES[$name]="$hash"
done < "$BUNDLE/SHA256SUMS"
# The listed paths must equal the bundle's regular files minus SHA256SUMS.
check_members() {
  local root=$1 rel
  local -a found
  local -A seen=()
  list_tree "$root" found
  for rel in "${found[@]}"; do
    [ "$rel" = SHA256SUMS ] && continue
    [ -n "${HASHES[$rel]+present}" ] || die "checksum list does not match bundle files: unlisted $rel"
    seen[$rel]=1
  done
  for rel in "${!HASHES[@]}"; do
    [ -n "${seen[$rel]+present}" ] || die "checksum list does not match bundle files: missing $rel"
  done
}
check_members "$BUNDLE"
for name in "${!HASHES[@]}"; do
  [ "$(digest "$BUNDLE/$name")" = "${HASHES[$name]}" ] || die "checksum mismatch: $name"
done
SUMS_SHA=$(digest "$BUNDLE/SHA256SUMS")

# Parse data, never shell code. Validate keys before using array subscripts.
declare -A META=()
while IFS='=' read -r key value || [ -n "$key$value" ]; do
  case "$key" in
    format|source_commit|platform|cass_version|mcp_version|glibc_min) ;;
    *) die "unknown release metadata key: $key" ;;
  esac
  [ -z "${META[$key]+present}" ] || die "duplicate release metadata: $key"
  META[$key]="$value"
done < "$BUNDLE/release.env"
[ "${#META[@]}" -eq 6 ] || die 'missing release metadata'
[ "${META[format]}" = 'cass-fork-release/2' ] || die 'unsupported release format'
[[ "${META[source_commit]}" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || die 'invalid source commit'
[ "${META[platform]}" = 'linux-x86_64' ] || die 'unsupported release platform'
for key in cass_version mcp_version; do
  [[ "${META[$key]}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+-][A-Za-z0-9._-]+)?$ ]] || die "invalid version: $key"
done
[[ "${META[glibc_min]}" =~ ^[0-9]+(\.[0-9]+)+$ ]] || die 'invalid glibc requirement'
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || die 'this bundle requires Linux x86-64'
glibc=$(getconf GNU_LIBC_VERSION) || die 'GNU libc is required'
case "$glibc" in 'glibc '*) glibc=${glibc#glibc } ;; *) die 'cannot identify GNU libc' ;; esac
[[ "$glibc" =~ ^[0-9]+(\.[0-9]+)+$ ]] || die 'cannot parse GNU libc version'
lowest=$(printf '%s\n%s\n' "${META[glibc_min]}" "$glibc" | LC_ALL=C sort -V | head -n 1)
[ "$lowest" = "${META[glibc_min]}" ] || die "requires glibc >= ${META[glibc_min]}; found $glibc"
for name in cass cass-mcp; do
  [ -x "$BUNDLE/$name" ] || die "not executable: $name"
  links=$(ldd "$BUNDLE/$name" 2>&1) || die "cannot resolve runtime libraries: $name"
  if printf '%s\n' "$links" | grep -q 'not found'; then die "missing runtime library: $name"; fi
  version=$("$BUNDLE/$name" --version) || die "cannot run $name --version"
  key=cass_version; [ "$name" != cass-mcp ] || key=mcp_version
  [ "$version" = "$name ${META[$key]}" ] || die "version mismatch: $name"
done

if [ "$DEPLOY" -eq 1 ]; then
  [ ! -e "$PREFIX/current" ] || [ -L "$PREFIX/current" ] || die "current exists and is not a symbolic link: $PREFIX/current"
  # disabled_agents: every connector of this binary except the three kept ones.
  # The bundle binary is verified above and is byte-identical to the published
  # one, so this runs before anything is written. Every non-empty line of the
  # list must be one name matching [a-z0-9_]; anything else is refused.
  caps=$(env -i PATH=/usr/bin:/bin HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent "$BUNDLE/cass" capabilities --json 2> /dev/null) \
    || die "cannot read the connector list of $BUNDLE/cass"
  block=$(printf '%s\n' "$caps" | sed -n '/^  "connectors": \[/,/^  \]/{/^  "connectors": \[/d;/^  \]/d;p}')
  lines=$(printf '%s\n' "$block" | grep -c '[^[:space:]]' || true)
  mapfile -t CONNECTORS < <(printf '%s\n' "$block" | sed -n 's/^    "\([a-z0-9_]*\)",\{0,1\}$/\1/p')
  [ "$lines" -eq "${#CONNECTORS[@]}" ] \
    || die "connector list of $BUNDLE/cass has $lines entries but only ${#CONNECTORS[@]} valid names"
  mapfile -t CONNECTORS < <(printf '%s\n' "${CONNECTORS[@]}" | LC_ALL=C sort -u)
  declare -A KEEP=([claude_code]=0 [codex]=0 [pi_agent]=0)
  DISABLED=()
  for name in "${CONNECTORS[@]}"; do
    if [ -n "${KEEP[$name]+present}" ]; then KEEP[$name]=1; else DISABLED+=("$name"); fi
  done
  for name in "${!KEEP[@]}"; do
    [ "${KEEP[$name]}" -eq 1 ] || die "connector list of $BUNDLE/cass lacks $name"
  done
  [ "${#DISABLED[@]}" -gt 0 ] || die "connector list of $BUNDLE/cass is empty"
fi

[ ! -e "$PREFIX" ] || [ -d "$PREFIX" ] || die 'installation root is not a directory'
[ ! -L "$PREFIX" ] || [ -d "$PREFIX" ] || die 'installation root is a dangling symlink'
mkdir -p -- "$PREFIX"
PREFIX=$(cd -- "$PREFIX" && pwd -P)
ID="cass-fork-${META[source_commit]}-${META[platform]}"
DEST="$PREFIX/$ID"
STAGE=""; CFG_STAGE=""; TMP_LINK=""; TMP_MARKER=""
on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ -n "$STAGE" ] && [ -d "$STAGE" ]; then printf 'Unpublished stage retained: %s\n' "$STAGE" >&2; fi
  # Deployment temporaries are never left behind, on success or failure.
  if [ -n "$CFG_STAGE" ]; then rm -rf -- "$CFG_STAGE"; fi
  if [ -n "$TMP_LINK" ] && [ -L "$TMP_LINK" ]; then rm -f -- "$TMP_LINK"; fi
  if [ -n "$TMP_MARKER" ] && [ -f "$TMP_MARKER" ]; then rm -f -- "$TMP_MARKER"; fi
}
trap on_exit EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
PUBLISH=1
if [ "$DEPLOY" -eq 1 ] && { [ -e "$DEST" ] || [ -L "$DEST" ]; }; then
  # An existing version counts as done only when it equals the bundle byte for byte.
  [ -d "$DEST" ] && [ ! -L "$DEST" ] || die "version directory differs from bundle; kept unchanged: $DEST"
  ( check_members "$DEST" ) > /dev/null 2>&1 || die "version directory differs from bundle; kept unchanged: $DEST"
  for name in "${!HASHES[@]}" SHA256SUMS; do
    cmp -s -- "$BUNDLE/$name" "$DEST/$name" || die "version directory differs from bundle; kept unchanged: $DEST"
  done
  PUBLISH=0
  printf 'VERSION_OK already installed install_dir=%s\n' "$DEST"
fi
if [ "$PUBLISH" -eq 1 ]; then
[ ! -e "$DEST" ] && [ ! -L "$DEST" ] || die "version already exists; kept unchanged: $DEST"
STAGE=$(mktemp -d "$PREFIX/.cass-release-stage.XXXXXX")
for name in "${FIXED[@]}" SHA256SUMS; do cp -p -- "$BUNDLE/$name" "$STAGE/$name"; done
cp -pR -- "$BUNDLE/templates" "$STAGE/templates"
check_members "$STAGE"
for name in "${!HASHES[@]}"; do
  [ "$(digest "$STAGE/$name")" = "${HASHES[$name]}" ] || die "staged checksum mismatch: $name"
done
[ "$(digest "$STAGE/SHA256SUMS")" = "$SUMS_SHA" ] || die 'staged checksum list changed'
# GNU mv -n can return zero when it skipped an existing destination.
mv -Tn -- "$STAGE" "$DEST" || die 'cannot publish version directory'
[ ! -e "$STAGE" ] && [ -d "$DEST" ] && [ ! -L "$DEST" ] || die 'version appeared concurrently; nothing overwritten'
printf 'INSTALL_OK source_commit=%s install_dir=%s\n' "${META[source_commit]}" "$DEST"
printf 'cass=%s/cass\ncass_mcp=%s/cass-mcp\n' "$DEST" "$DEST"
fi
[ "$DEPLOY" -eq 1 ] || exit 0

# ---------------------------------------------------------------------------
# Full deployment, after the version directory is complete.
# ---------------------------------------------------------------------------
# Run the published binary only against the staging directory: HOME and
# XDG_CONFIG_HOME both point inside it, so no user configuration is read.
staged_cass() { env -i PATH=/usr/bin:/bin HOME="$CFG_STAGE/home" XDG_CONFIG_HOME="$CFG_STAGE" "$DEST/cass" "$@"; }
umask 077
mkdir -p -- "$CONFIG_DIR" || die "cannot create configuration directory: $CONFIG_DIR"
chmod 700 -- "$CONFIG_DIR" || die "cannot set mode of $CONFIG_DIR"
# write_marker <dir>: the instance marker, by a temporary file and a rename.
write_marker() {
  TMP_MARKER=$(mktemp "$1/$MARKER.XXXXXX") || die "cannot write instance marker in $1"
  printf '%s\n' "$INSTANCE" > "$TMP_MARKER" || die "cannot write instance marker in $1"
  mv -T -- "$TMP_MARKER" "$1/$MARKER" || die "cannot write instance marker in $1"
  TMP_MARKER=""
}
CFG_STAGE=$(mktemp -d "$CONFIG_DIR/.cass-install-stage.XXXXXX") || die 'cannot create configuration stage'
mkdir -m 700 -- "$CFG_STAGE/cass" "$CFG_STAGE/home" || die 'cannot create configuration stage'

header="# Generated by install.sh --deploy for instance $INSTANCE. Rewritten on every deploy."
{
  printf '%s\ndisabled_agents = [\n' "$header"
  printf '  "%s",\n' "${DISABLED[@]}"
  printf ']\n'
  if [ -n "$LEGACY" ]; then
    printf '\n[[sources]]\nname = "%s"\ntype = "local"\norigin_host = "local"\nreadonly = true\npaths = ["%s/.claude/projects"]\n' \
      "$LEGACY_NAME" "$LEGACY"
  fi
} > "$CFG_STAGE/cass/sources.toml" || die 'cannot write sources.toml'
cat > "$CFG_STAGE/model-api.toml" <<EOF || die 'cannot write model-api.toml'
$header
version = 1
default_embedding = "embed"
default_rerank = "rerank"

[profiles.embed]
kind = "embedding"
protocol = "openai-embeddings-v1"
endpoint = "${OPT[embed-endpoint]}"
scope = "$EMBED_SCOPE"
model = "${OPT[embed-model]}"
model_revision = "${OPT[embed-revision]}"
api_key_env = "$KEY_ENV"
normalization = "l2"
timeout_ms = 125000

[profiles.rerank]
kind = "rerank"
protocol = "rerank-json-v1"
endpoint = "${OPT[rerank-endpoint]}"
scope = "$RERANK_SCOPE"
model = "${OPT[rerank-model]}"
model_revision = "${OPT[rerank-revision]}"
api_key_env = "$KEY_ENV"
timeout_ms = 125000
EOF
printf '%s=%s\n' "$KEY_ENV" "$KEY_VALUE" > "$CFG_STAGE/model-api.env" || die 'cannot write model-api.env'

# Both files must load in the published binary before anything is installed.
staged_cass sources list --json > /dev/null 2> "$CFG_STAGE/check.err" \
  || die "generated sources.toml rejected by $DEST/cass: $(head -c 2000 "$CFG_STAGE/check.err")"
staged_cass models list --api-config "$CFG_STAGE/model-api.toml" --json > /dev/null 2> "$CFG_STAGE/check.err" \
  || die "generated model-api.toml rejected by $DEST/cass: $(head -c 2000 "$CFG_STAGE/check.err")"

# Data directory: create it or claim it when empty; keep it when it is ours.
if [ "$DATA_STATE" != own ]; then
  if [ "$DATA_STATE" = absent ]; then
    mkdir -p -- "$(dirname -- "$DATA_DIR")" || die "cannot create parent of $DATA_DIR"
    mkdir -m 700 -- "$DATA_DIR" || die "cannot create data directory: $DATA_DIR"
  fi
  chmod 700 -- "$DATA_DIR" || die "cannot set mode of $DATA_DIR"
  write_marker "$DATA_DIR"
fi

# Install each configuration file by rename; an unchanged file is not touched.
[ "$CONFIG_STATE" = own ] || write_marker "$CONFIG_DIR"
mkdir -p -- "$CONFIG_DIR/cass" && chmod 700 -- "$CONFIG_DIR/cass" || die "cannot create $CONFIG_DIR/cass"
for rel in cass/sources.toml model-api.toml model-api.env; do
  if [ -f "$CONFIG_DIR/$rel" ] && [ ! -L "$CONFIG_DIR/$rel" ] && cmp -s -- "$CFG_STAGE/$rel" "$CONFIG_DIR/$rel" \
    && [ "$(stat -c %a -- "$CONFIG_DIR/$rel")" = 600 ]; then
    continue
  fi
  [ ! -d "$CONFIG_DIR/$rel" ] || die "configuration path is a directory: $CONFIG_DIR/$rel"
  chmod 600 -- "$CFG_STAGE/$rel" || die "cannot set mode of $rel"
  mv -T -- "$CFG_STAGE/$rel" "$CONFIG_DIR/$rel" || die "cannot install $CONFIG_DIR/$rel"
done

# Last step: switch current atomically (a new link renamed over the old one),
# only after the data directory and all configuration files are in place.
CURRENT="$PREFIX/current"
if [ -L "$CURRENT" ] && [ "$(readlink -- "$CURRENT")" = "$ID" ]; then
  :
else
  [ ! -e "$CURRENT" ] || [ -L "$CURRENT" ] || die "current exists and is not a symbolic link: $CURRENT"
  TMP_LINK="$PREFIX/.cass-current.$$.$RANDOM"
  ln -s -- "$ID" "$TMP_LINK" || die 'cannot create current link'
  mv -T -- "$TMP_LINK" "$CURRENT" || die "cannot switch current: $CURRENT"
  TMP_LINK=""
fi
printf 'DEPLOY_OK instance=%s current=%s data_dir=%s config_dir=%s\n' "$INSTANCE" "$CURRENT" "$DATA_DIR" "$CONFIG_DIR"
printf 'sources_config=%s/cass/sources.toml\napi_config=%s/model-api.toml\nenv_file=%s/model-api.env\n' \
  "$CONFIG_DIR" "$CONFIG_DIR" "$CONFIG_DIR"
