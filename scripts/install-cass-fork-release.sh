#!/usr/bin/env bash
# Shipped as install.sh in a native Linux release. No build tools or network.
set -euo pipefail
export LC_ALL=C

die() { printf 'FAIL[install]: %s\n' "$*" >&2; exit 1; }
usage() { printf 'Usage: bash install.sh --prefix /absolute/version-root\n'; }
PREFIX=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --prefix)
      [ "$#" -ge 2 ] && [ -z "$PREFIX" ] || die '--prefix requires one value'
      PREFIX="$2"; shift 2 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done
case "$PREFIX" in /*) ;; *) die '--prefix must be an absolute directory' ;; esac
BUNDLE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
for name in cass cass-mcp install.sh release.env SHA256SUMS; do
  [ -f "$BUNDLE/$name" ] && [ ! -L "$BUNDLE/$name" ] || die "not a regular bundle file: $name"
done

digest() { local value; value=$(sha256sum -- "$1") || die "cannot hash $1"; printf '%s' "${value%% *}"; }
declare -A HASHES=()
while IFS= read -r line || [ -n "$line" ]; do
  if [[ ! "$line" =~ ^([0-9a-f]{64})\ \ (cass|cass-mcp|install\.sh|release\.env)$ ]]; then
    die 'SHA256SUMS must contain only the four fixed relative files'
  fi
  hash=${BASH_REMATCH[1]}; name=${BASH_REMATCH[2]}
  [ -z "${HASHES[$name]+present}" ] || die "duplicate checksum: $name"
  HASHES[$name]="$hash"
done < "$BUNDLE/SHA256SUMS"
[ "${#HASHES[@]}" -eq 4 ] || die 'missing bundle checksum'
for name in cass cass-mcp install.sh release.env; do
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
[ "${META[format]}" = 'cass-fork-release/1' ] || die 'unsupported release format'
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

[ ! -e "$PREFIX" ] || [ -d "$PREFIX" ] || die 'installation root is not a directory'
[ ! -L "$PREFIX" ] || [ -d "$PREFIX" ] || die 'installation root is a dangling symlink'
mkdir -p -- "$PREFIX"
PREFIX=$(cd -- "$PREFIX" && pwd -P)
ID="cass-fork-${META[source_commit]}-${META[platform]}"
DEST="$PREFIX/$ID"
[ ! -e "$DEST" ] && [ ! -L "$DEST" ] || die "version already exists; kept unchanged: $DEST"
STAGE=$(mktemp -d "$PREFIX/.cass-release-stage.XXXXXX")
on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ -d "$STAGE" ]; then printf 'Unpublished stage retained: %s\n' "$STAGE" >&2; fi
}
trap on_exit EXIT
for name in cass cass-mcp install.sh release.env SHA256SUMS; do cp -p -- "$BUNDLE/$name" "$STAGE/$name"; done
for name in cass cass-mcp install.sh release.env; do
  [ "$(digest "$STAGE/$name")" = "${HASHES[$name]}" ] || die "staged checksum mismatch: $name"
done
[ "$(digest "$STAGE/SHA256SUMS")" = "$SUMS_SHA" ] || die 'staged checksum list changed'
# GNU mv -n can return zero when it skipped an existing destination.
mv -Tn -- "$STAGE" "$DEST" || die 'cannot publish version directory'
[ ! -e "$STAGE" ] && [ -d "$DEST" ] && [ ! -L "$DEST" ] || die 'version appeared concurrently; nothing overwritten'
printf 'INSTALL_OK source_commit=%s install_dir=%s\n' "${META[source_commit]}" "$DEST"
printf 'cass=%s/cass\ncass_mcp=%s/cass-mcp\n' "$DEST" "$DEST"
