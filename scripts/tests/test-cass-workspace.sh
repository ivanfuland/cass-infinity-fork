#!/usr/bin/env bash
# Root CLI checks use isolated Git fixtures, HOME and a real extracted bundle.
# Release compilation itself is checked separately by invoking ./cass release.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ENTRY=${ENTRY_SCRIPT:-$HERE/../../cass}
BUNDLE=${1:?usage: test-cass-workspace.sh /absolute/extracted-release}
BUNDLE=$(cd -- "$BUNDLE" && pwd -P)
ID=${BUNDLE##*/}
SANDBOX=${TEST_SANDBOX:-$(mktemp -d /tmp/cc-cass-workspace-test.XXXXXX)}
mkdir -p "$SANDBOX"
PASS=0; FAIL=0
printf 'sandbox=%s bundle=%s\n' "$SANDBOX" "$BUNDLE"
invoke() { env -i HOME="$home" PATH="$dir/tools:/usr/bin:/bin" bash "$project/cass" "$@" > "$dir/command.log" 2>&1; }
reject() {
  if invoke "$@"; then echo 'unexpected success' >&2; return 1; fi
}
snapshot() { find "$project" "$home" -printf '%p %y %l\n'; find "$project" "$home" -type f -exec sha256sum {} +; }
one_case() (
  set -e
  local kind=$1 dir="$SANDBOX/$1" home project prefix commit before after
  mkdir -p "$dir/project" "$dir/home" "$dir/tools"
  home="$dir/home"; project="$dir/project"; prefix="$home/.local/lib/cass-mcp"
  cp -- "$ENTRY" "$project/cass"
  printf '/.build/\n/dist/\n' > "$project/.gitignore"
  printf '[dependencies]\nfranken-agent-detection = { git = "https://example.invalid/fad", rev = "61f975f3b56f8dabc4ecbe1dae4102c1ea6b16e5" }\n' > "$project/Cargo.toml"
  git -C "$project" init -q
  git -C "$project" add cass Cargo.toml .gitignore
  git -C "$project" -c user.name=fixture -c user.email=fixture@example.invalid commit -qm fixture
  commit=$(git -C "$project" rev-parse HEAD)
  cat > "$dir/tools/systemctl" <<'SH'
#!/usr/bin/env bash
case "$*" in
  '--user show cass-mcp.service --property=MainPID --value') printf '0\n' ;;
  *) printf '%s\n' "$*" > "${0%/*}/forbidden-service-operation"; exit 89 ;;
esac
SH
  chmod +x "$dir/tools/systemctl"
  case "$kind" in
    help|status)
      before=$(snapshot)
      invoke "$kind"
      after=$(snapshot)
      [ "$before" = "$after" ]
      if [ "$kind" = help ]; then
        grep -q 'release' "$dir/command.log"; grep -q 'install' "$dir/command.log"
      else
        grep -qF "Development cache: $project/.build" "$dir/command.log"
        grep -qF "Production versions: $prefix" "$dir/command.log"
        grep -qF 'Running MCP: not running' "$dir/command.log"
      fi ;;
    dirty)
      printf 'unfinished\n' > "$project/unfinished.txt"
      reject release
      grep -q 'commit source changes' "$dir/command.log"
      [ ! -e "$project/.build" ] ;;
    missing-pin|invalid-pin)
      if [ "$kind" = missing-pin ]; then printf '[dependencies]\n' > "$project/Cargo.toml";
      else sed -i 's/61f975f3b56f8dabc4ecbe1dae4102c1ea6b16e5/invalid/' "$project/Cargo.toml"; fi
      git -C "$project" add Cargo.toml
      git -C "$project" -c user.name=fixture -c user.email=fixture@example.invalid commit -qm changed-fixture
      reject release
      grep -q 'missing or invalid FAD' "$dir/command.log"
      [ ! -e "$project/.build" ] ;;
    locked)
      mkdir "$project/.build"
      exec 8>"$project/.build/release.lock"; flock -n 8
      reject release
      grep -q 'build lock' "$dir/command.log"
      [ ! -e "$project/.build/cass-infinity-fork.git" ] ;;
    existing-output)
      mkdir "$project/dist"
      local target="$project/dist/cass-fork-$commit-linux-x86_64.tar.gz"
      printf 'keep-package\n' > "$target"
      reject release
      grep -q 'release already exists' "$dir/command.log"
      [ "$(cat "$target")" = keep-package ]
      [ ! -e "$project/.build" ] ;;
    cache-symlink)
      mkdir "$dir/external"
      ln -s "$dir/external" "$project/.build"
      reject release
      # A directory-only ignore also makes the symlink an untracked source;
      # either source preflight or cache validation must reject it.
      grep -qE '(commit source changes|\.build must not be a symlink)' "$dir/command.log"
      [ "$(find "$dir/external" -mindepth 1 | wc -l)" -eq 0 ] ;;
    no-bundle) reject install; grep -q 'release bundle missing' "$dir/command.log" ;;
    unknown) reject unrelated; grep -q 'unknown command' "$dir/command.log" ;;
    install|prefix|tampered|existing-version|wrong-default)
      mkdir -p "$prefix/old-version"
      printf 'keep-config\n' > "$home/config"
      printf 'keep-data\n' > "$prefix/old-version/data"
      local bundle="$dir/$ID"
      mkdir "$bundle"
      cp -p -- "$BUNDLE/"{cass,cass-mcp,install.sh,release.env,SHA256SUMS} "$bundle/"
      case "$kind" in
        install)
          invoke install "$bundle"
          grep -q '^INSTALL_OK ' "$dir/command.log"
          grep -q 'running service, configuration and data are unchanged' "$dir/command.log"
          (cd "$prefix/$ID" && sha256sum --check SHA256SUMS) ;;
        prefix)
          invoke install "$bundle" --prefix "$dir/alternative"
          (cd "$dir/alternative/$ID" && sha256sum --check SHA256SUMS)
          [ ! -e "$prefix/$ID" ] ;;
        tampered)
          printf 'tampered\n' >> "$bundle/cass-mcp"
          reject install "$bundle"
          grep -q 'checksum mismatch: cass-mcp' "$dir/command.log"
          [ ! -e "$prefix/$ID" ] ;;
        existing-version)
          printf 'old-version\n' > "$prefix/$ID"
          reject install "$bundle"
          grep -q 'version already exists' "$dir/command.log"
          [ "$(cat "$prefix/$ID")" = old-version ] ;;
        wrong-default)
          mkdir -p "$project/dist"
          mv "$bundle" "$project/dist/cass-fork-$commit-linux-x86_64"
          reject install
          grep -q 'default bundle does not match this Git HEAD' "$dir/command.log"
          [ ! -e "$prefix/$ID" ] ;;
      esac
      [ "$(cat "$home/config")" = keep-config ]
      [ "$(cat "$prefix/old-version/data")" = keep-data ] ;;
    *) exit 2 ;;
  esac
  [ ! -e "$dir/tools/forbidden-service-operation" ]
)
for kind in help status dirty missing-pin invalid-pin locked existing-output cache-symlink \
  no-bundle unknown install prefix tampered existing-version wrong-default; do
  set +e
  one_case "$kind" > "$SANDBOX/$kind.log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); printf 'FAIL %s: %s\n' "$kind" "$SANDBOX/$kind.log"; fi
done
printf 'TEST_SUMMARY total=%s pass=%s fail=%s\n' "$((PASS+FAIL))" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
