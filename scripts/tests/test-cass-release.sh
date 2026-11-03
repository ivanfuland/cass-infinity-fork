#!/usr/bin/env bash
# Use a real, extracted release: bash scripts/tests/test-cass-release.sh /path/to/bundle
# Each run owns its files and child environment. No shared HOME, service or database.
# Only the stage/race cases replace cp/mv; all binaries and other probes are real.
# Generic installer protections run twice: on the given bundle and on format 2 fixtures.
set -euo pipefail
BUNDLE=${1:?usage: test-cass-release.sh /absolute/extracted-bundle}
SANDBOX=${TEST_SANDBOX:-$(mktemp -d /tmp/cc-cass-release-test.XXXXXX)}
mkdir -p "$SANDBOX"
BUNDLE=$(cd -- "$BUNDLE" && pwd -P)
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
COMMIT=$(sed -n 's/^source_commit=//p' "$BUNDLE/release.env")
ID="cass-fork-$COMMIT-linux-x86_64"
PASS=0; FAIL=0
printf 'sandbox=%s bundle=%s\n' "$SANDBOX" "$BUNDLE"
# Format 2 fixtures reuse the real version 1 binaries, the installer under test
# (V2_INSTALL_SCRIPT overrides it, e.g. for mutation runs) and a templates/ tree.
V2_INSTALLER=${V2_INSTALL_SCRIPT:-$REPO/scripts/install-cass-fork-release.sh}
sign_v2() {
  (cd "$bundle" && { printf '%s\n' cass cass-mcp install.sh release.env; find templates -type f; } \
    | LC_ALL=C sort | xargs -d '\n' sha256sum -- > SHA256SUMS)
}
build_v2() {
  cp -p -- "$BUNDLE/"{cass,cass-mcp} "$bundle/"
  cp -- "$V2_INSTALLER" "$bundle/install.sh"; chmod 755 "$bundle/install.sh"
  sed 's#^format=.*#format=cass-fork-release/2#' "$BUNDLE/release.env" > "$bundle/release.env"
  mkdir -p "$bundle/templates/sub/deeper"
  printf 'Deployment templates.\n' > "$bundle/templates/README.md"
  printf 'name with a space\n' > "$bundle/templates/sub/a b.txt"
  printf 'nested\n' > "$bundle/templates/sub/deeper/note.conf"
  sign_v2
}
tree_list() { (cd "$1" && find . -mindepth 1 -printf '%y %m %P\n' | LC_ALL=C sort); }
resign() {
  if [ "${fmt:-v1}" = v2 ]; then sign_v2; return; fi
  (cd "$bundle" && sha256sum cass cass-mcp install.sh release.env > SHA256SUMS)
}
run_install() {
  env -i HOME="$dir/home" PATH="$path" bash "$bundle/install.sh" --prefix "$prefix" > "$dir/install.log" 2>&1
}
no_success() { if grep -q '^INSTALL_OK ' "$dir/install.log"; then return 1; fi; }
reject() {
  if run_install; then echo 'unexpected installation success' >&2; return 1; fi
  no_success
  grep -qF -- "$1" "$dir/install.log"
  [ ! -e "$prefix/$ID" ] && [ ! -L "$prefix/$ID" ]
}
# Sets path, bundle and prefix of the calling case (dynamic scope).
prepare_case() {
  mkdir -p "$dir/home" "$dir/bundle" "$dir/prefix/old-version" "$dir/tools"
  path="$dir/tools:/usr/bin:/bin"
  cat > "$dir/tools/forbidden-tool" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$0" >> "${0%/*}/unexpected-tool-calls"
exit 89
SH
  chmod +x "$dir/tools/forbidden-tool"
  local tool
  for tool in git cargo rustup rustc python python3 curl wget apt apt-get dnf yum; do
    ln -s forbidden-tool "$dir/tools/$tool"
  done
  bundle="$dir/bundle"; prefix="$dir/prefix"
  printf 'keep-config\n' > "$prefix/config"
  printf 'keep-database\n' > "$prefix/old-version/data"
}
# one_case <kind> [v1|v2]: v1 uses the given bundle and its own installer;
# v2 runs the same generic protection case on a signed format 2 fixture.
one_case() (
  set -e
  local kind=$1 fmt=${2:-v1} dir bundle prefix path
  dir="$SANDBOX/$kind"; [ "$fmt" = v1 ] || dir="$SANDBOX/v2g-$kind"
  prepare_case
  if [ "$fmt" = v2 ]; then
    build_v2
  else
    cp -p -- "$BUNDLE/"{cass,cass-mcp,install.sh,release.env,SHA256SUMS} "$bundle/"
    # Mutation runs replace the shipped installer, then sign that test fixture.
    if [ -n "${INSTALL_SCRIPT:-}" ]; then cp -- "$INSTALL_SCRIPT" "$bundle/install.sh"; resign; fi
  fi
  case "$kind" in
    install)
      run_install
      grep -q '^INSTALL_OK ' "$dir/install.log"
      diff "$bundle/SHA256SUMS" "$prefix/$ID/SHA256SUMS"
      (cd "$prefix/$ID" && sha256sum --check SHA256SUMS)
      [ "$("$prefix/$ID/cass" --version)" = 'cass 0.6.17' ]
      [ "$("$prefix/$ID/cass-mcp" --version)" = 'cass-mcp 0.6.17' ]
      ;;
    tamper-cli|tamper-mcp)
      local name=cass; [ "$kind" != tamper-mcp ] || name=cass-mcp
      printf 'tampered\n' >> "$bundle/$name"; reject "checksum mismatch: $name" ;;
    tamper-manifest) printf 'extra=value\n' >> "$bundle/release.env"; reject 'checksum mismatch: release.env' ;;
    missing-checksum) sed -i '/  cass-mcp$/d' "$bundle/SHA256SUMS"; reject 'missing bundle checksum' ;;
    duplicate-checksum)
      local first; first=$(head -n 1 "$bundle/SHA256SUMS")
      printf '%s\n' "$first" >> "$bundle/SHA256SUMS"; reject 'duplicate checksum' ;;
    traversal-checksum) printf '%064d  ../cass\n' 0 >> "$bundle/SHA256SUMS"; reject 'four fixed relative files' ;;
    invalid-checksum) sed -i '1s/./z/' "$bundle/SHA256SUMS"; reject 'four fixed relative files' ;;
    platform) sed -i 's/platform=.*/platform=windows-x86_64/' "$bundle/release.env"; resign; reject 'unsupported release platform' ;;
    glibc) sed -i 's/glibc_min=.*/glibc_min=999.0/' "$bundle/release.env"; resign; reject 'requires glibc >= 999.0' ;;
    missing-metadata) sed -i '/^mcp_version=/d' "$bundle/release.env"; resign; reject 'missing release metadata' ;;
    duplicate-metadata) printf 'format=cass-fork-release/1\n' >> "$bundle/release.env"; resign; reject 'duplicate release metadata' ;;
    unknown-metadata) printf 'other=value\n' >> "$bundle/release.env"; resign; reject 'unknown release metadata' ;;
    unsafe-metadata)
      # shellcheck disable=SC2016 # Deliberate literal payload, never execute it.
      printf 'source_commit=$(touch %s)\n' "$dir/executed" > "$dir/payload"
      sed -i '/^source_commit=/d' "$bundle/release.env"
      cat "$dir/payload" >> "$bundle/release.env"; resign; reject 'invalid source commit'
      [ ! -e "$dir/executed" ] ;;
    format) sed -i 's#format=.*#format=cass-fork-release/2#' "$bundle/release.env"; resign; reject 'unsupported release format' ;;
    invalid-version) sed -i 's/cass_version=.*/cass_version=bad value/' "$bundle/release.env"; resign; reject 'invalid version: cass_version' ;;
    invalid-glibc) sed -i 's/glibc_min=.*/glibc_min=unknown/' "$bundle/release.env"; resign; reject 'invalid glibc requirement' ;;
    second-version) sed -i 's/mcp_version=.*/mcp_version=0.0.0/' "$bundle/release.env"; resign; reject 'version mismatch: cass-mcp' ;;
    broken-second)
      printf 'not an ELF\n' > "$bundle/cass-mcp"; resign; reject 'cannot resolve runtime libraries: cass-mcp' ;;
    symlink-cli|symlink-manifest|symlink-sums)
      local name=cass
      case "$kind" in symlink-manifest) name=release.env ;; symlink-sums) name=SHA256SUMS ;; esac
      mv "$bundle/$name" "$dir/real-file"; ln -s "$dir/real-file" "$bundle/$name"
      reject "not a regular bundle file: $name" ;;
    existing-directory|existing-file|existing-dangling)
      case "$kind" in
        existing-directory) mkdir "$prefix/$ID"; printf 'old\n' > "$prefix/$ID/sentinel" ;;
        existing-file) printf 'old\n' > "$prefix/$ID" ;;
        existing-dangling) ln -s missing "$prefix/$ID" ;;
      esac
      local before after
      before=$(find "$prefix" -printf '%P %y %l\n'; find "$prefix" -type f -exec sha256sum {} +)
      if run_install; then return 1; fi
      grep -q 'version already exists' "$dir/install.log"
      no_success
      after=$(find "$prefix" -printf '%P %y %l\n'; find "$prefix" -type f -exec sha256sum {} +)
      [ "$before" = "$after" ] ;;
    stage-second|publish-race)
      if [ "$kind" = stage-second ]; then
        cat > "$dir/tools/cp" <<'SH'
#!/usr/bin/env bash
/usr/bin/cp "$@" || exit
dest=${!#}
case "$dest" in */.cass-release-stage.*/cass-mcp) printf 'changed\n' >> "$dest" ;; esac
SH
        chmod +x "$dir/tools/cp"
        reject 'staged checksum mismatch: cass-mcp'
      else
        cat > "$dir/tools/mv" <<'SH'
#!/usr/bin/env bash
dest=${!#}
mkdir "$dest" || exit
printf 'concurrent\n' > "$dest/sentinel"
exec /usr/bin/mv "$@"
SH
        chmod +x "$dir/tools/mv"
        if run_install; then return 1; fi
        grep -q 'version appeared concurrently' "$dir/install.log"
        [ "$(cat "$prefix/$ID/sentinel")" = concurrent ]
        [ "$(find "$prefix/$ID" -mindepth 1 | wc -l)" -eq 1 ]
        no_success
      fi
      [ "$(find "$prefix" -maxdepth 1 -name '.cass-release-stage.*' -type d | wc -l)" -eq 1 ] ;;
    *) exit 2 ;;
  esac
  [ "$(cat "$prefix/config")" = keep-config ]
  [ "$(cat "$prefix/old-version/data")" = keep-database ]
  [ ! -e "$dir/tools/unexpected-tool-calls" ]
)
for kind in install tamper-cli tamper-mcp tamper-manifest missing-checksum duplicate-checksum \
  traversal-checksum invalid-checksum platform glibc missing-metadata duplicate-metadata \
  unknown-metadata unsafe-metadata format invalid-version invalid-glibc second-version \
  broken-second symlink-cli symlink-manifest symlink-sums existing-directory existing-file \
  existing-dangling stage-second publish-race; do
  # Capture each subshell status outside a conditional so its errexit stays active.
  set +e
  one_case "$kind" > "$SANDBOX/$kind.log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); printf 'FAIL %s: %s\n' "$kind" "$SANDBOX/$kind.log"; fi
done
# The installer's generic protections, rerun on format 2 fixtures with the new
# installer. Checksum-format cases are format specific and covered below.
G_PASS=0; G_FAIL=0
for kind in install tamper-cli tamper-mcp tamper-manifest platform glibc missing-metadata \
  duplicate-metadata unknown-metadata unsafe-metadata invalid-version invalid-glibc \
  second-version broken-second symlink-cli symlink-manifest symlink-sums existing-directory \
  existing-file existing-dangling stage-second publish-race; do
  set +e
  one_case "$kind" v2 > "$SANDBOX/v2g-$kind.log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then G_PASS=$((G_PASS+1)); else G_FAIL=$((G_FAIL+1)); printf 'FAIL v2g-%s: %s\n' "$kind" "$SANDBOX/v2g-$kind.log"; fi
done
# ---------------------------------------------------------------------------
# Format 2 specific cases: templates/ and SHA256SUMS path rules.
# v1-cass-install runs the root entry against the unchanged version 1 bundle.
# ---------------------------------------------------------------------------
v2_case() (
  set -e
  local kind=$1 dir="$SANDBOX/$1" bundle prefix path
  prepare_case
  case "$kind" in
    v1-cass-install)
      env -i HOME="$dir/home" PATH="$path" bash "$REPO/cass" install "$BUNDLE" --prefix "$prefix" > "$dir/install.log" 2>&1
      grep -q '^INSTALL_OK ' "$dir/install.log"
      grep -q '^Installed only\.' "$dir/install.log"
      [ "$(tree_list "$BUNDLE")" = "$(tree_list "$prefix/$ID")" ]
      local name
      for name in cass cass-mcp install.sh release.env SHA256SUMS; do cmp -- "$BUNDLE/$name" "$prefix/$ID/$name"; done
      ;;
    v2-install)
      build_v2; run_install
      grep -q '^INSTALL_OK ' "$dir/install.log"
      local name
      for name in cass cass-mcp install.sh release.env SHA256SUMS; do cmp -- "$bundle/$name" "$prefix/$ID/$name"; done
      diff -r -- "$bundle/templates" "$prefix/$ID/templates"
      [ "$(tree_list "$bundle")" = "$(tree_list "$prefix/$ID")" ]
      (cd "$prefix/$ID" && sha256sum --check --quiet SHA256SUMS)
      [ "$("$prefix/$ID/cass" --version)" = 'cass 0.6.17' ]
      [ "$("$prefix/$ID/cass-mcp" --version)" = 'cass-mcp 0.6.17' ]
      [ "$(find "$prefix" -maxdepth 1 -name '.cass-release-stage.*' | wc -l)" -eq 0 ]
      ;;
    v2-tamper-template)
      build_v2; printf 'tampered\n' >> "$bundle/templates/sub/deeper/note.conf"
      reject 'checksum mismatch: templates/sub/deeper/note.conf' ;;
    v2-missing-template)
      build_v2; rm -- "$bundle/templates/sub/deeper/note.conf"
      reject 'checksum list does not match bundle files' ;;
    v2-extra-template)
      build_v2; printf 'unsigned\n' > "$bundle/templates/extra.txt"
      reject 'checksum list does not match bundle files' ;;
    v2-extra-member)
      build_v2; printf 'unsigned\n' > "$bundle/notes.txt"
      reject 'checksum list does not match bundle files' ;;
    v2-dotdot-checksum)
      build_v2; printf '%s  templates/../cass\n' "$(sha256sum "$bundle/cass" | cut -d' ' -f1)" >> "$bundle/SHA256SUMS"
      reject 'unsafe checksum path' ;;
    v2-absolute-checksum)
      build_v2; printf '%064d  /etc/hostname\n' 0 >> "$bundle/SHA256SUMS"
      reject 'unsafe checksum path' ;;
    v2-duplicate-checksum)
      build_v2; tail -n 1 "$bundle/SHA256SUMS" >> "$bundle/SHA256SUMS"
      reject 'duplicate checksum' ;;
    v2-symlink-template)
      build_v2; mv -- "$bundle/templates/README.md" "$dir/real-file"
      ln -s "$dir/real-file" "$bundle/templates/README.md"
      reject 'not a regular bundle file: templates/README.md' ;;
    v2-templates-missing)
      build_v2; rm -r -- "$bundle/templates"
      (cd "$bundle" && sha256sum cass cass-mcp install.sh release.env > SHA256SUMS)
      reject 'missing templates directory' ;;
    v2-format-1)
      build_v2; sed -i 's#^format=.*#format=cass-fork-release/1#' "$bundle/release.env"; sign_v2
      reject 'unsupported release format' ;;
    v2-stage-template)
      build_v2
      cat > "$dir/tools/cp" <<'SH'
#!/usr/bin/env bash
/usr/bin/cp "$@" || exit
dest=${!#}
case "$dest" in */.cass-release-stage.*/templates) printf 'changed\n' >> "$dest/README.md" ;; esac
SH
      chmod +x "$dir/tools/cp"
      reject 'staged checksum mismatch: templates/README.md'
      [ "$(find "$prefix" -maxdepth 1 -name '.cass-release-stage.*' -type d | wc -l)" -eq 1 ] ;;
    *) exit 2 ;;
  esac
  [ "$(cat "$prefix/config")" = keep-config ]
  [ "$(cat "$prefix/old-version/data")" = keep-database ]
  [ ! -e "$dir/tools/unexpected-tool-calls" ]
)
V2_PASS=0; V2_FAIL=0
for kind in v1-cass-install v2-install v2-tamper-template v2-missing-template v2-extra-template \
  v2-extra-member v2-dotdot-checksum v2-absolute-checksum v2-duplicate-checksum \
  v2-symlink-template v2-templates-missing v2-format-1 v2-stage-template; do
  set +e
  v2_case "$kind" > "$SANDBOX/$kind.log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then V2_PASS=$((V2_PASS+1)); else V2_FAIL=$((V2_FAIL+1)); printf 'FAIL %s: %s\n' "$kind" "$SANDBOX/$kind.log"; fi
done
printf 'GROUP_SUMMARY group=v1-bundle total=%s pass=%s fail=%s\n' "$((PASS+FAIL))" "$PASS" "$FAIL"
printf 'GROUP_SUMMARY group=v2-generic total=%s pass=%s fail=%s\n' "$((G_PASS+G_FAIL))" "$G_PASS" "$G_FAIL"
printf 'GROUP_SUMMARY group=v2-format total=%s pass=%s fail=%s\n' "$((V2_PASS+V2_FAIL))" "$V2_PASS" "$V2_FAIL"
PASS=$((PASS+G_PASS+V2_PASS)); FAIL=$((FAIL+G_FAIL+V2_FAIL))
printf 'TEST_SUMMARY total=%s pass=%s fail=%s\n' "$((PASS+FAIL))" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
