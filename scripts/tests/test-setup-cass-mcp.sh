#!/usr/bin/env bash
# test-setup-cass-mcp.sh — control-flow tests for the paired candidate mode of
# scripts/setup-cass-fork.sh, plus legacy single-CLI compatibility.
#
# MOCK BOUNDARY: this script replaces cargo, rustup, strings, ldd, ln and the
# asupersync git sibling with fakes earlier in PATH. Every case runs in its own
# temp directory with an isolated HOME and a throwaway local git origin. These
# cases prove branch and publication boundaries only. They are NOT release
# evidence: the real paired release is produced by the shipped script against
# the private source mirror in the task run root.
#
# Env:
#   SETUP_SCRIPT=<path>  override the script under test (used for the RED run
#                        against the pre-change basepoint script)
#   KEEP_SANDBOX=1       keep the run sandbox (it is kept by default)
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SETUP_SCRIPT="${SETUP_SCRIPT:-$HERE/../setup-cass-fork.sh}"
[ -f "$SETUP_SCRIPT" ] || { echo "missing setup script: $SETUP_SCRIPT" >&2; exit 2; }
BASH_BIN=$(command -v bash)
REAL_GIT=$(command -v git)
REAL_LN=$(command -v ln)

SANDBOX=${TEST_SANDBOX:-$(mktemp -d "${TMPDIR:-/tmp}/cc-cass-t16-test.XXXXXX")}
MOCKS="$SANDBOX/mocks"
FAKE_HOME="$SANDBOX/home"
mkdir -p "$MOCKS" "$FAKE_HOME" "$SANDBOX/cases"
echo "sandbox: $SANDBOX"
echo "setup:   $SETUP_SCRIPT"

# ---------------------------------------------------------------------------
# Fakes (mock boundary). Each fake logs its invocations into the case dir.
# ---------------------------------------------------------------------------
cat > "$MOCKS/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
set -u
log="${FAKE_LOG:?}/cargo-calls.log"
printf 'cwd=%s args=%s\n' "$PWD" "$*" >> "$log"
manifest=""
prev=""
for a in "$@"; do
  [ "$prev" = "--manifest-path" ] && manifest="$a"
  prev="$a"
done
if [ -n "$manifest" ]; then
  if [ "${FAKE_CARGO_MCP_FAIL:-0}" = "1" ]; then echo "fake cargo: mcp build failed" >&2; exit 101; fi
  mkdir -p mcp/target/release || exit 1
  ver="${FAKE_VERSION_MCP:-cass-mcp 0.6.17}"
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" %q\n' "$ver" > mcp/target/release/cass-mcp || exit 1
  chmod +x mcp/target/release/cass-mcp
else
  if [ "${FAKE_CARGO_ROOT_FAIL:-0}" = "1" ]; then echo "fake cargo: root build failed" >&2; exit 101; fi
  mkdir -p target/release || exit 1
  ver="${FAKE_VERSION_CLI:-cass 0.6.17}"
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" %q\n' "$ver" > target/release/cass || exit 1
  chmod +x target/release/cass
  case "${FAKE_POST_ROOT:-}" in
    commit) "${REAL_GIT:?}" -C "$PWD" -c user.email=t@example.invalid -c user.name=t commit --allow-empty -q -m "fake post-build commit" ;;
    dirty)  printf 'dirty\n' > post-build-dirty.txt ;;
  esac
fi
exit 0
FAKE_CARGO

cat > "$MOCKS/strings" <<'FAKE_STRINGS'
#!/usr/bin/env bash
set -u
bin="${!#}"
base=$(basename "$bin")
printf 'strings bin=%s\n' "$bin" >> "${FAKE_LOG:?}/strings-calls.log"
if [ -n "${FAKE_STRINGS_FAIL:-}" ] && [ "$base" = "$FAKE_STRINGS_FAIL" ]; then
  echo "fake strings: probe failed" >&2
  exit 1
fi
echo "fake-strings: $base"
if [ -n "${FAKE_STRINGS_HITS:-}" ] && [ "${FAKE_STRINGS_HITS:-0}" -gt 0 ] && [ "$base" = "${FAKE_STRINGS_HITS_BIN:-cass}" ]; then
  i=0
  while [ "$i" -lt "$FAKE_STRINGS_HITS" ]; do echo "onnxruntime"; i=$((i+1)); done
fi
exit 0
FAKE_STRINGS

cat > "$MOCKS/ldd" <<'FAKE_LDD'
#!/usr/bin/env bash
set -u
bin="${!#}"
base=$(basename "$bin")
printf 'ldd bin=%s\n' "$bin" >> "${FAKE_LOG:?}/ldd-calls.log"
if [ -n "${FAKE_LDD_FAIL:-}" ] && [ "$base" = "$FAKE_LDD_FAIL" ]; then
  echo "fake ldd: not a dynamic executable" >&2
  exit 1
fi
echo "	linux-vdso.so.1 (0x00007ffd00000000)"
echo "	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6"
if [ -n "${FAKE_LDD_HITS:-}" ] && [ "${FAKE_LDD_HITS:-0}" -gt 0 ] && [ "$base" = "${FAKE_LDD_HITS_BIN:-cass}" ]; then
  echo "	libonnxruntime.so.1 => /opt/fake/libonnxruntime.so.1"
fi
exit 0
FAKE_LDD

cat > "$MOCKS/rustup" <<'FAKE_RUSTUP'
#!/usr/bin/env bash
echo "nightly-x86_64-unknown-linux-gnu (default)"
FAKE_RUSTUP

cat > "$MOCKS/git" <<FAKE_GIT
#!/usr/bin/env bash
set -u
printf 'git %s\n' "\$*" >> "\${FAKE_LOG:?}/git-calls.log"
for a in "\$@"; do
  case "\$a" in
    *asupersync*)
      if [ "\$1" = "clone" ]; then
        dest="\${!#}"
        mkdir -p "\$dest/.git"
        printf '[package]\nname = "asupersync"\nversion = "0.3.5"\n' > "\$dest/Cargo.toml"
      fi
      exit 0
      ;;
  esac
done
exec "$REAL_GIT" "\$@"
FAKE_GIT

cat > "$MOCKS/ln" <<FAKE_LN
#!/usr/bin/env bash
set -u
dest="\${!#}"
printf 'ln args=%s\n' "\$*" >> "\${FAKE_LOG:?}/ln-calls.log"
if [ -n "\${FAKE_LN_FAIL_DEST:-}" ] && [ "\$dest" = "\$FAKE_LN_FAIL_DEST" ]; then
  echo "fake ln: refusing to create \$dest" >&2
  exit 1
fi
exec "$REAL_LN" "\$@"
FAKE_LN

chmod +x "$MOCKS"/*

# ---------------------------------------------------------------------------
# Throwaway local origin named like the real fork remote.
# ---------------------------------------------------------------------------
ORIGIN_ROOT="$SANDBOX/origin"
ORIGIN="$ORIGIN_ROOT/cass-infinity-fork.git"
ORIGIN_WORK="$ORIGIN_ROOT/work"
mkdir -p "$ORIGIN_ROOT"
"$REAL_GIT" init -q --bare "$ORIGIN"
"$REAL_GIT" -C "$ORIGIN" symbolic-ref HEAD refs/heads/t16-mock
"$REAL_GIT" init -q "$ORIGIN_WORK"
"$REAL_GIT" -C "$ORIGIN_WORK" symbolic-ref HEAD refs/heads/t16-mock
cat > "$ORIGIN_WORK/Cargo.toml" <<'TOML'
[package]
name = "coding-agent-search"
version = "0.6.17"

[dependencies]
asupersync = { version = "=0.3.5", path = "../asupersync" }
TOML
mkdir -p "$ORIGIN_WORK/mcp"
printf '[package]\nname = "cass-mcp"\nversion = "0.6.17"\n\n[workspace]\n' > "$ORIGIN_WORK/mcp/Cargo.toml"
printf 'target/\n' > "$ORIGIN_WORK/.gitignore"
"$REAL_GIT" -C "$ORIGIN_WORK" -c user.email=t@example.invalid -c user.name=t add -A
"$REAL_GIT" -C "$ORIGIN_WORK" -c user.email=t@example.invalid -c user.name=t commit -q -m fixture
"$REAL_GIT" -C "$ORIGIN_WORK" push -q "$ORIGIN" t16-mock

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
FAILED=()
CASE=""
CASE_DIR=""
CASE_FAIL=0
CLI_TARGET=""
MCP_TARGET=""

begin_case() {
  CASE="$1"
  CASE_DIR="$SANDBOX/cases/$1"
  CASE_FAIL=0
  mkdir -p "$CASE_DIR"
  CLI_TARGET="$CASE_DIR/cli/cass"
  MCP_TARGET="$CASE_DIR/mcp/cass-mcp"
}

end_case() {
  if [ "$CASE_FAIL" -eq 0 ]; then
    PASS=$((PASS + 1))
    printf 'PASS %s\n' "$CASE"
  else
    FAIL=$((FAIL + 1))
    FAILED+=("$CASE")
    printf 'FAIL %s (log: %s/setup.log)\n' "$CASE" "$CASE_DIR"
  fi
}

case_fail() { printf '  %s: %s\n' "$CASE" "$1"; CASE_FAIL=1; }
assert_rc_nonzero() { [ "$1" -ne 0 ] || case_fail "expected non-zero rc, got 0"; }
assert_rc_zero() { [ "$1" -eq 0 ] || case_fail "expected rc 0, got $1"; }
assert_file() { [ -f "$1" ] || case_fail "missing file $1"; }
assert_no_path() { { [ ! -e "$1" ] && [ ! -L "$1" ]; } || case_fail "unexpected path $1"; }
assert_exec() { [ -x "$1" ] || case_fail "not executable: $1"; }
assert_eq() { [ "$1" = "$2" ] || case_fail "${3:-value}: expected '$2', got '$1'"; }
assert_contains() { grep -qF -- "$2" "$1" || case_fail "expected '$2' in $1"; }
assert_not_contains() { ! grep -qF -- "$2" "$1" || case_fail "unexpected '$2' in $1"; }
assert_no_stage() {
  local n
  n=$(find "$1" -maxdepth 1 -name '.cass-pair-stage.*' 2>/dev/null | wc -l | tr -d ' ')
  assert_eq "$n" 0 "stage files left in $1"
}
log_lines() {
  if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi
}
sha_of() { sha256sum "$1" | awk '{print $1}'; }

# run_setup <case-dir> [KEY=VALUE ...]
run_setup() {
  local dir="$1"
  shift
  local rc=0
  (
    cd "$dir" || exit 99
    env -i \
      HOME="$FAKE_HOME" \
      PATH="$MOCKS:/usr/bin:/bin" \
      REAL_GIT="$REAL_GIT" \
      FAKE_LOG="$dir" \
      FORK_REPO="$ORIGIN" \
      FORK_REF=t16-mock \
      FORK_DIR="$dir/fork" \
      "$@" \
      "$BASH_BIN" "$SETUP_SCRIPT"
  ) >"$dir/setup.log" 2>&1 || rc=$?
  return "$rc"
}

# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------
case_old_missing_install() {
  begin_case old-missing-install
  local rc=0
  run_setup "$CASE_DIR" MCP_INSTALL_PATH="$MCP_TARGET" || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "INSTALL_PATH is required"
  assert_eq "$(log_lines "$CASE_DIR/git-calls.log")" 0 "git invocations"
  assert_eq "$(log_lines "$CASE_DIR/cargo-calls.log")" 0 "cargo invocations"
  end_case
}

case_paired_relative() {
  begin_case paired-relative-mcp
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="relative/cass-mcp" || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "MCP_INSTALL_PATH must be absolute"
  assert_eq "$(log_lines "$CASE_DIR/git-calls.log")" 0 "git invocations"
  end_case
}

case_paired_same_normalized() {
  begin_case paired-same-normalized
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CASE_DIR/cli/cass" MCP_INSTALL_PATH="$CASE_DIR/cli/./cass" || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "resolve to the same target"
  assert_eq "$(log_lines "$CASE_DIR/git-calls.log")" 0 "git invocations"
  end_case
}

case_paired_existing_file() {
  begin_case paired-existing-file
  mkdir -p "$(dirname "$MCP_TARGET")"
  printf 'keep-me\n' > "$MCP_TARGET"
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "already exists"
  assert_eq "$(cat "$MCP_TARGET")" "keep-me" "existing file content"
  assert_eq "$(log_lines "$CASE_DIR/cargo-calls.log")" 0 "cargo invocations"
  end_case
}

case_paired_existing_dir() {
  begin_case paired-existing-dir
  mkdir -p "$CLI_TARGET"
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "already exists"
  [ -d "$CLI_TARGET" ] || case_fail "existing directory was disturbed"
  assert_eq "$(log_lines "$CASE_DIR/cargo-calls.log")" 0 "cargo invocations"
  end_case
}

case_paired_dangling_symlink() {
  begin_case paired-dangling-symlink
  mkdir -p "$(dirname "$MCP_TARGET")"
  ln -s "$CASE_DIR/does-not-exist" "$MCP_TARGET"
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "already exists"
  [ -L "$MCP_TARGET" ] || case_fail "dangling symlink was removed"
  assert_eq "$(log_lines "$CASE_DIR/cargo-calls.log")" 0 "cargo invocations"
  end_case
}

case_paired_target_dir_empty() {
  begin_case paired-cargo-target-dir-empty
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" CARGO_TARGET_DIR= || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "CARGO_TARGET_DIR is also set"
  assert_eq "$(log_lines "$CASE_DIR/git-calls.log")" 0 "git invocations"
  end_case
}

case_paired_target_dir_set() {
  begin_case paired-cargo-target-dir-set
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" CARGO_TARGET_DIR="$CASE_DIR/ctd" || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "CARGO_TARGET_DIR is also set"
  assert_eq "$(log_lines "$CASE_DIR/git-calls.log")" 0 "git invocations"
  end_case
}

case_root_build_fail() {
  begin_case root-build-fail
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" FAKE_CARGO_ROOT_FAIL=1 || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "fake cargo: root build failed"
  assert_no_path "$CLI_TARGET"
  assert_no_path "$MCP_TARGET"
  end_case
}

case_mcp_build_fail_after_cli() {
  begin_case mcp-build-fail
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" FAKE_CARGO_MCP_FAIL=1 || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "fake cargo: mcp build failed"
  assert_file "$CASE_DIR/fork/target/release/cass"
  assert_no_path "$CLI_TARGET"
  assert_no_path "$MCP_TARGET"
  assert_eq "$(log_lines "$CASE_DIR/cargo-calls.log")" 2 "cargo invocations"
  end_case
}

case_strings_probe_fail() {
  begin_case strings-probe-fail
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" FAKE_STRINGS_FAIL=cass || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "strings probe itself failed"
  assert_no_path "$CLI_TARGET"
  assert_no_path "$MCP_TARGET"
  end_case
}

case_strings_banned_symbol() {
  begin_case strings-banned-symbol
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" FAKE_STRINGS_HITS=2 FAKE_STRINGS_HITS_BIN=cass-mcp || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "binary has 2 ONNX symbols"
  assert_no_path "$CLI_TARGET"
  assert_no_path "$MCP_TARGET"
  end_case
}

case_ldd_probe_fail() {
  begin_case ldd-probe-fail
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" FAKE_LDD_FAIL=cass-mcp || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "ldd probe itself failed"
  assert_no_path "$CLI_TARGET"
  assert_no_path "$MCP_TARGET"
  end_case
}

case_ldd_banned_link() {
  begin_case ldd-banned-link
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" FAKE_LDD_HITS=1 FAKE_LDD_HITS_BIN=cass || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "ldd shows 1 onnx/ort links"
  assert_no_path "$CLI_TARGET"
  assert_no_path "$MCP_TARGET"
  end_case
}

case_version_mismatch() {
  begin_case version-mismatch
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" FAKE_VERSION_CLI="cass 0.6.16" || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "expected 'cass 0.6.17'"
  assert_no_path "$CLI_TARGET"
  assert_no_path "$MCP_TARGET"
  end_case
}

case_source_commit_changed() {
  begin_case source-commit-changed
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" FAKE_POST_ROOT=commit || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "source commit changed during the builds"
  assert_no_path "$CLI_TARGET"
  assert_no_path "$MCP_TARGET"
  end_case
}

case_source_dirty() {
  begin_case source-dirty
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" FAKE_POST_ROOT=dirty || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "is not clean after the builds"
  assert_no_path "$CLI_TARGET"
  assert_no_path "$MCP_TARGET"
  end_case
}

case_paired_success() {
  begin_case paired-success
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" || rc=$?
  assert_rc_zero "$rc"
  assert_file "$CLI_TARGET"
  assert_file "$MCP_TARGET"
  assert_exec "$CLI_TARGET"
  assert_exec "$MCP_TARGET"
  local built_cli built_mcp published_cli published_mcp src_commit pair_line
  built_cli=$(sha_of "$CASE_DIR/fork/target/release/cass")
  built_mcp=$(sha_of "$CASE_DIR/fork/mcp/target/release/cass-mcp")
  published_cli=$(sha_of "$CLI_TARGET")
  published_mcp=$(sha_of "$MCP_TARGET")
  assert_eq "$published_cli" "$built_cli" "published CLI sha256"
  assert_eq "$published_mcp" "$built_mcp" "published MCP sha256"
  src_commit=$("$REAL_GIT" -C "$CASE_DIR/fork" rev-parse HEAD)
  pair_line=$(grep '^PAIR_OK ' "$CASE_DIR/setup.log" | tail -1)
  [ -n "$pair_line" ] || case_fail "missing PAIR_OK record"
  printf '%s\n' "$pair_line" > "$CASE_DIR/pair-ok.txt"
  assert_contains "$CASE_DIR/pair-ok.txt" "source_commit=$src_commit"
  assert_contains "$CASE_DIR/pair-ok.txt" "cass_version=0.6.17"
  assert_contains "$CASE_DIR/pair-ok.txt" "mcp_version=0.6.17"
  assert_contains "$CASE_DIR/pair-ok.txt" "cass_sha256=$built_cli"
  assert_contains "$CASE_DIR/pair-ok.txt" "mcp_sha256=$built_mcp"
  assert_contains "$CASE_DIR/pair-ok.txt" "cli_strings_hits=0"
  assert_contains "$CASE_DIR/pair-ok.txt" "cli_ldd_hits=0"
  assert_contains "$CASE_DIR/pair-ok.txt" "mcp_strings_hits=0"
  assert_contains "$CASE_DIR/pair-ok.txt" "mcp_ldd_hits=0"
  assert_no_stage "$(dirname "$CLI_TARGET")"
  assert_no_stage "$(dirname "$MCP_TARGET")"
  assert_contains "$CASE_DIR/cargo-calls.log" "build --release --locked --no-default-features --features qr,encryption"
  assert_contains "$CASE_DIR/cargo-calls.log" "build --release --locked --manifest-path mcp/Cargo.toml"
  assert_eq "$(log_lines "$CASE_DIR/cargo-calls.log")" 2 "cargo invocations"
  end_case
}

case_second_publish_fail() {
  begin_case second-publish-fail
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" MCP_INSTALL_PATH="$MCP_TARGET" FAKE_LN_FAIL_DEST="$MCP_TARGET" || rc=$?
  assert_rc_nonzero "$rc"
  assert_contains "$CASE_DIR/setup.log" "ln -T refused to publish"
  assert_file "$CLI_TARGET"
  assert_no_path "$MCP_TARGET"
  assert_not_contains "$CASE_DIR/setup.log" "PAIR_OK"
  assert_no_stage "$(dirname "$CLI_TARGET")"
  assert_no_stage "$(dirname "$MCP_TARGET")"
  end_case
}

case_old_single_cli() {
  begin_case old-single-cli
  mkdir -p "$(dirname "$CLI_TARGET")"
  printf 'old-binary\n' > "$CLI_TARGET"
  local rc=0
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" || rc=$?
  assert_rc_zero "$rc"
  assert_file "$CLI_TARGET"
  assert_file "$CLI_TARGET.prev"
  assert_eq "$(cat "$CLI_TARGET.prev")" "old-binary" "backup content"
  assert_eq "$("$CLI_TARGET" --version)" "cass 0.6.17" "installed version"
  assert_eq "$(log_lines "$CASE_DIR/cargo-calls.log")" 1 "cargo invocations"
  assert_not_contains "$CASE_DIR/cargo-calls.log" "--manifest-path"
  assert_no_path "$CASE_DIR/fork/mcp/target"
  assert_not_contains "$CASE_DIR/setup.log" "PAIR_OK"
  end_case
}

case_old_mode_cargo_target_dir_not_rejected() {
  begin_case old-mode-cargo-target-dir-not-rejected
  local rc=0
  # Mock limitation: the fake cargo ignores CARGO_TARGET_DIR, so this case only
  # proves the new paired-mode rejection did not leak into legacy mode.
  run_setup "$CASE_DIR" INSTALL_PATH="$CLI_TARGET" CARGO_TARGET_DIR="$CASE_DIR/ctd" || rc=$?
  assert_rc_zero "$rc"
  assert_not_contains "$CASE_DIR/setup.log" "MCP_INSTALL_PATH is set but CARGO_TARGET_DIR"
  assert_file "$CLI_TARGET"
  end_case
}

# ---------------------------------------------------------------------------
# Run all cases
# ---------------------------------------------------------------------------
case_old_missing_install
case_paired_relative
case_paired_same_normalized
case_paired_existing_file
case_paired_existing_dir
case_paired_dangling_symlink
case_paired_target_dir_empty
case_paired_target_dir_set
case_root_build_fail
case_mcp_build_fail_after_cli
case_strings_probe_fail
case_strings_banned_symbol
case_ldd_probe_fail
case_ldd_banned_link
case_version_mismatch
case_source_commit_changed
case_source_dirty
case_paired_success
case_second_publish_fail
case_old_single_cli
case_old_mode_cargo_target_dir_not_rejected

TOTAL=$((PASS + FAIL))
printf '\nTEST_SUMMARY total=%s pass=%s fail=%s\n' "$TOTAL" "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
  printf 'FAILED_CASES %s\n' "${FAILED[*]}"
  exit 1
fi
printf 'ALL_CASES_PASS\n'
exit 0
