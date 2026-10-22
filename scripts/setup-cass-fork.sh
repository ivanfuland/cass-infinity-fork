#!/usr/bin/env bash
# setup-cass-fork.sh — 从零 bootstrap CASS API-only fork 的可运行 release 二进制。
# 幂等：重复跑安全。新机可直接跑（自动 clone fork + asupersync）。
#
# 两种模式：
#   - 默认（MCP_INSTALL_PATH 未设置或为空）：只构建/核验/安装 CLI，旧行为不变。
#   - 配套（MCP_INSTALL_PATH 非空）：从同一冻结提交分别构建根 CLI 与 mcp/ 独立包，
#     两件全部核验后才发布到全新的候选路径，不覆盖既有文件。
set -euo pipefail

FORK_REPO="${FORK_REPO:-https://github.com/ivanfuland/cass-infinity-fork.git}"
FORK_REF="${FORK_REF:-infinity-main}"
# 专用 build clone（**不是**开发 worktree）：setup 自管这个目录的 checkout 状态，
# 在此 detach/build 不影响你开发用的 `~/projects/coding_agent_session_search-spike-infinity`。
# 放在 ~/projects 下，使 `../asupersync` 与开发 worktree 共享同一个 `~/projects/asupersync` sibling（不重复 463MB）。
FORK_DIR="${FORK_DIR:-$HOME/projects/cass-infinity-build}"
ASUPERSYNC_REPO="https://github.com/Dicklesworthstone/asupersync"
ASUPERSYNC_REV="e136c5da4547a44cec3201ada6d94325a7ca216b"
ASUPERSYNC_DIR="$(dirname "$FORK_DIR")/asupersync"   # 必须是 FORK_DIR 的 ../asupersync sibling
INSTALL_PATH="${INSTALL_PATH:-}"
MCP_INSTALL_PATH="${MCP_INSTALL_PATH:-}"
FEATURES="qr,encryption"
EXPECTED_CASS_VERSION="0.6.17"
EXPECTED_MCP_VERSION="0.6.17"

PAIRED=0
[ -n "$MCP_INSTALL_PATH" ] && PAIRED=1
if [ "$PAIRED" = 1 ]; then STEPS=8; else STEPS=7; fi

step() { printf '\n=== %s ===\n' "$1"; }
die()  { printf 'FAIL[%s]: %s\n' "$1" "$2" >&2; exit 1; }
is_abs() { case "$1" in /*) return 0 ;; *) return 1 ;; esac; }

# Require an explicit destination before cloning, fetching or building anything.
[ -n "$INSTALL_PATH" ] || die install-path 'INSTALL_PATH is required; select an explicit candidate binary path'

# ---- 配套模式预检：任何 clone/fetch/build/发布之前完成 ----------------------
if [ "$PAIRED" = 1 ]; then
  # 调用方设置的 CARGO_TARGET_DIR 会把一个或两个 release 产物挪离下面写死的取件路径。
  # 直接拒绝（包括空值），不隐式 unset 调用方配置；正式调用方须显式 env -u CARGO_TARGET_DIR。
  if [ "${CARGO_TARGET_DIR+x}" = x ]; then
    die paired-env "MCP_INSTALL_PATH is set but CARGO_TARGET_DIR is also set ('${CARGO_TARGET_DIR}'); run with env -u CARGO_TARGET_DIR"
  fi
  is_abs "$INSTALL_PATH" || die paired-path "INSTALL_PATH must be absolute in paired mode: $INSTALL_PATH"
  is_abs "$MCP_INSTALL_PATH" || die paired-path "MCP_INSTALL_PATH must be absolute in paired mode: $MCP_INSTALL_PATH"
  for t in "$INSTALL_PATH" "$MCP_INSTALL_PATH"; do
    # -L 单独判定断链：断链时 -e 为假，但仍占用该落点。
    if [ -e "$t" ] || [ -L "$t" ]; then
      die paired-target "paired candidate already exists (file, directory or dangling symlink): $t"
    fi
  done
  mkdir -p "$(dirname "$INSTALL_PATH")" "$(dirname "$MCP_INSTALL_PATH")" \
    || die paired-path "cannot create candidate parent directory"
  cli_parent=$(cd "$(dirname "$INSTALL_PATH")" && pwd -P)
  mcp_parent=$(cd "$(dirname "$MCP_INSTALL_PATH")" && pwd -P)
  CLI_DEST="$cli_parent/$(basename "$INSTALL_PATH")"
  MCP_DEST="$mcp_parent/$(basename "$MCP_INSTALL_PATH")"
  [ "$CLI_DEST" != "$MCP_DEST" ] || die paired-path "INSTALL_PATH and MCP_INSTALL_PATH resolve to the same target: $CLI_DEST"
fi

step "1/$STEPS fork repo @ $FORK_REF"
if [ ! -d "$FORK_DIR/.git" ]; then
  git clone "$FORK_REPO" "$FORK_DIR" || die clone-fork "fork clone failed"
fi
git -C "$FORK_DIR" remote get-url origin | grep -q cass-infinity-fork \
  || die fork-remote "$FORK_DIR origin is not cass-infinity-fork (wrong dir?)"
[ -z "$(git -C "$FORK_DIR" status --porcelain)" ] \
  || die fork-dirty "$FORK_DIR has uncommitted changes; commit/stash first"
git -C "$FORK_DIR" fetch --quiet origin "$FORK_REF" || die fetch-fork "fork fetch failed"
git -C "$FORK_DIR" checkout --quiet "$FORK_REF" 2>/dev/null || true   # 尽量到命名分支以便 ahead 判断
# 防御：这是专用 build clone，不该有本地开发。若意外 ahead（有未推送 commit）则停手，避免悄悄丢提交。
# FETCH_HEAD = 刚 fetch 的 origin/$FORK_REF（branch/tag 通用）。
ahead=$(git -C "$FORK_DIR" rev-list --count "FETCH_HEAD..HEAD" 2>/dev/null || echo 0)
[ "$ahead" = "0" ] || die fork-ahead "$FORK_DIR（build clone）有 $ahead 未推送 commit；它不该被用来开发，请清理或删后重 clone"
# 构建**精确的 fetched ref**（detached）：覆盖本地落后 origin（ahead=0 behind>0）时构建旧 HEAD 的情况。
# 此处 detached HEAD 无害——FORK_DIR 是 build mirror，非开发 worktree。
git -C "$FORK_DIR" checkout --quiet --detach FETCH_HEAD || die checkout-fork "checkout FETCH_HEAD failed"
if [ "$PAIRED" = 1 ]; then
  SRC_COMMIT=$(git -C "$FORK_DIR" rev-parse HEAD) || die source-commit "cannot resolve HEAD in $FORK_DIR"
  FETCHED_COMMIT=$(git -C "$FORK_DIR" rev-parse FETCH_HEAD) || die source-commit "cannot resolve FETCH_HEAD in $FORK_DIR"
  [ "$SRC_COMMIT" = "$FETCHED_COMMIT" ] \
    || die source-commit "checked out HEAD ($SRC_COMMIT) != fetched commit ($FETCHED_COMMIT)"
fi

step "2/$STEPS asupersync sibling @ pinned rev (path dep; contract forbids git/rev)"
# 注意：会 checkout 共享的 ~/projects/asupersync 到 pinned rev。**不要**与另一个正在用同一
# path dep（开发 worktree 的 cargo build）并发跑 setup——asupersync 恒在 pinned rev 故通常 no-op，
# 但并发 checkout + 编译同一源目录有竞态。串行执行即可。
if [ ! -d "$ASUPERSYNC_DIR/.git" ]; then
  git clone "$ASUPERSYNC_REPO" "$ASUPERSYNC_DIR" || die clone-asupersync "asupersync clone failed (463MB; check network)"
fi
git -C "$ASUPERSYNC_DIR" fetch --quiet origin || true
git -C "$ASUPERSYNC_DIR" checkout --quiet "$ASUPERSYNC_REV" || die pin-asupersync "asupersync rev checkout failed"
grep -q '^version = "0.3.5"' "$ASUPERSYNC_DIR/Cargo.toml" || die pin-asupersync "asupersync not version 0.3.5 at pinned rev"
# 契约 preflight：build.rs 只禁 git/rev，不校验 path 值——绝对 path 在本机假绿、换机断。
# 显式断言相对 ../asupersync（可移植），且无 git/rev。
grep -Eq 'asupersync = \{[^}]*path = "\.\./asupersync"' "$FORK_DIR/Cargo.toml" \
  || die contract-preflight 'Cargo.toml asupersync 必须是 path = "../asupersync"（相对、可移植）'
grep -E 'asupersync = \{' "$FORK_DIR/Cargo.toml" | grep -qE '(git|rev) =' \
  && die contract-preflight 'asupersync 依赖带了 git/rev——build.rs 契约会拒，必须纯 path' || true

step "3/$STEPS toolchain (rust-toolchain.toml in FORK_DIR pins nightly)"
command -v cargo >/dev/null || die toolchain "cargo not found (install rustup)"
( cd "$FORK_DIR" && rustup show active-toolchain 2>/dev/null | grep -q nightly ) \
  || die toolchain "active toolchain in FORK_DIR is not nightly (rust-toolchain.toml missing?)"

step "4/$STEPS release build (ORT-free: features=$FEATURES, semantic OFF; build.rs runs the dep-source contract here)"
if [ "$PAIRED" = 1 ]; then
  # 配套模式两包都用各自锁文件；--locked 阻止构建期改写 manifest/lock。
  ( cd "$FORK_DIR" && cargo build --release --locked --no-default-features --features "$FEATURES" ) \
    || die build "cargo build failed (if 'dependency source contract violation' -> asupersync must be path ../asupersync, no git/rev)"
else
  ( cd "$FORK_DIR" && cargo build --release --no-default-features --features "$FEATURES" ) \
    || die build "cargo build failed (if 'dependency source contract violation' -> asupersync must be path ../asupersync, no git/rev)"
fi
BIN="$FORK_DIR/target/release/cass"
[ -x "$BIN" ] || die build "release binary not produced at $BIN"

if [ "$PAIRED" = 1 ]; then
  step "5/$STEPS mcp release build (independent mcp/ workspace, own Cargo.lock and target)"
  # mcp/ 是自己的 workspace，产物落在 mcp/target；不从 PATH、debug 或外部 target 取件。
  ( cd "$FORK_DIR" && cargo build --release --locked --manifest-path mcp/Cargo.toml ) \
    || die build-mcp "cargo build failed for mcp/ (independent workspace/lock)"
  MCP_BIN="$FORK_DIR/mcp/target/release/cass-mcp"
  [ -x "$MCP_BIN" ] || die build-mcp "release binary not produced at $MCP_BIN"
fi

# 0-ONNX 探针：strings 与 ldd 各自判 rc，匹配只认锚定符号名，不吞探针失败。
probe_onnx() {
  local bin="$1" label="$2"
  local tmp s_rc n l_rc ldd_out
  tmp=$(mktemp) || die verify "$label: cannot create strings temp file"
  s_rc=0
  strings "$bin" > "$tmp" || s_rc=$?
  if [ "$s_rc" -ne 0 ]; then
    rm -f "$tmp"
    die verify "$label: strings probe itself failed (rc=$s_rc) — HOLD, not pass"
  fi
  n=$(grep -cE 'onnxruntime|ort_sys' "$tmp" || true)
  rm -f "$tmp"
  [ "$n" = "0" ] || die verify "$label: binary has $n ONNX symbols; expected 0 (did semantic feature leak in?)"
  PROBE_STR_HITS="$n"
  l_rc=0
  ldd_out=$(ldd "$bin" 2>&1) || l_rc=$?
  if [ "$l_rc" -ne 0 ]; then die verify "$label: ldd probe itself failed (rc=$l_rc) — HOLD, not pass"; fi
  PROBE_LDD_HITS=$(printf '%s' "$ldd_out" | grep -cE 'onnxruntime|ort_sys' || true)
  [ "$PROBE_LDD_HITS" = "0" ] || die verify "$label: ldd shows $PROBE_LDD_HITS onnx/ort links"
}

if [ "$PAIRED" = 1 ]; then
  step "6/$STEPS verify paired candidates (same source commit, versions, ZERO ONNX)"
  post_commit=$(git -C "$FORK_DIR" rev-parse HEAD) || die source-commit "cannot re-resolve HEAD after the builds"
  [ "$post_commit" = "$SRC_COMMIT" ] \
    || die source-commit "source commit changed during the builds: $SRC_COMMIT -> $post_commit"
  [ -z "$(git -C "$FORK_DIR" status --porcelain)" ] \
    || die fork-dirty "$FORK_DIR is not clean after the builds; refusing to publish"
  cli_version=$("$BIN" --version) || die version "cass --version failed"
  [ "$cli_version" = "cass $EXPECTED_CASS_VERSION" ] \
    || die version "cass --version is '$cli_version', expected 'cass $EXPECTED_CASS_VERSION'"
  mcp_version=$("$MCP_BIN" --version) || die version "cass-mcp --version failed"
  [ "$mcp_version" = "cass-mcp $EXPECTED_MCP_VERSION" ] \
    || die version "cass-mcp --version is '$mcp_version', expected 'cass-mcp $EXPECTED_MCP_VERSION'"
  probe_onnx "$BIN" "cass"; CLI_STR_HITS="$PROBE_STR_HITS"; CLI_LDD_HITS="$PROBE_LDD_HITS"
  probe_onnx "$MCP_BIN" "cass-mcp"; MCP_STR_HITS="$PROBE_STR_HITS"; MCP_LDD_HITS="$PROBE_LDD_HITS"
  printf 'source_commit: %s\n' "$SRC_COMMIT"
  printf 'cass version: %s\n' "$cli_version"
  printf 'cass-mcp version: %s\n' "$mcp_version"
else
  step "5/$STEPS verify ZERO ONNX (the whole point)"
  # 注意：set -e 下 `n=$(strings|grep -c)` 在 0 匹配（grep rc=1，正是我们要的好情况）会让赋值失败而退出。
  # probe_onnx 里先把 strings 写临时文件并检查其 rc，再用 `|| true` 包住 grep -c。
  probe_onnx "$BIN" "cass"
fi

# 配套发布：stage 与目标同父；ln -T 不覆盖；第二件失败时第一件保留，只清本次 stage。
publish_candidate() {
  local src="$1" dest="$2" want_sha="$3" label="$4"
  local parent stage got
  parent=$(dirname "$dest")
  stage=$(mktemp "$parent/.cass-pair-stage.XXXXXX") || die publish "$label: cannot create stage file in $parent"
  if ! cp -p "$src" "$stage"; then rm -f "$stage"; die publish "$label: copy into stage failed"; fi
  if [ ! -x "$stage" ]; then rm -f "$stage"; die publish "$label: staged copy lost the executable bit"; fi
  got=$(sha256sum "$stage" | awk '{print $1}')
  if [ "$got" != "$want_sha" ]; then rm -f "$stage"; die publish "$label: staged SHA256 $got != built SHA256 $want_sha"; fi
  if ! ln -T -- "$stage" "$dest"; then
    rm -f "$stage"
    die publish "$label: ln -T refused to publish $dest (target appeared?); already-published candidates are kept"
  fi
  rm -f "$stage"
  got=$(sha256sum "$dest" | awk '{print $1}')
  [ "$got" = "$want_sha" ] || die publish "$label: published SHA256 $got != built SHA256 $want_sha"
}

if [ "$PAIRED" = 1 ]; then
  step "7/$STEPS publish paired candidates (stage + ln -T; never overwrite)"
  CLI_SHA=$(sha256sum "$BIN" | awk '{print $1}')
  MCP_SHA=$(sha256sum "$MCP_BIN" | awk '{print $1}')
  publish_candidate "$BIN" "$CLI_DEST" "$CLI_SHA" "cass"
  publish_candidate "$MCP_BIN" "$MCP_DEST" "$MCP_SHA" "cass-mcp"
  step "8/$STEPS pair record"
  printf 'PAIR_OK source_commit=%s cass_version=%s mcp_version=%s cass_sha256=%s mcp_sha256=%s cli_strings_hits=%s cli_ldd_hits=%s mcp_strings_hits=%s mcp_ldd_hits=%s\n' \
    "$SRC_COMMIT" "$EXPECTED_CASS_VERSION" "$EXPECTED_MCP_VERSION" "$CLI_SHA" "$MCP_SHA" \
    "$CLI_STR_HITS" "$CLI_LDD_HITS" "$MCP_STR_HITS" "$MCP_LDD_HITS"
  exit 0
fi

step "6/$STEPS backup current install (rollback point)"
if [ -e "$INSTALL_PATH" ]; then cp -a "$INSTALL_PATH" "$INSTALL_PATH.prev"; fi

step "7/$STEPS install (atomic via temp+mv)"
mkdir -p "$(dirname "$INSTALL_PATH")"
cp "$BIN" "$INSTALL_PATH.tmp" && mv -f "$INSTALL_PATH.tmp" "$INSTALL_PATH"
printf '\nOK: ONNX-free CASS API-only installed -> %s\n' "$INSTALL_PATH"
"$INSTALL_PATH" --version
