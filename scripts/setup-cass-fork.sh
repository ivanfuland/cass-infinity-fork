#!/usr/bin/env bash
# setup-cass-fork.sh — 从零 bootstrap CASS-on-Infinity fork 的可运行 release 二进制。
# 幂等：重复跑安全。新机可直接跑（自动 clone fork + asupersync）。
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
INSTALL_PATH="${INSTALL_PATH:-$HOME/.local/bin/cass-infinity}"
FEATURES="qr,encryption,infinity"

step() { printf '\n=== %s ===\n' "$1"; }
die()  { printf 'FAIL[%s]: %s\n' "$1" "$2" >&2; exit 1; }

step "1/7 fork repo @ $FORK_REF"
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

step "2/7 asupersync sibling @ pinned rev (path dep; contract forbids git/rev)"
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

step "3/7 toolchain (rust-toolchain.toml in FORK_DIR pins nightly)"
command -v cargo >/dev/null || die toolchain "cargo not found (install rustup)"
( cd "$FORK_DIR" && rustup show active-toolchain 2>/dev/null | grep -q nightly ) \
  || die toolchain "active toolchain in FORK_DIR is not nightly (rust-toolchain.toml missing?)"

step "4/7 release build (ORT-free: features=$FEATURES, semantic OFF; build.rs runs the dep-source contract here)"
( cd "$FORK_DIR" && cargo build --release --no-default-features --features "$FEATURES" ) \
  || die build "cargo build failed (if 'dependency source contract violation' -> asupersync must be path ../asupersync, no git/rev)"
BIN="$FORK_DIR/target/release/cass"
[ -x "$BIN" ] || die build "release binary not produced at $BIN"

step "5/7 verify ZERO ONNX (the whole point)"
# 注意：set -e 下 `n=$(strings|grep -c)` 在 0 匹配（grep rc=1，正是我们要的好情况）会让赋值失败而退出。
# 故先把 strings 写临时文件并检查其 rc，再用 `|| true` 包住 grep -c。
str_tmp=$(mktemp)
strings "$BIN" > "$str_tmp" || { rm -f "$str_tmp"; die verify "strings failed on $BIN"; }
n=$(grep -cE 'onnxruntime|ort_sys' "$str_tmp" || true)
rm -f "$str_tmp"
[ "$n" = "0" ] || die verify "binary has $n ONNX symbols; expected 0 (did semantic feature leak in?)"
# w1b Task B1 (R0-B08): the old `ldd ... 2>/dev/null | grep -qiE 'onnx|ort'` swallowed
# ldd's own failure (e.g. "not a dynamic executable") into a false PASS -- if ldd
# itself errored, grep saw no input, found no match, and the `if` never fired.
# Split into an explicit rc check (HOLD, not pass, on probe failure) and count the
# same anchored `onnxruntime|ort_sys` pattern used above (not the bare `onnx|ort`
# substring, which false-positives on help text).
ldd_rc=0
ldd_out=$(ldd "$BIN" 2>&1) || ldd_rc=$?
if [ $ldd_rc -ne 0 ]; then die verify "ldd probe itself failed (rc=$ldd_rc) — HOLD, not pass"; fi
onnx_hits=$(printf '%s' "$ldd_out" | grep -cE 'onnxruntime|ort_sys' || true)
[ "$onnx_hits" = "0" ] || die verify "ldd shows $onnx_hits onnx/ort links"

step "6/7 backup current install (rollback point)"
if [ -e "$INSTALL_PATH" ]; then cp -a "$INSTALL_PATH" "$INSTALL_PATH.prev"; fi

step "7/7 install (atomic via temp+mv)"
mkdir -p "$(dirname "$INSTALL_PATH")"
cp "$BIN" "$INSTALL_PATH.tmp" && mv -f "$INSTALL_PATH.tmp" "$INSTALL_PATH"
printf '\nOK: ONNX-free CASS-on-Infinity installed -> %s\n' "$INSTALL_PATH"
"$INSTALL_PATH" --version
