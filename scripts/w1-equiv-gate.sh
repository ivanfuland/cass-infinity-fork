#!/bin/bash
# scripts/w1-equiv-gate.sh capture <out_dir>
# scripts/w1-equiv-gate.sh compare <baseline_dir> <candidate_dir> <out_dir>
#
# 基线等价门 harness（plan Task 0.2 Step2；EXEC.md 测试门口径 + 磁盘铁律）。
# capture 与 compare 同一脚本、同一 capture_one() 实现，保证两侧口径同构（R0-B02）。
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/cc-cass-w1-target}"
# W1_CARGO_FEATURES 覆盖仅供 fixture 自测使用（fixture crate 没有 qr/encryption/infinity
# 这套 feature）；生产/真库调用一律吃默认值，不覆盖。
FEATURES="${W1_CARGO_FEATURES-"--no-default-features --features qr,encryption,infinity"}"
DISK_FLOOR_GB="${W1_DISK_FLOOR_GB:-40}"

# tree_target_dir <tree_dir>
# 按物理路径派生独立 target dir（同路径每次都拿同一个值，允许合法增量复用；
# 不同路径永不撞名）——见 capture_one 内的踩坑记录：同名同版本 crate 共享
# target dir 时，cargo 会把候选侧构建静默复用成另一路径的旧产物。
tree_target_dir() {
  local real
  real="$(cd "$1" && pwd)"
  echo "${CARGO_TARGET_DIR%/}-$(printf '%s' "$real" | md5sum | cut -c1-8)"
}

usage() {
  cat >&2 <<'EOF'
usage:
  w1-equiv-gate.sh capture <out_dir>
  w1-equiv-gate.sh compare <baseline_dir> <candidate_dir> <out_dir>
EOF
  exit 64
}

# run_guarded <out_dir> <label> <log_file> -- <cmd...>
# 用 pidfile/donefile 而非 bash job 追踪：命令以 setsid 启动新会话（独立 pgid=sid=pid），
# 磁盘守卫按该真实 pid 伴跑；bash 若本身已是 session/pgroup leader，`setsid cmd &` 会
# double-fork 导致 $! 拿到已退出的中间进程 PID（已在 w1-disk-guard.sh 验证中踩过），
# 故改用「子进程自己先把 $$ 写进 pidfile 再 exec/跑」的方式拿真实 PID。
# 打印退出码到 stdout（被杀情形无 donefile 时约定输出 137）。
run_guarded() {
  local out_dir="$1" label="$2" log_file="$3"
  shift 3
  [ "${1:-}" = "--" ] && shift
  local pidfile="$out_dir/.${label}.pid"
  local donefile="$out_dir/.${label}.done"
  rm -f "$pidfile" "$donefile"

  setsid bash -c '
    pidfile="$1"; logfile="$2"; donefile="$3"; shift 3
    echo $$ > "$pidfile"
    "$@" > "$logfile" 2>&1
    echo $? > "$donefile"
  ' _ "$pidfile" "$log_file" "$donefile" "$@" &
  disown

  local waited=0
  while [ ! -s "$pidfile" ] && [ "$waited" -lt 100 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  if [ ! -s "$pidfile" ]; then
    echo "[w1-equiv-gate] FATAL: $label 未能启动（pidfile 未出现）" >&2
    echo 98
    return 0
  fi
  local target_pid
  target_pid=$(cat "$pidfile")

  # 先同步建空文件再 >> 追加：命令若近瞬时完成，backgrounding 与紧接着的 kill 之间
  # 窗口极窄，曾实测复现「guard 来不及跑就被杀，日志文件整个没生成」（true 命令验证）。
  # 不是安全问题（近瞬时命令本就没有磁盘地板可守的窗口），纯为产物齐整。
  : > "$out_dir/disk-guard-${label}.log"
  bash "$SCRIPT_DIR/w1-disk-guard.sh" "$DISK_FLOOR_GB" "$target_pid" \
    >> "$out_dir/disk-guard-${label}.log" 2>&1 &
  local guard_pid=$!

  while [ ! -f "$donefile" ]; do
    if ! kill -0 "$target_pid" 2>/dev/null; then
      break
    fi
    sleep 2
  done
  kill "$guard_pid" 2>/dev/null || true
  wait "$guard_pid" 2>/dev/null || true

  if [ -f "$donefile" ]; then
    cat "$donefile"
  else
    echo "137"
  fi
}

capture_one() {
  # $3 target_dir 可选：compare 模式必须给两侧不同的 target dir（见下方踩坑记录），
  # 不传则用全局默认 $CARGO_TARGET_DIR（capture 单树场景，无碰撞风险）。
  local tree_dir="$1" out_dir="$2" target_dir="${3:-$CARGO_TARGET_DIR}"
  mkdir -p "$out_dir" "$target_dir"

  # 踩坑记录（fixture 验证实测发现，R0-B02 同构口径下的真实风险）：
  # 两个不同源目录若共享同一个 CARGO_TARGET_DIR 且包名+版本相同（compare 模式下
  # baseline/candidate worktree 正是同一个 crate 在不同 commit），cargo 会把候选侧
  # 的构建错误复用成基线侧的旧产物——binary 文件名哈希逐字节相同，候选侧的代码改动
  # 被静默吃掉，等价门会把「候选其实挂了」误判成「候选和基线一样过」（假 PASS 的
  # 根源）。已用最小 fixture crate 复现：同目标目录连续 build 两个不同路径下、
  # 同名同版本的 crate，第二次构建的产物 hash 与第一次完全相同、断言改动未生效。
  # 修法：compare 的两侧各给独立 target 子目录（仍在 CARGO_TARGET_DIR 根下，
  # 满足磁盘铁律「独立 CARGO_TARGET_DIR」的隔离意图），capture 单树调用不受影响。

  # R2-N1 (PR-front code review round 2, control-plane adjudicated 2026-08-26):
  # `env | sort` dumped the entire process environment verbatim, including
  # ambient credentials (API keys/tokens/secrets this session's shell had
  # exported for unrelated tools) into a gate-evidence artifact under a
  # world-readable-by-default temp/artifacts path. Two independent layers:
  # (1) only capture a known-safe whitelist relevant to reproducing the
  # build/env (cargo/rust toolchain knobs, PATH/HOME/LANG/TZ, the disk-law
  # env vars this script itself requires); (2) belt-and-suspenders name-based
  # redaction on whatever *does* get captured, and 0600 perms on the file.
  {
    echo "tree_dir=$tree_dir"
    echo "target_dir=$target_dir"
    ( cd "$tree_dir" && git rev-parse HEAD 2>/dev/null ) || echo "HEAD=<no-git>"
    echo "---env (whitelist: CARGO_*/RUSTFLAGS/RUST_*/PATH/HOME/LANG/LC_*/TZ)---"
    env | sort | grep -E '^(CARGO_[A-Z_]*|RUSTFLAGS|RUST_[A-Z_]*|PATH|HOME|LANG|LC_[A-Z_]*|TZ|W1_[A-Z_]*)=' \
      | sed -E 's/^([A-Za-z_][A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|AUTH|BEARER)[A-Za-z0-9_]*)=.*/\1=<REDACTED>/I'
  } > "$out_dir/env.txt"
  chmod 600 "$out_dir/env.txt"

  echo "[w1-equiv-gate] test-inventory ..." >&2
  ( cd "$tree_dir" && python3 "$SCRIPT_DIR/w1-test-inventory.py" src/ tests/ benches/ 2>"$out_dir/inventory.err" ) \
    | sort > "$out_dir/test-inventory.txt"
  local inv_rc=${PIPESTATUS[0]}
  echo "$inv_rc" > "$out_dir/inventory-rc.txt"
  if [ "$inv_rc" != "0" ]; then
    echo "[w1-equiv-gate] HOLD: test-inventory 自检失败 (rc=$inv_rc)，见 $out_dir/inventory.err" >&2
  fi

  echo "[w1-equiv-gate] 期望 target 数（cargo metadata 独立真值源）..." >&2
  ( cd "$tree_dir" && CARGO_TARGET_DIR="$target_dir" cargo metadata --no-deps --format-version=1 $FEATURES 2>"$out_dir/cargo-metadata.err" ) \
    | python3 -c '
import json, sys
d = json.load(sys.stdin)
n = 0
has_lib = False
for pkg in d.get("packages", []):
    for t in pkg.get("targets", []):
        kinds = set(t.get("kind", []))
        # 注意：不含 "bin"——cargo test（不带 --bins/--all-targets）默认不给 [[bin]]
        # 目标单独起一条 unittests 测试二进制（哪怕包里同时有 lib）；实测本仓 2 个 bin
        # target 全程只出现 1 条 "Running unittests src/lib.rs"，加 bin 计数会把
        # expected 算多 2、跟 started/finished 对不上（真实基线捕获中踩到，243 vs 245）。
        if kinds & {"lib", "test"}:
            n += 1
        if "lib" in kinds:
            has_lib = True
# cargo test 对含 lib target 的包总会跑一个 Doc-tests 阶段（哪怕 0 条 doc test 也打印
# 一行 "test result: ok. 0 passed..."），这是独立于 lib/test kind 计数之外的
# 第 3 类 target——实测验证见 fixture PASS 场景（w1-equiv-gate 冒烟）。
if has_lib:
    n += 1
print(n)
' > "$out_dir/expected-targets.txt"

  echo "[w1-equiv-gate] cargo check --all-targets（磁盘守卫伴跑）..." >&2
  local check_rc
  check_rc=$(run_guarded "$out_dir" "check" "$out_dir/cargo-check.log" -- \
    env -C "$tree_dir" CARGO_TARGET_DIR="$target_dir" cargo check --all-targets $FEATURES)
  echo "$check_rc" > "$out_dir/cargo-check-rc.txt"

  echo "[w1-equiv-gate] cargo test --no-fail-fast --test-threads=1（磁盘守卫伴跑）..." >&2
  local test_rc
  test_rc=$(run_guarded "$out_dir" "test" "$out_dir/cargo-test.log" -- \
    env -C "$tree_dir" CARGO_TARGET_DIR="$target_dir" cargo test $FEATURES --no-fail-fast -- --test-threads=1)
  echo "$test_rc" > "$out_dir/cargo-test-rc.txt"

  echo "[w1-equiv-gate] 失败归一化 ..." >&2
  python3 "$SCRIPT_DIR/w1-normalize-failures.py" \
    "$out_dir/cargo-test.log" "$out_dir/expected-targets.txt" \
    "$out_dir/failures.jsonl" "$out_dir/completeness.json"
}

cmd="${1:-}"
case "$cmd" in
  capture)
    out_dir="${2:-}"
    [ -n "$out_dir" ] || usage
    capture_one "$REPO_ROOT" "$out_dir"
    echo "[w1-equiv-gate] capture 完成，产物在 $out_dir" >&2
    ;;
  compare)
    baseline_dir="${2:-}"; candidate_dir="${3:-}"; out_dir="${4:-}"
    [ -n "$baseline_dir" ] && [ -n "$candidate_dir" ] && [ -n "$out_dir" ] || usage
    mkdir -p "$out_dir"
    echo "[w1-equiv-gate] compare：紧邻串行双跑，同一环境窗口（R0-B7）" >&2
    capture_one "$baseline_dir" "$out_dir/baseline" "$(tree_target_dir "$baseline_dir")"
    capture_one "$candidate_dir" "$out_dir/candidate" "$(tree_target_dir "$candidate_dir")"
    echo "[w1-equiv-gate] 判定 ..." >&2
    python3 "$SCRIPT_DIR/w1-compare-verdict.py" "$out_dir/baseline" "$out_dir/candidate" \
      | tee "$out_dir/verdict.txt"
    exit "${PIPESTATUS[0]}"
    ;;
  *)
    usage
    ;;
esac
