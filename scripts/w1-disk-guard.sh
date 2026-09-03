#!/bin/bash
# scripts/w1-disk-guard.sh <阈值GB> <被守卫的PID>
# 契约（R0-B6）：被守卫进程必须由调用方用 `setsid <cmd> &` 启动，使其持有独立 PGID；
# 守卫杀组前断言目标 PGID 既非自身 PGID 也非自身 SID 所在组，防止把执行会话一起杀掉。
set -u
FLOOR_GB=${1:?}; GUARD_PID=${2:?}
# R3-N3: PGID 降级路径（下面 unsafe 分支）此前只 TERM 掉 GUARD_PID 本身。
# GUARD_PID 是包着 cargo 的 wrapper（通常是 bash），真正吃盘的是它 fork 出的
# cargo/rustc 子进程；wrapper 一死，这些子进程被 init 收养继续跑，磁盘守卫
# 已经退出、没人再管。降级路径本来就是因为 PGID 不可信才不敢做组杀，但至少
# 该把 wrapper 自己的子进程树显式枚举出来一并杀掉。
collect_descendants() {
  local frontier="$1" all="" next children
  while [ -n "$frontier" ]; do
    next=""
    for pid in $frontier; do
      children=$(pgrep -P "$pid" 2>/dev/null || true)
      if [ -n "$children" ]; then
        all="$all $children"
        next="$next $children"
      fi
    done
    frontier="$next"
  done
  printf '%s' "$all"
}

SELF_PGID=$(ps -o pgid= -p $$ | tr -d ' ')
SELF_SID=$(ps -o sid= -p $$ | tr -d ' ')
while kill -0 "$GUARD_PID" 2>/dev/null; do
  avail=$(df --output=avail -BG /tmp | tail -1 | tr -dc 0-9)
  if [ "$avail" -lt "$FLOOR_GB" ]; then
    TGT_PGID=$(ps -o pgid= -p "$GUARD_PID" | tr -d ' ')
    TGT_SID=$(ps -o sid= -p "$GUARD_PID" | tr -d ' ')
    if [ -z "$TGT_PGID" ] || [ "$TGT_PGID" = "$SELF_PGID" ] || [ "$TGT_SID" = "$SELF_SID" ]; then
      descendants=$(collect_descendants "$GUARD_PID")
      echo "DISK-FLOOR-BREACH but target pgid unsafe (tgt=$TGT_PGID self=$SELF_PGID); killing pid tree ($GUARD_PID$descendants)" >&2
      kill -TERM "$GUARD_PID" $descendants 2>/dev/null
      sleep 1
      kill -KILL "$GUARD_PID" $descendants 2>/dev/null
      exit 1
    fi
    echo "DISK-FLOOR-BREACH: ${avail}G < ${FLOOR_GB}G, killing pgid $TGT_PGID" >&2
    kill -TERM -- "-$TGT_PGID"    # 注意 `--`，procps 3.3.17 组杀坑
    exit 1
  fi
  sleep 20
done
