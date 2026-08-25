#!/bin/bash
# scripts/w1-disk-guard.sh <阈值GB> <被守卫的PID>
# 契约（R0-B6）：被守卫进程必须由调用方用 `setsid <cmd> &` 启动，使其持有独立 PGID；
# 守卫杀组前断言目标 PGID 既非自身 PGID 也非自身 SID 所在组，防止把执行会话一起杀掉。
set -u
FLOOR_GB=${1:?}; GUARD_PID=${2:?}
SELF_PGID=$(ps -o pgid= -p $$ | tr -d ' ')
SELF_SID=$(ps -o sid= -p $$ | tr -d ' ')
while kill -0 "$GUARD_PID" 2>/dev/null; do
  avail=$(df --output=avail -BG /tmp | tail -1 | tr -dc 0-9)
  if [ "$avail" -lt "$FLOOR_GB" ]; then
    TGT_PGID=$(ps -o pgid= -p "$GUARD_PID" | tr -d ' ')
    TGT_SID=$(ps -o sid= -p "$GUARD_PID" | tr -d ' ')
    if [ -z "$TGT_PGID" ] || [ "$TGT_PGID" = "$SELF_PGID" ] || [ "$TGT_SID" = "$SELF_SID" ]; then
      echo "DISK-FLOOR-BREACH but target pgid unsafe (tgt=$TGT_PGID self=$SELF_PGID); killing single pid" >&2
      kill -TERM "$GUARD_PID"; exit 1
    fi
    echo "DISK-FLOOR-BREACH: ${avail}G < ${FLOOR_GB}G, killing pgid $TGT_PGID" >&2
    kill -TERM -- "-$TGT_PGID"    # 注意 `--`，procps 3.3.17 组杀坑
    exit 1
  fi
  sleep 20
done
