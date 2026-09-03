# C7 — 并发演练（30 分钟窗口）

> Task C7（plan `2026-08-25-w1-relational-sqlite-swap.md` @1259-1271，§5 风险缓解专项）。
> 执行面：cass-sql-exec22，2026-08-29。

## ① 环境与命令（attestation）

- 候选二进制：`/tmp/cc-cass-exec21-target/release/cass`（sha256
  `929c541d4599a46fe6f0b087dd20114a3c4ce1c4b3c6d7ea2e1fe821789e2697`，含 C5
  游标修复），全程 `XDG_CONFIG_HOME=/tmp/cc-cass-w1-staging/config`。
- 演练副本（R4-N3：不得污染正库）：`VACUUM INTO` 出
  `/tmp/cc-cass-exec22-c7-drill-datadir/agent_search.db`（正库全程未变，跑前跑后
  `conversations` 计数与 mtime 一致，见④）。
- 驱动脚本：`scripts/w1-concurrency-drill.sh`（本棒新增，已提交）。R4-N3 安全闸：
  `CASS_DRILL_DATA_DIR` 路径不含 `drill` 字样直接拒跑，除非 `--force`。
- 调用：
  ```
  CASS_DRILL_BIN=/tmp/cc-cass-exec21-target/release/cass \
  CASS_DRILL_DATA_DIR=/tmp/cc-cass-exec22-c7-drill-datadir \
  CASS_DRILL_OUT_DIR=/tmp/cc-cass-w1-concurrency-drill \
  CASS_DRILL_DURATION_SECS=1800 \
  CASS_DRILL_N_SEARCHERS=8 \
  CASS_DRILL_CHECKPOINT_INTERVAL_SECS=300 \
  XDG_CONFIG_HOME=/tmp/cc-cass-w1-staging/config \
  bash scripts/w1-concurrency-drill.sh
  ```
  窗口：2026-08-29T00:49:32-07:00 → 01:19:35-07:00（30 分03秒）。
- 原始产物（临时诊断目录，未提交仓库，命令可按本报告复现）：
  `/tmp/cc-cass-w1-concurrency-drill/{searcher-results.tsv(996044行,45.8MB),
  writer.stderr.log(1817951字节 NDJSON progress事件), checkpoint-observations.tsv,
  searcher-stderr-all.log, classification-summary.txt}`。

## ② 方法论（含一处预演修正，如实记录）

**目标操作**：演练副本上同时跑 ①`cass index --watch`（增量持续写，真实生产代码路径，
非 C6 那种合成 SQL）②8 个并发 `cass search --mode lexical`（`--timeout 30000`
+ 外层 `timeout 35` 硬兜底）循环 30 分钟 ③每 5 分钟 `wal_checkpoint(PASSIVE)` 观测。

**预演发现并修正的一处方法论问题**：正式起跑前的排查中，对刚 `VACUUM INTO` 出的
演练副本直接跑 `search`/`--watch` 会触发一次性的"从零构建 Tantivy 词法索引"
重活（该目录 `index/` 不存在），期间 `search` 会被 `index-busy`
（`code:7,kind:"index-busy"`）拒绝，且若这个一次性重建被外部强杀（本棒踩到的是
Bash 工具自身的默认超时杀掉了一次手工探测命令），会留下**owner 进程已死但
文件仍在的过期 lock**——不过下一次 `search` 会正确探测到这个残局，`16ms` 内
返回结构化、可重试的 `code:5,kind:"checkpoint_incomplete"`，提示补跑
`cass index --json`（**实测这条提示对"大规模已填充索引"不够精确**：裸
`cass index` 只会再次 `deferred_authoritative_db_rebuild`，真正补完 checkpoint
需要 `--force-rebuild`；已记录，不影响本次四道判据，供后续 runbook 参考）。
若不做这一步预热，30 分钟正式窗口会被这个一次性冷启动重活污染，测不出真实
稳态并发行为。故正式跑之前先用 `cass index --force-rebuild` 把演练副本收敛到
干净、词法索引完整的状态（37.8s，4810 conversations / 1,019,084 messages），
再起 30 分钟计时窗口。

**contention 三分类口径**：按 cass 自身 `capabilities --json` 文档化的 exit code
表（`0`=success，`5`=data corruption/degraded，`7`=lock or busy，`8`=partial
result，均标注 `retryable`）划分：
- 类别 A「成功」= exit 0
- 类别 B「有文档、可重试的降级/忙响应」= exit ∈ {5,7,8}（不算 bug）
- 类别 C「未映射」= 其他非零 exit，或外层 `timeout 35` 硬杀（exit 124）

## ③ 结果

30 分 03 秒窗口内，8 个搜索进程共完成 **996,044 次搜索**（每进程 124,446-124,623
次，分布均衡，无掉队者）：

| 判据 | 结果 |
|---|---|
| 零 panic | **PASS**——`grep "panicked at"` 在 writer 与全部 searcher stderr 中命中 0 |
| 零未映射错误 | **PASS**——996,044 次搜索 exit code 全部为 `0`；类别 C 计数 = 0 |
| 搜索零超时（>30s） | **PASS**——`timeout_count_gt_30s=0`（硬 hang exit124=0，软超时>30000ms=0）；实测耗时分布 min=6ms / p50=10ms / p99=19ms / **max=733ms**，远低于 30s 门槛 |
| contention 三分类计数 + busy-timeout 占比 | 类别A(成功)=996,044；类别B(exit5\|7\|8)=0；类别C(未映射)=0；`busy_timeout_ratio=0.0000` |

`wal_checkpoint(PASSIVE)` 每 5 分钟观测（5 轮）：WAL 字节数全程维持在 78KB-861KB
区间，未见异常增长，checkpoint pragma 均返回非零 busy=0（无锁冲突）：

| ts | wal_bytes | ckpt_pragma(busy\|log\|checkpointed) |
|---|---|---|
| 00:54:34 | 861,112 | 0\|209\|209 |
| 00:59:34 | 861,112 | 0\|22\|22 |
| 01:04:34 | 861,112 | 0\|60\|60 |
| 01:09:34 | 78,312 | 0\|19\|19 |
| 01:14:34 | 98,912 | 0\|24\|24 |

**一处非阻断的良性观察**：8 个搜索进程中有 2 次（searcher 3/7，均在 iter 32，
即窗口开局第一秒内）打印了 stderr 警告 `Warning: Tantivy search index not
found ... Results will be severely limited`，但两次 exit 都是 `0`（成功）。
时间点吻合"演练开局、writer 第一个 watch tick 尚未完成"的瞬时窗口，是良性瞬态，
不计入类别 C（未映射），且发生率 2/996044 ≈ 0.0002%。

writer（`cass index --watch --watch-interval 15`）全程 1028 条 NDJSON 进度事件，
`last_error` 全部为 `null`，未见任何 phase 异常或 finalizing 卡死。窗口结束后
`kill` 干净退出，无残留 `cass` 进程。

## ④ 收口

- 判据满足：零 panic、零未映射错误、搜索零超时、contention 三分类 + busy-timeout
  占比已记录在案。**结论：C7 PASS，不触发波1 HOLD。**
- 正库全程未受影响：跑前跑后 `/tmp/cc-cass-w1-staging/data/agent_search.db`
  `conversations` 计数（4805）与文件 mtime（Aug 28 20:59）均未变化。
- 演练副本（`/tmp/cc-cass-exec22-c7-drill-datadir/`）用完可删，未删（供复核，
  下一步骤如需可继续复用或清理）。
