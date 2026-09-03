# KU1 — checkpoint(TRUNCATE) 时延实测 → 看门狗阈值定档

> Task C6（plan `2026-08-25-w1-relational-sqlite-swap.md` @1238-1257）。
> 执行面：cass-sql-exec22，2026-08-29。

## ① 环境与命令（attestation）

- 宿主：本机 Ubuntu 22.04 工作站，`/` 分区 NVMe SSD（`/dev/nvme1n1p2`），
  跑测时 `df -h /` avail ≈ 598-604G，`uptime` load average ≈ 4.2-4.5
  （`ps --sort=-pcpu` 核对为常驻服务 gunicorn/codegraph/glances 等，非构建撞车）。
- sqlite3 版本：`3.37.2 2022-01-06`（stock 系统二进制，非候选 `cass`）。
- 演练副本产生方式（R4-N3：不得污染已认证正库）：
  ```
  sqlite3 /tmp/cc-cass-w1-staging/data/agent_search.db \
    "VACUUM INTO '/tmp/cc-cass-exec22-drill/agent_search-drill.db';"
  sqlite3 /tmp/cc-cass-exec22-drill/agent_search-drill.db "PRAGMA journal_mode=WAL;"
  ```
  `VACUUM INTO` 只读源库，正库全程未变（跑前跑后 `SELECT COUNT(*) FROM conversations`
  均为 4805，文件 mtime 未变）。**注**：`VACUUM INTO` 产出的新文件默认落在
  `journal_mode=delete`（rollback journal），**不继承**源库的 WAL 设置，跑测前必须
  显式 `PRAGMA journal_mode=WAL;`，否则 `wal_checkpoint` 直接返回 `(0,-1,-1)`
  （代表"不在 WAL 模式"，本棒第一次尝试时踩到，已修正）。
- 驱动脚本：`/tmp/cc-cass-exec22-work/ku1-checkpoint-drill.sh`（临时诊断产物，未提交仓库；
  完整命令与方法论已在本报告全文记录，可按本报告复现）。20 轮原始输出：
  `/tmp/cc-cass-exec22-work/ku1-progress.tsv` + `/tmp/cc-cass-exec22-work/ku1-raw.log`。

## ② 方法论（含两次踩坑与修正，如实记录）

**目标操作**：「批量写入 N 万行 → `wal_checkpoint(TRUNCATE)`」，每轮独立计时，20 轮出分布。

**批大小裁定**：每轮 10 万行（发挥空间内的批次划分裁定，非硬约束数字）。每行 `messages`
表 `content` 字段用 `hex(randomblob(500))`（1000 字节文本），对齐 staging 库
`messages.content` 实测平均长度 1005 字节（`SELECT AVG(LENGTH(content))`），使
WAL 增长量贴近真实索引写入的字节密度。每轮同时写 `fts_messages`（porter tokenizer
FTS5 索引，贴合真实词法索引写入路径的双表写入形态），不只写 `messages` 单表。

**尝试 1（失败，已弃）**：insert 与 checkpoint 分别开两个独立 `sqlite3` 连接
（各自一次 heredoc 调用）。20 轮全部返回 `checkpointed_frames=0`，起初误判为
"WAL 一直是空的"。排查：SQLite 在**最后一个连接关闭时**会自动做一次 checkpoint
（"close checkpoint"，与 `wal_autocheckpoint` 阈值无关）——insert 连接的
`sqlite3` 进程退出时已把 WAL 冲刷干净，等第二个连接再显式 `wal_checkpoint` 时
WAL 早已是空的，测的是"空操作"耗时，不是真实 checkpoint 耗时。

**尝试 2（最终方案）**：insert 与 checkpoint 放进**同一个连接**（同一次 `sqlite3`
heredoc 调用内，insert 事务 `COMMIT` 之后紧跟 `PRAGMA wal_checkpoint(TRUNCATE)`，
再退出），且该连接开局 `PRAGMA wal_autocheckpoint=0`（关闭逐次 commit 后的自动
checkpoint，让 WAL 在整个批次写入期间不受阻拦地增长，对齐生产索引器"批量写入期间
延后 checkpoint 到 finalize 阶段"的模式——见 `src/lib.rs` 里
`index_finalize_abort_threshold` 的文档注释）。用 `.timer on` 测量
checkpoint 这条语句本身的 wall-clock 耗时，用 `.shell ls -la <db>-wal`
在 checkpoint 前后各查一次 WAL 文件字节数作为独立佐证。

**探针验证（发现一处 CLI 展示异常，未影响最终判据）**：`PRAGMA wal_checkpoint(TRUNCATE)`
的返回行三列（busy/log/checkpointed）在本机 sqlite3 3.37.2 下**全程显示 `0|0|0`**，
但同一批次 `.shell ls` 显示 WAL 文件确实从几百 MB truncate 到 0 字节——用文件大小
这个独立信号验证探针（本身可能有问题）之后，判定是这三列在本 CLI 版本下的展示异常
（TRUNCATE 模式下这三列取值有已知的历史古怪行为），**不是"checkpoint 没真的发生"**。
故本报告以 `.timer` 测得的 wall-clock 时间 + WAL 文件字节数前后对照为准，busy/log/
checkpointed 三列原始值仍逐轮记入 `ku1-progress.tsv`（透明记录，供复核）。

## ③ 20 轮原始数据

| round | wal_bytes_before_ckpt | checkpoint_ms | wal_bytes_after_ckpt |
|---|---|---|---|
| 1 | 268,100,792 | 1235.0 | 0 |
| 2 | 432,509,392 | 871.0 | 0 |
| 3 | 308,229,592 | 1447.0 | 0 |
| 4 | 440,452,752 | 1417.0 | 0 |
| 5 | 661,453,672 | 3078.0 | 0 |
| 6 | 594,783,832 | 580.0 | 0 |
| 7 | 547,346,152 | 2487.0 | 0 |
| 8 | 289,388,832 | 835.0 | 0 |
| 9 | 521,637,352 | 1160.0 | 0 |
| 10 | 314,796,872 | 1430.0 | 0 |
| 11 | 494,560,712 | 980.0 | 0 |
| 12 | 287,856,192 | 1388.0 | 0 |
| 13 | 419,107,032 | 1268.0 | 0 |
| 14 | 636,704,832 | 613.0 | 0 |
| 15 | 591,751,512 | 1048.0 | 0 |
| 16 | 610,975,432 | 713.0 | 0 |
| 17 | 672,985,552 | 3147.0 | 0 |
| 18 | 502,899,592 | 2101.0 | 0 |
| 19 | 298,980,192 | 1381.0 | 0 |
| 20 | 431,747,192 | 1994.0 | 0 |

`wal_after_ckpt` 全部为 0，确认每轮 TRUNCATE 都把 WAL 完全清空（即便 pragma 返回列显示
`0|0|0`，见②的探针验证段）。

## ④ 分布与定档

- n=20，min=580.0ms，**p50=1324.5ms**（第10/11个排序值均值），
  **p99=3147.0ms**（nearest-rank 法，`rank=ceil(0.99×20)=20`，n=20 时等于 max，
  样本量小导致 p99≈max 是已知统计现象，如实采用而非另造插值法），
  max=3147.0ms，mean=1458.7ms。
- 公式（plan 预注册）：阈值 = 实测 p99 × 3 = 3147ms × 3 ≈ **9.441s**。
- **下限**：现值 1800s（`CASS_INDEX_FINALIZE_ABORT_SECS` 默认值，不降防误杀）。
- **最终阈值 = max(9.441s, 1800s) = 1800s（不变）**。

**为什么"不变"是正确结论，不是测试失效**：`src/lib.rs` 里
`index_finalize_abort_threshold` 现有文档注释引用的 #319 报告实际场景是
**~1.1GB / ~29万帧 WAL**，且明确点名"尤其是 macOS，Darwin fsync/flock 慢"。
本次 20 轮实测的 WAL 规模在 268MB-673MB 区间（比 #319 场景小 2-4 倍），且跑在
本机 Linux NVMe 上（fsync 远快于 Darwin）——本地测得的 checkpoint 耗时（最慢一轮
3.1s）系统性地低估了 #319 那种大 WAL + 慢磁盘的真实最坏情形。1800s 这个下限本来
就是为覆盖那类场景设的安全垫，本次测量没有提供推翻它的证据，维持现值即是公式
按设计运作的结果，不是"测量白做了"。

## ⑤ 结论

- `INDEX_FINALIZE_ABORT_SECS_DEFAULT` 保持 `1800`（秒），代码位置
  `src/lib.rs::index_finalize_abort_threshold`（新增具名常量替换原先内联字面量
  `1800`，注释指回本报告）；`src/indexer/mod.rs` 两处相关文档注释同步补充指向
  本报告的指针。
- 阈值常量单测：`indexer_finalize_abort_threshold_tests::default_threshold_hits_real_code_path_and_honors_ku1_floor`
  ——调用真实 `index_finalize_abort_threshold()` 函数（非只读常量字面量），断言
  返回值 == 具名常量、且常量 ≥ 实测 p99×3、且常量 ≥ 旧值 1800s。
- 判据满足：「常量 ≥ 实测 p99×3 且 ≥ 旧值」——1800 ≥ 9.441 且 1800 ≥ 1800，两者成立。
