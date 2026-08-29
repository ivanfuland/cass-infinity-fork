# C8 — 波1 四道验收门 attestation

> Task C8（plan @1273-1293）。执行面：cass-sql-exec22，2026-08-29。
> 候选二进制（门②③④用）：`/tmp/cc-cass-exec21-target/release/cass`
> （sha256 `929c541d4599a46fe6f0b087dd20114a3c4ce1c4b3c6d7ea2e1fe821789e2697`，含 C5 修复），
> 全程 `XDG_CONFIG_HOME=/tmp/cc-cass-w1-staging/config`。
> 门①（源码级等价门）对比的候选源码树 HEAD 为最终代码态 `e0facad3`
> （C1-C7 全部提交 + 本门自身发现并修复的一处编译回归）。

## 门① 基线等价 —— PASS（带两条已核实的 C 段新增面例外）

**命令**：
```
scripts/w1-equiv-gate.sh compare \
  /home/ivan/projects/cc-cass-w1-baseline-tree \
  /home/ivan/projects/coding_agent_session_search-w1c \
  /tmp/cc-cass-w1-equiv-gate-exec22
```
基线 HEAD `31628af8`；`CARGO_TARGET_DIR=/tmp/cc-cass-exec22-target`（compare 内部
按树路径派生独立子目录，两侧互不干扰）。

### 第一次跑（发现真实编译回归，HOLD_INCOMPLETE）

PID 3905089，发射 2026-08-29T01:25:15-07:00。候选侧 `cargo check --all-targets`
以 exit 101 失败：
```
error[E0063]: missing field `last_message_id_conversation_id` in initializer of `BuildCheckpoint`
  --> tests/golden_readiness.rs:231:32
```
按「波1 失败处置总则」先验证门本身（此处即 baseline 侧正常完成、候选侧确实编译
失败，非 harness 误判）：定位到 C5 修复 commit `1f2dbe8a` 给 `BuildCheckpoint` 加了
新字段 `last_message_id_conversation_id`、更新了全部**生产代码**调用点，但漏了 3
处**只在集成测试里**构造该结构体字面量的地方——`tests/golden_readiness.rs`、
`tests/lifecycle_matrix.rs`、`tests/search_asset_harness.rs`，三者均不在
`cargo test --lib` 覆盖范围内，此前任何 `--lib` 跑法都测不到，只有 `--all-targets`
才会暴露。三处场景都是「模拟修复前写入的旧 checkpoint」，按该字段自己的文档
注释，`None` 就是这个场景的正确值——纯粹补全字段落地面，不是新的行为决策。
修复 commit `e0facad3`；本地 `cargo check --all-targets` 验证通过后，按规程**重跑
该门全量**（不做增量豁免）。

### 第二次跑（全量重跑，PASS 带两条已核实例外）

PID 31712，发射 2026-08-29T02:24:26-07:00，完成 2026-08-29T03:17:14-07:00
（约 53 分钟）。候选侧对比树 HEAD 已是 `e0facad3`。

**执行完整性**（两侧均 complete，零编译错）：
```
baseline : complete=True started=243 finished=243 expected=243 compile_error=False
candidate: complete=True started=245 finished=245 expected=245 compile_error=False
跨侧 target running 差分对账: True；总和差分校验 OK（cand_sum-base_sum=1 = cand_inv-base_inv=1）
```

**target 数 +2 净差逐一点名核实**（`diff` 两棵树 `tests/*.rs` 目录）：
- 新增（Stage C 自己的新面）：`tests/ingest_manifest.rs`、`tests/ingest_reconcile.rs`
  （d20/d21 落地的 `cass ingest manifest`/`reconcile` 子命令的测试）、
  `tests/query_plan_regression.rs`（本次门②机制性佐证用的那个测试，B9 缺陷A
  思想平移）。
- 删除：`tests/storage_migration_safety.rs`——`git log` 核实系 Stage B 提交
  `eb198177`（"w1b: replace the embedded franken relational engine with rusqlite"）
  主动删除，该文件测的正是 franken 引擎特有的迁移安全性，引擎本身被这次迁移
  退役后随之退役，属于迁移范围内的既定动作，不是意外丢测试。
- 净 +3 新增 -1 删除 = +2，与 target 计数差完全对上。

**失败形态多重集**：baseline 69 条/68 种；candidate 56 条/55 种（净减 13 条，
候选比基线更少失败）。`candidate ⊆ baseline` 按 mode 严格判定为 False，因为有
2 种失败形态是候选独有；逐条人工核实（非盲信 harness 或任何一方转述，含控制面
教练在门跑完后发来的裁决，本节数字与结论均为本执行面独立复核确认）：

1. **`capabilities_matches_golden_contract`**（候选x1 基线x0）：`tests/cli_robot.rs`
   里手写硬编码的"capabilities contract"期望对象，`assert_eq!` 报 drift。逐字节
   比对 `left`(实际)/`right`(期望) 两个巨型 debug repr 字符串，定位到期望对象里
   完全没有 `"ingest"` 这个词（`right.count("ingest")==0`），而实际输出里有且仅有
   一处、结构完整：
   `{"name":"ingest","description":"Staging reingest candidate-inventory and
   coverage tooling (plan v6 Stage C)",...}`。核对 `Commands` 枚举：
   `Ingest(IngestCommand)` 只存在于候选源码（`grep` 基线源码零命中），是 Stage C
   新增的顶层子命令（就是门④用的 `cass ingest manifest`/`reconcile`）。这份硬编码
   contract 测试没跟着 Stage C 的新命令一起更新，是维护欠账，不是候选行为倒退。
   （复核过程中排除了一个我自己的错误猜测：`MirrorRelink` 变体的 doc comment 确实
   有一处"两行黏在一起"的历史遗留小 bug——`grep` 基线源码同一行同一形态逐字节
   相同存在，是继承噪音，与这条候选独有失败无关，不是根因。）
2. **`scripts_rch_compliance_no_bare_cargo`**（候选x1x"3处" 基线x1x"1处"）：
   基线那 1 处是 `scripts/setup-cass-fork.sh:62` 的裸 `cargo build`；候选侧同一处
   照样命中（继承）+ 新增 2 处，均在 `scripts/w1-equiv-gate.sh`（本门自己的 harness
   脚本，非产品代码，本机没有 `rch` 可用，`env ... cargo ...` 是 EXEC.md 明确认可
   的替代形式）：`w1-equiv-gate.sh:171`（`cargo check --all-targets`）与其
   `cargo test` 姊妹行。属工具脚本自身的既有豁免范畴（同 setup-cass-fork.sh 那条
   继承例外同类），非产品行为回归。

`(target_label, 测试名, mode)` 配对多重集判定因 mode 多重集 subset 不成立而跳过
（harness 设计如此，两条独有形态已在上面逐条人工核实覆盖）。

**闭世界清单差集**：新增键 518 / 删除键 517，抽样核对（`src/analytics/query.rs`
的一批 `query_breakdown_*` 用例）系测试标识符里内嵌的内容 hash 后缀随测试体
微调而改变（同一测试名换了哈希后缀，非测试增删），advisory 属性，不参与判定。

**结论**：两条候选独有失败形态均已逐条技术核实，明确归因于 Stage C 自身的
既定新增面（新 `ingest` 命令 + 本门自己的 harness 脚本），符合 plan 预注册的
豁免条款「候选独有形态需对照 run6 谱系——C 段新增测试按新增面归类；rch 池内
例外」。**门① PASS（带两条已核实例外）**。

## 门② 语义回填 ≤1s —— PASS

**命令**（20 次，含 T8 病理查询"记忆"）：
```
cass search "<query>" --mode semantic --model bge-m3 --limit 5 --json --robot-meta \
  --data-dir /tmp/cc-cass-w1-staging/data
```
计时口径：`_meta.elapsed_ms`（与 T2-diagnosis/T8 报告对 52.6 分钟基线所用的同一
字段，apples-to-apples）。T8 病理查询"记忆"取自
`docs/projects/cass-fork/reports/2026-08-24-prod-deploy-incident/`
（`cc-cass-prod-mission.md`/`T2-diagnosis.md` 均记录为同一发"记忆"语义查询）。
20 条查询清单：queryset.json 全部 8 条共享记忆主题查询 + T8 病理查询"记忆" +
11 条补充查询（python/docker/error handling/rust cargo build/git commit
workflow/database schema migration/checkpoint recovery/SSH connection
timeout/vacuum sqlite/并发测试/watchdog threshold）。

| n | query | elapsed_ms |
|---|---|---|
| 1 | 记忆（T8 病理查询） | 162 |
| 2 | 跨 agent 共享记忆的统一方案 | 155 |
| 3 | claude codex openclaw 各 agent 记忆各存一份的问题 | 154 |
| 4 | 夜里定时把对话提炼进知识库的后台流程 | 152 |
| 5 | 只保留最终决策结论丢掉推理过程 | 147 |
| 6 | 知识在 agent 之间即时流动的理想终态 | 148 |
| 7 | 跨项目搜索编程助手历史会话的本地引擎 | 163 |
| 8 | 把提炼好的条目写进知识库后端接口 | 162 |
| 9 | 为什么记忆不能只记在 Claude 自己那里 | 279 |
| 10 | python | 157 |
| 11 | docker | 159 |
| 12 | error handling | 167 |
| 13 | rust cargo build | 175 |
| 14 | git commit workflow | 157 |
| 15 | database schema migration | 164 |
| 16 | checkpoint recovery | 158 |
| 17 | SSH connection timeout | 158 |
| 18 | vacuum sqlite | 158 |
| 19 | 并发测试 | 168 |
| 20 | watchdog threshold | 158 |

分布：min=147ms / p50=158ms / **p95=175ms** / max=279ms / mean=165.1ms。
**p95 175ms ≤ 1000ms 判据，PASS**（对照旧世界 T8/T2-diagnosis 记录的同一发"记忆"
语义查询 52.6 分钟 = 3,157,900ms，约 **18,000 倍**提升）。

机制性佐证：`cargo test --test query_plan_regression --no-default-features
--features qr,encryption,infinity -- --test-threads=1`：
`test result: ok. 2 passed; 0 failed`（`hydrate_by_ids_uses_pk_index` 断言真实走 PK
索引 seek；`hydrate_by_ids_without_pk_index_degrades_to_scan`(`#[should_panic]`)
反向验证探针本身有效——缺 PK 索引的表确实会被判定为退化扫描，说明前一条测试的
PASS 不是探针失灵的假阳性）。**PASS**。

副产物：staging 主库回读到 `_warning: Index may be stale (age: 16144s)`——
纯内容新鲜度提示（自 backfill 完成后约 4.5h 未增量），与本门耗时判据无关；
门④已对此做增量补齐。

## 门③ 新库完整性 —— PASS

stock `/usr/bin/sqlite3`（3.37.2，非候选二进制）对
`/tmp/cc-cass-w1-staging/data/agent_search.db`：

```
PRAGMA integrity_check(1000000);  →  ok（单行，未截断）
PRAGMA foreign_key_check;         →  （空，0 行）
PRAGMA user_version;              →  1
```

三项全过，**PASS**。

## 门④ 重摄覆盖对账（重密封）—— PASS

**根集合裁定**：v4（14 根）→ v5（12 根，Ivan 2026-08-29 裁 GongShi 退役永久排除 +
NAS 根摘除，物理文件已迁 `~/nas/openclaw/retired-GongShi-20260829/`；NAS 相关两条
`--scan-root` 整条从 v5 移除，非仅排除 GongShi 子路径）。清单：
`/tmp/cc-cass-w1-scanroots-v5.txt`（v4 去掉 `nas/openclaw/my-agent-histories`
两条镜像/活源根）。

**重密封 + 补增量 + reconcile**：
```
cass ingest manifest --scan-root <12 根 slug 前缀> \
  --mirror /tmp/cc-cass-w1-staging/mirror --out manifest-v5.jsonl
  → exit 0，6881 行（1 header + 6880 entries），耗时 49.9s

cass index --data-dir /tmp/cc-cass-w1-staging/data --json   # 正库补增量
  → exit 0，86 conversations / 43,367 messages 新增，lexical_strategy=incremental_inline

cass --db .../agent_search.db ingest reconcile \
  --manifest manifest-v5.jsonl --expected-roots scanroots-v5.txt
  → root_set_ok=true; missing=21; unexpected=0; content_mismatch=1739
```

**missing 21 条逐条人审**（G4 口径）：
- **19 条 codex**：逐条 `find + lsof` 核实，**19/19 全部被存活 codex 进程持有打开
  fd**（活跃写锁，本机当前 22 个 codex 进程在跑）——正确的延迟索引行为，非缺陷，
  与 exec20 的 C3 收口口径（"b 类残差随进程退出自愈"）完全一致，数字（19）恰好
  与 exec20 记录的历史值相同。
- **2 条 gemini**：`gemini|/home/ivan/.gemini/tmp/ivan|4df2c176-...` 与
  `|e469f1d2-...`，identity key 与 `W1_ARTIFACTS/w1c-c3-residual-exceptions.md`
  记录的 c 类例外**逐字符相同**——不是新残差，是已核实、已记档的既有例外原样复现。
- **其余 = 0**（19+2=21，与 `missing` 总数完全对上，无第三类未分类残差）。

`unexpected=0`（完美，无候选独有的误报）。`content_mismatch=1739`：延续 C3 收口
时就记录的"窗口漂移"分类（manifest 生成与 index 补增量之间的时间窗口内消息计数
±1 类小幅偏差，如 `wood/f5eea2f0...`：manifest=37 vs db=36），不在门④判据范围内
（判据只卡 missing/unexpected），仅如实记录延续既有分类。

**判据满足**："missing 中活跃写锁类与显式例外清单豁免，其余须零" → 其余=0。
`root_set_ok=true`。**PASS**。

演练副本（C6/C7 用过的）均已清理，未参与本次对账（原始正库路径
`/tmp/cc-cass-w1-staging/data/agent_search.db` 直接对账，符合"演练副本不参与
对账"）。

## 收口

| 门 | 结果 |
|---|---|
| ① 基线等价 | **PASS**（两条候选独有失败形态已逐条核实为 Stage C 既定新增面，非回归） |
| ② 语义回填 ≤1s | **PASS**（p95=175ms，对照旧世界提升约 1.8 万倍） |
| ③ 新库完整性 | **PASS** |
| ④ 重摄覆盖对账 | **PASS**（missing 21 条全部落在已核实豁免类，unexpected=0） |

**四道验收门全部 PASS。波1（Stage A+B+C）完成态达成。**

候选 HEAD：`e0facad3`（含本门自查自修的编译回归修复）。仅 commit 未 push；
PR `feat/w1c-reingest-staging → feat/sqlite-consolidation` 由控制面操办
（隐私三面扫 → Ivan 过目 bytes → draft → 门绿转 ready → Ivan merge）。
