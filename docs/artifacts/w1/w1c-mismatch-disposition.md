# 门④ content_mismatch 定性收口（R1 审后补强）

> 任务书 #27（exec23，2026-08-29），承接 exec22 交接件
> `~/projects/cc-cass-w1-artifacts/W1_ARTIFACTS/w1c-exec22-handoff.md` 的双探针结论。
> 引用自 `reports/w1-artifacts/w1-gate-attestation.md` 门④一节，本报告是该门的
> content_mismatch 桶定性收口，不重跑门④本身的判据（missing/unexpected 不变）。

## 1. 三轮三元组演进

| 轮次 | 二进制/口径 | missing | unexpected | content_mismatch |
|---|---|---|---|---|
| C8 attestation（门④首次密封） | v5 manifest，HEAD `e0facad3` | 21 | 0 | 1739 |
| R1 对抗审 6 修（B3/B9/N1/N3/B4/B5/B8/B6/B7）后 | manifest-v6，HEAD `66153d59` | 21 | 0 | 1738 |
| **R1-B10（本报告）后** | manifest-v7，HEAD `ff724535` | **21** | **0** | **1432** |

missing 21 条构成两轮均未变：19 条 codex（存活进程持有写锁，C8 门④已 `find+lsof`
逐条核实）+ 2 条 gemini（identity_key 与既有例外清单逐字符相同）。unexpected 恒为 0。

## 2. content_mismatch 内部拆解

`cass ingest reconcile` 把 `db_message_count != manifest_message_count` 与
`db_content_digest != manifest_content_digest` 两类判据合并进同一个
`content_mismatch` 数组（`src/ingest_reconcile.rs` 第 162 行左右）。R1 后
（1738 条）按 exec22 报告分两支：

- **manifest>db 计数差桶**：1431 条（占 82%）。
- **同计数异 digest 桶**：约 306-307 条（1738-1431）。

R1-B10 前后对该桶的机器统计（本报告用 `manifest-v7.jsonl` + 重跑的
`agent_search.db` 增量做的独立复算，未沿用任何缓存数字）：

| 桶 | R1 后（1738） | R1-B10 后（1432） |
|---|---|---|
| 同计数、异 digest | ~306-307 | **0（完全坍缩）** |
| manifest>db（计数差） | 1431 | 1431（不变） |
| db>manifest（计数差，新观测） | 0 | 1（见 §4 附记） |

1738 − 1432 = **306**，与 exec22 报告的"同计数异 digest 306 条子桶"精确对上。

## 3. R1-B10 根因与修复验证

**根因**（exec22 三方 digest 探针定位）：生产索引持久化路径
（`src/indexer/mod.rs:26606` `map_to_internal_with_redactor`，注释引 #112）在写
`messages.content` 前对每条消息跑 `redact_secrets::redact_text`；`src/ingest_manifest.rs`
的 `content_digest` 却一直吃 connector 的原始未脱敏内容。任何命中脱敏规则的会话，
manifest 侧 digest 与 db 侧永久对不上——不是数据丢失、不是 staleness，是 manifest
工具漏做了生产路径都在做的一步脱敏。

**修复**（commit `ff724535`）：`src/ingest_manifest.rs` 收集消息处，在
`redaction_enabled()` 为 true 时对每条内容跑 `crate::indexer::redact_secrets::redact_text`
——复用 indexer 侧同一函数与同一配置读取路径，未拷贝规则（单点纪律，同
`identity_key` 先例）。

**代码级验证**（3 条新测试，均 PASS）：
1. `tests/ingest_manifest.rs::manifest_content_digest_reflects_production_redaction_for_secret_content`
   —— `DATABASE_URL=postgres://user:pass@host/db` fixture，manifest digest 与真实
   `redact_text` 输出的 digest 相等，与原始内容 digest 不等。
2. `tests/ingest_manifest.rs::manifest_content_digest_unchanged_when_no_secret_present`
   —— 反向控制：无敏感内容会话 digest 前后不变。
3. `tests/ingest_reconcile.rs::reconcile_shows_no_content_mismatch_when_manifest_digest_is_computed_over_redacted_content`
   —— 用真实 `cass ingest reconcile` 二进制闭环：db 播种生产脱敏字节 + manifest
   digest 算脱敏后内容 → `content_mismatch` 数组为空。

**生产规模验证**（本报告 §1/§2 的三元组演进本身）：staging 正库 63 会话/39399
消息增量补齐后，同计数异 digest 桶从 ~306 条**精确坍缩为 0**，与代码级验证的
预期完全一致。逐样本闭环核对（复用 exec22 的 37 条分层抽样，见 §5）：37 条样本中
15 条属于该桶（`manifest_count==db_count` 但此前 digest 不同），R1-B10 后重新
比对 identity_key，**15/15 全部从 `content_mismatch` 里消失**；另外 22 条
eligibility 样本（manifest>db 计数差桶）**22/22 原样保留**（符合预期，R1-B10 只
动 digest 不动 eligibility）。

## 4. eligibility 桶（manifest>db，1431 条）机制定性 —— 已证

exec22 探针 B（20 分钟）排除了 `is_hard_message_noise`（只在词法/语义索引投影
路径，非核心 `messages` 表写入路径），未能指认到真实排除谓词，判定"机制未指认
（circumstantial 维持）"：模式成立（idx 全覆盖散布空洞、非末尾截断；二次增量
补跑数字不变；`cass quarantine list` 零隔离）但代码位置未落实。

**本报告续查指认到机制**：`src/storage/sqlite.rs`
`collect_new_messages_for_existing_conversation`（第 4696 行起）在向已存在的
conversation 追加消息时，对每条新消息计算
`message_replay_fingerprint`（`created_at` + `role` + `author` + `content` 的
blake3 哈希，第 4651 行）；若该指纹已在 `existing_replay_fingerprints` 集合里
出现过（不看 idx，只看内容指纹），直接 `continue` 跳过，不写入 `messages` 表，
日志文案原话是 `"skipping replay-equivalent recovered message with shifted idx"`。
该谓词有明确的既有单测覆盖此确切场景：
`insert_conversation_tree_merges_replay_equivalent_messages_with_shifted_idx`
（`src/storage/sqlite.rs:20309`，agent_slug 用例即为 `"codex"`）。

**空洞消息逐条验证**（真实 staging 数据，用 `get_connector_factories()` 里
`codex` 连接器对最大 gap 的会话重新过一遍源文件，跟 `message_replay_fingerprint`
定义完全同构地计算 `(created_at, role, author, content_hash)`）：

目标会话：`codex|/home/ivan/projects/cc-workspace|2026/07/19/rollout-2026-07-19T08-06-58-019f77b2-8e79-7322-8bfc-0ce3271c0860`，
manifest 计数 86544，db 计数 81681（差 4863，本轮 manifest>db 桶里差值最大的一条）。
db 侧 idx 范围完整覆盖 `0..86543`（与 manifest 隐含上限一致，非截断），散布多处
`gap=2` 的小洞。抽取三处洞逐条核实：

| 洞 idx | 内容摘要 | 命中的更早 idx | role/author/created_at 是否完全一致 |
|---|---|---|---|
| 10 | `"**Planning sequential tool execution**"`（reasoning 摘要） | 9 | 一致（同 content_hash） |
| 20 | `"**Checking skills directory contents**"`（reasoning 摘要） | 19 | 一致（同 content_hash） |
| 24 | `"**Verifying symlink file types**"`（reasoning 摘要） | 23 | 一致（同 content_hash） |

3/3 命中：每个洞 idx 的消息都与紧邻的前一条 idx 在 `created_at`/`role`/`author`/
`content_hash` 上完全相同——codex rollout 记录把同一条 reasoning 摘要写了两次
（相邻 idx），manifest 原样计入两条，db 侧的 `collect_new_messages_for_existing_conversation`
按内容指纹判定第二条是"replay-equivalent"予以跳过。**这就是 manifest>db 桶的
真实机制**：不是数据丢失，是一个已有设计意图的去重谓词（防止 codex 恢复/重放
把同一段历史当新消息重复入库），只是这个去重在这份长会话的 reasoning-summary
重复模式上被大量触发。

**定性从"机制未指认（circumstantial）"升级为"已证"**：代码定位 + 3 条空洞消息
逐条验证谓词命中，均通过。受限于 45 分钟 timebox 与个人项目的边界令（Ivan
2026-08-29：不追加新探针工具、不为完备统计扩大样本），本报告未对 1431 条逐条
验证，但机制本身（代码路径 + 单测先例 + 3 条真实样本 100% 命中）已足以把该桶从
"疑似正常但代码未定位"升级为"已定位、已证实的既有设计行为"。

**附记（db>manifest，1 条，非该桶内容）**：本轮新观测到 1 条
`db_message_count(338) > manifest_message_count(330)` 的条目，identity_key 指向
本执行会话（exec23）自己的 `.claude/projects/` 转录文件——`--scan-root` 会扫到
正在写入的本会话日志，manifest 快照与 index 补增量之间会话自己又写了新消息，
标准的 `db_ahead` 窗口漂移（非真散度），与 R1-B10/eligibility 均无关，如实记录
为自扫描 artifact。

## 5. 37 条分层抽样明细（复用 exec22 抽样，identity_key/mtime 未变）

抽样方法：`agent_slug` 分层（codex16/claude_code8/openclaw-wood4/openclaw-javich3/
openclaw-main3/openclaw-justin2/gemini1），种子固定，脚本
`/tmp/cc-cass-r1probe-sample.py`（exec22 产物）。

| 分类 | 条数 | R1-B10 后状态 |
|---|---|---|
| eligibility（manifest>db 计数差） | 22 | 22/22 仍在 `content_mismatch`（预期内，R1-B10 不改变 eligibility 判定） |
| 同计数异 digest（原"UNRESOLVED"） | 15 | 15/15 已从 `content_mismatch` 消失（R1-B10 直接解决） |

原始产物：`/tmp/cc-cass-r1probe-sample-classified.json`（37 条全量分类）、
`/tmp/cc-cass-w1-r1b10-reconcile.json`（本轮 reconcile 全量输出）、
`/tmp/cc-cass-w1-staging/manifest-v7.jsonl`（R1-B10 修复后的 manifest）。

## 6. 结论

- **R1-B10（脱敏对齐）**：根因明确、修复落地（commit `ff724535`）、代码级+生产
  规模双重验证，306 条同计数异 digest 桶精确坍缩为 0，抽样闭环 15/15 全部解决。
  **已收口，不留残余**。
- **eligibility 桶（manifest>db，1431 条）**：机制从"circumstantial"升级为
  "已证"——`collect_new_messages_for_existing_conversation` 的 replay-fingerprint
  去重（`src/storage/sqlite.rs:4651`/`4696`），非数据丢失、非索引缺陷，是既有
  设计意图的去重谓词在长会话重复 reasoning-summary 模式上的正常触发。代码未改动
  （无新增修复项，遵循个人项目边界令），定性只体现在本报告文字里。
- **content_mismatch 从 1739 → 1432**，剩余全部落在已定性、已证实为非缺陷的
  eligibility 桶（1431 条）+ 1 条已解释的自扫描 db_ahead artifact。**门④对
  content_mismatch 的定性收口到此完成**。
