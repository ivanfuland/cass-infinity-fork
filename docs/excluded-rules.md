# Excluded-context rules (R1–R12)

> PR6「进库口径收口」T1（任务书 #111），fork 内规范，与 `normalize_v3_rules.md` 并列。
> 唯一规范：测试名、探针输出、T2 实现都用这里的条目号（`R<n>` 或 `R<n>-<letter>`）互相引用。
> 基线：`origin/infinity-main` 82cd5f0a；spec `docs/projects/cass-fork/specs/2026-09-07-pr6-ingest-hygiene-design.md` v4.3 §2.1/§2.2/§2.3/§2.4；plan `docs/projects/cass-fork/plans/2026-09-07-pr6-ingest-hygiene.md` v4 Task 1/Task 2。
>
> **T1 范围**：R1–R12 全部条目号在本轮冻结；R7、R11 的字段映射/别名表本轮**只填 claude_code 与 codex 两族**，其余连接器标「待 T1b 盘点」（T1b 收尾按结构探针覆盖率回填并冻结，见 plan Task 1b）。判定实现（`exclusion.rs`）是 T2 范围，不在本轮。

## R1 · 锚点 1 `cass_recall`

`role = tool_result`，且按 **R4 配对** 规则配对到的 tool_call 的 `tool_name` 以 `mcp__cass-mcp__` 为前缀。

- **R1-a**（正例）：配对 tool_call `tool_name = "mcp__cass-mcp__cass_search"` → 命中。
- **R1-b**（反例）：配对 tool_call `tool_name = "mcp__other-mcp__cass_search"`（同名非 cass-mcp 前缀）→ 不命中。
- **R1-c**（反例）：cass-mcp tool_result 的 hits JSON 解析失败 → 仍按 R1 命中（`reason = cass_recall`），但 `excluded.src = null`、`excluded.parse_error = Some(<原因>)`（spec §一 发挥空间）。

## R2 · 锚点 2 `context_file_read`

`role = tool_result`，且按 **R4 配对** 到的 tool_call 满足**全部**：

1. 工具属于读取类三选一：
   - `Read`，参数 `file_path`；
   - `mcp__ccw-control-plane__project_read`，参数 `document`；
   - `Bash`，参数 `command` 属于**只读语法子集**（五形态，逐字匹配，参数为路径列表）：
     `cat <paths>` / `head [-n N] <paths>` / `tail [-n N] <paths>` / `sed -n '<N>p' <paths>` / `sed -n '<N>,<M>p' <paths>`。
     带 `e`/`w`/`s` 命令的 sed 脚本、换行分隔的多命令、命令替换 `$(…)`/反引号、变量展开、通配符 —— 一律不排除。
2. 从参数提取的路径集合 `S` 非空，且 `S` 的**每个**元素都满足谓词 P（见下）——`cat A B` 只要有一个不满足即整条不排除（混合输出保留）。
3. `Bash` 命令含管道 / `;` / `&&` / `||` / 重定向的复合形态一律不排除（**R2-e**）。

**谓词 P**（对单个路径 `p`，取 `base = basename(p)`，`p` 先规范化为 `/` 分隔并解析 `..`）：

```
(base ∈ {USER.md, SOUL.md, MEMORY.md, IDENTITY.md, TOOLS.md, WORKSPACE.md}
   AND normalize(p) matches /(^|\/)cc-workspace(\/\.worktrees\/[^\/]+)?\/<base>$/)
OR base ∈ {CLAUDE.local.md, claude-system.md}                         # 任意路径
OR (base ∈ {CLAUDE.md, AGENTS.md}
   AND normalize(p) matches /(^|\/)cc-workspace(\/\.worktrees\/[^\/]+)?\/<base>$/)
OR (tool = mcp__ccw-control-plane__project_read
   AND document ∈ {exec, status, memory, user, soul, identity, tools, workspace})
```

仍为相对路径（规范化后仍无法确定是否在 cc-workspace 根/worktree 根下）的，只按 `base ∈ {CLAUDE.local.md, claude-system.md}` 那一支判（**R2-d**）。

四数组（六文件名 / 两个注入专属文件名 / 两个需 `/cc-workspace/` 限定的文件名 / `project_read` 文档名集合）是配置文件的四个数组，实现见 `config/excluded_context_paths.toml` + `ExcludedContextPaths::load`（本轮已落地，`src/sources/config.rs`）。

- **R2-a**（正例）：`Read(file_path="/home/ivan/projects/cc-workspace/MEMORY.md")` → 命中（普通同名文件，仓根）。
- **R2-b**（反例）：`Read(file_path="/home/ivan/projects/cc-workspace/reports/USER.md")` → **不命中**（深层同名文档，控制仓普通文档，谓词 P 要求仓根/worktree 根直接子级）。
- **R2-c**（正例）：`Read(file_path="/home/ivan/projects/cc-workspace/.worktrees/feat-x/CLAUDE.md")` → 命中（worktree 根，多机与 worktree 路径）。
- **R2-d**（正例）：`Read(file_path="CLAUDE.local.md")` → 命中（相对路径，仅按注入专属文件名判；任意路径都命中）。
- **R2-e**（反例）：`Bash(command="cat MEMORY.md | grep foo")` → 不命中（复合命令，含管道）。
- **R2-f**（正例，多路径混合）：`Bash(command="cat /home/ivan/projects/cc-workspace/MEMORY.md /tmp/notes.txt")` → 不命中（`S` 含一个不满足 P 的路径，整条保留）；`Bash(command="cat /home/ivan/projects/cc-workspace/MEMORY.md /home/ivan/projects/cc-workspace/USER.md")` → 命中（`S` 全部满足 P）。
- **R2-g**（正例）：`mcp__ccw-control-plane__project_read(document="exec")` → 命中。
- **R2-h**（反例）：`Bash(command="sed -n '1e date' file.md")` → 不命中（sed 脚本含 `e` 命令，非只读子集；首词 `sed -n` 合法但整体非允许语法）。

## R3 · 锚点 3 `codex_host_shell`

codex 会话 `idx = 0` 且 `role = user` 的消息，且正文（去首尾空白后）**同时满足**：

- 含 `<environment_context>` 开标记，且其内含 `<cwd>` 元素；
- 以 `</environment_context>` 结尾（末尾无任何后续文本）。

`anchor.shell.opener` 记实际开头三种之一：`# AGENTS.md instructions`、`<recommended_plugins>`、`<environment_context>`（不伪填）。`anchor.shell.closer = "</environment_context>"`。

- **R3-a**（正例，opener=`# AGENTS.md instructions`）：`idx=0` user 消息 `"# AGENTS.md instructions for …\n…<environment_context>…<cwd>…</environment_context>"` → 命中。
- **R3-b**（正例，opener=`<recommended_plugins>`）：同结构、`<recommended_plugins>` 开头 → 命中。
- **R3-c**（正例，opener=`<environment_context>`）：直接以 `<environment_context>` 开头 → 命中。
- **R3-d**（反例）：用户手写 `<INSTRUCTIONS>…</INSTRUCTIONS>` 外壳，无 `<environment_context>`/`<cwd>` 结构 → 不命中。
- **R3-e**（反例，`idx≠0`）：同样结构但出现在 `idx=1` 及以后 → 不命中（锚点只认 `idx=0`）。
- **R3-f**（反例，已知漏判方向）：用户把完整 `<environment_context>…</environment_context>` 块粘贴在真实首条请求（`idx=0`）末尾 → **命中**（谓词无法区分，原文仍在镜像；接受此风险，见 spec §2.1 已知取舍）。此判例标注为**已知漏判方向**，不算 bug。

## R4 · 配对规则

- 连接器提供 `tool_call_id` 时按 id 精确配对。
- 无 id 时，仅当「本条 tool_result 之前、同一 assistant 轮内**未被配对的 tool_call 恰好一个**」才配对；候选 0 个或 ≥2 个 → 不排除。
- 配对成功但 tool_call 缺 `tool_name` 或缺参数 → 不排除。

判例（**R4-a/b/c**）：无 id 候选 0 个（不排除）/ 恰 1 个（配对成功，按锚点判定）/ ≥2 个（不排除）。

## R5 · 处理顺序

摄入准备阶段固定顺序（spec §2.2，与 plan Global Constraints §2.4 一致）：

```
连接器投影
→ 镜像捕获并从捕获 blob 重新解析（唯一输入，不再用「校验 sha 相等」的替代方案）
→ 排除判定（此时 tool_name 与参数仍在，FRANKEN_NORMALIZED_EXTRA_KEYS 压缩之前）
→ redactor（对判定命中的正文调用同一 redactor 函数）
→ sha256/bytes（对象 = 脱敏后、本应写入 content 的字符串）
→ content 与副本替换（含同事件其它行的 extra 副本，按 raw.blocks 精确到块）
→ extra 压缩
→ 既有的 map_to_internal_with_redactor（对未排除行照常脱敏）
→ 规范化 / 切块
```

普通摄入（`prepare_conversation_for_ingest`）与镜像恢复（`prepare_conversation_for_restore`）共用同一判定/替换函数。

## R6 · `excluded` 列形状（schema v6）

```json
{"reason": "cass_recall | context_file_read | codex_host_shell",
 "rule_version": 1,
 "bytes": 4380, "sha256": "…64 hex…", "fingerprint_blake3": "…64 hex…",
 "parse_error": null,
 "anchor": {"tool_call_id": "toolu_01…", "tool_name": "mcp__cass-mcp__cass_search", "paths": null, "shell": null},
 "src": {"sessions": ["…"], "message_ids": [1189316]},
 "raw": {"blob": "blobs/blake3/ab/ab12…cd.raw", "idx": 17, "event_key": "3f9c…-uuid", "blocks": [1]}}
```

- `bytes`/`sha256`：对脱敏后、本应写入 `content` 的字符串取 UTF-8 字节长度与 sha256（供 corpus_diff 与去重指纹审计，与旧库 `content` 的 sha 同口径）。
- `fingerprint_blake3`：同一脱敏后正文的 BLAKE3 hex（供 R10 去重指纹）。
- `parse_error` 仅 `cass_recall` 解析 hits 失败时非 `null`，此时 `src = null`（R1-c）。
- `raw.blob` = manifest 内同形的相对路径 `blobs/blake3/<prefix>/<hash>.raw`（相对镜像根）。
- `raw.idx` = 该消息在「从 blob 重解析」结果中的下标。
- `raw.event_key` = 原始事件身份（claude_code 事件顶层 `uuid`；codex 事件 `id`，缺则 `line:<1-based 行号>`），与 `tool_call_id` 无关——无 id 配对成功的行同样有事件身份。
- `raw.blocks` = 该事件 `content[]` 中被清的块下标数组（锚点 1/2 = 配对 id 对应的 tool_result 块；锚点 3 = 该事件全部 text 块；codex `payload.output` 整体记 `[0]`）；事件内其它块字节不动。
- `context_file_read`：`anchor.paths` = 命中的路径集合 `S`（规范化后），`src = null`。
- `codex_host_shell`：`anchor.shell = {"opener": "…", "closer": "</environment_context>"}`，`src = null`。
- 字段缺一不得写入。

## R7 · 连接器正文字段映射（T1b Step 3 回填并冻结）

落地形态是**代码内常量表**（`src/indexer/exclusion.rs` 的 `EXTRA_FIELD_MAP: &[(&str /*agent_slug*/, &[&str /*路径*/])]`，T2 范围），**不是配置文件**——spec 只把 R2 的路径清单点名为「配置」这一项（修复批边界令）。路径写法是小 DSL：段用 `.` 分隔、数组通配 `[*]`。

| 连接器 | 承载正文的 JSON 路径 |
|---|---|
| `claude_code` | `message.content[*].content`、`message.content[*].text`、`toolUseResult.file.content`；`historical_raw_json` 封装（`sqlite.rs:2046`）内的同名路径同样替换（先解包字符串内 JSON，按同表路径替换，再序列化写回）。另有 `message.content[*].thinking`（`thinking` 块，独立成 `role='reasoning'` 行）与顶层 `content`（`type=system,subtype=away_summary` 事件，独立成 `role='assistant'` 行）——两者是 T1b 探针为对齐 DB `(idx,role)` 序列而发现的正文承载点，供 T2 参考，不在 spec 原始四类锚点范围内，本身不参与排除判定 |
| `codex` | `payload.output[*].text`（`function_call_output`/`custom_tool_call_output`）、`payload.content[*].text`（`message`）、`payload.arguments`/`payload.input`（tool_call 参数，`function_call`/`custom_tool_call`） |
| 其它连接器（`gemini`、`openclaw/*` 各分身、`pi_agent`） | **锚点 1/2 不启用**：T1b 探针本轮未实现这些连接器的候选解析器（零覆盖率数据，`t1b-probe-report.md` §⑦ 对应行 `镜像可得=0`），无法确认其 `tool_name`/路径参数结构，按「宁漏勿误」不启用，非「已核实无结构」 |

**T1b 探针实测覆盖率**（`copy/` 全量 5,046 会话，见 `t1b-probe-report.md` §⑦）：`claude_code` 2,400 会话 / 98,030 条 tool_call 候选，100% 有 `tool_call_id`+`tool_name`，90.3% 有 path 类参数；`codex` 1,688 会话 / 28,678 条 tool_call 候选，100% 有 `call_id`+`name`，64.3% 有 path 类参数。

处理顺序以 **R5** 为准：判定 → redactor → hash（不是「先压缩再判定」）。

## R8 · `rule_version` 升版纪律

三类锚点各自独立 `rule_version`，初值 1。判定条件（谓词 P、配对规则、锚点结构标记）任何语义变化 → 对应锚点 `rule_version + 1`；升版后必须从 raw-mirror 重摄（旧库里的排除标记不回填）。**清单改名不升版**（`config/excluded_context_paths.toml` 四数组的文件名变化，只要匹配语义不变）。

## R9 · 镜像保留契约

被 `excluded.raw.blob` 引用的镜像 blob **及引用它的 manifest**都属于不可清理集合：`cass mirror prune`（`raw_mirror.rs:229` 起）的两级保护集合并入引用 blob 与引用它的 manifest；`--apply` 在**持有 `index-run.lock` 排他**后才读取引用集合、规划、删除（与摄入互斥，锁被占用即退出 2，`lock-busy`）；dry-run 不取锁。库内任何一行的唯一原文都不得因保留期到期被删。

判例（**R9-a**）：对含 `excluded.raw` 引用的库跑 `mirror prune --older-than 0 --apply` → 被引用 blob 仍在，未引用的过期 blob 被删；变异（去掉引用保护）→ 红。

## R10 · 去重指纹口径

三处消费同一个 `fingerprint_hash(msg)` 口径：

- 内存 `message_replay_fingerprint`（`sqlite.rs:4346`）；
- merge→replay 转换链 `message_merge_fingerprint` / `replay_fingerprint_from_merge`（`:4336–4343`、`:4404–4414`）；
- 数据库回读侧 BLAKE3 计算（`:10909–10921`、`:10938–10988`）。

正文项：排除行取 `excluded.fingerprint_blake3`（清空前、脱敏后正文的 BLAKE3 hex）；未排除行取 `blake3(content)`（现状算法字节级不变，**不是** `content_hash_hex` 的 SHA-256）。保证行数不变、tool_call ↔ tool_result 配对不断（含既有会话增量合并路径）。

## R11 · 连接器工具身份别名表（T1b Step 3 回填并冻结）

每连接器列出 `Read` / `mcp__ccw-control-plane__project_read` / `Bash` 在其 `tool_name` 字段中出现的**完整身份**，只匹配表内全名（不匹配裸名/别名）。

| 连接器 | `Read` | `project_read` | `Bash` |
|---|---|---|---|
| `claude_code` | `Read` | `mcp__ccw-control-plane__project_read`（冻结副本 1,586 次调用用此全名，裸名 `project_read` 0 次出现） | `Bash` |
| `codex` | **无独立 Read 工具**（不启用该分支；读操作全部经 `exec_command` shell 执行） | **`project_read`（裸名，不带 `mcp__ccw-control-plane__` 前缀！）**——T1b.2 全量跑发现与 claude_code 不同：codex 把 MCP 工具注册/调用成裸名，实测直接 grep blob 命中工具 schema `{"type":"function","name":"project_read","description":"Serve one byte-bounded control document chunk..."}`（与该工具真实 description 一致），且 `build_candidates_codex` 统计到 610 次真实调用（非 schema 声明）用此裸名。**T1 初版误写成沿用 claude_code 全名，已订正** | `exec_command`（**参数键名是 `cmd`，不是 `command`**——T1b 探针实测 codex tool_name 频次分布 `exec_command` 40,729 次 tool_call 中最高频之一；R2 只读子集判定对 `cmd` 字段值做同样的两步语法判定） |

**R1 已知缺口（本轮未修，供 T2/控制面裁）**：codex 同样把 cass-mcp 工具注册/调用成裸名——全量跑发现 `cass_search`（5 次）与 `cass_expand`（3 次）真实调用，共 8 条，均不带 `mcp__cass-mcp__` 前缀。R1 的判定逻辑（`tool_name.startswith("mcp__cass-mcp__")`）是 spec §2.1 锚点 1 的原文定义，改动需回到 spec 层面裁定（是否给 codex 加一条裸名例外），不在本轮「清单是配置」的修复批边界内——本轮按「宁漏勿误」处理：这 8 条不排除，原文仍在镜像。
| 其它连接器（`gemini`、`openclaw/*` 各分身、`pi_agent`） | 待盘点（同 R7：零覆盖率数据，不启用） | 同左 | 同左 |
| 其它连接器 | 待 T1b 盘点 | 待 T1b 盘点 | 待 T1b 盘点 |

## R12 · 锁保证边界

`index-run.lock`（`acquire_index_run_lock`，按规范化 `data_dir` 定位）只保证**同一规范化 `data_dir`** 内的互斥——跨目录指向同一底层库（例如通过不同挂载点/符号链接访问同一物理路径）不在本保证范围内。`cass models backfill` 与 `cass index`、`mirror prune --apply` 共用此锁语义。

## 判例表（八行，摘要索引；完整判例见各 R 条目下的字母子编号）

| # | 场景 | 判据 |
|---|---|---|
| 1 | 普通同名文件（`.../cc-workspace/MEMORY.md`） | 命中，**R2-a** |
| 2 | 控制仓普通文档（`.../cc-workspace/reports/USER.md`） | **不命中**（深层同名文档），**R2-b** |
| 3 | 多机与 worktree 路径（`.../cc-workspace/.worktrees/x/CLAUDE.md`） | 命中，**R2-c** |
| 4 | 相对路径（`CLAUDE.local.md`） | 命中（仅注入专属文件名支），**R2-d** |
| 5 | 复合命令（`cat MEMORY.md \| grep foo`） | 不命中，**R2-e** |
| 6 | 多路径（`cat A B`，A 满足 P、B 不满足） | 不命中（整条保留），**R2-f** |
| 7 | 用户手写外壳无环境块（`<INSTRUCTIONS>…</INSTRUCTIONS>`，无 `<environment_context>`） | 不命中，**R3-d** |
| 8 | 完整结构引用（用户把完整 `<environment_context>…</environment_context>` 粘在真实请求末尾） | 命中（**已知漏判方向**，非 bug），**R3-f** |

---

**T1 状态**：R1–R12 条目号本轮冻结；R7/R11 两族字段映射与别名表本轮初稿，T1b 收尾回填其余连接器并冻结（无环，见 plan 执行顺序）。判定实现（`exclusion.rs`）、`raw_mirror` 保护集合改造、schema v6 写路径是 T2 范围，本轮不动代码。
