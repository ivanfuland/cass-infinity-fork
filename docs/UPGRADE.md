# CASS-on-Infinity fork 升级重放 runbook

> 姿态：pin + 刻意升级。不追每个 upstream release；仅当需要 upstream 某 feature/fix 才升。每次 = 受控事件。

## 步骤
1. 记下旧基 tag（`git tag | grep upstream-base`），决定目标 upstream rev。
2. `git fetch upstream`
3. 新分支 rebase 我方补丁到新 upstream rev：
   `git checkout -b upgrade-<date> infinity-main && git rebase --onto <new-upstream-rev> upstream-base-0.6.17`
   - 冲突多在搜索侧 4 处接线（lib.rs 搜索装配 / SemanticIndexer match / embedder_registry / model_manager 的 load_infinity_semantic_context / 以及 lib.rs 的 SearchMode::Semantic cfg 门）；`infinity.rs` 通常零冲突。逐个解，保持语义。
4. **查 upstream 是否动 build.rs 契约 / asupersync pin**：
   `git diff upstream-base-0.6.17 <new-upstream-rev> -- build.rs Cargo.toml | grep -iE 'asupersync|contract|expected_'`
   - asupersync 期望 rev 变了 → 改 `setup-cass-fork.sh` 的 `ASUPERSYNC_REV` + 验 main 版本号。
5. 重跑 `bash scripts/setup-cass-fork.sh`（自动备份旧二进制到 `cass-infinity.prev` + 验无 ONNX + 装新）。
6. **重建 bge-m3 语义索引**（embedder/chunking 版本可能变）+ 跑召回回归门（在 cc-workspace）：
   `CASS_DATA_DIR=<data> CASS_INFINITY_URL=... python3 ~/projects/cc-workspace/docs/projects/shared-memory/recall-regression/run.py ~/.local/bin/cass-infinity`
   - **gate exit≠0 → 不切换**：`cp -a ~/.local/bin/cass-infinity.prev ~/.local/bin/cass-infinity` 回滚，记录原因。
7. PASS → 推 fork，打新 `upstream-base-<ver>` tag，merge 进 `infinity-main`。
