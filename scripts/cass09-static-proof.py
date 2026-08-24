#!/usr/bin/env python3
"""[cass-09] 搭车修复的静态证明。

两件事，都不做二进制配对构建：

  A. 两个持有 `ENV_LOCK` 的模块必须由 `#[cfg(test)]` 门住 —— 即它们在 release
     profile 下根本不编译，所以这次改动不可能影响生产二进制。
  B. 这两个 ENV_LOCK 的**全部**取锁点都必须走
     `unwrap_or_else(|e| e.into_inner())`，一个 `.unwrap()` / `.expect(` 都不许剩。

用法：
    cass09-static-proof.py <repo-root>            # 检查工作树
    cass09-static-proof.py --from-git <rev> <repo-root>   # 检查某个 commit 的内容

退出码分档，不用「非 0 即失败」兜底：
    0  PASS
    1  FAIL —— 真违规（模块没被 cfg(test) 门住，或有取锁点会因中毒 panic）
    2  PRECONDITION —— 输入不满足（文件缺失、找不到 ENV_LOCK 声明、git 读不出来）
"""
import re
import subprocess
import sys
from pathlib import Path

TARGETS = {
    "src/indexer/semantic_progress.rs": 6,
    "src/indexer/mod.rs": 1,
}
GOOD = "ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())"
BAD = re.compile(r"ENV_LOCK\.lock\(\)\s*\.\s*(unwrap\(\)|expect\()")
MOD_OPEN = re.compile(r"^\s*(?:pub(?:\(crate\))?\s+)?mod\s+\w+\s*\{")


def load(root: Path, rel: str, rev):
    if rev is None:
        p = root / rel
        if not p.is_file():
            return None, f"文件不存在: {p}"
        return p.read_text(encoding="utf-8").splitlines(), None
    r = subprocess.run(
        ["git", "-C", str(root), "show", f"{rev}:{rel}"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None, f"git show {rev}:{rel} 失败: {r.stderr.strip()}"
    return r.stdout.splitlines(), None


def enclosing_mod_is_cfg_test(lines, decl_idx):
    """从 ENV_LOCK 声明行往上找最近的 `mod X {`，判它上面是不是 #[cfg(test)]。"""
    for i in range(decl_idx, -1, -1):
        if MOD_OPEN.match(lines[i]):
            j = i - 1
            while j >= 0 and (not lines[j].strip() or lines[j].lstrip().startswith("//")):
                j -= 1
            if j >= 0 and lines[j].strip() == "#[cfg(test)]":
                return True, i + 1
            return False, i + 1
    return None, None


def main():
    argv = sys.argv[1:]
    rev = None
    if argv and argv[0] == "--from-git":
        if len(argv) < 3:
            print("PRECONDITION: --from-git 需要 <rev> <repo-root>")
            return 2
        rev, argv = argv[1], argv[2:]
    if not argv:
        print("PRECONDITION: 缺少 <repo-root>")
        return 2
    root = Path(argv[0]).resolve()

    failures, checked_sites = [], 0
    for rel, expected_sites in TARGETS.items():
        lines, err = load(root, rel, rev)
        if lines is None:
            print(f"PRECONDITION: {err}")
            return 2

        decls = [i for i, ln in enumerate(lines) if re.search(r"static ENV_LOCK\s*:", ln)]
        if len(decls) != 1:
            print(f"PRECONDITION: {rel} 里 ENV_LOCK 声明数为 {len(decls)}，期望恰好 1")
            return 2

        # A. 模块必须被 cfg(test) 门住
        gated, mod_line = enclosing_mod_is_cfg_test(lines, decls[0])
        if gated is None:
            print(f"PRECONDITION: {rel} 的 ENV_LOCK 声明找不到外层 mod")
            return 2
        if not gated:
            failures.append(f"{rel}:{mod_line} 持有 ENV_LOCK 的模块没有被 #[cfg(test)] 门住")
        else:
            print(f"  OK  {rel}:{mod_line} 模块由 #[cfg(test)] 门住，release 不编译")

        # B. 取锁点全部 poison-safe
        good = sum(ln.count(GOOD) for ln in lines)
        bad = [(i + 1, ln.strip()) for i, ln in enumerate(lines) if BAD.search(ln)]
        checked_sites += good
        if good != expected_sites:
            failures.append(f"{rel} poison-safe 取锁点 {good} 处，期望 {expected_sites} 处")
        for line_no, text in bad:
            failures.append(f"{rel}:{line_no} 取锁点会因中毒 panic: {text}")
        if not bad and good == expected_sites:
            print(f"  OK  {rel} {good} 处取锁点全部 unwrap_or_else(into_inner)")

    if failures:
        print("\nFAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"\nPASS: 2 个模块均 cfg(test) 门住；{checked_sites} 处取锁点全部 poison-safe")
    return 0


if __name__ == "__main__":
    sys.exit(main())
