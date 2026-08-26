#!/usr/bin/env python3
"""w1-equiv-gate 闭世界测试清单抽取器（R0-B4 + R1-B1/B2 + R2-F7/R3-B3 契约）。

用法: python3 scripts/w1-test-inventory.py <dir> [<dir> ...]
输出（stdout）: 每个 #[test] 一行 "<路径>::<函数名>::<active|ignored>::<哈希前8>"
自检（stderr）: 抽取行数 == 行锚定 #[test] 属性总数；不等 -> exit 2（HOLD）。

口径（照抄 plan，不发明）:
- 计数/抽取统一用行锚定 `^[ \t]*#\[test\]`（非锚定会把注释/字符串里的字面量计进去）。
- #[test] 前后属性都可堆叠（#[ignore]/#[serial] 等，Rust 对属性顺序不作要求）：先向上
  扫过连续的属性/注释/空行找到属性块首行，再从 #[test] 起前向扫描 8 行内找首个
  `fn <name>`；`#[ignore` 判定覆盖属性块上下两段（R3-B1：此前只前向扫描会漏判
  `#[ignore]` 置于 `#[test]` 之前的合法写法，候选把失败测试的 ignore 属性挪到 #[test]
  前即可让该测试仍被记成 active、哈希不变，equiv-gate 判 PASS 而实际已停跑）。
- 键含 ignore 态，同名跨文件不塌缩（键含完整路径）。
- 哈希覆盖 "属性块首行 起 至 函数体闭括号止" 的完整归一化文本（含全部属性行，不论其
  排在 #[test] 前还是后），防「加 #[cfg(any())] 静默撤测」与「断言掏空」两型阉割；
  哈希差异不自动 FAIL，落变更清单人审。
"""
import hashlib
import re
import sys
from pathlib import Path

TEST_ATTR_RE = re.compile(r'^[ \t]*#\[test\]')
IGNORE_ATTR_RE = re.compile(r'^[ \t]*#\[ignore')
FN_RE = re.compile(r'\bfn\s+([A-Za-z_][A-Za-z0-9_]*)')
ATTR_LINE_RE = re.compile(r'^[ \t]*#\[')
COMMENT_LINE_RE = re.compile(r'^[ \t]*//')
BLANK_LINE_RE = re.compile(r'^[ \t]*$')
MAX_FORWARD_SCAN = 8
MAX_BACKWARD_SCAN = 8


def find_attr_block_start(raw_lines, test_idx):
    """R3-B1: walk upward from the `#[test]` line through any contiguous run
    of attribute/comment/blank lines to find the top of the attribute block.
    Rust doesn't require `#[ignore]` to come after `#[test]` -- a candidate
    can place it *before* `#[test]` and the old forward-only scan (and
    forward-only hash range) would silently miss it, recording a stopped
    test as still `active` with an unchanged hash. Bounded like the forward
    scan; conservative on purpose (control-plane 2026-08-26): a non-attr/
    comment/blank line always stops the scan, so at worst the block is
    drawn a little too large (harmless extra rehashing), never too small
    (which is what would let an #[ignore] fall outside it)."""
    block_start = test_idx
    j = test_idx - 1
    floor = max(-1, test_idx - 1 - MAX_BACKWARD_SCAN)
    while j > floor:
        line = raw_lines[j]
        if ATTR_LINE_RE.match(line) or COMMENT_LINE_RE.match(line):
            block_start = j
            j -= 1
            continue
        if BLANK_LINE_RE.match(line):
            j -= 1
            continue
        break
    return block_start


def mask_file(text):
    """把字符串/字符字面量/注释内容原地替换为空格（保留换行与长度），
    使后续按字符扫花括号时不会被这些区域里的 { } 干扰。"""
    n = len(text)
    mask = list(text)
    i = 0
    while i < n:
        c = text[i]

        # 行注释
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            j = i
            while j < n and text[j] != '\n':
                mask[j] = ' '
                j += 1
            i = j
            continue

        # 块注释（支持 Rust 的嵌套块注释）
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            depth = 1
            mask[i] = ' '
            mask[i + 1] = ' '
            j = i + 2
            while j < n and depth > 0:
                if text[j] == '/' and j + 1 < n and text[j + 1] == '*':
                    depth += 1
                    mask[j] = ' '
                    mask[j + 1] = ' '
                    j += 2
                    continue
                if text[j] == '*' and j + 1 < n and text[j + 1] == '/':
                    depth -= 1
                    mask[j] = ' '
                    mask[j + 1] = ' '
                    j += 2
                    continue
                if text[j] != '\n':
                    mask[j] = ' '
                j += 1
            i = j
            continue

        # 字符串前缀探测：b"..", r"..", r#".."#, br#".."#，以及普通 ".."
        if c in ('b', 'r', '"'):
            k = i
            if k < n and text[k] == 'b':
                k += 1
            is_raw = False
            hashes = 0
            if k < n and text[k] == 'r':
                is_raw = True
                k += 1
                while k < n and text[k] == '#':
                    hashes += 1
                    k += 1
            if k < n and text[k] == '"':
                prefix_start = i
                if is_raw:
                    closer = '"' + ('#' * hashes)
                    end = text.find(closer, k + 1)
                    close_end = (end + len(closer)) if end != -1 else n
                else:
                    j = k + 1
                    while j < n and text[j] != '"':
                        if text[j] == '\\' and j + 1 < n:
                            j += 2
                            continue
                        j += 1
                    close_end = min(j + 1, n)
                for p in range(prefix_start, close_end):
                    if mask[p] != '\n':
                        mask[p] = ' '
                i = close_end
                continue

        # 字符字面量 vs 生命周期标注的启发式判定
        if c == "'":
            if i + 1 < n and text[i + 1] == '\\':
                j = i + 2
                if j < n and text[j] == 'u' and j + 1 < n and text[j + 1] == '{':
                    end = text.find('}', j)
                    j = (end + 1) if end != -1 else j + 1
                else:
                    j += 1
                if j < n and text[j] == "'":
                    for p in range(i, j + 1):
                        if mask[p] != '\n':
                            mask[p] = ' '
                    i = j + 1
                    continue
            elif i + 2 < n and text[i + 1] != "'" and text[i + 2] == "'":
                for p in range(i, i + 3):
                    if mask[p] != '\n':
                        mask[p] = ' '
                i = i + 3
                continue
            # 否则当生命周期标注，原样放行

        i += 1
    return ''.join(mask)


def find_close_line(masked_lines, start_line_idx):
    depth = 0
    found_open = False
    for li in range(start_line_idx, len(masked_lines)):
        for ch in masked_lines[li]:
            if ch == '{':
                depth += 1
                found_open = True
            elif ch == '}':
                depth -= 1
                if found_open and depth == 0:
                    return li
    return None


def process_file(path, rel_path, errors):
    text = path.read_text(encoding='utf-8', errors='replace')
    raw_lines = text.splitlines()
    masked_lines = mask_file(text).splitlines()
    if len(masked_lines) != len(raw_lines):
        # 长度理论上应恒等；不等说明 mask_file 有缺陷，整文件计入错误不抽取，交自检抓
        test_count = sum(1 for ln in raw_lines if TEST_ATTR_RE.match(ln))
        errors.append((rel_path, 'mask-length-mismatch', test_count))
        return [], test_count

    emitted = []
    test_count = 0
    n = len(raw_lines)
    i = 0
    while i < n:
        if TEST_ATTR_RE.match(raw_lines[i]):
            test_count += 1
            block_start = find_attr_block_start(raw_lines, i)
            fn_idx = None
            ignored = any(
                IGNORE_ATTR_RE.match(raw_lines[k]) for k in range(block_start, i)
            )
            for k in range(i, min(i + MAX_FORWARD_SCAN + 1, n)):
                if k > i and IGNORE_ATTR_RE.match(raw_lines[k]):
                    ignored = True
                m = FN_RE.search(raw_lines[k])
                if m:
                    fn_idx = k
                    fn_name = m.group(1)
                    break
            if fn_idx is None:
                errors.append((rel_path, f'no-fn-within-{MAX_FORWARD_SCAN}-lines@{i + 1}', 1))
                i += 1
                continue
            close_idx = find_close_line(masked_lines, fn_idx)
            if close_idx is None:
                errors.append((rel_path, f'no-matching-close-brace@{i + 1}', 1))
                i = fn_idx + 1
                continue
            full_text = '\n'.join(raw_lines[block_start:close_idx + 1])
            normalized = re.sub(r'\s+', ' ', full_text).strip()
            hash8 = hashlib.md5(normalized.encode('utf-8')).hexdigest()[:8]
            state = 'ignored' if ignored else 'active'
            emitted.append(f'{rel_path}::{fn_name}::{state}::{hash8}')
            i = close_idx + 1
            continue
        i += 1
    return emitted, test_count


def main(argv):
    if len(argv) < 2:
        print('usage: w1-test-inventory.py <dir> [<dir> ...]', file=sys.stderr)
        return 2

    roots = [Path(a) for a in argv[1:]]
    all_emitted = []
    total_test_count = 0
    errors = []

    for root in roots:
        if not root.is_dir():
            print(f'[w1-test-inventory] WARN: {root} 不是目录，跳过', file=sys.stderr)
            continue
        for path in sorted(root.rglob('*.rs')):
            rel_path = str(path)
            emitted, test_count = process_file(path, rel_path, errors)
            all_emitted.extend(emitted)
            total_test_count += test_count

    for line in all_emitted:
        print(line)

    emit_count = len(all_emitted)
    if errors:
        for rel_path, kind, cnt in errors:
            print(f'[w1-test-inventory] ERROR {rel_path}: {kind} (affects {cnt})', file=sys.stderr)

    if emit_count != total_test_count:
        print(
            f'[w1-test-inventory] self-check HOLD: emitted={emit_count} != '
            f'#[test]-lines={total_test_count}',
            file=sys.stderr,
        )
        return 2

    print(
        f'[w1-test-inventory] self-check PASS: emitted={emit_count} == '
        f'#[test]-lines={total_test_count}',
        file=sys.stderr,
    )
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
