#!/usr/bin/env python3
"""w1-equiv-gate compare 判定器（plan Task 0.2 Step2 契约 R0-B7）。

用法: w1-compare-verdict.py <baseline_out_dir> <candidate_out_dir>

读取两侧 capture_one() 产物（completeness.json / failures.jsonl / test-inventory.txt），
输出人读诊断 + 末行 `VERDICT=<PASS|HOLD_INCOMPLETE|HOLD_SUPERSET|HOLD_DRIFT>`。

判定优先级（前一条不过，后面照样跑出诊断但不覆盖已判定的 verdict）：
  1) 执行完整性（两侧都要 complete=true，含 run_count_mismatches 为空）-> 否则 HOLD_INCOMPLETE
  2) 候选失败形态集合 ⊆ 基线失败形态集合 -> 否则 HOLD_SUPERSET
  3) 闭世界清单差集为空 -> 否则 HOLD_DRIFT（新增/删除/ignore态变更/哈希变更 逐条列出待人审）
  全过 -> PASS

「确定性内核逐条相等」（spec 字面要求）在本通用 harness 里降级为附加信息位
`exact_failure_set_match`：本版本只做单侧单跑（无重复跑抓 flaky），不做流水态分类，
是否要求逐条相等由调用方（各 Stage 的具体门，如 A8）按该字段自行加严判定，
不在此处硬编码——A8 等 Stage A 门理应额外断言 exact_failure_set_match==true。
"""
import json
import sys


def load_json(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return {'_load_error': str(e)}


def load_failures(path):
    out = []
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    except OSError:
        pass
    return out


def load_inventory(path):
    keys = set()
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    keys.add(line)
    except OSError:
        pass
    return keys


def main(argv):
    if len(argv) != 3:
        print('usage: w1-compare-verdict.py <baseline_out_dir> <candidate_out_dir>', file=sys.stderr)
        return 64

    baseline_dir, candidate_dir = argv[1], argv[2]

    base_completeness = load_json(f'{baseline_dir}/completeness.json')
    cand_completeness = load_json(f'{candidate_dir}/completeness.json')
    base_failures = load_failures(f'{baseline_dir}/failures.jsonl')
    cand_failures = load_failures(f'{candidate_dir}/failures.jsonl')
    base_inventory = load_inventory(f'{baseline_dir}/test-inventory.txt')
    cand_inventory = load_inventory(f'{candidate_dir}/test-inventory.txt')

    print('=== 执行完整性 ===')
    base_complete = bool(base_completeness.get('complete')) and not base_completeness.get(
        'run_count_mismatches'
    )
    cand_complete = bool(cand_completeness.get('complete')) and not cand_completeness.get(
        'run_count_mismatches'
    )
    print(f'baseline: complete={base_completeness.get("complete")} '
          f'started={base_completeness.get("started_targets")} '
          f'finished={base_completeness.get("finished_targets")} '
          f'expected={base_completeness.get("expected_targets")} '
          f'compile_error={base_completeness.get("compile_error")} '
          f'run_count_mismatches={len(base_completeness.get("run_count_mismatches") or [])}')
    print(f'candidate: complete={cand_completeness.get("complete")} '
          f'started={cand_completeness.get("started_targets")} '
          f'finished={cand_completeness.get("finished_targets")} '
          f'expected={cand_completeness.get("expected_targets")} '
          f'compile_error={cand_completeness.get("compile_error")} '
          f'run_count_mismatches={len(cand_completeness.get("run_count_mismatches") or [])}')

    incomplete = not (base_complete and cand_complete)

    base_modes = {f['mode'] for f in base_failures}
    cand_modes = {f['mode'] for f in cand_failures}
    new_modes = cand_modes - base_modes
    is_subset = not new_modes
    exact_match = base_modes == cand_modes

    print()
    print('=== 失败形态集合 ===')
    print(f'baseline: {len(base_failures)} 条失败, {len(base_modes)} 种形态')
    print(f'candidate: {len(cand_failures)} 条失败, {len(cand_modes)} 种形态')
    print(f'candidate ⊆ baseline: {is_subset}')
    print(f'exact_failure_set_match（附加信息，Stage A 等门应另行断言）: {exact_match}')
    if new_modes:
        print('候选新增的失败形态（基线没有，超集判定命中）:')
        for m in sorted(new_modes):
            print(f'  - {m[:200]}')

    print()
    print('=== 闭世界清单差集 ===')
    added = cand_inventory - base_inventory
    removed = base_inventory - cand_inventory
    drift = bool(added or removed)
    print(f'新增键（含哈希/ignore态变更视为新增+对应旧键删除）: {len(added)}')
    print(f'删除键: {len(removed)}')
    if added:
        print('新增示例（至多20条）:')
        for k in sorted(added)[:20]:
            print(f'  + {k}')
    if removed:
        print('删除示例（至多20条）:')
        for k in sorted(removed)[:20]:
            print(f'  - {k}')

    print()
    if incomplete:
        verdict = 'HOLD_INCOMPLETE'
    elif not is_subset:
        verdict = 'HOLD_SUPERSET'
    elif drift:
        verdict = 'HOLD_DRIFT'
    else:
        verdict = 'PASS'

    print(f'VERDICT={verdict}')
    return {'PASS': 0, 'HOLD_INCOMPLETE': 10, 'HOLD_SUPERSET': 11, 'HOLD_DRIFT': 12}[verdict]


if __name__ == '__main__':
    sys.exit(main(sys.argv))
