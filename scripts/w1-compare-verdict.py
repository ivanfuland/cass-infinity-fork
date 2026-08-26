#!/usr/bin/env python3
"""w1-equiv-gate compare 判定器（plan Task 0.2 Step2 契约 R0-B7）。

用法: w1-compare-verdict.py <baseline_out_dir> <candidate_out_dir>

读取两侧 capture_one() 产物（completeness.json / failures.jsonl / test-inventory.txt /
cargo-check-rc.txt / inventory-rc.txt），输出人读诊断 + 末行
`VERDICT=<PASS|HOLD_INCOMPLETE|HOLD_SUPERSET|HOLD_DRIFT>`。

判定优先级（前一条不过，后面照样跑出诊断但不覆盖已判定的 verdict）：
  1) 执行完整性（两侧都要 complete=true，含 run_count_mismatches 为空，
     cargo-check-rc.txt==0，inventory-rc.txt==0，poison_excluded==0，
     target_accounting 逐 target 均 reconciled） -> 否则 HOLD_INCOMPLETE
     （plan delta R1-B1/B2/B3，PR 前对抗审阻断项：此前 `cargo check --all-targets`
     与 test-inventory 抽取的非零退出码从未被本判定器消费——候选只破坏
     benchmark/额外 target 或漏收新测试仍可判 PASS；PoisonError 级联失败被
     归一化器整条剔除且不核对失败数，单个真实失败混着 PoisonError 也会让
     `complete` 照过）
  2) 候选失败形态**多重集** ⊆ 基线失败形态多重集（按 (target 无关的) mode
     计数比较，候选每种 mode 的出现次数不得超过基线同一 mode 的出现次数）
     -> 否则 HOLD_SUPERSET（plan delta R1-B4：此前用 set 比较会把「候选两个
     不同测试的 panic 文本归一化后相同」与「基线只有一个同 mode 失败」误判
     成同一形态、判 PASS，丢失了失败身份与重数；形态口径本身不变，按 EXEC
     「按形态判，不按测试名判」的原则保留，只是从 set 升级为多重集，并新增
     (测试名, mode) 配对附表供人审）
  3) 闭世界清单差集为空 -> 否则 HOLD_DRIFT（新增/删除/ignore态变更/哈希变更 逐条列出待人审）
  全过 -> PASS

「确定性内核逐条相等」（spec 字面要求）在本通用 harness 里降级为附加信息位
`exact_failure_set_match`：本版本只做单侧单跑（无重复跑抓 flaky），不做流水态分类，
是否要求逐条相等由调用方（各 Stage 的具体门，如 A8）按该字段自行加严判定，
不在此处硬编码——A8 等 Stage A 门理应额外断言 exact_failure_set_match==true。
"""
import json
import sys
from collections import Counter


def load_json(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return {'_load_error': str(e)}


def load_rc(path):
    """R1-B1/B2: read a `*-rc.txt` exit-code file. Returns None (treated as a
    hard failure by the caller) if missing or unparseable -- capture_one()
    always writes one of these, so an absent/corrupt file means the run
    itself is untrustworthy, not that the check "didn't apply"."""
    try:
        with open(path, encoding='utf-8') as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


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
    base_check_rc = load_rc(f'{baseline_dir}/cargo-check-rc.txt')
    cand_check_rc = load_rc(f'{candidate_dir}/cargo-check-rc.txt')
    base_inventory_rc = load_rc(f'{baseline_dir}/inventory-rc.txt')
    cand_inventory_rc = load_rc(f'{candidate_dir}/inventory-rc.txt')

    print('=== 执行完整性 ===')
    base_poison = base_completeness.get('poison_excluded') or 0
    cand_poison = cand_completeness.get('poison_excluded') or 0
    base_unreconciled = base_completeness.get('unreconciled_targets') or []
    cand_unreconciled = cand_completeness.get('unreconciled_targets') or []
    base_complete = (
        bool(base_completeness.get('complete'))
        and not base_completeness.get('run_count_mismatches')
        and base_check_rc == 0
        and base_inventory_rc == 0
        and base_poison == 0
        and not base_unreconciled
    )
    cand_complete = (
        bool(cand_completeness.get('complete'))
        and not cand_completeness.get('run_count_mismatches')
        and cand_check_rc == 0
        and cand_inventory_rc == 0
        and cand_poison == 0
        and not cand_unreconciled
    )
    print(f'baseline: complete={base_completeness.get("complete")} '
          f'started={base_completeness.get("started_targets")} '
          f'finished={base_completeness.get("finished_targets")} '
          f'expected={base_completeness.get("expected_targets")} '
          f'compile_error={base_completeness.get("compile_error")} '
          f'run_count_mismatches={len(base_completeness.get("run_count_mismatches") or [])} '
          f'cargo_check_rc={base_check_rc} inventory_rc={base_inventory_rc} '
          f'poison_excluded={base_poison} unreconciled_targets={len(base_unreconciled)}')
    print(f'candidate: complete={cand_completeness.get("complete")} '
          f'started={cand_completeness.get("started_targets")} '
          f'finished={cand_completeness.get("finished_targets")} '
          f'expected={cand_completeness.get("expected_targets")} '
          f'compile_error={cand_completeness.get("compile_error")} '
          f'run_count_mismatches={len(cand_completeness.get("run_count_mismatches") or [])} '
          f'cargo_check_rc={cand_check_rc} inventory_rc={cand_inventory_rc} '
          f'poison_excluded={cand_poison} unreconciled_targets={len(cand_unreconciled)}')
    if base_unreconciled:
        print(f'baseline unreconciled targets (至多10条): {base_unreconciled[:10]}')
    if cand_unreconciled:
        print(f'candidate unreconciled targets (至多10条): {cand_unreconciled[:10]}')

    incomplete = not (base_complete and cand_complete)

    # R1-B4: multiset (Counter), not set. A plain set comparison collapses
    # distinct failing tests whose panic text normalizes to the same mode --
    # baseline test A failing once and candidate tests B+C failing once each
    # with the same mode both read as "the mode set is {A's mode}", silently
    # hiding that candidate broke two things baseline didn't. Subset now
    # means "for every mode, candidate's occurrence count <= baseline's".
    base_mode_counts = Counter(f['mode'] for f in base_failures)
    cand_mode_counts = Counter(f['mode'] for f in cand_failures)
    base_modes = set(base_mode_counts)
    cand_modes = set(cand_mode_counts)
    over_count_modes = {
        m: (cand_mode_counts[m], base_mode_counts.get(m, 0))
        for m in cand_modes
        if cand_mode_counts[m] > base_mode_counts.get(m, 0)
    }
    is_subset = not over_count_modes
    exact_match = base_mode_counts == cand_mode_counts

    print()
    print('=== 失败形态多重集 ===')
    print(f'baseline: {len(base_failures)} 条失败, {len(base_modes)} 种形态')
    print(f'candidate: {len(cand_failures)} 条失败, {len(cand_modes)} 种形态')
    print(f'candidate ⊆ baseline（按 mode 计数,候选每种形态出现次数 <= 基线同形态次数）: {is_subset}')
    print(f'exact_failure_set_match（附加信息，Stage A 等门应另行断言）: {exact_match}')
    if over_count_modes:
        print('候选超出基线计数的失败形态（新增形态,或既有形态候选比基线更多次）:')
        for m in sorted(over_count_modes):
            cand_n, base_n = over_count_modes[m]
            print(f'  - [候选x{cand_n} 基线x{base_n}] {m[:200]}')

    print()
    print('=== (测试名, mode) 配对附表（人审用,不参与判定）===')
    print('候选侧全部失败记录:')
    for f in sorted(cand_failures, key=lambda r: (r['test'], r['mode'])):
        print(f"  candidate: {f['test']} :: {f['mode'][:160]}")
    print('基线侧全部失败记录:')
    for f in sorted(base_failures, key=lambda r: (r['test'], r['mode'])):
        print(f"  baseline: {f['test']} :: {f['mode'][:160]}")

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
