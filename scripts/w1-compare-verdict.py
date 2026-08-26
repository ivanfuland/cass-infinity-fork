#!/usr/bin/env python3
"""w1-equiv-gate compare 判定器（plan Task 0.2 Step2 契约 R0-B7）。

用法: w1-compare-verdict.py <baseline_out_dir> <candidate_out_dir>

读取两侧 capture_one() 产物（completeness.json / failures.jsonl / test-inventory.txt /
cargo-check-rc.txt / inventory-rc.txt），输出人读诊断 + 末行
`VERDICT=<PASS|HOLD_INCOMPLETE|HOLD_SUPERSET|HOLD_NAME_DRIFT|HOLD_DRIFT>`。

判定优先级（前一条不过，后面照样跑出诊断但不覆盖已判定的 verdict）：
  1) 执行完整性（两侧都要 complete=true，含 run_count_mismatches 为空，
     cargo-check-rc.txt==0，inventory-rc.txt==0，poison_excluded==0，
     target_accounting 逐 target 均 reconciled，failures.jsonl 文件存在，
     两侧「非 doc-test target 的 declared running 总和」与该侧
     test-inventory.txt 行数相等） -> 否则 HOLD_INCOMPLETE
     （plan delta R1-B1/B2/B3 + R2-B2/B3，PR 前对抗审阻断项：此前
     `cargo check --all-targets` 与 test-inventory 抽取的非零退出码从未被
     本判定器消费——候选只破坏 benchmark/额外 target 或漏收新测试仍可判
     PASS；PoisonError 级联失败被归一化器整条剔除且不核对失败数；
     failures.jsonl 缺失时 `load_failures` 曾静默当空表处理，一侧真实失败
     记录全部丢失也可能判 PASS；两侧总测试数从未做过跨 target 的独立源
     交叉核（cargo 自己声明的 running 总和 vs test-inventory.py 静态扫描
     的 active+ignored 计数），归一化器自身的扫描窗口 bug 不会报错也不会
     被任何既有判据发现）
  2) 候选失败形态**多重集** ⊆ 基线失败形态多重集（按 (target 无关的) mode
     计数比较，候选每种 mode 的出现次数不得超过基线同一 mode 的出现次数）
     -> 否则 HOLD_SUPERSET（plan delta R1-B4：此前用 set 比较会把「候选两个
     不同测试的 panic 文本归一化后相同」与「基线只有一个同 mode 失败」误判
     成同一形态、判 PASS，丢失了失败身份与重数；形态口径本身不变，按 EXEC
     「按形态判，不按测试名判」的原则保留，只是从 set 升级为多重集，并新增
     (测试名, mode) 配对附表供人审）
  3) 仅当 2) 的 mode 多重集 subset 成立时才检查：候选失败(测试名,mode)
     **配对多重集** ⊆ 基线配对多重集 -> 否则 HOLD_NAME_DRIFT（plan delta
     R2-B1，R1-B4 重开：mode 多重集 subset 只保证「候选每种 mode 出现次数
     不超基线」，不保证是**同一批测试**在失败——基线 A 失败 mode X、候选 B
     失败 mode X（A 反而通过了），mode 计数两侧都是 {X:1}，纯 mode 多重集
     判 PASS，但这其实是一次身份漂移，需要人审，不该自动放行）
  4) 闭世界清单差集为空 -> 否则 HOLD_DRIFT（新增/删除/ignore态变更/哈希变更 逐条列出待人审）
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
    """R2-B3: returns (records, missing). `missing=True` means the file
    itself doesn't exist/isn't readable -- distinct from an existing,
    genuinely-empty file (zero failures is a legitimate, common result).
    Previously an OSError here was swallowed into an empty list identical to
    the "zero failures" case, so a deleted/never-written failures.jsonl for
    one side silently looked like "that side had no failures" instead of
    "this run's data can't be trusted"."""
    out = []
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out, False
    except OSError:
        return out, True


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


def inventory_identity(key):
    """Strip the trailing content hash, keeping `<file>::<test>::<status>`
    -- the identity that's stable across a source-body edit that changes the
    hash but not the test's existence (R2-B2 v2 needs "did a test get
    added/removed", not "did its body change")."""
    parts = key.rsplit('::', 1)
    return parts[0] if len(parts) == 2 else key


def identity_file(identity):
    return identity.split('::', 1)[0]


def target_file_scope(label):
    """R2-B2 v2 (control-plane redesign 2026-08-26): map a target_label to
    the inventory file(s) it corresponds to. The lib unittest target is the
    one many-to-one case -- every `src/*.rs` file's #[test]s all run inside
    a single `unittests src/lib.rs` binary/target, so its scope is a prefix
    match; every other target (an integration test file or a bench file) is
    exactly the file whose relative path equals the target label."""
    if label is not None and label.startswith('unittests '):
        return ('prefix', 'src/')
    return ('exact', label)


def file_in_scope(file, scope):
    kind, val = scope
    return file.startswith(val) if kind == 'prefix' else file == val


def build_target_running(completeness):
    """Per-target declared-running totals for one side, keyed by the
    tree-relative target_label (doctests excluded -- they have no
    test-inventory.txt counterpart to reconcile against)."""
    out = {}
    for t in completeness.get('target_accounting') or []:
        if t.get('is_doctest'):
            continue
        label = t.get('target_label')
        n = t.get('declared_running')
        if label is None or n is None:
            continue
        out[label] = out.get(label, 0) + n
    return out


def main(argv):
    if len(argv) != 3:
        print('usage: w1-compare-verdict.py <baseline_out_dir> <candidate_out_dir>', file=sys.stderr)
        return 64

    baseline_dir, candidate_dir = argv[1], argv[2]

    base_completeness = load_json(f'{baseline_dir}/completeness.json')
    cand_completeness = load_json(f'{candidate_dir}/completeness.json')
    base_failures, base_failures_missing = load_failures(f'{baseline_dir}/failures.jsonl')
    cand_failures, cand_failures_missing = load_failures(f'{candidate_dir}/failures.jsonl')
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
    # R2-B2 v2 (control-plane redesign 2026-08-26, replaces the first cut):
    # the absolute "running sum == inventory count" check per side rejected
    # v5's real data on a ~1.44x structural gap the inventory scanner and
    # cargo's own per-target running count have always had (an inherited,
    # symmetric baseline property, not a defect this wave introduced) --
    # wrong invariant. The threat model B2 actually guards is "candidate
    # silently suppresses tests baseline used to run" (e.g. a stray
    # `#[cfg(any())]`), and baseline is the reference, not the audit target.
    # Re-anchored to a cross-side DIFFERENTIAL invariant instead: for each
    # target (by tree-relative label, matched across both sides' distinct
    # absolute build paths), the change in declared running count between
    # baseline and candidate must equal the net test-identity change (added
    # minus removed, ignoring pure content-hash churn) among the inventory
    # entries that belong to that target's source file(s). A `#[cfg(any())]`
    # suppression drops that target's candidate running count without a
    # matching inventory removal, so it can't hide from this either -- but a
    # target's count legitimately growing because its own source file
    # gained new #[test]s (this wave's own `src/storage/api/*.rs`) is
    # correctly explained and does not HOLD.
    base_target_running = build_target_running(base_completeness)
    cand_target_running = build_target_running(cand_completeness)
    base_identities = {inventory_identity(k) for k in base_inventory}
    cand_identities = {inventory_identity(k) for k in cand_inventory}
    added_identities = cand_identities - base_identities
    removed_identities = base_identities - cand_identities
    running_mismatches = []
    for label in sorted(set(base_target_running) | set(cand_target_running)):
        base_n = base_target_running.get(label, 0)
        cand_n = cand_target_running.get(label, 0)
        actual_diff = cand_n - base_n
        scope = target_file_scope(label)
        added_in_scope = sum(1 for i in added_identities if file_in_scope(identity_file(i), scope))
        removed_in_scope = sum(1 for i in removed_identities if file_in_scope(identity_file(i), scope))
        expected_diff = added_in_scope - removed_in_scope
        if actual_diff != expected_diff:
            running_mismatches.append(
                {
                    'target_label': label,
                    'base_running': base_n,
                    'cand_running': cand_n,
                    'actual_diff': actual_diff,
                    'expected_diff_from_inventory': expected_diff,
                }
            )
    running_reconciled = not running_mismatches
    # Advisory-only aggregate sums (not a judging input -- the absolute ratio
    # is inherited baseline structure, see comment above).
    base_running_sum = base_completeness.get('total_declared_running_non_doctest')
    cand_running_sum = cand_completeness.get('total_declared_running_non_doctest')
    base_complete = (
        bool(base_completeness.get('complete'))
        and not base_completeness.get('run_count_mismatches')
        and base_check_rc == 0
        and base_inventory_rc == 0
        and base_poison == 0
        and not base_unreconciled
        and not base_failures_missing
    )
    cand_complete = (
        bool(cand_completeness.get('complete'))
        and not cand_completeness.get('run_count_mismatches')
        and cand_check_rc == 0
        and cand_inventory_rc == 0
        and cand_poison == 0
        and not cand_unreconciled
        and not cand_failures_missing
    )
    print(f'baseline: complete={base_completeness.get("complete")} '
          f'started={base_completeness.get("started_targets")} '
          f'finished={base_completeness.get("finished_targets")} '
          f'expected={base_completeness.get("expected_targets")} '
          f'compile_error={base_completeness.get("compile_error")} '
          f'run_count_mismatches={len(base_completeness.get("run_count_mismatches") or [])} '
          f'failures_jsonl_missing={base_failures_missing} '
          f'running_sum={base_running_sum} inventory_count={len(base_inventory)} '
          f'(advisory ratio only, not judged) '
          f'cargo_check_rc={base_check_rc} inventory_rc={base_inventory_rc} '
          f'poison_excluded={base_poison} unreconciled_targets={len(base_unreconciled)}')
    print(f'candidate: complete={cand_completeness.get("complete")} '
          f'started={cand_completeness.get("started_targets")} '
          f'finished={cand_completeness.get("finished_targets")} '
          f'expected={cand_completeness.get("expected_targets")} '
          f'compile_error={cand_completeness.get("compile_error")} '
          f'run_count_mismatches={len(cand_completeness.get("run_count_mismatches") or [])} '
          f'failures_jsonl_missing={cand_failures_missing} '
          f'running_sum={cand_running_sum} inventory_count={len(cand_inventory)} '
          f'(advisory ratio only, not judged) '
          f'cargo_check_rc={cand_check_rc} inventory_rc={cand_inventory_rc} '
          f'poison_excluded={cand_poison} unreconciled_targets={len(cand_unreconciled)}')
    print()
    print('=== 跨侧 target running 差分对账（R2-B2 v2）===')
    print(f'candidate ⊆ baseline running-diff reconciled against inventory identity diff: {running_reconciled}')
    total_actual_diff = sum(cand_target_running.values()) - sum(base_target_running.values())
    total_expected_diff = len(added_identities) - len(removed_identities)
    print(f'总和差分校验（advisory,per-target 通过时恒等）: '
          f'cand_sum-base_sum={total_actual_diff} vs cand_inv-base_inv={total_expected_diff} '
          f'({"OK" if total_actual_diff == total_expected_diff else "MISMATCH"})')
    if running_mismatches:
        print(f'不能被清单差分解释的 target（{len(running_mismatches)} 个,逐条列出）:')
        for m in running_mismatches:
            print(f"  - {m['target_label']}: base_running={m['base_running']} "
                  f"cand_running={m['cand_running']} actual_diff={m['actual_diff']} "
                  f"expected_diff_from_inventory={m['expected_diff_from_inventory']}")
    if base_unreconciled:
        print(f'baseline unreconciled targets (至多10条): {base_unreconciled[:10]}')
    if cand_unreconciled:
        print(f'candidate unreconciled targets (至多10条): {cand_unreconciled[:10]}')

    incomplete = not (base_complete and cand_complete and running_reconciled)

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

    # R2-B1 (R1-B4 reopened): mode-count subset alone can't distinguish "the
    # same tests failed with the same content" from "a different set of
    # tests happened to produce panic text that normalizes to a mode the
    # baseline already had" -- e.g. baseline: test A fails with mode X;
    # candidate: test A passes but test B now fails with mode X. Both sides
    # have {X: 1} in the mode Counter (subset holds), yet this is a real
    # identity drift a human needs to see. Only evaluated when the mode-level
    # subset already holds -- if it doesn't, HOLD_SUPERSET already covers a
    # strictly coarser version of the same problem.
    name_drift = False
    over_count_pairs = {}
    if is_subset:
        base_pair_counts = Counter((f['test'], f['mode']) for f in base_failures)
        cand_pair_counts = Counter((f['test'], f['mode']) for f in cand_failures)
        over_count_pairs = {
            pair: (cand_pair_counts[pair], base_pair_counts.get(pair, 0))
            for pair in cand_pair_counts
            if cand_pair_counts[pair] > base_pair_counts.get(pair, 0)
        }
        name_drift = bool(over_count_pairs)

    print()
    print('=== (测试名, mode) 配对多重集判定 ===')
    if not is_subset:
        print('跳过（mode 多重集 subset 已经不成立，HOLD_SUPERSET 已覆盖，无需再判配对）')
    else:
        print(f'candidate 配对 ⊆ baseline 配对（同一 mode 必须是同一批测试在挂）: {not name_drift}')
        if name_drift:
            print('候选独有的 (测试名,mode) 配对（mode 本身基线有，但挂的测试变了 -- 需要人审）:')
            for pair in sorted(over_count_pairs):
                cand_n, base_n = over_count_pairs[pair]
                test, mode = pair
                print(f'  - [候选x{cand_n} 基线x{base_n}] test={test} :: {mode[:160]}')

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
    elif name_drift:
        verdict = 'HOLD_NAME_DRIFT'
    elif drift:
        verdict = 'HOLD_DRIFT'
    else:
        verdict = 'PASS'

    print(f'VERDICT={verdict}')
    return {
        'PASS': 0,
        'HOLD_INCOMPLETE': 10,
        'HOLD_SUPERSET': 11,
        'HOLD_DRIFT': 12,
        'HOLD_NAME_DRIFT': 13,
    }[verdict]


if __name__ == '__main__':
    sys.exit(main(sys.argv))
