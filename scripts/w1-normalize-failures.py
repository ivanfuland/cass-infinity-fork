#!/usr/bin/env python3
"""w1-equiv-gate 失败归一化器（EXEC.md 测试门口径 + plan Task 0.2 Step2 契约）。

用法:
  w1-normalize-failures.py <cargo-test-log> <expected-targets-count-file> \
      <failures-out.jsonl> <completeness-out.json>

从 `cargo test $FEATURES --no-fail-fast -- --test-threads=1` 的完整 stdout+stderr 日志中：
- 按 target 切块（"Running ... (bin)" 或 "Doc-tests <crate>" 起，至该 target 的
  "test result: ..." 止），逐块核对 "running N tests" 与最终 passed+failed+ignored+
  measured+filtered_out 是否一致（c2 运行数对账）。
- 对每个 FAILED 用例，从 "---- <name> stdout ----" 块抓取 panic/断言文本，
  归一化（去 file:line:col / 十六进制地址 / 计时数字 / 绝对路径），得到失败形态 mode；
  含 PoisonError/poisoned 连带的记录整条剔除（不写入 failures.jsonl，仅计数报告）。
- 执行完整性三判据：启动 target 数 == 收尾 test result 数 == 期望 target 数（独立真值源，
  来自 cargo metadata，读自 <expected-targets-count-file>）；日志内出现编译期错误
  （error[E.../ error: could not compile / error: linking）视为真编译错误，完整性判 False。
"""
import json
import re
import sys

RUNNING_RE = re.compile(r'^\s*Running\s+(\S.*?)\s+\(([^)]*)\)\s*$')
DOCTEST_RE = re.compile(r'^\s*Doc-tests\s+(\S+)\s*$')
RUNNING_N_RE = re.compile(r'^running (\d+) tests?$')
TEST_RESULT_RE = re.compile(
    r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
    r'(\d+) measured; (\d+) filtered out(?:; finished in ([\d.]+)s)?\s*$'
)
FAILURES_HEADER_RE = re.compile(r'^failures:\s*$')
FAILED_TEST_NAME_RE = re.compile(r'^    (\S+)\s*$')
STDOUT_BLOCK_RE = re.compile(r'^---- (\S+) stdout ----$')
# 只认真编译错误的信号（EXEC.md 明文坑：`error: test failed` / `error: N targets failed`
# 是 --no-fail-fast 下正常的测试失败汇总行，不是编译失败，禁止用宽的 `^error: ` 兜底误判）。
COMPILE_ERROR_RE = re.compile(
    r'^error\[[A-Z]\d+\]:|^error: could not compile|^error: linking|^error: aborting due to'
)

LOC_RE = re.compile(r'\S+\.rs:\d+:\d+')
ADDR_RE = re.compile(r'\b0x[0-9a-fA-F]+\b')
TIME_RE = re.compile(r'\bfinished in [\d.]+s\b')
# plan delta d9: was scoped to `.rs` source paths only, which missed absolute
# paths to non-.rs files (golden fixtures, shell scripts, etc.) that panic
# messages routinely embed (e.g. "Expected: /home/.../tests/golden/robot/
# capabilities.json.golden"). Those paths are rooted at the tree's own working
# directory, which differs between the baseline and candidate worktrees (two
# distinct absolute paths) even when the underlying failure content is
# byte-identical -- inflating both sides' failure-form counts the same way the
# d8 PID/tmpdir leak did. Broadened to strip the directory prefix of any
# absolute path down to its basename, regardless of extension; the basename is
# kept (not collapsed away) so genuinely different files still normalize
# differently.
ABS_PATH_RE = re.compile(r'/[^\s:]+/([A-Za-z0-9_.\-]+)')
# plan delta d8: cross-run thread ids in "thread '<name>' (<PID>) panicked" are not
# stable (random per-process), so leaving them in makes two runs of the identical
# assertion normalize to different strings and get misclassified as a new failure
# form. Same for the ephemeral first-level /tmp/<random> segment (tempfile-crate
# dirs, per-worktree CARGO_TARGET_DIR hash) that appears throughout panic payloads.
THREAD_PID_RE = re.compile(r"(thread '[^']*') \(\d+\) panicked")
TMPDIR_RE = re.compile(r'/tmp/[^/\s]+')
# plan delta d10 (v3.1 verdict follow-up, control-plane adjudicated 2026-08-25):
# five more per-invocation-random fields observed inflating candidate-vs-baseline
# diffs after d9 -- each anchored to a fixed literal/structural context (not a
# bare hex/digit substring) so real content differences elsewhere still survive:
#   - elapsed_ms: anchored to the literal `"elapsed_ms":` JSON key.
ELAPSED_MS_RE = re.compile(r'"elapsed_ms":\s*\d+')
#   - blake3: anchored to the literal `blake3: Some("...")` Rust Debug field
#     (doctor snapshot's content hash of the fixture db file, which embeds
#     run-varying bytes -- confirmed non-deterministic on a single unchanged
#     tree across repeated runs, see v3.1 README).
BLAKE3_RE = re.compile(r'blake3: Some\("[0-9a-f]+"\)')
# JSON-string sibling shape (e.g. `"manifest_blake3": "<hex>"`), anchored to a
# key name containing "blake3" so it doesn't touch unrelated hex strings.
BLAKE3_JSON_RE = re.compile(r'"([A-Za-z0-9_]*blake3[A-Za-z0-9_]*)":\s*"[0-9a-f]{16,}"')
#   - millisecond timing rendered inline in a human-readable message (e.g.
#     "Unhealthy (12ms)"), a different textual shape than `"elapsed_ms": N`
#     but the same non-deterministic-timing family; anchored to the literal
#     `(<N>ms)` parenthesized suffix.
TIMING_MS_PAREN_RE = re.compile(r'\(\d+ms\)')
#   - tempfile random segment: anchored to the `tempfile` crate's own `.tmp`
#     prefix convention (distinct from the `/tmp/<random>` TMPDIR_RE case --
#     this is the *basename* ABS_PATH_RE leaves behind, e.g. a `HOME=".../
#     .tmpoA8yrE"` value embedded inside a command line, not a standalone path).
TMPFILE_BASENAME_RE = re.compile(r'\.tmp[A-Za-z0-9]{4,}\b')
#   - ISO8601/RFC3339 timestamp: structural datetime shape, not a key name (it
#     shows up under more than one JSON key across doctor/robot-docs surfaces).
ISO8601_RE = re.compile(r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b')
#   - FailureDump filename timestamp: anchored to the literal `_YYYYMMDD_HHMMSS`
#     suffix the test harness's own failure-dump writer appends before `.txt`.
FAILUREDUMP_TS_RE = re.compile(r'_\d{8}_\d{6}\.txt\b')
# Discretionary 6th rule, same family as blake3 (both are doctor-snapshot
# fields sitting side by side in the same `DoctorNoWriteTreeEntry` struct
# Debug dump) but not in the control-plane-approved 5-item list verbatim --
# flagged separately in the v4 report rather than folded silently into "d10".
# `modified_ms` is the fixture db file's real OS mtime: structurally it can
# never match between two independent process runs regardless of any code
# fix, so leaving it unstripped would permanently block subset/exact-match
# on every doctor test that snapshots a file tree (an unavoidable-noise field,
# not a content difference).
MODIFIED_MS_RE = re.compile(r'modified_ms: Some\(\d+\)')


def normalize_mode(text):
    t = LOC_RE.sub('<LOC>', text)
    t = ADDR_RE.sub('<ADDR>', t)
    t = TIME_RE.sub('<TIME>', t)
    t = ELAPSED_MS_RE.sub('"elapsed_ms": <MS>', t)
    t = TIMING_MS_PAREN_RE.sub('(<MS>ms)', t)
    t = MODIFIED_MS_RE.sub('modified_ms: Some(<MS>)', t)
    t = BLAKE3_RE.sub('blake3: Some(<HASH>)', t)
    t = BLAKE3_JSON_RE.sub(r'"\1": <HASH>', t)
    t = ISO8601_RE.sub('<ISO8601>', t)
    t = ABS_PATH_RE.sub(r'<PATH>/\1', t)
    t = FAILUREDUMP_TS_RE.sub('_<TS>.txt', t)
    t = TMPFILE_BASENAME_RE.sub('.tmp<RAND>', t)
    t = THREAD_PID_RE.sub(r'\1 (<PID>) panicked', t)
    t = TMPDIR_RE.sub('/tmp/<TMPDIR>', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t


def target_label(cur_target):
    """R2-B2 v2 (control-plane redesign 2026-08-26): strip the absolute
    binary path suffix (` (/tmp/.../deps/foo-<hash>)`) from a `cur_target`
    string, leaving just the tree-relative label (e.g. `tests/connector_
    crush.rs` or `unittests src/lib.rs`) that's stable across baseline and
    candidate builds -- the absolute path differs by construction (distinct
    tree_target_dir per side), so cross-side target matching must key on
    this, not the raw `cur_target` string.
    """
    if cur_target is None:
        return cur_target
    idx = cur_target.find(' (')
    return cur_target[:idx] if idx != -1 else cur_target


def is_poison_cascade(text):
    low = text.lower()
    return 'poisonerror' in low or 'poisoned' in low


def parse(lines):
    started = 0
    finished = 0
    compile_error = False
    run_count_mismatches = []
    failures = []
    poison_excluded = 0
    # plan delta R1-B3 (PR-front code review, control-plane adjudicated
    # 2026-08-25): per-target reconciliation between cargo's own reported
    # `failed` count and what this parser actually recorded (failures.jsonl
    # entries + poison-excluded entries for that target). A mismatch means
    # the parser silently dropped or miscounted failures for that target
    # (e.g. a name appearing twice in the "failures:" list, or a parsing
    # edge case) -- previously undetectable because `complete` only checked
    # target counts and compile errors, never cross-checked failure counts.
    target_accounting = []
    # plan delta R2-B2 (PR-front code review round 2, control-plane
    # adjudicated 2026-08-26): cross-target reconciliation between cargo's
    # own declared "running N tests" sum (across all non-doctest targets)
    # and w1-test-inventory.py's independent static AST scan of #[test]
    # functions (active+ignored). Doc-tests are excluded on both sides of
    # this comparison -- they're a real cargo phase with their own "running
    # N tests" line, but the inventory scanner only scans #[test]-annotated
    # functions in src/tests/benches, never doc comments, so including them
    # would create a permanent, expected mismatch rather than catching a
    # real one. A mismatch here means the two independently-derived test
    # counts disagree even when neither side's own internal accounting
    # (run_count_mismatches, per-target `reconciled`) caught anything --
    # e.g. the inventory scanner's fixed-line scan window silently
    # miscounting a target's tests without erroring.
    total_declared_running_non_doctest = 0
    total_declared_running_doctest = 0

    cur_target = None
    cur_declared_n = None
    cur_failed_names = []
    collecting_failure_names = False
    stdout_blocks = {}  # name -> list[str]
    cur_stdout_name = None
    cur_stdout_buf = []

    def flush_stdout_block():
        nonlocal cur_stdout_name, cur_stdout_buf
        if cur_stdout_name is not None:
            stdout_blocks[cur_stdout_name] = cur_stdout_buf
        cur_stdout_name = None
        cur_stdout_buf = []

    def close_target(result_word, passed, failed, ignored, measured, filtered):
        nonlocal cur_target, cur_declared_n, cur_failed_names, stdout_blocks
        nonlocal finished, total_declared_running_non_doctest, total_declared_running_doctest
        finished += 1
        if cur_declared_n is not None:
            total = passed + failed + ignored + measured + filtered
            if total != cur_declared_n:
                run_count_mismatches.append(
                    {
                        'target': cur_target,
                        'declared_running': cur_declared_n,
                        'result_total': total,
                    }
                )
            if cur_target is not None and cur_target.startswith('doctests '):
                total_declared_running_doctest += cur_declared_n
            else:
                total_declared_running_non_doctest += cur_declared_n
        recorded_here = 0
        poison_here = 0
        for name in cur_failed_names:
            body = '\n'.join(stdout_blocks.get(name, []))
            if is_poison_cascade(body):
                poison_excluded_ref[0] += 1
                poison_here += 1
                continue
            mode = normalize_mode(body) if body else '<no-captured-output>'
            failures.append({'target': cur_target, 'test': name, 'mode': mode})
            recorded_here += 1
        is_doctest = cur_target is not None and cur_target.startswith('doctests ')
        target_accounting.append(
            {
                'target': cur_target,
                'target_label': target_label(cur_target),
                'is_doctest': is_doctest,
                'declared_running': cur_declared_n,
                'cargo_reported_failed': failed,
                'recorded_failures': recorded_here,
                'poison_excluded': poison_here,
                'reconciled': (recorded_here + poison_here == failed),
            }
        )
        cur_target = None
        cur_declared_n = None
        cur_failed_names = []
        stdout_blocks = {}

    poison_excluded_ref = [0]

    for raw_line in lines:
        line = raw_line.rstrip('\n')

        if COMPILE_ERROR_RE.match(line):
            compile_error = True

        m = RUNNING_RE.match(line)
        if m:
            flush_stdout_block()
            cur_target = f'{m.group(1)} ({m.group(2)})'
            cur_declared_n = None
            cur_failed_names = []
            stdout_blocks = {}
            started += 1
            collecting_failure_names = False
            continue

        m = DOCTEST_RE.match(line)
        if m:
            flush_stdout_block()
            cur_target = f'doctests {m.group(1)}'
            cur_declared_n = None
            cur_failed_names = []
            stdout_blocks = {}
            started += 1
            collecting_failure_names = False
            continue

        m = RUNNING_N_RE.match(line)
        if m and cur_target is not None:
            cur_declared_n = int(m.group(1))
            continue

        m = STDOUT_BLOCK_RE.match(line)
        if m:
            flush_stdout_block()
            cur_stdout_name = m.group(1)
            cur_stdout_buf = []
            collecting_failure_names = False
            continue

        if FAILURES_HEADER_RE.match(line):
            flush_stdout_block()
            collecting_failure_names = True
            continue

        m = TEST_RESULT_RE.match(line)
        if m and cur_target is not None:
            flush_stdout_block()
            collecting_failure_names = False
            _, passed, failed, ignored, measured, filtered, _dur = m.groups()
            close_target(
                m.group(1), int(passed), int(failed), int(ignored), int(measured), int(filtered)
            )
            continue

        if collecting_failure_names:
            m = FAILED_TEST_NAME_RE.match(line)
            if m:
                if m.group(1) not in cur_failed_names:
                    cur_failed_names.append(m.group(1))
                continue
            if line.strip() == '':
                continue
            collecting_failure_names = False

        if cur_stdout_name is not None:
            cur_stdout_buf.append(line)

    flush_stdout_block()

    return {
        'started_targets': started,
        'finished_targets': finished,
        'compile_error': compile_error,
        'run_count_mismatches': run_count_mismatches,
        'failures': failures,
        'poison_excluded': poison_excluded_ref[0],
        'target_accounting': target_accounting,
        'total_declared_running_non_doctest': total_declared_running_non_doctest,
        'total_declared_running_doctest': total_declared_running_doctest,
    }


def main(argv):
    if len(argv) != 5:
        print(
            'usage: w1-normalize-failures.py <cargo-test-log> <expected-targets-count-file> '
            '<failures-out.jsonl> <completeness-out.json>',
            file=sys.stderr,
        )
        return 64

    log_path, expected_path, failures_out_path, completeness_out_path = argv[1:5]

    with open(log_path, encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    result = parse(lines)

    try:
        with open(expected_path, encoding='utf-8') as f:
            expected_targets = int(f.read().strip())
    except (OSError, ValueError):
        expected_targets = None

    completeness = {
        'started_targets': result['started_targets'],
        'finished_targets': result['finished_targets'],
        'expected_targets': expected_targets,
        'compile_error': result['compile_error'],
        'run_count_mismatches': result['run_count_mismatches'],
        'poison_excluded': result['poison_excluded'],
        'target_accounting': result['target_accounting'],
        'unreconciled_targets': [
            t for t in result['target_accounting'] if not t['reconciled']
        ],
        'total_declared_running_non_doctest': result['total_declared_running_non_doctest'],
        'total_declared_running_doctest': result['total_declared_running_doctest'],
        'complete': (
            result['started_targets'] == result['finished_targets'] == expected_targets
            and not result['compile_error']
        )
        if expected_targets is not None
        else False,
    }

    # plan delta R2-B3 (PR-front code review round 2, control-plane
    # adjudicated 2026-08-26): write order reversed -- failures.jsonl first,
    # completeness.json last as a seal. If this process is killed/crashes
    # mid-write, completeness.json existing now implies failures.jsonl is
    # already fully written (the seal was only written after), so a
    # comparator that trusts "completeness.json present == this side's
    # capture finished" can no longer be fooled by a truncated/missing
    # failures.jsonl that got left behind by the OLD order (completeness.json
    # written first, so it could exist and look "done" while failures.jsonl
    # was still being written or never got written at all).
    with open(failures_out_path, 'w', encoding='utf-8') as f:
        # 失败形态集合按 (target,mode) 去重，但逐条 test 归属仍全量保留在 JSON 行里
        for rec in result['failures']:
            f.write(json.dumps(rec, sort_keys=True))
            f.write('\n')

    with open(completeness_out_path, 'w', encoding='utf-8') as f:
        json.dump(completeness, f, indent=2, sort_keys=True)
        f.write('\n')

    print(
        f"[w1-normalize-failures] started={result['started_targets']} "
        f"finished={result['finished_targets']} expected={expected_targets} "
        f"compile_error={result['compile_error']} "
        f"run_count_mismatches={len(result['run_count_mismatches'])} "
        f"failures={len(result['failures'])} poison_excluded={result['poison_excluded']} "
        f"complete={completeness['complete']}",
        file=sys.stderr,
    )
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
