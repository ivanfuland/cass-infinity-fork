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
ABS_PATH_RE = re.compile(r'/[^\s:]+/([A-Za-z0-9_.\-]+\.rs)')
# plan delta d8: cross-run thread ids in "thread '<name>' (<PID>) panicked" are not
# stable (random per-process), so leaving them in makes two runs of the identical
# assertion normalize to different strings and get misclassified as a new failure
# form. Same for the ephemeral first-level /tmp/<random> segment (tempfile-crate
# dirs, per-worktree CARGO_TARGET_DIR hash) that appears throughout panic payloads.
THREAD_PID_RE = re.compile(r"(thread '[^']*') \(\d+\) panicked")
TMPDIR_RE = re.compile(r'/tmp/[^/\s]+')


def normalize_mode(text):
    t = LOC_RE.sub('<LOC>', text)
    t = ADDR_RE.sub('<ADDR>', t)
    t = TIME_RE.sub('<TIME>', t)
    t = ABS_PATH_RE.sub(r'<PATH>/\1', t)
    t = THREAD_PID_RE.sub(r'\1 (<PID>) panicked', t)
    t = TMPDIR_RE.sub('/tmp/<TMPDIR>', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t


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
        nonlocal finished
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
        for name in cur_failed_names:
            body = '\n'.join(stdout_blocks.get(name, []))
            if is_poison_cascade(body):
                poison_excluded_ref[0] += 1
                continue
            mode = normalize_mode(body) if body else '<no-captured-output>'
            failures.append({'target': cur_target, 'test': name, 'mode': mode})
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
        'complete': (
            result['started_targets'] == result['finished_targets'] == expected_targets
            and not result['compile_error']
        )
        if expected_targets is not None
        else False,
    }

    with open(completeness_out_path, 'w', encoding='utf-8') as f:
        json.dump(completeness, f, indent=2, sort_keys=True)
        f.write('\n')

    with open(failures_out_path, 'w', encoding='utf-8') as f:
        # 失败形态集合按 (target,mode) 去重，但逐条 test 归属仍全量保留在 JSON 行里
        for rec in result['failures']:
            f.write(json.dumps(rec, sort_keys=True))
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
