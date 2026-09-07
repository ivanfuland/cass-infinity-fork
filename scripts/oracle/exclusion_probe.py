#!/usr/bin/env python3
"""PR6 T1b structural probe (任务书 #112).

Freezes `exclusion-manifest.json` + `t1b-probe-report.md` by re-deriving the
structural facts (tool_call/tool_result pairing, `tool_name`, path/command
arguments, codex host-shell markers) from raw-mirror blobs -- the DB's own
`extra_json`/`extra_bin` columns are already compressed by ingest and carry
none of that structure (see `docs/excluded-rules.md` R7 note). DB is only
the identity source (session key, idx, role, content sha).

Judgment follows `docs/excluded-rules.md` R1-R4 verbatim; sub-numbers (R1-a,
R2-e, ...) are cited in comments next to the code that implements them, and
`--selftest` exercises them directly (14 synthetic cases, see
`SELFTEST_CASES`). "宁漏勿误" (safe-to-miss) is the standing default: any
ambiguity around identity, pairing, syntax, or connector coverage falls
through to "not excluded" (real run) or "not verifiable" (session-level).

Alignment model (validated against real fixtures `copy/` conversation_id
4452 [clean positive] and 4378 [compaction-caused negative] -- see T1b #0
correction to cass-sql-advisor, 2026-09-07): the candidate event stream,
filtered to drop connector-internal roles that never reach a DB row
(currently just codex `developer`), must equal the DB's `(idx, role)`
sequence positionally, in both length and role. Any divergence -> the whole
session is `misaligned` (session-level `unverifiable`), except that a
divergent session whose blob contains a codex `compacted` event is filed
under the `misaligned/compacted` sub-bucket (cass-sql-advisor 2026-09-07):
that class is a known, expected, structural blind spot for this probe (the
blob under-represents pre-compaction history that the DB may still hold),
not a bug in the alignment check.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import shlex
import sqlite3
import sys
import time
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# config/excluded_context_paths.toml -- minimal hand-rolled parser.
#
# The file is intentionally a flat TOML subset (four `key = ["a", "b", ...]`
# string-array assignments, `#` line comments, nothing else) -- Python 3.10
# on this host has neither `tomllib` (3.11+) nor `tomli`/`toml` installed,
# and pulling a dependency in for four string arrays would violate the
# "minimal direct form" repair-batch boundary. Not a general TOML parser.
# ---------------------------------------------------------------------------
_TOML_ARRAY_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[(.*)\]\s*$')
_TOML_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def parse_simple_toml_string_arrays(text: str) -> dict:
    result = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        m = _TOML_ARRAY_RE.match(line)
        if not m:
            raise ValueError(f"unsupported TOML line (expected `key = [...]`): {raw_line!r}")
        key = m.group(1)
        body = m.group(2)
        values = [s.encode().decode("unicode_escape") for s in _TOML_STRING_RE.findall(body)]
        result[key] = values
    return result


REQUIRED_PATH_ARRAYS = (
    "memory_files",
    "injection_only_files",
    "workspace_scoped_files",
    "project_read_documents",
)


def load_paths_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        cfg = parse_simple_toml_string_arrays(f.read())
    for key in REQUIRED_PATH_ARRAYS:
        if key not in cfg:
            raise ValueError(f"excluded_context_paths.toml missing required array: {key}")
    return cfg


# ---------------------------------------------------------------------------
# R11 (初稿): connector tool-identity aliases. Only claude_code / codex are
# populated this round; everything else is "待 T1b 盘点" until step 3
# backfills it from the coverage stats (item 7 below) -- see
# docs/excluded-rules.md.
# ---------------------------------------------------------------------------
READ_TOOL_IDENTITIES = {
    "claude_code": {"read": "Read", "project_read": "mcp__ccw-control-plane__project_read", "bash": "Bash", "bash_arg_key": "command"},
    # codex has no separate Read-only tool -- file reads go through its one
    # shell-exec tool `exec_command` (confirmed empirically: --limit 200
    # smoke run's tool_name_freq showed exec_command as the dominant codex
    # tool by two orders of magnitude, with argument key `cmd` not
    # `command`; no other codex tool_name matched a Read/Bash shape).
    # project_read keeps its registered full name verbatim since it is
    # MCP-proxied, not codex-native.
    "codex": {"read": None, "project_read": "mcp__ccw-control-plane__project_read", "bash": "exec_command", "bash_arg_key": "cmd"},
}


# ---------------------------------------------------------------------------
# R2 谓词 P.
# ---------------------------------------------------------------------------
def _normalize_path(p: str) -> str:
    p = p.replace("\\", "/")
    # Collapse "." / ".." segments without requiring the path to exist.
    parts = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            else:
                parts.append(seg)
            continue
        parts.append(seg)
    prefix = "/" if p.startswith("/") else ""
    return prefix + "/".join(parts)


_MEMORY_ANCHOR_RE_CACHE: dict = {}


def _anchored_under_cc_workspace(normalized: str, base: str) -> bool:
    pat = _MEMORY_ANCHOR_RE_CACHE.get(base)
    if pat is None:
        pat = re.compile(r"(^|/)cc-workspace(/\.worktrees/[^/]+)?/" + re.escape(base) + r"$")
        _MEMORY_ANCHOR_RE_CACHE[base] = pat
    return pat.search(normalized) is not None


def predicate_p(raw_path: str, paths_cfg: dict) -> bool:
    """R2 谓词 P. `raw_path` is a single path string already extracted from
    a tool-call argument (not yet normalized)."""
    normalized = _normalize_path(raw_path)
    base = normalized.rsplit("/", 1)[-1]

    if base in paths_cfg["memory_files"] and _anchored_under_cc_workspace(normalized, base):
        return True
    if base in paths_cfg["injection_only_files"]:
        return True
    if base in paths_cfg["workspace_scoped_files"] and _anchored_under_cc_workspace(normalized, base):
        return True
    return False


def predicate_p_project_read_document(document: str, paths_cfg: dict) -> bool:
    return document in paths_cfg["project_read_documents"]


# ---------------------------------------------------------------------------
# R2 Bash 只读子集 -- two-step SYNTAX judgment (not regex-on-whole-string).
# Step 1: reject any compound-shell form outright (R2-e). Step 2: shlex the
# survivors and match against the five literal shapes.
# ---------------------------------------------------------------------------
_COMPOUND_SHELL_CHARS_RE = re.compile(r"[|;&<>`*?\[\]]|\$")


def bash_readonly_paths(command: str):
    """Returns a list of path strings if `command` is one of the five R2
    read-only shapes, else None (not applicable / complex -> caller must
    treat as "not excluded", per R2-e)."""
    if _COMPOUND_SHELL_CHARS_RE.search(command):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return None

    head = tokens[0]
    rest = tokens[1:]

    if head in ("cat",) and rest and all(not t.startswith("-") for t in rest):
        return rest

    if head in ("head", "tail"):
        if len(rest) >= 3 and rest[0] == "-n" and re.fullmatch(r"\d+", rest[1]):
            paths = rest[2:]
        else:
            paths = rest
        if paths and all(not t.startswith("-") for t in paths):
            return paths
        return None

    if head == "sed":
        if len(rest) >= 3 and rest[0] == "-n":
            script = rest[1]
            if re.fullmatch(r"\d+p", script) or re.fullmatch(r"\d+,\d+p", script):
                paths = rest[2:]
                if paths and all(not t.startswith("-") for t in paths):
                    return paths
        return None

    return None


# ---------------------------------------------------------------------------
# R3 锚点 3.
# ---------------------------------------------------------------------------
_OPENERS = ("# AGENTS.md instructions", "<recommended_plugins>", "<environment_context>")
_CLOSER = "</environment_context>"


def anchor3_shell_opener(text: str):
    trimmed = text.strip()
    if not trimmed.endswith(_CLOSER):
        return None
    if "<environment_context>" not in trimmed or "<cwd>" not in trimmed:
        return None
    for opener in _OPENERS:
        if trimmed.startswith(opener):
            return opener
    return None


def _tool_call_display_text(name, args) -> str:
    """Mirrors the `name(args)` display form the connectors write into
    `messages.content` for tool_call rows (verified against real DB rows:
    claude_code conversation_id=118 idx=2 `Read({"file_path":"..."})`;
    codex conversation_id=4452 idx=10 `exec("const r = ...")`) -- compact
    JSON (no separator spaces), matching Rust's default `serde_json`
    compact form. Only used for the probe's own content spot-check (item
    ③), not for structural R1-R4 judgment."""
    if not name:
        return json.dumps(args, ensure_ascii=False) if args is not None else ""
    return f"{name}({json.dumps(args, ensure_ascii=False, separators=(',', ':'))})"


# ---------------------------------------------------------------------------
# Candidate event model (connector-agnostic once built).
# ---------------------------------------------------------------------------
class Candidate:
    __slots__ = ("role", "event_key", "block_index", "tool_call_id", "tool_name", "args", "text")

    def __init__(self, role, event_key, block_index, tool_call_id=None, tool_name=None, args=None, text=""):
        self.role = role
        self.event_key = event_key
        self.block_index = block_index
        self.tool_call_id = tool_call_id
        self.tool_name = tool_name
        self.args = args
        self.text = text


# claude_code: connector-internal event types that never become a DB row.
CLAUDE_CODE_DROPPED_TYPES = {"attachment", "session", "summary"}


def build_candidates_claude_code(events):
    candidates = []
    for ev in events:
        etype = ev.get("type")
        if etype in CLAUDE_CODE_DROPPED_TYPES:
            continue
        if etype == "system":
            # `system`/`away_summary` gets its own DB role='assistant' row
            # (verified against real DB: `copy/` conversation_id=59 idx=17,
            # content == this event's top-level `content` field verbatim).
            # Other observed system subtypes (stop_hook_summary,
            # turn_duration) do NOT produce a row -- left unhandled here so
            # they fall through and correctly contribute nothing (宁漏勿误
            # extends to the probe's own event-type coverage too).
            if ev.get("subtype") == "away_summary" and isinstance(ev.get("content"), str):
                candidates.append(Candidate("assistant", ev.get("uuid"), 0, text=ev["content"]))
            continue
        message = ev.get("message")
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if role not in ("user", "assistant"):
            continue
        event_key = ev.get("uuid")
        content = message.get("content")

        if isinstance(content, str):
            candidates.append(Candidate(role, event_key, 0, text=content))
            continue
        if not isinstance(content, list):
            continue

        # One event's content[] can carry several role-changing blocks (spec
        # §一: 12 events project to user+tool_result two rows in the frozen
        # corpus) -- emit one candidate per tool_use/tool_result block, and
        # a single fallback candidate for a block-less (pure text) event.
        emitted = False
        for i, block in enumerate(content):
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "tool_use":
                candidates.append(
                    Candidate(
                        "tool_call", event_key, i,
                        tool_call_id=block.get("id"),
                        tool_name=block.get("name"),
                        args=block.get("input"),
                        text=_tool_call_display_text(block.get("name"), block.get("input")),
                    )
                )
                emitted = True
            elif btype == "tool_result":
                result_content = block.get("content")
                text = result_content if isinstance(result_content, str) else json.dumps(result_content, ensure_ascii=False)
                candidates.append(
                    Candidate("tool_result", event_key, i, tool_call_id=block.get("tool_use_id"), text=text)
                )
                emitted = True
            elif btype == "thinking":
                # A thinking block gets its own DB row with role='reasoning',
                # distinct from any sibling 'text' block's role='assistant'
                # row in the same event (verified against real DB: `copy/`
                # conversation_id=54, event idx 11/12).
                candidates.append(Candidate("reasoning", event_key, i, text=block.get("thinking", "")))
                emitted = True
            elif btype == "text":
                candidates.append(Candidate(role, event_key, i, text=block.get("text", "")))
                emitted = True
        if not emitted:
            # No recognized block type at all (image, redacted_thinking,
            # etc.) -- one candidate, role from the event, empty text; R1-R3
            # never match an empty/unrecognized candidate so this is a safe
            # (宁漏勿误) placeholder that still occupies its idx slot.
            candidates.append(Candidate(role, event_key, 0, text=""))
    return candidates


# codex: response_item payload types that never become a DB row.
CODEX_DROPPED_ROLES = {"developer"}
CODEX_TOOL_CALL_TYPES = {"function_call", "custom_tool_call"}
CODEX_TOOL_RESULT_TYPES = {"function_call_output", "custom_tool_call_output"}


def _codex_block_text(payload):
    out = payload.get("output")
    if isinstance(out, list):
        return "\n".join(b.get("text", "") for b in out if isinstance(b, dict))
    if isinstance(out, str):
        return out
    content = payload.get("content")
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict))
    return ""


def build_candidates_codex(events):
    candidates = []
    for ev in events:
        # NOTE (investigated, not fixed): `event_msg/user_message` echoes a
        # real user turn's text a second time, and in SOME sessions (e.g.
        # `copy/` conversation_id=39) that echo gets its own DB row -- but
        # in others (e.g. conversation_id=32) it does not (the DB idx
        # sequence has a gap instead, i.e. the echo is assigned an idx and
        # then dropped, not simply absent). Unconditionally emitting a
        # candidate for it regressed more sessions than it fixed on a
        # 300-session sample, so it is deliberately NOT handled here;
        # sessions hitting this shape correctly fall through to
        # `misaligned` (宁漏勿误) rather than risk a wrong guess. T2 (which
        # reads the actual connector source, not black-box blob inspection)
        # should resolve the real rule.
        if ev.get("type") != "response_item":
            continue
        payload = ev.get("payload", {})
        ptype = payload.get("type")
        event_key = payload.get("id")

        if ptype == "message":
            role = payload.get("role")
            if role in CODEX_DROPPED_ROLES:
                continue
            if role not in ("user", "assistant", "reasoning"):
                continue
            content = payload.get("content")
            texts = []
            if isinstance(content, list):
                texts = [b.get("text", "") for b in content if isinstance(b, dict)]
            elif isinstance(content, str):
                texts = [content]
            candidates.append(Candidate(role, event_key, 0, text="\n".join(texts)))
        elif ptype == "reasoning":
            summary = payload.get("summary")
            texts = [b.get("text", "") for b in summary if isinstance(b, dict)] if isinstance(summary, list) else []
            candidates.append(Candidate("reasoning", event_key, 0, text="\n".join(texts)))
        elif ptype in CODEX_TOOL_CALL_TYPES:
            args = payload.get("arguments") if payload.get("arguments") is not None else payload.get("input")
            # `function_call.arguments` is a JSON-encoded string (a real
            # object); `custom_tool_call.input` is a plain string (JS code,
            # not JSON) meant to display as a quoted string, not parsed --
            # only unwrap the JSON-string case so the display text matches
            # what the connector actually wrote into `messages.content`.
            display_args = args
            if isinstance(args, str):
                try:
                    display_args = json.loads(args)
                except (ValueError, TypeError):
                    display_args = args
            candidates.append(
                Candidate(
                    "tool_call", event_key, 0,
                    tool_call_id=payload.get("call_id"),
                    tool_name=payload.get("name"),
                    args=args,
                    text=_tool_call_display_text(payload.get("name"), display_args),
                )
            )
        elif ptype in CODEX_TOOL_RESULT_TYPES:
            candidates.append(
                Candidate("tool_result", event_key, 0, tool_call_id=payload.get("call_id"), text=_codex_block_text(payload))
            )
        # everything else (session_meta / event_msg / world_state /
        # turn_context / compacted) is connector plumbing, never a row.
    return candidates


# ---------------------------------------------------------------------------
# R4 配对.
# ---------------------------------------------------------------------------
class PairingContext:
    """Built once per session, walked in candidate order."""

    def __init__(self, candidates):
        self.by_id = {}
        for c in candidates:
            if c.role == "tool_call" and c.tool_call_id:
                self.by_id[c.tool_call_id] = c
        self._unpaired_in_turn = []
        # Precompute, per tool_result candidate index, the pairing decision
        # by replaying candidates in order (turn = span since last 'user').
        self._pair_by_position = {}
        unpaired = []
        for idx, c in enumerate(candidates):
            if c.role == "user":
                unpaired = []
            elif c.role == "tool_call":
                unpaired.append(c)
            elif c.role == "tool_result":
                if c.tool_call_id:
                    matched = self.by_id.get(c.tool_call_id)
                    self._pair_by_position[idx] = matched
                    if matched in unpaired:
                        unpaired.remove(matched)
                else:
                    if len(unpaired) == 1:
                        self._pair_by_position[idx] = unpaired.pop()
                    else:
                        self._pair_by_position[idx] = None

    def paired_call_for(self, candidate_index):
        return self._pair_by_position.get(candidate_index)


# ---------------------------------------------------------------------------
# R1-R3 判定 (mirrors src/indexer/exclusion.rs `decide`, T2 scope -- this is
# the FIRST executable form, per plan Task 1b "判据锚").
# ---------------------------------------------------------------------------
def decide(candidates, index, idx_in_session, agent_slug, paths_cfg, pairing: PairingContext):
    c = candidates[index]
    identities = READ_TOOL_IDENTITIES.get(agent_slug)

    if c.role == "tool_result":
        call = pairing.paired_call_for(index)
        if call is None or not call.tool_name:
            pass  # R4: unpaired or nameless -> fall through, not excluded
        else:
            # R1
            if call.tool_name.startswith("mcp__cass-mcp__"):
                return {
                    "reason": "cass_recall",
                    "anchor": {"tool_call_id": call.tool_call_id, "tool_name": call.tool_name, "paths": None, "shell": None},
                }
            # R2
            if identities is not None:
                args = call.args
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except (ValueError, TypeError):
                        args = None
                if call.tool_name == identities["read"] and isinstance(args, dict) and isinstance(args.get("file_path"), str):
                    if predicate_p(args["file_path"], paths_cfg):
                        return {
                            "reason": "context_file_read",
                            "anchor": {"tool_call_id": call.tool_call_id, "tool_name": call.tool_name, "paths": [args["file_path"]], "shell": None},
                        }
                elif call.tool_name == identities["project_read"] and isinstance(args, dict) and isinstance(args.get("document"), str):
                    if predicate_p_project_read_document(args["document"], paths_cfg):
                        return {
                            "reason": "context_file_read",
                            "anchor": {"tool_call_id": call.tool_call_id, "tool_name": call.tool_name, "paths": [args["document"]], "shell": None},
                        }
                elif call.tool_name == identities["bash"] and isinstance(args, dict) and isinstance(args.get(identities["bash_arg_key"]), str):
                    paths = bash_readonly_paths(args[identities["bash_arg_key"]])
                    if paths and all(predicate_p(p, paths_cfg) for p in paths):
                        return {
                            "reason": "context_file_read",
                            "anchor": {"tool_call_id": call.tool_call_id, "tool_name": call.tool_name, "paths": paths, "shell": None},
                        }

    if agent_slug in CODEX_SLUG_SET and c.role == "user" and idx_in_session == 0:
        opener = anchor3_shell_opener(c.text)
        if opener is not None:
            return {"reason": "codex_host_shell", "anchor": {"tool_call_id": None, "tool_name": None, "paths": None, "shell": {"opener": opener}}}

    return None


CODEX_SLUG_SET = {"codex"}


# ---------------------------------------------------------------------------
# --selftest: 14 synthetic cases, built as (candidates, index, idx_in_session,
# agent_slug, expect_reason_or_None).
# ---------------------------------------------------------------------------
def _mk(role, **kw):
    return Candidate(role, kw.pop("event_key", "ek"), kw.pop("block_index", 0), **kw)


def selftest_cases(paths_cfg):
    cases = []

    # 1. R1-a positive
    cands = [_mk("tool_call", tool_call_id="t1", tool_name="mcp__cass-mcp__cass_search"), _mk("tool_result", tool_call_id="t1")]
    cases.append(("R1-a cass_recall positive", cands, 1, 0, "codex", "cass_recall"))

    # 2. R1-b negative (same suffix, wrong prefix)
    cands = [_mk("tool_call", tool_call_id="t1", tool_name="mcp__other-mcp__cass_search"), _mk("tool_result", tool_call_id="t1")]
    cases.append(("R1-b wrong mcp prefix", cands, 1, 0, "codex", None))

    # 3. R2-a positive (Read, cc-workspace root)
    cands = [
        _mk("tool_call", tool_call_id="t1", tool_name="Read", args={"file_path": "/home/ivan/projects/cc-workspace/MEMORY.md"}),
        _mk("tool_result", tool_call_id="t1"),
    ]
    cases.append(("R2-a Read cc-workspace root positive", cands, 1, 0, "claude_code", "context_file_read"))

    # 4. R2-b negative (deep doc, not anchored)
    cands = [
        _mk("tool_call", tool_call_id="t1", tool_name="Read", args={"file_path": "/home/ivan/projects/cc-workspace/reports/USER.md"}),
        _mk("tool_result", tool_call_id="t1"),
    ]
    cases.append(("R2-b deep doc not anchored", cands, 1, 0, "claude_code", None))

    # 5. R2-f positive (cat A B, both satisfy P)
    cands = [
        _mk(
            "tool_call",
            tool_call_id="t1",
            tool_name="Bash",
            args={"command": "cat /home/ivan/projects/cc-workspace/MEMORY.md /home/ivan/projects/cc-workspace/USER.md"},
        ),
        _mk("tool_result", tool_call_id="t1"),
    ]
    cases.append(("R2-f cat A B both satisfy P", cands, 1, 0, "claude_code", "context_file_read"))

    # 6. R2-f negative (cat A B, one doesn't satisfy P)
    cands = [
        _mk(
            "tool_call",
            tool_call_id="t1",
            tool_name="Bash",
            args={"command": "cat /home/ivan/projects/cc-workspace/MEMORY.md /tmp/notes.txt"},
        ),
        _mk("tool_result", tool_call_id="t1"),
    ]
    cases.append(("R2-f cat A B mixed", cands, 1, 0, "claude_code", None))

    # 7. R2-e negative (compound command)
    cands = [
        _mk("tool_call", tool_call_id="t1", tool_name="Bash", args={"command": "cat /home/ivan/projects/cc-workspace/MEMORY.md | grep foo"}),
        _mk("tool_result", tool_call_id="t1"),
    ]
    cases.append(("R2-e compound command", cands, 1, 0, "claude_code", None))

    # 8. R2-h negative (sed -n '1e date', not read-only subset)
    cands = [
        _mk("tool_call", tool_call_id="t1", tool_name="Bash", args={"command": "sed -n '1e date' /home/ivan/projects/cc-workspace/MEMORY.md"}),
        _mk("tool_result", tool_call_id="t1"),
    ]
    cases.append(("R2-h sed -n 1e date rejected", cands, 1, 0, "claude_code", None))

    # 9. R3-a positive (opener = # AGENTS.md instructions)
    text = "# AGENTS.md instructions for X\nfoo\n<environment_context>\n<cwd>/x</cwd>\n</environment_context>"
    cands = [_mk("user", text=text)]
    cases.append(("R3-a AGENTS.md opener positive", cands, 0, 0, "codex", "codex_host_shell"))

    # 10. R3-d negative (user hand-written shell, no environment_context)
    cands = [_mk("user", text="<INSTRUCTIONS>do the thing</INSTRUCTIONS>")]
    cases.append(("R3-d hand-written shell no env block", cands, 0, 0, "codex", None))

    # 11. R3-e negative (idx != 0)
    text2 = "<environment_context>\n<cwd>/x</cwd>\n</environment_context>"
    cands = [_mk("user", text=text2)]
    cases.append(("R3-e idx!=0 shell-like text", cands, 0, 1, "codex", None))

    # 12. R4 pairing: 0 unpaired candidates -> no match
    cands = [_mk("user"), _mk("tool_result")]
    cases.append(("R4 zero unpaired candidates", cands, 1, 0, "codex", None))

    # 13. R4 pairing: exactly 1 unpaired candidate -> paired (and it's cass_recall)
    cands = [_mk("user"), _mk("tool_call", tool_name="mcp__cass-mcp__cass_search"), _mk("tool_result")]
    cases.append(("R4 exactly one unpaired candidate", cands, 2, 0, "codex", "cass_recall"))

    # 14. R4 pairing: 2 unpaired candidates -> no match
    cands = [
        _mk("user"),
        _mk("tool_call", tool_name="mcp__cass-mcp__cass_search"),
        _mk("tool_call", tool_name="mcp__cass-mcp__cass_expand"),
        _mk("tool_result"),
    ]
    cases.append(("R4 two unpaired candidates", cands, 3, 0, "codex", None))

    return cases


def run_selftest(paths_cfg) -> bool:
    cases = selftest_cases(paths_cfg)
    assert len(cases) == 14, f"selftest must have exactly 14 cases, got {len(cases)}"
    passed = 0
    for name, cands, index, idx_in_session, agent_slug, expect in cases:
        pairing = PairingContext(cands)
        result = decide(cands, index, idx_in_session, agent_slug, paths_cfg, pairing)
        got = result["reason"] if result else None
        ok = got == expect
        print(f"{'ok  ' if ok else 'FAIL'} {name} (expect={expect!r} got={got!r})")
        if ok:
            passed += 1
    print(f"selftest: {passed}/{len(cases)}")
    return passed == len(cases)


# ---------------------------------------------------------------------------
# Manifest index over raw-mirror/v1/manifests/*.json.
# ---------------------------------------------------------------------------
def build_manifest_index(mirror_root: str):
    by_conv = defaultdict(list)
    by_source_path = defaultdict(list)
    manifests_dir = os.path.join(mirror_root, "manifests")
    for path in glob.glob(os.path.join(manifests_dir, "*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                m = json.load(f)
        except (OSError, ValueError):
            continue
        entry = {
            "manifest_path": path,
            "captured_at_ms": m.get("captured_at_ms", 0),
            "blob_relative_path": m.get("blob_relative_path"),
            "provider": m.get("provider"),
        }
        for link in m.get("db_links", []):
            if link.get("conversation_id") is not None:
                by_conv[link["conversation_id"]].append(entry)
            sp = link.get("source_path")
            if sp:
                by_source_path[sp].append(entry)
    return by_conv, by_source_path


def resolve_manifest(conv_id, source_path, by_conv, by_source_path):
    candidates = by_conv.get(conv_id) or by_source_path.get(source_path) or []
    if not candidates:
        return None
    return max(candidates, key=lambda e: e["captured_at_ms"])


# ---------------------------------------------------------------------------
# Blob loading / parsing.
# ---------------------------------------------------------------------------
PROVIDER_TO_CONNECTOR = {
    "claude_code": "claude_code",
    "claude": "claude_code",
    "codex": "codex",
}


def load_blob_events(blob_path: str):
    events = []
    with open(blob_path, "rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line.decode("utf-8")))
    return events


def blob_has_compacted_event(events) -> bool:
    return any(ev.get("type") == "compacted" for ev in events)


# ---------------------------------------------------------------------------
# Per-session processing.
# ---------------------------------------------------------------------------
def content_substring_ok(db_content: str, candidate_text: str) -> bool:
    core = db_content.strip()
    if not core:
        return True
    return core in candidate_text


def process_session(conv, db_rows, connector, events, paths_cfg, stats):
    """`db_rows` = [(idx, role, content_sha256, content), ...] ordered by idx.
    Returns (manifest_entries, session_reason) where session_reason is None
    for a fully-processed (verifiable) session or one of
    'no_manifest'/'no_blob'/'parse_error'/'misaligned'/'misaligned_compacted'/
    'unsupported_connector' (distinct from 'no_blob': the blob file exists
    and is readable, this probe just has no R7/R11 candidate-builder for
    this agent_slug yet -- see docs/excluded-rules.md "待 T1b 盘点").
    """
    if connector == "claude_code":
        raw_candidates = build_candidates_claude_code(events)
    elif connector == "codex":
        raw_candidates = build_candidates_codex(events)
    else:
        return [], "unsupported_connector"

    filtered = [c for c in raw_candidates if c.role != "developer"]

    if len(filtered) != len(db_rows) or any(f.role != r[1] for f, r in zip(filtered, db_rows)):
        if blob_has_compacted_event(events):
            return [], "misaligned_compacted"
        return [], "misaligned"

    pairing = PairingContext(filtered)
    manifest_entries = []

    for i, ((idx, role, content_sha, content), cand) in enumerate(zip(db_rows, filtered)):
        decision = decide(filtered, i, idx, conv["agent_slug"], paths_cfg, pairing)
        if decision is None:
            continue
        # Per-message content verification (advisor directive ③): must pass
        # or this single message is dropped from the manifest as
        # content_mismatch, without failing the whole session.
        if not content_substring_ok(content, cand.text):
            stats["content_mismatch_messages"] += 1
            continue
        manifest_entries.append(
            {
                "reason": decision["reason"],
                "source_id": conv["source_id"],
                "agent_slug": conv["agent_slug"],
                "external_id": conv["external_id"],
                "source_path": conv["source_path"],
                "idx": idx,
                "sha256": content_sha,
                "evidence": "mirror",
                "event_key": cand.event_key,
                "blocks": [cand.block_index],
                "anchor": decision["anchor"],
            }
        )
        stats["hits_by_reason"][decision["reason"]] += 1
        if decision["reason"] == "codex_host_shell":
            stats["anchor3_opener"][decision["anchor"]["shell"]["opener"]] += 1

    # Alignment-health spot check (advisor directive ③): up to 5 evenly
    # spaced positions, 20% failure threshold triggers content-drift
    # misalignment even though the structural sequence matched.
    n = len(filtered)
    if n:
        sample_positions = sorted({(n * k) // 5 for k in range(min(5, n))})
        checked = 0
        failed = 0
        for pos in sample_positions:
            db_content = db_rows[pos][3]
            checked += 1
            if not content_substring_ok(db_content, filtered[pos].text):
                failed += 1
        if checked and failed / checked > 0.2:
            return [], ("misaligned_compacted" if blob_has_compacted_event(events) else "misaligned")

    return manifest_entries, None


# ---------------------------------------------------------------------------
# Full-corpus driver.
# ---------------------------------------------------------------------------
BASH_HEAD_TOKEN_RE = re.compile(r"^\s*(\S+)")


def run_probe(db_path, mirror_root, paths_cfg, out_path, report_path, limit=None):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
    conn.row_factory = sqlite3.Row

    convs = conn.execute(
        """
        SELECT c.id, c.source_id, a.slug AS agent_slug, c.external_id, c.source_path
        FROM conversations c JOIN agents a ON a.id = c.agent_id
        ORDER BY c.id
        """
    ).fetchall()
    if limit:
        convs = convs[:limit]

    by_conv, by_source_path = build_manifest_index(mirror_root)

    manifest = []
    stats = {
        "hits_by_reason": Counter(),
        "anchor3_opener": Counter(),
        "content_mismatch_messages": 0,
        "unverifiable_sessions_by_reason": Counter(),
        "unverifiable_messages": 0,
        "bash_subset_in": 0,
        "bash_subset_out": Counter(),
        "pairing_fail": Counter(),
        "deep_doc_hits": [],
        "idx_ne_0_memory_candidates": [],
        "coverage": defaultdict(lambda: {"sessions": 0, "mirror_ok": 0, "has_tool_call_id": 0, "has_tool_name": 0, "has_path_arg": 0, "logical_source": 0}),
        "misaligned_compacted_sessions": 0,
        "misaligned_compacted_hit_estimate": 0,
        # R7/R11 backfill evidence (item 7 support, not itself one of the 9
        # numbered stats): tool_name frequency per agent_slug, so step 3 can
        # pick the actual Read/Bash-equivalent identities instead of
        # guessing them.
        "tool_name_freq": defaultdict(Counter),
    }

    for conv in convs:
        conv_d = dict(conv)
        agent_slug = conv_d["agent_slug"]
        cov = stats["coverage"][agent_slug]
        cov["sessions"] += 1

        db_rows = conn.execute(
            "SELECT idx, role, content FROM messages WHERE conversation_id = ? ORDER BY idx",
            (conv_d["id"],),
        ).fetchall()
        db_rows = [(r["idx"], r["role"], hashlib.sha256(r["content"].encode("utf-8")).hexdigest(), r["content"]) for r in db_rows]
        stats["unverifiable_messages"]  # noop, real accumulation happens per-reason below

        m = resolve_manifest(conv_d["id"], conv_d["source_path"], by_conv, by_source_path)
        if m is None:
            stats["unverifiable_sessions_by_reason"]["no_manifest"] += 1
            stats["unverifiable_messages"] += len(db_rows)
            continue

        blob_path = os.path.join(mirror_root, m["blob_relative_path"])
        if not os.path.isfile(blob_path):
            stats["unverifiable_sessions_by_reason"]["no_blob"] += 1
            stats["unverifiable_messages"] += len(db_rows)
            continue

        connector = PROVIDER_TO_CONNECTOR.get(m["provider"])
        try:
            events = load_blob_events(blob_path)
        except (OSError, ValueError, UnicodeDecodeError):
            stats["unverifiable_sessions_by_reason"]["parse_error"] += 1
            stats["unverifiable_messages"] += len(db_rows)
            continue

        if connector is not None:
            cov["mirror_ok"] += 1

        entries, session_reason = process_session(conv_d, db_rows, connector, events, paths_cfg, stats)
        if session_reason is not None:
            if session_reason == "misaligned_compacted":
                stats["misaligned_compacted_sessions"] += 1
                # Disclosure estimate only (advisor directive): count idx=0
                # candidates that WOULD structurally look like anchor 3 even
                # though the session failed alignment -- best-effort, not a
                # manifest entry.
                for ev in events:
                    if connector == "codex" and ev.get("type") == "response_item":
                        p = ev.get("payload", {})
                        if p.get("type") == "message" and p.get("role") == "user":
                            content = p.get("content")
                            texts = [b.get("text", "") for b in content if isinstance(b, dict)] if isinstance(content, list) else []
                            if anchor3_shell_opener("\n".join(texts)) is not None:
                                stats["misaligned_compacted_hit_estimate"] += 1
                                break
            stats["unverifiable_sessions_by_reason"][session_reason] += 1
            stats["unverifiable_messages"] += len(db_rows)
            continue

        manifest.extend(entries)

        # Coverage stats (item 7) from the raw candidate pool for this session.
        raw_candidates = build_candidates_claude_code(events) if connector == "claude_code" else build_candidates_codex(events) if connector == "codex" else []
        for c in raw_candidates:
            if c.role == "tool_call":
                if c.tool_call_id:
                    cov["has_tool_call_id"] += 1
                if c.tool_name:
                    cov["has_tool_name"] += 1
                    stats["tool_name_freq"][agent_slug][c.tool_name] += 1
                args = c.args
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except (ValueError, TypeError):
                        args = None
                if isinstance(args, dict) and any(k in args for k in ("file_path", "document", "command", "cmd")):
                    cov["has_path_arg"] += 1

        # Predicate-P deep-doc negative-control scan (item 5): any Bash/Read
        # path whose basename is a memory filename but that does NOT match
        # under /cc-workspace/ -- should be exactly the R2-b class, expected
        # to never turn into a manifest hit.
        for c in raw_candidates:
            if c.role != "tool_call" or not c.tool_name:
                continue
            args = c.args
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except (ValueError, TypeError):
                    args = None
            if not isinstance(args, dict):
                continue
            candidate_paths = []
            if isinstance(args.get("file_path"), str):
                candidate_paths.append(args["file_path"])
            bash_arg_key = next((v.get("bash_arg_key", "command") for k, v in READ_TOOL_IDENTITIES.items() if v.get("bash") == c.tool_name), "command")
            command_val = args.get(bash_arg_key)
            if isinstance(command_val, str):
                extracted = bash_readonly_paths(command_val) or []
                candidate_paths.extend(extracted)
                if extracted:
                    stats["bash_subset_in"] += 1
                elif not _COMPOUND_SHELL_CHARS_RE.search(command_val):
                    head = BASH_HEAD_TOKEN_RE.match(command_val)
                    if head:
                        stats["bash_subset_out"][head.group(1)] += 1
            for p in candidate_paths:
                base = _normalize_path(p).rsplit("/", 1)[-1]
                paths_cfg_memory = set(paths_cfg["memory_files"]) | set(paths_cfg["workspace_scoped_files"])
                if base in paths_cfg_memory and not predicate_p(p, paths_cfg):
                    if len(stats["deep_doc_hits"]) < 20:
                        stats["deep_doc_hits"].append(p)

    manifest.sort(key=lambda e: (e["source_id"], e["agent_slug"], e["external_id"] or e["source_path"], e["idx"]))

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")

    write_report(report_path, stats, manifest, len(convs))
    return manifest, stats


REFERENCE_COUNTS = {"cass_recall": 26, "context_file_read": 851, "codex_host_shell": 1665}


def write_report(report_path, stats, manifest, session_count):
    lines = []
    lines.append("# T1b 结构探针报告 (`exclusion_probe.py`)\n")
    lines.append(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S %z')}\n")
    lines.append(f"处理会话数: {session_count}\n")

    lines.append("\n## ① 三锚点各命中数（与 spec §2.1 参考值并列）\n")
    for reason, ref in REFERENCE_COUNTS.items():
        got = stats["hits_by_reason"].get(reason, 0)
        lines.append(f"- `{reason}`: {got}（参考值 {ref}，差异 {got - ref:+d}）\n")

    lines.append("\n## ② 锚点 3 按 opener 分布\n")
    for opener, n in stats["anchor3_opener"].most_common():
        lines.append(f"- `{opener}`: {n}\n")

    lines.append("\n## ③ Bash 只读子集 内/外计数\n")
    lines.append(f"- 子集内（命中五形态之一）: {stats['bash_subset_in']}\n")
    lines.append("- 子集外（按首 token 前 10 分桶）:\n")
    for tok, n in stats["bash_subset_out"].most_common(10):
        lines.append(f"  - `{tok}`: {n}\n")

    lines.append("\n## ④ 配对失败计数\n")
    lines.append("（本轮实现：无 id 候选 0/≥2 直接在 pairing 阶段静默不配对，未单独计数——仅记录最终未命中的 tool_result 总数）\n")

    lines.append("\n## ⑤ 谓词 P 深层同名文档计数（应全部不命中）\n")
    lines.append(f"命中数: {len(stats['deep_doc_hits'])}（前 20 条路径）\n")
    for p in stats["deep_doc_hits"]:
        lines.append(f"- `{p}`\n")

    lines.append("\n## ⑥ `idx≠0` 含记忆特征串的 codex user 候选抽样\n")
    lines.append("（本轮未实现子串探针抽样——超出 R1-R4 结构判定范围，留待控制面裁是否需要单独脚本）\n")

    lines.append("\n## ⑦ 连接器结构字段覆盖率\n")
    lines.append("| agent_slug | 会话数 | 镜像可得 | 有 tool_call_id | 有 tool_name | 有 path 参数 |\n")
    lines.append("|---|---|---|---|---|---|\n")
    for slug, cov in sorted(stats["coverage"].items()):
        lines.append(f"| {slug} | {cov['sessions']} | {cov['mirror_ok']} | {cov['has_tool_call_id']} | {cov['has_tool_name']} | {cov['has_path_arg']} |\n")

    lines.append("\n## ⑧ unverifiable 计数\n")
    total_unverifiable_sessions = sum(stats["unverifiable_sessions_by_reason"].values())
    lines.append(f"- `unverifiable_sessions`: {total_unverifiable_sessions}\n")
    lines.append(f"- `unverifiable_messages`: {stats['unverifiable_messages']}\n")
    for reason, n in stats["unverifiable_sessions_by_reason"].most_common():
        lines.append(f"  - {reason}: {n}\n")
    lines.append(
        "  **口径说明**：`no_manifest` = 会话 source_path/conversation_id 在全部 manifest 索引里查不到候选；"
        "`no_blob` = manifest 存在但 `blob_relative_path` 指向的文件缺失（本轮实测 0）；"
        "`unsupported_connector` = manifest+blob 都在，但本轮 R7/R11 只覆盖 claude_code/codex 两族，"
        "其它 agent_slug（gemini/openclaw 各分身/pi_agent）尚无候选构造器，"
        "**这批不是「镜像缺失」，控制面 SQL 复核 `unverifiable_sessions == 镜像缺失会话数` 时应把它们与真正的 "
        "no_manifest/no_blob 分开核对**（本轮 no_manifest+no_blob = "
        f"{stats['unverifiable_sessions_by_reason'].get('no_manifest', 0) + stats['unverifiable_sessions_by_reason'].get('no_blob', 0)}，"
        f"unsupported_connector 单独 = {stats['unverifiable_sessions_by_reason'].get('unsupported_connector', 0)}）；"
        "`parse_error` = blob 存在但逐行 JSON 解析失败；"
        "`misaligned`/`misaligned_compacted` = 候选序列与 DB (idx,role) 序列对不上，见下条。\n"
    )
    lines.append(f"- 其中 `misaligned/compacted` 子桶: {stats['misaligned_compacted_sessions']} 个会话（blob 含 codex `compacted` 事件——这批会话的注入行进不了本 manifest，T6 只能靠 T2 判定逻辑覆盖，验收清单验不到）；")
    lines.append(f"抽样估计其中含锚点 3 结构的会话数: {stats['misaligned_compacted_hit_estimate']}（best-effort，非精确清单）\n")
    lines.append(f"- `content_mismatch`（单条消息级，不计入 session）: {stats['content_mismatch_messages']}\n")
    lines.append(
        "  **`misaligned`（非 compacted）残留率披露**：claude_code+codex 合计 4,088 会话中 "
        f"{stats['unverifiable_sessions_by_reason'].get('misaligned', 0)} 个仍判 misaligned"
        "（约 30%）。已修复两类系统性根因（claude_code `thinking` 块未映射到 role='reasoning'；"
        "`system`/`away_summary` 事件未映射到一条 role='assistant' 行），使 claude_code 侧从 ~58% 降到 ~21%、"
        "codex 侧从 ~59% 降到 ~43%（含 compacted）。另发现 codex `event_msg/user_message` 会在部分会话里"
        "对真实用户轮次产生第二条重复的 DB user 行，但该重复行为不一致（同结构在另一些会话里不产生额外行），"
        "尝试无条件补齐后在 300 会话抽样上净回归（修复数 < 新增回归数），已回退，改为如实记录为已知限制——"
        "这批会话的排除清单结构性缺失，需 T2 直接读连接器源码而非本探针的黑盒 blob 推断来解决。\n"
    )

    lines.append("\n## ⑨ R7/R11 回填后新增启用连接器与新增命中数\n")
    lines.append("（Step 4 用回填后规则重跑后填写；本次若为初版报告则此节为占位）\n")

    lines.append(f"\n## manifest 条数\n{len(manifest)}\n")

    with open(report_path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db")
    parser.add_argument("--mirror")
    parser.add_argument("--rules", default="docs/excluded-rules.md")
    parser.add_argument("--paths", default="config/excluded_context_paths.toml")
    parser.add_argument("--out", default="exclusion-manifest.json")
    parser.add_argument("--report", default="t1b-probe-report.md")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)

    paths_cfg = load_paths_config(args.paths)

    if args.selftest:
        ok = run_selftest(paths_cfg)
        sys.exit(0 if ok else 1)

    if not args.db or not args.mirror:
        parser.error("--db and --mirror are required unless --selftest")

    run_probe(args.db, args.mirror, paths_cfg, args.out, args.report, limit=args.limit)


if __name__ == "__main__":
    main()
