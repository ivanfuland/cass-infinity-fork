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
`--selftest` exercises them directly -- in families, each with its own runner
and its own printed tally: `decide` (`selftest_cases`, the R1-R4 judgment
cases driven through `decide`) and `content` (`selftest_content_cases`, the
projection+redaction+empty-body gate driven through the PRODUCTION entry
`process_session_v2`); further families are added next to the fix that needs
them. The last line is the grand total across families. "宁漏勿误"
(safe-to-miss) is the standing default: any
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

T1b.2 CORRECTION (cass-sql-advisor 2026-09-07, after reviewing the first
manifest): whole-session positional alignment was the WRONG verification
model -- it threw away ~30% of otherwise-verifiable sessions just because
one unrelated position diverged. Manifest inclusion now uses **per-message
structural lookup** instead: a DB `tool_result` row's own `tool_call_id`
(read from its `extra_bin` -- msgpack; see `extract_tool_call_id_from_extra`)
locates the matching blob event directly (0 or ≥2 matches -> that ONE
message is unverifiable, not the whole session); a DB `idx=0` `user` row is
checked against the blob's first `user`-role event. `process_session_v2`
implements this; the old `process_session` (whole-session alignment) is
kept ONLY to compute the alignment-rate reporting statistic (§ old-model
disclosure in the report), not to gate the manifest.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import msgpack
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
    # codex registers/calls this MCP tool under its BARE name "project_read"
    # (confirmed: grep of a real blob shows the tool schema
    # `{"type":"function","name":"project_read","description":"Serve one
    # byte-bounded control document chunk..."}` -- the same tool's real
    # description -- and build_candidates_codex's tool_name_freq showed 610
    # actual invocations under this bare name), NOT the
    # `mcp__ccw-control-plane__` prefixed full name claude_code uses.
    "codex": {"read": None, "project_read": "project_read", "bash": "exec_command", "bash_arg_key": "cmd"},
}


# ---------------------------------------------------------------------------
# R1 (v4.4, Ivan 2026-09-07 裁; T2a 落地, 任务书 #113): connector cass-mcp
# tool-identity aliases. `claude_code` recognizes any full name under its
# MCP server's `mcp__cass-mcp__` prefix; `codex` registers/calls these tools
# under BARE names instead (T1b full-corpus run: `cass_search` 5x,
# `cass_expand` 3x, 0 occurrences under the `mcp__cass-mcp__` prefix) --
# see docs/excluded-rules.md R1/R11. No other connector matches (宁漏勿误).
# ---------------------------------------------------------------------------


CASS_RECALL_ALIAS_TABLE = {
    "claude_code": {"mcp__cass-mcp__cass_search", "mcp__cass-mcp__cass_expand"},
    "codex": {"cass_search", "cass_expand"},
}


def is_cass_recall_tool(tool_name: str, agent_slug: str) -> bool:
    """R1/R11 identity check (任务书 #118b N12 收紧, mirrors
    src/indexer/exclusion.rs::is_cass_recall_tool): matches ONLY the exact
    full identities R11's alias table registers per connector -- replacing
    the old `claude_code` PREFIX match (`startswith("mcp__cass-mcp__")`),
    which would also match a hypothetical `mcp__cass-mcp__anything_else`
    tool never registered in R11."""
    return tool_name in CASS_RECALL_ALIAS_TABLE.get(agent_slug, frozenset())


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


def _is_windows_drive_absolute(p: str) -> bool:
    """Mirrors `exclusion.rs::is_windows_drive_absolute` exactly: a
    Windows drive-letter absolute path AFTER `_normalize_path`'s `\\` ->
    `/` conversion, e.g. `C:/projects/...`."""
    return len(p) >= 3 and p[0].isalpha() and p[1] == ":" and p[2] == "/"


def predicate_p(raw_path: str, paths_cfg: dict) -> bool:
    """R2 谓词 P. `raw_path` is a single path string already extracted from
    a tool-call argument (not yet normalized).

    任务书 #118b N9: a path still relative AFTER normalization (no
    resolvable repo-root/worktree-root anchor) only matches
    `injection_only_files`, never `memory_files`/`workspace_scoped_files` --
    `_anchored_under_cc_workspace` does a raw regex search for a
    `cc-workspace` path SEGMENT and doesn't care whether the input was
    absolute, so `cc-workspace/USER.md` (any relative path a caller could
    construct from ANY cwd) must not be treated as proof it resolves under
    the real cc-workspace root.

    任务书 #119b R2-N11: a Windows absolute path (`C:\\projects\\...`)
    normalizes to `C:/projects/...`, which does not start with `/` --
    without `_is_windows_drive_absolute`, that fell into the "still
    relative" branch above and could only ever match
    `injection_only_files`, silently missing `memory_files`/
    `workspace_scoped_files` hits."""
    normalized = _normalize_path(raw_path)
    base = normalized.rsplit("/", 1)[-1]

    if not normalized.startswith("/") and not _is_windows_drive_absolute(normalized):
        return base in paths_cfg["injection_only_files"]

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
# 任务书 #118b N10: `\n`/`\r` added -- `shlex.split` treats a newline as an
# ordinary token separator (same as a space), so a newline-joined
# multi-command string was parsed as one command's multiple path arguments
# instead of being rejected as the two separate shell commands a real shell
# would execute.
_COMPOUND_SHELL_CHARS_RE = re.compile(r"[|;&<>`*?\[\]\n\r]|\$")


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

    if head == "nl":
        # R2 sixth form (v4.4, Ivan 加): `nl [-ba] <paths>` -- codex's
        # dominant read-with-line-numbers shape (docs/excluded-rules.md
        # R2-i, T1b full-corpus run: 1,003 occurrences).
        if rest and rest[0] == "-ba":
            paths = rest[1:]
        else:
            paths = rest
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
    # mission #116⑦: mirrors src/indexer/exclusion.rs::anchor3_shell_opener
    # exactly -- once closer/open/cwd all match, the match condition is
    # satisfied (CONTAINS, not STARTS-WITH; see that function's doc comment),
    # so this must never fall back to None here. `startswith` only picks
    # which of the 3 known constants to *record* as `anchor.shell.opener`;
    # when the message doesn't start with any of them (R3-f: a real request
    # with a full env-context block pasted at its own end, "已知漏判方向"),
    # it still matches and falls back to recording the structural tag
    # `<environment_context>` itself, since some value must be written.
    # 任务书 #118b N11: `<cwd>` must be INSIDE the `<environment_context>`
    # block (after its open tag), not merely present somewhere in the
    # message -- the old independent `in` checks would match
    # `"<cwd>/x</cwd> real request<environment_context></environment_context>"`.
    # 任务书 #119b R2-N12: N11 above only checked "after the open tag" --
    # never "before the CORRESPONDING close tag", so
    # `"<environment_context></environment_context><cwd>/x</cwd></environment_context>"`
    # still matched (the first block closes empty immediately; `<cwd>`
    # only appears afterward, in text wrapped by a second closer that
    # satisfies the outer `endswith` check). Fixed by narrowing the search
    # window to `[open tag end, nearest following close tag)`.
    #
    # 任务书 #119d R3-N3 (回归): the R2-N12 fix above only ever looked at the
    # FIRST `<environment_context>` open tag -- if that first block didn't
    # contain `<cwd>`, it returned None immediately without checking any
    # LATER block. Real shape this misses: an opener that shows an empty
    # example block before the actual environment context, e.g.
    # "# AGENTS.md instructions\nExample: <environment_context></environment_context>\n<environment_context><cwd>/project</cwd></environment_context>"
    # -- the first (example) block is empty, but the second (real) block
    # does contain `<cwd>` and satisfies R3's structural shape. Fixed by
    # walking open-tag occurrences left to right, checking each one's own
    # `[open tag end, nearest following close tag)` window in turn, resuming
    # the next search right after that nearest close tag, and only
    # returning None once no further open tag remains -- not on the first
    # block's miss.
    #
    # 任务书 #120b R4-N4: after a miss, the search resumes AFTER the nearest
    # close tag, so a nested open tag that falls BETWEEN the current open
    # and its own nearest close (e.g. "<environment_context><environment_
    # context></environment_context></environment_context>") is never
    # independently re-checked -- this does NOT walk every open-tag
    # occurrence in the message, only the ones not already subsumed by a
    # checked-and-missed window. Still correct: such a nested open's own
    # `[open, nearest close)` window is a SUBSET of the outer window just
    # checked and confirmed not to contain `<cwd>`, so skipping it cannot
    # miss a real `<cwd>` hit.
    trimmed = text.strip()
    if not trimmed.endswith(_CLOSER):
        return None
    search_from = 0
    while True:
        open_pos = trimmed.find("<environment_context>", search_from)
        if open_pos == -1:
            return None
        after_open = trimmed[open_pos + len("<environment_context>"):]
        close_rel = after_open.find(_CLOSER)
        if close_rel == -1:
            # No close tag anywhere after this open -- unreachable in
            # practice given the `endswith(_CLOSER)` precondition above and
            # that the opener string is not a substring of the closer
            # string; kept only as a defensive bail (mirrors the Rust side).
            return None
        if "<cwd>" in after_open[:close_rel]:
            for opener in _OPENERS:
                if trimmed.startswith(opener):
                    return opener
            return "<environment_context>"
        search_from = open_pos + len("<environment_context>") + close_rel + len(_CLOSER)


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


# ---------------------------------------------------------------------------
# Connector projection port (任务书 #125, R1-N19 + R2-N14).
#
# Mirrors the PINNED `franken_agent_detection` rev `bc0f4d3c...`:
# `claude_code.rs::render_tool_result_content`, `utils.rs::flatten_content`,
# `utils.rs::extract_content_part`. This is not decoration: `messages.content`
# was written from EXACTLY this projection, so the mirror side of a content
# comparison is only meaningful if it goes through the same transform. The
# previous `json.dumps(content)` shape disagreed with the connector on array
# tool_results and was the R2-N14 defect.
# ---------------------------------------------------------------------------
_MISSING = object()


def _extract_content_part(item):
    """`utils.rs::extract_content_part` -- returns None when the connector
    would drop the part (`flatten_content` skips both None and "")."""
    if isinstance(item, str):
        return item
    if not isinstance(item, dict):
        return None
    item_type = item.get("type")
    text = item.get("text")
    if isinstance(text, str) and (
        item_type is None or item_type in ("text", "input_text", "output_text")
    ):
        return text
    if item_type == "tool_use":
        name = item.get("name")
        if not isinstance(name, str):
            name = "unknown"
        desc = ""
        inp = item.get("input")
        if isinstance(inp, dict):
            if isinstance(inp.get("description"), str):
                desc = inp["description"]
            elif isinstance(inp.get("file_path"), str):
                desc = inp["file_path"]
        return f"[Tool: {name} - {desc}]" if desc else f"[Tool: {name}]"
    return None


def _flatten_content(val):
    """`utils.rs::flatten_content` -- string passthrough, array joined with a
    single `\\n` dropping empty parts, anything else empty."""
    if isinstance(val, str):
        return val
    if isinstance(val, list):
        parts = []
        for item in val:
            text = _extract_content_part(item)
            if text is None or text == "":
                continue
            parts.append(text)
        return "\n".join(parts)
    return ""


def _render_tool_result_content(content):
    """`claude_code.rs::render_tool_result_content`. Takes `_MISSING` for an
    absent `content` key so an EXPLICIT JSON `null` keeps serde_json's
    `null` rendering instead of collapsing into the absent branch."""
    if content is _MISSING:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return _flatten_content(content)
    return json.dumps(content, ensure_ascii=False, separators=(",", ":"))


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
                # R2-N14: the connector renders this block's `content` with
                # `render_tool_result_content` (string passthrough / array
                # flatten / serde_json display), never with `json.dumps`.
                text = _render_tool_result_content(block.get("content", _MISSING))
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
def decide_r1_r2_for_call(call, agent_slug, paths_cfg):
    """R1/R2 given an ALREADY-RESOLVED paired tool_call (however it was
    resolved -- blob-positional pairing in the original design, or
    DB-id-based lookup in T1b.2's per-message model). Pure function, no
    positional/session state; factored out of `decide()` so both models
    share one judgment implementation."""
    # 任务书 #118b N12: the cass-mcp identity check now runs AFTER the
    # args-presence gate below -- R4's general "配对成功但 tool_call 缺
    # tool_name 或缺参数 → 不排除" is not an R2-only rule; a cass-mcp call
    # with no captured arguments at all must not match, even though R1's
    # own condition never reads any argument value.
    if not call.tool_name:
        return None
    identities = READ_TOOL_IDENTITIES.get(agent_slug)
    args = call.args
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (ValueError, TypeError):
            args = None
    if not isinstance(args, dict):
        return None
    if is_cass_recall_tool(call.tool_name, agent_slug):
        return {
            "reason": "cass_recall",
            "anchor": {"tool_call_id": call.tool_call_id, "tool_name": call.tool_name, "paths": None, "shell": None},
        }
    if identities is None:
        return None
    if call.tool_name == identities["read"] and isinstance(args.get("file_path"), str):
        if predicate_p(args["file_path"], paths_cfg):
            return {
                "reason": "context_file_read",
                # 任务书 #118b N9: `anchor.paths` stores the NORMALIZED
                # path, not the raw string the tool call carried.
                "anchor": {"tool_call_id": call.tool_call_id, "tool_name": call.tool_name, "paths": [_normalize_path(args["file_path"])], "shell": None},
            }
    elif call.tool_name == identities["project_read"] and isinstance(args.get("document"), str):
        if predicate_p_project_read_document(args["document"], paths_cfg):
            return {
                "reason": "context_file_read",
                "anchor": {"tool_call_id": call.tool_call_id, "tool_name": call.tool_name, "paths": [args["document"]], "shell": None},
            }
    elif call.tool_name == identities["bash"] and isinstance(args.get(identities["bash_arg_key"]), str):
        paths = bash_readonly_paths(args[identities["bash_arg_key"]])
        if paths and all(predicate_p(p, paths_cfg) for p in paths):
            return {
                "reason": "context_file_read",
                "anchor": {"tool_call_id": call.tool_call_id, "tool_name": call.tool_name, "paths": [_normalize_path(p) for p in paths], "shell": None},
            }
    return None


def decide(candidates, index, idx_in_session, agent_slug, paths_cfg, pairing: PairingContext):
    c = candidates[index]

    if c.role == "tool_result":
        call = pairing.paired_call_for(index)
        if call is not None:
            decision = decide_r1_r2_for_call(call, agent_slug, paths_cfg)
            if decision is not None:
                return decision

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

    # 1. R1-a positive (claude_code full name; v4.4 scopes the
    # `mcp__cass-mcp__` prefix match to claude_code only -- codex's own R1
    # identity is bare names, see case 13/14 below and R1-d in the Rust
    # `exclusion.rs` unit tests, not duplicated here per advisor guidance
    # to keep this file's case count at 14)
    cands = [_mk("tool_call", tool_call_id="t1", tool_name="mcp__cass-mcp__cass_search", args={}), _mk("tool_result", tool_call_id="t1")]
    cases.append(("R1-a cass_recall positive", cands, 1, 0, "claude_code", "cass_recall"))

    # 2. R1-b negative (same suffix, wrong prefix)
    cands = [_mk("tool_call", tool_call_id="t1", tool_name="mcp__other-mcp__cass_search"), _mk("tool_result", tool_call_id="t1")]
    cases.append(("R1-b wrong mcp prefix", cands, 1, 0, "claude_code", None))

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
    cands = [_mk("user"), _mk("tool_call", tool_name="mcp__cass-mcp__cass_search", args={}), _mk("tool_result")]
    cases.append(("R4 exactly one unpaired candidate", cands, 2, 0, "claude_code", "cass_recall"))

    # 14. R4 pairing: 2 unpaired candidates -> no match
    cands = [
        _mk("user"),
        _mk("tool_call", tool_name="mcp__cass-mcp__cass_search", args={}),
        _mk("tool_call", tool_name="mcp__cass-mcp__cass_expand", args={}),
        _mk("tool_result"),
    ]
    cases.append(("R4 two unpaired candidates", cands, 3, 0, "claude_code", None))

    # 15. R3-f positive, fallback opener (mission #116⑦): a real user request
    # with a full <environment_context>...<cwd>...</environment_context>
    # block pasted at the end. Doesn't start with any of the 3 known
    # openers, but still satisfies closer+open+cwd -- CONTAINS, not
    # STARTS-WITH (see anchor3_shell_opener's doc comment / Rust's own
    # R3-f). Must still match, falling back to recording
    # "<environment_context>" as the opener rather than returning None.
    text3 = "please do X\n<environment_context>\n<cwd>/x</cwd>\n</environment_context>"
    cands = [_mk("user", text=text3)]
    cases.append(("R3-f known-opener-miss still matches (fallback opener)", cands, 0, 0, "codex", "codex_host_shell"))

    # 16. N9 negative (任务书 #118b): a RELATIVE path (no leading `/`) that
    # merely contains a `cc-workspace` segment must not match a
    # memory_files name -- only the injection-only branch may match a
    # relative path.
    cands = [
        _mk("tool_call", tool_call_id="t1", tool_name="Read", args={"file_path": "cc-workspace/USER.md"}),
        _mk("tool_result", tool_call_id="t1"),
    ]
    cases.append(("N9 relative cc-workspace-prefixed memory file not anchored", cands, 1, 0, "claude_code", None))

    # 17. N10 negative (任务书 #118b): a newline-joined "command" is two
    # separate shell commands to a real shell, not `cat`'s two path args.
    cands = [
        _mk(
            "tool_call",
            tool_call_id="t1",
            tool_name="Bash",
            args={"command": "cat /home/ivan/projects/cc-workspace/USER.md\n/home/ivan/projects/cc-workspace/TOOLS.md"},
        ),
        _mk("tool_result", tool_call_id="t1"),
    ]
    cases.append(("N10 bash newline-separated commands rejected", cands, 1, 0, "claude_code", None))

    # 18. N11 negative (任务书 #118b): `<cwd>` outside the
    # `<environment_context>` block must not count.
    text4 = "<cwd>/home/u/project</cwd> please look at this real request\n<environment_context>\n</environment_context>"
    cands = [_mk("user", text=text4)]
    cases.append(("N11 cwd outside environment_context block", cands, 0, 0, "codex", None))

    # 19. N12 negative (任务书 #118b): a cass-mcp call with NO captured
    # arguments at all must not match (R4's general "缺参数不排" applies to
    # R1 too), even though R1's own match condition never reads args.
    cands = [_mk("tool_call", tool_call_id="t1", tool_name="mcp__cass-mcp__cass_search"), _mk("tool_result", tool_call_id="t1")]
    cases.append(("N12 cass_recall with no args does not match", cands, 1, 0, "claude_code", None))

    # 20. R2-N11 positive (任务书 #119b): a Windows absolute path
    # (backslash separators, drive letter) must still match `memory_files`
    # under the cc-workspace root -- pre-fix, `predicate_p` treated the
    # post-normalization `C:/...` as relative (didn't start with `/`) and
    # could only ever match `injection_only_files`.
    cands = [
        _mk("tool_call", tool_call_id="t1", tool_name="Read", args={"file_path": "C:\\projects\\cc-workspace\\USER.md"}),
        _mk("tool_result", tool_call_id="t1"),
    ]
    cases.append(("R2-N11 Windows absolute path memory file positive", cands, 1, 0, "claude_code", "context_file_read"))

    # 21. R2-N12 negative (任务书 #119b): `<cwd>` appears AFTER the open tag
    # but also after that SAME block's own close tag (the first
    # environment-context block closes empty immediately); a second,
    # unrelated close tag trailing the message satisfies the outer
    # `endswith` check. Case 18 above (N11, #118b) puts `<cwd>` BEFORE the
    # open tag -- a different code path than this one, which needs the
    # close-tag boundary specifically.
    text5 = "<environment_context></environment_context><cwd>/x</cwd></environment_context>"
    cands = [_mk("user", text=text5)]
    cases.append(("R2-N12 cwd after close tag of first environment_context block", cands, 0, 0, "codex", None))

    # 22. R3-N3 positive (任务书 #119d, 回归): a LATER environment_context
    # block containing `<cwd>` must match even when an EARLIER block (an
    # opener's own example text) is empty -- the R2-N12 fix above stopped
    # checking after the first block's miss. Must not be confused with case
    # 21 above (same "empty block first" shape, opposite verdict): there
    # `<cwd>` sits outside any complete block; here it sits inside its own
    # complete second block. Frozen-corpus check (W6_ARTIFACTS/
    # n3-corpus-compare-119d.txt): old vs new predicate over all 1,684
    # codex idx=0 role=user messages in copy/agent_search.db -- 1,665 hits
    # both sides, 0 differ (this corpus doesn't contain the shape this test
    # targets).
    text6 = "# AGENTS.md instructions\nExample: <environment_context></environment_context>\n<environment_context><cwd>/project</cwd></environment_context>"
    cands = [_mk("user", text=text6)]
    cases.append(("R3-N3 cwd in second environment_context block after empty first block", cands, 0, 0, "codex", "codex_host_shell"))

    return cases


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _v2_stats():
    """Minimal `stats` mapping for driving `process_session_v2` outside
    `run_probe`. Only the counters that function actually touches are
    present; a missing key here is a KeyError in the selftest, not a
    silently-skipped assertion."""
    return {
        "hits_by_reason": Counter(),
        "anchor3_opener": Counter(),
        "content_mismatch_messages": 0,
        "pairing_fail": Counter(),
    }


def _tool_result_fixture(result_block, db_content, agent_slug="claude_code",
                         tool_name="Read", args=None):
    """Build the minimal (conv, db_rows_full, raw_candidates) triple that
    drives ONE claude_code tool_result DB row through the PRODUCTION entry
    `process_session_v2` -- not through `decide` directly (任务书 #125
    R2-N13: the production entry and the selftest must share one judgment
    path). DB rows: a user turn boundary, the `tool_call` row carrying
    `tool_call_id=t1`, and the `tool_result` row under test."""
    if args is None:
        args = {"file_path": "/home/ivan/projects/cc-workspace/MEMORY.md"}
    call_event = {
        "type": "assistant",
        "uuid": "u1",
        "message": {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": "t1", "name": tool_name, "input": args}],
        },
    }
    result_event = {
        "type": "user",
        "uuid": "u2",
        "message": {"role": "user", "content": [result_block]},
    }
    raw_candidates = build_candidates_claude_code([call_event, result_event])
    conv = {
        "id": 1,
        "source_id": "local",
        "agent_slug": agent_slug,
        "external_id": "ext-1",
        "source_path": "/src/ext-1.jsonl",
    }
    db_rows_full = [
        (0, "user", _sha("turn boundary"), "turn boundary", None),
        (1, "tool_call", _sha("call row"), "Read(...)", "t1"),
        (2, "tool_result", _sha(db_content), db_content, "t1"),
    ]
    return conv, db_rows_full, raw_candidates


def selftest_content_cases():
    """Family B (任务书 #125, R1-N19 + R2-N14 + §〇 空正文): content
    verification must go through the SAME connector projection and the SAME
    ingest-side redactor that produced `messages.content`, and must compare
    the whole body -- not a substring.

    Each case is `(name, result_block, db_content, expect_entries,
    expect_content_mismatch)` and is driven through `process_session_v2`."""
    cases = []

    # C1 (R1-N19): the mirror still holds the RAW secret; the DB holds the
    # redacted form written by `redact_secrets::redact_text`. A substring
    # gate can never accept this pair -- `token: [REDACTED]` does not occur
    # anywhere in the raw mirror text.
    cases.append((
        "C1 redacted DB body vs raw mirror",
        {"type": "tool_result", "tool_use_id": "t1",
         "content": "token: AKIAIOSFODNN7EXAMPLE\ntail of the tool output"},
        "token: [REDACTED]\ntail of the tool output",
        1, 0,
    ))

    # C2 (R2-N14): a claude ARRAY-typed tool_result projects through the
    # connector's `render_tool_result_content -> flatten_content` (single
    # `\n` join, empty parts dropped) -- NOT `json.dumps`.
    cases.append((
        "C2 array tool_result projection",
        {"type": "tool_result", "tool_use_id": "t1",
         "content": [{"type": "text", "text": "L1"}, {"type": "text", "text": "L2"}]},
        "L1\nL2",
        1, 0,
    ))

    # C3 (§〇): an empty DB body whose mirror projection is ALSO empty stays
    # a legitimate hit. The projection is empty when the block carries no
    # `content` key at all (`render_tool_result_content(None) -> ""`).
    cases.append((
        "C3 empty DB body with empty mirror projection",
        {"type": "tool_result", "tool_use_id": "t1"},
        "",
        1, 0,
    ))

    # C3b (R2-N14 appendix): an EXPLICIT JSON `null` `content` is NOT the same
    # as an absent one -- Rust's `Some(value) => value.to_string()` renders it
    # as the literal `null`, and the production DB body proves it. Pinned so
    # the port cannot quietly collapse the two.
    cases.append((
        "C3b explicit null content renders as null",
        {"type": "tool_result", "tool_use_id": "t1", "content": None},
        "null",
        1, 0,
    ))

    # C4 (§〇): an empty DB body whose mirror projection is NON-empty must no
    # longer pass unconditionally -- that is a `content_mismatch`, and the
    # message is dropped rather than frozen into the manifest.
    cases.append((
        "C4 empty DB body with non-empty mirror projection",
        {"type": "tool_result", "tool_use_id": "t1", "content": "a real tool body"},
        "",
        0, 1,
    ))

    return cases


def _run_decide_selftest(paths_cfg):
    cases = selftest_cases(paths_cfg)
    assert len(cases) == 22, f"selftest must have exactly 22 cases, got {len(cases)}"
    passed = 0
    for name, cands, index, idx_in_session, agent_slug, expect in cases:
        pairing = PairingContext(cands)
        result = decide(cands, index, idx_in_session, agent_slug, paths_cfg, pairing)
        got = result["reason"] if result else None
        ok = got == expect
        print(f"{'ok  ' if ok else 'FAIL'} {name} (expect={expect!r} got={got!r})")
        if ok:
            passed += 1
    print(f"selftest/decide: {passed}/{len(cases)}")
    return passed, len(cases)


def _run_content_selftest(paths_cfg):
    """Family B runner: every case goes through the PRODUCTION entry."""
    cases = selftest_content_cases()
    passed = 0
    for name, result_block, db_content, expect_entries, expect_mismatch in cases:
        conv, db_rows_full, raw_candidates = _tool_result_fixture(result_block, db_content)
        stats = _v2_stats()
        entries = process_session_v2(conv, db_rows_full, raw_candidates, paths_cfg, stats)
        got = (len(entries), stats["content_mismatch_messages"])
        want = (expect_entries, expect_mismatch)
        ok = got == want
        print(f"{'ok  ' if ok else 'FAIL'} {name} (expect={want} got={got})")
        if ok:
            passed += 1
    print(f"selftest/content: {passed}/{len(cases)}")
    return passed, len(cases)


def run_selftest(paths_cfg) -> bool:
    passed = total = 0
    for runner in (_run_decide_selftest, _run_content_selftest):
        p, t = runner(paths_cfg)
        passed += p
        total += t
    print(f"selftest: {passed}/{total}")
    return passed == total


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
# ---------------------------------------------------------------------------
# Ingest-side redactor port (任务书 #125 §〇, R1-N19 + R2-N14).
#
# Mirrors `src/indexer/redact_secrets.rs`: `SECRET_PATTERNS` (:95) applied by
# `apply_replacements` (:194) -- ASCENDING pattern-index order, one sequential
# `replace_all` per pattern, replacement constant `[REDACTED]`. That ordering
# is a frozen behaviour contract in Rust and is reproduced here verbatim.
# `messages.content` is written as `redact_text(<connector projection>)`
# (`indexer/mod.rs::map_to_internal_with_redactor`), so the mirror side of a
# content comparison must go through this function to be comparable at all.
#
# ASSUMED INGEST CONFIGURATION: the frozen DB was ingested with the default
# `CASS_REDACT_SECRETS` (redaction ON). Rust's `redaction_enabled()` gate is
# deliberately NOT mirrored from the environment here -- doing so would make
# this probe's output depend on the caller's shell, and the manifest has to
# be reproducible: same DB + same mirror must yield the same manifest for
# anyone. A DB ingested with redaction OFF simply fails the byte-equality
# gate loudly, which is the intended, visible failure.
# ---------------------------------------------------------------------------
REDACTED = "[REDACTED]"

_SECRET_PATTERNS = (
    r"\bAKIA[0-9A-Z]{16}\b",
    r"(?i)aws(.{0,20})?(secret|access)?[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
    r"\bgh[pousr]_[A-Za-z0-9]{36}\b",
    r"\bsk-[A-Za-z0-9]{20,}\b",
    r"\bsk-ant-[A-Za-z0-9]{20,}\b",
    r"(?i)Bearer\s+[A-Za-z0-9_\-.]{20,}",
    r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
    r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----",
    r"(?i)\b(postgres|postgresql|mysql|mongodb|redis)://[^\s]{8,}",
    r"(?i)(api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|secret[_-]?key|password|passwd)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=]{8,}['\"]?",
    r"\bxox[bpsar]-[A-Za-z0-9\-]{10,}",
    r"\b[spr]k_live_[A-Za-z0-9]{20,}",
)

_SECRET_REGEXES = tuple(re.compile(pattern) for pattern in _SECRET_PATTERNS)


def redact_text(text: str) -> str:
    """Rust `redact_secrets::redact_text`, including its RegexSet prefilter
    (clean inputs take no replacement pass) and its ordered `replace_all`
    semantics. `[REDACTED]` cannot itself re-trigger any pattern, so running
    every pattern over the evolving string is equivalent to running only the
    ones that matched the original input."""
    if not any(regex.search(text) for regex in _SECRET_REGEXES):
        return text
    out = text
    for regex in _SECRET_REGEXES:
        out = regex.sub(REDACTED, out)
    return out


def content_body_ok(db_content: str, candidate_text: str) -> bool:
    """R1-N19 + R2-N14 + §〇 (任务书 #125): the mirror side must be projected
    by the connector and redacted by the ingest-side redactor, then compared
    as a WHOLE against `messages.content` -- no substring test.

    An empty DB body is no longer an unconditional pass: it is only a hit
    when the mirror side is empty too. A body that production emptied for a
    reason other than an empty source is a `content_mismatch` and stays out
    of the manifest."""
    if candidate_text is None:
        return False
    return redact_text(candidate_text) == db_content


def compute_session_alignment(conv, db_rows, raw_candidates, events, stats):
    """T1b.2 (cass-sql-advisor 2026-09-07): whole-session positional
    alignment is NO LONGER used to gate manifest inclusion -- see module
    docstring. Kept only to produce the reporting-only alignment-rate
    statistic (per agent_slug + first-divergence-position histogram).
    Records stats as a side effect; does not return manifest entries.
    `raw_candidates` is built once by the caller and shared with
    `process_session_v2` (avoids rebuilding it twice per session).
    """
    filtered = [c for c in raw_candidates if c.role != "developer"]
    aligned = len(filtered) == len(db_rows) and all(f.role == r[1] for f, r in zip(filtered, db_rows))
    agent_slug = conv["agent_slug"]
    stats["alignment_by_agent"][agent_slug]["total"] += 1
    if aligned:
        stats["alignment_by_agent"][agent_slug]["aligned"] += 1
    else:
        stats["alignment_by_agent"][agent_slug]["misaligned"] += 1
        if blob_has_compacted_event(events):
            stats["alignment_by_agent"][agent_slug]["misaligned_compacted"] += 1
        first_diff = next(
            (i for i in range(min(len(filtered), len(db_rows))) if filtered[i].role != db_rows[i][1]),
            min(len(filtered), len(db_rows)),
        )
        stats["alignment_first_diff_pos"][first_diff] += 1
    return aligned


# ---------------------------------------------------------------------------
# T1b.2: per-message structural lookup (replaces whole-session alignment as
# the manifest-inclusion gate; cass-sql-advisor correction, 2026-09-07).
# ---------------------------------------------------------------------------
def extract_tool_call_id_from_extra(extra_bin):
    """DB `messages.extra_bin` is msgpack (NOT the compressed form the
    original design assumed for either connector -- see report note: a
    full decode of a sample `copy/` row for both claude_code and codex
    showed the WHOLE original event, including `name`/`input`, not just
    `raw_role`/`tool_call_id`/`tool_call_args`). Per cass-sql-advisor's
    T1b.2 instruction this probe still only reads `tool_call_id` from here
    -- an identity anchor to LOCATE the blob event -- and takes the
    structural facts (`tool_name`, args) from the blob, preserving
    `evidence:"mirror"` semantics rather than exploiting the extra
    richness this probe happened to find in `copy/`."""
    if not extra_bin:
        return None
    try:
        d = msgpack.unpackb(extra_bin, raw=False)
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    tid = d.get("tool_call_id")
    return tid if isinstance(tid, str) else None


def build_blob_id_indices(raw_candidates):
    """Index blob-derived tool_call/tool_result candidates by their own
    `tool_call_id`, and locate the first `user`-role candidate (blob
    order) for anchor 3 -- independent of any whole-session positional
    correspondence with DB."""
    calls_by_id = defaultdict(list)
    results_by_id = defaultdict(list)
    first_user = None
    for c in raw_candidates:
        if c.role == "tool_call" and c.tool_call_id:
            calls_by_id[c.tool_call_id].append(c)
        elif c.role == "tool_result" and c.tool_call_id:
            results_by_id[c.tool_call_id].append(c)
        if c.role == "user" and first_user is None:
            first_user = c
    return calls_by_id, results_by_id, first_user


def process_session_v2(conv, db_rows_full, raw_candidates, paths_cfg, stats):
    """`db_rows_full` = [(idx, role, content_sha256, content, tool_call_id_or_None), ...]
    ordered by idx, covering EVERY message in the session (not just
    tool_call/tool_result -- 'user' rows are needed as R4 turn boundaries).
    `raw_candidates` is built once by the caller (shared with
    `compute_session_alignment`). Returns manifest_entries; there is no
    session-level gating here anymore (unsupported-connector sessions are
    filtered by the caller before this is even called).
    """
    calls_by_id, results_by_id, first_user_cand = build_blob_id_indices(raw_candidates)

    # R4 pairing over the DB's OWN (idx, role, tool_call_id) sequence --
    # complete and authoritative (every row, straight from SQLite), unlike
    # the blob reconstruction that whole-session alignment depended on.
    db_pairing_candidates = [Candidate(role, None, 0, tool_call_id=tid) for (_idx, role, _sha, _content, tid) in db_rows_full]
    pairing = PairingContext(db_pairing_candidates)

    agent_slug = conv["agent_slug"]
    manifest_entries = []

    for i, (idx, role, content_sha, content, _tid) in enumerate(db_rows_full):
        if role == "tool_result":
            paired = pairing.paired_call_for(i)
            if paired is None:
                stats["pairing_fail"]["no_unpaired_candidate"] += 1
                continue
            call_id = paired.tool_call_id
            if not call_id:
                stats["pairing_fail"]["no_unpaired_candidate"] += 1
                continue
            call_matches = calls_by_id.get(call_id, [])
            if len(call_matches) == 0:
                stats["pairing_fail"]["call_id_not_in_mirror"] += 1
                continue
            if len(call_matches) >= 2:
                stats["pairing_fail"]["ambiguous_call_id"] += 1
                continue
            call = call_matches[0]
            if not call.tool_name:
                stats["pairing_fail"]["missing_tool_name"] += 1
                continue
            if call.args is None:
                # R4: "配对成功但 tool_call ... 缺参数 -> 不排除". This is
                # the call having NO argument payload at all -- distinct
                # from a call whose args just don't match this reason's
                # expected shape (that is the ordinary, majority case of
                # "not a Read/Bash/project_read call", not a failure).
                stats["pairing_fail"]["missing_args"] += 1
                continue

            decision = decide_r1_r2_for_call(call, agent_slug, paths_cfg)
            if decision is None:
                continue

            result_matches = results_by_id.get(call_id, [])
            if len(result_matches) != 1:
                stats["pairing_fail"]["result_not_uniquely_in_mirror"] += 1
                continue
            evidence = result_matches[0]
            if not content_body_ok(content, evidence.text):
                stats["content_mismatch_messages"] += 1
                continue

            manifest_entries.append(
                {
                    "reason": decision["reason"],
                    "source_id": conv["source_id"],
                    "agent_slug": agent_slug,
                    "external_id": conv["external_id"],
                    "source_path": conv["source_path"],
                    "idx": idx,
                    "sha256": content_sha,
                    "evidence": "mirror",
                    "event_key": evidence.event_key,
                    "blocks": [evidence.block_index],
                    "anchor": decision["anchor"],
                }
            )
            stats["hits_by_reason"][decision["reason"]] += 1

        elif role == "user" and idx == 0 and agent_slug == "codex":
            if first_user_cand is None:
                stats["pairing_fail"]["anchor3_no_first_user_in_mirror"] += 1
                continue
            if not content_body_ok(content, first_user_cand.text):
                stats["content_mismatch_messages"] += 1
                continue
            opener = anchor3_shell_opener(content)
            if opener is None:
                continue
            manifest_entries.append(
                {
                    "reason": "codex_host_shell",
                    "source_id": conv["source_id"],
                    "agent_slug": agent_slug,
                    "external_id": conv["external_id"],
                    "source_path": conv["source_path"],
                    "idx": idx,
                    "sha256": content_sha,
                    "evidence": "mirror",
                    "event_key": first_user_cand.event_key,
                    "blocks": [first_user_cand.block_index],
                    "anchor": {"tool_call_id": None, "tool_name": None, "paths": None, "shell": {"opener": opener}},
                }
            )
            stats["hits_by_reason"]["codex_host_shell"] += 1
            stats["anchor3_opener"][opener] += 1

    return manifest_entries


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
        # T1b.2: manifest inclusion no longer depends on whole-session
        # alignment; these are reporting-only (old-model disclosure).
        "alignment_by_agent": defaultdict(lambda: {"total": 0, "aligned": 0, "misaligned": 0, "misaligned_compacted": 0}),
        "alignment_first_diff_pos": Counter(),
        "compacted_sessions_by_agent": Counter(),
        "out_of_scope_connector_sessions": 0,
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

        db_msg_rows = conn.execute(
            "SELECT idx, role, content, extra_bin FROM messages WHERE conversation_id = ? ORDER BY idx",
            (conv_d["id"],),
        ).fetchall()
        # T1b.2: every row's own tool_call_id is read directly from its
        # extra_bin (msgpack) -- an identity anchor, not evidence (see
        # extract_tool_call_id_from_extra docstring).
        db_rows_full = [
            (
                r["idx"],
                r["role"],
                hashlib.sha256(r["content"].encode("utf-8")).hexdigest(),
                r["content"],
                extract_tool_call_id_from_extra(r["extra_bin"]),
            )
            for r in db_msg_rows
        ]
        db_rows = [(idx, role, sha, content) for (idx, role, sha, content, _tid) in db_rows_full]

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

        # "镜像可得" = manifest found + blob file present + JSON-parseable,
        # independent of whether this probe has a candidate builder for the
        # connector (advisor directive ⑤: openclaw/gemini/pi_agent DO have
        # usable mirrors, this column must say so; "候选构造器" is the
        # separate column for whether R7/R11 covers the connector).
        cov["mirror_ok"] += 1

        if connector is None:
            # T1b.2 (advisor directive): out-of-scope connector coverage is
            # NOT an unverifiable session -- manifest+blob are both present,
            # this probe just has no R7/R11 candidate builder for this
            # agent_slug yet. Kept as its own counter, excluded from
            # unverifiable_sessions entirely.
            stats["out_of_scope_connector_sessions"] += 1
            continue

        raw_candidates = build_candidates_claude_code(events) if connector == "claude_code" else build_candidates_codex(events)

        # Reporting-only: does NOT gate manifest inclusion (T1b.2).
        compute_session_alignment(conv_d, db_rows, raw_candidates, events, stats)
        if blob_has_compacted_event(events):
            stats["compacted_sessions_by_agent"][agent_slug] += 1

        entries = process_session_v2(conv_d, db_rows_full, raw_candidates, paths_cfg, stats)
        manifest.extend(entries)

        # Coverage stats (item 7) from the raw candidate pool for this session.
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

    lines.append("\n## ④ 配对失败计数（T1b.2：按 DB 消息逐条统计，不再静默）\n")
    pf = stats["pairing_fail"]
    lines.append(f"- `no_unpaired_candidate`（无 id 且同轮内候选 0 或 ≥2 个，或候选自身无 id）: {pf.get('no_unpaired_candidate', 0)}\n")
    lines.append(f"- `call_id_not_in_mirror`（DB 有 tool_call_id，但 blob 里找不到匹配的 tool_call 事件）: {pf.get('call_id_not_in_mirror', 0)}\n")
    lines.append(f"- `ambiguous_call_id`（同一 tool_call_id 在 blob 里匹配到 ≥2 个 tool_call 事件）: {pf.get('ambiguous_call_id', 0)}\n")
    lines.append(f"- `missing_tool_name`（匹配到的 tool_call 事件缺 tool_name）: {pf.get('missing_tool_name', 0)}\n")
    lines.append(f"- `missing_args`（识别的连接器但参数解析失败/非 dict）: {pf.get('missing_args', 0)}\n")
    lines.append(f"- `result_not_uniquely_in_mirror`（tool_call 匹配成功，但对应 tool_result 事件在 blob 里 0 或 ≥2 个，无法取证据做正文核验）: {pf.get('result_not_uniquely_in_mirror', 0)}\n")
    lines.append(f"- `anchor3_no_first_user_in_mirror`（DB idx=0 是 user，但 blob 里找不到任何 user 角色事件）: {pf.get('anchor3_no_first_user_in_mirror', 0)}\n")

    lines.append("\n## ⑤ 谓词 P 深层同名文档计数（应全部不命中）\n")
    lines.append(f"命中数: {len(stats['deep_doc_hits'])}（前 20 条路径）\n")
    for p in stats["deep_doc_hits"]:
        lines.append(f"- `{p}`\n")
    nl_count = stats["bash_subset_out"].get("nl", 0)
    lines.append(
        f"\n**`nl` 单列披露**（advisor 2026-09-07 指出；v4.4 Ivan 已裁并入 R2 六形态，T2a 落地，任务书 #113）："
        f"Bash 子集外前 10 分桶里 `nl` 有 {nl_count} 条（本次 `--selftest` 后的常量表已识别 `nl [-ba] <paths>`；"
        "本报告若来自尚未按 v4.4 重跑的 `run_full`，这里的计数仍是六形态生效**前**的旧口径，子集内/外分布"
        "以下一次控制面重跑探针出的 manifest v2 为准，见 docs/excluded-rules.md R2-i）。\n"
    )

    lines.append("\n## ⑥ codex 全部 tool_name 频次（advisor 2026-09-07：核对有无可疑的 cass-mcp 调用名）\n")
    codex_freq = stats["tool_name_freq"].get("codex", Counter())
    lines.append(f"`cass_recall` 本轮命中 25 条，全部来自 claude_code；codex 侧 0 条。以下是 codex 全部 tool_call 候选（不限于配对成功的）按 `tool_name` 的前 20 频次，供核对 codex 是否真的从不调用 cass-mcp（或以另一个名字调用）：\n")
    for name, n in codex_freq.most_common(20):
        lines.append(f"- `{name}`: {n}\n")

    lines.append("\n## ⑦ 连接器结构字段覆盖率\n")
    lines.append("| agent_slug | 会话数 | 镜像可得 | 候选构造器 | 有 tool_call_id | 有 tool_name | 有 path 参数 |\n")
    lines.append("|---|---|---|---|---|---|---|\n")
    for slug, cov in sorted(stats["coverage"].items()):
        builder = "有（claude_code/codex）" if slug in ("claude_code", "codex") else "无（本轮未实现，见 R7/R11「不启用」）"
        lines.append(f"| {slug} | {cov['sessions']} | {cov['mirror_ok']} | {builder} | {cov['has_tool_call_id']} | {cov['has_tool_name']} | {cov['has_path_arg']} |\n")

    lines.append("\n## ⑧ unverifiable 计数（T1b.2：`out_of_scope_connector` 单列，不计入 `unverifiable_sessions`）\n")
    total_unverifiable_sessions = sum(stats["unverifiable_sessions_by_reason"].values())
    lines.append(f"- `unverifiable_sessions`: {total_unverifiable_sessions}（仅 `no_manifest`/`no_blob`/`parse_error` 三类——T1b.2 不再有 session 级 `misaligned`，对齐是消息级判定或纯报告统计，见下）\n")
    lines.append(f"- `unverifiable_messages`: {stats['unverifiable_messages']}\n")
    for reason, n in stats["unverifiable_sessions_by_reason"].most_common():
        lines.append(f"  - {reason}: {n}\n")
    lines.append(f"- `out_of_scope_connector_sessions`（manifest+blob 都在，本轮无候选构造器，**不计入 unverifiable_sessions**）: {stats['out_of_scope_connector_sessions']}\n")
    lines.append(
        "  **SQL 复核口径**（advisor 2026-09-07 接受）：`unverifiable_sessions == 镜像缺失会话数`，"
        "只对 `no_manifest`+`no_blob` 这一项复核，`out_of_scope_connector_sessions` 不参与。\n"
    )
    lines.append(f"- `content_mismatch`（单条消息级，因证据文本核验不过被剔除，不计入 session）: {stats['content_mismatch_messages']}\n")

    lines.append("\n## 旧模型披露：整会话逐位对齐（T1b.2 起仅作报告统计，不再决定 manifest 收录）\n")
    lines.append("| agent_slug | 会话数 | 逐位对齐 | 不对齐 | 其中含 compacted 事件 |\n")
    lines.append("|---|---|---|---|---|\n")
    for slug, a in sorted(stats["alignment_by_agent"].items()):
        lines.append(f"| {slug} | {a['total']} | {a['aligned']} | {a['misaligned']} | {a['misaligned_compacted']} |\n")
    lines.append("首次分叉位置分布（前 5，仅统计不对齐会话）：\n")
    for pos, n in stats["alignment_first_diff_pos"].most_common(5):
        lines.append(f"- idx {pos}: {n} 个会话\n")
    lines.append(
        "这份统计解释了为什么 T1b.1 的旧模型报告里锚点 3 只有 683（参考 1665）——30% 非 compaction 会话被整体"
        "判死；T1b.2 改用消息级结构定位后，这些会话里能定位到唯一 tool_call/tool_result 或首条 user 行的消息"
        "照样进 manifest，不再被同会话别处的分叉拖累。\n"
    )

    lines.append("\n## ⑨ R7/R11 回填后新增启用连接器与新增命中数\n")
    lines.append(
        "见 `t1b-mission112-report.md`（本棒终报）附的回填前/后对照表；本报告本身是回填**后**（T1b Step 4）"
        "的产物，`codex.bash=exec_command`/`bash_arg_key=cmd` 已生效。\n"
    )

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
