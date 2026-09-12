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
import contextlib
import io
import glob
import hashlib
import json
try:
    import msgpack
except ImportError as _msgpack_error:  # pragma: no cover - interpreter setup
    # `extra_bin` is msgpack on every path of this script, and `--verify` also
    # needs SQLite >= 3.45 for JSONB. On the deployment host no single
    # interpreter has both (python3.10 has msgpack, SQLite 3.37; python3.12 has
    # SQLite 3.50, no msgpack), so spell out the combination that works
    # instead of dying on a bare ImportError.
    raise SystemExit(
        "exclusion_probe.py needs the `msgpack` module: "
        "PYTHONPATH=/usr/lib/python3/dist-packages python3.12 "
        "scripts/oracle/exclusion_probe.py ..."
    ) from _msgpack_error
import os
import random
import re
import shlex
import sqlite3
import sys
import tempfile
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
# Mirrors `src/indexer/mod.rs:15708 LOGICAL_SOURCE_CONNECTORS` -- connector
# slugs whose `source_path` is not a real filesystem path (a DB-derived key, a
# synthetic id), so their sessions are `SourceKind::Logical`: capture absence
# there is expected (`capture_na`), never a `CaptureFailed`.
LOGICAL_SOURCE_CONNECTORS = ("opencode",)


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
    `/` conversion, e.g. `C:/projects/...`.

    R3-N4 (任务书 #125): the drive letter is ASCII-only there
    (`bytes[0].is_ascii_alphabetic()`), and `str.isalpha()` is Unicode --
    `é:/projects/cc-workspace/USER.md` was judged an absolute path here and
    a relative one in Rust, so the probe could freeze a manifest entry
    production would never produce. `isascii()` restores the equivalence;
    with the first character ASCII, byte and character indexing agree, so
    the remaining `[1] == ":"` / `[2] == "/"` tests are unaffected."""
    return (
        len(p) >= 3
        and p[0].isascii()
        and p[0].isalpha()
        and p[1] == ":"
        and p[2] == "/"
    )


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
        # R4-N2 (任务书 #125): offsets, not slices. The old form copied the
        # whole remaining suffix into `after_open` on EVERY block, so a
        # message of N empty blocks moved O(N^2) characters (measured 0.697 s
        # at N=32000). `trimmed[open_end:close_pos]` is exactly what
        # `after_open[:close_rel]` was, without the copy, and the Rust side
        # this mirrors already borrows rather than copying.
        open_end = open_pos + len("<environment_context>")
        close_pos = trimmed.find(_CLOSER, open_end)
        if close_pos == -1:
            # No close tag anywhere after this open -- unreachable in
            # practice given the `endswith(_CLOSER)` precondition above and
            # that the opener string is not a substring of the closer
            # string; kept only as a defensive bail (mirrors the Rust side).
            return None
        if trimmed.find("<cwd>", open_end, close_pos) != -1:
            for opener in _OPENERS:
                if trimmed.startswith(opener):
                    return opener
            return "<environment_context>"
        search_from = close_pos + len(_CLOSER)


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
        event_key = ev.get("uuid") or line_identity(ev)
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


def _codex_block_text_nonempty(block):
    """`utils.rs::extract_content_part`'s first branch: a bare non-empty
    string element counts as visible text."""
    if isinstance(block, str):
        return bool(block.strip())
    if isinstance(block, dict):
        text = block.get("text")
        return isinstance(text, str) and bool(text.strip())
    return False


def _codex_content_nonempty(payload):
    """Rust `codex_events_from_blob`'s `content_nonempty`: a bare non-empty
    STRING `payload.content`/`payload.output` counts (the connector's
    `flatten_content` accepts it), and an array form counts when any element
    carries non-empty text -- an array of only empty-text blocks is zero real
    messages, not one."""
    value = payload.get("content")
    if value is None:
        value = payload.get("output")
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return any(_codex_block_text_nonempty(block) for block in value)
    return False


def _codex_reasoning_text(payload):
    """`codex.rs::reasoning_summary_text`: each non-empty `summary[].text`
    (type `summary_text`), newline-joined."""
    summary = payload.get("summary")
    if not isinstance(summary, list):
        return ""
    parts = []
    for item in summary:
        if not isinstance(item, dict) or item.get("type") != "summary_text":
            continue
        text = item.get("text")
        if isinstance(text, str) and text:
            parts.append(text)
    return "\n".join(parts)


def _codex_agent_message_text(payload):
    """`codex.rs::parse_agent_message_content`'s visible half: the
    text/input_text/output_text blocks' `text`, newline-joined."""
    blocks = payload.get("content")
    if not isinstance(blocks, list):
        return ""
    parts = [
        block["text"]
        for block in blocks
        if isinstance(block, dict)
        and block.get("type") in ("text", "input_text", "output_text")
        and isinstance(block.get("text"), str)
    ]
    return "\n".join(parts)


def _codex_tool_output_text(payload):
    """`codex.rs::tool_output_text`: a bare string `output`; else its `content`
    flattened when that is non-blank; else the whole `output` flattened."""
    output = payload.get("output")
    if output is None:
        return ""
    if isinstance(output, str):
        return output
    if isinstance(output, dict) and "content" in output:
        flattened = _flatten_content(output["content"])
        if flattened.strip():
            return flattened
    return _flatten_content(output)


def _codex_tool_call_arguments(payload, decode_json_string):
    """`codex.rs::parse_tool_call_arguments` for `response_item` (key order
    `arguments` then `input`, a non-empty JSON string decoded) versus the
    `event_msg` arm's raw pick (key order `input` then `arguments`, never
    decoded)."""
    if decode_json_string:
        raw = payload.get("arguments")
        if raw is None:
            raw = payload.get("input")
    else:
        raw = payload.get("input")
        if raw is None:
            raw = payload.get("arguments")
    if raw is None:
        return None
    if decode_json_string and isinstance(raw, str) and raw != "":
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return raw
    return raw


def _codex_render_tool_call(name, arguments):
    """`codex.rs::render_tool_call_content`: `<name>(<args>)`, or the bare name
    when there is no input (absent or JSON null)."""
    if arguments is None:
        return name
    return f"{name}({json.dumps(arguments, ensure_ascii=False, separators=(',', ':'))})"


def build_candidates_codex(events):
    """Port of `src/indexer/exclusion.rs::codex_events_from_blob` (N-codexkey,
    任务书 #131 T6-c).

    That function is the authority for a codex event's identity (`payload.id`,
    else `line:<physical line>`), for which lines produce a message at all, and
    for their order; the roles and texts below mirror the connector's own
    projection (`connectors/codex.rs`), because those are what the DB rows hold
    -- `_session_alignment` compares roles row by row.

    The pre-fix builder walked only `type == "response_item"`, so the whole
    `event_msg` layer (user_message / agent_reasoning / tool_call) was missing:
    its candidate list came out SHORTER than the recorded `raw.idx` positions
    of the same session, every later candidate shifted up, and the rebuild
    checks then compared the wrong event against the marker (`rs_…`/`fco_…` vs
    `line:23`, 4,449 candidates against a marker `raw.idx` of 5,384). Its
    `message` arm also had no non-emptiness test (an empty user message was
    emitted as a row) and no `agent_message` / missing-`payload.type` arms.
    """
    candidates = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        entry_type = ev.get("type") if isinstance(ev.get("type"), str) else ""
        payload = ev.get("payload")
        if not isinstance(payload, dict):
            continue
        payload_id = payload.get("id") if isinstance(payload.get("id"), str) else None
        event_key = payload_id or line_identity(ev)
        call_id = payload.get("call_id") if isinstance(payload.get("call_id"), str) else None
        name = payload.get("name") if isinstance(payload.get("name"), str) else None

        if entry_type == "response_item":
            ptype = payload.get("type") if isinstance(payload.get("type"), str) else None
            if ptype is None or ptype == "message":
                # `Some("message") | None`: a missing payload.type takes this
                # arm, and only a user/assistant role with non-empty content
                # produces a row -- the developer/system prompt line is dropped
                # by that test, not by a role blacklist.
                role = payload.get("role")
                if role in ("user", "assistant") and _codex_content_nonempty(payload):
                    candidates.append(
                        Candidate(role, event_key, 0, text=_flatten_content(payload.get("content")))
                    )
            elif ptype == "agent_message":
                if _codex_content_nonempty(payload):
                    candidates.append(
                        Candidate("user", event_key, 0, text=_codex_agent_message_text(payload))
                    )
            elif ptype == "reasoning":
                # Emptiness is judged on the EXTRACTED text, with
                # `encrypted_content` as the other way to survive.
                text = _codex_reasoning_text(payload)
                if text.strip() or payload.get("encrypted_content") is not None:
                    candidates.append(Candidate("reasoning", event_key, 0, text=text))
            elif ptype in CODEX_TOOL_CALL_TYPES:
                arguments = _codex_tool_call_arguments(payload, decode_json_string=True)
                candidates.append(
                    Candidate(
                        "tool_call", event_key, 0,
                        tool_call_id=call_id or payload_id,
                        tool_name=name or "unknown",
                        args=arguments,
                        text=_codex_render_tool_call(name or "unknown", arguments),
                    )
                )
            elif ptype in CODEX_TOOL_RESULT_TYPES:
                candidates.append(
                    Candidate(
                        "tool_result", event_key, 0,
                        tool_call_id=call_id,
                        text=_codex_tool_output_text(payload),
                    )
                )
        elif entry_type == "event_msg":
            etype = payload.get("type") if isinstance(payload.get("type"), str) else None
            if etype == "user_message":
                text = payload.get("message")
                if isinstance(text, str) and text.strip():
                    candidates.append(Candidate("user", event_key, 0, text=text))
            elif etype == "agent_reasoning":
                text = payload.get("text")
                if isinstance(text, str) and text.strip():
                    candidates.append(Candidate("reasoning", event_key, 0, text=text))
            elif etype == "tool_call":
                arguments = _codex_tool_call_arguments(payload, decode_json_string=False)
                candidates.append(
                    Candidate(
                        "tool_call", event_key, 0,
                        tool_call_id=call_id or payload_id,
                        tool_name=name or "unknown",
                        args=arguments,
                        text=_codex_render_tool_call(name or "unknown", arguments),
                    )
                )
            # `event_msg/agent_message` duplicates the response_item version and
            # is dropped; `token_count` attaches to an existing message and
            # emits none of its own; anything else here is connector plumbing.
        # any other outer `type` is dropped entirely.
    return candidates


# ---------------------------------------------------------------------------
# R4 配对.
# ---------------------------------------------------------------------------
class PairingContext:
    """Built once per session, walked in candidate order."""

    def __init__(self, candidates):
        # B03 (任务书 #131): two constraints on id-based pairing, mirroring
        # `src/indexer/exclusion.rs::PairingContext::build`:
        #   1. an id reused by two different `tool_call`s resolves to NO entry
        #      at all (R1-B5's 宁漏 half -- this port was missing it: plain
        #      assignment let the LAST call win);
        #   2. the call must sit STRICTLY BEFORE the result. The lookup used
        #      to be session-wide, so a result whose own call is gone
        #      (compacted/concatenated log) bound to a LATER call reusing the
        #      id and was judged -- and cleared -- as that call's hit.
        self.by_id = {}
        self.ambiguous_ids = set()
        for index, c in enumerate(candidates):
            if c.role != "tool_call" or not c.tool_call_id:
                continue
            if c.tool_call_id in self.ambiguous_ids:
                continue
            if c.tool_call_id in self.by_id:
                del self.by_id[c.tool_call_id]
                self.ambiguous_ids.add(c.tool_call_id)
            else:
                self.by_id[c.tool_call_id] = (c, index)
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
                    entry = self.by_id.get(c.tool_call_id)
                    matched = entry[0] if entry is not None and entry[1] < idx else None
                    self._pair_by_position[idx] = matched
                    if matched is not None and matched in unpaired:
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

    # 23. R3-N4 (任务书 #125): the Windows drive-letter test must use the
    # ASCII character class, not Python's Unicode `str.isalpha()`. Rust is
    # `bytes[0].is_ascii_alphabetic()` (`exclusion.rs:763`), so `é:/...` is
    # NOT a Windows absolute path there -- and the probe must not invent a
    # manifest entry production would never produce. `_normalize_path` keeps
    # the segment intact, so the non-ASCII first character is what decides.
    cands = [
        _mk("tool_call", tool_call_id="t1", tool_name="Read", args={"file_path": "é:/projects/cc-workspace/USER.md"}),
        _mk("tool_result", tool_call_id="t1"),
    ]
    cases.append(("R3-N4 non-ASCII drive letter is not an absolute path", cands, 1, 0, "claude_code", None))

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
        "hits_by_reason_agent": Counter(),
        "anchor3_opener": Counter(),
        "content_mismatch_messages": 0,
        "pairing_fail": Counter(),
    }


def _tool_result_fixture(result_block, db_content, agent_slug="claude_code",
                         tool_name="Read", args=None, call_id="t1"):
    """Build the minimal (conv, db_rows_full, raw_candidates) triple that
    drives ONE claude_code tool_result DB row through the PRODUCTION entry
    `process_session_v2` -- not through `decide` directly (任务书 #125
    R2-N13: the production entry and the selftest must share one judgment
    path). DB rows: a user turn boundary, the `tool_call` row carrying
    `tool_call_id=t1`, and the `tool_result` row under test."""
    if args is None:
        args = {"file_path": "/home/ivan/projects/cc-workspace/MEMORY.md"}
    call_block = {"type": "tool_use", "name": tool_name, "input": args}
    if call_id is not None:
        call_block["id"] = call_id
    call_event = {
        "type": "assistant",
        "uuid": "u1",
        "message": {"role": "assistant", "content": [call_block]},
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
        (1, "tool_call", _sha("call row"), "Read(...)", call_id),
        (2, "tool_result", _sha(db_content), db_content, call_id),
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
    assert len(cases) == 23, f"selftest must have exactly 23 cases, got {len(cases)}"
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
        # Every emitted entry must also land in the per-connector counter the
        # report derives its cass_recall split from (R1-N20) -- once each.
        agent_total = sum(stats["hits_by_reason_agent"].values())
        got = (len(entries), stats["content_mismatch_messages"], agent_total)
        want = (expect_entries, expect_mismatch, expect_entries)
        ok = got == want
        print(f"{'ok  ' if ok else 'FAIL'} {name} (expect={want} got={got})")
        if ok:
            passed += 1
    print(f"selftest/content: {passed}/{len(cases)}")
    return passed, len(cases)


def selftest_pairing_cases():
    """Family D (任务书 #125, R2-N13): the no-`tool_call_id` shape must be
    judged through the PRODUCTION entry, not only through `decide`.

    `PairingContext` (used by both `decide` and `process_session_v2`) accepts
    a turn with exactly one unpaired tool_call and one result even when
    neither carries an id -- `selftest_cases` case 13 asserts exactly that
    through `decide`. The production entry then threw the row away at
    `if not call_id: continue`, so the manifest was not the output of the
    rule the selftest claimed to cover.

    Each case is `(name, fixture_triple, expect_entries, expect_mismatch)`."""
    cases = []

    # D1: one unpaired no-id call, one no-id result -- the shape case 13
    # covers for `decide`, here driven end to end.
    cases.append((
        "D1 unique no-id call pairs through the production entry",
        _tool_result_fixture(
            {"type": "tool_result", "content": "read body"}, "read body", call_id=None
        ),
        1, 0,
    ))

    # D2: two no-id results carrying the SAME body in the mirror -- the
    # evidence anchor is not unique, so the row stays out (宁漏勿误).
    cases.append((
        "D2 twin no-id results are not verifiable",
        _twin_no_id_fixture({"type": "tool_result", "content": "read body"},
                            {"type": "tool_result", "content": "read body"}),
        0, 0,
    ))

    # D3: two no-id results with DIFFERENT bodies. This is what makes the
    # body comparison load-bearing: without it both events would claim the
    # row and the row would be dropped. With it, exactly the event whose
    # projected+redacted body IS this row's content anchors the pairing.
    cases.append((
        "D3 the no-id anchor is the event whose body matches",
        _twin_no_id_fixture({"type": "tool_result", "content": "read body"},
                            {"type": "tool_result", "content": "a different body"}),
        1, 0,
    ))

    return cases


def _twin_no_id_fixture(first_block, second_block):
    """One no-id `tool_use`, two no-id `tool_result` blocks in the same turn.
    `PairingContext` pairs the first result to the call and leaves the second
    unpaired, so only a body match can pick the right evidence."""
    conv, db_rows_full, _unused = _tool_result_fixture(
        {"type": "tool_result", "content": "placeholder"}, "read body", call_id=None
    )
    call_event = {
        "type": "assistant",
        "uuid": "u1",
        "message": {
            "role": "assistant",
            "content": [{
                "type": "tool_use",
                "name": "Read",
                "input": {"file_path": "/home/ivan/projects/cc-workspace/MEMORY.md"},
            }],
        },
    }
    result_event = {
        "type": "user",
        "uuid": "u2",
        "message": {"role": "user", "content": [first_block, second_block]},
    }
    return conv, db_rows_full, build_candidates_claude_code([call_event, result_event])


def _run_pairing_selftest(paths_cfg):
    cases = selftest_pairing_cases()
    passed = 0
    for name, (conv, db_rows_full, raw_candidates), expect_entries, expect_mismatch in cases:
        stats = _v2_stats()
        entries = process_session_v2(conv, db_rows_full, raw_candidates, paths_cfg, stats)
        got = (len(entries), stats["content_mismatch_messages"])
        want = (expect_entries, expect_mismatch)
        ok = got == want
        print(f"{'ok  ' if ok else 'FAIL'} {name} (expect={want} got={got})")
        if ok:
            passed += 1

    # B03 (任务书 #131): pairing is position-constrained, and a session-wide
    # reused id still resolves to nothing. Pre-fix `PairingContext` indexed
    # every call in the whole session up front, so a result whose own call is
    # gone (compacted or concatenated log) bound to a LATER call that merely
    # reuses the id, and the ordinary result was then judged -- and cleared --
    # as that call's `context_file_read`. Each case is
    # `(name, candidates, result_index, want_reason)`; the assertion goes
    # through the same `decide_r1_r2_for_call` the production entry calls.
    read_args = {"file_path": "/x/cc-workspace/USER.md"}
    extra_cases = [
        (
            "B03 a result that PRECEDES its call stays unpaired",
            [
                Candidate("tool_result", "later", 0, tool_call_id="x", text="ordinary result before the read ever occurred"),
                Candidate("tool_call", "later", 0, tool_call_id="x", tool_name="Read", args=read_args),
            ],
            0, None,
        ),
        (
            "B03 the same pair in call-then-result order still resolves",
            [
                Candidate("tool_call", "ek", 0, tool_call_id="x", tool_name="Read", args=read_args),
                Candidate("tool_result", "ek", 0, tool_call_id="x", text="read body"),
            ],
            1, "context_file_read",
        ),
        (
            "B03 a session-wide reused id leaves its results unpaired",
            [
                Candidate("tool_call", "ek", 0, tool_call_id="x", tool_name="Read", args=read_args),
                Candidate("tool_result", "ek", 0, tool_call_id="x", text="read body"),
                Candidate("tool_call", "ek", 0, tool_call_id="x", tool_name="Read", args=read_args),
            ],
            1, None,
        ),
    ]
    for name, candidates, result_index, want_reason in extra_cases:
        ctx = PairingContext(candidates)
        paired = ctx.paired_call_for(result_index)
        decision = decide_r1_r2_for_call(paired, "claude_code", paths_cfg) if paired is not None else None
        got_reason = decision["reason"] if decision else None
        ok = got_reason == want_reason
        print(f"{'ok  ' if ok else 'FAIL'} {name} (expect={want_reason!r} got={got_reason!r})")
        if ok:
            passed += 1
    total = len(cases) + len(extra_cases)
    print(f"selftest/pairing: {passed}/{total}")
    return passed, total


def selftest_perf_cases():
    """Family E (任务书 #125, R4-N2): `anchor3_shell_opener` must scan a long
    message in linear time. The pre-fix loop re-sliced the whole remaining
    suffix on every block (`after_open = trimmed[open_pos + len(...):]`), so
    a message of N empty environment-context blocks copied O(N^2) characters
    -- the reviewer measured 0.659778 s at N=32000 for a function the Rust
    side (`exclusion.rs`, borrowing slices) does in microseconds.

    Each case is `(name, text, max_seconds, expected_return)`."""
    blocks = 32000
    return [
        (
            f"E1 {blocks} empty environment-context blocks scan in linear time",
            "<environment_context></environment_context>" * blocks,
            0.05,
            None,
        ),
    ]


def _run_perf_selftest(paths_cfg):
    cases = selftest_perf_cases()
    passed = 0
    for name, text, max_seconds, expect in cases:
        start = time.perf_counter()
        got = anchor3_shell_opener(text)
        elapsed = time.perf_counter() - start
        ok = got == expect and elapsed < max_seconds
        print(
            f"{'ok  ' if ok else 'FAIL'} {name} "
            f"({elapsed:.4f}s < {max_seconds}s, result={got!r}, want {expect!r})"
        )
        if ok:
            passed += 1
    print(f"selftest/perf: {passed}/{len(cases)}")
    return passed, len(cases)


def selftest_report_cases():
    """Family C (任务书 #125, R1-N20 + R2-N15): every number the report prints
    must be derived from `stats` -- no frozen prose about "this run", no count
    that is really a list length, no field that was initialised and never
    filled. `checks` entries are `("in"|"not_in", needle)` against the
    rendered report text, or `("bucket", (command, expected))` against
    `bash_bucket_of`."""
    cases = []

    # B1: the per-connector cass_recall split must come from stats. The old
    # report asserted, in prose, "命中 25 条，全部来自 claude_code；codex 侧
    # 0 条" -- three numbers, none of them read from the counters.
    stats = _new_stats()
    stats["hits_by_reason"]["cass_recall"] = 37
    stats["hits_by_reason_agent"] = Counter()
    stats["hits_by_reason_agent"][("cass_recall", "claude_code")] = 28
    stats["hits_by_reason_agent"][("cass_recall", "codex")] = 9
    cases.append((
        "B1 cass_recall split is counted, not asserted in prose",
        stats, [],
        [("not_in", "命中 25 条"),
         ("not_in", "codex 侧 0 条"),
         ("in", "`cass_recall`: 合计 37；按 agent_slug：claude_code 28、codex 9")],
    ))

    # B2: the deep-doc negative-control count must be the real count, not the
    # length of a list that was capped at 20 during collection.
    stats = _new_stats()
    stats["deep_doc_hits_total"] = 37  # test-supplied: pre-fix stats has no such key
    stats["deep_doc_hits"] = [f"/elsewhere/doc{i}.md" for i in range(20)]
    cases.append((
        "B2 deep-doc count is the full count, list is what is capped",
        stats, [],
        [("in", "命中数: 37"), ("in", "前 20 条"), ("in", "共 37")],
    ))

    # B3: the two fields that were initialised and never filled. `idx!=0`
    # candidates are the known out-of-anchor class the T6 downstream gate
    # needs a number for; `logical_source` is the `SourceKind::Logical`
    # connector column (`LOGICAL_SOURCE_CONNECTORS`, indexer/mod.rs:15708).
    stats = _new_stats()
    stats["idx_ne_0_memory_candidates_total"] = 41  # test-supplied
    stats["idx_ne_0_memory_candidates"] = [f"codex idx={i}" for i in range(20)]
    stats["idx_ne_0_anchor3_also"] = 3
    stats["coverage"]["opencode"] = {
        "sessions": 7, "mirror_ok": 0, "has_tool_call_id": 0,
        "has_tool_name": 0, "has_path_arg": 0, "logical_source": 7,
    }
    cases.append((
        "B3 idx!=0 candidates and logical-source are filled in",
        stats, [],
        [("in", "命中数: 41"),
         ("in", "其中 anchor3_shell_opener 也命中 3"),
         ("in", "| 有 path 参数 | 逻辑来源 |"),
         ("in", "| opencode | 7 | 0 | 无（本轮未实现，见 R7/R11「不启用」） | 0 | 0 | 0 | 7 |")],
    ))

    # B4: a truncated list must say so ("前 N 条 / 共 M"), not masquerade as
    # the whole population.
    stats = _new_stats()
    for i in range(30):
        stats["tool_name_freq"]["codex"][f"tool_{i:02d}"] = 100 - i
    cases.append((
        "B4 truncated tool-name list carries its own total",
        stats, [],
        [("in", "共 30")],
    ))

    # B5: compound Bash forms used to be dropped from BOTH Bash buckets --
    # neither "in the subset" nor "outside it by head token" -- so the report
    # could not show how much Bash traffic R2-e was rejecting.
    stats = _new_stats()
    stats["bash_subset_out_compound"] = Counter()
    stats["bash_subset_out_compound"]["cat"] = 5
    cases.append((
        "B5 compound Bash forms get their own bucket",
        stats, [],
        [("in", "复合形态"), ("in", "`cat`: 5")],
    ))

    # B6: the classification itself, driven directly.
    cases.append((
        "B6 compound command classifies as a compound bucket, not as a subset miss",
        _new_stats(), [],
        [("bucket", ("cat /a/MEMORY.md && grep -n x /tmp/y", ("compound", "cat"))),
         ("bucket", ("grep -rn x /tmp", ("out", "grep"))),
         ("bucket", ("cat /a/MEMORY.md /a/USER.md", ("in", None)))],
    ))

    return cases


def _run_report_selftest(paths_cfg):
    cases = selftest_report_cases()
    passed = 0
    for name, stats, manifest, checks in cases:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = os.path.join(tmp, "report.md")
            write_report(report_path, stats, manifest, 1)
            with open(report_path, encoding="utf-8") as f:
                text = f.read()
        failures = []
        for kind, payload in checks:
            if kind == "in":
                if payload not in text:
                    failures.append(f"missing {payload!r}")
            elif kind == "not_in":
                if payload in text:
                    failures.append(f"still present {payload!r}")
            elif kind == "bucket":
                command, expected = payload
                got = bash_bucket_of(command)
                if got != expected:
                    failures.append(f"bucket({command!r}) = {got!r}, want {expected!r}")
        ok = not failures
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f" ({'; '.join(failures)})"))
        if ok:
            passed += 1
    print(f"selftest/report: {passed}/{len(cases)}")
    return passed, len(cases)


# ---------------------------------------------------------------------------
# verify family (PR6 T5): drives the PRODUCTION `_verify_once` against a
# synthetic v6/reference pair so the assertions are exercised without the
# 30 GB frozen library. Bodies are invented strings -- no real content, no
# real host paths.
# ---------------------------------------------------------------------------
_VERIFY_BODY = "PR6 T5 verify fixture body " + "abcdefghij" * 8
_VERIFY_SIBLING = "PR6 T5 verify fixture sibling block " + "klmnopqrst" * 8
_VERIFY_ORDINARY = "PR6 T5 verify fixture ordinary field " + "uvwxyzabcd" * 8
# B08 (任务书 #131): a body that JSON has to escape, so "the body is still
# in the extra" cannot be decided by looking at a serialized dump of it.
_VERIFY_MULTILINE_BODY = "PR6 T5 verify fixture multiline body\nline two with a \"quote\"\n" + "abcdefghij" * 8
# B08: shorter than the old `len(body) >= 32` gate, which skipped the whole
# carried-body check for it.
_VERIFY_SHORT_BODY = "short leaked body"
# R9-B03 (任务书 #132): a body the connector carries as an ARRAY of fragments
# -- `flatten_content` joins them with `\n`, so the projected body is this
# whole string while no single element is it.
_VERIFY_FRAGMENT_BODY = "secret A\nsecret B"


def _verify_extra(block_value):
    """The EVENT shape `raw.blocks` addresses: `result_event` has exactly one
    `message.content` entry, so a marker recorded against it carries
    `blocks=[0]` and index 0 IS the tool_result block. (Before B07 this
    fixture put a sibling text block at 0 and the tool_result at 1, a pairing
    no real marker/event can produce -- which is what let an over-clear at a
    block the exclusion does not own look identical to a legitimate one.)

    `ordinary` is a field of this event that no R7 path may touch; the
    over-clear case replaces it with the same redacted placeholder and must
    still be a failure."""
    return {
        "uuid": "u2",
        "message": {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": block_value},
            ],
        },
        "ordinary": _VERIFY_ORDINARY,
    }


def _write_opencode_probe_db(root):
    """A minimal corpus holding ONE `opencode` session (the connector whose
    sessions the plan models as `SourceKind::Logical`), and no mirror at all --
    so `run_probe` reaches its `no_manifest` branch for it."""
    path = os.path.join(root, "opencode-probe.db")
    conn = sqlite3.connect(path)
    conn.executescript(_verify_schema(False))
    conn.execute("INSERT INTO agents(id, slug, name, kind) VALUES (1, 'opencode', 'OpenCode', 'cli')")
    conn.execute(
        "INSERT INTO conversations(id, agent_id, source_id, external_id, title, source_path) "
        "VALUES (1, 1, 'local', 'opencode-ext-1', 'probe fixture session', '/src/opencode-1.jsonl')"
    )
    conn.execute(
        "INSERT INTO messages(id, conversation_id, idx, role, content, extra_bin) "
        "VALUES (1, 1, 0, 'user', 'hello', NULL)"
    )
    conn.commit()
    conn.close()
    return path


def _verify_schema(with_excluded):
    excluded = ", excluded BLOB" if with_excluded else ""
    return (
        "CREATE TABLE agents(id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE, "
        "name TEXT, version TEXT, kind TEXT);"
        "CREATE TABLE conversations(id INTEGER PRIMARY KEY, agent_id INTEGER, "
        "source_id TEXT, external_id TEXT, title TEXT, source_path TEXT);"
        "CREATE TABLE messages(id INTEGER PRIMARY KEY, conversation_id INTEGER, "
        f"idx INTEGER, role TEXT, content TEXT NOT NULL, extra_bin BLOB{excluded});"
    )


def _write_verify_fixture(root, *, sibling_leak=False, non_target_cleared=False,
                          non_manifest_altered=False, overclear_ordinary=False,
                          leak_multiline_body=False, short_body=False,
                          missing_nonmanifest_row=False, wrong_raw_idx=False,
                          wrong_marker_sha=False, project_read_anchor=False,
                          legit_sibling_redaction=False, compact_extra_no_body=False,
                          candidate_only_row=False, array_tool_use_result=None,
                          excludable_sibling_leak=False,
                          beyond_manifest_excluded=None,
                          fragmented_array_tool_use_result=False,
                          foreign_array_tool_use_result_cleared=False,
                          candidate_only_excluded_row=None,
                          fragmented_extra_text_blocks=False,
                          duplicate_source_row=False, null_raw_event_key=False):
    candidate = os.path.join(root, "candidate.db")
    reference = os.path.join(root, "reference.db")
    manifest_path = os.path.join(root, "manifest.json")
    mirror = os.path.join(root, "mirror")
    blob_rel = "blobs/blake3/aa/verify-fixture.raw"
    blob_path = os.path.join(mirror, blob_rel)
    os.makedirs(os.path.dirname(blob_path), exist_ok=True)

    fragmented = (
        fragmented_array_tool_use_result
        or foreign_array_tool_use_result_cleared
        or fragmented_extra_text_blocks
    )
    body_text = (
        _VERIFY_FRAGMENT_BODY if fragmented
        else _VERIFY_SHORT_BODY if short_body
        else _VERIFY_MULTILINE_BODY if leak_multiline_body
        else _VERIFY_BODY
    )
    # B10 (任务书 #131): a marker whose recorded identity was tampered with.
    # `wrong_marker_sha` moves the marker's sha AND its placeholder together,
    # so only the manifest binding (not the placeholder-shape check) can
    # expose it.
    marker_sha = hashlib.sha256(b"not the body this fixture excluded").hexdigest() if wrong_marker_sha else None
    body_sha = hashlib.sha256(redact_text(body_text).encode("utf-8")).hexdigest()
    redacted = {"redacted": True, "sha256": body_sha, "bytes": len(body_text.encode("utf-8"))}
    if wrong_marker_sha:
        redacted = dict(redacted, sha256=marker_sha)

    call_event = {
        "type": "assistant",
        "uuid": "u1",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "name": "Read", "id": "t1",
             "input": {"file_path": "/srv/cc-workspace/MEMORY.md"}},
        ]},
    }
    # R9-B03 (任务书 #132): the connector's ARRAY form of a `tool_result`
    # body. `_flatten_content` joins these fragments with `\n`, so the
    # projected body is exactly `body_text` -- but no single element is it.
    fragment_blocks = [{"type": "text", "text": part} for part in body_text.split("\n")]
    result_block_value = fragment_blocks if fragmented else body_text
    result_event = {
        "type": "user",
        "uuid": "u2",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": result_block_value},
        ]},
    }
    second_pair = []
    if excludable_sibling_leak:
        # N-fam4 (任务书 #131 T6-c): a SECOND call/result pair whose result
        # carries the same body AND is itself excludable -- the shape a real
        # leak has (the body survives in a row the rules would have excluded),
        # as opposed to the `sibling_leak` shape above (a plain user row the
        # rules never cover).
        second_pair = [
            {"type": "assistant", "uuid": "u3", "message": {"role": "assistant", "content": [
                {"type": "tool_use", "name": "Read", "id": "t2",
                 "input": {"file_path": "/srv/cc-workspace/MEMORY.md"}},
            ]}},
            {"type": "user", "uuid": "u4", "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t2", "content": body_text},
            ]}},
        ]
    with open(blob_path, "w", encoding="utf-8") as handle:
        for event in [call_event, result_event] + second_pair:
            handle.write(json.dumps(event) + "\n")

    boundary = {"message": {"role": "user", "content": [{"type": "text", "text": "turn boundary"}]}}
    sibling_extra = {"message": {"content": [{"type": "text", "text": body_text}]}}
    for path, with_excluded in ((reference, False), (candidate, True)):
        conn = sqlite3.connect(path)
        conn.executescript(_verify_schema(with_excluded))
        if with_excluded:
            conn.executescript(
                "CREATE TABLE snippets(id INTEGER PRIMARY KEY, message_id INTEGER, snippet_text TEXT);"
                "CREATE TABLE lex_docs(doc_id INTEGER PRIMARY KEY, content TEXT);"
                "CREATE TABLE message_chunks(chunk_id INTEGER PRIMARY KEY, message_id INTEGER);"
            )
        conn.execute("INSERT INTO agents(id, slug, name, kind) VALUES (1, 'claude_code', 'Claude', 'cli')")
        if duplicate_source_row and not with_excluded:
            # R9-B08 (任务书 #132): the OTHER source's row, inserted FIRST (rowid
            # 0) so it is scanned before the candidate's survivor -- the fold R9
            # measured, where the later row overwrote it in the pre-fix dict and
            # the dropped row became invisible. The reference keeps it; the
            # candidate never has it.
            conn.execute(
                "INSERT INTO conversations(id, agent_id, source_id, external_id, title, source_path) "
                "VALUES (4, 1, 'other', 'verify-ext-1', 'same session key, other source', '/src/other/verify-ext-1.jsonl')"
            )
            conn.execute(
                "INSERT INTO messages(id, conversation_id, idx, role, content, extra_bin) "
                "VALUES (0, 4, 7, 'user', 'host A unique data', ?)",
                [msgpack.packb(
                    {"message": {"content": [{"type": "text", "text": "host A unique data"}]}},
                    use_bin_type=True,
                )],
            )
        conn.execute(
            "INSERT INTO conversations(id, agent_id, source_id, external_id, title, source_path) "
            "VALUES (1, 1, 'local', 'verify-ext-1', 'verify fixture session', '/src/verify-ext-1.jsonl')"
        )
        if duplicate_source_row:
            # The same (agent, external_id, idx) from the OTHER source -- the
            # key both rows would fold to if `source_id` were not part of it.
            conn.execute(
                "INSERT INTO messages(id, conversation_id, idx, role, content, extra_bin) "
                "VALUES (800, 1, 7, 'user', 'host B data', ?)",
                [msgpack.packb(
                    {"message": {"content": [{"type": "text", "text": "host B data"}]}},
                    use_bin_type=True,
                )],
            )
        boundary_content = "altered boundary" if (non_manifest_altered and with_excluded) else "turn boundary"
        if not (missing_nonmanifest_row and with_excluded):
            # B09: the candidate simply does not have this ordinary row, while
            # the reference library does. Only a two-way comparison of the
            # stable keys can see it.
            conn.execute(
                "INSERT INTO messages(id, conversation_id, idx, role, content, extra_bin) "
                "VALUES (1, 1, 0, 'user', ?, ?)",
                [boundary_content, msgpack.packb(boundary, use_bin_type=True)],
            )
        candidate_extra = _verify_extra(redacted if with_excluded else result_block_value)
        # R9-B03 (任务书 #132): the array-form top-level `toolUseResult`.
        # `fragmented_array_tool_use_result` is the POSITIVE shape -- its join
        # IS the excluded body, so every element is a fragment of that body's
        # copy and the candidate replaced them all. The foreign one is the
        # boundary: its join is a different body, so clearing the elements is
        # an over-clear the judge must keep failing.
        if fragmented_array_tool_use_result:
            candidate_extra["toolUseResult"] = (
                [{"type": "text", "text": redacted}, {"type": "text", "text": redacted}]
                if with_excluded
                else [{"type": "text", "text": part} for part in body_text.split("\n")]
            )
        if foreign_array_tool_use_result_cleared:
            candidate_extra["toolUseResult"] = (
                [{"type": "text", "text": redacted}, {"type": "text", "text": redacted}]
                if with_excluded
                else [{"type": "text", "text": "some other"}, {"type": "text", "text": "tool's body"}]
            )
        if fragmented_extra_text_blocks:
            # R9-B06's other half: the extra carries the body as SEVERAL
            # `text` blocks, so the connector's visible text is their `\n`
            # join and no single leaf holds it. Left identical on both sides
            # (the candidate never touched the extra), so only a check that
            # PROJECTS the extra can see the body survive.
            candidate_extra["message"]["content"] = [
                {"type": "text", "text": part} for part in body_text.split("\n")
            ]
        if compact_extra_no_body:
            # N-fam2: the "compact" shape the frozen corpus has for ~31% of
            # rows -- prior compression left only these keys, so NO field ever
            # carried the body and the two sides' extras are byte-identical.
            candidate_extra = {"raw_role": "tool_result", "tool_call_id": "t1"}
        if with_excluded and non_target_cleared:
            # A change that is NOT a redacted placeholder (an extra block the
            # reference library does not have).
            candidate_extra["message"]["content"].append({"type": "text", "text": ""})
        if with_excluded and overclear_ordinary:
            # B07: the SAME redacted placeholder, at a path this exclusion
            # does not own. Pre-fix this passed as a clean exclusion.
            candidate_extra["ordinary"] = redacted
        if array_tool_use_result is not None:
            # N-R7arr (任务书 #131 T6-c): the ARRAY form of a top-level
            # `toolUseResult` (`[{type:text,text:...}]`, what the MCP tool
            # results record). The candidate replaced element 0's `text` with
            # the placeholder; the reference's element either IS the excluded
            # body's own copy (`owned` -- a legitimate exclusion the field map
            # must admit) or is some other body's (`foreign` -- an over-clear
            # that must stay a failure).
            reference_text = body_text if array_tool_use_result == "owned" else "some other tool's body"
            candidate_extra["toolUseResult"] = [
                {"type": "text", "text": redacted if with_excluded else reference_text}
            ]
        conn.execute(
            "INSERT INTO messages(conversation_id, idx, role, content, extra_bin) "
            "VALUES (1, 1, 'tool_result', ?, ?)",
            ["" if with_excluded else body_text, msgpack.packb(candidate_extra, use_bin_type=True)],
        )
        if sibling_leak:
            # N-fam4: the body must sit in the row's CONTENT for this case --
            # that is the limb N-fam4 splits. A body verbatim in another row's
            # extra_bin is B08's shape and keeps its (unsplit) judgment below.
            conn.execute(
                "INSERT INTO messages(conversation_id, idx, role, content, extra_bin) "
                "VALUES (1, 2, 'user', ?, ?)",
                [
                    f"sibling turn {body_text}",
                    msgpack.packb({"message": {"content": [{"type": "text", "text": "sibling turn"}]}}, use_bin_type=True),
                ],
            )
        if beyond_manifest_excluded is not None:
            # N-fam5 (任务书 #131 T6-c): a row the CANDIDATE excluded that the
            # frozen manifest cannot know about (it was added to the corpus
            # after the manifest's snapshot). `ok` carries the shape a correct
            # exclusion has -- empty content, a marker, and extra differences
            # that are all redacted placeholders; `bad` carries a stray change
            # the marker does not account for.
            beyond_extra = _verify_extra(redacted if with_excluded else body_text)
            beyond_content = "" if with_excluded else body_text
            if beyond_manifest_excluded == "body_retained":
                # R9-B04 (任务书 #132), the leak shape: an ordinary field holds a
                # verbatim copy of the body on BOTH sides. The candidate cleared
                # the row's content and appended a well-shaped marker but never
                # touched that copy, so no `extra_bin` DIFF can see it -- the body
                # is still reconstructible out of the candidate's own extra.
                beyond_extra["ordinary"] = body_text
            if with_excluded and beyond_manifest_excluded == "bad":
                beyond_extra["stray"] = "a change no redacted placeholder explains"
            if with_excluded and beyond_manifest_excluded == "overclear":
                # R9-B04, the over-clear shape: the same ordinary field replaced
                # with the marker's OWN placeholder -- an over-clear wearing the
                # exclusion's sha, at a path this exclusion does not own.
                beyond_extra["ordinary"] = redacted
            beyond_marker_sha = body_sha
            if beyond_manifest_excluded == "wrong_sha":
                # R9-B04's "does the sha correspond to the reference body at
                # all" half: a marker (and the placeholder it explains) whose
                # sha belongs to some OTHER text.
                beyond_marker_sha = hashlib.sha256(b"a body this exclusion never saw").hexdigest()
                if with_excluded:
                    beyond_extra = _verify_extra(
                        {"redacted": True, "sha256": beyond_marker_sha,
                         "bytes": len(body_text.encode("utf-8"))}
                    )
            marker_json = json.dumps({
                # R9-B04's "is the message really excludable for this reason"
                # half: `cass_recall` on a message the rules read as a
                # `context_file_read` must not be taken at face value.
                "reason": "cass_recall" if beyond_manifest_excluded == "reason_mismatch" else "context_file_read",
                "rule_version": 1,
                "bytes": len(body_text.encode("utf-8")),
                "sha256": beyond_marker_sha,
                "fingerprint_blake3": "0" * 64,
                "parse_error": None,
                "anchor": {"tool_call_id": "t9", "tool_name": "Read", "paths": None, "shell": None},
                "src": None,
                "raw": {"blob": blob_rel, "idx": 1, "event_key": "u2", "blocks": [0]},
            })
            # R9-B04 (任务书 #132): the beyond-manifest row lives in its OWN
            # session, so the branch under test is the only judge that can
            # reach it -- left inside the manifest entry's session, the
            # session-wide "still carries the body in extra_bin" scan (a
            # different limb) would catch some of these shapes for reasons that
            # say nothing about whether this branch validates anything at all.
            conn.execute(
                "INSERT INTO conversations(id, agent_id, source_id, external_id, title, source_path) "
                "VALUES (2, 1, 'local', 'verify-ext-2', 'verify fixture session 2', '/src/verify-ext-2.jsonl')"
            )
            if with_excluded:
                # Only the candidate schema (v6) has the `excluded` column.
                conn.execute(
                    "INSERT INTO messages(conversation_id, idx, role, content, extra_bin, excluded) "
                    "VALUES (2, 5, 'tool_result', ?, ?, jsonb(?))",
                    [beyond_content, msgpack.packb(beyond_extra, use_bin_type=True), marker_json],
                )
            else:
                conn.execute(
                    "INSERT INTO messages(conversation_id, idx, role, content, extra_bin) "
                    "VALUES (2, 5, 'tool_result', ?, ?)",
                    [beyond_content, msgpack.packb(beyond_extra, use_bin_type=True)],
                )
        if excludable_sibling_leak:
            conn.execute(
                "INSERT INTO messages(conversation_id, idx, role, content, extra_bin) "
                "VALUES (1, 2, 'user', ?, ?)",
                [f"sibling turn {body_text}", msgpack.packb(sibling_extra, use_bin_type=True)],
            )
        if candidate_only_excluded_row is not None and with_excluded:
            # R9-B05 (任务书 #132): a session the CANDIDATE alone has (the
            # reference snapshot predates it), whose single row carries an
            # `excluded` marker. Its own invariants are all the judge has --
            # and a marker next to a surviving body is a contradiction the
            # reference's absence cannot excuse.
            conn.execute(
                "INSERT INTO conversations(id, agent_id, source_id, external_id, title, source_path) "
                "VALUES (3, 1, 'local', 'verify-ext-3', 'verify fixture session 3', '/src/verify-ext-3.jsonl')"
            )
            co_marker = json.dumps({
                "reason": "context_file_read",
                "rule_version": 1,
                "bytes": len(body_text.encode("utf-8")),
                "sha256": body_sha,
                "fingerprint_blake3": "0" * 64,
                "parse_error": None,
                "anchor": {"tool_call_id": "t1", "tool_name": "Read", "paths": None, "shell": None},
                "src": None,
                "raw": {
                    "blob": (
                        "blobs/blake3/zz/not-in-the-mirror.raw"
                        if candidate_only_excluded_row == "unverifiable"
                        else blob_rel
                    ),
                    "idx": 1,
                    "event_key": "u2",
                    "blocks": [0],
                },
            })
            co_content = body_text if candidate_only_excluded_row == "body_retained" else ""
            co_extra = _verify_extra(redacted)
            if candidate_only_excluded_row == "extra_leak":
                co_extra["leak"] = body_text
            conn.execute(
                "INSERT INTO messages(conversation_id, idx, role, content, extra_bin, excluded) "
                "VALUES (3, 0, 'tool_result', ?, ?, jsonb(?))",
                [co_content, msgpack.packb(co_extra, use_bin_type=True), co_marker],
            )
        if candidate_only_row and with_excluded:
            # N-fam2: a row only the CANDIDATE has (a newer library).
            conn.execute(
                "INSERT INTO messages(conversation_id, idx, role, content, extra_bin) "
                "VALUES (1, 4, 'user', ?, ?)",
                ["a newer session row", msgpack.packb({"message": {"content": [{"type": "text", "text": "newer"}]}}, use_bin_type=True)],
            )
        if legit_sibling_redaction:
            # N02 (任务书 #131): a SECOND row carrying the same event, with the
            # same target block replaced -- what `apply_sibling` produces. The
            # reference library has the same row un-redacted.
            conn.execute(
                "INSERT INTO messages(conversation_id, idx, role, content, extra_bin) "
                "VALUES (1, 2, 'user', ?, ?)",
                [
                    "assistant commentary, must stay",
                    msgpack.packb(_verify_extra(redacted if with_excluded else body_text), use_bin_type=True),
                ],
            )
        if leak_multiline_body or short_body:
            # B08: the body survives verbatim in a later row's extra,
            # IDENTICAL on both sides -- so no `extra_bin` diff can expose it
            # and only a scan of the decoded string leaves can.
            conn.execute(
                "INSERT INTO messages(conversation_id, idx, role, content, extra_bin) "
                "VALUES (1, 3, 'user', ?, ?)",
                [
                    "a later turn",
                    msgpack.packb({"message": {"content": [{"type": "text", "text": body_text}]}}, use_bin_type=True),
                ],
            )
        fixture_reason = "context_file_read" if project_read_anchor else "cass_recall"
        if with_excluded:
            marker = {
                "reason": fixture_reason,
                "rule_version": 1,
                "bytes": len(body_text.encode("utf-8")),
                "sha256": marker_sha if wrong_marker_sha else body_sha,
                "fingerprint_blake3": "0" * 64,
                "parse_error": None,
                "anchor": (
                    {
                        "tool_call_id": "t1",
                        "tool_name": "mcp__ccw-control-plane__project_read",
                        "paths": ["exec"],
                        "shell": None,
                    }
                    if project_read_anchor
                    else {"tool_call_id": "t1", "tool_name": "Read", "paths": None, "shell": None}
                ),
                "src": None,
                "raw": {"blob": blob_rel, "idx": 123456 if wrong_raw_idx else 1,
                        "event_key": None if null_raw_event_key else "u2", "blocks": [0]},
            }
            conn.execute(
                "UPDATE messages SET excluded = jsonb(?) WHERE conversation_id = 1 AND idx = 1",
                [json.dumps(marker)],
            )
        conn.commit()
        conn.close()

    manifest = [{
        "reason": fixture_reason,
        "source_id": "local",
        "agent_slug": "claude_code",
        "external_id": "verify-ext-1",
        "source_path": "/src/verify-ext-1.jsonl",
        "idx": 1,
        "sha256": body_sha,
        "evidence": "mirror",
        "event_key": "u2",
        "blocks": [0],
    }]
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle)
    return candidate, reference, manifest_path, mirror


_VERIFY_CODEX_SHELL_BLOCKS = (
    "<environment_context>\n<cwd>/fixture</cwd>",
    "private injected context\n</environment_context>",
)


def _write_codex_verify_fixture(root):
    """R9-B06 (任务书 #132): a `codex_host_shell` whose body the connector
    carries as TWO `input_text` blocks.

    `flatten_content` joins the visible blocks with `\n`, so the projected body
    is the whole joined string while each block holds only a fragment. The
    candidate cleared `messages.content` and wrote its marker but left
    `extra.payload.content` untouched, so the complete original is still
    reconstructible from the extra -- yet no single string leaf contains it and
    the leaf-only scan called this `extra_unchanged_no_body`.

    The first (and only) message of a codex session is the host shell at idx 0,
    so this is the R3 shape end to end: a real blob, a real marker, a real
    manifest entry, and a candidate whose only change is the one it claims.
    """
    candidate = os.path.join(root, "codex-candidate.db")
    reference = os.path.join(root, "codex-reference.db")
    manifest_path = os.path.join(root, "codex-manifest.json")
    mirror = os.path.join(root, "codex-mirror")
    blob_rel = "blobs/blake3/cc/codex-host-shell.raw"
    blob_path = os.path.join(mirror, blob_rel)
    os.makedirs(os.path.dirname(blob_path), exist_ok=True)

    body_text = "\n".join(_VERIFY_CODEX_SHELL_BLOCKS)
    body_sha = hashlib.sha256(redact_text(body_text).encode("utf-8")).hexdigest()
    redacted = {"redacted": True, "sha256": body_sha, "bytes": len(body_text.encode("utf-8"))}
    event = {
        "type": "response_item",
        "payload": {
            "id": "ev-1",
            "type": "message",
            "role": "user",
            "content": [
                {"type": "input_text", "text": _VERIFY_CODEX_SHELL_BLOCKS[0]},
                {"type": "input_text", "text": _VERIFY_CODEX_SHELL_BLOCKS[1]},
            ],
        },
    }
    with open(blob_path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")

    marker = {
        "reason": "codex_host_shell",
        "rule_version": 1,
        "bytes": len(body_text.encode("utf-8")),
        "sha256": body_sha,
        "fingerprint_blake3": "0" * 64,
        "parse_error": None,
        "anchor": {"tool_call_id": None, "tool_name": None, "paths": None,
                   "shell": {"opener": "environment_context"}},
        "src": None,
        "raw": {"blob": blob_rel, "idx": 0, "event_key": "ev-1", "blocks": [0]},
    }
    for path, with_excluded in ((reference, False), (candidate, True)):
        conn = sqlite3.connect(path)
        conn.executescript(_verify_schema(with_excluded))
        if with_excluded:
            conn.executescript(
                "CREATE TABLE snippets(id INTEGER PRIMARY KEY, message_id INTEGER, snippet_text TEXT);"
                "CREATE TABLE lex_docs(doc_id INTEGER PRIMARY KEY, content TEXT);"
                "CREATE TABLE message_chunks(chunk_id INTEGER PRIMARY KEY, message_id INTEGER);"
            )
        conn.execute("INSERT INTO agents(id, slug, name, kind) VALUES (1, 'codex', 'Codex', 'cli')")
        conn.execute(
            "INSERT INTO conversations(id, agent_id, source_id, external_id, title, source_path) "
            "VALUES (1, 1, 'local', 'codex-ext-1', 'codex host shell session', '/src/codex-ext-1.jsonl')"
        )
        if with_excluded:
            conn.execute(
                "INSERT INTO messages(id, conversation_id, idx, role, content, extra_bin, excluded) "
                "VALUES (1, 1, 0, 'user', '', ?, jsonb(?))",
                [msgpack.packb(event, use_bin_type=True), json.dumps(marker)],
            )
        else:
            conn.execute(
                "INSERT INTO messages(id, conversation_id, idx, role, content, extra_bin) "
                "VALUES (1, 1, 0, 'user', ?, ?)",
                [body_text, msgpack.packb(event, use_bin_type=True)],
            )
        conn.commit()
        conn.close()

    manifest = [{
        "reason": "codex_host_shell",
        "source_id": "local",
        "agent_slug": "codex",
        "external_id": "codex-ext-1",
        "source_path": "/src/codex-ext-1.jsonl",
        "idx": 0,
        "sha256": body_sha,
        "evidence": "mirror",
        "event_key": "ev-1",
        "blocks": [0],
    }]
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle)
    return candidate, reference, manifest_path, mirror


def _write_b07_fixture(root):
    """R9-B07 (任务书 #132): an informational hit must not end the session scan.

    Four rows, in insertion (and therefore idx) order:

    | idx | row                                                   |
    |-----|-------------------------------------------------------|
    | 0   | an ordinary row that QUOTES the excluded body          |
    | 1   | the Read call                                          |
    | 2   | the ordinary row of the SAME mixed event as the result |
    | 3   | the excluded `tool_result` itself                      |

    Row 0's copy is one the rules do not cover, so it is informational. Row 2
    still carries the excluded body inside its `extra_bin` -- a real leak. The
    pre-fix scan matched row 0 first, counted it, and `break`ed, so row 2 was
    never examined and the run reported `failures=0`.
    """
    candidate = os.path.join(root, "b07-candidate.db")
    reference = os.path.join(root, "b07-reference.db")
    manifest_path = os.path.join(root, "b07-manifest.json")
    mirror = os.path.join(root, "b07-mirror")
    blob_rel = "blobs/blake3/bb/b07-fixture.raw"
    blob_path = os.path.join(mirror, blob_rel)
    os.makedirs(os.path.dirname(blob_path), exist_ok=True)

    body = _VERIFY_BODY
    body_sha = hashlib.sha256(redact_text(body).encode("utf-8")).hexdigest()
    redacted = {"redacted": True, "sha256": body_sha, "bytes": len(body.encode("utf-8"))}
    call_uuid, mixed_uuid = "b07-call", "b07-mixed"
    call_event = {
        "type": "assistant", "uuid": call_uuid,
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "name": "Read", "id": "a",
             "input": {"file_path": "/srv/cc-workspace/MEMORY.md"}}]},
    }
    mixed_dirty = {
        "type": "user", "uuid": mixed_uuid,
        "message": {"role": "user", "content": [
            {"type": "text", "text": "ordinary prose of the mixed event"},
            {"type": "tool_result", "tool_use_id": "a", "content": body}]},
    }
    mixed_clean = {
        "type": "user", "uuid": mixed_uuid,
        "message": {"role": "user", "content": [
            {"type": "text", "text": "ordinary prose of the mixed event"},
            {"type": "tool_result", "tool_use_id": "a", "content": redacted}]},
    }
    with open(blob_path, "w", encoding="utf-8") as handle:
        for event in (call_event, mixed_dirty):
            handle.write(json.dumps(event) + "\n")

    marker = {
        "reason": "context_file_read",
        "rule_version": 1,
        "bytes": len(body.encode("utf-8")),
        "sha256": body_sha,
        "fingerprint_blake3": "0" * 64,
        "parse_error": None,
        "anchor": {"tool_call_id": "a", "tool_name": "Read", "paths": None, "shell": None},
        "src": None,
        # `raw.idx` indexes the BUILDER's candidate list, which is not the DB
        # row order: the blob holds two events, and the mixed event's
        # `tool_result` is its second block -- candidate 2, block 1.
        "raw": {"blob": blob_rel, "idx": 2, "event_key": mixed_uuid, "blocks": [1]},
    }
    rows = [
        (0, "user", f"ordinary row quoting {body}",
         {"message": {"content": [{"type": "text", "text": "plain"}]}}),
        (1, "tool_call", 'Read({"file_path":"/srv/cc-workspace/MEMORY.md"})', {}),
        (2, "user", "ordinary prose of the mixed event", mixed_dirty),
        # A SECOND leak, further down the same session: it is what separates
        # "the informational branch no longer ends the scan" from "the scan
        # really runs to the end" -- the extra branch's own `break` stopped at
        # the first leak and would still hide this one.
        (4, "user", "a later ordinary turn", mixed_dirty),
    ]
    for path, with_excluded in ((reference, False), (candidate, True)):
        conn = sqlite3.connect(path)
        conn.executescript(_verify_schema(with_excluded))
        if with_excluded:
            conn.executescript(
                "CREATE TABLE snippets(id INTEGER PRIMARY KEY, message_id INTEGER, snippet_text TEXT);"
                "CREATE TABLE lex_docs(doc_id INTEGER PRIMARY KEY, content TEXT);"
                "CREATE TABLE message_chunks(chunk_id INTEGER PRIMARY KEY, message_id INTEGER);"
            )
        conn.execute("INSERT INTO agents(id, slug, name, kind) VALUES (1, 'claude_code', 'Claude', 'cli')")
        conn.execute(
            "INSERT INTO conversations(id, agent_id, source_id, external_id, title, source_path) "
            "VALUES (1, 1, 'local', 'b07-ext-1', 'b07 fixture session', '/src/b07-ext-1.jsonl')"
        )
        for idx, role, content, extra in rows:
            conn.execute(
                "INSERT INTO messages(id, conversation_id, idx, role, content, extra_bin) "
                "VALUES (?, 1, ?, ?, ?, ?)",
                [idx + 1, idx, role, content, msgpack.packb(extra, use_bin_type=True)],
            )
        if with_excluded:
            conn.execute(
                "INSERT INTO messages(id, conversation_id, idx, role, content, extra_bin, excluded) "
                "VALUES (4, 1, 3, 'tool_result', '', ?, jsonb(?))",
                [msgpack.packb(mixed_clean, use_bin_type=True), json.dumps(marker)],
            )
        else:
            conn.execute(
                "INSERT INTO messages(id, conversation_id, idx, role, content, extra_bin) "
                "VALUES (4, 1, 3, 'tool_result', ?, ?)",
                [body, msgpack.packb(mixed_dirty, use_bin_type=True)],
            )
        conn.commit()
        conn.close()

    manifest = [{
        "reason": "context_file_read",
        "source_id": "local",
        "agent_slug": "claude_code",
        "external_id": "b07-ext-1",
        "source_path": "/src/b07-ext-1.jsonl",
        "idx": 3,
        "sha256": body_sha,
        "evidence": "mirror",
        "event_key": mixed_uuid,
        "blocks": [1],
    }]
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle)
    return candidate, reference, manifest_path, mirror


def _verify_case(root, paths_cfg, expect_ok, want_substring, want_report=None, **flags):
    candidate, reference, manifest_path, mirror = _write_verify_fixture(root, **flags)
    report_path = os.path.join(root, "report.json")
    try:
        failures, report = _verify_once(
            candidate, manifest_path, reference, mirror, 50, 6, paths_cfg
        )
    except _NotV6 as not_v6:
        return False, f"unexpected _NotV6 for {not_v6}"
    details = "; ".join(f"{label}: {detail}" for label, detail in failures)
    if expect_ok:
        if failures:
            return False, f"expected a clean pass, got {details}"
        for key, want in (want_report or {}).items():
            if report.get(key) != want:
                return False, f"expected report[{key!r}] == {want!r}, got {report.get(key)!r}"
        if report["rebuild_ok"] != report["rebuild_sample"] or report["rebuild_sample"] != 1:
            return False, f"rebuild proof did not run: {report}"
        return True, ""
    if not failures:
        return False, "expected a FAIL, got none"
    if want_substring not in details:
        return False, f"expected {want_substring!r} in {details!r}"
    return True, ""


def verify_selftest_cases():
    return [
        ("V1 clean candidate verifies", True, ""),
        # N-fam4 (任务书 #131 T6-c): the sibling row here is a plain user row
        # the rules never cover, so a surviving copy of the body in it is
        # recorded, not failed. (Before N-fam4 this case asserted the
        # opposite; the judge was stronger than the rules.)
        ("V2 a retained body the rules do not cover is informational", True, "",
         {"body_retained_unexcludable": 1}),
        ("V3 a non-target block was cleared", False, "changed somewhere other than a redacted block"),
        ("V4 a non-manifest row was altered", False, "non-manifest body differs from reference"),
        # B07 (任务书 #131): the same placeholder at a path the exclusion does
        # not own is an over-clear, not a clean exclusion.
        ("V7 an over-cleared ordinary field is a failure", False, "redacted a field this exclusion does not own"),
        # B08 (任务书 #131): a multi-line body that is still verbatim in a
        # later row's extra -- escaped by `json.dumps`, so the old comparison
        # could not see it.
        ("V8 a multi-line body leaking in an extra is a failure", False, "still carries the body"),
        ("V8b a SHORT body leaking in an extra is a failure", False, "still carries the body"),
        # B09 (任务书 #131): a non-manifest row the candidate lost entirely --
        # the pre-fix loop only ever looked at rows the candidate still has.
        ("V9 a missing non-manifest row is a failure", False, "non-manifest row is missing"),
        # B10 (任务书 #131): the rebuild never read `raw.idx`, and no
        # per-entry comparison bound the marker's sha to the manifest's.
        ("V10 a wrong raw.idx is a failure", False, "raw.idx"),
        ("V10b a marker sha still bound to no manifest entry is a failure", False, "sha_binding_mismatch"),
        # N01 (任务书 #131): a project_read hit's `anchor.paths` holds DOCUMENT
        # names, not file paths -- judging them with the file predicate rejects
        # a legitimate hit.
        ("V11 a project_read document anchor passes", True, ""),
        # N02 (任务书 #131): an ordinary row sharing the excluded row's event
        # legitimately carries the same redacted target block.
        ("V12 a legit sibling redaction passes", True, ""),
        # N-fam2 (任务书 #131 追加): zero diff is not a failure when no copy of
        # the body was ever in the extra (the corpus' compact shape).
        ("V13 an unchanged extra with no body anywhere passes", True, ""),
        # N-R7arr (任务书 #131 T6-c): the ARRAY form of a top-level
        # `toolUseResult` is a legitimate clearing target exactly when the
        # element's `text` IS the excluded body's copy (B04's ownership proof,
        # applied per element).
        ("V14 an owned array toolUseResult element passes", True, ""),
        # ... and an element carrying some OTHER body is an over-clear, even
        # though it wears the same redacted placeholder shape.
        ("V15 a foreign array toolUseResult element is a failure", False, "redacted a field this exclusion does not own"),
        # N-fam4's other half: a retained body in a row the rules WOULD have
        # excluded is still a real leak. (Case order and the `flags` mapping in
        # `_run_verify_selftest` are index-coupled -- append, do not insert.)
        ("V16 a retained body in an excludable row is a failure", False, "retained_excludable"),
        # N-fam5 (任务书 #131 T6-c): an exclusion the candidate made beyond the
        # frozen manifest is recorded, not failed -- and only when its marker
        # and its extra differences hold up.
        ("V17 an exclusion beyond the manifest is informational", True, "",
         {"candidate_excluded_beyond_manifest": 1}),
        ("V18 an exclusion beyond the manifest with a bad marker is a failure", False,
         "beyond_manifest_invalid"),
        # R9-B03 (任务书 #132): `toolUseResult`'s array form is ONE projected
        # value. When its elements are FRAGMENTS of the excluded body the join
        # is that body's copy, so every element is a legitimate target -- the
        # per-element proof alone saw neither fragment as the body and called
        # the exclusion an over-clear.
        ("V19 a fragmented array toolUseResult is one owned body's copy", True, ""),
        # ...and the boundary: fragments joining to a DIFFERENT body are not
        # this exclusion's copy, so clearing them stays an over-clear.
        ("V20 a foreign fragmented array toolUseResult is a failure", False,
         "redacted a field this exclusion does not own"),
        # R9-B04 (任务书 #132): going beyond the manifest is a CLAIM, not an
        # exemption. A candidate that cleared an ordinary message and appended a
        # well-shaped marker passed with `failures=0` whether it left the body
        # verbatim in an untouched extra field...
        ("V21 a beyond-manifest exclusion that leaves the body in its extra is a failure", False,
         "still reconstructible from extra_bin"),
        # ...or over-cleared an ordinary field into the marker's own placeholder.
        ("V22 a beyond-manifest exclusion that over-clears an ordinary field is a failure", False,
         "does not own"),
        # ...and the two identity halves the branch previously never checked:
        # a reason the probe's own decide() does not return for that block,
        ("V23 a beyond-manifest marker whose reason disagrees with decide is a failure", False,
         "reason_disagrees_with_decide"),
        # ...and a sha that is not the reference body's at all.
        ("V24 a beyond-manifest marker whose sha is not the reference body is a failure", False,
         "sha_is_not_the_reference_body"),
        # R9-B05 (任务书 #132): a candidate-only row carrying an exclusion
        # marker is held to the exclusion's own invariants -- `excluded` next
        # to a surviving body is a contradiction the reference's absence
        # cannot excuse.
        ("V25 a well-formed candidate-only exclusion passes", True, "",
         {"candidate_only_excluded": 1, "candidate_only_unjudgeable": 0}),
        ("V26 a candidate-only excluded row that still carries its body is a failure", False,
         "candidate_only_bad_marker"),
        ("V27 a candidate-only excluded row that leaves the body in its extra is a failure", False,
         "body_still_in_extra"),
        # ...and when the raw-mirror blob is not on disk the half that needs it
        # is RECORDED, never silently passed.
        ("V28 a candidate-only exclusion with no mirror blob is recorded as unjudgeable", True, "",
         {"candidate_only_unjudgeable": 1}),
        # R9-B06 (任务书 #132) via the claude side: the extra's visible text is
        # the `\n` join of several blocks, so leaf-by-leaf search misses it and
        # only projecting the extra reconstructs the body.
        ("V29 a claude body fragmented across extra text blocks is a failure", False,
         "still present in extra_bin"),
        # R9-B08 (任务书 #132): two rows differing only in `source_id` used to
        # fold to one dict key, so the row the candidate dropped was invisible
        # -- each side showed one row, and they matched.
        ("V30 a row dropped from one source is a missing non-manifest row", False,
         "non-manifest row is missing"),
        # R9-B09 (任务书 #132): `event_key: null` used to switch the rebuild's
        # identity check off, so a marker naming no event rebuilt "successfully".
        ("V31 a raw marker whose event_key is null is a failure", False,
         "rebuild_raw_invalid"),
    ]


def _run_verify_selftest(paths_cfg):
    passed = 0
    total = 0
    if not _verify_jsonb_available():
        print(
            f"FAIL verify family needs SQLite >= "
            f"{'.'.join(map(str, VERIFY_JSONB_MIN))} (JSONB); this interpreter has "
            f"{sqlite3.sqlite_version}. Run `python3.12 scripts/oracle/exclusion_probe.py "
            f"--selftest`."
        )
        return 0, len(verify_selftest_cases()) + 1
    for index, case in enumerate(verify_selftest_cases()):
        total += 1
        name, expect_ok, want_substring = case[0], case[1], case[2]
        want_report = case[3] if len(case) > 3 else None
        flags = {
            1: {"sibling_leak": True},
            2: {"non_target_cleared": True},
            3: {"non_manifest_altered": True},
            4: {"overclear_ordinary": True},
            5: {"leak_multiline_body": True},
            6: {"short_body": True},
            7: {"missing_nonmanifest_row": True},
            8: {"wrong_raw_idx": True},
            9: {"wrong_marker_sha": True},
            10: {"project_read_anchor": True},
            11: {"legit_sibling_redaction": True},
            12: {"compact_extra_no_body": True},
            13: {"array_tool_use_result": "owned"},
            14: {"array_tool_use_result": "foreign"},
            15: {"excludable_sibling_leak": True},
            16: {"beyond_manifest_excluded": "ok"},
            17: {"beyond_manifest_excluded": "bad"},
            18: {"fragmented_array_tool_use_result": True},
            19: {"foreign_array_tool_use_result_cleared": True},
            20: {"beyond_manifest_excluded": "body_retained"},
            21: {"beyond_manifest_excluded": "overclear"},
            22: {"beyond_manifest_excluded": "reason_mismatch"},
            23: {"beyond_manifest_excluded": "wrong_sha"},
            24: {"candidate_only_excluded_row": "ok"},
            25: {"candidate_only_excluded_row": "body_retained"},
            26: {"candidate_only_excluded_row": "extra_leak"},
            27: {"candidate_only_excluded_row": "unverifiable"},
            28: {"fragmented_extra_text_blocks": True},
            29: {"duplicate_source_row": True},
            30: {"null_raw_event_key": True},
        }.get(index, {})
        with tempfile.TemporaryDirectory() as root:
            ok, why = _verify_case(root, paths_cfg, expect_ok, want_substring, want_report, **flags)
        if ok:
            passed += 1
            print(f"ok   {name}")
        else:
            print(f"FAIL {name}: {why}")

    total += 1
    with tempfile.TemporaryDirectory() as root:
        candidate, reference, manifest_path, mirror = _write_verify_fixture(root)
        # A pre-v6 candidate (no `excluded` column) must be a loud precondition
        # error, never a pass with nothing to check.
        try:
            _verify_once(reference, manifest_path, reference, mirror, 50, 6, paths_cfg)
            print("FAIL verify rejects a non-v6 candidate: no error raised")
        except _NotV6:
            passed += 1
            print("ok   V5 a non-v6 candidate is refused")

    # B09 (任务书 #131): the report's own count must come from the REFERENCE
    # side's rows -- walking the candidate alone reported
    # `non_manifest_rows_checked=0` for a candidate that had dropped one.
    total += 1
    with tempfile.TemporaryDirectory() as root:
        candidate, reference, manifest_path, mirror = _write_verify_fixture(root, missing_nonmanifest_row=True)
        _failures, report = _verify_once(candidate, manifest_path, reference, mirror, 50, 6, paths_cfg)
        if report["non_manifest_rows_checked"] == 1:
            passed += 1
            print("ok   V9b non_manifest_rows_checked counts the reference side")
        else:
            print(
                "FAIL V9b non_manifest_rows_checked counts the reference side: "
                f"got {report['non_manifest_rows_checked']!r}, want 1"
            )

    # N10 (任务书 #131): `logical_source` counts sessions of a connector the
    # plan models as `SourceKind::Logical` (opencode). That counting sat AFTER
    # the `no_manifest`/`connector is None` branches, both of which `continue`
    # -- so the one connector the column exists for could never be counted.
    total += 1
    with tempfile.TemporaryDirectory() as root:
        db = _write_opencode_probe_db(root)
        mirror = os.path.join(root, "empty-mirror")
        os.makedirs(mirror)
        _manifest, probe_stats = run_probe(
            db, mirror, paths_cfg, os.path.join(root, "out.json"), os.path.join(root, "report.md")
        )
        got = probe_stats["coverage"]["opencode"]["logical_source"]
        if got == 1:
            passed += 1
            print("ok   N10 logical_source counts an opencode session")
        else:
            print(f"FAIL N10 logical_source counts an opencode session: got {got!r}, want 1")

    # N-fam2 (任务书 #131 追加): a row only the candidate has is recorded, not
    # failed -- the candidate is a newer library.
    total += 1
    with tempfile.TemporaryDirectory() as root:
        candidate, reference, manifest_path, mirror = _write_verify_fixture(root, candidate_only_row=True)
        failures, report = _verify_once(candidate, manifest_path, reference, mirror, 50, 6, paths_cfg)
        details = " | ".join(detail for _label, detail in failures)
        if report.get("candidate_only_rows") == 1 and not failures:
            passed += 1
            print("ok   N-fam2 a candidate-only row is recorded, not failed")
        else:
            print(
                f"FAIL N-fam2 a candidate-only row is recorded, not failed: "
                f"candidate_only_rows={report.get('candidate_only_rows')!r} failures={details!r}"
            )

    # N-fam2, the other half: the zero-diff compact row must also be counted.
    total += 1
    with tempfile.TemporaryDirectory() as root:
        candidate, reference, manifest_path, mirror = _write_verify_fixture(root, compact_extra_no_body=True)
        failures, report = _verify_once(candidate, manifest_path, reference, mirror, 50, 6, paths_cfg)
        details = " | ".join(detail for _label, detail in failures)
        if report.get("extra_unchanged_no_body") == 1 and not failures:
            passed += 1
            print("ok   N-fam2 an unchanged extra with no body is counted, not failed")
        else:
            print(
                f"FAIL N-fam2 an unchanged extra with no body is counted, not failed: "
                f"extra_unchanged_no_body={report.get('extra_unchanged_no_body')!r} failures={details!r}"
            )

    # N-fam3 (任务书 #131 追加): the report must carry EVERY failure, not just
    # the first twenty and not just the family totals.
    total += 1
    with tempfile.TemporaryDirectory() as root:
        candidate, reference, manifest_path, mirror = _write_verify_fixture(root, non_target_cleared=True)
        failures, report = _verify_once(candidate, manifest_path, reference, mirror, 50, 6, paths_cfg)
        listed = report.get("failure_list") or []
        if len(listed) == report["failures"] and len(listed) == len(failures) and listed and listed[0][0] == "extra_unexpected_change":
            passed += 1
            print("ok   N-fam3 the report carries every failure")
        else:
            print(
                f"FAIL N-fam3 the report carries every failure: failures={report['failures']!r} "
                f"listed={len(listed)} sample={listed[:1]!r}"
            )

    # N-fam (任务书 #131, 控制面追加): a run that reports tens of thousands of
    # failures must be reducible to families, not just to a total.
    total += 1
    with tempfile.TemporaryDirectory() as root:
        candidate, reference, manifest_path, mirror = _write_verify_fixture(root, non_target_cleared=True)
        failures, report = _verify_once(candidate, manifest_path, reference, mirror, 50, 6, paths_cfg)
        families = report.get("failure_families") or {}
        details = " | ".join(detail for _label, detail in failures)
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            rc = run_verify(
                candidate, manifest_path, reference, mirror, 50, 6,
                os.path.join(root, "report.json"), paths_cfg,
            )
        printed = stream.getvalue()
        if (
            families.get("extra_unexpected_change") == 1
            and "changed somewhere other than" in details
            and rc == 1
            and "failure families:" in printed
            and "extra_unexpected_change=1" in printed
        ):
            passed += 1
            print("ok   N-fam failures are counted by family (report + stdout)")
        else:
            print(
                f"FAIL N-fam failures are counted by family (report + stdout): "
                f"families={families!r} rc={rc!r} printed={printed!r} details={details!r}"
            )

    # N03 (任务书 #131): `events_from_blob` falls back to the event's PHYSICAL
    # 1-based line number (`line:N`) when the event carries no id of its own.
    # The probe's builders recorded `None`, so a marker written against such an
    # event could never be found on a rebuild (`reparse found 0 block(s)`).
    # Blank lines count: the identity is the physical line, not an index into
    # the events that survived parsing.
    for name, events, want_key, builder in (
        (
            "N03 codex event without payload.id falls back to line:N",
            [
                {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "x", "output": "the full result"}},
            ],
            "line:2",
            build_candidates_codex,
        ),
        (
            "N03b claude event without uuid falls back to line:N",
            [
                {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": "hello"}]}},
            ],
            "line:2",
            build_candidates_claude_code,
        ),
    ):
        total += 1
        with tempfile.TemporaryDirectory() as root:
            blob = os.path.join(root, "line_fallback.jsonl")
            with open(blob, "w", encoding="utf-8") as handle:
                handle.write("\n")  # physical line 1 is blank
                for event in events:
                    handle.write(json.dumps(event) + "\n")
            keys = [cand.event_key for cand in builder(load_blob_events(blob))]
        if keys == [want_key]:
            passed += 1
            print(f"ok   {name}")
        else:
            print(f"FAIL {name}: got {keys!r}, want {[want_key]!r}")

    # B01 (任务书 #131): an output that names an input must be refused BEFORE
    # anything is written. Pre-fix, `run_verify` verified the candidate and
    # then unconditionally `open(report_path, "w")` -- with `--report` naming
    # the candidate library itself, the verified database was truncated into
    # JSON and the exit code still said "verified".
    total += 1
    with tempfile.TemporaryDirectory() as root:
        candidate, reference, manifest_path, mirror = _write_verify_fixture(root)
        before = open(candidate, "rb").read()
        rc = run_verify(candidate, manifest_path, reference, mirror, 50, 6, candidate, paths_cfg)
        after = open(candidate, "rb").read()
        if rc == 0:
            print("FAIL V6 an output that names an input is refused: run_verify exited 0")
        elif after != before:
            print("FAIL V6 an output that names an input is refused: the candidate library was modified")
        else:
            passed += 1
            print("ok   V6 an output that names an input is refused (and nothing was written)")

    # B01, the probe's own entry point: `--out` naming the database the probe
    # is reading is the same collision on the other command (there the
    # manifest write, not a report, does the truncating).
    total += 1
    with tempfile.TemporaryDirectory() as root:
        candidate, _reference, _manifest_path, mirror = _write_verify_fixture(root)
        before = open(candidate, "rb").read()
        rc = run_probe(candidate, mirror, paths_cfg, candidate, os.path.join(root, "report.md"))
        after = open(candidate, "rb").read()
        if rc != 2:
            print(f"FAIL V6b probe refuses an --out that names its --db: run_probe returned {rc!r}")
        elif after != before:
            print("FAIL V6b probe refuses an --out that names its --db: the database was rewritten")
        else:
            passed += 1
            print("ok   V6b probe refuses an --out that names its --db (and nothing was written)")

    # B01 regression guard: the refused path returns an int, but the NORMAL
    # path returns `(manifest, stats)` -- a caller that fed that tuple to
    # `sys.exit` would print it and exit 1, turning every healthy probe run
    # into a failure.
    total += 1
    with tempfile.TemporaryDirectory() as root:
        candidate, _reference, _manifest_path, mirror = _write_verify_fixture(root)
        manifest_out = os.path.join(root, "manifest.json")
        try:
            main(["--db", candidate, "--mirror", mirror, "--out", manifest_out,
                  "--report", os.path.join(root, "report.md")])
            code = 0
        except SystemExit as exit_:
            code = exit_.code
        if code == 0 and os.path.exists(manifest_out):
            passed += 1
            print("ok   V6c a normal probe run still exits 0 and writes its manifest")
        else:
            print(f"FAIL V6c a normal probe run still exits 0 and writes its manifest (code={code!r})")

    # R9-B03 (任务书 #132): the ownership bodies are read off the reference
    # EVENT, projected exactly as the connector projects it. The string-only
    # reading dropped an array-form body entirely, which is what left the
    # sibling path (no `ref_row` of its own to offer) with nothing to prove
    # ownership against.
    total += 1
    array_event = {
        "uuid": "u2",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1",
             "content": [{"type": "text", "text": "secret A"}]},
        ]},
    }
    got = _owned_bodies(array_event, [0], None)
    if got == ["secret A"]:
        passed += 1
        print("ok   B03 an array-form content block projects to its own body")
    else:
        print(f"FAIL B03 an array-form content block projects to its own body: got {got!r}, want ['secret A']")

    total += 1
    got = _owned_bodies(array_event, [0], "the row's own body")
    if got == ["the row's own body", "secret A"]:
        passed += 1
        print("ok   B03 the row's own body and the event's array body are both owned")
    else:
        print(
            "FAIL B03 the row's own body and the event's array body are both owned: "
            f"got {got!r}"
        )

    # R9-B06 (任务书 #132): a body the connector carries as SEVERAL blocks is
    # still a body. The leaf scan above sees only fragments; projecting the
    # extra through the probe's own builder reconstructs the whole thing.
    total += 1
    with tempfile.TemporaryDirectory() as root:
        candidate, reference, manifest_path, mirror = _write_codex_verify_fixture(root)
        failures, report = _verify_once(candidate, manifest_path, reference, mirror, 50, 6, paths_cfg)
        details = " | ".join(detail for _label, detail in failures)
        if any("still present in extra_bin" in detail for _label, detail in failures):
            passed += 1
            print("ok   B06 a body fragmented across several extra blocks is a failure")
        else:
            print(
                "FAIL B06 a body fragmented across several extra blocks is a failure: "
                f"failures={report.get('failures')!r} extra_unchanged_no_body="
                f"{report.get('extra_unchanged_no_body')!r} details={details!r}"
            )

    # R9-B07 (任务书 #132): the session scan must run to the END of the
    # session. A row whose copy the rules do not cover is informational, and
    # stopping there hid the leak sitting in a later row's extra.
    total += 1
    with tempfile.TemporaryDirectory() as root:
        candidate, reference, manifest_path, mirror = _write_b07_fixture(root)
        failures, report = _verify_once(candidate, manifest_path, reference, mirror, 50, 6, paths_cfg)
        details = " | ".join(detail for _label, detail in failures)
        leaked = sorted(
            sib
            for label, detail in failures
            for sib in [detail.split("idx=")[1].split(" ")[0]] if "still carries the body in extra_bin" in detail
        )
        if leaked == ["2", "4"]:
            passed += 1
            print("ok   B07 the session scan runs to the end past an informational hit and past a leak")
        else:
            print(
                "FAIL B07 the session scan runs to the end past an informational hit and past a leak: "
                f"leaked rows={leaked!r}, want ['2', '4']; failures={report.get('failures')!r} "
                f"body_retained_unexcludable={report.get('body_retained_unexcludable')!r} "
                f"details={details!r}"
            )

    print(f"selftest/verify: {passed}/{total}")
    return passed, total


def codex_projection_selftest_cases():
    """N-codexkey (任务书 #131 T6-c): the codex candidate projection must be
    `codex_events_from_blob`'s, event for event.

    The fixtures are the Rust side's own: case A is
    `events_from_blob_codex_developer_dropped_and_reasoning_sequence_matches_real_reparse_positive`'s
    six lines verbatim (its `real_count == 5` is asserted against the REAL
    connector), so the expected sequence below is that test's count and keys in
    order. B and C pin the two layers the pre-fix builder dropped whole: the
    `event_msg` outer type (Rust emits user_message/agent_reasoning/tool_call,
    drops agent_message, emits nothing for token_count) and the
    `response_item` arms the old role filter rejected (a missing payload.type
    taking the `message` arm, `agent_message`, and a `reasoning` kept alive by
    `encrypted_content` alone). A blank line is present in B to pin the
    PHYSICAL line numbering the `line:<n>` fallback uses.
    """
    a = [
        '{"type":"response_item","timestamp":"2026-01-01T00:00:00Z","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"You are Codex, a coding agent."}]}}',
        '{"type":"response_item","timestamp":"2026-01-01T00:00:01Z","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"list files"}]}}',
        '{"type":"response_item","timestamp":"2026-01-01T00:00:02Z","payload":{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"I should run ls."}]}}',
        '{"type":"response_item","timestamp":"2026-01-01T00:00:03Z","payload":{"type":"function_call","id":"fc_1","name":"exec_command","arguments":"{\\"cmd\\":\\"ls\\"}","call_id":"call_1"}}',
        '{"type":"response_item","timestamp":"2026-01-01T00:00:04Z","payload":{"type":"function_call_output","call_id":"call_1","output":"README.md\\n"}}',
        '{"type":"response_item","timestamp":"2026-01-01T00:00:05Z","payload":{"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"Found README.md."}]}}',
    ]
    b = [
        '{"type":"event_msg","payload":{"type":"token_count","info":{}}}',
        '{"type":"event_msg","payload":{"type":"user_message","message":"hello there"}}',
        '{"type":"event_msg","payload":{"type":"agent_message","message":"duplicate of the response_item version"}}',
        '',
        '{"type":"event_msg","payload":{"type":"agent_reasoning","text":"weighing options"}}',
        '{"type":"event_msg","payload":{"type":"tool_call","id":"tc_9","name":"exec_command","input":{"cmd":"ls"}}}',
        '{"type":"event_msg","payload":{"type":"user_message","message":"   "}}',
    ]
    c = [
        '{"type":"response_item","payload":{"type":"agent_message","id":"am_1","content":[{"type":"output_text","text":"hi"}]}}',
        '{"type":"response_item","payload":{"type":"message","id":"m_bare","role":"user","content":["a bare string content block"]}}',
        '{"type":"response_item","payload":{"type":"message","id":"m_empty","role":"user","content":[{"type":"input_text","text":""}]}}',
        '{"type":"response_item","payload":{"type":"reasoning","id":"rs_enc","summary":[{"type":"summary_text","text":""}],"encrypted_content":"opaque"}}',
        '{"type":"response_item","payload":{"role":"assistant","content":"a message with no payload.type"}}',
        '{"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"system prompt"}]}}',
    ]
    return [
        ("A developer dropped, reasoning/function_call/function_call_output kept",
         a, [("user", "line:2"), ("reasoning", "rs_1"), ("tool_call", "fc_1"),
             ("tool_result", "line:5"), ("assistant", "msg_1")]),
        ("B the event_msg layer projects per Rust, blank line counted physically",
         b, [("user", "line:2"), ("reasoning", "line:5"), ("tool_call", "tc_9")]),
        ("C response_item arms the old role filter rejected",
         c, [("user", "am_1"), ("user", "m_bare"), ("reasoning", "rs_enc"),
             ("assistant", "line:5")]),
    ]


def _run_codex_projection_selftest(paths_cfg):
    passed = 0
    cases = codex_projection_selftest_cases()
    for name, lines, want in cases:
        with tempfile.TemporaryDirectory() as root:
            blob = os.path.join(root, "rollout-projection.jsonl")
            with io.open(blob, "w", encoding="utf-8") as handle:
                for line in lines:
                    handle.write(line + "\n")
            got = [(c.role, c.event_key) for c in build_candidates_codex(load_blob_events(blob))]
        ok = got == want
        print(f"{'ok  ' if ok else 'FAIL'} N-codexkey {name} (want={want} got={got})")
        if ok:
            passed += 1
    print(f"selftest/codex_projection: {passed}/{len(cases)}")
    return passed, len(cases)


def run_selftest(paths_cfg) -> bool:
    passed = total = 0
    for runner in (_run_decide_selftest, _run_content_selftest,
                   _run_pairing_selftest, _run_perf_selftest,
                   _run_report_selftest, _run_verify_selftest,
                   _run_codex_projection_selftest):
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


# N03 (任务书 #131): the 1-based PHYSICAL line number each parsed event came
# from, stashed on the parsed dict so the builders can mint the same
# `line:<n>` identity `events_from_blob` mints when an event carries no id.
_PROBE_LINE_KEY = "__cass_probe_line__"


def load_blob_events(blob_path: str):
    events = []
    with open(blob_path, "rb") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            event = json.loads(line.decode("utf-8"))
            if isinstance(event, dict):
                event[_PROBE_LINE_KEY] = line_no
            events.append(event)
    return events


def line_identity(event):
    """`line:<physical line>` for an event with no id of its own, else `None`."""
    line_no = event.get(_PROBE_LINE_KEY) if isinstance(event, dict) else None
    return f"line:{line_no}" if isinstance(line_no, int) else None


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


def _resolve_no_id_evidence(raw_candidates, blob_pairing, content, stats):
    """R2-N13: locate the mirror evidence for a DB `tool_result` row whose
    paired call carries no `tool_call_id`.

    The only admissible anchor left is the body itself: the mirror event must
    also be a no-id `tool_result` whose projected+redacted text IS this row's
    content (the same gate every other row goes through), and it must be the
    ONLY such event. Returns `(call, evidence)` or `(None, None);` the caller
    treats the latter as "not verifiable"."""
    matches = []
    for pos, cand in enumerate(raw_candidates):
        if cand.role != "tool_result" or cand.tool_call_id:
            continue
        if not content_body_ok(content, cand.text):
            continue
        matches.append((pos, cand))
    if len(matches) != 1:
        stats["pairing_fail"]["no_id_evidence_not_unique"] += 1
        return None, None
    pos, evidence = matches[0]
    call = blob_pairing.paired_call_for(pos)
    if call is None or not call.tool_name or call.args is None:
        stats["pairing_fail"]["no_id_call_missing_structure"] += 1
        return None, None
    return call, evidence


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
    # The blob's own candidates, paired by the SAME rule, for the no-id path
    # below.
    blob_pairing = PairingContext(raw_candidates)

    agent_slug = conv["agent_slug"]
    manifest_entries = []

    for i, (idx, role, content_sha, content, _tid) in enumerate(db_rows_full):
        if role == "tool_result":
            paired = pairing.paired_call_for(i)
            if paired is None:
                # B03 (任务书 #131): an id carried by two tool_calls now
                # resolves to no pairing at all, so such a row never reaches
                # the mirror-side `calls_by_id` ambiguity check below. Count it
                # here instead of losing the statistic (T1b reported 416 such
                # rows); everything else keeps meaning "no unpaired candidate".
                if _tid and _tid in pairing.ambiguous_ids:
                    stats["pairing_fail"]["ambiguous_call_id"] += 1
                else:
                    stats["pairing_fail"]["no_unpaired_candidate"] += 1
                continue
            call_id = paired.tool_call_id
            if not call_id:
                # R2-N13: the DB turn's unique-unpaired rule already resolved
                # this row (that is the `PairingContext` rule `decide` uses
                # too) -- the call just carries no id, so `calls_by_id` cannot
                # locate its structural facts. Rather than `continue`, anchor
                # on the mirror event that has no id either and whose
                # projected+redacted body IS this row's content; 0 or >=2
                # candidates is not verifiable and stays out (宁漏勿误). This
                # deliberately does NOT reintroduce whole-session positional
                # alignment, which T1b.2 retired.
                call, evidence = _resolve_no_id_evidence(
                    raw_candidates, blob_pairing, content, stats
                )
                if call is None:
                    continue
                decision = decide_r1_r2_for_call(call, agent_slug, paths_cfg)
                if decision is None:
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
                stats["hits_by_reason_agent"][(decision["reason"], agent_slug)] += 1
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
            stats["hits_by_reason_agent"][(decision["reason"], agent_slug)] += 1

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
            stats["hits_by_reason_agent"][("codex_host_shell", agent_slug)] += 1
            stats["anchor3_opener"][opener] += 1

    return manifest_entries


# ---------------------------------------------------------------------------
# Full-corpus driver.
# ---------------------------------------------------------------------------
BASH_HEAD_TOKEN_RE = re.compile(r"^\s*(\S+)")


def bash_bucket_of(command):
    """Classify one Bash `command` for the report's sub-set tallies.

    Returns `("in", None)`, `("out", <head token>)`, `("compound",
    <head token>)`, or None when the string is not a classified read
    attempt at all. Extracted verbatim from the `run_probe` loop so the
    classification can be driven from `--selftest` instead of only being
    observable through a full corpus run."""
    if bash_readonly_paths(command) is not None:
        return ("in", None)
    head = BASH_HEAD_TOKEN_RE.match(command)
    if _COMPOUND_SHELL_CHARS_RE.search(command):
        # R2-e: a compound form is not one of the five literal shapes, so it
        # is not in the subset -- but it also must not be filed as "a single
        # command whose head token is outside the subset", because that is a
        # different reason. Its own bucket (R2-N15).
        return ("compound", head.group(1)) if head else None
    return ("out", head.group(1)) if head else None


def _memory_basenames(paths_cfg) -> frozenset:
    """Every basename predicate P can match, i.e. what "记忆特征串" means for
    the `idx≠0` candidate tally (spec §60)."""
    return frozenset(
        paths_cfg["memory_files"]
        + paths_cfg["injection_only_files"]
        + paths_cfg["workspace_scoped_files"]
    )


def _new_stats():
    return {
        "hits_by_reason": Counter(),
        # R1-N20/R2-N15: the report used to state the cass_recall split in
        # prose. Same counter, keyed by connector, so the text can be derived.
        "hits_by_reason_agent": Counter(),
        "anchor3_opener": Counter(),
        "content_mismatch_messages": 0,
        "unverifiable_sessions_by_reason": Counter(),
        "unverifiable_messages": 0,
        "bash_subset_in": 0,
        "bash_subset_out": Counter(),
        "bash_subset_out_compound": Counter(),
        "pairing_fail": Counter(),
        "deep_doc_hits": [],
        "deep_doc_hits_total": 0,
        "idx_ne_0_memory_candidates": [],
        "idx_ne_0_memory_candidates_total": 0,
        "idx_ne_0_anchor3_also": 0,
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


def run_probe(db_path, mirror_root, paths_cfg, out_path, report_path, limit=None):
    # B01 (任务书 #131): `--out`/`--report` naming the database being read (or
    # each other) used to be caught only by the opening read -- the manifest
    # and report writes come last and truncate whatever they name. Refuse
    # before opening anything.
    collision = report_output_collisions(
        "probe",
        [
            ("--db", db_path),
            ("--mirror", mirror_root),
            *[("--db sidecar", path) for path in sqlite_sidecar_paths(db_path)],
        ],
        [("--out", out_path), ("--report", report_path)],
    )
    if collision is not None:
        print(collision, file=sys.stderr)
        return 2
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
    stats = _new_stats()

    for conv in convs:
        conv_d = dict(conv)
        agent_slug = conv_d["agent_slug"]
        cov = stats["coverage"][agent_slug]
        cov["sessions"] += 1
        # N10 (任务书 #131): `logical_source` is a property of the SESSION's
        # connector, so it must be counted here -- before the `no_manifest` /
        # `no_blob` / `parse_error` / `connector is None` branches `continue`,
        # which is exactly the state an opencode session is in (it has no
        # manifest and no candidate builder). Counting it at the end left the
        # one connector the column exists for permanently at 0.
        if agent_slug.split("/")[0] in LOGICAL_SOURCE_CONNECTORS:
            cov["logical_source"] += 1

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

        # R1-N20/R2-N15: codex `user` rows at `idx != 0` whose body carries a
        # memory feature string are the known out-of-anchor class (spec §60:
        # "含记忆特征串但 `idx≠0` 的 40 条 codex user 行"). `anchor3_shell_opener`
        # is additionally counted for the same rows, because that is exactly
        # the evidence for "另立锚点 or not" the spec defers.
        if agent_slug == "codex":
            memory_basenames = _memory_basenames(paths_cfg)
            for (row_idx, row_role, _row_sha, row_content, _row_tid) in db_rows_full:
                if row_role != "user" or row_idx == 0:
                    continue
                if not any(name in row_content for name in memory_basenames):
                    continue
                stats["idx_ne_0_memory_candidates_total"] += 1
                if anchor3_shell_opener(row_content) is not None:
                    stats["idx_ne_0_anchor3_also"] += 1
                if len(stats["idx_ne_0_memory_candidates"]) < 20:
                    stats["idx_ne_0_memory_candidates"].append(f"{conv_d['external_id']} idx={row_idx}")

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
                bucket = bash_bucket_of(command_val)
                if bucket is not None:
                    kind, key = bucket
                    if kind == "in":
                        stats["bash_subset_in"] += 1
                    elif kind == "compound":
                        # R2-N15: compound forms (R2-e) used to fall out of
                        # BOTH tallies, so the report could not show how much
                        # Bash traffic the subset was rejecting for being
                        # compound. Own bucket, kept OUT of `bash_subset_out`
                        # so the v1 head-token buckets stay comparable.
                        stats["bash_subset_out_compound"][key] += 1
                    else:
                        stats["bash_subset_out"][key] += 1
            for p in candidate_paths:
                base = _normalize_path(p).rsplit("/", 1)[-1]
                paths_cfg_memory = set(paths_cfg["memory_files"]) | set(paths_cfg["workspace_scoped_files"])
                if base in paths_cfg_memory and not predicate_p(p, paths_cfg):
                    # R1-N20: the COUNT is the whole population; only the
                    # sample list is capped, and the report says so.
                    stats["deep_doc_hits_total"] += 1
                    if len(stats["deep_doc_hits"]) < 20:
                        stats["deep_doc_hits"].append(p)

    manifest.sort(key=lambda e: (e["source_id"], e["agent_slug"], e["external_id"] or e["source_path"], e["idx"]))

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")

    write_report(report_path, stats, manifest, len(convs))
    return manifest, stats


# spec §2.1's frozen reference counts. Constants on purpose: this is the SPEC
# BASELINE the report is compared against, NOT a statement about this run.
# (The old report also hard-coded "命中 25 条，全部来自 claude_code；codex 侧
# 0 条" as though it were a measurement -- that is gone; every "this run"
# number below is read from `stats`.)
REFERENCE_COUNTS = {"cass_recall": 26, "context_file_read": 851, "codex_host_shell": 1665}


def write_report(report_path, stats, manifest, session_count):
    lines = []
    lines.append("# T1b 结构探针报告 (`exclusion_probe.py`)\n")
    lines.append(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S %z')}\n")
    lines.append(f"处理会话数: {session_count}\n")

    lines.append("\n## ① 三锚点各命中数（「命中」= 本次运行值，来自 stats；「参考值」= spec §2.1 冻结基线，不是本次结论）\n")
    for reason, ref in REFERENCE_COUNTS.items():
        got = stats["hits_by_reason"].get(reason, 0)
        lines.append(f"- `{reason}`: {got}（参考值 {ref}，差异 {got - ref:+d}）\n")

    lines.append("\n## ② 锚点 3 按 opener 分布\n")
    for opener, n in stats["anchor3_opener"].most_common():
        lines.append(f"- `{opener}`: {n}\n")

    lines.append("\n## ③ Bash 只读子集 内/外计数\n")
    lines.append(f"- 子集内（命中五形态之一）: {stats['bash_subset_in']}\n")
    out_total = sum(stats["bash_subset_out"].values())
    lines.append(
        f"- 子集外（按首 token 分桶；此处只列前 10 个 token，共 {out_total} 条 / "
        f"{len(stats['bash_subset_out'])} 个不同首 token）:\n"
    )
    for tok, n in stats["bash_subset_out"].most_common(10):
        lines.append(f"  - `{tok}`: {n}\n")
    compound = stats["bash_subset_out_compound"]
    compound_total = sum(compound.values())
    lines.append(
        f"- 复合形态（R2-e 拒绝：含 `|`/`&`/`;`/`<`/`>`/反引号/`*`/`?`/`[`/`]`/换行/`$` 之一；"
        f"既不判入子集，也不计入上方「子集外」分桶）: {compound_total} 条 / {len(compound)} 个不同首 token\n"
    )
    for tok, n in compound.most_common(10):
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
    deep_total = stats["deep_doc_hits_total"]
    lines.append(f"命中数: {deep_total}（全量计数）\n")
    lines.append(f"列表为前 {len(stats['deep_doc_hits'])} 条，共 {deep_total} 条：\n")
    for p in stats["deep_doc_hits"]:
        lines.append(f"- `{p}`\n")
    nl_count = stats["bash_subset_out"].get("nl", 0)
    lines.append(
        f"\n**`nl` 单列披露**（advisor 2026-09-07 指出；v4.4 Ivan 已裁并入 R2 六形态，T2a 落地，任务书 #113）："
        f"`nl` 已在只读子集内（见 docs/excluded-rules.md R2-i），本次运行落在「子集外」分桶里的 `nl` 还有 {nl_count} 条 —— "
        "读 `nl` 的完整体量要把上方「子集内」计数一起看。\n"
    )

    lines.append("\n## ⑥ codex 全部 tool_name 频次（advisor 2026-09-07：核对有无可疑的 cass-mcp 调用名）\n")
    recall_by_agent = "、".join(
        f"{slug} {n}"
        for (reason, slug), n in sorted(
            (item for item in stats["hits_by_reason_agent"].items() if item[0][0] == "cass_recall"),
            key=lambda item: item[0][1],
        )
    )
    lines.append(
        f"- `cass_recall`: 合计 {stats['hits_by_reason'].get('cass_recall', 0)}；"
        f"按 agent_slug：{recall_by_agent or '（无）'}\n"
    )
    codex_freq = stats["tool_name_freq"].get("codex", Counter())
    lines.append(
        f"以下是 codex 全部 tool_call 候选（不限于配对成功的）按 `tool_name` 的前 20 频次"
        f"（共 {len(codex_freq)} 个不同 `tool_name`），供核对 codex 是否真的从不调用 cass-mcp"
        "（或以另一个名字调用）：\n"
    )
    for name, n in codex_freq.most_common(20):
        lines.append(f"- `{name}`: {n}\n")

    lines.append("\n## ⑦ 连接器结构字段覆盖率\n")
    lines.append("| agent_slug | 会话数 | 镜像可得 | 候选构造器 | 有 tool_call_id | 有 tool_name | 有 path 参数 | 逻辑来源 |\n")
    lines.append("|---|---|---|---|---|---|---|---|\n")
    for slug, cov in sorted(stats["coverage"].items()):
        builder = "有（claude_code/codex）" if slug in ("claude_code", "codex") else "无（本轮未实现，见 R7/R11「不启用」）"
        lines.append(f"| {slug} | {cov['sessions']} | {cov['mirror_ok']} | {builder} | {cov['has_tool_call_id']} | {cov['has_tool_name']} | {cov['has_path_arg']} | {cov['logical_source']} |\n")
    lines.append(
        "「逻辑来源」= 该 agent_slug 属于 `SourceKind::Logical` 连接器（`LOGICAL_SOURCE_CONNECTORS`，"
        "镜像 `src/indexer/mod.rs:15708`）的会话数；这类连接器没有真实文件源，捕获缺席记 `capture_na` 而非失败。\n"
    )

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

    lines.append("\n## ⑩ `idx≠0` codex user 记忆特征串候选（spec §60；不在锚点 3 内，默认保留）\n")
    idx_total = stats["idx_ne_0_memory_candidates_total"]
    lines.append(
        f"命中数: {idx_total}（全量计数；其中 anchor3_shell_opener 也命中 "
        f"{stats['idx_ne_0_anchor3_also']} 条）\n"
    )
    lines.append(
        f"列表为前 {len(stats['idx_ne_0_memory_candidates'])} 条，共 {idx_total} 条"
        "（判据：agent=codex、role=user、idx≠0、正文含 memory/injection-only/workspace-scoped 名单里的任一 basename）：\n"
    )
    for sample in stats["idx_ne_0_memory_candidates"]:
        lines.append(f"- `{sample}`\n")

    lines.append(f"\n## manifest 条数\n{len(manifest)}\n")

    with open(report_path, "w", encoding="utf-8") as f:
        f.writelines(lines)


# ---------------------------------------------------------------------------
# PR6 T5 (任务书 #126): `--verify` -- the T6 Step 3b consumer.
#
# Checks a reingest candidate against the frozen exclusion manifest and the
# PR4 reference library. Four shapes of assertion:
#   1. every manifest row: `content` cleared, `excluded` present with the
#      manifest's reason, its `extra_bin` differing from the reference's ONLY
#      by `{"redacted": true, "sha256": <marker sha>, "bytes": n}` at the
#      cleared positions, no row of its session still carrying the original
#      body, `snippets` empty, the session title free of the body, and no
#      `lex_docs`/`message_chunks` row for it;
#   2. every non-manifest row: same `(session key, idx)` sha and the same
#      `extra_bin` bytes as the reference library;
#   3. sampled manifest rows: the marker's sha reproduces by reparsing the
#      recorded raw-mirror blob, re-projecting the recorded blocks and
#      applying the ingest-side redactor;
#   4. the manifest itself contains no `context_file_read` hit outside the
#      path predicate (`predicate_p`) -- i.e. zero deep same-name misfires.
#
# `messages.excluded` is SQLite JSONB (schema v6 writes `jsonb(?)`), which
# needs SQLite >= 3.45 to read. This repo's `python3` is 3.10 with SQLite
# 3.37 on the deployment host, where `json(blob)` cannot decode JSONB at all,
# so `--verify` refuses to run rather than reading a blob as text: run it with
# an interpreter built against a newer SQLite (`python3.12` on that host).
# ---------------------------------------------------------------------------
VERIFY_JSONB_MIN = (3, 45, 0)
VERIFY_MAX_LISTED_FAILURES = 20


def _verify_jsonb_available() -> bool:
    return sqlite3.sqlite_version_info >= VERIFY_JSONB_MIN


def _open_verify_db(path, label):
    """Read-only handle plus whether `messages` carries the v6 `excluded`
    column. The reference library is the PR4 reingest product and predates
    schema v6, so the column has to be probed, not assumed."""
    conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    conn.row_factory = sqlite3.Row
    columns = {row[1] for row in conn.execute("PRAGMA table_info(messages)")}
    if not columns:
        raise RuntimeError(f"{label} {path} has no `messages` table")
    return conn, "excluded" in columns


def _row_columns(has_excluded):
    excluded = "json(m.excluded) AS excluded_json" if has_excluded else "NULL AS excluded_json"
    return (
        "SELECT m.id AS id, m.idx AS idx, m.content AS content, "
        f"{excluded}, m.extra_bin AS extra_bin, "
        "c.id AS conversation_id, c.title AS title, c.source_path AS source_path, "
        "c.source_id AS source_id, a.slug AS agent_slug, c.external_id AS external_id "
        "FROM messages m JOIN conversations c ON c.id = m.conversation_id "
        "JOIN agents a ON a.id = c.agent_id"
    )


def _field(entry, name):
    """`entry[name]` for both a manifest dict and a `sqlite3.Row`, returning
    `None` when the key is not there."""
    try:
        return entry[name]
    except (KeyError, IndexError):
        return None


def _session_predicate(entry):
    """The manifest's stable session key: `external_id` when it has one, else
    `source_path` -- the same rule `w4_corpus_diff` uses."""
    if _field(entry, "external_id"):
        return (
            "c.source_id = ? AND a.slug = ? AND c.external_id = ?",
            [_field(entry, "source_id"), _field(entry, "agent_slug"), _field(entry, "external_id")],
        )
    return (
        "c.source_id = ? AND a.slug = ? AND c.source_path = ?",
        [_field(entry, "source_id"), _field(entry, "agent_slug"), _field(entry, "source_path")],
    )


def _fetch_row(conn, sql, entry, idx):
    predicate, params = _session_predicate(entry)
    return conn.execute(f"{sql} WHERE {predicate} AND m.idx = ?", params + [idx]).fetchone()


def _session_key(entry):
    return (
        _field(entry, "source_id"),
        _field(entry, "agent_slug"),
        _field(entry, "external_id") or _field(entry, "source_path"),
        _field(entry, "idx"),
    )


def _stable_row_key(row):
    """B09 (任务书 #131) / R9-B08 (任务书 #132): the key the candidate and the
    reference library must agree on for an ordinary row -- SOURCE, agent,
    session identity, position.

    The key used to drop `source_id`, on the theory that it is derived from
    provenance and may legitimately differ between the two libraries. That
    theory does not survive contact with the data: two rows differing ONLY in
    `source_id` then collapse to one dict key, the later one silently
    overwrites the earlier, and "non-manifest row is missing" cannot fire for a
    row that was dropped -- each side shows one row and they match. Whether a
    source change is legitimate is a question for an explicit mapping to
    answer, not for a key that discards the field.

    `external_id` is still the session identity (falling back to
    `source_path`, the same rule the manifest uses)."""
    return (
        _field(row, "source_id"),
        _field(row, "agent_slug"),
        _field(row, "external_id") or _field(row, "source_path"),
        _field(row, "idx"),
    )


def _decode_extra(blob):
    if blob is None:
        return None
    return msgpack.unpackb(blob, raw=False)


def _diff_paths(candidate, reference, path=""):
    """Positions where `candidate` differs from `reference`, as
    `(path, candidate_value, reference_value)` triples."""
    if isinstance(reference, dict) and isinstance(candidate, dict):
        out = []
        for key in sorted(set(reference) | set(candidate)):
            here = f"{path}.{key}"
            if key not in candidate or key not in reference:
                out.append((here, candidate.get(key), reference.get(key)))
            else:
                out.extend(_diff_paths(candidate[key], reference[key], here))
        return out
    if isinstance(reference, list) and isinstance(candidate, list):
        out = []
        for i in range(max(len(reference), len(candidate))):
            here = f"{path}[{i}]"
            if i >= len(candidate) or i >= len(reference):
                out.append((here, None, None))
            else:
                out.extend(_diff_paths(candidate[i], reference[i], here))
        return out
    if candidate != reference:
        return [(path, candidate, reference)]
    return []


# ---------------------------------------------------------------------------
# B07 (任务书 #131): the R7 body-field map, mirrored from
# `src/indexer/exclusion.rs::EXTRA_FIELD_MAP` (claude_code / codex entries --
# the only two connectors with a candidate builder). The verifier uses it to
# derive the exact set of `extra_bin` positions an exclusion may rewrite for a
# given event and block set; a redacted placeholder anywhere else is an
# over-clear, not an exclusion.
# `[*]` on a segment means "index into that array with the block index".
# ---------------------------------------------------------------------------
EXTRA_FIELD_MAP = {
    "claude_code": ("message.content[*].content", "message.content[*].text", "toolUseResult.file.content"),
    "codex": (
        "payload.output[*].text",
        "payload.content[*].text",
        "payload.arguments",
        "payload.input",
        "payload.output",
        "payload.content",
        "payload.message",
    ),
}

# Mirrors `is_owned_body_copy`/`TOOL_USE_RESULT_WRAPPER_SLACK` in that same
# file (B04).
TOOL_USE_RESULT_WRAPPER_SLACK = 1024


def _owned_body_copy(recorded, body):
    if not isinstance(recorded, str) or not isinstance(body, str):
        return False
    if recorded == body:
        return True
    return bool(body) and len(recorded) <= len(body) + TOOL_USE_RESULT_WRAPPER_SLACK and body in recorded


def _expand_field_paths(agent_slug, blocks):
    """The R7 field map resolved to concrete dot-paths for `blocks`."""
    allowed = set()
    for path in EXTRA_FIELD_MAP.get(agent_slug, ()):
        if "[*]" in path:
            for index in blocks:
                allowed.add(path.replace("[*]", f"[{index}]"))
        else:
            allowed.add(path)
    return allowed


def _owned_bodies(extra, blocks, own_body):
    """Mirrors `exclusion.rs::owned_bodies`: the bodies an exclusion may treat
    as its own -- the row's own pre-clear content (absent on the sibling path,
    whose content is never cleared) plus, for every targeted block, that
    block's body as the CONNECTOR projects it.

    R9-B03 (任务书 #132): the string-only reading dropped an array-form body
    (`tool_result.content = [{"type":"text","text":...}]`) entirely, so both
    top-level `toolUseResult` shapes that exist to be cleared against it kept
    the excluded body verbatim in `extra_bin`.
    """
    bodies = []
    if own_body:
        bodies.append(own_body)
    if not isinstance(extra, dict):
        return bodies
    message = extra.get("message")
    blocks_value = message.get("content") if isinstance(message, dict) else None
    if blocks_value is None:
        blocks_value = extra.get("content")
    if not isinstance(blocks_value, list):
        return bodies
    for index in blocks:
        if not isinstance(index, int) or not 0 <= index < len(blocks_value):
            continue
        block = blocks_value[index]
        if isinstance(block, str):
            bodies.append(block)
            continue
        if not isinstance(block, dict):
            continue
        for key in ("content", "text"):
            if key not in block:
                continue
            value = block[key]
            if isinstance(value, str):
                bodies.append(value)
                continue
            projected = _flatten_content(value)
            if projected:
                bodies.append(projected)
    return bodies


def _allowed_extra_paths(entry, ref_row, ref_extra):
    """Concrete dot-paths (no leading dot) this exclusion may rewrite."""
    allowed = _expand_field_paths(entry.get("agent_slug"), entry.get("blocks") or [])
    if entry.get("agent_slug") == "claude_code" and isinstance(ref_extra, dict):
        own_body = ref_row["content"] if ref_row is not None else None
        # B04's ownership proof, but read off the reference EVENT rather than
        # the row's content alone: that covers the sibling path (N02, no row
        # of its own) and the array-form body R9-B03 measured the string-only
        # reading dropping.
        bodies = _owned_bodies(ref_extra, entry.get("blocks") or [], own_body)
        # The string-form top-level `toolUseResult` is a legitimate target
        # only when it IS one of those bodies' copy.
        if any(_owned_body_copy(ref_extra.get("toolUseResult"), body) for body in bodies):
            allowed.add("toolUseResult")
        # N-R7arr (任务书 #131 T6-c): the ARRAY form
        # (`[{"type":"text","text":...}]`, what the MCP tool results such as
        # `mcp__cass-mcp__cass_expand` record) carries the body in each
        # element's `text`, which no R7 field path names. Admitted PER
        # ELEMENT, and only for an element whose reference-side `text` proves
        # ownership of the body -- the element index is not the block index,
        # so it cannot be expanded from `blocks` the way the `[*]` paths are.
        items = ref_extra.get("toolUseResult")
        if isinstance(items, list):
            for index, item in enumerate(items):
                if isinstance(item, dict) and any(
                    _owned_body_copy(item.get("text"), body) for body in bodies
                ):
                    allowed.add(f"toolUseResult[{index}].text")
            # R9-B03: the array is ONE projected value for the whole result.
            # When its elements are FRAGMENTS (`[text A, text B]` for a body
            # `"secret A\nsecret B"`) no single element is that body, yet the
            # connector's own join reconstructs it exactly -- so the whole
            # array is the body's copy and every element is a target.
            joined = _flatten_content(items)
            if joined and any(joined == body for body in bodies):
                for index in range(len(items)):
                    allowed.add(f"toolUseResult[{index}].text")
    return allowed


def _extra_event_key(extra):
    """The event identity a decoded extra carries: claude's top-level `uuid`,
    codex's `payload.id`."""
    if not isinstance(extra, dict):
        return None
    if isinstance(extra.get("uuid"), str):
        return extra["uuid"]
    payload = extra.get("payload")
    if isinstance(payload, dict) and isinstance(payload.get("id"), str):
        return payload["id"]
    return None


def _sibling_extra_diff_is_target_only(cand_extra, ref_extra, agent_slug, manifest_by_event):
    """N02 (任务书 #131): a row that shares the excluded row's EVENT legitimately
    carries that same event with the same target blocks replaced -- that is
    `apply_sibling`'s whole job -- so "a non-manifest extra_bin must be
    byte-equal to the reference" is too strong for it. The exemption is kept
    narrow: every difference must be a redacted placeholder at a path this
    event's blocks may rewrite, and nowhere else. A blanket per-row exemption
    would hide exactly the over-clears B07 exists to catch.
    """
    entry = manifest_by_event.get((agent_slug, _extra_event_key(cand_extra)))
    if entry is None:
        return False
    allowed = _expand_field_paths(agent_slug, entry.get("blocks") or [])
    sha = entry.get("sha256")
    diffs = _diff_paths(cand_extra, ref_extra)
    if not diffs:
        return False
    return all(
        _is_redacted_placeholder(candidate_value, sha) and _normalized_diff_path(path) in allowed
        for path, candidate_value, _reference_value in diffs
    )


def _string_leaves(value, depth=0):
    """Every string leaf of a decoded extra, unwrapping one level of
    JSON-in-a-string (the `__cass_historical_raw_json__` envelope) so a body
    stored inside it counts too."""
    if isinstance(value, str):
        yield value
        if depth == 0 and value.lstrip()[:1] in ("{", "["):
            try:
                yield from _string_leaves(json.loads(value), depth + 1)
            except ValueError:
                pass
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_leaves(item, depth)
    elif isinstance(value, list):
        for item in value:
            yield from _string_leaves(item, depth)


def _extra_carries_body(extra, body, agent_slug=None):
    """B08 (任务书 #131): compare against the DECODED string leaves, never
    against `json.dumps(extra)` -- serialization escapes newlines, quotes and
    backslashes, so a multi-line body still sitting verbatim in the extra was
    invisible to the old comparison and the run reported failures=0. Length is
    not a gate either: a short body is a body (the old `len(body) >= 32` guard
    skipped the whole check for anything shorter).

    R9-B06 (任务书 #132): a leaf scan still cannot see a body the connector
    carries as SEVERAL blocks -- the visible text is the `\n`-joined
    projection of them, so each leaf holds a fragment and none holds the whole.
    The extra IS an event, so it is projected through the probe's own candidate
    builder (the same code that projects the mirror side for the content
    comparison) and the result compared as a whole."""
    if not body:
        return False
    if any(body in leaf for leaf in _string_leaves(extra)):
        return True
    builder = {
        "claude_code": build_candidates_claude_code,
        "codex": build_candidates_codex,
    }.get(agent_slug)
    if builder is None or not isinstance(extra, dict):
        return False
    try:
        texts = [candidate.text or "" for candidate in builder([extra])]
    except Exception:
        return False
    # The `\n` join, not a per-candidate equality: a single candidate makes the
    # two identical, and several candidates are exactly the case a per-candidate
    # test cannot see (no one of them is the body).
    joined = "\n".join(texts)
    return bool(joined) and joined == body


def _normalized_diff_path(path):
    return path[1:] if path.startswith(".") else path


# ---------------------------------------------------------------------------
# N-fam (任务书 #131, 控制面追加): a coarse family per failure detail. A real
# run can report tens of thousands of failures (`failures=84642` on the T6-b
# rehearsal); a bare total cannot be reduced to a cause, and listing the first
# twenty cannot either. The families are matched on the detail text emitted by
# `_verify_once` below -- ordered, because several details share substrings.
# ---------------------------------------------------------------------------
_FAILURE_FAMILIES = (
    ("sha_binding_mismatch", "sha_binding_mismatch"),
    # The rebuild family is matched on the DETAIL text: the `rebuild/...` part
    # is the failure's LABEL, not its detail, so a `"rebuild/"` needle here
    # would never fire.
    ("rebuild_raw_invalid", "rebuild_raw_invalid"),
    ("rebuilt sha256", "rebuild_sha"),
    ("is not a position in the reparsed candidate list", "rebuild_raw_idx"),
    ("carries event_key=", "rebuild_event_key"),
    ("is block ", "rebuild_block"),
    ("raw-mirror blob is gone", "rebuild_blob_missing"),
    ("marker has no raw.blob", "rebuild_no_blob"),
    ("no reparse builder", "rebuild_no_builder"),
    ("context_file_read hit outside predicate P", "outside_predicate_p"),
    ("the session title still contains the body", "title_retained"),
    ("retained_excludable", "retained_excludable"),
    ("still carries the body in extra_bin", "body_retained_in_extra"),
    ("still carries the body", "body_retained_in_content"),
    ("redacted a field this exclusion does not own", "extra_over_clear"),
    ("changed somewhere other than a redacted block", "extra_unexpected_change"),
    ("is still present in extra_bin", "extra_body_present"),
    ("extra_bin presence differs", "extra_presence"),
    ("still carries a body", "content_retained"),
    ("has no `excluded` marker", "marker_missing"),
    ("marker reason", "marker_reason"),
    ("beyond_manifest_invalid", "beyond_manifest_invalid"),
    ("candidate_only_bad_marker", "candidate_only_bad_marker"),
    ("non-manifest row is missing", "non_manifest_row_missing"),
    ("non-manifest row is not in the reference", "non_manifest_row_extra"),
    ("non-manifest body differs", "non_manifest_body_changed"),
    ("non-manifest extra_bin differs", "non_manifest_extra_changed"),
    ("manifest row is absent", "manifest_row_missing"),
    ("snippet_text survived", "snippet_retained"),
    ("lex_docs row(s)", "lex_row_present"),
    ("message_chunks row(s)", "chunk_row_present"),
)


def failure_family(detail):
    for needle, family in _FAILURE_FAMILIES:
        if needle in detail:
            return family
    return "other"


def _is_redacted_placeholder(value, sha):
    return (
        isinstance(value, dict)
        and value.get("redacted") is True
        and value.get("sha256") == sha
        and isinstance(value.get("bytes"), int)
    )


def _session_rows(conn, sql, entry):
    predicate, params = _session_predicate(entry)
    return conn.execute(f"{sql} WHERE {predicate}", params).fetchall()


def _excludable_session_bodies(entry, marker, mirror_root, paths_cfg, cache):
    """The projected texts of this session's EXCLUDABLE candidates, other than
    the entry's own recorded position -- `None` when the session cannot be
    rebuilt (then the caller keeps the old, stronger verdict).

    N-fam4 (任务书 #131 T6-c): "some row of the session still contains the
    body" is stronger than the rules themselves. A body legitimately survives
    in rows the exclusion rules do not cover -- an unrelated `tool_result`
    that happens to carry the same text, a `codex_host_shell` injection at
    `idx != 0` (the rule only covers idx 0), a sibling call whose pairing
    failed -- and calling every one of those a leak hides the ones that ARE
    leaks. So the judge asks the probe's OWN decision function instead of
    guessing: rebuild the session's candidates from the recorded blob, run
    `PairingContext` + `decide` over them, and let only candidates that would
    themselves be excluded count.
    """
    raw = marker.get("raw") or {}
    blob_rel = raw.get("blob")
    if not blob_rel:
        return None
    blob_path = os.path.join(mirror_root, blob_rel)
    if not os.path.exists(blob_path):
        return None
    key = (blob_path, entry.get("agent_slug"))
    if key in cache:
        return cache[key]
    builder = {
        "claude_code": build_candidates_claude_code,
        "codex": build_candidates_codex,
    }.get(entry.get("agent_slug"))
    if builder is None:
        return None
    candidates = builder(load_blob_events(blob_path))
    pairing = PairingContext(candidates)
    own_idx = raw.get("idx")
    bodies = []
    for index, candidate in enumerate(candidates):
        if index == own_idx:
            # The entry's own message: it IS excludable (that is why this
            # entry exists) and it was excluded -- its body lives in the
            # excluded row, not in a surviving one.
            continue
        if decide(candidates, index, index, entry["agent_slug"], paths_cfg, pairing) is not None:
            bodies.append(candidate.text or "")
    cache[key] = bodies
    return bodies


EXCLUSION_REASONS = ("cass_recall", "context_file_read", "codex_host_shell")


def _raw_reference_problem(raw):
    """The required fields and types of a marker's `raw` record, before
    anything is looked up with it. A record that cannot name an event must not
    be able to switch the identity check off by carrying `null`."""
    if not isinstance(raw, dict):
        return "marker carries no raw record"
    blob = raw.get("blob")
    if not isinstance(blob, str) or not blob:
        return f"raw.blob {blob!r} is not a non-empty path"
    idx = raw.get("idx")
    if not isinstance(idx, int) or isinstance(idx, bool):
        return f"raw.idx {idx!r} is not an integer"
    event_key = raw.get("event_key")
    if not isinstance(event_key, str) or not event_key:
        return f"raw.event_key {event_key!r} is not a non-empty string"
    blocks = raw.get("blocks")
    if not isinstance(blocks, list) or not all(
        isinstance(block, int) and not isinstance(block, bool) for block in blocks
    ):
        return f"raw.blocks {blocks!r} is not a list of integers"
    return None


def _residue_problems(conn, message_id):
    """The rows an excluded message must not leave behind, as detail strings."""
    problems = []
    for snippet in conn.execute(
        "SELECT snippet_text FROM snippets WHERE message_id = ?", [message_id]
    ):
        if (snippet["snippet_text"] or "") != "":
            problems.append("a snippet_text survived the exclusion")
            break
    lex_hits = conn.execute("SELECT COUNT(*) FROM lex_docs WHERE doc_id = ?", [message_id]).fetchone()[0]
    if lex_hits:
        problems.append(f"{lex_hits} lex_docs row(s) for an excluded message")
    chunk_hits = conn.execute(
        "SELECT COUNT(*) FROM message_chunks WHERE message_id = ?", [message_id]
    ).fetchone()[0]
    if chunk_hits:
        problems.append(f"{chunk_hits} message_chunks row(s) for an excluded message")
    return problems


def _reparse_recorded_candidate(agent_slug, raw, mirror_root):
    """The candidate `raw` names, rebuilt from the raw-mirror blob. Returns
    `(candidates, index, problem)`; `problem` is `None` on success, the string
    `"unverifiable"` when the blob is simply not on disk (the caller records
    that rather than guessing), else a one-line reason."""
    blob_path = os.path.join(mirror_root, raw["blob"])
    if not os.path.exists(blob_path):
        return None, None, "unverifiable"
    builder = {
        "claude_code": build_candidates_claude_code,
        "codex": build_candidates_codex,
    }.get(agent_slug)
    if builder is None:
        return None, None, f"no reparse builder for agent_slug {agent_slug!r}"
    candidates = builder(load_blob_events(blob_path))
    idx = raw["idx"]
    if idx < 0 or idx >= len(candidates):
        return candidates, None, (
            f"marker raw.idx={idx!r} is not a position in the reparsed candidate list "
            f"({len(candidates)} candidates) for {agent_slug}"
        )
    picked = candidates[idx]
    if picked.event_key != raw["event_key"]:
        return candidates, idx, (
            f"candidate at raw.idx={idx} carries event_key={picked.event_key!r}, "
            f"marker records {raw['event_key']!r}"
        )
    if picked.block_index not in raw["blocks"]:
        return candidates, idx, (
            f"candidate at raw.idx={idx} is block {picked.block_index}, marker records {raw['blocks']!r}"
        )
    return candidates, idx, None


def _beyond_manifest_exclusion_problem(entry, marker, row, ref_row, conn_cand, mirror_root, paths_cfg):
    """`None` when an exclusion made beyond the manifest really IS one; else
    `(subreason, detail)`.

    N-fam5 (任务书 #131 T6-c) made such a row informational -- the manifest
    comes from an older snapshot, so it cannot list an exclusion the candidate
    made afterwards. R9-B04 (任务书 #132) measured what "informational" had
    become: the branch checked the marker's SHAPE only, so a candidate that
    cleared an ordinary message's body and appended a well-shaped marker passed
    with `failures=0` whether it left the body in `extra` or over-cleared an
    ordinary field into a placeholder.

    Going beyond the manifest is therefore a claim, not an exemption: the row
    has to satisfy the same invariants a manifest row does -- the marker names
    a reason this tool knows, its sha IS the reference body's, its `raw` record
    is complete and really points at this message's block, every `extra`
    difference is a placeholder at a path this exclusion owns, the body is not
    reconstructible from the extra, and no snippet/lex/chunks row survived.
    """
    reason = marker.get("reason")
    if reason not in EXCLUSION_REASONS:
        return "exclusion_reason", f"marker reason {reason!r} is not a known exclusion reason"
    sha = marker.get("sha256")
    if not isinstance(sha, str) or len(sha) != 64:
        return "marker_shape", f"marker sha256 {sha!r} is not a 64-character digest"
    if not isinstance(marker.get("bytes"), int) or isinstance(marker.get("bytes"), bool):
        return "marker_shape", f"marker bytes {marker.get('bytes')!r} is not an integer"
    raw_problem = _raw_reference_problem(marker.get("raw"))
    if raw_problem is not None:
        return "marker_shape", raw_problem

    body = ref_row["content"] or ""
    expected_sha = hashlib.sha256(redact_text(body).encode("utf-8")).hexdigest()
    if sha != expected_sha:
        return "sha_is_not_the_reference_body", (
            f"marker sha256 {sha} is not sha256(redact(reference body)) {expected_sha}"
        )

    cand_extra = _decode_extra(row["extra_bin"])
    ref_extra = _decode_extra(ref_row["extra_bin"])
    allowed = _allowed_extra_paths(entry, ref_row, ref_extra)
    for path, value, _reference in _diff_paths(cand_extra, ref_extra):
        if not _is_redacted_placeholder(value, sha):
            return "extra_changed_outside_a_placeholder", (
                f"extra_bin changed outside a redacted placeholder: {path}"
            )
        if _normalized_diff_path(path) not in allowed:
            return "extra_redacted_a_path_this_exclusion_does_not_own", (
                f"extra_bin redacted a field this exclusion does not own: {path} "
                f"(allowed: {sorted(allowed)[:5]})"
            )
    if body and _extra_carries_body(cand_extra, body, entry.get("agent_slug")):
        return "body_still_in_extra", "the excluded body is still reconstructible from extra_bin"

    residue = _residue_problems(conn_cand, row["id"])
    if residue:
        return "residue", residue[0]

    candidates, index, problem = _reparse_recorded_candidate(entry["agent_slug"], marker["raw"], mirror_root)
    if problem == "unverifiable":
        return "unverifiable", f"the raw-mirror blob {marker['raw']['blob']!r} is not on disk"
    if problem is not None:
        return "raw_does_not_name_this_row", problem
    pairing = PairingContext(candidates)
    decision = decide(candidates, index, row["idx"], entry["agent_slug"], paths_cfg, pairing)
    if decision is None:
        return "not_excludable", (
            f"the probe's own decide() does not exclude the candidate at raw.idx={index} "
            f"({entry['agent_slug']})"
        )
    if decision["reason"] != reason:
        return "reason_disagrees_with_decide", (
            f"marker reason {reason!r} != decide() {decision['reason']!r} for the candidate at raw.idx={index}"
        )
    rebuilt = hashlib.sha256(redact_text(candidates[index].text).encode("utf-8")).hexdigest()
    if rebuilt != sha:
        return "sha_is_not_the_rebuilt_body", (
            f"marker sha256 {sha} != the rebuilt candidate's {rebuilt}"
        )
    return None


def _candidate_only_excluded_problem(row, marker, conn_cand, mirror_root):
    """`None` when a CANDIDATE-ONLY row's own exclusion holds up; else
    `(subreason, detail)`; `("unverifiable", ...)` when the raw-mirror blob is
    not on disk.

    N-fam2 (任务书 #131 追加) made candidate-only rows informational -- the
    candidate is a newer library, so rows the reference snapshot does not have
    yet are expected. R9-B05 (任务书 #132) measured what that left: the loop
    only incremented a counter, so a row carrying an `excluded` marker AND a
    non-empty `content` -- a self-contradiction, and exactly what a body left
    behind by a broken exclusion looks like -- passed with `failures=0`.

    Whether the reference has the row is beside the point: `excluded != NULL`
    plus a surviving body is a contradiction on its own. There is no reference
    row to compare against, so the invariants here are the ones the row can be
    held to by itself: content cleared, marker complete, no snippet/lex/chunks
    residue, and -- when the raw-mirror blob is available -- the marker really
    naming this row's block and its sha really being that block's body, with no
    copy of that body left in the extra.
    """
    content = row["content"] or ""
    if content != "":
        return "body_not_cleared", (
            f"an excluded row still carries a {len(content)}-character body"
        )
    reason = marker.get("reason")
    if reason not in EXCLUSION_REASONS:
        return "exclusion_reason", f"marker reason {reason!r} is not a known exclusion reason"
    sha = marker.get("sha256")
    if not isinstance(sha, str) or len(sha) != 64:
        return "marker_shape", f"marker sha256 {sha!r} is not a 64-character digest"
    if not isinstance(marker.get("bytes"), int) or isinstance(marker.get("bytes"), bool):
        return "marker_shape", f"marker bytes {marker.get('bytes')!r} is not an integer"
    raw_problem = _raw_reference_problem(marker.get("raw"))
    if raw_problem is not None:
        return "marker_shape", raw_problem
    residue = _residue_problems(conn_cand, row["id"])
    if residue:
        return "residue", residue[0]
    candidates, index, problem = _reparse_recorded_candidate(row["agent_slug"], marker["raw"], mirror_root)
    if problem == "unverifiable":
        return "unverifiable", f"the raw-mirror blob {marker['raw']['blob']!r} is not on disk"
    if problem is not None:
        return "raw_does_not_name_this_row", problem
    rebuilt = hashlib.sha256(redact_text(candidates[index].text).encode("utf-8")).hexdigest()
    if rebuilt != sha:
        return "sha_is_not_the_rebuilt_body", (
            f"marker sha256 {sha} != the rebuilt candidate's {rebuilt}"
        )
    body = candidates[index].text
    if body and _extra_carries_body(_decode_extra(row["extra_bin"]), body, row["agent_slug"]):
        return "body_still_in_extra", "the excluded body is still reconstructible from extra_bin"
    return None


def _verify_rebuild_blob(entry, marker, mirror_root):
    """Reparse the recorded blob, re-project the recorded blocks and re-apply
    the ingest-side redactor; returns the rebuilt body's sha256 or an error
    string."""
    raw = marker.get("raw") or {}
    blob_rel = raw.get("blob")
    blocks = raw.get("blocks") or []
    event_key = raw.get("event_key")
    if not blob_rel:
        return None, "marker has no raw.blob"
    # R9-B09 (任务书 #132): the identity check below reads
    # `if event_key is not None and ...`, so a marker whose `raw.event_key` was
    # set to JSON null switched that check off ENTIRELY: its position and body
    # sha both still checked out and the rebuild reported success for a record
    # that names no event at all. A raw record must carry its fields, and carry
    # them as the right types, BEFORE anything is looked up with it.
    raw_problem = _raw_reference_problem(raw)
    if raw_problem is not None:
        return None, f"rebuild_raw_invalid: {raw_problem}"
    blob_path = os.path.join(mirror_root, blob_rel)
    if not os.path.exists(blob_path):
        return None, f"raw-mirror blob is gone: {blob_path}"
    events = load_blob_events(blob_path)
    builders = {
        "claude_code": build_candidates_claude_code,
        "codex": build_candidates_codex,
    }
    builder = builders.get(entry["agent_slug"])
    if builder is None:
        return None, f"no reparse builder for agent_slug {entry['agent_slug']!r}"
    # B10 (任务书 #131): the rebuild must take the message the marker's
    # `raw.idx` points at, then VERIFY that this position really is the
    # recorded event/block -- the old version searched the reparsed candidates
    # for a matching event_key/blocks pair and never read `raw.idx` at all, so
    # a corrupted idx (or one that disagrees with the recorded event) rebuilt
    # "successfully".
    candidates = builder(events)
    idx = raw.get("idx")
    if not isinstance(idx, int) or idx < 0 or idx >= len(candidates):
        return None, (
            f"marker raw.idx={idx!r} is not a position in the reparsed candidate list "
            f"({len(candidates)} candidates) for {entry['agent_slug']}"
        )
    picked = candidates[idx]
    if event_key is not None and picked.event_key != event_key:
        return None, (
            f"candidate at raw.idx={idx} carries event_key={picked.event_key!r}, marker records {event_key!r}"
        )
    if picked.block_index not in blocks:
        return None, (
            f"candidate at raw.idx={idx} is block {picked.block_index}, marker records blocks={blocks!r}"
        )
    return hashlib.sha256(redact_text(picked.text).encode("utf-8")).hexdigest(), None


def _verify_once(candidate, manifest_path, reference, mirror_root, sample_rebuild,
                 seed, paths_cfg):
    """The whole check, returning `(failures, report)`. Split out of
    `run_verify` so `--selftest` drives the same code and asserts on the
    failures themselves, not on an exit code."""
    conn_cand, cand_has_excluded = _open_verify_db(candidate, "--candidate")
    if not cand_has_excluded:
        raise _NotV6(candidate)
    conn_ref, ref_has_excluded = _open_verify_db(reference, "--reference")
    sql_cand = _row_columns(cand_has_excluded)
    sql_ref = _row_columns(ref_has_excluded)

    manifest = json.load(open(manifest_path, encoding="utf-8"))
    failures = []
    sha_binding_mismatch = 0
    body_retained_unexcludable = 0
    candidate_excluded_beyond_manifest = 0
    candidate_excluded_beyond_manifest_samples = []
    beyond_manifest_unverifiable = 0
    beyond_manifest_unverifiable_samples = []
    candidate_only_excluded = 0
    candidate_only_unjudgeable = 0
    candidate_only_unjudgeable_samples = []
    body_retained_unexcludable_samples = []
    excludable_cache = {}
    extra_unchanged_no_body = 0
    candidate_only_rows = 0
    for entry in manifest:
        label = f"{entry['agent_slug']}/{entry['reason']}/idx={entry['idx']}"
        row = _fetch_row(conn_cand, sql_cand, entry, entry["idx"])
        if row is None:
            failures.append((label, "manifest row is absent from the candidate"))
            continue
        if row["content"] != "":
            failures.append((label, "excluded row still carries a body"))
            continue
        marker = json.loads(row["excluded_json"]) if row["excluded_json"] else None
        if marker is None:
            failures.append((label, "manifest row has no `excluded` marker"))
            continue
        if marker.get("reason") != entry["reason"]:
            failures.append(
                (label, f"marker reason {marker.get('reason')!r} != manifest {entry['reason']!r}")
            )
        sha = marker.get("sha256")
        # B10 (任务书 #131): every manifest entry's own sha must BE the marker's
        # -- sampled rebuilds only re-derive the ones they happen to pick, so
        # an unsampled entry whose marker sha (and placeholder) were both
        # changed together had nothing binding it to the manifest at all. Its
        # own failure class, so a corpus-wide binding gap is countable apart
        # from a real rebuild mismatch.
        if entry.get("sha256") != sha:
            sha_binding_mismatch += 1
            failures.append(
                (
                    label,
                    f"sha_binding_mismatch: marker sha256 {sha!r} != manifest sha256 {entry.get('sha256')!r}",
                )
            )
        ref_row = _fetch_row(conn_ref, sql_ref, entry, entry["idx"])
        if ref_row is None:
            failures.append((label, "manifest row is absent from the reference library"))
            continue

        cand_extra = _decode_extra(row["extra_bin"])
        ref_extra = _decode_extra(ref_row["extra_bin"])
        if (cand_extra is None) != (ref_extra is None):
            failures.append((label, "extra_bin presence differs from the reference"))
        elif cand_extra is not None:
            diffs = _diff_paths(cand_extra, ref_extra)
            cleared = [d for d in diffs if _is_redacted_placeholder(d[1], sha)]
            if not diffs:
                # N-fam2 (任务书 #131 追加, 控制面 on T6-b new6): zero diff is
                # NOT a failure by itself. An exclusion whose event never
                # carried the body in `extra` (the ~31% "compact" shape: the
                # reference and candidate extras are byte-identical, 59 bytes,
                # no body anywhere) has nothing to redact, yet the pre-fix
                # judge called every such row "the excluded block is still
                # present in extra_bin". The failure condition is that the
                # body is STILL THERE -- which is exactly what the recursive
                # leaf check above decides.
                if _extra_carries_body(cand_extra, ref_row["content"], entry["agent_slug"]):
                    failures.append((label, "the excluded block is still present in extra_bin"))
                else:
                    extra_unchanged_no_body += 1
            elif len(cleared) != len(diffs):
                stray = [d[0] for d in diffs if d not in cleared]
                failures.append(
                    (label, f"extra_bin changed somewhere other than a redacted block: {stray[:5]}")
                )
            else:
                # B07 (任务书 #131): "the new value looks like a placeholder"
                # is not enough -- the PATH has to be one this event/block set
                # may legitimately rewrite. Otherwise an over-clear that
                # redacts an ordinary field with the same sha (or any other
                # body-bearing field the exclusion does not own) reads as a
                # clean exclusion with failures=0.
                allowed = _allowed_extra_paths(entry, ref_row, ref_extra)
                off_map = [d[0] for d in cleared if _normalized_diff_path(d[0]) not in allowed]
                if off_map:
                    failures.append(
                        (
                            label,
                            f"extra_bin redacted a field this exclusion does not own: {off_map[:5]} "
                            f"(allowed: {sorted(allowed)[:5]})",
                        )
                    )


        # R9-B07 (任务书 #132): the scan used to `break` on the FIRST row that
        # matched -- including the informational branch -- so a session whose
        # row 0 legitimately quoted the body ended the scan there and a real
        # leak in a LATER row's `extra_bin` was never looked at. Every row of
        # the session gets both checks now; a match on one row is not evidence
        # about the next.
        body = ref_row["content"]
        if body:
            excludable = _excludable_session_bodies(entry, marker, mirror_root, paths_cfg, excludable_cache)
            for sib in _session_rows(conn_cand, sql_cand, entry):
                if body in (sib["content"] or ""):
                    if excludable is not None and any(body in text for text in excludable):
                        failures.append(
                            (
                                label,
                                f"session row idx={sib['idx']} still carries the body (retained_excludable: an excludable copy was left in place)",
                            )
                        )
                    else:
                        # N-fam4: the rules do not cover this copy -- recorded,
                        # not failed. See `_excludable_session_bodies`.
                        body_retained_unexcludable += 1
                        if len(body_retained_unexcludable_samples) < 20:
                            body_retained_unexcludable_samples.append([label, sib["idx"]])
                sib_extra = _decode_extra(sib["extra_bin"])
                if sib_extra is not None and _extra_carries_body(sib_extra, body, entry["agent_slug"]):
                    failures.append(
                        (label, f"session row idx={sib['idx']} still carries the body in extra_bin")
                    )
        if body and body in (row["title"] or ""):
            failures.append((label, "the session title still contains the body"))

        for detail in _residue_problems(conn_cand, row["id"]):
            failures.append((label, detail))

        # The predicate-P misfire check (spec §七 风险行): a context_file_read
        # hit whose recorded paths are not all inside the configured predicate
        # is a false positive by construction.
        if entry["reason"] == "context_file_read":
            anchor = (marker.get("anchor") or {})
            paths = anchor.get("paths") or []
            # N01 (任务书 #131): `project_read` records the DOCUMENT name in
            # `anchor.paths` (that is what predicate P's fourth arm judges),
            # so running the file-path predicate over it rejects every
            # legitimate project_read hit.
            identities = READ_TOOL_IDENTITIES.get(entry["agent_slug"]) or {}
            if anchor.get("tool_name") and anchor.get("tool_name") == identities.get("project_read"):
                outside = [p for p in paths if not predicate_p_project_read_document(p, paths_cfg)]
            else:
                outside = [p for p in paths if not predicate_p(p, paths_cfg)]
            if outside:
                failures.append(
                    (label, f"context_file_read hit outside predicate P: {outside[:5]}")
                )

    # Non-manifest rows must be untouched, byte for byte -- on BOTH sides.
    # B09 (任务书 #131): walking only the candidate's rows (as this did) cannot
    # see a row the candidate no longer has at all: the reference library still
    # holds it, the candidate dropped it, and "非清单零误清" passed with
    # `non_manifest_rows_checked=0`. The comparison is now two-way over the
    # stable key both libraries must agree on.
    manifest_keys = {_session_key(entry) for entry in manifest}
    manifest_by_event = {(entry["agent_slug"], entry.get("event_key")): entry for entry in manifest}
    cand_rows = {
        _stable_row_key(row): row
        for row in conn_cand.execute(sql_cand)
        if _session_key(row) not in manifest_keys
    }
    ref_rows = {
        _stable_row_key(row): row
        for row in conn_ref.execute(sql_ref)
        if _session_key(row) not in manifest_keys
    }
    checked = len(ref_rows)
    for key, ref_row in ref_rows.items():
        label = f"{key[1]}/{key[0]}/idx={key[3]}"
        row = cand_rows.get(key)
        if row is None:
            failures.append((label, "non-manifest row is missing from the candidate"))
            continue
        marker = json.loads(row["excluded_json"]) if _field(row, "excluded_json") else None
        if marker is not None and row["content"] == "":
            # N-fam5 (任务书 #131 T6-c): a row the candidate excluded that the
            # manifest CANNOT know about -- the manifest comes from the `copy`
            # snapshot, and this row was added to the corpus afterwards (the
            # control plane regenerated it against `copy`: 6,882 entries, zero
            # added or removed). The reference library is a later snapshot, so
            # it still holds the original text and the two sides differ by
            # construction. Recorded, not failed -- after a shape check.
            candidate_excluded_beyond_manifest += 1
            if len(candidate_excluded_beyond_manifest_samples) < 20:
                candidate_excluded_beyond_manifest_samples.append([label, key[3]])
            # R9-B04 (任务书 #132): going beyond the manifest is a CLAIM, not
            # an exemption -- the row is held to the same invariants a manifest
            # row is. The entry is synthesized from the row itself, because no
            # manifest entry describes it.
            entry = {
                "reason": marker.get("reason"),
                "source_id": _field(row, "source_id"),
                "agent_slug": key[1],
                "external_id": _field(row, "external_id"),
                "source_path": _field(row, "source_path"),
                "idx": key[3],
                "blocks": (marker.get("raw") or {}).get("blocks") or [],
            }
            problem = _beyond_manifest_exclusion_problem(
                entry, marker, row, ref_row, conn_cand, mirror_root, paths_cfg
            )
            if problem is not None:
                subreason, detail = problem
                if subreason == "unverifiable":
                    # The raw-mirror blob is not on disk, so the decide/raw
                    # half cannot run. Recorded, never silently passed.
                    beyond_manifest_unverifiable += 1
                    if len(beyond_manifest_unverifiable_samples) < 20:
                        beyond_manifest_unverifiable_samples.append([label, detail])
                else:
                    failures.append((label, f"beyond_manifest_invalid: {subreason}: {detail}"))
            continue
        if row["content"] != ref_row["content"]:
            failures.append((label, "non-manifest body differs from reference"))
        if row["extra_bin"] != ref_row["extra_bin"] and not _sibling_extra_diff_is_target_only(
            _decode_extra(row["extra_bin"]),
            _decode_extra(ref_row["extra_bin"]),
            key[1],
            manifest_by_event,
        ):
            failures.append((label, "non-manifest extra_bin differs from reference"))
    for key in cand_rows:
        if key not in ref_rows:
            # N-fam2 (任务书 #131 追加): the candidate is a NEWER library than
            # the reference snapshot (T6-b: 5,439 sessions today against
            # 5,112 on 2026-09-05), so rows the reference simply does not have
            # yet are expected -- counting them as failures produced ~82k of
            # them in one real run. They are still RECORDED, because a large
            # jump is worth seeing; only "the candidate lost something the
            # reference has" is a failure.
            candidate_only_rows += 1
            # R9-B05 (任务书 #132): "the reference does not have this row" is
            # not a licence for the row to contradict itself. A marker plus a
            # surviving body is a contradiction whatever the reference holds.
            row = cand_rows[key]
            marker = json.loads(row["excluded_json"]) if _field(row, "excluded_json") else None
            if marker is not None:
                candidate_only_excluded += 1
                problem = _candidate_only_excluded_problem(row, marker, conn_cand, mirror_root)
                if problem is not None:
                    subreason, detail = problem
                    label = f"{key[1]}/{key[0]}/idx={key[3]}"
                    if subreason == "unverifiable":
                        candidate_only_unjudgeable += 1
                        if len(candidate_only_unjudgeable_samples) < 20:
                            candidate_only_unjudgeable_samples.append([label, detail])
                    else:
                        failures.append((label, f"candidate_only_bad_marker: {subreason}: {detail}"))

    # Sampled rebuilds.
    rng = random.Random(seed)
    sample = rng.sample(manifest, min(sample_rebuild, len(manifest)))
    rebuilt = 0
    for entry in sample:
        row = _fetch_row(conn_cand, sql_cand, entry, entry["idx"])
        if row is None or not row["excluded_json"]:
            continue
        marker = json.loads(row["excluded_json"])
        sha, error = _verify_rebuild_blob(entry, marker, mirror_root)
        if error is not None:
            failures.append((f"rebuild/{entry['agent_slug']}/idx={entry['idx']}", error))
        elif sha != marker.get("sha256"):
            failures.append(
                (
                    f"rebuild/{entry['agent_slug']}/idx={entry['idx']}",
                    f"rebuilt sha256 {sha} != marker {marker.get('sha256')}",
                )
            )
        else:
            rebuilt += 1

    report = {
        "candidate": candidate,
        "reference": reference,
        "manifest": manifest_path,
        "manifest_entries": len(manifest),
        "non_manifest_rows_checked": checked,
        "rebuild_sample": len(sample),
        "rebuild_ok": rebuilt,
        "sha_binding_mismatch": sha_binding_mismatch,
        "extra_unchanged_no_body": extra_unchanged_no_body,
        "body_retained_unexcludable": body_retained_unexcludable,
        "body_retained_unexcludable_samples": body_retained_unexcludable_samples,
        "candidate_excluded_beyond_manifest": candidate_excluded_beyond_manifest,
        "candidate_excluded_beyond_manifest_samples": candidate_excluded_beyond_manifest_samples,
        # R9-B04: an exclusion beyond the manifest whose raw-mirror blob is not
        # on disk cannot have its decide/raw half run. Recorded separately so a
        # non-zero count is visible instead of looking like a clean pass.
        "beyond_manifest_unverifiable": beyond_manifest_unverifiable,
        "beyond_manifest_unverifiable_samples": beyond_manifest_unverifiable_samples,
        "candidate_only_rows": candidate_only_rows,
        # R9-B05: of the candidate-only rows, the ones that carry an exclusion
        # marker (held to the exclusion invariants) and the ones whose
        # raw-mirror blob is not on disk (recorded, never silently passed).
        "candidate_only_excluded": candidate_only_excluded,
        "candidate_only_unjudgeable": candidate_only_unjudgeable,
        "candidate_only_unjudgeable_samples": candidate_only_unjudgeable_samples,
        "failure_families": dict(sorted(Counter(failure_family(detail) for _label, detail in failures).items())),
        # N-fam3 (任务书 #131 追加): the families give the shape of a failure
        # set, this gives every one of them -- `[family, label, message]` per
        # failure, never truncated (stdout keeps its first-20 listing).
        "failure_list": [[failure_family(detail), label, detail] for label, detail in failures],
        "failures": len(failures),
    }
    return failures, report


def _file_identity(path):
    """`(realpath, (st_dev, st_ino) or None)` -- what a same-file check can
    compare before anything is written. The inode is what catches an alias or
    symlink of the same file; the realpath alone already covers a path that
    does not exist yet."""
    try:
        st = os.stat(path)
        inode = (st.st_dev, st.st_ino)
    except OSError:
        inode = None
    return (os.path.realpath(path), inode)


def find_output_collisions(inputs, outputs):
    """`[(out_label, other_label, path)]` for every output that names one of
    the inputs, or that names another output. Pure -- nothing is opened,
    created or written."""
    problems = []
    identity_by_input = [(label, _file_identity(path)) for label, path in inputs]
    seen_outputs = []
    for out_label, out_path in outputs:
        out_real, out_inode = _file_identity(out_path)
        for in_label, (in_real, in_inode) in identity_by_input:
            if out_real == in_real or (out_inode is not None and out_inode == in_inode):
                problems.append((out_label, in_label, out_path))
        for other_label, (other_real, other_inode) in seen_outputs:
            if out_real == other_real or (out_inode is not None and out_inode == other_inode):
                problems.append((out_label, other_label, out_path))
        seen_outputs.append((out_label, (out_real, out_inode)))
    return problems


def sqlite_sidecar_paths(path):
    """The two files SQLite may hold committed data in besides the database
    itself; naming either as an output would destroy the input too."""
    return [f"{path}{suffix}" for suffix in ("-wal", "-shm")]


def report_output_collisions(what, inputs, outputs):
    """B01 (任务书 #131): fail-loud message when an output names an input, or
    `None` when the write is safe. Callers must check this BEFORE any
    computation or write."""
    problems = find_output_collisions(inputs, outputs)
    if not problems:
        return None
    detail = "; ".join(
        f"{out} ({out_label}) is the same file as {other_label}" for out_label, other_label, out in problems
    )
    return f"{what}: refusing to write an output over an input (nothing was written): {detail}"


class _NotV6(Exception):
    """The candidate library predates schema v6, i.e. it has no `excluded`
    column at all -- a precondition failure, never a silent pass."""


def run_verify(candidate, manifest_path, reference, mirror_root, sample_rebuild,
               seed, report_path, paths_cfg):
    if not _verify_jsonb_available():
        print(
            "--verify reads `messages.excluded`, which schema v6 stores as SQLite "
            f"JSONB (needs SQLite >= {'.'.join(map(str, VERIFY_JSONB_MIN))}); this "
            f"interpreter has SQLite {sqlite3.sqlite_version} "
            f"(python {sys.version.split()[0]}). Run this script with an interpreter "
            "built against a newer SQLite (python3.12 on this host).",
            file=sys.stderr,
        )
        return 2
    for label, path in (("--candidate", candidate), ("--manifest", manifest_path),
                        ("--reference", reference)):
        if not os.path.exists(path):
            print(f"--verify: {label} {path} does not exist", file=sys.stderr)
            return 2

    # B01 (任务书 #131): the report write used to be unconditional and last --
    # `--report` naming the candidate (or the reference, the manifest, or a
    # raw-mirror blob) truncated a verified input into JSON. Check before the
    # read-only verification even runs, so a rejected invocation writes
    # nothing at all.
    collision = report_output_collisions(
        "--verify",
        [
            ("--candidate", candidate),
            ("--manifest", manifest_path),
            ("--reference", reference),
            ("--mirror", mirror_root),
            *[("--candidate sidecar", path) for path in sqlite_sidecar_paths(candidate)],
            *[("--reference sidecar", path) for path in sqlite_sidecar_paths(reference)],
        ],
        [("--report", report_path)],
    )
    if collision is not None:
        print(collision, file=sys.stderr)
        return 2

    try:
        failures, report = _verify_once(
            candidate, manifest_path, reference, mirror_root, sample_rebuild, seed, paths_cfg
        )
    except _NotV6 as not_v6:
        print(
            f"--verify: candidate {not_v6} is not a v6 library "
            "(`messages` has no `excluded` column)",
            file=sys.stderr,
        )
        return 2

    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    for label, detail in failures[:VERIFY_MAX_LISTED_FAILURES]:
        print(f"FAIL {label}: {detail}")
    if len(failures) > VERIFY_MAX_LISTED_FAILURES:
        print(f"... and {len(failures) - VERIFY_MAX_LISTED_FAILURES} more")
    if failures:
        families = Counter(failure_family(detail) for _label, detail in failures)
        print("verify: failure families: " + ", ".join(f"{name}={count}" for name, count in families.most_common()))
    informational = {
        key: report[key]
        for key in ("extra_unchanged_no_body", "candidate_only_rows",
                    "body_retained_unexcludable", "candidate_excluded_beyond_manifest",
                    "beyond_manifest_unverifiable", "candidate_only_excluded",
                    "candidate_only_unjudgeable")
        if key in report
    }
    if any(informational.values()):
        print("verify: informational (not failures): " + ", ".join(f"{k}={v}" for k, v in informational.items()))
    print(
        f"verify: manifest={report['manifest_entries']} "
        f"non_manifest_rows={report['non_manifest_rows_checked']} "
        f"rebuild_ok={report['rebuild_ok']}/{report['rebuild_sample']} "
        f"failures={report['failures']}"
    )
    return 0 if not failures else 1


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
    # PR6 T5: `--verify` (T6 Step 3b). In this mode `--report` names a JSON
    # report instead of the markdown one the probe writes.
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--candidate")
    parser.add_argument("--manifest")
    parser.add_argument("--reference")
    parser.add_argument("--sample-rebuild", type=int, default=50)
    parser.add_argument("--seed", type=int, default=6)
    args = parser.parse_args(argv)

    paths_cfg = load_paths_config(args.paths)

    if args.selftest:
        ok = run_selftest(paths_cfg)
        sys.exit(0 if ok else 1)

    if args.verify:
        missing = [
            name
            for name, value in (
                ("--candidate", args.candidate),
                ("--manifest", args.manifest),
                ("--reference", args.reference),
                ("--mirror", args.mirror),
            )
            if not value
        ]
        if missing:
            parser.error("--verify requires " + ", ".join(missing))
        sys.exit(
            run_verify(
                candidate=args.candidate,
                manifest_path=args.manifest,
                reference=args.reference,
                mirror_root=args.mirror,
                sample_rebuild=args.sample_rebuild,
                seed=args.seed,
                report_path=args.report,
                paths_cfg=paths_cfg,
            )
        )

    if not args.db or not args.mirror:
        parser.error("--db and --mirror are required unless --selftest")

    # B01 (任务书 #131): `run_probe` returns the integer 2 when it refused an
    # output/input collision, and its usual `(manifest, stats)` tuple
    # otherwise -- the tuple must never reach `sys.exit` (which would print it
    # and exit 1).
    probe_outcome = run_probe(args.db, args.mirror, paths_cfg, args.out, args.report, limit=args.limit)
    sys.exit(probe_outcome if isinstance(probe_outcome, int) else 0)


if __name__ == "__main__":
    main()
