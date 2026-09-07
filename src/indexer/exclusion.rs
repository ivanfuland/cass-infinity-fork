//! PR6 "进库口径收口" (任务书 #113, T2a): injected-context exclusion
//! judgment (`decide`) and replacement (`apply`/`apply_sibling`).
//!
//! This module is the Rust counterpart of `scripts/oracle/exclusion_probe.py`
//! (the "first executable form" of the rules, plan Task 1b) and implements
//! `docs/excluded-rules.md` R1-R12 verbatim -- every judgment branch below
//! cites the rule sub-number it implements so tests, the probe, and this
//! module stay traceable to one another.
//!
//! `decide` is a pure structural function (Global Constraints: "排除判定只
//! 看结构锚点...不看内容子串") operating on [`RawEvent`]/[`RawBlock`] --
//! connector-agnostic facts reconstructed by reparsing a raw-mirror blob
//! (T2b, 任务书 #114), not on the DB's own `extra_json`/`extra_bin` (already
//! compressed by the time a row exists, R7 note). `apply`/`apply_sibling`
//! then do the actual content/extra replacement once a [`Decision`] exists.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::connectors::NormalizedMessage;
use crate::indexer::redact_secrets::MemoizingRedactor;
use crate::sources::config::ExcludedContextPaths;

// ============================================================================
// R6: `excluded` column shape (schema v6 JSONB).
// ============================================================================

/// The three exclusion reasons (R1/R2/R3). `serde` renames match the JSON
/// strings in R6's example verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    CassRecall,
    ContextFileRead,
    CodexHostShell,
}

/// `anchor` sub-object (R6): which structural fact triggered the decision.
/// Exactly one of `tool_call_id`/`tool_name` (R1/R2) or `shell` (R3) is
/// populated per reason; `paths` is R2-only.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct ExclusionAnchor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<ShellAnchor>,
}

/// R3's `anchor.shell` sub-object: the opener actually seen (never
/// backfilled) plus the fixed closer.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ShellAnchor {
    pub opener: String,
    pub closer: String,
}

/// R1-c: cass-mcp tool_result hits, parsed from the (pre-redaction) content
/// when parsing succeeds. `sessions`/`message_ids` per R6's example.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RecallSrc {
    pub sessions: Vec<String>,
    pub message_ids: Vec<i64>,
}

/// R6 `raw` sub-object: locates the message inside the raw-mirror blob and
/// the original event, for audit/rebuild and for `mirror prune`'s reference
/// protection (R9).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RawRef {
    /// Manifest-relative blob path, e.g. `blobs/blake3/ab/ab12...cd.raw`.
    pub blob: String,
    /// This message's index in "reparse the blob from scratch" order.
    pub idx: u32,
    /// Original event identity (claude_code top-level `uuid`; codex `id`,
    /// or `line:<1-based line number>` when absent) -- independent of
    /// `tool_call_id`, so an id-less R4 pairing still has one.
    pub event_key: String,
    /// Indices into the event's `content[]` that were redacted. Empty when
    /// the message's own `extra` carries no body-bearing copy to redact
    /// (R7's "compact/精简形态" case -- see `apply`'s doc comment).
    pub blocks: Vec<u32>,
}

/// The full `messages.excluded` JSONB shape (R6). Every field is written on
/// every marker (schema v6 DDL has no partial-marker concept); `parse_error`
/// is non-null only for R1-c (cass-mcp hits JSON parse failure), and then
/// `src` is `None`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ExcludedMarker {
    pub reason: ExclusionReason,
    pub rule_version: u32,
    pub bytes: u64,
    pub sha256: String,
    pub fingerprint_blake3: String,
    pub anchor: ExclusionAnchor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<RecallSrc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
    pub raw: RawRef,
}

impl ExcludedMarker {
    /// JSON text form written into the JSONB column via `jsonb(?)` (SQL
    /// side does the JSONB encoding -- see R6/T2a mission Interfaces).
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).expect("ExcludedMarker fields are all JSON-representable")
    }

    /// Inverse of [`Self::to_json_string`], for reading a JSONB column back
    /// via `json(excluded)`.
    pub fn from_json_str(s: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

// ============================================================================
// Raw-mirror-reparsed event/block facts (built by T2b's `reparse_from_capture`,
// consumed here by `decide`/`apply`).
// ============================================================================

/// Coarse classification of one element in an event's `content[]` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    ToolUse,
    ToolResult,
    Text,
    Other,
}

/// One block inside a [`RawEvent`]'s `content[]` (or codex's single
/// `payload.output`/`payload.content` string, conventionally represented as
/// one block at index 0 -- see R6 `raw.blocks` note).
#[derive(Debug, Clone)]
pub struct RawBlock {
    pub index: u32,
    pub kind: BlockKind,
    pub tool_use_id: Option<String>,
    pub tool_name: Option<String>,
    pub args: Option<serde_json::Value>,
}

/// One original event (claude_code JSONL line; codex `response_item`),
/// reconstructed by reparsing the raw-mirror blob -- the sole source of
/// structural facts for judgment (Global Constraints §2.2: "宁漏勿误").
#[derive(Debug, Clone)]
pub struct RawEvent {
    pub event_key: String,
    pub blocks: Vec<RawBlock>,
}

// ============================================================================
// R4: pairing.
// ============================================================================

/// A resolved tool_call's identity, as needed by R1/R2 judgment.
#[derive(Debug, Clone, PartialEq)]
pub struct PairedTool {
    pub tool_call_id: Option<String>,
    pub tool_name: String,
    pub args: Option<serde_json::Value>,
}

/// One position in session order, as seen by R4 pairing. `TurnBoundary`
/// (a `user`-role row) clears the in-turn unpaired-tool_call set; `ToolCall`
/// accumulates into it; `ToolResult` either resolves by `tool_call_id` (any
/// earlier tool_call, any turn) or, when id-less, by "exactly one unpaired
/// tool_call since the last turn boundary" (R4).
#[derive(Debug, Clone)]
pub enum PairingCandidate {
    TurnBoundary,
    ToolCall(PairedTool),
    ToolResult { tool_call_id: Option<String> },
}

/// Session-wide R4 resolution, precomputed once by [`PairingContext::build`]
/// and consulted by `decide` per message position. Mirrors
/// `exclusion_probe.py`'s `PairingContext` (that file's own comment: "the
/// FIRST executable form... mirrors src/indexer/exclusion.rs decide").
#[derive(Debug, Clone, Default)]
pub struct PairingContext {
    resolved: HashMap<usize, PairedTool>,
}

impl PairingContext {
    pub fn build(candidates: &[PairingCandidate]) -> Self {
        let mut by_id: HashMap<&str, &PairedTool> = HashMap::new();
        for c in candidates {
            if let PairingCandidate::ToolCall(pt) = c {
                if let Some(id) = pt.tool_call_id.as_deref() {
                    by_id.insert(id, pt);
                }
            }
        }

        let mut resolved: HashMap<usize, PairedTool> = HashMap::new();
        let mut unpaired: Vec<usize> = Vec::new();
        for (idx, c) in candidates.iter().enumerate() {
            match c {
                PairingCandidate::TurnBoundary => unpaired.clear(),
                PairingCandidate::ToolCall(_) => unpaired.push(idx),
                PairingCandidate::ToolResult { tool_call_id } => {
                    if let Some(id) = tool_call_id {
                        if let Some(pt) = by_id.get(id.as_str()) {
                            resolved.insert(idx, (*pt).clone());
                            if let Some(pos) = unpaired.iter().position(|&i| {
                                matches!(&candidates[i], PairingCandidate::ToolCall(p) if p.tool_call_id.as_deref() == Some(id.as_str()))
                            }) {
                                unpaired.remove(pos);
                            }
                        }
                        // id given but not found in `by_id` -> R4: not
                        // excluded (no entry in `resolved`).
                    } else if unpaired.len() == 1 {
                        let call_idx = unpaired.remove(0);
                        if let PairingCandidate::ToolCall(pt) = &candidates[call_idx] {
                            resolved.insert(idx, pt.clone());
                        }
                    }
                    // 0 or >=2 unpaired candidates -> R4: not excluded,
                    // `unpaired` left untouched (matches the python
                    // reference: ambiguity doesn't consume candidates).
                }
            }
        }
        PairingContext { resolved }
    }

    pub fn paired_call_for(&self, idx: usize) -> Option<&PairedTool> {
        self.resolved.get(&idx)
    }
}

// ============================================================================
// R1/R11: cass-mcp tool identity (v4.4 -- per-connector alias table, not a
// universal prefix).
// ============================================================================

const CASS_RECALL_PREFIX: &str = "mcp__cass-mcp__";

fn cass_recall_bare_names(agent_slug: &str) -> &'static [&'static str] {
    match agent_slug {
        "codex" => &["cass_search", "cass_expand"],
        _ => &[],
    }
}

/// R1 (v4.4, Ivan 2026-09-07 裁): `claude_code` matches any full name under
/// the `mcp__cass-mcp__` prefix; `codex` matches only its registered bare
/// names (R11: `cass_search`/`cass_expand`, T1b found 8 such calls). No
/// other connector matches (宁漏勿误).
fn is_cass_recall_tool(tool_name: &str, agent_slug: &str) -> bool {
    if agent_slug == "claude_code" {
        tool_name.starts_with(CASS_RECALL_PREFIX)
    } else {
        cass_recall_bare_names(agent_slug).contains(&tool_name)
    }
}

// ============================================================================
// R2/R11: read-tool identities + Bash read-only subset + predicate P.
// ============================================================================

struct ReadToolIdentities {
    read: Option<&'static str>,
    project_read: &'static str,
    bash: &'static str,
    bash_arg_key: &'static str,
}

/// R11 alias table. Only `claude_code`/`codex` are populated (T1b backfilled
/// these two; other connectors have zero镜像 coverage and stay
/// "不启用" -- see `docs/excluded-rules.md` R7/R11).
fn read_tool_identities(agent_slug: &str) -> Option<ReadToolIdentities> {
    match agent_slug {
        "claude_code" => Some(ReadToolIdentities {
            read: Some("Read"),
            project_read: "mcp__ccw-control-plane__project_read",
            bash: "Bash",
            bash_arg_key: "command",
        }),
        "codex" => Some(ReadToolIdentities {
            read: None,
            project_read: "project_read",
            bash: "exec_command",
            bash_arg_key: "cmd",
        }),
        _ => None,
    }
}

/// Same normalization as `exclusion_probe.py::_normalize_path`: forward
/// slashes, collapse `.`/`..` segments without touching the filesystem.
fn normalize_path(p: &str) -> String {
    let p = p.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                if matches!(parts.last(), Some(&last) if last != "..") {
                    parts.pop();
                } else {
                    parts.push(seg);
                }
            }
            _ => parts.push(seg),
        }
    }
    let prefix = if p.starts_with('/') { "/" } else { "" };
    format!("{prefix}{}", parts.join("/"))
}

fn anchored_under_cc_workspace(normalized: &str, base: &str) -> bool {
    // `(^|/)cc-workspace(/\.worktrees/[^/]+)?/<base>$`, hand-rolled (no
    // regex compile per call): find a `cc-workspace` path segment, then
    // require the remainder to be either `/<base>` directly or
    // `/.worktrees/<one segment>/<base>`.
    let mut search_from = 0usize;
    while let Some(rel) = normalized[search_from..].find("cc-workspace") {
        let pos = search_from + rel;
        let at_start = pos == 0;
        let boundary_ok = at_start || normalized.as_bytes()[pos - 1] == b'/';
        if boundary_ok {
            let after = &normalized[pos + "cc-workspace".len()..];
            let direct = format!("/{base}");
            if after == direct {
                return true;
            }
            if let Some(rest) = after.strip_prefix("/.worktrees/") {
                if let Some((worktree_seg, tail)) = rest.split_once('/') {
                    if !worktree_seg.is_empty() && tail == base {
                        return true;
                    }
                }
            }
        }
        search_from = pos + "cc-workspace".len();
    }
    false
}

/// R2 谓词 P.
fn predicate_p(raw_path: &str, paths_cfg: &ExcludedContextPaths) -> bool {
    let normalized = normalize_path(raw_path);
    let base = normalized.rsplit('/').next().unwrap_or(&normalized);

    if paths_cfg.memory_files.iter().any(|f| f == base) && anchored_under_cc_workspace(&normalized, base) {
        return true;
    }
    if paths_cfg.injection_only_files.iter().any(|f| f == base) {
        return true;
    }
    if paths_cfg.workspace_scoped_files.iter().any(|f| f == base) && anchored_under_cc_workspace(&normalized, base) {
        return true;
    }
    false
}

fn predicate_p_project_read_document(document: &str, paths_cfg: &ExcludedContextPaths) -> bool {
    paths_cfg.project_read_documents.iter().any(|d| d == document)
}

/// R2 Bash 只读子集 -- two-step SYNTAX judgment, not regex-on-whole-string:
/// reject any compound-shell form outright (R2-e), then match the survivor
/// against the six literal shapes (v4.4 added `nl`). Returns the extracted
/// path list, or `None` when the command doesn't match / is complex enough
/// that the caller must treat it as "not excluded" (R2-e/宁漏勿误).
fn bash_readonly_paths(command: &str) -> Option<Vec<String>> {
    if command.contains(['|', ';', '&', '<', '>', '`', '*', '?', '[', ']', '$']) {
        return None;
    }
    let tokens = shell_words::split(command).ok()?;
    let (head, rest) = tokens.split_first()?;

    let all_plain = |paths: &[String]| !paths.is_empty() && paths.iter().all(|t| !t.starts_with('-'));

    match head.as_str() {
        "cat" => all_plain(rest).then(|| rest.to_vec()),
        "head" | "tail" => {
            let paths: &[String] =
                if rest.len() >= 3 && rest[0] == "-n" && rest[1].chars().all(|c| c.is_ascii_digit()) && !rest[1].is_empty() {
                    &rest[2..]
                } else {
                    rest
                };
            all_plain(paths).then(|| paths.to_vec())
        }
        "sed" => {
            if rest.len() >= 3 && rest[0] == "-n" {
                let script = &rest[1];
                let is_line = |s: &str| !s.is_empty() && s.ends_with('p') && s[..s.len() - 1].chars().all(|c| c.is_ascii_digit());
                let is_range = |s: &str| {
                    s.ends_with('p')
                        && s[..s.len() - 1].split_once(',').is_some_and(|(a, b)| {
                            !a.is_empty() && !b.is_empty() && a.chars().all(|c| c.is_ascii_digit()) && b.chars().all(|c| c.is_ascii_digit())
                        })
                };
                if is_line(script) || is_range(script) {
                    let paths = &rest[2..];
                    return all_plain(paths).then(|| paths.to_vec());
                }
            }
            None
        }
        "nl" => {
            // v4.4 sixth form: `nl [-ba] <paths>`.
            let paths: &[String] = if rest.first().map(String::as_str) == Some("-ba") { &rest[1..] } else { rest };
            all_plain(paths).then(|| paths.to_vec())
        }
        _ => None,
    }
}

// ============================================================================
// R3: `codex_host_shell`.
// ============================================================================

const ENVIRONMENT_CONTEXT_OPEN: &str = "<environment_context>";
const ENVIRONMENT_CONTEXT_CLOSE: &str = "</environment_context>";
const ANCHOR3_OPENERS: [&str; 3] = ["# AGENTS.md instructions", "<recommended_plugins>", ENVIRONMENT_CONTEXT_OPEN];

/// R3's match condition (docs/excluded-rules.md R3, spec §2.1) is CONTAINS,
/// not STARTS-WITH: "含 `<environment_context>` 开标记...以
/// `</environment_context>` 结尾" -- "开标记" names the *tag* (an opening
/// tag, as opposed to the closing one), not a requirement that the message
/// itself begin with it. `startswith` is only used afterward to fill in
/// `anchor.shell.opener`'s recorded value (one of the 3 known constants);
/// R3-f (a real request with a full env-context block pasted at the end,
/// "已知漏判方向") still matches even though the message starts with the
/// user's own words -- falls back to recording the structural tag itself
/// as the opener in that case, since some value must be written and
/// claiming it started with one of the other two openers would be a lie.
fn anchor3_shell_opener(text: &str) -> Option<&'static str> {
    let trimmed = text.trim();
    if !trimmed.ends_with(ENVIRONMENT_CONTEXT_CLOSE) {
        return None;
    }
    if !trimmed.contains(ENVIRONMENT_CONTEXT_OPEN) || !trimmed.contains("<cwd>") {
        return None;
    }
    Some(ANCHOR3_OPENERS.iter().find(|o| trimmed.starts_with(**o)).copied().unwrap_or(ENVIRONMENT_CONTEXT_OPEN))
}

// ============================================================================
// `Decision` + `decide`.
// ============================================================================

/// The judgment output: which rule fired, on which event/blocks. Carries no
/// content-derived fields (those belong to [`ExcludedMarker`], built later
/// by `apply` once redaction has actually happened).
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub reason: ExclusionReason,
    pub anchor: ExclusionAnchor,
    pub event_key: String,
    pub target_blocks: Vec<u32>,
}

/// Indices of `event`'s `ToolResult`-kind blocks that this decision should
/// clear: when `tool_call_id` is known, only the block(s) whose own
/// `tool_use_id` matches it; when pairing was id-less (R4's "exactly one
/// unpaired" branch), every `ToolResult` block without its own id is
/// presumed to belong to the row currently being judged.
fn tool_result_block_indices(event: &RawEvent, tool_call_id: Option<&str>) -> Vec<u32> {
    event
        .blocks
        .iter()
        .filter(|b| b.kind == BlockKind::ToolResult)
        .filter(|b| match (b.tool_use_id.as_deref(), tool_call_id) {
            (Some(bid), Some(id)) => bid == id,
            (None, _) => true,
            (Some(_), None) => false,
        })
        .map(|b| b.index)
        .collect()
}

fn decide_r1_r2_for_call(call: &PairedTool, event: &RawEvent, agent_slug: &str, paths_cfg: &ExcludedContextPaths) -> Option<Decision> {
    let tool_name = call.tool_name.as_str();

    if is_cass_recall_tool(tool_name, agent_slug) {
        return Some(Decision {
            reason: ExclusionReason::CassRecall,
            anchor: ExclusionAnchor {
                tool_call_id: call.tool_call_id.clone(),
                tool_name: Some(tool_name.to_string()),
                paths: None,
                shell: None,
            },
            event_key: event.event_key.clone(),
            target_blocks: tool_result_block_indices(event, call.tool_call_id.as_deref()),
        });
    }

    let identities = read_tool_identities(agent_slug)?;
    let args = call.args.as_ref()?;

    if identities.read == Some(tool_name) {
        let file_path = args.get("file_path")?.as_str()?;
        if !predicate_p(file_path, paths_cfg) {
            return None;
        }
        return Some(Decision {
            reason: ExclusionReason::ContextFileRead,
            anchor: ExclusionAnchor {
                tool_call_id: call.tool_call_id.clone(),
                tool_name: Some(tool_name.to_string()),
                paths: Some(vec![file_path.to_string()]),
                shell: None,
            },
            event_key: event.event_key.clone(),
            target_blocks: tool_result_block_indices(event, call.tool_call_id.as_deref()),
        });
    }

    if identities.project_read == tool_name {
        let document = args.get("document")?.as_str()?;
        if !predicate_p_project_read_document(document, paths_cfg) {
            return None;
        }
        return Some(Decision {
            reason: ExclusionReason::ContextFileRead,
            anchor: ExclusionAnchor {
                tool_call_id: call.tool_call_id.clone(),
                tool_name: Some(tool_name.to_string()),
                paths: Some(vec![document.to_string()]),
                shell: None,
            },
            event_key: event.event_key.clone(),
            target_blocks: tool_result_block_indices(event, call.tool_call_id.as_deref()),
        });
    }

    if identities.bash == tool_name {
        let command = args.get(identities.bash_arg_key)?.as_str()?;
        let bash_paths = bash_readonly_paths(command)?;
        if bash_paths.is_empty() || !bash_paths.iter().all(|p| predicate_p(p, paths_cfg)) {
            return None;
        }
        return Some(Decision {
            reason: ExclusionReason::ContextFileRead,
            anchor: ExclusionAnchor {
                tool_call_id: call.tool_call_id.clone(),
                tool_name: Some(tool_name.to_string()),
                paths: Some(bash_paths),
                shell: None,
            },
            event_key: event.event_key.clone(),
            target_blocks: tool_result_block_indices(event, call.tool_call_id.as_deref()),
        });
    }

    None
}

/// R1-R4 judgment (pure function, structure only -- Global Constraints).
/// `idx` is this message's position in session order, the same indexing
/// space [`PairingContext`] was built over.
pub(crate) fn decide(
    msg: &NormalizedMessage,
    idx: usize,
    event: &RawEvent,
    ctx: &PairingContext,
    agent_slug: &str,
    paths_cfg: &ExcludedContextPaths,
) -> Option<Decision> {
    if msg.role == "tool_result" {
        if let Some(call) = ctx.paired_call_for(idx) {
            if let Some(decision) = decide_r1_r2_for_call(call, event, agent_slug, paths_cfg) {
                return Some(decision);
            }
        }
    }

    if agent_slug == "codex" && msg.role == "user" && idx == 0 {
        if let Some(opener) = anchor3_shell_opener(&msg.content) {
            let target_blocks: Vec<u32> = event.blocks.iter().filter(|b| b.kind == BlockKind::Text).map(|b| b.index).collect();
            return Some(Decision {
                reason: ExclusionReason::CodexHostShell,
                anchor: ExclusionAnchor {
                    tool_call_id: None,
                    tool_name: None,
                    paths: None,
                    shell: Some(ShellAnchor { opener: opener.to_string(), closer: ENVIRONMENT_CONTEXT_CLOSE.to_string() }),
                },
                event_key: event.event_key.clone(),
                target_blocks,
            });
        }
    }

    None
}

// ============================================================================
// R7: connector body-field map + `apply`/`apply_sibling`.
// ============================================================================

/// R7 constant table: per connector, dot-separated JSON paths (small DSL --
/// `[*]` on a segment means "array; only touch elements whose index is in
/// this decision's `target_blocks`", matching `raw.blocks`' own indexing).
/// `historical_raw_json`'s string-wrapped JSON (`sqlite.rs`'s
/// `__cass_historical_raw_json__` sentinel) is handled separately in
/// [`apply_extra`] since it wraps the *entire* `extra` value, not a
/// sub-field the DSL can address.
pub const EXTRA_FIELD_MAP: &[(&str, &[&str])] = &[
    ("claude_code", &["message.content[*].content", "message.content[*].text", "toolUseResult.file.content"]),
    ("codex", &["payload.output[*].text", "payload.content[*].text", "payload.arguments", "payload.input"]),
];

/// Resolved per-connector path list -- what `apply`/`apply_sibling` actually
/// take (the caller looks up [`EXTRA_FIELD_MAP`] by `agent_slug` once and
/// passes the slice in).
pub type ExtraFieldMap = &'static [&'static str];

pub fn field_map_for(agent_slug: &str) -> ExtraFieldMap {
    EXTRA_FIELD_MAP.iter().find(|(slug, _)| *slug == agent_slug).map_or(&[], |(_, paths)| *paths)
}

const HISTORICAL_RAW_JSON_SENTINEL_KEY: &str = "__cass_historical_raw_json__";

fn apply_path(value: &mut serde_json::Value, segments: &[&str], target_blocks: &[u32], placeholder: &serde_json::Value) {
    let Some((seg, rest)) = segments.split_first() else { return };
    if let Some(key) = seg.strip_suffix("[*]") {
        if let Some(arr) = value.get_mut(key).and_then(|v| v.as_array_mut()) {
            for &i in target_blocks {
                if let Some(elem) = arr.get_mut(i as usize) {
                    if rest.is_empty() {
                        *elem = placeholder.clone();
                    } else {
                        apply_path(elem, rest, target_blocks, placeholder);
                    }
                }
            }
        }
    } else if rest.is_empty() {
        if let Some(obj) = value.as_object_mut() {
            if obj.contains_key(*seg) {
                obj.insert((*seg).to_string(), placeholder.clone());
            }
        }
    } else if let Some(next) = value.get_mut(*seg) {
        apply_path(next, rest, target_blocks, placeholder);
    }
}

/// Replace every R7 field map path's leaf value with `placeholder`, only at
/// `target_blocks` positions for array (`[*]`) segments. Unwraps/rewraps the
/// `historical_raw_json` string envelope first when present (R7 note): the
/// whole `extra` value being exactly `{"__cass_historical_raw_json__": "..."}`
/// means the real event JSON lives inside that string.
fn apply_extra(extra: &mut serde_json::Value, field_map: ExtraFieldMap, target_blocks: &[u32], placeholder: &serde_json::Value) {
    let historical = matches!(extra, serde_json::Value::Object(m) if m.len() == 1 && m.contains_key(HISTORICAL_RAW_JSON_SENTINEL_KEY));
    if historical {
        let raw = extra[HISTORICAL_RAW_JSON_SENTINEL_KEY].as_str().unwrap_or_default().to_string();
        if let Ok(mut inner) = serde_json::from_str::<serde_json::Value>(&raw) {
            for path in field_map {
                let segments: Vec<&str> = path.split('.').collect();
                apply_path(&mut inner, &segments, target_blocks, placeholder);
            }
            let rewritten = serde_json::to_string(&inner).unwrap_or(raw);
            extra[HISTORICAL_RAW_JSON_SENTINEL_KEY] = serde_json::Value::String(rewritten);
        }
        return;
    }
    for path in field_map {
        let segments: Vec<&str> = path.split('.').collect();
        apply_path(extra, &segments, target_blocks, placeholder);
    }
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn blake3_hex(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

/// R1-c: parse a cass-mcp tool_result's hits JSON into [`RecallSrc`].
/// Implementation detail left to this round (spec §一 发挥空间): a top-level
/// JSON object with a `hits` array, each element carrying `session_id`
/// (string) and `message_id` (integer). Any other shape, or invalid JSON,
/// is a parse failure (`src = None`, `parse_error = Some(reason)`) --
/// `decide` already committed to `reason = CassRecall` regardless, per R1-c.
fn parse_recall_hits(content: &str) -> Result<RecallSrc, String> {
    let value: serde_json::Value = serde_json::from_str(content).map_err(|e| format!("invalid JSON: {e}"))?;
    let hits = value.get("hits").and_then(|v| v.as_array()).ok_or_else(|| "missing `hits` array".to_string())?;
    let mut sessions = Vec::with_capacity(hits.len());
    let mut message_ids = Vec::with_capacity(hits.len());
    for (i, hit) in hits.iter().enumerate() {
        let session_id = hit.get("session_id").and_then(|v| v.as_str()).ok_or_else(|| format!("hits[{i}] missing session_id"))?;
        let message_id = hit.get("message_id").and_then(|v| v.as_i64()).ok_or_else(|| format!("hits[{i}] missing message_id"))?;
        sessions.push(session_id.to_string());
        message_ids.push(message_id);
    }
    Ok(RecallSrc { sessions, message_ids })
}

/// Apply a [`Decision`] to the row it was computed for: redact `content`,
/// compute the marker's `sha256`/`fingerprint_blake3`/`bytes` against the
/// *redacted* string (R5: redactor runs before hashing), replace the R7
/// field-map paths in `extra` (only at `decision.target_blocks`), and clear
/// every attached snippet's text (R2.2: "snippets 表中该消息的所有行
/// snippet_text 置 ''"). `blob`/`idx` become `marker.raw.blob`/`raw.idx`
/// verbatim (T2b supplies both from the raw-mirror capture, out of this
/// function's own knowledge).
///
/// `field_map` is the *already-resolved* per-connector path list (see
/// [`field_map_for`]) -- when it doesn't recognize any of `extra`'s shape
/// (R7's "精简/compact" ~31% case: only `raw_role`/`tool_call_id`/
/// `tool_call_args` survive prior compression), every path silently misses
/// and `extra` comes out byte-identical; that's expected, not a bug.
pub(crate) fn apply(
    msg: &mut NormalizedMessage,
    decision: &Decision,
    redactor: &mut MemoizingRedactor,
    blob: &str,
    idx: u32,
    field_map: ExtraFieldMap,
) -> ExcludedMarker {
    let original = std::mem::take(&mut msg.content);
    let redacted = redactor.redact_text(&original);

    let (src, parse_error) = if decision.reason == ExclusionReason::CassRecall {
        match parse_recall_hits(&original) {
            Ok(s) => (Some(s), None),
            Err(e) => (None, Some(e)),
        }
    } else {
        (None, None)
    };

    let marker = ExcludedMarker {
        reason: decision.reason,
        rule_version: 1,
        bytes: redacted.len() as u64,
        sha256: sha256_hex(&redacted),
        fingerprint_blake3: blake3_hex(&redacted),
        anchor: decision.anchor.clone(),
        src,
        parse_error,
        raw: RawRef { blob: blob.to_string(), idx, event_key: decision.event_key.clone(), blocks: decision.target_blocks.clone() },
    };

    let placeholder = serde_json::json!({"redacted": true, "sha256": marker.sha256, "bytes": marker.bytes});
    apply_extra(&mut msg.extra, field_map, &decision.target_blocks, &placeholder);

    for snippet in &mut msg.snippets {
        snippet.snippet_text = Some(String::new());
    }

    marker
}

/// Replace the same `target_blocks` in another row's `extra` that shares
/// `marker.raw.event_key` with the row [`apply`] just processed (the
/// "same-event, projected-into-multiple-rows" case, R2.2's `Message`未命中
/// 例外). Content is *not* touched and no new marker is produced -- this
/// row is not itself excluded, only its copy of the same event blocks is.
pub(crate) fn apply_sibling(msg: &mut NormalizedMessage, marker: &ExcludedMarker, field_map: ExtraFieldMap) {
    let placeholder = serde_json::json!({"redacted": true, "sha256": marker.sha256, "bytes": marker.bytes});
    apply_extra(&mut msg.extra, field_map, &marker.raw.blocks, &placeholder);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths_cfg() -> ExcludedContextPaths {
        ExcludedContextPaths::default()
    }

    fn text_block(index: u32) -> RawBlock {
        RawBlock { index, kind: BlockKind::Text, tool_use_id: None, tool_name: None, args: None }
    }

    fn tool_use_block(index: u32, id: &str, name: &str, args: serde_json::Value) -> RawBlock {
        RawBlock { index, kind: BlockKind::ToolUse, tool_use_id: Some(id.to_string()), tool_name: Some(name.to_string()), args: Some(args) }
    }

    fn tool_result_block(index: u32, id: Option<&str>) -> RawBlock {
        RawBlock { index, kind: BlockKind::ToolResult, tool_use_id: id.map(str::to_string), tool_name: None, args: None }
    }

    fn msg(role: &str, content: &str) -> NormalizedMessage {
        NormalizedMessage {
            idx: 0,
            role: role.to_string(),
            author: None,
            created_at: None,
            content: content.to_string(),
            extra: serde_json::json!({}),
            snippets: Vec::new(),
            invocations: Vec::new(),
        }
    }

    fn ctx_from(candidates: &[PairingCandidate]) -> PairingContext {
        PairingContext::build(candidates)
    }

    // -- R1 -------------------------------------------------------------

    #[test]
    fn r1_a_claude_code_full_name_prefix_match_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool { tool_call_id: Some("t1".into()), tool_name: "mcp__cass-mcp__cass_search".into(), args: None }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "{}");
        let decision = decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).expect("R1-a must match");
        assert_eq!(decision.reason, ExclusionReason::CassRecall);
        assert_eq!(decision.target_blocks, vec![0]);
    }

    #[test]
    fn r1_b_same_suffix_wrong_mcp_prefix_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool { tool_call_id: Some("t1".into()), tool_name: "mcp__other-mcp__cass_search".into(), args: None }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "{}");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(), "R1-b must not match");
    }

    #[test]
    fn r1_d_codex_bare_name_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool { tool_call_id: Some("t1".into()), tool_name: "cass_search".into(), args: None }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "{}");
        let decision = decide(&m, 1, &event, &ctx, "codex", &paths_cfg()).expect("R1-d bare name must match under codex");
        assert_eq!(decision.reason, ExclusionReason::CassRecall);
    }

    #[test]
    fn r1_d_codex_bare_name_not_in_alias_table_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool { tool_call_id: Some("t1".into()), tool_name: "search".into(), args: None }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "{}");
        assert!(decide(&m, 1, &event, &ctx, "codex", &paths_cfg()).is_none(), "an unregistered bare name must not match R1");
    }

    // -- R2 ---------------------------------------------------------------

    #[test]
    fn r2_a_read_cc_workspace_root_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Read".into(),
                args: Some(serde_json::json!({"file_path": "/home/ivan/projects/cc-workspace/MEMORY.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        let decision = decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).expect("R2-a must match");
        assert_eq!(decision.reason, ExclusionReason::ContextFileRead);
    }

    #[test]
    fn r2_b_deep_doc_not_anchored_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Read".into(),
                args: Some(serde_json::json!({"file_path": "/home/ivan/projects/cc-workspace/reports/USER.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(), "deep doc must not match (R2-b)");
    }

    #[test]
    fn r2_worktree_root_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Read".into(),
                args: Some(serde_json::json!({"file_path": "/home/ivan/projects/cc-workspace/.worktrees/feat-x/CLAUDE.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_some(), "worktree-root CLAUDE.md must match");
    }

    #[test]
    fn r2_project_read_document_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "mcp__ccw-control-plane__project_read".into(),
                args: Some(serde_json::json!({"document": "exec"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "exec doc contents");
        let decision = decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).expect("R2-g must match");
        assert_eq!(decision.reason, ExclusionReason::ContextFileRead);
    }

    #[test]
    fn r2_codex_exec_command_cmd_key_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "exec_command".into(),
                args: Some(serde_json::json!({"cmd": "cat /home/ivan/projects/cc-workspace/MEMORY.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "codex", &paths_cfg()).is_some(), "codex exec_command with `cmd` key must match");
    }

    #[test]
    fn r2_f_cat_a_b_both_satisfy_p_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Bash".into(),
                args: Some(serde_json::json!({
                    "command": "cat /home/ivan/projects/cc-workspace/MEMORY.md /home/ivan/projects/cc-workspace/USER.md"
                })),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_some());
    }

    #[test]
    fn r2_f_cat_a_b_mixed_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Bash".into(),
                args: Some(serde_json::json!({"command": "cat /home/ivan/projects/cc-workspace/MEMORY.md /tmp/notes.txt"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(), "mixed satisfy/not-satisfy must not match (R2-f)");
    }

    #[test]
    fn r2_e_compound_command_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Bash".into(),
                args: Some(serde_json::json!({"command": "cat /home/ivan/projects/cc-workspace/MEMORY.md | grep foo"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(), "compound command must not match (R2-e)");
    }

    #[test]
    fn r2_h_sed_e_command_rejected_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Bash".into(),
                args: Some(serde_json::json!({"command": "sed -n '1e date' /home/ivan/projects/cc-workspace/MEMORY.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(), "sed script with `e` command must not match (R2-h)");
    }

    #[test]
    fn r2_i_relative_path_only_injection_only_branch_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool { tool_call_id: Some("t1".into()), tool_name: "Read".into(), args: Some(serde_json::json!({"file_path": "CLAUDE.local.md"})) }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_some(), "R2-d: relative injection-only filename matches at any path");
    }

    #[test]
    fn r2_i_nl_ba_sixth_form_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "exec_command".into(),
                args: Some(serde_json::json!({"cmd": "nl -ba /home/ivan/projects/cc-workspace/MEMORY.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "codex", &paths_cfg()).is_some(), "R2-i: `nl -ba <path>` must match the sixth read-only form");
    }

    #[test]
    fn r2_i_nl_without_flag_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Bash".into(),
                args: Some(serde_json::json!({"command": "nl /home/ivan/projects/cc-workspace/MEMORY.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_some(), "bare `nl <path>` (no -ba) must still match");
    }

    // -- R3 ---------------------------------------------------------------

    #[test]
    fn r3_a_opener_agents_md_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![text_block(0)] };
        let ctx = PairingContext::default();
        let text = "# AGENTS.md instructions for X\nfoo\n<environment_context>\n<cwd>/x</cwd>\n</environment_context>";
        let m = msg("user", text);
        let decision = decide(&m, 0, &event, &ctx, "codex", &paths_cfg()).expect("R3-a must match");
        assert_eq!(decision.reason, ExclusionReason::CodexHostShell);
        assert_eq!(decision.anchor.shell.as_ref().unwrap().opener, "# AGENTS.md instructions");
    }

    #[test]
    fn r3_b_opener_recommended_plugins_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![text_block(0)] };
        let ctx = PairingContext::default();
        let text = "<recommended_plugins>\nfoo\n<environment_context>\n<cwd>/x</cwd>\n</environment_context>";
        let m = msg("user", text);
        let decision = decide(&m, 0, &event, &ctx, "codex", &paths_cfg()).expect("R3-b must match");
        assert_eq!(decision.anchor.shell.as_ref().unwrap().opener, "<recommended_plugins>");
    }

    #[test]
    fn r3_c_opener_environment_context_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![text_block(0)] };
        let ctx = PairingContext::default();
        let text = "<environment_context>\n<cwd>/x</cwd>\n</environment_context>";
        let m = msg("user", text);
        let decision = decide(&m, 0, &event, &ctx, "codex", &paths_cfg()).expect("R3-c must match");
        assert_eq!(decision.anchor.shell.as_ref().unwrap().opener, "<environment_context>");
    }

    #[test]
    fn r3_d_hand_written_instructions_no_env_block_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![text_block(0)] };
        let ctx = PairingContext::default();
        let m = msg("user", "<INSTRUCTIONS>do the thing</INSTRUCTIONS>");
        assert!(decide(&m, 0, &event, &ctx, "codex", &paths_cfg()).is_none(), "hand-written shell without env block must not match (R3-d)");
    }

    #[test]
    fn r3_e_idx_ne_0_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![text_block(0)] };
        let ctx = PairingContext::default();
        let text = "<environment_context>\n<cwd>/x</cwd>\n</environment_context>";
        let m = msg("user", text);
        assert!(decide(&m, 1, &event, &ctx, "codex", &paths_cfg()).is_none(), "idx != 0 must not match anchor 3 (R3-e)");
    }

    #[test]
    fn r3_f_full_structural_reference_known_missing_detection_direction() {
        // R3-f: a real request with a full <environment_context>...</environment_context>
        // block pasted at the end. The predicate cannot distinguish this from
        // the CLI-generated shell -- documented as a known miss direction
        // (spec §2.1 "已知取舍"), not a bug.
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![text_block(0)] };
        let ctx = PairingContext::default();
        let text = "please fix the bug in foo.rs\n<environment_context>\n<cwd>/x</cwd>\n</environment_context>";
        let m = msg("user", text);
        assert!(decide(&m, 0, &event, &ctx, "codex", &paths_cfg()).is_some(), "R3-f known-miss direction: this DOES match, by design");
    }

    #[test]
    fn r3_19_real_user_messages_without_closer_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![text_block(0)] };
        let ctx = PairingContext::default();
        for text in [
            "fix the login bug please",
            "<environment_context> not closed properly",
            "what does this function do?",
        ] {
            let m = msg("user", text);
            assert!(decide(&m, 0, &event, &ctx, "codex", &paths_cfg()).is_none(), "real user message must not match anchor 3: {text:?}");
        }
    }

    // -- R4 -----------------------------------------------------------------

    #[test]
    fn r4_zero_unpaired_candidates_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, None)] };
        let ctx = ctx_from(&[PairingCandidate::TurnBoundary, PairingCandidate::ToolResult { tool_call_id: None }]);
        let m = msg("tool_result", "{}");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(), "0 unpaired candidates -> no pairing (R4)");
    }

    #[test]
    fn r4_exactly_one_unpaired_candidate_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, None)] };
        let ctx = ctx_from(&[
            PairingCandidate::TurnBoundary,
            PairingCandidate::ToolCall(PairedTool { tool_call_id: None, tool_name: "mcp__cass-mcp__cass_search".into(), args: None }),
            PairingCandidate::ToolResult { tool_call_id: None },
        ]);
        let m = msg("tool_result", "{}");
        let decision = decide(&m, 2, &event, &ctx, "claude_code", &paths_cfg()).expect("exactly 1 unpaired candidate must pair");
        assert_eq!(decision.reason, ExclusionReason::CassRecall);
    }

    #[test]
    fn r4_two_unpaired_candidates_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, None)] };
        let ctx = ctx_from(&[
            PairingCandidate::TurnBoundary,
            PairingCandidate::ToolCall(PairedTool { tool_call_id: None, tool_name: "mcp__cass-mcp__cass_search".into(), args: None }),
            PairingCandidate::ToolCall(PairedTool { tool_call_id: None, tool_name: "mcp__cass-mcp__cass_expand".into(), args: None }),
            PairingCandidate::ToolResult { tool_call_id: None },
        ]);
        let m = msg("tool_result", "{}");
        assert!(decide(&m, 3, &event, &ctx, "claude_code", &paths_cfg()).is_none(), "2 unpaired candidates -> no pairing (R4)");
    }

    #[test]
    fn r4_missing_tool_name_never_happens_but_missing_args_negative() {
        // The type system already forbids a missing `tool_name` (`PairedTool.tool_name`
        // is a non-optional `String`) -- the structurally-equivalent gap R4
        // guards against is missing/invalid *arguments*, exercised here for R2.
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool { tool_call_id: Some("t1".into()), tool_name: "Read".into(), args: None }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(), "missing args must not match R2");
    }

    #[test]
    fn r1_c_mutation_removing_codex_alias_breaks_r1_d() {
        // Mutation for R1-d: without codex in the bare-name table, the R1-d
        // positive test above would go red. Exercised inline via the
        // predicate directly (no need to duplicate the full decide() setup).
        assert!(is_cass_recall_tool("cass_search", "codex"));
        assert!(!is_cass_recall_tool("cass_search", "gemini"), "an unlisted connector must never match (宁漏勿误)");
    }

    #[test]
    fn nl_mutation_removing_sixth_form_breaks_r2_i() {
        assert_eq!(bash_readonly_paths("nl -ba /a/b.md"), Some(vec!["/a/b.md".to_string()]));
        assert_eq!(bash_readonly_paths("nl -x /a/b.md"), None, "an unsupported nl flag must not match");
    }

    // -- apply/apply_sibling ------------------------------------------------

    fn decision_cass_recall(target_blocks: Vec<u32>) -> Decision {
        Decision {
            reason: ExclusionReason::CassRecall,
            anchor: ExclusionAnchor { tool_call_id: Some("t1".into()), tool_name: Some("mcp__cass-mcp__cass_search".into()), paths: None, shell: None },
            event_key: "ek1".into(),
            target_blocks,
        }
    }

    #[test]
    fn apply_clears_content_and_hashes_the_redacted_string() {
        let mut m = msg("tool_result", "here is my AKIAABCDEFGHIJKLMNOP secret and the rest of the hit");
        let decision = decision_cass_recall(vec![]);
        let mut redactor = MemoizingRedactor::new();
        let marker = apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 3, &[]);

        assert_eq!(m.content, "", "content must be cleared");
        assert_ne!(marker.sha256, sha256_hex("here is my AKIAABCDEFGHIJKLMNOP secret and the rest of the hit"), "sha must be over the REDACTED string, not the original");
        assert_eq!(marker.raw.blob, "blobs/blake3/ab/abcd.raw");
        assert_eq!(marker.raw.idx, 3);
        assert_eq!(marker.raw.event_key, "ek1");
    }

    #[test]
    fn apply_replaces_only_target_blocks_in_claude_code_extra() {
        let mut m = msg("tool_result", "secret file contents");
        m.extra = serde_json::json!({
            "message": {"content": [
                {"type": "tool_result", "text": "secret file contents"},
                {"type": "text", "text": "unrelated sibling block, must stay"}
            ]}
        });
        let decision = decision_cass_recall(vec![0]);
        let mut redactor = MemoizingRedactor::new();
        let field_map = field_map_for("claude_code");
        apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map);

        // R7's DSL replaces the leaf field the path names (`.text`), not
        // the whole array element -- sibling fields like `.type` on the
        // SAME redacted block survive untouched.
        assert_eq!(m.extra["message"]["content"][0]["text"]["redacted"], serde_json::json!(true));
        assert_eq!(m.extra["message"]["content"][0]["type"], serde_json::json!("tool_result"), "sibling field on the redacted block must stay");
        assert_eq!(m.extra["message"]["content"][1]["text"], serde_json::json!("unrelated sibling block, must stay"));
    }

    #[test]
    fn apply_replaces_tool_use_result_file_content_for_claude_code() {
        let mut m = msg("tool_result", "the file body");
        m.extra = serde_json::json!({"toolUseResult": {"file": {"content": "the file body", "numLines": 1}}});
        let decision = decision_cass_recall(vec![]);
        let mut redactor = MemoizingRedactor::new();
        apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("claude_code"));

        assert_eq!(m.extra["toolUseResult"]["file"]["content"]["redacted"], serde_json::json!(true));
        assert_eq!(m.extra["toolUseResult"]["file"]["numLines"], serde_json::json!(1), "sibling field must stay");
    }

    #[test]
    fn apply_replaces_codex_payload_output_text() {
        let mut m = msg("tool_result", "codex output text");
        m.extra = serde_json::json!({"payload": {"output": [{"text": "codex output text"}]}});
        let decision = decision_cass_recall(vec![0]);
        let mut redactor = MemoizingRedactor::new();
        apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("codex"));

        assert_eq!(m.extra["payload"]["output"][0]["text"]["redacted"], serde_json::json!(true));
    }

    #[test]
    fn apply_historical_raw_json_unwraps_replaces_and_rewraps() {
        let inner = serde_json::json!({"message": {"content": [{"type": "tool_result", "text": "secret body"}]}});
        let mut m = msg("tool_result", "secret body");
        m.extra = serde_json::json!({"__cass_historical_raw_json__": inner.to_string()});
        let decision = decision_cass_recall(vec![0]);
        let mut redactor = MemoizingRedactor::new();
        apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("claude_code"));

        let rewritten: serde_json::Value = serde_json::from_str(m.extra["__cass_historical_raw_json__"].as_str().unwrap()).unwrap();
        assert_eq!(rewritten["message"]["content"][0]["text"]["redacted"], serde_json::json!(true));
        assert!(!m.extra.to_string().contains("secret body"), "no raw copy of the body may survive in extra");
    }

    #[test]
    fn apply_compact_shape_fixture_clears_content_leaves_extra_untouched_and_blocks_empty() {
        // R7 "精简形态" (~31% of real rows): only raw_role/tool_call_id/
        // tool_call_args survive prior compression, no body-bearing field
        // exists for any R7 path to find.
        let mut m = msg("tool_result", "secret body");
        let compact = serde_json::json!({"raw_role": "tool_result", "tool_call_id": "t1", "tool_call_args": {"query": "q"}});
        m.extra = compact.clone();
        let decision = decision_cass_recall(vec![]); // no blocks resolvable from a compact-shape source event
        let mut redactor = MemoizingRedactor::new();
        let marker = apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("claude_code"));

        assert_eq!(m.content, "");
        assert_eq!(m.extra, compact, "extra must be byte-identical when no R7 path resolves");
        assert_eq!(marker.raw.blocks, Vec::<u32>::new());
    }

    #[test]
    fn apply_mixed_event_fixture_both_rows_tool_result_block_redacted_text_block_untouched() {
        // Real shape from the frozen corpus: messages 1287477 (user, idx 1)
        // and 1287478 (tool_result, idx 2) share one event whose `content[]`
        // has a tool_result block (index 0) and a text block (index 1); both
        // projected rows carry the *whole* event in `extra`.
        let shared_event_extra = serde_json::json!({"message": {"content": [
            {"type": "tool_result", "text": "secret file contents"},
            {"type": "text", "text": "assistant commentary, must stay"}
        ]}});

        let mut tool_result_row = msg("tool_result", "secret file contents");
        tool_result_row.extra = shared_event_extra.clone();
        let decision = decision_cass_recall(vec![0]);
        let mut redactor = MemoizingRedactor::new();
        let marker = apply(&mut tool_result_row, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 2, field_map_for("claude_code"));

        let mut user_row = msg("user", "assistant commentary, must stay");
        user_row.extra = shared_event_extra;
        apply_sibling(&mut user_row, &marker, field_map_for("claude_code"));

        for row in [&tool_result_row, &user_row] {
            assert_eq!(row.extra["message"]["content"][0]["text"]["redacted"], serde_json::json!(true), "tool_result block must be redacted in both rows");
            assert_eq!(row.extra["message"]["content"][1]["text"], serde_json::json!("assistant commentary, must stay"), "text block must survive in both rows");
        }
        assert_eq!(user_row.content, "assistant commentary, must stay", "apply_sibling must never touch content");
    }

    #[test]
    fn apply_mixed_event_mutation_wildcard_target_blocks_corrupts_text_block() {
        let shared_event_extra = serde_json::json!({"message": {"content": [
            {"type": "tool_result", "text": "secret file contents"},
            {"type": "text", "text": "assistant commentary, must stay"}
        ]}});
        let mut tool_result_row = msg("tool_result", "secret file contents");
        tool_result_row.extra = shared_event_extra;
        // Mutation: target_blocks widened to the whole event instead of just
        // the tool_result block -- the text block's `.text` must now be
        // wrongly replaced too.
        let decision = decision_cass_recall(vec![0, 1]);
        let mut redactor = MemoizingRedactor::new();
        apply(&mut tool_result_row, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 2, field_map_for("claude_code"));

        // `apply` faithfully executes whatever `target_blocks` it is given
        // -- it has no independent way to know block 1 shouldn't be
        // touched. This demonstrates why the *positive* test above (target
        // scoped correctly to [0]) depends on `decide` computing
        // `target_blocks` correctly, not on `apply` guessing right.
        assert_ne!(
            tool_result_row.extra["message"]["content"][1]["text"],
            serde_json::json!("assistant commentary, must stay"),
            "with target_blocks wrongly widened to include the text block, its sibling copy gets corrupted too"
        );
    }

    #[test]
    fn apply_snippets_cleared() {
        let mut m = msg("tool_result", "secret body");
        m.snippets = vec![crate::connectors::NormalizedSnippet {
            file_path: Some(std::path::PathBuf::from("/a/b.rs")),
            start_line: Some(1),
            end_line: Some(2),
            language: Some("rust".into()),
            snippet_text: Some("fn secret() {}".into()),
        }];
        let decision = decision_cass_recall(vec![]);
        let mut redactor = MemoizingRedactor::new();
        apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("claude_code"));
        assert_eq!(m.snippets[0].snippet_text, Some(String::new()));
    }

    #[test]
    fn apply_r1_c_hits_parse_success_sets_src() {
        let mut m = msg("tool_result", r#"{"hits": [{"session_id": "s1", "message_id": 42}]}"#);
        let decision = decision_cass_recall(vec![]);
        let mut redactor = MemoizingRedactor::new();
        let marker = apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("claude_code"));
        assert_eq!(marker.src, Some(RecallSrc { sessions: vec!["s1".to_string()], message_ids: vec![42] }));
        assert!(marker.parse_error.is_none());
    }

    #[test]
    fn apply_r1_c_hits_parse_failure_sets_parse_error_not_src() {
        let mut m = msg("tool_result", "not json at all");
        let decision = decision_cass_recall(vec![]);
        let mut redactor = MemoizingRedactor::new();
        let marker = apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("claude_code"));
        assert!(marker.src.is_none());
        assert!(marker.parse_error.is_some());
    }

    // -- ExcludedMarker JSON round-trip --------------------------------------

    #[test]
    fn excluded_marker_json_round_trip() {
        let marker = ExcludedMarker {
            reason: ExclusionReason::ContextFileRead,
            rule_version: 1,
            bytes: 4380,
            sha256: "a".repeat(64),
            fingerprint_blake3: "b".repeat(64),
            anchor: ExclusionAnchor { tool_call_id: None, tool_name: Some("Read".into()), paths: Some(vec!["/x".into()]), shell: None },
            src: None,
            parse_error: None,
            raw: RawRef { blob: "blobs/blake3/ab/abcd.raw".into(), idx: 17, event_key: "ek".into(), blocks: vec![1] },
        };
        let json = marker.to_json_string();
        assert!(json.contains("\"reason\":\"context_file_read\""));
        let round_tripped = ExcludedMarker::from_json_str(&json).unwrap();
        assert_eq!(round_tripped, marker);
    }
}
