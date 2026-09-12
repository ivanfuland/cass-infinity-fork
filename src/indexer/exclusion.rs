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
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::connectors::{NormalizedConversation, NormalizedMessage};
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
///
/// R2-N6 (任务书 #129): the frozen interface is "字段齐全、空值为 null" -- all
/// four keys are written on every marker, empty ones as `null`. `default`
/// stays (old rows written before this fix, with keys omitted, still
/// deserialize), `skip_serializing_if` does not.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct ExclusionAnchor {
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub shell: Option<ShellAnchor>,
}

/// R3's `anchor.shell` sub-object: the opener actually seen (never
/// backfilled) plus the fixed closer.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ShellAnchor {
    pub opener: String,
    pub closer: String,
}

/// R1-c: one cass-mcp recall hit (spec v4.5 shape -- real cass-mcp responses
/// carry no `session_id`/`message_id`, only `source_id`/`source_path`/
/// `line_number` per hit).
///
/// R1-N7 (任务书 #118a): `source_id` is a STRING in every real cass-mcp
/// response (T1b's frozen exclusion clist: 176/176 real recall hits carry a
/// string like `"local"`, never an integer) -- an `i64` field rejected every
/// real response as a parse failure, losing `src` entirely for genuine
/// cass_recall exclusions.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RecallHit {
    pub source_id: String,
    pub source_path: String,
    #[serde(default)]
    pub line_number: Option<u64>,
}

/// R1-c: cass-mcp tool_result hits, parsed from the (pre-redaction) content
/// when parsing succeeds (spec v4.5 T2b replacement of T2a's placeholder
/// shape). `sessions` is the distinct `source_path` set across `hits`.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct RecallSrc {
    pub sessions: Vec<String>,
    pub hits: Vec<RecallHit>,
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
///
/// R2-N6 (任务书 #129): this sentence was aspirational until then --
/// `skip_serializing_if` on `src`/`parse_error` (and on the `anchor`/
/// `RecallHit` optionals) omitted those keys whenever they were empty, so a
/// context-file marker carried neither. Now it holds literally: every key
/// above is present on every marker, empty ones as `null`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ExcludedMarker {
    pub reason: ExclusionReason,
    pub rule_version: u32,
    pub bytes: u64,
    pub sha256: String,
    pub fingerprint_blake3: String,
    pub anchor: ExclusionAnchor,
    #[serde(default)]
    pub src: Option<RecallSrc>,
    #[serde(default)]
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
    ///
    /// R1-B4 (任务书 #118a): validates `sha256`/`fingerprint_blake3` as
    /// 64-char lowercase hex *here*, at deserialization -- not left for
    /// `storage::sqlite`'s `fingerprint_hash_for` to discover downstream.
    /// `apply()` always writes both fields that way, so a well-formed row
    /// never trips this; a malformed one (corrupted DB, hand-built test
    /// fixture, future writer bug) becomes a plain `Err` a caller can turn
    /// into a per-session `ScanError`, instead of surviving into a
    /// `Message` whose `fingerprint_hash(msg).expect(...)` would abort the
    /// whole process (release builds are `panic = "abort"`).
    pub fn from_json_str(s: &str) -> anyhow::Result<Self> {
        let marker: Self = serde_json::from_str(s)?;
        validate_hex64_field(&marker.sha256, "sha256")?;
        validate_hex64_field(&marker.fingerprint_blake3, "fingerprint_blake3")?;
        Ok(marker)
    }
}

fn validate_hex64_field(value: &str, field: &str) -> anyhow::Result<()> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        anyhow::bail!("excluded.{field} must be 64 lowercase hex chars, got {value:?}")
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
// T2b (任务书 #114): `RawEvent` production from a raw-mirror blob.
// ============================================================================

/// Build the raw event/block facts for one connector's raw-mirror blob file
/// (already materialized back into its original directory shape by
/// `materialize_capture_to_scratch`, then reparsed by that connector's own
/// file parser -- `events_from_blob` reads the *same bytes* directly,
/// independently of the connector parser, since the connector's own
/// `NormalizedMessage`/`NormalizedConversation` output drops the raw event
/// identity (claude_code's per-line `uuid`, codex's `payload.id`) entirely --
/// neither field survives into any `NormalizedMessage` field.
///
/// **Disclosed alignment judgment call** (spec/plan describe this as
/// "`Vec<Option<RawEvent>>`按消息序对齐"; this round implements the
/// empirically-verified case, not a full reimplementation of each
/// connector's own message-splitting logic): claude_code normally emits one
/// event = one message, **except** when one JSONL line's `message.content[]`
/// mixes a `tool_result` block with other (`text`/`tool_use`) blocks -- T1b's
/// documented example (messages 1287477/1287478: one event, `content` =
/// `[tool_result, text]`, projected into a `user` row (idx N, the non-
/// `tool_result` content) followed by a `tool_result` row (idx N+1)) -- in
/// which case this function pushes the *same* `RawEvent` (identical
/// `event_key`, full `blocks`) twice in a row, so positional alignment with
/// the connector's own two emitted rows holds for this documented shape.
/// Rarer shapes (multiple `tool_result` blocks in one event, `tool_use` mixed
/// with `tool_result`, etc.) are not modeled and fall back to a single
/// emitted entry -- `decide` only ever looks at `event.blocks` by kind/id,
/// never by the calling message's own position within a split event, so a
/// coarser split only risks *under*-splitting the vector length (宁漏勿误:
/// the caller's `events.get(idx)` degrades to `None` for a short vector,
/// never to a wrong event). Connectors other than `claude_code`/`codex`
/// return an empty vec (no structural facts -- R7/R11 "不启用").
pub(crate) fn events_from_blob(agent_slug: &str, blob_path: &Path) -> Vec<RawEvent> {
    match agent_slug {
        "claude_code" => claude_code_events_from_blob(blob_path).unwrap_or_default(),
        "codex" => codex_events_from_blob(blob_path).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// R1-N16 (任务书 #118b): whether `events_from_blob` has any judgment logic
/// at all for this connector. A connector outside this set always gets
/// `Vec::new()` back from `events_from_blob` regardless of its actual
/// message count -- that is expected "not applicable" behavior (R7: 锚点 1/2
/// 只对有 `tool_name`/结构字段的连接器启用), not the alignment *failure* the
/// caller's `event_align_failed` counter is meant to track.
pub(crate) fn structural_facts_available(agent_slug: &str) -> bool {
    matches!(agent_slug, "claude_code" | "codex")
}

/// R1-N15 (任务书 #118b): pairs each surviving non-blank line with its
/// 1-based PHYSICAL line number in the original file. Pre-fix, callers
/// `enumerate()`d the already-filtered `Vec<String>`, so `line:N` (the
/// `event_key` fallback for a line with no `uuid`/`id`) was off by however
/// many blank lines preceded it -- wrong by construction whenever a blank
/// line appears anywhere earlier in the file.
fn read_jsonl_lines(blob_path: &Path) -> std::io::Result<Vec<(usize, String)>> {
    let text = std::fs::read_to_string(blob_path)?;
    Ok(text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()).map(|(i, l)| (i + 1, l.to_string())).collect())
}

/// Mirrors `franken_agent_detection::connectors::claude_code`'s content-block
/// splitting (pinned rev `bc0f4d3c02356eac4d4dbc48e6f7d830d2caa9e8`,
/// `split_content_blocks` in `connectors/utils.rs` + the projection loop in
/// `connectors/claude_code.rs`), T2b.2 (任务书 #115) control-plane fix
/// 2026-09-07: the original version pushed at most one duplicate `RawEvent`
/// per line (only for a `tool_result` mixed with another block kind on the
/// same line), but the connector actually splits EVERY content-block array
/// into up to `1 (concatenated prose text, if non-empty) + 1 per
/// tool_use/tool_result/thinking block that matches the line's own role`
/// separate `NormalizedMessage`s -- so a common `[text, tool_use]` assistant
/// turn (one JSONL line) reparses into TWO messages but was only ever one
/// raw event, silently failing `events.len() == reparsed.messages.len()`
/// and skipping judgment for the whole session (`EVENT_ALIGN_FAILED`,
/// 宁漏勿误 -- but a false-negative-heavy one, since claude_code sessions
/// mix text + tool_use in nearly every tool-using assistant turn). Fixed by
/// counting/duplicating per the same split rule instead of only the
/// tool_result-mixed case.
///
/// Each pushed copy carries the event's FULL block list (not narrowed to
/// "the blocks this particular output message corresponds to"): `decide`'s
/// pairing (`tool_result_block_indices`, anchor 3's Text-kind filter) all
/// filter `event.blocks` by block `kind`/`tool_use_id`, never by the
/// duplicate's position, so a full block list is sufficient and exactly
/// matches what the pre-existing tool_result-mixed duplication already did.
fn claude_code_events_from_blob(blob_path: &Path) -> std::io::Result<Vec<RawEvent>> {
    let lines = read_jsonl_lines(blob_path)?;
    let mut events = Vec::with_capacity(lines.len());
    for (line_no, line) in &lines {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let event_key = value.get("uuid").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| format!("line:{line_no}"));

        // Role resolution (claude_code.rs's `message_role`): only a
        // user/assistant envelope (explicit `message.role`, or an implicit
        // top-level `type` of "user"/"assistant" with no nested role) ever
        // emits a message; `system`'s `away_summary` subtype is the one
        // exception (handled separately, no content-block splitting).
        let entry_type = value.get("type").and_then(|v| v.as_str());
        let inner_role = value.pointer("/message/role").and_then(|v| v.as_str());
        let role: Option<&str> = match (entry_type, inner_role) {
            (Some("user" | "assistant" | "message"), Some(r)) if r == "user" || r == "assistant" => Some(r),
            (Some(r @ ("user" | "assistant")), None) => Some(r),
            _ => None,
        };
        let is_system_away_summary =
            entry_type == Some("system") && value.get("subtype").and_then(|v| v.as_str()) == Some("away_summary");

        let content_val = value.pointer("/message/content").or_else(|| value.get("content"));

        if is_system_away_summary {
            let has_content = content_val.and_then(|v| v.as_str()).is_some_and(|s| !s.trim().is_empty());
            if has_content {
                events.push(RawEvent { event_key, blocks: Vec::new() });
            }
            continue;
        }
        let Some(role) = role else { continue };

        match content_val {
            Some(serde_json::Value::Array(content)) => {
                let mut blocks = Vec::with_capacity(content.len());
                for (i, block) in content.iter().enumerate() {
                    let block_type = block.get("type").and_then(|v| v.as_str());
                    let kind = match block_type {
                        Some("text" | "input_text" | "output_text") if block.get("text").and_then(|v| v.as_str()).is_some() => BlockKind::Text,
                        Some("tool_use") if block.get("name").and_then(|v| v.as_str()).is_some() => BlockKind::ToolUse,
                        Some("tool_result") => BlockKind::ToolResult,
                        // `thinking` blocks (need `thinking` or `text` as a
                        // string) never participate in any decision filter,
                        // so BlockKind::Other is sufficient here.
                        Some("thinking")
                            if block.get("thinking").and_then(|v| v.as_str()).or_else(|| block.get("text").and_then(|v| v.as_str())).is_some() =>
                        {
                            BlockKind::Other
                        }
                        _ => continue, // split_content_blocks drops malformed/unknown blocks entirely
                    };
                    let tool_use_id = block
                        .get("id")
                        .and_then(|v| v.as_str())
                        .or_else(|| block.get("tool_use_id").and_then(|v| v.as_str()))
                        .map(str::to_string);
                    let tool_name = block.get("name").and_then(|v| v.as_str()).map(str::to_string);
                    let args = block.get("input").cloned();
                    blocks.push(RawBlock { index: i as u32, kind, tool_use_id, tool_name, args });
                }
                let event = RawEvent { event_key, blocks };

                // N14 (任务书 #118a): index by each block's own `.index`
                // field, not by zipping `event.blocks` positionally against
                // `content` -- `blocks` already dropped unrecognized
                // elements (the `_ => continue` above), so a leading skipped
                // block (e.g. `[image, text]`) shifts every later block's
                // Vec position out of sync with its `content` position; a
                // straight positional zip would then pair the surviving
                // `text` block descriptor with the WRONG `content` element
                // and silently fail to find its `text` field.
                let prose: String = event
                    .blocks
                    .iter()
                    .filter(|b| b.kind == BlockKind::Text)
                    .filter_map(|b| content.get(b.index as usize))
                    .filter_map(|block| block.get("text").and_then(|v| v.as_str()))
                    .collect::<Vec<_>>()
                    .join("\n");
                if !prose.trim().is_empty() {
                    events.push(event.clone());
                }
                for b in &event.blocks {
                    let matches_role = match b.kind {
                        BlockKind::ToolUse | BlockKind::Other => role == "assistant",
                        BlockKind::ToolResult => role == "user",
                        BlockKind::Text => false, // already accounted for as prose above
                    };
                    if matches_role && b.kind != BlockKind::Text {
                        events.push(event.clone());
                    }
                }
            }
            Some(other) => {
                let content_str = match other {
                    serde_json::Value::String(s) => s.clone(),
                    _ => String::new(),
                };
                if !content_str.trim().is_empty() {
                    events.push(RawEvent { event_key, blocks: Vec::new() });
                }
            }
            None => {}
        }
    }
    Ok(events)
}

/// Mirrors `franken_agent_detection::connectors::codex` (pinned rev
/// `bc0f4d3c02356eac4d4dbc48e6f7d830d2caa9e8`, `connectors/codex.rs`'s
/// projection loop), T2b.2 (任务书 #115) control-plane fix 2026-09-07: the
/// original version pushed exactly one `RawEvent` per JSONL line
/// unconditionally, but the real connector's outer `type` dispatch is
/// `"session_meta"`/`"turn_context"` (metadata only, 0 messages),
/// `"response_item"` (payload-type-gated: a `message` with `role="developer"`
/// -- or any role other than user/assistant -- or empty content is dropped;
/// `agent_message`/`reasoning` need non-empty content or, for reasoning, an
/// `encrypted_content`; `function_call`/`custom_tool_call`/
/// `function_call_output`/`custom_tool_call_output` always emit one),
/// `"event_msg"` (an `agent_message` sub-payload is dropped as a duplicate
/// of the response-item version; `user_message`/`agent_reasoning`/`tool_call`
/// need non-empty text; `token_count` attaches to an existing message and
/// emits none of its own), and any other outer `type` is dropped entirely.
/// Every codex line still produces at most ONE message (unlike claude_code),
/// so this only needed to stop over-counting lines that produce zero --
/// every codex session has at least one dropped `developer`-role line, so
/// the prior always-push-one behavior meant `EVENT_ALIGN_FAILED` on
/// essentially every codex session, not just an edge case.
fn codex_events_from_blob(blob_path: &Path) -> std::io::Result<Vec<RawEvent>> {
    let lines = read_jsonl_lines(blob_path)?;
    let mut events = Vec::with_capacity(lines.len());
    for (line_no, line) in &lines {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let entry_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let Some(payload) = value.get("payload") else { continue };
        let event_key = payload.get("id").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| format!("line:{line_no}"));
        let call_id = payload.get("call_id").and_then(|v| v.as_str()).map(str::to_string);
        let name = payload.get("name").and_then(|v| v.as_str()).map(str::to_string);

        let text_nonempty = |key: &str| payload.get(key).and_then(|v| v.as_str()).is_some_and(|s| !s.trim().is_empty());
        // R2-B3 (任务书 #119a): mirrors pin `utils.rs:416`'s
        // `extract_content_part` FIRST branch (`item.as_str()`) -- a
        // `payload.content`/`payload.output` array element may itself be a
        // bare JSON string, not only `{"type":"text","text":...}`; the
        // pre-fix version only ever read `.get("text")`, so an array like
        // `["hello"]` counted as empty and a real, non-empty `message`/
        // `agent_message` event got dropped instead of counted (miscounting
        // in the OTHER direction from R1-B2/N1's array-of-empty-text case
        // below -- both are "does this array actually carry visible text").
        let block_text_nonempty = |block: &serde_json::Value| {
            block.as_str().is_some_and(|s| !s.trim().is_empty())
                || block.get("text").and_then(|v| v.as_str()).is_some_and(|t| !t.trim().is_empty())
        };
        // R1-B2/N1 (任务书 #118a): mirrors the real connector's
        // `flatten_content` (pin `codex.rs:773`), which accepts a bare
        // non-empty STRING `payload.content`/`payload.output` (not just an
        // array), and for an array form drops blocks with no non-empty
        // `text` before deciding whether anything survived -- an array of
        // only empty-text blocks produces zero real messages, not one.
        let content_nonempty = || match payload.get("content").or_else(|| payload.get("output")) {
            Some(serde_json::Value::String(s)) => !s.trim().is_empty(),
            Some(serde_json::Value::Array(arr)) => arr.iter().any(block_text_nonempty),
            _ => false,
        };

        let blocks: Option<Vec<RawBlock>> = match entry_type {
            "response_item" => {
                let payload_type = payload.get("type").and_then(|v| v.as_str());
                match payload_type {
                    Some("message") | None => {
                        let role = payload.get("role").and_then(|v| v.as_str());
                        if matches!(role, Some("user" | "assistant")) && content_nonempty() {
                            Some(vec![RawBlock { index: 0, kind: BlockKind::Text, tool_use_id: None, tool_name: None, args: None }])
                        } else {
                            None
                        }
                    }
                    Some("agent_message") => content_nonempty()
                        .then(|| vec![RawBlock { index: 0, kind: BlockKind::Text, tool_use_id: None, tool_name: None, args: None }]),
                    Some("reasoning") => {
                        // R2-B3 (任务书 #119a): mirrors pin `codex.rs:849-853`
                        // (`reasoning_summary_text` + the keep/drop check
                        // right after it) -- the real connector judges
                        // emptiness on the EXTRACTED text (join every
                        // non-empty `summary[].text` with `\n`), not on
                        // whether the `summary` array itself is non-empty.
                        // `summary:[{"type":"summary_text","text":""}]` is a
                        // non-empty ARRAY whose extracted text is empty; the
                        // pre-fix version kept it (miscounting an event pin
                        // would drop), which is the exact "counts equal but
                        // wrong events" shape R2-B3's alignment-gate report
                        // describes.
                        let summary_text_nonempty = payload
                            .get("summary")
                            .and_then(|v| v.as_array())
                            .is_some_and(|items| items.iter().any(|item| item.get("text").and_then(|v| v.as_str()).is_some_and(|t| !t.trim().is_empty())));
                        (summary_text_nonempty || payload.get("encrypted_content").is_some())
                            .then(|| vec![RawBlock { index: 0, kind: BlockKind::Text, tool_use_id: None, tool_name: None, args: None }])
                    }
                    Some("function_call" | "custom_tool_call") => {
                        let args = payload.get("arguments").or_else(|| payload.get("input")).cloned();
                        Some(vec![RawBlock { index: 0, kind: BlockKind::ToolUse, tool_use_id: call_id, tool_name: name, args }])
                    }
                    Some("function_call_output" | "custom_tool_call_output") => {
                        Some(vec![RawBlock { index: 0, kind: BlockKind::ToolResult, tool_use_id: call_id, tool_name: None, args: None }])
                    }
                    Some(_) => None,
                }
            }
            "event_msg" => {
                let event_type = payload.get("type").and_then(|v| v.as_str());
                match event_type {
                    Some("agent_message") => None, // duplicates the response_item version
                    Some("user_message") => text_nonempty("message")
                        .then(|| vec![RawBlock { index: 0, kind: BlockKind::Text, tool_use_id: None, tool_name: None, args: None }]),
                    Some("agent_reasoning") => text_nonempty("text")
                        .then(|| vec![RawBlock { index: 0, kind: BlockKind::Text, tool_use_id: None, tool_name: None, args: None }]),
                    Some("tool_call") => {
                        let args = payload.get("input").or_else(|| payload.get("arguments")).cloned();
                        Some(vec![RawBlock { index: 0, kind: BlockKind::ToolUse, tool_use_id: call_id, tool_name: name, args }])
                    }
                    // "token_count" attaches to an existing message, no message of its own.
                    _ => None,
                }
            }
            // "session_meta" / "turn_context" / anything else: metadata only.
            _ => None,
        };
        let Some(blocks) = blocks else { continue };
        events.push(RawEvent { event_key, blocks });
    }
    Ok(events)
}

// ============================================================================
// T2b: prepare-pipeline carrier types.
// ============================================================================

/// The output of `prepare_conversation_for_ingest`/`_for_restore`: the
/// projected conversation plus its per-message exclusion markers, aligned by
/// index (`excluded[i]` corresponds to `conv.messages[i]`). Threaded through
/// the ingest transport chain and the restore chain unpacked exactly once, at
/// `map_to_internal_with_redactor` -- `NormalizedMessage` itself cannot carry
/// `excluded` (pinned upstream type, no new fields allowed).
#[derive(Debug, Clone)]
pub(crate) struct PreparedConversation {
    pub conv: NormalizedConversation,
    pub excluded: Vec<Option<ExcludedMarker>>,
}

/// Prepare-time failure that must abort ingestion of the whole session
/// (Global Constraints: "捕获失败 → 该会话整体跳过...不落行、水位不越过、
/// 计 ScanError、CLI 末尾退出码非零"). Carries a human-readable reason for
/// logging; callers do not match on failure kind.
#[derive(Debug, Clone)]
pub(crate) struct PrepareError(pub String);

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PrepareError {}

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
        // R1-B5 (任务书 #118a): a `tool_call_id` reused by two different
        // `ToolCall`s (T1b measured 416 such `ambiguous_call_id` cases) must
        // resolve to NO entry at all, not "whichever one `insert` saw last" --
        // an ordinary tool call's result getting silently bound to a later,
        // unrelated call with the same id (and then judged/cleared as that
        // call's result) is data corruption, not a pairing nuance. Once an id
        // is seen twice it's marked ambiguous and permanently excluded from
        // `by_id` (a third+ occurrence must not resurrect it either).
        // B03 (任务书 #131): R1-B5's ledger says the fix includes "限定配对到
        // 结果之前的调用"; the tree only had the duplicate-id half. `by_id`
        // used to index every call in the WHOLE session and the result branch
        // looked its id up without regard to position, so a concatenated or
        // compacted log -- one that keeps a result whose own call is gone --
        // bound that ordinary result to a LATER call reusing the same id, and
        // `decide` then cleared it as that call's hit. The position is now
        // part of the entry, and the lookup below requires it to be strictly
        // earlier than the result being resolved.
        let mut by_id: HashMap<&str, (usize, &PairedTool)> = HashMap::new();
        let mut ambiguous_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for (idx, c) in candidates.iter().enumerate() {
            if let PairingCandidate::ToolCall(pt) = c {
                if let Some(id) = pt.tool_call_id.as_deref() {
                    if ambiguous_ids.contains(id) {
                        continue;
                    }
                    if by_id.insert(id, (idx, pt)).is_some() {
                        by_id.remove(id);
                        ambiguous_ids.insert(id);
                    }
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
                        // B03: `call_idx < idx` -- see the `by_id` construction
                        // above. A call at or after this result's own position
                        // cannot be the call that produced it.
                        if let Some((_, pt)) = by_id.get(id.as_str()).filter(|(call_idx, _)| *call_idx < idx) {
                            resolved.insert(idx, (*pt).clone());
                            if let Some(pos) = unpaired.iter().position(|&i| {
                                matches!(&candidates[i], PairingCandidate::ToolCall(p) if p.tool_call_id.as_deref() == Some(id.as_str()))
                            }) {
                                unpaired.remove(pos);
                            }
                        }
                        // id given but no EARLIER call carries it -> R4: not
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

fn cass_recall_alias_table(agent_slug: &str) -> &'static [&'static str] {
    match agent_slug {
        "claude_code" => &["mcp__cass-mcp__cass_search", "mcp__cass-mcp__cass_expand"],
        "codex" => &["cass_search", "cass_expand"],
        _ => &[],
    }
}

/// R1/R11 (v4.4, Ivan 2026-09-07 裁; 任务书 #118b N12 收紧): matches ONLY the
/// exact full identities R11's alias table registers per connector --
/// `claude_code`: `mcp__cass-mcp__cass_search`/`mcp__cass-mcp__cass_expand`
/// (full names); `codex`: `cass_search`/`cass_expand` (bare names, T1b found
/// 8 such calls). Pre-fix, `claude_code` matched by PREFIX
/// (`starts_with("mcp__cass-mcp__")`), which would also match a
/// hypothetical `mcp__cass-mcp__anything_else` tool never registered in
/// R11 -- R11 says "只匹配表内完整身份", not "any name under this prefix".
/// No other connector matches (宁漏勿误).
fn is_cass_recall_tool(tool_name: &str, agent_slug: &str) -> bool {
    cass_recall_alias_table(agent_slug).contains(&tool_name)
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

/// A Windows drive-letter absolute path AFTER `normalize_path`'s `\` -> `/`
/// conversion, e.g. `C:/projects/...` (from source `C:\projects\...`).
/// `normalize_path` already handles the separator conversion; what it does
/// NOT do is tell the caller the result is still absolute -- it doesn't
/// start with `/`, so without this check `predicate_p` below would treat it
/// as a bare relative path (R1-N9's injection-only-only branch).
fn is_windows_drive_absolute(p: &str) -> bool {
    let bytes = p.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/'
}

/// R2 谓词 P.
///
/// R1-N9 (任务书 #118b): a path still relative AFTER normalization (no
/// resolvable repo-root/worktree-root anchor -- `anchored_under_cc_workspace`
/// does a raw substring search for a `cc-workspace` path SEGMENT and doesn't
/// care whether the input was absolute) must only match the two
/// injection-only file names (spec R2-d), never `memory_files`/
/// `workspace_scoped_files` -- `cc-workspace/USER.md` is not the same claim
/// as `/home/u/projects/cc-workspace/USER.md`; the former is any relative
/// path a caller could construct from ANY cwd and does not prove it resolves
/// under the real cc-workspace root at all.
///
/// R2-N11 (任务书 #119b): a Windows absolute path (`C:\projects\...`)
/// normalizes to `C:/projects/...`, which does not start with `/` --
/// pre-fix, that fell into the "still relative" branch above and could only
/// ever match `injection_only_files`, silently missing `memory_files`/
/// `workspace_scoped_files` hits like `C:\projects\cc-workspace\USER.md`.
/// spec v4.5 explicitly requires Windows separator normalization to work.
fn predicate_p(raw_path: &str, paths_cfg: &ExcludedContextPaths) -> bool {
    let normalized = normalize_path(raw_path);
    let base = normalized.rsplit('/').next().unwrap_or(&normalized);

    if !normalized.starts_with('/') && !is_windows_drive_absolute(&normalized) {
        return paths_cfg.injection_only_files.iter().any(|f| f == base);
    }

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
    // R1-N10 (任务书 #118b): `\n`/`\r` were missing from the reject set --
    // `shell_words::split` treats a newline as an ordinary token separator
    // (same as a space), so a newline-joined multi-command string like
    // `"cat /a/USER.md\n/a/TOOLS.md"` parsed as `cat` with TWO path
    // arguments instead of being rejected as the two separate shell
    // commands a real shell would execute.
    if command.contains(['|', ';', '&', '<', '>', '`', '*', '?', '[', ']', '$', '\n', '\r']) {
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
/// R1-N11 (任务书 #118b): `<cwd>` must actually be INSIDE the
/// `<environment_context>` block (after its open tag), not merely present
/// somewhere in the message -- the pre-fix independent `contains()` checks
/// would match `"<cwd>/x</cwd> real request<environment_context></environment_context>"`
/// (a real request that happens to mention `<cwd>` earlier, followed by an
/// empty env-context block), which is not the structural host-shell shape
/// R3 exists to detect.
///
/// R2-N12 (任务书 #119b): R1-N11 above only checked "after the open tag" --
/// it never checked "before the CORRESPONDING close tag", so
/// `"<environment_context></environment_context><cwd>/x</cwd></environment_context>"`
/// still matched: the first environment-context block closes immediately
/// (empty), and `<cwd>` only appears afterward, wrapped in unrelated text
/// that happens to end with a second `</environment_context>` (satisfying
/// the outer `ends_with` check). Control-plane's original R1-N11 ruling was
/// "`<cwd>` must be located after the open tag AND before the close tag" --
/// the implementation only ever did the first half. Fixed by narrowing the
/// search window to `[open tag end, nearest following close tag)`.
///
/// R3-N3 (任务书 #119d, 回归): the R2-N12 fix above only ever looked at the
/// FIRST `<environment_context>` open tag in the whole message -- if that
/// first block didn't contain `<cwd>`, it returned `None` immediately
/// without ever checking a LATER block. Real shape this misses: an opener
/// that shows an empty example block before the actual environment context,
/// e.g. `"# AGENTS.md instructions\nExample: <environment_context></environment_context>\n<environment_context><cwd>/project</cwd></environment_context>"`
/// -- the first (example) block is empty, but the second (real) block does
/// contain `<cwd>` and satisfies R3's structural shape. Fixed by walking
/// open-tag occurrences left to right, checking each one's own `[open tag
/// end, nearest following close tag)` window in turn, resuming the next
/// search right after that nearest close tag, and only returning `None`
/// once no further open tag remains -- not on the first block's miss.
///
/// R4-N4 (任务书 #120b): after a miss, the search resumes AFTER the nearest
/// close tag, so a nested open tag that falls BETWEEN the current open and
/// its own nearest close (e.g. `<environment_context><environment_context>
/// </environment_context></environment_context>`) is never independently
/// re-checked -- this does NOT walk every open-tag occurrence in the
/// message, only the ones not already subsumed by a checked-and-missed
/// window. This is still correct: such a nested open's own
/// `[open, nearest close)` window is a SUBSET of the outer window just
/// checked and confirmed not to contain `<cwd>`, so skipping it cannot miss
/// a real `<cwd>` hit. `opener` recording is unchanged: it is a property of
/// the WHOLE trimmed message (does it start with one of the 3 known
/// constants), not of which block happened to match.
fn anchor3_shell_opener(text: &str) -> Option<&'static str> {
    let trimmed = text.trim();
    if !trimmed.ends_with(ENVIRONMENT_CONTEXT_CLOSE) {
        return None;
    }
    let mut search_from = 0usize;
    loop {
        let Some(open_rel) = trimmed[search_from..].find(ENVIRONMENT_CONTEXT_OPEN) else {
            return None;
        };
        let open_pos = search_from + open_rel;
        let after_open = &trimmed[open_pos + ENVIRONMENT_CONTEXT_OPEN.len()..];
        let Some(close_rel) = after_open.find(ENVIRONMENT_CONTEXT_CLOSE) else {
            // No close tag anywhere after this open -- given the function's
            // own `ends_with(CLOSE)` precondition above and that OPEN is not
            // a substring of CLOSE, this branch is unreachable in practice
            // (there is always at least the message's own trailing closer
            // after any open tag position), kept only as a defensive bail.
            return None;
        };
        if after_open[..close_rel].contains("<cwd>") {
            return Some(ANCHOR3_OPENERS.iter().find(|o| trimmed.starts_with(**o)).copied().unwrap_or(ENVIRONMENT_CONTEXT_OPEN));
        }
        search_from = open_pos + ENVIRONMENT_CONTEXT_OPEN.len() + close_rel + ENVIRONMENT_CONTEXT_CLOSE.len();
    }
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
/// `tool_use_id` matches it EXACTLY; when pairing was id-less (R4's "exactly
/// one unpaired" branch), only when there is likewise exactly ONE id-less
/// `ToolResult` block in this event is it presumed to belong to the row
/// being judged -- ≥2 such blocks is the same ambiguity R4 already treats
/// as "don't pair" and must not select any of them (宁漏勿误).
///
/// R1-N13 (任务书 #118b): the pre-fix `(None, _) => true` arm swept every
/// id-less `ToolResult` block into `target_blocks` regardless of what
/// `tool_call_id` this decision was actually resolved for -- a `Some(id)`
/// decision would then also clear an unrelated sibling result block that
/// happens to carry no id of its own.
fn tool_result_block_indices(event: &RawEvent, tool_call_id: Option<&str>) -> Vec<u32> {
    match tool_call_id {
        Some(id) => event
            .blocks
            .iter()
            .filter(|b| b.kind == BlockKind::ToolResult && b.tool_use_id.as_deref() == Some(id))
            .map(|b| b.index)
            .collect(),
        None => {
            let candidates: Vec<u32> =
                event.blocks.iter().filter(|b| b.kind == BlockKind::ToolResult && b.tool_use_id.is_none()).map(|b| b.index).collect();
            if candidates.len() == 1 { candidates } else { Vec::new() }
        }
    }
}

/// R1-N12 (任务书 #118b): the cass-mcp identity check now runs AFTER the
/// args-presence gate (`call.args.as_ref()?`, right below) -- R4's general
/// "配对成功但 tool_call 缺 tool_name 或缺参数 → 不排除" is not an R2-only
/// rule; a cass-mcp call with no captured arguments at all is exactly the
/// kind of incomplete pairing 宁漏勿误 exists for, even though R1's own
/// match condition never reads any argument value.
/// R2-B4 (任务书 #119a): wraps a would-be [`Decision`]'s `target_blocks`
/// computation and refuses to return it when the block(s) cannot be
/// uniquely located -- an empty vec here means "id known but no block in
/// this event carries it" (including the R4 fallback-paired case where the
/// call resolved via the id-less "exactly one unpaired" branch but the
/// actual `ToolResult` block(s) in this event carry no id of their own, so
/// filtering by the call's id can never match) or "id-less and 0/≥2
/// candidate blocks" -- both are "cannot uniquely locate the target block",
/// which per spec §2.1.4/R1-N13's original ruling ("多个无 id 结果块 →
/// 不排，宁漏") must yield `None`, not a `Decision` whose `apply` would clear
/// `content` while leaving every block's `extra` copy untouched.
fn decide_with_located_blocks(
    reason: ExclusionReason,
    anchor: ExclusionAnchor,
    event: &RawEvent,
    tool_call_id: Option<&str>,
) -> Option<Decision> {
    let target_blocks = tool_result_block_indices(event, tool_call_id);
    if target_blocks.is_empty() {
        return None;
    }
    Some(Decision { reason, anchor, event_key: event.event_key.clone(), target_blocks })
}

fn decide_r1_r2_for_call(call: &PairedTool, event: &RawEvent, agent_slug: &str, paths_cfg: &ExcludedContextPaths) -> Option<Decision> {
    let tool_name = call.tool_name.as_str();
    let identities = read_tool_identities(agent_slug)?;
    let args = call.args.as_ref()?;

    if is_cass_recall_tool(tool_name, agent_slug) {
        return decide_with_located_blocks(
            ExclusionReason::CassRecall,
            ExclusionAnchor { tool_call_id: call.tool_call_id.clone(), tool_name: Some(tool_name.to_string()), paths: None, shell: None },
            event,
            call.tool_call_id.as_deref(),
        );
    }

    if identities.read == Some(tool_name) {
        let file_path = args.get("file_path")?.as_str()?;
        if !predicate_p(file_path, paths_cfg) {
            return None;
        }
        return decide_with_located_blocks(
            ExclusionReason::ContextFileRead,
            ExclusionAnchor {
                tool_call_id: call.tool_call_id.clone(),
                tool_name: Some(tool_name.to_string()),
                // R1-N9 (任务书 #118b): store the NORMALIZED path, not the
                // raw string the tool call carried -- `anchor.paths` is an
                // audit field, and an unnormalized `../`-laden path would
                // silently misrepresent what predicate P actually matched.
                paths: Some(vec![normalize_path(file_path)]),
                shell: None,
            },
            event,
            call.tool_call_id.as_deref(),
        );
    }

    if identities.project_read == tool_name {
        let document = args.get("document")?.as_str()?;
        if !predicate_p_project_read_document(document, paths_cfg) {
            return None;
        }
        return decide_with_located_blocks(
            ExclusionReason::ContextFileRead,
            ExclusionAnchor { tool_call_id: call.tool_call_id.clone(), tool_name: Some(tool_name.to_string()), paths: Some(vec![document.to_string()]), shell: None },
            event,
            call.tool_call_id.as_deref(),
        );
    }

    if identities.bash == tool_name {
        let command = args.get(identities.bash_arg_key)?.as_str()?;
        let bash_paths = bash_readonly_paths(command)?;
        if bash_paths.is_empty() || !bash_paths.iter().all(|p| predicate_p(p, paths_cfg)) {
            return None;
        }
        return decide_with_located_blocks(
            ExclusionReason::ContextFileRead,
            ExclusionAnchor {
                tool_call_id: call.tool_call_id.clone(),
                tool_name: Some(tool_name.to_string()),
                paths: Some(bash_paths.iter().map(|p| normalize_path(p)).collect()),
                shell: None,
            },
            event,
            call.tool_call_id.as_deref(),
        );
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
/// R1-N1 (任务书 #118a): the bare (non-`[*]`) codex entries below replace
/// `payload.output`/`payload.content`/`payload.message` WHOLESALE whenever
/// `apply` runs for a codex row -- codex's `RawBlock`s are always
/// constructed at `index: 0` (one block per event, `codex_events_from_blob`),
/// so `target_blocks` for a codex decision is always `[]` or `[0]`; R6's
/// "codex `payload.output` 整体记 `[0]`" note means the whole field is one
/// logical block, not element 0 of an array -- the pre-fix `[*].text`-only
/// entries left a STRING-form `payload.content`/`payload.output` untouched
/// entirely (`.and_then(|v| v.as_array_mut())` returns `None` for a string),
/// and for array form only cleared each element's `.text` sub-field,
/// leaving every other element (and the array's own shape) intact.
/// `payload.message` covers the separate `event_msg`/`user_message` shape
/// (`codex_events_from_blob`'s `text_nonempty("message")` branch), which
/// carries its text directly on `payload.message`, not `payload.content`/
/// `.output` at all.
pub const EXTRA_FIELD_MAP: &[(&str, &[&str])] = &[
    ("claude_code", &["message.content[*].content", "message.content[*].text", "toolUseResult.file.content"]),
    (
        "codex",
        &[
            "payload.output[*].text",
            "payload.content[*].text",
            "payload.arguments",
            "payload.input",
            "payload.output",
            "payload.content",
            "payload.message",
        ],
    ),
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

/// R2-B2 (任务书 #119a): claude_code's top-level `toolUseResult` field takes
/// TWO distinct shapes depending on which tool produced it -- a nested
/// object (`{"file":{"content":...}}`, already covered by
/// `EXTRA_FIELD_MAP`'s `toolUseResult.file.content` sub-path) for
/// file-editing tools, and a bare STRING carrying the raw tool_result body
/// verbatim (measured on the frozen corpus: 1,533 `context_file_read` +
/// 25 `cass_recall` rows where this string is byte-identical to
/// `message.content`) for others (e.g. `mcp__cass-mcp__*`, `Bash`,
/// `project_read`). A generic DSL entry can't distinguish the two: adding a
/// bare `"toolUseResult"` path to `EXTRA_FIELD_MAP` would also nuke the
/// object shape's sibling metadata (`filePath`/`type`/`oldTodos`/...), which
/// the sub-path entry deliberately leaves alone. So this is a small,
/// type-guarded step run alongside the DSL rather than a DSL entry: replace
/// `toolUseResult` wholesale only when it is currently a JSON string,
/// leaving the object shape untouched here (the existing sub-path handles
/// it).
///
/// B04 (任务书 #131): the top-level string is ONE value for the whole event,
/// while the call being applied names only the block indices it is
/// redacting. R3-N2 (任务书 #129) guarded that with "clear only when EVERY
/// `tool_result` block in the event is targeted", which over-corrected in
/// the opposite direction: an event with two result blocks where only block
/// 0 is excluded left the string behind EVEN WHEN it was byte-identical to
/// block 0's own body, so the excluded body survived in `extra_bin` while
/// the row reported a successful exclusion (R2-B2's "原文只在 raw-mirror"
/// broken). `apply_sibling` was worse off: it always passes exactly ONE
/// block, so the all-members guard could never be satisfied at all.
///
/// The guard is now an ownership proof: clear the string when it IS the
/// pre-clear body of a block this call is clearing (or a bounded superset of
/// it -- see [`TOOL_USE_RESULT_WRAPPER_SLACK`]), and keep it otherwise. That
/// keeps R3-N2's protection (a string holding some OTHER block's body
/// survives) without re-opening R2-B2's leak.
fn strip_claude_string_tool_use_result(value: &mut serde_json::Value, owned_bodies: &[String], placeholder: &serde_json::Value) {
    let Some(recorded) = value.get("toolUseResult").and_then(serde_json::Value::as_str) else { return };
    if !owned_bodies.iter().any(|body| is_owned_body_copy(recorded, body)) {
        return;
    }
    if let Some(v) = value.get_mut("toolUseResult") {
        *v = placeholder.clone();
    }
}

/// How much decoration a string-form `toolUseResult` may carry around a body
/// it copies before that copy stops being attributable to the body. Every
/// measured shape is byte-identical (R2-B2's 1,558 rows); this absorbs small
/// wrappers so the rule does not hinge on an exact-equality accident, while
/// staying far too tight for "anything containing the body" to be treated as
/// that body's copy.
const TOOL_USE_RESULT_WRAPPER_SLACK: usize = 1024;

fn is_owned_body_copy(recorded: &str, body: &str) -> bool {
    if recorded == body {
        return true;
    }
    !body.is_empty()
        && recorded.len() <= body.len() + TOOL_USE_RESULT_WRAPPER_SLACK
        && recorded.contains(body)
}

/// The bodies this call may treat as its own: the caller row's own pre-clear
/// content (`own_body`, absent for `apply_sibling`, whose content is never
/// cleared) plus, for each targeted block, that block's body as read from the
/// still-intact event. Both are captured BEFORE the R7 DSL rewrites anything,
/// so they really are the pre-clear values (the DSL replaces
/// `message.content[i].content` itself, which would otherwise destroy the
/// evidence for exactly the blocks under judgment).
///
/// The event may be an `historical_raw_json`-wrapped string (`apply_extra`
/// unwraps it first) or a compact shape with no `message.content` at all --
/// in that case only `own_body` remains, which is precisely the attribution
/// the corpus' string rows offer (`content` is byte-identical to the string).
fn owned_bodies(value: &serde_json::Value, target_blocks: &[u32], own_body: Option<&str>) -> Vec<String> {
    let mut bodies: Vec<String> = Vec::new();
    if let Some(body) = own_body.filter(|body| !body.is_empty()) {
        bodies.push(body.to_string());
    }
    let blocks = value
        .pointer("/message/content")
        .or_else(|| value.get("content"))
        .and_then(serde_json::Value::as_array);
    if let Some(blocks) = blocks {
        for index in target_blocks {
            let Some(block) = blocks.get(*index as usize) else { continue };
            match block {
                serde_json::Value::String(text) => bodies.push(text.clone()),
                serde_json::Value::Object(_) => {
                    for key in ["content", "text"] {
                        if let Some(text) = block.get(key).and_then(serde_json::Value::as_str) {
                            bodies.push(text.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    bodies
}

/// Replace every R7 field map path's leaf value with `placeholder`, only at
/// `target_blocks` positions for array (`[*]`) segments. Unwraps/rewraps the
/// `historical_raw_json` string envelope first when present (R7 note): the
/// whole `extra` value being exactly `{"__cass_historical_raw_json__": "..."}`
/// means the real event JSON lives inside that string.
///
/// `own_body` is the row's pre-clear content (`apply`'s `original`), used for
/// the ownership proof in [`strip_claude_string_tool_use_result`]; see there.
fn apply_extra(
    extra: &mut serde_json::Value,
    field_map: ExtraFieldMap,
    target_blocks: &[u32],
    placeholder: &serde_json::Value,
    own_body: Option<&str>,
) {
    let historical = matches!(extra, serde_json::Value::Object(m) if m.len() == 1 && m.contains_key(HISTORICAL_RAW_JSON_SENTINEL_KEY));
    if historical {
        let raw = extra[HISTORICAL_RAW_JSON_SENTINEL_KEY].as_str().unwrap_or_default().to_string();
        if let Ok(mut inner) = serde_json::from_str::<serde_json::Value>(&raw) {
            let bodies = owned_bodies(&inner, target_blocks, own_body);
            for path in field_map {
                let segments: Vec<&str> = path.split('.').collect();
                apply_path(&mut inner, &segments, target_blocks, placeholder);
            }
            strip_claude_string_tool_use_result(&mut inner, &bodies, placeholder);
            let rewritten = serde_json::to_string(&inner).unwrap_or(raw);
            extra[HISTORICAL_RAW_JSON_SENTINEL_KEY] = serde_json::Value::String(rewritten);
        }
        return;
    }
    let bodies = owned_bodies(extra, target_blocks, own_body);
    for path in field_map {
        let segments: Vec<&str> = path.split('.').collect();
        apply_path(extra, &segments, target_blocks, placeholder);
    }
    strip_claude_string_tool_use_result(extra, &bodies, placeholder);
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
/// R1-c (spec v4.5): a real cass-mcp tool_result is one of two legitimate
/// JSON shapes -- a hits envelope, or `{"error": ...}` when the underlying
/// `cass` invocation itself failed. Both are "parsed successfully" (no
/// `parse_error`); only non-JSON, or JSON that is neither shape, is a parse
/// failure. `line_number` is the only optional per-hit field (real
/// responses always carry `source_id`/`source_path`).
fn parse_recall_hits(content: &str) -> Result<RecallSrc, String> {
    let value: serde_json::Value = serde_json::from_str(content).map_err(|e| format!("invalid JSON: {e}"))?;
    if value.get("error").is_some() {
        // Error-shaped response (`{"error":"cass_exit","code","stderr"}`):
        // a legitimate cass-mcp answer with no hits to report.
        return Ok(RecallSrc::default());
    }
    let hits = value
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "neither `hits` array nor `error` field present".to_string())?;
    let mut sessions: Vec<String> = Vec::new();
    let mut out_hits = Vec::with_capacity(hits.len());
    for (i, hit) in hits.iter().enumerate() {
        let source_id = hit.get("source_id").and_then(|v| v.as_str()).ok_or_else(|| format!("hits[{i}] missing source_id"))?.to_string();
        let source_path = hit.get("source_path").and_then(|v| v.as_str()).ok_or_else(|| format!("hits[{i}] missing source_path"))?.to_string();
        let line_number = hit.get("line_number").and_then(|v| v.as_u64());
        if !sessions.iter().any(|s| s == &source_path) {
            sessions.push(source_path.clone());
        }
        out_hits.push(RecallHit { source_id, source_path, line_number });
    }
    Ok(RecallSrc { sessions, hits: out_hits })
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
    // R1-N25 (任务书 #118b): must agree with the ordinary (non-excluded)
    // mapping layer's own `redaction_enabled()` gate (`indexer/mod.rs`'s
    // `should_redact` check) -- `apply` used to call `redact_text`
    // unconditionally, so with `CASS_REDACT_SECRETS=0` the marker's
    // sha256/fingerprint_blake3 still corresponded to the REDACTED string
    // while every unexcluded row's content/dedup fingerprint corresponded
    // to the ORIGINAL string, breaking both the "sha256 = what should have
    // been written to content" audit contract and cross-row dedup identity
    // for that config.
    let redacted = if crate::indexer::redact_secrets::redaction_enabled() {
        redactor.redact_text(&original)
    } else {
        original.clone()
    };

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
    // B04 (任务书 #131): `original` is this row's pre-clear content -- one of
    // the ownership proofs the top-level string-form `toolUseResult` is
    // cleared against (the others come from the event itself, inside
    // `apply_extra`).
    apply_extra(&mut msg.extra, field_map, &decision.target_blocks, &placeholder, Some(&original));

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
    // B04 (任务书 #131): no `own_body` here -- a sibling's content is never
    // cleared, so there is nothing of its own to attribute the top-level
    // string to. Its copy of the SAME event still supplies the targeted
    // blocks' pre-clear bodies inside `apply_extra`, which is what lets this
    // path clear an excluded body's string copy at all (pre-fix it passed a
    // single block, so R3-N2's all-members guard could never be satisfied).
    apply_extra(&mut msg.extra, field_map, &marker.raw.blocks, &placeholder, None);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // T4-F1 / #122b-1 invariant: any test here that reads OR writes
    // process env (directly, or via a function that does, e.g.
    // `apply`'s `redaction_enabled()` read of `CASS_REDACT_SECRETS`) must
    // carry `#[serial]` -- the crate-wide default `#[serial]` lock is
    // shared with `src/indexer/mod.rs`'s test modules. Full rationale at
    // that file's `mod tests` opening.

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

    // -- events_from_blob (T2b) ------------------------------------------

    fn write_blob(dir: &tempfile::TempDir, name: &str, lines: &[&str]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }

    #[test]
    fn events_from_blob_claude_code_single_text_event_positive() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"assistant","uuid":"ek1","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]}}"#;
        let path = write_blob(&dir, "s.jsonl", &[line]);
        let events = events_from_blob("claude_code", &path);
        assert_eq!(events.len(), 1, "one JSONL line with no tool_result must produce exactly one RawEvent");
        assert_eq!(events[0].event_key, "ek1");
        assert_eq!(events[0].blocks.len(), 1);
        assert_eq!(events[0].blocks[0].kind, BlockKind::Text);
    }

    #[test]
    fn events_from_blob_claude_code_fully_aligned_session_matches_message_count_positive() {
        // T2b R1 (control-plane 裁定) alignment lock, "全对齐" shape: a
        // plain sequence of events with no mixed tool_result+text content
        // reparses 1:1 (one connector message per JSONL line), so
        // `events.len()` must equal the session's real message count and
        // `prepare_conversation_for_ingest`'s `events.len() ==
        // reparsed.messages.len()` self-check must NOT skip judgment for
        // this common shape.
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            r#"{"type":"user","uuid":"ek1","message":{"role":"user","content":[{"type":"text","text":"hi"}]}}"#,
            r#"{"type":"assistant","uuid":"ek2","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/tmp/x"}}]}}"#,
            r#"{"type":"user","uuid":"ek3","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"file contents"}]}]}}"#,
        ];
        let path = write_blob(&dir, "s.jsonl", &lines);
        let events = events_from_blob("claude_code", &path);
        assert_eq!(events.len(), 3, "3 non-mixed events must produce exactly 3 aligned RawEvent entries (1:1, no splitting)");
        assert_eq!(events[2].blocks.len(), 1, "a tool_result-only event has no `has_other` content, so it does not split");
    }

    #[test]
    fn events_from_blob_claude_code_mixed_tool_result_and_text_splits_into_two_positive() {
        // T1b/T2a documented shape (messages 1287477/1287478): one event
        // whose `message.content` mixes a `tool_result` block with a `text`
        // block projects into two consecutive rows sharing the same event.
        // Doubles as the T2b R1 alignment lock for this shape: `events.len()
        // == 2` must equal the session's real message count (idx 1 + idx 2)
        // so `prepare_conversation_for_ingest`'s alignment self-check does
        // NOT skip judgment for this documented split.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"user","uuid":"ek-shared","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"result"}]},{"type":"text","text":"<fork-boilerplate>..."}]}}"#;
        let path = write_blob(&dir, "s.jsonl", &[line]);
        let events = events_from_blob("claude_code", &path);
        assert_eq!(events.len(), 2, "mixed tool_result+text event must produce two aligned RawEvent entries");
        assert_eq!(events[0].event_key, "ek-shared");
        assert_eq!(events[1].event_key, "ek-shared");
        assert_eq!(events[0].blocks.len(), 2, "both entries carry the full event's block list");
        let tool_result_block = events[0].blocks.iter().find(|b| b.kind == BlockKind::ToolResult).expect("tool_result block present");
        assert_eq!(tool_result_block.tool_use_id.as_deref(), Some("toolu_1"));
    }

    #[test]
    fn events_from_blob_claude_code_missing_uuid_falls_back_to_line_number_negative() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"user","message":{"role":"user","content":[{"type":"text","text":"hi"}]}}"#;
        let path = write_blob(&dir, "s.jsonl", &[line]);
        let events = events_from_blob("claude_code", &path);
        assert_eq!(events[0].event_key, "line:1", "missing top-level uuid falls back to 1-based line number");
    }

    /// R1-N15 (任务书 #118b): `line:N` must be the PHYSICAL 1-based line
    /// number in the original file, not the position among only the
    /// non-blank lines -- pre-fix, `enumerate()` ran on the already-filtered
    /// `Vec<String>`, so a leading blank line shifted every fallback
    /// `line:N` down by one.
    #[test]
    fn events_from_blob_claude_code_missing_uuid_after_blank_line_uses_physical_line_number_negative() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"user","message":{"role":"user","content":[{"type":"text","text":"hi"}]}}"#;
        let path = write_blob(&dir, "s.jsonl", &["", line]);
        let events = events_from_blob("claude_code", &path);
        assert_eq!(events[0].event_key, "line:2", "the event is on physical line 2 (line 1 is blank), not line 1");
    }

    /// N14 (任务书 #118a): a leading unrecognized block (`image`, which
    /// `split_content_blocks` drops entirely -- no `BlockKind` matches it)
    /// must not shift the surviving `text` block's position out of sync
    /// with its own `content[]` index. Pre-fix, `event.blocks.iter().zip
    /// (content.iter())` paired `blocks[0]` (the text block, `.index == 1`)
    /// against `content[0]` (the image block) and silently found no
    /// `.text` field, producing zero prose for an event that plainly has
    /// prose.
    #[test]
    fn events_from_blob_claude_code_leading_unrecognized_block_does_not_misalign_prose_positive() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"assistant","uuid":"ek-img-text","message":{"role":"assistant","content":[{"type":"image","source":{"data":"..."}},{"type":"text","text":"the actual prose"}]}}"#;
        let path = write_blob(&dir, "s.jsonl", &[line]);
        let events = events_from_blob("claude_code", &path);
        assert_eq!(events.len(), 1, "the surviving text block must still produce a prose event, not silently zero");
        assert_eq!(events[0].blocks.len(), 1, "only the text block survives split_content_blocks; the image block is dropped");
        assert_eq!(events[0].blocks[0].index, 1, "the surviving block keeps its ORIGINAL content[] index");
        assert_eq!(events[0].blocks[0].kind, BlockKind::Text);
    }

    #[test]
    fn events_from_blob_codex_function_call_and_output_pairing_positive() {
        let dir = tempfile::tempdir().unwrap();
        let call =
            r#"{"type":"response_item","payload":{"type":"custom_tool_call","id":"ctc_1","call_id":"call_abc","name":"exec","input":{"cmd":"cat x"}}}"#;
        let result = r#"{"type":"response_item","payload":{"type":"custom_tool_call_output","id":"ctco_1","call_id":"call_abc","output":[{"type":"input_text","text":"hi"}]}}"#;
        let path = write_blob(&dir, "s.jsonl", &[call, result]);
        let events = events_from_blob("codex", &path);
        assert_eq!(events.len(), 2, "codex response_items are 1:1 with events (no splitting)");
        assert_eq!(events[0].event_key, "ctc_1");
        assert_eq!(events[0].blocks[0].kind, BlockKind::ToolUse);
        assert_eq!(events[0].blocks[0].tool_use_id.as_deref(), Some("call_abc"));
        assert_eq!(events[0].blocks[0].tool_name.as_deref(), Some("exec"));
        assert_eq!(events[1].event_key, "ctco_1");
        assert_eq!(events[1].blocks[0].kind, BlockKind::ToolResult);
        assert_eq!(events[1].blocks[0].tool_use_id.as_deref(), Some("call_abc"));
    }

    #[test]
    fn events_from_blob_codex_message_type_produces_single_text_block_positive() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"response_item","payload":{"type":"message","id":"msg_1","role":"user","content":[{"type":"input_text","text":"<environment_context>...</environment_context>"}]}}"#;
        let path = write_blob(&dir, "s.jsonl", &[line]);
        let events = events_from_blob("codex", &path);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].blocks.len(), 1, "R6: payload.output/content 整体记单块索引 0");
        assert_eq!(events[0].blocks[0].kind, BlockKind::Text);
        assert_eq!(events[0].blocks[0].index, 0);
    }

    /// R1-B2 (任务书 #118a), review反例①: the real connector accepts a bare
    /// non-empty STRING `payload.content`/`payload.output`, not just an
    /// array -- the pre-fix `content_array_nonempty` (`.and_then(|v|
    /// v.as_array())`) returned `None`/`false` for a string, silently
    /// dropping this event and misaligning every event after it against the
    /// real connector's message count.
    #[test]
    fn events_from_blob_codex_string_form_payload_content_counts_as_one_event_positive() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"response_item","payload":{"type":"message","id":"msg_str","role":"user","content":"a bare string host-shell body"}}"#;
        let path = write_blob(&dir, "s.jsonl", &[line]);
        let events = events_from_blob("codex", &path);
        assert_eq!(events.len(), 1, "a non-empty STRING payload.content must still produce one event");
        assert_eq!(events[0].event_key, "msg_str");
    }

    /// R1-B2 (任务书 #118a), review反例②: an array whose only element has no
    /// non-empty `text` produces ZERO real messages (the real connector
    /// drops empty text blocks before deciding), not one -- the pre-fix
    /// `content_array_nonempty` only checked `!arr.is_empty()`, so this
    /// shape wrongly counted as an event.
    #[test]
    fn events_from_blob_codex_array_of_only_empty_text_blocks_produces_zero_events_negative() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"response_item","payload":{"type":"message","id":"msg_empty","role":"user","content":[{"type":"input_text","text":""}]}}"#;
        let path = write_blob(&dir, "s.jsonl", &[line]);
        let events = events_from_blob("codex", &path);
        assert!(events.is_empty(), "an array of only empty-text blocks must produce zero events, matching the real connector dropping them");
    }

    #[test]
    fn events_from_blob_unknown_connector_returns_empty_negative() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_blob(&dir, "s.jsonl", &[r#"{"uuid":"x"}"#]);
        assert!(events_from_blob("openclaw", &path).is_empty(), "R7/R11 不启用的连接器不产结构事实");
    }

    // -- events_from_blob alignment lock against the REAL connector (T2b.2,
    // 任务书 #115, control-plane fix 2026-09-07) ---------------------------
    //
    // The tests above assert `events_from_blob`'s own internal shape; these
    // assert it against what `franken_agent_detection`'s real connector
    // actually reparses a blob into, closing the loop the original
    // `EVENT_ALIGN_FAILED` bug slipped through (self-consistent unit tests
    // that never called the real parser).

    fn real_reparse_message_count(connector_key: &'static str, dir: &tempfile::TempDir, file_name: &str) -> usize {
        let (_name, factory) = crate::connectors::get_connector_factories()
            .into_iter()
            .find(|(name, _)| *name == connector_key)
            .unwrap_or_else(|| panic!("no registered connector factory named {connector_key:?}"));
        let connector = factory();
        let file_path = dir.path().join(file_name);
        let scan_root = crate::connectors::ScanRoot::local(file_path.clone());
        let ctx = crate::connectors::ScanContext::with_roots(dir.path().to_path_buf(), vec![scan_root], None);
        let convs = connector.scan(&ctx).expect("real connector scan must succeed for a well-formed fixture");
        assert!(convs.len() <= 1, "fixture must reparse into at most one conversation, got {}", convs.len());
        // A fixture whose only content produces zero real messages may
        // legitimately scan to zero conversations (the connector drops an
        // empty session rather than emitting one with `messages: []`).
        convs.into_iter().next().map(|c| c.messages.len()).unwrap_or(0)
    }

    #[test]
    fn events_from_blob_claude_code_thinking_text_tool_use_one_line_matches_real_reparse_positive() {
        // Real shape: one assistant JSONL record whose content array mixes
        // thinking + text + tool_use -- three blocks, but (thinking ->
        // reasoning message) + (text -> prose message) + (tool_use ->
        // tool_call message) = THREE separate NormalizedMessages from the
        // real connector, not one.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"assistant","uuid":"ek-ttt","message":{"role":"assistant","content":[{"type":"thinking","thinking":"considering the read"},{"type":"text","text":"Let me check that file."},{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/tmp/foo.txt"}}]}}"#;
        write_blob(&dir, "session.jsonl", &[line]);
        let real_count = real_reparse_message_count("claude", &dir, "session.jsonl");
        let events = events_from_blob("claude_code", &dir.path().join("session.jsonl"));
        assert_eq!(events.len(), real_count, "thinking+text+tool_use on one line must produce 3 aligned RawEvent entries, matching the real connector's 3 messages");
        assert_eq!(real_count, 3);
        assert!(events.iter().all(|e| e.event_key == "ek-ttt"));
    }

    #[test]
    fn events_from_blob_claude_code_pure_multi_text_blocks_collapse_to_one_matches_real_reparse_positive() {
        // Real shape: multiple `text` blocks in one content array collapse
        // into ONE prose message (newline-joined), not one message per
        // block.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"assistant","uuid":"ek-multitext","message":{"role":"assistant","content":[{"type":"text","text":"part one"},{"type":"text","text":"part two"}]}}"#;
        write_blob(&dir, "session.jsonl", &[line]);
        let real_count = real_reparse_message_count("claude", &dir, "session.jsonl");
        let events = events_from_blob("claude_code", &dir.path().join("session.jsonl"));
        assert_eq!(events.len(), real_count, "multiple text blocks on one line must collapse to a single aligned RawEvent, matching the real connector's single prose message");
        assert_eq!(real_count, 1);
    }

    #[test]
    fn events_from_blob_claude_code_developer_style_empty_content_produces_zero_matches_real_reparse_negative() {
        // Real shape: an assistant record whose only content block fails
        // its own required-field check (a `text` block with no string
        // `text`) produces zero messages, not one.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"assistant","uuid":"ek-empty","message":{"role":"assistant","content":[{"type":"text"}]}}"#;
        write_blob(&dir, "session.jsonl", &[line]);
        let real_count = real_reparse_message_count("claude", &dir, "session.jsonl");
        let events = events_from_blob("claude_code", &dir.path().join("session.jsonl"));
        assert_eq!(events.len(), real_count, "a malformed/empty content-only line must produce zero aligned RawEvent entries, matching the real connector's zero messages");
        assert_eq!(real_count, 0);
    }

    #[test]
    fn events_from_blob_codex_developer_dropped_and_reasoning_sequence_matches_real_reparse_positive() {
        // Real shape (T2b.2 root cause): a `developer`-role response_item
        // (the system prompt line every real codex session has) is dropped
        // by the connector entirely -- zero messages -- while `reasoning`,
        // `function_call`, `function_call_output`, and a normal `user`
        // message each produce exactly one.
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            r#"{"type":"response_item","timestamp":"2026-01-01T00:00:00Z","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"You are Codex, a coding agent."}]}}"#,
            r#"{"type":"response_item","timestamp":"2026-01-01T00:00:01Z","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"list files"}]}}"#,
            r#"{"type":"response_item","timestamp":"2026-01-01T00:00:02Z","payload":{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"I should run ls."}]}}"#,
            r#"{"type":"response_item","timestamp":"2026-01-01T00:00:03Z","payload":{"type":"function_call","id":"fc_1","name":"exec_command","arguments":"{\"cmd\":\"ls\"}","call_id":"call_1"}}"#,
            r#"{"type":"response_item","timestamp":"2026-01-01T00:00:04Z","payload":{"type":"function_call_output","call_id":"call_1","output":"README.md\n"}}"#,
            r#"{"type":"response_item","timestamp":"2026-01-01T00:00:05Z","payload":{"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"Found README.md."}]}}"#,
        ];
        write_blob(&dir, "rollout-w6-test.jsonl", &lines);
        let real_count = real_reparse_message_count("codex", &dir, "rollout-w6-test.jsonl");
        let events = events_from_blob("codex", &dir.path().join("rollout-w6-test.jsonl"));
        assert_eq!(events.len(), real_count, "the dropped developer line must not be counted, matching the real connector's message count");
        assert_eq!(real_count, 5, "developer dropped; user/reasoning/function_call/function_call_output/assistant each kept");
    }

    /// R2-B3 (任务书 #119a): pin `codex.rs:849-853` judges a `reasoning`
    /// event's emptiness on the EXTRACTED text (join non-empty
    /// `summary[].text`), not on whether the `summary` array itself is
    /// non-empty. `summary:[{"type":"summary_text","text":""}]` is a
    /// non-empty array whose extracted text is empty and no
    /// `encrypted_content` -- the real connector drops it (zero messages);
    /// the pre-fix `events_from_blob` kept it (one event), miscounting in
    /// the direction R2-B3's alignment-gate report names.
    #[test]
    fn events_from_blob_codex_reasoning_empty_summary_text_produces_zero_matches_real_reparse_negative() {
        // `real_reparse_message_count` -> `CodexConnector::scan` only
        // recognizes files named `rollout-*.jsonl` (pin
        // `codex.rs::is_rollout_file`) -- a bare `s.jsonl` name is
        // invisible to the real connector's own file discovery regardless
        // of content, which would make this "matches_real_reparse" a
        // vacuous 0==0 rather than an actual alignment check.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"response_item","timestamp":"2026-01-01T00:00:00Z","payload":{"type":"reasoning","id":"rs_empty","summary":[{"type":"summary_text","text":""}]}}"#;
        write_blob(&dir, "rollout-r2-b3-a.jsonl", &[line]);
        let real_count = real_reparse_message_count("codex", &dir, "rollout-r2-b3-a.jsonl");
        let events = events_from_blob("codex", &dir.path().join("rollout-r2-b3-a.jsonl"));
        assert_eq!(events.len(), real_count, "a reasoning summary whose only item has empty text must produce zero events, matching the real connector dropping it");
        assert_eq!(real_count, 0);
    }

    /// R2-B3 (任务书 #119a): pin `utils.rs:416`'s `extract_content_part`
    /// accepts a bare STRING array element (not only `{"type":"text",...}`
    /// objects) as visible text. `payload.content: ["a bare string"]` on a
    /// `message`-role event must count as non-empty and produce one event --
    /// the pre-fix `content_nonempty` only read `.get("text")` per element,
    /// so this shape counted as empty and the event was wrongly dropped.
    #[test]
    fn events_from_blob_codex_message_array_bare_string_element_matches_real_reparse_positive() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"response_item","timestamp":"2026-01-01T00:00:00Z","payload":{"type":"message","id":"msg_bare","role":"user","content":["a bare string content block"]}}"#;
        write_blob(&dir, "rollout-r2-b3-b.jsonl", &[line]);
        let real_count = real_reparse_message_count("codex", &dir, "rollout-r2-b3-b.jsonl");
        let events = events_from_blob("codex", &dir.path().join("rollout-r2-b3-b.jsonl"));
        assert_eq!(events.len(), real_count, "a bare-string content array element must produce one event, matching the real connector counting it as visible text");
        assert_eq!(real_count, 1);
    }

    // -- R1 -------------------------------------------------------------

    #[test]
    fn r1_a_claude_code_full_name_exact_match_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool { tool_call_id: Some("t1".into()), tool_name: "mcp__cass-mcp__cass_search".into(), args: Some(serde_json::json!({})) }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "{}");
        let decision = decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).expect("R1-a must match");
        assert_eq!(decision.reason, ExclusionReason::CassRecall);
        assert_eq!(decision.target_blocks, vec![0]);
    }

    /// R1-N12 (任务书 #118b): R4's general "缺参数不排" applies to R1 too --
    /// a cass-mcp call with NO captured arguments at all must not be
    /// excluded just because its `tool_name` matches, even though R1's own
    /// match condition never reads any argument value.
    #[test]
    fn r1_a_mutation_missing_args_does_not_match_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool { tool_call_id: Some("t1".into()), tool_name: "mcp__cass-mcp__cass_search".into(), args: None }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "{}");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(), "R4: missing args must not match, even for R1");
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

    /// R1-N13 (任务书 #118b): an event with a matched, ID-bearing
    /// `ToolResult` (A, `tool_use_id="t1"`) AND a sibling ID-LESS
    /// `ToolResult` (B) must only select A's block -- pre-fix,
    /// `(None, _) => true` swept B in too regardless of what id this
    /// decision resolved for.
    #[test]
    fn r1_target_blocks_excludes_unrelated_id_less_sibling_result() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1")), tool_result_block(1, None)] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "mcp__cass-mcp__cass_search".into(),
                args: Some(serde_json::json!({})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "{}");
        let decision = decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).expect("must match");
        assert_eq!(decision.target_blocks, vec![0], "the id-less sibling block (index 1) must NOT be swept in");
    }

    /// R2-B4 (任务书 #119a, was R1-N13): when pairing itself was id-less
    /// (R4's "exactly one unpaired" branch), selecting a block ALSO requires
    /// the event to have exactly one id-less `ToolResult` block -- two or
    /// more is the same ambiguity R4 already refuses to pair on, and per
    /// spec §2.1.4/R1-N13's ORIGINAL ruling ("多个无 id 结果块 → 不排，宁漏")
    /// must make `decide` return `None` entirely, not a `Decision` with an
    /// empty `target_blocks` -- the pre-fix assertion here
    /// (`.expect("id-less pairing must still succeed (R4-b)")` +
    /// `assert!(target_blocks.is_empty())`) locked the WRONG behavior in:
    /// `apply` would still have cleared `content` for a `Some` decision
    /// while being unable to locate which block(s) to redact in `extra`.
    #[test]
    fn r2_b4_decide_is_none_when_multiple_id_less_result_blocks_are_ambiguous() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, None), tool_result_block(1, None)] };
        let ctx = ctx_from(&[
            PairingCandidate::TurnBoundary,
            PairingCandidate::ToolCall(PairedTool { tool_call_id: None, tool_name: "mcp__cass-mcp__cass_search".into(), args: Some(serde_json::json!({})) }),
            PairingCandidate::ToolResult { tool_call_id: None },
        ]);
        let m = msg("tool_result", "{}");
        assert!(
            decide(&m, 2, &event, &ctx, "claude_code", &paths_cfg()).is_none(),
            "two id-less ToolResult blocks in the same event is ambiguous -- decide must return None (宁漏勿误), not Some with an empty target_blocks"
        );
    }

    /// R2-B4 (任务书 #119a): the OTHER known member -- a call resolved via
    /// R4's id-less "exactly one unpaired" fallback still carries that
    /// call's OWN `tool_call_id` (`Some(id)`), but the actual `ToolResult`
    /// block(s) in this event are themselves id-less (`tool_use_id: None`).
    /// Filtering `event.blocks` by `tool_use_id == Some(id)` then never
    /// matches anything -- `target_blocks` comes out empty for a structural
    /// reason distinct from the ambiguous-candidates case above, and must
    /// likewise make `decide` return `None`, not `Some` with an empty vec.
    #[test]
    fn r2_b4_decide_is_none_when_id_resolved_call_meets_id_less_result_block() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, None)] };
        let ctx = ctx_from(&[
            PairingCandidate::TurnBoundary,
            PairingCandidate::ToolCall(PairedTool { tool_call_id: None, tool_name: "mcp__cass-mcp__cass_search".into(), args: Some(serde_json::json!({})) }),
            PairingCandidate::ToolResult { tool_call_id: None },
        ]);
        // `paired_call_for` resolves via R4's id-less fallback, but the
        // resolved `PairedTool` here is constructed with a `tool_call_id`
        // (unlike the fixture above) to model the real-world shape R2-B4
        // names explicitly: the call itself carries an id (from its own
        // connector event), yet the paired `ToolResult` block has none.
        let ctx_with_id = PairingContext { resolved: ctx.resolved.iter().map(|(&idx, pt)| (idx, PairedTool { tool_call_id: Some("t1".into()), ..pt.clone() })).collect() };
        let m = msg("tool_result", "{}");
        assert!(
            decide(&m, 2, &event, &ctx_with_id, "claude_code", &paths_cfg()).is_none(),
            "call resolved with a tool_call_id but the event's own ToolResult block carries none -- target block cannot be uniquely located, decide must return None"
        );
    }

    #[test]
    fn r1_d_codex_bare_name_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool { tool_call_id: Some("t1".into()), tool_name: "cass_search".into(), args: Some(serde_json::json!({})) }),
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

    /// R2-N11 (任务书 #119b): a Windows absolute path (backslash separators,
    /// drive letter) must still match `memory_files` under the cc-workspace
    /// root, same as its POSIX-style equivalent -- pre-fix, `predicate_p`
    /// treated `C:/...` (post-normalization) as relative (didn't start with
    /// `/`) and could only ever match `injection_only_files`.
    #[test]
    fn r2_n11_windows_absolute_path_memory_file_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Read".into(),
                args: Some(serde_json::json!({"file_path": "C:\\projects\\cc-workspace\\USER.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        let decision = decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).expect("R2-N11 Windows absolute path must match");
        assert_eq!(decision.reason, ExclusionReason::ContextFileRead);
    }

    /// Reverse of the positive above: a Windows absolute path OUTSIDE
    /// cc-workspace must still be rejected -- proves the fix widened
    /// "recognized as absolute" without also widening "anchored under
    /// cc-workspace" to match anything.
    #[test]
    fn r2_n11_windows_absolute_path_outside_cc_workspace_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Read".into(),
                args: Some(serde_json::json!({"file_path": "C:\\other\\USER.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(
            decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(),
            "Windows absolute path outside cc-workspace must not match (R2-N11 must not widen matching itself)"
        );
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

    /// R1-N10 (任务书 #118b): a newline-joined "command" is two separate
    /// shell commands to a real shell, not `cat`'s two path arguments --
    /// `shell_words::split` treats `\n` as an ordinary token separator, so
    /// this must be explicitly rejected the same way `|`/`;`/`&&` already
    /// are.
    #[test]
    fn r2_bash_newline_separated_commands_rejected_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Bash".into(),
                args: Some(serde_json::json!({"command": "cat /home/ivan/projects/cc-workspace/USER.md\n/home/ivan/projects/cc-workspace/TOOLS.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        assert!(decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(), "newline-joined commands must not match (R2-e)");
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

    /// R1-N9 (任务书 #118b): `cc-workspace/USER.md` and `../cc-workspace/USER.md`
    /// are RELATIVE paths (no leading `/`) -- `predicate_p` must only match
    /// them against `injection_only_files` (R2-d), never `memory_files`,
    /// even though `anchored_under_cc_workspace`'s raw substring search
    /// would otherwise find a `cc-workspace` segment in either string. A
    /// relative path proves nothing about which real directory it resolves
    /// under.
    #[test]
    fn r2_relative_cc_workspace_prefixed_memory_file_not_anchored_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        for relative_path in ["cc-workspace/USER.md", "../cc-workspace/USER.md"] {
            let ctx = ctx_from(&[
                PairingCandidate::ToolCall(PairedTool {
                    tool_call_id: Some("t1".into()),
                    tool_name: "Read".into(),
                    args: Some(serde_json::json!({"file_path": relative_path})),
                }),
                PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
            ]);
            let m = msg("tool_result", "file contents");
            assert!(
                decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(),
                "relative path {relative_path:?} must not match a memory_files name via a bare substring search"
            );
        }
    }

    /// R1-N9 (任务书 #118b): `anchor.paths` must store the NORMALIZED path
    /// (forward slashes, `..` resolved), not the raw string the tool call
    /// carried.
    #[test]
    fn r2_anchor_paths_stores_normalized_path() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = ctx_from(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Read".into(),
                args: Some(serde_json::json!({"file_path": "/home/ivan/projects/cc-workspace/sub/../MEMORY.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let m = msg("tool_result", "file contents");
        let decision = decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()).expect("must match after `..` resolves to the repo root");
        assert_eq!(decision.anchor.paths, Some(vec!["/home/ivan/projects/cc-workspace/MEMORY.md".to_string()]));
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

    /// R1-N11 (任务书 #118b): `<cwd>` must be INSIDE the
    /// `<environment_context>` block, not merely present somewhere earlier
    /// in the message -- a real request that happens to mention `<cwd>` on
    /// its own, followed by an unrelated empty env-context block, must not
    /// match.
    #[test]
    fn r3_cwd_outside_environment_context_block_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![text_block(0)] };
        let ctx = PairingContext::default();
        let m = msg("user", "<cwd>/home/u/project</cwd> please look at this real request\n<environment_context>\n</environment_context>");
        assert!(decide(&m, 0, &event, &ctx, "codex", &paths_cfg()).is_none(), "cwd outside the environment_context block must not match (R3)");
    }

    /// R2-N12 (任务书 #119b): the negative case above puts `<cwd>` BEFORE the
    /// open tag; this one is the R2 report's actual reproduction -- `<cwd>`
    /// appears AFTER the open tag but also after that SAME block's close tag
    /// (the first environment-context block closes empty immediately), with
    /// a second unrelated close tag trailing the message to satisfy the
    /// outer `ends_with` check. The two tests exercise different code paths
    /// in `anchor3_shell_opener` (one fails the `contains("<cwd>")` check
    /// entirely; this one needs the close-tag boundary specifically) and
    /// must not be treated as the same coverage.
    #[test]
    fn r3_cwd_after_close_tag_of_first_environment_context_block_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![text_block(0)] };
        let ctx = PairingContext::default();
        let m = msg("user", "<environment_context></environment_context><cwd>/x</cwd></environment_context>");
        assert!(
            decide(&m, 0, &event, &ctx, "codex", &paths_cfg()).is_none(),
            "cwd after the first environment_context block's own close tag must not match, even \
             though a second close tag later satisfies ends_with (R2-N12)"
        );
    }

    /// R3-N3 (任务书 #119d, 回归): the R2-N12 fix above narrowed the search to
    /// the FIRST `<environment_context>` block only -- if a message shows an
    /// empty example block before the real one (a shape codex's own opener
    /// text produces: "Example: <environment_context></environment_context>"
    /// followed by the actual `<environment_context><cwd>...`), the fix
    /// never looked past that first empty block and returned `None`,
    /// silently un-matching a message that satisfies R3's structural shape
    /// exactly like `r3_a_opener_agents_md_positive` does. This must match
    /// (and must NOT be confused with `r3_cwd_after_close_tag_of_first_
    /// environment_context_block_negative` above, which is deliberately the
    /// opposite verdict for a superficially similar "empty block first"
    /// shape -- that one's `<cwd>` sits OUTSIDE any complete block, this
    /// one's sits INSIDE its own complete second block).
    ///
    /// Frozen-corpus check (任务书 #119d, `W6_ARTIFACTS/n3-corpus-compare-119d.txt`):
    /// old (pre-fix) vs new (this fix) predicate run over all 1,684 codex
    /// idx=0 role=user messages in the read-only `copy/agent_search.db`
    /// basis library (spec §2.1's own population) -- 1,665 hits both sides,
    /// 0 messages differ. This corpus does not happen to contain the
    /// "empty example block, then real block" shape this fix targets, so
    /// the fix is a no-op on it; it is not evidence the bug was harmless,
    /// only that this particular frozen sample doesn't exercise it (mirrors
    /// the R3 review's own finding on the same population).
    #[test]
    fn r3_n3_second_environment_context_block_with_cwd_after_empty_example_block_positive() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![text_block(0)] };
        let ctx = PairingContext::default();
        let text = "# AGENTS.md instructions\nExample: <environment_context></environment_context>\n<environment_context><cwd>/project</cwd></environment_context>";
        let m = msg("user", text);
        let decision = decide(&m, 0, &event, &ctx, "codex", &paths_cfg())
            .expect("R3-N3: a later environment_context block containing <cwd> must match even when an earlier block is empty");
        assert_eq!(decision.reason, ExclusionReason::CodexHostShell);
        assert_eq!(decision.anchor.shell.as_ref().unwrap().opener, "# AGENTS.md instructions");
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
            PairingCandidate::ToolCall(PairedTool { tool_call_id: None, tool_name: "mcp__cass-mcp__cass_search".into(), args: Some(serde_json::json!({})) }),
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

    /// R1-B5 (任务书 #118a): two different `ToolCall`s reusing the same
    /// `tool_call_id` (T1b measured 416 real `ambiguous_call_id` cases) must
    /// leave BOTH of their results unpaired (宁漏勿误), never bind an
    /// ordinary result to the wrong call's identity.
    #[test]
    fn r4_duplicate_tool_call_id_leaves_both_results_unpaired_negative() {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1")), tool_result_block(1, Some("t1"))] };
        let ctx = ctx_from(&[
            // Call A: an ordinary, non-excluded tool.
            PairingCandidate::ToolCall(PairedTool { tool_call_id: Some("t1".into()), tool_name: "SomeOtherTool".into(), args: Some(serde_json::json!({})) }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
            // Call B: reuses the SAME id, and is itself a cass-mcp recall call.
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "mcp__cass-mcp__cass_search".into(),
                args: Some(serde_json::json!({})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let result_a = msg("tool_result", "ordinary result A, must never be excluded");
        let result_b = msg("tool_result", "recall result B");
        assert!(
            decide(&result_a, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none(),
            "call A's result must not be excluded just because a later call reused its id"
        );
        assert!(
            decide(&result_b, 3, &event, &ctx, "claude_code", &paths_cfg()).is_none(),
            "call B's own result must ALSO stay unpaired once its id is ambiguous (宁漏勿误), not just A's"
        );
    }

    #[test]
    fn r4_result_pairing_is_position_constrained_negative() {
        // B03 (任务书 #131): R1-B5's ledger says the fix includes "限定配对到
        // 结果之前的调用"; the tree only ever had the visible-duplicate-id
        // half. `by_id` indexed every call in the SESSION up front, so when a
        // concatenated/compacted log keeps a result whose own call is gone
        // and a LATER position reuses that id, the ordinary result bound to
        // the later call -- and was then judged (and cleared) as that call's
        // `context_file_read`.
        let later_project_read = || {
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("x".into()),
                tool_name: "mcp__ccw-control-plane__project_read".into(),
                args: Some(serde_json::json!({"document": "exec"})),
            })
        };
        let event = RawEvent { event_key: "later".into(), blocks: vec![tool_result_block(0, Some("x"))] };

        let ctx = ctx_from(&[PairingCandidate::ToolResult { tool_call_id: Some("x".into()) }, later_project_read()]);
        assert!(ctx.paired_call_for(0).is_none(), "a result that precedes its call must not pair to it");
        let ordinary = msg("tool_result", "ordinary result before the read ever occurred");
        assert!(
            decide(&ordinary, 0, &event, &ctx, "claude_code", &paths_cfg()).is_none(),
            "the earlier ordinary result must stay unpaired (and so unexcluded), not bind to the later call"
        );

        // Control: the very same pair, in call-then-result order, still
        // resolves and is judged exactly as before.
        let ctx = ctx_from(&[later_project_read(), PairingCandidate::ToolResult { tool_call_id: Some("x".into()) }]);
        assert!(ctx.paired_call_for(1).is_some(), "call-then-result order must keep pairing");
        let hit = msg("tool_result", "exec doc contents");
        let decision = decide(&hit, 1, &event, &ctx, "claude_code", &paths_cfg()).expect("the control pair must still resolve");
        assert_eq!(decision.reason, ExclusionReason::ContextFileRead);
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
    #[serial]
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

    /// R1-N25 (任务书 #118b): `apply` used to call `redact_text`
    /// unconditionally regardless of `CASS_REDACT_SECRETS`, while the
    /// ordinary (non-excluded) mapping layer gates its own redaction on
    /// `redaction_enabled()` -- with the env var disabled, marker.sha256
    /// still corresponded to the redacted string instead of "what should
    /// have been written to content" (the original, un-redacted string),
    /// breaking the audit/dedup identity contract for that config. Uses the
    /// same synthetic-secret fixture as the sibling positive test above
    /// (`AKIAABCDEFGHIJKLMNOP`, a real AWS-access-key-shaped pattern the
    /// redactor detects) so the two configs are actually distinguishable --
    /// a fixture with no detectable secret would hash identically either
    /// way and prove nothing.
    #[test]
    #[serial]
    fn apply_hashes_original_string_when_redaction_disabled() {
        unsafe { std::env::set_var("CASS_REDACT_SECRETS", "0") };
        let mut m = msg("tool_result", "here is my AKIAABCDEFGHIJKLMNOP secret and the rest of the hit");
        let decision = decision_cass_recall(vec![]);
        let mut redactor = MemoizingRedactor::new();
        let marker = apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 3, &[]);
        unsafe { std::env::remove_var("CASS_REDACT_SECRETS") };

        assert_eq!(m.content, "", "content must still be cleared regardless of redaction config");
        assert_eq!(
            marker.sha256,
            sha256_hex("here is my AKIAABCDEFGHIJKLMNOP secret and the rest of the hit"),
            "with redaction disabled, sha must be over the ORIGINAL string (what would have been written to content), not a redacted one"
        );
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

    /// R2-B2 (任务书 #119a): a top-level STRING `toolUseResult` (distinct
    /// from the nested-object `.file.content` shape above) carries the raw
    /// tool_result body directly -- measured on the frozen corpus: 1,533
    /// `context_file_read` + 25 `cass_recall` rows where this string is
    /// byte-identical to `message.content`. Pre-fix, `EXTRA_FIELD_MAP`'s
    /// claude_code entry had no path for this shape at all, so the full
    /// original body survived in `extra` even though `content` was cleared
    /// -- violating "原文只在 raw-mirror".
    #[test]
    fn apply_replaces_string_form_tool_use_result_for_claude_code() {
        let mut m = msg("tool_result", "the recall hit body");
        m.extra = serde_json::json!({"toolUseResult": "the recall hit body"});
        let decision = decision_cass_recall(vec![]);
        let mut redactor = MemoizingRedactor::new();
        apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("claude_code"));

        assert_eq!(m.extra["toolUseResult"]["redacted"], serde_json::json!(true), "a string-form toolUseResult must be replaced wholesale");
    }

    /// R2-B2 mutation guard: the type-guarded string check must NOT touch
    /// the object shape's sibling metadata -- if a future edit made the
    /// replacement unconditional on type, this would start nuking
    /// `filePath`/`numLines`/etc. alongside `.file.content`. Restates the
    /// sibling-survives assertion from
    /// `apply_replaces_tool_use_result_file_content_for_claude_code` as its
    /// own named case so the two shapes' tests can't silently regress
    /// independently of each other.
    #[test]
    fn apply_object_form_tool_use_result_untouched_by_string_only_strip() {
        let mut m = msg("tool_result", "the file body");
        m.extra = serde_json::json!({"toolUseResult": {"file": {"content": "the file body"}, "filePath": "/tmp/x", "type": "text"}});
        let decision = decision_cass_recall(vec![]);
        let mut redactor = MemoizingRedactor::new();
        apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("claude_code"));

        assert_eq!(m.extra["toolUseResult"]["file"]["content"]["redacted"], serde_json::json!(true), "the sub-path entry must still redact the nested content");
        assert_eq!(m.extra["toolUseResult"]["filePath"], serde_json::json!("/tmp/x"), "non-body metadata sibling to .file must survive");
        assert_eq!(m.extra["toolUseResult"]["type"], serde_json::json!("text"), "non-body metadata sibling to .file must survive");
    }

    /// B04 (任务书 #131): R3-N2's all-members guard was itself the reverse
    /// hole. An event carrying two `tool_result` blocks where only block 0 is
    /// targeted had its top-level string copy left behind EVEN WHEN that
    /// string was byte-identical to the very block being cleared -- so the
    /// excluded body stayed in `extra_bin` while the row reported a
    /// successful exclusion, breaking R2-B2's "原文只在 raw-mirror".
    /// (`apply_sibling` was worse off still: it always passes ONE block, so
    /// the all-members guard could never be satisfied.)
    ///
    /// The guard is now an *ownership proof*: the string is cleared when it
    /// equals -- or contains, within the bounded gate -- the pre-clear body
    /// of a block THIS call is clearing, and left alone otherwise. That keeps
    /// R3-N2's over-clear protection (a string holding another block's body
    /// survives) without re-opening R2-B2's leak.
    #[test]
    fn apply_clears_string_tool_use_result_only_when_it_proves_ownership() {
        let two_results = |string: &str| {
            serde_json::json!({
                "type": "user",
                "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "a", "content": "secret A"},
                    {"type": "tool_result", "tool_use_id": "b", "content": "secret B"}
                ]},
                "toolUseResult": string
            })
        };

        // (a) Targeting block 0, string == block 0's own body: PROVEN, clear.
        // Pre-fix the all-members guard returned early here and the excluded
        // body survived in `extra`.
        let mut owned = msg("tool_result", "secret A");
        owned.extra = two_results("secret A");
        let mut redactor = MemoizingRedactor::new();
        apply(&mut owned, &decision_cass_recall(vec![0]), &mut redactor, "blobs/blake3/ab/abcd.raw", 1, field_map_for("claude_code"));
        assert_eq!(
            owned.extra["toolUseResult"]["redacted"],
            serde_json::json!(true),
            "a string byte-equal to the targeted block's own body is that body's copy and must be cleared, got {:?}",
            owned.extra["toolUseResult"]
        );
        assert!(
            !owned.extra.to_string().contains("secret A"),
            "no raw copy of the excluded body may remain anywhere in extra: {:?}",
            owned.extra
        );

        // (b) Targeting block 0, string == block 1's body: not this call's
        // copy, keep it (the R3-N2 protection, restated on the new rule).
        let mut unowned = msg("tool_result", "secret A");
        unowned.extra = two_results("secret B");
        let mut redactor = MemoizingRedactor::new();
        apply(&mut unowned, &decision_cass_recall(vec![0]), &mut redactor, "blobs/blake3/ab/abcd.raw", 1, field_map_for("claude_code"));
        assert_eq!(
            unowned.extra["toolUseResult"],
            serde_json::json!("secret B"),
            "a string belonging to an un-targeted block must survive, got {:?}",
            unowned.extra["toolUseResult"]
        );

        // (c) Both blocks targeted: the string belongs to one of them.
        let mut both_targeted = msg("tool_result", "secret A");
        both_targeted.extra = two_results("secret A");
        let mut redactor = MemoizingRedactor::new();
        apply(&mut both_targeted, &decision_cass_recall(vec![0, 1]), &mut redactor, "blobs/blake3/ab/abcd.raw", 1, field_map_for("claude_code"));
        assert_eq!(both_targeted.extra["toolUseResult"]["redacted"], serde_json::json!(true), "when every tool_result block is targeted the string belongs to one of them");

        // (d) The single-result shape the frozen corpus actually has.
        let mut single = msg("tool_result", "secret A");
        single.extra = serde_json::json!({
            "type": "user",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "a", "content": "secret A"}
            ]},
            "toolUseResult": "secret A"
        });
        let mut redactor = MemoizingRedactor::new();
        apply(&mut single, &decision_cass_recall(vec![0]), &mut redactor, "blobs/blake3/ab/abcd.raw", 1, field_map_for("claude_code"));
        assert_eq!(single.extra["toolUseResult"]["redacted"], serde_json::json!(true), "the corpus' single-result shape must keep being cleared");

        // (e) A bounded superset (the copy wrapped in decoration) is the same
        // copy; the length gate keeps this from becoming "clear anything
        // containing the body".
        let mut wrapped = msg("tool_result", "secret A");
        wrapped.extra = two_results("prefix :: secret A :: suffix");
        let mut redactor = MemoizingRedactor::new();
        apply(&mut wrapped, &decision_cass_recall(vec![0]), &mut redactor, "blobs/blake3/ab/abcd.raw", 1, field_map_for("claude_code"));
        assert_eq!(wrapped.extra["toolUseResult"]["redacted"], serde_json::json!(true), "a bounded superset of the owned body is that same copy");

        // (f) The row's own pre-clear content is an ownership proof too: the
        // minimal `{"toolUseResult": "..."}` extras have no inspectable block
        // array at all, so attribution has nothing else to go on.
        let mut minimal = msg("tool_result", "the recall hit body");
        minimal.extra = serde_json::json!({"toolUseResult": "the recall hit body"});
        let mut redactor = MemoizingRedactor::new();
        apply(&mut minimal, &decision_cass_recall(vec![0]), &mut redactor, "blobs/blake3/ab/abcd.raw", 1, field_map_for("claude_code"));
        assert_eq!(minimal.extra["toolUseResult"]["redacted"], serde_json::json!(true), "the row's own pre-clear body proves the string is its copy");

        // (g) ...and it proves nothing about a DIFFERENT string.
        let mut foreign = msg("tool_result", "the recall hit body");
        foreign.extra = serde_json::json!({"toolUseResult": "some other body"});
        let mut redactor = MemoizingRedactor::new();
        apply(&mut foreign, &decision_cass_recall(vec![0]), &mut redactor, "blobs/blake3/ab/abcd.raw", 1, field_map_for("claude_code"));
        assert_eq!(foreign.extra["toolUseResult"], serde_json::json!("some other body"), "an unrelated string must not be cleared just because this row is excluded");
    }

    /// B04, `apply_sibling` path: a sibling row (same event, projected into a
    /// second row) has no `original` of its own to offer -- content is never
    /// cleared for it -- so attribution has to come from its own copy of the
    /// event. Before the fix this path could never clear the string at all:
    /// it always passes exactly ONE block, and the all-members guard demanded
    /// every block be targeted.
    #[test]
    fn apply_sibling_clears_owned_string_tool_use_result() {
        let mut row = msg("user", "ordinary sibling prose");
        // The report's shape: a two-result event where only A is targeted.
        // The sibling row carries the whole event, so its own copy of A's
        // body must go -- but its copy of the OTHER block's body must not.
        row.extra = serde_json::json!({
            "type": "user",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "a", "content": "secret A"},
                {"type": "tool_result", "tool_use_id": "b", "content": "secret B"}
            ]},
            "toolUseResult": "secret A"
        });
        let marker = ExcludedMarker {
            reason: ExclusionReason::CassRecall,
            rule_version: 1,
            bytes: 8,
            sha256: sha256_hex("secret A"),
            fingerprint_blake3: blake3_hex("secret A"),
            anchor: ExclusionAnchor { tool_call_id: Some("a".into()), tool_name: Some("Read".into()), paths: None, shell: None },
            src: None,
            parse_error: None,
            raw: RawRef { blob: "blobs/blake3/ab/abcd.raw".into(), idx: 1, event_key: "ek1".into(), blocks: vec![0] },
        };
        apply_sibling(&mut row, &marker, field_map_for("claude_code"));

        assert_eq!(row.content, "ordinary sibling prose", "apply_sibling must never touch content");
        assert_eq!(row.extra["message"]["content"][0]["content"]["redacted"], serde_json::json!(true), "the sibling's copy of the targeted block is redacted");
        assert_eq!(row.extra["message"]["content"][1]["content"], serde_json::json!("secret B"), "the sibling's copy of an un-targeted block survives");
        assert_eq!(row.extra["toolUseResult"]["redacted"], serde_json::json!(true), "the sibling's copy of the excluded body's top-level string must not survive");
    }

    #[test]
    fn apply_replaces_codex_payload_output_text() {
        // N1 (任务书 #118a): array-form `payload.output` is replaced
        // WHOLESALE (R6: "整体记 [0]"), not just element 0's `.text`
        // sub-field -- a second array element (or any other sibling field
        // on the array itself) would otherwise survive redaction.
        let mut m = msg("tool_result", "codex output text");
        m.extra = serde_json::json!({"payload": {"output": [{"text": "codex output text"}, {"text": "a second element must also be gone"}]}});
        let decision = decision_cass_recall(vec![0]);
        let mut redactor = MemoizingRedactor::new();
        apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("codex"));

        assert_eq!(m.extra["payload"]["output"]["redacted"], serde_json::json!(true), "the whole array must be replaced, not just element 0");
        assert!(m.extra["payload"]["output"].get(1).is_none(), "no array element may survive under the replaced value");
    }

    /// N1 (任务书 #118a): a bare non-array STRING `payload.output` (T1b:
    /// 49,718 real codex tool-result outputs use this shape) was completely
    /// unmapped pre-fix -- `.and_then(|v| v.as_array_mut())` returns `None`
    /// for a string, so the field silently survived redaction untouched.
    #[test]
    fn apply_replaces_codex_string_form_payload_output() {
        let mut m = msg("tool_result", "README.md\n");
        m.extra = serde_json::json!({"payload": {"output": "README.md\n"}});
        let decision = decision_cass_recall(vec![0]);
        let mut redactor = MemoizingRedactor::new();
        apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("codex"));

        assert_eq!(m.extra["payload"]["output"]["redacted"], serde_json::json!(true));
    }

    /// N1 (任务书 #118a): the separate `event_msg`/`user_message` shape
    /// carries its text on `payload.message`, not `payload.content`/
    /// `.output` -- entirely unmapped pre-fix.
    #[test]
    fn apply_replaces_codex_event_msg_user_message_payload_message() {
        let mut m = msg("user", "please rotate the leaked key");
        m.extra = serde_json::json!({"type": "event_msg", "payload": {"type": "user_message", "message": "please rotate the leaked key"}});
        let decision = decision_cass_recall(vec![0]);
        let mut redactor = MemoizingRedactor::new();
        apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("codex"));

        assert_eq!(m.extra["payload"]["message"]["redacted"], serde_json::json!(true));
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
        // R1-N7 (任务书 #118a): `source_id` is a string in every real
        // cass-mcp response (T1b: 176/176 real hits, e.g. `"local"`).
        let mut m = msg(
            "tool_result",
            r#"{"hits": [{"source_id": "local", "source_path": "/home/x/session.jsonl", "line_number": 214}]}"#,
        );
        let decision = decision_cass_recall(vec![]);
        let mut redactor = MemoizingRedactor::new();
        let marker = apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("claude_code"));
        assert_eq!(
            marker.src,
            Some(RecallSrc {
                sessions: vec!["/home/x/session.jsonl".to_string()],
                hits: vec![RecallHit { source_id: "local".to_string(), source_path: "/home/x/session.jsonl".to_string(), line_number: Some(214) }],
            })
        );
        assert!(marker.parse_error.is_none());
    }

    /// Mutation for N7: an INTEGER `source_id` (the pre-fix assumption --
    /// no real cass-mcp response has ever used this shape) must now be a
    /// parse failure, proving the old `i64` field would have rejected
    /// every genuine response.
    #[test]
    fn apply_r1_c_integer_source_id_is_a_parse_failure_mutation() {
        let mut m = msg("tool_result", r#"{"hits": [{"source_id": 3, "source_path": "/home/x/session.jsonl"}]}"#);
        let decision = decision_cass_recall(vec![]);
        let mut redactor = MemoizingRedactor::new();
        let marker = apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("claude_code"));
        assert!(marker.src.is_none(), "an integer source_id (never seen in real responses) must not parse under the string-typed field");
        assert!(marker.parse_error.is_some());
    }

    #[test]
    fn apply_r1_c_error_shaped_response_sets_empty_src_not_parse_error() {
        // R1-c v4.5: `{"error":"cass_exit",...}` is a legitimate cass-mcp
        // answer (the underlying `cass` invocation failed) -- empty src,
        // no parse_error.
        let mut m = msg("tool_result", r#"{"error": "cass_exit", "code": 127, "stderr": "not found"}"#);
        let decision = decision_cass_recall(vec![]);
        let mut redactor = MemoizingRedactor::new();
        let marker = apply(&mut m, &decision, &mut redactor, "blobs/blake3/ab/abcd.raw", 0, field_map_for("claude_code"));
        assert_eq!(marker.src, Some(RecallSrc::default()));
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

    #[test]
    fn apply_r1_c_json_without_hits_or_error_sets_parse_error() {
        let mut m = msg("tool_result", r#"{"query": "x", "count": 0}"#);
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

    /// R2-N6 (任务书 #129): the frozen interface (spec v4.5 §2.3 / R6 section
    /// of `docs/excluded-rules.md`) is "字段齐全、空值为 null" -- every key is
    /// written on EVERY marker, with `null` where the value is absent.
    /// `skip_serializing_if = "Option::is_none"` broke that for the
    /// usually-empty fields: a context-file marker lost `src`/
    /// `parse_error`/`tool_call_id`/`tool_name`/`shell` outright. The
    /// round-trip test above cannot see that -- it compares Rust objects,
    /// which are equal whether or not the key was written. This one compares
    /// JSON key SETS, i.e. what a reader of the JSONB column actually sees.
    /// The key-set assertion is the load-bearing one: `value["x"].is_null()`
    /// alone would also hold for an omitted key (serde_json's `Index` yields
    /// `Null` for a missing key), so the `is_null` checks below only pin
    /// "present and empty", never "present".
    #[test]
    fn excluded_marker_json_always_carries_every_frozen_key() {
        fn key_set(value: &serde_json::Value) -> std::collections::BTreeSet<String> {
            value
                .as_object()
                .expect("marker JSON must be an object")
                .keys()
                .cloned()
                .collect()
        }
        fn frozen(names: &[&str]) -> std::collections::BTreeSet<String> {
            names.iter().map(|n| (*n).to_string()).collect()
        }

        let context_file = ExcludedMarker {
            reason: ExclusionReason::ContextFileRead,
            rule_version: 1,
            bytes: 4380,
            sha256: "a".repeat(64),
            fingerprint_blake3: "b".repeat(64),
            // Every anchor field except `paths` empty: the shape a real
            // context-file-read marker has.
            anchor: ExclusionAnchor {
                tool_call_id: None,
                tool_name: None,
                paths: Some(vec!["/x".into()]),
                shell: None,
            },
            src: None,
            parse_error: None,
            raw: RawRef {
                blob: "blobs/blake3/ab/abcd.raw".into(),
                idx: 17,
                event_key: "ek".into(),
                blocks: vec![1],
            },
        };
        // R1-c's id-less pairing shape: empty `tool_call_id`, present `src`,
        // and its only optional per-hit field (`line_number`) empty too.
        let pairing = ExcludedMarker {
            reason: ExclusionReason::CassRecall,
            rule_version: 1,
            bytes: 12,
            sha256: "c".repeat(64),
            fingerprint_blake3: "d".repeat(64),
            anchor: ExclusionAnchor::default(),
            src: Some(RecallSrc {
                sessions: vec!["/s.jsonl".into()],
                hits: vec![RecallHit {
                    source_id: "local".into(),
                    source_path: "/s.jsonl".into(),
                    line_number: None,
                }],
            }),
            parse_error: None,
            raw: RawRef {
                blob: "blobs/blake3/ab/abcd.raw".into(),
                idx: 0,
                event_key: "line:1".into(),
                blocks: vec![],
            },
        };

        let top_level = frozen(&[
            "reason",
            "rule_version",
            "bytes",
            "sha256",
            "fingerprint_blake3",
            "anchor",
            "src",
            "parse_error",
            "raw",
        ]);
        for (label, marker) in [("context_file_read", &context_file), ("cass_recall", &pairing)] {
            let value: serde_json::Value =
                serde_json::from_str(&marker.to_json_string()).expect("marker JSON parses");
            assert_eq!(key_set(&value), top_level, "{label}: every frozen top-level key must be written");
            assert_eq!(
                key_set(&value["anchor"]),
                frozen(&["tool_call_id", "tool_name", "paths", "shell"]),
                "{label}: anchor must carry all four keys"
            );
            assert_eq!(
                key_set(&value["raw"]),
                frozen(&["blob", "idx", "event_key", "blocks"]),
                "{label}: raw must carry all four keys"
            );
            assert!(value["parse_error"].is_null(), "{label}: absent parse_error must be null");
            assert!(value["anchor"]["tool_call_id"].is_null(), "{label}: absent tool_call_id must be null");
            assert!(value["anchor"]["tool_name"].is_null(), "{label}: absent tool_name must be null");
            assert!(value["anchor"]["shell"].is_null(), "{label}: absent shell must be null");
        }

        let context_file_value: serde_json::Value =
            serde_json::from_str(&context_file.to_json_string()).unwrap();
        assert!(
            context_file_value["src"].is_null(),
            "an absent src must be written as null (key present, per the set assertion above)"
        );

        let pairing_value: serde_json::Value = serde_json::from_str(&pairing.to_json_string()).unwrap();
        assert_eq!(
            key_set(&pairing_value["src"]),
            frozen(&["sessions", "hits"]),
            "a present src must carry both keys"
        );
        let hit = &pairing_value["src"]["hits"][0];
        assert_eq!(
            key_set(hit),
            frozen(&["source_id", "source_path", "line_number"]),
            "a recall hit must carry all three keys"
        );
        assert!(hit["line_number"].is_null(), "an absent hit line_number must be null");
    }

    /// R1-B4 (任务书 #118a): a malformed `fingerprint_blake3` (structurally
    /// valid JSON, invalid hex/length) must be a plain `Err` from
    /// `from_json_str` itself -- never a `Message` that later `.expect()`s
    /// its way into a process abort inside `storage::sqlite`'s merge/replay
    /// fingerprint helpers (release builds are `panic = "abort"`).
    #[test]
    fn from_json_str_rejects_malformed_fingerprint_blake3() {
        let json = format!(
            r#"{{"reason":"context_file_read","rule_version":1,"bytes":4,"sha256":"{}","fingerprint_blake3":"zz","anchor":{{}},"raw":{{"blob":"blobs/blake3/ab/abcd.raw","idx":0,"event_key":"ek","blocks":[]}}}}"#,
            "a".repeat(64)
        );
        let err = ExcludedMarker::from_json_str(&json).expect_err("length/hex-invalid fingerprint_blake3 must be rejected, not silently accepted");
        assert!(err.to_string().contains("fingerprint_blake3"), "error must name the offending field: {err}");
    }

    /// Mutation for the above: reverting `from_json_str` to a bare
    /// `serde_json::from_str` (no hex/length validation) would make this
    /// malformed marker parse successfully -- confirmed by inspection of
    /// the pre-fix code (`Ok(serde_json::from_str(s)?)`), which has no way
    /// to fail on a structurally-valid-but-wrong-length string field.
    #[test]
    fn from_json_str_rejects_wrong_length_sha256() {
        let json = format!(
            r#"{{"reason":"context_file_read","rule_version":1,"bytes":4,"sha256":"deadbeef","fingerprint_blake3":"{}","anchor":{{}},"raw":{{"blob":"blobs/blake3/ab/abcd.raw","idx":0,"event_key":"ek","blocks":[]}}}}"#,
            "b".repeat(64)
        );
        let err = ExcludedMarker::from_json_str(&json).expect_err("short sha256 must be rejected");
        assert!(err.to_string().contains("sha256"), "error must name the offending field: {err}");
    }
}
