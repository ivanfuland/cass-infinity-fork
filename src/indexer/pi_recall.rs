// Dead-code tolerated module-wide: the structural facts and the cleanup
// consumer share helpers whose only caller inside a single build may be the
// other one. The Pi cleanup ticket (02) consumes `PiFacts`, its bindings,
// candidate results and body shapes, and runs the shared v2 recall judgment
// for `pi_agent`; the facts module's own tests remain the second reader.
#![allow(dead_code)]

//! Tickets 01 and 02 (`cass-alien-fresh-ingest`): Pi raw-event facts, unique
//! tool-call binding, and the full-cleanup consumer.
//!
//! Ticket 01 builds the structural facts. Ticket 02 judges and clears the
//! proven CASS recall results of a `pi_agent` conversation through the same
//! direct-tool core the old v2 entry uses. Neither ticket adds a CLI/MCP
//! surface, changes a legacy `PairingContext` branch, or opens the old
//! `cass_supported_agent` gate for Pi.
//!
//! The facts are built from two inputs that must describe the same bytes:
//!
//! * the captured raw-mirror blob (the original JSONL bytes), and
//! * a `NormalizedConversation` re-projected from those bytes by the pinned
//!   `PiAgentConnector` (FAD rev `61f975f3…`, `src/connectors/pi_agent.rs`).
//!
//! The live `conversation.source_path` is never read: only the captured blob
//! is opened here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use serde_json::Value;

use crate::connectors::{NormalizedConversation, NormalizedMessage};
use crate::indexer::exclusion::{
    BlockKind, ExcludedMarker, PairedTool, RawBlock, RawEvent, field_map_for,
};
use crate::indexer::recall_v2::{
    DirectToolCategory, Outcome, UncoveredReason, apply_with_redaction, judge_direct_tool_result,
    looks_like_recall_wrapper, parse_cli,
};
use crate::indexer::redact_secrets::MemoizingRedactor;
use crate::recall_output::{RecallTool, decode};

/// The four strong Pi tool identities from spec C1. Only the exact full name
/// is proof of attribution; an unknown MCP namespace is never treated as a
/// known server, and a bare name is not a Pi identity.
const PI_STRONG_TOOL_NAMES: [&str; 4] = [
    "mcp__cass_mcp__cass_search",
    "mcp__cass_mcp__cass_expand",
    "mcp__cass_mcp__cass_sessions",
    "mcp__cass_mcp__cass_timeline",
];

/// One result-to-call binding. `result_idx` and `call_idx` are canonical
/// message indexes; `call_block_idx` is the original position of the
/// `toolCall` block inside the assistant message's `content[]`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PiBinding {
    pub(crate) result_idx: usize,
    pub(crate) call_idx: usize,
    pub(crate) call_block_idx: u32,
    pub(crate) tool_call_id: String,
    pub(crate) tool_name: String,
    pub(crate) arguments: Option<Value>,
}

/// The shape of a result's `message.content`. `Mixed` means the result
/// carries a non-text block, so ticket 02 must not guess a body boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PiResultBodyShape {
    String,
    TextBlocks,
    Mixed,
}

/// Structural facts for one Pi conversation.
#[derive(Debug, Clone)]
pub(crate) struct PiFacts {
    /// One `RawEvent` per canonical message index. `event_key` is
    /// `pi:line:N` with `N` the 1-based physical line in the captured blob;
    /// an unmatched position (only possible when `alignment_ok` is false)
    /// carries an empty key and no blocks.
    pub(crate) events: Vec<RawEvent>,
    /// Bindings keyed by result message index.
    pub(crate) bindings: BTreeMap<usize, PiBinding>,
    /// Observable candidate hint for results that may be CASS recall output:
    /// a strong full name, a bare or foreign-namespaced name whose body is a
    /// complete C04 envelope, or a nameless result tied to exactly one
    /// earlier strong CASS call. It neither upgrades an identity nor decides
    /// anything; ticket 02 still judges each candidate itself.
    pub(crate) candidate_result_indices: BTreeSet<usize>,
    /// True when every canonical message was matched one-to-one, in order,
    /// to one projected native message record and no such record was left
    /// over.
    pub(crate) alignment_ok: bool,
    /// Result body shape keyed by result message index.
    pub(crate) result_body_shapes: BTreeMap<usize, PiResultBodyShape>,
}

/// One projected native `message` record from the captured blob.
struct RawMessage {
    line_no: usize,
    value: Value,
}

/// One `toolCall` site found inside a matched assistant message.
struct CallSite {
    call_idx: usize,
    call_block_idx: u32,
    tool_name: String,
    arguments: Option<Value>,
}

impl PiFacts {
    /// Build the structural facts for `conversation` from `blob_path`.
    ///
    /// The mapping runs over the physical lines of the captured blob in
    /// order. Each canonical message consumes the next unused projected
    /// native `message` record whose whole-line `Value` equals the message's
    /// own `extra`; nothing here guesses a pairing from body text, time, the
    /// most recent call or the first invocation. A blob that cannot be read,
    /// or any position that cannot be matched one-to-one, leaves
    /// `alignment_ok` false and an empty-key event at that position.
    pub(crate) fn build(blob_path: &Path, conversation: &NormalizedConversation) -> Self {
        let raw_messages = projected_raw_messages(blob_path);
        let mut used = vec![false; raw_messages.len()];
        let mut matched: Vec<Option<usize>> = vec![None; conversation.messages.len()];
        let mut cursor = 0usize;
        let mut alignment_ok = true;

        for (idx, message) in conversation.messages.iter().enumerate() {
            let found = (cursor..raw_messages.len())
                .find(|&raw_idx| !used[raw_idx] && raw_messages[raw_idx].value == message.extra);
            match found {
                Some(raw_idx) => {
                    used[raw_idx] = true;
                    matched[idx] = Some(raw_idx);
                    cursor = raw_idx + 1;
                }
                None => alignment_ok = false,
            }
        }
        // A projected native record left over with no canonical counterpart
        // is not a one-to-one correspondence either.
        if used.iter().any(|used| !used) {
            alignment_ok = false;
        }

        let events = matched
            .iter()
            .map(|raw_idx| match raw_idx {
                Some(raw_idx) => raw_event(&raw_messages[*raw_idx]),
                None => RawEvent {
                    event_key: String::new(),
                    blocks: Vec::new(),
                },
            })
            .collect();

        let mut facts = Self {
            events,
            bindings: BTreeMap::new(),
            candidate_result_indices: BTreeSet::new(),
            alignment_ok,
            result_body_shapes: BTreeMap::new(),
        };

        // Every `toolCall` block of every matched assistant message is a
        // candidate call site, with its original block index kept.
        let calls_by_id =
            collect_call_sites(matched.iter().enumerate().filter_map(|(idx, raw_idx)| {
                raw_idx.map(|raw_idx| (idx, &raw_messages[raw_idx].value))
            }));

        for (result_idx, raw_idx) in matched.iter().enumerate() {
            let Some(raw_idx) = raw_idx else { continue };
            let value = &raw_messages[*raw_idx].value;
            if raw_role(value) != Some("toolResult") {
                continue;
            }
            facts
                .result_body_shapes
                .insert(result_idx, result_body_shape(value));

            // A structural candidate hint only. The four strong names are the
            // sole strong identity; a bare name or another MCP namespace is a
            // candidate only with the result's own complete C04 envelope, and
            // a result that lost its name stays one only through a unique
            // prior strong CASS call. None of this clears or upgrades an
            // identity, and an unrelated tool is never a candidate.
            if is_recall_candidate(value, result_idx, &calls_by_id) {
                facts.candidate_result_indices.insert(result_idx);
            }

            let tool_name = value
                .pointer("/message/toolName")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty());

            // Binding requires a non-empty id that names exactly one call
            // site, that call strictly before this result, and an exact
            // non-empty tool-name match. There is no Pi R4 fallback.
            let Some(tool_call_id) = value
                .pointer("/message/toolCallId")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
            else {
                continue;
            };
            let Some(calls) = calls_by_id.get(tool_call_id) else {
                continue;
            };
            let [call] = calls.as_slice() else { continue };
            if call.call_idx >= result_idx {
                continue;
            }
            let Some(result_name) = tool_name else {
                continue;
            };
            if result_name != call.tool_name {
                continue;
            }
            facts.bindings.insert(
                result_idx,
                PiBinding {
                    result_idx,
                    call_idx: call.call_idx,
                    call_block_idx: call.call_block_idx,
                    tool_call_id: tool_call_id.to_string(),
                    tool_name: result_name.to_string(),
                    arguments: call.arguments.clone(),
                },
            );
        }

        facts
    }
}

/// Every `toolCall` block of the given projected assistant messages, keyed by
/// call id and kept in projection order. `idx` is the projected position the
/// call site occupies, so a later check can require the call strictly before
/// its result.
fn collect_call_sites<'a>(
    messages: impl Iterator<Item = (usize, &'a Value)>,
) -> HashMap<String, Vec<CallSite>> {
    let mut calls_by_id: HashMap<String, Vec<CallSite>> = HashMap::new();
    for (idx, value) in messages {
        if raw_role(value) != Some("assistant") {
            continue;
        }
        for (block_idx, block) in content_blocks(value).iter().enumerate() {
            if block.get("type").and_then(Value::as_str) != Some("toolCall") {
                continue;
            }
            let Some(call_id) = block
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
            else {
                continue;
            };
            calls_by_id
                .entry(call_id.to_string())
                .or_default()
                .push(CallSite {
                    call_idx: idx,
                    call_block_idx: block_idx as u32,
                    tool_name: block
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    arguments: block.get("arguments").cloned(),
                });
        }
    }
    calls_by_id
}

/// Whether a result record is an identifiable CASS recall candidate. This is
/// the same predicate [`PiFacts::build`] records as a hint, exposed for the
/// alignment-failure count that must read the valid native records directly.
fn is_recall_candidate(
    value: &Value,
    result_idx: usize,
    calls_by_id: &HashMap<String, Vec<CallSite>>,
) -> bool {
    let tool_name = value
        .pointer("/message/toolName")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty());
    match tool_name {
        Some(name) if strong_recall_tool(name).is_some() => true,
        Some(name) => bare_recall_tool(name)
            .or_else(|| foreign_namespace_recall_tool(name))
            .is_some_and(|tool| declares_c04(&result_body_text(value), tool)),
        None => unique_prior_cass_call(
            value
                .pointer("/message/toolCallId")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty()),
            result_idx,
            calls_by_id,
            &result_body_text(value),
            true,
        ),
    }
}

/// Every projected native `message` record of the captured blob, with its
/// 1-based physical line number.
fn projected_raw_messages(blob_path: &Path) -> Vec<RawMessage> {
    let Ok(text) = std::fs::read_to_string(blob_path) else {
        return Vec::new();
    };
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .filter_map(|(index, line)| {
            let value: Value = serde_json::from_str(line).ok()?;
            projection_emits_message(&value).then_some(RawMessage {
                line_no: index + 1,
                value,
            })
        })
        .collect()
}

/// The connector's projection eligibility, mirrored from the pinned
/// `PiAgentConnector::flatten_message_content` (FAD `61f975f3…`,
/// `src/connectors/pi_agent.rs`): a message whose flattened content is empty
/// (for example image-only) is not projected, so it must not break the
/// one-to-one alignment.
fn projection_emits_message(value: &Value) -> bool {
    if value.get("type").and_then(Value::as_str) != Some("message") {
        return false;
    }
    let Some(content) = value.pointer("/message/content") else {
        return false;
    };
    match content {
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(blocks) => {
            let parts: Vec<String> = blocks
                .iter()
                .filter_map(|block| match block.get("type").and_then(Value::as_str) {
                    Some("text") => block
                        .get("text")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    Some("thinking") => block
                        .get("thinking")
                        .and_then(Value::as_str)
                        .map(|thinking| format!("[Thinking] {thinking}")),
                    // The connector always renders a non-empty `[Tool: …]`
                    // marker for a tool call; only emptiness matters here.
                    Some("toolCall") => Some(String::from("[Tool]")),
                    _ => None,
                })
                .collect();
            !parts.join("\n").trim().is_empty()
        }
        _ => false,
    }
}

fn raw_role(value: &Value) -> Option<&str> {
    value.pointer("/message/role").and_then(Value::as_str)
}

fn content_blocks(value: &Value) -> &[Value] {
    value
        .pointer("/message/content")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// The `RawEvent` for one projected native message. The key is the fixed
/// `pi:line:N` form so a reused native event id cannot join copies across
/// lines; the original id stays in the raw blob and the message `extra`.
fn raw_event(raw: &RawMessage) -> RawEvent {
    // A plain-string body is one logical text block at index 0. Its physical
    // line, not a synthetic block offset, still names the event.
    if let Some(Value::String(text)) = raw.value.pointer("/message/content")
        && !text.trim().is_empty()
    {
        return RawEvent {
            event_key: format!("pi:line:{}", raw.line_no),
            blocks: vec![RawBlock {
                index: 0,
                kind: BlockKind::Text,
                tool_use_id: None,
                tool_name: None,
                args: None,
            }],
        };
    }
    let blocks = content_blocks(&raw.value)
        .iter()
        .enumerate()
        .filter_map(|(index, block)| {
            let block_type = block.get("type").and_then(Value::as_str)?;
            let kind = match block_type {
                "text" if block.get("text").and_then(Value::as_str).is_some() => BlockKind::Text,
                "toolCall" => BlockKind::ToolUse,
                "toolResult" => BlockKind::ToolResult,
                _ => BlockKind::Other,
            };
            Some(RawBlock {
                index: index as u32,
                kind,
                tool_use_id: block.get("id").and_then(Value::as_str).map(str::to_string),
                tool_name: block
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                args: block.get("arguments").cloned(),
            })
        })
        .collect();
    RawEvent {
        event_key: format!("pi:line:{}", raw.line_no),
        blocks,
    }
}

/// `string` for a whole-string result, `text_blocks` only when every block is
/// text, and `mixed` for any result carrying a non-text block (ticket 02 must
/// not guess a body boundary there).
fn result_body_shape(value: &Value) -> PiResultBodyShape {
    match value.pointer("/message/content") {
        Some(Value::String(_)) => PiResultBodyShape::String,
        Some(Value::Array(blocks))
            if blocks
                .iter()
                .all(|block| block.get("type").and_then(Value::as_str) == Some("text")) =>
        {
            PiResultBodyShape::TextBlocks
        }
        _ => PiResultBodyShape::Mixed,
    }
}

/// The recall tool behind one of the four strong full names. These are the
/// only names that identify a CASS result on their own.
fn strong_recall_tool(name: &str) -> Option<RecallTool> {
    const TOOLS: [RecallTool; 4] = [
        RecallTool::Search,
        RecallTool::Expand,
        RecallTool::Sessions,
        RecallTool::Timeline,
    ];
    let position = PI_STRONG_TOOL_NAMES
        .iter()
        .position(|candidate| *candidate == name)?;
    Some(TOOLS[position])
}

/// The recall tool behind a bare name such as `cass_search`. A bare name is
/// not a Pi identity by itself: it becomes a candidate only when the result
/// body carries the complete C04 envelope for the same tool.
fn bare_recall_tool(name: &str) -> Option<RecallTool> {
    const BARE_NAMES: [(&str, RecallTool); 4] = [
        ("cass_search", RecallTool::Search),
        ("cass_expand", RecallTool::Expand),
        ("cass_sessions", RecallTool::Sessions),
        ("cass_timeline", RecallTool::Timeline),
    ];
    BARE_NAMES
        .iter()
        .find(|(bare, _)| *bare == name)
        .map(|(_, tool)| *tool)
}

/// The recall tool behind a name from another MCP namespace, for example
/// `mcp__other__cass_search`. The namespace is never treated as a known CASS
/// server, so this is only a candidate shape: the C04 envelope in the result
/// itself has to be complete.
fn foreign_namespace_recall_tool(name: &str) -> Option<RecallTool> {
    let rest = name.strip_prefix("mcp__")?;
    let (server, last) = rest.rsplit_once("__")?;
    if server.is_empty() || server == "cass_mcp" {
        return None;
    }
    bare_recall_tool(last)
}

/// True when the body is exactly one complete C04 envelope for `tool`.
fn declares_c04(body: &str, tool: RecallTool) -> bool {
    decode(body, tool).is_ok()
}

/// The text a result carries: a plain string as-is, otherwise its text
/// blocks in order. Only the C04 envelope check reads this.
fn result_body_text(value: &Value) -> String {
    match value.pointer("/message/content") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Whether a result that lost its `toolName` still points at exactly one
/// earlier CASS call. Only a missing result name may use a bare or foreign
/// call with the corresponding complete C04 envelope. This is candidate
/// evidence only; the binding itself still requires the result's own
/// non-empty matching name.
fn unique_prior_cass_call(
    tool_call_id: Option<&str>,
    result_idx: usize,
    calls_by_id: &HashMap<String, Vec<CallSite>>,
    body: &str,
    result_name_missing: bool,
) -> bool {
    let Some(calls) = tool_call_id.and_then(|id| calls_by_id.get(id)) else {
        return false;
    };
    let [call] = calls.as_slice() else {
        return false;
    };
    if call.call_idx >= result_idx {
        return false;
    }
    strong_recall_tool(&call.tool_name).is_some()
        || (result_name_missing
            && bare_recall_tool(&call.tool_name)
                .or_else(|| foreign_namespace_recall_tool(&call.tool_name))
                .is_some_and(|tool| declares_c04(body, tool)))
}

/// Every result record of the captured blob that is an identifiable CASS
/// candidate, counted over the valid native records themselves. Used only
/// when the canonical projection does not align one-to-one: the canonical
/// indices are then not trustworthy, so no exclusion is made and each
/// candidate is diagnosed as unpaired instead.
///
/// The count uses the same candidate identification as the normal diagnosis.
/// The ticket-01 structural hint is not enough here: it misses a damaged bare
/// envelope, a shell result that carries a complete envelope, and a result
/// whose own name is wrong but whose id names one earlier strong CASS call.
fn alignment_failure_candidates(blob_path: &Path) -> u64 {
    let raw_messages = projected_raw_messages(blob_path);
    let calls_by_id = collect_call_sites(
        raw_messages
            .iter()
            .enumerate()
            .map(|(idx, raw)| (idx, &raw.value)),
    );
    let declarations = read_declarations(
        raw_messages
            .iter()
            .enumerate()
            .map(|(idx, raw)| (idx, &raw.value)),
    );
    raw_messages
        .iter()
        .enumerate()
        .filter(|(idx, raw)| {
            raw_role(&raw.value) == Some("toolResult")
                && identify_candidate(
                    &raw.value,
                    *idx,
                    &result_body_text(&raw.value),
                    &calls_by_id,
                    &declarations,
                )
                .is_some()
        })
        .count() as u64
}

/// Why one Pi result is an observable CASS candidate. It is decided from the
/// native record and its call evidence alone, before any shape or binding
/// rejection, so a candidate is never dropped silently because its own
/// identity fields are unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiCandidateKind {
    /// One of the four strong full names.
    Strong(RecallTool),
    /// A bare CASS name with an envelope (complete or damaged) in its body.
    Bare(RecallTool),
    /// Another MCP namespace with the same suffix and a complete envelope.
    Foreign(RecallTool),
    /// A shell call whose own captured command or body identifies CASS.
    Shell,
    /// A read of a prior CASS result's declared full-output path, carrying a
    /// complete recall envelope.
    Read,
    /// The result's own name proves nothing, but its id names exactly one
    /// earlier strong CASS call, or a missing name has the envelope-backed
    /// bare/foreign candidate proof.
    IdOnly,
}

/// The candidate kind of one native result record, or `None` when the record
/// is not an observable CASS candidate at all.
///
/// `declarations` are the earlier native records that declared a CASS
/// result's full output path. A `read` is not an identity by itself: it is a
/// candidate only when it is bound to a read call whose path one of those
/// records declared (see [`read_is_companion_result`]).
fn identify_candidate(
    raw: &Value,
    result_idx: usize,
    body: &str,
    calls_by_id: &HashMap<String, Vec<CallSite>>,
    declarations: &[ReadDeclaration],
) -> Option<PiCandidateKind> {
    let named = raw
        .pointer("/message/toolName")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty());
    let id_only = || {
        unique_prior_cass_call(
            result_tool_call_id(raw),
            result_idx,
            calls_by_id,
            body,
            named.is_none(),
        )
        .then_some(PiCandidateKind::IdOnly)
    };
    match named {
        Some(name) => {
            if let Some(tool) = strong_recall_tool(name) {
                return Some(PiCandidateKind::Strong(tool));
            }
            if name == "bash" || name == "codemode" {
                let declares = RECALL_TOOLS.iter().any(|tool| declares_c04(body, *tool));
                let shell_arguments = name == "bash"
                    && raw_binding_call(raw, result_idx, calls_by_id)
                        .and_then(|call| call.arguments.as_ref())
                        .and_then(|args| args.get("command"))
                        .and_then(Value::as_str)
                        .is_some_and(|command| !matches!(parse_cli(command), Ok(None)));
                return if declares || shell_arguments {
                    Some(PiCandidateKind::Shell)
                } else {
                    id_only()
                };
            }
            if name == "read" {
                return if read_is_companion_result(raw, result_idx, body, calls_by_id, declarations)
                {
                    Some(PiCandidateKind::Read)
                } else {
                    id_only()
                };
            }
            if let Some(tool) = bare_recall_tool(name) {
                return if declares_c04(body, tool) || looks_like_recall_wrapper(body) {
                    Some(PiCandidateKind::Bare(tool))
                } else {
                    id_only()
                };
            }
            if let Some(tool) = foreign_namespace_recall_tool(name) {
                return if declares_c04(body, tool) {
                    Some(PiCandidateKind::Foreign(tool))
                } else {
                    id_only()
                };
            }
            id_only()
        }
        None => id_only(),
    }
}

/// The result's own non-empty tool-call id, if it has one.
fn result_tool_call_id(raw: &Value) -> Option<&str> {
    raw.pointer("/message/toolCallId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
}

/// The one earlier call that this record names by id and exact tool name.
/// This is the same rule the canonical binding uses (no Pi R4 fallback); it
/// is applied to native records so the alignment-failure count can read call
/// arguments without canonical indices.
fn raw_binding_call<'a>(
    raw: &Value,
    result_idx: usize,
    calls_by_id: &'a HashMap<String, Vec<CallSite>>,
) -> Option<&'a CallSite> {
    let name = raw
        .pointer("/message/toolName")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())?;
    let [call] = calls_by_id.get(result_tool_call_id(raw)?)?.as_slice() else {
        return None;
    };
    (call.call_idx < result_idx && call.tool_name == name).then_some(call)
}

/// One earlier native record that declares where a CASS result's full output
/// was written. Only a real `toolResult` record with one of the four strong
/// names can declare a path; a user, assistant or unknown-tool record with the
/// same metadata fields is not a result and declares nothing.
struct ReadDeclaration {
    index: usize,
    path: String,
}

/// Every earlier native record that declares a CASS `details.fullOutputPath`.
fn read_declarations<'a>(
    records: impl Iterator<Item = (usize, &'a Value)>,
) -> Vec<ReadDeclaration> {
    records
        .filter_map(|(index, record)| {
            if raw_role(record) != Some("toolResult") {
                return None;
            }
            let name = record
                .pointer("/message/toolName")
                .and_then(Value::as_str)?;
            if strong_recall_tool(name).is_none() {
                return None;
            }
            let path = record
                .pointer("/message/details/fullOutputPath")
                .and_then(Value::as_str)
                .filter(|path| !path.is_empty())?;
            Some(ReadDeclaration {
                index,
                path: path.to_string(),
            })
        })
        .collect()
}

/// Whether a native `read` result is the companion of a prior CASS result.
///
/// All of these facts must hold, and nothing is read from disk:
///
/// * the result binds by its own non-empty id to exactly one earlier `read`
///   call with the exact name (the same rule as every other Pi binding, with
///   no R4 fallback);
/// * that call's `arguments.path` is non-empty and equals, byte for byte, a
///   path declared by an earlier native `toolResult` with a strong name;
/// * the read body carries a complete C04 envelope.
fn read_is_companion_result(
    raw: &Value,
    result_idx: usize,
    body: &str,
    calls_by_id: &HashMap<String, Vec<CallSite>>,
    declarations: &[ReadDeclaration],
) -> bool {
    let Some(call) = raw_binding_call(raw, result_idx, calls_by_id) else {
        return false;
    };
    if call.tool_name != "read" {
        return false;
    }
    let Some(path) = call
        .arguments
        .as_ref()
        .and_then(|args| args.get("path"))
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
    else {
        return false;
    };
    declarations
        .iter()
        .any(|declaration| declaration.index < result_idx && declaration.path == path)
        && RECALL_TOOLS.iter().any(|tool| declares_c04(body, *tool))
}

// ============================================================================
// Ticket 02 (`cass-alien-fresh-ingest`): the Pi full-cleanup consumer.
//
// The judgment table is fixed by `contracts/t02-task.md`:
//
// * the four strong Pi identities are excluded whatever the output is;
// * a bare or foreign-namespaced name is a candidate only through the
//   result's own complete C04 envelope;
// * a result with no usable binding is preserved and counted, never
//   re-paired through the legacy R4 fallback;
// * a mixed body, or an unproven copy of the body elsewhere in the same
//   record, is preserved and counted;
// * a shell call or a read of a declared full-output path is diagnosed, not
//   excluded, and nothing is executed or read from disk;
// * an alignment failure excludes nothing and counts each candidate.
// ============================================================================

/// The four recall tools, in a fixed order, for "any tool" body checks only.
const RECALL_TOOLS: [RecallTool; 4] = [
    RecallTool::Search,
    RecallTool::Expand,
    RecallTool::Sessions,
    RecallTool::Timeline,
];

/// The result of one Pi cleanup pass.
#[derive(Debug, Clone)]
pub(crate) struct PiCleanupOutcome {
    /// One marker slot per canonical message.
    pub(crate) excluded: Vec<Option<ExcludedMarker>>,
    /// Preserved candidates counted by frozen reason string.
    pub(crate) uncovered_by_reason: BTreeMap<String, u64>,
    /// True when the canonical messages did not match the projected native
    /// records one-to-one. The caller records its own align-failure counters
    /// from this flag; the local reasons above already hold the diagnosis.
    pub(crate) alignment_failed: bool,
    /// Canonical event count, for the caller's align-failure detail.
    pub(crate) event_count: usize,
}

/// Judge and clear every proven Pi recall result in `conv`.
///
/// `blob_path` is the materialized capture blob and `blob_relative_path` is
/// the mirror-relative path stamped into each marker. The live
/// `conversation.source_path` is never read.
pub(crate) fn cleanup_pi_conversation(
    blob_path: &Path,
    conv: &mut NormalizedConversation,
    blob_relative_path: &str,
    redaction_enabled: bool,
) -> PiCleanupOutcome {
    let facts = PiFacts::build(blob_path, conv);
    let mut uncovered_by_reason: BTreeMap<String, u64> = BTreeMap::new();

    if !facts.alignment_ok {
        for _ in 0..alignment_failure_candidates(blob_path) {
            bump(&mut uncovered_by_reason, UncoveredReason::UnpairedResult);
        }
        return PiCleanupOutcome {
            excluded: vec![None; conv.messages.len()],
            uncovered_by_reason,
            alignment_failed: true,
            event_count: facts.events.len(),
        };
    }

    let field_map = field_map_for(&conv.agent_slug);
    let mut redactor = MemoizingRedactor::new();
    let mut excluded: Vec<Option<ExcludedMarker>> = vec![None; conv.messages.len()];
    // Every call site of the canonical messages, keyed by call id. The
    // candidate identification needs it to recognize a result whose own name
    // proves nothing but whose id names one earlier strong CASS call.
    let calls_by_id = collect_call_sites(
        conv.messages
            .iter()
            .enumerate()
            .map(|(idx, message)| (idx, &message.extra)),
    );
    // The earlier native records that declared a CASS full output path. A
    // read is a candidate only against one of these; the read output alone is
    // never evidence that the file belongs to CASS.
    let declarations = read_declarations(
        conv.messages
            .iter()
            .enumerate()
            .map(|(idx, message)| (idx, &message.extra)),
    );

    for idx in 0..conv.messages.len() {
        let Some(shape) = facts.result_body_shapes.get(&idx).copied() else {
            continue;
        };
        let body = conv.messages[idx].content.clone();
        let binding = facts.bindings.get(&idx);

        let outcome = judge_pi_result(
            &facts,
            &conv.messages[idx],
            idx,
            shape,
            binding,
            &body,
            &calls_by_id,
            &declarations,
        );
        match outcome {
            Outcome::Exclude(judged) => {
                let marker = apply_with_redaction(
                    &mut conv.messages[idx],
                    &judged,
                    &mut redactor,
                    blob_relative_path,
                    idx as u32,
                    field_map,
                    redaction_enabled,
                );
                clear_pi_result_body(&mut conv.messages[idx].extra, shape, &marker);
                excluded[idx] = Some(marker);
            }
            Outcome::Preserve(Some(reason)) => bump(&mut uncovered_by_reason, reason),
            Outcome::Preserve(None) => {}
        }
    }

    PiCleanupOutcome {
        excluded,
        uncovered_by_reason,
        alignment_failed: false,
        event_count: facts.events.len(),
    }
}

/// The judgment for one Pi result record.
///
/// The order is fixed: first decide whether the native result is an
/// identifiable CASS candidate, then reject any candidate whose body shape or
/// binding is unsafe, and only then apply the identity branch. A candidate
/// with a wrong name or a missing id is counted, never dropped silently; a
/// record with no candidate evidence at all stays untouched and unreported.
fn judge_pi_result(
    facts: &PiFacts,
    message: &NormalizedMessage,
    idx: usize,
    shape: PiResultBodyShape,
    binding: Option<&PiBinding>,
    body: &str,
    calls_by_id: &HashMap<String, Vec<CallSite>>,
    declarations: &[ReadDeclaration],
) -> Outcome {
    let Some(kind) = identify_candidate(&message.extra, idx, body, calls_by_id, declarations)
    else {
        return Outcome::Preserve(None);
    };

    // Candidate-only: an unsafe body shape or a missing/ambiguous binding is
    // diagnosed before any identity or format branch.
    let Some(binding) = binding else {
        return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
    };
    if shape == PiResultBodyShape::Mixed {
        return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
    }

    match kind {
        PiCandidateKind::Strong(tool) => {
            // A strong identity is proven by its exact full name. An
            // unproven copy of the body elsewhere in the record is preserved
            // and counted -- never excluded.
            if has_unproven_body_copy(&message.extra, body, tool) {
                return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
            }
            shared_pi_outcome(
                facts,
                message,
                idx,
                binding,
                DirectToolCategory::Strong(tool),
            )
        }
        PiCandidateKind::Bare(tool) => {
            // A complete envelope is the bare identity's proof; a copy of it
            // elsewhere is still unproven. A bound damaged envelope keeps the
            // bounded invalid-format diagnosis from the shared core.
            if declares_c04(body, tool) && has_unproven_body_copy(&message.extra, body, tool) {
                return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
            }
            shared_pi_outcome(facts, message, idx, binding, DirectToolCategory::Bare(tool))
        }
        PiCandidateKind::Foreign(_) => {
            // Another server's same-suffixed name is never a CASS identity.
            // A bound result carrying the complete envelope is ambiguous
            // enough to report.
            Outcome::Preserve(Some(UncoveredReason::AmbiguousToolIdentity))
        }
        PiCandidateKind::Shell => {
            // A shell call is never excluded and never executed.
            Outcome::Preserve(Some(UncoveredReason::UnsupportedShell))
        }
        PiCandidateKind::Read => {
            // Eligibility is already proven: a bound read of a prior CASS
            // result's declared full output carrying a complete envelope. The
            // attribution is ambiguous, so the row is preserved and counted.
            // Nothing is read from disk and no response is fabricated.
            Outcome::Preserve(Some(UncoveredReason::AmbiguousToolIdentity))
        }
        PiCandidateKind::IdOnly => {
            // The result's id names one earlier strong CASS call, but its own
            // name does not prove the identity, so it cannot bind.
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult))
        }
    }
}

/// Run the shared direct-tool core for a proven Pi result.
///
/// The shared core expects a `ToolResult` block carrying the real binding id;
/// ticket 01's raw events mark a Pi result's text blocks as `Text`, so the
/// judgment copy is adjusted here. The persisted row keeps its own `tool`
/// role: the temporary message is a copy used only for judgment.
fn shared_pi_outcome(
    facts: &PiFacts,
    message: &NormalizedMessage,
    idx: usize,
    binding: &PiBinding,
    category: DirectToolCategory,
) -> Outcome {
    let call = PairedTool {
        tool_call_id: Some(binding.tool_call_id.clone()),
        tool_name: binding.tool_name.clone(),
        args: binding.arguments.clone(),
    };
    let judgment_event = pi_judgment_event(&facts.events[idx], &binding.tool_call_id);
    let mut judgment_message = message.clone();
    judgment_message.role = "tool_result".to_string();
    judge_direct_tool_result(&judgment_message, &judgment_event, &call, category)
}

/// The judgment view of one Pi result event: every text block becomes the
/// bound result block. Nothing else changes, so a target-block list is
/// exactly the body's original block indices.
fn pi_judgment_event(event: &RawEvent, binding_id: &str) -> RawEvent {
    let mut judged = event.clone();
    for block in &mut judged.blocks {
        if block.kind == BlockKind::Text {
            block.kind = BlockKind::ToolResult;
            block.tool_use_id = Some(binding_id.to_string());
        }
    }
    judged
}

/// True when the same record carries a copy of the result body outside the
/// proven body leaf. The body's attribution is proven only for the content
/// slot: for a plain string that whole value, for a block array the `text`
/// field of each text block. Every other string in the record is checked,
/// including a text block's other fields, a non-text block's metadata, the
/// message's other fields and the record's top-level fields.
///
/// A complete C04 envelope is recognized through the shared codec: a copy
/// must decode for the same tool to the same value. Surrounding whitespace
/// therefore does not hide a copy. If the body cannot be decoded, a complete
/// envelope for the same tool elsewhere makes attribution unproven instead.
/// Plain JSON and other non-envelope metadata do not acquire copy semantics.
fn has_unproven_body_copy(extra: &Value, body: &str, tool: RecallTool) -> bool {
    let reference = decode(body, tool).ok();
    let reference = reference.as_ref();
    match extra {
        Value::Object(record) => record.iter().any(|(key, value)| {
            if key == "message" {
                copy_in_message(value, body, reference, tool)
            } else {
                value_has_body_copy(value, body, reference, tool)
            }
        }),
        other => value_has_body_copy(other, body, reference, tool),
    }
}

/// Walk one message object, skipping only the proven body leaves under
/// `content`.
fn copy_in_message(
    message: &Value,
    body: &str,
    reference: Option<&Value>,
    tool: RecallTool,
) -> bool {
    match message {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            if key == "content" {
                copy_in_content(value, body, reference, tool)
            } else {
                value_has_body_copy(value, body, reference, tool)
            }
        }),
        other => value_has_body_copy(other, body, reference, tool),
    }
}

/// Walk the content slot, skipping only the proven body leaves.
fn copy_in_content(
    content: &Value,
    body: &str,
    reference: Option<&Value>,
    tool: RecallTool,
) -> bool {
    match content {
        // A plain string body is the whole proven leaf itself.
        Value::String(_) => false,
        Value::Array(blocks) => blocks.iter().any(|block| match block {
            Value::Object(fields) => {
                let is_text_block = block.get("type").and_then(Value::as_str) == Some("text");
                fields.iter().any(|(key, value)| {
                    let proven_leaf = is_text_block && key == "text";
                    !proven_leaf && value_has_body_copy(value, body, reference, tool)
                })
            }
            other => value_has_body_copy(other, body, reference, tool),
        }),
        other => value_has_body_copy(other, body, reference, tool),
    }
}

fn value_has_body_copy(
    value: &Value,
    body: &str,
    reference: Option<&Value>,
    tool: RecallTool,
) -> bool {
    match value {
        Value::String(text) => is_body_copy(text, body, reference, tool),
        Value::Array(items) => items
            .iter()
            .any(|item| value_has_body_copy(item, body, reference, tool)),
        Value::Object(fields) => fields
            .values()
            .any(|item| value_has_body_copy(item, body, reference, tool)),
        _ => false,
    }
}

fn is_body_copy(text: &str, body: &str, reference: Option<&Value>, tool: RecallTool) -> bool {
    if looks_like_recall_wrapper(body) && text == body {
        return true;
    }
    match reference {
        Some(expected) => decode(text, tool).ok().as_ref() == Some(expected),
        None => decode(text, tool).is_ok(),
    }
}

/// Replace the proven body with the shared redaction placeholder, keeping
/// every array index and every non-body field. A mixed body never reaches
/// here.
fn clear_pi_result_body(extra: &mut Value, shape: PiResultBodyShape, marker: &ExcludedMarker) {
    let placeholder = serde_json::json!({
        "redacted": true,
        "sha256": marker.sha256,
        "bytes": marker.bytes,
    });
    let Some(content) = extra.pointer_mut("/message/content") else {
        return;
    };
    match shape {
        PiResultBodyShape::String => *content = placeholder,
        PiResultBodyShape::TextBlocks => {
            let Some(blocks) = content.as_array_mut() else {
                return;
            };
            for block in blocks {
                if block.get("type").and_then(Value::as_str) == Some("text")
                    && let Some(block) = block.as_object_mut()
                {
                    block.insert("text".to_string(), placeholder.clone());
                }
            }
        }
        PiResultBodyShape::Mixed => {}
    }
}

fn bump(uncovered_by_reason: &mut BTreeMap<String, u64>, reason: UncoveredReason) {
    *uncovered_by_reason
        .entry(reason.as_str().to_string())
        .or_insert(0) += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::{Connector, ScanContext, ScanRoot};
    use crate::indexer::PiAgentConnector;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    struct Projected {
        conversation: NormalizedConversation,
        facts: PiFacts,
        _dir: TempDir,
    }

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alien_pi_facts")
    }

    fn case(id: &str) -> Value {
        let manifest = fs::read_to_string(fixture_dir().join("manifest.json")).unwrap();
        let manifest: Value = serde_json::from_str(&manifest).unwrap();
        manifest["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == id)
            .unwrap_or_else(|| panic!("manifest case {id} missing"))
            .clone()
    }

    /// Materialize one fixture under its own `.pi/agent/sessions` root and
    /// project it with the real pinned connector into an isolated root. No
    /// global HOME or environment is touched.
    fn project(id: &str) -> Projected {
        let case = case(id);
        let file_name = Path::new(case["file"].as_str().unwrap())
            .file_name()
            .unwrap()
            .to_owned();
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join(".pi/agent/sessions");
        fs::create_dir_all(&sessions).unwrap();
        let file = sessions.join(&file_name);
        fs::copy(fixture_dir().join(&file_name), &file).unwrap();

        let ctx = ScanContext::with_roots(
            dir.path().join("cass-data"),
            vec![ScanRoot::local(dir.path().to_path_buf())],
            None,
        );
        let mut conversations = PiAgentConnector::new().scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1, "{id}: one projected conversation");
        let conversation = conversations.remove(0);
        assert_eq!(conversation.agent_slug, "pi_agent", "{id}: connector slug");
        assert_eq!(
            conversation.source_path, file,
            "{id}: projection reads the materialized copy"
        );

        let facts = PiFacts::build(&file, &conversation);
        Projected {
            conversation,
            facts,
            _dir: dir,
        }
    }

    fn usize_at(value: &Value) -> usize {
        value.as_u64().unwrap() as usize
    }

    /// One derived variant of a frozen fixture: the parsed JSONL lines after
    /// `mutate`, plus the real pinned-connector projection of exactly those
    /// bytes. Nothing here writes back to `tests/fixtures`.
    struct Variant {
        lines: Vec<Value>,
        conversation: NormalizedConversation,
        facts: PiFacts,
        _dir: TempDir,
    }

    /// The C04 wrapper a Pi result would carry when the tool name alone is
    /// not a strong identity.
    const SEARCH_C04: &str =
        r#"<cass_recall version="1" tool="cass_search">{"hits":[]}</cass_recall>"#;

    fn fixture_lines(id: &str) -> Vec<Value> {
        let case = case(id);
        let file_name = Path::new(case["file"].as_str().unwrap())
            .file_name()
            .unwrap();
        fs::read_to_string(fixture_dir().join(file_name))
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn project_variant(id: &str, tag: &str, mutate: impl FnOnce(&mut Vec<Value>)) -> Variant {
        let mut lines = fixture_lines(id);
        mutate(&mut lines);

        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join(".pi/agent/sessions");
        fs::create_dir_all(&sessions).unwrap();
        let file = sessions.join(format!("2026-10-24T00-00-00_{tag}.jsonl"));
        let mut text = lines
            .iter()
            .map(|line| serde_json::to_string(line).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        text.push('\n');
        fs::write(&file, text).unwrap();

        let ctx = ScanContext::with_roots(
            dir.path().join("cass-data"),
            vec![ScanRoot::local(dir.path().to_path_buf())],
            None,
        );
        let mut conversations = PiAgentConnector::new().scan(&ctx).unwrap();
        assert_eq!(
            conversations.len(),
            1,
            "{tag}: one projected conversation from the derived blob"
        );
        let conversation = conversations.remove(0);
        assert_eq!(
            conversation.source_path, file,
            "{tag}: projection reads the derived copy"
        );
        let facts = PiFacts::build(&file, &conversation);
        Variant {
            lines,
            conversation,
            facts,
            _dir: dir,
        }
    }

    fn role_line(lines: &[Value], role: &str) -> usize {
        lines
            .iter()
            .position(|line| line.pointer("/message/role").and_then(Value::as_str) == Some(role))
            .unwrap_or_else(|| panic!("derived blob has no {role} message"))
    }

    fn set_call_name(lines: &mut [Value], assistant: usize, name: &str) {
        let block = lines[assistant]
            .pointer_mut("/message/content")
            .and_then(Value::as_array_mut)
            .and_then(|blocks| {
                blocks
                    .iter_mut()
                    .find(|block| block.get("type").and_then(Value::as_str) == Some("toolCall"))
            })
            .expect("assistant toolCall block");
        block["name"] = Value::String(name.to_string());
    }

    fn set_read_arguments(lines: &mut [Value], assistant: usize, path: &str) {
        let block = lines[assistant]
            .pointer_mut("/message/content")
            .and_then(Value::as_array_mut)
            .and_then(|blocks| {
                blocks
                    .iter_mut()
                    .find(|block| block.get("type").and_then(Value::as_str) == Some("toolCall"))
            })
            .expect("assistant toolCall block");
        block["arguments"] = serde_json::json!({ "path": path });
    }

    fn set_result_fields(lines: &mut [Value], result: usize, name: Option<&str>, body: Value) {
        let message = lines[result]["message"].as_object_mut().unwrap();
        match name {
            Some(name) => {
                message.insert("toolName".into(), Value::String(name.to_string()));
            }
            None => {
                message.remove("toolName");
            }
        }
        message.insert("content".into(), body);
    }

    fn text_block(text: &str) -> Value {
        serde_json::json!([{ "type": "text", "text": text }])
    }

    fn derived_extra_matches_blob(variant: &Variant) {
        assert_eq!(
            variant.conversation.messages.len(),
            variant.lines.len() - 1,
            "derived: one canonical message per blob message line after the session row"
        );
        for (idx, message) in variant.conversation.messages.iter().enumerate() {
            assert_eq!(
                message.extra,
                variant.lines[idx + 1],
                "derived: message {idx} raw extra"
            );
        }
    }

    fn assert_case(id: &str) {
        let case = case(id);
        let expected = &case["expected"];
        let projected = project(id);
        let facts = &projected.facts;

        // Message count and one event per canonical message.
        assert_eq!(
            projected.conversation.messages.len(),
            usize_at(&expected["message_count"]),
            "{id}: canonical message count"
        );
        assert_eq!(
            facts.events.len(),
            projected.conversation.messages.len(),
            "{id}: one event per canonical message"
        );

        // Event keys and their physical line numbers.
        let actual_keys: Vec<String> = facts
            .events
            .iter()
            .map(|event| event.event_key.clone())
            .collect();
        let expected_keys: Vec<String> = expected["event_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_string())
            .collect();
        assert_eq!(actual_keys, expected_keys, "{id}: event keys");
        let actual_lines: Vec<usize> = actual_keys
            .iter()
            .map(|key| key.strip_prefix("pi:line:").unwrap().parse().unwrap())
            .collect();
        let expected_lines: Vec<usize> = expected["physical_lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(usize_at)
            .collect();
        assert_eq!(actual_lines, expected_lines, "{id}: physical lines");

        assert_eq!(
            facts.alignment_ok,
            expected["alignment_ok"].as_bool().unwrap(),
            "{id}: alignment_ok"
        );

        // Bindings: exact set, and the fields ticket 02 consumes.
        let expected_bindings = expected["bindings"].as_array().unwrap();
        assert_eq!(
            facts.bindings.len(),
            expected_bindings.len(),
            "{id}: binding count"
        );
        for expected_binding in expected_bindings {
            let result_idx = usize_at(&expected_binding["result_idx"]);
            let binding = facts
                .bindings
                .get(&result_idx)
                .unwrap_or_else(|| panic!("{id}: no binding for result {result_idx}"));
            assert_eq!(binding.result_idx, result_idx, "{id}: binding result_idx");
            assert_eq!(
                binding.call_idx,
                usize_at(&expected_binding["call_idx"]),
                "{id}: binding call_idx"
            );
            assert_eq!(
                binding.call_block_idx as usize,
                usize_at(&expected_binding["call_block_idx"]),
                "{id}: binding call_block_idx"
            );
            assert_eq!(
                binding.tool_call_id,
                expected_binding["tool_call_id"].as_str().unwrap(),
                "{id}: binding tool_call_id"
            );

            // The result's own toolName must be the bound name; the captured
            // arguments must be the call block's own `arguments` value.
            let result_raw = &projected.conversation.messages[result_idx].extra;
            assert_eq!(
                Some(binding.tool_name.as_str()),
                result_raw
                    .pointer("/message/toolName")
                    .and_then(Value::as_str),
                "{id}: binding tool_name"
            );
            let call_raw = &projected.conversation.messages[binding.call_idx].extra;
            let call_arguments = call_raw
                .pointer("/message/content")
                .and_then(Value::as_array)
                .and_then(|blocks| blocks.get(binding.call_block_idx as usize))
                .and_then(|block| block.get("arguments").cloned());
            assert_eq!(binding.arguments, call_arguments, "{id}: binding arguments");
        }

        // Unpaired candidates: strong-identity results that got no binding.
        let actual_unpaired: Vec<usize> = facts
            .candidate_result_indices
            .iter()
            .copied()
            .filter(|idx| !facts.bindings.contains_key(idx))
            .collect();
        let expected_unpaired: Vec<usize> = expected["unpaired_result_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(usize_at)
            .collect();
        assert_eq!(
            actual_unpaired, expected_unpaired,
            "{id}: unpaired result indices"
        );

        // Result body shapes, as the frozen string vocabulary.
        let mut actual_shapes = serde_json::Map::new();
        for (idx, shape) in &facts.result_body_shapes {
            let name = match shape {
                PiResultBodyShape::String => "string",
                PiResultBodyShape::TextBlocks => "text_blocks",
                PiResultBodyShape::Mixed => "mixed",
            };
            actual_shapes.insert(idx.to_string(), Value::String(name.to_string()));
        }
        assert_eq!(
            Value::Object(actual_shapes),
            expected["result_body_shapes"],
            "{id}: result body shapes"
        );

        // Text block indexes derived from the events the 02 consumer reads.
        let mut actual_text_indices = serde_json::Map::new();
        for idx in facts.result_body_shapes.keys() {
            let indices: Vec<Value> = facts.events[*idx]
                .blocks
                .iter()
                .filter(|block| block.kind == BlockKind::Text)
                .map(|block| Value::from(block.index))
                .collect();
            if !indices.is_empty() {
                actual_text_indices.insert(idx.to_string(), Value::Array(indices));
            }
        }
        assert_eq!(
            Value::Object(actual_text_indices),
            expected["result_text_block_indices"],
            "{id}: result text block indices"
        );

        let any_mixed = facts
            .result_body_shapes
            .values()
            .any(|shape| *shape == PiResultBodyShape::Mixed);
        assert_eq!(
            any_mixed,
            expected["mixed_result"].as_bool().unwrap(),
            "{id}: mixed_result"
        );
    }

    #[test]
    fn alien_pi_facts_f01() {
        assert_case("F01");
    }

    #[test]
    fn alien_pi_facts_f02() {
        assert_case("F02");

        // R1-2 derived: the original strong call and the same ID, but the
        // result lost its own tool name. No binding may be invented, yet the
        // result stays an observable CASS candidate.
        let variant = project_variant("F02", "F02-noname", |lines| {
            let result = role_line(lines, "toolResult");
            let body = lines[result]["message"]["content"].clone();
            set_result_fields(lines, result, None, body);
        });
        assert!(
            !variant.facts.bindings.contains_key(&2),
            "derived noname: a missing result tool name must not bind"
        );
        assert!(
            variant.facts.candidate_result_indices.contains(&2),
            "derived noname: a unique prior CASS call keeps the result a candidate"
        );
        assert_eq!(
            variant.facts.result_body_shapes.get(&2),
            Some(&PiResultBodyShape::TextBlocks),
            "derived noname: body shape stays text_blocks"
        );
        derived_extra_matches_blob(&variant);
    }

    #[test]
    fn alien_pi_facts_f03() {
        assert_case("F03");
    }

    #[test]
    fn alien_pi_facts_f04() {
        assert_case("F04");
    }

    #[test]
    fn alien_pi_facts_f05() {
        assert_case("F05");
    }

    #[test]
    fn alien_pi_facts_f06() {
        assert_case("F06");
    }

    #[test]
    fn alien_pi_facts_f07() {
        assert_case("F07");
    }

    #[test]
    fn alien_pi_facts_f08() {
        assert_case("F08");
    }

    #[test]
    fn alien_pi_facts_f09() {
        assert_case("F09");
    }

    #[test]
    fn alien_pi_facts_f10() {
        assert_case("F10");
    }

    #[test]
    fn alien_pi_facts_f11() {
        assert_case("F11");

        // R1-1 derived: a whole-string result body still has one logical
        // block at index 0, and binding plus every raw message line survive.
        let variant = project_variant("F11", "F11-string", |lines| {
            let result = role_line(lines, "toolResult");
            let body = lines[result]["message"]["content"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n");
            set_result_fields(
                lines,
                result,
                Some("mcp__cass_mcp__cass_search"),
                Value::String(body),
            );
        });
        assert_eq!(
            variant.facts.result_body_shapes.get(&2),
            Some(&PiResultBodyShape::String),
            "derived string: shape is string"
        );
        let string_blocks = &variant.facts.events[2].blocks;
        assert_eq!(
            string_blocks.len(),
            1,
            "derived string: exactly one logical block"
        );
        assert_eq!(
            string_blocks[0].index, 0,
            "derived string: logical block index 0"
        );
        assert_eq!(
            string_blocks[0].kind,
            BlockKind::Text,
            "derived string: block is text"
        );
        let expected = &case("F11")["expected"]["bindings"][0];
        assert_eq!(
            variant.facts.bindings.get(&2),
            Some(&PiBinding {
                result_idx: 2,
                call_idx: usize_at(&expected["call_idx"]),
                call_block_idx: usize_at(&expected["call_block_idx"]) as u32,
                tool_call_id: expected["tool_call_id"].as_str().unwrap().to_string(),
                tool_name: "mcp__cass_mcp__cass_search".to_string(),
                arguments: Some(serde_json::json!({ "query": "synthetic alien" })),
            }),
            "derived string: binding unchanged"
        );
        derived_extra_matches_blob(&variant);

        // R1-2 derived: a bare name is not a strong identity; only the
        // result's own complete C04 envelope makes it an observable candidate.
        let bare = project_variant("F11", "F11-bare", |lines| {
            let assistant = role_line(lines, "assistant");
            let result = role_line(lines, "toolResult");
            set_call_name(lines, assistant, "cass_search");
            set_result_fields(lines, result, Some("cass_search"), text_block(SEARCH_C04));
        });
        assert!(
            bare.facts.candidate_result_indices.contains(&2),
            "derived bare: full C04 envelope makes the result a candidate"
        );
        assert!(
            !PI_STRONG_TOOL_NAMES.contains(&"cass_search"),
            "derived bare: the strong name table is unchanged"
        );
        derived_extra_matches_blob(&bare);

        // R1-2 derived: another MCP namespace with the same suffix and a full
        // C04 envelope is a candidate, still without joining the strong table.
        let foreign = project_variant("F11", "F11-foreign", |lines| {
            let assistant = role_line(lines, "assistant");
            let result = role_line(lines, "toolResult");
            set_call_name(lines, assistant, "mcp__other__cass_search");
            set_result_fields(
                lines,
                result,
                Some("mcp__other__cass_search"),
                text_block(SEARCH_C04),
            );
        });
        assert!(
            foreign.facts.candidate_result_indices.contains(&2),
            "derived foreign: full C04 envelope makes the result a candidate"
        );
        assert!(
            !PI_STRONG_TOOL_NAMES.contains(&"mcp__other__cass_search"),
            "derived foreign: the strong name table is unchanged"
        );
        derived_extra_matches_blob(&foreign);

        // R1-2 derived: an unrelated tool is never a CASS candidate, even when
        // its body carries a complete C04 envelope; its text stays untouched.
        let ordinary = project_variant("F11", "F11-ordinary", |lines| {
            let assistant = role_line(lines, "assistant");
            let result = role_line(lines, "toolResult");
            set_call_name(lines, assistant, "ordinary_echo");
            set_result_fields(lines, result, Some("ordinary_echo"), text_block(SEARCH_C04));
        });
        assert!(
            !ordinary.facts.candidate_result_indices.contains(&2),
            "derived ordinary: an unrelated tool name is not a CASS candidate"
        );
        let result_line = role_line(&ordinary.lines, "toolResult");
        assert_eq!(
            ordinary.conversation.messages[2].extra, ordinary.lines[result_line],
            "derived ordinary: raw message line and its C04 body preserved"
        );
        assert_eq!(
            ordinary.facts.events[2]
                .blocks
                .iter()
                .filter(|block| block.kind == BlockKind::Text)
                .map(|block| block.index)
                .collect::<Vec<_>>(),
            vec![0],
            "derived ordinary: body text preserved at block 0"
        );
    }

    #[test]
    fn alien_pi_facts_f12() {
        assert_case("F12");
    }

    /// One derived P01 blob projected by the real pinned connector in its own
    /// root, with the blob path kept alive for the cleanup pass.
    struct FullVariant {
        blob: PathBuf,
        conversation: NormalizedConversation,
        _dir: TempDir,
    }

    fn full_fixture_lines(id: &str) -> Vec<Value> {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "tests/fixtures/alien_pi_full/2026-10-24T00-00-00_{id}.jsonl"
        ));
        fs::read_to_string(fixture)
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn p01_lines() -> Vec<Value> {
        full_fixture_lines("P01")
    }

    fn p17_lines() -> Vec<Value> {
        full_fixture_lines("P17")
    }

    fn project_full(tag: &str, lines: &[Value]) -> FullVariant {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join(".pi/agent/sessions");
        fs::create_dir_all(&sessions).unwrap();
        let blob = sessions.join(format!("2026-10-24T00-00-00_P01_{tag}.jsonl"));
        let mut text = lines
            .iter()
            .map(|line| serde_json::to_string(line).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        text.push('\n');
        fs::write(&blob, text).unwrap();

        let ctx = ScanContext::with_roots(
            dir.path().join("cass-data"),
            vec![ScanRoot::local(dir.path().to_path_buf())],
            None,
        );
        let mut conversations = PiAgentConnector::new().scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1, "{tag}: one projected conversation");
        let conversation = conversations.remove(0);
        assert_eq!(conversation.agent_slug, "pi_agent", "{tag}: connector slug");
        assert_eq!(
            conversation.source_path, blob,
            "{tag}: projection reads the derived copy"
        );
        FullVariant {
            blob,
            conversation,
            _dir: dir,
        }
    }

    /// Derive the canonical result extra so it no longer equals any blob
    /// line: the result itself leaves the one-to-one mapping while the blob
    /// keeps its valid native record.
    fn unmapped_result(variant: &mut FullVariant) {
        unmap_message(variant, 2);
    }

    /// Derive one canonical message's extra so it no longer equals any blob
    /// line while the blob keeps its valid native record.
    fn unmap_message(variant: &mut FullVariant, idx: usize) {
        variant.conversation.messages[idx].extra["message"]["content"] =
            Value::String("derived mismatch".to_string());
    }

    fn assert_one_unpaired_alignment(variant: &mut FullVariant, label: &str) {
        assert_alignment_unpaired_at(variant, label, 2, 1);
    }

    /// One alignment-failure check: the canonical message at `unmapped_idx`
    /// left the mapping, the whole session stays unchanged, and the raw
    /// candidates are counted exactly `expected_unpaired` times.
    fn assert_alignment_unpaired_at(
        variant: &mut FullVariant,
        label: &str,
        unmapped_idx: usize,
        expected_unpaired: u64,
    ) {
        let facts = PiFacts::build(&variant.blob, &variant.conversation);
        let messages = variant.conversation.messages.len();
        assert!(!facts.alignment_ok, "{label}: alignment must fail");
        assert_eq!(
            facts.events[unmapped_idx].event_key, "",
            "{label}: the unmapped record is outside the canonical mapping"
        );
        let before = serde_json::to_value(&variant.conversation.messages).unwrap();

        let outcome = cleanup_pi_conversation(
            &variant.blob,
            &mut variant.conversation,
            "derived/full.jsonl",
            false,
        );

        assert!(outcome.alignment_failed, "{label}: alignment failure");
        assert_eq!(outcome.event_count, messages, "{label}: event count");
        assert_eq!(
            outcome.excluded,
            vec![None; messages],
            "{label}: an alignment failure excludes nothing"
        );
        let expected = if expected_unpaired == 0 {
            BTreeMap::new()
        } else {
            BTreeMap::from([("unpaired_result".to_string(), expected_unpaired)])
        };
        assert_eq!(
            outcome.uncovered_by_reason, expected,
            "{label}: raw candidates are counted once each"
        );
        assert_eq!(
            serde_json::to_value(&variant.conversation.messages).unwrap(),
            before,
            "{label}: an alignment failure mutates no canonical message"
        );
    }

    /// Ticket 02: an alignment failure cannot be produced through the real
    /// lossless CLI (the connector emits every native message record, and the
    /// canonical extras are that record). This internal test therefore takes
    /// real pinned projections of the frozen P01 fixture and derives canonical
    /// extras that no longer equal their blob lines.
    ///
    /// Two facts are asserted for every sub-case: the strong CASS result is
    /// outside the canonical mapping, and cleanup still counts the valid raw
    /// candidate once. The candidate must be found from the native record, not
    /// from the structural hint alone.
    #[test]
    fn alien_pi_cleanup_alignment_failure() {
        let original = p01_lines();

        // Sub-case A: the mismatch is in the user record, so the strong CASS
        // result keeps its canonical slot but the session no longer aligns.
        // The raw result is still counted exactly once.
        let mut variant = project_full("align-user-mismatch", &original);
        let clean = PiFacts::build(&variant.blob, &variant.conversation);
        assert!(clean.alignment_ok, "A: P01 projection aligns one-to-one");
        assert_eq!(
            clean.candidate_result_indices,
            BTreeSet::from([2]),
            "A: P01 holds exactly one strong CASS candidate"
        );
        variant.conversation.messages[0].extra["message"]["content"] =
            Value::String("derived mismatch".to_string());
        let facts = PiFacts::build(&variant.blob, &variant.conversation);
        assert!(!facts.alignment_ok, "A: alignment must fail");
        assert_eq!(
            facts.events[2].event_key, "pi:line:4",
            "A: the strong result is still inside the mapping here"
        );
        assert_eq!(
            facts.candidate_result_indices,
            BTreeSet::from([2]),
            "A: the hint still sees the strong result"
        );
        let before = serde_json::to_value(&variant.conversation.messages).unwrap();
        let outcome = cleanup_pi_conversation(
            &variant.blob,
            &mut variant.conversation,
            "derived/P01.jsonl",
            false,
        );
        assert!(outcome.alignment_failed, "A: alignment failure");
        assert_eq!(outcome.event_count, 4, "A: event count");
        assert_eq!(
            outcome.excluded,
            vec![None; 4],
            "A: an alignment failure excludes nothing"
        );
        assert_eq!(
            outcome.uncovered_by_reason,
            BTreeMap::from([("unpaired_result".to_string(), 1)]),
            "A: the strong CASS result is counted as unpaired"
        );
        assert_eq!(
            serde_json::to_value(&variant.conversation.messages).unwrap(),
            before,
            "A: an alignment failure mutates no canonical message"
        );

        // Sub-case B: the result itself leaves the mapping, so neither the
        // candidate hint nor the event key can locate it. The raw record is
        // still one candidate.
        let mut variant = project_full("align-result-mismatch", &original);
        unmapped_result(&mut variant);
        let facts = PiFacts::build(&variant.blob, &variant.conversation);
        assert!(
            facts.candidate_result_indices.is_empty(),
            "B: the hint sees no candidate once the result is unmapped"
        );
        assert_one_unpaired_alignment(&mut variant, "B strong result outside the mapping");

        // Sub-case C: a bare candidate whose body is a damaged envelope plus
        // an image. The result is outside the mapping; the raw candidate must
        // still be counted even though the hint requires a complete envelope.
        let mut bare_lines = original.clone();
        let assistant = role_line(&bare_lines, "assistant");
        let result = role_line(&bare_lines, "toolResult");
        set_call_name(&mut bare_lines, assistant, "cass_search");
        set_result_fields(
            &mut bare_lines,
            result,
            Some("cass_search"),
            serde_json::json!([
                {
                    "type": "text",
                    "text": "<cass_recall version=\"1\" tool=\"cass_search\">{broken</cass_recall>",
                },
                { "type": "image", "data": "synthetic" },
            ]),
        );
        let mut variant = project_full("align-bare-mixed", &bare_lines);
        unmapped_result(&mut variant);
        assert_one_unpaired_alignment(&mut variant, "C bare damaged envelope outside the mapping");

        // Sub-case D: a bash candidate whose body carries the complete C04
        // envelope but whose result lost its id.
        let mut bash_lines = original.clone();
        let assistant = role_line(&bash_lines, "assistant");
        let result = role_line(&bash_lines, "toolResult");
        let body = bash_lines[result]["message"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        set_call_name(&mut bash_lines, assistant, "bash");
        bash_lines[assistant]["message"]["content"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|block| block["type"].as_str() == Some("toolCall"))
            .unwrap()["arguments"] =
            serde_json::json!({ "command": "cass search synthetic alien" });
        set_result_fields(&mut bash_lines, result, Some("bash"), text_block(&body));
        bash_lines[result]["message"]
            .as_object_mut()
            .unwrap()
            .remove("toolCallId");
        let mut variant = project_full("align-bash-envelope", &bash_lines);
        unmapped_result(&mut variant);
        assert_one_unpaired_alignment(&mut variant, "D bash envelope outside the mapping");

        // Sub-case E: the result's own name is wrong but its id names the one
        // earlier strong CASS call. The candidate must be recognized by that
        // call evidence, not dropped because the name is non-empty yet wrong.
        let mut wrong_lines = original.clone();
        let result = role_line(&wrong_lines, "toolResult");
        wrong_lines[result]["message"]["toolName"] = Value::String("ordinary_echo".to_string());
        let mut variant = project_full("align-wrong-name", &wrong_lines);
        unmapped_result(&mut variant);
        assert_one_unpaired_alignment(&mut variant, "E wrong result name outside the mapping");

        // Sub-case F: an ordinary read of a path no CASS result declared. Its
        // body is the complete envelope, yet the read is not a CASS companion
        // and the raw count is zero.
        let mut read_lines = original.clone();
        let assistant = role_line(&read_lines, "assistant");
        let result = role_line(&read_lines, "toolResult");
        let body = read_lines[result]["message"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        set_call_name(&mut read_lines, assistant, "read");
        set_read_arguments(&mut read_lines, assistant, "/synthetic/unrelated-note.txt");
        set_result_fields(&mut read_lines, result, Some("read"), text_block(&body));
        let mut variant = project_full("align-read-ordinary", &read_lines);
        unmapped_result(&mut variant);
        assert_alignment_unpaired_at(&mut variant, "F ordinary read outside the mapping", 2, 0);

        // Sub-case G: the same ordinary read, with the user record carrying
        // `toolName` and `details.fullOutputPath`. A user message is not a
        // result and cannot declare the read as a CASS companion.
        let mut fake_declaration = read_lines.clone();
        let user = role_line(&fake_declaration, "user");
        fake_declaration[user]["message"]["toolName"] =
            Value::String("mcp__cass_mcp__cass_search".to_string());
        fake_declaration[user]["message"]["details"] = serde_json::json!({
            "fullOutputPath": "/synthetic/unrelated-note.txt",
        });
        let mut variant = project_full("align-read-user-declaration", &fake_declaration);
        unmapped_result(&mut variant);
        assert_alignment_unpaired_at(
            &mut variant,
            "G user metadata declaration outside the mapping",
            2,
            0,
        );

        // Sub-case H: the real P17 chain. The clean session proves the read of
        // the declared path and diagnoses it as ambiguous. Once the read
        // result leaves the mapping, the raw count is the strong CASS result
        // plus that proven read, and the whole session stays unchanged.
        let original_p17 = p17_lines();
        let mut clean = project_full("read-p17-clean", &original_p17);
        let clean_facts = PiFacts::build(&clean.blob, &clean.conversation);
        assert!(clean_facts.alignment_ok, "H: P17 projection aligns");
        assert_eq!(
            clean_facts.candidate_result_indices,
            BTreeSet::from([2]),
            "H: the structural hint sees the strong CASS result"
        );
        let mut clean_conversation = clean.conversation;
        let clean_outcome = cleanup_pi_conversation(
            &clean.blob,
            &mut clean_conversation,
            "derived/full.jsonl",
            false,
        );
        assert_eq!(
            clean_outcome
                .excluded
                .iter()
                .filter(|marker| marker.is_some())
                .count(),
            1,
            "H: the strong CASS result is the excluded row"
        );
        assert_eq!(
            clean_outcome.uncovered_by_reason,
            BTreeMap::from([("ambiguous_tool_identity".to_string(), 1)]),
            "H: the read of the declared path is a proven companion"
        );

        let mut variant = project_full("read-p17-unmapped", &original_p17);
        unmap_message(&mut variant, 4);
        assert_alignment_unpaired_at(
            &mut variant,
            "H strong result and proven read outside the mapping",
            4,
            2,
        );
    }
}
