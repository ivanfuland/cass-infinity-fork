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
use crate::recall_output::{RecallTool, decode, decode_with_original_json};
use franken_agent_detection::LosslessSourceValue;

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
    /// Native message records projected from the captured blob, independent
    /// of the number of canonical message slots in `events`.
    pub(crate) raw_message_count: usize,
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
    /// The captured blob line of every matched message, keyed by canonical
    /// message index. The lossless copy proof reads the result line and the
    /// paired call line from here; the text is never written into a message's
    /// `extra` or the database.
    pub(crate) line_texts: BTreeMap<usize, String>,
}

/// One projected native `message` record from the captured blob.
struct RawMessage {
    line_no: usize,
    value: Value,
    /// The captured line exactly as it sits in the blob. The lossless copy
    /// proof reads number spellings and repeated member names from here; the
    /// parsed `value` cannot preserve them.
    text: String,
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

        let line_texts = matched
            .iter()
            .enumerate()
            .filter_map(|(idx, raw_idx)| {
                raw_idx.map(|raw_idx| (idx, raw_messages[raw_idx].text.clone()))
            })
            .collect();
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
            raw_message_count: raw_messages.len(),
            bindings: BTreeMap::new(),
            candidate_result_indices: BTreeSet::new(),
            alignment_ok,
            result_body_shapes: BTreeMap::new(),
            line_texts,
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
            projection_emits_message(&value).then(|| RawMessage {
                line_no: index + 1,
                value,
                text: line.to_string(),
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
    /// Actual projected native record count, for the caller's failure detail.
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
            event_count: facts.raw_message_count,
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

        let PiJudgment {
            outcome,
            copies,
            tool,
        } = judge_pi_result(
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
                let original = conv.messages[idx].clone();
                let marker = apply_with_redaction(
                    &mut conv.messages[idx],
                    &judged,
                    &mut redactor,
                    blob_relative_path,
                    idx as u32,
                    field_map,
                    redaction_enabled,
                );
                // Both the body and every proven copy land on one message
                // copy and one write. The write is taken only when nothing is
                // left to exclude and every changed leaf is owned by this
                // cleanup; otherwise the whole record is kept.
                let before = original.extra.clone();
                let mut cleaned = before.clone();
                clear_pi_result_body(&mut cleaned, shape, &marker);
                clear_pi_copies(&mut cleaned, &copies, &marker);
                let atomic = tool.is_some_and(|tool| {
                    pi_cleanup_is_atomic(&before, &cleaned, shape, &copies, &marker, &body, tool)
                });
                if atomic {
                    conv.messages[idx].extra = cleaned;
                    excluded[idx] = Some(marker);
                } else {
                    conv.messages[idx] = original;
                    bump(&mut uncovered_by_reason, UncoveredReason::UnpairedResult);
                }
            }
            Outcome::Preserve(Some(reason)) => bump(&mut uncovered_by_reason, reason),
            Outcome::Preserve(None) => {}
        }
    }

    PiCleanupOutcome {
        excluded,
        uncovered_by_reason,
        alignment_failed: false,
        event_count: facts.raw_message_count,
    }
}

/// The judgment for one Pi result record, plus the proven copy slots to clear
/// when the shared core excludes it. `tool` is set exactly when `outcome` is
/// `Exclude`, so the atomic write can re-check the cleaned extra.
struct PiJudgment {
    outcome: Outcome,
    copies: Vec<PiCopySlot>,
    tool: Option<RecallTool>,
}

impl PiJudgment {
    fn preserved(reason: Option<UncoveredReason>) -> Self {
        Self {
            outcome: Outcome::Preserve(reason),
            copies: Vec::new(),
            tool: None,
        }
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
) -> PiJudgment {
    let Some(kind) = identify_candidate(&message.extra, idx, body, calls_by_id, declarations)
    else {
        return PiJudgment::preserved(None);
    };

    // Candidate-only: an unsafe body shape or a missing/ambiguous binding is
    // diagnosed before any identity or format branch.
    let Some(binding) = binding else {
        return PiJudgment::preserved(Some(UncoveredReason::UnpairedResult));
    };
    if shape == PiResultBodyShape::Mixed {
        return PiJudgment::preserved(Some(UncoveredReason::UnpairedResult));
    }

    match kind {
        PiCandidateKind::Strong(tool) => judged_pi_outcome(
            facts,
            message,
            idx,
            binding,
            DirectToolCategory::Strong(tool),
            tool,
            body,
        ),
        PiCandidateKind::Bare(tool) => {
            // A complete envelope is the bare identity's proof. A bound
            // damaged envelope keeps the bounded invalid-format diagnosis
            // from the shared core.
            judged_pi_outcome(
                facts,
                message,
                idx,
                binding,
                DirectToolCategory::Bare(tool),
                tool,
                body,
            )
        }
        PiCandidateKind::Foreign(_) => {
            // Another server's same-suffixed name is never a CASS identity.
            // A bound result carrying the complete envelope is ambiguous
            // enough to report.
            PiJudgment::preserved(Some(UncoveredReason::AmbiguousToolIdentity))
        }
        PiCandidateKind::Shell => {
            // A shell call is never excluded and never executed.
            PiJudgment::preserved(Some(UncoveredReason::UnsupportedShell))
        }
        PiCandidateKind::Read => {
            // Eligibility is already proven: a bound read of a prior CASS
            // result's declared full output carrying a complete envelope. The
            // attribution is ambiguous, so the row is preserved and counted.
            // Nothing is read from disk and no response is fabricated.
            PiJudgment::preserved(Some(UncoveredReason::AmbiguousToolIdentity))
        }
        PiCandidateKind::IdOnly => {
            // The result's id names one earlier strong CASS call, but its own
            // name does not prove the identity, so it cannot bind.
            PiJudgment::preserved(Some(UncoveredReason::UnpairedResult))
        }
    }
}

/// Run the shared direct-tool core, then consume the copy proof only when the
/// core gives `Exclude`. An unproven or ambiguous copy turns that exclusion
/// into the existing whole-record preservation.
fn judged_pi_outcome(
    facts: &PiFacts,
    message: &NormalizedMessage,
    idx: usize,
    binding: &PiBinding,
    category: DirectToolCategory,
    tool: RecallTool,
    body: &str,
) -> PiJudgment {
    match shared_pi_outcome(facts, message, idx, binding, category) {
        Outcome::Preserve(reason) => PiJudgment::preserved(reason),
        Outcome::Exclude(judged) => {
            // The binding's own source must be unambiguous too. A repeated
            // member name in the paired call's captured line means the id,
            // name or arguments may not be the values the file declares, so a
            // valid result line never authorizes the new cleaning.
            let call_document = facts
                .line_texts
                .get(&binding.call_idx)
                .and_then(|line| LosslessSourceValue::parse(line.as_bytes()).ok());
            if !call_evidence_is_lossless(call_document.as_ref(), binding) {
                return PiJudgment::preserved(Some(UncoveredReason::UnpairedResult));
            }
            let Some(result_document) = facts
                .line_texts
                .get(&idx)
                .and_then(|line| LosslessSourceValue::parse(line.as_bytes()).ok())
            else {
                return PiJudgment::preserved(Some(UncoveredReason::UnpairedResult));
            };
            match pi_copy_cleanup_plan(&message.extra, body, tool, &result_document) {
                Some(copies) => PiJudgment {
                    outcome: Outcome::Exclude(judged),
                    copies,
                    tool: Some(tool),
                },
                None => PiJudgment::preserved(Some(UncoveredReason::UnpairedResult)),
            }
        }
    }
}

/// Whether the paired call's captured line is itself unambiguous.
///
/// The line must parse losslessly, so a repeated member name anywhere in it
/// (including the call block or its arguments) rejects the evidence, and the
/// recorded call block must still be at the recorded position with the same
/// type, id and name. A missing line is not evidence either.
fn call_evidence_is_lossless(document: Option<&LosslessSourceValue>, binding: &PiBinding) -> bool {
    let Some(document) = document else {
        return false;
    };
    let Some(LosslessSourceValue::Array(blocks)) = document
        .get("message")
        .and_then(|message| message.get("content"))
    else {
        return false;
    };
    let Some(LosslessSourceValue::Object(block)) = blocks.get(binding.call_block_idx as usize)
    else {
        return false;
    };
    let member = |name: &str| {
        block
            .iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| value.as_str())
    };
    member("type") == Some("toolCall")
        && member("id") == Some(binding.tool_call_id.as_str())
        && member("name") == Some(binding.tool_name.as_str())
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

/// One of the three fixed carriers under `/message/details` that R18 may
/// clean once its value is proven equal to the verified result. The position
/// alone never grants permission; the value proof must hold at the same time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiCopySlot {
    Raw,
    StructuredContent,
    Text,
}

impl PiCopySlot {
    const ALL: [Self; 3] = [Self::Raw, Self::StructuredContent, Self::Text];

    fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::StructuredContent => "structuredContent",
            Self::Text => "text",
        }
    }
}

/// The proof state of one permitted copy slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiCopyProof {
    /// The slot holds no value, so it neither leaks nor blocks the exclusion.
    Absent,
    /// The slot holds a copy proven equal to the verified result.
    Proven,
    /// The slot cannot be proven; the whole record is kept.
    Unproven,
}

/// True when the same record carries a copy of the result body outside the
/// proven body leaf and outside `proven_slots`. The body's attribution is
/// proven only for the content slot: for a plain string that whole value, for
/// a block array the `text` field of each text block. Every other string in
/// the record is checked, including a text block's other fields, a non-text
/// block's metadata, the message's other fields and the record's top-level
/// fields.
///
/// A complete C04 envelope is recognized through the shared codec: a copy
/// must decode for the same tool to the same value. Surrounding whitespace
/// therefore does not hide a copy. A byte-identical copy of the whole body is
/// a copy whether the body is a complete envelope or the older unwrapped JSON.
/// If the body cannot be decoded, a complete envelope for the same tool
/// elsewhere makes attribution unproven instead. Plain JSON and other
/// non-envelope metadata do not acquire copy semantics beyond that exact
/// equality.
fn has_unproven_body_copy(
    extra: &Value,
    body: &str,
    tool: RecallTool,
    proven_slots: &[PiCopySlot],
) -> bool {
    let reference = decode(body, tool).ok();
    let reference = reference.as_ref();
    match extra {
        Value::Object(record) => record.iter().any(|(key, value)| {
            if key == "message" {
                copy_in_message(value, body, reference, tool, proven_slots)
            } else {
                value_has_body_copy(value, body, reference, tool)
            }
        }),
        other => value_has_body_copy(other, body, reference, tool),
    }
}

/// Walk one message object, skipping only the proven body leaves under
/// `content` and the already proven copy slots under `details`.
fn copy_in_message(
    message: &Value,
    body: &str,
    reference: Option<&Value>,
    tool: RecallTool,
    proven_slots: &[PiCopySlot],
) -> bool {
    match message {
        Value::Object(fields) => fields.iter().any(|(key, value)| match key.as_str() {
            "content" => copy_in_content(value, body, reference, tool),
            "details" => copy_in_details(value, body, reference, tool, proven_slots),
            _ => value_has_body_copy(value, body, reference, tool),
        }),
        other => value_has_body_copy(other, body, reference, tool),
    }
}

/// Walk the `details` object while ignoring the proven slots. An unproven
/// slot is not skipped: its value still counts as a copy.
fn copy_in_details(
    details: &Value,
    body: &str,
    reference: Option<&Value>,
    tool: RecallTool,
    proven_slots: &[PiCopySlot],
) -> bool {
    match details {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            let proven = proven_slots.iter().any(|slot| slot.name() == key.as_str());
            !proven && value_has_body_copy(value, body, reference, tool)
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
    // A byte-identical copy of the whole body is a copy whether the body is a
    // complete C04 envelope or the older unwrapped JSON. Inside the three
    // permitted slots this equality is the A1 proof; anywhere else it can
    // only stop an exclusion.
    if text == body {
        return true;
    }
    match reference {
        Some(expected) => decode(text, tool).ok().as_ref() == Some(expected),
        None => decode(text, tool).is_ok(),
    }
}

/// Decide the copy cleanup of a result the shared core already decided to
/// exclude.
///
/// `None` means the whole record is kept: a permitted slot holds a value that
/// cannot be proven, or a copy of the body survives outside the proven slots.
/// `Some(slots)` lists the proven slots to replace; the body itself is always
/// cleared by the caller.
///
/// The proof is only ever consumed after the identity, binding and body rules
/// gave `Exclude`; it never grants an exclusion by itself.
fn pi_copy_cleanup_plan(
    extra: &Value,
    body: &str,
    tool: RecallTool,
    raw_document: &LosslessSourceValue,
) -> Option<Vec<PiCopySlot>> {
    // The verified result JSON text. A complete C04 envelope carries it inside
    // the root element; an older unwrapped body is that text itself. Nothing
    // here re-serializes a parsed value.
    let envelope = decode_with_original_json(body, tool).ok();
    let legacy_body = match &envelope {
        Some(_) => None,
        None => LosslessSourceValue::parse(body.as_bytes())
            .ok()
            .map(|_| body),
    };
    let reference_json = envelope
        .as_ref()
        .map(|(_, json)| json.as_str())
        .or(legacy_body);
    let reference =
        reference_json.and_then(|json| LosslessSourceValue::parse(json.as_bytes()).ok());

    let mut proven = Vec::new();
    for slot in PiCopySlot::ALL {
        let proof = prove_pi_copy_slot(
            extra,
            Some(raw_document),
            slot,
            reference.as_ref(),
            legacy_body,
        );
        match proof {
            PiCopyProof::Absent => {}
            PiCopyProof::Proven => proven.push(slot),
            PiCopyProof::Unproven => return None,
        }
    }

    if has_unproven_body_copy(extra, body, tool, &proven) {
        return None;
    }
    // A complete structured copy at any other position is still a copy of the
    // verified result. It grants no cleaning at a fourth position; it keeps the
    // whole record.
    if has_foreign_structured_copy(raw_document, reference.as_ref(), &proven) {
        return None;
    }
    Some(proven)
}

/// True when the captured record holds the complete verified JSON value as an
/// object outside the proven body leaf and the proven copy slots.
///
/// The comparison is the same fixed lossless equality, so a different value, a
/// shared fragment or an ordinary same-named field is not a copy. Only the
/// third copy carrier (the structured object) is looked for elsewhere; strings
/// outside the permitted slots are already covered by the body-copy walk.
fn has_foreign_structured_copy(
    document: &LosslessSourceValue,
    reference: Option<&LosslessSourceValue>,
    proven: &[PiCopySlot],
) -> bool {
    let Some(reference) = reference else {
        return false;
    };
    let mut stack: Vec<&LosslessSourceValue> = Vec::new();
    match document {
        LosslessSourceValue::Object(record) => {
            for (key, value) in record {
                if key == "message" {
                    if message_has_foreign_copy(value, reference, proven) {
                        return true;
                    }
                } else if is_structured_copy(value, reference) {
                    return true;
                } else {
                    stack.push(value);
                }
            }
        }
        other => stack.push(other),
    }
    stack_has_structured_copy(stack, reference)
}

/// The `message` level of [`has_foreign_structured_copy`]: the proven body
/// leaves under `content` and the proven slots under `details` are skipped,
/// every other value is a candidate.
fn message_has_foreign_copy(
    message: &LosslessSourceValue,
    reference: &LosslessSourceValue,
    proven: &[PiCopySlot],
) -> bool {
    let LosslessSourceValue::Object(fields) = message else {
        return is_structured_copy(message, reference);
    };
    let mut stack: Vec<&LosslessSourceValue> = Vec::new();
    for (key, value) in fields {
        match key.as_str() {
            "content" => push_content_children(value, &mut stack),
            "details" => match value {
                LosslessSourceValue::Object(details) => {
                    if is_structured_copy(value, reference) {
                        return true;
                    }
                    for (name, value) in details {
                        let is_proven = proven.iter().any(|slot| slot.name() == name.as_str());
                        if !is_proven {
                            stack.push(value);
                        }
                    }
                }
                other => stack.push(other),
            },
            _ => stack.push(value),
        }
    }
    stack_has_structured_copy(stack, reference)
}

/// The unskipped leaves of a `content` value: a plain string is the proven
/// body itself and yields nothing; a text block contributes everything except
/// its `text` member.
fn push_content_children<'a>(
    content: &'a LosslessSourceValue,
    stack: &mut Vec<&'a LosslessSourceValue>,
) {
    match content {
        LosslessSourceValue::Array(blocks) => {
            for block in blocks {
                match block {
                    LosslessSourceValue::Object(block_fields) => {
                        let is_text_block = block_fields
                            .iter()
                            .any(|(key, value)| key == "type" && value.as_str() == Some("text"));
                        for (key, value) in block_fields {
                            if !(is_text_block && key == "text") {
                                stack.push(value);
                            }
                        }
                    }
                    other => stack.push(other),
                }
            }
        }
        _ => {}
    }
}

fn stack_has_structured_copy(
    mut stack: Vec<&LosslessSourceValue>,
    reference: &LosslessSourceValue,
) -> bool {
    while let Some(value) = stack.pop() {
        if is_structured_copy(value, reference) {
            return true;
        }
        match value {
            LosslessSourceValue::Object(fields) => {
                stack.extend(fields.iter().map(|(_, value)| value));
            }
            LosslessSourceValue::Array(items) => stack.extend(items.iter()),
            _ => {}
        }
    }
    false
}

fn is_structured_copy(value: &LosslessSourceValue, reference: &LosslessSourceValue) -> bool {
    matches!(value, LosslessSourceValue::Object(_)) && lossless_copy_equal(reference, value)
}

/// Prove one permitted slot against its fixed carrier rule.
///
/// * `raw`: a non-envelope string byte-identical to the verified legacy body.
/// * `structuredContent`: an object equal to the verified JSON value.
/// * `text`: a string that decodes exactly once to the verified JSON value.
///
/// The value is read from the captured blob line, not from the parsed
/// `extra`, so a repeated member name or a distinct number spelling is still
/// visible. A missing captured line, a position mismatch, a rejected parse or
/// a value difference is `Unproven`.
fn prove_pi_copy_slot(
    extra: &Value,
    raw_document: Option<&LosslessSourceValue>,
    slot: PiCopySlot,
    reference: Option<&LosslessSourceValue>,
    legacy_body: Option<&str>,
) -> PiCopyProof {
    let present = extra
        .pointer("/message/details")
        .and_then(Value::as_object)
        .is_some_and(|details| details.contains_key(slot.name()));
    if !present {
        return PiCopyProof::Absent;
    }
    let Some(document) = raw_document else {
        return PiCopyProof::Unproven;
    };
    let Some(candidate) = document
        .get("message")
        .and_then(|message| message.get("details"))
        .and_then(|details| details.get(slot.name()))
    else {
        return PiCopyProof::Unproven;
    };
    let proven = match slot {
        PiCopySlot::Raw => matches!(legacy_body, Some(body) if candidate.as_str() == Some(body)),
        PiCopySlot::StructuredContent => {
            matches!(candidate, LosslessSourceValue::Object(_))
                && reference.is_some_and(|reference| lossless_copy_equal(reference, candidate))
        }
        PiCopySlot::Text => candidate.as_str().is_some_and(|text| {
            let Ok(decoded) = LosslessSourceValue::parse(text.as_bytes()) else {
                return false;
            };
            // At most one decode: a value that is still a string is never
            // decoded a second time.
            !matches!(decoded, LosslessSourceValue::String(_))
                && reference.is_some_and(|reference| lossless_copy_equal(reference, &decoded))
        }),
    };
    if proven {
        PiCopyProof::Proven
    } else {
        PiCopyProof::Unproven
    }
}

/// The fixed copy equality. Object member order is irrelevant; array order,
/// value type and string value matter; a number is equal only to the identical
/// token, never to an equal float or a rounded neighbour. Values that exceed
/// the comparison bound are never proven.
fn lossless_copy_equal(reference: &LosslessSourceValue, candidate: &LosslessSourceValue) -> bool {
    const MAX_DEPTH: usize = 128;
    if !within_copy_depth(reference, MAX_DEPTH) || !within_copy_depth(candidate, MAX_DEPTH) {
        return false;
    }
    let mut stack = vec![(reference, candidate)];
    while let Some((left, right)) = stack.pop() {
        match (left, right) {
            (LosslessSourceValue::Object(left), LosslessSourceValue::Object(right)) => {
                if left.len() != right.len() {
                    return false;
                }
                for (key, left_value) in left {
                    let Some((_, right_value)) = right.iter().find(|(other, _)| other == key)
                    else {
                        return false;
                    };
                    stack.push((left_value, right_value));
                }
            }
            (LosslessSourceValue::Array(left), LosslessSourceValue::Array(right)) => {
                if left.len() != right.len() {
                    return false;
                }
                stack.extend(left.iter().zip(right));
            }
            (LosslessSourceValue::String(left), LosslessSourceValue::String(right)) => {
                if left != right {
                    return false;
                }
            }
            (LosslessSourceValue::Number(left), LosslessSourceValue::Number(right)) => {
                if left.as_str() != right.as_str() {
                    return false;
                }
            }
            (LosslessSourceValue::Bool(left), LosslessSourceValue::Bool(right)) => {
                if left != right {
                    return false;
                }
            }
            (LosslessSourceValue::Null, LosslessSourceValue::Null) => {}
            _ => return false,
        }
    }
    true
}

/// Whether a value's nesting stays within the comparison bound.
fn within_copy_depth(value: &LosslessSourceValue, max: usize) -> bool {
    let mut stack = vec![(value, 1usize)];
    while let Some((value, depth)) = stack.pop() {
        if depth > max {
            return false;
        }
        match value {
            LosslessSourceValue::Object(members) => {
                stack.extend(members.iter().map(|(_, value)| (value, depth + 1)));
            }
            LosslessSourceValue::Array(items) => {
                stack.extend(items.iter().map(|item| (item, depth + 1)));
            }
            _ => {}
        }
    }
    true
}

/// Replace each proven copy with the same placeholder the body uses. Keys and
/// the `details` object itself stay; only the proven leaf value changes.
fn clear_pi_copies(extra: &mut Value, slots: &[PiCopySlot], marker: &ExcludedMarker) {
    if slots.is_empty() {
        return;
    }
    let placeholder = serde_json::json!({
        "redacted": true,
        "sha256": marker.sha256,
        "bytes": marker.bytes,
    });
    let Some(details) = extra
        .pointer_mut("/message/details")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    for slot in slots {
        if details.contains_key(slot.name()) {
            details.insert(slot.name().to_string(), placeholder.clone());
        }
    }
}

/// Verify the atomic write before it reaches the canonical message: no copy
/// of the body survives, and every changed leaf is one the cleanup owns and
/// now holds the marker placeholder. Anything else keeps the record whole.
fn pi_cleanup_is_atomic(
    before: &Value,
    after: &Value,
    shape: PiResultBodyShape,
    slots: &[PiCopySlot],
    marker: &ExcludedMarker,
    body: &str,
    tool: RecallTool,
) -> bool {
    if has_unproven_body_copy(after, body, tool, &[]) {
        return false;
    }
    let placeholder = serde_json::json!({
        "redacted": true,
        "sha256": marker.sha256,
        "bytes": marker.bytes,
    });
    let mut paths = Vec::new();
    changed_paths(before, after, "", &mut paths);
    paths.iter().all(|path| {
        // A scalar slot is replaced at its own path; an object or array slot
        // is replaced as a whole, so its changed children are reported. Both
        // count only when the slot value itself is now the placeholder.
        let cleared_slot = slots.iter().any(|slot| {
            let root = format!("/message/details/{}", slot.name());
            let changed = path == &root
                || (path.starts_with(&root) && path.as_bytes().get(root.len()) == Some(&b'/'));
            changed && after.pointer(&root) == Some(&placeholder)
        });
        let cleared_body = match shape {
            PiResultBodyShape::String => {
                path == "/message/content"
                    && after.pointer("/message/content") == Some(&placeholder)
            }
            PiResultBodyShape::TextBlocks => {
                path.starts_with("/message/content/")
                    && path.ends_with("/text")
                    && after.pointer(path) == Some(&placeholder)
            }
            PiResultBodyShape::Mixed => false,
        };
        cleared_slot || cleared_body
    })
}

/// Every path whose value differs between two JSON documents. A container that
/// changed shape (or an array whose length changed) is reported as that
/// container's own path.
fn changed_paths(before: &Value, after: &Value, path: &str, out: &mut Vec<String>) {
    if before == after {
        return;
    }
    match (before, after) {
        (Value::Object(left), Value::Object(right)) => {
            for (key, left_value) in left {
                let child = format!("{path}/{key}");
                match right.get(key) {
                    Some(right_value) => changed_paths(left_value, right_value, &child, out),
                    None => out.push(child),
                }
            }
            for key in right.keys() {
                if !left.contains_key(key) {
                    out.push(format!("{path}/{key}"));
                }
            }
        }
        (Value::Array(left), Value::Array(right)) if left.len() == right.len() => {
            for (index, (left_value, right_value)) in left.iter().zip(right).enumerate() {
                changed_paths(left_value, right_value, &format!("{path}/{index}"), out);
            }
        }
        _ => out.push(path.to_string()),
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

    // ========================================================================
    // R18: three proven non-envelope copies.
    //
    // These helpers write the derived blob from literal JSONL lines instead of
    // re-serializing a `Value`, so a case can carry a JSON number token or a
    // duplicate key exactly as the matrix fixture spells it. The real pinned
    // connector still projects the result.
    // ========================================================================

    const R18_SESSION_LINE: &str = r#"{"type":"session","version":3,"id":"synthetic-R18","timestamp":"2026-10-24T00:00:00.000Z","cwd":"/synthetic/alien"}"#;

    fn r18_user_line(id: &str, text: &str) -> String {
        serde_json::json!({
            "type": "message",
            "id": id,
            "timestamp": "2026-10-24T00:00:00.000Z",
            "message": {"role": "user", "content": [{"type": "text", "text": text}]},
        })
        .to_string()
    }

    fn r18_call_line(id: &str, call_id: &str, tool_name: &str, arguments: Value) -> String {
        serde_json::json!({
            "type": "message",
            "id": id,
            "timestamp": "2026-10-24T00:00:00.000Z",
            "message": {
                "role": "assistant",
                "content": [{
                    "type": "toolCall",
                    "id": call_id,
                    "name": tool_name,
                    "arguments": arguments,
                }],
            },
        })
        .to_string()
    }

    /// One native result line. `details` is spliced in as a literal JSON text,
    /// so a copy keeps its own number spelling and member order.
    fn r18_result_line(
        id: &str,
        call_id: &str,
        tool_name: &str,
        body: &str,
        details: Option<&str>,
    ) -> String {
        let body = serde_json::to_string(body).unwrap();
        let details = details.map_or_else(String::new, |details| format!(",\"details\":{details}"));
        format!(
            "{{\"type\":\"message\",\"id\":\"{id}\",\"timestamp\":\"2026-10-24T00:00:00.000Z\",\"message\":{{\"role\":\"toolResult\",\"content\":[{{\"type\":\"text\",\"text\":{body}}}],\"toolCallId\":\"{call_id}\",\"toolName\":\"{tool_name}\",\"isError\":false{details}}}}}"
        )
    }

    fn project_literal(tag: &str, lines: &[String]) -> FullVariant {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join(".pi/agent/sessions");
        fs::create_dir_all(&sessions).unwrap();
        let blob = sessions.join(format!("2026-10-24T00-00-00_R18_{tag}.jsonl"));
        let mut text = lines.join("\n");
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

    fn r18_placeholder(marker: &ExcludedMarker) -> Value {
        serde_json::json!({
            "redacted": true,
            "sha256": marker.sha256,
            "bytes": marker.bytes,
        })
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

    #[test]
    fn alien_pi_cleanup_alignment_reports_native_record_count() {
        for (case, raw_count, canonical_count) in [
            ("drop-canonical", 4, 3),
            ("extra-canonical", 4, 5),
            ("drop-raw", 3, 4),
            ("extra-raw", 5, 4),
            ("same-count-mismatch", 4, 4),
        ] {
            let mut lines = p01_lines();
            let mut variant = project_full(case, &lines);
            match case {
                "drop-canonical" => {
                    variant.conversation.messages.pop();
                }
                "extra-canonical" => {
                    let mut extra = variant.conversation.messages[0].clone();
                    extra.idx = 4;
                    variant.conversation.messages.push(extra);
                }
                "drop-raw" => {
                    lines.remove(1);
                }
                "extra-raw" => {
                    lines.push(lines[1].clone());
                }
                "same-count-mismatch" => unmap_message(&mut variant, 0),
                _ => unreachable!(),
            }
            if matches!(case, "drop-raw" | "extra-raw") {
                let text = lines
                    .iter()
                    .map(|line| serde_json::to_string(line).unwrap())
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                fs::write(&variant.blob, text).unwrap();
            }
            assert_eq!(variant.conversation.messages.len(), canonical_count);
            let before = serde_json::to_value(&variant.conversation.messages).unwrap();
            let outcome = cleanup_pi_conversation(
                &variant.blob,
                &mut variant.conversation,
                "derived/diagnostic.jsonl",
                false,
            );
            assert!(outcome.alignment_failed, "{case}");
            assert_eq!(
                outcome.event_count, raw_count,
                "{case}: actual native record count"
            );
            assert_eq!(outcome.excluded, vec![None; canonical_count], "{case}");
            assert_eq!(
                outcome.uncovered_by_reason,
                BTreeMap::from([("unpaired_result".to_string(), 1)]),
                "{case}"
            );
            assert_eq!(
                serde_json::to_value(&variant.conversation.messages).unwrap(),
                before,
                "{case}: no cleanup on failed alignment"
            );
        }
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

    /// C1: one legacy-JSON body with its byte-identical `details.raw` copy, and
    /// one C04 body with both a decoded `details.structuredContent` object and
    /// a once-decoded `details.text` string. Each proven copy is replaced by
    /// the same marker placeholder as the body, ordinary sibling metadata
    /// survives, and the captured blob is never written.
    #[test]
    fn r18_pi_three_slots_clean() {
        let legacy_body = r#"{"hits":[{"line_number":1,"content":"synthetic"}]}"#;
        let inner = r#"{"hits":[]}"#;
        let lines = vec![
            R18_SESSION_LINE.to_string(),
            r18_user_line("u", "ordinary synthetic user"),
            r18_call_line(
                "a1",
                "c1",
                "mcp__cass_mcp__cass_search",
                serde_json::json!({"query": "synthetic alien"}),
            ),
            r18_result_line(
                "r1",
                "c1",
                "mcp__cass_mcp__cass_search",
                legacy_body,
                Some(&format!(
                    r#"{{"server":"cass-mcp","fullOutputPath":"/synthetic/out.json","raw":{}}}"#,
                    serde_json::to_string(legacy_body).unwrap()
                )),
            ),
            r18_call_line(
                "a2",
                "c2",
                "mcp__cass_mcp__cass_search",
                serde_json::json!({"query": "synthetic alien"}),
            ),
            r18_result_line(
                "r2",
                "c2",
                "mcp__cass_mcp__cass_search",
                SEARCH_C04,
                Some(&format!(
                    r#"{{"server":"cass-mcp","structuredContent":{inner},"text":{}}}"#,
                    serde_json::to_string(inner).unwrap()
                )),
            ),
        ];
        let mut variant = project_literal("three-slots", &lines);
        let blob_before = fs::read(&variant.blob).unwrap();

        let outcome = cleanup_pi_conversation(
            &variant.blob,
            &mut variant.conversation,
            "derived/r18.jsonl",
            false,
        );

        assert!(!outcome.alignment_failed, "real projection aligns");
        assert_eq!(
            outcome.uncovered_by_reason,
            BTreeMap::new(),
            "both proven results are excluded, nothing is preserved"
        );

        // A1: legacy body plus its byte-identical raw copy.
        let legacy_marker = outcome.excluded[2]
            .as_ref()
            .expect("A1 legacy-JSON result is excluded");
        let legacy_placeholder = r18_placeholder(legacy_marker);
        let legacy_message = &variant.conversation.messages[2];
        assert!(
            legacy_message.content.is_empty(),
            "A1: the body leaves the content slot"
        );
        assert_eq!(
            legacy_message.extra.pointer("/message/content/0/text"),
            Some(&legacy_placeholder),
            "A1: the body uses the marker placeholder"
        );
        assert_eq!(
            legacy_message.extra.pointer("/message/details/raw"),
            Some(&legacy_placeholder),
            "A1: the proven raw copy uses the same placeholder"
        );
        assert_eq!(
            legacy_message.extra.pointer("/message/details/server"),
            Some(&Value::String("cass-mcp".to_string())),
            "A1: ordinary sibling metadata survives"
        );
        assert_eq!(
            legacy_message
                .extra
                .pointer("/message/details/fullOutputPath"),
            Some(&Value::String("/synthetic/out.json".to_string())),
            "A1: an unrelated details field is untouched"
        );

        // A2 and A3: C04 body with the decoded object and the once-decoded
        // string copy.
        let c04_marker = outcome.excluded[4]
            .as_ref()
            .expect("A2/A3 C04 result is excluded");
        let c04_placeholder = r18_placeholder(c04_marker);
        let c04_message = &variant.conversation.messages[4];
        assert!(
            c04_message.content.is_empty(),
            "A2/A3: the body leaves the content slot"
        );
        assert_eq!(
            c04_message.extra.pointer("/message/content/0/text"),
            Some(&c04_placeholder),
            "A2/A3: the body uses the marker placeholder"
        );
        assert_eq!(
            c04_message
                .extra
                .pointer("/message/details/structuredContent"),
            Some(&c04_placeholder),
            "A2: the decoded object copy uses the same placeholder"
        );
        assert_eq!(
            c04_message.extra.pointer("/message/details/text"),
            Some(&c04_placeholder),
            "A3: the once-decoded string copy uses the same placeholder"
        );
        assert_eq!(
            c04_message.extra.pointer("/message/details/server"),
            Some(&Value::String("cass-mcp".to_string())),
            "A2/A3: ordinary sibling metadata survives"
        );
        assert_eq!(
            fs::read(&variant.blob).unwrap(),
            blob_before,
            "the captured blob is never written"
        );
    }

    /// One user turn, one strong CASS call and its result, written from
    /// literal lines. The result is canonical message index 2.
    fn r18_single_result_lines(body: &str, details: Option<&str>) -> Vec<String> {
        vec![
            R18_SESSION_LINE.to_string(),
            r18_user_line("u", "ordinary synthetic user"),
            r18_call_line(
                "a",
                "c1",
                "mcp__cass_mcp__cass_search",
                serde_json::json!({"query": "synthetic alien"}),
            ),
            r18_result_line("r", "c1", "mcp__cass_mcp__cass_search", body, details),
        ]
    }

    /// Run one cleanup and require the whole record to survive: nothing is
    /// excluded, the single candidate is counted as unpaired, every canonical
    /// message keeps its exact pre-run value and the blob is unchanged.
    fn assert_r18_preserved(tag: &str, variant: &mut FullVariant) {
        let blob_before = fs::read(&variant.blob).unwrap();
        let before = serde_json::to_value(&variant.conversation.messages).unwrap();
        let outcome = cleanup_pi_conversation(
            &variant.blob,
            &mut variant.conversation,
            "derived/r18.jsonl",
            false,
        );
        assert!(!outcome.alignment_failed, "{tag}: alignment holds");
        assert_eq!(
            outcome.excluded,
            vec![None; variant.conversation.messages.len()],
            "{tag}: nothing is excluded"
        );
        assert_eq!(
            outcome.uncovered_by_reason,
            BTreeMap::from([("unpaired_result".to_string(), 1)]),
            "{tag}: the one candidate is preserved and counted"
        );
        assert_eq!(
            serde_json::to_value(&variant.conversation.messages).unwrap(),
            before,
            "{tag}: body and the whole decoded extra are unchanged"
        );
        assert_eq!(
            fs::read(&variant.blob).unwrap(),
            blob_before,
            "{tag}: the captured blob is never written"
        );
    }

    fn run_r18_cleanup(variant: &mut FullVariant) -> PiCleanupOutcome {
        cleanup_pi_conversation(
            &variant.blob,
            &mut variant.conversation,
            "derived/r18.jsonl",
            false,
        )
    }

    fn copy_policy_cases() -> Vec<Value> {
        let path = fixture_dir().join("followup_copy_policy.json");
        let fixture: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        fixture["cases"].as_array().unwrap().clone()
    }

    /// C2: the frozen 6-positive/16-negative comparison matrix, run against
    /// the same production proof helper the cleanup consumes.
    #[test]
    fn r18_pi_copy_policy_matrix() {
        let cases = copy_policy_cases();
        assert_eq!(cases.len(), 22, "the frozen matrix keeps its 22 cases");
        assert_eq!(
            cases
                .iter()
                .filter(|case| case["expected_proven"] == Value::Bool(true))
                .count(),
            6,
            "6 proven and 16 unproven"
        );

        for case in &cases {
            let id = case["id"].as_str().unwrap();
            let slot = match case["carrier"].as_str().unwrap() {
                "raw" => PiCopySlot::Raw,
                "structured" => PiCopySlot::StructuredContent,
                "text" => PiCopySlot::Text,
                other => panic!("{id}: unknown carrier {other}"),
            };
            let reference_json = case["reference_json"].as_str().unwrap();
            let candidate_json = case["candidate_json"].as_str().unwrap();
            let expected = case["expected_proven"].as_bool().unwrap();

            // The candidate's real value is read from the captured line, so
            // the parsed `extra` only needs to carry the key. A non-permitted
            // pointer keeps the slot out of `details` entirely.
            let permitted = format!("/message/details/{}", slot.name());
            let pointer = case["pointer"].as_str().unwrap_or(&permitted);
            let embedded = match slot {
                PiCopySlot::StructuredContent => candidate_json.to_string(),
                _ => serde_json::to_string(candidate_json).unwrap(),
            };
            let (extra, line) = if pointer == permitted {
                let mut line = String::from(r#"{"message":{"details":{"#);
                line.push('"');
                line.push_str(slot.name());
                line.push_str("\":");
                line.push_str(&embedded);
                line.push_str("}}}");
                let mut details = serde_json::Map::new();
                details.insert(slot.name().to_string(), Value::Null);
                (serde_json::json!({"message": {"details": details}}), line)
            } else {
                let name = pointer.rsplit('/').next().unwrap();
                let mut line = String::from(r#"{"message":{"details":{},"other":{"#);
                line.push('"');
                line.push_str(name);
                line.push_str("\":");
                line.push_str(&embedded);
                line.push_str("}}}");
                let mut other = serde_json::Map::new();
                other.insert(name.to_string(), Value::Null);
                (
                    serde_json::json!({"message": {"details": {}, "other": other}}),
                    line,
                )
            };

            let raw_evidence = case["raw_evidence_available"].as_bool().unwrap_or(true);
            // The production path parses the captured line losslessly; a
            // repeated member name anywhere in it rejects that parse, exactly
            // as it would in a captured blob.
            let document = raw_evidence
                .then(|| LosslessSourceValue::parse(line.as_bytes()).ok())
                .flatten();
            let legacy_body = (slot == PiCopySlot::Raw && case["body_is_c04"] != Value::Bool(true))
                .then_some(reference_json);
            let reference = LosslessSourceValue::parse(reference_json.as_bytes()).unwrap();

            let proof = prove_pi_copy_slot(
                &extra,
                document.as_ref(),
                slot,
                Some(&reference),
                legacy_body,
            );
            assert_eq!(
                proof == PiCopyProof::Proven,
                expected,
                "{id}: carrier {} pointer {pointer}",
                slot.name()
            );
        }
    }

    /// C3: A4 and every copy outside the proven slots keep the whole record.
    /// Ordinary metadata with the same field names or a shared fragment is
    /// not a copy, so that row is still excluded untouched.
    #[test]
    fn r18_pi_unknown_copies_preserve() {
        let legacy = r#"{"hits":[]}"#;

        // A4: the raw slot carries the complete C04 envelope itself.
        let mut variant = project_literal(
            "a4-raw-envelope",
            &r18_single_result_lines(
                SEARCH_C04,
                Some(&format!(
                    r#"{{"raw":{}}}"#,
                    serde_json::to_string(SEARCH_C04).unwrap()
                )),
            ),
        );
        assert_r18_preserved("A4 raw holds the complete envelope", &mut variant);

        // A legacy byte-identical copy outside the three permitted slots.
        let mut variant = project_literal(
            "legacy-elsewhere",
            &r18_single_result_lines(
                legacy,
                Some(&format!(
                    r#"{{"note":{}}}"#,
                    serde_json::to_string(legacy).unwrap()
                )),
            ),
        );
        assert_r18_preserved("legacy copy outside the permitted slots", &mut variant);

        // An unknown field carrying the complete envelope.
        let mut variant = project_literal(
            "c04-elsewhere",
            &r18_single_result_lines(
                SEARCH_C04,
                Some(&format!(
                    r#"{{"other":{}}}"#,
                    serde_json::to_string(SEARCH_C04).unwrap()
                )),
            ),
        );
        assert_r18_preserved(
            "complete envelope outside the permitted slots",
            &mut variant,
        );

        // N16 shape: the complete structured result value at a fourth
        // position. It grants no cleaning there and keeps the whole record;
        // the positive control shows the same pair without the copy excludes.
        let inner = r#"{"hits":[{"content":"synthetic"}]}"#;
        let body = format!(r#"<cass_recall version="1" tool="cass_search">{inner}</cass_recall>"#);
        let lines = r18_single_result_lines(&body, None);
        let mut control = project_literal("wrong-position-control", &lines);
        assert!(
            run_r18_cleanup(&mut control)
                .excluded
                .iter()
                .any(Option::is_some),
            "positive control: the same pair without a copy excludes"
        );
        let mut outside = lines.clone();
        assert_eq!(outside[3].pop(), Some('}'));
        outside[3].push_str(&format!(r#","other":{{"structuredContent":{inner}}}}}"#));
        let mut variant = project_literal("wrong-position", &outside);
        assert_r18_preserved(
            "complete structured copy outside the permitted slots",
            &mut variant,
        );

        // Ordinary metadata that only shares field names or a fragment is not
        // a copy: the row is excluded and every metadata value survives.
        let mut variant = project_literal(
            "ordinary-metadata",
            &r18_single_result_lines(
                legacy,
                Some(r#"{"server":"cass-mcp","summary":"hits: synthetic","hits":[]}"#),
            ),
        );
        let outcome = run_r18_cleanup(&mut variant);
        let marker = outcome.excluded[2]
            .as_ref()
            .expect("ordinary metadata does not block the exclusion");
        let placeholder = r18_placeholder(marker);
        let extra = &variant.conversation.messages[2].extra;
        assert_eq!(
            extra.pointer("/message/content/0/text"),
            Some(&placeholder),
            "the body is cleared"
        );
        assert_eq!(
            extra.pointer("/message/details/summary"),
            Some(&Value::String("hits: synthetic".to_string())),
            "a similar fragment stays"
        );
        assert_eq!(
            extra.pointer("/message/details/hits"),
            Some(&serde_json::json!([])),
            "a same-named ordinary field stays"
        );
        assert_eq!(
            extra.pointer("/message/details/server"),
            Some(&Value::String("cass-mcp".to_string())),
            "an ordinary details field stays"
        );
    }

    /// C3: a copy that cannot be proven keeps the whole record, including a
    /// repeated member name, a damaged candidate, a different number token, a
    /// non-identical raw string and a non-envelope raw value under a C04 body.
    #[test]
    fn r18_pi_source_ambiguity_preserves() {
        let c04 = |inner: &str| {
            format!(r#"<cass_recall version="1" tool="cass_search">{inner}</cass_recall>"#)
        };
        let as_text = |text: &str| serde_json::to_string(text).unwrap();

        // A repeated decoded member name in the candidate object.
        let mut variant = project_literal(
            "dup-key",
            &r18_single_result_lines(
                SEARCH_C04,
                Some(r#"{"structuredContent":{"hits":[],"hits":[]}}"#),
            ),
        );
        assert_r18_preserved("repeated member name", &mut variant);

        // A repeated member name spelled with an escape in the second copy.
        let mut variant = project_literal(
            "dup-key-escaped",
            &r18_single_result_lines(
                SEARCH_C04,
                Some(r#"{"structuredContent":{"hits":[],"\u0068its":[]}}"#),
            ),
        );
        assert_r18_preserved("escaped repeated member name", &mut variant);

        // A repeated member name in the paired call's captured line. The call
        // block still parses to id `c1` (the last member wins), so the binding
        // looks valid, but the captured source declares two ids.
        let details = Some(r#"{"structuredContent":{"hits":[]}}"#);
        let lines = r18_single_result_lines(SEARCH_C04, details);
        let mut control = project_literal("call-source-control", &lines);
        assert!(
            run_r18_cleanup(&mut control)
                .excluded
                .iter()
                .any(Option::is_some),
            "positive control: the unique call id still excludes"
        );
        let mut ambiguous = lines.clone();
        assert!(ambiguous[2].contains(r#""id":"c1""#));
        ambiguous[2] = ambiguous[2].replacen(r#""id":"c1""#, r#""id":"other","id":"c1""#, 1);
        let mut variant = project_literal("call-source-duplicate", &ambiguous);
        assert_r18_preserved("repeated id in the paired call line", &mut variant);

        // A damaged candidate string.
        let mut variant = project_literal(
            "damaged-text",
            &r18_single_result_lines(
                SEARCH_C04,
                Some(&format!(r#"{{"text":{}}}"#, as_text(r#"{"hits":["#))),
            ),
        );
        assert_r18_preserved("damaged candidate", &mut variant);

        // A different number token at the same leaf.
        let scored = c04(r#"{"hits":[{"n":1}]}"#);
        let mut variant = project_literal(
            "number-token",
            &r18_single_result_lines(
                &scored,
                Some(r#"{"structuredContent":{"hits":[{"n":1.0}]}}"#),
            ),
        );
        assert_r18_preserved("different number token", &mut variant);

        // A raw value that is not byte-identical to the legacy body.
        let mut variant = project_literal(
            "raw-bytes",
            &r18_single_result_lines(
                r#"{"hits":[]}"#,
                Some(&format!(r#"{{"raw":{}}}"#, as_text(r#"{ "hits": [] }"#))),
            ),
        );
        assert_r18_preserved("raw bytes differ", &mut variant);

        // A non-envelope raw value under a C04 body: A1 is closed here.
        let mut variant = project_literal(
            "c04-raw-inner",
            &r18_single_result_lines(
                SEARCH_C04,
                Some(&format!(r#"{{"raw":{}}}"#, as_text(r#"{"hits":[]}"#))),
            ),
        );
        assert_r18_preserved("raw inner JSON under a C04 body", &mut variant);
    }

    /// C4: several proven copies are cleared in the same write; one unsafe
    /// copy keeps the body and every copy exactly as captured.
    #[test]
    fn r18_pi_atomic_multiple_copies() {
        let inner = r#"{"hits":[]}"#;
        let as_text = |text: &str| serde_json::to_string(text).unwrap();

        // Two proven carriers plus ordinary metadata, all on one C04 result.
        let mut variant = project_literal(
            "both-proven",
            &r18_single_result_lines(
                SEARCH_C04,
                Some(&format!(
                    r#"{{"structuredContent":{inner},"text":{},"tool":"cass_search"}}"#,
                    as_text(inner)
                )),
            ),
        );
        let blob_before = fs::read(&variant.blob).unwrap();
        let outcome = run_r18_cleanup(&mut variant);
        let marker = outcome.excluded[2]
            .as_ref()
            .expect("both copies are proven");
        let placeholder = r18_placeholder(marker);
        let extra = &variant.conversation.messages[2].extra;
        assert_eq!(
            extra.pointer("/message/details/structuredContent"),
            Some(&placeholder),
            "the object copy is cleared"
        );
        assert_eq!(
            extra.pointer("/message/details/text"),
            Some(&placeholder),
            "the string copy is cleared with the same marker"
        );
        assert_eq!(
            extra.pointer("/message/details/tool"),
            Some(&Value::String("cass_search".to_string())),
            "the sibling field is kept"
        );
        assert_eq!(
            fs::read(&variant.blob).unwrap(),
            blob_before,
            "the captured blob is never written"
        );

        // The same shape with one damaged carrier: nothing is written.
        let mut variant = project_literal(
            "one-unsafe",
            &r18_single_result_lines(
                SEARCH_C04,
                Some(&format!(
                    r#"{{"structuredContent":{inner},"text":{}}}"#,
                    as_text(r#"{"hits":["#)
                )),
            ),
        );
        assert_r18_preserved("one unsafe copy keeps all", &mut variant);

        // A proven raw copy plus a second legacy copy elsewhere: the outer
        // copy has no proven position, so the whole record stays.
        let legacy = r#"{"hits":[]}"#;
        let mut variant = project_literal(
            "outer-copy",
            &r18_single_result_lines(
                legacy,
                Some(&format!(
                    r#"{{"raw":{},"note":{}}}"#,
                    as_text(legacy),
                    as_text(legacy)
                )),
            ),
        );
        assert_r18_preserved("an outer legacy copy keeps all", &mut variant);
    }

    /// C5: the public codec keeps its accept, reject and error behavior, and
    /// the internal helper returns the same value plus the original JSON text.
    #[test]
    fn r18_codec_public_behavior_kept() {
        use crate::recall_output::{RecallError, encode};
        let values = [
            (RecallTool::Search, serde_json::json!({"hits": []})),
            (RecallTool::Expand, serde_json::json!([])),
            (RecallTool::Sessions, serde_json::json!({"sessions": []})),
            (
                RecallTool::Timeline,
                serde_json::json!({
                    "range": {},
                    "total_sessions": 0,
                    "groups": {},
                }),
            ),
        ];
        for (tool, value) in values {
            let encoded = encode(tool, &value).unwrap();
            assert_eq!(
                decode(&encoded, tool).unwrap(),
                value,
                "{tool:?}: round trip"
            );
            let (decoded, original) = decode_with_original_json(&encoded, tool).unwrap();
            assert_eq!(decoded, value, "{tool:?}: same value from the helper");
            let reparsed: Value = serde_json::from_str(&original).unwrap();
            assert_eq!(
                reparsed, value,
                "{tool:?}: the helper keeps the source JSON"
            );
        }

        assert!(
            decode(
                &encode(RecallTool::Search, &serde_json::json!({"hits": []})).unwrap(),
                RecallTool::Expand
            )
            .is_err()
        );
        assert!(
            decode(
                "<cass_recall version=\"2\" tool=\"cass_search\">{\"hits\":[]}</cass_recall>",
                RecallTool::Search
            )
            .is_err()
        );
        assert!(
            decode(
                "<cass_recall version=\"1\" tool=\"cass_search\">{\"hits\":[</cass_recall>",
                RecallTool::Search
            )
            .is_err()
        );
        assert!(decode("<cass_recall version=\"1\" tool=\"cass_search\">{\"hits\":[]}</cass_recall><extra/>", RecallTool::Search).is_err());
        assert!(
            decode(
                "prefix<cass_recall version=\"1\" tool=\"cass_search\">{\"hits\":[]}</cass_recall>",
                RecallTool::Search
            )
            .is_err()
        );

        // A repeated member name is still accepted by the public codec (the
        // last member wins), exactly as before; only the copy proof refuses it.
        let duplicate = "<cass_recall version=\"1\" tool=\"cass_search\">{\"hits\":[],\"hits\":[]}</cass_recall>";
        assert_eq!(
            decode(duplicate, RecallTool::Search).unwrap(),
            serde_json::json!({"hits": []}),
            "public decode keeps its duplicate-key behavior"
        );
        let (_, original) = decode_with_original_json(duplicate, RecallTool::Search).unwrap();
        assert_eq!(
            original, r#"{"hits":[],"hits":[]}"#,
            "the helper hands back the captured JSON text, repeated member and all"
        );
        let _: fn(&str, RecallTool) -> Result<Value, RecallError> = decode;
    }
}
