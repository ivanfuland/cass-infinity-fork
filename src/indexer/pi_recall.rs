// Dead-code tolerated module-wide: ticket 01 of the `cass-alien-fresh-ingest`
// batch lands the Pi structural facts ahead of the consumer. The Pi cleanup
// ticket (02) reads `PiFacts`, its bindings, candidate results and body shapes
// when it runs the shared v2 recall judgment for `pi_agent`; until then the
// only readers are this module's own tests.
#![allow(dead_code)]

//! Ticket 01 (`cass-alien-fresh-ingest`): Pi raw-event facts and unique
//! tool-call binding.
//!
//! Structural expansion only. This module builds the internal facts that the
//! later Pi cleanup ticket (02) consumes to run the shared v2 recall judgment
//! for `pi_agent`. It makes no exclusion decision, adds no CLI/MCP surface,
//! changes no legacy `PairingContext` branch and does not claim that Pi recall
//! cleaning is finished.
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

use crate::connectors::NormalizedConversation;
use crate::indexer::exclusion::{BlockKind, RawBlock, RawEvent};

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
    /// Canonical message indexes of results whose tool name is one of the
    /// four strong Pi identities.
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
        let mut calls_by_id: HashMap<String, Vec<CallSite>> = HashMap::new();
        for (idx, raw_idx) in matched.iter().enumerate() {
            let Some(raw_idx) = raw_idx else { continue };
            let value = &raw_messages[*raw_idx].value;
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

        for (result_idx, raw_idx) in matched.iter().enumerate() {
            let Some(raw_idx) = raw_idx else { continue };
            let value = &raw_messages[*raw_idx].value;
            if raw_role(value) != Some("toolResult") {
                continue;
            }
            facts
                .result_body_shapes
                .insert(result_idx, result_body_shape(value));

            let tool_name = value
                .pointer("/message/toolName")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty());
            if tool_name.is_some_and(|name| PI_STRONG_TOOL_NAMES.contains(&name)) {
                facts.candidate_result_indices.insert(result_idx);
            }

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
    }

    #[test]
    fn alien_pi_facts_f12() {
        assert_case("F12");
    }
}
