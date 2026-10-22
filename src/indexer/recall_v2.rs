//! Ticket 05: v2 MCP recall judgment, source extraction and the
//! source-aware apply entry.
//!
//! This module is **not wired into the default producer**. The legacy
//! `exclusion::decide` / `exclusion::apply_with_redaction` path, its alias
//! table and its `rule_version = 1` markers are unchanged; a later ticket
//! consumes [`decide`], [`apply_with_redaction`] and [`parse_result`] to
//! switch ingest over.
//!
//! v2 differs from v1 in exactly two places:
//!
//! * **tool identity** — the four MCP tools are recognized by their exact
//!   full names (`mcp__cass-mcp__cass_*`), or, for the connectors that record
//!   bare names, by a bare name *plus* a complete C04 recall envelope. A bare
//!   name alone is never enough to delete a body, because an ordinary tool
//!   called `cass_search` is indistinguishable from a recall by name.
//! * **source extraction** — a result is decoded from the single C04
//!   envelope (or a legacy unwrapped shape) instead of the old
//!   `{"hits": ...}`-only parser, so `cass_sessions` / `cass_timeline` can
//!   contribute `src` metadata too. Decoding never rewrites the message body;
//!   it only produces marker metadata.
//!
//! Everything structural (R4 pairing, block location, R7 copy clearing,
//! hashing and anchors) is reused from [`crate::indexer::exclusion`].

use serde_json::Value;

use crate::connectors::NormalizedMessage;
use crate::indexer::exclusion::{
    self, BlockKind, Decision, ExcludedMarker, ExclusionAnchor, ExclusionReason, ExtraFieldMap,
    PairingContext, RawEvent, RecallHit, RecallSrc,
};
use crate::indexer::redact_secrets::MemoizingRedactor;
use crate::recall_output::{self, RecallTool};
use crate::sources::config::ExcludedContextPaths;

/// C05 fixes the v2 rule epoch's marker version at 2.
const RULE_VERSION: u32 = 2;

/// Why a recognized recall candidate was not excluded, or why a bare-name
/// result was preserved. The strings are the frozen diagnostic reasons from
/// C1/05; [`UnsupportedShell`](Self::UnsupportedShell) is reserved for
/// ticket 06 (limited direct-CLI syntax) and is never produced here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UncoveredReason {
    #[allow(dead_code)] // reserved for ticket 06
    UnsupportedShell,
    UnpairedResult,
    AmbiguousToolIdentity,
    InvalidRecallFormat,
}

impl UncoveredReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedShell => "unsupported_shell",
            Self::UnpairedResult => "unpaired_result",
            Self::AmbiguousToolIdentity => "ambiguous_tool_identity",
            Self::InvalidRecallFormat => "invalid_recall_format",
        }
    }
}

/// A v2 exclusion: the structural v1 decision (anchor, event key, target
/// blocks) plus the metadata that v1 used to re-derive inside `apply`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Exclusion {
    pub decision: Decision,
    pub src: Option<RecallSrc>,
    pub parse_error: Option<String>,
}

/// The v2 judgment result. `Exclude` carries everything `apply` needs;
/// `Preserve` still reports a bounded diagnostic for recognized candidates
/// (`None` for rows that were never recall candidates at all).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Outcome {
    Exclude(Exclusion),
    Preserve(Option<UncoveredReason>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateKind {
    /// Exact full server-namespaced tool name: identity is proven by the
    /// name itself (C05/C06).
    Strong(RecallTool),
    /// Bare `cass_*` name: identity needs a complete, valid C04 envelope.
    Bare(RecallTool),
}

fn cass_supported_agent(agent_slug: &str) -> bool {
    matches!(agent_slug, "claude_code" | "codex")
}

fn full_name_tool(name: &str) -> Option<RecallTool> {
    match name {
        "mcp__cass-mcp__cass_search" => Some(RecallTool::Search),
        "mcp__cass-mcp__cass_expand" => Some(RecallTool::Expand),
        "mcp__cass-mcp__cass_sessions" => Some(RecallTool::Sessions),
        "mcp__cass-mcp__cass_timeline" => Some(RecallTool::Timeline),
        _ => None,
    }
}

fn bare_name_tool(name: &str) -> Option<RecallTool> {
    match name {
        "cass_search" => Some(RecallTool::Search),
        "cass_expand" => Some(RecallTool::Expand),
        "cass_sessions" => Some(RecallTool::Sessions),
        "cass_timeline" => Some(RecallTool::Timeline),
        _ => None,
    }
}

/// Exact-name identity only. In particular `mcp__other-mcp__cass_search`
/// and any other server prefix do not match: a shared suffix is not proof
/// that this tool was Cass's.
fn classify_tool(name: &str, agent_slug: &str) -> Option<CandidateKind> {
    if !cass_supported_agent(agent_slug) {
        return None;
    }
    if let Some(tool) = full_name_tool(name) {
        return Some(CandidateKind::Strong(tool));
    }
    bare_name_tool(name).map(CandidateKind::Bare)
}

fn known_cass_tool_name(name: &str) -> bool {
    full_name_tool(name).is_some() || bare_name_tool(name).is_some()
}

/// True when the raw text contains any `cass_recall` opening tag. Used only
/// to separate "looks like a wrapper but is invalid" from "plain output" for
/// bare-name candidates; it is never used to extract a payload.
fn looks_like_recall_wrapper(content: &str) -> bool {
    content.contains("<cass_recall")
}

/// A complete declaration: the root tag, version 1, and one of the four tool
/// names. Used only to count an unpaired row as a candidate; it never
/// authorizes deletion.
fn declares_recall_wrapper(content: &str) -> bool {
    if !content.contains("<cass_recall") || !content.contains("version=\"1\"") {
        return false;
    }
    [
        RecallTool::Search,
        RecallTool::Expand,
        RecallTool::Sessions,
        RecallTool::Timeline,
    ]
    .iter()
    .any(|tool| content.contains(tool.name()))
}

/// No R4 pairing: a tool_result may still prove itself a recall candidate
/// through its own structural tool name or a complete wrapper declaration.
/// It is then counted as `unpaired_result`, never excluded.
fn unpaired_cass_candidate(msg: &NormalizedMessage, event: &RawEvent) -> bool {
    let named_result = event.blocks.iter().any(|block| {
        block.kind == BlockKind::ToolResult
            && block.tool_name.as_deref().is_some_and(known_cass_tool_name)
    });
    named_result || declares_recall_wrapper(&msg.content)
}

fn legacy_outcome(
    msg: &NormalizedMessage,
    idx: usize,
    event: &RawEvent,
    ctx: &PairingContext,
    agent_slug: &str,
    paths_cfg: &ExcludedContextPaths,
) -> Outcome {
    match exclusion::decide(msg, idx, event, ctx, agent_slug, paths_cfg) {
        Some(decision) => Outcome::Exclude(Exclusion { decision, src: None, parse_error: None }),
        None => Outcome::Preserve(None),
    }
}

/// v2 judgment. The signature mirrors the legacy `decide` exactly so a later
/// ingest ticket can swap the call without reshaping its inputs.
///
/// Order is fixed:
/// 1. non-`tool_result` rows, unknown connectors and non-Cass tools fall back
///    to the unchanged legacy judgment (R2/R3 still apply, now with marker 2
///    when they fire through this entry);
/// 2. a recognized Cass candidate that lacks R4 pairing, captured args or a
///    uniquely locatable result block is preserved as `unpaired_result` — it
///    must **not** fall back to the legacy R1 rule, whose bare-name alias
///    would delete an ordinary same-named tool's output;
/// 3. a strong identity is excluded whatever the output is (damaged output
///    is excluded with `src = None` and a bounded `parse_error`);
/// 4. a bare identity is excluded only after the whole result decodes as a
///    complete C04 envelope for that exact tool.
pub(crate) fn decide(
    msg: &NormalizedMessage,
    idx: usize,
    event: &RawEvent,
    ctx: &PairingContext,
    agent_slug: &str,
    paths_cfg: &ExcludedContextPaths,
) -> Outcome {
    if msg.role != "tool_result" || !cass_supported_agent(agent_slug) {
        return legacy_outcome(msg, idx, event, ctx, agent_slug, paths_cfg);
    }

    let Some(call) = ctx.paired_call_for(idx) else {
        return if unpaired_cass_candidate(msg, event) {
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult))
        } else {
            legacy_outcome(msg, idx, event, ctx, agent_slug, paths_cfg)
        };
    };

    let Some(kind) = classify_tool(&call.tool_name, agent_slug) else {
        return legacy_outcome(msg, idx, event, ctx, agent_slug, paths_cfg);
    };

    let Some(args) = call.args.as_ref() else {
        return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
    };
    let target_blocks = exclusion::tool_result_block_indices(event, call.tool_call_id.as_deref());
    if target_blocks.is_empty() {
        return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
    }

    let decision = Decision {
        reason: ExclusionReason::CassRecall,
        anchor: ExclusionAnchor {
            tool_call_id: call.tool_call_id.clone(),
            tool_name: Some(call.tool_name.clone()),
            paths: None,
            shell: None,
        },
        event_key: event.event_key.clone(),
        target_blocks,
    };

    match kind {
        CandidateKind::Strong(tool) => {
            let (src, parse_error) = match parse_result(tool, &msg.content, args) {
                Ok(src) => (Some(src), None),
                Err(reason) => (None, Some(reason.to_string())),
            };
            Outcome::Exclude(Exclusion { decision, src, parse_error })
        }
        CandidateKind::Bare(tool) => match recall_output::decode(&msg.content, tool) {
            Ok(value) => {
                let src = extract_source(tool, &value, args);
                Outcome::Exclude(Exclusion { decision, src: Some(src), parse_error: None })
            }
            Err(_) if looks_like_recall_wrapper(&msg.content) => {
                Outcome::Preserve(Some(UncoveredReason::InvalidRecallFormat))
            }
            Err(_) => Outcome::Preserve(Some(UncoveredReason::AmbiguousToolIdentity)),
        },
    }
}

/// The v2 apply entry: clear the body/copies/snippets with the unchanged R7
/// implementation, then stamp the v2 marker. Hash, byte count, anchor and
/// raw reference all come from the legacy implementation untouched.
///
/// `redaction_enabled` is stated by the caller (not read from the process
/// environment), matching `exclusion::apply_with_redaction`.
pub(crate) fn apply_with_redaction(
    msg: &mut NormalizedMessage,
    judged: &Exclusion,
    redactor: &mut MemoizingRedactor,
    blob: &str,
    idx: u32,
    field_map: ExtraFieldMap,
    redaction_enabled: bool,
) -> ExcludedMarker {
    let mut marker = exclusion::apply_with_redaction(
        msg,
        &judged.decision,
        redactor,
        blob,
        idx,
        field_map,
        redaction_enabled,
    );
    marker.rule_version = RULE_VERSION;
    marker.src = judged.src.clone();
    marker.parse_error = judged.parse_error.clone();
    marker
}

/// Parse a tool result into source metadata. Shared with ticket 06, so it
/// contains no attribution judgment and executes nothing.
///
/// Accepted inputs, in order:
/// 1. one complete C04 envelope (`recall_output::decode`);
/// 2. the legacy unwrapped `{"hits": ...}` / `{"error": ...}` shape for
///    search and expand, parsed by the unchanged legacy parser so historical
///    strong-identity samples keep their source semantics;
/// 3. any other legacy shape the C04 codec already accepts (sessions and
///    timeline envelopes, expand message arrays);
/// 4. a confirmed `{"error": ...}` response, which yields an empty source.
///
/// Every failure is the bounded static reason `invalid_recall_format`; the
/// original content is never echoed.
pub(crate) fn parse_result(
    tool: RecallTool,
    content: &str,
    args: &Value,
) -> Result<RecallSrc, &'static str> {
    if let Ok(value) = recall_output::decode(content, tool) {
        return Ok(extract_source(tool, &value, args));
    }

    let Ok(value) = serde_json::from_str::<Value>(content) else {
        return Err("invalid_recall_format");
    };

    if matches!(tool, RecallTool::Search | RecallTool::Expand)
        && (value.get("hits").is_some() || value.get("error").is_some())
    {
        return exclusion::parse_recall_hits(content).map_err(|_| "invalid_recall_format");
    }

    if tool.accepts(&value) {
        return Ok(extract_source(tool, &value, args));
    }

    if value.get("error").is_some() {
        return Ok(RecallSrc::default());
    }

    Err("invalid_recall_format")
}

/// Fixed per-tool source traversal. Only fields that exist, have the right
/// type and are non-empty contribute; nothing is defaulted to `local` and no
/// path is invented when the metadata is absent.
fn extract_source(tool: RecallTool, value: &Value, args: &Value) -> RecallSrc {
    let mut src = RecallSrc::default();
    match tool {
        RecallTool::Search => {
            for hit in array_items(value.get("hits")) {
                push_source_record(
                    &mut src,
                    hit,
                    "source_id",
                    "source_path",
                    hit.get("line_number").and_then(Value::as_u64),
                );
            }
        }
        RecallTool::Sessions => {
            for session in array_items(value.get("sessions")) {
                push_source_record(&mut src, session, "source_id", "path", None);
            }
        }
        RecallTool::Timeline => {
            let mut records = array_items(value.get("sessions"));
            if let Some(groups) = value.get("groups").and_then(Value::as_object) {
                for group in groups.values() {
                    records.extend(array_items(Some(group)));
                }
            }
            for record in records {
                push_source_record(&mut src, record, "source_id", "source_path", None);
            }
        }
        RecallTool::Expand => {
            let messages = array_items(Some(value));
            if messages.is_empty() {
                return src;
            }
            let targets: Vec<&Value> = messages
                .iter()
                .copied()
                .filter(|message| message.get("is_target").and_then(Value::as_bool) == Some(true))
                .collect();
            let line_number = if targets.len() == 1 {
                targets[0].get("line").and_then(Value::as_u64)
            } else {
                None
            };
            let (Some(source_id), Some(source_path)) =
                (non_empty_str(args, "source_id"), non_empty_str(args, "source_path"))
            else {
                return src;
            };
            push_hit(&mut src, source_id, source_path, line_number);
        }
    }
    src
}

fn array_items(value: Option<&Value>) -> Vec<&Value> {
    value.and_then(Value::as_array).map(|items| items.iter().collect()).unwrap_or_default()
}

fn non_empty_str(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).filter(|text| !text.is_empty()).map(str::to_string)
}

fn push_source_record(
    src: &mut RecallSrc,
    record: &Value,
    source_id_key: &str,
    path_key: &str,
    line_number: Option<u64>,
) {
    let (Some(source_id), Some(source_path)) = (
        non_empty_str(record, source_id_key),
        non_empty_str(record, path_key),
    ) else {
        return;
    };
    push_hit(src, source_id, source_path, line_number);
}

fn push_hit(src: &mut RecallSrc, source_id: String, source_path: String, line_number: Option<u64>) {
    if !src.sessions.iter().any(|path| path == &source_path) {
        src.sessions.push(source_path.clone());
    }
    src.hits.push(RecallHit { source_id, source_path, line_number });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::NormalizedSnippet;
    use crate::indexer::exclusion::{PairedTool, PairingCandidate, RawBlock, field_map_for};
    use sha2::{Digest, Sha256};
    use serde_json::json;

    fn paths_cfg() -> ExcludedContextPaths {
        ExcludedContextPaths::default()
    }

    fn msg(role: &str, content: &str) -> NormalizedMessage {
        NormalizedMessage {
            idx: 0,
            role: role.to_string(),
            author: None,
            created_at: None,
            content: content.to_string(),
            extra: json!({}),
            snippets: Vec::new(),
            invocations: Vec::new(),
        }
    }

    fn text_block(index: u32) -> RawBlock {
        RawBlock { index, kind: BlockKind::Text, tool_use_id: None, tool_name: None, args: None }
    }

    fn tool_result_block(index: u32, id: Option<&str>) -> RawBlock {
        RawBlock { index, kind: BlockKind::ToolResult, tool_use_id: id.map(str::to_string), tool_name: None, args: None }
    }

    fn named_tool_result_block(index: u32, id: Option<&str>, name: &str) -> RawBlock {
        RawBlock {
            index,
            kind: BlockKind::ToolResult,
            tool_use_id: id.map(str::to_string),
            tool_name: Some(name.to_string()),
            args: None,
        }
    }

    /// One paired call + one result block, the shape R4 proves.
    fn fixture(tool_name: &str, args: Value, content: &str) -> (NormalizedMessage, RawEvent, PairingContext) {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = PairingContext::build(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: tool_name.to_string(),
                args: Some(args),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        (msg("tool_result", content), event, ctx)
    }

    fn sha256_hex(text: &str) -> String {
        hex::encode(Sha256::digest(text.as_bytes()))
    }

    fn search_value() -> Value {
        json!({"hits": [
            {"source_id": "local", "source_path": "/srv/sessions/a.jsonl", "line_number": 7, "content": "hit"},
            {"source_id": "remote", "source_path": "/srv/sessions/b.jsonl", "content": "hit two"},
        ]})
    }

    fn search_src() -> RecallSrc {
        RecallSrc {
            sessions: vec!["/srv/sessions/a.jsonl".into(), "/srv/sessions/b.jsonl".into()],
            hits: vec![
                RecallHit {
                    source_id: "local".into(),
                    source_path: "/srv/sessions/a.jsonl".into(),
                    line_number: Some(7),
                },
                RecallHit {
                    source_id: "remote".into(),
                    source_path: "/srv/sessions/b.jsonl".into(),
                    line_number: None,
                },
            ],
        }
    }

    // -- AC1: strong identity, four tools, real apply -----------------------

    #[test]
    fn mcp_v2_mcp_strong_four_tools_exclude_and_apply_marker2() {
        let expand_args = json!({"source_id": "local", "source_path": "/srv/sessions/expand.jsonl"});
        let cases = vec![
            (
                RecallTool::Search,
                "mcp__cass-mcp__cass_search",
                json!({}),
                search_value(),
                search_src(),
            ),
            (
                RecallTool::Expand,
                "mcp__cass-mcp__cass_expand",
                expand_args.clone(),
                json!([
                    {"line": 1, "role": "user", "is_target": false, "content": "before"},
                    {"line": 3, "role": "assistant", "is_target": true, "content": "target"},
                ]),
                RecallSrc {
                    sessions: vec!["/srv/sessions/expand.jsonl".into()],
                    hits: vec![RecallHit {
                        source_id: "local".into(),
                        source_path: "/srv/sessions/expand.jsonl".into(),
                        line_number: Some(3),
                    }],
                },
            ),
            (
                RecallTool::Sessions,
                "mcp__cass-mcp__cass_sessions",
                json!({}),
                json!({"sessions": [{"source_id": "local", "path": "/srv/sessions/list.jsonl"}]}),
                RecallSrc {
                    sessions: vec!["/srv/sessions/list.jsonl".into()],
                    hits: vec![RecallHit {
                        source_id: "local".into(),
                        source_path: "/srv/sessions/list.jsonl".into(),
                        line_number: None,
                    }],
                },
            ),
            (
                RecallTool::Timeline,
                "mcp__cass-mcp__cass_timeline",
                json!({}),
                json!({"range": {"start": 1, "end": 2}, "total_sessions": 1,
                       "groups": {"hour": [{"source_id": "local", "source_path": "/srv/sessions/t.jsonl"}]}}),
                RecallSrc {
                    sessions: vec!["/srv/sessions/t.jsonl".into()],
                    hits: vec![RecallHit {
                        source_id: "local".into(),
                        source_path: "/srv/sessions/t.jsonl".into(),
                        line_number: None,
                    }],
                },
            ),
        ];

        for (tool, tool_name, args, value, expected_src) in cases {
            let wrapper = recall_output::encode(tool, &value).expect("fixture must encode");
            let (mut message, event, ctx) = fixture(tool_name, args, &wrapper);
            message.extra = json!({
                "message": {"content": [{"type": "tool_result", "text": wrapper}]},
                "toolUseResult": wrapper,
            });
            message.snippets = vec![NormalizedSnippet {
                file_path: Some(std::path::PathBuf::from("/srv/a.rs")),
                start_line: Some(1),
                end_line: Some(2),
                language: Some("rust".into()),
                snippet_text: Some("fn copied() {}".into()),
            }];

            let Outcome::Exclude(judged) =
                decide(&message, 1, &event, &ctx, "claude_code", &paths_cfg())
            else {
                panic!("{tool:?} strong identity must be excluded");
            };
            assert_eq!(judged.decision.reason, ExclusionReason::CassRecall);
            assert_eq!(judged.decision.target_blocks, vec![0]);
            assert_eq!(judged.decision.anchor.tool_name.as_deref(), Some(tool_name));
            assert_eq!(judged.src.as_ref(), Some(&expected_src), "{tool:?} source");
            assert!(judged.parse_error.is_none());

            let original = message.content.clone();
            let mut redactor = MemoizingRedactor::new();
            let marker = apply_with_redaction(
                &mut message,
                &judged,
                &mut redactor,
                "blobs/blake3/ab/abcd.raw",
                7,
                field_map_for("claude_code"),
                false,
            );

            assert_eq!(marker.rule_version, 2);
            assert_eq!(message.content, "", "body must be cleared");
            assert_eq!(marker.bytes, original.len() as u64);
            assert_eq!(marker.sha256, sha256_hex(&original));
            assert_eq!(marker.src, Some(expected_src), "{tool:?} marker source");
            assert_eq!(marker.parse_error, None);
            assert_eq!(marker.anchor, judged.decision.anchor);
            assert_eq!(marker.raw.blob, "blobs/blake3/ab/abcd.raw");
            assert_eq!(marker.raw.idx, 7);
            assert_eq!(marker.raw.event_key, "ek1");
            assert_eq!(marker.raw.blocks, vec![0]);
            assert_eq!(message.extra["message"]["content"][0]["text"]["redacted"], json!(true));
            assert_eq!(message.extra["toolUseResult"]["redacted"], json!(true));
            assert_eq!(message.snippets[0].snippet_text, Some(String::new()));

            let mut sibling = msg("user", "sibling prose stays");
            sibling.extra = json!({"message": {"content": [{"type": "tool_result", "text": wrapper}]}});
            exclusion::apply_sibling(&mut sibling, &marker, field_map_for("claude_code"));
            assert_eq!(sibling.content, "sibling prose stays", "sibling content is not cleared");
            assert_eq!(sibling.extra["message"]["content"][0]["text"]["redacted"], json!(true));
        }
    }

    #[test]
    fn mcp_v2_mcp_apply_preserves_raw_inputs_and_mirror_bytes() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let (mut message, event, ctx) =
            fixture("mcp__cass-mcp__cass_search", json!({}), &wrapper);
        let Outcome::Exclude(judged) =
            decide(&message, 1, &event, &ctx, "claude_code", &paths_cfg())
        else {
            panic!("strong identity must be excluded");
        };

        let dir = tempfile::tempdir().unwrap();
        let blob = dir.path().join("mirror.raw");
        std::fs::write(&blob, b"raw mirror bytes are never rewritten").unwrap();
        let before = std::fs::read(&blob).unwrap();
        let blob_label = blob.to_string_lossy().to_string();

        let marker = apply_with_redaction(
            &mut message,
            &judged,
            &mut MemoizingRedactor::new(),
            &blob_label,
            3,
            field_map_for("claude_code"),
            false,
        );

        assert_eq!(marker.raw.blob, blob_label);
        assert_eq!(marker.raw.idx, 3);
        assert_eq!(marker.raw.event_key, "ek1");
        assert_eq!(marker.raw.blocks, vec![0]);
        assert_eq!(std::fs::read(&blob).unwrap(), before);
    }

    #[test]
    fn mcp_v2_mcp_payload_closing_tag_and_unicode_stay_data() {
        let value = json!({"hits": [{
            "source_id": "local",
            "source_path": "/srv/sessions/中文.jsonl",
            "line_number": 9,
            "content": "a & <b> </cass_recall> 中文"
        }]});
        let wrapper = recall_output::encode(RecallTool::Search, &value).unwrap();

        let (message, event, ctx) = fixture("mcp__cass-mcp__cass_search", json!({}), &wrapper);
        let Outcome::Exclude(judged) =
            decide(&message, 1, &event, &ctx, "claude_code", &paths_cfg())
        else {
            panic!("strong identity must be excluded");
        };
        let src = judged.src.expect("source must parse");
        assert_eq!(src.sessions, vec!["/srv/sessions/中文.jsonl"]);
        assert_eq!(src.hits[0].line_number, Some(9));

        let (bare_message, bare_event, bare_ctx) = fixture("cass_search", json!({}), &wrapper);
        let Outcome::Exclude(bare_judged) =
            decide(&bare_message, 1, &bare_event, &bare_ctx, "codex", &paths_cfg())
        else {
            panic!("a complete wrapper proves the bare name's identity");
        };
        assert_eq!(bare_judged.src.unwrap().sessions, vec!["/srv/sessions/中文.jsonl"]);
    }

    // -- AC1: source extraction per tool ------------------------------------

    #[test]
    fn mcp_v2_mcp_source_fields_are_per_tool_and_never_invented() {
        // sessions reads `path`; timeline reads `source_path`. The same value
        // under the other key must not be picked up.
        let (sessions_msg, sessions_event, sessions_ctx) = fixture(
            "mcp__cass-mcp__cass_sessions",
            json!({}),
            &recall_output::encode(
                RecallTool::Sessions,
                &json!({"sessions": [
                    {"source_id": "local", "path": "/srv/sessions/one.jsonl", "source_path": "/wrong/a.jsonl"},
                    {"source_id": "local", "source_path": "/wrong/b.jsonl"}
                ]}),
            )
            .unwrap(),
        );
        let Outcome::Exclude(sessions_judged) =
            decide(&sessions_msg, 1, &sessions_event, &sessions_ctx, "claude_code", &paths_cfg())
        else {
            panic!("sessions must be excluded");
        };
        let sessions_src = sessions_judged.src.unwrap();
        assert_eq!(sessions_src.sessions, vec!["/srv/sessions/one.jsonl"]);
        assert_eq!(sessions_src.hits.len(), 1);

        let (timeline_msg, timeline_event, timeline_ctx) = fixture(
            "mcp__cass-mcp__cass_timeline",
            json!({}),
            &recall_output::encode(
                RecallTool::Timeline,
                &json!({"range": {"start": 1, "end": 2}, "total_sessions": 2,
                        "groups": {
                            "hour": [{"source_id": "a", "source_path": "/srv/sessions/t1.jsonl"},
                                     {"source_id": "b", "source_path": "/srv/sessions/t2.jsonl"}],
                            "day": [{"source_id": "a", "source_path": "/srv/sessions/t1.jsonl"}]
                        }}),
            )
            .unwrap(),
        );
        let Outcome::Exclude(timeline_judged) = decide(
            &timeline_msg,
            1,
            &timeline_event,
            &timeline_ctx,
            "claude_code",
            &paths_cfg(),
        ) else {
            panic!("timeline must be excluded");
        };
        let timeline_src = timeline_judged.src.unwrap();
        assert_eq!(
            timeline_src.sessions,
            vec!["/srv/sessions/t1.jsonl", "/srv/sessions/t2.jsonl"],
            "groups arrays are traversed and paths are deduplicated"
        );
        assert_eq!(timeline_src.hits.len(), 3, "each actual record is kept");

        // Empty expand result: no fake source, but still no parse error.
        let (empty_msg, empty_event, empty_ctx) =
            fixture("mcp__cass-mcp__cass_expand", json!({"source_id": "local"}), "[]");
        let Outcome::Exclude(empty_judged) =
            decide(&empty_msg, 1, &empty_event, &empty_ctx, "claude_code", &paths_cfg())
        else {
            panic!("strong identity with empty output is still excluded");
        };
        assert_eq!(empty_judged.src, Some(RecallSrc::default()));
        assert!(empty_judged.parse_error.is_none());

        // Confirmed error response: empty source, no parse error.
        let (error_msg, error_event, error_ctx) = fixture(
            "mcp__cass-mcp__cass_search",
            json!({}),
            r#"{"error": "cass_exit", "code": 127, "stderr": "not found"}"#,
        );
        let Outcome::Exclude(error_judged) =
            decide(&error_msg, 1, &error_event, &error_ctx, "claude_code", &paths_cfg())
        else {
            panic!("strong identity error response is still excluded");
        };
        assert_eq!(error_judged.src, Some(RecallSrc::default()));
        assert!(error_judged.parse_error.is_none());
    }

    #[test]
    fn mcp_v2_mcp_expand_source_comes_from_arguments_and_unique_target_line() {
        let args = json!({"source_id": "local", "source_path": "/srv/sessions/e.jsonl"});
        let (message, event, ctx) = fixture(
            "mcp__cass-mcp__cass_expand",
            args,
            &recall_output::encode(
                RecallTool::Expand,
                &json!([
                    {"line": 4, "is_target": true, "content": "one"},
                    {"line": 5, "is_target": false, "content": "two"}
                ]),
            )
            .unwrap(),
        );
        let Outcome::Exclude(judged) =
            decide(&message, 1, &event, &ctx, "claude_code", &paths_cfg())
        else {
            panic!("expand must be excluded");
        };
        assert_eq!(
            judged.src.unwrap(),
            RecallSrc {
                sessions: vec!["/srv/sessions/e.jsonl".into()],
                hits: vec![RecallHit {
                    source_id: "local".into(),
                    source_path: "/srv/sessions/e.jsonl".into(),
                    line_number: Some(4),
                }],
            }
        );

        // Two targets: ambiguous, so no line number — but the source path is
        // still real and still kept.
        let (two_msg, two_event, two_ctx) = fixture(
            "mcp__cass-mcp__cass_expand",
            json!({"source_id": "local", "source_path": "/srv/sessions/e.jsonl"}),
            &recall_output::encode(
                RecallTool::Expand,
                &json!([
                    {"line": 4, "is_target": true, "content": "one"},
                    {"line": 5, "is_target": true, "content": "two"}
                ]),
            )
            .unwrap(),
        );
        let Outcome::Exclude(two_judged) =
            decide(&two_msg, 1, &two_event, &two_ctx, "claude_code", &paths_cfg())
        else {
            panic!("expand must be excluded");
        };
        assert_eq!(two_judged.src.unwrap().hits[0].line_number, None);
    }

    // -- AC2: bare names and damaged wrappers are preserved ----------------

    #[test]
    fn mcp_v2_mcp_bare_plain_text_and_legacy_json_are_ambiguous_not_deleted() {
        for content in [
            "ordinary tool output that merely happens to come from cass_search",
            r#"{"hits": [{"source_id": "local", "source_path": "/srv/x.jsonl"}]}"#,
        ] {
            let (message, event, ctx) = fixture("cass_search", json!({}), content);
            assert_eq!(
                decide(&message, 1, &event, &ctx, "codex", &paths_cfg()),
                Outcome::Preserve(Some(UncoveredReason::AmbiguousToolIdentity)),
                "bare name without a wrapper must be preserved"
            );
            assert_eq!(message.content, content);

            let (claude_message, claude_event, claude_ctx) =
                fixture("cass_search", json!({}), content);
            assert_eq!(
                decide(&claude_message, 1, &claude_event, &claude_ctx, "claude_code", &paths_cfg()),
                Outcome::Preserve(Some(UncoveredReason::AmbiguousToolIdentity)),
                "the same rule holds for claude_code bare names"
            );
        }
    }

    #[test]
    fn mcp_v2_mcp_bare_damaged_wrappers_are_preserved_with_reason() {
        let cases = [
            // Unsafe version.
            r#"<cass_recall version="2" tool="cass_search">{"hits":[]}</cass_recall>"#.to_string(),
            // Wrong tool for this call.
            recall_output::encode(RecallTool::Expand, &json!([{"line": 1, "is_target": true}]))
                .unwrap(),
            // Complete wrapper with extra application text.
            format!(
                "prefix {}",
                recall_output::encode(RecallTool::Search, &json!({"hits": []})).unwrap()
            ),
            // Truncated wrapper.
            r#"<cass_recall version="1" tool="cass_search">{"hits":[]"#.to_string(),
        ];
        for content in cases {
            let (message, event, ctx) = fixture("cass_search", json!({}), &content);
            assert_eq!(
                decide(&message, 1, &event, &ctx, "codex", &paths_cfg()),
                Outcome::Preserve(Some(UncoveredReason::InvalidRecallFormat)),
                "wrapper-looking but invalid content must be preserved: {content}"
            );
            assert_eq!(message.content, content);
        }
    }

    #[test]
    fn mcp_v2_mcp_bare_complete_wrapper_is_excluded_with_source() {
        let cases = [
            (
                RecallTool::Search,
                "cass_search",
                json!({}),
                search_value(),
            ),
            (
                RecallTool::Expand,
                "cass_expand",
                json!({"source_id": "local", "source_path": "/srv/e.jsonl"}),
                json!([{"line": 2, "is_target": true, "content": "body"}]),
            ),
            (
                RecallTool::Sessions,
                "cass_sessions",
                json!({}),
                json!({"sessions": [{"source_id": "local", "path": "/srv/s.jsonl"}]}),
            ),
            (
                RecallTool::Timeline,
                "cass_timeline",
                json!({}),
                json!({"range": {}, "total_sessions": 1,
                       "sessions": [{"source_id": "local", "source_path": "/srv/t.jsonl"}]}),
            ),
        ];
        for (tool, tool_name, args, value) in cases {
            let wrapper = recall_output::encode(tool, &value).unwrap();
            let (mut message, event, ctx) = fixture(tool_name, args, &wrapper);
            let Outcome::Exclude(judged) =
                decide(&message, 1, &event, &ctx, "codex", &paths_cfg())
            else {
                panic!("{tool:?}: a complete wrapper proves bare-name identity");
            };
            assert!(
                judged.src.as_ref().is_some_and(|src| !src.sessions.is_empty()),
                "{tool:?}: source must be extracted"
            );
            let marker = apply_with_redaction(
                &mut message,
                &judged,
                &mut MemoizingRedactor::new(),
                "blob",
                0,
                field_map_for("codex"),
                false,
            );
            assert_eq!(marker.rule_version, 2);
            assert_eq!(message.content, "");
        }
    }

    #[test]
    fn mcp_v2_mcp_foreign_namespace_unknown_agent_and_discussion_are_not_candidates() {
        let (foreign, foreign_event, foreign_ctx) =
            fixture("mcp__other-mcp__cass_search", json!({}), "plain");
        assert_eq!(
            decide(&foreign, 1, &foreign_event, &foreign_ctx, "claude_code", &paths_cfg()),
            Outcome::Preserve(None),
            "a shared suffix under another server is not Cass identity"
        );

        let (unknown, unknown_event, unknown_ctx) = fixture("cass_search", json!({}), "plain");
        assert_eq!(
            decide(&unknown, 1, &unknown_event, &unknown_ctx, "openclaw", &paths_cfg()),
            Outcome::Preserve(None),
            "unsupported connectors are not judged"
        );

        let wrapper = recall_output::encode(RecallTool::Search, &json!({"hits": []})).unwrap();
        let discussion = msg("user", &format!("here is what a wrapper looks like:\n{wrapper}"));
        assert_eq!(
            decide(&discussion, 0, &RawEvent { event_key: "ek1".into(), blocks: vec![text_block(0)] }, &PairingContext::default(), "codex", &paths_cfg()),
            Outcome::Preserve(None),
            "ordinary prose that quotes a wrapper is not a recall result"
        );

        let (ordinary_result, ordinary_event, _) = fixture("cass_search", json!({}), "plain");
        assert_eq!(
            decide(
                &ordinary_result,
                1,
                &ordinary_event,
                &PairingContext::default(),
                "codex",
                &paths_cfg()
            ),
            Outcome::Preserve(None),
            "an unpaired tool_result with no Cass evidence is not counted"
        );
    }

    #[test]
    fn mcp_v2_mcp_unpaired_cass_evidence_counts_unpaired_result() {
        let wrapper = recall_output::encode(RecallTool::Search, &json!({"hits": []})).unwrap();
        let (message, event, _) = fixture("cass_search", json!({}), &wrapper);
        assert_eq!(
            decide(&message, 1, &event, &PairingContext::default(), "codex", &paths_cfg()),
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult)),
            "no R4 pairing must not fall back to legacy R1"
        );

        let named_event = RawEvent {
            event_key: "ek1".into(),
            blocks: vec![named_tool_result_block(0, Some("t1"), "cass_search")],
        };
        assert_eq!(
            decide(&message, 1, &named_event, &PairingContext::default(), "codex", &paths_cfg()),
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult))
        );
    }

    #[test]
    fn mcp_v2_mcp_r4_counterexamples_preserve_instead_of_deleting() {
        // Missing captured args.
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let no_args = PairingContext::build(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "mcp__cass-mcp__cass_search".into(),
                args: None,
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let message = msg("tool_result", "body");
        assert_eq!(
            decide(&message, 1, &event, &no_args, "claude_code", &paths_cfg()),
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult))
        );

        // Call id present but the result block carries a different id.
        let wrong_id_event =
            RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t2"))] };
        let (wrong_message, _, wrong_ctx) =
            fixture("mcp__cass-mcp__cass_search", json!({}), "body");
        assert_eq!(
            decide(&wrong_message, 1, &wrong_id_event, &wrong_ctx, "claude_code", &paths_cfg()),
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult))
        );

        // Two id-less result blocks: ambiguous target block.
        let ambiguous_event = RawEvent {
            event_key: "ek1".into(),
            blocks: vec![tool_result_block(0, None), tool_result_block(1, None)],
        };
        let ambiguous_ctx = PairingContext::build(&[
            PairingCandidate::TurnBoundary,
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: None,
                tool_name: "mcp__cass-mcp__cass_search".into(),
                args: Some(json!({})),
            }),
            PairingCandidate::ToolResult { tool_call_id: None },
        ]);
        assert_eq!(
            decide(&wrong_message, 2, &ambiguous_event, &ambiguous_ctx, "claude_code", &paths_cfg()),
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult))
        );
    }

    // -- AC1: strong identity damaged output -------------------------------

    #[test]
    fn mcp_v2_mcp_strong_damaged_output_excluded_with_bounded_parse_error() {
        for content in [
            "not json and definitely not a wrapper",
            "<cass_recall version=\"2\" tool=\"cass_search\">{\"hits\":[]}</cass_recall>",
        ] {
            let (message, event, ctx) =
                fixture("mcp__cass-mcp__cass_search", json!({}), content);
            let Outcome::Exclude(judged) =
                decide(&message, 1, &event, &ctx, "claude_code", &paths_cfg())
            else {
                panic!("strong identity must be excluded even when damaged");
            };
            assert!(judged.src.is_none());
            let parse_error = judged.parse_error.expect("damaged strong output records an error");
            assert_eq!(parse_error, "invalid_recall_format");
            assert!(!parse_error.contains("not json"), "the reason never echoes the body");
        }
    }

    // -- AC3: v1 is unchanged ----------------------------------------------

    #[test]
    fn mcp_v2_mcp_v1_strong_sample_keeps_rule_and_source_semantics() {
        let content = r#"{"hits": [{"source_id": "local", "source_path": "/srv/sessions/a.jsonl", "line_number": 214}]}"#;
        let (message, event, ctx) =
            fixture("mcp__cass-mcp__cass_search", json!({}), content);

        let v1 = exclusion::decide(&message, 1, &event, &ctx, "claude_code", &paths_cfg())
            .expect("v1 strong identity still matches");
        assert_eq!(v1.reason, ExclusionReason::CassRecall);

        let mut v1_message = message.clone();
        let v1_marker = exclusion::apply_with_redaction(
            &mut v1_message,
            &v1,
            &mut MemoizingRedactor::new(),
            "blob",
            0,
            field_map_for("claude_code"),
            false,
        );
        assert_eq!(v1_marker.rule_version, 1, "the legacy entry stays at marker 1");
        assert_eq!(v1_message.content, "");
        let expected_src = RecallSrc {
            sessions: vec!["/srv/sessions/a.jsonl".into()],
            hits: vec![RecallHit {
                source_id: "local".into(),
                source_path: "/srv/sessions/a.jsonl".into(),
                line_number: Some(214),
            }],
        };
        assert_eq!(v1_marker.src, Some(expected_src.clone()));

        let Outcome::Exclude(judged) =
            decide(&message, 1, &event, &ctx, "claude_code", &paths_cfg())
        else {
            panic!("v2 also excludes the same strong sample");
        };
        let mut v2_message = message.clone();
        let v2_marker = apply_with_redaction(
            &mut v2_message,
            &judged,
            &mut MemoizingRedactor::new(),
            "blob",
            0,
            field_map_for("claude_code"),
            false,
        );
        assert_eq!(v2_marker.rule_version, 2);
        assert_eq!(v2_marker.src, Some(expected_src), "historical strong source semantics survive");
    }

    #[test]
    fn mcp_v2_mcp_v1_bare_name_sample_stays_legacy_while_v2_preserves_it() {
        let content = "ordinary output from a tool that happens to be named cass_search";
        let (message, event, ctx) = fixture("cass_search", json!({}), content);

        let v1 = exclusion::decide(&message, 1, &event, &ctx, "codex", &paths_cfg())
            .expect("v1's registered bare-name rule still matches (unchanged)");
        assert_eq!(v1.reason, ExclusionReason::CassRecall);
        let mut v1_message = message.clone();
        let v1_marker = exclusion::apply_with_redaction(
            &mut v1_message,
            &v1,
            &mut MemoizingRedactor::new(),
            "blob",
            0,
            field_map_for("codex"),
            false,
        );
        assert_eq!(v1_marker.rule_version, 1);
        assert_eq!(v1_message.content, "", "v1 keeps its historical behavior");

        assert_eq!(
            decide(&message, 1, &event, &ctx, "codex", &paths_cfg()),
            Outcome::Preserve(Some(UncoveredReason::AmbiguousToolIdentity)),
            "v2 no longer deletes a bare name without a wrapper"
        );
        assert_eq!(message.content, content);
    }

    #[test]
    fn mcp_v2_mcp_legacy_rules_through_v2_use_marker2() {
        let read_event = RawEvent { event_key: "ek2".into(), blocks: vec![tool_result_block(0, Some("r1"))] };
        let read_ctx = PairingContext::build(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("r1".into()),
                tool_name: "Read".into(),
                args: Some(json!({"file_path": "/srv/cc-workspace/MEMORY.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("r1".into()) },
        ]);
        let mut read_message = msg("tool_result", "file body");
        let Outcome::Exclude(read_judged) =
            decide(&read_message, 1, &read_event, &read_ctx, "claude_code", &paths_cfg())
        else {
            panic!("R2 context-file read still fires through the v2 entry");
        };
        assert_eq!(read_judged.decision.reason, ExclusionReason::ContextFileRead);
        assert!(read_judged.src.is_none());
        let marker = apply_with_redaction(
            &mut read_message,
            &read_judged,
            &mut MemoizingRedactor::new(),
            "blob",
            0,
            field_map_for("claude_code"),
            false,
        );
        assert_eq!(marker.rule_version, 2);
        assert_eq!(read_message.content, "");

        let shell_event = RawEvent { event_key: "ek3".into(), blocks: vec![text_block(0)] };
        let mut shell_message = msg(
            "user",
            "<environment_context>\n<cwd>/srv</cwd>\n</environment_context>",
        );
        let Outcome::Exclude(shell_judged) = decide(
            &shell_message,
            0,
            &shell_event,
            &PairingContext::default(),
            "codex",
            &paths_cfg(),
        ) else {
            panic!("R3 host-shell still fires through the v2 entry");
        };
        assert_eq!(shell_judged.decision.reason, ExclusionReason::CodexHostShell);
        let marker = apply_with_redaction(
            &mut shell_message,
            &shell_judged,
            &mut MemoizingRedactor::new(),
            "blob",
            0,
            field_map_for("codex"),
            false,
        );
        assert_eq!(marker.rule_version, 2);
        assert_eq!(shell_message.content, "");
    }

    // -- Downstream (06) interface -----------------------------------------

    #[test]
    fn mcp_v2_mcp_parse_result_is_bounded_and_source_only() {
        for (tool, value, args) in [
            (RecallTool::Search, search_value(), json!({})),
            (
                RecallTool::Expand,
                json!([{"line": 2, "is_target": true}]),
                json!({"source_id": "local", "source_path": "/srv/e.jsonl"}),
            ),
            (
                RecallTool::Sessions,
                json!({"sessions": [{"source_id": "local", "path": "/srv/s.jsonl"}]}),
                json!({}),
            ),
            (
                RecallTool::Timeline,
                json!({"range": {}, "total_sessions": 1,
                       "sessions": [{"source_id": "local", "source_path": "/srv/t.jsonl"}]}),
                json!({}),
            ),
        ] {
            let wrapper = recall_output::encode(tool, &value).unwrap();
            let src = parse_result(tool, &wrapper, &args).expect("valid wrapper parses");
            assert!(!src.sessions.is_empty(), "{tool:?} must extract its source");
        }

        // Historical unwrapped shapes stay readable: search/expand `hits`
        // reuse the legacy parser, sessions/timeline reuse the C04 shape
        // check. These are the samples the legacy strong-identity path has
        // always produced.
        assert_eq!(
            parse_result(
                RecallTool::Expand,
                r#"{"hits": [{"source_id": "local", "source_path": "/srv/legacy-expand.jsonl", "line_number": 1}]}"#,
                &json!({})
            )
            .unwrap()
            .sessions,
            vec!["/srv/legacy-expand.jsonl"]
        );
        assert_eq!(
            parse_result(
                RecallTool::Sessions,
                r#"{"sessions": [{"source_id": "local", "path": "/srv/legacy-sessions.jsonl"}]}"#,
                &json!({})
            )
            .unwrap()
            .sessions,
            vec!["/srv/legacy-sessions.jsonl"]
        );
        assert_eq!(
            parse_result(
                RecallTool::Timeline,
                r#"{"range": {}, "total_sessions": 1, "sessions": [{"source_id": "local", "source_path": "/srv/legacy-timeline.jsonl"}]}"#,
                &json!({})
            )
            .unwrap()
            .sessions,
            vec!["/srv/legacy-timeline.jsonl"]
        );

        assert_eq!(
            parse_result(RecallTool::Search, r#"{"error": "cass_exit"}"#, &json!({})),
            Ok(RecallSrc::default())
        );
        assert_eq!(
            parse_result(RecallTool::Search, "secret body", &json!({})),
            Err("invalid_recall_format")
        );
        assert_eq!(
            parse_result(RecallTool::Search, r#"{"query": "x"}"#, &json!({})),
            Err("invalid_recall_format")
        );
    }

    #[test]
    fn mcp_v2_mcp_uncovered_reason_strings_are_frozen() {
        assert_eq!(UncoveredReason::UnsupportedShell.as_str(), "unsupported_shell");
        assert_eq!(UncoveredReason::UnpairedResult.as_str(), "unpaired_result");
        assert_eq!(
            UncoveredReason::AmbiguousToolIdentity.as_str(),
            "ambiguous_tool_identity"
        );
        assert_eq!(UncoveredReason::InvalidRecallFormat.as_str(), "invalid_recall_format");
    }
}
