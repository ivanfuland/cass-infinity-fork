//! Ticket 05 / Task10: v2 MCP recall judgment, source extraction and the
//! source-aware apply entry.
//!
//! `source_ingest` applies this module as the default rule epoch (2) through
//! [`decide_for_record`], [`apply_with_redaction`] and [`parse_result`]. The
//! legacy `exclusion::decide` / `exclusion::apply_with_redaction` path, its
//! alias table and its `rule_version = 1` markers remain unchanged for the v1
//! epoch and its replay materials.
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

use crate::connectors::{NormalizedConversation, NormalizedMessage};
use crate::indexer::exclusion::{
    self, BlockKind, Decision, ExcludedMarker, ExclusionAnchor, ExclusionReason, ExtraFieldMap,
    PairedTool, PairingContext, RawEvent, RecallHit, RecallSrc,
};
use crate::indexer::redact_secrets::MemoizingRedactor;
use crate::recall_output::{self, RecallTool};
use crate::sources::config::ExcludedContextPaths;

/// C05 fixes the v2 rule epoch's marker version at 2.
const RULE_VERSION: u32 = 2;

/// Why a recognized recall candidate was not excluded, or why a bare-name
/// result was preserved. The strings are the frozen diagnostic reasons from
/// C1/05; [`UnsupportedShell`](Self::UnsupportedShell) belongs to ticket 06's
/// limited direct-CLI syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UncoveredReason {
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

// ============================================================================
// Ticket 06: limited direct-CLI syntax (C06 + C3).
//
// A direct `Bash`/`exec_command` invocation is only recognized when the whole
// command is a single simple command whose head is Cass and whose arguments
// fit the frozen read-only table below. Nothing here executes a shell, reads
// a file or an environment variable, resolves a path or consults a model.
// ============================================================================

/// One recognized direct-CLI read invocation. `args` exists only so
/// [`parse_result`] can extract expand's source from the actual PATH and
/// `--source`; the other tools carry an empty object.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CliInvocation {
    pub(crate) tool: RecallTool,
    pub(crate) args: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliValueKind {
    Text,
    /// Decimal non-negative literal; no range re-interpretation.
    Number,
    /// 64 hex digits (C2's content digest form).
    Sha256,
}

#[derive(Debug, Clone, Copy)]
enum CliOption<'a> {
    Value { canonical: &'a str, kind: CliValueKind, repeatable: bool },
    Flag { canonical: &'a str },
}

/// The frozen per-tool option table. Names outside these arms are syntax
/// beyond the subset and preserve the result (`unsupported_shell`).
fn cli_option<'a>(tool: RecallTool, name: &'a str) -> Option<CliOption<'a>> {
    use CliOption::{Flag, Value};
    use CliValueKind::{Number, Sha256, Text};
    match tool {
        RecallTool::Search => match name {
            "agent" => Some(Value { canonical: name, kind: Text, repeatable: true }),
            "workspace" => Some(Value { canonical: name, kind: Text, repeatable: true }),
            "source" | "since" | "until" | "mode" | "embedding-profile" | "rerank-profile"
            | "api-config" | "cursor" | "vector-search-mode" | "fields" | "request-id" => {
                Some(Value { canonical: name, kind: Text, repeatable: false })
            }
            "rrf-limit" | "rerank-limit" | "offset" | "max-content-length" | "max-tokens" => {
                Some(Value { canonical: name, kind: Number, repeatable: false })
            }
            "rerank" | "no-model-fallback" | "robot-meta" | "recall" => {
                Some(Flag { canonical: name })
            }
            "json" | "robot" => Some(Flag { canonical: "json" }),
            _ => None,
        },
        RecallTool::Expand => match name {
            "source" => Some(Value { canonical: "source", kind: Text, repeatable: false }),
            "source-id" | "source_id" => {
                Some(Value { canonical: "source", kind: Text, repeatable: false })
            }
            "line" => Some(Value { canonical: "line", kind: Number, repeatable: false }),
            "line-number" | "line_number" => {
                Some(Value { canonical: "line", kind: Number, repeatable: false })
            }
            "message-id" => {
                Some(Value { canonical: "message-id", kind: Number, repeatable: false })
            }
            "message_id" => {
                Some(Value { canonical: "message-id", kind: Number, repeatable: false })
            }
            "expected-content-sha256" => {
                Some(Value { canonical: "expected-content-sha256", kind: Sha256, repeatable: false })
            }
            "expected_content_sha256" => {
                Some(Value { canonical: "expected-content-sha256", kind: Sha256, repeatable: false })
            }
            "context" => Some(Value { canonical: "context", kind: Number, repeatable: false }),
            "json" | "robot" => Some(Flag { canonical: "json" }),
            "recall" => Some(Flag { canonical: "recall" }),
            _ => None,
        },
        RecallTool::Sessions => match name {
            "workspace" | "since" => {
                Some(Value { canonical: name, kind: Text, repeatable: false })
            }
            "limit" => Some(Value { canonical: "limit", kind: Number, repeatable: false }),
            "json" | "robot" => Some(Flag { canonical: "json" }),
            "recall" => Some(Flag { canonical: "recall" }),
            _ => None,
        },
        RecallTool::Timeline => match name {
            "since" | "until" | "source" | "group-by" => {
                Some(Value { canonical: name, kind: Text, repeatable: false })
            }
            "agent" => Some(Value { canonical: "agent", kind: Text, repeatable: true }),
            "json" | "robot" => Some(Flag { canonical: "json" }),
            "recall" => Some(Flag { canonical: "recall" }),
            _ => None,
        },
    }
}

/// The relative-time filters of search, sessions and timeline document
/// `-7d`/`-24h` style values, and the current CLI admits them with
/// `allow_hyphen_values`; both the space and the equals form stay literal.
fn cli_option_accepts_hyphen_value(tool: RecallTool, canonical: &str) -> bool {
    matches!(
        (tool, canonical),
        (
            RecallTool::Search | RecallTool::Sessions | RecallTool::Timeline,
            "since" | "until"
        )
    )
}

fn cli_value_matches(kind: CliValueKind, value: &str) -> bool {
    match kind {
        CliValueKind::Text => true,
        CliValueKind::Number => !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
        CliValueKind::Sha256 => value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
    }
}

fn is_cass_command_head(word: &str) -> bool {
    if word == "cass" || word == "cass-infinity" {
        return true;
    }
    if word.starts_with('/') {
        let base = word.rsplit_once('/').map(|(_, base)| base).unwrap_or(word);
        return base == "cass" || base == "cass-infinity";
    }
    false
}

/// `NAME=value` prefix. Any such prefix in front of a Cass head is outside
/// the supported subset (the command could still be Cass, so the result is
/// preserved rather than handed to the legacy rules).
fn looks_like_env_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else { return false };
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Read one shell word with quote removal. The word ends at whitespace or at
/// an unquoted command separator, so `cass; echo …` still exposes `cass` as
/// the first literal command head.
fn read_leading_word(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    while matches!(chars.peek(), Some(' ' | '\t' | '\n' | '\r')) {
        chars.next();
    }
    if chars.peek().is_none() {
        return None;
    }
    let mut word = String::new();
    let mut quote = Quote::None;
    while let Some(&c) = chars.peek() {
        match quote {
            Quote::None => match c {
                ' ' | '\t' | '\n' | '\r' => break,
                '|' | '&' | ';' | '<' | '>' | '(' | ')' | '{' | '}' => break,
                '\'' => {
                    chars.next();
                    quote = Quote::Single;
                }
                '"' => {
                    chars.next();
                    quote = Quote::Double;
                }
                '\\' => {
                    chars.next();
                    if let Some(escaped) = chars.next() {
                        word.push(escaped);
                    }
                }
                _ => {
                    word.push(c);
                    chars.next();
                }
            },
            Quote::Single => {
                chars.next();
                if c == '\'' {
                    quote = Quote::None;
                } else {
                    word.push(c);
                }
            }
            Quote::Double => {
                chars.next();
                match c {
                    '"' => quote = Quote::None,
                    '\\' => {
                        if let Some(escaped) = chars.next() {
                            word.push(escaped);
                        }
                    }
                    _ => word.push(c),
                }
            }
        }
    }
    Some(word)
}

/// The first word that is not a `NAME=value` assignment, plus whether any
/// assignment prefix was skipped. There is deliberately no numeric limit:
/// any number of leading assignments still makes the later Cass head a
/// preserved candidate. Used only to decide whether the head is Cass before
/// the stricter syntax pass.
fn command_head_word(command: &str) -> Option<(String, bool)> {
    let mut chars = command.chars().peekable();
    let mut had_assignment = false;
    while let Some(word) = read_leading_word(&mut chars) {
        if looks_like_env_assignment(&word) {
            had_assignment = true;
            continue;
        }
        return Some((word, had_assignment));
    }
    None
}

/// Reject every dynamic or compound shell construct **outside quotes** and
/// every expansion inside double quotes. Quoted metacharacters are data:
/// `cass search "a|b"` mode is accepted, `cass search a | b` is not.
fn scan_dynamic_shell(command: &str) -> Result<(), ()> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Scan {
        None,
        Single,
        Double,
    }

    let mut chars = command.chars().peekable();
    let mut state = Scan::None;
    let mut at_word_start = true;
    while let Some(c) = chars.next() {
        match state {
            Scan::None => match c {
                '\'' => {
                    state = Scan::Single;
                    at_word_start = false;
                }
                '"' => {
                    state = Scan::Double;
                    at_word_start = false;
                }
                '\\' => match chars.next() {
                    None | Some('\n') => return Err(()),
                    Some(_) => at_word_start = false,
                },
                ' ' | '\t' => at_word_start = true,
                '\n' => return Err(()),
                '|' | ';' | '&' | '<' | '>' | '(' | ')' | '{' | '}' | '*' | '?' | '[' | ']'
                | '$' | '`' => return Err(()),
                '#' if at_word_start => return Err(()),
                '~' if at_word_start => return Err(()),
                _ => at_word_start = false,
            },
            Scan::Single => {
                if c == '\'' {
                    state = Scan::None;
                }
            }
            Scan::Double => match c {
                '"' => state = Scan::None,
                '\\' => match chars.next() {
                    None | Some('\n') => return Err(()),
                    Some('$' | '`' | '"' | '\\') => {}
                    Some(_) => {}
                },
                '$' | '`' => return Err(()),
                _ => {}
            },
        }
    }
    if state == Scan::None { Ok(()) } else { Err(()) }
}

fn parse_subcommand<'a>(
    tool: RecallTool,
    tokens: &'a [String],
) -> Result<Option<CliInvocation>, UncoveredReason> {
    let unsupported = UncoveredReason::UnsupportedShell;
    let mut positionals: Vec<&'a str> = Vec::new();
    let mut values: Vec<(&'a str, &'a str)> = Vec::new();
    let mut flags: Vec<&'a str> = Vec::new();
    let mut options_done = false;
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i].as_str();
        if !options_done {
            if token == "--" {
                options_done = true;
                i += 1;
                continue;
            }
            if matches!(token, "--help" | "-h" | "--version" | "-V") {
                return Err(unsupported);
            }
            if let Some(body) = token.strip_prefix("--") {
                let (name, inline) = match body.split_once('=') {
                    Some((name, value)) => (name, Some(value)),
                    None => (body, None),
                };
                match cli_option(tool, name) {
                    Some(CliOption::Flag { canonical }) => {
                        if inline.is_some() || flags.contains(&canonical) {
                            return Err(unsupported);
                        }
                        flags.push(canonical);
                    }
                    Some(CliOption::Value { canonical, kind, repeatable }) => {
                        let value = match inline {
                            Some(value) => value,
                            None => {
                                i += 1;
                                let Some(next) = tokens.get(i) else {
                                    return Err(unsupported);
                                };
                                let next = next.as_str();
                                // `help`/`version` in option position never proves a
                                // recall, even when a value slot is next.
                                if matches!(next, "--help" | "-h" | "--version" | "-V" | "--") {
                                    return Err(unsupported);
                                }
                                // The current CLI accepts dash-leading relative
                                // offsets for since/until; every other value option
                                // rejects a dash-leading token as a missing value.
                                if next.starts_with('-')
                                    && !cli_option_accepts_hyphen_value(tool, canonical)
                                {
                                    return Err(unsupported);
                                }
                                next
                            }
                        };
                        if !cli_value_matches(kind, value)
                            || (!repeatable && values.iter().any(|(seen, _)| *seen == canonical))
                        {
                            return Err(unsupported);
                        }
                        values.push((canonical, value));
                    }
                    None => return Err(unsupported),
                }
                i += 1;
                continue;
            }
            if token.len() > 1 && token.starts_with('-') {
                let (canonical, kind) = match (tool, token) {
                    (RecallTool::Expand, "-n") => ("line", CliValueKind::Number),
                    (RecallTool::Expand, "-C") => ("context", CliValueKind::Number),
                    _ => return Err(unsupported),
                };
                i += 1;
                let Some(next) = tokens.get(i) else { return Err(unsupported) };
                if next.starts_with('-') || !cli_value_matches(kind, next) {
                    return Err(unsupported);
                }
                if values.iter().any(|(seen, _)| *seen == canonical) {
                    return Err(unsupported);
                }
                values.push((canonical, next.as_str()));
                i += 1;
                continue;
            }
        }
        positionals.push(token);
        i += 1;
    }

    let value_of = |name: &str| {
        values.iter().find(|(canonical, _)| *canonical == name).map(|(_, value)| *value)
    };
    let has_flag = |name: &str| flags.contains(&name);
    let recall_conflicts = has_flag("recall")
        && (has_flag("json")
            || (tool == RecallTool::Search && value_of("fields").is_some()));
    if recall_conflicts {
        return Err(unsupported);
    }

    match tool {
        RecallTool::Search => {
            if positionals.len() != 1 {
                return Err(unsupported);
            }
            Ok(Some(CliInvocation { tool, args: Value::Object(serde_json::Map::new()) }))
        }
        RecallTool::Expand => {
            if positionals.len() != 1 {
                return Err(unsupported);
            }
            let path = positionals[0];
            let line = value_of("line");
            let message_id = value_of("message-id");
            let sha = value_of("expected-content-sha256");
            let source = value_of("source");
            let located = match (line, message_id, sha) {
                (Some(_), None, None) => true,
                (None, Some(_), Some(_)) => source.is_some(),
                _ => false,
            };
            if !located {
                return Err(unsupported);
            }
            let mut args = serde_json::Map::new();
            args.insert("source_path".to_string(), Value::String(path.to_string()));
            if let Some(source) = source {
                args.insert("source_id".to_string(), Value::String(source.to_string()));
            }
            Ok(Some(CliInvocation { tool, args: Value::Object(args) }))
        }
        RecallTool::Sessions | RecallTool::Timeline => {
            if !positionals.is_empty() {
                return Err(unsupported);
            }
            Ok(Some(CliInvocation { tool, args: Value::Object(serde_json::Map::new()) }))
        }
    }
}

/// Parse one captured shell command into the limited direct-CLI form.
///
/// `Ok(None)` means the head is not Cass at all (ordinary shell work stays on
/// the legacy path); `Err(UnsupportedShell)` means the head **is** Cass but
/// the syntax is outside C06's subset, so the result must be preserved and
/// diagnosed instead of silently excluded. `Ok(Some(_))` is one of the four
/// frozen read commands. Executes nothing.
pub(crate) fn parse_cli(command: &str) -> Result<Option<CliInvocation>, UncoveredReason> {
    let unsupported = UncoveredReason::UnsupportedShell;
    let Some((head, had_assignment_prefix)) = command_head_word(command) else {
        return Ok(None);
    };
    if !is_cass_command_head(&head) {
        return Ok(None);
    }
    if had_assignment_prefix {
        return Err(unsupported);
    }
    scan_dynamic_shell(command).map_err(|()| unsupported)?;
    let tokens = shell_words::split(command).map_err(|_| unsupported)?;
    let Some((head_token, rest)) = tokens.split_first() else { return Err(unsupported) };
    if !is_cass_command_head(head_token) {
        return Ok(None);
    }
    let Some((subcommand, args)) = rest.split_first() else { return Err(unsupported) };
    let tool = match subcommand.as_str() {
        "search" => RecallTool::Search,
        "expand" => RecallTool::Expand,
        "sessions" => RecallTool::Sessions,
        "timeline" => RecallTool::Timeline,
        _ => return Err(unsupported),
    };
    parse_subcommand(tool, args)
}

/// Which captured argument key holds the shell command for this
/// connector/tool pair. Exact names only: a shared suffix or another
/// connector's tool name proves nothing.
fn shell_command_key(tool_name: &str, agent_slug: &str) -> Option<&'static str> {
    match (agent_slug, tool_name) {
        ("claude_code", "Bash") => Some("command"),
        ("codex", "exec_command") => Some("cmd"),
        _ => None,
    }
}

/// True when the raw text contains any `cass_recall` opening tag. Used only
/// to separate "looks like a wrapper but is invalid" from "plain output" for
/// bare-name candidates; it is never used to extract a payload.
pub(crate) fn looks_like_recall_wrapper(content: &str) -> bool {
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

/// The attribution strength a caller has already established for one direct
/// tool result. The old v2 entry derives it from its own name table; the Pi
/// consumer derives it from the captured Pi tool identity. The shared core
/// below never re-classifies a name, so a caller cannot silently gain or lose
/// an identity through this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectToolCategory {
    Strong(RecallTool),
    Bare(RecallTool),
}

/// The direct tool-result judgment core, shared by the old v2 entry and the
/// Pi consumer (ticket 02).
///
/// It receives facts, not identity: `msg` is the message whose body is read,
/// `event` locates the result blocks, `call` supplies the anchor identity and
/// the argument map, and `category` states the already-proven attribution.
/// The result-block lookup, the `Decision` construction and the Strong/Bare
/// outcome rules are identical for both callers, so a later change to one
/// cannot diverge from the other.
pub(crate) fn judge_direct_tool_result(
    msg: &NormalizedMessage,
    event: &RawEvent,
    call: &PairedTool,
    category: DirectToolCategory,
) -> Outcome {
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

    match category {
        DirectToolCategory::Strong(tool) => {
            // Arguments only feed source extraction. `Null` is the explicit
            // "no captured arguments" value and `extract_source` reads it as
            // absent, so nothing is defaulted or invented.
            let absent = Value::Null;
            let args = call.args.as_ref().unwrap_or(&absent);
            let (src, parse_error) = match parse_result(tool, &msg.content, args) {
                Ok(src) => (Some(src), None),
                Err(reason) => (None, Some(reason.to_string())),
            };
            Outcome::Exclude(Exclusion {
                decision,
                src,
                parse_error,
            })
        }
        DirectToolCategory::Bare(tool) => {
            // Arguments only feed source extraction; the complete C04
            // envelope below proves the identity. `Null` is the explicit
            // "no captured arguments" value and `extract_source` reads it as
            // absent, so an expand invents no source.
            let absent = Value::Null;
            let args = call.args.as_ref().unwrap_or(&absent);
            match recall_output::decode(&msg.content, tool) {
                Ok(value) => {
                    let src = extract_source(tool, &value, args);
                    Outcome::Exclude(Exclusion {
                        decision,
                        src: Some(src),
                        parse_error: None,
                    })
                }
                Err(_) if looks_like_recall_wrapper(&msg.content) => {
                    Outcome::Preserve(Some(UncoveredReason::InvalidRecallFormat))
                }
                Err(_) => Outcome::Preserve(Some(UncoveredReason::AmbiguousToolIdentity)),
            }
        }
    }
}

/// v2 judgment. The signature mirrors the legacy `decide` exactly so a later

/// ingest ticket can swap the call without reshaping its inputs.
///
/// Order is fixed:
/// 1. non-`tool_result` rows, unknown connectors and non-Cass tools fall back
///    to the unchanged legacy judgment (R2/R3 still apply, now with marker 2
///    when they fire through this entry);
/// 2. a paired `Bash`/`exec_command` call is first read as a direct CLI
///    command (ticket 06): a non-Cass head keeps the legacy path, an
///    unsupported Cass syntax is preserved as `unsupported_shell`, and a
///    proven read command still needs the captured args and a uniquely
///    locatable result block before it can be excluded;
/// 3. a recognized Cass candidate that lacks R4 pairing or a uniquely
///    locatable result block is preserved as `unpaired_result`. Captured
///    arguments are not an identity proof: they only feed source extraction,
///    so a bare identity without them still reaches the envelope check in
///    step 5. A bare identity must **not** fall back to the legacy R1 rule,
///    whose bare-name alias would delete an ordinary same-named tool's
///    output. An unrecognized tool name is never a v2 candidate: it returns
///    to the unchanged legacy judgment before any check;
/// 4. a strong identity is excluded whatever the output is (damaged output
///    is excluded with `src = None` and a bounded `parse_error`). Its exact
///    full name proves attribution, so a missing argument capture does not
///    downgrade it: arguments only feed source extraction, and an absent
///    argument map reads as "no argument" without inventing a field;
/// 5. a bare identity is excluded only after the whole result decodes as a
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

    if let Some(command_key) = shell_command_key(&call.tool_name, agent_slug) {
        let Some(args) = call.args.as_ref() else {
            return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
        };
        let Some(command) = args.get(command_key).and_then(Value::as_str) else {
            return legacy_outcome(msg, idx, event, ctx, agent_slug, paths_cfg);
        };
        match parse_cli(command) {
            Ok(None) => return legacy_outcome(msg, idx, event, ctx, agent_slug, paths_cfg),
            Err(reason) => return Outcome::Preserve(Some(reason)),
            Ok(Some(invocation)) => {
                let target_blocks =
                    exclusion::tool_result_block_indices(event, call.tool_call_id.as_deref());
                if target_blocks.is_empty() {
                    return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
                }
                let decision = Decision {
                    reason: ExclusionReason::CassRecall,
                    anchor: ExclusionAnchor {
                        tool_call_id: call.tool_call_id.clone(),
                        // The actual shell tool name, never an MCP name.
                        tool_name: Some(call.tool_name.clone()),
                        paths: None,
                        shell: None,
                    },
                    event_key: event.event_key.clone(),
                    target_blocks,
                };
                let (src, parse_error) =
                    match parse_result(invocation.tool, &msg.content, &invocation.args) {
                        Ok(src) => (Some(src), None),
                        Err(reason) => (None, Some(reason.to_string())),
                    };
                return Outcome::Exclude(Exclusion { decision, src, parse_error });
            }
        }
    }

    let Some(kind) = classify_tool(&call.tool_name, agent_slug) else {
        // An unknown tool — including another server's same-suffixed name — is
        // not a Cass candidate here. It goes back through the unchanged legacy
        // judgment BEFORE any argument check, so a missing capture never turns
        // it into a v2 `unpaired_result`.
        return legacy_outcome(msg, idx, event, ctx, agent_slug, paths_cfg);
    };

    let category = match kind {
        CandidateKind::Strong(tool) => DirectToolCategory::Strong(tool),
        CandidateKind::Bare(tool) => DirectToolCategory::Bare(tool),
    };
    judge_direct_tool_result(msg, event, call, category)
}

// ============================================================================
// Ticket 07: the current host's synchronous single-call wrapper (C07).
//
// A Codex `custom_tool_call` named `exec` may carry its free-form input as a
// JavaScript literal. Only one exact shape is recognized:
//
//     text(await tools.exec_command(J));
//     text(await tools.mcp__cass_mcp__cass_{search,expand,sessions,timeline}(J));
//
// `J` must be one complete JSON object. Nothing here executes JavaScript or
// Shell; the text is split only at the fixed outer prefix/suffix and handed
// to `serde_json`. The original whole body, the R4 pairing result and the R7
// copy clearing are untouched.
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecTarget {
    /// `tools.exec_command` whose `cmd` is one proven CASS read command.
    Cli,
    /// One of the four `tools.mcp__cass_mcp__cass_*` method names.
    Mcp(RecallTool),
}

/// Split the fixed C07 expression and parse `J`. The `exec_command` branch is
/// unchanged: exactly `text(await tools.exec_command(J));` with `J` one strict
/// JSON object. The four MCP methods use the limited literal grammar of
/// ticket 06: whitespace between the outer tokens, double-quoted JSON strings,
/// decimal safe integers, booleans, null, arrays, and objects whose keys are
/// JSON strings or ASCII identifiers, with one optional trailing comma.
/// The ticket 07a form binds that same call to one name and prints only that
/// name: `const IDENT = await tools.METHOD(J); text(IDENT);`.
/// Anything else (unquoted CLI keys, variables, templates, spreads, computed
/// keys, accessors, comments, calls, operators, unknown methods) returns
/// `None`. Nothing here evaluates JavaScript.
fn parse_exec_literal(expression: &str) -> Option<(ExecTarget, Value)> {
    if let Some(input) = exact_exec_command_input(expression) {
        let value: Value = serde_json::from_str(input).ok()?;
        return value.is_object().then_some((ExecTarget::Cli, value));
    }
    if let Some((tool, args)) = parse_mcp_call_literal(expression) {
        return Some((ExecTarget::Mcp(tool), args));
    }
    parse_const_mcp_call_literal(expression).map(|(tool, args)| (ExecTarget::Mcp(tool), args))
}

/// The unchanged C07 `exec_command` form: exactly
/// `text(await tools.exec_command(J));` with `J` one strict JSON object. The
/// ticket 06 literal grammar is never applied to this method.
fn exact_exec_command_input(expression: &str) -> Option<&str> {
    let body = expression
        .trim()
        .strip_prefix("text(await tools.")?
        .strip_suffix("));")?;
    let open = body.find('(')?;
    if &body[..open] != "exec_command" {
        return None;
    }
    Some(&body[open + 1..])
}

/// The largest magnitude a literal integer argument may carry.
const MAX_SAFE_LITERAL_INTEGER: u64 = 9_007_199_254_740_991;

/// The number of nested objects and arrays the old strict JSON path accepted.
/// `serde_json` refuses the 128th open container, so 127 is the deepest
/// literal this parser admits. The check runs before the recursive call, so a
/// deeper input returns `None` instead of exhausting the stack.
const MAX_LITERAL_DEPTH: usize = 127;

/// Keys that would reach the JavaScript prototype chain. They are never data,
/// so a literal that sets one anywhere is refused, including an escaped
/// spelling that decodes to the same name.
const PROTOTYPE_KEYS: [&str; 3] = ["__proto__", "prototype", "constructor"];

/// Parse one `text(await tools.mcp__cass_mcp__cass_*(ARGS));` expression.
/// The whole expression is trimmed the way the original function trimmed it,
/// so Unicode whitespace around the fixed shape is accepted. Separator
/// whitespace inside the shape stays ASCII, and the expression must end at the
/// single closing semicolon.
fn parse_mcp_call_literal(expression: &str) -> Option<(RecallTool, Value)> {
    let expression = expression.trim();
    let mut parser = LiteralParser::new(expression);
    parser.skip_whitespace();
    parser.expect_keyword("text")?;
    parser.skip_whitespace();
    parser.expect_byte(b'(')?;
    parser.skip_whitespace();
    parser.expect_keyword("await")?;
    parser.skip_whitespace();
    parser.expect_keyword("tools")?;
    parser.skip_whitespace();
    parser.expect_byte(b'.')?;
    parser.skip_whitespace();
    let tool = match parser.take_identifier()? {
        "mcp__cass_mcp__cass_search" => RecallTool::Search,
        "mcp__cass_mcp__cass_expand" => RecallTool::Expand,
        "mcp__cass_mcp__cass_sessions" => RecallTool::Sessions,
        "mcp__cass_mcp__cass_timeline" => RecallTool::Timeline,
        _ => return None,
    };
    parser.skip_whitespace();
    parser.expect_byte(b'(')?;
    parser.skip_whitespace();
    // The argument object itself is the first nesting level.
    let args = parser.parse_value(1)?;
    if !args.is_object() {
        return None;
    }
    parser.skip_whitespace();
    parser.expect_byte(b')')?;
    parser.skip_whitespace();
    parser.expect_byte(b')')?;
    parser.skip_whitespace();
    parser.expect_byte(b';')?;
    parser.skip_whitespace();
    parser.at_end().then_some((tool, args))
}

/// Binding names the single-`const` form refuses: the keywords, the
/// strict-mode future reserved words, and the two strict-mode binding
/// restrictions. `async` is deliberately absent; it is a valid binding name.
const CONST_REJECTED_BINDINGS: [&str; 48] = [
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "yield",
    "implements",
    "interface",
    "let",
    "package",
    "private",
    "protected",
    "public",
    "static",
    "arguments",
    "eval",
];

/// Parse one `const IDENT = await tools.mcp__cass_mcp__cass_*(ARGS); text(IDENT);`
/// expression. The whole expression is trimmed the way the original function
/// trimmed it. The declaration name and the printed name must be the same
/// identifier, so the value that reaches `text` is the call result and nothing
/// else. Only one declaration and one print are accepted, both semicolons are
/// required, and the expression must end there. The argument object reuses the
/// ticket 06 literal parser unchanged.
fn parse_const_mcp_call_literal(expression: &str) -> Option<(RecallTool, Value)> {
    let expression = expression.trim();
    let mut parser = LiteralParser::new(expression);
    parser.skip_whitespace();
    parser.expect_keyword("const")?;
    parser.skip_whitespace();
    let binding = parser.take_identifier()?;
    if CONST_REJECTED_BINDINGS.contains(&binding) {
        return None;
    }
    parser.skip_whitespace();
    parser.expect_byte(b'=')?;
    parser.skip_whitespace();
    parser.expect_keyword("await")?;
    parser.skip_whitespace();
    parser.expect_keyword("tools")?;
    parser.skip_whitespace();
    parser.expect_byte(b'.')?;
    parser.skip_whitespace();
    let tool = match parser.take_identifier()? {
        "mcp__cass_mcp__cass_search" => RecallTool::Search,
        "mcp__cass_mcp__cass_expand" => RecallTool::Expand,
        "mcp__cass_mcp__cass_sessions" => RecallTool::Sessions,
        "mcp__cass_mcp__cass_timeline" => RecallTool::Timeline,
        _ => return None,
    };
    parser.skip_whitespace();
    parser.expect_byte(b'(')?;
    parser.skip_whitespace();
    // The argument object itself is the first nesting level.
    let args = parser.parse_value(1)?;
    if !args.is_object() {
        return None;
    }
    parser.skip_whitespace();
    parser.expect_byte(b')')?;
    parser.skip_whitespace();
    parser.expect_byte(b';')?;
    parser.skip_whitespace();
    parser.expect_keyword("text")?;
    parser.skip_whitespace();
    parser.expect_byte(b'(')?;
    parser.skip_whitespace();
    let printed = parser.take_identifier()?;
    parser.skip_whitespace();
    parser.expect_byte(b')')?;
    parser.skip_whitespace();
    parser.expect_byte(b';')?;
    parser.skip_whitespace();
    if printed != binding || !parser.at_end() {
        return None;
    }
    Some((tool, args))
}

/// A byte-oriented reader for the limited literal grammar above. It only ever
/// slices at ASCII boundaries: quotes, braces and the fixed outer tokens.
struct LiteralParser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> LiteralParser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn at_end(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Option<()> {
        if self.peek() != Some(expected) {
            return None;
        }
        self.pos += 1;
        Some(())
    }

    /// Match one fixed keyword. The keyword must end at a lexical boundary, so
    /// `awaittools` does not read as `await` followed by more input.
    fn expect_keyword(&mut self, keyword: &str) -> Option<()> {
        let end = self.pos.checked_add(keyword.len())?;
        if self.text.get(self.pos..end)? != keyword {
            return None;
        }
        if self
            .bytes
            .get(end)
            .copied()
            .is_some_and(identifier_continue)
        {
            return None;
        }
        self.pos = end;
        Some(())
    }

    fn take_identifier(&mut self) -> Option<&'a str> {
        let start = self.pos;
        if !self.peek().is_some_and(identifier_start) {
            return None;
        }
        self.pos += 1;
        while self.peek().is_some_and(identifier_continue) {
            self.pos += 1;
        }
        Some(&self.text[start..self.pos])
    }

    /// `depth` is the nesting level the value would occupy if it is a
    /// container. The check lives at container entry, before the recursive
    /// call, so a too-deep literal is refused without growing the stack.
    fn parse_value(&mut self, depth: usize) -> Option<Value> {
        match self.peek()? {
            b'"' => self.parse_string().map(Value::String),
            b'{' => self.parse_object(depth),
            b'[' => self.parse_array(depth),
            b'-' | b'0'..=b'9' => self.parse_integer(),
            b't' => self.expect_keyword("true").map(|()| Value::Bool(true)),
            b'f' => self.expect_keyword("false").map(|()| Value::Bool(false)),
            b'n' => self.expect_keyword("null").map(|()| Value::Null),
            _ => None,
        }
    }

    /// One JSON double-quoted string. The raw slice, escapes included, is
    /// decoded by `serde_json`; keys are compared after that decode so an
    /// escaped alias is the same key.
    fn parse_string(&mut self) -> Option<String> {
        let start = self.pos;
        self.expect_byte(b'"')?;
        loop {
            match self.peek()? {
                b'"' => {
                    self.pos += 1;
                    return serde_json::from_str(&self.text[start..self.pos]).ok();
                }
                b'\\' => {
                    self.pos += 1;
                    self.peek()?;
                    self.pos += 1;
                }
                _ => self.pos += 1,
            }
        }
    }

    /// A decimal safe integer: no sign but `-`, no leading zero, no negative
    /// zero, no fraction or exponent, magnitude at most 2^53 - 1.
    fn parse_integer(&mut self) -> Option<Value> {
        let negative = self.peek() == Some(b'-');
        if negative {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == digits_start {
            return None;
        }
        let digits = &self.text[digits_start..self.pos];
        if digits.len() > 1 && digits.starts_with('0') {
            return None;
        }
        if negative && digits == "0" {
            return None;
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return None;
        }
        let magnitude: u64 = digits.parse().ok()?;
        if magnitude > MAX_SAFE_LITERAL_INTEGER {
            return None;
        }
        if negative {
            Some(Value::from(-(magnitude as i64)))
        } else {
            Some(Value::from(magnitude))
        }
    }

    /// One object literal. Keys are double-quoted strings or ASCII
    /// identifiers. A repeated decoded key, a prototype key, or more than one
    /// trailing comma is refused.
    fn parse_object(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_LITERAL_DEPTH {
            return None;
        }
        self.expect_byte(b'{')?;
        let mut members = serde_json::Map::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Some(Value::Object(members));
        }
        loop {
            let key = match self.peek()? {
                b'"' => self.parse_string()?,
                _ => self.take_identifier()?.to_string(),
            };
            if members.contains_key(&key) || PROTOTYPE_KEYS.contains(&key.as_str()) {
                return None;
            }
            self.skip_whitespace();
            self.expect_byte(b':')?;
            self.skip_whitespace();
            let value = self.parse_value(depth + 1)?;
            members.insert(key, value);
            self.skip_whitespace();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                    self.skip_whitespace();
                    // One trailing comma is allowed; a second one is not.
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        return Some(Value::Object(members));
                    }
                }
                b'}' => {
                    self.pos += 1;
                    return Some(Value::Object(members));
                }
                _ => return None,
            }
        }
    }

    /// One array literal under the JSON rules: comma separated, no trailing
    /// comma.
    fn parse_array(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_LITERAL_DEPTH {
            return None;
        }
        self.expect_byte(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Some(Value::Array(items));
        }
        loop {
            items.push(self.parse_value(depth + 1)?);
            self.skip_whitespace();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                    self.skip_whitespace();
                }
                b']' => {
                    self.pos += 1;
                    return Some(Value::Array(items));
                }
                _ => return None,
            }
        }
    }
}

fn identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$'
}

fn identifier_continue(byte: u8) -> bool {
    identifier_start(byte) || byte.is_ascii_digit()
}

/// One `input_text` block's text, with no other block type accepted.
fn input_text_block_text(block: &Value) -> Option<&str> {
    let object = block.as_object()?;
    if object.get("type").and_then(Value::as_str) != Some("input_text") {
        return None;
    }
    object.get("text").and_then(Value::as_str)
}

/// The fixed transport description, exactly three lines:
/// `Script completed`, `Wall time NUMBER seconds`, `Output:`.
/// NUMBER is a non-negative finite number; `Script running` and other
/// segmented forms are not accepted.
fn transport_header_is_exact(text: &str) -> bool {
    let mut lines = text.split('\n');
    if lines.next() != Some("Script completed") {
        return false;
    }
    let Some(wall) = lines.next() else { return false };
    let Some(number) = wall.strip_prefix("Wall time ").and_then(|rest| rest.strip_suffix(" seconds"))
    else {
        return false;
    };
    let Ok(value) = number.parse::<f64>() else { return false };
    if !value.is_finite() || value < 0.0 {
        return false;
    }
    lines.next() == Some("Output:") && lines.next().is_none()
}

/// The application result text from `payload.output`: either one JSON string
/// or an array of `input_text` blocks holding exactly one application block,
/// optionally preceded by the one exact transport description block.
fn application_text(payload_output: &Value) -> Option<&str> {
    match payload_output {
        Value::String(text) => Some(text.as_str()),
        Value::Array(blocks) if blocks.len() == 1 => input_text_block_text(&blocks[0]),
        Value::Array(blocks) if blocks.len() == 2 => {
            let header = input_text_block_text(&blocks[0])?;
            if !transport_header_is_exact(header) {
                return None;
            }
            input_text_block_text(&blocks[1])
        }
        _ => None,
    }
}

/// The application JSON must be one complete object, with no other JSON or
/// text before or after it (outer JSON whitespace is allowed).
fn application_object(text: &str) -> Option<Value> {
    let value: Value = serde_json::from_str(text).ok()?;
    value.is_object().then_some(value)
}

const CLI_TRANSPORT_FIELDS: &[&str] =
    &["output", "exit_code", "chunk_id", "wall_time_seconds", "original_token_count"];

/// `exec_command` application object: integer `exit_code` 0, no `session_id`
/// at all (including null), `output` is the complete C04 text, and no other
/// application data hides behind unknown fields.
fn cli_application_output(value: &Value) -> Option<&str> {
    let object = value.as_object()?;
    if object.get("exit_code").and_then(Value::as_i64) != Some(0) {
        return None;
    }
    if object.contains_key("session_id") {
        return None;
    }
    if object.keys().any(|key| !CLI_TRANSPORT_FIELDS.contains(&key.as_str())) {
        return None;
    }
    object.get("output").and_then(Value::as_str)
}

/// MCP application object: `isError` absent or boolean false, `content` is
/// exactly one `type: "text"` block whose text is the complete C04 wrapper.
/// Only `content`/`isError` and the optional SDK completion metadata
/// `resultType` are supported. `resultType` may be absent (the 2025 protocol
/// omits it) or the string `"complete"` (the 2026 protocol); `null`, a
/// non-string, `task`, `input_required` and any other value are not a
/// completed result and must stay.
fn mcp_application_text(value: &Value) -> Option<&str> {
    let object = value.as_object()?;
    if object
        .keys()
        .any(|key| key != "content" && key != "isError" && key != "resultType")
    {
        return None;
    }
    match object.get("isError") {
        None | Some(Value::Bool(false)) => {}
        _ => return None,
    }
    if let Some(result_type) = object.get("resultType")
        && result_type.as_str() != Some("complete")
    {
        return None;
    }
    let content = object.get("content")?.as_array()?;
    if content.len() != 1 {
        return None;
    }
    let block = content[0].as_object()?;
    if block.keys().any(|key| key != "type" && key != "text") {
        return None;
    }
    if block.get("type").and_then(Value::as_str) != Some("text") {
        return None;
    }
    block.get("text").and_then(Value::as_str)
}

/// `response_item` / `payload.type = custom_tool_call_output`, or `None`.
fn custom_tool_output_payload(raw_record: &Value) -> Option<&Value> {
    if raw_record.get("type").and_then(Value::as_str) != Some("response_item") {
        return None;
    }
    let payload = raw_record.get("payload")?;
    if payload.get("type").and_then(Value::as_str) != Some("custom_tool_call_output") {
        return None;
    }
    Some(payload)
}

fn decode_any_tool(text: &str) -> bool {
    [
        RecallTool::Search,
        RecallTool::Expand,
        RecallTool::Sessions,
        RecallTool::Timeline,
    ]
    .iter()
    .any(|tool| recall_output::decode(text, *tool).is_ok())
}

/// Ticket 07 C07 result shape without an R4 pair: a complete single
/// application result that decodes as one of the four C04 tools. This only
/// counts an `unpaired_result` diagnostic; it never authorizes deletion.
fn complete_unpaired_recall(payload: &Value) -> bool {
    let Some(output) = payload.get("output") else { return false };
    let Some(text) = application_text(output) else { return false };
    let Some(application) = application_object(text) else { return false };
    if let Some(wrapper) = mcp_application_text(&application) {
        return decode_any_tool(wrapper);
    }
    if let Some(wrapper) = cli_application_output(&application) {
        return decode_any_tool(wrapper);
    }
    false
}

/// C01/C06/C07 hint: does this `exec` call's own text name one of the four
/// Cass reads?
///
/// Only literal evidence is read: the frozen C07 single-call expression, the
/// four complete MCP method literals inside an otherwise unsupported script,
/// or one JSON string `cmd` value that decodes to a Cass-headed command. No
/// variable, template, loop or other script text is interpreted, and nothing
/// is executed.
fn exec_text_names_a_cass_call(expression: &str) -> bool {
    if let Some((target, input)) = parse_exec_literal(expression) {
        return match target {
            ExecTarget::Mcp(_) => true,
            ExecTarget::Cli => input
                .get("cmd")
                .and_then(Value::as_str)
                .is_some_and(cli_names_cass),
        };
    }
    if script_calls_a_cass_tool(expression) {
        return true;
    }
    json_string_cmd(expression).is_some_and(|command| cli_names_cass(&command))
}

/// Ticket 07b: does this unsupported script contain a static call to one of
/// the four Cass MCP reads?
///
/// The scan is lexical only. Strings, comments, template text and regex
/// literals are skipped, and `tools . METHOD (` is recognized with the same
/// four ASCII separators the literal parser allows. Comments between the
/// method and its call parenthesis remain candidate evidence only. A method reference,
/// `typeof tools.METHOD` or a descriptive string has no call parenthesis after
/// the method, so it never matches. Nothing is executed, evaluated or
/// rewritten: this answer only decides whether the strict checks after
/// [`exec_recall_candidate_hint`] run, and it never authorizes an exclusion.
fn script_calls_a_cass_tool(expression: &str) -> bool {
    /// One level of the explicit stack: template text, or the `{...}` nesting
    /// of a `${...}` interpolation that returns to code scanning.
    enum Frame {
        Template,
        Interpolation(usize),
    }

    fn skip_separators(bytes: &[u8], mut pos: usize) -> usize {
        while bytes
            .get(pos)
            .copied()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            pos += 1;
        }
        pos
    }

    fn call_parenthesis_after_trivia(bytes: &[u8], mut pos: usize) -> bool {
        loop {
            pos = skip_separators(bytes, pos);
            if bytes.get(pos..pos + 2) == Some(b"/*") {
                let Some(end) = bytes[pos + 2..].windows(2).position(|part| part == b"*/") else {
                    return false;
                };
                pos += end + 4;
            } else if bytes.get(pos..pos + 2) == Some(b"//") {
                pos += 2;
                while bytes
                    .get(pos)
                    .is_some_and(|byte| !matches!(byte, b'\n' | b'\r'))
                {
                    pos += 1;
                }
            } else {
                return bytes.get(pos) == Some(&b'(');
            }
        }
    }

    /// `tools <sep> . <sep> METHOD <sep> (` at a complete identifier boundary.
    fn callee_after_tools(bytes: &[u8], pos: usize) -> bool {
        let mut pos = skip_separators(bytes, pos);
        if bytes.get(pos) != Some(&b'.') {
            return false;
        }
        pos = skip_separators(bytes, pos + 1);
        [
            "mcp__cass_mcp__cass_search",
            "mcp__cass_mcp__cass_expand",
            "mcp__cass_mcp__cass_sessions",
            "mcp__cass_mcp__cass_timeline",
        ]
        .iter()
        .any(|method| {
            let end = pos + method.len();
            bytes.get(pos..end) == Some(method.as_bytes())
                && !bytes.get(end).copied().is_some_and(identifier_continue)
                && call_parenthesis_after_trivia(bytes, end)
        })
    }

    let bytes = expression.as_bytes();
    let mut pos = 0;
    let mut frames: Vec<Frame> = Vec::new();
    // Expression context distinguishes regex literals from division. Control
    // headers and statement blocks can end before a new regex statement;
    // ordinary parenthesized values still end an operand.
    let mut operand_expected = true;
    let mut previous_significant: Option<u8> = None;
    let mut control_parenthesis_pending = false;
    let mut control_parentheses = Vec::new();
    let mut statement_expected = true;
    let mut statement_braces = Vec::new();

    while pos < bytes.len() {
        let byte = bytes[pos];

        if matches!(frames.last(), Some(Frame::Template)) {
            match byte {
                b'\\' => pos = (pos + 2).min(bytes.len()),
                b'`' => {
                    pos += 1;
                    frames.pop();
                    operand_expected = false;
                    previous_significant = Some(b'`');
                }
                b'$' if bytes.get(pos + 1) == Some(&b'{') => {
                    pos += 2;
                    frames.push(Frame::Interpolation(0));
                    operand_expected = true;
                    previous_significant = Some(b'{');
                }
                _ => pos += 1,
            }
            continue;
        }

        let pending_control = std::mem::take(&mut control_parenthesis_pending);
        let statement_start = std::mem::replace(&mut statement_expected, false);
        match byte {
            b' ' | b'\t' | b'\n' | b'\r' => {
                control_parenthesis_pending = pending_control;
                statement_expected = statement_start;
                pos += 1;
            }
            b'/' if bytes.get(pos + 1) == Some(&b'/') => {
                control_parenthesis_pending = pending_control;
                statement_expected = statement_start;
                pos += 2;
                while pos < bytes.len() && !matches!(bytes[pos], b'\n' | b'\r') {
                    pos += 1;
                }
            }
            b'/' if bytes.get(pos + 1) == Some(&b'*') => {
                control_parenthesis_pending = pending_control;
                statement_expected = statement_start;
                pos += 2;
                while pos < bytes.len() {
                    if bytes[pos] == b'*' && bytes.get(pos + 1) == Some(&b'/') {
                        pos += 2;
                        break;
                    }
                    pos += 1;
                }
            }
            b'"' | b'\'' => {
                pos += 1;
                while pos < bytes.len() {
                    match bytes[pos] {
                        b'\\' => pos += 2,
                        closer if closer == byte => {
                            pos += 1;
                            break;
                        }
                        _ => pos += 1,
                    }
                }
                operand_expected = false;
                previous_significant = Some(byte);
            }
            b'`' => {
                pos += 1;
                frames.push(Frame::Template);
            }
            b'/' if operand_expected => {
                // A regex literal: skip escapes and character classes, then
                // its flags. The pattern is never scanned for method names.
                pos += 1;
                let mut in_class = false;
                while pos < bytes.len() {
                    match bytes[pos] {
                        b'\\' => pos += 2,
                        b'[' if !in_class => {
                            in_class = true;
                            pos += 1;
                        }
                        b']' if in_class => {
                            in_class = false;
                            pos += 1;
                        }
                        b'/' if !in_class => {
                            pos += 1;
                            break;
                        }
                        _ => pos += 1,
                    }
                }
                while bytes.get(pos).copied().is_some_and(identifier_continue) {
                    pos += 1;
                }
                operand_expected = false;
                previous_significant = Some(b'/');
            }
            b'/' => {
                pos += 1;
                operand_expected = true;
                previous_significant = Some(b'/');
            }
            b'{' => {
                statement_braces.push(statement_start);
                if let Some(Frame::Interpolation(depth)) = frames.last_mut() {
                    *depth += 1;
                }
                pos += 1;
                operand_expected = true;
                statement_expected = statement_start;
                previous_significant = Some(b'{');
            }
            b'}' => {
                if matches!(frames.last(), Some(Frame::Interpolation(0))) {
                    frames.pop();
                    operand_expected = false;
                } else if let Some(Frame::Interpolation(depth)) = frames.last_mut() {
                    *depth -= 1;
                    operand_expected = statement_braces.pop().unwrap_or(false);
                } else {
                    operand_expected = statement_braces.pop().unwrap_or(false);
                }
                pos += 1;
                statement_expected = operand_expected;
                previous_significant = Some(b'}');
            }
            b'(' => {
                control_parentheses.push(pending_control);
                pos += 1;
                operand_expected = true;
                previous_significant = Some(byte);
            }
            b'[' => {
                pos += 1;
                operand_expected = true;
                previous_significant = Some(byte);
            }
            b')' => {
                pos += 1;
                operand_expected = control_parentheses.pop().unwrap_or(false);
                statement_expected = operand_expected;
                previous_significant = Some(byte);
            }
            b']' => {
                pos += 1;
                operand_expected = false;
                previous_significant = Some(byte);
            }
            b'=' | b':' | b',' | b';' | b'?' | b'+' | b'-' | b'*' | b'%' | b'&' | b'|' | b'^'
            | b'!' | b'~' | b'<' | b'>' => {
                pos += 1;
                operand_expected = true;
                statement_expected = byte == b';';
                previous_significant = Some(byte);
            }
            b'.' => {
                pos += 1;
                operand_expected = true;
                previous_significant = Some(b'.');
            }
            b'0'..=b'9' => {
                while bytes
                    .get(pos)
                    .copied()
                    .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
                {
                    pos += 1;
                }
                operand_expected = false;
                previous_significant = Some(b'0');
            }
            byte if identifier_start(byte) => {
                let start = pos;
                pos += 1;
                while bytes.get(pos).copied().is_some_and(identifier_continue) {
                    pos += 1;
                }
                let word = &expression[start..pos];
                if word == "tools"
                    && previous_significant != Some(b'.')
                    && callee_after_tools(bytes, pos)
                {
                    return true;
                }
                control_parenthesis_pending = previous_significant != Some(b'.')
                    && (matches!(word, "if" | "while" | "for" | "with" | "switch" | "catch")
                        || (pending_control && word == "await"));
                statement_expected = matches!(word, "else" | "do" | "try" | "finally");
                operand_expected = matches!(
                    word,
                    "return"
                        | "throw"
                        | "case"
                        | "delete"
                        | "void"
                        | "typeof"
                        | "new"
                        | "in"
                        | "of"
                        | "instanceof"
                        | "do"
                        | "else"
                        | "yield"
                        | "await"
                );
                previous_significant = Some(b'a');
            }
            byte if byte >= 0x80 => {
                // A non-ASCII byte is an opaque part of a value; it is never
                // sliced, so no UTF-8 boundary can be cut.
                pos += 1;
                operand_expected = false;
                previous_significant = Some(byte);
            }
            _ => {
                pos += 1;
                operand_expected = true;
                previous_significant = Some(byte);
            }
        }
    }
    false
}

/// True when the command head is Cass, whether or not its syntax is one of the
/// frozen read commands. `Ok(None)` is the only answer that proves it is not.
fn cli_names_cass(command: &str) -> bool {
    !matches!(parse_cli(command), Ok(None))
}

/// The first JSON string `cmd` value in the text that names a Cass command.
///
/// Every `"cmd": "..."` pair is scanned, so an earlier ordinary command (a
/// date, a local script) does not hide a later Cass one. A quoted key and a
/// quoted value are required, so an arbitrary script is never parsed as JSON.
fn json_string_cmd(text: &str) -> Option<String> {
    static CMD_VALUE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pattern = CMD_VALUE.get_or_init(|| {
        regex::Regex::new(r#""cmd"\s*:\s*("(?:[^"\\]|\\.)*")"#).expect("a fixed regex")
    });
    for capture in pattern.captures_iter(text) {
        let Some(raw) = capture.get(1) else { continue };
        let Ok(command) = serde_json::from_str::<String>(raw.as_str()) else {
            continue;
        };
        if cli_names_cass(&command) {
            return Some(command);
        }
    }
    None
}

/// Does this result block declare a complete C04 envelope? Accepts the one
/// string form or the blocks of an `input_text` array, and looks one JSON
/// application layer down at the `output`/`content` text only.
fn output_declares_recall(output: &Value) -> bool {
    match output {
        Value::String(text) => text_declares_recall(text),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(input_text_block_text)
            .any(text_declares_recall),
        _ => false,
    }
}

/// Does this text declare a complete C04 envelope? One JSON application layer
/// is inspected for the `output` string or a `content` block's `text` only;
/// the application's own exit/error/completion fields are deliberately not
/// checked here. Those strict checks stay in the C07 exclusion path, so an
/// unqualified application state still preserves the body and its diagnostic.
fn text_declares_recall(text: &str) -> bool {
    if declares_recall_wrapper(text) {
        return true;
    }
    let Some(application) = application_object(text) else {
        return false;
    };
    if application
        .get("output")
        .and_then(Value::as_str)
        .is_some_and(declares_recall_wrapper)
    {
        return true;
    }
    application
        .get("content")
        .and_then(Value::as_array)
        .is_some_and(|blocks| {
            blocks
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .any(declares_recall_wrapper)
        })
}

/// Whether this `exec` record is a recall candidate at all.
///
/// The answer only decides whether a diagnostic is reported: `false` means the
/// row is ordinary work and stays preserved with no count, and `true` only
/// lets the existing strict C07 checks run. It never authorizes an exclusion.
fn exec_recall_candidate_hint(args: Option<&Value>, raw_record: &Value) -> bool {
    let named_call = match args {
        Some(Value::String(expression)) => exec_text_names_a_cass_call(expression),
        // An object argument is not a supported C07 form; its `cmd` string is
        // read as the same hint and nothing else.
        Some(Value::Object(members)) => members
            .get("cmd")
            .and_then(Value::as_str)
            .is_some_and(cli_names_cass),
        _ => false,
    };
    named_call
        || raw_record
            .get("payload")
            .and_then(|payload| payload.get("output"))
            .is_some_and(output_declares_recall)
}

/// Ticket 07 entry: C07 judgment against the *original* record, while every
/// other path delegates to the already-verified [`decide`].
///
/// The new facts used here are only:
/// * the source call row's real position (`paired_call_index_for`) and its
///   `extra.raw_role`, so a same-named `function_call` is not mistaken for
///   the supported `custom_tool_call` shape;
/// * the raw `payload.output` block structure, so the transport description
///   and the one application result are proved without guessing from the
///   flattened `NormalizedMessage.content`;
/// * the existing result-block locator, so an ambiguous/mismatched result is
///   never revived.
///
/// `raw_record` is read only; this function mutates nothing. `apply` later
/// hashes and clears the original complete body, still measured over this
/// message's full projected text, never over the inner XML.
pub(crate) fn decide_for_record(
    conv: &NormalizedConversation,
    idx: usize,
    event: &RawEvent,
    ctx: &PairingContext,
    paths_cfg: &ExcludedContextPaths,
    raw_record: &Value,
) -> Outcome {
    let Some(msg) = conv.messages.get(idx) else {
        return Outcome::Preserve(None);
    };
    let agent_slug = conv.agent_slug.as_str();
    if agent_slug != "codex" || msg.role != "tool_result" {
        return decide(msg, idx, event, ctx, agent_slug, paths_cfg);
    }

    let Some(call) = ctx.paired_call_for(idx) else {
        if custom_tool_output_payload(raw_record).is_some_and(complete_unpaired_recall) {
            return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
        }
        return decide(msg, idx, event, ctx, agent_slug, paths_cfg);
    };

    // Other paired tools keep the verified MCP/direct-CLI/R2/R3 judgment.
    if call.tool_name != "exec" {
        return decide(msg, idx, event, ctx, agent_slug, paths_cfg);
    }

    // Task10: an `exec` whose own call text and result show no Cass evidence is
    // ordinary work (a date literal, a local script, a plain pipeline). It
    // stays preserved without a diagnostic, so the uncovered counters describe
    // real candidates rather than every exec call. This hint can only remove a
    // count; it never authorizes an exclusion, and a recognized candidate
    // still runs every strict check below.
    if !exec_recall_candidate_hint(call.args.as_ref(), raw_record) {
        return Outcome::Preserve(None);
    }

    // From here on this is a candidate `exec` call. Every missing proof is a
    // bounded preserve, never an exclusion and never a legacy fallback that
    // could delete an ordinary same-named tool's output.
    let Some(call_idx) = ctx.paired_call_index_for(idx) else {
        return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
    };
    let Some(source_row) = conv.messages.get(call_idx) else {
        return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
    };
    if source_row.role != "tool_call"
        || source_row.extra.get("raw_role").and_then(Value::as_str) != Some("custom_tool_call")
    {
        return Outcome::Preserve(Some(UncoveredReason::UnsupportedShell));
    }
    let Some(args) = call.args.as_ref() else {
        return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
    };
    let Value::String(expression) = args else {
        return Outcome::Preserve(Some(UncoveredReason::UnsupportedShell));
    };
    let target_blocks = exclusion::tool_result_block_indices(event, call.tool_call_id.as_deref());
    if target_blocks.is_empty() {
        return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
    }

    let Some(payload) = custom_tool_output_payload(raw_record) else {
        return Outcome::Preserve(Some(UncoveredReason::UnsupportedShell));
    };
    if let Some(raw_call_id) = payload.get("call_id").and_then(Value::as_str)
        && call.tool_call_id.as_deref() != Some(raw_call_id)
    {
        // Another row's output cannot stand in for this call.
        return Outcome::Preserve(Some(UncoveredReason::UnpairedResult));
    }

    let Some((target, input)) = parse_exec_literal(expression) else {
        return Outcome::Preserve(Some(UncoveredReason::UnsupportedShell));
    };
    let (tool, source_args) = match target {
        ExecTarget::Cli => {
            let Some(command) = input.get("cmd").and_then(Value::as_str) else {
                return Outcome::Preserve(Some(UncoveredReason::UnsupportedShell));
            };
            match parse_cli(command) {
                Ok(Some(invocation)) => (invocation.tool, invocation.args),
                // A proven CASS expression whose command is not one frozen
                // read command is unsupported, not "not Cass".
                _ => return Outcome::Preserve(Some(UncoveredReason::UnsupportedShell)),
            }
        }
        ExecTarget::Mcp(tool) => (tool, input.clone()),
    };

    let Some(output) = payload.get("output") else {
        return Outcome::Preserve(Some(UncoveredReason::UnsupportedShell));
    };
    let Some(application) = application_text(output).and_then(application_object) else {
        return Outcome::Preserve(Some(UncoveredReason::UnsupportedShell));
    };
    let wrapper = match target {
        ExecTarget::Cli => cli_application_output(&application),
        ExecTarget::Mcp(_) => mcp_application_text(&application),
    };
    let Some(wrapper) = wrapper else {
        return Outcome::Preserve(Some(UncoveredReason::UnsupportedShell));
    };
    if recall_output::decode(wrapper, tool).is_err() {
        return Outcome::Preserve(Some(UncoveredReason::InvalidRecallFormat));
    }

    let decision = Decision {
        reason: ExclusionReason::CassRecall,
        anchor: ExclusionAnchor {
            tool_call_id: call.tool_call_id.clone(),
            // The actual shell tool (`exec`), never a disguised MCP name.
            tool_name: Some(call.tool_name.clone()),
            paths: None,
            shell: None,
        },
        event_key: event.event_key.clone(),
        target_blocks,
    };
    match parse_result(tool, wrapper, &source_args) {
        Ok(src) => Outcome::Exclude(Exclusion { decision, src: Some(src), parse_error: None }),
        Err(_) => Outcome::Preserve(Some(UncoveredReason::InvalidRecallFormat)),
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

    /// The same proven pair, but the call row carried no captured arguments at
    /// all (the native identity samples: strong names from Task18a, bare names
    /// from Task18e).
    fn fixture_without_args(
        tool_name: &str,
        content: &str,
    ) -> (NormalizedMessage, RawEvent, PairingContext) {
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let ctx = PairingContext::build(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: tool_name.to_string(),
                args: None,
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

    // Task18a: the full server-namespaced name proves identity by itself, so a
    // missing argument capture must not turn a completed recall into
    // `unpaired_result`. Source extraction still reads only what the result
    // and any available arguments actually contain.
    #[test]
    fn mcp_v2_native_strong_missing_args_excludes_search() {
        let content = recall_output::encode(RecallTool::Search, &search_value()).expect("encode");
        let (m, event, ctx) =
            fixture_without_args("mcp__cass-mcp__cass_search", &content);
        let Outcome::Exclude(exclusion) = decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg())
        else {
            panic!("a paired strong identity without args must still exclude");
        };
        assert_eq!(exclusion.parse_error, None, "the valid envelope has no parse error");
        assert_eq!(
            exclusion.src,
            Some(search_src()),
            "the source is extracted from the result alone"
        );
        assert_eq!(exclusion.decision.reason, ExclusionReason::CassRecall);
    }

    #[test]
    fn mcp_v2_native_strong_missing_args_expand_fabricates_no_source() {
        let value = json!([
            {"line": 1, "role": "user", "is_target": false, "content": "before"},
            {"line": 3, "role": "assistant", "is_target": true, "content": "target"},
        ]);
        let content = recall_output::encode(RecallTool::Expand, &value).expect("encode");
        let (m, event, ctx) = fixture_without_args("mcp__cass-mcp__cass_expand", &content);
        let Outcome::Exclude(exclusion) = decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg())
        else {
            panic!("a paired strong expand without args must still exclude");
        };
        assert_eq!(exclusion.parse_error, None);
        assert_eq!(
            exclusion.src,
            Some(RecallSrc::default()),
            "without the expand target arguments no source is invented"
        );
    }

    // Task18e: a complete C04 envelope proves a bare identity by itself. The
    // captured call arguments are not an identity proof -- they only feed
    // source extraction -- so an absent argument capture must not turn a
    // completed recall into `unpaired_result`. The four tools are the whole
    // positive matrix, and both supported connectors judge them the same way.
    #[test]
    fn mcp_v2_native_missing_args_bare_four_tools_exclude_with_c04() {
        let cases = vec![
            (RecallTool::Search, "cass_search", search_value(), search_src()),
            (
                RecallTool::Expand,
                "cass_expand",
                json!([
                    {"line": 1, "role": "user", "is_target": false, "content": "before"},
                    {"line": 3, "role": "assistant", "is_target": true, "content": "target"},
                ]),
                RecallSrc::default(),
            ),
            (
                RecallTool::Sessions,
                "cass_sessions",
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
                "cass_timeline",
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

        assert_eq!(cases.len(), 4, "four bare tools are the positive matrix");
        for agent in ["claude_code", "codex"] {
            for (tool, tool_name, value, expected_src) in &cases {
                let wrapper = recall_output::encode(*tool, value).expect("encode");
                let (m, event, ctx) = fixture_without_args(tool_name, &wrapper);
                let Outcome::Exclude(exclusion) =
                    decide(&m, 1, &event, &ctx, agent, &paths_cfg())
                else {
                    panic!(
                        "{agent} {tool:?}: a paired bare identity with a complete C04 envelope \
                         must exclude without captured arguments"
                    );
                };
                assert_eq!(exclusion.parse_error, None, "{agent} {tool:?}: no parse error");
                assert_eq!(
                    exclusion.src.as_ref(),
                    Some(expected_src),
                    "{agent} {tool:?}: the source comes from the result alone"
                );
                assert_eq!(exclusion.decision.reason, ExclusionReason::CassRecall);
            }
        }
    }

    // Task18e: removing the argument gate only lets a *complete* C04 envelope
    // prove a bare identity. Every damaged or ambiguous body still stays. The
    // literal quantities are six non-overlapping counterexamples:
    //   * 4 x `invalid_recall_format` -- wrong version, wrong tool, mixed
    //     application text, truncated root;
    //   * 1 x `ambiguous_tool_identity` -- an ordinary body under a bare name;
    //   * 1 x `unpaired_result` -- a complete envelope with no R4 pair at all.
    #[test]
    fn mcp_v2_native_missing_args_bare_counterexamples_still_preserve() {
        let invalid = [
            r#"<cass_recall version="2" tool="cass_search">{"hits":[]}</cass_recall>"#.to_string(),
            recall_output::encode(RecallTool::Expand, &json!([{"line": 1, "is_target": true}]))
                .expect("encode"),
            format!(
                "prefix {}",
                recall_output::encode(RecallTool::Search, &json!({"hits": []})).expect("encode")
            ),
            r#"<cass_recall version="1" tool="cass_search">{"hits":[]"#.to_string(),
        ];
        assert_eq!(invalid.len(), 4, "four damaged wrappers stay preserved");
        for content in &invalid {
            let (m, event, ctx) = fixture_without_args("cass_search", content);
            assert_eq!(
                decide(&m, 1, &event, &ctx, "codex", &paths_cfg()),
                Outcome::Preserve(Some(UncoveredReason::InvalidRecallFormat)),
                "a damaged bare envelope stays preserved without arguments: {content}"
            );
        }

        let (ordinary, ordinary_event, ordinary_ctx) =
            fixture_without_args("cass_search", "ordinary tool output");
        assert_eq!(
            decide(&ordinary, 1, &ordinary_event, &ordinary_ctx, "codex", &paths_cfg()),
            Outcome::Preserve(Some(UncoveredReason::AmbiguousToolIdentity)),
            "an ordinary body under a bare name is ambiguous, with or without arguments"
        );

        let complete =
            recall_output::encode(RecallTool::Search, &json!({"hits": []})).expect("encode");
        let (unpaired, unpaired_event, _) = fixture_without_args("cass_search", &complete);
        assert_eq!(
            decide(
                &unpaired,
                1,
                &unpaired_event,
                &PairingContext::default(),
                "codex",
                &paths_cfg()
            ),
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult)),
            "a complete envelope without an R4 pair is never excluded"
        );
    }

    #[test]
    fn mcp_v2_native_missing_args_other_server_still_preserves() {
        let content = recall_output::encode(RecallTool::Search, &search_value()).expect("encode");
        let (m, event, ctx) = fixture_without_args("mcp__other-mcp__cass_search", &content);
        assert_eq!(
            decide(&m, 1, &event, &ctx, "claude_code", &paths_cfg()),
            Outcome::Preserve(None),
            "an unknown identity falls back to the legacy judgment before any argument gate"
        );
    }

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
        // Missing captured args on a bare identity with an ordinary body: the
        // R4 pair resolves, so what is missing is the C04 wrapper proof, not
        // the pairing. Task18e keeps this counterexample and only changes its
        // diagnosed reason from `unpaired_result` to `ambiguous_tool_identity`.
        // (A full server-namespaced name is excluded by its exact identity
        // even without args; that is covered by the
        // `mcp_v2_native_strong_missing_args_*` tests.)
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let no_args = PairingContext::build(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "cass_search".into(),
                args: None,
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        let message = msg("tool_result", "body");
        assert_eq!(
            decide(&message, 1, &event, &no_args, "claude_code", &paths_cfg()),
            Outcome::Preserve(Some(UncoveredReason::AmbiguousToolIdentity))
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

    // -- Ticket 06: limited direct-CLI syntax ------------------------------

    fn cli_sha() -> String {
        "0123456789abcdef".repeat(4)
    }

    fn assert_unsupported(command: &str) {
        assert_eq!(
            parse_cli(command),
            Err(UncoveredReason::UnsupportedShell),
            "{command}"
        );
    }

    fn assert_not_cass(command: &str) {
        assert_eq!(parse_cli(command), Ok(None), "{command}");
    }

    fn expand_value() -> Value {
        json!([
            {"line": 2, "role": "user", "is_target": false, "content": "before"},
            {"line": 3, "role": "assistant", "is_target": true, "content": "target"},
        ])
    }

    fn expand_src() -> RecallSrc {
        RecallSrc {
            sessions: vec!["/srv/sessions/e.jsonl".into()],
            hits: vec![RecallHit {
                source_id: "local".into(),
                source_path: "/srv/sessions/e.jsonl".into(),
                line_number: Some(3),
            }],
        }
    }

    fn sessions_value() -> Value {
        json!({"sessions": [{"source_id": "local", "path": "/srv/sessions/list.jsonl"}]})
    }

    fn sessions_src() -> RecallSrc {
        RecallSrc {
            sessions: vec!["/srv/sessions/list.jsonl".into()],
            hits: vec![RecallHit {
                source_id: "local".into(),
                source_path: "/srv/sessions/list.jsonl".into(),
                line_number: None,
            }],
        }
    }

    fn timeline_value() -> Value {
        json!({"range": {"start": 1, "end": 2}, "total_sessions": 1,
               "groups": {"hour": [{"source_id": "local", "source_path": "/srv/sessions/t.jsonl"}]}})
    }

    fn timeline_src() -> RecallSrc {
        RecallSrc {
            sessions: vec!["/srv/sessions/t.jsonl".into()],
            hits: vec![RecallHit {
                source_id: "local".into(),
                source_path: "/srv/sessions/t.jsonl".into(),
                line_number: None,
            }],
        }
    }

    #[test]
    fn mcp_v2_cli_parse_cli_recognizes_four_commands_and_cass_heads() {
        for (command, tool) in [
            ("cass search auth --recall", RecallTool::Search),
            (
                "cass-infinity expand /srv/sessions/e.jsonl -n 3 --json",
                RecallTool::Expand,
            ),
            ("/usr/local/bin/cass sessions --limit 5 --recall", RecallTool::Sessions),
            (
                "/opt/bin/cass-infinity timeline --group-by day --json",
                RecallTool::Timeline,
            ),
        ] {
            let invocation = parse_cli(command).unwrap().unwrap();
            assert_eq!(invocation.tool, tool, "{command}");
        }
        for command in [
            "cass search auth --recall",
            "cass sessions --limit 5 --recall",
            "cass timeline --group-by day --json",
        ] {
            assert_eq!(parse_cli(command).unwrap().unwrap().args, json!({}), "{command}");
        }

        for command in [
            "./cass search auth",
            "cassx search auth",
            "/usr/local/bin/cassx search auth",
            "/usr/bin/cass-fork search auth",
            "echo cass search auth",
            "echo cass; echo ordinary",
            "echo cass | cat",
            "FOO=1 echo cass",
        ] {
            assert_not_cass(command);
        }

        for command in ["cass", "cass --help", "cass help", "cass refresh", "cass current"] {
            assert_unsupported(command);
        }
    }

    #[test]
    fn mcp_v2_cli_parse_cli_search_option_table_and_boundaries() {
        for command in [
            "cass search --mode hybrid --vector-search-mode=exact --rerank --rrf-limit 200 \
             --rerank-limit=5 --api-config=P --embedding-profile E --rerank-profile R \
             --no-model-fallback --recall --agent a --agent=b --workspace /w \
             --workspace=/w2 --max-content-length 100 --max-tokens=50 --request-id r1 \
             --offset 0 -- \"auth query\"",
            "cass search --recall --robot-meta query",
            "cass search --since -7d query",
            "cass search --since=-7d --until now query",
            "cass search query --agent a --agent b",
        ] {
            assert!(matches!(parse_cli(command), Ok(Some(_))), "{command}");
        }

        for command in [
            "cass search q --source a --source b",
            "cass search q --rerank --rerank",
            "cass search q --json --robot",
            "cass search q --json --json",
            "cass search q --recall --json",
            "cass search q --recall --robot",
            "cass search q --recall --fields minimal",
            "cass search q --rrf-limit abc",
            "cass search q --rrf-limit=",
            "cass search q --rrf-limit -1",
            "cass search q --source",
            "cass search q --source --recall",
            "cass search q extra",
            "cass search",
            "cass search --",
            "cass search q -- bar",
            "cass search q --bogus",
            "cass search q --days 7",
            "cass search q --sessions-from -",
            "cass search q --help",
            "cass search --version",
            "cass search q --recall=true",
        ] {
            assert_unsupported(command);
        }

        // `--` turns `--help` into query data only when it is the single query.
        assert_eq!(
            parse_cli("cass search -- --help").unwrap().unwrap().tool,
            RecallTool::Search
        );
        assert_eq!(
            parse_cli("cass search --recall -- --help").unwrap().unwrap().tool,
            RecallTool::Search
        );
    }

    #[test]
    fn mcp_v2_cli_parse_cli_expand_location_modes_and_aliases() {
        let sha = cli_sha();
        let message_mode = format!(
            "cass expand /srv/sessions/e.jsonl --source local --message-id 42 \
             --expected-content-sha256 {sha} --context 3 --recall"
        );
        let invocation = parse_cli(&message_mode).unwrap().unwrap();
        assert_eq!(invocation.tool, RecallTool::Expand);
        assert_eq!(
            invocation.args,
            json!({"source_path": "/srv/sessions/e.jsonl", "source_id": "local"})
        );

        let alias_mode = format!(
            "cass expand /srv/sessions/e.jsonl --source_id local --message_id=42 \
             --expected_content_sha256={sha} --recall"
        );
        assert_eq!(
            parse_cli(&alias_mode).unwrap().unwrap().args,
            invocation.args,
            "published aliases normalize to the frozen table"
        );

        for command in [
            "cass expand /srv/sessions/e.jsonl -n 3 --recall".to_string(),
            "cass expand /srv/sessions/e.jsonl --line 3 --source local --recall".to_string(),
            "cass expand /srv/sessions/e.jsonl --line-number=3 -C 2 --recall".to_string(),
            "cass expand /srv/sessions/e.jsonl --line_number 3 --context=2 --json".to_string(),
            "cass expand /srv/sessions/e.jsonl -n 3".to_string(),
        ] {
            assert!(matches!(parse_cli(&command), Ok(Some(_))), "{command}");
        }

        for command in [
            "cass expand /srv/sessions/e.jsonl --recall".to_string(),
            "cass expand -n 3 --recall".to_string(),
            "cass expand /a /b -n 3".to_string(),
            "cass expand /srv/sessions/e.jsonl -n abc".to_string(),
            "cass expand /srv/sessions/e.jsonl -n -3".to_string(),
            "cass expand /srv/sessions/e.jsonl --context nope".to_string(),
            "cass expand /srv/sessions/e.jsonl -n 3 --line 4".to_string(),
            "cass expand /srv/sessions/e.jsonl -n 3 --source a --source b".to_string(),
            "cass expand /srv/sessions/e.jsonl -n 3 --bogus".to_string(),
            format!(
                "cass expand /srv/sessions/e.jsonl -n 3 --source local --message-id 42 \
                 --expected-content-sha256 {sha}"
            ),
            format!(
                "cass expand /srv/sessions/e.jsonl -n 3 --expected-content-sha256 {sha}"
            ),
            "cass expand /srv/sessions/e.jsonl --source local --message-id 42".to_string(),
            format!(
                "cass expand /srv/sessions/e.jsonl --message-id 42 --expected-content-sha256 {sha}"
            ),
            "cass expand /srv/sessions/e.jsonl --message-id 42 --source local \
             --expected-content-sha256 abc"
                .to_string(),
            "cass expand /srv/sessions/e.jsonl -n 3 --recall --json".to_string(),
        ] {
            assert_unsupported(&command);
        }
    }

    #[test]
    fn mcp_v2_cli_parse_cli_sessions_and_timeline_shapes() {
        for command in [
            "cass sessions",
            "cass sessions --limit 10 --workspace /w --since 2026-01-01 --recall",
            "cass sessions --limit=10 --since=-7d --json",
            "cass sessions --since -7d --json",
            "cass sessions --since -24h --recall",
            "cass timeline",
            "cass timeline --since -7d --until now --agent a --agent=b --source s \
             --group-by hour --json",
            "cass timeline --group-by=day --recall",
        ] {
            assert!(matches!(parse_cli(command), Ok(Some(_))), "{command}");
        }

        for command in [
            "cass sessions extra",
            "cass sessions --limit -1",
            "cass sessions --limit abc",
            "cass sessions --current",
            "cass sessions --recall --json",
            "cass sessions --recall --robot",
            "cass timeline extra",
            "cass timeline --today",
            "cass timeline --source a --source b",
            "cass timeline --agent a --recall --json",
            "cass timeline --group-by",
        ] {
            assert_unsupported(command);
        }
    }

    #[test]
    fn mcp_v2_cli_quoted_metacharacters_are_data_and_real_operators_preserved() {
        for command in [
            "cass search \"a|b\" --recall",
            "cass search 'a&b' --json",
            "cass search \"a<b>c\"",
            "cass search 'a;b'",
            "cass search '$(touch nope)'",
            "cass search '`touch nope`'",
            "cass search \"a\\$b\"",
            "cass search a\\|b",
            "cass search a\\&b",
            "cass search \"a b\"",
            "cass search 'a`b'",
            "cass search a~b",
        ] {
            assert!(matches!(parse_cli(command), Ok(Some(_))), "{command}");
        }

        for command in [
            "cass search a | cat",
            "cass search a|cat",
            "cass; echo ordinary",
            "cass;echo",
            "cass|cat",
            "cass>out",
            "cass&",
            "cass search a; cass search b",
            "cass search a;b",
            "cass search a && echo",
            "cass search a&b",
            "cass search a > out",
            "cass search a>out",
            "cass search a < in",
            "cass search $(touch marker)",
            "cass search `touch marker`",
            "cass search $HOME",
            "cass search \"a$b\"",
            "cass search \"a`b`\"",
            "cass search a\nb",
            "cass search *",
            "cass search ?",
            "cass search [ab]",
            "cass search {a,b}",
            "cass search (a)",
            "cass search ~/x",
            "cass search a # comment",
            "cass search a &",
            "FOO=1 cass search a",
            "A=1 B=2 cass search a",
            "FOO=1 /usr/bin/cass search a",
            "cass search \"unclosed",
            "cass search 'unclosed",
            "cass search a\\",
            "cass search a\\\nb",
        ] {
            assert_unsupported(command);
        }
    }

    #[test]
    fn mcp_v2_cli_parse_cli_never_executes_or_touches_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("executed");
        let marker = marker.to_string_lossy().to_string();

        for command in [
            format!("cass search \"$(touch {marker})\""),
            format!("cass search x | tee {marker}"),
            format!("cass search x > {marker}"),
            format!("cass search `touch {marker}`"),
        ] {
            assert_unsupported(&command);
            assert!(!std::path::Path::new(&marker).exists(), "{command} must not run");
        }
    }

    #[test]
    fn mcp_v2_cli_four_commands_json_and_recall_exclude_apply_marker2() {
        let cases = [
            (
                RecallTool::Search,
                "cass search \"auth error\" --recall",
                search_value(),
                search_src(),
            ),
            (
                RecallTool::Expand,
                "cass expand /srv/sessions/e.jsonl --source local -n 3 --recall",
                expand_value(),
                expand_src(),
            ),
            (
                RecallTool::Sessions,
                "cass sessions --limit 5 --recall",
                sessions_value(),
                sessions_src(),
            ),
            (
                RecallTool::Timeline,
                "cass timeline --since 2026-01-01 --group-by hour --recall",
                timeline_value(),
                timeline_src(),
            ),
        ];

        for (tool, command, value, expected_src) in cases {
            for recall in [false, true] {
                let content = if recall {
                    recall_output::encode(tool, &value).unwrap()
                } else {
                    value.to_string()
                };
                let (mut message, event, ctx) =
                    fixture("Bash", json!({ "command": command }), &content);
                message.extra = json!({
                    "message": {"content": [{"type": "tool_result", "text": content.clone()}]},
                    "toolUseResult": content.clone(),
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
                    panic!("{tool:?} direct CLI must be excluded (recall={recall})");
                };
                assert_eq!(judged.decision.reason, ExclusionReason::CassRecall);
                assert_eq!(judged.decision.target_blocks, vec![0]);
                assert_eq!(
                    judged.decision.anchor.tool_name.as_deref(),
                    Some("Bash"),
                    "the actual shell tool name is kept"
                );
                assert_eq!(judged.decision.anchor.tool_call_id.as_deref(), Some("t1"));
                assert_eq!(judged.src.as_ref(), Some(&expected_src), "{tool:?} source");
                assert!(judged.parse_error.is_none());

                let original = content.clone();
                let marker = apply_with_redaction(
                    &mut message,
                    &judged,
                    &mut MemoizingRedactor::new(),
                    "blobs/blake3/ab/abcd.raw",
                    7,
                    field_map_for("claude_code"),
                    false,
                );
                assert_eq!(marker.rule_version, 2);
                assert_eq!(message.content, "", "body must be cleared");
                assert_eq!(marker.bytes, original.len() as u64);
                assert_eq!(marker.sha256, sha256_hex(&original));
                assert_eq!(marker.src, Some(expected_src.clone()));
                assert_eq!(marker.parse_error, None);
                assert_eq!(marker.anchor, judged.decision.anchor);
                assert_eq!(marker.raw.blob, "blobs/blake3/ab/abcd.raw");
                assert_eq!(marker.raw.idx, 7);
                assert_eq!(marker.raw.event_key, "ek1");
                assert_eq!(marker.raw.blocks, vec![0]);
                assert_eq!(message.extra["message"]["content"][0]["text"]["redacted"], json!(true));
                assert_eq!(message.extra["toolUseResult"]["redacted"], json!(true));
                assert_eq!(message.snippets[0].snippet_text, Some(String::new()));
            }
        }
    }

    #[test]
    fn mcp_v2_cli_codex_exec_command_uses_cmd_and_keeps_actual_anchor() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let (mut message, event, ctx) = fixture(
            "exec_command",
            json!({"cmd": "cass search auth --recall"}),
            &wrapper,
        );
        let Outcome::Exclude(judged) =
            decide(&message, 1, &event, &ctx, "codex", &paths_cfg())
        else {
            panic!("codex exec_command must be recognized through cmd");
        };
        assert_eq!(judged.decision.anchor.tool_name.as_deref(), Some("exec_command"));
        assert_eq!(judged.src, Some(search_src()));

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

        // The wrong captured key proves nothing and stays on the legacy path.
        let (wrong_key, wrong_event, wrong_ctx) = fixture(
            "exec_command",
            json!({"command": "cass search auth --recall"}),
            &wrapper,
        );
        assert_eq!(
            decide(&wrong_key, 1, &wrong_event, &wrong_ctx, "codex", &paths_cfg()),
            Outcome::Preserve(None)
        );
        assert_eq!(wrong_key.content, wrapper);

        // claude_code's Bash reads `command`, not `cmd`.
        let (wrong_agent_key, wrong_agent_event, wrong_agent_ctx) =
            fixture("Bash", json!({"cmd": "cass search auth --recall"}), &wrapper);
        assert_eq!(
            decide(
                &wrong_agent_key,
                1,
                &wrong_agent_event,
                &wrong_agent_ctx,
                "claude_code",
                &paths_cfg()
            ),
            Outcome::Preserve(None)
        );
    }

    #[test]
    fn mcp_v2_cli_r4_counterexamples_do_not_delete() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();

        // Missing captured args on a known shell tool is not proof.
        let event = RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t1"))] };
        let no_args = PairingContext::build(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("t1".into()),
                tool_name: "Bash".into(),
                args: None,
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("t1".into()) },
        ]);
        assert_eq!(
            decide(&msg("tool_result", &wrapper), 1, &event, &no_args, "claude_code", &paths_cfg()),
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult))
        );

        // Wrong result block id.
        let (message, _, ctx) =
            fixture("Bash", json!({"command": "cass search auth --recall"}), &wrapper);
        let wrong_id_event =
            RawEvent { event_key: "ek1".into(), blocks: vec![tool_result_block(0, Some("t2"))] };
        assert_eq!(
            decide(&message, 1, &wrong_id_event, &ctx, "claude_code", &paths_cfg()),
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult))
        );

        // Two id-less result blocks: ambiguous target.
        let ambiguous_event = RawEvent {
            event_key: "ek1".into(),
            blocks: vec![tool_result_block(0, None), tool_result_block(1, None)],
        };
        let ambiguous_ctx = PairingContext::build(&[
            PairingCandidate::TurnBoundary,
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: None,
                tool_name: "Bash".into(),
                args: Some(json!({"command": "cass search auth --recall"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: None },
        ]);
        assert_eq!(
            decide(
                &message,
                2,
                &ambiguous_event,
                &ambiguous_ctx,
                "claude_code",
                &paths_cfg()
            ),
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult))
        );
        assert_eq!(message.content, wrapper);
    }

    #[test]
    fn mcp_v2_cli_unsupported_shell_and_non_cass_outputs_are_preserved() {
        for command in [
            "cass search auth --bogus",
            "cass refresh",
            "cass search auth | tee out.txt",
            "cass search $(echo auth)",
            "cass search --help",
            "FOO=1 cass search auth",
            "cass sessions-from x",
            "cass search \"unclosed",
        ] {
            let (message, event, ctx) =
                fixture("Bash", json!({"command": command}), "body");
            assert_eq!(
                decide(&message, 1, &event, &ctx, "claude_code", &paths_cfg()),
                Outcome::Preserve(Some(UncoveredReason::UnsupportedShell)),
                "{command}"
            );
            assert_eq!(message.content, "body");
        }

        // XML tags in a non-Cass command's output prove no Cassandra identity.
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let (echo_message, echo_event, echo_ctx) = fixture(
            "Bash",
            json!({"command": "echo '<cass_recall version=\"1\" tool=\"cass_search\">'"}),
            &wrapper,
        );
        assert_eq!(
            decide(&echo_message, 1, &echo_event, &echo_ctx, "claude_code", &paths_cfg()),
            Outcome::Preserve(None)
        );
        assert_eq!(echo_message.content, wrapper);

        // Unsupported connectors keep the legacy path untouched.
        let (unknown, unknown_event, unknown_ctx) =
            fixture("Bash", json!({"command": "cass search auth --recall"}), &wrapper);
        assert_eq!(
            decide(&unknown, 1, &unknown_event, &unknown_ctx, "openclaw", &paths_cfg()),
            Outcome::Preserve(None)
        );
        assert_eq!(unknown.content, wrapper);
    }

    #[test]
    fn mcp_v2_cli_damaged_empty_and_error_results_keep_bounded_sources() {
        // Damaged strong CLI output: excluded with the bounded reason.
        let (mut damaged, event, ctx) =
            fixture("Bash", json!({"command": "cass search auth --recall"}), "not a recall body");
        let Outcome::Exclude(judged) =
            decide(&damaged, 1, &event, &ctx, "claude_code", &paths_cfg())
        else {
            panic!("a proven direct CLI result is excluded even when damaged");
        };
        assert!(judged.src.is_none());
        assert_eq!(judged.parse_error.as_deref(), Some("invalid_recall_format"));
        let marker = apply_with_redaction(
            &mut damaged,
            &judged,
            &mut MemoizingRedactor::new(),
            "blob",
            0,
            field_map_for("claude_code"),
            false,
        );
        assert_eq!(marker.parse_error.as_deref(), Some("invalid_recall_format"));
        assert_eq!(damaged.content, "");

        // Error-shaped JSON: no invented source, no parse error.
        let (mut error_message, error_event, error_ctx) = fixture(
            "Bash",
            json!({"command": "cass search auth --json"}),
            r#"{"error": "cass_exit", "code": 3}"#,
        );
        let Outcome::Exclude(error_judged) =
            decide(&error_message, 1, &error_event, &error_ctx, "claude_code", &paths_cfg())
        else {
            panic!("a proven direct CLI error result is excluded");
        };
        assert_eq!(error_judged.src, Some(RecallSrc::default()));
        assert!(error_judged.parse_error.is_none());
        apply_with_redaction(
            &mut error_message,
            &error_judged,
            &mut MemoizingRedactor::new(),
            "blob",
            0,
            field_map_for("claude_code"),
            false,
        );
        assert_eq!(error_message.content, "");

        // Empty results: no fake source.
        for (command, content) in [
            ("cass expand /srv/sessions/e.jsonl -n 3 --json", "[]"),
            ("cass sessions --json", r#"{"sessions": []}"#),
            (
                "cass timeline --json",
                r#"{"range": {"start": 1, "end": 2}, "total_sessions": 0, "groups": {}}"#,
            ),
        ] {
            let (message, event, ctx) =
                fixture("Bash", json!({"command": command}), content);
            let Outcome::Exclude(judged) =
                decide(&message, 1, &event, &ctx, "claude_code", &paths_cfg())
            else {
                panic!("{command} must be excluded");
            };
            assert_eq!(judged.src, Some(RecallSrc::default()), "{command}");
            assert!(judged.parse_error.is_none(), "{command}");
        }

        // Expand line mode without --source cannot invent a source id.
        let (no_source, no_source_event, no_source_ctx) = fixture(
            "Bash",
            json!({"command": "cass expand /srv/sessions/e.jsonl -n 3 --json"}),
            &expand_value().to_string(),
        );
        let Outcome::Exclude(no_source_judged) = decide(
            &no_source,
            1,
            &no_source_event,
            &no_source_ctx,
            "claude_code",
            &paths_cfg(),
        ) else {
            panic!("expand line mode without --source is still a proven read command");
        };
        assert_eq!(no_source_judged.src, Some(RecallSrc::default()));
    }

    #[test]
    fn mcp_v2_cli_env_assignment_prefix_has_no_word_cap() {
        for count in [1usize, 17, 40] {
            let assignments: Vec<String> =
                (0..count).map(|index| format!("VAR{index}=literal")).collect();
            let prefix = assignments.join(" ");
            assert_unsupported(&format!("{prefix} cass sessions --json"));
            assert_unsupported(&format!("{prefix} /usr/bin/cass search auth"));
            assert_not_cass(&format!("{prefix} echo cass"));
        }
    }

    #[test]
    fn mcp_v2_cli_rework_sessions_since_and_compound_head_are_attributed() {
        // F06-1: the space form of the already-supported sessions --since is
        // a proven Sessions read; its literal value is not re-interpreted.
        let (mut message, event, ctx) = fixture(
            "Bash",
            json!({"command": "cass sessions --since -7d --json"}),
            &sessions_value().to_string(),
        );
        let Outcome::Exclude(judged) =
            decide(&message, 1, &event, &ctx, "claude_code", &paths_cfg())
        else {
            panic!("sessions --since -7d must be attributed to the Sessions read command");
        };
        assert_eq!(judged.decision.reason, ExclusionReason::CassRecall);
        assert_eq!(judged.decision.anchor.tool_name.as_deref(), Some("Bash"));
        assert_eq!(judged.src, Some(sessions_src()));
        let marker = apply_with_redaction(
            &mut message,
            &judged,
            &mut MemoizingRedactor::new(),
            "blob",
            0,
            field_map_for("claude_code"),
            false,
        );
        assert_eq!(marker.rule_version, 2);
        assert_eq!(message.content, "");

        // F06-2: a separator glued to the head still leaves Cass as the first
        // literal command head; the compound command is preserved, not claimed.
        for command in ["cass; echo ordinary", "cass;echo"] {
            let (compound, compound_event, compound_ctx) =
                fixture("Bash", json!({"command": command}), "ordinary output");
            assert_eq!(
                decide(
                    &compound,
                    1,
                    &compound_event,
                    &compound_ctx,
                    "claude_code",
                    &paths_cfg()
                ),
                Outcome::Preserve(Some(UncoveredReason::UnsupportedShell)),
                "{command}"
            );
            assert_eq!(compound.content, "ordinary output");
        }

        // F06-3: no numeric cap on the assignment prefix.
        let assignments: Vec<String> =
            (0..17).map(|index| format!("VAR{index}=literal")).collect();
        let command = format!("{} cass sessions --json", assignments.join(" "));
        let (assigned, assigned_event, assigned_ctx) =
            fixture("Bash", json!({"command": command}), &sessions_value().to_string());
        assert_eq!(
            decide(
                &assigned,
                1,
                &assigned_event,
                &assigned_ctx,
                "claude_code",
                &paths_cfg()
            ),
            Outcome::Preserve(Some(UncoveredReason::UnsupportedShell))
        );
        assert_eq!(assigned.content, sessions_value().to_string());
    }

    // ==========================================================================
    // Ticket 07: C07 synchronous single-call wrapper (`mcp_v2_exec_`).
    // ==========================================================================

    use franken_agent_detection::NormalizedInvocation;
    use std::path::PathBuf;

    fn flatten_output(output: &Value) -> String {
        match output {
            Value::String(text) => text.clone(),
            Value::Array(blocks) => blocks
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n"),
            _ => String::new(),
        }
    }

    fn header_text(wall: &str) -> String {
        format!("Script completed\nWall time {wall} seconds\nOutput:")
    }

    /// The array output of one CLI application result, with the exact
    /// transport description in front.
    fn cli_output(wall: &str, application: &Value) -> Value {
        json!([
            {"type": "input_text", "text": header_text(wall)},
            {"type": "input_text", "text": application.to_string()},
        ])
    }

    /// The string output form: one JSON application result, no header.
    fn cli_output_string(application: &Value) -> Value {
        Value::String(application.to_string())
    }

    fn mcp_output(application: &Value) -> Value {
        json!([{"type": "input_text", "text": application.to_string()}])
    }

    fn cli_application(wrapper: &str) -> Value {
        json!({"exit_code": 0, "output": wrapper, "wall_time_seconds": 0.25, "chunk_id": "c1"})
    }

    fn mcp_application(wrapper: &str) -> Value {
        json!({"content": [{"type": "text", "text": wrapper}]})
    }

    /// The actual 2026-07-28 SDK result shape: `content`/`isError` plus the
    /// protocol completion metadata `resultType = "complete"`. The old 2025
    /// protocol omits `resultType`, so both shapes must be accepted.
    fn mcp_application_2026(wrapper: &str) -> Value {
        json!({
            "content": [{"type": "text", "text": wrapper}],
            "isError": false,
            "resultType": "complete",
        })
    }

    fn cli_expression(command: &str) -> String {
        format!("text(await tools.exec_command({}));", json!({"cmd": command}))
    }

    fn mcp_expression(method: &str, input: Value) -> String {
        format!("text(await tools.{method}({input}));")
    }

    fn codex_message(role: &str, content: &str, extra: Value) -> NormalizedMessage {
        NormalizedMessage {
            idx: 0,
            role: role.to_string(),
            author: None,
            created_at: None,
            content: content.to_string(),
            extra,
            snippets: Vec::new(),
            invocations: Vec::new(),
        }
    }

    fn codex_call_row(expression: &str, call_id: Option<&str>, raw_role: &str) -> NormalizedMessage {
        let mut row = codex_message(
            "tool_call",
            "",
            json!({"raw_role": raw_role, "tool_call_id": call_id}),
        );
        row.invocations = vec![NormalizedInvocation {
            kind: "tool".to_string(),
            name: "exec".to_string(),
            raw_name: None,
            call_id: call_id.map(str::to_string),
            arguments: Some(Value::String(expression.to_string())),
        }];
        row
    }

    fn codex_result_row(output: &Value, raw_record: &Value) -> NormalizedMessage {
        codex_message("tool_result", &flatten_output(output), raw_record.clone())
    }

    fn codex_conversation(messages: Vec<NormalizedMessage>) -> NormalizedConversation {
        NormalizedConversation {
            agent_slug: "codex".to_string(),
            external_id: None,
            title: None,
            workspace: None,
            source_path: PathBuf::from("/srv/cc/rollout-t07.jsonl"),
            started_at: None,
            ended_at: None,
            metadata: json!({}),
            messages,
        }
    }

    fn result_raw_record(call_id: Option<&str>, output: &Value, payload_type: &str) -> Value {
        json!({
            "type": "response_item",
            "timestamp": "2026-10-22T00:00:01Z",
            "payload": {"type": payload_type, "call_id": call_id, "output": output},
        })
    }

    /// Two-message Codex pair: one `exec` custom_tool_call and its
    /// custom_tool_call_output, with the same block facts R4/`apply` use.
    fn exec_fixture(
        expression: &str,
        output: Value,
    ) -> (NormalizedConversation, Vec<RawEvent>, Value) {
        let call_id = "call-t07";
        let raw_record = result_raw_record(Some(call_id), &output, "custom_tool_call_output");
        let call = codex_call_row(expression, Some(call_id), "custom_tool_call");
        let result = codex_result_row(&output, &raw_record);
        let conv = codex_conversation(vec![call, result]);
        let events = vec![
            RawEvent {
                event_key: "line:1".into(),
                blocks: vec![RawBlock {
                    index: 0,
                    kind: BlockKind::ToolUse,
                    tool_use_id: Some(call_id.into()),
                    tool_name: Some("exec".into()),
                    args: Some(Value::String(expression.into())),
                }],
            },
            RawEvent {
                event_key: "line:2".into(),
                blocks: vec![tool_result_block(0, Some(call_id))],
            },
        ];
        (conv, events, raw_record)
    }

    fn exec_outcome(expression: &str, output: Value) -> (Outcome, NormalizedConversation, Value) {
        let (conv, events, raw_record) = exec_fixture(expression, output);
        let ctx = PairingContext::build(&crate::indexer::build_pairing_candidates(&conv));
        (
            decide_for_record(&conv, 1, &events[1], &ctx, &paths_cfg(), &raw_record),
            conv,
            raw_record,
        )
    }

    fn assert_preserved(outcome: Outcome, reason: UncoveredReason) {
        assert_eq!(outcome, Outcome::Preserve(Some(reason)));
    }

    // ========================================================================
    // Ticket 06: the frozen L01-L24 and B01-B20 literal matrix.
    //
    // Both fixtures are copied byte-for-byte from the batch roadmap and are
    // compiled in here, so the assertions cannot drift from the frozen input.
    // Each case ID appears exactly once; the B cases attach to the test of
    // their declared `parent_test_case` rather than adding named targets.
    // ========================================================================

    const ALIEN_LITERALS: &str = include_str!("../../tests/fixtures/alien_codex/literals.json");
    const ALIEN_LITERAL_BOUNDARIES: &str =
        include_str!("../../tests/fixtures/alien_codex/literal_boundaries.json");

    fn alien_case(fixture: &str, id: &str) -> Value {
        let root: Value = serde_json::from_str(fixture).expect("frozen fixture JSON");
        let matches: Vec<&Value> = root["cases"]
            .as_array()
            .expect("cases array")
            .iter()
            .filter(|case| case["id"].as_str() == Some(id))
            .collect();
        assert_eq!(matches.len(), 1, "case {id} must appear exactly once");
        matches[0].clone()
    }

    fn alien_literal_case(id: &str) -> Value {
        alien_case(ALIEN_LITERALS, id)
    }

    fn alien_boundary_case(id: &str) -> Value {
        alien_case(ALIEN_LITERAL_BOUNDARIES, id)
    }

    fn recall_tool_method(tool: RecallTool) -> &'static str {
        match tool {
            RecallTool::Search => "mcp__cass_mcp__cass_search",
            RecallTool::Expand => "mcp__cass_mcp__cass_expand",
            RecallTool::Sessions => "mcp__cass_mcp__cass_sessions",
            RecallTool::Timeline => "mcp__cass_mcp__cass_timeline",
        }
    }

    fn alien_tool_value(tool: RecallTool) -> Value {
        match tool {
            RecallTool::Search => search_value(),
            RecallTool::Expand => expand_value(),
            RecallTool::Sessions => sessions_value(),
            RecallTool::Timeline => timeline_value(),
        }
    }

    /// Judge one frozen case the way production does. A supported case must
    /// parse to the exact method and the original argument value, and the
    /// same expression fed through the existing `exec_fixture` /
    /// `decide_for_record` path with a complete MCP record must really be
    /// excluded. An unsupported case must parse to `None` and reach the
    /// production `unsupported_shell` preserve; a C04 result is supplied so
    /// the row is a proven candidate, which is the only way that bounded
    /// reason can be reached.
    fn assert_alien_literal_case(case: &Value) {
        let id = case["id"].as_str().expect("case id");
        let expression = case["expression"].as_str().expect("case expression");
        let expected = &case["expected"];
        let supported = expected["supported"].as_bool().expect("case supported");
        println!("case {id}: supported={supported}");

        if supported {
            let (target, args) = parse_exec_literal(expression)
                .unwrap_or_else(|| panic!("{id}: expected a supported literal"));
            let ExecTarget::Mcp(tool) = target else {
                panic!("{id}: only the four MCP methods are supported");
            };
            let method = expected["method"].as_str().expect("case method");
            assert_eq!(recall_tool_method(tool), method, "{id}: method");
            assert_eq!(args, expected["args"], "{id}: original argument value");

            let wrapper = recall_output::encode(tool, &alien_tool_value(tool))
                .expect("frozen wrapper encodes");
            let (outcome, _, _) = exec_outcome(expression, mcp_output(&mcp_application(&wrapper)));
            let Outcome::Exclude(judged) = outcome else {
                panic!("{id}: the production path must exclude this literal, got {outcome:?}");
            };
            assert!(judged.parse_error.is_none(), "{id}: no parse error");
            println!("case {id}: excluded through decide_for_record");
        } else {
            assert!(
                parse_exec_literal(expression).is_none(),
                "{id}: an unsupported literal must not parse"
            );
            let wrapper = recall_output::encode(RecallTool::Search, &search_value())
                .expect("frozen wrapper encodes");
            let (outcome, _, _) = exec_outcome(expression, mcp_output(&mcp_application(&wrapper)));
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
            println!("case {id}: preserved unsupported_shell");
        }
    }

    fn assert_alien_literal_group(id: &str, boundary_ids: &[&str]) {
        assert_alien_literal_case(&alien_literal_case(id));
        for boundary_id in boundary_ids {
            let case = alien_boundary_case(boundary_id);
            assert_eq!(
                case["parent_test_case"].as_str(),
                Some(id),
                "{boundary_id} must attach to {id}"
            );
            assert_alien_literal_case(&case);
        }
    }

    // ========================================================================
    // Rework R1: keyword token boundaries, the old outer trim, and the old
    // strict JSON recursion boundary. Each case stays inside an existing
    // named test and prints its own R1 label, so the 24 named targets and the
    // frozen fixture bytes do not change.
    // ========================================================================

    fn assert_r1_supported(label: &str, expression: &str, tool: RecallTool, expected: Value) {
        let (target, args) = parse_exec_literal(expression)
            .unwrap_or_else(|| panic!("{label}: expected a supported literal"));
        let ExecTarget::Mcp(actual) = target else {
            panic!("{label}: only the four MCP methods are supported");
        };
        assert_eq!(
            recall_tool_method(actual),
            recall_tool_method(tool),
            "{label}: method"
        );
        assert_eq!(args, expected, "{label}: original argument value");

        let wrapper =
            recall_output::encode(tool, &alien_tool_value(tool)).expect("frozen wrapper encodes");
        let (outcome, _, _) = exec_outcome(expression, mcp_output(&mcp_application(&wrapper)));
        let Outcome::Exclude(judged) = outcome else {
            panic!("{label}: the production path must exclude this literal, got {outcome:?}");
        };
        assert!(judged.parse_error.is_none(), "{label}: no parse error");
        println!("case {label}: excluded through decide_for_record");
    }

    fn assert_r1_unsupported(label: &str, expression: &str) {
        assert!(
            parse_exec_literal(expression).is_none(),
            "{label}: an unsupported literal must not parse"
        );
        let wrapper = recall_output::encode(RecallTool::Search, &search_value())
            .expect("frozen wrapper encodes");
        let (outcome, _, _) = exec_outcome(expression, mcp_output(&mcp_application(&wrapper)));
        assert_preserved(outcome, UncoveredReason::UnsupportedShell);
        println!("case {label}: preserved unsupported_shell");
    }

    fn r1_expression(args: &str) -> String {
        format!("text(await tools.mcp__cass_mcp__cass_search({args}));")
    }

    /// `{"query": [[...0...]]}` with `levels` arrays.
    fn r1_array_args(levels: usize) -> (String, Value) {
        let args = format!(
            "{{\"query\":{}{}{}}}",
            "[".repeat(levels),
            "0",
            "]".repeat(levels)
        );
        let mut value = json!(0);
        for _ in 0..levels {
            value = json!([value]);
        }
        (args, json!({"query": value}))
    }

    /// `{"query": [[...[]...]]}` with `levels` empty arrays.
    fn r1_empty_array_args(levels: usize) -> (String, Value) {
        let args = format!("{{\"query\":{}{}}}", "[".repeat(levels), "]".repeat(levels));
        let mut value = json!([]);
        for _ in 1..levels {
            value = json!([value]);
        }
        (args, json!({"query": value}))
    }

    /// `{"query": {"x": {"x": ... 0 ...}}}` with `levels` nested objects
    /// under `query`.
    fn r1_object_args(levels: usize) -> (String, Value) {
        let args = format!(
            "{{\"query\":{}{}{}}}",
            "{\"x\":".repeat(levels),
            "0",
            "}".repeat(levels)
        );
        let mut value = json!(0);
        for _ in 0..levels {
            value = json!({"x": value});
        }
        (args, json!({"query": value}))
    }

    #[test]
    fn alien_codex_literal_l01() {
        assert_alien_literal_group("L01", &[]);
    }

    #[test]
    fn alien_codex_literal_l02() {
        assert_alien_literal_group("L02", &[]);
    }

    #[test]
    fn alien_codex_literal_l03() {
        assert_alien_literal_group("L03", &[]);
    }

    #[test]
    fn alien_codex_literal_l04() {
        assert_alien_literal_group("L04", &[]);
    }

    #[test]
    fn alien_codex_literal_l05() {
        assert_alien_literal_group("L05", &["B01", "B02", "B03", "B04", "B20"]);

        // R1-3 accepted side: 126 nested containers plus the argument object
        // is 127, the deepest value the old strict JSON path accepted.
        let (args, expected) = r1_array_args(126);
        assert_r1_supported(
            "R1-3-array-126",
            &r1_expression(&args),
            RecallTool::Search,
            expected,
        );
        let (args, expected) = r1_empty_array_args(126);
        assert_r1_supported(
            "R1-3-empty-array-126",
            &r1_expression(&args),
            RecallTool::Search,
            expected,
        );
        let (args, expected) = r1_object_args(126);
        assert_r1_supported(
            "R1-3-object-126",
            &r1_expression(&args),
            RecallTool::Search,
            expected,
        );

        // R1-3 rejected side: 127 nested containers plus the argument object
        // is 128, the depth the old strict JSON path refused.
        let (args, _) = r1_array_args(127);
        assert_r1_unsupported("R1-3-array-127", &r1_expression(&args));
        let (args, _) = r1_empty_array_args(127);
        assert_r1_unsupported("R1-3-empty-array-127", &r1_expression(&args));
        let (args, _) = r1_object_args(127);
        assert_r1_unsupported("R1-3-object-127", &r1_expression(&args));
        // R1-3: refusal happens before the recursion, so a much deeper input
        // returns `None` instead of exhausting the stack.
        let (args, _) = r1_array_args(256);
        assert_r1_unsupported("R1-3-array-256", &r1_expression(&args));
    }

    #[test]
    fn alien_codex_literal_l06() {
        assert_alien_literal_group("L06", &[]);

        // R1-2: the old function trimmed the whole expression before matching,
        // so Unicode whitespace around the fixed shape is accepted again.
        let nbsp = '\u{00A0}';
        assert_r1_supported(
            "R1-2-outer-trim",
            &format!("{nbsp}{}{nbsp}", r1_expression("{\"query\":\"x\"}")),
            RecallTool::Search,
            json!({"query": "x"}),
        );
        // R1-2: trimming never reaches the argument values.
        assert_r1_supported(
            "R1-2-string-value",
            &r1_expression("{\"query\":\"a\u{00A0}b\"}"),
            RecallTool::Search,
            json!({"query": "a\u{00A0}b"}),
        );
    }

    #[test]
    fn alien_codex_literal_l07() {
        assert_alien_literal_group("L07", &["B12"]);
    }

    #[test]
    fn alien_codex_literal_l08() {
        assert_alien_literal_group("L08", &[]);
    }

    #[test]
    fn alien_codex_literal_l09() {
        assert_alien_literal_group("L09", &["B05"]);
    }

    #[test]
    fn alien_codex_literal_l10() {
        assert_alien_literal_group("L10", &["B06"]);
    }

    #[test]
    fn alien_codex_literal_l11() {
        assert_alien_literal_group("L11", &["B07"]);
    }

    #[test]
    fn alien_codex_literal_l12() {
        assert_alien_literal_group("L12", &["B08"]);
    }

    #[test]
    fn alien_codex_literal_l13() {
        assert_alien_literal_group("L13", &["B09", "B10", "B11"]);
    }

    #[test]
    fn alien_codex_literal_l14() {
        assert_alien_literal_group("L14", &[]);
    }

    #[test]
    fn alien_codex_literal_l15() {
        assert_alien_literal_group("L15", &["B13"]);
    }

    #[test]
    fn alien_codex_literal_l16() {
        assert_alien_literal_group("L16", &["B14"]);
    }

    #[test]
    fn alien_codex_literal_l17() {
        assert_alien_literal_group("L17", &[]);
    }

    #[test]
    fn alien_codex_literal_l18() {
        assert_alien_literal_group("L18", &["B15"]);
    }

    #[test]
    fn alien_codex_literal_l19() {
        assert_alien_literal_group("L19", &[]);
    }

    #[test]
    fn alien_codex_literal_l20() {
        assert_alien_literal_group("L20", &["B16", "B17", "B18"]);
    }

    #[test]
    fn alien_codex_literal_l21() {
        assert_alien_literal_group("L21", &["B19"]);
    }

    #[test]
    fn alien_codex_literal_l22() {
        assert_alien_literal_group("L22", &[]);

        // R1-1: a keyword ends at a token boundary. `awaittools` is one
        // identifier, not `await tools`, so this is not the fixed shape.
        assert_r1_unsupported(
            "R1-1-awaittools",
            "text(awaittools.mcp__cass_mcp__cass_search({\"query\":\"x\"}));",
        );
        // R1-1: the same boundary applies to the value keywords.
        assert_r1_unsupported(
            "R1-1-trueish",
            "text(await tools.mcp__cass_mcp__cass_search({\"query\":trueish}));",
        );

        // R1-2: only the whole expression is trimmed; separator whitespace
        // inside the fixed shape stays ASCII.
        assert_r1_unsupported(
            "R1-2-inner-nbsp",
            "text(\u{00A0}await tools.mcp__cass_mcp__cass_search({\"query\":\"x\"}));",
        );
    }

    #[test]
    fn alien_codex_literal_l23() {
        assert_alien_literal_group("L23", &[]);
    }

    #[test]
    fn alien_codex_literal_l24() {
        assert_alien_literal_group("L24", &[]);
    }

    /// Task10: the candidate hint separates ordinary `exec` work (a date
    /// literal, a local script) from a recognized Cass call, using literal
    /// evidence only.
    #[test]
    fn mcp_activate_v2_hint_separates_ordinary_exec_from_cass_candidates() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let cass_result = result_raw_record(
            Some("call-t10"),
            &cli_output_string(&cli_application(&wrapper)),
            "custom_tool_call_output",
        );
        let ordinary_result = result_raw_record(
            Some("call-t10"),
            &Value::String("2026-10-22".to_string()),
            "custom_tool_call_output",
        );

        for expression in [
            cli_expression("cass search needle --recall"),
            cli_expression("cass search needle --recall | head -5"),
            mcp_expression("mcp__cass_mcp__cass_sessions", json!({"limit": 5})),
            "const r = await tools.exec_command({\"cmd\":\"cass search needle --recall\"}); text(r);"
                .to_string(),
            "text(await tools.mcp__cass_mcp__cass_timeline({\"group_by\":\"hour\"}));".to_string(),
        ] {
            assert!(
                exec_recall_candidate_hint(Some(&Value::String(expression.clone())), &ordinary_result),
                "a Cass call literal is a candidate: {expression}"
            );
        }
        for expression in [
            cli_expression("date +%F"),
            "const d = new Date(); text(await tools.exec_command({\"cmd\":\"echo \" + d.toISOString()}));"
                .to_string(),
            "text(await tools.wait({\"cell_id\":\"1\"}));".to_string(),
            "text(await tools.exec_command({\"cmd\":42}));".to_string(),
        ] {
            assert!(
                !exec_recall_candidate_hint(Some(&Value::String(expression.clone())), &ordinary_result),
                "ordinary work is not a candidate: {expression}"
            );
        }

        // An object argument is never a supported C07 form; only its `cmd`
        // string is read as the hint.
        assert!(!exec_recall_candidate_hint(
            Some(&json!({"cmd": "ls -la"})),
            &ordinary_result
        ));
        assert!(exec_recall_candidate_hint(
            Some(&json!({"cmd": "cass sessions --limit 5 --recall"})),
            &ordinary_result
        ));

        // A complete result envelope is evidence even without call evidence.
        assert!(exec_recall_candidate_hint(
            Some(&Value::String("for (;;) {}".to_string())),
            &cass_result
        ));
        assert!(!exec_recall_candidate_hint(
            Some(&Value::String("for (;;) {}".to_string())),
            &ordinary_result
        ));
        assert!(!exec_recall_candidate_hint(None, &json!({})));

        // An earlier ordinary command must not hide a later Cass command.
        let date_then_cass = "const a = await tools.exec_command({\"cmd\":\"date +%F\"}); \
                              const b = await tools.exec_command({\"cmd\":\"cass search x --recall\"}); text(b);"
            .to_string();
        assert!(
            exec_recall_candidate_hint(Some(&Value::String(date_then_cass.clone())), &ordinary_result),
            "the scan continues past a non-Cass cmd: {date_then_cass}"
        );
        // ...and a script whose commands are all ordinary stays uncounted.
        let date_then_echo = "const a = await tools.exec_command({\"cmd\":\"date +%F\"}); \
                              const b = await tools.exec_command({\"cmd\":\"echo done\"}); text(b);"
            .to_string();
        assert!(!exec_recall_candidate_hint(
            Some(&Value::String(date_then_echo)),
            &ordinary_result
        ));

        // A declaration is evidence even when the application's own state is
        // not qualified for exclusion: the strict C07 checks still own the
        // delete decision, so the body stays and its diagnostic is counted.
        let failed_cli = Value::String(
            json!({"exit_code": 1, "session_id": "s-1", "output": wrapper}).to_string(),
        );
        let failed_cli_record = result_raw_record(
            Some("call-t10"),
            &failed_cli,
            "custom_tool_call_output",
        );
        let unknown_script = "for (;;) {}".to_string();
        assert!(exec_recall_candidate_hint(
            Some(&Value::String(unknown_script.clone())),
            &failed_cli_record
        ));
        let (outcome, _, _) = exec_outcome(&unknown_script, failed_cli);
        assert_preserved(outcome, UncoveredReason::UnsupportedShell);

        let failed_mcp = Value::String(
            json!({"isError": true, "content": [{"type": "text", "text": wrapper}]}).to_string(),
        );
        let failed_mcp_record = result_raw_record(
            Some("call-t10"),
            &failed_mcp,
            "custom_tool_call_output",
        );
        assert!(exec_recall_candidate_hint(
            Some(&Value::String(unknown_script.clone())),
            &failed_mcp_record
        ));
        let (outcome, _, _) = exec_outcome(&unknown_script, failed_mcp);
        assert_preserved(outcome, UncoveredReason::UnsupportedShell);
    }

    #[test]
    fn mcp_v2_exec_real_codex_cli_header_apply_hashes_original_full_body() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let application = cli_application(&wrapper);
        let output = cli_output("0.25", &application);
        let expression = cli_expression("cass search \"needle\" --recall");

        let call_line = json!({
            "type": "response_item",
            "timestamp": "2026-10-22T00:00:00Z",
            "payload": {
                "type": "custom_tool_call",
                "name": "exec",
                "input": expression,
                "call_id": "call-t07",
            },
        });
        let result_line = json!({
            "type": "response_item",
            "timestamp": "2026-10-22T00:00:01Z",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "call-t07",
                "output": output,
            },
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollout-t07.jsonl");
        std::fs::write(&path, format!("{call_line}\n{result_line}\n")).unwrap();
        let before = std::fs::read(&path).unwrap();

        let factory = crate::connectors::get_connector_factories()
            .into_iter()
            .find(|(name, _)| *name == "codex")
            .expect("codex connector factory must be registered")
            .1;
        let connector = factory();
        let scan_ctx = crate::connectors::ScanContext::with_roots(
            dir.path().to_path_buf(),
            vec![crate::connectors::ScanRoot::local(path.clone())],
            None,
        );
        let mut convs = connector.scan(&scan_ctx).expect("real codex scan must succeed");
        assert_eq!(convs.len(), 1);
        let mut conv = convs.pop().unwrap();
        assert_eq!(conv.agent_slug, "codex");
        assert_eq!(conv.messages.len(), 2);
        assert_eq!(conv.messages[0].role, "tool_call");
        assert_eq!(conv.messages[0].extra["raw_role"], "custom_tool_call");
        assert_eq!(
            conv.messages[0].invocations[0].arguments,
            Some(Value::String(expression.clone())),
            "the real connector must keep the literal JavaScript as Value::String"
        );
        assert_eq!(conv.messages[1].role, "tool_result");
        assert_eq!(conv.messages[1].extra["raw_role"], "custom_tool_call_output");

        let original = conv.messages[1].content.clone();
        assert!(original.starts_with("Script completed\nWall time 0.25 seconds\nOutput:\n"));
        assert!(original.contains("\"exit_code\":0"));
        assert!(
            original.contains(&serde_json::to_string(&wrapper).unwrap()),
            "the projected body carries the complete application JSON, not only the inner XML"
        );

        let events = exclusion::events_from_blob("codex", &path);
        assert_eq!(events.len(), 2);
        let pairing = PairingContext::build(&crate::indexer::build_pairing_candidates(&conv));
        assert_eq!(pairing.paired_call_index_for(1), Some(0));

        let Outcome::Exclude(judged) =
            decide_for_record(&conv, 1, &events[1], &pairing, &paths_cfg(), &result_line)
        else {
            panic!("a real paired C07 CLI result must be excluded");
        };
        assert_eq!(judged.decision.reason, ExclusionReason::CassRecall);
        assert_eq!(judged.decision.anchor.tool_name.as_deref(), Some("exec"));
        assert_eq!(judged.decision.anchor.tool_call_id.as_deref(), Some("call-t07"));
        assert_eq!(judged.decision.event_key, "line:2");
        assert_eq!(judged.decision.target_blocks, vec![0]);
        assert_eq!(judged.src.as_ref(), Some(&search_src()));
        assert!(judged.parse_error.is_none());

        let marker = apply_with_redaction(
            &mut conv.messages[1],
            &judged,
            &mut MemoizingRedactor::new(),
            path.to_str().unwrap(),
            1,
            field_map_for("codex"),
            false,
        );
        assert_eq!(marker.rule_version, 2);
        assert_eq!(conv.messages[1].content, "");
        assert_eq!(marker.bytes, original.len() as u64);
        assert_eq!(marker.sha256, sha256_hex(&original));
        assert_eq!(marker.raw.event_key, "line:2");
        assert_eq!(marker.raw.blocks, vec![0]);
        assert_eq!(marker.src, Some(search_src()));
        assert_eq!(conv.messages[1].extra["payload"]["output"]["redacted"], json!(true));
        assert_eq!(std::fs::read(&path).unwrap(), before, "raw mirror bytes stay untouched");

        // R7's same-event sibling copy clearing is unchanged: the sibling's
        // own ordinary text must survive.
        let mut sibling = codex_message(
            "user",
            "ordinary sibling prose",
            json!({"type": "response_item", "payload": {"type": "custom_tool_call_output", "output": output}}),
        );
        exclusion::apply_sibling(&mut sibling, &marker, field_map_for("codex"));
        assert_eq!(sibling.content, "ordinary sibling prose");
        assert_eq!(sibling.extra["payload"]["output"]["redacted"], json!(true));
    }

    #[test]
    fn mcp_v2_exec_real_codex_mcp_single_block_excludes_without_header() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let application = mcp_application(&wrapper);
        let output = mcp_output(&application);
        let expression = mcp_expression("mcp__cass_mcp__cass_search", json!({"query": "needle"}));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollout-t07-mcp.jsonl");
        let call_line = json!({
            "type": "response_item",
            "payload": {"type": "custom_tool_call", "name": "exec", "input": expression, "call_id": "call-m"},
        });
        let result_line = json!({
            "type": "response_item",
            "payload": {"type": "custom_tool_call_output", "call_id": "call-m", "output": output},
        });
        std::fs::write(&path, format!("{call_line}\n{result_line}\n")).unwrap();

        let connector = crate::connectors::get_connector_factories()
            .into_iter()
            .find(|(name, _)| *name == "codex")
            .unwrap()
            .1();
        let scan_ctx = crate::connectors::ScanContext::with_roots(
            dir.path().to_path_buf(),
            vec![crate::connectors::ScanRoot::local(path.clone())],
            None,
        );
        let mut conv = connector.scan(&scan_ctx).unwrap().pop().unwrap();
        let original = conv.messages[1].content.clone();
        assert_eq!(original, application.to_string());
        let events = exclusion::events_from_blob("codex", &path);
        let pairing = PairingContext::build(&crate::indexer::build_pairing_candidates(&conv));
        let Outcome::Exclude(judged) =
            decide_for_record(&conv, 1, &events[1], &pairing, &paths_cfg(), &result_line)
        else {
            panic!("a real paired C07 MCP result must be excluded");
        };
        assert_eq!(judged.src.as_ref(), Some(&search_src()));
        let marker = apply_with_redaction(
            &mut conv.messages[1],
            &judged,
            &mut MemoizingRedactor::new(),
            "blob",
            1,
            field_map_for("codex"),
            false,
        );
        assert_eq!(marker.sha256, sha256_hex(&original));
        assert_eq!(marker.bytes, original.len() as u64);
        assert_eq!(conv.messages[1].extra["payload"]["output"]["redacted"], json!(true));
    }

    #[test]
    fn mcp_v2_exec_real_codex_2026_result_type_complete_excludes() {
        // Real 2026-07-28 SDK result: `content`, `isError: false` and
        // `resultType: "complete"`. The field is protocol completion
        // metadata, not a second application body, so the one C04 wrapper
        // must still be decoded, excluded and hashed over the whole body.
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let application = mcp_application_2026(&wrapper);
        let output = mcp_output(&application);
        let expression = mcp_expression("mcp__cass_mcp__cass_search", json!({"query": "needle"}));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollout-t07-2026.jsonl");
        let call_line = json!({
            "type": "response_item",
            "payload": {"type": "custom_tool_call", "name": "exec", "input": expression, "call_id": "call-2026"},
        });
        let result_line = json!({
            "type": "response_item",
            "payload": {"type": "custom_tool_call_output", "call_id": "call-2026", "output": output},
        });
        std::fs::write(&path, format!("{call_line}\n{result_line}\n")).unwrap();

        let connector = crate::connectors::get_connector_factories()
            .into_iter()
            .find(|(name, _)| *name == "codex")
            .unwrap()
            .1();
        let scan_ctx = crate::connectors::ScanContext::with_roots(
            dir.path().to_path_buf(),
            vec![crate::connectors::ScanRoot::local(path.clone())],
            None,
        );
        let mut conv = connector.scan(&scan_ctx).unwrap().pop().unwrap();
        let original = conv.messages[1].content.clone();
        assert_eq!(original, application.to_string());
        assert!(original.contains("\"resultType\":\"complete\""));
        let events = exclusion::events_from_blob("codex", &path);
        let pairing = PairingContext::build(&crate::indexer::build_pairing_candidates(&conv));
        let Outcome::Exclude(judged) =
            decide_for_record(&conv, 1, &events[1], &pairing, &paths_cfg(), &result_line)
        else {
            panic!("the actual 2026 content/isError/resultType result must be excluded");
        };
        assert_eq!(judged.decision.reason, ExclusionReason::CassRecall);
        assert_eq!(judged.decision.anchor.tool_name.as_deref(), Some("exec"));
        assert_eq!(judged.src.as_ref(), Some(&search_src()));
        assert!(judged.parse_error.is_none());

        let marker = apply_with_redaction(
            &mut conv.messages[1],
            &judged,
            &mut MemoizingRedactor::new(),
            "blob",
            1,
            field_map_for("codex"),
            false,
        );
        assert_eq!(marker.rule_version, 2);
        assert_eq!(marker.sha256, sha256_hex(&original));
        assert_eq!(marker.bytes, original.len() as u64);
        assert_eq!(conv.messages[1].extra["payload"]["output"]["redacted"], json!(true));
    }

    #[test]
    fn mcp_v2_exec_result_type_missing_or_complete_excludes_other_values_preserve() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let expression = mcp_expression("mcp__cass_mcp__cass_search", json!({"query": "needle"}));

        // Missing (2025 protocol) and string "complete" (2026 protocol) are
        // both completed results. `isError` may be absent or boolean false.
        for application in [
            json!({"content": [{"type": "text", "text": wrapper}]}),
            json!({"content": [{"type": "text", "text": wrapper}], "isError": false}),
            mcp_application_2026(&wrapper),
        ] {
            let (outcome, _, _) = exec_outcome(&expression, mcp_output(&application));
            let Outcome::Exclude(judged) = outcome else {
                panic!("a completed result must be excluded: {application}");
            };
            assert_eq!(judged.src.as_ref(), Some(&search_src()));
        }

        // Every other value is not a completed result and must stay.
        for result_type in [
            json!(null),
            json!("task"),
            json!("input_required"),
            json!("Complete"),
            json!(""),
            json!(1),
            json!(true),
            json!(["complete"]),
            json!({"kind": "complete"}),
        ] {
            let application = json!({
                "content": [{"type": "text", "text": wrapper}],
                "isError": false,
                "resultType": result_type.clone(),
            });
            let (outcome, _, _) = exec_outcome(&expression, mcp_output(&application));
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
        }
    }

    #[test]
    fn mcp_v2_exec_four_cli_commands_exclude_with_expected_sources() {
        let sha = "a".repeat(64);
        let expand_command = format!(
            "cass expand /srv/sessions/e.jsonl --source local --message-id 3 --expected-content-sha256 {sha} --recall"
        );
        let cases: Vec<(RecallTool, String, Value)> = vec![
            (
                RecallTool::Search,
                "cass search \"needle\" --recall".to_string(),
                search_value(),
            ),
            (RecallTool::Expand, expand_command, expand_value()),
            (
                RecallTool::Sessions,
                "cass sessions --limit 5 --recall".to_string(),
                sessions_value(),
            ),
            (
                RecallTool::Timeline,
                "cass timeline --group-by hour --recall".to_string(),
                timeline_value(),
            ),
        ];
        for (tool, command, value) in cases {
            let wrapper = recall_output::encode(tool, &value).unwrap();
            let expression = cli_expression(&command);
            let (outcome, _, _) =
                exec_outcome(&expression, cli_output_string(&cli_application(&wrapper)));
            let Outcome::Exclude(judged) = outcome else {
                panic!("{command} must be excluded");
            };
            assert_eq!(judged.decision.anchor.tool_name.as_deref(), Some("exec"));
            assert!(judged.parse_error.is_none());
            match tool {
                RecallTool::Expand => assert_eq!(
                    judged.src.unwrap().hits[0].line_number,
                    Some(3),
                    "expand source uses the proven CLI args and the unique target line"
                ),
                RecallTool::Search => assert_eq!(judged.src.unwrap(), search_src()),
                RecallTool::Sessions => assert_eq!(judged.src.unwrap(), sessions_src()),
                RecallTool::Timeline => assert_eq!(judged.src.unwrap(), timeline_src()),
            }
        }
    }

    #[test]
    fn mcp_v2_exec_four_mcp_methods_exclude_with_expected_sources() {
        let cases: Vec<(RecallTool, &str, Value)> = vec![
            (RecallTool::Search, "mcp__cass_mcp__cass_search", search_value()),
            (RecallTool::Expand, "mcp__cass_mcp__cass_expand", expand_value()),
            (RecallTool::Sessions, "mcp__cass_mcp__cass_sessions", sessions_value()),
            (RecallTool::Timeline, "mcp__cass_mcp__cass_timeline", timeline_value()),
        ];
        for (tool, method, value) in cases {
            let wrapper = recall_output::encode(tool, &value).unwrap();
            let expression = mcp_expression(
                method,
                json!({"source_id": "local", "source_path": "/srv/sessions/e.jsonl"}),
            );
            let (outcome, _, _) = exec_outcome(&expression, mcp_output(&mcp_application(&wrapper)));
            let Outcome::Exclude(judged) = outcome else {
                panic!("{method} must be excluded");
            };
            assert_eq!(judged.decision.anchor.tool_name.as_deref(), Some("exec"));
            assert!(judged.parse_error.is_none());
        }
    }

    #[test]
    fn mcp_v2_exec_json_data_may_hold_parens_semicolons_closing_tag_and_unicode() {
        let value = json!({"hits": [{
            "source_id": "local",
            "source_path": "/srv/sessions/中文.jsonl",
            "line_number": 4,
            "content": "a ); </cass_recall> b"
        }]});
        let wrapper = recall_output::encode(RecallTool::Search, &value).unwrap();
        let command = "cass search \"a); </cass_recall> 中文\" --recall";
        let (outcome, _, _) =
            exec_outcome(&cli_expression(command), cli_output_string(&cli_application(&wrapper)));
        let Outcome::Exclude(judged) = outcome else {
            panic!("quoted metacharacters inside JSON are data");
        };
        assert_eq!(judged.src.unwrap().sessions, vec!["/srv/sessions/中文.jsonl"]);
    }

    #[test]
    fn mcp_v2_exec_unpaired_complete_c04_counts_unpaired_but_never_excludes() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let output = cli_output_string(&cli_application(&wrapper));
        let raw_record = result_raw_record(None, &output, "custom_tool_call_output");
        let conv = codex_conversation(vec![codex_result_row(&output, &raw_record)]);
        let event = RawEvent {
            event_key: "line:1".into(),
            blocks: vec![tool_result_block(0, None)],
        };
        assert_eq!(
            decide_for_record(&conv, 0, &event, &PairingContext::default(), &paths_cfg(), &raw_record),
            Outcome::Preserve(Some(UncoveredReason::UnpairedResult))
        );

        // An unknown application result with no recall evidence falls back
        // to the legacy conservative result.
        let bad_output = Value::String(json!({"hello": "world"}).to_string());
        let bad_raw = result_raw_record(None, &bad_output, "custom_tool_call_output");
        let bad_conv = codex_conversation(vec![codex_result_row(&bad_output, &bad_raw)]);
        assert_eq!(
            decide_for_record(&bad_conv, 0, &event, &PairingContext::default(), &paths_cfg(), &bad_raw),
            Outcome::Preserve(None)
        );

        // Ordinary user text is never a candidate.
        let user = codex_message("user", "the assistant ran text(await tools.exec_command(...))", json!({}));
        let user_conv = codex_conversation(vec![user]);
        assert_eq!(
            decide_for_record(&user_conv, 0, &event, &PairingContext::default(), &paths_cfg(), &json!({})),
            Outcome::Preserve(None)
        );
    }

    #[test]
    fn mcp_v2_exec_idx_out_of_bounds_preserves_without_reason() {
        let conv = codex_conversation(vec![codex_message("user", "hi", json!({}))]);
        let event = RawEvent { event_key: "line:1".into(), blocks: Vec::new() };
        assert_eq!(
            decide_for_record(&conv, 9, &event, &PairingContext::default(), &paths_cfg(), &json!({})),
            Outcome::Preserve(None)
        );
    }

    #[test]
    fn mcp_v2_exec_multiple_application_blocks_preserve() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let application = cli_application(&wrapper).to_string();
        let expression = cli_expression("cass search needle --recall");
        for output in [
            json!([
                {"type": "input_text", "text": application},
                {"type": "input_text", "text": application},
            ]),
            json!([
                {"type": "input_text", "text": header_text("0.1")},
                {"type": "input_text", "text": application},
                {"type": "input_text", "text": application},
            ]),
            json!([
                {"type": "input_text", "text": application},
                {"type": "input_text", "text": header_text("0.1")},
            ]),
            json!([
                {"type": "input_text", "text": header_text("0.1")},
                {"type": "input_text", "text": application},
                {"type": "input_text", "text": "extra host text"},
            ]),
        ] {
            let (outcome, _, _) = exec_outcome(&expression, output);
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
        }
    }

    #[test]
    fn mcp_v2_exec_header_shapes_and_block_types_preserve() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let application = cli_application(&wrapper).to_string();
        let expression = cli_expression("cass search needle --recall");
        let headers = [
            "Script running\nWall time 0.1 seconds\nOutput:".to_string(),
            "Script completed\nWall time 0.1 seconds:\nOutput:".to_string(),
            "Script completed\nWall time -1 seconds\nOutput:".to_string(),
            "Script completed\nWall time NaN seconds\nOutput:".to_string(),
            "Script completed\nWall time 0.1 seconds".to_string(),
            "Script completed\nOutput:\nWall time 0.1 seconds".to_string(),
        ];
        for header in headers {
            let (outcome, _, _) = exec_outcome(
                &expression,
                json!([
                    {"type": "input_text", "text": header},
                    {"type": "input_text", "text": application},
                ]),
            );
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
        }
        for block_type in ["text", "output_text", ""] {
            let (outcome, _, _) = exec_outcome(
                &expression,
                json!([{"type": block_type, "text": application}]),
            );
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
        }
    }

    #[test]
    fn mcp_v2_exec_cli_application_transport_fields_preserve() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let expression = cli_expression("cass search needle --recall");
        let cases = [
            json!({"exit_code": 0, "session_id": null, "output": wrapper}),
            json!({"exit_code": 0, "session_id": "s-1", "output": wrapper}),
            json!({"exit_code": 1, "output": wrapper}),
            json!({"exit_code": 0.0, "output": wrapper}),
            json!({"exit_code": 0}),
            json!({"exit_code": 0, "output": wrapper, "stdout": "second copy"}),
        ];
        for application in cases {
            let (outcome, _, _) = exec_outcome(&expression, cli_output_string(&application));
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
        }
    }

    #[test]
    fn mcp_v2_exec_mcp_application_shape_preserves() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let expression = mcp_expression("mcp__cass_mcp__cass_search", json!({"query": "needle"}));
        let cases = [
            json!({"isError": true, "content": [{"type": "text", "text": wrapper}]}),
            json!({"isError": "false", "content": [{"type": "text", "text": wrapper}]}),
            json!({"content": []}),
            json!({"content": [
                {"type": "text", "text": wrapper},
                {"type": "text", "text": wrapper}
            ]}),
            json!({"content": [{"type": "input_text", "text": wrapper}]}),
            json!({"content": [{"type": "text", "text": wrapper}], "structuredContent": {"hits": []}}),
            json!({"isError": false}),
        ];
        for application in cases {
            let (outcome, _, _) = exec_outcome(&expression, mcp_output(&application));
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
        }
    }

    #[test]
    fn mcp_v2_exec_broken_or_wrong_tool_c04_preserves_invalid_format() {
        let truncated = "<cass_recall version=\"1\" tool=\"cass_search\">{\"hits\": []}";
        let cases = [
            (cli_expression("cass search needle --recall"), truncated.to_string(), false),
            (
                cli_expression("cass search needle --recall"),
                recall_output::encode(RecallTool::Sessions, &sessions_value()).unwrap(),
                false,
            ),
            (
                mcp_expression("mcp__cass_mcp__cass_expand", json!({"message_id": 1})),
                recall_output::encode(RecallTool::Search, &search_value()).unwrap(),
                true,
            ),
        ];
        for (expression, wrapper, is_mcp) in cases {
            let output = if is_mcp {
                mcp_output(&mcp_application(&wrapper))
            } else {
                cli_output_string(&cli_application(&wrapper))
            };
            let (outcome, _, _) = exec_outcome(&expression, output);
            assert_preserved(outcome, UncoveredReason::InvalidRecallFormat);
        }
    }

    #[test]
    fn mcp_v2_exec_dynamic_javascript_and_unknown_methods_preserve() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let output = cli_output_string(&cli_application(&wrapper));
        let valid_command = json!({"cmd": "cass search needle --recall"});
        let expressions = [
            format!("const r = await tools.exec_command({valid_command}); text(r);"),
            "text(await tools.exec_command({cmd: \"cass search needle\"}));".to_string(),
            "text(await tools.exec_command(`{\"cmd\":\"cass search needle\"}`));".to_string(),
            "for (let i = 0; i < 2; i++) { text(await tools.exec_command({\"cmd\":\"cass search needle\"})); }".to_string(),
            format!(
                "text(await tools.exec_command({valid_command})); text(await tools.exec_command({valid_command}));"
            ),
            "text(await tools.exec_command([1, 2]));".to_string(),
            "text(await tools.exec_command({\"cmd\":\"cass search needle\"}))".to_string(),
            "text(await tools.wait({\"cell_id\":\"1\"}));".to_string(),
            "text(await tools.mcp__other_mcp__cass_search({\"query\":\"x\"}));".to_string(),
            "text(await tools.exec_command({\"cmd\":\"rg needle\"}));".to_string(),
            "text(await tools.exec_command({\"cmd\":\"cass search needle | head\"}));".to_string(),
            "text(await tools.exec_command({\"cmd\":42}));".to_string(),
        ];
        for expression in expressions {
            let (outcome, _, _) = exec_outcome(&expression, output.clone());
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
        }
    }

    #[test]
    fn mcp_v2_exec_function_call_or_nonstring_args_preserve() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let output = cli_output_string(&cli_application(&wrapper));
        let expression = cli_expression("cass search needle --recall");

        let (mut conv, events, raw_record) = exec_fixture(&expression, output.clone());
        conv.messages[0].extra["raw_role"] = json!("function_call");
        let ctx = PairingContext::build(&crate::indexer::build_pairing_candidates(&conv));
        assert_preserved(
            decide_for_record(&conv, 1, &events[1], &ctx, &paths_cfg(), &raw_record),
            UncoveredReason::UnsupportedShell,
        );

        let (mut conv, events, raw_record) = exec_fixture(&expression, output.clone());
        conv.messages[0].invocations[0].arguments = Some(json!({"cmd": "cass search needle --recall"}));
        let ctx = PairingContext::build(&crate::indexer::build_pairing_candidates(&conv));
        assert_preserved(
            decide_for_record(&conv, 1, &events[1], &ctx, &paths_cfg(), &raw_record),
            UncoveredReason::UnsupportedShell,
        );

        let (mut conv, events, raw_record) = exec_fixture(&expression, output);
        conv.messages[0].invocations[0].arguments = None;
        let ctx = PairingContext::build(&crate::indexer::build_pairing_candidates(&conv));
        assert_preserved(
            decide_for_record(&conv, 1, &events[1], &ctx, &paths_cfg(), &raw_record),
            UncoveredReason::UnpairedResult,
        );
    }

    #[test]
    fn mcp_v2_exec_raw_record_shape_and_call_id_mismatch_preserve() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let output = cli_output_string(&cli_application(&wrapper));
        let expression = cli_expression("cass search needle --recall");

        let (conv, events, _) = exec_fixture(&expression, output.clone());
        let ctx = PairingContext::build(&crate::indexer::build_pairing_candidates(&conv));
        let mismatched = result_raw_record(Some("other-call"), &output, "custom_tool_call_output");
        assert_preserved(
            decide_for_record(&conv, 1, &events[1], &ctx, &paths_cfg(), &mismatched),
            UncoveredReason::UnpairedResult,
        );

        let plain = result_raw_record(Some("call-t07"), &output, "function_call_output");
        assert_preserved(
            decide_for_record(&conv, 1, &events[1], &ctx, &paths_cfg(), &plain),
            UncoveredReason::UnsupportedShell,
        );

        assert_preserved(
            decide_for_record(&conv, 1, &events[1], &ctx, &paths_cfg(), &json!([1, 2])),
            UncoveredReason::UnsupportedShell,
        );
    }

    #[test]
    fn mcp_v2_exec_r4_ambiguity_and_future_calls_never_exclude() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let output = cli_output_string(&cli_application(&wrapper));
        let raw_record = result_raw_record(None, &output, "custom_tool_call_output");
        let result = codex_result_row(&output, &raw_record);

        // Duplicate id (R1-B5): no pair.
        let duplicate = vec![
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("dup".into()),
                tool_name: "exec".into(),
                args: Some(Value::String(cli_expression("cass search x --recall"))),
            }),
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("dup".into()),
                tool_name: "exec".into(),
                args: Some(Value::String(cli_expression("cass search x --recall"))),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("dup".into()) },
        ];
        let ctx = PairingContext::build(&duplicate);
        assert!(ctx.paired_call_for(2).is_none());
        assert!(ctx.paired_call_index_for(2).is_none());
        let conv = codex_conversation(vec![
            codex_call_row(&cli_expression("cass search x --recall"), Some("dup"), "custom_tool_call"),
            codex_call_row(&cli_expression("cass search x --recall"), Some("dup"), "custom_tool_call"),
            result.clone(),
        ]);
        let event = RawEvent { event_key: "line:3".into(), blocks: vec![tool_result_block(0, Some("dup"))] };
        assert_preserved(
            decide_for_record(&conv, 2, &event, &ctx, &paths_cfg(), &raw_record),
            UncoveredReason::UnpairedResult,
        );

        // Result before its call: no pair.
        let future = vec![
            PairingCandidate::ToolResult { tool_call_id: Some("late".into()) },
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("late".into()),
                tool_name: "exec".into(),
                args: Some(Value::String(cli_expression("cass search x --recall"))),
            }),
        ];
        let ctx = PairingContext::build(&future);
        assert!(ctx.paired_call_index_for(0).is_none());
        let conv = codex_conversation(vec![
            result.clone(),
            codex_call_row(&cli_expression("cass search x --recall"), Some("late"), "custom_tool_call"),
        ]);
        let event = RawEvent { event_key: "line:1".into(), blocks: vec![tool_result_block(0, Some("late"))] };
        assert_preserved(
            decide_for_record(&conv, 0, &event, &ctx, &paths_cfg(), &raw_record),
            UncoveredReason::UnpairedResult,
        );

        // Two id-less calls: ambiguous, no pair.
        let ambiguous = vec![
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: None,
                tool_name: "exec".into(),
                args: Some(Value::String(cli_expression("cass search x --recall"))),
            }),
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: None,
                tool_name: "exec".into(),
                args: Some(Value::String(cli_expression("cass search x --recall"))),
            }),
            PairingCandidate::ToolResult { tool_call_id: None },
        ];
        let ctx = PairingContext::build(&ambiguous);
        assert!(ctx.paired_call_index_for(2).is_none());
        let conv = codex_conversation(vec![
            codex_call_row(&cli_expression("cass search x --recall"), None, "custom_tool_call"),
            codex_call_row(&cli_expression("cass search x --recall"), None, "custom_tool_call"),
            result.clone(),
        ]);
        let event = RawEvent { event_key: "line:3".into(), blocks: vec![tool_result_block(0, None)] };
        assert_preserved(
            decide_for_record(&conv, 2, &event, &ctx, &paths_cfg(), &raw_record),
            UncoveredReason::UnpairedResult,
        );

        // Turn boundary clears the id-less candidate: no pair.
        let bounded = vec![
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: None,
                tool_name: "exec".into(),
                args: Some(Value::String(cli_expression("cass search x --recall"))),
            }),
            PairingCandidate::TurnBoundary,
            PairingCandidate::ToolResult { tool_call_id: None },
        ];
        let ctx = PairingContext::build(&bounded);
        assert!(ctx.paired_call_index_for(2).is_none());
        let conv = codex_conversation(vec![
            codex_call_row(&cli_expression("cass search x --recall"), None, "custom_tool_call"),
            codex_message("user", "next turn", json!({})),
            result,
        ]);
        let event = RawEvent { event_key: "line:3".into(), blocks: vec![tool_result_block(0, None)] };
        assert_preserved(
            decide_for_record(&conv, 2, &event, &ctx, &paths_cfg(), &raw_record),
            UncoveredReason::UnpairedResult,
        );
    }

    #[test]
    fn mcp_v2_exec_non_custom_tool_and_non_codex_delegate_to_decide() {
        // A paired non-exec tool keeps the verified MCP/CLI/R2/R3 judgment.
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).unwrap();
        let (mut message, event, ctx) =
            fixture("mcp__cass-mcp__cass_search", json!({}), &wrapper);
        let conv = codex_conversation(vec![
            codex_message("tool_call", "", json!({"raw_role": "custom_tool_call"})),
            std::mem::replace(&mut message, msg("tool_result", "")),
        ]);
        assert_eq!(
            decide_for_record(&conv, 1, &event, &ctx, &paths_cfg(), &json!({})),
            decide(&conv.messages[1], 1, &event, &ctx, "codex", &paths_cfg())
        );

        // claude_code is not the C07 path; the same strong-identity result is
        // excluded exactly as the verified v2 entry does.
        let (claude_message, claude_event, claude_ctx) =
            fixture("mcp__cass-mcp__cass_search", json!({}), &wrapper);
        let claude_conv = codex_conversation(vec![
            codex_message("tool_call", "", json!({})),
            claude_message,
        ]);
        let mut claude_conv = claude_conv;
        claude_conv.agent_slug = "claude_code".to_string();
        let Outcome::Exclude(judged) =
            decide_for_record(&claude_conv, 1, &claude_event, &claude_ctx, &paths_cfg(), &json!({}))
        else {
            panic!("non-codex rows keep the verified v2 result");
        };
        assert_eq!(judged.decision.anchor.tool_name.as_deref(), Some("mcp__cass-mcp__cass_search"));
        assert_eq!(judged.src.as_ref(), Some(&search_src()));
    }

    #[test]
    fn mcp_v2_cli_v1_has_no_direct_cli_rule_and_legacy_bash_still_fires() {
        // v1 is unchanged: it never recognizes a direct CLI command.
        let (message, event, ctx) = fixture(
            "Bash",
            json!({"command": "cass search auth --recall"}),
            "body",
        );
        assert!(
            exclusion::decide(&message, 1, &event, &ctx, "claude_code", &paths_cfg()).is_none()
        );

        // A non-Cass Bash command still reaches the legacy R2 rule through v2.
        let read_event = RawEvent { event_key: "ek4".into(), blocks: vec![tool_result_block(0, Some("r2"))] };
        let read_ctx = PairingContext::build(&[
            PairingCandidate::ToolCall(PairedTool {
                tool_call_id: Some("r2".into()),
                tool_name: "Bash".into(),
                args: Some(json!({"command": "cat /srv/cc-workspace/MEMORY.md"})),
            }),
            PairingCandidate::ToolResult { tool_call_id: Some("r2".into()) },
        ]);
        let mut read_message = msg("tool_result", "file body");
        let Outcome::Exclude(read_judged) = decide(
            &mut read_message,
            1,
            &read_event,
            &read_ctx,
            "claude_code",
            &paths_cfg(),
        ) else {
            panic!("non-Cass Bash keeps the legacy R2 path");
        };
        assert_eq!(read_judged.decision.reason, ExclusionReason::ContextFileRead);
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
    }

    // ========================================================================
    // Ticket 07a: the frozen K01-K12 single-`const` binding matrix.
    //
    // The fixture is copied byte-for-byte from the batch roadmap and compiled
    // in here, so the assertions cannot drift from the frozen input. Derived
    // boundaries stay inside K01/K02 and print their own stable labels, so
    // the named interface stays at twelve targets.
    // ========================================================================

    const ALIEN_CONST: &str = include_str!("../../tests/fixtures/alien_codex/const.json");

    fn alien_const_case(id: &str) -> Value {
        alien_case(ALIEN_CONST, id)
    }

    /// One supported `const` form for the given method and argument value.
    fn const_expression(method: &str, args: &Value) -> String {
        format!("const r=await tools.{method}({args});text(r);")
    }

    /// The 48 binding names the frozen identifier table refuses: the keywords,
    /// the strict-mode future reserved words, and the two strict-mode binding
    /// restrictions. `async` is deliberately absent; it is a valid binding.
    const CONST_REJECTED_BINDINGS: [&str; 48] = [
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "enum",
        "export",
        "extends",
        "false",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "new",
        "null",
        "return",
        "super",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "typeof",
        "var",
        "void",
        "while",
        "with",
        "yield",
        "implements",
        "interface",
        "let",
        "package",
        "private",
        "protected",
        "public",
        "static",
        "arguments",
        "eval",
    ];

    /// Judge one frozen K case the way production does. A supported case must
    /// parse to the exact method and argument value, and the same expression
    /// fed through the existing `exec_fixture` / `decide_for_record` path with
    /// a complete MCP record must really be excluded. An unsupported case must
    /// parse to `None` and reach the production `unsupported_shell` preserve.
    fn assert_alien_const_case(case: &Value) {
        let id = case["id"].as_str().expect("case id");
        let expression = case["expression"].as_str().expect("case expression");
        let expected = &case["expected"];
        let supported = expected["supported"].as_bool().expect("case supported");
        println!("case {id}: supported={supported}");

        if supported {
            let (target, args) = parse_exec_literal(expression)
                .unwrap_or_else(|| panic!("{id}: expected a supported const literal"));
            let ExecTarget::Mcp(tool) = target else {
                panic!("{id}: only the four MCP methods are supported");
            };
            let method = expected["method"].as_str().expect("case method");
            assert_eq!(recall_tool_method(tool), method, "{id}: method");
            assert_eq!(args, expected["args"], "{id}: original argument value");

            let wrapper = recall_output::encode(tool, &alien_tool_value(tool))
                .expect("frozen wrapper encodes");
            let (outcome, _, _) = exec_outcome(expression, mcp_output(&mcp_application(&wrapper)));
            let Outcome::Exclude(judged) = outcome else {
                panic!("{id}: the production path must exclude this literal, got {outcome:?}");
            };
            assert!(judged.parse_error.is_none(), "{id}: no parse error");
            println!("case {id}: excluded through decide_for_record");
        } else {
            assert!(
                parse_exec_literal(expression).is_none(),
                "{id}: an unsupported const literal must not parse"
            );
            let wrapper = recall_output::encode(RecallTool::Search, &search_value())
                .expect("frozen wrapper encodes");
            let (outcome, _, _) = exec_outcome(expression, mcp_output(&mcp_application(&wrapper)));
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
            println!("case {id}: preserved unsupported_shell");
        }
    }

    fn assert_const_supported(label: &str, expression: &str, tool: RecallTool, expected: &Value) {
        let (target, args) = parse_exec_literal(expression)
            .unwrap_or_else(|| panic!("{label}: expected a supported const literal"));
        let ExecTarget::Mcp(actual) = target else {
            panic!("{label}: only the four MCP methods are supported");
        };
        assert_eq!(
            recall_tool_method(actual),
            recall_tool_method(tool),
            "{label}: method"
        );
        assert_eq!(&args, expected, "{label}: original argument value");
        let wrapper =
            recall_output::encode(tool, &alien_tool_value(tool)).expect("frozen wrapper encodes");
        let (outcome, _, _) = exec_outcome(expression, mcp_output(&mcp_application(&wrapper)));
        let Outcome::Exclude(judged) = outcome else {
            panic!("{label}: the production path must exclude this literal, got {outcome:?}");
        };
        assert!(judged.parse_error.is_none(), "{label}: no parse error");
        println!("const-case {label}: supported, excluded through decide_for_record");
    }

    fn assert_const_unsupported(label: &str, expression: &str) {
        assert!(
            parse_exec_literal(expression).is_none(),
            "{label}: must stay unsupported"
        );
        println!("const-case {label}: unsupported as expected");
    }

    /// One `exec` Codex pair whose raw result record is supplied verbatim, so a
    /// single native field can change without touching the expression.
    fn const_negative_outcome(expression: &str, raw_record: Value) -> Outcome {
        let call_id = "call-t07";
        let output = raw_record["payload"]["output"].clone();
        let call = codex_call_row(expression, Some(call_id), "custom_tool_call");
        let result = codex_result_row(&output, &raw_record);
        let conv = codex_conversation(vec![call, result]);
        let events = vec![
            RawEvent {
                event_key: "line:1".into(),
                blocks: vec![RawBlock {
                    index: 0,
                    kind: BlockKind::ToolUse,
                    tool_use_id: Some(call_id.into()),
                    tool_name: Some("exec".into()),
                    args: Some(Value::String(expression.into())),
                }],
            },
            RawEvent {
                event_key: "line:2".into(),
                blocks: vec![tool_result_block(0, Some(call_id))],
            },
        ];
        let ctx = PairingContext::build(&crate::indexer::build_pairing_candidates(&conv));
        decide_for_record(&conv, 1, &events[1], &ctx, &paths_cfg(), &raw_record)
    }

    #[test]
    fn alien_codex_const_k01() {
        assert_alien_const_case(&alien_const_case("K01"));

        // The same shape reaches all four frozen methods with the first legal
        // argument value of each from the 06 fixture, and each still excludes
        // through the matching C04 envelope.
        for (literal_id, tool) in [
            ("L01", RecallTool::Search),
            ("L02", RecallTool::Expand),
            ("L03", RecallTool::Sessions),
            ("L04", RecallTool::Timeline),
        ] {
            let case = alien_literal_case(literal_id);
            let method = case["expected"]["method"].as_str().expect("literal method");
            let args = case["expected"]["args"].clone();
            assert_eq!(
                recall_tool_method(tool),
                method,
                "{literal_id}: method pairing"
            );
            let expression = const_expression(method, &args);
            assert_const_supported(&format!("K01/method-{method}"), &expression, tool, &args);
        }

        // The six allowed binding names from the frozen identifier table.
        for binding in ["r", "answer", "_", "$r", "async", "answer9"] {
            let expression = format!(
                "const {binding}=await tools.mcp__cass_mcp__cass_search({{\"query\":\"synthetic\"}});text({binding});"
            );
            assert_const_supported(
                &format!("K01/binding-{binding}"),
                &expression,
                RecallTool::Search,
                &json!({"query": "synthetic"}),
            );
        }

        // The outer trim keeps the 06 Unicode behaviour.
        let trimmed = format!(
            "\u{2003}const r=await tools.mcp__cass_mcp__cass_search({{\"query\":\"synthetic\"}});text(r);\u{2003}"
        );
        assert_const_supported(
            "K01/outer-unicode-trim",
            &trimmed,
            RecallTool::Search,
            &json!({"query": "synthetic"}),
        );

        // The binding-name table never reaches object keys: the const form
        // parses the same reserved-word keys to the same Value as the 06 form.
        let direct = "text(await tools.mcp__cass_mcp__cass_search({query:\"synthetic\",default:null,public:true}));";
        let expected = parse_mcp_call_literal(direct)
            .expect("06 accepts the reserved-word keys as object keys")
            .1;
        let keyed = "const r=await tools.mcp__cass_mcp__cass_search({query:\"synthetic\",default:null,public:true});text(r);";
        let (target, args) =
            parse_exec_literal(keyed).expect("the const form accepts the same object keys");
        let ExecTarget::Mcp(tool) = target else {
            panic!("K01/object-reserved-keys: MCP only");
        };
        assert_eq!(tool, RecallTool::Search, "K01/object-reserved-keys: method");
        assert_eq!(
            args, expected,
            "K01/object-reserved-keys: same Value as the 06 form"
        );
        println!("const-case K01/object-reserved-keys: same Value as the 06 direct form");

        // The five fixed negative sides keep their original reason. Each uses
        // the same legal const expression and changes one native field only,
        // so a syntax failure could never stand in for the native check.
        let expression = alien_const_case("K01")["expression"]
            .as_str()
            .expect("case expression")
            .to_string();
        assert!(
            parse_exec_literal(&expression).is_some(),
            "K01/negative-sides: the expression stays supported"
        );
        let wrapper = recall_output::encode(RecallTool::Search, &search_value())
            .expect("frozen wrapper encodes");
        let output = mcp_output(&mcp_application(&wrapper));

        let mismatch = result_raw_record(Some("call-other"), &output, "custom_tool_call_output");
        assert_preserved(
            const_negative_outcome(&expression, mismatch),
            UncoveredReason::UnpairedResult,
        );
        println!("const-case K01/negative-call-id: unpaired_result as expected");

        let partial_app = json!({
            "content": [{"type": "text", "text": wrapper}],
            "resultType": "partial",
        });
        let partial = result_raw_record(
            Some("call-t07"),
            &mcp_output(&partial_app),
            "custom_tool_call_output",
        );
        assert_preserved(
            const_negative_outcome(&expression, partial),
            UncoveredReason::UnsupportedShell,
        );
        println!("const-case K01/negative-result-type: unsupported_shell as expected");

        let application = mcp_application(&wrapper).to_string();
        let double = json!([
            {"type": "input_text", "text": application},
            {"type": "input_text", "text": application},
        ]);
        let two_blocks = result_raw_record(Some("call-t07"), &double, "custom_tool_call_output");
        assert_preserved(
            const_negative_outcome(&expression, two_blocks),
            UncoveredReason::UnsupportedShell,
        );
        println!("const-case K01/negative-two-blocks: unsupported_shell as expected");

        let extra_app = json!({
            "content": [{"type": "text", "text": wrapper}],
            "serverInfo": {"name": "synthetic"},
        });
        let extra = result_raw_record(
            Some("call-t07"),
            &mcp_output(&extra_app),
            "custom_tool_call_output",
        );
        assert_preserved(
            const_negative_outcome(&expression, extra),
            UncoveredReason::UnsupportedShell,
        );
        println!("const-case K01/negative-extra-field: unsupported_shell as expected");

        let truncated = "<cass_recall version=\"1\" tool=\"cass_search\">{\"hits\": []}";
        let broken = result_raw_record(
            Some("call-t07"),
            &mcp_output(&mcp_application(truncated)),
            "custom_tool_call_output",
        );
        assert_preserved(
            const_negative_outcome(&expression, broken),
            UncoveredReason::InvalidRecallFormat,
        );
        println!("const-case K01/negative-broken-c04: invalid_recall_format as expected");
    }

    #[test]
    fn alien_codex_const_k02() {
        assert_alien_const_case(&alien_const_case("K02"));

        for binding in CONST_REJECTED_BINDINGS {
            let expression = format!(
                "const {binding}=await tools.mcp__cass_mcp__cass_search({{\"query\":\"synthetic\"}});text({binding});"
            );
            assert_const_unsupported(&format!("K02/binding-{binding}"), &expression);
        }

        // Unicode and escaped identifiers are not ASCII identifiers.
        for (label, binding) in [("unicode", "é"), ("escaped", "\\u0072")] {
            let expression = format!(
                "const {binding}=await tools.mcp__cass_mcp__cass_search({{\"query\":\"synthetic\"}});text({binding});"
            );
            assert_const_unsupported(&format!("K02/ident-{label}"), &expression);
        }

        // Token gluing on either side of a keyword is not the keyword.
        for (label, expression) in [
            (
                "constx",
                "constx r=await tools.mcp__cass_mcp__cass_search({\"query\":\"synthetic\"});text(r);".to_string(),
            ),
            (
                "awaittools",
                "const r=awaittools.mcp__cass_mcp__cass_search({\"query\":\"synthetic\"});text(r);".to_string(),
            ),
            (
                "textual",
                "const r=await tools.mcp__cass_mcp__cass_search({\"query\":\"synthetic\"});textual(r);".to_string(),
            ),
        ] {
            assert_const_unsupported(&format!("K02/token-{label}"), &expression);
        }

        // Both semicolons are required and no code may follow the print.
        for (label, expression) in [
            (
                "missing-declaration-semicolon",
                "const r=await tools.mcp__cass_mcp__cass_search({\"query\":\"synthetic\"})\ntext(r);",
            ),
            (
                "missing-print-semicolon",
                "const r=await tools.mcp__cass_mcp__cass_search({\"query\":\"synthetic\"});text(r)",
            ),
            (
                "trailing-code",
                "const r=await tools.mcp__cass_mcp__cass_search({\"query\":\"synthetic\"});text(r);+1",
            ),
        ] {
            assert_const_unsupported(&format!("K02/semicolon-{label}"), expression);
        }
    }

    #[test]
    fn alien_codex_const_k03() {
        assert_alien_const_case(&alien_const_case("K03"));
    }

    #[test]
    fn alien_codex_const_k04() {
        assert_alien_const_case(&alien_const_case("K04"));
    }

    #[test]
    fn alien_codex_const_k05() {
        assert_alien_const_case(&alien_const_case("K05"));
    }

    #[test]
    fn alien_codex_const_k06() {
        assert_alien_const_case(&alien_const_case("K06"));
    }

    #[test]
    fn alien_codex_const_k07() {
        assert_alien_const_case(&alien_const_case("K07"));
    }

    #[test]
    fn alien_codex_const_k08() {
        assert_alien_const_case(&alien_const_case("K08"));
    }

    #[test]
    fn alien_codex_const_k09() {
        assert_alien_const_case(&alien_const_case("K09"));
    }

    #[test]
    fn alien_codex_const_k10() {
        assert_alien_const_case(&alien_const_case("K10"));
    }

    #[test]
    fn alien_codex_const_k11() {
        assert_alien_const_case(&alien_const_case("K11"));
    }

    #[test]
    fn alien_codex_const_k12() {
        assert_alien_const_case(&alien_const_case("K12"));
    }

    // ========================================================================
    // Ticket 07b: the frozen D01-D22 discovery-call boundary matrix.
    //
    // The fixture is copied byte-for-byte from the batch roadmap. Each case
    // runs through the existing `exec_fixture` / `decide_for_record` path, so
    // the assertion covers the whole hint and the strict judgment behind it,
    // not a helper boolean. The three C04 reverse-side cases (D01, D02, D15)
    // are executed inside the no-call test: a complete envelope stays
    // independent evidence even when no static call is proved.
    // ========================================================================

    const ALIEN_DISCOVERY: &str =
        include_str!("../../tests/fixtures/alien_codex/discovery.json");

    fn alien_discovery_case(id: &str) -> Value {
        alien_case(ALIEN_DISCOVERY, id)
    }

    /// Judge every frozen D case of one group. `expected_calls` is 0 for the
    /// capture-free group and 1 for the real-call group; the two groups must
    /// partition all 22 cases exactly once.
    fn assert_alien_discovery_group(expected_calls: u64, expected_group_len: usize) {
        let root: Value =
            serde_json::from_str(ALIEN_DISCOVERY).expect("frozen discovery fixture JSON");
        let cases = root["cases"].as_array().expect("cases array");
        let mut judged = 0;

        for case in cases {
            let calls = case["expected_actual_stub_calls"]
                .as_u64()
                .expect("case stub calls");
            if calls != expected_calls {
                continue;
            }
            judged += 1;
            let id = case["id"].as_str().expect("case id");
            let expression = case["expression"].as_str().expect("case expression");
            let expected_candidate = case["expected_candidate_without_recall"]
                .as_bool()
                .expect("case candidate");
            let expected_reason = case["expected_reason_without_recall"].as_str();

            // No D case is one of the 07a supported const forms, so only the
            // discovery hint decides what happens here.
            assert!(
                parse_exec_literal(expression).is_none(),
                "{id}: no discovery case is a const literal"
            );

            // A captured result that only printed a length or a truncation:
            // no C04 envelope anywhere, so the call evidence has to stand.
            let (outcome, _, _) = exec_outcome(expression, Value::String("partial".to_string()));
            let actual_candidate = outcome != Outcome::Preserve(None);
            println!(
                "case {id}: expected_calls={calls} expected_candidate={expected_candidate} \
                 actual_candidate={actual_candidate} outcome={outcome:?}"
            );

            assert_eq!(actual_candidate, expected_candidate, "{id}: candidate hint");
            if expected_candidate {
                assert_eq!(expected_reason, Some("unsupported_shell"), "{id}: fixture reason");
                assert_preserved(outcome, UncoveredReason::UnsupportedShell);
            } else {
                assert_eq!(
                    outcome,
                    Outcome::Preserve(None),
                    "{id}: a discovery-only exec is ordinary work"
                );
            }
        }

        assert_eq!(
            judged, expected_group_len,
            "the fixture group must keep its frozen size"
        );
    }

    /// D01/D02/D15: no static call is proved, but the result declares a
    /// complete C04 envelope. The existing output OR-branch is independent
    /// evidence, and the unsupported expression still preserves.
    fn assert_alien_discovery_reverse_side() {
        let wrapper = recall_output::encode(RecallTool::Search, &search_value())
            .expect("frozen wrapper encodes");
        for id in ["D01", "D02", "D15"] {
            let case = alien_discovery_case(id);
            let expression = case["expression"].as_str().expect("case expression");
            let (outcome, _, _) =
                exec_outcome(expression, mcp_output(&mcp_application(&wrapper)));
            let actual_candidate = outcome != Outcome::Preserve(None);
            println!(
                "case {id}+recall: expected_candidate=true \
                 actual_candidate={actual_candidate} outcome={outcome:?}"
            );
            assert!(actual_candidate, "{id}: a complete envelope stands alone");
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
        }
    }

    /// r1 regression: a `//` comment that ended only at LF used to swallow a
    /// real call that followed an ASCII CR. Both frozen newlines must end the
    /// comment, so both cases keep the original `unsupported_shell` alert.
    fn assert_alien_discovery_newline_regression() {
        let cases = [
            (
                "CR01",
                "// synthetic discovery\rconst r=await tools.mcp__cass_mcp__cass_search({query:\"synthetic\"});text(r.content.length);",
            ),
            (
                "LF01",
                "// synthetic discovery\nconst r=await tools.mcp__cass_mcp__cass_search({query:\"synthetic\"});text(r.content.length);",
            ),
        ];
        for (id, expression) in cases {
            let (outcome, _, _) = exec_outcome(expression, Value::String("partial".to_string()));
            let actual_candidate = outcome != Outcome::Preserve(None);
            println!(
                "r1-case {id}: expected_candidate=true actual_candidate={actual_candidate} \
                 outcome={outcome:?}"
            );
            assert!(
                actual_candidate,
                "r1-case {id}: the call after the comment must be found"
            );
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
        }
    }

    #[test]
    fn alien_codex_const_discovery_no_call() {
        assert_alien_discovery_group(0, 14);
        assert_alien_discovery_reverse_side();
    }

    #[test]
    fn alien_codex_const_actual_call_partial() {
        assert_alien_discovery_group(1, 8);
        assert_alien_discovery_newline_regression();
    }

    #[test]
    fn alien_codex_call_comments_remain_unsupported_candidates() {
        for method in [
            "mcp__cass_mcp__cass_search",
            "mcp__cass_mcp__cass_expand",
            "mcp__cass_mcp__cass_sessions",
            "mcp__cass_mcp__cass_timeline",
        ] {
            for gap in ["/* note */", "// note\n", "/* one */ // two\n /* three */"] {
                let expression = format!(
                    "const r=await tools.{method}{gap}({{query:\"synthetic\"}});text(r.content.length);"
                );
                assert!(
                    parse_exec_literal(&expression).is_none(),
                    "comments stay unsupported"
                );
                let (outcome, _, _) = exec_outcome(&expression, Value::String("partial".into()));
                assert_preserved(outcome, UncoveredReason::UnsupportedShell);
            }
        }

        // Keep the complete-envelope OR route independent from call discovery.
        let expression = "const r=await tools.mcp__cass_mcp__cass_search/* note */({query:\"synthetic\"});text(r.content.length);";
        let wrapper = recall_output::encode(RecallTool::Search, &search_value()).expect("encode");
        let (outcome, _, _) = exec_outcome(expression, mcp_output(&mcp_application(&wrapper)));
        assert_preserved(outcome, UncoveredReason::UnsupportedShell);

        for expression in [
            r#"text("tools.mcp__cass_mcp__cass_search/* note */(");"#,
            "/* tools.mcp__cass_mcp__cass_search() */ text(1);",
            "text(typeof tools.mcp__cass_mcp__cass_search/* note */);",
            "text(tools.mcp__cass_mcp__cass_search/* note */);",
            "const f=tools.mcp__cass_mcp__cass_search/* unterminated",
            "const f=tools.mcp__cass_mcp__cass_search// no call",
            "if (x) /tools.mcp__cass_mcp__cass_search// note\n(y)",
            "if ((x)) /tools.mcp__cass_mcp__cass_search// note\n(y)",
            "if (x) {} /tools.mcp__cass_mcp__cass_search// note\n(y)",
            "{} /tools.mcp__cass_mcp__cass_search// note\n(y)",
            "while (x) /tools.mcp__cass_mcp__cass_search// note\n(y)",
            "for (;x;) /tools.mcp__cass_mcp__cass_search// note\n(y)",
        ] {
            let (outcome, _, _) = exec_outcome(expression, Value::String("partial".into()));
            assert_eq!(outcome, Outcome::Preserve(None), "no call: {expression}");
        }

        for expression in [
            "const r=obj.if(x)/await tools.mcp__cass_mcp__cass_search/* note */({query:\"synthetic\"});text(r);",
            "const r=({x:1})/await tools.mcp__cass_mcp__cass_search/* note */({query:\"synthetic\"});text(r);",
        ] {
            let (outcome, _, _) = exec_outcome(expression, Value::String("partial".into()));
            assert_preserved(outcome, UncoveredReason::UnsupportedShell);
        }
    }
}
