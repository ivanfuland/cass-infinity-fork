//! The four fixed CASS tools: names, JSON schemas, input validation, and the
//! exact argv each one hands to the companion binary.
//!
//! Validation only rejects; it never rewrites a caller's string. Numbers are
//! checked for representation range before conversion, and every named option
//! is one `--name=value` element so a dash-leading value stays data.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmcp::model::JsonObject;
use serde_json::{Map, Value};

use crate::runner::ToolError;

/// The four tools this server exposes. The order is the `tools/list` order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecallTool {
    Search,
    Expand,
    Sessions,
    Timeline,
}

impl RecallTool {
    pub const ALL: [Self; 4] = [Self::Search, Self::Expand, Self::Sessions, Self::Timeline];

    pub fn name(self) -> &'static str {
        match self {
            Self::Search => "cass_search",
            Self::Expand => "cass_expand",
            Self::Sessions => "cass_sessions",
            Self::Timeline => "cass_timeline",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    /// Shape check shared with the CLI recall envelope (C04).
    pub fn accepts(self, value: &Value) -> bool {
        let objects = |value: &Value| {
            value
                .as_array()
                .is_some_and(|array| array.iter().all(Value::is_object))
        };
        match self {
            Self::Search => value.get("hits").is_some_and(objects),
            Self::Expand => objects(value),
            Self::Sessions => value.get("sessions").is_some_and(objects),
            Self::Timeline => {
                value.get("range").is_some_and(Value::is_object)
                    && value.get("total_sessions").is_some_and(Value::is_u64)
                    && (value.get("groups").is_some_and(Value::is_object)
                        || value.get("sessions").is_some_and(objects))
            }
        }
    }
}

/// Startup values fixed for every call. Request input cannot override them.
pub struct FixedProfiles<'a> {
    pub api_config: &'a Path,
    pub embedding_profile: &'a str,
    pub rerank_profile: &'a str,
}

/// A validated call: which tool, and every value it will pass on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCall {
    Search {
        query: String,
        agent: Vec<String>,
        workspace: Vec<String>,
        source: Option<String>,
        since: Option<String>,
        until: Option<String>,
        cursor: Option<String>,
    },
    Expand {
        source_path: String,
        source_id: String,
        message_id: u64,
        expected_content_sha256: String,
        context: u64,
    },
    Sessions {
        limit: u64,
        workspace: Option<String>,
        since: Option<String>,
    },
    Timeline {
        since: Option<String>,
        until: Option<String>,
        agent: Vec<String>,
        source: Option<String>,
        group_by: GroupBy,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    Hour,
    Day,
    None,
}

impl GroupBy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::None => "none",
        }
    }
}

impl ToolCall {
    /// The complete argv after the companion binary path.
    ///
    /// The literal order is frozen (C09a, C3): all fixed options first, then
    /// provided filters in the documented order, and for search a final `--`
    /// followed by the one unmodified query element.
    pub fn argv(&self, profiles: &FixedProfiles<'_>) -> Vec<OsString> {
        let mut argv = Vec::new();
        match self {
            Self::Search {
                query,
                agent,
                workspace,
                source,
                since,
                until,
                cursor,
            } => {
                argv.push("search".into());
                argv.push("--mode=hybrid".into());
                argv.push("--vector-search-mode=exact".into());
                argv.push("--rerank".into());
                argv.push("--rrf-limit=200".into());
                argv.push("--rerank-limit=5".into());
                argv.push(named_path("--api-config", profiles.api_config));
                argv.push(named("--embedding-profile", profiles.embedding_profile));
                argv.push(named("--rerank-profile", profiles.rerank_profile));
                argv.push("--no-model-fallback".into());
                argv.push("--recall".into());
                for value in agent {
                    argv.push(named("--agent", value));
                }
                for value in workspace {
                    argv.push(named("--workspace", value));
                }
                push_optional(&mut argv, "--source", source);
                push_optional(&mut argv, "--since", since);
                push_optional(&mut argv, "--until", until);
                push_optional(&mut argv, "--cursor", cursor);
                argv.push("--".into());
                argv.push(query.into());
            }
            Self::Expand {
                source_path,
                source_id,
                message_id,
                expected_content_sha256,
                context,
            } => {
                argv.push("expand".into());
                argv.push(source_path.into());
                argv.push(named("--source", source_id));
                argv.push(named("--message-id", &message_id.to_string()));
                argv.push(named("--expected-content-sha256", expected_content_sha256));
                argv.push(named("--context", &context.to_string()));
                argv.push("--recall".into());
            }
            Self::Sessions {
                limit,
                workspace,
                since,
            } => {
                argv.push("sessions".into());
                argv.push(named("--limit", &limit.to_string()));
                argv.push("--recall".into());
                push_optional(&mut argv, "--workspace", workspace);
                push_optional(&mut argv, "--since", since);
            }
            Self::Timeline {
                since,
                until,
                agent,
                source,
                group_by,
            } => {
                argv.push("timeline".into());
                argv.push(named("--group-by", group_by.as_str()));
                argv.push("--recall".into());
                push_optional(&mut argv, "--since", since);
                push_optional(&mut argv, "--until", until);
                for value in agent {
                    argv.push(named("--agent", value));
                }
                push_optional(&mut argv, "--source", source);
            }
        }
        argv
    }
}

fn named(name: &str, value: &str) -> OsString {
    let mut element = OsString::from(name);
    element.push("=");
    element.push(value);
    element
}

fn named_path(name: &str, value: &Path) -> OsString {
    let mut element = OsString::from(name);
    element.push("=");
    element.push(value.as_os_str());
    element
}

fn push_optional(argv: &mut Vec<OsString>, name: &str, value: &Option<String>) {
    if let Some(value) = value {
        argv.push(named(name, value));
    }
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

/// The exact tool table advertised by `tools/list`.
pub fn definitions() -> Vec<rmcp::model::Tool> {
    RecallTool::ALL
        .into_iter()
        .map(|tool| {
            rmcp::model::Tool::new(tool.name(), description(tool), schema_for(tool))
                .with_title(tool.name().to_string())
        })
        .collect()
}

fn description(tool: RecallTool) -> &'static str {
    match tool {
        RecallTool::Search => {
            "Search indexed agent sessions through the companion CASS binary. The query is passed \
             as one literal argv element after `--`."
        }
        RecallTool::Expand => {
            "Expand one indexed message by its exact source, message id, and content digest. The \
             source path is passed through unchanged and is never opened by this server."
        }
        RecallTool::Sessions => "List recent indexed sessions from the companion CASS binary.",
        RecallTool::Timeline => {
            "Show the activity timeline over an absolute time range, using the companion binary's \
             own default window when no bound is supplied."
        }
    }
}

fn schema_for(tool: RecallTool) -> Arc<JsonObject> {
    let value = match tool {
        RecallTool::Search => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["query"],
            "properties": {
                "query": { "type": "string", "pattern": "\\S", "description": "The query, passed through unchanged." },
                "agent": { "type": "array", "items": { "type": "string" }, "description": "Agent slugs; order and duplicates are preserved." },
                "workspace": { "type": "array", "items": { "type": "string" }, "description": "Absolute server-side workspace identifiers returned by the index." },
                "source": { "type": "string" },
                "since": { "type": "string", "description": "RFC3339 timestamp with an explicit offset." },
                "until": { "type": "string", "description": "RFC3339 timestamp with an explicit offset." },
                "cursor": { "type": "string" }
            }
        }),
        RecallTool::Expand => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["message_id", "source_id", "source_path", "expected_content_sha256"],
            "properties": {
                "message_id": { "type": "integer", "minimum": 1, "maximum": i64::MAX },
                "source_id": { "type": "string" },
                "source_path": { "type": "string", "description": "The exact locating string returned by the index." },
                "expected_content_sha256": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" },
                "context": { "type": "integer", "minimum": 0, "default": 3 }
            }
        }),
        RecallTool::Sessions => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "limit": { "type": "integer", "minimum": 1, "default": 10 },
                "workspace": { "type": "string", "description": "Absolute server-side workspace identifier returned by the index." },
                "since": { "type": "string", "description": "RFC3339 timestamp with an explicit offset." }
            }
        }),
        RecallTool::Timeline => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "since": { "type": "string", "description": "RFC3339 timestamp with an explicit offset." },
                "until": { "type": "string", "description": "RFC3339 timestamp with an explicit offset." },
                "agent": { "type": "array", "items": { "type": "string" } },
                "source": { "type": "string" },
                "group_by": { "type": "string", "enum": ["hour", "day", "none"], "default": "hour" }
            }
        }),
    };
    Arc::new(
        value
            .as_object()
            .expect("tool schema is a JSON object")
            .clone(),
    )
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const SEARCH_FIELDS: &[&str] = &[
    "query",
    "agent",
    "workspace",
    "source",
    "since",
    "until",
    "cursor",
];
const EXPAND_FIELDS: &[&str] = &[
    "message_id",
    "source_id",
    "source_path",
    "expected_content_sha256",
    "context",
];
const SESSIONS_FIELDS: &[&str] = &["limit", "workspace", "since"];
const TIMELINE_FIELDS: &[&str] = &["since", "until", "agent", "source", "group_by"];

pub fn parse(tool: RecallTool, arguments: Option<&JsonObject>) -> Result<ToolCall, ToolError> {
    let empty = Map::new();
    let arguments = arguments.unwrap_or(&empty);
    let allowed = match tool {
        RecallTool::Search => SEARCH_FIELDS,
        RecallTool::Expand => EXPAND_FIELDS,
        RecallTool::Sessions => SESSIONS_FIELDS,
        RecallTool::Timeline => TIMELINE_FIELDS,
    };
    for key in arguments.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(ToolError::invalid_argument(format!(
                "`{key}` is not a field of {}",
                tool.name()
            )));
        }
    }

    match tool {
        RecallTool::Search => parse_search(arguments),
        RecallTool::Expand => parse_expand(arguments),
        RecallTool::Sessions => parse_sessions(arguments),
        RecallTool::Timeline => parse_timeline(arguments),
    }
}

fn parse_search(arguments: &Map<String, Value>) -> Result<ToolCall, ToolError> {
    let query = required_string(arguments, "query")?;
    let agent = string_array(arguments, "agent")?;
    let workspace = string_array(arguments, "workspace")?;
    for value in &workspace {
        require_absolute(value, "workspace")?;
    }
    let source = optional_string(arguments, "source")?;
    let since = optional_string(arguments, "since")?;
    let until = optional_string(arguments, "until")?;
    validate_times(since.as_deref(), until.as_deref())?;
    let cursor = optional_string(arguments, "cursor")?;
    Ok(ToolCall::Search {
        query,
        agent,
        workspace,
        source,
        since,
        until,
        cursor,
    })
}

fn parse_expand(arguments: &Map<String, Value>) -> Result<ToolCall, ToolError> {
    let source_path = required_string(arguments, "source_path")?;
    let source_id = required_string(arguments, "source_id")?;
    let message_id = required_u64(arguments, "message_id", 1)?;
    if message_id > i64::MAX as u64 {
        return Err(ToolError::invalid_argument(
            "`message_id` must be within the signed 64-bit range",
        ));
    }
    let expected_content_sha256 = required_string(arguments, "expected_content_sha256")?;
    if expected_content_sha256.len() != 64
        || !expected_content_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(ToolError::invalid_argument(
            "`expected_content_sha256` must be 64 hexadecimal characters",
        ));
    }
    let context = match arguments.get("context") {
        None => 3,
        Some(value) => integer(value, "context", 0)?,
    };
    let _ = usize::try_from(context)
        .map_err(|_| ToolError::invalid_argument("`context` must fit the platform usize range"))?;
    Ok(ToolCall::Expand {
        source_path,
        source_id,
        message_id,
        expected_content_sha256,
        context,
    })
}

fn parse_sessions(arguments: &Map<String, Value>) -> Result<ToolCall, ToolError> {
    let limit = match arguments.get("limit") {
        None => 10,
        Some(value) => integer(value, "limit", 1)?,
    };
    let _ = usize::try_from(limit)
        .map_err(|_| ToolError::invalid_argument("`limit` must fit the platform usize range"))?;
    let workspace = optional_string(arguments, "workspace")?;
    if let Some(value) = workspace.as_deref() {
        require_absolute(value, "workspace")?;
    }
    let since = optional_string(arguments, "since")?;
    validate_times(since.as_deref(), None)?;
    Ok(ToolCall::Sessions {
        limit,
        workspace,
        since,
    })
}

fn parse_timeline(arguments: &Map<String, Value>) -> Result<ToolCall, ToolError> {
    let since = optional_string(arguments, "since")?;
    let until = optional_string(arguments, "until")?;
    validate_times(since.as_deref(), until.as_deref())?;
    let agent = string_array(arguments, "agent")?;
    let source = optional_string(arguments, "source")?;
    let group_by = match arguments.get("group_by") {
        None => GroupBy::Hour,
        Some(Value::String(value)) if !value.trim().is_empty() => match value.as_str() {
            "hour" => GroupBy::Hour,
            "day" => GroupBy::Day,
            "none" => GroupBy::None,
            _ => {
                return Err(ToolError::invalid_argument(
                    "`group_by` must be one of hour, day, none",
                ));
            }
        },
        Some(_) => {
            return Err(ToolError::invalid_argument(
                "`group_by` must be one of hour, day, none",
            ));
        }
    };
    Ok(ToolCall::Timeline {
        since,
        until,
        agent,
        source,
        group_by,
    })
}

fn required_string(arguments: &Map<String, Value>, key: &str) -> Result<String, ToolError> {
    match arguments.get(key) {
        None => Err(ToolError::invalid_argument(format!("`{key}` is required"))),
        Some(value) => string(value, key),
    }
}

fn optional_string(arguments: &Map<String, Value>, key: &str) -> Result<Option<String>, ToolError> {
    match arguments.get(key) {
        None => Ok(None),
        Some(value) => string(value, key).map(Some),
    }
}

fn string(value: &Value, key: &str) -> Result<String, ToolError> {
    match value {
        Value::String(text) if !text.trim().is_empty() => Ok(text.clone()),
        _ => Err(ToolError::invalid_argument(format!(
            "`{key}` must be a non-blank string"
        ))),
    }
}

fn string_array(arguments: &Map<String, Value>, key: &str) -> Result<Vec<String>, ToolError> {
    match arguments.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| string(item, key))
            .collect::<Result<Vec<_>, _>>(),
        Some(_) => Err(ToolError::invalid_argument(format!(
            "`{key}` must be an array of strings"
        ))),
    }
}

fn required_u64(arguments: &Map<String, Value>, key: &str, minimum: u64) -> Result<u64, ToolError> {
    match arguments.get(key) {
        None => Err(ToolError::invalid_argument(format!("`{key}` is required"))),
        Some(value) => integer(value, key, minimum),
    }
}

/// Accept only JSON integers that are present as a whole number, at or above
/// `minimum`, and representable exactly. Fractions, exponents that landed on
/// a float, negatives below the minimum, and out-of-range values are rejected.
fn integer(value: &Value, key: &str, minimum: u64) -> Result<u64, ToolError> {
    let parsed = match value {
        Value::Number(number) => number.as_u64(),
        _ => None,
    };
    match parsed {
        Some(number) if number >= minimum => Ok(number),
        _ => Err(ToolError::invalid_argument(format!(
            "`{key}` must be an integer greater than or equal to {minimum}"
        ))),
    }
}

fn require_absolute(value: &str, key: &str) -> Result<(), ToolError> {
    if PathBuf::from(value).is_absolute() {
        Ok(())
    } else {
        Err(ToolError::invalid_argument(format!(
            "`{key}` must be an absolute server-side identifier"
        )))
    }
}

/// Strict RFC3339 with `Z` or an explicit numeric offset. The caller's text is
/// never converted; parsing only decides whether the input may proceed.
fn validate_times(since: Option<&str>, until: Option<&str>) -> Result<(), ToolError> {
    let since = since.map(parse_time).transpose()?;
    let until = until.map(parse_time).transpose()?;
    if let (Some(since), Some(until)) = (since, until)
        && since > until
    {
        return Err(ToolError::invalid_argument(
            "`since` must not be later than `until`",
        ));
    }
    Ok(())
}

fn parse_time(value: &str) -> Result<chrono::DateTime<chrono::FixedOffset>, ToolError> {
    chrono::DateTime::parse_from_rfc3339(value).map_err(|_| {
        ToolError::invalid_argument(
            "time values must be RFC3339 timestamps with an explicit offset",
        )
    })
}
