//! Claude standard-fact mapping (Task11).
//!
//! This module maps one already-parsed Claude `Jsonl` or `JsonDocument` source
//! value to the frozen `StandardFacts` shape. It reads only the lossless source
//! tree, delegates every scalar fact to the Task28 primitives, and never goes
//! through `serde_json::Value`, `f64` or the legacy statistics chain.

use std::collections::BTreeMap;

use franken_agent_detection::LosslessSourceValue;

use super::{
    FactStatus, FactValue, FieldFact, MessageFacts, StandardFacts, ToolFact, UsageSnapshot,
    alias_fact, count_fact, time_fact, value_fact,
};
use crate::storage::source_facts::SourceFormat;

/// Map one Claude source value to the complete standard fact object.
#[must_use]
pub fn map_claude_standard(
    format: SourceFormat,
    safe_value: &LosslessSourceValue,
) -> StandardFacts {
    match format {
        SourceFormat::Jsonl => map_jsonl(safe_value),
        SourceFormat::JsonDocument => map_document(safe_value),
    }
}

fn default_standard() -> StandardFacts {
    StandardFacts {
        model: not_applicable("model"),
        provider: not_applicable("provider"),
        native_ids: BTreeMap::new(),
        times: BTreeMap::new(),
        tools: Vec::new(),
        usage: Vec::new(),
        messages: Vec::new(),
    }
}

fn map_jsonl(root: &LosslessSourceValue) -> StandardFacts {
    let mut standard = default_standard();
    let event_type = root.get("type").and_then(LosslessSourceValue::as_str);
    let role = effective_role(root, event_type);
    let message = root.get("message");

    if role == Some("assistant") {
        standard.model = string_fact(
            "model",
            message.and_then(|value| value.get("model")),
            "/message/model",
            false,
        );
    }

    let native_gate = matches!(event_type, Some("assistant" | "user" | "system"));
    if native_gate || root.get("sessionId").is_some() {
        standard.native_ids.insert(
            "session_id".to_owned(),
            string_fact("session_id", root.get("sessionId"), "/sessionId", true),
        );
    }
    if native_gate || root.get("uuid").is_some() {
        standard.native_ids.insert(
            "record_uuid".to_owned(),
            string_fact("record_uuid", root.get("uuid"), "/uuid", true),
        );
    }
    if role == Some("assistant") {
        standard.native_ids.insert(
            "provider_message_id".to_owned(),
            string_fact(
                "provider_message_id",
                message.and_then(|value| value.get("id")),
                "/message/id",
                true,
            ),
        );
        standard.native_ids.insert(
            "request_id".to_owned(),
            string_fact("request_id", root.get("requestId"), "/requestId", true),
        );
    }

    standard.times.insert(
        "event".to_owned(),
        time_fact(root.get("timestamp"), "/timestamp"),
    );
    standard.tools = jsonl_tools(message, role);
    standard.usage = jsonl_usage(root, message, role);
    standard
}

fn effective_role<'a>(
    root: &'a LosslessSourceValue,
    event_type: Option<&'a str>,
) -> Option<&'a str> {
    let message = root.get("message");
    let inner = message
        .and_then(|value| value.get("role"))
        .and_then(LosslessSourceValue::as_str);
    if matches!(event_type, Some("user" | "assistant" | "message"))
        && matches!(inner, Some("user" | "assistant"))
    {
        return inner;
    }
    let role_key_present = message.is_some_and(|value| {
        matches!(value, LosslessSourceValue::Object(members) if members.iter().any(|(key, _)| key == "role"))
    });
    if matches!(event_type, Some("user" | "assistant")) && !role_key_present {
        return event_type;
    }
    None
}

fn jsonl_tools(message: Option<&LosslessSourceValue>, role: Option<&str>) -> Vec<ToolFact> {
    let mut tools = Vec::new();
    let Some(message) = message else {
        return tools;
    };
    if let Some(LosslessSourceValue::Array(blocks)) = message.get("content") {
        for (index, block) in blocks.iter().enumerate() {
            let raw_ref = format!("/message/content/{index}");
            let block_type = block.get("type").and_then(LosslessSourceValue::as_str);
            match block_type {
                Some("tool_use") if role == Some("assistant") => {
                    let mut fields = BTreeMap::new();
                    fields.insert(
                        "name".to_owned(),
                        string_fact("name", block.get("name"), &format!("{raw_ref}/name"), false),
                    );
                    fields.insert(
                        "id".to_owned(),
                        string_fact("id", block.get("id"), &format!("{raw_ref}/id"), true),
                    );
                    fields.insert(
                        "input".to_owned(),
                        value_fact("input", block.get("input"), &format!("{raw_ref}/input")),
                    );
                    tools.push(ToolFact {
                        kind: "call".to_owned(),
                        raw_ref,
                        fields,
                    });
                }
                Some("tool_use") => {
                    let mut fields = BTreeMap::new();
                    fields.insert(
                        "name".to_owned(),
                        string_fact("name", block.get("name"), &format!("{raw_ref}/name"), false),
                    );
                    tools.push(ToolFact {
                        kind: "tool_use_off_role".to_owned(),
                        raw_ref,
                        fields,
                    });
                }
                Some("tool_result") => {
                    let mut fields = BTreeMap::new();
                    fields.insert(
                        "id".to_owned(),
                        string_fact(
                            "id",
                            block.get("tool_use_id"),
                            &format!("{raw_ref}/tool_use_id"),
                            true,
                        ),
                    );
                    fields.insert(
                        "content".to_owned(),
                        value_fact(
                            "content",
                            block.get("content"),
                            &format!("{raw_ref}/content"),
                        ),
                    );
                    fields.insert(
                        "is_error".to_owned(),
                        bool_fact(
                            "is_error",
                            block.get("is_error"),
                            &format!("{raw_ref}/is_error"),
                        ),
                    );
                    tools.push(ToolFact {
                        kind: "result".to_owned(),
                        raw_ref,
                        fields,
                    });
                }
                _ => {}
            }
        }
    }
    if message.get("stop_reason").is_some() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "value".to_owned(),
            string_fact(
                "stop_reason",
                message.get("stop_reason"),
                "/message/stop_reason",
                false,
            ),
        );
        tools.push(ToolFact {
            kind: "stop_reason".to_owned(),
            raw_ref: "/message/stop_reason".to_owned(),
            fields,
        });
    }
    tools
}

fn jsonl_usage(
    root: &LosslessSourceValue,
    message: Option<&LosslessSourceValue>,
    role: Option<&str>,
) -> Vec<UsageSnapshot> {
    let mut usage = Vec::new();
    if role == Some("assistant") {
        if let Some(container) = message.and_then(|value| value.get("usage")) {
            let mut fields = usage_container(
                Some(container),
                "/message/usage",
                &[
                    ("input", "input_tokens"),
                    ("output", "output_tokens"),
                    ("cache_read", "cache_read_input_tokens"),
                    ("cache_write", "cache_creation_input_tokens"),
                    ("thinking", "thinking_tokens"),
                ],
            );
            fields.insert("total".to_owned(), not_applicable("total"));
            if let Some(details) = container.get("output_tokens_details") {
                fields.insert(
                    "output_tokens_details".to_owned(),
                    value_fact(
                        "output_tokens_details",
                        Some(details),
                        "/message/usage/output_tokens_details",
                    ),
                );
            }
            usage.push(UsageSnapshot {
                scope: "event".to_owned(),
                role: "message_usage".to_owned(),
                raw_ref: "/message/usage".to_owned(),
                fields,
            });
            if let Some(cache_creation) = container.get("cache_creation") {
                usage.push(UsageSnapshot {
                    scope: "cache_creation_detail".to_owned(),
                    role: "message_usage".to_owned(),
                    raw_ref: "/message/usage/cache_creation".to_owned(),
                    fields: usage_container(
                        Some(cache_creation),
                        "/message/usage/cache_creation",
                        &[
                            ("cache_write_5m", "ephemeral_5m_input_tokens"),
                            ("cache_write_1h", "ephemeral_1h_input_tokens"),
                        ],
                    ),
                });
            }
        }
    }

    if let Some(tool_use_result) = root.get("toolUseResult") {
        if matches!(tool_use_result, LosslessSourceValue::Object(_)) {
            if let Some(nested) = tool_use_result.get("usage") {
                usage.push(UsageSnapshot {
                    scope: "nested_result".to_owned(),
                    role: "tool_use_result".to_owned(),
                    raw_ref: "/toolUseResult/usage".to_owned(),
                    fields: usage_container(
                        Some(nested),
                        "/toolUseResult/usage",
                        &[
                            ("input", "input_tokens"),
                            ("output", "output_tokens"),
                            ("cache_read", "cache_read_input_tokens"),
                            ("cache_write", "cache_creation_input_tokens"),
                        ],
                    ),
                });
            }
            if let Some(total) = tool_use_result.get("totalTokens") {
                let mut fields = BTreeMap::new();
                fields.insert(
                    "total".to_owned(),
                    count_fact("total", Some(total), "/toolUseResult/totalTokens"),
                );
                usage.push(UsageSnapshot {
                    scope: "nested_result_total".to_owned(),
                    role: "tool_use_result".to_owned(),
                    raw_ref: "/toolUseResult/totalTokens".to_owned(),
                    fields,
                });
            }
            for cost_key in ["costState", "cost-state"] {
                let Some(cost_state) = tool_use_result.get(cost_key) else {
                    continue;
                };
                if !matches!(cost_state, LosslessSourceValue::Object(_)) {
                    continue;
                }
                let Some(LosslessSourceValue::Object(models)) = cost_state.get("modelUsage") else {
                    continue;
                };
                for (model_key, model_value) in models {
                    if !matches!(model_value, LosslessSourceValue::Object(_)) {
                        continue;
                    }
                    let raw_ref = format!(
                        "/toolUseResult/{cost_key}/modelUsage/{}",
                        escape_pointer(model_key)
                    );
                    usage.push(UsageSnapshot {
                        scope: "cost_state".to_owned(),
                        role: "model_usage".to_owned(),
                        raw_ref,
                        fields: usage_container(
                            Some(model_value),
                            &format!(
                                "/toolUseResult/{cost_key}/modelUsage/{}",
                                escape_pointer(model_key)
                            ),
                            &[
                                ("input", "input_tokens"),
                                ("output", "output_tokens"),
                                ("cache_read", "cache_read_input_tokens"),
                                ("cache_write", "cache_creation_input_tokens"),
                            ],
                        ),
                    });
                }
            }
        }
    }

    if let Some(LosslessSourceValue::Object(models)) = root.get("modelUsage") {
        for (model_key, model_value) in models {
            let raw_ref = format!("/modelUsage/{}", escape_pointer(model_key));
            let mut fields = usage_container(
                Some(model_value),
                &raw_ref,
                &[
                    ("input", "input_tokens"),
                    ("output", "output_tokens"),
                    ("cache_read", "cache_read_input_tokens"),
                    ("cache_write", "cache_creation_input_tokens"),
                ],
            );
            fields.insert(
                "source_details".to_owned(),
                value_fact("source_details", Some(model_value), &raw_ref),
            );
            usage.push(UsageSnapshot {
                scope: "cost_state".to_owned(),
                role: "model_usage".to_owned(),
                raw_ref,
                fields,
            });
        }
    }

    usage
}

fn usage_container(
    container: Option<&LosslessSourceValue>,
    container_ref: &str,
    keys: &[(&str, &str)],
) -> BTreeMap<String, FieldFact> {
    let mut fields = BTreeMap::new();
    for (field, source_key) in keys {
        let fact = match container {
            Some(LosslessSourceValue::Object(_)) => count_fact(
                field,
                container.and_then(|value| value.get(source_key)),
                &format!("{container_ref}/{source_key}"),
            ),
            Some(LosslessSourceValue::Null) => container_missing(field, container_ref),
            Some(_) => container_invalid(field, container_ref),
            None => count_fact(field, None, &format!("{container_ref}/{source_key}")),
        };
        fields.insert((*field).to_owned(), fact);
    }
    fields
}

fn map_document(root: &LosslessSourceValue) -> StandardFacts {
    let mut standard = default_standard();
    standard.native_ids.insert(
        "session_id".to_owned(),
        string_fact("session_id", root.get("sessionId"), "/sessionId", true),
    );

    if let Some(LosslessSourceValue::Array(items)) = root.get("messages") {
        for (index, item) in items.iter().enumerate() {
            let reference = format!("/messages/{index}");
            let timestamp = item.get("timestamp");
            let mut times = BTreeMap::new();
            if let Some(value) = timestamp {
                times.insert(
                    "timestamp".to_owned(),
                    time_fact(Some(value), &format!("{reference}/timestamp")),
                );
            }
            if let Some(value) = item.get("time") {
                let fact = if let Some(timestamp) = timestamp {
                    let candidates = [
                        time_fact(Some(timestamp), &format!("{reference}/timestamp")),
                        time_fact(Some(value), &format!("{reference}/time")),
                    ];
                    alias_fact("time", &candidates)
                } else {
                    time_fact(Some(value), &format!("{reference}/time"))
                };
                times.insert("time".to_owned(), fact);
            }

            let mut candidates = Vec::new();
            for key in ["role", "type"] {
                if let Some(value) = item.get(key) {
                    candidates.push(string_fact(
                        "role",
                        Some(value),
                        &format!("{reference}/{key}"),
                        false,
                    ));
                }
            }
            let mut role = Vec::new();
            if !candidates.is_empty() {
                role.push(alias_fact("role", &candidates));
            }

            standard.messages.push(MessageFacts {
                reference: reference.clone(),
                model: not_applicable("model"),
                ids: BTreeMap::new(),
                times,
                role,
                usage: Vec::new(),
                tools: document_tools(item, &reference),
            });
        }
    }
    standard
}

fn document_tools(item: &LosslessSourceValue, reference: &str) -> Vec<ToolFact> {
    let mut tools = Vec::new();
    if let Some(LosslessSourceValue::Array(blocks)) = item.get("content") {
        for (index, block) in blocks.iter().enumerate() {
            let block_type = block.get("type").and_then(LosslessSourceValue::as_str);
            if !matches!(block_type, Some("tool_use" | "tool_result")) {
                continue;
            }
            let raw_ref = format!("{reference}/content/{index}");
            let mut fields = BTreeMap::new();
            fields.insert(
                "content".to_owned(),
                FieldFact {
                    field: "content".to_owned(),
                    status: FactStatus::Invalid,
                    value: None,
                    value_kind: None,
                    raw_ref: Some(raw_ref.clone()),
                    presence_ref: None,
                    reason: Some("unmapped".to_owned()),
                    refs: None,
                    unit: None,
                },
            );
            tools.push(ToolFact {
                kind: "event".to_owned(),
                raw_ref,
                fields,
            });
        }
    }
    tools
}

fn escape_pointer(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn not_applicable(field: &str) -> FieldFact {
    FieldFact {
        field: field.to_owned(),
        status: FactStatus::Missing,
        value: None,
        value_kind: None,
        raw_ref: None,
        presence_ref: None,
        reason: Some("not_applicable".to_owned()),
        refs: None,
        unit: None,
    }
}

fn missing_absent(field: &str, raw_ref: &str) -> FieldFact {
    FieldFact {
        field: field.to_owned(),
        status: FactStatus::Missing,
        value: None,
        value_kind: None,
        raw_ref: None,
        presence_ref: Some(raw_ref.to_owned()),
        reason: Some("absent".to_owned()),
        refs: None,
        unit: None,
    }
}

fn missing_null(field: &str, raw_ref: &str) -> FieldFact {
    FieldFact {
        field: field.to_owned(),
        status: FactStatus::Missing,
        value: None,
        value_kind: None,
        raw_ref: Some(raw_ref.to_owned()),
        presence_ref: None,
        reason: Some("null".to_owned()),
        refs: None,
        unit: None,
    }
}

fn invalid(field: &str, raw_ref: &str, reason: &str) -> FieldFact {
    FieldFact {
        field: field.to_owned(),
        status: FactStatus::Invalid,
        value: None,
        value_kind: None,
        raw_ref: Some(raw_ref.to_owned()),
        presence_ref: None,
        reason: Some(reason.to_owned()),
        refs: None,
        unit: None,
    }
}

fn present_string(field: &str, value: &str, raw_ref: &str) -> FieldFact {
    FieldFact {
        field: field.to_owned(),
        status: FactStatus::Present,
        value: Some(FactValue::String(value.to_owned())),
        value_kind: None,
        raw_ref: Some(raw_ref.to_owned()),
        presence_ref: None,
        reason: None,
        refs: None,
        unit: None,
    }
}

fn present_bool(field: &str, value: bool, raw_ref: &str) -> FieldFact {
    FieldFact {
        field: field.to_owned(),
        status: FactStatus::Present,
        value: Some(FactValue::Boolean(value)),
        value_kind: None,
        raw_ref: Some(raw_ref.to_owned()),
        presence_ref: None,
        reason: None,
        refs: None,
        unit: None,
    }
}

fn string_fact(
    field: &str,
    node: Option<&LosslessSourceValue>,
    raw_ref: &str,
    id: bool,
) -> FieldFact {
    match node {
        None => missing_absent(field, raw_ref),
        Some(LosslessSourceValue::Null) => missing_null(field, raw_ref),
        Some(LosslessSourceValue::String(text)) => {
            if id && text.trim().is_empty() {
                invalid(field, raw_ref, "empty_id")
            } else {
                present_string(field, text, raw_ref)
            }
        }
        Some(_) => invalid(field, raw_ref, "bad_type"),
    }
}

fn bool_fact(field: &str, node: Option<&LosslessSourceValue>, raw_ref: &str) -> FieldFact {
    match node {
        None => missing_absent(field, raw_ref),
        Some(LosslessSourceValue::Null) => missing_null(field, raw_ref),
        Some(LosslessSourceValue::Bool(value)) => present_bool(field, *value, raw_ref),
        Some(_) => invalid(field, raw_ref, "bad_type"),
    }
}

fn container_missing(field: &str, container_ref: &str) -> FieldFact {
    missing_null(field, container_ref)
}

fn container_invalid(field: &str, container_ref: &str) -> FieldFact {
    invalid(field, container_ref, "bad_type")
}
