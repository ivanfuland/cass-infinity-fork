//! Codex standard-fact mapping (Task12).
//!
//! This module maps one already-parsed Codex `Jsonl` or `JsonDocument` source
//! value to the frozen `StandardFacts` shape. It reads only the lossless source
//! tree, delegates every scalar fact to the Task28 primitives, and never goes
//! through `serde_json::Value`, `f64` or the legacy statistics chain.

use std::collections::BTreeMap;

use franken_agent_detection::LosslessSourceValue;

use super::{
    FactStatus, FactValue, FieldFact, StandardFacts, ToolFact, UsageSnapshot, alias_fact,
    count_fact, time_fact, value_fact,
};
use crate::storage::source_facts::SourceFormat;

/// Codex count registration: standard field to source key.
const COUNT_KEYS: &[(&str, &str)] = &[
    ("input", "input_tokens"),
    ("output", "output_tokens"),
    ("cache_read", "cached_input_tokens"),
    ("cache_write", "cache_write_input_tokens"),
    ("thinking", "reasoning_output_tokens"),
    ("total", "total_tokens"),
];

/// Map one Codex source value to the complete standard fact object.
#[must_use]
pub fn map_codex_standard(format: SourceFormat, safe_value: &LosslessSourceValue) -> StandardFacts {
    match format {
        // Codex keeps one event dialect for both wire formats.
        SourceFormat::Jsonl | SourceFormat::JsonDocument => map_event(safe_value),
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

fn map_event(root: &LosslessSourceValue) -> StandardFacts {
    let mut standard = default_standard();
    let event_type = root.get("type").and_then(LosslessSourceValue::as_str);
    let payload = root.get("payload");

    standard.times.insert(
        "event".to_owned(),
        time_fact(root.get("timestamp"), "/timestamp"),
    );
    if matches!(payload, Some(LosslessSourceValue::Object(_))) {
        if let Some(timestamp) = payload.and_then(|value| value.get("timestamp")) {
            standard.times.insert(
                "payload".to_owned(),
                time_fact(Some(timestamp), "/payload/timestamp"),
            );
        }
        if let Some(cwd) = payload.and_then(|value| value.get("cwd")) {
            standard.native_ids.insert(
                "cwd".to_owned(),
                string_fact("cwd", Some(cwd), "/payload/cwd", false),
            );
        }
    }

    match event_type {
        Some("turn_context") => {
            standard.model = string_fact(
                "model",
                payload.and_then(|value| value.get("model")),
                "/payload/model",
                false,
            );
        }
        Some("session_meta") => {
            standard.provider = string_fact(
                "provider",
                payload.and_then(|value| value.get("model_provider")),
                "/payload/model_provider",
                false,
            );
            standard.native_ids.insert(
                "session_metadata_id".to_owned(),
                string_fact(
                    "session_metadata_id",
                    payload.and_then(|value| value.get("id")),
                    "/payload/id",
                    true,
                ),
            );
        }
        Some("response_item") => map_response_item(&mut standard, payload),
        Some("event_msg") => map_event_msg(&mut standard, payload),
        Some("token_count") => map_token_count(&mut standard, payload),
        Some("token_usage_record") => map_token_usage_record(&mut standard, payload),
        _ => {}
    }
    standard
}

fn map_response_item(standard: &mut StandardFacts, payload: Option<&LosslessSourceValue>) {
    standard.native_ids.insert(
        "item_id".to_owned(),
        string_fact(
            "item_id",
            payload.and_then(|value| value.get("id")),
            "/payload/id",
            true,
        ),
    );

    let item_type = payload
        .and_then(|value| value.get("type"))
        .and_then(LosslessSourceValue::as_str);
    let is_call = matches!(item_type, Some("function_call" | "custom_tool_call"));
    let is_output = matches!(
        item_type,
        Some("function_call_output" | "custom_tool_call_output")
    );
    if is_call || is_output {
        standard.native_ids.insert(
            "call_id".to_owned(),
            string_fact(
                "call_id",
                payload.and_then(|value| value.get("call_id")),
                "/payload/call_id",
                true,
            ),
        );
    }

    if is_call {
        standard.tools.push(response_call_tool(payload));
    } else if is_output {
        standard.tools.push(response_result_tool(payload));
    }
}

fn response_call_tool(payload: Option<&LosslessSourceValue>) -> ToolFact {
    let mut fields = BTreeMap::new();
    fields.insert(
        "name".to_owned(),
        string_fact(
            "name",
            payload.and_then(|value| value.get("name")),
            "/payload/name",
            false,
        ),
    );
    fields.insert(
        "id".to_owned(),
        string_fact(
            "id",
            payload.and_then(|value| value.get("call_id")),
            "/payload/call_id",
            true,
        ),
    );
    fields.insert("arguments".to_owned(), arguments_fact(payload));
    ToolFact {
        kind: "call".to_owned(),
        raw_ref: "/payload".to_owned(),
        fields,
    }
}

fn response_result_tool(payload: Option<&LosslessSourceValue>) -> ToolFact {
    let mut fields = BTreeMap::new();
    fields.insert(
        "id".to_owned(),
        string_fact(
            "id",
            payload.and_then(|value| value.get("call_id")),
            "/payload/call_id",
            true,
        ),
    );
    fields.insert(
        "output".to_owned(),
        value_fact(
            "output",
            payload.and_then(|value| value.get("output")),
            "/payload/output",
        ),
    );
    fields.insert(
        "status".to_owned(),
        status_fact(
            payload.and_then(|value| value.get("status")),
            "/payload/status",
        ),
    );
    ToolFact {
        kind: "result".to_owned(),
        raw_ref: "/payload/output".to_owned(),
        fields,
    }
}

fn map_event_msg(standard: &mut StandardFacts, payload: Option<&LosslessSourceValue>) {
    let payload_type = payload
        .and_then(|value| value.get("type"))
        .and_then(LosslessSourceValue::as_str);

    if matches!(
        payload_type,
        Some("tool_call" | "function_call" | "token_usage_record")
    ) {
        for (name, source_key) in [
            ("call_id", "call_id"),
            ("record_id", "id"),
            ("response_id", "response_id"),
            ("thread_id", "thread_id"),
            ("turn_id", "turn_id"),
        ] {
            if let Some(node) = payload.and_then(|value| value.get(source_key)) {
                standard.native_ids.insert(
                    name.to_owned(),
                    string_fact(name, Some(node), &format!("/payload/{source_key}"), true),
                );
            }
        }
    }

    match payload_type {
        Some("tool_call" | "function_call") => {
            standard.tools.push(event_tool(payload));
            standard.tools.push(event_call_tool(payload));
        }
        Some("token_usage_record") => map_token_usage_snapshots(standard, payload),
        Some("token_count") => map_token_count(standard, payload),
        _ => {}
    }
}

fn event_tool(payload: Option<&LosslessSourceValue>) -> ToolFact {
    let mut fields = BTreeMap::new();
    fields.insert(
        "event_type".to_owned(),
        string_fact(
            "event_type",
            payload.and_then(|value| value.get("type")),
            "/payload/type",
            false,
        ),
    );
    fields.insert(
        "status".to_owned(),
        status_fact(
            payload.and_then(|value| value.get("status")),
            "/payload/status",
        ),
    );
    ToolFact {
        kind: "event".to_owned(),
        raw_ref: "/payload".to_owned(),
        fields,
    }
}

fn event_call_tool(payload: Option<&LosslessSourceValue>) -> ToolFact {
    let mut fields = BTreeMap::new();
    fields.insert(
        "name".to_owned(),
        string_fact(
            "name",
            payload.and_then(|value| value.get("name")),
            "/payload/name",
            false,
        ),
    );
    // The fallback is only for a truly absent `call_id` key. A present null or
    // wrong type stays at its own location and never reaches `id`.
    let (id_node, id_ref) = match payload.and_then(|value| value.get("call_id")) {
        Some(node) => (Some(node), "/payload/call_id"),
        None => (payload.and_then(|value| value.get("id")), "/payload/id"),
    };
    fields.insert("id".to_owned(), string_fact("id", id_node, id_ref, true));
    fields.insert("arguments".to_owned(), arguments_fact(payload));
    ToolFact {
        kind: "call".to_owned(),
        raw_ref: "/payload".to_owned(),
        fields,
    }
}

fn arguments_fact(payload: Option<&LosslessSourceValue>) -> FieldFact {
    let arguments = payload.and_then(|value| value.get("arguments"));
    let input = payload.and_then(|value| value.get("input"));
    if arguments.is_none() && input.is_none() {
        return value_fact("arguments", None, "/payload/arguments");
    }
    let mut candidates = Vec::new();
    if let Some(node) = arguments {
        candidates.push(value_fact("arguments", Some(node), "/payload/arguments"));
    }
    if let Some(node) = input {
        candidates.push(value_fact("arguments", Some(node), "/payload/input"));
    }
    alias_fact("arguments", &candidates)
}

fn status_fact(node: Option<&LosslessSourceValue>, raw_ref: &str) -> FieldFact {
    let mut fact = value_fact("status", node, raw_ref);
    if fact.status == FactStatus::Present {
        fact.status = FactStatus::Invalid;
        fact.reason = Some("unmapped".to_owned());
    }
    fact
}

fn map_token_count(standard: &mut StandardFacts, payload: Option<&LosslessSourceValue>) {
    let Some(payload @ LosslessSourceValue::Object(_)) = payload else {
        return;
    };

    if let Some(info @ LosslessSourceValue::Object(_)) = payload.get("info") {
        if let Some(last) = info.get("last_token_usage") {
            standard.usage.push(snapshot(
                "codex_last",
                "snapshot",
                "/payload/info/last_token_usage",
                usage_container(Some(last), "/payload/info/last_token_usage", COUNT_KEYS),
            ));
        }
        if let Some(total) = info.get("total_token_usage") {
            standard.usage.push(snapshot(
                "codex_total",
                "snapshot",
                "/payload/info/total_token_usage",
                usage_container(Some(total), "/payload/info/total_token_usage", COUNT_KEYS),
            ));
        }
        if let Some(window) = info.get("model_context_window") {
            let mut fields = BTreeMap::new();
            fields.insert(
                "context_window".to_owned(),
                count_fact(
                    "context_window",
                    Some(window),
                    "/payload/info/model_context_window",
                ),
            );
            standard.usage.push(snapshot(
                "capacity",
                "context_window",
                "/payload/info/model_context_window",
                fields,
            ));
        }
    }

    if let Some(rate_limits) = payload.get("rate_limits") {
        let mut fields = BTreeMap::new();
        fields.insert(
            "rate_limits".to_owned(),
            value_fact("rate_limits", Some(rate_limits), "/payload/rate_limits"),
        );
        standard.usage.push(snapshot(
            "rate_limits",
            "limits",
            "/payload/rate_limits",
            fields,
        ));
    }

    map_legacy_usage(standard, payload);
}

fn map_legacy_usage(standard: &mut StandardFacts, payload: &LosslessSourceValue) {
    let input = payload.get("input_tokens");
    let output = payload.get("output_tokens");
    let tokens = payload.get("tokens");
    if input.is_none() && output.is_none() && tokens.is_none() {
        return;
    }

    let mut fields = BTreeMap::new();
    if let Some(node) = input {
        fields.insert(
            "input".to_owned(),
            count_fact("input", Some(node), "/payload/input_tokens"),
        );
    }
    if let Some(node) = tokens {
        fields.insert(
            "output_legacy".to_owned(),
            count_fact("output_legacy", Some(node), "/payload/tokens"),
        );
    }
    let mut candidates = Vec::new();
    if let Some(node) = output {
        candidates.push(count_fact("output", Some(node), "/payload/output_tokens"));
    }
    if let Some(node) = tokens {
        candidates.push(count_fact("output", Some(node), "/payload/tokens"));
    }
    if !candidates.is_empty() {
        fields.insert("output".to_owned(), alias_fact("output", &candidates));
    }
    standard
        .usage
        .push(snapshot("codex_legacy", "token_count", "/payload", fields));
}

fn map_token_usage_record(standard: &mut StandardFacts, payload: Option<&LosslessSourceValue>) {
    for (name, source_key) in [
        ("response_id", "response_id"),
        ("thread_id", "thread_id"),
        ("turn_id", "turn_id"),
    ] {
        standard.native_ids.insert(
            name.to_owned(),
            string_fact(
                name,
                payload.and_then(|value| value.get(source_key)),
                &format!("/payload/{source_key}"),
                true,
            ),
        );
    }
    map_token_usage_snapshots(standard, payload);
}

fn map_token_usage_snapshots(standard: &mut StandardFacts, payload: Option<&LosslessSourceValue>) {
    for (source_key, scope) in [
        ("usage", "token_usage_record_usage"),
        ("turn_token_usage", "token_usage_record_turn"),
        ("thread_token_usage", "token_usage_record_thread"),
    ] {
        let Some(node) = payload.and_then(|value| value.get(source_key)) else {
            continue;
        };
        standard.usage.push(snapshot(
            scope,
            "snapshot",
            &format!("/payload/{source_key}"),
            usage_container(Some(node), &format!("/payload/{source_key}"), COUNT_KEYS),
        ));
    }
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
            Some(LosslessSourceValue::Null) => missing_null(field, container_ref),
            Some(_) => invalid(field, container_ref, "bad_type"),
            None => count_fact(field, None, &format!("{container_ref}/{source_key}")),
        };
        fields.insert((*field).to_owned(), fact);
    }
    fields
}

fn snapshot(
    scope: &str,
    role: &str,
    raw_ref: &str,
    fields: BTreeMap<String, FieldFact>,
) -> UsageSnapshot {
    UsageSnapshot {
        scope: scope.to_owned(),
        role: role.to_owned(),
        raw_ref: raw_ref.to_owned(),
        fields,
    }
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
