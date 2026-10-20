//! Task11 Claude standard mapper tests.
//!
//! Exactly six test functions. The original ten cases come from the fixed
//! product gold copy. The extra eighteen cases are embedded below as one fixed
//! independent literal. No expected data is generated from the mapper.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use coding_agent_search::storage::source_facts::{SourceFormat, map_claude_standard};
use franken_agent_detection::LosslessSourceValue;
use serde_json::{Value, json};

const BOUNDARY_JSON: &str = r#"{"schema":"cass.claude-mapper-boundary/1","expected_origin":"Controller-authored complete literal facts, cross-checked independently with frozen de50 oracle; no product imports or candidate output. Fixed original24/16 unchanged.","spec_sha256":"131d3ed17d99c0661e0e138571e73b8085017531be31fc324cd8b1575fbc334a","cases":[{"id":"cb01-root-array","connector":"claude_code","format":"jsonl","input_json":"[1,null,{\"type\":\"assistant\"}]","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[],"messages":[]}},{"id":"cb02-unknown-event","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"future\",\"timestamp\":null,\"message\":{\"model\":\"not-applicable\"}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{},"times":{"event":{"field":"time","status":"missing","reason":"null","raw_ref":"/timestamp"}},"tools":[],"usage":[],"messages":[]}},{"id":"cb03-role-null","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"assistant\",\"message\":{\"role\":null,\"model\":\"must-not-promote\"}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"},"record_uuid":{"field":"record_uuid","status":"missing","reason":"absent","presence_ref":"/uuid"}},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[],"messages":[]}},{"id":"cb04-role-wrong-type","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"assistant\",\"message\":{\"role\":false,\"model\":\"must-not-promote\"}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"},"record_uuid":{"field":"record_uuid","status":"missing","reason":"absent","presence_ref":"/uuid"}},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[],"messages":[]}},{"id":"cb05-role-unknown","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"assistant\",\"message\":{\"role\":\"future\",\"model\":\"must-not-promote\"}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"},"record_uuid":{"field":"record_uuid","status":"missing","reason":"absent","presence_ref":"/uuid"}},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[],"messages":[]}},{"id":"cb06-blank-ids","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"assistant\",\"sessionId\":\"\",\"uuid\":\"  \",\"requestId\":\"\\t\",\"message\":{\"id\":\"\"}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"absent","presence_ref":"/message/model"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"invalid","reason":"empty_id","raw_ref":"/sessionId"},"record_uuid":{"field":"record_uuid","status":"invalid","reason":"empty_id","raw_ref":"/uuid"},"provider_message_id":{"field":"provider_message_id","status":"invalid","reason":"empty_id","raw_ref":"/message/id"},"request_id":{"field":"request_id","status":"invalid","reason":"empty_id","raw_ref":"/requestId"}},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[],"messages":[]}},{"id":"cb07-null-usage","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"assistant\",\"message\":{\"usage\":null}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"absent","presence_ref":"/message/model"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"},"record_uuid":{"field":"record_uuid","status":"missing","reason":"absent","presence_ref":"/uuid"},"provider_message_id":{"field":"provider_message_id","status":"missing","reason":"absent","presence_ref":"/message/id"},"request_id":{"field":"request_id","status":"missing","reason":"absent","presence_ref":"/requestId"}},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[{"scope":"event","role":"message_usage","raw_ref":"/message/usage","fields":{"input":{"field":"input","status":"missing","reason":"null","raw_ref":"/message/usage"},"output":{"field":"output","status":"missing","reason":"null","raw_ref":"/message/usage"},"cache_read":{"field":"cache_read","status":"missing","reason":"null","raw_ref":"/message/usage"},"cache_write":{"field":"cache_write","status":"missing","reason":"null","raw_ref":"/message/usage"},"thinking":{"field":"thinking","status":"missing","reason":"null","raw_ref":"/message/usage"},"total":{"field":"total","status":"missing","reason":"not_applicable"}}}],"messages":[]}},{"id":"cb08-wrong-usage","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"assistant\",\"message\":{\"usage\":false}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"absent","presence_ref":"/message/model"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"},"record_uuid":{"field":"record_uuid","status":"missing","reason":"absent","presence_ref":"/uuid"},"provider_message_id":{"field":"provider_message_id","status":"missing","reason":"absent","presence_ref":"/message/id"},"request_id":{"field":"request_id","status":"missing","reason":"absent","presence_ref":"/requestId"}},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[{"scope":"event","role":"message_usage","raw_ref":"/message/usage","fields":{"input":{"field":"input","status":"invalid","reason":"bad_type","raw_ref":"/message/usage"},"output":{"field":"output","status":"invalid","reason":"bad_type","raw_ref":"/message/usage"},"cache_read":{"field":"cache_read","status":"invalid","reason":"bad_type","raw_ref":"/message/usage"},"cache_write":{"field":"cache_write","status":"invalid","reason":"bad_type","raw_ref":"/message/usage"},"thinking":{"field":"thinking","status":"invalid","reason":"bad_type","raw_ref":"/message/usage"},"total":{"field":"total","status":"missing","reason":"not_applicable"}}}],"messages":[]}},{"id":"cb09-model-wrong-type","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"assistant\",\"message\":{\"model\":false}}","expected_standard":{"model":{"field":"model","status":"invalid","reason":"bad_type","raw_ref":"/message/model"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"},"record_uuid":{"field":"record_uuid","status":"missing","reason":"absent","presence_ref":"/uuid"},"provider_message_id":{"field":"provider_message_id","status":"missing","reason":"absent","presence_ref":"/message/id"},"request_id":{"field":"request_id","status":"missing","reason":"absent","presence_ref":"/requestId"}},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[],"messages":[]}},{"id":"cb10-dynamic-pointer","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"future\",\"modelUsage\":{\"a~/b\":{\"input_tokens\":1,\"m\":\"x\"}}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[{"scope":"cost_state","role":"model_usage","raw_ref":"/modelUsage/a~0~1b","fields":{"input":{"field":"input","status":"present","value":"1","raw_ref":"/modelUsage/a~0~1b/input_tokens","unit":"count"},"output":{"field":"output","status":"missing","reason":"absent","presence_ref":"/modelUsage/a~0~1b/output_tokens","unit":"count"},"cache_read":{"field":"cache_read","status":"missing","reason":"absent","presence_ref":"/modelUsage/a~0~1b/cache_read_input_tokens","unit":"count"},"cache_write":{"field":"cache_write","status":"missing","reason":"absent","presence_ref":"/modelUsage/a~0~1b/cache_creation_input_tokens","unit":"count"},"source_details":{"field":"source_details","status":"present","value":["obj",[["input_tokens",["num","1"]],["m",["str","x"]]]],"raw_ref":"/modelUsage/a~0~1b","value_kind":"object"}}}],"messages":[]}},{"id":"cb11-both-cost-keys-skip-bad","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"future\",\"toolUseResult\":{\"costState\":{\"modelUsage\":{\"a\":{\"input_tokens\":1},\"bad\":\"oops\"}},\"cost-state\":{\"modelUsage\":{\"b\":{\"input_tokens\":2}}}}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[{"scope":"cost_state","role":"model_usage","raw_ref":"/toolUseResult/costState/modelUsage/a","fields":{"input":{"field":"input","status":"present","value":"1","raw_ref":"/toolUseResult/costState/modelUsage/a/input_tokens","unit":"count"},"output":{"field":"output","status":"missing","reason":"absent","presence_ref":"/toolUseResult/costState/modelUsage/a/output_tokens","unit":"count"},"cache_read":{"field":"cache_read","status":"missing","reason":"absent","presence_ref":"/toolUseResult/costState/modelUsage/a/cache_read_input_tokens","unit":"count"},"cache_write":{"field":"cache_write","status":"missing","reason":"absent","presence_ref":"/toolUseResult/costState/modelUsage/a/cache_creation_input_tokens","unit":"count"}}},{"scope":"cost_state","role":"model_usage","raw_ref":"/toolUseResult/cost-state/modelUsage/b","fields":{"input":{"field":"input","status":"present","value":"2","raw_ref":"/toolUseResult/cost-state/modelUsage/b/input_tokens","unit":"count"},"output":{"field":"output","status":"missing","reason":"absent","presence_ref":"/toolUseResult/cost-state/modelUsage/b/output_tokens","unit":"count"},"cache_read":{"field":"cache_read","status":"missing","reason":"absent","presence_ref":"/toolUseResult/cost-state/modelUsage/b/cache_read_input_tokens","unit":"count"},"cache_write":{"field":"cache_write","status":"missing","reason":"absent","presence_ref":"/toolUseResult/cost-state/modelUsage/b/cache_creation_input_tokens","unit":"count"}}}],"messages":[]}},{"id":"cb12-document-aliases","connector":"claude_code","format":"json_document","input_json":"{\"messages\":[{\"role\":\"assistant\",\"type\":\"user\",\"timestamp\":\"1970-01-01T00:00:01Z\",\"time\":\"1970-01-01T00:00:02Z\"}]}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"}},"times":{},"tools":[],"usage":[],"messages":[{"ref":"/messages/0","model":{"field":"model","status":"missing","reason":"not_applicable"},"ids":{},"times":{"timestamp":{"field":"time","status":"present","value":"1","raw_ref":"/messages/0/timestamp","unit":"epoch"},"time":{"field":"time","status":"conflict","refs":[{"status":"present","value":"1","raw_ref":"/messages/0/timestamp","unit":"epoch"},{"status":"present","value":"2","raw_ref":"/messages/0/time","unit":"epoch"}]}},"role":[{"field":"role","status":"conflict","refs":[{"status":"present","value":"assistant","raw_ref":"/messages/0/role"},{"status":"present","value":"user","raw_ref":"/messages/0/type"}]}],"usage":[],"tools":[]}]}},{"id":"cb13-document-nonobject-item","connector":"claude_code","format":"json_document","input_json":"{\"messages\":[null]}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"}},"times":{},"tools":[],"usage":[],"messages":[{"ref":"/messages/0","model":{"field":"model","status":"missing","reason":"not_applicable"},"ids":{},"times":{},"role":[],"usage":[],"tools":[]}]}},{"id":"cb14-off-role-tool","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"user\",\"message\":{\"content\":[{\"type\":\"tool_use\",\"name\":\"\",\"id\":\"hidden\",\"input\":false}]}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"},"record_uuid":{"field":"record_uuid","status":"missing","reason":"absent","presence_ref":"/uuid"}},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[{"kind":"tool_use_off_role","raw_ref":"/message/content/0","name":{"field":"name","status":"present","value":"","raw_ref":"/message/content/0/name"}}],"usage":[],"messages":[]}},{"id":"cb15-tool-null-wrong-type","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"user\",\"message\":{\"content\":[{\"type\":\"tool_result\",\"tool_use_id\":\" \",\"content\":null,\"is_error\":\"false\"}]}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"},"record_uuid":{"field":"record_uuid","status":"missing","reason":"absent","presence_ref":"/uuid"}},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[{"kind":"result","raw_ref":"/message/content/0","id":{"field":"id","status":"invalid","reason":"empty_id","raw_ref":"/message/content/0/tool_use_id"},"content":{"field":"content","status":"missing","reason":"null","raw_ref":"/message/content/0/content"},"is_error":{"field":"is_error","status":"invalid","reason":"bad_type","raw_ref":"/message/content/0/is_error"}}],"usage":[],"messages":[]}},{"id":"cb16-nested-usage-wrong-type","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"future\",\"toolUseResult\":{\"usage\":[]}}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[{"scope":"nested_result","role":"tool_use_result","raw_ref":"/toolUseResult/usage","fields":{"input":{"field":"input","status":"invalid","reason":"bad_type","raw_ref":"/toolUseResult/usage"},"output":{"field":"output","status":"invalid","reason":"bad_type","raw_ref":"/toolUseResult/usage"},"cache_read":{"field":"cache_read","status":"invalid","reason":"bad_type","raw_ref":"/toolUseResult/usage"},"cache_write":{"field":"cache_write","status":"invalid","reason":"bad_type","raw_ref":"/toolUseResult/usage"}}}],"messages":[]}},{"id":"cb17-model-empty-allowed","connector":"claude_code","format":"jsonl","input_json":"{\"type\":\"assistant\",\"message\":{\"model\":\"\"}}","expected_standard":{"model":{"field":"model","status":"present","value":"","raw_ref":"/message/model"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"},"record_uuid":{"field":"record_uuid","status":"missing","reason":"absent","presence_ref":"/uuid"},"provider_message_id":{"field":"provider_message_id","status":"missing","reason":"absent","presence_ref":"/message/id"},"request_id":{"field":"request_id","status":"missing","reason":"absent","presence_ref":"/requestId"}},"times":{"event":{"field":"time","status":"missing","reason":"absent","presence_ref":"/timestamp"}},"tools":[],"usage":[],"messages":[]}},{"id":"cb18-document-tool-events","connector":"claude_code","format":"json_document","input_json":"{\"messages\":[{\"content\":[{\"type\":\"tool_use\",\"input\":false},{\"type\":\"tool_result\",\"content\":\"x\"},{\"type\":\"future\"}]}]}","expected_standard":{"model":{"field":"model","status":"missing","reason":"not_applicable"},"provider":{"field":"provider","status":"missing","reason":"not_applicable"},"native_ids":{"session_id":{"field":"session_id","status":"missing","reason":"absent","presence_ref":"/sessionId"}},"times":{},"tools":[],"usage":[],"messages":[{"ref":"/messages/0","model":{"field":"model","status":"missing","reason":"not_applicable"},"ids":{},"times":{},"role":[],"usage":[],"tools":[{"kind":"event","raw_ref":"/messages/0/content/0","content":{"field":"content","status":"invalid","raw_ref":"/messages/0/content/0","reason":"unmapped"}},{"kind":"event","raw_ref":"/messages/0/content/1","content":{"field":"content","status":"invalid","raw_ref":"/messages/0/content/1","reason":"unmapped"}}]}]}}]}"#;

const C02_IDS: &[&str] = &[
    "cb01-root-array",
    "cb02-unknown-event",
    "cb03-role-null",
    "cb04-role-wrong-type",
    "cb05-role-unknown",
    "cb06-blank-ids",
    "cb09-model-wrong-type",
    "cb17-model-empty-allowed",
];

const C03_IDS: &[&str] = &[
    "cb07-null-usage",
    "cb08-wrong-usage",
    "cb16-nested-usage-wrong-type",
];

const C04_IDS: &[&str] = &["cb10-dynamic-pointer", "cb11-both-cost-keys-skip-bad"];

const C05_IDS: &[&str] = &[
    "cb12-document-aliases",
    "cb13-document-nonobject-item",
    "cb18-document-tool-events",
];

const C06_IDS: &[&str] = &["cb14-off-role-tool", "cb15-tool-null-wrong-type"];

const ALL_IDS: &[&[&str]] = &[C02_IDS, C03_IDS, C04_IDS, C05_IDS, C06_IDS];

fn boundary() -> &'static Value {
    static BOUNDARY: OnceLock<Value> = OnceLock::new();
    BOUNDARY.get_or_init(|| {
        serde_json::from_str(BOUNDARY_JSON).expect("parse embedded boundary catalogue")
    })
}

fn actual_standard(format: &str, input_json: &str) -> Value {
    let safe_value =
        LosslessSourceValue::parse(input_json.as_bytes()).expect("parse lossless source value");
    let format = match format {
        "jsonl" => SourceFormat::Jsonl,
        "json_document" => SourceFormat::JsonDocument,
        other => panic!("unknown source format {other}"),
    };
    let mut before = Vec::new();
    safe_value
        .write_tagged(&mut before)
        .expect("snapshot tagged source bytes before mapping");
    let standard = map_claude_standard(format, &safe_value);
    let mut after = Vec::new();
    safe_value
        .write_tagged(&mut after)
        .expect("snapshot tagged source bytes after mapping");
    assert_eq!(before, after, "mapper changed the tagged source bytes");
    serde_json::to_value(standard).expect("serialize StandardFacts")
}

fn typed_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(left), Value::Bool(right)) => left == right,
        (Value::Number(left), Value::Number(right)) => left == right,
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right.iter())
                    .all(|(left, right)| typed_equal(left, right))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right
                        .get(key)
                        .is_some_and(|expected| typed_equal(value, expected))
                })
        }
        _ => false,
    }
}

fn assert_case(id: &str, format: &str, input_json: &str, expected: &Value) -> Value {
    let actual = actual_standard(format, input_json);
    assert!(
        typed_equal(&actual, expected),
        "case {id} differs\nexpected: {}\nactual: {}",
        serde_json::to_string_pretty(expected).expect("pretty expected"),
        serde_json::to_string_pretty(&actual).expect("pretty actual")
    );
    actual
}

fn assert_boundary(function: &str, ids: &[&str]) {
    let catalogue = boundary();
    let cases = catalogue["cases"].as_array().expect("boundary cases");
    let by_id: BTreeMap<&str, &Value> = cases
        .iter()
        .map(|case| (case["id"].as_str().expect("boundary case id"), case))
        .collect();
    for id in ids {
        let case = by_id
            .get(id)
            .unwrap_or_else(|| panic!("{function}: missing embedded case {id}"));
        let format = case["format"].as_str().expect("case format");
        let input_json = case["input_json"].as_str().expect("case input_json");
        assert_case(id, format, input_json, &case["expected_standard"]);
    }
    assert_eq!(
        ids.len(),
        ids.iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        "{function}: case list contains duplicate ids"
    );
}

fn assert_boundary_roster() {
    let catalogue = boundary();
    let mut catalogue_ids: Vec<&str> = catalogue["cases"]
        .as_array()
        .expect("boundary cases")
        .iter()
        .map(|case| case["id"].as_str().expect("boundary case id"))
        .collect();
    assert_eq!(
        catalogue_ids.len(),
        18,
        "embedded boundary catalogue must hold exactly 18 cases"
    );
    let mut listed: Vec<&str> = ALL_IDS
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect();
    assert_eq!(
        listed.len(),
        18,
        "six test groups must list exactly 18 cases"
    );
    listed.sort_unstable();
    catalogue_ids.sort_unstable();
    assert_eq!(
        listed, catalogue_ids,
        "test groups must cover every embedded boundary case"
    );
    let mut unique = listed.clone();
    unique.dedup();
    assert_eq!(unique.len(), 18, "boundary case ids must be unique");
}

fn write_mapper_result(results: &[Value]) {
    let Some(path) = std::env::var_os("CASS_MAPPER_RESULT") else {
        return;
    };
    let path = PathBuf::from(path);
    let temporary = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(results).expect("serialize mapper results");
    fs::write(&temporary, bytes).expect("write temporary mapper result");
    fs::rename(&temporary, &path).expect("replace mapper result");
}

#[test]
fn c01_original_claude_gold10() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("source_standard")
        .join("two-source-gold.json");
    let gold: Value = serde_json::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .expect("parse product gold copy");
    let cases = gold["cases"].as_array().expect("gold cases");
    let claude: Vec<&Value> = cases
        .iter()
        .filter(|case| case["connector"] == json!("claude_code"))
        .collect();
    assert_eq!(
        claude.len(),
        10,
        "original Claude gold must hold exactly 10 cases"
    );

    let mut results = Vec::new();
    for case in claude {
        let id = case["id"].as_str().expect("case id");
        let format = case["format"].as_str().expect("case format");
        let input_json = case["input_json"].as_str().expect("case input_json");
        let actual = assert_case(id, format, input_json, &case["expected_standard"]);
        results.push(json!({"id": id, "actual_standard": actual}));
    }
    assert_eq!(results.len(), 10, "c01 must write exactly 10 records");
    write_mapper_result(&results);
}

#[test]
fn c02_event_role_and_id_boundaries() {
    assert_boundary("c02_event_role_and_id_boundaries", C02_IDS);
    assert_boundary_roster();
}

#[test]
fn c03_usage_container_boundaries() {
    assert_boundary("c03_usage_container_boundaries", C03_IDS);
}

#[test]
fn c04_model_usage_order_and_pointers() {
    assert_boundary("c04_model_usage_order_and_pointers", C04_IDS);
}

#[test]
fn c05_document_alias_and_unknown_items() {
    assert_boundary("c05_document_alias_and_unknown_items", C05_IDS);
}

#[test]
fn c06_tool_role_presence_and_types() {
    assert_boundary("c06_tool_role_presence_and_types", C06_IDS);
}
