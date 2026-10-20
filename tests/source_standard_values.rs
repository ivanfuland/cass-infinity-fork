//! Task28 standard scalar primitive tests.
//!
//! Exactly ten test functions and 233 planned call-composition checks. Every
//! expected value comes from a frozen gold fixture or from a controller
//! literal listed in the frozen test catalogue. Source input is parsed through
//! the pinned lossless type, never through `serde_json::Value` or `f64`.

use std::path::PathBuf;

use coding_agent_search::storage::source_facts::{
    CandidateFact, FactStatus, FactUnit, FactValue, FactValueKind, FieldFact, alias_fact,
    count_fact, time_fact, value_fact,
};
use franken_agent_detection::{LosslessSourceValue, ValidatedJsonNumberText};
use serde_json::{Value, json};

fn fixture(name: &str) -> Value {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        "source_standard",
        name,
    ]
    .iter()
    .collect();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn parse(text: &str) -> LosslessSourceValue {
    LosslessSourceValue::parse(text.as_bytes()).expect("fixture input parses as JSON")
}

fn tagged_bytes(node: &LosslessSourceValue) -> Vec<u8> {
    let mut bytes = Vec::new();
    node.write_tagged(&mut bytes).expect("tagged write");
    bytes
}

fn as_json(fact: &FieldFact) -> Value {
    serde_json::to_value(fact).expect("fact serialises")
}

fn json_pointer<'a>(value: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() {
        return Some(value);
    }
    let mut current = value;
    for raw in pointer.split('/').skip(1) {
        let segment = raw.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(map) => map.get(&segment)?,
            Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

fn tree_pointer<'a>(
    node: &'a LosslessSourceValue,
    pointer: &str,
) -> Option<&'a LosslessSourceValue> {
    if pointer.is_empty() {
        return Some(node);
    }
    let mut current = node;
    for raw in pointer.split('/').skip(1) {
        let segment = raw.replace("~1", "/").replace("~0", "~");
        current = match current {
            LosslessSourceValue::Object(members) => members
                .iter()
                .find(|(name, _)| name == &segment)
                .map(|(_, value)| value)?,
            LosslessSourceValue::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

fn case_with_id(fixture_name: &str, id: &str) -> Value {
    let document = fixture(fixture_name);
    document["cases"]
        .as_array()
        .expect("cases array")
        .iter()
        .find(|case| case["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("missing case {id} in {fixture_name}"))
}

fn node_of(case: &Value) -> Option<LosslessSourceValue> {
    if case["node_present"].as_bool() == Some(false) {
        None
    } else {
        Some(parse(case["input_json"].as_str().expect("input_json text")))
    }
}

fn call_node_primitive(case: &Value) -> FieldFact {
    let field = case["field"].as_str().expect("field");
    let raw_ref = case["raw_ref"].as_str().expect("raw_ref");
    let node = node_of(case);
    let before = node.as_ref().map(tagged_bytes);
    let fact = match case["primitive"].as_str().expect("primitive") {
        "count_fact" => count_fact(field, node.as_ref(), raw_ref),
        "time_fact" => time_fact(node.as_ref(), raw_ref),
        "value_fact" => value_fact(field, node.as_ref(), raw_ref),
        other => panic!("unexpected node primitive {other}"),
    };
    if let (Some(node), Some(before)) = (node.as_ref(), before) {
        assert_eq!(tagged_bytes(node), before, "source tree changed");
    }
    fact
}

fn status_of(value: &Value) -> FactStatus {
    match value.as_str().expect("status string") {
        "present" => FactStatus::Present,
        "missing" => FactStatus::Missing,
        "invalid" => FactStatus::Invalid,
        "conflict" => FactStatus::Conflict,
        other => panic!("unknown status {other}"),
    }
}

fn unit_of(value: &Value) -> FactUnit {
    match value.as_str().expect("unit string") {
        "count" => FactUnit::Count,
        "epoch" => FactUnit::Epoch,
        "number_text" => FactUnit::NumberText,
        other => panic!("unknown unit {other}"),
    }
}

fn kind_of(value: &Value) -> FactValueKind {
    match value.as_str().expect("value kind string") {
        "object" => FactValueKind::Object,
        "array" => FactValueKind::Array,
        other => panic!("unknown value kind {other}"),
    }
}

fn optional_string(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_owned)
}

fn value_of(value: &Value) -> FactValue {
    match value {
        Value::String(text) => FactValue::String(text.clone()),
        Value::Bool(flag) => FactValue::Boolean(*flag),
        Value::Array(_) => FactValue::Tree(tree_of_tagged(value)),
        other => panic!("unexpected fact value {other}"),
    }
}

fn tree_of_tagged(value: &Value) -> LosslessSourceValue {
    let parts = value.as_array().expect("tagged array");
    match parts[0].as_str().expect("tag") {
        "str" => LosslessSourceValue::String(parts[1].as_str().expect("str").to_owned()),
        "num" => LosslessSourceValue::Number(
            ValidatedJsonNumberText::new(parts[1].as_str().expect("num").to_owned())
                .expect("valid number text"),
        ),
        "bool" => LosslessSourceValue::Bool(parts[1].as_bool().expect("bool")),
        "null" => LosslessSourceValue::Null,
        "arr" => LosslessSourceValue::Array(
            parts[1]
                .as_array()
                .expect("arr")
                .iter()
                .map(tree_of_tagged)
                .collect(),
        ),
        "obj" => LosslessSourceValue::Object(
            parts[1]
                .as_array()
                .expect("obj")
                .iter()
                .map(|pair| {
                    let pair = pair.as_array().expect("member pair");
                    (
                        pair[0].as_str().expect("member name").to_owned(),
                        tree_of_tagged(&pair[1]),
                    )
                })
                .collect(),
        ),
        other => panic!("unknown tag {other}"),
    }
}

fn candidate_from_json(value: &Value) -> CandidateFact {
    CandidateFact {
        status: status_of(&value["status"]),
        value: value.get("value").map(value_of),
        value_kind: value.get("value_kind").map(kind_of),
        raw_ref: optional_string(value, "raw_ref"),
        presence_ref: optional_string(value, "presence_ref"),
        reason: optional_string(value, "reason"),
        refs: value
            .get("refs")
            .and_then(Value::as_array)
            .map(|refs| refs.iter().map(candidate_from_json).collect()),
        unit: value.get("unit").map(unit_of),
    }
}

fn fact_from_json(value: &Value) -> FieldFact {
    let candidate = candidate_from_json(value);
    FieldFact {
        field: value["field"].as_str().expect("field").to_owned(),
        status: candidate.status,
        value: candidate.value,
        value_kind: candidate.value_kind,
        raw_ref: candidate.raw_ref,
        presence_ref: candidate.presence_ref,
        reason: candidate.reason,
        refs: candidate.refs,
        unit: candidate.unit,
    }
}

fn candidates_of(case: &Value) -> Vec<FieldFact> {
    case["candidates"]
        .as_array()
        .expect("candidates array")
        .iter()
        .map(fact_from_json)
        .collect()
}

fn assert_fact(actual: &FieldFact, expected: &Value, label: &str) {
    assert_eq!(&as_json(actual), expected, "case {label}");
}

#[test]
fn s01_count_fixed16() {
    let gold = fixture("two-source-gold.json");
    let cases = gold["count_gold"].as_array().expect("count_gold");
    assert_eq!(cases.len(), 16);
    let mut seen = 0;
    for case in cases {
        let input = case["input_json"].as_str().expect("input_json");
        let tree = parse(input);
        let before = tagged_bytes(&tree);
        let fact = count_fact("probe", Some(&tree), "/probe");
        assert_eq!(tagged_bytes(&tree), before, "source tree changed: {input}");

        let mut expected = json!({
            "field": "probe",
            "status": case["status"],
            "raw_ref": "/probe",
            "unit": "count",
        });
        if !case["value"].is_null() {
            expected["value"] = case["value"].clone();
        }
        if !case["reason"].is_null() {
            expected["reason"] = case["reason"].clone();
        }
        assert_fact(&fact, &expected, input);
        seen += 1;
    }
    assert_eq!(seen, 16);
}

#[test]
fn s02_count_presence_and_wrong_types() {
    let mut seen = 0;
    for id in ["count_fact-absent", "count_fact-null"] {
        let case = case_with_id("scalar-boundary-gold.json", id);
        let fact = call_node_primitive(&case);
        assert_fact(&fact, &case["expected"], id);
        seen += 1;
    }
    for (id, input) in [
        ("nonnumber-0", "[]"),
        ("nonnumber-1", "{}"),
        ("nonnumber-2", "false"),
        ("nonnumber-3", "\"\""),
    ] {
        let tree = parse(input);
        let before = tagged_bytes(&tree);
        let fact = count_fact("probe", Some(&tree), "/probe");
        assert_eq!(tagged_bytes(&tree), before, "source tree changed: {id}");
        let expected = json!({
            "field": "probe",
            "status": "invalid",
            "raw_ref": "/probe",
            "reason": "not_a_number",
            "unit": "count",
        });
        assert_fact(&fact, &expected, id);
        seen += 1;
    }
    assert_eq!(seen, 6);
}

#[test]
fn s03_count_unbounded_exponents_and_sign() {
    let ids = [
        "negative-magnitude--18446744073709551616",
        "negative-magnitude--99999999999999999999",
        "negative-magnitude--100000000000000000000",
        "unbounded-exponent-15",
        "unbounded-exponent-16",
        "unbounded-exponent-17",
    ];
    let mut seen = 0;
    for id in ids {
        let case = case_with_id("scalar-r0-supplement.json", id);
        let fact = call_node_primitive(&case);
        assert_fact(&fact, &case["expected"], id);
        seen += 1;
    }
    assert_eq!(seen, 6);
}

#[test]
fn s04_count_three_cancellations() {
    let mut seen = 0;
    for n in [999_999_usize, 1_000_000, 10_000_000] {
        let mut input = String::from("0.");
        input.push_str(&"0".repeat(n - 1));
        input.push('1');
        input.push('e');
        input.push_str(&n.to_string());
        let tree = parse(&input);
        let before = tagged_bytes(&tree);
        let fact = count_fact("probe", Some(&tree), "/probe");
        assert_eq!(tagged_bytes(&tree), before, "source tree changed: n={n}");
        let expected = json!({
            "field": "probe",
            "status": "present",
            "raw_ref": "/probe",
            "value": "1",
            "unit": "count",
        });
        assert_fact(&fact, &expected, &format!("n={n}"));
        seen += 1;
    }
    assert_eq!(seen, 3);
}

#[test]
fn s05_value_exact_kind_and_text() {
    let ids = [
        "value_fact-absent",
        "value_fact-null",
        "value-empty-string",
        "value-false",
        "value-number-text",
        "value-empty-array",
        "value-empty-object",
        "value-ordered-object",
    ];
    let mut seen = 0;
    for id in ids {
        let case = case_with_id("scalar-boundary-gold.json", id);
        let fact = call_node_primitive(&case);
        assert_fact(&fact, &case["expected"], id);
        seen += 1;
    }
    assert_eq!(seen, 8);
}

#[test]
fn s06_time_fixed_boundaries() {
    let ids = [
        "time_fact-absent",
        "time_fact-null",
        "time-epoch",
        "time-negative-fraction",
        "time-positive-fraction",
        "time-positive-offset",
        "time-negative-offset",
        "time-lowercase",
        "time-missing-zone",
        "time-unknown-offset",
        "time-bad-day",
        "time-bad-hour",
        "time-bad-offset",
        "time-leap-second",
        "time-numeric",
        "time-bool",
        "time-array",
        "time-object",
    ];
    let mut seen = 0;
    for id in ids {
        let case = case_with_id("scalar-boundary-gold.json", id);
        let fact = call_node_primitive(&case);
        assert_fact(&fact, &case["expected"], id);
        seen += 1;
    }
    let literals = [
        (
            "long-positive",
            "\"1970-01-01T00:00:00.12345678901234567890Z\"",
            "0.12345678901234567890",
        ),
        (
            "long-negative-cross-zero",
            "\"1969-12-31T23:59:59.99999999999999999999Z\"",
            "-0.00000000000000000001",
        ),
        (
            "negative-integer-with-fraction-zero",
            "\"1969-12-31T23:59:59.000000000000Z\"",
            "-1.000000000000",
        ),
    ];
    for (id, input, value) in literals {
        let tree = parse(input);
        let before = tagged_bytes(&tree);
        let fact = time_fact(Some(&tree), "/probe");
        assert_eq!(tagged_bytes(&tree), before, "source tree changed: {id}");
        let expected = json!({
            "field": "time",
            "status": "present",
            "value": value,
            "raw_ref": "/probe",
            "unit": "epoch",
        });
        assert_fact(&fact, &expected, id);
        seen += 1;
    }
    assert_eq!(seen, 21);
}

#[test]
fn s07_time_numeric_string_contract() {
    let ids = [
        "numeric-time-string-123",
        "numeric-time-string-1700000000",
        "numeric-time-string--1",
        "numeric-time-string-1e3",
    ];
    let mut seen = 0;
    for id in ids {
        let case = case_with_id("scalar-r0-supplement.json", id);
        let fact = call_node_primitive(&case);
        assert_fact(&fact, &case["expected"], id);
        seen += 1;
    }
    assert_eq!(seen, 4);
}

#[test]
fn s08_alias_complete_candidates() {
    let boundary = [
        "alias-different-values",
        "alias-same-values",
        "alias-both-null",
        "alias-one-null",
    ];
    let supplement = [
        "single",
        "valid-and-invalid",
        "conflict-before-invalid",
        "same-value-different-unit",
        "count-null-parent-no-unit",
    ];
    let mut seen = 0;
    for id in boundary {
        let case = case_with_id("scalar-boundary-gold.json", id);
        let candidates = candidates_of(&case);
        let before: Vec<Value> = candidates.iter().map(as_json).collect();
        let fact = alias_fact(case["field"].as_str().expect("field"), &candidates);
        let after: Vec<Value> = candidates.iter().map(as_json).collect();
        assert_eq!(before, after, "candidates changed: {id}");
        assert_fact(&fact, &case["expected"], id);
        seen += 1;
    }
    for id in supplement {
        let case = case_with_id("scalar-r0-supplement.json", id);
        let candidates = candidates_of(&case);
        let before: Vec<Value> = candidates.iter().map(as_json).collect();
        let fact = alias_fact(case["field"].as_str().expect("field"), &candidates);
        let after: Vec<Value> = candidates.iter().map(as_json).collect();
        assert_eq!(before, after, "candidates changed: {id}");
        assert_fact(&fact, &case["expected"], id);
        seen += 1;
    }
    assert_eq!(seen, 9);
}

#[test]
fn s09_alias_malformed_calls() {
    let ids = ["empty", "wrong-field", "already-conflict"];
    let mut seen = 0;
    for id in ids {
        let case = case_with_id("scalar-r0-supplement.json", id);
        let candidates = candidates_of(&case);
        let before: Vec<Value> = candidates.iter().map(as_json).collect();
        let fact = alias_fact(case["field"].as_str().expect("field"), &candidates);
        let after: Vec<Value> = candidates.iter().map(as_json).collect();
        assert_eq!(before, after, "candidates changed: {id}");
        assert_fact(&fact, &case["expected"], id);
        seen += 1;
    }
    assert_eq!(seen, 3);
}

#[test]
fn s10_original_record_primitives157() {
    let gold = fixture("two-source-gold.json");
    let map = fixture("scalar-record-extraction-map.json");
    assert_eq!(map["records"].as_i64(), Some(24));
    assert_eq!(map["total_field_facts"].as_i64(), Some(204));
    let cases = gold["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 24);
    let specs = map["primitive_cases"].as_array().expect("primitive_cases");
    assert_eq!(specs.len(), 157);

    let mut seen = 0;
    for spec in specs {
        let case_id = spec["case_id"].as_str().expect("case_id");
        let case = cases
            .iter()
            .find(|candidate| candidate["id"] == case_id)
            .unwrap_or_else(|| panic!("missing gold case {case_id}"));
        let tree = parse(case["input_json"].as_str().expect("input_json"));
        let before = tagged_bytes(&tree);
        let expected = json_pointer(&gold, spec["expected_pointer"].as_str().expect("expected"))
            .unwrap_or_else(|| panic!("missing expected pointer for {case_id}"));
        let field = spec["field"].as_str().expect("field");
        let primitive = spec["primitive"].as_str().expect("primitive");

        let actual = match primitive {
            "count_fact" => {
                let raw_ref = spec["input_pointer"].as_str().expect("input pointer");
                count_fact(field, tree_pointer(&tree, raw_ref), raw_ref)
            }
            "time_fact" => {
                let raw_ref = spec["input_pointer"].as_str().expect("input pointer");
                time_fact(tree_pointer(&tree, raw_ref), raw_ref)
            }
            "value_fact" => {
                let raw_ref = spec["input_pointer"].as_str().expect("input pointer");
                value_fact(field, tree_pointer(&tree, raw_ref), raw_ref)
            }
            "alias_fact" => {
                let mut candidates = Vec::new();
                for candidate in spec["candidates"].as_array().expect("candidates") {
                    let raw_ref = candidate["input_pointer"]
                        .as_str()
                        .expect("candidate input pointer");
                    let candidate_field = candidate["field"].as_str().expect("candidate field");
                    let node = tree_pointer(&tree, raw_ref);
                    let fact = match candidate["primitive"]
                        .as_str()
                        .expect("candidate primitive")
                    {
                        "count_fact" => count_fact(candidate_field, node, raw_ref),
                        "time_fact" => time_fact(node, raw_ref),
                        "value_fact" => value_fact(candidate_field, node, raw_ref),
                        other => panic!("unexpected candidate primitive {other}"),
                    };
                    candidates.push(fact);
                }
                alias_fact(field, &candidates)
            }
            other => panic!("unexpected primitive {other}"),
        };

        assert_eq!(
            tagged_bytes(&tree),
            before,
            "source tree changed: {case_id}"
        );
        assert_fact(&actual, expected, case_id);
        seen += 1;
    }
    assert_eq!(seen, 157);
}
