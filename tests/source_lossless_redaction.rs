//! SRC05B-03 acceptance tests for lossless source-tree secret redaction.
//!
//! These tests drive the public `redact_lossless_source` entry point over
//! real [`LosslessSourceValue`] trees and verify the result through the
//! existing `safe-json-msgpack/1` codec. The expected canonical JSON and the
//! expected object key lists below are written by hand; they are never
//! produced by the code under test.
//!
//! Every credential-shaped string here is synthetic (assembled from the same
//! shapes the module's own unit tests use) and exists only to exercise the
//! pattern matcher.

use coding_agent_search::indexer::redact_secrets::{
    SourceRedactionError, redact_json, redact_lossless_source, redact_text,
};
use coding_agent_search::storage::source_codec::{decode_safe_source, encode_safe_source};
use franken_agent_detection::{LosslessSourceValue, ValidatedJsonNumberText};

/// The marker the module writes where a secret was found.
const REDACTED: &str = "[REDACTED]";

// Synthetic pattern-shaped keys. Each redacts to `[REDACTED]` under
// `redact_text`, so a pair of them collides in the object key space.
const SYNTHETIC_OPENAI_KEY: &str = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"; // ubs:ignore -- synthetic redaction fixture.
const SYNTHETIC_GITHUB_PAT: &str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"; // ubs:ignore -- synthetic redaction fixture.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse(json: &str) -> LosslessSourceValue {
    LosslessSourceValue::parse(json.as_bytes()).expect("fixture JSON must parse")
}

fn canonical(value: &LosslessSourceValue) -> String {
    let mut bytes = Vec::new();
    value
        .write_canonical(&mut bytes)
        .expect("write_canonical must succeed");
    String::from_utf8(bytes).expect("canonical JSON is UTF-8")
}

fn object_keys(value: &LosslessSourceValue) -> Vec<String> {
    match value {
        LosslessSourceValue::Object(members) => {
            members.iter().map(|(key, _)| key.clone()).collect()
        }
        other => panic!("expected an object node, got {other:?}"),
    }
}

fn string_at<'a>(value: &'a LosslessSourceValue, name: &str) -> &'a str {
    value
        .get(name)
        .and_then(LosslessSourceValue::as_str)
        .unwrap_or_else(|| panic!("member {name} must be a string"))
}

fn number_text(value: &LosslessSourceValue) -> &str {
    match value {
        LosslessSourceValue::Number(text) => text.as_str(),
        other => panic!("expected a number node, got {other:?}"),
    }
}

fn num(text: &str) -> LosslessSourceValue {
    LosslessSourceValue::Number(
        ValidatedJsonNumberText::new(text.to_owned()).expect("fixture number token"),
    )
}

fn text(value: &str) -> LosslessSourceValue {
    LosslessSourceValue::String(value.to_owned())
}

// ---------------------------------------------------------------------------
// R1 — lossless round-trip: extreme numbers and unknown fields survive
// ---------------------------------------------------------------------------

#[test]
fn r1_extreme_numbers_and_unknown_fields_roundtrip_through_the_codec() {
    // The two secrets are a String value under a safe key (caught by the text
    // patterns) and a value under a sensitive key (replaced by key semantics).
    let input = concat!(
        r#"{"user":"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij","password":"SyntheticValue1234","#,
        r#""nums":[9007199254740993,18446744073709551615,1e400,1e-400,0.1000000000000000001,-0,-0.0],"#,
        r#""nested":{"note":"hello","count":42},"list":["a","b"],"flag":true,"nil":null,"#,
        r#""$serde_json::private::Number":"num-key","$serde_json::private::RawValue":"raw-key"}"#
    );
    // Expected canonical bytes, fixed by hand: only the two secret values
    // change; every number token keeps its exact original lexeme.
    let expected = concat!(
        r#"{"user":"[REDACTED]","password":"[REDACTED]","#,
        r#""nums":[9007199254740993,18446744073709551615,1e400,1e-400,0.1000000000000000001,-0,-0.0],"#,
        r#""nested":{"note":"hello","count":42},"list":["a","b"],"flag":true,"nil":null,"#,
        r#""$serde_json::private::Number":"num-key","$serde_json::private::RawValue":"raw-key"}"#
    );

    let tree = parse(input);
    let redacted = redact_lossless_source(&tree).expect("redaction must succeed");

    assert_eq!(
        canonical(&redacted),
        expected,
        "canonical bytes must match the fixed literal, not a self-echo"
    );

    // Round-trip through the existing lossless codec: bytes, stored text and
    // decoded tree must all agree with the redacted tree.
    let bytes = encode_safe_source(&redacted).expect("encode must succeed");
    let decoded = decode_safe_source(&bytes).expect("decode must succeed");
    assert_eq!(decoded.safe_json(), expected);
    assert_eq!(decoded.value(), &redacted);

    // Array identity is preserved: same length, same element order.
    let nums = redacted.get("nums").expect("nums member must survive");
    let LosslessSourceValue::Array(items) = nums else {
        panic!("nums must stay an array");
    };
    let texts: Vec<&str> = items.iter().map(number_text).collect();
    assert_eq!(
        texts,
        vec![
            "9007199254740993",
            "18446744073709551615",
            "1e400",
            "1e-400",
            "0.1000000000000000001",
            "-0",
            "-0.0",
        ],
        "every number token must keep its original lexical form"
    );

    // Unknown object fields, including keys named after serde's private
    // markers, are preserved as ordinary members.
    assert_eq!(
        string_at(&redacted, "$serde_json::private::Number"),
        "num-key"
    );
    assert_eq!(
        string_at(&redacted, "$serde_json::private::RawValue"),
        "raw-key"
    );
    assert_eq!(canonical(redacted.get("nested").expect("nested")), r#"{"note":"hello","count":42}"#);
    assert_eq!(canonical(redacted.get("list").expect("list")), r#"["a","b"]"#);
}

#[test]
fn r1_nested_containers_preserve_element_and_member_order() {
    // At least three distinct values per container, plus nested arrays and
    // objects, so a swapped or reversed rebuild cannot pass.
    let tree = LosslessSourceValue::Object(vec![
        ("a".to_owned(), text("A")),
        ("b".to_owned(), text("B")),
        ("c".to_owned(), text("C")),
        (
            "arr".to_owned(),
            LosslessSourceValue::Array(vec![text("one"), text("two"), text("three")]),
        ),
        (
            "obj".to_owned(),
            LosslessSourceValue::Object(vec![
                ("x".to_owned(), text("1")),
                ("y".to_owned(), text("2")),
                ("z".to_owned(), text("3")),
            ]),
        ),
        (
            "mixed".to_owned(),
            LosslessSourceValue::Array(vec![
                num("1"),
                text("two"),
                LosslessSourceValue::Bool(true),
                LosslessSourceValue::Null,
                LosslessSourceValue::Object(vec![
                    ("k".to_owned(), text("v")),
                    ("m".to_owned(), num("-0.0")),
                ]),
            ]),
        ),
    ]);

    let out = redact_lossless_source(&tree).expect("redaction must succeed");
    assert_eq!(
        canonical(&out),
        concat!(
            r#"{"a":"A","b":"B","c":"C","#,
            r#""arr":["one","two","three"],"#,
            r#""obj":{"x":"1","y":"2","z":"3"},"#,
            r#""mixed":[1,"two",true,null,{"k":"v","m":-0.0}]}"#
        ),
        "member and element order and each member's own value must be preserved"
    );
}

// ---------------------------------------------------------------------------
// R2 — agreed with the legacy `serde_json` entry on non-colliding samples
// ---------------------------------------------------------------------------

#[test]
fn r2_legacy_and_lossless_entries_agree_without_key_collisions() {
    let cases: [&str; 5] = [
        r#"{"password":"hunter2hunter2","note":"plain text"}"#,
        r#"{"authorization":"Bearer abcdefghijklmnopqrstuvwxyz","user":"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}"#,
        r#"{"API-Key":"xyz","api_key":"abc","apiKey":"def","Access-Token":"ghi"}"#,
        r#"{"pin":123456,"token":true,"credentials":["a","b"],"secret":{"x":1},"raw":null}"#,
        r#"{"keyframe":"animation","monkey":"animal","token_count":2048,"public_key":"ssh-ed25519 AAAATEST","null_password":null,"note":"contains sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij inside"}"#,
    ];

    for json in cases {
        let value: serde_json::Value = serde_json::from_str(json).expect("serde parse");
        let legacy = redact_json(&value);

        let tree = parse(json);
        let lossless = redact_lossless_source(&tree).expect("redaction must succeed");
        let lossless_value: serde_json::Value =
            serde_json::from_str(&canonical(&lossless)).expect("reparse redacted tree");

        assert_eq!(legacy, lossless_value, "entries must agree for case {json}");
    }
}

#[test]
fn r2_sensitive_key_branches_have_fixed_expectations() {
    // Sensitive key semantics are asserted directly, per value kind, rather
    // than only through the legacy entry's equality check above.
    let json = r#"{"pin":123456,"token":true,"credentials":["a","b"],"secret":{"x":1},"password":null,"keyframe":"animation","token_count":2048,"monkey":"animal"}"#;
    let tree = parse(json);
    let redacted = redact_lossless_source(&tree).expect("redaction must succeed");

    // String, Number, Bool, Array and Object values under a sensitive key all
    // collapse to the single redacted marker string...
    for key in ["pin", "token", "credentials", "secret"] {
        assert_eq!(
            redacted.get(key),
            Some(&text(REDACTED)),
            "sensitive member {key} must be fully replaced"
        );
    }
    // ...but a null value under a sensitive key stays null.
    assert_eq!(redacted.get("password"), Some(&LosslessSourceValue::Null));
    // Near-miss keys are not sensitive and keep their original values.
    assert_eq!(string_at(&redacted, "keyframe"), "animation");
    assert_eq!(number_text(redacted.get("token_count").expect("token_count")), "2048");
    assert_eq!(string_at(&redacted, "monkey"), "animal");
}

// ---------------------------------------------------------------------------
// R3 — collision handling: suffixing skips reserved and assigned names
// ---------------------------------------------------------------------------

#[test]
fn r3_colliding_keys_skip_reserved_and_assigned_names() {
    // Precondition of the whole scenario: two distinct keys redact to one name.
    assert_eq!(redact_text(SYNTHETIC_OPENAI_KEY), REDACTED);
    assert_eq!(redact_text(SYNTHETIC_GITHUB_PAT), REDACTED);

    // These safe keys occupy the exact names the suffix search would try, in
    // member order that interleaves them with the two secret keys.
    let tree = LosslessSourceValue::Object(vec![
        (SYNTHETIC_OPENAI_KEY.to_owned(), text("v1")),
        ("[REDACTED]#1".to_owned(), text("safe-one")),
        (SYNTHETIC_GITHUB_PAT.to_owned(), text("v2")),
        ("[REDACTED]#2".to_owned(), text("safe-two")),
        (
            "keep".to_owned(),
            LosslessSourceValue::Object(vec![("deep".to_owned(), num("7"))]),
        ),
        ("token_count".to_owned(), num("2048")),
    ]);

    let out = redact_lossless_source(&tree).expect("redaction must succeed");

    // First secret takes the bare redacted name; the second must skip the
    // reserved `#1` and `#2` names and land on `#3`.
    assert_eq!(
        object_keys(&out),
        vec![
            "[REDACTED]",
            "[REDACTED]#1",
            "[REDACTED]#3",
            "[REDACTED]#2",
            "keep",
            "token_count",
        ],
        "member order and count must be preserved with collision-free names"
    );

    // Safe members keep their original values verbatim.
    assert_eq!(string_at(&out, "[REDACTED]#1"), "safe-one");
    assert_eq!(string_at(&out, "[REDACTED]#2"), "safe-two");
    // The renamed members keep their original (unknown) values.
    assert_eq!(string_at(&out, "[REDACTED]"), "v1");
    assert_eq!(string_at(&out, "[REDACTED]#3"), "v2");
    assert_eq!(canonical(out.get("keep").expect("keep")), r#"{"deep":7}"#);
    assert_eq!(number_text(out.get("token_count").expect("token_count")), "2048");

    // Deterministic for the same input, and a fixed point when re-redacted.
    let again = redact_lossless_source(&tree).expect("redaction must succeed");
    assert_eq!(canonical(&again), canonical(&out), "same input must be deterministic");
    assert_eq!(
        redact_lossless_source(&out).expect("redaction must succeed"),
        out,
        "redacting the result again must not change it"
    );

    // With no reserved names, the two secrets reuse the bare name and `#1`.
    let plain = LosslessSourceValue::Object(vec![
        (SYNTHETIC_OPENAI_KEY.to_owned(), text("x")),
        (SYNTHETIC_GITHUB_PAT.to_owned(), text("y")),
    ]);
    let plain_out = redact_lossless_source(&plain).expect("redaction must succeed");
    assert_eq!(object_keys(&plain_out), vec!["[REDACTED]", "[REDACTED]#1"]);
}

#[test]
fn r3_member_order_selects_the_suffixed_name_and_nesting_is_independent() {
    // Reordering the two secret members swaps which value lands on the bare
    // name: allocation follows original member order.
    let reversed = LosslessSourceValue::Object(vec![
        (SYNTHETIC_GITHUB_PAT.to_owned(), text("y")),
        (SYNTHETIC_OPENAI_KEY.to_owned(), text("x")),
    ]);
    let out = redact_lossless_source(&reversed).expect("redaction must succeed");
    assert_eq!(object_keys(&out), vec!["[REDACTED]", "[REDACTED]#1"]);
    assert_eq!(string_at(&out, "[REDACTED]"), "y");
    assert_eq!(string_at(&out, "[REDACTED]#1"), "x");

    // A nested object allocates its own names: the inner safe key occupies the
    // bare redacted name, so both inner secrets move to suffixed names even
    // though the outer object never needed a suffix.
    let nested = LosslessSourceValue::Object(vec![(
        "outer".to_owned(),
        LosslessSourceValue::Object(vec![
            (SYNTHETIC_OPENAI_KEY.to_owned(), text("inner1")),
            ("[REDACTED]".to_owned(), text("inner-safe")),
            (SYNTHETIC_GITHUB_PAT.to_owned(), text("inner2")),
        ]),
    )]);
    let out = redact_lossless_source(&nested).expect("redaction must succeed");
    let inner = out.get("outer").expect("outer member");
    assert_eq!(
        object_keys(inner),
        vec!["[REDACTED]#1", "[REDACTED]", "[REDACTED]#2"]
    );
    assert_eq!(string_at(inner, "[REDACTED]"), "inner-safe");
    assert_eq!(string_at(inner, "[REDACTED]#1"), "inner1");
    assert_eq!(string_at(inner, "[REDACTED]#2"), "inner2");
}

// ---------------------------------------------------------------------------
// R4 — duplicate original keys are refused, payload-free
// ---------------------------------------------------------------------------

#[test]
fn r4_duplicate_original_keys_are_refused_without_leaking_payload() {
    let dup_key = "leaky_duplicate_member_name";
    let dup_value = "SENTINEL_DUPLICATE_VALUE";
    let tree = LosslessSourceValue::Object(vec![
        (dup_key.to_owned(), text("first")),
        (dup_key.to_owned(), text(dup_value)),
    ]);

    let err = redact_lossless_source(&tree).expect_err("duplicate key must be refused");
    assert_eq!(err, SourceRedactionError::DuplicateObjectMember);
    assert_eq!(err.code(), "duplicate-object-member");

    // Neither rendering may carry the key, either value, or any input text.
    let shown = format!("{err}");
    let debug = format!("{err:?}");
    assert_eq!(shown, "duplicate-object-member");
    for needle in [dup_key, dup_value, "first", "second"] {
        assert!(!shown.contains(needle), "Display leaked {needle}");
        assert!(!debug.contains(needle), "Debug leaked {needle}");
    }

    // A duplicate nested below an array is refused too.
    let nested = LosslessSourceValue::Object(vec![(
        "ok".to_owned(),
        LosslessSourceValue::Array(vec![LosslessSourceValue::Object(vec![
            ("dup".to_owned(), LosslessSourceValue::Null),
            ("dup".to_owned(), LosslessSourceValue::Null),
        ])]),
    )]);
    assert_eq!(
        redact_lossless_source(&nested),
        Err(SourceRedactionError::DuplicateObjectMember)
    );

    // Control: the same members with distinct names succeed.
    let control = LosslessSourceValue::Object(vec![
        ("a".to_owned(), text("first")),
        ("b".to_owned(), text("second")),
    ]);
    assert!(redact_lossless_source(&control).is_ok());
}
