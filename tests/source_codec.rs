//! SRC05A1 acceptance tests for the `safe-json-msgpack/1` source payload codec.
//!
//! The expected envelopes are fixed by hand, byte for byte, in this file; they
//! are never produced by the encoder under test. The SQLite case uses the
//! crate's existing `rusqlite` dependency to build a private fixture database
//! file, because `frankensqlite` is not a dependency of this crate at this
//! commit and no dependency change is in scope for this task.

use coding_agent_search::storage::source_codec::{
    SAFE_SOURCE_CODEC_ID, SAFE_SOURCE_CODEC_VERSION, SourceCodecError, decode_safe_source,
    encode_safe_source,
};
use franken_agent_detection::LosslessSourceValue;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn parse(json: &str) -> LosslessSourceValue {
    LosslessSourceValue::parse(json.as_bytes()).expect("fixture JSON must parse")
}

/// MessagePack string header, written independently of the codec under test.
fn str_header(len: usize) -> Vec<u8> {
    match len {
        0..=31 => vec![0xa0 | u8::try_from(len).expect("fixstr length")],
        32..=255 => vec![0xd9, u8::try_from(len).expect("str8 length")],
        256..=65535 => {
            let mut out = vec![0xda];
            out.extend_from_slice(&u16::try_from(len).expect("str16 length").to_be_bytes());
            out
        }
        _ => {
            let mut out = vec![0xdb];
            out.extend_from_slice(&u32::try_from(len).expect("str32 length").to_be_bytes());
            out
        }
    }
}

/// The envelope the contract fixes for one JSON text: a two-field MessagePack
/// map, never a struct or tuple, with the source object kept outside it.
fn envelope(json: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x82);
    out.extend_from_slice(&str_header(7));
    out.extend_from_slice(b"version");
    out.push(0x01);
    out.extend_from_slice(&str_header(9));
    out.extend_from_slice(b"safe_json");
    out.extend_from_slice(&str_header(json.len()));
    out.extend_from_slice(json.as_bytes());
    out
}

fn number_text(value: &LosslessSourceValue) -> &str {
    match value {
        LosslessSourceValue::Number(text) => text.as_str(),
        other => panic!("expected a number node, got {other:?}"),
    }
}

fn object_keys(value: &LosslessSourceValue) -> Vec<&str> {
    match value {
        LosslessSourceValue::Object(members) => {
            members.iter().map(|(key, _)| key.as_str()).collect()
        }
        other => panic!("expected an object node, got {other:?}"),
    }
}

fn decode_error(bytes: &[u8]) -> SourceCodecError {
    decode_safe_source(bytes)
        .err()
        .expect("envelope must be refused")
}

// ---------------------------------------------------------------------------
// 1. Byte gold, fixed by hand
// ---------------------------------------------------------------------------

#[test]
fn gold_envelope_bytes_are_fixed_literals() {
    let cases: [(&str, &[u8]); 6] = [
        ("null", b"\x82\xa7version\x01\xa9safe_json\xa4null"),
        ("{}", b"\x82\xa7version\x01\xa9safe_json\xa2{}"),
        ("[]", b"\x82\xa7version\x01\xa9safe_json\xa2[]"),
        ("true", b"\x82\xa7version\x01\xa9safe_json\xa4true"),
        ("false", b"\x82\xa7version\x01\xa9safe_json\xa5false"),
        ("0", b"\x82\xa7version\x01\xa9safe_json\xa10"),
    ];
    for (json, expected) in cases {
        assert_eq!(
            encode_safe_source(&parse(json)).expect("encode"),
            expected,
            "case {json}"
        );
        assert_eq!(
            envelope(json),
            expected,
            "hand-built envelope must agree for {json}"
        );
    }
}

#[test]
fn gold_envelope_bytes_preserve_number_lexical_form() {
    // > 2^53, the u64 boundary, a long decimal, an exponent and negative zero.
    let cases: [&str; 6] = [
        "9007199254740993",
        "18446744073709551615",
        "0.1000000000000000001",
        "1e400",
        "-0.0",
        "-0",
    ];
    for json in cases {
        assert_eq!(
            encode_safe_source(&parse(json)).expect("encode"),
            envelope(json),
            "case {json}"
        );
    }
}

#[test]
fn gold_envelope_bytes_treat_serde_number_marker_as_ordinary_key() {
    // A plain source key whose name collides with serde's internal number
    // marker keeps its original spelling and stays a normal object member.
    let json = r#"{"$serde_json::private::Number":1}"#;
    assert_eq!(json.len(), 34, "case must exercise the str8 header");
    let bytes = encode_safe_source(&parse(json)).expect("encode");
    assert_eq!(bytes, envelope(json));
    assert_eq!(
        &bytes[20..22],
        b"\xd9\x22",
        "34-byte payload uses a str8 header"
    );

    let decoded = decode_safe_source(&bytes).expect("decode");
    assert_eq!(decoded.safe_json(), json);
    let member = decoded
        .value()
        .get("$serde_json::private::Number")
        .expect("marker-named key is an ordinary member");
    assert_eq!(number_text(member), "1");
}

#[test]
fn gold_envelope_bytes_preserve_object_and_array_order() {
    let json = r#"{"z":9007199254740993,"a":[0,-0.0,1e400,true,null],"b":0.1000000000000000001}"#;
    let bytes = encode_safe_source(&parse(json)).expect("encode");
    assert_eq!(bytes, envelope(json));

    let decoded = decode_safe_source(&bytes).expect("decode");
    assert_eq!(decoded.safe_json(), json);
    assert_eq!(object_keys(decoded.value()), vec!["z", "a", "b"]);
    assert_eq!(
        number_text(decoded.value().get("z").expect("z")),
        "9007199254740993"
    );
    assert_eq!(
        number_text(decoded.value().get("b").expect("b")),
        "0.1000000000000000001"
    );

    let Some(LosslessSourceValue::Array(items)) = decoded.value().get("a") else {
        panic!("a must stay an array");
    };
    assert_eq!(items.len(), 5);
    assert_eq!(number_text(&items[0]), "0");
    assert_eq!(number_text(&items[1]), "-0.0");
    assert_eq!(number_text(&items[2]), "1e400");
    assert_eq!(items[3], LosslessSourceValue::Bool(true));
    assert_eq!(items[4], LosslessSourceValue::Null);
}

#[test]
fn codec_identity_is_pinned() {
    assert_eq!(SAFE_SOURCE_CODEC_ID, "safe-json-msgpack/1");
    assert_eq!(SAFE_SOURCE_CODEC_VERSION, 1);
}

// ---------------------------------------------------------------------------
// 2. Strict negative cases
// ---------------------------------------------------------------------------

#[test]
fn strict_outer_envelope_rejections() {
    let cases: [(&str, &[u8], SourceCodecError); 12] = [
        ("empty input", b"", SourceCodecError::InvalidEnvelope),
        (
            "non-map envelope",
            b"\xc0",
            SourceCodecError::InvalidEnvelope,
        ),
        ("array envelope", b"\x90", SourceCodecError::InvalidEnvelope),
        (
            "truncated map16 header",
            b"\xde\x00",
            SourceCodecError::InvalidEnvelope,
        ),
        (
            "map32 with an absurd entry count",
            b"\xdf\xff\xff\xff\xff",
            SourceCodecError::InvalidEnvelope,
        ),
        (
            "non-string key",
            b"\x82\x01\x01\xa9safe_json\xa2{}",
            SourceCodecError::InvalidEnvelope,
        ),
        ("empty map", b"\x80", SourceCodecError::MissingField),
        (
            "missing safe_json",
            b"\x81\xa7version\x01",
            SourceCodecError::MissingField,
        ),
        (
            "missing version",
            b"\x81\xa9safe_json\xa2{}",
            SourceCodecError::MissingField,
        ),
        (
            "unknown field only",
            b"\x81\xa3foo\x01",
            SourceCodecError::UnknownField,
        ),
        (
            "unknown third field",
            b"\x83\xa7version\x01\xa9safe_json\xa2{}\xa3foo\x01",
            SourceCodecError::UnknownField,
        ),
        (
            "truncated safe_json string",
            b"\x82\xa7version\x01\xa9safe_json\xb5{}",
            SourceCodecError::InvalidEnvelope,
        ),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(decode_error(bytes), expected, "case {name}");
    }
}

#[test]
fn strict_version_rejections() {
    let cases: [(&str, &[u8], SourceCodecError); 8] = [
        (
            "version is a string",
            b"\x82\xa7version\xa11\xa9safe_json\xa2{}",
            SourceCodecError::InvalidVersion,
        ),
        (
            "version is nil",
            b"\x82\xa7version\xc0\xa9safe_json\xa2{}",
            SourceCodecError::InvalidVersion,
        ),
        (
            "version is a bool",
            b"\x82\xa7version\xc3\xa9safe_json\xa2{}",
            SourceCodecError::InvalidVersion,
        ),
        (
            "version is a float",
            b"\x82\xa7version\xcb\x3f\xf0\x00\x00\x00\x00\x00\x00\xa9safe_json\xa2{}",
            SourceCodecError::InvalidVersion,
        ),
        (
            "version is 0",
            b"\x82\xa7version\x00\xa9safe_json\xa2{}",
            SourceCodecError::UnsupportedVersion,
        ),
        (
            "version is 2",
            b"\x82\xa7version\x02\xa9safe_json\xa2{}",
            SourceCodecError::UnsupportedVersion,
        ),
        (
            "version is u64::MAX",
            b"\x82\xa7version\xcf\xff\xff\xff\xff\xff\xff\xff\xff\xa9safe_json\xa2{}",
            SourceCodecError::UnsupportedVersion,
        ),
        (
            "version is negative",
            b"\x82\xa7version\xff\xa9safe_json\xa2{}",
            SourceCodecError::UnsupportedVersion,
        ),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(decode_error(bytes), expected, "case {name}");
    }
}

#[test]
fn version_value_one_is_accepted_in_every_integer_width() {
    // Hand-written wire gold: the same logical version (1) in each MessagePack
    // integer encoding, with an identical payload. Every one of these is a
    // legal encoding of the integer 1.
    let cases: [(&str, &[u8]); 9] = [
        ("positive fixint", b"\x01"),
        ("uint8", b"\xcc\x01"),
        ("uint16", b"\xcd\x00\x01"),
        ("uint32", b"\xce\x00\x00\x00\x01"),
        ("uint64", b"\xcf\x00\x00\x00\x00\x00\x00\x00\x01"),
        ("int8", b"\xd0\x01"),
        ("int16", b"\xd1\x00\x01"),
        ("int32", b"\xd2\x00\x00\x00\x01"),
        ("int64", b"\xd3\x00\x00\x00\x00\x00\x00\x00\x01"),
    ];
    for (name, encoded) in cases {
        let mut bytes = b"\x82\xa7version".to_vec();
        bytes.extend_from_slice(encoded);
        bytes.extend_from_slice(b"\xa9safe_json\xa4null");
        let decoded =
            decode_safe_source(&bytes).unwrap_or_else(|error| panic!("case {name}: {error}"));
        assert_eq!(decoded.safe_json(), "null", "case {name}");
        assert_eq!(decoded.value(), &LosslessSourceValue::Null, "case {name}");
    }

    // The writer still emits the canonical positive fixint form, so the nine
    // accepted inputs above all round-trip to one canonical envelope.
    assert_eq!(
        encode_safe_source(&LosslessSourceValue::Null).expect("encode"),
        b"\x82\xa7version\x01\xa9safe_json\xa4null"
    );
}

#[test]
fn version_values_other_than_one_are_refused_in_every_integer_width() {
    let cases: [(&str, &[u8]); 8] = [
        ("uint8 two", b"\x82\xa7version\xcc\x02\xa9safe_json\xa4null"),
        (
            "uint64 two",
            b"\x82\xa7version\xcf\x00\x00\x00\x00\x00\x00\x00\x02\xa9safe_json\xa4null",
        ),
        ("int8 two", b"\x82\xa7version\xd0\x02\xa9safe_json\xa4null"),
        (
            "int64 two",
            b"\x82\xa7version\xd3\x00\x00\x00\x00\x00\x00\x00\x02\xa9safe_json\xa4null",
        ),
        (
            "uint64 max",
            b"\x82\xa7version\xcf\xff\xff\xff\xff\xff\xff\xff\xff\xa9safe_json\xa4null",
        ),
        (
            "int8 minus one",
            b"\x82\xa7version\xd0\xff\xa9safe_json\xa4null",
        ),
        (
            "int64 minus one",
            b"\x82\xa7version\xd3\xff\xff\xff\xff\xff\xff\xff\xff\xa9safe_json\xa4null",
        ),
        (
            "int64 min",
            b"\x82\xa7version\xd3\x80\x00\x00\x00\x00\x00\x00\x00\xa9safe_json\xa4null",
        ),
    ];
    for (name, bytes) in cases {
        assert_eq!(
            decode_error(bytes),
            SourceCodecError::UnsupportedVersion,
            "case {name}"
        );
    }
}

#[test]
fn strict_safe_json_rejections() {
    let cases: [(&str, &[u8], SourceCodecError); 7] = [
        (
            "safe_json is bin8 holding valid UTF-8",
            b"\x82\xa7version\x01\xa9safe_json\xc4\x02{}",
            SourceCodecError::InvalidEnvelope,
        ),
        (
            "safe_json is bin32",
            b"\x82\xa7version\x01\xa9safe_json\xc6\x00\x00\x00\x02{}",
            SourceCodecError::InvalidEnvelope,
        ),
        (
            "safe_json is an integer",
            b"\x82\xa7version\x01\xa9safe_json\x01",
            SourceCodecError::InvalidEnvelope,
        ),
        (
            "safe_json is nil",
            b"\x82\xa7version\x01\xa9safe_json\xc0",
            SourceCodecError::InvalidEnvelope,
        ),
        (
            "safe_json is ext",
            b"\x82\xa7version\x01\xa9safe_json\xd4\x01\x02",
            SourceCodecError::InvalidEnvelope,
        ),
        (
            "safe_json is not JSON",
            b"\x82\xa7version\x01\xa9safe_json\xa1x",
            SourceCodecError::InvalidSafeJson,
        ),
        (
            "safe_json has duplicate object keys",
            b"\x82\xa7version\x01\xa9safe_json\xad{\"a\":1,\"a\":2}",
            SourceCodecError::InvalidSafeJson,
        ),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(decode_error(bytes), expected, "case {name}");
    }
}

#[test]
fn safe_json_with_trailing_json_content_is_refused() {
    let bytes = envelope("{} {}");
    assert_eq!(decode_error(&bytes), SourceCodecError::InvalidSafeJson);
}

#[test]
fn duplicate_map_keys_are_refused_before_they_overwrite() {
    // The second "safe_json" carries malformed JSON. A decoder that overwrote
    // the first value would report InvalidSafeJson; the contract requires the
    // duplicate itself to be refused first, with nothing overwritten.
    let bytes = b"\x83\xa7version\x01\xa9safe_json\xa2{}\xa9safe_json\xa2xx";
    assert_eq!(decode_error(bytes), SourceCodecError::DuplicateField);

    // Same for version: the second copy is unsupported, but the repeat is the
    // failure that must be reported.
    let bytes = b"\x83\xa7version\x01\xa9safe_json\xa2{}\xa7version\x02";
    assert_eq!(decode_error(bytes), SourceCodecError::DuplicateField);

    let bytes = b"\x83\xa7version\x01\xa7version\x01\xa9safe_json\xa2{}";
    assert_eq!(decode_error(bytes), SourceCodecError::DuplicateField);
}

#[test]
fn trailing_bytes_after_a_valid_envelope_are_refused() {
    let mut bytes = envelope("null");
    bytes.push(0x00);
    assert_eq!(decode_error(&bytes), SourceCodecError::TrailingBytes);

    // Two well-formed envelopes concatenated: the first consumes exactly its
    // own bytes, so the second is trailing input.
    let mut concatenated = envelope("null");
    concatenated.extend_from_slice(&envelope("null"));
    assert_eq!(decode_error(&concatenated), SourceCodecError::TrailingBytes);
}

#[test]
fn hand_built_tree_with_duplicate_members_is_refused() {
    let member = |name: &str, number: &str| {
        (
            name.to_string(),
            LosslessSourceValue::Number(
                franken_agent_detection::ValidatedJsonNumberText::new(number.to_string())
                    .expect("fixture number"),
            ),
        )
    };

    let flat = LosslessSourceValue::Object(vec![member("a", "1"), member("a", "2")]);
    assert_eq!(
        encode_safe_source(&flat),
        Err(SourceCodecError::EncodeFailed)
    );

    // The same violation nested inside an array must be caught too.
    let nested = LosslessSourceValue::Array(vec![LosslessSourceValue::Object(vec![
        member("k", "1"),
        member("k", "2"),
    ])]);
    assert_eq!(
        encode_safe_source(&nested),
        Err(SourceCodecError::EncodeFailed)
    );

    // A tree with unique names still encodes.
    let clean = LosslessSourceValue::Object(vec![member("a", "1"), member("b", "2")]);
    assert!(encode_safe_source(&clean).is_ok());
}

// ---------------------------------------------------------------------------
// 3. Error surface carries no source content
// ---------------------------------------------------------------------------

#[test]
fn error_text_never_echoes_source_content() {
    const SYNTHETIC_SECRET: &str = "SYNTHETIC-SECRET-9f3c1a";

    let valid = format!("{{\"token\":\"{SYNTHETIC_SECRET}\"}}");
    let mut trailing = envelope(&valid);
    trailing.push(0x00);
    let err = decode_error(&trailing);
    assert_eq!(err, SourceCodecError::TrailingBytes);
    assert!(!err.to_string().contains(SYNTHETIC_SECRET));
    assert!(!format!("{err:?}").contains(SYNTHETIC_SECRET));

    // The payload itself is broken JSON, so the failure is content-level too.
    let broken = format!("{{\"token\":\"{SYNTHETIC_SECRET}\"");
    let err = decode_error(&envelope(&broken));
    assert_eq!(err, SourceCodecError::InvalidSafeJson);
    assert!(!err.to_string().contains(SYNTHETIC_SECRET));
    assert!(!format!("{err:?}").contains(SYNTHETIC_SECRET));

    // Every rendering is a fixed short code and nothing else.
    let codes = [
        SourceCodecError::EncodeFailed,
        SourceCodecError::InvalidEnvelope,
        SourceCodecError::DuplicateField,
        SourceCodecError::UnknownField,
        SourceCodecError::MissingField,
        SourceCodecError::InvalidVersion,
        SourceCodecError::UnsupportedVersion,
        SourceCodecError::InvalidSafeJson,
        SourceCodecError::TrailingBytes,
    ];
    for code in codes {
        let rendered = code.to_string();
        assert!(
            rendered.starts_with("invalid")
                || rendered.starts_with("encode")
                || rendered.starts_with("duplicate")
                || rendered.starts_with("unknown")
                || rendered.starts_with("missing")
                || rendered.starts_with("unsupported")
                || rendered.starts_with("trailing"),
            "unexpected code {rendered}"
        );
        assert!(
            !rendered.contains('{') && !rendered.contains('"'),
            "code must carry no payload: {rendered}"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Real SQLite BLOB, written by one process and read by another
// ---------------------------------------------------------------------------

const SQLITE_CHILD_TEST: &str = "sqlite_blob_child_decodes_by_path";
const SQLITE_CHILD_DB_ENV: &str = "CASS_SRC05A1_SQLITE_DB";
const SQLITE_CHILD_EXPECT_ENV: &str = "CASS_SRC05A1_EXPECT_JSON";
const SQLITE_CHILD_SENTINEL: &str = "SRC05A1_CHILD_DECODE_OK";

fn sqlite_fixture_json() -> &'static str {
    r#"{"z":9007199254740993,"a":[0,-0.0,1e400,true,null],"b":0.1000000000000000001}"#
}

#[test]
fn sqlite_blob_survives_a_process_boundary() {
    let dir = tempfile::tempdir().expect("private tempdir");
    let db_path = dir.path().join("source-codec.sqlite");
    let json = sqlite_fixture_json();
    let blob = encode_safe_source(&parse(json)).expect("encode fixture");

    {
        let conn = rusqlite::Connection::open(&db_path).expect("open fixture db");
        conn.execute_batch(
            "CREATE TABLE src05a1_payloads (id INTEGER PRIMARY KEY, payload BLOB NOT NULL);",
        )
        .expect("create fixture table");
        conn.execute(
            "INSERT INTO src05a1_payloads (id, payload) VALUES (1, ?1)",
            rusqlite::params![blob],
        )
        .expect("insert payload");
    } // the writer connection is closed before any reader exists

    let output = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", SQLITE_CHILD_TEST, "--nocapture"])
        .env(SQLITE_CHILD_DB_ENV, &db_path)
        .env(SQLITE_CHILD_EXPECT_ENV, json)
        .output()
        .expect("spawn decoder child process");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "child failed: {:?}\n{stderr}",
        output.status
    );
    assert!(
        stdout.contains(SQLITE_CHILD_SENTINEL),
        "child sentinel missing in: {stdout}"
    );
    assert!(
        stdout.contains("1 passed"),
        "child did not run the decoder test: {stdout}"
    );
}

/// Child half of [`sqlite_blob_survives_a_process_boundary`]. Runs only when the
/// parent passes the database path through the environment; as an ordinary test
/// it is a no-op.
#[test]
fn sqlite_blob_child_decodes_by_path() {
    let Ok(db_path) = std::env::var(SQLITE_CHILD_DB_ENV) else {
        return;
    };
    let expected_json = std::env::var(SQLITE_CHILD_EXPECT_ENV).expect("child expected JSON");

    let conn =
        rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open fixture db read-only");
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT payload FROM src05a1_payloads WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("read payload blob");
    drop(conn);

    assert_eq!(
        blob,
        encode_safe_source(&parse(&expected_json)).expect("re-encode expected")
    );

    let decoded = decode_safe_source(&blob).expect("decode blob read from disk");
    assert_eq!(
        decoded.safe_json(),
        expected_json,
        "stored JSON text must come back verbatim"
    );
    assert_eq!(
        decoded.value(),
        &parse(&expected_json),
        "decoded nodes must match exactly"
    );

    println!("{SQLITE_CHILD_SENTINEL}");
}
