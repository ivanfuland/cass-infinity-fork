//! Numeric sideview for the legacy Python ordered-pool encoding.
//!
//! The caller must pin these exact windows JSONL bytes and first validate them
//! with the strict input reader. This module does not validate the input schema,
//! read files, encode whole tuples, or project identifiers into Run fields.
//! It is not declared in the regression module until integration is authorized.

use std::ops::Range;

const MAX_DEPTH: usize = 128;
const MAX_SCORES: usize = 1800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericKind {
    Integer,
    Float,
}

/// A carrier that preserves both the value and the original numeric kind.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumericValue {
    I64(i64),
    U64(u64),
    F64(f64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepresentationGap {
    /// The integer has exact canonical bytes but needs a larger integer carrier.
    IntegerOutsideI64U64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NumericEncoding {
    pub kind: NumericKind,
    pub canonical: Vec<u8>,
    pub value: Result<NumericValue, RepresentationGap>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScoreSpan {
    pub item_index: usize,
    pub rank: u64,
    /// Absolute byte offsets into the caller's original JSONL bytes.
    pub number_span: Range<usize>,
    pub encoding: NumericEncoding,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WindowScores {
    pub window_index: usize,
    pub qid: String,
    pub scores: Vec<ScoreSpan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingError {
    InvalidNumber,
    NonFiniteFloat,
    InvalidSideview,
    DuplicateTarget,
    MissingTarget,
    DepthLimit,
    ScoreLimit,
}

/// Encode one JSON number as Python json.loads/json.dumps would encode it.
/// Integers never pass through f64. Floating tokens use Rust's correctly rounded
/// parser, then the existing serde_json shortest formatter for those exact bits.
pub fn encode_numeric(token: &[u8]) -> Result<NumericEncoding, EncodingError> {
    if number_end(token, 0)? != token.len() {
        return Err(EncodingError::InvalidNumber);
    }
    let text = std::str::from_utf8(token).map_err(|_| EncodingError::InvalidNumber)?;
    if !token.iter().any(|b| matches!(b, b'.' | b'e' | b'E')) {
        let canonical = if text == "-0" { "0" } else { text };
        let value = canonical
            .parse::<i64>()
            .map(NumericValue::I64)
            .or_else(|_| canonical.parse::<u64>().map(NumericValue::U64))
            .map_err(|_| RepresentationGap::IntegerOutsideI64U64);
        return Ok(NumericEncoding {
            kind: NumericKind::Integer,
            canonical: canonical.as_bytes().to_vec(),
            value,
        });
    }
    let value = text
        .parse::<f64>()
        .map_err(|_| EncodingError::InvalidNumber)?;
    let shortest = serde_json::Number::from_f64(value)
        .ok_or(EncodingError::NonFiniteFloat)?
        .to_string();
    Ok(NumericEncoding {
        kind: NumericKind::Float,
        canonical: python_float_text(&shortest).into_bytes(),
        value: Ok(NumericValue::F64(value)),
    })
}

// Normalize notation without recomputing digits or using an f64 logarithm.
fn python_float_text(shortest: &str) -> String {
    let (sign, unsigned) = shortest
        .strip_prefix('-')
        .map_or(("", shortest), |text| ("-", text));
    let (mantissa, tail) = unsigned.split_once('e').map_or((unsigned, 0), |(m, e)| {
        (m, e.parse::<i32>().expect("finite shortest exponent"))
    });
    let fraction_len = mantissa.split_once('.').map_or(0, |(_, f)| f.len());
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return format!("{sign}0.0");
    }
    let exponent = tail - fraction_len as i32 + digits.len() as i32 - 1;
    let digits = digits.trim_end_matches('0');
    if !(-4..16).contains(&exponent) {
        let fraction = if digits.len() == 1 {
            String::new()
        } else {
            format!(".{}", &digits[1..])
        };
        return format!(
            "{sign}{}{fraction}e{}{:02}",
            &digits[..1],
            if exponent < 0 { '-' } else { '+' },
            exponent.unsigned_abs()
        );
    }
    let point = exponent + 1;
    if point <= 0 {
        format!("{sign}0.{}{digits}", "0".repeat((-point) as usize))
    } else if point as usize >= digits.len() {
        format!(
            "{sign}{digits}{}.0",
            "0".repeat(point as usize - digits.len())
        )
    } else {
        let point = point as usize;
        format!("{sign}{}.{}", &digits[..point], &digits[point..])
    }
}

fn number_end(bytes: &[u8], start: usize) -> Result<usize, EncodingError> {
    let mut pos = start;
    if bytes.get(pos) == Some(&b'-') {
        pos += 1;
    }
    match bytes.get(pos) {
        Some(b'0') => pos += 1,
        Some(b'1'..=b'9') => {
            pos += 1;
            while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
                pos += 1;
            }
        }
        _ => return Err(EncodingError::InvalidNumber),
    }
    if bytes.get(pos) == Some(&b'.') {
        pos += 1;
        let first = pos;
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        if first == pos {
            return Err(EncodingError::InvalidNumber);
        }
    }
    if bytes.get(pos).is_some_and(|b| matches!(b, b'e' | b'E')) {
        pos += 1;
        if bytes.get(pos).is_some_and(|b| matches!(b, b'+' | b'-')) {
            pos += 1;
        }
        let first = pos;
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        if first == pos {
            return Err(EncodingError::InvalidNumber);
        }
    }
    Ok(pos)
}

/// Locate root.items[index].original_score without parsing numbers into Value.
/// The walk is bounded by the input bytes, the strict reader's 128-level
/// recursion budget and 1800 scores. The reader rejects budget exhaustion,
/// so at most 127 nested containers are accepted, including the root object.
/// Offsets cover only the original numeric token, excluding adjacent whitespace.
/// qid is stored once per window; each score is associated by index and rank.
pub fn original_score_sideview(bytes: &[u8]) -> Result<Vec<WindowScores>, EncodingError> {
    let mut windows = Vec::new();
    let mut offset = 0;
    let mut score_count = 0;
    for line in bytes.split(|b| *b == b'\n') {
        if line.is_empty() && offset == bytes.len() {
            break;
        }
        let mut walk = ScoreWalk {
            bytes: line,
            pos: 0,
            offset,
        };
        let mut window = walk.window(&mut score_count)?;
        walk.space();
        if walk.pos != line.len() {
            return Err(EncodingError::InvalidSideview);
        }
        window.window_index = windows.len();
        windows.push(window);
        offset += line.len() + 1;
    }
    Ok(windows)
}

struct ScoreWalk<'a> {
    bytes: &'a [u8],
    pos: usize,
    offset: usize,
}

impl ScoreWalk<'_> {
    fn space(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.pos += 1;
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        self.space();
        if self.bytes.get(self.pos) == Some(&byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), EncodingError> {
        if self.take(byte) {
            Ok(())
        } else {
            Err(EncodingError::InvalidSideview)
        }
    }

    fn string_span(&mut self) -> Result<Range<usize>, EncodingError> {
        self.space();
        let start = self.pos;
        self.expect(b'"')?;
        while let Some(byte) = self.bytes.get(self.pos) {
            self.pos += 1;
            match byte {
                b'"' => return Ok(start..self.pos),
                b'\\' => {
                    if self.pos == self.bytes.len() {
                        return Err(EncodingError::InvalidSideview);
                    }
                    self.pos += 1;
                }
                _ => {}
            }
        }
        Err(EncodingError::InvalidSideview)
    }

    fn string(&mut self) -> Result<String, EncodingError> {
        let span = self.string_span()?;
        serde_json::from_slice::<String>(&self.bytes[span])
            .map_err(|_| EncodingError::InvalidSideview)
    }

    fn number_span(&mut self) -> Result<Range<usize>, EncodingError> {
        self.space();
        let start = self.pos;
        self.pos = number_end(self.bytes, self.pos)?;
        if self
            .bytes
            .get(self.pos)
            .is_some_and(|b| !matches!(b, b' ' | b'\t' | b'\r' | b',' | b'}' | b']'))
        {
            return Err(EncodingError::InvalidNumber);
        }
        Ok(start..self.pos)
    }

    fn window(&mut self, count: &mut usize) -> Result<WindowScores, EncodingError> {
        self.expect(b'{')?;
        let mut qid = None;
        let mut scores = None;
        if !self.take(b'}') {
            loop {
                let key = self.string()?;
                self.expect(b':')?;
                match key.as_str() {
                    "qid" => {
                        if qid.is_some() {
                            return Err(EncodingError::DuplicateTarget);
                        }
                        qid = Some(self.string()?);
                    }
                    "items" => {
                        if scores.is_some() {
                            return Err(EncodingError::DuplicateTarget);
                        }
                        scores = Some(self.items(count)?);
                    }
                    _ => self.skip_value(1)?,
                }
                if self.take(b'}') {
                    break;
                }
                self.expect(b',')?;
            }
        }
        Ok(WindowScores {
            window_index: 0,
            qid: qid.ok_or(EncodingError::MissingTarget)?,
            scores: scores.ok_or(EncodingError::MissingTarget)?,
        })
    }

    fn items(&mut self, count: &mut usize) -> Result<Vec<ScoreSpan>, EncodingError> {
        self.expect(b'[')?;
        let mut scores = Vec::new();
        if !self.take(b']') {
            loop {
                if *count == MAX_SCORES {
                    return Err(EncodingError::ScoreLimit);
                }
                scores.push(self.item(scores.len())?);
                *count += 1;
                if self.take(b']') {
                    break;
                }
                self.expect(b',')?;
            }
        }
        Ok(scores)
    }

    fn item(&mut self, item_index: usize) -> Result<ScoreSpan, EncodingError> {
        self.expect(b'{')?;
        let mut rank = None;
        let mut score = None;
        if !self.take(b'}') {
            loop {
                let key = self.string()?;
                self.expect(b':')?;
                match key.as_str() {
                    "rank" => {
                        if rank.is_some() {
                            return Err(EncodingError::DuplicateTarget);
                        }
                        let span = self.number_span()?;
                        rank = Some(
                            std::str::from_utf8(&self.bytes[span])
                                .map_err(|_| EncodingError::InvalidSideview)?
                                .parse::<u64>()
                                .map_err(|_| EncodingError::InvalidSideview)?,
                        );
                    }
                    "original_score" => {
                        if score.is_some() {
                            return Err(EncodingError::DuplicateTarget);
                        }
                        let span = self.number_span()?;
                        let encoding = encode_numeric(&self.bytes[span.clone()])?;
                        score = Some((span, encoding));
                    }
                    _ => self.skip_value(3)?,
                }
                if self.take(b'}') {
                    break;
                }
                self.expect(b',')?;
            }
        }
        let (span, encoding) = score.ok_or(EncodingError::MissingTarget)?;
        Ok(ScoreSpan {
            item_index,
            rank: rank.ok_or(EncodingError::MissingTarget)?,
            number_span: (self.offset + span.start)..(self.offset + span.end),
            encoding,
        })
    }

    // Unknown fields have already passed strict JSON validation. Only walk their
    // extent here; do not decode their keys, numbers, or arbitrary nested values.
    fn skip_value(&mut self, parent_depth: usize) -> Result<(), EncodingError> {
        self.space();
        match self.bytes.get(self.pos) {
            Some(b'"') => {
                self.string_span()?;
            }
            Some(b'{' | b'[') => {
                let mut closers = Vec::new();
                loop {
                    match self.bytes.get(self.pos) {
                        Some(b'"') => {
                            self.string_span()?;
                        }
                        Some(b'{' | b'[') => {
                            if parent_depth + closers.len() >= MAX_DEPTH - 1 {
                                return Err(EncodingError::DepthLimit);
                            }
                            closers.push(if self.bytes[self.pos] == b'{' {
                                b'}'
                            } else {
                                b']'
                            });
                            self.pos += 1;
                        }
                        Some(b'}' | b']') => {
                            if closers.pop() != Some(self.bytes[self.pos]) {
                                return Err(EncodingError::InvalidSideview);
                            }
                            self.pos += 1;
                            if closers.is_empty() {
                                break;
                            }
                        }
                        Some(_) => self.pos += 1,
                        None => return Err(EncodingError::InvalidSideview),
                    }
                }
            }
            Some(_) => {
                let start = self.pos;
                while self
                    .bytes
                    .get(self.pos)
                    .is_some_and(|b| !matches!(b, b' ' | b'\t' | b'\r' | b',' | b'}' | b']'))
                {
                    self.pos += 1;
                }
                if start == self.pos {
                    return Err(EncodingError::InvalidSideview);
                }
            }
            None => return Err(EncodingError::InvalidSideview),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_integer_kind_and_reports_carrier_gap() {
        for (text, canonical, carrier) in [
            ("-0", "0", Ok(NumericValue::I64(0))),
            (
                "9007199254740993",
                "9007199254740993",
                Ok(NumericValue::I64(9007199254740993)),
            ),
            (
                "9223372036854775807",
                "9223372036854775807",
                Ok(NumericValue::I64(i64::MAX)),
            ),
            (
                "-9223372036854775808",
                "-9223372036854775808",
                Ok(NumericValue::I64(i64::MIN)),
            ),
            (
                "18446744073709551615",
                "18446744073709551615",
                Ok(NumericValue::U64(u64::MAX)),
            ),
            (
                "18446744073709551616",
                "18446744073709551616",
                Err(RepresentationGap::IntegerOutsideI64U64),
            ),
        ] {
            let encoded = encode_numeric(text.as_bytes()).unwrap();
            assert_eq!(encoded.kind, NumericKind::Integer);
            assert_eq!(encoded.canonical, canonical.as_bytes());
            assert_eq!(encoded.value, carrier);
        }
    }

    #[test]
    fn python_float_notation_and_exact_bits() {
        // Literal Python-generated expected tokens and IEEE bits; no formatter oracle.
        for (text, canonical, bits) in [
            ("0.0", "0.0", 0x0000000000000000),
            ("-0.0", "-0.0", 0x8000000000000000),
            ("1e-400", "0.0", 0x0000000000000000),
            ("-1e-400", "-0.0", 0x8000000000000000),
            ("1.0", "1.0", 0x3ff0000000000000),
            ("0.0001", "0.0001", 0x3f1a36e2eb1c432d),
            ("1e-5", "1e-05", 0x3ee4f8b588e368f1),
            ("1e15", "1000000000000000.0", 0x430c6bf526340000),
            ("1e16", "1e+16", 0x4341c37937e08000),
            ("5e-324", "5e-324", 0x0000000000000001),
            (
                "1.7976931348623157e308",
                "1.7976931348623157e+308",
                0x7fefffffffffffff,
            ),
            (
                "-1.9799289335064246e+301",
                "-1.9799289335064246e+301",
                0xfe7d909229733243,
            ),
            (
                "1.00000000000000011102230246251565404236316680908203125",
                "1.0",
                0x3ff0000000000000,
            ),
            (
                "1.00000000000000011102230246251565404236316680908203126",
                "1.0000000000000002",
                0x3ff0000000000001,
            ),
        ] {
            let encoded = encode_numeric(text.as_bytes()).unwrap();
            assert_eq!(encoded.kind, NumericKind::Float);
            assert_eq!(encoded.canonical, canonical.as_bytes(), "{text}");
            let Ok(NumericValue::F64(value)) = encoded.value else {
                panic!("float carrier");
            };
            assert_eq!(value.to_bits(), bits, "{text}");
        }
    }

    #[test]
    fn rejects_invalid_or_nonfinite_numeric_tokens() {
        for token in [
            "", "+1", "01", "-01", ".1", "1.", "1e", "1e+", "NaN", "Infinity", "1 2", "1\n", "1x",
        ] {
            assert_eq!(
                encode_numeric(token.as_bytes()),
                Err(EncodingError::InvalidNumber),
                "{token}"
            );
        }
        for token in ["1e309", "-1e309"] {
            assert_eq!(
                encode_numeric(token.as_bytes()),
                Err(EncodingError::NonFiniteFloat)
            );
        }
    }

    #[test]
    fn skips_false_paths_and_decodes_escaped_target_keys() {
        let bytes = br#"{"extra":{"items":[{"original_score":77}]},"query":"fake \"original_score\":99 \\ \u263a","items":[{"unused":{"original_score":88,"items":[null,true,false,"}"]},"original_\u0073core":-0.0,"rank":7}],"q\u0069d":"SYN_\u5408\u6210\ud83d\ude00"}
{"qid":"SYN_2","items":[{"rank":2,"original_score":9007199254740993}]}
"#;
        let windows = original_score_sideview(bytes).unwrap();
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].qid, "SYN_合成😀");
        assert_eq!(windows[1].window_index, 1);
        for (index, token, rank) in [(0, "-0.0", 7), (1, "9007199254740993", 2)] {
            assert_eq!(windows[index].scores.len(), 1);
            let score = &windows[index].scores[0];
            assert_eq!(&bytes[score.number_span.clone()], token.as_bytes());
            assert_eq!(score.item_index, 0);
            assert_eq!(score.rank, rank);
            assert_eq!(score.encoding.canonical, token.as_bytes());
        }
    }

    #[test]
    fn refuses_duplicate_or_missing_targets() {
        for text in [
            r#"{"qid":"SYN","q\u0069d":"SYN","items":[]}"#,
            r#"{"qid":"SYN","items":[],"items":[]}"#,
            r#"{"qid":"SYN","items":[{"rank":1,"rank":1,"original_score":0}]}"#,
            r#"{"qid":"SYN","items":[{"rank":1,"original_score":0,"original_\u0073core":0}]}"#,
        ] {
            assert_eq!(
                original_score_sideview(text.as_bytes()),
                Err(EncodingError::DuplicateTarget)
            );
        }
        for text in [
            r#"{"items":[]}"#,
            r#"{"qid":"SYN"}"#,
            r#"{"qid":"SYN","items":[{"rank":1}]}"#,
            r#"{"qid":"SYN","items":[{"original_score":0}]}"#,
        ] {
            assert_eq!(
                original_score_sideview(text.as_bytes()),
                Err(EncodingError::MissingTarget)
            );
        }
    }

    #[test]
    fn enforces_depth_and_total_score_bounds() {
        for (depth, expected) in [(126, true), (127, false)] {
            let text = format!(
                "{{\"qid\":\"SYN\",\"items\":[],\"extra\":{}0{}}}",
                "[".repeat(depth),
                "]".repeat(depth)
            );
            let result = original_score_sideview(text.as_bytes());
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&text).is_ok(),
                expected
            );
            if expected {
                assert!(result.is_ok());
            } else {
                assert_eq!(result, Err(EncodingError::DepthLimit));
            }
        }
        // root / items / item also consume the reader's recursion budget.
        for (depth, expected) in [(124, true), (125, false)] {
            let text = format!(
                "{{\"qid\":\"SYN\",\"items\":[{{\"rank\":1,\"original_score\":0,\"extra\":{}0{}}}]}}",
                "[".repeat(depth),
                "]".repeat(depth)
            );
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&text).is_ok(),
                expected
            );
            let result = original_score_sideview(text.as_bytes());
            if expected {
                assert!(result.is_ok());
            } else {
                assert_eq!(result, Err(EncodingError::DepthLimit));
            }
        }
        for (count, expected) in [(1800, true), (1801, false)] {
            let items = vec![r#"{"rank":1,"original_score":0}"#; count].join(",");
            let text = format!("{{\"qid\":\"SYN\",\"items\":[{items}]}}");
            let result = original_score_sideview(text.as_bytes());
            if expected {
                assert_eq!(result.unwrap()[0].scores.len(), count);
            } else {
                assert_eq!(result, Err(EncodingError::ScoreLimit));
            }
        }
    }

    #[test]
    fn rejects_truncated_or_wrong_target_types() {
        for text in [
            r#"{"qid":"SYN","items":[{"rank":1,"original_score":"1"}]}"#,
            r#"{"qid":"SYN","items":[{"rank":1,"original_score":null}]}"#,
            r#"{"qid":"SYN","items":[{"rank":1.0,"original_score":0}]}"#,
            r#"{"qid":"SYN","items":[],"extra":[}"#,
            r#"{"qid":"SYN","items":[],"extra":"unterminated}"#,
            r#"{"qid":"SYN","items":[]} trailing"#,
        ] {
            assert!(original_score_sideview(text.as_bytes()).is_err(), "{text}");
        }
    }
}
