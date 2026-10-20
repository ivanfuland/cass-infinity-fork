//! Strict lossless source payload codec (`safe-json-msgpack/1`).
//!
//! The codec serialises one already-sanitised lossless source tree into a
//! self-describing MessagePack envelope and reads it back byte-exactly. It is
//! the only storage format for safe source payloads in this stage; it does not
//! sanitise, redact or re-map anything. The caller owns the safety plan and
//! passes in a tree that the safety pass has already produced.
//!
//! Wire format, exactly two fields and nothing else:
//!
//! ```text
//! { "version": 1, "safe_json": "<canonical JSON of the lossless source tree>" }
//! ```
//!
//! Both fields are written by hand as a MessagePack *map*, never as a struct or
//! tuple array, and the source object is never merged with the envelope fields.
//! Decoding is strict: duplicate, unknown and missing fields, a non-map
//! envelope, a non-string key, a non-integer or unsupported `version`, a
//! `safe_json` that is not a MessagePack string (bin bytes included), any
//! trailing byte after the envelope, and any `safe_json` that is not a single
//! well-formed JSON value with unique object keys all fail with a structured
//! error. No failure path degrades to a successful empty value.
//!
//! Error values are deliberately payload-free: they carry no source JSON, key,
//! credential or upstream parser text. [`SourceCodecError::Display`] prints a
//! fixed short code, and the derived `Debug` prints the variant name only.

use std::collections::HashSet;
use std::fmt;

use franken_agent_detection::LosslessSourceValue;

/// Codec identifier persisted next to the payload bytes.
pub const SAFE_SOURCE_CODEC_ID: &str = "safe-json-msgpack/1";

/// The only envelope version this codec writes and accepts.
pub const SAFE_SOURCE_CODEC_VERSION: u64 = 1;

/// Envelope field name for the integer format version.
const FIELD_VERSION: &str = "version";

/// Envelope field name for the canonical JSON payload.
const FIELD_SAFE_JSON: &str = "safe_json";

/// Structured, finite codec error.
///
/// The set is closed on purpose: callers branch on the variant, never on a
/// rendered string, and no variant carries source content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCodecError {
    /// The source tree does not satisfy the lossless IR contract, or encoding
    /// it exceeded an addressable size. Nothing was produced.
    EncodeFailed,
    /// The outer MessagePack structure is not a two-field map of strings and
    /// integers: truncated or malformed bytes, a non-map, a non-string key, or
    /// a `safe_json` value that is not a MessagePack string.
    InvalidEnvelope,
    /// An envelope field appeared twice. The duplicate is rejected before its
    /// value can overwrite the first one.
    DuplicateField,
    /// An envelope field that this version does not define.
    UnknownField,
    /// A required envelope field (`version` or `safe_json`) is absent.
    MissingField,
    /// The `version` field is present but is not an integer.
    InvalidVersion,
    /// The `version` field is an integer that this codec does not support.
    UnsupportedVersion,
    /// `safe_json` is not exactly one valid JSON value: malformed JSON,
    /// duplicate JSON object keys, or trailing JSON content.
    InvalidSafeJson,
    /// Well-formed envelope followed by unconsumed bytes.
    TrailingBytes,
}

impl SourceCodecError {
    /// Stable short code for logs and robot output. Contains no source data.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::EncodeFailed => "encode-failed",
            Self::InvalidEnvelope => "invalid-envelope",
            Self::DuplicateField => "duplicate-field",
            Self::UnknownField => "unknown-field",
            Self::MissingField => "missing-field",
            Self::InvalidVersion => "invalid-version",
            Self::UnsupportedVersion => "unsupported-version",
            Self::InvalidSafeJson => "invalid-safe-json",
            Self::TrailingBytes => "trailing-bytes",
        }
    }
}

impl fmt::Display for SourceCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SourceCodecError {}

/// A decoded envelope: the stored `safe_json` string and its lossless tree.
///
/// Reading a payload successfully only proves that the bytes matched the codec
/// contract. It is not evidence that the sanitisation policy passed, and the
/// tree must not be handed to a consumer as "already safe" on that basis.
#[derive(Debug, Clone)]
pub struct DecodedSafeSource {
    safe_json: String,
    value: LosslessSourceValue,
}

impl DecodedSafeSource {
    /// The stored JSON text exactly as it was persisted, with its original
    /// whitespace and number lexical forms. The codec never rewrites it.
    #[must_use]
    pub fn safe_json(&self) -> &str {
        &self.safe_json
    }

    /// Read-only access to the lossless node tree.
    #[must_use]
    pub fn value(&self) -> &LosslessSourceValue {
        &self.value
    }
}

/// Encode one sanitised lossless source tree as a `safe-json-msgpack/1`
/// envelope.
///
/// The payload comes from [`LosslessSourceValue::write_canonical`]; raw source
/// text is not an encode input. Object member order, array order and every
/// number's original token text are preserved.
///
/// A tree whose object carries a repeated member name is refused with
/// [`SourceCodecError::EncodeFailed`]. The public `Object(Vec)` constructor can
/// build such a tree by hand, and accepting it would emit an envelope that this
/// module's own decoder rejects.
pub fn encode_safe_source(source: &LosslessSourceValue) -> Result<Vec<u8>, SourceCodecError> {
    reject_duplicate_members(source)?;

    let mut safe_json = Vec::new();
    source
        .write_canonical(&mut safe_json)
        .map_err(|_| SourceCodecError::EncodeFailed)?;

    let version =
        u8::try_from(SAFE_SOURCE_CODEC_VERSION).map_err(|_| SourceCodecError::EncodeFailed)?;

    let mut out = Vec::with_capacity(safe_json.len() + 32);
    // fixmap with exactly two fields.
    out.push(0x82);
    write_str(&mut out, FIELD_VERSION.as_bytes())?;
    out.push(version);
    write_str(&mut out, FIELD_SAFE_JSON.as_bytes())?;
    write_str(&mut out, &safe_json)?;
    Ok(out)
}

/// Decode a `safe-json-msgpack/1` envelope.
pub fn decode_safe_source(bytes: &[u8]) -> Result<DecodedSafeSource, SourceCodecError> {
    let mut reader = Reader { bytes, pos: 0 };
    let entries = read_map_header(&mut reader)?;

    let mut version: Option<VersionInteger> = None;
    let mut safe_json: Option<String> = None;

    // At most two distinct field names are valid, so a hostile entry count
    // cannot make this loop run long: the second field of a known name is a
    // duplicate and the first field of an unknown name is unknown. The count is
    // never used to pre-allocate.
    for _ in 0..entries {
        let key = read_str(&mut reader)?;
        let is_version = key == FIELD_VERSION;
        if !is_version && key != FIELD_SAFE_JSON {
            return Err(SourceCodecError::UnknownField);
        }
        // Reject the repeat before reading its value, so the first value is
        // never overwritten.
        let already_seen = if is_version {
            version.is_some()
        } else {
            safe_json.is_some()
        };
        if already_seen {
            return Err(SourceCodecError::DuplicateField);
        }
        if is_version {
            version = Some(read_version(&mut reader)?);
        } else {
            safe_json = Some(read_str(&mut reader)?.to_owned());
        }
    }

    if reader.remaining() != 0 {
        return Err(SourceCodecError::TrailingBytes);
    }

    let Some(version) = version else {
        return Err(SourceCodecError::MissingField);
    };
    let Some(safe_json) = safe_json else {
        return Err(SourceCodecError::MissingField);
    };

    // Every MessagePack integer width is a legal encoding of version 1; the
    // kind of wire encoding is not part of the version. A negative value has
    // no `u64` form at all, so it can never compare equal to 1.
    if version.value() != Some(SAFE_SOURCE_CODEC_VERSION) {
        return Err(SourceCodecError::UnsupportedVersion);
    }

    // `parse` requires one complete well-formed JSON value and rejects
    // duplicate object keys itself, so both are covered here.
    let value = LosslessSourceValue::parse(safe_json.as_bytes())
        .map_err(|_| SourceCodecError::InvalidSafeJson)?;

    Ok(DecodedSafeSource { safe_json, value })
}

/// Walk the tree iteratively and refuse any object with a repeated member name.
///
/// A hand-built `Object` can violate the lossless IR contract in exactly this
/// way; `parse` never produces one. The walk owns its own heap stack so a
/// deeply nested tree cannot overflow the call stack.
fn reject_duplicate_members(root: &LosslessSourceValue) -> Result<(), SourceCodecError> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node {
            LosslessSourceValue::Object(members) => {
                let mut seen = HashSet::with_capacity(members.len());
                for (key, value) in members {
                    if !seen.insert(key.as_str()) {
                        return Err(SourceCodecError::EncodeFailed);
                    }
                    stack.push(value);
                }
            }
            LosslessSourceValue::Array(values) => stack.extend(values.iter()),
            LosslessSourceValue::String(_)
            | LosslessSourceValue::Number(_)
            | LosslessSourceValue::Bool(_)
            | LosslessSourceValue::Null => {}
        }
    }
    Ok(())
}

/// Append one MessagePack string. Lengths that do not fit in the `str32` header
/// are an explicit resource failure, never a truncation.
fn write_str(out: &mut Vec<u8>, text: &[u8]) -> Result<(), SourceCodecError> {
    let len = text.len();
    if len < 32 {
        out.push(0xa0 | len as u8);
    } else if let Ok(len) = u8::try_from(len) {
        out.push(0xd9);
        out.push(len);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(0xda);
        out.extend_from_slice(&len.to_be_bytes());
    } else if let Ok(len) = u32::try_from(len) {
        out.push(0xdb);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        return Err(SourceCodecError::EncodeFailed);
    }
    out.extend_from_slice(text);
    Ok(())
}

/// A `version` value read off the wire, kept apart so a 64-bit unsigned value
/// is never cast into a signed integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionInteger {
    Unsigned(u64),
    Signed(i64),
}

impl VersionInteger {
    /// The value as a non-negative integer, or `None` when the wire value is
    /// negative. Callers compare this against the supported version, so a
    /// negative or out-of-range wire value can never compare equal to it and
    /// no widening cast is involved.
    fn value(self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(value),
            Self::Signed(value) => u64::try_from(value).ok(),
        }
    }
}

/// Minimal forward-only cursor over the envelope bytes.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, SourceCodecError> {
        let byte = *self
            .bytes
            .get(self.pos)
            .ok_or(SourceCodecError::InvalidEnvelope)?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SourceCodecError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(SourceCodecError::InvalidEnvelope)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(SourceCodecError::InvalidEnvelope)?;
        self.pos = end;
        Ok(slice)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
}

/// Read the MessagePack map header and return its declared entry count.
fn read_map_header(reader: &mut Reader<'_>) -> Result<u32, SourceCodecError> {
    match reader.byte()? {
        byte @ 0x80..=0x8f => Ok(u32::from(byte & 0x0f)),
        0xde => Ok(u32::from(u16::from_be_bytes([
            reader.byte()?,
            reader.byte()?,
        ]))),
        0xdf => Ok(u32::from_be_bytes([
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
        ])),
        _ => Err(SourceCodecError::InvalidEnvelope),
    }
}

/// Read one MessagePack string as UTF-8. Binary, extension and every other wire
/// type are envelope violations even when their payload happens to be valid
/// UTF-8.
fn read_str<'a>(reader: &mut Reader<'a>) -> Result<&'a str, SourceCodecError> {
    let len = match reader.byte()? {
        byte @ 0xa0..=0xbf => usize::from(byte & 0x1f),
        0xd9 => usize::from(reader.byte()?),
        0xda => usize::from(u16::from_be_bytes([reader.byte()?, reader.byte()?])),
        0xdb => usize::try_from(u32::from_be_bytes([
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
        ]))
        .map_err(|_| SourceCodecError::InvalidEnvelope)?,
        _ => return Err(SourceCodecError::InvalidEnvelope),
    };
    let raw = reader.take(len)?;
    std::str::from_utf8(raw).map_err(|_| SourceCodecError::InvalidEnvelope)
}

/// Read the `version` field, which must be a MessagePack integer.
fn read_version(reader: &mut Reader<'_>) -> Result<VersionInteger, SourceCodecError> {
    match reader.byte()? {
        byte @ 0x00..=0x7f => Ok(VersionInteger::Unsigned(u64::from(byte))),
        byte @ 0xe0..=0xff => Ok(VersionInteger::Signed(i64::from(byte as i8))),
        0xcc => Ok(VersionInteger::Unsigned(u64::from(reader.byte()?))),
        0xcd => Ok(VersionInteger::Unsigned(u64::from(u16::from_be_bytes([
            reader.byte()?,
            reader.byte()?,
        ])))),
        0xce => Ok(VersionInteger::Unsigned(u64::from(u32::from_be_bytes([
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
        ])))),
        0xcf => Ok(VersionInteger::Unsigned(u64::from_be_bytes([
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
        ]))),
        0xd0 => Ok(VersionInteger::Signed(i64::from(i8::from_be_bytes([
            reader.byte()?,
        ])))),
        0xd1 => Ok(VersionInteger::Signed(i64::from(i16::from_be_bytes([
            reader.byte()?,
            reader.byte()?,
        ])))),
        0xd2 => Ok(VersionInteger::Signed(i64::from(i32::from_be_bytes([
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
        ])))),
        0xd3 => Ok(VersionInteger::Signed(i64::from_be_bytes([
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
            reader.byte()?,
        ]))),
        _ => Err(SourceCodecError::InvalidVersion),
    }
}
