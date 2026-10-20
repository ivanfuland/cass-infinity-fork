//! Source-aware storage primitives (SRC05A).
//!
//! This module owns the three source-aware tables (`source_inputs`,
//! `source_records`, `source_message_links`), their strict structural
//! verification gate, the canonical hashing/encoding primitives the
//! activation flow is built on, and the five transaction-scoped primitives
//! (`stage_source_records_in_tx`, `install_conversation_projection_in_tx`,
//! `install_source_links_in_tx`, `activate_source_input_in_tx`,
//! `verify_source_receipt_in_tx`).
//!
//! The wire/encoding contract is the frozen SRC05A施工合同 §4–§6, §9–§13. Two
//! rules dominate the layout here:
//!
//! - **Standards are separated from encoding.** The five stream roots, the
//!   canonical tuples and the per-leaf digests are the frozen contract; the
//!   JSON writer below is only how they are serialised. The writer emits
//!   compact UTF-8 JSON, writes every `u64`/`i64`/`u32` as a *decimal string*
//!   (never a JSON number, so no consumer ever sees an `f64`), and applies the
//!   contract's escape rule verbatim.
//! - **A saved digest is never proof.** Historical verification re-reads and
//!   re-encodes each leaf and compares recomputed digests against the stored
//!   ones; it never hashes a stored digest column to make a decision.
//!
//! The structural gate ([`verify_source_schema`]) is deliberately *not* part
//! of the derived-repair machinery: a missing or drifted source table is a
//! structured refusal, not a table to be silently rebuilt.

use std::fmt;
use std::io::Cursor;
use std::path::Path;

use franken_agent_detection::LosslessSourceValue;
use sha2::{Digest, Sha256};

use super::api::{Conn, Row, StorageError, Tx, Value};
use super::source_codec::SourceCodecError;
use crate::storage::schema::{CURRENT_SCHEMA_VERSION, SOURCE_FACTS_REVISION_META_KEY};

mod framing;
mod reader;
mod standard;

pub use framing::{
    FRAMING_DEFAULT_MAX_RECORDS, FRAMING_DEFAULT_TARGET_BYTES, FramingStream,
};

pub use reader::{
    RawSourceFactsPage, RawSourceFactsRecord, SourceFactsExpectedManifest, SourceFactsFilter,
    SourceFactsInput, SourceFactsPage, SourceFactsPageLimits, SourceFactsReadError,
    SourceFactsReadErrorCode, SourceFactsReader, SourceFactsRecord, SourceFactsRecordLink,
    SourceFactsScope, SOURCE_FACTS_READER_VERSION,
};

pub use standard::{
    CandidateFact, FactStatus, FactUnit, FactValue, FactValueKind, FieldFact, MessageFacts,
    StandardFacts, ToolFact, UsageSnapshot, alias_fact, count_fact, map_claude_standard,
    map_codex_standard, time_fact, value_fact,
};

// =============================================================================
// Errors
// =============================================================================

/// Strict source-schema verification failure (SRC05A §6.4).
///
/// The set is closed and payload-light: it names the object and the dimension
/// that drifted, never a full DDL dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceSchemaError {
    /// A required table or index is absent from `sqlite_master`.
    MissingObject { kind: &'static str, name: &'static str },
    /// The stored `sqlite_master.sql` does not match this module's frozen DDL
    /// after whitespace normalization.
    DdlDrift { name: &'static str },
    /// A `PRAGMA` introspection dimension disagrees with the frozen shape:
    /// `table_info` columns/`NOT NULL`/PK, `index_list` uniqueness/partial
    /// flags, `index_xinfo` key ordering, or `foreign_key_list` delete action.
    ShapeDrift { name: &'static str, detail: String },
    /// The database could not be introspected at all.
    Inaccessible { detail: String },
}

impl fmt::Display for SourceSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingObject { kind, name } => {
                write!(f, "source schema object missing: {kind} {name}")
            }
            Self::DdlDrift { name } => write!(f, "source schema DDL drift: {name}"),
            Self::ShapeDrift { name, detail } => {
                write!(f, "source schema shape drift: {name}: {detail}")
            }
            Self::Inaccessible { detail } => {
                write!(f, "source schema introspection failed: {detail}")
            }
        }
    }
}

impl std::error::Error for SourceSchemaError {}

/// Read side of the storage facade, so the verification gate can run against
/// either a live [`Conn`] or an in-flight [`Tx`] (SRC05A §6.4 keeps the check
/// inside the initialization transaction).
pub trait SourceSchemaRead {
    fn read_all<T>(
        &self,
        sql: &str,
        params: &[Value],
        f: impl FnMut(&Row) -> Result<T, StorageError>,
    ) -> Result<Vec<T>, StorageError>;
}

impl SourceSchemaRead for Conn {
    fn read_all<T>(
        &self,
        sql: &str,
        params: &[Value],
        f: impl FnMut(&Row) -> Result<T, StorageError>,
    ) -> Result<Vec<T>, StorageError> {
        self.query_all_map(sql, params, f)
    }
}

impl SourceSchemaRead for Tx<'_> {
    fn read_all<T>(
        &self,
        sql: &str,
        params: &[Value],
        f: impl FnMut(&Row) -> Result<T, StorageError>,
    ) -> Result<Vec<T>, StorageError> {
        self.query_all_map(sql, params, f)
    }
}

// =============================================================================
// Strict structural verification
// =============================================================================

/// Collapse every run of ASCII whitespace to a single space and trim the ends.
/// SQLite stores `CREATE` text largely verbatim; only whitespace is
/// insignificant, so this is the only normalization applied before comparing a
/// stored statement against the frozen DDL.
fn normalize_sql(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut pending_space = false;
    for ch in sql.trim().chars() {
        if ch.is_ascii_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        out.push(ch);
    }
    out
}

/// `(column, NOT NULL, PK ordinal)` for one table, in declaration order.
type ColumnShape = (&'static str, bool, u8);

/// `(index name, unique, partial)` for an explicitly named index.
type NamedIndexShape = (&'static str, bool, bool);

/// Expected `PRAGMA table_info` shape for `source_inputs` (§6).
const SOURCE_INPUTS_COLUMNS: &[ColumnShape] = &[
    ("id", false, 1),
    ("input_key", true, 0),
    ("identity_tuple_bin", true, 0),
    ("source_id", true, 0),
    ("identity_namespace", true, 0),
    ("connector", true, 0),
    ("origin_host", false, 0),
    ("origin_source_version", false, 0),
    ("role_bin", false, 0),
    ("platform_bin", false, 0),
    ("root_id_bin", true, 0),
    ("relative_locator_bin", true, 0),
    ("discovery_bin", true, 0),
    ("parser_context_bin", true, 0),
    ("context_digest", true, 0),
    ("sealed_ref_bin", true, 0),
    ("sealed_sha256", true, 0),
    ("byte_len", true, 0),
    ("format", true, 0),
    ("expected_manifest_bin", true, 0),
    ("normalizer_id", true, 0),
    ("safety_contract_id", true, 0),
    ("state", true, 0),
    ("expected_records", true, 0),
    ("expected_blank_lines", true, 0),
    ("observed_records", false, 0),
    ("observed_blank_lines", false, 0),
    ("unprocessed_ranges_bin", false, 0),
    ("attempt_history_bin", false, 0),
    ("activation_request_hash", false, 0),
    ("receipt_key", false, 0),
    ("applied_content_generation", false, 0),
];

/// Expected `PRAGMA table_info` shape for `source_records` (§6).
const SOURCE_RECORDS_COLUMNS: &[ColumnShape] = &[
    ("id", false, 1),
    ("input_id", true, 0),
    ("ordinal", true, 0),
    ("record_pointer", true, 0),
    ("position_bin", true, 0),
    ("expected_source_record_sha256", true, 0),
    ("observed_source_record_sha256", false, 0),
    ("frame_state", true, 0),
    ("native_ids_bin", false, 0),
    ("parse_state", true, 0),
    ("record_mapping_state", true, 0),
    ("safety_state", true, 0),
    ("retention_state", true, 0),
    ("codec", false, 0),
    ("payload_bin", false, 0),
    ("safe_value_hash", false, 0),
    ("diagnostics_bin", false, 0),
];

/// Expected `PRAGMA table_info` shape for `source_message_links` (§6).
const SOURCE_MESSAGE_LINKS_COLUMNS: &[ColumnShape] = &[
    ("id", false, 1),
    ("record_id", true, 0),
    ("projection_key", true, 0),
    ("conversation_ordinal", false, 0),
    ("final_message_idx", false, 0),
    ("source_positions_bin", true, 0),
    ("projection_pointer", false, 0),
    ("message_id", false, 0),
    ("authority", false, 0),
    ("evidence_kind", true, 0),
    ("binding_digest", true, 0),
];

/// Expected explicitly named indexes (§6), `(name, unique, partial)`.
const SOURCE_NAMED_INDEXES: &[NamedIndexShape] = &[
    ("idx_source_records_stream", false, false),
    ("idx_source_records_activated", false, true),
];

/// Expected key-column ordering for each explicitly named index (§7 ordering).
const SOURCE_NAMED_INDEX_KEYS: &[(&str, &[&str])] = &[
    ("idx_source_records_stream", &["input_id", "ordinal", "record_pointer"]),
    ("idx_source_records_activated", &["input_id", "ordinal", "record_pointer"]),
];

/// Strictly verify the three source-aware tables and their indexes against the
/// frozen DDL (SRC05A §6.4).
///
/// Runs on every open, after the `user_version` check and before any derived
/// repair. It checks, in order:
///
/// 1. every frozen object is present in `sqlite_master` (`type` + `name`);
/// 2. its stored `sql` equals the frozen DDL after whitespace normalization
///    (this pins `CHECK` bodies, `NOT NULL`, `UNIQUE`, `COLLATE` and the
///    partial-index `WHERE` predicate as text);
/// 3. `PRAGMA table_info` matches the expected column order, `NOT NULL` set
///    and primary-key column;
/// 4. `PRAGMA index_list` / `index_xinfo` match the expected index uniqueness,
///    partial flag and key-column ordering;
/// 5. `PRAGMA foreign_key_list` reports the expected `ON DELETE` actions.
///
/// A missing table or a drifted shape is refused outright. Nothing here
/// creates, repairs or backfills an object, and the three tables are
/// deliberately absent from `REQUIRED_CURRENT_SCHEMA_TABLE_PROBES` and the
/// derived repair batches.
pub fn verify_source_schema<R: SourceSchemaRead>(read: &R) -> Result<(), SourceSchemaError> {
    use super::schema::{
        SOURCE_FACTS_DDL_STATEMENTS, SOURCE_FACTS_FOREIGN_KEY_ACTIONS, SOURCE_FACTS_SCHEMA_OBJECTS,
    };

    // (1) + (2): presence and DDL text.
    for (kind, name, statement_index) in SOURCE_FACTS_SCHEMA_OBJECTS {
        let stored: Vec<String> = read
            .read_all(
                "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
                &[Value::Text(kind.into()), Value::Text(name.into())],
                |row| row.get_typed(0),
            )
            .map_err(|err| SourceSchemaError::Inaccessible { detail: err.to_string() })?;
        let Some(stored) = stored.into_iter().next() else {
            return Err(SourceSchemaError::MissingObject { kind, name });
        };
        let expected = SOURCE_FACTS_DDL_STATEMENTS[statement_index];
        if normalize_sql(&stored) != normalize_sql(expected) {
            return Err(SourceSchemaError::DdlDrift { name });
        }
    }

    // (3): table_info shape.
    verify_table_columns(read, "source_inputs", SOURCE_INPUTS_COLUMNS)?;
    verify_table_columns(read, "source_records", SOURCE_RECORDS_COLUMNS)?;
    verify_table_columns(read, "source_message_links", SOURCE_MESSAGE_LINKS_COLUMNS)?;

    // (4): index uniqueness, partial flags and key ordering.
    verify_named_indexes(read, "source_records")?;

    // (5): delete actions on the three foreign-key edges.
    for (child, column, parent, on_delete) in SOURCE_FACTS_FOREIGN_KEY_ACTIONS {
        let rows: Vec<(String, String, String)> = read
            .read_all(
                &format!("PRAGMA foreign_key_list({child})"),
                &[],
                // `foreign_key_list` columns: 0 id, 1 seq, 2 table, 3 from,
                // 4 to, 5 on_update, 6 on_delete, 7 match.
                |row| Ok((row.get_typed(3)?, row.get_typed(2)?, row.get_typed(6)?)),
            )
            .map_err(|err| SourceSchemaError::Inaccessible { detail: err.to_string() })?;
        let found = rows
            .iter()
            .find(|(from, table, _)| from == column && table == parent)
            .map(|(_, _, action)| action.as_str());
        match found {
            Some(action) if action == on_delete => {}
            other => {
                return Err(SourceSchemaError::ShapeDrift {
                    name: child,
                    detail: format!(
                        "foreign key {column} references {parent} with delete action {other:?}, \
                         expected {on_delete:?}"
                    ),
                });
            }
        }
    }

    Ok(())
}

fn verify_table_columns<R: SourceSchemaRead>(
    read: &R,
    table: &'static str,
    expected: &[ColumnShape],
) -> Result<(), SourceSchemaError> {
    let rows: Vec<(String, bool, u8)> = read
        .read_all(&format!("PRAGMA table_info({table})"), &[], |row| {
            let name: String = row.get_typed(1)?;
            let notnull: i64 = row.get_typed(3)?;
            let pk: i64 = row.get_typed(5)?;
            Ok((name, notnull != 0, u8::try_from(pk).unwrap_or(0)))
        })
        .map_err(|err| SourceSchemaError::Inaccessible { detail: err.to_string() })?;

    if rows.len() != expected.len() {
        return Err(SourceSchemaError::ShapeDrift {
            name: table,
            detail: format!("column count {} != {}", rows.len(), expected.len()),
        });
    }
    for (got, want) in rows.iter().zip(expected.iter()) {
        if got.0 != want.0 || got.1 != want.1 || got.2 != want.2 {
            return Err(SourceSchemaError::ShapeDrift {
                name: table,
                detail: format!(
                    "column {:?} (notnull={}, pk={}) != expected {:?} (notnull={}, pk={})",
                    got.0, got.1, got.2, want.0, want.1, want.2
                ),
            });
        }
    }
    Ok(())
}

fn verify_named_indexes<R: SourceSchemaRead>(
    read: &R,
    table: &'static str,
) -> Result<(), SourceSchemaError> {
    // `origin = 'c'` selects the explicitly `CREATE INDEX`-ed ones; the
    // UNIQUE table constraints surface as `origin = 'u'` and are pinned by the
    // DDL-text check above.
    let rows: Vec<(String, bool, bool)> = read
        .read_all(&format!("PRAGMA index_list({table})"), &[], |row| {
            let name: String = row.get_typed(1)?;
            let unique: i64 = row.get_typed(2)?;
            let partial: i64 = row.get_typed(4)?;
            Ok((name, unique != 0, partial != 0))
        })
        .map_err(|err| SourceSchemaError::Inaccessible { detail: err.to_string() })?;

    // `PRAGMA index_list` reports newest-first, so compare by name rather than
    // by position: the frozen order lives in `SOURCE_NAMED_INDEX_KEYS`.
    let created: Vec<(String, bool, bool)> =
        rows.into_iter().filter(|(name, _, _)| !name.starts_with("sqlite_autoindex_")).collect();

    if created.len() != SOURCE_NAMED_INDEXES.len() {
        return Err(SourceSchemaError::ShapeDrift {
            name: table,
            detail: format!(
                "created index count {} != {}",
                created.len(),
                SOURCE_NAMED_INDEXES.len()
            ),
        });
    }
    for (name, unique, partial) in SOURCE_NAMED_INDEXES {
        let found = created.iter().find(|(got, _, _)| got == name);
        match found {
            Some((_, got_unique, got_partial))
                if *got_unique == *unique && *got_partial == *partial => {}
            other => {
                return Err(SourceSchemaError::ShapeDrift {
                    name: table,
                    detail: format!(
                        "index {name:?} (unique={:?}, partial={:?}) != expected (unique={unique}, \
                         partial={partial})",
                        other.map(|(_, got_unique, _)| *got_unique),
                        other.map(|(_, _, got_partial)| *got_partial),
                    ),
                });
            }
        }
    }

    for (index, keys) in SOURCE_NAMED_INDEX_KEYS {
        let columns: Vec<String> = read
            .read_all(&format!("PRAGMA index_xinfo({index})"), &[], |row| {
                let name: Option<String> = row.get_typed(2)?;
                let key: i64 = row.get_typed(5)?;
                Ok((name, key))
            })
            .map_err(|err| SourceSchemaError::Inaccessible { detail: err.to_string() })?
            .into_iter()
            .filter(|(_, key)| *key != 0)
            .map(|(name, _)| name.unwrap_or_default())
            .collect();
        let expected: Vec<String> = keys.iter().map(|key| (*key).to_string()).collect();
        if columns != expected {
            return Err(SourceSchemaError::ShapeDrift {
                name: index,
                detail: format!("key columns {columns:?} != expected {expected:?}"),
            });
        }
    }

    Ok(())
}

// =============================================================================
// Canonical encoding core (§4, §5, §12)
// =============================================================================

/// Append one JSON string literal using the contract's escape rule (§4):
/// `"` → `\"`, `\` → `\\`, U+0000–U+001F via the short forms `\b`, `\f`, `\n`,
/// `\r`, `\t` or lowercase `\u00xx`, and every other code point written as
/// raw UTF-8. No Unicode normalization is ever applied.
pub(crate) fn write_json_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{000c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            ch if (ch as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", ch as u32).as_bytes());
            }
            ch => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Append one JSON string holding the decimal rendering of `value` (§4: every
/// `u64` is a quoted decimal string, never a JSON number). Used where a count
/// is written into a raw nested array rather than through [`CanonicalTuple`].
pub(crate) fn write_json_decimal(out: &mut Vec<u8>, value: u64) {
    write_json_string(out, &value.to_string());
}

/// Compact canonical-JSON tuple writer for the frozen digest inputs (§4).
///
/// Elements are appended in order; `finish` closes the array. Numbers on the
/// public API are written as quoted decimal strings except where the contract
/// explicitly keeps them as JSON integers ([`Self::json_int`], used only by
/// `projection_key/1`).
#[derive(Debug, Default)]
pub(crate) struct CanonicalTuple {
    buf: Vec<u8>,
    first: bool,
    open: bool,
}

impl CanonicalTuple {
    /// Start a compact JSON array.
    pub(crate) fn new() -> Self {
        Self { buf: vec![b'['], first: true, open: true }
    }

    fn sep(&mut self) {
        if !self.first {
            self.buf.push(b',');
        }
        self.first = false;
    }

    /// Append an already-encoded compact JSON value (from a nested writer).
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.sep();
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Append a JSON string with the contract escape rule.
    pub(crate) fn str(&mut self, text: &str) -> &mut Self {
        self.sep();
        write_json_string(&mut self.buf, text);
        self
    }

    /// Append an unsigned decimal *string* (never a JSON number).
    pub(crate) fn dec(&mut self, value: u64) -> &mut Self {
        self.sep();
        write_json_string(&mut self.buf, &value.to_string());
        self
    }

    /// Append a signed decimal *string* (never a JSON number).
    pub(crate) fn idec(&mut self, value: i64) -> &mut Self {
        self.sep();
        write_json_string(&mut self.buf, &value.to_string());
        self
    }

    /// Append a JSON boolean.
    pub(crate) fn boolean(&mut self, value: bool) -> &mut Self {
        self.sep();
        self.buf.extend_from_slice(if value { b"true" } else { b"false" });
        self
    }

    /// Append a JSON `null`.
    pub(crate) fn null(&mut self) -> &mut Self {
        self.sep();
        self.buf.extend_from_slice(b"null");
        self
    }

    /// Append a decimal string or `null` for an optional unsigned value.
    pub(crate) fn opt_dec(&mut self, value: Option<u64>) -> &mut Self {
        match value {
            Some(value) => self.dec(value),
            None => self.null(),
        }
    }

    /// Append a decimal string or `null` for an optional signed value.
    pub(crate) fn opt_idec(&mut self, value: Option<i64>) -> &mut Self {
        match value {
            Some(value) => self.idec(value),
            None => self.null(),
        }
    }

    /// Append a string or `null`.
    pub(crate) fn opt_str(&mut self, value: Option<&str>) -> &mut Self {
        match value {
            Some(value) => self.str(value),
            None => self.null(),
        }
    }

    /// Append a 64-character lowercase hex SHA-256 digest or `null`.
    pub(crate) fn opt_sha_hex(&mut self, value: Option<&Sha256Digest>) -> &mut Self {
        match value {
            Some(value) => self.str(value.hex().as_str()),
            None => self.null(),
        }
    }

    /// Append a raw JSON integer (`projection_key/1` is the only contract site
    /// that writes integers directly).
    pub(crate) fn json_int(&mut self, value: i64) -> &mut Self {
        self.sep();
        self.buf.extend_from_slice(value.to_string().as_bytes());
        self
    }

    /// Append an optional raw JSON integer.
    pub(crate) fn opt_json_int(&mut self, value: Option<i64>) -> &mut Self {
        match value {
            Some(value) => self.json_int(value),
            None => self.null(),
        }
    }

    /// Close the array and return the compact UTF-8 bytes. Takes `&mut self`
    /// so the writer can be chained directly on a temporary
    /// (`CanonicalTuple::new().str(..).dec(..).finish()`).
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        self.buf.push(b']');
        self.open = false;
        std::mem::take(&mut self.buf)
    }

    /// Close the array and return its SHA-256.
    pub(crate) fn finish_sha(&mut self) -> Sha256Digest {
        Sha256Digest::of(&self.finish())
    }
}

/// A 32-byte SHA-256 digest with the persisted lowercase-hex rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

/// Digests ride the MessagePack envelopes as raw 32-byte `bin` values, not as
/// hex strings or as a 32-element integer array, so the stored bytes match the
/// SHA columns exactly.
impl serde::Serialize for Sha256Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Sha256Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DigestVisitor;

        impl<'de> serde::de::Visitor<'de> for DigestVisitor {
            type Value = Sha256Digest;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("32 raw SHA-256 bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                Sha256Digest::from_slice(bytes)
                    .ok_or_else(|| E::custom("digest is not exactly 32 bytes"))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = [0u8; 32];
                for slot in bytes.iter_mut() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("digest shorter than 32 bytes"))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::custom("digest longer than 32 bytes"));
                }
                Ok(Sha256Digest(bytes))
            }
        }

        deserializer.deserialize_bytes(DigestVisitor)
    }
}

impl Sha256Digest {
    /// Hash a byte slice.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    /// Hash the concatenation of two slices, without an intermediate buffer.
    #[must_use]
    pub fn of_two(a: &[u8], b: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(a);
        hasher.update(b);
        Self(hasher.finalize().into())
    }

    /// The raw 32 bytes, as persisted in a SHA column.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Rebuild from a column read that must be exactly 32 bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let array: [u8; 32] = bytes.try_into().ok()?;
        Some(Self(array))
    }

    /// 64-character lowercase hex.
    #[must_use]
    pub fn hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// Parse a 64-character lowercase/uppercase hex string.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(chunk).ok()?;
            bytes[index] = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

/// `stream_root(domain, leaves, footer)` (§4): the domain bytes, then each
/// leaf length-prefixed with an 8-byte big-endian length, then the footer leaf
/// the same way. An empty set still writes the footer.
pub(crate) fn stream_root(domain: &str, leaves: &[Vec<u8>], footer: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    for leaf in leaves {
        hasher.update((leaf.len() as u64).to_be_bytes());
        hasher.update(leaf);
    }
    hasher.update((footer.len() as u64).to_be_bytes());
    hasher.update(footer);
    Sha256Digest(hasher.finalize().into())
}

// =============================================================================
// Stream domains, leaf encodings and roots (§4, §5, §9, §10, §12)
// =============================================================================

/// Root domain of the record-semantic stream (§5).
pub const SOURCE_SEMANTIC_RECORDS_ROOT_DOMAIN: &str = "cass.source-semantic-records-root/1";
/// Leaf domain of a record-semantic leaf.
pub const SOURCE_RECORD_SEMANTIC_DOMAIN: &str = "cass.source-record-semantic/1";
/// Root domain of the claims stream.
pub const SOURCE_CLAIMS_ROOT_DOMAIN: &str = "cass.source-claims-root/1";
/// Leaf domain of a claim leaf.
pub const SOURCE_CLAIM_DOMAIN: &str = "cass.source-claim/1";
/// Root domain of the installed-records stream.
pub const SOURCE_INSTALLED_RECORDS_ROOT_DOMAIN: &str = "cass.source-installed-records-root/1";
/// Leaf domain of an installed-record leaf.
pub const SOURCE_RECORD_INSTALLED_DOMAIN: &str = "cass.source-record-installed/1";
/// Root domain of the witness-binding stream.
pub const SOURCE_BINDINGS_ROOT_DOMAIN: &str = "cass.source-bindings-root/1";
/// Leaf domain of a witness-binding leaf.
pub const SOURCE_BINDING_DOMAIN: &str = "cass.source-binding/1";

/// Top-level semantic-request tuple domain (§5).
/// Root domain of the expected framing stream (v0.4 §17.2, unchanged).
pub const SOURCE_FRAMING_DOMAIN: &str = "cass.source-framing/1";
/// The verifier identity every independently produced manifest carries.
pub const SOURCE_VERIFIER_VERSION: &str = "cass.source-verifier/1";
/// Domain of the bounded expected-manifest header (§20.1).
pub const SOURCE_EXPECTED_MANIFEST_DOMAIN: &str = "cass.source-expected-manifest/1";
/// The fixed element count of the expected-manifest header (§20.1).
pub const EXPECTED_MANIFEST_HEADER_LEN: usize = 15;

pub const SOURCE_SEMANTIC_REQUEST_DOMAIN: &str = "cass.source-semantic-request/1";
/// Top-level installation tuple domain (§5).
pub const SOURCE_INSTALLATION_DOMAIN: &str = "cass.source-installation/1";
/// Canonical array domain for one original installation (§5).
pub const SOURCE_ORIGINAL_INSTALLATION_DOMAIN: &str = "cass.source-original-installation/1";
/// Canonical array domain for one original binding (§5).
pub const SOURCE_ORIGINAL_BINDING_DOMAIN: &str = "cass.source-original-binding/1";
/// Canonical array domain for one winner-rejection evidence (§9).
pub const SOURCE_WINNER_REJECTION_DOMAIN: &str = "cass.source-winner-rejection/1";
/// Canonical array domain for one safe position (§10).
pub const SOURCE_SAFE_POSITION_DOMAIN: &str = "cass.source-safe-position/1";
/// Canonical array domain for one safe diagnostic (§10).
pub const SOURCE_DIAGNOSTIC_DOMAIN: &str = "cass.source-diagnostic/1";
/// Canonical array domain for one record locator (§10).
pub const SOURCE_RECORD_LOCATOR_DOMAIN: &str = "cass.source-record-locator/1";
/// Canonical tuple domain for the finish measurement (§10).
pub const SOURCE_FINISH_DOMAIN: &str = "cass.source-finish/1";
/// Canonical array domain for `projection_key/1` (§12).
pub const SOURCE_PROJECTION_DOMAIN: &str = "cass.source-projection/1";
/// Receipt-key tuple domain (§12).
pub const SOURCE_RECEIPT_KEY_DOMAIN: &str = "cass.source-receipt-key/1";
/// Failure-publication digest domain (§10).
pub const SOURCE_FAILURE_PUBLICATION_DOMAIN: &str = "cass.source-failure-publication/1";
/// Pending-claim digest domain (§19).
pub const SOURCE_PENDING_CLAIM_DOMAIN: &str = "cass.source-pending-claim/1";
/// Receipt `operation` column value (§12).
pub const SOURCE_ACTIVATION_OPERATION: &str = "source_input_activation_v1";
/// Receipt `state` column value (§12).
pub const SOURCE_ACTIVATION_STATE: &str = "committed";
/// Prefix of the deterministic activation receipt key (§12).
pub const SOURCE_RECEIPT_KEY_PREFIX: &str = "source-input-v1:";

// --- state domains -----------------------------------------------------------

/// Wire/leaf spelling of a record's frame state (mirrors the SQL column).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameState {
    FramePending,
    Staged,
    Activated,
}

impl FrameState {
    /// SQL/leaf literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FramePending => "frame_pending",
            Self::Staged => "staged",
            Self::Activated => "activated",
        }
    }
}

/// Record-level claim aggregate (mirrors `source_records.record_mapping_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordMappingState {
    ClaimsPending,
    NoClaims,
    AllCanonical,
    AllStandalone,
    AllUnmapped,
    Mixed,
}

impl RecordMappingState {
    /// SQL/leaf literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaimsPending => "claims_pending",
            Self::NoClaims => "no_claims",
            Self::AllCanonical => "all_canonical",
            Self::AllStandalone => "all_standalone",
            Self::AllUnmapped => "all_unmapped",
            Self::Mixed => "mixed",
        }
    }
}

/// Claim-level target (a different concept from [`RecordMappingState`], §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClaimMappingState {
    Canonical,
    Standalone,
    Unmapped,
}

impl ClaimMappingState {
    /// SQL/leaf literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Standalone => "standalone",
            Self::Unmapped => "unmapped",
        }
    }
}

/// Closed evidence-kind domain (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EvidenceKind {
    Prose,
    ToolCall,
    ToolResult,
    Reasoning,
    NoMessage,
    ParseFailed,
}

impl EvidenceKind {
    /// SQL/leaf literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prose => "prose",
            Self::ToolCall => "tool_call",
            Self::ToolResult => "tool_result",
            Self::Reasoning => "reasoning",
            Self::NoMessage => "no_message",
            Self::ParseFailed => "parse_failed",
        }
    }
}

/// Parse state of one staged record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseState {
    Pending,
    Parsed,
    ParseFailed,
}

impl ParseState {
    /// SQL/leaf literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Parsed => "parsed",
            Self::ParseFailed => "parse_failed",
        }
    }
}

/// Safety state of one staged record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyState {
    Pending,
    Preserved,
    Blocked,
}

impl SafetyState {
    /// SQL/leaf literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Preserved => "preserved",
            Self::Blocked => "blocked",
        }
    }
}

/// Retention state of one staged record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionState {
    PayloadAbsent,
    PayloadPresent,
}

impl RetentionState {
    /// SQL/leaf literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PayloadAbsent => "payload_absent",
            Self::PayloadPresent => "payload_present",
        }
    }
}

/// Installation class of one original installation (§9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InstallationClass {
    CanonicalBound,
    UnresolvedNoBinding,
    StandaloneNoBinding,
    UnmappedNoBinding,
    WinnerRejectedNoBinding,
}

impl InstallationClass {
    /// Canonical array literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalBound => "CanonicalBound",
            Self::UnresolvedNoBinding => "UnresolvedNoBinding",
            Self::StandaloneNoBinding => "StandaloneNoBinding",
            Self::UnmappedNoBinding => "UnmappedNoBinding",
            Self::WinnerRejectedNoBinding => "WinnerRejectedNoBinding",
        }
    }

    /// Fixed footer order (§5, §7): the binding footer's last five counters.
    #[must_use]
    pub const fn footer_order() -> [Self; 5] {
        [
            Self::CanonicalBound,
            Self::UnresolvedNoBinding,
            Self::StandaloneNoBinding,
            Self::UnmappedNoBinding,
            Self::WinnerRejectedNoBinding,
        ]
    }
}

/// Outcome of one original binding (§9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OriginalBindingOutcome {
    AcceptedNew,
    VerifiedReplay,
}

impl OriginalBindingOutcome {
    /// Canonical array literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedNew => "AcceptedNew",
            Self::VerifiedReplay => "VerifiedReplay",
        }
    }
}

/// Storage kind of a bound message's extra payload (§9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExtraStorageKind {
    HistoricalJson,
    MsgPack,
    Null,
}

impl ExtraStorageKind {
    /// Canonical array literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HistoricalJson => "HistoricalJson",
            Self::MsgPack => "MsgPack",
            Self::Null => "Null",
        }
    }
}

/// The closed field-name domain of the two [`ReplayRejectReason`] variants that
/// carry a field (§20.3).
///
/// It is exactly the union of the [`ReplayCandidateMatch`] and
/// [`StoredBindingEvidence`] field names, in the contract's order. The domain
/// is a closed Rust type rather than a `String`, so a drifted or hostile value
/// cannot widen it: an unknown name is a decode failure, not a new variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplayRejectField {
    CreatedAt,
    Role,
    Author,
    ContentHash,
    Outcome,
    ConversationId,
    ConversationIdentityDigest,
    StoredIdx,
    OriginalMessageId,
    StoredMergeFingerprint,
    SafeContentSha256,
    ExtraStorageKind,
    ExtraJsonSha256,
    ExtraBinSha256,
    ExtraSemanticDigest,
    ExcludedSemanticDigest,
}

impl ReplayRejectField {
    /// Every member, in the contract's fixed order (§20.3).
    pub const ALL: [Self; 16] = [
        Self::CreatedAt,
        Self::Role,
        Self::Author,
        Self::ContentHash,
        Self::Outcome,
        Self::ConversationId,
        Self::ConversationIdentityDigest,
        Self::StoredIdx,
        Self::OriginalMessageId,
        Self::StoredMergeFingerprint,
        Self::SafeContentSha256,
        Self::ExtraStorageKind,
        Self::ExtraJsonSha256,
        Self::ExtraBinSha256,
        Self::ExtraSemanticDigest,
        Self::ExcludedSemanticDigest,
    ];

    /// The persisted and canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Role => "role",
            Self::Author => "author",
            Self::ContentHash => "content_hash",
            Self::Outcome => "outcome",
            Self::ConversationId => "conversation_id",
            Self::ConversationIdentityDigest => "conversation_identity_digest",
            Self::StoredIdx => "stored_idx",
            Self::OriginalMessageId => "original_message_id",
            Self::StoredMergeFingerprint => "stored_merge_fingerprint",
            Self::SafeContentSha256 => "safe_content_sha256",
            Self::ExtraStorageKind => "extra_storage_kind",
            Self::ExtraJsonSha256 => "extra_json_sha256",
            Self::ExtraBinSha256 => "extra_bin_sha256",
            Self::ExtraSemanticDigest => "extra_semantic_digest",
            Self::ExcludedSemanticDigest => "excluded_semantic_digest",
        }
    }

    /// Resolve a persisted name. Anything outside the closed domain is `None`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.as_str() == name)
    }
}

impl serde::Serialize for ReplayRejectField {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ReplayRejectField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldVisitor;

        impl serde::de::Visitor<'_> for FieldVisitor {
            type Value = ReplayRejectField;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one of the closed ReplayRejectReason field names")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                ReplayRejectField::from_name(value)
                    .ok_or_else(|| E::custom(format!("unknown replay-reject field: {value}")))
            }
        }

        deserializer.deserialize_str(FieldVisitor)
    }
}

/// Why a replay candidate was refused (§10).
///
/// The two field-carrying variants name a [`ReplayRejectField`], never a free
/// string, so the field domain cannot be widened at a call site. The persisted
/// form is a MessagePack map with exactly the keys `tag` and `field` (§20.3);
/// unknown or duplicate keys, a missing key, a wrong type, a future tag and
/// trailing bytes are all decode failures rather than a new reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRejectReason {
    NoMatchingStoredRow,
    AmbiguousStoredRows,
    StoredFactMismatch(ReplayRejectField),
    WinnerRejected,
    InvalidStoredEvidence(ReplayRejectField),
}

/// The five `tag` values, as their own closed type so an unknown tag is a
/// decode failure before any conversion runs.
///
/// The decoder accepts a *string* only. A derived enum would also accept an
/// integer variant index, which is a different persisted shape from the one
/// §20.3 freezes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayRejectTag {
    NoMatchingStoredRow,
    AmbiguousStoredRows,
    StoredFactMismatch,
    WinnerRejected,
    InvalidStoredEvidence,
}

impl ReplayRejectTag {
    /// Every member, in the contract's order.
    const ALL: [Self; 5] = [
        Self::NoMatchingStoredRow,
        Self::AmbiguousStoredRows,
        Self::StoredFactMismatch,
        Self::WinnerRejected,
        Self::InvalidStoredEvidence,
    ];

    /// The persisted name.
    const fn as_str(self) -> &'static str {
        match self {
            Self::NoMatchingStoredRow => "NoMatchingStoredRow",
            Self::AmbiguousStoredRows => "AmbiguousStoredRows",
            Self::StoredFactMismatch => "StoredFactMismatch",
            Self::WinnerRejected => "WinnerRejected",
            Self::InvalidStoredEvidence => "InvalidStoredEvidence",
        }
    }

    /// Resolve a persisted name. Anything outside the closed set is `None`.
    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tag| tag.as_str() == name)
    }
}

impl serde::Serialize for ReplayRejectTag {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ReplayRejectTag {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TagVisitor;

        impl serde::de::Visitor<'_> for TagVisitor {
            type Value = ReplayRejectTag;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one of the five frozen replay-reject tags")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                ReplayRejectTag::from_name(value)
                    .ok_or_else(|| E::custom(format!("unknown replay-reject tag: {value}")))
            }
        }

        deserializer.deserialize_str(TagVisitor)
    }
}

/// The two persisted keys, as their own closed type so an unknown key is a
/// decode failure rather than an ignored member. Like the tag, the key decoder
/// accepts a string only.
#[derive(Debug, Clone, Copy)]
enum ReplayRejectReasonKey {
    Tag,
    Field,
}

impl<'de> serde::Deserialize<'de> for ReplayRejectReasonKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyVisitor;

        impl serde::de::Visitor<'_> for KeyVisitor {
            type Value = ReplayRejectReasonKey;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("the key tag or field")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "tag" => Ok(ReplayRejectReasonKey::Tag),
                    "field" => Ok(ReplayRejectReasonKey::Field),
                    other => Err(E::custom(format!("unknown replay-reject key: {other}"))),
                }
            }
        }

        deserializer.deserialize_str(KeyVisitor)
    }
}

impl ReplayRejectReason {
    /// The persisted `tag` value.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::NoMatchingStoredRow => "NoMatchingStoredRow",
            Self::AmbiguousStoredRows => "AmbiguousStoredRows",
            Self::StoredFactMismatch(_) => "StoredFactMismatch",
            Self::WinnerRejected => "WinnerRejected",
            Self::InvalidStoredEvidence(_) => "InvalidStoredEvidence",
        }
    }

    /// The persisted `field` value: `Some` only for the two field-carrying
    /// variants, `None` (persisted as nil) for the other three.
    #[must_use]
    pub const fn field(self) -> Option<ReplayRejectField> {
        match self {
            Self::StoredFactMismatch(field) | Self::InvalidStoredEvidence(field) => Some(field),
            Self::NoMatchingStoredRow | Self::AmbiguousStoredRows | Self::WinnerRejected => None,
        }
    }

    /// Canonical array literal, generated from the closed decoded type — never
    /// from `Debug` (§20.3). A reason is absent as JSON `null` at the caller
    /// ([`OriginalInstallation::encode`]), not as a string here.
    #[must_use]
    pub fn as_str(self) -> String {
        match self.field() {
            Some(field) => format!("{}{{{}}}", self.tag(), field.as_str()),
            None => self.tag().to_string(),
        }
    }

    /// Build from a strictly decoded `(tag, field)` pair, enforcing the
    /// pairing rule: the two field-carrying tags require a field, the other
    /// three require nil.
    fn from_wire(
        tag: ReplayRejectTag,
        field: Option<ReplayRejectField>,
    ) -> Result<Self, SourceCodecError> {
        match (tag, field) {
            (ReplayRejectTag::StoredFactMismatch, Some(field)) => {
                Ok(Self::StoredFactMismatch(field))
            }
            (ReplayRejectTag::InvalidStoredEvidence, Some(field)) => {
                Ok(Self::InvalidStoredEvidence(field))
            }
            (ReplayRejectTag::StoredFactMismatch | ReplayRejectTag::InvalidStoredEvidence, None) => {
                Err(SourceCodecError::InvalidEnvelope)
            }
            (
                ReplayRejectTag::NoMatchingStoredRow
                | ReplayRejectTag::AmbiguousStoredRows
                | ReplayRejectTag::WinnerRejected,
                Some(_),
            ) => Err(SourceCodecError::InvalidEnvelope),
            (ReplayRejectTag::NoMatchingStoredRow, None) => Ok(Self::NoMatchingStoredRow),
            (ReplayRejectTag::AmbiguousStoredRows, None) => Ok(Self::AmbiguousStoredRows),
            (ReplayRejectTag::WinnerRejected, None) => Ok(Self::WinnerRejected),
        }
    }
}

impl serde::Serialize for ReplayRejectReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("tag", self.tag())?;
        map.serialize_entry("field", &self.field())?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for ReplayRejectReason {
    /// A hand-written map decoder rather than a derived struct: a derived
    /// struct silently defaults a missing `Option` member to `None`, which
    /// would accept a one-key map even though the persisted form is exactly
    /// `tag` plus `field` (§20.3). This decoder requires both keys, refuses an
    /// unknown or repeated key, and only then applies the pairing rule.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ReasonVisitor;

        impl<'de> serde::de::Visitor<'de> for ReasonVisitor {
            type Value = ReplayRejectReason;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map with exactly the keys tag and field")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut tag: Option<ReplayRejectTag> = None;
                let mut field: Option<Option<ReplayRejectField>> = None;
                while let Some(key) = map.next_key::<ReplayRejectReasonKey>()? {
                    match key {
                        ReplayRejectReasonKey::Tag => {
                            if tag.is_some() {
                                return Err(serde::de::Error::custom("repeated tag key"));
                            }
                            tag = Some(map.next_value()?);
                        }
                        ReplayRejectReasonKey::Field => {
                            if field.is_some() {
                                return Err(serde::de::Error::custom("repeated field key"));
                            }
                            field = Some(map.next_value()?);
                        }
                    }
                }
                let tag = tag.ok_or_else(|| serde::de::Error::missing_field("tag"))?;
                let field = field.ok_or_else(|| serde::de::Error::missing_field("field"))?;
                ReplayRejectReason::from_wire(tag, field).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_map(ReasonVisitor)
    }
}

/// Encode one reason in its persisted nested form (§20.3): a MessagePack map
/// with exactly the keys `tag` and `field`, in that order.
///
/// # Errors
/// Only when the writer itself fails.
pub fn encode_replay_reject_reason(
    reason: ReplayRejectReason,
) -> Result<Vec<u8>, SourceInstallError> {
    encode_envelope(&reason)
}

/// Strictly decode one persisted reason, including the trailing-byte rule a
/// nested value inside a larger envelope cannot check by itself.
///
/// # Errors
/// Any shape outside the frozen map — unknown or duplicate keys, a missing
/// key, a wrong type, a future tag, a mismatched `field`, or trailing bytes.
pub fn decode_replay_reject_reason(bytes: &[u8]) -> Result<ReplayRejectReason, SourceInstallError> {
    decode_envelope(bytes)
}

/// Projection disposition of one activation request (§10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionDisposition {
    Ready,
    WholeInputRejected,
}

impl ProjectionDisposition {
    /// Canonical array literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::WholeInputRejected => "WholeInputRejected",
        }
    }
}

/// Requested terminal state of one activation request (§10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalState {
    Complete,
    Partial,
    Failed,
}

impl TerminalState {
    /// Canonical array literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "Complete",
            Self::Partial => "Partial",
            Self::Failed => "Failed",
        }
    }
}

// --- canonical value types ---------------------------------------------------

/// `[sha256_hex, count_decimal]` — an expanded root, never a pseudo-object (§10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Root {
    pub sha256: Sha256Digest,
    pub count: u64,
}

impl Root {
    /// Encode the canonical two-element array.
    #[must_use]
    pub fn to_array(&self) -> Vec<u8> {
        CanonicalTuple::new().str(&self.sha256.hex()).dec(self.count).finish()
    }
}

/// A 64-bit big-endian value as persisted in a `length(col)=8` BLOB column.
#[must_use]
pub fn u64_be8(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// A signed 64-bit big-endian value as persisted in a `length(col)=8` BLOB
/// column. The source-aware integer columns are unsigned by contract, but the
/// helper keeps the byte order explicit for readability at call sites.
#[must_use]
pub fn i64_be8(value: i64) -> [u8; 8] {
    value.to_be_bytes()
}

/// One step of a safe position's index path (§10).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IndexStep {
    ObjectMember(u64),
    ArrayElement(u64),
}

impl IndexStep {
    /// Canonical two-element array (the `index` is a decimal string).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (tag, index) = match self {
            Self::ObjectMember(index) => ("object_member", *index),
            Self::ArrayElement(index) => ("array_element", *index),
        };
        CanonicalTuple::new().str(tag).dec(index).finish()
    }
}

/// A safe position inside the lossless source tree (§10).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SafePosition {
    pub index_path: Vec<IndexStep>,
    pub original_pointer_sha256: Sha256Digest,
    pub safe_pointer: Option<String>,
}

impl SafePosition {
    /// Encode the domain-tagged four-element tuple (§10, §19: every hash object
    /// uses this tagged form, never a bare three-element variant).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut tuple = CanonicalTuple::new();
        tuple.str(SOURCE_SAFE_POSITION_DOMAIN);
        let mut path = Vec::new();
        path.push(b'[');
        for (position, step) in self.index_path.iter().enumerate() {
            if position > 0 {
                path.push(b',');
            }
            path.extend_from_slice(&step.encode());
        }
        path.push(b']');
        tuple.raw(&path);
        tuple.str(&self.original_pointer_sha256.hex());
        tuple.opt_str(self.safe_pointer.as_deref());
        tuple.finish()
    }
}

/// A sanitisation diagnostic attached to a staged record (§10).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SafeDiagnostic {
    pub code: String,
    pub detail: Option<String>,
    pub offset: Option<u64>,
    pub position: Option<SafePosition>,
}

impl SafeDiagnostic {
    /// Encode the domain-tagged five-element tuple.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut tuple = CanonicalTuple::new();
        tuple.str(SOURCE_DIAGNOSTIC_DOMAIN);
        tuple.str(&self.code);
        tuple.opt_str(self.detail.as_deref());
        tuple.opt_dec(self.offset);
        match &self.position {
            Some(position) => tuple.raw(&position.encode()),
            None => tuple.null(),
        };
        tuple.finish()
    }
}

/// One record's locale inside its source input (§10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRecordLocator {
    pub ordinal: u64,
    pub record_pointer: String,
    pub byte_start: u64,
    pub byte_end: u64,
}

impl SourceRecordLocator {
    /// Encode the domain-tagged five-element tuple (§10).
    ///
    /// This is the standalone form, used where a locator is hashed on its own.
    /// It is **not** what §5's semantic leaf and §20.6's `position_bin` carry:
    /// both embed the untagged four-element array, which [`Self::to_array`]
    /// produces.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut tuple = CanonicalTuple::new();
        tuple.str(SOURCE_RECORD_LOCATOR_DOMAIN);
        tuple.dec(self.ordinal);
        tuple.str(&self.record_pointer);
        tuple.dec(self.byte_start);
        tuple.dec(self.byte_end);
        tuple.finish()
    }

    /// Encode the untagged four-element array §5 and §20.6 freeze:
    /// `[ordinal_decimal, record_pointer, byte_start_decimal, byte_end_decimal]`.
    #[must_use]
    pub fn to_array(&self) -> Vec<u8> {
        let mut tuple = CanonicalTuple::new();
        tuple.dec(self.ordinal);
        tuple.str(&self.record_pointer);
        tuple.dec(self.byte_start);
        tuple.dec(self.byte_end);
        tuple.finish()
    }
}

/// The four-field merge fingerprint carried by every binding (§9).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MergeFingerprint {
    pub idx: i64,
    pub created_at: Option<i64>,
    pub role: String,
    pub author: Option<String>,
    pub content_blake3_hex: String,
}

impl MergeFingerprint {
    /// Encode the five-element array.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut tuple = CanonicalTuple::new();
        tuple.idec(self.idx);
        tuple.opt_idec(self.created_at);
        tuple.str(&self.role);
        tuple.opt_str(self.author.as_deref());
        tuple.str(&self.content_blake3_hex);
        tuple.finish()
    }
}

/// The original binding of one canonical claim to a stored message (§9).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OriginalBinding {
    pub outcome: OriginalBindingOutcome,
    pub original_conversation_id: i64,
    pub original_message_id: i64,
    pub stored_idx: i64,
    pub stored_merge_fingerprint: MergeFingerprint,
    pub safe_content_sha256: Sha256Digest,
    pub extra_storage_kind: ExtraStorageKind,
    pub extra_json_sha256: Option<Sha256Digest>,
    pub extra_bin_sha256: Option<Sha256Digest>,
    pub extra_semantic_digest: Option<Sha256Digest>,
    pub excluded_semantic_digest: Option<Sha256Digest>,
    pub conversation_identity_digest: Sha256Digest,
}

impl OriginalBinding {
    /// Encode the canonical `cass.source-original-binding/1` array (§5).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut tuple = CanonicalTuple::new();
        tuple.str(SOURCE_ORIGINAL_BINDING_DOMAIN);
        tuple.str(self.outcome.as_str());
        tuple.idec(self.original_conversation_id);
        tuple.idec(self.original_message_id);
        tuple.idec(self.stored_idx);
        tuple.raw(&self.stored_merge_fingerprint.encode());
        tuple.str(&self.safe_content_sha256.hex());
        tuple.str(self.extra_storage_kind.as_str());
        tuple.opt_sha_hex(self.extra_json_sha256.as_ref());
        tuple.opt_sha_hex(self.extra_bin_sha256.as_ref());
        tuple.opt_sha_hex(self.extra_semantic_digest.as_ref());
        tuple.opt_sha_hex(self.excluded_semantic_digest.as_ref());
        tuple.str(&self.conversation_identity_digest.hex());
        tuple.finish()
    }
}

/// The evidence that an incoming message was refused because an existing row
/// already holds its `idx` with a different fingerprint (§9).
///
/// `conversation_identity_digest` is the parent conversation identity the
/// rejection was taken against. It is a required member here rather than an
/// argument to [`Self::encode`], because the canonical array has to be
/// re-derivable from the persisted witness alone: without it a stored
/// rejection could never be re-hashed after its winner row is gone.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WinnerRejectionEvidence {
    pub claim_digest: Sha256Digest,
    pub conversation_identity_digest: Sha256Digest,
    pub incoming_idx: i64,
    pub incoming_merge_fingerprint: MergeFingerprint,
    pub winner_conversation_id: i64,
    pub winner_message_id: i64,
    pub winner_idx: i64,
    pub winner_merge_fingerprint: MergeFingerprint,
}

impl WinnerRejectionEvidence {
    /// Encode the canonical `cass.source-winner-rejection/1` array (§9).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut tuple = CanonicalTuple::new();
        tuple.str(SOURCE_WINNER_REJECTION_DOMAIN);
        tuple.str(&self.claim_digest.hex());
        tuple.str(&self.conversation_identity_digest.hex());
        tuple.idec(self.incoming_idx);
        tuple.raw(&self.incoming_merge_fingerprint.encode());
        tuple.idec(self.winner_conversation_id);
        tuple.idec(self.winner_message_id);
        tuple.idec(self.winner_idx);
        tuple.raw(&self.winner_merge_fingerprint.encode());
        tuple.str("cass.merge-existing-idx/1");
        tuple.str("existing_idx_conflict");
        tuple.finish()
    }
}

/// One's claim's original installation: the A-side promise about where the
/// claim's message went, with no dependency on B (§9).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OriginalInstallation {
    pub semantic_request_digest: Sha256Digest,
    pub class: InstallationClass,
    pub binding: Option<OriginalBinding>,
    pub rejection: Option<WinnerRejectionEvidence>,
    pub reason: Option<ReplayRejectReason>,
}

impl OriginalInstallation {
    /// Encode the canonical `cass.source-original-installation/1` array (§5).
    ///
    /// Every piece comes from the installation itself, so the canonical array
    /// is reproducible from a strictly decoded witness with no side channel.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut tuple = CanonicalTuple::new();
        tuple.str(SOURCE_ORIGINAL_INSTALLATION_DOMAIN);
        tuple.str(&self.semantic_request_digest.hex());
        tuple.str(self.class.as_str());
        match &self.binding {
            Some(binding) => tuple.raw(&binding.encode()),
            None => tuple.null(),
        };
        match &self.rejection {
            Some(rejection) => tuple.raw(&rejection.encode()),
            None => tuple.null(),
        };
        match &self.reason {
            Some(reason) => tuple.str(&reason.as_str()),
            None => tuple.null(),
        };
        tuple.finish()
    }
}

/// One claim produced by the mapper (§10).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SourceClaim {
    pub input_key: Sha256Digest,
    pub record_ordinal: u64,
    pub record_pointer: String,
    pub conversation_ordinal: Option<u32>,
    pub final_message_idx: Option<i64>,
    pub positions: Vec<SafePosition>,
    pub projection_pointer: Option<String>,
    pub evidence_kind: EvidenceKind,
    pub mapping_state: ClaimMappingState,
}

impl SourceClaim {
    /// Encode the canonical `cass.source-claim/1` leaf array (§5).
    #[must_use]
    pub fn encode_leaf(&self) -> Vec<u8> {
        let mut tuple = CanonicalTuple::new();
        tuple.str(SOURCE_CLAIM_DOMAIN);
        tuple.str(&self.input_key.hex());
        tuple.dec(self.record_ordinal);
        tuple.str(&self.record_pointer);
        tuple.opt_dec(self.conversation_ordinal.map(u64::from));
        tuple.opt_idec(self.final_message_idx);
        tuple.opt_str(self.projection_pointer.as_deref());
        tuple.str(self.evidence_kind.as_str());
        tuple.str(self.mapping_state.as_str());
        let mut positions = Vec::new();
        positions.push(b'[');
        for (index, position) in self.positions.iter().enumerate() {
            if index > 0 {
                positions.push(b',');
            }
            positions.extend_from_slice(&position.encode());
        }
        positions.push(b']');
        tuple.raw(&positions);
        tuple.finish()
    }

    /// `projection_key/1` (§12): the three targets with the two integers as
    /// exact JSON integers, never through an `f64`.
    #[must_use]
    pub fn projection_key(&self) -> Sha256Digest {
        let mut tuple = CanonicalTuple::new();
        tuple.str(SOURCE_PROJECTION_DOMAIN);
        tuple.opt_json_int(self.conversation_ordinal.map(i64::from));
        tuple.opt_json_int(self.final_message_idx);
        tuple.opt_str(self.projection_pointer.as_deref());
        tuple.finish_sha()
    }

    /// The pending-claim digest stored in `binding_digest` before a real
    /// installation exists (§19).
    #[must_use]
    pub fn pending_claim_digest(&self) -> Sha256Digest {
        let mut tuple = CanonicalTuple::new();
        tuple.str(SOURCE_PENDING_CLAIM_DOMAIN);
        tuple.raw(&self.encode_leaf());
        tuple.finish_sha()
    }
}

/// One staged record as re-read from SQL, in the shape the semantic leaf
/// encodes (§10 `VerifiedStagedRecord`, carried here as plain verified data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedRecordLeafInput {
    pub locator: SourceRecordLocator,
    pub expected_raw_sha256: Sha256Digest,
    pub observed_raw_sha256: Option<Sha256Digest>,
    pub parse_state: ParseState,
    pub record_mapping_state: RecordMappingState,
    pub safety_state: SafetyState,
    pub retention_state: RetentionState,
    pub codec: Option<String>,
    pub payload_bytes_sha256: Option<Sha256Digest>,
    pub safe_value_sha256: Option<Sha256Digest>,
    pub native_ids_semantic_sha256: Option<Sha256Digest>,
    pub diagnostics_semantic_sha256: Option<Sha256Digest>,
}

/// Encode one record-semantic leaf (§5).
#[must_use]
pub fn encode_record_semantic_leaf(
    input_key: &Sha256Digest,
    record: &StagedRecordLeafInput,
) -> Vec<u8> {
    let mut tuple = CanonicalTuple::new();
    tuple.str(SOURCE_RECORD_SEMANTIC_DOMAIN);
    tuple.str(&input_key.hex());
    // §5 embeds the untagged quadruple here, not the domain-tagged tuple.
    tuple.raw(&record.locator.to_array());
    tuple.str(&record.expected_raw_sha256.hex());
    tuple.opt_sha_hex(record.observed_raw_sha256.as_ref());
    tuple.str(record.parse_state.as_str());
    tuple.str(record.record_mapping_state.as_str());
    tuple.str(record.safety_state.as_str());
    tuple.str(record.retention_state.as_str());
    tuple.opt_str(record.codec.as_deref());
    tuple.opt_sha_hex(record.payload_bytes_sha256.as_ref());
    tuple.opt_sha_hex(record.safe_value_sha256.as_ref());
    tuple.opt_sha_hex(record.native_ids_semantic_sha256.as_ref());
    tuple.opt_sha_hex(record.diagnostics_semantic_sha256.as_ref());
    tuple.finish()
}

/// Encode one installed-record leaf (§5): the semantic leaf embedded as a
/// nested array plus the record's actual frame state on the B side.
#[must_use]
pub fn encode_record_installed_leaf(
    semantic_leaf: &[u8],
    actual_frame_state: FrameState,
) -> Vec<u8> {
    let mut tuple = CanonicalTuple::new();
    tuple.str(SOURCE_RECORD_INSTALLED_DOMAIN);
    tuple.raw(semantic_leaf);
    tuple.str(actual_frame_state.as_str());
    tuple.finish()
}

/// Encode one witness-binding leaf (§5): the envelope version, the claim leaf
/// and the canonical original-installation array.
#[must_use]
pub fn encode_binding_leaf(
    envelope_version: u64,
    claim_leaf: &[u8],
    original_installation_array: &[u8],
) -> Vec<u8> {
    let mut tuple = CanonicalTuple::new();
    tuple.str(SOURCE_BINDING_DOMAIN);
    tuple.dec(envelope_version);
    tuple.raw(claim_leaf);
    tuple.raw(original_installation_array);
    tuple.finish()
}

/// One row's finish measurement (§10).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedFinish {
    pub content_digest: Sha256Digest,
    pub bytes_read: u64,
    pub records_seen: u64,
    pub blank_lines: u64,
    pub parse_failed: u64,
    pub mapping_diagnostics: u64,
    pub unprocessed_ranges: Vec<SourceUnprocessedRange>,
    pub reached_eof: bool,
}

/// One contiguous unprocessed input range (§10).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceUnprocessedRange {
    pub start: u64,
    pub end: u64,
    pub reason: String,
    pub ordinal: Option<u64>,
    pub record_pointer: Option<String>,
}

impl VerifiedFinish {
    /// Encode the canonical `cass.source-finish/1` tuple (§10).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut tuple = CanonicalTuple::new();
        tuple.str(SOURCE_FINISH_DOMAIN);
        tuple.str(&self.content_digest.hex());
        tuple.dec(self.bytes_read);
        tuple.dec(self.records_seen);
        tuple.dec(self.blank_lines);
        tuple.dec(self.parse_failed);
        tuple.dec(self.mapping_diagnostics);
        let mut ranges = Vec::new();
        ranges.push(b'[');
        for (index, range) in self.unprocessed_ranges.iter().enumerate() {
            if index > 0 {
                ranges.push(b',');
            }
            let mut entry = CanonicalTuple::new();
            entry
                .dec(range.start)
                .dec(range.end)
                .str(&range.reason)
                .opt_dec(range.ordinal)
                .opt_str(range.record_pointer.as_deref());
            ranges.extend_from_slice(&entry.finish());
        }
        ranges.push(b']');
        tuple.raw(&ranges);
        tuple.boolean(self.reached_eof);
        tuple.finish()
    }
}

/// Footer of a records stream: `['summary', count]` (§5).
#[must_use]
pub fn records_footer(count: u64) -> Vec<u8> {
    CanonicalTuple::new().str("summary").dec(count).finish()
}

/// Footer of the claims stream: `['summary', count, canonical, standalone,
/// unmapped]` (§5).
#[must_use]
pub fn claims_footer(canonical: u64, standalone: u64, unmapped: u64) -> Vec<u8> {
    CanonicalTuple::new()
        .str("summary")
        .dec(canonical + standalone + unmapped)
        .dec(canonical)
        .dec(standalone)
        .dec(unmapped)
        .finish()
}

/// Footer of the witness-binding stream: `['summary', count, CanonicalBound,
/// UnresolvedNoBinding, StandaloneNoBinding, UnmappedNoBinding,
/// WinnerRejectedNoBinding]` (§5).
#[must_use]
pub fn bindings_footer(class_counts: &BindingClassCounts) -> Vec<u8> {
    let mut tuple = CanonicalTuple::new();
    tuple.str("summary").dec(class_counts.total());
    for class in InstallationClass::footer_order() {
        tuple.dec(class_counts.get(class));
    }
    tuple.finish()
}

/// The five installation-class counters, in the fixed footer order (§5, §7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BindingClassCounts {
    pub canonical_bound: u64,
    pub unresolved_no_binding: u64,
    pub standalone_no_binding: u64,
    pub unmapped_no_binding: u64,
    pub winner_rejected_no_binding: u64,
}

impl BindingClassCounts {
    /// Counter for one class.
    #[must_use]
    pub fn get(&self, class: InstallationClass) -> u64 {
        match class {
            InstallationClass::CanonicalBound => self.canonical_bound,
            InstallationClass::UnresolvedNoBinding => self.unresolved_no_binding,
            InstallationClass::StandaloneNoBinding => self.standalone_no_binding,
            InstallationClass::UnmappedNoBinding => self.unmapped_no_binding,
            InstallationClass::WinnerRejectedNoBinding => self.winner_rejected_no_binding,
        }
    }

    /// Total leaves across all five classes.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.canonical_bound
            + self.unresolved_no_binding
            + self.standalone_no_binding
            + self.unmapped_no_binding
            + self.winner_rejected_no_binding
    }
}

/// The expanded `original_binding_root`:
/// `[sha256_hex, count_decimal, [five decimal counters]]` (§5).
#[must_use]
pub fn encode_original_binding_root(sha256: &Sha256Digest, class_counts: &BindingClassCounts) -> Vec<u8> {
    let mut tuple = CanonicalTuple::new();
    tuple.str(&sha256.hex());
    tuple.dec(class_counts.total());
    let mut counts = Vec::new();
    counts.push(b'[');
    for (index, class) in InstallationClass::footer_order().into_iter().enumerate() {
        if index > 0 {
            counts.push(b',');
        }
        write_json_decimal(&mut counts, class_counts.get(class));
    }
    counts.push(b']');
    tuple.raw(&counts);
    tuple.finish()
}

/// The A-side top-level tuple, hashed to `semantic_request_digest` (§5).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn semantic_request_digest(
    input_key: &Sha256Digest,
    expected_manifest_digest: &Sha256Digest,
    sealed_sha256: &Sha256Digest,
    byte_len: u64,
    format: &str,
    normalizer_id: &str,
    safety_contract_id: &str,
    finish: &VerifiedFinish,
    projection_disposition: ProjectionDisposition,
    source_semantic_records_root: &Root,
    claims_root: &Root,
) -> Sha256Digest {
    let mut tuple = CanonicalTuple::new();
    tuple.str(SOURCE_SEMANTIC_REQUEST_DOMAIN);
    tuple.str(&input_key.hex());
    tuple.str(&expected_manifest_digest.hex());
    tuple.str(&sealed_sha256.hex());
    tuple.dec(byte_len);
    tuple.str(format);
    tuple.str(normalizer_id);
    tuple.str(safety_contract_id);
    tuple.raw(&finish.encode());
    tuple.str(projection_disposition.as_str());
    tuple.raw(&source_semantic_records_root.to_array());
    tuple.raw(&claims_root.to_array());
    tuple.finish_sha()
}

/// The B-side top-level tuple, hashed to `installation_digest` (§5).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn installation_digest(
    library_identity: &str,
    semantic_request_digest: &Sha256Digest,
    immutable_records_root: &Root,
    original_binding_root: &Root,
    binding_class_counts: &BindingClassCounts,
    terminal_state: TerminalState,
    applied_content_generation: &str,
    committed_source_facts_revision: u64,
) -> Sha256Digest {
    let mut tuple = CanonicalTuple::new();
    tuple.str(SOURCE_INSTALLATION_DOMAIN);
    tuple.str(library_identity);
    tuple.str(&semantic_request_digest.hex());
    tuple.raw(&immutable_records_root.to_array());
    tuple.raw(&encode_original_binding_root(&original_binding_root.sha256, binding_class_counts));
    tuple.str(terminal_state.as_str());
    tuple.str(applied_content_generation);
    tuple.dec(committed_source_facts_revision);
    tuple.finish_sha()
}

/// The deterministic activation receipt key (§12).
#[must_use]
pub fn activation_receipt_key(
    library_identity: &str,
    input_key: &Sha256Digest,
    semantic_request_digest: &Sha256Digest,
) -> String {
    let mut tuple = CanonicalTuple::new();
    tuple.str(SOURCE_RECEIPT_KEY_DOMAIN);
    tuple.str(library_identity);
    tuple.str(&input_key.hex());
    tuple.str(&semantic_request_digest.hex());
    format!("{SOURCE_RECEIPT_KEY_PREFIX}{}", tuple.finish_sha().hex())
}

/// The `visible_facts_digest` of a final partial/failed publication (§10).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn visible_facts_digest(
    input_key: &Sha256Digest,
    terminal: TerminalState,
    source_semantic_records_root: &Root,
    claims_root: &Root,
    finish: &VerifiedFinish,
    projection_disposition: ProjectionDisposition,
) -> Sha256Digest {
    let mut tuple = CanonicalTuple::new();
    tuple.str(SOURCE_FAILURE_PUBLICATION_DOMAIN);
    tuple.str(&input_key.hex());
    tuple.str(terminal.as_str());
    tuple.raw(&source_semantic_records_root.to_array());
    tuple.raw(&claims_root.to_array());
    tuple.raw(&finish.encode());
    tuple.str(projection_disposition.as_str());
    tuple.finish_sha()
}

// =============================================================================
// Versioned MessagePack envelopes (§9, §10)
// =============================================================================

/// Domain of the strict `source_positions_bin` LinkEvidence envelope (§9).
pub const SOURCE_LINK_EVIDENCE_DOMAIN: &str = "cass.source-link-evidence/1";
/// Envelope version of both versioned payload envelopes in this module.
pub const SOURCE_ENVELOPE_VERSION: u32 = 1;
/// Domain of the strict `diagnostics_bin` envelope (§10).
pub const SOURCE_DIAGNOSTICS_DOMAIN: &str = "cass.source-diagnostics/1";
/// Domain of the versioned `unprocessed_ranges_bin` carrier (§6 column, §13).
pub const SOURCE_UNPROCESSED_RANGES_DOMAIN: &str = "cass.source-unprocessed-ranges/1";
/// Domain of the versioned `attempt_history_bin` carrier (§13.6).
pub const SOURCE_ATTEMPT_HISTORY_DOMAIN: &str = "cass.source-attempt-history/1";
/// Domain of the receipt `detail` object (§12).
pub const SOURCE_RECEIPT_DETAIL_DOMAIN: &str = "cass.source-receipt-detail/1";
/// Prefix of the content generation a successful activation applies (§13.5).
pub const SOURCE_GENERATION_PREFIX: &str = "source-activation-v1:";

/// The versioned LinkEvidence map stored in `source_message_links.source_positions_bin`
/// (§9): the claim the link came from plus the original installation, if one
/// exists yet.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkEvidence {
    /// Envelope version; only [`SOURCE_ENVELOPE_VERSION`] is accepted.
    pub version: u32,
    /// Fixed domain string [`SOURCE_LINK_EVIDENCE_DOMAIN`].
    pub domain: String,
    /// The claim this link projects.
    pub claim: SourceClaim,
    /// The original installation, or `None` for a claim that is not installed.
    pub installation: Option<OriginalInstallation>,
}

/// The versioned diagnostics map stored in `source_records.diagnostics_bin` (§10).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsEnvelope {
    /// Envelope version; only [`SOURCE_ENVELOPE_VERSION`] is accepted.
    pub version: u32,
    /// Fixed domain string [`SOURCE_DIAGNOSTICS_DOMAIN`].
    pub domain: String,
    /// The diagnostics, in their original order.
    pub items: Vec<SafeDiagnostic>,
}

/// First-byte check: a MessagePack map. The envelope rule forbids a non-map
/// top level (§9), and `rmp_serde` would otherwise accept the array form of a
/// struct as well.
fn ensure_msgpack_map(bytes: &[u8]) -> Result<(), SourceCodecError> {
    match bytes.first() {
        Some(0x80..=0x8f) | Some(0xde) | Some(0xdf) => Ok(()),
        _ => Err(SourceCodecError::InvalidEnvelope),
    }
}

fn encode_envelope<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, SourceInstallError> {
    // `to_vec_named` writes a map with the field names, never a positional
    // array, so the decoder's field set is checkable by name.
    rmp_serde::to_vec_named(value).map_err(|_| SourceInstallError::Staging {
        detail: "could not encode the versioned envelope".to_string(),
    })
}

fn decode_envelope<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, SourceInstallError> {
    ensure_msgpack_map(bytes).map_err(SourceInstallError::Codec)?;
    let mut deserializer = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
    let value = T::deserialize(&mut deserializer).map_err(|err| SourceInstallError::Corrupt {
        detail: format!("envelope does not match its frozen field set: {err}"),
    })?;
    // Trailing bytes after a complete envelope are a corruption, never a
    // silently ignored tail; `from_slice` alone does not check this.
    if deserializer.get_ref().position() as usize != bytes.len() {
        return Err(SourceInstallError::Codec(SourceCodecError::TrailingBytes));
    }
    Ok(value)
}

/// Encode one claim's LinkEvidence (§9).
///
/// The conversation identity digest a winner-rejection evidence carries lives
/// in the *canonical tuple* (§9 passes it alongside), not in the serialised
/// struct, so it is deliberately not an argument here.
pub fn encode_link_evidence(
    claim: &SourceClaim,
    installation: Option<&OriginalInstallation>,
) -> Result<Vec<u8>, SourceInstallError> {
    encode_envelope(&LinkEvidence {
        version: SOURCE_ENVELOPE_VERSION,
        domain: SOURCE_LINK_EVIDENCE_DOMAIN.to_string(),
        claim: claim.clone(),
        installation: installation.cloned(),
    })
}

/// Strictly decode one LinkEvidence, rejecting any shape a hostile or drifted
/// writer could produce (§9's rejection list).
pub fn decode_link_evidence(bytes: &[u8]) -> Result<LinkEvidence, SourceInstallError> {
    let evidence: LinkEvidence = decode_envelope(bytes)?;
    if evidence.version != SOURCE_ENVELOPE_VERSION {
        return Err(SourceInstallError::Codec(SourceCodecError::UnsupportedVersion));
    }
    if evidence.domain != SOURCE_LINK_EVIDENCE_DOMAIN {
        return Err(SourceInstallError::Corrupt {
            detail: "LinkEvidence domain does not match the frozen value".to_string(),
        });
    }
    Ok(evidence)
}

/// Strictly decode one diagnostics envelope.
pub fn decode_diagnostics(bytes: &[u8]) -> Result<DiagnosticsEnvelope, SourceInstallError> {
    let envelope: DiagnosticsEnvelope = decode_envelope(bytes)?;
    if envelope.version != SOURCE_ENVELOPE_VERSION {
        return Err(SourceInstallError::Codec(SourceCodecError::UnsupportedVersion));
    }
    if envelope.domain != SOURCE_DIAGNOSTICS_DOMAIN {
        return Err(SourceInstallError::Corrupt {
            detail: "diagnostics domain does not match the frozen value".to_string(),
        });
    }
    Ok(envelope)
}

// =============================================================================
// Verified inputs (§10) and the staging primitive (§11)
// =============================================================================

/// Wire format of one source input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    Jsonl,
    JsonDocument,
}

impl SourceFormat {
    /// Column literal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::JsonDocument => "json_document",
        }
    }
}

/// The expected-manifest header, derived by the independent scan of the sealed
/// bytes (§10, §17.2).
///
/// The fields are private and only [`VerifiedSourceInput::verify`] (through
/// [`Self::from_scan`]) builds one, so a caller cannot hand a plausible-looking
/// header to the staging primitive. A pair of forged digests that agree with
/// each other is never a substitute for the sealed bytes they claim to
/// describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExpectedManifest {
    verifier_version: String,
    sealed_sha256: Sha256Digest,
    byte_len: u64,
    format: SourceFormat,
    records: u64,
    blank_lines: u64,
    framing_sha256: Sha256Digest,
    complete: bool,
    blank_bytes: u64,
}

impl VerifiedExpectedManifest {
    /// Build the header from a completed independent scan.
    fn from_scan(scan: &FramingSummary, format: SourceFormat) -> Self {
        Self {
            verifier_version: SOURCE_VERIFIER_VERSION.to_string(),
            sealed_sha256: scan.sealed_sha256,
            byte_len: scan.byte_len,
            format,
            records: scan.records,
            blank_lines: scan.blank_lines,
            framing_sha256: scan.framing_sha256,
            complete: scan.complete,
            blank_bytes: scan.blank_bytes,
        }
    }

    /// The verifier identity that produced this header.
    #[must_use]
    pub fn verifier_version(&self) -> &str {
        &self.verifier_version
    }

    /// SHA-256 of the sealed bytes the scan read.
    #[must_use]
    pub fn sealed_sha256(&self) -> &Sha256Digest {
        &self.sealed_sha256
    }

    /// Length of the sealed bytes.
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Wire format the scan applied.
    #[must_use]
    pub fn format(&self) -> SourceFormat {
        self.format
    }

    /// Physical record count, from the scan's own denominator.
    #[must_use]
    pub fn records(&self) -> u64 {
        self.records
    }

    /// Blank-line count, from the scan's own denominator.
    #[must_use]
    pub fn blank_lines(&self) -> u64 {
        self.blank_lines
    }

    /// Bytes occupied by those blank lines, terminators excluded.
    #[must_use]
    pub fn blank_bytes(&self) -> u64 {
        self.blank_bytes
    }

    /// The `cass.source-framing/1` stream digest.
    #[must_use]
    pub fn framing_sha256(&self) -> &Sha256Digest {
        &self.framing_sha256
    }

    /// Whether the scan ran to the end of the sealed bytes. An incomplete scan
    /// never authorises an activation.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.complete
    }
}

/// The safety-context identity the sanitisation ran under (§10).
///
/// Built only from a checked [`SourceSafetyConfig`], so the two digests and the
/// desensitisation flag always describe a configuration that was really
/// supplied rather than two caller-echoed equal strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSafetyIdentity {
    code_version: String,
    desensitization_enabled: bool,
    config_source_identity: String,
    fixed_config_sha256: Sha256Digest,
    effective_four_arrays_sha256: Sha256Digest,
}

impl VerifiedSafetyIdentity {
    /// The capture code version the fixed configuration belonged to.
    #[must_use]
    pub fn code_version(&self) -> &str {
        &self.code_version
    }

    /// Whether desensitisation was on. Verification refuses a capture made with
    /// it off (§17.3).
    #[must_use]
    pub fn desensitization_enabled(&self) -> bool {
        self.desensitization_enabled
    }

    /// Which fixed configuration copy the digests describe.
    #[must_use]
    pub fn config_source_identity(&self) -> &str {
        &self.config_source_identity
    }

    /// The fixed configuration copy's digest.
    #[must_use]
    pub fn fixed_config_sha256(&self) -> &Sha256Digest {
        &self.fixed_config_sha256
    }

    /// The effective four-array digest.
    #[must_use]
    pub fn effective_four_arrays_sha256(&self) -> &Sha256Digest {
        &self.effective_four_arrays_sha256
    }
}

/// The fixed safety configuration a capture actually ran under (§17.3, v0.4
/// §8).
///
/// This is the raw, caller-writable input side of the boundary, and it carries
/// **no digest of its own** on purpose: the two digests the header stores are
/// recomputed from the material here, so there is nothing for a caller to
/// assert and no arbitrary-but-plausible value to pass off as evidence. The
/// evidence is the exact configuration bytes plus the four arrays actually in
/// force, and the two must agree with each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSafetyConfig {
    pub code_version: String,
    pub desensitization_enabled: bool,
    pub config_source_identity: String,
    /// The exact bytes of the fixed configuration copy this capture ran under.
    pub fixed_config_bytes: Vec<u8>,
    /// The four arrays actually in force, element order preserved.
    pub effective_four_arrays: crate::sources::config::ExcludedContextPaths,
}

impl SourceSafetyConfig {
    /// Check this configuration and promote it to a verified identity.
    ///
    /// The fixed copy is parsed, its four arrays are compared with the arrays
    /// the capture says were effective, and both digests are then computed from
    /// that material — never read back from a caller-supplied string.
    ///
    /// # Errors
    /// `Activation` when the desensitisation flag is off or a required identity
    /// string is empty; `Conflict` when the configuration bytes are not UTF-8
    /// TOML, do not parse, or describe different arrays than the effective set.
    pub fn verify(&self) -> Result<VerifiedSafetyIdentity, SourceInstallError> {
        if !self.desensitization_enabled {
            return Err(SourceInstallError::Activation {
                detail: "the capture ran with desensitisation disabled".to_string(),
            });
        }
        if self.code_version.trim().is_empty() {
            return Err(SourceInstallError::Activation {
                detail: "the safety configuration has no code version".to_string(),
            });
        }
        if self.config_source_identity.trim().is_empty() {
            return Err(SourceInstallError::Activation {
                detail: "the safety configuration names no fixed config copy".to_string(),
            });
        }
        let text = std::str::from_utf8(&self.fixed_config_bytes).map_err(|_| {
            SourceInstallError::Conflict {
                detail: "the fixed configuration copy is not UTF-8 TOML".to_string(),
            }
        })?;
        let parsed: crate::sources::config::ExcludedContextPaths =
            toml::from_str(text).map_err(|err| SourceInstallError::Conflict {
                detail: format!("the fixed configuration copy does not parse: {err}"),
            })?;
        // The whole point of keeping the bytes: a packet cannot claim a
        // configuration copy it did not really run under, and a changed TOML
        // under unchanged arrays (or the reverse) is a refusal, not a silently
        // re-derived identity.
        if parsed != self.effective_four_arrays {
            return Err(SourceInstallError::Conflict {
                detail: "the fixed configuration copy and the effective four arrays disagree"
                    .to_string(),
            });
        }
        Ok(VerifiedSafetyIdentity {
            code_version: self.code_version.clone(),
            desensitization_enabled: true,
            config_source_identity: self.config_source_identity.clone(),
            fixed_config_sha256: Sha256Digest::of(&self.fixed_config_bytes),
            effective_four_arrays_sha256: effective_four_arrays_digest(&self.effective_four_arrays),
        })
    }
}

/// The canonical encoding of the effective four arrays (v0.4 §8): a compact
/// UTF-8 JSON object whose keys are sorted and whose arrays keep their element
/// order.
#[must_use]
pub fn canonical_four_arrays_json(paths: &crate::sources::config::ExcludedContextPaths) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(b'{');
    let fields: [(&str, &Vec<String>); 4] = [
        ("injection_only_files", &paths.injection_only_files),
        ("memory_files", &paths.memory_files),
        ("project_read_documents", &paths.project_read_documents),
        ("workspace_scoped_files", &paths.workspace_scoped_files),
    ];
    for (index, (name, items)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        write_json_string(&mut out, name);
        out.push(b':');
        out.push(b'[');
        for (item_index, item) in items.iter().enumerate() {
            if item_index > 0 {
                out.push(b',');
            }
            write_json_string(&mut out, item);
        }
        out.push(b']');
    }
    out.push(b'}');
    out
}

/// SHA-256 of [`canonical_four_arrays_json`] — the `effective_four_arrays`
/// digest of the frozen safety identity (v0.4 §8).
#[must_use]
pub fn effective_four_arrays_digest(
    paths: &crate::sources::config::ExcludedContextPaths,
) -> Sha256Digest {
    Sha256Digest::of(&canonical_four_arrays_json(paths))
}

/// One source input whose sealed bytes, context and identity have been verified
/// (§10).
///
/// The fields are private and the only constructor is [`Self::new`], which
/// refuses the shapes the contract forbids, so a caller cannot hand a
/// plausible-looking struct straight to the staging primitive.
#[derive(Debug, Clone)]
pub struct VerifiedSourceInput {
    input_key: Sha256Digest,
    identity_tuple: Vec<Option<String>>,
    source_id: String,
    identity_namespace: String,
    connector: String,
    origin_host: Option<String>,
    origin_source_version: Option<String>,
    role: Option<String>,
    platform: Option<String>,
    root_id: String,
    relative_locator: String,
    discovery: LosslessSourceValue,
    parser_context: LosslessSourceValue,
    context_digest: Sha256Digest,
    sealed_ref: LosslessSourceValue,
    sealed_sha256: Sha256Digest,
    byte_len: u64,
    format: SourceFormat,
    normalizer_id: String,
    safety_contract_id: String,
    manifest: VerifiedExpectedManifest,
    safety_identity: VerifiedSafetyIdentity,
}

/// The 15 identity fields of `input_identity/2` (§10: fixed order, unchanged).
pub const IDENTITY_TUPLE_LEN: usize = 15;

/// Everything one capture declares about an input *before* it is verified
/// (§10).
///
/// This is the raw, caller-writable side of the boundary. It deliberately has
/// no digest, no length and no manifest field: those are measurements of the
/// sealed bytes, and a declaration that could name them would be able to forge
/// a self-consistent pair the sealed bytes never match.
#[derive(Debug, Clone)]
pub struct SourceInputDeclaration {
    /// The 15 `input_identity/2` fields, in their frozen order.
    pub identity_tuple: Vec<Option<String>>,
    pub identity_namespace: String,
    pub source_id: String,
    pub connector: String,
    pub origin_kind: Option<String>,
    pub origin_host: Option<String>,
    pub origin_source_version: Option<String>,
    pub role: Option<String>,
    pub platform: Option<String>,
    pub root_id: String,
    pub relative_locator: String,
    /// The published safe persistent representation of the discovery record.
    pub discovery: LosslessSourceValue,
    /// The published safe persistent representation of the parser context. Its
    /// object members must already be in ascending key order (§17.1).
    pub parser_context: LosslessSourceValue,
    /// The published safe persistent representation of the sealed reference.
    pub sealed_ref: LosslessSourceValue,
    pub format: SourceFormat,
    pub normalizer_id: String,
    pub safety_contract_id: String,
}

impl VerifiedSourceInput {
    /// Independently scan `sealed` and build the verified input (§10, §17.2).
    ///
    /// This is [`Self::verify_reader`] over an in-memory slice, so the slice
    /// entry and the file entry share one implementation: the same sealed bytes
    /// verified either way produce the same identity, the same header and the
    /// same summary.
    ///
    /// # Errors
    /// As [`Self::verify_reader`].
    pub fn verify(
        declaration: SourceInputDeclaration,
        sealed: &[u8],
        safety: &SourceSafetyConfig,
    ) -> Result<(Self, FramingSummary), SourceInstallError> {
        Self::verify_reader(declaration, Cursor::new(sealed), safety)
    }

    /// Independently scan a file stream and build the verified input (§10,
    /// §17.2).
    ///
    /// Every measurement is recomputed here rather than accepted: the content
    /// digest and byte length come from the bytes the reader produced, the
    /// record and blank denominators and the framing digest come from this
    /// module's own streaming scan, and the input key comes from the identity
    /// tuple. The declaration's own fields are then checked *against* that
    /// recomputed identity, so a header and a digest that agree with each other
    /// but not with the bytes on disk cannot validate.
    ///
    /// There is no parameter here for a summary, and
    /// [`VerifiedExpectedManifest`] has no public constructor, so a caller
    /// cannot hand in a plausible self-report and have it promoted into a
    /// verified input.
    ///
    /// The reader is consumed through its own bounded buffer. The scan keeps no
    /// record bytes, so an input far larger than memory is still framed and
    /// hashed record by record.
    ///
    /// # Errors
    /// `Staging` when the identity tuple is not [`IDENTITY_TUPLE_LEN`] entries;
    /// `Conflict` when any declared field disagrees with the identity tuple or
    /// with the measured bytes; `Activation` when the safety configuration is
    /// incomplete, desensitisation was off, or the scan did not reach the end of
    /// the input; `Overflow` when an ordinal or byte counter would not fit a
    /// `u64`; `Io` when the input could not be read.
    pub fn verify_reader<R: std::io::BufRead>(
        declaration: SourceInputDeclaration,
        reader: R,
        safety: &SourceSafetyConfig,
    ) -> Result<(Self, FramingSummary), SourceInstallError> {
        let safety_identity = safety.verify()?;
        let SourceInputDeclaration {
            identity_tuple,
            identity_namespace,
            source_id,
            connector,
            origin_kind,
            origin_host,
            origin_source_version,
            role,
            platform,
            root_id,
            relative_locator,
            discovery,
            parser_context,
            sealed_ref,
            format,
            normalizer_id,
            safety_contract_id,
        } = declaration;

        if identity_tuple.len() != IDENTITY_TUPLE_LEN {
            return Err(SourceInstallError::Staging {
                detail: format!(
                    "identity tuple has {} entries, expected {IDENTITY_TUPLE_LEN}",
                    identity_tuple.len()
                ),
            });
        }

        let context_digest = context_digest(&parser_context)?;
        let input_key = Sha256Digest::of(&identity_tuple_bin(&identity_tuple));

        // The independent scan is this module's own denominator: it measures
        // the bytes it reads and cannot be told what to expect. A scan that
        // stopped early — because the input ended or because a read failed —
        // never authorises an activation.
        let mut scan = FramingStream::new(reader, format);
        scan.run_to_end()?;
        let summary = scan.finish();
        if !summary.complete {
            return Err(SourceInstallError::Activation {
                detail: "the independent scan did not reach the end of the sealed bytes".to_string(),
            });
        }
        let sealed_sha256 = summary.sealed_sha256;

        // §17.1's identity tuple is the binding surface: every declared field
        // and both measured digests must appear in it, or the declaration and
        // the bytes describe different inputs.
        for (index, name, expected) in [
            (0usize, "version", Some("cass.source-input/2")),
            (1, "identity_namespace", Some(identity_namespace.as_str())),
            (2, "source_id", Some(source_id.as_str())),
            (3, "connector", Some(connector.as_str())),
            (4, "root_id", Some(root_id.as_str())),
            (5, "relative_locator", Some(relative_locator.as_str())),
            (6, "role", role.as_deref()),
            (7, "origin.kind", origin_kind.as_deref()),
            (8, "origin.host", origin_host.as_deref()),
            (9, "origin.source_version", origin_source_version.as_deref()),
            (10, "platform", platform.as_deref()),
            (13, "normalizer_id", Some(normalizer_id.as_str())),
            (14, "safety_contract_id", Some(safety_contract_id.as_str())),
        ] {
            expect_identity_element(&identity_tuple, index, name, expected)?;
        }
        let context_hex = context_digest.hex();
        expect_identity_element(
            &identity_tuple,
            11,
            "parser_context_digest",
            Some(context_hex.as_str()),
        )?;
        let sealed_hex = sealed_sha256.hex();
        expect_identity_element(&identity_tuple, 12, "sealed_sha256", Some(sealed_hex.as_str()))?;

        let manifest = VerifiedExpectedManifest::from_scan(&summary, format);

        Ok((
            Self {
                input_key,
                identity_tuple,
                source_id,
                identity_namespace,
                connector,
                origin_host,
                origin_source_version,
                role,
                platform,
                root_id,
                relative_locator,
                discovery,
                parser_context,
                context_digest,
                sealed_ref,
                sealed_sha256,
                byte_len: summary.byte_len,
                format,
                normalizer_id,
                safety_contract_id,
                manifest,
                safety_identity,
            },
            summary,
        ))
    }

    /// The input's content key.
    #[must_use]
    pub fn input_key(&self) -> &Sha256Digest {
        &self.input_key
    }

    /// The input's own identity tuple, in its frozen order.
    #[must_use]
    pub fn identity_tuple(&self) -> &[Option<String>] {
        &self.identity_tuple
    }

    /// The independently derived manifest for this input.
    #[must_use]
    pub fn manifest(&self) -> &VerifiedExpectedManifest {
        &self.manifest
    }

    /// The verified safety identity this input was captured under.
    #[must_use]
    pub fn safety_identity(&self) -> &VerifiedSafetyIdentity {
        &self.safety_identity
    }

    /// The expected-record count of the manifest.
    #[must_use]
    pub fn expected_records(&self) -> u64 {
        self.manifest.records
    }

    /// The expected blank-line count of the manifest.
    #[must_use]
    pub fn expected_blank_lines(&self) -> u64 {
        self.manifest.blank_lines
    }
}

/// Check one identity-tuple element against the value it must carry.
fn expect_identity_element(
    tuple: &[Option<String>],
    index: usize,
    name: &str,
    expected: Option<&str>,
) -> Result<(), SourceInstallError> {
    let actual = tuple.get(index).and_then(|value| value.as_deref());
    if actual != expected {
        return Err(SourceInstallError::Conflict {
            detail: format!(
                "identity tuple element {index} ({name}) is {actual:?}, expected {expected:?}"
            ),
        });
    }
    Ok(())
}

/// The parser-context digest (§17.1).
///
/// Key sorting is a **normalisation step of the digest**, not a precondition on
/// the input: two semantically equal context objects that differ only in member
/// order must hash the same, while two arrays that differ in order must not.
/// The digest is therefore taken over a sorted *view* built here; the context's
/// own persisted bytes keep the member order the caller supplied, and no raw
/// source payload is rewritten.
pub fn context_digest(context: &LosslessSourceValue) -> Result<Sha256Digest, SourceInstallError> {
    let mut out = Vec::new();
    write_sorted_context_json(context, &mut out)?;
    Ok(Sha256Digest::of(&out))
}

/// Write a compact JSON *view* of a context value with every object's members
/// sorted by key and every array left in its original order.
fn write_sorted_context_json(
    value: &LosslessSourceValue,
    out: &mut Vec<u8>,
) -> Result<(), SourceInstallError> {
    match value {
        LosslessSourceValue::Object(members) => {
            let mut ordered: Vec<&(String, LosslessSourceValue)> = members.iter().collect();
            ordered.sort_by(|left, right| left.0.cmp(&right.0));
            for pair in ordered.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(SourceInstallError::Conflict {
                        detail: format!(
                            "parser context object repeats the key {:?}; a sorted digest view \
                             would be ambiguous",
                            pair[0].0
                        ),
                    });
                }
            }
            out.push(b'{');
            for (index, (key, member)) in ordered.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_string(out, key);
                out.push(b':');
                write_sorted_context_json(member, out)?;
            }
            out.push(b'}');
        }
        LosslessSourceValue::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_sorted_context_json(item, out)?;
            }
            out.push(b']');
        }
        LosslessSourceValue::String(text) => write_json_string(out, text),
        // Numbers keep their original token text, never a re-rendered float.
        LosslessSourceValue::Number(number) => out.extend_from_slice(number.as_str().as_bytes()),
        LosslessSourceValue::Bool(value) => {
            out.extend_from_slice(if *value { b"true" } else { b"false" });
        }
        LosslessSourceValue::Null => out.extend_from_slice(b"null"),
    }
    Ok(())
}

/// One record as `stage_source_records_in_tx` writes it (§10:
/// `VerifiedStagedRecord`).
///
/// The fields are private and the frame-derived half — the locator and the
/// expected raw digest — can only come from [`FramedSourceRecord`], so the
/// expected denominator a page registers is always the one the independent
/// scan produced. The retention state is derived from the safe payload rather
/// than accepted, because the two must never be able to disagree: the SQL pair
/// of `CHECK`s refuses a half-filled row outright.
#[derive(Debug, Clone)]
pub struct VerifiedStagedRecord {
    locator: SourceRecordLocator,
    expected_raw_sha256: Sha256Digest,
    observed_raw_sha256: Option<Sha256Digest>,
    parse_state: ParseState,
    record_mapping_state: RecordMappingState,
    safety_state: SafetyState,
    retention_state: RetentionState,
    native_ids: Option<LosslessSourceValue>,
    safe_value: Option<LosslessSourceValue>,
    diagnostics: Option<Vec<SafeDiagnostic>>,
}

impl VerifiedStagedRecord {
    /// Build one staged record from a frame of the independent scan.
    #[must_use]
    pub fn from_frame(
        frame: &FramedSourceRecord,
        observed_raw_sha256: Option<Sha256Digest>,
        parse_state: ParseState,
        record_mapping_state: RecordMappingState,
        safety_state: SafetyState,
        native_ids: Option<LosslessSourceValue>,
        safe_value: Option<LosslessSourceValue>,
        diagnostics: Option<Vec<SafeDiagnostic>>,
    ) -> Self {
        let retention_state = if safe_value.is_some() {
            RetentionState::PayloadPresent
        } else {
            RetentionState::PayloadAbsent
        };
        Self {
            locator: frame.locator.clone(),
            expected_raw_sha256: frame.raw_sha256,
            observed_raw_sha256,
            parse_state,
            record_mapping_state,
            safety_state,
            retention_state,
            native_ids,
            safe_value,
            diagnostics,
        }
    }

    /// The record's physical position, from the independent scan.
    #[must_use]
    pub fn locator(&self) -> &SourceRecordLocator {
        &self.locator
    }

    /// The scan's expected digest for the record's own bytes.
    #[must_use]
    pub fn expected_raw_sha256(&self) -> &Sha256Digest {
        &self.expected_raw_sha256
    }

    /// The digest the reader actually observed, when it read the record.
    #[must_use]
    pub fn observed_raw_sha256(&self) -> Option<&Sha256Digest> {
        self.observed_raw_sha256.as_ref()
    }

    /// How the record parsed.
    #[must_use]
    pub fn parse_state(&self) -> ParseState {
        self.parse_state
    }

    /// The record-level aggregate of its claims' mapping states.
    #[must_use]
    pub fn record_mapping_state(&self) -> RecordMappingState {
        self.record_mapping_state
    }

    /// Whether the safety pass preserved, blocked or has not reached it.
    #[must_use]
    pub fn safety_state(&self) -> SafetyState {
        self.safety_state
    }

    /// Whether the safe payload is present. Always consistent with
    /// [`Self::safe_value`].
    #[must_use]
    pub fn retention_state(&self) -> RetentionState {
        self.retention_state
    }

    /// The native identifiers, when the record carried any.
    #[must_use]
    pub fn native_ids(&self) -> Option<&LosslessSourceValue> {
        self.native_ids.as_ref()
    }

    /// The preserved safe payload, when the record has one.
    #[must_use]
    pub fn safe_value(&self) -> Option<&LosslessSourceValue> {
        self.safe_value.as_ref()
    }

    /// The safety/parse diagnostics, when the record produced any.
    #[must_use]
    pub fn diagnostics(&self) -> Option<&[SafeDiagnostic]> {
        self.diagnostics.as_deref()
    }
}

/// What one bounded staging page did (§10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageOutcome {
    pub input_id: i64,
    pub registered: u64,
    pub updated: u64,
    pub verified_same: u64,
    pub last_locator: Option<SourceRecordLocator>,
}

/// Canonical bytes of the lossless safe tree (`write_canonical`, §4).
fn lossless_bin(value: &LosslessSourceValue) -> Result<Vec<u8>, SourceInstallError> {
    let mut out = Vec::new();
    value
        .write_canonical(&mut out)
        .map_err(|_| SourceInstallError::Codec(SourceCodecError::EncodeFailed))?;
    Ok(out)
}

/// `SHA256(write_canonical(tree))`, the `safe_value_sha256` (§10).
fn safe_value_sha256(value: &LosslessSourceValue) -> Result<Sha256Digest, SourceInstallError> {
    Ok(Sha256Digest::of(&lossless_bin(value)?))
}

/// The stored `identity_tuple_bin`: a compact JSON array of the 15
/// string/null identity fields, in their frozen order (§4: not re-encoded).
fn identity_tuple_bin(items: &[Option<String>]) -> Vec<u8> {
    let mut tuple = CanonicalTuple::new();
    for item in items {
        tuple.opt_str(item.as_deref());
    }
    tuple.finish()
}

/// Encode the bounded expected-manifest header (§20.1).
///
/// The header is a fixed 15-element compact UTF-8 JSON array: the domain, the
/// nine manifest fields and the five safety-identity fields, in that order.
/// Every integer is a decimal *string* and every digest a lowercase hex
/// *string*, so no consumer ever sees an `f64`. Only bounded metadata lives
/// here — the per-record leaves stay in `source_records`, never in this BLOB.
#[must_use]
pub fn encode_expected_manifest_header(
    manifest: &VerifiedExpectedManifest,
    safety: &VerifiedSafetyIdentity,
) -> Vec<u8> {
    let mut tuple = CanonicalTuple::new();
    tuple
        .str(SOURCE_EXPECTED_MANIFEST_DOMAIN)
        .str(&manifest.verifier_version)
        .str(&manifest.sealed_sha256.hex())
        .dec(manifest.byte_len)
        .str(manifest.format.as_str())
        .dec(manifest.records)
        .dec(manifest.blank_lines)
        .str(&manifest.framing_sha256.hex())
        .boolean(manifest.complete)
        .dec(manifest.blank_bytes)
        .str(&safety.code_version)
        .boolean(safety.desensitization_enabled)
        .str(&safety.config_source_identity)
        .str(&safety.fixed_config_sha256.hex())
        .str(&safety.effective_four_arrays_sha256.hex());
    tuple.finish()
}

/// The `expected_manifest_digest` A and the receipt carry (§20.2): the SHA-256
/// of the canonical header bytes above.
///
/// It is always recomputed from the SQL-read header bytes after a strict
/// decode, never copied from the neighbouring `activation_request_hash` column
/// or from a caller-supplied digest.
#[must_use]
pub fn expected_manifest_digest(
    manifest: &VerifiedExpectedManifest,
    safety: &VerifiedSafetyIdentity,
) -> Sha256Digest {
    Sha256Digest::of(&encode_expected_manifest_header(manifest, safety))
}

/// Strictly decode a stored expected-manifest header (§20.1).
///
/// The element count, every element's type, the closed `format` domain, the
/// canonical decimal spelling of each integer, the lowercase-hex spelling of
/// each digest and the canonical byte form of the whole array are all checked.
/// A non-canonical spelling, extra whitespace or any trailing bytes is a
/// refusal: the header round-trips byte-for-byte or it is rejected.
///
/// # Errors
/// `Corrupt` for every shape outside the frozen header.
pub fn decode_expected_manifest_header(
    bytes: &[u8],
) -> Result<(VerifiedExpectedManifest, VerifiedSafetyIdentity), SourceInstallError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|err| {
        SourceInstallError::Corrupt {
            detail: format!("expected manifest header is not JSON: {err}"),
        }
    })?;
    let items = value.as_array().ok_or_else(|| SourceInstallError::Corrupt {
        detail: "expected manifest header is not a JSON array".to_string(),
    })?;
    if items.len() != EXPECTED_MANIFEST_HEADER_LEN {
        return Err(SourceInstallError::Corrupt {
            detail: format!(
                "expected manifest header has {} elements, expected {EXPECTED_MANIFEST_HEADER_LEN}",
                items.len()
            ),
        });
    }
    let domain = header_str(&items[0], "domain")?;
    if domain != SOURCE_EXPECTED_MANIFEST_DOMAIN {
        return Err(SourceInstallError::Corrupt {
            detail: format!("expected manifest header domain is {domain:?}"),
        });
    }
    let format = match header_str(&items[4], "format")?.as_str() {
        "jsonl" => SourceFormat::Jsonl,
        "json_document" => SourceFormat::JsonDocument,
        other => {
            return Err(SourceInstallError::Corrupt {
                detail: format!("expected manifest header format is {other:?}"),
            });
        }
    };
    let manifest = VerifiedExpectedManifest {
        verifier_version: header_str(&items[1], "verifier_version")?,
        sealed_sha256: header_hex(&items[2], "sealed_sha256")?,
        byte_len: header_decimal(&items[3], "byte_len")?,
        format,
        records: header_decimal(&items[5], "records")?,
        blank_lines: header_decimal(&items[6], "blank_lines")?,
        framing_sha256: header_hex(&items[7], "framing_sha256")?,
        complete: header_bool(&items[8], "complete")?,
        blank_bytes: header_decimal(&items[9], "blank_bytes")?,
    };
    let safety = VerifiedSafetyIdentity {
        code_version: header_str(&items[10], "safety.code_version")?,
        desensitization_enabled: header_bool(&items[11], "safety.desensitization_enabled")?,
        config_source_identity: header_str(&items[12], "safety.config_source_identity")?,
        fixed_config_sha256: header_hex(&items[13], "safety.fixed_config_sha256")?,
        effective_four_arrays_sha256: header_hex(&items[14], "safety.effective_four_arrays_sha256")?,
    };
    // Canonical-form check: re-encoding must reproduce the input exactly. This
    // rejects a leading zero, a `+` or uppercase hex, insignificant whitespace
    // and any trailing bytes in one comparison, without a second parser.
    if encode_expected_manifest_header(&manifest, &safety) != bytes {
        return Err(SourceInstallError::Corrupt {
            detail: "expected manifest header is not in its canonical form".to_string(),
        });
    }
    Ok((manifest, safety))
}

/// One JSON string element of the manifest header.
fn header_str(value: &serde_json::Value, field: &str) -> Result<String, SourceInstallError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| SourceInstallError::Corrupt {
            detail: format!("expected manifest header field {field} is not a string"),
        })
}

/// One JSON boolean element of the manifest header.
fn header_bool(value: &serde_json::Value, field: &str) -> Result<bool, SourceInstallError> {
    value
        .as_bool()
        .ok_or_else(|| SourceInstallError::Corrupt {
            detail: format!("expected manifest header field {field} is not a boolean"),
        })
}

/// One canonical decimal-string element of the manifest header.
fn header_decimal(value: &serde_json::Value, field: &str) -> Result<u64, SourceInstallError> {
    let text = header_str(value, field)?;
    let canonical = text == "0"
        || (!text.starts_with('0')
            && !text.is_empty()
            && text.bytes().all(|byte| byte.is_ascii_digit()));
    if !canonical {
        return Err(SourceInstallError::Corrupt {
            detail: format!("expected manifest header field {field} is not a canonical decimal"),
        });
    }
    text.parse::<u64>().map_err(|_| SourceInstallError::Corrupt {
        detail: format!("expected manifest header field {field} does not fit a u64"),
    })
}

/// One lowercase-hex digest element of the manifest header.
fn header_hex(value: &serde_json::Value, field: &str) -> Result<Sha256Digest, SourceInstallError> {
    let text = header_str(value, field)?;
    Sha256Digest::from_hex(&text).ok_or_else(|| SourceInstallError::Corrupt {
        detail: format!("expected manifest header field {field} is not 64 lowercase hex digits"),
    })
}

// =============================================================================
// Independent framing scan (§17.2)
// =============================================================================

/// One physical frame found by the independent scan of the sealed bytes
/// (§17.2): its locator and the digest of the record bytes alone.
///
/// A JSONL frame excludes its own terminator from both the range and the
/// digest; a JSON document is a single frame covering the whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedSourceRecord {
    locator: SourceRecordLocator,
    raw_sha256: Sha256Digest,
}

impl FramedSourceRecord {
    /// The frame's physical position.
    #[must_use]
    pub fn locator(&self) -> &SourceRecordLocator {
        &self.locator
    }

    /// SHA-256 of the record bytes, terminators excluded.
    #[must_use]
    pub fn raw_sha256(&self) -> &Sha256Digest {
        &self.raw_sha256
    }
}

/// The counters and stream digest one independent scan produced (§17.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramingSummary {
    /// Length of the scanned bytes.
    pub byte_len: u64,
    /// SHA-256 of every byte that was scanned.
    pub sealed_sha256: Sha256Digest,
    /// Physical record count.
    pub records: u64,
    /// Blank-line count.
    pub blank_lines: u64,
    /// Bytes occupied by those blank lines, terminators excluded.
    pub blank_bytes: u64,
    /// The `cass.source-framing/1` stream digest.
    pub framing_sha256: Sha256Digest,
    /// Whether the scan reached the end of the sealed bytes.
    pub complete: bool,
}

/// A paged independent scan of one sealed input (§17.2).
///
/// The scan owns its own denominator: it counts records and blank lines,
/// hashes each record's own bytes and streams the `cass.source-framing/1`
/// digest, without consulting a parser, a reader or any FAD output.
///
/// It is the streaming engine ([`FramingStream`]) driven through a `Cursor`, so
/// the slice path and the file path frame bytes through one machine instead of
/// two that happen to agree.
pub struct FramingScan<'a> {
    stream: FramingStream<Cursor<&'a [u8]>>,
    /// The slice's own length, reported by [`Self::finish`] exactly as before,
    /// even when the caller stopped before the end.
    sealed_len: u64,
}

impl<'a> FramingScan<'a> {
    /// Start a scan over one sealed input.
    #[must_use]
    pub fn new(sealed: &'a [u8], format: SourceFormat) -> Self {
        Self {
            stream: FramingStream::new(Cursor::new(sealed), format),
            sealed_len: sealed.len() as u64,
        }
    }

    /// Whether the scan has consumed every byte it was given.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.stream.is_done()
    }

    /// Take the next page of at most `limit` frames.
    ///
    /// Blank lines advance the scan without producing a frame, so a page can
    /// legitimately come back empty while the scan is still running; callers
    /// drive the loop on [`Self::is_done`], not on the page being non-empty.
    ///
    /// # Errors
    /// `Overflow` when an ordinal or byte counter would not fit a `u64`; `Io`
    /// when the input could not be read.
    pub fn next_page(
        &mut self,
        limit: usize,
    ) -> Result<Vec<FramedSourceRecord>, SourceInstallError> {
        self.stream.next_page(limit)
    }

    /// Consume the rest of the input without keeping any frame, for callers
    /// that only need the counters and the stream digest.
    ///
    /// # Errors
    /// `Overflow` when an ordinal or byte counter would not fit a `u64`; `Io`
    /// when the input could not be read.
    pub fn run_to_end(&mut self) -> Result<(), SourceInstallError> {
        self.stream.run_to_end()
    }

    /// Close the scan against the bytes it was given.
    ///
    /// `complete` reports whether every byte was consumed; a scan that stopped
    /// early still yields its counters, and the caller must not treat it as an
    /// authorisation.
    #[must_use]
    pub fn finish(self) -> FramingSummary {
        self.stream.finish_with_byte_len(self.sealed_len)
    }
}

/// One `cass.source-framing/1` leaf (§17.2): ordinal, empty pointer, the
/// record's byte range and its own digest, all as JSON strings.
fn framing_leaf(ordinal: u64, byte_start: u64, byte_end: u64, raw_sha256: &Sha256Digest) -> Vec<u8> {
    let mut tuple = CanonicalTuple::new();
    tuple
        .str(&ordinal.to_string())
        .str("")
        .str(&byte_start.to_string())
        .str(&byte_end.to_string())
        .str(&raw_sha256.hex());
    tuple.finish()
}

/// A TEXT value written as its raw UTF-8 bytes into a BLOB column.
fn text_bin(value: &str) -> Value {
    Value::Blob(value.as_bytes().to_vec())
}

/// An optional TEXT value written as raw UTF-8 bytes, or SQL NULL.
fn optional_text_bin(value: Option<&str>) -> Value {
    match value {
        Some(value) => text_bin(value),
        None => Value::Null,
    }
}

/// `ordinal`'s persisted form: an 8-byte big-endian blob (§4).
fn ordinal_blob(value: u64) -> Value {
    Value::Blob(u64_be8(value).to_vec())
}

/// Commit-time material for one staged record row.
fn record_row_values(record: &VerifiedStagedRecord) -> Result<Vec<Value>, SourceInstallError> {
    // §20.6: `position_bin` is the untagged locator quadruple, not §10's
    // domain-tagged canonical tuple.
    let position_bin = Value::Blob(record.locator.to_array());
    let native_ids_bin = match &record.native_ids {
        Some(value) => Value::Blob(lossless_bin(value)?),
        None => Value::Null,
    };
    let diagnostics_bin = match &record.diagnostics {
        Some(items) => Value::Blob(encode_envelope(&DiagnosticsEnvelope {
            version: SOURCE_ENVELOPE_VERSION,
            domain: SOURCE_DIAGNOSTICS_DOMAIN.to_string(),
            items: items.clone(),
        })?),
        None => Value::Null,
    };
    // The payload envelope and the safe-value hash are produced here from the
    // verified tree; a caller-supplied BLOB is never trusted (§10).
    let (codec, payload_bin, safe_value_hash) = match &record.safe_value {
        Some(value) => (
            Value::Text(super::source_codec::SAFE_SOURCE_CODEC_ID.to_string()),
            Value::Blob(
                super::source_codec::encode_safe_source(value).map_err(SourceInstallError::Codec)?,
            ),
            Value::Blob(safe_value_sha256(value)?.as_bytes().to_vec()),
        ),
        None => (Value::Null, Value::Null, Value::Null),
    };
    Ok(vec![
        ordinal_blob(record.locator.ordinal),
        Value::Text(record.locator.record_pointer.clone()),
        position_bin,
        Value::Blob(record.expected_raw_sha256.as_bytes().to_vec()),
        match &record.observed_raw_sha256 {
            Some(digest) => Value::Blob(digest.as_bytes().to_vec()),
            None => Value::Null,
        },
        Value::Text(record.parse_state.as_str().to_string()),
        Value::Text(record.record_mapping_state.as_str().to_string()),
        Value::Text(record.safety_state.as_str().to_string()),
        Value::Text(record.retention_state.as_str().to_string()),
        codec,
        payload_bin,
        safe_value_hash,
        native_ids_bin,
        diagnostics_bin,
    ])
}

/// Stage one bounded page of records for `input` (§11).
///
/// Registers the parent `source_inputs` row on first sight and keeps it at
/// `staged`, then inserts or refreshes this page's `source_records` rows with
/// `frame_state = 'frame_pending'`. Whole-input completion, the `activated`
/// frame transition, the witnesses and the receipt all belong to
/// [`activate_source_input_in_tx`]; this primitive never touches the reader
/// revision or the content generation.
///
/// # Errors
/// Propagates the storage failure typed, and refuses a page whose `input_key`
/// disagrees with the parent it found.
pub fn stage_source_records_in_tx(
    tx: &Tx<'_>,
    input: &VerifiedSourceInput,
    records: &[VerifiedStagedRecord],
) -> Result<StageOutcome, SourceInstallError> {
    let input_key = input.input_key.as_bytes().to_vec();
    let existing: Option<i64> = tx
        .query_opt_map(
            "SELECT id FROM source_inputs WHERE input_key = ?1",
            &[Value::Blob(input_key.clone())],
            |row| row.get_typed(0),
        )?;

    let (input_id, registered, updated) = match existing {
        None => {
            let manifest_bin = encode_expected_manifest_header(&input.manifest, &input.safety_identity);
            let inserted = tx.execute(
                "INSERT INTO source_inputs (
                     input_key, identity_tuple_bin, source_id, identity_namespace, connector,
                     origin_host, origin_source_version, role_bin, platform_bin,
                     root_id_bin, relative_locator_bin, discovery_bin, parser_context_bin,
                     context_digest, sealed_ref_bin, sealed_sha256, byte_len, format,
                     expected_manifest_bin, normalizer_id, safety_contract_id, state,
                     expected_records, expected_blank_lines)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                     ?17, ?18, ?19, ?20, ?21, 'staged', ?22, ?23)",
                &[
                    Value::Blob(input_key.clone()),
                    Value::Blob(identity_tuple_bin(&input.identity_tuple)),
                    Value::Text(input.source_id.clone()),
                    Value::Text(input.identity_namespace.clone()),
                    Value::Text(input.connector.clone()),
                    optional_text_bin(input.origin_host.as_deref()),
                    optional_text_bin(input.origin_source_version.as_deref()),
                    optional_text_bin(input.role.as_deref()),
                    optional_text_bin(input.platform.as_deref()),
                    text_bin(&input.root_id),
                    text_bin(&input.relative_locator),
                    Value::Blob(lossless_bin(&input.discovery)?),
                    Value::Blob(lossless_bin(&input.parser_context)?),
                    Value::Blob(input.context_digest.as_bytes().to_vec()),
                    Value::Blob(lossless_bin(&input.sealed_ref)?),
                    Value::Blob(input.sealed_sha256.as_bytes().to_vec()),
                    ordinal_blob(input.byte_len),
                    Value::Text(input.format.as_str().to_string()),
                    Value::Blob(manifest_bin),
                    Value::Text(input.normalizer_id.clone()),
                    Value::Text(input.safety_contract_id.clone()),
                    ordinal_blob(input.manifest.records),
                    ordinal_blob(input.manifest.blank_lines),
                ],
            )?;
            if inserted != 1 {
                return Err(SourceInstallError::Conflict {
                    detail: "source input insert did not write exactly one row".to_string(),
                });
            }
            (tx.last_insert_rowid(), 1, 0)
        }
        Some(input_id) => {
            let stored_key: Vec<u8> = tx.query_row_map(
                "SELECT input_key FROM source_inputs WHERE id = ?1",
                &[Value::Integer(input_id)],
                |row| row.get_typed(0),
            )?;
            if stored_key != input_key {
                return Err(SourceInstallError::Conflict {
                    detail: "staged input_key disagrees with the registered parent".to_string(),
                });
            }
            // The parent already exists: refresh the expected counts, and
            // report it as verified-same rather than rewriting the identity.
            tx.execute(
                "UPDATE source_inputs SET expected_records = ?1, expected_blank_lines = ?2
                 WHERE id = ?3",
                &[
                    ordinal_blob(input.manifest.records),
                    ordinal_blob(input.manifest.blank_lines),
                    Value::Integer(input_id),
                ],
            )?;
            (input_id, 0, 1)
        }
    };

    let mut verified_same: u64 = 0;
    let mut page_updated: u64 = 0;
    for record in records {
        // `record_row_values` order: 0 ordinal, 1 pointer, 2 position_bin,
        // 3 expected sha, 4 observed sha, 5 parse, 6 mapping, 7 safety,
        // 8 retention, 9 codec, 10 payload, 11 safe hash, 12 native ids,
        // 13 diagnostics.
        let row = record_row_values(record)?;
        let stored: Option<StoredRecordShape> = tx.query_opt_map(
            "SELECT position_bin, expected_source_record_sha256, observed_source_record_sha256,
                    parse_state, record_mapping_state, safety_state, retention_state, codec,
                    payload_bin, safe_value_hash, native_ids_bin, diagnostics_bin
             FROM source_records WHERE input_id = ?1 AND ordinal = ?2 AND record_pointer = ?3",
            &[
                Value::Integer(input_id),
                ordinal_blob(record.locator.ordinal),
                Value::Text(record.locator.record_pointer.clone()),
            ],
            |row| {
                Ok((
                    row.get_typed(0)?,
                    row.get_typed(1)?,
                    row.get_typed(2)?,
                    row.get_typed(3)?,
                    row.get_typed(4)?,
                    row.get_typed(5)?,
                    row.get_typed(6)?,
                    row.get_typed(7)?,
                    row.get_typed(8)?,
                    row.get_typed(9)?,
                    row.get_typed(10)?,
                    row.get_typed(11)?,
                ))
            },
        )?;

        match stored {
            None => {
                tx.execute(
                    "INSERT INTO source_records (
                         input_id, ordinal, record_pointer, position_bin,
                         expected_source_record_sha256, observed_source_record_sha256,
                         frame_state, parse_state, record_mapping_state, safety_state,
                         retention_state, codec, payload_bin, safe_value_hash, native_ids_bin,
                         diagnostics_bin)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'frame_pending', ?7, ?8, ?9, ?10, ?11, ?12,
                         ?13, ?14, ?15)",
                    &[
                        Value::Integer(input_id),
                        row[0].clone(),
                        row[1].clone(),
                        row[2].clone(),
                        row[3].clone(),
                        row[4].clone(),
                        row[5].clone(),
                        row[6].clone(),
                        row[7].clone(),
                        row[8].clone(),
                        row[9].clone(),
                        row[10].clone(),
                        row[11].clone(),
                        row[12].clone(),
                        row[13].clone(),
                    ],
                )?;
            }
            Some(stored) => {
                let incoming: StoredRecordShape = (
                    expect_blob(&row[2], "position_bin")?,
                    expect_blob(&row[3], "expected sha")?,
                    optional_blob(&row[4]),
                    expect_text(&row[5], "parse_state")?,
                    expect_text(&row[6], "record_mapping_state")?,
                    expect_text(&row[7], "safety_state")?,
                    expect_text(&row[8], "retention_state")?,
                    optional_text(&row[9]),
                    optional_blob(&row[10]),
                    optional_blob(&row[11]),
                    optional_blob(&row[12]),
                    optional_blob(&row[13]),
                );
                if stored == incoming {
                    // Re-staging identical facts is a no-op, not a rewrite.
                    verified_same += 1;
                } else {
                    tx.execute(
                        "UPDATE source_records SET
                             position_bin = ?1, expected_source_record_sha256 = ?2,
                             observed_source_record_sha256 = ?3, parse_state = ?4,
                             record_mapping_state = ?5, safety_state = ?6, retention_state = ?7,
                             codec = ?8, payload_bin = ?9, safe_value_hash = ?10,
                             native_ids_bin = ?11, diagnostics_bin = ?12
                         WHERE input_id = ?13 AND ordinal = ?14 AND record_pointer = ?15",
                        &[
                            row[2].clone(),
                            row[3].clone(),
                            row[4].clone(),
                            row[5].clone(),
                            row[6].clone(),
                            row[7].clone(),
                            row[8].clone(),
                            row[9].clone(),
                            row[10].clone(),
                            row[11].clone(),
                            row[12].clone(),
                            row[13].clone(),
                            Value::Integer(input_id),
                            row[0].clone(),
                            row[1].clone(),
                        ],
                    )?;
                    page_updated += 1;
                }
            }
        }
    }
    Ok(StageOutcome {
        input_id,
        registered,
        updated: updated + page_updated,
        verified_same,
        last_locator: records.last().map(|record| record.locator.clone()),
    })
}

/// The comparable shape of one stored `source_records` row.
type StoredRecordShape = (
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

fn expect_blob(value: &Value, field: &str) -> Result<Vec<u8>, SourceInstallError> {
    match value {
        Value::Blob(bytes) => Ok(bytes.clone()),
        other => Err(SourceInstallError::Staging {
            detail: format!("{field} is not a BLOB: {other:?}"),
        }),
    }
}

fn optional_blob(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Blob(bytes) => Some(bytes.clone()),
        _ => None,
    }
}

fn expect_text(value: &Value, field: &str) -> Result<String, SourceInstallError> {
    match value {
        Value::Text(text) => Ok(text.clone()),
        other => Err(SourceInstallError::Staging {
            detail: format!("{field} is not TEXT: {other:?}"),
        }),
    }
}

fn optional_text(value: &Value) -> Option<String> {
    match value {
        Value::Text(text) => Some(text.clone()),
        _ => None,
    }
}

// =============================================================================
// Link installation (§9, §11)
// =============================================================================

/// One claim to install together with the installation the projection produced
/// for it, if any (§9).
#[derive(Debug, Clone)]
pub struct ClaimLinkInstall {
    pub claim: SourceClaim,
    pub installation: Option<OriginalInstallation>,
}

/// What one bounded link page did (§10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkInstallOutcome {
    pub inserted: u64,
    pub verified_same: u64,
    pub canonical: u64,
    pub standalone: u64,
    pub unmapped: u64,
    pub unresolved: u64,
    pub last_key: Option<(u64, String, String)>,
}

/// The canonical `binding_digest` of one installed claim: the SHA-256 of the
/// binding leaf, which embeds the claim leaf and the original installation
/// (§9, §19).
pub fn binding_digest(claim: &SourceClaim, installation: &OriginalInstallation) -> Sha256Digest {
    let leaf = encode_binding_leaf(1, &claim.encode_leaf(), &installation.encode());
    Sha256Digest::of(&leaf)
}

/// One stored `source_message_links` row, as the SQL columns report it.
struct StoredLinkRow {
    digest: Vec<u8>,
    positions: Vec<u8>,
    authority: Option<String>,
    message_id: Option<i64>,
    conversation_ordinal: Option<i64>,
    final_message_idx: Option<i64>,
    projection_pointer: Option<String>,
    evidence_kind: String,
}

/// Decode a stored link's envelope and require the row's own SQL columns to
/// agree with the claim, installation and authority it carries (§9/§10).
///
/// A stored envelope that does not decode, or whose columns disagree with it, is
/// `Corrupt` (§571): it is never repaired in place, never upgraded, and never
/// reported as verified. Reading the columns instead of trusting them is what
/// stops a drifted row from being masked by the branch that replaces it.
///
/// The authority/message pairing is checked against the installation's own
/// class, because those two columns are what readers act on: a `CanonicalBound`
/// row is `canonical` with its live original message or `historical` with no
/// message (the original need not survive), and every other class is its own
/// authority with no live message.
fn decode_stored_link_row(
    tx: &Tx<'_>,
    row: &StoredLinkRow,
) -> Result<LinkEvidence, SourceInstallError> {
    let corrupt = |detail: String| SourceInstallError::Corrupt { detail };
    let evidence = decode_link_evidence(&row.positions)
        .map_err(|err| corrupt(format!("the stored LinkEvidence does not decode: {err}")))?;
    let (conversation_ordinal, final_message_idx, projection_pointer) =
        target_triple(&evidence.claim);
    let ordinal_agrees = match (row.conversation_ordinal, conversation_ordinal) {
        (Some(stored), Value::Integer(claim)) => stored == claim,
        (None, Value::Null) => true,
        _ => false,
    };
    let idx_agrees = match (row.final_message_idx, final_message_idx) {
        (Some(stored), Value::Integer(claim)) => stored == claim,
        (None, Value::Null) => true,
        _ => false,
    };
    let pointer_agrees = match (row.projection_pointer.as_deref(), projection_pointer) {
        (Some(stored), Value::Text(claim)) => stored == claim,
        (None, Value::Null) => true,
        _ => false,
    };
    if !ordinal_agrees || !idx_agrees || !pointer_agrees
        || row.evidence_kind != evidence.claim.evidence_kind.as_str()
    {
        return Err(corrupt(
            "the stored link's columns disagree with the claim its envelope carries".to_string(),
        ));
    }

    // The digest column must be exactly what this envelope recomputes to; a
    // damaged digest is a corruption, not a conflicting witness.
    let envelope_digest = match &evidence.installation {
        Some(installation) => binding_digest(&evidence.claim, installation),
        None => evidence.claim.pending_claim_digest(),
    };
    if row.digest != envelope_digest.as_bytes().to_vec() {
        return Err(corrupt(
            "the stored link's digest column does not match its envelope".to_string(),
        ));
    }

    // A digest that agrees with its own envelope says nothing about whether the
    // envelope is a legal shape for its class.
    if let Some(installation) = &evidence.installation
        && (!installation_shape_matches_class(installation)
            || !claim_shape_matches_class(&evidence.claim, installation.class))
    {
        return Err(corrupt(format!(
            "a {} installation does not carry the members its class requires",
            installation.class.as_str()
        )));
    }

    let authority = row.authority.as_deref();
    match (&evidence.installation, authority) {
        (None, None) if row.message_id.is_none() => {}
        (None, _) => {
            return Err(corrupt(
                "a link with no installation must carry no authority and no message".to_string(),
            ));
        }
        (Some(installation), Some(authority)) => match installation.class {
            InstallationClass::CanonicalBound => {
                let binding = installation.binding.as_ref().ok_or_else(|| corrupt(
                    "a canonical installation must carry its binding".to_string(),
                ))?;
                match authority {
                    "canonical" => {
                        if row.message_id != Some(binding.original_message_id) {
                            return Err(corrupt(
                                "a canonical link must point at the message its binding names"
                                    .to_string(),
                            ));
                        }
                        let live: Option<i64> = tx.query_opt_map(
                            "SELECT id FROM messages WHERE id = ?1",
                            &[Value::Integer(binding.original_message_id)],
                            |row| row.get_typed(0),
                        )?;
                        if live.is_none() {
                            return Err(corrupt(
                                "a canonical link's bound message must exist".to_string(),
                            ));
                        }
                    }
                    "historical" => {
                        if row.message_id.is_some() {
                            return Err(corrupt(
                                "a historical link must not point at a live message".to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(corrupt(format!(
                            "a canonical installation has no authority {authority}"
                        )));
                    }
                }
            }
            class => {
                if authority != authority_for(installation) || row.message_id.is_some() {
                    return Err(corrupt(format!(
                        "a {} link must be {} with no live message",
                        class.as_str(),
                        authority_for(installation)
                    )));
                }
            }
        },
        (Some(_), None) => {
            return Err(corrupt(
                "an installed link must carry its authority".to_string(),
            ));
        }
    }

    Ok(evidence)
}

/// The current authority a class installs at first sight (§9).
fn authority_for(installation: &OriginalInstallation) -> &'static str {
    match installation.class {
        InstallationClass::CanonicalBound => "canonical",
        InstallationClass::WinnerRejectedNoBinding => "historical",
        InstallationClass::UnresolvedNoBinding => "unresolved",
        InstallationClass::StandaloneNoBinding => "standalone",
        InstallationClass::UnmappedNoBinding => "unmapped",
    }
}

/// Whether an installation's own members match its class (SRC05A storage
/// contract §330, §381–§387).
///
/// A self-consistent digest is not enough: each class fixes which of the three
/// members it carries.
///
/// - `CanonicalBound` carries its binding, and neither of the other two;
/// - `WinnerRejectedNoBinding` carries its rejection and the winner-rejected
///   reason, and no binding;
/// - `UnresolvedNoBinding` carries a reason that is *not* a winner rejection,
///   and neither a binding nor a rejection;
/// - `StandaloneNoBinding` carries none of the three;
/// - `UnmappedNoBinding` carries neither a binding nor a rejection. Its reason
///   is deliberately left unconstrained: the contract does not fix it, and this
///   guard does not invent a stricter rule than the frozen one.
#[must_use]
fn installation_shape_matches_class(installation: &OriginalInstallation) -> bool {
    match installation.class {
        InstallationClass::CanonicalBound => {
            installation.binding.is_some()
                && installation.rejection.is_none()
                && installation.reason.is_none()
        }
        InstallationClass::WinnerRejectedNoBinding => {
            installation.binding.is_none()
                && installation.rejection.is_some()
                && installation.reason == Some(ReplayRejectReason::WinnerRejected)
        }
        InstallationClass::UnresolvedNoBinding => {
            installation.binding.is_none()
                && installation.rejection.is_none()
                && matches!(
                    installation.reason,
                    Some(reason) if reason != ReplayRejectReason::WinnerRejected
                )
        }
        InstallationClass::StandaloneNoBinding => {
            installation.binding.is_none()
                && installation.rejection.is_none()
                && installation.reason.is_none()
        }
        InstallationClass::UnmappedNoBinding => {
            installation.binding.is_none() && installation.rejection.is_none()
        }
    }
}

/// Whether a claim's own members match the class its installation carries
/// (SRC05A storage contract §330, §381–§387).
///
/// The class fixes which claim it can belong to, not only which installation
/// members travel with it: a canonical binding belongs to a canonical claim, a
/// standalone binding to a `standalone`/`no_message` claim with no target
/// triple, an unmapped binding to an `unmapped`/`parse_failed` claim with no
/// target triple, and an unresolved or winner-rejected installation to a
/// canonical claim that has one.
#[must_use]
fn claim_shape_matches_class(claim: &SourceClaim, class: InstallationClass) -> bool {
    let has_target = claim.conversation_ordinal.is_some()
        && claim.final_message_idx.is_some()
        && claim.projection_pointer.is_some();
    let has_no_target = claim.conversation_ordinal.is_none()
        && claim.final_message_idx.is_none()
        && claim.projection_pointer.is_none();
    match class {
        InstallationClass::CanonicalBound
        | InstallationClass::UnresolvedNoBinding
        | InstallationClass::WinnerRejectedNoBinding => {
            claim.mapping_state == ClaimMappingState::Canonical && has_target
        }
        InstallationClass::StandaloneNoBinding => {
            claim.mapping_state == ClaimMappingState::Standalone
                && claim.evidence_kind == EvidenceKind::NoMessage
                && has_no_target
        }
        InstallationClass::UnmappedNoBinding => {
            claim.mapping_state == ClaimMappingState::Unmapped
                && claim.evidence_kind == EvidenceKind::ParseFailed
                && has_no_target
        }
    }
}

/// The live `message_id` a class installs at first sight, or `None` (§9).
fn message_id_for(installation: &OriginalInstallation) -> Option<i64> {
    match installation.class {
        InstallationClass::CanonicalBound => {
            installation.binding.as_ref().map(|binding| binding.original_message_id)
        }
        _ => None,
    }
}

/// A column value carrying the claim's nullable target triple (§9).
fn target_triple(claim: &SourceClaim) -> (Value, Value, Value) {
    (
        match claim.conversation_ordinal {
            Some(value) => Value::Integer(i64::from(value)),
            None => Value::Null,
        },
        match claim.final_message_idx {
            Some(value) => Value::Integer(value),
            None => Value::Null,
        },
        match &claim.projection_pointer {
            Some(value) => Value::Text(value.clone()),
            None => Value::Null,
        },
    )
}

/// What one input's link row already carries for one claim (§9), read-only
/// (SRC05B-08).
///
/// A retry of an input whose links were already published must not present
/// those claims as *pending* again: the witness is immutable once installed
/// (§14.2), so the caller hands the original installation back to
/// [`install_source_links_in_tx`] instead of `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstalledLinkEvidence {
    /// No link row exists for this `(record, projection)`.
    Absent,
    /// The row exists and still carries the pending-claim form: no installation
    /// was ever promised for it.
    Pending,
    /// The row's own verified installation.
    Installed(Box<OriginalInstallation>),
}

/// The installation one input's link row already carries for `claim`, or why
/// it carries none.
///
/// Everything the install path checks is checked here, on the same
/// `(input_id, claim)` the caller will install: the parent row's `input_key`,
/// the record the claim names, and the stored envelope through
/// [`decode_stored_link_row`] (envelope decodes, columns agree with the claim,
/// digest column equals the recomputed digest, authority and message id agree
/// with the installation). The stored claim must equal `claim` field by field.
///
/// Three outcomes are kept apart on purpose, because a caller may only reuse
/// what was really installed: an absent row and a legitimate pending row are
/// *not* evidence of an installation, and a row that does not decode, belongs
/// to another input, or encodes another claim is an error rather than a
/// fallback to `None`.
///
/// This is a read: it issues no `UPDATE`, `DELETE` or `INSERT`.
///
/// # Errors
/// `Conflict` when the parent row or the stored envelope names a different
/// input or claim, `Staging` when the claim's record is not staged under
/// `input_id`, and `Corrupt` when the stored row does not decode or its columns
/// disagree with its envelope.
pub fn read_installed_link_evidence(
    tx: &Tx<'_>,
    input_id: i64,
    claim: &SourceClaim,
) -> Result<InstalledLinkEvidence, SourceInstallError> {
    let input_key: Option<Vec<u8>> = tx.query_opt_map(
        "SELECT input_key FROM source_inputs WHERE id = ?1",
        &[Value::Integer(input_id)],
        |row| row.get_typed(0),
    )?;
    match input_key {
        None => {
            return Err(SourceInstallError::Staging {
                detail: format!("input {input_id} is not registered"),
            });
        }
        Some(stored_key) if stored_key != claim.input_key.as_bytes().to_vec() => {
            return Err(SourceInstallError::Conflict {
                detail: format!("claim for input {} was handed to input {input_id}", claim.input_key.hex()),
            });
        }
        Some(_) => {}
    }

    let record_id: Option<i64> = tx.query_opt_map(
        "SELECT id FROM source_records
         WHERE input_id = ?1 AND ordinal = ?2 AND record_pointer = ?3",
        &[
            Value::Integer(input_id),
            ordinal_blob(claim.record_ordinal),
            Value::Text(claim.record_pointer.clone()),
        ],
        |row| row.get_typed(0),
    )?;
    let Some(record_id) = record_id else {
        return Err(SourceInstallError::Staging {
            detail: format!(
                "claim for record {} ordinal {} is not staged under input {input_id}",
                claim.record_pointer, claim.record_ordinal
            ),
        });
    };

    let projection_key = claim.projection_key();
    let stored = tx.query_opt_map(
        "SELECT binding_digest, source_positions_bin, authority, message_id,
                conversation_ordinal, final_message_idx, projection_pointer, evidence_kind
         FROM source_message_links
         WHERE record_id = ?1 AND projection_key = ?2",
        &[Value::Integer(record_id), Value::Blob(projection_key.as_bytes().to_vec())],
        |row| {
            Ok(StoredLinkRow {
                digest: row.get_typed::<Vec<u8>>(0)?,
                positions: row.get_typed::<Vec<u8>>(1)?,
                authority: row.get_typed::<Option<String>>(2)?,
                message_id: row.get_typed::<Option<i64>>(3)?,
                conversation_ordinal: row.get_typed::<Option<i64>>(4)?,
                final_message_idx: row.get_typed::<Option<i64>>(5)?,
                projection_pointer: row.get_typed::<Option<String>>(6)?,
                evidence_kind: row.get_typed::<String>(7)?,
            })
        },
    )?;
    let Some(stored) = stored else {
        return Ok(InstalledLinkEvidence::Absent);
    };

    let envelope = decode_stored_link_row(tx, &stored)?;
    if envelope.claim != *claim {
        return Err(SourceInstallError::Conflict {
            detail: format!(
                "the stored link for projection {:?} of record {} encodes another claim",
                claim.projection_pointer, claim.record_pointer
            ),
        });
    }
    Ok(match envelope.installation {
        Some(installation) => InstalledLinkEvidence::Installed(Box::new(installation)),
        None => InstalledLinkEvidence::Pending,
    })
}

/// Install one bounded page of claim links for `input_id` (§11).
///
/// Each row stores the versioned LinkEvidence envelope, the claim's
/// `projection_key` and either the real binding digest (when the projection
/// produced an installation) or the domain-tagged pending-claim digest (§9,
/// §19). A claim that already carries the same digest is left alone; a claim
/// whose stored digest disagrees is refused rather than overwritten, because
/// the witness and its digest are immutable once installed.
///
/// # Errors
/// Refuses a claim whose record is not staged under `input_id`, and a
/// winner-rejection installation that arrives without its conversation identity
/// digest.
pub fn install_source_links_in_tx(
    tx: &Tx<'_>,
    input_id: i64,
    links: &[ClaimLinkInstall],
) -> Result<LinkInstallOutcome, SourceInstallError> {
    let mut outcome = LinkInstallOutcome::default();

    for link in links {
        let claim = &link.claim;
        // The claim must belong to the input it is being installed under, or
        // the record lookup below would happily bind it to another input's row.
        let parent_input_key: Option<Vec<u8>> = tx.query_opt_map(
            "SELECT input_key FROM source_inputs WHERE id = ?1",
            &[Value::Integer(input_id)],
            |row| row.get_typed(0),
        )?;
        let Some(parent_input_key) = parent_input_key else {
            return Err(SourceInstallError::Staging {
                detail: format!("input {input_id} is not staged"),
            });
        };
        if parent_input_key != claim.input_key.as_bytes().to_vec() {
            return Err(SourceInstallError::Staging {
                detail: format!(
                    "claim for record {} ordinal {} belongs to another input",
                    claim.record_pointer, claim.record_ordinal
                ),
            });
        }
        let record_id: Option<i64> = tx.query_opt_map(
            "SELECT id FROM source_records
             WHERE input_id = ?1 AND ordinal = ?2 AND record_pointer = ?3",
            &[
                Value::Integer(input_id),
                ordinal_blob(claim.record_ordinal),
                Value::Text(claim.record_pointer.clone()),
            ],
            |row| row.get_typed(0),
        )?;
        let Some(record_id) = record_id else {
            return Err(SourceInstallError::Staging {
                detail: format!(
                    "claim for record {} ordinal {} is not staged under input {input_id}",
                    claim.record_pointer, claim.record_ordinal
                ),
            });
        };

        let digest = match &link.installation {
            Some(installation) => binding_digest(claim, installation),
            None => claim.pending_claim_digest(),
        };
        let projection_key = claim.projection_key();

        let stored = tx.query_opt_map(
            "SELECT binding_digest, source_positions_bin, authority, message_id,
                    conversation_ordinal, final_message_idx, projection_pointer, evidence_kind
             FROM source_message_links
             WHERE record_id = ?1 AND projection_key = ?2",
            &[Value::Integer(record_id), Value::Blob(projection_key.as_bytes().to_vec())],
            |row| {
                Ok(StoredLinkRow {
                    digest: row.get_typed::<Vec<u8>>(0)?,
                    positions: row.get_typed::<Vec<u8>>(1)?,
                    authority: row.get_typed::<Option<String>>(2)?,
                    message_id: row.get_typed::<Option<i64>>(3)?,
                    conversation_ordinal: row.get_typed::<Option<i64>>(4)?,
                    final_message_idx: row.get_typed::<Option<i64>>(5)?,
                    projection_pointer: row.get_typed::<Option<String>>(6)?,
                    evidence_kind: row.get_typed::<String>(7)?,
                })
            },
        )?;

        if let Some(stored) = stored {
            // Both branches below read the stored row's own bytes and columns.
            // A row that does not decode, or whose columns disagree with its
            // envelope, is `Corrupt` whether or not its digest column moved.
            let envelope = decode_stored_link_row(tx, &stored)?;
            if stored.digest == digest.as_bytes().to_vec() {
                if envelope.claim != *claim
                    || envelope.installation.as_ref() != link.installation.as_ref()
                {
                    return Err(SourceInstallError::Corrupt {
                        detail: format!(
                            "the stored link for projection {:?} hashes to the recomputed digest \
                             but does not encode that claim and installation",
                            claim.projection_pointer
                        ),
                    });
                }
                outcome.verified_same += 1;
            } else if link.installation.is_some()
                && stored.authority.is_none()
                && stored.message_id.is_none()
                && envelope.installation.is_none()
                && envelope.claim.pending_claim_digest().as_bytes() == stored.digest.as_slice()
                && envelope.claim.pending_claim_digest() == claim.pending_claim_digest()
            {
                // §6/§8: a claim staged without an installation carries the
                // pending-claim digest and no authority. Its **first** real
                // installation replaces that pending form in place; from then on
                // the witness is immutable, which the branch above covers.
                let installation = link.installation.as_ref().expect("checked above");
                let positions = encode_link_evidence(claim, Some(installation))?;
                let (authority, message_id) = (
                    Value::Text(authority_for(installation).to_string()),
                    match message_id_for(installation) {
                        Some(value) => Value::Integer(value),
                        None => Value::Null,
                    },
                );
                tx.execute(
                    "UPDATE source_message_links
                     SET source_positions_bin = ?1, message_id = ?2, authority = ?3,
                         binding_digest = ?4
                     WHERE record_id = ?5 AND projection_key = ?6",
                    &[
                        Value::Blob(positions),
                        message_id,
                        authority,
                        Value::Blob(digest.as_bytes().to_vec()),
                        Value::Integer(record_id),
                        Value::Blob(projection_key.as_bytes().to_vec()),
                    ],
                )?;
                outcome.inserted += 1;
                match installation.class {
                    InstallationClass::CanonicalBound => outcome.canonical += 1,
                    InstallationClass::StandaloneNoBinding => outcome.standalone += 1,
                    InstallationClass::UnmappedNoBinding => outcome.unmapped += 1,
                    InstallationClass::UnresolvedNoBinding
                    | InstallationClass::WinnerRejectedNoBinding => outcome.unresolved += 1,
                }
            } else {
                return Err(SourceInstallError::Conflict {
                    detail: format!(
                        "installed link for projection {:?} of record {} disagrees with the \
                         recomputed digest",
                        claim.projection_pointer, claim.record_pointer
                    ),
                });
            }
        } else {
            let positions = encode_link_evidence(claim, link.installation.as_ref())?;
            let (conversation_ordinal, final_message_idx, projection_pointer) = target_triple(claim);
            let (authority, message_id) = match &link.installation {
                Some(installation) => (
                    Value::Text(authority_for(installation).to_string()),
                    match message_id_for(installation) {
                        Some(value) => Value::Integer(value),
                        None => Value::Null,
                    },
                ),
                None => (Value::Null, Value::Null),
            };
            tx.execute(
                "INSERT INTO source_message_links (
                     record_id, projection_key, conversation_ordinal, final_message_idx,
                     source_positions_bin, projection_pointer, message_id, authority,
                     evidence_kind, binding_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                &[
                    Value::Integer(record_id),
                    Value::Blob(projection_key.as_bytes().to_vec()),
                    conversation_ordinal,
                    final_message_idx,
                    Value::Blob(positions),
                    projection_pointer,
                    message_id,
                    authority,
                    Value::Text(claim.evidence_kind.as_str().to_string()),
                    Value::Blob(digest.as_bytes().to_vec()),
                ],
            )?;
            outcome.inserted += 1;
            match link.installation.as_ref().map(|value| value.class) {
                Some(InstallationClass::CanonicalBound) => outcome.canonical += 1,
                Some(InstallationClass::StandaloneNoBinding) => outcome.standalone += 1,
                Some(InstallationClass::UnmappedNoBinding) => outcome.unmapped += 1,
                Some(InstallationClass::UnresolvedNoBinding)
                | Some(InstallationClass::WinnerRejectedNoBinding)
                | None => outcome.unresolved += 1,
            }
        }
        outcome.last_key = Some((
            claim.record_ordinal,
            claim.record_pointer.clone(),
            projection_key.hex(),
        ));
    }

    Ok(outcome)
}

// =============================================================================
// Conversation projection (§10, §11)
// =============================================================================

/// Domain of the parent conversation identity digest (§9's
/// `conversation_identity_digest`).
pub const SOURCE_CONVERSATION_IDENTITY_DOMAIN: &str = "cass.source-conversation-identity/1";

/// The real outcome of one incoming message (§10: `IncomingMessageBinding`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncomingStatus {
    AcceptedNew,
    VerifiedReplay,
    Rejected,
    Unresolved,
}

impl IncomingStatus {
    /// Closed spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedNew => "AcceptedNew",
            Self::VerifiedReplay => "VerifiedReplay",
            Self::Rejected => "Rejected",
            Self::Unresolved => "Unresolved",
        }
    }
}

/// The incoming side of a replay comparison (§10: `ReplayCandidateMatch`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCandidateMatch {
    pub created_at: Option<i64>,
    pub role: String,
    pub author: Option<String>,
    pub content_hash: String,
}

/// The stored side of a replay comparison (§10: `StoredBindingEvidence`),
/// every field read from the same transaction's SQL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBindingEvidence {
    pub outcome: OriginalBindingOutcome,
    pub conversation_id: i64,
    pub conversation_identity_digest: Sha256Digest,
    pub stored_idx: i64,
    pub original_message_id: i64,
    pub stored_merge_fingerprint: MergeFingerprint,
    pub safe_content_sha256: Sha256Digest,
    pub extra_storage_kind: ExtraStorageKind,
    pub extra_json_sha256: Option<Sha256Digest>,
    pub extra_bin_sha256: Option<Sha256Digest>,
    pub extra_semantic_digest: Option<Sha256Digest>,
    pub excluded_semantic_digest: Option<Sha256Digest>,
}

impl StoredBindingEvidence {
    /// The canonical `cass.source-original-binding/1` array (§5).
    #[must_use]
    pub fn to_original_binding(&self) -> OriginalBinding {
        OriginalBinding {
            outcome: self.outcome,
            original_conversation_id: self.conversation_id,
            original_message_id: self.original_message_id,
            stored_idx: self.stored_idx,
            stored_merge_fingerprint: self.stored_merge_fingerprint.clone(),
            safe_content_sha256: self.safe_content_sha256,
            extra_storage_kind: self.extra_storage_kind,
            extra_json_sha256: self.extra_json_sha256,
            extra_bin_sha256: self.extra_bin_sha256,
            extra_semantic_digest: self.extra_semantic_digest,
            excluded_semantic_digest: self.excluded_semantic_digest,
            conversation_identity_digest: self.conversation_identity_digest,
        }
    }
}

/// One incoming message's binding, exactly one per incoming (§10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingMessageBinding {
    pub incoming_final_message_idx: i64,
    pub status: IncomingStatus,
    pub candidate_match: Option<ReplayCandidateMatch>,
    pub stored: Option<StoredBindingEvidence>,
    pub reason: Option<ReplayRejectReason>,
}

/// What one source-aware conversation projection did (§10:
/// `SourceAwareInsertOutcome`).
///
/// `input_key` and `conversation_ordinal` are carried explicitly rather than
/// taken from the caller's slice position, because the batched entry points
/// order their outcomes by a *filtered* subset and a positional pairing would
/// silently mis-associate them (§11, counterexample 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAwareInsertOutcome {
    pub input_key: Sha256Digest,
    pub conversation_ordinal: u32,
    pub conversation_id: i64,
    pub conversation_inserted: bool,
    /// The parent conversation's identity digest, read from the resolved SQL
    /// parent row in the installing transaction (§9). Carried here because a
    /// `WinnerRejectedNoBinding` witness has to embed it and a rejection has no
    /// [`StoredBindingEvidence`] to carry it instead.
    pub conversation_identity_digest: Sha256Digest,
    pub incoming: Vec<IncomingMessageBinding>,
    /// §9: the winner-rejection witnesses this projection actually proved, each
    /// keyed by the **frozen claim digest** it was taken against.
    ///
    /// Private on purpose. Every witness in here was built where the claim and
    /// the merge's retained winner row were both in hand, and the map is the
    /// only way one reaches an installation; a caller can therefore read a
    /// witness but can neither write a field nor hand in a self-reported
    /// identity digest.
    winner_rejections: Vec<(Sha256Digest, WinnerRejectionEvidence)>,
}

impl SourceAwareInsertOutcome {
    /// Assemble an outcome. Only the projection calls this, with witnesses its
    /// own SQL branch produced.
    #[must_use]
    pub(crate) fn new(
        input_key: Sha256Digest,
        conversation_ordinal: u32,
        conversation_id: i64,
        conversation_inserted: bool,
        conversation_identity_digest: Sha256Digest,
        incoming: Vec<IncomingMessageBinding>,
        winner_rejections: Vec<(Sha256Digest, WinnerRejectionEvidence)>,
    ) -> Self {
        Self {
            input_key,
            conversation_ordinal,
            conversation_id,
            conversation_inserted,
            conversation_identity_digest,
            incoming,
            winner_rejections,
        }
    }

    /// The frozen witness this projection proved for `claim`, if any (§9).
    ///
    /// The lookup key is the claim's own digest, which covers the whole claim
    /// leaf — input key, record ordinal and pointer, conversation ordinal, final
    /// message index, projection pointer, evidence kind, mapping state and every
    /// safe position. A claim whose pointer or locator differs is a different
    /// claim and finds no witness, so a rejection can never be attached by
    /// numeric index alone.
    #[must_use]
    pub fn winner_rejection_for_claim(&self, claim: &SourceClaim) -> Option<&WinnerRejectionEvidence> {
        let digest = claim.pending_claim_digest();
        self.winner_rejections
            .iter()
            .find(|(key, _)| *key == digest)
            .map(|(_, evidence)| evidence)
    }

    /// §9/§11: the original installation this projection promised for `claim`,
    /// or `None` when this projection says nothing about that claim.
    ///
    /// The join is by the claim's own identity (`input_key`, conversation
    /// ordinal, final message index), never by slice position. An accepted or
    /// replay outcome becomes a `CanonicalBound` installation from the stored
    /// evidence; a rejection the merge really took becomes a
    /// `WinnerRejectedNoBinding` carrying the frozen rejection witness. A
    /// message the projection could not bind becomes `UnresolvedNoBinding` —
    /// never a fabricated canonical binding and never a fabricated rejection.
    #[must_use]
    pub fn installation_for_claim(
        &self,
        claim: &SourceClaim,
        semantic_request_digest: Sha256Digest,
    ) -> Option<OriginalInstallation> {
        if claim.input_key != self.input_key
            || claim.conversation_ordinal != Some(self.conversation_ordinal)
        {
            return None;
        }
        if let Some(rejection) = self.winner_rejection_for_claim(claim) {
            return Some(OriginalInstallation {
                semantic_request_digest,
                class: InstallationClass::WinnerRejectedNoBinding,
                binding: None,
                rejection: Some(rejection.clone()),
                reason: Some(ReplayRejectReason::WinnerRejected),
            });
        }
        let idx = claim.final_message_idx?;
        let binding = self
            .incoming
            .iter()
            .find(|binding| binding.incoming_final_message_idx == idx)?;
        match binding.status {
            IncomingStatus::AcceptedNew | IncomingStatus::VerifiedReplay => {
                let stored = binding.stored.as_ref()?;
                Some(OriginalInstallation {
                    semantic_request_digest,
                    class: InstallationClass::CanonicalBound,
                    binding: Some(stored.to_original_binding()),
                    rejection: None,
                    reason: None,
                })
            }
            IncomingStatus::Unresolved => Some(OriginalInstallation {
                semantic_request_digest,
                class: InstallationClass::UnresolvedNoBinding,
                binding: None,
                rejection: None,
                reason: binding.reason,
            }),
            IncomingStatus::Rejected => None,
        }
    }
}

/// The parent conversation identity digest (§9), as frozen by the controller's
/// 2026-10-13 ruling.
///
/// ```
/// SHA256(["cass.source-conversation-identity/1", library_identity,
///         conversation_id_decimal, identity_host, agent_id_decimal, locator])
/// ```
///
/// `locator` is `["external", external_id]` when the parent row carries an
/// external id (an empty string is preserved, never treated as NULL) and
/// `["source_path", source_path]` otherwise. Both SQL ids are written as `i64`
/// decimal strings, never through an `f64`. Mutable, non-identity attributes
/// (`title`, `workspace`, `source_id`, `started_at`, any derived rollup) are
/// deliberately absent: `source_id` is a first-ingest attribute and does not
/// take part in conversation identity, so a path change on the same parent row
/// cannot move the digest.
#[must_use]
pub fn conversation_identity_digest(
    library_identity: &str,
    conversation_id: i64,
    identity_host: &str,
    agent_id: i64,
    external_id: Option<&str>,
    source_path: &str,
) -> Sha256Digest {
    let mut tuple = CanonicalTuple::new();
    tuple.str(SOURCE_CONVERSATION_IDENTITY_DOMAIN);
    tuple.str(library_identity);
    tuple.idec(conversation_id);
    tuple.str(identity_host);
    tuple.idec(agent_id);
    match external_id {
        Some(external_id) => {
            let mut locator = CanonicalTuple::new();
            locator.str("external").str(external_id);
            tuple.raw(&locator.finish());
        }
        None => {
            let mut locator = CanonicalTuple::new();
            locator.str("source_path").str(source_path);
            tuple.raw(&locator.finish());
        }
    }
    tuple.finish_sha()
}

/// Check that a projection's incoming list is exactly one entry per incoming
/// message, with no repeated `idx` inside one projection (§8 rule 6).
///
/// A repeated `idx` is refused rather than deduplicated: `INSERT OR IGNORE`
/// would silently drop the second variant and make the outcome list lie about
/// what the projection contained.
///
/// # Errors
/// `Staging` when an `idx` repeats inside the same projection.
pub fn check_incoming_indices(indices: &[i64]) -> Result<(), SourceInstallError> {
    let mut sorted: Vec<i64> = indices.to_vec();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        if pair[0] == pair[1] {
            return Err(SourceInstallError::Staging {
                detail: format!(
                    "one projection carries the incoming message idx {} twice",
                    pair[0]
                ),
            });
        }
    }
    Ok(())
}

// =============================================================================
// Activation, publication and receipt verification (§11, §12, §13)
// =============================================================================

/// One activation request (§10 `SourceActivationRequest`).
#[derive(Debug, Clone)]
pub struct SourceActivationRequest {
    pub input_key: Sha256Digest,
    pub library_identity: String,
    pub normalizer_id: String,
    pub safety_contract_id: String,
    pub expected_manifest_digest: Sha256Digest,
    pub finish: VerifiedFinish,
    pub projection_disposition: ProjectionDisposition,
    pub source_semantic_records_root: Root,
    pub claims_root: Root,
    pub requested_terminal: TerminalState,
}

/// What one activation did (§10 `SourceActivationOutcome`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceActivationOutcome {
    /// The input stays staged: nothing reached the reader-visible set, so the
    /// revision is untouched.
    StagedOnly { input_id: i64, state: TerminalState },
    /// A final partial/failed result was published: the revision moved once,
    /// and no success receipt and no content generation were written.
    PublishedFailure {
        input_id: i64,
        state: TerminalState,
        source_facts_revision: u64,
        visible_facts_digest: Sha256Digest,
    },
    /// The input completed: A, the witnesses, B, the generation, the revision
    /// and the receipt all landed in this one transaction.
    Activated {
        input_id: i64,
        receipt_key: String,
        semantic_request_digest: Sha256Digest,
        installation_digest: Sha256Digest,
        generation: String,
        source_facts_revision: u64,
    },
    /// The same activation was already committed; the stored receipt is
    /// returned unchanged and nothing is written.
    Replay { receipt: VerifiedReceipt },
}

/// The committed activation receipt (§12), as a strict field structure rather
/// than an opaque string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReceipt {
    pub input_key: Sha256Digest,
    pub library_identity: String,
    pub semantic_request_digest: Sha256Digest,
    pub installation_digest: Sha256Digest,
    pub expected_manifest_digest: Sha256Digest,
    pub source_semantic_records_root: Root,
    pub claims_root: Root,
    pub immutable_records_root: Root,
    pub original_binding_root: Root,
    pub binding_class_counts: BindingClassCounts,
    pub terminal_state: TerminalState,
    pub applied_content_generation: String,
    pub committed_source_facts_revision: u64,
}

/// The outcome of verifying a stored receipt against the current database
/// (§10 `SourceReceiptMatch`). There is deliberately no second state enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceReceiptMatch {
    Absent,
    VerifiedReplay {
        receipt: Box<VerifiedReceipt>,
        currency: ReceiptCurrency,
    },
    Conflict { expected: Sha256Digest, found: Sha256Digest },
    Inconsistent { reason: ReceiptInconsistency },
}

/// Whether a verified receipt still describes the current winner (§10:
/// `Current | Historical | Mixed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptCurrency {
    Current,
    Historical,
    Mixed,
}

/// The versioned `unprocessed_ranges_bin` carrier (§6 column).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnprocessedRangesEnvelope {
    pub version: u32,
    pub domain: String,
    pub items: Vec<SourceUnprocessedRange>,
}

/// One measured activation attempt, appended to the versioned attempt history
/// (§13.6).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptRecord {
    pub attempt: u64,
    pub measured_finish: VerifiedFinish,
    pub outcome: String,
}

/// The versioned `attempt_history_bin` carrier (§13.6).
///
/// The successful finish and disposition are written once, in the activation
/// transaction that committed them, and never change afterwards; later
/// transient attempts are appended as independent records and never take part
/// in the committed success request's roots.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptHistory {
    pub version: u32,
    pub domain: String,
    pub original_success_finish: Option<VerifiedFinish>,
    pub attempts: Vec<AttemptRecord>,
    /// The `visible_facts_digest` of the last published failure, used to make a
    /// same-value failure replay idempotent (§13.4).
    pub last_published_failure: Option<Sha256Digest>,
}

impl AttemptHistory {
    /// An empty history at the current envelope version.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            version: SOURCE_ENVELOPE_VERSION,
            domain: SOURCE_ATTEMPT_HISTORY_DOMAIN.to_string(),
            original_success_finish: None,
            attempts: Vec::new(),
            last_published_failure: None,
        }
    }
}

/// Read and strictly decode the attempt history, treating an absent column as
/// an empty history.
fn read_attempt_history(blob: Option<&[u8]>) -> Result<AttemptHistory, SourceInstallError> {
    match blob {
        None => Ok(AttemptHistory::empty()),
        Some(bytes) => {
            let history: AttemptHistory = decode_envelope(bytes)?;
            if history.version != SOURCE_ENVELOPE_VERSION {
                return Err(SourceInstallError::Codec(SourceCodecError::UnsupportedVersion));
            }
            if history.domain != SOURCE_ATTEMPT_HISTORY_DOMAIN {
                return Err(SourceInstallError::Corrupt {
                    detail: "attempt history domain does not match the frozen value".to_string(),
                });
            }
            Ok(history)
        }
    }
}

/// The stored parent row of one source input, as activation reads it.
struct StoredSourceInput {
    id: i64,
    state: String,
    format: String,
    normalizer_id: String,
    safety_contract_id: String,
    expected_manifest_bin: Vec<u8>,
    receipt_key: Option<String>,
    applied_content_generation: Option<String>,
    attempt_history_bin: Option<Vec<u8>>,
    /// The semantic request digest the success committed to (§12).
    activation_request_hash: Option<Vec<u8>>,
}

fn read_source_input(
    tx: &Tx<'_>,
    input_key: &Sha256Digest,
) -> Result<Option<StoredSourceInput>, SourceInstallError> {
    Ok(tx.query_opt_map(
        "SELECT id, state, format, normalizer_id, safety_contract_id, expected_manifest_bin,
                receipt_key, applied_content_generation, attempt_history_bin,
                activation_request_hash
         FROM source_inputs WHERE input_key = ?1",
        &[Value::Blob(input_key.as_bytes().to_vec())],
        |row| {
            Ok(StoredSourceInput {
                id: row.get_typed(0)?,
                state: row.get_typed(1)?,
                format: row.get_typed(2)?,
                normalizer_id: row.get_typed(3)?,
                safety_contract_id: row.get_typed(4)?,
                expected_manifest_bin: row.get_typed(5)?,
                receipt_key: row.get_typed(6)?,
                applied_content_generation: row.get_typed(7)?,
                attempt_history_bin: row.get_typed(8)?,
                activation_request_hash: row.get_typed(9)?,
            })
        },
    )?)
}

/// One `source_records` row as the semantic leaf needs it.
struct StoredRecord {
    frame_state: String,
    leaf_input: StagedRecordLeafInput,
}

/// Decode `position_bin` (§20.6): the record-locator quadruple, checked against
/// the row's own `ordinal` and `record_pointer` columns.
fn decode_position_bin(
    bytes: &[u8],
    row_ordinal: u64,
    row_pointer: &str,
) -> Result<SourceRecordLocator, SourceInstallError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|err| {
        SourceInstallError::Corrupt { detail: format!("position_bin is not JSON: {err}") }
    })?;
    let items = value.as_array().ok_or_else(|| SourceInstallError::Corrupt {
        detail: "position_bin is not an array".to_string(),
    })?;
    if items.len() != 4 {
        return Err(SourceInstallError::Corrupt {
            detail: format!("position_bin has {} elements, expected 4", items.len()),
        });
    }
    let ordinal = header_decimal(&items[0], "position_bin.ordinal")?;
    let record_pointer = header_str(&items[1], "position_bin.record_pointer")?;
    let byte_start = header_decimal(&items[2], "position_bin.byte_start")?;
    let byte_end = header_decimal(&items[3], "position_bin.byte_end")?;
    if ordinal != row_ordinal || record_pointer != row_pointer {
        return Err(SourceInstallError::Corrupt {
            detail: "position_bin disagrees with the row's ordinal or record_pointer".to_string(),
        });
    }
    if byte_start > byte_end {
        return Err(SourceInstallError::Corrupt {
            detail: "position_bin has byte_start after byte_end".to_string(),
        });
    }
    let locator = SourceRecordLocator { ordinal, record_pointer, byte_start, byte_end };
    if locator.to_array() != bytes {
        return Err(SourceInstallError::Corrupt {
            detail: "position_bin is not in its canonical form".to_string(),
        });
    }
    Ok(locator)
}

/// Recompute the diagnostics semantic digest (§10): the compact UTF-8 JSON
/// array of the strictly decoded `cass.source-diagnostic/1` tuples. The
/// persisted bytes are an envelope, so hashing them directly would be a
/// different (and wrong) digest.
fn diagnostics_semantic_sha256(blob: Option<&[u8]>) -> Result<Option<Sha256Digest>, SourceInstallError> {
    let Some(bytes) = blob else { return Ok(None) };
    let envelope = decode_diagnostics(bytes)?;
    let mut array = Vec::new();
    array.push(b'[');
    for (index, item) in envelope.items.iter().enumerate() {
        if index > 0 {
            array.push(b',');
        }
        array.extend_from_slice(&item.encode());
    }
    array.push(b']');
    Ok(Some(Sha256Digest::of(&array)))
}

/// Read every frame row of one input, in the frozen `(ordinal,
/// record_pointer)` order, recomputing each leaf input's digests from the
/// stored bytes rather than trusting the neighbouring digest columns (§19).
fn read_stored_records(
    tx: &Tx<'_>,
    input_id: i64,
) -> Result<Vec<StoredRecord>, SourceInstallError> {
    type RecordRow = (
        i64,
        Vec<u8>,
        String,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    );
    let rows: Vec<RecordRow> =
        tx.query_all_map(
            "SELECT id, ordinal, record_pointer, position_bin, expected_source_record_sha256,
                    observed_source_record_sha256, frame_state, parse_state,
                    record_mapping_state, safety_state, retention_state, codec, payload_bin,
                    safe_value_hash, native_ids_bin, diagnostics_bin
             FROM source_records WHERE input_id = ?1
             ORDER BY ordinal ASC, record_pointer ASC",
            &[Value::Integer(input_id)],
            |row| {
                Ok((
                    row.get_typed(0)?,
                    row.get_typed(1)?,
                    row.get_typed(2)?,
                    row.get_typed(3)?,
                    row.get_typed(4)?,
                    row.get_typed(5)?,
                    row.get_typed(6)?,
                    row.get_typed(7)?,
                    row.get_typed(8)?,
                    row.get_typed(9)?,
                    row.get_typed(10)?,
                    row.get_typed(11)?,
                    row.get_typed(12)?,
                    row.get_typed(13)?,
                    row.get_typed(14)?,
                    row.get_typed(15)?,
                ))
            },
        )?;

    let mut records = Vec::with_capacity(rows.len());
    for (
        _row_id,
        ordinal_blob_bytes,
        record_pointer,
        position_bin,
        expected_sha,
        observed_sha,
        frame_state,
        parse_state,
        record_mapping_state,
        safety_state,
        retention_state,
        codec,
        payload_bin,
        safe_value_hash,
        native_ids_bin,
        diagnostics_bin,
    ) in rows
    {
        let ordinal = u64::from_be_bytes(
            ordinal_blob_bytes
                .as_slice()
                .try_into()
                .map_err(|_| SourceInstallError::Corrupt {
                    detail: "source_records.ordinal is not 8 bytes".to_string(),
                })?,
        );
        let locator = decode_position_bin(&position_bin, ordinal, &record_pointer)?;
        let expected_raw_sha256 =
            Sha256Digest::from_slice(&expected_sha).ok_or_else(|| SourceInstallError::Corrupt {
                detail: "expected_source_record_sha256 is not 32 bytes".to_string(),
            })?;
        let observed_raw_sha256 = match observed_sha.as_deref() {
            Some(bytes) => Some(Sha256Digest::from_slice(bytes).ok_or_else(|| {
                SourceInstallError::Corrupt {
                    detail: "observed_source_record_sha256 is not 32 bytes".to_string(),
                }
            })?),
            None => None,
        };
        // §10: the payload digest is over the stored BLOB's own bytes; the
        // safe-value digest is *recomputed* from the decoded tree and compared
        // against the stored column, so a swapped payload cannot ride along on
        // an unchanged digest column.
        let payload_bytes_sha256 = payload_bin.as_deref().map(Sha256Digest::of);
        let safe_value_sha256 = match payload_bin.as_deref() {
            Some(bytes) => {
                let decoded = super::source_codec::decode_safe_source(bytes)
                    .map_err(SourceInstallError::Codec)?;
                let recomputed = safe_value_sha256(decoded.value())?;
                if let Some(stored) = safe_value_hash.as_deref() {
                    let stored = Sha256Digest::from_slice(stored).ok_or_else(|| {
                        SourceInstallError::Corrupt {
                            detail: "safe_value_hash is not 32 bytes".to_string(),
                        }
                    })?;
                    if stored != recomputed {
                        return Err(SourceInstallError::Corrupt {
                            detail: "safe_value_hash does not match the stored payload".to_string(),
                        });
                    }
                }
                Some(recomputed)
            }
            None => None,
        };
        let native_ids_semantic_sha256 = native_ids_bin.as_deref().map(Sha256Digest::of);
        let diagnostics_semantic_sha256 = diagnostics_semantic_sha256(diagnostics_bin.as_deref())?;

        records.push(StoredRecord {
            frame_state,
            leaf_input: StagedRecordLeafInput {
                locator,
                expected_raw_sha256,
                observed_raw_sha256,
                parse_state: parse_parse_state(&parse_state)?,
                record_mapping_state: parse_record_mapping_state(&record_mapping_state)?,
                safety_state: parse_safety_state(&safety_state)?,
                retention_state: parse_retention_state(&retention_state)?,
                codec,
                payload_bytes_sha256,
                safe_value_sha256,
                native_ids_semantic_sha256,
                diagnostics_semantic_sha256,
            },
        });
    }
    Ok(records)
}

/// One `source_message_links` row, decoded back into its claim and witness.
struct StoredLink {
    claim: SourceClaim,
    installation: Option<OriginalInstallation>,
    authority: Option<String>,
    message_id: Option<i64>,
}

/// Read every link of one input in the frozen `(ordinal, record_pointer,
/// projection_key)` order, re-decoding the evidence envelope and recomputing
/// its witness digest (§19).
fn read_stored_links(
    tx: &Tx<'_>,
    input_id: i64,
    input_key: &Sha256Digest,
) -> Result<Vec<StoredLink>, SourceInstallError> {
    struct JoinedLink {
        record_ordinal: Vec<u8>,
        record_pointer: String,
        projection_key: Vec<u8>,
        row: StoredLinkRow,
    }

    let rows: Vec<JoinedLink> = tx.query_all_map(
        "SELECT r.ordinal, r.record_pointer, l.projection_key, l.source_positions_bin,
                l.authority, l.message_id, l.binding_digest, l.conversation_ordinal,
                l.final_message_idx, l.projection_pointer, l.evidence_kind
         FROM source_message_links l
         JOIN source_records r ON r.id = l.record_id
         WHERE r.input_id = ?1
         ORDER BY r.ordinal ASC, r.record_pointer ASC, l.projection_key ASC",
        &[Value::Integer(input_id)],
        |row| {
            Ok(JoinedLink {
                record_ordinal: row.get_typed(0)?,
                record_pointer: row.get_typed(1)?,
                projection_key: row.get_typed(2)?,
                row: StoredLinkRow {
                    positions: row.get_typed(3)?,
                    authority: row.get_typed(4)?,
                    message_id: row.get_typed(5)?,
                    digest: row.get_typed(6)?,
                    conversation_ordinal: row.get_typed(7)?,
                    final_message_idx: row.get_typed(8)?,
                    projection_pointer: row.get_typed(9)?,
                    evidence_kind: row.get_typed(10)?,
                },
            })
        },
    )?;

    let mut links = Vec::with_capacity(rows.len());
    for joined in rows {
        // The same read-back the install path uses, so a reader and a writer can
        // never disagree about what a stored row is allowed to say.
        let evidence = decode_stored_link_row(tx, &joined.row)?;
        // The row must also sit under the record and the projection it claims.
        // The join already restricts the input, so these two close the locator
        // and the projection key.
        // The join proves SQL ownership; the envelope's own claim has to name
        // this input as well, or a row could carry another input's claim.
        if evidence.claim.input_key != *input_key
            || joined.record_pointer != evidence.claim.record_pointer
            || joined.record_ordinal != u64_be8(evidence.claim.record_ordinal).to_vec()
            || joined.projection_key != evidence.claim.projection_key().as_bytes().to_vec()
        {
            return Err(SourceInstallError::Corrupt {
                detail: format!(
                    "the stored link for record {} does not sit under the record and projection \
                     its own claim names",
                    joined.record_pointer
                ),
            });
        }
        links.push(StoredLink {
            claim: evidence.claim,
            installation: evidence.installation,
            authority: joined.row.authority,
            message_id: joined.row.message_id,
        });
    }
    Ok(links)
}

/// One conversation a stored source input was actually installed into, with the
/// immutable identity digest its `CanonicalBound` binding recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstalledSourceConversation {
    pub(crate) conversation_id: i64,
    pub(crate) identity_digest: Sha256Digest,
}

/// Collect the immutable `CanonicalBound` installation targets of one input,
/// read-only in the caller's transaction.
///
/// `None` means the input is not registered (a first install, or an input that
/// never staged). `Some` carries every distinct `original_conversation_id` its
/// canonical bindings name, irrespective of the link's current authority: a
/// historical link keeps its binding after the message is gone, which is what
/// lets a legitimate historical replay prove its target without requiring the
/// old message to survive. The rejected winner of a `WinnerRejected`
/// installation is never used. Two different digests for the same conversation
/// are corruption, not two installation targets.
///
/// # Errors
/// `Db` when a read fails, `Conflict`/`Corrupt`/`Receipt`/`Codec` when the
/// stored evidence cannot be re-verified.
pub(crate) fn installed_source_conversations_in_tx(
    tx: &Tx<'_>,
    input_key: &Sha256Digest,
) -> Result<Option<Vec<InstalledSourceConversation>>, SourceInstallError> {
    let Some(input_id) = registered_source_input_id(tx, input_key)? else {
        return Ok(None);
    };
    let links = read_stored_links(tx, input_id, input_key)?;
    let mut by_id: std::collections::BTreeMap<i64, Sha256Digest> =
        std::collections::BTreeMap::new();
    for link in links {
        let Some(installation) = link.installation else {
            continue;
        };
        if installation.class != InstallationClass::CanonicalBound {
            continue;
        }
        let Some(binding) = installation.binding else {
            continue;
        };
        match by_id.get(&binding.original_conversation_id) {
            Some(existing) if *existing != binding.conversation_identity_digest => {
                return Err(SourceInstallError::Corrupt {
                    detail: format!(
                        "conversation {} carries two different immutable identity digests",
                        binding.original_conversation_id
                    ),
                });
            }
            _ => {
                by_id.insert(
                    binding.original_conversation_id,
                    binding.conversation_identity_digest,
                );
            }
        }
    }
    Ok(Some(
        by_id
            .into_iter()
            .map(|(conversation_id, identity_digest)| InstalledSourceConversation {
                conversation_id,
                identity_digest,
            })
            .collect(),
    ))
}

/// The conversation identity digest one stored installation was taken against
/// (§9).
///
/// Both classes now carry it as an immutable witness member — a bound
/// installation in its binding, a winner rejection in its own evidence — so the
/// canonical array is reproducible from the stored rows alone, even after the
/// winner row has been deleted.
fn installation_conversation_identity_digest(
    installation: &OriginalInstallation,
) -> Option<Sha256Digest> {
    match (&installation.binding, &installation.rejection) {
        (Some(binding), _) => Some(binding.conversation_identity_digest),
        (None, Some(rejection)) => Some(rejection.conversation_identity_digest),
        (None, None) => None,
    }
}

/// Build the A-side roots from the stored rows (§5, §19).
fn recompute_a_roots(
    input_key: &Sha256Digest,
    records: &[StoredRecord],
    links: &[StoredLink],
) -> Result<(Root, Root), SourceInstallError> {
    let mut record_leaves = Vec::with_capacity(records.len());
    for record in records {
        record_leaves.push(encode_record_semantic_leaf(input_key, &record.leaf_input));
    }
    let records_count = record_leaves.len() as u64;
    let records_root = Root {
        sha256: stream_root(
            SOURCE_SEMANTIC_RECORDS_ROOT_DOMAIN,
            &record_leaves,
            &records_footer(records_count),
        ),
        count: records_count,
    };

    let mut claim_leaves = Vec::with_capacity(links.len());
    let mut canonical = 0u64;
    let mut standalone = 0u64;
    let mut unmapped = 0u64;
    for link in links {
        claim_leaves.push(link.claim.encode_leaf());
        match link.claim.mapping_state {
            ClaimMappingState::Canonical => canonical += 1,
            ClaimMappingState::Standalone => standalone += 1,
            ClaimMappingState::Unmapped => unmapped += 1,
        }
    }
    let claims_count = claim_leaves.len() as u64;
    let claims_root = Root {
        sha256: stream_root(
            SOURCE_CLAIMS_ROOT_DOMAIN,
            &claim_leaves,
            &claims_footer(canonical, standalone, unmapped),
        ),
        count: claims_count,
    };
    Ok((records_root, claims_root))
}

/// Build the B-side roots from the stored rows (§5, §19).
fn recompute_b_roots(
    input_key: &Sha256Digest,
    records: &[StoredRecord],
    links: &[StoredLink],
) -> Result<(Root, Root, BindingClassCounts), SourceInstallError> {
    let mut installed_leaves = Vec::with_capacity(records.len());
    for record in records {
        let semantic = encode_record_semantic_leaf(input_key, &record.leaf_input);
        installed_leaves.push(encode_record_installed_leaf(
            &semantic,
            parse_frame_state(&record.frame_state)?,
        ));
    }
    let installed_count = installed_leaves.len() as u64;
    let installed_root = Root {
        sha256: stream_root(
            SOURCE_INSTALLED_RECORDS_ROOT_DOMAIN,
            &installed_leaves,
            &records_footer(installed_count),
        ),
        count: installed_count,
    };

    let mut binding_leaves = Vec::with_capacity(links.len());
    let mut counts = BindingClassCounts::default();
    for link in links {
        let Some(installation) = &link.installation else {
            return Err(SourceInstallError::Activation {
                detail: "an uninstalled claim cannot enter the witness stream".to_string(),
            });
        };
        let claim_leaf = link.claim.encode_leaf();
        // The digest is a member of the witness itself, so this recomputation
        // needs nothing that is not already persisted (§9). Exactly the two
        // binding classes carry one -- a canonical binding in its binding, a
        // winner rejection in its own evidence -- and the three no-binding
        // classes (`StandaloneNoBinding`, `UnmappedNoBinding`,
        // `UnresolvedNoBinding`) legitimately carry none. Inventing a digest
        // for them would fabricate a witness, so the rule is stated per class
        // instead.
        match installation.class {
            InstallationClass::CanonicalBound => debug_assert!(
                installation.binding.is_some(),
                "a canonical-bound installation must carry its binding"
            ),
            InstallationClass::WinnerRejectedNoBinding => debug_assert!(
                installation.rejection.is_some(),
                "a winner-rejected installation must carry its rejection"
            ),
            InstallationClass::StandaloneNoBinding
            | InstallationClass::UnmappedNoBinding
            | InstallationClass::UnresolvedNoBinding => {}
        }
        debug_assert_eq!(
            installation_conversation_identity_digest(installation).is_some(),
            matches!(
                installation.class,
                InstallationClass::CanonicalBound | InstallationClass::WinnerRejectedNoBinding
            ),
            "a conversation identity digest belongs to the two binding classes and to no other"
        );
        binding_leaves.push(encode_binding_leaf(
            u64::from(SOURCE_ENVELOPE_VERSION),
            &claim_leaf,
            &installation.encode(),
        ));
        match installation.class {
            InstallationClass::CanonicalBound => counts.canonical_bound += 1,
            InstallationClass::UnresolvedNoBinding => counts.unresolved_no_binding += 1,
            InstallationClass::StandaloneNoBinding => counts.standalone_no_binding += 1,
            InstallationClass::UnmappedNoBinding => counts.unmapped_no_binding += 1,
            InstallationClass::WinnerRejectedNoBinding => counts.winner_rejected_no_binding += 1,
        }
    }
    let binding_count = binding_leaves.len() as u64;
    let binding_root = Root {
        sha256: stream_root(
            SOURCE_BINDINGS_ROOT_DOMAIN,
            &binding_leaves,
            &bindings_footer(&counts),
        ),
        count: binding_count,
    };
    Ok((installed_root, binding_root, counts))
}

fn parse_frame_state(text: &str) -> Result<FrameState, SourceInstallError> {
    match text {
        "frame_pending" => Ok(FrameState::FramePending),
        "staged" => Ok(FrameState::Staged),
        "activated" => Ok(FrameState::Activated),
        other => Err(SourceInstallError::Corrupt {
            detail: format!("unknown frame_state {other:?}"),
        }),
    }
}

fn parse_parse_state(text: &str) -> Result<ParseState, SourceInstallError> {
    match text {
        "pending" => Ok(ParseState::Pending),
        "parsed" => Ok(ParseState::Parsed),
        "parse_failed" => Ok(ParseState::ParseFailed),
        other => Err(SourceInstallError::Corrupt { detail: format!("unknown parse_state {other:?}") }),
    }
}

fn parse_record_mapping_state(text: &str) -> Result<RecordMappingState, SourceInstallError> {
    match text {
        "claims_pending" => Ok(RecordMappingState::ClaimsPending),
        "no_claims" => Ok(RecordMappingState::NoClaims),
        "all_canonical" => Ok(RecordMappingState::AllCanonical),
        "all_standalone" => Ok(RecordMappingState::AllStandalone),
        "all_unmapped" => Ok(RecordMappingState::AllUnmapped),
        "mixed" => Ok(RecordMappingState::Mixed),
        other => Err(SourceInstallError::Corrupt {
            detail: format!("unknown record_mapping_state {other:?}"),
        }),
    }
}

fn parse_safety_state(text: &str) -> Result<SafetyState, SourceInstallError> {
    match text {
        "pending" => Ok(SafetyState::Pending),
        "preserved" => Ok(SafetyState::Preserved),
        "blocked" => Ok(SafetyState::Blocked),
        other => Err(SourceInstallError::Corrupt { detail: format!("unknown safety_state {other:?}") }),
    }
}

fn parse_retention_state(text: &str) -> Result<RetentionState, SourceInstallError> {
    match text {
        "payload_absent" => Ok(RetentionState::PayloadAbsent),
        "payload_present" => Ok(RetentionState::PayloadPresent),
        other => Err(SourceInstallError::Corrupt {
            detail: format!("unknown retention_state {other:?}"),
        }),
    }
}

/// Read the `source_facts_revision` meta counter (§13.1).
fn read_source_facts_revision(tx: &Tx<'_>) -> Result<u64, SourceInstallError> {
    let stored: Option<String> = tx.query_opt_map(
        "SELECT value FROM meta WHERE key = ?1",
        &[Value::Text(SOURCE_FACTS_REVISION_META_KEY.to_string())],
        |row| row.get_typed(0),
    )?;
    match stored.as_deref() {
        None | Some("0") => Ok(0),
        Some(text) => text.parse::<u64>().map_err(|_| SourceInstallError::Corrupt {
            detail: "source_facts_revision is not a canonical decimal".to_string(),
        }),
    }
}

/// Write the `source_facts_revision` meta counter.
fn write_source_facts_revision(tx: &Tx<'_>, value: u64) -> Result<(), SourceInstallError> {
    tx.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?1, ?2)",
        &[
            Value::Text(SOURCE_FACTS_REVISION_META_KEY.to_string()),
            Value::Text(value.to_string()),
        ],
    )?;
    Ok(())
}

/// Read this library's identity from `meta` (§12).
fn read_library_identity(tx: &Tx<'_>) -> Result<String, SourceInstallError> {
    tx.query_opt_map(
        "SELECT value FROM meta WHERE key = ?1",
        &[Value::Text(crate::storage::schema::LIBRARY_IDENTITY_META_KEY.to_string())],
        |row| row.get_typed(0),
    )?
    .ok_or_else(|| SourceInstallError::Corrupt {
        detail: "the library identity meta row is missing".to_string(),
    })
}

/// Activate one staged source input (§11, §13).
///
/// Every number this decides on is recomputed from the stored rows in this
/// same transaction: the expected manifest is re-read from SQL and re-decoded,
/// the A roots are rebuilt from the frame and claim rows, and the witnesses are
/// re-digested. Nothing is taken from the request except the caller's own
/// claims, which are checked against those recomputed values.
///
/// # Errors
/// `Conflict` when the stored input disagrees with the request, `Corrupt` when
/// a stored row cannot be re-verified, and `Activation` when the stored frame
/// set is not ready for activation.
pub fn activate_source_input_in_tx(
    tx: &Tx<'_>,
    request: &SourceActivationRequest,
    expected_manifest: &VerifiedExpectedManifest,
) -> Result<SourceActivationOutcome, SourceInstallError> {
    let stored = read_source_input(tx, &request.input_key)?.ok_or_else(|| {
        SourceInstallError::Conflict {
            detail: "the source input is not registered".to_string(),
        }
    })?;

    // The header always comes from SQL, never from the caller (§20.2).
    let (manifest, _safety) = decode_expected_manifest_header(&stored.expected_manifest_bin)?;
    let recomputed_digest = Sha256Digest::of(&stored.expected_manifest_bin);
    if recomputed_digest != request.expected_manifest_digest {
        return Err(SourceInstallError::Conflict {
            detail: "the request's expected_manifest_digest is not the stored header's digest"
                .to_string(),
        });
    }
    if &manifest != expected_manifest {
        return Err(SourceInstallError::Conflict {
            detail: "the supplied manifest is not the one stored for this input".to_string(),
        });
    }
    if stored.normalizer_id != request.normalizer_id
        || stored.safety_contract_id != request.safety_contract_id
        || stored.format != manifest.format.as_str()
    {
        return Err(SourceInstallError::Conflict {
            detail: "the request's normalizer, safety contract or format disagrees with the \
                     stored parent"
                .to_string(),
        });
    }
    let library_identity = read_library_identity(tx)?;
    if library_identity != request.library_identity {
        return Err(SourceInstallError::Conflict {
            detail: "the request names a different library identity".to_string(),
        });
    }

    let mut records = read_stored_records(tx, stored.id)?;
    let links = read_stored_links(tx, stored.id, &request.input_key)?;

    // §17.2: a row the reader never processed must block activation.
    if let Some(pending) = records.iter().find(|record| record.frame_state == "frame_pending") {
        return Err(SourceInstallError::Activation {
            detail: format!(
                "record {} is still frame_pending; the frame set is not complete",
                pending.leaf_input.locator.record_pointer
            ),
        });
    }
    // The independent denominator is the manifest's, not the reader's.
    if records.len() as u64 != manifest.records() {
        return Err(SourceInstallError::Conflict {
            detail: format!(
                "the stored frame set has {} records, the independent manifest says {}",
                records.len(),
                manifest.records()
            ),
        });
    }

    // The reader's Finish must agree with the independent measurements (§17.2).
    let finish = &request.finish;
    if finish.content_digest != *manifest.sealed_sha256()
        || finish.bytes_read != manifest.byte_len()
        || finish.records_seen != manifest.records()
        || finish.blank_lines != manifest.blank_lines()
        || !finish.reached_eof
    {
        return Err(SourceInstallError::Conflict {
            detail: "the reader's Finish disagrees with the independent manifest".to_string(),
        });
    }

    // A roots are rebuilt from the rows; the request only supplies the claim to
    // be checked against them.
    let (records_root, claims_root) = recompute_a_roots(&request.input_key, &records, &links)?;
    if records_root != request.source_semantic_records_root {
        return Err(SourceInstallError::Conflict {
            detail: "the request's record root is not the one the stored rows hash to".to_string(),
        });
    }
    if claims_root != request.claims_root {
        return Err(SourceInstallError::Conflict {
            detail: "the request's claims root is not the one the stored rows hash to".to_string(),
        });
    }

    let semantic_request_digest = semantic_request_digest(
        &request.input_key,
        &recomputed_digest,
        manifest.sealed_sha256(),
        manifest.byte_len(),
        manifest.format().as_str(),
        &request.normalizer_id,
        &request.safety_contract_id,
        finish,
        request.projection_disposition,
        &records_root,
        &claims_root,
    );

    // §9: every installed witness must be bound to the request this activation
    // is committing. A complete input that now computes a different request is a
    // conflict, never a second commit over the first one's header and receipt.
    require_installations_bound_to(&links, &semantic_request_digest)?;
    if stored.state == "complete" {
        if let Some(committed) = stored.activation_request_hash.as_deref() {
            if committed != semantic_request_digest.as_bytes() {
                return Err(SourceInstallError::Conflict {
                    detail: "this input is already complete under a different semantic request; \
                             a second activation must not overwrite its header and receipt"
                        .to_string(),
                });
            }
        }
    }

    // §8's completion matrix, decided on the stored witness classes.
    //
    // A legitimately empty JSONL input is the one case with no witness to bind:
    // the independent scan's own denominator recorded zero physical records, so
    // there is nothing for a claim or a link to refer to, and the "at least one
    // installed witness" rule has nothing to test. That case completes on the
    // *absence* of records, claims and links together. Every input whose own
    // denominator did record a physical record keeps the rule, so a non-empty
    // input whose claims or links are missing still cannot complete.
    let empty_jsonl_input = manifest.format() == SourceFormat::Jsonl
        && manifest.records() == 0
        && records.is_empty()
        && links.is_empty();
    let completable = request.requested_terminal == TerminalState::Complete
        && request.projection_disposition == ProjectionDisposition::Ready
        && finish.parse_failed == 0
        && finish.unprocessed_ranges.is_empty()
        && records.iter().all(|record| record.leaf_input.safety_state == SafetyState::Preserved)
        && (empty_jsonl_input || !links.is_empty())
        && links.iter().all(|link| {
            link.installation.as_ref().is_some_and(|installation| {
                matches!(
                    installation.class,
                    InstallationClass::CanonicalBound
                        | InstallationClass::StandaloneNoBinding
                        | InstallationClass::WinnerRejectedNoBinding
                )
            })
        });

    if !completable {
        return publish_or_stage_failure(tx, &stored, request, &semantic_request_digest, &records_root, &claims_root);
    }

    let receipt_key = activation_receipt_key(
        &library_identity,
        &request.input_key,
        &semantic_request_digest,
    );

    // A committed receipt for the same key is a replay only if it survives the
    // full historical verification (§12): every field is re-derived from the
    // stored rows and the request, not read back from the detail. Decoding a
    // receipt is not verifying it, and a receipt whose bytes still parse must
    // not become a replay on that ground alone.
    if read_receipt_detail(tx, &receipt_key)?.is_some() {
        return match verify_source_receipt_in_tx(tx, request)? {
            SourceReceiptMatch::VerifiedReplay { receipt, .. } => {
                Ok(SourceActivationOutcome::Replay { receipt: *receipt })
            }
            SourceReceiptMatch::Conflict { expected, found } => Err(SourceInstallError::Conflict {
                detail: format!(
                    "the stored receipt disagrees with the request: expected {}, found {}",
                    expected.hex(),
                    found.hex()
                ),
            }),
            SourceReceiptMatch::Inconsistent { reason } => Err(SourceInstallError::Receipt(reason)),
            SourceReceiptMatch::Absent => Err(SourceInstallError::Corrupt {
                detail: "the parent row names a receipt that is not in the receipt table"
                    .to_string(),
            }),
        };
    }
    // The B side records each row's *actual* frame state, so the frames move
    // first: the receipt's `immutable_records_root` has to describe the state
    // this transaction leaves behind, which is what a later re-verification
    // reads back.
    tx.execute(
        "UPDATE source_records SET frame_state = 'activated'
         WHERE input_id = ?1 AND frame_state = 'staged'",
        &[Value::Integer(stored.id)],
    )?;
    for record in &mut records {
        record.frame_state = "activated".to_string();
    }
    let (installed_root, binding_root, class_counts) =
        recompute_b_roots(&request.input_key, &records, &links)?;
    let revision = read_source_facts_revision(tx)?.checked_add(1).ok_or(
        SourceInstallError::Overflow { field: "source_facts_revision" },
    )?;
    let generation = format!("{SOURCE_GENERATION_PREFIX}{}", semantic_request_digest.hex());
    let installation = installation_digest(
        &library_identity,
        &semantic_request_digest,
        &installed_root,
        &binding_root,
        &class_counts,
        request.requested_terminal,
        &generation,
        revision,
    );
    let receipt = VerifiedReceipt {
        input_key: request.input_key,
        library_identity: library_identity.clone(),
        semantic_request_digest,
        installation_digest: installation,
        expected_manifest_digest: recomputed_digest,
        source_semantic_records_root: records_root,
        claims_root,
        immutable_records_root: installed_root,
        original_binding_root: binding_root,
        binding_class_counts: class_counts,
        terminal_state: request.requested_terminal,
        applied_content_generation: generation.clone(),
        committed_source_facts_revision: revision,
    };

    // One transaction: the generation moves, the revision moves and the
    // receipt lands — or none of it does. The frames already moved above.
    let mut history = read_attempt_history(stored.attempt_history_bin.as_deref())?;
    if history.original_success_finish.is_none() {
        history.original_success_finish = Some(finish.clone());
    }
    history.attempts.push(AttemptRecord {
        attempt: history.attempts.len() as u64 + 1,
        measured_finish: finish.clone(),
        outcome: "Activated".to_string(),
    });
    write_source_facts_revision(tx, revision)?;
    crate::storage::sqlite::franken_set_source_content_generation_in_tx(tx, &generation)
        .map_err(anyhow_source_error)?;
    crate::storage::sqlite::franken_insert_operation_commit_receipt_in_tx(
        tx,
        &receipt_key,
        SOURCE_ACTIVATION_OPERATION,
        SOURCE_ACTIVATION_STATE,
        Some(&semantic_request_digest.hex()),
        now_ms(),
        Some(&String::from_utf8_lossy(&encode_receipt_detail(&receipt))),
    )
    .map_err(anyhow_source_error)?;
    tx.execute(
        "UPDATE source_inputs SET state = 'complete', receipt_key = ?1,
             applied_content_generation = ?2, activation_request_hash = ?3,
             observed_records = ?4, observed_blank_lines = ?5, attempt_history_bin = ?6
         WHERE id = ?7",
        &[
            Value::Text(receipt_key.clone()),
            Value::Text(generation.clone()),
            Value::Blob(semantic_request_digest.as_bytes().to_vec()),
            ordinal_blob(finish.records_seen),
            ordinal_blob(finish.blank_lines),
            Value::Blob(encode_envelope(&history)?),
            Value::Integer(stored.id),
        ],
    )?;

    Ok(SourceActivationOutcome::Activated {
        input_id: stored.id,
        receipt_key,
        semantic_request_digest,
        installation_digest: installation,
        generation,
        source_facts_revision: revision,
    })
}

/// The registered `source_inputs.id` for one input key, if the input exists.
///
/// # Errors
/// Propagates the storage failure typed.
pub fn registered_source_input_id(
    tx: &Tx<'_>,
    input_key: &Sha256Digest,
) -> Result<Option<i64>, SourceInstallError> {
    Ok(read_source_input(tx, input_key)?.map(|input| input.id))
}

/// Rebuild the A-side roots from the rows already staged for `input_id`
/// (§5, §19).
///
/// A caller builds its activation request from these, and the primitive checks
/// that request back against a fresh recomputation, so a caller-supplied root is
/// never trusted on its own.
///
/// # Errors
/// `Corrupt` when a stored row cannot be re-verified.
pub fn source_a_roots_in_tx(
    tx: &Tx<'_>,
    input_key: &Sha256Digest,
    input_id: i64,
) -> Result<(Root, Root), SourceInstallError> {
    let records = read_stored_records(tx, input_id)?;
    let links = read_stored_links(tx, input_id, input_key)?;
    recompute_a_roots(input_key, &records, &links)
}

/// Rebuild the B-side roots and class counts from the rows already installed
/// for `input_id` (§5, §19).
///
/// # Errors
/// `Corrupt` when a stored row cannot be re-verified, and `Activation` when a
/// claim is still uninstalled.
pub fn source_b_roots_in_tx(
    tx: &Tx<'_>,
    input_key: &Sha256Digest,
    input_id: i64,
) -> Result<(Root, Root, BindingClassCounts), SourceInstallError> {
    let records = read_stored_records(tx, input_id)?;
    let links = read_stored_links(tx, input_id, input_key)?;
    recompute_b_roots(input_key, &records, &links)
}

/// Publish a final partial/failed result, or leave the input staged (§13.3,
/// §13.4).
///
/// A whole-input rejection (`WholeInputRejected`) is the caller's declaration
/// that this failed attempt is final, so it is published: the revision moves
/// once and the `visible_facts_digest` is recorded. Any other non-completing
/// request stays `StagedOnly` and moves nothing.
fn publish_or_stage_failure(
    tx: &Tx<'_>,
    stored: &StoredSourceInput,
    request: &SourceActivationRequest,
    _semantic_request_digest: &Sha256Digest,
    records_root: &Root,
    claims_root: &Root,
) -> Result<SourceActivationOutcome, SourceInstallError> {
    let terminal = if request.requested_terminal == TerminalState::Complete {
        TerminalState::Partial
    } else {
        request.requested_terminal
    };
    let state = match terminal {
        TerminalState::Complete => "complete",
        TerminalState::Partial => "partial",
        TerminalState::Failed => "failed",
    };

    let mut history = read_attempt_history(stored.attempt_history_bin.as_deref())?;
    let mut revision = read_source_facts_revision(tx)?;

    if request.projection_disposition == ProjectionDisposition::WholeInputRejected {
        let visible = visible_facts_digest(
            &request.input_key,
            terminal,
            records_root,
            claims_root,
            &request.finish,
            request.projection_disposition,
        );
        // A same-value replay of the same publication does not move the
        // counter again (§13.4).
        let already = history.last_published_failure == Some(visible);
        if !already {
            revision = revision
                .checked_add(1)
                .ok_or(SourceInstallError::Overflow { field: "source_facts_revision" })?;
        }
        history.last_published_failure = Some(visible);
        history.attempts.push(AttemptRecord {
            attempt: history.attempts.len() as u64 + 1,
            measured_finish: request.finish.clone(),
            outcome: format!("PublishedFailure{}", if already { "(replay)" } else { "" }),
        });
        tx.execute(
            "UPDATE source_inputs SET state = ?1, observed_records = ?2, observed_blank_lines = ?3,
                 unprocessed_ranges_bin = ?4, attempt_history_bin = ?5
             WHERE id = ?6",
            &[
                Value::Text(state.to_string()),
                ordinal_blob(request.finish.records_seen),
                ordinal_blob(request.finish.blank_lines),
                Value::Blob(encode_envelope(&UnprocessedRangesEnvelope {
                    version: SOURCE_ENVELOPE_VERSION,
                    domain: SOURCE_UNPROCESSED_RANGES_DOMAIN.to_string(),
                    items: request.finish.unprocessed_ranges.clone(),
                })?),
                Value::Blob(encode_envelope(&history)?),
                Value::Integer(stored.id),
            ],
        )?;
        if !already {
            write_source_facts_revision(tx, revision)?;
        }
        return Ok(SourceActivationOutcome::PublishedFailure {
            input_id: stored.id,
            state: terminal,
            source_facts_revision: revision,
            visible_facts_digest: visible,
        });
    }

    // Transient work: recorded, but the reader-visible set and the revision
    // are untouched.
    history.attempts.push(AttemptRecord {
        attempt: history.attempts.len() as u64 + 1,
        measured_finish: request.finish.clone(),
        outcome: format!("StagedOnly({state})"),
    });
    tx.execute(
        "UPDATE source_inputs SET state = ?1, observed_records = ?2, observed_blank_lines = ?3,
             attempt_history_bin = ?4
         WHERE id = ?5",
        &[
            Value::Text(state.to_string()),
            ordinal_blob(request.finish.records_seen),
            ordinal_blob(request.finish.blank_lines),
            Value::Blob(encode_envelope(&history)?),
            Value::Integer(stored.id),
        ],
    )?;
    Ok(SourceActivationOutcome::StagedOnly { input_id: stored.id, state: terminal })
}

/// Verify one committed activation receipt against the current database (§12).
///
/// The stored detail is re-decoded strictly and every field is re-checked
/// against the rows it claims to describe; the receipt table's existence alone
/// proves nothing.
///
/// # Errors
/// `Corrupt` when the stored detail cannot be re-decoded or re-verified.
pub fn verify_source_receipt_in_tx(
    tx: &Tx<'_>,
    request: &SourceActivationRequest,
) -> Result<SourceReceiptMatch, SourceInstallError> {
    let stored = read_source_input(tx, &request.input_key)?.ok_or_else(|| {
        SourceInstallError::Conflict { detail: "the source input is not registered".to_string() }
    })?;
    // The stored header must decode, and its own digest — not the neighbouring
    // column — is what the receipt has to agree with (§20.2).
    let (manifest, _safety) = decode_expected_manifest_header(&stored.expected_manifest_bin)?;
    let manifest_digest = Sha256Digest::of(&stored.expected_manifest_bin);
    // The request must name the header that is stored, and the library that is
    // actually installed: a caller that supplies different ones is asking about
    // a different input, and a standalone verify must not accept that merely
    // because the receipt happens to agree with the request (§12).
    if request.expected_manifest_digest != manifest_digest {
        return Ok(SourceReceiptMatch::Conflict {
            expected: manifest_digest,
            found: request.expected_manifest_digest,
        });
    }
    let library_identity = read_library_identity(tx)?;
    if library_identity != request.library_identity {
        return Ok(SourceReceiptMatch::Inconsistent {
            reason: ReceiptInconsistency::LibraryMismatch,
        });
    }
    if stored.normalizer_id != request.normalizer_id
        || stored.safety_contract_id != request.safety_contract_id
        || stored.format != manifest.format.as_str()
    {
        return Ok(SourceReceiptMatch::Inconsistent { reason: ReceiptInconsistency::InvalidHeader });
    }
    // The reader's Finish must agree with the independent measurements (§17.2).
    let finish = &request.finish;
    if finish.content_digest != *manifest.sealed_sha256()
        || finish.bytes_read != manifest.byte_len()
        || finish.records_seen != manifest.records()
        || finish.blank_lines != manifest.blank_lines()
        || !finish.reached_eof
    {
        return Ok(SourceReceiptMatch::Inconsistent { reason: ReceiptInconsistency::InvalidHeader });
    }

    let records = read_stored_records(tx, stored.id)?;
    let links = read_stored_links(tx, stored.id, &request.input_key)?;
    let (records_root, claims_root) = recompute_a_roots(&request.input_key, &records, &links)?;
    // The request's own A-side roots have to be the rows' roots. A mismatch is
    // a request about another input, not a replay of this one.
    if request.source_semantic_records_root != records_root
        || request.claims_root != claims_root
    {
        return Ok(SourceReceiptMatch::Conflict {
            expected: records_root.sha256,
            found: request.source_semantic_records_root.sha256,
        });
    }
    let recomputed_request_digest = semantic_request_digest(
        &request.input_key,
        &manifest_digest,
        manifest.sealed_sha256(),
        manifest.byte_len(),
        manifest.format().as_str(),
        &request.normalizer_id,
        &request.safety_contract_id,
        finish,
        request.projection_disposition,
        &records_root,
        &claims_root,
    );
    // §9: the stored witness has to be bound to this request, not merely parse.
    require_installations_bound_to(&links, &recomputed_request_digest)?;
    // §12: so does the parent row's own record of what it committed. The
    // neighbouring column is compared against the recomputed digest, never
    // read back as if it were the truth.
    if stored.activation_request_hash.as_deref() != Some(recomputed_request_digest.as_bytes()) {
        return Ok(SourceReceiptMatch::Inconsistent { reason: ReceiptInconsistency::InvalidHeader });
    }

    // §12: the receipt key is recomputed, not taken from the column, and the
    // row must be the activation's own operation in its committed state.
    let expected_receipt_key =
        activation_receipt_key(&library_identity, &request.input_key, &recomputed_request_digest);
    let Some(receipt_key) = stored.receipt_key.as_deref() else {
        // No receipt key: either the input never completed, or a receipt was
        // installed while the parent row lost its evidence.
        let any_receipt = read_any_source_receipt(tx, &request.input_key)?;
        return match any_receipt {
            Some(_) => Ok(SourceReceiptMatch::Inconsistent {
                reason: ReceiptInconsistency::MissingReceiptWithInstallEvidence,
            }),
            None => Ok(SourceReceiptMatch::Absent),
        };
    };
    if receipt_key != expected_receipt_key {
        return Ok(SourceReceiptMatch::Inconsistent { reason: ReceiptInconsistency::InvalidHeader });
    }
    let row = read_receipt_row(tx, receipt_key)?.ok_or_else(|| SourceInstallError::Corrupt {
        detail: "the parent row names a receipt that is not in the receipt table".to_string(),
    })?;
    if row.operation != SOURCE_ACTIVATION_OPERATION || row.state != SOURCE_ACTIVATION_STATE {
        return Ok(SourceReceiptMatch::Inconsistent { reason: ReceiptInconsistency::InvalidHeader });
    }
    let receipt = decode_receipt_detail(row.detail.as_bytes())?;

    if receipt.expected_manifest_digest != manifest_digest {
        return Ok(SourceReceiptMatch::Conflict {
            expected: manifest_digest,
            found: receipt.expected_manifest_digest,
        });
    }
    if receipt.library_identity != library_identity {
        return Ok(SourceReceiptMatch::Inconsistent {
            reason: ReceiptInconsistency::LibraryMismatch,
        });
    }
    if receipt.semantic_request_digest != recomputed_request_digest {
        return Ok(SourceReceiptMatch::Inconsistent { reason: ReceiptInconsistency::RecordMismatch });
    }
    if receipt.input_key != request.input_key
        || receipt.terminal_state != request.requested_terminal
        || receipt.applied_content_generation.as_str() != stored.applied_content_generation.as_deref().unwrap_or_default()
    {
        return Ok(SourceReceiptMatch::Inconsistent { reason: ReceiptInconsistency::InvalidHeader });
    }
    if records_root != receipt.source_semantic_records_root || claims_root != receipt.claims_root {
        return Ok(SourceReceiptMatch::Inconsistent { reason: ReceiptInconsistency::RecordMismatch });
    }

    let (installed_root, binding_root, class_counts) =
        recompute_b_roots(&request.input_key, &records, &links)?;
    if installed_root != receipt.immutable_records_root
        || binding_root != receipt.original_binding_root
        || class_counts != receipt.binding_class_counts
    {
        return Ok(SourceReceiptMatch::Inconsistent { reason: ReceiptInconsistency::LinkMismatch });
    }
    let recomputed_installation_digest = installation_digest(
        &receipt.library_identity,
        &receipt.semantic_request_digest,
        &installed_root,
        &binding_root,
        &class_counts,
        receipt.terminal_state,
        &receipt.applied_content_generation,
        receipt.committed_source_facts_revision,
    );
    if recomputed_installation_digest != receipt.installation_digest {
        return Ok(SourceReceiptMatch::Inconsistent { reason: ReceiptInconsistency::LinkMismatch });
    }
    // The rows are still the ones the receipt describes; whether the *winner*
    // they point at is still the live one is a separate fact (§13.8).
    let currency = if links.iter().all(|link| link.authority.as_deref() == Some("canonical"))
        && links.iter().all(|link| link.message_id.is_some())
    {
        ReceiptCurrency::Current
    } else if links.iter().all(|link| link.message_id.is_none()) {
        ReceiptCurrency::Historical
    } else {
        ReceiptCurrency::Mixed
    };
    // A receipt whose input has since lost its completed state is recorded as
    // inconsistent rather than reported as a clean replay.
    if stored.state != "complete"
        || receipt.terminal_state != TerminalState::Complete
        || manifest.format().as_str() != stored.format
    {
        return Ok(SourceReceiptMatch::Inconsistent { reason: ReceiptInconsistency::InvalidHeader });
    }
    Ok(SourceReceiptMatch::VerifiedReplay { receipt: Box::new(receipt), currency })
}

/// Read one receipt's `detail` column.
fn read_receipt_detail(tx: &Tx<'_>, key: &str) -> Result<Option<String>, SourceInstallError> {
    Ok(read_receipt_row(tx, key)?.map(|row| row.detail))
}

/// One `operation_commit_receipt` row, with the columns that say it is this
/// activation's own committed receipt (§12).
struct StoredReceiptRow {
    operation: String,
    state: String,
    detail: String,
}

fn read_receipt_row(
    tx: &Tx<'_>,
    key: &str,
) -> Result<Option<StoredReceiptRow>, SourceInstallError> {
    Ok(tx.query_opt_map(
        "SELECT operation, state, detail FROM operation_commit_receipt WHERE idempotency_key = ?1",
        &[Value::Text(key.to_string())],
        |row| {
            Ok(StoredReceiptRow {
                operation: row.get_typed(0)?,
                state: row.get_typed(1)?,
                detail: row.get_typed(2)?,
            })
        },
    )?)
}

/// §9: every installed witness must be bound to this input's semantic request
/// digest. A witness that commits to another request — or to a placeholder — is
/// not the witness of this activation, however well its envelope decodes.
fn require_installations_bound_to(
    links: &[StoredLink],
    semantic_request_digest: &Sha256Digest,
) -> Result<(), SourceInstallError> {
    for link in links {
        if let Some(installation) = &link.installation {
            if installation.semantic_request_digest != *semantic_request_digest {
                return Err(SourceInstallError::Conflict {
                    detail: format!(
                        "the stored witness for record {} is bound to a different semantic \
                         request",
                        link.claim.record_pointer
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Find any receipt that looks like a source activation for this input, used
/// only to tell "never completed" from "completed but the parent row lost its
/// receipt key".
fn read_any_source_receipt(
    tx: &Tx<'_>,
    input_key: &Sha256Digest,
) -> Result<Option<String>, SourceInstallError> {
    Ok(tx.query_opt_map(
        "SELECT idempotency_key FROM operation_commit_receipt
         WHERE operation = ?1 AND detail LIKE ?2 LIMIT 1",
        &[
            Value::Text(SOURCE_ACTIVATION_OPERATION.to_string()),
            Value::Text(format!("%\"input_key\":\"{}\"%", input_key.hex())),
        ],
        |row| row.get_typed(0),
    )?)
}

/// The strict JSON writer for a receipt detail (§12).
fn encode_receipt_detail(receipt: &VerifiedReceipt) -> Vec<u8> {
    let mut out = Vec::new();
    let field = |out: &mut Vec<u8>, first: &mut bool, name: &str, value: &[u8]| {
        if !*first {
            out.push(b',');
        }
        *first = false;
        write_json_string(out, name);
        out.push(b':');
        out.extend_from_slice(value);
    };
    let string = |value: &str| {
        let mut buf = Vec::new();
        write_json_string(&mut buf, value);
        buf
    };
    out.push(b'{');
    let mut first = true;
    field(&mut out, &mut first, "version", b"1");
    field(&mut out, &mut first, "domain", &string(SOURCE_RECEIPT_DETAIL_DOMAIN));
    field(&mut out, &mut first, "input_key", &string(&receipt.input_key.hex()));
    field(&mut out, &mut first, "library_identity", &string(&receipt.library_identity));
    field(
        &mut out,
        &mut first,
        "semantic_request_digest",
        &string(&receipt.semantic_request_digest.hex()),
    );
    field(
        &mut out,
        &mut first,
        "installation_digest",
        &string(&receipt.installation_digest.hex()),
    );
    field(
        &mut out,
        &mut first,
        "expected_manifest_digest",
        &string(&receipt.expected_manifest_digest.hex()),
    );
    field(
        &mut out,
        &mut first,
        "source_semantic_records_root",
        &receipt.source_semantic_records_root.to_array(),
    );
    field(&mut out, &mut first, "claims_root", &receipt.claims_root.to_array());
    field(
        &mut out,
        &mut first,
        "immutable_records_root",
        &receipt.immutable_records_root.to_array(),
    );
    field(
        &mut out,
        &mut first,
        "original_binding_root",
        &encode_original_binding_root(
            &receipt.original_binding_root.sha256,
            &receipt.binding_class_counts,
        ),
    );
    field(&mut out, &mut first, "terminal_state", &string(receipt.terminal_state.as_str()));
    field(
        &mut out,
        &mut first,
        "applied_content_generation",
        &string(&receipt.applied_content_generation),
    );
    field(
        &mut out,
        &mut first,
        "committed_source_facts_revision",
        &string(&receipt.committed_source_facts_revision.to_string()),
    );
    out.push(b'}');
    out
}

/// Strictly decode a receipt detail and re-verify it against its canonical
/// bytes, so a drifted or truncated detail is a refusal rather than a
/// half-believed receipt.
pub fn decode_receipt_detail(bytes: &[u8]) -> Result<VerifiedReceipt, SourceInstallError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|err| {
        SourceInstallError::Corrupt { detail: format!("receipt detail is not JSON: {err}") }
    })?;
    let object = value.as_object().ok_or_else(|| SourceInstallError::Corrupt {
        detail: "receipt detail is not a JSON object".to_string(),
    })?;
    const FIELDS: [&str; 14] = [
        "version",
        "domain",
        "input_key",
        "library_identity",
        "semantic_request_digest",
        "installation_digest",
        "expected_manifest_digest",
        "source_semantic_records_root",
        "claims_root",
        "immutable_records_root",
        "original_binding_root",
        "terminal_state",
        "applied_content_generation",
        "committed_source_facts_revision",
    ];
    if object.len() != FIELDS.len() || FIELDS.iter().any(|name| !object.contains_key(*name)) {
        return Err(SourceInstallError::Corrupt {
            detail: "receipt detail does not carry exactly its frozen field set".to_string(),
        });
    }
    if object["version"].as_u64() != Some(1) {
        return Err(SourceInstallError::Corrupt {
            detail: "receipt detail version is not 1".to_string(),
        });
    }
    if object["domain"].as_str() != Some(SOURCE_RECEIPT_DETAIL_DOMAIN) {
        return Err(SourceInstallError::Corrupt {
            detail: "receipt detail domain does not match the frozen value".to_string(),
        });
    }
    let terminal = match object["terminal_state"].as_str() {
        Some("Complete") => TerminalState::Complete,
        Some("Partial") => TerminalState::Partial,
        Some("Failed") => TerminalState::Failed,
        _ => {
            return Err(SourceInstallError::Corrupt {
                detail: "receipt detail has an unknown terminal_state".to_string(),
            });
        }
    };
    let receipt = VerifiedReceipt {
        input_key: header_hex(&object["input_key"], "input_key")?,
        library_identity: header_str(&object["library_identity"], "library_identity")?,
        semantic_request_digest: header_hex(
            &object["semantic_request_digest"],
            "semantic_request_digest",
        )?,
        installation_digest: header_hex(&object["installation_digest"], "installation_digest")?,
        expected_manifest_digest: header_hex(
            &object["expected_manifest_digest"],
            "expected_manifest_digest",
        )?,
        source_semantic_records_root: decode_root(&object["source_semantic_records_root"])?,
        claims_root: decode_root(&object["claims_root"])?,
        immutable_records_root: decode_root(&object["immutable_records_root"])?,
        original_binding_root: decode_original_binding_root(&object["original_binding_root"])?,
        binding_class_counts: decode_binding_class_counts(&object["original_binding_root"])?,
        terminal_state: terminal,
        applied_content_generation: header_str(
            &object["applied_content_generation"],
            "applied_content_generation",
        )?,
        committed_source_facts_revision: header_decimal(
            &object["committed_source_facts_revision"],
            "committed_source_facts_revision",
        )?,
    };
    if encode_receipt_detail(&receipt) != bytes {
        return Err(SourceInstallError::Corrupt {
            detail: "receipt detail is not in its canonical form".to_string(),
        });
    }
    Ok(receipt)
}

/// One `[sha256_hex, count_decimal]` root in a receipt.
fn decode_root(value: &serde_json::Value) -> Result<Root, SourceInstallError> {
    let items = value.as_array().ok_or_else(|| SourceInstallError::Corrupt {
        detail: "a receipt root is not an array".to_string(),
    })?;
    if items.len() != 2 {
        return Err(SourceInstallError::Corrupt {
            detail: "a receipt root is not a two-element array".to_string(),
        });
    }
    Ok(Root {
        sha256: header_hex(&items[0], "root.sha256")?,
        count: header_decimal(&items[1], "root.count")?,
    })
}

/// The `original_binding_root` of a receipt: `[sha256, count, [five counts]]`.
fn decode_original_binding_root(value: &serde_json::Value) -> Result<Root, SourceInstallError> {
    let items = value.as_array().ok_or_else(|| SourceInstallError::Corrupt {
        detail: "original_binding_root is not an array".to_string(),
    })?;
    if items.len() != 3 {
        return Err(SourceInstallError::Corrupt {
            detail: "original_binding_root is not a three-element array".to_string(),
        });
    }
    Ok(Root { sha256: header_hex(&items[0], "binding root sha")?, count: header_decimal(&items[1], "binding root count")? })
}

/// The five class counters inside `original_binding_root`.
fn decode_binding_class_counts(
    value: &serde_json::Value,
) -> Result<BindingClassCounts, SourceInstallError> {
    let items = value.as_array().ok_or_else(|| SourceInstallError::Corrupt {
        detail: "original_binding_root is not an array".to_string(),
    })?;
    let counts = items
        .get(2)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| SourceInstallError::Corrupt {
            detail: "original_binding_root has no class counters".to_string(),
        })?;
    if counts.len() != 5 {
        return Err(SourceInstallError::Corrupt {
            detail: "original_binding_root does not carry five class counters".to_string(),
        });
    }
    Ok(BindingClassCounts {
        canonical_bound: header_decimal(&counts[0], "CanonicalBound")?,
        unresolved_no_binding: header_decimal(&counts[1], "UnresolvedNoBinding")?,
        standalone_no_binding: header_decimal(&counts[2], "StandaloneNoBinding")?,
        unmapped_no_binding: header_decimal(&counts[3], "UnmappedNoBinding")?,
        winner_rejected_no_binding: header_decimal(&counts[4], "WinnerRejectedNoBinding")?,
    })
}

/// The current wall-clock millisecond stamp for a receipt row.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
}

/// Keep a database failure typed instead of collapsing it into a string.
pub(crate) fn anyhow_source_error(err: anyhow::Error) -> SourceInstallError {
    match err.downcast::<StorageError>() {
        Ok(storage) => SourceInstallError::Db(storage),
        Err(other) => SourceInstallError::Activation { detail: other.to_string() },
    }
}

// =============================================================================
// Installation errors
// =============================================================================

/// Structured failure of one source-aware operation (§13.9).
///
/// DB failures keep their type ([`Self::Db`]) instead of collapsing into a
/// string, and a bad stored evidence is [`Self::Corrupt`] rather than a
/// successful "no binding" outcome.
#[derive(Debug)]
pub enum SourceInstallError {
    Schema(SourceSchemaError),
    Codec(SourceCodecError),
    Staging { detail: String },
    Activation { detail: String },
    Conflict { detail: String },
    Overflow { field: &'static str },
    EntropyUnavailable,
    Db(StorageError),
    Receipt(ReceiptInconsistency),
    Corrupt { detail: String },
    /// An input could not be read (§17.2).
    ///
    /// It carries the error kind and a static stage name and nothing else: no
    /// input bytes, no path and no upstream message, so a failure to read a
    /// sealed input can be reported without echoing what it contained.
    Io { kind: std::io::ErrorKind, stage: &'static str },
}

/// The finite receipt-consistency reasons (§10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptInconsistency {
    MissingReceiptWithInstallEvidence,
    InvalidHeader,
    RecordMismatch,
    LinkMismatch,
    LibraryMismatch,
}

impl fmt::Display for ReceiptInconsistency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingReceiptWithInstallEvidence => "missing-receipt-with-install-evidence",
            Self::InvalidHeader => "invalid-header",
            Self::RecordMismatch => "record-mismatch",
            Self::LinkMismatch => "link-mismatch",
            Self::LibraryMismatch => "library-mismatch",
        })
    }
}

impl fmt::Display for SourceInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(err) => write!(f, "source schema: {err}"),
            Self::Codec(err) => write!(f, "source codec: {err}"),
            Self::Staging { detail } => write!(f, "source staging: {detail}"),
            Self::Activation { detail } => write!(f, "source activation: {detail}"),
            Self::Conflict { detail } => write!(f, "source conflict: {detail}"),
            Self::Overflow { field } => write!(f, "source integer overflow in {field}"),
            Self::EntropyUnavailable => f.write_str("system entropy unavailable"),
            Self::Db(err) => write!(f, "storage: {err}"),
            Self::Receipt(reason) => write!(f, "receipt inconsistent: {reason}"),
            Self::Corrupt { detail } => write!(f, "source data corrupt: {detail}"),
            Self::Io { kind, stage } => {
                write!(f, "source input read failed during {stage}: {kind:?}")
            }
        }
    }
}

impl std::error::Error for SourceInstallError {}

impl From<StorageError> for SourceInstallError {
    fn from(err: StorageError) -> Self {
        Self::Db(err)
    }
}

impl From<SourceSchemaError> for SourceInstallError {
    fn from(err: SourceSchemaError) -> Self {
        Self::Schema(err)
    }
}

impl From<SourceCodecError> for SourceInstallError {
    fn from(err: SourceCodecError) -> Self {
        Self::Codec(err)
    }
}

// =============================================================================
// Prune protection (§17.1): the sealed references of retry-pending inputs
// =============================================================================

/// One sealed raw-mirror address a retry-pending source input still needs
/// (`source_inputs.sealed_ref_bin`, the version-1 sealed reference, §17.1).
///
/// The four members are returned exactly as stored, with no interpretation
/// applied. Whether they name an address this raw mirror can honour is the
/// pruner's question, and the module that owns mirror addressing answers it
/// -- interpreting a locator here would put a second address derivation in
/// the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingSealedBlobRef {
    /// The sealed-reference transport, e.g. `raw_blob`.
    pub transport: String,
    /// The address algorithm the locator is content-addressed by, e.g.
    /// `blake3`.
    pub blob_algorithm: String,
    /// The content digest the locator is addressed by.
    pub blob_digest: String,
    /// The mirror-relative locator of the sealed bytes.
    pub blob_relative_path: String,
}

/// What the read-only sealed-reference extraction found (§17.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingSealedBlobRefs {
    /// The archive predates source facts: `user_version` is below this
    /// binary's schema, so the archive carries no source tables at all and
    /// there is nothing to protect. The caller keeps its previous behaviour.
    NoSourceFacts,
    /// One entry per retry-pending `source_inputs` row, in `id` order.
    Refs(Vec<PendingSealedBlobRef>),
}

/// Why the sealed-reference extraction refused (§17.1).
///
/// The set is closed and payload-light: no variant carries source content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceSealedRefError {
    /// `PRAGMA user_version` reports a schema newer than this binary serves.
    UnsupportedVersion { found: i64 },
    /// The archive could not be read at all. On this binary's schema that
    /// means the source tables are missing or unreadable, which is a refusal
    /// and never an empty reference set.
    Unreadable { detail: String },
    /// One `sealed_ref_bin` did not decode into the frozen sealed-reference
    /// shape.
    InvalidSealedRef { input_id: i64, detail: String },
}

impl SourceSealedRefError {
    /// Stable short code for logs and robot output. Contains no source data.
    #[must_use]
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedVersion { .. } => "source-schema-unsupported",
            Self::Unreadable { .. } => "source-read-failed",
            Self::InvalidSealedRef { .. } => "sealed-ref-invalid",
        }
    }
}

impl fmt::Display for SourceSealedRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found } => write!(
                f,
                "{}: archive schema version {found} is newer than this binary's schema",
                self.code()
            ),
            Self::Unreadable { detail } => write!(f, "{}: {detail}", self.code()),
            Self::InvalidSealedRef { input_id, detail } => {
                write!(f, "{}: source input {input_id}: {detail}", self.code())
            }
        }
    }
}

impl std::error::Error for SourceSealedRefError {}

/// Read-only: the sealed raw-mirror references that `staged`, `partial` and
/// `failed` source inputs still need in order to replay (§17.1).
///
/// Version authority is `PRAGMA user_version`, the same marker
/// [`crate::storage::legacy_messages`] reads: a legal schema-7/8 archive has
/// no source tables and returns [`PendingSealedBlobRefs::NoSourceFacts`],
/// while this binary's schema must have them -- a failed read there is an
/// error, never an empty set that would let a prune delete a replay-needed
/// blob.
///
/// The stored bytes are the canonical JSON of the lossless safe tree the
/// capture wrote (`lossless_bin` above), so they are read back through the
/// same lossless reader. They are never re-interpreted as MessagePack or as
/// an arbitrary serde shape, and a reference that does not decode is refused
/// rather than skipped: skipping one would silently drop its protection.
pub(crate) fn pending_sealed_blob_refs<R: SourceSchemaRead>(
    read: &R,
) -> Result<PendingSealedBlobRefs, SourceSealedRefError> {
    let version = read
        .read_all("PRAGMA user_version;", &[], |row| row.get_typed::<i64>(0))
        .map_err(|err| SourceSealedRefError::Unreadable {
            detail: format!("schema version probe failed: {err}"),
        })?
        .into_iter()
        .next()
        .ok_or_else(|| SourceSealedRefError::Unreadable {
            detail: "schema version probe returned no row".to_string(),
        })?;
    if version < CURRENT_SCHEMA_VERSION {
        return Ok(PendingSealedBlobRefs::NoSourceFacts);
    }
    if version > CURRENT_SCHEMA_VERSION {
        return Err(SourceSealedRefError::UnsupportedVersion { found: version });
    }
    // `complete` is deliberately absent from this filter: an activated input
    // is already in the canonical archive, so its blob follows the ordinary
    // mirror retention rules. The three states below are the ones that still
    // replay from the sealed bytes.
    let rows = read
        .read_all(
            "SELECT id, sealed_ref_bin FROM source_inputs \
             WHERE state IN ('staged', 'partial', 'failed') ORDER BY id",
            &[],
            |row| Ok((row.get_typed::<i64>(0)?, row.get_typed::<Vec<u8>>(1)?)),
        )
        .map_err(|err| SourceSealedRefError::Unreadable {
            detail: format!("sealed reference query failed: {err}"),
        })?;
    let mut refs = Vec::with_capacity(rows.len());
    for (input_id, bytes) in rows {
        refs.push(decode_pending_sealed_blob_ref(input_id, &bytes)?);
    }
    Ok(PendingSealedBlobRefs::Refs(refs))
}

/// Strictly decode one `sealed_ref_bin` into its four recorded members.
///
/// Only the shape this module writes is accepted: one well-formed JSON value
/// that is an object carrying the four string members the capture records. A
/// non-object tree, a missing or non-string member, or a payload that is not
/// one complete JSON value is refused -- never degraded to an empty value.
fn decode_pending_sealed_blob_ref(
    input_id: i64,
    bytes: &[u8],
) -> Result<PendingSealedBlobRef, SourceSealedRefError> {
    let tree =
        LosslessSourceValue::parse(bytes).map_err(|_| SourceSealedRefError::InvalidSealedRef {
            input_id,
            detail: "sealed reference is not one well-formed JSON value".to_string(),
        })?;
    let member = |name: &str| -> Result<String, SourceSealedRefError> {
        tree.get(name)
            .and_then(LosslessSourceValue::as_str)
            .map(str::to_string)
            .ok_or_else(|| SourceSealedRefError::InvalidSealedRef {
                input_id,
                detail: format!("sealed reference member `{name}` is missing or not a string"),
            })
    };
    Ok(PendingSealedBlobRef {
        transport: member("transport")?,
        blob_algorithm: member("blob_algorithm")?,
        blob_digest: member("blob_digest")?,
        blob_relative_path: member("blob_relative_path")?,
    })
}

// =============================================================================
// Forget/purge: the source copies of canonical data (§14.5)
// =============================================================================
//
// `cass forget --source-glob` and `cass sources agents exclude` delete
// canonical rows. The source-aware tables are a *copy* of that same canonical
// data, so the source facts they matched have to leave in the same
// transaction -- otherwise the content an operator asked to forget stays
// readable through the source tables ([`visible_facts_digest`] is exactly what
// a reader recomputes from them).
//
// Two rules keep this from widening the old deletion scope:
//
// - The selection is the **original** locator. `root_id_bin` joined with
//   `relative_locator_bin` is the path the ingest derived, so the forget glob
//   means the same thing here as it does over `conversations.source_path`.
//   Today's filesystem, a canonicalized path and a workspace rewrite are all
//   deliberately not consulted.
// - A canonical link whose message is about to disappear, but whose own input
//   is *not* matched, is historyized instead of deleted: the row keeps every
//   immutable installation member and only moves `authority`/`message_id`.
//   Without that step the message delete's `ON DELETE SET NULL` would collide
//   with the canonical CHECK (schema §6) and abort the whole transaction.

/// How a forget/purge entry point picks the source inputs it removes.
///
/// Two matchers, one per operator. They are not interchangeable: the glob
/// addresses original locators, the connector addresses the agent an operator
/// excluded, and each entry point uses exactly one of them.
#[derive(Debug, Clone)]
pub(crate) enum SourceDeletionSelection {
    /// Every input whose original locator path matches (`cass forget`).
    OriginalGlob(glob::Pattern),
    /// Every input whose connector is this slug (`cass sources agents
    /// exclude`).
    Connector(String),
}

/// The bound both entries apply to a reported original-locator sample.
const SOURCE_LOCATOR_SAMPLE_LIMIT: usize = 20;

/// Bound on one `IN (...)` statement. Matching runs in Rust over the decoded
/// locators, so the selected-id list is unbounded in principle; deleting and
/// counting it in bounded statement-sized batches keeps every statement's text
/// and parameter count fixed no matter how much a glob matches.
const SOURCE_DELETE_BATCH_ROWS: usize = 500;

/// The source facts one selection matches, before anything is removed.
#[derive(Debug, Default, Clone)]
pub(crate) struct SourceSelection {
    pub(crate) input_ids: Vec<i64>,
    /// Whether each matched input is *published*, positionally paired with
    /// `input_ids` (§15.3).
    ///
    /// Published means this input's facts are in one of the readers' stable
    /// fact domains: a `complete` input (the default analysis view), or one
    /// whose attempt ended in a final failure publication (the all-source
    /// oracle's view). A `staged` input, and a `failed`/`partial` row that
    /// only ever reached the attempt record (`StagedOnly`), are private
    /// staging state -- no stable reader domain ever included them, so
    /// removing them changes nothing a reader can see.
    pub(crate) input_published: Vec<bool>,
    /// The activation receipt key each matched input names, positionally
    /// paired with `input_ids` (`None` where the column is NULL).
    pub(crate) receipt_keys: Vec<Option<String>>,
    pub(crate) records_matched: usize,
    pub(crate) links_matched: usize,
    /// Bounded sample of the matched inputs' original locator paths.
    pub(crate) sample_locators: Vec<String>,
}

/// What one [`delete_source_facts_in_tx`] actually removed.
///
/// The deletion range and the visibility decision are deliberately separate
/// numbers. Every matched input is removed whatever state it is in (§14.5),
/// while `source_facts_revision` moves only for the part a reader can actually
/// see (§15.3).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SourceDeletionOutcome {
    pub(crate) inputs_deleted: usize,
    pub(crate) records_deleted: usize,
    pub(crate) links_deleted: usize,
    pub(crate) links_historicalized: usize,
    /// The removed inputs a stable fact domain could see (§15.3): `complete`,
    /// or a final failure publication.
    pub(crate) published_inputs_deleted: usize,
}

impl SourceDeletionOutcome {
    /// Whether this outcome is a visible change to the source facts, and so
    /// earns the single `source_facts_revision` increment (§15.3).
    ///
    /// Two things move the revision: a published input leaving its stable
    /// fact domain (§15.3 -- the complete-facts view, and the all-source
    /// oracle once a final outcome is published), and a link being historyized
    /// (an association change). Private staging state does not: deleting a
    /// never-activated `staged` page, or a `StagedOnly` attempt row, is
    /// invisible to every stable domain, which is exactly why §15.3 keeps
    /// those reads off the facts revision. A dry run, an unmatched selection
    /// and a repeated apply leave every counter at zero, which is what keeps
    /// the revision still across them.
    #[must_use]
    pub(crate) fn is_visible_change(&self) -> bool {
        self.published_inputs_deleted > 0 || self.links_historicalized > 0
    }
}

/// Whether one stored input's facts sit in a stable fact domain (§15.3).
///
/// The `state` column alone is not the answer: a `failed`/`partial` row is
/// published only when the failure publication really ran, which is what
/// writes `unprocessed_ranges_bin` and carries the `last_published_failure`
/// witness. A row that only reached the attempt record keeps
/// `unprocessed_ranges_bin` NULL and stays out of every stable domain --
/// `staged` pages and `StagedOnly` attempts are read through the separate
/// diagnostics surface, which §15.3 keeps off the facts revision.
#[must_use]
fn stored_input_is_published(state: &str, unprocessed_ranges_present: bool) -> bool {
    state == "complete" || unprocessed_ranges_present
}

/// Rebuild one stored input's original locator path.
///
/// `root_id_bin` and `relative_locator_bin` hold the raw UTF-8 bytes of the
/// original scan root and of the input's place inside it (§4), so the path is
/// their join -- the same path this ingest derived at capture time. A stored
/// value that is not UTF-8 is refused rather than lossily replaced: a lossy
/// decode would match a *different* path and remove the wrong copy.
fn original_locator_path(root: &[u8], relative: &[u8]) -> Result<String, StorageError> {
    let not_utf8 = || StorageError::Corrupt {
        detail: "a stored source original locator is not UTF-8".to_string(),
    };
    let root = std::str::from_utf8(root).map_err(|_| not_utf8())?;
    let relative = std::str::from_utf8(relative).map_err(|_| not_utf8())?;
    Path::new(root)
        .join(relative)
        .into_os_string()
        .into_string()
        .map_err(|_| not_utf8())
}

/// The `?1, ?2, ...` placeholder list for one bounded `IN (...)`, starting at
/// parameter `first`.
fn source_in_placeholders_from(count: usize, first: usize) -> String {
    let mut out = String::with_capacity(count * 4);
    for index in 0..count {
        if index > 0 {
            out.push_str(", ");
        }
        out.push('?');
        out.push_str(&(first + index).to_string());
    }
    out
}

/// The `?1, ?2, ...` placeholder list for one bounded `IN (...)` statement.
fn source_in_placeholders(count: usize) -> String {
    source_in_placeholders_from(count, 1)
}

fn integer_params(ids: &[i64]) -> Vec<Value> {
    ids.iter().map(|id| Value::from(*id)).collect()
}

/// Count the `source_records` rows one bounded input batch owns.
fn count_records_under_inputs_in_tx(tx: &Tx<'_>, input_ids: &[i64]) -> Result<usize, StorageError> {
    let placeholders = source_in_placeholders(input_ids.len());
    let count: i64 = tx.query_row_map(
        &format!("SELECT COUNT(*) FROM source_records WHERE input_id IN ({placeholders})"),
        &integer_params(input_ids),
        |row| row.get_typed(0),
    )?;
    Ok(count.max(0) as usize)
}

/// Count the `source_message_links` rows one bounded input batch owns.
fn count_links_under_inputs_in_tx(tx: &Tx<'_>, input_ids: &[i64]) -> Result<usize, StorageError> {
    let placeholders = source_in_placeholders(input_ids.len());
    let count: i64 = tx.query_row_map(
        &format!(
            "SELECT COUNT(*) FROM source_message_links
             WHERE record_id IN (SELECT id FROM source_records WHERE input_id IN ({placeholders}))"
        ),
        &integer_params(input_ids),
        |row| row.get_typed(0),
    )?;
    Ok(count.max(0) as usize)
}

/// Every stored input whose original locator matches `selection`, plus the
/// matched record/link counts and the bounded locator sample.
///
/// Read-only: it never mutates a row, so the dry-run and the operator preview
/// can call it on the same code path as the deletion does.
pub(crate) fn select_source_inputs_in_tx(
    tx: &Tx<'_>,
    selection: &SourceDeletionSelection,
) -> Result<SourceSelection, StorageError> {
    let rows: Vec<(i64, Vec<u8>, Vec<u8>, String, String, bool, Option<String>)> = tx
        .query_all_map(
            "SELECT id, root_id_bin, relative_locator_bin, connector, state,
                unprocessed_ranges_bin IS NOT NULL, receipt_key
         FROM source_inputs ORDER BY id",
            &[],
            |row| {
                Ok((
                    row.get_typed::<i64>(0)?,
                    row.get_typed::<Vec<u8>>(1)?,
                    row.get_typed::<Vec<u8>>(2)?,
                    row.get_typed::<String>(3)?,
                    row.get_typed::<String>(4)?,
                    row.get_typed::<bool>(5)?,
                    row.get_typed::<Option<String>>(6)?,
                ))
            },
        )?;

    let mut selected = SourceSelection::default();
    for (id, root, relative, connector, state, published_failure, receipt_key) in rows {
        let matched = match selection {
            // The purge matches on the connector alone, so it decodes no
            // locator: a row this selection does not touch must not be able
            // to fail the operation over bytes nothing here reads.
            SourceDeletionSelection::Connector(slug) => connector == *slug,
            SourceDeletionSelection::OriginalGlob(pattern) => {
                let path = original_locator_path(&root, &relative)?;
                let matched = pattern.matches(&path);
                if matched && selected.sample_locators.len() < SOURCE_LOCATOR_SAMPLE_LIMIT {
                    selected.sample_locators.push(path);
                }
                matched
            }
        };
        if matched {
            selected.input_ids.push(id);
            selected
                .input_published
                .push(stored_input_is_published(&state, published_failure));
            selected.receipt_keys.push(receipt_key);
        }
    }

    for batch in selected.input_ids.chunks(SOURCE_DELETE_BATCH_ROWS) {
        selected.records_matched += count_records_under_inputs_in_tx(tx, batch)?;
        selected.links_matched += count_links_under_inputs_in_tx(tx, batch)?;
    }
    Ok(selected)
}

/// Historyize only the canonical links of the messages the caller is about to
/// delete: `authority = 'historical'`, `message_id = NULL`.
///
/// Nothing else moves. Every immutable member of the link row -- envelope,
/// claim, `OriginalInstallation`, `binding_digest` -- stays byte-for-byte as it
/// was, as do `payload`, `source_inputs`, `source_records` and the activation
/// receipt. Rows of any other authority, and rows naming another message, are
/// never touched. A message id that SQLite later reuses for a new row does not
/// revive an old link: the old row already carries `historical`/`NULL`, and the
/// new installation writes its own row.
///
/// The helper does **not** move `source_facts_revision`. A caller that must
/// make the change visible installs a new activation in the same transaction
/// (which moves the revision exactly once) or lets its transaction roll back.
/// The delete entry point keeps its own single advance and calls this helper
/// for the link half.
pub(crate) fn historyize_source_message_links_in_tx(
    tx: &Tx<'_>,
    protected_message_ids: &[i64],
) -> Result<usize, StorageError> {
    let mut historicalized = 0usize;
    for batch in protected_message_ids.chunks(SOURCE_DELETE_BATCH_ROWS) {
        let placeholders = source_in_placeholders(batch.len());
        historicalized += tx.execute(
            &format!(
                "UPDATE source_message_links SET authority = 'historical', message_id = NULL
                 WHERE authority = 'canonical' AND message_id IN ({placeholders})"
            ),
            &integer_params(batch),
        )?;
    }
    Ok(historicalized)
}

/// Remove the source copies `selection` matches, in the caller's transaction.
///
/// Runs in three bounded steps and returns what it really removed:
///
/// 1. every matched `source_inputs` row is deleted; `source_records` and
///    `source_message_links` follow through the two `ON DELETE CASCADE` edges
///    the frozen DDL declares, so no row is ever left orphaned by hand and no
///    extra deletion machinery is introduced. The activation receipt each
///    `complete` input names in its own `receipt_key` column goes with it, for
///    the same consistency reason: a receipt whose input is gone can never be
///    re-verified, so the next ingest of that file would be refused instead of
///    simply indexed again;
/// 2. every *surviving* canonical link whose message is in
///    `protected_message_ids` -- the messages the caller is about to delete --
///    is historyized, so the message delete's `ON DELETE SET NULL` cannot
///    collide with the canonical CHECK. The link's envelope, digest and every
///    other immutable member stay byte-for-byte as they were; only the
///    `authority`/`message_id` pair moves;
/// 3. `source_facts_revision` moves once, and only when step 1 or step 2
///    changed something the **default reader** can see (§15.3): a published
///    input leaving the complete-facts set, or a link whose association moved.
///    A never-published `staged` page and a `StagedOnly` attempt row are
///    removed just the same but are invisible, so they do not move it.
///
/// A no-op selection, a repeated apply and a rolled-back transaction all leave
/// the revision exactly where it was.
pub(crate) fn delete_source_facts_in_tx(
    tx: &Tx<'_>,
    selection: &SourceDeletionSelection,
    protected_message_ids: &[i64],
) -> Result<SourceDeletionOutcome, StorageError> {
    let selected = select_source_inputs_in_tx(tx, selection)?;
    let mut outcome = SourceDeletionOutcome::default();

    for (batch, published) in selected
        .input_ids
        .chunks(SOURCE_DELETE_BATCH_ROWS)
        .zip(selected.input_published.chunks(SOURCE_DELETE_BATCH_ROWS))
    {
        outcome.published_inputs_deleted += published.iter().filter(|flag| **flag).count();
        outcome.records_deleted += count_records_under_inputs_in_tx(tx, batch)?;
        outcome.links_deleted += count_links_under_inputs_in_tx(tx, batch)?;
        let placeholders = source_in_placeholders(batch.len());
        outcome.inputs_deleted += tx.execute(
            &format!("DELETE FROM source_inputs WHERE id IN ({placeholders})"),
            &integer_params(batch),
        )?;
    }

    // The activation receipt goes with its input, and the binding is an
    // **existing exact column**, not a guess: `source_inputs.receipt_key` is
    // NOT NULL for exactly the `complete` inputs (the frozen CHECK guarantees
    // it) and holds the `operation_commit_receipt` primary key the activation
    // wrote. Nothing is matched by the shape of a `detail` blob.
    //
    // It has to go: a receipt whose input row no longer exists can never be
    // re-verified, and the next ingest of that file is refused as
    // `receipt inconsistent` instead of simply being indexed again.
    //
    // A `complete` input naming a key outside the source receipt namespace
    // cannot be correlated at all, so the whole transaction is refused rather
    // than a differently-namespaced receipt being removed by coincidence.
    let mut receipt_keys: Vec<String> = Vec::new();
    for key in selected.receipt_keys.iter().flatten() {
        if !key.starts_with(SOURCE_RECEIPT_KEY_PREFIX) {
            return Err(StorageError::Corrupt {
                detail: "a complete source input names a foreign receipt key".to_string(),
            });
        }
        receipt_keys.push(key.clone());
    }
    for batch in receipt_keys.chunks(SOURCE_DELETE_BATCH_ROWS) {
        let mut params: Vec<Value> = vec![Value::Text(SOURCE_ACTIVATION_OPERATION.to_string())];
        for key in batch {
            params.push(Value::Text(key.clone()));
        }
        let placeholders = source_in_placeholders_from(batch.len(), 2);
        tx.execute(
            &format!(
                "DELETE FROM operation_commit_receipt
                 WHERE operation = ?1 AND idempotency_key IN ({placeholders})"
            ),
            &params,
        )?;
    }

    outcome.links_historicalized +=
        historyize_source_message_links_in_tx(tx, protected_message_ids)?;

    if outcome.is_visible_change() {
        let revision = read_source_facts_revision(tx).map_err(source_install_into_storage)?;
        let next = revision.checked_add(1).ok_or(StorageError::Corrupt {
            detail: "source_facts_revision overflowed".to_string(),
        })?;
        write_source_facts_revision(tx, next).map_err(source_install_into_storage)?;
    }
    Ok(outcome)
}

/// Keep a storage failure typed when a source-facts primitive crosses back
/// into the storage layer. The deletes above produce only `Db` and `Corrupt`,
/// so nothing else is silently re-labelled as corruption.
fn source_install_into_storage(err: SourceInstallError) -> StorageError {
    match err {
        SourceInstallError::Db(inner) => inner,
        other => StorageError::Corrupt {
            detail: other.to_string(),
        },
    }
}

/// Test-only fault injection for the same-transaction source deletion.
///
/// Deliberately `#[cfg(test)]`: acceptance D needs a *late* failure inside the
/// delete transaction, and a production fault switch (an environment variable)
/// would be a new way for a real run to fail. The flag is thread-local, so a
/// parallel test cannot arm another test's transaction.
#[cfg(test)]
pub(crate) mod delete_fault_hooks {
    use std::cell::Cell;

    thread_local! {
        static FAIL_LATE_IN_DELETE_TX: Cell<bool> = const { Cell::new(false) };
    }

    /// Arm the next (and every following) delete transaction on this thread to
    /// fail after its work is done and before it commits.
    pub(crate) fn arm_late_delete_failure() {
        FAIL_LATE_IN_DELETE_TX.with(|flag| flag.set(true));
    }

    /// Disarm it again.
    pub(crate) fn disarm_late_delete_failure() {
        FAIL_LATE_IN_DELETE_TX.with(|flag| flag.set(false));
    }

    /// Whether a transaction on this thread should fail late.
    #[must_use]
    pub(crate) fn late_delete_failure_armed() -> bool {
        FAIL_LATE_IN_DELETE_TX.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One scratch database with a minimal, internally consistent triple of
    /// rows: a parent input, one staged record, and — when the caller asks —
    /// the link row that record carries for one claim.
    fn zeros(len: usize) -> Value {
        Value::Blob(vec![0u8; len])
    }

    struct ScratchLink {
        dir: tempfile::TempDir,
        storage: crate::storage::sqlite::FrankenStorage,
        input_id: i64,
        input_key: Sha256Digest,
        claim: SourceClaim,
    }

    fn scratch_link() -> ScratchLink {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let storage = crate::storage::sqlite::FrankenStorage::open(&dir.path().join("t.db"))
            .expect("open the database");
        let input_key = Sha256Digest::of(dir.path().as_os_str().as_encoded_bytes());
        let claim = SourceClaim {
            input_key,
            record_ordinal: 1,
            record_pointer: "r0".to_string(),
            conversation_ordinal: Some(0),
            final_message_idx: Some(0),
            positions: Vec::new(),
            projection_pointer: Some("/messages/0".to_string()),
            evidence_kind: EvidenceKind::Prose,
            mapping_state: ClaimMappingState::Canonical,
        };
        let input_id = {
            let tx = storage.raw().transaction().expect("begin");
            tx.execute(
                "INSERT INTO source_inputs (input_key, identity_tuple_bin, source_id,
                     identity_namespace, connector, root_id_bin, relative_locator_bin,
                     discovery_bin, parser_context_bin, context_digest, sealed_ref_bin,
                     sealed_sha256, byte_len, format, expected_manifest_bin, normalizer_id,
                     safety_contract_id, state, expected_records, expected_blank_lines)
                 VALUES (?1, ?2, 'src', 'ns', 'claude', x'72', x'6c', x'00', x'00',
                     ?3, x'00', ?4, ?5, 'jsonl', x'00', 'norm', 'safe', 'staged', ?6, ?7)",
                &[
                    // input_key, identity_tuple_bin (opaque), context_digest,
                    // sealed_sha256, byte_len, expected_records,
                    // expected_blank_lines -- the frozen DDL pins the widths
                    // of the last five.
                    Value::Blob(input_key.as_bytes().to_vec()),
                    zeros(32),
                    zeros(32),
                    zeros(32),
                    zeros(8),
                    zeros(8),
                    zeros(8),
                ],
            )
            .expect("insert the parent input");
            let id = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO source_records (input_id, ordinal, record_pointer, position_bin,
                     expected_source_record_sha256, frame_state, parse_state,
                     record_mapping_state, safety_state, retention_state)
                 VALUES (?1, ?2, ?3, x'00', ?4, 'frame_pending', 'parsed', 'all_canonical',
                     'preserved', 'payload_absent')",
                &[
                    Value::Integer(id),
                    ordinal_blob(1),
                    Value::Text(claim.record_pointer.clone()),
                    zeros(32),
                ],
            )
            .expect("insert the record");
            tx.commit().expect("commit the scratch rows");
            id
        };
        ScratchLink { dir, storage, input_id, input_key, claim }
    }

    impl ScratchLink {
        /// Write the link row for `stored_claim` with `installation`, exactly as
        /// the install path would: envelope, digest column, authority and
        /// message id must all agree or the decode step refuses the row.
        fn write_link_row(
            &self,
            stored_claim: &SourceClaim,
            installation: Option<OriginalInstallation>,
        ) -> Result<(), SourceInstallError> {
            let positions = encode_link_evidence(stored_claim, installation.as_ref())?;
            let digest = match &installation {
                Some(installation) => binding_digest(stored_claim, installation),
                None => stored_claim.pending_claim_digest(),
            };
            let (authority, message_id) = match &installation {
                Some(installation) => (
                    Value::Text(authority_for(installation).to_string()),
                    match message_id_for(installation) {
                        Some(id) => Value::Integer(id),
                        None => Value::Null,
                    },
                ),
                None => (Value::Null, Value::Null),
            };
            let tx = self.storage.raw().transaction()?;
            let record_id: i64 = tx
                .query_row_map(
                    "SELECT id FROM source_records WHERE input_id = ?1",
                    &[Value::Integer(self.input_id)],
                    |row| row.get_typed(0),
                )?;
            let (conversation_ordinal, final_message_idx, projection_pointer) =
                target_triple(stored_claim);
            tx.execute(
                "INSERT INTO source_message_links (record_id, projection_key,
                     conversation_ordinal, final_message_idx, source_positions_bin,
                     projection_pointer, message_id, authority, evidence_kind, binding_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                &[
                    Value::Integer(record_id),
                    Value::Blob(stored_claim.projection_key().as_bytes().to_vec()),
                    conversation_ordinal,
                    final_message_idx,
                    Value::Blob(positions),
                    projection_pointer,
                    message_id,
                    authority,
                    Value::Text(stored_claim.evidence_kind.as_str().to_string()),
                    Value::Blob(digest.as_bytes().to_vec()),
                ],
            )?;
            tx.commit()?;
            Ok(())
        }

        fn read(&self, claim: &SourceClaim) -> Result<InstalledLinkEvidence, SourceInstallError> {
            let tx = self.storage.raw().transaction().expect("begin");
            read_installed_link_evidence(&tx, self.input_id, claim)
        }

        /// A claim that differs from the stored one only in a field the
        /// projection key does not cover.
        fn variant(&self) -> SourceClaim {
            let mut claim = self.claim.clone();
            claim.mapping_state = ClaimMappingState::Unmapped;
            claim
        }
    }

    /// A legal `UnresolvedNoBinding`: a reason that is not a winner rejection,
    /// and neither a binding nor a rejection.
    fn unbound_installation() -> OriginalInstallation {
        OriginalInstallation {
            semantic_request_digest: Sha256Digest::of(b"synthetic request"),
            class: InstallationClass::UnresolvedNoBinding,
            binding: None,
            rejection: None,
            reason: Some(ReplayRejectReason::NoMatchingStoredRow),
        }
    }

    /// An `UnresolvedNoBinding` with no reason at all: a digest that agrees
    /// with its own envelope, in a shape its class does not allow.
    fn unbound_installation_without_a_reason() -> OriginalInstallation {
        OriginalInstallation {
            reason: None,
            ..unbound_installation()
        }
    }

    /// A digest that agrees with its own envelope does not make a substituted
    /// member legal: each class fixes which members it carries, and a claim
    /// that does not belong to the class is just as illegal as a missing one.
    #[test]
    fn class_shape_refuses_a_substituted_member_or_a_foreign_claim() {
        // A canonical binding with no binding member.
        assert!(!installation_shape_matches_class(&OriginalInstallation {
            class: InstallationClass::CanonicalBound,
            ..unbound_installation()
        }));
        // A winner rejection with no rejection member.
        assert!(!installation_shape_matches_class(&OriginalInstallation {
            class: InstallationClass::WinnerRejectedNoBinding,
            ..unbound_installation()
        }));
        // A standalone installation that also carries a rejection.
        assert!(!installation_shape_matches_class(&OriginalInstallation {
            class: InstallationClass::StandaloneNoBinding,
            binding: None,
            rejection: Some(WinnerRejectionEvidence {
                claim_digest: Sha256Digest::of(b"claim"),
                conversation_identity_digest: Sha256Digest::of(b"identity"),
                incoming_idx: 0,
                incoming_merge_fingerprint: MergeFingerprint {
                    idx: 0,
                    created_at: Some(10),
                    role: "User".to_string(),
                    author: None,
                    content_blake3_hex: "cd".repeat(32),
                },
                winner_conversation_id: 1,
                winner_message_id: 2,
                winner_idx: 1,
                winner_merge_fingerprint: MergeFingerprint {
                    idx: 1,
                    created_at: Some(10),
                    role: "User".to_string(),
                    author: None,
                    content_blake3_hex: "ab".repeat(32),
                },
            }),
            reason: None,
            ..unbound_installation()
        }));

        // The claim side: the same installation members under a claim of
        // another kind are not a legal pair.
        let scratch = scratch_link();
        assert!(claim_shape_matches_class(
            &scratch.claim,
            InstallationClass::CanonicalBound
        ));
        for class in [
            InstallationClass::StandaloneNoBinding,
            InstallationClass::UnmappedNoBinding,
        ] {
            assert!(
                !claim_shape_matches_class(&scratch.claim, class),
                "a canonical claim cannot carry a {} installation",
                class.as_str()
            );
        }
        let mut standalone_claim = scratch.claim.clone();
        standalone_claim.conversation_ordinal = None;
        standalone_claim.final_message_idx = None;
        standalone_claim.projection_pointer = None;
        standalone_claim.mapping_state = ClaimMappingState::Standalone;
        standalone_claim.evidence_kind = EvidenceKind::NoMessage;
        assert!(claim_shape_matches_class(
            &standalone_claim,
            InstallationClass::StandaloneNoBinding
        ));
        assert!(
            !claim_shape_matches_class(&standalone_claim, InstallationClass::UnmappedNoBinding),
            "a standalone claim is not an unmapped one"
        );
    }

    #[test]
    fn link_evidence_rejects_partial_targets_for_unbound_claims() {
        for (class, mapping_state, evidence_kind) in [
            (
                InstallationClass::StandaloneNoBinding,
                ClaimMappingState::Standalone,
                EvidenceKind::NoMessage,
            ),
            (
                InstallationClass::UnmappedNoBinding,
                ClaimMappingState::Unmapped,
                EvidenceKind::ParseFailed,
            ),
        ] {
            for present_fields in 0_u8..8 {
                let scratch = scratch_link();
                let claim = SourceClaim {
                    conversation_ordinal: (present_fields & 1 != 0).then_some(0),
                    final_message_idx: (present_fields & 2 != 0).then_some(0),
                    projection_pointer: (present_fields & 4 != 0)
                        .then(|| "/messages/0".to_string()),
                    mapping_state,
                    evidence_kind,
                    ..scratch.claim.clone()
                };
                let installation = OriginalInstallation {
                    class,
                    reason: None,
                    ..unbound_installation()
                };
                assert_eq!(
                    claim_shape_matches_class(&claim, class),
                    present_fields == 0,
                    "{} requires all target fields to be absent (mask {present_fields})",
                    class.as_str(),
                );
                // The envelope and digest agree. The table must reject target
                // fields on unbound rows before a reader can consume them.
                let written = scratch.write_link_row(&claim, Some(installation.clone()));
                if present_fields == 0 {
                    written.expect("persist the valid unbound row");
                    assert_eq!(
                        scratch.read(&claim).expect("read the valid unbound row"),
                        InstalledLinkEvidence::Installed(Box::new(installation)),
                    );
                } else {
                    let error = written.expect_err("the schema refuses an unbound target");
                    assert!(
                        error.to_string().contains("CHECK constraint failed"),
                        "{} with target field mask {present_fields}: {error}",
                        class.as_str()
                    );
                }
            }
        }
    }

    #[test]
    fn link_evidence_separates_absent_pending_and_installed() {
        let scratch = scratch_link();

        assert_eq!(
            scratch.read(&scratch.claim).expect("no row is not an error"),
            InstalledLinkEvidence::Absent
        );

        scratch.write_link_row(&scratch.claim, None).expect("write pending link");
        assert_eq!(
            scratch.read(&scratch.claim).expect("a pending row reads"),
            InstalledLinkEvidence::Pending
        );

        // Replacing the pending row with a real installation is what the
        // install path does on a first successful installation.
        {
            let tx = scratch.storage.raw().transaction().expect("begin");
            tx.execute("DELETE FROM source_message_links", &[]).expect("clear");
            tx.commit().expect("commit");
        }
        let installation = unbound_installation();
        scratch
            .write_link_row(&scratch.claim, Some(installation.clone()))
            .expect("write installed link");
        assert_eq!(
            scratch.read(&scratch.claim).expect("an installed row reads"),
            InstalledLinkEvidence::Installed(Box::new(installation))
        );
    }

    #[test]
    fn link_evidence_refuses_a_different_claim_a_different_input_and_a_damaged_row() {
        let scratch = scratch_link();
        scratch
            .write_link_row(&scratch.claim, Some(unbound_installation()))
            .expect("write installed link");

        let err = scratch
            .read(&scratch.variant())
            .expect_err("a row that encodes another claim is not evidence");
        assert!(
            matches!(err, SourceInstallError::Conflict { .. }),
            "a different claim is a conflict, never a fallback: {err:?}"
        );

        let other = scratch_link();
        let err = read_installed_link_evidence(
            &other.storage.raw().transaction().expect("begin"),
            other.input_id,
            &scratch.claim,
        )
        .expect_err("a claim handed to another input is refused");
        assert!(
            matches!(err, SourceInstallError::Conflict { .. }),
            "a wrong input is a conflict: {err:?}"
        );

        {
            let tx = scratch.storage.raw().transaction().expect("begin");
            tx.execute(
                "UPDATE source_message_links SET source_positions_bin = x'ff'",
                &[],
            )
            .expect("damage the envelope");
            tx.commit().expect("commit");
        }
        let err = scratch
            .read(&scratch.claim)
            .expect_err("a damaged envelope is not a pending row");
        assert!(
            matches!(err, SourceInstallError::Corrupt { .. }),
            "a damaged row is corruption: {err:?}"
        );

        // A row whose digest is self-consistent but whose installation does
        // not carry the members its class requires is corruption too.
        {
            let tx = scratch.storage.raw().transaction().expect("begin");
            tx.execute("DELETE FROM source_message_links", &[]).expect("clear");
            tx.commit().expect("commit");
        }
        scratch.write_link_row(
            &scratch.claim,
            Some(unbound_installation_without_a_reason()),
        ).expect("write a self-consistent but invalid installation");
        let err = scratch
            .read(&scratch.claim)
            .expect_err("an illegal class shape is not evidence");
        assert!(
            matches!(err, SourceInstallError::Corrupt { .. }),
            "an installation whose members do not match its class is corrupt: {err:?}"
        );

        let stray = SourceClaim { record_ordinal: 99, ..scratch.claim.clone() };
        let err = scratch
            .read(&stray)
            .expect_err("a claim whose record is not staged is refused");
        assert!(
            matches!(err, SourceInstallError::Staging { .. }),
            "an unstaged record is a staging error: {err:?}"
        );
        let _ = &scratch.input_key;
    }

    #[test]
    fn json_string_escape_rule_matches_contract() {
        let mut out = Vec::new();
        write_json_string(&mut out, "a\"b\\c\nd\te\u{1}f\u{7f}g中");
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text, "\"a\\\"b\\\\c\\nd\\te\\u0001f\u{7f}g中\"");
    }

    #[test]
    fn canonical_tuple_writes_numbers_as_decimal_strings() {
        let mut tuple = CanonicalTuple::new();
        tuple.str("x").dec(7).idec(-3).boolean(true).null();
        assert_eq!(String::from_utf8(tuple.finish()).unwrap(), "[\"x\",\"7\",\"-3\",true,null]");
    }

    #[test]
    fn projection_key_gold_matches_contract() {
        // §12 gold: canonical triplet.
        let mut tuple = CanonicalTuple::new();
        tuple
            .str("cass.source-projection/1")
            .json_int(0)
            .json_int(3)
            .str("/messages/3");
        assert_eq!(
            tuple.finish_sha().hex(),
            "48dcbaed5ab8ea9ffef451e1a95c2997c6cf6ba677a599ead26c5efd7be6f0b8"
        );

        // §12 gold: all-null triplet.
        let mut tuple = CanonicalTuple::new();
        tuple
            .str("cass.source-projection/1")
            .opt_json_int(None)
            .opt_json_int(None)
            .opt_str(None);
        assert_eq!(
            tuple.finish_sha().hex(),
            "10175b4ba5821f831e2fd1a05b3dacf1e2ecc4e417d9e1623ca91e69d1e7c77c"
        );
    }

    #[test]
    fn normalize_sql_collapses_whitespace() {
        assert_eq!(normalize_sql("CREATE  TABLE\n a (\n x\n)"), "CREATE TABLE a ( x )");
    }

    #[test]
    fn library_identity_uuid_has_version_and_variant_bits() {
        crate::storage::schema::generate_library_identity_uuid_v4()
            .map(|uuid| {
                let parts: Vec<&str> = uuid.split('-').collect();
                assert_eq!(parts.len(), 5);
                assert_eq!(parts[0].len(), 8);
                assert_eq!(parts[1].len(), 4);
                assert_eq!(parts[2].len(), 4);
                assert_eq!(parts[3].len(), 4);
                assert_eq!(parts[4].len(), 12);
                assert!(parts[2].starts_with('4'), "version nibble: {uuid}");
                assert!(
                    matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'),
                    "variant nibble: {uuid}"
                );
            })
            .expect("entropy available in test environment");
    }

    fn leaf(ordinal: u64, payload: Option<Sha256Digest>) -> Vec<u8> {
        let record = StagedRecordLeafInput {
            locator: SourceRecordLocator {
                ordinal,
                record_pointer: "record-0".to_string(),
                byte_start: 0,
                byte_end: 10,
            },
            expected_raw_sha256: Sha256Digest::of(b"raw"),
            observed_raw_sha256: Some(Sha256Digest::of(b"raw")),
            parse_state: ParseState::Parsed,
            record_mapping_state: RecordMappingState::AllCanonical,
            safety_state: SafetyState::Preserved,
            retention_state: if payload.is_some() {
                RetentionState::PayloadPresent
            } else {
                RetentionState::PayloadAbsent
            },
            codec: payload.as_ref().map(|_| "safe-json-msgpack/1".to_string()),
            payload_bytes_sha256: payload,
            safe_value_sha256: payload.map(|_| Sha256Digest::of(b"safe")),
            native_ids_semantic_sha256: None,
            diagnostics_semantic_sha256: None,
        };
        encode_record_semantic_leaf(&Sha256Digest::of(b"input"), &record)
    }

    /// §15: changing the safe payload (and its hashes together) moves the A
    /// root; the root is a function of the actual leaf bytes, not of a count.
    #[test]
    fn semantic_root_moves_when_safe_payload_changes() {
        let with_payload = leaf(1, Some(Sha256Digest::of(b"payload-a")));
        let with_other_payload = leaf(1, Some(Sha256Digest::of(b"payload-b")));
        let without_payload = leaf(1, None);

        let root_a = stream_root(
            SOURCE_SEMANTIC_RECORDS_ROOT_DOMAIN,
            &[with_payload],
            &records_footer(1),
        );
        let root_b = stream_root(
            SOURCE_SEMANTIC_RECORDS_ROOT_DOMAIN,
            &[with_other_payload],
            &records_footer(1),
        );
        let root_c = stream_root(
            SOURCE_SEMANTIC_RECORDS_ROOT_DOMAIN,
            &[without_payload],
            &records_footer(1),
        );
        assert_ne!(root_a, root_b);
        assert_ne!(root_a, root_c);
        assert_ne!(root_b, root_c);
    }

    /// The stream root is order sensitive over its leaves (§4 length-prefixed
    /// framing), so two leaves swapped is a different root.
    #[test]
    fn stream_root_is_leaf_order_sensitive() {
        let first = leaf(1, None);
        let second = leaf(2, None);
        let forward = stream_root(
            SOURCE_SEMANTIC_RECORDS_ROOT_DOMAIN,
            &[first.clone(), second.clone()],
            &records_footer(2),
        );
        let reversed =
            stream_root(SOURCE_SEMANTIC_RECORDS_ROOT_DOMAIN, &[second, first], &records_footer(2));
        assert_ne!(forward, reversed);
    }

    /// §4: leave lengths are part of the framing, so a leaf whose bytes are a
    /// concatenation of two others still produces a different root.
    #[test]
    fn stream_root_length_prefixes_every_leaf() {
        let whole = vec![b'a', b'b'];
        let split_left = vec![b'a'];
        let split_right = vec![b'b'];
        let one = stream_root("d", &[whole], &records_footer(1));
        let two = stream_root("d", &[split_left, split_right], &records_footer(2));
        assert_ne!(one, two);
    }

    #[test]
    fn leaf_and_footer_carry_decimal_strings_not_json_numbers() {
        let encoded = leaf(7, None);
        let text = String::from_utf8(encoded).unwrap();
        assert!(text.starts_with("[\"cass.source-record-semantic/1\",\""), "{text}");
        // The ordinal appears as a quoted decimal string inside the locator.
        assert!(text.contains("\"7\""), "{text}");
        assert!(!text.contains(",7,"), "ordinal must not be a bare JSON number: {text}");

        let footer = String::from_utf8(records_footer(3)).unwrap();
        assert_eq!(footer, "[\"summary\",\"3\"]");
    }

    #[test]
    fn binding_footer_counts_follow_the_fixed_class_order() {
        let counts = BindingClassCounts {
            canonical_bound: 1,
            unresolved_no_binding: 2,
            standalone_no_binding: 3,
            unmapped_no_binding: 4,
            winner_rejected_no_binding: 5,
        };
        assert_eq!(counts.total(), 15);
        assert_eq!(
            String::from_utf8(bindings_footer(&counts)).unwrap(),
            "[\"summary\",\"15\",\"1\",\"2\",\"3\",\"4\",\"5\"]"
        );
        let root = encode_original_binding_root(&Sha256Digest::of(b"root"), &counts);
        assert_eq!(
            String::from_utf8(root).unwrap(),
            format!("[\"{}\",\"15\",[\"1\",\"2\",\"3\",\"4\",\"5\"]]", Sha256Digest::of(b"root").hex())
        );
    }

    #[test]
    fn claims_footer_orders_canonical_standalone_unmapped() {
        assert_eq!(
            String::from_utf8(claims_footer(2, 3, 4)).unwrap(),
            "[\"summary\",\"9\",\"2\",\"3\",\"4\"]"
        );
    }

    #[test]
    fn receipt_key_is_prefixed_and_deterministic() {
        let library = "0f0f0f0f-1111-4222-8333-444444444444";
        let input = Sha256Digest::of(b"input");
        let request = Sha256Digest::of(b"request");
        let key = activation_receipt_key(library, &input, &request);
        assert!(key.starts_with(SOURCE_RECEIPT_KEY_PREFIX), "{key}");
        assert_eq!(key, activation_receipt_key(library, &input, &request));
        assert_ne!(key, activation_receipt_key("other", &input, &request));
    }

    #[test]
    fn projection_key_distinguishes_records_with_distinct_targets() {
        let mut claim = SourceClaim {
            input_key: Sha256Digest::of(b"input"),
            record_ordinal: 1,
            record_pointer: "r".to_string(),
            conversation_ordinal: Some(0),
            final_message_idx: Some(3),
            positions: Vec::new(),
            projection_pointer: Some("/messages/3".to_string()),
            evidence_kind: EvidenceKind::Prose,
            mapping_state: ClaimMappingState::Canonical,
        };
        let canonical = claim.projection_key();
        claim.projection_pointer = Some("/messages/4".to_string());
        assert_ne!(canonical, claim.projection_key());
    }

    /// The `binding_digest` a staged claim carries is the pending-claim digest
    /// (§19), and it changes when the claim leaf changes.
    #[test]
    fn pending_claim_digest_tracks_the_claim_leaf() {
        let mut claim = SourceClaim {
            input_key: Sha256Digest::of(b"input"),
            record_ordinal: 1,
            record_pointer: "r".to_string(),
            conversation_ordinal: None,
            final_message_idx: None,
            positions: Vec::new(),
            projection_pointer: None,
            evidence_kind: EvidenceKind::NoMessage,
            mapping_state: ClaimMappingState::Standalone,
        };
        let before = claim.pending_claim_digest();
        claim.evidence_kind = EvidenceKind::Prose;
        assert_ne!(before, claim.pending_claim_digest());
    }

    /// The failure-publication digest binds the actual finish and roots, and
    /// is domain-separated from the successful installation digest.
    #[test]
    fn visible_facts_digest_is_domain_separated() {
        let finish = VerifiedFinish {
            content_digest: Sha256Digest::of(b"content"),
            bytes_read: 10,
            records_seen: 1,
            blank_lines: 0,
            parse_failed: 0,
            mapping_diagnostics: 0,
            unprocessed_ranges: vec![SourceUnprocessedRange {
                start: 4,
                end: 6,
                reason: "unterminated".to_string(),
                ordinal: Some(1),
                record_pointer: Some("record-1".to_string()),
            }],
            reached_eof: false,
        };
        let records_root = Root { sha256: Sha256Digest::of(b"records"), count: 1 };
        let claims_root = Root { sha256: Sha256Digest::of(b"claims"), count: 0 };
        let failure = visible_facts_digest(
            &Sha256Digest::of(b"input"),
            TerminalState::Partial,
            &records_root,
            &claims_root,
            &finish,
            ProjectionDisposition::Ready,
        );
        // Same inputs, different terminal state => different digest.
        let other = visible_facts_digest(
            &Sha256Digest::of(b"input"),
            TerminalState::Failed,
            &records_root,
            &claims_root,
            &finish,
            ProjectionDisposition::Ready,
        );
        assert_ne!(failure, other);
        // A later attempt appending unprocessed ranges changes the digest,
        // because the finish tuple is an input.
        let mut later = finish.clone();
        later.unprocessed_ranges.push(SourceUnprocessedRange {
            start: 8,
            end: 9,
            reason: "later".to_string(),
            ordinal: None,
            record_pointer: None,
        });
        let later_digest = visible_facts_digest(
            &Sha256Digest::of(b"input"),
            TerminalState::Partial,
            &records_root,
            &claims_root,
            &later,
            ProjectionDisposition::Ready,
        );
        assert_ne!(failure, later_digest);
    }

    // --- replay-reject reason encoding (§20.3) ------------------------------

    /// The frozen bytes of `{"tag":"WinnerRejected","field":null}`, written out
    /// from the MessagePack spec rather than from the encoder under test.
    const WINNER_REJECTED_GOLD: &[u8] = &[
        0x82, // fixmap, 2 entries
        0xa3, b't', b'a', b'g', // "tag"
        0xae, b'W', b'i', b'n', b'n', b'e', b'r', b'R', b'e', b'j', b'e', b'c', b't', b'e',
        b'd', // "WinnerRejected"
        0xa5, b'f', b'i', b'e', b'l', b'd', // "field"
        0xc0, // null
    ];

    /// The frozen bytes of `{"tag":"StoredFactMismatch","field":"role"}`.
    const STORED_FACT_MISMATCH_GOLD: &[u8] = &[
        0x82, 0xa3, b't', b'a', b'g', 0xb2, b'S', b't', b'o', b'r', b'e', b'd', b'F', b'a', b'c',
        b't', b'M', b'i', b's', b'm', b'a', b't', b'c', b'h', 0xa5, b'f', b'i', b'e', b'l', b'd',
        0xa4, b'r', b'o', b'l', b'e',
    ];

    #[test]
    fn replay_reject_reason_has_a_fixed_nested_byte_gold() {
        assert_eq!(
            encode_replay_reject_reason(ReplayRejectReason::WinnerRejected).expect("encode"),
            WINNER_REJECTED_GOLD
        );
        assert_eq!(
            encode_replay_reject_reason(ReplayRejectReason::StoredFactMismatch(
                ReplayRejectField::Role
            ))
            .expect("encode"),
            STORED_FACT_MISMATCH_GOLD
        );
        assert_eq!(
            decode_replay_reject_reason(WINNER_REJECTED_GOLD).expect("decode"),
            ReplayRejectReason::WinnerRejected
        );
        assert_eq!(
            decode_replay_reject_reason(STORED_FACT_MISMATCH_GOLD).expect("decode"),
            ReplayRejectReason::StoredFactMismatch(ReplayRejectField::Role)
        );
        // The five field-free tags all write `field: null`, and the two
        // field-carrying tags never write a bare tag.
        for reason in [
            ReplayRejectReason::NoMatchingStoredRow,
            ReplayRejectReason::AmbiguousStoredRows,
            ReplayRejectReason::WinnerRejected,
        ] {
            assert!(reason.field().is_none());
            assert_eq!(reason.as_str(), reason.tag());
            let bytes = encode_replay_reject_reason(reason).expect("encode");
            assert_eq!(bytes.last(), Some(&0xc0), "field must be null");
        }
        assert_eq!(
            ReplayRejectReason::InvalidStoredEvidence(ReplayRejectField::SafeContentSha256).as_str(),
            "InvalidStoredEvidence{safe_content_sha256}"
        );
        assert_eq!(
            ReplayRejectReason::StoredFactMismatch(ReplayRejectField::ExtraBinSha256).as_str(),
            "StoredFactMismatch{extra_bin_sha256}"
        );
        assert_eq!(ReplayRejectField::ALL.len(), 16);
        assert_eq!(
            ReplayRejectField::from_name("conversation_identity_digest"),
            Some(ReplayRejectField::ConversationIdentityDigest)
        );
        assert_eq!(ReplayRejectField::from_name("not_a_field"), None);
    }

    #[test]
    fn replay_reject_reason_refuses_every_shape_outside_the_frozen_map() {
        // A missing `field` key.
        let mut missing = vec![0x81, 0xa3, b't', b'a', b'g', 0xae];
        missing.extend_from_slice(b"WinnerRejected");
        assert!(decode_replay_reject_reason(&missing).is_err());

        // An unknown key beside the two required ones.
        let mut unknown = vec![0x83, 0xa3, b't', b'a', b'g', 0xae];
        unknown.extend_from_slice(b"WinnerRejected");
        unknown.extend_from_slice(&[0xa5, b'f', b'i', b'e', b'l', b'd', 0xc0]);
        unknown.extend_from_slice(&[0xa5, b'e', b'x', b't', b'r', b'a', 0xc0]);
        assert!(decode_replay_reject_reason(&unknown).is_err());

        // A duplicated key.
        let mut duplicate = vec![0x82, 0xa3, b't', b'a', b'g', 0xae];
        duplicate.extend_from_slice(b"WinnerRejected");
        duplicate.extend_from_slice(&[0xa3, b't', b'a', b'g', 0xae]);
        duplicate.extend_from_slice(b"WinnerRejected");
        assert!(decode_replay_reject_reason(&duplicate).is_err());

        // A wrong value type for `tag`.
        let wrong_type = {
            let mut bytes = vec![0x82, 0xa3, b't', b'a', b'g', 0x01, 0xa5, b'f', b'i', b'e', b'l'];
            bytes.extend_from_slice(&[b'd', 0xc0]);
            bytes
        };
        assert!(decode_replay_reject_reason(&wrong_type).is_err());

        // A tag this version does not know.
        let mut future = vec![0x82, 0xa3, b't', b'a', b'g', 0xa5];
        future.extend_from_slice(b"Futur");
        future.extend_from_slice(&[0xa5, b'f', b'i', b'e', b'l', b'd', 0xc0]);
        assert!(decode_replay_reject_reason(&future).is_err());

        // A field name outside the closed domain.
        let mut bad_field = vec![0x82, 0xa3, b't', b'a', b'g', 0xb2];
        bad_field.extend_from_slice(b"StoredFactMismatch");
        bad_field.extend_from_slice(&[0xa5, b'f', b'i', b'e', b'l', b'd', 0xa4]);
        bad_field.extend_from_slice(b"nope");
        assert!(decode_replay_reject_reason(&bad_field).is_err());

        // A field on a tag that must not carry one, and its mirror.
        let mut unexpected_field = vec![0x82, 0xa3, b't', b'a', b'g', 0xae];
        unexpected_field.extend_from_slice(b"WinnerRejected");
        unexpected_field.extend_from_slice(&[0xa5, b'f', b'i', b'e', b'l', b'd', 0xa4]);
        unexpected_field.extend_from_slice(b"role");
        assert!(decode_replay_reject_reason(&unexpected_field).is_err());

        let mut missing_field = vec![0x82, 0xa3, b't', b'a', b'g', 0xb2];
        missing_field.extend_from_slice(b"StoredFactMismatch");
        missing_field.extend_from_slice(&[0xa5, b'f', b'i', b'e', b'l', b'd', 0xc0]);
        assert!(decode_replay_reject_reason(&missing_field).is_err());

        // Trailing bytes after a complete map.
        let mut trailing = WINNER_REJECTED_GOLD.to_vec();
        trailing.push(0x00);
        assert!(decode_replay_reject_reason(&trailing).is_err());

        // A JSON array is not a map.
        assert!(decode_replay_reject_reason(b"[]").is_err());
    }

    // --- expected-manifest header (§20.1) -----------------------------------

    #[test]
    fn expected_manifest_header_round_trips_and_binds_both_halves() {
        let manifest = sample_manifest();
        let safety = sample_safety();
        let bytes = encode_expected_manifest_header(&manifest, &safety);
        let (decoded, decoded_safety) =
            decode_expected_manifest_header(&bytes).expect("the encoder output must decode");
        assert_eq!(decoded, manifest);
        assert_eq!(decoded_safety, safety);
        assert_eq!(decoded.verifier_version(), "expected/1");
        assert_eq!(decoded.records(), 2);
        assert_eq!(decoded.blank_lines(), 1);
        assert!(decoded.complete());

        // The digest is over exactly those bytes.
        assert_eq!(expected_manifest_digest(&manifest, &safety), Sha256Digest::of(&bytes));
        // And it is not a constant of the manifest's shape: moving one field
        // moves it.
        let mut other = sample_manifest();
        other.records = 3;
        assert_ne!(
            expected_manifest_digest(&manifest, &safety),
            expected_manifest_digest(&other, &safety)
        );
    }

    #[test]
    fn expected_manifest_header_refuses_every_non_canonical_spelling() {
        let good = encode_expected_manifest_header(&sample_manifest(), &sample_safety());
        let text = String::from_utf8(good.clone()).expect("the header is UTF-8");

        // Element count.
        assert!(decode_expected_manifest_header(b"[]").is_err());
        let short = text.replacen("[", "", 1);
        assert!(decode_expected_manifest_header(short.as_bytes()).is_err());

        // Domain.
        let wrong_domain = text.replacen("cass.source-expected-manifest/1", "cass.other/1", 1);
        assert!(decode_expected_manifest_header(wrong_domain.as_bytes()).is_err());

        // A non-canonical decimal spelling: "128" written as "0128".
        assert!(text.contains("\"128\""));
        let leading_zero = text.replacen("\"128\"", "\"0128\"", 1);
        assert!(decode_expected_manifest_header(leading_zero.as_bytes()).is_err());

        // A signed decimal string.
        let signed = text.replacen("\"128\"", "\"+128\"", 1);
        assert!(decode_expected_manifest_header(signed.as_bytes()).is_err());

        // Uppercase hex is not the canonical spelling.
        let upper = text.to_ascii_uppercase().replacen(
            "CASS.SOURCE-EXPECTED-MANIFEST/1",
            "cass.source-expected-manifest/1",
            1,
        );
        assert!(decode_expected_manifest_header(upper.as_bytes()).is_err());

        // A 31-byte digest.
        let short_digest = text.replacen(
            &Sha256Digest::of(b"sealed").hex(),
            &Sha256Digest::of(b"sealed").hex()[..62],
            1,
        );
        assert!(decode_expected_manifest_header(short_digest.as_bytes()).is_err());

        // Insignificant whitespace and trailing bytes are both refusals.
        let padded = format!(" {text} ");
        assert!(decode_expected_manifest_header(padded.as_bytes()).is_err());
        let mut trailing = good.clone();
        trailing.push(b'\n');
        assert!(decode_expected_manifest_header(&trailing).is_err());

        // A boolean where a decimal string belongs.
        let bool_for_count = text.replacen("\"2\"", "true", 1);
        assert!(decode_expected_manifest_header(bool_for_count.as_bytes()).is_err());

        // The honest header still decodes.
        decode_expected_manifest_header(&good).expect("the frozen header must decode");
    }

    // --- independent framing scan (§17.2) -----------------------------------

    /// Rebuild the framing stream digest from the contract's own description:
    /// the domain bytes, then each leaf's 8-byte big-endian length and bytes.
    fn framing_digest_from_leaves(leaves: &[Vec<u8>]) -> Sha256Digest {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SOURCE_FRAMING_DOMAIN.as_bytes());
        for leaf in leaves {
            bytes.extend_from_slice(&(leaf.len() as u64).to_be_bytes());
            bytes.extend_from_slice(leaf);
        }
        Sha256Digest::of(&bytes)
    }

    /// One `cass.source-framing/1` leaf, built from the spec's JSON shape.
    fn framing_leaf_text(ordinal: u64, start: u64, end: u64, sha: &Sha256Digest) -> Vec<u8> {
        format!("[\"{ordinal}\",\"\",\"{start}\",\"{end}\",\"{}\"]", sha.hex()).into_bytes()
    }

    #[test]
    fn framing_scan_counts_records_blanks_and_streams_the_frozen_digest() {
        let mut scan = FramingScan::new(SAMPLE_SEALED, SourceFormat::Jsonl);
        let page = scan.next_page(64).expect("scan");
        let summary = scan.finish();

        assert_eq!(summary.byte_len, SAMPLE_SEALED.len() as u64);
        assert_eq!(summary.sealed_sha256, Sha256Digest::of(SAMPLE_SEALED));
        assert_eq!(summary.records, 2);
        assert_eq!(summary.blank_lines, 1);
        assert_eq!(summary.blank_bytes, 0);
        assert!(summary.complete);

        assert_eq!(page.len(), 2);
        assert_eq!(page[0].locator().ordinal, 1);
        assert_eq!(page[0].locator().record_pointer, "");
        assert_eq!((page[0].locator().byte_start, page[0].locator().byte_end), (0, 7));
        assert_eq!(page[0].raw_sha256, Sha256Digest::of(b"{\"n\":1}"));
        // The blank line still consumes an ordinal: the physical line number
        // is 2, so the second record is ordinal 3.
        assert_eq!(page[1].locator().ordinal, 3);
        assert_eq!((page[1].locator().byte_start, page[1].locator().byte_end), (9, 16));
        assert_eq!(page[1].raw_sha256, Sha256Digest::of(b"{\"n\":2}"));

        let leaves = vec![
            framing_leaf_text(1, 0, 7, &page[0].raw_sha256),
            framing_leaf_text(3, 9, 16, &page[1].raw_sha256),
        ];
        assert_eq!(summary.framing_sha256, framing_digest_from_leaves(&leaves));
    }

    #[test]
    fn framing_scan_handles_crlf_missing_terminators_and_blank_only_inputs() {
        // A CRLF terminator contributes both bytes as separator, so the record
        // range and its digest stop before the CR.
        let crlf = b"{\"n\":1}\r\n";
        let mut scan = FramingScan::new(crlf, SourceFormat::Jsonl);
        let page = scan.next_page(8).expect("scan");
        let summary = scan.finish();
        assert_eq!(page.len(), 1);
        assert_eq!((page[0].locator().byte_start, page[0].locator().byte_end), (0, 7));
        assert_eq!(page[0].raw_sha256, Sha256Digest::of(b"{\"n\":1}"));
        assert_eq!(summary.blank_lines, 0);
        assert!(summary.complete);

        // A final line without a newline is still a record.
        let unterminated = b"{\"n\":1}";
        let mut scan = FramingScan::new(unterminated, SourceFormat::Jsonl);
        let page = scan.next_page(8).expect("scan");
        assert_eq!(page.len(), 1);
        assert_eq!((page[0].locator().byte_start, page[0].locator().byte_end), (0, 7));
        assert!(scan.finish().complete);

        // Blank lines carry their own bytes, and produce no record.
        let blanks = b"  \n\t\n";
        let mut scan = FramingScan::new(blanks, SourceFormat::Jsonl);
        assert!(scan.next_page(8).expect("scan").is_empty());
        let summary = scan.finish();
        assert_eq!(summary.records, 0);
        assert_eq!(summary.blank_lines, 2);
        assert_eq!(summary.blank_bytes, 3);
        assert_eq!(summary.framing_sha256, framing_digest_from_leaves(&[]));

        // An empty input is a complete scan of no records.
        let mut scan = FramingScan::new(b"", SourceFormat::Jsonl);
        assert!(scan.next_page(8).expect("scan").is_empty());
        let summary = scan.finish();
        assert_eq!(summary.records, 0);
        assert!(summary.complete);
        assert_eq!(summary.sealed_sha256, Sha256Digest::of(b""));
    }

    #[test]
    fn framing_scan_treats_a_document_as_one_whole_input_frame() {
        let document = b"{\n  \"n\": 1\n}";
        let mut scan = FramingScan::new(document, SourceFormat::JsonDocument);
        let page = scan.next_page(8).expect("scan");
        let summary = scan.finish();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].locator().ordinal, 1);
        assert_eq!(page[0].locator().record_pointer, "");
        assert_eq!((page[0].locator().byte_start, page[0].locator().byte_end), (0, document.len() as u64));
        assert_eq!(page[0].raw_sha256, Sha256Digest::of(document));
        assert_eq!(summary.blank_lines, 0);
        assert!(summary.complete);
    }

    #[test]
    fn framing_scan_pages_without_losing_leaves_or_the_digest() {
        let mut scan = FramingScan::new(SAMPLE_SEALED, SourceFormat::Jsonl);
        let mut collected = Vec::new();
        while !scan.is_done() {
            collected.extend(scan.next_page(1).expect("scan"));
        }
        let summary = scan.finish();
        assert_eq!(collected.len(), 2);
        assert_eq!(summary.records, 2);
        assert_eq!(summary.blank_lines, 1);

        // Paging must not change the stream digest.
        let mut whole = FramingScan::new(SAMPLE_SEALED, SourceFormat::Jsonl);
        whole.run_to_end().expect("scan");
        assert_eq!(summary.framing_sha256, whole.finish().framing_sha256);
    }

    // --- verified construction (§10) ----------------------------------------

    #[test]
    fn verified_input_derives_the_manifest_from_the_sealed_bytes() {
        let (input, summary) =
            VerifiedSourceInput::verify(sample_declaration(SAMPLE_SEALED), SAMPLE_SEALED, &sample_safety_config())
                .expect("a consistent declaration must verify");
        assert_eq!(summary.records, 2);
        assert_eq!(input.expected_records(), 2);
        assert_eq!(input.expected_blank_lines(), 1);
        assert_eq!(input.manifest().sealed_sha256(), &Sha256Digest::of(SAMPLE_SEALED));
        assert_eq!(input.manifest().byte_len(), SAMPLE_SEALED.len() as u64);
        assert_eq!(input.manifest().verifier_version(), SOURCE_VERIFIER_VERSION);
        assert!(input.manifest().complete());
        // The input key is the digest of the identity tuple, not a caller value.
        assert_eq!(input.input_key(), &Sha256Digest::of(&identity_tuple_bin(input.identity_tuple())));
    }

    #[test]
    fn verified_input_refuses_a_forged_digest_pair() {
        // The declaration and its identity tuple agree with each other, but not
        // with the bytes on disk: both are refused, because the digest is
        // recomputed from the sealed bytes and compared against the tuple.
        let mut declaration = sample_declaration(SAMPLE_SEALED);
        let forged = Sha256Digest::of(b"a different input").hex();
        declaration.identity_tuple[12] = Some(forged.clone());
        let err = VerifiedSourceInput::verify(declaration, SAMPLE_SEALED, &sample_safety_config())
            .expect_err("a declared digest the bytes do not hash to must be refused");
        assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");

        // Changing the bytes under a fixed declaration is the same refusal.
        let err = VerifiedSourceInput::verify(
            sample_declaration(SAMPLE_SEALED),
            b"{\"n\":9}\n",
            &sample_safety_config(),
        )
        .expect_err("different bytes must not verify against the old identity");
        assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");
    }

    #[test]
    fn verified_input_refuses_a_declaration_that_disagrees_with_its_identity() {
        let mut declaration = sample_declaration(SAMPLE_SEALED);
        declaration.connector = "codex".to_string();
        let err = VerifiedSourceInput::verify(declaration, SAMPLE_SEALED, &sample_safety_config())
            .expect_err("the tuple still names claude");
        assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");
    }

    /// A declaration whose parser context is the given JSON.
    fn declaration_with_context(json: &str) -> SourceInputDeclaration {
        let context = LosslessSourceValue::parse(json.as_bytes()).expect("json");
        let context_digest = context_digest(&context).expect("context digest");
        let sealed_sha256 = Sha256Digest::of(SAMPLE_SEALED);
        let mut declaration = sample_declaration(SAMPLE_SEALED);
        declaration.identity_tuple[11] = Some(context_digest.hex());
        declaration.identity_tuple[12] = Some(sealed_sha256.hex());
        declaration.parser_context = context;
        declaration
    }

    #[test]
    fn context_digest_sorts_members_but_preserves_array_order() {
        // Key sorting is a normalisation of the digest, not a precondition:
        // the same object written in either member order must hash the same,
        // including when the differing object is nested.
        let ascending = declaration_with_context("{\"a\":1,\"b\":{\"c\":2,\"d\":3}}");
        let reversed = declaration_with_context("{\"b\":{\"d\":3,\"c\":2},\"a\":1}");
        assert_eq!(
            context_digest(&ascending.parser_context).expect("digest"),
            context_digest(&reversed.parser_context).expect("digest"),
            "member order must not change the context digest"
        );
        for declaration in [ascending.clone(), reversed.clone()] {
            VerifiedSourceInput::verify(declaration, SAMPLE_SEALED, &sample_safety_config())
                .expect("both member orders describe the same context");
        }

        // Array order *is* significant.
        let array_ab = declaration_with_context("{\"a\":[1,2]}");
        let array_ba = declaration_with_context("{\"a\":[2,1]}");
        assert_ne!(
            context_digest(&array_ab.parser_context).expect("digest"),
            context_digest(&array_ba.parser_context).expect("digest"),
            "array order must change the context digest"
        );

        // The digest is taken over the sorted view only: the context's own
        // persisted bytes keep the member order the caller supplied.
        assert_eq!(
            lossless_bin(&reversed.parser_context).expect("canonical"),
            b"{\"b\":{\"d\":3,\"c\":2},\"a\":1}".to_vec(),
            "the persisted context must not be reordered"
        );
    }

    #[test]
    fn context_digest_refuses_a_repeated_member_name() {
        let context = LosslessSourceValue::Object(vec![
            ("a".to_string(), LosslessSourceValue::Bool(true)),
            ("a".to_string(), LosslessSourceValue::Bool(false)),
        ]);
        assert!(context_digest(&context).is_err());
    }

    #[test]
    fn verified_input_refuses_a_context_the_identity_does_not_name() {
        // The identity tuple carries the context digest, so a context swapped
        // for a different one is refused even when everything else agrees.
        let mut declaration = sample_declaration(SAMPLE_SEALED);
        declaration.parser_context =
            LosslessSourceValue::parse(b"{\"connector\":\"codex\",\"schema\":\"x\"}")
                .expect("json");
        let err = VerifiedSourceInput::verify(declaration, SAMPLE_SEALED, &sample_safety_config())
            .expect_err("the tuple still names the other context digest");
        assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");
    }

    #[test]
    fn safety_identity_matches_the_frozen_gold_and_is_recomputed_from_bytes() {
        // Both halves of the frozen safety identity, against v0.4 §8's own
        // golds: the configuration copy's byte digest and the key-sorted
        // encoding of the effective four arrays.
        assert_eq!(Sha256Digest::of(FIXED_CONFIG_BYTES).hex(), FIXED_CONFIG_GOLD);
        assert_eq!(effective_four_arrays_digest(&builtin_four_arrays()).hex(), FOUR_ARRAYS_GOLD);

        let verified = sample_safety_config().verify().expect("the honest configuration verifies");
        assert_eq!(verified.fixed_config_sha256().hex(), FIXED_CONFIG_GOLD);
        assert_eq!(verified.effective_four_arrays_sha256().hex(), FOUR_ARRAYS_GOLD);
        assert!(verified.desensitization_enabled());

        // The digests are *derived*, not echoed: there is no digest field to
        // set, and a configuration whose bytes differ produces a different
        // fixed-config digest even when the arrays it describes are identical.
        let mut relabelled = sample_safety_config();
        let mut bytes = FIXED_CONFIG_BYTES.to_vec();
        bytes.extend_from_slice(b"\n# a different copy of the same rules\n");
        relabelled.fixed_config_bytes = bytes;
        let other = relabelled.verify().expect("the extra comment still parses to the same arrays");
        assert_ne!(other.fixed_config_sha256().hex(), FIXED_CONFIG_GOLD);
        assert_eq!(other.effective_four_arrays_sha256().hex(), FOUR_ARRAYS_GOLD);
    }

    #[test]
    fn safety_configuration_refuses_incomplete_or_inconsistent_copies() {
        let mut disabled = sample_safety_config();
        disabled.desensitization_enabled = false;
        assert!(disabled.verify().is_err());

        let mut unnamed = sample_safety_config();
        unnamed.config_source_identity = String::new();
        assert!(unnamed.verify().is_err());

        let mut unversioned = sample_safety_config();
        unversioned.code_version = "   ".to_string();
        assert!(unversioned.verify().is_err());

        // A copy that is not TOML at all, and one that parses but does not
        // describe the arrays the capture claims were effective: the "arrays
        // changed under an unchanged configuration tag" case.
        let mut garbage = sample_safety_config();
        garbage.fixed_config_bytes = b"not toml at all".to_vec();
        assert!(garbage.verify().is_err());

        let mut drifted_arrays = sample_safety_config();
        drifted_arrays.effective_four_arrays.memory_files.push("EXTRA.md".to_string());
        let err = drifted_arrays
            .verify()
            .expect_err("arrays that the fixed copy does not describe must be refused");
        assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");

        // The mirror case: the configuration bytes changed to a different rule
        // set while the capture still claims the original arrays.
        let mut swapped_copy = sample_safety_config();
        swapped_copy.fixed_config_bytes =
            b"memory_files = [\"ONLY.md\"]\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n"
                .to_vec();
        let err = swapped_copy
            .verify()
            .expect_err("a different configuration copy under the old arrays must be refused");
        assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");

        sample_safety_config().verify().expect("the honest configuration verifies");
    }

    // --- staging primitive -------------------------------------------------

    fn sample_manifest() -> VerifiedExpectedManifest {
        VerifiedExpectedManifest {
            verifier_version: "expected/1".to_string(),
            sealed_sha256: Sha256Digest::of(b"sealed"),
            byte_len: 128,
            format: SourceFormat::Jsonl,
            records: 2,
            blank_lines: 1,
            framing_sha256: Sha256Digest::of(b"framing"),
            complete: true,
            blank_bytes: 0,
        }
    }

    /// The repository's own fixed configuration copy, byte for byte.
    const FIXED_CONFIG_BYTES: &[u8] = include_bytes!("../../config/excluded_context_paths.toml");

    /// v0.4 §8's frozen digest of that file's bytes.
    const FIXED_CONFIG_GOLD: &str =
        "fc0f68d79103cf3e6568014ddde9b325cefd82f72facc126b2e62d7293263778";
    /// v0.4 §8's frozen digest of the effective four arrays.
    const FOUR_ARRAYS_GOLD: &str =
        "c4c9194c6318d5a7a3384df97305db8f4175f99da376b58867a7812050913eab";

    fn builtin_four_arrays() -> crate::sources::config::ExcludedContextPaths {
        toml::from_str(std::str::from_utf8(FIXED_CONFIG_BYTES).expect("utf-8"))
            .expect("the built-in configuration parses")
    }

    fn sample_safety_config() -> SourceSafetyConfig {
        SourceSafetyConfig {
            code_version: "safety/1".to_string(),
            desensitization_enabled: true,
            config_source_identity: "config/1".to_string(),
            fixed_config_bytes: FIXED_CONFIG_BYTES.to_vec(),
            effective_four_arrays: builtin_four_arrays(),
        }
    }

    fn sample_safety() -> VerifiedSafetyIdentity {
        sample_safety_config().verify().expect("a complete safety configuration")
    }

    /// Two records with one blank line between them.
    const SAMPLE_SEALED: &[u8] = b"{\"n\":1}\n\n{\"n\":2}\n";

    fn sample_context() -> LosslessSourceValue {
        LosslessSourceValue::parse(b"{\"connector\":\"claude\",\"schema\":\"cass.source-parser-context/1\"}")
            .expect("json")
    }

    /// A declaration whose identity tuple agrees with its fields *and* with
    /// `sealed`.
    fn sample_declaration(sealed: &[u8]) -> SourceInputDeclaration {
        let context = sample_context();
        let context_digest = Sha256Digest::of(&lossless_bin(&context).expect("canonical context"));
        let sealed_sha256 = Sha256Digest::of(sealed);
        SourceInputDeclaration {
            identity_tuple: vec![
                Some("cass.source-input/2".to_string()),
                Some("ns".to_string()),
                Some("local".to_string()),
                Some("claude".to_string()),
                Some("root".to_string()),
                Some("relative.jsonl".to_string()),
                Some("user".to_string()),
                None,
                None,
                None,
                None,
                Some(context_digest.hex()),
                Some(sealed_sha256.hex()),
                Some("normalizer/1".to_string()),
                Some("safety-contract/1".to_string()),
            ],
            identity_namespace: "ns".to_string(),
            source_id: "local".to_string(),
            connector: "claude".to_string(),
            origin_kind: None,
            origin_host: None,
            origin_source_version: None,
            role: Some("user".to_string()),
            platform: None,
            root_id: "root".to_string(),
            relative_locator: "relative.jsonl".to_string(),
            discovery: LosslessSourceValue::parse(b"{\"a\":1}").expect("json"),
            parser_context: context,
            sealed_ref: LosslessSourceValue::parse(b"{\"c\":3}").expect("json"),
            format: SourceFormat::Jsonl,
            normalizer_id: "normalizer/1".to_string(),
            safety_contract_id: "safety-contract/1".to_string(),
        }
    }

    /// A verified input built only through the scanning constructor.
    fn sample_input() -> VerifiedSourceInput {
        VerifiedSourceInput::verify(
            sample_declaration(SAMPLE_SEALED),
            SAMPLE_SEALED,
            &sample_safety_config(),
        )
        .expect("a well-formed verified input")
        .0
    }

    fn sample_record(ordinal: u64, payload: Option<&str>) -> VerifiedStagedRecord {
        let safe_value = payload.map(|json| LosslessSourceValue::parse(json.as_bytes()).expect("json"));
        VerifiedStagedRecord {
            locator: SourceRecordLocator {
                ordinal,
                record_pointer: format!("record-{ordinal}"),
                byte_start: 0,
                byte_end: 10,
            },
            expected_raw_sha256: Sha256Digest::of(b"expected"),
            observed_raw_sha256: Some(Sha256Digest::of(b"expected")),
            parse_state: ParseState::Parsed,
            record_mapping_state: RecordMappingState::AllCanonical,
            safety_state: SafetyState::Preserved,
            retention_state: if safe_value.is_some() {
                RetentionState::PayloadPresent
            } else {
                RetentionState::PayloadAbsent
            },
            native_ids: None,
            safe_value,
            diagnostics: None,
        }
    }

    #[test]
    fn staging_registers_the_parent_once_and_verifies_identical_pages() {
        use crate::storage::api::TxMode;

        let conn = Conn::open_memory().expect("in-memory sqlite");
        crate::storage::schema::ensure(&conn).expect("schema 9 must build");

        let input = sample_input();
        let records = vec![sample_record(1, None), sample_record(2, Some("{\"k\":null}"))];

        let tx = conn.transaction_with_mode(TxMode::Immediate).unwrap();
        let first = stage_source_records_in_tx(&tx, &input, &records).expect("first stage");
        tx.commit().unwrap();
        assert_eq!(first.registered, 1);
        assert_eq!(first.verified_same, 0);
        assert_eq!(first.updated, 0);

        let tx = conn.transaction_with_mode(TxMode::Immediate).unwrap();
        let second = stage_source_records_in_tx(&tx, &input, &records).expect("re-stage");
        tx.commit().unwrap();
        assert_eq!(second.input_id, first.input_id, "the parent is not re-created");
        assert_eq!(second.registered, 0);
        assert_eq!(second.verified_same, 2, "identical records are not rewritten");
        assert_eq!(second.updated, 1, "the parent's expected counts are refreshed");

        // Records stay `frame_pending`; the input stays `staged`. Activation is
        // a separate primitive.
        let states: Vec<String> = conn
            .query_all_map(
                "SELECT frame_state FROM source_records ORDER BY ordinal",
                &[],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(states, vec!["frame_pending".to_string(), "frame_pending".to_string()]);
        let input_state: String = conn
            .query_row_map("SELECT state FROM source_inputs", &[], |row| row.get_typed(0))
            .unwrap();
        assert_eq!(input_state, "staged");

        // The payload envelope round-trips through the strict codec and the
        // safe-value hash matches the stored column.
        let stored: Option<Vec<u8>> = conn
            .query_opt_map(
                "SELECT payload_bin FROM source_records WHERE ordinal = ?1",
                &[Value::Blob(u64_be8(2).to_vec())],
                |row| row.get_typed(0),
            )
            .unwrap();
        let payload = stored.expect("the payload-present record stores its envelope");
        let decoded = super::super::source_codec::decode_safe_source(&payload)
            .expect("the stored envelope decodes");
        assert_eq!(decoded.safe_json(), "{\"k\":null}");
    }

    #[test]
    fn staging_updates_a_record_whose_facts_changed() {
        use crate::storage::api::TxMode;

        let conn = Conn::open_memory().expect("in-memory sqlite");
        crate::storage::schema::ensure(&conn).expect("schema 9 must build");
        let input = sample_input();

        let tx = conn.transaction_with_mode(TxMode::Immediate).unwrap();
        stage_source_records_in_tx(&tx, &input, &[sample_record(1, None)]).expect("stage");
        tx.commit().unwrap();

        let tx = conn.transaction_with_mode(TxMode::Immediate).unwrap();
        let changed = stage_source_records_in_tx(&tx, &input, &[sample_record(1, Some("{\"n\":1}"))])
            .expect("re-stage with a payload");
        tx.commit().unwrap();
        assert_eq!(changed.verified_same, 0);
        // One update for the parent's refreshed expected counts and one for the
        // changed record row.
        assert_eq!(changed.updated, 2, "the changed record and parent are rewritten");

        let retention: String = conn
            .query_row_map("SELECT retention_state FROM source_records", &[], |row| row.get_typed(0))
            .unwrap();
        assert_eq!(retention, "payload_present");
    }

    #[test]
    fn verified_input_refuses_a_wrong_length_identity_tuple() {
        let mut declaration = sample_declaration(SAMPLE_SEALED);
        declaration.identity_tuple = vec![Some("too-short".to_string())];
        let err = VerifiedSourceInput::verify(declaration, SAMPLE_SEALED, &sample_safety_config())
            .expect_err("a 1-entry identity tuple is not the frozen 15");
        assert!(matches!(err, SourceInstallError::Staging { .. }), "{err}");
    }

    // --- envelopes ---------------------------------------------------------

    fn sample_claim() -> SourceClaim {
        SourceClaim {
            input_key: Sha256Digest::of(b"input"),
            record_ordinal: 1,
            record_pointer: "record-1".to_string(),
            conversation_ordinal: Some(0),
            final_message_idx: Some(3),
            positions: vec![SafePosition {
                index_path: vec![IndexStep::ObjectMember(2), IndexStep::ArrayElement(1)],
                original_pointer_sha256: Sha256Digest::of(b"pointer"),
                safe_pointer: Some("/messages/0".to_string()),
            }],
            projection_pointer: Some("/messages/3".to_string()),
            evidence_kind: EvidenceKind::Prose,
            mapping_state: ClaimMappingState::Canonical,
        }
    }

    #[test]
    fn link_evidence_round_trips_and_rejects_a_drifted_field_set() {
        let claim = sample_claim();
        let bytes = encode_link_evidence(&claim, None).expect("encode");
        let decoded = decode_link_evidence(&bytes).expect("decode");
        assert_eq!(decoded.version, SOURCE_ENVELOPE_VERSION);
        assert_eq!(decoded.domain, SOURCE_LINK_EVIDENCE_DOMAIN);
        assert_eq!(decoded.claim, claim);
        assert!(decoded.installation.is_none());

        // A non-map top level is refused before any field decoding.
        assert!(matches!(
            decode_link_evidence(&[0x91, 0x01]),
            Err(SourceInstallError::Codec(SourceCodecError::InvalidEnvelope))
        ));
        // Trailing bytes after a complete envelope are refused.
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert!(matches!(
            decode_link_evidence(&trailing),
            Err(SourceInstallError::Codec(SourceCodecError::TrailingBytes))
        ));
        // The envelope is a named map, not a positional array: the first byte
        // is a fixmap header rather than an array header.
        assert!(matches!(bytes.first(), Some(0x80..=0x8f)), "envelope must be a map");
        // An installation that is absent in the bytes is absent after decoding;
        // it is never filled in from a default.
        let with_binding =
            encode_link_evidence(&claim, Some(&sample_installation())).expect("encode");
        assert_ne!(with_binding, bytes);
        assert!(decode_link_evidence(&with_binding)
            .expect("decode")
            .installation
            .is_some());
    }

    fn sample_installation() -> OriginalInstallation {
        OriginalInstallation {
            semantic_request_digest: Sha256Digest::of(b"request"),
            class: InstallationClass::CanonicalBound,
            binding: Some(OriginalBinding {
                outcome: OriginalBindingOutcome::AcceptedNew,
                original_conversation_id: 1,
                original_message_id: 7,
                stored_idx: 3,
                stored_merge_fingerprint: MergeFingerprint {
                    idx: 3,
                    created_at: Some(10),
                    role: "user".to_string(),
                    author: None,
                    content_blake3_hex: "ab".repeat(32),
                },
                safe_content_sha256: Sha256Digest::of(b"content"),
                extra_storage_kind: ExtraStorageKind::Null,
                extra_json_sha256: None,
                extra_bin_sha256: None,
                extra_semantic_digest: None,
                excluded_semantic_digest: None,
                conversation_identity_digest: Sha256Digest::of(b"identity"),
            }),
            rejection: None,
            reason: None,
        }
    }

    /// A claim on the given staged record, with the given target triple.
    fn claim_on(ordinal: u64, mapping: ClaimMappingState, targets: Option<(u32, i64)>) -> SourceClaim {
        SourceClaim {
            // The input this claim is installed under, not a placeholder: a
            // claim is refused when it names another input (§11).
            input_key: *sample_input().input_key(),
            record_ordinal: ordinal,
            record_pointer: format!("record-{ordinal}"),
            conversation_ordinal: targets.map(|(conversation, _)| conversation),
            final_message_idx: targets.map(|(_, index)| index),
            positions: Vec::new(),
            projection_pointer: targets.map(|(_, index)| format!("/messages/{index}")),
            evidence_kind: if targets.is_some() {
                EvidenceKind::Prose
            } else {
                EvidenceKind::NoMessage
            },
            mapping_state: mapping,
        }
    }

    fn standalone_installation() -> OriginalInstallation {
        OriginalInstallation {
            semantic_request_digest: Sha256Digest::of(b"request"),
            class: InstallationClass::StandaloneNoBinding,
            binding: None,
            rejection: None,
            reason: None,
        }
    }

    /// A winner-rejection installation whose rejection evidence carries the
    /// given parent identity digest.
    fn rejection_installation(identity: Sha256Digest) -> OriginalInstallation {
        OriginalInstallation {
            semantic_request_digest: Sha256Digest::of(b"request"),
            class: InstallationClass::WinnerRejectedNoBinding,
            binding: None,
            rejection: Some(WinnerRejectionEvidence {
                claim_digest: Sha256Digest::of(b"claim"),
                conversation_identity_digest: identity,
                incoming_idx: 0,
                incoming_merge_fingerprint: MergeFingerprint {
                    idx: 0,
                    created_at: Some(10),
                    role: "User".to_string(),
                    author: None,
                    content_blake3_hex: "cd".repeat(32),
                },
                winner_conversation_id: 1,
                winner_message_id: 7,
                winner_idx: 0,
                winner_merge_fingerprint: MergeFingerprint {
                    idx: 0,
                    created_at: Some(11),
                    role: "User".to_string(),
                    author: None,
                    content_blake3_hex: "ef".repeat(32),
                },
            }),
            reason: None,
        }
    }

    #[test]
    fn conversation_identity_digest_tracks_the_parent_not_its_mutable_attributes() {
        let base =
            conversation_identity_digest("lib-1", 7, "host-a", 3, Some("ext-1"), "/p/a.jsonl");
        // With an external id the locator is the external id, so a path change
        // on the same parent row cannot move the identity.
        assert_eq!(
            base,
            conversation_identity_digest("lib-1", 7, "host-a", 3, Some("ext-1"), "/p/b.jsonl")
        );
        // Without one the path is the locator, and the two forms differ.
        let by_path = conversation_identity_digest("lib-1", 7, "host-a", 3, None, "/p/a.jsonl");
        assert_ne!(by_path, base);
        assert_ne!(
            by_path,
            conversation_identity_digest("lib-1", 7, "host-a", 3, None, "/p/b.jsonl")
        );
        // An empty external id is preserved rather than folded into the path
        // form.
        assert_ne!(
            conversation_identity_digest("lib-1", 7, "host-a", 3, Some(""), "/p/a.jsonl"),
            by_path
        );
        // A different parent row, host, agent or library is a different
        // identity.
        for other in [
            conversation_identity_digest("lib-1", 8, "host-a", 3, Some("ext-1"), "/p/a.jsonl"),
            conversation_identity_digest("lib-1", 7, "host-b", 3, Some("ext-1"), "/p/a.jsonl"),
            conversation_identity_digest("lib-1", 7, "host-a", 4, Some("ext-1"), "/p/a.jsonl"),
            conversation_identity_digest("lib-2", 7, "host-a", 3, Some("ext-1"), "/p/a.jsonl"),
            conversation_identity_digest("lib-1", 7, "host-a", 3, Some("ext-2"), "/p/a.jsonl"),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn a_winner_rejection_rebuilds_its_leaf_from_the_persisted_witness_alone() {
        let claim = claim_on(1, ClaimMappingState::Canonical, Some((0, 3)));
        let first = rejection_installation(Sha256Digest::of(b"identity-a"));
        let second = rejection_installation(Sha256Digest::of(b"identity-b"));

        let digest_a = binding_digest(&claim, &first);
        let digest_b = binding_digest(&claim, &second);
        assert_ne!(
            digest_a, digest_b,
            "the conversation identity must be load-bearing in the witness digest"
        );

        // The persisted envelope alone reproduces the leaf: no side channel and
        // no live winner row is needed.
        let bytes = encode_link_evidence(&claim, Some(&first)).expect("encode");
        let decoded = decode_link_evidence(&bytes).expect("decode");
        let decoded_installation = decoded.installation.as_ref().expect("installation");
        assert_eq!(
            decoded_installation
                .rejection
                .as_ref()
                .expect("rejection")
                .conversation_identity_digest,
            Sha256Digest::of(b"identity-a")
        );
        assert_eq!(binding_digest(&decoded.claim, decoded_installation), digest_a);
    }

    /// Seed the minimal conversation chain a live `messages` row needs, so the
    /// link table's `message_id` foreign key is satisfiable.
    fn seed_message(conn: &Conn, message_id: i64) {
        conn.execute_batch(&format!(
            "INSERT INTO agents (id, slug, name, kind, created_at, updated_at)
                 VALUES (1, 'claude', 'Claude', 'agent', 0, 0);
             INSERT INTO workspaces (id, path) VALUES (1, '/tmp/ws');
             INSERT INTO conversations (id, agent_id, workspace_id, source_id, source_path)
                 VALUES (1, 1, 1, 'local', '/tmp/session.jsonl');
             INSERT INTO messages (id, conversation_id, idx, role, content)
                 VALUES ({message_id}, 1, 3, 'user', 'hello');"
        ))
        .expect("seed a conversation and message");
    }

    #[test]
    fn links_install_per_class_and_refuse_a_conflicting_digest() {
        use crate::storage::api::TxMode;

        let conn = Conn::open_memory().expect("in-memory sqlite");
        crate::storage::schema::ensure(&conn).expect("schema 9 must build");
        seed_message(&conn, 7);
        let input = sample_input();
        let records = vec![
            sample_record(1, None),
            sample_record(2, None),
            sample_record(3, None),
        ];
        let tx = conn.transaction_with_mode(TxMode::Immediate).unwrap();
        let staged = stage_source_records_in_tx(&tx, &input, &records).expect("stage");
        tx.commit().unwrap();

        let canonical = ClaimLinkInstall {
            claim: claim_on(1, ClaimMappingState::Canonical, Some((0, 3))),
            installation: Some(sample_installation()),
        };
        let standalone = ClaimLinkInstall {
            claim: claim_on(2, ClaimMappingState::Standalone, None),
            installation: Some(standalone_installation()),
        };
        // No installation yet: the row keeps the domain-tagged pending digest
        // and a NULL authority, and is not counted as canonical.
        let pending = ClaimLinkInstall {
            claim: claim_on(3, ClaimMappingState::Canonical, Some((0, 9))),
            installation: None,
        };

        let page = [canonical.clone(), standalone.clone(), pending.clone()];
        let tx = conn.transaction_with_mode(TxMode::Immediate).unwrap();
        let first = install_source_links_in_tx(&tx, staged.input_id, &page).expect("install");
        tx.commit().unwrap();
        assert_eq!(first.inserted, 3);
        assert_eq!(first.canonical, 1);
        assert_eq!(first.standalone, 1);
        assert_eq!(first.unresolved, 1);

        let tx = conn.transaction_with_mode(TxMode::Immediate).unwrap();
        let again = install_source_links_in_tx(&tx, staged.input_id, &page).expect("re-install");
        tx.commit().unwrap();
        assert_eq!(again.inserted, 0);
        assert_eq!(again.verified_same, 3, "an installed witness is never rewritten");

        let rows: Vec<(Option<String>, Option<i64>)> = conn
            .query_all_map(
                "SELECT authority, message_id FROM source_message_links ORDER BY id",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )
            .unwrap();
        assert_eq!(
            rows,
            vec![
                (Some("canonical".to_string()), Some(7)),
                (Some("standalone".to_string()), None),
                (None, None),
            ]
        );

        // The pending row stores the pending digest, not a binding digest.
        let stored: Vec<u8> = conn
            .query_row_map(
                "SELECT binding_digest FROM source_message_links WHERE authority IS NULL",
                &[],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(stored, pending.claim.pending_claim_digest().as_bytes().to_vec());

        // A conflicting digest for an already-installed link is refused rather
        // than overwritten.
        let mut conflicting = canonical.clone();
        if let Some(installation) = conflicting.installation.as_mut() {
            installation.semantic_request_digest = Sha256Digest::of(b"a different request");
        }
        let tx = conn.transaction_with_mode(TxMode::Immediate).unwrap();
        let err = install_source_links_in_tx(&tx, staged.input_id, &[conflicting])
            .expect_err("a witness digest is immutable");
        drop(tx);
        assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");

        // A claim whose record was never staged is refused.
        let tx = conn.transaction_with_mode(TxMode::Immediate).unwrap();
        let err = install_source_links_in_tx(
            &tx,
            staged.input_id,
            &[ClaimLinkInstall {
                claim: claim_on(99, ClaimMappingState::Standalone, None),
                installation: Some(standalone_installation()),
            }],
        )
        .expect_err("an unstaged record has nothing to link");
        drop(tx);
        assert!(matches!(err, SourceInstallError::Staging { .. }), "{err}");
    }

    #[test]
    fn diagnostics_envelope_round_trips() {
        let envelope = DiagnosticsEnvelope {
            version: SOURCE_ENVELOPE_VERSION,
            domain: SOURCE_DIAGNOSTICS_DOMAIN.to_string(),
            items: vec![SafeDiagnostic {
                code: "duplicate_object_key".to_string(),
                detail: None,
                offset: Some(12),
                position: None,
            }],
        };
        let bytes = encode_envelope(&envelope).expect("encode");
        assert_eq!(decode_diagnostics(&bytes).expect("decode"), envelope);
    }

    // -- §17.1: the sealed references prune must protect ---------------------

    /// The canonical `sealed_ref_bin` bytes, built the way the capture builds
    /// them: parse the compact JSON into the lossless tree, then write it
    /// canonically. Never a hand-spelled byte string.
    fn sealed_ref_bytes(blob_relative_path: &str, blob_digest: &str) -> Vec<u8> {
        let json = format!(
            "{{\"transport\":\"raw_blob\",\"blob_algorithm\":\"blake3\",\
             \"blob_digest\":\"{blob_digest}\",\"blob_relative_path\":\"{blob_relative_path}\"}}"
        );
        let tree = LosslessSourceValue::parse(json.as_bytes()).expect("parse");
        let mut bytes = Vec::new();
        tree.write_canonical(&mut bytes).expect("write canonical");
        bytes
    }

    /// Insert one `source_inputs` row in `state` carrying `sealed_ref_bin`,
    /// honouring the frozen DDL's width and state-pairing CHECKs.
    fn insert_input_row(storage: &crate::storage::sqlite::FrankenStorage, state: &str, sealed_ref_bin: &[u8], key_seed: u8) {
        let complete = state == "complete";
        let tx = storage.raw().transaction().expect("begin");
        tx.execute(
            "INSERT INTO source_inputs (
                 input_key, identity_tuple_bin, source_id, identity_namespace, connector,
                 root_id_bin, relative_locator_bin, discovery_bin, parser_context_bin,
                 context_digest, sealed_ref_bin, sealed_sha256, byte_len, format,
                 expected_manifest_bin, normalizer_id, safety_contract_id, state,
                 expected_records, expected_blank_lines, receipt_key, applied_content_generation,
                 activation_request_hash, observed_records, observed_blank_lines)
             VALUES (?1, ?2, 'src', 'ns', 'claude', ?2, ?2, ?2, ?2, ?3, ?4, ?3, ?5, 'jsonl',
                 ?2, 'norm', 'safe', ?6, ?5, ?5, ?7, ?7, ?8, ?9, ?9)",
            &[
                Value::Blob(vec![key_seed; 32]),
                Value::Blob(vec![key_seed; 4]),
                zeros(32),
                Value::Blob(sealed_ref_bin.to_vec()),
                zeros(8),
                Value::Text(state.to_string()),
                if complete {
                    Value::Text("receipt-key".to_string())
                } else {
                    Value::Null
                },
                if complete { zeros(32) } else { Value::Null },
                if complete { zeros(8) } else { Value::Null },
            ],
        )
        .expect("insert the input row");
        tx.commit().expect("commit");
    }

    /// A legal schema-7/8 archive has no source tables at all. It must report
    /// "no source facts" — not an error, and not a table probe.
    #[test]
    fn pending_sealed_blob_refs_reports_absent_capability_on_a_legacy_archive() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let conn = crate::storage::testing::open_writable_for_tests(
            &dir.path().join("legacy.db"),
            crate::storage::api::Profile::Production,
        )
        .expect("open a schema-free connection");
        conn.execute("PRAGMA user_version = 8", &[]).expect("mark schema 8");

        assert_eq!(
            pending_sealed_blob_refs(&conn).expect("a legal legacy archive is not a failure"),
            PendingSealedBlobRefs::NoSourceFacts
        );
    }

    /// Schema 9 must have the source tables. A read that fails there is a
    /// refusal: degrading to an empty set would let prune delete a
    /// replay-needed blob.
    #[test]
    fn pending_sealed_blob_refs_refuses_a_schema_nine_archive_without_source_tables() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let conn = crate::storage::testing::open_writable_for_tests(
            &dir.path().join("broken.db"),
            crate::storage::api::Profile::Production,
        )
        .expect("open a schema-free connection");
        conn.execute("PRAGMA user_version = 9", &[]).expect("mark schema 9");

        let err = pending_sealed_blob_refs(&conn)
            .expect_err("a schema-9 archive without source_inputs must refuse");
        assert!(matches!(err, SourceSealedRefError::Unreadable { .. }), "{err}");
        assert_eq!(err.code(), "source-read-failed");
    }

    /// A schema newer than this binary's is refused rather than guessed at.
    #[test]
    fn pending_sealed_blob_refs_refuses_a_newer_schema() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let conn = crate::storage::testing::open_writable_for_tests(
            &dir.path().join("newer.db"),
            crate::storage::api::Profile::Production,
        )
        .expect("open a schema-free connection");
        conn.execute("PRAGMA user_version = 10", &[]).expect("mark a newer schema");

        let err = pending_sealed_blob_refs(&conn).expect_err("a newer archive must refuse");
        assert_eq!(err, SourceSealedRefError::UnsupportedVersion { found: 10 });
    }

    /// One row per retry-pending state, none for `complete`, and every
    /// reference decoded from its stored canonical bytes.
    #[test]
    fn pending_sealed_blob_refs_returns_only_the_retry_pending_states() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let storage = crate::storage::sqlite::FrankenStorage::open(&dir.path().join("t.db"))
            .expect("open the database");
        let digest = "a".repeat(64);
        let path = format!("blobs/blake3/aa/{digest}.raw");
        for (index, state) in ["staged", "partial", "failed", "complete"].iter().enumerate() {
            let seed = u8::try_from(index).expect("small index") + 1;
            insert_input_row(&storage, state, &sealed_ref_bytes(&path, &digest), seed);
        }

        let found = pending_sealed_blob_refs(storage.raw()).expect("read the references");
        let PendingSealedBlobRefs::Refs(refs) = found else {
            panic!("schema 9 with the source tables present must report references");
        };
        assert_eq!(refs.len(), 3, "`complete` is not a retry-pending state");
        for reference in &refs {
            assert_eq!(reference.transport, "raw_blob");
            assert_eq!(reference.blob_algorithm, "blake3");
            assert_eq!(reference.blob_digest, digest);
            assert_eq!(reference.blob_relative_path, path);
        }
    }

    /// A reference that does not decode is refused, never skipped.
    #[test]
    fn pending_sealed_blob_refs_refuses_an_undecodable_reference() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let storage = crate::storage::sqlite::FrankenStorage::open(&dir.path().join("t.db"))
            .expect("open the database");
        insert_input_row(&storage, "staged", b"not the sealed reference", 1);

        let err = pending_sealed_blob_refs(storage.raw())
            .expect_err("an undecodable sealed reference must refuse");
        assert!(matches!(err, SourceSealedRefError::InvalidSealedRef { .. }), "{err}");
        assert_eq!(err.code(), "sealed-ref-invalid");
    }

    /// A decodable tree that is missing one recorded member is refused too:
    /// the four members are the contract, not a convention.
    #[test]
    fn pending_sealed_blob_refs_refuses_a_reference_missing_a_member() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let storage = crate::storage::sqlite::FrankenStorage::open(&dir.path().join("t.db"))
            .expect("open the database");
        let digest = "b".repeat(64);
        insert_input_row(
            &storage,
            "staged",
            &sealed_ref_bytes(&format!("blobs/blake3/bb/{digest}.raw"), &digest),
            1,
        );
        // Overwrite the member set with a tree the capture never writes.
        let tx = storage.raw().transaction().expect("begin");
        tx.execute(
            "UPDATE source_inputs SET sealed_ref_bin = ?1 WHERE id = 1",
            &[Value::Blob(br#"{"transport":"raw_blob"}"#.to_vec())],
        )
        .expect("replace the sealed reference");
        tx.commit().expect("commit");

        let err = pending_sealed_blob_refs(storage.raw())
            .expect_err("a sealed reference missing a recorded member must refuse");
        assert!(matches!(err, SourceSealedRefError::InvalidSealedRef { .. }), "{err}");
    }
}
