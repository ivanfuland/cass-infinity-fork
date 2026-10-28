//! Read-only source-facts paging (Task10, reader contract v2).
//!
//! This module reads the original source facts one page at a time through the
//! public [`SourceFactsReader`]. Every page runs inside its own `Deferred`
//! read transaction: the strict source-schema gate, the library identity, the
//! facts revision and the filter digest are re-checked there before any row is
//! read, and the last input's raw 31-column header snapshot is bound into the
//! cursor so a same-revision transient change is refused instead of silently
//! served.
//!
//! The reader never calls the whole-input helpers that materialise a `Vec`;
//! records and links are queried per input in their frozen order, with the
//! page limits as an explicit bound.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use franken_agent_detection::LosslessSourceValue;

use super::{
    AttemptHistory, CanonicalTuple, DiagnosticsEnvelope, OriginalInstallation,
    SOURCE_ENVELOPE_VERSION, SOURCE_UNPROCESSED_RANGES_DOMAIN, Sha256Digest, SourceClaim,
    SourceFormat, StoredLinkRow, UnprocessedRangesEnvelope, decode_envelope,
    decode_expected_manifest_header, decode_position_bin, read_attempt_history,
    read_library_identity, read_source_facts_revision, safe_value_sha256, verify_source_schema,
};
use crate::storage::api::{Conn, Tx, TxMode, Value};
use crate::storage::schema::CURRENT_SCHEMA_VERSION;
use crate::storage::source_codec::{SAFE_SOURCE_CODEC_ID, decode_safe_source};

use super::standard::{StandardFacts, map_standard};

/// The global cursor/reader version this module implements.
pub const SOURCE_FACTS_READER_VERSION: u32 = 2;

/// Cursor domain prefix; only the exact `/2` tuple is accepted.
const CURSOR_DOMAIN: &str = "cass.source-facts-cursor/2";
const CURSOR_DOMAIN_PREFIX: &str = "cass.source-facts-cursor/";
/// Domain of the per-input raw header snapshot carried inside the cursor.
const INPUT_HEADER_SNAPSHOT_DOMAIN: &str = "cass.source-input-header-snapshot/1";

/// The one published-input predicate (reader contract v2). `all_source` must
/// consume this exact fragment in its stable query; no extra state list and no
/// non-empty `items` requirement.
const PUBLISHED_INPUT_SQL: &str = "(i.state = 'complete' OR i.unprocessed_ranges_bin IS NOT NULL)";

const INPUT_SNAPSHOT_COLUMNS: [&str; 31] = [
    "input_key",
    "identity_tuple_bin",
    "source_id",
    "identity_namespace",
    "connector",
    "origin_host",
    "origin_source_version",
    "role_bin",
    "platform_bin",
    "root_id_bin",
    "relative_locator_bin",
    "discovery_bin",
    "parser_context_bin",
    "context_digest",
    "sealed_ref_bin",
    "sealed_sha256",
    "byte_len",
    "format",
    "expected_manifest_bin",
    "normalizer_id",
    "safety_contract_id",
    "state",
    "expected_records",
    "expected_blank_lines",
    "observed_records",
    "observed_blank_lines",
    "unprocessed_ranges_bin",
    "attempt_history_bin",
    "activation_request_hash",
    "receipt_key",
    "applied_content_generation",
];

const INPUT_COLUMNS_SQL: &str = "SELECT input_key, identity_tuple_bin, source_id, \
     identity_namespace, connector, origin_host, origin_source_version, role_bin, platform_bin, \
     root_id_bin, relative_locator_bin, discovery_bin, parser_context_bin, context_digest, \
     sealed_ref_bin, sealed_sha256, byte_len, format, expected_manifest_bin, normalizer_id, \
     safety_contract_id, state, expected_records, expected_blank_lines, observed_records, \
     observed_blank_lines, unprocessed_ranges_bin, attempt_history_bin, activation_request_hash, \
     receipt_key, applied_content_generation \
     FROM source_inputs WHERE input_key = ?1";

// =============================================================================
// Errors
// =============================================================================

/// The seven public, payload-free error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFactsReadErrorCode {
    SourceFactsUnavailable,
    UnsupportedReaderVersion,
    StaleCursor,
    DecodeFailed,
    InputIncomplete,
    InvalidCursor,
    DbError,
}

impl SourceFactsReadErrorCode {
    /// Stable short code.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceFactsUnavailable => "source_facts_unavailable",
            Self::UnsupportedReaderVersion => "unsupported_reader_version",
            Self::StaleCursor => "stale_cursor",
            Self::DecodeFailed => "decode_failed",
            Self::InputIncomplete => "input_incomplete",
            Self::InvalidCursor => "invalid_cursor",
            Self::DbError => "db_error",
        }
    }
}

/// One read refusal: a closed kind plus a safe, whitelisted JSON detail.
#[derive(Clone)]
pub struct SourceFactsReadError {
    code: SourceFactsReadErrorCode,
    detail: serde_json::Value,
}

impl SourceFactsReadError {
    fn new(code: SourceFactsReadErrorCode, reason: &str) -> Self {
        let mut map = serde_json::Map::new();
        map.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
        Self {
            code,
            detail: serde_json::Value::Object(map),
        }
    }

    fn with(mut self, key: &str, value: serde_json::Value) -> Self {
        if let Some(map) = self.detail.as_object_mut() {
            map.insert(key.to_string(), value);
        }
        self
    }

    fn with_input_key(self, key: &Sha256Digest) -> Self {
        self.with("input_key", serde_json::Value::String(key.hex()))
    }

    fn with_pointer(self, pointer: &str) -> Self {
        // A pointer may be an arbitrary string; only its digest is safe to
        // expose.
        self.with(
            "pointer_sha256",
            serde_json::Value::String(Sha256Digest::of(pointer.as_bytes()).hex()),
        )
    }

    /// The closed error kind.
    #[must_use]
    pub fn kind(&self) -> SourceFactsReadErrorCode {
        self.code
    }

    /// The stable short code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code.as_str()
    }

    /// A private copy of the safe detail object.
    #[must_use]
    pub fn detail(&self) -> serde_json::Value {
        self.detail.clone()
    }
}

impl fmt::Display for SourceFactsReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = self
            .detail
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        write!(f, "{}: {reason}", self.code.as_str())
    }
}

impl fmt::Debug for SourceFactsReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceFactsReadError")
            .field("code", &self.code.as_str())
            .field("detail", &self.detail)
            .finish()
    }
}

impl std::error::Error for SourceFactsReadError {}

fn unavailable() -> SourceFactsReadError {
    SourceFactsReadError::new(
        SourceFactsReadErrorCode::SourceFactsUnavailable,
        "source_facts_unavailable",
    )
}

fn db_error() -> SourceFactsReadError {
    SourceFactsReadError::new(SourceFactsReadErrorCode::DbError, "read_failed")
}

fn invalid_page_limits() -> SourceFactsReadError {
    SourceFactsReadError::new(
        SourceFactsReadErrorCode::InvalidCursor,
        "invalid_page_limits",
    )
}

fn invalid_cursor(reason: &str) -> SourceFactsReadError {
    SourceFactsReadError::new(SourceFactsReadErrorCode::InvalidCursor, reason)
}

fn stale_cursor(reason: &str) -> SourceFactsReadError {
    SourceFactsReadError::new(SourceFactsReadErrorCode::StaleCursor, reason)
}

fn input_incomplete(key: &Sha256Digest) -> SourceFactsReadError {
    SourceFactsReadError::new(
        SourceFactsReadErrorCode::InputIncomplete,
        "input_not_available_in_scope",
    )
    .with_input_key(key)
}

fn input_metadata_error() -> SourceFactsReadError {
    SourceFactsReadError::new(
        SourceFactsReadErrorCode::DecodeFailed,
        "invalid_input_metadata",
    )
}

fn record_metadata_error() -> SourceFactsReadError {
    SourceFactsReadError::new(
        SourceFactsReadErrorCode::DecodeFailed,
        "invalid_record_metadata",
    )
}

/// Re-label a column read taken from a `source_records` row as a
/// record-context failure. The same helpers are shared with the input header,
/// where a type error is an input-metadata failure instead.
fn record_col<T>(value: Result<T, SourceFactsReadError>) -> Result<T, SourceFactsReadError> {
    value.map_err(|_| record_metadata_error())
}

fn link_evidence_error() -> SourceFactsReadError {
    SourceFactsReadError::new(
        SourceFactsReadErrorCode::DecodeFailed,
        "invalid_link_evidence",
    )
}

fn codec_error(codec_detail: &'static str) -> SourceFactsReadError {
    SourceFactsReadError::new(SourceFactsReadErrorCode::DecodeFailed, "codec_invalid")
        .with("codec", serde_json::Value::String(codec_detail.to_string()))
}

fn safe_hash_error() -> SourceFactsReadError {
    SourceFactsReadError::new(
        SourceFactsReadErrorCode::DecodeFailed,
        "safe_value_hash_mismatch",
    )
}

// =============================================================================
// Filter, limits and DTOs
// =============================================================================

/// Which stable fact domain a page reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFactsScope {
    Analysis,
    HistoryUnresolved,
    AllSource,
}

impl SourceFactsScope {
    /// Column/JSON spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Analysis => "analysis",
            Self::HistoryUnresolved => "history_unresolved",
            Self::AllSource => "all_source",
        }
    }
}

/// Exact-match filter. Empty members do not limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFactsFilter {
    pub scope: SourceFactsScope,
    pub connectors: Vec<String>,
    pub input_keys: Vec<Sha256Digest>,
}

impl Default for SourceFactsFilter {
    fn default() -> Self {
        Self {
            scope: SourceFactsScope::Analysis,
            connectors: Vec::new(),
            input_keys: Vec::new(),
        }
    }
}

impl SourceFactsFilter {
    /// SHA-256 of `["cass.source-filter/1", scope, sorted connectors, sorted
    /// keys]`, compact UTF-8 JSON. The caller's vectors are never modified.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        let mut connectors = self.connectors.clone();
        connectors.sort();
        connectors.dedup();
        let mut keys = self.input_keys.clone();
        keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        keys.dedup();

        let mut tuple = CanonicalTuple::new();
        tuple.str("cass.source-filter/1").str(self.scope.as_str());
        let mut connector_array = CanonicalTuple::new();
        for connector in &connectors {
            connector_array.str(connector);
        }
        tuple.raw(&connector_array.finish());
        let mut key_array = CanonicalTuple::new();
        for key in &keys {
            key_array.str(&key.hex());
        }
        tuple.raw(&key_array.finish());
        tuple.finish_sha()
    }
}

/// Page bounds. Zero in either member is an `invalid_page_limits` refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceFactsPageLimits {
    pub max_records: usize,
    pub target_bytes: u64,
}

impl Default for SourceFactsPageLimits {
    fn default() -> Self {
        Self {
            max_records: 64,
            target_bytes: 8_388_608,
        }
    }
}

/// The expected-manifest header as stored, plus its verified safety identity.
#[derive(Clone)]
pub struct SourceFactsExpectedManifest {
    pub manifest: super::VerifiedExpectedManifest,
    pub safety: super::VerifiedSafetyIdentity,
}

impl fmt::Debug for SourceFactsExpectedManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceFactsExpectedManifest")
            .field("records", &self.manifest.records())
            .field("blank_lines", &self.manifest.blank_lines())
            .finish()
    }
}

/// One input header, exactly the frozen field set.
#[derive(Clone)]
pub struct SourceFactsInput {
    pub input_key: Sha256Digest,
    pub identity_tuple: Vec<Option<String>>,
    pub identity_namespace: String,
    pub source_id: String,
    pub connector: String,
    pub root_id: String,
    pub relative_locator: String,
    pub origin_kind: Option<String>,
    pub origin_host: Option<String>,
    pub origin_source_version: Option<String>,
    pub role: Option<String>,
    pub platform: Option<String>,
    pub discovery: LosslessSourceValue,
    pub parser_context: LosslessSourceValue,
    pub sealed_ref: LosslessSourceValue,
    pub context_digest: Sha256Digest,
    pub sealed_sha256: Sha256Digest,
    pub byte_len: u64,
    pub format: SourceFormat,
    pub expected_manifest: SourceFactsExpectedManifest,
    pub normalizer_id: String,
    pub safety_contract_id: String,
    pub state: String,
    pub expected_records: u64,
    pub expected_blank_lines: u64,
    pub observed_records: Option<u64>,
    pub observed_blank_lines: Option<u64>,
    pub unprocessed_ranges: Option<UnprocessedRangesEnvelope>,
    pub attempt_history: Option<AttemptHistory>,
    pub activation_request_hash: Option<Sha256Digest>,
    pub receipt_key: Option<String>,
    pub applied_content_generation: Option<String>,
}

impl fmt::Debug for SourceFactsInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceFactsInput")
            .field("key", &self.short_key())
            .field("format", &self.format.as_str())
            .field("expected_records", &self.expected_records)
            .field("observed_records", &self.observed_records)
            .finish()
    }
}

impl SourceFactsInput {
    fn short_key(&self) -> String {
        self.input_key.hex()[..8].to_string()
    }
}

/// One stored record link, with its immutable installation when installed.
#[derive(Clone)]
pub struct SourceFactsRecordLink {
    pub claim: SourceClaim,
    pub original_installation: Option<OriginalInstallation>,
    pub binding_digest: Sha256Digest,
    pub authority: Option<String>,
    pub message_id: Option<i64>,
}

impl fmt::Debug for SourceFactsRecordLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceFactsRecordLink")
            .field("installed", &self.original_installation.is_some())
            .field("authority", &self.authority)
            .field("message_present", &self.message_id.is_some())
            .finish()
    }
}

/// One raw record (no standard facts).
#[derive(Clone)]
pub struct RawSourceFactsRecord {
    pub input_key: Sha256Digest,
    pub ordinal: u64,
    pub record_pointer: String,
    pub byte_start: u64,
    pub byte_end: u64,
    pub record_byte_len: u64,
    pub expected_source_record_sha256: Sha256Digest,
    pub observed_source_record_sha256: Option<Sha256Digest>,
    pub frame_state: String,
    pub parse_state: String,
    pub record_mapping_state: String,
    pub safety_state: String,
    pub retention_state: String,
    pub codec: Option<String>,
    pub payload: Option<Vec<u8>>,
    pub payload_sha256: Option<Sha256Digest>,
    pub safe_value_hash: Option<Sha256Digest>,
    pub safe_value: Option<LosslessSourceValue>,
    pub native_ids: Option<LosslessSourceValue>,
    pub diagnostics: Option<DiagnosticsEnvelope>,
    pub links: Vec<SourceFactsRecordLink>,
}

impl fmt::Debug for RawSourceFactsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawSourceFactsRecord")
            .field("ordinal", &self.ordinal)
            .field("record_byte_len", &self.record_byte_len)
            .field("links", &self.links.len())
            .field("payload_present", &self.payload.is_some())
            .finish()
    }
}

/// One full record: raw facts plus the standard facts of its own input's
/// accepted connector, when the record retained a safe value.
#[derive(Clone)]
pub struct SourceFactsRecord {
    pub raw: RawSourceFactsRecord,
    pub standard: Option<StandardFacts>,
}

impl fmt::Debug for SourceFactsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceFactsRecord")
            .field("raw", &self.raw)
            .field("standard_present", &self.standard.is_some())
            .finish()
    }
}

/// A page of raw records.
#[derive(Clone)]
pub struct RawSourceFactsPage {
    pub reader_version: u32,
    pub library_identity: String,
    pub source_facts_revision: u64,
    pub filter_digest: Sha256Digest,
    pub inputs: Vec<SourceFactsInput>,
    pub records: Vec<RawSourceFactsRecord>,
    pub oversized_records: u64,
    pub next_cursor: Option<String>,
}

impl fmt::Debug for RawSourceFactsPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawSourceFactsPage")
            .field("reader_version", &self.reader_version)
            .field("inputs", &self.inputs.len())
            .field("records", &self.records.len())
            .field("has_next", &self.next_cursor.is_some())
            .finish()
    }
}

/// A page of full records: every raw member carried over unchanged, with the
/// standard facts joined per record.
#[derive(Clone)]
pub struct SourceFactsPage {
    pub reader_version: u32,
    pub library_identity: String,
    pub source_facts_revision: u64,
    pub filter_digest: Sha256Digest,
    pub inputs: Vec<SourceFactsInput>,
    pub records: Vec<SourceFactsRecord>,
    pub oversized_records: u64,
    pub next_cursor: Option<String>,
}

impl fmt::Debug for SourceFactsPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceFactsPage")
            .field("reader_version", &self.reader_version)
            .field("inputs", &self.inputs.len())
            .field("records", &self.records.len())
            .field("has_next", &self.next_cursor.is_some())
            .finish()
    }
}

// =============================================================================
// Reader
// =============================================================================

/// A read-only source-facts handle over one SQLite archive.
pub struct SourceFactsReader {
    conn: Conn,
}

impl fmt::Debug for SourceFactsReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceFactsReader")
    }
}

impl SourceFactsReader {
    /// Open `path` read-only and refuse anything that is not a schema-9
    /// archive with the frozen source tables.
    ///
    /// # Errors
    /// `source_facts_unavailable` for a schema below or above this binary's
    /// schema, or a missing/drifted source table; `db_error` when the file
    /// cannot be opened or probed.
    pub fn open(path: &Path) -> Result<Self, SourceFactsReadError> {
        let conn = Conn::open_read(path).map_err(|_| db_error())?;
        let version: i64 = conn
            .query_row_map("PRAGMA user_version;", &[], |row| row.get_typed(0))
            .map_err(|_| db_error())?;
        if version != CURRENT_SCHEMA_VERSION {
            return Err(unavailable());
        }
        verify_source_schema(&conn).map_err(|_| unavailable())?;
        Ok(Self { conn })
    }

    /// Read one bounded page of raw source facts.
    ///
    /// # Errors
    /// The closed [`SourceFactsReadErrorCode`] set; see the reader contract.
    pub fn read_raw_source_facts(
        &self,
        filter: &SourceFactsFilter,
        cursor: Option<&str>,
        limits: SourceFactsPageLimits,
    ) -> Result<RawSourceFactsPage, SourceFactsReadError> {
        if limits.max_records == 0 || limits.target_bytes == 0 {
            return Err(invalid_page_limits());
        }
        let filter_digest = filter.digest();
        let decoded_cursor = match cursor {
            Some(text) => Some(decode_cursor(text, &filter_digest)?),
            None => None,
        };

        let tx = self
            .conn
            .transaction_with_mode(TxMode::Deferred)
            .map_err(|_| db_error())?;
        verify_source_schema(&tx).map_err(|_| unavailable())?;
        let library_identity = read_library_identity(&tx).map_err(|_| input_metadata_error())?;
        let revision = read_source_facts_revision(&tx).map_err(|_| input_metadata_error())?;

        // Explicitly requested inputs must be available in this scope; a
        // broad query silently skips unpublished inputs instead.
        for key in &filter.input_keys {
            if !input_available(&tx, filter.scope, key)? {
                return Err(input_incomplete(key));
            }
        }

        let mut start: Option<CursorState> = None;
        if let Some(cursor) = decoded_cursor {
            if cursor.library_identity != library_identity {
                return Err(stale_cursor("library_changed"));
            }
            if cursor.revision != revision {
                return Err(stale_cursor("revision_changed"));
            }
            let columns = fetch_input_columns(&tx, cursor.last_key.as_bytes())?
                .ok_or_else(|| invalid_cursor("invalid_position"))?;
            let snapshot = header_snapshot_digest(&columns)?;
            if snapshot != cursor.header_digest {
                return Err(stale_cursor("input_header_changed"));
            }
            validate_cursor_position(&tx, filter, &cursor, &columns)?;
            start = Some(cursor);
        }

        let mut page = RawSourceFactsPage {
            reader_version: SOURCE_FACTS_READER_VERSION,
            library_identity,
            source_facts_revision: revision,
            filter_digest,
            inputs: Vec::new(),
            records: Vec::new(),
            oversized_records: 0,
            next_cursor: None,
        };
        let mut headers: usize = 0;
        let mut used_bytes: u64 = 0;

        // `last` is the position a page-end cursor names: either the last
        // record really output, or the input's completion marker
        // (`None`/`None`) once its visible records are exhausted.
        let mut last: Option<(Sha256Digest, Option<u64>, Option<String>, Sha256Digest)> = None;
        let mut stopped = false;
        let mut more_after = false;

        let mut next_key = match &start {
            Some(cursor) => {
                if cursor.last_ordinal.is_none() {
                    // The input was already completely crossed; resume after it.
                    next_input_key(&tx, filter, Some(cursor.last_key.as_bytes()), false)?
                } else {
                    Some(cursor.last_key.as_bytes().to_vec())
                }
            }
            None => next_input_key(&tx, filter, None, false)?,
        };

        'inputs: while let Some(key_bytes) = next_key {
            let key = digest_from_bytes(&key_bytes).ok_or_else(input_metadata_error)?;

            // The header cap is checked before the next header is read or
            // decoded, so a page never fails on a header it would not touch.
            if headers == limits.max_records {
                stopped = true;
                more_after = true;
                break 'inputs;
            }

            let columns = fetch_input_columns(&tx, &key_bytes)?.ok_or_else(input_metadata_error)?;
            let input = decode_input(&columns)?;
            let snapshot = header_snapshot_digest(&columns)?;

            let position = match &start {
                Some(cursor) if cursor.last_key == key => cursor
                    .last_ordinal
                    .map(|ordinal| (ordinal, cursor.last_pointer.clone().unwrap_or_default())),
                _ => None,
            };

            // One fixed, bounded query per record. No caller-sized LIMIT and
            // no whole-input prefetch: the input is walked until the page
            // limits stop it or the visible records really run out.
            let first_row = next_visible_record(&tx, filter.scope, &key, position.as_ref())?;
            let Some(mut row) = first_row else {
                // A visible zero-record input still contributes its header and
                // is marked completely crossed.
                headers += 1;
                page.inputs.push(input);
                last = Some((key, None, None, snapshot));
                next_key = next_input_key(&tx, filter, Some(&key_bytes), false)?;
                continue 'inputs;
            };

            // The byte target accumulates across inputs. If the page already
            // carries records and this input's first visible record would
            // exceed it, end the page before this input's header. The input is
            // left untouched and its first record starts the next page.
            let first_len = record_length(&row)?;
            if !page.records.is_empty()
                && used_bytes.saturating_add(first_len) > limits.target_bytes
            {
                stopped = true;
                more_after = finalize_stop(&tx, filter, &mut last)?;
                break 'inputs;
            }

            headers += 1;
            page.inputs.push(input);
            let mut after;
            loop {
                if page.records.len() == limits.max_records {
                    stopped = true;
                    break;
                }
                let record = decode_record(&tx, &key, &row)?;
                let length = record.record_byte_len;
                if !page.records.is_empty()
                    && used_bytes.saturating_add(length) > limits.target_bytes
                {
                    stopped = true;
                    break;
                }
                let ordinal = record.ordinal;
                let pointer = record.record_pointer.clone();
                page.records.push(record);
                used_bytes = used_bytes.saturating_add(length);
                last = Some((key, Some(ordinal), Some(pointer.clone()), snapshot));
                if length > limits.target_bytes {
                    // One oversized record is alone on its page.
                    page.oversized_records += 1;
                    stopped = true;
                    break;
                }
                if page.records.len() == limits.max_records {
                    stopped = true;
                    break;
                }
                after = Some((ordinal, pointer));
                let Some(next_row) = next_visible_record(&tx, filter.scope, &key, after.as_ref())?
                else {
                    // The input's visible records are truly exhausted.
                    last = Some((key, None, None, snapshot));
                    next_key = next_input_key(&tx, filter, Some(&key_bytes), false)?;
                    continue 'inputs;
                };
                row = next_row;
            }

            // Every non-`continue` exit from the inner loop is a page stop
            // (record cap, byte target or an oversized record).
            more_after = finalize_stop(&tx, filter, &mut last)?;
            break 'inputs;
        }

        if stopped && more_after {
            if let Some((key, ordinal, pointer, snapshot)) = last {
                page.next_cursor = Some(encode_cursor(
                    &page.library_identity,
                    page.source_facts_revision,
                    &page.filter_digest,
                    &key,
                    ordinal,
                    pointer.as_deref(),
                    &snapshot,
                ));
            }
        }
        Ok(page)
    }

    /// Read one bounded page of full source facts.
    ///
    /// The page is produced by exactly one call to
    /// [`Self::read_raw_source_facts`]; every raw member is carried over
    /// unchanged. A record whose input retained a safe value gets the standard
    /// facts of its own input's connector: `claude_code` and `codex` each use
    /// their accepted mapper, every other stored connector (including the
    /// literal `claude` alias) produces no standard facts.
    ///
    /// # Errors
    /// The closed [`SourceFactsReadErrorCode`] set; every raw refusal passes
    /// through unchanged. A record naming an input header that is not on this
    /// page is refused as `invalid_input_metadata`.
    pub fn read_source_facts(
        &self,
        filter: &SourceFactsFilter,
        cursor: Option<&str>,
        limits: SourceFactsPageLimits,
    ) -> Result<SourceFactsPage, SourceFactsReadError> {
        let raw = self.read_raw_source_facts(filter, cursor, limits)?;
        let mut headers: BTreeMap<[u8; 32], (&str, SourceFormat)> = BTreeMap::new();
        for input in &raw.inputs {
            headers.insert(
                *input.input_key.as_bytes(),
                (input.connector.as_str(), input.format),
            );
        }
        let mut records = Vec::with_capacity(raw.records.len());
        for record in raw.records {
            let Some((connector, format)) = headers.get(record.input_key.as_bytes()).copied()
            else {
                return Err(input_metadata_error());
            };
            let standard = match record.safe_value.as_ref() {
                Some(safe_value) => map_standard(connector, format, safe_value),
                None => None,
            };
            records.push(SourceFactsRecord {
                raw: record,
                standard,
            });
        }
        Ok(SourceFactsPage {
            reader_version: raw.reader_version,
            library_identity: raw.library_identity,
            source_facts_revision: raw.source_facts_revision,
            filter_digest: raw.filter_digest,
            inputs: raw.inputs,
            records,
            oversized_records: raw.oversized_records,
            next_cursor: raw.next_cursor,
        })
    }
}

// =============================================================================
// Key iteration and availability
// =============================================================================

/// Finish a stopped page: if the last output input has no further visible
/// record, replace its position with the completion marker, and report whether
/// any later input or record still exists.
fn finalize_stop(
    tx: &Tx<'_>,
    filter: &SourceFactsFilter,
    last: &mut Option<(Sha256Digest, Option<u64>, Option<String>, Sha256Digest)>,
) -> Result<bool, SourceFactsReadError> {
    let (last_key, last_ordinal, last_pointer, last_snapshot) = last
        .clone()
        .expect("a stopped page has already output an item");
    let more_records = match (last_ordinal, last_pointer.as_deref()) {
        (Some(ordinal), Some(pointer)) => {
            has_visible_record_after(tx, filter.scope, &last_key, Some((ordinal, pointer)))?
        }
        _ => false,
    };
    let more_keys = next_input_key(tx, filter, Some(last_key.as_bytes()), false)?.is_some();
    if !more_records {
        *last = Some((last_key, None, None, last_snapshot));
    }
    Ok(more_records || more_keys)
}

fn scope_input_predicate(scope: SourceFactsScope) -> &'static str {
    match scope {
        SourceFactsScope::Analysis | SourceFactsScope::HistoryUnresolved => "i.state = 'complete'",
        SourceFactsScope::AllSource => PUBLISHED_INPUT_SQL,
    }
}

fn build_key_query(
    filter: &SourceFactsFilter,
    after: Option<&[u8]>,
    inclusive: bool,
) -> (String, Vec<Value>) {
    let mut sql = format!(
        "SELECT i.input_key FROM source_inputs i WHERE {}",
        scope_input_predicate(filter.scope)
    );
    let mut params: Vec<Value> = Vec::new();
    if !filter.connectors.is_empty() {
        sql.push_str(" AND i.connector IN (");
        for (index, connector) in filter.connectors.iter().enumerate() {
            if index > 0 {
                sql.push(',');
            }
            sql.push_str(&format!("?{}", params.len() + 1));
            params.push(Value::Text(connector.clone()));
        }
        sql.push(')');
    }
    if !filter.input_keys.is_empty() {
        sql.push_str(" AND i.input_key IN (");
        for (index, key) in filter.input_keys.iter().enumerate() {
            if index > 0 {
                sql.push(',');
            }
            sql.push_str(&format!("?{}", params.len() + 1));
            params.push(Value::Blob(key.as_bytes().to_vec()));
        }
        sql.push(')');
    }
    if let Some(after) = after {
        sql.push_str(&format!(
            " AND i.input_key {} ?{}",
            if inclusive { ">=" } else { ">" },
            params.len() + 1
        ));
        params.push(Value::Blob(after.to_vec()));
    }
    sql.push_str(" ORDER BY i.input_key ASC LIMIT 1");
    (sql, params)
}

fn next_input_key(
    tx: &Tx<'_>,
    filter: &SourceFactsFilter,
    after: Option<&[u8]>,
    inclusive: bool,
) -> Result<Option<Vec<u8>>, SourceFactsReadError> {
    let (sql, params) = build_key_query(filter, after, inclusive);
    tx.query_opt_map(&sql, &params, |row| row.get_typed::<Vec<u8>>(0))
        .map_err(|_| db_error())
}

fn input_available(
    tx: &Tx<'_>,
    scope: SourceFactsScope,
    key: &Sha256Digest,
) -> Result<bool, SourceFactsReadError> {
    let sql = format!(
        "SELECT 1 FROM source_inputs i WHERE i.input_key = ?1 AND {}",
        scope_input_predicate(scope)
    );
    let found: Option<i64> = tx
        .query_opt_map(&sql, &[Value::Blob(key.as_bytes().to_vec())], |row| {
            row.get_typed(0)
        })
        .map_err(|_| db_error())?;
    Ok(found.is_some())
}

// =============================================================================
// Cursor
// =============================================================================

struct CursorState {
    library_identity: String,
    revision: u64,
    last_key: Sha256Digest,
    last_ordinal: Option<u64>,
    last_pointer: Option<String>,
    header_digest: Sha256Digest,
}

fn encode_cursor(
    library_identity: &str,
    revision: u64,
    filter_digest: &Sha256Digest,
    last_key: &Sha256Digest,
    last_ordinal: Option<u64>,
    last_pointer: Option<&str>,
    header_digest: &Sha256Digest,
) -> String {
    use base64::Engine as _;
    let mut out = Vec::new();
    out.push(b'[');
    super::write_json_string(&mut out, CURSOR_DOMAIN);
    out.push(b',');
    super::write_json_string(&mut out, library_identity);
    out.push(b',');
    super::write_json_string(&mut out, &revision.to_string());
    out.push(b',');
    super::write_json_string(&mut out, &filter_digest.hex());
    out.push(b',');
    super::write_json_string(&mut out, &last_key.hex());
    out.push(b',');
    match last_ordinal {
        Some(ordinal) => super::write_json_string(&mut out, &ordinal.to_string()),
        None => out.extend_from_slice(b"null"),
    }
    out.push(b',');
    match last_pointer {
        Some(pointer) => super::write_json_string(&mut out, pointer),
        None => out.extend_from_slice(b"null"),
    }
    out.push(b',');
    super::write_json_string(&mut out, &header_digest.hex());
    out.push(b']');
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
}

fn canonical_decimal(text: &str) -> Option<u64> {
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok()
}

/// A cursor version suffix: canonical non-empty ASCII decimal, no leading
/// zero, and within `u32`.
fn canonical_version(text: &str) -> Option<u32> {
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok()
}

fn canonical_hex_digest(text: &str) -> Option<Sha256Digest> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Sha256Digest::from_hex(text)
}

fn decode_cursor(
    cursor: &str,
    filter_digest: &Sha256Digest,
) -> Result<CursorState, SourceFactsReadError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| invalid_cursor("invalid_encoding"))?;
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != cursor {
        return Err(invalid_cursor("invalid_encoding"));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| invalid_cursor("invalid_encoding"))?;
    let items = value
        .as_array()
        .ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?;
    let domain = items
        .first()
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?;
    // The version branch is decided before the tuple length: a real canonical
    // `/1` seven-tuple is an older version, not a malformed `/2` tuple.
    if domain != CURSOR_DOMAIN {
        if let Some(suffix) = domain.strip_prefix(CURSOR_DOMAIN_PREFIX) {
            // Only a canonical non-empty ASCII decimal `u32` is a recognised
            // version; anything else is a shape error and its raw text is
            // never echoed into `found_version`.
            let Some(version) = canonical_version(suffix) else {
                return Err(invalid_cursor("invalid_cursor_shape"));
            };
            return Err(SourceFactsReadError::new(
                SourceFactsReadErrorCode::UnsupportedReaderVersion,
                "unsupported_reader_version",
            )
            .with(
                "found_version",
                serde_json::Value::String(version.to_string()),
            )
            .with(
                "expected_version",
                serde_json::Value::String(SOURCE_FACTS_READER_VERSION.to_string()),
            ));
        }
        return Err(invalid_cursor("invalid_cursor_shape"));
    }
    if items.len() != 8 {
        return Err(invalid_cursor("invalid_cursor_shape"));
    }
    let library_identity = items[1]
        .as_str()
        .ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?
        .to_string();
    let revision_text = items[2]
        .as_str()
        .ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?;
    let revision =
        canonical_decimal(revision_text).ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?;
    let filter_hex = items[3]
        .as_str()
        .ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?;
    let cursor_filter =
        canonical_hex_digest(filter_hex).ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?;
    let key_hex = items[4]
        .as_str()
        .ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?;
    let last_key =
        canonical_hex_digest(key_hex).ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?;
    let last_ordinal = match &items[5] {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => {
            Some(canonical_decimal(text).ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?)
        }
        _ => return Err(invalid_cursor("invalid_cursor_shape")),
    };
    let last_pointer = match &items[6] {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        _ => return Err(invalid_cursor("invalid_cursor_shape")),
    };
    if last_ordinal.is_some() != last_pointer.is_some() {
        return Err(invalid_cursor("invalid_cursor_shape"));
    }
    let header_hex = items[7]
        .as_str()
        .ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?;
    let header_digest =
        canonical_hex_digest(header_hex).ok_or_else(|| invalid_cursor("invalid_cursor_shape"))?;

    // Canonical compact spelling: rebuild the same tuple from the parsed
    // values and require the bytes to match exactly (no whitespace, no
    // alternative escapes, no trailing data).
    let rebuilt = encode_cursor(
        &library_identity,
        revision,
        &cursor_filter,
        &last_key,
        last_ordinal,
        last_pointer.as_deref(),
        &header_digest,
    );
    let rebuilt_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&rebuilt)
        .map_err(|_| invalid_cursor("invalid_encoding"))?;
    if rebuilt_bytes != bytes {
        return Err(invalid_cursor("invalid_encoding"));
    }

    if cursor_filter != *filter_digest {
        return Err(invalid_cursor("filter_changed"));
    }

    Ok(CursorState {
        library_identity,
        revision,
        last_key,
        last_ordinal,
        last_pointer,
        header_digest,
    })
}

fn validate_cursor_position(
    tx: &Tx<'_>,
    filter: &SourceFactsFilter,
    cursor: &CursorState,
    columns: &[Value],
) -> Result<(), SourceFactsReadError> {
    // The last input must still be in this filter's input domain.
    if !input_available(tx, filter.scope, &cursor.last_key)? {
        return Err(invalid_cursor("invalid_position"));
    }
    let input = decode_input(columns)?;
    if !filter.connectors.is_empty() && !filter.connectors.contains(&input.connector) {
        return Err(invalid_cursor("invalid_position"));
    }
    if !filter.input_keys.is_empty() && !filter.input_keys.contains(&cursor.last_key) {
        return Err(invalid_cursor("invalid_position"));
    }
    match (cursor.last_ordinal, &cursor.last_pointer) {
        (Some(ordinal), Some(pointer)) => {
            let exists =
                visible_record_exists(tx, filter.scope, &cursor.last_key, ordinal, pointer)?;
            if !exists {
                return Err(invalid_cursor("invalid_position"));
            }
        }
        (None, None) => {
            // A completion marker means this input was already crossed in this
            // filter; the reader only emits it after consuming the input.
        }
        _ => return Err(invalid_cursor("invalid_cursor_shape")),
    }
    Ok(())
}

// =============================================================================
// Input header decoding
// =============================================================================

fn blob(value: &Value) -> Result<&[u8], SourceFactsReadError> {
    match value {
        Value::Blob(bytes) => Ok(bytes.as_slice()),
        _ => Err(input_metadata_error()),
    }
}

fn text(value: &Value) -> Result<&str, SourceFactsReadError> {
    match value {
        Value::Text(text) => Ok(text.as_str()),
        _ => Err(input_metadata_error()),
    }
}

fn optional_text(value: &Value) -> Result<Option<String>, SourceFactsReadError> {
    match value {
        Value::Null => Ok(None),
        Value::Text(text) => Ok(Some(text.clone())),
        _ => Err(input_metadata_error()),
    }
}

/// Some optional text columns are written by the staging path as UTF-8 BLOB
/// bytes (the `*_bin` convention), even though the column affinity is TEXT.
/// Both representations carry the same original string; any other type is a
/// refusal.
fn optional_string(value: &Value) -> Result<Option<String>, SourceFactsReadError> {
    match value {
        Value::Null => Ok(None),
        Value::Text(text) => Ok(Some(text.clone())),
        Value::Blob(bytes) => String::from_utf8(bytes.clone())
            .map(Some)
            .map_err(|_| input_metadata_error()),
        _ => Err(input_metadata_error()),
    }
}

fn optional_blob(value: &Value) -> Result<Option<&[u8]>, SourceFactsReadError> {
    match value {
        Value::Null => Ok(None),
        Value::Blob(bytes) => Ok(Some(bytes.as_slice())),
        _ => Err(input_metadata_error()),
    }
}

fn digest_from_bytes(bytes: &[u8]) -> Option<Sha256Digest> {
    Sha256Digest::from_slice(bytes)
}

fn required_digest(value: &Value) -> Result<Sha256Digest, SourceFactsReadError> {
    digest_from_bytes(blob(value)?).ok_or_else(input_metadata_error)
}

fn optional_digest(value: &Value) -> Result<Option<Sha256Digest>, SourceFactsReadError> {
    match optional_blob(value)? {
        Some(bytes) => digest_from_bytes(bytes)
            .map(Some)
            .ok_or_else(input_metadata_error),
        None => Ok(None),
    }
}

fn ordinal_blob(value: &Value) -> Result<u64, SourceFactsReadError> {
    let bytes = blob(value)?;
    let array: [u8; 8] = bytes.try_into().map_err(|_| input_metadata_error())?;
    Ok(u64::from_be_bytes(array))
}

fn optional_ordinal(value: &Value) -> Result<Option<u64>, SourceFactsReadError> {
    match optional_blob(value)? {
        Some(bytes) => {
            let array: [u8; 8] = bytes.try_into().map_err(|_| input_metadata_error())?;
            Ok(Some(u64::from_be_bytes(array)))
        }
        None => Ok(None),
    }
}

fn fetch_input_columns(
    tx: &Tx<'_>,
    key: &[u8],
) -> Result<Option<Vec<Value>>, SourceFactsReadError> {
    tx.query_opt_map(INPUT_COLUMNS_SQL, &[Value::Blob(key.to_vec())], |row| {
        let mut values = Vec::with_capacity(31);
        for index in 0..31 {
            values.push(row.get_value(index)?);
        }
        Ok(values)
    })
    .map_err(|_| db_error())
}

/// Read the input header with the same strict checks as source export.
pub(crate) fn input_header_in_tx(
    tx: &Tx<'_>,
    key: &Sha256Digest,
) -> Result<Option<SourceFactsInput>, SourceFactsReadError> {
    fetch_input_columns(tx, key.as_bytes())?
        .map(|columns| decode_input(&columns))
        .transpose()
}

fn decode_identity_tuple(value: &Value) -> Result<Vec<Option<String>>, SourceFactsReadError> {
    let bytes = blob(value)?;
    let parsed: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| input_metadata_error())?;
    let items = parsed.as_array().ok_or_else(input_metadata_error)?;
    if items.len() != super::IDENTITY_TUPLE_LEN {
        return Err(input_metadata_error());
    }
    let mut tuple = Vec::with_capacity(items.len());
    for item in items {
        match item {
            serde_json::Value::Null => tuple.push(None),
            serde_json::Value::String(text) => tuple.push(Some(text.clone())),
            _ => return Err(input_metadata_error()),
        }
    }
    // The stored bytes must be the canonical tuple spelling, and the key is
    // exactly their SHA-256.
    if super::identity_tuple_bin(&tuple) != bytes {
        return Err(input_metadata_error());
    }
    Ok(tuple)
}

fn decode_unprocessed_ranges(
    bytes: &[u8],
) -> Result<UnprocessedRangesEnvelope, SourceFactsReadError> {
    let envelope: UnprocessedRangesEnvelope =
        decode_envelope(bytes).map_err(|_| input_metadata_error())?;
    if envelope.version != SOURCE_ENVELOPE_VERSION
        || envelope.domain != SOURCE_UNPROCESSED_RANGES_DOMAIN
    {
        return Err(input_metadata_error());
    }
    Ok(envelope)
}

fn decode_input(columns: &[Value]) -> Result<SourceFactsInput, SourceFactsReadError> {
    if columns.len() != 31 {
        return Err(input_metadata_error());
    }
    let input_key = required_digest(&columns[0])?;
    let identity_tuple = decode_identity_tuple(&columns[1])?;
    if Sha256Digest::of(blob(&columns[1])?) != input_key {
        return Err(input_metadata_error());
    }
    let source_id = text(&columns[2])?.to_string();
    let identity_namespace = text(&columns[3])?.to_string();
    let connector = text(&columns[4])?.to_string();
    let origin_host = optional_string(&columns[5])?;
    let origin_source_version = optional_string(&columns[6])?;
    let role = optional_blob(&columns[7])?
        .map(|bytes| String::from_utf8(bytes.to_vec()).map_err(|_| input_metadata_error()))
        .transpose()?;
    let platform = optional_blob(&columns[8])?
        .map(|bytes| String::from_utf8(bytes.to_vec()).map_err(|_| input_metadata_error()))
        .transpose()?;
    let root_id =
        String::from_utf8(blob(&columns[9])?.to_vec()).map_err(|_| input_metadata_error())?;
    let relative_locator =
        String::from_utf8(blob(&columns[10])?.to_vec()).map_err(|_| input_metadata_error())?;
    let discovery =
        LosslessSourceValue::parse(blob(&columns[11])?).map_err(|_| input_metadata_error())?;
    let parser_context =
        LosslessSourceValue::parse(blob(&columns[12])?).map_err(|_| input_metadata_error())?;
    let context_digest = required_digest(&columns[13])?;
    let sealed_ref =
        LosslessSourceValue::parse(blob(&columns[14])?).map_err(|_| input_metadata_error())?;
    let sealed_sha256 = required_digest(&columns[15])?;
    let byte_len = ordinal_blob(&columns[16])?;
    let format = match text(&columns[17])? {
        "jsonl" => SourceFormat::Jsonl,
        "json_document" => SourceFormat::JsonDocument,
        _ => return Err(input_metadata_error()),
    };
    let manifest_bytes = blob(&columns[18])?;
    let (manifest, safety) =
        decode_expected_manifest_header(manifest_bytes).map_err(|_| input_metadata_error())?;
    let normalizer_id = text(&columns[19])?.to_string();
    let safety_contract_id = text(&columns[20])?.to_string();
    let state = text(&columns[21])?.to_string();
    let expected_records = ordinal_blob(&columns[22])?;
    let expected_blank_lines = ordinal_blob(&columns[23])?;
    let observed_records = optional_ordinal(&columns[24])?;
    let observed_blank_lines = optional_ordinal(&columns[25])?;
    let unprocessed_ranges = match optional_blob(&columns[26])? {
        Some(bytes) => Some(decode_unprocessed_ranges(bytes)?),
        None => None,
    };
    let attempt_history = match optional_blob(&columns[27])? {
        Some(bytes) => Some(read_attempt_history(Some(bytes)).map_err(|_| input_metadata_error())?),
        None => None,
    };
    let activation_request_hash = optional_digest(&columns[28])?;
    let receipt_key = optional_text(&columns[29])?;
    let applied_content_generation = optional_text(&columns[30])?;

    // Identity cross-checks: every duplicated field agrees with the tuple.
    let tuple = &identity_tuple;
    if tuple[0].as_deref() != Some("cass.source-input/2")
        || tuple[1].as_deref() != Some(identity_namespace.as_str())
        || tuple[2].as_deref() != Some(source_id.as_str())
        || tuple[3].as_deref() != Some(connector.as_str())
        || tuple[4].as_deref() != Some(root_id.as_str())
        || tuple[5].as_deref() != Some(relative_locator.as_str())
        || tuple[6] != role
        || tuple[8] != origin_host
        || tuple[9] != origin_source_version
        || tuple[10] != platform
        || tuple[11].as_deref() != Some(context_digest.hex().as_str())
        || tuple[12].as_deref() != Some(sealed_sha256.hex().as_str())
        || tuple[13].as_deref() != Some(normalizer_id.as_str())
        || tuple[14].as_deref() != Some(safety_contract_id.as_str())
    {
        return Err(input_metadata_error());
    }
    let origin_kind = tuple[7].clone();
    let recomputed_context =
        super::context_digest(&parser_context).map_err(|_| input_metadata_error())?;
    if recomputed_context != context_digest {
        return Err(input_metadata_error());
    }
    if manifest.sealed_sha256() != &sealed_sha256
        || manifest.byte_len() != byte_len
        || manifest.format() != format
        || manifest.records() != expected_records
        || manifest.blank_lines() != expected_blank_lines
    {
        return Err(input_metadata_error());
    }

    Ok(SourceFactsInput {
        input_key,
        identity_tuple,
        identity_namespace,
        source_id,
        connector,
        root_id,
        relative_locator,
        origin_kind,
        origin_host,
        origin_source_version,
        role,
        platform,
        discovery,
        parser_context,
        sealed_ref,
        context_digest,
        sealed_sha256,
        byte_len,
        format,
        expected_manifest: SourceFactsExpectedManifest { manifest, safety },
        normalizer_id,
        safety_contract_id,
        state,
        expected_records,
        expected_blank_lines,
        observed_records,
        observed_blank_lines,
        unprocessed_ranges,
        attempt_history,
        activation_request_hash,
        receipt_key,
        applied_content_generation,
    })
}

/// SHA-256 of the compact canonical header-snapshot tuple: the domain followed
/// by 31 `[column, type_tag, value]` triples. BLOB bytes are lower-case hex,
/// TEXT is the original string and NULL is JSON null; any other SQL type is a
/// refusal.
fn header_snapshot_digest(columns: &[Value]) -> Result<Sha256Digest, SourceFactsReadError> {
    if columns.len() != INPUT_SNAPSHOT_COLUMNS.len() {
        return Err(input_metadata_error());
    }
    let mut root = CanonicalTuple::new();
    root.str(INPUT_HEADER_SNAPSHOT_DOMAIN);
    for (name, value) in INPUT_SNAPSHOT_COLUMNS.iter().zip(columns.iter()) {
        let mut triple = CanonicalTuple::new();
        triple.str(name);
        match value {
            Value::Blob(bytes) => {
                let mut hex = String::with_capacity(bytes.len() * 2);
                for byte in bytes {
                    hex.push_str(&format!("{byte:02x}"));
                }
                triple.str("b").str(&hex);
            }
            Value::Text(text_value) => {
                triple.str("s").str(text_value);
            }
            Value::Null => {
                triple.str("n").null();
            }
            _ => return Err(input_metadata_error()),
        }
        root.raw(&triple.finish());
    }
    Ok(root.finish_sha())
}

// =============================================================================
// Record visibility and decoding
// =============================================================================

fn record_visibility_predicate(scope: SourceFactsScope) -> &'static str {
    match scope {
        SourceFactsScope::Analysis => {
            "r.safety_state = 'preserved' AND EXISTS (SELECT 1 FROM source_message_links l \
             WHERE l.record_id = r.id AND l.authority IN ('canonical', 'standalone'))"
        }
        SourceFactsScope::HistoryUnresolved => {
            "r.safety_state = 'preserved' AND (EXISTS (SELECT 1 FROM source_message_links l \
             WHERE l.record_id = r.id AND l.authority IN ('historical', 'unresolved', 'unmapped')) \
             OR (r.record_mapping_state <> 'claims_pending' AND NOT EXISTS \
             (SELECT 1 FROM source_message_links l WHERE l.record_id = r.id)))"
        }
        SourceFactsScope::AllSource => "1",
    }
}

struct RecordColumns {
    row_id: i64,
    columns: Vec<Value>,
}

/// Exactly one visible record after `after`, or `None` when the input is truly
/// exhausted. The query is fixed-bounded (`LIMIT 1`): the caller's page limits
/// never become a SQL LIMIT, so a huge `max_records` cannot disable bounding.
fn next_visible_record(
    tx: &Tx<'_>,
    scope: SourceFactsScope,
    input_key: &Sha256Digest,
    after: Option<&(u64, String)>,
) -> Result<Option<RecordColumns>, SourceFactsReadError> {
    // The input id is looked up by key so the public DTO never exposes the
    // internal row id.
    let input_id: Option<i64> = tx
        .query_opt_map(
            "SELECT id FROM source_inputs WHERE input_key = ?1",
            &[Value::Blob(input_key.as_bytes().to_vec())],
            |row| row.get_typed(0),
        )
        .map_err(|_| db_error())?;
    let Some(input_id) = input_id else {
        return Err(invalid_cursor("invalid_position"));
    };
    let mut sql = format!(
        "SELECT r.id, r.ordinal, r.record_pointer, r.position_bin, \
         r.expected_source_record_sha256, r.observed_source_record_sha256, r.frame_state, \
         r.parse_state, r.record_mapping_state, r.safety_state, r.retention_state, r.codec, \
         r.payload_bin, r.safe_value_hash, r.native_ids_bin, r.diagnostics_bin \
         FROM source_records r WHERE r.input_id = ?1 AND {} ",
        record_visibility_predicate(scope)
    );
    let mut params = vec![Value::Integer(input_id)];
    if let Some((ordinal, pointer)) = after {
        sql.push_str("AND (r.ordinal > ?2 OR (r.ordinal = ?2 AND r.record_pointer > ?3)) ");
        params.push(Value::Blob(super::u64_be8(*ordinal).to_vec()));
        params.push(Value::Text(pointer.clone()));
    }
    sql.push_str("ORDER BY r.ordinal ASC, r.record_pointer ASC LIMIT 1");

    tx.query_opt_map(&sql, &params, |row| {
        let row_id: i64 = row.get_typed(0)?;
        let mut columns = Vec::with_capacity(15);
        for index in 1..=15 {
            columns.push(row.get_value(index)?);
        }
        Ok(RecordColumns { row_id, columns })
    })
    .map_err(|_| db_error())
}

fn visible_record_exists(
    tx: &Tx<'_>,
    scope: SourceFactsScope,
    input_key: &Sha256Digest,
    ordinal: u64,
    pointer: &str,
) -> Result<bool, SourceFactsReadError> {
    let input_id: Option<i64> = tx
        .query_opt_map(
            "SELECT id FROM source_inputs WHERE input_key = ?1",
            &[Value::Blob(input_key.as_bytes().to_vec())],
            |row| row.get_typed(0),
        )
        .map_err(|_| db_error())?;
    let Some(input_id) = input_id else {
        return Ok(false);
    };
    let sql = format!(
        "SELECT 1 FROM source_records r WHERE r.input_id = ?1 AND r.ordinal = ?2 \
         AND r.record_pointer = ?3 AND {} LIMIT 1",
        record_visibility_predicate(scope)
    );
    let found: Option<i64> = tx
        .query_opt_map(
            &sql,
            &[
                Value::Integer(input_id),
                Value::Blob(super::u64_be8(ordinal).to_vec()),
                Value::Text(pointer.to_string()),
            ],
            |row| row.get_typed(0),
        )
        .map_err(|_| db_error())?;
    Ok(found.is_some())
}

fn has_visible_record_after(
    tx: &Tx<'_>,
    scope: SourceFactsScope,
    input_key: &Sha256Digest,
    after: Option<(u64, &str)>,
) -> Result<bool, SourceFactsReadError> {
    let input_id: Option<i64> = tx
        .query_opt_map(
            "SELECT id FROM source_inputs WHERE input_key = ?1",
            &[Value::Blob(input_key.as_bytes().to_vec())],
            |row| row.get_typed(0),
        )
        .map_err(|_| db_error())?;
    let Some(input_id) = input_id else {
        return Ok(false);
    };
    let mut sql = format!(
        "SELECT 1 FROM source_records r WHERE r.input_id = ?1 AND {} ",
        record_visibility_predicate(scope)
    );
    let mut params = vec![Value::Integer(input_id)];
    if let Some((ordinal, pointer)) = after {
        sql.push_str("AND (r.ordinal > ?2 OR (r.ordinal = ?2 AND r.record_pointer > ?3)) ");
        params.push(Value::Blob(super::u64_be8(ordinal).to_vec()));
        params.push(Value::Text(pointer.to_string()));
    }
    sql.push_str("LIMIT 1");
    let found: Option<i64> = tx
        .query_opt_map(&sql, &params, |row| row.get_typed(0))
        .map_err(|_| db_error())?;
    Ok(found.is_some())
}

/// The byte length of one record row, from its canonical `position_bin`, used
/// for the cross-input byte-budget check before the row is fully decoded.
fn record_length(row: &RecordColumns) -> Result<u64, SourceFactsReadError> {
    let columns = &row.columns;
    if columns.len() != 15 {
        return Err(record_metadata_error());
    }
    let ordinal_bytes = record_col(blob(&columns[0]))?;
    let ordinal_array: [u8; 8] = ordinal_bytes
        .try_into()
        .map_err(|_| record_metadata_error())?;
    let ordinal = u64::from_be_bytes(ordinal_array);
    let record_pointer = record_col(text(&columns[1]))?;
    let locator = decode_position_bin(record_col(blob(&columns[2]))?, ordinal, record_pointer)
        .map_err(|_| record_metadata_error())?;
    locator
        .byte_end
        .checked_sub(locator.byte_start)
        .ok_or_else(record_metadata_error)
}

fn decode_record(
    tx: &Tx<'_>,
    input_key: &Sha256Digest,
    row: &RecordColumns,
) -> Result<RawSourceFactsRecord, SourceFactsReadError> {
    let columns = &row.columns;
    if columns.len() != 15 {
        return Err(record_metadata_error());
    }
    let ordinal_bytes = record_col(blob(&columns[0]))?;
    let ordinal_array: [u8; 8] = ordinal_bytes
        .try_into()
        .map_err(|_| record_metadata_error())?;
    let ordinal = u64::from_be_bytes(ordinal_array);
    let record_pointer = record_col(text(&columns[1]))?.to_string();
    let locator = decode_position_bin(record_col(blob(&columns[2]))?, ordinal, &record_pointer)
        .map_err(|_| record_metadata_error())?;
    let record_byte_len = locator
        .byte_end
        .checked_sub(locator.byte_start)
        .ok_or_else(record_metadata_error)?;
    let expected_source_record_sha256 =
        digest_from_bytes(record_col(blob(&columns[3]))?).ok_or_else(record_metadata_error)?;
    let observed_source_record_sha256 = match record_col(optional_blob(&columns[4]))? {
        Some(bytes) => Some(digest_from_bytes(bytes).ok_or_else(record_metadata_error)?),
        None => None,
    };
    let frame_state = record_col(text(&columns[5]))?.to_string();
    let parse_state = record_col(text(&columns[6]))?.to_string();
    let record_mapping_state = record_col(text(&columns[7]))?.to_string();
    let safety_state = record_col(text(&columns[8]))?.to_string();
    let retention_state = record_col(text(&columns[9]))?.to_string();
    let codec = record_col(optional_text(&columns[10]))?;
    let payload = record_col(optional_blob(&columns[11]))?.map(<[u8]>::to_vec);
    let stored_safe_hash = record_col(optional_digest(&columns[12]))?;
    let native_ids = record_col(optional_blob(&columns[13]))?
        .map(|bytes| LosslessSourceValue::parse(bytes).map_err(|_| record_metadata_error()))
        .transpose()?;
    let diagnostics = record_col(optional_blob(&columns[14]))?
        .map(|bytes| super::decode_diagnostics(bytes).map_err(|_| record_metadata_error()))
        .transpose()?;

    let mut payload_sha256 = None;
    let mut safe_value = None;
    match &payload {
        Some(bytes) => {
            match codec.as_deref() {
                Some(SAFE_SOURCE_CODEC_ID) => {}
                Some(_) => return Err(codec_error("unsupported")),
                None => return Err(codec_error("none")),
            }
            let decoded =
                decode_safe_source(bytes).map_err(|_| codec_error(SAFE_SOURCE_CODEC_ID))?;
            let tree = decoded.value().clone();
            let recomputed =
                safe_value_sha256(&tree).map_err(|_| codec_error(SAFE_SOURCE_CODEC_ID))?;
            if let Some(stored) = stored_safe_hash {
                if stored != recomputed {
                    return Err(safe_hash_error());
                }
            }
            payload_sha256 = Some(Sha256Digest::of(bytes));
            safe_value = Some(tree);
        }
        None => {
            if stored_safe_hash.is_some() || codec.is_some() {
                return Err(record_metadata_error());
            }
        }
    }

    let links = decode_record_links(tx, input_key, row.row_id, ordinal, &record_pointer)?;

    Ok(RawSourceFactsRecord {
        input_key: *input_key,
        ordinal,
        record_pointer,
        byte_start: locator.byte_start,
        byte_end: locator.byte_end,
        record_byte_len,
        expected_source_record_sha256,
        observed_source_record_sha256,
        frame_state,
        parse_state,
        record_mapping_state,
        safety_state,
        retention_state,
        codec,
        payload,
        payload_sha256,
        safe_value_hash: stored_safe_hash,
        safe_value,
        native_ids,
        diagnostics,
        links,
    })
}

fn decode_record_links(
    tx: &Tx<'_>,
    input_key: &Sha256Digest,
    record_id: i64,
    ordinal: u64,
    record_pointer: &str,
) -> Result<Vec<SourceFactsRecordLink>, SourceFactsReadError> {
    // The query and the row-type decoding are deliberately separate: a real
    // SQL/IO failure is `db_error`, while a column whose stored type is wrong
    // is damaged link evidence (`invalid_link_evidence`). Each row is read as
    // raw `Value`s first so a type mismatch is caught here, not turned into a
    // database failure by a typed getter.
    let rows: Vec<Vec<Value>> = tx
        .query_all_map(
            "SELECT projection_key, binding_digest, source_positions_bin, authority, message_id, \
             conversation_ordinal, final_message_idx, projection_pointer, evidence_kind \
             FROM source_message_links WHERE record_id = ?1 ORDER BY projection_key ASC",
            &[Value::Integer(record_id)],
            |row| {
                let mut columns = Vec::with_capacity(9);
                for index in 0..9 {
                    columns.push(row.get_value(index)?);
                }
                Ok(columns)
            },
        )
        .map_err(|_| db_error())?;

    let mut links = Vec::with_capacity(rows.len());
    for raw in rows {
        let link_damage = || link_evidence_error().with_pointer(record_pointer);
        let projection_key = match &raw[0] {
            Value::Blob(bytes) => bytes.clone(),
            _ => return Err(link_damage()),
        };
        let digest = match &raw[1] {
            Value::Blob(bytes) => bytes.clone(),
            _ => return Err(link_damage()),
        };
        let positions = match &raw[2] {
            Value::Blob(bytes) => bytes.clone(),
            _ => return Err(link_damage()),
        };
        let authority = match &raw[3] {
            Value::Text(text) => Some(text.clone()),
            Value::Null => None,
            _ => return Err(link_damage()),
        };
        let message_id = match &raw[4] {
            Value::Integer(value) => Some(*value),
            Value::Null => None,
            _ => return Err(link_damage()),
        };
        let conversation_ordinal = match &raw[5] {
            Value::Integer(value) => Some(*value),
            Value::Null => None,
            _ => return Err(link_damage()),
        };
        let final_message_idx = match &raw[6] {
            Value::Integer(value) => Some(*value),
            Value::Null => None,
            _ => return Err(link_damage()),
        };
        let projection_pointer = match &raw[7] {
            Value::Text(text) => Some(text.clone()),
            Value::Null => None,
            _ => return Err(link_damage()),
        };
        let evidence_kind = match &raw[8] {
            Value::Text(text) => text.clone(),
            _ => return Err(link_damage()),
        };

        let evidence = super::decode_stored_link_row(
            tx,
            &StoredLinkRow {
                digest: digest.clone(),
                positions,
                authority: authority.clone(),
                message_id,
                conversation_ordinal,
                final_message_idx,
                projection_pointer,
                evidence_kind,
            },
        )
        .map_err(|_| link_damage())?;
        if evidence.claim.input_key != *input_key
            || evidence.claim.record_ordinal != ordinal
            || evidence.claim.record_pointer != record_pointer
            || projection_key != evidence.claim.projection_key().as_bytes().to_vec()
        {
            return Err(link_damage());
        }
        let binding_digest = digest_from_bytes(&digest).ok_or_else(link_evidence_error)?;
        links.push(SourceFactsRecordLink {
            claim: evidence.claim,
            original_installation: evidence.installation,
            binding_digest,
            authority,
            message_id,
        });
    }
    Ok(links)
}
