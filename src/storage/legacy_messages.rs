//! Explicit, library-level read-only adapter for legacy schema-7/8 archives
//! (PRX source-carrier contract v0.4 §4; ticket SRC05C-01).
//!
//! The current binary is rebuild-only on both sides of its schema version:
//! [`crate::storage::sqlite::SqliteStorage::open_readonly`] refuses a
//! pre-schema-9 archive with `SchemaRebuildRequired` and a newer one with
//! `ReadonlySchemaNewerThanBinary`, and [`crate::storage::schema::ensure`]
//! refuses anything below [`crate::storage::schema::CURRENT_SCHEMA_VERSION`].
//! Those refusals stay exactly as they are; this module does not relax them
//! and adds no CLI fallback.
//!
//! What it adds is the one escape hatch §4 names: a database-level function
//! that a caller must invoke explicitly, and that reads the *message* view of
//! a schema-7/8 archive — the `messages` row and its raw `extra_bin` /
//! `extra_json` columns — through a private read-only connection. It never
//! migrates, never writes `meta`, never creates a table, and never claims the
//! archive carries source facts: [`LegacyMessageReader::read_source_facts`]
//! always fails with the stable `source_facts_unavailable` code, including on
//! an archive with zero messages.
//!
//! Version authority is `PRAGMA user_version`, the marker the schema-7/8 code
//! itself wrote (`storage::schema::ensure` → `set_user_version_sql`) and the
//! one every current read-only gate consults. The `meta.schema_version` key is
//! the retired legacy-engine mirror, not the version this adapter trusts, and
//! the reader never reads it to decide anything.

use std::fmt;
use std::path::Path;

use crate::storage::api::{Conn, StorageError, Value as SqlValue};

/// Lowest legacy schema version this adapter accepts (frontier of the frozen
/// reference contract, PRX v0.4 §4: "schema7/8之外的旧版拒绝").
pub const LEGACY_SCHEMA_MIN: i64 = 7;

/// Highest legacy schema version this adapter accepts.
pub const LEGACY_SCHEMA_MAX: i64 = 8;

/// Stable code: the file could not be opened for reading.
pub const CODE_DB_OPEN_FAILED: &str = "legacy_db_open_failed";
/// Stable code: the file is not a readable SQLite database.
pub const CODE_DB_INVALID: &str = "legacy_db_invalid";
/// Stable code: no usable schema version marker.
pub const CODE_SCHEMA_VERSION_MISSING: &str = "legacy_schema_version_missing";
/// Stable code: a version marker outside the accepted legacy range.
pub const CODE_SCHEMA_VERSION_UNSUPPORTED: &str = "legacy_schema_version_unsupported";
/// Stable code: a required table or column is absent.
pub const CODE_SCHEMA_SHAPE_INVALID: &str = "legacy_schema_shape_invalid";
/// Stable code: reading the message view failed.
pub const CODE_QUERY_FAILED: &str = "legacy_query_failed";
/// Stable code: an explicit `extra` decode failed.
pub const CODE_EXTRA_DECODE_FAILED: &str = "legacy_extra_decode_failed";
/// Stable code: source facts are never available through this adapter
/// (PRX v0.4 §4 — the legacy handle must not invent source facts).
pub const CODE_SOURCE_FACTS_UNAVAILABLE: &str = "source_facts_unavailable";

/// Coarse classification of an open failure.
///
/// This is the only failure detail the adapter keeps. The underlying engine
/// message is deliberately discarded: it can carry the absolute path and raw
/// bytes, and this error type must not (PRX v0.4 §8's "错误只含稳定码、版本数/
/// 消息ID/字段名及必要ErrorKind").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyIoKind {
    /// No file at the requested path.
    NotFound,
    /// The path exists but reading it is not permitted.
    PermissionDenied,
    /// Anything else.
    Other,
}

impl LegacyIoKind {
    /// Stable wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::PermissionDenied => "permission_denied",
            Self::Other => "other",
        }
    }
}

/// Failure of the legacy read-only adapter.
///
/// Every field is a stable code, a version number, a message id, a static
/// schema field name, or a coarse I/O kind — nothing else. In particular no
/// variant can carry a filesystem path, message content, an `extra` payload,
/// a raw SQL value or an underlying engine message, so the derived [`fmt::Debug`]
/// cannot leak them either. Callers must treat the *content* returned by
/// [`LegacyMessageReader::fetch_messages`] with the same care: being readable
/// is not permission to write it to a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyReadError {
    /// The database file could not be opened for reading.
    OpenFailed { kind: LegacyIoKind },
    /// The file exists but is not a readable SQLite database.
    NotADatabase,
    /// The archive carries no usable schema version marker.
    VersionMissing,
    /// The archive's schema version is outside the accepted legacy range.
    VersionUnsupported { found: i64 },
    /// A required legacy table or column is absent.
    ShapeInvalid { field: &'static str },
    /// Reading the message view failed.
    QueryFailed { message_id: Option<i64> },
    /// An explicit `extra` decode failed.
    ExtraDecodeFailed { message_id: i64, column: &'static str },
    /// Source facts are unavailable through a legacy read-only handle.
    SourceFactsUnavailable,
}

impl LegacyReadError {
    /// Stable machine-readable code for this failure.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::OpenFailed { .. } => CODE_DB_OPEN_FAILED,
            Self::NotADatabase => CODE_DB_INVALID,
            Self::VersionMissing => CODE_SCHEMA_VERSION_MISSING,
            Self::VersionUnsupported { .. } => CODE_SCHEMA_VERSION_UNSUPPORTED,
            Self::ShapeInvalid { .. } => CODE_SCHEMA_SHAPE_INVALID,
            Self::QueryFailed { .. } => CODE_QUERY_FAILED,
            Self::ExtraDecodeFailed { .. } => CODE_EXTRA_DECODE_FAILED,
            Self::SourceFactsUnavailable => CODE_SOURCE_FACTS_UNAVAILABLE,
        }
    }
}

impl fmt::Display for LegacyReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenFailed { kind } => {
                write!(f, "legacy archive could not be opened for reading ({})", kind.as_str())
            }
            Self::NotADatabase => write!(f, "legacy archive file is not a readable SQLite database"),
            Self::VersionMissing => write!(f, "legacy archive has no schema version marker"),
            Self::VersionUnsupported { found } => {
                write!(f, "legacy archive schema version {found} is not supported")
            }
            Self::ShapeInvalid { field } => {
                write!(f, "legacy archive schema shape is invalid: {field}")
            }
            Self::QueryFailed { message_id: Some(id) } => {
                write!(f, "reading legacy messages failed at message {id}")
            }
            Self::QueryFailed { message_id: None } => write!(f, "reading legacy messages failed"),
            Self::ExtraDecodeFailed { message_id, column } => {
                write!(f, "decoding legacy extra failed for message {message_id} column {column}")
            }
            Self::SourceFactsUnavailable => {
                write!(f, "source facts are unavailable through a legacy read-only archive")
            }
        }
    }
}

impl std::error::Error for LegacyReadError {}

/// One message row read verbatim from a legacy archive.
///
/// Field names mirror the schema-7/8 `messages` columns. `role` is the stored
/// string exactly as written — no `MessageRole` mapping, no re-numbering, no
/// truncation — so an unknown historical role survives the read. The two
/// `extra` columns are exposed as raw storage values (`extra_json` as its
/// original `TEXT`, `extra_bin` as its original bytes) so callers can assert
/// byte fidelity or tell SQL `NULL` apart from a stored JSON `null`. Decoding
/// is a separate, explicit step: [`LegacyMessage::decode_extra`].
///
/// [`fmt::Debug`] is written by hand and reports identifiers, timestamps and
/// lengths only. The values of `role`, `author`, `content` and both `extra`
/// columns — anything that can hold recorded text — are never rendered, so a
/// message can be logged for its shape without logging the conversation. The
/// fields themselves are unchanged and still returned by the read API.
#[derive(Clone, PartialEq)]
pub struct LegacyMessage {
    /// `messages.id`.
    pub id: i64,
    /// `messages.conversation_id`.
    pub conversation_id: i64,
    /// `messages.idx` (not re-numbered).
    pub idx: i64,
    /// `messages.role`, the stored string verbatim.
    pub role: String,
    /// `messages.author`, raw.
    pub author: Option<String>,
    /// `messages.created_at`, raw.
    pub created_at: Option<i64>,
    /// `messages.content`, complete and untruncated.
    pub content: String,
    /// `messages.extra_json` original `TEXT` (`None` is SQL `NULL`).
    pub extra_json: Option<String>,
    /// `messages.extra_bin` original bytes (`None` is SQL `NULL`).
    pub extra_bin: Option<Vec<u8>>,
}

impl fmt::Debug for LegacyMessage {
    /// Shape-only rendering: identifiers, a timestamp and byte/character
    /// lengths. No recorded text reaches the log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacyMessage")
            .field("id", &self.id)
            .field("conversation_id", &self.conversation_id)
            .field("idx", &self.idx)
            .field("role_len", &self.role.chars().count())
            .field("author_len", &self.author.as_deref().map(|a| a.chars().count()))
            .field("created_at", &self.created_at)
            .field("content_len", &self.content.chars().count())
            .field("extra_json_len", &self.extra_json.as_deref().map(|t| t.chars().count()))
            .field("extra_bin_len", &self.extra_bin.as_deref().map(<[u8]>::len))
            .finish()
    }
}

impl LegacyMessage {
    /// Decode this row's preserved `extra` envelope.
    ///
    /// Selection order is the archive's existing rule — non-empty `extra_bin`
    /// (MessagePack) wins, otherwise `extra_json` (`TEXT`), otherwise nothing —
    /// but unlike the compat reader this decode is strict: a non-empty
    /// `extra_bin` that fails to decode is an error and is **not** silently
    /// retried against `extra_json`, and a present-but-unparseable `extra_json`
    /// is an error rather than an empty object. An empty `extra_bin` falls
    /// through to `extra_json` exactly as the existing rule does; a row with
    /// both columns at SQL `NULL` decodes to [`serde_json::Value::Null`].
    ///
    /// # Errors
    /// [`LegacyReadError::ExtraDecodeFailed`] when the selected column holds a
    /// non-empty value this crate cannot decode. The error names the message
    /// id and the column only; the offending bytes and the decoder's own
    /// message are not carried.
    pub fn decode_extra(&self) -> Result<serde_json::Value, LegacyReadError> {
        if let Some(bytes) = self.extra_bin.as_deref().filter(|bytes| !bytes.is_empty()) {
            return rmp_serde::from_slice(bytes).map_err(|_| LegacyReadError::ExtraDecodeFailed {
                message_id: self.id,
                column: "extra_bin",
            });
        }
        if let Some(text) = self.extra_json.as_deref() {
            return serde_json::from_str(text).map_err(|_| LegacyReadError::ExtraDecodeFailed {
                message_id: self.id,
                column: "extra_json",
            });
        }
        Ok(serde_json::Value::Null)
    }
}

/// Read-only handle over a legacy schema-7/8 archive's message view.
///
/// The connection is private and read-only; no accessor returns it, and there
/// is no write, migration or schema-initialization path through this type.
pub struct LegacyMessageReader {
    conn: Conn,
    schema_version: i64,
}

impl fmt::Debug for LegacyMessageReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The connection and the archive path stay private, so the derived
        // shape is not available; report only the accepted version.
        f.debug_struct("LegacyMessageReader")
            .field("schema_version", &self.schema_version)
            .finish_non_exhaustive()
    }
}

impl LegacyMessageReader {
    /// The legacy schema version this handle was opened against (7 or 8).
    #[must_use]
    pub fn schema_version(&self) -> i64 {
        self.schema_version
    }

    /// Read every message of one conversation, ordered by `idx`.
    ///
    /// Rows come back in ascending `idx` order (with `id` as a tiebreak that
    /// the archive's `UNIQUE (conversation_id, idx)` never exercises). Every
    /// field is returned exactly as stored; a conversation with no rows is an
    /// empty vector, not an error.
    ///
    /// # Errors
    /// [`LegacyReadError::QueryFailed`] if the read fails.
    pub fn fetch_messages(&self, conversation_id: i64) -> Result<Vec<LegacyMessage>, LegacyReadError> {
        self.conn
            .query_all_map(
                "SELECT id, conversation_id, idx, role, author, created_at, content, extra_json, extra_bin \
                 FROM messages WHERE conversation_id = ?1 ORDER BY idx ASC, id ASC",
                &[SqlValue::Integer(conversation_id)],
                |row| {
                    Ok(LegacyMessage {
                        id: row.get_typed(0)?,
                        conversation_id: row.get_typed(1)?,
                        idx: row.get_typed(2)?,
                        role: row.get_typed(3)?,
                        author: row.get_typed(4)?,
                        created_at: row.get_typed(5)?,
                        content: row.get_typed(6)?,
                        extra_json: row.get_typed(7)?,
                        extra_bin: row.get_typed(8)?,
                    })
                },
            )
            .map_err(|_| LegacyReadError::QueryFailed { message_id: None })
    }

    /// The legacy adapter's source-fact entry point.
    ///
    /// A schema-7/8 archive has no `source_inputs` / `source_records` /
    /// `source_message_links` rows and this adapter will not fabricate them
    /// (PRX v0.4 §4). The answer is therefore always the same: the stable
    /// `source_facts_unavailable` error, on an empty archive just as much as
    /// on a populated one. It never returns an empty successful result and
    /// never writes.
    ///
    /// # Errors
    /// Always [`LegacyReadError::SourceFactsUnavailable`].
    pub fn read_source_facts(&self) -> Result<(), LegacyReadError> {
        Err(LegacyReadError::SourceFactsUnavailable)
    }
}

/// Open a legacy schema-7/8 archive read-only and prove its shape.
///
/// Explicit-only entry point: nothing in the CLI or the normal open paths
/// calls this, and its existence does not change what
/// [`crate::storage::sqlite::SqliteStorage::open`] or
/// [`crate::storage::sqlite::SqliteStorage::open_readonly`] do with an old
/// archive.
///
/// The check order is: open read-only, read `PRAGMA user_version`, accept
/// exactly 7 or 8, then verify every `messages` column this adapter reads
/// exists. `PRAGMA user_version` is the only version authority: the retired
/// `meta.schema_version` mirror is neither read nor required, so an archive
/// with the right `user_version` but no such `meta` row still opens, and an
/// archive whose `meta` row claims 7 or 8 while `user_version` says 9 is
/// refused on the PRAGMA alone. Source-table presence is never consulted
/// either — a schema-9-shaped archive cannot get in by adding or dropping
/// source objects, and version 9 or later is refused before any shape check
/// runs.
///
/// # Errors
/// See [`LegacyReadError`]; each variant carries a stable [`LegacyReadError::code`].
pub fn read_legacy_messages_ro(path: &Path) -> Result<LegacyMessageReader, LegacyReadError> {
    let conn = Conn::open_read(path).map_err(|_: StorageError| classify_open_failure(path))?;
    let schema_version = read_schema_version(&conn)?;
    if schema_version == 0 {
        return Err(LegacyReadError::VersionMissing);
    }
    if !(LEGACY_SCHEMA_MIN..=LEGACY_SCHEMA_MAX).contains(&schema_version) {
        return Err(LegacyReadError::VersionUnsupported { found: schema_version });
    }
    verify_legacy_shape(&conn)?;
    Ok(LegacyMessageReader { conn, schema_version })
}

fn classify_open_failure(path: &Path) -> LegacyReadError {
    let kind = match std::fs::metadata(path) {
        Ok(_) => LegacyIoKind::Other,
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => LegacyIoKind::NotFound,
            std::io::ErrorKind::PermissionDenied => LegacyIoKind::PermissionDenied,
            _ => LegacyIoKind::Other,
        },
    };
    LegacyReadError::OpenFailed { kind }
}

fn read_schema_version(conn: &Conn) -> Result<i64, LegacyReadError> {
    conn.query_row_map("PRAGMA user_version;", &[], |row| row.get_typed::<i64>(0))
        .map_err(|_| LegacyReadError::NotADatabase)
}

/// Columns [`LegacyMessageReader::fetch_messages`] reads, in DDL order.
const REQUIRED_MESSAGE_COLUMNS: [&str; 9] = [
    "id",
    "conversation_id",
    "idx",
    "role",
    "author",
    "created_at",
    "content",
    "extra_json",
    "extra_bin",
];

fn verify_legacy_shape(conn: &Conn) -> Result<(), LegacyReadError> {
    if !table_exists(conn, "messages")? {
        return Err(LegacyReadError::ShapeInvalid { field: "messages" });
    }
    let columns = conn
        .query_all_map("PRAGMA table_info(messages);", &[], |row| {
            row.get_typed::<String>(1)
        })
        .map_err(|_| LegacyReadError::NotADatabase)?;
    for required in REQUIRED_MESSAGE_COLUMNS {
        if !columns.iter().any(|name| name == required) {
            return Err(LegacyReadError::ShapeInvalid { field: required });
        }
    }
    Ok(())
}

fn table_exists(conn: &Conn, name: &str) -> Result<bool, LegacyReadError> {
    conn.query_opt_map(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        &[SqlValue::Text(name.to_string())],
        |row| row.get_typed::<i64>(0),
    )
    .map(|found| found.is_some())
    .map_err(|_| LegacyReadError::NotADatabase)
}
