//! Fixed-order rerank window snapshots and cursors.
//!
//! A rerank first lookup computes a full ordering of the candidate window
//! (`N` hits) and returns the first page (`K` hits). Every later page must
//! reuse that same ordering instead of re-running retrieval or the rerank
//! model. This module owns the private, reclaimable cache that makes that
//! possible:
//!
//! - [`WindowSnapshot`] is the complete first-lookup result plus the metadata
//!   needed to prove a later page belongs to the same request and the same
//!   index generation.
//! - [`WindowStore`] writes and reads one snapshot per file under
//!   `<data_dir>/cache/rerank-windows/`, private (`0700`/`0600`), atomically
//!   published and bounded by [`WindowPolicy`].
//! - [`page_hits`] and [`next_cursor`] slice the stored ordering without
//!   touching the model, and advance the cursor by the number of hits
//!   actually delivered (a display budget may shrink a page below `K`).
//! - [`capture_index_stamp`] is the cross-process index identity guard: a
//!   persisted DB/WAL file fingerprint plus the active vector generation,
//!   never an in-process value such as `reader_generation`.
//!
//! Error codes are the whole vocabulary a caller may branch on:
//! [`WindowError`] renders only a `snake_case` short code, never a query, a
//! path or a response body. The mapping this module uses:
//!
//! - `InvalidInput` — a caller-supplied snapshot or binding violates the
//!   frozen contract (bad limits, non-finite scores, applied/score mismatch,
//!   duplicate hit identity, a snapshot that is too large for the policy, a
//!   private directory that is not owner-only, or a malformed `load` argument).
//! - `CacheUnavailable` — the private cache cannot be used safely right now
//!   (I/O error, lock busy, unsafe existing permissions, missing data root).
//! - `NotFound` — the cursor names a window file that is not present.
//! - `InvalidCursor` — the cursor itself is malformed, or its offset lies
//!   outside the window it names.
//! - `Corrupt` — the stored bytes, schema, key set or content violate the
//!   frozen window format, or the index identity cannot be established.
//! - `Expired` — the window's own `expires_at_ms` has passed.
//! - `BindingMismatch` — the continuation request differs from the frozen one.
//! - `IndexChanged` — the database or vector generation changed since the
//!   window was written (or changed while it was being fingerprinted).
//!
//! The WAL boundary follows the frozen P04 verdict
//! (`reports/window-stamp-boundary-verdict.md`): "no WAL" and "a zero-length
//! regular WAL" normalise to the same absent state, the SHM file is never part
//! of the identity, and every other DB/WAL field plus the first 32 WAL header
//! bytes are compared strictly.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::types::{
    CallIdentity, ProviderChoice, RerankFailureReason, decode_search_result, encode_search_result,
};
use crate::search::query::{SearchFilters, SearchHit, SearchResult};
use crate::sources::provenance::SourceFilter;

/// The frozen on-disk schema tag for a rerank window file.
pub const WINDOW_SCHEMA: &str = "cass.rerank-window.v1";

/// The frozen cursor payload version. Version 1 is the old `offset`/`limit`
/// cursor this module deliberately does not accept.
const CURSOR_VERSION: u64 = 2;

/// Directory (relative to the data root) that holds this module's windows.
const WINDOW_DIR_RELATIVE: &str = "cache/rerank-windows";

/// Lock file name inside the window directory.
const LOCK_FILE_NAME: &str = ".lock";

/// Prefix for this module's own temporary publish files.
const TEMP_PREFIX: &str = ".tmp-";

/// Bytes copied from a non-empty WAL as its identity header.
const WAL_HEADER_BYTES: usize = 32;

/// Bound used when opening the read-only index connection for a fingerprint.
const INDEX_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

const WINDOW_KEYS: &[&str] = &[
    "schema",
    "created_at_ms",
    "expires_at_ms",
    "request_binding",
    "index_stamp",
    "resolved_filters",
    "result",
    "aggregates",
    "explanation",
    "retrieval_status",
    "rerank",
];

const BINDING_KEYS: &[&str] = &[
    "query",
    "agents",
    "workspaces",
    "roles",
    "source_filter",
    "session_paths",
    "time",
    "mode",
    "vector_search_mode",
    "embedding_model",
    "rrf_limit",
    "rerank_limit",
    "provider",
    "endpoint",
    "aggregate",
    "explain",
    "timeout_ms",
    "daemon",
    "no_daemon",
];

const TIME_KEYS: &[&str] = &["days", "today", "yesterday", "week", "since", "until"];

const RERANK_KEYS: &[&str] = &[
    "requested_provider",
    "requested_model",
    "identity",
    "applied",
    "failure_reason",
    "http_status",
    "scored_count",
    "http_requests",
    "model_requests",
    "duration_ms",
];

const IDENTITY_KEYS: &[&str] = &["actual_provider", "actual_model", "serving_provider"];

const STAMP_KEYS: &[&str] = &["db_path", "schema_version", "db_file", "wal", "vector"];

const FILE_IDENTITY_KEYS: &[&str] = &["dev", "inode", "len", "mtime_ns"];

const WAL_IDENTITY_KEYS: &[&str] = &["file", "header32"];

const VECTOR_IDENTITY_KEYS: &[&str] = &[
    "generation_id",
    "dim",
    "fingerprint",
    "revision",
    "instance_id",
];

const CURSOR_KEYS: &[&str] = &["version", "window_id", "offset"];

/// Every failure this module can report, as an enumerable short code.
///
/// The `Display` output is the short code and nothing else: no query text, no
/// path and no response body can leak through an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    /// A caller-supplied snapshot, binding or argument broke the contract.
    InvalidInput,
    /// The private cache cannot be used safely right now.
    CacheUnavailable,
    /// The requested window file does not exist.
    NotFound,
    /// The cursor is malformed or points outside its window.
    InvalidCursor,
    /// The stored bytes, schema, keys or content are not valid.
    Corrupt,
    /// The window's own expiry has passed.
    Expired,
    /// The continuation request differs from the frozen request.
    BindingMismatch,
    /// The database or vector generation changed since the window was written.
    IndexChanged,
}

impl WindowError {
    /// The frozen short code used on every surface.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::CacheUnavailable => "cache_unavailable",
            Self::NotFound => "not_found",
            Self::InvalidCursor => "invalid_cursor",
            Self::Corrupt => "corrupt",
            Self::Expired => "expired",
            Self::BindingMismatch => "binding_mismatch",
            Self::IndexChanged => "index_changed",
        }
    }
}

impl std::fmt::Display for WindowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for WindowError {}

/// Retention and size policy for the private window cache.
///
/// Every value must be non-zero, one window may not exceed the total budget,
/// and the arithmetic used to enforce the budget must be representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowPolicy {
    /// Lifetime of a window in milliseconds.
    pub ttl_ms: u64,
    /// Maximum number of window files kept.
    pub max_windows: usize,
    /// Maximum total bytes across this module's window files.
    pub max_total_bytes: u64,
    /// Maximum size of a single window file.
    pub max_window_bytes: u64,
}

impl Default for WindowPolicy {
    fn default() -> Self {
        Self {
            ttl_ms: 3_600_000,
            max_windows: 128,
            max_total_bytes: 536_870_912,
            max_window_bytes: 67_108_864,
        }
    }
}

impl WindowPolicy {
    /// Reject a policy whose bounds cannot be enforced.
    pub fn validate(&self) -> Result<(), WindowError> {
        if self.ttl_ms == 0
            || self.max_windows == 0
            || self.max_total_bytes == 0
            || self.max_window_bytes == 0
        {
            return Err(WindowError::InvalidInput);
        }
        if self.max_window_bytes > self.max_total_bytes {
            return Err(WindowError::InvalidInput);
        }
        // The budget arithmetic must not overflow: the ttl must fit the signed
        // expiry domain, and the window count times the per-window cap must be
        // representable so the accounting below can never wrap.
        i64::try_from(self.ttl_ms).map_err(|_| WindowError::InvalidInput)?;
        (self.max_windows as u64)
            .checked_mul(self.max_window_bytes)
            .ok_or(WindowError::InvalidInput)?;
        self.max_total_bytes
            .checked_add(self.max_window_bytes)
            .ok_or(WindowError::InvalidInput)?;
        Ok(())
    }
}

/// The user's original relative-time selection, kept verbatim so a later page
/// never re-resolves it against the current clock.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeSelectors {
    pub days: Option<u32>,
    pub today: bool,
    pub yesterday: bool,
    pub week: bool,
    pub since: Option<String>,
    pub until: Option<String>,
}

/// The frozen request identity of the first lookup.
///
/// Collection-valued fields are compared order-insensitively by
/// [`RequestBinding::normalized`]; `query`, the time selectors and every other
/// scalar stay byte-for-byte as the user supplied them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestBinding {
    pub query: String,
    pub agents: Vec<String>,
    pub workspaces: Vec<String>,
    pub roles: Option<Vec<u8>>,
    pub source_filter: SourceFilter,
    pub session_paths: Vec<String>,
    pub time: TimeSelectors,
    pub mode: String,
    pub vector_search_mode: String,
    pub embedding_model: Option<String>,
    pub rrf_limit: usize,
    pub rerank_limit: usize,
    pub provider: ProviderChoice,
    pub endpoint: String,
    pub aggregate: Option<Vec<String>>,
    pub explain: bool,
    pub timeout_ms: Option<u64>,
    pub daemon: bool,
    pub no_daemon: bool,
}

impl RequestBinding {
    /// Normalise this binding to its canonical comparison form.
    ///
    /// Only the collection-valued fields are sorted and deduplicated; the
    /// query, the time selectors, the aggregate projection order and every
    /// scalar are preserved exactly. The endpoint is reduced to its canonical
    /// `http`/`https` origin. The scalar contract (mode, vector mode, the
    /// `N`/`K` limits) is validated here, so a caller can never freeze an
    /// unreachable request.
    pub fn normalized(&self) -> Result<Self, WindowError> {
        let mut out = self.clone();
        sort_dedup(&mut out.agents);
        sort_dedup(&mut out.workspaces);
        sort_dedup(&mut out.session_paths);
        if let Some(roles) = out.roles.as_mut() {
            roles.sort_unstable();
            roles.dedup();
        }

        match out.mode.as_str() {
            "lexical" | "semantic" | "hybrid" => {}
            _ => return Err(WindowError::InvalidInput),
        }
        match out.vector_search_mode.as_str() {
            "exact" | "fast" => {}
            _ => return Err(WindowError::InvalidInput),
        }
        if out.rrf_limit == 0 || out.rerank_limit == 0 || out.rerank_limit > out.rrf_limit {
            return Err(WindowError::InvalidInput);
        }

        out.endpoint = normalize_endpoint(&out.endpoint)?;
        Ok(out)
    }
}

/// Identity and completeness evidence of the rerank call that produced the
/// window's ordering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowRerankMeta {
    pub requested_provider: ProviderChoice,
    pub requested_model: String,
    pub identity: CallIdentity,
    pub applied: bool,
    pub failure_reason: Option<RerankFailureReason>,
    pub http_status: Option<u16>,
    pub scored_count: usize,
    /// Every HTTP request the first lookup made, including readiness probes.
    /// `None` when a failure happened before the count could be proven.
    pub http_requests: Option<usize>,
    /// Scoring requests only; `None` when not provable.
    pub model_requests: Option<usize>,
    pub duration_ms: u64,
}

/// Fingerprint of one regular file, at nanosecond mtime precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentity {
    pub dev: u64,
    pub inode: u64,
    pub len: u64,
    pub mtime_ns: i64,
}

/// A non-empty WAL file: its own file identity plus its first 32 header bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalIdentity {
    pub file: FileIdentity,
    pub header32: Vec<u8>,
}

/// The persisted vector generation, copied out of the storage layer so this
/// module never depends on storage types on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorIdentity {
    pub generation_id: i64,
    pub dim: i64,
    pub fingerprint: Vec<u8>,
    pub revision: i64,
    pub instance_id: String,
}

/// Cross-process index identity.
///
/// It is a cache-invalidation guard over ordinary SQLite writes and file
/// replacement, not a content hash of a large corpus. It never carries an
/// in-process value (`reader_generation`) or `PRAGMA data_version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexStamp {
    /// Canonical absolute database path.
    pub db_path: String,
    /// `PRAGMA user_version` read from the index.
    pub schema_version: i64,
    pub db_file: FileIdentity,
    /// `None` both when there is no WAL and when the WAL is a zero-length
    /// regular file; both normalise to the same absent state.
    pub wal: Option<WalIdentity>,
    /// The active generation's persisted snapshot, when one exists.
    pub vector: Option<VectorIdentity>,
}

/// The complete first-lookup result, frozen for later pages.
#[derive(Debug, Clone)]
pub struct WindowSnapshot {
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub request_binding: RequestBinding,
    pub index_stamp: IndexStamp,
    /// The first lookup's resolved absolute filters. Later pages reuse these
    /// instead of re-resolving the relative selectors against the clock.
    pub resolved_filters: SearchFilters,
    pub result: SearchResult,
    pub aggregates: Option<Value>,
    pub explanation: Option<Value>,
    pub retrieval_status: Value,
    pub rerank: WindowRerankMeta,
}

/// The private window cache rooted at `<data_dir>/cache/rerank-windows/`.
#[derive(Debug, Clone)]
pub struct WindowStore {
    dir: PathBuf,
    policy: WindowPolicy,
}

impl WindowStore {
    /// Open (creating if needed) the private window directory under
    /// `data_dir`, refusing any unsafe existing path.
    pub fn new(data_dir: &Path, policy: WindowPolicy) -> Result<Self, WindowError> {
        policy.validate()?;

        let root = fs::canonicalize(data_dir).map_err(|_| WindowError::CacheUnavailable)?;
        let cache = root.join("cache");
        ensure_dir(&cache, /* require_private */ false)?;
        let dir = cache.join("rerank-windows");
        ensure_dir(&dir, /* require_private */ true)?;

        Ok(Self { dir, policy })
    }

    /// The policy this store was built with.
    pub fn policy(&self) -> WindowPolicy {
        self.policy
    }

    /// Publish `snapshot` and return its 64-hex window id.
    ///
    /// The id is the SHA-256 of the exact bytes written to disk. The file is
    /// serialized within `max_window_bytes`, written to a private temporary
    /// file, fsynced and atomically renamed, all under the directory lock.
    pub fn save(&self, snapshot: &WindowSnapshot, now_ms: i64) -> Result<String, WindowError> {
        let binding = snapshot.request_binding.normalized()?;
        validate_snapshot(snapshot, &binding, self.policy, now_ms)?;

        let value = snapshot_to_json(snapshot, &binding)?;
        let bytes = serialize_bounded(&value, self.policy.max_window_bytes)?;
        let len = bytes.len() as u64;
        if len > self.policy.max_total_bytes {
            // A single window that cannot fit even an empty cache is a
            // contract violation, not a capacity race.
            return Err(WindowError::InvalidInput);
        }

        let id = sha256_hex(&bytes);
        let final_name = format!("{id}.json");

        self.with_lock(|| {
            self.prune_to_fit(now_ms, &final_name, len)?;
            self.write_atomic(&final_name, &bytes)
        })?;

        Ok(id)
    }

    /// Load the window named by `cursor`, proving it belongs to the same
    /// request and the same index generation.
    ///
    /// Returns the snapshot and the cursor's starting offset. It never
    /// re-searches, never calls a model and never repairs a bad window.
    pub fn load(
        &self,
        cursor: &str,
        expected: &RequestBinding,
        db_path: &Path,
        now_ms: i64,
    ) -> Result<(WindowSnapshot, usize), WindowError> {
        let (window_id, offset) = decode_cursor(cursor)?;

        let path = self.dir.join(format!("{window_id}.json"));
        let meta = fs::symlink_metadata(&path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                WindowError::NotFound
            } else {
                WindowError::CacheUnavailable
            }
        })?;
        if !meta.file_type().is_file() {
            return Err(WindowError::Corrupt);
        }
        // An existing window file with unsafe permissions is refused, never
        // used: the private-cache guarantee is a gate, not a creation hint.
        require_private_file_mode(&meta)?;
        if meta.len() > self.policy.max_window_bytes {
            return Err(WindowError::Corrupt);
        }

        let mut buf = Vec::new();
        let cap = self.policy.max_window_bytes.saturating_add(1);
        let mut limited = File::open(&path)
            .map_err(|_| WindowError::Corrupt)?
            .take(cap);
        limited
            .read_to_end(&mut buf)
            .map_err(|_| WindowError::Corrupt)?;
        if buf.len() as u64 > self.policy.max_window_bytes {
            return Err(WindowError::Corrupt);
        }

        // The id is the raw bytes' digest; it must be checked before any
        // decode so a re-serialized file can never pass.
        if sha256_hex(&buf) != window_id {
            return Err(WindowError::Corrupt);
        }

        let value: Value = serde_json::from_slice(&buf).map_err(|_| WindowError::Corrupt)?;
        let snapshot = snapshot_from_json(value)?;

        if now_ms >= snapshot.expires_at_ms {
            return Err(WindowError::Expired);
        }
        if offset >= snapshot.result.hits.len() {
            return Err(WindowError::InvalidCursor);
        }

        let expected = expected.clone().normalized()?;
        let stored = snapshot.request_binding.clone().normalized()?;
        if stored != expected {
            return Err(WindowError::BindingMismatch);
        }

        if capture_index_stamp(db_path)? != snapshot.index_stamp {
            return Err(WindowError::IndexChanged);
        }

        Ok((snapshot, offset))
    }

    fn lock_path(&self) -> PathBuf {
        self.dir.join(LOCK_FILE_NAME)
    }

    /// Run `f` while holding the directory's exclusive lock. A busy lock is a
    /// refusal, never a wait.
    fn with_lock<T>(&self, f: impl FnOnce() -> Result<T, WindowError>) -> Result<T, WindowError> {
        let lock_path = self.lock_path();
        if let Ok(meta) = fs::symlink_metadata(&lock_path) {
            if !meta.file_type().is_file() {
                return Err(WindowError::CacheUnavailable);
            }
            require_private_file_mode(&meta)?;
        }

        let mut opts = OpenOptions::new();
        opts.write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let file = opts
            .open(&lock_path)
            .map_err(|_| WindowError::CacheUnavailable)?;

        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => {}
            Err(_) => return Err(WindowError::CacheUnavailable),
        }

        let result = f();
        let _ = fs2::FileExt::unlock(&file);
        result
    }

    /// Evict expired windows first, then the oldest by `created_at_ms`, until
    /// one more file of `incoming_len` bytes fits the policy.
    fn prune_to_fit(
        &self,
        now_ms: i64,
        incoming_name: &str,
        incoming_len: u64,
    ) -> Result<(), WindowError> {
        let ttl = i64::try_from(self.policy.ttl_ms).map_err(|_| WindowError::InvalidInput)?;

        let mut entries: Vec<WindowEntry> = self
            .scan_windows()?
            .into_iter()
            .filter(|entry| entry.name != incoming_name)
            .collect();

        let mut total: u64 = entries.iter().map(|entry| entry.size).sum();
        let mut count = entries.len();

        // Expired first, then oldest. An unreadable window carries
        // `created_at = i64::MIN`, so it sorts first and is reclaimed.
        entries.sort_by(|a, b| {
            let a_expired = window_expired(a.created_at, ttl, now_ms);
            let b_expired = window_expired(b.created_at, ttl, now_ms);
            b_expired
                .cmp(&a_expired)
                .then_with(|| a.created_at.cmp(&b.created_at))
        });

        let mut index = 0;
        while count + 1 > self.policy.max_windows
            || total.saturating_add(incoming_len) > self.policy.max_total_bytes
        {
            let Some(entry) = entries.get(index) else {
                break;
            };
            fs::remove_file(&entry.path).map_err(|_| WindowError::CacheUnavailable)?;
            total = total.saturating_sub(entry.size);
            count -= 1;
            index += 1;
        }
        Ok(())
    }

    /// List this module's own window files. Symlinks, subdirectories and any
    /// file whose name is not `<64 lower hex>.json` are ignored, so reclaim
    /// never deletes a neighbour.
    fn scan_windows(&self) -> Result<Vec<WindowEntry>, WindowError> {
        let mut out = Vec::new();
        let dir = fs::read_dir(&self.dir).map_err(|_| WindowError::CacheUnavailable)?;
        for entry in dir {
            let entry = entry.map_err(|_| WindowError::CacheUnavailable)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            if !is_window_id(id) {
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if !meta.file_type().is_file() {
                continue;
            }
            let created_at =
                read_created_at(&entry.path(), self.policy.max_window_bytes).unwrap_or(i64::MIN);
            out.push(WindowEntry {
                path: entry.path(),
                name: name.to_string(),
                created_at,
                size: meta.len(),
            });
        }
        Ok(out)
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), WindowError> {
        let final_path = self.dir.join(name);
        let tmp_path = temp_path(&self.dir, name);

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&tmp_path)
            .map_err(|_| WindowError::CacheUnavailable)?;

        let written = file
            .write_all(bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all());
        if written.is_err() {
            drop(file);
            let _ = fs::remove_file(&tmp_path);
            return Err(WindowError::CacheUnavailable);
        }
        drop(file);

        if fs::rename(&tmp_path, &final_path).is_err() {
            let _ = fs::remove_file(&tmp_path);
            return Err(WindowError::CacheUnavailable);
        }

        // The rename must be durable before an id is handed back. A failure
        // here is reported (and therefore yields no id); it is not rolled
        // back, so the published file is simply left in place.
        File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| WindowError::CacheUnavailable)?;
        Ok(())
    }
}

struct WindowEntry {
    path: PathBuf,
    name: String,
    created_at: i64,
    size: u64,
}

/// Slice the window's frozen ordering at `offset`, returning at most `K` hits.
pub fn page_hits(snapshot: &WindowSnapshot, offset: usize) -> Result<Vec<SearchHit>, WindowError> {
    let hits = &snapshot.result.hits;
    if offset > hits.len() {
        return Err(WindowError::InvalidInput);
    }
    let k = snapshot.request_binding.rerank_limit;
    let end = offset.saturating_add(k).min(hits.len());
    Ok(hits[offset..end].to_vec())
}

/// Build the continuation cursor after `delivered` hits were actually handed
/// out at `offset`.
///
/// The next offset advances by the delivered count, not by `K`: a display
/// budget may shorten a page without skipping a window entry. A page that
/// delivered nothing has no continuation, one page can never deliver more
/// than `min(K, remaining)`, and reaching the end yields `None`. Asking for
/// more hits than that cap allows is a refusal, not a silent clamp.
pub fn next_cursor(
    window_id: &str,
    snapshot: &WindowSnapshot,
    offset: usize,
    delivered: usize,
) -> Result<Option<String>, WindowError> {
    if !is_window_id(window_id) {
        return Err(WindowError::InvalidInput);
    }
    let len = snapshot.result.hits.len();
    if offset > len {
        return Err(WindowError::InvalidInput);
    }
    let remaining = len - offset;
    let cap = snapshot.request_binding.rerank_limit.min(remaining);
    if delivered > cap {
        return Err(WindowError::InvalidInput);
    }
    // Zero delivered is not a page: it can never advance the cursor.
    if delivered == 0 {
        return Ok(None);
    }
    let next = offset + delivered;
    if next >= len {
        return Ok(None);
    }
    Ok(Some(encode_cursor(window_id, next)?))
}

/// Capture the cross-process index identity of the database at `db_path`.
///
/// The DB and WAL files must be regular files (a symlink is refused). A fresh
/// read-only connection with a deferred transaction reads the current schema
/// and the active vector generation; nothing is repaired, migrated or
/// checkpointed, and no `data_version`/`immutable` shortcut is used. If the
/// DB or WAL fingerprint changes across that read, the result is
/// [`WindowError::IndexChanged`] rather than a stitched-together stamp.
pub fn capture_index_stamp(db_path: &Path) -> Result<IndexStamp, WindowError> {
    let db_before = file_identity(db_path)?;
    let canonical = fs::canonicalize(db_path).map_err(|_| WindowError::CacheUnavailable)?;
    let wal_path = wal_path_for(db_path);
    let wal_before = wal_identity(&wal_path)?;

    let conn = crate::storage::sqlite::open_franken_raw_readonly_connection_with_timeout(
        db_path,
        INDEX_OPEN_TIMEOUT,
    )
    .map_err(|_| WindowError::Corrupt)?;
    crate::storage::sqlite::ensure_readonly_schema_current(&conn)
        .map_err(|_| WindowError::Corrupt)?;
    let schema_version =
        crate::storage::schema::read_user_version(&conn).map_err(|_| WindowError::Corrupt)?;

    let vector = conn
        .with_tx_no_replay(crate::storage::api::TxMode::Deferred, |tx| {
            let active: Option<i64> = tx.query_opt_map(
                "SELECT id FROM embedding_generations WHERE is_active = 1",
                &[],
                |row| row.get_typed(0),
            )?;
            match active {
                Some(generation_id) => {
                    crate::storage::vector_domain::vector_snapshot_in_tx(tx, generation_id)
                }
                None => Ok(None),
            }
        })
        .map_err(|_| WindowError::Corrupt)?;

    let db_after = file_identity(db_path)?;
    let wal_after = wal_identity(&wal_path)?;
    if db_before != db_after || wal_before != wal_after {
        return Err(WindowError::IndexChanged);
    }

    Ok(IndexStamp {
        db_path: canonical.to_string_lossy().into_owned(),
        schema_version,
        db_file: db_before,
        wal: wal_before,
        vector: vector.map(|snapshot| VectorIdentity {
            generation_id: snapshot.generation_id,
            dim: snapshot.dim,
            fingerprint: snapshot.fingerprint,
            revision: snapshot.revision,
            instance_id: snapshot.instance_id,
        }),
    })
}

// ---------------------------------------------------------------------------
// JSON encoding / decoding
// ---------------------------------------------------------------------------

fn snapshot_to_json(
    snapshot: &WindowSnapshot,
    binding: &RequestBinding,
) -> Result<Value, WindowError> {
    let mut obj = serde_json::Map::new();
    obj.insert("schema".to_string(), Value::from(WINDOW_SCHEMA));
    obj.insert(
        "created_at_ms".to_string(),
        Value::from(snapshot.created_at_ms),
    );
    obj.insert(
        "expires_at_ms".to_string(),
        Value::from(snapshot.expires_at_ms),
    );
    obj.insert(
        "request_binding".to_string(),
        serde_json::to_value(binding).map_err(|_| WindowError::InvalidInput)?,
    );
    obj.insert(
        "index_stamp".to_string(),
        serde_json::to_value(&snapshot.index_stamp).map_err(|_| WindowError::InvalidInput)?,
    );
    obj.insert(
        "resolved_filters".to_string(),
        serde_json::to_value(&snapshot.resolved_filters).map_err(|_| WindowError::InvalidInput)?,
    );
    obj.insert(
        "result".to_string(),
        encode_search_result(&snapshot.result).map_err(|_| WindowError::InvalidInput)?,
    );
    obj.insert(
        "aggregates".to_string(),
        snapshot.aggregates.clone().unwrap_or(Value::Null),
    );
    obj.insert(
        "explanation".to_string(),
        snapshot.explanation.clone().unwrap_or(Value::Null),
    );
    obj.insert(
        "retrieval_status".to_string(),
        snapshot.retrieval_status.clone(),
    );
    obj.insert(
        "rerank".to_string(),
        serde_json::to_value(&snapshot.rerank).map_err(|_| WindowError::InvalidInput)?,
    );
    Ok(Value::Object(obj))
}

fn snapshot_from_json(value: Value) -> Result<WindowSnapshot, WindowError> {
    let obj = value.as_object().ok_or(WindowError::Corrupt)?;
    require_keys(obj, WINDOW_KEYS)?;

    if obj.get("schema").and_then(Value::as_str) != Some(WINDOW_SCHEMA) {
        return Err(WindowError::Corrupt);
    }

    let created_at_ms = obj
        .get("created_at_ms")
        .and_then(Value::as_i64)
        .ok_or(WindowError::Corrupt)?;
    let expires_at_ms = obj
        .get("expires_at_ms")
        .and_then(Value::as_i64)
        .ok_or(WindowError::Corrupt)?;

    let binding_value = obj
        .get("request_binding")
        .cloned()
        .ok_or(WindowError::Corrupt)?;
    let binding_obj = binding_value.as_object().ok_or(WindowError::Corrupt)?;
    require_keys(binding_obj, BINDING_KEYS)?;
    let time_obj = binding_obj
        .get("time")
        .and_then(Value::as_object)
        .ok_or(WindowError::Corrupt)?;
    require_keys(time_obj, TIME_KEYS)?;
    let request_binding: RequestBinding =
        serde_json::from_value(binding_value).map_err(|_| WindowError::Corrupt)?;

    let stamp_value = obj
        .get("index_stamp")
        .cloned()
        .ok_or(WindowError::Corrupt)?;
    validate_stamp_keys(&stamp_value)?;
    let index_stamp: IndexStamp =
        serde_json::from_value(stamp_value).map_err(|_| WindowError::Corrupt)?;

    let resolved_filters: SearchFilters = serde_json::from_value(
        obj.get("resolved_filters")
            .cloned()
            .ok_or(WindowError::Corrupt)?,
    )
    .map_err(|_| WindowError::Corrupt)?;

    let result = decode_search_result(obj.get("result").cloned().ok_or(WindowError::Corrupt)?)
        .map_err(|_| WindowError::Corrupt)?;

    let aggregates = optional_object(obj.get("aggregates").ok_or(WindowError::Corrupt)?)?;
    let explanation = optional_object(obj.get("explanation").ok_or(WindowError::Corrupt)?)?;

    let retrieval_status = obj
        .get("retrieval_status")
        .cloned()
        .ok_or(WindowError::Corrupt)?;
    if !retrieval_status.is_object() {
        return Err(WindowError::Corrupt);
    }

    let rerank_value = obj.get("rerank").cloned().ok_or(WindowError::Corrupt)?;
    let rerank_obj = rerank_value.as_object().ok_or(WindowError::Corrupt)?;
    require_keys(rerank_obj, RERANK_KEYS)?;
    let identity_obj = rerank_obj
        .get("identity")
        .and_then(Value::as_object)
        .ok_or(WindowError::Corrupt)?;
    require_keys(identity_obj, IDENTITY_KEYS)?;
    let rerank: WindowRerankMeta =
        serde_json::from_value(rerank_value).map_err(|_| WindowError::Corrupt)?;

    let snapshot = WindowSnapshot {
        created_at_ms,
        expires_at_ms,
        request_binding,
        index_stamp,
        resolved_filters,
        result,
        aggregates,
        explanation,
        retrieval_status,
        rerank,
    };

    validate_content(
        &snapshot.request_binding,
        &snapshot.result,
        &snapshot.rerank,
    )
    .map_err(|_| WindowError::Corrupt)?;
    if snapshot.expires_at_ms <= snapshot.created_at_ms {
        return Err(WindowError::Corrupt);
    }

    Ok(snapshot)
}

fn validate_stamp_keys(value: &Value) -> Result<(), WindowError> {
    let obj = value.as_object().ok_or(WindowError::Corrupt)?;
    require_keys(obj, STAMP_KEYS)?;

    let db_file = obj.get("db_file").ok_or(WindowError::Corrupt)?;
    require_keys(
        db_file.as_object().ok_or(WindowError::Corrupt)?,
        FILE_IDENTITY_KEYS,
    )?;

    match obj.get("wal").ok_or(WindowError::Corrupt)? {
        Value::Null => {}
        wal => {
            let wal_obj = wal.as_object().ok_or(WindowError::Corrupt)?;
            require_keys(wal_obj, WAL_IDENTITY_KEYS)?;
            require_keys(
                wal_obj
                    .get("file")
                    .and_then(Value::as_object)
                    .ok_or(WindowError::Corrupt)?,
                FILE_IDENTITY_KEYS,
            )?;
        }
    }

    match obj.get("vector").ok_or(WindowError::Corrupt)? {
        Value::Null => {}
        vector => {
            require_keys(
                vector.as_object().ok_or(WindowError::Corrupt)?,
                VECTOR_IDENTITY_KEYS,
            )?;
        }
    }
    Ok(())
}

fn optional_object(value: &Value) -> Result<Option<Value>, WindowError> {
    match value {
        Value::Null => Ok(None),
        other if other.is_object() => Ok(Some(other.clone())),
        _ => Err(WindowError::Corrupt),
    }
}

/// Reject a stored or about-to-be-stored snapshot whose content breaks the
/// frozen contract. Callers map the returned code to their own vocabulary.
fn validate_content(
    binding: &RequestBinding,
    result: &SearchResult,
    rerank: &WindowRerankMeta,
) -> Result<(), WindowError> {
    if result.hits.len() > binding.rrf_limit {
        return Err(WindowError::InvalidInput);
    }

    // Every hit must carry a positive, unique message identity: a fixed
    // window is an identified candidate set, so an absent or duplicated
    // identity cannot be paginated safely.
    let mut seen_ids: BTreeSet<i64> = BTreeSet::new();
    for hit in &result.hits {
        if !hit.score.is_finite() {
            return Err(WindowError::InvalidInput);
        }
        if let Some(score) = hit.rerank_score {
            if !score.is_finite() {
                return Err(WindowError::InvalidInput);
            }
        }
        let id = hit.message_id.ok_or(WindowError::InvalidInput)?;
        if id <= 0 || !seen_ids.insert(id) {
            return Err(WindowError::InvalidInput);
        }
    }

    if let Some(actual) = rerank.identity.actual_provider {
        if actual != rerank.requested_provider {
            return Err(WindowError::InvalidInput);
        }
    }

    if rerank.applied {
        if rerank.scored_count != result.hits.len() || rerank.failure_reason.is_some() {
            return Err(WindowError::InvalidInput);
        }
        for hit in &result.hits {
            match hit.rerank_score {
                Some(score) if score.is_finite() => {}
                _ => return Err(WindowError::InvalidInput),
            }
        }
    } else {
        if rerank.scored_count != 0 {
            return Err(WindowError::InvalidInput);
        }
        for hit in &result.hits {
            if hit.rerank_score.is_some() {
                return Err(WindowError::InvalidInput);
            }
        }
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: &WindowSnapshot,
    binding: &RequestBinding,
    policy: WindowPolicy,
    now_ms: i64,
) -> Result<(), WindowError> {
    validate_content(binding, &snapshot.result, &snapshot.rerank)?;

    if !snapshot.retrieval_status.is_object() {
        return Err(WindowError::InvalidInput);
    }
    if snapshot.aggregates.as_ref().is_some_and(|v| !v.is_object()) {
        return Err(WindowError::InvalidInput);
    }
    if snapshot
        .explanation
        .as_ref()
        .is_some_and(|v| !v.is_object())
    {
        return Err(WindowError::InvalidInput);
    }

    let ttl = i64::try_from(policy.ttl_ms).map_err(|_| WindowError::InvalidInput)?;
    if snapshot.created_at_ms > now_ms || now_ms >= snapshot.expires_at_ms {
        return Err(WindowError::InvalidInput);
    }
    match snapshot.created_at_ms.checked_add(ttl) {
        Some(expected) if expected == snapshot.expires_at_ms => {}
        _ => return Err(WindowError::InvalidInput),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cursor codec
// ---------------------------------------------------------------------------

fn encode_cursor(window_id: &str, offset: usize) -> Result<String, WindowError> {
    use base64::Engine as _;

    if !is_window_id(window_id) {
        return Err(WindowError::InvalidInput);
    }
    let mut obj = serde_json::Map::new();
    obj.insert("version".to_string(), Value::from(CURSOR_VERSION));
    obj.insert("window_id".to_string(), Value::from(window_id));
    obj.insert("offset".to_string(), Value::from(offset as u64));
    let bytes = serde_json::to_vec(&Value::Object(obj)).map_err(|_| WindowError::InvalidInput)?;
    Ok(base64::prelude::BASE64_STANDARD.encode(bytes))
}

fn decode_cursor(cursor: &str) -> Result<(String, usize), WindowError> {
    use base64::Engine as _;

    let bytes = base64::prelude::BASE64_STANDARD
        .decode(cursor)
        .map_err(|_| WindowError::InvalidCursor)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| WindowError::InvalidCursor)?;
    let obj = value.as_object().ok_or(WindowError::InvalidCursor)?;

    if obj.len() != CURSOR_KEYS.len() {
        return Err(WindowError::InvalidCursor);
    }
    require_keys(obj, CURSOR_KEYS).map_err(|_| WindowError::InvalidCursor)?;

    if obj.get("version").and_then(Value::as_u64) != Some(CURSOR_VERSION) {
        return Err(WindowError::InvalidCursor);
    }
    let window_id = obj
        .get("window_id")
        .and_then(Value::as_str)
        .ok_or(WindowError::InvalidCursor)?;
    if !is_window_id(window_id) {
        return Err(WindowError::InvalidCursor);
    }
    let offset = obj
        .get("offset")
        .and_then(Value::as_u64)
        .ok_or(WindowError::InvalidCursor)?;
    let offset = usize::try_from(offset).map_err(|_| WindowError::InvalidCursor)?;

    Ok((window_id.to_string(), offset))
}

fn is_window_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// Filesystem and identity helpers
// ---------------------------------------------------------------------------

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn normalize_endpoint(raw: &str) -> Result<String, WindowError> {
    let url = url::Url::parse(raw).map_err(|_| WindowError::InvalidInput)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(WindowError::InvalidInput);
    }
    // A credential must never reach the binding or the stored file.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(WindowError::InvalidInput);
    }
    let origin = url.origin();
    if !origin.is_tuple() {
        return Err(WindowError::InvalidInput);
    }
    Ok(origin.ascii_serialization())
}

/// Ensure a directory exists. When `require_private` is set the directory
/// must be owner-only (`0700`); a symlink or non-directory is always refused.
/// A shared parent is created `0700` when absent but never modified.
fn ensure_dir(path: &Path, require_private: bool) -> Result<(), WindowError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder
                .create(path)
                .map_err(|_| WindowError::CacheUnavailable)?;
            fs::symlink_metadata(path).map_err(|_| WindowError::CacheUnavailable)?
        }
        Err(_) => return Err(WindowError::CacheUnavailable),
    };
    if !metadata.file_type().is_dir() {
        return Err(WindowError::CacheUnavailable);
    }
    if require_private {
        require_private_dir_mode(&metadata)?;
    }
    Ok(())
}

/// A private directory must already be exactly `0700`. On a platform where
/// the owner-only guarantee cannot be established, this refuses rather than
/// silently continuing.
fn require_private_dir_mode(metadata: &fs::Metadata) -> Result<(), WindowError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(WindowError::CacheUnavailable);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(WindowError::CacheUnavailable)
    }
}

/// A private file must already be exactly `0600`. On a platform where the
/// owner-only guarantee cannot be established, this refuses rather than
/// silently continuing.
fn require_private_file_mode(metadata: &fs::Metadata) -> Result<(), WindowError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(WindowError::CacheUnavailable);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(WindowError::CacheUnavailable)
    }
}

fn file_identity(path: &Path) -> Result<FileIdentity, WindowError> {
    let meta = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            WindowError::NotFound
        } else {
            WindowError::Corrupt
        }
    })?;
    if !meta.file_type().is_file() {
        return Err(WindowError::Corrupt);
    }
    Ok(identity_from_metadata(&meta))
}

fn identity_from_metadata(meta: &fs::Metadata) -> FileIdentity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        FileIdentity {
            dev: meta.dev(),
            inode: meta.ino(),
            len: meta.len(),
            mtime_ns: system_time_to_nanos(meta.modified().ok()),
        }
    }
    #[cfg(not(unix))]
    {
        FileIdentity {
            dev: 0,
            inode: 0,
            len: meta.len(),
            mtime_ns: system_time_to_nanos(meta.modified().ok()),
        }
    }
}

fn system_time_to_nanos(time: Option<SystemTime>) -> i64 {
    let Some(time) = time else { return 0 };
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX),
        Err(err) => {
            let nanos = i64::try_from(err.duration().as_nanos()).unwrap_or(i64::MAX);
            nanos.saturating_neg()
        }
    }
}

fn wal_path_for(db_path: &Path) -> PathBuf {
    let mut raw = db_path.as_os_str().to_os_string();
    raw.push("-wal");
    PathBuf::from(raw)
}

fn wal_identity(path: &Path) -> Result<Option<WalIdentity>, WindowError> {
    let meta = match fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(WindowError::Corrupt),
        Ok(meta) => meta,
    };
    if !meta.file_type().is_file() {
        return Err(WindowError::Corrupt);
    }
    // A zero-length regular WAL is the same absent state as no WAL at all.
    if meta.len() == 0 {
        return Ok(None);
    }
    if meta.len() < WAL_HEADER_BYTES as u64 {
        return Err(WindowError::Corrupt);
    }
    let mut header = [0u8; WAL_HEADER_BYTES];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|_| WindowError::Corrupt)?;
    Ok(Some(WalIdentity {
        file: identity_from_metadata(&meta),
        header32: header.to_vec(),
    }))
}

fn read_created_at(path: &Path, cap: u64) -> Option<i64> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > cap {
        return None;
    }
    let mut buf = Vec::new();
    let mut limited = File::open(path).ok()?.take(cap.saturating_add(1));
    limited.read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > cap {
        return None;
    }
    let value: Value = serde_json::from_slice(&buf).ok()?;
    value.get("created_at_ms")?.as_i64()
}

fn window_expired(created_at: i64, ttl: i64, now_ms: i64) -> bool {
    match created_at.checked_add(ttl) {
        Some(expires) => now_ms >= expires,
        None => true,
    }
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn temp_path(dir: &Path, name: &str) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    dir.join(format!("{TEMP_PREFIX}{name}-{nanos}-{sequence}"))
}

fn require_keys(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Result<(), WindowError> {
    for key in keys {
        if !obj.contains_key(*key) {
            return Err(WindowError::Corrupt);
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A `Write` sink that refuses to grow past `limit` bytes, so a snapshot is
/// never materialized in full before its size is checked.
struct LimitedWriter {
    buf: Vec<u8>,
    limit: usize,
}

impl std::io::Write for LimitedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len().saturating_add(data.len()) > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "rerank window exceeds max_window_bytes",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_bounded(value: &Value, limit: u64) -> Result<Vec<u8>, WindowError> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut writer = LimitedWriter {
        buf: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| WindowError::InvalidInput)?;
    Ok(writer.buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::query::{
        CacheStats, CandidateMeta, CandidateMode, MatchType, SearchHit, SearchResult,
    };
    use crate::storage::api::{Conn, Profile};
    use serde_json::json;
    use std::collections::HashSet;

    const NOW: i64 = 1_700_000_000_000;

    /// The libtest name of the subprocess entrypoint, resolved from the crate
    /// root. `--exact` needs this whole path, not the short function name.
    const CHILD_TEST_NAME: &str = "search::rerank::window::tests::p04_child_entrypoint";

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    fn make_db(dir: &Path) -> PathBuf {
        let db = dir.join("agent_search.db");
        make_db_at(&db, false);
        db
    }

    fn make_db_with_generation(dir: &Path) -> PathBuf {
        let db = dir.join("agent_search.db");
        make_db_at(&db, true);
        db
    }

    fn make_db_at(db: &Path, with_generation: bool) {
        let conn =
            Conn::open_writable(db, Profile::Production).expect("open writable test database");
        crate::storage::schema::ensure(&conn).expect("build current schema");
        if with_generation {
            conn.execute(
                "INSERT INTO embedding_generations \
                 (embedder_id, dim, canonicalize_version, chunking_policy_version, fingerprint, \
                  byte_order, audit_status, is_active, created_at, activated_at, vector_revision) \
                 VALUES ('test-embedder', 4, 1, 1, X'0102', 'le', 'passed', 1, 1, 1, 0)",
                &[],
            )
            .expect("insert active embedding generation");
        }
        drop(conn);
    }

    fn store(dir: &Path) -> WindowStore {
        WindowStore::new(dir, WindowPolicy::default()).expect("open window store")
    }

    fn binding(n: usize, k: usize) -> RequestBinding {
        RequestBinding {
            query: "how do I page a rerank window".to_string(),
            agents: vec![
                "codex".to_string(),
                "claude".to_string(),
                "claude".to_string(),
            ],
            workspaces: vec!["/w/b".to_string(), "/w/a".to_string()],
            roles: Some(vec![2, 1, 2]),
            source_filter: SourceFilter::All,
            session_paths: vec!["/s/b.jsonl".to_string(), "/s/a.jsonl".to_string()],
            time: TimeSelectors {
                days: Some(7),
                today: false,
                yesterday: true,
                week: false,
                since: Some("2026-01-01".to_string()),
                until: None,
            },
            mode: "hybrid".to_string(),
            vector_search_mode: "exact".to_string(),
            embedding_model: Some("bge-m3".to_string()),
            rrf_limit: n,
            rerank_limit: k,
            provider: ProviderChoice::Qwen3Local,
            endpoint: "http://127.0.0.1:8000/v1/rerank?x=1".to_string(),
            aggregate: Some(vec!["agent".to_string(), "workspace".to_string()]),
            explain: true,
            timeout_ms: Some(60_000),
            daemon: false,
            no_daemon: true,
        }
    }

    fn hit(index: usize, score: f32) -> SearchHit {
        let message_id = index as i64 + 1;
        SearchHit {
            title: format!("hit-{index:02}"),
            snippet: format!("snippet {index}"),
            content: format!("content {index}"),
            content_hash: 0xDEAD_BEEF_0000_0000 + message_id as u64,
            conversation_id: Some(1000 + message_id),
            score,
            source_path: format!("/tmp/hit-{index:02}.jsonl"),
            agent: "claude".to_string(),
            workspace: "/w/a".to_string(),
            workspace_original: None,
            created_at: Some(NOW),
            line_number: Some(message_id as usize),
            match_type: MatchType::Exact,
            source_id: "local".to_string(),
            origin_kind: "local".to_string(),
            origin_host: None,
            message_id: Some(message_id),
            winning_chunk_idx: Some(1),
            winning_chunk_span: Some((10, 20)),
            winning_chunk_hash: Some("abc123".to_string()),
            rerank_score: None,
        }
    }

    /// `hits` is how many hits the frozen ordering stores; `n`/`k` are the
    /// bound window and page sizes (so an empty window still has `N >= 1`).
    fn snapshot(
        db: &Path,
        now: i64,
        applied: bool,
        hits: usize,
        n: usize,
        k: usize,
    ) -> WindowSnapshot {
        let binding = binding(n, k);
        let mut ordered = Vec::with_capacity(hits);
        for index in 0..hits {
            let mut entry = hit(index, 100.0 - index as f32);
            if applied {
                entry.rerank_score = Some(0.5 + index as f64);
            }
            ordered.push(entry);
        }

        WindowSnapshot {
            created_at_ms: now,
            expires_at_ms: now + WindowPolicy::default().ttl_ms as i64,
            request_binding: binding,
            index_stamp: capture_index_stamp(db).expect("capture index stamp"),
            resolved_filters: SearchFilters {
                agents: HashSet::from(["claude".to_string()]),
                created_from: Some(now - 86_400_000),
                created_to: Some(now),
                ..Default::default()
            },
            result: SearchResult {
                hits: ordered,
                wildcard_fallback: true,
                cache_stats: CacheStats {
                    cache_hits: 3,
                    eviction_policy: "s3-fifo".to_string(),
                    reader_generation: Some(11),
                    ..Default::default()
                },
                suggestions: Vec::new(),
                total_count: Some(hits),
                candidates: Some(CandidateMeta {
                    mode: CandidateMode::Knn,
                    k: 800,
                    first_round_rows: 812,
                    unique_messages: hits,
                    incomplete: false,
                    reason: None,
                    approximate: true,
                    requested_coarse_k: Some(4096),
                    effective_coarse_k: Some(1024),
                    coarse_cap_hit: Some(true),
                    corpus_limited: Some(false),
                    coarse_shard_count: Some(4),
                    coarse_rows_collected: Some(1024),
                    float_rescore_rows: Some(800),
                    coarse_skip_reason: None,
                }),
                semantic_degraded: false,
            },
            aggregates: Some(json!({"agent": {"claude": hits}})),
            explanation: Some(json!({"rrf": {"k": 60}})),
            retrieval_status: json!({"mode": "hybrid", "partial": false}),
            rerank: WindowRerankMeta {
                requested_provider: ProviderChoice::Qwen3Local,
                requested_model: ProviderChoice::Qwen3Local.request_model().to_string(),
                identity: CallIdentity {
                    actual_provider: Some(ProviderChoice::Qwen3Local),
                    actual_model: Some("Qwen3-Reranker-8B-local".to_string()),
                    serving_provider: None,
                },
                applied,
                failure_reason: if applied {
                    None
                } else {
                    Some(RerankFailureReason::HttpError)
                },
                http_status: if applied { Some(200) } else { Some(503) },
                scored_count: if applied { hits } else { 0 },
                http_requests: if applied { Some(2) } else { None },
                model_requests: if applied { Some(1) } else { None },
                duration_ms: 42,
            },
        }
    }

    fn titles(hits: &[SearchHit]) -> Vec<String> {
        hits.iter().map(|hit| hit.title.clone()).collect()
    }

    fn window_dir(root: &Path) -> PathBuf {
        root.join(WINDOW_DIR_RELATIVE)
    }

    fn save_and_cursor(st: &WindowStore, snap: &WindowSnapshot, offset: usize) -> (String, String) {
        let id = st.save(snap, snap.created_at_ms).expect("save window");
        let cursor = encode_cursor(&id, offset).expect("encode cursor");
        (id, cursor)
    }

    fn read_saved(root: &Path, id: &str) -> Value {
        let bytes = fs::read(window_dir(root).join(format!("{id}.json"))).expect("read window");
        serde_json::from_slice(&bytes).expect("parse window json")
    }

    /// Write a file `0600` so it passes the private-file gate.
    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("tighten to 0600");
        }
    }

    /// Write tampered bytes under their own content hash so the load path
    /// reaches schema/key validation instead of failing the hash check first.
    fn write_tampered(root: &Path, value: &Value) -> String {
        let bytes = serde_json::to_vec(value).expect("serialize tampered window");
        let id = sha256_hex(&bytes);
        write_private(&window_dir(root).join(format!("{id}.json")), &bytes);
        encode_cursor(&id, 0).expect("encode tampered cursor")
    }

    fn raw_cursor(value: Value) -> String {
        use base64::Engine as _;
        base64::prelude::BASE64_STANDARD.encode(serde_json::to_vec(&value).unwrap())
    }

    // ------------------------------------------------------------------
    // C1 - storage round trip and pagination
    // ------------------------------------------------------------------

    #[test]
    fn round_trip_preserves_private_fields_and_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, cursor) = save_and_cursor(&st, &snap, 0);
        assert!(is_window_id(&id));

        let (loaded, offset) = st.load(&cursor, &snap.request_binding, &db, NOW).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(loaded.result.hits.len(), 12);
        assert_eq!(
            loaded.result.hits[0].content_hash,
            snap.result.hits[0].content_hash
        );
        assert_eq!(loaded.result.hits[0].conversation_id, Some(1001));
        assert_eq!(loaded.result.hits[0].rerank_score, Some(0.5));
        assert_eq!(loaded.result.hits[1].rerank_score, Some(1.5));
        assert!(loaded.result.wildcard_fallback);
        assert_eq!(loaded.result.cache_stats.reader_generation, Some(11));
        assert_eq!(loaded.result.cache_stats.eviction_policy, "s3-fifo");

        let candidates = loaded.result.candidates.as_ref().expect("candidates");
        assert_eq!(candidates.mode, CandidateMode::Knn);
        assert_eq!(candidates.effective_coarse_k, Some(1024));
        assert_eq!(candidates.coarse_skip_reason, None);

        assert_eq!(loaded.resolved_filters.created_from, Some(NOW - 86_400_000));
        assert_eq!(loaded.resolved_filters.created_to, Some(NOW));
        assert_eq!(loaded.aggregates, Some(json!({"agent": {"claude": 12}})));
        assert_eq!(loaded.explanation, Some(json!({"rrf": {"k": 60}})));
        assert_eq!(
            loaded.retrieval_status,
            json!({"mode": "hybrid", "partial": false})
        );
        assert_eq!(loaded.rerank.http_requests, Some(2));
        assert_eq!(loaded.rerank.model_requests, Some(1));
        assert_eq!(loaded.rerank.scored_count, 12);
        assert_eq!(loaded.index_stamp, snap.index_stamp);
        assert_eq!(
            titles(&loaded.result.hits),
            (0..12).map(|i| format!("hit-{i:02}")).collect::<Vec<_>>()
        );
    }

    #[test]
    fn round_trip_preserves_null_call_counts_for_failed_window() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, false, 3, 5, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        let (loaded, _) = st.load(&cursor, &snap.request_binding, &db, NOW).unwrap();
        assert!(!loaded.rerank.applied);
        assert_eq!(loaded.rerank.scored_count, 0);
        assert_eq!(loaded.rerank.http_requests, None);
        assert_eq!(loaded.rerank.model_requests, None);
        assert_eq!(
            loaded.rerank.failure_reason,
            Some(RerankFailureReason::HttpError)
        );
        assert!(
            loaded
                .result
                .hits
                .iter()
                .all(|hit| hit.rerank_score.is_none()),
            "a failed window must keep every rerank score absent"
        );
    }

    #[test]
    fn pages_advance_by_delivered_and_stop_at_end() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);

        let page1 = page_hits(&snap, 0).unwrap();
        assert_eq!(
            titles(&page1),
            ["hit-00", "hit-01", "hit-02", "hit-03", "hit-04"]
        );
        let cursor1 = next_cursor(&id, &snap, 0, page1.len()).unwrap().unwrap();

        let (snap2, offset2) = st.load(&cursor1, &snap.request_binding, &db, NOW).unwrap();
        assert_eq!(offset2, 5);
        let page2 = page_hits(&snap2, offset2).unwrap();
        assert_eq!(
            titles(&page2),
            ["hit-05", "hit-06", "hit-07", "hit-08", "hit-09"]
        );
        let cursor2 = next_cursor(&id, &snap2, offset2, page2.len())
            .unwrap()
            .unwrap();

        let (snap3, offset3) = st.load(&cursor2, &snap.request_binding, &db, NOW).unwrap();
        assert_eq!(offset3, 10);
        let page3 = page_hits(&snap3, offset3).unwrap();
        assert_eq!(titles(&page3), ["hit-10", "hit-11"]);
        assert_eq!(
            next_cursor(&id, &snap3, offset3, page3.len()).unwrap(),
            None
        );
    }

    #[test]
    fn budget_shrink_advances_by_delivered_without_skipping() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);

        // The display budget let only 2 of the first 5 through.
        let cursor = next_cursor(&id, &snap, 0, 2).unwrap().unwrap();
        let (snap2, offset) = st.load(&cursor, &snap.request_binding, &db, NOW).unwrap();
        assert_eq!(offset, 2);
        assert_eq!(
            titles(&page_hits(&snap2, offset).unwrap()),
            ["hit-02", "hit-03", "hit-04", "hit-05", "hit-06"]
        );

        // Zero delivered, and over-delivery, are handled distinctly.
        assert_eq!(next_cursor(&id, &snap, 0, 0).unwrap(), None);
        assert_eq!(
            next_cursor(&id, &snap, 0, 13).unwrap_err(),
            WindowError::InvalidInput
        );
    }

    #[test]
    fn empty_window_has_no_continuation_cursor() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 0, 5, 5);
        let (id, cursor) = save_and_cursor(&st, &snap, 0);

        assert!(page_hits(&snap, 0).unwrap().is_empty());
        assert_eq!(next_cursor(&id, &snap, 0, 0).unwrap(), None);
        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::InvalidCursor
        );
    }

    // ------------------------------------------------------------------
    // C2 - request/index identity, corruption and reclaim
    // ------------------------------------------------------------------

    #[test]
    fn relative_time_window_survives_changed_now() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        let later = NOW + 120_000;
        let (loaded, _) = st.load(&cursor, &snap.request_binding, &db, later).unwrap();
        // The relative selectors are unchanged and the resolved bounds stay
        // frozen at the first lookup, not re-derived from `later`.
        assert_eq!(loaded.request_binding.time, snap.request_binding.time);
        assert_eq!(loaded.resolved_filters.created_from, Some(NOW - 86_400_000));
        assert_eq!(loaded.resolved_filters.created_to, Some(NOW));
    }

    #[test]
    fn changed_request_is_a_binding_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        let mut variants = Vec::new();
        let mut query = snap.request_binding.clone();
        query.query = "a different query".to_string();
        variants.push(query);
        let mut agents = snap.request_binding.clone();
        agents.agents = vec!["other".to_string()];
        variants.push(agents);
        let mut limits = snap.request_binding.clone();
        limits.rerank_limit = 4;
        variants.push(limits);
        let mut provider = snap.request_binding.clone();
        provider.provider = ProviderChoice::BgeLocal;
        variants.push(provider);
        let mut endpoint = snap.request_binding.clone();
        endpoint.endpoint = "http://127.0.0.1:9999".to_string();
        variants.push(endpoint);
        let mut filters = snap.request_binding.clone();
        filters.roles = Some(vec![3]);
        variants.push(filters);

        for variant in variants {
            assert_eq!(
                st.load(&cursor, &variant, &db, NOW).unwrap_err(),
                WindowError::BindingMismatch
            );
        }
    }

    #[test]
    fn reordered_collections_are_the_same_binding() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        let mut reordered = snap.request_binding.clone();
        reordered.agents = vec!["claude".to_string(), "codex".to_string()];
        reordered.workspaces = vec!["/w/a".to_string(), "/w/b".to_string()];
        reordered.session_paths = vec!["/s/a.jsonl".to_string(), "/s/b.jsonl".to_string()];
        reordered.roles = Some(vec![1, 2]);
        assert!(st.load(&cursor, &reordered, &db, NOW).is_ok());
    }

    #[test]
    fn tampered_bytes_fail_the_raw_hash_check() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, cursor) = save_and_cursor(&st, &snap, 0);

        // Re-serialize valid JSON with a changed field: the filename no longer
        // matches the raw-byte digest, so the whole window is refused.
        let mut value = read_saved(tmp.path(), &id);
        value["result"]["hits"][0]["title"] = json!("tampered");
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(window_dir(tmp.path()).join(format!("{id}.json")), &bytes).unwrap();

        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::Corrupt
        );
    }

    #[test]
    fn unknown_schema_and_missing_keys_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);
        let base = read_saved(tmp.path(), &id);

        let mut wrong_schema = base.clone();
        wrong_schema["schema"] = json!("cass.rerank-window.v2");
        let cursor = write_tampered(tmp.path(), &wrong_schema);
        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::Corrupt
        );

        for key in WINDOW_KEYS {
            let mut value = base.clone();
            value.as_object_mut().unwrap().remove(*key);
            let cursor = write_tampered(tmp.path(), &value);
            assert_eq!(
                st.load(&cursor, &snap.request_binding, &db, NOW)
                    .unwrap_err(),
                WindowError::Corrupt,
                "missing outer key {key} must be Corrupt"
            );
        }
        for key in BINDING_KEYS {
            let mut value = base.clone();
            value["request_binding"]
                .as_object_mut()
                .unwrap()
                .remove(*key);
            let cursor = write_tampered(tmp.path(), &value);
            assert_eq!(
                st.load(&cursor, &snap.request_binding, &db, NOW)
                    .unwrap_err(),
                WindowError::Corrupt,
                "missing binding key {key} must be Corrupt"
            );
        }
        for key in TIME_KEYS {
            let mut value = base.clone();
            value["request_binding"]["time"]
                .as_object_mut()
                .unwrap()
                .remove(*key);
            let cursor = write_tampered(tmp.path(), &value);
            assert_eq!(
                st.load(&cursor, &snap.request_binding, &db, NOW)
                    .unwrap_err(),
                WindowError::Corrupt,
                "missing time key {key} must be Corrupt"
            );
        }
        for key in RERANK_KEYS {
            let mut value = base.clone();
            value["rerank"].as_object_mut().unwrap().remove(*key);
            let cursor = write_tampered(tmp.path(), &value);
            assert_eq!(
                st.load(&cursor, &snap.request_binding, &db, NOW)
                    .unwrap_err(),
                WindowError::Corrupt,
                "missing rerank key {key} must be Corrupt"
            );
        }
        for key in IDENTITY_KEYS {
            let mut value = base.clone();
            value["rerank"]["identity"]
                .as_object_mut()
                .unwrap()
                .remove(*key);
            let cursor = write_tampered(tmp.path(), &value);
            assert_eq!(
                st.load(&cursor, &snap.request_binding, &db, NOW)
                    .unwrap_err(),
                WindowError::Corrupt,
                "missing identity key {key} must be Corrupt"
            );
        }
    }

    #[test]
    fn null_option_keys_are_accepted_but_missing_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, false, 3, 5, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);
        let base = read_saved(tmp.path(), &id);

        // Nulls round-trip: they are present keys. The expected binding must
        // carry the same nulled roles to compare equal.
        let mut nulled = base.clone();
        nulled["aggregates"] = Value::Null;
        nulled["explanation"] = Value::Null;
        nulled["request_binding"]["roles"] = Value::Null;
        nulled["rerank"]["failure_reason"] = Value::Null;
        nulled["rerank"]["http_status"] = Value::Null;
        let mut expected = snap.request_binding.clone();
        expected.roles = None;
        let cursor = write_tampered(tmp.path(), &nulled);
        assert!(st.load(&cursor, &expected, &db, NOW).is_ok());

        // A missing null-valued key is Corrupt.
        let mut missing = base.clone();
        missing["rerank"]
            .as_object_mut()
            .unwrap()
            .remove("http_status");
        let cursor = write_tampered(tmp.path(), &missing);
        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::Corrupt
        );
    }

    #[test]
    fn duplicate_message_identity_is_refused_on_save() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());

        // Duplicate identity.
        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits[1].message_id = snap.result.hits[0].message_id;
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        // Zero identity.
        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits[0].message_id = Some(0);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        // Negative identity.
        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits[0].message_id = Some(-4);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        // Absent identity.
        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits[2].message_id = None;
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        // A normal all-positive, unique window still saves.
        let snap = snapshot(&db, NOW, true, 3, 5, 5);
        assert!(st.save(&snap, NOW).is_ok());
    }

    #[test]
    fn next_cursor_enforces_the_page_contract() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);

        // A page that delivered nothing never repeats the same cursor.
        assert_eq!(next_cursor(&id, &snap, 5, 0).unwrap(), None);
        assert_eq!(next_cursor(&id, &snap, 0, 0).unwrap(), None);

        // One page can never deliver more than min(K, remaining).
        assert_eq!(
            next_cursor(&id, &snap, 0, 6).unwrap_err(),
            WindowError::InvalidInput
        );
        assert_eq!(
            next_cursor(&id, &snap, 0, 12).unwrap_err(),
            WindowError::InvalidInput
        );
        // Exactly K is the largest legal page.
        assert!(next_cursor(&id, &snap, 0, 5).unwrap().is_some());

        // On the last page the cap is what remains, which is below K.
        assert_eq!(next_cursor(&id, &snap, 10, 2).unwrap(), None);
        assert_eq!(
            next_cursor(&id, &snap, 10, 3).unwrap_err(),
            WindowError::InvalidInput
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_window_file_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, cursor) = save_and_cursor(&st, &snap, 0);

        let path = window_dir(tmp.path()).join(format!("{id}.json"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::CacheUnavailable
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_lock_file_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());

        let lock = window_dir(tmp.path()).join(LOCK_FILE_NAME);
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();

        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        assert_eq!(
            st.save(&snap, NOW).unwrap_err(),
            WindowError::CacheUnavailable
        );
    }

    #[test]
    fn applied_flag_must_match_the_scores() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());

        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits[0].rerank_score = None;
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        let mut snap = snapshot(&db, NOW, false, 3, 5, 5);
        snap.result.hits[0].rerank_score = Some(0.1);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.rerank.identity.actual_provider = Some(ProviderChoice::BgeLocal);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        // The applied flag says every hit was scored, but the stored count no
        // longer matches the number of hits.
        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits.push(hit(9, 1.0));
        snap.result.hits.last_mut().unwrap().rerank_score = Some(0.9);
        snap.rerank.scored_count = 3;
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);
    }

    #[test]
    fn hits_beyond_the_window_bound_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 6, 5, 5);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);
    }

    #[test]
    fn the_policy_bounds_are_validated() {
        let tmp = tempfile::tempdir().unwrap();
        let base = WindowPolicy::default();

        for policy in [
            WindowPolicy { ttl_ms: 0, ..base },
            WindowPolicy {
                max_windows: 0,
                ..base
            },
            WindowPolicy {
                max_total_bytes: 0,
                ..base
            },
            WindowPolicy {
                max_window_bytes: 0,
                ..base
            },
            WindowPolicy {
                max_window_bytes: base.max_total_bytes + 1,
                ..base
            },
        ] {
            assert_eq!(
                WindowStore::new(tmp.path(), policy).unwrap_err(),
                WindowError::InvalidInput
            );
        }
    }

    #[test]
    fn malformed_cursors_are_rejected() {
        use base64::Engine as _;

        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);

        let cases = vec![
            // offset at the window length is out of range
            raw_cursor(json!({"version": 2, "window_id": id.clone(), "offset": 12})),
            // old cursor version
            raw_cursor(json!({"version": 1, "window_id": id.clone(), "offset": 0})),
            // negative offset
            raw_cursor(json!({"version": 2, "window_id": id.clone(), "offset": -1})),
            // fractional offset
            raw_cursor(json!({"version": 2, "window_id": id.clone(), "offset": 1.5})),
            // extra field
            raw_cursor(json!({"version": 2, "window_id": id.clone(), "offset": 0, "extra": 1})),
            // path traversal in the id
            raw_cursor(json!({"version": 2, "window_id": "../escape", "offset": 0})),
            // uppercase hex is not the frozen spelling
            raw_cursor(json!({"version": 2, "window_id": id.to_uppercase(), "offset": 0})),
            // not base64 at all
            "not-base64!!".to_string(),
            // base64 that decodes to a non-JSON body
            base64::prelude::BASE64_STANDARD.encode(b"not json"),
            // base64 of trailing garbage after a valid object
            base64::prelude::BASE64_STANDARD
                .encode(format!(r#"{{"version":2,"window_id":"{id}","offset":0}}}}"#).as_bytes()),
        ];

        for cursor in cases {
            let result = st.load(&cursor, &snap.request_binding, &db, NOW);
            assert!(
                matches!(
                    result,
                    Err(WindowError::InvalidCursor) | Err(WindowError::NotFound)
                ),
                "cursor {cursor:?} must be refused, got {result:?}"
            );
        }
    }

    #[test]
    fn expired_window_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, snap.expires_at_ms)
                .unwrap_err(),
            WindowError::Expired
        );
        assert!(
            st.load(&cursor, &snap.request_binding, &db, snap.expires_at_ms - 1)
                .is_ok()
        );
    }

    #[test]
    fn missing_window_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let cursor = encode_cursor(&"a".repeat(64), 0).unwrap();
        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::NotFound
        );
    }

    #[test]
    fn index_change_invalidates_a_window() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);
        assert!(st.load(&cursor, &snap.request_binding, &db, NOW).is_ok());

        {
            let conn = Conn::open_writable(&db, Profile::Production).unwrap();
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('p04_index_probe', '1')",
                &[],
            )
            .unwrap();
        }

        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::IndexChanged
        );
    }

    #[test]
    fn oversized_single_window_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let policy = WindowPolicy {
            max_window_bytes: 256,
            max_total_bytes: 1024,
            ..WindowPolicy::default()
        };
        let st = WindowStore::new(tmp.path(), policy).unwrap();
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);
    }

    #[test]
    fn prune_enforces_the_window_count_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let ttl = WindowPolicy::default().ttl_ms as i64;
        let policy = WindowPolicy {
            max_windows: 2,
            max_window_bytes: 4_000_000,
            max_total_bytes: 8_000_000,
            ..WindowPolicy::default()
        };
        let st = WindowStore::new(tmp.path(), policy).unwrap();

        let mut ids = Vec::new();
        for step in 0..3i64 {
            let created = NOW + step;
            let mut snap = snapshot(&db, created, true, 3, 5, 5);
            snap.created_at_ms = created;
            snap.expires_at_ms = created + ttl;
            ids.push(st.save(&snap, created).unwrap());
        }

        let files: Vec<String> = fs::read_dir(window_dir(tmp.path()))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.ends_with(".json"))
            .collect();
        assert_eq!(files.len(), 2, "only max_windows files may remain");
        assert!(
            !files.contains(&format!("{}.json", ids[0])),
            "oldest must go"
        );
        assert!(
            files.contains(&format!("{}.json", ids[2])),
            "newest must stay"
        );
    }

    #[test]
    fn prune_enforces_the_total_byte_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let first = snapshot(&db, NOW, true, 3, 5, 5);
        let first_id = st.save(&first, NOW).unwrap();
        let size = fs::metadata(window_dir(tmp.path()).join(format!("{first_id}.json")))
            .unwrap()
            .len();

        let policy = WindowPolicy {
            max_windows: 16,
            max_window_bytes: size,
            max_total_bytes: size * 2,
            ..WindowPolicy::default()
        };
        let st = WindowStore::new(tmp.path(), policy).unwrap();

        let mut ids = vec![first_id];
        for step in 1..3i64 {
            let created = NOW + step;
            let mut snap = snapshot(&db, created, true, 3, 5, 5);
            snap.created_at_ms = created;
            snap.expires_at_ms = created + policy.ttl_ms as i64;
            ids.push(st.save(&snap, created).unwrap());
        }

        let names: Vec<String> = fs::read_dir(window_dir(tmp.path()))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.ends_with(".json"))
            .collect();
        assert!(names.len() <= 2, "total bytes must stay within the bound");
        assert!(names.contains(&format!("{}.json", ids[2])));
    }

    #[test]
    fn reclaim_leaves_neighbour_files_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let policy = WindowPolicy {
            max_windows: 1,
            max_window_bytes: 4_000_000,
            max_total_bytes: 8_000_000,
            ..WindowPolicy::default()
        };
        let st = WindowStore::new(tmp.path(), policy).unwrap();

        let dir = window_dir(tmp.path());
        let stray = dir.join("notes.txt");
        fs::write(&stray, b"keep me").unwrap();
        let subdir = dir.join("subdir");
        fs::create_dir(&subdir).unwrap();

        for step in 0..3i64 {
            let created = NOW + step;
            let mut snap = snapshot(&db, created, true, 3, 5, 5);
            snap.created_at_ms = created;
            snap.expires_at_ms = created + policy.ttl_ms as i64;
            st.save(&snap, created).unwrap();
        }

        assert_eq!(fs::read(&stray).unwrap(), b"keep me");
        assert!(subdir.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_private_directory_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let dir = window_dir(tmp.path());
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            WindowStore::new(tmp.path(), WindowPolicy::default()).unwrap_err(),
            WindowError::CacheUnavailable
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_window_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("elsewhere");
        fs::create_dir_all(&target).unwrap();
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        std::os::unix::fs::symlink(&target, cache.join("rerank-windows")).unwrap();

        assert_eq!(
            WindowStore::new(tmp.path(), WindowPolicy::default()).unwrap_err(),
            WindowError::CacheUnavailable
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_window_file_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, cursor) = save_and_cursor(&st, &snap, 0);

        // Replace the published file with a symlink to a copy of the same
        // bytes: identity is the inode's content, not whatever a link names.
        let path = window_dir(tmp.path()).join(format!("{id}.json"));
        let copy = tmp.path().join("copy.json");
        fs::rename(&path, &copy).unwrap();
        std::os::unix::fs::symlink(&copy, &path).unwrap();

        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::Corrupt
        );
    }

    // ------------------------------------------------------------------
    // C2 - two real processes
    // ------------------------------------------------------------------

    #[test]
    #[ignore]
    fn p04_child_entrypoint() {
        let action = std::env::var("CASS_P04_ACTION").expect("CASS_P04_ACTION");
        let data_dir =
            PathBuf::from(std::env::var("CASS_P04_DATA_DIR").expect("CASS_P04_DATA_DIR"));
        let db_path = PathBuf::from(std::env::var("CASS_P04_DB").expect("CASS_P04_DB"));
        let result_path = PathBuf::from(std::env::var("CASS_P04_RESULT").expect("CASS_P04_RESULT"));
        let st = WindowStore::new(&data_dir, WindowPolicy::default()).expect("open store");

        match action.as_str() {
            "save" => {
                let snap = snapshot(&db_path, NOW, true, 12, 12, 5);
                let id = st.save(&snap, NOW).expect("save");
                let cursor = next_cursor(&id, &snap, 0, 5)
                    .expect("cursor")
                    .expect("a window with 12 hits must have a continuation");
                fs::write(&result_path, format!("{id}\n{cursor}\n")).expect("write child result");
            }
            "load" => {
                let cursor = std::env::var("CASS_P04_CURSOR").expect("CASS_P04_CURSOR");
                let expected = binding(12, 5);
                let (snap, offset) = st.load(&cursor, &expected, &db_path, NOW).expect("load");
                let titles = titles(&page_hits(&snap, offset).expect("page"));
                fs::write(&result_path, format!("{offset}\n{}\n", titles.join(",")))
                    .expect("write child result");
            }
            // A model-failure window: the original RRF order is kept and no
            // rerank score exists anywhere.
            "save-failed" => {
                let snap = snapshot(&db_path, NOW, false, 4, 6, 3);
                let id = st.save(&snap, NOW).expect("save failed window");
                fs::write(&result_path, format!("{id}\n")).expect("write child result");
            }
            other => panic!("unknown child action {other}"),
        }
    }

    fn run_child(data_dir: &Path, db: &Path, action: &str, result: &Path, cursor: Option<&str>) {
        let exe = std::env::current_exe().expect("test binary path");
        let mut cmd = std::process::Command::new(exe);
        cmd.args(["--ignored", "--exact", CHILD_TEST_NAME])
            .env("CASS_P04_ACTION", action)
            .env("CASS_P04_DATA_DIR", data_dir)
            .env("CASS_P04_DB", db)
            .env("CASS_P04_RESULT", result);
        if let Some(cursor) = cursor {
            cmd.env("CASS_P04_CURSOR", cursor);
        }
        let output = cmd.output().expect("spawn child test process");
        assert!(
            output.status.success(),
            "child {action} failed: status={:?}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn cross_process_child_saves_parent_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let result = tmp.path().join("child-save.txt");
        run_child(tmp.path(), &db, "save", &result, None);

        let text = fs::read_to_string(&result).unwrap();
        let mut lines = text.lines();
        let id = lines.next().unwrap().to_string();
        let cursor = lines.next().unwrap().to_string();
        assert!(is_window_id(&id));

        let st = store(tmp.path());
        let (snap, offset) = st.load(&cursor, &binding(12, 5), &db, NOW).unwrap();
        assert_eq!(offset, 5);
        assert_eq!(snap.result.hits.len(), 12);
        assert_eq!(titles(&page_hits(&snap, offset).unwrap())[0], "hit-05");
    }

    #[test]
    fn cross_process_parent_saves_child_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        let result = tmp.path().join("child-load.txt");
        run_child(tmp.path(), &db, "load", &result, Some(&cursor));

        let text = fs::read_to_string(&result).unwrap();
        let mut lines = text.lines();
        assert_eq!(lines.next().unwrap(), "0");
        assert_eq!(lines.next().unwrap(), "hit-00,hit-01,hit-02,hit-03,hit-04");
    }

    /// A model-failure window written by one process and read by another must
    /// keep the original RRF order, the original scores and the failure
    /// metadata, with no rerank score anywhere.
    #[test]
    fn cross_process_failed_window_keeps_original_order() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let result = tmp.path().join("child-failed.txt");
        run_child(tmp.path(), &db, "save-failed", &result, None);

        let id = fs::read_to_string(&result).unwrap().trim().to_string();
        assert!(is_window_id(&id));

        // This process reads what the child wrote.
        let st = store(tmp.path());
        let cursor = encode_cursor(&id, 0).unwrap();
        let (snap, offset) = st.load(&cursor, &binding(6, 3), &db, NOW).unwrap();
        assert_eq!(offset, 0);

        assert_eq!(
            titles(&snap.result.hits),
            ["hit-00", "hit-01", "hit-02", "hit-03"]
        );
        assert_eq!(
            snap.result
                .hits
                .iter()
                .map(|hit| hit.score)
                .collect::<Vec<f32>>(),
            vec![100.0f32, 99.0, 98.0, 97.0]
        );
        assert!(
            snap.result
                .hits
                .iter()
                .all(|hit| hit.rerank_score.is_none()),
            "a failed window must carry no rerank score"
        );

        assert!(!snap.rerank.applied);
        assert_eq!(snap.rerank.scored_count, 0);
        assert_eq!(
            snap.rerank.failure_reason,
            Some(RerankFailureReason::HttpError)
        );
        assert_eq!(snap.rerank.http_status, Some(503));
        assert_eq!(snap.rerank.http_requests, None);
        assert_eq!(snap.rerank.model_requests, None);

        // The frozen failed window still paginates by K.
        assert_eq!(
            titles(&page_hits(&snap, 0).unwrap()),
            ["hit-00", "hit-01", "hit-02"]
        );
        assert_eq!(titles(&page_hits(&snap, 3).unwrap()), ["hit-03"]);
    }

    /// Real concurrent saves on one private store must never exceed the
    /// policy, must not collapse distinct snapshots onto one id, and a
    /// contended save must refuse cleanly instead of corrupting the budget.
    #[test]
    fn concurrent_save_stays_within_the_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let ttl = WindowPolicy::default().ttl_ms as i64;
        let policy = WindowPolicy {
            max_windows: 2,
            max_window_bytes: 4_000_000,
            max_total_bytes: 8_000_000,
            ..WindowPolicy::default()
        };
        let st = WindowStore::new(tmp.path(), policy).unwrap();

        let mut prepared = Vec::new();
        for step in 0..4i64 {
            let created = NOW + step;
            let mut snap = snapshot(&db, created, true, 3, 5, 5);
            snap.created_at_ms = created;
            snap.expires_at_ms = created + ttl;
            prepared.push(snap);
        }

        let threads = prepared.len();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(threads));
        let mut handles = Vec::new();
        for snap in prepared {
            let st = st.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                st.save(&snap, snap.created_at_ms)
            }));
        }
        let outcomes: Vec<Result<String, WindowError>> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread join"))
            .collect();

        let succeeded = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        assert!(succeeded >= 1, "at least one concurrent save must succeed");
        for outcome in &outcomes {
            if let Err(err) = outcome {
                assert_eq!(
                    *err,
                    WindowError::CacheUnavailable,
                    "a contended save must refuse cleanly"
                );
            }
        }

        // Distinct snapshots must produce distinct ids, never one overwriting
        // another to fake the budget.
        let ids: HashSet<&String> = outcomes.iter().filter_map(|o| o.as_ref()).collect();
        assert_eq!(ids.len(), succeeded, "each successful save has its own id");

        // The real on-disk set honours the policy.
        let files: Vec<PathBuf> = fs::read_dir(window_dir(tmp.path()))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .into_string()
                    .map(|name| name.ends_with(".json"))
                    .unwrap_or(false)
            })
            .map(|entry| entry.path())
            .collect();
        assert!(
            files.len() <= policy.max_windows,
            "{} files exceed max_windows {}",
            files.len(),
            policy.max_windows
        );
        let total: u64 = files
            .iter()
            .map(|path| fs::metadata(path).unwrap().len())
            .sum();
        assert!(
            total <= policy.max_total_bytes,
            "{total} bytes exceed max_total_bytes {}",
            policy.max_total_bytes
        );
    }

    /// While another holder owns the directory lock, `save` must refuse
    /// rather than queue, and must succeed once the lock is free.
    #[cfg(unix)]
    #[test]
    fn save_refuses_while_the_lock_is_held() {
        use std::os::unix::fs::OpenOptionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());

        let lock_path = window_dir(tmp.path()).join(LOCK_FILE_NAME);
        let holder = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .expect("create the lock file as 0600");
        fs2::FileExt::try_lock_exclusive(&holder).expect("acquire the lock");

        let snap = snapshot(&db, NOW, true, 3, 5, 5);
        assert_eq!(
            st.save(&snap, NOW).unwrap_err(),
            WindowError::CacheUnavailable,
            "save must refuse while the lock is held"
        );

        fs2::FileExt::unlock(&holder).unwrap();
        assert!(
            st.save(&snap, NOW).is_ok(),
            "save must work once the lock is free"
        );
    }

    // ------------------------------------------------------------------
    // C3 - real WAL, replacement and generation change
    // ------------------------------------------------------------------

    #[test]
    fn real_wal_write_invalidates_the_stamp() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());

        // A live writer keeps the committed frames un-checkpointed.
        let conn = Conn::open_writable(&db, Profile::Production).unwrap();
        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('p04_wal_probe_a', '1')",
            &[],
        )
        .unwrap();

        let before = capture_index_stamp(&db).unwrap();
        assert!(
            before.wal.is_some(),
            "a committed write must leave a non-empty WAL"
        );

        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('p04_wal_probe_b', '2')",
            &[],
        )
        .unwrap();
        let after = capture_index_stamp(&db).unwrap();

        assert_ne!(before, after);
        assert_ne!(
            before.wal.as_ref().map(|wal| wal.file.len),
            after.wal.as_ref().map(|wal| wal.file.len),
            "the WAL file must actually grow across the write"
        );
        drop(conn);
    }

    #[test]
    fn empty_wal_creation_and_shm_do_not_invalidate() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let wal = wal_path_for(&db);
        let shm = {
            let mut raw = db.as_os_str().to_os_string();
            raw.push("-shm");
            PathBuf::from(raw)
        };
        let _ = fs::remove_file(&wal);
        let _ = fs::remove_file(&shm);

        let before = capture_index_stamp(&db).unwrap();
        assert_eq!(before.wal, None, "an absent WAL is the absent state");

        // A read-only open may create a zero-length WAL; it must stay absent.
        let after = capture_index_stamp(&db).unwrap();
        assert_eq!(before, after);
        if let Ok(meta) = fs::metadata(&wal) {
            assert_eq!(meta.len(), 0, "a created WAL must be zero-length here");
        }

        // The SHM file is never part of the identity.
        fs::write(&shm, b"shm bytes that must not matter").unwrap();
        let with_shm = capture_index_stamp(&db).unwrap();
        assert_eq!(before, with_shm);
        let _ = fs::remove_file(&shm);
    }

    #[test]
    fn same_path_replacement_invalidates_the_stamp() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let before = capture_index_stamp(&db).unwrap();

        // Build the replacement under another name first, while the original
        // still exists, so the two files cannot share an inode; then move it
        // into place. A same-content replacement at the same path must still
        // invalidate the window.
        let staged = tmp.path().join("staged.db");
        make_db_at(&staged, false);
        let _ = fs::remove_file(wal_path_for(&staged));
        let _ = fs::remove_file(wal_path_for(&db));
        fs::remove_file(&db).unwrap();
        fs::rename(&staged, &db).unwrap();

        let after = capture_index_stamp(&db).unwrap();
        assert_ne!(before, after);
        assert_ne!(
            before.db_file.inode, after.db_file.inode,
            "a replaced file must be a different inode"
        );
    }

    #[test]
    fn vector_revision_and_generation_change_invalidate_the_stamp() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db_with_generation(tmp.path());

        let before = capture_index_stamp(&db).unwrap();
        assert_eq!(before.vector.as_ref().map(|v| v.revision), Some(0));

        {
            let conn = Conn::open_writable(&db, Profile::Production).unwrap();
            conn.execute(
                "UPDATE embedding_generations SET vector_revision = vector_revision + 1 \
                 WHERE is_active = 1",
                &[],
            )
            .unwrap();
        }
        let after_revision = capture_index_stamp(&db).unwrap();
        assert_eq!(after_revision.vector.as_ref().map(|v| v.revision), Some(1));
        assert_ne!(before.vector, after_revision.vector);

        {
            let conn = Conn::open_writable(&db, Profile::Production).unwrap();
            conn.execute(
                "UPDATE embedding_generations SET is_active = 0 WHERE is_active = 1",
                &[],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO embedding_generations \
                 (embedder_id, dim, canonicalize_version, chunking_policy_version, fingerprint, \
                  byte_order, audit_status, is_active, created_at, activated_at, vector_revision) \
                 VALUES ('other-embedder', 8, 1, 1, X'AA', 'le', 'passed', 1, 2, 2, 0)",
                &[],
            )
            .unwrap();
        }
        let after_generation = capture_index_stamp(&db).unwrap();
        assert_ne!(
            after_revision.vector.as_ref().map(|v| v.generation_id),
            after_generation.vector.as_ref().map(|v| v.generation_id),
            "a new active generation must be a new vector identity"
        );
    }

    #[test]
    fn absent_vector_generation_is_stamped_as_none() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let stamp = capture_index_stamp(&db).unwrap();
        assert_eq!(stamp.vector, None);
        assert_eq!(
            stamp.schema_version,
            crate::storage::schema::CURRENT_SCHEMA_VERSION
        );
        assert!(stamp.db_path.ends_with("agent_search.db"));
    }

    #[test]
    fn endpoint_normalisation_uses_the_origin_only() {
        assert_eq!(
            normalize_endpoint("http://127.0.0.1:8000/v1/rerank?x=1").unwrap(),
            "http://127.0.0.1:8000"
        );
        assert_eq!(
            normalize_endpoint("https://API.OpenRouter.ai/api/v1?k=1#f").unwrap(),
            "https://api.openrouter.ai"
        );
        assert_eq!(
            normalize_endpoint("https://example.com:443/path").unwrap(),
            "https://example.com"
        );
        assert!(normalize_endpoint("ftp://example.com").is_err());
        assert!(normalize_endpoint("http://user:pass@example.com").is_err());
        assert!(normalize_endpoint("not a url").is_err());
    }
}
