//! Semantic model management (local-only detection).
//!
//! This module wires the FastEmbed MiniLM embedder into semantic search by:
//! - validating the local model files
//! - loading the vector index
//! - building filter maps from the SQLite database
//! - detecting model version mismatches
//!
//! It does **not** download or load models: embedding is served exclusively by
//! the configured external model API. Availability is surfaced from the
//! DB-vector-domain state so the UI can report semantic readiness.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::search::embedder::Embedder;
use crate::search::hash_embedder::HashEmbedder;
use crate::search::model_identity;
use crate::search::vector_index::{ROLE_ASSISTANT, ROLE_USER, vector_index_path};
use crate::storage::api::params;
use crate::storage::sqlite::FrankenStorage;

/// Unified TUI state machine for semantic search availability.
///
/// This enum tracks the full lifecycle of semantic search from the user's perspective:
/// - Model installation flow (NotInstalled → NeedsConsent → Downloading → Verifying → Ready)
/// - Index building flow (Ready → IndexBuilding → Ready)
/// - User preferences (HashFallback, Disabled)
/// - Error states (LoadFailed, ModelMissing, etc.)
#[derive(Debug, Clone)]
pub enum SemanticAvailability {
    /// Model is ready for use.
    Ready { embedder_id: String },

    // =========================================================================
    // TUI-centric states for user flow
    // =========================================================================
    /// Model not installed - semantic not available.
    /// TUI should show option to download or use hash fallback.
    NotInstalled,

    /// User needs to consent before downloading model.
    /// TUI should show consent dialog.
    NeedsConsent,

    /// Model download in progress.
    Downloading {
        /// Progress percentage (0-100).
        progress_pct: u8,
        /// Bytes downloaded so far.
        bytes_downloaded: u64,
        /// Total bytes to download.
        total_bytes: u64,
    },

    /// Verifying downloaded model (SHA256 check).
    Verifying,

    /// Index is being built or rebuilt.
    IndexBuilding {
        embedder_id: String,
        /// Optional progress percentage (0-100).
        progress_pct: Option<u8>,
        /// Number of items indexed so far.
        items_indexed: u64,
        /// Total items to index.
        total_items: u64,
    },

    /// User opted for hash-based fallback (no ML model).
    HashFallback,

    /// Semantic search disabled by policy or user.
    Disabled { reason: String },

    // =========================================================================
    // Diagnostic states for troubleshooting
    // =========================================================================
    /// Model files are missing.
    ModelMissing {
        model_dir: PathBuf,
        missing_files: Vec<String>,
    },

    /// Vector index is missing.
    IndexMissing { index_path: PathBuf },

    /// Database is unavailable.
    DatabaseUnavailable { db_path: PathBuf, error: String },

    /// Failed to load semantic context.
    LoadFailed { context: String },

    /// Model update available - index rebuild needed.
    UpdateAvailable {
        embedder_id: String,
        current_revision: String,
        latest_revision: String,
    },
}

impl SemanticAvailability {
    /// Check if semantic search is ready to use.
    pub fn is_ready(&self) -> bool {
        matches!(self, SemanticAvailability::Ready { .. })
    }

    /// Check if a model update is available.
    pub fn has_update(&self) -> bool {
        matches!(self, SemanticAvailability::UpdateAvailable { .. })
    }

    /// Check if the index is being rebuilt.
    pub fn is_building(&self) -> bool {
        matches!(self, SemanticAvailability::IndexBuilding { .. })
    }

    /// Check if a download is in progress.
    pub fn is_downloading(&self) -> bool {
        matches!(self, SemanticAvailability::Downloading { .. })
    }

    /// Check if user consent is needed.
    pub fn needs_consent(&self) -> bool {
        matches!(self, SemanticAvailability::NeedsConsent)
    }

    /// Check if hash fallback is active.
    pub fn is_hash_fallback(&self) -> bool {
        matches!(self, SemanticAvailability::HashFallback)
    }

    /// Check if semantic search is disabled.
    pub fn is_disabled(&self) -> bool {
        matches!(self, SemanticAvailability::Disabled { .. })
    }

    /// Check if the model is not installed.
    pub fn is_not_installed(&self) -> bool {
        matches!(
            self,
            SemanticAvailability::NotInstalled | SemanticAvailability::ModelMissing { .. }
        )
    }

    /// Check if any error state is active.
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            SemanticAvailability::LoadFailed { .. }
                | SemanticAvailability::DatabaseUnavailable { .. }
        )
    }

    /// Check if semantic can be used (ready or hash fallback).
    pub fn can_search(&self) -> bool {
        matches!(
            self,
            SemanticAvailability::Ready { .. } | SemanticAvailability::HashFallback
        )
    }

    /// Get download progress if downloading.
    pub fn download_progress(&self) -> Option<(u8, u64, u64)> {
        match self {
            SemanticAvailability::Downloading {
                progress_pct,
                bytes_downloaded,
                total_bytes,
            } => Some((*progress_pct, *bytes_downloaded, *total_bytes)),
            _ => None,
        }
    }

    /// Get index building progress if building.
    pub fn index_progress(&self) -> Option<(Option<u8>, u64, u64)> {
        match self {
            SemanticAvailability::IndexBuilding {
                progress_pct,
                items_indexed,
                total_items,
                ..
            } => Some((*progress_pct, *items_indexed, *total_items)),
            _ => None,
        }
    }

    /// Get a short status label for display in status bar.
    pub fn status_label(&self) -> &'static str {
        match self {
            SemanticAvailability::Ready { .. } => "SEM",
            SemanticAvailability::HashFallback => "SEM*",
            SemanticAvailability::NotInstalled => "LEX",
            SemanticAvailability::NeedsConsent => "LEX",
            SemanticAvailability::Downloading { .. } => "DL...",
            SemanticAvailability::Verifying => "VFY...",
            SemanticAvailability::IndexBuilding { .. } => "IDX...",
            SemanticAvailability::Disabled { .. } => "OFF",
            SemanticAvailability::ModelMissing { .. } => "NOMODEL",
            SemanticAvailability::IndexMissing { .. } => "NOIDX",
            SemanticAvailability::DatabaseUnavailable { .. } => "NODB",
            SemanticAvailability::LoadFailed { .. } => "ERR",
            SemanticAvailability::UpdateAvailable { .. } => "UPD",
        }
    }

    /// Get a detailed summary for display.
    pub fn summary(&self) -> String {
        match self {
            SemanticAvailability::Ready { embedder_id } => {
                format!("semantic ready ({embedder_id})")
            }
            SemanticAvailability::NotInstalled => "model not installed".to_string(),
            SemanticAvailability::NeedsConsent => "consent required for model download".to_string(),
            SemanticAvailability::Downloading {
                progress_pct,
                bytes_downloaded,
                total_bytes,
            } => {
                let mb_done = *bytes_downloaded as f64 / 1_048_576.0;
                let mb_total = *total_bytes as f64 / 1_048_576.0;
                format!("downloading model: {progress_pct}% ({mb_done:.1}/{mb_total:.1} MB)")
            }
            SemanticAvailability::Verifying => "verifying model checksum".to_string(),
            SemanticAvailability::IndexBuilding {
                items_indexed,
                total_items,
                progress_pct,
                ..
            } => {
                if let Some(pct) = progress_pct {
                    format!("building index: {pct}% ({items_indexed}/{total_items})")
                } else {
                    format!("building index: {items_indexed}/{total_items}")
                }
            }
            SemanticAvailability::HashFallback => "using hash-based fallback".to_string(),
            SemanticAvailability::Disabled { reason } => {
                format!("semantic disabled: {reason}")
            }
            SemanticAvailability::ModelMissing { model_dir, .. } => {
                format!("model missing at {}", model_dir.display())
            }
            SemanticAvailability::IndexMissing { index_path } => {
                format!("vector index missing at {}", index_path.display())
            }
            SemanticAvailability::DatabaseUnavailable { error, .. } => {
                format!("db unavailable ({error})")
            }
            SemanticAvailability::LoadFailed { context } => {
                format!("semantic load failed ({context})")
            }
            SemanticAvailability::UpdateAvailable {
                current_revision,
                latest_revision,
                ..
            } => {
                format!("update available: {current_revision} -> {latest_revision}")
            }
        }
    }
}

pub struct SemanticContext {
    pub embedder: Arc<dyn Embedder>,
    pub roles: Option<HashSet<u8>>,
}

pub struct SemanticSetup {
    pub availability: SemanticAvailability,
    pub context: Option<SemanticContext>,
}

/// Probe semantic availability without loading an embedder, vector index, or
/// DB-backed filter maps. Status/health surfaces use this to report readiness
/// cheaply.
///
/// In-process semantic tiers (ONNX/fastembed and the local Infinity HTTP
/// engine) are retired: embedding is served exclusively by the configured
/// external model API, so readiness is exactly the DB-vector-domain state read
/// from `embedding_generations`.
pub(crate) fn probe_semantic_availability(_data_dir: &Path, db_path: &Path) -> SemanticAvailability {
    probe_db_vector_domain_availability(db_path)
}

/// DB-vector-domain-aware availability probe (W3-4 Step2-1): reads
/// `embedding_generations` directly instead of the legacy `.fsvi`
/// file-existence short-circuit. w3-d7① three-state contract:
/// `is_active=1 && audit_status='passed'` -> `Ready`; a generation exists
/// but isn't certified/active yet (no active row with any row present, or
/// an active row that hasn't passed its W3-4 activation audit) ->
/// `IndexBuilding`; no generation at all -> `IndexMissing` (this domain's
/// "absent" -- reusing the existing variant rather than adding a new one
/// the enum's other consumers would all need to learn about).
fn probe_db_vector_domain_availability(db_path: &Path) -> SemanticAvailability {
    let storage = match FrankenStorage::open_readonly(db_path) {
        Ok(storage) => storage,
        Err(err) => {
            return SemanticAvailability::DatabaseUnavailable {
                db_path: db_path.to_path_buf(),
                error: err.to_string(),
            };
        }
    };
    probe_db_vector_domain_availability_with_connection(storage.raw(), db_path)
}

fn probe_db_vector_domain_availability_with_connection(
    conn: &crate::storage::api::Conn,
    db_path: &Path,
) -> SemanticAvailability {
    // R1-N7: a genuine SQL error here (corrupted table, malformed schema
    // after a botched migration, etc.) previously fell through
    // `.unwrap_or(None)`/`.unwrap_or(0)` as if it meant "no active
    // generation" / "zero generations" -- indistinguishable from the
    // db_path's own honest empty/absent state below, so a real error
    // reported the same `IndexBuilding`/`IndexMissing` a caller would see
    // for a perfectly healthy but genuinely-not-ready-yet database. Both
    // queries now propagate their error through the same
    // `DatabaseUnavailable` variant `open_readonly`'s own failure already
    // uses above, instead of being swallowed into a default.
    let active: Option<(String, String)> = match conn.query_opt_map(
        "SELECT embedder_id, audit_status FROM embedding_generations WHERE is_active = 1",
        &[],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
    ) {
        Ok(active) => active,
        Err(err) => {
            return SemanticAvailability::DatabaseUnavailable {
                db_path: db_path.to_path_buf(),
                error: err.to_string(),
            };
        }
    };
    if let Some((embedder_id, audit_status)) = active {
        return if audit_status == "passed" {
            SemanticAvailability::Ready { embedder_id }
        } else {
            SemanticAvailability::IndexBuilding {
                embedder_id,
                progress_pct: None,
                items_indexed: 0,
                total_items: 0,
            }
        };
    }

    let any_generation: i64 =
        match conn.query_row_map("SELECT COUNT(*) FROM embedding_generations", &[], |row| {
            row.get_typed(0)
        }) {
            Ok(count) => count,
            Err(err) => {
                return SemanticAvailability::DatabaseUnavailable {
                    db_path: db_path.to_path_buf(),
                    error: err.to_string(),
                };
            }
        };
    if any_generation > 0 {
        return SemanticAvailability::IndexBuilding {
            embedder_id: String::new(),
            progress_pct: None,
            items_indexed: 0,
            total_items: 0,
        };
    }

    SemanticAvailability::IndexMissing {
        index_path: db_path.to_path_buf(),
    }
}

/// Richer DB-vector-domain snapshot for `cass status`'s dedicated section
/// (W3-4 Step2-2, task book #62): same three-state read as
/// [`probe_db_vector_domain_availability`] plus the identity/count/audit
/// detail an operator actually wants from a status surface. This is a
/// parallel, additive status section -- it does not replace or change
/// the existing fsvi-driven `semantic` section, which keeps reporting
/// exactly as it always has during the W3-3..W3-5 coexistence window.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct DbVectorDomainStatus {
    pub active: bool,
    pub embedder_id: Option<String>,
    pub dim: Option<i64>,
    pub audit_status: Option<String>,
    pub embedded_count: Option<i64>,
    pub any_generation: bool,
    /// T8 (plan v5.1): `message_chunks` row count for the active
    /// generation -- `None` under the same conditions `embedded_count`
    /// is `None` (no active generation, or an SQL error already reported
    /// via `error`). `Some(0)` is a real, distinguishable state: an
    /// active v5 generation whose chunk-domain catch-up hasn't drained
    /// anything into it yet (or a legacy v4-only generation, which never
    /// has `message_chunks` rows at all).
    pub chunk_count: Option<i64>,
    /// T8: the active generation's `chunking_policy_version` column --
    /// `None` under the same conditions as `chunk_count`. A legacy (pre-T2)
    /// generation reads back `Some(0)` (`LEGACY_CHUNKING_POLICY_VERSION`),
    /// distinguishable from a real v5 generation's `Some(1)`.
    pub chunking_policy_version: Option<i64>,
    /// R1-N7: a genuine SQL error against an already-opened database (as
    /// opposed to the database itself failing to open at all, which stays
    /// `None` from this function per its own doc comment) used to be
    /// swallowed into the same fields a real "no active generation"/"zero
    /// generations" absence produces -- indistinguishable from a
    /// perfectly healthy but genuinely-empty database. `Some(detail)`
    /// here means the fields above are NOT a trustworthy absence signal;
    /// `None` means they are.
    pub error: Option<String>,
}

/// `None` only when the database itself cannot be opened read-only --
/// callers that already know `db_opened` is false should skip calling
/// this rather than treat `None` as a meaningful status of its own. R1-N7:
/// a query failing against a database that DID open is a different,
/// distinguishable failure -- reported via `DbVectorDomainStatus.error`,
/// not folded into the same fields a genuine "no active generation"/"zero
/// generations" absence produces.
pub(crate) fn probe_db_vector_domain_status(db_path: &Path) -> Option<DbVectorDomainStatus> {
    let storage = FrankenStorage::open_readonly(db_path).ok()?;
    let conn = storage.raw();
    let error_status = |err: &dyn std::fmt::Display| DbVectorDomainStatus {
        active: false,
        embedder_id: None,
        dim: None,
        audit_status: None,
        embedded_count: None,
        any_generation: false,
        chunk_count: None,
        chunking_policy_version: None,
        error: Some(err.to_string()),
    };
    let active: Option<(i64, String, i64, String, i64)> = match conn.query_opt_map(
        "SELECT id, embedder_id, dim, audit_status, chunking_policy_version FROM embedding_generations WHERE is_active = 1",
        &[],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?, row.get_typed(4)?)),
    ) {
        Ok(active) => active,
        Err(err) => return Some(error_status(&err)),
    };
    if let Some((generation_id, embedder_id, dim, audit_status, chunking_policy_version)) = active {
        // T11: `embedded_count` historically counted the retired v4
        // message-granularity table's rows (one row per embedded message).
        // Repointed to `message_chunks`, but `COUNT(DISTINCT message_id)`
        // -- not `COUNT(*)` -- to preserve the field's semantics ("how many
        // messages are embedded", not "how many chunks exist"; a message
        // can own more than one chunk, and `chunk_count` below already
        // reports the raw chunk-row count).
        let embedded_count: i64 = match conn.query_row_map(
            "SELECT COUNT(DISTINCT message_id) FROM message_chunks WHERE generation_id = ?1",
            &params![generation_id],
            |row| row.get_typed(0),
        ) {
            Ok(count) => count,
            Err(err) => return Some(error_status(&err)),
        };
        // T8: `message_chunks` is a base-schema table (present regardless
        // of whether this particular generation ever had anything drained
        // into it -- a legacy v4-only generation simply reads back `0`
        // here, not an error).
        let chunk_count: i64 = match conn.query_row_map(
            "SELECT COUNT(*) FROM message_chunks WHERE generation_id = ?1",
            &params![generation_id],
            |row| row.get_typed(0),
        ) {
            Ok(count) => count,
            Err(err) => return Some(error_status(&err)),
        };
        return Some(DbVectorDomainStatus {
            active: true,
            embedder_id: Some(embedder_id),
            dim: Some(dim),
            audit_status: Some(audit_status),
            embedded_count: Some(embedded_count),
            any_generation: true,
            chunk_count: Some(chunk_count),
            chunking_policy_version: Some(chunking_policy_version),
            error: None,
        });
    }

    let any_generation: i64 = match conn.query_row_map("SELECT COUNT(*) FROM embedding_generations", &[], |row| row.get_typed(0)) {
        Ok(count) => count,
        Err(err) => return Some(error_status(&err)),
    };
    Some(DbVectorDomainStatus {
        active: false,
        embedder_id: None,
        dim: None,
        audit_status: None,
        embedded_count: None,
        any_generation: any_generation > 0,
        chunk_count: None,
        chunking_policy_version: None,
        error: None,
    })
}


/// Probe hash semantic availability without opening the DB or vector index.
pub(crate) fn probe_hash_semantic_availability(data_dir: &Path) -> SemanticAvailability {
    let embedder = HashEmbedder::default();
    let index_path = vector_index_path(data_dir, embedder.id());
    if !index_path.is_file() {
        SemanticAvailability::IndexMissing { index_path }
    } else {
        SemanticAvailability::HashFallback
    }
}







/// Delete the vector index to force a rebuild.
///
/// Call this after a model upgrade when the user has consented to rebuilding
/// the semantic index. The next index run will rebuild from scratch.
///
/// # Returns
///
/// `Ok(true)` if the index was deleted.
/// `Ok(false)` if the index didn't exist.
/// `Err(_)` if deletion failed.
pub fn delete_vector_index_for_rebuild(data_dir: &Path) -> std::io::Result<bool> {
    let index_path = vector_index_path(data_dir, model_identity::embedder_id_static());

    if index_path.is_file() {
        std::fs::remove_file(&index_path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Get the model directory path for the retired default MiniLM model.
///
/// Retained only as a path helper for legacy read surfaces; no local weight is
/// ever loaded from here on the API-only path.
pub fn default_model_dir(data_dir: &Path) -> PathBuf {
    model_identity::default_model_dir(data_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::storage::api::{TxMode, params};
    use crate::storage::schema;

    type AvailabilityTuiCase = (
        SemanticAvailability,
        &'static str,
        fn(&SemanticAvailability) -> bool,
    );

    #[test]
    fn test_semantic_availability_ready() {
        let ready = SemanticAvailability::Ready {
            embedder_id: "test-123".into(),
        };
        assert!(ready.summary().contains("semantic ready"));
        assert!(ready.is_ready());
        assert!(!ready.has_update());
        assert!(ready.can_search());
        assert_eq!(ready.status_label(), "SEM");
    }

    #[test]
    fn test_semantic_availability_update() {
        let update = SemanticAvailability::UpdateAvailable {
            embedder_id: "test".into(),
            current_revision: "v1".into(),
            latest_revision: "v2".into(),
        };
        assert!(update.summary().contains("update available"));
        assert!(!update.is_ready());
        assert!(update.has_update());
        assert_eq!(update.status_label(), "UPD");
    }

    #[test]
    fn test_semantic_availability_index_building() {
        let building = SemanticAvailability::IndexBuilding {
            embedder_id: "test".into(),
            progress_pct: Some(45),
            items_indexed: 100,
            total_items: 200,
        };
        assert!(building.summary().contains("building index"));
        assert!(building.summary().contains("45%"));
        assert!(building.is_building());
        assert_eq!(building.status_label(), "IDX...");

        let (pct, done, total) = building.index_progress().unwrap();
        assert_eq!(pct, Some(45));
        assert_eq!(done, 100);
        assert_eq!(total, 200);
    }

    #[test]
    fn test_semantic_availability_downloading() {
        let downloading = SemanticAvailability::Downloading {
            progress_pct: 50,
            bytes_downloaded: 10_000_000,
            total_bytes: 20_000_000,
        };
        assert!(downloading.is_downloading());
        assert!(downloading.summary().contains("downloading"));
        assert!(downloading.summary().contains("50%"));
        assert_eq!(downloading.status_label(), "DL...");

        let (pct, bytes, total) = downloading.download_progress().unwrap();
        assert_eq!(pct, 50);
        assert_eq!(bytes, 10_000_000);
        assert_eq!(total, 20_000_000);
    }

    #[test]
    fn test_semantic_availability_tui_states() {
        let cases: &[AvailabilityTuiCase] = &[
            (
                SemanticAvailability::NotInstalled,
                "LEX",
                SemanticAvailability::is_not_installed,
            ),
            (
                SemanticAvailability::NeedsConsent,
                "LEX",
                SemanticAvailability::needs_consent,
            ),
            (SemanticAvailability::Verifying, "VFY...", |state| {
                state.summary().contains("verifying")
            }),
            (SemanticAvailability::HashFallback, "SEM*", |state| {
                state.is_hash_fallback() && state.can_search()
            }),
            (
                SemanticAvailability::Disabled {
                    reason: "offline mode".into(),
                },
                "OFF",
                |state| state.is_disabled() && state.summary().contains("offline"),
            ),
        ];

        for (state, expected_label, predicate) in cases {
            assert_eq!(state.status_label(), *expected_label, "{state:?}");
            assert!(predicate(state), "{state:?}");
        }
    }

    #[test]
    fn test_semantic_availability_error_states() {
        let load_failed = SemanticAvailability::LoadFailed {
            context: "test error".into(),
        };
        assert!(load_failed.is_error());
        assert_eq!(load_failed.status_label(), "ERR");

        let db_unavail = SemanticAvailability::DatabaseUnavailable {
            db_path: PathBuf::from("/test"),
            error: "locked".into(),
        };
        assert!(db_unavail.is_error());
        assert_eq!(db_unavail.status_label(), "NODB");
    }


    #[test]
    fn test_delete_vector_index_no_file() {
        let tmp = tempdir().unwrap();
        let result = delete_vector_index_for_rebuild(tmp.path());
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }


    // W3-4 Step2-1 (task book #62): the "no向量域" leg of the three-state
    // contract -- a library with a real, freshly-`schema::ensure`d
    // database but zero `embedding_generations` rows must report the
    // structured `IndexMissing` ("absent") availability, not error out,
    // not silently scan, and not need a real fsvi file to reach that
    // verdict.
    fn empty_db(dir: &std::path::Path) -> PathBuf {
        let db_path = dir.join("agent_search.db");
        let storage = FrankenStorage::open(&db_path).expect("open production storage");
        storage.close().unwrap();
        db_path
    }

    #[test]
    fn probe_db_vector_domain_availability_reports_absent_for_a_library_with_no_generations() {
        let dir = tempdir().unwrap();
        let db_path = empty_db(dir.path());
        let availability = probe_db_vector_domain_availability(&db_path);
        assert!(
            matches!(availability, SemanticAvailability::IndexMissing { .. }),
            "expected IndexMissing (absent), got {availability:?}"
        );
    }

    #[test]
    fn probe_semantic_availability_reports_absent_for_an_empty_library() {
        let dir = tempdir().unwrap();
        let db_path = empty_db(dir.path());
        let availability = probe_semantic_availability(dir.path(), &db_path);
        assert!(
            matches!(availability, SemanticAvailability::IndexMissing { .. }),
            "expected IndexMissing (absent), got {availability:?}"
        );
    }

    /// The "building" leg (task book #62 Step2, advisor ruling: all three
    /// legs of the d7 contract need a real green test, not "logically
    /// covered"). An active-but-not-yet-`passed` generation (exactly
    /// staging generation_id=1's real starting state pre-W3-4 Step1,
    /// per the backfill report) must report `IndexBuilding`, not `Ready`
    /// and not `IndexMissing`.
    fn db_with_active_pending_generation(dir: &std::path::Path) -> PathBuf {
        let db_path = dir.join("agent_search.db");
        let storage = FrankenStorage::open(&db_path).expect("open production storage");
        let gen_id = storage
            .raw()
            .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "BAAI/bge-m3", 1024, 1, 1, b"test-fingerprint", 0))
            .expect("create embedding generation");
        storage
            .raw()
            .execute("UPDATE embedding_generations SET is_active = 1 WHERE id = ?1", &params![gen_id])
            .expect("mark generation active");
        storage.close().unwrap();
        db_path
    }

    #[test]
    fn probe_db_vector_domain_availability_reports_building_for_an_active_unaudited_generation() {
        let dir = tempdir().unwrap();
        let db_path = db_with_active_pending_generation(dir.path());
        let availability = probe_db_vector_domain_availability(&db_path);
        assert!(
            matches!(availability, SemanticAvailability::IndexBuilding { .. }),
            "expected IndexBuilding, got {availability:?}"
        );
    }

    #[test]
    fn probe_semantic_availability_reports_building_for_an_active_pre_audit_generation() {
        let dir = tempdir().unwrap();
        let db_path = db_with_active_pending_generation(dir.path());
        let availability = probe_semantic_availability(dir.path(), &db_path);
        assert!(
            matches!(availability, SemanticAvailability::IndexBuilding { .. }),
            "expected IndexBuilding, got {availability:?}"
        );
    }

    /// R1-N7: a genuine SQL error querying `embedding_generations` (here,
    /// the table itself vanishing -- corruption, a botched migration, a
    /// concurrent DROP-and-recreate race -- but any SQL error takes the
    /// same code path) previously fell through `.unwrap_or(None)`/
    /// `.unwrap_or(0)` and reported the exact same `IndexMissing`/
    /// `IndexBuilding` states a genuinely absent/building library
    /// produces -- indistinguishable from those two legitimate states.
    /// Must now report `DatabaseUnavailable` instead.
    fn db_with_embedding_generations_table_dropped(dir: &std::path::Path) -> PathBuf {
        let db_path = dir.join("agent_search.db");
        let storage = FrankenStorage::open(&db_path).expect("open production storage");
        storage.raw().execute("DROP TABLE embedding_generations", &[]).expect("drop the table to force a real SQL error");
        storage.close().unwrap();
        db_path
    }

    #[test]
    fn probe_db_vector_domain_availability_reports_database_unavailable_on_sql_error_not_absent_or_building() {
        let dir = tempdir().unwrap();
        let db_path = db_with_embedding_generations_table_dropped(dir.path());
        let availability = probe_db_vector_domain_availability(&db_path);
        assert!(
            matches!(availability, SemanticAvailability::DatabaseUnavailable { .. }),
            "a genuine SQL error must report DatabaseUnavailable, not IndexMissing/IndexBuilding: {availability:?}"
        );
        assert!(!matches!(availability, SemanticAvailability::IndexMissing { .. }));
        assert!(!matches!(availability, SemanticAvailability::IndexBuilding { .. }));
    }

    /// T8 (plan v5.1): active v5 generation with one drained `message_chunks`
    /// row -- `db_with_active_pending_generation` above creates a generation
    /// but never inserts any chunk rows, so it always reads back
    /// `chunk_count=Some(0)` (`message_chunks` is a base-schema table,
    /// always queryable, just empty). This fixture goes through the real
    /// production write path (ingest a message, drain it into a chunk row)
    /// to prove a *populated* chunk_count and the real chunking policy
    /// version.
    fn db_with_active_v5_generation_and_one_chunk(dir: &std::path::Path) -> PathBuf {
        use crate::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};

        let db_path = dir.join("agent_search.db");
        let storage = FrankenStorage::open(&db_path).expect("open production storage");
        let fingerprint = vec![1u8; 3 * 4 * 4]; // 3 sentinels * dim=4 * 4 bytes/f32
        let gen_id = storage
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                schema::create_embedding_generation(tx, "mock-embedder-t8", 4, crate::search::canonicalize::CANONICALIZE_PIPELINE_VERSION, crate::search::chunking::CHUNKING_POLICY_VERSION, &fingerprint, 0)
            })
            .expect("create v5 embedding generation");

        // Production write path for the message (same pattern db_vector_
        // catchup.rs's own fixtures use) -- safer than a hand-rolled raw
        // INSERT against conversations/agents/messages' exact column shape.
        let agent_id = storage
            .ensure_agent(&Agent { id: None, slug: "claude_code".into(), name: "Claude Code".into(), version: Some("1.0".into()), kind: AgentKind::Cli })
            .expect("ensure agent");
        let conv = Conversation {
            id: None,
            agent_slug: "claude_code".into(),
            workspace: None,
            external_id: Some("status-fixture".into()),
            title: Some("status fixture".into()),
            source_path: std::path::PathBuf::from("/fixtures/status.jsonl"),
            started_at: Some(0),
            ended_at: Some(0),
            approx_tokens: None,
            metadata_json: serde_json::Value::Null,
            messages: vec![Message { excluded: None, id: None, idx: 0, role: MessageRole::User, author: None, created_at: Some(0), content: "status fixture message".into(), extra_json: serde_json::Value::Null, snippets: vec![] }],
            source_id: "local".into(),
            origin_host: None,
        };
        storage.insert_conversation_tree(agent_id, None, &conv).expect("insert fixture conversation");
        let message_id: i64 = storage.raw().query_row_map("SELECT id FROM messages LIMIT 1", &[], |row| row.get_typed(0)).unwrap();
        let conversation_id: i64 = storage.raw().query_row_map("SELECT conversation_id FROM messages WHERE id = ?1", &params![message_id], |row| row.get_typed(0)).unwrap();

        storage
            .raw()
            .execute(
                "INSERT INTO message_chunks (generation_id, message_id, conversation_id, chunk_idx, byte_start, byte_end, content_hash, embedding, norm, created_at) \
                 VALUES (?1, ?2, ?3, 0, 0, 5, 'fixture-hash', ?4, 1.0, 0)",
                &params![gen_id, message_id, conversation_id, schema::f32_vector_to_le_blob(&[1.0f32, 1.0, 1.0, 1.0])],
            )
            .expect("insert fixture message_chunks row");
        storage
            .raw()
            .execute("UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1", &params![gen_id])
            .expect("mark generation active");
        storage.close().unwrap();
        db_path
    }

    #[test]
    fn probe_db_vector_domain_status_reports_chunk_count_and_policy_version() {
        let dir = tempdir().unwrap();
        let db_path = db_with_active_v5_generation_and_one_chunk(dir.path());
        let status = probe_db_vector_domain_status(&db_path).expect("database must open");
        assert!(status.active);
        assert_eq!(status.chunk_count, Some(1), "the one seeded message_chunks row must be counted: {status:?}");
        assert_eq!(
            status.chunking_policy_version,
            Some(i64::from(crate::search::chunking::CHUNKING_POLICY_VERSION)),
            "must read back the real (non-legacy) chunking_policy_version stamped at creation: {status:?}"
        );
        let json = serde_json::to_value(&status).expect("DbVectorDomainStatus must serialize");
        assert_eq!(json["chunk_count"], serde_json::json!(1));
        assert_eq!(json["chunking_policy_version"], serde_json::json!(i64::from(crate::search::chunking::CHUNKING_POLICY_VERSION)));
    }

    #[test]
    fn probe_db_vector_domain_status_reports_the_error_field_on_sql_error_not_a_fabricated_absence() {
        let dir = tempdir().unwrap();
        let db_path = db_with_embedding_generations_table_dropped(dir.path());
        let status = probe_db_vector_domain_status(&db_path).expect("the database itself opened fine -- only the query inside it failed");
        assert!(status.error.is_some(), "a genuine SQL error must be reported via the error field, not silently absorbed into active=false/any_generation=false");
        assert!(!status.active);
        assert!(!status.any_generation);
    }

}

