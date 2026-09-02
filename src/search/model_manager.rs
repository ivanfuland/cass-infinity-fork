//! Semantic model management (local-only detection).
//!
//! This module wires the FastEmbed MiniLM embedder into semantic search by:
//! - validating the local model files
//! - loading the vector index
//! - building filter maps from the SQLite database
//! - detecting model version mismatches
//!
//! It does **not** download models. Missing files are surfaced as availability
//! states so the UI can guide the user. Downloads are handled by [`model_download`].

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::search::embedder::Embedder;
use crate::search::fastembed_embedder::FastEmbedder;
use crate::search::hash_embedder::HashEmbedder;
use crate::search::model_download::{
    ModelAcquisitionPolicy, ModelCacheState, ModelManifest, classify_model_cache,
    classify_model_cache_metadata,
};
use crate::search::policy::{CliSemanticOverrides, SemanticPolicy};
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

/// Load semantic context with optional version mismatch checking.
///
/// If `check_for_updates` is true, this function will check if the installed
/// model version matches the manifest and return `UpdateAvailable` if they differ.
pub fn load_semantic_context(data_dir: &Path, db_path: &Path) -> SemanticSetup {
    load_semantic_context_for_embedder(data_dir, db_path, active_policy_embedder_name())
}

pub fn load_semantic_context_for_embedder(
    data_dir: &Path,
    db_path: &Path,
    embedder_name: &str,
) -> SemanticSetup {
    load_semantic_context_inner(data_dir, db_path, true, embedder_name)
}

/// Probe semantic availability without loading the embedder, vector index, or
/// DB-backed filter maps. Status/health surfaces use this to report readiness
/// cheaply; actual semantic search still calls `load_semantic_context`.
pub(crate) fn probe_semantic_availability(data_dir: &Path, db_path: &Path) -> SemanticAvailability {
    probe_semantic_availability_for_embedder(data_dir, db_path, active_policy_embedder_name())
}

/// `true` for the Infinity-served embedder's own names (`bge-m3`/`infinity`
/// -- the same pair `lib.rs`'s CLI dispatch matches on to route to
/// [`load_infinity_semantic_context`]). Every other name is a FastEmbed
/// model.
fn is_infinity_embedder_name(embedder_name: &str) -> bool {
    matches!(embedder_name, "bge-m3" | "infinity")
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
    let conn = storage.raw();
    let active: Option<(String, String)> = conn
        .query_opt_map(
            "SELECT embedder_id, audit_status FROM embedding_generations WHERE is_active = 1",
            &[],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .unwrap_or(None);
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

    let any_generation: i64 = conn
        .query_row_map("SELECT COUNT(*) FROM embedding_generations", &[], |row| row.get_typed(0))
        .unwrap_or(0);
    if any_generation > 0 {
        return SemanticAvailability::IndexBuilding {
            embedder_id: String::new(),
            progress_pct: None,
            items_indexed: 0,
            total_items: 0,
        };
    }

    SemanticAvailability::IndexMissing { index_path: db_path.to_path_buf() }
}

/// Richer DB-vector-domain snapshot for `cass status`'s dedicated section
/// (W3-4 Step2-2, task book #62): same three-state read as
/// [`probe_db_vector_domain_availability`] plus the identity/count/audit
/// detail an operator actually wants from a status surface. This is a
/// parallel, additive status section -- it does not replace or change
/// the existing fsvi-driven `semantic` section, which keeps reporting
/// exactly as it always has during the W3-3..W3-5 coexistence window.
#[derive(Debug, Clone)]
pub(crate) struct DbVectorDomainStatus {
    pub active: bool,
    pub embedder_id: Option<String>,
    pub dim: Option<i64>,
    pub audit_status: Option<String>,
    pub embedded_count: Option<i64>,
    pub any_generation: bool,
}

/// `None` only when the database itself cannot be opened read-only --
/// callers that already know `db_opened` is false should skip calling
/// this rather than treat `None` as a meaningful status of its own.
pub(crate) fn probe_db_vector_domain_status(db_path: &Path) -> Option<DbVectorDomainStatus> {
    let storage = FrankenStorage::open_readonly(db_path).ok()?;
    let conn = storage.raw();
    let active: Option<(i64, String, i64, String)> = conn
        .query_opt_map(
            "SELECT id, embedder_id, dim, audit_status FROM embedding_generations WHERE is_active = 1",
            &[],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?)),
        )
        .ok()
        .flatten();
    if let Some((generation_id, embedder_id, dim, audit_status)) = active {
        let embedded_count: i64 = conn
            .query_row_map(
                "SELECT COUNT(*) FROM message_embeddings WHERE generation_id = ?1",
                &params![generation_id],
                |row| row.get_typed(0),
            )
            .unwrap_or(0);
        return Some(DbVectorDomainStatus {
            active: true,
            embedder_id: Some(embedder_id),
            dim: Some(dim),
            audit_status: Some(audit_status),
            embedded_count: Some(embedded_count),
            any_generation: true,
        });
    }

    let any_generation: i64 = conn
        .query_row_map("SELECT COUNT(*) FROM embedding_generations", &[], |row| row.get_typed(0))
        .unwrap_or(0);
    Some(DbVectorDomainStatus {
        active: false,
        embedder_id: None,
        dim: None,
        audit_status: None,
        embedded_count: None,
        any_generation: any_generation > 0,
    })
}

pub(crate) fn probe_semantic_availability_for_embedder(
    data_dir: &Path,
    db_path: &Path,
    embedder_name: &str,
) -> SemanticAvailability {
    if is_infinity_embedder_name(embedder_name) {
        return probe_db_vector_domain_availability(db_path);
    }
    let canonical_name = FastEmbedder::canonical_name(embedder_name).unwrap_or("minilm");
    let Some(config) = FastEmbedder::config_for(canonical_name) else {
        return SemanticAvailability::LoadFailed {
            context: format!("unknown semantic embedder: {embedder_name}"),
        };
    };
    let Some(model_dir) = FastEmbedder::runtime_model_dir_for(data_dir, canonical_name) else {
        return SemanticAvailability::LoadFailed {
            context: format!("no model directory mapping for semantic embedder: {embedder_name}"),
        };
    };
    let manifest =
        ModelManifest::for_embedder(canonical_name).unwrap_or_else(ModelManifest::minilm_v2);
    let semantic_policy = SemanticPolicy::resolve(&CliSemanticOverrides::default());
    let acquisition_policy = ModelAcquisitionPolicy::from_semantic_policy(&semantic_policy);
    let cache_report = classify_model_cache_metadata(&model_dir, &manifest, &acquisition_policy);

    if let Some(availability) =
        semantic_availability_from_cache_state(&model_dir, &cache_report.state, true)
    {
        return availability;
    }

    let index_path = vector_index_path(data_dir, &config.embedder_id);
    if !index_path.is_file() {
        return SemanticAvailability::IndexMissing { index_path };
    }

    SemanticAvailability::Ready {
        embedder_id: config.embedder_id,
    }
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

/// Load hash-based semantic context.
///
/// W3-5: the legacy fsvi vector-index loading this used to open (monolithic
/// + sharded) has been retired as a builder-without-reader (search-side
/// consumption of `.fsvi` files was already cut in 3f7aa054), and there is
/// no DB-vector-domain writer for the hash embedder either -- `models
/// backfill --embedder hash` was itself retired in 4064e8fc. There is no
/// substrate left to report `Ready` against, so this now always reports the
/// index as missing rather than pretend a stale on-disk `.fsvi` file (which
/// this build can no longer open) is usable.
pub fn load_hash_semantic_context(data_dir: &Path, _db_path: &Path) -> SemanticSetup {
    let embedder = HashEmbedder::default();
    let index_path = vector_index_path(data_dir, embedder.id());
    SemanticSetup {
        availability: SemanticAvailability::IndexMissing { index_path },
        context: None,
    }
}

/// Load Infinity-backed semantic context (M4-pre spike).
///
/// Uses the HTTP `InfinityEmbedder` (bge-m3, 1024-dim) — no local model
/// files / ONNX / cache-state machinery. The query is embedded via the
/// daemon path (Infinity) at search time; this in-proc embedder supplies
/// the matching id/dimension.
///
/// W3-5: DB-vector-domain (`embedding_generations`/`message_embeddings`) is
/// the sole substrate now -- the legacy fsvi-file path this used to fall
/// back to (behind `CASS_SEMANTIC_USE_FSVI`) is retired along with the
/// escape hatch itself, for the same builder-without-reader reason as
/// [`load_hash_semantic_context`].
#[cfg(feature = "infinity")]
pub fn load_infinity_semantic_context(data_dir: &Path, db_path: &Path) -> SemanticSetup {
    let _ = data_dir;
    let embedder = match crate::search::infinity::InfinityEmbedder::new() {
        Ok(e) => e,
        Err(err) => {
            return SemanticSetup {
                availability: SemanticAvailability::LoadFailed {
                    context: format!("infinity embedder: {err}"),
                },
                context: None,
            };
        }
    };

    match probe_db_vector_domain_availability(db_path) {
        SemanticAvailability::Ready { embedder_id } => {
            let roles = Some(HashSet::from([ROLE_USER, ROLE_ASSISTANT]));
            SemanticSetup {
                availability: SemanticAvailability::Ready { embedder_id },
                context: Some(SemanticContext {
                    embedder: Arc::new(embedder) as Arc<dyn Embedder>,
                    roles,
                }),
            }
        }
        other => SemanticSetup {
            availability: other,
            context: None,
        },
    }
}

/// Load semantic context without version checking.
///
/// Use this when you've already acknowledged an update and want to load
/// the model anyway.
pub fn load_semantic_context_no_version_check(data_dir: &Path, db_path: &Path) -> SemanticSetup {
    load_semantic_context_inner(data_dir, db_path, false, active_policy_embedder_name())
}

fn load_semantic_context_inner(
    data_dir: &Path,
    db_path: &Path,
    check_for_updates: bool,
    embedder_name: &str,
) -> SemanticSetup {
    let canonical_name = FastEmbedder::canonical_name(embedder_name).unwrap_or("minilm");
    let Some(config) = FastEmbedder::config_for(canonical_name) else {
        return SemanticSetup {
            availability: SemanticAvailability::LoadFailed {
                context: format!("unknown semantic embedder: {embedder_name}"),
            },
            context: None,
        };
    };
    let Some(model_dir) = FastEmbedder::runtime_model_dir_for(data_dir, canonical_name) else {
        return SemanticSetup {
            availability: SemanticAvailability::LoadFailed {
                context: format!(
                    "no model directory mapping for semantic embedder: {embedder_name}"
                ),
            },
            context: None,
        };
    };
    let manifest =
        ModelManifest::for_embedder(canonical_name).unwrap_or_else(ModelManifest::minilm_v2);
    let semantic_policy = SemanticPolicy::resolve(&CliSemanticOverrides::default());
    let acquisition_policy = ModelAcquisitionPolicy::from_semantic_policy(&semantic_policy);
    let cache_report = classify_model_cache(&model_dir, &manifest, &acquisition_policy);

    if let Some(availability) =
        semantic_availability_from_cache_state(&model_dir, &cache_report.state, check_for_updates)
    {
        return SemanticSetup {
            availability,
            context: None,
        };
    }

    // W3-5: the legacy fsvi vector-index loading this used to open
    // (monolithic + sharded) has been retired as a builder-without-reader,
    // and DB-vector-domain has no writer for non-infinity FastEmbed models
    // either -- `cass index --semantic` was cut over to infinity-only in
    // 4745367f. Model cache validation above still gives a real diagnostic
    // (not installed / downloading / verifying / update available); once
    // the model itself is acquired, there is simply no vector substrate
    // left for it to search against.
    let index_path = vector_index_path(data_dir, &config.embedder_id);
    let _ = db_path;
    SemanticSetup {
        availability: SemanticAvailability::IndexMissing { index_path },
        context: None,
    }
}

fn active_policy_embedder_name() -> &'static str {
    let semantic_policy = SemanticPolicy::resolve(&CliSemanticOverrides::default());
    FastEmbedder::canonical_name(&semantic_policy.quality_tier_embedder).unwrap_or("minilm")
}

fn semantic_availability_from_cache_state(
    model_dir: &Path,
    state: &ModelCacheState,
    check_for_updates: bool,
) -> Option<SemanticAvailability> {
    match state {
        ModelCacheState::Acquired { .. }
        | ModelCacheState::PreseededLocal { .. }
        | ModelCacheState::MirrorSourced { .. } => None,
        ModelCacheState::IncompatibleVersion {
            current_revision,
            expected_revision,
        } if check_for_updates => Some(SemanticAvailability::UpdateAvailable {
            embedder_id: FastEmbedder::embedder_id_static().to_string(),
            current_revision: current_revision.clone(),
            latest_revision: expected_revision.clone(),
        }),
        ModelCacheState::IncompatibleVersion { .. } => None,
        ModelCacheState::NotAcquired {
            missing_files,
            needs_consent,
        } => {
            if *needs_consent {
                Some(SemanticAvailability::NeedsConsent)
            } else {
                Some(SemanticAvailability::ModelMissing {
                    model_dir: model_dir.to_path_buf(),
                    missing_files: missing_files.clone(),
                })
            }
        }
        ModelCacheState::Acquiring {
            bytes_present,
            total_bytes,
            ..
        } => {
            let progress_pct = if *total_bytes == 0 {
                0
            } else {
                ((*bytes_present as f64 / *total_bytes as f64) * 100.0).min(100.0) as u8
            };
            Some(SemanticAvailability::Downloading {
                progress_pct,
                bytes_downloaded: *bytes_present,
                total_bytes: *total_bytes,
            })
        }
        ModelCacheState::ChecksumMismatch {
            file,
            expected,
            actual,
        } => Some(SemanticAvailability::LoadFailed {
            context: format!(
                "model checksum mismatch for {file}: expected {expected}, got {actual}"
            ),
        }),
        ModelCacheState::DisabledByPolicy { reason } => Some(SemanticAvailability::Disabled {
            reason: reason.clone(),
        }),
        ModelCacheState::BudgetBlocked {
            required_bytes,
            max_bytes,
        } => Some(SemanticAvailability::Disabled {
            reason: format!(
                "semantic model requires {required_bytes} bytes but policy allows {max_bytes}"
            ),
        }),
        ModelCacheState::QuarantinedCorrupt {
            marker_path,
            reason,
        } => Some(SemanticAvailability::LoadFailed {
            context: format!(
                "model cache quarantined at {}: {reason}",
                marker_path.display()
            ),
        }),
        ModelCacheState::OfflineBlocked { missing_files } => Some(SemanticAvailability::Disabled {
            reason: format!(
                "offline and semantic model is not acquired: missing {}",
                missing_files.join(", ")
            ),
        }),
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
    let index_path = vector_index_path(data_dir, FastEmbedder::embedder_id_static());

    if index_path.is_file() {
        std::fs::remove_file(&index_path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Get the model directory path for the default MiniLM model.
pub fn default_model_dir(data_dir: &Path) -> PathBuf {
    FastEmbedder::default_model_dir(data_dir)
}

/// Get the model manifest for the default MiniLM model.
pub fn default_model_manifest() -> ModelManifest {
    ModelManifest::minilm_v2()
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
    fn probe_semantic_availability_for_embedder_reports_absent_for_bge_m3_on_an_empty_library() {
        let dir = tempdir().unwrap();
        let db_path = empty_db(dir.path());
        let availability = probe_semantic_availability_for_embedder(dir.path(), &db_path, "bge-m3");
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
            .with_tx_no_replay(TxMode::Immediate, |tx| schema::create_embedding_generation(tx, "BAAI/bge-m3", 1024, 1, 0))
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
    fn probe_semantic_availability_for_embedder_reports_building_for_bge_m3_pre_audit() {
        let dir = tempdir().unwrap();
        let db_path = db_with_active_pending_generation(dir.path());
        let availability = probe_semantic_availability_for_embedder(dir.path(), &db_path, "bge-m3");
        assert!(
            matches!(availability, SemanticAvailability::IndexBuilding { .. }),
            "expected IndexBuilding, got {availability:?}"
        );
    }

    #[cfg(feature = "infinity")]
    #[test]
    fn load_infinity_semantic_context_reports_building_structured_state_pre_audit() {
        let dir = tempdir().unwrap();
        let db_path = db_with_active_pending_generation(dir.path());
        let setup = load_infinity_semantic_context(dir.path(), &db_path);
        assert!(setup.context.is_none(), "a not-yet-certified generation must never hand back a context");
        assert!(
            matches!(setup.availability, SemanticAvailability::IndexBuilding { .. }),
            "expected IndexBuilding, got {:?}",
            setup.availability
        );
    }

    #[cfg(feature = "infinity")]
    #[test]
    fn load_infinity_semantic_context_reports_absent_structured_error_for_an_empty_library() {
        let dir = tempdir().unwrap();
        let db_path = empty_db(dir.path());
        let setup = load_infinity_semantic_context(dir.path(), &db_path);
        assert!(setup.context.is_none(), "an absent domain must never hand back a context");
        assert!(
            matches!(setup.availability, SemanticAvailability::IndexMissing { .. }),
            "expected IndexMissing (absent), got {:?}",
            setup.availability
        );
    }
}
