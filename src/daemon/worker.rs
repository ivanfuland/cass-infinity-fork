//! Background embedding worker for the daemon.
//!
//! Processes embedding jobs on a dedicated thread using sync primitives.
//! Adapted from xf's async worker to cass's sync daemon architecture.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use tracing::{error, info, warn};

#[cfg(test)]
use crate::indexer::semantic::{message_id_from_db, saturating_u32_from_i64};
use crate::storage::sqlite::FrankenStorage;

const HASH_EMBEDDER_MODEL: &str = "hash";
const DEFAULT_SEMANTIC_MODEL: &str = "minilm";

/// How an embedding pass ended: normally, or via a user cancel (which must be
/// recorded as cancelled, not failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmbeddingPassOutcome {
    Completed,
    Cancelled,
}

/// Configuration for a single embedding job.
#[derive(Debug, Clone)]
pub struct EmbeddingJobConfig {
    pub db_path: String,
    pub index_path: String,
    pub two_tier: bool,
    pub fast_model: Option<String>,
    pub quality_model: Option<String>,
}

impl EmbeddingJobConfig {
    fn fast_pass_model(&self) -> String {
        self.fast_model
            .clone()
            .unwrap_or_else(|| HASH_EMBEDDER_MODEL.to_string())
    }

    fn quality_pass_model(&self) -> String {
        self.quality_model
            .clone()
            .unwrap_or_else(|| DEFAULT_SEMANTIC_MODEL.to_string())
    }

    fn single_pass_model(&self) -> String {
        self.quality_model
            .clone()
            .or_else(|| self.fast_model.clone())
            .unwrap_or_else(|| HASH_EMBEDDER_MODEL.to_string())
    }
}

/// Messages sent to the background worker.
#[derive(Debug)]
pub enum WorkerMessage {
    /// Submit a new embedding job.
    Submit(EmbeddingJobConfig),
    /// Cancel jobs for a db_path, optionally filtered by model_id.
    Cancel {
        db_path: String,
        model_id: Option<String>,
    },
    /// Shut down the worker thread.
    Shutdown,
}

/// The (db_path, model) pass the worker thread is currently embedding, used
/// by the handle to decide whether a cancel targets the running job or only
/// needs database-level cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunningEmbeddingPass {
    db_path: String,
    model: String,
}

/// Handle for sending messages to the background worker.
#[derive(Clone)]
pub struct EmbeddingWorkerHandle {
    sender: Sender<WorkerMessage>,
    /// Shared cancel flag — set directly from the handle so cancellation
    /// takes effect even while `process_job` is running on the worker thread.
    cancel_flag: Arc<AtomicBool>,
    /// The pass currently running on the worker thread, if any.
    running_pass: Arc<Mutex<Option<RunningEmbeddingPass>>>,
}

impl EmbeddingWorkerHandle {
    /// Submit an embedding job to the worker.
    pub fn submit(&self, config: EmbeddingJobConfig) -> Result<(), String> {
        self.sender
            .send(WorkerMessage::Submit(config))
            .map_err(|e| format!("worker channel closed: {e}"))
    }

    /// Cancel embedding jobs for a db_path.
    ///
    /// Sets the cancel flag directly — but only when the worker is currently
    /// running a pass for that `db_path` (and `model_id`, when given) — so a
    /// cancel aimed at one data dir can never abort another client's job.
    /// Always sends a Cancel message for database-level cleanup.
    pub fn cancel(&self, db_path: String, model_id: Option<String>) -> Result<(), String> {
        let targets_running_job = self
            .running_pass
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .is_some_and(|running| {
                running.db_path == db_path
                    && model_id
                        .as_deref()
                        .is_none_or(|model| running.model == model)
            });
        if targets_running_job {
            self.cancel_flag.store(true, Ordering::SeqCst);
        }
        self.sender
            .send(WorkerMessage::Cancel { db_path, model_id })
            .map_err(|e| format!("worker channel closed: {e}"))
    }

    /// Request the worker to shut down.
    pub fn shutdown(&self) -> Result<(), String> {
        self.sender
            .send(WorkerMessage::Shutdown)
            .map_err(|e| format!("worker channel closed: {e}"))
    }
}

/// Background embedding worker that processes jobs on a dedicated thread.
pub struct EmbeddingWorker {
    receiver: Receiver<WorkerMessage>,
    cancel_flag: Arc<AtomicBool>,
    running_pass: Arc<Mutex<Option<RunningEmbeddingPass>>>,
}

fn saturating_i64_from_usize(raw: usize) -> i64 {
    i64::try_from(raw).unwrap_or(i64::MAX)
}

impl EmbeddingWorker {
    /// Create a new worker and its handle.
    pub fn new() -> (Self, EmbeddingWorkerHandle) {
        let (sender, receiver) = std::sync::mpsc::channel();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let running_pass = Arc::new(Mutex::new(None));
        let handle = EmbeddingWorkerHandle {
            sender,
            cancel_flag: Arc::clone(&cancel_flag),
            running_pass: Arc::clone(&running_pass),
        };
        let worker = Self {
            receiver,
            cancel_flag,
            running_pass,
        };
        (worker, handle)
    }

    /// Run the worker loop (blocking). Call from a spawned thread.
    pub fn run(self) {
        info!("Embedding worker started");
        while let Ok(msg) = self.receiver.recv() {
            match msg {
                WorkerMessage::Submit(config) => {
                    self.cancel_flag.store(false, Ordering::SeqCst);
                    info!(db_path = %config.db_path, two_tier = config.two_tier, "Processing embedding job");
                    if let Err(e) = self.process_job(&config) {
                        error!(db_path = %config.db_path, error = %e, "Embedding job failed");
                    }
                }
                WorkerMessage::Cancel { db_path, model_id } => {
                    // The cancel_flag is already set by the handle (so the running
                    // job sees it immediately). This handler performs DB cleanup.
                    info!(%db_path, ?model_id, "Processing cancel — flag already set by handle");
                    // Cancel in the database
                    if let Err(e) = Self::cancel_in_db(&db_path, model_id.as_deref()) {
                        warn!(%db_path, error = %e, "Failed to cancel jobs in database");
                    }
                }
                WorkerMessage::Shutdown => {
                    info!("Embedding worker shutting down");
                    break;
                }
            }
        }
        info!("Embedding worker stopped");
    }

    /// Cancel jobs in the database.
    fn cancel_in_db(db_path: &str, model_id: Option<&str>) -> anyhow::Result<()> {
        // w1b Task B8 (d16, open-consumer audit): write path.
        let storage = FrankenStorage::open_writer(Path::new(db_path))?;
        storage.cancel_embedding_jobs(db_path, model_id)?;
        Ok(())
    }

    /// Process a single embedding job.
    fn process_job(&self, config: &EmbeddingJobConfig) -> anyhow::Result<()> {
        let db_path = Path::new(&config.db_path);
        let index_path = Path::new(&config.index_path);

        // Open storage and fetch messages
        // w1b Task B8 (d16, open-consumer audit): write path (job lifecycle).
        let storage = FrankenStorage::open_writer(db_path)?;
        let messages = storage.fetch_messages_for_embedding()?;
        let total_docs = saturating_i64_from_usize(messages.len());

        if total_docs == 0 {
            info!(db_path = %config.db_path, "No messages to embed");
            return Ok(());
        }

        info!(
            db_path = %config.db_path,
            total_docs,
            two_tier = config.two_tier,
            "Found messages to embed"
        );

        // Determine which passes to run
        let passes = self.build_passes(config);

        for (model_name, use_semantic) in &passes {
            if self.cancel_flag.load(Ordering::SeqCst) {
                info!("Embedding job cancelled");
                return Ok(());
            }

            let job_id = storage.upsert_embedding_job(&config.db_path, model_name, total_docs)?;
            storage.start_embedding_job(job_id)?;

            if let Ok(mut guard) = self.running_pass.lock() {
                *guard = Some(RunningEmbeddingPass {
                    db_path: config.db_path.clone(),
                    model: model_name.clone(),
                });
            }
            let pass_result = self.generate_embeddings_and_save(
                &storage,
                &messages,
                model_name,
                *use_semantic,
                job_id,
                index_path,
            );
            if let Ok(mut guard) = self.running_pass.lock() {
                *guard = None;
            }

            match pass_result {
                Ok(EmbeddingPassOutcome::Completed) => {
                    storage.complete_embedding_job(job_id)?;
                    info!(model = model_name, "Embedding pass completed");
                }
                Ok(EmbeddingPassOutcome::Cancelled) => {
                    // A user cancel is not a failure — record it as cancelled
                    // so job status matches what actually happened.
                    let _ = storage.cancel_embedding_jobs(&config.db_path, Some(model_name));
                    info!(model = model_name, "Embedding pass cancelled");
                    return Ok(());
                }
                Err(e) => {
                    let err_msg = format!("{e:#}");
                    storage.fail_embedding_job(job_id, &err_msg)?;
                    warn!(model = model_name, error = %e, "Embedding pass failed");
                }
            }
        }

        Ok(())
    }

    /// Determine the embedding passes to run based on config.
    fn build_passes(&self, config: &EmbeddingJobConfig) -> Vec<(String, bool)> {
        let mut passes = Vec::new();

        if config.two_tier {
            // Fast hash pass
            let fast = config.fast_pass_model();
            passes.push((fast, false));

            // Quality semantic pass
            let quality = config.quality_pass_model();
            passes.push((quality, true));
        } else {
            // Single pass with best available
            let model = config.single_pass_model();
            let is_semantic = model != HASH_EMBEDDER_MODEL;
            passes.push((model, is_semantic));
        }

        passes
    }

    /// W3-5: the daemon's fsvi-backed embedding job runner is retired along
    /// with frankensearch (this path built the two-tier fast/hash + quality
    /// passes, `build_passes`, that fed the now-dead two-tier progressive
    /// search index -- and the single-pass mode had no other consumer once
    /// fsvi itself is gone). No DB-vector-domain equivalent is wired here
    /// (OQ3 judgment: `cass models backfill --embedder infinity` /
    /// `cass index --semantic` are the supported catch-up entry points now;
    /// not expanding scope to give the daemon socket RPC its own).
    fn generate_embeddings_and_save(
        &self,
        _storage: &FrankenStorage,
        _messages: &[crate::storage::sqlite::MessageForEmbedding],
        model_name: &str,
        _use_semantic: bool,
        _job_id: i64,
        _index_path: &Path,
    ) -> anyhow::Result<EmbeddingPassOutcome> {
        anyhow::bail!(
            "embedding daemon pass for model '{model_name}' is retired (W3-5, \
             frankensearch/fsvi removed); use `cass models backfill --embedder infinity` \
             or `cass index --semantic` instead"
        );
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_pass_config(
        two_tier: bool,
        fast_model: Option<&str>,
        quality_model: Option<&str>,
    ) -> EmbeddingJobConfig {
        EmbeddingJobConfig {
            db_path: String::new(),
            index_path: String::new(),
            two_tier,
            fast_model: fast_model.map(str::to_string),
            quality_model: quality_model.map(str::to_string),
        }
    }

    #[test]
    fn cancel_only_flags_matching_running_pass() {
        let (worker, handle) = EmbeddingWorker::new();
        if let Ok(mut guard) = worker.running_pass.lock() {
            *guard = Some(RunningEmbeddingPass {
                db_path: "/data/a.db".to_string(),
                model: "minilm".to_string(),
            });
        }

        // Different db_path: must not abort the running job.
        assert!(handle.cancel("/data/b.db".to_string(), None).is_ok());
        assert!(
            !worker.cancel_flag.load(Ordering::SeqCst),
            "cancel for another db_path must not flag the running job"
        );

        // Same db_path but different model: must not abort the running pass.
        assert!(
            handle
                .cancel("/data/a.db".to_string(), Some("hash".to_string()))
                .is_ok()
        );
        assert!(
            !worker.cancel_flag.load(Ordering::SeqCst),
            "cancel for another model must not flag the running pass"
        );

        // Matching target: flags the running job.
        assert!(
            handle
                .cancel("/data/a.db".to_string(), Some("minilm".to_string()))
                .is_ok()
        );
        assert!(
            worker.cancel_flag.load(Ordering::SeqCst),
            "cancel matching the running pass must set the flag"
        );
    }

    #[test]
    fn test_worker_handle_clone() {
        let (_worker, handle) = EmbeddingWorker::new();
        let handle2 = handle.clone();
        // Both handles should be able to send
        assert!(handle.shutdown().is_ok());
        // Second handle will fail since receiver got Shutdown and loop ended
        // But the channel itself is still open until worker drops
        drop(handle2);
    }

    #[test]
    fn test_job_config() {
        let config = EmbeddingJobConfig {
            db_path: "/tmp/test.db".to_string(),
            index_path: "/tmp/test_index".to_string(),
            two_tier: true,
            fast_model: Some("hash".to_string()),
            quality_model: Some("minilm".to_string()),
        };
        assert!(config.two_tier);
        assert_eq!(config.fast_model.as_deref(), Some("hash"));
        assert_eq!(config.quality_model.as_deref(), Some("minilm"));
    }

    #[test]
    fn test_build_passes_single() {
        let (_worker, _handle) = EmbeddingWorker::new();
        let config = build_pass_config(false, None, Some("minilm"));
        let passes = _worker.build_passes(&config);
        assert_eq!(passes.len(), 1);
        assert_eq!(passes[0].0, "minilm");
        assert!(passes[0].1); // semantic
    }

    #[test]
    fn test_build_passes_two_tier() {
        let (_worker, _handle) = EmbeddingWorker::new();
        let config = build_pass_config(true, Some("hash"), Some("minilm"));
        let passes = _worker.build_passes(&config);
        assert_eq!(passes.len(), 2);
        assert_eq!(passes[0].0, "hash");
        assert!(!passes[0].1); // not semantic
        assert_eq!(passes[1].0, "minilm");
        assert!(passes[1].1); // semantic
    }

    #[test]
    fn test_build_passes_defaults() {
        let (_worker, _handle) = EmbeddingWorker::new();
        let config = build_pass_config(false, None, None);
        let passes = _worker.build_passes(&config);
        assert_eq!(passes.len(), 1);
        assert_eq!(passes[0].0, "hash");
        assert!(!passes[0].1); // hash is not semantic
    }

    #[test]
    fn test_message_id_from_db_rejects_negative_ids() {
        assert_eq!(message_id_from_db(-1), None);
        assert_eq!(message_id_from_db(0), Some(0));
        assert_eq!(message_id_from_db(42), Some(42));
    }

    #[test]
    fn test_saturating_u32_from_i64_clamps_bounds() {
        assert_eq!(saturating_u32_from_i64(-7), 0);
        assert_eq!(saturating_u32_from_i64(0), 0);
        assert_eq!(saturating_u32_from_i64(7), 7);
        assert_eq!(saturating_u32_from_i64(i64::from(u32::MAX) + 123), u32::MAX);
    }

    #[test]
    fn test_saturating_i64_from_usize_clamps_overflow() {
        assert_eq!(saturating_i64_from_usize(0), 0);
        assert_eq!(saturating_i64_from_usize(7), 7);
        assert_eq!(
            saturating_i64_from_usize(usize::MAX),
            i64::try_from(usize::MAX).unwrap_or(i64::MAX)
        );
    }

    // W3-5: test_resolve_embedder_kind_* tests deleted (delete bucket) --
    // asserted on `resolve_embedder_kind`/`WorkerEmbedderKind`, deleted
    // alongside `generate_embeddings_and_save` (their sole production
    // consumer, retired with frankensearch/fsvi).
}
