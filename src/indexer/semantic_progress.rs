//! Progress JSONL sink for quality semantic backfill.
//!
//! When `CASS_SEMANTIC_PROGRESS_JSONL=/abs/path/to/file.jsonl` is set,
//! the semantic backfill code path appends one JSON object per transition
//! event to that file. Each event carries a timestamp, a phase + sub-phase,
//! a row/batch counter where applicable, the wall-time delta since the
//! sink was started, and a cheap RSS estimate.
//!
//! Goal — give operators enough proof, during long-running quality semantic
//! backfill runs, to tell whether time is going to selection, packet
//! replay, embedding, staging, checkpoint, or publish; and to distinguish
//! storage-side stalls from model-inference stalls. See cass#257.
//!
//! Env-var family: matches the existing `CASS_SEMANTIC_*` namespace (see
//! `src/search/policy.rs` and `src/indexer/semantic.rs`). The sink itself
//! is silent when the env var is unset, so it has zero cost for normal
//! operation. Writes are best-effort: a failed write is logged at debug
//! and never propagated upward — we never want telemetry to crash a
//! backfill that would otherwise succeed.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Env var that activates the sink and names the output file.
pub const ENV_PROGRESS_JSONL: &str = "CASS_SEMANTIC_PROGRESS_JSONL";

/// PR8 C8: how often the finalize ticker posts a `finalize_progress`
/// event while a semantic run is draining holes or in its post-drain
/// tail. Overridable so tests do not have to wait a minute per tick.
pub const ENV_FINALIZE_PROGRESS_EVERY_MS: &str = "CASS_SEMANTIC_FINALIZE_PROGRESS_EVERY_MS";

/// Production cadence for the finalize ticker: one event per minute.
pub const DEFAULT_FINALIZE_PROGRESS_EVERY_MS: u64 = 60_000;

/// Schema version for the JSONL event stream. Bump on any
/// breaking change to event names or fields.
pub const PROGRESS_JSONL_SCHEMA: &str = "cass.semantic.progress.v1";

/// The named transition events. Strings deliberately mirror the
/// `phase` + `sub_phase` columns in each emitted record so a `jq` user
/// can filter on event name OR phase as they prefer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticProgressEvent {
    /// Backfill is about to materialize the message-selection query.
    SelectionStart,
    /// Selection finished; downstream knows how many candidate rows
    /// will be considered for this batch.
    SelectionDone,
    /// Canonical packet replay is about to begin (envelope fetch +
    /// per-conversation message materialization + packet build).
    PacketReplayStart,
    /// Periodic per-conversation tick during packet replay so a
    /// stuck conversation does not look like a stuck model.
    PacketReplayProgress,
    /// Packet replay finished — `EmbeddingInput`s are ready.
    PacketReplayDone,
    /// About to call `embedder.embed_batch_sync` for a single batch.
    EmbedBatchStart,
    /// `embedder.embed_batch_sync` returned for this batch.
    EmbedBatchDone,
    /// About to write the embedded vectors into the staging index.
    StagingWriteStart,
    /// Staging write returned.
    StagingWriteDone,
    /// About to fsync the updated manifest with this batch's checkpoint.
    CheckpointSaveStart,
    /// Manifest fsync returned.
    CheckpointSaveDone,
    /// About to atomically rename the staged index into the published
    /// index path (only fires on the batch that completes the tier).
    PublishStart,
    /// Publish rename + fsync done; tier is queryable.
    PublishDone,
    /// Backfill aborted with an error.
    Error,
    /// Backfill cancelled cooperatively (signal, idle-yield, etc).
    Cancelled,
    /// All work finished cleanly (terminal — emitted exactly once per
    /// run, after publish_done or in the no-op path).
    Complete,
    /// PR8 C8: periodic tick covering the semantic run's drain-and-tail
    /// window, where the batch-granular events above have nothing left to
    /// report but the process is still doing real work (lexical
    /// checkpoint, analytics, activation audit). Carries the elapsed
    /// seconds and the named stage, and each tick also refreshes the
    /// index-run lock's forward-progress evidence so an external
    /// `cass status --json` / `cass doctor` observer does not read a
    /// working run as `stalled` (cass#258's stall detector is keyed on
    /// that evidence, and this window used to post none).
    FinalizeProgress,
}

impl SemanticProgressEvent {
    /// Stable snake_case string for the event field. Used both as the
    /// JSONL `event` value and (with `phase()`) as a discriminator in
    /// downstream consumers.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelectionStart => "selection_start",
            Self::SelectionDone => "selection_done",
            Self::PacketReplayStart => "packet_replay_start",
            Self::PacketReplayProgress => "packet_replay_progress",
            Self::PacketReplayDone => "packet_replay_done",
            Self::EmbedBatchStart => "embed_batch_start",
            Self::EmbedBatchDone => "embed_batch_done",
            Self::StagingWriteStart => "staging_write_start",
            Self::StagingWriteDone => "staging_write_done",
            Self::CheckpointSaveStart => "checkpoint_save_start",
            Self::CheckpointSaveDone => "checkpoint_save_done",
            Self::PublishStart => "publish_start",
            Self::PublishDone => "publish_done",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
            Self::Complete => "complete",
            Self::FinalizeProgress => "finalize_progress",
        }
    }

    /// Coarse phase classification, useful to a downstream `jq` consumer
    /// that wants to bucket time across selection / replay / embed /
    /// staging / checkpoint / publish without enumerating every event.
    pub fn phase(self) -> &'static str {
        match self {
            Self::SelectionStart | Self::SelectionDone => "selection",
            Self::PacketReplayStart | Self::PacketReplayProgress | Self::PacketReplayDone => {
                "packet_replay"
            }
            Self::EmbedBatchStart | Self::EmbedBatchDone => "embed",
            Self::StagingWriteStart | Self::StagingWriteDone => "staging",
            Self::CheckpointSaveStart | Self::CheckpointSaveDone => "checkpoint",
            Self::PublishStart | Self::PublishDone => "publish",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
            Self::Complete => "complete",
            Self::FinalizeProgress => "finalize",
        }
    }

    /// `start` / `done` / `progress` / single (sub_phase=`event`).
    pub fn sub_phase(self) -> &'static str {
        match self {
            Self::SelectionStart
            | Self::PacketReplayStart
            | Self::EmbedBatchStart
            | Self::StagingWriteStart
            | Self::CheckpointSaveStart
            | Self::PublishStart => "start",
            Self::SelectionDone
            | Self::PacketReplayDone
            | Self::EmbedBatchDone
            | Self::StagingWriteDone
            | Self::CheckpointSaveDone
            | Self::PublishDone => "done",
            Self::PacketReplayProgress => "progress",
            Self::FinalizeProgress => "progress",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
            Self::Complete => "complete",
        }
    }
}

/// Optional counters carried by an event. Every field is `None` when
/// not applicable — JSON serializers should skip nulls so the row stays
/// readable.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SemanticProgressFields {
    /// Batch index within this backfill run, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_index: Option<u64>,
    /// Rows in the current batch, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_rows: Option<u64>,
    /// Cumulative rows processed so far, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_processed: Option<u64>,
    /// Total rows expected (best-effort).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_total: Option<u64>,
    /// Conversation cursor (per-tier semantic) at this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_conversation_id: Option<i64>,
    /// Message PK cursor at this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_message_id: Option<i64>,
    /// Conversations in the active batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversations_in_batch: Option<u64>,
    /// Free-form context note. Kept short — long context belongs in a
    /// debug log line, not in a high-frequency JSONL event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Bytes touched (e.g. content bytes selected, bytes embedded,
    /// staged write size). Lets operators distinguish a stalled query
    /// from a stalled model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Free-form error string when the event is `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// PR8 C8: the named stage a `finalize_progress` tick is covering
    /// (e.g. `semantic_drain`, `finalize`). Kept as a short label rather
    /// than free prose so a consumer can group ticks by stage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// PR8 C8: whole seconds elapsed since the ticker started. Redundant
    /// with the record's `elapsed_ms` for a `finalize_progress` tick, and
    /// carried anyway because the T6B report asked for a human-scaled
    /// number next to the stage name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct EventRecord<'a> {
    schema: &'static str,
    event: &'static str,
    phase: &'static str,
    sub_phase: &'static str,
    /// Unix milliseconds, wall clock.
    ts_ms: i64,
    /// Milliseconds since this sink was opened.
    elapsed_ms: u64,
    /// Tier label (`fast` / `quality` / `unknown`).
    tier: &'a str,
    /// Embedder id (e.g. `minilm-384`, `hash`).
    embedder_id: &'a str,
    /// Cheap RSS estimate in MiB (None if /proc parse fails or the
    /// platform doesn't expose it).
    #[serde(skip_serializing_if = "Option::is_none")]
    rss_mib: Option<u64>,
    #[serde(flatten)]
    fields: &'a SemanticProgressFields,
}

/// Process-pid, used only for cross-correlation when an operator
/// concatenates JSONL files from multiple runs.
fn current_pid() -> u32 {
    std::process::id()
}

/// Wall-clock Unix milliseconds at the moment of the call.
fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Cheap RSS estimate from /proc/self/status (Linux). Returns None on
/// other platforms or any parse failure. Reading /proc/self/status is
/// a cheap pseudo-file read — safe to call inside the embed batch loop.
fn read_rss_mib() -> Option<u64> {
    let bytes = std::fs::read("/proc/self/status").ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            // Expected format: `VmRSS:    12345 kB`
            let mut parts = rest.split_whitespace();
            let kb_str = parts.next()?;
            let kb: u64 = kb_str.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// Resolve the sink's destination path from the env var.
fn resolve_path() -> Option<PathBuf> {
    let raw = dotenvy::var(ENV_PROGRESS_JSONL).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed))
}

/// Open the sink file (append, create) on first event, cache the
/// handle in a Mutex. We deliberately accept the cost of a Mutex over
/// every event because the JSONL stream is several events per batch,
/// not per row — even a 50ms batch wall-time dwarfs the lock cost.
pub struct SemanticProgressSink {
    inner: Option<Mutex<SinkInner>>,
    tier: String,
    embedder_id: String,
    started: Instant,
}

struct SinkInner {
    file: File,
    /// Cached so we can include it in `complete`/`error` log lines.
    path: PathBuf,
    /// True after we've written at least one record successfully —
    /// lets us suppress repeat "failed to write" warnings.
    healthy: bool,
}

impl SemanticProgressSink {
    /// Open a sink for the given tier+embedder. Returns a no-op sink
    /// when the env var is unset, so callers can always emit events
    /// unconditionally without branching.
    pub fn open(tier: &str, embedder_id: &str) -> Self {
        let path = resolve_path();
        let inner = match path {
            Some(p) => match Self::open_file(&p) {
                Ok(file) => Some(Mutex::new(SinkInner {
                    file,
                    path: p,
                    healthy: false,
                })),
                Err(err) => {
                    tracing::warn!(
                        path = %p.display(),
                        error = %err,
                        "CASS_SEMANTIC_PROGRESS_JSONL: failed to open sink — continuing without progress JSONL",
                    );
                    None
                }
            },
            None => None,
        };
        Self {
            inner,
            tier: tier.to_string(),
            embedder_id: embedder_id.to_string(),
            started: Instant::now(),
        }
    }

    /// Open the sink for a Cass embedder id, labelling the tier the way the
    /// rest of the semantic stack does (`infinity` is the quality tier,
    /// `hash` the fast one). Convenience over [`Self::open`] for callers
    /// that only know the embedder id they just ran with.
    pub fn open_for_embedder(embedder_id: &str) -> Self {
        let tier = match embedder_id {
            "infinity" => "quality",
            "hash" => "fast",
            other => other,
        };
        Self::open(tier, embedder_id)
    }

    /// Sink that never writes — kept as an explicit factory so callers
    /// can default to a sink without consulting the env var (e.g. tests
    /// that don't care about telemetry).
    pub fn disabled() -> Self {
        Self {
            inner: None,
            tier: "unknown".to_string(),
            embedder_id: "unknown".to_string(),
            started: Instant::now(),
        }
    }

    /// True if the sink is actively writing (env var set + file
    /// opened). Callers can branch on this to skip building expensive
    /// `SemanticProgressFields` when no one will read them.
    pub fn is_active(&self) -> bool {
        self.inner.is_some()
    }

    fn open_file(path: &Path) -> std::io::Result<File> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        OpenOptions::new().create(true).append(true).open(path)
    }

    /// Emit one event. Best-effort: a write failure logs at debug and
    /// returns Ok — telemetry never bubbles errors into the backfill.
    pub fn emit(&self, event: SemanticProgressEvent, fields: SemanticProgressFields) {
        let Some(mutex) = self.inner.as_ref() else {
            return;
        };
        let elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let rss_mib = read_rss_mib();
        let record = EventRecord {
            schema: PROGRESS_JSONL_SCHEMA,
            event: event.as_str(),
            phase: event.phase(),
            sub_phase: event.sub_phase(),
            ts_ms: now_unix_ms(),
            elapsed_ms,
            tier: self.tier.as_str(),
            embedder_id: self.embedder_id.as_str(),
            rss_mib,
            fields: &fields,
        };
        let mut line = match serde_json::to_string(&record) {
            Ok(s) => s,
            Err(err) => {
                tracing::debug!(
                    ?err,
                    event = event.as_str(),
                    "skip JSONL emit: serialize failed"
                );
                return;
            }
        };
        line.push('\n');
        // Best-effort write under lock. We intentionally do not propagate
        // errors — a backfill that succeeded but couldn't write telemetry
        // is still a successful backfill.
        let mut guard = match mutex.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Err(err) = guard.file.write_all(line.as_bytes()) {
            if guard.healthy {
                // Surface once on transition healthy→sick to help
                // operators notice (e.g. disk full mid-run).
                tracing::warn!(
                    path = %guard.path.display(),
                    error = %err,
                    "CASS_SEMANTIC_PROGRESS_JSONL: write failed after previous successes; continuing without progress JSONL",
                );
                guard.healthy = false;
            } else {
                tracing::debug!(
                    path = %guard.path.display(),
                    error = %err,
                    "CASS_SEMANTIC_PROGRESS_JSONL: write failed",
                );
            }
        } else {
            guard.healthy = true;
            // We do NOT fsync per-event — sync at end is the operator's
            // job (e.g. shutdown drain). Per-event fsync would dominate
            // wall time on a long run. The file is opened append, so
            // partial writes are tolerable to the reader.
        }
    }

    /// Convenience: emit an event with no extra fields.
    pub fn emit_bare(&self, event: SemanticProgressEvent) {
        self.emit(event, SemanticProgressFields::default());
    }

    /// Process-pid for cross-correlation. Stable for the life of the sink.
    pub fn pid(&self) -> u32 {
        current_pid()
    }
}

/// PR8 C8: periodic `finalize_progress` ticker for a semantic run's
/// drain-and-tail window.
///
/// Why it exists: every event [`SemanticProgressSink`] knows how to emit is
/// batch-granular (`embed_batch_*`, `staging_write_*`). Once the last batch
/// lands, the run still has real work left — the post-drain lexical
/// checkpoint, analytics rebuild and activation audit — and that window
/// posted nothing at all. `cass status` / `cass doctor` read the index-run
/// lock's `last_progress_at_ms` to decide `stalled` (cass#258), so a healthy
/// run in that window was reported as wedged; the exam hall and the frozen
/// corpus both hit it (57 min and 14 min respectively).
///
/// The ticker therefore does two things on every tick, and both matter:
///
/// 1. emits a `finalize_progress` event through the sink (silent when
///    `CASS_SEMANTIC_PROGRESS_JSONL` is unset — the sink is a no-op);
/// 2. stores the current wall clock into the shared forward-progress atomic
///    the index-run lock heartbeat folds into `last_progress_at_ms=`, which
///    is exactly the evidence `asset_state::maintenance_stall_age_ms`
///    consumes. No new stall rule is introduced and no existing one is
///    relaxed for any other window.
///
/// Dropping the guard stops the thread and joins it, so the ticker cannot
/// outlive the run that started it.
pub struct SemanticFinalizeProgressEmitter {
    stop: Arc<AtomicBool>,
    stage: Arc<Mutex<&'static str>>,
    /// Shared with the ticker thread: `set_stage` posts the new stage's
    /// first tick from the calling thread, so the writer has to be usable
    /// from both. `SemanticProgressSink::emit` already serializes on its
    /// own mutex, so two writers is safe by construction.
    sink: Arc<SemanticProgressSink>,
    started: Instant,
    join: Option<JoinHandle<()>>,
}

impl SemanticFinalizeProgressEmitter {
    /// Production cadence, or the test override.
    pub fn interval_from_env() -> Duration {
        Duration::from_millis(
            dotenvy::var(ENV_FINALIZE_PROGRESS_EVERY_MS)
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(DEFAULT_FINALIZE_PROGRESS_EVERY_MS),
        )
    }

    /// Start ticking. `progress_bump` is the index-run lock's
    /// forward-progress atomic; `None` is legitimate for a caller that has
    /// no run lock (the events are then the only output).
    pub fn start(
        sink: SemanticProgressSink,
        progress_bump: Option<Arc<AtomicI64>>,
        interval: Duration,
        stage: &'static str,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stage_cell = Arc::new(Mutex::new(stage));
        let started = Instant::now();
        let sink = Arc::new(sink);
        let stop_flag = Arc::clone(&stop);
        let stage_for_thread = Arc::clone(&stage_cell);
        let sink_for_thread = Arc::clone(&sink);
        let join = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                std::thread::sleep(interval);
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                let stage_now = *stage_for_thread
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let elapsed = started.elapsed();
                sink_for_thread.emit(
                    SemanticProgressEvent::FinalizeProgress,
                    SemanticProgressFields {
                        stage: Some(stage_now.to_string()),
                        elapsed_secs: Some(elapsed.as_secs()),
                        ..Default::default()
                    },
                );
                if let Some(atomic) = progress_bump.as_ref() {
                    atomic.store(now_unix_ms(), Ordering::Relaxed);
                }
            }
        });
        Self {
            stop,
            stage: stage_cell,
            sink,
            started,
            join: Some(join),
        }
    }

    /// Relabel the window this ticker is covering. Callers switch it as the
    /// run crosses from hole-draining into the post-drain tail; the label is
    /// what makes a tick interpretable after the fact. The new stage's first
    /// tick is posted immediately rather than waiting out an interval, so a
    /// stage that turns out to be brief still leaves one line saying the run
    /// reached it.
    pub fn set_stage(&self, stage: &'static str) {
        *self
            .stage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = stage;
        self.sink.emit(
            SemanticProgressEvent::FinalizeProgress,
            SemanticProgressFields {
                stage: Some(stage.to_string()),
                elapsed_secs: Some(self.started.elapsed().as_secs()),
                ..Default::default()
            },
        );
    }

    /// Seconds since the ticker started.
    pub fn elapsed_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

impl Drop for SemanticFinalizeProgressEmitter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // env vars are process-global; serialize tests so concurrent
    // cargo test runs don't trample each other's env state.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn read_lines(path: &Path) -> Vec<String> {
        let f = File::open(path).expect("open jsonl");
        std::io::BufReader::new(f)
            .lines()
            .map_while(Result::ok)
            .collect()
    }

    #[test]
    fn disabled_sink_is_noop() {
        let sink = SemanticProgressSink::disabled();
        assert!(!sink.is_active());
        sink.emit_bare(SemanticProgressEvent::SelectionStart);
        // No panic = pass.
    }

    #[test]
    fn unset_env_is_noop() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: tests are serialized via ENV_LOCK; this is the
        // standard pattern in this crate for env-dependent tests.
        unsafe {
            std::env::remove_var(ENV_PROGRESS_JSONL);
        }
        let sink = SemanticProgressSink::open("quality", "minilm-384");
        assert!(!sink.is_active());
        sink.emit_bare(SemanticProgressEvent::SelectionStart);
    }

    #[test]
    fn writes_one_line_per_event() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("progress.jsonl");
        // SAFETY: tests are serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(ENV_PROGRESS_JSONL, &path);
        }
        let sink = SemanticProgressSink::open("quality", "minilm-384");
        assert!(sink.is_active());
        sink.emit_bare(SemanticProgressEvent::SelectionStart);
        sink.emit(
            SemanticProgressEvent::EmbedBatchDone,
            SemanticProgressFields {
                batch_index: Some(3),
                batch_rows: Some(128),
                rows_processed: Some(384),
                ..Default::default()
            },
        );
        sink.emit_bare(SemanticProgressEvent::Complete);
        drop(sink);

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 3, "expected 3 events; got {:?}", lines);
        assert!(
            lines[0].contains("\"event\":\"selection_start\""),
            "line 0: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("\"event\":\"embed_batch_done\""),
            "line 1: {}",
            lines[1]
        );
        assert!(
            lines[1].contains("\"batch_index\":3"),
            "line 1: {}",
            lines[1]
        );
        assert!(
            lines[2].contains("\"event\":\"complete\""),
            "line 2: {}",
            lines[2]
        );
        // SAFETY: tests serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(ENV_PROGRESS_JSONL);
        }
    }

    #[test]
    fn each_event_has_phase_and_sub_phase() {
        use SemanticProgressEvent::*;
        let all = [
            SelectionStart,
            SelectionDone,
            PacketReplayStart,
            PacketReplayProgress,
            PacketReplayDone,
            EmbedBatchStart,
            EmbedBatchDone,
            StagingWriteStart,
            StagingWriteDone,
            CheckpointSaveStart,
            CheckpointSaveDone,
            PublishStart,
            PublishDone,
            Error,
            Cancelled,
            Complete,
        ];
        assert_eq!(all.len(), 16);
        for event in all {
            assert!(!event.as_str().is_empty(), "{:?}", event);
            assert!(!event.phase().is_empty(), "{:?}", event);
            assert!(!event.sub_phase().is_empty(), "{:?}", event);
        }
    }

    #[test]
    fn invalid_env_var_is_safe_noop() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Whitespace-only env var should be treated as unset rather
        // than as an attempt to write to "" (which would fail). The
        // sink should silently degrade to disabled.
        // SAFETY: tests serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(ENV_PROGRESS_JSONL, "   ");
        }
        let sink = SemanticProgressSink::open("quality", "minilm-384");
        assert!(!sink.is_active());
        // SAFETY: tests serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(ENV_PROGRESS_JSONL);
        }
    }

    // -----------------------------------------------------------------
    // .5.2: agent-facing progress-sink acceptance — ordering, required
    // fields, failure events, schema stability, best-effort write failure.
    // -----------------------------------------------------------------

    /// Emit one record for `event` to a fresh sink and return its parsed
    /// JSON. Serializes env access via `ENV_LOCK`.
    fn one_record(
        event: SemanticProgressEvent,
        fields: SemanticProgressFields,
    ) -> serde_json::Value {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("progress.jsonl");
        // SAFETY: tests serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(ENV_PROGRESS_JSONL, &path);
        }
        let sink = SemanticProgressSink::open("quality", "minilm-384");
        sink.emit(event, fields);
        drop(sink);
        let lines = read_lines(&path);
        // SAFETY: tests serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(ENV_PROGRESS_JSONL);
        }
        assert_eq!(lines.len(), 1, "expected exactly one record");
        serde_json::from_str(&lines[0]).expect("record is valid JSON")
    }

    #[test]
    fn full_backfill_lifecycle_emits_events_in_phase_order() {
        use SemanticProgressEvent::*;
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("progress.jsonl");
        // SAFETY: tests serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(ENV_PROGRESS_JSONL, &path);
        }
        let sink = SemanticProgressSink::open("quality", "minilm-384");
        // The canonical #257 backfill lifecycle.
        let sequence = [
            SelectionStart,
            SelectionDone,
            PacketReplayStart,
            PacketReplayProgress,
            PacketReplayDone,
            EmbedBatchStart,
            EmbedBatchDone,
            StagingWriteStart,
            StagingWriteDone,
            CheckpointSaveStart,
            CheckpointSaveDone,
            PublishStart,
            PublishDone,
            Complete,
        ];
        for ev in sequence {
            sink.emit_bare(ev);
        }
        drop(sink);

        let lines = read_lines(&path);
        // SAFETY: tests serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(ENV_PROGRESS_JSONL);
        }
        assert_eq!(lines.len(), sequence.len(), "one line per emitted event");
        let emitted: Vec<String> = lines
            .iter()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["event"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        let expected: Vec<String> = sequence.iter().map(|e| e.as_str().to_string()).collect();
        assert_eq!(emitted, expected, "events must persist in emit order");
        assert_eq!(emitted.first().unwrap(), "selection_start");
        assert_eq!(emitted.last().unwrap(), "complete");
    }

    #[test]
    fn every_record_carries_the_required_stable_fields() {
        let v = one_record(
            SemanticProgressEvent::EmbedBatchDone,
            SemanticProgressFields {
                batch_index: Some(1),
                rows_processed: Some(64),
                ..Default::default()
            },
        );
        for key in [
            "schema",
            "event",
            "phase",
            "sub_phase",
            "ts_ms",
            "elapsed_ms",
            "tier",
            "embedder_id",
        ] {
            assert!(
                v.get(key).is_some(),
                "record missing required field {key}: {v}"
            );
        }
        assert_eq!(v["event"], "embed_batch_done");
        assert_eq!(v["phase"], "embed");
        assert_eq!(v["tier"], "quality");
        assert_eq!(v["embedder_id"], "minilm-384");
    }

    #[test]
    fn failure_events_serialize_with_their_detail() {
        let err = one_record(
            SemanticProgressEvent::Error,
            SemanticProgressFields {
                error: Some("embed batch OOM".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(err["event"], "error");
        assert_eq!(err["phase"], "error");
        assert_eq!(err["error"], "embed batch OOM");

        let cancelled = one_record(
            SemanticProgressEvent::Cancelled,
            SemanticProgressFields {
                note: Some("operator interrupt".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(cancelled["event"], "cancelled");
        assert_eq!(cancelled["note"], "operator interrupt");
    }

    #[test]
    fn jsonl_schema_version_is_pinned_and_present_in_records() {
        // Pin the schema string so any wire-format change is a deliberate,
        // reviewed break (the .5.2 "schema remains stable" requirement).
        assert_eq!(PROGRESS_JSONL_SCHEMA, "cass.semantic.progress.v1");
        let v = one_record(
            SemanticProgressEvent::SelectionStart,
            SemanticProgressFields::default(),
        );
        assert_eq!(v["schema"], "cass.semantic.progress.v1");
    }

    #[test]
    fn open_failure_degrades_to_disabled_without_panic() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new().unwrap();
        // Point the sink at a path whose PARENT is a regular file, so
        // create_dir_all (and the open) fail: the sink must degrade to a
        // disabled no-op, and emitting must not panic (best-effort).
        let file_as_parent = dir.path().join("not-a-dir");
        std::fs::write(&file_as_parent, b"x").unwrap();
        let bad_path = file_as_parent.join("progress.jsonl");
        // SAFETY: tests serialized via ENV_LOCK.
        unsafe {
            std::env::set_var(ENV_PROGRESS_JSONL, &bad_path);
        }
        let sink = SemanticProgressSink::open("quality", "minilm-384");
        assert!(!sink.is_active(), "open failure must degrade to disabled");
        // Emitting against the degraded sink is a safe no-op.
        sink.emit_bare(SemanticProgressEvent::SelectionStart);
        sink.emit(
            SemanticProgressEvent::Error,
            SemanticProgressFields {
                error: Some("ignored".to_string()),
                ..Default::default()
            },
        );
        // SAFETY: tests serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var(ENV_PROGRESS_JSONL);
        }
    }
}
