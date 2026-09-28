//! PR10 tasks 05 + 06 — `cass sync`.
//!
//! `cass sync --json` is one entry point that pulls configured remote mirrors,
//! ingests local sessions, drains the semantic domain, and reports the whole
//! round as one JSON object whose `exit_code` equals the process exit code.
//!
//! Task 05 built the local entry; task 06 put the mirror stage in front of it.
//! The order is fixed (spec hard constraint 2): read-only preflight, then
//! mirror, then **exactly one** `run_index`, then report. Nothing about the
//! remote result can skip or repeat that one index — not "no sources", not a
//! transfer of zero files, not a failed source.
//!
//! Design boundaries taken from the PR10 spec
//! (`2026-09-27-pr10-incremental-sync-design.md`, hard constraints 1–7):
//!
//! - **One `run_index` call.** The local work goes straight through
//!   `indexer::run_index` with an `IndexingProgress`; the older
//!   `run_index_with_data` wrapper is deliberately *not* used, because it
//!   prints its own stdout and re-reads the sources config.
//! - **The mirror stage is `SyncEngine::sync_source`, per source.** Not the
//!   `run_sources_sync` wrapper, which writes stdout, uses the default data
//!   dir and may index by itself. A source that reports `Ok` can still carry
//!   failed paths, so the status is read from `all_succeeded` *and* every
//!   `PathSyncResult.success`.
//! - **`--no-ingest` reads no config.** Its whole point is to drain derived
//!   holes without touching the corpus, so a corrupt `sources.toml` must not
//!   be able to fail it — and it never reaches the mirror stage either.
//! - **Preconditions are explicit and typed.** Old schema, a config that
//!   does not load, an unreachable Infinity, and a contended
//!   `index-run.lock` are each identified by construction — the lock by
//!   `IndexRunLockBusy`'s type — instead of by pattern-matching an `anyhow`
//!   string after the fact.
//! - **The config is read once.** The validated `SourcesConfig` from the
//!   preflight is the only one this round has; the mirror stage reads it and
//!   the post-index check verifies the indexer saw a working config too, so a
//!   round whose config stopped loading mid-flight fails closed instead of
//!   reporting success.
//! - **A transport that lies is an internal failure.** Every path the
//!   transport called successful must resolve to the mirror directory the
//!   index side derives for it, and that directory must exist. Otherwise the
//!   round still runs its one index (the local half is innocent) and is then
//!   forced to exit 1.
//! - **stdout carries exactly one JSON object.** The report is printed first
//!   and the process is then ended with `CliError::already_reported`, which
//!   makes the top-level handler exit with the report's own code without
//!   printing anything else on stdout. The same serialized line is appended
//!   to `<data_dir>/logs/sync-runs.jsonl` just before it is printed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;

use crate::CliError;
use crate::indexer::{IndexOptions, IndexRunLockBusy, IndexingProgress, IndexingStats, run_index};
use crate::model::cli_error_kind::ErrorKind as CliErrorKind;
use crate::sources::config::{SourceDefinition, SourcesConfig};
// Aliased: this module's own report type is `SyncReport` too, and the two are
// different objects — one describes the round, the other one source's transfer.
use crate::sources::sync::{SyncEngine, SyncReport as TransferReport, mirror_path_under};
use crate::storage::api::Conn;
use crate::storage::schema::{CURRENT_SCHEMA_VERSION, read_user_version};

/// Wire schema tag for the `cass sync` report object.
pub const SYNC_SCHEMA: &str = "cass.sync.v1";

/// Every configured remote mirror succeeded, and local ingest + semantic
/// are ready.
pub const EXIT_READY: i32 = 0;
/// A real indexing / audit / internal failure, or one this build cannot
/// identify further.
pub const EXIT_INTERNAL: i32 = 1;
/// A clearly identified precondition is not satisfied (old schema, invalid
/// config, unreachable Infinity probe). Nothing was indexed.
pub const EXIT_PRECONDITION: i32 = 2;
/// Partial completion: lexical is usable but semantic is not activated, or a
/// configured mirror failed.
pub const EXIT_PARTIAL: i32 = 3;

/// `partial_reasons` entry: a configured mirror source did not fully sync.
pub const REASON_MIRROR_FAILED: &str = "mirror_failed";
/// `partial_reasons` entry: the semantic domain is not activated.
pub const REASON_SEMANTIC_NOT_READY: &str = "semantic_not_ready";

/// `mirror.skip_reason` when the local-only `--no-ingest` mode suppressed the
/// mirror stage (it implies `--no-mirror`).
const MIRROR_SKIPPED_NO_INGEST: &str = "no-ingest";
/// `mirror.skip_reason` when `--no-mirror` was passed explicitly.
const MIRROR_SKIPPED_BY_FLAG: &str = "no-mirror";

/// Per-source status: every configured path of the source transferred.
pub const MIRROR_STATUS_SUCCESS: &str = "success";
/// Per-source status: some paths transferred and some did not.
pub const MIRROR_STATUS_PARTIAL: &str = "partial";
/// Per-source status: no path transferred, or the transfer could not start.
pub const MIRROR_STATUS_FAILED: &str = "failed";

/// `error.message` when the local half of the round is ready but the remote
/// half is not.
const MIRROR_INCOMPLETE: &str = "one or more configured mirror sources did not fully sync; \
     the local index and semantic drain are unaffected";

/// The four fixed stages of a round, in the order they run.
const STAGE_PREFLIGHT: &str = "preflight";
const STAGE_MIRROR: &str = "mirror";
const STAGE_INDEX: &str = "index";
const STAGE_REPORT: &str = "report";

/// A stage that ran to completion.
const STAGE_OK: &str = "ok";
/// A stage that ran and failed.
const STAGE_FAILED: &str = "failed";
/// A stage that was deliberately not run — either a flag suppressed it or an
/// earlier stage stopped the round.
const STAGE_SKIPPED: &str = "skipped";

/// File name of the append-only round log inside `<data_dir>/logs`.
const RUN_LOG_FILE: &str = "sync-runs.jsonl";

/// One `cass sync` round, as it appears on stdout — and, byte for byte, as the
/// line appended to `<data_dir>/logs/sync-runs.jsonl`.
#[derive(Debug, Clone, Serialize)]
pub struct SyncReport {
    pub schema: &'static str,
    /// Identifier for this round. Only used for correlation; it is not a
    /// lock, a watermark, or a completion proof.
    pub run_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub no_ingest: bool,
    pub no_mirror: bool,
    /// The four fixed stages, always in `preflight`, `mirror`, `index`,
    /// `report` order. A stage that never ran keeps `null` timestamps rather
    /// than a fabricated zero-length window.
    pub stages: Vec<SyncStage>,
    pub mirror: MirrorSection,
    pub index: IndexSection,
    /// `IndexingStats::semantic_activated` of the one index run, or `null`
    /// when this run never got as far as indexing.
    pub semantic_activated: Option<bool>,
    /// Machine-readable reasons the round is not `complete`; empty when it is.
    pub partial_reasons: Vec<&'static str>,
    /// True only when `exit_code == 0`.
    pub complete: bool,
    pub error: Option<SyncError>,
    /// The process exit code, repeated here so a consumer reading only
    /// stdout can branch without also capturing the process status.
    pub exit_code: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncError {
    /// Kebab-case kind, from the same vocabulary as the CLI error envelope.
    pub kind: &'static str,
    pub message: String,
}

/// One of the round's four stages.
///
/// Timings cover the stage and nothing else: the phases inside `run_index`
/// keep their own clock (spec, "控制面已裁的接缝").
#[derive(Debug, Clone, Serialize)]
pub struct SyncStage {
    /// `preflight` | `mirror` | `index` | `report`.
    pub name: &'static str,
    /// `null` when the stage never began.
    pub started_at: Option<String>,
    /// `null` when the stage never ran. A stage that ran is always closed by
    /// the time the report is serialized.
    pub finished_at: Option<String>,
    /// `ok` | `failed` | `skipped`.
    pub status: &'static str,
}

/// Mirror stage outcome.
#[derive(Debug, Clone, Serialize)]
pub struct MirrorSection {
    /// Whether this round actually contacted a configured remote source. A
    /// source that transferred zero files still counts — this reports the
    /// attempt, not the file count.
    pub attempted: bool,
    /// Why the stage did not run: `"no-ingest"`, `"no-mirror"`, or `null`
    /// when it would have run.
    pub skip_reason: Option<&'static str>,
    /// One entry per configured **remote** source. A `type = "local"` entry
    /// is a local scan root for the indexer, not a mirror to pull, so it does
    /// not appear here.
    pub sources: Vec<MirrorSourceResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MirrorSourceResult {
    pub name: String,
    /// `success` | `partial` | `failed`, decided by `all_succeeded` **and**
    /// every `PathSyncResult.success` — never by `Ok` alone.
    pub status: &'static str,
    pub paths: Vec<MirrorPathResult>,
    /// Present unless `status` is `success`.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MirrorPathResult {
    /// The mirror directory this path transfers into, as the transport
    /// reported it. For a successful path it is also the directory the index
    /// side must derive and find.
    pub path: String,
    /// The configured remote path (the `sources.toml` spelling), so a failed
    /// entry names the path an operator can act on.
    pub remote_path: String,
    pub success: bool,
    /// Files the transport says it moved. Reported for the operator; nothing
    /// in this module decides an exit code from it (a successful transfer of
    /// zero files is still a successful transfer).
    pub files_transferred: u64,
    pub error: Option<String>,
}

/// The one index run this round performed.
#[derive(Debug, Clone, Serialize)]
pub struct IndexSection {
    /// False when a precondition failed and indexing never started.
    pub started: bool,
    /// The indexer's own stats. `null` when indexing did not start, or when
    /// it failed before publishing stats.
    pub stats: Option<IndexingStats>,
}

/// Entry point for `Commands::Sync`.
///
/// Prints the report on stdout and then returns the `CliError` that makes
/// the process exit with `report.exit_code`, without the top-level handler
/// writing anything more to stdout.
pub fn run_sync(
    db_override: Option<PathBuf>,
    data_dir_override: Option<PathBuf>,
    no_ingest: bool,
    no_mirror: bool,
    structured: bool,
) -> Result<(), CliError> {
    let data_dir = data_dir_override.unwrap_or_else(crate::default_data_dir);
    let mut report = execute(db_override, data_dir.clone(), no_ingest, no_mirror);

    // The fourth stage, and what its window can honestly be.
    //
    // `finished_at` has to be inside the object it stamps, so the window can
    // only close *before* the line is serialized — it therefore covers the
    // round's own bookkeeping up to the moment the report is sealed, and it
    // does **not** cover the real output cost: the serialization, the log
    // append and the write to stdout all happen after both stamps and are not
    // measured by anything. Reading this stage as "how long the report took to
    // emit" would be wrong; it is a marker for "the round stopped working
    // here", which is what the log line needs to be ordered.
    report.stages.push(SyncStage {
        name: STAGE_REPORT,
        started_at: Some(Utc::now_stamp()),
        finished_at: Some(Utc::now_stamp()),
        status: STAGE_OK,
    });

    let line = match serde_json::to_string(&report) {
        Ok(line) => line,
        Err(err) => {
            // A report we cannot serialize is an internal failure; fall back
            // to a minimal envelope so stdout still carries exactly one JSON
            // object.
            let fallback = serde_json::json!({
                "schema": SYNC_SCHEMA,
                "run_id": report.run_id,
                "exit_code": EXIT_INTERNAL,
                "complete": false,
                "error": {
                    "kind": CliErrorKind::EncodeJson.kind_str(),
                    "message": err.to_string(),
                },
            })
            .to_string();
            println!("{fallback}");
            return Err(CliError::already_reported(
                EXIT_INTERNAL,
                CliErrorKind::EncodeJson.kind_str(),
                false,
            ));
        }
    };

    // Hard constraint 7: the round is appended to its log before it is
    // printed, and a log that cannot be written is a warning on stderr — it
    // never rewrites the exit code the round actually earned, and it never
    // produces a second copy of the report on stdout.
    if let Err(err) = append_run_log(&data_dir, &line) {
        eprintln!(
            "cass sync: could not append this round to {}: {err}",
            data_dir.join("logs").join(RUN_LOG_FILE).display()
        );
    }

    if structured {
        println!("{line}");
    } else {
        print_human_summary(&report);
    }

    if report.exit_code == EXIT_READY {
        Ok(())
    } else {
        let kind = report
            .error
            .as_ref()
            .map_or(CliErrorKind::Unknown.kind_str(), |e| e.kind);
        Err(CliError::already_reported(report.exit_code, kind, false))
    }
}

/// Run the round and build the report. Never returns `Err`: every failure is
/// expressed as a report with a non-zero `exit_code`, because the caller
/// must be able to print that report.
fn execute(
    db_override: Option<PathBuf>,
    data_dir: PathBuf,
    no_ingest: bool,
    no_mirror: bool,
) -> SyncReport {
    let started = Utc::now_stamp();
    let db_path = db_override.unwrap_or_else(|| data_dir.join("agent_search.db"));

    let mut report = SyncReport {
        schema: SYNC_SCHEMA,
        run_id: new_run_id(),
        started_at: started.clone(),
        finished_at: String::new(),
        no_ingest,
        no_mirror,
        // `stages` is filled in by `finish`, which is the only place that
        // knows which stages actually ran.
        stages: Vec::new(),
        mirror: MirrorSection {
            attempted: false,
            skip_reason: mirror_skip_reason(no_ingest, no_mirror),
            sources: Vec::new(),
        },
        index: IndexSection {
            started: false,
            stats: None,
        },
        semantic_activated: None,
        partial_reasons: Vec::new(),
        complete: false,
        error: None,
        exit_code: EXIT_INTERNAL,
    };

    // ---- preflight (read-only; no index has started yet) ----------------
    //
    // Order: config, schema, Infinity. All three are "the run could not
    // meaningfully start" checks, so the report can say `index.started =
    // false` truthfully for each of them.
    //
    // The config is loaded here and nowhere else: the same validated value
    // decides the mirror set below and is the thing the post-index check
    // compares against, so a second `SourcesConfig::load()` that swallows
    // its own error can never contradict this one. `--no-ingest` never reads
    // the file at all, which is why the load sits behind that check rather
    // than inside the loader.
    let config = if no_ingest {
        None
    } else {
        match preflight_config() {
            Ok(config) => Some(config),
            Err(err) => {
                return finish(
                    report,
                    EXIT_PRECONDITION,
                    Some(err),
                    preflight_failed(started.clone()),
                );
            }
        }
    };
    if let Some(err) = preflight_schema(&db_path) {
        return finish(
            report,
            EXIT_PRECONDITION,
            Some(err),
            preflight_failed(started.clone()),
        );
    }
    if let Some(err) = preflight_semantic() {
        return finish(
            report,
            EXIT_PRECONDITION,
            Some(err),
            preflight_failed(started.clone()),
        );
    }
    // The `preflight` stage's window is the whole read-only probe block above;
    // it is closed here, before the first thing with a side effect.
    let preflight = closed_stage(STAGE_PREFLIGHT, started, STAGE_OK);

    // ---- mirror ---------------------------------------------------------
    //
    // One `sync_source` call per configured remote source, in config order,
    // continuing past a failing source (hard constraint 4).
    //
    // Only remote sources count. A `type = "local"` entry is a local root for
    // the indexer, not something to pull; treating it as a pending mirror
    // would fail a perfectly healthy round (spec axis S1).
    //
    // Two independent facts come out of here:
    //
    // * `mirror_failed` — at least one configured source did not fully
    //   transfer. It makes the round *partial* (3) when the local half is
    //   otherwise ready, never a reason to skip the local index.
    // * `mirror_root_errors` — a path the transport called successful whose
    //   mirror directory is not the one the index side derives, or is not
    //   there at all. The local half still runs (it is innocent and its
    //   result is what the operator needs), and the round is then forced to
    //   exit 1 (hard constraints 4 and 10).
    let mirror_started = Utc::now_stamp();
    let mut mirror_root_errors: Vec<String> = Vec::new();
    if let (Some(config), false) = (&config, no_mirror) {
        let engine = SyncEngine::new(&data_dir);
        for source in config.remote_sources() {
            report.mirror.attempted = true;
            let (result, mut inconsistencies) = mirror_one_source(&engine, source);
            mirror_root_errors.append(&mut inconsistencies);
            report.mirror.sources.push(result);
        }
    }
    let mirror_failed = report
        .mirror
        .sources
        .iter()
        .any(|source| source.status != MIRROR_STATUS_SUCCESS);
    let mirror_status = if report.mirror.skip_reason.is_some() {
        STAGE_SKIPPED
    } else if mirror_failed || !mirror_root_errors.is_empty() {
        STAGE_FAILED
    } else {
        STAGE_OK
    };
    let mirror = closed_stage(STAGE_MIRROR, mirror_started, mirror_status);

    // ---- index (exactly once) -------------------------------------------
    //
    // The only `run_index` call in this module, and nothing above can reach it
    // conditionally: no source count, no transfer count and no mirror failure
    // feeds a branch around it. The mirror result decides the *exit code*, not
    // whether the local half runs (hard constraint 2).
    let index_started = Utc::now_stamp();
    let progress = Arc::new(IndexingProgress::default());
    let opts = IndexOptions {
        full: false,
        force_rebuild: false,
        watch: false,
        watch_once_paths: None,
        db_path,
        data_dir,
        semantic: true,
        no_ingest,
        embedder: "infinity".to_string(),
        progress: Some(Arc::clone(&progress)),
        watch_interval_secs: 30,
    };
    report.index.started = true;

    let index_outcome = run_index(opts, None);
    let stats = progress.stats.lock().ok().map(|s| s.clone());
    report.semantic_activated = stats.as_ref().and_then(|s| s.semantic_activated);
    // The indexer's own view of the sources config. The preflight above
    // already accepted this file, so a non-empty value here means the config
    // stopped loading *during* the round -- the mirror set this report
    // describes is then no longer the one the round actually indexed
    // against, and the round must not be reported complete (N1).
    let late_config_error = stats.as_ref().and_then(|s| s.sources_config_error.clone());
    report.index.stats = stats;

    let index_ok = index_outcome.is_ok();
    let outcome = match index_outcome {
        Ok(()) => match report.semantic_activated {
            Some(activated) => IndexOutcome::Completed(activated),
            None => IndexOutcome::CompletedWithoutSemanticFact,
        },
        // A contended `index-run.lock` is identified by type, not by the shape
        // of its message (hard constraint 6).
        Err(err) => match err.downcast_ref::<IndexRunLockBusy>() {
            Some(busy) => IndexOutcome::LockBusy(busy.to_string()),
            None => IndexOutcome::Failed(format!("{err:#}")),
        },
    };
    let index = closed_stage(
        STAGE_INDEX,
        index_started,
        if index_ok { STAGE_OK } else { STAGE_FAILED },
    );

    let mirror_root_error = if mirror_root_errors.is_empty() {
        None
    } else {
        Some(mirror_root_errors.join("; "))
    };
    let (exit_code, partial_reasons, error) = classify_round_outcome(
        outcome,
        mirror_failed,
        mirror_root_error.as_deref(),
        late_config_error.as_deref(),
    );
    report.partial_reasons = partial_reasons;
    finish(report, exit_code, error, vec![preflight, mirror, index])
}

/// What the one index run produced, reduced to the facts the exit code
/// depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexOutcome {
    /// `run_index` returned an error.
    Failed(String),
    /// `run_index` could not start because another process holds
    /// `<data_dir>/index-run.lock`. Identified by type
    /// ([`crate::indexer::IndexRunLockBusy`]), never by matching the text.
    LockBusy(String),
    /// `run_index` returned Ok and published `semantic_activated`.
    Completed(bool),
    /// `run_index` returned Ok but published no `semantic_activated` fact at
    /// all, so semantic readiness is unknown.
    CompletedWithoutSemanticFact,
}

/// The sync exit-code decision table for the post-index stage.
///
/// Pure on purpose: this is the branch set the spec pins (hard constraints 5
/// and 6), and it is exercised directly by
/// `tests/w10_sync_local.rs`.
///
/// Returns `(exit_code, partial_reasons, error)`.
pub fn classify_index_outcome(
    outcome: IndexOutcome,
    mirror_failed: bool,
    sources_config_error: Option<&str>,
) -> (i32, Vec<&'static str>, Option<SyncError>) {
    let mut reasons: Vec<&'static str> = Vec::new();
    if mirror_failed {
        reasons.push(REASON_MIRROR_FAILED);
    }
    // The table is matched on `(outcome, late config error)`. Reading it that
    // way keeps the config arm and the semantic arm from having to repeat
    // each other: `Failed` wins because a failed run has no facts to trust,
    // and a late config error wins over both success and partial because the
    // round indexed against a file this report cannot vouch for (N1).
    match (outcome, sources_config_error) {
        (IndexOutcome::Failed(message), _) => (
            EXIT_INTERNAL,
            reasons,
            Some(SyncError {
                kind: CliErrorKind::Index.kind_str(),
                message: format!("index run failed: {message}"),
            }),
        ),
        // Hard constraint 6: a contended index lock is a *precondition*, so it
        // is exit 2 with the same kind an `index-busy` CLI failure carries —
        // and the busy fact reached this table as a type, not as a substring.
        (IndexOutcome::LockBusy(message), _) => (
            EXIT_PRECONDITION,
            reasons,
            Some(SyncError {
                kind: CliErrorKind::IndexBusy.kind_str(),
                message: format!(
                    "the index run could not start because the index lock is held: {message}"
                ),
            }),
        ),
        (_, Some(detail)) => (
            EXIT_INTERNAL,
            reasons,
            Some(SyncError {
                kind: CliErrorKind::Config.kind_str(),
                message: format!(
                    "sources.toml loaded for the preflight but the index run reported a \
                     config error, so this round cannot be reported complete: {detail}"
                ),
            }),
        ),
        (IndexOutcome::Completed(true), None) => {
            if mirror_failed {
                // Lexical + semantic are ready; only the remote half of the
                // round is not. That is exactly the "partial" reading of
                // hard constraint 6.
                (
                    EXIT_PARTIAL,
                    reasons,
                    Some(SyncError {
                        kind: CliErrorKind::Source.kind_str(),
                        message: MIRROR_INCOMPLETE.to_string(),
                    }),
                )
            } else {
                (EXIT_READY, reasons, None)
            }
        }
        (IndexOutcome::Completed(false), None) => {
            reasons.push(REASON_SEMANTIC_NOT_READY);
            let kind = if mirror_failed {
                CliErrorKind::Source.kind_str()
            } else {
                CliErrorKind::SemanticUnavailable.kind_str()
            };
            (
                EXIT_PARTIAL,
                reasons,
                Some(SyncError {
                    kind,
                    message: "indexing finished with lexical data usable but the \
                              semantic domain not activated (holes remain); rerun \
                              `cass sync` to keep draining"
                        .to_string(),
                }),
            )
        }
        // Hard constraint 5: a run that requested semantic indexing but
        // published no `semantic_activated` fact must not report success.
        (IndexOutcome::CompletedWithoutSemanticFact, None) => (
            EXIT_INTERNAL,
            reasons,
            Some(SyncError {
                kind: CliErrorKind::Index.kind_str(),
                message: "the index run returned without publishing \
                          `semantic_activated`, so semantic readiness is unknown"
                    .to_string(),
            }),
        ),
    }
}

/// The round-level decision table: [`classify_index_outcome`] plus the one
/// fact that comes from the mirror stage's *consistency* check rather than
/// from its transfer results.
///
/// A path the transport called successful must resolve to a mirror directory
/// the index side derives and finds (hard constraints 4 and 10). When it does
/// not, the round is an internal failure — exit 1, `error.kind = index` —
/// whatever the index itself did, because the report would otherwise describe
/// a mirror the indexer cannot read.
///
/// One exception: an index that genuinely failed. That failure is the more
/// specific fact about this round, and it is already exit 1 with
/// `error.kind = index`, so it is reported instead of being relabelled.
///
/// The inconsistency otherwise outranks the other arms (`LockBusy`, a late
/// `sources.toml` error, a partial local half) because it is the only one that
/// says the round's own report does not describe the tree the index read. Every
/// one of those arms describes a round that tried to do the right thing and
/// could not; this one describes a round that would have reported success about
/// a mirror the indexer cannot see.
pub fn classify_round_outcome(
    outcome: IndexOutcome,
    mirror_failed: bool,
    mirror_root_error: Option<&str>,
    sources_config_error: Option<&str>,
) -> (i32, Vec<&'static str>, Option<SyncError>) {
    let index_failed = matches!(outcome, IndexOutcome::Failed(_));
    let (exit_code, partial_reasons, error) =
        classify_index_outcome(outcome, mirror_failed, sources_config_error);
    match mirror_root_error {
        Some(_) if index_failed => (exit_code, partial_reasons, error),
        Some(detail) => (
            EXIT_INTERNAL,
            partial_reasons,
            Some(SyncError {
                kind: CliErrorKind::Index.kind_str(),
                message: format!(
                    "the mirror stage reported a successful transfer, but the mirror roots \
                     the index side would read do not agree with it: {detail}"
                ),
            }),
        ),
        None => (exit_code, partial_reasons, error),
    }
}

/// Stamp the finish time, keep the stages that ran, derive `complete`, and
/// return the report.
///
/// `stages` holds `preflight`, `mirror` and `index`; the trailing `report`
/// stage is appended by [`run_sync`], which is the only place that knows when
/// the report itself is finished.
fn finish(
    mut report: SyncReport,
    exit_code: i32,
    error: Option<SyncError>,
    stages: Vec<SyncStage>,
) -> SyncReport {
    report.finished_at = Utc::now_stamp();
    report.stages = stages;
    report.exit_code = exit_code;
    report.complete = exit_code == EXIT_READY;
    report.error = error;
    report
}

/// A stage that began at `started_at` and has now stopped.
fn closed_stage(name: &'static str, started_at: String, status: &'static str) -> SyncStage {
    SyncStage {
        name,
        started_at: Some(started_at),
        finished_at: Some(Utc::now_stamp()),
        status,
    }
}

/// A stage that never began.
fn unstarted_stage(name: &'static str) -> SyncStage {
    SyncStage {
        name,
        started_at: None,
        finished_at: None,
        status: STAGE_SKIPPED,
    }
}

/// The stage list of a round that stopped in its preflight: the probe failed,
/// and neither the mirror nor the index ever began.
fn preflight_failed(started_at: String) -> Vec<SyncStage> {
    vec![
        closed_stage(STAGE_PREFLIGHT, started_at, STAGE_FAILED),
        unstarted_stage(STAGE_MIRROR),
        unstarted_stage(STAGE_INDEX),
    ]
}

// ---------------------------------------------------------------------------
// Mirror stage
// ---------------------------------------------------------------------------

/// Decide one source's status from what the transport reported.
///
/// Hard constraint 4 pins this shape and both halves of it are load-bearing:
/// `SyncReport::all_succeeded` **and** every `PathSyncResult::success` are
/// read, and neither may relax the other. So a report that says it succeeded
/// while carrying a failed path is not `success`, and a report that says it
/// failed while every path succeeded is not `success` either — the two signals
/// disagreeing is precisely the case a single-signal reading would get wrong,
/// in whichever direction the transport happens to be wrong.
///
/// No successful path at all is `failed`; some but not all is `partial`. The
/// empty-path report is the vacuous case of "every path succeeded", and only
/// `all_succeeded` can contradict it then — a source whose `sync_source`
/// returns `Ok` with no paths is not reachable today (`NoPaths` is an `Err`),
/// so this is a floor rather than a live path.
///
/// Narrow and pure on purpose: the control plane's reverse mutation removes
/// one signal or the other, and each of those must turn a test of *this*
/// function red. A CLI fixture cannot do that — its two signals agree.
pub fn mirror_source_status(report: &TransferReport) -> &'static str {
    let all_paths_succeeded = report.path_results.iter().all(|path| path.success);
    let any_path_succeeded = report.path_results.iter().any(|path| path.success);
    if report.all_succeeded && all_paths_succeeded {
        MIRROR_STATUS_SUCCESS
    } else if any_path_succeeded {
        MIRROR_STATUS_PARTIAL
    } else {
        MIRROR_STATUS_FAILED
    }
}

/// Mirror one configured remote source, and check what its report claims.
///
/// Returns the report entry plus any internal-consistency complaints about the
/// paths the transport called successful. A complaining round is not a failure
/// of the transfer — the transfer may even have moved every byte — it means the
/// directory the index side would read is not the one the transfer wrote, which
/// hard constraints 4 and 10 make an internal failure rather than a silent skip.
///
/// The status is read from `all_succeeded` **and** every `PathSyncResult.success`
/// (hard constraint 4): `Ok(report)` is not transfer success. A source with no
/// successful path is `failed`, one with some is `partial`, and only a source
/// where every path succeeded is `success` — so the `Ok` wrapper can never turn
/// a failed path into a green round.
fn mirror_one_source(
    engine: &SyncEngine,
    source: &SourceDefinition,
) -> (MirrorSourceResult, Vec<String>) {
    // The one derivation the write side and the index side share: source
    // definition + data dir -> mirror root, then raw remote path -> directory.
    let mirror_root = engine.mirror_dir(source);
    match engine.sync_source(source) {
        Ok(report) => {
            let mut inconsistencies: Vec<String> = Vec::new();
            let paths: Vec<MirrorPathResult> = report
                .path_results
                .iter()
                .map(|result| {
                    if result.success {
                        let expected = mirror_path_under(&mirror_root, &result.remote_path);
                        if expected != result.local_path {
                            inconsistencies.push(format!(
                                "source `{}` path `{}`: the transport published to {}, but the \
                                 index side derives {} for that path",
                                source.name,
                                result.remote_path,
                                result.local_path.display(),
                                expected.display()
                            ));
                        } else if !expected.is_dir() {
                            inconsistencies.push(format!(
                                "source `{}` path `{}`: the transport reported success but its \
                                 mirror directory {} does not exist",
                                source.name,
                                result.remote_path,
                                expected.display()
                            ));
                        }
                    }
                    MirrorPathResult {
                        path: result.local_path.display().to_string(),
                        remote_path: result.remote_path.clone(),
                        success: result.success,
                        files_transferred: result.files_transferred,
                        error: result.error.clone(),
                    }
                })
                .collect();

            let status = mirror_source_status(&report);
            let error = (status != MIRROR_STATUS_SUCCESS).then(|| summarize_path_failures(&paths));
            (
                MirrorSourceResult {
                    name: source.name.clone(),
                    status,
                    paths,
                    error,
                },
                inconsistencies,
            )
        }
        // The transfer never started. The source is still reported per
        // configured path so a consumer always sees `success = false` with the
        // reason, rather than an empty array it has to interpret.
        Err(err) => {
            let message = err.to_string();
            let paths = source
                .paths
                .iter()
                .map(|remote_path| MirrorPathResult {
                    path: mirror_path_under(&mirror_root, remote_path)
                        .display()
                        .to_string(),
                    remote_path: remote_path.clone(),
                    success: false,
                    files_transferred: 0,
                    error: Some(message.clone()),
                })
                .collect();
            (
                MirrorSourceResult {
                    name: source.name.clone(),
                    status: MIRROR_STATUS_FAILED,
                    paths,
                    error: Some(message),
                },
                Vec::new(),
            )
        }
    }
}

/// One sentence naming every path that did not transfer, for the source-level
/// `error`.
fn summarize_path_failures(paths: &[MirrorPathResult]) -> String {
    let failed: Vec<&MirrorPathResult> = paths.iter().filter(|path| !path.success).collect();
    if failed.is_empty() {
        return "the source reported failure without naming a path".to_string();
    }
    let mut message = format!(
        "{} of {} configured path(s) failed",
        failed.len(),
        paths.len()
    );
    for path in failed {
        message.push_str(&format!(
            "; {}: {}",
            path.remote_path,
            path.error.as_deref().unwrap_or("no error recorded")
        ));
    }
    message
}

fn mirror_skip_reason(no_ingest: bool, no_mirror: bool) -> Option<&'static str> {
    if no_ingest {
        Some(MIRROR_SKIPPED_NO_INGEST)
    } else if no_mirror {
        Some(MIRROR_SKIPPED_BY_FLAG)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Preflight probes
// ---------------------------------------------------------------------------

/// Load and validate `sources.toml` for the normal (ingesting) path.
///
/// A missing file is a legitimate empty config. An existing file that fails
/// to read, parse, or validate is exit 2 — the alternative (index only HOME
/// and call it a success) is exactly the silent-partial-result the spec
/// forbids.
///
/// Exactly one load happens per round, and the validated value is the one the
/// mirror stage reads. Loading again later (and swallowing that error) would
/// let the report describe a different config than the round indexed against
/// (N1), so there is deliberately no second read anywhere in this module.
///
/// `CASS_IGNORE_SOURCES_CONFIG` is **refused** rather than honoured: the
/// indexer skips the config under that variable, so accepting it here would
/// let a corrupt `sources.toml` produce a "complete" round that never looked
/// at it (S2). `--no-ingest` is the supported way to run without the config,
/// and it never reaches this function.
fn preflight_config() -> Result<SourcesConfig, SyncError> {
    if dotenvy::var("CASS_IGNORE_SOURCES_CONFIG").is_ok() {
        return Err(SyncError {
            kind: CliErrorKind::Config.kind_str(),
            message: "CASS_IGNORE_SOURCES_CONFIG is set, so the indexer would skip \
                      sources.toml entirely; a normal `cass sync` refuses to report \
                      success without validating the configured sources. Unset it, or \
                      use `--no-ingest` for the read-only hole-draining path."
                .to_string(),
        });
    }
    match SourcesConfig::load() {
        Ok(config) => Ok(config),
        Err(err) => Err(SyncError {
            kind: CliErrorKind::Config.kind_str(),
            message: format!("sources.toml exists but did not load: {err}"),
        }),
    }
}

/// Reject a database whose `user_version` this binary cannot open in place.
///
/// Rebuild-only is the project-wide contract (v5 onward): every version
/// below current is rejected, and so is a newer one this binary would
/// silently mis-read. A `user_version = 0` *empty* file is left alone — that
/// is what a fresh install looks like, and `run_index` will initialize it.
fn preflight_schema(db_path: &Path) -> Option<SyncError> {
    if !db_path.exists() {
        return None;
    }
    let conn = Conn::open_read(db_path).ok()?;
    let version = read_user_version(&conn).ok()?;
    let empty = conn
        .query_row_map("SELECT count(*) FROM sqlite_master;", &[], |row| {
            row.get_typed::<i64>(0)
        })
        .map(|count| count == 0)
        .unwrap_or(false);
    let _ = conn.close();

    if version == CURRENT_SCHEMA_VERSION {
        return None;
    }
    if version == 0 && empty {
        // Fresh, un-initialized database file: `run_index` will build it.
        return None;
    }
    Some(SyncError {
        kind: CliErrorKind::RebuildError.kind_str(),
        message: format!(
            "database {} is at schema version {version}, but this build requires \
             {CURRENT_SCHEMA_VERSION}; this is rebuild-only (no in-place migration)",
            db_path.display()
        ),
    })
}

/// Probe the semantic backend before indexing.
///
/// `run_index --semantic` probes Infinity itself and returns an `anyhow`
/// error whose text is the only signal; classifying *that* string after the
/// fact is the pattern the spec bans. Probing here — with the same
/// purpose-built probe, whose own doc comment already calls a missing
/// identity a precondition failure — makes "Infinity is unreachable" a
/// typed exit 2 by construction.
///
/// Infinity *is* the semantic backend in this fork — the fsvi/ONNX tier was
/// retired in W3-5 (`src/indexer/mod.rs`'s `#[cfg(not(feature =
/// "infinity"))]` arm says the same thing to `run_index`). The two arms below
/// are therefore the same precondition reached two ways, not a degraded
/// fallback: a build without the feature has no probe to run, so it fails
/// here, before the mirror stage and before the index, rather than compiling
/// the call away or letting the round report success.
#[cfg(feature = "infinity")]
fn preflight_semantic() -> Option<SyncError> {
    let config = crate::search::infinity::InfinityConfig::from_env();
    match crate::search::infinity::probe_served_embed_identity(&config) {
        Ok(_) => None,
        Err(err) => Some(SyncError {
            kind: CliErrorKind::SemanticUnavailable.kind_str(),
            message: format!(
                "Infinity at {} did not answer the embed-identity probe: {err}",
                config.base_url
            ),
        }),
    }
}

/// The same precondition for a build compiled without the `infinity` feature.
///
/// There is nothing to probe and no semantic tier this build could activate,
/// so `cass sync` — which requires semantic readiness — cannot start a round
/// at all. Same kind and same exit code as an unreachable Infinity; the
/// fixed message points at the build rather than at a server, because
/// retrying the network cannot fix it.
#[cfg(not(feature = "infinity"))]
fn preflight_semantic() -> Option<SyncError> {
    Some(SyncError {
        kind: CliErrorKind::SemanticUnavailable.kind_str(),
        message: "this build has no semantic backend: it was compiled without the \
                  `infinity` feature, and the fsvi/ONNX semantic tier was retired in \
                  W3-5; rebuild with --no-default-features --features \
                  qr,encryption,infinity to run `cass sync`"
            .to_string(),
    })
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn print_human_summary(report: &SyncReport) {
    let status = match report.exit_code {
        EXIT_READY => "ready",
        EXIT_PRECONDITION => "not started (precondition)",
        EXIT_PARTIAL => "partial",
        _ => "failed",
    };
    println!("sync {status} (exit {})", report.exit_code);
    println!("  run_id: {}", report.run_id);
    println!("  started: {}", report.started_at);
    println!("  finished: {}", report.finished_at);
    println!(
        "  mirror: {} source(s), skipped={}",
        report.mirror.sources.len(),
        report
            .mirror
            .skip_reason
            .map_or_else(|| "no".to_string(), |r| format!("yes ({r})"))
    );
    println!(
        "  index: started={} semantic_activated={}",
        report.index.started,
        report
            .semantic_activated
            .map_or_else(|| "unknown".to_string(), |v| v.to_string())
    );
    if let Some(stats) = &report.index.stats {
        println!(
            "  conversations={} messages={} scan_invocations={}",
            stats.total_conversations, stats.total_messages, stats.scan_invocations
        );
    }
    if !report.partial_reasons.is_empty() {
        println!("  partial_reasons: {}", report.partial_reasons.join(", "));
    }
    if let Some(err) = &report.error {
        println!("  error: {} — {}", err.kind, err.message);
    }
}

struct Utc;

impl Utc {
    /// RFC 3339 with microseconds and a `+00:00` offset, matching the rest
    /// of the robot surfaces.
    fn now_stamp() -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
    }
}

// ---------------------------------------------------------------------------
// Round log
// ---------------------------------------------------------------------------

/// Append one round to `<data_dir>/logs/sync-runs.jsonl`.
///
/// `line` is the exact serialization that goes to stdout (hard constraint 7):
/// one round is one line, and the two copies cannot drift because there is
/// only one serialization. The directory is private (0700) and the file is
/// private (0600) on Unix; the platform-specific calls are `#[cfg]`-gated so a
/// Windows build still compiles.
///
/// Concurrent rounds are expected (hard constraint 13 puts no lock between the
/// mirror and the index, and nothing serializes two `cass sync` processes), so
/// the whole record is built first and appended under a short-lived exclusive
/// lock on this file. Both halves matter and the body below says why.
///
/// Timing is not part of this function's contract — the caller writes the log
/// *before* printing, and a failure to write is the caller's to report as a
/// warning. Nothing here can change the round's exit code.
///
/// `pub` for the same reason the other narrow functions in this module are:
/// the concurrency contract above is a claim about this function, and the only
/// honest way to test it is to call it — a CLI round cannot hold the lock at a
/// chosen moment.
pub fn append_run_log(data_dir: &Path, line: &str) -> std::io::Result<()> {
    use fs2::FileExt;
    use std::io::Write;

    let dir = data_dir.join("logs");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let path = dir.join(RUN_LOG_FILE);
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    #[cfg(unix)]
    {
        // `mode` only applies when the file is created; an operator (or an
        // older build) may have left it looser, and the contract is that the
        // round log is 0600 whatever it was before.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    // One record, one `write_all` — never the JSON and then the newline as two
    // calls. Two calls interleave under `O_APPEND` (`{a}{b}\n\n`); the sibling
    // writer `src/doctor_runs.rs::append_action` documents and fixed exactly
    // that shape (its Pass-11 note), and this follows it.
    let mut record = String::with_capacity(line.len() + 1);
    record.push_str(line);
    record.push('\n');

    // A single `write_all` is not enough here, and the difference from
    // `append_action` is the record size. That one is bounded well under
    // PIPE_BUF, which is what makes one `write` all-or-nothing on Linux; a
    // `cass.sync.v1` report grows with the number of configured sources and
    // has no such bound, and above PIPE_BUF the kernel is free to split the
    // write and another appender can land inside the split. So the append
    // takes a short-lived exclusive lock on the log file itself and releases
    // it as soon as the record is in — it does not wrap the mirror stage, the
    // index or anything else in the round.
    FileExt::lock_exclusive(&file)?;
    let written = file
        .write_all(record.as_bytes())
        .and_then(|()| file.flush());
    // Released explicitly rather than left to `drop`, so that the next round's
    // writer is unblocked even when this one failed, and so the release is a
    // fact this function reports rather than a side effect nobody sees.
    let released = FileExt::unlock(&file);
    written.and(released)
}

/// A round identifier: UTC stamp plus pid, so two runs that start in the
/// same microsecond in different processes still differ.
fn new_run_id() -> String {
    format!(
        "sync-{}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.6fZ"),
        std::process::id()
    )
}
