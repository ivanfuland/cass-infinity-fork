//! PR10 task 05 — the local half of `cass sync`.
//!
//! `cass sync --json` is one entry point that (eventually) pulls configured
//! remote mirrors, ingests local sessions, drains the semantic domain, and
//! reports the whole round as one JSON object whose `exit_code` equals the
//! process exit code.
//!
//! This module implements the **local entry only**. The mirror stage
//! (`SyncEngine::sync_source`) is task 06's deliverable. Until it lands a
//! config with no sources reports `mirror.sources = []`, and a config that
//! *does* declare sources reports each one as unsynced and the round as
//! partial (exit 3) — never as success, and never as a reason to skip the
//! local index. See [`execute`].
//!
//! Design boundaries taken from the PR10 spec
//! (`2026-09-27-pr10-incremental-sync-design.md`, hard constraints 1–7):
//!
//! - **One `run_index` call.** The local work goes straight through
//!   `indexer::run_index` with an `IndexingProgress`; the older
//!   `run_index_with_data` wrapper is deliberately *not* used, because it
//!   prints its own stdout and re-reads the sources config.
//! - **`--no-ingest` reads no config.** Its whole point is to drain derived
//!   holes without touching the corpus, so a corrupt `sources.toml` must not
//!   be able to fail it.
//! - **Preconditions are explicit and typed.** Old schema, a config that
//!   does not load, and an unreachable Infinity are each probed *before* the
//!   index starts, so they classify as exit 2 by construction instead of by
//!   pattern-matching an `anyhow` string after the fact.
//! - **The config is read once.** The validated `SourcesConfig` from the
//!   preflight is the only one this round has; the mirror stage reads it and
//!   the post-index check verifies the indexer saw a working config too, so a
//!   round whose config stopped loading mid-flight fails closed instead of
//!   reporting success.
//! - **stdout carries exactly one JSON object.** The report is printed first
//!   and the process is then ended with `CliError::already_reported`, which
//!   makes the top-level handler exit with the report's own code without
//!   printing anything else on stdout.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;

use crate::CliError;
use crate::indexer::{IndexOptions, IndexingProgress, IndexingStats, run_index};
use crate::model::cli_error_kind::ErrorKind as CliErrorKind;
use crate::sources::config::SourcesConfig;
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

/// Per-source status when the source was not synced.
const MIRROR_STATUS_FAILED: &str = "failed";

/// Why a declared source carries `status = "failed"` in this build.
const MIRROR_NOT_IMPLEMENTED: &str = "the `sync` mirror stage is not implemented in this build; \
     sources.toml declares this source but nothing was pulled from it \
     (task 06 delivers the mirror stage)";

/// One `cass sync` round, as it appears on stdout.
///
/// The `<data_dir>/logs/sync-runs.jsonl` trace is **not** written here: its
/// per-stage timings and file semantics belong with the complete mirror
/// result in task 06, and a half-specified line format would be a contract
/// nobody agreed to.
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

/// Mirror stage outcome. Task 06 fills `sources`; task 05 always reports an
/// empty list because it performs no remote transfer.
#[derive(Debug, Clone, Serialize)]
pub struct MirrorSection {
    /// Whether this round attempted any remote transfer. Always false in
    /// this build.
    pub attempted: bool,
    /// Why the stage did not run: `"no-ingest"`, `"no-mirror"`, or `null`
    /// when it would have run.
    pub skip_reason: Option<&'static str>,
    /// Per-source results. Empty in this build.
    pub sources: Vec<MirrorSourceResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MirrorSourceResult {
    pub name: String,
    /// `success` | `partial` | `failed` | `not-attempted`.
    pub status: &'static str,
    pub paths: Vec<MirrorPathResult>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MirrorPathResult {
    pub path: String,
    pub success: bool,
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
    let report = execute(db_override, data_dir, no_ingest, no_mirror);

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
        started_at: started,
        finished_at: String::new(),
        no_ingest,
        no_mirror,
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
            Err(err) => return finish(report, EXIT_PRECONDITION, Some(err)),
        }
    };
    if let Some(err) = preflight_schema(&db_path) {
        return finish(report, EXIT_PRECONDITION, Some(err));
    }
    if let Some(err) = preflight_semantic() {
        return finish(report, EXIT_PRECONDITION, Some(err));
    }

    // ---- mirror ---------------------------------------------------------
    //
    // This build performs no remote transfer; task 06 wires
    // `SyncEngine::sync_source` in here. A *remote* source the round did not
    // sync is reported as such -- never as success, and never as a reason to
    // skip the local index below (hard constraint 2).
    //
    // Only remote sources count. A `type = "local"` entry is a local root for
    // the indexer, not something to pull; treating it as a pending mirror
    // would fail a perfectly healthy round (spec axis S1).
    //
    // Note the exit code: the local half of the round still runs and can
    // still succeed, so this is a *partial* round (3), not an internal
    // failure (1). A caller that reads 0 here would believe its configured
    // mirrors are in sync when none of them was contacted.
    let unsynced_remotes: Vec<String> = match (&config, no_mirror) {
        (Some(config), false) => config.remote_source_names(),
        _ => Vec::new(),
    };
    for name in unsynced_remotes {
        report.mirror.sources.push(MirrorSourceResult {
            name,
            status: MIRROR_STATUS_FAILED,
            paths: Vec::new(),
            error: Some(MIRROR_NOT_IMPLEMENTED.to_string()),
        });
    }
    let mirror_failed = !report.mirror.sources.is_empty();

    // ---- index (exactly once) -------------------------------------------
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

    let outcome = match index_outcome {
        Ok(()) => match report.semantic_activated {
            Some(activated) => IndexOutcome::Completed(activated),
            None => IndexOutcome::CompletedWithoutSemanticFact,
        },
        Err(err) => IndexOutcome::Failed(format!("{err:#}")),
    };
    let (exit_code, partial_reasons, error) =
        classify_index_outcome(outcome, mirror_failed, late_config_error.as_deref());
    report.partial_reasons = partial_reasons;
    finish(report, exit_code, error)
}

/// What the one index run produced, reduced to the facts the exit code
/// depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexOutcome {
    /// `run_index` returned an error.
    Failed(String),
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
                        message: MIRROR_NOT_IMPLEMENTED.to_string(),
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

/// Stamp the finish time, derive `complete`, and return the report.
fn finish(mut report: SyncReport, exit_code: i32, error: Option<SyncError>) -> SyncReport {
    report.finished_at = Utc::now_stamp();
    report.exit_code = exit_code;
    report.complete = exit_code == EXIT_READY;
    report.error = error;
    report
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

/// The `sources.toml` fact this round carries past the preflight.
///
/// Exactly one load happens per round, and the validated value is the one the
/// mirror stage reads. Loading again later (and swallowing that error) would
/// let the report describe a different config than the round indexed against
/// (N1), so there is deliberately no second read anywhere in this module.
struct LoadedConfig {
    config: SourcesConfig,
}

impl LoadedConfig {
    /// Names of the **remote** sources the round would have pulled.
    ///
    /// A `type = "local"` entry is a local root for the indexer, not a
    /// pending mirror; counting it here would fail a healthy round (S1).
    fn remote_source_names(&self) -> Vec<String> {
        self.config
            .sources
            .iter()
            .filter(|source| source.is_remote())
            .map(|source| source.name.clone())
            .collect()
    }
}

/// Load and validate `sources.toml` for the normal (ingesting) path.
///
/// A missing file is a legitimate empty config. An existing file that fails
/// to read, parse, or validate is exit 2 — the alternative (index only HOME
/// and call it a success) is exactly the silent-partial-result the spec
/// forbids.
///
/// `CASS_IGNORE_SOURCES_CONFIG` is **refused** rather than honoured: the
/// indexer skips the config under that variable, so accepting it here would
/// let a corrupt `sources.toml` produce a "complete" round that never looked
/// at it (S2). `--no-ingest` is the supported way to run without the config,
/// and it never reaches this function.
fn preflight_config() -> Result<LoadedConfig, SyncError> {
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
        Ok(config) => Ok(LoadedConfig { config }),
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

/// A round identifier: UTC stamp plus pid, so two runs that start in the
/// same microsecond in different processes still differ.
fn new_run_id() -> String {
    format!(
        "sync-{}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.6fZ"),
        std::process::id()
    )
}
