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

/// One `cass sync` round, as it appears on stdout and (one compact line per
/// round) in `<data_dir>/logs/sync-runs.jsonl`.
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
    let report = execute(db_override, data_dir.clone(), no_ingest, no_mirror);

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
            append_run_log(&data_dir, &fallback);
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
    // The line on disk is the same bytes stdout carried, so a later reader
    // can diff a round against what the caller actually saw.
    append_run_log(&data_dir, &line);

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

/// Append one round to `<data_dir>/logs/sync-runs.jsonl`.
///
/// This is a trace, not a completion proof: a SIGKILLed round simply has no
/// final line, and the absence of a line must never be read as "nothing was
/// ingested". A failure to write warns on stderr and is otherwise ignored —
/// the round's exit code belongs to the index, not to the log.
fn append_run_log(data_dir: &Path, line: &str) {
    let logs_dir = data_dir.join("logs");
    if let Err(err) = std::fs::create_dir_all(&logs_dir) {
        eprintln!(
            "warning: could not create {} for the sync run log: {err}",
            logs_dir.display()
        );
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&logs_dir, std::fs::Permissions::from_mode(0o700));
    }
    let path = logs_dir.join("sync-runs.jsonl");
    let opened = {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&path)
    };
    match opened {
        Ok(mut file) => {
            use std::io::Write as _;
            if let Err(err) = writeln!(file, "{line}") {
                eprintln!("warning: could not append to {}: {err}", path.display());
            }
        }
        Err(err) => eprintln!("warning: could not open {}: {err}", path.display()),
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
    if let Some(err) = preflight_config(no_ingest) {
        return finish(report, EXIT_PRECONDITION, Some(err));
    }
    if let Some(err) = preflight_schema(&db_path) {
        return finish(report, EXIT_PRECONDITION, Some(err));
    }
    if let Some(err) = preflight_semantic() {
        return finish(report, EXIT_PRECONDITION, Some(err));
    }

    // ---- mirror ---------------------------------------------------------
    //
    // This build performs no remote transfer; task 06 wires
    // `SyncEngine::sync_source` in here. A config that declares sources is
    // reported source-by-source as not synced -- never as success, and never
    // as a reason to skip the local index below (hard constraint 2).
    //
    // Note the exit code: the local half of the round still runs and can
    // still succeed, so this is a *partial* round (3), not an internal
    // failure (1). A caller that reads 0 here would believe its configured
    // mirrors are in sync when none of them was contacted.
    let configured_sources = if no_ingest || no_mirror {
        Vec::new()
    } else {
        configured_source_names()
    };
    for name in configured_sources {
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
    report.index.stats = stats;

    let outcome = match index_outcome {
        Ok(()) => match report.semantic_activated {
            Some(activated) => IndexOutcome::Completed(activated),
            None => IndexOutcome::CompletedWithoutSemanticFact,
        },
        Err(err) => IndexOutcome::Failed(format!("{err:#}")),
    };
    let (exit_code, partial_reasons, error) = classify_index_outcome(outcome, mirror_failed);
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
) -> (i32, Vec<&'static str>, Option<SyncError>) {
    let mut reasons: Vec<&'static str> = Vec::new();
    if mirror_failed {
        reasons.push(REASON_MIRROR_FAILED);
    }
    match outcome {
        IndexOutcome::Failed(message) => (
            EXIT_INTERNAL,
            reasons,
            Some(SyncError {
                kind: CliErrorKind::Index.kind_str(),
                message: format!("index run failed: {message}"),
            }),
        ),
        IndexOutcome::Completed(true) => {
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
        IndexOutcome::Completed(false) => {
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
        IndexOutcome::CompletedWithoutSemanticFact => (
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

/// Load and validate `sources.toml`, unless this run has no use for it.
///
/// A missing file is a legitimate empty config. An existing file that fails
/// to read, parse, or validate is exit 2 — the alternative (index only HOME
/// and call it a success) is exactly the silent-partial-result the spec
/// forbids.
///
/// `--no-ingest` skips this entirely: that mode neither mirrors nor scans,
/// so a corrupt config must not be able to stop it.
///
/// `CASS_IGNORE_SOURCES_CONFIG` is honoured for the same reason `run_index`
/// honours it — it is the operator's explicit "pretend there is no config"
/// switch, and sync must not be stricter than `index` about the same file.
fn preflight_config(no_ingest: bool) -> Option<SyncError> {
    if no_ingest || dotenvy::var("CASS_IGNORE_SOURCES_CONFIG").is_ok() {
        return None;
    }
    match SourcesConfig::load() {
        Ok(_) => None,
        Err(err) => Some(SyncError {
            kind: CliErrorKind::Config.kind_str(),
            message: format!("sources.toml exists but did not load: {err}"),
        }),
    }
}

/// Names of the sources the config declares, or an empty list when it
/// cannot be read (a bad config has already failed the preflight above by
/// then) or when the operator asked for the config to be ignored.
fn configured_source_names() -> Vec<String> {
    if dotenvy::var("CASS_IGNORE_SOURCES_CONFIG").is_ok() {
        return Vec::new();
    }
    SourcesConfig::load()
        .map(|c| c.sources.into_iter().map(|s| s.name).collect())
        .unwrap_or_default()
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
