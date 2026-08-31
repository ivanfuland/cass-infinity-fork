//! Corrupt-archive recovery surfaces for `cass doctor` (#285).
//!
//! When the read-only pre-index health gate refuses to index because the
//! canonical `agent_search.db` is corrupt, the operator previously hit a wall:
//! `doctor repair` refuses an unreadable archive, a stock-sqlite `.recover`
//! rebuild is rejected by the legacy embedded engine on readonly open, and the only working
//! path was a hand-rolled JSONL reconstruction from cass's own preserved
//! events. This module turns that working recovery into first-class commands:
//!
//! * [`run_doctor_recover_from_archive`] rebuilds the source JSONL tree from the
//!   canonical archive's preserved `extra_json`/`extra_bin` envelopes so the
//!   data can be re-ingested into a fresh, the legacy embedded engine-native archive — no
//!   `.recover` and no external SQLite tool needed.
//! * [`run_doctor_rebuild_canonical_fts`] drops and rebuilds the canonical FTS5
//!   shadow tables in place (the exact out-of-band fix that resolved the
//!   reporter's derived/FTS5 corruption), for the common case where the
//!   canonical rows are intact but a derived FTS5 structure is malformed.
//! * [`run_doctor_cleanup_interrupted_artifacts`] quarantines interrupted
//!   `raw_mirror_capture` staging dirs that otherwise block doctor mutation,
//!   without forcing the operator to `rm` inside cass's own data dir.
//!
//! None of these surfaces ever delete canonical rows or source data: recovery
//! is additive (writes reconstructed files), the FTS5 shadow is fully
//! rebuildable from the canonical `messages`, and interrupted artifacts are
//! moved into a quarantine dir rather than deleted.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage::sqlite::FrankenStorage;
use crate::{CliError, CliResult, RobotFormat, default_data_dir};

/// Page size for streaming conversations during reconstruction. Keeps memory
/// bounded on multi-GB archives (the exact failure surface from #285/#266).
const RECOVER_CONVERSATION_PAGE: i64 = 256;

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn resolve_db_path(data_dir: &Path, db_override: Option<&Path>) -> PathBuf {
    db_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| data_dir.join("agent_search.db"))
}

fn io_error(message: impl Into<String>, hint: Option<&str>) -> CliError {
    CliError {
        code: 14,
        kind: "io",
        message: message.into(),
        hint: hint.map(str::to_string),
        retryable: true,
    }
}

fn storage_error(message: impl Into<String>, hint: Option<&str>) -> CliError {
    CliError {
        code: 13,
        kind: "storage",
        message: message.into(),
        hint: hint.map(str::to_string),
        retryable: false,
    }
}

fn print_json(envelope: &serde_json::Value) -> CliResult<()> {
    let rendered = serde_json::to_string_pretty(envelope).map_err(|e| CliError {
        code: 9,
        kind: "internal",
        message: format!("serialize recovery envelope: {e}"),
        hint: None,
        retryable: false,
    })?;
    println!("{rendered}");
    Ok(())
}

/// One reconstructed session file (or a skip with the reason).
#[derive(Debug)]
struct ReconstructedSession {
    conversation_id: i64,
    external_id: Option<String>,
    relative_or_source_path: String,
    written_path: Option<PathBuf>,
    line_count: usize,
    skipped_reason: Option<String>,
}

/// Compute the on-disk output path for a reconstructed session.
///
/// We deliberately do NOT write back over the original `source_path`: the
/// recovery target is an operator-chosen directory so nothing existing is
/// clobbered. Each session is keyed by its `external_id` when present (stable,
/// collision-free across machines) and otherwise by its conversation id, with
/// the original file name preserved as a `.jsonl` suffix for readability.
fn reconstruction_output_path(
    target_dir: &Path,
    conversation_id: i64,
    external_id: Option<&str>,
    source_path: &Path,
) -> PathBuf {
    let stem = external_id
        .map(sanitize_path_component)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("conversation-{conversation_id}"));
    // Preserve a hint of the original file name without trusting it as a path.
    let original_hint = source_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .map(|s| sanitize_path_component(&s))
        .filter(|s| !s.is_empty());
    let file_name = match original_hint {
        Some(hint) if hint != stem => format!("{stem}__{hint}.jsonl"),
        _ => format!("{stem}.jsonl"),
    };
    target_dir.join(file_name)
}

/// Replace path-unsafe characters so reconstructed file names never escape the
/// recovery dir or collide on case-insensitive filesystems.
fn sanitize_path_component(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('.')
        .to_string()
}

/// Rebuild the source JSONL tree from the canonical archive's preserved events.
///
/// `target_dir` receives one `.jsonl` file per reconstructable conversation.
/// The canonical archive is opened read-only and never mutated. After this
/// completes the operator can `cass index --full` over `target_dir` to produce
/// a fresh the legacy embedded engine-native archive.
pub fn run_doctor_recover_from_archive(
    data_dir_override: Option<PathBuf>,
    db_override: Option<PathBuf>,
    target_dir: PathBuf,
    structured_format: Option<RobotFormat>,
) -> CliResult<()> {
    let data_dir = data_dir_override.unwrap_or_else(default_data_dir);
    let db_path = resolve_db_path(&data_dir, db_override.as_deref());

    if !db_path.exists() {
        return Err(storage_error(
            format!(
                "canonical archive {} does not exist; nothing to recover from",
                db_path.display()
            ),
            Some(
                "Point --db at the archive, or restore a backup with 'cass doctor backups restore'.",
            ),
        ));
    }

    // Read-only open: recovery must never widen the corruption or take a write
    // lock on a fragile archive.
    let storage = FrankenStorage::open_readonly(&db_path).map_err(|e| {
        storage_error(
            format!(
                "could not open canonical archive {} read-only for recovery: {e:#}",
                db_path.display()
            ),
            Some(
                "If even read-only open fails, the page store itself is unreadable; restore from a \
                 backup ('cass doctor backups list') or a remote mirror.",
            ),
        )
    })?;

    let total = storage
        .total_conversation_count()
        .map_err(|e| storage_error(format!("counting conversations: {e:#}"), None))?;

    std::fs::create_dir_all(&target_dir).map_err(|e| {
        io_error(
            format!(
                "could not create recovery target dir {}: {e}",
                target_dir.display()
            ),
            None,
        )
    })?;

    let mut results: Vec<ReconstructedSession> = Vec::new();
    let mut written = 0usize;
    let mut skipped = 0usize;
    let mut total_lines = 0usize;

    let mut offset: i64 = 0;
    loop {
        let conversations = storage
            .list_conversations(RECOVER_CONVERSATION_PAGE, offset)
            .map_err(|e| {
                storage_error(
                    format!("listing conversations at offset {offset}: {e:#}"),
                    None,
                )
            })?;
        if conversations.is_empty() {
            break;
        }
        let page_len = conversations.len() as i64;

        for conversation in conversations {
            let Some(conversation_id) = conversation.id else {
                continue;
            };
            let source_path_display = conversation.source_path.display().to_string();

            let lines = match storage.reconstruct_source_jsonl_for_conversation(conversation_id) {
                Ok(lines) => lines,
                Err(e) => {
                    skipped += 1;
                    results.push(ReconstructedSession {
                        conversation_id,
                        external_id: conversation.external_id.clone(),
                        relative_or_source_path: source_path_display,
                        written_path: None,
                        line_count: 0,
                        skipped_reason: Some(format!("reconstruct failed: {e:#}")),
                    });
                    continue;
                }
            };

            if lines.is_empty() {
                skipped += 1;
                results.push(ReconstructedSession {
                    conversation_id,
                    external_id: conversation.external_id.clone(),
                    relative_or_source_path: source_path_display,
                    written_path: None,
                    line_count: 0,
                    skipped_reason: Some(
                        "no preserved source events (extra_json/extra_bin) to reconstruct"
                            .to_string(),
                    ),
                });
                continue;
            }

            let out_path = reconstruction_output_path(
                &target_dir,
                conversation_id,
                conversation.external_id.as_deref(),
                &conversation.source_path,
            );

            let mut body = lines.join("\n");
            body.push('\n');
            std::fs::write(&out_path, body.as_bytes()).map_err(|e| {
                io_error(
                    format!(
                        "writing reconstructed session to {}: {e}",
                        out_path.display()
                    ),
                    None,
                )
            })?;

            written += 1;
            total_lines += lines.len();
            results.push(ReconstructedSession {
                conversation_id,
                external_id: conversation.external_id.clone(),
                relative_or_source_path: source_path_display,
                written_path: Some(out_path),
                line_count: lines.len(),
                skipped_reason: None,
            });
        }

        offset += page_len;
        if page_len < RECOVER_CONVERSATION_PAGE {
            break;
        }
    }

    let envelope = serde_json::json!({
        "schema_version": 1,
        "doctor_contract_version": 1,
        "kind": "recover_from_archive",
        "db_path": db_path.display().to_string(),
        "target_dir": target_dir.display().to_string(),
        "conversations_total": total,
        "sessions_written": written,
        "sessions_skipped": skipped,
        "lines_written": total_lines,
        "sessions": results
            .iter()
            .map(|r| serde_json::json!({
                "conversation_id": r.conversation_id,
                "external_id": r.external_id,
                "source_path": r.relative_or_source_path,
                "written_path": r.written_path.as_ref().map(|p| p.display().to_string()),
                "line_count": r.line_count,
                "skipped_reason": r.skipped_reason,
            }))
            .collect::<Vec<_>>(),
        "next_action": format!(
            "Re-ingest the recovered tree with: cass index --full --data-dir <fresh-data-dir> (point the source scan at {})",
            target_dir.display()
        ),
        "note": "Reconstructed verbatim from the canonical archive's preserved extra_json/extra_bin envelopes. The corrupt archive was opened read-only and never mutated; no stock-sqlite .recover was required.",
    });

    if structured_format.is_some() {
        print_json(&envelope)?;
    } else {
        println!(
            "Recovered {written} session(s) ({total_lines} lines) into {}",
            target_dir.display()
        );
        if skipped > 0 {
            println!("  {skipped} conversation(s) had no preserved events and were skipped.");
        }
        println!(
            "Next: re-ingest with 'cass index --full' over {} into a fresh data dir.",
            target_dir.display()
        );
    }
    Ok(())
}


/// Quarantine interrupted `raw_mirror_capture` staging artifacts.
///
/// Empty/partial `raw-mirror/v1/tmp/capture.*` staging dirs from killed index
/// runs otherwise block doctor mutation behind "interrupted doctor artifact(s)
/// require inspection", forcing a manual `rm` inside cass's own data dir. This
/// moves them into `<data_dir>/doctor/quarantine/interrupted-artifacts/`
/// (renamed, never deleted — cass never deletes; the operator owns final
/// reclamation), clearing the gate.
pub fn run_doctor_cleanup_interrupted_artifacts(
    data_dir_override: Option<PathBuf>,
    yes: bool,
    structured_format: Option<RobotFormat>,
) -> CliResult<()> {
    let data_dir = data_dir_override.unwrap_or_else(default_data_dir);
    let tmp_root = data_dir.join("raw-mirror").join("v1").join("tmp");

    let quarantine_root = data_dir
        .join("doctor")
        .join("quarantine")
        .join("interrupted-artifacts");

    // Enumerate the interrupted capture staging entries (top-level children of
    // the raw-mirror tmp dir). These are the `capture.*` dirs the doctor gate
    // flags as needs-inspection.
    let mut candidates: Vec<PathBuf> = Vec::new();
    if tmp_root.exists() {
        let entries = std::fs::read_dir(&tmp_root).map_err(|e| {
            io_error(
                format!(
                    "reading interrupted-capture staging dir {}: {e}",
                    tmp_root.display()
                ),
                None,
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                io_error(format!("enumerating interrupted-capture entry: {e}"), None)
            })?;
            candidates.push(entry.path());
        }
    }
    candidates.sort();

    if candidates.is_empty() {
        let envelope = serde_json::json!({
            "schema_version": 1,
            "doctor_contract_version": 1,
            "kind": "cleanup_interrupted_artifacts",
            "data_dir": data_dir.display().to_string(),
            "tmp_root": tmp_root.display().to_string(),
            "quarantined_count": 0,
            "quarantined": [],
            "note": "No interrupted raw_mirror_capture artifacts found; doctor mutation is not blocked by this class.",
        });
        if structured_format.is_some() {
            print_json(&envelope)?;
        } else {
            println!("No interrupted raw_mirror_capture artifacts found.");
        }
        return Ok(());
    }

    if !yes {
        return Err(CliError {
            code: 4,
            kind: "refused-unsafe",
            message: format!(
                "found {} interrupted raw_mirror_capture artifact(s); `--cleanup-interrupted-artifacts` requires `--yes` to quarantine them",
                candidates.len()
            ),
            hint: Some(format!(
                "Inspect them under {} first, then re-run with `--cleanup-interrupted-artifacts --yes`. They are renamed into a quarantine dir, never deleted.",
                tmp_root.display()
            )),
            retryable: false,
        });
    }

    std::fs::create_dir_all(&quarantine_root).map_err(|e| {
        io_error(
            format!("creating quarantine dir {}: {e}", quarantine_root.display()),
            None,
        )
    })?;

    let mut quarantined: Vec<String> = Vec::new();
    for src in &candidates {
        let name = src
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("artifact-{}", now_unix_ms()));
        let dst = quarantine_root.join(&name);
        let final_dst = if dst.exists() {
            quarantine_root.join(format!("{name}.{}", now_unix_ms()))
        } else {
            dst
        };
        std::fs::rename(src, &final_dst).map_err(|e| {
            io_error(
                format!(
                    "quarantining interrupted artifact {} → {}: {e}",
                    src.display(),
                    final_dst.display()
                ),
                Some("The cleanup halted at this artifact; inspect it manually."),
            )
        })?;
        quarantined.push(final_dst.display().to_string());
    }

    let envelope = serde_json::json!({
        "schema_version": 1,
        "doctor_contract_version": 1,
        "kind": "cleanup_interrupted_artifacts",
        "data_dir": data_dir.display().to_string(),
        "tmp_root": tmp_root.display().to_string(),
        "quarantine_root": quarantine_root.display().to_string(),
        "quarantined_count": quarantined.len(),
        "quarantined": quarantined,
        "note": "Interrupted raw_mirror_capture artifacts were renamed into quarantine; cass never deletes. This clears the 'interrupted doctor artifact(s) require inspection' mutation gate.",
    });

    if structured_format.is_some() {
        print_json(&envelope)?;
    } else {
        println!(
            "Quarantined {} interrupted raw_mirror_capture artifact(s) into {}",
            quarantined.len(),
            quarantine_root.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::api::Value as ParamValue;

    fn write_message(storage: &FrankenStorage, conversation_id: i64, idx: i64, raw_line: &str) {
        // Store the verbatim line via the historical-raw-json sentinel wrapper
        // (the exact shape franken_message_insert_payload writes for raw lines).
        let wrapper = serde_json::json!({ "__cass_historical_raw_json__": raw_line });
        let extra = serde_json::to_string(&wrapper).unwrap();
        storage
            .raw()
            .execute(
                "INSERT INTO messages(conversation_id, idx, role, author, created_at, content, extra_json, extra_bin) \
                 VALUES(?1, ?2, 'user', NULL, ?3, ?4, ?5, NULL)",
                &[
                    ParamValue::from(conversation_id),
                    ParamValue::from(idx),
                    ParamValue::from(1000_i64 + idx),
                    ParamValue::from(format!("content {idx}")),
                    ParamValue::from(extra),
                ] as &[ParamValue],
            )
            .expect("insert message");
    }

    fn seed_agent(storage: &FrankenStorage) -> i64 {
        // conversations.agent_id is NOT NULL REFERENCES agents(id) after
        // migrations, so a conversation row needs a real agent first.
        storage
            .raw()
            .execute(
                "INSERT INTO agents(slug, name, version, kind, created_at, updated_at) \
                 VALUES('claude', 'Claude Code', NULL, 'cli', 1000, 1000)",
                &[] as &[ParamValue],
            )
            .expect("insert agent");
        storage
            .raw()
            .query_row_map("SELECT last_insert_rowid()", &[] as &[ParamValue], |row| {
                row.get_typed::<i64>(0)
            })
            .expect("agent rowid")
    }

    fn seed_conversation(
        storage: &FrankenStorage,
        agent_id: i64,
        external_id: &str,
        source_path: &str,
    ) -> i64 {
        storage
            .raw()
            .execute(
                "INSERT INTO conversations(agent_id, external_id, title, source_path, started_at) \
                 VALUES(?1, ?2, ?3, ?4, 1000)",
                &[
                    ParamValue::from(agent_id),
                    ParamValue::from(external_id),
                    ParamValue::from(format!("title {external_id}")),
                    ParamValue::from(source_path),
                ] as &[ParamValue],
            )
            .expect("insert conversation");
        storage
            .raw()
            .query_row_map("SELECT last_insert_rowid()", &[] as &[ParamValue], |row| {
                row.get_typed::<i64>(0)
            })
            .expect("rowid")
    }

    #[test]
    fn sanitize_path_component_strips_separators_and_traversal() {
        // Path separators collapse to '_', so the result is always a single
        // flat filename component (interior dots are harmless once no '/'
        // remains).
        assert_eq!(sanitize_path_component("a/b/../c"), "a_b_.._c");
        assert!(!sanitize_path_component("a/b/../c").contains('/'));
        assert_eq!(sanitize_path_component("normal-id_1.2"), "normal-id_1.2");
        assert_eq!(sanitize_path_component(""), "");
        // Leading/trailing dots are trimmed so we never emit "." or "..".
        assert_eq!(sanitize_path_component(".."), "");
        assert_eq!(sanitize_path_component("."), "");
    }

    #[test]
    fn reconstruction_output_path_stays_inside_target_dir() {
        let target = Path::new("/tmp/recover");
        let out = reconstruction_output_path(
            target,
            7,
            Some("sess-abc"),
            Path::new("/home/u/.claude/projects/foo/bar.jsonl"),
        );
        assert!(out.starts_with(target));
        let name = out.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("sess-abc"));
        assert!(name.ends_with(".jsonl"));
        // A malicious external_id can never escape the recovery dir.
        let evil =
            reconstruction_output_path(target, 7, Some("../../etc/passwd"), Path::new("x.jsonl"));
        assert!(evil.starts_with(target));
        assert_eq!(evil.parent().unwrap(), target);
    }

    #[test]
    fn recover_from_archive_reconstructs_verbatim_lines() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("agent_search.db");
        let target = tmp.path().join("recovered");
        {
            let storage = FrankenStorage::open(&db_path).expect("open db");
            let agent_id = seed_agent(&storage);
            let cid = seed_conversation(&storage, agent_id, "sess-1", "/orig/a.jsonl");
            write_message(
                &storage,
                cid,
                0,
                r#"{"type":"user","uuid":"u1","text":"hi"}"#,
            );
            write_message(
                &storage,
                cid,
                1,
                r#"{"type":"assistant","uuid":"a1","text":"yo"}"#,
            );
        }

        run_doctor_recover_from_archive(
            Some(tmp.path().to_path_buf()),
            Some(db_path.clone()),
            target.clone(),
            Some(RobotFormat::Json),
        )
        .expect("recover");

        // One .jsonl file with the two verbatim lines, in order.
        let out_file = std::fs::read_dir(&target)
            .expect("read recovered dir")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| p.extension().and_then(|e| e.to_str()) == Some("jsonl"))
            .expect("a reconstructed jsonl file");
        let body = std::fs::read_to_string(&out_file).expect("read reconstructed file");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], r#"{"type":"user","uuid":"u1","text":"hi"}"#);
        assert_eq!(lines[1], r#"{"type":"assistant","uuid":"a1","text":"yo"}"#);
    }

    #[test]
    fn cleanup_interrupted_artifacts_quarantines_without_delete() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let tmp_root = data_dir.join("raw-mirror").join("v1").join("tmp");
        std::fs::create_dir_all(tmp_root.join("capture.dead1")).expect("mk capture dir");
        std::fs::create_dir_all(tmp_root.join("capture.dead2")).expect("mk capture dir");

        // Without --yes the command refuses (and does not move anything).
        let refused = run_doctor_cleanup_interrupted_artifacts(
            Some(data_dir.clone()),
            false,
            Some(RobotFormat::Json),
        );
        assert!(refused.is_err());
        assert!(tmp_root.join("capture.dead1").exists());

        // With --yes the artifacts are quarantined (moved, not deleted).
        run_doctor_cleanup_interrupted_artifacts(
            Some(data_dir.clone()),
            true,
            Some(RobotFormat::Json),
        )
        .expect("cleanup");
        assert!(!tmp_root.join("capture.dead1").exists());
        assert!(!tmp_root.join("capture.dead2").exists());
        let quarantine = data_dir
            .join("doctor")
            .join("quarantine")
            .join("interrupted-artifacts");
        assert!(quarantine.join("capture.dead1").exists());
        assert!(quarantine.join("capture.dead2").exists());
    }

    #[test]
    fn rebuild_canonical_fts_refuses_without_yes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("agent_search.db");
        {
            let _storage = FrankenStorage::open(&db_path).expect("open db");
        }
        let refused = run_doctor_rebuild_canonical_fts(
            Some(tmp.path().to_path_buf()),
            Some(db_path),
            false,
            Some(RobotFormat::Json),
        );
        assert!(refused.is_err());
    }
}
