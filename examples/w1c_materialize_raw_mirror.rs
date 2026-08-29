//! Drill asset (plan v6 Stage C, Task C3 Step 1) — not a product feature, not
//! wired into the `cass` command surface or `Commands` enum.
//!
//! Materializes production raw-mirror blobs into a fake-HOME filesystem tree
//! by `original_path`, so a subsequent `HOME=<dest> cass index --data-dir
//! <staging> --full` run discovers and parses them through the real
//! connector pipeline (not a DB-direct restore shortcut) — this is the
//! T7-validated staging reingest mechanism (2026-08-24 T7-reingest-probe.md
//! §3.1: materialized tree shape empirically confirmed as
//! `<dest>/.claude/projects/...`, `<dest>/nas/openclaw/...`, etc. — i.e. the
//! real machine's home-dir prefix is stripped, not the full absolute path
//! preserved).
//!
//! Two judgements, reported separately (control-plane-approved design,
//! 2026-08-28):
//! 1. Blob integrity (plan R0-N3): every DISTINCT blob in the raw-mirror,
//!    re-hashed and compared against its manifest-recorded blake3 + size.
//!    This is the "blake3 N/N" headline metric, N = distinct blob count
//!    enumerated at run time (never a hardcoded historical snapshot number).
//! 2. Materialization (plan Step 1, "按 original_path 物化"): one file per
//!    distinct `original_path`, selecting the newest manifest whose blob
//!    passed judgement 1 (falling back to the next-newest on a bad/missing
//!    blob rather than silently dropping the whole path — a real capture
//!    with an available good older copy must not vanish because the newest
//!    capture event happened to be corrupt). Ties on `captured_at_ms` break
//!    by `manifest_id` descending (lexicographic) for determinism: same
//!    input must produce the same sealed output. Writes get re-read and
//!    re-hashed after landing on disk — that reread is the final safety
//!    authority, not the (simplified, non-symlink-hardened) path checks
//!    below.
//!
//! Path safety (deliberately NOT the general-purpose, adversarial-input-safe
//! `phase3_restore::materialize_sealed_blob` primitive — control-plane
//! 2026-08-28 declined expanding that to `pub` for a one-shot tool; this
//! tool's `original_path` inputs are this machine's own historical local
//! captures, not attacker-controlled):
//! - the relative shape rejects any `..` component or an absolute residual
//! - the destination parent directory is canonicalized and asserted to
//!   still be inside the canonicalized destination root
//! - refuses to overwrite an existing file (every distinct original_path is
//!   visited exactly once by construction; a collision means the grouping
//!   logic has a bug and must not silently clobber)
//! - post-write blake3 reread against the manifest hash is the true gate

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Deserialize, Clone)]
struct ManifestJson {
    manifest_id: String,
    blob_relative_path: String,
    blob_blake3: String,
    blob_size_bytes: u64,
    original_path: String,
    captured_at_ms: i64,
}

#[derive(Debug, Serialize)]
struct DroppedEntry {
    original_path: String,
    candidates_tried: usize,
    last_failure: String,
}

#[derive(Debug, Serialize)]
struct FallbackEntry {
    original_path: String,
    used_manifest_id: String,
    used_captured_at_ms: i64,
    skipped_newer_candidates: usize,
}

#[derive(Debug, Serialize, Default)]
struct Report {
    raw_mirror: String,
    dest: String,
    strip_prefix: String,
    manifests_total: usize,
    distinct_blobs: usize,
    blob_verify_pass: usize,
    blob_verify_fail: usize,
    blob_missing: usize,
    distinct_original_paths: usize,
    materialized: usize,
    dropped: Vec<DroppedEntry>,
    fallback_used: Vec<FallbackEntry>,
    outside_strip_prefix: Vec<String>,
}

fn blake3_of_reader<R: Read>(mut reader: R) -> std::io::Result<(String, u64)> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hasher.finalize().to_hex().to_string(), total))
}

fn blake3_of_file(path: &Path) -> std::io::Result<(String, u64)> {
    blake3_of_reader(fs::File::open(path)?)
}

/// Reject `..` and absolute-looking residuals; otherwise pass the relative
/// path through unchanged. `original_path` is this machine's own historical
/// capture, so this is a sanity fence, not an adversarial-input hardening
/// layer (see module doc).
fn safe_relative_shape(relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    let mut rebuilt = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => rebuilt.push(part),
            std::path::Component::ParentDir => {
                return Err(format!("`..` component in {relative:?}"));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(format!("unexpected absolute component in {relative:?}"));
            }
            std::path::Component::CurDir => {}
        }
    }
    if rebuilt.as_os_str().is_empty() {
        return Err(format!("empty relative shape from {relative:?}"));
    }
    Ok(rebuilt)
}

fn parse_args() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let mut raw_mirror = None;
    let mut strip_prefix = None;
    let mut dest = None;
    let mut report = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .unwrap_or_else(|| panic!("{flag} requires a value"));
        match flag.as_str() {
            "--raw-mirror" => raw_mirror = Some(PathBuf::from(value)),
            "--strip-prefix" => strip_prefix = Some(PathBuf::from(value)),
            "--dest" => dest = Some(PathBuf::from(value)),
            "--report" => report = Some(PathBuf::from(value)),
            other => panic!("unknown flag {other}"),
        }
    }
    (
        raw_mirror.expect("--raw-mirror <raw-mirror/v1 dir> is required"),
        strip_prefix.expect("--strip-prefix <real home prefix to strip> is required"),
        dest.expect("--dest <fake-HOME materialization root> is required"),
        report.expect("--report <output json path> is required"),
    )
}

/// R1-B4: refuse a `--report` path that would land inside `raw_mirror` (real
/// captured evidence) or `dest` (the fake-HOME tree this run itself is about
/// to populate) -- same containment check shape as `cass ingest manifest`'s
/// `--out` guard (R1-B3), scaled to this tool's own two boundaries.
fn reject_report_inside_raw_mirror_or_dest(
    report_path: &Path,
    raw_mirror: &Path,
    canonical_dest: &Path,
) {
    let report_parent = report_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_report_parent = fs::canonicalize(report_parent)
        .unwrap_or_else(|e| panic!("canonicalizing --report parent directory {}: {e}", report_parent.display()));

    if let Ok(canonical_raw_mirror) = fs::canonicalize(raw_mirror) {
        if canonical_report_parent.starts_with(&canonical_raw_mirror) {
            panic!(
                "--report {} resolves inside --raw-mirror ({}) -- refusing to write the \
                 report where it could be mistaken for captured evidence",
                report_path.display(),
                canonical_raw_mirror.display()
            );
        }
    }
    if canonical_report_parent.starts_with(canonical_dest) {
        panic!(
            "--report {} resolves inside --dest ({}) -- refusing to write the report into \
             the fake-HOME tree this run is materializing",
            report_path.display(),
            canonical_dest.display()
        );
    }
}

fn main() {
    let (raw_mirror, strip_prefix, dest, report_path) = parse_args();

    fs::create_dir_all(&dest).expect("create destination root");
    let canonical_dest = fs::canonicalize(&dest).expect("canonicalize destination root");
    reject_report_inside_raw_mirror_or_dest(&report_path, &raw_mirror, &canonical_dest);

    let manifests_dir = raw_mirror.join("manifests");
    let mut manifest_paths: Vec<PathBuf> = fs::read_dir(&manifests_dir)
        .expect("read manifests dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    manifest_paths.sort();

    let mut manifests: Vec<ManifestJson> = Vec::with_capacity(manifest_paths.len());
    for path in &manifest_paths {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("reading manifest {}: {e}", path.display()));
        let parsed: ManifestJson = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("parsing manifest {}: {e}", path.display()));
        manifests.push(parsed);
    }
    let manifests_total = manifests.len();

    // Judgement 1: blob integrity, one hash per distinct blob_relative_path.
    let mut blob_verified: HashMap<String, bool> = HashMap::new();
    let mut blob_verify_pass = 0usize;
    let mut blob_verify_fail = 0usize;
    let mut blob_missing = 0usize;
    for m in &manifests {
        if blob_verified.contains_key(&m.blob_relative_path) {
            continue;
        }
        let blob_path = raw_mirror.join(&m.blob_relative_path);
        let ok = match blake3_of_file(&blob_path) {
            Ok((hash, size)) => hash == m.blob_blake3 && size == m.blob_size_bytes,
            Err(_) => {
                blob_missing += 1;
                blob_verified.insert(m.blob_relative_path.clone(), false);
                continue;
            }
        };
        if ok {
            blob_verify_pass += 1;
        } else {
            blob_verify_fail += 1;
        }
        blob_verified.insert(m.blob_relative_path.clone(), ok);
    }
    let distinct_blobs = blob_verified.len();

    // Judgement 2: materialize one file per distinct original_path, newest
    // *verified* manifest wins, tie-break by manifest_id descending.
    let mut by_original_path: HashMap<String, Vec<&ManifestJson>> = HashMap::new();
    for m in &manifests {
        by_original_path
            .entry(m.original_path.clone())
            .or_default()
            .push(m);
    }
    let distinct_original_paths = by_original_path.len();

    let mut original_paths: Vec<&String> = by_original_path.keys().collect();
    original_paths.sort();

    let mut materialized = 0usize;
    let mut dropped = Vec::new();
    let mut fallback_used = Vec::new();
    let mut outside_strip_prefix = Vec::new();

    for original_path in original_paths {
        let mut candidates = by_original_path[original_path].clone();
        candidates.sort_by(|a, b| {
            b.captured_at_ms
                .cmp(&a.captured_at_ms)
                .then_with(|| b.manifest_id.cmp(&a.manifest_id))
        });

        let mut selected: Option<&ManifestJson> = None;
        let mut tried = 0usize;
        let mut last_failure = String::new();
        for (index, candidate) in candidates.iter().enumerate() {
            tried += 1;
            let verified = blob_verified
                .get(&candidate.blob_relative_path)
                .copied()
                .unwrap_or(false);
            if verified {
                if index > 0 {
                    fallback_used.push(FallbackEntry {
                        original_path: original_path.clone(),
                        used_manifest_id: candidate.manifest_id.clone(),
                        used_captured_at_ms: candidate.captured_at_ms,
                        skipped_newer_candidates: index,
                    });
                }
                selected = Some(candidate);
                break;
            }
            last_failure = format!(
                "manifest {} blob {} failed integrity check",
                candidate.manifest_id, candidate.blob_relative_path
            );
        }

        let Some(manifest) = selected else {
            dropped.push(DroppedEntry {
                original_path: original_path.clone(),
                candidates_tried: tried,
                last_failure,
            });
            continue;
        };

        let relative_source = match Path::new(&manifest.original_path).strip_prefix(&strip_prefix)
        {
            Ok(stripped) => stripped.to_path_buf(),
            Err(_) => {
                outside_strip_prefix.push(manifest.original_path.clone());
                Path::new(manifest.original_path.trim_start_matches('/')).to_path_buf()
            }
        };
        let relative = safe_relative_shape(&relative_source.to_string_lossy())
            .unwrap_or_else(|e| panic!("unsafe original_path {}: {e}", manifest.original_path));

        let target = dest.join(&relative);
        let target_parent = target.parent().expect("target has a parent");
        fs::create_dir_all(target_parent)
            .unwrap_or_else(|e| panic!("create_dir_all {}: {e}", target_parent.display()));
        let canonical_parent = fs::canonicalize(target_parent)
            .unwrap_or_else(|e| panic!("canonicalize {}: {e}", target_parent.display()));
        assert!(
            canonical_parent.starts_with(&canonical_dest),
            "E-SCRATCH-ESCAPE: {} resolved outside destination root {}",
            canonical_parent.display(),
            canonical_dest.display()
        );
        assert!(
            !target.exists(),
            "refusing to overwrite existing materialized file at {}",
            target.display()
        );

        let blob_path = raw_mirror.join(&manifest.blob_relative_path);
        let bytes = fs::read(&blob_path)
            .unwrap_or_else(|e| panic!("reading blob {}: {e}", blob_path.display()));
        {
            let mut file = fs::File::create(&target)
                .unwrap_or_else(|e| panic!("creating {}: {e}", target.display()));
            file.write_all(&bytes)
                .unwrap_or_else(|e| panic!("writing {}: {e}", target.display()));
        }

        // Final authority: reread from disk and rehash, independent of the
        // in-memory bytes just written.
        let (reread_hash, reread_size) = blake3_of_file(&target)
            .unwrap_or_else(|e| panic!("rereading {}: {e}", target.display()));
        assert_eq!(
            reread_hash, manifest.blob_blake3,
            "post-write blake3 mismatch for {}",
            target.display()
        );
        assert_eq!(
            reread_size, manifest.blob_size_bytes,
            "post-write size mismatch for {}",
            target.display()
        );

        materialized += 1;
    }

    let report = Report {
        raw_mirror: raw_mirror.display().to_string(),
        dest: dest.display().to_string(),
        strip_prefix: strip_prefix.display().to_string(),
        manifests_total,
        distinct_blobs,
        blob_verify_pass,
        blob_verify_fail,
        blob_missing,
        distinct_original_paths,
        materialized,
        dropped,
        fallback_used,
        outside_strip_prefix,
    };

    println!(
        "blob integrity: {}/{} (fail={} missing={})",
        report.blob_verify_pass, report.distinct_blobs, report.blob_verify_fail, report.blob_missing
    );
    println!(
        "materialization: {}/{} distinct original_paths (dropped={} fallback_used={})",
        report.materialized,
        report.distinct_original_paths,
        report.dropped.len(),
        report.fallback_used.len()
    );

    let report_json = serde_json::to_string_pretty(&report).expect("serialize report");
    fs::write(&report_path, report_json).expect("write report");

    // R1-B5(b): any of these four counters non-empty means at least one
    // capture didn't materialize cleanly (bad/missing blob, dropped
    // original_path, or a path outside --strip-prefix skipped per B5(a)).
    // The report is already written above -- exit nonzero so a caller
    // scripting this tool can't silently treat a degraded run as clean.
    if report.blob_verify_fail > 0
        || report.blob_missing > 0
        || !report.dropped.is_empty()
        || !report.outside_strip_prefix.is_empty()
    {
        eprintln!(
            "degraded materialization run: blob_verify_fail={} blob_missing={} dropped={} \
             outside_strip_prefix={} (see {} for details)",
            report.blob_verify_fail,
            report.blob_missing,
            report.dropped.len(),
            report.outside_strip_prefix.len(),
            report_path.display()
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod report_path_safety_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    #[should_panic(expected = "resolves inside --raw-mirror")]
    fn report_inside_raw_mirror_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let raw_mirror = tmp.path().join("raw-mirror");
        fs::create_dir_all(&raw_mirror).unwrap();
        let dest = tmp.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        let canonical_dest = fs::canonicalize(&dest).unwrap();
        let report_path = raw_mirror.join("report.json");

        reject_report_inside_raw_mirror_or_dest(&report_path, &raw_mirror, &canonical_dest);
    }

    #[test]
    #[should_panic(expected = "resolves inside --dest")]
    fn report_inside_dest_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let raw_mirror = tmp.path().join("raw-mirror");
        fs::create_dir_all(&raw_mirror).unwrap();
        let dest = tmp.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        let canonical_dest = fs::canonicalize(&dest).unwrap();
        let report_path = dest.join("report.json");

        reject_report_inside_raw_mirror_or_dest(&report_path, &raw_mirror, &canonical_dest);
    }

    #[test]
    fn report_outside_both_boundaries_is_allowed() {
        let tmp = TempDir::new().unwrap();
        let raw_mirror = tmp.path().join("raw-mirror");
        fs::create_dir_all(&raw_mirror).unwrap();
        let dest = tmp.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        let canonical_dest = fs::canonicalize(&dest).unwrap();
        let report_dir = tmp.path().join("reports");
        fs::create_dir_all(&report_dir).unwrap();
        let report_path = report_dir.join("report.json");

        // Must not panic.
        reject_report_inside_raw_mirror_or_dest(&report_path, &raw_mirror, &canonical_dest);
    }
}
