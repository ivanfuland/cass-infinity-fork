use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RAW_MIRROR_SCHEMA_VERSION: u32 = 1;
const RAW_MIRROR_ROOT_DIR: &str = "raw-mirror";
const RAW_MIRROR_VERSION_DIR: &str = "v1";
const RAW_MIRROR_MANIFEST_KIND: &str = "cass_raw_session_mirror_v1";
const RAW_MIRROR_HASH_ALGORITHM: &str = "blake3";
const RAW_MIRROR_BLOB_EXTENSION: &str = "raw";

static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);
static BLOB_CAPTURE_CACHE: OnceLock<Mutex<HashMap<RawMirrorBlobCacheKey, RawMirrorBlobRecord>>> =
    OnceLock::new();
static MANIFEST_UPDATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// PR6 T2c (任务书 #113): prune/摄入互斥判例②的注入点-- fires inside
/// [`prune`] after the referenced-blob protection set has been computed
/// (R9 check already passed) but before any file is actually removed, so a
/// test can, from inside the hook, attempt a concurrent write that
/// references one of prune's about-to-be-deleted unreferenced blobs and
/// observe whether `index-run.lock` correctly serializes the two. Always
/// compiled (not `#[cfg(test)]`, since the integration test lives in a
/// separate `tests/` crate); zero-cost when unset (`OnceLock` + `Option`
/// check, no allocation on the hot path).
static PRUNE_FAULT_HOOK: OnceLock<Mutex<Option<Box<dyn Fn() + Send + Sync>>>> = OnceLock::new();

#[doc(hidden)]
pub fn set_prune_fault_hook(hook: Option<Box<dyn Fn() + Send + Sync>>) {
    *PRUNE_FAULT_HOOK.get_or_init(|| Mutex::new(None)).lock().unwrap() = hook;
}

fn fire_prune_fault_hook() {
    if let Some(lock) = PRUNE_FAULT_HOOK.get()
        && let Some(hook) = lock.lock().unwrap().as_ref()
    {
        hook();
    }
}

fn raw_mirror_fsync_enabled() -> bool {
    dotenvy::var("CASS_RAW_MIRROR_FSYNC")
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

/// R2-B5 (任务书 #119b) test observability: fires once per directory that
/// [`force_sync_dir`] actually fsyncs -- both `sync_capture_durable`'s
/// unconditional chain-walk and `replace_manifest_bytes`'s switch-gated one
/// (via `force_sync_dir_chain`) funnel through `force_sync_dir`, so a single
/// hook lets tests assert on the exact set of directories synced without
/// `strace`. Always compiled (zero-cost when unset), same shape as
/// `PRUNE_FAULT_HOOK` above.
static DIR_SYNC_PROBE: OnceLock<Mutex<Option<Box<dyn Fn(&Path) + Send + Sync>>>> = OnceLock::new();

#[doc(hidden)]
pub fn set_dir_sync_probe(hook: Option<Box<dyn Fn(&Path) + Send + Sync>>) {
    *DIR_SYNC_PROBE.get_or_init(|| Mutex::new(None)).lock().unwrap() = hook;
}

fn fire_dir_sync_probe(dir: &Path) {
    if let Some(lock) = DIR_SYNC_PROBE.get()
        && let Some(hook) = lock.lock().unwrap().as_ref()
    {
        hook(dir);
    }
}

#[derive(Debug, Clone)]
pub struct RawMirrorCaptureInput<'a> {
    pub data_dir: &'a Path,
    pub provider: &'a str,
    pub source_id: &'a str,
    pub origin_kind: &'a str,
    pub origin_host: Option<&'a str>,
    pub source_path: &'a Path,
    pub db_links: &'a [RawMirrorDbLink],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawMirrorCaptureRecord {
    pub manifest_id: String,
    pub manifest_relative_path: String,
    pub blob_relative_path: String,
    pub blob_blake3: String,
    pub blob_size_bytes: u64,
    pub captured_at_ms: i64,
    pub source_mtime_ms: Option<i64>,
    pub already_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawMirrorDbLink {
    pub conversation_id: Option<i64>,
    pub message_count: Option<usize>,
    pub source_path: Option<String>,
    pub started_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawMirrorStorageSummary {
    pub initialized: bool,
    pub root_path: String,
    pub total_storage_bytes: u64,
    pub manifest_count: u64,
    pub manifest_bytes: u64,
    pub unique_blob_count: u64,
    pub total_blob_bytes: u64,
    pub largest_blob_bytes: u64,
    pub missing_blob_count: u64,
    pub invalid_manifest_count: u64,
    pub oldest_capture_at_ms: Option<i64>,
    pub newest_capture_at_ms: Option<i64>,
    pub oldest_source_mtime_ms: Option<i64>,
    pub newest_source_mtime_ms: Option<i64>,
}

pub fn storage_summary(data_dir: &Path) -> RawMirrorStorageSummary {
    let root = raw_mirror_root(data_dir);
    let mut summary = RawMirrorStorageSummary {
        root_path: root.display().to_string(),
        ..RawMirrorStorageSummary::default()
    };
    let root_metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(_) => return summary,
    };
    summary.initialized = true;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        summary.invalid_manifest_count = 1;
        return summary;
    }

    summary.total_storage_bytes = raw_mirror_dir_file_bytes(&root);

    let manifests_dir = root.join("manifests");
    let Ok(manifests_metadata) = fs::symlink_metadata(&manifests_dir) else {
        return summary;
    };
    if manifests_metadata.file_type().is_symlink() || !manifests_metadata.is_dir() {
        summary.invalid_manifest_count = summary.invalid_manifest_count.saturating_add(1);
        return summary;
    }
    let entries = match fs::read_dir(&manifests_dir) {
        Ok(entries) => entries,
        Err(_) => return summary,
    };
    let mut seen_blobs = HashSet::new();
    for entry in entries {
        let Ok(entry) = entry else {
            summary.invalid_manifest_count = summary.invalid_manifest_count.saturating_add(1);
            continue;
        };
        let path = entry.path();
        let manifest_metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            _ => {
                summary.invalid_manifest_count = summary.invalid_manifest_count.saturating_add(1);
                continue;
            }
        };
        summary.manifest_bytes = summary
            .manifest_bytes
            .saturating_add(manifest_metadata.len());
        let manifest = match read_raw_mirror_manifest(&path) {
            Ok(manifest) if manifest.manifest_kind == RAW_MIRROR_MANIFEST_KIND => manifest,
            _ => {
                summary.invalid_manifest_count = summary.invalid_manifest_count.saturating_add(1);
                continue;
            }
        };
        summary.manifest_count = summary.manifest_count.saturating_add(1);
        merge_min_max(
            &mut summary.oldest_capture_at_ms,
            &mut summary.newest_capture_at_ms,
            Some(manifest.captured_at_ms),
        );
        merge_min_max(
            &mut summary.oldest_source_mtime_ms,
            &mut summary.newest_source_mtime_ms,
            manifest.source_mtime_ms,
        );

        let Some(blob_relative_path) = raw_mirror_blob_relative_path(&manifest.blob_blake3) else {
            summary.invalid_manifest_count = summary.invalid_manifest_count.saturating_add(1);
            continue;
        };
        if manifest.blob_relative_path != blob_relative_path {
            summary.invalid_manifest_count = summary.invalid_manifest_count.saturating_add(1);
            continue;
        }

        if !seen_blobs.insert(blob_relative_path.clone()) {
            continue;
        }
        let blob_path = root.join(blob_relative_path);
        match fs::symlink_metadata(&blob_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                let size = metadata.len();
                summary.unique_blob_count = summary.unique_blob_count.saturating_add(1);
                summary.total_blob_bytes = summary.total_blob_bytes.saturating_add(size);
                summary.largest_blob_bytes = summary.largest_blob_bytes.max(size);
            }
            _ => {
                summary.missing_blob_count = summary.missing_blob_count.saturating_add(1);
            }
        }
    }

    summary
}

#[derive(Debug, Clone, Default)]
pub struct RawMirrorPruneOptions {
    pub older_than_ms: Option<i64>,
    pub max_size_bytes: Option<u64>,
    pub keep_tags: Vec<String>,
    pub safety_hold_down_ms: i64,
    pub apply: bool,
    /// PR6 T2c (任务书 #113, R9): blob identities referenced by
    /// `messages.excluded.raw.blob` in the caller's database (manifest-
    /// relative paths, same encoding as [`RawMirrorPruneManifest::blob_relative_path`]).
    /// Never pruned, nor is any manifest that captured one of them --
    /// the caller reads this set via
    /// `SELECT json_extract(excluded,'$.raw.blob') FROM messages WHERE excluded IS NOT NULL`
    /// while holding `index-run.lock` (R1-B1).
    pub referenced_blobs: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RawMirrorPruneReport {
    pub initialized: bool,
    pub root_path: String,
    pub mode: String,
    pub manifest_count: u64,
    pub unique_blob_count: u64,
    pub current_blob_bytes: u64,
    pub safety_hold_down_ms: i64,
    pub keep_tags: Vec<String>,
    pub pinned_manifest_count: u64,
    pub pinned_blob_count: u64,
    pub planned_manifest_count: u64,
    pub planned_blob_count: u64,
    pub planned_reclaim_bytes: u64,
    pub applied_manifest_count: u64,
    pub applied_blob_count: u64,
    pub applied_reclaim_bytes: u64,
    pub audit_log_path: Option<String>,
    pub entries: Vec<RawMirrorPruneEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RawMirrorPruneEntry {
    pub kind: String,
    pub path: String,
    pub blob_blake3: Option<String>,
    pub size_bytes: u64,
    pub reason: String,
    pub applied: bool,
}

#[derive(Debug, Clone)]
struct RawMirrorPruneManifest {
    manifest_id: String,
    relative_path: String,
    size_bytes: u64,
    blob_blake3: String,
    blob_relative_path: String,
    blob_size_bytes: u64,
    captured_at_ms: i64,
    provider: String,
    original_path: String,
    db_links: Vec<RawMirrorDbLink>,
}

pub fn prune(data_dir: &Path, options: RawMirrorPruneOptions) -> Result<RawMirrorPruneReport> {
    let root = raw_mirror_root(data_dir);
    let mut report = RawMirrorPruneReport {
        initialized: false,
        root_path: root.display().to_string(),
        mode: if options.apply {
            "apply".to_string()
        } else {
            "dry-run".to_string()
        },
        manifest_count: 0,
        unique_blob_count: 0,
        current_blob_bytes: 0,
        safety_hold_down_ms: options.safety_hold_down_ms,
        keep_tags: options.keep_tags.clone(),
        pinned_manifest_count: 0,
        pinned_blob_count: 0,
        planned_manifest_count: 0,
        planned_blob_count: 0,
        planned_reclaim_bytes: 0,
        applied_manifest_count: 0,
        applied_blob_count: 0,
        applied_reclaim_bytes: 0,
        audit_log_path: None,
        entries: Vec::new(),
    };

    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(err) => {
            return Err(err).with_context(|| format!("stat raw mirror root {}", root.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "refusing to prune invalid raw mirror root {}",
            root.display()
        );
    }
    report.initialized = true;

    let manifests = collect_prune_manifests(&root)?;
    report.manifest_count = manifests.len() as u64;

    let mut blob_to_manifests: HashMap<String, Vec<String>> = HashMap::new();
    let mut manifest_by_id: HashMap<String, &RawMirrorPruneManifest> = HashMap::new();
    let mut blob_size_by_relative: HashMap<String, u64> = HashMap::new();
    for manifest in &manifests {
        manifest_by_id.insert(manifest.manifest_id.clone(), manifest);
        blob_to_manifests
            .entry(manifest.blob_relative_path.clone())
            .or_default()
            .push(manifest.manifest_id.clone());
        blob_size_by_relative
            .entry(manifest.blob_relative_path.clone())
            .or_insert_with(|| {
                blob_file_size(&root.join(&manifest.blob_relative_path))
                    .unwrap_or(manifest.blob_size_bytes)
            });
    }
    report.unique_blob_count = blob_size_by_relative.len() as u64;
    report.current_blob_bytes = blob_size_by_relative
        .values()
        .copied()
        .fold(0u64, u64::saturating_add);

    let now = now_ms();
    let mut pinned_manifests = pinned_prune_manifest_ids(
        data_dir,
        &manifests,
        &options.keep_tags,
        options.safety_hold_down_ms,
        now,
    )?;
    // R9 (任务书 #113): a manifest that captured a still-referenced blob is
    // protected regardless of age/keep-tags -- the mirror retention
    // contract (spec's "镜像保留契约") outranks ordinary retention policy.
    for manifest in &manifests {
        if options.referenced_blobs.contains(&manifest.blob_relative_path) {
            pinned_manifests.insert(manifest.manifest_id.clone());
        }
    }
    report.pinned_manifest_count = pinned_manifests.len() as u64;
    // R1-N18 (任务书 #118b): computed WITHOUT `referenced_blobs` chained in --
    // the old code unioned `referenced_blobs` into `pinned_blobs` *before*
    // checking `referenced_blobs.is_subset(&pinned_blobs)`, which made that
    // check vacuously true no matter what (a set is always a subset of
    // itself-plus-more). This set only contains blobs that actually have a
    // manifest backing them (including any manifest pinned above specifically
    // *because* it captured a referenced blob, R9's real protection
    // mechanism) -- a referenced blob with no manifest at all in the
    // inventory (a dangling `excluded.raw.blob` pointer) is absent from it,
    // so the subset check below can actually fail.
    let pinned_blobs_from_manifests: HashSet<String> = blob_to_manifests
        .iter()
        .filter(|(_, manifest_ids)| manifest_ids.iter().any(|id| pinned_manifests.contains(id)))
        .map(|(blob_relative_path, _)| blob_relative_path.clone())
        .collect();

    if options.apply && !options.referenced_blobs.is_subset(&pinned_blobs_from_manifests) {
        let missing: Vec<&String> =
            options.referenced_blobs.difference(&pinned_blobs_from_manifests).collect();
        anyhow::bail!(
            "raw mirror prune refused: {} referenced blob(s) have no protected manifest backing them \
             (R9 invariant violated): {missing:?}",
            missing.len()
        );
    }

    // Past the check above, `referenced_blobs` is already a subset of
    // `pinned_blobs_from_manifests` (or `apply` is false and the check never
    // ran) -- chaining it in here is the same defensive belt-and-suspenders
    // union the pre-fix code did, just after the check instead of before it.
    let pinned_blobs: HashSet<String> =
        pinned_blobs_from_manifests.into_iter().chain(options.referenced_blobs.iter().cloned()).collect();
    report.pinned_blob_count = pinned_blobs.len() as u64;

    let mut selected_manifests: HashSet<String> = HashSet::new();
    let mut manifest_reasons: HashMap<String, String> = HashMap::new();

    if let Some(older_than_ms) = options.older_than_ms {
        let cutoff_ms = now.saturating_sub(older_than_ms.max(0));
        for manifest in &manifests {
            if manifest.captured_at_ms <= cutoff_ms
                && !pinned_manifests.contains(&manifest.manifest_id)
            {
                selected_manifests.insert(manifest.manifest_id.clone());
                manifest_reasons
                    .entry(manifest.manifest_id.clone())
                    .or_insert_with(|| format!("captured_at_ms <= {cutoff_ms}"));
            }
        }
    }

    if let Some(max_size_bytes) = options.max_size_bytes
        && report.current_blob_bytes > max_size_bytes
    {
        let mut blob_groups: Vec<_> = blob_to_manifests
            .iter()
            .map(|(blob_relative_path, manifest_ids)| {
                let oldest_capture = manifest_ids
                    .iter()
                    .filter_map(|id| manifest_by_id.get(id).map(|m| m.captured_at_ms))
                    .min()
                    .unwrap_or(i64::MAX);
                let size = blob_size_by_relative
                    .get(blob_relative_path)
                    .copied()
                    .unwrap_or(0);
                (
                    blob_relative_path.clone(),
                    manifest_ids.clone(),
                    oldest_capture,
                    size,
                )
            })
            .collect::<Vec<_>>();
        blob_groups.sort_by(|left, right| left.2.cmp(&right.2).then_with(|| left.0.cmp(&right.0)));

        let mut projected_bytes = report.current_blob_bytes;
        for (blob_relative_path, manifest_ids, _, size) in blob_groups {
            if projected_bytes <= max_size_bytes {
                break;
            }
            if pinned_blobs.contains(&blob_relative_path) {
                continue;
            }
            for manifest_id in manifest_ids {
                if !pinned_manifests.contains(&manifest_id) {
                    selected_manifests.insert(manifest_id.clone());
                    manifest_reasons.entry(manifest_id).or_insert_with(|| {
                        format!("max-size over budget; retiring blob {blob_relative_path}")
                    });
                }
            }
            projected_bytes = projected_bytes.saturating_sub(size);
        }
    }

    let selected_blobs: HashSet<String> = blob_to_manifests
        .iter()
        .filter(|(_, manifest_ids)| {
            manifest_ids
                .iter()
                .all(|id| selected_manifests.contains(id))
        })
        .map(|(blob_relative_path, _)| blob_relative_path.clone())
        .collect();

    let mut entries = Vec::new();
    let mut selected_manifest_ids = selected_manifests.into_iter().collect::<Vec<_>>();
    selected_manifest_ids.sort();
    for manifest_id in selected_manifest_ids {
        let Some(manifest) = manifest_by_id.get(&manifest_id) else {
            continue;
        };
        let reason = manifest_reasons
            .remove(&manifest_id)
            .unwrap_or_else(|| "selected by retention policy".to_string());
        entries.push(RawMirrorPruneEntry {
            kind: "manifest".to_string(),
            path: manifest.relative_path.clone(),
            blob_blake3: Some(manifest.blob_blake3.clone()),
            size_bytes: manifest.size_bytes,
            reason,
            applied: false,
        });
    }

    let mut selected_blob_paths = selected_blobs.into_iter().collect::<Vec<_>>();
    selected_blob_paths.sort();
    for blob_relative_path in selected_blob_paths {
        let size = blob_size_by_relative
            .get(&blob_relative_path)
            .copied()
            .unwrap_or(0);
        let blob_blake3 = blob_relative_path
            .rsplit('/')
            .next()
            .and_then(|name| name.strip_suffix(".raw"))
            .map(ToOwned::to_owned);
        entries.push(RawMirrorPruneEntry {
            kind: "blob".to_string(),
            path: blob_relative_path,
            blob_blake3,
            size_bytes: size,
            reason: "no retained manifest references this blob after prune plan".to_string(),
            applied: false,
        });
    }

    report.planned_manifest_count = entries
        .iter()
        .filter(|entry| entry.kind == "manifest")
        .count() as u64;
    report.planned_blob_count = entries.iter().filter(|entry| entry.kind == "blob").count() as u64;
    report.planned_reclaim_bytes = entries
        .iter()
        .map(|entry| entry.size_bytes)
        .fold(0, u64::saturating_add);

    if options.apply {
        fire_prune_fault_hook();
        for entry in &mut entries {
            let path = root.join(&entry.path);
            let removed = remove_prune_target_file(&path)
                .with_context(|| format!("applying raw mirror prune for {}", path.display()))?;
            entry.applied = removed;
            if removed {
                if entry.kind == "manifest" {
                    report.applied_manifest_count = report.applied_manifest_count.saturating_add(1);
                } else if entry.kind == "blob" {
                    report.applied_blob_count = report.applied_blob_count.saturating_add(1);
                }
                report.applied_reclaim_bytes = report
                    .applied_reclaim_bytes
                    .saturating_add(entry.size_bytes);
            }
        }
    }

    report.entries = entries;
    if !report.entries.is_empty() {
        let audit_path = append_prune_audit_log(&root, &report)?;
        report.audit_log_path = Some(audit_path.display().to_string());
    }
    Ok(report)
}

fn collect_prune_manifests(root: &Path) -> Result<Vec<RawMirrorPruneManifest>> {
    let manifests_dir = root.join("manifests");
    let metadata = match fs::symlink_metadata(&manifests_dir) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("stat {}", manifests_dir.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "refusing to prune invalid raw mirror manifests directory {}",
            manifests_dir.display()
        );
    }

    let mut manifests = Vec::new();
    for entry in
        fs::read_dir(&manifests_dir).with_context(|| format!("read {}", manifests_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let manifest_metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("stat raw mirror manifest {}", path.display()))?;
        if manifest_metadata.file_type().is_symlink() || !manifest_metadata.is_file() {
            anyhow::bail!(
                "refusing to prune with non-regular raw mirror manifest {}",
                path.display()
            );
        }
        let manifest = read_raw_mirror_manifest(&path)?;
        if manifest.manifest_kind != RAW_MIRROR_MANIFEST_KIND {
            anyhow::bail!(
                "refusing to prune with unexpected raw mirror manifest kind `{}` in {}",
                manifest.manifest_kind,
                path.display()
            );
        }
        let Some(expected_blob_relative_path) =
            raw_mirror_blob_relative_path(&manifest.blob_blake3)
        else {
            anyhow::bail!(
                "refusing to prune raw mirror manifest {} with invalid blob hash",
                path.display()
            );
        };
        if manifest.blob_relative_path != expected_blob_relative_path {
            anyhow::bail!(
                "refusing to prune raw mirror manifest {} with unexpected blob path `{}`",
                path.display(),
                manifest.blob_relative_path
            );
        }
        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        manifests.push(RawMirrorPruneManifest {
            manifest_id: manifest.manifest_id,
            relative_path,
            size_bytes: manifest_metadata.len(),
            blob_blake3: manifest.blob_blake3,
            blob_relative_path: manifest.blob_relative_path,
            blob_size_bytes: manifest.blob_size_bytes,
            captured_at_ms: manifest.captured_at_ms,
            provider: manifest.provider,
            original_path: manifest.original_path,
            db_links: manifest.db_links,
        });
    }
    manifests.sort_by(|left, right| {
        left.captured_at_ms
            .cmp(&right.captured_at_ms)
            .then_with(|| left.provider.cmp(&right.provider))
            .then_with(|| left.original_path.cmp(&right.original_path))
            .then_with(|| left.manifest_id.cmp(&right.manifest_id))
    });
    Ok(manifests)
}

fn pinned_prune_manifest_ids(
    data_dir: &Path,
    manifests: &[RawMirrorPruneManifest],
    keep_tags: &[String],
    safety_hold_down_ms: i64,
    now_ms: i64,
) -> Result<HashSet<String>> {
    let mut pinned = HashSet::new();
    if safety_hold_down_ms > 0 {
        let cutoff_ms = now_ms.saturating_sub(safety_hold_down_ms);
        for manifest in manifests {
            if manifest.captured_at_ms > cutoff_ms {
                pinned.insert(manifest.manifest_id.clone());
            }
        }
    }

    let normalized_keep_tags = keep_tags
        .iter()
        .map(|tag| tag.trim())
        .filter(|tag| !tag.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if normalized_keep_tags.is_empty() {
        return Ok(pinned);
    }

    let keep_tag_conversation_ids =
        load_keep_tag_conversation_ids(data_dir, manifests, &normalized_keep_tags)?;
    for manifest in manifests {
        if manifest.db_links.iter().any(|link| {
            link.conversation_id
                .is_some_and(|id| keep_tag_conversation_ids.contains(&id))
        }) {
            pinned.insert(manifest.manifest_id.clone());
        }
    }
    Ok(pinned)
}

fn load_keep_tag_conversation_ids(
    data_dir: &Path,
    manifests: &[RawMirrorPruneManifest],
    keep_tags: &[String],
) -> Result<HashSet<i64>> {
    use crate::storage::api::Value as ParamValue;

    let mut conversation_ids = manifests
        .iter()
        .flat_map(|manifest| manifest.db_links.iter())
        .filter_map(|link| link.conversation_id)
        .collect::<Vec<_>>();
    conversation_ids.sort_unstable();
    conversation_ids.dedup();
    if conversation_ids.is_empty() {
        return Ok(HashSet::new());
    }

    let db_path = data_dir.join("agent_search.db");
    let conn = crate::storage::sqlite::open_franken_raw_readonly_connection_with_timeout(
        &db_path,
        Duration::from_secs(30),
    )
    .with_context(|| {
        format!(
            "open {} to honor raw-mirror prune --keep-tag",
            db_path.display()
        )
    })?;
    let _ = conn.execute("PRAGMA query_only = 1;", &[]);

    let mut pinned = HashSet::new();
    for id_chunk in conversation_ids.chunks(400) {
        let tag_placeholders = (0..keep_tags.len())
            .map(|idx| format!("?{}", idx + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let id_offset = keep_tags.len();
        let id_placeholders = (0..id_chunk.len())
            .map(|idx| format!("?{}", id_offset + idx + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT DISTINCT ct.conversation_id \
             FROM conversation_tags ct \
             JOIN tags t ON t.id = ct.tag_id \
             WHERE t.name IN ({tag_placeholders}) \
               AND ct.conversation_id IN ({id_placeholders})"
        );
        let mut params = keep_tags
            .iter()
            .map(|tag| ParamValue::from(tag.as_str()))
            .collect::<Vec<_>>();
        params.extend(id_chunk.iter().copied().map(ParamValue::from));
        let rows: Vec<i64> = conn
            .query_all_map(&sql, &params, |row| row.get_typed(0))
            .with_context(|| "query raw-mirror prune keep-tag conversation pins")?;
        pinned.extend(rows);
    }

    Ok(pinned)
}

fn blob_file_size(path: &Path) -> Option<u64> {
    fs::symlink_metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .map(|metadata| metadata.len())
}

fn remove_prune_target_file(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err).with_context(|| format!("stat {}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "refusing to prune non-regular raw mirror file {}",
            path.display()
        );
    }
    fs::remove_file(path).with_context(|| format!("remove raw mirror file {}", path.display()))?;
    sync_parent(path)?;
    Ok(true)
}

fn append_prune_audit_log(root: &Path, report: &RawMirrorPruneReport) -> Result<PathBuf> {
    ensure_private_dir(root)?;
    let audit_path = root.join("pruned.jsonl");
    ensure_prune_audit_log_appendable(&audit_path)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit_path)
        .with_context(|| format!("open raw mirror prune audit {}", audit_path.display()))?;
    set_private_file_permissions(&audit_path)?;
    let now = now_ms();
    for entry in &report.entries {
        let record = json!({
            "schema_version": 1,
            "recorded_at_ms": now,
            "mode": report.mode,
            "kind": entry.kind,
            "path": entry.path,
            "blob_blake3": entry.blob_blake3,
            "size_bytes": entry.size_bytes,
            "reason": entry.reason,
            "applied": entry.applied,
        });
        writeln!(file, "{record}")
            .with_context(|| format!("write raw mirror prune audit {}", audit_path.display()))?;
    }
    sync_open_file_if_required(&file, || {
        format!("sync raw mirror prune audit {}", audit_path.display())
    })?;
    sync_parent(&audit_path)?;
    Ok(audit_path)
}

fn ensure_prune_audit_log_appendable(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "refusing to append raw mirror prune audit through symlink {}",
                path.display()
            );
        }
        Ok(metadata) if !metadata.is_file() => {
            anyhow::bail!(
                "refusing to append raw mirror prune audit to non-file {}",
                path.display()
            );
        }
        Ok(_) => Ok(()),
        Err(err) if matches!(err.kind(), std::io::ErrorKind::NotFound) => Ok(()),
        Err(err) => Err(err).with_context(|| {
            format!(
                "inspect raw mirror prune audit before append {}",
                path.display()
            )
        }),
    }
}

fn merge_min_max(min: &mut Option<i64>, max: &mut Option<i64>, value: Option<i64>) {
    let Some(value) = value else {
        return;
    };
    *min = Some(min.map_or(value, |current| current.min(value)));
    *max = Some(max.map_or(value, |current| current.max(value)));
}

fn raw_mirror_dir_file_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        } else if metadata.is_dir() {
            let Ok(entries) = fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                stack.push(entry.path());
            }
        }
    }
    total
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RawMirrorBlobCacheKey {
    data_dir: PathBuf,
    source_path: PathBuf,
    source_identity: Option<String>,
    source_size_bytes: u64,
    source_mtime_ns: Option<u128>,
    source_change_time_ns: Option<u128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawMirrorBlobRecord {
    blob_blake3: String,
    bytes_copied: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawMirrorCompressionEnvelope {
    state: String,
    algorithm: Option<String>,
    uncompressed_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawMirrorEncryptionEnvelope {
    state: String,
    algorithm: Option<String>,
    key_id: Option<String>,
    envelope_version: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawMirrorVerificationRecord {
    status: String,
    verifier: String,
    content_blake3: Option<String>,
    verified_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawMirrorManifestFile {
    schema_version: u32,
    manifest_kind: String,
    manifest_id: String,
    blob_hash_algorithm: String,
    blob_relative_path: String,
    blob_blake3: String,
    blob_size_bytes: u64,
    provider: String,
    source_id: String,
    origin_kind: String,
    origin_host: Option<String>,
    original_path: String,
    redacted_original_path: String,
    original_path_blake3: String,
    captured_at_ms: i64,
    source_mtime_ms: Option<i64>,
    source_size_bytes: u64,
    compression: RawMirrorCompressionEnvelope,
    encryption: RawMirrorEncryptionEnvelope,
    db_links: Vec<RawMirrorDbLink>,
    verification: RawMirrorVerificationRecord,
    manifest_blake3: Option<String>,
}

pub fn capture_source_file(input: RawMirrorCaptureInput<'_>) -> Result<RawMirrorCaptureRecord> {
    let source_metadata = fs::symlink_metadata(input.source_path)
        .with_context(|| format!("stat raw mirror source {}", input.source_path.display()))?;
    if source_metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "refusing to raw-mirror symlink source {}",
            input.source_path.display()
        ));
    }
    if !source_metadata.is_file() {
        return Err(anyhow!(
            "refusing to raw-mirror non-file source {}",
            input.source_path.display()
        ));
    }

    let root = ensure_raw_mirror_root(input.data_dir)?;
    ensure_private_dir_descendant(&root, &root.join("tmp"))?;

    let cache_key = raw_mirror_blob_cache_key(&input, &source_metadata);
    let (blob_blake3, bytes_copied, blob_already_present) =
        match cached_raw_mirror_blob_record(&cache_key, &root) {
            Some(record) => (record.blob_blake3, record.bytes_copied, true),
            None => {
                let temp_dir = unique_capture_temp_dir(&root);
                ensure_private_dir_descendant(&root, &temp_dir)?;
                let CopyToTempResult {
                    temp_path,
                    blob_blake3,
                    bytes_copied,
                } = copy_source_to_private_temp(input.source_path, &temp_dir, &source_metadata)?;
                let blob_relative_path = raw_mirror_blob_relative_path(&blob_blake3)
                    .ok_or_else(|| anyhow!("computed invalid raw mirror blake3 digest"))?;
                let blob_path = root.join(&blob_relative_path);
                let already_present =
                    publish_content_addressed_temp(&root, &temp_path, &blob_path, &blob_blake3)?;
                remove_empty_temp_dir_best_effort(&temp_dir);
                cache_raw_mirror_blob_record(
                    cache_key.clone(),
                    RawMirrorBlobRecord {
                        blob_blake3: blob_blake3.clone(),
                        bytes_copied,
                    },
                );
                (blob_blake3, bytes_copied, already_present)
            }
        };
    let blob_relative_path = raw_mirror_blob_relative_path(&blob_blake3)
        .ok_or_else(|| anyhow!("computed invalid raw mirror blake3 digest"))?;

    let original_path = input.source_path.display().to_string();
    let original_path_blake3 = raw_mirror_original_path_blake3(&original_path);
    let manifest_id = raw_mirror_manifest_id(
        input.provider,
        input.source_id,
        input.origin_kind,
        input.origin_host,
        &original_path_blake3,
        &blob_blake3,
    );
    let manifest_relative_path = raw_mirror_manifest_relative_path(&manifest_id);
    let manifest_path = root.join(&manifest_relative_path);
    let captured_at_ms = now_ms();
    let source_mtime_ms = source_metadata.modified().ok().and_then(system_time_to_ms);
    let mut manifest = RawMirrorManifestFile {
        schema_version: RAW_MIRROR_SCHEMA_VERSION,
        manifest_kind: RAW_MIRROR_MANIFEST_KIND.to_string(),
        manifest_id: manifest_id.clone(),
        blob_hash_algorithm: RAW_MIRROR_HASH_ALGORITHM.to_string(),
        blob_relative_path: blob_relative_path.clone(),
        blob_blake3: blob_blake3.clone(),
        blob_size_bytes: bytes_copied,
        provider: input.provider.to_string(),
        source_id: input.source_id.to_string(),
        origin_kind: input.origin_kind.to_string(),
        origin_host: input.origin_host.map(ToOwned::to_owned),
        original_path,
        redacted_original_path: redacted_original_path(input.provider, input.source_path),
        original_path_blake3,
        captured_at_ms,
        source_mtime_ms,
        source_size_bytes: source_metadata.len(),
        compression: RawMirrorCompressionEnvelope {
            state: "none".to_string(),
            algorithm: None,
            uncompressed_size_bytes: Some(bytes_copied),
        },
        encryption: RawMirrorEncryptionEnvelope {
            state: "none".to_string(),
            algorithm: None,
            key_id: None,
            envelope_version: None,
        },
        db_links: unique_db_links(input.db_links),
        verification: RawMirrorVerificationRecord {
            status: "captured".to_string(),
            verifier: "cass_indexer".to_string(),
            content_blake3: Some(blob_blake3.clone()),
            verified_at_ms: Some(captured_at_ms),
        },
        manifest_blake3: None,
    };
    manifest.manifest_blake3 = Some(raw_mirror_manifest_blake3(&manifest));
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let manifest_already_present =
        publish_manifest_bytes_create_new(&root, &manifest_path, &manifest_bytes, &blob_blake3)?;
    let (record_blob_size_bytes, record_captured_at_ms, record_source_mtime_ms) =
        if manifest_already_present {
            merge_raw_mirror_manifest_db_links(
                &root,
                &manifest_path,
                input.db_links,
                Some(&blob_blake3),
            )?;
            let published = read_raw_mirror_manifest(&manifest_path)?;
            (
                published.blob_size_bytes,
                published.captured_at_ms,
                published.source_mtime_ms,
            )
        } else {
            (bytes_copied, captured_at_ms, source_mtime_ms)
        };

    Ok(RawMirrorCaptureRecord {
        manifest_id,
        manifest_relative_path,
        blob_relative_path,
        blob_blake3,
        blob_size_bytes: record_blob_size_bytes,
        captured_at_ms: record_captured_at_ms,
        source_mtime_ms: record_source_mtime_ms,
        already_present: blob_already_present && manifest_already_present,
    })
}

pub fn merge_manifest_db_links(
    data_dir: &Path,
    manifest_relative_path: &str,
    links: &[RawMirrorDbLink],
) -> Result<()> {
    if links.is_empty() {
        return Ok(());
    }
    let root = raw_mirror_root(data_dir);
    let manifest_path = raw_mirror_manifest_path_from_relative(&root, manifest_relative_path)?;
    merge_raw_mirror_manifest_db_links(&root, &manifest_path, links, None)
}

struct CopyToTempResult {
    temp_path: PathBuf,
    blob_blake3: String,
    bytes_copied: u64,
}

fn copy_source_to_private_temp(
    source_path: &Path,
    temp_dir: &Path,
    source_metadata: &fs::Metadata,
) -> Result<CopyToTempResult> {
    let temp_path = unique_temp_path(temp_dir, "blob");
    let mut source = open_stable_source_file(source_path, source_metadata)?;
    let mut temp = private_create_new_file(&temp_path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut bytes_copied = 0u64;
    loop {
        let read = source
            .read(&mut buffer)
            .with_context(|| format!("read raw mirror source {}", source_path.display()))?;
        if read == 0 {
            break;
        }
        temp.write_all(&buffer[..read])
            .with_context(|| format!("write raw mirror temp {}", temp_path.display()))?;
        hasher.update(&buffer[..read]);
        bytes_copied = bytes_copied.saturating_add(read as u64);
    }
    sync_open_file_if_required(&temp, || {
        format!("sync raw mirror temp {}", temp_path.display())
    })?;

    let final_source_metadata = source
        .metadata()
        .with_context(|| format!("stat opened raw mirror source {}", source_path.display()))?;
    if source_file_changed_during_capture(source_metadata, &final_source_metadata) {
        remove_temp_best_effort(&temp_path);
        return Err(anyhow!(
            "raw mirror source {} changed while it was being captured; retry indexing to capture a stable copy",
            source_path.display()
        ));
    }

    Ok(CopyToTempResult {
        temp_path,
        blob_blake3: hasher.finalize().to_hex().to_string(),
        bytes_copied,
    })
}

fn open_stable_source_file(source_path: &Path, expected_metadata: &fs::Metadata) -> Result<File> {
    let source = File::open(source_path)
        .with_context(|| format!("open raw mirror source {}", source_path.display()))?;
    let opened_metadata = source
        .metadata()
        .with_context(|| format!("stat opened raw mirror source {}", source_path.display()))?;
    if !same_source_identity(expected_metadata, &opened_metadata) {
        return Err(anyhow!(
            "raw mirror source {} changed identity before capture",
            source_path.display()
        ));
    }
    let current_path_metadata = fs::symlink_metadata(source_path)
        .with_context(|| format!("restat raw mirror source {}", source_path.display()))?;
    if current_path_metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "refusing to raw-mirror symlink source {}",
            source_path.display()
        ));
    }
    if !same_source_identity(expected_metadata, &current_path_metadata) {
        return Err(anyhow!(
            "raw mirror source {} changed identity before capture",
            source_path.display()
        ));
    }
    Ok(source)
}

#[cfg(unix)]
fn same_source_identity(expected: &fs::Metadata, actual: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    actual.is_file() && expected.dev() == actual.dev() && expected.ino() == actual.ino()
}

#[cfg(not(unix))]
fn same_source_identity(_expected: &fs::Metadata, actual: &fs::Metadata) -> bool {
    actual.is_file()
}

#[cfg(unix)]
fn source_identity_token(metadata: &fs::Metadata) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    Some(format!("{}:{}", metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn source_identity_token(_metadata: &fs::Metadata) -> Option<String> {
    None
}

#[cfg(unix)]
fn source_change_time_ns(metadata: &fs::Metadata) -> Option<u128> {
    use std::os::unix::fs::MetadataExt;

    let seconds = u128::try_from(metadata.ctime()).ok()?;
    let nanoseconds = u128::try_from(metadata.ctime_nsec()).ok()?;
    Some(
        seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(nanoseconds),
    )
}

#[cfg(not(unix))]
fn source_change_time_ns(_metadata: &fs::Metadata) -> Option<u128> {
    None
}

fn source_file_changed_during_capture(
    initial: &fs::Metadata,
    final_metadata: &fs::Metadata,
) -> bool {
    if initial.len() != final_metadata.len() {
        return true;
    }
    match (initial.modified().ok(), final_metadata.modified().ok()) {
        (Some(initial_mtime), Some(final_mtime)) => initial_mtime != final_mtime,
        _ => false,
    }
}

fn publish_content_addressed_temp(
    root: &Path,
    temp_path: &Path,
    final_path: &Path,
    expected_blake3: &str,
) -> Result<bool> {
    ensure_private_dir_descendant(
        root,
        final_path
            .parent()
            .ok_or_else(|| anyhow!("raw mirror blob path has no parent"))?,
    )?;
    if final_path.exists() {
        verify_existing_file(final_path, expected_blake3)?;
        remove_temp_best_effort(temp_path);
        return Ok(true);
    }

    match fs::hard_link(temp_path, final_path) {
        Ok(()) => {
            sync_file(final_path)?;
            sync_parent(final_path)?;
            remove_temp_best_effort(temp_path);
            Ok(false)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_existing_file(final_path, expected_blake3)?;
            remove_temp_best_effort(temp_path);
            Ok(true)
        }
        Err(err) => Err(anyhow!(
            "publish raw mirror blob {} from {}: {err}",
            final_path.display(),
            temp_path.display()
        )),
    }
}

fn publish_manifest_bytes_create_new(
    root: &Path,
    manifest_path: &Path,
    manifest_bytes: &[u8],
    blob_blake3: &str,
) -> Result<bool> {
    ensure_private_dir_descendant(
        root,
        manifest_path
            .parent()
            .ok_or_else(|| anyhow!("raw mirror manifest path has no parent"))?,
    )?;
    if manifest_path.exists() {
        verify_existing_manifest(manifest_path, blob_blake3)?;
        return Ok(true);
    }

    let temp_dir = unique_capture_temp_dir(root);
    ensure_private_dir_descendant(root, &temp_dir)?;
    let temp_path = unique_temp_path(&temp_dir, "manifest");
    let mut temp = private_create_new_file(&temp_path)?;
    temp.write_all(manifest_bytes)
        .with_context(|| format!("write raw mirror manifest temp {}", temp_path.display()))?;
    sync_open_file_if_required(&temp, || {
        format!("sync raw mirror manifest temp {}", temp_path.display())
    })?;

    match fs::hard_link(&temp_path, manifest_path) {
        Ok(()) => {
            // R2-B5b (任务书 #119c): this is the manifest's FIRST-EVER
            // publish for this capture -- `manifests/` may be the directory
            // `ensure_private_dir_descendant` above just created, so a
            // single-level `sync_parent` (only `manifests/` itself) leaves
            // `manifests/`'s own entry in `v1` unsynced. Same gap, same fix
            // as `replace_manifest_bytes` (#119b R2-B5 场景二): switch-gated
            // full chain walk via `sync_dir_chain_if_enabled`, not the
            // unconditional force barrier (this path runs for every
            // session, not just excluded ones).
            sync_file(manifest_path)?;
            let mut synced_dirs: HashSet<PathBuf> = HashSet::new();
            sync_dir_chain_if_enabled(manifest_path, root, &mut synced_dirs)?;
            remove_temp_best_effort(&temp_path);
            remove_empty_temp_dir_best_effort(&temp_dir);
            Ok(false)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_existing_manifest(manifest_path, blob_blake3)?;
            remove_temp_best_effort(&temp_path);
            remove_empty_temp_dir_best_effort(&temp_dir);
            Ok(true)
        }
        Err(err) => Err(anyhow!(
            "publish raw mirror manifest {} from {}: {err}",
            manifest_path.display(),
            temp_path.display()
        )),
    }
}

fn merge_raw_mirror_manifest_db_links(
    root: &Path,
    manifest_path: &Path,
    links: &[RawMirrorDbLink],
    expected_blob_blake3: Option<&str>,
) -> Result<()> {
    if links.is_empty() {
        return Ok(());
    }

    let lock = MANIFEST_UPDATE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| anyhow!("raw mirror manifest update lock poisoned"))?;

    let mut manifest = read_raw_mirror_manifest(manifest_path)?;
    if let Some(expected_blob_blake3) = expected_blob_blake3
        && manifest.blob_blake3 != expected_blob_blake3
    {
        return Err(anyhow!(
            "existing raw mirror manifest {} points at blob {}, expected {}",
            manifest_path.display(),
            manifest.blob_blake3,
            expected_blob_blake3
        ));
    }

    ensure_manifest_identity_before_write(&manifest, manifest_path)?;
    let had_self_digest = manifest.manifest_blake3.is_some();

    let mut merged_links = manifest.db_links.clone();
    merged_links.extend_from_slice(links);
    let merged_links = unique_db_links(&merged_links);
    if merged_links == manifest.db_links {
        return Ok(());
    }

    manifest.db_links = merged_links;
    // 换发新证书**只对本来就有证书的**。没记自摘要的旧件维持 `None`：
    // 「无从判断」不得被一次无关的写入洗成「已认证」（裁定 R-E-89 ②）。
    if had_self_digest {
        manifest.manifest_blake3 = Some(raw_mirror_manifest_blake3(&manifest));
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    replace_manifest_bytes(root, manifest_path, &manifest_bytes)
}

fn replace_manifest_bytes(root: &Path, manifest_path: &Path, manifest_bytes: &[u8]) -> Result<()> {
    ensure_private_dir_descendant(
        root,
        manifest_path
            .parent()
            .ok_or_else(|| anyhow!("raw mirror manifest path has no parent"))?,
    )?;
    let temp_dir = unique_capture_temp_dir(root);
    ensure_private_dir_descendant(root, &temp_dir)?;
    let temp_path = unique_temp_path(&temp_dir, "manifest-update");
    let mut temp = private_create_new_file(&temp_path)?;
    temp.write_all(manifest_bytes).with_context(|| {
        format!(
            "write raw mirror manifest update temp {}",
            temp_path.display()
        )
    })?;
    sync_open_file_if_required(&temp, || {
        format!(
            "sync raw mirror manifest update temp {}",
            temp_path.display()
        )
    })?;
    drop(temp);

    fs::rename(&temp_path, manifest_path).with_context(|| {
        format!(
            "replace raw mirror manifest {} from {}",
            manifest_path.display(),
            temp_path.display()
        )
    })?;
    set_private_file_permissions(manifest_path)?;
    sync_file(manifest_path)?;
    let mut synced_dirs: HashSet<PathBuf> = HashSet::new();
    sync_dir_chain_if_enabled(manifest_path, root, &mut synced_dirs)?;
    remove_empty_temp_dir_best_effort(&temp_dir);
    Ok(())
}

fn raw_mirror_manifest_path_from_relative(root: &Path, relative_path: &str) -> Result<PathBuf> {
    let relative = Path::new(relative_path);
    if relative.is_absolute() {
        return Err(anyhow!(
            "raw mirror manifest path must be relative: {relative_path}"
        ));
    }

    let mut normal_components = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => normal_components.push(part),
            _ => {
                return Err(anyhow!(
                    "raw mirror manifest path must use only normal relative components: {relative_path}"
                ));
            }
        }
    }

    if normal_components.len() != 2
        || normal_components[0] != std::ffi::OsStr::new("manifests")
        || Path::new(normal_components[1])
            .extension()
            .and_then(|ext| ext.to_str())
            != Some("json")
    {
        return Err(anyhow!(
            "raw mirror manifest path must match manifests/<id>.json: {relative_path}"
        ));
    }

    Ok(root.join(relative))
}

fn verify_existing_file(path: &Path, expected_blake3: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat raw mirror blob {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "refusing to read symlink raw mirror blob {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(anyhow!(
            "refusing to read non-file raw mirror blob {}",
            path.display()
        ));
    }
    let actual = file_blake3(path)?;
    if actual == expected_blake3 {
        Ok(())
    } else {
        Err(anyhow!(
            "existing raw mirror blob {} has blake3 {}, expected {}",
            path.display(),
            actual,
            expected_blake3
        ))
    }
}

fn verify_existing_manifest(path: &Path, expected_blob_blake3: &str) -> Result<()> {
    let manifest = read_raw_mirror_manifest(path)?;
    if manifest.blob_blake3 == expected_blob_blake3 {
        Ok(())
    } else {
        Err(anyhow!(
            "existing raw mirror manifest {} points at blob {}, expected {}",
            path.display(),
            manifest.blob_blake3,
            expected_blob_blake3
        ))
    }
}

fn read_raw_mirror_manifest(path: &Path) -> Result<RawMirrorManifestFile> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat raw mirror manifest {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "refusing to read symlink raw mirror manifest {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(anyhow!(
            "refusing to read non-file raw mirror manifest {}",
            path.display()
        ));
    }
    serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read raw mirror manifest {}", path.display()))?,
    )
    .with_context(|| format!("parse raw mirror manifest {}", path.display()))
}

fn raw_mirror_root(data_dir: &Path) -> PathBuf {
    data_dir
        .join(RAW_MIRROR_ROOT_DIR)
        .join(RAW_MIRROR_VERSION_DIR)
}

fn ensure_raw_mirror_root(data_dir: &Path) -> Result<PathBuf> {
    let root_parent = data_dir.join(RAW_MIRROR_ROOT_DIR);
    ensure_private_dir(&root_parent)?;
    let root = root_parent.join(RAW_MIRROR_VERSION_DIR);
    ensure_private_dir(&root)?;
    Ok(root)
}

/// PR6 T2b (任务书 #114): resolve a just-captured [`RawMirrorCaptureRecord`]
/// back to `(original_path, blob_bytes)` for `reparse_from_capture` to hand
/// to the connector's own file parser. Manifest-relative-path validation is
/// the same `raw_mirror_manifest_path_from_relative` every other manifest
/// reader uses -- no second path-safety implementation.
pub(crate) fn read_capture_for_reparse(data_dir: &Path, record: &RawMirrorCaptureRecord) -> Result<(String, Vec<u8>)> {
    let root = raw_mirror_root(data_dir);
    let manifest_path = raw_mirror_manifest_path_from_relative(&root, &record.manifest_relative_path)?;
    let manifest = read_raw_mirror_manifest(&manifest_path)?;
    let blob_path = root.join(&record.blob_relative_path);
    let blob = fs::read(&blob_path).with_context(|| format!("read raw mirror blob {}", blob_path.display()))?;
    Ok((manifest.original_path, blob))
}

/// PR6 T2b (任务书 #114, R2-B3): force-fsync a session's captured blob and
/// manifest (plus their parent directories) *unconditionally* -- unlike
/// [`sync_file`]/[`sync_parent`], this does **not** consult
/// `CASS_RAW_MIRROR_FSYNC` (Global Constraints: "排除行提交前镜像必须持久化
/// ...不受 CASS_RAW_MIRROR_FSYNC 默认关闭影响"). Called only when the
/// session being prepared has at least one exclusion marker; sessions with
/// none keep the existing (default-off) fsync behavior untouched.
pub(crate) fn sync_capture_durable(data_dir: &Path, record: &RawMirrorCaptureRecord) -> Result<()> {
    let root = raw_mirror_root(data_dir);
    let manifest_path = raw_mirror_manifest_path_from_relative(&root, &record.manifest_relative_path)?;
    let blob_path = root.join(&record.blob_relative_path);

    force_sync_file(&blob_path)?;
    force_sync_file(&manifest_path)?;

    // R1-B3 (任务书 #118a): fsync the FULL directory chain up to the mirror
    // root, not just each file's immediate parent -- a freshly-created
    // `blobs/blake3/<prefix>/` needs its own entry fsynced in `blake3/`,
    // and (if also new) `blake3/`'s entry fsynced in `blobs/`, or a crash
    // can lose an intermediate directory's entry even though the leaf file
    // itself is durable, making the blob unreachable despite `sync_all`
    // having "succeeded". `synced_dirs` dedupes across the blob/manifest
    // chains (they usually share ancestors) within this one call only --
    // no state carries across separate `sync_capture_durable` invocations.
    let mut synced_dirs: HashSet<PathBuf> = HashSet::new();
    force_sync_dir_chain(&blob_path, &root, &mut synced_dirs)?;
    force_sync_dir_chain(&manifest_path, &root, &mut synced_dirs)?;

    // R2-B5 场景一 (任务书 #119b): `force_sync_dir_chain` stops AT `root`
    // (inclusive) -- it fsyncs `v1`'s own directory listing but never the
    // entry FOR `v1` inside `v1`'s parent (`raw-mirror/`). A freshly-created
    // `v1` (this raw mirror's very first capture) is therefore still not
    // durable even after both chain-walks above succeed: `raw-mirror/`'s own
    // directory listing was never fsynced, so `v1`'s directory entry can
    // still be lost on crash despite everything under it being durable.
    // Unconditional (same as the rest of this function) and cheap --
    // `raw-mirror/`'s listing essentially never changes again after the
    // first capture ever made against this `data_dir`.
    if let Some(root_parent) = root.parent() {
        force_sync_dir(root_parent)?;
    }

    // R3-B1 (任务书 #119d): the fix directly above only carries the chain up
    // to `raw-mirror/`'s own directory listing -- it never fsyncs `data_dir`
    // itself, which is `raw-mirror/`'s parent and therefore the directory
    // that actually holds `raw-mirror/`'s entry. Same gap, one level higher:
    // a freshly-created `raw-mirror/` (this data_dir's very first capture
    // ever) is still not durably *reachable from data_dir* even though
    // everything under it (including `raw-mirror/`'s own listing) is now
    // durable. Unconditional and cheap regardless of whether `data_dir`
    // itself happens to be newly created this run -- `data_dir`'s "does it
    // contain raw-mirror/" fact only changes once, on the first capture ever
    // made against this `data_dir`.
    //
    // R4-B1 (任务书 #120a): this function has no way to create `data_dir`
    // itself and therefore no way to know whether it was just created --
    // that's `create_dir_all_durable`'s job, at whichever call site actually
    // creates `data_dir` (`acquire_index_run_lock` for a normal index run;
    // `QuarantineState::save`, `prepare_headless_once_tui_artifacts`, and
    // `cass doctor --fix`'s data-directory auto-repair for the other
    // production entry points that can create it). Each of those closes
    // `data_dir`'s OWN durability (its entry in ITS OWN parent) at creation
    // time, immediately, before any capture can run -- so by the time this
    // function is ever called, that half of the chain is already someone
    // else's discharged responsibility. This line's only job is the half
    // BELOW `data_dir`: making `raw-mirror/`'s entry inside `data_dir`
    // durable, which is unconditional and cheap for the reason above.
    force_sync_dir(data_dir)?;
    Ok(())
}

fn force_sync_file(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    options.write(true);
    options.open(path).and_then(|file| file.sync_all()).with_context(|| format!("force-sync raw mirror file {}", path.display()))
}

/// Walk `path`'s parent directory upward through `root` (inclusive),
/// force-syncing each level not already covered by an earlier call within
/// the same `synced_dirs` set. Stops at `root` even if further ancestors
/// exist (never fsyncs outside the mirror tree).
fn force_sync_dir_chain(path: &Path, root: &Path, synced_dirs: &mut HashSet<PathBuf>) -> Result<()> {
    let Some(start) = path.parent() else {
        return Ok(());
    };
    for dir in start.ancestors() {
        if !synced_dirs.insert(dir.to_path_buf()) {
            break;
        }
        force_sync_dir(dir)?;
        if dir == root {
            break;
        }
    }
    Ok(())
}

// R4-B1 (任务书 #120a): `pub(crate)` so `create_dir_all_durable`'s callers
// outside this module (`acquire_index_run_lock`, `QuarantineState::save`,
// `prepare_headless_once_tui_artifacts`, `cass doctor --fix`) share the same
// fsync-a-directory primitive AND the same `DIR_SYNC_PROBE` test hook --
// visibility change only, behavior unchanged.
#[cfg(not(windows))]
pub(crate) fn force_sync_dir(dir: &Path) -> Result<()> {
    File::open(dir).and_then(|file| file.sync_all()).with_context(|| format!("force-sync raw mirror directory {}", dir.display()))?;
    fire_dir_sync_probe(dir);
    Ok(())
}

#[cfg(windows)]
pub(crate) fn force_sync_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

/// R4-B1 (任务书 #120a): create `path` and any missing ancestors (exactly
/// like `fs::create_dir_all`, same permissions -- `path` is never treated as
/// a private raw-mirror directory here, unlike `create_private_dir_all`),
/// then fsync the PARENT of every ancestor this call actually created, so
/// each newly-created directory's own entry survives a crash.
///
/// This is the fix for the R4-B1 class of bug: four rounds in a row
/// (`v1` -> `raw-mirror/` -> `data_dir` -> `data_dir`'s own ancestors) each
/// guessed a fixed upper bound for how far up the fsync chain needed to
/// reach, and each guess was wrong because SOMETHING ELSE in this codebase
/// could -- and does -- create the directory one level above the previous
/// guess's stopping point. This function has no guessed stopping point: it
/// walks `path`'s ancestors, checking actual filesystem state to find which
/// ones do NOT yet exist, creates exactly those, and fsyncs exactly their
/// parents -- "新建到哪就同步到哪" (sync as far up as this call actually
/// built, nothing more, nothing less, no assumption about what's above).
///
/// Existing ancestors are left untouched and unsynced by this function --
/// this call's contract only covers what IT builds. A directory that
/// already existed before this call is either a) durable because whoever
/// created it already made it durable, or b) a residual crash-durability
/// gap that predates this call entirely and is out of scope for it to fix.
pub(crate) fn create_dir_all_durable(path: &Path) -> Result<()> {
    let mut missing: Vec<PathBuf> = Vec::new();
    for ancestor in path.ancestors() {
        if fs::symlink_metadata(ancestor).is_ok() {
            break;
        }
        missing.push(ancestor.to_path_buf());
    }
    // `missing` was collected leaf-first (`path` itself, then its parent,
    // ...); reverse it so `create_dir_all` below builds shallow-to-deep --
    // matches `std::fs::create_dir_all`'s own order and doesn't matter for
    // correctness (it creates the whole chain in one call regardless), but
    // keeps the syncing loop below in the same intuitive order.
    missing.reverse();

    fs::create_dir_all(path).with_context(|| format!("create directory {}", path.display()))?;

    let mut synced_parents: HashSet<PathBuf> = HashSet::new();
    for created in &missing {
        if let Some(parent) = created.parent()
            && synced_parents.insert(parent.to_path_buf())
        {
            force_sync_dir(parent)?;
        }
    }
    Ok(())
}

fn raw_mirror_blob_cache_key(
    input: &RawMirrorCaptureInput<'_>,
    source_metadata: &fs::Metadata,
) -> RawMirrorBlobCacheKey {
    RawMirrorBlobCacheKey {
        data_dir: input.data_dir.to_path_buf(),
        source_path: input.source_path.to_path_buf(),
        source_identity: source_identity_token(source_metadata),
        source_size_bytes: source_metadata.len(),
        source_mtime_ns: source_metadata.modified().ok().and_then(system_time_to_ns),
        source_change_time_ns: source_change_time_ns(source_metadata),
    }
}

fn cached_raw_mirror_blob_record(
    key: &RawMirrorBlobCacheKey,
    root: &Path,
) -> Option<RawMirrorBlobRecord> {
    let cache = BLOB_CAPTURE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let record = {
        let mut guard = cache.lock().ok()?;
        let record = guard.get(key).cloned()?;
        if raw_mirror_blob_relative_path(&record.blob_blake3).is_none() {
            guard.remove(key);
            return None;
        }
        record
    };

    let blob_relative_path = raw_mirror_blob_relative_path(&record.blob_blake3)?;
    let blob_path = root.join(blob_relative_path);
    let metadata_valid = fs::symlink_metadata(&blob_path)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false);
    if !metadata_valid {
        remove_cached_raw_mirror_blob_record_if_unchanged(cache, key, &record);
        return None;
    }

    match file_blake3(&blob_path) {
        Ok(actual) if actual == record.blob_blake3 => Some(record),
        Ok(actual) => {
            tracing::warn!(
                path = %blob_path.display(),
                expected_blake3 = %record.blob_blake3,
                actual_blake3 = %actual,
                "discarding raw mirror blob cache entry with mismatched content"
            );
            remove_cached_raw_mirror_blob_record_if_unchanged(cache, key, &record);
            None
        }
        Err(err) => {
            tracing::debug!(
                path = %blob_path.display(),
                error = %err,
                "discarding unreadable raw mirror blob cache entry"
            );
            remove_cached_raw_mirror_blob_record_if_unchanged(cache, key, &record);
            None
        }
    }
}

fn remove_cached_raw_mirror_blob_record_if_unchanged(
    cache: &Mutex<HashMap<RawMirrorBlobCacheKey, RawMirrorBlobRecord>>,
    key: &RawMirrorBlobCacheKey,
    stale_record: &RawMirrorBlobRecord,
) {
    if let Ok(mut guard) = cache.lock()
        && guard
            .get(key)
            .is_some_and(|current| current == stale_record)
    {
        guard.remove(key);
    }
}

fn cache_raw_mirror_blob_record(key: RawMirrorBlobCacheKey, record: RawMirrorBlobRecord) {
    let cache = BLOB_CAPTURE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = cache.lock() {
        guard.insert(key, record);
    }
}

fn raw_mirror_blob_relative_path(blob_blake3: &str) -> Option<String> {
    if blob_blake3.len() != 64 || !blob_blake3.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let lower = blob_blake3.to_ascii_lowercase();
    Some(format!(
        "blobs/{}/{}/{}.{}",
        RAW_MIRROR_HASH_ALGORITHM,
        &lower[..2],
        lower,
        RAW_MIRROR_BLOB_EXTENSION
    ))
}

fn raw_mirror_manifest_relative_path(manifest_id: &str) -> String {
    format!("manifests/{manifest_id}.json")
}

fn raw_mirror_original_path_blake3(original_path: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"doctor-raw-mirror-original-path-v1");
    hasher.update(&[0]);
    hasher.update(original_path.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn raw_mirror_manifest_id(
    provider: &str,
    source_id: &str,
    origin_kind: &str,
    origin_host: Option<&str>,
    original_path_blake3: &str,
    blob_blake3: &str,
) -> String {
    canonical_blake3(
        "doctor-raw-mirror-manifest-id-v1",
        json!({
            "provider": provider,
            "source_id": source_id,
            "origin_kind": origin_kind,
            "origin_host": origin_host,
            "original_path_blake3": original_path_blake3,
            "blob_blake3": blob_blake3,
        }),
    )
}

/// 落盘前的**独立防线**（FIND-12 / 裁定 R-E-89）：identity 不符的 manifest 一律不写。
///
/// 这一条不依赖上游有没有跳过它 —— 上游的跳过逻辑可能漏、可能被将来的重构绕开，
/// 而这里守的是**不可逆**的那一半：写盘会 `manifest_blake3 = recompute(...)`，
/// 于是「记录的自摘要与重算值不符」这个**篡改证据被这一次写抹掉**，
/// 此后任何一次 relink / doctor 都再也报不出它。实测过一次 `--apply` 的净效果：
/// 篡改留着、合法 backlink 清零、自摘要刷新成一致、`findings=[]`
/// —— 系统收敛到一个「看起来完全健康」的被篡改状态。
///
/// 三档处置与上游一致（裁定 R-E-89）：
/// * 记了自摘要且**不符** → 具名拒绝，一行不写；
/// * 记了自摘要且相符 → 正常写，写完换发新证书；
/// * **没记**自摘要（旧格式，「无从判断」档）→ 允许写，但**不补记** ——
///   给一份从未被校验过的 manifest 发第一张证书，等于把「无从判断」洗成「已认证」。
fn ensure_manifest_identity_before_write(
    manifest: &RawMirrorManifestFile,
    manifest_path: &Path,
) -> Result<()> {
    let Some(recorded) = manifest.manifest_blake3.as_deref() else {
        return Ok(());
    };
    let actual = raw_mirror_manifest_blake3(manifest);
    if recorded != actual {
        return Err(anyhow!(
            "E-MANIFEST-IDENTITY-MISMATCH: raw mirror manifest {} records self-digest {} \
             but its bytes hash to {} - refusing to write it (writing would recompute the \
             self-digest and destroy the only evidence that it was tampered with)",
            manifest_path.display(),
            recorded,
            actual
        ));
    }
    Ok(())
}

fn raw_mirror_manifest_blake3(manifest: &RawMirrorManifestFile) -> String {
    let mut value = serde_json::to_value(manifest).unwrap_or_default();
    if let Value::Object(map) = &mut value {
        map.remove("manifest_blake3");
    }
    canonical_blake3("doctor-raw-mirror-manifest-v1", value)
}

fn canonical_blake3(prefix: &str, value: Value) -> String {
    let encoded = serde_json::to_vec(&canonical_json_value(value)).unwrap_or_default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix.as_bytes());
    hasher.update(&[0]);
    hasher.update(&encoded);
    format!("{prefix}-{}", hasher.finalize().to_hex())
}

fn canonical_json_value(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(canonical_json_value).collect()),
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut canonical = serde_json::Map::new();
            for (key, value) in entries {
                canonical.insert(key, canonical_json_value(value));
            }
            Value::Object(canonical)
        }
        other => other,
    }
}

fn unique_db_links(links: &[RawMirrorDbLink]) -> Vec<RawMirrorDbLink> {
    let mut dedup = links.to_vec();
    dedup.sort_by(|left, right| {
        (
            left.conversation_id,
            left.message_count,
            left.started_at_ms,
            left.source_path.as_deref().unwrap_or(""),
        )
            .cmp(&(
                right.conversation_id,
                right.message_count,
                right.started_at_ms,
                right.source_path.as_deref().unwrap_or(""),
            ))
    });
    dedup.dedup();
    dedup
}

fn file_blake3(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    create_private_dir_all(path)
        .with_context(|| format!("create raw mirror dir {}", path.display()))?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat raw mirror dir {}", path.display()))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(anyhow!(
            "refusing to use symlink raw mirror dir {}",
            path.display()
        ));
    }
    if !file_type.is_dir() {
        return Err(anyhow!(
            "refusing to use non-directory raw mirror path {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            set_private_dir_permissions(path)?;
        }
    }
    #[cfg(not(unix))]
    {
        set_private_dir_permissions(path)?;
    }
    Ok(())
}

fn ensure_private_dir_descendant(root: &Path, path: &Path) -> Result<()> {
    let relative = path.strip_prefix(root).with_context(|| {
        format!(
            "raw mirror private dir {} is not under root {}",
            path.display(),
            root.display()
        )
    })?;

    if let Some(root_parent) = root.parent() {
        ensure_private_dir(root_parent)?;
    }
    ensure_private_dir(root)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                current.push(part);
                ensure_private_dir(&current)?;
            }
            Component::CurDir => {}
            _ => {
                return Err(anyhow!(
                    "raw mirror private dir contains non-normal component: {}",
                    path.display()
                ));
            }
        }
    }

    Ok(())
}

fn private_create_new_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_create_file_mode(&mut options);
    let file = options
        .open(path)
        .with_context(|| format!("create raw mirror file {}", path.display()))?;
    Ok(file)
}

#[cfg(unix)]
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(unix)]
fn set_private_create_file_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_create_file_mode(_options: &mut OpenOptions) {}

fn sync_open_file_if_required(message_file: &File, context: impl FnOnce() -> String) -> Result<()> {
    if !raw_mirror_fsync_enabled() {
        return Ok(());
    }
    message_file.sync_all().with_context(context)
}

fn sync_file(path: &Path) -> Result<()> {
    if !raw_mirror_fsync_enabled() {
        return Ok(());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    options.write(true);
    options
        .open(path)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("sync raw mirror file {}", path.display()))
}

#[cfg(not(windows))]
fn sync_parent(path: &Path) -> Result<()> {
    if !raw_mirror_fsync_enabled() {
        return Ok(());
    }
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("sync raw mirror parent {}", parent.display()))
}

#[cfg(windows)]
fn sync_parent(_path: &Path) -> Result<()> {
    Ok(())
}

/// R2-B5 场景二 (任务书 #119b): switch-controlled twin of
/// [`force_sync_dir_chain`]. `sync_parent` only fsyncs `path`'s immediate
/// parent -- fine for a file whose parent directory already existed, but
/// `replace_manifest_bytes` can be the call that creates an intermediate
/// directory for the first time (e.g. `manifests/`, on this mirror root's
/// very first manifest write, via its own `ensure_private_dir_descendant`
/// call), and a single-level sync leaves THAT directory's own entry in
/// `root` unfsynced. Still a no-op when `CASS_RAW_MIRROR_FSYNC` is unset --
/// Ivan's ruling is "the barrier is complete when the switch is on", not
/// "every write gets a hard sync by default".
fn sync_dir_chain_if_enabled(path: &Path, root: &Path, synced_dirs: &mut HashSet<PathBuf>) -> Result<()> {
    if !raw_mirror_fsync_enabled() {
        return Ok(());
    }
    force_sync_dir_chain(path, root, synced_dirs)
}

fn unique_temp_path(dir: &Path, label: &str) -> PathBuf {
    let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    dir.join(format!(
        ".{label}.{}.{}.{}.tmp",
        std::process::id(),
        nanos,
        nonce
    ))
}

fn unique_capture_temp_dir(root: &Path) -> PathBuf {
    let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    root.join("tmp").join(format!(
        "capture.{}.{}.{}",
        std::process::id(),
        nanos,
        nonce
    ))
}

fn remove_temp_best_effort(path: &Path) {
    if let Err(err) = fs::remove_file(path) {
        tracing::debug!(
            path = %path.display(),
            error = %err,
            "failed to remove raw mirror temp file"
        );
    }
}

fn remove_empty_temp_dir_best_effort(path: &Path) {
    if let Err(err) = fs::remove_dir(path) {
        tracing::debug!(
            path = %path.display(),
            error = %err,
            "failed to remove raw mirror temp directory"
        );
    }
}

fn redacted_original_path(provider: &str, source_path: &Path) -> String {
    let file_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("session");
    format!("[{provider}]/{file_name}")
}

fn now_ms() -> i64 {
    system_time_to_ms(SystemTime::now()).unwrap_or(0)
}

fn system_time_to_ms(time: SystemTime) -> Option<i64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
}

fn system_time_to_ns(time: SystemTime) -> Option<u128> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos())
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set raw mirror dir permissions {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set raw mirror file permissions {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

// ===========================================================================
// W1 relink 支撑面（Task E3，控制面裁定 16 扩入 Files 清单）
//
// 只新增公开面，**四个既有公开函数的签名一个不碰**
// （`storage_summary` / `prune` / `capture_source_file` / `merge_manifest_db_links`）。
// ===========================================================================

/// 落盘 manifest 的**只读投影**。
///
/// 刻意不把私有的 `RawMirrorManifestFile` 整个 `pub` 化：那会把落盘格式的每个字段
/// 都变成对外契约，日后改格式即破坏兼容。这里只暴露 relink 判定真正要用的字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMirrorManifestView {
    pub manifest_id: String,
    pub manifest_relative_path: String,
    pub blob_relative_path: String,
    pub blob_blake3: String,
    pub blob_size_bytes: u64,
    pub provider: String,
    pub source_id: String,
    pub origin_kind: String,
    pub origin_host: Option<String>,
    pub original_path: String,
    pub original_path_blake3: String,
    pub captured_at_ms: i64,
    /// 封存时记录的源文件字节数（`RawMirrorManifestFile.source_size_bytes`）。
    ///
    /// **类型是 `u64` 而不是 `Option<u64>`，这是一条防退化约束。** 附录 `W1-0` §A.1.1
    /// 规定 restore 侧的 compact 判据改读本字段，并明写「`source_size_bytes` 是 `u64`
    /// 非 `Option`，故 restore 侧**不存在**『取不到大小 → 不 compact』这条分支」。
    /// doctor 侧那份报告（`DoctorRawMirrorManifestReport.source_size_bytes`）是
    /// `Option<u64>`，**不得**拿它当本字段的来源 —— 那会把被明令消掉的分支重新引回来，
    /// 于是一份大 codex 会话在恢复时会静默地不 compact，与索引侧行为分叉。
    pub source_size_bytes: u64,
    /// 封存时记录的源文件 mtime（毫秒）；`None` 表示该 manifest 落盘时就没记。
    ///
    /// **restore 侧填 `metadata.cass.raw_mirror` 的八个键之一必须取自这里。** 不暴露它
    /// 就只能写 `null`，而那是一种**静默的保真度损失** —— 它伪装成「这份 manifest 本来
    /// 就没记 mtime」，比缺键更难被发现。E4 的 `manifest_fields::SOURCE_MTIME_MS`
    /// 同样消费该字段（winner 选择的时间倒挂交叉检查），故这个缺口是三方的。
    ///
    /// **注意它不进任何身份元组**：环境失败矩阵 E-4 明写 mtime 类字段靠时钟粒度生效的
    /// 守卫等于没有守卫。它只作裁定材料与 provenance 记录。
    pub source_mtime_ms: Option<i64>,
    pub db_links: Vec<RawMirrorDbLink>,
    /// 落盘时记录的 manifest 自摘要；`None` 表示该 manifest 是在引入该字段之前写的。
    pub manifest_blake3: Option<String>,
}

impl RawMirrorManifestView {
    /// 重算 manifest 自摘要并与落盘记录的值比对。
    ///
    /// 返回 `None` 表示落盘里根本没有记录摘要（旧 manifest），
    /// **调用方必须把 `None` 与 `Some(true)` 分开处理** —— 「没记」不是「校验通过」。
    pub fn manifest_identity_matches(&self, recomputed: &str) -> Option<bool> {
        self.manifest_blake3
            .as_deref()
            .map(|recorded| recorded == recomputed)
    }
}

/// 枚举 raw mirror 下全部 manifest 的只读投影。
///
/// 与 `prune` 的枚举同一套校验：拒绝符号链接、非常规文件、错误的 `manifest_kind`、
/// 以及 blob 路径与 blake3 不自洽的 manifest —— 这些是**硬失败**而不是跳过，
/// 因为 relink 的判定建立在「全量看到」之上，静默跳过会让重建结果自洽却错误。
pub fn manifest_views(data_dir: &Path) -> Result<Vec<RawMirrorManifestView>> {
    let root = raw_mirror_root(data_dir);
    let manifests_dir = root.join("manifests");
    if !manifests_dir.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(&manifests_dir)
        .with_context(|| format!("stat {}", manifests_dir.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "refusing to read invalid raw mirror manifests directory {}",
            manifests_dir.display()
        );
    }

    let mut views = Vec::new();
    for entry in
        fs::read_dir(&manifests_dir).with_context(|| format!("read {}", manifests_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let manifest_metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("stat raw mirror manifest {}", path.display()))?;
        if manifest_metadata.file_type().is_symlink() || !manifest_metadata.is_file() {
            anyhow::bail!(
                "refusing to read non-regular raw mirror manifest {}",
                path.display()
            );
        }
        let manifest = read_raw_mirror_manifest(&path)?;
        if manifest.manifest_kind != RAW_MIRROR_MANIFEST_KIND {
            anyhow::bail!(
                "unexpected raw mirror manifest kind `{}` in {}",
                manifest.manifest_kind,
                path.display()
            );
        }
        let Some(expected_blob_relative_path) =
            raw_mirror_blob_relative_path(&manifest.blob_blake3)
        else {
            anyhow::bail!(
                "raw mirror manifest {} has an invalid blob hash",
                path.display()
            );
        };
        if manifest.blob_relative_path != expected_blob_relative_path {
            anyhow::bail!(
                "raw mirror manifest {} has unexpected blob path `{}`",
                path.display(),
                manifest.blob_relative_path
            );
        }
        let relative_path = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        views.push(RawMirrorManifestView {
            manifest_id: manifest.manifest_id.clone(),
            manifest_relative_path: relative_path,
            blob_relative_path: manifest.blob_relative_path.clone(),
            blob_blake3: manifest.blob_blake3.clone(),
            blob_size_bytes: manifest.blob_size_bytes,
            provider: manifest.provider.clone(),
            source_id: manifest.source_id.clone(),
            origin_kind: manifest.origin_kind.clone(),
            origin_host: manifest.origin_host.clone(),
            original_path: manifest.original_path.clone(),
            original_path_blake3: manifest.original_path_blake3.clone(),
            captured_at_ms: manifest.captured_at_ms,
            source_size_bytes: manifest.source_size_bytes,
            source_mtime_ms: manifest.source_mtime_ms,
            db_links: manifest.db_links.clone(),
            manifest_blake3: manifest.manifest_blake3.clone(),
        });
    }
    views.sort_by(|a, b| a.manifest_id.cmp(&b.manifest_id));
    Ok(views)
}

/// 重算一份 manifest 的自摘要（不落盘），供 relink 的 identity 校验用。
pub fn recompute_manifest_blake3(data_dir: &Path, manifest_relative_path: &str) -> Result<String> {
    let root = raw_mirror_root(data_dir);
    let manifest_path = raw_mirror_manifest_path_from_relative(&root, manifest_relative_path)?;
    let manifest = read_raw_mirror_manifest(&manifest_path)?;
    Ok(raw_mirror_manifest_blake3(&manifest))
}

/// **整体重建**一份 manifest 的 `db_links`，返回是否真的写了盘。
///
/// ⚠ 与 [`merge_manifest_db_links`] 语义**不同，别用混**：
/// - `merge_manifest_db_links` 是**只增不删**的并集合并，且 `links` 为空时直接返回；
/// - 本函数是**整体替换**：传什么就是什么，**可以移除错误链接、也可以清空**。
///
/// relink 需要的是后者 —— 「按真实身份匹配重建」必然包含把错的链接去掉。
/// 落盘沿用与 merge 相同的 publish 序列（临时文件 → `fsync` → `rename` →
/// `fsync` 文件与父目录），不另写第二套。
/// [`rebuild_manifest_db_links`] 的三态结果。
///
/// **三态而不是 `bool`**：第三态「规划之后 manifest 变了」既不是「写了」也不是
/// 「内容一样所以没写」，把它折进 `bool` 就等于让调用方在两种完全不同的情形上
/// 做同一件事 —— 而这两种情形一个要沉默、一个必须出声。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebuildManifestDbLinksOutcome {
    /// 盘上内容与计划一致，没写盘。
    Unchanged,
    /// 按计划整体替换并落盘了。
    Written,
    /// **规划之后这份 manifest 被别人改过**：一行都没写，交调用方以自己的名义处置。
    ChangedSincePlan,
    /// **盘上已经是本计划的 `after`**：一行都没写，因为该写的上一轮已经写完了。
    ///
    /// 与 `ChangedSincePlan` 分开，是因为它们对调用方是两件相反的事：那个说「前提没了，
    /// 停手」，这个说「做过了，往前走」。合在一起报，崩溃重放就会把**自己上一轮的成果**
    /// 当成别人的改动（R2 第 13 条 / R-E-98 H3）—— 而那条路上重放多少次都是同一句错，
    /// 恢复永久卡死。
    ///
    /// 判定放在这里而不是交调用方重读：本函数此刻正持着锁、两个值都在手上，
    /// 调用方再读一次就是另一个时刻的事实了。
    AlreadyApplied,
}

pub fn rebuild_manifest_db_links(
    data_dir: &Path,
    manifest_relative_path: &str,
    expected_current: &[RawMirrorDbLink],
    links: &[RawMirrorDbLink],
) -> Result<RebuildManifestDbLinksOutcome> {
    let root = raw_mirror_root(data_dir);
    let manifest_path = raw_mirror_manifest_path_from_relative(&root, manifest_relative_path)?;

    let lock = MANIFEST_UPDATE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| anyhow!("raw mirror manifest update lock poisoned"))?;

    let mut manifest = read_raw_mirror_manifest(&manifest_path)?;

    // 身份防线排在新鲜度 CAS **之前**：输入本身不可信时，「我的计划还新不新鲜」
    // 根本不是该讨论的问题，而且先答那个问题会让操作者拿到一个误导的结论
    // （「规划之后被改过」听起来是并发，实际是篡改）。
    ensure_manifest_identity_before_write(&manifest, &manifest_path)?;

    // ── 新鲜度 CAS（FIND-6 / 裁定 R-E-88）────────────────────────────────
    //
    // 本函数是**整体替换**，而 `links` 是调用方**更早**算出来的计划。
    // 修前它在锁内重读了 manifest、却把读到的内容整个丢掉 —— 于是规划与施加之间
    // 任何一次合法的并发写入都会被静默抹掉。实测（确定性，不需要制造竞态）：
    // 规划态是 `[A]`，其间索引器 merge 进了 `B`，施加陈旧计划之后盘上只剩 `[A]`。
    //
    // 窗口不是毫秒级：`mirror_relink()` 在同一次调用内先算完**全部** manifest 的计划
    // 再逐个施加，规划要读全库（真语料 4567 会话实测 900s 未完）；崩溃重放路径
    // （`relink_drive_manifest_phase`）用的计划更可能是几小时前的。
    // 而并发写入方是常态：索引器每落一条会话就 `merge_manifest_db_links` 一次。
    //
    // **锁救不了这件事** —— 进程内 `Mutex` 保护的是写序，而计划早在取锁之前就算好了。
    // 所以这里在**锁内、重读之后、写之前**比一次：不等就一行都不写，
    // 由调用方以自己的名义拒绝或跳过。
    //
    // 残留窗口如实说：这只把窗口从「分钟级」压到「锁内重读到 rename 之间」，
    // 跨进程仍不是原子的。彻底关掉要跨进程锁或 manifest 级 CAS 落盘原语，记 E9 已知边界。
    let rebuilt = unique_db_links(links);
    if manifest.db_links != unique_db_links(expected_current) {
        // 前提不成立时还要再分一次：盘上恰好**就是本计划的 after**，说明这一步上一轮
        // 已经做完了（写临时件 → rename 已落，而调用方记 `published` 在本函数返回之后，
        // 两者之间那一段就是这个窗）。那不是「被别人改过」，是「我自己做过了」。
        if manifest.db_links == rebuilt {
            return Ok(RebuildManifestDbLinksOutcome::AlreadyApplied);
        }
        return Ok(RebuildManifestDbLinksOutcome::ChangedSincePlan);
    }

    let had_self_digest = manifest.manifest_blake3.is_some();

    if rebuilt == manifest.db_links {
        return Ok(RebuildManifestDbLinksOutcome::Unchanged);
    }
    manifest.db_links = rebuilt;
    // 同 merge：只给本来就有证书的换发新证书（裁定 R-E-89 ②）。
    if had_self_digest {
        manifest.manifest_blake3 = Some(raw_mirror_manifest_blake3(&manifest));
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    replace_manifest_bytes(&root, &manifest_path, &manifest_bytes)?;
    Ok(RebuildManifestDbLinksOutcome::Written)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that register [`set_dir_sync_probe`] mutate process-global
    /// state (like `HOOK_TEST_SERIALIZE` in `tests/w6_exclusion_ingest.rs`)
    /// and must be serialized against each other, or one test's hook can
    /// observe -- or clobber -- another's while `cargo test` runs them on
    /// different threads of the same process.
    static DIR_SYNC_PROBE_TEST_SERIALIZE: Mutex<()> = Mutex::new(());

    #[test]
    fn capture_source_file_writes_doctor_compatible_manifest_idempotently() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("rollout-fixture.jsonl");
        let source_bytes = b"{\"type\":\"message\",\"text\":\"hello\"}\n";
        fs::write(&source_path, source_bytes).expect("write source");
        let db_link = RawMirrorDbLink {
            conversation_id: Some(42),
            message_count: Some(1),
            source_path: Some(source_path.display().to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };

        let first = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: std::slice::from_ref(&db_link),
        })
        .expect("first capture");
        let second = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: std::slice::from_ref(&db_link),
        })
        .expect("second capture");

        assert_eq!(first.manifest_id, second.manifest_id);
        assert_eq!(first.blob_blake3, second.blob_blake3);
        assert_eq!(first.captured_at_ms, second.captured_at_ms);
        assert_eq!(first.source_mtime_ms, second.source_mtime_ms);
        assert!(!first.already_present);
        assert!(second.already_present);
        assert_eq!(fs::read(&source_path).expect("source bytes"), source_bytes);

        let blob_path = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR)
            .join(&first.blob_relative_path);
        let manifest_path = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR)
            .join(&first.manifest_relative_path);
        assert_eq!(fs::read(blob_path).expect("blob bytes"), source_bytes);

        let manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest bytes"))
                .expect("manifest json");
        assert_eq!(
            manifest["manifest_kind"].as_str(),
            Some(RAW_MIRROR_MANIFEST_KIND)
        );
        assert_eq!(manifest["provider"].as_str(), Some("codex"));
        assert_eq!(
            manifest["blob_blake3"].as_str(),
            Some(first.blob_blake3.as_str())
        );
        assert_eq!(
            manifest["redacted_original_path"].as_str(),
            Some("[codex]/rollout-fixture.jsonl")
        );
        assert_eq!(
            manifest["db_links"][0]["conversation_id"].as_i64(),
            Some(42)
        );
        assert_eq!(manifest["db_links"][0]["message_count"].as_u64(), Some(1));
        assert!(
            manifest["manifest_blake3"]
                .as_str()
                .is_some_and(|value| value.starts_with("doctor-raw-mirror-manifest-v1-"))
        );
        let tmp_root = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR)
            .join("tmp");
        assert_eq!(
            fs::read_dir(&tmp_root)
                .expect("raw mirror tmp root")
                .collect::<Vec<_>>()
                .len(),
            0,
            "successful captures must not leave doctor-visible interrupted temp artifacts"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let root = data_dir
                .join(RAW_MIRROR_ROOT_DIR)
                .join(RAW_MIRROR_VERSION_DIR);
            assert_eq!(
                fs::metadata(&root)
                    .expect("raw mirror root metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&manifest_path)
                    .expect("manifest metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    /// R1-B3 (任务书 #118a): a freshly-captured blob lives several
    /// directory levels deep (`raw-mirror/v1/blobs/blake3/<prefix>/`) under
    /// a mirror root that itself didn't exist before this capture -- every
    /// one of those levels is a brand-new directory. `sync_capture_durable`
    /// must walk and fsync the full chain up to the mirror root without
    /// erroring, not just the blob/manifest's immediate parent.
    #[test]
    fn sync_capture_durable_walks_full_directory_chain_to_root() {
        // R4-N1 (任务书 #120a): this test calls `sync_capture_durable`, which
        // fires the process-global `DIR_SYNC_PROBE` (via `force_sync_dir`)
        // just like every other test in this module -- but until now it did
        // NOT hold `DIR_SYNC_PROBE_TEST_SERIALIZE`. A concurrent test that
        // has armed the probe (e.g. `..._fsyncs_mirror_root_parent_directory_
        // entry`) would have this test's fsync calls land in ITS `synced`
        // collection, corrupting a set-equality assertion made against a
        // completely different temp tree. This test doesn't install a probe
        // itself, so holding the lock is a secondary defense only -- the
        // primary defense is the probe-observer test filtering by its own
        // `data_dir` prefix (see below), which doesn't depend on every
        // caller of `sync_capture_durable` remembering to take this lock.
        let _serialize = DIR_SYNC_PROBE_TEST_SERIALIZE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("rollout-b3-fixture.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"hello b3\"}\n").expect("write source");
        let db_link = RawMirrorDbLink {
            conversation_id: Some(1),
            message_count: Some(1),
            source_path: Some(source_path.display().to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };
        let record = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: std::slice::from_ref(&db_link),
        })
        .expect("capture");

        sync_capture_durable(&data_dir, &record)
            .expect("sync_capture_durable must succeed across a freshly-created multi-level directory chain");
    }

    /// R2-B5 场景一 (任务书 #119b): `force_sync_dir_chain` stops AT `root`
    /// (`raw-mirror/v1`) inclusive -- it never fsyncs `v1`'s own directory
    /// entry inside `v1`'s parent (`raw-mirror/`). This is the durability
    /// gap: a freshly-created `v1` can vanish from `raw-mirror/`'s listing
    /// after a crash even though everything under `v1` is itself durable.
    /// `sync_capture_durable` must fsync `raw-mirror/` too, unconditionally
    /// (it is already gated on "session has an exclusion marker" by its one
    /// caller -- the R1-B3 force barrier -- so this extra level costs
    /// nothing extra in the common case).
    ///
    /// R3-B1 (任务书 #119d): the same gap exists one level higher -- fsyncing
    /// `raw-mirror/`'s own listing only makes `v1`'s entry durable, not
    /// `raw-mirror/`'s OWN entry inside `data_dir`. `data_dir` is guaranteed
    /// pre-existing (the caller already has an open database inside it), so
    /// this is unconditional and cheap for the same reason as the level
    /// below it. This test now also asserts chain completeness: the full
    /// leaf-to-`data_dir` layer enumeration, derived from the capture's own
    /// relative paths, must equal exactly what the probe observed.
    #[test]
    fn sync_capture_durable_fsyncs_mirror_root_parent_directory_entry() {
        let _serialize = DIR_SYNC_PROBE_TEST_SERIALIZE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("rollout-b5-scenario1.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"hello b5-1\"}\n").expect("write source");
        let db_link = RawMirrorDbLink {
            conversation_id: Some(1),
            message_count: Some(1),
            source_path: Some(source_path.display().to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };
        // `capture_source_file` (not under test here) creates `v1` and
        // everything under it *before* the probe is armed, so only
        // `sync_capture_durable`'s own fsyncs land in `synced`.
        let record = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: std::slice::from_ref(&db_link),
        })
        .expect("capture");

        let synced: std::sync::Arc<Mutex<Vec<PathBuf>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        let synced_for_hook = synced.clone();
        set_dir_sync_probe(Some(Box::new(move |dir: &Path| {
            synced_for_hook.lock().unwrap().push(dir.to_path_buf());
        })));
        let result = sync_capture_durable(&data_dir, &record);
        set_dir_sync_probe(None);
        result.expect("sync_capture_durable must succeed");

        let raw_mirror_dir = data_dir.join(RAW_MIRROR_ROOT_DIR);
        let v1_dir = raw_mirror_dir.join(RAW_MIRROR_VERSION_DIR);
        // R4-N1 (任务书 #120a): `DIR_SYNC_PROBE` is process-global (see its
        // doc comment above) -- ANY concurrently-running test that calls
        // into `force_sync_dir` (directly or via `sync_capture_durable`)
        // while this probe is armed lands its own directories in `synced`
        // too, even though `DIR_SYNC_PROBE_TEST_SERIALIZE` is held here.
        // Holding that lock only orders this test against OTHER tests that
        // also remember to take it -- `sync_capture_durable_walks_full_
        // directory_chain_to_root` didn't (fixed above, but the fix is a
        // convention that the next new test could just as easily forget
        // again). Filtering to only this test's own `data_dir` subtree is
        // the primary defense: it doesn't depend on every future caller of
        // `sync_capture_durable` remembering to serialize -- a foreign
        // test's temp directory can never collide with this filter because
        // each test gets its own `tempfile::TempDir`.
        let synced = synced.lock().unwrap();
        let synced: Vec<PathBuf> = synced
            .iter()
            .filter(|dir| dir.starts_with(&data_dir))
            .cloned()
            .collect();
        assert!(
            synced.contains(&v1_dir),
            "sanity: v1 itself must still be fsynced (R1-B3, unchanged); synced dirs: {synced:?}"
        );
        assert!(
            synced.contains(&raw_mirror_dir),
            "sync_capture_durable must fsync raw-mirror/ itself (v1's own directory entry in \
             its parent), not just v1 and everything below it; synced dirs: {synced:?}"
        );
        // R3-B1 (任务书 #119d): `raw-mirror/`'s own listing being durable
        // only makes V1'S entry durable -- it does nothing for `raw-mirror/`
        // itself possibly being a brand-new entry in `data_dir`'s listing.
        // `data_dir` (this test's own `data_dir` binding) must also be
        // fsynced -- unconditionally, regardless of whether `data_dir`
        // itself is newly created this run (R4-B1, 任务书 #120a: whether
        // `data_dir`'s OWN entry in ITS parent needs syncing is a separate,
        // OUT-OF-SCOPE-for-this-function concern, handled at whoever
        // actually creates `data_dir` -- see `sync_capture_durable`'s doc
        // comment).
        assert!(
            synced.contains(&data_dir),
            "sync_capture_durable must also fsync data_dir itself (raw-mirror/'s own directory \
             entry in ITS parent) -- fsyncing raw-mirror/ alone only makes v1's entry durable, \
             not raw-mirror/'s own entry inside data_dir; synced dirs: {synced:?}"
        );

        // R3-B1 chain-completeness judge: derive the FULL enumerated layer
        // set (every leaf-to-data_dir directory level from the #119d layer
        // table) from this capture's OWN relative paths -- not a hardcoded
        // hash prefix -- and assert the probe observed exactly this set,
        // deduped, no more and no fewer. This is what turns the manual
        // layer-by-layer enumeration into a standing regression judge: the
        // next time a level silently drops out of the chain walk, this
        // assertion goes red instead of waiting for a reviewer to recount.
        fn walk_up_inclusive(mut dir: PathBuf, stop_at: &Path, into: &mut HashSet<PathBuf>) {
            loop {
                into.insert(dir.clone());
                if dir == stop_at {
                    break;
                }
                match dir.parent() {
                    Some(parent) => dir = parent.to_path_buf(),
                    None => break,
                }
            }
        }
        let mut expected_dirs: HashSet<PathBuf> = HashSet::new();
        expected_dirs.insert(data_dir.clone());
        expected_dirs.insert(raw_mirror_dir.clone());
        let blob_leaf_dir = v1_dir.join(&record.blob_relative_path).parent().expect("blob path has a parent").to_path_buf();
        let manifest_leaf_dir = v1_dir.join(&record.manifest_relative_path).parent().expect("manifest path has a parent").to_path_buf();
        walk_up_inclusive(blob_leaf_dir, &v1_dir, &mut expected_dirs);
        walk_up_inclusive(manifest_leaf_dir, &v1_dir, &mut expected_dirs);
        let observed_dirs: HashSet<PathBuf> = synced.iter().cloned().collect();
        assert_eq!(
            observed_dirs, expected_dirs,
            "chain completeness: probe-observed synced directory set must exactly equal the \
             #119d layer enumeration (every leaf-to-data_dir level), derived from this capture's \
             own relative paths"
        );
    }

    /// R4-N1 (任务书 #120a): the chain-completeness `assert_eq!` above is a
    /// SET-equality judge over `DIR_SYNC_PROBE` observations, and that probe
    /// is process-global -- a concurrently-running test's directories can
    /// land in the same observation stream. This test proves the fix (filter
    /// by this test's own `data_dir` prefix before comparing) actually does
    /// its job: it manually injects a foreign path -- shaped exactly like
    /// another test's temp tree, i.e. NOT under this test's `data_dir` --
    /// into the same probe stream a real concurrent test would pollute it
    /// with, then asserts the post-filter set still equals the untouched
    /// expected set. The mutation (commenting out the filter, done by hand
    /// during R4-N1's real fix -- see the report) turns this from "probably
    /// works" into "verified": without the filter, the injected path is an
    /// extra element the equality assertion cannot tolerate.
    #[test]
    fn sync_capture_durable_probe_filter_rejects_foreign_test_tree_pollution() {
        let _serialize = DIR_SYNC_PROBE_TEST_SERIALIZE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("rollout-n1-filter.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"hello n1\"}\n").expect("write source");
        let db_link = RawMirrorDbLink {
            conversation_id: Some(1),
            message_count: Some(1),
            source_path: Some(source_path.display().to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };
        let record = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: std::slice::from_ref(&db_link),
        })
        .expect("capture");

        // Shaped like another concurrent test's own tempdir + data_dir -- a
        // sibling of `temp`, not a descendant of THIS test's `data_dir`.
        let foreign_pollution = temp
            .path()
            .parent()
            .expect("tempdir has a parent")
            .join("other-concurrent-test-tree")
            .join("cass-data")
            .join("raw-mirror")
            .join("v1");

        let synced: std::sync::Arc<Mutex<Vec<PathBuf>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        let synced_for_hook = synced.clone();
        let foreign_for_hook = foreign_pollution.clone();
        set_dir_sync_probe(Some(Box::new(move |dir: &Path| {
            let mut guard = synced_for_hook.lock().unwrap();
            // Simulate the exact interleaving R4-N1 describes: a foreign
            // test's `force_sync_dir` call lands in this probe stream
            // alongside ours, once per real observation.
            guard.push(foreign_for_hook.clone());
            guard.push(dir.to_path_buf());
        })));
        let result = sync_capture_durable(&data_dir, &record);
        set_dir_sync_probe(None);
        result.expect("sync_capture_durable must succeed");

        let raw_mirror_dir = data_dir.join(RAW_MIRROR_ROOT_DIR);
        let v1_dir = raw_mirror_dir.join(RAW_MIRROR_VERSION_DIR);
        let synced = synced.lock().unwrap();
        // Positive: the foreign path is present in the RAW probe stream --
        // this is what a real concurrent-test interleaving would produce.
        assert!(
            synced.contains(&foreign_pollution),
            "test setup sanity: foreign pollution must actually be in the raw probe stream"
        );

        // R4-N1 fix under test: filtering by this test's own `data_dir`
        // prefix must drop the foreign path before any equality assertion.
        let filtered: HashSet<PathBuf> = synced
            .iter()
            .filter(|dir| dir.starts_with(&data_dir))
            .cloned()
            .collect();
        assert!(
            !filtered.contains(&foreign_pollution),
            "R4-N1: filtering by this test's own data_dir prefix must reject a foreign \
             concurrent test's directory tree, not just happen to not contain it"
        );

        fn walk_up_inclusive(mut dir: PathBuf, stop_at: &Path, into: &mut HashSet<PathBuf>) {
            loop {
                into.insert(dir.clone());
                if dir == stop_at {
                    break;
                }
                match dir.parent() {
                    Some(parent) => dir = parent.to_path_buf(),
                    None => break,
                }
            }
        }
        let mut expected_dirs: HashSet<PathBuf> = HashSet::new();
        expected_dirs.insert(data_dir.clone());
        expected_dirs.insert(raw_mirror_dir.clone());
        let blob_leaf_dir = v1_dir.join(&record.blob_relative_path).parent().expect("blob path has a parent").to_path_buf();
        let manifest_leaf_dir = v1_dir.join(&record.manifest_relative_path).parent().expect("manifest path has a parent").to_path_buf();
        walk_up_inclusive(blob_leaf_dir, &v1_dir, &mut expected_dirs);
        walk_up_inclusive(manifest_leaf_dir, &v1_dir, &mut expected_dirs);
        assert_eq!(
            filtered, expected_dirs,
            "R4-N1: after filtering out the injected foreign pollution, the chain-completeness \
             equality judge must still pass exactly as it would with no concurrent interference \
             (variant without the filter: this assertion fails because `filtered` would still \
             contain `foreign_pollution`, one extra element `expected_dirs` doesn't have)"
        );
    }

    /// R4-B1 (任务书 #120a) 正例①：`data_dir` 本身连同其祖先都是新建的（`temp`
    /// 下嵌套两层，`nested/` 与 `nested/cass-data` 都不存在）-- 断言
    /// `create_dir_all_durable` 对每个新建层各自的父目录都做了 fsync：既包括
    /// `data_dir` 自己的父目录（`nested/`），也包括 `nested/` 自己的父目录
    /// （`temp.path()`，本就存在，充当自然边界）。这正是"新建到哪就同步到
    /// 哪"要证明的：边界不是硬编码的一跳，而是由实际文件系统状态动态决定的。
    #[test]
    fn create_dir_all_durable_syncs_parent_of_every_newly_created_level_positive() {
        let _serialize = DIR_SYNC_PROBE_TEST_SERIALIZE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let temp = tempfile::TempDir::new().expect("tempdir");
        let nested = temp.path().join("nested");
        let data_dir = nested.join("cass-data");
        assert!(!nested.exists(), "test setup sanity: nested/ must not pre-exist");
        assert!(!data_dir.exists(), "test setup sanity: data_dir must not pre-exist");

        let synced: std::sync::Arc<Mutex<Vec<PathBuf>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        let synced_for_hook = synced.clone();
        set_dir_sync_probe(Some(Box::new(move |dir: &Path| {
            synced_for_hook.lock().unwrap().push(dir.to_path_buf());
        })));
        let result = create_dir_all_durable(&data_dir);
        set_dir_sync_probe(None);
        result.expect("create_dir_all_durable must succeed creating a multi-level path");

        assert!(data_dir.is_dir(), "data_dir must actually be created");
        assert!(nested.is_dir(), "nested/ must actually be created");

        let synced = synced.lock().unwrap();
        assert!(
            synced.contains(&nested),
            "create_dir_all_durable must fsync data_dir's own parent (nested/), which it newly \
             created; synced dirs: {synced:?}"
        );
        assert!(
            synced.contains(&temp.path().to_path_buf()),
            "create_dir_all_durable must ALSO fsync nested/'s own parent (temp.path()), because \
             nested/ itself was newly created too -- this is the 'no hardcoded upper bound' part: \
             it must keep climbing past data_dir's immediate parent for as long as each level up \
             was also newly built, not stop after exactly one hop; synced dirs: {synced:?}"
        );
        assert_eq!(
            synced.len(),
            2,
            "must sync exactly the two newly-created levels' parents, no more (temp.path() itself, \
             which pre-existed, must not have its own parent synced -- that's outside this call's \
             contract); synced dirs: {synced:?}"
        );
    }

    /// R4-B1 (任务书 #120a) 正例②：`data_dir` 已经预先存在（调用方已经
    /// `fs::create_dir_all` 过）-- 断言 `create_dir_all_durable` 不 fsync
    /// 任何目录，证明它不是无脑往上刷，只对"这次调用真正新建的"负责。
    #[test]
    fn create_dir_all_durable_does_not_sync_when_data_dir_already_exists_positive() {
        let _serialize = DIR_SYNC_PROBE_TEST_SERIALIZE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        fs::create_dir_all(&data_dir).expect("pre-create data_dir");

        let synced: std::sync::Arc<Mutex<Vec<PathBuf>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        let synced_for_hook = synced.clone();
        set_dir_sync_probe(Some(Box::new(move |dir: &Path| {
            synced_for_hook.lock().unwrap().push(dir.to_path_buf());
        })));
        let result = create_dir_all_durable(&data_dir);
        set_dir_sync_probe(None);
        result.expect("create_dir_all_durable must succeed as a no-op when data_dir pre-exists");

        let synced = synced.lock().unwrap();
        assert!(
            synced.is_empty(),
            "create_dir_all_durable must not fsync anything when data_dir already existed before \
             the call; synced dirs: {synced:?}"
        );
    }

    /// R4-B1 (任务书 #120a) 正例③（R4 点名的组合场景的 raw_mirror.rs 侧一半）：
    /// `create_dir_all_durable` 与 `sync_capture_durable` 各自的职责边界在
    /// 衔接点上不留缝隙 -- `data_dir` 连同其祖先都是新建的，走完
    /// `create_dir_all_durable` → `capture_source_file` →
    /// `sync_capture_durable` 这条真实调用链后，从镜像叶子（blob/manifest）
    /// 一路到"第一个本来就存在的祖先"（`temp.path()`）之间的每一层都被同步
    /// 过，恰好衔接、不重不漏。这条判例不依赖谁创建了 `data_dir` 之上还是
    /// 之下这类实现细节，只断言"整条链没有洞"。
    #[test]
    fn create_dir_all_durable_and_sync_capture_durable_seam_has_no_gap_positive() {
        let _serialize = DIR_SYNC_PROBE_TEST_SERIALIZE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let temp = tempfile::TempDir::new().expect("tempdir");
        let nested = temp.path().join("nested");
        let data_dir = nested.join("cass-data");
        let source_path = temp.path().join("rollout-r4b1-seam.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"hello r4b1\"}\n").expect("write source");

        let synced: std::sync::Arc<Mutex<Vec<PathBuf>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        let synced_for_hook = synced.clone();
        set_dir_sync_probe(Some(Box::new(move |dir: &Path| {
            synced_for_hook.lock().unwrap().push(dir.to_path_buf());
        })));

        // Same order as production: `acquire_index_run_lock` creates
        // `data_dir` (here simulated directly, since it's `indexer::mod.rs`
        // machinery this module doesn't otherwise need) BEFORE any capture
        // ever runs.
        create_dir_all_durable(&data_dir).expect("create_dir_all_durable");
        let db_link = RawMirrorDbLink {
            conversation_id: Some(1),
            message_count: Some(1),
            source_path: Some(source_path.display().to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };
        let record = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: std::slice::from_ref(&db_link),
        })
        .expect("capture");
        sync_capture_durable(&data_dir, &record).expect("sync_capture_durable");

        set_dir_sync_probe(None);

        let raw_mirror_dir = data_dir.join(RAW_MIRROR_ROOT_DIR);
        let v1_dir = raw_mirror_dir.join(RAW_MIRROR_VERSION_DIR);
        fn walk_up_inclusive(mut dir: PathBuf, stop_at: &Path, into: &mut HashSet<PathBuf>) {
            loop {
                into.insert(dir.clone());
                if dir == stop_at {
                    break;
                }
                match dir.parent() {
                    Some(parent) => dir = parent.to_path_buf(),
                    None => break,
                }
            }
        }
        // Every level from `temp.path()` (the first pre-existing ancestor)
        // down to `data_dir` -- this is `create_dir_all_durable`'s half.
        let mut expected: HashSet<PathBuf> = HashSet::new();
        expected.insert(nested.clone());
        expected.insert(temp.path().to_path_buf());
        // `sync_capture_durable`'s half: data_dir itself and everything
        // below (unchanged mechanism from R1-B3/R2-B5/R3-B1).
        expected.insert(data_dir.clone());
        expected.insert(raw_mirror_dir.clone());
        let blob_leaf_dir = v1_dir.join(&record.blob_relative_path).parent().expect("blob path has a parent").to_path_buf();
        let manifest_leaf_dir = v1_dir.join(&record.manifest_relative_path).parent().expect("manifest path has a parent").to_path_buf();
        walk_up_inclusive(blob_leaf_dir, &v1_dir, &mut expected);
        walk_up_inclusive(manifest_leaf_dir, &v1_dir, &mut expected);

        let synced = synced.lock().unwrap();
        let observed: HashSet<PathBuf> = synced
            .iter()
            .filter(|dir| dir.starts_with(temp.path()))
            .cloned()
            .collect();
        assert_eq!(
            observed, expected,
            "seam judge: the union of what create_dir_all_durable synced (data_dir and its newly \
             built ancestors' parents) and what sync_capture_durable synced (data_dir down to the \
             mirror leaves) must exactly equal every directory level from the mirror leaves up to \
             the first pre-existing ancestor -- no gap at the data_dir boundary, no double-sync \
             beyond it; synced dirs: {synced:?}"
        );
    }

    /// R2-B5 场景二 (任务书 #119b): `replace_manifest_bytes`'s post-rename
    /// sync used to be `sync_file` + `sync_parent`, and `sync_parent` only
    /// fsyncs the manifest's IMMEDIATE parent (`manifests/`) -- when the
    /// switch is on, it must now walk the full chain up to the mirror root,
    /// because `manifests/`'s own directory entry inside `v1` may never
    /// have been synced by any prior call (the unconditional force barrier
    /// only fires for sessions with an exclusion marker). Exercised through
    /// `merge_manifest_db_links` -- the real production call site
    /// (`record_persisted_raw_mirror_db_link` in `indexer/mod.rs`) -- not
    /// `replace_manifest_bytes` directly (private).
    #[test]
    fn merge_manifest_db_links_walks_full_directory_chain_when_fsync_enabled() {
        let _serialize = DIR_SYNC_PROBE_TEST_SERIALIZE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("rollout-b5-scenario2.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"hello b5-2\"}\n").expect("write source");

        // Switch off for the initial capture: this test is only about what
        // `replace_manifest_bytes` (via `merge_manifest_db_links`) does, not
        // `publish_manifest_bytes_create_new`'s own (separate, out of this
        // mission's scope) gap.
        let record = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("capture");

        let synced: std::sync::Arc<Mutex<Vec<PathBuf>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        let synced_for_hook = synced.clone();
        set_dir_sync_probe(Some(Box::new(move |dir: &Path| {
            synced_for_hook.lock().unwrap().push(dir.to_path_buf());
        })));
        // SAFETY: tests that touch `CASS_RAW_MIRROR_FSYNC` are serialized
        // via `DIR_SYNC_PROBE_TEST_SERIALIZE`, same pattern as `ENV_LOCK`
        // elsewhere in this crate (`indexer/semantic_progress.rs`).
        unsafe {
            std::env::set_var("CASS_RAW_MIRROR_FSYNC", "1");
        }
        let link = RawMirrorDbLink {
            conversation_id: Some(7),
            message_count: Some(1),
            source_path: Some(source_path.display().to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };
        let result = merge_manifest_db_links(&data_dir, &record.manifest_relative_path, std::slice::from_ref(&link));
        unsafe {
            std::env::remove_var("CASS_RAW_MIRROR_FSYNC");
        }
        set_dir_sync_probe(None);
        result.expect("merge_manifest_db_links must succeed with the switch on");

        let raw_mirror_dir = data_dir.join(RAW_MIRROR_ROOT_DIR);
        let v1_dir = raw_mirror_dir.join(RAW_MIRROR_VERSION_DIR);
        let manifests_dir = v1_dir.join("manifests");
        let synced = synced.lock().unwrap();
        assert!(
            synced.contains(&manifests_dir),
            "sanity: manifests/ itself must still be fsynced (pre-existing sync_parent \
             behavior); synced dirs: {synced:?}"
        );
        assert!(
            synced.contains(&v1_dir),
            "replace_manifest_bytes must walk the full chain up to v1 when the switch is on, \
             not just fsync manifests/ one level; synced dirs: {synced:?}"
        );
    }

    /// Negative half of the case above: with the switch off (default),
    /// `merge_manifest_db_links` must not fsync anything at all -- Ivan's
    /// ruling is "the barrier is complete when the switch is on", not
    /// "every write gets a hard sync by default" (不改 `CASS_RAW_MIRROR_FSYNC`
    /// 默认值).
    #[test]
    fn merge_manifest_db_links_does_not_sync_when_fsync_disabled() {
        let _serialize = DIR_SYNC_PROBE_TEST_SERIALIZE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("rollout-b5-scenario2-off.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"hello b5-2-off\"}\n").expect("write source");

        let record = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("capture");

        // SAFETY: see above -- serialized via DIR_SYNC_PROBE_TEST_SERIALIZE.
        unsafe {
            std::env::remove_var("CASS_RAW_MIRROR_FSYNC");
        }
        let synced: std::sync::Arc<Mutex<Vec<PathBuf>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        let synced_for_hook = synced.clone();
        set_dir_sync_probe(Some(Box::new(move |dir: &Path| {
            synced_for_hook.lock().unwrap().push(dir.to_path_buf());
        })));
        let link = RawMirrorDbLink {
            conversation_id: Some(8),
            message_count: Some(1),
            source_path: Some(source_path.display().to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };
        let result = merge_manifest_db_links(&data_dir, &record.manifest_relative_path, std::slice::from_ref(&link));
        set_dir_sync_probe(None);
        result.expect("merge_manifest_db_links must succeed with the switch off");

        // R4-N1 (任务书 #120a): `DIR_SYNC_PROBE_TEST_SERIALIZE` only excludes
        // OTHER tests that also hold it before touching the probe -- it does
        // NOT make `CASS_RAW_MIRROR_FSYNC`'s process-global env var reads
        // atomic with respect to the many OTHER tests in this module that
        // call `capture_source_file`/manifest-merge functions without ever
        // needing this lock at all (they don't assert on `synced`, so they
        // were never "victims" before, but they're still concurrent readers
        // of the same global env var `std::env::set_var`/`remove_var` mutate
        // -- real reproduction on baseline HEAD e29d2400 showed exactly this
        // test observing a foreign tmp tree's directory under
        // `--test-threads=8`). Filtering by this test's own `data_dir`
        // prefix is the same primary defense as the chain-completeness judge
        // above: it doesn't matter WHY a foreign path appeared in the raw
        // probe stream, only that it isn't part of what THIS test's own
        // capture actually touched.
        let synced = synced.lock().unwrap();
        let synced: Vec<PathBuf> = synced
            .iter()
            .filter(|dir| dir.starts_with(&data_dir))
            .cloned()
            .collect();
        assert!(
            synced.is_empty(),
            "default (switch off) must not fsync anything on manifest db-link merge; \
             synced dirs: {synced:?}"
        );
    }

    /// R2-B5b (任务书 #119c, 上一棒 #119b 主动报告的同构缺口): `publish_manifest_
    /// bytes_create_new` is the manifest's FIRST-EVER publish for a given
    /// capture -- `manifests/` may be the directory `ensure_private_dir_
    /// descendant` just created moments earlier in this same call, so (when
    /// the switch is on) it needs the same full-chain fsync
    /// `replace_manifest_bytes` (#119b R2-B5 场景二) already got, not the
    /// single-level `sync_parent` it had before this fix.
    #[test]
    fn capture_source_file_first_publish_walks_full_directory_chain_when_fsync_enabled() {
        let _serialize = DIR_SYNC_PROBE_TEST_SERIALIZE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("rollout-b5b-scenario.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"hello b5b\"}\n").expect("write source");

        let synced: std::sync::Arc<Mutex<Vec<PathBuf>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        let synced_for_hook = synced.clone();
        set_dir_sync_probe(Some(Box::new(move |dir: &Path| {
            synced_for_hook.lock().unwrap().push(dir.to_path_buf());
        })));
        // SAFETY: tests that touch `CASS_RAW_MIRROR_FSYNC` are serialized
        // via `DIR_SYNC_PROBE_TEST_SERIALIZE`.
        unsafe {
            std::env::set_var("CASS_RAW_MIRROR_FSYNC", "1");
        }
        let result = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        });
        unsafe {
            std::env::remove_var("CASS_RAW_MIRROR_FSYNC");
        }
        set_dir_sync_probe(None);
        result.expect("capture must succeed with the switch on");

        let raw_mirror_dir = data_dir.join(RAW_MIRROR_ROOT_DIR);
        let v1_dir = raw_mirror_dir.join(RAW_MIRROR_VERSION_DIR);
        let manifests_dir = v1_dir.join("manifests");
        let synced = synced.lock().unwrap();
        assert!(
            synced.contains(&manifests_dir),
            "sanity: manifests/ itself must still be fsynced (pre-existing sync_parent \
             behavior); synced dirs: {synced:?}"
        );
        assert!(
            synced.contains(&v1_dir),
            "publish_manifest_bytes_create_new must walk the full chain up to v1 on the \
             manifest's first-ever publish when the switch is on, not just fsync manifests/ \
             one level; synced dirs: {synced:?}"
        );
    }

    /// Negative half: switch off (default) must not trigger any extra fsync
    /// on the manifest's first-ever publish either -- same "barrier only
    /// complete when the switch is on" contract as #119b R2-B5.
    #[test]
    fn capture_source_file_first_publish_does_not_sync_when_fsync_disabled() {
        let _serialize = DIR_SYNC_PROBE_TEST_SERIALIZE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("rollout-b5b-scenario-off.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"hello b5b-off\"}\n").expect("write source");

        // SAFETY: see above -- serialized via DIR_SYNC_PROBE_TEST_SERIALIZE.
        unsafe {
            std::env::remove_var("CASS_RAW_MIRROR_FSYNC");
        }
        let synced: std::sync::Arc<Mutex<Vec<PathBuf>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        let synced_for_hook = synced.clone();
        set_dir_sync_probe(Some(Box::new(move |dir: &Path| {
            synced_for_hook.lock().unwrap().push(dir.to_path_buf());
        })));
        let result = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        });
        set_dir_sync_probe(None);
        result.expect("capture must succeed with the switch off");

        // R4-N1 (任务书 #120a): same defense as the chain-completeness judge
        // and `merge_manifest_db_links_does_not_sync_when_fsync_disabled`
        // above -- filter by this test's own `data_dir` prefix before
        // asserting, so a foreign concurrent test's directories (real
        // reproduction on baseline HEAD e29d2400 under `--test-threads=8`)
        // can't make this assertion fail regardless of how they got into
        // the raw probe stream.
        let synced = synced.lock().unwrap();
        let synced: Vec<PathBuf> = synced
            .iter()
            .filter(|dir| dir.starts_with(&data_dir))
            .cloned()
            .collect();
        assert!(
            synced.is_empty(),
            "default (switch off) must not fsync anything on the manifest's first-ever \
             publish; synced dirs: {synced:?}"
        );
    }

    #[test]
    fn capture_source_file_merges_db_links_into_existing_manifest() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("preparse-then-parsed.jsonl");
        let source_bytes = b"{\"type\":\"message\",\"text\":\"hello\"}\n";
        fs::write(&source_path, source_bytes).expect("write source");

        let preparse = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("preparse capture");

        let parsed_link = RawMirrorDbLink {
            conversation_id: None,
            message_count: Some(1),
            source_path: Some(source_path.display().to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };
        let parsed = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: std::slice::from_ref(&parsed_link),
        })
        .expect("parsed capture");

        assert_eq!(preparse.manifest_id, parsed.manifest_id);
        assert_eq!(preparse.blob_blake3, parsed.blob_blake3);
        assert!(parsed.already_present);

        let manifest_path = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR)
            .join(&parsed.manifest_relative_path);
        let manifest = read_raw_mirror_manifest(&manifest_path).expect("merged manifest");
        assert_eq!(
            manifest.db_links,
            vec![parsed_link],
            "second capture must enrich the pre-parse manifest with DB-link evidence"
        );
        let expected_manifest_blake3 = raw_mirror_manifest_blake3(&manifest);
        assert_eq!(
            manifest.manifest_blake3.as_deref(),
            Some(expected_manifest_blake3.as_str()),
            "manifest checksum must be recomputed after DB-link merge"
        );
        assert_eq!(fs::read(&source_path).expect("source bytes"), source_bytes);
    }

    #[test]
    fn merge_manifest_db_links_rejects_hostile_relative_paths() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let db_link = RawMirrorDbLink {
            conversation_id: Some(42),
            message_count: Some(1),
            source_path: Some("source.jsonl".to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };

        for relative in [
            "../escape.json",
            "/tmp/escape.json",
            "manifests/../escape.json",
            "blobs/blake3/ab/not-a-manifest.raw",
            "manifests/not-json.txt",
        ] {
            let err = merge_manifest_db_links(&data_dir, relative, std::slice::from_ref(&db_link))
                .expect_err("hostile manifest path should be rejected");
            assert!(
                err.to_string().contains("raw mirror manifest path"),
                "unexpected error for {relative}: {err}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn merge_manifest_db_links_rejects_symlink_manifest_path() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let manifest_dir = data_dir.join("raw-mirror/v1/manifests");
        fs::create_dir_all(&manifest_dir).expect("manifest dir");
        let outside = temp.path().join("outside.json");
        fs::write(&outside, "{}").expect("outside manifest");
        std::os::unix::fs::symlink(&outside, manifest_dir.join("link.json"))
            .expect("symlink manifest");
        let db_link = RawMirrorDbLink {
            conversation_id: Some(42),
            message_count: Some(1),
            source_path: Some("source.jsonl".to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };

        let err = merge_manifest_db_links(
            &data_dir,
            "manifests/link.json",
            std::slice::from_ref(&db_link),
        )
        .expect_err("symlink manifest should be rejected");
        assert!(
            err.to_string().contains("symlink raw mirror manifest"),
            "unexpected symlink-manifest error: {err}"
        );
    }

    #[test]
    fn capture_source_file_deduplicates_blob_for_distinct_source_paths() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let first_source = temp.path().join("first.jsonl");
        let second_source = temp.path().join("second.jsonl");
        let source_bytes = b"{\"type\":\"message\",\"text\":\"shared\"}\n";
        fs::write(&first_source, source_bytes).expect("write first source");
        fs::write(&second_source, source_bytes).expect("write second source");

        let first = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &first_source,
            db_links: &[],
        })
        .expect("first capture");
        let second = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &second_source,
            db_links: &[],
        })
        .expect("second capture");

        assert_eq!(first.blob_blake3, second.blob_blake3);
        assert_eq!(first.blob_relative_path, second.blob_relative_path);
        assert_ne!(first.manifest_id, second.manifest_id);
        assert!(
            !second.already_present,
            "a duplicate blob with a new source manifest is not a full capture replay"
        );

        let manifest_root = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR)
            .join("manifests");
        let manifests = fs::read_dir(manifest_root)
            .expect("manifest dir")
            .collect::<std::io::Result<Vec<_>>>()
            .expect("manifest entries");
        assert_eq!(manifests.len(), 2);

        let summary = storage_summary(&data_dir);
        assert!(summary.initialized);
        assert_eq!(summary.manifest_count, 2);
        assert_eq!(summary.unique_blob_count, 1);
        assert_eq!(summary.total_blob_bytes, source_bytes.len() as u64);
        assert_eq!(summary.largest_blob_bytes, source_bytes.len() as u64);
        assert_eq!(summary.missing_blob_count, 0);
        assert_eq!(summary.invalid_manifest_count, 0);
        assert!(summary.total_storage_bytes >= source_bytes.len() as u64);
    }

    #[test]
    fn storage_summary_rejects_hostile_blob_relative_path() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("source.jsonl");
        fs::write(
            &source_path,
            b"{\"type\":\"message\",\"text\":\"hostile\"}\n",
        )
        .expect("write source");

        let captured = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("capture source");
        let manifest_path = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR)
            .join(&captured.manifest_relative_path);
        let mut manifest = read_raw_mirror_manifest(&manifest_path).expect("read manifest");
        manifest.blob_relative_path = "../outside.raw".to_string();
        manifest.manifest_blake3 = Some(raw_mirror_manifest_blake3(&manifest));
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("tamper manifest");

        let summary = storage_summary(&data_dir);
        assert_eq!(summary.manifest_count, 1);
        assert_eq!(summary.invalid_manifest_count, 1);
        assert_eq!(summary.unique_blob_count, 0);
        assert_eq!(summary.total_blob_bytes, 0);
    }

    #[test]
    fn prune_fails_closed_on_hostile_manifest_inventory() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("source.jsonl");
        fs::write(
            &source_path,
            b"{\"type\":\"message\",\"text\":\"hostile\"}\n",
        )
        .expect("write source");

        let captured = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("capture source");
        let root = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR);
        let manifest_path = root.join(&captured.manifest_relative_path);
        let blob_path = root.join(&captured.blob_relative_path);
        let mut manifest = read_raw_mirror_manifest(&manifest_path).expect("read manifest");
        manifest.blob_relative_path = "../outside.raw".to_string();
        manifest.manifest_blake3 = Some(raw_mirror_manifest_blake3(&manifest));
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("tamper manifest");

        let err = prune(
            &data_dir,
            RawMirrorPruneOptions {
                referenced_blobs: HashSet::new(),
                older_than_ms: Some(0),
                max_size_bytes: None,
                keep_tags: Vec::new(),
                safety_hold_down_ms: 0,
                apply: true,
            },
        )
        .expect_err("hostile inventory should fail closed");

        assert!(
            err.to_string().contains("unexpected blob path"),
            "error should explain the unsafe manifest inventory: {err}"
        );
        assert!(manifest_path.exists());
        assert!(blob_path.exists());
        assert!(!root.join("pruned.jsonl").exists());
    }

    /// R9 (任务书 #113): a blob referenced by `messages.excluded.raw.blob`,
    /// and the manifest that captured it, both survive an otherwise-total
    /// prune (`--older-than 0 --safety-hold-down 0`); an unreferenced blob
    /// with no such protection is deleted as usual.
    #[test]
    fn prune_protects_referenced_blob_and_its_manifest_r9_positive() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");

        let referenced_source = temp.path().join("referenced.jsonl");
        fs::write(&referenced_source, b"{\"type\":\"message\",\"text\":\"still referenced\"}\n").expect("write referenced source");
        let referenced = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &referenced_source,
            db_links: &[],
        })
        .expect("capture referenced source");

        let unreferenced_source = temp.path().join("unreferenced.jsonl");
        fs::write(&unreferenced_source, b"{\"type\":\"message\",\"text\":\"no longer referenced\"}\n").expect("write unreferenced source");
        let unreferenced = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &unreferenced_source,
            db_links: &[],
        })
        .expect("capture unreferenced source");

        let root = data_dir.join(RAW_MIRROR_ROOT_DIR).join(RAW_MIRROR_VERSION_DIR);
        let referenced_manifest_path = root.join(&referenced.manifest_relative_path);
        let referenced_blob_path = root.join(&referenced.blob_relative_path);
        let unreferenced_manifest_path = root.join(&unreferenced.manifest_relative_path);
        let unreferenced_blob_path = root.join(&unreferenced.blob_relative_path);
        assert!(referenced_blob_path.exists() && unreferenced_blob_path.exists(), "both blobs must exist before pruning");

        let mut referenced_blobs = HashSet::new();
        referenced_blobs.insert(referenced.blob_relative_path.clone());

        let report = prune(
            &data_dir,
            RawMirrorPruneOptions {
                referenced_blobs,
                older_than_ms: Some(0),
                max_size_bytes: None,
                keep_tags: Vec::new(),
                safety_hold_down_ms: 0,
                apply: true,
            },
        )
        .expect("prune with a protected reference must succeed");

        assert!(referenced_manifest_path.exists(), "referenced manifest must survive prune");
        assert!(referenced_blob_path.exists(), "referenced blob must survive prune");
        assert!(!unreferenced_manifest_path.exists(), "unreferenced expired manifest must be pruned");
        assert!(!unreferenced_blob_path.exists(), "unreferenced expired blob must be pruned");
        assert_eq!(report.applied_blob_count, 1, "exactly the unreferenced blob should be deleted");
    }

    /// R9 mutation half of the pair above: the SAME two captures, but
    /// `referenced_blobs` left empty (as if the caller had forgotten to
    /// read `messages.excluded.raw.blob` before pruning, or the manifest-
    /// level protection union were missing) -- the blob that would
    /// otherwise have been protected now gets deleted too, proving the
    /// protection in the positive test is actually load-bearing.
    #[test]
    fn prune_without_referenced_blobs_deletes_what_would_have_been_protected_r9_mutation() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");

        let source = temp.path().join("would-be-referenced.jsonl");
        fs::write(&source, b"{\"type\":\"message\",\"text\":\"would be referenced\"}\n").expect("write source");
        let captured = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source,
            db_links: &[],
        })
        .expect("capture source");

        let root = data_dir.join(RAW_MIRROR_ROOT_DIR).join(RAW_MIRROR_VERSION_DIR);
        let manifest_path = root.join(&captured.manifest_relative_path);
        let blob_path = root.join(&captured.blob_relative_path);

        prune(
            &data_dir,
            RawMirrorPruneOptions {
                referenced_blobs: HashSet::new(), // mutation: no reference set
                older_than_ms: Some(0),
                max_size_bytes: None,
                keep_tags: Vec::new(),
                safety_hold_down_ms: 0,
                apply: true,
            },
        )
        .expect("prune without a reference set must still succeed (nothing left to protect)");

        assert!(!manifest_path.exists(), "MUTATION: without referenced_blobs, this manifest is wrongly deleted");
        assert!(!blob_path.exists(), "MUTATION: without referenced_blobs, this blob is wrongly deleted");
    }

    /// R1-N18 (任务书 #118b): `referenced_blobs` used to be unioned into
    /// `pinned_blobs` BEFORE checking `referenced_blobs.is_subset(&pinned_
    /// blobs)`, making that check vacuously true no matter what (a set is
    /// always a subset of itself-plus-more) -- a reference pointing at a
    /// blob with no manifest at all in the inventory (a dangling
    /// `excluded.raw.blob` pointer, e.g. from a corrupted/edited DB row)
    /// would silently pass the "core in the protected set" check instead of
    /// refusing `--apply`. This session has one real, legitimately-expired,
    /// UNREFERENCED capture (so the inventory is non-trivial) plus one
    /// dangling reference to a blob hash that was never captured at all.
    #[test]
    fn prune_apply_refuses_dangling_reference_with_no_backing_manifest_r1_n18_positive() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");

        let source_path = temp.path().join("unrelated.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"unrelated, real capture\"}\n")
            .expect("write source");
        capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("capture unrelated source");

        let dangling_blob = "blobs/blake3/00/dangling-reference-never-captured.raw".to_string();
        let mut referenced_blobs = HashSet::new();
        referenced_blobs.insert(dangling_blob.clone());

        let err = prune(
            &data_dir,
            RawMirrorPruneOptions {
                referenced_blobs,
                older_than_ms: Some(0),
                max_size_bytes: None,
                keep_tags: Vec::new(),
                safety_hold_down_ms: 0,
                apply: true,
            },
        )
        .expect_err("a referenced blob with no backing manifest must refuse --apply, not silently pass");
        let message = err.to_string();
        assert!(
            message.contains(&dangling_blob),
            "error must name the specific missing blob, not just a count: {message}"
        );
    }

    #[test]
    fn prune_dry_run_audits_without_removing_manifest_or_blob() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("source.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"old\"}\n")
            .expect("write source");
        let captured = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("capture source");

        let report = prune(
            &data_dir,
            RawMirrorPruneOptions {
                referenced_blobs: HashSet::new(),
                older_than_ms: Some(0),
                max_size_bytes: None,
                keep_tags: Vec::new(),
                safety_hold_down_ms: 0,
                apply: false,
            },
        )
        .expect("dry-run prune");

        assert!(report.initialized);
        assert_eq!(report.mode, "dry-run");
        assert_eq!(report.planned_manifest_count, 1);
        assert_eq!(report.planned_blob_count, 1);
        assert_eq!(report.applied_reclaim_bytes, 0);
        let root = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR);
        assert!(root.join(&captured.manifest_relative_path).exists());
        assert!(root.join(&captured.blob_relative_path).exists());
        let audit_path = root.join("pruned.jsonl");
        let audit = fs::read_to_string(audit_path).expect("read audit");
        assert!(audit.contains("\"mode\":\"dry-run\""));
        assert!(audit.contains("\"applied\":false"));
    }

    #[test]
    #[cfg(unix)]
    fn prune_refuses_symlinked_audit_log_without_writing_target() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::TempDir::new()?;
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("source.jsonl");
        let protected_audit_target = temp.path().join("protected-prune-audit.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"old\"}\n")?;
        fs::write(&protected_audit_target, b"protected\n")?;

        let captured = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })?;
        let root = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR);
        let audit_path = root.join("pruned.jsonl");
        symlink(&protected_audit_target, &audit_path)?;

        let err = match prune(
            &data_dir,
            RawMirrorPruneOptions {
                referenced_blobs: HashSet::new(),
                older_than_ms: Some(0),
                max_size_bytes: None,
                keep_tags: Vec::new(),
                safety_hold_down_ms: 0,
                apply: false,
            },
        ) {
            Ok(_) => anyhow::bail!("symlinked prune audit log was accepted"),
            Err(err) => err,
        };

        if !err.to_string().contains("prune audit through symlink") {
            anyhow::bail!("unexpected audit symlink error: {err:#}");
        }
        if !fs::read(&protected_audit_target)?
            .as_slice()
            .eq(b"protected\n")
        {
            anyhow::bail!("protected audit target was modified");
        }
        if !fs::read_link(&audit_path)?
            .as_os_str()
            .eq(protected_audit_target.as_os_str())
        {
            anyhow::bail!("audit path did not remain a symlink to the protected target");
        }
        if !root.join(&captured.manifest_relative_path).exists() {
            anyhow::bail!("failed audit append removed the captured manifest");
        }
        if !root.join(&captured.blob_relative_path).exists() {
            anyhow::bail!("failed audit append removed the captured blob");
        }
        Ok(())
    }

    #[test]
    fn prune_apply_removes_selected_manifest_and_unreferenced_blob() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("source.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\",\"text\":\"apply\"}\n")
            .expect("write source");
        let captured = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("capture source");
        let root = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR);
        let manifest_path = root.join(&captured.manifest_relative_path);
        let blob_path = root.join(&captured.blob_relative_path);

        let report = prune(
            &data_dir,
            RawMirrorPruneOptions {
                referenced_blobs: HashSet::new(),
                older_than_ms: Some(0),
                max_size_bytes: None,
                keep_tags: Vec::new(),
                safety_hold_down_ms: 0,
                apply: true,
            },
        )
        .expect("apply prune");

        assert_eq!(report.applied_manifest_count, 1);
        assert_eq!(report.applied_blob_count, 1);
        assert!(!manifest_path.exists());
        assert!(!blob_path.exists());
        let audit = fs::read_to_string(root.join("pruned.jsonl")).expect("read audit");
        assert!(audit.contains("\"mode\":\"apply\""));
        assert!(audit.contains("\"applied\":true"));
    }

    #[test]
    fn prune_apply_keeps_blob_referenced_by_retained_manifest() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let first_source = temp.path().join("first.jsonl");
        let second_source = temp.path().join("second.jsonl");
        let bytes = b"{\"type\":\"message\",\"text\":\"shared-retained\"}\n";
        fs::write(&first_source, bytes).expect("write first");
        fs::write(&second_source, bytes).expect("write second");
        let first = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &first_source,
            db_links: &[],
        })
        .expect("capture first");
        let second = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &second_source,
            db_links: &[],
        })
        .expect("capture second");
        let root = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR);
        let first_manifest_path = root.join(&first.manifest_relative_path);
        let second_manifest_path = root.join(&second.manifest_relative_path);
        let mut first_manifest =
            read_raw_mirror_manifest(&first_manifest_path).expect("first manifest");
        first_manifest.captured_at_ms = now_ms().saturating_sub(2 * 86_400_000);
        first_manifest.manifest_blake3 = Some(raw_mirror_manifest_blake3(&first_manifest));
        fs::write(
            &first_manifest_path,
            serde_json::to_vec_pretty(&first_manifest).expect("serialize first manifest"),
        )
        .expect("rewrite first manifest");

        let report = prune(
            &data_dir,
            RawMirrorPruneOptions {
                referenced_blobs: HashSet::new(),
                older_than_ms: Some(86_400_000),
                max_size_bytes: None,
                keep_tags: Vec::new(),
                safety_hold_down_ms: 0,
                apply: true,
            },
        )
        .expect("apply one-manifest prune");

        assert_eq!(report.applied_manifest_count, 1);
        assert_eq!(report.applied_blob_count, 0);
        assert!(!first_manifest_path.exists());
        assert!(second_manifest_path.exists());
        assert!(
            root.join(&first.blob_relative_path).exists(),
            "shared blob must stay while a retained manifest still references it"
        );
    }

    #[test]
    fn prune_apply_keep_tag_pins_linked_manifest_and_blob() {
        use crate::storage::api::{Conn as FrankenConnection, Profile};

        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        let source_path = temp.path().join("tagged.jsonl");
        fs::write(
            &source_path,
            b"{\"type\":\"message\",\"text\":\"tagged\"}\n",
        )
        .expect("write source");
        let db_link = RawMirrorDbLink {
            conversation_id: Some(7),
            message_count: Some(1),
            source_path: Some(source_path.display().to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };
        let captured = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: std::slice::from_ref(&db_link),
        })
        .expect("capture source");
        let db_path = data_dir.join("agent_search.db");
        let conn = FrankenConnection::open_writable(&db_path, Profile::Production)
            .expect("open keep-tag db");
        conn.execute(
            "CREATE TABLE tags (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)",
            &[],
        )
        .expect("create tags");
        conn.execute(
            "CREATE TABLE conversation_tags (conversation_id INTEGER NOT NULL, tag_id INTEGER NOT NULL, PRIMARY KEY (conversation_id, tag_id))",
            &[],
        )
        .expect("create conversation_tags");
        conn.execute(
            "INSERT INTO tags (id, name) VALUES (1, 'keep')",
            &[],
        )
        .expect("insert tag");
        conn.execute(
            "INSERT INTO conversation_tags (conversation_id, tag_id) VALUES (7, 1)",
            &[],
        )
        .expect("insert conversation tag");
        drop(conn);

        let report = prune(
            &data_dir,
            RawMirrorPruneOptions {
                referenced_blobs: HashSet::new(),
                older_than_ms: Some(0),
                max_size_bytes: Some(0),
                keep_tags: vec!["keep".to_string()],
                safety_hold_down_ms: 0,
                apply: true,
            },
        )
        .expect("keep-tag prune");

        let root = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR);
        assert_eq!(report.pinned_manifest_count, 1);
        assert_eq!(report.pinned_blob_count, 1);
        assert_eq!(report.planned_manifest_count, 0);
        assert_eq!(report.planned_blob_count, 0);
        assert!(root.join(&captured.manifest_relative_path).exists());
        assert!(root.join(&captured.blob_relative_path).exists());
    }

    #[test]
    fn prune_apply_safety_hold_down_pins_recent_manifest_during_size_prune() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("recent.jsonl");
        fs::write(
            &source_path,
            b"{\"type\":\"message\",\"text\":\"recent\"}\n",
        )
        .expect("write source");
        let captured = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("capture source");

        let report = prune(
            &data_dir,
            RawMirrorPruneOptions {
                referenced_blobs: HashSet::new(),
                older_than_ms: None,
                max_size_bytes: Some(0),
                keep_tags: Vec::new(),
                safety_hold_down_ms: 7 * 86_400_000,
                apply: true,
            },
        )
        .expect("hold-down prune");

        let root = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR);
        assert_eq!(report.pinned_manifest_count, 1);
        assert_eq!(report.pinned_blob_count, 1);
        assert_eq!(report.planned_manifest_count, 0);
        assert_eq!(report.planned_blob_count, 0);
        assert!(root.join(&captured.manifest_relative_path).exists());
        assert!(root.join(&captured.blob_relative_path).exists());
    }

    #[test]
    fn capture_source_file_revalidates_cached_blob_contents() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("cached-source.jsonl");
        let source_bytes = b"{\"type\":\"message\",\"text\":\"cache me\"}\n";
        fs::write(&source_path, source_bytes).expect("write source");

        let first = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("first capture");

        let blob_path = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR)
            .join(&first.blob_relative_path);
        fs::write(&blob_path, b"corrupted cached blob").expect("corrupt cached blob");

        let err = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect_err("corrupted content-addressed blob must be rejected");
        assert!(
            err.to_string().contains("existing raw mirror blob"),
            "unexpected cached-blob error: {err:#}"
        );
        assert_eq!(fs::read(&source_path).expect("source bytes"), source_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn capture_source_file_does_not_reuse_cache_after_same_size_mtime_preserving_rewrite() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("same-size-rewrite.jsonl");
        let first_bytes = b"same length payload A\n";
        let second_bytes = b"same length payload B\n";
        fs::write(&source_path, first_bytes).expect("write first source");

        let first_modified = fs::metadata(&source_path)
            .expect("first metadata")
            .modified()
            .expect("first modified time");
        let first = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("first capture");

        std::thread::sleep(std::time::Duration::from_millis(5));
        fs::write(&source_path, second_bytes).expect("rewrite source");
        let source = OpenOptions::new()
            .write(true)
            .open(&source_path)
            .expect("open rewritten source");
        source
            .set_times(std::fs::FileTimes::new().set_modified(first_modified))
            .expect("restore original mtime");

        let second = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect("second capture");

        assert_ne!(first.blob_blake3, second.blob_blake3);
        assert_eq!(
            second.blob_blake3,
            blake3::hash(second_bytes).to_hex().to_string()
        );
        assert_eq!(
            fs::read(&source_path).expect("source bytes after rewrite"),
            second_bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn capture_source_file_rejects_symlinked_existing_blob_path() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("cached-source.jsonl");
        let source_bytes = b"{\"type\":\"message\",\"text\":\"cache me\"}\n";
        fs::write(&source_path, source_bytes).expect("write source");

        let blob_blake3 = blake3::hash(source_bytes).to_hex().to_string();
        let blob_relative_path =
            raw_mirror_blob_relative_path(&blob_blake3).expect("blob relative path");
        let blob_path = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR)
            .join(&blob_relative_path);
        fs::create_dir_all(blob_path.parent().expect("blob parent")).expect("blob parent dir");
        let outside = temp.path().join("outside.raw");
        fs::write(&outside, source_bytes).expect("outside blob bytes");
        std::os::unix::fs::symlink(&outside, &blob_path).expect("symlink blob");

        let err = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect_err("symlinked content-addressed blob path must be rejected");
        assert!(
            err.to_string().contains("symlink raw mirror blob"),
            "unexpected symlink-blob error: {err:#}"
        );

        let manifest_root = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR)
            .join("manifests");
        assert!(
            !manifest_root.exists(),
            "failed blob publish must not write a manifest pointing at a symlinked blob"
        );
        assert_eq!(fs::read(&source_path).expect("source bytes"), source_bytes);
        assert_eq!(fs::read(&outside).expect("outside bytes"), source_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn capture_source_file_rejects_symlinked_raw_mirror_root_dir() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("source.jsonl");
        let outside_mirror = temp.path().join("outside-mirror");
        let source_bytes = b"{\"type\":\"message\",\"text\":\"do not redirect archive\"}\n";

        fs::create_dir_all(&data_dir).expect("data dir");
        fs::create_dir_all(&outside_mirror).expect("outside mirror dir");
        fs::write(&source_path, source_bytes).expect("write source");
        std::os::unix::fs::symlink(&outside_mirror, data_dir.join(RAW_MIRROR_ROOT_DIR))
            .expect("symlink raw mirror root");

        let err = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect_err("symlinked raw-mirror root must be rejected");

        assert!(
            err.to_string().contains("symlink raw mirror dir"),
            "unexpected symlink-root error: {err:#}"
        );
        assert!(
            !outside_mirror.join(RAW_MIRROR_VERSION_DIR).exists(),
            "raw mirror capture must not create redirected archive state outside data_dir"
        );
        assert_eq!(fs::read(&source_path).expect("source bytes"), source_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn capture_source_file_rejects_symlinked_blob_directory_component() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let root = data_dir
            .join(RAW_MIRROR_ROOT_DIR)
            .join(RAW_MIRROR_VERSION_DIR);
        let source_path = temp.path().join("source.jsonl");
        let outside_blobs = temp.path().join("outside-blobs");
        let source_bytes = b"{\"type\":\"message\",\"text\":\"do not redirect blobs\"}\n";

        fs::create_dir_all(&root).expect("raw mirror root");
        fs::create_dir_all(&outside_blobs).expect("outside blobs dir");
        fs::write(&source_path, source_bytes).expect("write source");
        std::os::unix::fs::symlink(&outside_blobs, root.join("blobs")).expect("symlink blobs dir");

        let err = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect_err("symlinked blob directory must be rejected");

        assert!(
            err.to_string().contains("symlink raw mirror dir"),
            "unexpected symlink-blob-dir error: {err:#}"
        );
        assert!(
            !outside_blobs.join(RAW_MIRROR_HASH_ALGORITHM).exists(),
            "raw mirror capture must not create redirected blob state outside data_dir"
        );
        assert!(
            !root.join("manifests").exists(),
            "failed blob publish must not write a manifest"
        );
        assert_eq!(fs::read(&source_path).expect("source bytes"), source_bytes);
    }

    #[test]
    fn capture_source_file_rejects_non_file_sources() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_dir = temp.path().join("source-dir");
        fs::create_dir(&source_dir).expect("source dir");

        let err = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_dir,
            db_links: &[],
        })
        .expect_err("directory source should be rejected");
        assert!(
            err.to_string().contains("non-file source"),
            "unexpected non-file-source error: {err}"
        );
        assert!(
            !data_dir.join(RAW_MIRROR_ROOT_DIR).exists(),
            "rejected non-file sources must not initialize raw mirror storage"
        );
    }

    #[cfg(unix)]
    #[test]
    fn capture_source_file_rejects_unreadable_sources_without_manifest() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("unreadable.jsonl");
        fs::write(&source_path, b"private session bytes\n").expect("source");
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o000))
            .expect("make source unreadable");

        let err = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: &[],
        })
        .expect_err("unreadable source should be rejected");
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600))
            .expect("restore source perms");
        assert!(
            err.to_string().contains("open raw mirror source"),
            "unexpected unreadable-source error: {err}"
        );
        assert!(
            !data_dir.join("raw-mirror/v1/manifests").exists(),
            "failed unreadable-source captures must not publish manifests"
        );
    }

    #[cfg(unix)]
    #[test]
    fn capture_source_file_rejects_symlink_sources() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let real_source = temp.path().join("real.jsonl");
        let symlink_source = temp.path().join("link.jsonl");
        fs::write(&real_source, b"secret session").expect("write source");
        symlink(&real_source, &symlink_source).expect("symlink");

        let err = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &symlink_source,
            db_links: &[],
        })
        .expect_err("symlink source should be rejected");
        assert!(
            err.to_string().contains("symlink source"),
            "unexpected error: {err:#}"
        );
    }

    // ============ R1 Finding 6 / 裁定 R-E-88 的判据（存储侧）============
    //
    // `rebuild_manifest_db_links` 是**整体替换**，而 `links` 是调用方更早算出来的计划。
    // 修前它在锁内重读了 manifest 却把读到的内容整个丢掉 —— 规划与施加之间任何一次
    // 合法的并发写入都会被静默抹掉。**不需要制造竞态就能演示**：缺陷的本体是
    // 「规划态与施加态之间的差异被无条件丢弃」，并发只是产生差异的一种方式。

    fn f6_fixture() -> (tempfile::TempDir, PathBuf, String, RawMirrorDbLink) {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("cass-data");
        let source_path = temp.path().join("rollout-fixture.jsonl");
        fs::write(&source_path, b"{\"type\":\"message\"}\n").expect("write source");
        let link_a = RawMirrorDbLink {
            conversation_id: Some(1),
            message_count: Some(1),
            source_path: Some(source_path.display().to_string()),
            started_at_ms: Some(1_733_000_000_000),
        };
        let captured = capture_source_file(RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source_path,
            db_links: std::slice::from_ref(&link_a),
        })
        .expect("capture");
        let rel = captured.manifest_relative_path.clone();
        (temp, data_dir, rel, link_a)
    }

    fn f6_links_on_disk(data_dir: &Path, rel: &str) -> Vec<RawMirrorDbLink> {
        let path = raw_mirror_manifest_path_from_relative(&raw_mirror_root(data_dir), rel).unwrap();
        read_raw_mirror_manifest(&path).unwrap().db_links
    }

    #[test]
    fn f6_rebuild_refuses_a_plan_whose_premise_changed_and_writes_nothing() {
        let (_t, data_dir, rel, link_a) = f6_fixture();

        // ① 规划态：此刻盘上是 [A]，计划也是 [A]。
        let planned_before = vec![link_a.clone()];
        let planned_after = vec![link_a.clone()];

        // ② 规划与施加之间，索引器落了一条新会话，把 B 并进同一份 manifest。
        let link_b = RawMirrorDbLink {
            conversation_id: Some(2),
            message_count: Some(3),
            source_path: link_a.source_path.clone(),
            started_at_ms: Some(1_733_000_100_000),
        };
        merge_manifest_db_links(&data_dir, &rel, std::slice::from_ref(&link_b))
            .expect("并发索引器的 merge");
        let mid = f6_links_on_disk(&data_dir, &rel);
        assert_eq!(
            mid.len(),
            2,
            "前置断言：B 必须真的并进去了，否则本用例没有分辨力"
        );

        // ③ 施加陈旧计划：必须一行都不写，并如实回报「前提变了」。
        let outcome =
            rebuild_manifest_db_links(&data_dir, &rel, &planned_before, &planned_after).unwrap();
        assert_eq!(outcome, RebuildManifestDbLinksOutcome::ChangedSincePlan);
        assert_eq!(
            f6_links_on_disk(&data_dir, &rel),
            mid,
            "被拒之后盘上必须逐条不变 —— 规划之后并进来的合法 backlink 不得被抹掉"
        );
    }

    #[test]
    fn f6_rebuild_still_writes_when_the_premise_holds() {
        // 分辨力对照：CAS 不能把正常路径也一起挡掉。
        let (_t, data_dir, rel, link_a) = f6_fixture();
        let current = f6_links_on_disk(&data_dir, &rel);
        assert_eq!(current.len(), 1);
        let outcome = rebuild_manifest_db_links(&data_dir, &rel, &current, &[]).unwrap();
        assert_eq!(outcome, RebuildManifestDbLinksOutcome::Written);
        assert!(f6_links_on_disk(&data_dir, &rel).is_empty());

        // 计划与现状一致时是 no-op，既不是「写了」也不是「被改过」。
        let outcome = rebuild_manifest_db_links(&data_dir, &rel, &[], &[]).unwrap();
        assert_eq!(outcome, RebuildManifestDbLinksOutcome::Unchanged);
        let _ = link_a;
    }
    // =============== R1 Finding 6 判据结束（存储侧）===============
}
