//! The legacy pre-state a migration test needs, built from public primitives.
//!
//! `source_root_ingest.rs` (r3) and `source_watch_once.rs` (w6) both need a
//! tree that an earlier, source-unaware run has already covered: a
//! conversation, a `(root_id, connector)` watermark, per-file state and a
//! raw-mirror capture -- and no source facts at all. Before this module they
//! staged that state by running the legacy CLI (the same command without the
//! source-aware flag), which pinned the migration cases to the very entry
//! point the contract is retiring.
//!
//! Everything here goes through the public library API the contract names and
//! nothing else:
//! [`FrankenStorage::open`], [`FrankenStorage::ensure_agent`],
//! [`FrankenStorage::insert_conversation_tree`],
//! [`FrankenStorage::set_scan_watermark`],
//! [`FrankenStorage::upsert_scan_file_state`],
//! [`raw_mirror::capture_source_file`] and the `scan_root_meta` root-id
//! helpers. No production behaviour, no new switch, and no schema version is
//! faked: this is the current schema's "history without source facts" state.
//!
//! The capture identity is the part that has to be right. A manifest's id
//! covers the origin (`source_id`, kind, host) and its session key covers the
//! locator, so a capture written with the wrong origin is a *second* manifest
//! rather than the one the source run merges into. The values below are the
//! ones discovery hands the capture on both paths: `identity_host` is the raw
//! mirror's legacy constant `"local"` (not the declaration's namespace), and
//! the origin is the scan root's own -- `local`/`local`/`None` for a
//! connector's home root, the configured source's name for a configured one.

use std::error::Error;
use std::path::Path;

use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::raw_mirror::{self, RawMirrorCaptureInput};
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde_json::json;

type SeedResult<T = ()> = Result<T, Box<dyn Error>>;

/// One session file the seed writes legacy facts for.
pub struct LegacySeedFile<'a> {
    /// The connector that discovers this file: `"claude"` or `"codex"`.
    pub connector: &'a str,
    /// The scan root's origin `source_id`: `"local"` for a connector's own
    /// home root, the configured source's name for a configured root.
    pub source_id: &'a str,
    /// The `cfg:`/`home:` root id the watermark and the per-file state belong
    /// to, as `scan_root_meta::{config_root_id, home_root_id}` builds it.
    pub root_id: &'a str,
    /// The scan root itself, so the per-file state records the path relative
    /// to it -- the same spelling the scan compares against.
    pub root_path: &'a Path,
    /// The session file. It must already be written: the seed reads its size
    /// and mtime rather than inventing a stamp.
    pub source_path: &'a Path,
}

/// Write the legacy pre-state for every listed file under `data_dir`.
///
/// The database is `<data_dir>/agent_search.db`, the same path `cass index`
/// uses, and it is closed before this returns so the caller can hand the
/// directory to a real run.
pub fn seed_legacy_source_fixture(data_dir: &Path, files: &[LegacySeedFile<'_>]) -> SeedResult {
    let storage = FrankenStorage::open(&data_dir.join("agent_search.db"))?;
    for file in files {
        seed_one(&storage, data_dir, file)?;
    }
    storage.close()?;
    Ok(())
}

fn seed_one(storage: &FrankenStorage, data_dir: &Path, file: &LegacySeedFile<'_>) -> SeedResult {
    let relative = file
        .source_path
        .strip_prefix(file.root_path)
        .map_err(|_| {
            format!(
                "seeded source {} is not under its scan root {}",
                file.source_path.display(),
                file.root_path.display()
            )
        })?
        .to_string_lossy()
        .replace('\\', "/");

    let metadata = std::fs::metadata(file.source_path)?;
    let size = i64::try_from(metadata.len())?;
    let mtime = mtime_ms(&metadata);

    let agent_id = storage.ensure_agent(&Agent {
        id: None,
        slug: file.connector.to_string(),
        name: file.connector.to_string(),
        version: None,
        kind: AgentKind::Cli,
    })?;

    // A conversation over the same file, so the tree carries the canonical
    // facts a previous run would have landed. Its `external_id` is derived
    // from the locator, which makes it unique per `(source_id, agent)`.
    storage.insert_conversation_tree(
        agent_id,
        None,
        &Conversation {
            id: None,
            agent_slug: file.connector.to_string(),
            workspace: None,
            external_id: Some(format!("legacy-seed-{relative}")),
            title: Some(format!("legacy seed {relative}")),
            source_path: file.source_path.to_path_buf(),
            started_at: Some(mtime),
            ended_at: Some(mtime),
            approx_tokens: None,
            metadata_json: json!({"fixture": "source_legacy_seed"}),
            messages: vec![Message {
                excluded: None,
                id: None,
                idx: 0,
                role: MessageRole::User,
                author: None,
                created_at: Some(mtime),
                content: format!("legacy seed body for {relative}"),
                extra_json: json!({}),
                snippets: Vec::new(),
            }],
            source_id: file.source_id.to_string(),
            origin_host: None,
        },
    )?;

    // The metadata comparison's own state: a watermark at the file's mtime and
    // the file's stamp. Both are what the legacy pass would have written, so a
    // migration case is deciding about a file the metadata comparison calls
    // *unchanged*, not about one it never saw.
    storage.set_scan_watermark(file.root_id, file.connector, mtime)?;
    storage.upsert_scan_file_state(file.root_id, file.connector, &relative, size, mtime, mtime)?;

    // The capture, under the identity discovery hands both paths.
    raw_mirror::capture_source_file(RawMirrorCaptureInput {
        data_dir,
        provider: file.connector,
        source_id: file.source_id,
        origin_kind: "local",
        origin_host: None,
        source_path: file.source_path,
        db_links: &[],
    })?;

    Ok(())
}

/// The `identity_host` of every manifest in `data_dir`'s raw mirror, sorted.
///
/// A caller compares this before and after a run: a capture that merged into
/// the seed's manifest leaves the list alone, and one that did not adds an
/// entry. It reports identity, not a count, because the count is the same when
/// a manifest is replaced by an equally-named one.
pub fn mirror_manifest_identities(data_dir: &Path) -> Vec<String> {
    let mut identities: Vec<String> = Vec::new();
    for path in files_under(&data_dir.join("raw-mirror/v1/manifests")) {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if let Some(identity) = manifest.get("identity_host").and_then(|value| value.as_str()) {
            identities.push(identity.to_string());
        }
    }
    identities.sort();
    identities
}

/// Every blob file in `data_dir`'s raw mirror, sorted: the evidence that a
/// capture wrote bytes rather than only a manifest naming them.
pub fn mirror_blob_files(data_dir: &Path) -> Vec<String> {
    let mut blobs: Vec<String> = files_under(&data_dir.join("raw-mirror/v1/blobs"))
        .into_iter()
        .map(|path| path.display().to_string())
        .collect();
    blobs.sort();
    blobs
}

fn files_under(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(files_under(&path));
        } else {
            found.push(path);
        }
    }
    found
}

fn mtime_ms(metadata: &std::fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}
