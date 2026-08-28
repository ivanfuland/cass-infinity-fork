//! `cass ingest manifest` (plan v6 Stage C, Task C1): read-only candidate
//! inventory over explicit `--scan-root` directories.
//!
//! For each connector, enumerates the files it discovers under the given
//! scan roots (pre-parse) and actually scans them (parse) to determine
//! eligibility, message count, and content digest. Sessions that resolve to
//! the same stable identity (e.g. the same session mirrored under two
//! different scan roots) collapse into one manifest line with multiple
//! `sources`. Files a connector discovers but never emits a conversation for
//! (empty session / malformed / oversized -- the connector's own internal
//! skip logic gives no structured reason back, see
//! `W1_ARTIFACTS/w1c-connector-enumeration-probe.md` #3) are reported with
//! `exclude_reason = "connector_filtered"` (d19: two-value enum, no finer
//! sub-classification).

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake3::Hasher;
use serde::Serialize;

use crate::connectors::{
    DiscoveredSourceRole, NormalizedConversation, ScanContext, ScanRoot, get_connector_factories,
};

pub struct ManifestArgs {
    pub scan_roots: Vec<PathBuf>,
    pub mirror: PathBuf,
    pub out: PathBuf,
}

#[derive(Debug, Serialize)]
struct ManifestEntry {
    identity_key: String,
    sources: Vec<String>,
    eligible: bool,
    exclude_reason: Option<String>,
    message_count: u64,
    content_digest: String,
}

/// `blake3(concat(u32_le(len(content_utf8)) || content_utf8))` over each
/// message's raw content, in source-parse order. No role/timestamp/metadata
/// -- plan v6 Stage C Task C1 digest contract (R1-S14/NG4 + R3-N5).
fn content_digest(messages: &[String]) -> String {
    let mut hasher = Hasher::new();
    for content in messages {
        let bytes = content.as_bytes();
        hasher.update(&(u32::try_from(bytes.len()).unwrap_or(u32::MAX)).to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().to_hex().to_string()
}

fn identity_key_for_conversation(agent_slug: &str, conv: &NormalizedConversation) -> String {
    let workspace = conv
        .workspace
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let external_id = conv.external_id.as_deref().unwrap_or_default();
    format!("{agent_slug}|{workspace}|{external_id}")
}

fn identity_key_for_excluded_file(provider_slug: &str, source_path: &Path) -> String {
    format!("excluded:{provider_slug}:{}", source_path.display())
}

pub fn run_manifest(args: ManifestArgs) -> Result<()> {
    fs::create_dir_all(&args.mirror)
        .with_context(|| format!("creating mirror dir {}", args.mirror.display()))?;

    let scan_roots: Vec<ScanRoot> = args.scan_roots.iter().cloned().map(ScanRoot::local).collect();

    // Keyed by identity_key for deterministic (sorted) manifest output.
    let mut entries: BTreeMap<String, ManifestEntry> = BTreeMap::new();

    for (provider_slug, factory) in get_connector_factories() {
        let connector = factory();
        let ctx = ScanContext::with_roots(PathBuf::new(), scan_roots.clone(), None);

        let discovered_paths: HashSet<PathBuf> = connector
            .discover_source_files(&ctx)
            .with_context(|| format!("discover_source_files failed for connector {provider_slug}"))?
            .into_iter()
            .filter(|source| source.role == DiscoveredSourceRole::PrimarySessionLog)
            .map(|source| source.source_path)
            .collect();

        if discovered_paths.is_empty() {
            continue;
        }

        let mut scanned_paths: HashSet<PathBuf> = HashSet::new();

        connector
            .scan_with_callback(&ctx, &mut |conv: NormalizedConversation| {
                scanned_paths.insert(conv.source_path.clone());
                let identity_key = identity_key_for_conversation(provider_slug, &conv);
                let source = conv.source_path.to_string_lossy().into_owned();

                // Subagent transcripts parse fine but are a structural
                // exclusion (plan Task C1) independent of the live indexer's
                // CASS_SKIP_SUBAGENTS opt-in toggle -- the manifest always
                // classifies them, it doesn't mirror a runtime env flag.
                if crate::indexer::conversation_source_is_subagent(&conv.source_path) {
                    entries
                        .entry(identity_key.clone())
                        .and_modify(|entry| {
                            if !entry.sources.contains(&source) {
                                entry.sources.push(source.clone());
                            }
                        })
                        .or_insert_with(|| ManifestEntry {
                            identity_key,
                            sources: vec![source],
                            eligible: false,
                            exclude_reason: Some("subagent".to_string()),
                            message_count: 0,
                            content_digest: content_digest(&[]),
                        });
                    return Ok(());
                }

                let messages: Vec<String> = conv.messages.iter().map(|m| m.content.clone()).collect();
                let message_count = messages.len() as u64;
                let digest = content_digest(&messages);

                entries
                    .entry(identity_key.clone())
                    .and_modify(|entry| {
                        if !entry.sources.contains(&source) {
                            entry.sources.push(source.clone());
                        }
                    })
                    .or_insert_with(|| ManifestEntry {
                        identity_key,
                        sources: vec![source],
                        eligible: true,
                        exclude_reason: None,
                        message_count,
                        content_digest: digest,
                    });
                Ok(())
            })
            .with_context(|| format!("scan_with_callback failed for connector {provider_slug}"))?;

        // Discovered-minus-scanned diff: the only structured signal available
        // for "this file produced nothing" without duplicating each
        // connector's private skip logic.
        for path in discovered_paths.difference(&scanned_paths) {
            let identity_key = identity_key_for_excluded_file(provider_slug, path);
            let source = path.to_string_lossy().into_owned();
            entries.entry(identity_key.clone()).or_insert_with(|| ManifestEntry {
                identity_key,
                sources: vec![source],
                eligible: false,
                exclude_reason: Some("connector_filtered".to_string()),
                message_count: 0,
                content_digest: content_digest(&[]),
            });
        }
    }

    let mut out_file = fs::File::create(&args.out)
        .with_context(|| format!("creating manifest output {}", args.out.display()))?;
    for entry in entries.values() {
        let line = serde_json::to_string(entry)?;
        writeln!(out_file, "{line}")?;
    }

    Ok(())
}
