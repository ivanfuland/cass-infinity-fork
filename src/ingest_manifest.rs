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
    /// Raw `--scan-root` values, each either a plain path (broadcast to
    /// every connector, back-compat) or `<slug>:<path>` (d21: fed only to
    /// the connector registered under that `get_connector_factories()` slug).
    pub scan_roots: Vec<String>,
    pub mirror: PathBuf,
    pub out: PathBuf,
    /// d20: subagent transcripts are eligible-by-default (production `cass
    /// index` ingests them unless the operator sets `CASS_SKIP_SUBAGENTS`).
    /// Only when this flag is set does the manifest classify them as
    /// structurally excluded (`exclude_reason = "subagent"`), mirroring the
    /// runtime opt-in rather than reversing it unconditionally.
    pub skip_subagents: bool,
}

/// d21: a parsed `--scan-root` value. Root sets used to be handed to every
/// connector unconditionally, which let generic extension-based connectors
/// (claude_code, codex) recurse into other connectors' own nested session
/// directories (e.g. an OpenClaw sub-agent's embedded `codex-home/sessions`)
/// -- over-discovery a real reconcile run traced to ~2700 manifest rows the
/// live indexer's own default detection never touches. Scoping a root to one
/// connector slug closes that off; the unscoped (`Broadcast`) form preserves
/// the old shared-root behavior for backward compatibility.
enum ScanRootSpec {
    Broadcast(PathBuf),
    Scoped { slug: String, path: PathBuf },
}

fn parse_scan_root_spec(raw: &str) -> ScanRootSpec {
    match raw.split_once(':') {
        Some((slug, path)) if !slug.is_empty() => ScanRootSpec::Scoped {
            slug: slug.to_string(),
            path: PathBuf::from(path),
        },
        _ => ScanRootSpec::Broadcast(PathBuf::from(raw)),
    }
}

#[derive(Debug, Serialize)]
struct ManifestHeader {
    /// Root-set attestation (plan v6 Stage C Task C2, R2-F5): the exact
    /// `--scan-root` set this manifest was generated against, so
    /// `cass ingest reconcile --expected-roots` can assert no root was
    /// silently dropped between manifest generation and reconcile.
    scan_roots: Vec<String>,
    /// d20: the effective `--skip-subagents` value this manifest was
    /// generated with, sealed into the header so a reconcile run can see
    /// which subagent policy produced the candidate set.
    skip_subagents: bool,
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
///
/// `pub(crate)` so `ingest_reconcile` (Task C2) recomputes with this exact
/// function -- never a second copy of the formula.
pub(crate) fn content_digest(messages: &[String]) -> String {
    let mut hasher = Hasher::new();
    for content in messages {
        let bytes = content.as_bytes();
        hasher.update(&(u32::try_from(bytes.len()).unwrap_or(u32::MAX)).to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().to_hex().to_string()
}

/// Stable session identity: `{agent_slug}|{workspace}|{external_id}`, blank
/// for absent workspace/external_id. `pub(crate)` so `ingest_reconcile`
/// (Task C2) recomputes identity from DB rows with this exact function --
/// never a second copy of the format string (same discipline as
/// `content_digest`).
pub(crate) fn identity_key(agent_slug: &str, workspace: &str, external_id: &str) -> String {
    format!("{agent_slug}|{workspace}|{external_id}")
}

fn identity_key_for_conversation(agent_slug: &str, conv: &NormalizedConversation) -> String {
    let workspace = conv
        .workspace
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let external_id = conv.external_id.as_deref().unwrap_or_default();
    identity_key(agent_slug, &workspace, external_id)
}

fn identity_key_for_excluded_file(provider_slug: &str, source_path: &Path) -> String {
    format!("excluded:{provider_slug}:{}", source_path.display())
}

pub fn run_manifest(args: ManifestArgs) -> Result<()> {
    fs::create_dir_all(&args.mirror)
        .with_context(|| format!("creating mirror dir {}", args.mirror.display()))?;

    let specs: Vec<ScanRootSpec> = args
        .scan_roots
        .iter()
        .map(|raw| parse_scan_root_spec(raw))
        .collect();

    let known_slugs: HashSet<&'static str> = get_connector_factories()
        .into_iter()
        .map(|(slug, _)| slug)
        .collect();
    for spec in &specs {
        if let ScanRootSpec::Scoped { slug, .. } = spec {
            if !known_slugs.contains(slug.as_str()) {
                anyhow::bail!(
                    "--scan-root slug {slug:?} does not match any registered connector \
                     (known slugs: {known_slugs:?})"
                );
            }
        }
    }

    let broadcast_roots: Vec<PathBuf> = specs
        .iter()
        .filter_map(|spec| match spec {
            ScanRootSpec::Broadcast(path) => Some(path.clone()),
            ScanRootSpec::Scoped { .. } => None,
        })
        .collect();

    // Keyed by identity_key for deterministic (sorted) manifest output.
    let mut entries: BTreeMap<String, ManifestEntry> = BTreeMap::new();

    for (provider_slug, factory) in get_connector_factories() {
        let connector = factory();

        // d21: this connector only sees broadcast (unscoped) roots plus
        // roots explicitly scoped to its own slug -- never another
        // connector's scoped root.
        let mut connector_roots: Vec<PathBuf> = broadcast_roots.clone();
        connector_roots.extend(specs.iter().filter_map(|spec| match spec {
            ScanRootSpec::Scoped { slug, path } if slug == provider_slug => Some(path.clone()),
            _ => None,
        }));
        if connector_roots.is_empty() {
            continue;
        }
        let scan_roots: Vec<ScanRoot> = connector_roots.into_iter().map(ScanRoot::local).collect();
        let ctx = ScanContext::with_roots(PathBuf::new(), scan_roots, None);

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
            .scan_with_callback(&ctx, &mut |mut conv: NormalizedConversation| {
                scanned_paths.insert(conv.source_path.clone());
                // Mirror the indexer's own dedup-key normalization
                // (src/indexer/mod.rs::canonicalize_claude_external_id,
                // gh #302) before computing identity_key: the claude
                // connector's raw `external_id` carries a leading
                // `projects/` segment when scanned via a `~/.claude`-shaped
                // root (the same rooting `detect_installed_agents` reports),
                // but the indexer strips that prefix before writing the DB
                // row. Skipping this step here left every such session's
                // identity_key permanently unmatchable against reconcile's
                // DB-side recomputation, exactly like the agent_slug case.
                crate::indexer::canonicalize_claude_external_id(provider_slug, &mut conv);
                // Use the conversation's own `agent_slug` (the exact value
                // `src/indexer/mod.rs` writes into the `agents.slug` DB
                // column via `conv.agent_slug.clone()`), not the
                // `get_connector_factories()` registry key (`provider_slug`)
                // used only to dispatch to this connector. Some connectors
                // remap or split their registry slug per-conversation --
                // e.g. claude_code always emits `agent_slug: "claude_code"`
                // (registry key is `"claude"`), and OpenClaw computes a
                // per-sub-agent `"openclaw/<name>"` slug internally. Using
                // `provider_slug` here made every such conversation's
                // identity_key permanently unmatchable against the DB's
                // recomputed identity in `cass ingest reconcile`.
                let identity_key = identity_key_for_conversation(&conv.agent_slug, &conv);
                let source = conv.source_path.to_string_lossy().into_owned();

                // d20: subagent transcripts are eligible-by-default, the
                // same as production `cass index` (which ingests them unless
                // the operator opts in to CASS_SKIP_SUBAGENTS). The manifest
                // only classifies them as excluded when this run's own
                // `--skip-subagents` flag mirrors that opt-in -- treating
                // them as an unconditional structural exclusion was the
                // modeling error d20 corrects (a real reconcile run found
                // production DB rows for subagent transcripts that the old
                // manifest logic could never match).
                if args.skip_subagents
                    && crate::indexer::conversation_source_is_subagent(&conv.source_path)
                {
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

    // Header records the exact raw --scan-root strings (slug prefix
    // included where given), matching reconcile's --expected-roots
    // exact-string-set-equality check.
    let mut header_roots: Vec<String> = args.scan_roots.clone();
    header_roots.sort();
    let header = ManifestHeader {
        scan_roots: header_roots,
        skip_subagents: args.skip_subagents,
    };
    writeln!(out_file, "{}", serde_json::to_string(&header)?)?;

    for entry in entries.values() {
        let line = serde_json::to_string(entry)?;
        writeln!(out_file, "{line}")?;
    }

    Ok(())
}
