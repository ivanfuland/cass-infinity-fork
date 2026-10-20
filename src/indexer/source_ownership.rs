//! Task 32: unique source ownership inside one source-root declaration.
//!
//! Spec: `2026-10-16-source-ownership-v1.2.md` (roadmap ticket 32).
//!
//! The Claude connector's discovery claims every `json` / `jsonl` / `claude`
//! file under an explicit root, so one shared root hands Codex rollouts and
//! Gemini chats to Claude as well. This module is the pure decision primitive
//! that gives every discovered path inside *one* source-root declaration at most
//! one owner, and rejects the path explicitly when the evidence is missing or
//! conflicting.
//!
//! The decision function reads no files and no environment. It works from the
//! already-discovered claims plus the declaration's own path facts, so it stays
//! usable after the inputs move or disappear. A caller (task 24) converts
//! `Unresolved` / `Ambiguous` into the `source_ownership_unresolved` /
//! `source_ownership_ambiguous` codes; this module keeps the raw path only as
//! the result map's key and never formats it into a diagnostic.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

/// Connector slugs of the first batch: the only two connectors whose inputs are
/// arbitrated here. A path no `claude` / `codex` claim touches keeps its legacy
/// routing.
const CLAUDE: &str = "claude";
const CODEX: &str = "codex";

/// Connector slug whose native chat layout is path evidence in its own right.
const GEMINI_FOR_PATH_EVIDENCE: &str = "gemini";

/// Aliases of the `claude` slug that must never be accepted, so an alias can
/// not slip past the ownership decision as an unregistered-but-harmless name.
const REJECTED_ALIASES: [&str; 2] = ["claude_code", "claude-code"];

/// Extensions the Claude layout owns, lowercase only (spec's evidence table).
const CLAUDE_EXTENSIONS: [&str; 3] = ["json", "jsonl", "claude"];

/// Directory components that anchor the Claude layout when they appear in the
/// declaration's root path or in the path relative to it.
const CLAUDE_ANCHORS: [(&str, &str); 2] = [(".claude", "projects"), ("claude-code", "projects")];

/// Desktop sidecar directory names; their presence (root or relative path) is
/// sufficient Claude evidence for a supported extension.
const CLAUDE_SESSION_DIRS: [&str; 2] = ["claude-code-sessions", "local-agent-mode-sessions"];

/// One connector's discovery claim for one absolute source path.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SourceOwnershipClaim {
    /// Connector slug as published by [`crate::connectors::get_connector_factories`].
    pub cass_connector: String,
    /// Absolute path the connector discovered, strictly below the declaration's
    /// root.
    pub source_path: PathBuf,
}

/// Debug output deliberately omits `source_path`: the map's raw paths must not
/// reach a log or a diagnostic through a derived `Debug` (spec 固定接口).
impl std::fmt::Debug for SourceOwnershipClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceOwnershipClaim")
            .field("cass_connector", &self.cass_connector)
            .field("source_path", &"<redacted>")
            .finish()
    }
}

/// What one path's declaration set resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceOwnershipDecision {
    /// Exactly one evidence owner, and it declared this path.
    Owner(String),
    /// No first-batch claim for this path: legacy routing is untouched.
    LegacyUnchanged,
    /// No usable evidence, or the single evidence owner did not claim the path.
    Unresolved,
    /// More than one connector's evidence points at this path.
    Ambiguous,
}

/// Structural failure of the whole call. Per-path `Unresolved` / `Ambiguous`
/// are results, not errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceOwnershipError {
    /// A claim, the native root owner or a path failed the fixed input contract.
    InvalidInput,
}

impl std::fmt::Display for SourceOwnershipError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("source_ownership_invalid")
    }
}

impl std::error::Error for SourceOwnershipError {}

/// Resolve the unique owner of every claimed path inside one root declaration.
///
/// `root` is the declaration's source root and `native_root_owner` is the
/// connector that owns an auto-detected root, or `None` for a configured,
/// mirror or fallback root. Every claimed path appears in the result map, in
/// `Unresolved` / `Ambiguous` cases too.
pub(crate) fn resolve_source_ownership(
    root: &Path,
    native_root_owner: Option<&str>,
    claims: &[SourceOwnershipClaim],
) -> Result<BTreeMap<PathBuf, SourceOwnershipDecision>, SourceOwnershipError> {
    let registry = registry_slugs();

    if !is_absolute_without_dot_components(root) {
        return Err(SourceOwnershipError::InvalidInput);
    }
    if let Some(owner) = native_root_owner {
        validate_slug(owner, &registry)?;
    }

    // Group the claims by path and fold duplicate connector declarations into a
    // set: grouping only de-duplicates for the decision and never rewrites the
    // caller's discovery descriptors.
    let mut groups: BTreeMap<PathBuf, (PathBuf, BTreeSet<&str>)> = BTreeMap::new();
    for claim in claims {
        validate_slug(&claim.cass_connector, &registry)?;
        if !is_absolute_without_dot_components(&claim.source_path) {
            return Err(SourceOwnershipError::InvalidInput);
        }
        let relative = claim
            .source_path
            .strip_prefix(root)
            .map_err(|_| SourceOwnershipError::InvalidInput)?;
        if relative.as_os_str().is_empty() {
            return Err(SourceOwnershipError::InvalidInput);
        }
        let entry = groups
            .entry(claim.source_path.clone())
            .or_insert_with(|| (relative.to_path_buf(), BTreeSet::new()));
        entry.1.insert(claim.cass_connector.as_str());
    }

    let mut decisions = BTreeMap::new();
    for (path, (relative, declared)) in groups {
        let decision = decide(root, &relative, &declared, native_root_owner);
        decisions.insert(path, decision);
    }
    Ok(decisions)
}

/// Task 34: one declaration's inside/outside split around the strict resolver.
///
/// Spec: `2026-10-16-source-ownership-consumption-v2.md` (roadmap ticket 34).
///
/// A caller that discovers claims for one declaration also observes claims for
/// paths *outside* it: discovery reports OpenCode's environment-default database
/// path while it sits outside the declared root. Those discoveries are legal and
/// must not be dropped, but they must not reach the inside decision either — the
/// strict resolver rejects any claim outside its root with `InvalidInput`, so one
/// outside discovery would fail the whole declaration.
///
/// This primitive splits first, hands only the inside claims to the unchanged
/// resolver, and returns the outside ones as an ordered, de-duplicated list the
/// caller consumes per root. Like the resolver it reads no file and no
/// environment, and returning `outside_claims` authorizes neither capture nor
/// persistence of those paths.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SourceOwnershipPartition {
    /// [`resolve_source_ownership`]'s table for the inside claims alone.
    pub(crate) decisions: BTreeMap<PathBuf, SourceOwnershipDecision>,
    /// Structurally valid claims for paths outside `root`, ordered by
    /// `source_path` and then by `cass_connector`. An exactly repeated
    /// `(cass_connector, source_path)` pair is kept once, while two connectors
    /// claiming the same outside path both stay.
    pub(crate) outside_claims: Vec<SourceOwnershipClaim>,
}

/// Debug output deliberately omits both collections: like the claim's own
/// `Debug`, this must not put a raw path or a connector slug into a log or a
/// diagnostic.
impl std::fmt::Debug for SourceOwnershipPartition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceOwnershipPartition")
            .field("decision_count", &self.decisions.len())
            .field("outside_claim_count", &self.outside_claims.len())
            .finish()
    }
}

/// Split `claims` at `root`, then resolve only the claims strictly inside it.
///
/// The root and the native root owner are validated before any claim, so an
/// empty claim list is still rejected for a bad root or a bad native root
/// owner. Every claim is validated, outside ones included: an unknown or
/// aliased connector, a relative path, a `.` / `..` component, or a claim equal
/// to the root is `InvalidInput`, and such a claim is never moved aside into
/// `outside_claims`.
pub(crate) fn partition_source_ownership(
    root: &Path,
    native_root_owner: Option<&str>,
    claims: &[SourceOwnershipClaim],
) -> Result<SourceOwnershipPartition, SourceOwnershipError> {
    let registry = registry_slugs();

    if !is_absolute_without_dot_components(root) {
        return Err(SourceOwnershipError::InvalidInput);
    }
    if let Some(owner) = native_root_owner {
        validate_slug(owner, &registry)?;
    }

    let mut inside_claims: Vec<SourceOwnershipClaim> = Vec::new();
    // Grouping the outside claims by path and folding their connectors into a
    // set is what orders and de-duplicates the returned list. The caller's own
    // descriptors are never rewritten.
    let mut outside_groups: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    for claim in claims {
        validate_slug(&claim.cass_connector, &registry)?;
        if !is_absolute_without_dot_components(&claim.source_path) {
            return Err(SourceOwnershipError::InvalidInput);
        }
        // `strip_prefix` compares whole components, so a root neighbour is
        // outside rather than a child, and a claim equal to the root leaves an
        // empty relative path, which is not a claim.
        match claim.source_path.strip_prefix(root) {
            Ok(relative) if relative.as_os_str().is_empty() => {
                return Err(SourceOwnershipError::InvalidInput);
            }
            Ok(_) => inside_claims.push(claim.clone()),
            Err(_) => {
                outside_groups
                    .entry(claim.source_path.clone())
                    .or_default()
                    .insert(claim.cass_connector.clone());
            }
        }
    }

    let decisions = resolve_source_ownership(root, native_root_owner, &inside_claims)?;
    let outside_claims = outside_groups
        .into_iter()
        .flat_map(|(source_path, connectors)| {
            connectors
                .into_iter()
                .map(move |cass_connector| SourceOwnershipClaim {
                    cass_connector,
                    source_path: source_path.clone(),
                })
        })
        .collect();

    Ok(SourceOwnershipPartition {
        decisions,
        outside_claims,
    })
}

/// The fixed decision table, for one grouped path.
fn decide(
    root: &Path,
    relative: &Path,
    declared: &BTreeSet<&str>,
    native_root_owner: Option<&str>,
) -> SourceOwnershipDecision {
    if !declared.contains(CLAUDE) && !declared.contains(CODEX) {
        return SourceOwnershipDecision::LegacyUnchanged;
    }

    // Candidate evidence, gathered without priority: the root's known owner,
    // the native layout evidence below, and "组内实际来自已注册非Claude/Codex
    // 连接器的既有发现声明". The last item keeps their existing discovery
    // contract instead of inventing a second path whitelist for them; a caller
    // must still build claims from real discovery, and a conflict with
    // first-batch evidence stays `Ambiguous` rather than being resolved here.
    let mut evidence: BTreeSet<String> = BTreeSet::new();
    if let Some(owner) = native_root_owner {
        evidence.insert(owner.to_string());
    }
    evidence.extend(
        native_path_evidence(root, relative)
            .into_iter()
            .map(str::to_string),
    );
    for connector in declared {
        if *connector != CLAUDE && *connector != CODEX {
            evidence.insert((*connector).to_string());
        }
    }

    match evidence.len() {
        0 => SourceOwnershipDecision::Unresolved,
        1 => match evidence.into_iter().next() {
            Some(owner) if declared.contains(owner.as_str()) => {
                SourceOwnershipDecision::Owner(owner)
            }
            _ => SourceOwnershipDecision::Unresolved,
        },
        _ => SourceOwnershipDecision::Ambiguous,
    }
}

/// Ownership evidence that comes from a path's own shape, inside the declaring
/// root. Matching is by full path component, never by substring, and only the
/// path relative to the root plus the root's own anchor components count.
fn native_path_evidence(root: &Path, relative: &Path) -> BTreeSet<&'static str> {
    let relative_names = component_names(relative);
    let root_names = component_names(root);
    let mut owners = BTreeSet::new();

    if claude_path_evidence(relative, &relative_names, &root_names) {
        owners.insert(CLAUDE);
    }
    if codex_path_evidence(relative) {
        owners.insert(CODEX);
    }
    if gemini_path_evidence(relative) {
        owners.insert(GEMINI_FOR_PATH_EVIDENCE);
    }
    owners
}

/// Claude owns its `projects` layout, its `.claude` / `claude-code` archives
/// (including a root that already sits inside them) and the desktop session
/// directories.
fn claude_path_evidence(
    relative: &Path,
    relative_names: &[Option<&str>],
    root_names: &[Option<&str>],
) -> bool {
    if !extension_matches(relative, &CLAUDE_EXTENSIONS, false) {
        return false;
    }

    // `projects/<project-dir>/.../<file>`
    if relative_names.first() == Some(&Some("projects")) && relative_names.len() >= 3 {
        return true;
    }

    for (first, second) in CLAUDE_ANCHORS {
        // `<anchor>/<project-dir>/.../<file>` anywhere inside the root.
        if let Some(anchor) = adjacent_component_pair(relative_names, first, second) {
            if relative_names.len() >= anchor + 4 {
                return true;
            }
        }
        // A root that is the anchor itself or a descendant of it. The root's own
        // position already supplies the project-directory level, so a file
        // placed directly in it counts as well as one below a project
        // directory; only the path *inside* the root needs the extra levels.
        if adjacent_component_pair(root_names, first, second).is_some() {
            return true;
        }
    }

    for directory in CLAUDE_SESSION_DIRS {
        if contains_component(relative_names, directory)
            || contains_component(root_names, directory)
        {
            return true;
        }
    }
    false
}

/// Codex owns its rollout files, with a case-insensitive extension.
fn codex_path_evidence(relative: &Path) -> bool {
    let Some(name) = relative.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with("rollout-") && extension_matches(relative, &["json", "jsonl"], true)
}

/// Gemini owns `session-*.json` whose direct parent directory is exactly
/// `chats`.
fn gemini_path_evidence(relative: &Path) -> bool {
    let Some(name) = relative.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let parent_is_chats = relative
        .parent()
        .and_then(Path::file_name)
        .and_then(|parent| parent.to_str())
        == Some("chats");
    parent_is_chats && name.starts_with("session-") && extension_matches(relative, &["json"], true)
}

/// The connector slugs the running build publishes. Reading the registry
/// constructs no connector and touches no environment or file.
fn registry_slugs() -> BTreeSet<&'static str> {
    crate::connectors::get_connector_factories()
        .into_iter()
        .map(|(slug, _factory)| slug)
        .collect()
}

fn validate_slug(
    slug: &str,
    registry: &BTreeSet<&'static str>,
) -> Result<(), SourceOwnershipError> {
    if slug.is_empty() || REJECTED_ALIASES.contains(&slug) || !registry.contains(slug) {
        return Err(SourceOwnershipError::InvalidInput);
    }
    Ok(())
}

fn is_absolute_without_dot_components(path: &Path) -> bool {
    path.is_absolute() && !has_dot_component(path)
}

/// `.` and `..` as whole raw segments. `Path::components()` normalizes an
/// interior `.` away before any caller could observe it, so the structural
/// check has to read the encoded bytes instead. A dot inside a directory or
/// file name (`.claude`, `session.jsonl`) is not a component and stays legal,
/// and this stays a pure byte inspection: no canonicalize, no stat, no read.
fn has_dot_component(path: &Path) -> bool {
    path.as_os_str()
        .as_encoded_bytes()
        .split(|byte| std::path::is_separator(char::from(*byte)))
        .any(|segment| segment == b"." || segment == b"..")
}

/// Component spellings of `path`, with non-UTF-8 and non-normal components kept
/// as `None` so they can never match a required name.
fn component_names(path: &Path) -> Vec<Option<&str>> {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect()
}

/// Index of the start of an adjacent `first`/`second` component pair.
fn adjacent_component_pair(names: &[Option<&str>], first: &str, second: &str) -> Option<usize> {
    names
        .windows(2)
        .position(|pair| pair[0] == Some(first) && pair[1] == Some(second))
}

fn contains_component(names: &[Option<&str>], name: &str) -> bool {
    names.iter().any(|component| *component == Some(name))
}

fn extension_matches(path: &Path, allowed: &[&str], case_insensitive: bool) -> bool {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return false;
    };
    allowed.iter().any(|candidate| {
        if case_insensitive {
            extension.eq_ignore_ascii_case(candidate)
        } else {
            extension == *candidate
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::{DiscoveredSourceFile, ScanContext, ScanRoot};
    use std::fs;
    use tempfile::TempDir;

    /// The existing CASS-registry-slug -> FAD `provider_slug` mapping: `claude`'s
    /// registry key differs from the slug the connector emits, while the other
    /// two agree. `src/ingest_manifest.rs` documents the same boundary, and FAD's
    /// private `connector_to_franken_slug` owns the mapping itself.
    const CASS_SLUG_TO_FAD_PROVIDER: [(&str, &str); 3] = [
        ("claude", "claude_code"),
        ("codex", "codex"),
        ("gemini", "gemini"),
    ];

    fn write_fixture(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture parent directory");
        }
        fs::write(path, contents).expect("fixture file");
    }

    fn claim(connector: &str, path: &Path) -> SourceOwnershipClaim {
        SourceOwnershipClaim {
            cass_connector: connector.to_string(),
            source_path: path.to_path_buf(),
        }
    }

    fn decision_for(
        root: &Path,
        native_root_owner: Option<&str>,
        claims: &[SourceOwnershipClaim],
        path: &Path,
    ) -> SourceOwnershipDecision {
        let mut decisions = resolve_source_ownership(root, native_root_owner, claims)
            .expect("claims should be valid");
        decisions
            .remove(path)
            .unwrap_or_else(|| panic!("missing decision for {}", path.display()))
    }

    fn owner(connector: &str) -> SourceOwnershipDecision {
        SourceOwnershipDecision::Owner(connector.to_string())
    }

    /// Run one registry connector's real discovery over the synthetic root.
    fn discover(slug: &str, ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let factory = crate::connectors::get_connector_factories()
            .into_iter()
            .find(|(registered, _)| *registered == slug)
            .map(|(_, factory)| factory)
            .unwrap_or_else(|| panic!("registered connector slug {slug} is missing"));
        factory()
            .discover_source_files(ctx)
            .expect("source discovery should succeed")
    }

    /// Build the shared fixture: one root holding a Claude project file, a Codex
    /// rollout and a Gemini chat session. Returns `(root, claude, codex, gemini)`.
    fn shared_root_fixture(temp: &TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let root = temp.path().join("shared-root");
        let claude_file = root.join("projects/project-a/session.jsonl");
        let codex_file = root.join("sessions/2026/01/rollout-a.jsonl");
        let gemini_file = root.join("hash-a/chats/session-a.json");
        write_fixture(&claude_file, "{\"connector\":\"claude\"}\n");
        write_fixture(&codex_file, "{\"connector\":\"codex\"}\n");
        write_fixture(&gemini_file, "{\"connector\":\"gemini\"}\n");
        (root, claude_file, codex_file, gemini_file)
    }

    fn shared_root_context(temp: &TempDir, root: &Path) -> ScanContext {
        // Independent data directory without a Gemini layout, explicit roots and
        // no host default detection.
        let data_dir = temp.path().join("cass-data");
        fs::create_dir_all(&data_dir).expect("data directory");
        ScanContext::with_roots(data_dir, vec![ScanRoot::local(root.to_path_buf())], None)
    }

    #[test]
    fn o1_real_discovery_unique_owners() {
        let temp = TempDir::new().expect("temp dir");
        let (root, claude_file, codex_file, gemini_file) = shared_root_fixture(&temp);
        let ctx = shared_root_context(&temp, &root);

        let claude_discovered = discover("claude", &ctx);
        let codex_discovered = discover("codex", &ctx);
        let gemini_discovered = discover("gemini", &ctx);

        // The real overlap: Claude's broad JSON discovery claims all three files.
        assert_eq!(
            claude_discovered.len(),
            3,
            "claude discovers every json file"
        );
        assert_eq!(
            codex_discovered.len(),
            1,
            "codex discovers only its rollout"
        );
        assert_eq!(gemini_discovered.len(), 1, "gemini discovers only its chat");
        assert!(
            claude_discovered
                .iter()
                .any(|source| source.source_path == codex_file),
            "claude must cross-claim the codex rollout"
        );
        assert!(
            claude_discovered
                .iter()
                .any(|source| source.source_path == gemini_file),
            "claude must cross-claim the gemini chat"
        );

        let mut claims = Vec::new();
        for (slug, expected_provider) in CASS_SLUG_TO_FAD_PROVIDER {
            let discovered = match slug {
                "claude" => &claude_discovered,
                "codex" => &codex_discovered,
                _ => &gemini_discovered,
            };
            assert!(
                discovered
                    .iter()
                    .all(|source| source.provider_slug == expected_provider),
                "registry slug {slug} must emit provider_slug {expected_provider}"
            );
            claims.extend(
                discovered
                    .iter()
                    .map(|source| claim(slug, &source.source_path)),
            );
        }
        assert_eq!(claims.len(), 5, "three claude claims plus one each");

        let decisions = resolve_source_ownership(&root, None, &claims).expect("valid claims");
        assert_eq!(decisions.len(), 3, "one key per claimed path");
        assert_eq!(decisions[&claude_file], owner("claude"));
        assert_eq!(decisions[&codex_file], owner("codex"));
        assert_eq!(decisions[&gemini_file], owner("gemini"));
        assert_ne!(decisions[&codex_file], owner("claude"));
        assert_ne!(decisions[&gemini_file], owner("claude"));
    }

    #[test]
    fn o2_native_roots_and_nested_archives() {
        let temp = TempDir::new().expect("temp dir");

        // Rule 1: a default `$HOME/.claude`-shaped auto-detected root carries the
        // claude owner and holds the `projects/<dir>/<file>` layout.
        let home_root = temp.path().join("home/.claude");
        let home_file = home_root.join("projects/proj-a/session.jsonl");
        write_fixture(&home_file, "{}\n");
        assert_eq!(
            decision_for(
                &home_root,
                Some("claude"),
                &[claim("claude", &home_file)],
                &home_file
            ),
            owner("claude")
        );

        // CLAUDE_CONFIG_DIR shapes: the config directory holding `projects`, and
        // the resolved `projects` directory itself.
        let config_root = temp.path().join("claude-config");
        let config_file = config_root.join("projects/proj-a/session.jsonl");
        write_fixture(&config_file, "{}\n");
        assert_eq!(
            decision_for(
                &config_root,
                Some("claude"),
                &[claim("claude", &config_file)],
                &config_file
            ),
            owner("claude")
        );

        let resolved_config_root = temp.path().join("claude-config-resolved/projects");
        let resolved_config_file = resolved_config_root.join("proj-a/session.jsonl");
        write_fixture(&resolved_config_file, "{}\n");
        assert_eq!(
            decision_for(
                &resolved_config_root,
                Some("claude"),
                &[claim("claude", &resolved_config_file)],
                &resolved_config_file
            ),
            owner("claude")
        );

        // XDG_CONFIG_HOME shape: `<xdg>/claude-code` holding `projects`.
        let xdg_root = temp.path().join("xdg/claude-code");
        let xdg_file = xdg_root.join("projects/proj-a/session.jsonl");
        write_fixture(&xdg_file, "{}\n");
        assert_eq!(
            decision_for(
                &xdg_root,
                Some("claude"),
                &[claim("claude", &xdg_file)],
                &xdg_file
            ),
            owner("claude")
        );

        // Nested archives under a configured/mirror root with no native owner:
        // the path evidence alone must own both anchor spellings.
        let mirror_root = temp.path().join("mirror");
        let nested_claude = mirror_root.join("snapshots/.claude/projects/proj-a/session.jsonl");
        let nested_dashed = mirror_root.join("claude-code/projects/proj-a/session.jsonl");
        write_fixture(&nested_claude, "{}\n");
        write_fixture(&nested_dashed, "{}\n");
        for path in [&nested_claude, &nested_dashed] {
            assert_eq!(
                decision_for(&mirror_root, None, &[claim("claude", path)], path),
                owner("claude"),
                "nested archive {} should be owned by claude",
                path.display()
            );
        }

        // A root that already sits inside `.claude/projects`.
        let anchored_root = temp.path().join("anchored/.claude/projects");
        let anchored_file = anchored_root.join("proj-a/session.jsonl");
        write_fixture(&anchored_file, "{}\n");
        assert_eq!(
            decision_for(
                &anchored_root,
                None,
                &[claim("claude", &anchored_file)],
                &anchored_file
            ),
            owner("claude")
        );

        // A descendant of either anchor owns a file placed directly in it: the
        // root's own position already supplies the project-directory level, so
        // no extra relative directory component is required.
        for (label, descendant_root) in [
            (
                "descendant-dot",
                temp.path().join("descendant/.claude/projects/project-a"),
            ),
            (
                "descendant-dash",
                temp.path()
                    .join("descendant/claude-code/projects/project-a"),
            ),
        ] {
            let direct_file = descendant_root.join("session.jsonl");
            write_fixture(&direct_file, "{}\n");
            assert_eq!(
                decision_for(
                    &descendant_root,
                    None,
                    &[claim("claude", &direct_file)],
                    &direct_file
                ),
                owner("claude"),
                "descendant root {label} must own its direct file"
            );
        }

        // The two desktop session directory names.
        let desktop_root = temp.path().join("desktop");
        let desktop_cli = desktop_root.join("Claude/claude-code-sessions/session-1.jsonl");
        let desktop_mode = desktop_root.join("Claude/local-agent-mode-sessions/session-2.jsonl");
        write_fixture(&desktop_cli, "{}\n");
        write_fixture(&desktop_mode, "{}\n");
        for path in [&desktop_cli, &desktop_mode] {
            assert_eq!(
                decision_for(&desktop_root, None, &[claim("claude", path)], path),
                owner("claude"),
                "desktop session file {} should be owned by claude",
                path.display()
            );
        }

        // Codex rollout extension, case-insensitive.
        let codex_root = temp.path().join("codex-home");
        let upper = codex_root.join("sessions/2026/01/rollout-upper.JSONL");
        let mixed = codex_root.join("sessions/rollout-mixed.Json");
        write_fixture(&upper, "{}\n");
        write_fixture(&mixed, "{}\n");
        for path in [&upper, &mixed] {
            assert_eq!(
                decision_for(&codex_root, None, &[claim("codex", path)], path),
                owner("codex"),
                "rollout file {} should be owned by codex",
                path.display()
            );
        }

        // Gemini's `chats` parent must be the exact directory component: an exact
        // parent adds gemini evidence, a near-miss parent leaves claude alone.
        let gemini_root = temp.path().join("gemini-home");
        let exact = gemini_root.join("projects/p/chats/session-a.json");
        let near_miss = gemini_root.join("projects/p/chats-archive/session-a.json");
        write_fixture(&exact, "{}\n");
        write_fixture(&near_miss, "{}\n");
        assert_eq!(
            decision_for(&gemini_root, None, &[claim("claude", &exact)], &exact),
            SourceOwnershipDecision::Ambiguous
        );
        assert_eq!(
            decision_for(
                &gemini_root,
                None,
                &[claim("claude", &near_miss)],
                &near_miss
            ),
            owner("claude")
        );

        // Directory-name substrings must not impersonate a full component.
        let substring_root = temp.path().join("substring");
        let fake_projects = substring_root.join("myprojects/proj-a/session.jsonl");
        let fake_anchor = substring_root.join(".claude/projects-archive/proj-a/session.jsonl");
        write_fixture(&fake_projects, "{}\n");
        write_fixture(&fake_anchor, "{}\n");
        for path in [&fake_projects, &fake_anchor] {
            assert_eq!(
                decision_for(&substring_root, None, &[claim("claude", path)], path),
                SourceOwnershipDecision::Unresolved,
                "substring path {} must not become claude evidence",
                path.display()
            );
        }
    }

    #[test]
    fn o3_unresolved_and_ambiguous_are_per_path() {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path().join("mixed-root");
        let broad = root.join("notes.json");
        let contested = root.join("projects/p/chats/session-a.json");
        let gemini_only = root.join("tmp/hash-b/chats/session-b.json");
        let normal = root.join("projects/project-z/session.jsonl");
        for path in [&broad, &contested, &gemini_only, &normal] {
            write_fixture(path, "{}\n");
        }

        let claims = vec![
            claim("claude", &broad),
            claim("claude", &contested),
            claim("gemini", &contested),
            claim("claude", &gemini_only),
            claim("claude", &normal),
        ];
        let decisions = resolve_source_ownership(&root, None, &claims).expect("valid claims");

        assert_eq!(decisions.len(), 4, "every legitimate path keeps its key");
        assert_eq!(decisions[&broad], SourceOwnershipDecision::Unresolved);
        assert_eq!(decisions[&contested], SourceOwnershipDecision::Ambiguous);
        assert_eq!(decisions[&gemini_only], SourceOwnershipDecision::Unresolved);
        assert_eq!(decisions[&normal], owner("claude"));
    }

    #[test]
    fn o4_invalid_claims_fail_closed() {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path().join("root");
        let file = root.join("projects/p/session.jsonl");
        write_fixture(&file, "{}\n");
        let outside = temp.path().join("outside.json");
        write_fixture(&outside, "{}\n");

        let rejected = |native_root_owner: Option<&str>, claims: Vec<SourceOwnershipClaim>| {
            resolve_source_ownership(&root, native_root_owner, &claims)
        };

        for slug in ["", "not-a-connector", "claude_code", "claude-code"] {
            assert_eq!(
                rejected(None, vec![claim(slug, &file)]),
                Err(SourceOwnershipError::InvalidInput),
                "slug {slug:?} must be rejected"
            );
        }

        for native in ["", "claude_code", "claude-code", "not-a-connector"] {
            assert_eq!(
                rejected(Some(native), vec![claim("claude", &file)]),
                Err(SourceOwnershipError::InvalidInput),
                "native root owner {native:?} must be rejected"
            );
        }

        // A registered connector outside the first batch stays legal.
        let legacy = resolve_source_ownership(&root, None, &[claim("amp", &file)])
            .expect("registered legacy slug is legal input");
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[&file], SourceOwnershipDecision::LegacyUnchanged);

        // Relative paths, escaping paths and the root itself all fail closed.
        assert_eq!(
            resolve_source_ownership(Path::new("relative/root"), None, &[claim("claude", &file)]),
            Err(SourceOwnershipError::InvalidInput)
        );
        assert_eq!(
            rejected(
                None,
                vec![claim("claude", Path::new("projects/p/session.jsonl"))]
            ),
            Err(SourceOwnershipError::InvalidInput)
        );
        assert_eq!(
            rejected(None, vec![claim("claude", &outside)]),
            Err(SourceOwnershipError::InvalidInput)
        );
        assert_eq!(
            rejected(None, vec![claim("claude", &root)]),
            Err(SourceOwnershipError::InvalidInput)
        );
        assert_eq!(
            rejected(
                None,
                vec![claim("claude", &root.join("..").join("escalated.json"))]
            ),
            Err(SourceOwnershipError::InvalidInput)
        );
        assert_eq!(
            resolve_source_ownership(
                &root.join(".."),
                None,
                &[claim("claude", &root.join("nested.json"))]
            ),
            Err(SourceOwnershipError::InvalidInput)
        );

        // A `.` component is dropped by `Path::components()` before a caller
        // could observe it, so the structural check must read the raw
        // separators: an interior dot fails closed for the source and for the
        // root alike.
        let dotted_source = root.join(".").join("projects/p/session.jsonl");
        assert_eq!(
            rejected(None, vec![claim("claude", &dotted_source)]),
            Err(SourceOwnershipError::InvalidInput)
        );
        let dotted_root = temp.path().join(".").join("root-sub");
        assert_eq!(
            resolve_source_ownership(&dotted_root, None, &[claim("claude", &file)]),
            Err(SourceOwnershipError::InvalidInput)
        );

        assert_eq!(
            SourceOwnershipError::InvalidInput.to_string(),
            "source_ownership_invalid"
        );
    }

    #[test]
    fn o5_order_duplicates_legacy_and_declarations() {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path().join("declaration-root");
        let legacy_only = root.join("vendor/notes.txt");
        let amp_owned = root.join("misc/first.json");
        let two_legacy = root.join("misc/second.json");
        let claude_owned = root.join("projects/p/session.jsonl");
        for path in [&legacy_only, &amp_owned, &two_legacy, &claude_owned] {
            write_fixture(path, "{}\n");
        }

        let claims = vec![
            claim("amp", &legacy_only),
            claim("openclaw", &legacy_only),
            claim("claude", &amp_owned),
            claim("amp", &amp_owned),
            claim("claude", &two_legacy),
            claim("amp", &two_legacy),
            claim("openclaw", &two_legacy),
            claim("claude", &claude_owned),
        ];
        let decisions = resolve_source_ownership(&root, None, &claims).expect("valid claims");
        assert_eq!(decisions.len(), 4);
        assert_eq!(
            decisions[&legacy_only],
            SourceOwnershipDecision::LegacyUnchanged,
            "a group without a first-batch claim keeps legacy routing"
        );
        assert_eq!(decisions[&amp_owned], owner("amp"));
        assert_eq!(decisions[&two_legacy], SourceOwnershipDecision::Ambiguous);
        assert_eq!(decisions[&claude_owned], owner("claude"));

        // Reversed order with every claim duplicated must not change the table.
        let mut reordered: Vec<SourceOwnershipClaim> = claims.iter().rev().cloned().collect();
        reordered.extend(claims.iter().cloned());
        assert_eq!(
            resolve_source_ownership(&root, None, &reordered).expect("valid claims"),
            decisions
        );

        // The same absolute path in two independent root declarations keeps each
        // declaration's own answer; no cross-call memoization folds the second.
        let nested_root = root.join("projects");
        let shared_path = root.join("projects/dual/session.jsonl");
        write_fixture(&shared_path, "{}\n");
        let outer = vec![claim("claude", &shared_path)];
        assert_eq!(
            decision_for(&root, None, &outer, &shared_path),
            owner("claude")
        );
        assert_eq!(
            decision_for(&nested_root, None, &outer, &shared_path),
            SourceOwnershipDecision::Unresolved
        );
        assert_eq!(
            decision_for(&root, None, &outer, &shared_path),
            owner("claude"),
            "the second declaration must not poison a later call"
        );
    }

    #[test]
    fn o6_decisions_do_not_read_live_files() {
        let temp = TempDir::new().expect("temp dir");
        let (root, claude_file, codex_file, gemini_file) = shared_root_fixture(&temp);
        let ctx = shared_root_context(&temp, &root);

        let mut claims = Vec::new();
        for (slug, _) in CASS_SLUG_TO_FAD_PROVIDER {
            claims.extend(
                discover(slug, &ctx)
                    .iter()
                    .map(|source| claim(slug, &source.source_path)),
            );
        }

        let before = resolve_source_ownership(&root, None, &claims).expect("valid claims");
        assert_eq!(before[&claude_file], owner("claude"));
        assert_eq!(before[&codex_file], owner("codex"));
        assert_eq!(before[&gemini_file], owner("gemini"));

        let fixture_paths = [&claude_file, &codex_file, &gemini_file];
        let digests_before: Vec<String> = fixture_paths
            .iter()
            .map(|path| {
                blake3::hash(&fs::read(path).expect("fixture readable"))
                    .to_hex()
                    .to_string()
            })
            .collect();

        // Rename the synthetic input directory into a kept sibling. The old
        // absolute paths no longer exist; the decision must not change.
        let kept = temp.path().join("kept-root");
        fs::rename(&root, &kept).expect("rename the synthetic input directory");
        assert!(!root.exists(), "the original input directory must be gone");

        let after = resolve_source_ownership(&root, None, &claims).expect("valid claims");
        assert_eq!(after, before, "decisions must not depend on live files");
        assert_eq!(after[&codex_file], owner("codex"));

        for (index, path) in fixture_paths.iter().enumerate() {
            let moved = kept.join(
                path.strip_prefix(&root)
                    .expect("fixture below the synthetic root"),
            );
            let digest_after = blake3::hash(&fs::read(&moved).expect("moved fixture readable"))
                .to_hex()
                .to_string();
            assert_eq!(
                digest_after.to_string(),
                digests_before[index],
                "fixture {} must be unchanged by the rename",
                path.display()
            );
        }
    }
}

/// Task 34 acceptance tests for the declaration partition.
///
/// Every path below is synthetic: these tests open no file, read no environment
/// and touch no global state, so their result does not depend on the runner's
/// thread count or on any neighbouring test.
#[cfg(test)]
mod partition_tests {
    use super::*;

    const ROOT: &str = "/synthetic/decl";
    const INSIDE_CLAUDE: &str = "/synthetic/decl/projects/p/session.jsonl";
    const INSIDE_ROLLOUT: &str = "/synthetic/decl/sessions/rollout-a.jsonl";
    const INSIDE_LEGACY: &str = "/synthetic/decl/legacy/log.txt";
    const OUTSIDE_DB: &str = "/synthetic/home/opencode.db";
    const OUTSIDE_NEIGHBOR: &str = "/synthetic/decl-neighbor/file.json";

    fn claim(connector: &str, path: &str) -> SourceOwnershipClaim {
        SourceOwnershipClaim {
            cass_connector: connector.to_string(),
            source_path: PathBuf::from(path),
        }
    }

    fn owner(connector: &str) -> SourceOwnershipDecision {
        SourceOwnershipDecision::Owner(connector.to_string())
    }

    fn decide(partition: &SourceOwnershipPartition, path: &str) -> SourceOwnershipDecision {
        partition
            .decisions
            .get(Path::new(path))
            .unwrap_or_else(|| panic!("missing decision for {path}"))
            .clone()
    }

    #[test]
    fn p1_outside_claims_do_not_poison_declared_owners() {
        let root = Path::new(ROOT);
        let claims = vec![
            claim("claude", INSIDE_CLAUDE),
            claim("claude", INSIDE_ROLLOUT),
            claim("codex", INSIDE_ROLLOUT),
            claim("amp", INSIDE_LEGACY),
            claim("opencode", OUTSIDE_DB),
            claim("claude", OUTSIDE_NEIGHBOR),
        ];
        let frozen = claims.clone();

        // The outside discoveries are legal input, so the call succeeds instead
        // of failing the whole declaration the way the strict resolver would.
        let partition = partition_source_ownership(root, None, &claims)
            .expect("an outside discovery must not fail the declaration");

        // The decisions equal the resolver's own result for the inside claims
        // alone, field by field, with the same map keys.
        let expected = resolve_source_ownership(
            root,
            None,
            &[
                claim("claude", INSIDE_CLAUDE),
                claim("claude", INSIDE_ROLLOUT),
                claim("codex", INSIDE_ROLLOUT),
                claim("amp", INSIDE_LEGACY),
            ],
        )
        .expect("valid inside claims");
        assert_eq!(partition.decisions, expected);
        assert_eq!(partition.decisions.len(), 3);
        assert_eq!(decide(&partition, INSIDE_CLAUDE), owner("claude"));
        assert_eq!(decide(&partition, INSIDE_ROLLOUT), owner("codex"));
        assert_eq!(
            decide(&partition, INSIDE_LEGACY),
            SourceOwnershipDecision::LegacyUnchanged
        );
        // A root *neighbour* is not a child of the root, so it owns nothing
        // inside: it can only appear in the outside list.
        assert!(
            !partition
                .decisions
                .contains_key(Path::new(OUTSIDE_NEIGHBOR)),
            "an outside path must not enter the decisions map"
        );

        // Outside claims keep their own order: by path, then by connector, with
        // an exactly repeated pair folded to one.
        assert_eq!(
            partition.outside_claims,
            vec![
                claim("claude", OUTSIDE_NEIGHBOR),
                claim("opencode", OUTSIDE_DB),
            ]
        );

        assert_eq!(
            claims, frozen,
            "the input descriptors must not be rewritten"
        );

        // Reversal plus repeats of both an inside and an outside claim leave the
        // partition identical.
        let mut reordered: Vec<SourceOwnershipClaim> = claims.iter().rev().cloned().collect();
        reordered.extend(claims.iter().cloned());
        reordered.push(claim("opencode", OUTSIDE_DB));
        reordered.push(claim("claude", INSIDE_ROLLOUT));
        let again = partition_source_ownership(root, None, &reordered).expect("valid claims");
        assert_eq!(
            again, partition,
            "order, duplicate claims and reversal must not change the partition"
        );
    }

    #[test]
    fn p2_invalid_structure_is_not_laundered() {
        let root = Path::new(ROOT);
        let invalid = SourceOwnershipError::InvalidInput;

        // Valid baseline: one inside and one outside claim. Every rejection
        // below changes exactly one factor away from it, so the failing reason
        // is the factor under test.
        assert!(
            partition_source_ownership(
                root,
                None,
                &[
                    claim("claude", INSIDE_CLAUDE),
                    claim("opencode", OUTSIDE_DB)
                ]
            )
            .is_ok()
        );

        for bad_root in [
            "synthetic/decl",
            "",
            "/synthetic/./decl",
            "/synthetic/decl/../decl",
        ] {
            assert_eq!(
                partition_source_ownership(
                    Path::new(bad_root),
                    None,
                    &[claim("claude", INSIDE_CLAUDE)]
                ),
                Err(invalid),
                "root {bad_root:?} must be rejected"
            );
        }

        for bad_native in ["", "claude_code", "claude-code", "not-a-connector"] {
            assert_eq!(
                partition_source_ownership(
                    root,
                    Some(bad_native),
                    &[claim("claude", INSIDE_CLAUDE)]
                ),
                Err(invalid),
                "native root owner {bad_native:?} must be rejected"
            );
        }

        // Inside claims: unknown slugs and both Claude aliases, plus the two
        // structural failures that already fail for the strict resolver.
        for bad_inside in [
            claim("", INSIDE_CLAUDE),
            claim("claude_code", INSIDE_CLAUDE),
            claim("claude-code", INSIDE_CLAUDE),
            claim("not-a-connector", INSIDE_CLAUDE),
            claim("claude", "projects/p/session.jsonl"),
            claim("claude", "/synthetic/decl/./projects/p/session.jsonl"),
            claim("claude", "/synthetic/decl/projects/../session.jsonl"),
        ] {
            assert_eq!(
                partition_source_ownership(root, None, &[bad_inside.clone()]),
                Err(invalid),
                "inside claim {bad_inside:?} must be rejected"
            );
        }

        // Outside claims are validated too: being outside the root is not a way
        // to reach the decision with an unregistered connector or a path that
        // never passed the structural contract.
        for bad_outside in [
            claim("", OUTSIDE_DB),
            claim("claude_code", OUTSIDE_DB),
            claim("claude-code", OUTSIDE_DB),
            claim("not-a-connector", OUTSIDE_DB),
            claim("opencode", "home/opencode.db"),
            claim("opencode", "/synthetic/./home/opencode.db"),
            claim("opencode", "/synthetic/home/../opencode.db"),
            claim("claude", "/synthetic/decl/../other/file.json"),
        ] {
            assert_eq!(
                partition_source_ownership(root, None, &[bad_outside.clone()]),
                Err(invalid),
                "outside claim {bad_outside:?} must be rejected, not moved aside"
            );
        }

        // One bad outside claim among good ones must fail the whole call rather
        // than be dropped from the list.
        assert_eq!(
            partition_source_ownership(
                root,
                None,
                &[
                    claim("claude", INSIDE_CLAUDE),
                    claim("opencode", OUTSIDE_DB),
                    claim("claude_code", OUTSIDE_NEIGHBOR),
                ]
            ),
            Err(invalid),
            "a structurally invalid outside claim must not be silently dropped"
        );

        // The root is not itself a claim: equal to the root, its relative path is
        // empty, which is the invalid-input contract the strict resolver uses.
        assert_eq!(
            partition_source_ownership(root, None, &[claim("claude", ROOT)]),
            Err(invalid)
        );

        // An empty, valid claim list succeeds with both collections empty, and
        // the root and native owner are still validated.
        let empty = partition_source_ownership(root, None, &[]).expect("empty claims are valid");
        assert!(empty.decisions.is_empty());
        assert!(empty.outside_claims.is_empty());
        let empty_native = partition_source_ownership(root, Some("claude"), &[])
            .expect("a registered native root owner is legal");
        assert!(empty_native.decisions.is_empty());
        assert!(empty_native.outside_claims.is_empty());
        assert_eq!(
            partition_source_ownership(Path::new("synthetic/decl"), None, &[]),
            Err(invalid),
            "an empty claim list must not skip the root check"
        );
        assert_eq!(
            partition_source_ownership(root, Some("not-a-connector"), &[]),
            Err(invalid),
            "an empty claim list must not skip the native owner check"
        );
    }

    #[test]
    fn p3_declarations_errors_and_debug_stay_separate() {
        let root = Path::new(ROOT);
        let unresolved = "/synthetic/decl/notes.json";
        let contested = "/synthetic/decl/projects/p/chats/session-a.json";
        let normal = "/synthetic/decl/projects/p/session.jsonl";

        let claims = vec![
            claim("claude", unresolved),
            claim("claude", contested),
            claim("gemini", contested),
            claim("claude", normal),
        ];
        let frozen = claims.clone();

        let partition = partition_source_ownership(root, None, &claims).expect("valid claims");
        assert_eq!(
            partition.decisions.len(),
            3,
            "unresolved and ambiguous paths keep their entries"
        );
        assert_eq!(
            decide(&partition, unresolved),
            SourceOwnershipDecision::Unresolved
        );
        assert_eq!(
            decide(&partition, contested),
            SourceOwnershipDecision::Ambiguous
        );
        assert_eq!(decide(&partition, normal), owner("claude"));
        assert!(partition.outside_claims.is_empty());
        assert_eq!(claims, frozen);

        // The same absolute path under an independent declaration gets that
        // declaration's own answer, and the first result is not rewritten.
        let outer = partition_source_ownership(
            Path::new("/synthetic"),
            Some("claude"),
            &[claim("claude", unresolved)],
        )
        .expect("valid claims");
        assert_eq!(decide(&outer, unresolved), owner("claude"));
        assert!(
            outer.outside_claims.is_empty(),
            "a path strictly inside the outer root is not an outside claim"
        );
        assert_eq!(
            decide(&partition, unresolved),
            SourceOwnershipDecision::Unresolved,
            "the second declaration must not poison the first result"
        );

        // The derived Debug would print every key and slug; the hand-written one
        // reports the two counts and names no input.
        let rendered = format!("{partition:?}");
        assert!(rendered.contains("decision_count"), "{rendered}");
        assert!(rendered.contains("outside_claim_count"), "{rendered}");
        assert!(rendered.contains('3'), "{rendered}");
        for leaked in [
            "/synthetic",
            "decl",
            "notes",
            "claude",
            "gemini",
            "json",
            "projects",
        ] {
            assert!(
                !rendered.contains(leaked),
                "Debug output leaked {leaked:?}: {rendered}"
            );
        }

        // Declaration order does not reach the result.
        let mut reordered: Vec<SourceOwnershipClaim> = claims.iter().rev().cloned().collect();
        reordered.extend(claims.iter().cloned());
        let again = partition_source_ownership(root, None, &reordered).expect("valid claims");
        assert_eq!(
            again, partition,
            "declaration order must not change the result"
        );
    }
}
