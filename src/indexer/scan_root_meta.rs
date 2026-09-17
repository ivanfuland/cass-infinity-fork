//! PR8 C3 (spec S2 / 硬约束 4、5、6、12): per-scan-root metadata.
//!
//! The scan watermark stopped being one row per database (and then one row per
//! connector) and became one row per `(root_id, connector)`. Nothing about a
//! `ScanRoot` says which root it is, and `ScanRoot` is a re-exported
//! `franken_agent_detection` type (no `root_id` / `readonly` field, and PR8
//! does not modify the FAD pin), so the identity travels *beside* the roots in
//! this side table -- hard constraint 12.
//!
//! Two kinds of roots get a `root_id`:
//!
//! - a configured source path: `cfg:<source>:<blake3(canonical_path)[:16]>`,
//!   one per `paths` entry, so two paths of the same `SourceDefinition` are two
//!   roots (hard constraint 4);
//! - a connector's own home root, discovered by [`home_scan_roots`]:
//!   `home:<connector>:<blake3(canonical_root)[:16]>`.
//!
//! [`home_scan_roots`] re-implements the two connectors' *private* root
//! resolvers on the CASS side, in the same precedence order, because the
//! `Connector` trait exposes no root list: claude_code resolves
//! `CLAUDE_CONFIG_DIR` -> `XDG_CONFIG_HOME/claude-code` -> `$HOME/.claude` and
//! appends `projects`; codex resolves `CODEX_HOME` -> `$HOME/.codex` and uses
//! its `sessions` child when that exists. The parity test in `w8_watermarks`
//! pins the result against `discover_source_files`, so a drift here shows up as
//! a failing test rather than as silently unscanned history.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// `source_name` of a connector's own (auto-discovered) roots.
pub const HOME_SOURCE_NAME: &str = "home";

/// The connectors whose own machine roots take part in per-root watermarks
/// (spec hard constraint 5: every other connector keeps the baseline
/// connector-level watermark). These are the connector *registry* names --
/// `claude` is the franken slug for claude_code, and [`home_scan_roots`]
/// accepts the agent slug too so either spelling resolves.
pub const CONNECTORS_WITH_HOME_ROOTS: [&str; 2] = ["claude", "codex"];

/// One scan root's identity, keyed by `(source_name, canonical_path)`.
///
/// `canonical_path` is the *on-disk* path (`fs::canonicalize` when the path
/// exists), which is what makes a fake `HOME` produce different ids from the
/// real one -- the same spelling of `~/.claude/projects` under two homes is two
/// roots, and a `--full` scan of one must not move the other's watermark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRootMeta {
    /// `cfg:...` / `home:...` -- the watermark key's first component.
    pub root_id: String,
    /// The machine the sessions under this root were produced on. Configured
    /// roots take it from `SourceDefinition::origin_host`; home roots are
    /// `local`.
    pub origin_host: String,
    /// Configured `readonly = true` local roots (hard constraint 9/10). Carried
    /// here so ingest reads it from the root metadata instead of C5's
    /// transitional `readonly_scan_root_paths()` side channel.
    pub readonly: bool,
    /// Canonicalized root path, as it went into `root_id`.
    pub canonical_path: PathBuf,
    /// Source name for configured roots, [`HOME_SOURCE_NAME`] for home roots.
    pub source_name: String,
    /// Whether `(root_id, connector)` watermarks apply to this root: local
    /// configured roots and home roots yes, ssh mirror roots and `full_scan`
    /// sources no (hard constraint 5).
    pub watermarks_enabled: bool,
}

impl ScanRootMeta {
    #[must_use]
    pub fn key(&self) -> (String, PathBuf) {
        (self.source_name.clone(), self.canonical_path.clone())
    }
}

/// `(source_name, canonical_path)` -> meta. The lookup is the only way ingest
/// turns a `ScanRoot` into an `identity_host` / `root_id`.
#[derive(Debug, Clone, Default)]
pub struct ScanRootMetaIndex {
    entries: HashMap<(String, PathBuf), ScanRootMeta>,
}

impl ScanRootMetaIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, meta: ScanRootMeta) {
        self.entries.insert(meta.key(), meta);
    }

    /// Merge another index into this one (configured roots + one connector's
    /// home roots are built apart and consulted together).
    pub fn merge(&mut self, other: &Self) {
        for meta in other.entries.values() {
            self.insert(meta.clone());
        }
    }

    #[must_use]
    pub fn get(&self, source_name: &str, canonical_path: &Path) -> Option<&ScanRootMeta> {
        self.entries
            .get(&(source_name.to_string(), canonical_path.to_path_buf()))
    }

    /// Look up by the root path as it appears on a `ScanRoot`. The scan side
    /// canonicalizes when it builds the root, so this is a plain lookup; a root
    /// that no meta was built for (a mirror root, or a connector outside
    /// claude_code / codex) simply misses.
    #[must_use]
    pub fn get_by_path(&self, root_path: &Path) -> Option<&ScanRootMeta> {
        let canonical = canonicalize_root_path(root_path);
        self.entries
            .values()
            .find(|meta| meta.canonical_path == canonical)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ScanRootMeta> {
        self.entries.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// `fs::canonicalize` when the path exists, the path itself otherwise (a scan
/// root that is about to be reported missing never becomes a root id, but a
/// caller may still canonicalize a path that has not been created yet).
#[must_use]
pub fn canonicalize_root_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn path_hash16(path: &Path) -> String {
    let hash = blake3::hash(path.as_os_str().as_encoded_bytes());
    let hex = hash.to_hex().to_string();
    hex.chars().take(16).collect()
}

/// `cfg:<name>:<blake3(canonical_path)[:16]>` -- one per configured `paths`
/// entry (hard constraint 4).
#[must_use]
pub fn config_root_id(source_name: &str, canonical_path: &Path) -> String {
    format!("cfg:{source_name}:{}", path_hash16(canonical_path))
}

/// `home:<connector>:<blake3(canonical_root)[:16]>` (hard constraint 4).
#[must_use]
pub fn home_root_id(connector: &str, canonical_root: &Path) -> String {
    format!("home:{connector}:{}", path_hash16(canonical_root))
}

/// The root id used by restore: sessions replayed out of a capture keep the
/// identity the capture recorded, and carry no scan root of their own.
#[must_use]
pub fn restore_root_id(identity_host: &str) -> String {
    format!("restore:{identity_host}")
}

fn env_path_nonempty(key: &str) -> Option<PathBuf> {
    let value = dotenvy::var(key).ok()?;
    if value.trim().is_empty() {
        return None;
    }
    Some(PathBuf::from(value))
}

/// The roots a connector would scan for its own machine, in the same
/// precedence order as its private resolver (see the module doc). Connectors
/// outside claude_code / codex return an empty list and keep the baseline
/// connector-level watermark (hard constraint 5's scope).
#[must_use]
pub fn home_scan_roots(connector: &str) -> Vec<PathBuf> {
    match connector {
        "claude" | "claude_code" | "claude-code" => claude_code_project_roots(),
        "codex" => codex_home_roots(),
        _ => Vec::new(),
    }
}

/// `CLAUDE_CONFIG_DIR` -> `<xdg>/claude-code` -> `$HOME/.claude`, each with
/// `projects` appended, plus the macOS desktop-sidecar roots the connector
/// scans on top of them.
fn claude_code_project_roots() -> Vec<PathBuf> {
    if let Some(explicit) = env_path_nonempty("CLAUDE_CONFIG_DIR") {
        return vec![explicit.join("projects")];
    }

    let mut roots = Vec::new();
    if let Some(xdg) = env_path_nonempty("XDG_CONFIG_HOME") {
        roots.push(xdg.join("claude-code").join("projects"));
    }
    roots.push(dirs::home_dir().map_or_else(
        || PathBuf::from(".claude/projects"),
        |home| home.join(".claude").join("projects"),
    ));
    if let Some(home) = dirs::home_dir() {
        let support = home
            .join("Library")
            .join("Application Support")
            .join("Claude");
        roots.push(support.join("claude-code-sessions"));
        roots.push(support.join("local-agent-mode-sessions"));
    }
    roots.sort();
    roots.dedup();
    roots
}

/// `CODEX_HOME` -> `$HOME/.codex`, then its `sessions` child when that exists
/// (the connector scans `sessions` and derives `external_id` relative to it).
fn codex_home_roots() -> Vec<PathBuf> {
    let home = env_path_nonempty("CODEX_HOME").unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".codex")
    });
    let sessions = home.join("sessions");
    if sessions.exists() {
        vec![sessions]
    } else {
        vec![home]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_entry(meta: &ScanRootMeta) -> (&'static str, &Path) {
        (
            if meta.source_name == HOME_SOURCE_NAME {
                "home"
            } else {
                "cfg"
            },
            &meta.canonical_path,
        )
    }

    #[test]
    fn root_ids_differ_per_path_and_per_kind() {
        let a = PathBuf::from("/tmp/cc-c3-root-a");
        let b = PathBuf::from("/tmp/cc-c3-root-b");

        assert_ne!(config_root_id("src", &a), config_root_id("src", &b));
        assert_ne!(
            config_root_id("src", &a),
            config_root_id("other-src", &a),
            "two sources over one path are two roots"
        );
        assert_ne!(config_root_id("src", &a), home_root_id("claude_code", &a));
        assert_ne!(
            home_root_id("claude_code", &a),
            home_root_id("codex", &a),
            "the home id is per connector"
        );
        assert!(config_root_id("src", &a).starts_with("cfg:src:"));
        assert!(home_root_id("codex", &a).starts_with("home:codex:"));
        assert_eq!(config_root_id("src", &a).rsplit(':').next().unwrap().len(), 16);
    }

    #[test]
    fn index_answers_by_source_key_and_by_root_path() {
        let canonical = PathBuf::from("/tmp/cc-c3-indexed-root");
        let meta = ScanRootMeta {
            root_id: config_root_id("laptop", &canonical),
            origin_host: "laptop".to_string(),
            readonly: false,
            canonical_path: canonical.clone(),
            source_name: "laptop".to_string(),
            watermarks_enabled: true,
        };

        let mut index = ScanRootMetaIndex::new();
        index.insert(meta.clone());

        assert_eq!(index.get("laptop", &canonical), Some(&meta));
        assert_eq!(
            index.get_by_path(Path::new("/tmp/cc-c3-indexed-root")),
            Some(&meta)
        );
        assert_eq!(index.get("home", &canonical), None);
        assert_eq!(index.get_by_path(Path::new("/tmp/cc-c3-other")), None);
        assert_eq!(source_entry(&meta).0, "cfg");
    }

    #[test]
    fn merge_keeps_both_families() {
        let cfg = PathBuf::from("/tmp/cc-c3-cfg-root");
        let home = PathBuf::from("/tmp/cc-c3-home-root");
        let mut configured = ScanRootMetaIndex::new();
        configured.insert(ScanRootMeta {
            root_id: config_root_id("laptop", &cfg),
            origin_host: "laptop".to_string(),
            readonly: false,
            canonical_path: cfg.clone(),
            source_name: "laptop".to_string(),
            watermarks_enabled: true,
        });
        let mut homes = ScanRootMetaIndex::new();
        homes.insert(ScanRootMeta {
            root_id: home_root_id("claude_code", &home),
            origin_host: "local".to_string(),
            readonly: false,
            canonical_path: home.clone(),
            source_name: HOME_SOURCE_NAME.to_string(),
            watermarks_enabled: true,
        });

        configured.merge(&homes);

        assert_eq!(configured.len(), 2);
        assert!(configured.get("laptop", &cfg).is_some());
        assert!(configured.get(HOME_SOURCE_NAME, &home).is_some());
    }

    #[test]
    fn unknown_connectors_have_no_home_roots() {
        assert!(home_scan_roots("openclaw").is_empty());
        assert!(home_scan_roots("aider").is_empty());
    }
}
